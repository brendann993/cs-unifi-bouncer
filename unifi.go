package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/paultyng/go-unifi/unifi"
	"github.com/rs/zerolog/log"
)

func dial(ctx context.Context) (*unifi.Client, error) {
	client := unifi.Client{}
	client.SetBaseURL(unifiHost)
	if skipTLSVerify {
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		jar, _ := cookiejar.New(nil)
		httpClient.Jar = jar
		client.SetHTTPClient(httpClient)
	}
	err := client.Login(ctx, username, password)

	if err != nil {
		return nil, err
	}

	return &client, nil
}

func (mal *unifiAddrList) initUnifi(ctx context.Context) {

	log.Info().Msg("Connecting to unifi")

	c, err := dial(ctx)
	if err != nil {
		log.Fatal().Err(err).Str("host", unifiHost).Str("username", username).Msg("Connection failed")
	}

	mal.c = c
	mal.cacheIpv4 = make(map[string]bool)
	mal.cacheIpv6 = make(map[string]bool)
	mal.firewallGroupsIPv4 = make(map[string]string)
	mal.firewallGroupsIPv6 = make(map[string]string)
	mal.firewallRuleIPv4 = make(map[string]FirewallRuleCache)
	mal.firewallRuleIPv6 = make(map[string]FirewallRuleCache)
	mal.modified = false

	// Check if firewall groups exist
	groups, err := c.ListFirewallGroup(ctx, unifiSite)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get firewall groups")
	}

	for _, group := range groups {
		if strings.Contains(group.Name, "cs-unifi-bouncer-ipv4") {
			mal.firewallGroupsIPv4[group.Name] = group.ID
			for _, member := range group.GroupMembers {
				mal.cacheIpv4[member] = true
			}
		}
		if strings.Contains(group.Name, "cs-unifi-bouncer-ipv6") {
			mal.firewallGroupsIPv6[group.Name] = group.ID
			for _, member := range group.GroupMembers {
				mal.cacheIpv6[member] = true
			}
		}
	}

	// Check if firewall rules exists
	rules, err := mal.c.ListFirewallRule(ctx, unifiSite)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get firewall rules")
	}

	for _, rule := range rules {
		if strings.Contains(rule.Name, "cs-unifi-bouncer-ipv4") {
			mal.firewallRuleIPv4[rule.Name] = FirewallRuleCache{id: rule.ID, groupId: rule.SrcFirewallGroupIDs[0]}
		}
		if strings.Contains(rule.Name, "cs-unifi-bouncer-ipv6") {
			mal.firewallRuleIPv6[rule.Name] = FirewallRuleCache{id: rule.ID, groupId: rule.SrcFirewallGroupIDs[0]}
		}
	}
}

// postFirewallRule creates or updates a firewall rule in the UniFi controller.
// The rule will drop all traffic from the specified source firewall group IDs.
//
// Parameters:
// - ctx: The context for the request.
// - index: An integer used to generate the rule name and differentiate between rules.
// - ID: The ID of the firewall rule to update. If empty, a new rule will be created.
// - ipv6: A boolean indicating whether the rule is for IPv6 traffic.
// - groupIds: A slice of strings containing the source firewall group IDs.
//
// The function constructs a firewall rule with the specified parameters and either
// updates an existing rule or creates a new one in the UniFi controller. If the
// operation fails, it logs a fatal error. Otherwise, it logs an informational message.
func (mal *unifiAddrList) postFirewallRule(ctx context.Context, index int, ID string, ipv6 bool, groupId string) {
	name := "cs-unifi-bouncer-ipv4-" + strconv.Itoa(index)
	if ipv6 {
		name = "cs-unifi-bouncer-ipv6-" + strconv.Itoa(index)
	}

	ruleset := "WAN_IN"
	if ipv6 {
		ruleset = "WANv6_IN"
	}

	startRuleIndex := ipv4StartRuleIndex
	if ipv6 {
		startRuleIndex = ipv6StartRuleIndex
	}

	firewallRule := &unifi.FirewallRule{
		Action:              "drop",
		Enabled:             true,
		Name:                name,
		SrcFirewallGroupIDs: []string{groupId},
		Protocol:            "all",
		Ruleset:             ruleset,
		SettingPreference:   "auto",
		RuleIndex:           startRuleIndex + index,
	}

	if !ipv6 {
		firewallRule.SrcNetworkType = "NETv4"
		firewallRule.DstNetworkType = "NETv4"
	}

	var err error
	var newFirewallRule *unifi.FirewallRule

	if ID != "" {
		firewallRule.ID = ID
		_, err = mal.c.UpdateFirewallRule(ctx, unifiSite, firewallRule)
	} else {
		newFirewallRule, err = mal.c.CreateFirewallRule(ctx, unifiSite, firewallRule)
	}

	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to post firewall rule: %v", firewallRule)
	} else {
		if newFirewallRule != nil {
			firewallRule = newFirewallRule
		}
		log.Info().Msg("Firewall Rule posted")
		if ipv6 {
			mal.firewallRuleIPv6[firewallRule.Name] = FirewallRuleCache{id: firewallRule.ID, groupId: groupId}
		} else {
			mal.firewallRuleIPv4[firewallRule.Name] = FirewallRuleCache{id: firewallRule.ID, groupId: groupId}
		}
	}
}

// postFirewallGroup creates or updates a firewall group in the UniFi controller.
// It constructs the group name and type based on the provided parameters and
// either updates an existing group if an ID is provided or creates a new one.
//
// Parameters:
// - ctx: The context for the request.
// - index: An integer used to generate the group name and differentiate between groups.
// - ID: The ID of the firewall group to update. If empty, a new group will be created.
// - ipv6: A boolean indicating whether the group is for IPv6 addresses.
// - members: A slice of strings representing the members of the firewall group.
//
// The function logs a fatal error if the operation fails, otherwise it logs a success message.
func (mal *unifiAddrList) postFirewallGroup(ctx context.Context, index int, ID string, ipv6 bool, members []string) string {
	name := "cs-unifi-bouncer-ipv4-" + strconv.Itoa(index)
	if ipv6 {
		name = "cs-unifi-bouncer-ipv6-" + strconv.Itoa(index)
	}

	groupType := "address-group"
	if ipv6 {
		groupType = "ipv6-address-group"
	}

	group := &unifi.FirewallGroup{
		Name:         name,
		GroupType:    groupType,
		GroupMembers: members,
	}

	var err error
	var newGroup *unifi.FirewallGroup

	if ID != "" {
		group.ID = ID
		_, err = mal.c.UpdateFirewallGroup(ctx, unifiSite, group)
	} else {
		newGroup, err = mal.c.CreateFirewallGroup(ctx, unifiSite, group)
	}

	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to post firewall group: %v", group)
		return ""
	} else {
		if newGroup != nil {
			group = newGroup
		}
		log.Info().Msg("Firewall Group posted")
		if ipv6 {
			mal.firewallGroupsIPv6[name] = group.ID
		} else {
			mal.firewallGroupsIPv4[name] = group.ID
		}
		return group.ID
	}
}

// Function to get keys from a map
func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// Function to update the firewall group
func (mal *unifiAddrList) updateFirewall(ctx context.Context) {

	if !mal.modified {
		log.Debug().Msg("No changes detected, skipping update")
		return
	}

	// Get all cache IPv4 addresses
	ipv4Addresses := getKeys(mal.cacheIpv4)

	// Calculate the number of groups needed
	numGroupsIPv4 := (len(ipv4Addresses) + maxGroupSize - 1) / maxGroupSize
	log.Info().Msgf("Number of IPv4 groups needed: %d", numGroupsIPv4)

	// Split IPv4 addresses into groups of maxGroupSize
	for i := 0; i < len(ipv4Addresses); i += maxGroupSize {
		end := i + maxGroupSize
		if end > len(ipv4Addresses) {
			end = len(ipv4Addresses)
		}
		group := ipv4Addresses[i:end]

		// Get the group ID if it exists
		groupID := ""
		if id, exists := mal.firewallGroupsIPv4["cs-unifi-bouncer-ipv4-"+strconv.Itoa(i/maxGroupSize)]; exists {
			groupID = id
		}

		// Post the firewall group
		groupID = mal.postFirewallGroup(ctx, i/maxGroupSize, groupID, false, group)

		// Get the rule ID if it exists
		ruleId := ""
		cachedGroupId := ""
		if ruleCache, exists := mal.firewallRuleIPv4["cs-unifi-bouncer-ipv4-"+strconv.Itoa(i/maxGroupSize)]; exists {
			ruleId = ruleCache.id
			cachedGroupId = ruleCache.groupId
		}

		// Post the firewall rule, skip if the group ID is the same as the cached one (no changes)
		if groupID != "" && groupID != cachedGroupId {
			mal.postFirewallRule(ctx, i/maxGroupSize, ruleId, false, groupID)
		}
	}

	// Delete old rules and groups that are no longer needed with an index higher than numGroups
	for i := numGroupsIPv4; ; i++ {
		name := "cs-unifi-bouncer-ipv4-" + strconv.Itoa(i)
		ruleCache, exists := mal.firewallRuleIPv4[name]
		if !exists {
			break
		}

		err := mal.c.DeleteFirewallRule(ctx, unifiSite, ruleCache.id)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall rule: %s", name)
		} else {
			log.Info().Msgf("Deleted old firewall rule: %s", name)
			delete(mal.firewallRuleIPv4, name)
		}

		err = mal.c.DeleteFirewallGroup(ctx, unifiSite, ruleCache.groupId)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall group: %s", name)
		} else {
			log.Info().Msgf("Deleted old firewall group: %s", name)
			delete(mal.firewallGroupsIPv4, name)
		}
	}

	// Get all cache IPv6 addresses
	ipv6Addresses := getKeys(mal.cacheIpv6)

	// Calculate the number of groups needed
	numGroupsIPv6 := (len(ipv6Addresses) + maxGroupSize - 1) / maxGroupSize
	log.Info().Msgf("Number of IPv6 groups needed: %d", numGroupsIPv6)

	// Split IPv6 addresses into groups of maxGroupSize
	for i := 0; i < len(ipv6Addresses); i += maxGroupSize {
		end := i + maxGroupSize
		if end > len(ipv6Addresses) {
			end = len(ipv6Addresses)
		}
		group := ipv6Addresses[i:end]

		// Get the group ID if it exists
		groupID := ""
		if id, exists := mal.firewallGroupsIPv6["cs-unifi-bouncer-ipv6-"+strconv.Itoa(i/maxGroupSize)]; exists {
			groupID = id
		}

		// Post the firewall group
		groupID = mal.postFirewallGroup(ctx, i/maxGroupSize, groupID, true, group)

		// Get the rule ID if it exists
		ruleId := ""
		cachedGroupId := ""
		if ruleCache, exists := mal.firewallRuleIPv6["cs-unifi-bouncer-ipv6-"+strconv.Itoa(i/maxGroupSize)]; exists {
			ruleId = ruleCache.id
			cachedGroupId = ruleCache.groupId
		}

		// Post the firewall rule, skip if the group ID is the same as the cached one (no changes)
		if groupID != "" && groupID != cachedGroupId {
			mal.postFirewallRule(ctx, i/maxGroupSize, ruleId, true, groupID)
		}
	}

	// Delete old groups that are no longer needed with an index higher than numGroups
	for i := numGroupsIPv6; ; i++ {
		groupName := "cs-unifi-bouncer-ipv6-" + strconv.Itoa(i)
		ruleCache, exists := mal.firewallRuleIPv6[groupName]
		if !exists {
			break
		}

		err := mal.c.DeleteFirewallRule(ctx, unifiSite, ruleCache.id)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall rule: %s", groupName)
		} else {
			log.Info().Msgf("Deleted old firewall rule: %s", groupName)
			delete(mal.firewallRuleIPv6, groupName)
		}

		err = mal.c.DeleteFirewallGroup(ctx, unifiSite, ruleCache.groupId)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall group: %s", groupName)
		} else {
			log.Info().Msgf("Deleted old firewall group: %s", groupName)
			delete(mal.firewallGroupsIPv6, groupName)
		}
	}
}

func (mal *unifiAddrList) add(decision *models.Decision) {

	log.Info().Msgf("new decisions from %s: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Origin, *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	if strings.Contains(*decision.Value, ":") {
		if !useIPV6 {
			log.Info().Msgf("Ignore adding address %s (IPv6 disabled)", *decision.Value)
			return
		}

		if mal.cacheIpv6[*decision.Value] {
			log.Warn().Msgf("Address %s already present", *decision.Value)
		} else {
			mal.modified = true
			mal.cacheIpv6[*decision.Value] = true
		}
	} else {
		if mal.cacheIpv4[*decision.Value] {
			log.Warn().Msgf("Address %s already present", *decision.Value)
		} else {
			mal.modified = true
			mal.cacheIpv4[*decision.Value] = true
		}
	}
}

func (mal *unifiAddrList) remove(decision *models.Decision) {

	log.Info().Msgf("removed decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	if strings.Contains(*decision.Value, ":") {
		if !useIPV6 {
			log.Info().Msgf("Ignore removing address %s (IPv6 disabled)", *decision.Value)
			return
		}

		if mal.cacheIpv6[*decision.Value] {
			mal.modified = true
			delete(mal.cacheIpv6, *decision.Value)
		} else {
			log.Warn().Msgf("%s not found in local cache", *decision.Value)
		}
	} else {
		if mal.cacheIpv4[*decision.Value] {
			mal.modified = true
			delete(mal.cacheIpv4, *decision.Value)
		} else {
			log.Warn().Msgf("%s not found in local cache", *decision.Value)
		}
	}
}

func (mal *unifiAddrList) decisionProcess(streamDecision *models.DecisionsStreamResponse) {
	for _, decision := range streamDecision.Deleted {
		mal.remove(decision)
	}
	for _, decision := range streamDecision.New {
		mal.add(decision)
	}
}
