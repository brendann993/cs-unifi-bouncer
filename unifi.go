package main

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/filipowm/go-unifi/unifi"
	"github.com/filipowm/go-unifi/unifi/features"
	"github.com/rs/zerolog/log"
)

func dial(ctx context.Context) (unifi.Client, error) {
	var client unifi.Client
	var err error

	if unifiAPIKey != "" {
		client, err = unifi.NewClient(
			&unifi.ClientConfig{
				URL:            unifiHost,
				APIKey:         unifiAPIKey,
				VerifySSL:      skipTLSVerify,
				ValidationMode: unifi.SoftValidation,
			},
		)
	} else {
		client, err = unifi.NewClient(&unifi.ClientConfig{
			URL:            unifiHost,
			User:           unifiUsername,
			Password:       unifiPassword,
			VerifySSL:      skipTLSVerify,
			ValidationMode: unifi.SoftValidation,
		},
		)
	}

	if err != nil {
		return nil, err
	}

	return client, nil
}

func (mal *unifiAddrList) isZoneBasedFirewallEnabled(ctx context.Context) bool {
	f, err := mal.c.GetFeature(ctx, "default", features.ZoneBasedFirewallMigration)
	if err != nil {
		if errors.Is(err, unifi.ErrNotFound) {
			log.Printf("Feature %s unavailable (not found)", features.ZoneBasedFirewallMigration)
			return false
		}
		log.Fatal().Err(err).Msg("Error getting feature")
	}

	return f.FeatureExists
}

func (mal *unifiAddrList) initUnifi(ctx context.Context) {

	log.Info().Msg("Connecting to unifi")

	c, err := dial(ctx)
	if err != nil {
		log.Fatal().Err(err).Str("host", unifiHost).Msg("Connection failed")
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
	if mal.isZoneBasedFirewallEnabled(ctx) {
		rules, err := mal.c.ListFirewallZonePolicy(ctx, unifiSite)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get firewall zone policies")
		}

		for _, rule := range rules {
			if strings.Contains(rule.Name, "cs-unifi-bouncer-ipv4") {
				mal.firewallRuleIPv4[rule.Name] = FirewallRuleCache{id: rule.ID, groupId: rule.Source.IPGroupID}
			}
			if strings.Contains(rule.Name, "cs-unifi-bouncer-ipv6") {
				mal.firewallRuleIPv6[rule.Name] = FirewallRuleCache{id: rule.ID, groupId: rule.Source.IPGroupID}
			}
		}
	} else {
		// If zone-based firewall is not enabled, use FirewallRule
		// Get the list of firewall rules

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
}

// postFirewallRule creates or updates a firewall rule in the UniFi controller.
// It constructs the rule name and type based on the provided parameters and
// either updates an existing rule if an ID is provided or creates a new one.
//
// Parameters:
// - ctx: The context for the request.
// - index: An integer used to generate the rule name and differentiate between rules.
// - ID: The ID of the firewall rule to update. If empty, a new rule will be created.
// - ipv6: A boolean indicating whether the rule is for IPv6 addresses.
// - groupId: The ID of the firewall group to use in the rule.
//
// The function logs a fatal error if the operation fails, otherwise it logs a success message.
func (mal *unifiAddrList) postFirewallRule(ctx context.Context, index int, ID string, ipv6 bool, groupId string) {
	// Check if zone based firewall is enabled
	zoneBasedFirewallEnabled := mal.isZoneBasedFirewallEnabled(ctx)

	name := "cs-unifi-bouncer-ipv4-" + strconv.Itoa(index)
	if ipv6 {
		name = "cs-unifi-bouncer-ipv6-" + strconv.Itoa(index)
	}

	if zoneBasedFirewallEnabled {
		IPVersion := "IPV4"
		startRuleIndex := ipv4StartRuleIndex
		if ipv6 {
			IPVersion = "IPV6"
			startRuleIndex = ipv6StartRuleIndex
		}

		// Get the zone ID for the external zone
		externalZoneID, externalErr := mal.getFirewallZoneID(ctx, unifiSite, "External")
		if externalErr != nil {
			log.Fatal().Err(externalErr).Msgf("Failed to get firewall zone ID: %v", "External")
		}

		// Get the zone ID for the internal zone
		internalZoneID, internalErr := mal.getFirewallZoneID(ctx, unifiSite, "Internal")
		if internalErr != nil {
			log.Fatal().Err(internalErr).Msgf("Failed to get firewall zone ID: %v", "Internal")
		}

		zonePolicy := &unifi.FirewallZonePolicy{
			Action:    "BLOCK",
			Enabled:   true,
			Name:      name,
			Protocol:  "all",
			IPVersion: IPVersion,
			Index:     startRuleIndex + index,
			Logging:   unifiLogging,
			Source: unifi.FirewallZonePolicySource{
				ZoneID:             externalZoneID,
				MatchingTargetType: "OBJECT",
				MatchingTarget:     "IP",
				IPGroupID:          groupId,
			},
			Destination: unifi.FirewallZonePolicyDestination{
				ZoneID: internalZoneID,
			},
			Schedule: unifi.FirewallZonePolicySchedule{
				Mode: "ALWAYS",
			},
		}

		var err error
		var newFirewallZonePolicy *unifi.FirewallZonePolicy

		if ID != "" {
			zonePolicy.ID = ID
			_, err = mal.c.UpdateFirewallZonePolicy(ctx, unifiSite, zonePolicy)
		} else {
			newFirewallZonePolicy, err = mal.c.CreateFirewallZonePolicy(ctx, unifiSite, zonePolicy)
		}

		if err != nil {
			log.Fatal().Err(err).Msgf("Failed to post firewall zone policy: %v", zonePolicy)
		} else {
			if newFirewallZonePolicy != nil {
				zonePolicy = newFirewallZonePolicy
			}
			log.Info().Msg("Firewall Zone Policy posted")
			if ipv6 {
				mal.firewallRuleIPv6[name] = FirewallRuleCache{id: zonePolicy.ID, groupId: groupId}
			} else {
				mal.firewallRuleIPv4[name] = FirewallRuleCache{id: zonePolicy.ID, groupId: groupId}
			}
		}
	} else {
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
			Logging:             unifiLogging,
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

func (mal *unifiAddrList) getFirewallZoneID(ctx context.Context, site string, zoneName string) (string, error) {
	zones, err := mal.c.ListFirewallZone(ctx, site)
	if err != nil {
		return "", err
	}

	for _, zone := range zones {
		if zone.Name == zoneName {
			return zone.ID, nil
		}
	}

	return "", errors.New("zone not found")
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

		// Handle deletion of old rules or zone policies
		if mal.isZoneBasedFirewallEnabled(ctx) {
			err := mal.c.DeleteFirewallZonePolicy(ctx, unifiSite, ruleCache.id)
			if err != nil {
				log.Error().Err(err).Msgf("Failed to delete old firewall zone policy: %s", name)
			} else {
				log.Info().Msgf("Deleted old firewall zone policy: %s", name)
				delete(mal.firewallRuleIPv4, name)
			}
		} else {
			err := mal.c.DeleteFirewallRule(ctx, unifiSite, ruleCache.id)
			if err != nil {
				log.Error().Err(err).Msgf("Failed to delete old firewall rule: %s", name)
			} else {
				log.Info().Msgf("Deleted old firewall rule: %s", name)
				delete(mal.firewallRuleIPv4, name)
			}
		}

		err := mal.c.DeleteFirewallGroup(ctx, unifiSite, ruleCache.groupId)
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

		// Handle deletion of old rules or zone policies
		if mal.isZoneBasedFirewallEnabled(ctx) {
			err := mal.c.DeleteFirewallZonePolicy(ctx, unifiSite, ruleCache.id)
			if err != nil {
				log.Error().Err(err).Msgf("Failed to delete old firewall zone policy: %s", groupName)
			} else {
				log.Info().Msgf("Deleted old firewall zone policy: %s", groupName)
				delete(mal.firewallRuleIPv6, groupName)
			}
		} else {
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
}

func (mal *unifiAddrList) add(decision *models.Decision) {

	if *decision.Type != "ban" {
		log.Debug().Msgf("Ignore adding decision type %s", *decision.Type)
		return
	}

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

	if *decision.Type != "ban" {
		log.Debug().Msgf("Ignore removing decision type %s", *decision.Type)
		return
	}

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
