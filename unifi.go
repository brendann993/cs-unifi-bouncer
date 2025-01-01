package main

import (
	"context"
	"strconv"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/paultyng/go-unifi/unifi"
	"github.com/rs/zerolog/log"
	"golang.org/x/text/number"
)

func dial(ctx context.Context) (*unifi.Client, error) {
	client := unifi.Client{}
	client.SetBaseURL(unifiHost)
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

	mal.cache = make(map[string]bool)

	// Get or create firewall group for IPv4
	groups, err := c.ListFirewallGroup(ctx, unifiSite)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get firewall groups")
	}

	var firewallgroupExists bool = false

	for _, group := range groups {
		if group.Name == "cs-unifi-bouncer-ipv4" {
			log.Info().Msg("Group already present")
			mal.firewallGroupIPv4 = &group
			firewallgroupExists = true
			break
		}
	}

	if !firewallgroupExists {
		mal.firewallGroupIPv4 = &unifi.FirewallGroup{
			Name:      "cs-unifi-bouncer-ipv4",
			GroupType: "address-group",
		}
		mal.firewallGroupIPv4, err = mal.c.CreateFirewallGroup(ctx, unifiSite, mal.firewallGroupIPv4)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create firewall group")
		} else {
			log.Info().Msg("Firewall Group created")
		}
	}

	// Add existing members to cache
	for _, member := range mal.firewallGroupIPv4.GroupMembers {
		mal.cache[member] = true
	}

	// Create firewall rule
	rules, err := mal.c.ListFirewallRule(ctx, unifiSite)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get firewall rules")
	}

	var firewallRuleExists bool = false

	for _, rule := range rules {
		if rule.Name == "cs-unifi-bouncer-ipv4" {
			log.Info().Msg("Rule already present")
			firewallRuleExists = true
			break
		}
	}

	if !firewallRuleExists {
		_, err := mal.c.CreateFirewallRule(ctx, unifiSite, &unifi.FirewallRule{
			Action:              "drop",
			Enabled:             true,
			Name:                "cs-unifi-bouncer-ipv4",
			SrcFirewallGroupIDs: []string{mal.firewallGroupIPv4.ID},
			Protocol:            "all",
			Ruleset:             "WAN_IN",
			SrcNetworkType:      "NETv4",
			DstNetworkType:      "NETv4",
			SettingPreference:   "auto",
			RuleIndex:           20000,
		})
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create firewall rule")
		} else {
			log.Info().Msg("Firewall Rule created")
		}
	}
}


// postFirewallRule creates or updates a firewall rule in the UniFi controller.
// The rule will drop all traffic from the specified source firewall group IDs.
//
// Parameters:
// - ctx: The context for the request.
// - ID: The ID of the firewall rule to update. If empty, a new rule will be created.
// - ipv6: A boolean indicating whether the rule is for IPv6 traffic.
// - groupIds: A slice of strings containing the source firewall group IDs.
//
// The function constructs a firewall rule with the specified parameters and either
// updates an existing rule or creates a new one in the UniFi controller. If the
// operation fails, it logs a fatal error. Otherwise, it logs an informational message.
func (mal *unifiAddrList) postFirewallRule(ctx context.Context, ID string, ipv6 bool, groupIds []string) {
	name := "cs-unifi-bouncer-ipv4"
	if ipv6 {
		name += "cs-unifi-bouncer-ipv6"
	}

	ruleset := "WAN_IN"
	if ipv6 {
		ruleset = "WANv6_IN"
	}

	firewallRule := &unifi.FirewallRule{
		Action:              "drop",
		Enabled:             true,
		Name:                name,
		SrcFirewallGroupIDs: groupIds,
		Protocol:            "all",
		Ruleset:             ruleset,
		SettingPreference:   "auto",
		RuleIndex:           20000,
	}

	if !ipv6 {
		firewallRule.SrcNetworkType = "NETv4"
		firewallRule.DstNetworkType = "NETv4"
	}

	var err error;

	if ID != "" {
		firewallRule.ID = ID
		_, err = mal.c.UpdateFirewallRule(ctx, unifiSite, firewallRule)
	} else {
		_, err = mal.c.CreateFirewallRule(ctx, unifiSite, firewallRule)
	}

	
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to post firewall rule")
	} else {
		log.Info().Msg("Firewall Rule posted")
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
func (mal *unifiAddrList) postFirewallGroup(ctx context.Context, index int, ID string, ipv6 bool, members []string) {
	name := "cs-unifi-bouncer-ipv4-" + strconv.Itoa(index)
	if ipv6 {
		name += "cs-unifi-bouncer-ipv6-" + strconv.Itoa(index)
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

	var err error;

	if ID != "" {
		group.ID = ID
		_, err = mal.c.UpdateFirewallGroup(ctx, unifiSite, group)
	} else {
		_, err = mal.c.CreateFirewallGroup(ctx, unifiSite, group)
	}

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to post firewall group")
	} else {
		log.Info().Msg("Firewall Group posted")
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
func (mal *unifiAddrList) updateFirewallGroup(ctx context.Context) {
	var err error

	mal.firewallGroupIPv4.GroupMembers = getKeys(mal.cache)
	mal.firewallGroupIPv4, err = mal.c.UpdateFirewallGroup(ctx, unifiSite, mal.firewallGroupIPv4)

	// If group members is 0 the API sometimes does not return the group causing the Library to error.
	// The setting however is properly updated.
	if err != nil && len(mal.cache) != 0 {
		log.Error().Err(err).Msgf("Could not update firewall group: %v", mal.firewallGroupIPv4)
	} else {
		log.Debug().Msg("Firewall Group updated")
	}
}

func (mal *unifiAddrList) add(decision *models.Decision) {

	log.Info().Msgf("new decisions from %s: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Origin, *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	if strings.Contains(*decision.Value, ":") {
		log.Info().Msgf("Ignore adding address %s (IPv6 disabled)", *decision.Value)
		return
	}

	var address string = *decision.Value

	if mal.cache[address] {
		log.Warn().Msgf("Address %s already present", address)
	} else {
		mal.cache[address] = true
	}
}

func (mal *unifiAddrList) remove(decision *models.Decision) {

	log.Info().Msgf("removed decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	if strings.Contains(*decision.Value, ":") {
		log.Info().Msgf("Ignore removing address %s (IPv6 disabled)", *decision.Value)
		return
	}

	var address string = *decision.Value

	if mal.cache[address] {
		delete(mal.cache, address)
	} else {
		log.Warn().Msgf("%s not found in local cache", address)
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
