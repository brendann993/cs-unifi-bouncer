package main

import (
	"context"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/paultyng/go-unifi/unifi"
	"github.com/rs/zerolog/log"
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

	// TODO: Find correct Site
	// sites, err := c.ListSites(ctx)
	// log.Info().Msgf("sites %v", sites)

	// Get or create firewall group for IPv4
	groups, err := c.ListFirewallGroup(ctx, "default")
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
		mal.firewallGroupIPv4, err = mal.c.CreateFirewallGroup(ctx, "default", mal.firewallGroupIPv4)
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
	rules, err := mal.c.ListFirewallRule(ctx, "default")
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
		_, err := mal.c.CreateFirewallRule(ctx, "default", &unifi.FirewallRule{
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
	mal.firewallGroupIPv4, err = mal.c.UpdateFirewallGroup(ctx, "default", mal.firewallGroupIPv4)

	if err != nil {
		log.Error().Err(err).Msgf("Could not update firewall group: %v", mal.firewallGroupIPv4)
	} else {
		log.Debug().Msg("Firewall Group updated")
	}
}

func (mal *unifiAddrList) add(ctx context.Context, decision *models.Decision) {

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
		mal.updateFirewallGroup(ctx)
	}
}

func (mal *unifiAddrList) remove(ctx context.Context, decision *models.Decision) {

	log.Info().Msgf("removed decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	if strings.Contains(*decision.Value, ":") {
		log.Info().Msgf("Ignore removing address %s (IPv6 disabled)", *decision.Value)
		return
	}

	var address string = *decision.Value

	if mal.cache[address] {
		delete(mal.cache, address)
		mal.updateFirewallGroup(ctx)
	} else {
		log.Warn().Msgf("%s not found in local cache", address)
	}
}

func (mal *unifiAddrList) decisionProcess(ctx context.Context, streamDecision *models.DecisionsStreamResponse) {

	for _, decision := range streamDecision.Deleted {
		mal.remove(ctx, decision)
	}
	for _, decision := range streamDecision.New {
		mal.add(ctx, decision)
	}
}
