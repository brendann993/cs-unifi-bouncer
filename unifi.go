package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/filipowm/go-unifi/unifi"
	"github.com/rs/zerolog/log"
)

func dial(ctx context.Context) (unifi.Client, error) {
	client, err := unifi.NewClient(
		&unifi.ClientConfig{
			URL:       unifiHost,
			User:      unifiUsername,
			Password:  unifiPassword,
			APIKey:    unifiAPIKey,
			VerifySSL: !skipTLSVerify,
		},
	)

	if err != nil {
		return nil, err
	}

	return client, nil
}

func (mal *unifiAddrList) initUnifi(ctx context.Context) {

	log.Info().Msg("Connecting to unifi")

	c, err := dial(ctx)
	if err != nil {
		log.Fatal().Err(err).Str("host", unifiHost).Str("username", unifiUsername).Msg("Connection failed")
	}

	mal.c = c

	mal.blockedAddresses = make(map[bool]map[string]bool)
	mal.blockedAddresses[true] = make(map[string]bool)
	mal.blockedAddresses[false] = make(map[string]bool)

	mal.firewallGroups = make(map[bool]map[string]string)
	mal.firewallGroups[true] = make(map[string]string)
	mal.firewallGroups[false] = make(map[string]string)

	mal.firewallRule = make(map[bool]map[string]FirewallRuleCache)
	mal.firewallRule[true] = make(map[string]FirewallRuleCache)
	mal.firewallRule[false] = make(map[string]FirewallRuleCache)

	mal.firewallZonePolicy = make(map[bool]map[string]FirewallZonePolicyCache)
	mal.firewallZonePolicy[true] = make(map[string]FirewallZonePolicyCache)
	mal.firewallZonePolicy[false] = make(map[string]FirewallZonePolicyCache)

	mal.modified = false
	mal.isZoneBased = false
	mal.firewallZones = make(map[string]ZoneCache)

	// Check if zone-based firewall is enabled
	mal.isZoneBased, err = c.IsFeatureEnabled(ctx, unifiSite, "ZONE_BASED_FIREWALL_MIGRATION")

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get networks")
	}

	log.Info().Msgf("Zone Based Firewall: %t", mal.isZoneBased)

	// Check if firewall groups exist
	groups, err := c.ListFirewallGroup(ctx, unifiSite)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get firewall groups")
	}

	for _, group := range groups {
		if strings.Contains(group.Name, "cs-unifi-bouncer") {
			ipv6 := strings.Contains(group.Name, "ipv6")

			mal.firewallGroups[ipv6][group.Name] = group.ID
			for _, member := range group.GroupMembers {
				mal.blockedAddresses[ipv6][member] = true
			}
		}
	}

	// Check if firewall rules exists
	rules, err := mal.c.ListFirewallRule(ctx, unifiSite)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get firewall rules")
	}

	for _, rule := range rules {
		if strings.Contains(rule.Name, "cs-unifi-bouncer") {
			ipv6 := strings.Contains(rule.Name, "ipv6")

			mal.firewallRule[ipv6][rule.Name] = FirewallRuleCache{id: rule.ID, groupId: rule.SrcFirewallGroupIDs[0]}
		}
	}

	// Check if firewall policies exists
	if mal.isZoneBased {
		policies, err := mal.c.ListFirewallZonePolicy(ctx, unifiSite)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get firewall policies")
		}

		for _, policy := range policies {
			if strings.Contains(policy.Name, "cs-unifi-bouncer") {
				ipv6 := strings.Contains(policy.Name, "ipv6")

				mal.firewallZonePolicy[ipv6][policy.Name] = FirewallZonePolicyCache{id: policy.ID, groupId: policy.Source.IPGroupID}
			}
		}
	}

	// Cache Firewall Zones
	if mal.isZoneBased {
		if len(unifiZoneSrc) == 0 || len(unifiZoneDst) == 0 {
			log.Fatal().Msg("At least one unifiZoneSrc and one unifiZoneDst must be configured")
		}

		zones, err := c.ListFirewallZone(ctx, unifiSite)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get firewall zones")
		}

		for _, zone := range zones {
			mal.firewallZones[zone.Name] = ZoneCache{id: zone.ID}
		}

		// Check if source and destination zones are defined
		for _, zone := range unifiZoneSrc {
			if _, exists := mal.firewallZones[zone]; !exists {
				log.Fatal().Msgf("Source Zone %s not found", zone)
			}
		}
		for _, zone := range unifiZoneDst {
			if _, exists := mal.firewallZones[zone]; !exists {
				log.Fatal().Msgf("Destination Zone %s not found", zone)
			}
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
func (mal *unifiAddrList) updateFirewall(ctx context.Context, ipv6 bool) {

	if !mal.modified {
		log.Debug().Msg("No changes detected, skipping update")
		return
	}

	ipVersionString := "ipv4"
	if ipv6 {
		ipVersionString = "ipv6"
	}

	// Get all cached addresses
	addresses := getKeys(mal.blockedAddresses[ipv6])

	// Calculate the number of groups needed
	numGroups := (len(addresses) + maxGroupSize - 1) / maxGroupSize
	log.Info().Msgf("Number of %s groups needed: %d", ipVersionString, numGroups)

	// Split addresses into groups of maxGroupSize
	for i := 0; i < len(addresses); i += maxGroupSize {
		end := i + maxGroupSize
		if end > len(addresses) {
			end = len(addresses)
		}
		group := addresses[i:end]

		// Get the group ID if it exists
		groupName := fmt.Sprintf("cs-unifi-bouncer-%s-%d", ipVersionString, i/maxGroupSize)
		groupID := ""
		if id, exists := mal.firewallGroups[ipv6][groupName]; exists {
			groupID = id
		}

		// Post the firewall group
		groupID = mal.postFirewallGroup(ctx, groupID, groupName, ipv6, group)

		if mal.isZoneBased {
			for _, zoneSrc := range unifiZoneSrc {
				for _, zoneDst := range unifiZoneDst {
					// Get the policy ID if it exists
					policyName := fmt.Sprintf("cs-unifi-bouncer-%s-%s->%s-%d", ipVersionString, zoneSrc, zoneDst, i/maxGroupSize)
					policyId := ""
					cachedGroupId := ""
					if policyCache, exists := mal.firewallZonePolicy[ipv6][policyName]; exists {
						policyId = policyCache.id
						cachedGroupId = policyCache.groupId
					}
					// Post the firewall rule, skip if the group ID is the same as the cached one (no changes)
					if groupID != "" && groupID != cachedGroupId {
						mal.postFirewallPolicy(ctx, policyId, policyName, false, groupID, zoneSrc, zoneDst)
					}
				}
			}
		} else {
			// Get the rule ID if it exists
			ruleName := fmt.Sprintf("cs-unifi-bouncer-%s-%d", ipVersionString, i/maxGroupSize)
			ruleId := ""
			cachedGroupId := ""
			if ruleCache, exists := mal.firewallRule[ipv6][ruleName]; exists {
				ruleId = ruleCache.id
				cachedGroupId = ruleCache.groupId
			}

			// Post the firewall rule, skip if the group ID is the same as the cached one (no changes)
			if groupID != "" && groupID != cachedGroupId {
				mal.postFirewallRule(ctx, i/maxGroupSize, ruleId, ruleName, false, groupID)
			}
		}
	}

	// Delete old firewall rules
	for ruleName, ruleCache := range mal.firewallRule[ipv6] {
		// Check if the rule index is lower than numGroups
		parts := strings.Split(ruleName, "-")
		index, err := strconv.Atoi(parts[4])
		if err != nil {
			log.Warn().Msgf("Invalid rule index in name: %s", ruleName)
			continue
		}
		// If isZoneBased, then delete all rules independent of index
		if !mal.isZoneBased && (err != nil || index >= numGroups) {
			continue
		}
		// Delete the old firewall rule
		err = mal.c.DeleteFirewallRule(ctx, unifiSite, ruleCache.id)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall rule: %s", ruleName)
		} else {
			log.Info().Msgf("Deleted old firewall rule: %s", ruleName)
			delete(mal.firewallRule[ipv6], ruleName)
		}
	}

	// Delete old firewall policies
	for policyName, policyCache := range mal.firewallZonePolicy[ipv6] {
		// Check if the policy index is higher than numGroups
		parts := strings.Split(policyName, "-")
		index, err := strconv.Atoi(parts[6])
		if err != nil {
			log.Warn().Msgf("Invalid policy index in name: %s", policyName)
			continue
		}
		// If isZoneBased is false, then delete all policies independent of index
		if mal.isZoneBased && (err != nil || index < numGroups) {
			continue
		}
		// Delete the old firewall policy
		err = mal.c.DeleteFirewallZonePolicy(ctx, unifiSite, policyCache.id)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall policy: %s", policyName)
		} else {
			log.Info().Msgf("Deleted old firewall policy: %s", policyName)
			delete(mal.firewallZonePolicy[ipv6], policyName)
		}
	}

	// Delete old firewall groups
	for groupName, groupId := range mal.firewallGroups[ipv6] {
		// Check if the group index is higher than numGroups
		parts := strings.Split(groupName, "-")
		index, err := strconv.Atoi(parts[4])
		if err != nil {
			log.Warn().Msgf("Invalid group index in name: %s", groupName)
			continue
		}
		if err != nil || index < numGroups {
			continue
		}
		// Delete the old firewall group
		err = mal.c.DeleteFirewallGroup(ctx, unifiSite, groupId)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall group: %s", groupName)
		} else {
			log.Info().Msgf("Deleted old firewall group: %s", groupName)
			delete(mal.firewallGroups[ipv6], groupName)
		}
	}
}

func (mal *unifiAddrList) add(decision *models.Decision) {

	if *decision.Type != "ban" {
		log.Debug().Msgf("Ignore adding decision type %s", *decision.Type)
		return
	}

	log.Info().Msgf("new decisions from %s: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Origin, *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	ipv6 := strings.Contains(*decision.Value, ":")

	if ipv6 && !useIPV6 {
		log.Info().Msgf("Ignore adding address %s (IPv6 disabled)", *decision.Value)
		return
	}

	if mal.blockedAddresses[ipv6][*decision.Value] {
		log.Warn().Msgf("Address %s already present", *decision.Value)
	} else {
		mal.modified = true
		mal.blockedAddresses[ipv6][*decision.Value] = true
	}
}

func (mal *unifiAddrList) remove(decision *models.Decision) {

	if *decision.Type != "ban" {
		log.Debug().Msgf("Ignore removing decision type %s", *decision.Type)
		return
	}

	log.Info().Msgf("removed decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	ipv6 := strings.Contains(*decision.Value, ":")

	if ipv6 && !useIPV6 {
		log.Info().Msgf("Ignore removing address %s (IPv6 disabled)", *decision.Value)
		return
	}

	if mal.blockedAddresses[ipv6][*decision.Value] {
		mal.modified = true
		delete(mal.blockedAddresses[ipv6], *decision.Value)
	} else {
		log.Warn().Msgf("%s not found in local cache", *decision.Value)
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
