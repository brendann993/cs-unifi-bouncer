package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/filipowm/go-unifi/unifi"
	"github.com/rs/zerolog/log"
)

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

func (mal *unifiAddrList) postFirewallPolicy(ctx context.Context, index int, ID string, ipv6 bool, groupId string, srcZone string, dstZone string) {
	name := fmt.Sprintf("cs-unifi-bouncer-ipv4-%s->%s-%d", srcZone, dstZone, index)
	if ipv6 {
		name = fmt.Sprintf("cs-unifi-bouncer-ipv6-%s->%s-%d", srcZone, dstZone, index)
	}

	ipVersion := "IPV4"
	if ipv6 {
		ipVersion = "IPV6"
	}

	srcZoneId := mal.firewallZones[srcZone].id
	dstZoneId := mal.firewallZones[dstZone].id

	firewallZonePolicy := &unifi.FirewallZonePolicy{
		Action:              "BLOCK",
		Enabled:             true,
		Name:                name,
		ConnectionStateType: "ALL",
		Protocol:            "all",
		IPVersion:           ipVersion,
		Index:               10000, //TODO: Autocalculate next free index
		Logging:             unifiLogging,
		Source: unifi.FirewallZonePolicySource{
			ZoneID:             srcZoneId,
			MatchingTarget:     "IP",
			MatchingTargetType: "OBJECT",
			PortMatchingType:   "ANY",
			IPGroupID:          groupId,
		},
		Destination: unifi.FirewallZonePolicyDestination{
			ZoneID:           dstZoneId,
			MatchingTarget:   "ANY",
			PortMatchingType: "ANY",
		},
		Schedule: unifi.FirewallZonePolicySchedule{
			Mode: "ALWAYS",
		},
	}

	var err error
	var newFirewallZonePolicy *unifi.FirewallZonePolicy

	if ID != "" {
		firewallZonePolicy.ID = ID
		_, err = mal.c.UpdateFirewallZonePolicy(ctx, unifiSite, firewallZonePolicy)
	} else {
		newFirewallZonePolicy, err = mal.c.CreateFirewallZonePolicy(ctx, unifiSite, firewallZonePolicy)
	}

	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to post firewall rule: %v", firewallZonePolicy)
	} else {
		if newFirewallZonePolicy != nil {
			firewallZonePolicy = newFirewallZonePolicy
		}
		log.Info().Msg("Firewall Rule posted")
		var firewallZonePolicyCache = FirewallZonePolicyCache{id: firewallZonePolicy.ID, groupId: groupId}
		if ipv6 {
			mal.firewallZonePoliyIPv6[firewallZonePolicy.Name] = firewallZonePolicyCache
		} else {
			mal.firewallZonePoliyIPv4[firewallZonePolicy.Name] = firewallZonePolicyCache
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
