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

	mal.cache = make(map[string]string)

	// TODO: Find correct Site
	// sites, err := c.ListSites(ctx)
	// log.Info().Msgf("sites %v", sites)

	rules, err := mal.c.ListFirewallRule(ctx, "default")

	if err != nil {
		log.Fatal().Err(err).Msg("failed to list firewall rules")
	}

	for _, rule := range rules {
		if rule.Name == "cs-unifi-bouncer-ipv4" {
			mal.cache[rule.SrcAddress] = rule.ID
		}
	}
}

func (mal *unifiAddrList) add(ctx context.Context, decision *models.Decision) {

	log.Info().Msgf("new decisions from %s: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Origin, *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	if strings.Contains(*decision.Value, ":") {
		log.Info().Msgf("Ignore adding address %s (IPv6 disabled)", *decision.Value)
		return
	}

	var address string = *decision.Value
	var ruleIndex int = mal.calculateNextRuleIndex(ctx)

	if mal.cache[address] != "" {
		log.Info().Msgf("Address %s already present", address)
	} else {
		log.Info().Msgf("Next rule index: %d", ruleIndex)
		rule, err := mal.c.CreateFirewallRule(ctx, "default", &unifi.FirewallRule{
			Action:         "drop",
			Enabled:        true,
			Name:           "cs-unifi-bouncer-ipv4",
			SrcAddress:     address,
			Protocol:       "all",
			Ruleset:        "WAN_IN",
			SrcNetworkType: "NETv4",
			DstNetworkType: "NETv4",
			RuleIndex:      ruleIndex,
		})

		if err != nil {
			log.Error().Err(err).Msgf("Could not create firewall rule: %v", rule)
		} else {
			mal.cache[address] = rule.ID
			log.Info().Msgf("Address %s blocked in unifi", address)
		}
	}
}

func (mal *unifiAddrList) remove(decision *models.Decision) {

	log.Info().Msgf("removed decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	// var proto string
	// if strings.Contains(*decision.Value, ":") {
	// 	log.Info().Msgf("Ignore removing address %s (IPv6 disabled)", *decision.Value)
	// 	if !useIPV6 {
	// 		return
	// 	}
	// 	proto = "ipv6"
	// } else {
	// 	proto = "ip"
	// }

	// var address string
	// if *decision.Scope == "Ip" && proto == "ipv6" {
	// 	address = fmt.Sprintf("%s/128", *decision.Value)
	// } else {
	// 	address = *decision.Value
	// }

	// if mal.cache[address] != "" {

	// 	log.Info().Msgf("Verify address %s in mikrotik", address)
	// 	checkCmd := fmt.Sprintf("/%s/firewall/address-list/print =.proplist=address ?.id=%s", proto, mal.cache[address])
	// 	r, err := mal.c.RunArgs(strings.Split(checkCmd, " "))
	// 	if err != nil {
	// 		log.Fatal().Err(err).Msgf("%s address-list search cmd failed", proto)
	// 	}

	// 	if len(r.Re) == 1 && r.Re[0].Map["address"] == address {
	// 		delCmd := fmt.Sprintf("/%s/firewall/address-list/remove =numbers=%s", proto, mal.cache[address])
	// 		_, err = mal.c.RunArgs(strings.Split(delCmd, " "))
	// 		if err != nil {
	// 			log.Error().Err(err).Msgf("%s address-list remove cmd failed", proto)
	// 		}
	// 		log.Info().Msgf("%s removed from mikrotik", address)
	// 	} else {
	// 		log.Info().Msgf("%s already removed from mikrotik", address)
	// 	}
	// 	delete(mal.cache, address)

	// } else {
	// 	log.Info().Msgf("%s not find in local cache", address)
	// }
}

func (mal *unifiAddrList) calculateNextRuleIndex(ctx context.Context) int {
	rules, err := mal.c.ListFirewallRule(ctx, "default")

	if err != nil {
		log.Fatal().Err(err).Msg("failed to list firewall rules")
	}

	// UI defaulted to 20000 i dont know if this is the case for all unifi devices
	var newRuleIndex int = 20000

	ruleIndices := make(map[int]bool)
	for _, rule := range rules {
		if rule.Ruleset == "WAN_IN" {
			ruleIndices[rule.RuleIndex] = true
		}
	}

	for i := newRuleIndex; i <= newRuleIndex+len(ruleIndices); i++ {
		if !ruleIndices[i] {
			newRuleIndex = i
			return newRuleIndex
		}
	}

	return newRuleIndex
}

func (mal *unifiAddrList) decisionProcess(ctx context.Context, streamDecision *models.DecisionsStreamResponse) {

	// for _, decision := range streamDecision.Deleted {
	// 	// mal.remove(decision)
	// }
	for _, decision := range streamDecision.New {
		mal.add(ctx, decision)
	}
}
