package main

import (
	"context"
	"fmt"
	"time"

	"github.com/paultyng/go-unifi/unifi"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

type unifiAddrList struct {
	c                  *unifi.Client
	cacheIpv4          map[string]bool
	cacheIpv6          map[string]bool
	firewallGroupsIPv4 map[string]string
	firewallGroupsIPv6 map[string]string
	firewallRuleIPv4   map[string]string
	firewallRuleIPv6   map[string]string
}

func main() {

	// zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	initConfig()

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         crowdsecBouncerAPIKey,
		APIUrl:         crowdsecBouncerURL,
		TickerInterval: "5s",
		Origins:        crowdsecOrigins,
	}
	if err := bouncer.Init(); err != nil {
		log.Fatal().Err(err).Msg("Bouncer init failed")
	}

	var mal unifiAddrList

	g, ctx := errgroup.WithContext(context.Background())

	mal.initUnifi(ctx)
	log.Info().Msg("Unifi Connection Initialized")

	g.Go(func() error {
		bouncer.Run(ctx)
		return fmt.Errorf("bouncer stream halted")
	})

	// Timer to detect inactivity initialization can take longer
	inactivityTimer := time.NewTimer(10 * time.Second)
	defer inactivityTimer.Stop()

	g.Go(func() error {
		log.Printf("Processing new and deleted decisions . . .")
		for {
			select {
			case <-ctx.Done():
				log.Error().Msg("terminating bouncer process")
				return nil
			case decisions := <-bouncer.Stream:
				// Reset the inactivity timer
				if !inactivityTimer.Stop() {
					<-inactivityTimer.C
				}
				inactivityTimer.Reset(time.Second)

				mal.decisionProcess(decisions)
			case <-inactivityTimer.C:
				// Execute the update to unifi when no new messages have been received
				mal.updateFirewall(ctx)
			}
		}
	})

	err := g.Wait()

	if err != nil {
		log.Error().Err(err).Send()
	}
}
