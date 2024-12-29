package main

import (
	"context"
	"fmt"

	"github.com/paultyng/go-unifi/unifi"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

type unifiAddrList struct {
	c                 *unifi.Client
	cache             map[string]bool
	firewallGroupIPv4 *unifi.FirewallGroup
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

	g.Go(func() error {
		log.Printf("Processing new and deleted decisions . . .")
		for {
			select {
			case <-ctx.Done():
				log.Error().Msg("terminating bouncer process")
				return nil
			case decisions := <-bouncer.Stream:
				mal.decisionProcess(ctx, decisions)
			}
		}
	})

	err := g.Wait()

	if err != nil {
		log.Error().Err(err).Send()
	}
}
