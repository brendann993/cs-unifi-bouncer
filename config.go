package main

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/spf13/viper"
)

var (
	logLevel              string
	crowdsecBouncerAPIKey string
	crowdsecBouncerURL    string
	unifiHost             string
	unifiSite             string
	username              string
	password              string
	useIPV6               bool
	crowdsecOrigins       []string
)

func initConfig() {
	viper.BindEnv("log_level")
	viper.SetDefault("log_level", "1")
	viper.BindEnv("crowdsec_bouncer_api_key")
	viper.BindEnv("crowdsec_url")
	viper.SetDefault("crowdsec_url", "http://crowdsec:8080/")
	viper.BindEnv("unifi_host")
	viper.BindEnv("unifi_user")
	viper.BindEnv("unifi_pass")
	viper.BindEnv("unifi_site")
	viper.SetDefault("unifi_site", "default")
	viper.BindEnv("unifi_ipv6")
	viper.SetDefault("unifi_ipv6", "true")
	viper.BindEnv("crowdsec_origins")
	viper.SetDefault("crowdsec_origins", nil)

	logLevel = viper.GetString("log_level")
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid log level")
	}
	zerolog.SetGlobalLevel(level)

	crowdsecBouncerAPIKey = viper.GetString("crowdsec_bouncer_api_key")
	if crowdsecBouncerAPIKey == "" {
		log.Fatal().Msg("Crowdsec API key is not set")
	}
	crowdsecBouncerURL = viper.GetString("crowdsec_url")
	if crowdsecBouncerURL == "" {
		log.Fatal().Msg("Crowdsec URL is not set")
	}

	crowdsecOrigins = viper.GetStringSlice("crowdsec_origins")

	unifiHost = viper.GetString("unifi_host")

	username = viper.GetString("unifi_user")
	if username == "" {
		log.Fatal().Msg("Unifi username is not set")
	}

	password = viper.GetString("unifi_pass")
	if password == "" {
		log.Fatal().Msg("Unifi password is not set")
	}

	useIPV6 = viper.GetBool("unifi_ipv6")

	all := viper.AllSettings()
	delete(all, "unifi_pass")

	log.Printf("Using config: %+v", all)
}
