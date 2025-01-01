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
	maxGroupSize          int
	ipv4StartRuleIndex    int
	ipv6StartRuleIndex    int
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
	viper.BindEnv("unifi_max_group_size")
	viper.SetDefault("unifi_max_group_size", 10000)
	viper.BindEnv("unifi_ipv4_start_rule_index")
	viper.SetDefault("unifi_ipv4_start_rule_index", 20000)
	viper.BindEnv("unifi_ipv6_start_rule_index")
	viper.SetDefault("unifi_ipv6_start_rule_index", 25000)
	viper.BindEnv("unifi_max_group_size")
	viper.SetDefault("unifi_max_group_size", 10000)
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

	unifiSite = viper.GetString("unifi_site")

	useIPV6 = viper.GetBool("unifi_ipv6")

	maxGroupSize = viper.GetInt("unifi_max_group_size")

	ipv4StartRuleIndex = viper.GetInt("unifi_ipv4_start_rule_index")
	ipv6StartRuleIndex = viper.GetInt("unifi_ipv6_start_rule_index")

	all := viper.AllSettings()
	delete(all, "unifi_pass")

	log.Printf("Using config: %+v", all)
}
