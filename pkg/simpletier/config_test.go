package simpletier

import (
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{
		Listen:    []string{"tcp://127.0.0.1:23456"},
		Upstreams: []string{"tcp://peer.example:34567"},
		Network:   NetworkConfig{Name: "test-network", CIDR: "10.20.0.0/24", Token: "secret"},
		Options:   RuntimeOptions{FixedIP: "10.20.0.7"},
	}
}

func TestNormalizeConfigValidatesAndCopies(t *testing.T) {
	cfg := validConfig()
	got, err := normalizeConfig(cfg)
	if err != nil {
		t.Fatalf("normalizeConfig() error = %v", err)
	}
	if got.networkPrefix != netip.MustParsePrefix("10.20.0.0/24") || got.fixedIP != netip.MustParseAddr("10.20.0.7") {
		t.Fatalf("normalized network = %v / %v", got.networkPrefix, got.fixedIP)
	}
	if got.listen[0] != (carrierAddress{host: "127.0.0.1", port: 23456}) || got.upstreams[0] != (carrierAddress{host: "peer.example", port: 34567}) {
		t.Fatalf("normalized endpoints = %#v / %#v", got.listen, got.upstreams)
	}
	cfg.Listen[0] = "tcp://changed.example:1"
	if got.config.Listen[0] != "tcp://127.0.0.1:23456" {
		t.Fatal("normalized config aliases caller-owned slice")
	}
}

func TestNormalizeConfigDefaultsRelayAndPreservesExplicitFalse(t *testing.T) {
	cfg := validConfig()
	got, err := normalizeConfig(cfg)
	if err != nil {
		t.Fatalf("normalizeConfig() error = %v", err)
	}
	if got.config.Options.Relay == nil || !*got.config.Options.Relay {
		t.Fatal("nil relay option did not normalize to the documented true default")
	}

	noRelay := false
	cfg.Options.Relay = &noRelay
	got, err = normalizeConfig(cfg)
	if err != nil {
		t.Fatalf("normalizeConfig() with relay=false error = %v", err)
	}
	if got.config.Options.Relay == nil || *got.config.Options.Relay {
		t.Fatal("explicit relay=false was not preserved")
	}
}

func TestNormalizeConfigLogLevel(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  slog.Level
	}{
		{"", slog.LevelInfo},
		{"debug", slog.LevelDebug},
		{"INFO", slog.LevelInfo},
		{"WaRn", slog.LevelWarn},
		{"error", slog.LevelError},
	} {
		cfg := validConfig()
		cfg.Options.LogLevel = tt.value
		got, err := normalizeConfig(cfg)
		if err != nil {
			t.Fatalf("normalizeConfig(log_level=%q): %v", tt.value, err)
		}
		if got.logLevel != tt.want {
			t.Errorf("log level for %q = %v; want %v", tt.value, got.logLevel, tt.want)
		}
	}
}

func TestNormalizeConfigKeepsSDKValuesLiteralAndAllowsNoUpstreams(t *testing.T) {
	cfg := validConfig()
	cfg.Upstreams = nil
	cfg.Network.Name = " ${NETWORK_NAME} "
	cfg.Network.Token = "${NETWORK_TOKEN}"
	got, err := normalizeConfig(cfg)
	if err != nil {
		t.Fatalf("normalizeConfig() error = %v", err)
	}
	if got.config.Network.Name != cfg.Network.Name || got.config.Network.Token != cfg.Network.Token {
		t.Fatalf("SDK config strings were expanded or normalized: %#v", got.config.Network)
	}
	if len(got.upstreams) != 0 {
		t.Fatalf("upstreams = %#v; want empty", got.upstreams)
	}
}

func TestNormalizeConfigAllowsFixedIPEdges(t *testing.T) {
	for _, tt := range []struct{ cidr, ip string }{
		{"10.0.0.0/24", "10.0.0.1"},
		{"192.0.2.0/31", "192.0.2.0"},
		{"192.0.2.0/31", "192.0.2.1"},
		{"192.0.2.9/32", "192.0.2.9"},
	} {
		cfg := validConfig()
		cfg.Network.CIDR, cfg.Options.FixedIP = tt.cidr, tt.ip
		if _, err := normalizeConfig(cfg); err != nil {
			t.Errorf("normalizeConfig(%q, %q): %v", tt.cidr, tt.ip, err)
		}
	}
}

func TestNormalizeConfigRejectsInvalidFields(t *testing.T) {
	cases := []struct {
		name, field string
		mutate      func(*Config)
	}{
		{"empty name", "network.name", func(c *Config) { c.Network.Name = "" }},
		{"NUL name", "network.name", func(c *Config) { c.Network.Name = "a\x00b" }},
		{"invalid UTF-8 name", "network.name", func(c *Config) { c.Network.Name = string([]byte{0xff}) }},
		{"empty token", "network.token", func(c *Config) { c.Network.Token = "" }},
		{"unknown log level", "options.log_level", func(c *Config) { c.Options.LogLevel = "trace" }},
		{"IPv6 CIDR", "network.cidr", func(c *Config) { c.Network.CIDR = "fd00::/64" }},
		{"default route", "network.cidr", func(c *Config) { c.Network.CIDR = "0.0.0.0/0" }},
		{"noncanonical CIDR", "network.cidr", func(c *Config) { c.Network.CIDR = "10.20.0.1/24" }},
		{"fixed IP network address", "options.fixed_ip", func(c *Config) { c.Options.FixedIP = "10.20.0.0" }},
		{"fixed IP broadcast", "options.fixed_ip", func(c *Config) { c.Options.FixedIP = "10.20.0.255" }},
		{"fixed IP outside pool", "options.fixed_ip", func(c *Config) { c.Options.FixedIP = "10.20.1.1" }},
		{"wrong carrier scheme", "listen", func(c *Config) { c.Listen = []string{"udp://127.0.0.1:1234"} }},
		{"empty listen host", "listen", func(c *Config) { c.Listen = []string{"tcp://:1234"} }},
		{"zero listen port", "listen", func(c *Config) { c.Listen = []string{"tcp://127.0.0.1:0"} }},
		{"invalid port", "listen", func(c *Config) { c.Listen = []string{"tcp://127.0.0.1:65536"} }},
		{"listen URL path", "listen", func(c *Config) { c.Listen = []string{"tcp://127.0.0.1:1234/path"} }},
		{"listen empty query", "listen", func(c *Config) { c.Listen = []string{"tcp://127.0.0.1:1234?"} }},
		{"listen empty fragment", "listen", func(c *Config) { c.Listen = []string{"tcp://127.0.0.1:1234#"} }},
		{"upstream zero port", "upstreams", func(c *Config) { c.Upstreams = []string{"tcp://peer.example:0"} }},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			_, err := normalizeConfig(cfg)
			if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("normalizeConfig() error = %v; want ErrInvalidConfig for %s", err, tt.field)
			}
		})
	}
}
