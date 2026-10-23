package simpletier

import (
	"errors"
	"testing"
)

func validAgentConfig() AgentConfig {
	tun := true
	return AgentConfig{
		Config: validConfig(),
		// TUN requires an explicit device name; a crash leaves only that name behind.
		DeviceName: "st-valid0",
		Inbounds: AgentInbounds{
			TUN: &tun,
			SOCKS5: &ProxyConfig{
				Listen:   "127.0.0.1:1080",
				Username: "alice",
				Password: "secret",
			},
		},
	}
}

func TestAgentConfigValidateAllowsTypedValuesLiterally(t *testing.T) {
	cfg := validAgentConfig()
	cfg.Network.Token = "${TOKEN}"
	cfg.Inbounds.SOCKS5.Username = "${USER}"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("AgentConfig.Validate() error = %v", err)
	}
	if cfg.Network.Token != "${TOKEN}" || cfg.Inbounds.SOCKS5.Username != "${USER}" {
		t.Fatal("typed SDK config values were rewritten")
	}
}

func TestAgentConfigValidateAllowsNoInbounds(t *testing.T) {
	cfg := AgentConfig{Config: validConfig()}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("AgentConfig.Validate() error = %v", err)
	}
}

func TestAgentConfigValidateRejectsIncompleteProxy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proxy *ProxyConfig
	}{
		{name: "missing listen", proxy: &ProxyConfig{Username: "alice", Password: "secret"}},
		{name: "missing username", proxy: &ProxyConfig{Listen: "127.0.0.1:1080", Password: "secret"}},
		{name: "missing password", proxy: &ProxyConfig{Listen: "127.0.0.1:1080", Username: "alice"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := AgentConfig{Config: validConfig(), Inbounds: AgentInbounds{SOCKS5: tc.proxy}}
			if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("AgentConfig.Validate() error = %v; want ErrInvalidConfig", err)
			}
		})
	}
}

func TestAgentConfigValidateRejectsInvalidCoreConfig(t *testing.T) {
	cfg := validAgentConfig()
	cfg.Network.Token = ""
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("AgentConfig.Validate() error = %v; want ErrInvalidConfig", err)
	}
}
