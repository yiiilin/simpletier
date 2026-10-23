package simpletier

import "github.com/yiiilin/simpletier/internal/agent"

// AgentConfig is the typed SDK configuration for explicit Agent services.
// It is separate from Config so NewNetwork cannot create host resources.
type AgentConfig struct {
	Config
	Inbounds AgentInbounds
	// DeviceName names the L3 device the Agent opens when Inbounds.TUN is true, and is
	// required in that case.
	//
	// A TUN device installs an interface and routes in the host's network stack, and those
	// outlive a process that is killed. The name is the only handle the next run has to
	// find them by, so it cannot be left to the platform: a platform-chosen name (tunN,
	// utunN) is not stable across a restart.
	//
	// Distinct names also keep several Agents on one host apart, since platform adapter
	// names are host-global.
	//
	// It has no effect when Inbounds.TUN is absent or false.
	DeviceName string
}

// AgentInbounds controls optional host and proxy integrations.
type AgentInbounds struct {
	TUN       *bool
	SOCKS5    *ProxyConfig
	HTTPProxy *ProxyConfig
}

// ProxyConfig describes one credentialed local or remote proxy listener.
type ProxyConfig struct {
	Listen   string
	Username string
	Password string
}

// Validate checks core and explicitly enabled Agent configuration without side effects.
func (cfg AgentConfig) Validate() error {
	if err := cfg.Config.Validate(); err != nil {
		return err
	}
	for _, entry := range []struct {
		name  string
		proxy *ProxyConfig
	}{
		{name: "socks5", proxy: cfg.Inbounds.SOCKS5},
		{name: "http_proxy", proxy: cfg.Inbounds.HTTPProxy},
	} {
		if entry.proxy != nil && (entry.proxy.Listen == "" || entry.proxy.Username == "" || entry.proxy.Password == "") {
			return invalidConfig("inbounds."+entry.name, "listen, username, and password are required")
		}
	}
	if err := validateDeviceName(cfg.DeviceName); err != nil {
		return err
	}
	if cfg.Inbounds.TUN != nil && *cfg.Inbounds.TUN && cfg.DeviceName == "" {
		return invalidConfig("device_name", "a TUN device requires an explicit name")
	}
	return nil
}

// validateDeviceName checks a requested device name against the platform's
// printable-name rule. The Agent's own device config applies the same rule, so
// an invalid name is rejected at configuration time rather than when the
// device is opened.
func validateDeviceName(name string) error {
	if name == "" {
		return nil
	}
	if !agent.PrintableDeviceName(name) {
		return invalidConfig("device_name", "the device name must be a printable, non-empty name")
	}
	return nil
}
