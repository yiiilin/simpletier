package simpletier

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/yiiilin/simpletier/internal/security"
)

var ErrInvalidConfig = errors.New("invalid config")

type Config struct {
	Listen    []string
	Upstreams []string
	// Targets use host-provided Connectors; their physical endpoint syntax is opaque to core.
	Targets []ConnectionTarget
	Network NetworkConfig
	Options RuntimeOptions
}

type NetworkConfig struct {
	Name  string
	CIDR  string
	Token string
}

type RuntimeOptions struct {
	FixedIP  string
	Relay    *bool
	LogLevel string
	// RateLimit enables the connection-admission flood guard (per-source and
	// per-listener handshake budgets). It is off by default.
	//
	// The guard exists so a single peer cannot open unbounded Links per second or
	// exhaust a listener's handshake slots. That matters for a node accepting
	// arbitrary internet peers, and works against a deployment that legitimately
	// admits many peers from one address in a short window — a room relay behind a
	// load balancer, a benchmark driving thousands of peers over loopback, or a
	// fleet booting at once from one egress IP. Those deployments set this true
	// knowing they are relying on their own upstream protection instead.
	//
	// Nil keeps the default, which is off. It is a pointer so an explicit false and
	// an unset value are distinguishable.
	RateLimit *bool
}

// rateLimitEnabled reports whether the connection-admission guard should run. The
// zero value is false: no guard unless asked for.
func (o RuntimeOptions) rateLimitEnabled() bool {
	return o.RateLimit != nil && *o.RateLimit
}

type carrierAddress struct {
	host string
	port uint16
}

type normalizedConfig struct {
	config         Config
	networkContext security.NetworkContext
	networkPSK     [32]byte
	networkPrefix  netip.Prefix
	fixedIP        netip.Addr
	listen         []carrierAddress
	upstreams      []carrierAddress
	logLevel       slog.Level
}

func normalizeConfig(cfg Config) (normalizedConfig, error) {
	for _, target := range cfg.Targets {
		if nilValue(target.Connector) {
			return normalizedConfig{}, invalidConfig("targets", "each target must have a non-nil Connector")
		}
		if target.Endpoint == "" {
			return normalizedConfig{}, invalidConfig("targets", "each target must have a nonempty physical endpoint")
		}
	}
	if cfg.Network.Name == "" || !utf8.ValidString(cfg.Network.Name) || strings.IndexByte(cfg.Network.Name, 0) >= 0 {
		return normalizedConfig{}, invalidConfig("network.name", "must be nonempty valid UTF-8 without NUL")
	}
	if cfg.Network.Token == "" {
		return normalizedConfig{}, invalidConfig("network.token", "must be nonempty")
	}

	prefix, err := netip.ParsePrefix(cfg.Network.CIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 1 || prefix.Bits() > 32 || prefix != prefix.Masked() || prefix.String() != cfg.Network.CIDR {
		return normalizedConfig{}, invalidConfig("network.cidr", "must be a canonical IPv4 prefix with length 1..32")
	}

	normalized := normalizedConfig{config: cloneConfig(cfg), networkPrefix: prefix}
	if normalized.config.Options.Relay == nil {
		relay := true
		normalized.config.Options.Relay = &relay
	}
	switch strings.ToLower(cfg.Options.LogLevel) {
	case "":
		normalized.logLevel = slog.LevelInfo
	case "debug":
		normalized.logLevel = slog.LevelDebug
	case "info":
		normalized.logLevel = slog.LevelInfo
	case "warn":
		normalized.logLevel = slog.LevelWarn
	case "error":
		normalized.logLevel = slog.LevelError
	default:
		return normalizedConfig{}, invalidConfig("options.log_level", "must be debug, info, warn, or error")
	}
	if cfg.Options.FixedIP != "" {
		addr, err := netip.ParseAddr(cfg.Options.FixedIP)
		if err != nil || !addr.Is4() || !prefix.Contains(addr) || !usableHost(prefix, addr) {
			return normalizedConfig{}, invalidConfig("options.fixed_ip", "must be a usable IPv4 host in network.cidr")
		}
		normalized.fixedIP = addr
	}

	normalized.listen = make([]carrierAddress, 0, len(cfg.Listen))
	for _, raw := range cfg.Listen {
		addr, err := parseCarrierAddress(raw)
		if err != nil {
			return normalizedConfig{}, invalidConfig("listen", "each entry must be tcp://host:port with explicit host and port 1..65535")
		}
		normalized.listen = append(normalized.listen, addr)
	}
	normalized.upstreams = make([]carrierAddress, 0, len(cfg.Upstreams))
	for _, raw := range cfg.Upstreams {
		addr, err := parseCarrierAddress(raw)
		if err != nil {
			return normalizedConfig{}, invalidConfig("upstreams", "each entry must be tcp://host:port with explicit host and port 1..65535")
		}
		normalized.upstreams = append(normalized.upstreams, addr)
	}
	preparedContext, err := security.NewNetworkContext(cfg.Network.Name, cfg.Network.CIDR)
	if err != nil {
		return normalizedConfig{}, invalidConfig("network", "cannot prepare network context")
	}
	preparedPSK, err := preparedContext.DerivePSK(cfg.Network.Token)
	if err != nil {
		return normalizedConfig{}, invalidConfig("network.token", "cannot prepare network PSK")
	}
	normalized.networkContext = preparedContext
	normalized.networkPSK = preparedPSK
	return normalized, nil
}

func cloneConfig(cfg Config) Config {
	cfg.Listen = append([]string(nil), cfg.Listen...)
	cfg.Upstreams = append([]string(nil), cfg.Upstreams...)
	cfg.Targets = append([]ConnectionTarget(nil), cfg.Targets...)
	if cfg.Options.Relay != nil {
		relay := *cfg.Options.Relay
		cfg.Options.Relay = &relay
	}
	return cfg
}

func parseCarrierAddress(raw string) (carrierAddress, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "tcp" || u.Opaque != "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsRune(raw, '#') {
		return carrierAddress{}, errors.New("invalid TCP carrier URL")
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" {
		return carrierAddress{}, errors.New("carrier URL requires explicit host and port")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return carrierAddress{}, errors.New("carrier port must be in range 1..65535")
	}
	return carrierAddress{host: host, port: uint16(port)}, nil
}

func usableHost(prefix netip.Prefix, addr netip.Addr) bool {
	if prefix.Bits() >= 31 {
		return true
	}
	networkBytes := prefix.Masked().Addr().As4()
	addressBytes := addr.As4()
	network := binary.BigEndian.Uint32(networkBytes[:])
	address := binary.BigEndian.Uint32(addressBytes[:])
	mask := uint32(0xffffffff) << uint(32-prefix.Bits())
	broadcast := network | ^mask
	return address != network && address != broadcast
}

func invalidConfig(field, reason string) error {
	return fmt.Errorf("%s: %s: %w", field, reason, ErrInvalidConfig)
}

// Validate checks Config without performing network or filesystem side effects.
func (cfg Config) Validate() error {
	_, err := normalizeConfig(cfg)
	return err
}
