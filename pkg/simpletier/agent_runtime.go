package simpletier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/yiiilin/simpletier/internal/agent"
)

// The Agent wrapper is the additive, SDK-facing way to run the host adapters
// (TUN device, SOCKS5/HTTP proxy inbounds) on top of one Network. NewNetwork
// stays exactly as it is and never opens a host resource: a caller opts in by
// constructing an Agent with the same Config plus AgentInbounds.

// PacketDevice, SystemNetwork and AgentStats alias the internal adapter types so
// an SDK caller can use them without importing anything under internal/.
type (
	// PacketDevice is one complete-packet L3 device (TUN/Wintun/utun).
	PacketDevice = agent.PacketDevice
	// DeviceReporter is the optional capability of a PacketDevice backend to
	// report its concrete platform metadata. A caller that names the device
	// (AgentConfig.DeviceName) needs to read back which interface actually
	// opened, so this is part of the public surface.
	DeviceReporter = agent.DeviceReporter
	// DeviceInfo is the metadata a DeviceReporter returns.
	DeviceInfo = agent.DeviceInfo
	// SystemNetwork is the host address/route transaction owner of the device.
	SystemNetwork = agent.SystemNetwork
	// AgentStats reports proxy ingress counters.
	AgentStats = agent.Stats
)

// Agent owns one Network plus the optional host adapters of an AgentConfig.
// Close releases both; Done closes when the Network or an adapter stops, and a
// watcher then releases the other side so neither is left running.
type Agent struct {
	network Network
	inner   *agent.Agent

	startMu sync.Mutex
	started bool

	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// NewAgent validates the configuration, creates the Network and maps the
// enabled inbounds onto the internal agent adapter. It opens no bare TUN device:
// with Inbounds.TUN absent or false no L3 device is created (D-DOC-021). It does
// create the Network, which owns the configured carrier listeners and data
// plane, so "no host I/O" means specifically "no packet device" here.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	handle, err := NewNetwork(cfg.Config)
	if err != nil {
		return nil, err
	}
	n, ok := handle.(*network)
	if !ok || n == nil {
		_ = handle.Close()
		return nil, fmt.Errorf("%w: unexpected Network implementation", ErrInvalidConfig)
	}

	inbounds := agent.Inbounds{TUN: cfg.Inbounds.TUN}
	if cfg.Inbounds.SOCKS5 != nil {
		inbounds.SOCKS5 = &agent.ProxyConfig{
			Listen:   cfg.Inbounds.SOCKS5.Listen,
			Username: cfg.Inbounds.SOCKS5.Username,
			Password: cfg.Inbounds.SOCKS5.Password,
		}
	}
	if cfg.Inbounds.HTTPProxy != nil {
		inbounds.HTTPProxy = &agent.ProxyConfig{
			Listen:   cfg.Inbounds.HTTPProxy.Listen,
			Username: cfg.Inbounds.HTTPProxy.Username,
			Password: cfg.Inbounds.HTTPProxy.Password,
		}
	}

	inner, err := agent.New(agent.AgentConfig{
		Inbounds: inbounds,
		Device: agent.DeviceConfig{
			Name:    cfg.DeviceName,
			Address: netip.PrefixFrom(n.localVirtualIP(), 32),
			Routes:  overlayDeviceRoutes(n),
			// No path: runtime state is process-local, so the host-network journal
			// stays in memory. A crash loses it either way, and there is no writable
			// directory to point at.
			JournalPath: "",
		},
	}, agent.Deps{
		Dialer: agent.DialerFunc(func(ctx context.Context, networkName, address string) (net.Conn, error) {
			return n.DialContext(ctx, networkName, address)
		}),
		TargetResolver:  &agentTargetResolver{n: n},
		DatagramBackend: newAgentDatagramBackend(n.streams),
	})
	if err != nil {
		_ = handle.Close()
		return nil, err
	}
	a := &Agent{network: handle, inner: inner, done: make(chan struct{})}
	// Register the optional host-address mover. An automatic loser reallocation
	// calls it before it publishes the new VirtualIP, so the live device moves
	// before peers can be told about the new address, and a failed move publishes
	// nothing.
	n.setAddressApply(func(ctx context.Context, vip netip.Addr) error {
		return inner.RetargetAddress(ctx, netip.PrefixFrom(vip, 32))
	})
	go a.watchDone()
	return a, nil
}

// overlayDeviceRoutes returns the overlay CIDR route to install on an opened
// device so every virtual peer is reached through the TUN rather than the host
// default route. It is empty when the prefix is invalid.
func overlayDeviceRoutes(n *network) []netip.Prefix {
	if n == nil || !n.normalized.networkPrefix.IsValid() {
		return nil
	}
	return []netip.Prefix{n.normalized.networkPrefix}
}

// watchDone closes the Agent's Done channel as soon as either the Network or the
// inner adapter stops, and then releases the other side so a stopped component
// never leaves its owner running.
func (a *Agent) watchDone() {
	if a == nil {
		return
	}
	defer close(a.done)
	networkDone := a.network.Done()
	var innerDone <-chan struct{}
	if a.inner != nil {
		innerDone = a.inner.Done()
	}
	select {
	case <-networkDone:
	case <-innerDone:
	}
	_ = a.Close()
}

// Start starts the host adapters and, when a TUN device was opened, attaches it
// to this Network's packet plane (the same production packet path as NewNetwork
// plus an explicit device). It is idempotent: a repeated Start is a no-op, and a
// failure after the inner adapters started rolls the whole Agent back so no
// device, listener or data-plane service is left half-installed.
func (a *Agent) Start(ctx context.Context) error {
	if a == nil || a.inner == nil {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	a.startMu.Lock()
	defer a.startMu.Unlock()
	select {
	case <-a.done:
		// Either the Network or an adapter already stopped: the Agent is spent
		// and must not report a successful Start.
		return ErrClosed
	default:
	}
	if a.started {
		return nil
	}
	// The address NewAgent handed to the inner adapter is a snapshot taken before
	// Start. An automatic reallocation may have moved the Network's VirtualIP in
	// between, so refresh the configuration Start will consume first; before the
	// device exists this is a configuration-only retarget that keeps the same
	// metadata, and after a restart it is still the same TUN FD.
	if current := a.network.LocalVirtualIP(); current.IsValid() {
		if err := a.inner.RetargetAddress(ctx, netip.PrefixFrom(current, 32)); err != nil {
			return err
		}
	}
	if err := a.inner.Start(ctx); err != nil {
		// A concurrent/repeated inner Start is a successful start from this
		// wrapper's point of view; every other failure is terminal.
		if !errors.Is(err, agent.ErrAlreadyStarted) {
			return err
		}
	}
	device := a.inner.PacketDevice()
	if device == nil {
		a.started = true
		return nil
	}
	n, ok := a.network.(*network)
	if !ok || n == nil || n.streams == nil {
		a.rollbackStart()
		return ErrClosed
	}
	if err := n.streams.enablePacketService(device); err != nil {
		a.rollbackStart()
		return err
	}
	n.streams.startPacketDevice()
	a.started = true
	return nil
}

// rollbackStart releases everything a failed Start already started: the host
// adapters (including the opened device and proxy listeners) and the Network.
func (a *Agent) rollbackStart() {
	if a.inner != nil {
		_ = a.inner.Close()
	}
	if a.network != nil {
		_ = a.network.Close()
	}
}

// Close closes the adapters and the Network, exactly once.
func (a *Agent) Close() error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		var errs []error
		if a.inner != nil {
			errs = append(errs, a.inner.Close())
		}
		if a.network != nil {
			errs = append(errs, a.network.Close())
		}
		a.closeErr = errors.Join(errs...)
	})
	return a.closeErr
}

// Done closes when either the underlying Network or an inner adapter stops. The
// watcher then releases the other side, so the two never outlive each other.
func (a *Agent) Done() <-chan struct{} {
	if a == nil || a.done == nil {
		return nil
	}
	return a.done
}

// Network returns the Network this Agent owns.
func (a *Agent) Network() Network {
	if a == nil {
		return nil
	}
	return a.network
}

// LocalVirtualIP returns this Agent's selected VirtualIP/32.
func (a *Agent) LocalVirtualIP() netip.Addr {
	if a == nil || a.network == nil {
		return netip.Addr{}
	}
	return a.network.LocalVirtualIP()
}

// PacketDevice returns the opened L3 device, or nil when TUN is disabled or the
// Agent has not started.
func (a *Agent) PacketDevice() PacketDevice {
	if a == nil || a.inner == nil {
		return nil
	}
	return a.inner.PacketDevice()
}

// SystemNetwork returns the host network transaction owner, or nil when TUN is
// disabled or the Agent has not started.
func (a *Agent) SystemNetwork() SystemNetwork {
	if a == nil || a.inner == nil {
		return nil
	}
	return a.inner.SystemNetwork()
}

// Stats reports proxy ingress counters.
func (a *Agent) Stats() AgentStats {
	if a == nil || a.inner == nil {
		return AgentStats{}
	}
	return a.inner.Stats()
}

// ProxyAddrs returns the bound SOCKS5 and HTTP proxy listener addresses, or nil
// for an inbound that is not configured or not started yet. It is how a caller
// that listens on an ephemeral port learns the real address to connect to.
func (a *Agent) ProxyAddrs() (socks5, http net.Addr) {
	if a == nil || a.inner == nil {
		return nil, nil
	}
	return a.inner.ListenAddrs()
}

// agentTargetResolver enforces the overlay-only target policy: a domain is
// resolved once to IPv4 and must name a current virtual-CIDR owner; a literal
// address must already be inside the overlay CIDR and owned by a live address
// fact. No public/LAN or default-gateway target is ever dialed.
type agentTargetResolver struct{ n *network }

func (r *agentTargetResolver) ResolveTarget(ctx context.Context, host string, port uint16) (netip.AddrPort, error) {
	if r == nil || r.n == nil {
		return netip.AddrPort{}, ErrNoRoute
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return netip.AddrPort{}, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		resolved, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if lookupErr != nil || len(resolved) == 0 {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return netip.AddrPort{}, ctxErr
			}
			return netip.AddrPort{}, fmt.Errorf("%w: %s", ErrNoRoute, host)
		}
		addr = resolved[0]
	}
	if !addr.Is4() {
		return netip.AddrPort{}, fmt.Errorf("%w: target %s is not IPv4", ErrNoRoute, host)
	}
	if !r.n.normalized.networkPrefix.Contains(addr) {
		return netip.AddrPort{}, fmt.Errorf("%w: target %s is outside the overlay CIDR", ErrPermissionDenied, addr)
	}
	if r.n.facts == nil || r.n.facts.routes == nil {
		return netip.AddrPort{}, ErrNoRoute
	}
	if _, err := r.n.facts.routes.ResolveVirtualIP(addr); err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %v", ErrNoRoute, err)
	}
	return netip.AddrPortFrom(addr, port), nil
}
