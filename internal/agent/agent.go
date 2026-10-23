// Package agent owns the SimpleTier Agent service boundary: the typed inbound
// configuration, the authenticated proxy listeners, the packet/host ports for
// the future L3 data plane, and the listener lifecycle that the pkg-level Agent
// will drive.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Requirements owned here: R-MESH-002, R-MESH-003, R-MESH-004, R-MESH-006,
// plus R-L3-001 for the packet/host ports, whose L3 specification lives in
// docs/domains/overlay/features/l3-vpn.md (that document owns internal/packet,
// internal/host and internal/sysnet, not this package).
//
// # Current implementation boundary
//
// This slice is a production-wireable set of ports and adapters, not a finished
// Agent and not an overlay data plane. It must not be described as if the
// overlay path worked:
//
//   - SOCKS5 RFC 1929 username/password authentication, CONNECT and UDP
//     ASSOCIATE are real and covered by tests against local TCP listeners, real
//     local UDP sockets and net.Pipe. BIND is answered with the RFC 1928
//     "command not supported" reply (0x07). UDP ASSOCIATE additionally needs an
//     injected DatagramBackend; an entry without one reports the command as
//     unsupported instead of silently succeeding.
//   - HTTP CONNECT with mandatory Proxy-Authorization: Basic (RFC 7617) is real,
//     and normal forward-proxy requests (an http absolute-form URI or an
//     origin-form request with a valid Host) are streamed to the target without
//     buffering the body. Chunked request/response framing, a bounded
//     Expect: 100-continue and hop-by-hop/Proxy-Authorization stripping are
//     implemented. WebSocket rides through CONNECT opaquely; there is no HTTPS
//     man-in-the-middle.
//   - Target resolution and every outbound TCP connection go through the
//     injected Dialer port. The library never dials a default of its own, because
//     proxied traffic must use the running node's identity and overlay policy.
//     The pkg-level wiring does not exist yet: pkg/simpletier's
//     Network.DialContext currently returns ErrNoRoute because RouteView,
//     Path/Session/Circuit and remote Streams are unimplemented. A wired agent
//     would therefore authenticate clients and then fail every CONNECT with a
//     dial-failure reply.
//   - PacketDevice, HostAdapter and SystemNetwork have real platform backends
//     (Linux TUN, Windows Wintun, macOS utun). inbounds.tun: true opens the
//     platform device before any listener is bound and fails loudly with
//     ErrPlatformUnavailable when the device, driver, permission or entitlement
//     is missing; it never silently degrades to TCP-only. See device.go for the
//     backend map and the per-GOOS files for the platform work. What is still
//     missing is the packet plane: nothing reads or forwards packets between
//     devices, no capability is published, and cross-compiling is still not
//     platform acceptance (Windows/macOS runtime is unverified here).
//
// # Outbound policy enforcement point
//
// With no Deps.TargetResolver configured, the enforcement point for the virtual
// CIDR, the single-IPv4 name resolution and the DNS-rebinding check is the
// injected Dialer (and, for datagrams, the injected DatagramBackend): this
// package forwards the requested host:port unchanged. That is the current
// default and it is why the pkg-level runtime adapter, which knows the local CIDR
// and owns NetworkDial plus the validated address, must be wired before the
// proxy is a policy boundary.
//
// When Deps.TargetResolver is configured the proxy becomes the enforcement
// point: every SOCKS5 CONNECT/UDP destination, HTTP CONNECT authority and normal
// HTTP origin is authorised and resolved to exactly one IPv4 endpoint before the
// Dialer or DatagramBackend sees it, and the proxy then uses that exact endpoint
// so a name cannot rebind between the check and the dial. A resolver error is
// fail-closed: the request is refused and counted as PolicyDenied, never retried
// around the policy.
//
//   - UDP target traffic goes only through the injected DatagramBackend; this
//     package never opens an outbound UDP socket of its own. The local relay
//     socket behind a SOCKS5 UDP BND.ADDR/BND.PORT is inbound-facing.
//   - Credential failures are answered with the protocol-standard replies and
//     counted. A per-entry failure budget, derived from that entry's connection
//     limit and handshake timeout, refuses further authentication work once it is
//     exhausted inside the window (Throttled).
package agent

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Sentinel errors returned by this package. Protocol-level failures inside the
// proxy handlers (ErrAuthentication, ErrUnsupported) are reported to the client
// through the protocol replies and counted in Stats; the pkg-level wiring does
// not surface them as call errors yet.
var (
	// ErrClosed reports use of an Agent after Close, or Close before Start
	// followed by Start.
	ErrClosed = errors.New("agent: closed")
	// ErrAlreadyStarted reports a second Start on a running Agent.
	ErrAlreadyStarted = errors.New("agent: already started")
	// ErrCloseTimeout reports that handler goroutines did not stop within the
	// bounded Close drain.
	ErrCloseTimeout = errors.New("agent: close timeout")
	// ErrInvalidConfig reports a typed configuration value that the Agent
	// refuses before any side effect.
	ErrInvalidConfig = errors.New("agent: invalid config")
	// ErrNoDialer reports that a proxy inbound was configured without the
	// target Dialer port.
	ErrNoDialer = errors.New("agent: target dialer is required")
	// ErrTargetDenied reports that a configured TargetResolver refused a proxy
	// target, or resolved it to something that is not a definite IPv4 endpoint.
	// It is fail-closed: the request is never retried around the policy.
	ErrTargetDenied = errors.New("agent: proxy target denied by outbound policy")
	// ErrAuthentication is the protocol-level identity of a rejected proxy
	// client: no acceptable method, malformed credentials or wrong credentials.
	ErrAuthentication = errors.New("agent: proxy authentication failed")
	// ErrUnsupported is the protocol-level identity of a request this slice
	// refuses to half implement: SOCKS5 BIND/UDP ASSOCIATE, IPv6 targets and
	// unknown address types.
	ErrUnsupported = errors.New("agent: unsupported")
	// ErrPlatformUnavailable reports that no host adapter can be resolved or
	// opened for the effective platform: an unknown platform, a backend that
	// belongs to another GOOS build, a missing device node/driver/library, or a
	// missing permission or entitlement. It carries an actionable detail; see
	// ErrDriverMissing for the driver/library case.
	ErrPlatformUnavailable = errors.New("agent: platform backend unavailable")
)

const (
	// MaxProxyConnections is the P1 hard initial value for concurrent proxy
	// ingress connections (FEAT-MULTIPROTOCOL-OVERLAY 3.8). It is enforced
	// Agent-wide across all enabled proxy inbounds; a per-entry option may lower
	// it but never raise it.
	MaxProxyConnections = 256

	// DefaultDeviceMTU is the internal virtual device MTU. It is not user
	// configurable (D-L3-004) and every backend configures exactly this value
	// unless the caller asks for a smaller one inside MinDeviceMTU..DefaultDeviceMTU.
	DefaultDeviceMTU = 1380

	defaultHandshakeTimeout = 10 * time.Second
	defaultDialTimeout      = 10 * time.Second
	closeDrainTimeout       = 5 * time.Second
	rejectWriteTimeout      = 2 * time.Second
	relayBufferSize         = 32 << 10
	acceptBackoffMin        = 5 * time.Millisecond
	acceptBackoffMax        = time.Second
)

// Dialer is the target-connection port for both proxy inbounds.
//
// Hosts inject it; the Agent never dials a default of its own. pkg/simpletier's
// Network satisfies this port through a small adapter in the future pkg-level
// wiring, because Go has no covariant return types:
//
//	type networkDialer struct{ network simpletier.Network }
//
//	func (d networkDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
//		return d.network.DialContext(ctx, network, address)
//	}
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialerFunc adapts a function to Dialer.
type DialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DialContext implements Dialer.
func (f DialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if f == nil {
		return nil, ErrNoDialer
	}
	return f(ctx, network, address)
}

// TargetResolver is the optional outbound policy and name-resolution port. A
// runtime adapter implements it over the local virtual CIDR and the single-IPv4
// resolver, which this standalone package cannot know.
//
// When configured it is the policy enforcement point for every proxy target:
// ResolveTarget authorises host:port and returns the exact IPv4 endpoint the
// proxy must use. The proxy dials or sends to that returned endpoint, so a name
// cannot rebind between the policy check and the dial. Returning an error fails
// the request closed (ErrTargetDenied); the proxy never falls back to a default
// dial or to the OS resolver.
//
// When nil, the target is forwarded unchanged and the injected Dialer and
// DatagramBackend own virtual-CIDR and DNS policy.
type TargetResolver interface {
	ResolveTarget(ctx context.Context, host string, port uint16) (netip.AddrPort, error)
}

// ListenFunc binds one proxy listener. The default is
// (*net.ListenConfig).Listen; hosts may inject one to own socket options or to
// embed the Agent behind an already-created listener.
type ListenFunc func(ctx context.Context, network, address string) (net.Listener, error)

// Credentials is one proxy entry's required username/password pair. Both
// proxies compare byte-exact, in constant time, and share the RFC 1929 length
// bound (1..255 bytes) because the SOCKS5 sub-negotiation transmits both values
// as single length-prefixed fields.
type Credentials struct {
	Username string
	Password string
}

// Validate reports whether the pair can be used by a proxy inbound.
func (c Credentials) Validate() error {
	if c.Username == "" {
		return invalid("username", "must not be empty; credentials are mandatory for every proxy inbound")
	}
	if c.Password == "" {
		return invalid("password", "must not be empty; credentials are mandatory for every proxy inbound")
	}
	if len(c.Username) > 255 {
		return invalid("username", "must be at most 255 bytes (RFC 1929 ULEN)")
	}
	if len(c.Password) > 255 {
		return invalid("password", "must be at most 255 bytes (RFC 1929 PLEN)")
	}
	return nil
}

// Matches reports whether the supplied pair is exactly the configured one. Both
// sides are hashed first, so a wrong-length guess does not short-circuit the
// comparison and the compared values have a fixed length.
func (c Credentials) Matches(username, password string) bool {
	// An unvalidated empty configuration must never authenticate an empty
	// client-supplied pair.
	if c.Username == "" || c.Password == "" {
		return false
	}
	wantUsername := sha256.Sum256([]byte(c.Username))
	gotUsername := sha256.Sum256([]byte(username))
	wantPassword := sha256.Sum256([]byte(c.Password))
	gotPassword := sha256.Sum256([]byte(password))
	usernameOK := subtle.ConstantTimeCompare(wantUsername[:], gotUsername[:])
	passwordOK := subtle.ConstantTimeCompare(wantPassword[:], gotPassword[:])
	return usernameOK&passwordOK == 1
}

// ProxyKind identifies one proxy inbound.
type ProxyKind string

const (
	// ProxySOCKS5 is the RFC 1928 SOCKS5 inbound.
	ProxySOCKS5 ProxyKind = "socks5"
	// ProxyHTTP is the HTTP CONNECT inbound.
	ProxyHTTP ProxyKind = "http_proxy"
)

// ProxyOptions carries bounded implementation options. Every zero value means
// "use the default"; no option may raise a P1 hard limit.
type ProxyOptions struct {
	// MaxConnections bounds concurrent ingress connections for this entry.
	// Zero means MaxProxyConnections. It may only be lowered.
	MaxConnections int
	// HandshakeTimeout bounds method negotiation, authentication and the proxy
	// request of one ingress connection. Zero means 10s. It does not bound an
	// established tunnel.
	HandshakeTimeout time.Duration
	// DialTimeout bounds one target connection attempt. Zero means 10s.
	DialTimeout time.Duration
}

// ProxyConfig describes one credentialed proxy inbound. It mirrors the public
// pkg/simpletier ProxyConfig (Listen, Username, Password) and adds bounded
// internal options; the pkg-level Agent maps the public DTO onto this type
// field by field. Credentials are per entry and are never derived from
// network.token.
type ProxyConfig struct {
	Listen   string
	Username string
	Password string
	Options  ProxyOptions
}

// Credentials returns the configured pair as a validator value.
func (c ProxyConfig) Credentials() Credentials {
	return Credentials{Username: c.Username, Password: c.Password}
}

// Validate checks one inbound without side effects.
func (c ProxyConfig) Validate(kind ProxyKind) error {
	name := string(kind)
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return invalid(name+".listen", "must be host:port: "+err.Error())
	}
	if host == "" {
		return invalid(name+".listen", "host must not be empty")
	}
	if !isDecimal(port) {
		return invalid(name+".listen", "port must be a decimal number")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 0 || number > 65535 {
		return invalid(name+".listen", "port must be between 0 and 65535 (0 selects an OS-assigned port)")
	}
	if err := c.Credentials().Validate(); err != nil {
		return fmt.Errorf("%s credentials: %w", name, err)
	}
	if c.Options.MaxConnections < 0 || c.Options.MaxConnections > MaxProxyConnections {
		return invalid(fmt.Sprintf("%s.options.max_connections", name),
			fmt.Sprintf("must be between 1 and %d; the P1 hard limit may only be lowered", MaxProxyConnections))
	}
	if c.Options.HandshakeTimeout < 0 {
		return invalid(name+".options.handshake_timeout", "must not be negative")
	}
	if c.Options.DialTimeout < 0 {
		return invalid(name+".options.dial_timeout", "must not be negative")
	}
	return nil
}

func (c ProxyConfig) handshakeTimeout() time.Duration {
	if c.Options.HandshakeTimeout > 0 {
		return c.Options.HandshakeTimeout
	}
	return defaultHandshakeTimeout
}

func (c ProxyConfig) dialTimeout() time.Duration {
	if c.Options.DialTimeout > 0 {
		return c.Options.DialTimeout
	}
	return defaultDialTimeout
}

func (c ProxyConfig) maxConnections() int {
	if c.Options.MaxConnections > 0 {
		return c.Options.MaxConnections
	}
	return MaxProxyConnections
}

// Inbounds mirrors the public pkg/simpletier AgentInbounds.
type Inbounds struct {
	// TUN opts in to the platform host adapter. Missing or false creates no
	// system device (D-DOC-021); true must fail loudly when no backend exists.
	TUN *bool
	// SOCKS5 enables the credentialed SOCKS5 inbound when non-nil.
	SOCKS5 *ProxyConfig
	// HTTPProxy enables the credentialed HTTP CONNECT inbound when non-nil.
	HTTPProxy *ProxyConfig
}

func (i Inbounds) tunEnabled() bool {
	return i.TUN != nil && *i.TUN
}

// AgentConfig is the internal typed Agent configuration. The public
// pkg/simpletier.AgentConfig already validates the same core fields; the
// pkg-level Agent maps its Inbounds onto this type. This package deliberately
// does not import pkg/simpletier so the dependency stays one-way and no import
// cycle can appear when pkg wires the Agent.
type AgentConfig struct {
	Inbounds Inbounds
	// Platform selects the host adapter family. Empty means the running host.
	Platform Platform
	// Device configures the L3 device when Inbounds.TUN is true: requested
	// interface name, local VirtualIP/32 and optional routes. It has no effect
	// when TUN is absent or false (D-DOC-021).
	Device DeviceConfig
}

// effectivePlatform resolves the configured or current host adapter family.
func (cfg AgentConfig) effectivePlatform() Platform {
	if cfg.Platform != "" {
		return cfg.Platform
	}
	return CurrentPlatform()
}

// Validate checks the typed inbound configuration without side effects.
func (cfg AgentConfig) Validate() error {
	if cfg.Platform != "" && !cfg.Platform.known() {
		return invalid("platform", fmt.Sprintf("%q is not one of linux, windows or darwin", cfg.Platform))
	}
	if err := cfg.Device.Validate(); err != nil {
		return err
	}
	if cfg.Inbounds.SOCKS5 != nil {
		if err := cfg.Inbounds.SOCKS5.Validate(ProxySOCKS5); err != nil {
			return err
		}
	}
	if cfg.Inbounds.HTTPProxy != nil {
		if err := cfg.Inbounds.HTTPProxy.Validate(ProxyHTTP); err != nil {
			return err
		}
	}
	return nil
}

// Platform identifies one host adapter family (Linux TUN, Windows Wintun, macOS
// utun). Platform differences are owned by the backend; the core only depends
// on the PacketDevice contract.
type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformWindows Platform = "windows"
	PlatformDarwin  Platform = "darwin"
)

func (p Platform) known() bool {
	switch p {
	case PlatformLinux, PlatformWindows, PlatformDarwin:
		return true
	default:
		return false
	}
}

// CurrentPlatform reports the host adapter family of the running host. It never
// probes or opens a device.
func CurrentPlatform() Platform {
	return Platform(runtime.GOOS)
}

// PacketDevice is the canonical L3 device port (FEAT-MULTIPROTOCOL-OVERLAY
// 3.2): exactly one complete IP packet per ReadPacket/WritePacket call, never a
// TAP Ethernet frame and never a TCP/UDP application message. Platform-specific
// prefixes and ring ownership (Linux IFF_NO_PI, Windows Wintun receive/release,
// macOS utun address-family prefix) are the backend's responsibility.
//
// Backends: tunDevice (Linux, device_linux.go), utunDevice (macOS,
// device_darwin.go) and wintunDevice (Windows, device_windows.go). ReadPacket
// and WritePacket observe ctx cancellation and Close without waiting for the
// device to become readable, and Close is idempotent.
type PacketDevice interface {
	ReadPacket(ctx context.Context, buf []byte) (int, error)
	WritePacket(ctx context.Context, packet []byte) error
	MTU() int
	Events() <-chan DeviceEvent
	Close() error
}

// DeviceEvent reports one platform device event. Kind values belong to the
// platform adapter contract; this slice emits "ready" once after a successful
// open and "closed" after cleanup, and reports asynchronous device errors with
// Kind "error".
type DeviceEvent struct {
	Kind string
	MTU  int
	Err  error
}

// DeviceOptions are the typed inputs for opening one platform device. MTU
// defaults to DefaultDeviceMTU and is bounded by MinDeviceMTU..DefaultDeviceMTU
// (D-L3-004: it is not a user-facing knob).
type DeviceOptions struct {
	// MTU is the requested virtual device MTU. Zero means DefaultDeviceMTU.
	MTU int
	// Name is the requested device/interface name. Empty lets the platform
	// choose (Linux tunN, Windows adapter name, macOS utunN).
	Name string
	// Address is the local overlay address that will be installed on the device. It is
	// used to recognise an interface left behind by an earlier run that did not shut down
	// cleanly: a name on its own does not prove ownership, and attaching to another
	// program's interface would tear down its network configuration.
	Address netip.Prefix
}

// HostAdapter is the platform backend port. A backend opens the platform device
// and, together with SystemNetwork, owns addresses, MTU, routes, permissions and
// cleanup. The core must never branch on the platform itself.
type HostAdapter interface {
	Platform() Platform
	Open(ctx context.Context, opts DeviceOptions) (PacketDevice, error)
}

// SystemNetworkState is the transaction state of the platform resource owner
// (FEAT-MULTIPROTOCOL-OVERLAY 3.4.1). Every OS side effect must be preceded by a
// durable write-ahead journal entry, and recovery only removes resources that
// this instance created and that still match its recorded fingerprints.
type SystemNetworkState string

const (
	SystemNetworkAbsent    SystemNetworkState = "absent"
	SystemNetworkPrepared  SystemNetworkState = "prepared"
	SystemNetworkApplied   SystemNetworkState = "applied"
	SystemNetworkRunning   SystemNetworkState = "running"
	SystemNetworkReconcile SystemNetworkState = "reconcile"
	SystemNetworkRollback  SystemNetworkState = "rollback"
	SystemNetworkDegraded  SystemNetworkState = "degraded"
	SystemNetworkClosed    SystemNetworkState = "closed"
)

// SystemNetwork is the platform transaction port. Implementations journal each
// resource intent before applying it and roll back only owned resources. See
// sysnet_linux.go for the native Linux owner and NewSystemNetwork for the
// cross-platform constructor.
type SystemNetwork interface {
	State() SystemNetworkState
	Prepare(ctx context.Context) error
	Apply(ctx context.Context) error
	Rollback(ctx context.Context) error
	Close() error
}

// ResolveHostAdapter returns the platform backend for one host adapter family.
//
// The concrete backend belongs to the GOOS it targets: a linux build resolves
// Linux TUN and refuses the Windows/macOS families with ErrPlatformUnavailable
// (their drivers cannot exist in that process). Open then performs the real
// platform work and fails with an actionable error when the device node, driver
// library, permission or entitlement is missing. Resolution itself performs no
// side effect; use InspectHostAdapter for readiness metadata.
func ResolveHostAdapter(platform Platform) (HostAdapter, error) {
	if !platform.known() {
		return nil, fmt.Errorf("%w: unknown platform %q", ErrPlatformUnavailable, platform)
	}
	return resolveHostAdapter(platform)
}

// Deps are the injected ports of an Agent.
type Deps struct {
	// Dialer is required when a proxy inbound is configured.
	Dialer Dialer
	// Listen binds proxy listeners. Nil means (*net.ListenConfig).Listen.
	Listen ListenFunc
	// SystemNetwork builds the host network transaction owner for the device the
	// Agent opens. Nil selects the platform default (Linux: native netlink-free
	// ioctl/netlink owner; other platforms: an explicit unavailable error). It
	// is consulted only when Inbounds.TUN is true and Device asks for an address
	// or routes.
	SystemNetwork SystemNetworkFactory
	// TargetResolver is the optional outbound policy and single-IPv4 resolution
	// port (see TargetResolver). Nil forwards the requested host:port unchanged
	// to Dialer/DatagramBackend, which then own virtual-CIDR and DNS policy.
	TargetResolver TargetResolver
	// DatagramBackend is the optional SOCKS5 UDP ASSOCIATE egress port. Nil makes
	// the command report "command not supported" instead of dialling the OS.
	DatagramBackend DatagramBackend
}

// Stats reports proxy ingress counters. Accepted counts admitted connections,
// Rejected counts connections refused by a connection limit, and the remaining
// fields count protocol-level outcomes. They cover the counting half of
// R-MESH-006: every drop has a named reason.
type Stats struct {
	Accepted     uint64
	Rejected     uint64
	AuthFailures uint64
	DialFailures uint64
	Unsupported  uint64
	Active       int64

	// PolicyDenied counts proxy targets refused by the configured
	// TargetResolver before any dial or datagram send.
	PolicyDenied uint64
	// Throttled counts authentication attempts refused without credential work
	// because the entry's failure budget was exhausted inside its window.
	Throttled uint64
	// UDPAssociations counts successful SOCKS5 UDP ASSOCIATE replies.
	UDPAssociations uint64
	// UDPRequests counts client datagrams accepted for forwarding.
	UDPRequests uint64
	// UDPReplies counts datagrams returned to the client.
	UDPReplies uint64
	// UDPDropped counts client and reply datagrams dropped for malformed framing,
	// FRAG != 0, IPv6/unknown address type, a source outside the association
	// binding, an unknown client port or a reply too large for one local IPv4 UDP
	// packet.
	UDPDropped uint64
	// UDPFailures counts association setup failures and backend send/receive
	// errors. An unwired backend is counted as Unsupported instead.
	UDPFailures uint64
}

type proxyStats struct {
	accepted     atomic.Uint64
	rejected     atomic.Uint64
	authFailures atomic.Uint64
	dialFailures atomic.Uint64
	unsupported  atomic.Uint64
	active       atomic.Int64

	policyDenied    atomic.Uint64
	throttled       atomic.Uint64
	udpAssociations atomic.Uint64
	udpRequests     atomic.Uint64
	udpReplies      atomic.Uint64
	udpDropped      atomic.Uint64
	udpFailures     atomic.Uint64
}

func (s *proxyStats) snapshot() Stats {
	return Stats{
		Accepted:        s.accepted.Load(),
		Rejected:        s.rejected.Load(),
		AuthFailures:    s.authFailures.Load(),
		DialFailures:    s.dialFailures.Load(),
		Unsupported:     s.unsupported.Load(),
		Active:          s.active.Load(),
		PolicyDenied:    s.policyDenied.Load(),
		Throttled:       s.throttled.Load(),
		UDPAssociations: s.udpAssociations.Load(),
		UDPRequests:     s.udpRequests.Load(),
		UDPReplies:      s.udpReplies.Load(),
		UDPDropped:      s.udpDropped.Load(),
		UDPFailures:     s.udpFailures.Load(),
	}
}

// limiter is a non-blocking bounded semaphore. A full limiter rejects instead of
// queueing, so the number of admitted connections stays bounded and the accept
// loop never blocks.
type limiter struct {
	slots chan struct{}
}

func newLimiter(capacity int) *limiter {
	if capacity < 1 {
		capacity = 1
	}
	return &limiter{slots: make(chan struct{}, capacity)}
}

func (l *limiter) acquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *limiter) release() {
	select {
	case <-l.slots:
	default:
	}
}

type proxyServer struct {
	kind        ProxyKind
	config      ProxyConfig
	credentials Credentials
	dialer      Dialer
	// resolver and datagram are optional outbound ports; see Deps.
	resolver TargetResolver
	datagram DatagramBackend
	limiter  *limiter
	// authBudget bounds failed authentication work per entry. It is derived from
	// the entry's own connection limit and handshake timeout.
	authBudget *authFailureBudget
	stats      proxyStats
	listener   net.Listener
}

func newProxyServer(kind ProxyKind, config ProxyConfig, deps Deps) *proxyServer {
	return &proxyServer{
		kind:        kind,
		config:      config,
		credentials: config.Credentials(),
		dialer:      deps.Dialer,
		resolver:    deps.TargetResolver,
		datagram:    deps.DatagramBackend,
		limiter:     newLimiter(config.maxConnections()),
		authBudget:  newAuthFailureBudget(config.maxConnections(), config.handshakeTimeout()),
	}
}

// noteAuthFailure records one rejected authentication exchange against the entry
// and its bounded failure budget.
func (s *proxyServer) noteAuthFailure() {
	s.stats.authFailures.Add(1)
	s.authBudget.record(time.Now())
}

// resolveTarget applies the optional outbound policy port to one requested
// target. With no resolver the requested host:port is returned unchanged and the
// injected Dialer/DatagramBackend own virtual-CIDR and DNS policy; with a
// resolver the target is authorised and pinned to the returned IPv4 endpoint so
// name resolution cannot rebind between the check and the dial.
func (s *proxyServer) resolveTarget(ctx context.Context, host string, port uint16) (string, error) {
	if s.resolver == nil {
		return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
	}
	resolved, err := s.resolver.ResolveTarget(ctx, host, port)
	if err != nil {
		return "", fmt.Errorf("%w: %s:%d: %v", ErrTargetDenied, host, port, err)
	}
	if !resolved.IsValid() || !resolved.Addr().Is4() {
		return "", fmt.Errorf("%w: %s:%d resolved to %q, which is not a definite IPv4 endpoint", ErrTargetDenied, host, port, resolved)
	}
	return resolved.String(), nil
}

// dialProxyTarget resolves and dials one TCP target within the bounded dial
// timeout and returns the RFC 1928 reply that a failure maps to. The success
// reply code is returned for symmetry; the caller reports the endpoint the
// Dialer actually used.
func (s *proxyServer) dialProxyTarget(ctx context.Context, host string, port uint16) (net.Conn, byte, error) {
	dialCtx, cancel := context.WithTimeout(ctx, s.config.dialTimeout())
	defer cancel()
	target, err := s.resolveTarget(dialCtx, host, port)
	if err != nil {
		return nil, socksReplyForDialError(err), err
	}
	upstream, err := s.dialer.DialContext(dialCtx, "tcp", target)
	if err != nil {
		return nil, socksReplyForDialError(err), err
	}
	return upstream, socksReplySucceeded, nil
}

// authFailureBudget is one entry's bound on failed authentication work. Its
// capacity is the entry's connection limit and its window is the entry's
// handshake timeout, so it introduces no new numeric ceiling. Once the budget is
// exhausted, further authentication attempts are refused without credential work
// until the window rolls over.
type authFailureBudget struct {
	mu       sync.Mutex
	capacity uint64
	window   time.Duration
	start    time.Time
	failures uint64
}

func newAuthFailureBudget(capacity int, window time.Duration) *authFailureBudget {
	if capacity < 1 {
		capacity = 1
	}
	if window <= 0 {
		window = defaultHandshakeTimeout
	}
	return &authFailureBudget{capacity: uint64(capacity), window: window}
}

// allow reports whether a new authentication attempt may do credential work.
func (b *authFailureBudget) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll(now)
	return b.failures < b.capacity
}

// record counts one rejected authentication exchange.
func (b *authFailureBudget) record(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll(now)
	b.failures++
}

// roll starts a new window when the current one expired.
func (b *authFailureBudget) roll(now time.Time) {
	if b.start.IsZero() || now.Sub(b.start) >= b.window {
		b.start = now
		b.failures = 0
	}
}

func (s *proxyServer) serve(ctx context.Context, conn net.Conn) {
	switch s.kind {
	case ProxySOCKS5:
		serveSOCKS5(ctx, s, conn)
	case ProxyHTTP:
		serveHTTPProxy(ctx, s, conn)
	}
}

type agentState uint8

const (
	stateCreated agentState = iota
	stateRunning
	stateClosed
)

// Agent owns the lifecycle of the configured proxy listeners and, when
// inbounds.tun is true, of one opened platform packet device together with its
// host network transaction. It never fakes a device: a missing device node,
// driver, permission or entitlement fails Start before any listener is bound.
type Agent struct {
	config AgentConfig
	dialer Dialer
	listen ListenFunc
	// systemNetworkFactory is the injected host network owner constructor. Nil
	// means defaultSystemNetworkFactory.
	systemNetworkFactory SystemNetworkFactory

	ctx    context.Context
	cancel context.CancelFunc

	ingress *limiter

	proxies []*proxyServer
	socks5  *proxyServer
	http    *proxyServer

	// device is the opened platform PacketDevice, nil when TUN is off or Start
	// has not run. sysnet is its host network transaction owner, nil when no
	// address/route configuration was requested.
	device PacketDevice
	sysnet SystemNetwork

	mu     sync.Mutex
	state  agentState
	active map[net.Conn]struct{}

	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
	done      chan struct{}
}

// New validates the typed configuration and returns an Agent that has not taken
// any side effect yet. Proxies require an injected Dialer; binding happens in
// Start.
func New(cfg AgentConfig, deps Deps) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if (cfg.Inbounds.SOCKS5 != nil || cfg.Inbounds.HTTPProxy != nil) && deps.Dialer == nil {
		return nil, fmt.Errorf("%w: proxy inbounds dial every target through the injected Dialer", ErrNoDialer)
	}
	listen := deps.Listen
	if listen == nil {
		listen = (&net.ListenConfig{}).Listen
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &Agent{
		config:               cfg,
		dialer:               deps.Dialer,
		listen:               listen,
		systemNetworkFactory: deps.SystemNetwork,
		ctx:                  ctx,
		cancel:               cancel,
		ingress:              newLimiter(MaxProxyConnections),
		active:               make(map[net.Conn]struct{}),
		done:                 make(chan struct{}),
	}
	if cfg.Inbounds.SOCKS5 != nil {
		a.socks5 = newProxyServer(ProxySOCKS5, *cfg.Inbounds.SOCKS5, deps)
		a.proxies = append(a.proxies, a.socks5)
	}
	if cfg.Inbounds.HTTPProxy != nil {
		a.http = newProxyServer(ProxyHTTP, *cfg.Inbounds.HTTPProxy, deps)
		a.proxies = append(a.proxies, a.http)
	}
	return a, nil
}

// Start opens the platform packet device (when inbounds.tun is true), runs the
// optional host network transaction and binds every configured proxy listener.
// It is all-or-nothing: any failure closes the listeners, the device and the
// host network resources opened by this call and leaves the Agent startable
// again. With inbounds.tun enabled, a missing device/driver/permission fails
// Start with ErrPlatformUnavailable instead of silently degrading to a TCP-only
// agent (D-DOC-021).
func (a *Agent) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch a.state {
	case stateRunning:
		return fmt.Errorf("%w: Start was already called", ErrAlreadyStarted)
	case stateClosed:
		return ErrClosed
	}
	if a.config.Inbounds.tunEnabled() {
		if err := a.openPacketDeviceLocked(ctx); err != nil {
			return err
		}
	}
	for _, proxy := range a.proxies {
		listener, err := a.listen(ctx, "tcp", proxy.config.Listen)
		if err != nil {
			for _, bound := range a.proxies {
				if bound.listener != nil {
					_ = bound.listener.Close()
					bound.listener = nil
				}
			}
			teardownCtx, cancel := context.WithTimeout(context.Background(), closeDrainTimeout)
			teardownErr := a.closePacketDeviceLocked(teardownCtx)
			cancel()
			return errors.Join(fmt.Errorf("agent: %s inbound listen %q: %w", proxy.kind, proxy.config.Listen, err), teardownErr)
		}
		proxy.listener = listener
	}
	for _, proxy := range a.proxies {
		a.wg.Add(1)
		go a.acceptLoop(proxy)
	}
	a.state = stateRunning
	return nil
}

// openPacketDeviceLocked resolves the platform backend, opens the real device
// and applies the optional host network transaction. Every failure path closes
// what this call already created, so a failed Start leaves no owned device or
// address/route behind. The caller holds a.mu.
func (a *Agent) openPacketDeviceLocked(ctx context.Context) error {
	adapter, err := ResolveHostAdapter(a.config.effectivePlatform())
	if err != nil {
		return fmt.Errorf("agent: inbounds.tun: %w", err)
	}
	device, err := adapter.Open(ctx, DeviceOptions{MTU: DefaultDeviceMTU, Name: a.config.Device.Name, Address: a.config.Device.Address})
	if err != nil {
		return fmt.Errorf("agent: inbounds.tun: %w", err)
	}
	// The device MTU (and any address or route) is only ever changed through the
	// journaled transaction. Open itself touches no OS network state, so the
	// prior MTU is still visible to Prepare and can be restored on rollback even
	// when the device was opened without an address or routes. Without this the
	// MTU change would be an un-journaled side effect that Close could not undo.
	name, ok := deviceName(device)
	if !ok {
		_ = device.Close()
		return fmt.Errorf("agent: inbounds.tun: %w: the %s backend did not report its interface name, so the host network transaction cannot be built",
			ErrNetworkConfigUnavailable, adapter.Platform())
	}
	factory := a.systemNetworkFactory
	if factory == nil {
		factory = defaultSystemNetworkFactory
	}
	opts := SystemNetworkOptions{
		Interface:   name,
		MTU:         device.MTU(),
		Address:     a.config.Device.Address,
		Routes:      a.config.Device.Routes,
		JournalPath: a.config.Device.JournalPath,
	}
	sysnet, err := factory(name, opts)
	if err != nil {
		_ = device.Close()
		return fmt.Errorf("agent: inbounds.tun: %w", err)
	}
	if err := sysnet.Prepare(ctx); err != nil {
		_ = sysnet.Close()
		_ = device.Close()
		return fmt.Errorf("agent: inbounds.tun: prepare host network on %q: %w", name, err)
	}
	if err := sysnet.Apply(ctx); err != nil {
		rollbackErr := sysnet.Rollback(ctx)
		_ = sysnet.Close()
		_ = device.Close()
		if rollbackErr != nil {
			return fmt.Errorf("agent: inbounds.tun: apply host network on %q: %w (rollback also reported: %v)", name, err, rollbackErr)
		}
		return fmt.Errorf("agent: inbounds.tun: apply host network on %q: %w", name, err)
	}
	a.sysnet = sysnet
	a.device = device
	return nil
}

// closePacketDeviceLocked rolls the host network transaction back and closes the
// device exactly once. The caller holds a.mu.
func (a *Agent) closePacketDeviceLocked(ctx context.Context) error {
	var errs []error
	if a.sysnet != nil {
		if err := a.sysnet.Rollback(ctx); err != nil {
			errs = append(errs, fmt.Errorf("agent: host network rollback: %w", err))
		}
		if err := a.sysnet.Close(); err != nil {
			errs = append(errs, fmt.Errorf("agent: host network close: %w", err))
		}
		a.sysnet = nil
	}
	if a.device != nil {
		if err := a.device.Close(); err != nil && !errors.Is(err, ErrDeviceClosed) {
			errs = append(errs, fmt.Errorf("agent: packet device close: %w", err))
		}
		a.device = nil
	}
	return errors.Join(errs...)
}

// Close stops the listeners, closes admitted connections, waits for the
// handlers within a bounded drain and closes Done. It is idempotent and safe to
// call before Start or concurrently from several goroutines.
func (a *Agent) Close() error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.state = stateClosed
		listeners := make([]net.Listener, 0, len(a.proxies))
		for _, proxy := range a.proxies {
			if proxy.listener != nil {
				listeners = append(listeners, proxy.listener)
			}
		}
		active := make([]net.Conn, 0, len(a.active))
		for conn := range a.active {
			active = append(active, conn)
		}
		a.mu.Unlock()

		a.cancel()
		var errs []error
		for _, listener := range listeners {
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		for _, conn := range active {
			_ = conn.Close()
		}
		// The device must still exist while the host network transaction rolls
		// back its address and routes, so device teardown runs after rollback
		// and before the drain wait.
		teardownCtx, cancel := context.WithTimeout(context.Background(), closeDrainTimeout)
		if err := a.closePacketDeviceLocked(teardownCtx); err != nil {
			errs = append(errs, err)
		}
		cancel()
		if !waitTimeout(&a.wg, closeDrainTimeout) {
			errs = append(errs, fmt.Errorf("%w: proxy handlers did not stop within %s", ErrCloseTimeout, closeDrainTimeout))
		}
		a.closeErr = errors.Join(errs...)
		close(a.done)
	})
	return a.closeErr
}

// Done is closed after Close finished its cleanup.
func (a *Agent) Done() <-chan struct{} {
	return a.done
}

// addressRetargeter is the optional SystemNetwork owner capability that
// Agent.RetargetAddress uses to move a live device's local VirtualIP without
// reopening it. An owner that does not implement it is refused with
// ErrNetworkConfigUnavailable rather than silently reopening the device: the
// device FD and its kernel state must stay untouched.
type addressRetargeter interface {
	RetargetAddress(ctx context.Context, address netip.Prefix) error
}

// RetargetAddress moves the local IPv4 /32 VirtualIP to newVIP without
// reopening the packet device.
//
// Before Start (or with inbounds.tun off) it only updates the configuration
// Start will consume. After Start it asks the live SystemNetwork owner to roll
// back exactly the resources that transaction owns — with the owner's own
// fingerprint and alias proof, so a user-owned or dangling marker is never
// overwritten — and then to apply the new /32 in a fresh journaled transaction
// on the same open journal and device. The owner first proves it still owns
// every applied resource and, when it does not, returns ErrPlatformUnavailable
// with zero kernel effects: an externally replaced route or address is never
// released as collateral. On any failure the previous configured address is
// preserved and the error is returned; the caller must fail closed (stop
// publishing the new node address) rather than assume packet continuity.
//
// Concurrent calls are serialized by the Agent mutex. The lock order is
// Agent.mu then the owner's own mutex; the owner never calls back into the
// Agent, so the order cannot deadlock.
func (a *Agent) RetargetAddress(ctx context.Context, newVIP netip.Prefix) error {
	if a == nil {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !newVIP.IsValid() || !newVIP.Addr().Is4() || newVIP.Bits() != 32 {
		return fmt.Errorf("%w: system_network.address must be an IPv4 /32 local VirtualIP, got %s", ErrInvalidConfig, newVIP)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state == stateClosed {
		return ErrClosed
	}
	if a.config.Device.Address == newVIP {
		return nil
	}
	if a.sysnet == nil || a.device == nil {
		// Not started, or the TUN inbound is off: no OS state exists yet, so
		// updating the configuration Start will consume is the whole change.
		a.config.Device.Address = newVIP
		return nil
	}
	retargeter, ok := a.sysnet.(addressRetargeter)
	if !ok {
		return fmt.Errorf("%w: the %s host network owner cannot retarget a live address without reopening the device",
			ErrNetworkConfigUnavailable, a.config.effectivePlatform())
	}
	if err := retargeter.RetargetAddress(ctx, newVIP); err != nil {
		return fmt.Errorf("agent: retarget host network address to %s: %w", newVIP, err)
	}
	a.config.Device.Address = newVIP
	return nil
}

// PacketDevice returns the L3 device opened by Start, or nil when inbounds.tun
// is off, Start has not run, or Start failed. The device belongs to the Agent:
// the caller must not Close it, and Close invalidates it.
func (a *Agent) PacketDevice() PacketDevice {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.device
}

// DeviceInfo reports the concrete metadata and readiness of the opened device.
// Ready is false (and the second result false) when no device is open, including
// the whole Proxy-only configuration. Address is whatever host network
// configuration was applied, so a device opened without Device.Address reports
// the zero prefix.
func (a *Agent) DeviceInfo() (DeviceInfo, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.device == nil {
		return DeviceInfo{}, false
	}
	if reporter, ok := a.device.(DeviceReporter); ok {
		info := reporter.DeviceInfo()
		info.Ready = true
		return info, true
	}
	return DeviceInfo{MTU: a.device.MTU(), Ready: true}, true
}

// AdapterInfo reports the backend metadata and readiness for the effective
// platform without opening a device. A missing driver or device node is
// reported through AdapterInfo.Available/Detail rather than an error; only an
// unknown platform or a backend belonging to another GOOS is an error.
func (a *Agent) AdapterInfo() (AdapterInfo, error) {
	return InspectHostAdapter(a.config.effectivePlatform())
}

// SystemNetwork returns the host network transaction owner created by Start, or
// nil when none was requested. The Agent owns it; the caller must not Close it.
func (a *Agent) SystemNetwork() SystemNetwork {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sysnet
}

// ListenAddrs reports the actually bound proxy addresses. Either result is nil
// when that inbound is not configured or Start has not run.
func (a *Agent) ListenAddrs() (socks5, http net.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.socks5 != nil && a.socks5.listener != nil {
		socks5 = a.socks5.listener.Addr()
	}
	if a.http != nil && a.http.listener != nil {
		http = a.http.listener.Addr()
	}
	return socks5, http
}

// Stats aggregates the ingress counters of every configured proxy.
func (a *Agent) Stats() Stats {
	var total Stats
	for _, proxy := range a.proxies {
		snapshot := proxy.stats.snapshot()
		total.Accepted += snapshot.Accepted
		total.Rejected += snapshot.Rejected
		total.AuthFailures += snapshot.AuthFailures
		total.DialFailures += snapshot.DialFailures
		total.Unsupported += snapshot.Unsupported
		total.Active += snapshot.Active
		total.PolicyDenied += snapshot.PolicyDenied
		total.Throttled += snapshot.Throttled
		total.UDPAssociations += snapshot.UDPAssociations
		total.UDPRequests += snapshot.UDPRequests
		total.UDPReplies += snapshot.UDPReplies
		total.UDPDropped += snapshot.UDPDropped
		total.UDPFailures += snapshot.UDPFailures
	}
	return total
}

func (a *Agent) acceptLoop(proxy *proxyServer) {
	defer a.wg.Done()
	backoff := acceptBackoffMin
	for {
		conn, err := proxy.listener.Accept()
		if err != nil {
			if a.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// An unexpected listener failure is bounded here; surfacing it as a
			// capability withdrawal event is not implemented in this slice.
			select {
			case <-a.ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > acceptBackoffMax {
				backoff = acceptBackoffMax
			}
			continue
		}
		backoff = acceptBackoffMin
		a.admit(proxy, conn)
	}
}

// admit charges one accepted connection against the Agent-wide P1 budget and the
// per-entry option, then hands it to a tracked handler goroutine. Over-limit
// connections are rejected immediately instead of queued.
func (a *Agent) admit(proxy *proxyServer, conn net.Conn) {
	if !a.ingress.acquire() {
		proxy.stats.rejected.Add(1)
		rejectOverLimitProxyConn(proxy.kind, conn)
		return
	}
	if !proxy.limiter.acquire() {
		a.ingress.release()
		proxy.stats.rejected.Add(1)
		rejectOverLimitProxyConn(proxy.kind, conn)
		return
	}
	proxy.stats.accepted.Add(1)
	proxy.stats.active.Add(1)
	a.track(conn)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer a.ingress.release()
		defer proxy.limiter.release()
		defer proxy.stats.active.Add(-1)
		defer a.untrack(conn)
		defer conn.Close()
		proxy.serve(a.ctx, conn)
	}()
}

func (a *Agent) track(conn net.Conn) {
	a.mu.Lock()
	a.active[conn] = struct{}{}
	a.mu.Unlock()
}

func (a *Agent) untrack(conn net.Conn) {
	a.mu.Lock()
	delete(a.active, conn)
	a.mu.Unlock()
}

func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

var relayBuffers = sync.Pool{
	New: func() any {
		buffer := make([]byte, relayBufferSize)
		return &buffer
	},
}

// relay moves bytes in both directions until both directions end or the Agent
// context is cancelled. It preserves TCP half-close: a clean EOF from one side
// half-closes the peer direction and lets the other direction keep draining.
//
// A non-EOF error is different from a half-close: the failing direction cannot
// deliver the rest of its stream, so the tunnel is broken in both directions.
// Closing both endpoints there is what interrupts the sibling copy, which may be
// parked in a Read or Write that would otherwise never return and would leak the
// handler goroutine (and the client's HTTP request) forever. Both endpoint
// closes are best-effort and idempotent, and an already-closed endpoint, an
// expected net.ErrClosed, or a close error never blocks the final drain: relay
// always collects the second result before returning.
func relay(ctx context.Context, client, upstream net.Conn) {
	closeBoth := func() {
		_ = client.Close()
		_ = upstream.Close()
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()

	results := make(chan error, 2)
	go func() { results <- copyHalf(upstream, client) }()
	go func() { results <- copyHalf(client, upstream) }()

	if err := <-results; err != nil {
		// Only a genuine error breaks the tunnel; a clean EOF (nil) is a
		// half-close whose response direction must stay open.
		closeBoth()
	}
	// Drain the sibling so no copy goroutine outlives this relay.
	<-results
}

// copyHalf copies one direction and reports whether it ended cleanly. A nil
// result means the source reached EOF: the destination is half-closed so the
// peer can finish its response. A non-nil result is any read or write failure,
// including an expected net.ErrClosed after teardown; the caller decides whether
// it means the tunnel is broken. A half-close failure is deliberately not
// reported, because it does not stop the reverse direction from finishing.
func copyHalf(dst, src net.Conn) error {
	buffer := relayBuffers.Get().(*[]byte)
	defer relayBuffers.Put(buffer)
	if _, err := io.CopyBuffer(dst, src, *buffer); err != nil {
		return err
	}
	if halfCloser, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
	return nil
}

// writeAll writes the whole buffer, tolerating short writes.
func writeAll(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := conn.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[written:]
	}
	return nil
}

func invalid(field, detail string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidConfig, field, detail)
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

// printableHost reports whether a target host token is a bounded, printable
// hostname or address literal.
func printableHost(host string) bool {
	if host == "" {
		return false
	}
	for _, char := range host {
		if char <= 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

// ipv6LiteralHost reports whether a target host is an IPv6 address literal.
// IPv6 is out of scope for this version, so such targets are rejected before any
// dial instead of being silently passed to the Dialer.
func ipv6LiteralHost(host string) bool {
	trimmed := strings.Trim(host, "[]")
	address, err := netip.ParseAddr(trimmed)
	if err != nil {
		return false
	}
	return !address.Is4()
}
