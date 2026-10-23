package agent

// This file owns the platform-neutral half of the L3 host adapter slice:
// configuration and metadata types, the additive error identities, and the
// build-tag dispatch that selects one concrete backend per GOOS.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// L3 feature prose path (not an ownership pointer):
// docs/domains/overlay/features/l3-vpn.md.
//
// Requirements owned here: R-L3-001 (three platform host adapters, diagnosable
// permission/driver/entitlement failures) and R-L3-005 (host lifecycle and
// system side-effect boundary). The platform device work itself lives in the
// build-tagged files beside this one:
//
//	device_linux.go        Linux TUN (/dev/net/tun, TUNSETIFF, IFF_TUN|IFF_NO_PI)
//	device_darwin.go       macOS utun (PF_SYSTEM kernel control, 4-byte AF header)
//	device_windows.go      Windows Wintun (dynamic wintun.dll session/ring)
//	device_unsupported.go  honest refusal for every other GOOS
//	sysnet_linux.go        Linux address/MTU/route transaction with rollback
//	sysnet_unsupported.go  explicit actionable error on platforms without it

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	// MinDeviceMTU is the smallest virtual device MTU this slice configures.
	// 68 is the IPv4 minimum an interface may carry.
	MinDeviceMTU = 68

	// MaxDeviceNameLength bounds a requested device name before it reaches the
	// platform. Linux additionally rejects anything at or above IFNAMSIZ.
	MaxDeviceNameLength = 128
)

// Sentinel errors of the L3 device slice. They are additive: existing proxy
// identities in agent.go are unchanged. Platform availability failures wrap
// ErrPlatformUnavailable so a caller can decide from the top-level identity and
// still read the actionable detail from the message.
var (
	// ErrDeviceClosed reports use of a PacketDevice after Close.
	ErrDeviceClosed = errors.New("agent: packet device closed")
	// ErrInvalidPacket reports a write that is not one complete IPv4 packet:
	// empty, shorter than an IPv4 header, or not IP version 4.
	ErrInvalidPacket = errors.New("agent: invalid IPv4 packet")
	// ErrPacketTooLarge reports a packet or read buffer beyond the device MTU.
	ErrPacketTooLarge = errors.New("agent: packet exceeds device MTU")
	// ErrBufferTooSmall reports a ReadPacket buffer smaller than the device MTU.
	// The device refuses before reading so the packet is not silently truncated.
	ErrBufferTooSmall = errors.New("agent: read buffer smaller than device MTU")
	// ErrDriverMissing reports that the platform packet driver or dynamic
	// library the backend needs could not be loaded or opened. It always wraps
	// ErrPlatformUnavailable and carries the install/repair step.
	ErrDriverMissing = errors.New("agent: virtual network driver unavailable")
	// ErrNetworkConfigUnavailable reports that host address/route/MTU
	// configuration is not available in this build or platform without an
	// external capability (root/CAP_NET_ADMIN, an entitlement or a helper). The
	// PacketDevice itself is unaffected: it still opens and moves packets.
	ErrNetworkConfigUnavailable = errors.New("agent: host network configuration unavailable")
)

// DeviceConfig is the optional L3 device configuration the Agent applies when
// Inbounds.TUN is true. It mirrors no public pkg/simpletier field yet; the
// pkg-level Agent can map onto it without changing this package's dependency
// direction. MTU is deliberately absent: D-L3-004 freezes the virtual MTU at
// DefaultDeviceMTU and it is not user configurable.
type DeviceConfig struct {
	// Name requests the device/interface name. Empty lets the platform choose
	// (Linux tunN, Windows adapter name, macOS utunN).
	Name string
	// Address is the local IPv4 VirtualIP/32 assigned to the opened device when
	// host network configuration runs. P1 publishes only the node's own /32;
	// zero means "do not configure an address".
	Address netip.Prefix
	// Routes lists IPv4 prefixes to install on the opened device. P1 installs
	// nothing by default and never touches the default route.
	Routes []netip.Prefix
	// JournalPath optionally persists the transaction's write-ahead journal as
	// JSON lines. A host that needs crash recovery points this at its canonical
	// per-node state directory; empty keeps the journal in memory only, which is
	// not a durable write-ahead log.
	JournalPath string
}

// Validate checks the device configuration without side effects.
func (d DeviceConfig) Validate() error {
	if d.Name != "" {
		if len(d.Name) > MaxDeviceNameLength {
			return invalid("device.name", fmt.Sprintf("must be at most %d bytes", MaxDeviceNameLength))
		}
		if !printableDeviceName(d.Name) {
			return invalid("device.name", "must not contain control characters, spaces, '/' or NUL")
		}
	}
	if d.Address.IsValid() {
		if !d.Address.Addr().Is4() {
			return invalid("device.address", "must be an IPv4 address; IPv6 is out of scope for this version")
		}
		if d.Address.Bits() != 32 {
			return invalid("device.address", "must be a /32 local VirtualIP; this version does not publish prefixes")
		}
	}
	for index, route := range d.Routes {
		field := fmt.Sprintf("device.routes[%d]", index)
		if !route.IsValid() || !route.Addr().Is4() {
			return invalid(field, "must be a valid IPv4 prefix")
		}
		if route.Bits() > 32 {
			return invalid(field, "must be an IPv4 prefix of at most 32 bits")
		}
		if d.Address.IsValid() && route.Addr() == d.Address.Addr() && route.Bits() == 32 {
			return invalid(field, "must not repeat the device address; the /32 local route is implicit")
		}
	}
	return nil
}

func (d DeviceConfig) configured() bool {
	return d.Name != "" || d.Address.IsValid() || len(d.Routes) > 0
}

func printableDeviceName(name string) bool {
	for _, char := range name {
		if char <= 0x20 || char == 0x7f || char == '/' || char == '\\' {
			return false
		}
	}
	return true
}

// PrintableDeviceName reports whether name is a usable device name on every
// platform. The SDK exposes it so a caller that names the device (for example
// to run two Agents on one host) validates the name the same way the device
// open does, instead of keeping a second copy of the rule.
func PrintableDeviceName(name string) bool {
	return printableDeviceName(name)
}

// DeviceInfo is the concrete metadata of one opened packet device. It is the
// minimal readiness surface of the L3 host adapter slice: Ready means the device
// was opened and its read/write path is usable. It does not publish the
// packet.ipv4 capability, which belongs to the (unimplemented) packet plane.
type DeviceInfo struct {
	Platform Platform
	Name     string
	MTU      int
	Address  netip.Prefix
	Ready    bool
	// Owned reports that this Open created the platform interface/adapter and
	// that Close is responsible for releasing it. A backend that attached to a
	// pre-existing interface/adapter reports false and Close leaves it in place.
	Owned bool
}

// DeviceReporter is the optional capability of a PacketDevice backend to report
// its concrete platform metadata. The canonical PacketDevice port is unchanged;
// callers type-assert when they need device identity (for example to hand an
// interface name to SystemNetwork).
type DeviceReporter interface {
	DeviceInfo() DeviceInfo
}

// AdapterInfo describes one resolved HostAdapter without opening a device. It is
// the minimal readiness/diagnostic metadata of the backend and never performs a
// blocking open.
type AdapterInfo struct {
	Platform Platform
	// DevicePath is the platform resource the backend opens, for diagnostics
	// only (for example /dev/net/tun). It is empty for API-only backends.
	DevicePath string
	// Driver names the platform API or dynamic library the backend uses.
	Driver string
	// MaxMTU is the largest MTU the backend accepts (DefaultDeviceMTU).
	MaxMTU int
	// Available reports whether the platform resource the backend needs is
	// present on this host. It is false together with Detail when a driver,
	// device node or library is missing; Open then fails with a matching
	// actionable error instead of pretending the platform works.
	Available bool
	// Detail explains an unavailable backend and the repair step.
	Detail string
}

// AdapterInspector is the optional capability of a HostAdapter to report its
// AdapterInfo without opening a device.
type AdapterInspector interface {
	AdapterInfo() AdapterInfo
}

// InspectHostAdapter resolves one platform backend without opening a device and
// reports its metadata and readiness. It returns the same availability error as
// ResolveHostAdapter when the platform is unknown or belongs to another GOOS.
func InspectHostAdapter(platform Platform) (AdapterInfo, error) {
	adapter, err := ResolveHostAdapter(platform)
	if err != nil {
		return AdapterInfo{Platform: platform}, err
	}
	inspector, ok := adapter.(AdapterInspector)
	if !ok {
		return AdapterInfo{Platform: platform, MaxMTU: DefaultDeviceMTU, Available: true}, nil
	}
	return inspector.AdapterInfo(), nil
}

// SystemNetworkOptions are the typed inputs of one host network transaction.
// MTU zero means DefaultDeviceMTU; Address zero means "no address to assign".
type SystemNetworkOptions struct {
	// Interface is the interface name of the opened PacketDevice. Required.
	Interface string
	// MTU is the interface MTU to configure, bounded by DefaultDeviceMTU.
	MTU int
	// Address is the local IPv4 VirtualIP/32 to assign.
	Address netip.Prefix
	// Routes lists IPv4 prefixes to install on the interface.
	Routes []netip.Prefix
	// JournalPath optionally persists the write-ahead journal as JSON lines
	// before each OS side effect so a later process can read the intents. Empty
	// keeps the journal in memory for the lifetime of this transaction.
	JournalPath string
}

// Validate checks the transaction configuration without side effects.
func (o SystemNetworkOptions) Validate() error {
	if strings.TrimSpace(o.Interface) == "" {
		return invalid("system_network.interface", "must be the opened device interface name")
	}
	if !printableDeviceName(o.Interface) {
		return invalid("system_network.interface", "must not contain control characters, spaces, '/' or NUL")
	}
	if o.MTU != 0 && (o.MTU < MinDeviceMTU || o.MTU > DefaultDeviceMTU) {
		return invalid("system_network.mtu", fmt.Sprintf("must be between %d and %d (D-L3-004: %d is the frozen default)", MinDeviceMTU, DefaultDeviceMTU, DefaultDeviceMTU))
	}
	if o.Address.IsValid() {
		if !o.Address.Addr().Is4() || o.Address.Bits() != 32 {
			return invalid("system_network.address", "must be an IPv4 /32 local VirtualIP")
		}
	}
	for index, route := range o.Routes {
		if !route.IsValid() || !route.Addr().Is4() || route.Bits() > 32 {
			return invalid(fmt.Sprintf("system_network.routes[%d]", index), "must be a valid IPv4 prefix")
		}
	}
	return nil
}

func (o SystemNetworkOptions) mtu() int {
	if o.MTU > 0 {
		return o.MTU
	}
	return DefaultDeviceMTU
}

// SystemNetworkFactory builds the system resource owner for one opened device.
// The Agent calls it after Open because the platform may assign the interface
// name (Linux tunN, macOS utunN).
type SystemNetworkFactory func(interfaceName string, opts SystemNetworkOptions) (SystemNetwork, error)

// NewSystemNetwork returns the platform host network transaction owner.
//
// Linux: a native address/MTU/link/route transaction that reverses only what it
// applied. Other platforms: ErrNetworkConfigUnavailable with the capability that
// is missing, because their route/address APIs need a helper, entitlement or
// driver that this slice does not ship. A working PacketDevice is unaffected.
func NewSystemNetwork(platform Platform, interfaceName string, opts SystemNetworkOptions) (SystemNetwork, error) {
	if !platform.known() {
		return nil, fmt.Errorf("%w: unknown platform %q", ErrPlatformUnavailable, platform)
	}
	opts.Interface = interfaceName
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	return newSystemNetwork(platform, opts)
}

// defaultSystemNetworkFactory is the Agent's default when Deps.SystemNetwork is
// nil. It resolves the platform of the running host.
func defaultSystemNetworkFactory(interfaceName string, opts SystemNetworkOptions) (SystemNetwork, error) {
	return NewSystemNetwork(CurrentPlatform(), interfaceName, opts)
}

// deviceName reports the opened device's interface name when the backend can
// report one.
func deviceName(device PacketDevice) (string, bool) {
	reporter, ok := device.(DeviceReporter)
	if !ok {
		return "", false
	}
	info := reporter.DeviceInfo()
	if info.Name == "" {
		return "", false
	}
	return info.Name, true
}

// clampDeviceMTU validates a requested MTU against the frozen bounds.
func clampDeviceMTU(requested int) (int, error) {
	if requested == 0 {
		return DefaultDeviceMTU, nil
	}
	if requested < MinDeviceMTU || requested > DefaultDeviceMTU {
		return 0, fmt.Errorf("%w: mtu %d is outside the frozen bounds %d..%d (D-L3-004)",
			ErrInvalidConfig, requested, MinDeviceMTU, DefaultDeviceMTU)
	}
	return requested, nil
}

// ipv4PacketValid reports whether payload is exactly one complete IPv4 packet:
// version 4, IHL >= 5, and an IPv4 total length equal to the slice length. The
// device contract carries one complete packet and no link-layer padding, so a
// mismatch is a caller bug rather than traffic to forward. It is shared by every
// platform backend, including the Windows ring and the macOS AF-prefixed utun.
func ipv4PacketValid(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("%w: %d bytes is shorter than an IPv4 header", ErrInvalidPacket, len(packet))
	}
	if packet[0]>>4 != 4 {
		return fmt.Errorf("%w: IP version %d, want 4", ErrInvalidPacket, packet[0]>>4)
	}
	if packet[0]&0x0f < 5 {
		return fmt.Errorf("%w: IHL %d is smaller than 5", ErrInvalidPacket, packet[0]&0x0f)
	}
	total := int(packet[2])<<8 | int(packet[3])
	if total != len(packet) {
		return fmt.Errorf("%w: IPv4 total length %d does not match %d bytes", ErrInvalidPacket, total, len(packet))
	}
	return nil
}

// packetDeviceContextErr preserves a cancellation identity over a poll loop.
func packetDeviceContextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

// deviceContextErr reports the caller's cancellation together with the device
// identity, so every pre-syscall cancellation check has one shape.
func deviceContextErr(ctx context.Context, name string) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return fmt.Errorf("agent: %s: %w", name, err)
	}
	return nil
}

// afterFuncJoined registers callback to run once when ctx is done and returns a
// stop function that also joins a callback that has already started.
//
// This is a file-descriptor lifetime requirement, not a convenience. The
// callback signals the device wake descriptor (a Linux eventfd, a macOS pipe or
// a Windows event). context.AfterFunc's own stop does not wait for a callback
// that is already running, so a caller that returned as soon as stop() was
// called could release its device lock, let Close close the wake descriptor, and
// then have the late callback write to a descriptor number the process has
// already reused. The returned stop reports whether it prevented the callback
// after joining it, so a true result means the callback will never run and a
// false result means it has finished.
func afterFuncJoined(ctx context.Context, callback func()) (stop func() bool) {
	if ctx == nil {
		return func() bool { return true }
	}
	done := make(chan struct{})
	stopOnce := context.AfterFunc(ctx, func() {
		defer close(done)
		callback()
	})
	return func() bool {
		stopped := stopOnce()
		if !stopped {
			<-done
		}
		return stopped
	}
}
