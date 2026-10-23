//go:build darwin

package agent

// macOS host adapter: the real utun backend.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Requirement anchors (prose, not ownership pointers): R-L3-001, R-L3-005; the
// L3 feature prose path is docs/domains/overlay/features/l3-vpn.md.
//
// utun is not a device node: it is a PF_SYSTEM kernel control named
// "com.apple.net.utun_control". The backend resolves the control id with
// CTLIOCGINFO, connects one unit (the kernel assigns utunN), reads the assigned
// name with UTUN_OPT_IFNAME and then moves packets over the socket. Every utun
// packet carries a 4-byte address-family prefix in network byte order; the
// backend strips it on read and prepends AF_INET on write, so the PacketDevice
// contract (one complete IPv4 packet, no platform prefix) is preserved.
//
// Open owns the device handle only. It performs no OS network mutation at all:
// the interface MTU, the address and the routes are side effects of the
// journaled SystemNetwork transaction in sysnet_darwin.go, which is what makes
// them reversible (the prior MTU is still observable after Open) and leaves
// nothing behind when Start fails before the transaction runs. The
// kernel-assigned name is published through DeviceInfo so the Agent can hand it
// to that transaction.
//
// Runtime verification on macOS is not possible from this repository's Linux
// host. The code is cross-compiled only; that is a compile check, not platform
// acceptance. Signing, entitlement and route-configuration behaviour must be
// verified on a real macOS host.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	// utunControlName is the Darwin kernel control that provides utun devices
	// (<net/if_utun.h>).
	utunControlName = "com.apple.net.utun_control"
	// utunAFSystem is AF_SYSTEM/PF_SYSTEM (<sys/socket.h>).
	utunAFSystem = 0x20
	// utunSysprotoControl is SYSPROTO_CONTROL (<sys/kern_control.h>).
	utunSysprotoControl = 2
	// utunOptIfname is UTUN_OPT_IFNAME (<net/if_utun.h>): the getsockopt that
	// reports the assigned interface name.
	utunOptIfname = 2
	// utunHeaderSize is the 4-byte address-family prefix on every utun packet.
	utunHeaderSize = 4
)

// darwinHostAdapter is the macOS HostAdapter implementation.
type darwinHostAdapter struct{}

// Platform implements HostAdapter.
func (darwinHostAdapter) Platform() Platform { return PlatformDarwin }

// AdapterInfo implements AdapterInspector. The probe creates a PF_SYSTEM socket
// and resolves the kernel control id, which does not create a utun interface.
func (darwinHostAdapter) AdapterInfo() AdapterInfo {
	info := AdapterInfo{
		Platform: PlatformDarwin,
		Driver:   "utun (PF_SYSTEM kernel control " + utunControlName + ")",
		MaxMTU:   DefaultDeviceMTU,
	}
	fd, err := unix.Socket(utunAFSystem, unix.SOCK_DGRAM, utunSysprotoControl)
	if err != nil {
		info.Detail = fmt.Sprintf("socket(PF_SYSTEM, SYSPROTO_CONTROL) failed: %v; the process needs to run on macOS", err)
		return info
	}
	defer func() { _ = unix.Close(fd) }()
	control := unix.CtlInfo{}
	copy(control.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, &control); err != nil {
		info.Detail = fmt.Sprintf("CTLIOCGINFO for %s failed: %v; the process must be signed and hold the network entitlement", utunControlName, err)
		return info
	}
	info.Available = true
	info.Detail = "utun kernel control is resolvable; interface addresses and routes still need the SystemNetwork owner"
	return info
}

// Open implements HostAdapter. It performs the real utun connection.
func (darwinHostAdapter) Open(ctx context.Context, opts DeviceOptions) (PacketDevice, error) {
	return openUtunDevice(ctx, opts)
}

// resolveHostAdapter implements the per-GOOS dispatch declared by
// ResolveHostAdapter.
func resolveHostAdapter(platform Platform) (HostAdapter, error) {
	switch platform {
	case PlatformDarwin:
		return darwinHostAdapter{}, nil
	case PlatformLinux:
		return nil, fmt.Errorf("%w: the Linux TUN backend needs a linux build; this process was built for darwin", ErrPlatformUnavailable)
	case PlatformWindows:
		return nil, fmt.Errorf("%w: the Windows Wintun backend needs a windows build; this process was built for darwin", ErrPlatformUnavailable)
	default:
		return nil, fmt.Errorf("%w: unknown platform %q", ErrPlatformUnavailable, platform)
	}
}

// utunDevice is one connected utun interface.
type utunDevice struct {
	name string
	mtu  int
	// address is the prefix the caller asked to install, reported back through
	// DeviceInfo so a zero Prefix never renders as "invalid Prefix".
	address netip.Prefix
	fd      int
	wake    descriptorWake

	ioMu sync.RWMutex

	events chan DeviceEvent

	mu       sync.Mutex
	closed   bool
	closeErr error

	buffers sync.Pool
}

// InterfaceName returns the kernel-assigned utunN name.
func (d *utunDevice) InterfaceName() string { return d.name }

// MTU implements PacketDevice. It is the MTU this process configures through
// the journaled SystemNetwork transaction; Open has not changed the interface.
func (d *utunDevice) MTU() int { return d.mtu }

// Events implements PacketDevice.
func (d *utunDevice) Events() <-chan DeviceEvent { return d.events }

// DeviceInfo implements DeviceReporter. MTU is the MTU this process will
// configure through the journaled SystemNetwork transaction; Open has not
// touched the interface yet. Owned is true because connecting the PF_SYSTEM
// control created this utun and closing it releases the interface.
func (d *utunDevice) DeviceInfo() DeviceInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	return DeviceInfo{
		Platform: PlatformDarwin,
		Name:     d.name,
		MTU:      d.mtu,
		Address:  d.address,
		Ready:    !d.closed,
		Owned:    true,
	}
}

func (d *utunDevice) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// Close is idempotent and wakes a blocked reader before releasing the socket.
func (d *utunDevice) Close() error {
	d.mu.Lock()
	if d.closed {
		err := d.closeErr
		d.mu.Unlock()
		return err
	}
	d.closed = true
	d.mu.Unlock()

	d.wake.signal()

	d.ioMu.Lock()
	closeErr := unix.Close(d.fd)
	d.wake.close()
	d.ioMu.Unlock()

	kind := "closed"
	if closeErr != nil {
		kind = "error"
	}
	select {
	case d.events <- DeviceEvent{Kind: kind, MTU: d.mtu, Err: closeErr}:
	default:
	}
	close(d.events)

	d.mu.Lock()
	d.closeErr = closeErr
	d.mu.Unlock()
	return closeErr
}

func (d *utunDevice) buffer() *[]byte {
	if pooled, ok := d.buffers.Get().(*[]byte); ok {
		return pooled
	}
	buffer := make([]byte, d.mtu+utunHeaderSize+1)
	return &buffer
}

// ReadPacket implements PacketDevice. The 4-byte utun address-family prefix is
// stripped; the returned bytes are one complete IP packet. A buffer smaller than
// the device MTU is refused before reading.
func (d *utunDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	if len(buf) < d.mtu {
		return 0, fmt.Errorf("%w: buffer %d bytes, device MTU %d", ErrBufferTooSmall, len(buf), d.mtu)
	}
	d.ioMu.RLock()
	defer d.ioMu.RUnlock()
	if d.isClosed() {
		return 0, ErrDeviceClosed
	}
	scratch := d.buffer()
	defer d.buffers.Put(scratch)
	for {
		if err := deviceContextErr(ctx, d.name); err != nil {
			return 0, err
		}
		if err := pollDevice(ctx, d.fd, unix.POLLIN, d.wake, d.name); err != nil {
			return 0, err
		}
		if d.isClosed() {
			return 0, ErrDeviceClosed
		}
		// The wake may have been this context's own cancellation. Re-checking
		// here means an already-cancelled caller never consumes a packet that
		// was readable when it cancelled.
		if err := deviceContextErr(ctx, d.name); err != nil {
			return 0, err
		}
		read, err := unix.Read(d.fd, *scratch)
		switch {
		case err == nil && read == 0:
			return 0, fmt.Errorf("agent: read %s: %w", d.name, ErrDeviceClosed)
		case err == nil:
			if read < utunHeaderSize {
				return 0, fmt.Errorf("%w: utun delivered %d bytes without its address-family prefix", ErrInvalidPacket, read)
			}
			family := binary.BigEndian.Uint32((*scratch)[:utunHeaderSize])
			payload := (*scratch)[utunHeaderSize:read]
			if err := utunPayloadValid(family, payload, d.mtu); err != nil {
				return 0, err
			}
			copy(buf, payload)
			return len(payload), nil
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
			continue
		default:
			return 0, fmt.Errorf("agent: read %s: %w", d.name, err)
		}
	}
}

// WritePacket implements PacketDevice. The payload must be one complete IPv4
// packet; the AF_INET prefix the kernel expects is prepended on a private copy.
func (d *utunDevice) WritePacket(ctx context.Context, packet []byte) error {
	if err := ipv4PacketValid(packet); err != nil {
		return err
	}
	if len(packet) > d.mtu {
		return fmt.Errorf("%w: %d bytes, device MTU %d", ErrPacketTooLarge, len(packet), d.mtu)
	}
	assembled := make([]byte, utunHeaderSize+len(packet))
	binary.BigEndian.PutUint32(assembled[:utunHeaderSize], uint32(unix.AF_INET))
	copy(assembled[utunHeaderSize:], packet)

	d.ioMu.RLock()
	defer d.ioMu.RUnlock()
	if d.isClosed() {
		return ErrDeviceClosed
	}
	// A valid packet on an already-cancelled context must not be injected, and a
	// cancellation that arrives while waiting for writability must not either.
	if err := deviceContextErr(ctx, d.name); err != nil {
		return err
	}
	for {
		written, err := unix.Write(d.fd, assembled)
		switch {
		case err == nil && written == len(assembled):
			return nil
		case err == nil:
			return fmt.Errorf("agent: write %s: short write %d of %d bytes", d.name, written, len(assembled))
		case errors.Is(err, unix.EAGAIN):
			if err := pollDevice(ctx, d.fd, unix.POLLOUT, d.wake, d.name); err != nil {
				return err
			}
			if d.isClosed() {
				return ErrDeviceClosed
			}
			if err := deviceContextErr(ctx, d.name); err != nil {
				return err
			}
		case errors.Is(err, unix.EINTR):
			continue
		default:
			return fmt.Errorf("agent: write %s: %w", d.name, err)
		}
	}
}

// utunPayloadValid checks the address-family prefix against the IP version and
// the MTU. The IPv4-only core filters IPv6 packets later; the device itself only
// guarantees a well-formed family/version pair.
func utunPayloadValid(family uint32, payload []byte, mtu int) error {
	if len(payload) == 0 {
		return fmt.Errorf("%w: utun delivered an empty packet", ErrInvalidPacket)
	}
	version := payload[0] >> 4
	switch family {
	case unix.AF_INET:
		if version != 4 {
			return fmt.Errorf("%w: AF_INET prefix on an IP version %d packet", ErrInvalidPacket, version)
		}
	case unix.AF_INET6:
		if version != 6 {
			return fmt.Errorf("%w: AF_INET6 prefix on an IP version %d packet", ErrInvalidPacket, version)
		}
	default:
		return fmt.Errorf("%w: utun address family %d", ErrInvalidPacket, family)
	}
	if len(payload) > mtu {
		return fmt.Errorf("%w: device delivered %d bytes on a %d-byte MTU interface", ErrPacketTooLarge, len(payload), mtu)
	}
	return nil
}

// newUtunWake creates the macOS wake channel: a non-blocking pipe.
func newUtunWake() (descriptorWake, error) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		return descriptorWake{}, err
	}
	_ = unix.SetNonblock(fds[0], true)
	_ = unix.SetNonblock(fds[1], true)
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	return descriptorWake{readFd: fds[0], writeFd: fds[1]}, nil
}

// setUtunInterfaceMTU is deliberately absent: the interface MTU is a journaled
// side effect of the SystemNetwork transaction (sysnet_darwin.go), never an
// un-journaled side effect of Open.

// openUtunDevice connects one utun unit and publishes it as a PacketDevice.
// It creates the interface and reads the kernel-assigned name; it changes no
// interface property.
func openUtunDevice(ctx context.Context, opts DeviceOptions) (*utunDevice, error) {
	if err := packetDeviceContextErr(ctx); err != nil {
		return nil, err
	}
	mtu, err := clampDeviceMTU(opts.MTU)
	if err != nil {
		return nil, err
	}
	// macOS assigns utunN at connect time and offers no rename, so a requested
	// name cannot be honoured. Failing is honest; silently ignoring it is not.
	if opts.Name != "" {
		return nil, fmt.Errorf("%w: macOS assigns utunN names at connect time; leave device.name empty on darwin", ErrInvalidConfig)
	}
	fd, err := unix.Socket(utunAFSystem, unix.SOCK_DGRAM, utunSysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("%w: socket(PF_SYSTEM, SYSPROTO_CONTROL): %w; the process must run on macOS and hold the network entitlement", ErrPlatformUnavailable, err)
	}
	control := unix.CtlInfo{}
	copy(control.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, &control); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: CTLIOCGINFO for %s: %w; the process must be signed and entitled for utun", ErrPlatformUnavailable, utunControlName, err)
	}
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: control.Id, Unit: 0}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: connect utun unit: %w; check the network entitlement and that no unit limit is exhausted", ErrPlatformUnavailable, err)
	}
	name, err := unix.GetsockoptString(fd, utunSysprotoControl, utunOptIfname)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: UTUN_OPT_IFNAME: %w", ErrPlatformUnavailable, err)
	}
	if name == "" {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: the kernel did not report a utun interface name", ErrPlatformUnavailable)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: set utun socket non-blocking: %w", ErrPlatformUnavailable, err)
	}
	// The MTU is intentionally not applied here. mtu is the value this device
	// will carry and the value the journaled SystemNetwork transaction will set;
	// the interface keeps its kernel value until Apply, so Prepare can snapshot
	// and Rollback can restore it.
	wake, err := newUtunWake()
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: create wake pipe for %s: %v", ErrPlatformUnavailable, name, err)
	}
	device := &utunDevice{
		name:    name,
		mtu:     mtu,
		address: opts.Address,
		fd:      fd,
		wake:    wake,
		events:  make(chan DeviceEvent, 8),
	}
	device.buffers.New = func() any {
		buffer := make([]byte, mtu+utunHeaderSize+1)
		return &buffer
	}
	device.events <- DeviceEvent{Kind: "ready", MTU: mtu}
	return device, nil
}

var _ HostAdapter = darwinHostAdapter{}
var _ AdapterInspector = darwinHostAdapter{}
var _ PacketDevice = (*utunDevice)(nil)
var _ DeviceReporter = (*utunDevice)(nil)
