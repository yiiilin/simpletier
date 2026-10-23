//go:build linux

package agent

// Linux host adapter: the real TUN backend.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Requirement anchors (prose, not ownership pointers): R-L3-001, R-L3-005; the
// L3 feature prose path is docs/domains/overlay/features/l3-vpn.md.
//
// It opens /dev/net/tun, selects a layer-3 interface with TUNSETIFF and
// IFF_TUN|IFF_NO_PI (never TAP, never a 4-byte packet-info prefix), configures
// the frozen internal MTU and moves exactly one complete IPv4 packet per
// ReadPacket/WritePacket. Permission, device-node, name and MTU failures are
// returned with the repair step instead of being hidden behind a TCP-only
// fallback.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	// ifnamsiz is IFNAMSIZ: a Linux interface name plus its NUL terminator.
	ifnamsiz = 16
)

// tunDevicePath is the Linux TUN clone device. Opening it and issuing TUNSETIFF
// creates or attaches one virtual interface. It is a variable (not a constant)
// only so tests can point the missing-device diagnosis at a controlled path.
var tunDevicePath = "/dev/net/tun"

// linuxHostAdapter is the Linux HostAdapter implementation.
type linuxHostAdapter struct{}

// Platform implements HostAdapter.
func (linuxHostAdapter) Platform() Platform { return PlatformLinux }

// AdapterInfo implements AdapterInspector without opening the device.
func (linuxHostAdapter) AdapterInfo() AdapterInfo {
	info := AdapterInfo{
		Platform:   PlatformLinux,
		DevicePath: tunDevicePath,
		Driver:     "tun (TUNSETIFF, IFF_TUN|IFF_NO_PI)",
		MaxMTU:     DefaultDeviceMTU,
	}
	if _, err := os.Stat(tunDevicePath); err != nil {
		info.Detail = fmt.Sprintf("%s is missing (%v); load the kernel module (modprobe tun) and run in a container that passes the device through (docker --device /dev/net/tun)", tunDevicePath, err)
		return info
	}
	if err := unix.Access(tunDevicePath, unix.R_OK|unix.W_OK); err != nil {
		info.Detail = fmt.Sprintf("%s is not readable and writable (%v); grant the process access to it", tunDevicePath, err)
		return info
	}
	info.Available = true
	info.Detail = "device node present; creating the interface needs CAP_NET_ADMIN, and the interface MTU is applied by the journaled SystemNetwork transaction"
	return info
}

// Open implements HostAdapter. It performs the real TUN creation.
func (h linuxHostAdapter) Open(ctx context.Context, opts DeviceOptions) (PacketDevice, error) {
	return openTUNDevice(ctx, opts)
}

// resolveHostAdapter implements the per-GOOS dispatch declared by
// ResolveHostAdapter.
func resolveHostAdapter(platform Platform) (HostAdapter, error) {
	switch platform {
	case PlatformLinux:
		return linuxHostAdapter{}, nil
	case PlatformWindows:
		return nil, fmt.Errorf("%w: the Windows Wintun backend needs a windows build; this process was built for linux", ErrPlatformUnavailable)
	case PlatformDarwin:
		return nil, fmt.Errorf("%w: the macOS utun backend needs a darwin build; this process was built for linux", ErrPlatformUnavailable)
	default:
		return nil, fmt.Errorf("%w: unknown platform %q", ErrPlatformUnavailable, platform)
	}
}

// tunDevice is one open Linux TUN interface. It is safe for one concurrent
// reader and one concurrent writer, matching the P1 single-read/single-write
// device model; Close may run concurrently with both.
type tunDevice struct {
	name string
	mtu  int
	// address is the prefix the caller asked to install on this device, reported back
	// through DeviceInfo so a log or a comparison sees what was requested rather than a
	// zero Prefix that renders as "invalid Prefix".
	address netip.Prefix
	fd      int
	owned   bool
	wake    descriptorWake

	// ioMu serialises Close against in-flight poll/read/write so the descriptor
	// is never closed under another goroutine or reused by a later open.
	ioMu sync.RWMutex

	events chan DeviceEvent

	mu       sync.Mutex
	closed   bool
	closeErr error

	buffers sync.Pool
}

// InterfaceName returns the kernel-assigned or requested interface name.
func (d *tunDevice) InterfaceName() string { return d.name }

// MTU implements PacketDevice.
func (d *tunDevice) MTU() int { return d.mtu }

// Events implements PacketDevice.
func (d *tunDevice) Events() <-chan DeviceEvent { return d.events }

// DeviceInfo implements DeviceReporter.
func (d *tunDevice) DeviceInfo() DeviceInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	return DeviceInfo{
		Platform: PlatformLinux,
		Name:     d.name,
		MTU:      d.mtu,
		Address:  d.address,
		Ready:    !d.closed,
		Owned:    d.owned,
	}
}

func (d *tunDevice) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// Close is idempotent. It wakes any blocked reader or writer, waits for the
// in-flight operation to leave the descriptor, then closes the descriptor, the
// wake channel and the events channel exactly once.
func (d *tunDevice) Close() error {
	d.mu.Lock()
	if d.closed {
		err := d.closeErr
		d.mu.Unlock()
		return err
	}
	d.closed = true
	d.mu.Unlock()

	// Signal before taking the write lock: a blocked poll must return so its
	// holder can release ioMu.
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

// buffer returns one MTU+1 scratch buffer so a packet one byte over the MTU is
// detected as too large instead of being silently truncated.
func (d *tunDevice) buffer() *[]byte {
	if pooled, ok := d.buffers.Get().(*[]byte); ok {
		return pooled
	}
	buffer := make([]byte, d.mtu+1)
	return &buffer
}

// ReadPacket implements PacketDevice: exactly one complete IPv4 packet, or the
// context error, or ErrDeviceClosed. A buffer smaller than the device MTU is
// refused before reading, because a short read would consume and destroy the
// packet.
func (d *tunDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
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
			// A zero-length read means the interface is gone.
			return 0, fmt.Errorf("agent: read %s: %w", d.name, ErrDeviceClosed)
		case err == nil:
			if read > d.mtu {
				return 0, fmt.Errorf("%w: device delivered %d bytes on a %d-byte MTU interface", ErrPacketTooLarge, read, d.mtu)
			}
			copy(buf, (*scratch)[:read])
			return read, nil
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
			continue
		default:
			return 0, fmt.Errorf("agent: read %s: %w", d.name, err)
		}
	}
}

// WritePacket implements PacketDevice. The payload must be one complete IPv4
// packet whose total length matches its slice length and fits the device MTU.
func (d *tunDevice) WritePacket(ctx context.Context, packet []byte) error {
	if err := ipv4PacketValid(packet); err != nil {
		return err
	}
	if len(packet) > d.mtu {
		return fmt.Errorf("%w: %d bytes, device MTU %d", ErrPacketTooLarge, len(packet), d.mtu)
	}
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
		written, err := unix.Write(d.fd, packet)
		switch {
		case err == nil && written == len(packet):
			return nil
		case err == nil:
			return fmt.Errorf("agent: write %s: short write %d of %d bytes", d.name, written, len(packet))
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

// newTunWake creates the Linux wake channel: one eventfd used for both ends.
func newTunWake() (descriptorWake, error) {
	fd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return descriptorWake{}, err
	}
	return descriptorWake{readFd: fd, writeFd: fd}, nil
}

// openTUNDevice creates one TUN interface and publishes it as a PacketDevice.
func openTUNDevice(ctx context.Context, opts DeviceOptions) (*tunDevice, error) {
	if err := packetDeviceContextErr(ctx); err != nil {
		return nil, err
	}
	mtu, err := clampDeviceMTU(opts.MTU)
	if err != nil {
		return nil, err
	}
	if len(opts.Name) >= ifnamsiz {
		return nil, fmt.Errorf("%w: device name %q is %d bytes; Linux allows at most %d", ErrInvalidConfig, opts.Name, len(opts.Name), ifnamsiz-1)
	}
	// A requested name may already exist. TUNSETIFF then attaches to that interface
	// rather than failing, so ownership has to be decided before the ioctl: attaching to
	// something another program owns and then tearing it down would delete that program's
	// network configuration.
	//
	// The name is the only handle a crashed run leaves behind, so the deciding evidence is
	// whether the interface carries this node's own virtual address.
	owned := true
	if opts.Name != "" {
		if iface, err := net.InterfaceByName(opts.Name); err == nil {
			owned = false
			existing, addrErr := interfacePrefixes(iface.Index)
			if addrErr != nil {
				return nil, fmt.Errorf("%w: inspect existing interface %q: %v", ErrPlatformUnavailable, opts.Name, addrErr)
			}
			switch classifyExistingDevice(existing, opts.Address) {
			case deviceStale:
				// Left over from a run that did not shut down cleanly. Remove it so the
				// address and routes are installed from scratch instead of layered on top
				// of whatever state the crash left.
				if rmErr := removeStaleDevice(opts.Name); rmErr != nil {
					return nil, fmt.Errorf("%w: remove stale interface %q: %v", ErrPlatformUnavailable, opts.Name, rmErr)
				}
			case deviceForeign:
				return nil, foreignDeviceError(opts.Name, existing)
			}
		}
	}
	fd, err := unix.Open(tunDevicePath, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w; %s", ErrPlatformUnavailable, tunDevicePath, err, tunRepairHint(err))
	}
	request, err := unix.NewIfreq(opts.Name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: device name %q: %v", ErrInvalidConfig, opts.Name, err)
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: TUNSETIFF on %s for name %q: %w; %s", ErrPlatformUnavailable, tunDevicePath, opts.Name, err, tunRepairHint(err))
	}
	name := request.Name()
	if name == "" {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: the kernel did not report a TUN interface name", ErrPlatformUnavailable)
	}
	// MTU, addresses and routes are NOT changed here. Open only owns the device
	// handle; the MTU is a journaled SystemNetwork side effect so its prior value
	// is snapshotted before it changes and can be restored on failure or Close.
	wake, err := newTunWake()
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: create wake channel for %s: %w", ErrPlatformUnavailable, name, err)
	}
	device := &tunDevice{
		name:    name,
		mtu:     mtu,
		address: opts.Address,
		fd:      fd,
		wake:    wake,
		owned:   owned,
		events:  make(chan DeviceEvent, 8),
	}
	device.buffers.New = func() any {
		buffer := make([]byte, mtu+1)
		return &buffer
	}
	device.events <- DeviceEvent{Kind: "ready", MTU: mtu}
	return device, nil
}

// setInterfaceMTU configures the interface MTU through SIOCSIFMTU. It never
// shells out: the operation is one ioctl on a temporary AF_INET socket.
func setInterfaceMTU(name string, mtu int) error {
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(socket) }()
	request, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	request.SetUint32(uint32(mtu))
	return unix.IoctlIfreq(socket, unix.SIOCSIFMTU, request)
}

// tunRepairHint maps the errno of a failed TUN setup to the concrete repair
// step, so a missing capability is diagnosable instead of a bare "operation not
// permitted".
func tunRepairHint(err error) string {
	switch {
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return "the process needs CAP_NET_ADMIN (or root) and read/write access to " + tunDevicePath
	case errors.Is(err, unix.ENOENT):
		return "the tun kernel module is not loaded; run modprobe tun and ensure the container passes /dev/net/tun"
	case errors.Is(err, unix.EBUSY):
		return "another interface already uses that name; choose a different device name or leave it empty"
	case errors.Is(err, unix.EINVAL):
		return "the kernel does not support IFF_TUN with IFF_NO_PI on this device"
	case errors.Is(err, unix.ENODEV):
		return "the tun driver is not available in this kernel or network namespace"
	default:
		return "verify the kernel tun module, the /dev/net/tun device node and CAP_NET_ADMIN"
	}
}

var _ HostAdapter = linuxHostAdapter{}
var _ PacketDevice = (*tunDevice)(nil)
var _ AdapterInspector = linuxHostAdapter{}
var _ DeviceReporter = (*tunDevice)(nil)
