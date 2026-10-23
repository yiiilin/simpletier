//go:build windows

package agent

// Windows host adapter: the real Wintun backend.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Requirement anchors (prose, not ownership pointers): R-L3-001, R-L3-005; the
// L3 feature prose path is docs/domains/overlay/features/l3-vpn.md.
//
// Wintun is a driver plus a user-space DLL (wintun.dll). The backend loads the
// DLL dynamically, opens or creates an adapter, starts one session and moves
// packets through the session ring: WintunReceivePacket/WintunReleaseReceivePacket
// for reads and WintunAllocateSendPacket/WintunSendPacket for writes. A packet
// returned by the receive side is copied out and immediately released, so no
// goroutine keeps a pointer into a ring slot after release.
//
// Adapter ownership uses the official Close contract, not a guessed delete API:
// WintunCloseAdapter removes an adapter that WintunCreateAdapter created and
// leaves an adapter that WintunOpenAdapter opened in place, so Open records
// whether it created the adapter (DeviceInfo.Owned) and Close simply closes the
// handle. The official ABI (api/exports.def) exports no WintunDeleteAdapter, so
// requiring one would misreport every current wintun.dll as incomplete.
//
// Missing DLL, missing export, missing driver or missing Administrator rights
// produce an actionable error instead of a fake success. Open touches no OS
// network state: the adapter's OS-level MTU is applied by the journaled Windows
// SystemNetwork owner (sysnet_windows.go) so intent is fsynced before the
// change and Rollback can restore the prior value. This device reports the
// bounded virtual MTU and refuses larger packets with ErrPacketTooLarge rather
// than truncating them.
//
// Runtime verification on Windows is not possible from this repository's Linux
// host. The code is cross-compiled only; that is a compile check, not platform
// acceptance. Driver installation, elevation and ring behaviour must be verified
// on a real Windows host.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// wintunDLLName is the user-space half of the Wintun driver package.
	wintunDLLName = "wintun.dll"
	// wintunRingCapacity is the session ring size in bytes. 2 MiB matches the
	// P1 per-device bound (<= 1024 packets / 2 MiB) and is inside Wintun's
	// allowed 128 KiB..64 MiB power-of-two range.
	wintunRingCapacity = 0x200000
	// wintunTunnelType tags the adapter this project creates.
	wintunTunnelType = "SimpleTier"
	// wintunDefaultAdapter is used when no device name is configured.
	wintunDefaultAdapter = "SimpleTier"
	// wintunSendPollMin/Max bound the ring-full retry backoff (Wintun has no
	// send-ready event, so a full send ring is retried with a bounded sleep).
	wintunSendPollMin = time.Millisecond
	wintunSendPollMax = 10 * time.Millisecond
)

// wintunAPI holds the dynamically resolved Wintun exports.
type wintunAPI struct {
	createAdapter        *windows.LazyProc
	openAdapter          *windows.LazyProc
	closeAdapter         *windows.LazyProc
	startSession         *windows.LazyProc
	endSession           *windows.LazyProc
	getReadWaitEvent     *windows.LazyProc
	receivePacket        *windows.LazyProc
	releaseReceivePacket *windows.LazyProc
	allocateSendPacket   *windows.LazyProc
	sendPacket           *windows.LazyProc
	// moveMemory is kernel32!RtlMoveMemory. Wintun returns raw ring addresses as
	// uintptr values, and this project does not convert a syscall-returned
	// uintptr back into a Go pointer (go vet's unsafeptr check rejects that,
	// and the conversion is outside the unsafe.Pointer rules anyway). Copying
	// through RtlMoveMemory keeps the ring access vet-clean and adds no kernel
	// transition: it is one plain memmove inside the process.
	moveMemory *windows.LazyProc
}

var (
	wintunOnce    sync.Once
	wintunLoaded  *wintunAPI
	wintunLoadErr error
)

// loadWintun resolves wintun.dll once per process. A missing library or export
// is remembered so inspection and Open both report the same actionable error.
func loadWintun() (*wintunAPI, error) {
	wintunOnce.Do(func() {
		dll := windows.NewLazyDLL(wintunDLLName)
		if err := dll.Load(); err != nil {
			wintunLoadErr = fmt.Errorf("%w: %s could not be loaded: %v; install the Wintun driver from https://www.wintun.net and place %s next to the executable or on PATH with the same architecture as the process",
				ErrDriverMissing, wintunDLLName, err, wintunDLLName)
			return
		}
		api := &wintunAPI{
			createAdapter:        dll.NewProc("WintunCreateAdapter"),
			openAdapter:          dll.NewProc("WintunOpenAdapter"),
			closeAdapter:         dll.NewProc("WintunCloseAdapter"),
			startSession:         dll.NewProc("WintunStartSession"),
			endSession:           dll.NewProc("WintunEndSession"),
			getReadWaitEvent:     dll.NewProc("WintunGetReadWaitEvent"),
			receivePacket:        dll.NewProc("WintunReceivePacket"),
			releaseReceivePacket: dll.NewProc("WintunReleaseReceivePacket"),
			allocateSendPacket:   dll.NewProc("WintunAllocateSendPacket"),
			sendPacket:           dll.NewProc("WintunSendPacket"),
		}
		exports := map[string]*windows.LazyProc{
			"WintunCreateAdapter":        api.createAdapter,
			"WintunOpenAdapter":          api.openAdapter,
			"WintunCloseAdapter":         api.closeAdapter,
			"WintunStartSession":         api.startSession,
			"WintunEndSession":           api.endSession,
			"WintunGetReadWaitEvent":     api.getReadWaitEvent,
			"WintunReceivePacket":        api.receivePacket,
			"WintunReleaseReceivePacket": api.releaseReceivePacket,
			"WintunAllocateSendPacket":   api.allocateSendPacket,
			"WintunSendPacket":           api.sendPacket,
		}
		for exportName, proc := range exports {
			if err := proc.Find(); err != nil {
				wintunLoadErr = fmt.Errorf("%w: %s does not export %s: %v; the installed Wintun version is too old",
					ErrDriverMissing, wintunDLLName, exportName, err)
				return
			}
		}
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		if err := kernel32.Load(); err != nil {
			wintunLoadErr = fmt.Errorf("%w: kernel32.dll could not be loaded: %v", ErrDriverMissing, err)
			return
		}
		api.moveMemory = kernel32.NewProc("RtlMoveMemory")
		if err := api.moveMemory.Find(); err != nil {
			wintunLoadErr = fmt.Errorf("%w: kernel32.dll does not export RtlMoveMemory: %v", ErrDriverMissing, err)
			return
		}
		wintunLoaded = api
	})
	return wintunLoaded, wintunLoadErr
}

// wintunCallError normalises a DLL call result. LazyProc.Call can report a nil
// error even when the call failed (GetLastError stayed zero), which would turn a
// real failure into an empty diagnostic.
func wintunCallError(err error) error {
	if err == nil {
		return errors.New("the Wintun call failed without a reported error")
	}
	return err
}

// wintunHostAdapter is the Windows HostAdapter implementation.
type wintunHostAdapter struct{}

// Platform implements HostAdapter.
func (wintunHostAdapter) Platform() Platform { return PlatformWindows }

// AdapterInfo implements AdapterInspector by attempting to load wintun.dll. It
// does not create an adapter or a session.
func (wintunHostAdapter) AdapterInfo() AdapterInfo {
	info := AdapterInfo{
		Platform: PlatformWindows,
		Driver:   "Wintun (dynamic " + wintunDLLName + " session ring)",
		MaxMTU:   DefaultDeviceMTU,
	}
	if _, err := loadWintun(); err != nil {
		info.Detail = err.Error()
		return info
	}
	info.Available = true
	info.Detail = "wintun.dll loaded; adapter creation still needs Administrator rights, and the adapter MTU is applied by the journaled Windows SystemNetwork transaction, not by Open"
	return info
}

// Open implements HostAdapter. It performs the real Wintun adapter/session work.
func (wintunHostAdapter) Open(ctx context.Context, opts DeviceOptions) (PacketDevice, error) {
	return openWintunDevice(ctx, opts)
}

// resolveHostAdapter implements the per-GOOS dispatch declared by
// ResolveHostAdapter.
func resolveHostAdapter(platform Platform) (HostAdapter, error) {
	switch platform {
	case PlatformWindows:
		return wintunHostAdapter{}, nil
	case PlatformLinux:
		return nil, fmt.Errorf("%w: the Linux TUN backend needs a linux build; this process was built for windows", ErrPlatformUnavailable)
	case PlatformDarwin:
		return nil, fmt.Errorf("%w: the macOS utun backend needs a darwin build; this process was built for windows", ErrPlatformUnavailable)
	default:
		return nil, fmt.Errorf("%w: unknown platform %q", ErrPlatformUnavailable, platform)
	}
}

// wintunDevice is one open Wintun adapter with one session.
type wintunDevice struct {
	api     *wintunAPI
	adapter windows.Handle
	session windows.Handle

	name    string
	mtu     int
	created bool
	// address is the prefix the caller asked to install, reported back through
	// DeviceInfo so a zero Prefix never renders as "invalid Prefix".
	address    netip.Prefix
	readEvent  windows.Handle
	closeEvent windows.Handle

	events chan DeviceEvent

	// ioMu serialises Close against an in-flight wait/receive/send so no handle
	// is ended or closed while a reader or writer is still inside it. Close
	// signals the close event first, so a blocked wait returns and releases it.
	ioMu sync.RWMutex

	mu        sync.Mutex
	closed    bool
	closeErr  error
	closeOnce sync.Once
}

// InterfaceName returns the adapter name.
func (d *wintunDevice) InterfaceName() string { return d.name }

// MTU implements PacketDevice.
func (d *wintunDevice) MTU() int { return d.mtu }

// Events implements PacketDevice.
func (d *wintunDevice) Events() <-chan DeviceEvent { return d.events }

// DeviceInfo implements DeviceReporter.
func (d *wintunDevice) DeviceInfo() DeviceInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	return DeviceInfo{
		Platform: PlatformWindows,
		Name:     d.name,
		MTU:      d.mtu,
		Address:  d.address,
		Ready:    !d.closed,
		Owned:    d.created,
	}
}

func (d *wintunDevice) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// Close is idempotent: it wakes a blocked reader, ends the session and closes
// the adapter exactly once.
func (d *wintunDevice) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()

		if d.closeEvent != 0 {
			_ = windows.SetEvent(d.closeEvent)
		}
		// Wait for an in-flight wait/receive/send to leave the session and the
		// close event before either is destroyed.
		d.ioMu.Lock()
		if d.session != 0 {
			d.api.endSession.Call(uintptr(d.session))
		}
		if d.adapter != 0 {
			// Verified against the official Wintun ABI: WintunCloseAdapter
			// "Releases Wintun adapter resources and, if adapter was created with
			// WintunCreateAdapter, removes adapter."
			//   https://git.zx2c4.com/wintun/plain/README.md (WintunCloseAdapter)
			//   https://git.zx2c4.com/wintun/plain/api/exports.def
			// Wintun has no WintunDeleteAdapter export, so requiring one would
			// break every released DLL. Basing cleanup on this single documented
			// call is therefore both the real ABI and the ownership-correct
			// behaviour: a created adapter is removed, an adapter obtained with
			// WintunOpenAdapter is retained for its owner.
			d.api.closeAdapter.Call(uintptr(d.adapter))
		}
		if d.closeEvent != 0 {
			_ = windows.CloseHandle(d.closeEvent)
		}
		d.ioMu.Unlock()
		select {
		case d.events <- DeviceEvent{Kind: "closed", MTU: d.mtu}:
		default:
		}
		close(d.events)
	})
	return d.closeErr
}

// ReadPacket implements PacketDevice: one complete IPv4 packet per call.
func (d *wintunDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	if len(buf) < d.mtu {
		return 0, fmt.Errorf("%w: buffer %d bytes, device MTU %d", ErrBufferTooSmall, len(buf), d.mtu)
	}
	// The join guarantees the cancellation callback has stopped touching the
	// close event before this returns and the caller's ioMu read lock is
	// released, so Close can never destroy a handle a late callback still uses.
	defer afterFuncJoined(ctx, func() { _ = windows.SetEvent(d.closeEvent) })()

	d.ioMu.RLock()
	defer d.ioMu.RUnlock()
	for {
		if d.isClosed() {
			return 0, ErrDeviceClosed
		}
		if err := deviceContextErr(ctx, d.name); err != nil {
			return 0, err
		}
		wait, err := windows.WaitForMultipleObjects(
			[]windows.Handle{d.readEvent, d.closeEvent}, false, wintunWaitMillis(ctx))
		if err != nil {
			return 0, fmt.Errorf("agent: wait on %s: %w", d.name, err)
		}
		if wait == windows.WAIT_OBJECT_0+1 {
			// The close event is auto-reset and serves both Close and context
			// cancellation. A signal from an earlier cancelled read is retried
			// rather than misreported as a closed device.
			if err := packetDeviceContextErr(ctx); err != nil {
				return 0, fmt.Errorf("agent: %s: %w", d.name, err)
			}
			if !d.isClosed() {
				continue
			}
			return 0, ErrDeviceClosed
		}
		if wait == uint32(windows.WAIT_TIMEOUT) {
			continue
		}
		if err := deviceContextErr(ctx, d.name); err != nil {
			return 0, err
		}
		var size uint32
		packet, _, callErr := d.api.receivePacket.Call(uintptr(d.session), uintptr(unsafe.Pointer(&size)))
		if packet == 0 {
			if errors.Is(callErr, windows.ERROR_NO_MORE_ITEMS) {
				continue
			}
			if d.isClosed() {
				return 0, ErrDeviceClosed
			}
			return 0, fmt.Errorf("agent: WintunReceivePacket on %s: %w", d.name, callErr)
		}
		if size > uint32(d.mtu) {
			d.api.releaseReceivePacket.Call(uintptr(d.session), packet)
			return 0, fmt.Errorf("%w: device delivered %d bytes on a %d-byte MTU interface", ErrPacketTooLarge, size, d.mtu)
		}
		if int(size) > len(buf) {
			d.api.releaseReceivePacket.Call(uintptr(d.session), packet)
			return 0, fmt.Errorf("%w: buffer %d bytes, packet %d bytes", ErrBufferTooSmall, len(buf), size)
		}
		if size == 0 {
			d.api.releaseReceivePacket.Call(uintptr(d.session), packet)
			return 0, fmt.Errorf("%w: Wintun delivered an empty packet", ErrInvalidPacket)
		}
		// Copy out, then release: nothing may reference the ring slot afterwards.
		d.api.moveMemory.Call(uintptr(unsafe.Pointer(&buf[0])), packet, uintptr(size))
		d.api.releaseReceivePacket.Call(uintptr(d.session), packet)
		return int(size), nil
	}
}

// WritePacket implements PacketDevice. The payload must be one complete IPv4
// packet; it is copied into the send ring before WintunSendPacket.
func (d *wintunDevice) WritePacket(ctx context.Context, packet []byte) error {
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
	// A valid packet on an already-cancelled context must never be sent.
	if err := deviceContextErr(ctx, d.name); err != nil {
		return err
	}
	backoff := wintunSendPollMin
	for {
		slot, _, callErr := d.api.allocateSendPacket.Call(uintptr(d.session), uintptr(len(packet)))
		if slot == 0 {
			if !errors.Is(callErr, windows.ERROR_BUFFER_OVERFLOW) {
				if d.isClosed() {
					return ErrDeviceClosed
				}
				return fmt.Errorf("agent: WintunAllocateSendPacket on %s: %w", d.name, callErr)
			}
			// The send ring is full. Wintun has no send-ready event, so retry
			// after a bounded sleep, re-checking Close and the context between
			// attempts. No goroutine is started per attempt.
			deadline := time.Now().Add(backoff)
			for {
				if d.isClosed() {
					return ErrDeviceClosed
				}
				if err := packetDeviceContextErr(ctx); err != nil {
					return fmt.Errorf("agent: %s: %w", d.name, err)
				}
				if !time.Now().Before(deadline) {
					break
				}
				time.Sleep(time.Millisecond)
			}
			backoff *= 2
			if backoff > wintunSendPollMax {
				backoff = wintunSendPollMax
			}
			continue
		}
		d.api.moveMemory.Call(slot, uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)))
		d.api.sendPacket.Call(uintptr(d.session), slot)
		return nil
	}
}

// wintunWaitMillis converts a context deadline into a WaitForMultipleObjects
// timeout. A deadline-less context waits in bounded slices so Close is always
// observed.
func wintunWaitMillis(ctx context.Context) uint32 {
	const cancelledSliceMillis = 1000
	if ctx == nil {
		return cancelledSliceMillis
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return cancelledSliceMillis
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	millis := int64(remaining / time.Millisecond)
	if millis <= 0 {
		return 1
	}
	if millis > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(millis)
}

// openWintunDevice opens an existing adapter or creates one, then starts the
// session ring and the read-wait event.
func openWintunDevice(ctx context.Context, opts DeviceOptions) (*wintunDevice, error) {
	if err := packetDeviceContextErr(ctx); err != nil {
		return nil, err
	}
	mtu, err := clampDeviceMTU(opts.MTU)
	if err != nil {
		return nil, err
	}
	api, err := loadWintun()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPlatformUnavailable, err)
	}
	name := opts.Name
	if name == "" {
		name = wintunDefaultAdapter
	}
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("%w: adapter name %q: %v", ErrInvalidConfig, name, err)
	}
	tunnelPointer, err := windows.UTF16PtrFromString(wintunTunnelType)
	if err != nil {
		return nil, fmt.Errorf("%w: tunnel type %q: %v", ErrInvalidConfig, wintunTunnelType, err)
	}

	created := false
	adapter, _, openErr := api.openAdapter.Call(uintptr(unsafe.Pointer(namePointer)))
	if adapter == 0 {
		adapter, _, openErr = api.createAdapter.Call(
			uintptr(unsafe.Pointer(namePointer)), uintptr(unsafe.Pointer(tunnelPointer)), 0)
		if adapter != 0 {
			created = true
		}
	}
	if adapter == 0 {
		return nil, fmt.Errorf("%w: WintunOpenAdapter/WintunCreateAdapter(%q) failed: %w; run elevated (Administrator) and verify the Wintun driver is installed",
			ErrPlatformUnavailable, name, wintunCallError(openErr))
	}
	session, _, sessionErr := api.startSession.Call(adapter, uintptr(wintunRingCapacity))
	if session == 0 {
		api.closeAdapter.Call(adapter)
		return nil, fmt.Errorf("%w: WintunStartSession(%q, %d bytes) failed: %w", ErrPlatformUnavailable, name, wintunRingCapacity, wintunCallError(sessionErr))
	}
	readEvent, _, eventErr := api.getReadWaitEvent.Call(uintptr(session))
	if readEvent == 0 {
		api.endSession.Call(session)
		api.closeAdapter.Call(adapter)
		return nil, fmt.Errorf("%w: WintunGetReadWaitEvent(%q) failed: %w", ErrPlatformUnavailable, name, wintunCallError(eventErr))
	}
	closeEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		api.endSession.Call(session)
		api.closeAdapter.Call(adapter)
		return nil, fmt.Errorf("%w: create close event for %q: %v", ErrPlatformUnavailable, name, err)
	}
	device := &wintunDevice{
		api:        api,
		adapter:    windows.Handle(adapter),
		session:    windows.Handle(session),
		name:       name,
		mtu:        mtu,
		created:    created,
		address:    opts.Address,
		readEvent:  windows.Handle(readEvent),
		closeEvent: closeEvent,
		events:     make(chan DeviceEvent, 8),
	}
	device.events <- DeviceEvent{Kind: "ready", MTU: mtu}
	return device, nil
}

var _ HostAdapter = wintunHostAdapter{}
var _ AdapterInspector = wintunHostAdapter{}
var _ PacketDevice = (*wintunDevice)(nil)
var _ DeviceReporter = (*wintunDevice)(nil)
