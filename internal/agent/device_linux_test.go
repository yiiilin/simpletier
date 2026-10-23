//go:build linux

package agent

// Real Linux device runtime tests.
//
// These tests open an actual /dev/net/tun interface through the production
// adapter, configure the interface through the production SystemNetwork
// transaction and move real IPv4 packets through the kernel stack. They require
// CAP_NET_ADMIN (or root) and a present /dev/net/tun; when the environment does
// not provide that, the open fails with the production ErrPlatformUnavailable
// error and the test skips with that exact reason instead of pretending to pass.
// No test escalates privilege or shells out.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var testTUNCounter atomic.Uint32

// testTUNName returns a short, unique interface name inside IFNAMSIZ.
func testTUNName() string {
	return fmt.Sprintf("st%x%x", os.Getpid()&0xffff, testTUNCounter.Add(1))
}

// openTestTUN opens a real TUN device through the production adapter. A missing
// capability or device node is an external environment blocker and skips.
func openTestTUN(t *testing.T, opts DeviceOptions) *tunDevice {
	t.Helper()
	if opts.MTU == 0 {
		opts.MTU = DefaultDeviceMTU
	}
	if opts.Name == "" {
		opts.Name = testTUNName()
	}
	adapter, err := ResolveHostAdapter(PlatformLinux)
	if err != nil {
		t.Fatalf("ResolveHostAdapter(linux): %v", err)
	}
	device, err := adapter.Open(context.Background(), opts)
	if err != nil {
		if errors.Is(err, ErrPlatformUnavailable) {
			// Report the exact external condition (errno text plus the adapter's
			// own readiness inspection) instead of a bare skip.
			info := adapter.(AdapterInspector).AdapterInfo()
			t.Skipf("external blocker: adapter resolved but the device did not open: %v (inspected available=%v device=%s detail=%q)",
				err, info.Available, info.DevicePath, info.Detail)
		}
		t.Fatalf("Open(%+v): %v", opts, err)
	}
	tun, ok := device.(*tunDevice)
	if !ok {
		t.Fatalf("the linux adapter returned %T, want *tunDevice", device)
	}
	t.Cleanup(func() { _ = tun.Close() })
	return tun
}

// applyTestSystemNetwork runs the production Prepare/Apply transaction and
// registers rollback+close cleanup, which runs before the device cleanup.
func applyTestSystemNetwork(t *testing.T, opts SystemNetworkOptions) *linuxSystemNetwork {
	t.Helper()
	network, err := newLinuxSystemNetwork(opts)
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork(%+v): %v", opts, err)
	}
	if err := network.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare(%+v): %v", opts, err)
	}
	if err := network.Apply(context.Background()); err != nil {
		_ = network.Rollback(context.Background())
		_ = network.Close()
		if errors.Is(err, ErrPlatformUnavailable) {
			t.Skipf("external blocker: cannot configure host networking: %v", err)
		}
		t.Fatalf("Apply(%+v): %v", opts, err)
	}
	t.Cleanup(func() {
		_ = network.Rollback(context.Background())
		_ = network.Close()
	})
	return network
}

func TestLinuxTUNDeviceMetadataAndClose(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{Address: netip.MustParsePrefix("10.201.0.7/32")})
	if device.MTU() != DefaultDeviceMTU {
		t.Fatalf("MTU() = %d, want %d", device.MTU(), DefaultDeviceMTU)
	}
	info := device.DeviceInfo()
	if info.Platform != PlatformLinux || !info.Ready {
		t.Fatalf("DeviceInfo = %+v, want a ready linux device", info)
	}
	if info.Name != device.InterfaceName() || info.Name == "" {
		t.Fatalf("DeviceInfo name %q, interface name %q", info.Name, device.InterfaceName())
	}
	if len(device.InterfaceName()) >= ifnamsiz {
		t.Fatalf("interface name %q is longer than IFNAMSIZ allows", device.InterfaceName())
	}
	if _, err := net.InterfaceByName(device.InterfaceName()); err != nil {
		t.Fatalf("the kernel does not know interface %q: %v", device.InterfaceName(), err)
	}
	// Open owns the device handle only. The interface MTU is a journaled
	// SystemNetwork side effect, so opening a device must not change it: the
	// transaction needs to snapshot the prior value first.
	if info.MTU != DefaultDeviceMTU {
		t.Fatalf("DeviceInfo MTU %d, want the bounded %d", info.MTU, DefaultDeviceMTU)
	}
	// Address is what the caller asked to install on this device. It is part of the
	// reported identity, and leaving it at the zero Prefix made String() render as
	// "invalid Prefix" wherever the info was logged or compared.
	if want := netip.MustParsePrefix("10.201.0.7/32"); info.Address != want {
		t.Fatalf("DeviceInfo Address = %v; want %v", info.Address, want)
	}
	select {
	case event := <-device.Events():
		if event.Kind != "ready" || event.MTU != DefaultDeviceMTU {
			t.Fatalf("first device event %+v, want ready/%d", event, DefaultDeviceMTU)
		}
	default:
		t.Fatal("opening the device must publish a ready event")
	}
	if err := device.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}
	if _, err := device.ReadPacket(context.Background(), make([]byte, DefaultDeviceMTU)); !errors.Is(err, ErrDeviceClosed) {
		t.Fatalf("ReadPacket after Close error %v, want ErrDeviceClosed", err)
	}
	if _, err := net.InterfaceByName(info.Name); err == nil {
		t.Fatalf("interface %q still exists after Close", info.Name)
	}
}

func TestLinuxTUNPacketRoundTripThroughHostStack(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	address := netip.MustParsePrefix("10.207.11.1/32")
	remotePrefix := netip.MustParsePrefix("10.207.12.0/24")
	remote := netip.MustParseAddr("10.207.12.5")
	applyTestSystemNetwork(t, SystemNetworkOptions{
		Interface: device.InterfaceName(),
		MTU:       DefaultDeviceMTU,
		Address:   address,
		Routes:    []netip.Prefix{remotePrefix},
	})

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(address.Addr().AsSlice()), Port: 0})
	if err != nil {
		t.Fatalf("bind a UDP socket on the virtual address %s: %v", address, err)
	}
	defer listener.Close()
	localPort := listener.LocalAddr().(*net.UDPAddr).Port

	// Ingress: writing an IPv4/UDP packet to the TUN injects it into the kernel
	// as a received packet, which the local UDP socket must observe.
	ingress := buildTestUDPPacket(t, remote, address.Addr(), 40000, uint16(localPort), []byte("tun-in"))
	if err := device.WritePacket(context.Background(), ingress); err != nil {
		t.Fatalf("WritePacket(ingress): %v", err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	payload := make([]byte, 2048)
	read, from, err := listener.ReadFromUDP(payload)
	if err != nil {
		t.Fatalf("the kernel stack did not deliver the injected packet: %v", err)
	}
	if string(payload[:read]) != "tun-in" || !from.IP.Equal(net.IP(remote.AsSlice())) {
		t.Fatalf("delivered payload %q from %v, want %q from %s", payload[:read], from, "tun-in", remote)
	}

	// Egress: the kernel routes the reply to the remote prefix out the TUN, so
	// ReadPacket must return that complete IPv4/UDP packet. A freshly created
	// interface also emits IPv6 link-local traffic (DAD/MLD); the IPv4-only core
	// filters it, so this test reads past non-IPv4 packets and fails if the
	// expected UDP packet never arrives.
	if _, err := listener.WriteToUDP([]byte("tun-out"), &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: 40000}); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	readCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	buffer := make([]byte, DefaultDeviceMTU)
	skipped := 0
	for {
		count, err := device.ReadPacket(readCtx, buffer)
		if err != nil {
			t.Fatalf("ReadPacket(egress) after skipping %d non-IPv4 packets: %v", skipped, err)
		}
		egress := buffer[:count]
		if len(egress) == 0 || egress[0]>>4 != 4 {
			skipped++
			continue
		}
		source, destination, sourcePort, destinationPort, body := parseTestUDPPacket(t, egress)
		if source != address.Addr() || destination != remote {
			t.Fatalf("egress %s -> %s, want %s -> %s", source, destination, address.Addr(), remote)
		}
		if int(sourcePort) != localPort || destinationPort != 40000 {
			t.Fatalf("egress ports %d -> %d, want %d -> 40000", sourcePort, destinationPort, localPort)
		}
		if string(body) != "tun-out" {
			t.Fatalf("egress payload %q, want %q", body, "tun-out")
		}
		t.Logf("read the expected IPv4/UDP egress packet after skipping %d non-IPv4 packets", skipped)
		return
	}
}

func TestLinuxTUNReadCancellationAndCloseInterrupt(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := device.ReadPacket(ctx, make([]byte, DefaultDeviceMTU)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled ReadPacket error %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancellation took %s; a blocked read must not wait for traffic", elapsed)
	}

	blocked := make(chan error, 1)
	go func() {
		_, err := device.ReadPacket(context.Background(), make([]byte, DefaultDeviceMTU))
		blocked <- err
	}()
	time.Sleep(150 * time.Millisecond)
	if err := device.Close(); err != nil {
		t.Fatalf("Close while a read is blocked: %v", err)
	}
	select {
	case err := <-blocked:
		if !errors.Is(err, ErrDeviceClosed) {
			t.Fatalf("blocked ReadPacket returned %v, want ErrDeviceClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not interrupt a blocked ReadPacket")
	}
}

func TestLinuxTUNWriteAndBufferValidation(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	ctx := context.Background()

	oversize := make([]byte, DefaultDeviceMTU+1)
	oversize[0] = 0x45
	binary.BigEndian.PutUint16(oversize[2:4], uint16(len(oversize)))
	if err := device.WritePacket(ctx, oversize); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("oversize write error %v, want ErrPacketTooLarge", err)
	}
	notIPv4 := make([]byte, 40)
	notIPv4[0] = 0x60
	binary.BigEndian.PutUint16(notIPv4[4:6], uint16(len(notIPv4)))
	if err := device.WritePacket(ctx, notIPv4); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("non-IPv4 write error %v, want ErrInvalidPacket", err)
	}
	if err := device.WritePacket(ctx, nil); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("empty write error %v, want ErrInvalidPacket", err)
	}
	if _, err := device.ReadPacket(ctx, make([]byte, DefaultDeviceMTU-1)); !errors.Is(err, ErrBufferTooSmall) {
		t.Fatalf("short read buffer error %v, want ErrBufferTooSmall", err)
	}
	if _, err := device.ReadPacket(ctx, nil); !errors.Is(err, ErrBufferTooSmall) {
		t.Fatalf("nil read buffer error %v, want ErrBufferTooSmall", err)
	}
}

func TestLinuxTUNRepairHints(t *testing.T) {
	cases := []struct {
		err      error
		contains string
	}{
		{unix.EPERM, "CAP_NET_ADMIN"},
		{unix.EACCES, "CAP_NET_ADMIN"},
		{unix.ENOENT, "modprobe tun"},
		{unix.EBUSY, "name"},
		{unix.EINVAL, "IFF_NO_PI"},
		{unix.ENODEV, "namespace"},
		{errors.New("other"), tunDevicePath},
	}
	for _, testCase := range cases {
		hint := tunRepairHint(testCase.err)
		if !strings.Contains(hint, testCase.contains) {
			t.Fatalf("tunRepairHint(%v) = %q, want it to mention %q", testCase.err, hint, testCase.contains)
		}
	}
}

func TestLinuxTUNNameTooLongIsRejected(t *testing.T) {
	adapter, err := ResolveHostAdapter(PlatformLinux)
	if err != nil {
		t.Fatalf("ResolveHostAdapter(linux): %v", err)
	}
	longName := strings.Repeat("a", ifnamsiz)
	if _, err := adapter.Open(context.Background(), DeviceOptions{Name: longName}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("oversized interface name error %v, want ErrInvalidConfig", err)
	}
}

// TestLinuxTUNMissingDeviceNodeIsDiagnosable separates the two conditions a bare
// "platform unavailable" hides: resolving a backend (a linux build always has
// one) and actually opening the device (which needs /dev/net/tun and
// CAP_NET_ADMIN). The missing-device path is reproduced by pointing the clone
// device at a controlled nonexistent path, so the exact errno can be asserted
// without touching the host's real device node.
func TestLinuxTUNMissingDeviceNodeIsDiagnosable(t *testing.T) {
	original := tunDevicePath
	tunDevicePath = filepath.Join(t.TempDir(), "missing-tun")
	t.Cleanup(func() { tunDevicePath = original })

	// Construction succeeds: the linux build resolves a concrete adapter.
	adapter, err := ResolveHostAdapter(PlatformLinux)
	if err != nil {
		t.Fatalf("ResolveHostAdapter(linux) must succeed in a linux build: %v", err)
	}
	inspector, ok := adapter.(AdapterInspector)
	if !ok {
		t.Fatalf("the linux adapter %T does not implement AdapterInspector", adapter)
	}
	info := inspector.AdapterInfo()
	if info.Available {
		t.Fatalf("AdapterInfo must report the missing device node as unavailable: %+v", info)
	}
	if !strings.Contains(info.Detail, tunDevicePath) {
		t.Fatalf("adapter detail %q must name the missing path %q", info.Detail, tunDevicePath)
	}

	// Open fails with the exact errno and the repair step, not a generic error.
	_, openErr := adapter.Open(context.Background(), DeviceOptions{Name: testTUNName()})
	if !errors.Is(openErr, ErrPlatformUnavailable) {
		t.Fatalf("Open error %v, want ErrPlatformUnavailable", openErr)
	}
	if !errors.Is(openErr, unix.ENOENT) {
		t.Fatalf("Open error %v must carry the exact ENOENT errno", openErr)
	}
	if !strings.Contains(openErr.Error(), "modprobe tun") {
		t.Fatalf("Open error %q must contain the actionable repair step", openErr)
	}
	if !strings.Contains(openErr.Error(), tunDevicePath) {
		t.Fatalf("Open error %q must name %q", openErr, tunDevicePath)
	}
}

// TestLinuxTUNEnvironmentRecordsActualCondition records the real environment and
// asserts the error-class contract: either a TUN device opens, or the failure
// wraps ErrPlatformUnavailable together with a recognisable errno, so an
// external blocker is reported with the exact cause instead of a vague skip.
func TestLinuxTUNEnvironmentRecordsActualCondition(t *testing.T) {
	info, err := InspectHostAdapter(PlatformLinux)
	if err != nil {
		t.Fatalf("InspectHostAdapter(linux): %v", err)
	}
	t.Logf("adapter inspection: available=%v device=%s driver=%s maxMTU=%d detail=%q",
		info.Available, info.DevicePath, info.Driver, info.MaxMTU, info.Detail)
	adapter, err := ResolveHostAdapter(PlatformLinux)
	if err != nil {
		t.Fatalf("ResolveHostAdapter(linux): %v", err)
	}
	name := testTUNName()
	device, err := adapter.Open(context.Background(), DeviceOptions{Name: name})
	if err != nil {
		if !errors.Is(err, ErrPlatformUnavailable) {
			t.Fatalf("Open error %v, want ErrPlatformUnavailable", err)
		}
		recognised := errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EPERM) ||
			errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EBUSY)
		if !recognised {
			t.Fatalf("external TUN failure %v must carry a recognisable errno (ENOENT/EPERM/EACCES/ENODEV/EBUSY)", err)
		}
		t.Skipf("external blocker recorded: %v", err)
	}
	defer device.Close()
	tun := device.(*tunDevice)
	t.Logf("real device opened: name=%s mtu=%d", tun.InterfaceName(), tun.MTU())
}

// --- SystemNetwork ---------------------------------------------------------

func TestLinuxSystemNetworkStateAndErrors(t *testing.T) {
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{Interface: "stmissing0"})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	if network.State() != SystemNetworkAbsent {
		t.Fatalf("initial state %s, want absent", network.State())
	}
	if err := network.Apply(context.Background()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Apply before Prepare error %v, want ErrInvalidConfig", err)
	}
	if err := network.Prepare(context.Background()); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("Prepare on a missing interface error %v, want ErrPlatformUnavailable", err)
	}
	if err := network.Close(); err != nil {
		t.Fatalf("Close on an absent transaction: %v", err)
	}
	if network.State() != SystemNetworkClosed {
		t.Fatalf("state after Close = %s, want closed", network.State())
	}
	if err := network.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestLinuxSystemNetworkApplyAndRollback(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	name := device.InterfaceName()
	address := netip.MustParsePrefix("10.207.31.1/32")
	routePrefix := netip.MustParsePrefix("10.207.32.0/24")

	// Start from a different MTU so Apply's MTU step and rollback's restore are
	// both exercised.
	if err := setInterfaceMTU(name, 1400); err != nil {
		t.Fatalf("seed interface MTU: %v", err)
	}
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface: name,
		MTU:       DefaultDeviceMTU,
		Address:   address,
		Routes:    []netip.Prefix{routePrefix},
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	if err := network.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if network.State() != SystemNetworkPrepared {
		t.Fatalf("state after Prepare = %s", network.State())
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	if link.MTU != 1400 {
		t.Fatalf("Prepare mutated the MTU to %d; it must not touch the OS", link.MTU)
	}
	if hasTestAddress(t, link, address.Addr()) {
		t.Fatal("Prepare assigned the address; it must not touch the OS")
	}

	if err := network.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if network.State() != SystemNetworkApplied {
		t.Fatalf("state after Apply = %s", network.State())
	}
	link, err = net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q after Apply: %v", name, err)
	}
	if link.MTU != DefaultDeviceMTU {
		t.Fatalf("interface MTU after Apply = %d, want %d", link.MTU, DefaultDeviceMTU)
	}
	if link.Flags&net.FlagUp == 0 {
		t.Fatal("Apply must bring the interface up")
	}
	if !hasTestAddress(t, link, address.Addr()) {
		t.Fatalf("Apply did not assign %s", address)
	}
	present, _, err := routePresent(routePrefix, link.Index)
	if err != nil {
		t.Fatalf("routePresent: %v", err)
	}
	if !present {
		t.Fatalf("Apply did not install route %s on %s", routePrefix, name)
	}
	if len(network.Journal()) == 0 {
		t.Fatal("the transaction must journal its intents")
	}

	if err := network.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if network.State() != SystemNetworkRollback {
		t.Fatalf("state after Rollback = %s", network.State())
	}
	link, err = net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q after Rollback: %v", name, err)
	}
	if link.MTU != 1400 {
		t.Fatalf("Rollback left MTU %d, want the original 1400", link.MTU)
	}
	if hasTestAddress(t, link, address.Addr()) {
		t.Fatalf("Rollback left address %s behind", address)
	}
	present, _, err = routePresent(routePrefix, link.Index)
	if err != nil {
		t.Fatalf("routePresent after Rollback: %v", err)
	}
	if present {
		t.Fatalf("Rollback left route %s behind", routePrefix)
	}
	if err := network.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if network.State() != SystemNetworkClosed {
		t.Fatalf("state after Close = %s", network.State())
	}
}

func TestLinuxSystemNetworkKeepsExternalChanges(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	name := device.InterfaceName()
	address := netip.MustParsePrefix("10.207.41.1/32")
	if err := setInterfaceMTU(name, 1400); err != nil {
		t.Fatalf("seed interface MTU: %v", err)
	}
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface: name,
		MTU:       DefaultDeviceMTU,
		Address:   address,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	if err := network.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// An external actor changes the MTU after the transaction applied it.
	if err := setInterfaceMTU(name, 1420); err != nil {
		t.Fatalf("external MTU change: %v", err)
	}
	if err := network.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if network.State() != SystemNetworkDegraded {
		t.Fatalf("state after an external change = %s, want degraded", network.State())
	}
	detail := network.DegradedDetail()
	if len(detail) == 0 {
		t.Fatal("degraded rollback must record what it refused to overwrite")
	}
	if !strings.Contains(strings.Join(detail, " "), "MTU") {
		t.Fatalf("degraded detail %v does not mention the MTU", detail)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	if link.MTU != 1420 {
		t.Fatalf("keep-external rule broken: MTU is %d, want the external 1420", link.MTU)
	}
	// The address this transaction owns is still removed.
	if hasTestAddress(t, link, address.Addr()) {
		t.Fatalf("Rollback left its own address %s behind", address)
	}
	if err := network.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestLinuxSystemNetworkJournalIsPersisted(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	name := device.InterfaceName()
	path := t.TempDir() + "/sysnet.journal"
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		MTU:         DefaultDeviceMTU,
		JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	if err := network.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := network.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if !strings.Contains(string(payload), `"interface":"`+name+`"`) {
		t.Fatalf("persisted journal %q does not record interface %q", payload, name)
	}
	if !strings.Contains(string(payload), `"kind":"apply:`) {
		t.Fatalf("persisted journal %q does not record an apply intent", payload)
	}
}

// --- Agent integration -----------------------------------------------------

func TestAgentTUNLinuxOpensRealDeviceAndCleansUp(t *testing.T) {
	name := testTUNName()
	address := netip.MustParsePrefix("10.207.51.1/32")
	route := netip.MustParsePrefix("10.207.52.0/24")
	socks5 := socksProxyConfig(ProxyOptions{})
	socks5.Listen = "127.0.0.1:0"
	config := AgentConfig{
		Platform: PlatformLinux,
		Inbounds: Inbounds{TUN: boolPointer(true), SOCKS5: &socks5},
		Device:   DeviceConfig{Name: name, Address: address, Routes: []netip.Prefix{route}},
	}
	agent, err := New(config, Deps{Dialer: newScriptedDialer(nil), Listen: testListenFunc()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Start(context.Background()); err != nil {
		if errors.Is(err, ErrPlatformUnavailable) {
			t.Skipf("external blocker: agent TUN start unavailable: %v", err)
		}
		t.Fatalf("Start: %v", err)
	}
	if agent.PacketDevice() == nil {
		t.Fatal("Start with inbounds.tun reported success without an open PacketDevice")
	}
	info, ok := agent.DeviceInfo()
	if !ok || !info.Ready {
		t.Fatalf("DeviceInfo = %+v, %v; want a ready device", info, ok)
	}
	if info.Name != name || info.MTU != DefaultDeviceMTU {
		t.Fatalf("DeviceInfo = %+v, want name %q and MTU %d", info, name, DefaultDeviceMTU)
	}
	if agent.SystemNetwork() == nil {
		t.Fatal("a device address was requested but no host network transaction was created")
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q was not created: %v", name, err)
	}
	if link.MTU != DefaultDeviceMTU {
		t.Fatalf("interface MTU %d, want %d", link.MTU, DefaultDeviceMTU)
	}
	if !hasTestAddress(t, link, address.Addr()) {
		t.Fatalf("interface %q does not carry %s", name, address)
	}
	if socksAddr, _ := agent.ListenAddrs(); socksAddr == nil {
		t.Fatal("the proxy listener was not bound after the device opened")
	}
	adapterInfo, err := agent.AdapterInfo()
	if err != nil {
		t.Fatalf("AdapterInfo: %v", err)
	}
	if adapterInfo.Platform != PlatformLinux || !adapterInfo.Available {
		t.Fatalf("AdapterInfo = %+v, want an available linux adapter", adapterInfo)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if agent.PacketDevice() != nil {
		t.Fatal("PacketDevice still reports a device after Close")
	}
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatalf("Close left interface %q behind", name)
	}
}

// --- helpers ---------------------------------------------------------------

func hasTestAddress(t *testing.T, link *net.Interface, want netip.Addr) bool {
	t.Helper()
	for _, address := range mustAddrs(link) {
		if address.Addr() == want {
			return true
		}
	}
	return false
}

// buildTestUDPPacket encodes one complete IPv4 UDP packet with a valid IPv4
// header checksum and a valid UDP checksum over the IPv4 pseudo-header.
func buildTestUDPPacket(t *testing.T, source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte) []byte {
	t.Helper()
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], testUDPChecksum(source, destination, udp))

	header := make([]byte, 20)
	header[0] = 0x45
	header[1] = 0
	binary.BigEndian.PutUint16(header[2:4], uint16(len(header)+len(udp)))
	binary.BigEndian.PutUint16(header[4:6], 0)
	header[6] = 0x40
	header[8] = 64
	header[9] = 17
	copy(header[12:16], source.AsSlice())
	copy(header[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(header[10:12], testHeaderChecksum(header))
	return append(header, udp...)
}

// parseTestUDPPacket decodes one complete IPv4 UDP packet and fails the test on
// anything unexpected.
func parseTestUDPPacket(t *testing.T, packet []byte) (netip.Addr, netip.Addr, uint16, uint16, []byte) {
	t.Helper()
	if err := ipv4PacketValid(packet); err != nil {
		t.Fatalf("egress packet is not one complete IPv4 packet: %v", err)
	}
	if packet[9] != 17 {
		t.Fatalf("egress protocol %d, want UDP (17)", packet[9])
	}
	source, ok := netip.AddrFromSlice(packet[12:16])
	if !ok {
		t.Fatal("egress packet has no IPv4 source")
	}
	destination, ok := netip.AddrFromSlice(packet[16:20])
	if !ok {
		t.Fatal("egress packet has no IPv4 destination")
	}
	headerLength := int(packet[0]&0x0f) * 4
	udp := packet[headerLength:]
	if len(udp) < 8 {
		t.Fatal("egress packet has a truncated UDP header")
	}
	length := int(binary.BigEndian.Uint16(udp[4:6]))
	if length != len(udp) {
		t.Fatalf("egress UDP length %d does not match %d bytes", length, len(udp))
	}
	return source.Unmap(), destination.Unmap(),
		binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4]), udp[8:length]
}

func testHeaderChecksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	return testFoldChecksum(sum)
}

func testUDPChecksum(source, destination netip.Addr, udp []byte) uint16 {
	var sum uint32
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	for index := 0; index < 4; index += 2 {
		sum += uint32(binary.BigEndian.Uint16(sourceBytes[index : index+2]))
		sum += uint32(binary.BigEndian.Uint16(destinationBytes[index : index+2]))
	}
	sum += uint32(17)
	sum += uint32(len(udp))
	for index := 0; index+1 < len(udp); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[index : index+2]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	checksum := testFoldChecksum(sum)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func testFoldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

// --- Agent transaction wiring ----------------------------------------------

// recordingSystemNetwork is a SystemNetwork double used to prove the Agent's
// transaction wiring: it records the options the Agent derived from the opened
// device, and whether Apply/Rollback/Close were called. The real netlink owner
// is covered by the tests above; this double covers the Agent's ordering and
// cleanup on success and failure.
type recordingSystemNetwork struct {
	mu         sync.Mutex
	opts       SystemNetworkOptions
	state      SystemNetworkState
	applyErr   error
	prepared   bool
	applied    bool
	rolledBack bool
	closed     bool
	// delegate, when set, receives every call after it is recorded, so a test can
	// combine the Agent's transaction wiring with the real platform owner.
	delegate SystemNetwork
}

func (r *recordingSystemNetwork) State() SystemNetworkState {
	r.mu.Lock()
	delegate := r.delegate
	state := r.state
	r.mu.Unlock()
	if delegate != nil {
		return delegate.State()
	}
	return state
}

func (r *recordingSystemNetwork) Prepare(ctx context.Context) error {
	r.mu.Lock()
	r.prepared = true
	r.state = SystemNetworkPrepared
	delegate := r.delegate
	r.mu.Unlock()
	if delegate != nil {
		return delegate.Prepare(ctx)
	}
	return nil
}

func (r *recordingSystemNetwork) Apply(ctx context.Context) error {
	r.mu.Lock()
	if r.applyErr != nil {
		err := r.applyErr
		r.mu.Unlock()
		return err
	}
	r.applied = true
	r.state = SystemNetworkApplied
	delegate := r.delegate
	r.mu.Unlock()
	if delegate != nil {
		return delegate.Apply(ctx)
	}
	return nil
}

func (r *recordingSystemNetwork) Rollback(ctx context.Context) error {
	r.mu.Lock()
	r.rolledBack = true
	r.state = SystemNetworkRollback
	delegate := r.delegate
	r.mu.Unlock()
	if delegate != nil {
		return delegate.Rollback(ctx)
	}
	return nil
}

func (r *recordingSystemNetwork) Close() error {
	r.mu.Lock()
	r.closed = true
	r.state = SystemNetworkClosed
	delegate := r.delegate
	r.mu.Unlock()
	if delegate != nil {
		return delegate.Close()
	}
	return nil
}

func (r *recordingSystemNetwork) snapshot() (SystemNetworkOptions, bool, bool, bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.opts, r.prepared, r.applied, r.rolledBack, r.closed
}

func TestAgentTUNSystemNetworkTransactionWiring(t *testing.T) {
	name := testTUNName()
	address := netip.MustParsePrefix("10.207.61.1/32")
	route := netip.MustParsePrefix("10.207.62.0/24")
	network := &recordingSystemNetwork{}
	config := AgentConfig{
		Platform: PlatformLinux,
		Inbounds: Inbounds{TUN: boolPointer(true)},
		Device:   DeviceConfig{Name: name, Address: address, Routes: []netip.Prefix{route}},
	}
	var derivedName string
	agent, err := New(config, Deps{SystemNetwork: func(interfaceName string, opts SystemNetworkOptions) (SystemNetwork, error) {
		derivedName = interfaceName
		network.mu.Lock()
		network.opts = opts
		network.mu.Unlock()
		return network, nil
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Start(context.Background()); err != nil {
		if errors.Is(err, ErrPlatformUnavailable) {
			t.Skipf("external blocker: %v", err)
		}
		t.Fatalf("Start: %v", err)
	}
	opts, prepared, applied, rolledBack, closed := network.snapshot()
	if derivedName != name {
		t.Fatalf("the factory received interface %q, want the opened device %q", derivedName, name)
	}
	if !prepared || !applied || rolledBack || closed {
		t.Fatalf("transaction calls prepared=%v applied=%v rolledBack=%v closed=%v", prepared, applied, rolledBack, closed)
	}
	if opts.Interface != name || opts.MTU != DefaultDeviceMTU || opts.Address != address || len(opts.Routes) != 1 || opts.Routes[0] != route {
		t.Fatalf("the Agent derived %+v from the device and DeviceConfig", opts)
	}
	if agent.SystemNetwork() != SystemNetwork(network) {
		t.Fatal("the Agent does not expose the transaction owner it created")
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, _, _, rolledBack, closed = network.snapshot()
	if !rolledBack || !closed {
		t.Fatalf("Close must roll back and close the transaction: rolledBack=%v closed=%v", rolledBack, closed)
	}
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatalf("Close left interface %q behind", name)
	}
}

func TestAgentTUNSystemNetworkApplyFailureCleansUp(t *testing.T) {
	name := testTUNName()
	address := netip.MustParsePrefix("10.207.71.1/32")
	applyErr := errors.New("injected apply failure")
	network := &recordingSystemNetwork{applyErr: applyErr}
	config := AgentConfig{
		Platform: PlatformLinux,
		Inbounds: Inbounds{TUN: boolPointer(true)},
		Device:   DeviceConfig{Name: name, Address: address},
	}
	agent, err := New(config, Deps{SystemNetwork: func(string, SystemNetworkOptions) (SystemNetwork, error) {
		return network, nil
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	startErr := agent.Start(context.Background())
	if startErr == nil {
		t.Fatal("Start succeeded although the host network transaction failed")
	}
	// The injected SystemNetwork is a stub, but Start opens the real PacketDevice
	// before consulting it. Without CAP_NET_ADMIN that open fails first and the
	// rollback path this test exists to prove is never reached, so the case is
	// unprovable here rather than broken.
	if errors.Is(startErr, ErrPlatformUnavailable) {
		t.Skipf("external blocker: no TUN capability: %v", startErr)
	}
	if !errors.Is(startErr, applyErr) {
		t.Fatalf("Start error %v must carry the injected Apply failure", startErr)
	}
	_, prepared, applied, rolledBack, closed := network.snapshot()
	if !prepared || applied || !rolledBack || !closed {
		t.Fatalf("failed Apply must roll back and close: prepared=%v applied=%v rolledBack=%v closed=%v", prepared, applied, rolledBack, closed)
	}
	if agent.PacketDevice() != nil {
		t.Fatal("a failed Start left the PacketDevice open")
	}
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatalf("a failed Start left interface %q behind", name)
	}
	// The Agent must be startable again after the failed Start.
	if err := agent.Close(); err != nil {
		t.Fatalf("Close after a failed Start: %v", err)
	}
}

func TestAgentTUNAppliesMTUThroughTransactionWithoutAddressOrRoutes(t *testing.T) {
	name := testTUNName()
	recorder := &recordingSystemNetwork{}
	var received SystemNetworkOptions
	calls := 0
	config := AgentConfig{
		Platform: PlatformLinux,
		Inbounds: Inbounds{TUN: boolPointer(true)},
		Device:   DeviceConfig{Name: name},
	}
	agent, err := New(config, Deps{SystemNetwork: func(interfaceName string, opts SystemNetworkOptions) (SystemNetwork, error) {
		calls++
		received = opts
		real, err := NewSystemNetwork(PlatformLinux, interfaceName, opts)
		if err != nil {
			return nil, err
		}
		recorder.mu.Lock()
		recorder.delegate = real
		recorder.mu.Unlock()
		return recorder, nil
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Start(context.Background()); err != nil {
		if errors.Is(err, ErrPlatformUnavailable) {
			t.Skipf("external blocker: %v", err)
		}
		t.Fatalf("Start: %v", err)
	}
	// A device with no address and no routes still needs its bounded MTU applied,
	// and that change must be journaled and rollbackable rather than an
	// un-journaled side effect of opening the device.
	if calls != 1 {
		t.Fatalf("the Agent must build one host network transaction to apply the MTU, got %d calls", calls)
	}
	if received.MTU != DefaultDeviceMTU {
		t.Fatalf("transaction MTU %d, want the bounded %d", received.MTU, DefaultDeviceMTU)
	}
	if received.Address.IsValid() || len(received.Routes) != 0 {
		t.Fatalf("transaction unexpectedly carries address %v routes %v", received.Address, received.Routes)
	}
	if !recorder.applied {
		t.Fatal("the MTU transaction was not applied")
	}
	if agent.SystemNetwork() == nil {
		t.Fatal("no transaction owner was created")
	}
	if link, err := net.InterfaceByName(name); err != nil {
		t.Fatalf("interface %q: %v", name, err)
	} else if link.MTU != DefaultDeviceMTU {
		t.Fatalf("interface MTU %d, want the applied %d", link.MTU, DefaultDeviceMTU)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !recorder.rolledBack || !recorder.closed {
		t.Fatalf("Close must roll the MTU transaction back: rolledBack=%v closed=%v", recorder.rolledBack, recorder.closed)
	}
}

func TestAgentTUNListenerBindFailureClosesDevice(t *testing.T) {
	name := testTUNName()
	socks5 := socksProxyConfig(ProxyOptions{})
	socks5.Listen = "127.0.0.1:0"
	config := AgentConfig{
		Platform: PlatformLinux,
		Inbounds: Inbounds{TUN: boolPointer(true), SOCKS5: &socks5},
		Device:   DeviceConfig{Name: name},
	}
	bindErr := errors.New("injected bind failure")
	agent, err := New(config, Deps{
		Dialer: newScriptedDialer(nil),
		Listen: func(context.Context, string, string) (net.Listener, error) {
			return nil, bindErr
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = agent.Start(context.Background())
	if err == nil {
		t.Fatal("Start succeeded although the proxy listener could not bind")
	}
	if errors.Is(err, ErrPlatformUnavailable) {
		t.Skipf("external blocker: %v", err)
	}
	if !errors.Is(err, bindErr) {
		t.Fatalf("Start error %v must carry the injected bind failure", err)
	}
	if agent.PacketDevice() != nil {
		t.Fatal("a failed proxy bind left the PacketDevice open")
	}
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatalf("a failed proxy bind left interface %q behind", name)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("Close after a failed Start: %v", err)
	}
}

// --- cancellation boundary -------------------------------------------------

// TestLinuxTUNPreCancelledContextDoesNotInjectOrConsume proves the cancellation
// boundary: a context that is already cancelled must not inject a packet into
// the host stack and must not consume a packet that is already readable.
func TestLinuxTUNPreCancelledContextDoesNotInjectOrConsume(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	address := netip.MustParsePrefix("10.207.81.1/32")
	remotePrefix := netip.MustParsePrefix("10.207.82.0/24")
	remote := netip.MustParseAddr("10.207.82.9")
	applyTestSystemNetwork(t, SystemNetworkOptions{
		Interface: device.InterfaceName(),
		MTU:       DefaultDeviceMTU,
		Address:   address,
		Routes:    []netip.Prefix{remotePrefix},
	})

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(address.Addr().AsSlice()), Port: 0})
	if err != nil {
		t.Fatalf("bind UDP socket on %s: %v", address, err)
	}
	defer listener.Close()
	localPort := listener.LocalAddr().(*net.UDPAddr).Port

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	// 1. Ingress must not happen on a cancelled context.
	ingress := buildTestUDPPacket(t, remote, address.Addr(), 40001, uint16(localPort), []byte("cancelled-in"))
	if err := device.WritePacket(cancelled, ingress); !errors.Is(err, context.Canceled) {
		t.Fatalf("WritePacket with a cancelled context error %v, want context.Canceled", err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, 2048)
	if _, _, err := listener.ReadFromUDP(buffer); err == nil {
		t.Fatal("a cancelled WritePacket still injected a packet into the host stack")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected a read timeout proving no injection, got %v", err)
	}

	// 2. Egress: queue a real packet, then a cancelled read must not consume it.
	if _, err := listener.WriteToUDP([]byte("survives-cancel"), &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: 40001}); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := device.ReadPacket(cancelled, buffer); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadPacket with a cancelled context error %v, want context.Canceled", err)
	}
	// The packet must still be there: read with a live context and look for it,
	// skipping the kernel's IPv6 link-local noise.
	liveCtx, liveCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer liveCancel()
	for {
		count, err := device.ReadPacket(liveCtx, buffer)
		if err != nil {
			t.Fatalf("the cancelled ReadPacket consumed the queued packet: %v", err)
		}
		if count == 0 || buffer[0]>>4 != 4 {
			continue
		}
		_, _, sourcePort, destinationPort, body := parseTestUDPPacket(t, buffer[:count])
		if int(sourcePort) != localPort || destinationPort != 40001 {
			t.Fatalf("unexpected packet %d -> %d", sourcePort, destinationPort)
		}
		if string(body) != "survives-cancel" {
			t.Fatalf("payload %q, want %q", body, "survives-cancel")
		}
		return
	}
}

// TestLinuxTUNCancelledReadBeforePacketArrivesReturnsImmediately checks that a
// cancellation that arrives while nothing is readable fails fast and leaves the
// device usable.
func TestLinuxTUNCancelledReadBeforePacketArrivesReturnsImmediately(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := device.ReadPacket(cancelled, make([]byte, DefaultDeviceMTU)); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadPacket error %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a pre-cancelled read waited %s; it must observe cancellation immediately", elapsed)
	}
}

// TestLinuxTUNCancelCloseRaceReusesWakeDescriptors cancels a read and closes the
// device concurrently many times. It is the regression test for the wake
// descriptor lifetime: the cancellation callback must have finished before the
// device lock is released, otherwise Close can free the descriptor while the
// callback still writes it. Run under -race to cover the shared state.
func TestLinuxTUNCancelCloseRaceReusesWakeDescriptors(t *testing.T) {
	for attempt := 0; attempt < 40; attempt++ {
		adapter, err := ResolveHostAdapter(PlatformLinux)
		if err != nil {
			t.Fatalf("ResolveHostAdapter(linux): %v", err)
		}
		device, err := adapter.Open(context.Background(), DeviceOptions{Name: testTUNName()})
		if err != nil {
			if errors.Is(err, ErrPlatformUnavailable) {
				t.Skipf("external blocker: %v", err)
			}
			t.Fatalf("Open: %v", err)
		}
		tun := device.(*tunDevice)
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		readDone := make(chan error, 1)
		go func() {
			_, err := tun.ReadPacket(ctx, make([]byte, DefaultDeviceMTU))
			readDone <- err
		}()
		cancel()
		if err := tun.Close(); err != nil {
			t.Fatalf("Close during a cancelled read: %v", err)
		}
		select {
		case err := <-readDone:
			if err == nil {
				t.Fatal("a cancelled read reported success")
			}
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrDeviceClosed) {
				t.Fatalf("unexpected read error %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a cancelled read did not return after Close")
		}
	}
}

// --- crash recovery --------------------------------------------------------

// TestLinuxSystemNetworkRecovery proves the durability half of the contract:
// after a crash (the transaction object is abandoned without Rollback), a new
// process can load the persisted journal and remove only the resources whose
// fingerprint still matches, keeping externally modified values.
func TestLinuxSystemNetworkRecovery(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	name := device.InterfaceName()
	address := netip.MustParsePrefix("10.207.91.1/32")
	routePrefix := netip.MustParsePrefix("10.207.92.0/24")
	if err := setInterfaceMTU(name, 1500); err != nil {
		t.Fatalf("seed MTU: %v", err)
	}
	journalPath := t.TempDir() + "/recovery.journal"
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		MTU:         DefaultDeviceMTU,
		Address:     address,
		Routes:      []netip.Prefix{routePrefix},
		JournalPath: journalPath,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	if err := network.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Simulate a crash: release the journal file without rolling back.
	if err := network.journal.close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	entries, err := LoadJournal(journalPath)
	if err != nil {
		t.Fatalf("LoadJournal: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("the persisted journal is empty")
	}

	report, err := RecoverLinuxSystemNetwork(context.Background(), name, journalPath)
	if err != nil {
		t.Fatalf("RecoverLinuxSystemNetwork: %v", err)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	if hasTestAddress(t, link, address.Addr()) {
		t.Fatalf("recovery left address %s behind: %+v", address, report)
	}
	present, _, err := routePresent(routePrefix, link.Index)
	if err != nil {
		t.Fatalf("routePresent: %v", err)
	}
	if present {
		t.Fatalf("recovery left route %s behind: %+v", routePrefix, report)
	}
	if link.MTU != 1500 {
		t.Fatalf("recovery left MTU %d, want the prior 1500: %+v", link.MTU, report)
	}
	if len(report.Removed) == 0 {
		t.Fatalf("recovery removed nothing: %+v", report)
	}
}

// TestLinuxSystemNetworkRecoveryKeepsExternalChanges checks that recovery never
// overwrites a value someone else changed after the crash.
func TestLinuxSystemNetworkRecoveryKeepsExternalChanges(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	name := device.InterfaceName()
	journalPath := t.TempDir() + "/recovery-external.journal"
	if err := setInterfaceMTU(name, 1500); err != nil {
		t.Fatalf("seed MTU: %v", err)
	}
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		MTU:         DefaultDeviceMTU,
		JournalPath: journalPath,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	if err := network.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := network.journal.close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	// An external actor changes the MTU after the crash.
	if err := setInterfaceMTU(name, 1420); err != nil {
		t.Fatalf("external MTU change: %v", err)
	}
	report, err := RecoverLinuxSystemNetwork(context.Background(), name, journalPath)
	if err != nil {
		t.Fatalf("RecoverLinuxSystemNetwork: %v", err)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	if link.MTU != 1420 {
		t.Fatalf("recovery overwrote the external MTU %d: %+v", link.MTU, report)
	}
	if len(report.Degraded) == 0 {
		t.Fatalf("recovery did not report the external modification: %+v", report)
	}
}
