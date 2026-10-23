//go:build darwin

package agent

// Real macOS host network tests.
//
// Two layers, both compiled into the darwin build and executed only on macOS:
//
//   - Native ABI/layout, encoder and state-machine tests. These run without
//     privileges on any macOS host: they verify the Darwin wire structs against
//     the C layout, the routing-message encoder/decoder, the bounded parser and
//     the transaction/recovery state machine, including recovery of an
//     interface that no longer exists.
//   - Real utun tests. These open an actual utun interface through the
//     production adapter and drive the production SystemNetwork transaction
//     against the live kernel: MTU, IPv4 address, link state and routes are
//     applied and rolled back for real. They need root (or the network
//     entitlement); when the environment cannot provide that, the open fails
//     with the production ErrPlatformUnavailable error and the test skips with
//     that exact reason instead of pretending to pass.
//
// No test escalates privilege or shells out.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// --- ABI and encoder -------------------------------------------------------

// TestDarwinNetworkABIByteLayout verifies the hand-written wire structs against
// the Darwin C ABI on the actual host. A wrong size or offset would produce a
// request the kernel either rejects or, worse, misreads.
func TestDarwinNetworkABIByteLayout(t *testing.T) {
	if got := unsafe.Sizeof(darwinSockaddr{}); got != darwinSockaddrSize {
		t.Fatalf("sizeof(struct sockaddr) = %d, want %d", got, darwinSockaddrSize)
	}
	if got := unsafe.Sizeof(darwinSockaddrInet4{}); got != darwinSockaddrSize {
		t.Fatalf("sizeof(struct sockaddr_in) = %d, want %d", got, darwinSockaddrSize)
	}
	for _, field := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"sin_len", unsafe.Offsetof(darwinSockaddrInet4{}.Len), 0},
		{"sin_family", unsafe.Offsetof(darwinSockaddrInet4{}.Family), 1},
		{"sin_port", unsafe.Offsetof(darwinSockaddrInet4{}.Port), 2},
		{"sin_addr", unsafe.Offsetof(darwinSockaddrInet4{}.Addr), 4},
		{"sin_zero", unsafe.Offsetof(darwinSockaddrInet4{}.Zero), 8},
	} {
		if field.got != field.want {
			t.Fatalf("offsetof(%s) = %d, want %d", field.name, field.got, field.want)
		}
	}
	if got := unsafe.Sizeof(darwinIfaliasreq{}); got != 64 {
		t.Fatalf("sizeof(struct ifaliasreq) = %d, want 64", got)
	}
	for _, field := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"ifra_name", unsafe.Offsetof(darwinIfaliasreq{}.Name), 0},
		{"ifra_addr", unsafe.Offsetof(darwinIfaliasreq{}.Addr), unix.IFNAMSIZ},
		{"ifra_broadaddr", unsafe.Offsetof(darwinIfaliasreq{}.Broadaddr), unix.IFNAMSIZ + 16},
		{"ifra_mask", unsafe.Offsetof(darwinIfaliasreq{}.Mask), unix.IFNAMSIZ + 32},
	} {
		if field.got != field.want {
			t.Fatalf("offsetof(%s) = %d, want %d", field.name, field.got, field.want)
		}
	}
	if got := unsafe.Sizeof(darwinIfreqFlags{}); got != 32 {
		t.Fatalf("sizeof(struct ifreq) = %d, want 32", got)
	}
	if got := unsafe.Offsetof(darwinIfreqFlags{}.Flags); got != unix.IFNAMSIZ {
		t.Fatalf("offsetof(ifr_flags) = %d, want %d", got, unix.IFNAMSIZ)
	}
	if unix.SizeofRtMsghdr != 92 {
		t.Fatalf("sizeof(struct rt_msghdr) = %d, want 92", unix.SizeofRtMsghdr)
	}
	header := unix.RtMsghdr{}
	for _, field := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"rtm_msglen", unsafe.Offsetof(header.Msglen), 0},
		{"rtm_version", unsafe.Offsetof(header.Version), 2},
		{"rtm_type", unsafe.Offsetof(header.Type), 3},
		{"rtm_index", unsafe.Offsetof(header.Index), 4},
		{"rtm_flags", unsafe.Offsetof(header.Flags), 8},
		{"rtm_addrs", unsafe.Offsetof(header.Addrs), 12},
		{"rtm_pid", unsafe.Offsetof(header.Pid), 16},
		{"rtm_seq", unsafe.Offsetof(header.Seq), 20},
		{"rtm_errno", unsafe.Offsetof(header.Errno), 24},
	} {
		if field.got != field.want {
			t.Fatalf("offsetof(%s) = %d, want %d", field.name, field.got, field.want)
		}
	}
	if darwinRTMVersion != unix.RTM_VERSION {
		t.Fatalf("darwinRTMVersion = %d, want the kernel's RTM_VERSION %d", darwinRTMVersion, unix.RTM_VERSION)
	}
}

// TestDarwinSockaddrEncoding verifies that an IPv4 address is laid out exactly
// as sockaddr_in expects: length, family, zero port, network-order address.
func TestDarwinSockaddrEncoding(t *testing.T) {
	address := netip.MustParseAddr("10.11.12.13")
	sockaddr := darwinSockaddrInet4Of(address)
	inet := *(*darwinSockaddrInet4)(unsafe.Pointer(&sockaddr))
	if inet.Len != darwinSockaddrSize || inet.Family != uint8(unix.AF_INET) || inet.Port != 0 {
		t.Fatalf("sockaddr_in header = {len:%d family:%d port:%d}, want {16, AF_INET, 0}", inet.Len, inet.Family, inet.Port)
	}
	if want := [4]byte{10, 11, 12, 13}; inet.Addr != want {
		t.Fatalf("sockaddr_in address = %v, want %v", inet.Addr, want)
	}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&sockaddr)), darwinSockaddrSize)
	if raw[1] != uint8(unix.AF_INET) || raw[4] != 10 || raw[5] != 11 || raw[6] != 12 || raw[7] != 13 {
		t.Fatalf("wire bytes = %v, want the address at offsets 4..7 in network order", raw)
	}
	if roundTrip := darwinSockaddrInet4Addr(sockaddr); roundTrip != address {
		t.Fatalf("sockaddr round trip = %s, want %s", roundTrip, address)
	}
}

// TestDarwinNetmaskConversion verifies prefix length to netmask and back.
func TestDarwinNetmaskConversion(t *testing.T) {
	for _, testCase := range []struct {
		bits int
		want string
	}{
		{0, "0.0.0.0"},
		{1, "128.0.0.0"},
		{8, "255.0.0.0"},
		{16, "255.255.0.0"},
		{24, "255.255.255.0"},
		{25, "255.255.255.128"},
		{32, "255.255.255.255"},
	} {
		prefix := netip.PrefixFrom(netip.MustParseAddr("10.0.0.0"), testCase.bits)
		mask := darwinNetmaskAddr(prefix)
		if mask.String() != testCase.want {
			t.Fatalf("netmask of /%d = %s, want %s", testCase.bits, mask, testCase.want)
		}
		if got := darwinMaskBits(mask); got != testCase.bits {
			t.Fatalf("mask bits of %s = %d, want %d", mask, got, testCase.bits)
		}
	}
}

// TestDarwinRouteMessageEncodingRoundTrip verifies the byte-for-byte request
// the routing socket receives and the decoder that reads replies.
func TestDarwinRouteMessageEncodingRoundTrip(t *testing.T) {
	prefix := netip.MustParsePrefix("10.31.0.0/16")
	message := darwinRouteMessage(unix.RTM_ADD, prefix, 7, 42, darwinRouteFlagsStatic)
	if want := unix.SizeofRtMsghdr + 2*darwinSockaddrSize; len(message) != want {
		t.Fatalf("message length = %d, want %d", len(message), want)
	}
	header := (*unix.RtMsghdr)(unsafe.Pointer(&message[0]))
	if int(header.Msglen) != len(message) {
		t.Fatalf("rtm_msglen = %d, want %d", header.Msglen, len(message))
	}
	if header.Version != darwinRTMVersion || header.Type != uint8(unix.RTM_ADD) {
		t.Fatalf("message header = {version:%d type:%d}, want {5, RTM_ADD}", header.Version, header.Type)
	}
	if header.Index != 7 {
		t.Fatalf("rtm_index = %d, want 7", header.Index)
	}
	if want := int32(darwinRouteFlagsStatic); header.Flags != want {
		t.Fatalf("rtm_flags = 0x%x, want 0x%x (RTF_UP|RTF_STATIC)", header.Flags, want)
	}
	if want := int32(unix.RTA_DST | unix.RTA_NETMASK); header.Addrs != want {
		t.Fatalf("rtm_addrs = 0x%x, want 0x%x", header.Addrs, want)
	}
	if header.Seq != 42 || header.Pid != int32(os.Getpid()) {
		t.Fatalf("message identity = {seq:%d pid:%d}, want {42, %d}", header.Seq, header.Pid, os.Getpid())
	}
	addrs, err := darwinParseSockaddrs(message, header.Addrs)
	if err != nil {
		t.Fatalf("parse own message: %v", err)
	}
	if destination, ok := addrs[unix.RTA_DST]; !ok || destination != netip.MustParseAddr("10.31.0.0") {
		t.Fatalf("RTA_DST = %s (%v), want 10.31.0.0", destination, ok)
	}
	if mask, ok := addrs[unix.RTA_NETMASK]; !ok || mask != netip.MustParseAddr("255.255.0.0") {
		t.Fatalf("RTA_NETMASK = %s (%v), want 255.255.0.0", mask, ok)
	}
	if got := darwinPrefixFromMessage(header, addrs); got != prefix {
		t.Fatalf("decoded prefix = %s, want %s", got, prefix)
	}
	// Two back-to-back messages split cleanly, with the cap enforced.
	messages, err := darwinRouteMessages(append(append([]byte(nil), message...), message...), 4)
	if err != nil {
		t.Fatalf("split two messages: %v", err)
	}
	if len(messages) != 2 {
		t.Fatalf("split two messages into %d", len(messages))
	}
	if _, err := darwinRouteMessages(append(append([]byte(nil), message...), message...), 1); err == nil {
		t.Fatal("the message cap was not enforced")
	}
}

// TestDarwinRouteMessagesRejectCorruption proves a malformed buffer is refused
// instead of misread: a truncated message must never feed an ownership check.
func TestDarwinRouteMessagesRejectCorruption(t *testing.T) {
	message := darwinRouteMessage(unix.RTM_ADD, netip.MustParsePrefix("10.31.0.0/16"), 7, 1, darwinRouteFlagsStatic)

	truncated := append([]byte(nil), message...)
	if _, err := darwinRouteMessages(truncated[:len(truncated)-1], 4); err == nil {
		t.Fatal("a truncated message was accepted")
	}

	short := append([]byte(nil), message...)
	(*unix.RtMsghdr)(unsafe.Pointer(&short[0])).Msglen = uint16(unix.SizeofRtMsghdr - 1)
	if _, err := darwinRouteMessages(short, 4); err == nil {
		t.Fatal("a message shorter than one header was accepted")
	}

	foreign := append([]byte(nil), message...)
	(*unix.RtMsghdr)(unsafe.Pointer(&foreign[0])).Version = darwinRTMVersion - 1
	if _, err := darwinRouteMessages(foreign, 4); err == nil {
		t.Fatal("a foreign routing message version was accepted")
	}

	if _, err := darwinRouteMessages([]byte{1, 2, 3}, 4); err == nil {
		t.Fatal("a non-message tail was accepted")
	}
	if _, err := darwinRouteMessages([]byte{0, 0, 0}, 4); err != nil {
		t.Fatalf("zero padding must be accepted: %v", err)
	}
	// An address list that claims more bytes than the message holds is refused.
	broken := append([]byte(nil), message...)
	(*darwinSockaddr)(unsafe.Pointer(&broken[unix.SizeofRtMsghdr])).Len = 64
	if _, err := darwinParseSockaddrs(broken, int32(unix.RTA_DST)); err == nil {
		t.Fatal("an over-long sockaddr was accepted")
	}
}

// --- transaction state machine (no privileges) -----------------------------

func TestDarwinSystemNetworkStateAndErrors(t *testing.T) {
	network, err := newDarwinSystemNetwork(SystemNetworkOptions{Interface: "utun_darwin_missing"})
	if err != nil {
		t.Fatalf("newDarwinSystemNetwork: %v", err)
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

func TestDarwinSystemNetworkForeignPlatformRejected(t *testing.T) {
	if _, err := newSystemNetwork(PlatformWindows, SystemNetworkOptions{Interface: "utun0"}); !errors.Is(err, ErrNetworkConfigUnavailable) {
		t.Fatalf("newSystemNetwork(windows) error %v, want ErrNetworkConfigUnavailable", err)
	}
	if _, err := newSystemNetwork(PlatformLinux, SystemNetworkOptions{Interface: "utun0"}); !errors.Is(err, ErrNetworkConfigUnavailable) {
		t.Fatalf("newSystemNetwork(linux) error %v, want ErrNetworkConfigUnavailable", err)
	}
}

func TestNewSystemNetworkDarwinDispatch(t *testing.T) {
	network, err := NewSystemNetwork(PlatformDarwin, "utun_darwin_dispatch", SystemNetworkOptions{})
	if err != nil {
		t.Fatalf("NewSystemNetwork(darwin): %v", err)
	}
	defer func() { _ = network.Close() }()
	if _, ok := network.(*darwinSystemNetwork); !ok {
		t.Fatalf("NewSystemNetwork(darwin) returned %T, want *darwinSystemNetwork", network)
	}
	if network.State() != SystemNetworkAbsent {
		t.Fatalf("fresh state = %s, want absent", network.State())
	}
}

// --- recovery (no privileges) ----------------------------------------------

// TestDarwinRecoverKeepsEverythingWhenInterfaceIsGone is the crash case that
// matters most on macOS: the dead process's utun socket closed, the kernel
// destroyed the interface, and recovery must not touch anything.
func TestDarwinRecoverKeepsEverythingWhenInterfaceIsGone(t *testing.T) {
	const name = "utun_darwin_gone"
	if _, err := net.InterfaceByName(name); err == nil {
		t.Skipf("external blocker: %q exists on this host", name)
	}
	path := filepath.Join(t.TempDir(), "gone.journal")
	journal, err := newResourceJournal(path)
	if err != nil {
		t.Fatalf("newResourceJournal: %v", err)
	}
	entries := []struct {
		kind        string
		resource    string
		detail      string
		fingerprint string
	}{
		{"prepare", "route", "10.207.92.0/24", ""},
		{"apply", "mtu", "mtu=1380", "prior=1500"},
		{"apply", "address", "10.207.91.1/32", "fingerprint=10.207.91.1"},
		{"apply", "link_up", name, "was down"},
		{"apply", "route", "10.207.92.0/24", "dev=" + name},
	}
	for _, entry := range entries {
		if err := journal.record(entry.kind, entry.resource, name, entry.detail, entry.fingerprint); err != nil {
			t.Fatalf("record %s:%s: %v", entry.kind, entry.resource, err)
		}
	}
	if err := journal.close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	report, err := RecoverDarwinSystemNetwork(context.Background(), name, path)
	if err != nil {
		t.Fatalf("RecoverDarwinSystemNetwork: %v", err)
	}
	if len(report.Removed) != 0 {
		t.Fatalf("recovery removed resources of a gone interface: %+v", report)
	}
	if want := len(entries) - 1; len(report.Kept) != want {
		t.Fatalf("recovery kept %d entries, want the %d apply entries: %+v", len(report.Kept), want, report)
	}
}

func TestDarwinRecoverWithoutApplyEntries(t *testing.T) {
	const name = "utun_darwin_noapply"
	path := filepath.Join(t.TempDir(), "prepare-only.journal")
	journal, err := newResourceJournal(path)
	if err != nil {
		t.Fatalf("newResourceJournal: %v", err)
	}
	if err := journal.record("prepare", "address", name, "10.207.93.1/32", ""); err != nil {
		t.Fatalf("record prepare: %v", err)
	}
	if err := journal.close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	report, err := RecoverDarwinSystemNetwork(context.Background(), name, path)
	if err != nil {
		t.Fatalf("RecoverDarwinSystemNetwork: %v", err)
	}
	if len(report.Removed) != 0 || len(report.Kept) != 1 {
		t.Fatalf("prepare-only journal report = %+v, want one kept note and no removal", report)
	}
}

func TestDarwinRecoverRejectsIncompleteInput(t *testing.T) {
	report, err := RecoverDarwinSystemNetwork(context.Background(), "  ", filepath.Join(t.TempDir(), "unused.journal"))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty interface error %v, want ErrInvalidConfig", err)
	}
	if report.Interface != "  " {
		t.Fatalf("report interface = %q, want the caller's value", report.Interface)
	}
	_, err = RecoverDarwinSystemNetwork(context.Background(), "utun_darwin_missing", filepath.Join(t.TempDir(), "missing.journal"))
	if err == nil || !strings.Contains(err.Error(), "read system network journal") {
		t.Fatalf("missing journal error %v, want the load failure", err)
	}
}

// --- live routing queries (no privileges) ----------------------------------

// TestDarwinRouteTableQueryIsBounded reads the real IPv4 routing table through
// the bounded sysctl path and checks the parser against live kernel data.
func TestDarwinRouteTableQueryIsBounded(t *testing.T) {
	entries, err := darwinRouteTable(context.Background())
	if err != nil {
		t.Skipf("external blocker: sysctl NET_RT_DUMP unavailable: %v", err)
	}
	if len(entries) == 0 {
		t.Skip("external blocker: the IPv4 routing table is empty")
	}
	if len(entries) > darwinRouteTableLimit {
		t.Fatalf("parsed %d entries, beyond the %d bound", len(entries), darwinRouteTableLimit)
	}
	for index, entry := range entries {
		if !entry.Prefix.IsValid() || !entry.Prefix.Addr().Is4() {
			t.Fatalf("entry %d = %+v, want a valid IPv4 prefix", index, entry)
		}
	}
}

// TestDarwinRouteGetMatchesTheTable takes a route the kernel just reported and
// asks the kernel for it again through RTM_GET: the two independent queries must
// agree on the interface for an exact prefix.
func TestDarwinRouteGetMatchesTheTable(t *testing.T) {
	table, err := darwinRouteTable(context.Background())
	if err != nil {
		t.Skipf("external blocker: sysctl NET_RT_DUMP unavailable: %v", err)
	}
	var target darwinRouteEntry
	found := false
	for _, entry := range table {
		if entry.InterfaceIndex != 0 {
			target = entry
			found = true
			break
		}
	}
	if !found {
		t.Skip("external blocker: the routing table has no interface route to re-query")
	}
	info, err := darwinRouteGet(context.Background(), target.Prefix)
	if err != nil {
		t.Skipf("external blocker: routing socket RTM_GET unavailable: %v", err)
	}
	if !info.Present {
		t.Skipf("external blocker: RTM_GET returned only a covering route for %s", target.Prefix)
	}
	if info.InterfaceIndex != target.InterfaceIndex {
		t.Fatalf("RTM_GET put %s on interface %d, the dump on %d", target.Prefix, info.InterfaceIndex, target.InterfaceIndex)
	}
}

// --- retarget preflight (pure predicate) -----------------------------------

// TestDarwinRouteOwnershipProof pins the conservative bound of the macOS
// PF_ROUTE query for one route this transaction installed. The query exposes the
// exact prefix, the interface index and an optional IPv4 gateway; it never
// exposes the metric or the protocol, so even a fully matching observation is
// NOT proof of ownership (an external actor can change only the metric or the
// protocol) and the predicate fails closed on every observation this query can
// produce.
func TestDarwinRouteOwnershipProof(t *testing.T) {
	const linkIndex = 9
	for _, testCase := range []struct {
		name       string
		state      darwinRouteInfo
		proven     bool
		reasonPart string
	}{
		{
			name:       "matching prefix and interface is still unproven",
			state:      darwinRouteInfo{Present: true, InterfaceIndex: linkIndex},
			proven:     false,
			reasonPart: "metric or protocol",
		},
		{
			name:       "unspecified gateway does not prove ownership",
			state:      darwinRouteInfo{Present: true, InterfaceIndex: linkIndex, Gateway: netip.IPv4Unspecified()},
			proven:     false,
			reasonPart: "metric or protocol",
		},
		{
			name:       "no longer present",
			state:      darwinRouteInfo{},
			proven:     false,
			reasonPart: "no longer present",
		},
		{
			name:       "moved to another interface",
			state:      darwinRouteInfo{Present: true, InterfaceIndex: linkIndex + 1},
			proven:     false,
			reasonPart: "interface index",
		},
		{
			name:       "replaced by a gateway route",
			state:      darwinRouteInfo{Present: true, InterfaceIndex: linkIndex, Gateway: netip.MustParseAddr("10.0.0.1")},
			proven:     false,
			reasonPart: "gateway",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			proven, reason := darwinRouteOwnershipProof(testCase.state, linkIndex)
			if proven != testCase.proven {
				t.Fatalf("darwinRouteOwnershipProof(%+v) proven = %v, want %v (reason %q)", testCase.state, proven, testCase.proven, reason)
			}
			if testCase.proven {
				if reason != "" {
					t.Fatalf("a proven route must carry no reason, got %q", reason)
				}
				return
			}
			if !strings.Contains(reason, testCase.reasonPart) {
				t.Fatalf("reason = %q, want it to mention %q", reason, testCase.reasonPart)
			}
		})
	}
}

// TestDarwinRetargetPreflightDegradedIsFailClosed pins the failure contract the
// Darwin preflight shares with the Linux owner: a route the recorded instance
// fingerprint cannot match is refused with ErrPlatformUnavailable and reported
// through DegradedDetail, and the recorded fingerprint names nothing stronger
// than the interface index this transaction actually observed.
func TestDarwinRetargetPreflightDegradedIsFailClosed(t *testing.T) {
	route := netip.MustParsePrefix("10.222.9.0/24")
	instance := darwinInterfaceInstance(9)
	recorded := darwinRouteFingerprint(route, instance)
	if !strings.Contains(recorded, instance) || !strings.Contains(recorded, "index=9") {
		t.Fatalf("recorded fingerprint %q does not name the observed interface index", recorded)
	}
	proven, reason := darwinRouteOwnershipProof(darwinRouteInfo{Present: true, InterfaceIndex: 10}, 9)
	if proven {
		t.Fatal("a route on another interface must not be proven")
	}
	network, err := newDarwinSystemNetwork(SystemNetworkOptions{Interface: "utun_darwin_retarget"})
	if err != nil {
		t.Fatalf("newDarwinSystemNetwork: %v", err)
	}
	defer func() { _ = network.Close() }()
	network.instance = instance
	err = network.preflightDegraded("route "+route.String(),
		"route "+route.String()+" recorded as "+recorded+" "+reason+"; the external route is kept and nothing was released")
	if !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("preflightDegraded error %v, want ErrPlatformUnavailable", err)
	}
	detail := network.DegradedDetail()
	if len(detail) == 0 || !strings.Contains(strings.Join(detail, " "), "route "+route.String()) {
		t.Fatalf("DegradedDetail = %v, want the refused route recorded", detail)
	}
}

// --- real utun (root) ------------------------------------------------------

func requireDarwinNetworkPrivileges(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("external blocker: configuring a utun interface needs root or the network entitlement")
	}
}

func openTestUtun(t *testing.T, mtu int) *utunDevice {
	t.Helper()
	device, err := openUtunDevice(context.Background(), DeviceOptions{MTU: mtu})
	if err != nil {
		t.Skipf("external blocker: utun did not open: %v", err)
	}
	t.Cleanup(func() { _ = device.Close() })
	return device
}

func liveInterfaceMTU(t *testing.T, name string) int {
	t.Helper()
	mtu, err := getInterfaceMTU(name)
	if err != nil {
		t.Fatalf("read MTU of %q: %v", name, err)
	}
	return mtu
}

func liveInterfaceAddress(t *testing.T, name string, want netip.Addr) bool {
	t.Helper()
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	return hasInterfaceAddress(link, want)
}

// TestDarwinUtunRejectsRequestedName keeps the approved behaviour: macOS assigns
// utunN at connect time, so a requested name is an explicit configuration error
// rather than a silent ignore.
func TestDarwinUtunRejectsRequestedName(t *testing.T) {
	if _, err := openUtunDevice(context.Background(), DeviceOptions{Name: "utun42"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("openUtunDevice with a requested name error %v, want ErrInvalidConfig", err)
	}
}

// TestDarwinUtunOpenLeavesInterfaceMTUAlone proves Open creates the interface
// and reports the kernel-assigned name, but changes no interface property: the
// prior MTU is still there for Prepare to snapshot.
func TestDarwinUtunOpenLeavesInterfaceMTUAlone(t *testing.T) {
	requireDarwinNetworkPrivileges(t)
	device := openTestUtun(t, MinDeviceMTU)
	name := device.InterfaceName()
	if !strings.HasPrefix(name, "utun") {
		t.Fatalf("kernel-assigned name %q is not a utun name", name)
	}
	info := device.DeviceInfo()
	if info.Name != name || !info.Ready {
		t.Fatalf("DeviceInfo = %+v, want the ready kernel-assigned name %q", info, name)
	}
	if !info.Owned {
		t.Fatal("a utun this process connected must report DeviceInfo.Owned")
	}
	if info.MTU != MinDeviceMTU {
		t.Fatalf("DeviceInfo.MTU = %d, want the configured %d", info.MTU, MinDeviceMTU)
	}
	live := liveInterfaceMTU(t, name)
	if live == MinDeviceMTU {
		t.Fatalf("Open mutated the interface MTU to %d; only the journaled transaction may change it", live)
	}

	target := MinDeviceMTU + 100
	network, err := newDarwinSystemNetwork(SystemNetworkOptions{Interface: name, MTU: target})
	if err != nil {
		t.Fatalf("newDarwinSystemNetwork: %v", err)
	}
	if err := network.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if network.snapshot.MTU != live {
		t.Fatalf("Prepare snapshotted MTU %d, the live interface has %d", network.snapshot.MTU, live)
	}
	if after := liveInterfaceMTU(t, name); after != live {
		t.Fatalf("Prepare mutated the MTU to %d; it must not touch the OS", after)
	}
	if err := network.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestDarwinSystemNetworkApplyAndRollback(t *testing.T) {
	requireDarwinNetworkPrivileges(t)
	device := openTestUtun(t, DefaultDeviceMTU)
	name := device.InterfaceName()
	address := netip.MustParsePrefix("10.207.31.1/32")
	routePrefix := netip.MustParsePrefix("10.207.32.0/24")
	const priorMTU = 1400
	if err := setInterfaceMTU(name, priorMTU); err != nil {
		t.Fatalf("seed interface MTU: %v", err)
	}
	network, err := newDarwinSystemNetwork(SystemNetworkOptions{
		Interface: name,
		MTU:       DefaultDeviceMTU,
		Address:   address,
		Routes:    []netip.Prefix{routePrefix},
	})
	if err != nil {
		t.Fatalf("newDarwinSystemNetwork: %v", err)
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
	if live := liveInterfaceMTU(t, name); live != priorMTU {
		t.Fatalf("Prepare mutated the MTU to %d; it must not touch the OS", live)
	}
	if hasInterfaceAddress(link, address.Addr()) {
		t.Fatal("Prepare assigned the address; it must not touch the OS")
	}

	if err := network.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if network.State() != SystemNetworkApplied {
		t.Fatalf("state after Apply = %s", network.State())
	}
	if live := liveInterfaceMTU(t, name); live != DefaultDeviceMTU {
		t.Fatalf("interface MTU after Apply = %d, want %d", live, DefaultDeviceMTU)
	}
	link, err = net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q after Apply: %v", name, err)
	}
	if link.Flags&net.FlagUp == 0 {
		t.Fatal("Apply must bring the interface up")
	}
	if !hasInterfaceAddress(link, address.Addr()) {
		t.Fatalf("Apply did not assign %s", address)
	}
	present, _, err := routePresent(context.Background(), routePrefix, link.Index)
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
	if live := liveInterfaceMTU(t, name); live != priorMTU {
		t.Fatalf("Rollback left MTU %d, want the original %d", live, priorMTU)
	}
	if liveInterfaceAddress(t, name, address.Addr()) {
		t.Fatalf("Rollback left address %s behind", address)
	}
	link, err = net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q after Rollback: %v", name, err)
	}
	present, _, err = routePresent(context.Background(), routePrefix, link.Index)
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

func TestDarwinSystemNetworkKeepsExternalChanges(t *testing.T) {
	requireDarwinNetworkPrivileges(t)
	device := openTestUtun(t, DefaultDeviceMTU)
	name := device.InterfaceName()
	address := netip.MustParsePrefix("10.207.41.1/32")
	const priorMTU = 1400
	const externalMTU = 1420
	if err := setInterfaceMTU(name, priorMTU); err != nil {
		t.Fatalf("seed interface MTU: %v", err)
	}
	network, err := newDarwinSystemNetwork(SystemNetworkOptions{
		Interface: name,
		MTU:       DefaultDeviceMTU,
		Address:   address,
	})
	if err != nil {
		t.Fatalf("newDarwinSystemNetwork: %v", err)
	}
	if err := network.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// An external actor changes the MTU after the transaction applied it.
	if err := setInterfaceMTU(name, externalMTU); err != nil {
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
	if live := liveInterfaceMTU(t, name); live != externalMTU {
		t.Fatalf("keep-external rule broken: MTU is %d, want the external %d", live, externalMTU)
	}
	// The address this transaction owns is still removed.
	if liveInterfaceAddress(t, name, address.Addr()) {
		t.Fatalf("Rollback left its own address %s behind", address)
	}
	if err := network.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestDarwinSystemNetworkJournalIsPersisted(t *testing.T) {
	requireDarwinNetworkPrivileges(t)
	device := openTestUtun(t, DefaultDeviceMTU)
	name := device.InterfaceName()
	const priorMTU = 1400
	if err := setInterfaceMTU(name, priorMTU); err != nil {
		t.Fatalf("seed interface MTU: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sysnet.journal")
	network, err := newDarwinSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		MTU:         DefaultDeviceMTU,
		JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newDarwinSystemNetwork: %v", err)
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

// --- crash recovery (root) -------------------------------------------------

// TestDarwinSystemNetworkRecovery proves the durability half of the contract:
// after a crash (the transaction object is abandoned without Rollback), a new
// process loads the persisted journal and removes only the resources whose
// fingerprint still matches.
func TestDarwinSystemNetworkRecovery(t *testing.T) {
	requireDarwinNetworkPrivileges(t)
	device := openTestUtun(t, DefaultDeviceMTU)
	name := device.InterfaceName()
	address := netip.MustParsePrefix("10.207.91.1/32")
	routePrefix := netip.MustParsePrefix("10.207.92.0/24")
	const priorMTU = 1400
	if err := setInterfaceMTU(name, priorMTU); err != nil {
		t.Fatalf("seed MTU: %v", err)
	}
	journalPath := filepath.Join(t.TempDir(), "recovery.journal")
	network, err := newDarwinSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		MTU:         DefaultDeviceMTU,
		Address:     address,
		Routes:      []netip.Prefix{routePrefix},
		JournalPath: journalPath,
	})
	if err != nil {
		t.Fatalf("newDarwinSystemNetwork: %v", err)
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

	report, err := RecoverDarwinSystemNetwork(context.Background(), name, journalPath)
	if err != nil {
		t.Fatalf("RecoverDarwinSystemNetwork: %v", err)
	}
	if liveInterfaceAddress(t, name, address.Addr()) {
		t.Fatalf("recovery left address %s behind: %+v", address, report)
	}
	// macOS route ownership cannot be proven from the journal alone (RTM_GET's
	// interface index is unverified at runtime), so recovery must NOT delete the
	// route: it keeps it and reports Degraded.
	for _, removed := range report.Removed {
		if strings.HasPrefix(removed, "route ") {
			t.Fatalf("recovery deleted route %q although macOS route ownership is unprovable: %+v", removed, report)
		}
	}
	if len(report.Degraded) == 0 {
		t.Fatalf("recovery did not report the unprovable macOS route: %+v", report)
	}
	if live := liveInterfaceMTU(t, name); live != priorMTU {
		t.Fatalf("recovery left MTU %d, want the prior %d: %+v", live, priorMTU, report)
	}
	if len(report.Removed) == 0 {
		t.Fatalf("recovery removed nothing: %+v", report)
	}
}

// TestDarwinSystemNetworkRecoveryKeepsExternalChanges checks that recovery never
// overwrites a value someone else changed after the crash.
func TestDarwinSystemNetworkRecoveryKeepsExternalChanges(t *testing.T) {
	requireDarwinNetworkPrivileges(t)
	device := openTestUtun(t, DefaultDeviceMTU)
	name := device.InterfaceName()
	journalPath := filepath.Join(t.TempDir(), "recovery-external.journal")
	const priorMTU = 1400
	const externalMTU = 1420
	if err := setInterfaceMTU(name, priorMTU); err != nil {
		t.Fatalf("seed MTU: %v", err)
	}
	network, err := newDarwinSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		MTU:         DefaultDeviceMTU,
		JournalPath: journalPath,
	})
	if err != nil {
		t.Fatalf("newDarwinSystemNetwork: %v", err)
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
	if err := setInterfaceMTU(name, externalMTU); err != nil {
		t.Fatalf("external MTU change: %v", err)
	}
	report, err := RecoverDarwinSystemNetwork(context.Background(), name, journalPath)
	if err != nil {
		t.Fatalf("RecoverDarwinSystemNetwork: %v", err)
	}
	if live := liveInterfaceMTU(t, name); live != externalMTU {
		t.Fatalf("recovery overwrote the external MTU %d: %+v", live, report)
	}
	if len(report.Degraded) == 0 {
		t.Fatalf("recovery did not report the external modification: %+v", report)
	}
}
