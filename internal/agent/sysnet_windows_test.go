//go:build windows

package agent

// Windows-native verification for the SystemNetwork transaction and the IP
// Helper payload bindings.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// These tests are windows-tagged: they compile only for GOOS=windows. This
// repository's host is Linux, so nothing here has been executed. The Linux
// verification claimed for this change is a GOOS=windows/amd64 and
// GOOS=windows/arm64 cross-compile plus `go vet` on the package, which is a
// compile and design check, not Windows platform acceptance. Two groups exist:
//
//   - pure helpers and the state machine driven through the windowsIPHelperOps
//     seam, which need no adapter, driver, elevation or live OS mutation;
//   - TestWindowsSystemNetworkRealAdapter, the only runtime acceptance check,
//     which needs a real Windows host with an existing adapter and elevation and
//     is skipped unless SIMPLETIER_WINDOWS_ADAPTER names that adapter.
//
// The journal-ordering tests read the persisted journal file from inside the
// fake mutation, so they prove the write-ahead record is on disk before the
// side effect runs, not merely that both happened.

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fakeIPHelper is a scriptable windowsIPHelperOps backend. It models an adapter
// with an IPv4 MTU, a set of present addresses and a set of present routes, and
// records every call in order so a test can prove the journal/side-effect order
// and the rollback order.
type fakeIPHelper struct {
	luid  uint64
	index uint32
	mtu   int

	luidErr          error
	indexErr         error
	readMTUErr       error
	writeMTUErr      error
	readAddressErr   error
	addAddressErr    error
	removeAddressErr error
	hasAddressErr    error
	addRouteErr      error
	removeRouteErr   error
	hasRouteErr      error

	addresses map[netip.Addr]netip.Prefix
	// routes holds routes this transaction created (exact canonical tuple);
	// foreignRoutes holds routes that share a prefix but carry different
	// attributes, which ownership checks must keep.
	routes        map[netip.Prefix]bool
	foreignRoutes map[netip.Prefix]bool

	calls  []string
	onCall func(name string)
}

func newFakeIPHelper() *fakeIPHelper {
	return &fakeIPHelper{
		luid:          7,
		index:         3,
		mtu:           1500,
		addresses:     make(map[netip.Addr]netip.Prefix),
		routes:        make(map[netip.Prefix]bool),
		foreignRoutes: make(map[netip.Prefix]bool),
	}
}

func (f *fakeIPHelper) note(name string) {
	f.calls = append(f.calls, name)
	if f.onCall != nil {
		f.onCall(name)
	}
}

func (f *fakeIPHelper) interfaceLUID(string) (uint64, error) {
	f.note("resolve-luid")
	return f.luid, f.luidErr
}

func (f *fakeIPHelper) interfaceIndex(uint64) (uint32, error) {
	f.note("resolve-index")
	return f.index, f.indexErr
}

func (f *fakeIPHelper) readMTU(uint64) (int, error) {
	f.note("read-mtu")
	return f.mtu, f.readMTUErr
}

func (f *fakeIPHelper) writeMTU(_ uint64, mtu int) error {
	f.note("set-mtu")
	if f.writeMTUErr != nil {
		return f.writeMTUErr
	}
	f.mtu = mtu
	return nil
}

func (f *fakeIPHelper) readAddress(_ uint64, address netip.Addr) (netip.Prefix, bool, error) {
	f.note("read-address")
	if f.readAddressErr != nil {
		return netip.Prefix{}, false, f.readAddressErr
	}
	prefix, ok := f.addresses[address]
	return prefix, ok, nil
}

func (f *fakeIPHelper) addAddress(_ uint64, _ uint32, prefix netip.Prefix) error {
	f.note("add-address")
	if f.addAddressErr != nil {
		return f.addAddressErr
	}
	f.addresses[prefix.Addr()] = prefix
	return nil
}

func (f *fakeIPHelper) removeAddress(_ uint64, _ uint32, address netip.Addr) error {
	f.note("remove-address")
	if f.removeAddressErr != nil {
		return f.removeAddressErr
	}
	delete(f.addresses, address)
	return nil
}

func (f *fakeIPHelper) hasAddress(_ uint64, address netip.Addr) (bool, error) {
	f.note("has-address")
	if f.hasAddressErr != nil {
		return false, f.hasAddressErr
	}
	_, ok := f.addresses[address]
	return ok, nil
}

func (f *fakeIPHelper) addRoute(_ uint64, _ uint32, prefix netip.Prefix) error {
	f.note("add-route")
	if f.addRouteErr != nil {
		if errors.Is(f.addRouteErr, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			// The route appeared concurrently and belongs to someone else.
			f.routes[prefix] = true
		}
		return f.addRouteErr
	}
	f.routes[prefix] = true
	return nil
}

func (f *fakeIPHelper) removeRoute(_ uint64, _ uint32, prefix netip.Prefix) error {
	f.note("remove-route")
	if f.removeRouteErr != nil {
		return f.removeRouteErr
	}
	delete(f.routes, prefix)
	return nil
}

func (f *fakeIPHelper) hasRoute(_ uint64, prefix netip.Prefix) (bool, error) {
	f.note("has-route")
	if f.hasRouteErr != nil {
		return false, f.hasRouteErr
	}
	return f.routes[prefix] || f.foreignRoutes[prefix], nil
}

// routeState models the full-tuple ownership lookup: a route created through
// addRoute is exact, a foreign route shares only the prefix.
func (f *fakeIPHelper) routeState(_ uint64, _ uint32, prefix netip.Prefix) (windowsRouteResult, error) {
	f.note("has-route")
	if f.hasRouteErr != nil {
		return windowsRouteResult{}, f.hasRouteErr
	}
	if f.foreignRoutes[prefix] {
		return windowsRouteResult{Found: true, Exact: false}, nil
	}
	if f.routes[prefix] {
		return windowsRouteResult{Found: true, Exact: true}, nil
	}
	return windowsRouteResult{}, nil
}

func (f *fakeIPHelper) ops() *windowsIPHelperOps {
	return &windowsIPHelperOps{
		interfaceLUID:    f.interfaceLUID,
		interfaceIndex:   f.interfaceIndex,
		interfaceMTU:     f.readMTU,
		setInterfaceMTU:  f.writeMTU,
		interfaceAddress: f.readAddress,
		createIPv4Addr:   f.addAddress,
		deleteIPv4Addr:   f.removeAddress,
		addressPresent:   f.hasAddress,
		createIPv4Route:  f.addRoute,
		deleteIPv4Route:  f.removeRoute,
		routeState:       f.routeState,
	}
}

// windowsTestMutations are the calls that change OS host network state.
var windowsTestMutations = map[string]bool{
	"set-mtu":        true,
	"add-address":    true,
	"remove-address": true,
	"add-route":      true,
	"remove-route":   true,
}

func windowsTestMutatingCalls(calls []string) []string {
	mutating := make([]string, 0, len(calls))
	for _, call := range calls {
		if windowsTestMutations[call] {
			mutating = append(mutating, call)
		}
	}
	return mutating
}

func assertWindowsTestCalls(t *testing.T, label string, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s calls = %v, want %v", label, got, want)
	}
}

func writeWindowsTestJournal(t *testing.T, path string, entries []journalEntry) {
	t.Helper()
	var builder strings.Builder
	for _, entry := range entries {
		payload, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal journal entry: %v", err)
		}
		builder.Write(payload)
		builder.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(builder.String()), 0o600); err != nil {
		t.Fatalf("write journal %q: %v", path, err)
	}
}

// --- IP Helper payload bindings --------------------------------------------

func TestWindowsIPHelperSockaddrPayloads(t *testing.T) {
	// The MIB structures declare the address as RawSockaddrInet6, so the IPv4
	// view must alias family at offset 0 and the address at offset 4, and it
	// must overwrite a previous family value rather than append.
	target := windows.RawSockaddrInet6{Family: windows.AF_INET6}
	setSockaddrInet4(&target, [4]byte{10, 44, 0, 2})
	view := (*windows.RawSockaddrInet4)(unsafe.Pointer(&target))
	if view.Family != windows.AF_INET {
		t.Fatalf("family = %d, want AF_INET(%d); the IPv4 view must alias offset 0", view.Family, windows.AF_INET)
	}
	if view.Addr != [4]byte{10, 44, 0, 2} {
		t.Fatalf("address bytes = %v, want [10 44 0 2]", view.Addr)
	}
	address, ok := sockaddrInet4Address(&target)
	if !ok || address != netip.MustParseAddr("10.44.0.2") {
		t.Fatalf("sockaddrInet4Address = %s, %v; want 10.44.0.2, true", address, ok)
	}
	target.Family = windows.AF_INET6
	if got, ok := sockaddrInet4Address(&target); ok {
		t.Fatalf("sockaddrInet4Address(AF_INET6) = %s, true; want false", got)
	}

	raw := windows.RawSockaddrInet{Family: windows.AF_INET6}
	setSockaddrInet4Raw(&raw, [4]byte{192, 0, 2, 9})
	rawView := (*windows.RawSockaddrInet4)(unsafe.Pointer(&raw))
	if rawView.Family != windows.AF_INET || rawView.Addr != [4]byte{192, 0, 2, 9} {
		t.Fatalf("setSockaddrInet4Raw produced family %d addr %v", rawView.Family, rawView.Addr)
	}
	rawAddress, ok := sockaddrInet4RawAddress(&raw)
	if !ok || rawAddress != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("sockaddrInet4RawAddress = %s, %v; want 192.0.2.9, true", rawAddress, ok)
	}
	raw.Family = windows.AF_INET6
	if got, ok := sockaddrInet4RawAddress(&raw); ok {
		t.Fatalf("sockaddrInet4RawAddress(AF_INET6) = %s, true; want false", got)
	}
}

func TestWindowsSystemNetworkForeignPlatformRejected(t *testing.T) {
	opts := SystemNetworkOptions{Interface: "st-win0"}
	// The constructor performs no native call, so this is safe without an
	// adapter: it only proves the dispatch refuses a foreign platform.
	if _, err := newSystemNetwork(PlatformWindows, opts); err != nil {
		t.Fatalf("newSystemNetwork(windows): %v", err)
	}
	for _, platform := range []Platform{PlatformLinux, PlatformDarwin} {
		network, err := newSystemNetwork(platform, opts)
		if network != nil {
			t.Fatalf("newSystemNetwork(%s) returned an owner in a windows build", platform)
		}
		if !errors.Is(err, ErrNetworkConfigUnavailable) {
			t.Fatalf("newSystemNetwork(%s) error %v, want ErrNetworkConfigUnavailable", platform, err)
		}
		if !strings.Contains(err.Error(), "build") {
			t.Fatalf("newSystemNetwork(%s) error %q must name the required build", platform, err)
		}
	}
}

// --- transaction state machine ---------------------------------------------

func TestWindowsSystemNetworkPrepareSnapshotsActualPriorState(t *testing.T) {
	fake := newFakeIPHelper()
	fake.mtu = 1420
	// The address is present with a different prefix length: the snapshot must
	// record what is actually there, not what this transaction would assign.
	fake.addresses[netip.MustParseAddr("10.10.0.5")] = netip.MustParsePrefix("10.10.0.5/24")
	route := netip.MustParsePrefix("10.10.9.0/24")
	fake.routes[route] = true

	network, err := newWindowsSystemNetworkWithOps(SystemNetworkOptions{
		Interface: "st-win0",
		Address:   netip.MustParsePrefix("10.10.0.5/32"),
		Routes:    []netip.Prefix{route},
	}, fake.ops())
	if err != nil {
		t.Fatalf("newWindowsSystemNetworkWithOps: %v", err)
	}
	defer func() { _ = network.Close() }()

	if err := network.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if network.State() != SystemNetworkPrepared {
		t.Fatalf("state = %s, want prepared", network.State())
	}
	if network.snapshot.MTU != 1420 {
		t.Fatalf("snapshot MTU = %d, want the actual prior 1420", network.snapshot.MTU)
	}
	if !network.snapshot.HadAddress {
		t.Fatal("snapshot must record that the VirtualIP was already present")
	}
	if got := network.snapshot.Address.String(); got != "10.10.0.5/24" {
		t.Fatalf("snapshot address = %s, want the actual prior 10.10.0.5/24", got)
	}
	if !network.snapshot.HadRoutes[route] {
		t.Fatalf("snapshot must record the pre-existing route %s", route)
	}
	if got := network.snapshot.LUID; got != fake.luid {
		t.Fatalf("snapshot LUID = %d, want %d", got, fake.luid)
	}
	assertWindowsTestCalls(t, "Prepare must not mutate", windowsTestMutatingCalls(fake.calls), nil)
}

func TestWindowsSystemNetworkApplyJournalsAndFsyncsBeforeEachSideEffect(t *testing.T) {
	fake := newFakeIPHelper()
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.jsonl")
	expected := map[string]string{
		"set-mtu":        `"kind":"apply:mtu"`,
		"add-address":    `"kind":"apply:address"`,
		"add-route":      `"kind":"apply:route"`,
		"remove-route":   `"kind":"rollback:route"`,
		"remove-address": `"kind":"rollback:address"`,
	}
	fake.onCall = func(name string) {
		want, ok := expected[name]
		if !ok {
			return
		}
		payload, err := os.ReadFile(journalPath)
		if err != nil {
			t.Errorf("%s: read journal: %v", name, err)
			return
		}
		if !strings.Contains(string(payload), want) {
			t.Errorf("%s ran before %s was persisted; journal:\n%s", name, want, payload)
		}
		if !strings.Contains(string(payload), `"interface":"st-win0"`) {
			t.Errorf("%s: journal does not name the adapter; journal:\n%s", name, payload)
		}
	}
	route := netip.MustParsePrefix("10.44.9.0/24")
	network, err := newWindowsSystemNetworkWithOps(SystemNetworkOptions{
		Interface:   "st-win0",
		Address:     netip.MustParsePrefix("10.44.0.2/32"),
		Routes:      []netip.Prefix{route},
		JournalPath: journalPath,
	}, fake.ops())
	if err != nil {
		t.Fatalf("newWindowsSystemNetworkWithOps: %v", err)
	}
	defer func() { _ = network.Close() }()
	ctx := context.Background()

	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if network.State() != SystemNetworkApplied {
		t.Fatalf("state = %s, want applied", network.State())
	}
	if !network.applied.MTU || !network.applied.Address || len(network.applied.Routes) != 1 {
		t.Fatalf("applied = %+v, want MTU, address and one route", network.applied)
	}
	assertWindowsTestCalls(t, "Apply order", windowsTestMutatingCalls(fake.calls), []string{"set-mtu", "add-address", "add-route"})

	// The persisted journal is the durable half: reload it from disk and check
	// the frozen record shape (interface + kind) and the apply-entry order.
	entries, err := LoadJournal(journalPath)
	if err != nil {
		t.Fatalf("LoadJournal: %v", err)
	}
	var kinds []string
	for _, entry := range entries {
		if entry.Interface != "st-win0" {
			t.Fatalf("journal entry %+v does not name the adapter", entry)
		}
		kinds = append(kinds, entry.Kind)
	}
	assertWindowsTestCalls(t, "persisted journal kinds", kinds,
		[]string{"prepare:address", "prepare:route", "apply:mtu", "apply:mtu", "apply:address", "apply:address", "apply:route", "apply:route"})

	if err := network.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if network.State() != SystemNetworkRollback {
		t.Fatalf("state = %s, want rollback", network.State())
	}
	assertWindowsTestCalls(t, "Rollback order", windowsTestMutatingCalls(fake.calls),
		[]string{"set-mtu", "add-address", "add-route", "remove-route", "remove-address", "set-mtu"})
	if fake.mtu != 1500 {
		t.Fatalf("MTU = %d, want the prior 1500 restored", fake.mtu)
	}
	if len(fake.addresses) != 0 || len(fake.routes) != 0 {
		t.Fatalf("rollback left addresses %v routes %v", fake.addresses, fake.routes)
	}
}

func TestWindowsSystemNetworkApplySkipsAndNeverDeletesPreExistingResources(t *testing.T) {
	fake := newFakeIPHelper()
	address := netip.MustParsePrefix("10.50.0.7/32")
	route := netip.MustParsePrefix("10.50.9.0/24")
	fake.addresses[address.Addr()] = address
	fake.routes[route] = true
	fake.mtu = DefaultDeviceMTU

	network, err := newWindowsSystemNetworkWithOps(SystemNetworkOptions{
		Interface: "st-win0",
		MTU:       DefaultDeviceMTU,
		Address:   address,
		Routes:    []netip.Prefix{route},
	}, fake.ops())
	if err != nil {
		t.Fatalf("newWindowsSystemNetworkWithOps: %v", err)
	}
	defer func() { _ = network.Close() }()
	ctx := context.Background()

	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if network.applied.MTU || network.applied.Address || len(network.applied.Routes) != 0 {
		t.Fatalf("applied = %+v, want nothing owned", network.applied)
	}
	assertWindowsTestCalls(t, "Apply with pre-existing resources", windowsTestMutatingCalls(fake.calls), nil)

	if err := network.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if network.State() != SystemNetworkRollback {
		t.Fatalf("state = %s, want rollback", network.State())
	}
	assertWindowsTestCalls(t, "Rollback of unowned resources", windowsTestMutatingCalls(fake.calls), nil)
	if _, ok := fake.addresses[address.Addr()]; !ok {
		t.Fatal("rollback deleted a user address it never created")
	}
	if !fake.routes[route] {
		t.Fatal("rollback deleted a user route it never created")
	}
}

func TestWindowsSystemNetworkApplyTreatsConcurrentRouteAsUnowned(t *testing.T) {
	fake := newFakeIPHelper()
	fake.addRouteErr = windows.ERROR_OBJECT_ALREADY_EXISTS
	route := netip.MustParsePrefix("10.60.9.0/24")

	network, err := newWindowsSystemNetworkWithOps(SystemNetworkOptions{
		Interface: "st-win0",
		Routes:    []netip.Prefix{route},
	}, fake.ops())
	if err != nil {
		t.Fatalf("newWindowsSystemNetworkWithOps: %v", err)
	}
	defer func() { _ = network.Close() }()
	ctx := context.Background()

	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply must absorb a concurrently created route: %v", err)
	}
	if len(network.applied.Routes) != 0 {
		t.Fatalf("applied routes = %v, want none: the route is not ours", network.applied.Routes)
	}
	if !network.snapshot.HadRoutes[route] {
		t.Fatal("a route that appeared during Apply must be recorded as pre-existing")
	}
	// Rollback may revert the state it owns — it restores the MTU that Apply
	// set — but it must never remove a route it never proved it created. The
	// invariant is therefore about removals, not about the whole call log.
	mutationsBefore := windowsTestMutatingCalls(fake.calls)
	if err := network.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	for _, mutation := range windowsTestMutatingCalls(fake.calls)[len(mutationsBefore):] {
		if mutation == "remove-route" || mutation == "remove-address" {
			t.Fatalf("Rollback removed a resource it never owned: %v (before=%v)",
				windowsTestMutatingCalls(fake.calls), mutationsBefore)
		}
	}
	if !fake.routes[route] {
		t.Fatal("rollback deleted a route created by someone else")
	}
}

func TestWindowsSystemNetworkRollbackKeepsExternalChanges(t *testing.T) {
	fake := newFakeIPHelper()
	address := netip.MustParsePrefix("10.70.0.2/32")
	route := netip.MustParsePrefix("10.70.9.0/24")
	network, err := newWindowsSystemNetworkWithOps(SystemNetworkOptions{
		Interface: "st-win0",
		Address:   address,
		Routes:    []netip.Prefix{route},
	}, fake.ops())
	if err != nil {
		t.Fatalf("newWindowsSystemNetworkWithOps: %v", err)
	}
	defer func() { _ = network.Close() }()
	ctx := context.Background()

	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// External changes: the MTU moved, the route disappeared, the address was
	// replaced. Rollback must not overwrite or recreate any of them.
	fake.mtu = 1400
	delete(fake.routes, route)
	delete(fake.addresses, address.Addr())

	if err := network.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if network.State() != SystemNetworkDegraded {
		t.Fatalf("state = %s, want degraded", network.State())
	}
	detail := network.DegradedDetail()
	if len(detail) == 0 || !strings.Contains(strings.Join(detail, " "), "MTU is now 1400") {
		t.Fatalf("DegradedDetail = %v, want the external MTU reported", detail)
	}
	if fake.mtu != 1400 {
		t.Fatalf("rollback overwrote the external MTU: got %d, want 1400 kept", fake.mtu)
	}
	assertWindowsTestCalls(t, "Rollback after external changes", windowsTestMutatingCalls(fake.calls),
		[]string{"set-mtu", "add-address", "add-route"})
}

func TestWindowsSystemNetworkCloseIsIdempotent(t *testing.T) {
	fake := newFakeIPHelper()
	network, err := newWindowsSystemNetworkWithOps(SystemNetworkOptions{
		Interface: "st-win0",
		Address:   netip.MustParsePrefix("10.80.0.2/32"),
	}, fake.ops())
	if err != nil {
		t.Fatalf("newWindowsSystemNetworkWithOps: %v", err)
	}
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := network.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if network.State() != SystemNetworkClosed {
		t.Fatalf("state = %s, want closed", network.State())
	}
	before := windowsTestMutatingCalls(fake.calls)
	if err := network.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	assertWindowsTestCalls(t, "second Close must be a no-op", windowsTestMutatingCalls(fake.calls), before)
	if network.State() != SystemNetworkClosed {
		t.Fatalf("state after second Close = %s, want closed", network.State())
	}

	// Close before Prepare owns nothing and still ends in the closed state.
	freshFake := newFakeIPHelper()
	fresh, err := newWindowsSystemNetworkWithOps(SystemNetworkOptions{Interface: "st-win0"}, freshFake.ops())
	if err != nil {
		t.Fatalf("newWindowsSystemNetworkWithOps: %v", err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatalf("Close on an absent transaction: %v", err)
	}
	assertWindowsTestCalls(t, "Close of an absent transaction", windowsTestMutatingCalls(freshFake.calls), nil)
}

func TestWindowsSystemNetworkPrepareRejectsUnresolvedAdapter(t *testing.T) {
	fake := newFakeIPHelper()
	fake.luidErr = errors.New("no such adapter")
	network, err := newWindowsSystemNetworkWithOps(SystemNetworkOptions{Interface: "st-missing0"}, fake.ops())
	if err != nil {
		t.Fatalf("newWindowsSystemNetworkWithOps: %v", err)
	}
	defer func() { _ = network.Close() }()

	if err := network.Prepare(context.Background()); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("Prepare error %v, want ErrPlatformUnavailable", err)
	}
	if network.State() != SystemNetworkAbsent {
		t.Fatalf("state = %s, want absent", network.State())
	}
	assertWindowsTestCalls(t, "failed Prepare", windowsTestMutatingCalls(fake.calls), nil)
}

// --- retarget preflight -----------------------------------------------------

// windowsAppliedRetargetFixture prepares and applies one transaction that owns
// the MTU, one address and one route, leaving the fake backend holding exactly
// what Apply created.
func windowsAppliedRetargetFixture(t *testing.T, fake *fakeIPHelper, addressA, route netip.Prefix, journalPath string) *windowsSystemNetwork {
	t.Helper()
	network, err := newWindowsSystemNetworkWithOps(SystemNetworkOptions{
		Interface:   "st-win0",
		MTU:         DefaultDeviceMTU,
		Address:     addressA,
		Routes:      []netip.Prefix{route},
		JournalPath: journalPath,
	}, fake.ops())
	if err != nil {
		t.Fatalf("newWindowsSystemNetworkWithOps: %v", err)
	}
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return network
}

// TestWindowsRetargetPreflightRefusesExternalChangesWithZeroEffects proves the
// Windows parity of the Linux retarget ordering: after an external actor
// replaces the owned MTU, widens the owned address prefix, replaces the owned
// route or rebinds the adapter, RetargetAddress fails closed with
// ErrPlatformUnavailable BEFORE the first side effect. The owned address A is
// untouched, the new address B is never created, the external value survives,
// the transaction state stays applied and no new transaction reaches the
// journal.
func TestWindowsRetargetPreflightRefusesExternalChangesWithZeroEffects(t *testing.T) {
	addressA := netip.MustParsePrefix("10.220.0.1/32")
	addressB := netip.MustParsePrefix("10.220.0.2/32")
	route := netip.MustParsePrefix("10.220.9.0/24")
	for _, testCase := range []struct {
		name       string
		mutate     func(fake *fakeIPHelper)
		detailPart string
		// externalAddress, when set, is the value the external actor installed
		// for the owned address. The test then requires retarget to leave that
		// exact value in place instead of the original addressA.
		externalAddress netip.Prefix
	}{
		{
			name:       "replaced MTU",
			mutate:     func(fake *fakeIPHelper) { fake.mtu = DefaultDeviceMTU + 20 },
			detailPart: "MTU is now",
		},
		{
			name: "widened owned address prefix",
			mutate: func(fake *fakeIPHelper) {
				fake.addresses[addressA.Addr()] = netip.MustParsePrefix("10.220.0.1/24")
			},
			detailPart: "different prefix length",
			// This case is the one where the external actor changed the owned
			// address itself. "Zero effects" then means the widened prefix is
			// left exactly as the actor set it, not that it still equals the
			// original /32.
			externalAddress: netip.MustParsePrefix("10.220.0.1/24"),
		},
		{
			name: "replaced owned route",
			mutate: func(fake *fakeIPHelper) {
				delete(fake.routes, route)
				fake.foreignRoutes[route] = true
			},
			detailPart: "different attributes",
		},
		{
			name:       "rebound adapter identity",
			mutate:     func(fake *fakeIPHelper) { fake.luid = 99 },
			detailPart: "LUID",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fake := newFakeIPHelper()
			fake.mtu = 1500 // so Apply owns and sets the configured 1380 MTU
			journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
			network := windowsAppliedRetargetFixture(t, fake, addressA, route, journalPath)
			defer func() { _ = network.Close() }()

			// The external change happens after Apply, exactly as an external
			// actor would race the retarget.
			testCase.mutate(fake)
			mutationsBefore := len(windowsTestMutatingCalls(fake.calls))
			journalBefore, err := LoadJournal(journalPath)
			if err != nil {
				t.Fatalf("LoadJournal before retarget: %v", err)
			}

			if err := network.RetargetAddress(context.Background(), addressB); !errors.Is(err, ErrPlatformUnavailable) {
				t.Fatalf("retarget must fail closed on %s, got %v", testCase.name, err)
			}
			// Zero effects: no OS mutation ran, A is still exactly owned, B was
			// never created and the external route/value survived.
			if mutations := windowsTestMutatingCalls(fake.calls); len(mutations) != mutationsBefore {
				t.Fatalf("retarget mutated the OS: %v, want %d mutating calls", mutations, mutationsBefore)
			}
			wantAddress := addressA
			if testCase.externalAddress.IsValid() {
				wantAddress = testCase.externalAddress
			}
			if present, ok := fake.addresses[addressA.Addr()]; !ok || present != wantAddress {
				t.Fatalf("retarget disturbed the owned address: present=%v ok=%v, want %s", present, ok, wantAddress)
			}
			if _, ok := fake.addresses[addressB.Addr()]; ok {
				t.Fatal("retarget created the new address despite the Degraded preflight")
			}
			if !fake.routes[route] && !fake.foreignRoutes[route] {
				t.Fatalf("retarget removed the route it never proved: routes=%v foreign=%v", fake.routes, fake.foreignRoutes)
			}
			detail := strings.Join(network.DegradedDetail(), " ")
			if !strings.Contains(detail, testCase.detailPart) {
				t.Fatalf("DegradedDetail = %v, want it to mention %q", network.DegradedDetail(), testCase.detailPart)
			}
			if network.State() != SystemNetworkApplied {
				t.Fatalf("a preflight-refused retarget changed state to %s", network.State())
			}
			journalAfter, err := LoadJournal(journalPath)
			if err != nil {
				t.Fatalf("LoadJournal after retarget: %v", err)
			}
			if len(journalAfter) != len(journalBefore) {
				t.Fatalf("a preflight-refused retarget mutated the journal: %d -> %d records", len(journalBefore), len(journalAfter))
			}
		})
	}
}

// TestWindowsRetargetAddressMovesOwnedAddress is the mock-ops parity of the
// Linux retarget: the preflight proves ownership, the owned transaction is
// released, a fresh transaction starts on the same journal and the new /32, its
// route and the configured MTU are applied.
func TestWindowsRetargetAddressMovesOwnedAddress(t *testing.T) {
	fake := newFakeIPHelper()
	fake.mtu = 1500
	addressA := netip.MustParsePrefix("10.221.0.1/32")
	addressB := netip.MustParsePrefix("10.221.0.2/32")
	route := netip.MustParsePrefix("10.221.9.0/24")
	network := windowsAppliedRetargetFixture(t, fake, addressA, route, "")
	defer func() { _ = network.Close() }()

	if err := network.RetargetAddress(context.Background(), addressB); err != nil {
		t.Fatalf("RetargetAddress: %v", err)
	}
	if network.opts.Address != addressB {
		t.Fatalf("transaction address = %s, want %s", network.opts.Address, addressB)
	}
	if present, ok := fake.addresses[addressB.Addr()]; !ok || present != addressB {
		t.Fatalf("address B = %v (%v), want %s", present, ok, addressB)
	}
	if _, ok := fake.addresses[addressA.Addr()]; ok {
		t.Fatalf("address A %s survived the retarget", addressA)
	}
	if !fake.routes[route] {
		t.Fatalf("route %s was not re-applied on the new address", route)
	}
	if fake.mtu != DefaultDeviceMTU {
		t.Fatalf("MTU = %d, want the configured %d re-applied", fake.mtu, DefaultDeviceMTU)
	}
	if network.State() != SystemNetworkApplied {
		t.Fatalf("state after retarget = %s, want applied", network.State())
	}
	if detail := network.DegradedDetail(); len(detail) != 0 {
		t.Fatalf("DegradedDetail = %v, want a clean retarget", detail)
	}
}

// --- crash recovery ---------------------------------------------------------

// windowsTestJournalEntry builds one version-2 record the way the owners write
// it: transaction id, adapter-instance resource id and explicit outcome.
func windowsTestJournalEntry(kind, interfaceName, detail, fingerprint, outcome string) journalEntry {
	return journalEntry{
		Version:     journalVersion,
		Time:        time.Now().UTC(),
		Kind:        kind,
		Interface:   interfaceName,
		Detail:      detail,
		Fingerprint: fingerprint,
		Transaction: "t-windows-test",
		ResourceID:  windowsInterfaceInstance(7, 3),
		Outcome:     outcome,
	}
}

func TestWindowsRecoverAppliesExactOwnership(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
	route := netip.MustParsePrefix("10.90.9.0/24")
	address := netip.MustParsePrefix("10.90.0.2/32")
	// Same order Apply appends: MTU, address, route, each with its confirmation
	// and no terminal checkpoint (the process crashed). Recovery reverses it.
	writeWindowsTestJournal(t, journalPath, []journalEntry{
		windowsTestJournalEntry("prepare:address", "st-win0", address.String(), "", journalOutcomeIntent),
		windowsTestJournalEntry("apply:mtu", "st-win0", "mtu=1380", "prior=1500", journalOutcomeIntent),
		windowsTestJournalEntry("apply:mtu", "st-win0", "mtu=1380", "prior=1500", journalOutcomeConfirmed),
		windowsTestJournalEntry("apply:address", "st-win0", address.String(), "addr=10.90.0.2;prefixlen=32", journalOutcomeIntent),
		windowsTestJournalEntry("apply:address", "st-win0", address.String(), "addr=10.90.0.2;prefixlen=32", journalOutcomeConfirmed),
		windowsTestJournalEntry("apply:route", "st-win0", route.String(), windowsRouteFingerprint(route, 7, 3), journalOutcomeIntent),
		windowsTestJournalEntry("apply:route", "st-win0", route.String(), windowsRouteFingerprint(route, 7, 3), journalOutcomeConfirmed),
	})

	fake := newFakeIPHelper()
	fake.mtu = 1380
	fake.addresses[address.Addr()] = address
	fake.routes[route] = true

	report, err := recoverWindowsSystemNetwork(context.Background(), "st-win0", journalPath, fake.ops())
	if err != nil {
		t.Fatalf("recoverWindowsSystemNetwork: %v", err)
	}
	if report.Interface != "st-win0" {
		t.Fatalf("report interface = %q, want st-win0", report.Interface)
	}
	assertWindowsTestCalls(t, "recovery removals", report.Removed, []string{
		"route 10.90.9.0/24",
		"address 10.90.0.2/32",
		"mtu 1380 (restored to 1500)",
	})
	if len(report.Kept) != 0 || len(report.Degraded) != 0 {
		t.Fatalf("report = %+v, want nothing kept or degraded", report)
	}
	// Reverse order, exactly like Rollback.
	assertWindowsTestCalls(t, "recovery order", windowsTestMutatingCalls(fake.calls),
		[]string{"remove-route", "remove-address", "set-mtu"})
	if fake.mtu != 1500 {
		t.Fatalf("MTU = %d, want the prior 1500 restored", fake.mtu)
	}
	if len(fake.addresses) != 0 || len(fake.routes) != 0 {
		t.Fatalf("recovery left addresses %v routes %v", fake.addresses, fake.routes)
	}
}

func TestWindowsRecoverKeepsExternalChanges(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
	route := netip.MustParsePrefix("10.91.9.0/24")
	address := netip.MustParsePrefix("10.91.0.2/32")
	// Same order Apply appends: MTU, address, route.
	writeWindowsTestJournal(t, journalPath, []journalEntry{
		windowsTestJournalEntry("apply:mtu", "st-win0", "mtu=1380", "prior=1500", journalOutcomeConfirmed),
		windowsTestJournalEntry("apply:address", "st-win0", address.String(), "addr=10.91.0.2;prefixlen=32", journalOutcomeConfirmed),
		windowsTestJournalEntry("apply:route", "st-win0", route.String(), windowsRouteFingerprint(route, 7, 3), journalOutcomeConfirmed),
	})

	fake := newFakeIPHelper()
	fake.mtu = 1400 // externally changed
	// The address and the route are gone; nothing may be recreated or removed.

	report, err := recoverWindowsSystemNetwork(context.Background(), "st-win0", journalPath, fake.ops())
	if err != nil {
		t.Fatalf("recoverWindowsSystemNetwork: %v", err)
	}
	assertWindowsTestCalls(t, "recovery must not mutate", windowsTestMutatingCalls(fake.calls), nil)
	if len(report.Removed) != 0 {
		t.Fatalf("report.Removed = %v, want nothing removed", report.Removed)
	}
	if len(report.Kept) != 3 {
		t.Fatalf("report.Kept = %v, want the address, route and MTU kept", report.Kept)
	}
	if len(report.Degraded) != 1 || !strings.Contains(report.Degraded[0], "MTU is now 1400") {
		t.Fatalf("report.Degraded = %v, want the external MTU reported", report.Degraded)
	}
	if fake.mtu != 1400 {
		t.Fatalf("recovery overwrote the external MTU: got %d, want 1400 kept", fake.mtu)
	}
}

func TestWindowsRecoverKeepsExternalRouteReplacement(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
	route := netip.MustParsePrefix("10.91.10.0/24")
	writeWindowsTestJournal(t, journalPath, []journalEntry{
		windowsTestJournalEntry("apply:route", "st-win0", route.String(), windowsRouteFingerprint(route, 7, 3), journalOutcomeConfirmed),
	})
	fake := newFakeIPHelper()
	// The route exists but with different attributes (a gateway/metric an
	// external actor installed): it must be kept, not deleted by prefix.
	fake.foreignRoutes[route] = true

	report, err := recoverWindowsSystemNetwork(context.Background(), "st-win0", journalPath, fake.ops())
	if err != nil {
		t.Fatalf("recoverWindowsSystemNetwork: %v", err)
	}
	assertWindowsTestCalls(t, "route replacement must not be deleted", windowsTestMutatingCalls(fake.calls), nil)
	if len(report.Removed) != 0 {
		t.Fatalf("report.Removed = %v, want the replaced route kept", report.Removed)
	}
	if len(report.Degraded) == 0 {
		t.Fatalf("report = %+v, want the replaced route reported Degraded", report)
	}
	if !fake.routes[route] && !fake.foreignRoutes[route] {
		t.Fatal("recovery deleted a route it could not prove it owned")
	}
}

func TestWindowsRecoverIgnoresClosedAndUnconfirmedTransactions(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
	address := netip.MustParsePrefix("10.91.20.2/32")
	// A terminal checkpoint means a clean rollback already handled the
	// transaction; the same journal path is reused, and an external resource
	// with the same prefix appeared afterwards.
	closed := []journalEntry{
		windowsTestJournalEntry("apply:address", "st-win0", address.String(), "addr=10.91.20.2;prefixlen=32", journalOutcomeConfirmed),
		windowsTestJournalEntry("rolledback:address", "st-win0", address.String(), "addr=10.91.20.2;prefixlen=32", journalOutcomeConfirmed),
	}
	closed = append(closed, journalEntry{
		Version: journalVersion, Time: time.Now().UTC(), Kind: journalTerminalKind,
		Interface: "st-win0", Detail: "rolledback", Transaction: "t-windows-test",
		ResourceID: windowsInterfaceInstance(7, 3), Outcome: journalOutcomeConfirmed,
	})
	writeWindowsTestJournal(t, journalPath, closed)
	fake := newFakeIPHelper()
	fake.addresses[address.Addr()] = address

	report, err := recoverWindowsSystemNetwork(context.Background(), "st-win0", journalPath, fake.ops())
	if err != nil {
		t.Fatalf("recoverWindowsSystemNetwork(closed): %v", err)
	}
	assertWindowsTestCalls(t, "a closed transaction must not be replayed", windowsTestMutatingCalls(fake.calls), nil)
	if len(report.Removed) != 0 {
		t.Fatalf("report.Removed = %v, want nothing removed for a closed transaction", report.Removed)
	}
	if _, ok := fake.addresses[address.Addr()]; !ok {
		t.Fatal("recovery deleted the external resource of a closed transaction")
	}

	// An intent without a confirmation proves nothing about the effect, even
	// when the resource is present.
	journalPath = filepath.Join(t.TempDir(), "journal.jsonl")
	writeWindowsTestJournal(t, journalPath, []journalEntry{
		windowsTestJournalEntry("apply:address", "st-win0", address.String(), "addr=10.91.20.2;prefixlen=32", journalOutcomeIntent),
	})
	fake = newFakeIPHelper()
	fake.addresses[address.Addr()] = address
	report, err = recoverWindowsSystemNetwork(context.Background(), "st-win0", journalPath, fake.ops())
	if err != nil {
		t.Fatalf("recoverWindowsSystemNetwork(intent): %v", err)
	}
	assertWindowsTestCalls(t, "an unconfirmed intent must not delete", windowsTestMutatingCalls(fake.calls), nil)
	if len(report.Removed) != 0 || len(report.Degraded) == 0 {
		t.Fatalf("report = %+v, want the unconfirmed resource kept and Degraded", report)
	}
	if _, ok := fake.addresses[address.Addr()]; !ok {
		t.Fatal("recovery deleted a resource whose effect was never confirmed")
	}
}

func TestWindowsRecoverKeepsLegacyJournalRecords(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
	address := netip.MustParsePrefix("10.91.30.2/32")
	// A pre-version-2 record has no transaction id: its effect can never be
	// attributed to this instance, so recovery keeps the live resource.
	writeWindowsTestJournal(t, journalPath, []journalEntry{
		{Time: time.Now().UTC(), Kind: "apply:address", Interface: "st-win0", Detail: address.String()},
	})
	fake := newFakeIPHelper()
	fake.addresses[address.Addr()] = address

	report, err := recoverWindowsSystemNetwork(context.Background(), "st-win0", journalPath, fake.ops())
	if err != nil {
		t.Fatalf("recoverWindowsSystemNetwork(legacy): %v", err)
	}
	assertWindowsTestCalls(t, "a legacy journal must not delete", windowsTestMutatingCalls(fake.calls), nil)
	if len(report.Removed) != 0 || len(report.Degraded) == 0 {
		t.Fatalf("report = %+v, want the legacy resource kept and Degraded", report)
	}
	if _, ok := fake.addresses[address.Addr()]; !ok {
		t.Fatal("recovery deleted a resource a legacy record described")
	}
}

func TestWindowsRecoverKeepsEverythingWhenAdapterGone(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
	address := netip.MustParsePrefix("10.92.0.2/32")
	route := netip.MustParsePrefix("10.92.9.0/24")
	writeWindowsTestJournal(t, journalPath, []journalEntry{
		windowsTestJournalEntry("apply:address", "st-win0", address.String(), "addr=10.92.0.2;prefixlen=32", journalOutcomeConfirmed),
		windowsTestJournalEntry("apply:route", "st-win0", route.String(), windowsRouteFingerprint(route, 7, 3), journalOutcomeConfirmed),
	})
	fake := newFakeIPHelper()
	fake.luidErr = errors.New("the adapter was removed")

	report, err := recoverWindowsSystemNetwork(context.Background(), "st-win0", journalPath, fake.ops())
	if err != nil {
		t.Fatalf("recoverWindowsSystemNetwork: %v", err)
	}
	if len(report.Removed) != 0 {
		t.Fatalf("report.Removed = %v, want nothing removed", report.Removed)
	}
	if len(report.Kept) != 2 {
		t.Fatalf("report.Kept = %v, want both entries kept", report.Kept)
	}
	assertWindowsTestCalls(t, "recovery without an adapter", fake.calls, []string{"resolve-luid"})
}

func TestWindowsRecoverRejectsIncompleteInput(t *testing.T) {
	fake := newFakeIPHelper()
	if _, err := recoverWindowsSystemNetwork(context.Background(), "  ", filepath.Join(t.TempDir(), "missing.jsonl"), fake.ops()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty adapter error %v, want ErrInvalidConfig", err)
	}
	report, err := recoverWindowsSystemNetwork(context.Background(), "st-win0", filepath.Join(t.TempDir(), "missing.jsonl"), fake.ops())
	if err == nil {
		t.Fatal("a missing persisted journal must be reported, not treated as empty")
	}
	if len(report.Removed) != 0 {
		t.Fatalf("report.Removed = %v, want nothing removed", report.Removed)
	}
	// No apply entries for this adapter is a keep, not a mutation.
	journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
	writeWindowsTestJournal(t, journalPath, []journalEntry{
		{Time: time.Now().UTC(), Kind: "apply:address", Interface: "st-other0", Detail: "10.93.0.2/32"},
	})
	if _, err := recoverWindowsSystemNetwork(context.Background(), "st-win0", journalPath, fake.ops()); err != nil {
		t.Fatalf("recover for an unrelated adapter: %v", err)
	}
	assertWindowsTestCalls(t, "recovery for an unrelated adapter", windowsTestMutatingCalls(fake.calls), nil)
}

// --- device ABI guards ------------------------------------------------------

func TestWintunAPIBindsTheOfficialABIOnly(t *testing.T) {
	typ := reflect.TypeOf(wintunAPI{})
	want := []string{
		"createAdapter", "openAdapter", "closeAdapter", "startSession", "endSession",
		"getReadWaitEvent", "receivePacket", "releaseReceivePacket", "allocateSendPacket",
		"sendPacket", "moveMemory",
	}
	if typ.NumField() != len(want) {
		t.Fatalf("wintunAPI has %d bindings, want %d", typ.NumField(), len(want))
	}
	for _, name := range want {
		if _, ok := typ.FieldByName(name); !ok {
			t.Fatalf("wintunAPI is missing the %s binding", name)
		}
	}
	// The official ABI (api/exports.def) exports no WintunDeleteAdapter, and the
	// device must never mutate the driver or the adapter MTU: the adapter MTU is
	// the journaled SystemNetwork transaction's side effect.
	for index := 0; index < typ.NumField(); index++ {
		name := typ.Field(index).Name
		lower := strings.ToLower(name)
		if strings.Contains(lower, "delete") {
			t.Fatalf("wintunAPI binds %q; WintunCloseAdapter removes a created adapter and there is no delete export", name)
		}
		if strings.Contains(lower, "mtu") || strings.Contains(lower, "ipinterface") || strings.Contains(lower, "driver") {
			t.Fatalf("wintunAPI binds %q; the device must not change the OS MTU or the driver", name)
		}
	}
}

func TestWintunDeviceInfoReportsOpenOwnership(t *testing.T) {
	created := &wintunDevice{name: "st-owned0", mtu: DefaultDeviceMTU, created: true, events: make(chan DeviceEvent, 1)}
	info := created.DeviceInfo()
	if info.Platform != PlatformWindows || info.Name != "st-owned0" || info.MTU != DefaultDeviceMTU || !info.Ready || !info.Owned {
		t.Fatalf("DeviceInfo of a created adapter = %+v; want windows, ready and Owned", info)
	}
	opened := &wintunDevice{name: "st-existing0", mtu: DefaultDeviceMTU, created: false, events: make(chan DeviceEvent, 1)}
	if info := opened.DeviceInfo(); info.Owned {
		t.Fatalf("DeviceInfo of an opened adapter = %+v; want Owned false so Close keeps it", info)
	}
}

func TestWintunCallErrorNeverReportsSuccess(t *testing.T) {
	if err := wintunCallError(nil); err == nil {
		t.Fatal("a failed call with no reported error must still produce an error")
	}
	want := errors.New("boom")
	if got := wintunCallError(want); got != want {
		t.Fatalf("wintunCallError = %v, want the original error", got)
	}
}

// --- runtime acceptance (Windows host only) --------------------------------

// TestWindowsSystemNetworkRealAdapter is the only runtime acceptance check in
// this file. It needs a real Windows host, an existing adapter and elevation,
// and it mutates that adapter's MTU inside a journaled transaction and restores
// it during Rollback. It is skipped unless SIMPLETIER_WINDOWS_ADAPTER names the
// adapter. It has never run from this repository's Linux host: the result must
// be recorded by whoever executes it on Windows.
func TestWindowsSystemNetworkRealAdapter(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("the real-adapter transaction needs a Windows host, running %s", runtime.GOOS)
	}
	name := strings.TrimSpace(os.Getenv("SIMPLETIER_WINDOWS_ADAPTER"))
	if name == "" {
		t.Skip("set SIMPLETIER_WINDOWS_ADAPTER to an existing adapter alias (and run elevated) to exercise the real IP Helper transaction")
	}
	journalPath := filepath.Join(t.TempDir(), "journal.jsonl")
	network, err := newWindowsSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		MTU:         DefaultDeviceMTU,
		JournalPath: journalPath,
	})
	if err != nil {
		t.Fatalf("newWindowsSystemNetwork: %v", err)
	}
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare on the real adapter %q: %v", name, err)
	}
	if network.State() != SystemNetworkPrepared {
		t.Fatalf("state = %s, want prepared", network.State())
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply on the real adapter %q: %v", name, err)
	}
	if network.State() != SystemNetworkApplied {
		t.Fatalf("state = %s, want applied", network.State())
	}
	if err := network.Rollback(ctx); err != nil {
		t.Fatalf("Rollback on the real adapter %q: %v", name, err)
	}
	if detail := network.DegradedDetail(); len(detail) != 0 {
		t.Fatalf("DegradedDetail = %v, want the transaction to own the MTU it restored", detail)
	}
	if err := network.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := LoadJournal(journalPath); err != nil {
		t.Fatalf("the transaction journal must be readable on disk: %v", err)
	}
}
