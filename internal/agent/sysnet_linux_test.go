//go:build linux

package agent

// Real-kernel durability and ownership tests for the Linux SystemNetwork owner.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// These tests need /dev/net/tun and CAP_NET_ADMIN; openTestTUN skips them on a
// host without either, exactly like the rest of this package's Linux network
// tests. They exercise the properties the journal protocol exists for: a reused
// journal path across clean transaction cycles, a resource recreated externally
// after a clean rollback, repeated recovery, not-owned intents, incomplete
// intents, a crash after a confirmed apply, external replacement of a route or
// address and the MTU interleaving between Prepare and Apply.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// addForeignMetricRoute installs a route with the same destination and output
// interface as the canonical owner route but a non-zero metric, modelling an
// external actor that replaced the owned route with different attributes.
func addForeignMetricRoute(t *testing.T, prefix netip.Prefix, ifindex int, metric uint32) {
	t.Helper()
	message := buildForeignMetricRouteMessage(prefix, ifindex, metric, unix.RTM_NEWROUTE)
	if _, err := routeExchange(message); err != nil {
		t.Fatalf("install foreign metric route %s: %v", prefix, err)
	}
}

func deleteForeignMetricRoute(t *testing.T, prefix netip.Prefix, ifindex int, metric uint32) {
	t.Helper()
	message := buildForeignMetricRouteMessage(prefix, ifindex, metric, unix.RTM_DELROUTE)
	if _, err := routeExchange(message); err != nil {
		t.Fatalf("remove foreign metric route %s: %v", prefix, err)
	}
}

func buildForeignMetricRouteMessage(prefix netip.Prefix, ifindex int, metric uint32, messageType uint16) []byte {
	body := make([]byte, rtmsgHeaderLen)
	body[0] = unix.AF_INET
	body[1] = byte(prefix.Bits())
	body[4] = rtTableMain
	body[5] = unix.RTPROT_BOOT
	body[6] = rtScopeLink
	body[7] = rtnUnicast
	body = appendRouteAttr(body, rtaDst, prefix.Addr().AsSlice())
	oif := make([]byte, 4)
	binary.NativeEndian.PutUint32(oif, uint32(ifindex))
	body = appendRouteAttr(body, rtaOif, oif)
	priority := make([]byte, 4)
	binary.NativeEndian.PutUint32(priority, metric)
	body = appendRouteAttr(body, rtaPriority, priority)
	header := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(header[0:4], uint32(unix.NLMSG_HDRLEN+len(body)))
	binary.NativeEndian.PutUint16(header[4:6], messageType)
	binary.NativeEndian.PutUint16(header[6:8], unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(header[8:12], netlinkSequence.Add(1))
	return append(header, body...)
}

// writeLinuxJournal persists hand-built records (used to model a crash in a
// precise protocol state, including torn or incomplete records).
func writeLinuxJournal(t *testing.T, path string, entries []journalEntry) {
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

func linuxJournalIntent(interfaceName, instance, txn, kind, detail, fingerprint string) journalEntry {
	return journalEntry{
		Version:     journalVersion,
		Time:        time.Now().UTC(),
		Kind:        kind,
		Interface:   interfaceName,
		Detail:      detail,
		Fingerprint: fingerprint,
		Transaction: txn,
		ResourceID:  instance,
		Outcome:     journalOutcomeIntent,
	}
}

// TestLinuxJournalPathReuseNeverDeletesFreshResources runs several clean
// transaction cycles on one journal path, then lets an external actor recreate
// the exact address and route the last cycle owned, and proves recovery does not
// delete them. This is the regression the transaction-terminal checkpoint exists
// for: without it, recovery replays the historical clean-rollback intents.
func TestLinuxJournalPathReuseNeverDeletesFreshResources(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/reuse.journal"
	address := netip.MustParsePrefix("10.208.1.1/32")
	route := netip.MustParsePrefix("10.208.10.0/24")
	if err := setInterfaceMTU(name, 1500); err != nil {
		t.Fatalf("seed MTU: %v", err)
	}

	for cycle := 0; cycle < 2; cycle++ {
		network, err := newLinuxSystemNetwork(SystemNetworkOptions{
			Interface:   name,
			MTU:         DefaultDeviceMTU,
			Address:     address,
			Routes:      []netip.Prefix{route},
			JournalPath: path,
		})
		if err != nil {
			t.Fatalf("cycle %d: newLinuxSystemNetwork: %v", cycle, err)
		}
		ctx := context.Background()
		if err := network.Prepare(ctx); err != nil {
			t.Fatalf("cycle %d: Prepare: %v", cycle, err)
		}
		if err := network.Apply(ctx); err != nil {
			t.Fatalf("cycle %d: Apply: %v", cycle, err)
		}
		if err := network.Rollback(ctx); err != nil {
			t.Fatalf("cycle %d: Rollback: %v", cycle, err)
		}
		if err := network.Close(); err != nil {
			t.Fatalf("cycle %d: Close: %v", cycle, err)
		}
	}

	entries, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal: %v", err)
	}
	// Every transaction on this reused path wrote its terminal checkpoint (a
	// close after a rollback may checkpoint again, which is harmless).
	transactions := make(map[string]bool)
	terminals := make(map[string]bool)
	for _, entry := range entries {
		if entry.Transaction == "" {
			continue
		}
		transactions[entry.Transaction] = true
		if entry.Kind == journalTerminalKind {
			terminals[entry.Transaction] = true
		}
	}
	if len(transactions) != 2 || len(terminals) != 2 {
		t.Fatalf("journal transactions=%d terminals=%d, want every clean cycle terminal", len(transactions), len(terminals))
	}

	// An external actor now creates the same address and route prefix.
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	// Rollback of the second cycle owned the link-up step, so bring it back up
	// for the external route.
	if err := setLinkUp(name, true); err != nil {
		t.Fatalf("bring %q up for the external route: %v", name, err)
	}
	if err := addIPv4Address(address, link.Index); err != nil {
		t.Fatalf("external address %s: %v", address, err)
	}
	if err := addRoute(route, link.Index); err != nil {
		t.Fatalf("external route %s: %v", route, err)
	}
	if err := setInterfaceMTU(name, 1420); err != nil {
		t.Fatalf("external MTU: %v", err)
	}

	report, err := RecoverLinuxSystemNetwork(context.Background(), name, path)
	if err != nil {
		t.Fatalf("RecoverLinuxSystemNetwork: %v", err)
	}
	if len(report.Removed) != 0 {
		t.Fatalf("recovery deleted resources of clean transactions: %+v", report)
	}
	if !hasTestAddress(t, link, address.Addr()) {
		t.Fatalf("recovery deleted the externally recreated address %s: %+v", address, report)
	}
	present, _, err := routePresent(route, link.Index)
	if err != nil {
		t.Fatalf("routePresent: %v", err)
	}
	if !present {
		t.Fatalf("recovery deleted the externally recreated route %s: %+v", route, report)
	}
	if live, _ := currentInterfaceMTU(name); live != 1420 {
		t.Fatalf("recovery changed the external MTU to %d: %+v", live, report)
	}
}

// TestLinuxRecoveryIsIdempotent runs recovery twice on the same crashed
// transaction: the first removes what the transaction owned, the second finds
// nothing to remove and mutates nothing.
func TestLinuxRecoveryIsIdempotent(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/idempotent.journal"
	address := netip.MustParsePrefix("10.208.2.1/32")
	route := netip.MustParsePrefix("10.208.20.0/24")
	if err := setInterfaceMTU(name, 1500); err != nil {
		t.Fatalf("seed MTU: %v", err)
	}
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		MTU:         DefaultDeviceMTU,
		Address:     address,
		Routes:      []netip.Prefix{route},
		JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Crash: release the journal without rolling back.
	if err := network.journal.close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	first, err := RecoverLinuxSystemNetwork(ctx, name, path)
	if err != nil {
		t.Fatalf("first RecoverLinuxSystemNetwork: %v", err)
	}
	if len(first.Removed) == 0 {
		t.Fatalf("first recovery removed nothing: %+v", first)
	}
	second, err := RecoverLinuxSystemNetwork(ctx, name, path)
	if err != nil {
		t.Fatalf("second RecoverLinuxSystemNetwork: %v", err)
	}
	if len(second.Removed) != 0 {
		t.Fatalf("second recovery removed resources again: %+v", second)
	}
}

// TestLinuxRecoveryKeepsNotOwnedRoute proves that an apply intent closed as
// not_owned (the route already existed) is never deleted by recovery, even
// though the durable intent line is on disk and the route is present.
func TestLinuxRecoveryKeepsNotOwnedRoute(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/notowned.journal"
	route := netip.MustParsePrefix("10.208.30.0/24")
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	// The external actor owns the route before this transaction starts.
	if err := setLinkUp(name, true); err != nil {
		t.Fatalf("bring %q up for the external route: %v", name, err)
	}
	if err := addRoute(route, link.Index); err != nil {
		t.Fatalf("external route %s: %v", route, err)
	}
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		Routes:      []netip.Prefix{route},
		JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply must absorb the existing route: %v", err)
	}
	if err := network.journal.close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	report, err := RecoverLinuxSystemNetwork(ctx, name, path)
	if err != nil {
		t.Fatalf("RecoverLinuxSystemNetwork: %v", err)
	}
	// The transaction legitimately removed resources it owned (the MTU it set
	// and its instance marker). What must never happen is removing the route it
	// only observed as not_owned, so assert on that resource, not on an empty
	// report.
	for _, removed := range report.Removed {
		if strings.HasPrefix(removed, "route ") || strings.HasPrefix(removed, "address ") {
			t.Fatalf("recovery removed a resource it never owned: %+v", report)
		}
	}
	// Re-read the kernel: the externally owned canonical route must still be
	// installed with its exact tuple.
	state, err := routeState(route, link.Index)
	if err != nil {
		t.Fatalf("routeState: %v", err)
	}
	if !state.Found || !state.Exact {
		t.Fatalf("recovery changed or deleted the external route %s: %+v (report %+v)", route, state, report)
	}
	if state.Entry.metric != 0 || state.Entry.gateway.IsValid() {
		t.Fatalf("external route tuple changed: %+v", state.Entry)
	}
}

// TestLinuxRecoveryKeepsUnconfirmedIntentsAndExternalResources models a crash
// between the journal intent and the effect: the intents are durable, the
// effects may or may not have happened, and an external route and address exist.
// Recovery must keep both and report Degraded.
func TestLinuxRecoveryKeepsUnconfirmedIntentsAndExternalResources(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/intent-only.journal"
	address := netip.MustParsePrefix("10.208.40.1/32")
	route := netip.MustParsePrefix("10.208.41.0/24")
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	instance := linuxInterfaceInstance(name, link.Index, "inst-unconfirmed")
	writeLinuxJournal(t, path, []journalEntry{
		linuxJournalIntent(name, instance, "t-crash", "apply:address", address.String(), encodeJournalFields([2]string{"addr", address.Addr().String()}, [2]string{"prefixlen", "32"})),
		linuxJournalIntent(name, instance, "t-crash", "apply:route", route.String(), canonicalRouteFields(route, link.Index).fingerprint()),
	})

	// The external resources the crashed transaction must not touch.
	if err := setLinkUp(name, true); err != nil {
		t.Fatalf("bring %q up for the external route: %v", name, err)
	}
	if err := addIPv4Address(address, link.Index); err != nil {
		t.Fatalf("external address %s: %v", address, err)
	}
	if err := addRoute(route, link.Index); err != nil {
		t.Fatalf("external route %s: %v", route, err)
	}

	report, err := RecoverLinuxSystemNetwork(context.Background(), name, path)
	if err != nil {
		t.Fatalf("RecoverLinuxSystemNetwork: %v", err)
	}
	if len(report.Removed) != 0 {
		t.Fatalf("recovery deleted resources of an unconfirmed transaction: %+v", report)
	}
	if len(report.Degraded) == 0 {
		t.Fatalf("recovery did not report the unprovable ownership: %+v", report)
	}
	if !hasTestAddress(t, link, address.Addr()) {
		t.Fatalf("recovery deleted the external address %s: %+v", address, report)
	}
	present, _, err := routePresent(route, link.Index)
	if err != nil {
		t.Fatalf("routePresent: %v", err)
	}
	if !present {
		t.Fatalf("recovery deleted the external route %s: %+v", route, report)
	}
}

// TestLinuxRecoveryRemovesConfirmedApplyWithoutRollback is the positive case: a
// completed apply with explicit confirmations and no rollback checkpoint is
// recovered and removed.
func TestLinuxRecoveryRemovesConfirmedApplyWithoutRollback(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/confirmed.journal"
	address := netip.MustParsePrefix("10.208.50.1/32")
	route := netip.MustParsePrefix("10.208.51.0/24")
	if err := setInterfaceMTU(name, 1500); err != nil {
		t.Fatalf("seed MTU: %v", err)
	}
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		MTU:         DefaultDeviceMTU,
		Address:     address,
		Routes:      []netip.Prefix{route},
		JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := network.journal.close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}
	report, err := RecoverLinuxSystemNetwork(ctx, name, path)
	if err != nil {
		t.Fatalf("RecoverLinuxSystemNetwork: %v", err)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	if hasTestAddress(t, link, address.Addr()) {
		t.Fatalf("recovery left the confirmed address %s behind: %+v", address, report)
	}
	present, _, err := routePresent(route, link.Index)
	if err != nil {
		t.Fatalf("routePresent: %v", err)
	}
	if present {
		t.Fatalf("recovery left the confirmed route %s behind: %+v", route, report)
	}
	if live, _ := currentInterfaceMTU(name); live != 1500 {
		t.Fatalf("recovery left MTU %d, want the prior 1500: %+v", live, report)
	}
}

// TestLinuxRecoveryKeepsExternallyReplacedRoute replaces an owned canonical
// route with an external route on the same prefix but a different metric, and
// proves recovery keeps the external route: it re-reads the kernel and must see
// the full foreign tuple still installed, not delete it because the prefix
// matches.
func TestLinuxRecoveryKeepsExternallyReplacedRoute(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/replaced-route.journal"
	route := netip.MustParsePrefix("10.208.61.0/24")
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		Routes:      []netip.Prefix{route},
		JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	// Keep the link up before Prepare so the transaction does not own link-up:
	// bringing an owned interface back down makes the kernel purge its routes,
	// which would mask whether the external route itself was preserved.
	if err := setLinkUp(name, true); err != nil {
		t.Fatalf("bring %q up before Prepare: %v", name, err)
	}
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	// External replacement: the owned canonical route becomes a different-metric
	// route on the same prefix and interface.
	if err := deleteRoute(route, link.Index); err != nil {
		t.Fatalf("remove owned route: %v", err)
	}
	addForeignMetricRoute(t, route, link.Index, 100)
	if state, err := routeState(route, link.Index); err != nil {
		t.Fatalf("routeState after external replacement: %v", err)
	} else if !state.Found || state.Exact || state.Entry.metric != 100 {
		t.Fatalf("foreign metric route was not installed: %+v", state)
	}
	if err := network.journal.close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	report, err := RecoverLinuxSystemNetwork(ctx, name, path)
	if err != nil {
		t.Fatalf("RecoverLinuxSystemNetwork: %v", err)
	}
	// The transaction legitimately removes the MTU it set and its marker; it
	// must not remove the replaced route.
	for _, removed := range report.Removed {
		if strings.HasPrefix(removed, "route ") {
			t.Fatalf("recovery removed the externally replaced route: %+v", report)
		}
	}
	if len(report.Degraded) == 0 {
		t.Fatalf("recovery did not report the replaced route: %+v", report)
	}
	// Re-read the kernel: the foreign route must survive with its exact tuple.
	state, err := routeState(route, link.Index)
	if err != nil {
		t.Fatalf("routeState: %v", err)
	}
	if !state.Found || state.Exact {
		t.Fatalf("recovery changed the external metric route (state=%+v): %+v", state, report)
	}
	if state.Entry.metric != 100 || state.Entry.gateway.IsValid() {
		t.Fatalf("external route tuple changed: %+v", state.Entry)
	}
	if state.Entry.ifindex != link.Index || state.Entry.table != rtTableMain ||
		state.Entry.protocol != unix.RTPROT_BOOT || state.Entry.scope != rtScopeLink {
		t.Fatalf("external route attributes changed: %+v", state.Entry)
	}
	deleteForeignMetricRoute(t, route, link.Index, 100)
}

// TestLinuxRecoveryKeepsExternallyReplacedAddress replaces an owned /32 with an
// external /24 on the same IP and proves recovery keeps the external prefix: the
// kernel must still report the /24 and never the /32.
func TestLinuxRecoveryKeepsExternallyReplacedAddress(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/replaced-address.journal"
	address := netip.MustParsePrefix("10.208.60.1/32")
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		Address:     address,
		JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	if err := setLinkUp(name, true); err != nil {
		t.Fatalf("bring %q up before Prepare: %v", name, err)
	}
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	// External replacement: the owned /32 becomes a /24 on the same IP.
	if err := deleteIPv4Address(address, link.Index); err != nil {
		t.Fatalf("remove owned address: %v", err)
	}
	if err := addIPv4Address(netip.MustParsePrefix("10.208.60.1/24"), link.Index); err != nil {
		t.Fatalf("external /24 address: %v", err)
	}
	if err := network.journal.close(); err != nil {
		t.Fatalf("close journal: %v", err)
	}

	report, err := RecoverLinuxSystemNetwork(ctx, name, path)
	if err != nil {
		t.Fatalf("RecoverLinuxSystemNetwork: %v", err)
	}
	for _, removed := range report.Removed {
		if strings.HasPrefix(removed, "address ") {
			t.Fatalf("recovery removed the externally replaced address: %+v", report)
		}
	}
	if len(report.Degraded) == 0 {
		t.Fatalf("recovery did not report the replaced address: %+v", report)
	}
	// Re-read the kernel: the /24 must be the installed prefix, never the /32.
	prefixes, err := interfacePrefixes(link.Index)
	if err != nil {
		t.Fatalf("interfacePrefixes: %v", err)
	}
	found24 := false
	found32 := false
	for _, prefix := range prefixes {
		if prefix.Addr() != address.Addr() {
			continue
		}
		switch prefix.Bits() {
		case 24:
			found24 = true
		case 32:
			found32 = true
		}
	}
	if !found24 || found32 {
		t.Fatalf("external /24 address not preserved (prefixes %v): %+v", prefixes, report)
	}
	found, exact, err := addressState(address, link.Index)
	if err != nil {
		t.Fatalf("addressState: %v", err)
	}
	if !found || exact {
		t.Fatalf("recovery changed the external /24 address (found=%v exact=%v): %+v", found, exact, report)
	}
}

// TestLinuxApplyKeepsExternalMTUChangeBetweenPrepareAndApply proves Apply
// re-reads the live MTU and refuses to overwrite an external change: the
// prepared 1500 becomes 1420 before Apply, and Apply must leave 1420 alone.
func TestLinuxApplyKeepsExternalMTUChangeBetweenPrepareAndApply(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	if err := setInterfaceMTU(name, 1500); err != nil {
		t.Fatalf("seed MTU: %v", err)
	}
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface: name,
		MTU:       DefaultDeviceMTU,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	// An external actor changes the MTU between Prepare and Apply.
	if err := setInterfaceMTU(name, 1420); err != nil {
		t.Fatalf("external MTU change: %v", err)
	}
	err = network.Apply(ctx)
	if err == nil {
		t.Fatal("Apply must abort instead of overwriting the external MTU")
	}
	if !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("Apply error %v, want ErrPlatformUnavailable", err)
	}
	live, readErr := currentInterfaceMTU(name)
	if readErr != nil {
		t.Fatalf("read MTU: %v", readErr)
	}
	if live != 1420 {
		t.Fatalf("Apply overwrote the external MTU: got %d, want 1420 kept", live)
	}
	detail := strings.Join(network.DegradedDetail(), " ")
	if !strings.Contains(detail, "MTU") {
		t.Fatalf("DegradedDetail = %v, want the external MTU reported", network.DegradedDetail())
	}
}

// TestLinuxApplyAbortsWhenTheJournalCannotBeWritten proves intent-before-effect:
// when the durable journal write fails, the OS side effect never runs and the
// in-memory journal does not pretend the intent was recorded.
func TestLinuxApplyAbortsWhenTheJournalCannotBeWritten(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/failed-write.journal"
	if err := setInterfaceMTU(name, 1500); err != nil {
		t.Fatalf("seed MTU: %v", err)
	}
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		MTU:         DefaultDeviceMTU,
		JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	ctx := context.Background()
	// Prepare with an MTU-only transaction writes no records, so the journal is
	// still usable here; break it afterwards to model a failing disk.
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.journal.file.Close(); err != nil {
		t.Fatalf("close journal file: %v", err)
	}
	if err := network.Apply(ctx); err == nil {
		t.Fatal("Apply must fail when the intent cannot be journaled")
	}
	live, readErr := currentInterfaceMTU(name)
	if readErr != nil {
		t.Fatalf("read MTU: %v", readErr)
	}
	if live != 1500 {
		t.Fatalf("Apply ran the MTU side effect despite a failed journal write: MTU %d", live)
	}
	for _, entry := range network.Journal() {
		if strings.HasPrefix(entry.Kind, "apply:") {
			t.Fatalf("a failed journal write produced a visible intent: %+v", entry)
		}
	}
}

// TestLinuxRecoveryKeepsResourcesOfAnotherInterfaceInstance proves the
// interface-instance fingerprint is enforced: a journal written for one ifindex
// is not acted on when the name now resolves to a different instance.
func TestLinuxRecoveryKeepsResourcesOfAnotherInterfaceInstance(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/instance.journal"
	address := netip.MustParsePrefix("10.208.70.1/32")
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	// The journal carries a confirmed instance marker that names a different
	// interface instance (another ifindex) than the live one, plus a confirmed
	// address. Recovery must refuse to act across the instance.
	otherInstance := linuxInterfaceInstance(name, link.Index+1000, "inst-other")
	writeLinuxJournal(t, path, []journalEntry{
		{
			Version: journalVersion, Time: time.Now().UTC(), Kind: "apply:instance", Interface: name,
			Detail: "inst-other", Transaction: "t-other", ResourceID: otherInstance,
			Outcome: journalOutcomeIntent,
		},
		{
			Version: journalVersion, Time: time.Now().UTC(), Kind: "apply:instance", Interface: name,
			Detail: "inst-other", Transaction: "t-other", ResourceID: otherInstance,
			Outcome: journalOutcomeConfirmed,
		},
		{
			Version: journalVersion, Time: time.Now().UTC(), Kind: "apply:address", Interface: name,
			Detail: address.String(), Transaction: "t-other", ResourceID: otherInstance,
			Outcome: journalOutcomeConfirmed,
		},
	})
	if err := addIPv4Address(address, link.Index); err != nil {
		t.Fatalf("external address: %v", err)
	}
	report, err := RecoverLinuxSystemNetwork(context.Background(), name, path)
	if err != nil {
		t.Fatalf("RecoverLinuxSystemNetwork: %v", err)
	}
	if len(report.Removed) != 0 {
		t.Fatalf("recovery acted across interface instances: %+v", report)
	}
	if len(report.Degraded) == 0 {
		t.Fatalf("recovery did not report the instance mismatch: %+v", report)
	}
	if !hasTestAddress(t, link, address.Addr()) {
		t.Fatalf("recovery deleted the address of another instance: %+v", report)
	}
}

// --- retarget (single-owner address move) ----------------------------------

// journalTransactions groups persisted records by transaction id.
func journalTransactions(entries []JournalEntry) (map[string][]JournalEntry, []string) {
	grouped := make(map[string][]JournalEntry)
	var order []string
	for _, entry := range entries {
		if entry.Transaction == "" {
			continue
		}
		if _, seen := grouped[entry.Transaction]; !seen {
			order = append(order, entry.Transaction)
		}
		grouped[entry.Transaction] = append(grouped[entry.Transaction], entry)
	}
	return grouped, order
}

// TestLinuxRetargetAddressMovesOwnedAddress proves the single-owner retarget on
// the real kernel: the old /32 is released, the new /32 is installed with the
// same route and MTU, a fresh journal transaction owns it, and a repeated
// retarget is a no-op that adds nothing to the journal.
func TestLinuxRetargetAddressMovesOwnedAddress(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/retarget.journal"
	addressA := netip.MustParsePrefix("10.209.1.1/32")
	addressB := netip.MustParsePrefix("10.209.1.2/32")
	route := netip.MustParsePrefix("10.209.9.0/24")
	if err := setInterfaceMTU(name, 1500); err != nil {
		t.Fatalf("seed MTU: %v", err)
	}
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface:   name,
		MTU:         DefaultDeviceMTU,
		Address:     addressA,
		Routes:      []netip.Prefix{route},
		JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	defer func() { _ = network.Close() }()
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	if !hasTestAddress(t, link, addressA.Addr()) {
		t.Fatalf("Apply did not install %s", addressA)
	}

	before, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal before retarget: %v", err)
	}
	if err := network.RetargetAddress(ctx, addressB); err != nil {
		t.Fatalf("RetargetAddress: %v", err)
	}
	// Kernel re-read: A gone, B present, route and MTU intact.
	foundA, _, err := addressState(addressA, link.Index)
	if err != nil {
		t.Fatalf("addressState(A): %v", err)
	}
	foundB, exactB, err := addressState(addressB, link.Index)
	if err != nil {
		t.Fatalf("addressState(B): %v", err)
	}
	if foundA || !foundB || !exactB {
		t.Fatalf("retarget kernel state wrong: A found=%v B found=%v exact=%v", foundA, foundB, exactB)
	}
	state, err := routeState(route, link.Index)
	if err != nil {
		t.Fatalf("routeState: %v", err)
	}
	if !state.Found || !state.Exact {
		t.Fatalf("retarget changed the route: %+v", state)
	}
	if live, _ := currentInterfaceMTU(name); live != DefaultDeviceMTU {
		t.Fatalf("retarget changed MTU to %d", live)
	}
	if linkAfter, err := net.InterfaceByName(name); err == nil && linkAfter.Flags&net.FlagUp == 0 {
		t.Fatal("retarget left the interface down")
	}

	// Journal: the old transaction is terminal and a NEW transaction owns B.
	after, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal after retarget: %v", err)
	}
	grouped, order := journalTransactions(after)
	if len(order) < 2 {
		t.Fatalf("retarget did not start a new journal transaction: %v", order)
	}
	if len(after) <= len(before) {
		t.Fatalf("retarget added no journal records: before=%d after=%d", len(before), len(after))
	}
	oldTxn, newTxn := order[0], order[len(order)-1]
	oldTerminal := false
	for _, entry := range grouped[oldTxn] {
		if entry.Kind == journalTerminalKind {
			oldTerminal = true
		}
	}
	if !oldTerminal {
		t.Fatalf("the pre-retarget transaction %q has no terminal checkpoint", oldTxn)
	}
	ownsB := false
	for _, entry := range grouped[newTxn] {
		if entry.Kind == "apply:address" && entry.Outcome == journalOutcomeConfirmed && entry.Detail == addressB.String() {
			ownsB = true
		}
	}
	if !ownsB {
		t.Fatalf("the new transaction %q does not own %s: %+v", newTxn, addressB, grouped[newTxn])
	}

	// Repeat retarget is a no-op and preserves the journal.
	if err := network.RetargetAddress(ctx, addressB); err != nil {
		t.Fatalf("repeat RetargetAddress: %v", err)
	}
	repeat, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal after repeat: %v", err)
	}
	if len(repeat) != len(after) {
		t.Fatalf("a repeated retarget mutated the journal: %d -> %d records", len(after), len(repeat))
	}
}

// TestLinuxAgentRetargetAddressKeepsSameDeviceFD drives the retarget through the
// public Agent API on a real TUN: the PacketDevice (and therefore the kernel FD)
// must be the very same object before and after the address move.
func TestLinuxAgentRetargetAddressKeepsSameDeviceFD(t *testing.T) {
	name := testTUNName()
	addressA := netip.MustParsePrefix("10.209.21.1/32")
	addressB := netip.MustParsePrefix("10.209.21.2/32")
	route := netip.MustParsePrefix("10.209.29.0/24")
	path := t.TempDir() + "/agent-retarget.journal"
	config := AgentConfig{
		Platform: PlatformLinux,
		Inbounds: Inbounds{TUN: boolPointer(true)},
		Device:   DeviceConfig{Name: name, Address: addressA, Routes: []netip.Prefix{route}, JournalPath: path},
	}
	agent, err := New(config, Deps{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := agent.Start(ctx); err != nil {
		if errors.Is(err, ErrPlatformUnavailable) {
			t.Skipf("external blocker: %v", err)
		}
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = agent.Close() }()
	deviceBefore := agent.PacketDevice()
	if deviceBefore == nil {
		t.Fatal("Start reported success without a PacketDevice")
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	indexBefore := link.Index

	if err := agent.RetargetAddress(ctx, addressB); err != nil {
		t.Fatalf("Agent.RetargetAddress: %v", err)
	}
	deviceAfter := agent.PacketDevice()
	if deviceAfter == nil || deviceAfter != deviceBefore {
		t.Fatal("retarget reopened or replaced the packet device (FD must stay the same)")
	}
	linkAfter, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q after retarget: %v", name, err)
	}
	if linkAfter.Index != indexBefore {
		t.Fatalf("retarget changed the interface index %d -> %d", indexBefore, linkAfter.Index)
	}
	foundA, _, err := addressState(addressA, linkAfter.Index)
	if err != nil {
		t.Fatalf("addressState(A): %v", err)
	}
	foundB, exactB, err := addressState(addressB, linkAfter.Index)
	if err != nil {
		t.Fatalf("addressState(B): %v", err)
	}
	if foundA || !foundB || !exactB {
		t.Fatalf("agent retarget kernel state wrong: A found=%v B found=%v exact=%v", foundA, foundB, exactB)
	}
	if err := agent.RetargetAddress(ctx, addressB); err != nil {
		t.Fatalf("repeat Agent.RetargetAddress: %v", err)
	}
}

// TestLinuxRetargetRefusesExternalAlias proves a non-empty alias that is not
// this transaction's token stops the retarget: the external marker is kept and
// the old address is not silently replaced.
func TestLinuxRetargetRefusesExternalAlias(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/retarget-alias.journal"
	addressA := netip.MustParsePrefix("10.209.31.1/32")
	addressB := netip.MustParsePrefix("10.209.31.2/32")
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface: name, Address: addressA, JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	defer func() { _ = network.Close() }()
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	before, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal before: %v", err)
	}
	// An external actor replaces the alias after Apply.
	if err := setInterfaceAlias(name, "user-marker"); err != nil {
		t.Fatalf("external alias: %v", err)
	}
	if err := network.RetargetAddress(ctx, addressB); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("retarget must refuse an external non-empty alias with ErrPlatformUnavailable, got %v", err)
	}
	live, err := readInterfaceAlias(name)
	if err != nil {
		t.Fatalf("readInterfaceAlias: %v", err)
	}
	if live != "user-marker" {
		t.Fatalf("retarget overwrote the external alias: %q", live)
	}
	// The preflight failure precedes every side effect: the owned /32 survives,
	// the new address was never applied and the journal gained nothing.
	foundA, exactA, err := addressState(addressA, link.Index)
	if err != nil {
		t.Fatalf("addressState(A): %v", err)
	}
	if !foundA || !exactA {
		t.Fatalf("retarget released the owned address %s despite the refused alias: present=%v exact=%v", addressA, foundA, exactA)
	}
	foundB, _, err := addressState(addressB, link.Index)
	if err != nil {
		t.Fatalf("addressState(B): %v", err)
	}
	if foundB {
		t.Fatal("retarget applied the new address despite the refused alias")
	}
	after, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal after: %v", err)
	}
	_, orderBefore := journalTransactions(before)
	_, orderAfter := journalTransactions(after)
	if len(after) != len(before) || strings.Join(orderAfter, ",") != strings.Join(orderBefore, ",") {
		t.Fatalf("a preflight-refused retarget mutated the journal: %d -> %d records, transactions %v -> %v", len(before), len(after), orderBefore, orderAfter)
	}
	if network.State() != SystemNetworkApplied {
		t.Fatalf("a preflight-refused retarget changed state to %s", network.State())
	}
	if len(network.DegradedDetail()) == 0 {
		t.Fatal("the refused alias was not reported Degraded")
	}
	if err := setInterfaceAlias(name, ""); err != nil {
		t.Fatalf("clear external alias: %v", err)
	}
}

// TestLinuxRetargetKeepsExternallyReplacedRoute proves an externally replaced
// route stops the retarget with Degraded BEFORE any side effect: the foreign
// route, the transaction's own address, MTU, link state, alias and journal all
// stay untouched, and the new address is not applied. Releasing the owned /32
// first would make the kernel drop the foreign device route as collateral.
func TestLinuxRetargetKeepsExternallyReplacedRoute(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/retarget-route.journal"
	addressA := netip.MustParsePrefix("10.209.41.1/32")
	addressB := netip.MustParsePrefix("10.209.41.2/32")
	route := netip.MustParsePrefix("10.209.49.0/24")
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface: name, Address: addressA, Routes: []netip.Prefix{route}, JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	defer func() { _ = network.Close() }()
	// Keep the link up before Prepare so this transaction does not own link-up:
	// the kernel purges device routes when an owned link is brought back down,
	// which would mask whether our code preserved the external route.
	if err := setLinkUp(name, true); err != nil {
		t.Fatalf("bring %q up before Prepare: %v", name, err)
	}
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	// External replacement of the owned route with a different metric.
	if err := deleteRoute(route, link.Index); err != nil {
		t.Fatalf("remove owned route: %v", err)
	}
	addForeignMetricRoute(t, route, link.Index, 100)
	before, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal before retarget: %v", err)
	}
	beforeMTU, err := currentInterfaceMTU(name)
	if err != nil {
		t.Fatalf("currentInterfaceMTU before retarget: %v", err)
	}
	if err := network.RetargetAddress(ctx, addressB); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("retarget must fail closed when an owned route was replaced externally, got %v", err)
	}
	// The only changes are the error and Degraded: the foreign route survives,
	// the owned /32 and every other owned resource are untouched, and the journal
	// gained no record and started no new transaction.
	state, err := routeState(route, link.Index)
	if err != nil {
		t.Fatalf("routeState: %v", err)
	}
	if !state.Found || state.Exact || state.Entry.metric != 100 {
		t.Fatalf("retarget changed the external route: %+v", state)
	}
	foundA, exactA, err := addressState(addressA, link.Index)
	if err != nil {
		t.Fatalf("addressState(A): %v", err)
	}
	if !foundA || !exactA {
		t.Fatalf("retarget released the owned address %s: present=%v exact=%v", addressA, foundA, exactA)
	}
	foundB, _, err := addressState(addressB, link.Index)
	if err != nil {
		t.Fatalf("addressState(B): %v", err)
	}
	if foundB {
		t.Fatal("retarget applied the new address despite the Degraded preflight")
	}
	afterMTU, err := currentInterfaceMTU(name)
	if err != nil {
		t.Fatalf("currentInterfaceMTU after retarget: %v", err)
	}
	if afterMTU != beforeMTU {
		t.Fatalf("retarget changed MTU %d -> %d", beforeMTU, afterMTU)
	}
	linkAfter, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q after retarget: %v", name, err)
	}
	if linkAfter.Flags&net.FlagUp == 0 {
		t.Fatal("retarget brought the link down")
	}
	liveAlias, err := readInterfaceAlias(name)
	if err != nil {
		t.Fatalf("readInterfaceAlias after retarget: %v", err)
	}
	if liveAlias != network.instanceToken {
		t.Fatalf("retarget changed the ownership alias: %q != %q", liveAlias, network.instanceToken)
	}
	if network.State() != SystemNetworkApplied {
		t.Fatalf("a preflight-refused retarget changed state to %s", network.State())
	}
	if len(network.DegradedDetail()) == 0 {
		t.Fatal("the replaced route was not reported Degraded")
	}
	after, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal after retarget: %v", err)
	}
	_, orderBefore := journalTransactions(before)
	_, orderAfter := journalTransactions(after)
	if len(after) != len(before) || strings.Join(orderAfter, ",") != strings.Join(orderBefore, ",") {
		t.Fatalf("a preflight-refused retarget mutated the journal: %d -> %d records, transactions %v -> %v", len(before), len(after), orderBefore, orderAfter)
	}
	deleteForeignMetricRoute(t, route, link.Index, 100)
}

// TestLinuxRetargetRefusesAddressPrefixChange proves an external actor that
// replaced the owned /32 with the same address at another prefix length stops
// the retarget before any release: the external prefix is kept, the owned
// address was never deleted, the new address is not applied and the journal
// gains nothing.
func TestLinuxRetargetRefusesAddressPrefixChange(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/retarget-prefix.journal"
	addressA := netip.MustParsePrefix("10.209.42.1/32")
	addressB := netip.MustParsePrefix("10.209.42.2/32")
	widened := netip.MustParsePrefix("10.209.42.1/24")
	if err := setInterfaceMTU(name, DefaultDeviceMTU); err != nil {
		t.Fatalf("seed MTU: %v", err)
	}
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface: name, Address: addressA, JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	defer func() { _ = network.Close() }()
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %q: %v", name, err)
	}
	// An external actor replaces the owned /32 with the same address on a /24.
	if err := deleteIPv4Address(addressA, link.Index); err != nil {
		t.Fatalf("remove owned address: %v", err)
	}
	if err := addIPv4Address(widened, link.Index); err != nil {
		t.Fatalf("install widened external address: %v", err)
	}
	present, exact, err := addressState(addressA, link.Index)
	if err != nil {
		t.Fatalf("addressState fixture: %v", err)
	}
	if !present || exact {
		t.Fatalf("fixture: %s must be present with the widened prefix, got present=%v exact=%v", addressA, present, exact)
	}
	before, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal before retarget: %v", err)
	}
	if err := network.RetargetAddress(ctx, addressB); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("retarget must fail closed on an externally widened address, got %v", err)
	}
	foundB, _, err := addressState(addressB, link.Index)
	if err != nil {
		t.Fatalf("addressState(B): %v", err)
	}
	if foundB {
		t.Fatal("retarget applied the new address despite the widened external prefix")
	}
	present, exact, err = addressState(addressA, link.Index)
	if err != nil {
		t.Fatalf("addressState(A) after retarget: %v", err)
	}
	if !present || exact {
		t.Fatalf("retarget mutated the external prefix: present=%v exact=%v", present, exact)
	}
	after, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal after retarget: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("a preflight-refused retarget mutated the journal: %d -> %d records", len(before), len(after))
	}
	if network.State() != SystemNetworkApplied {
		t.Fatalf("a preflight-refused retarget changed state to %s", network.State())
	}
	if len(network.DegradedDetail()) == 0 {
		t.Fatal("the widened address was not reported Degraded")
	}
	if err := deleteIPv4Address(widened, link.Index); err != nil {
		t.Fatalf("remove external address: %v", err)
	}
}

// TestLinuxRetargetCloseRace runs a retarget concurrently with Close under the
// race detector: the owner mutex and the Agent serialization must keep this
// safe, and Close must complete.
func TestLinuxRetargetCloseRace(t *testing.T) {
	device := openTestTUN(t, DeviceOptions{})
	defer func() { _ = device.Close() }()
	name := device.InterfaceName()
	path := t.TempDir() + "/retarget-race.journal"
	addressA := netip.MustParsePrefix("10.209.51.1/32")
	addressB := netip.MustParsePrefix("10.209.51.2/32")
	network, err := newLinuxSystemNetwork(SystemNetworkOptions{
		Interface: name, Address: addressA, JournalPath: path,
	})
	if err != nil {
		t.Fatalf("newLinuxSystemNetwork: %v", err)
	}
	ctx := context.Background()
	if err := network.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_ = network.RetargetAddress(ctx, addressB)
	}()
	go func() {
		defer wait.Done()
		_ = network.Close()
	}()
	wait.Wait()
}
