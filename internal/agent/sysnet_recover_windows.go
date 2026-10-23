//go:build windows

package agent

// Crash recovery for the Windows host network transaction.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// A crash leaves the persisted journal on disk but no live transaction. Recover
// acts only on the newest transaction of the named adapter and only on resources
// that transaction explicitly confirmed it created and never rolled back (see
// sysnet_journal.go). It then proves ownership again against the live adapter:
//
//   - the adapter instance must still resolve to the journaled LUID and index,
//     otherwise the alias now names a different adapter and nothing is touched;
//   - a route must match the whole recorded tuple (destination, prefix length,
//     on-link next hop, zero metric, NETMGMT protocol, adapter and interface
//     index), not just the prefix;
//   - an address must match the recorded prefix exactly, including prefix
//     length;
//   - an MTU is restored only while the adapter still holds the value this
//     transaction set.
//
// Transactions with a terminal checkpoint, pre-version-2 records, intents
// without a completion and incomplete final records are kept and reported
// Degraded: presence on the adapter is never accepted as proof of ownership.
//
// Recovery always reads the persisted journal path: the in-memory journal of a
// dead process is not a write-ahead log. The returned checkpoints are the
// remaining resource names, never live transaction state.

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// RecoverWindowsSystemNetwork reconciles one persisted journal after a crash.
// The caller supplies the adapter alias and the journal path the crashed
// transaction used.
func RecoverWindowsSystemNetwork(ctx context.Context, interfaceName, journalPath string) (RecoveryReport, error) {
	return recoverWindowsSystemNetwork(ctx, interfaceName, journalPath, nativeWindowsIPHelperOps())
}

func recoverWindowsSystemNetwork(ctx context.Context, interfaceName, journalPath string, ops *windowsIPHelperOps) (RecoveryReport, error) {
	report := RecoveryReport{Interface: interfaceName}
	if strings.TrimSpace(interfaceName) == "" {
		return report, fmt.Errorf("%w: system_network.interface must name the crashed transaction's adapter", ErrInvalidConfig)
	}
	if ops == nil {
		return report, fmt.Errorf("%w: Windows recovery needs its IP Helper bindings", ErrPlatformUnavailable)
	}
	loaded, err := readJournal(journalPath)
	if err != nil {
		return report, err
	}
	view := selectInterfaceJournal(loaded.Entries, interfaceName)
	reportLegacyJournal(&report, view)
	if view.Transaction == "" {
		if len(view.Legacy) == 0 && !view.TornTail {
			report.keep("adapter " + interfaceName + " (no apply entries)")
		}
		return report, nil
	}
	if view.Terminal {
		report.keep("transaction " + view.Transaction + " (already rolled back)")
		return report, nil
	}
	if err := packetDeviceContextErr(ctx); err != nil {
		return report, err
	}
	luid, err := ops.interfaceLUID(interfaceName)
	if err != nil {
		// Nothing to reconcile: the adapter (and therefore every address and
		// route on it) is already gone.
		for _, entry := range view.Active {
			if strings.HasPrefix(entry.Kind, "apply:") {
				report.keep(entry.Kind + " " + entry.Detail)
			}
		}
		return report, nil
	}
	index, err := ops.interfaceIndex(luid)
	if err != nil {
		return report, fmt.Errorf("agent: recovery resolve adapter %q interface index: %w", interfaceName, err)
	}
	if !journalInstanceMatches(view.Active, windowsInterfaceInstance(luid, index)) {
		report.degrade("adapter "+interfaceName,
			"the live adapter instance does not match the journaled LUID/index; nothing is removed")
		return report, nil
	}
	ownership := ownershipFromJournal(view.Active)
	for _, entry := range ownership.NotOwned {
		report.keep(entry.Kind + " " + entry.Detail + " (not owned: the resource already existed)")
	}
	for _, entry := range ownership.RolledBack {
		report.keep(entry.Kind + " " + entry.Detail + " (already rolled back)")
	}
	for _, entry := range ownership.Uncertain {
		report.degrade(entry.Kind+" "+entry.Detail,
			"the transaction has no confirmed completion for this resource; the live resource is kept")
	}
	// Reverse order, exactly like Rollback: routes, address, MTU.
	for position := len(ownership.Owned) - 1; position >= 0; position-- {
		entry := ownership.Owned[position]
		resource, ok := strings.CutPrefix(entry.Kind, "apply:")
		if !ok {
			continue
		}
		switch resource {
		case "route":
			if err := recoverWindowsRoute(&report, entry, luid, index, ops); err != nil {
				return report, err
			}
		case "address":
			if err := recoverWindowsAddress(&report, entry, luid, index, ops); err != nil {
				return report, err
			}
		case "mtu":
			if err := recoverWindowsMTU(&report, entry, luid, interfaceName, ops); err != nil {
				return report, err
			}
		default:
			report.degrade(entry.Kind+" "+entry.Detail, "unknown resource kind; the live resource is kept")
		}
	}
	return report, nil
}

// recoverWindowsRoute removes one confirmed route only while the adapter reports
// the exact recorded tuple.
func recoverWindowsRoute(report *RecoveryReport, entry JournalEntry, luid uint64, index uint32, ops *windowsIPHelperOps) error {
	prefix, err := netip.ParsePrefix(entry.Detail)
	if err != nil {
		report.degrade(entry.Kind, fmt.Sprintf("route entry %q is not a prefix: %v", entry.Detail, err))
		return nil
	}
	if !windowsRouteFingerprintMatches(entry.Fingerprint, prefix, luid) {
		report.degrade(entry.Kind+" "+entry.Detail,
			fmt.Sprintf("route fingerprint %q does not describe this adapter and prefix; the live route is kept", entry.Fingerprint))
		return nil
	}
	state, err := ops.routeState(luid, index, prefix)
	if err != nil {
		return fmt.Errorf("agent: recovery route lookup %s: %w", prefix, err)
	}
	switch {
	case !state.Found:
		report.keep("route " + prefix.String())
	case !state.Exact:
		report.degrade(entry.Kind+" "+entry.Detail,
			fmt.Sprintf("route %s is present with different attributes; the external route is kept", prefix))
	default:
		if err := ops.deleteIPv4Route(luid, index, prefix); err != nil {
			return fmt.Errorf("agent: recovery remove route %s from %q: %w", prefix, report.Interface, err)
		}
		report.remove("route " + prefix.String())
	}
	return nil
}

// recoverWindowsAddress removes one confirmed address only while the adapter
// reports the same address with the exact recorded prefix length.
func recoverWindowsAddress(report *RecoveryReport, entry JournalEntry, luid uint64, index uint32, ops *windowsIPHelperOps) error {
	prefix, err := netip.ParsePrefix(entry.Detail)
	if err != nil {
		report.degrade(entry.Kind, fmt.Sprintf("address entry %q is not a prefix: %v", entry.Detail, err))
		return nil
	}
	present, found, err := ops.interfaceAddress(luid, prefix.Addr())
	if err != nil {
		return fmt.Errorf("agent: recovery address lookup %s: %w", prefix, err)
	}
	switch {
	case !found:
		report.keep("address " + prefix.String())
	case present != prefix:
		report.degrade(entry.Kind+" "+entry.Detail,
			fmt.Sprintf("address %s is present with prefix length %d, not the recorded %d; the external address is kept", prefix.Addr(), present.Bits(), prefix.Bits()))
	default:
		if err := ops.deleteIPv4Addr(luid, index, prefix.Addr()); err != nil {
			return fmt.Errorf("agent: recovery remove %s from %q: %w", prefix, report.Interface, err)
		}
		report.remove("address " + prefix.String())
	}
	return nil
}

// recoverWindowsMTU restores the prior MTU only while the adapter still holds
// the value this transaction set.
func recoverWindowsMTU(report *RecoveryReport, entry JournalEntry, luid uint64, interfaceName string, ops *windowsIPHelperOps) error {
	appliedMTU, priorMTU, ok := parseMTUFingerprintWindows(strings.TrimPrefix(entry.Detail, "mtu="), entry.Fingerprint)
	if !ok {
		report.degrade(entry.Kind, fmt.Sprintf("MTU entry %q/%q is not parseable", entry.Detail, entry.Fingerprint))
		return nil
	}
	current, err := ops.interfaceMTU(luid)
	if err != nil {
		report.degrade("mtu "+strconv.Itoa(appliedMTU),
			fmt.Sprintf("MTU of %q could not be read: %v; the external value is kept", interfaceName, err))
		return nil
	}
	if current != appliedMTU {
		report.degrade("mtu "+strconv.Itoa(appliedMTU),
			fmt.Sprintf("MTU is now %d, not the %d this transaction set; the external value is kept", current, appliedMTU))
		return nil
	}
	if err := ops.setInterfaceMTU(luid, priorMTU); err != nil {
		return fmt.Errorf("agent: recovery restore MTU %d on %q: %w", priorMTU, interfaceName, err)
	}
	report.remove(fmt.Sprintf("mtu %d (restored to %d)", appliedMTU, priorMTU))
	return nil
}

// windowsRouteFingerprintMatches checks that a recorded route fingerprint names
// this adapter and prefix. A missing or malformed field is unprovable
// ownership, never a wildcard.
func windowsRouteFingerprintMatches(raw string, prefix netip.Prefix, luid uint64) bool {
	if raw == "" {
		return false
	}
	fields := decodeJournalFields(raw)
	if fields["dst"] != prefix.String() {
		return false
	}
	if fields["luid"] != strconv.FormatUint(luid, 10) {
		return false
	}
	return true
}

// parseMTUFingerprintWindows reads the "mtu=<applied>" detail and "prior=<n>"
// fingerprint recorded by Apply.
func parseMTUFingerprintWindows(detail, fingerprint string) (int, int, bool) {
	applied, err := strconv.Atoi(strings.TrimSpace(detail))
	if err != nil {
		return 0, 0, false
	}
	prior, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(fingerprint, "prior=")))
	if err != nil {
		return 0, 0, false
	}
	return applied, prior, true
}
