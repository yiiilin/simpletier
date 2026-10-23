//go:build linux

package agent

// Crash recovery for the Linux host network transaction.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// A crash leaves the journal on disk but no live transaction. Recovery acts only
// on the newest transaction of the named interface and only on resources that
// transaction explicitly confirmed it created and never rolled back (see
// sysnet_journal.go). It then proves ownership again against the live kernel:
//
//   - the interface instance must still have the journaled ifindex, otherwise
//     the name now belongs to a different interface and nothing is touched;
//   - a route must match the whole recorded tuple (destination, prefix length,
//     output interface, table, protocol, scope, type, metric and gateway), not
//     just the prefix;
//   - an address must match the recorded prefix exactly, including its prefix
//     length, so a same-address /24 is not mistaken for the /32 this
//     transaction created;
//   - an MTU is restored only while the interface still holds the value this
//     transaction set.
//
// Transactions with a terminal checkpoint, pre-version-2 records, intents
// without a completion, incomplete final records and interfaces whose instance
// cannot be reproduced are all kept and reported Degraded: presence on the host
// is never accepted as proof of ownership.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// RecoverLinuxSystemNetwork reconciles one persisted journal after a crash. The
// caller supplies the interface name and the journal path the crashed
// transaction used.
func RecoverLinuxSystemNetwork(ctx context.Context, interfaceName, journalPath string) (RecoveryReport, error) {
	report := RecoveryReport{Interface: interfaceName}
	if interfaceName == "" {
		return report, fmt.Errorf("%w: system_network.interface must name the crashed transaction's interface", ErrInvalidConfig)
	}
	loaded, err := readJournal(journalPath)
	if err != nil {
		return report, err
	}
	view := selectInterfaceJournal(loaded.Entries, interfaceName)
	reportLegacyJournal(&report, view)
	if view.Transaction == "" {
		if len(view.Legacy) == 0 && !view.TornTail {
			report.keep("interface " + interfaceName + " (no apply entries)")
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
	link, err := net.InterfaceByName(interfaceName)
	if err != nil {
		// Nothing to reconcile: the interface (and therefore every address and
		// route on it) is already gone.
		for _, entry := range view.Active {
			if strings.HasPrefix(entry.Kind, "apply:") {
				report.keep(entry.Kind + " " + entry.Detail)
			}
		}
		return report, nil
	}
	token, priorAlias, failure, proven := linuxInstanceProof(view.Active, link)
	ownership := ownershipFromJournal(withoutInstanceEntries(view.Active))
	if !proven {
		for _, entry := range ownership.Owned {
			report.degrade(entry.Kind+" "+entry.Detail, failure)
		}
		report.degrade("instance "+interfaceName, failure)
		return report, nil
	}
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
	// Reverse order, exactly like Rollback: routes, link-up, address, MTU.
	for position := len(ownership.Owned) - 1; position >= 0; position-- {
		entry := ownership.Owned[position]
		resource, ok := strings.CutPrefix(entry.Kind, "apply:")
		if !ok {
			continue
		}
		switch resource {
		case "route":
			if err := recoverLinuxRoute(&report, entry, link.Index); err != nil {
				return report, err
			}
		case "address":
			if err := recoverLinuxAddress(&report, entry, link.Index); err != nil {
				return report, err
			}
		case "link_up":
			flags, err := net.InterfaceByName(interfaceName)
			if err != nil {
				report.degrade(entry.Kind+" "+entry.Detail, fmt.Sprintf("link state of %q could not be read: %v; the state is kept", interfaceName, err))
				continue
			}
			if flags.Flags&net.FlagUp == 0 {
				report.keep("link up state of " + interfaceName)
				continue
			}
			if err := setLinkUp(interfaceName, false); err != nil {
				return report, fmt.Errorf("agent: recovery bring %q down: %w", interfaceName, err)
			}
			report.remove("link up state of " + interfaceName)
		case "mtu":
			if err := recoverLinuxMTU(&report, entry, interfaceName); err != nil {
				return report, err
			}
		default:
			report.degrade(entry.Kind+" "+entry.Detail, "unknown resource kind; the live resource is kept")
		}
	}
	// The instance marker is proof, not a resource: clear it only while the
	// kernel still reports exactly this transaction's random token, and restore
	// the alias the transaction observed at Prepare (usually empty).
	if live, err := readInterfaceAlias(interfaceName); err != nil {
		report.degrade("instance "+interfaceName, fmt.Sprintf("the live interface alias could not be re-read before clearing it: %v; the marker is kept", err))
		return report, nil
	} else if live == token {
		if err := setInterfaceAlias(interfaceName, priorAlias); err != nil {
			return report, fmt.Errorf("agent: recovery restore alias %q on %q: %w", priorAlias, interfaceName, err)
		}
		report.remove("instance marker of " + interfaceName)
	} else {
		report.degrade("instance "+interfaceName, fmt.Sprintf("the live interface alias is now %q, not this transaction's marker; the external alias is kept", live))
	}
	return report, nil
}

// withoutInstanceEntries removes the instance-marker records from a
// transaction: the marker is proved separately, not recovered as a resource.
func withoutInstanceEntries(active []JournalEntry) []JournalEntry {
	filtered := make([]JournalEntry, 0, len(active))
	for _, entry := range active {
		switch entry.Kind {
		case "apply:instance", "applied:instance", "rollback:instance", "rolledback:instance":
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

// linuxInstanceProof verifies the transaction's instance marker against the
// live kernel. It succeeds only when the newest confirmed marker names this
// interface (name + ifindex) and the live kernel alias is exactly the recorded
// random token. Name or index reuse alone is never proof. An apply confirmation
// shares the intent's kind and is distinguished by Outcome, so the marker is
// the newest "apply:instance" record with Outcome=confirmed.
func linuxInstanceProof(active []JournalEntry, link *net.Interface) (token, priorAlias, failure string, proven bool) {
	recorded := ""
	for _, entry := range active {
		switch entry.Kind {
		case "apply:instance":
			if entry.Outcome == journalOutcomeConfirmed {
				recorded = entry.ResourceID
				priorAlias = decodeJournalFields(entry.Fingerprint)["prior"]
			}
		case "rolledback:instance":
			recorded = ""
		}
	}
	if recorded == "" {
		return "", "", "the transaction has no confirmed instance marker; ownership cannot be proven and nothing is removed", false
	}
	fields := decodeJournalFields(recorded)
	if fields["name"] != link.Name || fields["ifindex"] != strconv.Itoa(link.Index) {
		return "", "", fmt.Sprintf("the journaled instance does not name the live interface %q (index %d); nothing is removed", link.Name, link.Index), false
	}
	token = fields["alias"]
	if token == "" {
		return "", "", "the journaled instance carries no alias token; ownership cannot be proven", false
	}
	live, err := readInterfaceAlias(link.Name)
	if err != nil {
		return "", "", fmt.Sprintf("the live interface alias could not be read: %v; nothing is removed", err), false
	}
	if live != token {
		return "", "", fmt.Sprintf("the live interface alias %q is not the journaled marker %q; the instance cannot be proven and nothing is removed", live, token), false
	}
	return token, priorAlias, "", true
}

// recoverLinuxRoute removes one confirmed route only while the live kernel
// reports the exact recorded tuple.
func recoverLinuxRoute(report *RecoveryReport, entry JournalEntry, ifindex int) error {
	prefix, err := netip.ParsePrefix(entry.Detail)
	if err != nil {
		report.degrade(entry.Kind, fmt.Sprintf("route entry %q is not a prefix: %v", entry.Detail, err))
		return nil
	}
	recorded, ok := parseRouteFields(entry.Fingerprint)
	if !ok {
		report.degrade(entry.Kind+" "+entry.Detail,
			fmt.Sprintf("route fingerprint %q is incomplete; the live route is kept", entry.Fingerprint))
		return nil
	}
	if recorded.destination != prefix.Addr() || recorded.bits != prefix.Bits() || recorded.ifindex != ifindex {
		report.degrade(entry.Kind+" "+entry.Detail,
			"the recorded route tuple does not describe this interface and prefix; the live route is kept")
		return nil
	}
	state, err := routeState(prefix, ifindex)
	if err != nil {
		return fmt.Errorf("agent: recovery route lookup %s: %w", prefix, err)
	}
	switch {
	case !state.Found:
		report.keep("route " + prefix.String())
	case !state.Exact:
		report.degrade(entry.Kind+" "+entry.Detail,
			fmt.Sprintf("route %s now has different attributes or output interface; the external route is kept", prefix))
	default:
		if err := deleteRoute(prefix, ifindex); err != nil {
			return fmt.Errorf("agent: recovery remove route %s: %w", prefix, err)
		}
		report.remove("route " + prefix.String())
	}
	return nil
}

// recoverLinuxAddress removes one confirmed address only while the live kernel
// reports the same address with the exact recorded prefix length.
func recoverLinuxAddress(report *RecoveryReport, entry JournalEntry, ifindex int) error {
	prefix, err := netip.ParsePrefix(entry.Detail)
	if err != nil {
		report.degrade(entry.Kind, fmt.Sprintf("address entry %q is not a prefix: %v", entry.Detail, err))
		return nil
	}
	found, exact, err := addressState(prefix, ifindex)
	if err != nil {
		return fmt.Errorf("agent: recovery address lookup %s: %w", prefix, err)
	}
	switch {
	case !found:
		report.keep("address " + prefix.String())
	case !exact:
		report.degrade(entry.Kind+" "+entry.Detail,
			fmt.Sprintf("address %s is present with a different prefix length; the external address is kept", prefix.Addr()))
	default:
		if err := deleteIPv4Address(prefix, ifindex); err != nil {
			return fmt.Errorf("agent: recovery remove %s: %w", prefix, err)
		}
		report.remove("address " + prefix.String())
	}
	return nil
}

// recoverLinuxMTU restores the prior MTU only while the interface still holds
// the value this transaction set.
func recoverLinuxMTU(report *RecoveryReport, entry JournalEntry, interfaceName string) error {
	appliedMTU, priorMTU, ok := parseMTUFingerprint(strings.TrimPrefix(entry.Detail, "mtu="), entry.Fingerprint)
	if !ok {
		report.degrade(entry.Kind, fmt.Sprintf("MTU entry %q/%q is not parseable", entry.Detail, entry.Fingerprint))
		return nil
	}
	current, err := currentInterfaceMTU(interfaceName)
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
	if err := setInterfaceMTU(interfaceName, priorMTU); err != nil {
		return fmt.Errorf("agent: recovery restore MTU %d on %q: %w", priorMTU, interfaceName, err)
	}
	report.remove(fmt.Sprintf("mtu %d (restored to %d)", appliedMTU, priorMTU))
	return nil
}

// parseMTUFingerprint reads the "mtu=<applied>" detail and "prior=<n>"
// fingerprint recorded by Apply.
func parseMTUFingerprint(detail, fingerprint string) (int, int, bool) {
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
