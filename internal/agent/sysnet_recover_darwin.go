//go:build darwin

package agent

// Crash recovery for the macOS host network transaction.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// A crash leaves the journal on disk but no live transaction. Recover acts only
// on the newest transaction of the named interface and only on resources that
// transaction explicitly confirmed it created and never rolled back (see
// sysnet_journal.go).
//
// macOS ownership evidence is weaker than Linux's, and recovery is honest about
// it:
//
//   - the interface instance must still have the journaled index;
//   - a route is NEVER removed from a journal alone. The kernel's RTM_GET route
//     index semantics are not verified at runtime here, so a route whose
//     interface cannot be proven is kept and reported Degraded rather than
//     guessed at;
//   - an address is removed only when the interface still carries exactly the
//     recorded /32; anything else is kept;
//   - an MTU is restored only while the interface still holds the value this
//     transaction set.
//
// Transactions with a terminal checkpoint, pre-version-2 records, intents
// without a completion and incomplete final records are kept and reported
// Degraded. No resource is touched when the interface no longer exists: a dead
// utun socket destroys its interface, so that is the common crash outcome.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// RecoverDarwinSystemNetwork reconciles one persisted journal after a crash. The
// caller supplies the interface name the crashed transaction used (the
// kernel-assigned utunN recorded in the journal) and its journal path.
func RecoverDarwinSystemNetwork(ctx context.Context, interfaceName, journalPath string) (RecoveryReport, error) {
	report := RecoveryReport{Interface: interfaceName}
	if strings.TrimSpace(interfaceName) == "" {
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
	if !journalInstanceMatches(view.Active, darwinInterfaceInstance(link.Index)) {
		report.degrade("interface "+interfaceName,
			fmt.Sprintf("the live interface index %d does not match the journaled instance; nothing is removed", link.Index))
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
	// Reverse order, exactly like Rollback: routes, link-up, address, MTU.
	for position := len(ownership.Owned) - 1; position >= 0; position-- {
		entry := ownership.Owned[position]
		resource, ok := strings.CutPrefix(entry.Kind, "apply:")
		if !ok {
			continue
		}
		switch resource {
		case "route":
			// macOS route-instance proof is unavailable from this repository's
			// non-Darwin hosts and the RTM_GET interface index is unverified at
			// runtime. Keeping the route is the honest outcome.
			report.degrade(entry.Kind+" "+entry.Detail,
				"macOS route ownership cannot be proven from the journal without a verified RTM_GET interface index; the route is kept")
		case "address":
			if err := recoverDarwinAddress(&report, entry, link); err != nil {
				return report, err
			}
		case "link_up":
			flags, err := getInterfaceFlags(interfaceName)
			if err != nil {
				report.degrade(entry.Kind+" "+entry.Detail, fmt.Sprintf("flags of %q could not be read: %v; the link state is kept", interfaceName, err))
				continue
			}
			if flags&unix.IFF_UP == 0 {
				report.keep("link up state of " + interfaceName)
				continue
			}
			if err := setLinkUp(interfaceName, false); err != nil {
				return report, fmt.Errorf("agent: recovery bring %q down: %w", interfaceName, err)
			}
			report.remove("link up state of " + interfaceName)
		case "mtu":
			if err := recoverDarwinMTU(&report, entry, interfaceName); err != nil {
				return report, err
			}
		default:
			report.degrade(entry.Kind+" "+entry.Detail, "unknown resource kind; the live resource is kept")
		}
	}
	return report, nil
}

// recoverDarwinAddress removes one confirmed address only while the interface
// still carries exactly the recorded /32. The masked net.Interface view cannot
// distinguish every prefix length, so anything not exactly a /32 match is kept.
func recoverDarwinAddress(report *RecoveryReport, entry JournalEntry, link *net.Interface) error {
	prefix, err := netip.ParsePrefix(entry.Detail)
	if err != nil {
		report.degrade(entry.Kind, fmt.Sprintf("address entry %q is not a prefix: %v", entry.Detail, err))
		return nil
	}
	found, exact, err := darwinAddressState(link, prefix)
	if err != nil {
		return fmt.Errorf("agent: recovery address lookup %s: %w", prefix, err)
	}
	switch {
	case !found:
		report.keep("address " + prefix.String())
	case !exact:
		report.degrade(entry.Kind+" "+entry.Detail,
			fmt.Sprintf("address %s is present with a different or unprovable prefix; the external address is kept", prefix.Addr()))
	default:
		if err := deleteIPv4Address(prefix, link.Index); err != nil {
			if errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.ENOENT) {
				report.keep("address " + prefix.String())
				return nil
			}
			return fmt.Errorf("agent: recovery remove %s from %q: %w", prefix, link.Name, err)
		}
		report.remove("address " + prefix.String())
	}
	return nil
}

// recoverDarwinMTU restores the prior MTU only while the interface still holds
// the value this transaction set.
func recoverDarwinMTU(report *RecoveryReport, entry JournalEntry, interfaceName string) error {
	appliedMTU, priorMTU, ok := parseMTUFingerprint(strings.TrimPrefix(entry.Detail, "mtu="), entry.Fingerprint)
	if !ok {
		report.degrade(entry.Kind, fmt.Sprintf("MTU entry %q/%q is not parseable", entry.Detail, entry.Fingerprint))
		return nil
	}
	current, err := getInterfaceMTU(interfaceName)
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
