//go:build darwin

package agent

// macOS SystemNetwork: the real host network transaction owner.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// It applies, in order, the interface MTU, the local IPv4 /32 address, the
// interface up flag and the optional IPv4 routes, and reverses exactly what it
// applied, in reverse order. Every side effect is preceded by a durable
// write-ahead intent and followed by an explicit outcome record (see
// sysnet_journal.go). Rollback verifies its own fingerprint before undoing a
// resource: an MTU, address or route changed or moved by someone else is kept,
// and the transaction reports Degraded instead of overwriting external
// configuration. It never touches the default route, DNS or the firewall, and
// it never shells out.
//
// Apply re-reads the MTU and the link flags immediately before it changes them.
// An external value that no longer matches the Prepare snapshot is kept: this
// transaction only restores the state it actually observed.
//
// Open (device_darwin.go) performs no OS network mutation. The utun interface is
// created by the PF_SYSTEM connect and the kernel assigns its utunN name, so the
// prior MTU is still observable here and can be restored on rollback even when
// the transaction only sets the MTU. The Agent reads the kernel-assigned name
// from DeviceInfo and hands it to this transaction.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"golang.org/x/sys/unix"
)

// darwinLinkSnapshot is the pre-Apply state of the utun interface. Prepare
// records it without touching the OS.
type darwinLinkSnapshot struct {
	Index      int
	MTU        int
	Up         bool
	HadAddress bool
	Address    netip.Prefix
	// HadRoutes lists the requested routes that were already installed before
	// Apply. They are never journaled, never re-added and never rolled back:
	// the transaction owns only what it created.
	HadRoutes []netip.Prefix
}

// hasRoute reports whether prefix was already installed before Apply.
func (s darwinLinkSnapshot) hasRoute(prefix netip.Prefix) bool {
	for _, existing := range s.HadRoutes {
		if existing == prefix {
			return true
		}
	}
	return false
}

// darwinAppliedResources records exactly what this transaction created, so
// rollback only removes owned resources.
type darwinAppliedResources struct {
	MTU     bool
	Address bool
	LinkUp  bool
	Routes  []netip.Prefix
}

// darwinSystemNetwork is the macOS SystemNetwork implementation for one utun
// interface: MTU, one local /32 address and optional IPv4 routes.
type darwinSystemNetwork struct {
	// systemNetworkState is the shared transaction state machine: the state,
	// the degraded record, the journal and the one mutex. It is embedded by
	// value so the shared fields stay reachable as n.opts, n.journal and
	// n.mu, exactly as before the extraction.
	systemNetworkState

	// owner runs the shared transaction state machine. The platform's own
	// hooks below are reached only through it.
	owner systemNetworkOwner

	linkIndex int
	linkName  string
	// instance is the interface-instance fingerprint recorded with every
	// journal record: a reused utunN index is a different interface instance.
	instance string

	// snapshot records what existed before Apply so rollback restores it.
	snapshot darwinLinkSnapshot

	applied darwinAppliedResources
}

// newSystemNetwork implements the per-GOOS dispatch declared by
// NewSystemNetwork.
func newSystemNetwork(platform Platform, opts SystemNetworkOptions) (SystemNetwork, error) {
	if platform != PlatformDarwin {
		return nil, fmt.Errorf("%w: the %s host network owner needs a %s build", ErrNetworkConfigUnavailable, platform, platform)
	}
	return newDarwinSystemNetwork(opts)
}

func newDarwinSystemNetwork(opts SystemNetworkOptions) (*darwinSystemNetwork, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	journal, err := newResourceJournal(opts.JournalPath)
	if err != nil {
		return nil, err
	}
	network := &darwinSystemNetwork{
		systemNetworkState: systemNetworkState{
			opts:    opts,
			mtu:     opts.mtu(),
			current: SystemNetworkAbsent,
			journal: journal,
		},
	}
	network.owner = newSystemNetworkOwner(&network.systemNetworkState, network)
	return network, nil
}

// State implements SystemNetwork.

// Prepare resolves the interface and snapshots the resources this transaction
// intends to own: the prior MTU, the link state, whether the address is already
// present and whether each route is already installed. It performs no OS
// mutation.

// prepareLocked implements Prepare. The caller holds n.mu; RetargetAddress calls
// it directly so a retarget is one atomic transition under the owner mutex.
func (n *darwinSystemNetwork) prepareLocked(ctx context.Context, s *systemNetworkState) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	if s.current != SystemNetworkAbsent {
		return fmt.Errorf("%w: Prepare requires the absent state, got %s", ErrInvalidConfig, s.current)
	}
	link, err := net.InterfaceByName(s.opts.Interface)
	if err != nil {
		return fmt.Errorf("%w: interface %q: %v; open the PacketDevice before preparing its network configuration", ErrPlatformUnavailable, s.opts.Interface, err)
	}
	mtu, err := getInterfaceMTU(link.Name)
	if err != nil {
		return fmt.Errorf("%w: read the prior MTU of %q: %v; the process needs access to the utun socket", ErrPlatformUnavailable, link.Name, err)
	}
	flags, err := getInterfaceFlags(link.Name)
	if err != nil {
		return fmt.Errorf("%w: read the flags of %q: %v", ErrPlatformUnavailable, link.Name, err)
	}
	n.linkIndex = link.Index
	n.linkName = link.Name
	n.instance = darwinInterfaceInstance(link.Index)
	s.journal.setResourceID(n.instance)
	n.snapshot = darwinLinkSnapshot{
		Index: link.Index,
		MTU:   mtu,
		Up:    flags&unix.IFF_UP != 0,
	}
	if s.opts.Address.IsValid() {
		if err := n.journalIntent("prepare", "address", s.opts.Address.String(), ""); err != nil {
			return err
		}
		present, _, err := darwinAddressState(link, s.opts.Address)
		if err != nil {
			return fmt.Errorf("agent: read addresses of %q: %w", link.Name, err)
		}
		if present {
			n.snapshot.HadAddress = true
			n.snapshot.Address = s.opts.Address
		}
	}
	for _, route := range s.opts.Routes {
		if err := n.journalIntent("prepare", "route", route.String(), ""); err != nil {
			return err
		}
		present, _, err := routePresent(ctx, route, link.Index)
		if err != nil {
			return fmt.Errorf("%w: inspect route %s on %q: %v", ErrPlatformUnavailable, route, link.Name, err)
		}
		if present {
			n.snapshot.HadRoutes = append(n.snapshot.HadRoutes, route.Masked())
		}
	}
	s.current = SystemNetworkPrepared
	return nil
}

// Apply installs the MTU, address, link-up and routes in order, journaling each
// intent first and its outcome after. A failure leaves the already-applied
// resources in place for Rollback to reverse; callers must Rollback (the Agent
// does).

// applyLocked implements Apply. The caller holds n.mu; RetargetAddress calls
// it directly so a retarget is one atomic transition under the owner mutex.
func (n *darwinSystemNetwork) applyLocked(ctx context.Context, s *systemNetworkState) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	if s.current != SystemNetworkPrepared {
		return fmt.Errorf("%w: Apply requires the prepared state, got %s", ErrInvalidConfig, s.current)
	}
	s.current = SystemNetworkApplied
	if err := n.applyMTU(ctx); err != nil {
		return err
	}
	if s.opts.Address.IsValid() && !n.snapshot.HadAddress {
		if err := n.applyAddress(ctx); err != nil {
			return err
		}
	}
	if err := n.applyLinkUp(ctx); err != nil {
		return err
	}
	for _, route := range s.opts.Routes {
		if err := n.applyRoute(ctx, route); err != nil {
			return err
		}
	}
	return nil
}

// applyMTU re-reads the live MTU immediately before changing it and keeps an
// external value that no longer matches the Prepare snapshot.
func (n *darwinSystemNetwork) applyMTU(ctx context.Context) error {
	if n.snapshot.MTU == n.mtu {
		return nil
	}
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	current, err := getInterfaceMTU(n.linkName)
	if err != nil {
		return fmt.Errorf("%w: read MTU of %q before Apply: %v", ErrPlatformUnavailable, n.linkName, err)
	}
	if current != n.snapshot.MTU {
		n.markDegraded("mtu", fmt.Sprintf("MTU changed from the prepared %d to %d before Apply; the external value is kept", n.snapshot.MTU, current))
		return fmt.Errorf("%w: MTU of %q changed from %d to %d between Prepare and Apply; the external value is kept", ErrPlatformUnavailable, n.linkName, n.snapshot.MTU, current)
	}
	// The fingerprint carries both values so a crash-recovery run can prove the
	// interface still holds the value this transaction set before restoring the
	// prior one.
	if err := n.journalIntent("apply", "mtu", fmt.Sprintf("mtu=%d", n.mtu), fmt.Sprintf("prior=%d", n.snapshot.MTU)); err != nil {
		return err
	}
	if err := setInterfaceMTU(n.linkName, n.mtu); err != nil {
		return fmt.Errorf("%w: set MTU %d on %q: %w; the process needs root or the network entitlement", ErrPlatformUnavailable, n.mtu, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "mtu", fmt.Sprintf("mtu=%d", n.mtu), fmt.Sprintf("prior=%d", n.snapshot.MTU), journalOutcomeConfirmed); err != nil {
		return err
	}
	n.applied.MTU = true
	return nil
}

// applyAddress adds the local address. A concurrently created identical address
// makes the exclusive add fail with EEXIST: it is someone else's, so the intent
// is closed as not_owned.
func (n *darwinSystemNetwork) applyAddress(ctx context.Context) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	fingerprint := n.owner.addressFingerprint()
	if err := n.journalIntent("apply", "address", n.opts.Address.String(), fingerprint); err != nil {
		return err
	}
	if err := addIPv4Address(n.opts.Address, n.linkIndex); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return n.journalConfirm("apply", "address", n.opts.Address.String(), fingerprint, journalOutcomeNotOwned)
		}
		return fmt.Errorf("%w: assign %s to %q: %w; the process needs root or the network entitlement", ErrPlatformUnavailable, n.opts.Address, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "address", n.opts.Address.String(), fingerprint, journalOutcomeConfirmed); err != nil {
		return err
	}
	n.applied.Address = true
	return nil
}

// applyLinkUp brings the interface up, but only when it is still down. An
// external actor that brought it up between Prepare and Apply owns that state.
func (n *darwinSystemNetwork) applyLinkUp(ctx context.Context) error {
	if n.snapshot.Up {
		return nil
	}
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	flags, err := getInterfaceFlags(n.linkName)
	if err != nil {
		return fmt.Errorf("%w: read flags of %q before Apply: %v", ErrPlatformUnavailable, n.linkName, err)
	}
	if flags&unix.IFF_UP != 0 {
		n.markDegraded("link_up", fmt.Sprintf("%q was brought up by someone else between Prepare and Apply; the external link state is kept", n.linkName))
		return nil
	}
	if err := n.journalIntent("apply", "link_up", n.linkName, "was down"); err != nil {
		return err
	}
	if err := setLinkUp(n.linkName, true); err != nil {
		return fmt.Errorf("%w: bring %q up: %w; the process needs root or the network entitlement", ErrPlatformUnavailable, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "link_up", n.linkName, "was down", journalOutcomeConfirmed); err != nil {
		return err
	}
	n.applied.LinkUp = true
	return nil
}

// applyRoute installs one route. A route that was already installed at Prepare
// time, or that appears before this call, is not owned by this transaction: it
// is closed as not_owned, neither recorded nor rolled back, so recovery can
// never remove it.
func (n *darwinSystemNetwork) applyRoute(ctx context.Context, route netip.Prefix) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	route = route.Masked()
	if n.snapshot.hasRoute(route) {
		return nil
	}
	if present, _, err := routePresent(ctx, route, n.linkIndex); err == nil && present {
		return nil
	}
	fingerprint := darwinRouteFingerprint(route, n.instance)
	if err := n.journalIntent("apply", "route", route.String(), fingerprint); err != nil {
		return err
	}
	if err := addRoute(ctx, route, n.linkIndex); err != nil {
		if errors.Is(err, unix.EEXIST) {
			// The route appeared between the check and the add. It is someone
			// else's, so it is not recorded as owned.
			return n.journalConfirm("apply", "route", route.String(), fingerprint, journalOutcomeNotOwned)
		}
		return fmt.Errorf("%w: install route %s on %q: %w; the process needs root or the network entitlement", ErrPlatformUnavailable, route, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "route", route.String(), fingerprint, journalOutcomeConfirmed); err != nil {
		return err
	}
	n.applied.Routes = append(n.applied.Routes, route)
	return nil
}

// Rollback reverses the applied resources in reverse order, verifying the
// fingerprint recorded for each one. A resource that no longer matches, that
// disappeared or that now belongs to another interface is left alone and the
// transaction becomes Degraded. It finishes with a terminal checkpoint so a
// later recovery run ignores the whole transaction.

// rollbackLocked implements Rollback. The caller holds n.mu; RetargetAddress calls
// it directly so a retarget is one atomic transition under the owner mutex.
func (n *darwinSystemNetwork) rollbackLocked(ctx context.Context, s *systemNetworkState) error {
	if s.current == SystemNetworkAbsent || s.current == SystemNetworkClosed {
		return nil
	}
	if err := packetDeviceContextErr(ctx); err != nil {
		// Cleanup must still run when the caller's context is already done.
		ctx = context.Background()
	}
	var errs []error
	for index := len(n.applied.Routes) - 1; index >= 0; index-- {
		route := n.applied.Routes[index]
		state, err := darwinRouteState(ctx, route)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent: inspect route %s on %q: %w", route, n.linkName, err))
			continue
		}
		if !state.Present {
			continue
		}
		if state.InterfaceIndex != n.linkIndex {
			n.markDegraded("route "+route.String(),
				fmt.Sprintf("route %s is now on interface index %d, not %q; the external route is kept", route, state.InterfaceIndex, n.linkName))
			continue
		}
		fingerprint := darwinRouteFingerprint(route, n.instance)
		if err := n.journalIntent("rollback", "route", route.String(), fingerprint); err != nil {
			errs = append(errs, err)
		}
		if err := deleteRoute(ctx, route, n.linkIndex); err != nil {
			if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
				continue // it disappeared between the proof and the delete
			}
			errs = append(errs, fmt.Errorf("agent: remove route %s from %q: %w", route, n.linkName, err))
			continue
		}
		if err := n.journalConfirm("rolledback", "route", route.String(), fingerprint, journalOutcomeConfirmed); err != nil {
			errs = append(errs, err)
		}
	}
	n.applied.Routes = nil
	if n.applied.LinkUp && !n.snapshot.Up {
		flags, err := getInterfaceFlags(n.linkName)
		switch {
		case err != nil:
			n.markDegraded("link_up", fmt.Sprintf("flags of %q could not be read before rollback: %v; the link state is kept", n.linkName, err))
		case flags&unix.IFF_UP != 0:
			if err := n.journalIntent("rollback", "link_up", n.linkName, "was down"); err != nil {
				errs = append(errs, err)
			}
			if err := setLinkUp(n.linkName, false); err != nil {
				errs = append(errs, fmt.Errorf("agent: bring %q down: %w", n.linkName, err))
			} else if err := n.journalConfirm("rolledback", "link_up", n.linkName, "was down", journalOutcomeConfirmed); err != nil {
				errs = append(errs, err)
			}
		}
	}
	n.applied.LinkUp = false
	if n.applied.Address {
		link, err := net.InterfaceByName(n.linkName)
		switch {
		case err != nil:
			n.markDegraded("address", fmt.Sprintf("interface %q disappeared before rollback: %v", n.linkName, err))
		default:
			found, exact, err := darwinAddressState(link, s.opts.Address)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("agent: verify %s on %q: %w", s.opts.Address, n.linkName, err))
			case found && !exact:
				n.markDegraded("address "+s.opts.Address.String(),
					fmt.Sprintf("address %s is now present with a different prefix; the external address is kept", s.opts.Address.Addr()))
			case found:
				if err := n.journalIntent("rollback", "address", s.opts.Address.String(), n.owner.addressFingerprint()); err != nil {
					errs = append(errs, err)
				}
				if err := deleteIPv4Address(s.opts.Address, n.linkIndex); err != nil {
					if !errors.Is(err, unix.EADDRNOTAVAIL) {
						errs = append(errs, fmt.Errorf("agent: remove %s from %q: %w", s.opts.Address, n.linkName, err))
						break
					}
				}
				if err := n.journalConfirm("rolledback", "address", s.opts.Address.String(), n.owner.addressFingerprint(), journalOutcomeConfirmed); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	n.applied.Address = false
	if n.applied.MTU {
		current, err := getInterfaceMTU(n.linkName)
		switch {
		case err != nil:
			n.markDegraded("mtu", fmt.Sprintf("MTU of %q could not be read before rollback: %v; the external value is kept", n.linkName, err))
		case current != s.mtu:
			n.markDegraded("mtu", fmt.Sprintf("MTU is now %d, not the %d this transaction set; the external value is kept", current, s.mtu))
		default:
			if err := n.journalIntent("rollback", "mtu", fmt.Sprintf("mtu=%d", s.mtu), fmt.Sprintf("prior=%d", n.snapshot.MTU)); err != nil {
				errs = append(errs, err)
			}
			if err := setInterfaceMTU(n.linkName, n.snapshot.MTU); err != nil {
				errs = append(errs, fmt.Errorf("agent: restore MTU %d on %q: %w", n.snapshot.MTU, n.linkName, err))
			} else if err := n.journalConfirm("rolledback", "mtu", fmt.Sprintf("mtu=%d", s.mtu), fmt.Sprintf("prior=%d", n.snapshot.MTU), journalOutcomeConfirmed); err != nil {
				errs = append(errs, err)
			}
		}
	}
	n.applied.MTU = false
	if s.degraded {
		s.current = SystemNetworkDegraded
	} else {
		s.current = SystemNetworkRollback
	}
	if err := n.journalTerminal(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// addressFingerprint is the recorded identity of the local address.

// DegradedDetail reports the external modifications rollback refused to
// overwrite. It is empty when rollback fully owned its resources.

// Close rolls back if needed and releases the journal. It is idempotent.

// journalIntent records one write-ahead intent before an OS side effect. A
// journal write failure aborts the side effect, because the port contract
// requires intent-before-effect.

// journalConfirm records the durable outcome of an intent that already ran.

// journalTerminal closes the transaction durably.

// Journal returns a copy of the in-memory write-ahead journal.

// darwinInterfaceInstance is the interface-instance fingerprint recorded in the
// journal.
func darwinInterfaceInstance(index int) string {
	return encodeJournalFields([2]string{"index", strconv.Itoa(index)})
}

// darwinRouteFingerprint is the recorded identity of one interface route.
func darwinRouteFingerprint(route netip.Prefix, instance string) string {
	return encodeJournalFields(
		[2]string{"dst", route.Masked().String()},
		[2]string{"instance", instance},
	)
}

// darwinAddressState classifies one local prefix against the interface's
// address list: present (the address exists) and exact (the prefix length
// matches too). Because net.Interface reports a masked prefix, only a /32 is
// treated as exactly provable; a longer prefix with the same address is kept.
func darwinAddressState(link *net.Interface, want netip.Prefix) (present bool, exact bool, err error) {
	if link == nil {
		return false, false, errors.New("nil interface")
	}
	for _, existing := range mustAddrs(link) {
		if existing.Addr() != want.Addr() {
			continue
		}
		present = true
		if existing == want && want.Bits() == 32 {
			exact = true
		}
	}
	return present, exact, nil
}

// RetargetAddress moves this transaction's local VirtualIP to a new IPv4 /32 on
// the same device, without reopening it. It is the single-owner retarget: before
// anything is released it proves by live kernel reads that the old transaction
// still owns every resource it applied (preflightAppliedOwnership); only then
// does it roll the old transaction back with its own fingerprint proof and a
// terminal checkpoint, start a fresh transaction id on the same open journal
// (same file, same exclusive lock) and Prepare/Apply the new address.
//
// An external value the old transaction cannot prove as its own stops the
// retarget BEFORE the first side effect, with Degraded and
// ErrPlatformUnavailable. That ordering is the design parity the Linux owner
// fixed for a concrete kernel side effect: releasing this transaction's own /32
// first lets the kernel drop device routes an external actor had replaced as
// collateral, so a retarget that rolled back first could not keep the external
// route it claims to keep. The window between this proof and the later delete is
// the same bounded race rollback carries; it is not closed by an OS
// compare-and-swap.
//
// Close is the separate per-resource cleanup path: on teardown it may still
// release this transaction's owned link/address and let the kernel flush routes,
// keeping the per-resource fingerprint proof. Only the retarget preflight
// failure is guaranteed to have zero kernel effects.
//
// The native calls are unverified on this platform: this is a compile-and-design
// parity path, not host acceptance.

// darwinRouteOwnershipProof classifies one live route observation against the
// identity of a route this transaction installed. The native PF_ROUTE query
// exposes the exact prefix, the interface index and, when the kernel reports an
// IPv4 one, a gateway: it does not expose the route metric or the protocol.
// A matching prefix, interface index and absent gateway are therefore NOT proof
// of ownership, because an external actor can change only the metric or the
// protocol and leave every field this query observes unchanged. The predicate
// reports why a route cannot be accepted and never returns proven for the
// observations this query can produce; until a full-tuple proof is available the
// caller fails closed with Degraded before any mutation instead of guessing.
func darwinRouteOwnershipProof(state darwinRouteInfo, linkIndex int) (proven bool, reason string) {
	switch {
	case !state.Present:
		return false, "is no longer present"
	case state.InterfaceIndex != linkIndex:
		return false, fmt.Sprintf("is now on interface index %d", state.InterfaceIndex)
	case state.Gateway.IsValid() && !state.Gateway.IsUnspecified():
		return false, fmt.Sprintf("now carries gateway %s", state.Gateway)
	}
	return false, "cannot prove the route metric or protocol from a PF_ROUTE reply"
}

// preflightAppliedOwnership proves, by live kernel reads, that this transaction
// still owns every resource it applied, before RetargetAddress releases
// anything. Ownership is the exact full tuple where the platform can prove it:
// the interface still carries this transaction's recorded index, an owned MTU
// still holds the value this transaction set, an owned address is still present
// at its exact /32 and a link this transaction brought up is still up. An owned
// route is never accepted: the PF_ROUTE reply exposes neither the metric nor the
// protocol, so darwinRouteOwnershipProof reports it unproven and the retarget
// stops with Degraded before any mutation. Creating and applying resources is
// unaffected; only the retarget safety preflight is this strict.
//
// The interface index is the instance proof every other resource hangs on. It is
// the identity this transaction actually recorded, not a stronger unique hash: a
// reused utunN index is treated as the same instance.
//
// The first divergence or unreadable resource marks the transaction Degraded and
// returns ErrPlatformUnavailable with no kernel mutation, no journal record and
// no new transaction. It never removes the address, changes the link, restores
// the MTU or deletes a route: those belong to Rollback/Close, and doing them
// here would let the kernel flush an externally replaced route as collateral.
// The caller holds n.mu.
func (n *darwinSystemNetwork) preflightAppliedOwnership(ctx context.Context, s *systemNetworkState) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	link, err := net.InterfaceByName(n.linkName)
	switch {
	case err != nil:
		return n.preflightDegraded("instance", fmt.Sprintf("interface %q could not be resolved before retarget: %v; nothing was released and the new address was not applied", n.linkName, err))
	case link.Index != n.linkIndex:
		return n.preflightDegraded("instance", fmt.Sprintf("interface %q now has index %d, not this transaction's %d; the external interface is kept and nothing was released", n.linkName, link.Index, n.linkIndex))
	}
	if n.applied.MTU {
		live, err := getInterfaceMTU(n.linkName)
		switch {
		case err != nil:
			return n.preflightDegraded("mtu", fmt.Sprintf("MTU of %q could not be read before retarget: %v; nothing was released and the new address was not applied", n.linkName, err))
		case live != s.mtu:
			return n.preflightDegraded("mtu", fmt.Sprintf("MTU is now %d, not the %d this transaction set; the external value is kept and nothing was released", live, s.mtu))
		}
	}
	if n.applied.Address {
		found, exact, err := darwinAddressState(link, s.opts.Address)
		switch {
		case err != nil:
			return n.preflightDegraded("address "+s.opts.Address.String(), fmt.Sprintf("address %s on %q could not be read before retarget: %v; nothing was released and the new address was not applied", s.opts.Address, n.linkName, err))
		case !found:
			return n.preflightDegraded("address "+s.opts.Address.String(), fmt.Sprintf("address %s is no longer present on %q; nothing was released and the new address was not applied", s.opts.Address, n.linkName))
		case !exact:
			return n.preflightDegraded("address "+s.opts.Address.String(), fmt.Sprintf("address %s is now present with a different or unprovable prefix; the external address is kept and nothing was released", s.opts.Address.Addr()))
		}
	}
	for _, route := range n.applied.Routes {
		state, err := darwinRouteState(ctx, route)
		if err != nil {
			return n.preflightDegraded("route "+route.String(), fmt.Sprintf("route %s on %q could not be read before retarget: %v; nothing was released and the new address was not applied", route, n.linkName, err))
		}
		proven, reason := darwinRouteOwnershipProof(state, n.linkIndex)
		if !proven {
			return n.preflightDegraded("route "+route.String(), fmt.Sprintf("route %s recorded as %s %s; the external route is kept and nothing was released", route, darwinRouteFingerprint(route, n.instance), reason))
		}
	}
	if n.applied.LinkUp {
		flags, err := getInterfaceFlags(n.linkName)
		switch {
		case err != nil:
			return n.preflightDegraded("link_up", fmt.Sprintf("flags of %q could not be read before retarget: %v; nothing was released and the new address was not applied", n.linkName, err))
		case flags&unix.IFF_UP == 0:
			return n.preflightDegraded("link_up", fmt.Sprintf("%q is now down, not the up state this transaction brought it to; the external link state is kept and nothing was released", n.linkName))
		}
	}
	return nil
}

// preflightDegraded records the divergence and returns the fail-closed error.
// markDegraded only appends to the in-memory detail list, so this performs no
// kernel mutation and writes no journal record.

// retargetFailedLocked releases whatever the failed new transaction owns and
// best-effort restores the ORIGINAL address (never the failed new one) in
// another fresh transaction. If it cannot be restored safely the error is
// returned so the caller can fail closed.

// resetTransactionLocked clears the per-transaction state before a fresh
// Prepare. The journal file and its lock stay open; only the transaction id and
// instance fingerprint are renewed.
func (n *darwinSystemNetwork) resetTransactionLocked(s *systemNetworkState) {
	s.current = SystemNetworkAbsent
	n.snapshot = darwinLinkSnapshot{}
	n.applied = darwinAppliedResources{}
	s.degraded = false
	s.degradedDetail = nil
	n.instance = ""
}

var _ SystemNetwork = (*darwinSystemNetwork)(nil)

// --- shared transaction state machine ---------------------------------------

// State implements SystemNetwork.
func (n *darwinSystemNetwork) State() SystemNetworkState { return n.owner.State() }

// Prepare implements SystemNetwork.
func (n *darwinSystemNetwork) Prepare(ctx context.Context) error { return n.owner.Prepare(ctx) }

// Apply implements SystemNetwork.
func (n *darwinSystemNetwork) Apply(ctx context.Context) error { return n.owner.Apply(ctx) }

// Rollback implements SystemNetwork.
func (n *darwinSystemNetwork) Rollback(ctx context.Context) error { return n.owner.Rollback(ctx) }

// Close implements SystemNetwork.
func (n *darwinSystemNetwork) Close() error { return n.owner.Close() }

// DegradedDetail reports the external modifications rollback refused to
// overwrite. It is empty when rollback fully owned its resources.
func (n *darwinSystemNetwork) DegradedDetail() []string { return n.owner.DegradedDetail() }

// Journal returns the in-memory view of this owner's write-ahead records.
func (n *darwinSystemNetwork) Journal() []journalEntry { return n.owner.Journal() }

// RetargetAddress moves the local IPv4 /32 VirtualIP to a new /32 on the same
// device, without reopening it.
func (n *darwinSystemNetwork) RetargetAddress(ctx context.Context, address netip.Prefix) error {
	return n.owner.RetargetAddress(ctx, address)
}

// journalIntent records one write-ahead intent before an OS side effect.
func (n *darwinSystemNetwork) journalIntent(kind, resource, detail, fingerprint string) error {
	return n.owner.journalIntent(kind, resource, detail, fingerprint)
}

// journalConfirm records the durable outcome of an intent that already ran.
func (n *darwinSystemNetwork) journalConfirm(kind, resource, detail, fingerprint, outcome string) error {
	return n.owner.journalConfirm(kind, resource, detail, fingerprint, outcome)
}

// journalTerminal records the terminal checkpoint of this transaction.
func (n *darwinSystemNetwork) journalTerminal() error { return n.owner.journalTerminal() }

// markDegraded records that the transaction could not be fully proven.
func (n *darwinSystemNetwork) markDegraded(kind, detail string) { n.owner.markDegraded(kind, detail) }

// preflightDegraded records the degraded reason and fails closed.
func (n *darwinSystemNetwork) preflightDegraded(kind, detail string) error {
	return n.owner.preflightDegraded(kind, detail)
}

// retargetFailedLocked releases whatever the failed new transaction owned.
func (n *darwinSystemNetwork) retargetFailedLocked(ctx context.Context, previous netip.Prefix, cause error) error {
	return n.owner.retargetFailedLocked(ctx, previous, cause)
}

// --- platform hooks --------------------------------------------------------

// journalInterfaceName is the interface the journal records are stamped with.
func (n *darwinSystemNetwork) journalInterfaceName(s *systemNetworkState) string {
	return n.linkName
}

// platformAddressFingerprint is this platform's ownership fingerprint for the
// configured address.
func (n *darwinSystemNetwork) platformAddressFingerprint(s *systemNetworkState) string {
	return encodeJournalFields(
		[2]string{"addr", s.opts.Address.Addr().String()},
		[2]string{"prefixlen", strconv.Itoa(s.opts.Address.Bits())},
	)
}
