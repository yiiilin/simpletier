//go:build windows

package agent

// Windows SystemNetwork: the real host network transaction owner.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// It applies, in order, the IPv4 interface MTU (the frozen DefaultDeviceMTU),
// the local IPv4 /32 VirtualIP and the optional routes, and reverses exactly
// what it applied, in reverse order. Every side effect is preceded by a durable
// write-ahead intent and followed by an explicit outcome record (see
// sysnet_journal.go), so a crashed process leaves a journal from which a later
// run can prove what this transaction really created. With JournalPath set the
// records are persisted as JSON lines; without it they stay in memory for the
// lifetime of the transaction.
//
// The transaction stamps the adapter LUID and interface index on every record.
// Rollback and recovery verify their own fingerprint before undoing a resource:
// an MTU, address or route with different attributes is kept and the transaction
// reports Degraded instead of overwriting external configuration. A resource
// that existed before Prepare, or that appeared concurrently (EEXIST /
// ERROR_OBJECT_ALREADY_EXISTS), is closed as not_owned so recovery can never
// delete it. The owner never touches the default route, DNS, the firewall or the
// Wintun driver.
//
// Apply re-reads the MTU immediately before changing it; if an external actor
// moved it after Prepare, Apply aborts that step and keeps the external value.
// A concurrent change in the nanosecond after the re-read remains an honest race
// this code does not claim to solve atomically.
//
// Every native call lives in iphelper_windows.go; this file owns the state
// machine and goes through windowsIPHelperOps, so the journal ordering, the
// payload and the state machine can be exercised on a Windows host without
// mutating a live adapter (see sysnet_windows_test.go). Runtime behaviour
// against a real adapter cannot be verified from this repository's Linux host;
// that is a cross-compile and design check, not platform acceptance.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"golang.org/x/sys/windows"
)

// windowsRouteResult is the outcome of looking one canonical route up on the
// adapter. Exact means the whole tuple matches (on-link gateway, zero metric,
// NETMGMT protocol, same adapter and interface index).
type windowsRouteResult struct {
	Found bool
	Exact bool
}

// windowsIPHelperOps is the seam over the native IP Helper calls. The zero value
// is not usable; every field must be set (nativeWindowsIPHelperOps or a test
// double).
type windowsIPHelperOps struct {
	interfaceLUID    func(alias string) (uint64, error)
	interfaceIndex   func(luid uint64) (uint32, error)
	interfaceMTU     func(luid uint64) (int, error)
	setInterfaceMTU  func(luid uint64, mtu int) error
	interfaceAddress func(luid uint64, address netip.Addr) (netip.Prefix, bool, error)
	createIPv4Addr   func(luid uint64, index uint32, prefix netip.Prefix) error
	deleteIPv4Addr   func(luid uint64, index uint32, address netip.Addr) error
	addressPresent   func(luid uint64, address netip.Addr) (bool, error)
	createIPv4Route  func(luid uint64, index uint32, prefix netip.Prefix) error
	deleteIPv4Route  func(luid uint64, index uint32, prefix netip.Prefix) error
	routeState       func(luid uint64, index uint32, prefix netip.Prefix) (windowsRouteResult, error)
}

// nativeWindowsIPHelperOps binds the seam to the real iphlpapi.dll bindings.
func nativeWindowsIPHelperOps() *windowsIPHelperOps {
	return &windowsIPHelperOps{
		interfaceLUID:    interfaceLUID,
		interfaceIndex:   interfaceIndex,
		interfaceMTU:     interfaceMTU,
		setInterfaceMTU:  setInterfaceMTU,
		interfaceAddress: interfaceIPv4Prefix,
		createIPv4Addr:   createIPv4Address,
		deleteIPv4Addr:   deleteIPv4Address,
		addressPresent:   addressPresent,
		createIPv4Route:  createIPv4Route,
		deleteIPv4Route:  deleteIPv4Route,
		routeState:       routeState,
	}
}

// windowsNetworkSnapshot is the pre-Apply state of the adapter.
type windowsNetworkSnapshot struct {
	Name string
	LUID uint64
	// Index is the interface index; SetIpInterfaceEntry/address rows carry both
	// LUID and index.
	Index uint32
	// MTU is the IPv4 MTU observed before Apply, restored by Rollback.
	MTU int
	// HadAddress reports that the adapter already carried the requested
	// VirtualIP, in which case Apply adds nothing and Rollback deletes nothing.
	HadAddress bool
	// Address is the address actually present before Apply.
	Address netip.Prefix
	// HadRoutes marks the configured routes that already existed before Apply.
	HadRoutes map[netip.Prefix]bool
}

// windowsAppliedResources records exactly what this transaction created so
// Rollback and recovery remove only owned resources.
type windowsAppliedResources struct {
	MTU     bool
	Address bool
	Routes  []netip.Prefix
}

// windowsSystemNetwork is the Windows SystemNetwork implementation for one
// Wintun adapter: IPv4 MTU, one local /32 address and optional IPv4 routes.
type windowsSystemNetwork struct {
	// systemNetworkState is the shared transaction state machine: the state,
	// the degraded record, the journal and the one mutex. It is embedded by
	// value so the shared fields stay reachable as n.opts, n.journal and
	// n.mu, exactly as before the extraction.
	systemNetworkState

	// owner runs the shared transaction state machine. The platform's own
	// hooks below are reached only through it.
	owner systemNetworkOwner

	ops *windowsIPHelperOps

	linkName string
	luid     uint64
	index    uint32
	// instance is the adapter-instance fingerprint recorded with every journal
	// record: the same alias with another LUID is a different adapter.
	instance string

	snapshot windowsNetworkSnapshot
	applied  windowsAppliedResources
}

// newSystemNetwork implements the per-GOOS dispatch declared by
// NewSystemNetwork. Only the actual windows build owns a Windows host network
// transaction; every other platform value is a foreign build and says so.
func newSystemNetwork(platform Platform, opts SystemNetworkOptions) (SystemNetwork, error) {
	if platform != PlatformWindows {
		return nil, fmt.Errorf("%w: the %s host network owner needs a %s build", ErrNetworkConfigUnavailable, platform, platform)
	}
	return newWindowsSystemNetwork(opts)
}

func newWindowsSystemNetwork(opts SystemNetworkOptions) (*windowsSystemNetwork, error) {
	return newWindowsSystemNetworkWithOps(opts, nativeWindowsIPHelperOps())
}

func newWindowsSystemNetworkWithOps(opts SystemNetworkOptions, ops *windowsIPHelperOps) (*windowsSystemNetwork, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if ops == nil {
		return nil, fmt.Errorf("%w: the Windows host network owner needs its IP Helper bindings", ErrPlatformUnavailable)
	}
	journal, err := newResourceJournal(opts.JournalPath)
	if err != nil {
		return nil, err
	}
	network := &windowsSystemNetwork{
		systemNetworkState: systemNetworkState{
			opts:    opts,
			mtu:     opts.mtu(),
			current: SystemNetworkAbsent,
			journal: journal,
		},
		ops: ops,
	}
	network.owner = newSystemNetworkOwner(&network.systemNetworkState, network)
	return network, nil
}

// State implements SystemNetwork.

// Prepare resolves the adapter LUID and snapshots the resources this
// transaction intends to own. It performs no OS mutation.

// prepareLocked implements Prepare. The caller holds n.mu; RetargetAddress calls
// it directly so a retarget is one atomic transition under the owner mutex.
func (n *windowsSystemNetwork) prepareLocked(ctx context.Context, s *systemNetworkState) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	if s.current != SystemNetworkAbsent {
		return fmt.Errorf("%w: Prepare requires the absent state, got %s", ErrInvalidConfig, s.current)
	}
	luid, err := n.ops.interfaceLUID(s.opts.Interface)
	if err != nil {
		return fmt.Errorf("%w: adapter %q: %v; open the PacketDevice before preparing its network configuration", ErrPlatformUnavailable, s.opts.Interface, err)
	}
	index, err := n.ops.interfaceIndex(luid)
	if err != nil {
		return fmt.Errorf("%w: adapter %q interface index: %v", ErrPlatformUnavailable, s.opts.Interface, err)
	}
	priorMTU, err := n.ops.interfaceMTU(luid)
	if err != nil {
		return fmt.Errorf("%w: read MTU of %q: %v", ErrPlatformUnavailable, s.opts.Interface, err)
	}
	n.linkName = s.opts.Interface
	n.luid = luid
	n.index = index
	n.instance = windowsInterfaceInstance(luid, index)
	s.journal.setResourceID(n.instance)
	n.snapshot = windowsNetworkSnapshot{
		Name:      s.opts.Interface,
		LUID:      luid,
		Index:     index,
		MTU:       priorMTU,
		HadRoutes: make(map[netip.Prefix]bool),
	}
	if s.opts.Address.IsValid() {
		if err := n.journalIntent("prepare", "address", s.opts.Address.String(), ""); err != nil {
			return err
		}
		present, found, err := n.ops.interfaceAddress(luid, s.opts.Address.Addr())
		if err != nil {
			return fmt.Errorf("agent: read address %s on %q: %w", s.opts.Address, s.opts.Interface, err)
		}
		if found {
			n.snapshot.HadAddress = true
			n.snapshot.Address = present
		}
	}
	for _, route := range s.opts.Routes {
		if err := n.journalIntent("prepare", "route", route.String(), ""); err != nil {
			return err
		}
		state, err := n.ops.routeState(luid, index, route)
		if err != nil {
			return fmt.Errorf("agent: read route %s on %q: %w", route, s.opts.Interface, err)
		}
		n.snapshot.HadRoutes[route] = state.Found
	}
	s.current = SystemNetworkPrepared
	return nil
}

// Apply installs MTU, address and routes in order, journaling (and fsyncing)
// each intent first and its outcome after. A failure leaves the already-applied
// resources in place for Rollback to reverse; callers must Rollback (the Agent
// does).

// applyLocked implements Apply. The caller holds n.mu; RetargetAddress calls
// it directly so a retarget is one atomic transition under the owner mutex.
func (n *windowsSystemNetwork) applyLocked(ctx context.Context, s *systemNetworkState) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	if s.current != SystemNetworkPrepared {
		return fmt.Errorf("%w: Apply requires the prepared state, got %s", ErrInvalidConfig, s.current)
	}
	s.current = SystemNetworkApplied
	if err := n.applyMTU(); err != nil {
		return err
	}
	if s.opts.Address.IsValid() && !n.snapshot.HadAddress {
		if err := n.applyAddress(); err != nil {
			return err
		}
	}
	for _, route := range s.opts.Routes {
		if err := n.applyRoute(route); err != nil {
			return err
		}
	}
	return nil
}

// applyMTU re-reads the live MTU immediately before changing it and keeps an
// external value that no longer matches the Prepare snapshot.
func (n *windowsSystemNetwork) applyMTU() error {
	if n.snapshot.MTU == n.mtu {
		return nil
	}
	current, err := n.ops.interfaceMTU(n.luid)
	if err != nil {
		return fmt.Errorf("%w: read MTU of %q before Apply: %v", ErrPlatformUnavailable, n.linkName, err)
	}
	if current != n.snapshot.MTU {
		n.markDegraded("mtu", fmt.Sprintf("MTU changed from the prepared %d to %d before Apply; the external value is kept", n.snapshot.MTU, current))
		return fmt.Errorf("%w: MTU of %q changed from %d to %d between Prepare and Apply; the external value is kept", ErrPlatformUnavailable, n.linkName, n.snapshot.MTU, current)
	}
	// The fingerprint carries both values so crash recovery can prove the
	// adapter still holds the value this transaction set before restoring the
	// prior one.
	if err := n.journalIntent("apply", "mtu", fmt.Sprintf("mtu=%d", n.mtu), fmt.Sprintf("prior=%d", n.snapshot.MTU)); err != nil {
		return err
	}
	if err := n.ops.setInterfaceMTU(n.luid, n.mtu); err != nil {
		return fmt.Errorf("%w: set MTU %d on %q: %v; the process must run elevated (Administrator)", ErrPlatformUnavailable, n.mtu, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "mtu", fmt.Sprintf("mtu=%d", n.mtu), fmt.Sprintf("prior=%d", n.snapshot.MTU), journalOutcomeConfirmed); err != nil {
		return err
	}
	n.applied.MTU = true
	return nil
}

// applyAddress adds the VirtualIP. A concurrently created identical address is
// closed as not_owned: it is someone else's and is never recorded as applied.
func (n *windowsSystemNetwork) applyAddress() error {
	fingerprint := n.owner.addressFingerprint()
	if err := n.journalIntent("apply", "address", n.opts.Address.String(), fingerprint); err != nil {
		return err
	}
	if err := n.ops.createIPv4Addr(n.luid, n.index, n.opts.Address); err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return n.journalConfirm("apply", "address", n.opts.Address.String(), fingerprint, journalOutcomeNotOwned)
		}
		return fmt.Errorf("%w: assign %s to %q: %v; the process must run elevated (Administrator)", ErrPlatformUnavailable, n.opts.Address, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "address", n.opts.Address.String(), fingerprint, journalOutcomeConfirmed); err != nil {
		return err
	}
	n.applied.Address = true
	return nil
}

// applyRoute installs one on-link route. An existing route, including one that
// appears concurrently, is not ours: the intent is closed as not_owned so
// recovery can never delete it.
func (n *windowsSystemNetwork) applyRoute(route netip.Prefix) error {
	if n.snapshot.HadRoutes[route] {
		// Someone else already owns this route; it is never recorded as applied.
		return nil
	}
	state, err := n.ops.routeState(n.luid, n.index, route)
	if err != nil {
		return fmt.Errorf("agent: read route %s on %q: %w", route, n.linkName, err)
	}
	if state.Found {
		n.snapshot.HadRoutes[route] = true
		return nil
	}
	fingerprint := windowsRouteFingerprint(route, n.luid, n.index)
	if err := n.journalIntent("apply", "route", route.String(), fingerprint); err != nil {
		return err
	}
	if err := n.ops.createIPv4Route(n.luid, n.index, route); err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			// The route appeared between the snapshot and the add: it is not
			// ours, so it is not recorded as applied.
			n.snapshot.HadRoutes[route] = true
			return n.journalConfirm("apply", "route", route.String(), fingerprint, journalOutcomeNotOwned)
		}
		return fmt.Errorf("%w: install route %s on %q: %v; the process must run elevated (Administrator)", ErrPlatformUnavailable, route, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "route", route.String(), fingerprint, journalOutcomeConfirmed); err != nil {
		return err
	}
	n.applied.Routes = append(n.applied.Routes, route)
	return nil
}

// Rollback reverses the applied resources in reverse order, verifying the full
// fingerprint recorded for each one. A resource that no longer matches (someone
// else changed or replaced it) is left alone and the transaction becomes
// Degraded. It finishes with a terminal checkpoint so a later recovery run
// ignores the whole transaction.

// rollbackLocked implements Rollback. The caller holds n.mu; RetargetAddress calls
// it directly so a retarget is one atomic transition under the owner mutex.
func (n *windowsSystemNetwork) rollbackLocked(ctx context.Context, s *systemNetworkState) error {
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
		state, err := n.ops.routeState(n.luid, n.index, route)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent: verify route %s on %q: %w", route, n.linkName, err))
			continue
		}
		switch {
		case !state.Found:
			continue
		case !state.Exact:
			n.markDegraded("route "+route.String(),
				fmt.Sprintf("route %s is now present with different attributes; the external route is kept", route))
			continue
		}
		fingerprint := windowsRouteFingerprint(route, n.luid, n.index)
		if err := n.journalIntent("rollback", "route", route.String(), fingerprint); err != nil {
			errs = append(errs, err)
		}
		if err := n.ops.deleteIPv4Route(n.luid, n.index, route); err != nil {
			errs = append(errs, fmt.Errorf("agent: remove route %s from %q: %w", route, n.linkName, err))
			continue
		}
		if err := n.journalConfirm("rolledback", "route", route.String(), fingerprint, journalOutcomeConfirmed); err != nil {
			errs = append(errs, err)
		}
	}
	n.applied.Routes = nil
	if n.applied.Address {
		present, found, err := n.ops.interfaceAddress(n.luid, s.opts.Address.Addr())
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("agent: verify %s on %q: %w", s.opts.Address, n.linkName, err))
		case found && present != s.opts.Address:
			n.markDegraded("address "+s.opts.Address.String(),
				fmt.Sprintf("address %s is now present with a different prefix length; the external address is kept", s.opts.Address.Addr()))
		case found:
			if err := n.journalIntent("rollback", "address", s.opts.Address.String(), n.owner.addressFingerprint()); err != nil {
				errs = append(errs, err)
			}
			if err := n.ops.deleteIPv4Addr(n.luid, n.index, s.opts.Address.Addr()); err != nil {
				errs = append(errs, fmt.Errorf("agent: remove %s from %q: %w", s.opts.Address, n.linkName, err))
				break
			}
			if err := n.journalConfirm("rolledback", "address", s.opts.Address.String(), n.owner.addressFingerprint(), journalOutcomeConfirmed); err != nil {
				errs = append(errs, err)
			}
		}
	}
	n.applied.Address = false
	if n.applied.MTU {
		current, err := n.ops.interfaceMTU(n.luid)
		switch {
		case err != nil:
			n.markDegraded("mtu", fmt.Sprintf("MTU of %q could not be read before rollback: %v; the external value is kept", n.linkName, err))
		case current != s.mtu:
			n.markDegraded("mtu", fmt.Sprintf("MTU is now %d, not the %d this transaction set; the external value is kept", current, s.mtu))
		default:
			if err := n.journalIntent("rollback", "mtu", fmt.Sprintf("mtu=%d", s.mtu), fmt.Sprintf("prior=%d", n.snapshot.MTU)); err != nil {
				errs = append(errs, err)
			}
			if err := n.ops.setInterfaceMTU(n.luid, n.snapshot.MTU); err != nil {
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

// addressFingerprint is the recorded identity of the VirtualIP.

// DegradedDetail reports the external modifications rollback refused to
// overwrite. It is empty when rollback fully owned its resources.

// Close rolls back if needed and releases the journal. It is idempotent.

// journalIntent records one write-ahead intent before an OS side effect. A
// journal write or fsync failure aborts the side effect, because the port
// contract requires intent-before-effect.

// journalConfirm records the durable outcome of an intent that already ran.

// journalTerminal closes the transaction durably.

// Journal returns a copy of the in-memory write-ahead journal.

// windowsInterfaceInstance is the adapter-instance fingerprint recorded in the
// journal. The LUID identifies the live adapter; the same alias with another
// LUID is a different adapter.
func windowsInterfaceInstance(luid uint64, index uint32) string {
	return encodeJournalFields(
		[2]string{"luid", strconv.FormatUint(luid, 10)},
		[2]string{"index", strconv.FormatUint(uint64(index), 10)},
	)
}

// windowsRouteFingerprint is the recorded identity of one on-link route.
func windowsRouteFingerprint(route netip.Prefix, luid uint64, index uint32) string {
	return encodeJournalFields(
		[2]string{"dst", route.String()},
		[2]string{"luid", strconv.FormatUint(luid, 10)},
		[2]string{"index", strconv.FormatUint(uint64(index), 10)},
		[2]string{"gateway", "onlink"},
		[2]string{"metric", "0"},
		[2]string{"protocol", "netmgmt"},
	)
}

// RetargetAddress moves this transaction's local VirtualIP to a new IPv4 /32 on
// the same device, without reopening it. It is the single-owner retarget: before
// anything is released it proves by live IP Helper reads that the old
// transaction still owns every resource it applied
// (preflightAppliedOwnership); only then does it roll the old transaction back
// with its own fingerprint proof and a terminal checkpoint, start a fresh
// transaction id on the same open journal (same file, same exclusive lock) and
// Prepare/Apply the new address.
//
// An external value the old transaction cannot prove as its own stops the
// retarget BEFORE the first side effect, with Degraded and
// ErrPlatformUnavailable. That ordering is the design parity the Linux owner
// fixed for a concrete kernel side effect: releasing this transaction's own /32
// first lets the OS drop routes an external actor had replaced as collateral, so
// a retarget that rolled back first could not keep the external route it claims
// to keep. The window between this proof and the later delete is the same
// bounded race rollback carries; it is not closed by an OS compare-and-swap.
//
// Close is the separate per-resource cleanup path: on teardown it may still
// release this transaction's owned MTU/address and let the OS flush routes,
// keeping the per-resource fingerprint proof. Only the retarget preflight
// failure is guaranteed to have zero OS effects.
//
// The native calls are unverified on this platform: this is a compile-and-design
// parity path, not host acceptance.

// preflightAppliedOwnership proves, by live IP Helper reads, that this
// transaction still owns every resource it applied, before RetargetAddress
// releases anything. Ownership is the exact full tuple: the adapter still
// resolves to this transaction's LUID and interface index, an owned MTU still
// holds the value this transaction set, an owned address is still present at its
// exact prefix length, and every owned route still matches its full fingerprint
// (destination, prefix length, LUID, interface index, on-link gateway, zero
// metric and NETMGMT protocol, as reported by windowsRouteResult.Exact).
//
// The adapter LUID/index pair is the interface-instance proof every other
// resource hangs on. It is the identity this transaction actually recorded, not
// a stronger synthetic hash: the same alias rebound to another LUID is a
// different adapter and is never claimed.
//
// The first divergence or unreadable resource marks the transaction Degraded and
// returns ErrPlatformUnavailable with no OS mutation, no journal record and no
// new transaction. It never removes the address, restores the MTU or deletes a
// route: those belong to Rollback/Close, and doing them here would let the OS
// flush an externally replaced route as collateral. The caller holds n.mu.
func (n *windowsSystemNetwork) preflightAppliedOwnership(ctx context.Context, s *systemNetworkState) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	luid, err := n.ops.interfaceLUID(s.opts.Interface)
	switch {
	case err != nil:
		return n.preflightDegraded("instance", fmt.Sprintf("adapter %q could not be resolved before retarget: %v; nothing was released and the new address was not applied", s.opts.Interface, err))
	case luid != n.luid:
		return n.preflightDegraded("instance", fmt.Sprintf("adapter %q now resolves to LUID %d, not this transaction's %d; the external adapter is kept and nothing was released", s.opts.Interface, luid, n.luid))
	}
	index, err := n.ops.interfaceIndex(luid)
	switch {
	case err != nil:
		return n.preflightDegraded("instance", fmt.Sprintf("interface index of %q could not be read before retarget: %v; nothing was released and the new address was not applied", s.opts.Interface, err))
	case index != n.index:
		return n.preflightDegraded("instance", fmt.Sprintf("adapter %q now has interface index %d, not this transaction's %d; the external adapter is kept and nothing was released", s.opts.Interface, index, n.index))
	}
	if n.applied.MTU {
		live, err := n.ops.interfaceMTU(n.luid)
		switch {
		case err != nil:
			return n.preflightDegraded("mtu", fmt.Sprintf("MTU of %q could not be read before retarget: %v; nothing was released and the new address was not applied", n.linkName, err))
		case live != s.mtu:
			return n.preflightDegraded("mtu", fmt.Sprintf("MTU is now %d, not the %d this transaction set; the external value is kept and nothing was released", live, s.mtu))
		}
	}
	if n.applied.Address {
		present, found, err := n.ops.interfaceAddress(n.luid, s.opts.Address.Addr())
		switch {
		case err != nil:
			return n.preflightDegraded("address "+s.opts.Address.String(), fmt.Sprintf("address %s on %q could not be read before retarget: %v; nothing was released and the new address was not applied", s.opts.Address, n.linkName, err))
		case !found:
			return n.preflightDegraded("address "+s.opts.Address.String(), fmt.Sprintf("address %s is no longer present on %q; nothing was released and the new address was not applied", s.opts.Address, n.linkName))
		case present != s.opts.Address:
			return n.preflightDegraded("address "+s.opts.Address.String(), fmt.Sprintf("address %s is now present with a different prefix length; the external address is kept and nothing was released", s.opts.Address.Addr()))
		}
	}
	for _, route := range n.applied.Routes {
		state, err := n.ops.routeState(n.luid, n.index, route)
		switch {
		case err != nil:
			return n.preflightDegraded("route "+route.String(), fmt.Sprintf("route %s on %q could not be read before retarget: %v; nothing was released and the new address was not applied", route, n.linkName, err))
		case !state.Found:
			return n.preflightDegraded("route "+route.String(), fmt.Sprintf("route %s is no longer present on %q; nothing was released and the new address was not applied", route, n.linkName))
		case !state.Exact:
			return n.preflightDegraded("route "+route.String(), fmt.Sprintf("route %s is now present with different attributes; the external route is kept and nothing was released", route))
		}
	}
	return nil
}

// preflightDegraded records the divergence and returns the fail-closed error.
// markDegraded only appends to the in-memory detail list, so this performs no OS
// mutation and writes no journal record.

// retargetFailedLocked releases whatever the failed new transaction owns and
// best-effort restores the ORIGINAL address (never the failed new one) in
// another fresh transaction. If it cannot be restored safely the error is
// returned so the caller can fail closed.

// resetTransactionLocked clears the per-transaction state before a fresh
// Prepare. The journal file and its lock stay open; only the transaction id and
// instance fingerprint are renewed.
func (n *windowsSystemNetwork) resetTransactionLocked(s *systemNetworkState) {
	s.current = SystemNetworkAbsent
	n.snapshot = windowsNetworkSnapshot{}
	n.applied = windowsAppliedResources{}
	s.degraded = false
	s.degradedDetail = nil
	n.instance = ""
}

var _ SystemNetwork = (*windowsSystemNetwork)(nil)

// --- shared transaction state machine ---------------------------------------

// State implements SystemNetwork.
func (n *windowsSystemNetwork) State() SystemNetworkState { return n.owner.State() }

// Prepare implements SystemNetwork.
func (n *windowsSystemNetwork) Prepare(ctx context.Context) error { return n.owner.Prepare(ctx) }

// Apply implements SystemNetwork.
func (n *windowsSystemNetwork) Apply(ctx context.Context) error { return n.owner.Apply(ctx) }

// Rollback implements SystemNetwork.
func (n *windowsSystemNetwork) Rollback(ctx context.Context) error { return n.owner.Rollback(ctx) }

// Close implements SystemNetwork.
func (n *windowsSystemNetwork) Close() error { return n.owner.Close() }

// DegradedDetail reports the external modifications rollback refused to
// overwrite. It is empty when rollback fully owned its resources.
func (n *windowsSystemNetwork) DegradedDetail() []string { return n.owner.DegradedDetail() }

// Journal returns the in-memory view of this owner's write-ahead records.
func (n *windowsSystemNetwork) Journal() []journalEntry { return n.owner.Journal() }

// RetargetAddress moves the local IPv4 /32 VirtualIP to a new /32 on the same
// adapter, without reopening it.
func (n *windowsSystemNetwork) RetargetAddress(ctx context.Context, address netip.Prefix) error {
	return n.owner.RetargetAddress(ctx, address)
}

// journalIntent records one write-ahead intent before an OS side effect.
func (n *windowsSystemNetwork) journalIntent(kind, resource, detail, fingerprint string) error {
	return n.owner.journalIntent(kind, resource, detail, fingerprint)
}

// journalConfirm records the durable outcome of an intent that already ran.
func (n *windowsSystemNetwork) journalConfirm(kind, resource, detail, fingerprint, outcome string) error {
	return n.owner.journalConfirm(kind, resource, detail, fingerprint, outcome)
}

// journalTerminal records the terminal checkpoint of this transaction.
func (n *windowsSystemNetwork) journalTerminal() error { return n.owner.journalTerminal() }

// markDegraded records that the transaction could not be fully proven.
func (n *windowsSystemNetwork) markDegraded(kind, detail string) { n.owner.markDegraded(kind, detail) }

// preflightDegraded records the degraded reason and fails closed.
func (n *windowsSystemNetwork) preflightDegraded(kind, detail string) error {
	return n.owner.preflightDegraded(kind, detail)
}

// retargetFailedLocked releases whatever the failed new transaction owned.
func (n *windowsSystemNetwork) retargetFailedLocked(ctx context.Context, previous netip.Prefix, cause error) error {
	return n.owner.retargetFailedLocked(ctx, previous, cause)
}

// --- platform hooks --------------------------------------------------------

// journalInterfaceName is the interface the journal records are stamped with.
func (n *windowsSystemNetwork) journalInterfaceName(s *systemNetworkState) string {
	return n.linkName
}

// platformAddressFingerprint is this platform's ownership fingerprint for the
// configured address.
func (n *windowsSystemNetwork) platformAddressFingerprint(s *systemNetworkState) string {
	return encodeJournalFields(
		[2]string{"addr", s.opts.Address.Addr().String()},
		[2]string{"prefixlen", strconv.Itoa(s.opts.Address.Bits())},
	)
}
