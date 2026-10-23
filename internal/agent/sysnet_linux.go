//go:build linux

package agent

// Linux SystemNetwork: the real host network transaction owner.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// It applies, in order, the interface MTU, the local IPv4 /32 address, the
// interface up flag and the optional routes, and reverses exactly what it
// applied, in reverse order. Every side effect is preceded by a durable
// write-ahead intent and followed by an explicit outcome record (see
// sysnet_journal.go), and the resource identity is the full tuple, not the
// prefix alone: a route or address that someone else replaced with different
// attributes is kept and the transaction reports Degraded instead of
// overwriting external configuration. It never touches the default route, DNS
// or the firewall, and it never shells out.
//
// Apply re-reads the MTU and link state immediately before it changes them. If
// an external actor moved either value after Prepare, Apply aborts that step and
// keeps the external value: the snapshot is the only prior state this
// transaction may restore. A concurrent change in the nanosecond between the
// re-read and the mutation remains an honest race this code does not try to
// hide with a claim of atomicity.
//
// MTU and link/address use ioctls where the kernel accepts them on an existing
// interface; routes and the exact address table use netlink exchanges because
// the ioctl surface is not portably sufficient to prove ownership.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// linuxSystemNetwork is the Linux SystemNetwork implementation for one
// interface: MTU, one local /32 address and optional IPv4 routes.
type linuxSystemNetwork struct {
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
	// journal record. It names the interface, its ifindex and the random
	// ownership marker this transaction writes into the kernel interface alias.
	// A reused name/index can never match the marker, so recovery refuses to
	// act across instances.
	instance string
	// instanceToken is the cryptographically unpredictable alias marker written
	// into IFLA_IFALIAS before any other effect.
	instanceToken string
	// priorAlias is the alias the kernel reported before Apply, read back from
	// the kernel rather than assumed. An empty value means the interface had no
	// external or dangling marker.
	priorAlias string
	// aliasOwned reports that this transaction wrote instanceToken successfully.
	aliasOwned bool

	// snapshot records what existed before Apply so rollback restores it.
	snapshot linkSnapshot

	applied appliedResources
}

// linkSnapshot is the pre-Apply state of the interface.
type linkSnapshot struct {
	Index        int
	MTU          int
	Up           bool
	HadAddress   bool
	HadRoute     bool
	Address      netip.Prefix
	Route        netip.Prefix
	RouteGateway netip.Addr
}

// appliedResources records exactly what this transaction created so rollback
// only removes owned resources.
type appliedResources struct {
	MTU     bool
	Address bool
	LinkUp  bool
	Routes  []netip.Prefix
}

// newSystemNetwork implements the per-GOOS dispatch declared by
// NewSystemNetwork.
func newSystemNetwork(platform Platform, opts SystemNetworkOptions) (SystemNetwork, error) {
	if platform != PlatformLinux {
		return nil, fmt.Errorf("%w: the %s host network owner needs a %s build", ErrNetworkConfigUnavailable, platform, platform)
	}
	return newLinuxSystemNetwork(opts)
}

func newLinuxSystemNetwork(opts SystemNetworkOptions) (*linuxSystemNetwork, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	journal, err := newResourceJournal(opts.JournalPath)
	if err != nil {
		return nil, err
	}
	network := &linuxSystemNetwork{
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
// intends to own. It performs no OS mutation.

// prepareLocked implements Prepare. The caller holds n.mu; RetargetAddress calls
// it directly so a retarget is one atomic transition under the owner mutex and
// never re-enters a public method that would lock again.
func (n *linuxSystemNetwork) prepareLocked(ctx context.Context, s *systemNetworkState) error {
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
	// Read the live kernel alias before anything is journaled or changed. Every
	// field of the instance fingerprint is either kernel-read here or journaled
	// as an intent before the write; none is assumed.
	priorAlias, err := readInterfaceAlias(link.Name)
	if err != nil {
		return fmt.Errorf("%w: read the instance alias of %q: %v", ErrPlatformUnavailable, link.Name, err)
	}
	n.linkIndex = link.Index
	n.linkName = link.Name
	n.priorAlias = priorAlias
	n.instanceToken = newInstanceToken()
	n.instance = linuxInterfaceInstance(link.Name, link.Index, n.instanceToken)
	s.journal.setResourceID(n.instance)
	n.snapshot = linkSnapshot{
		Index: link.Index,
		MTU:   link.MTU,
		Up:    link.Flags&net.FlagUp != 0,
	}
	if s.opts.Address.IsValid() {
		if err := n.journalIntent("prepare", "address", s.opts.Address.String(), ""); err != nil {
			return err
		}
		present, _, err := addressState(s.opts.Address, n.linkIndex)
		if err != nil {
			return fmt.Errorf("agent: read addresses of %q: %w", n.linkName, err)
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
		state, err := routeState(route, n.linkIndex)
		if err != nil {
			return fmt.Errorf("agent: inspect route %s on %q: %w", route, n.linkName, err)
		}
		if state.Found {
			n.snapshot.HadRoute = true
			n.snapshot.Route = route
			n.snapshot.RouteGateway = state.Entry.gateway
		}
	}
	s.current = SystemNetworkPrepared
	return nil
}

// Apply installs MTU, address, link-up and routes in order, journaling each
// intent first and each outcome after. A failure leaves the already-applied
// resources in place for Rollback to reverse; callers must Rollback (the Agent
// does).

// applyLocked implements Apply. The caller holds n.mu.
func (n *linuxSystemNetwork) applyLocked(ctx context.Context, s *systemNetworkState) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	if s.current != SystemNetworkPrepared {
		return fmt.Errorf("%w: Apply requires the prepared state, got %s", ErrInvalidConfig, s.current)
	}
	s.current = SystemNetworkApplied
	if err := n.applyInstance(); err != nil {
		return err
	}
	if err := n.applyMTU(); err != nil {
		return err
	}
	if s.opts.Address.IsValid() && !n.snapshot.HadAddress {
		if err := n.applyAddress(); err != nil {
			return err
		}
	}
	if err := n.applyLinkUp(); err != nil {
		return err
	}
	for _, route := range s.opts.Routes {
		if err := n.applyRoute(route); err != nil {
			return err
		}
	}
	return nil
}

// applyInstance writes the transaction's random ownership marker into the
// kernel interface alias before any other side effect, so a later kernel read
// can prove which transaction owns the interface instance. The prior alias is
// journaled as a fingerprint before the write. An interface that already
// carries a non-empty alias is never overwritten: that alias is either the
// user's or a dangling marker of a previous transaction, and only a recovery
// run that proves the marker may clear it. In that case Apply aborts with
// Degraded and touches nothing.
func (n *linuxSystemNetwork) applyInstance() error {
	if n.instanceToken == "" {
		return fmt.Errorf("%w: the interface instance marker was not prepared", ErrInvalidConfig)
	}
	// Re-read immediately before the effect: no field of the proof is assumed.
	current, err := readInterfaceAlias(n.linkName)
	if err != nil {
		return fmt.Errorf("%w: read the instance alias of %q before Apply: %v", ErrPlatformUnavailable, n.linkName, err)
	}
	if current != n.priorAlias {
		n.markDegraded("instance", fmt.Sprintf("interface alias changed from %q to %q between Prepare and Apply; the external alias is kept", n.priorAlias, current))
		return fmt.Errorf("%w: interface %q alias changed from %q to %q between Prepare and Apply; the external alias is kept", ErrPlatformUnavailable, n.linkName, n.priorAlias, current)
	}
	if n.priorAlias != "" {
		n.markDegraded("instance", fmt.Sprintf("interface %q already carries the alias %q; refusing to overwrite an external or dangling owner marker", n.linkName, n.priorAlias))
		return fmt.Errorf("%w: interface %q already carries alias %q; reconcile the previous transaction before claiming it", ErrPlatformUnavailable, n.linkName, n.priorAlias)
	}
	fingerprint := encodeJournalFields([2]string{"prior", n.priorAlias})
	if err := n.journalIntent("apply", "instance", n.instanceToken, fingerprint); err != nil {
		return err
	}
	if err := setInterfaceAlias(n.linkName, n.instanceToken); err != nil {
		return fmt.Errorf("%w: write the instance marker on %q: %v; the process needs CAP_NET_ADMIN", ErrPlatformUnavailable, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "instance", n.instanceToken, fingerprint, journalOutcomeConfirmed); err != nil {
		return err
	}
	n.aliasOwned = true
	return nil
}

// applyMTU re-reads the live MTU immediately before changing it. An external
// value that no longer matches the Prepare snapshot is kept: this transaction
// only restores the state it actually observed.
func (n *linuxSystemNetwork) applyMTU() error {
	if n.snapshot.MTU == n.mtu {
		return nil
	}
	current, err := currentInterfaceMTU(n.linkName)
	if err != nil {
		return fmt.Errorf("%w: read MTU of %q before Apply: %w", ErrPlatformUnavailable, n.linkName, err)
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
		return fmt.Errorf("%w: set MTU %d on %q: %w; the process needs CAP_NET_ADMIN", ErrPlatformUnavailable, n.mtu, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "mtu", fmt.Sprintf("mtu=%d", n.mtu), fmt.Sprintf("prior=%d", n.snapshot.MTU), journalOutcomeConfirmed); err != nil {
		return err
	}
	n.applied.MTU = true
	return nil
}

// applyAddress adds the local address. A concurrent identical address makes the
// exclusive create fail with EEXIST; that address is someone else's, so the
// intent is closed as not_owned and the transaction never claims it.
func (n *linuxSystemNetwork) applyAddress() error {
	if err := n.journalIntent("apply", "address", n.opts.Address.String(), n.owner.addressFingerprint()); err != nil {
		return err
	}
	if err := addIPv4Address(n.opts.Address, n.linkIndex); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return n.journalConfirm("apply", "address", n.opts.Address.String(), n.owner.addressFingerprint(), journalOutcomeNotOwned)
		}
		return fmt.Errorf("%w: assign %s to %q: %w; the process needs CAP_NET_ADMIN", ErrPlatformUnavailable, n.opts.Address, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "address", n.opts.Address.String(), n.owner.addressFingerprint(), journalOutcomeConfirmed); err != nil {
		return err
	}
	n.applied.Address = true
	return nil
}

// applyLinkUp brings the interface up, but only when it is still down. An
// external actor that brought it up between Prepare and Apply owns that state;
// this transaction neither journals nor rolls it back.
func (n *linuxSystemNetwork) applyLinkUp() error {
	if n.snapshot.Up {
		return nil
	}
	link, err := net.InterfaceByName(n.linkName)
	if err != nil {
		return fmt.Errorf("%w: read link state of %q before Apply: %w", ErrPlatformUnavailable, n.linkName, err)
	}
	if link.Flags&net.FlagUp != 0 {
		n.markDegraded("link_up", fmt.Sprintf("%q was brought up by someone else between Prepare and Apply; the external link state is kept", n.linkName))
		return nil
	}
	if err := n.journalIntent("apply", "link_up", n.linkName, "was down"); err != nil {
		return err
	}
	if err := setLinkUp(n.linkName, true); err != nil {
		return fmt.Errorf("%w: bring %q up: %w; the process needs CAP_NET_ADMIN", ErrPlatformUnavailable, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "link_up", n.linkName, "was down", journalOutcomeConfirmed); err != nil {
		return err
	}
	n.applied.LinkUp = true
	return nil
}

// applyRoute installs one route on the canonical device tuple. EEXIST means the
// route already existed (someone else's): the durable intent is closed as
// not_owned so a later recovery can never delete it from the intent alone.
func (n *linuxSystemNetwork) applyRoute(route netip.Prefix) error {
	fingerprint := canonicalRouteFields(route, n.linkIndex).fingerprint()
	if err := n.journalIntent("apply", "route", route.String(), fingerprint); err != nil {
		return err
	}
	if err := addRoute(route, n.linkIndex); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return n.journalConfirm("apply", "route", route.String(), fingerprint, journalOutcomeNotOwned)
		}
		return fmt.Errorf("%w: install route %s on %q: %w; the process needs CAP_NET_ADMIN", ErrPlatformUnavailable, route, n.linkName, err)
	}
	if err := n.journalConfirm("apply", "route", route.String(), fingerprint, journalOutcomeConfirmed); err != nil {
		return err
	}
	n.applied.Routes = append(n.applied.Routes, route)
	return nil
}

// Rollback reverses the applied resources in reverse order, verifying the full
// fingerprint recorded for each one. A resource that no longer matches (someone
// else changed or moved it) is left alone and the transaction becomes Degraded.
// It finishes with a terminal checkpoint so a later recovery run ignores the
// whole transaction.

// rollbackLocked implements Rollback. The caller holds n.mu.
func (n *linuxSystemNetwork) rollbackLocked(ctx context.Context, s *systemNetworkState) error {
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
		state, err := routeState(route, n.linkIndex)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("agent: verify route %s on %q: %w", route, n.linkName, err))
			continue
		case !state.Found:
			continue
		case !state.Exact:
			n.markDegraded("route "+route.String(),
				fmt.Sprintf("route %s is now on interface index %d with different attributes; the external route is kept", route, state.Entry.ifindex))
			continue
		}
		if err := n.journalIntent("rollback", "route", route.String(), state.Entry.fields().fingerprint()); err != nil {
			errs = append(errs, err)
		}
		if err := deleteRoute(route, n.linkIndex); err != nil {
			if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
				continue // it disappeared between the proof and the delete
			}
			errs = append(errs, fmt.Errorf("agent: remove route %s from %q: %w", route, n.linkName, err))
			continue
		}
		if err := n.journalConfirm("rolledback", "route", route.String(), state.Entry.fields().fingerprint(), journalOutcomeConfirmed); err != nil {
			errs = append(errs, err)
		}
	}
	n.applied.Routes = nil
	if n.applied.LinkUp && !n.snapshot.Up {
		link, err := net.InterfaceByName(n.linkName)
		switch {
		case err != nil:
			n.markDegraded("link_up", fmt.Sprintf("link state of %q could not be read before rollback: %v; the external state is kept", n.linkName, err))
		case link.Flags&net.FlagUp != 0:
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
		found, exact, err := addressState(s.opts.Address, n.linkIndex)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("agent: verify %s on %q: %w", s.opts.Address, n.linkName, err))
		case found && !exact:
			n.markDegraded("address "+s.opts.Address.String(),
				fmt.Sprintf("address %s is now present with a different prefix length; the external address is kept", s.opts.Address.Addr()))
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
	n.applied.Address = false
	if n.applied.MTU {
		current, err := currentInterfaceMTU(n.linkName)
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
	if err := n.rollbackInstance(); err != nil {
		errs = append(errs, err)
	}
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

// rollbackInstance restores the alias this transaction wrote, but only while
// the kernel still reports exactly this transaction's random marker. An alias
// someone else changed is kept and reported Degraded.
func (n *linuxSystemNetwork) rollbackInstance() error {
	if !n.aliasOwned {
		return nil
	}
	current, err := readInterfaceAlias(n.linkName)
	switch {
	case err != nil:
		n.markDegraded("instance", fmt.Sprintf("interface alias of %q could not be read before rollback: %v; the external alias is kept", n.linkName, err))
		return nil
	case current != n.instanceToken:
		n.markDegraded("instance", fmt.Sprintf("interface alias is now %q, not this transaction's marker; the external alias is kept", current))
		return nil
	}
	fingerprint := encodeJournalFields([2]string{"prior", n.priorAlias})
	if err := n.journalIntent("rollback", "instance", n.instanceToken, fingerprint); err != nil {
		return err
	}
	if err := setInterfaceAlias(n.linkName, n.priorAlias); err != nil {
		return fmt.Errorf("agent: restore alias %q on %q: %w", n.priorAlias, n.linkName, err)
	}
	if err := n.journalConfirm("rolledback", "instance", n.instanceToken, fingerprint, journalOutcomeConfirmed); err != nil {
		return err
	}
	n.aliasOwned = false
	return nil
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

// linuxInterfaceInstance is the interface-instance fingerprint recorded in the
// journal: the interface name, its ifindex and the transaction's unpredictable
// alias marker. The name and index alone are not proof (a persisted interface
// can be recreated with the same values), so recovery additionally requires the
// live kernel alias to equal the recorded marker.
func linuxInterfaceInstance(name string, ifindex int, token string) string {
	return encodeJournalFields(
		[2]string{"name", name},
		[2]string{"ifindex", strconv.Itoa(ifindex)},
		[2]string{"alias", token},
	)
}

// interfaceAliasPath is the kernel sysfs attribute for IFLA_IFALIAS.
func interfaceAliasPath(name string) string {
	return "/sys/class/net/" + name + "/ifalias"
}

// readInterfaceAlias reads the live interface alias from the kernel. An empty
// result means no alias is set.
func readInterfaceAlias(name string) (string, error) {
	payload, err := os.ReadFile(interfaceAliasPath(name))
	if err != nil {
		return "", fmt.Errorf("agent: read interface alias of %q: %w", name, err)
	}
	return strings.TrimRight(string(payload), "\n"), nil
}

// setInterfaceAlias writes the interface alias through the kernel attribute. An
// empty alias clears it. This is the only write that tags the instance; it is
// always preceded by a durable journal intent.
func setInterfaceAlias(name, alias string) error {
	if err := os.WriteFile(interfaceAliasPath(name), []byte(alias+"\n"), 0o644); err != nil {
		return fmt.Errorf("agent: set interface alias of %q: %w", name, err)
	}
	return nil
}

// currentInterfaceMTU reads the live MTU of one interface.
func currentInterfaceMTU(name string) (int, error) {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return link.MTU, nil
}

func mustAddrs(link *net.Interface) []netip.Prefix {
	addrs, err := link.Addrs()
	if err != nil {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

// setLinkUp sets or clears IFF_UP through SIOCSIFFLAGS.
func setLinkUp(name string, up bool) error {
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(socket) }()
	request, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(socket, unix.SIOCGIFFLAGS, request); err != nil {
		return err
	}
	flags := request.Uint16()
	if up {
		flags |= unix.IFF_UP
	} else {
		flags &^= unix.IFF_UP
	}
	request.SetUint16(flags)
	return unix.IoctlIfreq(socket, unix.SIOCSIFFLAGS, request)
}

// RetargetAddress moves this transaction's local VirtualIP to a new IPv4 /32 on
// the same device, without reopening it. It is the single-owner retarget: before
// anything is released it proves by live kernel reads that the old transaction
// still owns every resource it applied (preflightAppliedOwnership); only then
// does it roll the old transaction back with its own fingerprint/alias proof and
// a terminal checkpoint, start a fresh transaction id on the same open journal
// (same file, same exclusive lock) and Prepare/Apply the new address.
//
// An external value the old transaction cannot prove as its own stops the
// retarget BEFORE the first side effect, with Degraded and
// ErrPlatformUnavailable. That ordering is the fix for a concrete kernel
// side effect: releasing this transaction's own /32 first makes the kernel drop
// device routes an external actor had replaced, so a retarget that rolled back
// first could not keep the external route it claimed to keep. The window between
// this proof and the later delete is the same bounded kernel race rollback
// carries; it is not closed by an OS compare-and-swap.
//
// Close is the separate per-resource cleanup path: on teardown it may still
// release this transaction's owned link/address and let the kernel flush routes,
// keeping the per-resource fingerprint proof. Only the retarget preflight
// failure is guaranteed to have zero kernel effects.

// preflightAppliedOwnership proves, by live kernel reads, that this transaction
// still owns every resource it applied, before RetargetAddress releases anything.
// Ownership is the exact full tuple: the instance alias still carries this
// transaction's random marker, an owned MTU still holds the value this
// transaction set, an owned address is still present at its exact /32 prefix,
// every owned route still matches its full fingerprint (destination, prefix
// length, output interface, table, protocol, scope, type, metric and gateway),
// and a link this transaction brought up is still up.
//
// The first divergence or unreadable resource marks the transaction Degraded and
// returns ErrPlatformUnavailable with no OS mutation, no journal record and no
// new transaction. It never removes the address, changes the link, restores the
// MTU or clears the alias: those belong to Rollback/Close, and doing them here
// would let the kernel flush an externally replaced route as collateral. The
// caller holds n.mu.
func (n *linuxSystemNetwork) preflightAppliedOwnership(ctx context.Context, s *systemNetworkState) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	// The alias is the instance/epoch proof every other resource hangs on.
	if !n.aliasOwned {
		return n.preflightDegraded("instance", fmt.Sprintf("interface %q does not carry this transaction's ownership marker; nothing was released and the new address was not applied", n.linkName))
	}
	current, err := readInterfaceAlias(n.linkName)
	switch {
	case err != nil:
		return n.preflightDegraded("instance", fmt.Sprintf("interface alias of %q could not be read before retarget: %v; nothing was released and the new address was not applied", n.linkName, err))
	case current != n.instanceToken:
		return n.preflightDegraded("instance", fmt.Sprintf("interface alias is now %q, not this transaction's marker; the external alias is kept and nothing was released", current))
	}
	if n.applied.MTU {
		live, err := currentInterfaceMTU(n.linkName)
		switch {
		case err != nil:
			return n.preflightDegraded("mtu", fmt.Sprintf("MTU of %q could not be read before retarget: %v; nothing was released and the new address was not applied", n.linkName, err))
		case live != s.mtu:
			return n.preflightDegraded("mtu", fmt.Sprintf("MTU is now %d, not the %d this transaction set; the external value is kept and nothing was released", live, s.mtu))
		}
	}
	if n.applied.Address {
		found, exact, err := addressState(s.opts.Address, n.linkIndex)
		switch {
		case err != nil:
			return n.preflightDegraded("address "+s.opts.Address.String(), fmt.Sprintf("address %s on %q could not be read before retarget: %v; nothing was released and the new address was not applied", s.opts.Address, n.linkName, err))
		case !found:
			return n.preflightDegraded("address "+s.opts.Address.String(), fmt.Sprintf("address %s is no longer present on %q; nothing was released and the new address was not applied", s.opts.Address, n.linkName))
		case !exact:
			return n.preflightDegraded("address "+s.opts.Address.String(), fmt.Sprintf("address %s is now present with a different prefix length; the external address is kept and nothing was released", s.opts.Address.Addr()))
		}
	}
	for _, route := range n.applied.Routes {
		state, err := routeState(route, n.linkIndex)
		switch {
		case err != nil:
			return n.preflightDegraded("route "+route.String(), fmt.Sprintf("route %s on %q could not be read before retarget: %v; nothing was released and the new address was not applied", route, n.linkName, err))
		case !state.Found:
			return n.preflightDegraded("route "+route.String(), fmt.Sprintf("route %s is no longer present on %q; nothing was released and the new address was not applied", route, n.linkName))
		case !state.Exact:
			return n.preflightDegraded("route "+route.String(), fmt.Sprintf("route %s is now on interface index %d with different attributes; the external route is kept and nothing was released", route, state.Entry.ifindex))
		}
	}
	if n.applied.LinkUp {
		link, err := net.InterfaceByName(n.linkName)
		switch {
		case err != nil:
			return n.preflightDegraded("link_up", fmt.Sprintf("link state of %q could not be read before retarget: %v; nothing was released and the new address was not applied", n.linkName, err))
		case link.Flags&net.FlagUp == 0:
			return n.preflightDegraded("link_up", fmt.Sprintf("%q is now down, not the up state this transaction brought it to; the external link state is kept and nothing was released", n.linkName))
		}
	}
	return nil
}

// preflightDegraded records the divergence and returns the fail-closed error.
// markDegraded only appends to the in-memory detail list, so this performs no OS
// mutation and writes no journal record.

// retargetFailedLocked releases whatever the failed new transaction owns and
// best-effort restores the previous address in another fresh transaction. If
// the previous address cannot be restored safely it is left Degraded and the
// error is returned: the caller must fail closed, never pretend the packet path
// is continuous.

// resetTransactionLocked clears the per-transaction state before a fresh
// Prepare. The journal file and its lock stay open; only the transaction id and
// instance fingerprint are renewed.
func (n *linuxSystemNetwork) resetTransactionLocked(s *systemNetworkState) {
	s.current = SystemNetworkAbsent
	n.snapshot = linkSnapshot{}
	n.applied = appliedResources{}
	s.degraded = false
	s.degradedDetail = nil
	n.instance = ""
	n.instanceToken = ""
	n.priorAlias = ""
	n.aliasOwned = false
}

var _ SystemNetwork = (*linuxSystemNetwork)(nil)

// --- shared transaction state machine ---------------------------------------
//
// The methods below forward to the shared owner. They are the SystemNetwork
// interface plus the optional capabilities Agent.RetargetAddress uses.

// State implements SystemNetwork.
func (n *linuxSystemNetwork) State() SystemNetworkState {
	return n.owner.State()
}

// Prepare implements SystemNetwork.
func (n *linuxSystemNetwork) Prepare(ctx context.Context) error {
	return n.owner.Prepare(ctx)
}

// Apply implements SystemNetwork.
func (n *linuxSystemNetwork) Apply(ctx context.Context) error {
	return n.owner.Apply(ctx)
}

// Rollback implements SystemNetwork.
func (n *linuxSystemNetwork) Rollback(ctx context.Context) error {
	return n.owner.Rollback(ctx)
}

// Close implements SystemNetwork.
func (n *linuxSystemNetwork) Close() error {
	return n.owner.Close()
}

// DegradedDetail reports the external modifications rollback refused to
// overwrite. It is empty when rollback fully owned its resources.
func (n *linuxSystemNetwork) DegradedDetail() []string {
	return n.owner.DegradedDetail()
}

// Journal returns the in-memory view of this owner's write-ahead records.
func (n *linuxSystemNetwork) Journal() []journalEntry {
	return n.owner.Journal()
}

// RetargetAddress moves the local IPv4 /32 VirtualIP to a new /32 on the same
// device, without reopening it.
func (n *linuxSystemNetwork) RetargetAddress(ctx context.Context, address netip.Prefix) error {
	return n.owner.RetargetAddress(ctx, address)
}

// --- platform hooks --------------------------------------------------------

// journalInterfaceName is the interface the journal records are stamped with.
func (n *linuxSystemNetwork) journalInterfaceName(s *systemNetworkState) string {
	return n.linkName
}

// platformAddressFingerprint is this platform's ownership fingerprint for the
// configured address.
func (n *linuxSystemNetwork) platformAddressFingerprint(s *systemNetworkState) string {
	return encodeJournalFields(addressFingerprintFields(s.opts.Address)...)
}

// journalIntent records one write-ahead intent before an OS side effect.
func (n *linuxSystemNetwork) journalIntent(kind, resource, detail, fingerprint string) error {
	return n.owner.journalIntent(kind, resource, detail, fingerprint)
}

// journalConfirm records the durable outcome of an intent that already ran.
func (n *linuxSystemNetwork) journalConfirm(kind, resource, detail, fingerprint, outcome string) error {
	return n.owner.journalConfirm(kind, resource, detail, fingerprint, outcome)
}

// journalTerminal records the terminal checkpoint of this transaction.
func (n *linuxSystemNetwork) journalTerminal() error {
	return n.owner.journalTerminal()
}

// markDegraded records that the transaction could not be fully proven.
func (n *linuxSystemNetwork) markDegraded(kind, detail string) {
	n.owner.markDegraded(kind, detail)
}

// preflightDegraded records the degraded reason and fails closed.
func (n *linuxSystemNetwork) preflightDegraded(kind, detail string) error {
	return n.owner.preflightDegraded(kind, detail)
}

// retargetFailedLocked releases whatever the failed new transaction owned.
func (n *linuxSystemNetwork) retargetFailedLocked(ctx context.Context, previous netip.Prefix, cause error) error {
	return n.owner.retargetFailedLocked(ctx, previous, cause)
}

// addressFingerprint is this platform's ownership fingerprint for the
// configured address.
func (n *linuxSystemNetwork) addressFingerprintValue(s *systemNetworkState) string {
	return encodeJournalFields(addressFingerprintFields(s.opts.Address)...)
}
