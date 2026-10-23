package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
)

// systemNetworkState is the shared half of the platform SystemNetwork
// transaction.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// The three platform owners (sysnet_linux.go, sysnet_darwin.go,
// sysnet_windows.go) each implemented the same transaction state machine on
// their own struct. Normalising the three method bodies and comparing them word
// for word showed fourteen of them to be byte-identical: State, Prepare, Apply,
// Rollback, Close, DegradedDetail, Journal, RetargetAddress, addressFingerprint,
// journalIntent, journalConfirm, journalTerminal, markDegraded,
// preflightDegraded and retargetFailedLocked. Those fourteen live here.
//
// What stays in the platform files is what the platform's capabilities decide:
// the step list of Prepare and Apply, the ownership proof, and the rollback of
// resources the platform actually owns. Windows has no link_up step because a
// Wintun adapter has no link-up concept, and only Linux writes an instance
// alias marker; those are capability differences, not copies.
//
// The seam is deliberately narrow. A platform owner holds one of these and
// forwards the SystemNetwork methods to it; the platform-specific hooks below are
// the only way the shared state machine reaches the OS. The fingerprint formats
// stay per-platform: the journal file is one per node and shared by all three
// platforms, so a record written on Linux must still verify on Windows, and
// the shared code therefore passes fingerprints through as opaque strings.
//
// Locking: the shared state owns the one mutex. A platform owner reaches the
// shared state through the pointer below, so the platform hooks and the shared
// methods contend on the same lock — which the original code relied on, where
// the platform hooks were called with n.mu already held.

// systemNetworkState owns the transaction state, the degraded record and the
// journal. It holds no OS state: everything platform-specific is reached
// through the hooks on the platform owner.
type systemNetworkState struct {
	mu      sync.Mutex
	opts    SystemNetworkOptions
	mtu     int
	current SystemNetworkState
	journal *resourceJournal

	degraded       bool
	degradedDetail []string
}

// systemNetworkHooks are the platform-specific operations the shared state
// machine calls. A platform owner implements them; the shared code never
// touches the OS directly.
//
// The interface is the test surface: a test double can drive every branch of
// the shared state machine — degraded marking, ownership refusal, retarget
// rollback — without a live kernel.
//
// Every hook is called with the shared state's mutex already held, exactly as
// the original per-platform code called its own locked helpers.
type systemNetworkHooks interface {
	// prepareLocked snapshots the resources this transaction intends to own. It
	// performs no OS mutation.
	prepareLocked(ctx context.Context, s *systemNetworkState) error
	// applyLocked applies the platform's own step list.
	applyLocked(ctx context.Context, s *systemNetworkState) error
	// rollbackLocked releases exactly the resources this transaction owns.
	rollbackLocked(ctx context.Context, s *systemNetworkState) error
	// resetTransactionLocked clears the per-transaction platform state so a
	// fresh transaction starts from a clean baseline.
	resetTransactionLocked(s *systemNetworkState)
	// preflightAppliedOwnership proves the live resources still match this
	// transaction's recorded fingerprints, before any retarget side effect.
	preflightAppliedOwnership(ctx context.Context, s *systemNetworkState) error
	// journalInterfaceName is the interface the journal records are stamped
	// with. It is named apart from a platform's own linkName field so the
	// hook and that field can coexist.
	journalInterfaceName(s *systemNetworkState) string
	// platformAddressFingerprint is this platform's ownership fingerprint for
	// the configured address. The format stays per-platform: the journal is one
	// file per node, shared across platforms.
	platformAddressFingerprint(s *systemNetworkState) string
}

// systemNetworkOwner couples the shared state machine with one platform's
// hooks. The platform owner embeds it and forwards the SystemNetwork methods.
//
// It holds the shared state by pointer so the owner's view and the platform
// struct's embedded copy are the same memory: a retarget that changes the
// configured address is visible through both.
type systemNetworkOwner struct {
	state *systemNetworkState
	hooks systemNetworkHooks
}

func newSystemNetworkOwner(state *systemNetworkState, hooks systemNetworkHooks) systemNetworkOwner {
	return systemNetworkOwner{state: state, hooks: hooks}
}

// State implements SystemNetwork.
func (o *systemNetworkOwner) State() SystemNetworkState {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	return o.state.current
}

// Prepare resolves the interface and snapshots the resources this transaction
// intends to own. It performs no OS mutation.
func (o *systemNetworkOwner) Prepare(ctx context.Context) error {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	return o.hooks.prepareLocked(ctx, o.state)
}

// Apply installs the owned resources, journaling each intent before the side
// effect it describes.
func (o *systemNetworkOwner) Apply(ctx context.Context) error {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	return o.hooks.applyLocked(ctx, o.state)
}

// Rollback releases the owned resources in reverse order.
func (o *systemNetworkOwner) Rollback(ctx context.Context) error {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	return o.hooks.rollbackLocked(ctx, o.state)
}

// Close releases the transaction and the journal. It is idempotent.
func (o *systemNetworkOwner) Close() error {
	o.state.mu.Lock()
	if o.state.current == SystemNetworkClosed {
		o.state.mu.Unlock()
		return nil
	}
	pending := o.state.current != SystemNetworkAbsent
	o.state.mu.Unlock()
	var errs []error
	if pending {
		if err := o.Rollback(context.Background()); err != nil {
			errs = append(errs, err)
		}
	}
	if err := o.state.journal.close(); err != nil {
		errs = append(errs, err)
	}
	o.state.mu.Lock()
	o.state.current = SystemNetworkClosed
	o.state.mu.Unlock()
	return errors.Join(errs...)
}

// DegradedDetail reports why the last transaction could not be fully proven.
func (o *systemNetworkOwner) DegradedDetail() []string {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	return append([]string(nil), o.state.degradedDetail...)
}

// Journal returns the in-memory view of this owner's write-ahead records.
func (o *systemNetworkOwner) Journal() []journalEntry {
	return o.state.journal.snapshot()
}

// RetargetAddress moves the transaction's local VirtualIP to a new IPv4 /32 on
// the same device, without reopening it.
//
// 1. Prove ownership before the first side effect. Releasing the owned /32
// first would make the kernel drop an externally replaced device route as
// collateral; the retarget must fail here, with zero effects, instead.
// 2. Release exactly what this transaction owns. The alias proof means a
// user-owned or dangling alias is never touched.
// 3. Fresh transaction on the same journal and lock, then 4. fresh baseline
// and apply of the new /32 plus the configured routes and MTU.
func (o *systemNetworkOwner) RetargetAddress(ctx context.Context, address netip.Prefix) error {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	if !address.IsValid() || !address.Addr().Is4() || address.Bits() != 32 {
		return fmt.Errorf("%w: system_network.address must be an IPv4 /32 local VirtualIP, got %s", ErrInvalidConfig, address)
	}
	if o.state.current == SystemNetworkAbsent || o.state.current == SystemNetworkClosed {
		return fmt.Errorf("%w: RetargetAddress requires an active transaction, got %s", ErrInvalidConfig, o.state.current)
	}
	if o.state.opts.Address == address {
		return nil
	}
	previous := o.state.opts.Address
	if err := o.hooks.preflightAppliedOwnership(ctx, o.state); err != nil {
		return err
	}
	if err := o.hooks.rollbackLocked(ctx, o.state); err != nil {
		return err
	}
	if o.state.degraded {
		return fmt.Errorf("%w: the previous address could not be fully released; the new address was not applied (see DegradedDetail)", ErrPlatformUnavailable)
	}
	if err := o.state.journal.beginTransaction(); err != nil {
		return err
	}
	o.state.opts.Address = address
	o.hooks.resetTransactionLocked(o.state)
	if err := o.hooks.prepareLocked(ctx, o.state); err != nil {
		return o.retargetFailedLocked(ctx, previous, err)
	}
	if err := o.hooks.applyLocked(ctx, o.state); err != nil {
		return o.retargetFailedLocked(ctx, previous, err)
	}
	return nil
}

// retargetFailedLocked releases whatever the failed new transaction owned. If it
// cannot be fully released, stop: restoring the previous address would then
// stack another unproven transaction on top of a degraded one.
//
// The caller holds o.state.mu.
func (o *systemNetworkOwner) retargetFailedLocked(ctx context.Context, previous netip.Prefix, cause error) error {
	var errs []error
	if err := o.hooks.rollbackLocked(ctx, o.state); err != nil {
		errs = append(errs, err)
	}
	if o.state.degraded {
		return errors.Join(cause, errors.Join(errs...))
	}
	if !previous.IsValid() {
		return errors.Join(cause, errors.Join(errs...))
	}
	// Restore the ORIGINAL address, never the failed new one.
	if err := o.state.journal.beginTransaction(); err != nil {
		errs = append(errs, err)
		return errors.Join(cause, errors.Join(errs...))
	}
	o.state.opts.Address = previous
	o.hooks.resetTransactionLocked(o.state)
	if err := o.hooks.prepareLocked(ctx, o.state); err != nil {
		errs = append(errs, fmt.Errorf("agent: restore address %s: %w", previous, err))
		return errors.Join(cause, errors.Join(errs...))
	}
	if err := o.hooks.applyLocked(ctx, o.state); err != nil {
		if rollbackErr := o.hooks.rollbackLocked(ctx, o.state); rollbackErr != nil {
			errs = append(errs, rollbackErr)
		}
		errs = append(errs, fmt.Errorf("agent: restore address %s: %w", previous, err))
	}
	return errors.Join(cause, errors.Join(errs...))
}

// markDegraded records that the transaction could not be fully proven.
//
// The caller holds o.state.mu.
func (o *systemNetworkOwner) markDegraded(kind, detail string) {
	o.state.degraded = true
	o.state.degradedDetail = append(o.state.degradedDetail, kind+": "+detail)
}

// preflightDegraded records the degraded reason and fails closed.
//
// The caller holds o.state.mu.
func (o *systemNetworkOwner) preflightDegraded(kind, detail string) error {
	o.markDegraded(kind, detail)
	return fmt.Errorf("%w: the previous transaction no longer provably owns %s; nothing was released and the new address was not applied", ErrPlatformUnavailable, kind)
}

// journalIntent records one write-ahead intent before an OS side effect.
func (o *systemNetworkOwner) journalIntent(kind, resource, detail, fingerprint string) error {
	return o.state.journal.record(kind, resource, o.hooks.journalInterfaceName(o.state), detail, fingerprint)
}

// journalConfirm records the durable outcome of an intent that already ran.
func (o *systemNetworkOwner) journalConfirm(kind, resource, detail, fingerprint, outcome string) error {
	return o.state.journal.confirm(kind, resource, o.hooks.journalInterfaceName(o.state), detail, fingerprint, outcome)
}

// journalTerminal records the terminal checkpoint of this transaction.
func (o *systemNetworkOwner) journalTerminal() error {
	if o.state.degraded {
		return o.state.journal.terminal(o.hooks.journalInterfaceName(o.state), "degraded")
	}
	return o.state.journal.terminal(o.hooks.journalInterfaceName(o.state), "rolledback")
}

// addressFingerprint is the platform's ownership fingerprint for the configured
// address. The format is per-platform and the shared code passes it through
// unchanged: the journal is one file per node, shared across platforms.
func (o *systemNetworkOwner) addressFingerprint() string {
	return o.hooks.platformAddressFingerprint(o.state)
}

// addressFingerprintFields renders the common address fingerprint. The shared
// code uses it so the three platforms agree on the address part of the
// fingerprint; each platform adds its own instance fields.
func addressFingerprintFields(address netip.Prefix) [][2]string {
	return [][2]string{
		{"addr", address.Addr().String()},
		{"prefixlen", strconv.Itoa(address.Bits())},
	}
}
