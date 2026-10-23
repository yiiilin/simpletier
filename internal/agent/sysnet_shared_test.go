package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// fakeSystemNetworkHooks is a test double for the platform hooks of the shared
// SystemNetwork transaction state machine.
//
// It exists so every branch of the shared state machine — degraded marking,
// ownership refusal, retarget rollback, terminal checkpointing — can be driven
// without a live kernel. Before the shared state machine was extracted, the
// Darwin and Linux owners had no such double: their transaction tests needed
// root or a network entitlement and skipped instead.
type fakeSystemNetworkHooks struct {
	prepareErr   error
	applyErr     error
	rollbackErr  error
	preflightErr error

	prepareCalls   int
	applyCalls     int
	rollbackCalls  int
	resetCalls     int
	preflightCalls int

	// prepareErrOnce fails only the first Prepare, so a retarget can fail after
	// a successful prepare.
	prepareErrOnce error
}

// prepareLocked mirrors the real platform hook: it refuses a transaction that
// is not absent and moves the state to Prepared.
func (f *fakeSystemNetworkHooks) prepareLocked(ctx context.Context, s *systemNetworkState) error {
	f.prepareCalls++
	if f.prepareErrOnce != nil {
		err := f.prepareErrOnce
		f.prepareErrOnce = nil
		return err
	}
	if f.prepareErr != nil {
		return f.prepareErr
	}
	if s.current != SystemNetworkAbsent {
		return fmt.Errorf("%w: Prepare requires the absent state, got %s", ErrInvalidConfig, s.current)
	}
	s.current = SystemNetworkPrepared
	return nil
}

// applyLocked mirrors the real platform hook: it refuses a transaction that is
// not prepared and moves the state to Applied.
func (f *fakeSystemNetworkHooks) applyLocked(ctx context.Context, s *systemNetworkState) error {
	f.applyCalls++
	if f.applyErr != nil {
		return f.applyErr
	}
	if s.current != SystemNetworkPrepared {
		return fmt.Errorf("%w: Apply requires the prepared state, got %s", ErrInvalidConfig, s.current)
	}
	s.current = SystemNetworkApplied
	return nil
}

// rollbackLocked mirrors the real platform hook: it releases the transaction,
// records the terminal checkpoint the journal requires before a new transaction
// may start, and leaves the state at Degraded or Rollback — never Absent, which
// is what the real hooks do (see sysnet_linux.go rollbackLocked).
func (f *fakeSystemNetworkHooks) rollbackLocked(ctx context.Context, s *systemNetworkState) error {
	f.rollbackCalls++
	if f.rollbackErr != nil {
		return f.rollbackErr
	}
	if err := f.journalTerminal(s); err != nil {
		return err
	}
	if s.degraded {
		s.current = SystemNetworkDegraded
	} else {
		s.current = SystemNetworkRollback
	}
	return nil
}

// journalTerminal writes the terminal checkpoint through the shared owner.
func (f *fakeSystemNetworkHooks) journalTerminal(s *systemNetworkState) error {
	if s.degraded {
		return s.journal.terminal(f.journalInterfaceName(s), "degraded")
	}
	return s.journal.terminal(f.journalInterfaceName(s), "rolledback")
}

// resetTransactionLocked mirrors the real platform hook: a fresh transaction
// starts from a clean baseline, including no leftover degraded record.
func (f *fakeSystemNetworkHooks) resetTransactionLocked(s *systemNetworkState) {
	f.resetCalls++
	s.current = SystemNetworkAbsent
	s.degraded = false
	s.degradedDetail = nil
}

func (f *fakeSystemNetworkHooks) preflightAppliedOwnership(ctx context.Context, s *systemNetworkState) error {
	f.preflightCalls++
	return f.preflightErr
}

func (f *fakeSystemNetworkHooks) journalInterfaceName(s *systemNetworkState) string {
	return "fake0"
}

func (f *fakeSystemNetworkHooks) platformAddressFingerprint(s *systemNetworkState) string {
	return encodeJournalFields(addressFingerprintFields(s.opts.Address)...)
}

// newFakeSystemNetworkOwner builds a shared owner over an in-memory journal.
func newFakeSystemNetworkOwner(t *testing.T, opts SystemNetworkOptions, hooks systemNetworkHooks) systemNetworkOwner {
	t.Helper()
	journal, err := newResourceJournal("")
	if err != nil {
		t.Fatal(err)
	}
	return newSystemNetworkOwner(&systemNetworkState{
		opts:    opts,
		mtu:     opts.mtu(),
		current: SystemNetworkAbsent,
		journal: journal,
	}, hooks)
}

func fakeSystemNetworkOptions() SystemNetworkOptions {
	return SystemNetworkOptions{
		Interface: "fake0",
		Address:   netip.MustParsePrefix("10.240.0.1/32"),
	}
}

// TestSharedStateMachinePrepareApplyRollback drives the shared transaction
// through one full cycle and checks that the platform hooks are called in the
// order the contract requires.
func TestSharedStateMachinePrepareApplyRollback(t *testing.T) {
	hooks := &fakeSystemNetworkHooks{}
	owner := newFakeSystemNetworkOwner(t, fakeSystemNetworkOptions(), hooks)

	if got := owner.State(); got != SystemNetworkAbsent {
		t.Fatalf("State = %s, want %s", got, SystemNetworkAbsent)
	}
	if err := owner.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := owner.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := owner.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if hooks.prepareCalls != 1 || hooks.applyCalls != 1 || hooks.rollbackCalls != 1 {
		t.Fatalf("hook calls = prepare %d apply %d rollback %d, want 1/1/1",
			hooks.prepareCalls, hooks.applyCalls, hooks.rollbackCalls)
	}
}

// TestSharedStateMachineCloseIsIdempotent checks the shared Close: a second
// Close must not roll back again, and a Close on an absent transaction must
// not roll back at all.
func TestSharedStateMachineCloseIsIdempotent(t *testing.T) {
	hooks := &fakeSystemNetworkHooks{}
	owner := newFakeSystemNetworkOwner(t, fakeSystemNetworkOptions(), hooks)

	if err := owner.Close(); err != nil {
		t.Fatalf("Close on an absent transaction: %v", err)
	}
	if hooks.rollbackCalls != 0 {
		t.Fatalf("Close on an absent transaction rolled back %d times, want 0", hooks.rollbackCalls)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := owner.State(); got != SystemNetworkClosed {
		t.Fatalf("State after Close = %s, want %s", got, SystemNetworkClosed)
	}
}

// TestSharedStateMachinePrepareRequiresAbsentState checks the state guard:
// Prepare must refuse a transaction that is not absent.
func TestSharedStateMachinePrepareRequiresAbsentState(t *testing.T) {
	hooks := &fakeSystemNetworkHooks{}
	owner := newFakeSystemNetworkOwner(t, fakeSystemNetworkOptions(), hooks)
	if err := owner.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	err := owner.Prepare(context.Background())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("second Prepare error = %v, want ErrInvalidConfig", err)
	}
}

// TestSharedStateMachineDegradedDetail checks that the degraded reason is
// recorded and readable, and that the caller's copy cannot mutate it.
func TestSharedStateMachineDegradedDetail(t *testing.T) {
	hooks := &fakeSystemNetworkHooks{}
	owner := newFakeSystemNetworkOwner(t, fakeSystemNetworkOptions(), hooks)

	owner.markDegraded("mtu", "the external value is kept")
	detail := owner.DegradedDetail()
	if len(detail) != 1 || !strings.Contains(detail[0], "mtu") {
		t.Fatalf("DegradedDetail = %v, want one entry mentioning mtu", detail)
	}
	detail[0] = "mutated"
	if again := owner.DegradedDetail(); again[0] == "mutated" {
		t.Fatal("DegradedDetail returned the caller's slice, not a copy")
	}
}

// TestSharedStateMachinePreflightDegradedFailsClosed checks that a degraded
// preflight fails with ErrPlatformUnavailable and records why.
func TestSharedStateMachinePreflightDegradedFailsClosed(t *testing.T) {
	hooks := &fakeSystemNetworkHooks{}
	owner := newFakeSystemNetworkOwner(t, fakeSystemNetworkOptions(), hooks)

	err := owner.preflightDegraded("route", "the external route is kept")
	if !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("preflightDegraded error = %v, want ErrPlatformUnavailable", err)
	}
	if detail := owner.DegradedDetail(); len(detail) == 0 {
		t.Fatal("preflightDegraded recorded no degraded detail")
	}
}

// TestSharedStateMachineRetargetRefusesWithoutOwnership checks the retarget
// preflight: when the platform cannot prove ownership, the retarget must fail
// with zero effects.
func TestSharedStateMachineRetargetRefusesWithoutOwnership(t *testing.T) {
	hooks := &fakeSystemNetworkHooks{preflightErr: errors.New("the adapter identity changed")}
	owner := newFakeSystemNetworkOwner(t, fakeSystemNetworkOptions(), hooks)
	if err := owner.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := owner.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	before := owner.state.opts.Address
	err := owner.RetargetAddress(context.Background(), netip.MustParsePrefix("10.240.0.2/32"))
	if err == nil {
		t.Fatal("RetargetAddress succeeded without an ownership proof")
	}
	if hooks.rollbackCalls != 0 {
		t.Fatalf("a refused retarget rolled back %d times, want 0", hooks.rollbackCalls)
	}
	if owner.state.opts.Address != before {
		t.Fatalf("a refused retarget changed the address to %s, want %s", owner.state.opts.Address, before)
	}
}

// TestSharedStateMachineRetargetMovesAddress checks the successful retarget: a
// fresh transaction starts on the same journal and the new address is the one
// the transaction carries.
func TestSharedStateMachineRetargetMovesAddress(t *testing.T) {
	hooks := &fakeSystemNetworkHooks{}
	owner := newFakeSystemNetworkOwner(t, fakeSystemNetworkOptions(), hooks)
	if err := owner.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := owner.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	newAddress := netip.MustParsePrefix("10.240.0.2/32")
	if err := owner.RetargetAddress(context.Background(), newAddress); err != nil {
		t.Fatalf("RetargetAddress: %v", err)
	}
	if owner.state.opts.Address != newAddress {
		t.Fatalf("transaction address = %s, want %s", owner.state.opts.Address, newAddress)
	}
	if hooks.resetCalls != 1 {
		t.Fatalf("resetTransactionLocked called %d times, want 1", hooks.resetCalls)
	}
}

// TestSharedStateMachineRetargetRejectsNonHostRoute checks the address
// validation the retarget shares with the platform owners.
func TestSharedStateMachineRetargetRejectsNonHostRoute(t *testing.T) {
	hooks := &fakeSystemNetworkHooks{}
	owner := newFakeSystemNetworkOwner(t, fakeSystemNetworkOptions(), hooks)
	if err := owner.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := owner.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, address := range []netip.Prefix{
		netip.MustParsePrefix("10.240.0.2/24"),
		netip.MustParsePrefix("2001:db8::1/128"),
	} {
		err := owner.RetargetAddress(context.Background(), address)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("RetargetAddress(%s) error = %v, want ErrInvalidConfig", address, err)
		}
	}
	if hooks.preflightCalls != 0 {
		t.Fatalf("a rejected address reached the ownership preflight %d times, want 0", hooks.preflightCalls)
	}
}

// TestSharedStateMachineJournalRecordsTerminalOutcome checks that the shared
// terminal checkpoint distinguishes a degraded transaction from a clean one.
func TestSharedStateMachineJournalRecordsTerminalOutcome(t *testing.T) {
	hooks := &fakeSystemNetworkHooks{}
	owner := newFakeSystemNetworkOwner(t, fakeSystemNetworkOptions(), hooks)
	if err := owner.journalTerminal(); err != nil {
		t.Fatalf("journalTerminal: %v", err)
	}
	entries := owner.Journal()
	if len(entries) == 0 {
		t.Fatal("journalTerminal recorded nothing")
	}
	last := entries[len(entries)-1]
	if last.Detail != "rolledback" {
		t.Fatalf("terminal detail = %q, want %q", last.Detail, "rolledback")
	}

	owner.markDegraded("mtu", "the external value is kept")
	if err := owner.journalTerminal(); err != nil {
		t.Fatalf("journalTerminal (degraded): %v", err)
	}
	entries = owner.Journal()
	last = entries[len(entries)-1]
	if last.Detail != "degraded" {
		t.Fatalf("degraded terminal detail = %q, want %q", last.Detail, "degraded")
	}
}

// TestSharedStateMachineRollbackLeavesDegradedState checks the state a
// rollback leaves behind, which is what the retarget path branches on.
//
// The shared state machine reads the degraded flag, not the state, after a
// rollback. A test double that left the state at Absent would hide a platform
// hook that failed to record the degradation, so the double must mirror the real
// hooks: Rollback leaves the state at Degraded when something could not be
// proven, and at Rollback otherwise — never Absent.
func TestSharedStateMachineRollbackLeavesDegradedState(t *testing.T) {
	hooks := &fakeSystemNetworkHooks{}
	owner := newFakeSystemNetworkOwner(t, fakeSystemNetworkOptions(), hooks)
	if err := owner.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := owner.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := owner.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := owner.State(); got != SystemNetworkRollback {
		t.Fatalf("State after a clean Rollback = %s, want %s", got, SystemNetworkRollback)
	}

	// A rollback that could not prove ownership leaves the state Degraded, and
	// the retarget must then refuse rather than stack a new transaction on top.
	hooks2 := &fakeSystemNetworkHooks{}
	owner2 := newFakeSystemNetworkOwner(t, fakeSystemNetworkOptions(), hooks2)
	if err := owner2.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := owner2.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	owner2.markDegraded("route", "the external route is kept")
	if err := owner2.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := owner2.State(); got != SystemNetworkDegraded {
		t.Fatalf("State after a degraded Rollback = %s, want %s", got, SystemNetworkDegraded)
	}
	if err := owner2.RetargetAddress(context.Background(), netip.MustParsePrefix("10.240.0.2/32")); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("RetargetAddress after a degraded rollback error = %v, want ErrPlatformUnavailable", err)
	}
}
