package security

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// linkAttemptGateCount reports the number of live serialization slots. It is a
// test-only introspection helper kept out of production code; it takes the same
// lock as the gate and never blocks on I/O.
func linkAttemptGateCount() int {
	linkAttemptGates.mu.Lock()
	defer linkAttemptGates.mu.Unlock()
	return len(linkAttemptGates.entries)
}

// linkAttemptGateState reports the accounting of one slot so cancellation
// regressions can synchronize on real gate state instead of sleeping.
func linkAttemptGateState(key string) (refs, tokens int) {
	linkAttemptGates.mu.Lock()
	defer linkAttemptGates.mu.Unlock()
	entry := linkAttemptGates.entries[key]
	if entry == nil {
		return 0, 0
	}
	return entry.refs, len(entry.token)
}

func withGateEntry(t *testing.T, key string, mutate func(*linkAttemptGateEntry)) {
	t.Helper()
	linkAttemptGates.mu.Lock()
	defer linkAttemptGates.mu.Unlock()
	entry := linkAttemptGates.entries[key]
	if entry == nil {
		t.Fatalf("no gate entry for key %q", key)
	}
	mutate(entry)
}

// waitGateRefs blocks until the live slot for key reports want references. It
// synchronizes on the gate's own accounting and yields the scheduler instead of
// sleeping a fixed interval.
func waitGateRefs(t *testing.T, key string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if refs, _ := linkAttemptGateState(key); refs == want {
			return
		}
		runtime.Gosched()
	}
	refs, tokens := linkAttemptGateState(key)
	t.Fatalf("gate refs = %d tokens = %d; want refs = %d", refs, tokens, want)
}

func TestAcquireLinkAttemptSerializesHolders(t *testing.T) {
	contextID := [32]byte{1}
	first, err := AcquireLinkAttempt(context.Background(), "scope", contextID, 0)
	if err != nil {
		t.Fatal(err)
	}

	second := make(chan *LinkAttemptLease, 1)
	secondErr := make(chan error, 1)
	go func() {
		lease, err := AcquireLinkAttempt(context.Background(), "scope", contextID, 0)
		if err != nil {
			secondErr <- err
			return
		}
		second <- lease
	}()

	// The second acquirer must block while the first holds the slot.
	select {
	case lease := <-second:
		lease.Release()
		t.Fatal("second acquirer was not serialized")
	case err := <-secondErr:
		t.Fatalf("second acquirer failed early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	first.Release()
	select {
	case lease := <-second:
		lease.Release()
	case err := <-secondErr:
		t.Fatalf("second acquirer failed after release: %v", err)
	case <-time.After(time.Second):
		t.Fatal("second acquirer never obtained the released slot")
	}
	// Double release must be harmless.
	first.Release()
	if got := linkAttemptGateCount(); got != 0 {
		t.Fatalf("live gate entries = %d; want 0", got)
	}
}

func TestAcquireLinkAttemptCancellationCleansUp(t *testing.T) {
	contextID := [32]byte{2}
	holder, err := AcquireLinkAttempt(context.Background(), "scope", contextID, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		lease, err := AcquireLinkAttempt(ctx, "scope", contextID, 1)
		if err == nil {
			lease.Release()
		}
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled acquire = %v; want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled acquirer did not return")
	}
	holder.Release()
	if got := linkAttemptGateCount(); got != 0 {
		t.Fatalf("canceled acquisition leaked gate entries: %d", got)
	}
}

// Regression: a waiter that is cancelled before it ever receives the token must
// not manufacture a free token. The original release path decremented refs and
// then pushed a token whenever any reference remained, so a cancelled waiter
// handed the still-held slot to a peer and two acquirers could hold the same
// slot at once.
//
// State under test: one holder, two queued waiters (their refs are registered
// exactly as AcquireLinkAttempt registers them before its select), and one
// waiter that cancels. The slot must stay empty until the holder itself
// releases.
func TestAcquireLinkAttemptCancelledWaiterMustNotReleaseHeldToken(t *testing.T) {
	contextID := [32]byte{7}
	key := linkAttemptKey("scope", contextID, 0)
	holder, err := AcquireLinkAttempt(context.Background(), "scope", contextID, 0)
	if err != nil {
		t.Fatal(err)
	}

	withGateEntry(t, key, func(entry *linkAttemptGateEntry) { entry.refs += 2 })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AcquireLinkAttempt(ctx, "scope", contextID, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled acquire = %v; want context.Canceled", err)
	}

	refs, tokens := linkAttemptGateState(key)
	if tokens != 0 {
		t.Fatalf("cancelled waiter freed the held slot: tokens=%d refs=%d", tokens, refs)
	}
	if refs != 3 {
		t.Fatalf("gate refs = %d; want 3 (holder + two waiters)", refs)
	}

	// Only the holder itself may hand the slot on: exactly one token appears.
	holder.Release()
	refs, tokens = linkAttemptGateState(key)
	if tokens != 1 || refs != 2 {
		t.Fatalf("after holder release: tokens=%d refs=%d; want tokens=1 refs=2", tokens, refs)
	}

	// Drop the simulated waiters so the package gate map does not leak into
	// other tests.
	linkAttemptGates.mu.Lock()
	delete(linkAttemptGates.entries, key)
	linkAttemptGates.mu.Unlock()
}

// Regression companion: with real queued waiters, cancelling one must leave the
// remaining waiter blocked until the holder releases; the survivor then gets the
// slot and the gate map drains to zero.
func TestAcquireLinkAttemptCancelledWaiterKeepsRemainingWaiterBlocked(t *testing.T) {
	contextID := [32]byte{8}
	key := linkAttemptKey("scope", contextID, 0)

	holder, err := AcquireLinkAttempt(context.Background(), "scope", contextID, 0)
	if err != nil {
		t.Fatal(err)
	}

	wAcquired := make(chan *LinkAttemptLease, 1)
	go func() {
		lease, err := AcquireLinkAttempt(context.Background(), "scope", contextID, 0)
		if err != nil {
			return
		}
		wAcquired <- lease
	}()
	waitGateRefs(t, key, 2)

	cCtx, cCancel := context.WithCancel(context.Background())
	cDone := make(chan error, 1)
	go func() {
		_, err := AcquireLinkAttempt(cCtx, "scope", contextID, 0)
		cDone <- err
	}()
	waitGateRefs(t, key, 3)

	cCancel()
	if err := <-cDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter error = %v; want context.Canceled", err)
	}

	// The cancelled waiter never owned the token, so it must not hand the slot to
	// the surviving waiter while the holder is still active.
	refs, tokens := linkAttemptGateState(key)
	if tokens != 0 {
		t.Fatalf("cancelled waiter freed a token while holder active: tokens=%d refs=%d", tokens, refs)
	}
	if refs != 2 {
		t.Fatalf("gate refs = %d; want 2 (holder + surviving waiter)", refs)
	}
	select {
	case lease := <-wAcquired:
		lease.Release()
		t.Fatal("surviving waiter acquired while the holder still owned the slot")
	default:
	}

	holder.Release()
	select {
	case lease := <-wAcquired:
		lease.Release()
	case <-time.After(time.Second):
		t.Fatal("surviving waiter never acquired after the holder released")
	}
	if got := linkAttemptGateCount(); got != 0 {
		t.Fatalf("gate map leaked after cancellation: %d", got)
	}
}

// Regression: Release must stay idempotent even if a caller copies the lease
// value. The lease shares one heap-allocated Once across copies, so a second
// Release may not refund the slot a second time.
func TestLinkAttemptLeaseValueCopySharesReleaseOnce(t *testing.T) {
	contextID := [32]byte{9}
	key := linkAttemptKey("scope", contextID, 0)
	lease, err := AcquireLinkAttempt(context.Background(), "scope", contextID, 0)
	if err != nil {
		t.Fatal(err)
	}
	copied := *lease

	next := make(chan *LinkAttemptLease, 1)
	go func() {
		acquired, err := AcquireLinkAttempt(context.Background(), "scope", contextID, 0)
		if err != nil {
			return
		}
		next <- acquired
	}()
	waitGateRefs(t, key, 2)

	lease.Release()
	var waiter *LinkAttemptLease
	select {
	case waiter = <-next:
	case <-time.After(time.Second):
		t.Fatal("waiter did not acquire after Release")
	}

	copied.Release()
	if refs, _ := linkAttemptGateState(key); refs != 1 {
		t.Fatalf("value-copy Release refunded the slot twice: refs=%d; want 1", refs)
	}
	waiter.Release()
	if got := linkAttemptGateCount(); got != 0 {
		t.Fatalf("gate map leaked: %d", got)
	}
}

func TestAcquireLinkAttemptDeadlineCleansUpWithoutHolder(t *testing.T) {
	contextID := [32]byte{3}
	holder, err := AcquireLinkAttempt(context.Background(), "scope", contextID, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := AcquireLinkAttempt(ctx, "scope", contextID, 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed-out acquire = %v; want context.DeadlineExceeded", err)
	}
	holder.Release()
	if got := linkAttemptGateCount(); got != 0 {
		t.Fatalf("timed-out acquisition leaked gate entries: %d", got)
	}
}

func TestAcquireLinkAttemptIsIsolatedByContextDirectoryAndLane(t *testing.T) {
	stateDirA := t.TempDir()
	contextA := [32]byte{4}
	contextB := [32]byte{5}
	holder, err := AcquireLinkAttempt(context.Background(), "scope", contextA, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()

	keys := []struct {
		name      string
		stateDir  string
		contextID [32]byte
		lane      uint8
	}{
		{"different context", stateDirA, contextB, 0},
		{"different lane", stateDirA, contextA, 1},
	}
	for _, key := range keys {
		t.Run(key.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			lease, err := AcquireLinkAttempt(ctx, "scope", key.contextID, key.lane)
			if err != nil {
				t.Fatalf("independent key blocked on unrelated holder: %v", err)
			}
			lease.Release()
		})
	}
}

func TestAcquireLinkAttemptRejectsInvalidKeys(t *testing.T) {
	var contextID [32]byte
	for _, tc := range []struct {
		name     string
		ctx      context.Context
		stateDir string
		context  [32]byte
		lane     uint8
	}{
		{"nil context", nil, "state", [32]byte{1}, 0},
		{"zero context", context.Background(), "state", contextID, 0},
		{"bad lane", context.Background(), "state", [32]byte{1}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := AcquireLinkAttempt(tc.ctx, "scope", tc.context, tc.lane); !errors.Is(err, ErrInvalidLinkAttempt) {
				t.Fatalf("error = %v; want ErrInvalidLinkAttempt", err)
			}
		})
	}
}

func TestAcquireLinkAttemptConcurrentWaitersMakeProgress(t *testing.T) {
	contextID := [32]byte{6}
	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	order := make(chan int, workers)
	for index := 0; index < workers; index++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			lease, err := AcquireLinkAttempt(ctx, "scope", contextID, 2)
			if err != nil {
				errs <- err
				return
			}
			order <- id
			lease.Release()
		}(index)
	}
	wg.Wait()
	close(errs)
	close(order)
	for err := range errs {
		t.Fatal(err)
	}
	seen := 0
	for range order {
		seen++
	}
	if seen != workers {
		t.Fatalf("serialized acquisitions = %d; want %d", seen, workers)
	}
	if got := linkAttemptGateCount(); got != 0 {
		t.Fatalf("gate map leaked after concurrent use: %d", got)
	}
}
