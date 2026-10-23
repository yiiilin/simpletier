package topology

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// factTestStateBudget is a recording StateBudget: it keeps exactly one
// reservation, reports the bytes it currently holds and can be switched to
// refuse, so the store's shared-allocator refusal path is exercised without
// lowering any frozen limit.
type factTestStateBudget struct {
	mu       sync.Mutex
	refuse   bool
	reserves int
	resizes  int
	held     uint64
}

func (b *factTestStateBudget) ResizeState(want uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.refuse {
		return false
	}
	if b.held == 0 {
		b.reserves++
	} else {
		b.resizes++
	}
	b.held = want
	return true
}

func (b *factTestStateBudget) ReleaseState() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.held = 0
}

func (b *factTestStateBudget) setRefuse(refuse bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refuse = refuse
}

func (b *factTestStateBudget) reservation() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.held
}

func (b *factTestStateBudget) counts() (reserves, resizes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reserves, b.resizes
}

// factTestLiveOwnedBytes is the store's own owned-byte figure for its currently
// published maps: the same accounting the store books, read back from the live
// state rather than from the candidate it staged.
func factTestLiveOwnedBytes(fs *FactStore) uint64 {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return uint64(ownedFactStoreBytes(&factStoreCandidate{
		entries:    fs.entries,
		tombstones: fs.tombstones,
		hwm:        fs.hwm,
		senders:    fs.senders,
	}))
}

// TestFactStoreStateBudgetTracksOwnedBytes proves an attached StateBudget holds
// exactly one reservation and that it is sized to the store's owned bytes: it is
// first reserved at the first publish, resized in place (never stacked) as the
// published state grows, and resized back down when the state is reaped.
func TestFactStoreStateBudgetTracksOwnedBytes(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-a"))
	budget := &factTestStateBudget{}
	env.fs.SetStateBudget(budget)
	source := factTestSource(env.contextID, 1, 1)

	first := factTestNodeRecord(factTestPub(1), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, source, []FactRecord{first}, factTestNow); err != nil {
		t.Fatalf("commit first fact: %v", err)
	}
	firstWant := budget.reservation()
	if firstWant == 0 {
		t.Fatal("the first publish booked no FACT state")
	}
	if want := factTestLiveOwnedBytes(env.fs); firstWant != want {
		t.Fatalf("reservation = %d bytes; want the store's owned bytes %d", firstWant, want)
	}
	if reserves, resizes := budget.counts(); reserves != 1 || resizes != 0 {
		t.Fatalf("reserves/resizes = %d/%d after the first publish; want 1/0 (one reservation)", reserves, resizes)
	}

	second := factTestNodeRecord(factTestPub(2), nil, FactVersion{2, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 2, 1, source, []FactRecord{second}, factTestNow); err != nil {
		t.Fatalf("commit second fact: %v", err)
	}
	secondWant := budget.reservation()
	if want := factTestLiveOwnedBytes(env.fs); secondWant != want {
		t.Fatalf("reservation = %d bytes; want the store's owned bytes %d", secondWant, want)
	}
	if secondWant <= firstWant {
		t.Fatalf("reservation did not grow with the published state: %d -> %d", firstWant, secondWant)
	}
	if reserves, resizes := budget.counts(); reserves != 1 || resizes != 1 {
		t.Fatalf("reserves/resizes = %d/%d after the second publish; want 1/1 (resized in place)", reserves, resizes)
	}

	// Past both validity windows an empty snapshot reaps every live entry, so the
	// same single reservation has to shrink with the published state.
	later := factTestNow.Add(2 * time.Minute)
	if err := factTestCommit(t, env.fs, 3, 1, source, nil, later); err != nil {
		t.Fatalf("commit reaping snapshot: %v", err)
	}
	reapedWant := budget.reservation()
	if want := factTestLiveOwnedBytes(env.fs); reapedWant != want {
		t.Fatalf("reservation = %d bytes after reap; want the store's owned bytes %d", reapedWant, want)
	}
	if reapedWant >= secondWant {
		t.Fatalf("reservation did not shrink after the reap: %d -> %d", secondWant, reapedWant)
	}
	if reserves, _ := budget.counts(); reserves != 1 {
		t.Fatalf("reserves = %d; the store must hold exactly one reservation", reserves)
	}
}

// TestFactStoreStateBudgetRefusalKeepsPreviousState proves a refused booking
// fails the publish with the same ErrFactTooLarge a peer already sees as
// REJECT(resource), leaves the previously published facts and view version
// untouched, and leaves no partial state behind: the same snapshot still
// commits once the allocator accepts again, which also proves the durable
// watermark write had not run.
func TestFactStoreStateBudgetRefusalKeepsPreviousState(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-a"))
	budget := &factTestStateBudget{}
	env.fs.SetStateBudget(budget)
	source := factTestSource(env.contextID, 1, 1)

	first := factTestNodeRecord(factTestPub(1), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, source, []FactRecord{first}, factTestNow); err != nil {
		t.Fatalf("commit first fact: %v", err)
	}
	held := budget.reservation()
	version := env.fs.Version()
	firstKey := factTestFactKey(t, first)

	second := factTestNodeRecord(factTestPub(2), nil, FactVersion{2, 1}, factTestIssued, factTestExpires)
	secondKey := factTestFactKey(t, second)
	budget.setRefuse(true)
	if err := factTestCommit(t, env.fs, 2, 1, source, []FactRecord{second}, factTestNow); !errors.Is(err, ErrFactTooLarge) {
		t.Fatalf("refused commit error = %v; want ErrFactTooLarge", err)
	}

	assertPreviousStateIntact := func(t *testing.T, phase string) {
		t.Helper()
		if got := budget.reservation(); got != held {
			t.Fatalf("reservation after %s = %d; want the previous %d still in force", phase, got, held)
		}
		records, gotVersion, err := env.fs.Snapshot(factTestNow)
		if err != nil {
			t.Fatalf("snapshot after %s: %v", phase, err)
		}
		if gotVersion != version {
			t.Fatalf("view version after %s = %d; want the previous %d", phase, gotVersion, version)
		}
		if len(records) != 1 || records[0].Envelope.Origin != first.Envelope.Origin {
			t.Fatalf("snapshot after %s holds %d records; want exactly the previously published one", phase, len(records))
		}
		if !env.fs.IsCurrent(firstKey, first.Envelope.Version, factTestNow) {
			t.Fatalf("the previously published fact is no longer current after %s", phase)
		}
		if env.fs.IsCurrent(secondKey, second.Envelope.Version, factTestNow) {
			t.Fatalf("the refused fact became visible after %s", phase)
		}
	}
	assertPreviousStateIntact(t, "a refused commit")

	// The same port refusal must gate a local publish: no local fact may become
	// live while the shared allocator refuses to book it.
	local := factTestNodeRecord(factTestLocalPublic(env.privateKey), nil, FactVersion{5, 1}, factTestIssued, factTestExpires)
	if err := env.fs.PublishLocal([]FactRecord{local}, factTestNow); !errors.Is(err, ErrFactTooLarge) {
		t.Fatalf("refused PublishLocal error = %v; want ErrFactTooLarge", err)
	}
	assertPreviousStateIntact(t, "a refused local publish")

	// Nothing was persisted for the refused candidate: the identical snapshot
	// still commits and becomes visible once the allocator accepts again.
	budget.setRefuse(false)
	if err := factTestCommit(t, env.fs, 2, 1, source, []FactRecord{second}, factTestNow); err != nil {
		t.Fatalf("retried commit after the allocator accepted: %v", err)
	}
	if !env.fs.IsCurrent(secondKey, second.Envelope.Version, factTestNow) {
		t.Fatal("the retried fact is not current; the refused candidate left durable state behind")
	}
	if got := budget.reservation(); got != factTestLiveOwnedBytes(env.fs) {
		t.Fatalf("reservation after the retry = %d; want the store's owned bytes %d", got, factTestLiveOwnedBytes(env.fs))
	}
}

// TestFactStoreWithoutStateBudgetKeepsOwnBound proves a store with no attached
// StateBudget behaves exactly as before: publishes succeed, queries work and
// Close is safe. It is the no-budget half of the port contract.
func TestFactStoreWithoutStateBudgetKeepsOwnBound(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-a"))
	source := factTestSource(env.contextID, 1, 1)
	record := factTestNodeRecord(factTestPub(3), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, source, []FactRecord{record}, factTestNow); err != nil {
		t.Fatalf("commit without a state budget: %v", err)
	}
	if !env.fs.IsCurrent(factTestFactKey(t, record), record.Envelope.Version, factTestNow) {
		t.Fatal("a published fact is not current without a state budget")
	}
	if records, _, err := env.fs.Snapshot(factTestNow); err != nil || len(records) != 1 {
		t.Fatalf("snapshot without a state budget = %d records, %v; want 1, nil", len(records), err)
	}
	// An explicitly detached port is the same as never attaching one, and Close
	// must be safe with no port at all.
	env.fs.SetStateBudget(nil)
	env.fs.Close()
	env.fs.Close()
}

// TestFactStoreCloseReleasesStateReservation proves Close drops the shared
// reservation and is idempotent, so a Network teardown leaves the ledger owning
// nothing instead of stranding FACT state.
func TestFactStoreCloseReleasesStateReservation(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-a"))
	budget := &factTestStateBudget{}
	env.fs.SetStateBudget(budget)
	source := factTestSource(env.contextID, 1, 1)
	record := factTestNodeRecord(factTestPub(4), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, source, []FactRecord{record}, factTestNow); err != nil {
		t.Fatalf("commit with a state budget: %v", err)
	}
	if budget.reservation() == 0 {
		t.Fatal("the publish booked no FACT state to release")
	}
	env.fs.Close()
	if got := budget.reservation(); got != 0 {
		t.Fatalf("reservation after Close = %d; want the reservation dropped", got)
	}
	env.fs.Close()
	if got := budget.reservation(); got != 0 {
		t.Fatalf("reservation after a second Close = %d; want it still dropped", got)
	}
	// Detaching a port releases whatever it still holds.
	env.fs.SetStateBudget(budget)
	if err := factTestCommit(t, env.fs, 2, 1, source, []FactRecord{record}, factTestNow); err != nil {
		t.Fatalf("re-attached commit: %v", err)
	}
	if budget.reservation() == 0 {
		t.Fatal("the re-attached publish booked no FACT state")
	}
	env.fs.SetStateBudget(nil)
	if got := budget.reservation(); got != 0 {
		t.Fatalf("reservation after detaching the port = %d; want it dropped", got)
	}
}
