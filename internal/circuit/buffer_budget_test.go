package circuit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// shared receive-buffer accounting harness
// ---------------------------------------------------------------------------

// errBudgetLimit is the fake allocator's refusal, deliberately distinct from
// Circuit's sentinels so a test proves the Manager reports its own ErrResource.
var errBudgetLimit = errors.New("test budget: limit reached")

// fakeBudget is a minimal shared receive-buffer ledger standing in for an
// internal/budget-backed adapter: one charge per ReserveData, a hard byte
// ceiling, and a Release counter that proves exactly-once return.
type fakeBudget struct {
	mu       sync.Mutex
	limit    uint64
	bytes    uint64
	peak     uint64
	reserves int
	releases int
	rejected int
	held     map[*fakeReservation]struct{}

	// probe, when set, observes whether the Manager lock is held while a
	// callback runs. It is called from ReserveData and Release.
	probe *managerLockProbe
}

type fakeReservation struct {
	b     *fakeBudget
	bytes uint64
	once  sync.Once
}

type budgetStats struct {
	bytes, peak                  uint64
	reserves, releases, rejected int
	held                         int
}

func newFakeBudget(limit uint64) *fakeBudget {
	return &fakeBudget{limit: limit, held: make(map[*fakeReservation]struct{})}
}

func (b *fakeBudget) ReserveData(bytes uint64) (Reservation, error) {
	if b.probe != nil {
		b.probe.check()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if bytes == 0 || b.bytes+bytes > b.limit {
		b.rejected++
		return nil, errBudgetLimit
	}
	r := &fakeReservation{b: b, bytes: bytes}
	b.bytes += bytes
	if b.bytes > b.peak {
		b.peak = b.bytes
	}
	b.reserves++
	b.held[r] = struct{}{}
	return r, nil
}

func (r *fakeReservation) Release() {
	r.once.Do(func() {
		if r.b.probe != nil {
			r.b.probe.check()
		}
		r.b.mu.Lock()
		delete(r.b.held, r)
		r.b.bytes -= r.bytes
		r.b.releases++
		r.b.mu.Unlock()
	})
}

func (b *fakeBudget) stats() budgetStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return budgetStats{
		bytes: b.bytes, peak: b.peak,
		reserves: b.reserves, releases: b.releases, rejected: b.rejected,
		held: len(b.held),
	}
}

// managerLockProbe records whether the Manager's lock was free when an injected
// BufferBudget callback ran. The documented contract is that both ReserveData
// and Release run with m.mu held, so TryLock must never succeed: sync.Mutex is
// not reentrant, so a callback on the lock-holding goroutine sees it locked.
type managerLockProbe struct {
	mgr *Manager
	mu  sync.Mutex
	// outside counts callbacks that observed the Manager lock free.
	outside int
	// calls counts observed callbacks.
	calls int
}

func (p *managerLockProbe) check() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.mgr.mu.TryLock() {
		p.mgr.mu.Unlock()
		p.outside++
	}
}

func (p *managerLockProbe) observed() (calls, outside int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls, p.outside
}

// newBudgetHarness installs one shared budget on a standard harness.
func newBudgetHarness(t *testing.T, b *fakeBudget) *harness {
	t.Helper()
	return newHarness(t, func(cfg *Config) { cfg.BufferBudget = b })
}

// targetKey is the inbound key of a target-side record from h.peer.
func (h *harness) targetKey(id CircuitID) Key {
	return Key{ContextID: h.ctx, SrcNodeID: h.peer, CircuitID: id}
}

// acceptTarget admits one inbound stream for id and Accepts it.
func (h *harness) acceptTarget(t *testing.T, id CircuitID) *Circuit {
	t.Helper()
	msg := h.openMessage(FirstAttempt, uint64(id[0])+1)
	msg.CircuitID = id
	if _, err := h.mgr.HandleOpen(msg); err != nil {
		t.Fatalf("HandleOpen(%s): %v", id, err)
	}
	c, err := h.mgr.Accept(context.Background())
	if err != nil {
		t.Fatalf("Accept(%s): %v", id, err)
	}
	return c
}

// pushData delivers one in-order DATA frame for a target circuit.
func (h *harness) pushData(t *testing.T, id CircuitID, seq uint64, payload []byte) {
	t.Helper()
	msg := StreamDataMessage{FromNodeID: h.peer, CircuitID: id, Flags: FlagData, StreamSeq: seq, Payload: payload}
	if n, err := h.mgr.HandleStreamData(msg); err != nil || n != len(payload) {
		t.Fatalf("HandleStreamData(%s@%d) = %d, %v; want %d, nil", id, seq, n, err, len(payload))
	}
}

func (h *harness) pushFin(t *testing.T, id CircuitID, seq uint64) {
	t.Helper()
	if _, err := h.mgr.HandleStreamData(StreamDataMessage{FromNodeID: h.peer, CircuitID: id, Flags: FlagFin, StreamSeq: seq}); err != nil {
		t.Fatalf("HandleStreamData FIN(%s@%d): %v", id, seq, err)
	}
}

// TestBufferBudgetManyCircuitsShareOneLedger proves the port is the single
// accounting point: one 64 KiB charge per receiving Circuit, a shared peak, and
// a complete drain once the Manager closes.
func TestBufferBudgetManyCircuitsShareOneLedger(t *testing.T) {
	const n = 16
	b := newFakeBudget(n * MaxBuffer)
	h := newBudgetHarness(t, b)

	ids := make([]CircuitID, n)
	for i := range ids {
		ids[i] = testCircuitID(byte(0x40 + i))
		h.acceptTarget(t, ids[i])
	}
	for i, id := range ids {
		h.pushData(t, id, 0, bytes.Repeat([]byte{byte(i)}, 40))
	}

	want := uint64(n * recvInitialChunk)
	if got := b.stats(); got.bytes != want || got.peak != want || got.reserves != n || got.held != n || got.rejected != 0 {
		t.Fatalf("ledger after %d circuits = %+v; want bytes/peak %d, %d reservations, none rejected", n, got, want, n)
	}

	// Every circuit stays usable and its charge survives a partial read.
	buf := make([]byte, 40)
	for i, id := range ids {
		nRead, err := h.mgr.ReadData(context.Background(), h.targetKey(id), buf)
		if err != nil || nRead != 40 {
			t.Fatalf("ReadData(%s) = %d, %v; want 40, nil", id, nRead, err)
		}
		if buf[0] != byte(i) {
			t.Fatalf("ReadData(%s) returned %d, want %d", id, buf[0], i)
		}
	}
	if got := b.stats(); got.bytes != want || got.releases != 0 {
		t.Fatalf("reads released shared bytes: %+v", got)
	}

	if err := h.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := b.stats(); got.bytes != 0 || got.held != 0 || got.releases != n || got.reserves != n {
		t.Fatalf("ledger after Close = %+v; want a complete drain of %d charges", got, n)
	}
}

// TestBufferBudgetRejectionIsolatesOneCircuit covers the refusal contract: only
// the offending Circuit is reset with ErrResource, the Manager, its Link and
// every other stream keep working, and no charge is created for the refusal.
func TestBufferBudgetRejectionIsolatesOneCircuit(t *testing.T) {
	b := newFakeBudget(2 * recvInitialChunk)
	h := newBudgetHarness(t, b)

	ids := []CircuitID{testCircuitID(0x51), testCircuitID(0x52), testCircuitID(0x53)}
	circuits := make([]*Circuit, len(ids))
	for i, id := range ids {
		circuits[i] = h.acceptTarget(t, id)
	}
	h.pushData(t, ids[0], 0, []byte("aaaa"))
	h.pushData(t, ids[1], 0, []byte("bbbb"))

	msg := StreamDataMessage{FromNodeID: h.peer, CircuitID: ids[2], Flags: FlagData, StreamSeq: 0, Payload: []byte("cccc")}
	n, err := h.mgr.HandleStreamData(msg)
	if n != 0 || !errors.Is(err, ErrResource) {
		t.Fatalf("over-cap HandleStreamData = %d, %v; want 0, ErrResource", n, err)
	}
	if !circuits[2].State().Finished() {
		t.Fatalf("offending circuit state = %s, want a finished state", circuits[2].State())
	}
	if err := h.mgr.Reset(Key{}, ResetReasonNoRoute); err == nil {
		t.Fatal("Reset with the zero key unexpectedly succeeded")
	}
	if got := b.stats(); got.bytes != 2*recvInitialChunk || got.held != 2 || got.rejected != 1 || got.releases != 0 {
		t.Fatalf("ledger after refusal = %+v; want the two healthy charges untouched", got)
	}

	// The healthy circuits are still readable and still accept in-order data.
	buf := make([]byte, 8)
	if n, err := h.mgr.ReadData(context.Background(), h.targetKey(ids[0]), buf); err != nil || n != 4 {
		t.Fatalf("ReadData(a) = %d, %v; want 4, nil", n, err)
	}
	if !circuits[0].State().readable() {
		t.Fatalf("circuit a state = %s, want readable", circuits[0].State())
	}
	h.pushData(t, ids[0], 4, []byte("more"))

	// The manager itself was never closed and still owns both live records.
	if _, err := h.mgr.Lookup(h.targetKey(ids[1])); err != nil {
		t.Fatalf("Lookup(b) after the refusal: %v", err)
	}
	if err := h.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := b.stats(); got.bytes != 0 || got.held != 0 || got.releases != 2 {
		t.Fatalf("ledger after Close = %+v; want both charges returned", got)
	}
}

// TestBufferBudgetReadRetainsAccountedCapacity proves the buffer starts at the
// first chunk, grows with real traffic up to MaxBuffer, and that a read neither
// shrinks its accounted capacity nor drops the reservation early.
func TestBufferBudgetReadRetainsAccountedCapacity(t *testing.T) {
	b := newFakeBudget(recvInitialChunk)
	h := newBudgetHarness(t, b)
	id := testCircuitID(0x61)
	c := h.acceptTarget(t, id)
	h.pushData(t, id, 0, []byte("abcdefgh"))

	// A circuit that has moved eight bytes holds one initial chunk, not the whole
	// ceiling: buffers are a ceiling that grows, so idle flows do not lock the
	// data pool away from active ones.
	if got := b.stats(); got.bytes != recvInitialChunk || got.reserves != 1 {
		t.Fatalf("ledger after first data = %+v; want one %d-byte charge", got, recvInitialChunk)
	}
	h.mgr.mu.Lock()
	capAtReserve := cap(c.recvBuf)
	resAtReserve := c.recvRes
	h.mgr.mu.Unlock()
	if capAtReserve != recvInitialChunk || resAtReserve == nil {
		t.Fatalf("owned array cap/reservation = %d/%v, want %d/non-nil", capAtReserve, resAtReserve, recvInitialChunk)
	}

	buf := make([]byte, 3)
	if n, err := h.mgr.ReadData(context.Background(), h.targetKey(id), buf); err != nil || n != 3 {
		t.Fatalf("partial ReadData = %d, %v; want 3, nil", n, err)
	}
	h.mgr.mu.Lock()
	capAfterRead, lenAfterRead, resAfterRead := cap(c.recvBuf), len(c.recvBuf), c.recvRes
	h.mgr.mu.Unlock()
	if resAfterRead == nil || lenAfterRead != 5 || capAfterRead != recvInitialChunk {
		t.Fatalf("after partial read len/cap/res = %d/%d/%v, want 5/%d/non-nil", lenAfterRead, capAfterRead, resAfterRead, recvInitialChunk)
	}
	if got := b.stats(); got.bytes != recvInitialChunk || got.releases != 0 {
		t.Fatalf("partial read released the charge: %+v", got)
	}

	// The retained capacity is reused, never reallocated: a second frame lands
	// in the same accounted array.
	before := c.recvBuf
	beforeCap := cap(before)
	h.pushData(t, id, 8, []byte("ij"))
	h.mgr.mu.Lock()
	after := c.recvBuf
	h.mgr.mu.Unlock()
	// A frame that still fits reuses the accounted array and books nothing more.
	if &before[0] != &after[0] || cap(after) != beforeCap {
		t.Fatal("a second accepted frame reallocated the accounted receive array")
	}
	if got := b.stats(); got.reserves != 1 || got.bytes != recvInitialChunk {
		t.Fatalf("second frame booked another charge: %+v", got)
	}
}

// TestBufferBudgetReleasesExactlyOncePerTerminalPath walks every reclaim path:
// drained EOF, local and peer reset, Manager.Close, the TTL reaper, and a
// Manager that is closed after an earlier terminal path. Each must return the
// one charge exactly once and leave the ledger at zero.
func TestBufferBudgetReleasesExactlyOncePerTerminalPath(t *testing.T) {
	t.Run("eof", func(t *testing.T) {
		b := newFakeBudget(MaxBuffer)
		h := newBudgetHarness(t, b)
		id := testCircuitID(0x71)
		h.acceptTarget(t, id)
		h.pushData(t, id, 0, []byte("hello"))
		h.pushFin(t, id, 5)

		buf := make([]byte, 16)
		if n, err := h.mgr.ReadData(context.Background(), h.targetKey(id), buf); err != nil || n != 5 {
			t.Fatalf("ReadData = %d, %v; want 5, nil", n, err)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 {
			t.Fatalf("draining read did not release the charge: %+v", got)
		}
		if _, err := h.mgr.ReadData(context.Background(), h.targetKey(id), buf); !errors.Is(err, io.EOF) {
			t.Fatalf("ReadData after drain err = %v, want io.EOF", err)
		}
		if got := b.stats(); got.releases != 1 {
			t.Fatalf("the EOF call released a second time: %+v", got)
		}
	})

	t.Run("local reset", func(t *testing.T) {
		b := newFakeBudget(MaxBuffer)
		h := newBudgetHarness(t, b)
		id := testCircuitID(0x72)
		h.acceptTarget(t, id)
		h.pushData(t, id, 0, []byte("hello"))

		if err := h.mgr.Reset(h.targetKey(id), ResetReasonLinkDown); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		// The accepted prefix stays readable: a terminal reset retains the
		// charge until the reader drains it, then returns it exactly once.
		if got := b.stats(); got.releases != 0 || got.bytes != recvInitialChunk || got.held != 1 {
			t.Fatalf("Reset dropped the accepted buffer's charge: %+v", got)
		}
		buf := make([]byte, 8)
		if n, err := h.mgr.ReadData(context.Background(), h.targetKey(id), buf); err != nil || n != 5 {
			t.Fatalf("ReadData after Reset = %d, %v; want 5, nil", n, err)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 || got.held != 0 {
			t.Fatalf("draining read did not return the charge exactly once: %+v", got)
		}
		// Idempotent paths must not release again.
		if err := h.mgr.Reset(h.targetKey(id), ResetReasonLinkDown); err != nil {
			t.Fatalf("second Reset: %v", err)
		}
		if err := h.mgr.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 {
			t.Fatalf("a later terminal path double-released: %+v", got)
		}
	})

	t.Run("peer reset", func(t *testing.T) {
		b := newFakeBudget(MaxBuffer)
		h := newBudgetHarness(t, b)
		id := testCircuitID(0x73)
		h.acceptTarget(t, id)
		h.pushData(t, id, 0, []byte("hello"))

		if err := h.mgr.HandleReset(ResetMessage{FromNodeID: h.peer, CircuitID: id, Attempt: FirstAttempt, Reason: ResetReasonProtocol}); err != nil {
			t.Fatalf("HandleReset: %v", err)
		}
		// The accepted prefix survives the inbound reset and its charge is
		// returned by the read that drains the last byte.
		if got := b.stats(); got.releases != 0 || got.bytes != recvInitialChunk || got.held != 1 {
			t.Fatalf("inbound reset dropped the accepted buffer's charge: %+v", got)
		}
		buf := make([]byte, 8)
		if n, err := h.mgr.ReadData(context.Background(), h.targetKey(id), buf); err != nil || n != 5 {
			t.Fatalf("ReadData after HandleReset = %d, %v; want 5, nil", n, err)
		}
		if _, err := h.mgr.ReadData(context.Background(), h.targetKey(id), buf); !errors.Is(err, ErrProtocol) {
			t.Fatalf("ReadData after drain err = %v, want ErrProtocol", err)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 || got.held != 0 {
			t.Fatalf("inbound reset did not release exactly once on drain: %+v", got)
		}
	})

	t.Run("manager close", func(t *testing.T) {
		b := newFakeBudget(MaxBuffer)
		h := newBudgetHarness(t, b)
		id := testCircuitID(0x74)
		h.acceptTarget(t, id)
		h.pushData(t, id, 0, []byte("hello"))

		if err := h.mgr.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := h.mgr.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 {
			t.Fatalf("Close did not release exactly once: %+v", got)
		}
	})

	t.Run("ttl reap", func(t *testing.T) {
		b := newFakeBudget(MaxBuffer)
		h := newBudgetHarness(t, b)
		id := testCircuitID(0x75)
		h.acceptTarget(t, id)
		h.pushData(t, id, 0, []byte("hello"))
		h.pushFin(t, id, 5)
		if err := h.mgr.CloseWrite(h.targetKey(id)); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
		if got := b.stats(); got.releases != 0 {
			t.Fatalf("BothClosed released the charge before any reclaim: %+v", got)
		}

		h.clock.Advance(DefaultTombstoneTTL + time.Second)
		if removed := h.mgr.Expire(); removed != 1 {
			t.Fatalf("Expire removed %d records, want 1", removed)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 || got.held != 0 {
			t.Fatalf("reaper did not release exactly once: %+v", got)
		}
		// A repeated reap finds nothing and releases nothing.
		if removed := h.mgr.Expire(); removed != 0 {
			t.Fatalf("second Expire removed %d records, want 0", removed)
		}
		if got := b.stats(); got.releases != 1 {
			t.Fatalf("repeated reap double-released: %+v", got)
		}
	})
}

// TestBufferBudgetProtocolResetDoesNotLeak covers the overlap and FIN races:
// a reset-triggering violation returns the charge, while an idempotent duplicate
// FIN leaves it held until a terminal path returns it.
func TestBufferBudgetProtocolResetDoesNotLeak(t *testing.T) {
	t.Run("partial overlap", func(t *testing.T) {
		b := newFakeBudget(MaxBuffer)
		h := newBudgetHarness(t, b)
		id := testCircuitID(0x81)
		h.acceptTarget(t, id)
		h.pushData(t, id, 0, []byte("hello"))

		_, err := h.mgr.HandleStreamData(StreamDataMessage{FromNodeID: h.peer, CircuitID: id, Flags: FlagData, StreamSeq: 3, Payload: []byte("xxxxx")})
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("partial overlap err = %v, want ErrProtocol", err)
		}
		// The protocol reset ends the direction but keeps the accepted prefix
		// readable; the charge follows the bytes and returns on the last drain.
		if got := b.stats(); got.releases != 0 || got.bytes != recvInitialChunk || got.held != 1 {
			t.Fatalf("protocol reset dropped the buffered charge: %+v", got)
		}
		buf := make([]byte, 8)
		if n, err := h.mgr.ReadData(context.Background(), h.targetKey(id), buf); err != nil || n != 5 {
			t.Fatalf("ReadData after the reset = %d, %v; want 5, nil", n, err)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 || got.held != 0 {
			t.Fatalf("protocol reset leaked the charge: %+v", got)
		}
	})

	t.Run("data after fin", func(t *testing.T) {
		b := newFakeBudget(MaxBuffer)
		h := newBudgetHarness(t, b)
		id := testCircuitID(0x82)
		h.acceptTarget(t, id)
		h.pushData(t, id, 0, []byte("hello"))
		h.pushFin(t, id, 5)

		_, err := h.mgr.HandleStreamData(StreamDataMessage{FromNodeID: h.peer, CircuitID: id, Flags: FlagData, StreamSeq: 5, Payload: []byte("x")})
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("DATA after FIN err = %v, want ErrProtocol", err)
		}
		if got := b.stats(); got.releases != 0 || got.bytes != recvInitialChunk || got.held != 1 {
			t.Fatalf("DATA after FIN dropped the buffered charge: %+v", got)
		}
		buf := make([]byte, 8)
		if n, err := h.mgr.ReadData(context.Background(), h.targetKey(id), buf); err != nil || n != 5 {
			t.Fatalf("ReadData after the reset = %d, %v; want 5, nil", n, err)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 || got.held != 0 {
			t.Fatalf("DATA after FIN leaked the charge: %+v", got)
		}
	})

	t.Run("duplicate fin", func(t *testing.T) {
		b := newFakeBudget(MaxBuffer)
		h := newBudgetHarness(t, b)
		id := testCircuitID(0x83)
		h.acceptTarget(t, id)
		h.pushData(t, id, 0, []byte("hello"))
		h.pushFin(t, id, 5)

		n, err := h.mgr.HandleStreamData(StreamDataMessage{FromNodeID: h.peer, CircuitID: id, Flags: FlagFin, StreamSeq: 5})
		if err != nil || n != 0 {
			t.Fatalf("duplicate FIN = %d, %v; want 0, nil", n, err)
		}
		if got := b.stats(); got.releases != 0 || got.bytes != recvInitialChunk {
			t.Fatalf("duplicate FIN dropped the buffered charge: %+v", got)
		}
		if err := h.mgr.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 {
			t.Fatalf("Close after duplicate FIN did not drain exactly once: %+v", got)
		}
	})
}

// TestBufferBudgetReserveRunsUnderManagerLock pins the documented callback
// contract: the Manager calls ReserveData and Release with m.mu held, so an
// adapter must never re-enter the Manager from either.
func TestBufferBudgetReserveRunsUnderManagerLock(t *testing.T) {
	b := newFakeBudget(recvInitialChunk)
	h := newBudgetHarness(t, b)
	probe := &managerLockProbe{mgr: h.mgr}
	b.probe = probe

	id := testCircuitID(0x91)
	h.acceptTarget(t, id)
	h.pushData(t, id, 0, []byte("hello"))
	if err := h.mgr.Reset(h.targetKey(id), ResetReasonLinkDown); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	// The terminal reset retains the accepted buffer, so the Release callback
	// belongs to the read that drains the last accepted byte, not to the reset
	// itself. Both boundary calls must still run with the Manager lock held.
	buf := make([]byte, 8)
	if n, err := h.mgr.ReadData(context.Background(), h.targetKey(id), buf); err != nil || n != 5 {
		t.Fatalf("ReadData after Reset = %d, %v; want 5, nil", n, err)
	}

	calls, outside := probe.observed()
	if calls < 2 {
		t.Fatalf("probe observed %d callbacks, want at least one reserve and one release", calls)
	}
	if outside != 0 {
		t.Fatalf("%d BufferBudget callbacks ran without the Manager lock held", outside)
	}
}

// TestBufferBudgetNilPortKeepsLocalBound covers the nil-port default: no
// reservation is created, the array is not preallocated to MaxBuffer, and the
// local append path still drops the buffer when it drains.
func TestBufferBudgetNilPortKeepsLocalBound(t *testing.T) {
	h := newHarness(t, nil)
	id := testCircuitID(0xA1)
	c := h.acceptTarget(t, id)
	h.pushData(t, id, 0, []byte("hello"))

	h.mgr.mu.Lock()
	res, capGot, lenGot := c.recvRes, cap(c.recvBuf), len(c.recvBuf)
	h.mgr.mu.Unlock()
	if res != nil {
		t.Fatal("a nil port created a shared reservation")
	}
	if lenGot != 5 || capGot >= MaxBuffer {
		t.Fatalf("nil-port owned len/cap = %d/%d, want 5 and no MaxBuffer preallocation", lenGot, capGot)
	}

	buf := make([]byte, 8)
	if n, err := h.mgr.ReadData(context.Background(), h.targetKey(id), buf); err != nil || n != 5 {
		t.Fatalf("ReadData = %d, %v; want 5, nil", n, err)
	}
	h.mgr.mu.Lock()
	drained := c.recvBuf == nil
	h.mgr.mu.Unlock()
	if !drained {
		t.Fatal("nil-port drained buffer was not dropped")
	}
}

// TestBufferBudgetConcurrentReceiveReadCloseIsRaceFree drives the same Manager
// from concurrent receivers, readers, the TTL reaper and Close. Run with -race;
// it also proves the ledger always ends at zero with one release per reserve.
func TestBufferBudgetConcurrentReceiveReadCloseIsRaceFree(t *testing.T) {
	const (
		circuits = 4
		frames   = 32
		payload  = 128
	)
	b := newFakeBudget(circuits * MaxBuffer)
	h := newBudgetHarness(t, b)

	ids := make([]CircuitID, circuits)
	keys := make([]Key, circuits)
	for i := range ids {
		ids[i] = testCircuitID(byte(0xB0 + i))
		h.acceptTarget(t, ids[i])
		keys[i] = h.targetKey(ids[i])
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var writers, observers sync.WaitGroup
	for i := range ids {
		writers.Add(1)
		go func(i int) {
			defer writers.Done()
			for f := 0; f < frames; f++ {
				msg := StreamDataMessage{
					FromNodeID: h.peer, CircuitID: ids[i], Flags: FlagData,
					StreamSeq: uint64(f * payload), Payload: bytes.Repeat([]byte{byte(f)}, payload),
				}
				if _, err := h.mgr.HandleStreamData(msg); err != nil {
					return
				}
			}
			_, _ = h.mgr.HandleStreamData(StreamDataMessage{FromNodeID: h.peer, CircuitID: ids[i], Flags: FlagFin, StreamSeq: frames * payload})
		}(i)

		observers.Add(1)
		go func(i int) {
			defer observers.Done()
			buf := make([]byte, 97)
			for ctx.Err() == nil {
				if _, err := h.mgr.ReadData(ctx, keys[i], buf); err != nil {
					return
				}
			}
		}(i)
	}
	observers.Add(1)
	go func() {
		defer observers.Done()
		for ctx.Err() == nil {
			_ = h.mgr.Expire()
			time.Sleep(time.Millisecond)
		}
	}()

	writers.Wait()
	for _, k := range keys {
		_ = h.mgr.CloseCircuit(k)
	}
	cancel()
	observers.Wait()
	if err := h.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := b.stats()
	if got.bytes != 0 || got.held != 0 {
		t.Fatalf("ledger leaked after the concurrent run: %+v", got)
	}
	if got.reserves != circuits {
		t.Fatalf("reservations = %d, want exactly one per receiving circuit (%d)", got.reserves, circuits)
	}
	if got.releases != got.reserves {
		t.Fatalf("releases = %d, want one per reservation (%d)", got.releases, got.reserves)
	}
}
