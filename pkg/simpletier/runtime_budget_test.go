package simpletier

import (
	"errors"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/session"
	"github.com/yiiilin/simpletier/internal/wire"
)

// TestReserveStateAccountsAndReleases proves n.reserveState books exactly one
// CategoryState charge against the shared 256 MiB heap and that releasing the
// lease returns the ledger to its baseline.
func TestReserveStateAccountsAndReleases(t *testing.T) {
	n := admissionNetwork(t, "state-reserve-token-0123456789")
	alloc := n.stateBudgetPtr()
	if alloc == nil {
		t.Fatal("network has no published state allocator")
	}
	before := alloc.Stats()
	lease, err := n.reserveState(4096)
	if err != nil {
		t.Fatalf("reserveState(4096): %v", err)
	}
	if lease == nil {
		t.Fatal("reserveState(4096) returned a nil lease without an error")
	}
	during := alloc.Stats()
	if got := during.State.Bytes - before.State.Bytes; got != 4096 {
		t.Fatalf("state bytes delta = %d; want 4096", got)
	}
	if got := during.Heap.Bytes - before.Heap.Bytes; got != 4096 {
		t.Fatalf("heap bytes delta = %d; want 4096 (state counts once in the heap)", got)
	}
	if got := during.Data.Bytes; got != before.Data.Bytes {
		t.Fatalf("a state reservation charged the data category: %d -> %d", before.Data.Bytes, got)
	}
	n.releaseState(lease)
	// A second release is a no-op, so every cleanup path is idempotent.
	n.releaseState(lease)
	after := alloc.Stats()
	if after.Heap.Bytes != before.Heap.Bytes || after.State.Bytes != before.State.Bytes {
		t.Fatalf("release did not restore the baseline: heap %d -> %d, state %d -> %d",
			before.Heap.Bytes, after.Heap.Bytes, before.State.Bytes, after.State.Bytes)
	}
}

// TestReserveStateZeroIsNoop pins that an empty estimate needs no lease and never
// creates a zero-byte charge (which the allocator would refuse).
func TestReserveStateZeroIsNoop(t *testing.T) {
	n := admissionNetwork(t, "state-zero-token-0123456789")
	lease, err := n.reserveState(0)
	if err != nil || lease != nil {
		t.Fatalf("reserveState(0) = (%v,%v); want (nil,nil)", lease, err)
	}
}

// TestReserveStateFailsClosedWithoutAllocator proves a Network that never
// published a shared allocator refuses the reservation explicitly instead of
// admitting unaccounted state.
func TestReserveStateFailsClosedWithoutAllocator(t *testing.T) {
	n := &network{}
	if _, err := n.reserveState(64); !errors.Is(err, ErrResource) {
		t.Fatalf("reserveState without allocator error = %v; want ErrResource", err)
	}
}

// TestReservePendingCiphertextCompositeChargesEachPoolOnce proves the shared
// staging reservation books the exact copied envelope+body once against the
// Network Data pool through the physical Link account (Frames=1), books the
// bounded pendingFrame metadata as Network state, and returns everything to the
// baseline on release. A second NetworkPool data charge would double the Data
// delta, so the single-charge shape is asserted directly.
func TestReservePendingCiphertextCompositeChargesEachPoolOnce(t *testing.T) {
	n := admissionNetwork(t, "pending-composite-token-0123456789")
	alloc := n.stateBudgetPtr()
	pump := stagingTestPump(t, n, 0x41, 4)
	before := alloc.Stats()
	lease, err := n.reservePendingCiphertext(pump, 85, 4096)
	if err != nil {
		t.Fatalf("reservePendingCiphertext: %v", err)
	}
	if lease == nil {
		t.Fatal("reservePendingCiphertext returned a nil lease without an error")
	}
	during := alloc.Stats()
	if got := during.Data.Bytes - before.Data.Bytes; got != 85+4096 {
		t.Fatalf("Data bytes delta = %d; want %d charged exactly once", got, 85+4096)
	}
	if got := during.Data.Frames - before.Data.Frames; got != 1 {
		t.Fatalf("Data frames delta = %d; want 1", got)
	}
	if got := during.State.Bytes - before.State.Bytes; got != pendingFrameMetadataBytes {
		t.Fatalf("State bytes delta = %d; want %d", got, pendingFrameMetadataBytes)
	}
	if got := during.Heap.Bytes - before.Heap.Bytes; got != 85+4096+pendingFrameMetadataBytes {
		t.Fatalf("heap bytes delta = %d; want %d", got, 85+4096+pendingFrameMetadataBytes)
	}
	if got := during.Rejected; got != before.Rejected {
		t.Fatalf("a successful composite advanced rejected to %d", got)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	after := alloc.Stats()
	if after.Data.Bytes != before.Data.Bytes || after.Data.Frames != before.Data.Frames ||
		after.State.Bytes != before.State.Bytes || after.Heap.Bytes != before.Heap.Bytes ||
		after.Leases != before.Leases {
		t.Fatalf("release did not restore the baseline: %+v -> %+v", before, after)
	}
}

// TestReservePendingCiphertextRefusedIsAllOrNone proves a composite that cannot
// fit the Network Data cap takes no lease and changes no counter, and that the
// refusal is counted as one rejected request.
func TestReservePendingCiphertextRefusedIsAllOrNone(t *testing.T) {
	n := stagingTestNetwork(t, "pending-refusal-token-0123456789", func(l *budget.Limits) {
		l.DataBytes = 1024
	})
	alloc := n.stateBudgetPtr()
	pump := stagingTestPump(t, n, 0x42, 5)
	before := alloc.Stats()
	if _, err := n.reservePendingCiphertext(pump, 85, 4096); !errors.Is(err, ErrResource) {
		t.Fatalf("reservePendingCiphertext over the Data cap = %v; want ErrResource", err)
	}
	after := alloc.Stats()
	if after.Data.Bytes != before.Data.Bytes || after.State.Bytes != before.State.Bytes ||
		after.Heap.Bytes != before.Heap.Bytes || after.Leases != before.Leases {
		t.Fatalf("refused composite changed the ledger: %+v -> %+v", before, after)
	}
	if got := after.Rejected - before.Rejected; got != 1 {
		t.Fatalf("rejected delta = %d; want 1", got)
	}
}

// TestReservePendingCiphertextFailsClosedWithoutNetworkOrLink proves a missing
// Network, allocator or physical ingress Link is an explicit ErrResource rather
// than a silent Network-only admission.
func TestReservePendingCiphertextFailsClosedWithoutNetworkOrLink(t *testing.T) {
	if _, err := (&network{}).reservePendingCiphertext(nil, 1, 1); !errors.Is(err, ErrResource) {
		t.Fatalf("reservePendingCiphertext without a network = %v; want ErrResource", err)
	}
	n := admissionNetwork(t, "pending-closed-token-0123456789")
	if _, err := n.reservePendingCiphertext(nil, 1, 1); !errors.Is(err, ErrResource) {
		t.Fatalf("reservePendingCiphertext without an ingress Link = %v; want ErrResource", err)
	}
	if _, err := n.reservePendingCiphertext(&controlPump{}, 1, 1); !errors.Is(err, ErrResource) {
		t.Fatalf("reservePendingCiphertext with a linkless pump = %v; want ErrResource", err)
	}
	if _, err := n.reservePendingCiphertext(&controlPump{network: n}, 0, 0); !errors.Is(err, ErrResource) {
		t.Fatalf("reservePendingCiphertext for zero bytes = %v; want ErrResource", err)
	}
}

// TestPhysicalLinkKeyRegistrationLifecycle proves charges are admitted only
// while the exact (LinkID, Epoch) instance is registered and that dropping it
// refuses later charges rather than silently reusing a stale account.
func TestPhysicalLinkKeyRegistrationLifecycle(t *testing.T) {
	n := admissionNetwork(t, "link-key-token-0123456789")
	alloc := n.stateBudgetPtr()
	key := budget.LinkKey{LinkID: 0x1122334455667788, Epoch: 7}
	charge := budget.Request{Charges: []budget.Charge{{
		Owner:    budget.LinkPool(budget.NetworkID(n.networkContext.WireID()), key),
		Category: budget.CategoryControl,
		Bytes:    128,
		Frames:   1,
	}}}
	if _, err := alloc.Reserve(charge); err == nil {
		t.Fatal("an unregistered Link instance accepted a charge")
	}
	if err := n.registerPhysicalLinkKey(key.LinkID, key.Epoch); err != nil {
		t.Fatalf("registerPhysicalLinkKey: %v", err)
	}
	lease, err := alloc.Reserve(charge)
	if err != nil {
		t.Fatalf("registered Link refused a charge: %v", err)
	}
	n.dropPhysicalLinkKey(key.LinkID, key.Epoch)
	if _, err := alloc.Reserve(charge); err == nil {
		t.Fatal("a dropped Link instance accepted a new charge")
	}
	// Outstanding leases stay visible and releasable after DropLink.
	if err := lease.Release(); err != nil {
		t.Fatalf("releasing an outstanding lease after DropLink: %v", err)
	}
}

// TestPumpRecvStateReleasedOnRetire proves the fixed per-pump receive-state
// reservation is booked while the pump lives and returned exactly once when the
// pump is retired before it ever started.
func TestPumpRecvStateReleasedOnRetire(t *testing.T) {
	n := admissionNetwork(t, "pump-recv-token-0123456789")
	alloc := n.stateBudgetPtr()
	before := alloc.Stats().State.Bytes
	pump := &controlPump{
		network: n,
		linkKey: budget.LinkKey{LinkID: 1, Epoch: 1},
	}
	lease, err := n.reservePumpRecvState()
	if err != nil {
		t.Fatalf("reservePumpRecvState: %v", err)
	}
	pump.recvLease = lease
	if got := alloc.Stats().State.Bytes - before; got != pumpRecvFrameAllowance+pumpRecvScratchAllowance {
		t.Fatalf("recv-state charge = %d; want %d", got, pumpRecvFrameAllowance+pumpRecvScratchAllowance)
	}
	pump.releaseResources()
	if got := alloc.Stats().State.Bytes; got != before {
		t.Fatalf("state bytes after pump retire = %d; want baseline %d", got, before)
	}
	// The release is once: a second retire must not underflow the ledger.
	pump.releaseResources()
	if got := alloc.Stats().State.Bytes; got != before {
		t.Fatalf("second release changed the ledger to %d; want %d", got, before)
	}
}

// TestE2EProtectorsShareNetworkFailedTagLedger proves the E2E half of the shared
// failed-tag ledger: the one Network-lifetime budget is injected into every
// directional E2E protector built by the production createProtectors, so a
// genuine rejected inner AEAD tag aggregates into the shared Network count and
// its ceiling instead of only each protector's private per-key counter. It drives
// the real createProtectors and a real E2E protector pair; one flipped tag byte
// is a genuine bad tag (valid outer wire, valid envelope binding, valid replay
// window), never a schema or replay rejection.
func TestE2EProtectorsShareNetworkFailedTagLedger(t *testing.T) {
	const limit = 3
	n := admissionNetwork(t, "e2e-ledger-token-0123456789")
	// An unrelated Network must stay open when this one trips its own ceiling.
	other := admissionNetwork(t, "e2e-ledger-other-token-0123456789")

	// Lower the aggregate ceiling before any protector exists and before any
	// failure is recorded, so the test can reach it deterministically.
	n.verification.limit = limit
	if failed, got := n.verificationStats(); failed != 0 || got != limit {
		t.Fatalf("baseline ledger = (%d,%d); want (0,%d)", failed, got, limit)
	}

	var sid session.SessionID
	sid[0] = 0x7a
	scope := pathScope{id: 0x21, gen: 4}
	entry := &sessionEntry{
		id: sid, scope: scope, class: session.SessionClassStream, lane: session.LaneStream,
		src: [16]byte{0x01}, dst: [16]byte{0x02}, initiator: true, ready: make(chan struct{}),
	}
	root := make([]byte, 64)
	for i := range root {
		root[i] = byte(i + 3)
	}
	re := session.RootEpoch{Epoch: 1, Root: root}
	if err := n.streams.createProtectors(entry, re); err != nil {
		t.Fatalf("createProtectors: %v", err)
	}
	if entry.tx == nil || entry.rx == nil {
		t.Fatal("createProtectors did not install the tx/rx pair")
	}

	// A peer protector in the exact direction of entry.rx derives the same key,
	// so the frames it seals are genuine tag candidates for rx.
	peer, err := session.NewE2EProtectorForContext(n.networkContext, session.E2EConfig{
		Root: root, SrcNodeID: entry.src, DstNodeID: entry.dst,
		PathID: scope.id, PathGeneration: scope.gen, SessionID: sid,
		Class: session.SessionClassStream, Direction: entry.rx.Direction(),
	}, session.E2EPolicy{})
	if err != nil {
		t.Fatalf("build peer protector: %v", err)
	}
	t.Cleanup(peer.Close)
	if err := peer.InstallEpoch(re.Epoch, root); err != nil {
		t.Fatalf("install peer epoch: %v", err)
	}

	plaintext := []byte("staged-e2e-ledger")
	for i := 0; i < limit; i++ {
		number := uint64(i + 1)
		envelope := buildEnvelope(n.networkContext.WireID(), entry.dst, entry.src,
			wire.MessageTypeStreamData, [16]byte(sid), re.Epoch, number, scope.id, scope.gen, len(plaintext))
		sealed, err := peer.Seal(wire.Frame{Kind: wire.FrameKindEndToEnd, Envelope: envelope}, plaintext)
		if err != nil {
			t.Fatalf("seal frame %d: %v", number, err)
		}
		// Flip one byte of the inner ciphertext: the outer hop wire and the
		// envelope binding stay valid, the inner AEAD tag is genuinely wrong.
		sealed.Body[len(sealed.Body)-1] ^= 0x01
		if _, err := entry.rx.Open(sealed); err == nil {
			t.Fatalf("frame %d with a corrupted inner tag was accepted", number)
		}
		if failed, got := n.verificationStats(); failed != uint64(i+1) || got != limit {
			t.Fatalf("shared ledger after %d bad tags = (%d,%d); want (%d,%d)", i+1, failed, got, i+1, limit)
		}
	}

	// The aggregate ceiling is terminal for this Network only.
	tripped := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !tripped {
		select {
		case <-n.done:
			tripped = true
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !tripped {
		t.Fatal("the Network did not close at the aggregate E2E failed-tag ceiling")
	}
	select {
	case <-other.done:
		t.Fatal("an unrelated Network was closed by another Network's E2E ledger")
	default:
	}
	if failed, got := n.verificationStats(); failed != limit || got != limit {
		t.Fatalf("shared ledger after the ceiling = (%d,%d); want the saturated (%d,%d)", failed, got, limit, limit)
	}
}
