package link

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/wire"
)

// assertKeyUpdateIdentical fails if the engine status, the installed pending
// slot or the recorded stable generation changed across a rejected message.
func assertKeyUpdateIdentical(t *testing.T, io *ProtectedControlIO, before KeyUpdateStatus, pending *KeyUpdateSlot, stable uint32) {
	t.Helper()
	if after := io.KeyUpdateStatus(); after != before {
		t.Fatalf("engine status changed across a rejected message:\n before %+v\n after  %+v", before, after)
	}
	if io.pendingSlot != pending {
		t.Fatalf("pending slot changed across a rejected message: %p -> %p", pending, io.pendingSlot)
	}
	if io.stableGeneration != stable {
		t.Fatalf("stable generation changed across a rejected message: %d -> %d", stable, io.stableGeneration)
	}
}

// TestKeyUpdateCoordinatorRejectsXX1WithoutMutation proves the coordinator role
// check runs before any adoption, so an inbound XX1 on the coordinator leaves
// the live transaction, its pending slot and the stable generation identical.
func TestKeyUpdateCoordinatorRejectsXX1WithoutMutation(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePair(t, pair)
	if _, err := pair.a.RequestKeyUpdate(); err != nil {
		t.Fatalf("request: %v", err)
	}
	before := pair.a.KeyUpdateStatus()
	beforePending := pair.a.pendingSlot
	beforeStable := pair.a.stableGeneration

	body, err := EncodeKeyUpdate(KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateXX1, Lane: pair.ar.LaneID,
		TargetLinkID: pair.ar.LinkID, TargetLinkEpoch: pair.ar.LinkEpoch,
		UpdateSeq: 2, OldGeneration: pair.a.txGen, NewGeneration: 0x0abc1234,
		PreviousRevision: [32]byte{7}, Noise: bytes.Repeat([]byte{0x42}, 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte{ControlTypeKeyUpdate}, body...)
	if _, err := pair.a.HandleUpdate(ProtectedMessage{Kind: wire.FrameKindLinkControl, Payload: frame}); !errors.Is(err, ErrKeyUpdateConflict) {
		t.Fatalf("coordinator XX1 error = %v; want ErrKeyUpdateConflict", err)
	}
	assertKeyUpdateIdentical(t, pair.a, before, beforePending, beforeStable)
}

// TestKeyUpdateFollowerRejectsInvalidXX1ThenAcceptsLegit proves a high-sequenced
// XX1 whose Noise bytes do not authenticate is staged and rejected without
// committing seq/slot/hs/state, and that a later legitimate XX1 is still
// accepted on the same engine.
func TestKeyUpdateFollowerRejectsInvalidXX1ThenAcceptsLegit(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePair(t, pair)

	before := pair.b.KeyUpdateStatus()
	beforePending := pair.b.pendingSlot
	beforeStable := pair.b.stableGeneration

	bad, err := EncodeKeyUpdate(KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateXX1, Lane: pair.ar.LaneID,
		TargetLinkID: pair.ar.LinkID, TargetLinkEpoch: pair.ar.LinkEpoch,
		UpdateSeq: 77, OldGeneration: pair.b.rxGen, NewGeneration: 0x0badf00d,
		PreviousRevision: [32]byte{3}, Noise: bytes.Repeat([]byte{0x7f}, 8),
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte{ControlTypeKeyUpdate}, bad...)
	if _, err := pair.b.HandleUpdate(ProtectedMessage{Kind: wire.FrameKindLinkControl, Payload: frame}); err == nil {
		t.Fatal("XX1 with malformed Noise was accepted")
	}
	assertKeyUpdateIdentical(t, pair.b, before, beforePending, beforeStable)
	if seq := pair.b.KeyUpdateStatus().Seq; seq != before.Seq {
		t.Fatalf("rejected XX1 committed its sequence: %d -> %d", before.Seq, seq)
	}

	// A later legitimate XX1 from the real coordinator is still accepted.
	xx1, err := pair.a.RequestKeyUpdate()
	if err != nil {
		t.Fatalf("legit request: %v", err)
	}
	follow := deliverKeyUpdate(t, pair.b, xx1[0])
	if len(follow) != 1 || follow[0].Phase != KeyUpdateXX2 {
		t.Fatalf("legit XX1 follow-up = %+v; want one XX2", follow)
	}
	if got := pair.b.KeyUpdateStatus().State; got != KuStatePending {
		t.Fatalf("follower state = %s; want Pending", got)
	}
	if got := pair.b.KeyUpdateStatus().Seq; got != xx1[0].Seq {
		t.Fatalf("follower seq = %d; want %d", got, xx1[0].Seq)
	}
}

// testVerificationBudget is a shared failed-tag ledger: RecordFailure records
// one failure and refuses (false) once the configured limit is reached.
type testVerificationBudget struct {
	mu       sync.Mutex
	limit    int
	failures int
}

func (b *testVerificationBudget) RecordFailure() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	return b.failures < b.limit
}

func (b *testVerificationBudget) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failures
}

// TestKeyUpdateSharedVerificationBudget proves the optional ledger aggregates
// actual AEAD tag failures across two Links, fails the charging Link closed and
// closes its owned stream on the refusing failure, and is never charged for a
// replay or a post-AEAD schema rejection.
func TestKeyUpdateSharedVerificationBudget(t *testing.T) {
	t.Run("shared-across-two-links", func(t *testing.T) {
		pair := establishedControlPair(t)
		budget := &testVerificationBudget{limit: 3}
		pair.a.SetVerificationBudget(budget)
		pair.b.SetVerificationBudget(budget)

		// Two bad tags charged through pair.b's reader.
		wrongForB := wrongKeyControlProtector(t, pair)
		for i := 0; i < 2; i++ {
			if err := writeBadControlFrame(t, pair, wrongForB, uint64(100+i)); errors.Is(err, ErrKeyUpdateRequired) {
				t.Fatalf("shared ledger crossed hard early on frame %d", i)
			}
		}
		if pair.b.terminal.Load() {
			t.Fatal("the shared ledger failed pair.b closed before its limit")
		}
		if got := budget.count(); got != 2 {
			t.Fatalf("ledger failures = %d; want 2", got)
		}

		// The third failure is charged through the other Link of the same ledger.
		wrongRoot := pair.br.TxRoot
		wrongRoot[0] ^= 0x5a
		wrongForA, err := NewFrameProtector(wrongRoot, pair.descriptor, pair.br.LinkID, [16]byte{}, SessionClassStream, pair.b.txDirection)
		if err != nil {
			t.Fatal(err)
		}
		frame := sealControl(t, wrongForA, 1, bytes.Repeat([]byte{0x5a}, 16), pair.a.rxGen, 300)
		written := sendRawFrame(pair.right, frame)
		if _, err := pair.a.ReadMessage(); err == nil {
			t.Fatal("wrong-key frame was accepted by pair.a")
		}
		if werr := <-written; werr != nil {
			t.Fatal(werr)
		}
		if got := budget.count(); got != 3 {
			t.Fatalf("ledger failures = %d; want 3", got)
		}
		if !pair.a.terminal.Load() {
			t.Fatal("the refusing shared ledger did not fail the charging Link closed")
		}
		// The owned physical stream was closed so a blocked pump wakes instead
		// of hanging forever.
		if _, err := pair.left.Read(make([]byte, 1)); err == nil {
			t.Fatal("owned stream is still open after the shared ledger refused")
		}
	})

	t.Run("replay-and-schema-do-not-charge", func(t *testing.T) {
		pair := establishedControlPair(t)
		budget := &testVerificationBudget{limit: 8}
		pair.b.SetVerificationBudget(budget)

		// A well-authenticated frame whose counter is a replay is rejected before
		// the hop AEAD, so it must not be charged as a tag failure.
		replay := sealControl(t, pair.a.tx, 1, bytes.Repeat([]byte{0x11}, 16), pair.b.rxGen, 0)
		written := sendRawFrame(pair.left, replay)
		if _, err := pair.b.ReadMessage(); !errors.Is(err, ErrReplay) {
			t.Fatalf("replay frame error = %v; want ErrReplay", err)
		}
		if werr := <-written; werr != nil {
			t.Fatal(werr)
		}
		if got := budget.count(); got != 0 {
			t.Fatalf("replay charged the shared ledger: %d", got)
		}

		// A frame that authenticates but violates the control schema is rejected
		// after the AEAD; it is not a tag failure either.
		schema := sealControl(t, pair.a.tx, 0x7e, bytes.Repeat([]byte{0x22}, 16), pair.b.rxGen, 5)
		written = sendRawFrame(pair.left, schema)
		if _, err := pair.b.ReadMessage(); err == nil {
			t.Fatal("invalid control schema was accepted")
		}
		if werr := <-written; werr != nil {
			t.Fatal(werr)
		}
		if got := budget.count(); got != 0 {
			t.Fatalf("schema rejection charged the shared ledger: %d", got)
		}
	})
}

// TestKeyUpdateHardAgeLivenessRecoversSamePhysicalLink proves the age liveness
// path with a fake clock: after idling past the built-in hard age the first
// business use is refused before any trigger, the runtime's callback-safe policy
// tick starts the update, and the very same physical Link then carries business
// again once the update is Stable. No 24h sleep, new wire field or user config is
// involved.
func TestKeyUpdateHardAgeLivenessRecoversSamePhysicalLink(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePolicyPair(t, pair, DefaultKeyUpdatePolicy())

	var clockMu sync.Mutex
	current := time.Now()
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return current
	}
	pair.a.usage.setClock(clock)
	pair.b.usage.setClock(clock)
	clockMu.Lock()
	current = current.Add(24 * time.Hour)
	clockMu.Unlock()

	// The first business use is refused before any trigger fires.
	if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: make([]byte, 16)}); !errors.Is(err, ErrKeyUpdateRequired) {
		t.Fatalf("first business write after the hard age = %v; want ErrKeyUpdateRequired", err)
	}
	if got := pair.a.KeyUpdateStatus().Usage.Requests; got != 0 {
		t.Fatalf("a refused business write started an update: requests %d", got)
	}
	if err := pair.a.KeyUpdateTriggerError(); err != nil {
		t.Fatalf("a refused business write recorded a trigger error: %v", err)
	}

	driverA, driverB := newKeyUpdateHookDriver(pair.a), newKeyUpdateHookDriver(pair.b)
	driverA.start(t)
	driverB.start(t)
	defer driverA.stop()
	defer driverB.stop()
	pair.a.SetKeyUpdateActionSink(func(actions []KeyUpdateAction) error {
		for _, action := range actions {
			driverA.actions <- action
		}
		return nil
	})

	// The runtime tick performs no I/O and starts no goroutine of its own; it
	// just evaluates the policy and hands the prepared batch to the sink.
	pair.a.PollKeyUpdatePolicy()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if pair.a.KeyUpdateStatus().State == KuStateStable && pair.b.KeyUpdateStatus().State == KuStateStable {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if err := driverA.failure(); err != nil {
		t.Fatalf("driver A: %v", err)
	}
	if err := driverB.failure(); err != nil {
		t.Fatalf("driver B: %v", err)
	}
	if pair.a.KeyUpdateStatus().State != KuStateStable || pair.b.KeyUpdateStatus().State != KuStateStable {
		t.Fatalf("age-driven update did not stabilize: A %s B %s",
			pair.a.KeyUpdateStatus().State, pair.b.KeyUpdateStatus().State)
	}
	if err := pair.a.KeyUpdateTriggerError(); err != nil {
		t.Fatalf("age-driven trigger error: %v", err)
	}

	// The same physical Link carries business again after Stable.
	written := make(chan error, 1)
	go func() {
		written <- pair.a.WriteControl(ControlMessage{Type: 1, Payload: bytes.Repeat([]byte{0x5a}, 16)})
	}()
	if got := awaitKind(t, driverB, wire.FrameKindLinkControl, 3*time.Second); got.Kind != wire.FrameKindLinkControl {
		t.Fatalf("business frame kind after Stable = 0x%02x", uint8(got.Kind))
	}
	if err := <-written; err != nil {
		t.Fatalf("business write after Stable: %v", err)
	}
}

// keyUpdateDirectionLeaves returns the (root, direction, protector) triples an
// admission must have derived in both directions.
func assertAdmittedRoot(t *testing.T, io *ProtectedControlIO, sessionID [16]byte, entry *sessionAdmission, txRoot, rxRoot [32]byte, txGeneration, rxGeneration uint32) {
	t.Helper()
	for _, direction := range []struct {
		root       [32]byte
		dir        byte
		generation uint32
		got        *FrameProtector
	}{
		{txRoot, io.txDirection, txGeneration, entry.tx},
		{rxRoot, io.rxDirection, rxGeneration, entry.rx},
	} {
		want, err := NewFrameProtector(direction.root, io.descriptor, io.linkID, sessionID, SessionClassStream, direction.dir)
		if err != nil {
			t.Fatal(err)
		}
		if direction.got == nil {
			t.Fatal("admitted direction has no protector")
		}
		if direction.got.keys[purposeE2E] != want.keys[purposeE2E] {
			t.Fatalf("admitted hop leaf for direction %d generation %d does not derive from the current published root",
				direction.dir, direction.generation)
		}
	}
}

// TestAdmitSessionDerivesCurrentPublishedRoot is the deterministic barrier
// regression: an admission that overlaps a direction's snapshot publication must
// derive from the NEW snapshot, not the one that was current before it blocked.
// A stale leaf here is exactly what made business sealed with the new root fail
// the peer's AEAD open.
func TestAdmitSessionDerivesCurrentPublishedRoot(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0xE1)

	newTxRoot := pair.a.txRoot
	newTxRoot[0] ^= 0x11
	newRxRoot := pair.a.rxRoot
	newRxRoot[0] ^= 0x22
	generation := pair.a.txGen + 1

	txBefore, routeBefore, rxLastBefore := pair.a.txNext, pair.a.routeNext, pair.a.rxLast

	// Hold the table lock so the admission cannot load its snapshots yet, then
	// publish both new direction snapshots exactly like a direction switch does.
	pair.a.sessionMu.Lock()
	admitted := make(chan error, 1)
	go func() { admitted <- pair.a.AdmitSession(sessionID, SessionClassStream) }()
	time.Sleep(20 * time.Millisecond)
	pair.a.atomicTxSlot.Store(&keyUpdateDirectionSlot{root: newTxRoot, generation: generation, direction: pair.a.txDirection})
	pair.a.atomicRxSlot.Store(&keyUpdateDirectionSlot{root: newRxRoot, generation: generation, direction: pair.a.rxDirection})
	pair.a.sessionMu.Unlock()
	if err := <-admitted; err != nil {
		t.Fatalf("admit: %v", err)
	}

	pair.a.sessionMu.RLock()
	entry := pair.a.sessions[sessionID]
	pair.a.sessionMu.RUnlock()
	if entry == nil {
		t.Fatal("session was not admitted")
	}
	assertAdmittedRoot(t, pair.a, sessionID, entry, newTxRoot, newRxRoot, generation, generation)
	if pair.a.txNext != txBefore || pair.a.routeNext != routeBefore || pair.a.rxLast != rxLastBefore {
		t.Fatal("an admission moved a direction counter or replay floor")
	}
}

// TestAdmitSessionConcurrentPublicationStress races admissions against
// snapshot publications and refreshes. After every publisher has refreshed, each
// admitted leaf must equal the leaf of the current published root in both
// directions; a leaf derived from a pre-publication snapshot would still be
// stale here. Run under -race, it also exercises the lock discipline.
func TestAdmitSessionConcurrentPublicationStress(t *testing.T) {
	pair := establishedControlPair(t)
	const admits = 48
	const publications = 24

	var publishMu sync.Mutex
	var publishers sync.WaitGroup
	publishers.Add(1)
	go func() {
		defer publishers.Done()
		for i := 0; i < publications; i++ {
			publishMu.Lock()
			root := [32]byte{byte(0x40 + i), 0x5a, 0x01}
			pair.a.txRoot, pair.a.rxRoot = root, root
			pair.a.atomicTxSlot.Store(&keyUpdateDirectionSlot{root: root, generation: pair.a.txGen + uint32(i) + 1, direction: pair.a.txDirection})
			pair.a.atomicRxSlot.Store(&keyUpdateDirectionSlot{root: root, generation: pair.a.rxGen + uint32(i) + 1, direction: pair.a.rxDirection})
			pair.a.refreshSessionTX()
			pair.a.refreshSessionRX()
			publishMu.Unlock()
			time.Sleep(time.Millisecond)
		}
	}()

	var admitsDone sync.WaitGroup
	for index := 0; index < admits; index++ {
		admitsDone.Add(1)
		go func(index int) {
			defer admitsDone.Done()
			id := testSessionID(byte(index + 1))
			id[15] ^= 0xC3
			if err := pair.a.AdmitSession(id, SessionClassStream); err != nil {
				t.Errorf("admit %d: %v", index, err)
			}
		}(index)
	}
	admitsDone.Wait()
	publishers.Wait()

	txRoot, rxRoot := pair.a.txRoot, pair.a.rxRoot
	pair.a.sessionMu.RLock()
	defer pair.a.sessionMu.RUnlock()
	for index := 0; index < admits; index++ {
		id := testSessionID(byte(index + 1))
		id[15] ^= 0xC3
		entry := pair.a.sessions[id]
		if entry == nil {
			t.Fatalf("admitted session %d is missing", index)
		}
		assertAdmittedRoot(t, pair.a, id, entry, txRoot, rxRoot, pair.a.txGen, pair.a.rxGen)
	}
}

// TestRetiredTombstoneReclaimIgnoresGenerationOrder forces a new generation that
// is numerically SMALLER than the generation it replaces and proves the tombstone
// is still reclaimed. Eligibility is the monotonic per-direction root serial, not
// a numeric generation comparison: a fresh generation is a random uint32 on the
// wire, so a numeric rule would strand every such tombstone as unreclaimable.
func TestRetiredTombstoneReclaimIgnoresGenerationOrder(t *testing.T) {
	previous := keyUpdateRandomGeneration
	keyUpdateRandomGeneration = func() (uint32, error) { return 3, nil }
	defer func() { keyUpdateRandomGeneration = previous }()

	const oldGeneration = uint32(1) << 30
	pair := establishedControlPairWith(t, 91, 2, oldGeneration)
	retired := testSessionID(0xD5)
	if err := pair.a.AdmitSession(retired, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	if err := pair.a.RetireSession(retired); err != nil {
		t.Fatal(err)
	}
	if n := pair.a.ReclaimRetiredSessions(); n != 0 {
		t.Fatalf("reclaimed %d tombstones before any mutual DONE", n)
	}

	driverA, driverB := runSelfKeyUpdate(t, pair)
	defer driverA.stop()
	defer driverB.stop()

	if got := pair.a.txGen; got != 3 {
		t.Fatalf("forced new generation = %d; want 3 (numerically below %d)", got, oldGeneration)
	}
	if pair.a.txGen >= oldGeneration {
		t.Fatal("test setup did not produce a numerically lower generation")
	}
	// Both roots advanced to a fresh serial, so the serial rule reclaims even
	// though the numeric generation went backwards.
	if slot := pair.a.atomicTxSlot.Load(); slot == nil || slot.serial != 2 {
		t.Fatalf("TX root serial after one rekey = %v; want 2", slot)
	}
	if n := pair.a.ReclaimRetiredSessions(); n != 1 {
		t.Fatalf("reclaimed %d tombstones after a numerically lower new root; want 1", n)
	}
	if sessionPresent(pair.a, retired) {
		t.Fatal("eligible tombstone survived the root-serial reclaim")
	}
}

// TestDataTargetStableProofEnablesReclaim runs the real DATA-target orchestration
// and proves the mutual-DONE proof is recorded on the carrier whose roots actually
// advanced: the DATA target reclaims its own retired tombstone after BOTH its
// directions reached the new root serial, while the CONTROL carrier (whose roots
// did not change) records no proof and never reclaims from that transaction.
func TestDataTargetStableProofEnablesReclaim(t *testing.T) {
	control := establishedControlPairWith(t, 91, 2, 17)
	data := establishedControlPairWith(t, 137, 9, 41)

	configure := func(io *ProtectedControlIO, identity security.Identity, peer [32]byte, target *ProtectedControlIO) {
		t.Helper()
		if err := io.ConfigureKeyUpdate(KeyUpdateConfig{
			Identity: identity, PeerStatic: peer, PSK: control.psk, Descriptor: control.descriptor,
			TargetLinkID: data.ar.LinkID, TargetLinkEpoch: data.ar.LinkEpoch, LaneID: data.ar.LaneID,
			PeerAdvertisedKeyUpdate: true,
			TargetLookup: func(linkID, epoch uint64, lane uint8) (KeyUpdateCarrier, error) {
				if linkID != data.ar.LinkID || epoch != data.ar.LinkEpoch || lane != data.ar.LaneID {
					return nil, ErrKeyUpdateTarget
				}
				return target, nil
			},
		}); err != nil {
			t.Fatalf("configure: %v", err)
		}
	}
	configure(control.a, control.alice, control.ar.PeerStatic, data.a)
	configure(control.b, control.bob, control.br.PeerStatic, data.b)

	dataRetired := testSessionID(0xD7)
	controlRetired := testSessionID(0xD8)
	for _, target := range []struct {
		io *ProtectedControlIO
		id [16]byte
	}{{data.a, dataRetired}, {control.a, controlRetired}} {
		if err := target.io.AdmitSession(target.id, SessionClassStream); err != nil {
			t.Fatal(err)
		}
		if err := target.io.RetireSession(target.id); err != nil {
			t.Fatal(err)
		}
	}

	driverA, driverB := newKeyUpdateTargetDriver(control.a), newKeyUpdateTargetDriver(control.b)
	driverA.start(t, control.a, data.a)
	driverB.start(t, control.b, data.b)
	defer driverA.stop()
	defer driverB.stop()
	actions, err := control.a.RequestKeyUpdate()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range actions {
		driverA.actions <- action
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if control.a.KeyUpdateStatus().State == KuStateStable && control.b.KeyUpdateStatus().State == KuStateStable {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if err := driverA.failure(); err != nil {
		t.Fatalf("driver A: %v", err)
	}
	if err := driverB.failure(); err != nil {
		t.Fatalf("driver B: %v", err)
	}
	if control.a.KeyUpdateStatus().State != KuStateStable || control.b.KeyUpdateStatus().State != KuStateStable {
		t.Fatalf("DATA-target update did not stabilize: A %s B %s",
			control.a.KeyUpdateStatus().State, control.b.KeyUpdateStatus().State)
	}

	// The DATA target advanced both directions exactly one root serial and agrees
	// with its peer on the roots and generations.
	txSlot, rxSlot := data.a.atomicTxSlot.Load(), data.a.atomicRxSlot.Load()
	if txSlot == nil || rxSlot == nil || txSlot.serial != 2 || rxSlot.serial != 2 {
		t.Fatalf("DATA root serials = %v/%v; want 2/2", txSlot, rxSlot)
	}
	if data.a.txRoot != data.b.rxRoot || data.a.rxRoot != data.b.txRoot {
		t.Fatal("DATA Link directions do not agree after the target rekey")
	}
	if data.a.txGen != data.b.rxGen || data.b.txGen != data.a.rxGen {
		t.Fatal("DATA generations disagree after the target rekey")
	}
	if !data.a.stableProofValid {
		t.Fatal("the DATA target recorded no mutual-DONE proof for the roots it advanced")
	}
	if n := data.a.ReclaimRetiredSessions(); n != 1 {
		t.Fatalf("DATA target reclaimed %d tombstones; want 1", n)
	}
	if sessionPresent(data.a, dataRetired) {
		t.Fatal("the DATA target's eligible tombstone was not reclaimed")
	}

	// The CONTROL carrier's roots did not advance, so it must record no proof and
	// must never reclaim its own tombstone out of the DATA transaction.
	if control.a.stableProofValid {
		t.Fatal("the CONTROL carrier claimed a stable proof for roots it never advanced")
	}
	if n := control.a.ReclaimRetiredSessions(); n != 0 {
		t.Fatalf("the CONTROL carrier reclaimed %d tombstones from the DATA transaction; want 0", n)
	}
	if !sessionPresent(control.a, controlRetired) {
		t.Fatal("the CONTROL tombstone was reclaimed although its root never advanced")
	}
}

// TestDataTargetRekeyKeepsControlPolicyBaseline is the real 4-end policy test for
// the DATA-only rotation: the CONTROL owner's roots never change, so its key-use
// accounting must NOT be refreshed (no replenished Remaining, no zeroed age, no
// false new stable generation and no reset of the injected network ledger), while
// the DATA target's baseline DOES advance under its fresh roots.
func TestDataTargetRekeyKeepsControlPolicyBaseline(t *testing.T) {
	control := establishedControlPairWith(t, 91, 2, 17)
	data := establishedControlPairWith(t, 137, 9, 41)
	const sealLimit = 64
	policy := KeyUpdatePolicy{SealLimit: sealLimit}

	// One fake clock for all four carriers, so the age baseline is observable.
	var clockMu sync.Mutex
	current := time.Now()
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return current
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		current = current.Add(d)
		clockMu.Unlock()
	}
	for _, io := range []*ProtectedControlIO{control.a, control.b, data.a, data.b} {
		io.usage.setPolicy(policy)
		io.usage.setClock(clock)
	}

	configure := func(io *ProtectedControlIO, identity security.Identity, peer [32]byte, target *ProtectedControlIO) {
		t.Helper()
		if err := io.ConfigureKeyUpdate(KeyUpdateConfig{
			Identity: identity, PeerStatic: peer, PSK: control.psk, Descriptor: control.descriptor,
			TargetLinkID: data.ar.LinkID, TargetLinkEpoch: data.ar.LinkEpoch, LaneID: data.ar.LaneID,
			PeerAdvertisedKeyUpdate: true, Policy: policy,
			TargetLookup: func(linkID, epoch uint64, lane uint8) (KeyUpdateCarrier, error) {
				if linkID != data.ar.LinkID || epoch != data.ar.LinkEpoch || lane != data.ar.LaneID {
					return nil, ErrKeyUpdateTarget
				}
				return target, nil
			},
		}); err != nil {
			t.Fatalf("configure: %v", err)
		}
	}
	configure(control.a, control.alice, control.ar.PeerStatic, data.a)
	configure(control.b, control.bob, control.br.PeerStatic, data.b)

	// A shared network ledger on the DATA target, pre-charged, to prove a DATA
	// rekey never resets it.
	ledger := &testVerificationBudget{limit: 8}
	data.a.SetVerificationBudget(ledger)
	data.a.noteVerifyFailure(KeyDomainControl)
	if got := ledger.count(); got != 1 {
		t.Fatalf("ledger precondition = %d; want 1", got)
	}

	// Pre-consume CONTROL owner seals and let its age accrue, so a baseline reset
	// would be observable as a replenished Remaining and a zeroed Age.
	for i := 0; i < 3; i++ {
		writeControlDrained(t, control.a, control.b, 1, bytes.Repeat([]byte{0x31}, 16))
	}
	advance(90 * time.Minute)
	before := control.a.KeyUpdateUsageSnapshot()
	if before.Control.Seals != 3 || before.AgeSeconds != int64(90*time.Minute/time.Second) {
		t.Fatalf("CONTROL precondition: %+v", before)
	}
	if dataBefore := data.a.KeyUpdateUsageSnapshot(); dataBefore.Control.Seals != 0 || dataBefore.RemainingSeals != sealLimit {
		t.Fatalf("DATA precondition: %+v", dataBefore)
	}

	driverA, driverB := newKeyUpdateTargetDriver(control.a), newKeyUpdateTargetDriver(control.b)
	driverA.start(t, control.a, data.a)
	driverB.start(t, control.b, data.b)
	defer driverA.stop()
	defer driverB.stop()
	actions, err := control.a.RequestKeyUpdate()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range actions {
		driverA.actions <- action
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if control.a.KeyUpdateStatus().State == KuStateStable && control.b.KeyUpdateStatus().State == KuStateStable {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if err := driverA.failure(); err != nil {
		t.Fatalf("driver A: %v", err)
	}
	if err := driverB.failure(); err != nil {
		t.Fatalf("driver B: %v", err)
	}
	if control.a.KeyUpdateStatus().State != KuStateStable || control.b.KeyUpdateStatus().State != KuStateStable {
		t.Fatalf("DATA-target update did not stabilize: A %s B %s",
			control.a.KeyUpdateStatus().State, control.b.KeyUpdateStatus().State)
	}

	// The CONTROL owner's roots never switched: its baseline, age, status and the
	// injected network ledger all stay exactly as they were, while the extra
	// negotiation 0x09 seals are still counted against the same relative budget.
	after := control.a.KeyUpdateUsageSnapshot()
	if after.StableGeneration != 0 {
		t.Fatalf("CONTROL owner reported stable generation %d for roots it never switched", after.StableGeneration)
	}
	if after.AgeSeconds != before.AgeSeconds || after.AgeSeconds == 0 {
		t.Fatalf("CONTROL owner age baseline moved: %d -> %d", before.AgeSeconds, after.AgeSeconds)
	}
	if after.RemainingSeals >= sealLimit || after.RemainingSeals > before.RemainingSeals {
		t.Fatalf("CONTROL owner relative budget was replenished: %d -> %d", before.RemainingSeals, after.RemainingSeals)
	}
	if after.Control.Seals <= before.Control.Seals {
		t.Fatalf("negotiation control seals were not counted: %d -> %d", before.Control.Seals, after.Control.Seals)
	}
	if got := ledger.count(); got != 1 {
		t.Fatalf("the injected network ledger was reset by a DATA-only rotation: %d; want 1", got)
	}

	// The DATA target's roots did switch: its baseline advanced under the fresh
	// roots, replenishing the relative budget without erasing its lifetime count.
	dataAfter := data.a.KeyUpdateUsageSnapshot()
	if dataAfter.Control.Seals == 0 {
		t.Fatal("the DATA target's FENCE/CONFIRM seals were not counted")
	}
	if dataAfter.RemainingSeals != sealLimit {
		t.Fatalf("the DATA target budget was not replenished under its fresh root: %d; want %d", dataAfter.RemainingSeals, sealLimit)
	}
	if dataAfter.AgeSeconds != 0 {
		t.Fatalf("the DATA target age baseline was not advanced under its fresh root: %d", dataAfter.AgeSeconds)
	}
	if dataAfter.StableGeneration != control.a.KeyUpdateStatus().NewGeneration {
		t.Fatalf("the DATA target stable generation = %d; want the committed %d",
			dataAfter.StableGeneration, control.a.KeyUpdateStatus().NewGeneration)
	}
}

// TestAdmitSessionExistingFastPathIsIdempotent pins the frame-path optimization:
// an already-admitted live SessionID returns idempotently WITHOUT re-deriving or
// replacing the cached directional protectors, a class mismatch reports a
// conflict without touching the cached entry, and a root refresh is not undone.
func TestAdmitSessionExistingFastPathIsIdempotent(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0xE5)
	if err := pair.a.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	pair.a.sessionMu.RLock()
	entry := pair.a.sessions[sessionID]
	txPtr, rxPtr := entry.tx, entry.rx
	pair.a.sessionMu.RUnlock()
	txNext, routeNext, rxLast := pair.a.txNext, pair.a.routeNext, pair.a.rxLast

	// Repeated idempotent admission: same entry, same protectors, no counter work.
	for i := 0; i < 4; i++ {
		if err := pair.a.AdmitSession(sessionID, SessionClassStream); err != nil {
			t.Fatalf("idempotent admit %d: %v", i, err)
		}
	}
	pair.a.sessionMu.RLock()
	again := pair.a.sessions[sessionID]
	sameTx, sameRx := again.tx, again.rx
	pair.a.sessionMu.RUnlock()
	if again != entry {
		t.Fatal("idempotent admit replaced the admission entry")
	}
	if sameTx != txPtr || sameRx != rxPtr {
		t.Fatal("idempotent admit re-derived the cached directional protectors")
	}
	if pair.a.txNext != txNext || pair.a.routeNext != routeNext || pair.a.rxLast != rxLast {
		t.Fatal("idempotent admit moved a direction counter or replay floor")
	}

	// A class mismatch is a conflict and must leave the live entry untouched.
	if err := pair.a.AdmitSession(sessionID, SessionClassPacket); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("class mismatch error = %v; want ErrSessionConflict", err)
	}
	pair.a.sessionMu.RLock()
	mismatchTx, mismatchRx := pair.a.sessions[sessionID].tx, pair.a.sessions[sessionID].rx
	pair.a.sessionMu.RUnlock()
	if mismatchTx != txPtr || mismatchRx != rxPtr {
		t.Fatal("a conflicting admission replaced the live protectors")
	}

	// A direction refresh (as a FENCE performs) replaces the cached protector; an
	// idempotent admission after it must not undo or re-derive that.
	newRoot := pair.a.txRoot
	newRoot[0] ^= 0x33
	pair.a.txRoot = newRoot
	pair.a.atomicTxSlot.Store(&keyUpdateDirectionSlot{root: newRoot, generation: pair.a.txGen, direction: pair.a.txDirection, serial: 2})
	pair.a.refreshSessionTX()
	pair.a.sessionMu.RLock()
	refreshed := pair.a.sessions[sessionID].tx
	pair.a.sessionMu.RUnlock()
	if err := pair.a.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatalf("admit after refresh: %v", err)
	}
	pair.a.sessionMu.RLock()
	afterRefresh := pair.a.sessions[sessionID].tx
	pair.a.sessionMu.RUnlock()
	if afterRefresh != refreshed {
		t.Fatal("idempotent admit re-derived over the refreshed cached protector")
	}
}

// BenchmarkAdmitSessionExisting measures the frame-path fast path: an existing
// live admission must allocate nothing and derive no key material.
func BenchmarkAdmitSessionExisting(b *testing.B) {
	pair := establishedControlPair(b)
	sessionID := testSessionID(0xE6)
	if err := pair.a.AdmitSession(sessionID, SessionClassStream); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pair.a.AdmitSession(sessionID, SessionClassStream); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAdmitSessionNew measures a fresh admission (two directional leaf
// derivations plus the table insert) for contrast with the fast path. The entry
// is removed each iteration so the table never grows; that removal is part of the
// loop and only makes this contrast benchmark slightly conservative.
func BenchmarkAdmitSessionNew(b *testing.B) {
	pair := establishedControlPair(b)
	sessionID := testSessionID(0xE7)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pair.a.AdmitSession(sessionID, SessionClassStream); err != nil {
			b.Fatal(err)
		}
		pair.a.sessionMu.Lock()
		delete(pair.a.sessions, sessionID)
		pair.a.sessionMu.Unlock()
	}
}
