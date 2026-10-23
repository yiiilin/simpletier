package simpletier

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/circuit"
	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/session"
	"github.com/yiiilin/simpletier/internal/topology"
	"github.com/yiiilin/simpletier/internal/wire"
)

// stagingLedger is the observable slice of the shared allocator this test suite
// asserts on: the bytes/frames of the Data and State categories, the heap total
// they aggregate into, the outstanding lease count and the refused-request
// count. A leaked or double-released reservation shows up here as a delta from
// the baseline, so the tests never need an internal counter.
type stagingLedger struct {
	dataBytes, dataFrames uint64
	stateBytes            uint64
	heapBytes, heapFrames uint64
	leases                int
	rejected              uint64
}

func snapshotStagingLedger(a *budget.Allocator) stagingLedger {
	s := a.Stats()
	return stagingLedger{
		dataBytes:  s.Data.Bytes,
		dataFrames: s.Data.Frames,
		stateBytes: s.State.Bytes,
		heapBytes:  s.Heap.Bytes,
		heapFrames: s.Heap.Frames,
		leases:     s.Leases,
		rejected:   s.Rejected,
	}
}

// stagingTestNetwork builds a real Network whose one production allocator
// carries the caller's lowered limits, so every assertion below runs against the
// real ledger and the real refusal path rather than a mock. The seam is restored
// immediately after construction; the Network keeps the allocator it was built
// with.
func stagingTestNetwork(t *testing.T, token string, mutate func(*budget.Limits)) *network {
	t.Helper()
	limits := budget.DefaultLimits()
	if mutate != nil {
		mutate(&limits)
	}
	previous := testNetworkBudgetLimits
	testNetworkBudgetLimits = &limits
	cfg := validConfig()
	url, _ := freeTCPListenAddress(t)
	cfg.Listen, cfg.Upstreams = []string{url}, nil
	cfg.Network.Token = token
	handle, err := NewNetwork(cfg)
	testNetworkBudgetLimits = previous
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := handle.Close(); err != nil {
			t.Error(err)
		}
	})
	return handle.(*network)
}

// stagingTestSession returns one live Session from a fresh local identity. The
// Noise handshake is deliberately never completed: the staging paths under test
// only need a real per-Session pending counter and its real lifecycle, and
// completing a handshake would not change any reservation this suite asserts on.
func stagingTestSession(t *testing.T, n *network) *session.Session {
	t.Helper()
	store, err := security.OpenIdentityStore()
	if err != nil {
		t.Fatalf("open test identity store: %v", err)
	}
	identity, err := store.Identity()
	if err != nil {
		_ = store.Close()
		t.Fatalf("read test identity: %v", err)
	}
	provider, err := session.NewNoiseProvider(identity, n.networkContext, session.ProviderPolicy{
		PendingMax: 8,
		PendingTTL: 30 * time.Second,
	})
	if err != nil {
		_ = store.Close()
		t.Fatalf("open test Noise provider: %v", err)
	}
	var peerStatic [32]byte
	peerStatic[0] = 0x5a
	manager, err := session.NewManager(session.Config{
		ContextID:   n.networkContext.ID(),
		PSK:         n.networkPSK,
		LocalStatic: identity.PublicKey,
		PeerStatic:  peerStatic,
		Crypto:      provider,
	})
	if err != nil {
		provider.Close()
		_ = store.Close()
		t.Fatalf("open test session manager: %v", err)
	}
	sess, err := manager.Open(context.Background(), 1, 1, session.SessionClassStream, session.LaneStream)
	if err != nil {
		_ = manager.Close()
		provider.Close()
		_ = store.Close()
		t.Fatalf("open test session: %v", err)
	}
	t.Cleanup(func() {
		_ = manager.Close()
		provider.Close()
		_ = store.Close()
	})
	return sess
}

// stagingTestPump returns the exact ingress pump identity the shared allocator
// pins a staged copy to. The physical Link instance is registered through the
// production helper, so the LinkPool charge is admitted exactly as in the
// runtime.
func stagingTestPump(t *testing.T, n *network, linkID, epoch uint64) *controlPump {
	t.Helper()
	if err := n.registerPhysicalLinkKey(linkID, epoch); err != nil {
		t.Fatalf("register test physical Link %d/%d: %v", linkID, epoch, err)
	}
	t.Cleanup(func() { n.dropPhysicalLinkKey(linkID, epoch) })
	return &controlPump{network: n, linkKey: budget.LinkKey{LinkID: linkID, Epoch: epoch}}
}

// stagingTestEntry builds one uncommitted entry of the given id. A relay entry
// carries no root by production construction; a test may still attach a Session
// to observe that the relay stage never touches the per-Session counter.
func stagingTestEntry(t *testing.T, id byte, sess *session.Session, relay bool) *sessionEntry {
	t.Helper()
	var sid session.SessionID
	sid[0] = id
	return &sessionEntry{
		id:    sid,
		scope: pathScope{id: 1, gen: 1},
		class: session.SessionClassStream,
		lane:  session.LaneStream,
		relay: relay,
		sess:  sess,
		ready: make(chan struct{}),
	}
}

// stagingEnvelope returns one complete inbound E2E envelope for this Network.
func stagingEnvelope(n *network, sid session.SessionID, innerLen int) []byte {
	return buildEnvelope(n.networkContext.WireID(), [16]byte{0xAA}, [16]byte{0xBB},
		wire.MessageTypeStreamData, [16]byte(sid), 1, 0, 1, 1, innerLen)
}

// stagingMessage builds one hop-authenticated inbound message the staging paths
// can hold: a complete envelope plus an opaque body.
func stagingMessage(n *network, sid session.SessionID, body []byte) link.ProtectedMessage {
	return link.ProtectedMessage{
		Kind:     wire.FrameKindEndToEnd,
		Envelope: stagingEnvelope(n, sid, len(body)),
		Payload:  body,
		Class:    byte(session.SessionClassStream),
	}
}

// TestStagedInboundCiphertextChargedOnceBeforeCopy proves an endpoint stage books
// the exact copied envelope+body once against the Network Data pool through the
// physical ingress Link account, books one bounded pendingFrame metadata charge
// as State, and returns both to the baseline exactly once on drop. The
// per-Session pending counter stays the secondary bound it always was.
func TestStagedInboundCiphertextChargedOnceBeforeCopy(t *testing.T) {
	n := stagingTestNetwork(t, "staging-inbound-token-0123456789", nil)
	alloc := n.stateBudgetPtr()
	sess := stagingTestSession(t, n)
	pump := stagingTestPump(t, n, 0x11, 1)
	entry := stagingTestEntry(t, 0x01, sess, false)
	body := bytes.Repeat([]byte{0xA5}, 4096)
	message := stagingMessage(n, entry.id, body)

	baseline := snapshotStagingLedger(alloc)
	n.streams.stageInboundFrame(entry, pump, message)

	wantData := uint64(len(message.Envelope) + len(message.Payload))
	after := snapshotStagingLedger(alloc)
	if got := after.dataBytes - baseline.dataBytes; got != wantData {
		t.Fatalf("Network Data bytes charged %d; want %d charged exactly once", got, wantData)
	}
	if got := after.dataFrames - baseline.dataFrames; got != 1 {
		t.Fatalf("Data frames charged %d; want 1", got)
	}
	if got := after.stateBytes - baseline.stateBytes; got != pendingFrameMetadataBytes {
		t.Fatalf("State metadata charged %d; want %d", got, pendingFrameMetadataBytes)
	}
	if got := after.heapBytes - baseline.heapBytes; got != wantData+pendingFrameMetadataBytes {
		t.Fatalf("heap charged %d; want %d (data + state each once)", got, wantData+pendingFrameMetadataBytes)
	}
	if got := after.leases - baseline.leases; got != 1 {
		t.Fatalf("outstanding leases %d; want 1", got)
	}
	if got := after.rejected; got != baseline.rejected {
		t.Fatalf("a successful stage refused %d request(s)", got-baseline.rejected)
	}
	if got := sess.PendingBytes(); got != len(body) {
		t.Fatalf("per-Session pending counter = %d; want %d", got, len(body))
	}
	if len(entry.pending) != 1 || entry.pendBytes != len(body) {
		t.Fatalf("staged queue = %d frames/%d bytes; want 1/%d", len(entry.pending), entry.pendBytes, len(body))
	}
	frame := &entry.pending[0]
	if frame.lease == nil || !frame.hasSessionReservation {
		t.Fatalf("staged frame ownership = lease %v / session-reserved %v; want both set", frame.lease != nil, frame.hasSessionReservation)
	}
	if !bytes.Equal(frame.envelope, message.Envelope) || !bytes.Equal(frame.body, message.Payload) {
		t.Fatal("staged frame does not hold the exact copied envelope and body")
	}

	// Drop returns every reservation exactly once; a second release is a no-op.
	releaseStagedFrame(entry, frame)
	releaseStagedFrame(entry, frame)
	if got := snapshotStagingLedger(alloc); got != baseline {
		t.Fatalf("ledger after drop = %+v; want baseline %+v", got, baseline)
	}
	if got := sess.PendingBytes(); got != 0 {
		t.Fatalf("per-Session pending counter after drop = %d; want 0", got)
	}
}

// TestStagedInboundCiphertextRefusalDropsOnlyTheFrame proves both the Network
// Data cap and the per-Link Data cap refuse the whole composite before any copy,
// leaving the ledger exactly at its baseline, the queue empty and the allocator's
// rejected count advanced by one.
func TestStagedInboundCiphertextRefusalDropsOnlyTheFrame(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*budget.Limits)
	}{
		{
			name:   "network data cap",
			mutate: func(l *budget.Limits) { l.DataBytes = 1024 },
		},
		{
			name:   "physical link data cap",
			mutate: func(l *budget.Limits) { l.LinkDataBytes = 1024 },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := stagingTestNetwork(t, "staging-refusal-token-0123456789", tc.mutate)
			alloc := n.stateBudgetPtr()
			sess := stagingTestSession(t, n)
			pump := stagingTestPump(t, n, 0x12, 2)
			entry := stagingTestEntry(t, 0x02, sess, false)
			message := stagingMessage(n, entry.id, bytes.Repeat([]byte{0x3C}, 4096))

			baseline := snapshotStagingLedger(alloc)
			n.streams.stageInboundFrame(entry, pump, message)

			if len(entry.pending) != 0 || entry.pendBytes != 0 {
				t.Fatalf("refused frame was staged: frames=%d bytes=%d", len(entry.pending), entry.pendBytes)
			}
			if got := sess.PendingBytes(); got != 0 {
				t.Fatalf("refused frame booked %d per-Session pending bytes", got)
			}
			after := snapshotStagingLedger(alloc)
			if after.dataBytes != baseline.dataBytes || after.stateBytes != baseline.stateBytes ||
				after.heapBytes != baseline.heapBytes || after.leases != baseline.leases {
				t.Fatalf("refused composite changed the ledger: %+v -> %+v", baseline, after)
			}
			if got := after.rejected - baseline.rejected; got != 1 {
				t.Fatalf("allocator rejected count advanced by %d; want 1", got)
			}
		})
	}
}

// TestStagedInboundQueueReleasedOnDrainAndClose proves the drop paths are
// balanced and terminal: a drain with no protector wipes and releases every
// staged frame, the close path does the same, and after the terminal latch no
// new frame can be staged unaccounted.
func TestStagedInboundQueueReleasedOnDrainAndClose(t *testing.T) {
	n := stagingTestNetwork(t, "staging-drain-token-0123456789", nil)
	alloc := n.stateBudgetPtr()
	sess := stagingTestSession(t, n)
	pump := stagingTestPump(t, n, 0x13, 3)
	entry := stagingTestEntry(t, 0x03, sess, false)
	baseline := snapshotStagingLedger(alloc)

	stage := func(count int) {
		for i := 0; i < count; i++ {
			n.streams.stageInboundFrame(entry, pump, stagingMessage(n, entry.id, bytes.Repeat([]byte{0x11}, 512)))
		}
	}

	stage(5)
	if len(entry.pending) != 5 {
		t.Fatalf("staged %d frames; want 5", len(entry.pending))
	}
	// A drain with no installed protector cannot open anything: every frame is
	// dropped and wiped, never re-queued.
	n.streams.drainStaged(entry)
	if len(entry.pending) != 0 || entry.pendBytes != 0 {
		t.Fatalf("drain left %d frames/%d bytes staged", len(entry.pending), entry.pendBytes)
	}
	if got := snapshotStagingLedger(alloc); got != baseline {
		t.Fatalf("ledger after drain = %+v; want baseline %+v", got, baseline)
	}
	if got := sess.PendingBytes(); got != 0 {
		t.Fatalf("per-Session pending counter after drain = %d; want 0", got)
	}

	stage(5)
	entry.releasePending()
	if got := snapshotStagingLedger(alloc); got != baseline {
		t.Fatalf("ledger after releasePending = %+v; want baseline %+v", got, baseline)
	}
	if got := sess.PendingBytes(); got != 0 {
		t.Fatalf("per-Session pending counter after releasePending = %d; want 0", got)
	}

	// The terminal latch refuses a later stage instead of owning a lease that
	// nothing would ever drain.
	n.streams.stageInboundFrame(entry, pump, stagingMessage(n, entry.id, bytes.Repeat([]byte{0x22}, 512)))
	if len(entry.pending) != 0 {
		t.Fatal("a frame was staged after the queue latched terminal")
	}
	if got := snapshotStagingLedger(alloc); got != baseline {
		t.Fatalf("ledger after terminal refusal = %+v; want baseline %+v", got, baseline)
	}
}

// TestStagedRelayCiphertextChargedWithoutSessionReservation proves a rootless
// relay stage books the exact copied envelope+body once against the shared Data
// pool and one metadata State charge, keeps its own explicit
// session.MaxPendingBytes/frame ceiling, and never touches the per-Session
// pending counter. Release and the close path both balance without underflowing.
func TestStagedRelayCiphertextChargedWithoutSessionReservation(t *testing.T) {
	n := stagingTestNetwork(t, "staging-relay-token-0123456789", nil)
	alloc := n.stateBudgetPtr()
	// A relay entry has no root; the attached Session only proves the relay
	// stage does not consume its pending counter.
	sess := stagingTestSession(t, n)
	pump := stagingTestPump(t, n, 0x21, 7)
	entry := stagingTestEntry(t, 0x21, sess, true)
	body := bytes.Repeat([]byte{0x7E}, 4096)
	envelope := stagingEnvelope(n, entry.id, len(body))
	hop := link.HopRoute{Cursor: 1, HopLimit: 8, RemainingBudget: 1 << 20}

	baseline := snapshotStagingLedger(alloc)
	if err := n.streams.stageRelayFrame(entry, pump, envelope, body, hop); err != nil {
		t.Fatalf("stageRelayFrame: %v", err)
	}
	wantData := uint64(len(envelope) + len(body))
	after := snapshotStagingLedger(alloc)
	if got := after.dataBytes - baseline.dataBytes; got != wantData {
		t.Fatalf("relay Data bytes charged %d; want %d charged exactly once", got, wantData)
	}
	if got := after.dataFrames - baseline.dataFrames; got != 1 {
		t.Fatalf("relay Data frames charged %d; want 1", got)
	}
	if got := after.stateBytes - baseline.stateBytes; got != pendingFrameMetadataBytes {
		t.Fatalf("relay State metadata charged %d; want %d", got, pendingFrameMetadataBytes)
	}
	if got := after.leases - baseline.leases; got != 1 {
		t.Fatalf("relay outstanding leases %d; want 1", got)
	}
	if got := sess.PendingBytes(); got != 0 {
		t.Fatalf("rootless relay stage consumed %d per-Session pending bytes; want 0", got)
	}
	if len(entry.pending) != 1 || entry.pendBytes != len(body) {
		t.Fatalf("relay queue = %d frames/%d bytes; want 1/%d", len(entry.pending), entry.pendBytes, len(body))
	}
	if frame := &entry.pending[0]; frame.hasSessionReservation || frame.reserved != 0 {
		t.Fatalf("relay frame claims a Session reservation (flag=%v reserved=%d); want none",
			frame.hasSessionReservation, frame.reserved)
	}

	releaseStagedFrame(entry, &entry.pending[0])
	if got := snapshotStagingLedger(alloc); got != baseline {
		t.Fatalf("ledger after relay drop = %+v; want baseline %+v", got, baseline)
	}
	if got := sess.PendingBytes(); got != 0 {
		t.Fatalf("per-Session pending counter changed to %d; want 0 (no negative clamp)", got)
	}

	// The close path on a relay entry is balanced too.
	if err := n.streams.stageRelayFrame(entry, pump, envelope, body, hop); err != nil {
		t.Fatalf("stageRelayFrame (second): %v", err)
	}
	entry.releasePending()
	if got := snapshotStagingLedger(alloc); got != baseline {
		t.Fatalf("ledger after relay releasePending = %+v; want baseline %+v", got, baseline)
	}
	if got := sess.PendingBytes(); got != 0 {
		t.Fatalf("per-Session pending counter after relay close = %d; want 0", got)
	}
}

// TestStagedRelayQueueCeilingRefusesWithoutCharging proves the relay queue keeps
// an explicit byte ceiling: once the next body would pass session.MaxPendingBytes
// the frame is refused, nothing is copied and no lease is taken.
func TestStagedRelayQueueCeilingRefusesWithoutCharging(t *testing.T) {
	n := stagingTestNetwork(t, "staging-relay-ceiling-token-0123456789", nil)
	alloc := n.stateBudgetPtr()
	pump := stagingTestPump(t, n, 0x22, 8)
	entry := stagingTestEntry(t, 0x22, nil, true)
	const bodyLen = 2000
	// 32 bodies of 2000 bytes are 64000 <= 65897; the 33rd would pass the
	// frozen per-Session ceiling, so the relay refuses it even though its frame
	// count (33) is still below the 64-frame secondary bound.
	const staged = 32
	baseline := snapshotStagingLedger(alloc)
	for i := 0; i < staged; i++ {
		if err := n.streams.stageRelayFrame(entry, pump, stagingEnvelope(n, entry.id, bodyLen), bytes.Repeat([]byte{0x01}, bodyLen), link.HopRoute{HopLimit: 8}); err != nil {
			t.Fatalf("stage %d: %v", i, err)
		}
	}
	if len(entry.pending) != staged || entry.pendBytes != staged*bodyLen {
		t.Fatalf("relay queue = %d frames/%d bytes; want %d/%d", len(entry.pending), entry.pendBytes, staged, staged*bodyLen)
	}
	charged := snapshotStagingLedger(alloc)
	if got := charged.dataBytes - baseline.dataBytes; got != uint64(staged)*(uint64(bodyLen)+uint64(len(stagingEnvelope(n, entry.id, bodyLen)))) {
		t.Fatalf("relay charged %d data bytes for %d frames; want %d", got, staged, staged*(bodyLen+len(stagingEnvelope(n, entry.id, bodyLen))))
	}
	if err := n.streams.stageRelayFrame(entry, pump, stagingEnvelope(n, entry.id, bodyLen), bytes.Repeat([]byte{0x02}, bodyLen), link.HopRoute{HopLimit: 8}); err != nil {
		t.Fatalf("over-ceiling relay stage returned %v; want a scoped drop", err)
	}
	if len(entry.pending) != staged || entry.pendBytes != staged*bodyLen {
		t.Fatalf("over-ceiling relay stage changed the queue: %d frames/%d bytes", len(entry.pending), entry.pendBytes)
	}
	if got := snapshotStagingLedger(alloc); got != charged {
		t.Fatalf("over-ceiling relay stage changed the ledger: %+v -> %+v", charged, got)
	}
	entry.releasePending()
	if got := snapshotStagingLedger(alloc); got != baseline {
		t.Fatalf("ledger after relay ceiling release = %+v; want baseline %+v", got, baseline)
	}
}

// TestStagedQueueFrameCapAndDrainCloseRaceExactlyOnce proves the 64-frame
// secondary bound still holds and that a concurrent stager, drainer and close
// release every lease exactly once: the ledger returns to its exact baseline
// (a double release would underflow the unsigned counters instead) with the
// per-Session counter back at zero.
func TestStagedQueueFrameCapAndDrainCloseRaceExactlyOnce(t *testing.T) {
	n := stagingTestNetwork(t, "staging-race-token-0123456789", nil)
	alloc := n.stateBudgetPtr()
	sess := stagingTestSession(t, n)
	pump := stagingTestPump(t, n, 0x31, 11)
	entry := stagingTestEntry(t, 0x31, sess, false)
	baseline := snapshotStagingLedger(alloc)

	for i := 0; i < pendingSessionFrames; i++ {
		n.streams.stageInboundFrame(entry, pump, stagingMessage(n, entry.id, bytes.Repeat([]byte{0x44}, 256)))
	}
	if len(entry.pending) != pendingSessionFrames {
		t.Fatalf("staged %d frames; want the %d-frame cap filled", len(entry.pending), pendingSessionFrames)
	}
	full := snapshotStagingLedger(alloc)
	if got := full.leases - baseline.leases; got != pendingSessionFrames {
		t.Fatalf("outstanding leases at cap = %d; want %d", got, pendingSessionFrames)
	}
	// The frame after the cap is refused without a lease.
	n.streams.stageInboundFrame(entry, pump, stagingMessage(n, entry.id, bytes.Repeat([]byte{0x45}, 256)))
	if len(entry.pending) != pendingSessionFrames {
		t.Fatalf("frame cap overflowed to %d", len(entry.pending))
	}
	if got := snapshotStagingLedger(alloc); got != full {
		t.Fatalf("cap refusal changed the ledger: %+v -> %+v", full, got)
	}

	// Race a stager against a drainer and the close path. Only the stager ever
	// calls the allocator's Reserve during this window (drain and release only
	// release), so the allocator's own Rejected delta around each attempt is an
	// exact, atomically-observed count of the attempts the shared ledger
	// refused. The terminal latch must stop new admissions, and every admitted
	// frame must be released once.
	var observedRefusals atomic.Uint64
	stop := make(chan struct{})
	var stager sync.WaitGroup
	stager.Add(1)
	go func() {
		defer stager.Done()
		for {
			select {
			case <-stop:
				return
			default:
				before := alloc.Stats().Rejected
				n.streams.stageInboundFrame(entry, pump, stagingMessage(n, entry.id, bytes.Repeat([]byte{0x46}, 128)))
				if after := alloc.Stats().Rejected; after > before {
					observedRefusals.Add(after - before)
				}
			}
		}
	}()
	var racers sync.WaitGroup
	racers.Add(2)
	go func() { defer racers.Done(); n.streams.drainStaged(entry) }()
	go func() { defer racers.Done(); entry.releasePending() }()
	racers.Wait()
	close(stop)
	stager.Wait()

	// Every resource counter and the outstanding lease count must return exactly
	// to baseline: a double release would underflow the unsigned byte/frame
	// counters and a leaked lease would leave a lease outstanding. The allocator's
	// rejected count is reconciled exactly against the atomically observed
	// refusals rather than ignored: while this drainer holds a snapshot whose
	// frame charges are not yet unbooked, the racing stager can legitimately
	// exhaust the physical Link's frozen 64-frame data bound, and every such drop
	// must be one observed, accounted refusal - never a silent or leaked one.
	after := snapshotStagingLedger(alloc)
	if after.dataBytes != baseline.dataBytes || after.dataFrames != baseline.dataFrames ||
		after.stateBytes != baseline.stateBytes || after.heapBytes != baseline.heapBytes ||
		after.heapFrames != baseline.heapFrames || after.leases != baseline.leases {
		t.Fatalf("resource ledger after drain/close race = %+v; want baseline %+v (a double release underflows)", after, baseline)
	}
	if got, observed := after.rejected-baseline.rejected, observedRefusals.Load(); got != observed {
		t.Fatalf("allocator refusals = %d but stager observed %d; a refusal was unobserved", got, observed)
	}
	if got := sess.PendingBytes(); got != 0 {
		t.Fatalf("per-Session pending counter after race = %d; want 0", got)
	}
	if len(entry.pending) != 0 || entry.pendBytes != 0 {
		t.Fatalf("queue after race = %d frames/%d bytes; want empty", len(entry.pending), entry.pendBytes)
	}
	// The latch is terminal: no later stage may own a lease.
	rejectedBefore := snapshotStagingLedger(alloc).rejected
	n.streams.stageInboundFrame(entry, pump, stagingMessage(n, entry.id, bytes.Repeat([]byte{0x47}, 128)))
	got := snapshotStagingLedger(alloc)
	if got.dataBytes != baseline.dataBytes || got.stateBytes != baseline.stateBytes ||
		got.heapBytes != baseline.heapBytes || got.leases != baseline.leases {
		t.Fatalf("post-race stage changed the resource ledger: %+v -> %+v", baseline, got)
	}
	if got.rejected != rejectedBefore {
		t.Fatalf("a terminal refusal reached the allocator: rejected %d -> %d", rejectedBefore, got.rejected)
	}
}

// TestStagedPhysicalLinkFrameCapRefusesOnceThenRecovers proves the staged
// ciphertext charges the physical Link's frozen 64-frame data bound: with that
// bound filled by one Session, a second Session's frame on the same Link is
// refused exactly once (allocator Rejected advances by one, nothing staged),
// and after the first Session's queue is released the very same Link admits the
// frame normally again. The refusal is scoped to the frame: no Link or Session
// is torn down.
func TestStagedPhysicalLinkFrameCapRefusesOnceThenRecovers(t *testing.T) {
	n := stagingTestNetwork(t, "staging-linkcap-token-0123456789", nil)
	alloc := n.stateBudgetPtr()
	pump := stagingTestPump(t, n, 0x32, 12)
	// Two separate Sessions share one physical Link, so the per-Session frame
	// bound cannot be what refuses the second Session's first frame.
	first := stagingTestEntry(t, 0x41, stagingTestSession(t, n), false)
	second := stagingTestEntry(t, 0x42, stagingTestSession(t, n), false)
	baseline := snapshotStagingLedger(alloc)

	for i := 0; i < pendingSessionFrames; i++ {
		n.streams.stageInboundFrame(first, pump, stagingMessage(n, first.id, bytes.Repeat([]byte{0x51}, 128)))
	}
	if len(first.pending) != pendingSessionFrames {
		t.Fatalf("first Session staged %d frames; want %d", len(first.pending), pendingSessionFrames)
	}
	atCap := snapshotStagingLedger(alloc)

	// The second Session's first frame would make the Link own 65 data frames.
	n.streams.stageInboundFrame(second, pump, stagingMessage(n, second.id, bytes.Repeat([]byte{0x52}, 128)))
	if len(second.pending) != 0 || second.pendBytes != 0 {
		t.Fatalf("over-cap frame was staged: frames=%d bytes=%d", len(second.pending), second.pendBytes)
	}
	refused := snapshotStagingLedger(alloc)
	if got := refused.rejected - atCap.rejected; got != 1 {
		t.Fatalf("allocator refusals = %d; want exactly 1", got)
	}
	// The refusal is all-or-none: only the rejected counter moved.
	if refused.dataBytes != atCap.dataBytes || refused.stateBytes != atCap.stateBytes ||
		refused.heapBytes != atCap.heapBytes || refused.leases != atCap.leases {
		t.Fatalf("refused frame changed the resource ledger: %+v -> %+v", atCap, refused)
	}

	// The scoped refusal failed only the offending second Session and left the
	// physical Link healthy.
	if !second.isTerminated() {
		t.Fatal("the refused Session was not latched terminal")
	}
	if err := second.sess.ReservePending(1); err == nil {
		t.Fatal("the refused Session still accepts reservations")
	}

	// Releasing the first Session's queue frees the Link's frame bound, so a
	// fresh third Session on the very same Link is admitted normally again: the
	// refusal was scoped, not a Link failure.
	first.releasePending()
	third := stagingTestEntry(t, 0x43, stagingTestSession(t, n), false)
	n.streams.stageInboundFrame(third, pump, stagingMessage(n, third.id, bytes.Repeat([]byte{0x53}, 128)))
	if len(third.pending) != 1 {
		t.Fatalf("fresh Session after recovery staged %d frames; want 1", len(third.pending))
	}
	if got := snapshotStagingLedger(alloc).rejected; got != refused.rejected {
		t.Fatalf("recovery admission advanced rejected to %d; want %d", got, refused.rejected)
	}
	third.releasePending()

	// Every resource counter returns to baseline; the single intentional refusal
	// is the only counter allowed to stay advanced.
	want := baseline
	want.rejected = refused.rejected
	if got := snapshotStagingLedger(alloc); got != want {
		t.Fatalf("ledger after recovery release = %+v; want %+v", got, want)
	}
}

// controlRPCPayload returns a minimal CONTROL_RPC payload carrying one opcode.
// The rate admission decision reads only the leading opcode, so no body is
// needed for these tests.
func controlRPCPayload(code circuit.RPCCode) []byte {
	out := make([]byte, 10)
	binary.BigEndian.PutUint16(out[:2], uint16(code))
	return out
}

// controlRPCWindowUpdatePayload builds a well-formed WINDOW_UPDATE body. It has
// to be complete: ingress now decodes the opcode before deciding whether to
// charge, so a short body is a malformed message rather than an over-budget one.
func controlRPCWindowUpdatePayload(circuitID [16]byte, window uint64) []byte {
	out := make([]byte, 10, 34)
	binary.BigEndian.PutUint16(out[:2], uint16(circuit.RPCWindowUpdate))
	out = append(out, circuitID[:]...)
	out = binary.BigEndian.AppendUint64(out, window)
	return out
}

// withOneControlToken lowers the frozen per-Link/Network control budget to a
// single token with no refill for one test, so the next genuine control charge
// must refuse.
func withOneControlToken(t *testing.T) {
	t.Helper()
	limits := defaultRateLimits()
	limits.linkControlPerSecond = 0
	limits.linkControlBurst = 1
	limits.networkControlPerSec = 0
	limits.networkControlBurst = 1
	limits.controlWait = time.Millisecond
	withRateLimits(t, limits)
}

// exhaustControlToken spends the single token of the lowered budget.
func exhaustControlToken(t *testing.T, n *network, linkID, epoch uint64) {
	t.Helper()
	if err := n.awaitIngressControl(n.ctx, linkID, epoch); err != nil {
		t.Fatalf("spending the single control token: %v", err)
	}
}

// TestControlRPCMessageTypeGovernsEgressCharging pins the frozen wire
// classification on the outbound path: the MessageType governs, so EVERY
// STREAM_DATA and receive-side credit feedback are both exempt from the shared
// control token, while session-lifecycle CONTROL_RPC still spends one.
func TestControlRPCMessageTypeGovernsEgressCharging(t *testing.T) {
	withOneControlToken(t)
	n := stagingTestNetwork(t, "control-egress-class-token-0123456789", nil)
	pump := stagingTestPump(t, n, 0x62, 22)
	exhaustControlToken(t, n, pump.linkKey.LinkID, pump.linkKey.Epoch)

	if err := n.streams.chargeEgressControlRPC(pump, circuit.Submission{Kind: circuit.KindStreamData}); err != nil {
		t.Fatalf("STREAM_DATA egress charge = %v; want nil (exempt)", err)
	}
	// Credit feedback is generated by this node's own drain rate and cannot be
	// amplified by a peer, so it must not be charged even with the budget spent.
	if err := n.streams.chargeEgressControlRPC(pump, circuit.Submission{Kind: circuit.KindControlRPC, FlowControl: true}); err != nil {
		t.Fatalf("WINDOW_UPDATE egress charge = %v; want nil (credit feedback is exempt)", err)
	}
	if err := n.streams.chargeEgressControlRPC(pump, circuit.Submission{Kind: circuit.KindControlRPC}); !errors.Is(err, circuit.ErrResource) {
		t.Fatalf("CONTROL_RPC egress over budget = %v; want circuit.ErrResource", err)
	}
}

// TestControlRPCIngressRefusalFailsSessionNotLink proves an over-budget inbound
// CONTROL_RPC is a scoped, observable failure: the delivery returns a handled
// nil (so the pump read loop keeps the physical Link), the offending Session is
// aborted and latched terminal, and every circuit-facing boundary then reports
// ErrSessionLost so the Manager closes that Session's Circuits instead of
// sealing on a dead Session.
func TestControlRPCIngressRefusalFailsSessionNotLink(t *testing.T) {
	withOneControlToken(t)
	n := stagingTestNetwork(t, "control-ingress-token-0123456789", nil)
	sess := stagingTestSession(t, n)
	entry := stagingTestEntry(t, 0x61, sess, false)
	// Register the entry so the circuit-facing boundaries (which resolve the
	// Session through the runtime table) exercise the real lookup path. The
	// Network close path then releases it like any other entry.
	n.streams.registerSession(entry)
	pump := stagingTestPump(t, n, 0x61, 21)
	exhaustControlToken(t, n, pump.linkKey.LinkID, pump.linkKey.Epoch)

	if err := n.streams.deliverCircuitFrame(wire.MessageTypeControlRPC, stagingEnvelope(n, entry.id, 10), entry, controlRPCPayload(circuit.RPCOpen), pump); err != nil {
		t.Fatalf("refused CONTROL_RPC delivery = %v; want a handled nil that keeps the Link", err)
	}
	if !entry.isTerminated() {
		t.Fatal("the refused Session was not latched terminal")
	}
	if err := sess.ReservePending(1); err == nil {
		t.Fatal("the refused Session still accepts reservations")
	}
	if _, err := (&circuitAdapter{rt: n.streams}).ProtectPayload(
		circuit.SessionRef{ID: circuit.SessionID(entry.id)}, circuit.DirectionSourceToTarget, []byte{1}); !errors.Is(err, circuit.ErrSessionLost) {
		t.Fatalf("ProtectPayload on a terminated Session = %v; want ErrSessionLost", err)
	}
	if err := n.streams.sendCircuitFrame(circuit.Submission{Session: circuit.SessionRef{ID: circuit.SessionID(entry.id)}}); !errors.Is(err, circuit.ErrSessionLost) {
		t.Fatalf("sendCircuitFrame on a terminated Session = %v; want ErrSessionLost", err)
	}
	// A later inbound frame for the terminated Session is consumed without
	// touching Circuit state and still does not fail the Link.
	if err := n.streams.deliverCircuitFrame(wire.MessageTypeControlRPC, stagingEnvelope(n, entry.id, 10), entry, controlRPCPayload(circuit.RPCOpen), pump); err != nil {
		t.Fatalf("post-terminal delivery = %v; want a handled nil", err)
	}
}

// TestControlRPCWindowUpdateConsumesControlToken proves the corrected inbound
// classification: a WINDOW_UPDATE is a CONTROL_RPC by MessageType, so over
// budget it spends the shared token and fails only its own Session with a
// handled nil (no Link teardown), exactly like every other opcode.
// WINDOW_UPDATE must stay deliverable with the control budget spent. It is
// receive-side credit feedback generated by this node's own drain rate, so it
// cannot be amplified by a peer; charging it pinned bulk throughput at one window
// per token and capped a 100 MiB transfer at about 3.5 MB/s. The session must also
// survive: a refused credit update used to fail the whole Session.
func TestControlRPCWindowUpdateExemptFromControlToken(t *testing.T) {
	withOneControlToken(t)
	n := stagingTestNetwork(t, "control-window-ingress-token-0123456789", nil)
	sess := stagingTestSession(t, n)
	entry := stagingTestEntry(t, 0x62, sess, false)
	n.streams.registerSession(entry)
	pump := stagingTestPump(t, n, 0x62, 22)
	exhaustControlToken(t, n, pump.linkKey.LinkID, pump.linkKey.Epoch)

	if err := n.streams.deliverCircuitFrame(wire.MessageTypeControlRPC, stagingEnvelope(n, entry.id, 10), entry, controlRPCWindowUpdatePayload([16]byte{0x62}, 131072), pump); err != nil {
		t.Fatalf("WINDOW_UPDATE delivery over budget = %v; want nil (credit feedback is exempt)", err)
	}
	if entry.isTerminated() {
		t.Fatal("WINDOW_UPDATE terminated the Session; credit feedback must not be refused")
	}
	// The exemption is scoped to this opcode only: a lifecycle CONTROL_RPC with
	// the same exhausted budget must still be refused, so the rate limiter keeps
	// protecting open/ready/reset traffic.
	if err := n.streams.deliverCircuitFrame(wire.MessageTypeControlRPC, stagingEnvelope(n, entry.id, 11), entry, controlRPCPayload(circuit.RPCStreamReset), pump); err != nil {
		t.Fatalf("STREAM_RESET delivery over budget = %v; want a handled nil", err)
	}
	if !entry.isTerminated() {
		t.Fatal("a lifecycle CONTROL_RPC over budget did not spend a control token")
	}
}

// TestControlRPCRelayChargesBothHalves proves the opaque relay halves are
// charged explicitly on the exact pump, and a pump-less relay charge is a
// permissive no-op rather than a hidden unaccounted charge.
func TestControlRPCRelayChargesBothHalves(t *testing.T) {
	withOneControlToken(t)
	n := stagingTestNetwork(t, "control-relay-token-0123456789", nil)
	pump := stagingTestPump(t, n, 0x64, 24)
	exhaustControlToken(t, n, pump.linkKey.LinkID, pump.linkKey.Epoch)
	if err := n.streams.chargeRelayControlRPC(pump, true); !errors.Is(err, ErrResource) {
		t.Fatalf("relay ingress over budget = %v; want ErrResource", err)
	}
	if err := n.streams.chargeRelayControlRPC(pump, false); !errors.Is(err, ErrResource) {
		t.Fatalf("relay egress over budget = %v; want ErrResource", err)
	}
	if err := n.streams.chargeRelayControlRPC(nil, true); err != nil {
		t.Fatalf("relay charge without a pump = %v; want nil", err)
	}
}

// TestStagedRelayRefusalLatchesPathTerminal proves a shared-allocator refusal on
// a staged relay frame is a typed scoped error that latches the relay path
// terminal, stages nothing, and does not keep re-attempting the allocator for
// later frames of that path.
func TestStagedRelayRefusalLatchesPathTerminal(t *testing.T) {
	n := stagingTestNetwork(t, "relay-refuse-token-0123456789", func(l *budget.Limits) {
		l.LinkDataBytes = 1024
	})
	alloc := n.stateBudgetPtr()
	pump := stagingTestPump(t, n, 0x65, 25)
	entry := stagingTestEntry(t, 0x65, nil, true)
	body := bytes.Repeat([]byte{0x66}, 4096)
	envelope := stagingEnvelope(n, entry.id, len(body))

	if err := n.streams.stageRelayFrame(entry, pump, envelope, body, link.HopRoute{HopLimit: 8}); !errors.Is(err, errRelayStagedRefused) {
		t.Fatalf("over-budget relay stage = %v; want errRelayStagedRefused", err)
	}
	if len(entry.pending) != 0 {
		t.Fatal("a refused relay frame was staged")
	}
	if !entry.relayPathBroken() || !entry.isTerminated() {
		t.Fatalf("relay path not latched terminal: broken=%v terminated=%v", entry.relayPathBroken(), entry.isTerminated())
	}
	// The latch is terminal: a later frame is refused without another allocator
	// attempt, so the rejected counter does not advance again.
	at := snapshotStagingLedger(alloc)
	if err := n.streams.stageRelayFrame(entry, pump, envelope, body, link.HopRoute{HopLimit: 8}); !errors.Is(err, errRelayStagedRefused) {
		t.Fatalf("latched relay stage = %v; want errRelayStagedRefused", err)
	}
	if got := snapshotStagingLedger(alloc); got != at {
		t.Fatalf("latched relay refusal changed the ledger: %+v -> %+v", at, got)
	}
}

// TestControlRPCEgressRefusalThroughSendCircuitFrame drives the REAL production
// egress call site rather than its helper: a live topology supplies a real
// authenticated STREAM pump, and a registered, ready Session entry with an
// installed E2E TX protector plus an installed Path pinned to that exact hop
// reaches the charge branch inside sendCircuitFrame. With the shared control
// budget drained, sendCircuitFrame itself must refuse the CONTROL_RPC with
// circuit.ErrResource, which is what makes the Manager reset only that Circuit.
func TestControlRPCEgressRefusalThroughSendCircuitFrame(t *testing.T) {
	const (
		name  = "control-egress"
		cidr  = "10.99.0.0/24"
		token = "control-egress-token-0123456789"
	)
	// A finite burst large enough for the real topology to converge, with a slow
	// refill so draining the budget leaves no token for the submission under
	// test.
	limits := defaultRateLimits()
	limits.linkControlPerSecond = 1
	limits.linkControlBurst = 8192
	limits.networkControlPerSec = 1
	limits.networkControlBurst = 8192
	limits.controlWait = time.Millisecond
	withRateLimits(t, limits)

	targetIP := netip.MustParseAddr("10.99.0.3")
	targetAddr := netip.AddrPortFrom(targetIP, 5001)
	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, "10.99.0.1", relayCarrierURL(target))

	listener, err := target.Listen("tcp", targetAddr.String())
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			stream, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(s Stream) {
				defer s.Close()
				buffer := make([]byte, 512)
				for {
					if _, readErr := s.Read(buffer); readErr != nil {
						return
					}
				}
			}(stream)
		}
	}()

	waitRelayLinks(t, target, 3, 30*time.Second)
	waitRelayLinks(t, source, 3, 30*time.Second)
	waitPacketRoute(t, source, targetIP, 30*time.Second)

	// The dedicated STREAM lane converges asynchronously, so the dial is retried
	// exactly like the other real-topology circuit tests.
	var stream Stream
	dialDeadline := time.Now().Add(30 * time.Second)
	for stream == nil && time.Now().Before(dialDeadline) {
		dialCtx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
		candidate, dialErr := source.DialContext(dialCtx, "tcp", targetAddr.String())
		cancelDial()
		if dialErr != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		stream = candidate
	}
	if stream == nil {
		t.Fatal("the source node never opened a STREAM circuit to the target")
	}
	defer stream.Close()

	// The dedicated STREAM hop is established by the Dial above.
	var pump *controlPump
	pumpDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(pumpDeadline) {
		source.mu.Lock()
		for _, candidate := range source.controlPumps {
			if candidate != nil && candidate.link != nil && candidate.control != nil &&
				candidate.link.Ready() && candidate.lane == uint8(path.LaneStream) {
				pump = candidate
				break
			}
		}
		source.mu.Unlock()
		if pump != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pump == nil {
		t.Fatal("the source node never established a Ready STREAM pump")
	}
	metadata := pump.link.Metadata()
	peer := pump.link.PeerNodeID()

	scope := pathScope{id: 0x51, gen: 5}
	var sid session.SessionID
	sid[0] = 0x51
	root := make([]byte, 64)
	for i := range root {
		root[i] = byte(i + 7)
	}
	protector, err := session.NewE2EProtector(session.E2EConfig{
		Root: root, Descriptor: source.networkContext.Descriptor(), WireID: source.networkContext.WireID(),
		SrcNodeID: source.streams.localID, DstNodeID: peer,
		PathID: scope.id, PathGeneration: scope.gen, SessionID: sid,
		Class: session.SessionClassStream, Direction: session.DirectionInitiatorToResponder,
	}, session.E2EPolicy{})
	if err != nil {
		t.Fatalf("build E2E protector: %v", err)
	}
	t.Cleanup(protector.Close)

	entry := &sessionEntry{
		id: sid, scope: scope, class: session.SessionClassStream, lane: session.LaneStream,
		src: source.streams.localID, dst: peer, tx: protector, ready: make(chan struct{}),
	}
	entry.signalReady()
	source.streams.registerSession(entry)
	source.streams.registerPath(&pathState{
		scope: scope, lane: path.LaneStream,
		nodes:      []topology.NodeID{topology.NodeID(peer), topology.NodeID(source.streams.localID)},
		links:      []topology.LinkRef{{ID: metadata.LinkID, Epoch: metadata.LinkEpoch, LaneID: metadata.LaneID}},
		localIndex: 1,
	})

	// Drain the finite shared control budget on this exact Link.
	for i := 0; i < 32768; i++ {
		if err := source.awaitIngressControl(source.ctx, metadata.LinkID, metadata.LinkEpoch); err != nil {
			break
		}
	}

	sub := circuit.Submission{
		Session:   circuit.SessionRef{ID: circuit.SessionID(sid), PathID: scope.id, PathGeneration: scope.gen},
		Direction: circuit.DirectionSourceToTarget,
		Kind:      circuit.KindControlRPC,
		Body:      controlRPCPayload(circuit.RPCOpen),
	}
	if err := source.streams.sendCircuitFrame(sub); !errors.Is(err, circuit.ErrResource) {
		t.Fatalf("sendCircuitFrame CONTROL_RPC over budget = %v; want circuit.ErrResource", err)
	}
}

// TestIngressControlRefusalWakesBlockedCircuitRead proves the scoped refusal
// disposition reaches an already-blocked SDK reader. A real Circuit is opened
// over a live topology; its stream is left blocked in Manager.ReadData (which
// waits on the Circuit's own wake channel, not on the Session); then a genuine
// inbound CONTROL_RPC is refused by the shared control budget. The refusal must
// abort and latch the Session AND fail its Circuits through the Manager-owned
// FailSession API, so the blocked Read exits with ErrSessionLost instead of
// hanging until its deadline. The physical Link must stay healthy.
func TestIngressControlRefusalWakesBlockedCircuitRead(t *testing.T) {
	const (
		name  = "refusal-wakes-read"
		cidr  = "10.97.0.0/24"
		token = "refusal-wakes-read-token-0123456789"
	)
	// A finite burst large enough for the real topology to converge, with a slow
	// refill so draining leaves no token for the refusal under test.
	limits := defaultRateLimits()
	limits.linkControlPerSecond = 1
	limits.linkControlBurst = 8192
	limits.networkControlPerSec = 1
	limits.networkControlBurst = 8192
	limits.controlWait = time.Millisecond
	withRateLimits(t, limits)

	targetIP := netip.MustParseAddr("10.97.0.3")
	targetAddr := netip.AddrPortFrom(targetIP, 5003)
	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, "10.97.0.1", relayCarrierURL(target))

	listener, err := target.Listen("tcp", targetAddr.String())
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			accepted, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(s Stream) {
				defer s.Close()
				buffer := make([]byte, 512)
				for {
					if _, readErr := s.Read(buffer); readErr != nil {
						return
					}
				}
			}(accepted)
		}
	}()

	waitRelayLinks(t, target, 3, 30*time.Second)
	waitRelayLinks(t, source, 3, 30*time.Second)
	waitPacketRoute(t, source, targetIP, 30*time.Second)

	var stream Stream
	dialDeadline := time.Now().Add(30 * time.Second)
	for stream == nil && time.Now().Before(dialDeadline) {
		dialCtx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
		candidate, dialErr := source.DialContext(dialCtx, "tcp", targetAddr.String())
		cancelDial()
		if dialErr != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		stream = candidate
	}
	if stream == nil {
		t.Fatal("the source node never opened a STREAM circuit")
	}
	defer stream.Close()

	// The live Circuit and the Session entry that owns it.
	var live circuit.CircuitSnapshot
	var entry *sessionEntry
	for _, candidate := range source.streams.circuits.Snapshot().Circuits {
		if owner := source.streams.sessionEntryByID(session.SessionID(candidate.Session.ID)); owner != nil {
			live, entry = candidate, owner
			break
		}
	}
	if entry == nil {
		t.Fatal("no live Circuit has an owning Session entry")
	}

	// The exact ingress pump of a real Ready STREAM hop.
	var pump *controlPump
	pumpDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(pumpDeadline) {
		source.mu.Lock()
		for _, candidate := range source.controlPumps {
			if candidate != nil && candidate.link != nil && candidate.control != nil &&
				candidate.link.Ready() && candidate.lane == uint8(path.LaneStream) {
				pump = candidate
				break
			}
		}
		source.mu.Unlock()
		if pump != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pump == nil {
		t.Fatal("the source node has no Ready STREAM pump")
	}
	metadata := pump.link.Metadata()

	// Drain the finite shared control budget on that exact Link.
	drained := false
	for i := 0; i < 32768; i++ {
		if err := source.awaitIngressControl(source.ctx, metadata.LinkID, metadata.LinkEpoch); err != nil {
			drained = true
			break
		}
	}
	if !drained {
		t.Fatal("the control budget never refused during drain")
	}

	// A genuine inbound CONTROL_RPC now hits the shared budget refusal. The
	// delivery is a handled nil (no Link failure) while the offending Session is
	// aborted, latched terminal, and its Circuits are failed.
	if err := source.streams.deliverCircuitFrame(wire.MessageTypeControlRPC,
		stagingEnvelope(source, entry.id, 10), entry, controlRPCPayload(circuit.RPCOpen), pump); err != nil {
		t.Fatalf("refused CONTROL_RPC delivery = %v; want a handled nil", err)
	}
	if !entry.isTerminated() {
		t.Fatal("the refused Session was not latched terminal")
	}

	failed, err := source.streams.circuits.Lookup(live.Key)
	if err != nil {
		t.Fatalf("Lookup after the scoped failure: %v", err)
	}
	if !failed.State().Finished() {
		t.Fatalf("Circuit state = %v after the scoped failure; want a terminal state", failed.State())
	}
	if cause := failed.Cause(); !errors.Is(cause, circuit.ErrSessionLost) {
		t.Fatalf("Circuit cause = %v; want circuit.ErrSessionLost", cause)
	}

	// The already-blocked reader must wake with the session-lost cause, not a
	// deadline (a hang would surface as ErrDeadline).
	if err := stream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, readErr := stream.Read(make([]byte, 32)); !errors.Is(readErr, ErrSessionLost) {
		t.Fatalf("blocked Read after the scoped refusal = %v; want ErrSessionLost (a hang would surface as ErrDeadline)", readErr)
	}

	// The physical Link is not collateral damage.
	if got := countReadyLinks(source); got == 0 {
		t.Fatal("the scoped refusal tore down the physical Link")
	}
}
