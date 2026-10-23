package link

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/wire"
)

// keyUpdateDriver mirrors the approved runtime shape: the reader never writes,
// it pushes actions to a queue; a separate single writer executes them in order.
// This is what lets both peers fence concurrently on the same physical stream
// without two readers blocking on each other.
// errTestKeyUpdateQueueFull is a test-harness resource failure: a bounded driver
// queue must never block a reader, because a blocked reader on a synchronous
// transport can deadlock against the peer's blocked writer.
var errTestKeyUpdateQueueFull = errors.New("test key-update driver action queue full")

// testKeyUpdateQueueCapacity is deliberately large: the bounded driver queue is a
// resource limit, not a back-pressure mechanism, so a test reader never blocks
// while the peer's writer is blocked on a synchronous transport.
const testKeyUpdateQueueCapacity = 4096

type keyUpdateDriver struct {
	io       *ProtectedControlIO
	actions  chan KeyUpdateAction
	done     chan struct{}
	quit     chan struct{}
	quitOnce sync.Once
	err      error
	mu       sync.Mutex
	seen     []ProtectedMessage
}

func newKeyUpdateDriver(io *ProtectedControlIO) *keyUpdateDriver {
	return &keyUpdateDriver{io: io, actions: make(chan KeyUpdateAction, testKeyUpdateQueueCapacity), done: make(chan struct{}), quit: make(chan struct{})}
}

func (d *keyUpdateDriver) start(t *testing.T) {
	t.Helper()
	go d.writeLoop(t)
	go d.readLoop(t)
}

func (d *keyUpdateDriver) writeLoop(t *testing.T) {
	defer close(d.done)
	for {
		var action KeyUpdateAction
		select {
		case <-d.quit:
			return
		case next, ok := <-d.actions:
			if !ok {
				return
			}
			action = next
		}
		carrier := action.Carrier
		if carrier == nil {
			carrier = d.io
		}
		applyErr := carrier.ApplyKeyUpdateAction(action)
		// Writer-completion event: the runtime reports the physical write outcome
		// so DONE is only emitted after a complete CONFIRM write.
		owner := action.Owner
		if owner == nil {
			if concrete, ok := carrier.(*ProtectedControlIO); ok {
				owner = concrete
			}
		}
		var follow []KeyUpdateAction
		var err error
		if owner != nil {
			follow, err = owner.CompleteKeyUpdateAction(action, applyErr)
		} else {
			err = applyErr
		}
		for _, next := range follow {
			if !d.enqueue(next) {
				return
			}
		}
		if errors.Is(applyErr, ErrKeyUpdateAbort) {
			// The cancel gate paused a FENCE that had not started. That is a
			// deliberate pause, not a physical write failure.
			continue
		}
		if applyErr != nil || err != nil {
			if applyErr != nil {
				d.fail(applyErr)
			} else {
				d.fail(err)
			}
			return
		}
	}
}

func (d *keyUpdateDriver) readLoop(t *testing.T) {
	for {
		select {
		case <-d.quit:
			return
		default:
		}
		message, err := d.io.ReadMessage()
		if err != nil {
			return
		}
		if message.Kind == wire.FrameKindLinkControl && len(message.Payload) > 0 && message.Payload[0] == ControlTypeKeyUpdate {
			actions, err := d.io.HandleUpdate(message)
			if err != nil {
				d.fail(err)
				return
			}
			for _, action := range actions {
				if !d.enqueue(action) {
					return
				}
			}
			continue
		}
		d.mu.Lock()
		d.seen = append(d.seen, message)
		d.mu.Unlock()
	}
}

func (d *keyUpdateDriver) fail(err error) {
	d.mu.Lock()
	if d.err == nil {
		d.err = err
	}
	d.mu.Unlock()
}

func (d *keyUpdateDriver) failure() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

func (d *keyUpdateDriver) stop() { d.quitOnce.Do(func() { close(d.quit) }) }

// enqueue hands one action to the single writer, or reports false once the
// driver is stopping, so a stop can never race a send on a closed channel.
func (d *keyUpdateDriver) enqueue(action KeyUpdateAction) bool {
	select {
	case d.actions <- action:
		return true
	case <-d.quit:
		return false
	default:
		d.fail(errTestKeyUpdateQueueFull)
		return false
	}
}

// TestKeyUpdateSelfUpdateSamePhysicalStream drives the full REQUEST/XX/READY/
// COMMIT/ARMED/FENCE/CONFIRM/DONE transaction over one real net.Pipe Link and
// proves the approved invariants: the transport is never replaced, the hop root
// and generation change, the CTRL/ROUTE counters restart in the new domain, and
// the inner E2E envelope counter is untouched.
func TestKeyUpdateSelfUpdateSamePhysicalStream(t *testing.T) {
	pair := establishedControlPair(t)
	leftStream, rightStream := pair.a.stream, pair.b.stream

	sessionID := testSessionID(0xE1)
	for _, side := range []*ProtectedControlIO{pair.a, pair.b} {
		if err := side.AdmitSession(sessionID, SessionClassStream); err != nil {
			t.Fatal(err)
		}
	}
	ciphertext := bytes.Repeat([]byte{0x9a}, 32)
	inner := len(ciphertext) - e2eTagSize

	configs := []struct {
		io       *ProtectedControlIO
		identity security.Identity
		peer     [32]byte
	}{
		{pair.a, pair.alice, pair.ar.PeerStatic},
		{pair.b, pair.bob, pair.br.PeerStatic},
	}
	for _, side := range configs {
		cfg := KeyUpdateConfig{
			Identity:                side.identity,
			PeerStatic:              side.peer,
			PSK:                     pair.psk,
			Descriptor:              pair.descriptor,
			TargetLinkID:            pair.ar.LinkID,
			TargetLinkEpoch:         pair.ar.LinkEpoch,
			LaneID:                  pair.ar.LaneID,
			PeerAdvertisedKeyUpdate: true,
		}
		if err := side.io.ConfigureKeyUpdate(cfg); err != nil {
			t.Fatalf("configure: %v", err)
		}
	}

	oldTxRootA, oldGenA := pair.a.txRoot, pair.a.txGen
	oldTxRootB, oldGenB := pair.b.txRoot, pair.b.txGen
	admissionBefore := pair.a.sessions[sessionID]

	driverA, driverB := newKeyUpdateDriver(pair.a), newKeyUpdateDriver(pair.b)
	driverA.start(t)
	driverB.start(t)
	defer driverA.stop()
	defer driverB.stop()

	actions, err := pair.a.RequestKeyUpdate()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range actions {
		driverA.actions <- action
	}

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
	if got := pair.a.KeyUpdateStatus().State; got != KuStateStable {
		t.Fatalf("A state = %s; want Stable", got)
	}
	if got := pair.b.KeyUpdateStatus().State; got != KuStateStable {
		t.Fatalf("B state = %s; want Stable", got)
	}

	// Transport and metadata identity are unchanged.
	if pair.a.stream != leftStream || pair.b.stream != rightStream {
		t.Fatal("key update replaced the physical stream")
	}
	if pair.a.linkID != pair.ar.LinkID || pair.a.linkEpoch != pair.ar.LinkEpoch ||
		pair.b.linkID != pair.br.LinkID || pair.b.linkEpoch != pair.br.LinkEpoch {
		t.Fatal("key update changed LinkID/LinkEpoch")
	}
	// Hop roots and generations advanced on both ends, and both ends agree.
	if pair.a.txRoot == oldTxRootA || pair.b.txRoot == oldTxRootB {
		t.Fatal("TX root did not change")
	}
	if pair.a.txGen == oldGenA || pair.b.txGen == oldGenB || pair.a.txGen != pair.b.rxGen || pair.b.txGen != pair.a.rxGen {
		t.Fatalf("generation mismatch: a tx/rx %d/%d, b tx/rx %d/%d", pair.a.txGen, pair.a.rxGen, pair.b.txGen, pair.b.rxGen)
	}
	if pair.a.txGen != pair.a.KeyUpdateStatus().NewGeneration {
		t.Fatal("installed generation differs from the committed one")
	}
	// CTRL/ROUTE counters restarted in the new domain: CONFIRM is the control
	// frame at counter 0 and DONE at counter 1, so txNext is exactly 2 (never
	// more: DONE is emitted once), while the ROUTE_CTRL domain restarts
	// independently at 0.
	if pair.a.txNext != 2 || pair.b.txNext != 2 || pair.a.routeNext != 0 || pair.b.routeNext != 0 {
		t.Fatalf("counters not re-initialized: a txNext=%d routeNext=%d, b txNext=%d routeNext=%d",
			pair.a.txNext, pair.a.routeNext, pair.b.txNext, pair.b.routeNext)
	}
	// The E2E admission and its inner counter are untouched by the Link rekey.
	if pair.a.sessions[sessionID] != admissionBefore || len(pair.a.sessions) != 1 {
		t.Fatal("Link key update replaced the Session admission")
	}
	// The driver remains the sole reader of the stream, so the post-rekey
	// business frame is observed through it rather than by a second reader.
	envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 9, 4, 2, inner)
	written := make(chan error, 1)
	go func() { written <- pair.a.WriteEndToEnd(envelope, ciphertext, testHop) }()
	var delivered ProtectedMessage
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && delivered.Kind == 0 {
		driverB.mu.Lock()
		if len(driverB.seen) > 0 {
			delivered = driverB.seen[0]
			driverB.seen = driverB.seen[1:]
		}
		driverB.mu.Unlock()
		if delivered.Kind == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	if err := <-written; err != nil {
		t.Fatalf("E2E write after rekey: %v", err)
	}
	if err := driverB.failure(); err != nil {
		t.Fatalf("driver B after rekey: %v", err)
	}
	if delivered.Kind != wire.FrameKindEndToEnd || len(delivered.Payload) != len(ciphertext) {
		t.Fatalf("E2E frame after rekey: kind 0x%02x payload %d; want kind 0x%02x payload %d",
			uint8(delivered.Kind), len(delivered.Payload), uint8(wire.FrameKindEndToEnd), len(ciphertext))
	}
	if got := pair.a.sessions[sessionID].txCounter; got != 9 {
		t.Fatalf("E2E MessageNumber = %d; want 9 (unchanged domain)", got)
	}
}

// deliverKeyUpdate feeds one already-encoded update body to peer.HandleUpdate
// without touching the physical stream, so a test controls the exact transcript
// order. The real AEAD/carrier path is exercised by the same-stream test above.
func deliverKeyUpdate(t *testing.T, peer *ProtectedControlIO, action KeyUpdateAction) []KeyUpdateAction {
	t.Helper()
	body := append([]byte{ControlTypeKeyUpdate}, action.Payload...)
	follow, err := peer.HandleUpdate(ProtectedMessage{Kind: wire.FrameKindLinkControl, Payload: body})
	if err != nil {
		t.Fatalf("deliver phase %s: %v", action.Phase, err)
	}
	return follow
}

// completeKeyUpdate reports the writer's completion event for an action whose
// physical write succeeded, exactly like the runtime's single writer.
func completeKeyUpdate(t *testing.T, action KeyUpdateAction) []KeyUpdateAction {
	t.Helper()
	if action.Owner == nil {
		t.Fatal("action has no owner")
	}
	follow, err := action.Owner.CompleteKeyUpdateAction(action, nil)
	if err != nil {
		t.Fatalf("complete phase %s: %v", action.Phase, err)
	}
	return follow
}

// confirmFromFence rebuilds the CONFIRM control message a FENCE action emits as
// its first new-key frame, from the slot the action carries.
func confirmFromFence(t *testing.T, fence KeyUpdateAction) KeyUpdateAction {
	t.Helper()
	if fence.Slot == nil {
		t.Fatal("fence action without slot")
	}
	slot := fence.Slot
	body, err := EncodeKeyUpdate(KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateConfirm, Lane: slot.Lane,
		TargetLinkID: slot.TargetLinkID, TargetLinkEpoch: slot.TargetLinkEpoch,
		UpdateSeq: slot.Seq, OldGeneration: slot.OldGeneration, NewGeneration: slot.NewGeneration,
		NewRevision: fence.NewRevision, Proof: fence.Proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	return KeyUpdateAction{Phase: KeyUpdateConfirm, Payload: body}
}

// TestKeyUpdatePeerDoneBeforeLocalConfirmComplete pins the exact event order that
// used to strand the transaction: side A receives B's DONE before A's own
// FENCE/CONFIRM write completion event. The DONE must be persisted and a later
// completion must still reach Stable, with DONE emitted exactly once per side.
func TestKeyUpdatePeerDoneBeforeLocalConfirmComplete(t *testing.T) {
	pair := establishedControlPair(t)
	configure := func(io *ProtectedControlIO, identity security.Identity, peer [32]byte) {
		t.Helper()
		if err := io.ConfigureKeyUpdate(KeyUpdateConfig{
			Identity: identity, PeerStatic: peer, PSK: pair.psk, Descriptor: pair.descriptor,
			TargetLinkID: pair.ar.LinkID, TargetLinkEpoch: pair.ar.LinkEpoch, LaneID: pair.ar.LaneID,
			PeerAdvertisedKeyUpdate: true,
		}); err != nil {
			t.Fatalf("configure: %v", err)
		}
	}
	configure(pair.a, pair.alice, pair.ar.PeerStatic)
	configure(pair.b, pair.bob, pair.br.PeerStatic)

	// Full negotiation transcript up to both fences, delivered synchronously so
	// the reorder below is deterministic rather than scheduling-dependent.
	xx1, err := pair.a.RequestKeyUpdate()
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if len(xx1) != 1 {
		t.Fatalf("REQUEST produced %d actions", len(xx1))
	}
	xx2 := deliverKeyUpdate(t, pair.b, xx1[0])
	xx3 := deliverKeyUpdate(t, pair.a, xx2[0])
	ready := deliverKeyUpdate(t, pair.b, xx3[0])
	commit := deliverKeyUpdate(t, pair.a, ready[0])
	bActions := deliverKeyUpdate(t, pair.b, commit[0])
	if len(bActions) != 3 || bActions[0].Phase != KeyUpdateArmed {
		t.Fatalf("COMMIT produced %d actions (first %s)", len(bActions), bActions[0].Phase)
	}
	var bFence KeyUpdateAction
	for _, action := range bActions {
		if action.Kind == ActionFenceTarget {
			bFence = action
			continue
		}
		completeKeyUpdate(t, action)
	}
	if bFence.Kind != ActionFenceTarget {
		t.Fatal("COMMIT did not queue a fence")
	}
	// B's fence write completed: its CONFIRM is on the wire.
	if follow := completeKeyUpdate(t, bFence); len(follow) != 0 {
		t.Fatalf("B queued %d actions before seeing A's CONFIRM", len(follow))
	}
	if status := pair.b.KeyUpdateStatus(); !status.LocalConfirmSent || status.PeerConfirmSeen {
		t.Fatalf("B pre-state: localConfirm=%v peerConfirm=%v", status.LocalConfirmSent, status.PeerConfirmSeen)
	}

	aActions := deliverKeyUpdate(t, pair.a, bActions[0])
	if len(aActions) != 2 || aActions[1].Kind != ActionFenceTarget {
		t.Fatalf("ARMED produced %d actions", len(aActions))
	}
	aFence := aActions[1]
	completeKeyUpdate(t, aActions[0])
	// Crux: A's FENCE/CONFIRM physical write is not yet complete.
	if status := pair.a.KeyUpdateStatus(); status.LocalConfirmSent {
		t.Fatal("reorder precondition failed: A already completed its CONFIRM")
	}

	// B sees A's CONFIRM and emits its single DONE.
	bDone := deliverKeyUpdate(t, pair.b, confirmFromFence(t, aFence))
	if len(bDone) != 1 || bDone[0].Phase != KeyUpdateDone {
		t.Fatalf("A's CONFIRM produced %d B actions (want one DONE)", len(bDone))
	}
	if follow := completeKeyUpdate(t, bDone[0]); len(follow) != 0 {
		t.Fatalf("B queued %d actions after writing DONE", len(follow))
	}
	if status := pair.b.KeyUpdateStatus(); status.State == KuStateStable {
		t.Fatal("B became Stable before observing A's DONE")
	}

	// A sees B's CONFIRM, then B's DONE, all before A's own write completion.
	if follow := deliverKeyUpdate(t, pair.a, confirmFromFence(t, bFence)); len(follow) != 0 {
		t.Fatalf("A queued DONE before its own CONFIRM completed: %d actions", len(follow))
	}
	if follow := deliverKeyUpdate(t, pair.a, bDone[0]); len(follow) != 0 {
		t.Fatalf("A reacted to B's DONE before its own CONFIRM completed: %d actions", len(follow))
	}
	if status := pair.a.KeyUpdateStatus(); status.LocalConfirmSent {
		t.Fatal("A completed its CONFIRM too early")
	}

	// A's writer now reports the completed FENCE/CONFIRM write: the persisted
	// peer DONE must still drive A to Stable, with DONE written exactly once.
	aFollow := completeKeyUpdate(t, aFence)
	if len(aFollow) != 1 || aFollow[0].Phase != KeyUpdateDone {
		t.Fatalf("fence completion queued %d actions (want one DONE)", len(aFollow))
	}
	if follow := completeKeyUpdate(t, aFollow[0]); len(follow) != 0 {
		t.Fatalf("A queued %d actions after writing DONE", len(follow))
	}
	if got := pair.a.KeyUpdateStatus().State; got != KuStateStable {
		t.Fatalf("A state = %s; want Stable (peer DONE was dropped)", got)
	}
	// No repeat DONE: replaying the same event must stay idempotent.
	if follow := completeKeyUpdate(t, aFence); len(follow) != 0 {
		t.Fatalf("A re-emitted %d actions on a repeated completion", len(follow))
	}

	// B consumes A's DONE and becomes Stable.
	if follow := deliverKeyUpdate(t, pair.b, aFollow[0]); len(follow) != 0 {
		t.Fatalf("B queued %d actions after A's DONE", len(follow))
	}
	if got := pair.b.KeyUpdateStatus().State; got != KuStateStable {
		t.Fatalf("B state = %s; want Stable", got)
	}
	if status := pair.b.KeyUpdateStatus(); status.State != KuStateStable {
		t.Fatalf("B state = %s after replay", status.State)
	}
}

// configureKeyUpdatePair installs the approved update configuration on both
// sides of an established Link with a real Noise handshake.
func configureKeyUpdatePair(t *testing.T, pair controlPair) {
	t.Helper()
	if err := pair.a.ConfigureKeyUpdate(KeyUpdateConfig{
		Identity: pair.alice, PeerStatic: pair.ar.PeerStatic, PSK: pair.psk, Descriptor: pair.descriptor,
		TargetLinkID: pair.ar.LinkID, TargetLinkEpoch: pair.ar.LinkEpoch, LaneID: pair.ar.LaneID,
		PeerAdvertisedKeyUpdate: true,
	}); err != nil {
		t.Fatalf("configure A: %v", err)
	}
	if err := pair.b.ConfigureKeyUpdate(KeyUpdateConfig{
		Identity: pair.bob, PeerStatic: pair.br.PeerStatic, PSK: pair.psk, Descriptor: pair.descriptor,
		TargetLinkID: pair.ar.LinkID, TargetLinkEpoch: pair.ar.LinkEpoch, LaneID: pair.ar.LaneID,
		PeerAdvertisedKeyUpdate: true,
	}); err != nil {
		t.Fatalf("configure B: %v", err)
	}
}

// negotiateKeyUpdateToPending drives REQUEST/XX/READY/COMMIT synchronously until
// both sides published their trusted pending slot. Physical writes are accounted
// through the writer-completion event; the frames themselves are delivered
// in-process so the gate tests can control the exact next frame.
func negotiateKeyUpdateToPending(t *testing.T, pair controlPair) {
	t.Helper()
	configureKeyUpdatePair(t, pair)
	xx1, err := pair.a.RequestKeyUpdate()
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	xx2 := deliverKeyUpdate(t, pair.b, xx1[0])
	xx3 := deliverKeyUpdate(t, pair.a, xx2[0])
	ready := deliverKeyUpdate(t, pair.b, xx3[0])
	commit := deliverKeyUpdate(t, pair.a, ready[0])
	for _, action := range deliverKeyUpdate(t, pair.b, commit[0]) {
		completeKeyUpdate(t, action)
	}
	if pair.a.pendingSlot == nil || pair.b.pendingSlot == nil {
		t.Fatal("negotiation did not publish both trusted pending slots")
	}
}

// peerConfirmMaterial returns the CONFIRM message the coordinator would emit and
// the new-domain TX protector that would seal it, derived from A's completed
// Noise split. It lets a test act as the fenced peer over the real transport.
func peerConfirmMaterial(t *testing.T, pair controlPair) (KeyUpdateMessage, *FrameProtector) {
	t.Helper()
	slot := pair.a.pendingSlot
	peerTx, err := NewFrameProtector(slot.TxRoot, pair.a.descriptor, pair.a.linkID, [16]byte{}, SessionClassStream, slot.TxDirection)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pair.a.keyUpdateEngine()
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	proof, err := engine.proof(KeyUpdateConfirm, engine.newRevision)
	if err != nil {
		t.Fatal(err)
	}
	return KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateConfirm, Lane: engine.cfg.LaneID,
		TargetLinkID: slot.TargetLinkID, TargetLinkEpoch: slot.TargetLinkEpoch,
		UpdateSeq: slot.Seq, OldGeneration: slot.OldGeneration, NewGeneration: slot.NewGeneration,
		NewRevision: engine.newRevision, Proof: toArray32(proof),
	}, peerTx
}

// sendRawFrame writes one frame on conn from a goroutine so the caller can read
// the synchronous net.Pipe at the same time.
func sendRawFrame(conn net.Conn, frame wire.Frame) <-chan error {
	written := make(chan error, 1)
	go func() { written <- wire.WriteFrame(conn, frame) }()
	return written
}

func sealControl(t *testing.T, protector *FrameProtector, controlType uint8, payload []byte, generation uint32, counter uint64) wire.Frame {
	t.Helper()
	plaintext := append([]byte{controlType}, payload...)
	frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, plaintext, generation, counter)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

// TestKeyUpdateConfirmFirstAcceptsValidConfirm proves the armed post-FENCE
// obligation accepts exactly the transaction's CONFIRM: new generation, control
// counter 0 and a MAC verified under the actual new AEAD.
func TestKeyUpdateConfirmFirstAcceptsValidConfirm(t *testing.T) {
	pair := establishedControlPair(t)
	negotiateKeyUpdateToPending(t, pair)
	if err := pair.b.switchRX(pair.b.pendingSlot); err != nil {
		t.Fatalf("switch RX: %v", err)
	}
	if pair.b.rxExpect == nil {
		t.Fatal("RX switch did not arm the CONFIRM-first obligation")
	}
	message, peerTx := peerConfirmMaterial(t, pair)
	body, err := EncodeKeyUpdate(message)
	if err != nil {
		t.Fatal(err)
	}
	frame := sealControl(t, peerTx, ControlTypeKeyUpdate, body, message.NewGeneration, 0)
	written := sendRawFrame(pair.left, frame)
	received, err := pair.b.ReadMessage()
	if err != nil {
		t.Fatalf("valid CONFIRM rejected: %v", err)
	}
	if werr := <-written; werr != nil {
		t.Fatal(werr)
	}
	if pair.b.terminal.Load() {
		t.Fatal("accepting the CONFIRM ended the object")
	}
	if pair.b.rxExpect != nil {
		t.Fatal("CONFIRM-first obligation not consumed")
	}
	decoded, err := DecodeKeyUpdate(received.Payload[1:])
	if err != nil || decoded.Phase != KeyUpdateConfirm {
		t.Fatalf("delivered frame is not the CONFIRM: phase %s err %v", decoded.Phase, err)
	}
}

// TestKeyUpdateConfirmFirstFailsClosed proves that any other first frame after
// the old-root FENCE is refused terminally instead of being deferred to a later
// CONFIRM: a ROUTE frame, an E2E frame and a LINK_CTRL PING sealed under the new
// AEAD at counter 0.
func TestKeyUpdateConfirmFirstFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, pair controlPair, peerTx *FrameProtector) wire.Frame
	}{
		{"route", func(t *testing.T, pair controlPair, peerTx *FrameProtector) wire.Frame {
			payload := bytes.Repeat([]byte{0x01}, 32)
			return wire.Frame{
				Kind:     wire.FrameKindRouteControl,
				Envelope: routeEnvelope(wire.MessageTypeSessionCtrl, testSessionID(0x77), 7, 3, len(payload)),
				Body:     payload,
			}
		}},
		{"end-to-end", func(t *testing.T, pair controlPair, peerTx *FrameProtector) wire.Frame {
			ciphertext := bytes.Repeat([]byte{0x5a}, 32)
			return wire.Frame{
				Kind:     wire.FrameKindEndToEnd,
				Envelope: newEndToEndEnvelope(testSessionID(0x78), wire.MessageTypeStreamData, 1, 1, 7, 3, len(ciphertext)-e2eTagSize),
				Body:     ciphertext,
			}
		}},
		{"link-control-ping", func(t *testing.T, pair controlPair, peerTx *FrameProtector) wire.Frame {
			return sealControl(t, peerTx, 1, make([]byte, 16), pair.b.pendingSlot.NewGeneration, 0)
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			pair := establishedControlPair(t)
			negotiateKeyUpdateToPending(t, pair)
			if err := pair.b.switchRX(pair.b.pendingSlot); err != nil {
				t.Fatalf("switch RX: %v", err)
			}
			_, peerTx := peerConfirmMaterial(t, pair)
			written := sendRawFrame(pair.left, testCase.build(t, pair, peerTx))
			_, err := pair.b.ReadMessage()
			if werr := <-written; werr != nil {
				t.Fatal(werr)
			}
			if !errors.Is(err, ErrKeyUpdateMessage) {
				t.Fatalf("first %s frame error = %v; want ErrKeyUpdateMessage", testCase.name, err)
			}
			if !pair.b.terminal.Load() {
				t.Fatalf("first %s frame did not fail closed", testCase.name)
			}
			if pair.b.rxExpect == nil {
				t.Fatal("obligation was consumed by a bad first frame")
			}
		})
	}
}

// TestKeyUpdateConfirmFirstRejectsBadMAC proves the new-key CONFIRM is bound to
// the installed trusted slot: a frame sealed under the actual new AEAD with a
// wrong directional MAC is rejected before delivery.
func TestKeyUpdateConfirmFirstRejectsBadMAC(t *testing.T) {
	pair := establishedControlPair(t)
	negotiateKeyUpdateToPending(t, pair)
	if err := pair.b.switchRX(pair.b.pendingSlot); err != nil {
		t.Fatalf("switch RX: %v", err)
	}
	message, peerTx := peerConfirmMaterial(t, pair)
	message.Proof[0] ^= 0xff
	body, err := EncodeKeyUpdate(message)
	if err != nil {
		t.Fatal(err)
	}
	frame := sealControl(t, peerTx, ControlTypeKeyUpdate, body, message.NewGeneration, 0)
	written := sendRawFrame(pair.left, frame)
	_, err = pair.b.ReadMessage()
	if werr := <-written; werr != nil {
		t.Fatal(werr)
	}
	if !errors.Is(err, ErrKeyUpdateProof) {
		t.Fatalf("bad-MAC CONFIRM error = %v; want ErrKeyUpdateProof", err)
	}
	if !pair.b.terminal.Load() {
		t.Fatal("bad-MAC CONFIRM did not fail closed")
	}
}

// TestKeyUpdateInstalledSlotVerifiesConfirmMAC proves a carrier that only holds
// an installed trusted slot (no negotiation engine) verifies the peer CONFIRM's
// directional MAC rather than comparing seq/revision only.
func TestKeyUpdateInstalledSlotVerifiesConfirmMAC(t *testing.T) {
	pair := establishedControlPair(t)
	negotiateKeyUpdateToPending(t, pair)
	// Simulate the DATA target carrier: installed slot, no negotiation engine.
	pair.b.ku = nil
	message, _ := peerConfirmMaterial(t, pair)
	good, err := EncodeKeyUpdate(message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pair.b.HandleUpdate(ProtectedMessage{Kind: wire.FrameKindLinkControl, Payload: append([]byte{ControlTypeKeyUpdate}, good...)}); err != nil {
		t.Fatalf("installed carrier rejected a valid CONFIRM MAC: %v", err)
	}
	message.Proof[31] ^= 0x01
	bad, err := EncodeKeyUpdate(message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pair.b.HandleUpdate(ProtectedMessage{Kind: wire.FrameKindLinkControl, Payload: append([]byte{ControlTypeKeyUpdate}, bad...)}); !errors.Is(err, ErrKeyUpdateProof) {
		t.Fatalf("installed carrier accepted a bad CONFIRM MAC: %v", err)
	}
}

// runSelfKeyUpdate drives a complete self key update with the approved
// single-reader/single-writer split and returns both drivers once Stable.
func runSelfKeyUpdate(t *testing.T, pair controlPair) (*keyUpdateDriver, *keyUpdateDriver) {
	t.Helper()
	configureKeyUpdatePair(t, pair)
	driverA, driverB := newKeyUpdateDriver(pair.a), newKeyUpdateDriver(pair.b)
	driverA.start(t)
	driverB.start(t)
	actions, err := pair.a.RequestKeyUpdate()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range actions {
		driverA.actions <- action
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if pair.a.KeyUpdateStatus().State == KuStateStable && pair.b.KeyUpdateStatus().State == KuStateStable {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if err := driverA.failure(); err != nil {
		t.Fatal(err)
	}
	if err := driverB.failure(); err != nil {
		t.Fatal(err)
	}
	if pair.a.KeyUpdateStatus().State != KuStateStable || pair.b.KeyUpdateStatus().State != KuStateStable {
		t.Fatal("self key update did not stabilize")
	}
	return driverA, driverB
}

func awaitDriverFrame(t *testing.T, driver *keyUpdateDriver, timeout time.Duration) ProtectedMessage {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		driver.mu.Lock()
		if len(driver.seen) > 0 {
			message := driver.seen[0]
			driver.seen = driver.seen[1:]
			driver.mu.Unlock()
			return message
		}
		driver.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("business frame was not delivered")
	return ProtectedMessage{}
}

// TestAdmitSessionDoesNotWaitOnDirectionalLocks pins the admission contract: a
// reader may hold rxMu across a blocking network read and a writer may hold
// txMu, and a new admission must still complete without waiting on either.
func TestAdmitSessionDoesNotWaitOnDirectionalLocks(t *testing.T) {
	pair := establishedControlPair(t)
	pair.a.rxMu.Lock()
	pair.a.txMu.Lock()
	admitted := make(chan error, 1)
	go func() { admitted <- pair.a.AdmitSession(testSessionID(0x91), SessionClassStream) }()
	select {
	case err := <-admitted:
		if err != nil {
			pair.a.rxMu.Unlock()
			pair.a.txMu.Unlock()
			t.Fatalf("admission failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		pair.a.rxMu.Unlock()
		pair.a.txMu.Unlock()
		t.Fatal("AdmitSession waited on a directional lock held by a reader/writer")
	}
	pair.a.rxMu.Unlock()
	pair.a.txMu.Unlock()
}

// TestAdmitSessionAfterRekeyUsesCurrentDirectionalRoots proves a session admitted
// after a completed rekey derives both directions from the new roots: business
// frames cross in both directions with no further key update.
func TestAdmitSessionAfterRekeyUsesCurrentDirectionalRoots(t *testing.T) {
	pair := establishedControlPair(t)
	oldTxA, oldRxA := pair.a.txRoot, pair.a.rxRoot
	driverA, driverB := runSelfKeyUpdate(t, pair)
	defer driverA.stop()
	defer driverB.stop()

	sessionID := testSessionID(0xA2)
	for _, side := range []*ProtectedControlIO{pair.a, pair.b} {
		if err := side.AdmitSession(sessionID, SessionClassStream); err != nil {
			t.Fatalf("admit after rekey: %v", err)
		}
	}
	if pair.a.txRoot == oldTxA || pair.a.rxRoot == oldRxA {
		t.Fatal("rekey did not advance the roots")
	}
	ciphertext := bytes.Repeat([]byte{0x3c}, 32)
	inner := len(ciphertext) - e2eTagSize
	envelopeA := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 4, 2, inner)
	envelopeB := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 5, 3, inner)
	writtenA := make(chan error, 1)
	go func() { writtenA <- pair.a.WriteEndToEnd(envelopeA, ciphertext, testHop) }()
	if got := awaitDriverFrame(t, driverB, 3*time.Second); got.Kind != wire.FrameKindEndToEnd {
		t.Fatalf("A->B frame after rekey: kind 0x%02x", uint8(got.Kind))
	}
	if err := <-writtenA; err != nil {
		t.Fatalf("A->B write: %v", err)
	}
	writtenB := make(chan error, 1)
	go func() { writtenB <- pair.b.WriteEndToEnd(envelopeB, ciphertext, testHop) }()
	if got := awaitDriverFrame(t, driverA, 3*time.Second); got.Kind != wire.FrameKindEndToEnd {
		t.Fatalf("B->A frame after rekey: kind 0x%02x", uint8(got.Kind))
	}
	if err := <-writtenB; err != nil {
		t.Fatalf("B->A write: %v", err)
	}
	if err := driverA.failure(); err != nil {
		t.Fatal(err)
	}
	if err := driverB.failure(); err != nil {
		t.Fatal(err)
	}
}

// TestKeyUpdateActionTargetBinding pins the exact-binding rule: an action
// resolved for one carrier instance is refused by another instance before any
// mutation, and a same-seq re-install with different trusted material is a
// conflict rather than a silent overwrite or a false idempotent success.
func TestKeyUpdateActionTargetBinding(t *testing.T) {
	pair := establishedControlPair(t)
	negotiateKeyUpdateToPending(t, pair)
	engine, err := pair.a.keyUpdateEngine()
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	actions, err := engine.installAndFenceLocked()
	engine.mu.Unlock()
	if err != nil || len(actions) != 2 {
		t.Fatalf("installAndFence: %d actions, err %v", len(actions), err)
	}
	if actions[0].Target.Instance != pair.a || actions[1].Target.Instance != pair.a {
		t.Fatal("actions were not bound to the resolving carrier instance")
	}
	if actions[0].Target.LinkID != pair.a.linkID || actions[0].Target.Lane != pair.a.linkLane {
		t.Fatal("actions were not bound to the resolving carrier tuple")
	}
	fenceStarted := pair.b.fenceStartedFlag
	pending := pair.b.pendingSlot
	if err := pair.b.ApplyKeyUpdateAction(actions[1]); !errors.Is(err, ErrKeyUpdateTarget) {
		t.Fatalf("foreign fence action error = %v; want ErrKeyUpdateTarget", err)
	}
	if pair.b.fenceStartedFlag != fenceStarted || pair.b.pendingSlot != pending {
		t.Fatal("a foreign action mutated the carrier")
	}
	if err := pair.b.ApplyKeyUpdateAction(actions[0]); !errors.Is(err, ErrKeyUpdateTarget) {
		t.Fatalf("foreign install action error = %v; want ErrKeyUpdateTarget", err)
	}
	if pair.b.pendingSlot != pending {
		t.Fatal("a foreign install action replaced the pending slot")
	}

	// The exact same trusted slot is idempotent; any differing material is a
	// conflict and leaves the installed slot untouched.
	original := *pair.b.pendingSlot
	if err := pair.b.InstallPendingKeyUpdate(original); err != nil {
		t.Fatalf("exact re-install: %v", err)
	}
	altered := original
	altered.TxRoot[0] ^= 0x01
	if err := pair.b.InstallPendingKeyUpdate(altered); !errors.Is(err, ErrKeyUpdateConflict) {
		t.Fatalf("altered re-install error = %v; want ErrKeyUpdateConflict", err)
	}
	if pair.b.pendingSlot.TxRoot != original.TxRoot {
		t.Fatal("altered re-install overwrote the trusted slot")
	}
	// At most one pending transaction: a different seq may not overwrite.
	third := original
	third.Seq++
	if err := pair.b.InstallPendingKeyUpdate(third); !errors.Is(err, ErrKeyUpdateConflict) {
		t.Fatalf("second pending seq error = %v; want ErrKeyUpdateConflict", err)
	}
	if pair.b.pendingSlot.Seq != original.Seq {
		t.Fatal("a second pending slot replaced the installed one")
	}
}

// driveKeyUpdateToFencePending delivers the transcript through ARMED and returns
// the coordinator's queued actions with the follower's own fence already
// completed, so the coordinator holds an install(completed)+fence(pending) pair.
func driveKeyUpdateToFencePending(t *testing.T, pair controlPair) []KeyUpdateAction {
	t.Helper()
	configureKeyUpdatePair(t, pair)
	xx1, err := pair.a.RequestKeyUpdate()
	if err != nil {
		t.Fatal(err)
	}
	xx2 := deliverKeyUpdate(t, pair.b, xx1[0])
	xx3 := deliverKeyUpdate(t, pair.a, xx2[0])
	ready := deliverKeyUpdate(t, pair.b, xx3[0])
	commit := deliverKeyUpdate(t, pair.a, ready[0])
	bActions := deliverKeyUpdate(t, pair.b, commit[0])
	if len(bActions) != 3 || bActions[0].Phase != KeyUpdateArmed {
		t.Fatalf("COMMIT produced %d follower actions", len(bActions))
	}
	for _, action := range bActions[1:] {
		completeKeyUpdate(t, action)
	}
	aActions := deliverKeyUpdate(t, pair.a, bActions[0])
	if len(aActions) != 2 || aActions[1].Kind != ActionFenceTarget {
		t.Fatalf("ARMED produced %d coordinator actions", len(aActions))
	}
	completeKeyUpdate(t, aActions[0])
	return aActions
}

// TestKeyUpdateCancelPausesQueuedFence proves the shared cancel gate stops a
// FENCE action that has not started (no nonce, no generation switch), and that
// the peer's ABORT_ACK is an irreversible no-future-FENCE promise.
func TestKeyUpdateCancelPausesQueuedFence(t *testing.T) {
	pair := establishedControlPair(t)
	// Stop before the follower fences so it can acknowledge the abort.
	configureKeyUpdatePair(t, pair)
	xx1, err := pair.a.RequestKeyUpdate()
	if err != nil {
		t.Fatal(err)
	}
	xx2 := deliverKeyUpdate(t, pair.b, xx1[0])
	xx3 := deliverKeyUpdate(t, pair.a, xx2[0])
	ready := deliverKeyUpdate(t, pair.b, xx3[0])
	deliverKeyUpdate(t, pair.a, ready[0])
	engine, err := pair.a.keyUpdateEngine()
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	queued, err := engine.installAndFenceLocked()
	engine.mu.Unlock()
	if err != nil || len(queued) != 2 {
		t.Fatalf("queued actions: %d, err %v", len(queued), err)
	}
	fence := queued[1]
	beforeGen := pair.a.txGen

	if actions, err := pair.a.CancelKeyUpdate(); err != nil || len(actions) != 0 {
		t.Fatalf("CancelKeyUpdate: %d actions, err %v", len(actions), err)
	}
	if err := pair.a.ApplyKeyUpdateAction(fence); !errors.Is(err, ErrKeyUpdateAbort) {
		t.Fatalf("paused FENCE error = %v; want ErrKeyUpdateAbort", err)
	}
	if pair.a.fenceStartedFlag || pair.a.txGen != beforeGen {
		t.Fatal("a paused FENCE mutated the carrier")
	}
	if follow, err := pair.a.CompleteKeyUpdateAction(fence, ErrKeyUpdateAbort); err != nil || len(follow) != 0 {
		t.Fatalf("paused completion: %d actions, err %v", len(follow), err)
	}
	if status := pair.a.KeyUpdateStatus(); status.LocalFenceSent || status.Aborted {
		t.Fatalf("paused FENCE claimed progress: %+v", status)
	}

	abortActions, err := pair.a.RequestAbort()
	if err != nil || len(abortActions) != 1 || abortActions[0].Phase != KeyUpdateAbort {
		t.Fatalf("RequestAbort: %d actions, err %v", len(abortActions), err)
	}
	ack := deliverKeyUpdate(t, pair.b, abortActions[0])
	if len(ack) != 1 || ack[0].Phase != KeyUpdateAbortAck {
		t.Fatalf("follower did not acknowledge the abort: %v", ack)
	}
	deliverKeyUpdate(t, pair.a, ack[0])
	if got := pair.a.KeyUpdateStatus().State; got != KuStateAborted {
		t.Fatalf("A state = %s; want Aborted", got)
	}
	if got := pair.b.KeyUpdateStatus().State; got != KuStateAborted {
		t.Fatalf("B state = %s; want Aborted", got)
	}
	// No FENCE may ever follow the ACK.
	if err := pair.a.ApplyKeyUpdateAction(fence); !errors.Is(err, ErrKeyUpdateAbort) {
		t.Fatalf("post-ACK FENCE error = %v; want ErrKeyUpdateAbort", err)
	}
	if pair.a.fenceStartedFlag {
		t.Fatal("a FENCE followed ABORT_ACK")
	}
}

// TestKeyUpdateAbortRejectContinuesForward proves an abort rejected by an
// already-fenced peer releases the gate and re-queues the FENCE with no rollback.
func TestKeyUpdateAbortRejectContinuesForward(t *testing.T) {
	pair := establishedControlPair(t)
	driveKeyUpdateToFencePending(t, pair)
	abortActions, err := pair.a.RequestAbort()
	if err != nil || len(abortActions) != 1 {
		t.Fatalf("RequestAbort: %d actions, err %v", len(abortActions), err)
	}
	reject := deliverKeyUpdate(t, pair.b, abortActions[0])
	if len(reject) != 1 || reject[0].Phase != KeyUpdateAbortReject {
		t.Fatalf("already-fenced follower did not reject: %v", reject)
	}
	follow := deliverKeyUpdate(t, pair.a, reject[0])
	if len(follow) != 2 || follow[1].Kind != ActionFenceTarget {
		t.Fatalf("reject did not re-queue install+fence: %v", follow)
	}
	if pair.a.cancelPendingFlag {
		t.Fatal("reject left the cancel gate armed")
	}
	// The re-queued FENCE is the same transaction and proceeds forward.
	if _, err := pair.a.CompleteKeyUpdateAction(follow[1], nil); err != nil {
		t.Fatalf("forward fence completion: %v", err)
	}
	status := pair.a.KeyUpdateStatus()
	if status.Aborted || !status.LocalConfirmSent || status.LocalFenceSent != true {
		t.Fatalf("forward progress not recorded: %+v", status)
	}
}

// TestPendingPublicationDoesNotWaitOnRX proves the pre-ARMED publication of the
// trusted slot takes only the short state lock: a reader holding rxMu across a
// blocking network read must not stall it before ARMED.
func TestPendingPublicationDoesNotWaitOnRX(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePair(t, pair)
	pair.b.rxMu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		xx1, err := pair.a.RequestKeyUpdate()
		if err != nil {
			return
		}
		xx2 := deliverKeyUpdate(t, pair.b, xx1[0])
		xx3 := deliverKeyUpdate(t, pair.a, xx2[0])
		ready := deliverKeyUpdate(t, pair.b, xx3[0])
		commit := deliverKeyUpdate(t, pair.a, ready[0])
		for _, action := range deliverKeyUpdate(t, pair.b, commit[0]) {
			completeKeyUpdate(t, action)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		pair.b.rxMu.Unlock()
		t.Fatal("pending publication waited on rxMu held by a blocked reader")
	}
	pair.b.rxMu.Unlock()
	if pair.a.pendingSlot == nil || pair.b.pendingSlot == nil {
		t.Fatal("the trusted pending slot was not published")
	}
}

func sessionPresent(io *ProtectedControlIO, sessionID [16]byte) bool {
	io.sessionMu.RLock()
	defer io.sessionMu.RUnlock()
	_, ok := io.sessions[sessionID]
	return ok
}

// TestRetiredSessionTombstonesReclaimAfterMutualDone pins the conservative
// reclaim rule: a retired tombstone survives until a mutual-DONE update advanced
// BOTH directions past its recorded per-direction generations, is never removed
// wholesale, and only then may the SessionID be admitted again under the new
// hop key.
func TestRetiredSessionTombstonesReclaimAfterMutualDone(t *testing.T) {
	pair := establishedControlPair(t)
	retired := testSessionID(0xD1)
	live := testSessionID(0xD2)
	if err := pair.a.AdmitSession(retired, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	if err := pair.a.RetireSession(retired); err != nil {
		t.Fatal(err)
	}
	if err := pair.a.AdmitSession(live, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	if n := pair.a.ReclaimRetiredSessions(); n != 0 {
		t.Fatalf("reclaimed %d tombstones before any mutual DONE", n)
	}
	if !sessionPresent(pair.a, retired) {
		t.Fatal("tombstone disappeared before a root change")
	}
	if err := pair.a.AdmitSession(retired, SessionClassStream); !errors.Is(err, ErrSessionRetired) {
		t.Fatalf("retired SessionID re-admitted early: %v", err)
	}
	if entry := pair.a.sessions[retired]; entry.retiredTxGeneration == 0 && entry.retiredRxGeneration == 0 {
		t.Fatal("retirement did not record the per-direction generations")
	}

	driverA, driverB := runSelfKeyUpdate(t, pair)
	defer driverA.stop()
	defer driverB.stop()

	if n := pair.a.ReclaimRetiredSessions(); n != 1 {
		t.Fatalf("reclaimed %d tombstones after mutual DONE; want 1", n)
	}
	if sessionPresent(pair.a, retired) {
		t.Fatal("eligible tombstone was not reclaimed")
	}
	if !sessionPresent(pair.a, live) {
		t.Fatal("reclaim removed a live admission")
	}
	if err := pair.a.AdmitSession(retired, SessionClassStream); err != nil {
		t.Fatalf("re-admit after reclaim under the new root: %v", err)
	}
}

// keyUpdateTargetDriver is the runtime shape for a transaction whose negotiation
// carrier and target carrier are distinct Links: both Links' readers feed the
// same control engine's HandleUpdate, and every returned action is executed by
// one shared writer (carrier = action.Carrier, completion event = action.Owner).
type keyUpdateTargetDriver struct {
	control  *ProtectedControlIO
	actions  chan KeyUpdateAction
	quit     chan struct{}
	quitOnce sync.Once
	mu       sync.Mutex
	seen     []ProtectedMessage
	err      error
}

func newKeyUpdateTargetDriver(control *ProtectedControlIO) *keyUpdateTargetDriver {
	return &keyUpdateTargetDriver{control: control, actions: make(chan KeyUpdateAction, testKeyUpdateQueueCapacity), quit: make(chan struct{})}
}

func (d *keyUpdateTargetDriver) start(t *testing.T, sources ...*ProtectedControlIO) {
	t.Helper()
	go d.writeLoop(t)
	for _, source := range sources {
		go d.readLoop(t, source)
	}
}

func (d *keyUpdateTargetDriver) stop() { d.quitOnce.Do(func() { close(d.quit) }) }

func (d *keyUpdateTargetDriver) enqueue(action KeyUpdateAction) bool {
	select {
	case d.actions <- action:
		return true
	case <-d.quit:
		return false
	default:
		d.fail(nil, errTestKeyUpdateQueueFull)
		return false
	}
}

func (d *keyUpdateTargetDriver) writeLoop(t *testing.T) {
	for {
		var action KeyUpdateAction
		select {
		case <-d.quit:
			return
		case next, ok := <-d.actions:
			if !ok {
				return
			}
			action = next
		}
		carrier := action.Carrier
		if carrier == nil {
			carrier = d.control
		}
		applyErr := carrier.ApplyKeyUpdateAction(action)
		owner := action.Owner
		if owner == nil {
			if concrete, ok := carrier.(*ProtectedControlIO); ok {
				owner = concrete
			}
		}
		var follow []KeyUpdateAction
		var err error
		if owner != nil {
			follow, err = owner.CompleteKeyUpdateAction(action, applyErr)
		} else {
			err = applyErr
		}
		for _, next := range follow {
			if !d.enqueue(next) {
				return
			}
		}
		if errors.Is(applyErr, ErrKeyUpdateAbort) {
			continue
		}
		if applyErr != nil || err != nil {
			d.fail(applyErr, err)
			return
		}
	}
}

func (d *keyUpdateTargetDriver) readLoop(t *testing.T, source *ProtectedControlIO) {
	for {
		message, err := source.ReadMessage()
		if err != nil {
			return
		}
		if message.Kind == wire.FrameKindLinkControl && len(message.Payload) > 0 && message.Payload[0] == ControlTypeKeyUpdate {
			actions, err := d.control.HandleUpdate(message)
			if err != nil {
				d.fail(nil, err)
				return
			}
			for _, action := range actions {
				d.actions <- action
			}
			continue
		}
		d.mu.Lock()
		d.seen = append(d.seen, message)
		d.mu.Unlock()
	}
}

func (d *keyUpdateTargetDriver) fail(applyErr, completionErr error) {
	d.mu.Lock()
	if d.err == nil {
		if applyErr != nil {
			d.err = applyErr
		} else {
			d.err = completionErr
		}
	}
	d.mu.Unlock()
}

func (d *keyUpdateTargetDriver) failure() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

// TestKeyUpdateDataTargetRekeysStreamCarrierNotControl runs the real DATA-target
// orchestration: a CONTROL Link negotiates, a DISTINCT DATA Link (different
// LinkID/Epoch/Generation, real Noise) carries the target FENCE/CONFIRM, and the
// transaction completes. It proves both physical connections are replaced by
// nothing, the DATA link's roots and generation advance, the CONTROL link's keys
// are untouched, and CarrierGen != TargetGen.
func TestKeyUpdateDataTargetRekeysStreamCarrierNotControl(t *testing.T) {
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

	controlLeft, controlRight := control.a.stream, control.b.stream
	dataLeft, dataRight := data.a.stream, data.b.stream
	oldControlTx, oldControlRx := control.a.txRoot, control.a.rxRoot
	oldDataTx, oldDataRx := data.a.txRoot, data.a.rxRoot

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
	if got := control.a.KeyUpdateStatus().State; got != KuStateStable {
		t.Fatalf("A state = %s; want Stable", got)
	}
	if got := control.b.KeyUpdateStatus().State; got != KuStateStable {
		t.Fatalf("B state = %s; want Stable", got)
	}
	// Both physical connections survive untouched.
	if control.a.stream != controlLeft || control.b.stream != controlRight {
		t.Fatal("the negotiation stream was replaced")
	}
	if data.a.stream != dataLeft || data.b.stream != dataRight {
		t.Fatal("the DATA target stream was replaced")
	}
	// The CONTROL link keeps its keys; the DATA link switches to the new domain.
	if control.a.txRoot != oldControlTx || control.a.rxRoot != oldControlRx {
		t.Fatal("the control Link roots changed; the target was misrouted")
	}
	if data.a.txRoot == oldDataTx || data.a.rxRoot == oldDataRx {
		t.Fatal("the DATA Link roots did not change")
	}
	if data.b.txRoot != data.a.rxRoot || data.b.rxRoot != data.a.txRoot {
		t.Fatal("DATA Link directions do not agree")
	}
	if data.a.txGen != data.b.rxGen || data.b.txGen != data.a.rxGen {
		t.Fatalf("DATA generations disagree: a tx/rx %d/%d, b tx/rx %d/%d", data.a.txGen, data.a.rxGen, data.b.txGen, data.b.rxGen)
	}
	// CarrierGen != TargetGen: the DATA domain is distinct from the control one.
	if data.a.txGen == control.a.txGen {
		t.Fatal("CarrierGen == TargetGen")
	}
	if data.a.txGen != control.a.KeyUpdateStatus().NewGeneration {
		t.Fatal("installed DATA generation differs from the committed one")
	}
}

// TestKeyUpdateRepeatedTransactionsSameLink proves a long-lived physical Link can
// run two consecutive in-place updates: after each mutual Stable the transaction
// scratch state and the carrier's completed pending slot are released, a fresh
// generation is used, the same stream and session table survive, and a business
// E2E frame crosses after each rekey.
func TestKeyUpdateRepeatedTransactionsSameLink(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePair(t, pair)
	sessionID := testSessionID(0xF1)
	for _, side := range []*ProtectedControlIO{pair.a, pair.b} {
		if err := side.AdmitSession(sessionID, SessionClassStream); err != nil {
			t.Fatal(err)
		}
	}
	driverA, driverB := newKeyUpdateDriver(pair.a), newKeyUpdateDriver(pair.b)
	driverA.start(t)
	driverB.start(t)
	defer driverA.stop()
	defer driverB.stop()
	left, right := pair.a.stream, pair.b.stream
	ciphertext := bytes.Repeat([]byte{0x44}, 32)
	inner := len(ciphertext) - e2eTagSize

	round := func(number uint64) {
		t.Helper()
		actions, err := pair.a.RequestKeyUpdate()
		if err != nil {
			t.Fatalf("round %d request: %v", number, err)
		}
		for _, action := range actions {
			driverA.actions <- action
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if pair.a.KeyUpdateStatus().State == KuStateStable && pair.b.KeyUpdateStatus().State == KuStateStable {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		if err := driverA.failure(); err != nil {
			t.Fatalf("round %d driver A: %v", number, err)
		}
		if err := driverB.failure(); err != nil {
			t.Fatalf("round %d driver B: %v", number, err)
		}
		if pair.a.KeyUpdateStatus().State != KuStateStable || pair.b.KeyUpdateStatus().State != KuStateStable {
			t.Fatalf("round %d not stable: A %s B %s", number,
				pair.a.KeyUpdateStatus().State, pair.b.KeyUpdateStatus().State)
		}
		envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, number, 4, 2, inner)
		written := make(chan error, 1)
		go func() { written <- pair.a.WriteEndToEnd(envelope, ciphertext, testHop) }()
		if got := awaitDriverFrame(t, driverB, 3*time.Second); got.Kind != wire.FrameKindEndToEnd {
			t.Fatalf("round %d business frame kind 0x%02x", number, uint8(got.Kind))
		}
		if err := <-written; err != nil {
			t.Fatalf("round %d business write: %v", number, err)
		}
	}

	first := pair.a.txGen
	round(1)
	generationOne := pair.a.txGen
	if generationOne == first {
		t.Fatal("round 1 did not advance the generation")
	}
	round(2)
	generationTwo := pair.a.txGen
	if generationTwo == generationOne {
		t.Fatal("round 2 reused the previous generation")
	}
	if pair.a.stream != left || pair.b.stream != right {
		t.Fatal("the physical stream was replaced")
	}
	if pair.a.txGen != pair.b.rxGen || pair.b.txGen != pair.a.rxGen {
		t.Fatalf("generations disagree: a tx/rx %d/%d, b tx/rx %d/%d", pair.a.txGen, pair.a.rxGen, pair.b.txGen, pair.b.rxGen)
	}
	if status := pair.a.KeyUpdateStatus(); status.Seq != 2 || status.NewGeneration != generationTwo {
		t.Fatalf("status seq %d generation %d; want seq 2 generation %d", status.Seq, status.NewGeneration, generationTwo)
	}
	if pair.a.pendingSlot != nil || pair.b.pendingSlot != nil {
		t.Fatal("a completed transaction left its pending slot installed")
	}
	if !sessionPresent(pair.a, sessionID) || !sessionPresent(pair.b, sessionID) {
		t.Fatal("the session table was rebuilt by a repeated rekey")
	}
	if got := pair.a.sessions[sessionID].txCounter; got != 2 {
		t.Fatalf("session inner counter = %d; want 2 (never reset by the Link rekey)", got)
	}
}

// TestKeyUpdateRepeatedTinyThresholdRekeys drives the built-in policy twice over
// one Link: a tiny seal threshold makes the automatic trigger start generation 1,
// mutual Stable re-arms it, and enough further seals start generation 2 — with a
// real business frame after each.
func TestKeyUpdateRepeatedTinyThresholdRekeys(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{SealLimit: 128})
	sessionID := testSessionID(0xF3)
	for _, side := range []*ProtectedControlIO{pair.a, pair.b} {
		if err := side.AdmitSession(sessionID, SessionClassStream); err != nil {
			t.Fatal(err)
		}
	}
	driverA, driverB := newKeyUpdateHookDriver(pair.a), newKeyUpdateHookDriver(pair.b)
	driverA.start(t)
	driverB.start(t)
	defer driverA.stop()
	defer driverB.stop()

	var mu sync.Mutex
	triggers := 0
	pair.a.SetKeyUpdateActionSink(func(actions []KeyUpdateAction) error {
		mu.Lock()
		triggers++
		mu.Unlock()
		for _, action := range actions {
			driverA.actions <- action
		}
		return nil
	})

	round := func(number int) {
		t.Helper()
		mu.Lock()
		before := triggers
		mu.Unlock()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			started := triggers
			mu.Unlock()
			if started > before {
				break
			}
			if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: bytes.Repeat([]byte{0xa5}, 16)}); err != nil {
				t.Fatalf("round %d control write: %v", number, err)
			}
		}
		mu.Lock()
		after := triggers
		mu.Unlock()
		if after <= before {
			t.Fatalf("round %d: the tiny threshold never triggered an update", number)
		}
		for time.Now().Before(deadline) {
			if pair.a.KeyUpdateStatus().State == KuStateStable && pair.b.KeyUpdateStatus().State == KuStateStable {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		if err := driverA.failure(); err != nil {
			t.Fatalf("round %d driver A: %v", number, err)
		}
		if err := driverB.failure(); err != nil {
			t.Fatalf("round %d driver B: %v", number, err)
		}
		if pair.a.KeyUpdateStatus().State != KuStateStable || pair.b.KeyUpdateStatus().State != KuStateStable {
			t.Fatalf("round %d not stable: A %s B %s", number,
				pair.a.KeyUpdateStatus().State, pair.b.KeyUpdateStatus().State)
		}
		ciphertext := bytes.Repeat([]byte{0x6a}, 32)
		inner := len(ciphertext) - e2eTagSize
		envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, uint64(number), 4, 2, inner)
		written := make(chan error, 1)
		go func() { written <- pair.a.WriteEndToEnd(envelope, ciphertext, testHop) }()
		delivered := awaitKind(t, driverB, wire.FrameKindEndToEnd, 3*time.Second)
		if err := <-written; err != nil {
			t.Fatalf("round %d business write: %v", number, err)
		}
		if len(delivered.Payload) != len(ciphertext) {
			t.Fatalf("round %d business payload %d; want %d", number, len(delivered.Payload), len(ciphertext))
		}
	}

	first := pair.a.txGen
	round(1)
	generationOne := pair.a.txGen
	if generationOne == first {
		t.Fatal("generation 1 did not rekey")
	}
	round(2)
	if pair.a.txGen == generationOne {
		t.Fatal("generation 2 reused the previous generation")
	}
	mu.Lock()
	total := triggers
	mu.Unlock()
	if total != 2 {
		t.Fatalf("automatic triggers = %d; want exactly 2 (one per generation)", total)
	}
	if status := pair.a.KeyUpdateStatus(); status.Seq != 2 {
		t.Fatalf("seq = %d; want 2", status.Seq)
	}
}

// TestKeyUpdateConcurrentRequestCoalesces proves concurrent RequestKeyUpdate
// calls coalesce onto one transaction: exactly one starts, the rest are refused
// with ErrKeyUpdateState, one XX1 is produced and the sequence is not bumped.
func TestKeyUpdateConcurrentRequestCoalesces(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePair(t, pair)
	type outcome struct {
		actions []KeyUpdateAction
		err     error
	}
	const callers = 8
	results := make(chan outcome, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		go func() {
			<-start
			actions, err := pair.a.RequestKeyUpdate()
			results <- outcome{actions, err}
		}()
	}
	close(start)
	started, refused, actionCount := 0, 0, 0
	for i := 0; i < callers; i++ {
		got := <-results
		switch {
		case got.err == nil:
			started++
			actionCount += len(got.actions)
		case errors.Is(got.err, ErrKeyUpdateState):
			refused++
		default:
			t.Fatalf("unexpected concurrent request error: %v", got.err)
		}
	}
	if started != 1 || refused != callers-1 {
		t.Fatalf("coalescing: %d started, %d refused; want 1 and %d", started, refused, callers-1)
	}
	if actionCount != 1 {
		t.Fatalf("the started request produced %d actions; want exactly one XX1", actionCount)
	}
	if status := pair.a.KeyUpdateStatus(); status.State != KuStatePending || status.Seq != 1 {
		t.Fatalf("engine state %s seq %d; want Pending seq 1", status.State, status.Seq)
	}
	if hint := pair.a.nextUpdateSeqHint(); hint != 2 {
		t.Fatalf("sequence hint = %d; want 2 (coalesced calls must not bump it)", hint)
	}
}

// TestKeyUpdateAbortReleasesSlotAndRepeatsTransaction proves a finished abort
// releases the carrier's pending slot (with the exact sequence/generation/target
// proof) and that a second real transaction then completes over the same Link.
func TestKeyUpdateAbortReleasesSlotAndRepeatsTransaction(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePair(t, pair)
	sessionID := testSessionID(0xF2)
	for _, side := range []*ProtectedControlIO{pair.a, pair.b} {
		if err := side.AdmitSession(sessionID, SessionClassStream); err != nil {
			t.Fatal(err)
		}
	}
	// Transaction 1 is negotiated in-process and aborted before either fence, so
	// the follower can still acknowledge.
	xx1, err := pair.a.RequestKeyUpdate()
	if err != nil {
		t.Fatal(err)
	}
	xx2 := deliverKeyUpdate(t, pair.b, xx1[0])
	xx3 := deliverKeyUpdate(t, pair.a, xx2[0])
	ready := deliverKeyUpdate(t, pair.b, xx3[0])
	commit := deliverKeyUpdate(t, pair.a, ready[0])
	// Deliver COMMIT so BOTH carriers publish their trusted pending slot, then
	// ARMED so the coordinator queues (but never applies) its fence. Neither side
	// completes a fence, so both can still acknowledge the abort.
	armed := deliverKeyUpdate(t, pair.b, commit[0])
	if len(armed) != 3 {
		t.Fatalf("COMMIT produced %d follower actions", len(armed))
	}
	deliverKeyUpdate(t, pair.a, armed[0])
	if pair.a.pendingSlot == nil || pair.b.pendingSlot == nil {
		t.Fatal("transaction 1 did not publish a trusted pending slot")
	}
	abortActions, err := pair.a.RequestAbort()
	if err != nil || len(abortActions) != 1 {
		t.Fatalf("RequestAbort: %d actions, err %v", len(abortActions), err)
	}
	ack := deliverKeyUpdate(t, pair.b, abortActions[0])
	if len(ack) != 1 || ack[0].Phase != KeyUpdateAbortAck {
		t.Fatalf("follower did not acknowledge the abort: %v", ack)
	}
	deliverKeyUpdate(t, pair.a, ack[0])
	if got := pair.a.KeyUpdateStatus().State; got != KuStateAborted {
		t.Fatalf("A state = %s; want Aborted", got)
	}
	if pair.a.pendingSlot != nil || pair.b.pendingSlot != nil {
		t.Fatal("the aborted transaction left its pending slot installed")
	}
	if got := recoveryReserve(pair.a); got != 0 {
		t.Fatalf("abort left the recovery reserve armed: %d", got)
	}
	if got := recoveryReserve(pair.b); got != 0 {
		t.Fatalf("abort left the peer recovery reserve armed: %d", got)
	}

	// Transaction 2 runs over the same real stream with a fresh sequence.
	driverA, driverB := newKeyUpdateDriver(pair.a), newKeyUpdateDriver(pair.b)
	driverA.start(t)
	driverB.start(t)
	defer driverA.stop()
	defer driverB.stop()
	actions, err := pair.a.RequestKeyUpdate()
	if err != nil {
		t.Fatalf("transaction 2 request: %v", err)
	}
	for _, action := range actions {
		driverA.actions <- action
	}
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
		t.Fatalf("transaction 2 not stable: A %s B %s",
			pair.a.KeyUpdateStatus().State, pair.b.KeyUpdateStatus().State)
	}
	if status := pair.a.KeyUpdateStatus(); status.Seq != 2 || status.Aborted {
		t.Fatalf("transaction 2 status: seq %d aborted %v; want seq 2 not aborted", status.Seq, status.Aborted)
	}
	ciphertext := bytes.Repeat([]byte{0x7b}, 32)
	inner := len(ciphertext) - e2eTagSize
	envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 4, 2, inner)
	written := make(chan error, 1)
	go func() { written <- pair.a.WriteEndToEnd(envelope, ciphertext, testHop) }()
	if got := awaitDriverFrame(t, driverB, 3*time.Second); got.Kind != wire.FrameKindEndToEnd {
		t.Fatalf("business frame after the repeated transaction: kind 0x%02x", uint8(got.Kind))
	}
	if err := <-written; err != nil {
		t.Fatalf("business write after the repeated transaction: %v", err)
	}
}

// TestKeyUpdateBothSidesAutoTriggerSameLink is the minimal reproducer for the
// concurrent tiny-policy hang: both ends of one Link install an action sink and
// cross the soft threshold, so each side may start (or request) an update at the
// same time. It must still converge to a new Stable generation with a bounded
// no-hang timeout, then repeat for a second generation.
func TestKeyUpdateBothSidesAutoTriggerSameLink(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{SealLimit: 64})
	sessionID := testSessionID(0x71)
	for _, side := range []*ProtectedControlIO{pair.a, pair.b} {
		if err := side.AdmitSession(sessionID, SessionClassStream); err != nil {
			t.Fatal(err)
		}
	}
	driverA, driverB := newKeyUpdateHookDriver(pair.a), newKeyUpdateHookDriver(pair.b)
	driverA.start(t)
	driverB.start(t)
	defer driverA.stop()
	defer driverB.stop()

	var mu sync.Mutex
	triggersA, triggersB := 0, 0
	pair.a.SetKeyUpdateActionSink(func(actions []KeyUpdateAction) error {
		mu.Lock()
		triggersA++
		mu.Unlock()
		for _, action := range actions {
			driverA.actions <- action
		}
		return nil
	})
	pair.b.SetKeyUpdateActionSink(func(actions []KeyUpdateAction) error {
		mu.Lock()
		triggersB++
		mu.Unlock()
		for _, action := range actions {
			driverB.actions <- action
		}
		return nil
	})

	generation := func(round int) {
		t.Helper()
		mu.Lock()
		beforeA, beforeB := triggersA, triggersB
		mu.Unlock()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			startedA, startedB := triggersA > beforeA, triggersB > beforeB
			mu.Unlock()
			if startedA && startedB {
				break
			}
			writeErr := make(chan error, 2)
			go func() {
				writeErr <- pair.a.WriteControl(ControlMessage{Type: 1, Payload: bytes.Repeat([]byte{0xa1}, 16)})
			}()
			go func() {
				writeErr <- pair.b.WriteControl(ControlMessage{Type: 1, Payload: bytes.Repeat([]byte{0xb2}, 16)})
			}()
			for i := 0; i < 2; i++ {
				if err := <-writeErr; err != nil {
					t.Fatalf("round %d control write: %v", round, err)
				}
			}
		}
		mu.Lock()
		startedA, startedB := triggersA > beforeA, triggersB > beforeB
		mu.Unlock()
		if !startedA || !startedB {
			t.Fatalf("round %d: both sides must trigger; A=%v B=%v", round, startedA, startedB)
		}
		for time.Now().Before(deadline) {
			if pair.a.KeyUpdateStatus().State == KuStateStable && pair.b.KeyUpdateStatus().State == KuStateStable {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		if err := driverA.failure(); err != nil {
			t.Fatalf("round %d driver A: %v", round, err)
		}
		if err := driverB.failure(); err != nil {
			t.Fatalf("round %d driver B: %v", round, err)
		}
		if pair.a.KeyUpdateStatus().State != KuStateStable || pair.b.KeyUpdateStatus().State != KuStateStable {
			t.Fatalf("round %d did not reach Stable: A %s (%d/%d) B %s (%d/%d)", round,
				pair.a.KeyUpdateStatus().State, pair.a.KeyUpdateStatus().Seq, pair.a.KeyUpdateStatus().Phase,
				pair.b.KeyUpdateStatus().State, pair.b.KeyUpdateStatus().Seq, pair.b.KeyUpdateStatus().Phase)
		}
		if pair.a.txGen != pair.b.rxGen || pair.b.txGen != pair.a.rxGen {
			t.Fatalf("round %d generations disagree: a tx/rx %d/%d b tx/rx %d/%d", round,
				pair.a.txGen, pair.a.rxGen, pair.b.txGen, pair.b.rxGen)
		}
		ciphertext := bytes.Repeat([]byte{0x5d}, 32)
		inner := len(ciphertext) - e2eTagSize
		envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, uint64(round), 4, 2, inner)
		written := make(chan error, 1)
		go func() { written <- pair.a.WriteEndToEnd(envelope, ciphertext, testHop) }()
		delivered := awaitKind(t, driverB, wire.FrameKindEndToEnd, 3*time.Second)
		if err := <-written; err != nil {
			t.Fatalf("round %d business write: %v", round, err)
		}
		if len(delivered.Payload) != len(ciphertext) {
			t.Fatalf("round %d business payload %d; want %d", round, len(delivered.Payload), len(ciphertext))
		}
	}

	first := pair.a.txGen
	generation(1)
	if pair.a.txGen == first {
		t.Fatal("generation 1 did not rekey")
	}
	one := pair.a.txGen
	generation(2)
	if pair.a.txGen == one {
		t.Fatal("generation 2 reused the previous generation")
	}
}

// recoveryReserve reads the carrier's remaining bounded recovery reserve.
func recoveryReserve(io *ProtectedControlIO) uint32 {
	io.kuMu.Lock()
	defer io.kuMu.Unlock()
	return io.kuRecoveryReserve
}

// TestKeyUpdateTinySealLimitCompletesAndRepeats pins the hard-stop recovery fix
// with the most aggressive policy that still lets a single maximal business
// frame through: SealLimit=1 makes the control soft threshold saturate to zero
// (so the update is always wanted) and its hard boundary one single old-domain
// seal. Without the bounded per-transaction recovery reserve the correlated
// old-domain control hits that wall and the Link fails closed mid-update. It is
// bounded (no hang), reaches a new Stable generation, delivers one maximal
// ~64KiB business frame, and repeats for a second generation.
func TestKeyUpdateTinySealLimitCompletesAndRepeats(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{SealLimit: 1})
	sessionID := testSessionID(0x82)
	for _, side := range []*ProtectedControlIO{pair.a, pair.b} {
		if err := side.AdmitSession(sessionID, SessionClassStream); err != nil {
			t.Fatal(err)
		}
	}
	driverA, driverB := newKeyUpdateHookDriver(pair.a), newKeyUpdateHookDriver(pair.b)
	driverA.start(t)
	driverB.start(t)
	pair.a.SetKeyUpdateActionSink(func(actions []KeyUpdateAction) error {
		for _, action := range actions {
			driverA.actions <- action
		}
		return nil
	})
	pair.b.SetKeyUpdateActionSink(func(actions []KeyUpdateAction) error {
		for _, action := range actions {
			driverB.actions <- action
		}
		return nil
	})

	waitNewGeneration := func(round int, previous uint32) uint32 {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if pair.a.KeyUpdateStatus().State == KuStateStable && pair.b.KeyUpdateStatus().State == KuStateStable &&
				pair.a.txGen != previous {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		if err := driverA.failure(); err != nil {
			t.Fatalf("round %d driver A: %v", round, err)
		}
		if err := driverB.failure(); err != nil {
			t.Fatalf("round %d driver B: %v", round, err)
		}
		if pair.a.KeyUpdateStatus().State != KuStateStable || pair.b.KeyUpdateStatus().State != KuStateStable {
			t.Fatalf("round %d did not stabilize: A %s (%d/%d) B %s (%d/%d)", round,
				pair.a.KeyUpdateStatus().State, pair.a.KeyUpdateStatus().Seq, pair.a.KeyUpdateStatus().Phase,
				pair.b.KeyUpdateStatus().State, pair.b.KeyUpdateStatus().Seq, pair.b.KeyUpdateStatus().Phase)
		}
		if pair.a.txGen == previous {
			t.Fatalf("round %d did not reach a new generation", round)
		}
		return pair.a.txGen
	}
	deliverBusiness := func(round int, generation uint32) {
		t.Helper()
		// The maximal single hop business frame: MaxFrameLength minus the frame,
		// hop-header and envelope overheads (64KiB-class).
		ciphertext := bytes.Repeat([]byte{0x9a}, maxEndToEndPayload)
		if len(ciphertext) < 64<<10-256 {
			t.Fatalf("maximal business payload %d is not 64KiB-class", len(ciphertext))
		}
		inner := len(ciphertext) - e2eTagSize
		envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, uint64(round), 4, 2, inner)
		written := make(chan error, 1)
		go func() { written <- pair.a.WriteEndToEnd(envelope, ciphertext, testHop) }()
		delivered := awaitKind(t, driverB, wire.FrameKindEndToEnd, 3*time.Second)
		if err := <-written; err != nil {
			t.Fatalf("round %d business write: %v", round, err)
		}
		if len(delivered.Payload) != len(ciphertext) {
			t.Fatalf("round %d business payload %d; want %d", round, len(delivered.Payload), len(ciphertext))
		}
		if pair.a.txGen != generation {
			t.Fatalf("round %d business crossed generation %d; want %d", round, pair.a.txGen, generation)
		}
	}

	first := pair.a.txGen
	// One old-domain control frame is permitted before the hard boundary and its
	// deferred poll starts generation 1.
	if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: make([]byte, 16)}); err != nil {
		t.Fatalf("generation 1 trigger: %v", err)
	}
	// The pathological tiny policy keeps the control soft threshold permanently
	// crossed, so the automatic trigger would chain generations without bound.
	// Generation 1 above was started automatically; stop the automatic churn and
	// drive generation 2 explicitly so the test is bounded.
	pair.a.SetKeyUpdateActionSink(nil)
	pair.b.SetKeyUpdateActionSink(nil)
	generationOne := waitNewGeneration(1, first)
	// The reserve is only ever armed while a transaction is in flight.
	if got := recoveryReserve(pair.a); got != 0 && !pair.a.keyUpdateInFlight() {
		t.Fatalf("reserve %d armed with no transaction in flight", got)
	}
	deliverBusiness(1, generationOne)
	second, err := pair.a.RequestKeyUpdate()
	if err != nil {
		t.Fatalf("generation 2 request: %v", err)
	}
	for _, action := range second {
		if !driverA.enqueue(action) {
			t.Fatalf("generation 2 enqueue failed")
		}
	}
	generationTwo := waitNewGeneration(2, generationOne)
	deliverBusiness(2, generationTwo)
	if pair.a.txGen != pair.b.rxGen || pair.b.txGen != pair.a.rxGen {
		t.Fatalf("generations disagree: a tx/rx %d/%d b tx/rx %d/%d",
			pair.a.txGen, pair.a.rxGen, pair.b.txGen, pair.b.rxGen)
	}
}

// TestKeyUpdateRecoveryReserveExhaustsFailClosed pins the reserve exactly: it is
// NOT armed by ordinary usage, it grants exactly the reserved number of
// old-domain control frames while a transaction is in flight, and both
// exhaustion and clearing fail closed. The key-update opcode is not an
// unconditional exemption: an arbitrary 0x09 is refused too, and only a 0x09
// this Link prepared consumes a permit.
func TestKeyUpdateRecoveryReserveExhaustsFailClosed(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{SealLimit: 1})
	driverB := newKeyUpdateHookDriver(pair.b)
	driverB.start(t)
	defer driverB.stop()

	// Reach the control hard boundary with no transaction in flight: ordinary
	// usage must fail closed rather than silently spend a reserve.
	if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: make([]byte, 16)}); err != nil {
		t.Fatalf("first old-domain control: %v", err)
	}
	if got := recoveryReserve(pair.a); got != 0 {
		t.Fatalf("reserve armed by ordinary usage: %d", got)
	}
	if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: make([]byte, 16)}); !errors.Is(err, ErrKeyUpdateRequired) {
		t.Fatalf("unarmed hard wall error = %v; want ErrKeyUpdateRequired", err)
	}

	writeRoute := func() error {
		return pair.a.WriteRoute(routeEnvelope(wire.MessageTypeSessionCtrl, testSessionID(0x83), 7, 3, 32),
			bytes.Repeat([]byte{0x01}, 32), testHop)
	}

	// An in-flight transaction arms exactly the reserved number of frames.
	pair.a.armKeyUpdateRecoveryReserve()
	if got := recoveryReserve(pair.a); got != uint32(keyUpdateControlHandshakeReserve) {
		t.Fatalf("armed reserve = %d; want %d", got, keyUpdateControlHandshakeReserve)
	}
	for i := 0; i < int(keyUpdateControlHandshakeReserve)-1; i++ {
		if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: make([]byte, 16)}); err != nil {
			t.Fatalf("reserved frame %d refused: %v", i, err)
		}
	}
	if got := recoveryReserve(pair.a); got != 1 {
		t.Fatalf("reserve after %d control frames = %d; want 1", keyUpdateControlHandshakeReserve-1, got)
	}
	// Bring the ROUTE domain to its own hard boundary. This seal is allowed
	// because route is not yet hard, so it must NOT spend the reserve.
	if err := writeRoute(); err != nil {
		t.Fatalf("route pre-boundary write: %v", err)
	}
	if got := recoveryReserve(pair.a); got != 1 {
		t.Fatalf("route pre-boundary write spent the reserve: %d", got)
	}
	// The shared reserve is the last permitted frame: a route frame may spend it.
	if err := writeRoute(); err != nil {
		t.Fatalf("shared reserve refused the route frame: %v", err)
	}
	if got := recoveryReserve(pair.a); got != 0 {
		t.Fatalf("reserve after the shared route frame = %d; want 0", got)
	}
	// Exhausted: both domains fail closed.
	if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: make([]byte, 16)}); !errors.Is(err, ErrKeyUpdateRequired) {
		t.Fatalf("post-reserve control error = %v; want ErrKeyUpdateRequired", err)
	}
	if err := writeRoute(); !errors.Is(err, ErrKeyUpdateRequired) {
		t.Fatalf("post-reserve route error = %v; want ErrKeyUpdateRequired", err)
	}
	// A never-prepared 0x09 is not an unconditional exemption: with the permit
	// budget exhausted it is refused before a nonce is spent. Only a 0x09 this
	// Link actually prepared for its transaction is the recovery channel (see
	// TestKeyUpdateHardBoundaryFailsClosed).
	arbitraryBody, err := EncodeKeyUpdate(KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateRequest, Lane: pair.a.linkLane,
		TargetLinkID: pair.ar.LinkID, TargetLinkEpoch: pair.ar.LinkEpoch, UpdateSeq: 99,
	})
	if err != nil {
		t.Fatal(err)
	}
	beforeNine := pair.a.txNext
	if err := pair.a.WriteControl(ControlMessage{Type: ControlTypeKeyUpdate, Payload: arbitraryBody}); !errors.Is(err, ErrKeyUpdateRequired) {
		t.Fatalf("arbitrary 0x09 after exhaustion error = %v; want ErrKeyUpdateRequired", err)
	}
	if pair.a.txNext != beforeNine {
		t.Fatal("a refused arbitrary 0x09 spent a nonce")
	}
	// Clearing (finalize/abort) restores fail-closed immediately.
	pair.a.armKeyUpdateRecoveryReserve()
	pair.a.clearKeyUpdateRecoveryReserve()
	if got := recoveryReserve(pair.a); got != 0 {
		t.Fatalf("cleared reserve = %d; want 0", got)
	}
	if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: make([]byte, 16)}); !errors.Is(err, ErrKeyUpdateRequired) {
		t.Fatalf("cleared reserve did not fail closed: %v", err)
	}
}

// TestKeyUpdateThreeLanesTinySealPolicy runs the pkg-shaped multi-lane case: three
// distinct real Links between the same two sides, each self-targeting with the
// same tiny policy, an action sink on every pump-like driver, and concurrent
// business. Every lane must reach a new Stable generation within a bounded time
// (no hang), carry one maximal ~64KiB business frame, and repeat for a second
// generation.
func TestKeyUpdateThreeLanesTinySealPolicy(t *testing.T) {
	const lanes = 3
	type lane struct {
		pair             controlPair
		driverA, driverB *keyUpdateHookDriver
		sessionID        [16]byte
	}
	lanesUnderTest := make([]*lane, 0, lanes)
	for i := 0; i < lanes; i++ {
		pair := establishedControlPairWith(t, uint64(200+i), uint64(10+i), uint32(50+i))
		configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{SealLimit: 1})
		sessionID := testSessionID(byte(0x90 + i))
		for _, side := range []*ProtectedControlIO{pair.a, pair.b} {
			if err := side.AdmitSession(sessionID, SessionClassStream); err != nil {
				t.Fatalf("lane %d admit: %v", i, err)
			}
		}
		entry := &lane{pair: pair, driverA: newKeyUpdateHookDriver(pair.a), driverB: newKeyUpdateHookDriver(pair.b), sessionID: sessionID}
		entry.driverA.start(t)
		entry.driverB.start(t)
		pair.a.SetKeyUpdateActionSink(func(actions []KeyUpdateAction) error {
			for _, action := range actions {
				entry.driverA.actions <- action
			}
			return nil
		})
		pair.b.SetKeyUpdateActionSink(func(actions []KeyUpdateAction) error {
			for _, action := range actions {
				entry.driverB.actions <- action
			}
			return nil
		})
		lanesUnderTest = append(lanesUnderTest, entry)
	}
	defer func() {
		for _, entry := range lanesUnderTest {
			entry.driverA.stop()
			entry.driverB.stop()
		}
	}()

	// Record each lane's starting generation before any trigger: a later lane's
	// transaction can complete while earlier lanes are still being waited on.
	initial := make([]uint32, len(lanesUnderTest))
	for index, entry := range lanesUnderTest {
		initial[index] = entry.pair.a.txGen
	}
	// All three lanes are triggered at once, exactly like the pkg's per-lane soft
	// policy crossing simultaneously. With this pathological threshold the soft
	// trigger never clears, so generation 1 is automatic and the automatic churn
	// is then stopped and generation 2 is requested explicitly.
	for _, entry := range lanesUnderTest {
		if err := entry.pair.a.WriteControl(ControlMessage{Type: 1, Payload: make([]byte, 16)}); err != nil {
			t.Fatalf("lane trigger: %v", err)
		}
		entry.pair.a.SetKeyUpdateActionSink(nil)
		entry.pair.b.SetKeyUpdateActionSink(nil)
	}
	deadline := time.Now().Add(20 * time.Second)
	waitLaneGeneration := func(entry *lane, index int, previous uint32) uint32 {
		t.Helper()
		for time.Now().Before(deadline) {
			if entry.pair.a.KeyUpdateStatus().State == KuStateStable && entry.pair.b.KeyUpdateStatus().State == KuStateStable &&
				entry.pair.a.txGen != previous {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		if err := entry.driverA.failure(); err != nil {
			t.Fatalf("lane %d driver A: %v", index, err)
		}
		if err := entry.driverB.failure(); err != nil {
			t.Fatalf("lane %d driver B: %v", index, err)
		}
		if entry.pair.a.KeyUpdateStatus().State != KuStateStable || entry.pair.b.KeyUpdateStatus().State != KuStateStable {
			t.Fatalf("lane %d hung: A %s (%d/%d) B %s (%d/%d)", index,
				entry.pair.a.KeyUpdateStatus().State, entry.pair.a.KeyUpdateStatus().Seq, entry.pair.a.KeyUpdateStatus().Phase,
				entry.pair.b.KeyUpdateStatus().State, entry.pair.b.KeyUpdateStatus().Seq, entry.pair.b.KeyUpdateStatus().Phase)
		}
		if entry.pair.a.txGen == previous {
			t.Fatalf("lane %d did not reach a new generation", index)
		}
		return entry.pair.a.txGen
	}
	deliverLaneBusiness := func(entry *lane, index, round int) {
		t.Helper()
		ciphertext := bytes.Repeat([]byte{0x5e}, maxEndToEndPayload)
		inner := len(ciphertext) - e2eTagSize
		envelope := newEndToEndEnvelope(entry.sessionID, wire.MessageTypeStreamData, 1, uint64(round), uint64(index+4), 2, inner)
		written := make(chan error, 1)
		go func() { written <- entry.pair.a.WriteEndToEnd(envelope, ciphertext, testHop) }()
		delivered := awaitKind(t, entry.driverB, wire.FrameKindEndToEnd, 3*time.Second)
		if err := <-written; err != nil {
			t.Fatalf("lane %d round %d business write: %v", index, round, err)
		}
		if len(delivered.Payload) != len(ciphertext) {
			t.Fatalf("lane %d round %d payload %d; want %d", index, round, len(delivered.Payload), len(ciphertext))
		}
	}

	for index, entry := range lanesUnderTest {
		generationOne := waitLaneGeneration(entry, index, initial[index])
		deliverLaneBusiness(entry, index, 1)
		// A second generation on the same physical Link, requested explicitly so
		// the pathological threshold cannot chain generations without bound.
		second, err := entry.pair.a.RequestKeyUpdate()
		if err != nil {
			t.Fatalf("lane %d generation 2 request: %v", index, err)
		}
		for _, action := range second {
			if !entry.driverA.enqueue(action) {
				t.Fatalf("lane %d generation 2 enqueue failed", index)
			}
		}
		waitLaneGeneration(entry, index, generationOne)
		deliverLaneBusiness(entry, index, 2)
		if entry.pair.a.txGen != entry.pair.b.rxGen || entry.pair.b.txGen != entry.pair.a.rxGen {
			t.Fatalf("lane %d generations disagree", index)
		}
		if got := recoveryReserve(entry.pair.a); got != 0 && !entry.pair.a.keyUpdateInFlight() {
			t.Fatalf("lane %d reserve %d armed with no transaction in flight", index, got)
		}
	}
}
