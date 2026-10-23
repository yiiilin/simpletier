package simpletier

import (
	"errors"
	"testing"

	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/session"
	"github.com/yiiilin/simpletier/internal/topology"
	"github.com/yiiilin/simpletier/internal/wire"
)

// guardNode builds a deterministic 16-byte node identity for the guard tests.
func guardNode(b byte) [16]byte {
	var n [16]byte
	n[0] = b
	return n
}

// TestGuardEnvelopeNetworkID proves a frame bound to another Network locator is
// rejected at both data-plane entry points before any state is touched, and that
// wireID 0 is a legal exact equality rather than a wildcard.
func TestGuardEnvelopeNetworkID(t *testing.T) {
	local, peer := guardNode(0xAA), guardNode(0xBB)
	rt := &streamRuntime{wireID: 7, localID: local}

	foreign := buildEnvelope(8, peer, local, wire.MessageTypeStreamData, [16]byte{1}, 0, 0, 5, 2, 0)
	if err := rt.handleEndToEndFrame(&controlPump{lane: laneStream}, link.ProtectedMessage{Envelope: foreign, Payload: []byte{1}}); !errors.Is(err, link.ErrEndToEndMessage) {
		t.Fatalf("foreign E2E wire id: err = %v, want ErrEndToEndMessage", err)
	}
	foreignRoute := buildEnvelope(8, peer, local, wire.MessageTypePathReady, [16]byte{}, 0, 0, 5, 2, 0)
	if err := rt.handleRouteFrame(&controlPump{lane: laneControl}, link.ProtectedMessage{Envelope: foreignRoute, Payload: []byte{1}}); !errors.Is(err, link.ErrRouteMessage) {
		t.Fatalf("foreign route wire id: err = %v, want ErrRouteMessage", err)
	}
	if got := envelopeWireID(foreign); got != 8 {
		t.Fatalf("envelopeWireID = %d, want 8", got)
	}

	// wireID 0 is an exact match: the frame passes the locator gate and fails
	// later for a missing session, not with the foreign-network sentinel.
	zero := &streamRuntime{wireID: 0, localID: local}
	matching := buildEnvelope(0, peer, local, wire.MessageTypeStreamData, [16]byte{1}, 0, 0, 5, 2, 0)
	if err := zero.handleEndToEndFrame(&controlPump{lane: laneStream}, link.ProtectedMessage{Envelope: matching, Payload: []byte{1}}); !errors.Is(err, link.ErrSessionNotAdmitted) {
		t.Fatalf("zero wire id: err = %v, want ErrSessionNotAdmitted", err)
	}
}

// TestGuardDirectionOnPath proves only the exact logical A/B endpoint pair is
// accepted, in either direction; a frame naming any other pair is neither.
func TestGuardDirectionOnPath(t *testing.T) {
	a, b, c := guardNode(1), guardNode(2), guardNode(3)
	ps := &pathState{
		nodes:      []topology.NodeID{topology.NodeID(a), topology.NodeID(b), topology.NodeID(c)},
		localIndex: 1,
	}
	forward := buildEnvelope(0, a, c, wire.MessageTypeStreamData, [16]byte{}, 0, 0, 1, 1, 0)
	reverse := buildEnvelope(0, c, a, wire.MessageTypeStreamData, [16]byte{}, 0, 0, 1, 1, 0)
	sideways := buildEnvelope(0, a, b, wire.MessageTypeStreamData, [16]byte{}, 0, 0, 1, 1, 0)
	if f, r := ps.directionOnPath(forward); !f || r {
		t.Fatalf("forward: f=%v r=%v", f, r)
	}
	if f, r := ps.directionOnPath(reverse); f || !r {
		t.Fatalf("reverse: f=%v r=%v", f, r)
	}
	if f, r := ps.directionOnPath(sideways); f || r {
		t.Fatalf("sideways must be neither: f=%v r=%v", f, r)
	}
}

// TestGuardOpenLocalEndToEnd proves the endpoint opens or stages nothing unless
// the envelope Path scope, the Path lane class, the wire direction and the
// physical ingress hop all match the installed session.
func TestGuardOpenLocalEndToEnd(t *testing.T) {
	local, peer := guardNode(0xAA), guardNode(0xBB)
	entryID := session.SessionID(guardNode(0x01))
	setup := func() (*streamRuntime, *sessionEntry, *pathState) {
		entry := &sessionEntry{
			id:    entryID,
			scope: pathScope{id: 5, gen: 2},
			class: session.SessionClassStream,
			lane:  session.LaneStream,
			ready: make(chan struct{}),
		}
		ps := &pathState{
			scope:      pathScope{id: 5, gen: 2},
			lane:       path.LaneStream,
			nodes:      []topology.NodeID{topology.NodeID(peer), topology.NodeID(local)},
			localIndex: 1,
			ready:      make(chan struct{}),
		}
		rt := &streamRuntime{
			wireID:       3,
			localID:      local,
			sessionsByID: map[session.SessionID]*sessionEntry{entryID: entry},
			pathsByScope: map[pathScope]*pathState{{id: 5, gen: 2}: ps},
		}
		return rt, entry, ps
	}
	msg := func(src, dst [16]byte, pathID uint64, pathGen uint32) (*controlPump, link.ProtectedMessage) {
		env := buildEnvelope(3, src, dst, wire.MessageTypeStreamData, [16]byte(entryID), 0, 0, pathID, pathGen, 0)
		return &controlPump{lane: laneStream}, link.ProtectedMessage{Envelope: env, Payload: []byte{0xde, 0xad}}
	}
	assertUntouched := func(t *testing.T, entry *sessionEntry) {
		t.Helper()
		if entry.isReady() {
			t.Fatal("session was committed by a rejected frame")
		}
		if len(entry.pending) != 0 || entry.pendBytes != 0 {
			t.Fatalf("rejected frame was staged: frames=%d bytes=%d", len(entry.pending), entry.pendBytes)
		}
	}

	// 1. Envelope Path scope != installed session scope.
	rt, entry, _ := setup()
	pump, m := msg(peer, local, 6, 2)
	if err := rt.openLocalEndToEnd(pump, m, 6, 2); !errors.Is(err, link.ErrEndToEndMessage) {
		t.Fatalf("wrong envelope scope: err = %v, want ErrEndToEndMessage", err)
	}
	assertUntouched(t, entry)

	// 2. Path lane class != session class.
	rt, entry, ps := setup()
	ps.lane = path.LanePacket
	pump, m = msg(peer, local, 5, 2)
	if err := rt.openLocalEndToEnd(pump, m, 5, 2); !errors.Is(err, link.ErrEndToEndMessage) {
		t.Fatalf("wrong lane class: err = %v, want ErrEndToEndMessage", err)
	}
	assertUntouched(t, entry)

	// 3. Wire src/dst are not the logical endpoints of either direction.
	rt, entry, _ = setup()
	pump, m = msg(guardNode(0xCC), guardNode(0xDD), 5, 2)
	if err := rt.openLocalEndToEnd(pump, m, 5, 2); !errors.Is(err, link.ErrEndToEndMessage) {
		t.Fatalf("wrong wire direction: err = %v, want ErrEndToEndMessage", err)
	}
	assertUntouched(t, entry)

	// 4. Correct direction, but the frame did not arrive on an authenticated
	// adjacent STREAM Link (no link at all).
	rt, entry, _ = setup()
	pump, m = msg(peer, local, 5, 2)
	if err := rt.openLocalEndToEnd(pump, m, 5, 2); !errors.Is(err, link.ErrInvalidHopRoute) {
		t.Fatalf("wrong physical peer: err = %v, want ErrInvalidHopRoute", err)
	}
	assertUntouched(t, entry)
}

// TestGuardSessionReadyIdentity proves a READY is refused unless the envelope
// SessionID, the Path scope and the frozen class/lane/attempt/target-epoch all
// match the local session, before any session state is mutated.
func TestGuardSessionReadyIdentity(t *testing.T) {
	entryID := session.SessionID(guardNode(0x21))
	entry := &sessionEntry{
		id:          entryID,
		scope:       pathScope{id: 7, gen: 1},
		class:       session.SessionClassStream,
		lane:        session.LaneStream,
		attempt:     4,
		targetEpoch: 9,
		ready:       make(chan struct{}),
	}
	rt := &streamRuntime{sessionsByID: map[session.SessionID]*sessionEntry{entryID: entry}}

	ready := session.SessionReady{
		SessionID:      entryID,
		Class:          session.SessionClassStream,
		DataLaneID:     session.LaneStream,
		Attempt:        4,
		TargetEpoch:    9,
		PathID:         7,
		PathGeneration: 1,
	}
	encode := func(t *testing.T, r session.SessionReady) ([]byte, [16]byte, []byte) {
		t.Helper()
		payload, err := r.Encode()
		if err != nil {
			t.Fatalf("encode ready: %v", err)
		}
		env := buildEnvelope(0, guardNode(1), guardNode(2), wire.MessageTypeSessionReady, [16]byte(entryID), 0, 0, 7, 1, len(payload))
		return payload, [16]byte(entryID), env
	}

	// Payload SID disagreeing with the envelope SID.
	wrongSID := ready
	wrongSID.SessionID = session.SessionID(guardNode(0x22))
	payload, _, env := encode(t, wrongSID)
	if err := rt.handleSessionReady(link.ProtectedMessage{Envelope: env, Payload: payload}, 7, 1); !errors.Is(err, link.ErrRouteMessage) {
		t.Fatalf("foreign SID: err = %v, want ErrRouteMessage", err)
	}

	// Wrong attempt.
	wrongAttempt := ready
	wrongAttempt.Attempt = 5
	payload, _, env = encode(t, wrongAttempt)
	if err := rt.handleSessionReady(link.ProtectedMessage{Envelope: env, Payload: payload}, 7, 1); !errors.Is(err, link.ErrRouteMessage) {
		t.Fatalf("wrong attempt: err = %v, want ErrRouteMessage", err)
	}

	// Wrong target epoch.
	wrongEpoch := ready
	wrongEpoch.TargetEpoch = 10
	payload, _, env = encode(t, wrongEpoch)
	if err := rt.handleSessionReady(link.ProtectedMessage{Envelope: env, Payload: payload}, 7, 1); !errors.Is(err, link.ErrRouteMessage) {
		t.Fatalf("wrong target epoch: err = %v, want ErrRouteMessage", err)
	}

	// Wrong Path scope.
	payload, _, env = encode(t, ready)
	if err := rt.handleSessionReady(link.ProtectedMessage{Envelope: env, Payload: payload}, 8, 1); !errors.Is(err, link.ErrRouteMessage) {
		t.Fatalf("wrong scope: err = %v, want ErrRouteMessage", err)
	}

	if entry.isReady() {
		t.Fatal("READY mutated a session that was never verified")
	}
}

// TestGuardSessionCtrlEnvelopeSID proves SESSION_CTRL must name the envelope's
// own session id before the frame can resolve or map any canonical identity.
func TestGuardSessionCtrlEnvelopeSID(t *testing.T) {
	entryID := session.SessionID(guardNode(0x31))
	other := session.SessionID(guardNode(0x32))
	ctrl := session.SessionCtrl{
		SessionID:   other,
		Class:       session.SessionClassStream,
		DataLaneID:  session.LaneStream,
		Attempt:     0,
		TargetEpoch: 3,
		Payload:     []byte{1, 2, 3},
	}
	payload, err := ctrl.Encode()
	if err != nil {
		t.Fatalf("encode ctrl: %v", err)
	}
	env := buildEnvelope(0, guardNode(1), guardNode(2), wire.MessageTypeSessionCtrl, [16]byte(entryID), 0, 0, 7, 1, len(payload))
	rt := &streamRuntime{}
	if err := rt.handleSessionCtrl(&controlPump{lane: laneControl}, link.ProtectedMessage{Envelope: env, Payload: payload}, 7, 1); !errors.Is(err, link.ErrRouteMessage) {
		t.Fatalf("envelope/payload SID mismatch: err = %v, want ErrRouteMessage", err)
	}
}

// TestGuardRelaySessionReadyRequiresPathAuthority proves a relay never commits
// forwarding before the reverse PATH_READY has passed through this hop.
func TestGuardRelaySessionReadyRequiresPathAuthority(t *testing.T) {
	entryID := session.SessionID(guardNode(0x41))
	entry := &sessionEntry{
		id:          entryID,
		scope:       pathScope{id: 8, gen: 1},
		class:       session.SessionClassStream,
		lane:        session.LaneStream,
		attempt:     0,
		targetEpoch: 5,
		relay:       true,
		ready:       make(chan struct{}),
	}
	rt := &streamRuntime{sessionsByID: map[session.SessionID]*sessionEntry{entryID: entry}}
	ps := &pathState{scope: pathScope{id: 8, gen: 1}, relay: true}

	ready := session.SessionReady{
		SessionID:      entryID,
		Class:          session.SessionClassStream,
		DataLaneID:     session.LaneStream,
		Attempt:        0,
		TargetEpoch:    5,
		PathID:         8,
		PathGeneration: 1,
	}
	payload, err := ready.Encode()
	if err != nil {
		t.Fatalf("encode ready: %v", err)
	}
	env := buildEnvelope(0, guardNode(1), guardNode(2), wire.MessageTypeSessionReady, [16]byte(entryID), 0, 0, 8, 1, len(payload))

	if err := rt.observeRelaySessionReady(ps, env, payload); !errors.Is(err, link.ErrRouteMessage) {
		t.Fatalf("READY before reverse PATH_READY: err = %v, want ErrRouteMessage", err)
	}
	if entry.isReady() {
		t.Fatal("relay committed forwarding without path authority")
	}

	ps.relayPending.Store(true)
	if err := rt.observeRelaySessionReady(ps, env, payload); err != nil {
		t.Fatalf("READY after reverse PATH_READY: err = %v", err)
	}
	if !entry.isReady() {
		t.Fatal("relay did not commit a matching READY")
	}
}

// TestGuardRelaySessionCtrlDuplicateIdentity proves a duplicate SESSION_CTRL
// cannot silently re-bind an existing relay session to a different frozen
// identity, while a matching duplicate is admitted unchanged.
func TestGuardRelaySessionCtrlDuplicateIdentity(t *testing.T) {
	entryID := session.SessionID(guardNode(0x51))
	entry := &sessionEntry{
		id:          entryID,
		scope:       pathScope{id: 9, gen: 1},
		class:       session.SessionClassStream,
		lane:        session.LaneStream,
		attempt:     0,
		targetEpoch: 6,
		relay:       true,
		ready:       make(chan struct{}),
	}
	rt := &streamRuntime{sessionsByID: map[session.SessionID]*sessionEntry{entryID: entry}}
	ps := &pathState{
		scope: pathScope{id: 9, gen: 1},
		relay: true,
		nodes: []topology.NodeID{topology.NodeID(guardNode(1)), topology.NodeID(guardNode(2)), topology.NodeID(guardNode(3))},
	}
	ctrl := session.SessionCtrl{
		SessionID:   entryID,
		Class:       session.SessionClassStream,
		DataLaneID:  session.LaneStream,
		Attempt:     0,
		TargetEpoch: 7,
		Payload:     []byte{1, 2, 3},
	}
	payload, err := ctrl.Encode()
	if err != nil {
		t.Fatalf("encode ctrl: %v", err)
	}
	env := buildEnvelope(0, guardNode(1), guardNode(3), wire.MessageTypeSessionCtrl, [16]byte(entryID), 0, 0, 9, 1, len(payload))
	if err := rt.observeRelaySessionCtrl(ps, env, payload); !errors.Is(err, link.ErrRouteMessage) {
		t.Fatalf("duplicate identity mismatch: err = %v, want ErrRouteMessage", err)
	}

	ctrl.TargetEpoch = 6
	payload, err = ctrl.Encode()
	if err != nil {
		t.Fatalf("encode matching ctrl: %v", err)
	}
	env = buildEnvelope(0, guardNode(1), guardNode(3), wire.MessageTypeSessionCtrl, [16]byte(entryID), 0, 0, 9, 1, len(payload))
	if err := rt.observeRelaySessionCtrl(ps, env, payload); err != nil {
		t.Fatalf("matching duplicate: err = %v", err)
	}
}

// TestGuardIngressPeerNoAdjacency proves the physical-hop gate fails closed when
// there is no authenticated Link to inspect.
func TestGuardIngressPeerNoAdjacency(t *testing.T) {
	ps := &pathState{
		nodes:      []topology.NodeID{topology.NodeID(guardNode(1)), topology.NodeID(guardNode(2))},
		localIndex: 1,
	}
	rt := &streamRuntime{}
	if err := rt.checkIngressPeer(ps, &controlPump{}, true, false); !errors.Is(err, link.ErrInvalidHopRoute) {
		t.Fatalf("empty pump: err = %v, want ErrInvalidHopRoute", err)
	}
	if err := rt.checkIngressPeer(ps, nil, false, true); !errors.Is(err, link.ErrInvalidHopRoute) {
		t.Fatalf("nil pump: err = %v, want ErrInvalidHopRoute", err)
	}
}
