package simpletier

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/circuit"
	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/session"
	"github.com/yiiilin/simpletier/internal/topology"
	"github.com/yiiilin/simpletier/internal/wire"
)

// dialControlPumpPeer dials the Network's carrier listener and completes the
// initiator handshake with the given identity, lane and Link tuple, returning
// the raw peer connection, the peer-side protected IO and the negotiated Link
// result. The Network is the responder, exactly as in controlPumpPeer; the
// helper only exists so one authenticated peer identity can open more than one
// lane (a STREAM data lane is refused unless the same peer already has an
// active CONTROL Link).
func dialControlPumpPeer(t *testing.T, n *network, identity security.Identity, lane uint8, linkID uint64, generation uint32) (net.Conn, *link.ProtectedControlIO, link.LinkResult) {
	t.Helper()
	peer, err := net.DialTimeout("tcp", n.carrierListeners[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := link.Handshake(ctx, peer, link.LinkConfig{
		Descriptor: n.networkContext.Descriptor(), NetworkID: n.networkContext.WireID(),
		PSK: n.networkPSK, Identity: identity, Initiator: true,
		LinkID: linkID, LinkEpoch: 1, Generation: generation, LaneID: lane,
		CapabilityVersion: uint16(link.CapabilityVersion), CapabilityMask: link.RequiredCapabilityMask,
		RequiredCapabilityMask: link.RequiredCapabilityMask,
	})
	if err != nil {
		t.Fatal(err)
	}
	control, err := link.NewProtectedControlIO(peer, result, n.networkContext.Descriptor(), true)
	if err != nil {
		t.Fatal(err)
	}
	return peer, control, result
}

func controlPumpPeer(t *testing.T) (*network, net.Conn, *link.ProtectedControlIO, link.LinkResult) {
	t.Helper()
	n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peer, control, result := dialControlPumpPeer(t, n, identity, laneControl, 42, 17)
	waitAdmissionLinks(t, n, 1)
	return n, peer, control, result
}

// closeWriteToleratingPeerClose half-closes the test peer after a deliberately
// truncated record. The pump may already have rejected the record and closed
// its side: an invalid frame kind is rejected after only the length prefix and
// the kind byte, so the server's close arrives while the remaining announced
// body bytes are still unread, which RSTs the loopback connection. The peer's
// shutdown then returns ENOTCONN. That race is expected and says nothing about
// what the subtest asserts, so only genuinely unexpected errors are fatal.
func closeWriteToleratingPeerClose(t *testing.T, tcp *net.TCPConn) {
	t.Helper()
	if err := tcp.CloseWrite(); err != nil &&
		!errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) && !errors.Is(err, syscall.ENOTCONN) {
		t.Fatal(err)
	}
}

func TestControlPumpPeerEOFWithdrawsLink(t *testing.T) {
	n, peer, _, _ := controlPumpPeer(t)
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	waitAdmissionLinks(t, n, 0)
}

func TestControlPumpEncryptedPingPong(t *testing.T) {
	n, peer, control, _ := controlPumpPeer(t)
	skipper := newFactFrameSkipper(n, control)
	if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	probe := bytes.Repeat([]byte{0x5a}, 16)
	if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatal(err)
	}
	got := readSkippingFacts(t, skipper, control)
	if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatalf("authenticated PONG mismatch: type=%d", got.Type)
	}
	// PONG is merely a probe response; Link success is still not a mesh route.
	if _, err := n.DialContext(context.Background(), "tcp", "10.20.0.8:8080"); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("control traffic incorrectly installed a route: %v", err)
	}
}

func TestControlPumpIgnoresUnsolicitedPong(t *testing.T) {
	n, peer, control, _ := controlPumpPeer(t)
	skipper := newFactFrameSkipper(n, control)
	if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// No admission probe is outstanding on this Link, so this PONG must not
	// refresh liveness, create a fact or grant a route.
	if err := control.WriteControl(link.ControlMessage{Type: 2, Payload: bytes.Repeat([]byte{0x44}, 16)}); err != nil {
		t.Fatal(err)
	}
	waitAdmissionLinks(t, n, 1)
	if _, err := n.DialContext(context.Background(), "tcp", "10.20.0.8:8080"); !errors.Is(err, ErrNoRoute) {
		t.Fatal("unsolicited PONG installed a route")
	}
	probe := bytes.Repeat([]byte{0x45}, 16)
	if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatal(err)
	}
	got := readSkippingFacts(t, skipper, control)
	if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatalf("PING/PONG after unsolicited PONG: type=%d", got.Type)
	}
}

// TestInitiatorConfirmationConsumesCounterOneAndKeepsCounting proves the
// admission confirmation reuses the unique post-CAPABILITY protector without
// resetting nonces: CAPABILITY consumed counter 0, the confirmation PING is
// counter 1, and a later exchange continues past it on both directions.
func TestInitiatorConfirmationConsumesCounterOneAndKeepsCounting(t *testing.T) {
	n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	left, right := net.Pipe()
	defer right.Close()
	client, err := NewConnection(left, ConnectionInfo{Type: "host-pipe"})
	if err != nil {
		t.Fatal(err)
	}
	admitted := make(chan error, 1)
	go func() {
		_, err := n.admitConnectionLink(client, true)
		admitted <- err
	}()
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := link.Handshake(ctx, right, link.LinkConfig{
		Descriptor: n.networkContext.Descriptor(), NetworkID: n.networkContext.WireID(),
		PSK: n.networkPSK, Identity: identity, Initiator: false, LaneID: 0,
		CapabilityVersion: uint16(link.CapabilityVersion), CapabilityMask: link.RequiredCapabilityMask,
		RequiredCapabilityMask: link.RequiredCapabilityMask,
	})
	if err != nil {
		t.Fatal(err)
	}
	control, err := link.NewProtectedControlIO(right, result, n.networkContext.Descriptor(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := right.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	skipper := newFactFrameSkipper(n, control)
	confirmation := readSkippingFacts(t, skipper, control)
	if confirmation.Type != 1 || len(confirmation.Payload) != 16 {
		t.Fatalf("confirmation PING: type=%d len=%d", confirmation.Type, len(confirmation.Payload))
	}
	if err := control.WriteControl(link.ControlMessage{Type: 2, Payload: confirmation.Payload}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-admitted:
		if err != nil {
			t.Fatalf("confirmed admission failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("confirmed admission did not finish")
	}
	probe := bytes.Repeat([]byte{0x33}, 16)
	if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatal(err)
	}
	reply := readSkippingFacts(t, skipper, control)
	if reply.Type != 2 || !bytes.Equal(reply.Payload, probe) {
		t.Fatalf("post-confirmation PING/PONG: type=%d", reply.Type)
	}
}

func TestControlPumpAuthenticatedTerminalMessages(t *testing.T) {
	for _, typ := range []uint8{3, 5, 6, 7, 8} {
		t.Run(string(rune('0'+typ)), func(t *testing.T) {
			n, _, control, _ := controlPumpPeer(t)
			payload := []byte{1}
			if typ == 3 {
				payload = []byte{0, 1, 0, 0}
			}
			if typ == 5 {
				payload = make([]byte, 10)
				binary.BigEndian.PutUint64(payload[:8], 1)
			}
			if err := control.WriteControl(link.ControlMessage{Type: typ, Payload: payload}); err != nil {
				t.Fatal(err)
			}
			waitAdmissionLinks(t, n, 0)
		})
	}
}

func TestControlPumpBadTagClosesWithoutAcceptingHighCounter(t *testing.T) {
	n, peer, _, result := controlPumpPeer(t)
	protector, err := link.NewFrameProtector(result.TxRoot, n.networkContext.Descriptor(), result.LinkID, [16]byte{}, link.SessionClassStream, link.DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{1}, bytes.Repeat([]byte{0x1}, 16)...), result.Generation, 100)
	if err != nil {
		t.Fatal(err)
	}
	frame.Body[len(frame.Body)-1] ^= 1
	if err := wire.WriteFrame(peer, frame); err != nil {
		t.Fatal(err)
	}
	waitAdmissionLinks(t, n, 0)
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// The pump may have queued frames before it retired, so drain until the stream
	// ends rather than requiring the very next read to be EOF.
	if err := drainUntilClosed(peer); err != nil {
		t.Fatalf("peer did not observe authenticated Link closure: %v", err)
	}
}

func TestControlPumpBlockedReplyDoesNotBlockReader(t *testing.T) {
	n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	left, right := net.Pipe()
	defer right.Close()
	owned, err := NewConnection(left, ConnectionInfo{Type: "host-pipe"})
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Close()
	admitted := make(chan error, 1)
	go func() { admitted <- n.admitConnection(owned, false) }()
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := link.Handshake(ctx, right, link.LinkConfig{
		Descriptor: n.networkContext.Descriptor(), NetworkID: n.networkContext.WireID(),
		PSK: n.networkPSK, Identity: identity, Initiator: true,
		LinkID: 88, LinkEpoch: 1, Generation: 19, LaneID: 0,
		CapabilityVersion: uint16(link.CapabilityVersion), CapabilityMask: link.RequiredCapabilityMask,
		RequiredCapabilityMask: link.RequiredCapabilityMask,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-admitted; err != nil {
		t.Fatal(err)
	}
	control, err := link.NewProtectedControlIO(right, result, n.networkContext.Descriptor(), true)
	if err != nil {
		t.Fatal(err)
	}
	// net.Pipe has no buffering and this peer deliberately never reads PONG.
	// Its writes still complete only if the protected reader is independent.
	written := make(chan error, 1)
	go func() {
		for range 10 {
			if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: make([]byte, 16)}); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked control reply writer stalled the protected reader")
	}
	if err := n.Close(); err != nil {
		t.Fatal("blocked reply survived Network.Close:", err)
	}
}

func TestControlPumpTargetRetriesAfterPeerClose(t *testing.T) {
	server := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	cfg := validConfig()
	clientURL, _ := freeTCPListenAddress(t)
	cfg.Listen = []string{clientURL}
	cfg.Upstreams = []string{"tcp://" + server.carrierListeners[0].Addr().String()}
	cfg.Network.Token = "0123456789abcdef0123456789abcdef"
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	client := handle.(*network)
	waitAdmissionLinks(t, client, 1)
	waitAdmissionLinks(t, server, 1)
	client.mu.Lock()
	var initial *link.Link
	for _, initial = range client.activeLinks {
	}
	client.mu.Unlock()
	first := initial.Metadata()
	server.mu.Lock()
	var remote *link.Link
	for _, remote = range server.activeLinks {
	}
	server.mu.Unlock()
	if err := remote.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-initial.Done():
	case <-time.After(time.Second):
		t.Fatal("peer EOF did not close the occupied outgoing Link")
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		client.mu.Lock()
		var replacement *link.Link
		for _, active := range client.activeLinks {
			if active != initial {
				replacement = active
			}
		}
		client.mu.Unlock()
		if replacement != nil {
			next := replacement.Metadata()
			if next.LinkID == first.LinkID || next.LinkEpoch <= first.LinkEpoch {
				t.Fatal("retry reused LinkID or did not advance persistent epoch")
			}
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("closed Target was not retried with a fresh Link")
		}
	}
}

func TestControlPumpNetworkCloseInterruptsReader(t *testing.T) {
	n, peer, _, _ := controlPumpPeer(t)
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-n.Done():
	case <-time.After(time.Second):
		t.Fatal("control reader survived Network cleanup")
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Frames already queued before Close are still readable, so drain to the end of
	// the stream: what must hold is that it does end, not that the next read is EOF.
	if err := drainUntilClosed(peer); err != nil {
		t.Fatalf("Network.Close failed to close owned control stream: %v", err)
	}
}

// tagVerificationFailure builds one real hop-AEAD authentication failure from a
// tampered sealed frame, so the classifier is checked against the actual
// tag-verification error rather than a hand-rolled stand-in.
func tagVerificationFailure(t *testing.T) error {
	t.Helper()
	protector, err := link.NewFrameProtector([32]byte{0x11}, []byte("classifier-descriptor"), 9, [16]byte{0x22},
		link.SessionClassStream, link.DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, []byte{1, 2, 3, 4}, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	frame.Body[len(frame.Body)-1] ^= 0x80
	_, err = protector.Verify(frame)
	if err == nil {
		t.Fatal("tampered hop frame verified")
	}
	return err
}

// TestIsFrameLocalSemanticError pins the exact classifier boundary: only a
// stale/expired ROUTE_CTRL/E2E or Session/Path semantic rejection is
// frame-local. Every transport, framing, authentication and LINK_CTRL failure
// stays fatal, most importantly a real hop tag failure.
func TestIsFrameLocalSemanticError(t *testing.T) {
	tagFailure := tagVerificationFailure(t)
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"route message", link.ErrRouteMessage, true},
		{"wrapped route message", fmt.Errorf("local ROUTE frame failed: %w", link.ErrRouteMessage), true},
		{"invalid hop route", link.ErrInvalidHopRoute, true},
		{"wrapped invalid hop route", fmt.Errorf("local ROUTE frame failed: %w", link.ErrInvalidHopRoute), true},
		{"session not admitted", link.ErrSessionNotAdmitted, true},
		{"end to end message", link.ErrEndToEndMessage, true},
		{"wrapped end to end message", fmt.Errorf("local E2E frame failed: %w", link.ErrEndToEndMessage), true},
		{"stale session id", session.ErrStaleSessionID, true},
		{"stale attempt", session.ErrStaleAttempt, true},
		{"future attempt", session.ErrFutureAttempt, true},
		{"stale epoch", session.ErrStaleEpoch, true},
		{"future epoch", session.ErrFutureEpoch, true},
		{"session not found", session.ErrSessionNotFound, true},
		{"session timeout", session.ErrSessionTimeout, true},
		{"session aborted", session.ErrSessionAborted, true},
		{"wrapped stale session id", fmt.Errorf("SESSION_CTRL not committed: %w", session.ErrStaleSessionID), true},
		{"joined stale identity", errors.Join(session.ErrStaleSessionID, session.ErrStaleEpoch), true},
		{"session ref failed", circuit.ErrSessionRefFailed, true},
		{"wrapped session ref failed", fmt.Errorf("CIRCUIT_OPEN %s is terminal: %w", "dead-ref", circuit.ErrSessionRefFailed), true},
		// The narrow refusal is documented to wrap both sentinels; errors.Is on
		// the narrow one classifies it even though the broad one is fatal.
		{"session ref failed wrapping session lost", fmt.Errorf("%w: %w", circuit.ErrSessionLost, circuit.ErrSessionRefFailed), true},
		// A bounded Circuit resource refusal is Circuit/Session-scoped. This is
		// the exact production shape: chargeEgressControlRPC returns
		// fmt.Errorf("%w: %v", circuit.ErrResource, err) and circuitAdapter.Send
		// wraps it as fmt.Errorf("%w: %w", circuit.ErrSessionLost, err).
		{"circuit resource", circuit.ErrResource, true},
		{"wrapped circuit resource", fmt.Errorf("CONTROL_RPC egress control budget exhausted: %w", circuit.ErrResource), true},
		{"production chain resource refusal", fmt.Errorf("%w: %w", circuit.ErrSessionLost,
			fmt.Errorf("%w: %v", circuit.ErrResource, errors.New("control budget exhausted"))), true},
		// Fatal framing / control semantics / authentication / transport classes.
		{"control message", link.ErrControlMessage, false},
		{"control message wrapping unexpected kind", fmt.Errorf("%w: kind 0x00: %w", link.ErrControlMessage, link.ErrUnexpectedKind), false},
		{"unexpected kind", link.ErrUnexpectedKind, false},
		{"replay", link.ErrReplay, false},
		{"counter exhausted", link.ErrCounterExhausted, false},
		{"session retired", link.ErrSessionRetired, false},
		{"real hop tag failure", tagFailure, false},
		{"link down", ErrLinkDown, false},
		{"resource", ErrResource, false},
		{"closed", ErrClosed, false},
		{"unsupported control", errUnsupportedControl, false},
		{"io eof", io.EOF, false},
		// Circuit and Session failures that are not scoped drops. Bare
		// ErrSessionLost is deliberately NOT classified: Manager.submit wraps an
		// arbitrary Egress.Send failure in it, so it can carry a genuine Link or
		// write failure.
		{"circuit session lost", circuit.ErrSessionLost, false},
		{"circuit session lost wrapping link down", fmt.Errorf("%w: %w", circuit.ErrSessionLost, ErrLinkDown), false},
		{"circuit session lost wrapping package resource", fmt.Errorf("%w: %w", circuit.ErrSessionLost, ErrResource), false},
		{"circuit unsupported control", circuit.ErrUnsupportedControl, false},
		{"circuit malformed message", circuit.ErrMalformedMessage, false},
		{"malformed session control", session.ErrMalformedMessage, false},
		{"attempt conflict", session.ErrAttemptConflict, false},
		{"invalid class", session.ErrInvalidClass, false},
		{"session id mismatch", session.ErrSessionIDMismatch, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFrameLocalSemanticError(tc.err); got != tc.want {
				t.Fatalf("isFrameLocalSemanticError(%v) = %v; want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestFrameLocalSemanticClassLabels pins the traced label to a compile-time
// class name and proves the raw handler error text is never surfaced: even a
// wrapped error carrying a frame-derived detail yields only the stable label.
func TestFrameLocalSemanticClassLabels(t *testing.T) {
	const secret = "session-deadbeef-path-7-1"
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"route message", link.ErrRouteMessage, "route-message"},
		{"wrapped route message", fmt.Errorf("SESSION_CTRL %s: %w", secret, link.ErrRouteMessage), "route-message"},
		{"invalid hop route", link.ErrInvalidHopRoute, "invalid-hop-route"},
		{"session not admitted", link.ErrSessionNotAdmitted, "session-not-admitted"},
		{"end to end message", link.ErrEndToEndMessage, "end-to-end-message"},
		{"stale session id", session.ErrStaleSessionID, "stale-session-id"},
		{"stale attempt", session.ErrStaleAttempt, "stale-attempt"},
		{"future attempt", session.ErrFutureAttempt, "future-attempt"},
		{"stale epoch", session.ErrStaleEpoch, "stale-epoch"},
		{"future epoch", session.ErrFutureEpoch, "future-epoch"},
		{"session not found", session.ErrSessionNotFound, "session-not-found"},
		{"session timeout", session.ErrSessionTimeout, "session-timeout"},
		{"session aborted", session.ErrSessionAborted, "session-aborted"},
		{"session ref failed", circuit.ErrSessionRefFailed, "session-ref-failed"},
		{"wrapped session ref failed", fmt.Errorf("CIRCUIT_OPEN %s: %w", secret, circuit.ErrSessionRefFailed), "session-ref-failed"},
		{"circuit resource", circuit.ErrResource, "circuit-resource"},
		{"wrapped circuit resource", fmt.Errorf("CONTROL_RPC %s: %w", secret, circuit.ErrResource), "circuit-resource"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, ok := frameLocalSemanticClassOf(tc.err)
			if !ok {
				t.Fatalf("frameLocalSemanticClassOf(%v) not classified", tc.err)
			}
			if class != tc.want {
				t.Fatalf("class = %q; want %q", class, tc.want)
			}
			if strings.Contains(class, secret) {
				t.Fatalf("class %q leaked the raw handler detail", class)
			}
		})
	}
	// A fatal, unclassified error must not gain a label.
	if class, ok := frameLocalSemanticClassOf(nil); ok || class != "" {
		t.Fatalf("nil class = %q, %v; want empty, false", class, ok)
	}
	if class, ok := frameLocalSemanticClassOf(ErrResource); ok || class != "" {
		t.Fatalf("resource class = %q, %v; want empty, false", class, ok)
	}
}

// TestReadMessageFrameLocalClass pins the replay-origin ReadMessage classifier
// boundary: only a ReplaySuspected record is frame-local here. Malformed,
// unauthenticated, truncated, I/O and counter-exhaustion failures stay
// Link-fatal, and the unadmitted-E2E class needs the frame Kind, so it is not
// this classifier's business (pinned by
// TestReadMessageEndToEndSessionNotAdmittedClass).
func TestReadMessageFrameLocalClass(t *testing.T) {
	tagFailure := tagVerificationFailure(t)
	cases := []struct {
		name string
		err  error
		want string
		ok   bool
	}{
		{"nil", nil, "", false},
		{"replay", link.ErrReplay, "replay-suspected", true},
		{"wrapped replay", fmt.Errorf("control counter 4 is not above 9: %w", link.ErrReplay), "replay-suspected", true},
		{"counter exhausted", link.ErrCounterExhausted, "", false},
		{"joined replay and counter exhausted", errors.Join(link.ErrReplay, link.ErrCounterExhausted), "", false},
		{"real hop tag failure", tagFailure, "", false},
		{"control message", link.ErrControlMessage, "", false},
		{"unexpected kind", link.ErrUnexpectedKind, "", false},
		{"malformed frame", wire.ErrFrameMalformed, "", false},
		{"truncated record", io.ErrUnexpectedEOF, "", false},
		{"io eof", io.EOF, "", false},
		{"link down", ErrLinkDown, "", false},
		// The sentinel that the kind-guarded E2E predicate owns is not absorbed
		// into the replay classifier, so the two origins stay separately pinned.
		{"session not admitted", link.ErrSessionNotAdmitted, "", false},
		{"session retired", link.ErrSessionRetired, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, ok := readMessageFrameLocalClass(tc.err)
			if ok != tc.ok || class != tc.want {
				t.Fatalf("readMessageFrameLocalClass(%v) = (%q, %v); want (%q, %v)", tc.err, class, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestReadMessageEndToEndSessionNotAdmittedClass pins the new ReadMessage-origin
// classifier boundary. Only a fully read E2E frame whose SessionID is not
// admitted on this Link is frame-local; the identical sentinel with any other
// Kind, the same sentinel from the consumeFrame origin, and every other
// ReadMessage failure keep their existing disposition.
func TestReadMessageEndToEndSessionNotAdmittedClass(t *testing.T) {
	tagFailure := tagVerificationFailure(t)
	const secret = "session-deadbeef-is-not-admitted"
	e2e := link.ProtectedMessage{Kind: wire.FrameKindEndToEnd}
	cases := []struct {
		name    string
		message link.ProtectedMessage
		err     error
		want    string
		ok      bool
	}{
		{"nil error", e2e, nil, "", false},
		{"e2e unadmitted", e2e, link.ErrSessionNotAdmitted, readMessageSessionNotAdmittedClass, true},
		{"e2e wrapped unadmitted", e2e,
			fmt.Errorf("end-to-end %s: %w", secret, link.ErrSessionNotAdmitted),
			readMessageSessionNotAdmittedClass, true},
		// The same sentinel with any other Kind is a different origin.
		{"route kind unadmitted", link.ProtectedMessage{Kind: wire.FrameKindRouteControl}, link.ErrSessionNotAdmitted, "", false},
		{"link-control kind unadmitted", link.ProtectedMessage{Kind: wire.FrameKindLinkControl}, link.ErrSessionNotAdmitted, "", false},
		{"unknown kind unadmitted", link.ProtectedMessage{}, link.ErrSessionNotAdmitted, "", false},
		// A different sentinel on an E2E frame stays outside THIS predicate: the
		// retired-SessionID rejection is frame-local at the Link layer too, but
		// it is owned by its own kind-guarded predicate
		// (readMessageSessionRetiredClassOf), not by the unadmitted one.
		{"e2e retired", e2e, link.ErrSessionRetired, "", false},
		{"e2e replay", e2e, link.ErrReplay, "", false},
		{"e2e end-to-end message", e2e, link.ErrEndToEndMessage, "", false},
		{"e2e route message", e2e, link.ErrRouteMessage, "", false},
		{"e2e unexpected kind", e2e, link.ErrUnexpectedKind, "", false},
		{"e2e control message", e2e, link.ErrControlMessage, "", false},
		{"e2e counter exhausted", e2e, link.ErrCounterExhausted, "", false},
		{"e2e joined unadmitted and counter exhausted", e2e,
			errors.Join(link.ErrSessionNotAdmitted, link.ErrCounterExhausted), "", false},
		{"e2e real hop tag failure", e2e, tagFailure, "", false},
		{"e2e malformed frame", e2e, wire.ErrFrameMalformed, "", false},
		{"e2e truncated record", e2e, io.ErrUnexpectedEOF, "", false},
		{"e2e io eof", e2e, io.EOF, "", false},
		{"e2e link down", e2e, ErrLinkDown, "", false},
		{"e2e resource", e2e, ErrResource, "", false},
		{"e2e closed", e2e, ErrClosed, "", false},
		{"e2e session lost", e2e, circuit.ErrSessionLost, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, ok := readMessageEndToEndSessionNotAdmittedClass(tc.message, tc.err)
			if ok != tc.ok || class != tc.want {
				t.Fatalf("readMessageEndToEndSessionNotAdmittedClass(%+v, %v) = (%q, %v); want (%q, %v)",
					tc.message, tc.err, class, ok, tc.want, tc.ok)
			}
			if strings.Contains(class, secret) {
				t.Fatalf("class %q leaked the raw handler detail", class)
			}
		})
	}
	// The consumeFrame origin keeps its existing disposition: the same sentinel
	// is already frame-local through the existing table, and the new
	// ReadMessage-origin predicate neither replaces nor widens that.
	if class, ok := frameLocalSemanticClassOf(link.ErrSessionNotAdmitted); !ok || class != readMessageSessionNotAdmittedClass {
		t.Fatalf("consumeFrame-origin ErrSessionNotAdmitted = (%q, %v); want (%q, true)",
			class, ok, readMessageSessionNotAdmittedClass)
	}
	if _, ok := readMessageEndToEndSessionNotAdmittedClass(e2e, link.ErrSessionNotAdmitted); !ok {
		t.Fatal("the E2E unadmitted sentinel lost its frame-local class")
	}
}

// TestReadMessageRouteMessageClass pins the ReadMessage-origin ROUTE_CTRL
// classifier boundary. Only a fully read ROUTE_CTRL frame rejected by the frozen
// envelope/reserved-value/redundant-hop-header/bootstrap-length rules is
// frame-local; the identical sentinel with any other Kind and every other
// ReadMessage failure stay terminal, and the ErrCounterExhausted guard forces
// the fatal path in the joined form.
func TestReadMessageRouteMessageClass(t *testing.T) {
	tagFailure := tagVerificationFailure(t)
	const secret = "route-hop-path-deadbeef-is-malformed"
	route := link.ProtectedMessage{Kind: wire.FrameKindRouteControl}
	e2e := link.ProtectedMessage{Kind: wire.FrameKindEndToEnd}
	linkControl := link.ProtectedMessage{Kind: wire.FrameKindLinkControl}
	unknown := link.ProtectedMessage{}
	cases := []struct {
		name    string
		message link.ProtectedMessage
		err     error
		want    string
		ok      bool
	}{
		{"nil error", route, nil, "", false},
		{"route message", route, link.ErrRouteMessage, readMessageRouteMessageClass, true},
		{"route wrapped message", route,
			fmt.Errorf("ROUTE_CTRL %s: %w", secret, link.ErrRouteMessage),
			readMessageRouteMessageClass, true},
		// The same sentinel with any other Kind is a different origin.
		{"e2e kind route message", e2e, link.ErrRouteMessage, "", false},
		{"link-control kind route message", linkControl, link.ErrRouteMessage, "", false},
		{"unknown kind route message", unknown, link.ErrRouteMessage, "", false},
		// A different sentinel on a ROUTE_CTRL frame stays outside THIS
		// predicate; the other ReadMessage-origin classes are owned by their own
		// kind-guarded predicates.
		{"route unadmitted", route, link.ErrSessionNotAdmitted, "", false},
		{"route retired", route, link.ErrSessionRetired, "", false},
		{"route end-to-end message", route, link.ErrEndToEndMessage, "", false},
		{"route replay", route, link.ErrReplay, "", false},
		{"route unexpected kind", route, link.ErrUnexpectedKind, "", false},
		{"route control message", route, link.ErrControlMessage, "", false},
		{"route counter exhausted", route, link.ErrCounterExhausted, "", false},
		{"route joined route message and counter exhausted", route,
			errors.Join(link.ErrRouteMessage, link.ErrCounterExhausted), "", false},
		{"route real hop tag failure", route, tagFailure, "", false},
		{"route malformed frame", route, wire.ErrFrameMalformed, "", false},
		{"route truncated record", route, io.ErrUnexpectedEOF, "", false},
		{"route io eof", route, io.EOF, "", false},
		{"route link down", route, ErrLinkDown, "", false},
		{"route resource", route, ErrResource, "", false},
		{"route closed", route, ErrClosed, "", false},
		{"route session lost", route, circuit.ErrSessionLost, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, ok := readMessageRouteMessageClassOf(tc.message, tc.err)
			if ok != tc.ok || class != tc.want {
				t.Fatalf("readMessageRouteMessageClassOf(%+v, %v) = (%q, %v); want (%q, %v)",
					tc.message, tc.err, class, ok, tc.want, tc.ok)
			}
			if strings.Contains(class, secret) {
				t.Fatalf("class %q leaked the raw handler detail", class)
			}
		})
	}
	// The consumeFrame-origin table keeps classifying the same sentinel under the
	// same stable name, and the ReadMessage-origin predicate neither replaces nor
	// widens that.
	if class, ok := frameLocalSemanticClassOf(link.ErrRouteMessage); !ok || class != readMessageRouteMessageClass {
		t.Fatalf("consumeFrame-origin ErrRouteMessage = (%q, %v); want (%q, true)",
			class, ok, readMessageRouteMessageClass)
	}
}

// TestReadMessageEndToEndMessageClass pins the ReadMessage-origin E2E structural
// classifier boundary. Only a fully read E2E frame rejected by the frozen
// envelope/hop-header redundancy or session-class/MessageType binding is
// frame-local; the identical sentinel with any other Kind, the retired-Session
// and unadmitted sentinels, the replay class and every other ReadMessage failure
// stay terminal, and the ErrCounterExhausted guard forces the fatal path in the
// joined form that decodeEndToEndEnvelope actually produces.
func TestReadMessageEndToEndMessageClass(t *testing.T) {
	tagFailure := tagVerificationFailure(t)
	const secret = "e2e-envelope-inner-len-deadbeef"
	e2e := link.ProtectedMessage{Kind: wire.FrameKindEndToEnd}
	route := link.ProtectedMessage{Kind: wire.FrameKindRouteControl}
	linkControl := link.ProtectedMessage{Kind: wire.FrameKindLinkControl}
	unknown := link.ProtectedMessage{}
	cases := []struct {
		name    string
		message link.ProtectedMessage
		err     error
		want    string
		ok      bool
	}{
		{"nil error", e2e, nil, "", false},
		{"e2e end-to-end message", e2e, link.ErrEndToEndMessage, readMessageEndToEndMessageClass, true},
		{"e2e wrapped end-to-end message", e2e,
			fmt.Errorf("end-to-end envelope %s: %w", secret, link.ErrEndToEndMessage),
			readMessageEndToEndMessageClass, true},
		// The same sentinel with any other Kind is a different origin.
		{"route kind end-to-end message", route, link.ErrEndToEndMessage, "", false},
		{"link-control kind end-to-end message", linkControl, link.ErrEndToEndMessage, "", false},
		{"unknown kind end-to-end message", unknown, link.ErrEndToEndMessage, "", false},
		// The other ReadMessage-origin E2E classes stay outside THIS predicate so
		// the three E2E origins remain separately pinned.
		{"e2e retired", e2e, link.ErrSessionRetired, "", false},
		{"e2e unadmitted", e2e, link.ErrSessionNotAdmitted, "", false},
		{"e2e replay", e2e, link.ErrReplay, "", false},
		{"e2e route message", e2e, link.ErrRouteMessage, "", false},
		{"e2e unexpected kind", e2e, link.ErrUnexpectedKind, "", false},
		{"e2e control message", e2e, link.ErrControlMessage, "", false},
		{"e2e counter exhausted", e2e, link.ErrCounterExhausted, "", false},
		// The exact production shape: decodeEndToEndEnvelope returns
		// errors.Join(ErrEndToEndMessage, ErrCounterExhausted) for a frame whose
		// message number is ^uint64(0). Without the counter-exhaustion guard this
		// would be classified frame-local and the Link would survive.
		{"e2e joined end-to-end message and counter exhausted", e2e,
			errors.Join(link.ErrEndToEndMessage, link.ErrCounterExhausted), "", false},
		{"e2e real hop tag failure", e2e, tagFailure, "", false},
		{"e2e malformed frame", e2e, wire.ErrFrameMalformed, "", false},
		{"e2e truncated record", e2e, io.ErrUnexpectedEOF, "", false},
		{"e2e io eof", e2e, io.EOF, "", false},
		{"e2e link down", e2e, ErrLinkDown, "", false},
		{"e2e resource", e2e, ErrResource, "", false},
		{"e2e closed", e2e, ErrClosed, "", false},
		{"e2e session lost", e2e, circuit.ErrSessionLost, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, ok := readMessageEndToEndMessageClassOf(tc.message, tc.err)
			if ok != tc.ok || class != tc.want {
				t.Fatalf("readMessageEndToEndMessageClassOf(%+v, %v) = (%q, %v); want (%q, %v)",
					tc.message, tc.err, class, ok, tc.want, tc.ok)
			}
			if strings.Contains(class, secret) {
				t.Fatalf("class %q leaked the raw handler detail", class)
			}
		})
	}
	// The consumeFrame-origin table keeps classifying the same sentinel under the
	// same stable name, and the ReadMessage-origin predicate neither replaces nor
	// widens that.
	if class, ok := frameLocalSemanticClassOf(link.ErrEndToEndMessage); !ok || class != readMessageEndToEndMessageClass {
		t.Fatalf("consumeFrame-origin ErrEndToEndMessage = (%q, %v); want (%q, true)",
			class, ok, readMessageEndToEndMessageClass)
	}
	// The two E2E predicates must not absorb each other's sentinel, and neither
	// may absorb the unadmitted or replay class: those origins stay separately
	// pinned.
	if _, ok := readMessageEndToEndMessageClassOf(e2e, link.ErrSessionRetired); ok {
		t.Fatal("the E2E message predicate absorbed the retired-Session class")
	}
	if _, ok := readMessageEndToEndMessageClassOf(e2e, link.ErrSessionNotAdmitted); ok {
		t.Fatal("the E2E message predicate absorbed the unadmitted class")
	}
	if _, ok := readMessageEndToEndMessageClassOf(e2e, link.ErrReplay); ok {
		t.Fatal("the E2E message predicate absorbed the replay class")
	}
	// RED counterfactual for the ErrCounterExhausted guard, shown against the
	// exact production input rather than by deleting the guard (that guard lives
	// in control_pump.go, which this task must not modify). Without the guard the
	// joined value decodeEndToEndEnvelope returns for messageNumber == ^uint64(0)
	// matches the predicate's two other conditions, so the frame would be dropped
	// frame-locally and the boundary subtest's Link would survive instead of
	// closing. The production predicate must reject it.
	unguarded := func(message link.ProtectedMessage, err error) bool {
		return err != nil && message.Kind == wire.FrameKindEndToEnd && errors.Is(err, link.ErrEndToEndMessage)
	}
	joinedCounterExhaustion := errors.Join(link.ErrEndToEndMessage, link.ErrCounterExhausted)
	if !unguarded(e2e, joinedCounterExhaustion) {
		t.Fatal("counterfactual did not reproduce the guard's trigger")
	}
	if _, ok := readMessageEndToEndMessageClassOf(e2e, joinedCounterExhaustion); ok {
		t.Fatal("the ErrCounterExhausted guard did not force the fatal path")
	}
}

// TestReadMessageSessionRetiredClass pins the last ReadMessage-origin E2E
// classifier boundary. Only a fully read E2E frame naming a SessionID this Link
// retired is frame-local; the identical sentinel with any other Kind, the
// end-to-end-message and unadmitted sentinels, the replay class and every other
// ReadMessage failure stay terminal, and the ErrCounterExhausted guard forces
// the fatal path.
func TestReadMessageSessionRetiredClass(t *testing.T) {
	tagFailure := tagVerificationFailure(t)
	const secret = "retired-session-deadbeef-tombstone"
	e2e := link.ProtectedMessage{Kind: wire.FrameKindEndToEnd}
	route := link.ProtectedMessage{Kind: wire.FrameKindRouteControl}
	linkControl := link.ProtectedMessage{Kind: wire.FrameKindLinkControl}
	unknown := link.ProtectedMessage{}
	cases := []struct {
		name    string
		message link.ProtectedMessage
		err     error
		want    string
		ok      bool
	}{
		{"nil error", e2e, nil, "", false},
		{"e2e retired", e2e, link.ErrSessionRetired, readMessageSessionRetiredClass, true},
		{"e2e wrapped retired", e2e,
			fmt.Errorf("withSession %s: %w", secret, link.ErrSessionRetired),
			readMessageSessionRetiredClass, true},
		// The same sentinel with any other Kind is a different origin.
		{"route kind retired", route, link.ErrSessionRetired, "", false},
		{"link-control kind retired", linkControl, link.ErrSessionRetired, "", false},
		{"unknown kind retired", unknown, link.ErrSessionRetired, "", false},
		// The other ReadMessage-origin E2E classes stay outside THIS predicate so
		// the three E2E origins remain separately pinned.
		{"e2e end-to-end message", e2e, link.ErrEndToEndMessage, "", false},
		{"e2e unadmitted", e2e, link.ErrSessionNotAdmitted, "", false},
		{"e2e replay", e2e, link.ErrReplay, "", false},
		{"e2e route message", e2e, link.ErrRouteMessage, "", false},
		{"e2e unexpected kind", e2e, link.ErrUnexpectedKind, "", false},
		{"e2e control message", e2e, link.ErrControlMessage, "", false},
		{"e2e counter exhausted", e2e, link.ErrCounterExhausted, "", false},
		{"e2e joined retired and counter exhausted", e2e,
			errors.Join(link.ErrSessionRetired, link.ErrCounterExhausted), "", false},
		{"e2e real hop tag failure", e2e, tagFailure, "", false},
		{"e2e malformed frame", e2e, wire.ErrFrameMalformed, "", false},
		{"e2e truncated record", e2e, io.ErrUnexpectedEOF, "", false},
		{"e2e io eof", e2e, io.EOF, "", false},
		{"e2e link down", e2e, ErrLinkDown, "", false},
		{"e2e resource", e2e, ErrResource, "", false},
		{"e2e closed", e2e, ErrClosed, "", false},
		{"e2e session lost", e2e, circuit.ErrSessionLost, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, ok := readMessageSessionRetiredClassOf(tc.message, tc.err)
			if ok != tc.ok || class != tc.want {
				t.Fatalf("readMessageSessionRetiredClassOf(%+v, %v) = (%q, %v); want (%q, %v)",
					tc.message, tc.err, class, ok, tc.want, tc.ok)
			}
			if strings.Contains(class, secret) {
				t.Fatalf("class %q leaked the raw handler detail", class)
			}
		})
	}
	// The retired origin is deliberately NOT in the consumeFrame-origin table:
	// the identical sentinel from AdmitSession or the outbound WriteEndToEnd must
	// stay terminal, so only the ReadMessage-origin kind-guarded predicate above
	// may classify it.
	if class, ok := frameLocalSemanticClassOf(link.ErrSessionRetired); ok || class != "" {
		t.Fatalf("consumeFrame-origin ErrSessionRetired = (%q, %v); want empty, false", class, ok)
	}
	// The two E2E predicates must not absorb each other's sentinel, and neither
	// may absorb the unadmitted or replay class.
	if _, ok := readMessageSessionRetiredClassOf(e2e, link.ErrEndToEndMessage); ok {
		t.Fatal("the retired-Session predicate absorbed the E2E message class")
	}
	if _, ok := readMessageSessionRetiredClassOf(e2e, link.ErrSessionNotAdmitted); ok {
		t.Fatal("the retired-Session predicate absorbed the unadmitted class")
	}
	if _, ok := readMessageSessionRetiredClassOf(e2e, link.ErrReplay); ok {
		t.Fatal("the retired-Session predicate absorbed the replay class")
	}
}

// TestControlPumpReplaySuspectedKeepsLinkServing proves the frozen replay rule:
// a duplicate control frame (same nonce, identical ciphertext) read below the
// committed floor is dropped and counted exactly once, and the same physical
// Link keeps reading and answering fresh frames afterwards. Replaying the exact
// sealed bytes never reuses a nonce for a different plaintext.
func TestControlPumpReplaySuspectedKeepsLinkServing(t *testing.T) {
	// This test needs the exact bytes a frame occupied on the wire, so it dials its
	// own connection and wraps it rather than using controlPumpPeer. The wrapper is
	// local to this test: other tests assert on *net.TCPConn, which a wrapper would
	// break.
	n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.DialTimeout("tcp", n.carrierListeners[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	tee := newTeeConn(raw)
	peer := net.Conn(tee)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := link.Handshake(ctx, peer, link.LinkConfig{
		Descriptor: n.networkContext.Descriptor(), NetworkID: n.networkContext.WireID(),
		PSK: n.networkPSK, Identity: identity, Initiator: true,
		LinkID: 42, LinkEpoch: 1, Generation: 17, LaneID: laneControl,
		CapabilityVersion: uint16(link.CapabilityVersion), CapabilityMask: link.RequiredCapabilityMask,
		RequiredCapabilityMask: link.RequiredCapabilityMask,
	})
	if err != nil {
		t.Fatal(err)
	}
	control, err := link.NewProtectedControlIO(peer, result, n.networkContext.Descriptor(), true)
	if err != nil {
		t.Fatal(err)
	}
	waitAdmissionLinks(t, n, 1)

	skipper := newFactFrameSkipper(n, control)
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	expectPong := func(probe [16]byte, what string) {
		t.Helper()
		got := readSkippingFacts(t, skipper, control)
		if got.Type != 2 || !bytes.Equal(got.Payload, probe[:]) {
			t.Fatalf("%s PING/PONG mismatch: type=%d", what, got.Type)
		}
	}

	// Send the frame through ProtectedControlIO so its counter is allocated exactly
	// as production allocates it, and capture the bytes it occupied on the wire. A
	// hand-sealed frame with a chosen counter would collide with the counters this
	// same Link allocates for FACT traffic.
	tee.take() // drop anything buffered before this point
	var probe1 [16]byte
	for i := range probe1 {
		probe1[i] = 0x61
	}
	if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe1[:]}); err != nil {
		t.Fatal(err)
	}
	frame1 := append([]byte(nil), tee.take()...)
	if len(frame1) == 0 {
		t.Fatal("captured no bytes for the first PING")
	}
	expectPong(probe1, "first")

	before := n.rates.stats().FrameLocalRejected

	// Byte-identical replay: the receiver's floor now covers this counter, so
	// ReadMessage returns ErrReplay before any AEAD work.
	if _, err := peer.Write(frame1); err != nil {
		t.Fatal(err)
	}
	var probe2 [16]byte
	for i := range probe2 {
		probe2[i] = 0x62
	}
	if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe2[:]}); err != nil {
		t.Fatal(err)
	}
	// A fresh higher-counter PING still being answered proves both the Link
	// survival and that the replayed frame stayed fully framed and consumed.
	expectPong(probe2, "post-replay")
	if after := n.rates.stats().FrameLocalRejected; after != before+1 {
		t.Fatalf("FrameLocalRejected = %d after one replayed frame; want %d", after, before+1)
	}
	waitAdmissionLinks(t, n, 1)

	// One more replay is one more counted violation, never a double count.
	if _, err := peer.Write(frame1); err != nil {
		t.Fatal(err)
	}
	var probe3 [16]byte
	for i := range probe3 {
		probe3[i] = 0x63
	}
	if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe3[:]}); err != nil {
		t.Fatal(err)
	}
	expectPong(probe3, "second post-replay")
	if after := n.rates.stats().FrameLocalRejected; after != before+2 {
		t.Fatalf("FrameLocalRejected = %d after two replayed frames; want %d", after, before+2)
	}
	waitAdmissionLinks(t, n, 1)
}

// staleSessionCtrlFrame builds one validly sealed SESSION_CTRL bootstrap whose
// Path scope (7/1) is never installed on the reading node. Its hop AEAD is a
// real seal of the authenticated peer, so only its semantic staleness makes it
// frame-local: handleSessionCtrl rejects it with link.ErrRouteMessage.
func staleSessionCtrlFrame(t *testing.T, rt *streamRuntime) (envelope, payload []byte) {
	t.Helper()
	sessionID := [16]byte{0x51, 0x54, 0x41, 0x4c, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	ctrl := session.SessionCtrl{
		SessionID:   session.SessionID(sessionID),
		Class:       session.SessionClassStream,
		DataLaneID:  session.LaneStream,
		Attempt:     0,
		TargetEpoch: 1,
		Payload:     bytes.Repeat([]byte{0x6e}, 32),
	}
	payload, err := ctrl.Encode()
	if err != nil {
		t.Fatal(err)
	}
	src := [16]byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
	envelope = buildEnvelope(rt.wireID, src, rt.localID, wire.MessageTypeSessionCtrl, sessionID, 0, 0, 7, 1, len(payload))
	return envelope, payload
}

// TestControlPumpStaleSessionCtrlKeepsLinkServing proves a cryptographically
// valid but semantically stale SESSION_CTRL (a Path scope this node does not
// own) drops only that frame: the same pump still reads and answers a later
// valid PING, and the physical Link stays admitted.
func TestControlPumpStaleSessionCtrlKeepsLinkServing(t *testing.T) {
	n, peer, control, _ := controlPumpPeer(t)
	skipper := newFactFrameSkipper(n, control)
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rt := n.streams
	envelope, payload := staleSessionCtrlFrame(t, rt)

	// The exact frame bytes are frame-local ErrRouteMessage at the runtime
	// handler, and the classifier accepts exactly that error. This bridges the
	// real wire injection below to the read() decision without a race.
	if err := rt.handleRouteFrame(&controlPump{lane: laneControl}, link.ProtectedMessage{Envelope: envelope, Payload: payload}); !errors.Is(err, link.ErrRouteMessage) {
		t.Fatalf("stale SESSION_CTRL handler error = %v; want ErrRouteMessage", err)
	} else if !isFrameLocalSemanticError(err) {
		t.Fatalf("stale SESSION_CTRL error %v is not classified frame-local", err)
	}

	before := n.rates.stats().FrameLocalRejected
	if err := control.WriteRoute(envelope, payload, link.HopRoute{Cursor: 0, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	// TCP order guarantees the pump consumed the stale ROUTE_CTRL frame before
	// this PING; the matching PONG proves the reader survived it.
	probe := bytes.Repeat([]byte{0x5a}, 16)
	if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatal(err)
	}
	got := readSkippingFacts(t, skipper, control)
	if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatalf("post-stale-frame PING/PONG mismatch: type=%d", got.Type)
	}
	// The frozen attribution rule requires the pre-E2E-auth semantic drop to be
	// counted exactly once. The direct handler call above bypassed read(), so
	// only the wire-injected stale frame is charged.
	if after := n.rates.stats().FrameLocalRejected; after != before+1 {
		t.Fatalf("FrameLocalRejected = %d after one stale frame; want %d", after, before+1)
	}
	waitAdmissionLinks(t, n, 1)
}

// TestControlPumpTamperedTagAfterRecoverableFrameStillClosesLink is the
// boundary: after the pump proved it recovered from a stale frame by answering
// a PING, a tampered hop tag still retires the physical Link. A bad AEAD tag is
// never classified recoverable.
func TestControlPumpTamperedTagAfterRecoverableFrameStillClosesLink(t *testing.T) {
	n, peer, control, result := controlPumpPeer(t)
	skipper := newFactFrameSkipper(n, control)
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	envelope, payload := staleSessionCtrlFrame(t, n.streams)
	before := n.rates.stats().FrameLocalRejected
	if err := control.WriteRoute(envelope, payload, link.HopRoute{Cursor: 0, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	probe := bytes.Repeat([]byte{0x5b}, 16)
	if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatal(err)
	}
	got := readSkippingFacts(t, skipper, control)
	if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatalf("recovery PING/PONG mismatch: type=%d", got.Type)
	}
	if after := n.rates.stats().FrameLocalRejected; after != before+1 {
		t.Fatalf("FrameLocalRejected = %d after one stale frame; want %d", after, before+1)
	}
	waitAdmissionLinks(t, n, 1)

	// Seal a genuine control frame and tamper its hop tag: the pump must fail
	// closed rather than classify an authentication failure as frame-local.
	protector, err := link.NewFrameProtector(result.TxRoot, n.networkContext.Descriptor(), result.LinkID, [16]byte{},
		link.SessionClassStream, link.DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{1}, bytes.Repeat([]byte{0x1}, 16)...), result.Generation, 100)
	if err != nil {
		t.Fatal(err)
	}
	frame.Body[len(frame.Body)-1] ^= 1
	if err := wire.WriteFrame(peer, frame); err != nil {
		t.Fatal(err)
	}
	waitAdmissionLinks(t, n, 0)
	// A hop-AEAD failure is rejected inside ReadMessage, before the classifier,
	// so it is a fatal Link failure and never a frame-local rejection.
	if after := n.rates.stats().FrameLocalRejected; after != before+1 {
		t.Fatalf("FrameLocalRejected = %d after tampered tag; want %d (auth failures are not frame-local)", after, before+1)
	}
}

// --- provenance-scoped malformed authenticated frames ------------------------

// waitPumpCondition polls cond until it holds or a short deadline expires. It is
// used for effects the read loop applies asynchronously after a real wire write.
func waitPumpCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// pumpOnLane returns the admitted pump of one LaneID (a Network carries one
// pump per authenticated Link, selected here by its authenticated lane).
func pumpOnLane(t *testing.T, n *network, lane uint8) *controlPump {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, pump := range n.controlPumps {
		if pump != nil && pump.lane == lane && pump.link != nil && pump.link.Ready() {
			return pump
		}
	}
	t.Fatalf("no admitted pump on lane %d", lane)
	return nil
}

// malformedSessionCtrlFrame builds one validly hop-sealed SESSION_CTRL whose
// inner body cannot decode: the declared handshake length agrees with the
// trailing bytes, so session.DecodeSessionCtrl reaches the class check and
// rejects the invalid class. The hop AEAD is a genuine seal of the authenticated
// peer, so only the structure is wrong.
func malformedSessionCtrlFrame(t *testing.T, rt *streamRuntime, sessionID [16]byte) (envelope, payload []byte) {
	t.Helper()
	const fixed = 28 // SessionID:16B | class:u8 | lane:u8 | attempt:u32 | epoch:u32 | noise_len:u16
	payload = make([]byte, fixed+4)
	copy(payload[:16], sessionID[:])
	payload[16] = 0x99 // not a valid SessionClass
	payload[17] = 0x02
	binary.BigEndian.PutUint16(payload[26:28], 4)
	src := [16]byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
	envelope = buildEnvelope(rt.wireID, src, rt.localID, wire.MessageTypeSessionCtrl, sessionID, 0, 0, 9, 3, len(payload))
	return envelope, payload
}

// TestControlPumpMalformedSessionCtrlDropsAndKeepsLinkServing proves origin (a):
// a hop-authenticated but structurally invalid SESSION_CTRL body is the frozen
// pre-E2E FrameMalformed class. It is dropped and counted exactly once, the
// physical Link stays admitted and answers a later valid PING, and no Session is
// terminated from the body's forgeable SessionID.
func TestControlPumpMalformedSessionCtrlDropsAndKeepsLinkServing(t *testing.T) {
	n, peer, control, _ := controlPumpPeer(t)
	skipper := newFactFrameSkipper(n, control)
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rt := n.streams
	// A Session entry claiming exactly the forged SessionID the malformed body
	// names: the frozen attribution rule forbids terminating it from a value a
	// hop could forge before any end-to-end authentication.
	var claimed session.SessionID
	claimed[0] = 0x77
	entry := &sessionEntry{
		id: claimed, scope: pathScope{id: 9, gen: 3},
		class: session.SessionClassStream, lane: session.LaneStream,
		ready: make(chan struct{}),
	}
	rt.registerSession(entry)
	envelope, payload := malformedSessionCtrlFrame(t, rt, [16]byte(claimed))

	before := n.rates.stats().FrameLocalRejected
	if err := control.WriteRoute(envelope, payload, link.HopRoute{Cursor: 0, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	// TCP order guarantees the pump consumed the malformed ROUTE_CTRL frame
	// before this PING; the matching PONG proves the reader survived it.
	probe := bytes.Repeat([]byte{0x5c}, 16)
	if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatal(err)
	}
	got := readSkippingFacts(t, skipper, control)
	if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatalf("post-malformed-frame PING/PONG mismatch: type=%d", got.Type)
	}
	if after := n.rates.stats().FrameLocalRejected; after != before+1 {
		t.Fatalf("FrameLocalRejected = %d after one malformed frame; want %d", after, before+1)
	}
	waitAdmissionLinks(t, n, 1)
	if entry.isTerminated() {
		t.Fatal("a malformed SESSION_CTRL terminated the Session named by its forgeable SessionID")
	}
	if rt.sessionEntryByID(claimed) == nil {
		t.Fatal("a malformed SESSION_CTRL removed the Session named by its forgeable SessionID")
	}
}

// TestPreAuthFrameMalformedProvenance pins the new attribution boundary: the
// sentinel alone is never the classification. Only the tag the
// FrameKindRouteControl dispatch applies carries the pre-E2E origin, and the
// authenticated-inner class is scoped to the two Circuit inner MessageTypes and
// excludes the broad sentinels that can carry a genuine transport failure.
func TestPreAuthFrameMalformedProvenance(t *testing.T) {
	if _, ok := preAuthFrameMalformedClassOf(nil); ok {
		t.Fatal("nil classified as pre-auth malformed")
	}
	if _, ok := preAuthFrameMalformedClassOf(session.ErrMalformedMessage); ok {
		t.Fatal("untagged session sentinel classified as pre-auth malformed")
	}
	for _, tc := range []struct {
		name     string
		sentinel error
		want     string
	}{
		{"malformed", session.ErrMalformedMessage, "malformed-session-control"},
		{"too large", session.ErrPayloadTooLarge, "session-control-too-large"},
		{"invalid class", session.ErrInvalidClass, "invalid-session-class"},
		{"lane mismatch", session.ErrLaneClassMismatch, "lane-class-mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if class, ok := preAuthMalformedClassOf(tc.sentinel); !ok || class != tc.want {
				t.Fatalf("preAuthMalformedClassOf(%v) = (%q,%v); want (%q,true)", tc.sentinel, class, ok, tc.want)
			}
			tagged := &preAuthFrameMalformedError{class: tc.want, err: tc.sentinel}
			class, ok := preAuthFrameMalformedClassOf(tagged)
			if !ok || class != tc.want {
				t.Fatalf("tagged class = (%q,%v); want (%q,true)", class, ok, tc.want)
			}
			if !errors.Is(tagged, tc.sentinel) {
				t.Fatalf("tagging lost the sentinel %v", tc.sentinel)
			}
		})
	}

	inner := buildEnvelope(0, [16]byte{}, [16]byte{}, wire.MessageTypeStreamData, [16]byte{}, 1, 1, 1, 1, 0)
	controlRPC := buildEnvelope(0, [16]byte{}, [16]byte{}, wire.MessageTypeControlRPC, [16]byte{}, 1, 1, 1, 1, 0)
	route := buildEnvelope(0, [16]byte{}, [16]byte{}, wire.MessageTypeSessionCtrl, [16]byte{}, 0, 0, 1, 1, 0)
	for _, sentinel := range []error{circuit.ErrMalformedMessage, circuit.ErrUnsupportedControl, circuit.ErrProtocol} {
		if class, ok := authenticatedInnerMalformedClassOf(link.ProtectedMessage{Envelope: inner}, sentinel); !ok || class == "" {
			t.Fatalf("authenticated inner sentinel %v not classified", sentinel)
		}
		if _, ok := authenticatedInnerMalformedClassOf(link.ProtectedMessage{Envelope: controlRPC}, sentinel); !ok {
			t.Fatalf("CONTROL_RPC sentinel %v not classified", sentinel)
		}
	}
	// A pre-AEAD MessageType never reaches the Circuit decoders.
	if _, ok := authenticatedInnerMalformedClassOf(link.ProtectedMessage{Envelope: route}, circuit.ErrMalformedMessage); ok {
		t.Fatal("a ROUTE_CTRL envelope was attributed to the authenticated inner class")
	}
	// The broad sentinels that carry Egress I/O failures and bounded resource
	// refusals stay out of the authenticated-inner class.
	for _, broad := range []error{circuit.ErrSessionLost, circuit.ErrResource, circuit.ErrSessionRefFailed} {
		if _, ok := authenticatedInnerMalformedClassOf(link.ProtectedMessage{Envelope: inner}, broad); ok {
			t.Fatalf("broad sentinel %v must not be attributed to the authenticated inner class", broad)
		}
	}
}

// TestControlPumpMalformedRouteBoundaryStaysFatal proves origin (a)'s fix does
// not widen the terminal boundary: a fresh-counter bad hop tag and a truncated
// frame still close the physical Link, because neither is a structural
// SESSION_CTRL/SESSION_READY body failure.
func TestControlPumpMalformedRouteBoundaryStaysFatal(t *testing.T) {
	t.Run("fresh-counter bad hop tag closes the Link", func(t *testing.T) {
		n, peer, _, result := controlPumpPeer(t)
		protector, err := link.NewFrameProtector(result.TxRoot, n.networkContext.Descriptor(), result.LinkID, [16]byte{},
			link.SessionClassStream, link.DirectionInitiatorToResponder)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{1}, bytes.Repeat([]byte{0x1}, 16)...), result.Generation, 100)
		if err != nil {
			t.Fatal(err)
		}
		frame.Body[len(frame.Body)-1] ^= 1
		if err := wire.WriteFrame(peer, frame); err != nil {
			t.Fatal(err)
		}
		waitAdmissionLinks(t, n, 0)
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := drainUntilClosed(peer); err != nil {
			t.Fatalf("peer did not observe authenticated Link closure: %v", err)
		}
	})
	t.Run("truncated frame closes the Link", func(t *testing.T) {
		n, peer, _, _ := controlPumpPeer(t)
		tcp, ok := peer.(*net.TCPConn)
		if !ok {
			t.Fatalf("peer connection is %T, want *net.TCPConn", peer)
		}
		// Announce a 64-byte body, deliver 8, then half-close: the reader sees a
		// half frame (TruncatedFrame), which is a link-layer failure, never the
		// newly classified pre-E2E FrameMalformed drop.
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, 64)
		if _, err := peer.Write(append(header, make([]byte, 8)...)); err != nil {
			t.Fatal(err)
		}
		// The peer may already have observed the truncation and closed its side,
		// so a half-close error here is expected and is not a failure.
		closeWriteToleratingPeerClose(t, tcp)
		waitAdmissionLinks(t, n, 0)
	})
}

// streamProbeSession registers one target-side E2E Session on the installed
// Path with a real protector pair and a peer protector whose frames entry.rx can
// open, exactly as the production commit path does. It admits the Session on the
// ingress STREAM Link's hop protector (required before ReadMessage delivers any
// E2E frame of it) and on the peer-side control IO (required before the peer can
// seal one).
func streamProbeSession(t *testing.T, n *network, streamIO *link.ProtectedControlIO, pump *controlPump, ps *pathState, id session.SessionID, peerNode [16]byte) (*sessionEntry, *session.E2EProtector) {
	t.Helper()
	rt := n.streams
	entry := &sessionEntry{
		id: id, scope: ps.scope, class: session.SessionClassStream, lane: session.LaneStream,
		src: peerNode, dst: rt.localID, initiator: false, ready: make(chan struct{}),
	}
	rt.registerSession(entry)
	entry.pendMu.Lock()
	entry.pendReady = true
	entry.pendMu.Unlock()
	root := make([]byte, 64)
	for i := range root {
		root[i] = byte(i+1) ^ byte(id[0])
	}
	if err := rt.createProtectors(entry, session.RootEpoch{Epoch: 1, Root: root}); err != nil {
		t.Fatalf("createProtectors: %v", err)
	}
	peer, err := session.NewE2EProtectorForContext(n.networkContext, session.E2EConfig{
		Root: root, SrcNodeID: entry.src, DstNodeID: entry.dst,
		PathID: ps.scope.id, PathGeneration: ps.scope.gen, SessionID: id,
		Class: session.SessionClassStream, Direction: entry.rx.Direction(),
	}, session.E2EPolicy{})
	if err != nil {
		t.Fatalf("peer protector: %v", err)
	}
	t.Cleanup(peer.Close)
	if err := peer.InstallEpoch(1, root); err != nil {
		t.Fatalf("peer install epoch: %v", err)
	}
	if err := pump.control.AdmitSession([16]byte(id), link.SessionClassStream); err != nil {
		t.Fatalf("admit on Link: %v", err)
	}
	if err := streamIO.AdmitSession([16]byte(id), link.SessionClassStream); err != nil {
		t.Fatalf("admit on peer: %v", err)
	}
	return entry, peer
}

// TestControlPumpAuthenticatedInnerMalformedFailsOnlyItsSession proves origin
// (b): a CONTROL_RPC/STREAM_DATA body that fails to decode AFTER the end-to-end
// tag authenticated is an authenticated state error. It fails only the exact E2E
// Session named by the authenticated envelope while a second Session on the same
// physical Link keeps working. The frame really traverses the paired pump: it is
// sealed with the Session's own end-to-end protector, hop-sealed by the peer's
// protected writer and read by the admitted STREAM Link.
func TestControlPumpAuthenticatedInnerMalformedFailsOnlyItsSession(t *testing.T) {
	n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// A STREAM data lane is only accepted from a peer that already carries an
	// active CONTROL Link, so the same authenticated identity first opens the
	// CONTROL carrier, then the STREAM Link the E2E frames ride.
	_, controlIO, _ := dialControlPumpPeer(t, n, identity, laneControl, 42, 17)
	if controlIO == nil {
		t.Fatal("no CONTROL protected IO")
	}
	waitAdmissionLinks(t, n, 1)
	_, streamIO, _ := dialControlPumpPeer(t, n, identity, laneStream, 43, 19)
	waitAdmissionLinks(t, n, 2)

	pump := pumpOnLane(t, n, laneStream)
	peerNode := pump.link.PeerNodeID()
	meta := pump.link.Metadata()
	scope := pathScope{id: 0x44, gen: 6}
	ps := &pathState{
		scope:      scope,
		lane:       path.LaneStream,
		nodes:      []topology.NodeID{topology.NodeID(peerNode), topology.NodeID(n.streams.localID)},
		links:      []topology.LinkRef{{ID: meta.LinkID, Epoch: meta.LinkEpoch, LaneID: meta.LaneID}},
		localIndex: 1,
		ready:      make(chan struct{}),
	}
	n.streams.registerPath(ps)

	var idA, idB session.SessionID
	idA[0], idB[0] = 0xa1, 0xb2
	entryA, peerA := streamProbeSession(t, n, streamIO, pump, ps, idA, peerNode)
	entryB, peerB := streamProbeSession(t, n, streamIO, pump, ps, idB, peerNode)

	sendInner := func(t *testing.T, protector *session.E2EProtector, id session.SessionID, number uint64, plaintext []byte) {
		t.Helper()
		envelope := buildEnvelope(n.networkContext.WireID(), peerNode, n.streams.localID,
			wire.MessageTypeStreamData, [16]byte(id), 1, number, scope.id, scope.gen, len(plaintext))
		sealed, err := protector.Seal(wire.Frame{Kind: wire.FrameKindEndToEnd, Envelope: envelope}, plaintext)
		if err != nil {
			t.Fatalf("seal E2E: %v", err)
		}
		if err := streamIO.WriteEndToEnd(envelope, sealed.Body, link.HopRoute{Cursor: 1, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
			t.Fatalf("write E2E: %v", err)
		}
	}

	// A 3-byte STREAM_DATA body is below the frozen header, so
	// circuit.DecodeStreamData rejects it with ErrMalformedMessage after the
	// inner tag opened.
	sendInner(t, peerA, idA, 1, []byte{0x01, 0x02, 0x03})
	waitPumpCondition(t, "Session A terminated", func() bool { return entryA.isTerminated() })
	if entryB.isTerminated() {
		t.Fatal("another Session on the same Link was terminated by A's frame")
	}
	waitAdmissionLinks(t, n, 2)

	// Session B keeps working on the same physical Link: a valid authenticated
	// inner STREAM_DATA frame is accepted and fails nothing.
	valid, err := circuit.StreamDataMessage{
		CircuitID: circuit.CircuitID{0x01},
		Flags:     circuit.FlagData,
		StreamSeq: 0,
		Payload:   []byte("x"),
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sendInner(t, peerB, idB, 1, valid)
	waitAdmissionLinks(t, n, 2)
	if entryB.isTerminated() {
		t.Fatal("B's valid authenticated frame failed its Session")
	}
}

// --- PATH_* pre-E2E FrameMalformed attribution -------------------------------

// pathPreAuthClasses pins the stable class name of every PATH sentinel the
// pre-E2E FrameMalformed table added. The names are compile-time constants, so
// a trace never echoes the raw path-handler error text.
var pathPreAuthClasses = []struct {
	name     string
	sentinel error
	want     string
}{
	{"path protocol", path.ErrProtocol, "path-protocol"},
	{"path resource limit", path.ErrResourceLimit, "path-resource-limit"},
	{"invalid path", path.ErrInvalidPath, "invalid-path"},
	{"invalid path lane", path.ErrInvalidLane, "invalid-path-lane"},
	{"invalid path node", path.ErrInvalidNode, "invalid-path-node"},
	{"duplicate path node", path.ErrDuplicateNode, "duplicate-path-node"},
	{"path hop limit", path.ErrHopLimit, "path-hop-limit"},
	{"path link mismatch", path.ErrLinkMismatch, "path-link-mismatch"},
	{"path inactive link", path.ErrInactiveLink, "path-inactive-link"},
	{"path digest mismatch", path.ErrPathDigestMismatch, "path-digest-mismatch"},
	{"path conflict", path.ErrPathConflict, "path-conflict"},
	{"path generation expired", path.ErrPathGenerationExpired, "path-generation-expired"},
	{"path identity mismatch", path.ErrPathMismatch, "path-identity-mismatch"},
	{"path state", path.ErrState, "path-state"},
}

// TestPreAuthFrameMalformedPathClasses pins the PATH half of the pre-E2E class
// table and, more importantly, the provenance rule: the sentinel alone is never
// the classification. Only the tag the FrameKindRouteControl dispatch applies
// carries the pre-E2E origin, so an untagged error wrapping the identical
// sentinel stays unclassified and terminal.
func TestPreAuthFrameMalformedPathClasses(t *testing.T) {
	if got, want := len(preAuthMalformedClasses), 4+len(pathPreAuthClasses); got != want {
		t.Fatalf("preAuthMalformedClasses has %d entries; want %d", got, want)
	}
	for _, tc := range pathPreAuthClasses {
		t.Run(tc.name, func(t *testing.T) {
			class, ok := preAuthMalformedClassOf(tc.sentinel)
			if !ok || class != tc.want {
				t.Fatalf("preAuthMalformedClassOf(%v) = (%q,%v); want (%q,true)", tc.sentinel, class, ok, tc.want)
			}
			// Provenance, not sentinel identity: an untagged error that wraps the
			// same sentinel must stay unclassified, even from a plausible origin.
			wrapped := fmt.Errorf("local ROUTE frame failed: %w", tc.sentinel)
			if class, ok := preAuthFrameMalformedClassOf(wrapped); ok {
				t.Fatalf("untagged %v classified as pre-auth malformed (%q)", wrapped, class)
			}
			tagged := &preAuthFrameMalformedError{class: tc.want, err: wrapped}
			gotClass, ok := preAuthFrameMalformedClassOf(tagged)
			if !ok || gotClass != tc.want {
				t.Fatalf("tagged class = (%q,%v); want (%q,true)", gotClass, ok, tc.want)
			}
			if !errors.Is(tagged, tc.sentinel) {
				t.Fatalf("tagging lost the sentinel %v", tc.sentinel)
			}
		})
	}
	// Sentinels deliberately left fatal: ErrClosed can mean the Network/path
	// Manager is shutting down, ErrEntropy is a local CSPRNG failure and
	// ErrNotFound has no live receive path.
	for _, fatal := range []error{path.ErrClosed, path.ErrEntropy, path.ErrNotFound} {
		if class, ok := preAuthMalformedClassOf(fatal); ok {
			t.Fatalf("fatal sentinel %v was attributed as pre-auth malformed (%q)", fatal, class)
		}
	}
}

// malformedPathControlFrame builds one validly hop-sealed PATH_* ROUTE_CTRL frame
// whose inner body cannot decode: a one-byte payload is below every frozen
// PATH_* header, so path.DecodeRouteControl rejects it with path.ErrProtocol
// before any path state is touched. The hop AEAD is a genuine seal of the
// authenticated peer, so only the structure is wrong.
func malformedPathControlFrame(t *testing.T, rt *streamRuntime, messageType wire.MessageType, pathID uint64, pathGen uint32) (envelope, payload []byte) {
	t.Helper()
	payload = []byte{0x00}
	src := [16]byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
	envelope = buildEnvelope(rt.wireID, src, rt.localID, messageType, [16]byte{}, 0, 0, pathID, pathGen, len(payload))
	return envelope, payload
}

// TestControlPumpMalformedPathControlDropsAndKeepsLinkServing proves the closed
// gap: a hop-authenticated PATH_OPEN / PATH_READY / PATH_BROKEN whose inner body
// is structurally invalid is the frozen pre-E2E FrameMalformed class. Each is
// dropped and counted exactly once, the physical Link stays admitted and answers
// a later valid PING, and no Path state is derived from the malformed body.
func TestControlPumpMalformedPathControlDropsAndKeepsLinkServing(t *testing.T) {
	for _, tc := range []struct {
		name        string
		messageType wire.MessageType
	}{
		{"malformed PATH_OPEN", wire.MessageTypePathOpen},
		{"malformed PATH_READY", wire.MessageTypePathReady},
		{"malformed PATH_BROKEN", wire.MessageTypePathBroken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, peer, control, _ := controlPumpPeer(t)
			skipper := newFactFrameSkipper(n, control)
			if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			rt := n.streams
			envelope, payload := malformedPathControlFrame(t, rt, tc.messageType, 0x21, 5)

			// Bridge the wire injection to the classifier: the receiver's own
			// decoder must produce the exact sentinel the new table names.
			if _, err := path.DecodeRouteControl(path.MessageType(tc.messageType), payload); !errors.Is(err, path.ErrProtocol) {
				t.Fatalf("DecodeRouteControl error = %v; want path.ErrProtocol", err)
			}

			before := n.rates.stats().FrameLocalRejected
			if err := control.WriteRoute(envelope, payload, link.HopRoute{Cursor: 0, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
				t.Fatal(err)
			}
			// TCP order guarantees the pump consumed the malformed ROUTE_CTRL
			// frame before this PING; the matching PONG proves the reader
			// survived it and the Link stayed admitted.
			probe := bytes.Repeat([]byte{0x5d}, 16)
			if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
				t.Fatal(err)
			}
			got := readSkippingFacts(t, skipper, control)
			if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
				t.Fatalf("post-malformed-frame PING/PONG mismatch: type=%d", got.Type)
			}
			if after := n.rates.stats().FrameLocalRejected; after != before+1 {
				t.Fatalf("FrameLocalRejected = %d after one malformed frame; want %d", after, before+1)
			}
			waitAdmissionLinks(t, n, 1)
		})
	}
}

// TestControlPumpValidPathControlAfterMalformedKeepsServing is the reachable
// half of the "still works" check: a well-formed PATH_BROKEN for a Path this
// node does not own is a no-op (handlePathBroken returns nil before any state
// change), so the decoder really accepts a valid PATH_* body on the same pump
// and charges no rejection. A full PATH_OPEN accept handshake is not cleanly
// reachable with this harness (it would need resolved hop LinkRefs, the active
// callback and a matching ComputeDigest), so this only proves the decoder and
// the serving Link, not an accepted path.
func TestControlPumpValidPathControlAfterMalformedKeepsServing(t *testing.T) {
	n, peer, control, _ := controlPumpPeer(t)
	skipper := newFactFrameSkipper(n, control)
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	rt := n.streams
	malformedEnvelope, malformedPayload := malformedPathControlFrame(t, rt, wire.MessageTypePathReady, 0x23, 7)
	before := n.rates.stats().FrameLocalRejected
	if err := control.WriteRoute(malformedEnvelope, malformedPayload, link.HopRoute{Cursor: 0, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	beforeValid := before + 1

	valid, err := path.PathBroken{
		PathID: 0x24, Generation: 8, Lane: path.LaneStream,
		Reason: path.BrokenReasonNoRoute, FailedCursor: 0,
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	src := [16]byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
	envelope := buildEnvelope(rt.wireID, src, rt.localID, wire.MessageTypePathBroken, [16]byte{}, 0, 0, 0x24, 8, len(valid))
	if err := control.WriteRoute(envelope, valid, link.HopRoute{Cursor: 0, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	probe := bytes.Repeat([]byte{0x5e}, 16)
	if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatal(err)
	}
	got := readSkippingFacts(t, skipper, control)
	if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatalf("post-valid-PATH PING/PONG mismatch: type=%d", got.Type)
	}
	if after := n.rates.stats().FrameLocalRejected; after != beforeValid {
		t.Fatalf("FrameLocalRejected = %d; want %d (the valid PATH_BROKEN must not be charged)", after, beforeValid)
	}
	waitAdmissionLinks(t, n, 1)
}

// TestControlPumpPathMalformedBoundaryStaysFatal proves the PATH attribution did
// not widen the terminal boundary: a fresh-counter bad hop AEAD tag and a
// truncated frame still close the physical Link, and a hop-valid frame that is
// not the malformed PATH body keeps its prior disposition.
func TestControlPumpPathMalformedBoundaryStaysFatal(t *testing.T) {
	t.Run("fresh-counter bad hop tag closes the Link", func(t *testing.T) {
		n, peer, _, result := controlPumpPeer(t)
		protector, err := link.NewFrameProtector(result.TxRoot, n.networkContext.Descriptor(), result.LinkID, [16]byte{},
			link.SessionClassStream, link.DirectionInitiatorToResponder)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{1}, bytes.Repeat([]byte{0x1}, 16)...), result.Generation, 100)
		if err != nil {
			t.Fatal(err)
		}
		frame.Body[len(frame.Body)-1] ^= 1
		if err := wire.WriteFrame(peer, frame); err != nil {
			t.Fatal(err)
		}
		waitAdmissionLinks(t, n, 0)
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := drainUntilClosed(peer); err != nil {
			t.Fatalf("peer did not observe authenticated Link closure: %v", err)
		}
	})
	t.Run("truncated frame closes the Link", func(t *testing.T) {
		n, peer, _, _ := controlPumpPeer(t)
		tcp, ok := peer.(*net.TCPConn)
		if !ok {
			t.Fatalf("peer connection is %T, want *net.TCPConn", peer)
		}
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, 64)
		if _, err := peer.Write(append(header, make([]byte, 8)...)); err != nil {
			t.Fatal(err)
		}
		// The peer may already have observed the truncation and closed its side,
		// so a half-close error here is expected and is not a failure.
		closeWriteToleratingPeerClose(t, tcp)
		waitAdmissionLinks(t, n, 0)
	})
	t.Run("hop-valid wrong-kind frame still behaves as before", func(t *testing.T) {
		// A hop-authenticated LINK_CTRL TEARDOWN is not a malformed ROUTE_CTRL
		// body, so its pre-existing terminal disposition is unchanged.
		n, _, control, _ := controlPumpPeer(t)
		payload := make([]byte, 10)
		binary.BigEndian.PutUint64(payload[:8], 1)
		if err := control.WriteControl(link.ControlMessage{Type: 5, Payload: payload}); err != nil {
			t.Fatal(err)
		}
		waitAdmissionLinks(t, n, 0)
	})
	t.Run("hop-valid PATH frame outside local path state stays frame-local", func(t *testing.T) {
		// The envelope MessageType is a PATH type, but the error is the
		// pre-existing frame-local link.ErrRouteMessage, not a path sentinel, so
		// the new pre-auth tag must NOT capture it: drop+count, Link retained.
		n, peer, control, _ := controlPumpPeer(t)
		skipper := newFactFrameSkipper(n, control)
		if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		rt := n.streams
		payload, err := path.PathReady{
			PathID: 0x31, Generation: 9, Lane: path.LaneStream,
			Status: path.ReadyStatusReady, Code: path.ErrorCodeNone,
		}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		src := [16]byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
		dst := [16]byte{0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c, 0x7c}
		envelope := buildEnvelope(rt.wireID, src, dst, wire.MessageTypePathReady, [16]byte{}, 0, 0, 0x31, 9, len(payload))
		before := n.rates.stats().FrameLocalRejected
		if err := control.WriteRoute(envelope, payload, link.HopRoute{Cursor: 0, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
			t.Fatal(err)
		}
		probe := bytes.Repeat([]byte{0x5f}, 16)
		if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
			t.Fatal(err)
		}
		got := readSkippingFacts(t, skipper, control)
		if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
			t.Fatalf("post-wrong-kind-frame PING/PONG mismatch: type=%d", got.Type)
		}
		if after := n.rates.stats().FrameLocalRejected; after != before+1 {
			t.Fatalf("FrameLocalRejected = %d after one frame-local rejection; want %d", after, before+1)
		}
		waitAdmissionLinks(t, n, 1)
	})
}

// --- E2E lane/kind binding rejection ------------------------------------------

// controlLaneMismatchFrame admits one E2E Session on both ends of a paired
// CONTROL Link and returns one genuine hop-sealed E2E frame of it. The Session is
// admitted on the receiving Link exactly as the production admit path admits a
// Session on its Path's data Link; only the frame's lane is wrong, because a
// CONTROL Link is never the STREAM/PACKET data lane a Session/Path owns, so the
// E2E dispatch's lane guard rejects it before any inner tag is verified. The body
// is opaque session ciphertext, so it only has to satisfy the frozen E2E payload
// shape (inner_len plus the 16-byte end-to-end tag) for the hop AEAD to carry it.
func controlLaneMismatchFrame(t *testing.T, n *network, control *link.ProtectedControlIO, pump *controlPump, id session.SessionID, pathID uint64, pathGen uint32) (envelope, payload []byte) {
	t.Helper()
	if err := pump.control.AdmitSession([16]byte(id), link.SessionClassStream); err != nil {
		t.Fatalf("admit the Session on the receiving CONTROL Link: %v", err)
	}
	if err := control.AdmitSession([16]byte(id), link.SessionClassStream); err != nil {
		t.Fatalf("admit the Session on the peer CONTROL Link: %v", err)
	}
	const e2eTag = 16
	payload = append(bytes.Repeat([]byte{0x7a}, 8), bytes.Repeat([]byte{0x00}, e2eTag)...)
	envelope = buildEnvelope(n.networkContext.WireID(), pump.link.PeerNodeID(), n.streams.localID,
		wire.MessageTypeStreamData, [16]byte(id), 1, 1, pathID, pathGen, len(payload)-e2eTag)
	return envelope, payload
}

// TestControlPumpEndToEndLaneMismatchDropsAndKeepsLinkServing proves the closed
// gap: a fully hop-authenticated E2E frame whose authenticated lane is not the
// Session/Path data lane is the frozen pre-end-to-end per-frame binding
// rejection. It is dropped and counted exactly once on the ingress Link, and the
// shared physical Link stays admitted and still answers a following valid PING.
func TestControlPumpEndToEndLaneMismatchDropsAndKeepsLinkServing(t *testing.T) {
	n, peer, control, _ := controlPumpPeer(t)
	skipper := newFactFrameSkipper(n, control)
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	pump := pumpOnLane(t, n, laneControl)
	var id session.SessionID
	id[0] = 0xe1
	envelope, payload := controlLaneMismatchFrame(t, n, control, pump, id, 0x51, 3)

	// Bridge the wire injection below to the read() decision without a race: the
	// exact frame is a lane/kind binding rejection at the E2E dispatch, and only
	// the tagged form of that error is classified frame-local. The guard runs
	// before any inner tag is opened, so this call touches no runtime state.
	direct := pump.consumeFrame(link.ProtectedMessage{Kind: wire.FrameKindEndToEnd, Envelope: envelope, Payload: payload})
	if !errors.Is(direct, link.ErrUnexpectedKind) {
		t.Fatalf("wrong-lane E2E dispatch error = %v; want ErrUnexpectedKind", direct)
	}
	if class, ok := endToEndLaneMismatchClassOf(direct); !ok || class != endToEndLaneMismatchClass {
		t.Fatalf("wrong-lane E2E class = (%q,%v); want (%q,true)", class, ok, endToEndLaneMismatchClass)
	}

	before := n.rates.stats().FrameLocalRejected
	if err := control.WriteEndToEnd(envelope, payload, link.HopRoute{Cursor: 0, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	waitPumpCondition(t, "the lane-mismatched E2E frame to be counted", func() bool {
		return n.rates.stats().FrameLocalRejected == before+1
	})
	// TCP order guarantees the pump consumed the E2E frame before this PING; the
	// matching PONG proves the shared Link survived it and stayed admitted.
	probe := bytes.Repeat([]byte{0x71}, 16)
	if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatal(err)
	}
	got := readSkippingFacts(t, skipper, control)
	if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatalf("post-lane-mismatch PING/PONG mismatch: type=%d", got.Type)
	}
	waitAdmissionLinks(t, n, 1)
	if after := n.rates.stats().FrameLocalRejected; after != before+1 {
		t.Fatalf("FrameLocalRejected = %d after one lane-mismatched E2E frame; want %d", after, before+1)
	}
}

// TestControlPumpEndToEndWrongPathLaneKeepsLinkServing covers the second origin of
// the same tag: the E2E frame arrives on a real data lane that is not the lane of
// the installed Path it names, so checkIngressPeer's data-lane guard rejects it.
// The frame rides the STREAM Link while the Session's Path is the PACKET lane, so
// the STREAM Link must survive and keep answering.
func TestControlPumpEndToEndWrongPathLaneKeepsLinkServing(t *testing.T) {
	n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// A data lane is only accepted from a peer that already carries an active
	// CONTROL Link, so the same authenticated identity opens the CONTROL carrier
	// first, then the two data lanes.
	_, controlIO, _ := dialControlPumpPeer(t, n, identity, laneControl, 42, 17)
	waitAdmissionLinks(t, n, 1)
	streamConn, streamIO, _ := dialControlPumpPeer(t, n, identity, laneStream, 43, 19)
	waitAdmissionLinks(t, n, 2)
	_, _, _ = dialControlPumpPeer(t, n, identity, lanePacket, 44, 21)
	waitAdmissionLinks(t, n, 3)
	skipper := newFactFrameSkipper(n, controlIO)
	if err := streamConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	rt := n.streams
	streamPump := pumpOnLane(t, n, laneStream)
	packetPump := pumpOnLane(t, n, lanePacket)
	peerNode := streamPump.link.PeerNodeID()
	packetMeta := packetPump.link.Metadata()
	scope := pathScope{id: 0x62, gen: 4}
	ps := &pathState{
		scope:      scope,
		lane:       path.LanePacket,
		nodes:      []topology.NodeID{topology.NodeID(peerNode), topology.NodeID(rt.localID)},
		links:      []topology.LinkRef{{ID: packetMeta.LinkID, Epoch: packetMeta.LinkEpoch, LaneID: packetMeta.LaneID}},
		localIndex: 1,
		ready:      make(chan struct{}),
	}
	rt.registerPath(ps)
	var id session.SessionID
	id[0] = 0xe2
	entry := &sessionEntry{
		id: id, scope: scope, class: session.SessionClassPacket, lane: session.LanePacket,
		src: peerNode, dst: rt.localID, initiator: false, ready: make(chan struct{}),
	}
	rt.registerSession(entry)
	// The Session is admitted on the STREAM Link exactly as the production admit
	// path admits a Session on its Path's data Link. Here the ingress Link is the
	// sibling lane, which is what the data-lane guard must reject per frame.
	if err := streamPump.control.AdmitSession([16]byte(id), link.SessionClassPacket); err != nil {
		t.Fatal(err)
	}
	if err := streamIO.AdmitSession([16]byte(id), link.SessionClassPacket); err != nil {
		t.Fatal(err)
	}

	const e2eTag = 16
	payload := append(bytes.Repeat([]byte{0x7b}, 8), bytes.Repeat([]byte{0x00}, e2eTag)...)
	envelope := buildEnvelope(n.networkContext.WireID(), peerNode, rt.localID,
		wire.MessageTypeIPPacket, [16]byte(id), 1, 1, scope.id, scope.gen, len(payload)-e2eTag)
	var hopHeader [wire.HopHeaderSize]byte
	hopHeader[24] = byte(ps.localIndex)

	// Bridge: the exact frame is a lane binding rejection at the data-lane guard,
	// reached after the Session/Path/class/direction/cursor bindings all hold, and
	// consumeFrame tags that origin at the E2E dispatch.
	direct := streamPump.consumeFrame(link.ProtectedMessage{
		Kind: wire.FrameKindEndToEnd, Envelope: envelope, Payload: payload, HopHeader: hopHeader,
	})
	if !errors.Is(direct, link.ErrUnexpectedKind) {
		t.Fatalf("wrong-path-lane E2E dispatch error = %v; want ErrUnexpectedKind", direct)
	}
	if class, ok := endToEndLaneMismatchClassOf(direct); !ok || class != endToEndLaneMismatchClass {
		t.Fatalf("wrong-path-lane E2E class = (%q,%v); want (%q,true)", class, ok, endToEndLaneMismatchClass)
	}

	before := n.rates.stats().FrameLocalRejected
	if err := streamIO.WriteEndToEnd(envelope, payload, link.HopRoute{Cursor: uint8(ps.localIndex), HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	waitPumpCondition(t, "the wrong-path-lane E2E frame to be counted", func() bool {
		return n.rates.stats().FrameLocalRejected == before+1
	})
	probe := bytes.Repeat([]byte{0x72}, 16)
	if err := streamIO.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatal(err)
	}
	got := readSkippingFacts(t, skipper, streamIO)
	if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatalf("post-wrong-path-lane PING/PONG mismatch: type=%d", got.Type)
	}
	waitAdmissionLinks(t, n, 3)
	if after := n.rates.stats().FrameLocalRejected; after != before+1 {
		t.Fatalf("FrameLocalRejected = %d after one wrong-path-lane E2E frame; want %d", after, before+1)
	}
}

// TestEndToEndLaneMismatchProvenance pins the provenance boundary: the sentinel
// alone is never the classification. Only the tag the FrameKindEndToEnd dispatch
// applies carries the pre-end-to-end origin, and the error a strict
// ReadMessage/ReadControl reader produces for a wrong-kind frame keeps its
// terminal disposition.
func TestEndToEndLaneMismatchProvenance(t *testing.T) {
	if _, ok := endToEndLaneMismatchClassOf(nil); ok {
		t.Fatal("nil classified as an E2E lane mismatch")
	}
	// The exact production shape of the error ProtectedControlIO.ReadControl
	// returns for a wrong-kind frame read on a specific reader.
	untagged := fmt.Errorf("%w: frame kind 0x%02x: %w", link.ErrControlMessage, uint8(wire.FrameKindEndToEnd), link.ErrUnexpectedKind)
	if class, ok := endToEndLaneMismatchClassOf(untagged); ok {
		t.Fatalf("untagged %v classified as an E2E lane mismatch (%q)", untagged, class)
	}
	if isFrameLocalSemanticError(link.ErrUnexpectedKind) {
		t.Fatal("link.ErrUnexpectedKind was added to the global frame-local semantic table")
	}
	if _, ok := frameLocalSemanticClassOf(untagged); ok {
		t.Fatal("a wrong-kind reader error became frame-local")
	}
	if _, ok := readMessageFrameLocalClass(link.ErrUnexpectedKind); ok {
		t.Fatal("the ReadMessage branch classified link.ErrUnexpectedKind")
	}
	tagged := &endToEndLaneMismatchError{err: untagged}
	class, ok := endToEndLaneMismatchClassOf(tagged)
	if !ok || class != endToEndLaneMismatchClass {
		t.Fatalf("tagged class = (%q,%v); want (%q,true)", class, ok, endToEndLaneMismatchClass)
	}
	if !errors.Is(tagged, link.ErrUnexpectedKind) || !errors.Is(tagged, link.ErrControlMessage) {
		t.Fatal("tagging lost the wrapped sentinels")
	}

	// A real one: the Network's own writer seals one E2E frame on a data lane
	// toward the peer, and the peer's strict control reader reads it. That is the
	// actual ReadMessage-produced ErrUnexpectedKind the tag must never capture.
	n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = dialControlPumpPeer(t, n, identity, laneControl, 42, 17)
	waitAdmissionLinks(t, n, 1)
	streamConn, streamIO, _ := dialControlPumpPeer(t, n, identity, laneStream, 43, 19)
	waitAdmissionLinks(t, n, 2)
	streamPump := pumpOnLane(t, n, laneStream)
	var id session.SessionID
	id[0] = 0xe3
	if err := streamPump.control.AdmitSession([16]byte(id), link.SessionClassStream); err != nil {
		t.Fatal(err)
	}
	if err := streamIO.AdmitSession([16]byte(id), link.SessionClassStream); err != nil {
		t.Fatal(err)
	}
	const e2eTag = 16
	payload := append(bytes.Repeat([]byte{0x7c}, 8), bytes.Repeat([]byte{0x00}, e2eTag)...)
	envelope := buildEnvelope(n.networkContext.WireID(), streamPump.link.PeerNodeID(), n.streams.localID,
		wire.MessageTypeStreamData, [16]byte(id), 1, 1, 0x53, 5, len(payload)-e2eTag)
	if err := streamPump.sendEndToEnd(envelope, payload, link.HopRoute{Cursor: 0, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if err := streamConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, readErr := streamIO.ReadControl()
	if !errors.Is(readErr, link.ErrUnexpectedKind) || !errors.Is(readErr, link.ErrControlMessage) {
		t.Fatalf("strict control read of a wrong-kind frame = %v; want ErrControlMessage+ErrUnexpectedKind", readErr)
	}
	if class, ok := endToEndLaneMismatchClassOf(readErr); ok {
		t.Fatalf("the real ReadControl error acquired the E2E lane-mismatch class %q", class)
	}
	if _, ok := readMessageFrameLocalClass(readErr); ok {
		t.Fatal("the real ReadControl error was classified frame-local")
	}
	waitAdmissionLinks(t, n, 2)
}

// TestControlPumpEndToEndLaneMismatchBoundaryStaysFatal proves the new tag did
// not widen the terminal boundary: link-layer failures and a LINK_CTRL semantic
// error still close the physical Link.
func TestControlPumpEndToEndLaneMismatchBoundaryStaysFatal(t *testing.T) {
	t.Run("truncated frame closes the Link", func(t *testing.T) {
		n, peer, _, _ := controlPumpPeer(t)
		tcp, ok := peer.(*net.TCPConn)
		if !ok {
			t.Fatalf("peer connection is %T, want *net.TCPConn", peer)
		}
		// Announce a 64-byte body, deliver 8, then half-close: the reader sees a
		// half frame (TruncatedFrame), which is a link-layer failure.
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, 64)
		if _, err := peer.Write(append(header, make([]byte, 8)...)); err != nil {
			t.Fatal(err)
		}
		// The peer may already have observed the truncation and closed its side,
		// so a half-close error here is expected and is not a failure.
		closeWriteToleratingPeerClose(t, tcp)
		waitAdmissionLinks(t, n, 0)
	})
	t.Run("fresh-counter bad hop tag closes the Link", func(t *testing.T) {
		n, peer, _, result := controlPumpPeer(t)
		protector, err := link.NewFrameProtector(result.TxRoot, n.networkContext.Descriptor(), result.LinkID, [16]byte{},
			link.SessionClassStream, link.DirectionInitiatorToResponder)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{1}, bytes.Repeat([]byte{0x1}, 16)...), result.Generation, 100)
		if err != nil {
			t.Fatal(err)
		}
		frame.Body[len(frame.Body)-1] ^= 1
		if err := wire.WriteFrame(peer, frame); err != nil {
			t.Fatal(err)
		}
		waitAdmissionLinks(t, n, 0)
	})
	t.Run("LINK_CTRL semantic error closes the Link", func(t *testing.T) {
		// A hop-authenticated LINK_CTRL body the frozen control schema rejects is
		// a control-plane failure, never the E2E lane binding rejection. The frame
		// is sealed directly because the local writer refuses to emit it.
		n, peer, _, result := controlPumpPeer(t)
		protector, err := link.NewFrameProtector(result.TxRoot, n.networkContext.Descriptor(), result.LinkID, [16]byte{},
			link.SessionClassStream, link.DirectionInitiatorToResponder)
		if err != nil {
			t.Fatal(err)
		}
		// Type 4 has no admitted shape, so validateControlMessage rejects it and
		// the strict LINK_CTRL reader ends the Link.
		frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, []byte{4, 0x01}, result.Generation, 100)
		if err != nil {
			t.Fatal(err)
		}
		if err := wire.WriteFrame(peer, frame); err != nil {
			t.Fatal(err)
		}
		waitAdmissionLinks(t, n, 0)
	})
}

// --- ROUTE_CTRL lane binding rejection ----------------------------------------

// routeBootstrapFrame builds one wire-valid ROUTE_CTRL bootstrap envelope and
// its matching hop header: a decodable PATH_READY body for the named scope,
// addressed to a two-node direction, with the hop cursor/limit/budget set. The
// only thing a test ever makes wrong with it is the ingress lane.
func routeBootstrapFrame(t *testing.T, wireID uint64, src, dst [16]byte, scope pathScope, lane path.Lane, cursor uint8) (envelope, payload []byte, hopHeader [wire.HopHeaderSize]byte) {
	t.Helper()
	body, err := path.PathReady{
		PathID: scope.id, Generation: scope.gen, Lane: lane,
		Status: path.ReadyStatusReady, Code: path.ErrorCodeNone,
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	envelope = buildEnvelope(wireID, src, dst, wire.MessageTypePathReady, [16]byte{}, 0, 0, scope.id, scope.gen, len(body))
	hopHeader[24] = cursor
	hopHeader[25] = 1
	binary.BigEndian.PutUint32(hopHeader[26:30], 1<<20)
	return envelope, body, hopHeader
}

// TestControlPumpRouteFrameOnDataLaneDropsAndKeepsLinkServing proves the closed
// gap: a fully hop-authenticated ROUTE_CTRL bootstrap frame (PATH_OPEN/
// PATH_READY/PATH_BROKEN/SESSION_CTRL/SESSION_READY) read from a DATA lane is
// rejected by checkIngressPeer's control-lane guard before any body decode or
// end-to-end authentication. The frozen attribution rule drops and counts that
// single frame on the ingress Link and never closes the shared physical DATA
// Link, which stays admitted and still answers a following valid PING.
func TestControlPumpRouteFrameOnDataLaneDropsAndKeepsLinkServing(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lane       uint8
		linkID     uint64
		generation uint32
		pathLane   path.Lane
	}{
		{"STREAM data lane", laneStream, 43, 19, path.LaneStream},
		{"PACKET data lane", lanePacket, 44, 21, path.LanePacket},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
			identity, err := security.GenerateIdentity()
			if err != nil {
				t.Fatal(err)
			}
			// A DATA lane is only accepted from a peer that already carries an
			// active CONTROL Link, so the same authenticated identity opens the
			// CONTROL carrier first.
			_, controlIO, _ := dialControlPumpPeer(t, n, identity, laneControl, 42, 17)
			waitAdmissionLinks(t, n, 1)
			dataConn, dataIO, _ := dialControlPumpPeer(t, n, identity, tc.lane, tc.linkID, tc.generation)
			waitAdmissionLinks(t, n, 2)
			skipper := newFactFrameSkipper(n, controlIO)
			if err := dataConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}

			rt := n.streams
			dataPump := pumpOnLane(t, n, tc.lane)
			peerNode := dataPump.link.PeerNodeID()
			dataMeta := dataPump.link.Metadata()
			scope := pathScope{id: 0x71, gen: 6}
			// The Path this node installed names the DATA lane as its hop, so a
			// ROUTE_CTRL frame of it read from that same Link clears every check
			// except checkIngressPeer's control-lane guard.
			ps := &pathState{
				scope:      scope,
				lane:       tc.pathLane,
				nodes:      []topology.NodeID{topology.NodeID(peerNode), topology.NodeID(rt.localID)},
				links:      []topology.LinkRef{{ID: dataMeta.LinkID, Epoch: dataMeta.LinkEpoch, LaneID: dataMeta.LaneID}},
				localIndex: 1,
				ready:      make(chan struct{}),
			}
			rt.registerPath(ps)
			envelope, payload, hopHeader := routeBootstrapFrame(t, rt.wireID, peerNode, rt.localID, scope, tc.pathLane, uint8(ps.localIndex))

			// Bridge the wire injection below to the read() decision without a
			// race: this exact frame is a lane binding rejection at the ROUTE
			// dispatch, and only the tagged form of that origin is classified
			// frame-local. The guard runs before any body decode, so this call
			// touches no runtime state.
			direct := dataPump.consumeFrame(link.ProtectedMessage{
				Kind: wire.FrameKindRouteControl, Envelope: envelope, Payload: payload, HopHeader: hopHeader,
			})
			if !errors.Is(direct, link.ErrUnexpectedKind) {
				t.Fatalf("wrongly-laned ROUTE dispatch error = %v; want ErrUnexpectedKind", direct)
			}
			if class, ok := routeLaneMismatchClassOf(direct); !ok || class != routeLaneMismatchClass {
				t.Fatalf("wrongly-laned ROUTE class = (%q,%v); want (%q,true)", class, ok, routeLaneMismatchClass)
			}

			before := n.rates.stats().FrameLocalRejected
			if err := dataIO.WriteRoute(envelope, payload, link.HopRoute{Cursor: uint8(ps.localIndex), HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
				t.Fatal(err)
			}
			waitPumpCondition(t, "the wrongly-laned ROUTE_CTRL frame to be counted", func() bool {
				return n.rates.stats().FrameLocalRejected == before+1
			})
			// TCP order guarantees the pump consumed the ROUTE frame before this
			// PING; the matching PONG proves the shared DATA Link survived it and
			// stayed admitted.
			probe := bytes.Repeat([]byte{0x74}, 16)
			if err := dataIO.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
				t.Fatal(err)
			}
			got := readSkippingFacts(t, skipper, dataIO)
			if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
				t.Fatalf("post-wrongly-laned-ROUTE PING/PONG mismatch: type=%d", got.Type)
			}
			waitAdmissionLinks(t, n, 2)
			if after := n.rates.stats().FrameLocalRejected; after != before+1 {
				t.Fatalf("FrameLocalRejected = %d after one wrongly-laned ROUTE frame; want %d", after, before+1)
			}
		})
	}
}

// TestRouteLaneMismatchProvenance pins the provenance boundary of the ROUTE tag:
// the sentinel alone is never the classification. Only the tag the
// FrameKindRouteControl dispatch applies carries this pre-E2E origin, the
// ReadMessage/ReadControl-produced ErrUnexpectedKind keeps its terminal
// disposition, and the two lane tags can never report each other's class.
func TestRouteLaneMismatchProvenance(t *testing.T) {
	if _, ok := routeLaneMismatchClassOf(nil); ok {
		t.Fatal("nil classified as a ROUTE lane mismatch")
	}
	// The exact production shape of the error ProtectedControlIO.ReadControl
	// returns for a wrong-kind frame read on a specific reader.
	untagged := fmt.Errorf("%w: frame kind 0x%02x: %w", link.ErrControlMessage, uint8(wire.FrameKindRouteControl), link.ErrUnexpectedKind)
	if class, ok := routeLaneMismatchClassOf(untagged); ok {
		t.Fatalf("untagged %v classified as a ROUTE lane mismatch (%q)", untagged, class)
	}
	if class, ok := routeLaneMismatchClassOf(link.ErrUnexpectedKind); ok {
		t.Fatalf("bare link.ErrUnexpectedKind classified as a ROUTE lane mismatch (%q)", class)
	}
	// Text that looks exactly like the route dispatch still carries no
	// provenance: the tag is a type, not a message.
	if class, ok := routeLaneMismatchClassOf(fmt.Errorf("local ROUTE frame failed: %w", link.ErrUnexpectedKind)); ok {
		t.Fatalf("untagged route-shaped error classified as a ROUTE lane mismatch (%q)", class)
	}
	if isFrameLocalSemanticError(link.ErrUnexpectedKind) {
		t.Fatal("link.ErrUnexpectedKind was added to the global frame-local semantic table")
	}
	if _, ok := frameLocalSemanticClassOf(untagged); ok {
		t.Fatal("a wrong-kind reader error became frame-local")
	}
	if _, ok := readMessageFrameLocalClass(link.ErrUnexpectedKind); ok {
		t.Fatal("the ReadMessage branch classified link.ErrUnexpectedKind")
	}

	tagged := &routeLaneMismatchError{err: untagged}
	class, ok := routeLaneMismatchClassOf(tagged)
	if !ok || class != routeLaneMismatchClass {
		t.Fatalf("tagged class = (%q,%v); want (%q,true)", class, ok, routeLaneMismatchClass)
	}
	if !errors.Is(tagged, link.ErrUnexpectedKind) || !errors.Is(tagged, link.ErrControlMessage) {
		t.Fatal("tagging lost the wrapped sentinels")
	}

	// The two provenance tags are mutually exclusive by type identity, so
	// neither dispatch can be reported under the other's class.
	if class, ok := routeLaneMismatchClassOf(&endToEndLaneMismatchError{err: untagged}); ok {
		t.Fatalf("the E2E-dispatch tag acquired the ROUTE class %q", class)
	}
	if class, ok := endToEndLaneMismatchClassOf(&routeLaneMismatchError{err: untagged}); ok {
		t.Fatalf("the ROUTE-dispatch tag acquired the E2E class %q", class)
	}

	// A real one: the Network's own writer seals one ROUTE_CTRL frame on a DATA
	// lane toward the peer, and the peer's strict control reader reads it. That
	// is the actual ReadControl-produced ErrUnexpectedKind the tag must never
	// capture.
	n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = dialControlPumpPeer(t, n, identity, laneControl, 42, 17)
	waitAdmissionLinks(t, n, 1)
	streamConn, streamIO, _ := dialControlPumpPeer(t, n, identity, laneStream, 43, 19)
	waitAdmissionLinks(t, n, 2)
	streamPump := pumpOnLane(t, n, laneStream)
	envelope, payload, _ := routeBootstrapFrame(t, n.networkContext.WireID(), n.streams.localID, streamPump.link.PeerNodeID(),
		pathScope{id: 0x53, gen: 5}, path.LaneStream, 0)
	if err := streamPump.sendRoute(envelope, payload, link.HopRoute{Cursor: 0, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if err := streamConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, readErr := streamIO.ReadControl()
	if !errors.Is(readErr, link.ErrUnexpectedKind) || !errors.Is(readErr, link.ErrControlMessage) {
		t.Fatalf("strict control read of a wrong-kind frame = %v; want ErrControlMessage+ErrUnexpectedKind", readErr)
	}
	if class, ok := routeLaneMismatchClassOf(readErr); ok {
		t.Fatalf("the real ReadControl error acquired the ROUTE lane-mismatch class %q", class)
	}
	if _, ok := readMessageFrameLocalClass(readErr); ok {
		t.Fatal("the real ReadControl error was classified frame-local")
	}
	waitAdmissionLinks(t, n, 2)
}

// TestControlPumpRouteLaneMismatchBoundaryStaysFatal proves the new tag did not
// widen the terminal boundary: link-layer failures and a LINK_CTRL semantic
// error still close the physical Link.
func TestControlPumpRouteLaneMismatchBoundaryStaysFatal(t *testing.T) {
	t.Run("truncated frame closes the Link", func(t *testing.T) {
		n, peer, _, _ := controlPumpPeer(t)
		tcp, ok := peer.(*net.TCPConn)
		if !ok {
			t.Fatalf("peer connection is %T, want *net.TCPConn", peer)
		}
		// Announce a 64-byte body, deliver 8, then half-close: the reader sees a
		// half frame (TruncatedFrame), which is a link-layer failure.
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, 64)
		if _, err := peer.Write(append(header, make([]byte, 8)...)); err != nil {
			t.Fatal(err)
		}
		// The peer may already have observed the truncation and closed its side,
		// so a half-close error here is expected and is not a failure.
		closeWriteToleratingPeerClose(t, tcp)
		waitAdmissionLinks(t, n, 0)
	})
	t.Run("fresh-counter bad hop tag closes the Link", func(t *testing.T) {
		n, peer, _, result := controlPumpPeer(t)
		protector, err := link.NewFrameProtector(result.TxRoot, n.networkContext.Descriptor(), result.LinkID, [16]byte{},
			link.SessionClassStream, link.DirectionInitiatorToResponder)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{1}, bytes.Repeat([]byte{0x1}, 16)...), result.Generation, 100)
		if err != nil {
			t.Fatal(err)
		}
		frame.Body[len(frame.Body)-1] ^= 1
		if err := wire.WriteFrame(peer, frame); err != nil {
			t.Fatal(err)
		}
		waitAdmissionLinks(t, n, 0)
	})
	t.Run("LINK_CTRL semantic error closes the Link", func(t *testing.T) {
		// A hop-authenticated LINK_CTRL body the frozen control schema rejects is
		// a control-plane failure, never the ROUTE lane binding rejection. The
		// frame is sealed directly because the local writer refuses to emit it.
		n, peer, _, result := controlPumpPeer(t)
		protector, err := link.NewFrameProtector(result.TxRoot, n.networkContext.Descriptor(), result.LinkID, [16]byte{},
			link.SessionClassStream, link.DirectionInitiatorToResponder)
		if err != nil {
			t.Fatal(err)
		}
		// Type 4 has no admitted shape, so validateControlMessage rejects it and
		// the strict LINK_CTRL reader ends the Link.
		frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, []byte{4, 0x01}, result.Generation, 100)
		if err != nil {
			t.Fatal(err)
		}
		if err := wire.WriteFrame(peer, frame); err != nil {
			t.Fatal(err)
		}
		waitAdmissionLinks(t, n, 0)
	})
}

// --- ReadMessage-origin E2E frame for an unadmitted SessionID ----------------

// e2eTagBytes is the frozen inner end-to-end ChaCha20-Poly1305 tag width: the
// hop layer treats the session ciphertext as opaque, so the envelope's inner_len
// is its length minus this tag.
const e2eTagBytes = 16

// TestControlPumpUnadmittedEndToEndSessionKeepsLinkServing proves the
// ReadMessage-origin frame-local rule on the real paired pump: a fully read E2E
// frame whose SessionID this Link never admitted is dropped and counted exactly
// once, and the shared physical STREAM Link keeps serving a later legitimate
// frame for an admitted Session as well as a fresh authenticated PING/PONG.
//
// The attack frame is sealed through the peer's real hop protector, so it is a
// genuine wire frame rather than a stub: the peer admits the SessionID locally
// (which is what derives its hop subkey) while this Link deliberately does not,
// exactly what an adjacent relay holding the Link root could do for a forged
// SessionID.
func TestControlPumpUnadmittedEndToEndSessionKeepsLinkServing(t *testing.T) {
	n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// A STREAM data lane is only accepted from a peer that already carries an
	// active CONTROL Link, so the same authenticated identity first opens the
	// CONTROL carrier, then the STREAM Link the E2E frames ride.
	_, controlIO, _ := dialControlPumpPeer(t, n, identity, laneControl, 42, 17)
	if controlIO == nil {
		t.Fatal("no CONTROL protected IO")
	}
	waitAdmissionLinks(t, n, 1)
	streamConn, streamIO, _ := dialControlPumpPeer(t, n, identity, laneStream, 43, 19)
	waitAdmissionLinks(t, n, 2)
	if err := streamConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	pump := pumpOnLane(t, n, laneStream)
	peerNode := pump.link.PeerNodeID()
	meta := pump.link.Metadata()
	scope := pathScope{id: 0x44, gen: 6}
	ps := &pathState{
		scope:      scope,
		lane:       path.LaneStream,
		nodes:      []topology.NodeID{topology.NodeID(peerNode), topology.NodeID(n.streams.localID)},
		links:      []topology.LinkRef{{ID: meta.LinkID, Epoch: meta.LinkEpoch, LaneID: meta.LaneID}},
		localIndex: 1,
		ready:      make(chan struct{}),
	}
	n.streams.registerPath(ps)

	// Session B is admitted on both sides and must stay healthy across the attack.
	var idB session.SessionID
	idB[0] = 0xb2
	entryB, peerB := streamProbeSession(t, n, streamIO, pump, ps, idB, peerNode)

	// Session U is admitted only by the peer, so its hop subkey exists on the
	// wire while this Link's admission table has no entry for it.
	var idU session.SessionID
	idU[0] = 0xa1
	if err := streamIO.AdmitSession([16]byte(idU), link.SessionClassStream); err != nil {
		t.Fatalf("peer-side admission for the unadmitted Session: %v", err)
	}
	ciphertext := bytes.Repeat([]byte{0x33}, 32)
	envelope := buildEnvelope(n.networkContext.WireID(), peerNode, n.streams.localID,
		wire.MessageTypeStreamData, [16]byte(idU), 1, 1, scope.id, scope.gen, len(ciphertext)-e2eTagBytes)

	skipper := newFactFrameSkipper(n, streamIO)
	before := n.rates.stats().FrameLocalRejected

	// The attack: one well-formed, fully read E2E frame naming an unadmitted
	// SessionID. On the unmodified reader this returns from read() and the
	// deferred Link close tears down the whole shared physical STREAM Link.
	if err := streamIO.WriteEndToEnd(envelope, ciphertext,
		link.HopRoute{Cursor: 1, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatalf("write the unadmitted-session frame: %v", err)
	}
	// A fresh authenticated PING on the same physical Link is still answered:
	// the reader survived the unadmitted frame and the writer still works.
	probe := bytes.Repeat([]byte{0x5a}, 16)
	if err := streamIO.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatalf("write the post-attack PING: %v", err)
	}
	got := readSkippingFacts(t, skipper, streamIO)
	if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatalf("post-unadmitted-frame PING/PONG mismatch: type=%d", got.Type)
	}
	// The frozen attribution rule requires the drop to be counted exactly once.
	if after := n.rates.stats().FrameLocalRejected; after != before+1 {
		t.Fatalf("FrameLocalRejected = %d after one unadmitted-session frame; want %d", after, before+1)
	}
	waitAdmissionLinks(t, n, 2)

	// The other admitted Session stays healthy on the same Link: a legitimate
	// authenticated STREAM_DATA frame is accepted and fails no Session.
	valid, err := circuit.StreamDataMessage{
		CircuitID: circuit.CircuitID{0x01},
		Flags:     circuit.FlagData,
		StreamSeq: 0,
		Payload:   []byte("x"),
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	envelopeB := buildEnvelope(n.networkContext.WireID(), peerNode, n.streams.localID,
		wire.MessageTypeStreamData, [16]byte(idB), 1, 1, scope.id, scope.gen, len(valid))
	sealedB, err := peerB.Seal(wire.Frame{Kind: wire.FrameKindEndToEnd, Envelope: envelopeB}, valid)
	if err != nil {
		t.Fatalf("seal the legitimate Session B frame: %v", err)
	}
	if err := streamIO.WriteEndToEnd(envelopeB, sealedB.Body,
		link.HopRoute{Cursor: 1, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatalf("write the legitimate Session B frame: %v", err)
	}
	waitAdmissionLinks(t, n, 2)
	if entryB.isTerminated() {
		t.Fatal("the unadmitted-session frame terminated another admitted Session")
	}
}

// TestControlPumpUnadmittedSessionBoundaryStaysFatal proves the new frame-local
// rule cannot keep a physically broken Link alive. After the reader has been
// shown to absorb an unadmitted-session E2E frame (a PING is still answered), a
// genuine link-layer failure on the same connection still closes the Link.
func TestControlPumpUnadmittedSessionBoundaryStaysFatal(t *testing.T) {
	t.Run("truncated frame closes the Link", func(t *testing.T) {
		n, peer, _, _ := controlPumpPeer(t)
		tcp, ok := peer.(*net.TCPConn)
		if !ok {
			t.Fatalf("peer connection is %T, want *net.TCPConn", peer)
		}
		// Announce a 64-byte body, deliver 8, then half-close: the reader sees a
		// half frame (TruncatedFrame), a link-layer failure that no classifier
		// may absorb.
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, 64)
		if _, err := peer.Write(append(header, make([]byte, 8)...)); err != nil {
			t.Fatal(err)
		}
		closeWriteToleratingPeerClose(t, tcp)
		waitAdmissionLinks(t, n, 0)
	})
	t.Run("unadmitted E2E frame absorbed, then truncation closes the Link", func(t *testing.T) {
		n, peer, control, _ := controlPumpPeer(t)
		skipper := newFactFrameSkipper(n, control)
		if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		tcp, ok := peer.(*net.TCPConn)
		if !ok {
			t.Fatalf("peer connection is %T, want *net.TCPConn", peer)
		}
		// The peer admits the SessionID locally so its hop subkey exists on the
		// wire; this Link never admits it, so ReadMessage rejects the frame.
		var idU session.SessionID
		idU[0] = 0xa1
		if err := control.AdmitSession([16]byte(idU), link.SessionClassStream); err != nil {
			t.Fatalf("peer-side admission: %v", err)
		}
		ciphertext := bytes.Repeat([]byte{0x33}, 32)
		envelope := buildEnvelope(n.networkContext.WireID(), [16]byte{0x0b}, n.streams.localID,
			wire.MessageTypeStreamData, [16]byte(idU), 1, 1, 7, 1, len(ciphertext)-e2eTagBytes)
		before := n.rates.stats().FrameLocalRejected
		if err := control.WriteEndToEnd(envelope, ciphertext,
			link.HopRoute{Cursor: 1, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
			t.Fatalf("write the unadmitted-session frame: %v", err)
		}
		// The matching PONG proves the unadmitted frame was absorbed rather than
		// fatal, and the aggregate counter moved exactly once.
		probe := bytes.Repeat([]byte{0x5a}, 16)
		if err := control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
			t.Fatal(err)
		}
		got := readSkippingFacts(t, skipper, control)
		if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
			t.Fatalf("post-unadmitted-frame PING/PONG mismatch: type=%d", got.Type)
		}
		if after := n.rates.stats().FrameLocalRejected; after != before+1 {
			t.Fatalf("FrameLocalRejected = %d after one unadmitted-session frame; want %d", after, before+1)
		}
		waitAdmissionLinks(t, n, 1)

		// The same connection now truncates a frame: the Link must still fail
		// closed, because TruncatedFrame is a link-layer failure.
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, 64)
		if _, err := peer.Write(append(header, make([]byte, 8)...)); err != nil {
			t.Fatal(err)
		}
		closeWriteToleratingPeerClose(t, tcp)
		waitAdmissionLinks(t, n, 0)
	})
}

// --- ReadMessage-origin pre-hop-AEAD structural rejections ------------------

// readMessageAttackHopHeader builds the 32-byte hop header of a raw
// ReadMessage-origin attack frame. hopPadOffset is the frozen 2-byte reserved
// pad at offset 30 and the pad and every other byte stay zero. The read-side
// structural checks read the LinkGeneration (0:4), the RouteCtrl/E2E counter
// (4:12), the redundant PathID (12:20) / PathGeneration (20:24) copies and that
// pad; cursor, hop limit and remaining budget are write-side/relay fields the
// read-side checks never inspect. It exists so a test can inject one exact
// frame that is structurally wrong in a chosen way but is still consumed
// completely by wire.ReadFrame.
func readMessageAttackHopHeader(generation uint32, counter uint64, pathID uint64, pathGeneration uint32) [wire.HopHeaderSize]byte {
	var header [wire.HopHeaderSize]byte
	binary.BigEndian.PutUint32(header[0:4], generation)
	binary.BigEndian.PutUint64(header[4:12], counter)
	binary.BigEndian.PutUint64(header[12:20], pathID)
	binary.BigEndian.PutUint32(header[20:24], pathGeneration)
	return header
}

// readMessageAttackLink is the paired pump both ReadMessage-origin tests need:
// the CONTROL carrier plus the STREAM data Link, a registered Session B that is
// admitted on both sides, and the raw peer connection the attack frame is
// injected on. It mirrors the landed unadmitted-session harness exactly, so the
// physical Link, the peer identity and the session protector are the genuine
// production objects rather than stubs.
type readMessageAttackLink struct {
	n        *network
	peer     net.Conn
	streamIO *link.ProtectedControlIO
	pump     *controlPump
	entryB   *sessionEntry
	peerB    *session.E2EProtector
	peerNode [16]byte
	scope    pathScope
	skipper  *factFrameSkipper
}

func newReadMessageAttackLink(t *testing.T) *readMessageAttackLink {
	t.Helper()
	n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// A STREAM data lane is only accepted from a peer that already carries an
	// active CONTROL Link, so the same authenticated identity first opens the
	// CONTROL carrier, then the STREAM Link the E2E frames ride.
	_, controlIO, _ := dialControlPumpPeer(t, n, identity, laneControl, 42, 17)
	if controlIO == nil {
		t.Fatal("no CONTROL protected IO")
	}
	waitAdmissionLinks(t, n, 1)
	streamConn, streamIO, _ := dialControlPumpPeer(t, n, identity, laneStream, 43, 19)
	waitAdmissionLinks(t, n, 2)
	if err := streamConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	pump := pumpOnLane(t, n, laneStream)
	peerNode := pump.link.PeerNodeID()
	meta := pump.link.Metadata()
	scope := pathScope{id: 0x44, gen: 6}
	ps := &pathState{
		scope:      scope,
		lane:       path.LaneStream,
		nodes:      []topology.NodeID{topology.NodeID(peerNode), topology.NodeID(n.streams.localID)},
		links:      []topology.LinkRef{{ID: meta.LinkID, Epoch: meta.LinkEpoch, LaneID: meta.LaneID}},
		localIndex: 1,
		ready:      make(chan struct{}),
	}
	n.streams.registerPath(ps)

	// Session B is admitted on both sides and must stay healthy across the
	// attack.
	var idB session.SessionID
	idB[0] = 0xb2
	entryB, peerB := streamProbeSession(t, n, streamIO, pump, ps, idB, peerNode)
	return &readMessageAttackLink{
		n: n, peer: streamConn, streamIO: streamIO, pump: pump,
		entryB: entryB, peerB: peerB, peerNode: peerNode, scope: scope,
		skipper: newFactFrameSkipper(n, streamIO),
	}
}

// assertServing proves the shared physical Link survived one dropped
// ReadMessage-origin frame: a fresh authenticated PING is still answered on the
// same Link, the aggregate FrameLocalRejected counter advanced by exactly one,
// and a later legitimate authenticated frame for the admitted Session B is
// still accepted without terminating that Session.
func (l *readMessageAttackLink) assertServing(t *testing.T, before uint64) {
	t.Helper()
	probe := bytes.Repeat([]byte{0x5a}, 16)
	if err := l.streamIO.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatalf("write the post-attack PING: %v", err)
	}
	got := readSkippingFacts(t, l.skipper, l.streamIO)
	if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatalf("post-attack PING/PONG mismatch: type=%d", got.Type)
	}
	if after := l.n.rates.stats().FrameLocalRejected; after != before+1 {
		t.Fatalf("FrameLocalRejected = %d after one dropped frame; want %d", after, before+1)
	}
	waitAdmissionLinks(t, l.n, 2)

	valid, err := circuit.StreamDataMessage{
		CircuitID: circuit.CircuitID{0x01},
		Flags:     circuit.FlagData,
		StreamSeq: 0,
		Payload:   []byte("x"),
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	envelopeB := buildEnvelope(l.n.networkContext.WireID(), l.peerNode, l.n.streams.localID,
		wire.MessageTypeStreamData, [16]byte(l.entryB.id), 1, 1, l.scope.id, l.scope.gen, len(valid))
	sealedB, err := l.peerB.Seal(wire.Frame{Kind: wire.FrameKindEndToEnd, Envelope: envelopeB}, valid)
	if err != nil {
		t.Fatalf("seal the legitimate Session B frame: %v", err)
	}
	if err := l.streamIO.WriteEndToEnd(envelopeB, sealedB.Body,
		link.HopRoute{Cursor: 1, HopLimit: 1, RemainingBudget: 1 << 20}); err != nil {
		t.Fatalf("write the legitimate Session B frame: %v", err)
	}
	waitAdmissionLinks(t, l.n, 2)
	if l.entryB.isTerminated() {
		t.Fatal("the dropped frame terminated the admitted Session B")
	}
}

// TestControlPumpReadMessageRouteMessageKeepsLinkServing proves the
// ReadMessage-origin frame-local rule for link.ErrRouteMessage: a fully read
// ROUTE_CTRL frame whose hop-header PathID copy disagrees with its envelope is
// rejected before the hop AEAD is verified, so the frame is dropped and counted
// exactly once while the shared physical STREAM Link keeps serving an admitted
// Session and a fresh authenticated PING/PONG.
func TestControlPumpReadMessageRouteMessageKeepsLinkServing(t *testing.T) {
	l := newReadMessageAttackLink(t)
	// PATH_OPEN reserves a zero SessionID, epoch and message number; the path is
	// non-zero, so the envelope is valid and the mismatch is the hop copy.
	envelope := buildEnvelope(l.n.networkContext.WireID(), l.peerNode, l.n.streams.localID,
		wire.MessageTypePathOpen, [16]byte{}, 0, 0, l.scope.id, l.scope.gen, 24)
	hop := readMessageAttackHopHeader(l.pump.link.Metadata().Generation, 1, l.scope.id+1, l.scope.gen)
	before := l.n.rates.stats().FrameLocalRejected
	if err := wire.WriteFrame(l.peer, wire.Frame{
		Kind:      wire.FrameKindRouteControl,
		HopHeader: hop,
		Envelope:  envelope,
		Body:      bytes.Repeat([]byte{0x11}, 24),
	}); err != nil {
		t.Fatalf("inject the malformed ROUTE_CTRL frame: %v", err)
	}
	l.assertServing(t, before)
}

// TestControlPumpReadMessageEndToEndMessageKeepsLinkServing proves the
// ReadMessage-origin frame-local rule for link.ErrEndToEndMessage: a fully read
// E2E frame whose hop nonce copies the envelope and whose inner_len matches its
// hop plaintext, but whose hop-header PathID copy disagrees with its envelope, is
// rejected by readEndToEndLocked's hop-path check before the hop AEAD is
// verified, so the frame is dropped and counted exactly once while the shared
// physical STREAM Link keeps serving an admitted Session and a fresh
// authenticated PING/PONG.
func TestControlPumpReadMessageEndToEndMessageKeepsLinkServing(t *testing.T) {
	l := newReadMessageAttackLink(t)
	// The 48-byte hop body is the only size that reaches the hop-path check: the
	// 16-byte inner plaintext plus the frozen 16-byte inner E2E tag plus the
	// 16-byte hop AEAD tag. readEndToEndLocked strips the hop AEAD tag, so
	// decodeEndToEndEnvelope sees hopPlaintextLen 32 == inner_len 16 +
	// e2eTagSize 16 and passes; the hop nonce copies the envelope (generation 1
	// and counter 1 equal key_epoch 1 and message_number 1), so the hop-path
	// comparison against the envelope path is the first check that can fail.
	var idA session.SessionID
	idA[0] = 0xa2
	envelope := buildEnvelope(l.n.networkContext.WireID(), l.peerNode, l.n.streams.localID,
		wire.MessageTypeStreamData, [16]byte(idA), 1, 1, l.scope.id, l.scope.gen, 16)
	hop := readMessageAttackHopHeader(1, 1, l.scope.id+1, l.scope.gen)
	before := l.n.rates.stats().FrameLocalRejected
	if err := wire.WriteFrame(l.peer, wire.Frame{
		Kind:      wire.FrameKindEndToEnd,
		HopHeader: hop,
		Envelope:  envelope,
		Body:      bytes.Repeat([]byte{0x22}, 48),
	}); err != nil {
		t.Fatalf("inject the malformed E2E frame: %v", err)
	}
	l.assertServing(t, before)
}

// TestControlPumpReadMessageSessionRetiredKeepsLinkServing proves the
// ReadMessage-origin frame-local rule for link.ErrSessionRetired: a fully read
// E2E frame that passes every envelope/hop-header redundancy check and names a
// SessionID this Link retired is rejected by withSession before the hop AEAD is
// verified, so the frame is dropped and counted exactly once while the shared
// physical Link keeps serving.
func TestControlPumpReadMessageSessionRetiredKeepsLinkServing(t *testing.T) {
	l := newReadMessageAttackLink(t)
	var idR session.SessionID
	idR[0] = 0xa3
	if err := l.pump.control.AdmitSession([16]byte(idR), link.SessionClassStream); err != nil {
		t.Fatalf("admit the soon-retired Session: %v", err)
	}
	if err := l.pump.control.RetireSession([16]byte(idR)); err != nil {
		t.Fatalf("retire the Session: %v", err)
	}
	// The hop body is 48 bytes: the 16-byte inner plaintext plus the frozen
	// 16-byte inner E2E tag plus the 16-byte hop AEAD tag. readEndToEndLocked
	// strips the hop AEAD tag, so decodeEndToEndEnvelope sees hopPlaintextLen
	// 32 == inner_len 16 + e2eTagSize 16 and passes instead of returning
	// ErrEndToEndMessage. The hop path matches the envelope and the hop nonce
	// copies the envelope, so readEndToEndLocked reaches withSession's retired
	// tombstone.
	envelope := buildEnvelope(l.n.networkContext.WireID(), l.peerNode, l.n.streams.localID,
		wire.MessageTypeStreamData, [16]byte(idR), 1, 1, l.scope.id, l.scope.gen, 16)
	hop := readMessageAttackHopHeader(1, 1, l.scope.id, l.scope.gen)
	before := l.n.rates.stats().FrameLocalRejected
	if err := wire.WriteFrame(l.peer, wire.Frame{
		Kind:      wire.FrameKindEndToEnd,
		HopHeader: hop,
		Envelope:  envelope,
		Body:      bytes.Repeat([]byte{0x33}, 48),
	}); err != nil {
		t.Fatalf("inject the retired-session E2E frame: %v", err)
	}
	l.assertServing(t, before)
}

// TestControlPumpReadMessageFrameLocalBoundaryStaysFatal proves the new
// ReadMessage-origin frame-local rules cannot keep a physically broken or unsafe
// Link alive. Each subtest drives one terminal origin through the real paired
// pump and asserts the physical Link really closes, so the fix is shown to widen
// only the named frame-local origins and nothing else.
func TestControlPumpReadMessageFrameLocalBoundaryStaysFatal(t *testing.T) {
	// Pins the link-layer rule: a half frame is TruncatedFrame, which the frozen
	// failure table calls a link failure. No kind guard and no counter guard may
	// absorb it.
	t.Run("truncated frame closes the Link", func(t *testing.T) {
		n, peer, _, _ := controlPumpPeer(t)
		tcp, ok := peer.(*net.TCPConn)
		if !ok {
			t.Fatalf("peer connection is %T, want *net.TCPConn", peer)
		}
		// Announce a 64-byte body, deliver 8, then half-close: the reader sees a
		// half frame (TruncatedFrame), a link-layer failure that no frame-local
		// classifier may absorb.
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, 64)
		if _, err := peer.Write(append(header, make([]byte, 8)...)); err != nil {
			t.Fatal(err)
		}
		closeWriteToleratingPeerClose(t, tcp)
		waitAdmissionLinks(t, n, 0)
	})
	// Pins the hop-AEAD rule: TamperDetected is terminal for the Link. The frame
	// is a genuine seal of this Link's own E2E hop key whose envelope, hop header,
	// redundant path copies and nonce are all exactly right, so every structural
	// and redundancy check passes and only the AEAD tag is corrupt.
	t.Run("hop AEAD tag failure closes the Link", func(t *testing.T) {
		n, peer, _, result := controlPumpPeer(t)
		pump := pumpOnLane(t, n, laneControl)
		var idT session.SessionID
		idT[0] = 0xb7
		if err := pump.control.AdmitSession([16]byte(idT), link.SessionClassStream); err != nil {
			t.Fatalf("admit the tampered-session ID on the ingress Link: %v", err)
		}
		const epoch, number = 1, 1
		const pathID, pathGeneration = 0x44, 6
		// A 32-byte session ciphertext (16 bytes of inner plaintext plus the
		// frozen inner E2E tag) is the shortest body the hop AEAD accepts; the
		// envelope's inner_len names the inner plaintext, not the ciphertext.
		inner := bytes.Repeat([]byte{0x4d}, 32)
		envelope := buildEnvelope(n.networkContext.WireID(), pump.link.PeerNodeID(), n.streams.localID,
			wire.MessageTypeStreamData, [16]byte(idT), epoch, number, pathID, pathGeneration, len(inner)-e2eTagBytes)
		// Rebuild the peer's own hop protector from its authenticated TX root, so
		// the seal is a real one under the exact key the ingress Link verifies.
		protector, err := link.NewFrameProtector(result.TxRoot, n.networkContext.Descriptor(), result.LinkID,
			[16]byte(idT), link.SessionClassStream, link.DirectionInitiatorToResponder)
		if err != nil {
			t.Fatalf("rebuild the peer hop protector: %v", err)
		}
		sealed, err := protector.Seal(wire.Frame{
			Kind:      wire.FrameKindEndToEnd,
			HopHeader: readMessageAttackHopHeader(epoch, number, pathID, pathGeneration),
			Envelope:  envelope,
		}, inner, epoch, number)
		if err != nil {
			t.Fatalf("seal the hop-valid frame: %v", err)
		}
		// Exactly one tag byte flips: the AAD (length, kind, hop header, envelope)
		// is untouched, so the frame still passes every structural check.
		sealed.Body[len(sealed.Body)-1] ^= 0x80
		if err := wire.WriteFrame(peer, sealed); err != nil {
			t.Fatalf("inject the tampered E2E frame: %v", err)
		}
		waitAdmissionLinks(t, n, 0)
	})
	// Pins the ErrCounterExhausted guard in readMessageEndToEndMessageClassOf: a
	// frame whose envelope message number is ^uint64(0) makes
	// decodeEndToEndEnvelope return errors.Join(ErrEndToEndMessage,
	// ErrCounterExhausted). Without that guard the joined sentinel would classify
	// the frame-local "end-to-end-message" class and this Link would survive.
	t.Run("counter exhaustion closes the Link", func(t *testing.T) {
		n, peer, _, _ := controlPumpPeer(t)
		pump := pumpOnLane(t, n, laneControl)
		var idE session.SessionID
		idE[0] = 0xb8
		if err := pump.control.AdmitSession([16]byte(idE), link.SessionClassStream); err != nil {
			t.Fatalf("admit the counter-exhausted-session ID on the ingress Link: %v", err)
		}
		const pathID, pathGeneration = 0x44, 6
		envelope := buildEnvelope(n.networkContext.WireID(), pump.link.PeerNodeID(), n.streams.localID,
			wire.MessageTypeStreamData, [16]byte(idE), 1, ^uint64(0), pathID, pathGeneration, 16)
		if err := wire.WriteFrame(peer, wire.Frame{
			Kind:      wire.FrameKindEndToEnd,
			HopHeader: readMessageAttackHopHeader(1, ^uint64(0), pathID, pathGeneration),
			Envelope:  envelope,
			Body:      bytes.Repeat([]byte{0x77}, 32),
		}); err != nil {
			t.Fatalf("inject the counter-exhausted E2E frame: %v", err)
		}
		waitAdmissionLinks(t, n, 0)
	})
}

// teeConn wraps a net.Conn and records every byte written through it, so a test can
// capture the exact wire bytes of a frame it just sent and replay them verbatim. It
// exists because ProtectedControlIO allocates its own counters: sealing a frame by
// hand with a chosen counter collides with the counters the same Link allocates for
// FACT traffic, and the collision shows up as a spurious replay.
type teeConn struct {
	net.Conn
	mu      sync.Mutex
	capture bytes.Buffer
}

func newTeeConn(conn net.Conn) *teeConn { return &teeConn{Conn: conn} }

func (c *teeConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	if n > 0 {
		c.capture.Write(p[:n])
	}
	c.mu.Unlock()
	return n, err
}

// take returns everything captured since the previous call.
func (c *teeConn) take() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]byte(nil), c.capture.Bytes()...)
	c.capture.Reset()
	return out
}

// drainUntilClosed reads and discards frames until the peer returns EOF or reports a
// closed connection. A retired Link can still have queued frames in flight, so a
// single read is not a reliable signal that the stream ended.
func drainUntilClosed(conn net.Conn) error {
	buf := make([]byte, 512)
	for {
		_, err := conn.Read(buf)
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
