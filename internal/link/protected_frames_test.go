package link

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/wire"
)

// memoryStream is a scripted duplex stream: inbound bytes are served to the
// reader and outbound bytes are captured, so a test can inject exact frames and
// count exactly how many bytes a reader consumed.
type memoryStream struct {
	src     io.Reader
	written bytes.Buffer
	reads   int
}

func (s *memoryStream) Read(p []byte) (int, error) {
	n, err := s.src.Read(p)
	s.reads += n
	return n, err
}

func (s *memoryStream) Write(p []byte) (int, error) { return s.written.Write(p) }
func (s *memoryStream) Close() error                { return nil }

func encodeFrame(t *testing.T, frame wire.Frame) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := wire.WriteFrame(&encoded, frame); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

// peerProtectorFor builds the protector the peer would use to SEAL a frame
// toward the local side (derived from the peer's TX root), with an explicit
// SessionClass for E2E. direction is the wire direction label of the sender.
func peerProtectorFor(t *testing.T, pair controlPair, sessionID [16]byte, class, direction byte) *FrameProtector {
	t.Helper()
	protector, err := NewFrameProtector(pair.br.TxRoot, pair.descriptor, pair.br.LinkID, sessionID, class, direction)
	if err != nil {
		t.Fatal(err)
	}
	return protector
}

// receiverProtectorFor independently derives what the peer uses to AUTHENTICATE
// a frame sent by the local side (the peer's RX root plus the canonical
// initiator->responder or reverse direction label).
func receiverProtectorFor(t *testing.T, pair controlPair, sessionID [16]byte, class, direction byte) *FrameProtector {
	t.Helper()
	protector, err := NewFrameProtector(pair.br.RxRoot, pair.descriptor, pair.br.LinkID, sessionID, class, direction)
	if err != nil {
		t.Fatal(err)
	}
	return protector
}

func sealPeerFrame(t *testing.T, protector *FrameProtector, kind wire.FrameKind, envelope []byte, hop HopRoute, payload []byte, generation uint32, counter uint64) wire.Frame {
	t.Helper()
	frame := wire.Frame{Kind: kind, Envelope: envelope}
	if kind != wire.FrameKindLinkControl {
		pathID := binary.BigEndian.Uint64(envelope[wire.EnvelopePathIDOffset:])
		pathGeneration := binary.BigEndian.Uint32(envelope[wire.EnvelopePathGenerationOffset:])
		frame.HopHeader = makeHopHeader(pathID, pathGeneration, hop)
	}
	sealed, err := protector.Seal(frame, payload, generation, counter)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func routeEnvelope(messageType wire.MessageType, sessionID [16]byte, pathID uint64, pathGeneration uint32, payloadLength int) []byte {
	envelope := make([]byte, wire.EnvelopeSize)
	binary.BigEndian.PutUint64(envelope, 0x1122334455667788)
	copy(envelope[8:24], bytes.Repeat([]byte{0xa1}, 16))
	copy(envelope[24:40], bytes.Repeat([]byte{0xb2}, 16))
	envelope[wire.EnvelopeMessageTypeOffset] = byte(messageType)
	copy(envelope[wire.EnvelopeSessionIDOffset:wire.EnvelopeKeyEpochOffset], sessionID[:])
	binary.BigEndian.PutUint64(envelope[wire.EnvelopePathIDOffset:], pathID)
	binary.BigEndian.PutUint32(envelope[wire.EnvelopePathGenerationOffset:], pathGeneration)
	binary.BigEndian.PutUint32(envelope[wire.EnvelopeInnerLengthOffset:], uint32(payloadLength))
	return envelope
}

func newEndToEndEnvelope(sessionID [16]byte, messageType wire.MessageType, keyEpoch uint32, messageNumber uint64, pathID uint64, pathGeneration uint32, innerLength int) []byte {
	envelope := make([]byte, wire.EnvelopeSize)
	binary.BigEndian.PutUint64(envelope, 0x8877665544332211)
	copy(envelope[8:24], bytes.Repeat([]byte{0xc3}, 16))
	copy(envelope[24:40], bytes.Repeat([]byte{0xd4}, 16))
	envelope[wire.EnvelopeMessageTypeOffset] = byte(messageType)
	copy(envelope[wire.EnvelopeSessionIDOffset:wire.EnvelopeKeyEpochOffset], sessionID[:])
	binary.BigEndian.PutUint32(envelope[wire.EnvelopeKeyEpochOffset:], keyEpoch)
	binary.BigEndian.PutUint64(envelope[wire.EnvelopeMessageNumberOffset:], messageNumber)
	binary.BigEndian.PutUint64(envelope[wire.EnvelopePathIDOffset:], pathID)
	binary.BigEndian.PutUint32(envelope[wire.EnvelopePathGenerationOffset:], pathGeneration)
	binary.BigEndian.PutUint32(envelope[wire.EnvelopeInnerLengthOffset:], uint32(innerLength))
	return envelope
}

func testSessionID(seed byte) [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = seed
	}
	id[0], id[15] = seed, seed^0x5a
	return id
}

// indexedSessionID returns a unique non-zero SessionID for a table index.
func indexedSessionID(i int) [16]byte {
	var id [16]byte
	binary.BigEndian.PutUint64(id[:8], uint64(i)+1)
	id[15] = 0x5a
	return id
}

var testHop = HopRoute{Cursor: 0, HopLimit: 16, RemainingBudget: 45_000}

func TestProtectedFramesInterleaveLinkRouteAndEndToEndBothDirections(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0x31)
	for _, side := range []*ProtectedControlIO{pair.a, pair.b} {
		if err := side.AdmitSession(sessionID, SessionClassStream); err != nil {
			t.Fatal(err)
		}
	}
	probe := bytes.Repeat([]byte{0x0e}, 16)
	ciphertext := bytes.Repeat([]byte{0x51}, 40) // 24-byte opaque inner payload + 16-byte tag
	routePayload := []byte{0x00, 0x01, 0x02, 0x03}
	inner := len(ciphertext) - e2eTagSize
	writeDone := make(chan error, 1)

	// a -> b: LINK_CTRL (counter 1 after the CAPABILITY counter 0), ROUTE_CTRL
	// (counter 0) and an admitted E2E frame (envelope epoch/message number).
	if got := sendControl(t, pair.a, pair.b, 1, probe); got.Type != 1 || !bytes.Equal(got.Payload, probe) {
		t.Fatal("LINK_CTRL did not round-trip")
	}
	go func() {
		writeDone <- pair.a.WriteRoute(routeEnvelope(wire.MessageTypeSessionCtrl, sessionID, 7, 3, len(routePayload)), routePayload, testHop)
	}()
	route, err := pair.b.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if route.Kind != wire.FrameKindRouteControl || !bytes.Equal(route.Payload, routePayload) {
		t.Fatal("ROUTE_CTRL did not round-trip")
	}
	if route.Envelope[wire.EnvelopeMessageTypeOffset] != byte(wire.MessageTypeSessionCtrl) {
		t.Fatal("ROUTE_CTRL envelope was not delivered")
	}
	go func() {
		writeDone <- pair.a.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 7, 3, inner), ciphertext, testHop)
	}()
	message, err := pair.b.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if message.Kind != wire.FrameKindEndToEnd || !bytes.Equal(message.Payload, ciphertext) {
		t.Fatal("E2E ciphertext was not delivered opaquely")
	}
	if message.Class != SessionClassStream {
		t.Fatalf("E2E class = 0x%02x", message.Class)
	}

	// b -> a: the same three kinds in reverse order, reusing the same
	// SessionID: the hop key must be direction-specific, not a shared secret.
	if got := sendControl(t, pair.b, pair.a, 2, probe); got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatal("reverse LINK_CTRL did not round-trip")
	}
	reverseRoute := routeEnvelope(wire.MessageTypePathOpen, [16]byte{}, 11, 5, len(routePayload))
	go func() { writeDone <- pair.b.WriteRoute(reverseRoute, routePayload, testHop) }()
	if _, err := pair.a.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	go func() {
		writeDone <- pair.b.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 11, 5, inner), ciphertext, testHop)
	}()
	message, err = pair.a.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if message.Kind != wire.FrameKindEndToEnd || !bytes.Equal(message.Payload, ciphertext) {
		t.Fatal("reverse E2E ciphertext was not delivered")
	}

	// Per-domain counters are independent: LINK_CTRL continues at 1 after the
	// consumed CAPABILITY counter 0, ROUTE_CTRL owns its own domain from 0, and
	// the E2E hop counter copies the envelope nonce.
	if pair.a.txNext != 2 || pair.a.rxLast != 1 || pair.a.routeNext != 1 || !pair.a.routeSeen || pair.a.routeLast != 0 {
		t.Fatalf("a counters txNext=%d rxLast=%d routeNext=%d routeSeen=%v routeLast=%d",
			pair.a.txNext, pair.a.rxLast, pair.a.routeNext, pair.a.routeSeen, pair.a.routeLast)
	}
	if pair.b.txNext != 2 || pair.b.rxLast != 1 || pair.b.routeNext != 1 || !pair.b.routeSeen || pair.b.routeLast != 0 {
		t.Fatalf("b counters txNext=%d rxLast=%d routeNext=%d routeSeen=%v routeLast=%d",
			pair.b.txNext, pair.b.rxLast, pair.b.routeNext, pair.b.routeSeen, pair.b.routeLast)
	}
	// The hop layer never commits E2E replay state: only the session layer can,
	// after its own tag verification.
	if entry := pair.b.sessions[sessionID]; entry.rxSeen {
		t.Fatal("hop layer committed E2E replay state")
	}
	if entry := pair.a.sessions[sessionID]; entry.rxSeen {
		t.Fatal("hop layer committed E2E replay state")
	}
}

func TestProtectedRouteCounterStartsAtZeroInLinkGenerationDomain(t *testing.T) {
	pair := establishedControlPair(t)
	stream := &memoryStream{src: bytes.NewReader(nil)}
	writer, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if writer.txNext != 1 || writer.routeNext != 0 {
		t.Fatalf("handoff counters txNext=%d routeNext=%d; want 1 and 0", writer.txNext, writer.routeNext)
	}
	payload := []byte{0x09, 0x08, 0x07}
	envelope := routeEnvelope(wire.MessageTypePathOpen, [16]byte{}, 42, 9, len(payload))
	for want := uint64(0); want < 2; want++ {
		if err := writer.WriteRoute(envelope, payload, testHop); err != nil {
			t.Fatal(err)
		}
	}
	reader := bytes.NewReader(stream.written.Bytes())
	peer := receiverProtectorFor(t, pair, [16]byte{}, SessionClassStream, DirectionInitiatorToResponder)
	for want := uint64(0); want < 2; want++ {
		frame, err := wire.ReadFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		if got := binary.BigEndian.Uint32(frame.HopHeader[:4]); got != pair.ar.Generation {
			t.Fatalf("route generation = %d; want LinkGeneration %d", got, pair.ar.Generation)
		}
		if got := binary.BigEndian.Uint64(frame.HopHeader[4:12]); got != want {
			t.Fatalf("route counter = %d; want %d", got, want)
		}
		pathID := binary.BigEndian.Uint64(frame.HopHeader[12:20])
		pathGeneration := binary.BigEndian.Uint32(frame.HopHeader[20:24])
		if pathID != 42 || pathGeneration != 9 {
			t.Fatalf("hop path = %d/%d; want envelope copies 42/9", pathID, pathGeneration)
		}
		if frame.HopHeader[hopPadOffset] != 0 || frame.HopHeader[hopPadOffset+1] != 0 {
			t.Fatal("hop pad was not zero")
		}
		if frame.HopHeader[24] != testHop.Cursor || frame.HopHeader[25] != testHop.HopLimit {
			t.Fatal("hop route fields were not carried")
		}
		plaintext, err := peer.Verify(frame)
		if err != nil {
			t.Fatalf("peer could not authenticate route frame: %v", err)
		}
		if !bytes.Equal(plaintext, payload) {
			t.Fatal("route payload changed in transit")
		}
	}
	// The CAPABILITY counter 0 was consumed by Handshake: the link floor rejects
	// the counter-0 replay while ROUTE_CTRL independently owns its own 0.
	capability, err := EncodeCapability(Capability{Version: CapabilityVersion, Bits: RequiredCapabilityMask})
	if err != nil {
		t.Fatal(err)
	}
	control := peerProtectorFor(t, pair, [16]byte{}, SessionClassStream, DirectionResponderToInitiator)
	capFrame := sealPeerFrame(t, control, wire.FrameKindLinkControl, nil, HopRoute{}, append([]byte{4}, capability...), pair.br.Generation, 0)
	injected := &memoryStream{src: bytes.NewReader(encodeFrame(t, capFrame))}
	linkReader, err := NewProtectedControlIO(injected, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := linkReader.ReadControl(); !errors.Is(err, ErrReplay) {
		t.Fatalf("CAPABILITY counter 0 replay = %v", err)
	}
	if linkReader.rxLast != 0 {
		t.Fatal("counter-0 replay advanced the link floor")
	}
}

func TestProtectedRouteReplayAndTamperDoNotAdvanceFloor(t *testing.T) {
	pair := establishedControlPair(t)
	peer := peerProtectorFor(t, pair, [16]byte{}, SessionClassStream, DirectionResponderToInitiator)
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	envelope := func() []byte {
		return routeEnvelope(wire.MessageTypeSessionCtrl, testSessionID(0x11), 5, 2, len(payload))
	}

	good := sealPeerFrame(t, peer, wire.FrameKindRouteControl, envelope(), testHop, payload, pair.br.Generation, 0)
	stream := &memoryStream{src: bytes.NewReader(encodeFrame(t, good))}
	reader, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	message, err := reader.ReadMessage()
	if err != nil || !bytes.Equal(message.Payload, payload) {
		t.Fatalf("route frame = %v (%v)", message.Payload, err)
	}
	if !reader.routeSeen || reader.routeLast != 0 {
		t.Fatalf("route floor = %v/%d", reader.routeSeen, reader.routeLast)
	}
	// A second copy of the same frame is read from the same stream.
	stream.src = bytes.NewReader(encodeFrame(t, good))
	if _, err := reader.ReadMessage(); !errors.Is(err, ErrReplay) {
		t.Fatalf("route replay = %v", err)
	}
	if reader.routeLast != 0 {
		t.Fatal("route replay advanced the floor")
	}

	// A forged high counter must not poison the floor: the tag fails and the
	// next legitimate (lower) counter is still accepted.
	forged := sealPeerFrame(t, peer, wire.FrameKindRouteControl, envelope(), testHop, payload, pair.br.Generation, 99_999)
	forged.Body[0] ^= 0xff
	next := sealPeerFrame(t, peer, wire.FrameKindRouteControl, envelope(), testHop, payload, pair.br.Generation, 1)
	script := append(encodeFrame(t, forged), encodeFrame(t, next)...)
	reader, err = NewProtectedControlIO(&memoryStream{src: bytes.NewReader(script)}, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadMessage(); err == nil {
		t.Fatal("tampered route ciphertext passed")
	}
	if reader.routeSeen {
		t.Fatal("tampered route frame advanced the floor")
	}
	if _, err := reader.ReadMessage(); err != nil {
		t.Fatalf("valid frame after tamper = %v", err)
	}
	if !reader.routeSeen || reader.routeLast != 1 {
		t.Fatalf("route floor after recovery = %v/%d", reader.routeSeen, reader.routeLast)
	}
}

func TestProtectedEndToEndNonceCopiesEnvelopeAndMatchesAdmittedHopKey(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0x22)
	stream := &memoryStream{src: bytes.NewReader(nil)}
	writer, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AdmitSession(sessionID, SessionClassPacket); err != nil {
		t.Fatal(err)
	}
	ciphertext := bytes.Repeat([]byte{0x77}, 32)
	envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeIPPacket, 4, 12, 6, 2, len(ciphertext)-e2eTagSize)
	if err := writer.WriteEndToEnd(envelope, ciphertext, testHop); err != nil {
		t.Fatal(err)
	}
	frame, err := wire.ReadFrame(bytes.NewReader(stream.written.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(frame.HopHeader[:4]); got != 4 {
		t.Fatalf("hop generation = %d; want envelope KeyEpoch 4", got)
	}
	if got := binary.BigEndian.Uint64(frame.HopHeader[4:12]); got != 12 {
		t.Fatalf("hop counter = %d; want envelope MessageNumber 12", got)
	}
	// The hop subkey must be exactly the existing purpose/KDF output keyed by
	// (LinkID, SessionID, class, direction) over the full descriptor: the peer,
	// which derives it independently from its RX root, authenticates it.
	peer, err := NewFrameProtector(pair.br.RxRoot, pair.descriptor, pair.br.LinkID, sessionID, SessionClassPacket, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := peer.Verify(frame)
	if err != nil {
		t.Fatalf("peer hop key did not match: %v", err)
	}
	if !bytes.Equal(plaintext, ciphertext) {
		t.Fatal("E2E ciphertext changed in transit")
	}
	// A different descriptor, class or SessionID must not authenticate it.
	for name, protector := range map[string]*FrameProtector{
		"descriptor": mustProtector(t, pair.br.RxRoot, []byte("another-full-descriptor"), pair.br.LinkID, sessionID, SessionClassPacket, DirectionInitiatorToResponder),
		"class":      mustProtector(t, pair.br.RxRoot, pair.descriptor, pair.br.LinkID, sessionID, SessionClassStream, DirectionInitiatorToResponder),
		"session":    mustProtector(t, pair.br.RxRoot, pair.descriptor, pair.br.LinkID, testSessionID(0x23), SessionClassPacket, DirectionInitiatorToResponder),
		"direction":  mustProtector(t, pair.br.RxRoot, pair.descriptor, pair.br.LinkID, sessionID, SessionClassPacket, DirectionResponderToInitiator),
	} {
		if _, err := protector.Verify(frame); err == nil {
			t.Fatalf("frame authenticated under a different %s", name)
		}
	}
}

func mustProtector(t *testing.T, root [32]byte, descriptor []byte, linkID uint64, sessionID [16]byte, class, direction byte) *FrameProtector {
	t.Helper()
	protector, err := NewFrameProtector(root, descriptor, linkID, sessionID, class, direction)
	if err != nil {
		t.Fatal(err)
	}
	return protector
}

func TestProtectedEndToEndOpaquePayloadAndTxNonceMonotonic(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0x33)
	stream := &memoryStream{src: bytes.NewReader(nil)}
	writer, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	// The payload is not valid session crypto and must still round-trip: this
	// seam never interprets it.
	ciphertext := bytes.Repeat([]byte{0x5c}, 24)
	inner := len(ciphertext) - e2eTagSize
	if err := writer.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 3, 1, inner), ciphertext, testHop); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 3, 1, inner), ciphertext, testHop); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("reused (epoch,message number) = %v", err)
	}
	if err := writer.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 3, 1, inner), ciphertext, testHop); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("lower nonce = %v", err)
	}
	frame, err := wire.ReadFrame(bytes.NewReader(stream.written.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint64(frame.HopHeader[4:12]); got != 1 {
		t.Fatalf("second frame reached the wire at counter %d", got)
	}
	if err := writer.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeControlRPC, 1, 2, 3, 1, inner), ciphertext, testHop); err != nil {
		t.Fatal(err)
	}
	// A higher epoch also advances, and the floor never moves backwards.
	if err := writer.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 2, 0, 3, 1, inner), ciphertext, testHop); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 2, 3, 1, inner), ciphertext, testHop); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("old epoch after a new epoch = %v", err)
	}
	if entry := writer.sessions[sessionID]; entry.txEpoch != 2 || entry.txCounter != 0 {
		t.Fatal("TX floor did not track the last emitted nonce")
	}
}

func TestProtectedUnknownSessionIsNotAllocated(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0x44)
	peer := peerProtectorFor(t, pair, sessionID, SessionClassPacket, DirectionResponderToInitiator)
	ciphertext := bytes.Repeat([]byte{0x10}, 32)
	envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeIPPacket, 1, 1, 4, 1, len(ciphertext)-e2eTagSize)
	frame := sealPeerFrame(t, peer, wire.FrameKindEndToEnd, envelope, testHop, ciphertext, 1, 1)

	stream := &memoryStream{src: bytes.NewReader(encodeFrame(t, frame))}
	reader, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	message, err := reader.ReadMessage()
	if !errors.Is(err, ErrSessionNotAdmitted) {
		t.Fatalf("unknown session = %v", err)
	}
	if message.Kind != wire.FrameKindEndToEnd {
		t.Fatal("rejection did not report the frame kind")
	}
	if len(reader.sessions) != 0 {
		t.Fatal("an untrusted envelope allocated session state")
	}
	if reader.terminal.Load() {
		t.Fatal("unknown session ended the link")
	}
	if err := reader.AdmitSession(sessionID, SessionClassPacket); err != nil {
		t.Fatal(err)
	}
	// TX for an unadmitted session must also spend nothing.
	writer, err := NewProtectedControlIO(&memoryStream{src: bytes.NewReader(nil)}, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteEndToEnd(envelope, ciphertext, testHop); !errors.Is(err, ErrSessionNotAdmitted) {
		t.Fatalf("unadmitted TX = %v", err)
	}
	if len(writer.sessions) != 0 {
		t.Fatal("rejected TX allocated session state")
	}
}

func TestProtectedSessionAdmissionBoundsConflictAndRetirement(t *testing.T) {
	pair := establishedControlPair(t)
	stream := &memoryStream{src: bytes.NewReader(nil)}
	control, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := testSessionID(0x55)
	if err := control.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	if err := control.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatalf("idempotent admission = %v", err)
	}
	if err := control.AdmitSession(sessionID, SessionClassPacket); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("class conflict = %v", err)
	}
	if err := control.AdmitSession([16]byte{}, SessionClassStream); !errors.Is(err, ErrSessionNotAdmitted) {
		t.Fatalf("zero SessionID = %v", err)
	}
	if err := control.AdmitSession(sessionID, 0x00); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("invalid class = %v", err)
	}
	if err := control.RetireSession(testSessionID(0x66)); !errors.Is(err, ErrSessionNotAdmitted) {
		t.Fatalf("retire unknown = %v", err)
	}
	if err := control.RetireSession(sessionID); err != nil {
		t.Fatal(err)
	}
	if err := control.RetireSession(sessionID); err != nil {
		t.Fatalf("idempotent retire = %v", err)
	}
	if err := control.AdmitSession(sessionID, SessionClassStream); !errors.Is(err, ErrSessionRetired) {
		t.Fatalf("re-admission of a retired SessionID = %v", err)
	}
	// A retired SessionID must not accept frames or be flipped back.
	peer := peerProtectorFor(t, pair, sessionID, SessionClassStream, DirectionResponderToInitiator)
	ciphertext := bytes.Repeat([]byte{0x21}, 32)
	envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 4, 1, len(ciphertext)-e2eTagSize)
	frame := sealPeerFrame(t, peer, wire.FrameKindEndToEnd, envelope, testHop, ciphertext, 1, 1)
	retired, err := NewProtectedControlIO(&memoryStream{src: bytes.NewReader(encodeFrame(t, frame))}, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := retired.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	if err := retired.RetireSession(sessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := retired.ReadMessage(); !errors.Is(err, ErrSessionRetired) {
		t.Fatalf("frame for retired session = %v", err)
	}
	if err := retired.CommitEndToEnd(sessionID, 1, 1); !errors.Is(err, ErrSessionRetired) {
		t.Fatalf("commit for retired session = %v", err)
	}
	// The bounded table counts live and retired admissions together.
	full, err := NewProtectedControlIO(&memoryStream{src: bytes.NewReader(nil)}, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxAdmittedSessions; i++ {
		if err := full.AdmitSession(indexedSessionID(i), SessionClassStream); err != nil {
			t.Fatalf("admission %d: %v", i, err)
		}
	}
	if err := full.AdmitSession(indexedSessionID(MaxAdmittedSessions), SessionClassStream); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("table overflow = %v", err)
	}
	if err := full.AdmitSession(indexedSessionID(MaxAdmittedSessions-1), SessionClassStream); err != nil {
		t.Fatalf("existing admission after overflow = %v", err)
	}
}

func TestProtectedEndToEndReplayFloorRequiresExplicitCommit(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0x77)
	peer := peerProtectorFor(t, pair, sessionID, SessionClassStream, DirectionResponderToInitiator)
	ciphertext := bytes.Repeat([]byte{0x42}, 32)
	inner := len(ciphertext) - e2eTagSize
	seal := func(epoch uint32, number uint64) wire.Frame {
		envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, epoch, number, 2, 1, inner)
		return sealPeerFrame(t, peer, wire.FrameKindEndToEnd, envelope, testHop, ciphertext, epoch, number)
	}
	first, poison, legit := seal(1, 1), seal(1, 99_999), seal(1, 2)

	// A hop-valid frame with a forged inner tag carries a huge MessageNumber and
	// must not poison the E2E floor: the inner tag is not this layer's to check,
	// so this layer must not commit anything at all.
	script := append(append(encodeFrame(t, first), encodeFrame(t, poison)...), encodeFrame(t, legit)...)
	stream := &memoryStream{src: bytes.NewReader(script)}
	reader, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		message, err := reader.ReadMessage()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(message.Payload, ciphertext) {
			t.Fatalf("frame %d ciphertext changed", i)
		}
	}
	if entry := reader.sessions[sessionID]; entry.rxSeen {
		t.Fatal("hop layer committed E2E replay state before the inner tag")
	}

	// The session layer authenticates `first` and commits (1,1). A frame at or
	// below the committed floor is then rejected read-only, without any AEAD.
	if err := reader.CommitEndToEnd(sessionID, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := reader.CommitEndToEnd(sessionID, 1, 1); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate commit = %v", err)
	}
	if err := reader.CommitEndToEnd(sessionID, 0, 5); !errors.Is(err, ErrEndToEndMessage) {
		t.Fatalf("zero-epoch commit = %v", err)
	}
	stream.src = bytes.NewReader(encodeFrame(t, first))
	if _, err := reader.ReadMessage(); !errors.Is(err, ErrReplay) {
		t.Fatalf("frame at or below the committed floor = %v", err)
	}
	// Frames above the floor are still delivered (the hop layer cannot judge the
	// inner tag), and delivery still does not move the floor.
	stream.src = bytes.NewReader(append(encodeFrame(t, legit), encodeFrame(t, poison)...))
	if _, err := reader.ReadMessage(); err != nil {
		t.Fatalf("legit frame above the floor = %v", err)
	}
	if _, err := reader.ReadMessage(); err != nil {
		t.Fatalf("poison frame above the floor = %v", err)
	}
	if entry := reader.sessions[sessionID]; entry.rxEpoch != 1 || entry.rxCounter != 1 {
		t.Fatal("delivery moved the committed floor")
	}
	// A tampered hop tag must neither deliver nor move the floor.
	tampered := seal(1, 5)
	tampered.Body[0] ^= 0xff
	tamperedIO, err := NewProtectedControlIO(&memoryStream{src: bytes.NewReader(encodeFrame(t, tampered))}, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := tamperedIO.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	if _, err := tamperedIO.ReadMessage(); err == nil {
		t.Fatal("tampered E2E hop tag passed")
	}
	if entry := tamperedIO.sessions[sessionID]; entry.rxSeen {
		t.Fatal("tampered E2E frame advanced the floor")
	}
}

func TestProtectedRedundantBindingsRejectedWithoutFloorMovement(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0x88)
	if err := func() error {
		io, err := NewProtectedControlIO(&memoryStream{src: bytes.NewReader(nil)}, pair.ar, pair.descriptor, true)
		if err != nil {
			return err
		}
		return io.AdmitSession(sessionID, SessionClassStream)
	}(); err != nil {
		t.Fatal(err)
	}
	peer := peerProtectorFor(t, pair, sessionID, SessionClassStream, DirectionResponderToInitiator)
	routePeer := peerProtectorFor(t, pair, [16]byte{}, SessionClassStream, DirectionResponderToInitiator)
	ciphertext := bytes.Repeat([]byte{0x63}, 32)
	inner := len(ciphertext) - e2eTagSize
	routePayload := []byte{1, 2, 3, 4}

	cases := []struct {
		name  string
		frame func() wire.Frame
		want  error
	}{
		{"route hop path mismatch", func() wire.Frame {
			envelope := routeEnvelope(wire.MessageTypeSessionCtrl, sessionID, 5, 2, len(routePayload))
			frame := sealPeerFrame(t, routePeer, wire.FrameKindRouteControl, envelope, testHop, routePayload, pair.br.Generation, 0)
			binary.BigEndian.PutUint64(frame.HopHeader[12:20], 6)
			return frame
		}, ErrRouteMessage},
		{"route non-zero pad", func() wire.Frame {
			frame := sealPeerFrame(t, routePeer, wire.FrameKindRouteControl, routeEnvelope(wire.MessageTypeSessionCtrl, sessionID, 5, 2, len(routePayload)), testHop, routePayload, pair.br.Generation, 0)
			frame.HopHeader[hopPadOffset] = 1
			return frame
		}, ErrRouteMessage},
		{"route wrong generation", func() wire.Frame {
			return sealPeerFrame(t, routePeer, wire.FrameKindRouteControl, routeEnvelope(wire.MessageTypeSessionCtrl, sessionID, 5, 2, len(routePayload)), testHop, routePayload, pair.br.Generation+1, 0)
		}, ErrRouteMessage},
		{"route reserved key epoch", func() wire.Frame {
			envelope := routeEnvelope(wire.MessageTypeSessionCtrl, sessionID, 5, 2, len(routePayload))
			binary.BigEndian.PutUint32(envelope[wire.EnvelopeKeyEpochOffset:], 3)
			return sealPeerFrame(t, routePeer, wire.FrameKindRouteControl, envelope, testHop, routePayload, pair.br.Generation, 0)
		}, ErrRouteMessage},
		{"route path message with a session id", func() wire.Frame {
			return sealPeerFrame(t, routePeer, wire.FrameKindRouteControl, routeEnvelope(wire.MessageTypePathOpen, sessionID, 5, 2, len(routePayload)), testHop, routePayload, pair.br.Generation, 0)
		}, ErrRouteMessage},
		{"route inner length mismatch", func() wire.Frame {
			envelope := routeEnvelope(wire.MessageTypeSessionCtrl, sessionID, 5, 2, len(routePayload))
			binary.BigEndian.PutUint32(envelope[wire.EnvelopeInnerLengthOffset:], 99)
			return sealPeerFrame(t, routePeer, wire.FrameKindRouteControl, envelope, testHop, routePayload, pair.br.Generation, 0)
		}, ErrRouteMessage},
		{"route zero envelope path", func() wire.Frame {
			return sealPeerFrame(t, routePeer, wire.FrameKindRouteControl, routeEnvelope(wire.MessageTypeSessionCtrl, sessionID, 0, 0, len(routePayload)), testHop, routePayload, pair.br.Generation, 0)
		}, ErrRouteMessage},
		{"e2e hop nonce mismatch", func() wire.Frame {
			envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 4, 2, 1, inner)
			frame := sealPeerFrame(t, peer, wire.FrameKindEndToEnd, envelope, testHop, ciphertext, 1, 4)
			binary.BigEndian.PutUint32(frame.HopHeader[:4], 2)
			return frame
		}, ErrEndToEndMessage},
		{"e2e hop path mismatch", func() wire.Frame {
			envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 4, 2, 1, inner)
			frame := sealPeerFrame(t, peer, wire.FrameKindEndToEnd, envelope, testHop, ciphertext, 1, 4)
			binary.BigEndian.PutUint64(frame.HopHeader[12:20], 9)
			return frame
		}, ErrEndToEndMessage},
		{"e2e non-zero pad", func() wire.Frame {
			frame := sealPeerFrame(t, peer, wire.FrameKindEndToEnd, newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 4, 2, 1, inner), testHop, ciphertext, 1, 4)
			frame.HopHeader[hopPadOffset+1] = 1
			return frame
		}, ErrEndToEndMessage},
		{"e2e inner length mismatch", func() wire.Frame {
			envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 4, 2, 1, inner+3)
			return sealPeerFrame(t, peer, wire.FrameKindEndToEnd, envelope, testHop, ciphertext, 1, 4)
		}, ErrEndToEndMessage},
		{"e2e zero session id", func() wire.Frame {
			return sealPeerFrame(t, peer, wire.FrameKindEndToEnd, newEndToEndEnvelope([16]byte{}, wire.MessageTypeStreamData, 1, 4, 2, 1, inner), testHop, ciphertext, 1, 4)
		}, ErrEndToEndMessage},
		{"e2e zero key epoch", func() wire.Frame {
			// Nonce generation 0 cannot be sealed by FrameProtector, so build
			// the raw envelope and confirm the hop layer rejects it before AEAD.
			envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 4, 2, 1, inner)
			binary.BigEndian.PutUint32(envelope[wire.EnvelopeKeyEpochOffset:], 0)
			return wire.Frame{Kind: wire.FrameKindEndToEnd, HopHeader: makeHopHeader(2, 1, testHop), Envelope: envelope, Body: bytes.Repeat([]byte{0x11}, len(ciphertext))}
		}, ErrEndToEndMessage},
		{"e2e lane mismatch", func() wire.Frame {
			packetPeer := peerProtectorFor(t, pair, sessionID, SessionClassPacket, DirectionResponderToInitiator)
			return sealPeerFrame(t, packetPeer, wire.FrameKindEndToEnd, newEndToEndEnvelope(sessionID, wire.MessageTypeIPPacket, 1, 4, 2, 1, inner), testHop, ciphertext, 1, 4)
		}, ErrEndToEndMessage},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			frame := test.frame()
			reader, err := NewProtectedControlIO(&memoryStream{src: bytes.NewReader(encodeFrame(t, frame))}, pair.ar, pair.descriptor, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.AdmitSession(sessionID, SessionClassStream); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.ReadMessage(); !errors.Is(err, test.want) {
				t.Fatalf("rejection = %v; want %v", err, test.want)
			}
			if reader.routeSeen || reader.sessions[sessionID].rxSeen {
				t.Fatal("rejected frame moved a floor")
			}
			if reader.terminal.Load() {
				t.Fatal("route/E2E semantic rejection ended the link")
			}
		})
	}
}

func TestProtectedRouteAndEndToEndFailuresAreNotTerminal(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0x99)
	peer := peerProtectorFor(t, pair, sessionID, SessionClassStream, DirectionResponderToInitiator)
	ciphertext := bytes.Repeat([]byte{0x24}, 32)
	inner := len(ciphertext) - e2eTagSize
	badRoute := sealPeerFrame(t, peer, wire.FrameKindRouteControl, routeEnvelope(wire.MessageTypeSessionCtrl, sessionID, 0, 0, 4), testHop, []byte{1, 2, 3, 4}, pair.br.Generation, 0)
	goodRoute := sealPeerFrame(t, peer, wire.FrameKindRouteControl, routeEnvelope(wire.MessageTypeSessionCtrl, sessionID, 5, 2, 4), testHop, []byte{1, 2, 3, 4}, pair.br.Generation, 0)
	goodE2E := sealPeerFrame(t, peer, wire.FrameKindEndToEnd, newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 2, 1, inner), testHop, ciphertext, 1, 1)

	script := append(append(encodeFrame(t, badRoute), encodeFrame(t, goodRoute)...), encodeFrame(t, goodE2E)...)
	reader, err := NewProtectedControlIO(&memoryStream{src: bytes.NewReader(script)}, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadMessage(); !errors.Is(err, ErrRouteMessage) {
		t.Fatalf("malformed route frame = %v", err)
	}
	if reader.routeSeen {
		t.Fatal("malformed route frame committed the floor")
	}
	if _, err := reader.ReadMessage(); err != nil {
		t.Fatalf("valid route frame after a malformed one = %v", err)
	}
	if _, err := reader.ReadMessage(); err != nil {
		t.Fatalf("valid E2E frame after a malformed route frame = %v", err)
	}
	if reader.terminal.Load() {
		t.Fatal("frame-local failures ended the link")
	}
}

func TestProtectedConcurrentWritersSerializeFrames(t *testing.T) {
	pair := establishedControlPair(t)
	const writers = 12
	sessions := make([][16]byte, writers)
	for i := range sessions {
		sessions[i] = testSessionID(byte(0xd0 + i))
		if err := pair.a.AdmitSession(sessions[i], SessionClassStream); err != nil {
			t.Fatal(err)
		}
		if err := pair.b.AdmitSession(sessions[i], SessionClassStream); err != nil {
			t.Fatal(err)
		}
	}
	ciphertext := bytes.Repeat([]byte{0x6d}, 32)
	payload := bytes.Repeat([]byte{0x05}, 16)
	failures := make(chan error, writers*3)
	var producers sync.WaitGroup
	for i := 0; i < writers; i++ {
		producers.Add(3)
		go func() {
			defer producers.Done()
			failures <- pair.a.WriteControl(ControlMessage{Type: 1, Payload: payload})
		}()
		go func(i int) {
			defer producers.Done()
			envelope := routeEnvelope(wire.MessageTypeSessionCtrl, sessions[i], uint64(i+1), 1, 4)
			failures <- pair.a.WriteRoute(envelope, []byte{byte(i), 0x01, 0x02, 0x03}, testHop)
		}(i)
		go func(i int) {
			defer producers.Done()
			envelope := newEndToEndEnvelope(sessions[i], wire.MessageTypeStreamData, 1, 1, uint64(i+1), 1, len(ciphertext)-e2eTagSize)
			failures <- pair.a.WriteEndToEnd(envelope, ciphertext, testHop)
		}(i)
	}
	seenControl, seenRoute, seenEndToEnd := 0, 0, 0
	var controlCounter, routeCounter uint64
	for frame := 0; frame < writers*3; frame++ {
		message, err := pair.b.ReadMessage()
		if err != nil {
			t.Fatalf("frame %d: %v", frame, err)
		}
		switch message.Kind {
		case wire.FrameKindLinkControl:
			if len(message.Payload) != 17 || !bytes.Equal(message.Payload[1:], payload) {
				t.Fatal("interleaved LINK_CTRL payload")
			}
			seenControl++
			counter := binary.BigEndian.Uint64(message.HopHeader[4:12])
			if counter <= controlCounter {
				t.Fatalf("LINK_CTRL counter %d did not advance past %d", counter, controlCounter)
			}
			controlCounter = counter
		case wire.FrameKindRouteControl:
			if len(message.Payload) != 4 || message.Payload[1] != 0x01 {
				t.Fatal("interleaved ROUTE_CTRL payload")
			}
			seenRoute++
			counter := binary.BigEndian.Uint64(message.HopHeader[4:12])
			if counter <= routeCounter && seenRoute > 1 {
				t.Fatalf("ROUTE_CTRL counter %d did not advance past %d", counter, routeCounter)
			}
			routeCounter = counter
		case wire.FrameKindEndToEnd:
			if !bytes.Equal(message.Payload, ciphertext) {
				t.Fatal("interleaved E2E ciphertext")
			}
			seenEndToEnd++
		default:
			t.Fatalf("unexpected kind 0x%02x", uint8(message.Kind))
		}
	}
	if seenControl != writers || seenRoute != writers || seenEndToEnd != writers {
		t.Fatalf("counts control=%d route=%d e2e=%d", seenControl, seenRoute, seenEndToEnd)
	}
	producers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if controlCounter != writers || routeCounter != writers-1 {
		t.Fatalf("final counters control=%d route=%d", controlCounter, routeCounter)
	}
}

func TestProtectedShortWriteIsTerminalAndSpendsNonce(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0xa5)
	cause := errors.New("injected partial transport write")
	ciphertext := bytes.Repeat([]byte{0x35}, 32)

	routeWriter, err := NewProtectedControlIO(&controlFaultWriter{ReadWriteCloser: pair.left, cause: cause}, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	envelope := routeEnvelope(wire.MessageTypeSessionCtrl, sessionID, 5, 2, 4)
	if err := routeWriter.WriteRoute(envelope, []byte{1, 2, 3, 4}, testHop); !errors.Is(err, cause) {
		t.Fatalf("route partial write = %v", err)
	}
	if routeWriter.routeNext != 1 {
		t.Fatal("route partial write rolled back its counter")
	}
	if err := routeWriter.WriteRoute(envelope, []byte{1, 2, 3, 4}, testHop); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("route partial write was retried")
	}

	e2eWriter, err := NewProtectedControlIO(&controlFaultWriter{ReadWriteCloser: pair.left, cause: cause}, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := e2eWriter.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	inner := len(ciphertext) - e2eTagSize
	if err := e2eWriter.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 7, 2, 1, inner), ciphertext, testHop); !errors.Is(err, cause) {
		t.Fatalf("E2E partial write = %v", err)
	}
	if entry := e2eWriter.sessions[sessionID]; entry.txCounter != 7 {
		t.Fatal("E2E partial write rolled back its nonce")
	}
	if err := e2eWriter.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 8, 2, 1, inner), ciphertext, testHop); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("E2E partial write was retried")
	}
}

func TestProtectedReadControlRejectsWrongKindWithoutDraining(t *testing.T) {
	pair := establishedControlPair(t)
	peer := peerProtectorFor(t, pair, testSessionID(0xb6), SessionClassStream, DirectionResponderToInitiator)
	routePayload := []byte{1, 2, 3, 4}
	routeFrame := sealPeerFrame(t, peer, wire.FrameKindRouteControl, routeEnvelope(wire.MessageTypeSessionCtrl, testSessionID(0xb6), 5, 2, len(routePayload)), testHop, routePayload, pair.br.Generation, 0)
	routeBytes := encodeFrame(t, routeFrame)
	linkFrame := sealPeerFrame(t, peer, wire.FrameKindLinkControl, nil, HopRoute{}, append([]byte{1}, bytes.Repeat([]byte{0x09}, 16)...), pair.br.Generation, 1)
	linkBytes := encodeFrame(t, linkFrame)

	stream := &memoryStream{src: bytes.NewReader(append(append([]byte(nil), routeBytes...), linkBytes...))}
	reader, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadControl(); !errors.Is(err, ErrControlMessage) || !errors.Is(err, ErrUnexpectedKind) {
		t.Fatalf("wrong kind in ReadControl = %v", err)
	}
	if !reader.terminal.Load() {
		t.Fatal("wrong-kind frame did not end the strict LINK_CTRL reader")
	}
	if stream.reads != len(routeBytes) {
		t.Fatalf("strict wrapper consumed %d bytes; want only the %d-byte route frame", stream.reads, len(routeBytes))
	}
	if _, err := reader.ReadControl(); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("strict wrapper continued after a wrong-kind frame")
	}
}

func TestProtectedFrameProtectorVerifyDoesNotCommit(t *testing.T) {
	pair := establishedControlPair(t)
	protector := peerProtectorFor(t, pair, [16]byte{}, SessionClassStream, DirectionResponderToInitiator)
	payload := []byte{1, 0x0a, 0x0b, 0x0c}
	frame := sealPeerFrame(t, protector, wire.FrameKindLinkControl, nil, HopRoute{}, payload, pair.br.Generation, 3)
	if _, err := protector.Verify(frame); err != nil {
		t.Fatal(err)
	}
	if _, err := protector.Verify(frame); err != nil {
		t.Fatalf("Verify committed replay state: %v", err)
	}
	if _, err := protector.Open(frame); err != nil {
		t.Fatalf("Open after Verify = %v", err)
	}
	if _, err := protector.Verify(frame); !errors.Is(err, ErrReplay) {
		t.Fatalf("Verify after Open = %v", err)
	}
}

func TestProtectedWriteRouteLocalValidationSpendsNothing(t *testing.T) {
	pair := establishedControlPair(t)
	stream := &memoryStream{src: bytes.NewReader(nil)}
	writer, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	valid := routeEnvelope(wire.MessageTypeSessionCtrl, testSessionID(0xc7), 5, 2, 4)
	badEnvelope := append([]byte(nil), valid...)
	binary.BigEndian.PutUint32(badEnvelope[wire.EnvelopeKeyEpochOffset:], 1)
	pathWithSession := routeEnvelope(wire.MessageTypePathOpen, testSessionID(0xc7), 5, 2, 4)
	sessionWithoutID := routeEnvelope(wire.MessageTypeSessionCtrl, [16]byte{}, 5, 2, 4)
	mismatchedInner := append([]byte(nil), valid...)
	binary.BigEndian.PutUint32(mismatchedInner[wire.EnvelopeInnerLengthOffset:], 3)
	cases := []struct {
		name     string
		envelope []byte
		payload  []byte
		hop      HopRoute
		want     error
	}{
		{"reserved key epoch", badEnvelope, []byte{1}, testHop, ErrRouteMessage},
		{"path with session id", pathWithSession, []byte{1}, testHop, ErrRouteMessage},
		{"session without id", sessionWithoutID, []byte{1}, testHop, ErrRouteMessage},
		{"inner length mismatch", mismatchedInner, []byte{1, 2, 3, 4}, testHop, ErrRouteMessage},
		{"empty payload", valid, nil, testHop, ErrRouteMessage},
		{"oversized payload", valid, make([]byte, maxRoutePayload+1), testHop, ErrRouteMessage},
		{"zero hop limit", valid, []byte{1, 2, 3, 4}, HopRoute{HopLimit: 0}, ErrInvalidHopRoute},
		{"hop limit above path bound", valid, []byte{1, 2, 3, 4}, HopRoute{HopLimit: 17}, ErrInvalidHopRoute},
		{"cursor above path bound", valid, []byte{1, 2, 3, 4}, HopRoute{Cursor: 16, HopLimit: 16}, ErrInvalidHopRoute},
		{"short envelope", valid[:84], []byte{1}, testHop, ErrRouteMessage},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := writer.WriteRoute(test.envelope, test.payload, test.hop); !errors.Is(err, test.want) {
				t.Fatalf("local rejection = %v; want %v", err, test.want)
			}
		})
	}
	if writer.routeNext != 0 || stream.written.Len() != 0 {
		t.Fatalf("local rejection spent a route nonce or wrote bytes: %d/%d", writer.routeNext, stream.written.Len())
	}
	if err := writer.WriteRoute(valid, []byte{1, 2, 3, 4}, testHop); err != nil {
		t.Fatal(err)
	}
	if writer.routeNext != 1 {
		t.Fatal("valid route frame did not advance the counter")
	}
	// An E2E class mismatch is also local: it must not spend the session nonce.
	session := testSessionID(0xc8)
	if err := writer.AdmitSession(session, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	packetEnvelope := newEndToEndEnvelope(session, wire.MessageTypeIPPacket, 1, 1, 2, 1, 16)
	if err := writer.WriteEndToEnd(packetEnvelope, bytes.Repeat([]byte{1}, 32), testHop); !errors.Is(err, ErrEndToEndMessage) {
		t.Fatalf("lane mismatch = %v", err)
	}
	if entry := writer.sessions[session]; entry.txEpoch != 0 || entry.txCounter != 0 {
		t.Fatal("rejected E2E frame spent a nonce")
	}
}

func TestProtectedNilReceiversAreTerminal(t *testing.T) {
	var nilIO *ProtectedControlIO
	if err := nilIO.WriteRoute(nil, nil, testHop); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("nil WriteRoute")
	}
	if err := nilIO.WriteEndToEnd(nil, nil, testHop); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("nil WriteEndToEnd")
	}
	if _, err := nilIO.ReadMessage(); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("nil ReadMessage")
	}
	if err := nilIO.AdmitSession(testSessionID(1), SessionClassStream); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("nil AdmitSession")
	}
	if err := nilIO.RetireSession(testSessionID(1)); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("nil RetireSession")
	}
	if err := nilIO.CommitEndToEnd(testSessionID(1), 1, 1); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("nil CommitEndToEnd")
	}
}

var _ io.ReadWriteCloser = (*memoryStream)(nil)

// D1: an authenticated ROUTE_CTRL frame above the frozen 8 KiB bootstrap bound
// could be read but never legitimately relayed. It must be rejected before the
// RouteCtrlCounter floor moves, and the Link must stay usable.
func TestProtectedRouteReaderEnforcesBootstrapBound(t *testing.T) {
	pair := establishedControlPair(t)
	peer := peerProtectorFor(t, pair, [16]byte{}, SessionClassStream, DirectionResponderToInitiator)
	for _, size := range []int{maxRoutePayload + 1, 65402} {
		payload := bytes.Repeat([]byte{0x4b}, size)
		envelope := routeEnvelope(wire.MessageTypeSessionCtrl, testSessionID(0xd1), 5, 2, size)
		frame := sealPeerFrame(t, peer, wire.FrameKindRouteControl, envelope, testHop, payload, pair.br.Generation, 0)
		stream := &memoryStream{src: bytes.NewReader(encodeFrame(t, frame))}
		reader, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
		if err != nil {
			t.Fatal(err)
		}
		message, err := reader.ReadMessage()
		if !errors.Is(err, ErrRouteMessage) {
			t.Fatalf("inner_len %d = %v; want ErrRouteMessage", size, err)
		}
		if message.Kind != wire.FrameKindRouteControl {
			t.Fatal("rejection lost the frame kind")
		}
		if reader.routeSeen || reader.terminal.Load() {
			t.Fatal("oversized bootstrap moved the floor or ended the link")
		}
		valid := sealPeerFrame(t, peer, wire.FrameKindRouteControl, routeEnvelope(wire.MessageTypeSessionCtrl, testSessionID(0xd1), 5, 2, 4), testHop, []byte{1, 2, 3, 4}, pair.br.Generation, 0)
		stream.src = bytes.NewReader(encodeFrame(t, valid))
		if _, err := reader.ReadMessage(); err != nil {
			t.Fatalf("valid frame after an oversized bootstrap = %v", err)
		}
	}
}

// D3: an oversized session ciphertext is a local FrameTooLarge rejection. It
// must spend nothing, must not end the Link, and the exact bound must still fit
// one maximum-size outer frame.
func TestProtectedEndToEndPayloadBoundIsLocalAndFaultFree(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0xd3)
	stream := &memoryStream{src: bytes.NewReader(nil)}
	writer, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, maxEndToEndPayload+1)
	envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 2, 1, len(oversized)-e2eTagSize)
	if err := writer.WriteEndToEnd(envelope, oversized, testHop); !errors.Is(err, wire.ErrFrameTooLarge) {
		t.Fatalf("oversized E2E ciphertext = %v; want wire.ErrFrameTooLarge", err)
	}
	if writer.terminal.Load() {
		t.Fatal("local oversize ended the link")
	}
	if entry := writer.sessions[sessionID]; entry.txEpoch != 0 || entry.txCounter != 0 {
		t.Fatal("local oversize spent a nonce")
	}
	if stream.written.Len() != 0 {
		t.Fatal("local oversize wrote bytes")
	}
	boundary := make([]byte, maxEndToEndPayload)
	envelope = newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 2, 1, len(boundary)-e2eTagSize)
	if err := writer.WriteEndToEnd(envelope, boundary, testHop); err != nil {
		t.Fatalf("boundary-sized E2E ciphertext = %v", err)
	}
	if got, want := stream.written.Len(), 4+int(wire.MaxFrameLength); got != want {
		t.Fatalf("boundary frame = %d wire bytes; want %d", got, want)
	}
	if entry := writer.sessions[sessionID]; entry.txEpoch != 1 || entry.txCounter != 1 {
		t.Fatal("boundary frame did not spend exactly one nonce")
	}
}

// D5: retirement must destroy the hop subkeys, keep only keyless metadata, and
// refuse every later seal/open while the Link stays usable.
func TestProtectedRetireDestroysKeysAndKeepsKeylessTombstone(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0xd5)
	writer, err := NewProtectedControlIO(&memoryStream{src: bytes.NewReader(nil)}, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AdmitSession(sessionID, SessionClassStream); err != nil {
		t.Fatal(err)
	}
	entry := writer.sessions[sessionID]
	if entry.tx == nil || entry.rx == nil {
		t.Fatal("admission did not install protectors")
	}
	payload := bytes.Repeat([]byte{0x61}, 32)
	if err := writer.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 7, 2, 1, len(payload)-e2eTagSize), payload, testHop); err != nil {
		t.Fatal(err)
	}
	if err := writer.RetireSession(sessionID); err != nil {
		t.Fatal(err)
	}
	if err := writer.RetireSession(sessionID); err != nil {
		t.Fatalf("idempotent retire = %v", err)
	}
	if !entry.retired || entry.tx == nil || entry.rx == nil {
		t.Fatal("retirement did not keep keyless metadata")
	}
	if !entry.tx.destroyed || !entry.rx.destroyed {
		t.Fatal("retirement did not destroy the hop keys")
	}
	if len(entry.tx.keys) != 0 || len(entry.rx.keys) != 0 || len(entry.tx.last) != 0 {
		t.Fatal("destroyed protector retained keys or replay state")
	}
	if entry.sessionID != sessionID || entry.class != SessionClassStream {
		t.Fatal("tombstone lost its identity metadata")
	}
	if entry.txEpoch != 1 || entry.txCounter != 7 {
		t.Fatal("tombstone lost its replay floor metadata")
	}
	frame := wire.Frame{Kind: wire.FrameKindEndToEnd, HopHeader: makeHopHeader(2, 1, testHop), Envelope: newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 8, 2, 1, len(payload)-e2eTagSize)}
	if _, err := entry.tx.Seal(frame, payload, 1, 8); !errors.Is(err, ErrInvalidProtector) {
		t.Fatalf("seal on a destroyed protector = %v", err)
	}
	if _, err := entry.rx.Verify(frame); !errors.Is(err, ErrInvalidProtector) {
		t.Fatalf("verify on a destroyed protector = %v", err)
	}
	if _, err := entry.rx.Open(frame); !errors.Is(err, ErrInvalidProtector) {
		t.Fatalf("open on a destroyed protector = %v", err)
	}
	if err := writer.WriteEndToEnd(newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 8, 2, 1, len(payload)-e2eTagSize), payload, testHop); !errors.Is(err, ErrSessionRetired) {
		t.Fatalf("write after retirement = %v", err)
	}
	if entry.txEpoch != 1 || entry.txCounter != 7 {
		t.Fatal("rejected post-retirement write moved the floor")
	}
	if writer.terminal.Load() {
		t.Fatal("retirement ended the link")
	}
}

// D5: the retirement fence must not deadlock against concurrent in-flight
// frames, must let an already-fenced frame finish, and must refuse everything
// afterwards.
func TestProtectedRetireIsFencedAgainstInFlightWriters(t *testing.T) {
	pair := establishedControlPair(t)
	writer, err := NewProtectedControlIO(&memoryStream{src: bytes.NewReader(nil)}, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	const sessions = 8
	ids := make([][16]byte, sessions)
	for i := range ids {
		ids[i] = indexedSessionID(0x500 + i)
		if err := writer.AdmitSession(ids[i], SessionClassStream); err != nil {
			t.Fatal(err)
		}
	}
	ciphertext := bytes.Repeat([]byte{0x51}, 32)
	inner := len(ciphertext) - e2eTagSize
	failures := make(chan error, sessions*2)
	var workers sync.WaitGroup
	for i := range ids {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			for number := uint64(1); number <= 40; number++ {
				envelope := newEndToEndEnvelope(ids[i], wire.MessageTypeStreamData, 1, number, uint64(i+1), 1, inner)
				err := writer.WriteEndToEnd(envelope, ciphertext, testHop)
				if err != nil && !errors.Is(err, ErrSessionRetired) {
					failures <- err
					return
				}
			}
		}(i)
	}
	for i := range ids {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			if err := writer.RetireSession(ids[i]); err != nil {
				failures <- err
			}
		}(i)
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("retirement and in-flight writers deadlocked")
	}
	close(failures)
	for err := range failures {
		t.Fatalf("fenced writer: %v", err)
	}
	for i := range ids {
		entry := writer.sessions[ids[i]]
		if !entry.retired || !entry.tx.destroyed || !entry.rx.destroyed {
			t.Fatalf("session %d was not retired and destroyed", i)
		}
		if err := writer.WriteEndToEnd(newEndToEndEnvelope(ids[i], wire.MessageTypeStreamData, 1, 41, uint64(i+1), 1, inner), ciphertext, testHop); !errors.Is(err, ErrSessionRetired) {
			t.Fatalf("post-retirement write on session %d = %v", i, err)
		}
	}
	if writer.terminal.Load() {
		t.Fatal("retirement fence ended the link")
	}
}

// D8: frameAAD must be byte- and error-equivalent to the wire codec's own
// frame encoding, without allocating a body or re-encoding the whole frame.
func TestFrameAADMatchesWireCodec(t *testing.T) {
	envelope := func(messageType wire.MessageType) []byte {
		raw := make([]byte, wire.EnvelopeSize)
		raw[wire.EnvelopeMessageTypeOffset] = byte(messageType)
		return raw
	}
	reference := func(frame wire.Frame, bodyLength int) (uint32, []byte, error) {
		candidate := frame
		candidate.Body = make([]byte, bodyLength)
		var encoded bytes.Buffer
		if err := wire.WriteFrame(&encoded, candidate); err != nil {
			return 0, nil, err
		}
		raw := encoded.Bytes()
		envelopeLength := 0
		if frame.Kind != wire.FrameKindLinkControl {
			envelopeLength = wire.EnvelopeSize
		}
		return binary.BigEndian.Uint32(raw[:4]), raw[:4+1+wire.HopHeaderSize+envelopeLength], nil
	}
	cases := []struct {
		name         string
		frame        wire.Frame
		bodyLength   int
		wantSentinel error
	}{
		{"link minimum", wire.Frame{Kind: wire.FrameKindLinkControl}, 17, nil},
		{"link below minimum", wire.Frame{Kind: wire.FrameKindLinkControl}, 16, wire.ErrFrameMalformed},
		{"link rejects envelope", wire.Frame{Kind: wire.FrameKindLinkControl, Envelope: envelope(wire.MessageTypeStreamData)}, 17, wire.ErrFrameMalformed},
		{"route minimum", wire.Frame{Kind: wire.FrameKindRouteControl, Envelope: envelope(wire.MessageTypeSessionCtrl)}, 17, nil},
		{"route below minimum", wire.Frame{Kind: wire.FrameKindRouteControl, Envelope: envelope(wire.MessageTypeSessionCtrl)}, 16, wire.ErrFrameMalformed},
		{"route rejects e2e type", wire.Frame{Kind: wire.FrameKindRouteControl, Envelope: envelope(wire.MessageTypeIPPacket)}, 17, wire.ErrFrameMalformed},
		{"route at max frame", wire.Frame{Kind: wire.FrameKindRouteControl, Envelope: envelope(wire.MessageTypePathOpen)}, 65536 - 1 - wire.HopHeaderSize - wire.EnvelopeSize, nil},
		{"route above max frame", wire.Frame{Kind: wire.FrameKindRouteControl, Envelope: envelope(wire.MessageTypePathOpen)}, 65536 - wire.HopHeaderSize - wire.EnvelopeSize, wire.ErrFrameTooLarge},
		{"route missing envelope", wire.Frame{Kind: wire.FrameKindRouteControl}, 17, wire.ErrFrameMalformed},
		{"e2e minimum", wire.Frame{Kind: wire.FrameKindEndToEnd, Envelope: envelope(wire.MessageTypeStreamData)}, 32, nil},
		{"e2e below minimum", wire.Frame{Kind: wire.FrameKindEndToEnd, Envelope: envelope(wire.MessageTypeStreamData)}, 31, wire.ErrFrameMalformed},
		{"e2e rejects route type", wire.Frame{Kind: wire.FrameKindEndToEnd, Envelope: envelope(wire.MessageTypeSessionCtrl)}, 32, wire.ErrFrameMalformed},
		{"unknown kind", wire.Frame{Kind: wire.FrameKind(0x09)}, 64, wire.ErrFrameMalformed},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			frame := test.frame
			for i := range frame.HopHeader {
				frame.HopHeader[i] = byte(i * 7)
			}
			length, aad, err := frameAAD(frame, test.bodyLength)
			wantLength, wantAAD, wantErr := reference(frame, test.bodyLength)
			if test.wantSentinel == nil {
				if err != nil {
					t.Fatalf("frameAAD = %v; want nil", err)
				}
				if wantErr != nil {
					t.Fatalf("reference disagreed: %v", wantErr)
				}
				if length != wantLength || !bytes.Equal(aad, wantAAD) {
					t.Fatalf("AAD mismatch: length %d/%d aad %x want %x", length, wantLength, aad, wantAAD)
				}
				return
			}
			if !errors.Is(err, test.wantSentinel) {
				t.Fatalf("frameAAD error = %v; want %v", err, test.wantSentinel)
			}
			if !errors.Is(wantErr, test.wantSentinel) {
				t.Fatalf("wire codec error = %v; want %v", wantErr, test.wantSentinel)
			}
		})
	}
}
