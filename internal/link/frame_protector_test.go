package link

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/yiiilin/simpletier/internal/wire"
)

// setEnvelopeNonce publishes the E2E nonce domain on a frame's envelope so the
// hop nonce and the envelope key_epoch|message_number are consistent before
// Seal. Production checkHopNonce requires this; control frames do not use it.
func setEnvelopeNonce(frame *wire.Frame, generation uint32, counter uint64) {
	binary.BigEndian.PutUint32(frame.Envelope[wire.EnvelopeKeyEpochOffset:], generation)
	binary.BigEndian.PutUint64(frame.Envelope[wire.EnvelopeMessageNumberOffset:], counter)
}

func TestFrameProtectorRoundTripsEachPurpose(t *testing.T) {
	root := sha256.Sum256([]byte("directional root"))
	descriptor := []byte("simpletier/v1/network\x00mesh\x0010.20.0.0/24")
	var session [16]byte
	copy(session[:], "session-identifier")
	protector, err := NewFrameProtector(root, descriptor, 7, session, SessionClassStream, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		kind wire.FrameKind
		body []byte
	}{
		{"link", wire.FrameKindLinkControl, []byte{0x04, 0x01, 0x00, 0x00}},
		{"route", wire.FrameKindRouteControl, []byte("path-open")},
		{"e2e", wire.FrameKindEndToEnd, []byte("stream payload!!")},
	} {
		t.Run(test.name, func(t *testing.T) {
			frame := testFrame(test.kind, test.body)
			epoch, messageNumber := uint32(0x01020304), uint64(len(test.body)+1)
			if test.kind == wire.FrameKindEndToEnd {
				setEnvelopeNonce(&frame, epoch, messageNumber)
			}
			sealed, err := protector.Seal(frame, test.body, epoch, messageNumber)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(sealed.Body, test.body) {
				t.Fatal("plaintext body was not protected")
			}
			got, err := protector.Open(sealed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, test.body) {
				t.Fatalf("plaintext = %q; want %q", got, test.body)
			}
		})
	}
}

func TestFrameProtectorSealWritesNonceHeader(t *testing.T) {
	root := sha256.Sum256([]byte("header nonce root"))
	p, err := NewFrameProtector(root, []byte("descriptor"), 9, [16]byte{}, SessionClassStream, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	frame := testFrame(wire.FrameKindLinkControl, []byte("control"))
	for i := range frame.HopHeader {
		frame.HopHeader[i] = byte(i + 1)
	}
	wantTail := append([]byte(nil), frame.HopHeader[12:]...)
	sealed, err := p.Seal(frame, []byte("control"), 0x11223344, 0x0102030405060708)
	if err != nil {
		t.Fatal(err)
	}
	want := [12]byte{0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(sealed.HopHeader[:12], want[:]) {
		t.Fatalf("nonce header = %x; want %x", sealed.HopHeader[:12], want)
	}
	if !bytes.Equal(sealed.HopHeader[12:], wantTail) {
		t.Fatalf("unrelated hop header fields changed: %x; want %x", sealed.HopHeader[12:], wantTail)
	}
	if got, err := p.Open(sealed); err != nil || string(got) != "control" {
		t.Fatalf("round trip after header publication = %q, %v", got, err)
	}
}

func TestFrameProtectorSeparatesContextDirectionAndPurpose(t *testing.T) {
	root := sha256.Sum256([]byte("root"))
	var session [16]byte
	a, err := NewFrameProtector(root, []byte("descriptor-a"), 1, session, SessionClassPacket, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewFrameProtector(root, []byte("descriptor-b"), 1, session, SessionClassPacket, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewFrameProtector(root, []byte("descriptor-a"), 1, session, SessionClassPacket, DirectionResponderToInitiator)
	if err != nil {
		t.Fatal(err)
	}
	frame := testFrame(wire.FrameKindEndToEnd, bytes.Repeat([]byte("s"), 32))
	setEnvelopeNonce(&frame, 3, 9)
	sealed, err := a.Seal(frame, frame.Body, 3, 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("different descriptor accepted ciphertext")
	}
	if _, err := c.Open(sealed); err == nil {
		t.Fatal("opposite direction accepted ciphertext")
	}
}

func TestFrameProtectorControlKeysDoNotDependOnSession(t *testing.T) {
	root := sha256.Sum256([]byte("shared directional link root"))
	descriptor := []byte("shared full descriptor")
	firstSession := [16]byte{1, 2, 3}
	secondSession := [16]byte{4, 5, 6}
	first, err := NewFrameProtector(root, descriptor, 41, firstSession, SessionClassPacket, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFrameProtector(root, descriptor, 41, secondSession, SessionClassStream, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []wire.FrameKind{wire.FrameKindLinkControl, wire.FrameKindRouteControl} {
		frame := testFrame(kind, []byte("session-independent control"))
		sealed, err := first.Seal(frame, frame.Body, 5, 0)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := second.Open(sealed)
		if err != nil || !bytes.Equal(plain, frame.Body) {
			t.Fatalf("purpose %d incorrectly binds session metadata: %v", kind, err)
		}
	}
	for _, purpose := range []framePurpose{purposeLink, purposeRoute} {
		if first.keys[purpose] != second.keys[purpose] {
			t.Fatalf("control purpose %d derived different keys for the same Link", purpose)
		}
	}
}

func TestFrameProtectorE2EKeysBindSessionAndClass(t *testing.T) {
	root := sha256.Sum256([]byte("shared directional link root"))
	descriptor := []byte("shared full descriptor")
	baseSession := [16]byte{1, 2, 3}
	base, err := NewFrameProtector(root, descriptor, 41, baseSession, SessionClassPacket, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	frame := testFrame(wire.FrameKindEndToEnd, bytes.Repeat([]byte{0x61}, 32))
	setEnvelopeNonce(&frame, 5, 0)
	sealed, err := base.Seal(frame, frame.Body, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct {
		session [16]byte
		class   byte
	}{
		{[16]byte{4, 5, 6}, SessionClassPacket},
		{baseSession, SessionClassStream},
		{[16]byte{4, 5, 6}, SessionClassStream},
	} {
		wrong, err := NewFrameProtector(root, descriptor, 41, variant.session, variant.class, DirectionInitiatorToResponder)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wrong.Open(sealed); err == nil {
			t.Fatal("wrong E2E session or class accepted ciphertext")
		}
		if wrong.keys[purposeE2E] == base.keys[purposeE2E] {
			t.Fatal("E2E session/class did not separate keys")
		}
	}
}

func TestFrameProtectorRejectsZeroRootAndInvalidSessionClass(t *testing.T) {
	for _, class := range []byte{0, 3} {
		if _, err := NewFrameProtector([32]byte{1}, []byte("descriptor"), 1, [16]byte{}, class, DirectionInitiatorToResponder); !errors.Is(err, ErrInvalidProtector) {
			t.Fatalf("session class %d error = %v; want ErrInvalidProtector", class, err)
		}
	}
	if _, err := NewFrameProtector([32]byte{}, []byte("descriptor"), 1, [16]byte{}, SessionClassStream, DirectionInitiatorToResponder); !errors.Is(err, ErrInvalidProtector) {
		t.Fatalf("zero root error = %v; want ErrInvalidProtector", err)
	}
}

func TestFrameProtectorRejectsTamperReplayAndInvalidFrames(t *testing.T) {
	root := sha256.Sum256([]byte("root"))
	p, err := NewFrameProtector(root, []byte("descriptor"), 1, [16]byte{}, SessionClassStream, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	frame := testFrame(wire.FrameKindRouteControl, []byte("route"))
	sealed, err := p.Seal(frame, frame.Body, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	tampered := sealed
	tampered.Body = append([]byte(nil), sealed.Body...)
	tampered.Body[len(tampered.Body)-1] ^= 0x80
	if _, err := p.Open(tampered); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := p.Open(sealed); err != nil {
		t.Fatal("valid ciphertext rejected after failed tamper: ", err)
	}
	if _, err := p.Open(sealed); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay = %v; want ErrReplay", err)
	}
	older, err := p.Seal(frame, frame.Body, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Open(older); !errors.Is(err, ErrReplay) {
		t.Fatalf("out-of-order frame = %v; want ErrReplay", err)
	}
	if _, err := p.Seal(frame, frame.Body, 0, 4); !errors.Is(err, ErrInvalidProtector) {
		t.Fatalf("zero generation = %v", err)
	}
	if _, err := p.Seal(frame, frame.Body, 1, ^uint64(0)); !errors.Is(err, ErrCounterExhausted) {
		t.Fatalf("reserved counter = %v", err)
	}
	invalid := frame
	invalid.Envelope = nil
	if _, err := p.Seal(invalid, []byte("x"), 1, 1); !errors.Is(err, wire.ErrFrameMalformed) {
		t.Fatalf("invalid envelope = %v", err)
	}
}

func TestFrameProtectorDescriptorKeyVector(t *testing.T) {
	root := sha256.Sum256([]byte("vector-root"))
	p, err := NewFrameProtector(root, []byte("descriptor-vector"), 0x0102030405060708, [16]byte{1, 2, 3}, SessionClassPacket, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	frame := testFrame(wire.FrameKindLinkControl, []byte{4, 1, 2, 3})
	sealed, err := p.Seal(frame, frame.Body, 0x11223344, 0x0102030405060709)
	if err != nil {
		t.Fatal(err)
	}
	// These project fixtures were independently calculated using Node's standard
	// SHA256/HMAC HKDF expansion and ChaCha20-Poly1305, never this implementation.
	// They are regression vectors, not a cross-implementation protocol claim.
	for purpose, expected := range map[framePurpose]string{
		purposeLink:  "efd6f047fead233ed6cbd10e2bdb82ff9712e1ae03a302b32de9e78c567ce05c",
		purposeRoute: "7c054333fc57525515c8b83fc487b49665217a39bc81ee8a022c15c6ef10813a",
		purposeE2E:   "075d98de3020ccfc1588dd2caa81ff1167cf2110382b28496245ef4f246b572a",
	} {
		key := p.keys[purpose]
		if hex.EncodeToString(key[:]) != expected {
			t.Fatalf("purpose %d did not match the independent project key fixture", purpose)
		}
	}
	const expectedCiphertext = "b856bca9c67d7a81641ac6e49652704b38f738ac"
	if hex.EncodeToString(sealed.Body) != expectedCiphertext {
		t.Fatal("protected body did not match the independent project ChaCha fixture")
	}
	_, aad, err := frameAAD(sealed, len(sealed.Body))
	if err != nil {
		t.Fatal(err)
	}
	const expectedAAD = "00000035011122334401020304050607090000000000000000000000000000000000000000"
	if hex.EncodeToString(aad) != expectedAAD {
		t.Fatal("frame AAD did not match the independent fixture")
	}
	if root != sha256.Sum256([]byte("vector-root")) {
		t.Fatal("constructor changed caller-owned root key")
	}
}

// newE2EProtector builds a protector whose E2E key is used by the hop-nonce
// tests below.
func newE2EProtector(t *testing.T, class byte) *FrameProtector {
	t.Helper()
	root := sha256.Sum256([]byte("hop nonce root"))
	p, err := NewFrameProtector(root, []byte("hop-nonce-descriptor"), 21, [16]byte{7, 8, 9}, class, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFrameProtectorE2EHopNonceRequiresMatchingEnvelope(t *testing.T) {
	p := newE2EProtector(t, SessionClassStream)
	body := []byte("matching envelope nonce!!")
	frame := testFrame(wire.FrameKindEndToEnd, body)
	setEnvelopeNonce(&frame, 0x01020304, 77)
	sealed, err := p.Seal(frame, body, 0x01020304, 77)
	if err != nil {
		t.Fatalf("matching E2E nonce refused by Seal: %v", err)
	}
	got, err := p.Open(sealed)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("round trip = %q, %v", got, err)
	}
	if _, err := p.Open(sealed); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay = %v; want ErrReplay", err)
	}
}

func TestFrameProtectorSealRejectsE2EHopNonceMismatch(t *testing.T) {
	p := newE2EProtector(t, SessionClassPacket)
	body := []byte("mismatched envelope nonce")
	cases := []struct {
		name                      string
		generation                uint32
		counter                   uint64
		envGeneration, envCounter uint64
		want                      error
	}{
		{"generation", 0x05060708, 4, 0x05060709, 4, ErrHopNonceMismatch},
		{"counter", 0x05060708, 4, 0x05060708, 5, ErrHopNonceMismatch},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			frame := testFrame(wire.FrameKindEndToEnd, body)
			setEnvelopeNonce(&frame, uint32(test.envGeneration), test.envCounter)
			sealed, err := p.Seal(frame, body, test.generation, test.counter)
			if !errors.Is(err, test.want) {
				t.Fatalf("Seal(%d, %d) = %v; want %v", test.generation, test.counter, err, test.want)
			}
			if len(sealed.Body) != 0 || sealed.HopHeader != ([wire.HopHeaderSize]byte{}) {
				t.Fatal("rejected Seal produced a body or nonce header")
			}
		})
	}
}

func TestFrameProtectorOpenRejectsE2EHopNonceMismatchWithoutAdvancingReplay(t *testing.T) {
	body := []byte("committed only on success")
	for _, mutate := range []struct {
		name string
		edit func(candidate *wire.Frame)
	}{
		{"envelope key epoch", func(candidate *wire.Frame) {
			binary.BigEndian.PutUint32(candidate.Envelope[wire.EnvelopeKeyEpochOffset:], 8)
		}},
		{"hop header counter", func(candidate *wire.Frame) {
			candidate.HopHeader[11]++
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			p := newE2EProtector(t, SessionClassStream)
			frame := testFrame(wire.FrameKindEndToEnd, body)
			setEnvelopeNonce(&frame, 7, 11)
			sealed, err := p.Seal(frame, body, 7, 11)
			if err != nil {
				t.Fatal(err)
			}
			wantEnvelope := append([]byte(nil), sealed.Envelope...)
			wantHop := sealed.HopHeader
			candidate := sealed
			candidate.Envelope = append([]byte(nil), sealed.Envelope...)
			mutate.edit(&candidate)
			if _, err := p.Open(candidate); !errors.Is(err, ErrHopNonceMismatch) {
				t.Fatalf("mismatched %s accepted: %v", mutate.name, err)
			}
			if !bytes.Equal(sealed.Envelope, wantEnvelope) || sealed.HopHeader != wantHop {
				t.Fatal("test candidate aliased and mutated the original sealed frame")
			}
			plain, err := p.Open(sealed)
			if err != nil || !bytes.Equal(plain, body) {
				t.Fatalf("valid frame lost its counter after a rejected mismatch: %q, %v", plain, err)
			}
			// The successful Open above committed counter 11; the original is now spent.
			if _, err := p.Open(sealed); !errors.Is(err, ErrReplay) {
				t.Fatalf("committed counter replayed = %v; want ErrReplay", err)
			}
		})
	}
}

func TestFrameProtectorE2EWrongTagDoesNotPolluteReplayWindow(t *testing.T) {
	p := newE2EProtector(t, SessionClassPacket)
	body := []byte("window is not a forgeries toll")
	validFrame := testFrame(wire.FrameKindEndToEnd, body)
	setEnvelopeNonce(&validFrame, 3, 10)
	valid, err := p.Seal(validFrame, body, 3, 10)
	if err != nil {
		t.Fatal(err)
	}
	forgedFrame := testFrame(wire.FrameKindEndToEnd, body)
	setEnvelopeNonce(&forgedFrame, 3, 99_999)
	forged, err := p.Seal(forgedFrame, body, 3, 99_999)
	if err != nil {
		t.Fatal(err)
	}
	forged.Body = append([]byte(nil), forged.Body...)
	forged.Body[len(forged.Body)-1] ^= 0x80
	if _, err := p.Open(forged); err == nil {
		t.Fatal("wrong tag accepted")
	}
	plain, err := p.Open(valid)
	if err != nil || !bytes.Equal(plain, body) {
		t.Fatalf("valid counter 10 rejected after a failed counter 99999: %q, %v", plain, err)
	}
}

func TestFrameProtectorControlFramesIgnoreEnvelopeNonce(t *testing.T) {
	p := newE2EProtector(t, SessionClassStream)
	for _, test := range []struct {
		name string
		kind wire.FrameKind
		body []byte
	}{
		{"route", wire.FrameKindRouteControl, []byte("path-open")},
		{"link", wire.FrameKindLinkControl, []byte{0x04, 0x01, 0x00, 0x00}},
	} {
		t.Run(test.name, func(t *testing.T) {
			frame := testFrame(test.kind, test.body)
			before := append([]byte(nil), frame.Envelope...)
			// A zero envelope nonce must not bind or block a control frame.
			sealed, err := p.Seal(frame, test.body, 0x0a0b0c0d, 0)
			if err != nil {
				t.Fatalf("control seal rejected by envelope nonce: %v", err)
			}
			if !bytes.Equal(sealed.Envelope, before) {
				t.Fatal("control Seal rewrote reserved envelope nonce fields")
			}
			plain, err := p.Open(sealed)
			if err != nil || !bytes.Equal(plain, test.body) {
				t.Fatalf("control round trip = %q, %v", plain, err)
			}
			// Converse: a control frame whose envelope nonce disagrees with the
			// hop nonce is still authenticated, so the check is E2E-only.
			other := testFrame(test.kind, test.body)
			if len(other.Envelope) != 0 {
				setEnvelopeNonce(&other, 0x0a0b0c0d, 4242)
			}
			otherSealed, err := p.Seal(other, test.body, 0x0a0b0c0d, 5)
			if err != nil {
				t.Fatalf("disagreeing control envelope nonce rejected: %v", err)
			}
			if _, err := p.Open(otherSealed); err != nil {
				t.Fatalf("disagreeing control envelope nonce broke Open: %v", err)
			}
		})
	}
}

func testFrame(kind wire.FrameKind, body []byte) wire.Frame {
	frame := wire.Frame{Kind: kind, Body: append([]byte(nil), body...)}
	if kind != wire.FrameKindLinkControl {
		frame.Envelope = make([]byte, wire.EnvelopeSize)
		frame.Envelope[wire.EnvelopeMessageTypeOffset] = byte(map[wire.FrameKind]wire.MessageType{
			wire.FrameKindEndToEnd:     wire.MessageTypeStreamData,
			wire.FrameKindRouteControl: wire.MessageTypePathOpen,
		}[kind])
	}
	return frame
}
