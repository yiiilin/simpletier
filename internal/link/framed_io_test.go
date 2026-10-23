package link

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/wire"
)

type controlPair struct {
	a, b        *ProtectedControlIO
	left, right net.Conn
	ar, br      LinkResult
	descriptor  []byte
	alice, bob  security.Identity
	psk         [32]byte
}

func establishedControlPair(t testing.TB) controlPair {
	return establishedControlPairWith(t, 91, 2, 17)
}

// establishedControlPairWith establishes one real Noise Link with an explicit
// LinkID/Epoch/Generation, so a test can run a negotiation Link and a DATA
// target Link with distinct identities and generation domains.
func establishedControlPairWith(t testing.TB, linkID, linkEpoch uint64, generation uint32) controlPair {
	t.Helper()
	network, err := security.NewNetworkContext("control-test", "10.20.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	psk, err := network.DerivePSK("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	for _, socket := range []net.Conn{left, right} {
		if err := socket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type outcome struct {
		r         LinkResult
		err       error
		initiator bool
	}
	finished := make(chan outcome, 2)
	cfg := LinkConfig{Descriptor: network.Descriptor(), PSK: psk, Identity: alice, LinkID: linkID, LinkEpoch: linkEpoch, Generation: generation, Initiator: true, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask}
	go func() { r, err := Handshake(ctx, left, cfg); finished <- outcome{r, err, true} }()
	other := cfg
	other.Identity, other.Initiator = bob, false
	go func() { r, err := Handshake(ctx, right, other); finished <- outcome{r, err, false} }()
	pair := controlPair{left: left, right: right, descriptor: network.Descriptor(), alice: alice, bob: bob, psk: psk}
	var handshakeErr error
	for count := 0; count < 2; count++ {
		select {
		case got := <-finished:
			if got.err != nil {
				handshakeErr = errors.Join(handshakeErr, got.err)
				_ = left.Close()
				_ = right.Close()
			}
			if got.initiator {
				pair.ar = got.r
			} else {
				pair.br = got.r
			}
		case <-ctx.Done():
			_ = left.Close()
			_ = right.Close()
			for remaining := count; remaining < 2; remaining++ {
				select {
				case <-finished:
				case <-time.After(time.Second):
					t.Fatal("handshake goroutine did not exit after caller Close")
				}
			}
			t.Fatal("real handshake did not finish")
		}
	}
	if handshakeErr != nil {
		t.Fatal(handshakeErr)
	}
	pair.a, err = NewProtectedControlIO(left, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	pair.b, err = NewProtectedControlIO(right, pair.br, pair.descriptor, false)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func sendControl(t *testing.T, sender, receiver *ProtectedControlIO, kind uint8, payload []byte) ControlMessage {
	t.Helper()
	written := make(chan error, 1)
	go func() { written <- sender.WriteControl(ControlMessage{Type: kind, Payload: payload}) }()
	message, err := receiver.ReadControl()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	return message
}

func injectControlFrame(t *testing.T, socket net.Conn, receiver *ProtectedControlIO, frame wire.Frame) (ControlMessage, error) {
	t.Helper()
	written := make(chan error, 1)
	go func() { written <- wire.WriteFrame(socket, frame) }()
	message, readErr := receiver.ReadControl()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	return message, readErr
}

func peerControlProtector(t *testing.T, pair controlPair) *FrameProtector {
	t.Helper()
	p, err := NewFrameProtector(pair.br.TxRoot, pair.descriptor, pair.br.LinkID, [16]byte{}, SessionClassStream, DirectionResponderToInitiator)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProtectedControlRoundTripAfterRealHandshake(t *testing.T) {
	pair := establishedControlPair(t)
	for i := byte(1); i <= 2; i++ {
		payload := bytes.Repeat([]byte{i}, 16)
		got := sendControl(t, pair.a, pair.b, 1, payload)
		if got.Type != 1 || !bytes.Equal(got.Payload, payload) {
			t.Fatal("PING was not returned intact")
		}
		got.Payload[0] = 255
		pong := sendControl(t, pair.b, pair.a, 2, payload)
		if pong.Type != 2 || !bytes.Equal(pong.Payload, payload) {
			t.Fatal("PONG was not returned intact")
		}
	}
	if pair.a.txNext != 3 || pair.a.rxLast != 2 || pair.b.txNext != 3 || pair.b.rxLast != 2 {
		t.Fatal("control counters did not start at 1 and advance independently")
	}
	payload := make([]byte, 10)
	binary.BigEndian.PutUint64(payload[:8], 7)
	got := sendControl(t, pair.a, pair.b, 5, payload)
	if got.Type != 5 || !bytes.Equal(got.Payload, payload) {
		t.Fatal("TEARDOWN was not returned intact")
	}
}

func TestProtectedControlRejectsCapabilityFloorAndReplay(t *testing.T) {
	pair := establishedControlPair(t)
	protector := peerControlProtector(t, pair)
	capability, err := EncodeCapability(Capability{Version: CapabilityVersion, Bits: RequiredCapabilityMask})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{4}, capability...), pair.br.Generation, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := injectControlFrame(t, pair.right, pair.a, frame); !errors.Is(err, ErrReplay) {
		t.Fatalf("capability counter 0 replay: %v", err)
	}
	payload := bytes.Repeat([]byte{8}, 16)
	frame, err = protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{1}, payload...), pair.br.Generation, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := injectControlFrame(t, pair.right, pair.a, frame); err != nil {
		t.Fatal(err)
	}
	if _, err := injectControlFrame(t, pair.right, pair.a, frame); !errors.Is(err, ErrReplay) {
		t.Fatalf("counter replay: %v", err)
	}
	if pair.a.rxLast != 1 {
		t.Fatal("replay changed RX floor")
	}
	if err := pair.b.WriteControl(ControlMessage{Type: 4, Payload: capability}); !errors.Is(err, ErrControlMessage) {
		t.Fatalf("post-handshake CAPABILITY emitted: %v", err)
	}
}

func TestProtectedControlBadTagDoesNotPoisonCounter(t *testing.T) {
	pair := establishedControlPair(t)
	protector := peerControlProtector(t, pair)
	payload := append([]byte{1}, bytes.Repeat([]byte{7}, 16)...)
	high, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, payload, pair.br.Generation, 99999)
	if err != nil {
		t.Fatal(err)
	}
	high.Body[0] ^= 1
	if _, err := injectControlFrame(t, pair.right, pair.a, high); err == nil {
		t.Fatal("tampered ciphertext passed")
	}
	if pair.a.rxLast != 0 {
		t.Fatal("invalid tag advanced replay floor")
	}
	good, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, payload, pair.br.Generation, 1)
	if err != nil {
		t.Fatal(err)
	}
	message, err := injectControlFrame(t, pair.right, pair.a, good)
	if err != nil || message.Type != 1 || !bytes.Equal(message.Payload, payload[1:]) {
		t.Fatal("forged high counter poisoned valid traffic")
	}
	if bytes.Contains(good.Body, payload) {
		t.Fatal("wire body exposed plaintext")
	}
}

func TestProtectedControlSchemaFailureDoesNotCommit(t *testing.T) {
	pair := establishedControlPair(t)
	protector := peerControlProtector(t, pair)
	frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, []byte{1, 2}, pair.br.Generation, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := injectControlFrame(t, pair.right, pair.a, frame); !errors.Is(err, ErrControlMessage) {
		t.Fatalf("short PING accepted: %v", err)
	}
	if pair.a.rxLast != 0 {
		t.Fatal("invalid schema committed RX floor")
	}
	if _, err := pair.a.ReadControl(); !errors.Is(err, ErrControlTerminal) {
		t.Fatalf("semantic failure continued reading: %v", err)
	}
}

func TestProtectedControlConcurrentWritesHaveWireOrder(t *testing.T) {
	pair := establishedControlPair(t)
	var producers sync.WaitGroup
	written := make(chan error, 20)
	for id := byte(0); id < 20; id++ {
		producers.Add(1)
		go func(id byte) {
			defer producers.Done()
			written <- pair.a.WriteControl(ControlMessage{Type: 1, Payload: bytes.Repeat([]byte{id}, 16)})
		}(id)
	}
	seen := make(map[byte]bool)
	for ordinal := uint64(1); ordinal <= 20; ordinal++ {
		message, err := pair.b.ReadControl()
		if err != nil {
			t.Fatal(err)
		}
		if message.Type != 1 || len(message.Payload) != 16 || seen[message.Payload[0]] {
			t.Fatal("concurrent messages interleaved or duplicated")
		}
		seen[message.Payload[0]] = true
		if pair.b.rxLast != ordinal {
			t.Fatal("counter allocation differed from wire order")
		}
	}
	producers.Wait()
	for range 20 {
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}
}

func TestProtectedControlSchemaAndCounterLimits(t *testing.T) {
	pair := establishedControlPair(t)
	for _, message := range []ControlMessage{{Type: 0}, {Type: 9}, {Type: 1, Payload: []byte{1}}, {Type: 2, Payload: make([]byte, 17)}, {Type: 3, Payload: []byte{0, 1, 0, 2, 3}}, {Type: 5, Payload: make([]byte, 9)}, {Type: 6}, {Type: 7}, {Type: 8}} {
		if err := pair.a.WriteControl(message); !errors.Is(err, ErrControlMessage) {
			t.Fatalf("invalid local schema = %v", err)
		}
	}
	if pair.a.txNext != 1 {
		t.Fatal("local rejection spent a nonce")
	}
	pair.a.txNext = ^uint64(0)
	if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: make([]byte, 16)}); !errors.Is(err, ErrCounterExhausted) {
		t.Fatalf("counter wrap = %v", err)
	}
	if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: make([]byte, 16)}); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("exhausted object remained writable")
	}
}

func TestProtectedControlCallerCloseAndEOF(t *testing.T) {
	pair := establishedControlPair(t)
	started := make(chan struct{})
	finished := make(chan error, 1)
	go func() { close(started); _, err := pair.a.ReadControl(); finished <- err }()
	<-started
	if err := pair.left.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("closed read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("caller close did not interrupt control read")
	}
	pair = establishedControlPair(t)
	if err := pair.right.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := pair.a.ReadControl(); !errors.Is(err, io.EOF) {
		t.Fatalf("clean EOF = %v", err)
	}
	if _, err := pair.a.ReadControl(); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("EOF silently retried")
	}
}

func TestProtectedControlTransportWriteFailureIsTerminal(t *testing.T) {
	pair := establishedControlPair(t)
	cause := errors.New("injected partial transport write")
	stream := &controlFaultWriter{ReadWriteCloser: pair.left, cause: cause}
	writer, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	message := ControlMessage{Type: 1, Payload: make([]byte, 16)}
	if err := writer.WriteControl(message); !errors.Is(err, cause) {
		t.Fatalf("partial write cause = %v", err)
	}
	if writer.txNext != 2 {
		t.Fatal("partial emission rolled back its nonce")
	}
	if err := writer.WriteControl(message); !errors.Is(err, ErrControlTerminal) || stream.calls != 1 {
		t.Fatal("failed transport was retried")
	}
}

type controlFaultWriter struct {
	io.ReadWriteCloser
	cause error
	calls int
}

func (s *controlFaultWriter) Write([]byte) (int, error) { s.calls++; return 1, s.cause }

func TestProtectedControlCallerCloseUnblocksWrite(t *testing.T) {
	pair := establishedControlPair(t)
	stream := &controlEnteredWriter{ReadWriteCloser: pair.left, entered: make(chan struct{})}
	writer, err := NewProtectedControlIO(stream, pair.ar, pair.descriptor, true)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- writer.WriteControl(ControlMessage{Type: 1, Payload: make([]byte, 16)}) }()
	select {
	case <-stream.entered:
	case <-time.After(time.Second):
		t.Fatal("write did not enter transport")
	}
	if err := pair.left.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked write succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("caller close did not release writer")
	}
	if writer.txNext != 2 {
		t.Fatal("blocked write lost its allocated nonce")
	}
}

type controlEnteredWriter struct {
	io.ReadWriteCloser
	entered chan struct{}
	once    sync.Once
}

func (s *controlEnteredWriter) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	return s.ReadWriteCloser.Write(p)
}

func TestProtectedControlTruncationAndHeaderFailure(t *testing.T) {
	pair := establishedControlPair(t)
	finished := make(chan error, 1)
	go func() {
		_, err := pair.right.Write([]byte{0, 0, 0, 66, 1})
		finished <- errors.Join(err, pair.right.Close())
	}()
	if _, err := pair.a.ReadControl(); !errors.Is(err, wire.ErrTruncatedFrame) {
		t.Fatalf("truncated frame = %v", err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if _, err := pair.a.ReadControl(); !errors.Is(err, ErrControlTerminal) {
		t.Fatal("truncated record parser resumed")
	}
	pair = establishedControlPair(t)
	protector := peerControlProtector(t, pair)
	frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{1}, make([]byte, 16)...), pair.br.Generation, 1)
	if err != nil {
		t.Fatal(err)
	}
	frame.HopHeader[12] = 1
	if _, err := injectControlFrame(t, pair.right, pair.a, frame); !errors.Is(err, ErrControlMessage) {
		t.Fatalf("nonzero reserved route field = %v", err)
	}
	if pair.a.rxLast != 0 {
		t.Fatal("header rejection advanced floor")
	}
}

func TestProtectedControlLocalValidationAndOwnedPayloads(t *testing.T) {
	pair := establishedControlPair(t)
	if _, err := NewProtectedControlIO(nil, pair.ar, pair.descriptor, true); !errors.Is(err, ErrInvalidControlIO) {
		t.Fatal("nil stream accepted")
	}
	if _, err := NewProtectedControlIO(pair.left, LinkResult{}, pair.descriptor, true); !errors.Is(err, ErrInvalidControlIO) {
		t.Fatal("unestablished result accepted")
	}
	if _, err := NewProtectedControlIO(pair.left, pair.ar, nil, true); !errors.Is(err, ErrInvalidControlIO) {
		t.Fatal("empty context accepted")
	}
	sendControl(t, pair.a, pair.b, 3, []byte{0, 1, 0, 0})
	for _, kind := range []uint8{6, 7, 8} {
		message := sendControl(t, pair.a, pair.b, kind, []byte{1, 2, 3})
		if message.Type != kind {
			t.Fatal("opaque FACT type was lost")
		}
	}
}
