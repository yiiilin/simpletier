package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

const (
	fxPathID     uint64 = 0x0102030405060708
	fxGeneration uint32 = 7
	fxPathID2    uint64 = 0x1112131415161718
)

func pattern32(seed byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}

func nodeIDFor(key [32]byte) [16]byte {
	digest := sha256.Sum256(key[:])
	var id [16]byte
	copy(id[:], digest[:16])
	return id
}

func copyParams(p HandshakeParams) HandshakeParams {
	copied := p
	copied.Prologue = append([]byte(nil), p.Prologue...)
	return copied
}

func fakePayload(tag string, p HandshakeParams, extra []byte) []byte {
	h := sha256.New()
	h.Write([]byte("simpletier-test/session/"))
	h.Write([]byte(tag))
	h.Write(p.Prologue)
	var scratch [8]byte
	binary.BigEndian.PutUint32(scratch[:4], p.Attempt)
	h.Write(scratch[:4])
	binary.BigEndian.PutUint32(scratch[:4], p.TargetEpoch)
	h.Write(scratch[:4])
	h.Write(extra)
	sum := h.Sum(nil)
	out := make([]byte, 0, len(tag)+len(sum))
	out = append(out, tag...)
	return append(out, sum...)
}

// fakeCrypto is a deterministic in-memory CryptoProvider. It never derives a
// real key: it exists so the state machine, caching and rejection rules can be
// exercised while the Noise IK/KDF implementation is still unfrozen.
type fakeCrypto struct {
	mu sync.Mutex

	initiateCalls int
	respondCalls  int
	finishCalls   int
	params        []HandshakeParams

	block bool

	initiateErr error
	respondErr  error
	finishErr   error
}

func (f *fakeCrypto) blocking() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.block = true
}

func (f *fakeCrypto) record(p HandshakeParams) {
	f.params = append(f.params, copyParams(p))
}

func (f *fakeCrypto) Initiate(ctx context.Context, p HandshakeParams) ([]byte, error) {
	f.mu.Lock()
	block, err := f.block, f.initiateErr
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.initiateCalls++
	f.record(p)
	if err != nil {
		return nil, err
	}
	return fakePayload("first", p, nil), nil
}

func (f *fakeCrypto) Respond(ctx context.Context, p HandshakeParams, first []byte) ([]byte, []byte, error) {
	f.mu.Lock()
	block, err := f.block, f.respondErr
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.respondCalls++
	f.record(p)
	if err != nil {
		return nil, nil, err
	}
	return fakePayload("reply", p, first), fakePayload("root-r", p, nil), nil
}

func (f *fakeCrypto) Finish(ctx context.Context, p HandshakeParams, reply []byte) ([]byte, error) {
	f.mu.Lock()
	block, err := f.block, f.finishErr
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finishCalls++
	f.record(p)
	if err != nil {
		return nil, err
	}
	return fakePayload("root-i", p, reply), nil
}

func (f *fakeCrypto) counts() (initiate, respond, finish int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.initiateCalls, f.respondCalls, f.finishCalls
}

func (f *fakeCrypto) lastParams(t *testing.T) HandshakeParams {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.params) == 0 {
		t.Fatalf("fake crypto received no handshake params")
	}
	return f.params[len(f.params)-1]
}

type fixture struct {
	t *testing.T

	mgr    *Manager
	fake   *fakeCrypto
	crypto CryptoProvider

	contextID [32]byte
	psk       [32]byte
	localKey  [32]byte
	peerKey   [32]byte
	localNode [16]byte
	peerNode  [16]byte
}

func newFixture(t *testing.T, crypto CryptoProvider) *fixture {
	t.Helper()
	f := &fixture{
		t:         t,
		crypto:    crypto,
		contextID: pattern32(0xA0),
		psk:       pattern32(0x40),
		localKey:  pattern32(0x01),
		peerKey:   pattern32(0x80),
	}
	f.localNode = nodeIDFor(f.localKey)
	f.peerNode = nodeIDFor(f.peerKey)
	if fake, ok := crypto.(*fakeCrypto); ok {
		f.fake = fake
	}
	mgr, err := NewManager(Config{
		ContextID:   f.contextID,
		PSK:         f.psk,
		LocalStatic: f.localKey,
		PeerStatic:  f.peerKey,
		Crypto:      crypto,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	f.mgr = mgr
	t.Cleanup(func() { _ = mgr.Close() })
	return f
}

func (f *fixture) open(class SessionClass) *Session {
	f.t.Helper()
	s, err := f.mgr.Open(context.Background(), fxPathID, fxGeneration, class, class.Lane())
	if err != nil {
		f.t.Fatalf("Open: %v", err)
	}
	return s
}

// ctrl builds an inbound SESSION_CTRL for a responder: the envelope keeps
// Src=initiator (the peer) and Dst=responder (the local node).
func (f *fixture) ctrl(id SessionID, class SessionClass, attempt, epoch uint32, payload []byte) SessionCtrl {
	return SessionCtrl{
		SessionID:      id,
		Class:          class,
		DataLaneID:     class.Lane(),
		Attempt:        attempt,
		TargetEpoch:    epoch,
		PathID:         fxPathID,
		PathGeneration: fxGeneration,
		SrcNodeID:      f.peerNode,
		DstNodeID:      f.localNode,
		Payload:        payload,
	}
}

// reply builds the responder-to-initiator SESSION_CTRL for a local initiator.
func (f *fixture) reply(id SessionID, class SessionClass, attempt, epoch uint32, payload []byte) SessionCtrl {
	msg := f.ctrl(id, class, attempt, epoch, payload)
	msg.SrcNodeID, msg.DstNodeID = f.localNode, f.peerNode
	return msg
}

func (f *fixture) ready(id SessionID, class SessionClass, attempt, epoch uint32, pathID uint64, generation uint32) SessionReady {
	return SessionReady{
		SessionID:      id,
		Class:          class,
		DataLaneID:     class.Lane(),
		Attempt:        attempt,
		TargetEpoch:    epoch,
		PathID:         pathID,
		PathGeneration: generation,
		SrcNodeID:      f.localNode,
		DstNodeID:      f.peerNode,
	}
}

func (f *fixture) readyResponder(id SessionID, class SessionClass, attempt, epoch uint32) SessionReady {
	msg := f.ready(id, class, attempt, epoch, fxPathID, fxGeneration)
	msg.SrcNodeID, msg.DstNodeID = f.peerNode, f.localNode
	return msg
}

func sessionID(seed byte) SessionID {
	var id SessionID
	for i := range id {
		id[i] = seed + byte(i)
	}
	return id
}

func TestNewManagerValidatesConfig(t *testing.T) {
	valid := Config{
		ContextID:   pattern32(0xA0),
		PSK:         pattern32(0x40),
		LocalStatic: pattern32(0x01),
		PeerStatic:  pattern32(0x80),
	}
	if _, err := NewManager(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name string
		cfg  Config
		want error
	}{
		{"zero context", func() Config { c := valid; c.ContextID = [32]byte{}; return c }(), ErrInvalidConfig},
		{"zero psk", func() Config { c := valid; c.PSK = [32]byte{}; return c }(), ErrInvalidConfig},
		{"zero local static", func() Config { c := valid; c.LocalStatic = [32]byte{}; return c }(), ErrInvalidConfig},
		{"no peer source", func() Config { c := valid; c.PeerStatic = [32]byte{}; return c }(), ErrInvalidConfig},
		{"peer equals local", func() Config { c := valid; c.PeerStatic = valid.LocalStatic; return c }(), ErrInvalidConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewManager(tc.cfg); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v; want %v", err, tc.want)
			}
		})
	}

	resolverOnly := valid
	resolverOnly.PeerStatic = [32]byte{}
	resolverOnly.Resolver = resolverFunc(func(uint64, uint32, SessionClass) (Peer, error) {
		return Peer{NodeID: nodeIDFor(valid.PeerStatic), StaticKey: valid.PeerStatic}, nil
	})
	if _, err := NewManager(resolverOnly); err != nil {
		t.Fatalf("resolver-only config rejected: %v", err)
	}
}

type resolverFunc func(uint64, uint32, SessionClass) (Peer, error)

func (fn resolverFunc) ResolvePeer(pathID uint64, generation uint32, class SessionClass) (Peer, error) {
	return fn(pathID, generation, class)
}

func TestOpenStartsBaselineAttemptAndBindsPrologue(t *testing.T) {
	fake := &fakeCrypto{}
	f := newFixture(t, fake)
	before := time.Now()
	s := f.open(SessionClassStream)
	after := time.Now()

	if s.ID().IsZero() {
		t.Fatal("SessionID is zero")
	}
	if s.Role() != RoleInitiator || s.Class() != SessionClassStream || s.Lane() != LaneStream {
		t.Fatalf("role/class/lane = %s/%s/%s", s.Role(), s.Class(), s.Lane())
	}
	if s.PathID() != fxPathID || s.PathGeneration() != fxGeneration {
		t.Fatalf("path = %d/%d", s.PathID(), s.PathGeneration())
	}
	if s.Peer().NodeID != f.peerNode || s.Peer().StaticKey != f.peerKey {
		t.Fatalf("peer = %+v", s.Peer())
	}
	if s.State() != StatePending || !s.PendingAttempt() || s.Epoch() != 0 {
		t.Fatalf("state/attempt/epoch = %s/%v/%d", s.State(), s.PendingAttempt(), s.Epoch())
	}
	attempt := s.Attempt()
	if attempt.Attempt != 0 || attempt.TargetEpoch != 1 {
		t.Fatalf("first attempt = %d/%d; want 0/1", attempt.Attempt, attempt.TargetEpoch)
	}
	if len(attempt.Bytes) == 0 {
		t.Fatal("pending attempt has no cached payload")
	}
	if deadline := s.Deadline(); deadline.Before(before.Add(DefaultPendingTTL-time.Second)) || deadline.After(after.Add(DefaultPendingTTL+time.Second)) {
		t.Fatalf("deadline = %v; want about now+%s", deadline, DefaultPendingTTL)
	}
	if f.mgr.Len() != 1 {
		t.Fatalf("Len = %d; want 1", f.mgr.Len())
	}

	prologue := s.Prologue()
	if len(prologue) != PrologueBindingSize {
		t.Fatalf("prologue %d bytes; want %d", len(prologue), PrologueBindingSize)
	}
	want := make([]byte, 0, PrologueBindingSize)
	want = append(want, f.contextID[:]...)
	want = append(want, f.localNode[:]...)
	want = append(want, f.peerNode[:]...)
	sessionIDBytes := s.ID()
	want = append(want, sessionIDBytes[:]...)
	want = append(want, byte(SessionClassStream), byte(LaneStream))
	want = binary.BigEndian.AppendUint32(want, 0)
	want = binary.BigEndian.AppendUint32(want, 1)
	want = binary.BigEndian.AppendUint64(want, fxPathID)
	want = binary.BigEndian.AppendUint32(want, fxGeneration)
	if !bytes.Equal(prologue, want) {
		t.Fatalf("prologue = %x; want %x", prologue, want)
	}

	params := fake.lastParams(t)
	if !params.Initiator || params.Attempt != 0 || params.TargetEpoch != 1 {
		t.Fatalf("params role/attempt/epoch = %v/%d/%d", params.Initiator, params.Attempt, params.TargetEpoch)
	}
	if params.ContextID != f.contextID || params.PSK != f.psk {
		t.Fatal("params context/psk mismatch")
	}
	if params.LocalStatic != f.localKey || params.PeerStatic != f.peerKey {
		t.Fatal("params static key mismatch")
	}
	if params.LocalNodeID != f.localNode || params.PeerNodeID != f.peerNode {
		t.Fatal("params node id mismatch")
	}
	if params.SessionID != s.ID() || params.Class != SessionClassStream || params.DataLaneID != LaneStream {
		t.Fatal("params session identity mismatch")
	}
	if params.PathID != fxPathID || params.PathGeneration != fxGeneration {
		t.Fatal("params path mismatch")
	}
	if !bytes.Equal(params.Prologue, prologue) {
		t.Fatal("handshake prologue differs from Session.Prologue")
	}
	if len(params.Prologue) > 0 {
		params.Prologue[0] ^= 0xFF
		if bytes.Equal(s.Prologue(), params.Prologue) {
			t.Fatal("HandshakeParams.Prologue aliases internal state")
		}
	}
	if initiate, _, _ := fake.counts(); initiate != 1 {
		t.Fatalf("Initiate calls = %d; want 1", initiate)
	}
}

func TestOpenRejectsInvalidScope(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	cases := []struct {
		name       string
		ctx        context.Context
		pathID     uint64
		generation uint32
		class      SessionClass
		lane       Lane
		want       error
	}{
		{"nil context", nil, fxPathID, fxGeneration, SessionClassStream, LaneStream, ErrInvalidScope},
		{"zero path", context.Background(), 0, fxGeneration, SessionClassStream, LaneStream, ErrInvalidScope},
		{"zero generation", context.Background(), fxPathID, 0, SessionClassStream, LaneStream, ErrInvalidScope},
		{"bad class", context.Background(), fxPathID, fxGeneration, SessionClass(0x03), LaneStream, ErrInvalidClass},
		{"bad lane", context.Background(), fxPathID, fxGeneration, SessionClassStream, Lane(0), ErrInvalidLane},
		{"lane mismatch", context.Background(), fxPathID, fxGeneration, SessionClassStream, LanePacket, ErrLaneClassMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.mgr.Open(tc.ctx, tc.pathID, tc.generation, tc.class, tc.lane); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v; want %v", err, tc.want)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.mgr.Open(canceled, fxPathID, fxGeneration, SessionClassStream, LaneStream); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context err = %v", err)
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("Len = %d; want 0", f.mgr.Len())
	}
}

func TestOpenIsIdempotentForScope(t *testing.T) {
	fake := &fakeCrypto{}
	f := newFixture(t, fake)
	first := f.open(SessionClassPacket)
	second := f.open(SessionClassPacket)
	if first != second {
		t.Fatal("second Open returned a different Session")
	}
	if first.ID() != second.ID() {
		t.Fatal("SessionID changed on retry")
	}
	if !bytes.Equal(first.Attempt().Bytes, second.Attempt().Bytes) {
		t.Fatal("retry did not reuse the byte-identical cached attempt")
	}
	if initiate, _, _ := fake.counts(); initiate != 1 {
		t.Fatalf("Initiate calls = %d; want 1", initiate)
	}
	if f.mgr.Len() != 1 {
		t.Fatalf("Len = %d; want 1", f.mgr.Len())
	}
}

func TestPlaceholderCryptoRefusesHandshake(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := f.mgr.Open(context.Background(), fxPathID, fxGeneration, SessionClassStream, LaneStream); !errors.Is(err, ErrCryptoUnavailable) {
		t.Fatalf("Open err = %v; want ErrCryptoUnavailable", err)
	}
	_, _, err := f.mgr.HandleOpen(context.Background(), f.ctrl(sessionID(1), SessionClassStream, 0, 1, []byte("noise")))
	if !errors.Is(err, ErrCryptoUnavailable) {
		t.Fatalf("HandleOpen err = %v; want ErrCryptoUnavailable", err)
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("Len = %d; want 0", f.mgr.Len())
	}
}

func TestResponderHandshakeCachesByteIdenticalReply(t *testing.T) {
	fake := &fakeCrypto{}
	f := newFixture(t, fake)
	id := sessionID(0x10)
	msg := f.ctrl(id, SessionClassStream, 0, 1, []byte("first-message"))

	s, out, err := f.mgr.HandleOpen(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleOpen: %v", err)
	}
	if s.ID() != id || s.Role() != RoleResponder || s.State() != StatePending {
		t.Fatalf("session = %s/%s/%s", s.ID(), s.Role(), s.State())
	}
	if len(out) == 0 || !bytes.Equal(s.Attempt().Bytes, out) {
		t.Fatal("cached reply differs from returned payload")
	}
	if attempt := s.Attempt(); attempt.Attempt != 0 || attempt.TargetEpoch != 1 {
		t.Fatalf("attempt = %d/%d; want 0/1", attempt.Attempt, attempt.TargetEpoch)
	}
	if root := s.Root(); root != nil {
		t.Fatal("responder exposes uncommitted root material before SESSION_READY")
	}
	if _, _, _, err := (func() (int, int, int, error) {
		same, again, err := f.mgr.HandleOpen(context.Background(), msg)
		if same != s {
			t.Errorf("retry returned a different Session")
		}
		if !bytes.Equal(again, out) {
			t.Errorf("retry reply = %x; want %x", again, out)
		}
		i, r, _ := fake.counts()
		return i, r, 0, err
	})(); err != nil {
		t.Fatalf("idempotent HandleOpen: %v", err)
	}
	if initiate, respond, _ := fake.counts(); initiate != 0 || respond != 1 {
		t.Fatalf("crypto calls initiate=%d respond=%d; want 0/1", initiate, respond)
	}

	conflict := f.ctrl(id, SessionClassStream, 0, 1, []byte("different-message"))
	if _, _, err := f.mgr.HandleOpen(context.Background(), conflict); !errors.Is(err, ErrAttemptConflict) {
		t.Fatalf("conflict err = %v; want ErrAttemptConflict", err)
	}
	if _, respond, _ := fake.counts(); respond != 1 {
		t.Fatalf("conflict consumed handshake state: respond=%d", respond)
	}

	stale := f.ctrl(id, SessionClassStream, 0, 1, []byte("first-message"))
	stale.SessionID = sessionID(0x11)
	if _, _, err := f.mgr.HandleOpen(context.Background(), stale); !errors.Is(err, ErrSessionIDMismatch) {
		t.Fatalf("SessionID mismatch err = %v", err)
	}
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.ctrl(id, SessionClassStream, 1, 2, []byte("next"))); !errors.Is(err, ErrFutureAttempt) {
		t.Fatalf("future attempt err = %v", err)
	}
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.ctrl(id, SessionClassStream, 0, 2, []byte("first-message"))); !errors.Is(err, ErrFutureEpoch) {
		t.Fatalf("future epoch err = %v", err)
	}
	swapped := f.ctrl(id, SessionClassStream, 0, 1, []byte("first-message"))
	swapped.SrcNodeID, swapped.DstNodeID = f.localNode, f.peerNode
	if _, _, err := f.mgr.HandleOpen(context.Background(), swapped); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("swapped endpoints err = %v", err)
	}
}

func TestResponderReadyCommitAndDuplicates(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	id := sessionID(0x20)
	msg := f.ctrl(id, SessionClassPacket, 0, 1, []byte("first"))
	s, _, err := f.mgr.HandleOpen(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleOpen: %v", err)
	}
	ready := f.readyResponder(id, SessionClassPacket, 0, 1)
	if err := f.mgr.HandleReady(ready); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	if s.State() != StateReady || s.Epoch() != 1 || s.PendingAttempt() {
		t.Fatalf("state/epoch/pending = %s/%d/%v", s.State(), s.Epoch(), s.PendingAttempt())
	}
	if s.Attempt().Bytes != nil {
		t.Fatal("committed attempt still exposes cached bytes")
	}
	if err := f.mgr.HandleReady(ready); err != nil {
		t.Fatalf("duplicate READY: %v", err)
	}
	if err := f.mgr.HandleReady(f.readyResponder(id, SessionClassPacket, 1, 2)); !errors.Is(err, ErrFutureAttempt) {
		t.Fatalf("future READY err = %v", err)
	}
	stale := f.readyResponder(id, SessionClassPacket, 0, 0)
	if err := f.mgr.HandleReady(stale); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("stale READY err = %v", err)
	}
	wrongID := f.readyResponder(sessionID(0x21), SessionClassPacket, 0, 1)
	if err := f.mgr.HandleReady(wrongID); !errors.Is(err, ErrSessionIDMismatch) {
		t.Fatalf("SessionID mismatch err = %v", err)
	}
	unknown := f.readyResponder(id, SessionClassPacket, 0, 1)
	unknown.PathID = fxPathID2
	if err := f.mgr.HandleReady(unknown); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown session err = %v", err)
	}
	if err := f.mgr.HandleReady(SessionReady{}); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("empty READY err = %v", err)
	}
	if s.State() != StateReady || s.Epoch() != 1 {
		t.Fatalf("rejected READY mutated state: %s/%d", s.State(), s.Epoch())
	}
}

func TestInitiatorFinishesOnceAndCommits(t *testing.T) {
	fake := &fakeCrypto{}
	f := newFixture(t, fake)
	s := f.open(SessionClassStream)
	if err := s.MarkReady(0, 1); !errors.Is(err, ErrHandshakeIncomplete) {
		t.Fatalf("MarkReady before finish err = %v", err)
	}
	reply := f.reply(s.ID(), SessionClassStream, 0, 1, []byte("reply-bytes"))
	got, out, err := f.mgr.HandleOpen(context.Background(), reply)
	if err != nil || got != s || out != nil {
		t.Fatalf("HandleOpen reply = %v/%v/%v", got, out, err)
	}
	if root := s.Root(); root != nil {
		t.Fatal("initiator exposes uncommitted root material before SESSION_READY")
	}
	if _, _, finish := fake.counts(); finish != 1 {
		t.Fatalf("Finish calls = %d; want 1", finish)
	}

	// A byte-identical duplicate must not consume handshake state again.
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.reply(s.ID(), SessionClassStream, 0, 1, []byte("reply-bytes"))); err != nil {
		t.Fatalf("duplicate reply: %v", err)
	}
	if _, _, finish := fake.counts(); finish != 1 {
		t.Fatalf("duplicate reply re-consumed state: Finish = %d", finish)
	}
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.reply(s.ID(), SessionClassStream, 0, 1, []byte("other-reply"))); !errors.Is(err, ErrAttemptConflict) {
		t.Fatalf("conflicting reply err = %v", err)
	}
	if err := s.MarkReady(0, 2); !errors.Is(err, ErrFutureEpoch) {
		t.Fatalf("future epoch commit err = %v", err)
	}
	if err := s.MarkReady(1, 1); !errors.Is(err, ErrFutureAttempt) {
		t.Fatalf("future attempt commit err = %v", err)
	}
	if err := s.MarkReady(0, 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	if s.State() != StateReady || s.Epoch() != 1 || s.PendingAttempt() {
		t.Fatalf("state/epoch/pending = %s/%d/%v", s.State(), s.Epoch(), s.PendingAttempt())
	}
	if len(s.Root()) == 0 {
		t.Fatal("committed session exposes no root material")
	}
	if err := s.MarkReady(0, 1); err != nil {
		t.Fatalf("idempotent MarkReady: %v", err)
	}
	if err := s.MarkReady(0, 0); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("stale epoch err = %v", err)
	}
	late := f.reply(s.ID(), SessionClassStream, 0, 1, []byte("reply-bytes"))
	if _, _, err := f.mgr.HandleOpen(context.Background(), late); !errors.Is(err, ErrReplay) {
		t.Fatalf("late reply err = %v", err)
	}
}

func TestRekeyMergesAndAdvancesEpoch(t *testing.T) {
	fake := &fakeCrypto{}
	f := newFixture(t, fake)
	s := f.open(SessionClassStream)
	if _, err := s.Rekey(context.Background()); !errors.Is(err, ErrSessionState) {
		t.Fatalf("rekey before commit err = %v", err)
	}
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.reply(s.ID(), SessionClassStream, 0, 1, []byte("reply"))); err != nil {
		t.Fatalf("finish initiator: %v", err)
	}
	if err := s.MarkReady(0, 1); err != nil {
		t.Fatalf("first MarkReady: %v", err)
	}
	first, err := s.Rekey(context.Background())
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	if first.Attempt != 1 || first.TargetEpoch != 2 || len(first.Bytes) == 0 {
		t.Fatalf("rekey attempt = %d/%d (%d bytes)", first.Attempt, first.TargetEpoch, len(first.Bytes))
	}
	merged, err := s.Rekey(context.Background())
	if err != nil {
		t.Fatalf("merged Rekey: %v", err)
	}
	if merged.Attempt != first.Attempt || !bytes.Equal(merged.Bytes, first.Bytes) {
		t.Fatal("concurrent rekey did not merge into the same byte-identical attempt")
	}
	if initiate, _, _ := fake.counts(); initiate != 2 {
		t.Fatalf("Initiate calls = %d; want 2", initiate)
	}
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.reply(s.ID(), SessionClassStream, 1, 2, []byte("reply2"))); err != nil {
		t.Fatalf("rekey finish: %v", err)
	}
	if err := s.MarkReady(1, 2); err != nil {
		t.Fatalf("rekey MarkReady: %v", err)
	}
	if s.Epoch() != 2 || s.State() != StateReady {
		t.Fatalf("epoch/state = %d/%s", s.Epoch(), s.State())
	}
	if err := s.MarkReady(0, 1); !errors.Is(err, ErrStaleAttempt) {
		t.Fatalf("stale commit err = %v", err)
	}
	if err := s.MarkReady(2, 3); !errors.Is(err, ErrFutureAttempt) {
		t.Fatalf("future commit err = %v", err)
	}
}

func TestRekeyRejectedForResponder(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	id := sessionID(0x30)
	s, _, err := f.mgr.HandleOpen(context.Background(), f.ctrl(id, SessionClassStream, 0, 1, []byte("first")))
	if err != nil {
		t.Fatalf("HandleOpen: %v", err)
	}
	if err := f.mgr.HandleReady(f.readyResponder(id, SessionClassStream, 0, 1)); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	if _, err := s.Rekey(context.Background()); !errors.Is(err, ErrSessionState) {
		t.Fatalf("responder rekey err = %v", err)
	}
}

func TestPendingByteAccounting(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	s := f.open(SessionClassStream)
	if err := s.ReservePending(MaxPendingBytes); err != nil {
		t.Fatalf("reserve max: %v", err)
	}
	if got := s.PendingBytes(); got != MaxPendingBytes {
		t.Fatalf("PendingBytes = %d; want %d", got, MaxPendingBytes)
	}
	if err := s.ReservePending(1); !errors.Is(err, ErrPendingLimit) {
		t.Fatalf("over-limit err = %v", err)
	}
	if err := s.ReservePending(-1); !errors.Is(err, ErrInvalidPending) {
		t.Fatalf("negative reserve err = %v", err)
	}
	s.ReleasePending(MaxPendingBytes)
	if got := s.PendingBytes(); got != 0 {
		t.Fatalf("PendingBytes after release = %d", got)
	}
	s.ReleasePending(100)
	if got := s.PendingBytes(); got != 0 {
		t.Fatalf("over-release = %d", got)
	}
	if err := s.ReservePending(1); err != nil {
		t.Fatalf("reserve after release: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := s.PendingBytes(); got != 0 {
		t.Fatalf("close retained pending accounting: %d", got)
	}
	if err := s.ReservePending(1); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("reserve after close err = %v", err)
	}
}

func TestDeadlineExpiresPendingSession(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, err := f.mgr.Open(ctx, fxPathID, fxGeneration, SessionClassStream, LaneStream)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	deadline := s.Deadline()
	if !deadline.Equal(time.Now().Add(time.Minute).Truncate(time.Second)) && deadline.After(time.Now().Add(time.Minute)) {
		t.Fatalf("deadline %v ignores the earlier context deadline", deadline)
	}
	if expired := f.mgr.ExpirePending(deadline.Add(-time.Millisecond)); expired != 0 {
		t.Fatalf("expired %d sessions before the deadline", expired)
	}
	if s.State() != StatePending {
		t.Fatalf("state before deadline = %s", s.State())
	}
	if expired := f.mgr.ExpirePending(deadline); expired != 1 {
		t.Fatalf("expired = %d; want 1", expired)
	}
	if s.State() != StateBroken {
		t.Fatalf("state = %s; want Broken", s.State())
	}
	if err := s.MarkReady(0, 1); !errors.Is(err, ErrSessionTimeout) {
		t.Fatalf("commit after timeout err = %v", err)
	}
	if err := s.ReservePending(1); !errors.Is(err, ErrSessionTimeout) {
		t.Fatalf("reserve after timeout err = %v", err)
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("Len = %d; want 0", f.mgr.Len())
	}
	if _, err := f.mgr.Lookup(fxPathID, fxGeneration, SessionClassStream); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("lookup after timeout err = %v", err)
	}
	if err := f.mgr.HandleReady(f.ready(s.ID(), SessionClassStream, 0, 1, fxPathID, fxGeneration)); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("READY after timeout err = %v", err)
	}
}

func TestOpenHonoursContextDuringHandshake(t *testing.T) {
	fake := &fakeCrypto{}
	fake.blocking()
	f := newFixture(t, fake)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := f.mgr.Open(ctx, fxPathID, fxGeneration, SessionClassStream, LaneStream)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v; want context.DeadlineExceeded", err)
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("failed Open left %d sessions", f.mgr.Len())
	}
	if _, err := f.mgr.Lookup(fxPathID, fxGeneration, SessionClassStream); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("lookup after canceled Open err = %v", err)
	}
	if _, err := NewManager(Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
}

func TestAbortAndCloseAreTerminalAndAllowFreshSession(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	s := f.open(SessionClassPacket)
	firstID := s.ID()
	if err := s.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if s.State() != StateBroken {
		t.Fatalf("state = %s; want Broken", s.State())
	}
	if err := s.Abort(); err != nil {
		t.Fatalf("idempotent Abort: %v", err)
	}
	if err := s.MarkReady(0, 1); !errors.Is(err, ErrSessionAborted) {
		t.Fatalf("commit after abort err = %v", err)
	}
	if s.Root() != nil {
		t.Fatal("aborted session exposes root material")
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("Len = %d; want 0", f.mgr.Len())
	}
	fresh := f.open(SessionClassPacket)
	if fresh.ID() == firstID {
		t.Fatal("aborted SessionID was reused")
	}
	if err := fresh.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
	if fresh.State() != StateClosed {
		t.Fatalf("state = %s; want Closed", fresh.State())
	}
	if _, err := fresh.Rekey(context.Background()); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("rekey after close err = %v", err)
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("Len = %d; want 0", f.mgr.Len())
	}
	if err := f.mgr.Close(); err != nil {
		t.Fatalf("manager Close: %v", err)
	}
	if _, err := f.mgr.Open(context.Background(), fxPathID2, fxGeneration, SessionClassStream, LaneStream); !errors.Is(err, ErrClosed) {
		t.Fatalf("Open after manager Close err = %v", err)
	}
}

func TestSessionTableLimit(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	for i := 0; i < MaxSessions; i++ {
		if _, err := f.mgr.Open(context.Background(), fxPathID+uint64(i)+1, fxGeneration, SessionClassStream, LaneStream); err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
	}
	if f.mgr.Len() != MaxSessions {
		t.Fatalf("Len = %d; want %d", f.mgr.Len(), MaxSessions)
	}
	_, err := f.mgr.Open(context.Background(), fxPathID+MaxSessions+1, fxGeneration, SessionClassStream, LaneStream)
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("over-limit err = %v", err)
	}
	victim, err := f.mgr.Lookup(fxPathID+1, fxGeneration, SessionClassStream)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if err := victim.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := f.mgr.Open(context.Background(), fxPathID+MaxSessions+1, fxGeneration, SessionClassStream, LaneStream); err != nil {
		t.Fatalf("Open after release: %v", err)
	}
}

// tombstoneCount and tombstoneExpiry inspect the internal termination records.
// Tombstones are deliberately not part of the public API; the tests read the
// table directly to pin the bounded lifetime and the MaxSessions accounting.
func tombstoneCount(m *Manager) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tombstones)
}

func tombstoneExpiry(m *Manager, id SessionID) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	expires, ok := m.tombstones[id]
	return expires, ok
}

func TestAbortTombstoneRejectsLateSessionCtrl(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	s := f.open(SessionClassStream)
	deadID := s.ID()
	if err := s.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if got := tombstoneCount(f.mgr); got != 1 {
		t.Fatalf("tombstones = %d; want 1", got)
	}
	// Closing the aborted handle is a local release only: the tombstone of the
	// failed identity survives it.
	if err := s.Close(); err != nil {
		t.Fatalf("Close after Abort: %v", err)
	}
	if got := tombstoneCount(f.mgr); got != 1 {
		t.Fatalf("tombstones = %d after closing an aborted handle; want 1", got)
	}
	// The aborted identity must not be rebuilt as a responder Session from a
	// replayed bootstrap SESSION_CTRL, nor from a late responder reply.
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.ctrl(deadID, SessionClassStream, 0, 1, []byte("late-first"))); !errors.Is(err, ErrStaleSessionID) {
		t.Fatalf("late SESSION_CTRL err = %v; want ErrStaleSessionID", err)
	}
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.reply(deadID, SessionClassStream, 0, 1, []byte("late-reply"))); !errors.Is(err, ErrStaleSessionID) {
		t.Fatalf("late SESSION_CTRL reply err = %v; want ErrStaleSessionID", err)
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("Len = %d; want 0", f.mgr.Len())
	}
	if _, err := f.mgr.Lookup(fxPathID, fxGeneration, SessionClassStream); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Lookup after Abort err = %v; want ErrSessionNotFound", err)
	}
	// The scope itself stays reusable, but only under a fresh SessionID.
	fresh, err := f.mgr.Open(context.Background(), fxPathID, fxGeneration, SessionClassStream, LaneStream)
	if err != nil {
		t.Fatalf("Open after Abort: %v", err)
	}
	if fresh.ID() == deadID {
		t.Fatal("terminated SessionID was handed out again")
	}
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.ctrl(deadID, SessionClassStream, 0, 1, []byte("late-first"))); !errors.Is(err, ErrStaleSessionID) {
		t.Fatalf("late SESSION_CTRL after reopen err = %v; want ErrStaleSessionID", err)
	}
}

func TestPendingTimeoutTombstoneRejectsRetransmittedSessionCtrl(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	id := sessionID(0x31)
	msg := f.ctrl(id, SessionClassStream, 0, 1, []byte("first"))
	s, out, err := f.mgr.HandleOpen(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleOpen: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("responder returned no SESSION_CTRL reply")
	}
	if expired := f.mgr.ExpirePending(s.Deadline()); expired != 1 {
		t.Fatalf("expired = %d; want 1", expired)
	}
	if s.State() != StateBroken {
		t.Fatalf("state = %s; want Broken", s.State())
	}
	if got := tombstoneCount(f.mgr); got != 1 {
		t.Fatalf("tombstones = %d; want 1", got)
	}
	// The peer's retransmission must not create a second Session under the
	// timed-out identity.
	if _, _, err := f.mgr.HandleOpen(context.Background(), msg); !errors.Is(err, ErrStaleSessionID) {
		t.Fatalf("retransmitted SESSION_CTRL err = %v; want ErrStaleSessionID", err)
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("Len = %d; want 0", f.mgr.Len())
	}
	// Recovery for the same scope is admitted only under a new SessionID.
	freshID := sessionID(0x32)
	fresh, _, err := f.mgr.HandleOpen(context.Background(), f.ctrl(freshID, SessionClassStream, 0, 1, []byte("fresh-first")))
	if err != nil {
		t.Fatalf("fresh SESSION_CTRL for the same scope err = %v", err)
	}
	if fresh.ID() != freshID {
		t.Fatalf("fresh session id = %s; want %s", fresh.ID(), freshID)
	}
}

func TestTombstoneExpiryDropsRecordButNeverReissuesSessionID(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	s := f.open(SessionClassStream)
	deadID := s.ID()
	if err := s.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	expires, ok := tombstoneExpiry(f.mgr, deadID)
	if !ok {
		t.Fatal("Abort left no tombstone")
	}
	if window := time.Until(expires); window <= 0 || window > tombstoneTTL {
		t.Fatalf("tombstone window = %v; want (0, %v]", window, tombstoneTTL)
	}
	if expired := f.mgr.ExpirePending(expires.Add(-time.Millisecond)); expired != 0 {
		t.Fatalf("expired = %d before the tombstone expiry; want 0", expired)
	}
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.ctrl(deadID, SessionClassStream, 0, 1, []byte("late"))); !errors.Is(err, ErrStaleSessionID) {
		t.Fatalf("late SESSION_CTRL inside the window err = %v; want ErrStaleSessionID", err)
	}
	// The expiry pass reclaims the record without counting it as a failed
	// Session.
	if expired := f.mgr.ExpirePending(expires); expired != 0 {
		t.Fatalf("expired = %d at the tombstone expiry; want 0", expired)
	}
	if got := tombstoneCount(f.mgr); got != 0 {
		t.Fatalf("tombstones = %d after expiry; want 0", got)
	}
	// Reuse of the scope still binds a new SessionID; the dead one is never
	// handed out again.
	fresh, err := f.mgr.Open(context.Background(), fxPathID, fxGeneration, SessionClassStream, LaneStream)
	if err != nil {
		t.Fatalf("Open after tombstone expiry: %v", err)
	}
	if fresh.ID() == deadID {
		t.Fatal("tombstoned SessionID was reissued")
	}
}

func TestTombstonesShareTheMaxSessionsCeiling(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	for i := 0; i < MaxSessions; i++ {
		s, err := f.mgr.Open(context.Background(), fxPathID+uint64(i)+1, fxGeneration, SessionClassStream, LaneStream)
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		if err := s.Abort(); err != nil {
			t.Fatalf("Abort %d: %v", i, err)
		}
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("Len = %d; want 0", f.mgr.Len())
	}
	if got := tombstoneCount(f.mgr); got != MaxSessions {
		t.Fatalf("tombstones = %d; want %d", got, MaxSessions)
	}
	// Unexpired tombstones hold the table budget, so new Sessions are refused
	// with the same sentinel as the live ceiling.
	if _, err := f.mgr.Open(context.Background(), fxPathID+MaxSessions+1, fxGeneration, SessionClassStream, LaneStream); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("Open while saturated with tombstones err = %v; want ErrResourceLimit", err)
	}
	// Expiry reclaims every slot; the return value counts failed Sessions only.
	if expired := f.mgr.ExpirePending(time.Now().Add(tombstoneTTL + time.Minute)); expired != 0 {
		t.Fatalf("expired = %d; want 0", expired)
	}
	if got := tombstoneCount(f.mgr); got != 0 {
		t.Fatalf("tombstones = %d after expiry; want 0", got)
	}
	if _, err := f.mgr.Open(context.Background(), fxPathID+MaxSessions+1, fxGeneration, SessionClassStream, LaneStream); err != nil {
		t.Fatalf("Open after tombstone expiry: %v", err)
	}
}

func TestManagerCloseClearsTombstones(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	s := f.open(SessionClassStream)
	deadID := s.ID()
	if err := s.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if got := tombstoneCount(f.mgr); got != 1 {
		t.Fatalf("tombstones = %d; want 1", got)
	}
	if err := f.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := tombstoneCount(f.mgr); got != 0 {
		t.Fatalf("tombstones = %d after Close; want 0", got)
	}
	if err := f.mgr.Close(); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.ctrl(deadID, SessionClassStream, 0, 1, []byte("late"))); !errors.Is(err, ErrClosed) {
		t.Fatalf("HandleOpen after manager Close err = %v; want ErrClosed", err)
	}
}

func TestCleanCloseLeavesNoTombstone(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	s := f.open(SessionClassStream)
	id := s.ID()
	// Close is the deliberate local release, so the confirmed policy keeps it
	// out of the tombstone path and frees the SessionID and scope at once.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := tombstoneCount(f.mgr); got != 0 {
		t.Fatalf("tombstones = %d after a clean Close; want 0", got)
	}
	if _, ok := tombstoneExpiry(f.mgr, id); ok {
		t.Fatal("clean Close left a tombstone")
	}
	fresh, err := f.mgr.Open(context.Background(), fxPathID, fxGeneration, SessionClassStream, LaneStream)
	if err != nil {
		t.Fatalf("Open after clean Close: %v", err)
	}
	if fresh.ID() == id {
		t.Fatal("cleanly closed SessionID was handed out again")
	}
}

func TestOpenNeverReissuesATombstonedSessionID(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	s := f.open(SessionClassStream)
	deadID := s.ID()
	if err := s.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	// Force the CSPRNG hook to hand back the dead SessionID once: the generator
	// must retry instead of rebinding a tombstoned identity.
	var calls int
	f.mgr.mu.Lock()
	f.mgr.rand = func(b []byte) error {
		calls++
		if calls == 1 {
			copy(b, deadID[:])
			return nil
		}
		for i := range b {
			b[i] = 0x5A + byte(i)
		}
		return nil
	}
	f.mgr.mu.Unlock()
	fresh, err := f.mgr.Open(context.Background(), fxPathID, fxGeneration, SessionClassStream, LaneStream)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if fresh.ID() == deadID {
		t.Fatal("tombstoned SessionID was reissued")
	}
	if calls != 2 {
		t.Fatalf("rand calls = %d; want 2 (one tombstoned candidate, one fresh)", calls)
	}
}

func TestConcurrentTombstoneRejectionAndCleanup(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	const workers, rounds = 6, 16

	// Phase 1: a sweep with a deadline in the past can never drop a fresh
	// tombstone, so every late SESSION_CTRL for an aborted identity is rejected
	// while Open/Abort/sweep/Len run concurrently.
	stop := make(chan struct{})
	var sweep sync.WaitGroup
	sweep.Add(1)
	go func() {
		defer sweep.Done()
		for {
			select {
			case <-stop:
				return
			default:
				f.mgr.ExpirePending(time.Now().Add(-time.Minute))
				f.mgr.Len()
			}
		}
	}()
	var wg sync.WaitGroup
	lateCtrl := func(pathID uint64, id SessionID) SessionCtrl {
		return SessionCtrl{
			SessionID:      id,
			Class:          SessionClassStream,
			DataLaneID:     LaneStream,
			Attempt:        FirstAttempt,
			TargetEpoch:    FirstTargetEpoch,
			PathID:         pathID,
			PathGeneration: fxGeneration,
			SrcNodeID:      f.peerNode,
			DstNodeID:      f.localNode,
			Payload:        []byte("late-first"),
		}
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				pathID := fxPathID + 0x100000 + uint64(w*rounds+i)
				s, err := f.mgr.Open(context.Background(), pathID, fxGeneration, SessionClassStream, LaneStream)
				if err != nil {
					t.Errorf("Open: %v", err)
					return
				}
				id := s.ID()
				if err := s.Abort(); err != nil {
					t.Errorf("Abort: %v", err)
					return
				}
				if _, _, err := f.mgr.HandleOpen(context.Background(), lateCtrl(pathID, id)); !errors.Is(err, ErrStaleSessionID) {
					t.Errorf("late SESSION_CTRL err = %v; want ErrStaleSessionID", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	sweep.Wait()
	if got := tombstoneCount(f.mgr); got != workers*rounds {
		t.Fatalf("tombstones = %d; want %d", got, workers*rounds)
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("Len = %d; want 0", f.mgr.Len())
	}

	// Phase 2: a sweep that does advance past the TTL races with Open/Abort, so
	// a late SESSION_CTRL is either still rejected or, once its tombstone was
	// reclaimed, admitted under its original SessionID. No other outcome is
	// legal.
	stop = make(chan struct{})
	sweep.Add(1)
	go func() {
		defer sweep.Done()
		for {
			select {
			case <-stop:
				return
			default:
				f.mgr.ExpirePending(time.Now().Add(tombstoneTTL + time.Minute))
				time.Sleep(time.Millisecond)
			}
		}
	}()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				pathID := fxPathID + 0x200000 + uint64(w*rounds+i)
				s, err := f.mgr.Open(context.Background(), pathID, fxGeneration, SessionClassStream, LaneStream)
				if err != nil {
					t.Errorf("Open: %v", err)
					return
				}
				id := s.ID()
				if err := s.Abort(); err != nil {
					t.Errorf("Abort: %v", err)
					return
				}
				reborn, _, err := f.mgr.HandleOpen(context.Background(), lateCtrl(pathID, id))
				switch {
				case errors.Is(err, ErrStaleSessionID):
					// Still inside the tombstone window.
				case err == nil:
					if reborn == nil || reborn.ID() != id || reborn.Role() != RoleResponder {
						t.Errorf("admitted SESSION_CTRL built %v; want responder session %s", reborn, id)
						return
					}
					if err := reborn.Close(); err != nil {
						t.Errorf("Close: %v", err)
						return
					}
				default:
					t.Errorf("late SESSION_CTRL err = %v; want ErrStaleSessionID or nil", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	sweep.Wait()
	if got := tombstoneCount(f.mgr); got > MaxSessions {
		t.Fatalf("tombstones = %d; want <= %d", got, MaxSessions)
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("Len = %d; want 0", f.mgr.Len())
	}
}

func TestCodecRoundTripAndRejections(t *testing.T) {
	id := sessionID(0x50)
	src := nodeIDFor(pattern32(0x01))
	ctrl := SessionCtrl{
		SessionID:      id,
		Class:          SessionClassStream,
		DataLaneID:     LaneStream,
		Attempt:        3,
		TargetEpoch:    4,
		PathID:         fxPathID,
		PathGeneration: fxGeneration,
		SrcNodeID:      src,
		Payload:        []byte("noise-message"),
	}
	encoded, err := ctrl.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if want := sessionCtrlHeaderSize + sessionCtrlLengthSize + len(ctrl.Payload); len(encoded) != want {
		t.Fatalf("encoded %d bytes; want %d", len(encoded), want)
	}
	decoded, err := DecodeSessionCtrl(encoded)
	if err != nil {
		t.Fatalf("DecodeSessionCtrl: %v", err)
	}
	if decoded.SessionID != id || decoded.Class != SessionClassStream || decoded.DataLaneID != LaneStream ||
		decoded.Attempt != 3 || decoded.TargetEpoch != 4 || !bytes.Equal(decoded.Payload, ctrl.Payload) {
		t.Fatalf("decoded = %+v", decoded)
	}
	if decoded.PathID != 0 || decoded.PathGeneration != 0 {
		t.Fatal("envelope-owned fields decoded from the SESSION_CTRL payload")
	}

	ready := SessionReady{
		SessionID:      id,
		Class:          SessionClassPacket,
		DataLaneID:     LanePacket,
		Attempt:        1,
		TargetEpoch:    2,
		PathID:         fxPathID,
		PathGeneration: fxGeneration,
	}
	encodedReady, err := ready.Encode()
	if err != nil {
		t.Fatalf("Encode READY: %v", err)
	}
	if len(encodedReady) != sessionReadySize {
		t.Fatalf("READY encoded %d bytes; want %d", len(encodedReady), sessionReadySize)
	}
	decodedReady, err := DecodeSessionReady(encodedReady)
	if err != nil {
		t.Fatalf("DecodeSessionReady: %v", err)
	}
	if decodedReady.SessionID != id || decodedReady.Class != SessionClassPacket || decodedReady.DataLaneID != LanePacket ||
		decodedReady.Attempt != 1 || decodedReady.TargetEpoch != 2 || decodedReady.PathID != fxPathID || decodedReady.PathGeneration != fxGeneration {
		t.Fatalf("decoded READY = %+v", decodedReady)
	}

	badCtrl := []struct {
		name string
		raw  []byte
		want error
	}{
		{"short", encoded[:10], ErrMalformedMessage},
		{"length mismatch", append(append([]byte(nil), encoded[:28]...), 0xFF), ErrMalformedMessage},
		{"empty payload", encoded[:28], ErrMalformedMessage},
		{"bad class", func() []byte { b := append([]byte(nil), encoded...); b[16] = 0x09; return b }(), ErrInvalidClass},
		{"lane mismatch", func() []byte { b := append([]byte(nil), encoded...); b[17] = byte(LanePacket); return b }(), ErrLaneClassMismatch},
	}
	for _, tc := range badCtrl {
		t.Run("ctrl/"+tc.name, func(t *testing.T) {
			if _, err := DecodeSessionCtrl(tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v; want %v", err, tc.want)
			}
		})
	}
	if _, err := DecodeSessionReady(encodedReady[:sessionReadySize-1]); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("short READY err = %v", err)
	}
	if _, err := DecodeSessionReady(append(append([]byte(nil), encodedReady...), 0)); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("long READY err = %v", err)
	}
	empty := SessionCtrl{SessionID: id, Class: SessionClassStream, DataLaneID: LaneStream}
	if _, err := empty.Encode(); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("empty payload encode err = %v", err)
	}
	oversized := ctrl
	oversized.Payload = make([]byte, MaxControlPayload)
	if _, err := oversized.Encode(); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversized encode err = %v", err)
	}
	if _, err := DecodeSessionCtrl(make([]byte, MaxControlPayload+1)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversized decode err = %v", err)
	}
}

func TestNoAliasingOfSessionBuffers(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	s := f.open(SessionClassStream)

	first := s.Attempt().Bytes
	original := append([]byte(nil), first...)
	first[0] ^= 0xFF
	if !bytes.Equal(s.Attempt().Bytes, original) {
		t.Fatal("Attempt().Bytes aliases internal state")
	}
	prologue := s.Prologue()
	originalPrologue := append([]byte(nil), prologue...)
	prologue[0] ^= 0xFF
	if !bytes.Equal(s.Prologue(), originalPrologue) {
		t.Fatal("Prologue() aliases internal state")
	}

	if _, _, err := f.mgr.HandleOpen(context.Background(), f.reply(s.ID(), SessionClassStream, 0, 1, []byte("reply"))); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if err := s.MarkReady(0, 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	root := s.Root()
	originalRoot := append([]byte(nil), root...)
	root[0] ^= 0xFF
	if !bytes.Equal(s.Root(), originalRoot) {
		t.Fatal("Root() aliases internal state")
	}

	responderID := sessionID(0x60)
	responderCtrl := func(payload []byte) SessionCtrl {
		msg := f.ctrl(responderID, SessionClassStream, 0, 1, payload)
		msg.PathID = fxPathID2
		return msg
	}
	payload := []byte("first-message")
	resp, out, err := f.mgr.HandleOpen(context.Background(), responderCtrl(payload))
	if err != nil {
		t.Fatalf("responder HandleOpen: %v", err)
	}
	cached := append([]byte(nil), out...)
	out[0] ^= 0xFF
	if !bytes.Equal(resp.Attempt().Bytes, cached) {
		t.Fatal("HandleOpen reply aliases internal state")
	}
	if bytes.Equal(resp.Attempt().Bytes, out) {
		t.Fatal("mutating the returned reply changed the cached reply")
	}
	if _, again, err := f.mgr.HandleOpen(context.Background(), responderCtrl([]byte("first-message"))); err != nil || !bytes.Equal(again, cached) {
		t.Fatalf("retransmission after caller slice mutation = %x/%v", again, err)
	}
}

func TestResolverAndPeerValidation(t *testing.T) {
	localKey := pattern32(0x01)
	peerKey := pattern32(0x80)
	peerNode := nodeIDFor(peerKey)
	base := Config{ContextID: pattern32(0xA0), PSK: pattern32(0x40), LocalStatic: localKey}

	cases := []struct {
		name     string
		resolver PeerResolver
		want     error
	}{
		{"resolver error", resolverFunc(func(uint64, uint32, SessionClass) (Peer, error) {
			return Peer{}, errors.New("no route")
		}), ErrUnknownPeer},
		{"zero static", resolverFunc(func(uint64, uint32, SessionClass) (Peer, error) {
			return Peer{NodeID: peerNode}, nil
		}), ErrInvalidPeer},
		{"node id mismatch", resolverFunc(func(uint64, uint32, SessionClass) (Peer, error) {
			return Peer{NodeID: sessionID(0xEE), StaticKey: peerKey}, nil
		}), ErrInvalidPeer},
		{"local node", resolverFunc(func(uint64, uint32, SessionClass) (Peer, error) {
			return Peer{NodeID: nodeIDFor(localKey), StaticKey: localKey}, nil
		}), ErrInvalidPeer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.Resolver = tc.resolver
			mgr, err := NewManager(cfg)
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}
			defer func() { _ = mgr.Close() }()
			if _, err := mgr.Open(context.Background(), fxPathID, fxGeneration, SessionClassStream, LaneStream); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v; want %v", err, tc.want)
			}
		})
	}

	// A well-behaved resolver accepts the responder path but rejects a claimed
	// source that is not the resolved peer.
	mgr, err := NewManager(Config{
		ContextID:   base.ContextID,
		PSK:         base.PSK,
		LocalStatic: localKey,
		Resolver: resolverFunc(func(uint64, uint32, SessionClass) (Peer, error) {
			return Peer{NodeID: peerNode, StaticKey: peerKey}, nil
		}),
		Crypto: &fakeCrypto{},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.Close() }()
	f := &fixture{t: t, mgr: mgr, localNode: nodeIDFor(localKey), peerNode: peerNode}
	msg := f.ctrl(sessionID(0x70), SessionClassStream, 0, 1, []byte("first"))
	if _, _, err := mgr.HandleOpen(context.Background(), msg); err != nil {
		t.Fatalf("HandleOpen: %v", err)
	}
	impostor := msg
	impostor.SessionID = sessionID(0x71)
	impostor.PathID = fxPathID2
	impostor.SrcNodeID = sessionID(0x99)
	if _, _, err := mgr.HandleOpen(context.Background(), impostor); !errors.Is(err, ErrInvalidPeer) {
		t.Fatalf("impostor err = %v", err)
	}
	unaddressed := msg
	unaddressed.SessionID = sessionID(0x72)
	unaddressed.PathID = fxPathID2
	unaddressed.DstNodeID = sessionID(0x98)
	if _, _, err := mgr.HandleOpen(context.Background(), unaddressed); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("unaddressed err = %v", err)
	}
	unknownInitiator := msg
	unknownInitiator.SessionID = sessionID(0x73)
	unknownInitiator.PathID = fxPathID2
	unknownInitiator.SrcNodeID, unknownInitiator.DstNodeID = f.localNode, f.peerNode
	if _, _, err := mgr.HandleOpen(context.Background(), unknownInitiator); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown initiator err = %v", err)
	}
}

func TestHandleOpenRejectsMalformedMessages(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	id := sessionID(0x80)
	cases := []struct {
		name string
		msg  SessionCtrl
		want error
	}{
		{"zero session id", func() SessionCtrl {
			m := f.ctrl(id, SessionClassStream, 0, 1, []byte("x"))
			m.SessionID = SessionID{}
			return m
		}(), ErrMalformedMessage},
		{"empty payload", f.ctrl(id, SessionClassStream, 0, 1, nil), ErrMalformedMessage},
		{"bad class", func() SessionCtrl {
			m := f.ctrl(id, SessionClassStream, 0, 1, []byte("x"))
			m.Class = SessionClass(0x05)
			return m
		}(), ErrInvalidClass},
		{"lane mismatch", func() SessionCtrl {
			m := f.ctrl(id, SessionClassStream, 0, 1, []byte("x"))
			m.DataLaneID = LanePacket
			return m
		}(), ErrLaneClassMismatch},
		{"zero path", func() SessionCtrl { m := f.ctrl(id, SessionClassStream, 0, 1, []byte("x")); m.PathID = 0; return m }(), ErrInvalidScope},
		{"same endpoints", func() SessionCtrl {
			m := f.ctrl(id, SessionClassStream, 0, 1, []byte("x"))
			m.SrcNodeID, m.DstNodeID = f.localNode, f.localNode
			return m
		}(), ErrInvalidScope},
		{"oversized payload", f.ctrl(id, SessionClassStream, 0, 1, make([]byte, MaxControlPayload)), ErrPayloadTooLarge},
		{"zero target epoch", f.ctrl(id, SessionClassStream, 0, 0, []byte("x")), ErrStaleEpoch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := f.mgr.HandleOpen(context.Background(), tc.msg); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v; want %v", err, tc.want)
			}
		})
	}
	if f.mgr.Len() != 0 {
		t.Fatalf("rejected messages created %d sessions", f.mgr.Len())
	}
}

func TestPrologueSeparatesAttemptsAndScopes(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	s := f.open(SessionClassStream)
	first := s.Prologue()
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.reply(s.ID(), SessionClassStream, 0, 1, []byte("reply"))); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if err := s.MarkReady(0, 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	if _, err := s.Rekey(context.Background()); err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	second := s.Prologue()
	if bytes.Equal(first, second) {
		t.Fatal("prologue did not change with attempt/target_epoch")
	}
	// Tail layout: attempt:u32be | target_epoch:u32be | PathID:u64be |
	// PathGeneration:u32be. After Rekey the pending attempt is 1 and targets
	// epoch 2, while the committed epoch is still 1.
	if want := uint32(1); binary.BigEndian.Uint32(second[len(second)-20:len(second)-16]) != want {
		t.Fatalf("prologue attempt = %d; want %d", binary.BigEndian.Uint32(second[len(second)-20:len(second)-16]), want)
	}
	if want := uint32(2); binary.BigEndian.Uint32(second[len(second)-16:len(second)-12]) != want {
		t.Fatalf("prologue target epoch = %d; want %d", binary.BigEndian.Uint32(second[len(second)-16:len(second)-12]), want)
	}
	if s.Epoch() != 1 || s.PendingAttempt() != true {
		t.Fatalf("rekey changed the committed epoch: epoch=%d pending=%v", s.Epoch(), s.PendingAttempt())
	}

	other := f.open(SessionClassPacket)
	if bytes.Equal(other.Prologue(), first) {
		t.Fatal("prologue ignores the session class/identity")
	}
	if other.PrologueDigest() == s.PrologueDigest() {
		t.Fatal("PrologueDigest ignores the session identity")
	}
	if other.PrologueDigest() != sha256.Sum256(other.Prologue()) {
		t.Fatal("PrologueDigest is not SHA-256 over Prologue")
	}
}

func TestConcurrentOpenMergesToOneSession(t *testing.T) {
	fake := &fakeCrypto{}
	f := newFixture(t, fake)
	const workers = 8
	sessions := make([]*Session, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			s, err := f.mgr.Open(context.Background(), fxPathID, fxGeneration, SessionClassStream, LaneStream)
			if err != nil {
				t.Errorf("Open: %v", err)
				return
			}
			sessions[i] = s
			for j := 0; j < 32; j++ {
				_ = s.State()
				_ = s.Attempt()
				_ = s.Prologue()
				_ = s.Root()
				if err := s.ReservePending(64); err == nil {
					s.ReleasePending(64)
				}
			}
		}(i)
	}
	close(start)
	wg.Wait()
	for i := 1; i < workers; i++ {
		if sessions[i] != sessions[0] {
			t.Fatalf("worker %d saw a different Session", i)
		}
	}
	if initiate, _, _ := fake.counts(); initiate != 1 {
		t.Fatalf("Initiate calls = %d; want 1", initiate)
	}
	if f.mgr.Len() != 1 {
		t.Fatalf("Len = %d; want 1", f.mgr.Len())
	}
	if got := sessions[0].PendingBytes(); got != 0 {
		t.Fatalf("PendingBytes = %d; want 0", got)
	}
}

func TestConcurrentScopesHandshakeAndReady(t *testing.T) {
	fake := &fakeCrypto{}
	f := newFixture(t, fake)
	const scopes = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < scopes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			pathID := fxPathID + uint64(i) + 1
			class := SessionClassStream
			id := sessionID(byte(0x90 + i))
			s, _, err := f.mgr.HandleOpen(context.Background(), SessionCtrl{
				SessionID:      id,
				Class:          class,
				DataLaneID:     LaneStream,
				Attempt:        0,
				TargetEpoch:    1,
				PathID:         pathID,
				PathGeneration: fxGeneration,
				SrcNodeID:      f.peerNode,
				DstNodeID:      f.localNode,
				Payload:        []byte(fmt.Sprintf("first-%d", i)),
			})
			if err != nil {
				t.Errorf("HandleOpen %d: %v", i, err)
				return
			}
			ready := SessionReady{
				SessionID:      id,
				Class:          class,
				DataLaneID:     LaneStream,
				Attempt:        0,
				TargetEpoch:    1,
				PathID:         pathID,
				PathGeneration: fxGeneration,
				SrcNodeID:      f.peerNode,
				DstNodeID:      f.localNode,
			}
			if err := f.mgr.HandleReady(ready); err != nil {
				t.Errorf("HandleReady %d: %v", i, err)
				return
			}
			if err := f.mgr.HandleReady(ready); err != nil {
				t.Errorf("duplicate HandleReady %d: %v", i, err)
				return
			}
			if s.State() != StateReady || s.Epoch() != 1 {
				t.Errorf("scope %d state/epoch = %s/%d", i, s.State(), s.Epoch())
			}
			if err := s.Close(); err != nil {
				t.Errorf("Close %d: %v", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if f.mgr.Len() != 0 {
		t.Fatalf("Len = %d; want 0", f.mgr.Len())
	}
	if _, respond, _ := fake.counts(); respond != scopes {
		t.Fatalf("Respond calls = %d; want %d", respond, scopes)
	}
}

func TestConcurrentReadyIsIdempotent(t *testing.T) {
	fake := &fakeCrypto{}
	f := newFixture(t, fake)
	id := sessionID(0xA0)
	if _, _, err := f.mgr.HandleOpen(context.Background(), f.ctrl(id, SessionClassStream, 0, 1, []byte("first"))); err != nil {
		t.Fatalf("HandleOpen: %v", err)
	}
	ready := f.readyResponder(id, SessionClassStream, 0, 1)
	const workers = 8
	var wg sync.WaitGroup
	errs := make([]error, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = f.mgr.HandleReady(ready)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("HandleReady %d: %v", i, err)
		}
	}
	s, err := f.mgr.Lookup(fxPathID, fxGeneration, SessionClassStream)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if s.Epoch() != 1 || s.State() != StateReady {
		t.Fatalf("epoch/state = %d/%s", s.Epoch(), s.State())
	}
}

func TestAttemptDigestDistinguishesBytes(t *testing.T) {
	f := newFixture(t, &fakeCrypto{})
	id := sessionID(0xB0)
	msg := f.ctrl(id, SessionClassStream, 0, 1, []byte("first"))
	if _, _, err := f.mgr.HandleOpen(context.Background(), msg); err != nil {
		t.Fatalf("HandleOpen: %v", err)
	}
	same := f.ctrl(id, SessionClassStream, 0, 1, []byte("first"))
	if _, _, err := f.mgr.HandleOpen(context.Background(), same); err != nil {
		t.Fatalf("identical retry: %v", err)
	}
	for _, mutated := range [][]byte{[]byte("firsT"), []byte("first "), []byte("first\x00"), []byte("firs")} {
		if _, _, err := f.mgr.HandleOpen(context.Background(), f.ctrl(id, SessionClassStream, 0, 1, mutated)); !errors.Is(err, ErrAttemptConflict) {
			t.Fatalf("mutated %q err = %v; want ErrAttemptConflict", mutated, err)
		}
	}
	if _, respond, _ := f.fake.counts(); respond != 1 {
		t.Fatalf("Respond calls = %d; want 1", respond)
	}
}

func TestCryptoResultValidation(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name string
		fake *fakeCrypto
	}{
		{"initiate error", &fakeCrypto{initiateErr: boom}},
		{"respond error", &fakeCrypto{respondErr: boom}},
		{"finish error", &fakeCrypto{finishErr: boom}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.fake)
			var err error
			var session *Session
			switch tc.name {
			case "respond error":
				_, _, err = f.mgr.HandleOpen(context.Background(), f.ctrl(sessionID(0xC0), SessionClassStream, 0, 1, []byte("first")))
			case "finish error":
				session = f.open(SessionClassStream)
				_, _, err = f.mgr.HandleOpen(context.Background(), f.reply(session.ID(), SessionClassStream, 0, 1, []byte("reply")))
			default:
				_, err = f.mgr.Open(context.Background(), fxPathID, fxGeneration, SessionClassStream, LaneStream)
			}
			if err == nil || !errors.Is(err, boom) {
				t.Fatalf("err = %v; want %v", err, boom)
			}
			// A provider failure never installs half a session: the responder
			// path registers nothing, and an initiator whose Finish failed stays
			// pending until the caller aborts it or the deadline expires.
			if session == nil {
				if f.mgr.Len() != 0 {
					t.Fatalf("failed handshake left %d sessions", f.mgr.Len())
				}
				return
			}
			if f.mgr.Len() != 1 || session.State() != StatePending {
				t.Fatalf("after Finish failure: len=%d state=%s", f.mgr.Len(), session.State())
			}
			if err := session.Abort(); err != nil {
				t.Fatalf("Abort: %v", err)
			}
			if f.mgr.Len() != 0 {
				t.Fatalf("abort left %d sessions", f.mgr.Len())
			}
		})
	}
}

func TestStateAndRoleStrings(t *testing.T) {
	if got := StatePending.String(); got != "Pending" {
		t.Fatalf("StatePending = %q", got)
	}
	if got := State(0).String(); got != "STATE(0)" {
		t.Fatalf("zero state = %q", got)
	}
	if got := RoleResponder.String(); got != "Responder" {
		t.Fatalf("RoleResponder = %q", got)
	}
	if got := SessionClassPacket.String(); got != "PACKET" {
		t.Fatalf("SessionClassPacket = %q", got)
	}
	if got := LaneStream.String(); got != "STREAM" {
		t.Fatalf("LaneStream = %q", got)
	}
	if got := sessionID(0x01).String(); got != "0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("SessionID = %q", got)
	}
	if got := (scopeKey{pathID: 1, generation: 2, class: SessionClassStream}).String(); got != "path 1/2 STREAM" {
		t.Fatalf("scopeKey = %q", got)
	}
}

func TestKeyIdentityAndScopeOwnership(t *testing.T) {
	if FirstAttempt != 0 || FirstTargetEpoch != 1 {
		t.Fatalf("baseline attempt/epoch = %d/%d; want 0/1", FirstAttempt, FirstTargetEpoch)
	}
	f := newFixture(t, &fakeCrypto{})
	s := f.open(SessionClassStream)
	key := s.Key()
	if key.ContextID != f.contextID || s.ContextID() != f.contextID {
		t.Fatal("session key does not carry the full ContextID")
	}
	if key.SrcNodeID != f.localNode || s.SrcNodeID() != f.localNode {
		t.Fatal("initiator session source is not the local node")
	}
	if key.DstNodeID != f.peerNode || s.DstNodeID() != f.peerNode {
		t.Fatal("initiator session destination is not the resolved peer")
	}
	if key.PathID != fxPathID || key.PathGeneration != fxGeneration || key.Class != SessionClassStream || key.Lane != LaneStream {
		t.Fatalf("session key scope = %+v", key)
	}
	found, err := f.mgr.LookupKey(key)
	if err != nil || found != s {
		t.Fatalf("LookupKey = %v/%v", found, err)
	}
	foreign := key
	foreign.ContextID = pattern32(0xEE)
	if _, err := f.mgr.LookupKey(foreign); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("LookupKey with a foreign ContextID err = %v", err)
	}

	// The Path scope already owns an identity: a peer claiming the same scope
	// with the reversed endpoints must not create a second SessionID.
	reversed := f.ctrl(sessionID(0x66), SessionClassStream, 0, 1, []byte("first"))
	if _, _, err := f.mgr.HandleOpen(context.Background(), reversed); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("scope takeover err = %v; want ErrInvalidScope", err)
	}
	if f.mgr.Len() != 1 {
		t.Fatalf("Len = %d; want 1", f.mgr.Len())
	}

	binding, err := PrologueBinding(key, s.ID(), FirstAttempt, FirstTargetEpoch)
	if err != nil {
		t.Fatalf("PrologueBinding: %v", err)
	}
	if !bytes.Equal(binding, s.Prologue()) {
		t.Fatal("PrologueBinding differs from Session.Prologue")
	}
	if len(binding) != PrologueBindingSize {
		t.Fatalf("binding %d bytes; want %d", len(binding), PrologueBindingSize)
	}
	if _, err := PrologueBinding(key, SessionID{}, 0, 1); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("zero-id binding err = %v", err)
	}
	if _, err := PrologueBinding(key, s.ID(), 0, 0); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("zero-epoch binding err = %v", err)
	}
	badKey := key
	badKey.Lane = LanePacket
	if _, err := PrologueBinding(badKey, s.ID(), 0, 1); !errors.Is(err, ErrLaneClassMismatch) {
		t.Fatalf("bad-key binding err = %v", err)
	}
}

func TestKeyValidateRejections(t *testing.T) {
	valid := Key{
		ContextID:      pattern32(0xA0),
		SrcNodeID:      nodeIDFor(pattern32(0x01)),
		DstNodeID:      nodeIDFor(pattern32(0x80)),
		PathID:         fxPathID,
		PathGeneration: fxGeneration,
		Class:          SessionClassStream,
		Lane:           LaneStream,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	cases := []struct {
		name string
		key  Key
		want error
	}{
		{"zero context", func() Key { k := valid; k.ContextID = [32]byte{}; return k }(), ErrInvalidConfig},
		{"empty src", func() Key { k := valid; k.SrcNodeID = [16]byte{}; return k }(), ErrInvalidScope},
		{"empty dst", func() Key { k := valid; k.DstNodeID = [16]byte{}; return k }(), ErrInvalidScope},
		{"equal endpoints", func() Key { k := valid; k.DstNodeID = k.SrcNodeID; return k }(), ErrInvalidScope},
		{"zero path", func() Key { k := valid; k.PathID = 0; return k }(), ErrInvalidScope},
		{"zero generation", func() Key { k := valid; k.PathGeneration = 0; return k }(), ErrInvalidScope},
		{"bad class", func() Key { k := valid; k.Class = SessionClass(0x07); return k }(), ErrInvalidClass},
		{"bad lane", func() Key { k := valid; k.Lane = Lane(0); return k }(), ErrInvalidLane},
		{"lane mismatch", func() Key { k := valid; k.Lane = LanePacket; return k }(), ErrLaneClassMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.key.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v; want %v", err, tc.want)
			}
		})
	}
}

// byteRange returns start, start+1, ... start+n-1. The fixed-vector tests use
// memorable byte runs so the literal hex below can be checked by hand against
// the documented layouts instead of against the implementation.
func byteRange(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

// fixedVectorKey is ContextID 0x00..0x1f, Src 0x20..0x2f, Dst 0x30..0x3f with a
// fixed Path scope; fixedVectorSessionID is 0x40..0x4f.
func fixedVectorKey() Key {
	key := Key{
		PathID:         0x0102030405060708,
		PathGeneration: 0x0a0b0c0d,
		Class:          SessionClassStream,
		Lane:           LaneStream,
	}
	copy(key.ContextID[:], byteRange(0x00, 32))
	copy(key.SrcNodeID[:], byteRange(0x20, 16))
	copy(key.DstNodeID[:], byteRange(0x30, 16))
	return key
}

func fixedVectorSessionID() SessionID {
	var id SessionID
	copy(id[:], byteRange(0x40, 16))
	return id
}

// Frozen vectors, derived from the documented layouts and not from this
// package: session prologue = ContextID:32B | Src:16B | Dst:16B | SessionID:16B
// | class:u8 | data_lane_id:u8 | attempt:u32be | target_epoch:u32be |
// PathID:u64be | PathGeneration:u32be (security.md C-SEC-003), with the fixed
// key/id above and the frozen first attempt=0/target_epoch=1.
const (
	fixedVectorPrologueHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f" +
		"303132333435363738393a3b3c3d3e3f" +
		"404142434445464748494a4b4c4d4e4f" +
		"0202" + "00000000" + "00000001" + "0102030405060708" + "0a0b0c0d"
	// fixedVectorPrologueDigestHex is SHA-256 over exactly the bytes above.
	fixedVectorPrologueDigestHex = "c5ea8215529d16b48877b9e9ba241a983293ac4a8a9ecbd6889a3569054c7b8c"

	// SESSION_CTRL: SessionID 0011..ff | class PACKET | lane PACKET |
	// attempt 0 | target_epoch 1 | noise_len 12 | "noise-vector".
	fixedVectorCtrlHex = "00112233445566778899aabbccddeeff" + "0101" + "00000000" + "00000001" + "000c" + "6e6f6973652d766563746f72"

	// SESSION_READY: SessionID 0011..ff | class STREAM | lane STREAM |
	// attempt 3 | target_epoch 4 | PathID 0x0102030405060708 | generation 0x0a0b0c0d.
	fixedVectorReadyHex = "00112233445566778899aabbccddeeff" + "0202" + "00000003" + "00000004" + "0102030405060708" + "0a0b0c0d"
)

func TestFixedVectorPrologueBinding(t *testing.T) {
	want, err := hex.DecodeString(fixedVectorPrologueHex)
	if err != nil {
		t.Fatalf("vector: %v", err)
	}
	if len(want) != PrologueBindingSize {
		t.Fatalf("vector is %d bytes; want PrologueBindingSize=%d", len(want), PrologueBindingSize)
	}
	got, err := PrologueBinding(fixedVectorKey(), fixedVectorSessionID(), FirstAttempt, FirstTargetEpoch)
	if err != nil {
		t.Fatalf("PrologueBinding: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("PrologueBinding =\n%x\nwant\n%x", got, want)
	}
	if digest := sha256.Sum256(want); hex.EncodeToString(digest[:]) != fixedVectorPrologueDigestHex {
		t.Fatalf("vector digest = %x; want %s", digest, fixedVectorPrologueDigestHex)
	}
	// The attempt/epoch fields are big-endian at their documented offsets.
	if attempt := binary.BigEndian.Uint32(want[len(want)-20 : len(want)-16]); attempt != FirstAttempt {
		t.Fatalf("vector attempt = %d", attempt)
	}
	if epoch := binary.BigEndian.Uint32(want[len(want)-16 : len(want)-12]); epoch != FirstTargetEpoch {
		t.Fatalf("vector target epoch = %d", epoch)
	}
}

func TestFixedVectorSessionCtrlCodec(t *testing.T) {
	want, err := hex.DecodeString(fixedVectorCtrlHex)
	if err != nil {
		t.Fatalf("vector: %v", err)
	}
	decoded, err := DecodeSessionCtrl(want)
	if err != nil {
		t.Fatalf("DecodeSessionCtrl: %v", err)
	}
	if decoded.SessionID != [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} {
		t.Fatalf("SessionID = %s", decoded.SessionID)
	}
	if decoded.Class != SessionClassPacket || decoded.DataLaneID != LanePacket {
		t.Fatalf("class/lane = %s/%s", decoded.Class, decoded.DataLaneID)
	}
	if decoded.Attempt != FirstAttempt || decoded.TargetEpoch != FirstTargetEpoch {
		t.Fatalf("attempt/epoch = %d/%d", decoded.Attempt, decoded.TargetEpoch)
	}
	if !bytes.Equal(decoded.Payload, []byte("noise-vector")) {
		t.Fatalf("payload = %q", decoded.Payload)
	}
	reencoded, err := decoded.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(reencoded, want) {
		t.Fatalf("re-encoded = %x; want %x", reencoded, want)
	}

	// Boundary: the largest legal payload fits in MaxControlPayload, one byte
	// more does not, and decode never allocates past the bound.
	maxPayload := MaxControlPayload - sessionCtrlHeaderSize - sessionCtrlLengthSize
	fit := decoded
	fit.Payload = make([]byte, maxPayload)
	encoded, err := fit.Encode()
	if err != nil || len(encoded) != MaxControlPayload {
		t.Fatalf("max payload encode = %d bytes/%v; want %d/nil", len(encoded), err, MaxControlPayload)
	}
	if _, err := fit.Encode(); err != nil {
		t.Fatalf("max payload re-encode: %v", err)
	}
	over := fit
	over.Payload = make([]byte, maxPayload+1)
	if _, err := over.Encode(); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("over-max encode err = %v; want ErrPayloadTooLarge", err)
	}
	if _, err := DecodeSessionCtrl(make([]byte, MaxControlPayload+1)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("over-max decode err = %v; want ErrPayloadTooLarge", err)
	}
}

func TestFixedVectorSessionReadyCodec(t *testing.T) {
	want, err := hex.DecodeString(fixedVectorReadyHex)
	if err != nil {
		t.Fatalf("vector: %v", err)
	}
	if len(want) != sessionReadySize {
		t.Fatalf("vector is %d bytes; want %d", len(want), sessionReadySize)
	}
	decoded, err := DecodeSessionReady(want)
	if err != nil {
		t.Fatalf("DecodeSessionReady: %v", err)
	}
	if decoded.SessionID.String() != "00112233445566778899aabbccddeeff" {
		t.Fatalf("SessionID = %s", decoded.SessionID)
	}
	if decoded.Class != SessionClassStream || decoded.DataLaneID != LaneStream {
		t.Fatalf("class/lane = %s/%s", decoded.Class, decoded.DataLaneID)
	}
	if decoded.Attempt != 3 || decoded.TargetEpoch != 4 {
		t.Fatalf("attempt/epoch = %d/%d", decoded.Attempt, decoded.TargetEpoch)
	}
	if decoded.PathID != 0x0102030405060708 || decoded.PathGeneration != 0x0a0b0c0d {
		t.Fatalf("path = %d/%d", decoded.PathID, decoded.PathGeneration)
	}
	reencoded, err := decoded.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(reencoded, want) {
		t.Fatalf("re-encoded = %x; want %x", reencoded, want)
	}
}

func TestFrozenResourceLimits(t *testing.T) {
	if MaxSessions != 1024 {
		t.Fatalf("MaxSessions = %d; want 1024", MaxSessions)
	}
	if MaxPendingBytes != 65897 {
		t.Fatalf("MaxPendingBytes = %d; want 65897", MaxPendingBytes)
	}
	if MaxControlPayload != 8192 {
		t.Fatalf("MaxControlPayload = %d; want 8192", MaxControlPayload)
	}
	if PrologueBindingSize != 102 {
		t.Fatalf("PrologueBindingSize = %d; want 102", PrologueBindingSize)
	}
	if DefaultPendingTTL != 30*time.Second {
		t.Fatalf("DefaultPendingTTL = %s; want 30s", DefaultPendingTTL)
	}
	if FirstAttempt != 0 || FirstTargetEpoch != 1 {
		t.Fatalf("first attempt/epoch = %d/%d; want 0/1", FirstAttempt, FirstTargetEpoch)
	}

	f := newFixture(t, &fakeCrypto{})
	s := f.open(SessionClassStream)
	if err := s.ReservePending(MaxPendingBytes); err != nil {
		t.Fatalf("reserve exactly the limit: %v", err)
	}
	if err := s.ReservePending(1); !errors.Is(err, ErrPendingLimit) {
		t.Fatalf("reserve past the limit err = %v; want ErrPendingLimit", err)
	}
	s.ReleasePending(MaxPendingBytes)
	if err := s.ReservePending(MaxPendingBytes + 1); !errors.Is(err, ErrPendingLimit) {
		t.Fatalf("oversized single reserve err = %v; want ErrPendingLimit", err)
	}
	if got := s.PendingBytes(); got != 0 {
		t.Fatalf("rejected reserve changed accounting: %d", got)
	}
}
