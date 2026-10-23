package circuit

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// test harness
// ---------------------------------------------------------------------------

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// submission is one recorded Egress call.
type submission struct {
	sub      Submission
	admitted bool
}

type fakeEgress struct {
	mu        sync.Mutex
	frames    []submission
	admission Admission
	admitErr  error
	sendErr   error
	admitHook func(Submission)
	sendHook  func(Submission)
}

func (e *fakeEgress) AdmitOpen(ctx context.Context, sub Submission) (Admission, error) {
	if e.admitHook != nil {
		e.admitHook(sub)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.frames = append(e.frames, submission{sub: copySubmission(sub), admitted: true})
	if e.admitErr != nil {
		return 0, e.admitErr
	}
	return e.admission, nil
}

func (e *fakeEgress) Send(ctx context.Context, sub Submission) error {
	if e.sendHook != nil {
		e.sendHook(sub)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.frames = append(e.frames, submission{sub: copySubmission(sub)})
	return e.sendErr
}

func copySubmission(sub Submission) Submission {
	sub.Body = append([]byte(nil), sub.Body...)
	return sub
}

func (e *fakeEgress) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.frames)
}

func (e *fakeEgress) at(i int) submission {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.frames[i]
}

func (e *fakeEgress) reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.frames = nil
}

func (e *fakeEgress) setAdmission(a Admission) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.admission = a
}

func (e *fakeEgress) setSendErr(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sendErr = err
}

func (e *fakeEgress) setAdmitErr(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.admitErr = err
}

func (e *fakeEgress) snapshotFrames() []submission {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]submission(nil), e.frames...)
}

// fakeCrypto prefixes the direction byte so tests can both prove the provider
// was used and recover the exact plaintext payload.
type fakeCrypto struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (c *fakeCrypto) ProtectPayload(ref SessionRef, dir Direction, plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	c.calls++
	err := c.err
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(plaintext)+1)
	out = append(out, byte(dir))
	return append(out, plaintext...), nil
}

func (c *fakeCrypto) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func plain(body []byte) []byte { return body[1:] }

type harness struct {
	mgr    *Manager
	egress *fakeEgress
	crypto *fakeCrypto
	clock  *fakeClock

	ctx      ContextID
	local    NodeID
	peer     NodeID
	session  SessionRef
	circuit  CircuitID
	openReq  OpenRequest
	testPeer NodeID
}

func testContextID() ContextID {
	var id ContextID
	for i := range id {
		id[i] = byte(0xA0 + i)
	}
	return id
}

func testNodeID(b byte) NodeID {
	var id NodeID
	for i := range id {
		id[i] = b
	}
	id[15] = b ^ 0x5A
	return id
}

func testSessionID(b byte) SessionID {
	var id SessionID
	for i := range id {
		id[i] = b
	}
	id[15] = b ^ 0x3C
	return id
}

func testCircuitID(b byte) CircuitID {
	var id CircuitID
	for i := range id {
		id[i] = b
	}
	id[15] = b ^ 0x77
	return id
}

func newHarness(t *testing.T, mutate func(cfg *Config)) *harness {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	egress := &fakeEgress{admission: AdmissionCommitted}
	crypto := &fakeCrypto{}
	cfg := Config{
		ContextID:   testContextID(),
		LocalNodeID: testNodeID(0x11),
		Crypto:      crypto,
		Egress:      egress,
		Now:         clock.Now,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	h := &harness{
		mgr:     mgr,
		egress:  egress,
		crypto:  crypto,
		clock:   clock,
		ctx:     cfg.ContextID,
		local:   cfg.LocalNodeID,
		peer:    testNodeID(0x22),
		session: SessionRef{ID: testSessionID(0x31), PathID: 7, PathGeneration: 3},
		circuit: testCircuitID(0x41),
	}
	h.openReq = OpenRequest{
		CircuitID:    h.circuit,
		TargetNodeID: h.peer,
		TargetPort:   8080,
		Candidates: []Candidate{{
			PathID:           7,
			PathGeneration:   3,
			RouteViewVersion: 11,
			PathDigest:       [32]byte{0x01, 0x02},
			Session:          h.session,
		}},
	}
	return h
}

func (h *harness) key() Key { return h.mgr.LocalKey(h.circuit) }

func (h *harness) peerKeyOf() Key {
	return Key{ContextID: h.ctx, SrcNodeID: h.peer, CircuitID: h.circuit}
}

type openResult struct {
	c   *Circuit
	err error
}

func (h *harness) openAsync(ctx context.Context, req OpenRequest) <-chan openResult {
	ch := make(chan openResult, 1)
	go func() {
		c, err := h.mgr.Open(ctx, req)
		ch <- openResult{c: c, err: err}
	}()
	return ch
}

func waitState(t *testing.T, m *Manager, key Key, want State) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last State
	found := false
	for time.Now().Before(deadline) {
		for _, cs := range m.Snapshot().Circuits {
			if cs.Key != key {
				continue
			}
			found = true
			last = cs.State
			if cs.State == want {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("circuit %s never reached %s (last %v, found=%v)", key, want, last, found)
}

func mustRecv(t *testing.T, ch <-chan openResult) openResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("Open did not return in time")
		return openResult{}
	}
}

func (h *harness) readyMessage() ReadyMessage {
	return ReadyMessage{
		FromNodeID:    h.peer,
		CircuitID:     h.circuit,
		Attempt:       0,
		RequestID:     1,
		Status:        StatusReady,
		InitialWindow: InitialWindow,
	}
}

func (h *harness) openMessage(attempt uint32, requestID uint64) OpenMessage {
	return OpenMessage{
		FromNodeID:          h.peer,
		CircuitID:           h.circuit,
		Attempt:             attempt,
		TargetPort:          8080,
		PathID:              7,
		PathGeneration:      3,
		RouteViewVersion:    11,
		PathDigest:          [32]byte{0x01, 0x02},
		SourceInitialWindow: InitialWindow,
		RequestID:           requestID,
		Session:             h.session,
	}
}

// decodeFrame decodes one recorded submission into its plaintext payload.
func decodeFrame(t *testing.T, sub submission) []byte {
	t.Helper()
	if len(sub.sub.Body) == 0 {
		t.Fatal("submission without body")
	}
	if sub.sub.Body[0] != byte(sub.sub.Direction) {
		t.Fatalf("protected body direction byte %d, want %d", sub.sub.Body[0], sub.sub.Direction)
	}
	return plain(sub.sub.Body)
}

// ---------------------------------------------------------------------------
// identifiers and codec
// ---------------------------------------------------------------------------

func TestNewCircuitIDIsNonZeroCSPRNG(t *testing.T) {
	seen := make(map[CircuitID]struct{}, 4096)
	for i := 0; i < 4096; i++ {
		id, err := NewCircuitID()
		if err != nil {
			t.Fatalf("NewCircuitID: %v", err)
		}
		if id.IsZero() {
			t.Fatal("NewCircuitID returned the zero id")
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate circuit id %s", id)
		}
		seen[id] = struct{}{}
		if len(id.String()) != 32 {
			t.Fatalf("String() = %q", id.String())
		}
	}
}

func TestNewCircuitIDRedrawsZero(t *testing.T) {
	h := newHarness(t, nil)
	draws := 0
	h.mgr.rand = func(b []byte) error {
		draws++
		if draws == 1 {
			for i := range b {
				b[i] = 0
			}
			return nil
		}
		for i := range b {
			b[i] = byte(draws)
		}
		return nil
	}
	id, err := h.mgr.newKeyLocked(CircuitID{})
	if err != nil {
		t.Fatalf("newKeyLocked: %v", err)
	}
	if draws != 2 {
		t.Fatalf("draws = %d, want 2 (zero id must be redrawn)", draws)
	}
	if id.CircuitID.IsZero() {
		t.Fatal("reserved the zero id")
	}
}

func TestNewCircuitIDConflictRedrawAndResource(t *testing.T) {
	h := newHarness(t, nil)
	existing := testCircuitID(0x41)
	h.mgr.mu.Lock()
	h.mgr.circuits[Key{ContextID: h.ctx, SrcNodeID: h.local, CircuitID: existing}] = &Circuit{
		mgr: h.mgr, key: h.mgr.LocalKey(existing), role: RoleSource, state: StateRequested,
		woke: make(chan struct{}),
	}
	h.mgr.mu.Unlock()

	draws := 0
	h.mgr.rand = func(b []byte) error {
		draws++
		if draws == 1 {
			copy(b, existing[:])
			return nil
		}
		for i := range b {
			b[i] = 0x7E
		}
		return nil
	}
	key, err := h.mgr.newKeyLocked(CircuitID{})
	if err != nil {
		t.Fatalf("newKeyLocked: %v", err)
	}
	if draws != 2 {
		t.Fatalf("draws = %d, want 2", draws)
	}
	if key.CircuitID == existing {
		t.Fatal("collision was not redrawn")
	}

	h.mgr.rand = func(b []byte) error {
		copy(b, existing[:])
		return nil
	}
	if _, err := h.mgr.newKeyLocked(CircuitID{}); !errors.Is(err, ErrResource) {
		t.Fatalf("always-colliding draw err = %v, want ErrResource", err)
	}

	if _, err := h.mgr.newKeyLocked(existing); !errors.Is(err, ErrResource) {
		t.Fatalf("pinned colliding id err = %v, want ErrResource", err)
	}
}

func TestOpenMessageCodec(t *testing.T) {
	h := newHarness(t, nil)
	msg := h.openMessage(0, 42)
	payload, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(payload) != controlRPCHeaderSize+openPayloadSize {
		t.Fatalf("len = %d, want %d", len(payload), controlRPCHeaderSize+openPayloadSize)
	}
	if got := binary.BigEndian.Uint16(payload[0:2]); RPCCode(got) != RPCOpen {
		t.Fatalf("rpc code = 0x%04x", got)
	}
	if got := binary.BigEndian.Uint64(payload[2:10]); got != 42 {
		t.Fatalf("request id = %d", got)
	}
	body := payload[10:]
	if !bytes.Equal(body[:16], h.circuit[:]) {
		t.Fatal("circuit id offset wrong")
	}
	if got := binary.BigEndian.Uint32(body[16:20]); got != 0 {
		t.Fatalf("attempt = %d", got)
	}
	if got := binary.BigEndian.Uint16(body[20:22]); got != 8080 {
		t.Fatalf("port = %d", got)
	}
	if got := binary.BigEndian.Uint64(body[22:30]); got != 7 {
		t.Fatalf("path id = %d", got)
	}
	if got := binary.BigEndian.Uint32(body[30:34]); got != 3 {
		t.Fatalf("path gen = %d", got)
	}
	if got := binary.BigEndian.Uint64(body[34:42]); got != 11 {
		t.Fatalf("view version = %d", got)
	}
	if !bytes.Equal(body[42:74], []byte{0x01, 0x02}) && !bytes.Equal(body[42:74], append([]byte{0x01, 0x02}, make([]byte, 30)...)) {
		t.Fatal("path digest offset wrong")
	}
	if got := binary.BigEndian.Uint64(body[74:82]); got != InitialWindow {
		t.Fatalf("initial window = %d", got)
	}

	decoded, err := DecodeOpenMessage(payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.CircuitID != msg.CircuitID || decoded.Attempt != msg.Attempt || decoded.TargetPort != msg.TargetPort ||
		decoded.PathID != msg.PathID || decoded.PathGeneration != msg.PathGeneration ||
		decoded.RouteViewVersion != msg.RouteViewVersion || decoded.PathDigest != msg.PathDigest ||
		decoded.SourceInitialWindow != msg.SourceInitialWindow || decoded.RequestID != msg.RequestID {
		t.Fatalf("round trip mismatch: %+v vs %+v", decoded, msg)
	}

	// strict length and opcode
	if _, err := DecodeOpenMessage(append(payload, 0)); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("trailing byte err = %v", err)
	}
	short := append([]byte(nil), payload...)
	short[0] = 0x09
	if _, err := DecodeOpenMessage(short); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("wrong opcode err = %v", err)
	}
	zeroID := msg
	zeroID.CircuitID = CircuitID{}
	if _, err := zeroID.Encode(); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("zero circuit id err = %v", err)
	}
	badWindow := msg
	badWindow.SourceInitialWindow = 0
	if _, err := badWindow.Encode(); !errors.Is(err, ErrInvalidWindow) {
		t.Fatalf("zero window err = %v", err)
	}
	badPort := msg
	badPort.TargetPort = 0
	if _, err := badPort.Encode(); !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("zero port err = %v", err)
	}
}

func TestReadyMessageCodecAndValidation(t *testing.T) {
	msg := ReadyMessage{
		FromNodeID:    testNodeID(0x22),
		CircuitID:     testCircuitID(0x41),
		Attempt:       2,
		RequestID:     9,
		Status:        StatusReady,
		ErrorCode:     ReadyErrorNone,
		InitialWindow: InitialWindow,
	}
	payload, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(payload) != controlRPCHeaderSize+readyPayloadSize {
		t.Fatalf("len = %d", len(payload))
	}
	if got := RPCCode(binary.BigEndian.Uint16(payload[0:2])); got != RPCReady {
		t.Fatalf("rpc code = %s", got)
	}
	body := payload[10:]
	if got := binary.BigEndian.Uint32(body[16:20]); got != 2 {
		t.Fatalf("attempt = %d", got)
	}
	if ReadyStatus(body[20]) != StatusReady {
		t.Fatalf("status = %d", body[20])
	}
	if got := binary.BigEndian.Uint16(body[21:23]); got != 0 {
		t.Fatalf("error code = %d", got)
	}
	if got := binary.BigEndian.Uint64(body[23:31]); got != InitialWindow {
		t.Fatalf("window = %d", got)
	}
	decoded, err := DecodeReadyMessage(payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Attempt != 2 || decoded.RequestID != 9 || decoded.Status != StatusReady ||
		decoded.InitialWindow != InitialWindow || decoded.CircuitID != msg.CircuitID {
		t.Fatalf("round trip mismatch: %+v", decoded)
	}

	cases := []struct {
		name string
		msg  ReadyMessage
		want error
	}{
		{"ready with error", ReadyMessage{CircuitID: msg.CircuitID, Status: StatusReady, ErrorCode: ReadyErrorNoRoute, InitialWindow: InitialWindow}, ErrMalformedMessage},
		{"ready zero window", ReadyMessage{CircuitID: msg.CircuitID, Status: StatusReady, InitialWindow: 0}, ErrInvalidWindow},
		{"ready over cap", ReadyMessage{CircuitID: msg.CircuitID, Status: StatusReady, InitialWindow: InitialWindow + 1}, ErrInvalidWindow},
		{"refused no code", ReadyMessage{CircuitID: msg.CircuitID, Status: StatusRefused}, ErrMalformedMessage},
		{"refused unknown code", ReadyMessage{CircuitID: msg.CircuitID, Status: StatusRefused, ErrorCode: ReadyErrorOutcomeUnknown}, ErrMalformedMessage},
		{"expired wrong code", ReadyMessage{CircuitID: msg.CircuitID, Status: StatusExpired, ErrorCode: ReadyErrorNoRoute}, ErrMalformedMessage},
		{"expired ok", ReadyMessage{CircuitID: msg.CircuitID, Status: StatusExpired, ErrorCode: ReadyErrorOutcomeUnknown}, nil},
		{"refused ok", ReadyMessage{CircuitID: msg.CircuitID, Status: StatusRefused, ErrorCode: ReadyErrorTargetRefused}, nil},
		{"unknown status", ReadyMessage{CircuitID: msg.CircuitID, Status: 0x09}, ErrMalformedMessage},
		{"unknown error code", ReadyMessage{CircuitID: msg.CircuitID, Status: StatusRefused, ErrorCode: 0x00FF}, ErrMalformedMessage},
		{"zero circuit", ReadyMessage{Status: StatusReady, InitialWindow: InitialWindow}, ErrMalformedMessage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.msg.Encode()
			if tc.want == nil {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestResetAndWindowUpdateCodec(t *testing.T) {
	reset := ResetMessage{CircuitID: testCircuitID(0x41), Attempt: 1, Reason: ResetReasonCanceled}
	payload, err := reset.Encode()
	if err != nil {
		t.Fatalf("Encode reset: %v", err)
	}
	if len(payload) != controlRPCHeaderSize+resetPayloadSize {
		t.Fatalf("reset len = %d", len(payload))
	}
	body := payload[10:]
	if got := binary.BigEndian.Uint32(body[16:20]); got != 1 {
		t.Fatalf("attempt = %d", got)
	}
	if got := ResetReason(binary.BigEndian.Uint32(body[20:24])); got != ResetReasonCanceled {
		t.Fatalf("reason = %s", got)
	}
	decoded, err := DecodeResetMessage(payload)
	if err != nil {
		t.Fatalf("Decode reset: %v", err)
	}
	if decoded.Reason != ResetReasonCanceled || decoded.Attempt != 1 || decoded.CircuitID != reset.CircuitID {
		t.Fatalf("reset round trip: %+v", decoded)
	}
	if _, err := (ResetMessage{CircuitID: reset.CircuitID, Reason: 0x99}).Encode(); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("unknown reason encode err = %v", err)
	}
	// An unknown reason must stay decodable so HandleReset can terminate the
	// stream and report ErrProtocol instead of the message being unparseable.
	unknown := append([]byte(nil), payload...)
	binary.BigEndian.PutUint32(unknown[30:34], 0x99)
	decodedUnknown, err := DecodeResetMessage(unknown)
	if err != nil {
		t.Fatalf("unknown reason must decode: %v", err)
	}
	if decodedUnknown.Reason.Valid() {
		t.Fatal("unknown reason reported as valid")
	}

	window := WindowUpdateMessage{CircuitID: testCircuitID(0x41), Window: 1 << 20}
	wpayload, err := window.Encode()
	if err != nil {
		t.Fatalf("Encode window: %v", err)
	}
	if len(wpayload) != controlRPCHeaderSize+windowPayloadSize {
		t.Fatalf("window len = %d", len(wpayload))
	}
	if got := binary.BigEndian.Uint64(wpayload[10+16 : 10+24]); got != 1<<20 {
		t.Fatalf("window = %d", got)
	}
	wdecoded, err := DecodeWindowUpdate(wpayload)
	if err != nil {
		t.Fatalf("Decode window: %v", err)
	}
	if wdecoded.Window != 1<<20 {
		t.Fatalf("window round trip = %d", wdecoded.Window)
	}
	if _, err := (WindowUpdateMessage{}).Encode(); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("zero circuit window err = %v", err)
	}
}

func TestStreamDataCodec(t *testing.T) {
	msg := StreamDataMessage{CircuitID: testCircuitID(0x41), Flags: FlagData, StreamSeq: 17, Payload: []byte("hello")}
	payload, err := msg.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(payload) != streamDataHeaderSize+5 {
		t.Fatalf("len = %d", len(payload))
	}
	if payload[16] != byte(FlagData) {
		t.Fatalf("flags = %d", payload[16])
	}
	if got := binary.BigEndian.Uint64(payload[17:25]); got != 17 {
		t.Fatalf("stream seq = %d", got)
	}
	if string(payload[25:]) != "hello" {
		t.Fatalf("payload = %q", payload[25:])
	}
	decoded, err := DecodeStreamData(payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Flags != FlagData || decoded.StreamSeq != 17 || string(decoded.Payload) != "hello" {
		t.Fatalf("round trip: %+v", decoded)
	}

	fin, err := StreamDataMessage{CircuitID: msg.CircuitID, Flags: FlagFin, StreamSeq: 5}.Encode()
	if err != nil {
		t.Fatalf("Encode FIN: %v", err)
	}
	if len(fin) != streamDataHeaderSize {
		t.Fatalf("FIN len = %d", len(fin))
	}

	bad := []struct {
		name string
		msg  StreamDataMessage
		want error
	}{
		{"data empty", StreamDataMessage{CircuitID: msg.CircuitID, Flags: FlagData}, ErrMalformedMessage},
		{"fin with payload", StreamDataMessage{CircuitID: msg.CircuitID, Flags: FlagFin, Payload: []byte{1}}, ErrMalformedMessage},
		{"flags zero", StreamDataMessage{CircuitID: msg.CircuitID}, ErrMalformedMessage},
		{"flags data|fin", StreamDataMessage{CircuitID: msg.CircuitID, Flags: FlagData | FlagFin, Payload: []byte{1}}, ErrMalformedMessage},
		{"zero circuit", StreamDataMessage{Flags: FlagFin}, ErrMalformedMessage},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.msg.Encode(); !errors.Is(err, tc.want) {
				t.Fatalf("Encode err = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := DecodeStreamData(payload[:24]); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("truncated decode err = %v", err)
	}
	oversized := append([]byte(nil), make([]byte, streamDataHeaderSize)...)
	if _, err := DecodeStreamData(append(oversized, make([]byte, MaxStreamDataPayload+1)...)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversized decode err = %v", err)
	}
}

func TestResourceErrorIsUnsupported(t *testing.T) {
	h := newHarness(t, nil)
	payload := make([]byte, controlRPCHeaderSize+resourceErrorPayloadSize)
	binary.BigEndian.PutUint16(payload[0:2], uint16(RPCResourceError))
	copy(payload[controlRPCHeaderSize:], h.circuit[:])
	payload[controlRPCHeaderSize+16] = 0x01
	if _, err := DecodeResourceError(payload); !errors.Is(err, ErrUnsupportedControl) {
		t.Fatalf("DecodeResourceError err = %v, want ErrUnsupportedControl", err)
	}
	if _, err := (ResourceErrorMessage{}).Encode(); !errors.Is(err, ErrUnsupportedControl) {
		t.Fatalf("Encode err = %v, want ErrUnsupportedControl", err)
	}
	code, err := DecodeControlRPCCode(payload)
	if !errors.Is(err, ErrUnsupportedControl) || code != RPCResourceError {
		t.Fatalf("DecodeControlRPCCode = %s, %v", code, err)
	}
	if _, err := DecodeControlRPCCode([]byte{0x01}); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("short code err = %v", err)
	}
	if _, err := DecodeControlRPCCode([]byte{0x09, 0x00}); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("unknown code err = %v", err)
	}
	if code, err := DecodeControlRPCCode([]byte{0x00, 0x01}); err != nil || code != RPCOpen {
		t.Fatalf("open code = %s, %v", code, err)
	}
}

func TestTruncatedResourceError(t *testing.T) {
	if _, err := DecodeResourceError([]byte{0x00, 0x04}); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("err = %v, want ErrMalformedMessage", err)
	}
}

// ---------------------------------------------------------------------------
// manager configuration and Open validation
// ---------------------------------------------------------------------------

func TestNewManagerValidation(t *testing.T) {
	if _, err := NewManager(Config{LocalNodeID: testNodeID(1)}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("zero context err = %v", err)
	}
	if _, err := NewManager(Config{ContextID: testContextID()}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("zero node err = %v", err)
	}
	over := []Limits{
		{MaxActive: MaxActive + 1},
		{MaxPreReadyPerPeer: MaxPreReadyPerPeer + 1},
		{MaxTombstones: MaxTombstones + 1},
		{TombstoneTTL: DefaultTombstoneTTL + time.Second},
		{MaxOpenBudget: MaxOpenBudget + time.Second},
	}
	for i, limits := range over {
		if _, err := NewManager(Config{ContextID: testContextID(), LocalNodeID: testNodeID(1), Limits: limits}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("limits %d err = %v, want ErrInvalidConfig", i, err)
		}
	}
	m, err := NewManager(Config{ContextID: testContextID(), LocalNodeID: testNodeID(1)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Close()
	if m.limits.MaxActive != MaxActive || m.limits.MaxPreReadyPerPeer != MaxPreReadyPerPeer ||
		m.limits.MaxTombstones != MaxTombstones || m.limits.TombstoneTTL != DefaultTombstoneTTL ||
		m.limits.MaxOpenBudget != MaxOpenBudget {
		t.Fatalf("default limits = %+v", m.limits)
	}
	ctx := context.Background()
	req := OpenRequest{TargetNodeID: testNodeID(2), TargetPort: 1, Candidates: []Candidate{{
		PathID: 1, PathGeneration: 1, Session: SessionRef{ID: testSessionID(1), PathID: 1, PathGeneration: 1}}}}
	// A failed Open returns a nil handle plus the error; it never hands out a
	// half-built Circuit.
	if c, err := m.Open(ctx, req); c != nil || !errors.Is(err, ErrCryptoUnavailable) {
		t.Fatalf("default crypto Open = %v, %v; want a nil handle and ErrCryptoUnavailable", c, err)
	}
	if _, err := m.HandleOpen(OpenMessage{FromNodeID: testNodeID(3), CircuitID: testCircuitID(1), TargetPort: 1,
		PathID: 1, PathGeneration: 1, SourceInitialWindow: InitialWindow, Session: h1Session()}); !errors.Is(err, ErrCryptoUnavailable) {
		t.Fatalf("default crypto HandleOpen err = %v, want ErrCryptoUnavailable", err)
	}

	// A usable CryptoProvider with the default Egress must fail closed with
	// ErrEgressUnavailable and never claim an outcome.
	m2, err := NewManager(Config{ContextID: testContextID(), LocalNodeID: testNodeID(1), Crypto: &fakeCrypto{}})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m2.Close()
	if c, err := m2.Open(ctx, req); c != nil || !errors.Is(err, ErrEgressUnavailable) {
		t.Fatalf("default egress Open = %v, %v; want a nil handle and ErrEgressUnavailable", c, err)
	}
	if _, err := m2.HandleOpen(OpenMessage{FromNodeID: testNodeID(3), CircuitID: testCircuitID(1), TargetPort: 1,
		PathID: 1, PathGeneration: 1, SourceInitialWindow: InitialWindow, Session: h1Session()}); !errors.Is(err, ErrEgressUnavailable) {
		t.Fatalf("default egress HandleOpen err = %v, want ErrEgressUnavailable", err)
	}
}

func h1Session() SessionRef {
	return SessionRef{ID: testSessionID(0x31), PathID: 7, PathGeneration: 3}
}

func TestOpenRequestValidation(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	valid := h.openReq

	cases := []struct {
		name string
		req  OpenRequest
		want error
	}{
		{"no target node", func() OpenRequest { r := valid; r.TargetNodeID = NodeID{}; return r }(), ErrInvalidKey},
		{"zero port", func() OpenRequest { r := valid; r.TargetPort = 0; return r }(), ErrInvalidPort},
		{"no candidates", func() OpenRequest { r := valid; r.Candidates = nil; return r }(), ErrNoCandidates},
		{"too many candidates", func() OpenRequest {
			r := valid
			r.Candidates = append(r.Candidates, valid.Candidates[0], valid.Candidates[0], valid.Candidates[0])
			return r
		}(), ErrInvalidCandidate},
		{"candidate session mismatch", func() OpenRequest {
			r := valid
			c := valid.Candidates[0]
			c.Session.PathID = 99
			r.Candidates = []Candidate{c}
			return r
		}(), ErrInvalidCandidate},
		{"candidate zero path", func() OpenRequest {
			r := valid
			c := valid.Candidates[0]
			c.PathID = 0
			r.Candidates = []Candidate{c}
			return r
		}(), ErrInvalidCandidate},
		{"zero session", func() OpenRequest {
			r := valid
			c := valid.Candidates[0]
			c.Session = SessionRef{PathID: 7, PathGeneration: 3}
			r.Candidates = []Candidate{c}
			return r
		}(), ErrInvalidSession},
		{"window not frozen", func() OpenRequest { r := valid; r.InitialWindow = 4096; return r }(), ErrInvalidWindow},
		{"budget too large", func() OpenRequest { r := valid; r.Budget = MaxOpenBudget + time.Second; return r }(), ErrInvalidBudget},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.mgr.Open(ctx, tc.req); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := h.mgr.Open(nil, valid); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil ctx err = %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.mgr.Open(cancelled, valid); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx err = %v", err)
	}
	if _, err := h.mgr.Open(nil, valid); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil ctx err = %v", err)
	}
}

func TestOpenCandidatesAreCopied(t *testing.T) {
	h := newHarness(t, nil)
	req := h.openReq
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.openAsync(ctx, req)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)
	req.Candidates[0].PathID = 999
	req.Candidates[0].Session.ID = testSessionID(0xEE)
	snap := h.mgr.Snapshot()
	if snap.Circuits[0].Candidate.PathID != 7 || snap.Circuits[0].Session.ID != h.session.ID {
		t.Fatalf("record aliased the caller slice: %+v", snap.Circuits[0])
	}
	cancel()
	if res := mustRecv(t, ch); res.err == nil {
		t.Fatal("expected the canceled Dial to fail")
	}
}

func TestOpenReadyHappyPath(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)

	if got := h.egress.count(); got != 1 {
		t.Fatalf("egress calls = %d, want 1", got)
	}
	sub := h.egress.at(0)
	if !sub.admitted {
		t.Fatal("CIRCUIT_OPEN must use AdmitOpen")
	}
	if sub.sub.Kind != KindControlRPC || sub.sub.Direction != DirectionSourceToTarget || sub.sub.Dest != h.peer {
		t.Fatalf("submission = %+v", sub.sub)
	}
	env, err := DecodeOpenMessage(decodeFrame(t, sub))
	if err != nil {
		t.Fatalf("decode open: %v", err)
	}
	if env.CircuitID != h.circuit || env.Attempt != FirstAttempt || env.RequestID != 1 ||
		env.SourceInitialWindow != InitialWindow || env.TargetPort != 8080 {
		t.Fatalf("open payload = %+v", env)
	}

	if err := h.mgr.HandleReady(h.readyMessage()); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	res := mustRecv(t, ch)
	if res.err != nil {
		t.Fatalf("Open err = %v", res.err)
	}
	if res.c.State() != StateReady {
		t.Fatalf("state = %s", res.c.State())
	}
	if res.c.Attempt() != FirstAttempt || res.c.RequestID() != 1 {
		t.Fatalf("attempt/request = %d/%d", res.c.Attempt(), res.c.RequestID())
	}
	if got := res.c.SendWindow(); got != InitialWindow {
		t.Fatalf("send window = %d", got)
	}
	if res.c.Buffered() != 0 || res.c.RecvWindow() != InitialWindow {
		t.Fatalf("receive state buffered=%d window=%d", res.c.Buffered(), res.c.RecvWindow())
	}
	if h.crypto.callCount() == 0 {
		t.Fatal("CryptoProvider was never asked to protect the Open")
	}
}

func TestHandleReadyRefusalMapping(t *testing.T) {
	cases := []struct {
		status ReadyStatus
		code   ReadyError
		want   error
	}{
		{StatusRefused, ReadyErrorNoRoute, ErrNoRoute},
		{StatusRefused, ReadyErrorLinkDown, ErrLinkDown},
		{StatusRefused, ReadyErrorPermission, ErrPermissionDenied},
		{StatusRefused, ReadyErrorTargetRefused, ErrTargetRefused},
		{StatusRefused, ReadyErrorResource, ErrResource},
		{StatusRefused, ReadyErrorCanceled, ErrCanceled},
		{StatusExpired, ReadyErrorOutcomeUnknown, ErrOutcomeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.want.Error(), func(t *testing.T) {
			h := newHarness(t, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch := h.openAsync(ctx, h.openReq)
			waitState(t, h.mgr, h.key(), StateOpenCommitted)
			msg := h.readyMessage()
			msg.Status = tc.status
			msg.ErrorCode = tc.code
			msg.InitialWindow = 0
			if err := h.mgr.HandleReady(msg); err != nil {
				t.Fatalf("HandleReady: %v", err)
			}
			res := mustRecv(t, ch)
			if !errors.Is(res.err, tc.want) {
				t.Fatalf("Open err = %v, want %v", res.err, tc.want)
			}
			if res.c != nil {
				t.Fatalf("Open returned a handle with error %v", res.err)
			}
			if snap := h.mgr.Snapshot(); snap.Circuits[0].State != StateFailed {
				t.Fatalf("state = %s", snap.Circuits[0].State)
			}
		})
	}
}

func TestHandleReadyMalformedRejected(t *testing.T) {
	h := newHarness(t, nil)
	msg := h.readyMessage()
	msg.Status = StatusReady
	msg.ErrorCode = ReadyErrorResource
	if err := h.mgr.HandleReady(msg); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("err = %v, want ErrMalformedMessage", err)
	}
}

func TestOpenAdmissionRefusedTriesNextCandidate(t *testing.T) {
	h := newHarness(t, nil)
	second := Candidate{PathID: 8, PathGeneration: 4, RouteViewVersion: 12, PathDigest: [32]byte{0x03},
		Session: SessionRef{ID: testSessionID(0x32), PathID: 8, PathGeneration: 4}}
	req := h.openReq
	req.Candidates = append(req.Candidates, second)

	admissions := 0
	h.egress.setAdmission(AdmissionRefused)
	// The first candidate is definitively refused; the retry on the second
	// candidate (higher attempt, fresh request_id) is admitted.
	h.egress.admitHook = func(Submission) {
		admissions++
		if admissions == 2 {
			h.egress.setAdmission(AdmissionCommitted)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.openAsync(ctx, req)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)

	snap := h.mgr.Snapshot()
	if snap.Circuits[0].Attempt != 1 {
		t.Fatalf("attempt = %d, want 1", snap.Circuits[0].Attempt)
	}
	if admissions != 2 {
		t.Fatalf("admissions = %d, want 2", admissions)
	}
	// request_id is scoped to (SessionID, direction): the second candidate uses
	// its own Session, so its first RPC id is 1 again, while the attempt advanced
	// within the same Dial. Monotonic reuse inside one Session is covered by
	// TestRequestIDMonotonicAndExhaustion.
	if snap.Circuits[0].RequestID != 1 {
		t.Fatalf("request id = %d, want 1 for the new session", snap.Circuits[0].RequestID)
	}
	msg := h.readyMessage()
	msg.Attempt = 1
	msg.RequestID = 1
	if err := h.mgr.HandleReady(msg); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	res := mustRecv(t, ch)
	if res.err != nil || res.c.State() != StateReady {
		t.Fatalf("Open = %v state %v", res.err, res.c)
	}
}

func TestOpenAllCandidatesRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.egress.admission = AdmissionRefused
	req := h.openReq
	req.Candidates = append(req.Candidates, Candidate{PathID: 8, PathGeneration: 4,
		Session: SessionRef{ID: testSessionID(0x32), PathID: 8, PathGeneration: 4}})
	ch := h.openAsync(context.Background(), req)
	res := mustRecv(t, ch)
	if !errors.Is(res.err, ErrNoRoute) {
		t.Fatalf("err = %v, want ErrNoRoute", res.err)
	}
	if got := h.egress.count(); got != 2 {
		t.Fatalf("admissions = %d, want 2", got)
	}
	snap := h.mgr.Snapshot()
	if snap.Circuits[0].State != StateFailed {
		t.Fatalf("state = %s", snap.Circuits[0].State)
	}
}

func TestOpenAmbiguousAdmissionDoesNotSwitchCandidate(t *testing.T) {
	h := newHarness(t, nil)
	req := h.openReq
	req.Candidates = append(req.Candidates, Candidate{PathID: 8, PathGeneration: 4,
		Session: SessionRef{ID: testSessionID(0x32), PathID: 8, PathGeneration: 4}})
	h.egress.admitErr = errors.New("link writer outcome unknown")
	ch := h.openAsync(context.Background(), req)
	res := mustRecv(t, ch)
	if !errors.Is(res.err, ErrOutcomeUnknown) {
		t.Fatalf("err = %v, want ErrOutcomeUnknown", res.err)
	}
	if got := h.egress.count(); got != 1 {
		t.Fatalf("admissions = %d, want 1 (no candidate switch after an ambiguous result)", got)
	}
	snap := h.mgr.Snapshot()
	if snap.Circuits[0].Attempt != 0 {
		t.Fatalf("attempt advanced to %d", snap.Circuits[0].Attempt)
	}
}

func TestOpenContextCancelPreCommit(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)
	cancel()
	res := mustRecv(t, ch)
	if !errors.Is(res.err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", res.err)
	}
	snap := h.mgr.Snapshot()
	if snap.Circuits[0].State != StateCancelSent {
		t.Fatalf("state = %s, want CancelSent", snap.Circuits[0].State)
	}
	// A CANCELED STREAM_RESET must have been submitted after the Open.
	h.egress.mu.Lock()
	frames := append([]submission(nil), h.egress.frames...)
	h.egress.mu.Unlock()
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want Open + Reset", len(frames))
	}
	reset, err := DecodeResetMessage(decodeFrame(t, frames[1]))
	if err != nil {
		t.Fatalf("decode reset: %v", err)
	}
	if reset.Reason != ResetReasonCanceled || reset.CircuitID != h.circuit {
		t.Fatalf("reset = %+v", reset)
	}
	if frames[1].admitted {
		t.Fatal("STREAM_RESET must use Send, not AdmitOpen")
	}
}

func TestOpenContextCancelPostCommit(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)
	cancel()
	res := mustRecv(t, ch)
	if !errors.Is(res.err, ErrOutcomeUnknown) {
		t.Fatalf("err = %v, want ErrOutcomeUnknown after commit", res.err)
	}
	if snap := h.mgr.Snapshot(); snap.Circuits[0].State != StateCancelSent {
		t.Fatalf("state = %s", snap.Circuits[0].State)
	}
	if got := h.egress.count(); got != 2 {
		t.Fatalf("frames = %d, want Open + Cancel", got)
	}
}

func TestOpenBudgetExceededPostCommit(t *testing.T) {
	h := newHarness(t, nil)
	req := h.openReq
	req.Budget = 20 * time.Millisecond
	ch := h.openAsync(context.Background(), req)
	res := mustRecv(t, ch)
	if !errors.Is(res.err, ErrOpenTimeout) {
		t.Fatalf("err = %v, want ErrOpenTimeout", res.err)
	}
	if !errors.Is(res.err, ErrOutcomeUnknown) {
		t.Fatalf("err = %v, want ErrOutcomeUnknown wrapper", res.err)
	}
	if snap := h.mgr.Snapshot(); snap.Circuits[0].State != StateCancelSent {
		t.Fatalf("state = %s", snap.Circuits[0].State)
	}
}

func TestLateReadyIgnoredAfterCancel(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)
	cancel()
	if res := mustRecv(t, ch); res.err == nil {
		t.Fatal("Open returned nil error after cancel")
	}
	before := h.mgr.Snapshot()
	if err := h.mgr.HandleReady(h.readyMessage()); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	after := h.mgr.Snapshot()
	if after.Circuits[0].State != StateCancelSent {
		t.Fatalf("late READY changed the state to %s", after.Circuits[0].State)
	}
	if after.Counters.LateReady != before.Counters.LateReady+1 {
		t.Fatalf("late ready counter = %d, want %d", after.Counters.LateReady, before.Counters.LateReady+1)
	}
}

func TestStaleAttemptReadyIgnored(t *testing.T) {
	h := newHarness(t, nil)
	second := Candidate{PathID: 8, PathGeneration: 4, Session: SessionRef{ID: testSessionID(0x32), PathID: 8, PathGeneration: 4}}
	req := h.openReq
	req.Candidates = append(req.Candidates, second)
	h.egress.setAdmission(AdmissionRefused)
	admissions := 0
	h.egress.admitHook = func(Submission) {
		admissions++
		if admissions == 2 {
			h.egress.setAdmission(AdmissionCommitted)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.openAsync(ctx, req)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)

	// attempt 0 READY is stale now that attempt 1 is committed
	stale := h.readyMessage()
	stale.Attempt = 0
	stale.RequestID = 1
	if err := h.mgr.HandleReady(stale); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	if snap := h.mgr.Snapshot(); snap.Circuits[0].State != StateOpenCommitted {
		t.Fatalf("stale READY applied: state = %s", snap.Circuits[0].State)
	}
	// request_id mismatch for the current attempt is ignored too
	wrongID := h.readyMessage()
	wrongID.Attempt = 1
	wrongID.RequestID = 99
	if err := h.mgr.HandleReady(wrongID); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	if snap := h.mgr.Snapshot(); snap.Circuits[0].State != StateOpenCommitted {
		t.Fatalf("mismatched request id applied: state = %s", snap.Circuits[0].State)
	}
	// the matching READY is accepted
	good := h.readyMessage()
	good.Attempt = 1
	good.RequestID = 1
	if err := h.mgr.HandleReady(good); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	if res := mustRecv(t, ch); res.err != nil {
		t.Fatalf("Open err = %v", res.err)
	}
}

func TestDuplicateReadyIsIdempotentAndDoesNotRegressCredit(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)
	if err := h.mgr.HandleReady(h.readyMessage()); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	res := mustRecv(t, ch)
	if res.err != nil {
		t.Fatalf("Open err = %v", res.err)
	}
	// The peer may advance the credit up to this side's send frontier (the next
	// byte to send, still 0 here) plus the frozen 256 KiB cap. Anything beyond it
	// is covered by TestWindowUpdateBeyondCreditFrontierIsProtocol, which must use
	// its own Circuit because the violation terminates the stream.
	later := res.c.SendNext() + MaxCreditAhead
	if err := h.mgr.HandleWindowUpdate(WindowUpdateMessage{FromNodeID: h.peer, CircuitID: h.circuit, Window: later}); err != nil {
		t.Fatalf("HandleWindowUpdate: %v", err)
	}
	if got := res.c.SendWindow(); got != later {
		t.Fatalf("send window = %d, want %d", got, later)
	}
	if err := h.mgr.HandleReady(h.readyMessage()); err != nil {
		t.Fatalf("duplicate HandleReady: %v", err)
	}
	if got := res.c.SendWindow(); got != later {
		t.Fatalf("duplicate READY regressed the window to %d", got)
	}
	if snap := h.mgr.Snapshot(); snap.Circuits[0].State != StateReady {
		t.Fatalf("state = %s", snap.Circuits[0].State)
	}
}

func TestHandleReadyUnknownKeyIgnored(t *testing.T) {
	h := newHarness(t, nil)
	msg := h.readyMessage()
	msg.CircuitID = testCircuitID(0x99)
	if err := h.mgr.HandleReady(msg); err != nil {
		t.Fatalf("unknown READY err = %v, want nil", err)
	}
}

func TestRetransmitOpenKeepsAttemptAndRequestID(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)
	first := decodeFrame(t, h.egress.at(0))
	if err := h.mgr.RetransmitOpen(ctx, h.key()); err != nil {
		t.Fatalf("RetransmitOpen: %v", err)
	}
	second := decodeFrame(t, h.egress.at(1))
	if !bytes.Equal(first, second) {
		t.Fatalf("retransmission is not byte-identical:\n%x\n%x", first, second)
	}
	if got := h.egress.at(1).sub.Kind; got != KindControlRPC {
		t.Fatalf("kind = %d", got)
	}
	if err := h.mgr.HandleReady(h.readyMessage()); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	if res := mustRecv(t, ch); res.err != nil {
		t.Fatalf("Open err = %v", res.err)
	}
	// A Ready circuit may not retransmit any more.
	if err := h.mgr.RetransmitOpen(ctx, h.key()); !errors.Is(err, ErrState) {
		t.Fatalf("retransmit after Ready err = %v, want ErrState", err)
	}
}

func TestRetransmitOpenRefusedIsOutcomeUnknown(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)
	h.egress.mu.Lock()
	h.egress.admission = AdmissionRefused
	h.egress.mu.Unlock()
	if err := h.mgr.RetransmitOpen(ctx, h.key()); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("err = %v, want ErrOutcomeUnknown", err)
	}
	cancel()
	if res := mustRecv(t, ch); !errors.Is(res.err, ErrOutcomeUnknown) {
		t.Fatalf("Open err = %v", res.err)
	}
}

func TestRequestIDMonotonicAndExhaustion(t *testing.T) {
	h := newHarness(t, nil)
	h.mgr.mu.Lock()
	for i := 0; i < 3; i++ {
		id, err := h.mgr.nextRequestIDLocked(h.session)
		if err != nil {
			h.mgr.mu.Unlock()
			t.Fatalf("nextRequestID: %v", err)
		}
		if id != uint64(i+1) {
			h.mgr.mu.Unlock()
			t.Fatalf("request id %d, want %d", id, i+1)
		}
	}
	h.mgr.requestIDs[h.session.ID] = math.MaxUint64
	if _, err := h.mgr.nextRequestIDLocked(h.session); !errors.Is(err, ErrRequestIDExhausted) {
		h.mgr.mu.Unlock()
		t.Fatalf("exhaustion err = %v", err)
	}
	h.mgr.mu.Unlock()
}

func TestSessionRefValidation(t *testing.T) {
	bad := []SessionRef{
		{},
		{ID: testSessionID(1)},
		{PathID: 1, PathGeneration: 1},
		{ID: testSessionID(1), PathID: 1},
	}
	for _, ref := range bad {
		if err := ref.Validate(); err == nil {
			t.Fatalf("Validate(%+v) = nil", ref)
		}
	}
	good := SessionRef{ID: testSessionID(1), PathID: 1, PathGeneration: 1}
	if err := good.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if good.IsZero() {
		t.Fatal("IsZero on a set reference")
	}
}

func TestKeyAndReasonStrings(t *testing.T) {
	key := Key{ContextID: testContextID(), SrcNodeID: testNodeID(1), CircuitID: testCircuitID(1)}
	if err := key.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if key.String() == "" {
		t.Fatal("empty key string")
	}
	for _, bad := range []Key{{}, {ContextID: testContextID()}, {ContextID: testContextID(), SrcNodeID: testNodeID(1)}} {
		if err := bad.Validate(); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("Validate(%+v) = %v", bad, err)
		}
	}
	reasons := []ResetReason{ResetReasonNoRoute, ResetReasonLinkDown, ResetReasonResource, ResetReasonProtocol, ResetReasonCanceled}
	wantErrs := []error{ErrNoRoute, ErrLinkDown, ErrResource, ErrProtocol, ErrCanceled}
	for i, r := range reasons {
		if !r.Valid() || r.String() == "" {
			t.Fatalf("reason %d invalid", i)
		}
		if !errors.Is(r.Err(), wantErrs[i]) {
			t.Fatalf("reason %s err = %v", r, r.Err())
		}
	}
	if ResetReason(0x99).Valid() || !errors.Is(ResetReason(0x99).Err(), ErrProtocol) {
		t.Fatal("unknown reason accepted")
	}
	states := []State{StateRequested, StateOpenUncommitted, StateOpenCommitted, StateReady,
		StateLocalWriteClosed, StateRemoteWriteClosed, StateBothClosed, StateCancelSent, StateResetting, StateFailed, StateClosed}
	want := []string{"Requested", "OpenUncommitted", "OpenCommitted", "Ready", "LocalWriteClosed",
		"RemoteWriteClosed", "BothClosed", "CancelSent", "Resetting", "Failed", "Closed"}
	for i, s := range states {
		if s.String() != want[i] {
			t.Fatalf("state %d String = %q, want %q", i, s.String(), want[i])
		}
	}
	if StateReady.Terminal() || StateReady.Finished() {
		t.Fatal("Ready must be neither terminal nor finished")
	}
	if StateBothClosed.Terminal() || !StateBothClosed.Finished() {
		t.Fatal("BothClosed classification wrong")
	}
	for _, s := range []State{StateCancelSent, StateResetting, StateFailed, StateClosed} {
		if !s.Terminal() || !s.Finished() {
			t.Fatalf("%s must be terminal", s)
		}
	}
	if State(0).String() == "" {
		t.Fatal("zero state string")
	}
}

func TestOpenNilContextHandleReadyClosedManager(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.mgr.Open(nil, h.openReq); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil ctx err = %v", err)
	}
	if err := h.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.mgr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	select {
	case <-h.mgr.Done():
	default:
		t.Fatal("Done not closed")
	}
	if _, err := h.mgr.Open(context.Background(), h.openReq); !errors.Is(err, ErrClosed) {
		t.Fatalf("Open after Close err = %v", err)
	}
	if err := h.mgr.HandleReady(h.readyMessage()); !errors.Is(err, ErrClosed) {
		t.Fatalf("HandleReady after Close err = %v", err)
	}
	if _, err := h.mgr.Accept(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Accept after Close err = %v", err)
	}
	if _, err := h.mgr.Lookup(h.key()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Lookup after Close err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// send credit, stream data, tombstones, local FIN and concurrency
// ---------------------------------------------------------------------------

// TestWindowUpdateBeyondCreditFrontierIsProtocol pins the sender-side cap: a
// peer may not advertise credit beyond this side's send frontier plus the frozen
// 256 KiB. The violation terminates the stream and the credit is never applied.
func TestWindowUpdateBeyondCreditFrontierIsProtocol(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)
	if err := h.mgr.HandleReady(h.readyMessage()); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	res := mustRecv(t, ch)
	if res.err != nil {
		t.Fatalf("Open err = %v", res.err)
	}
	frontier := res.c.SendNext() + MaxCreditAhead
	if err := h.mgr.HandleWindowUpdate(WindowUpdateMessage{FromNodeID: h.peer, CircuitID: h.circuit, Window: frontier + 1}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("credit beyond the frontier err = %v, want ErrProtocol", err)
	}
	if snap := h.mgr.Snapshot(); !snap.Circuits[0].State.Finished() {
		t.Fatalf("state = %s, want a finished state", snap.Circuits[0].State)
	}
	// A credit frame for a finished Circuit is ignored, never applied.
	if err := h.mgr.HandleWindowUpdate(WindowUpdateMessage{FromNodeID: h.peer, CircuitID: h.circuit, Window: frontier + 2}); err != nil {
		t.Fatalf("late HandleWindowUpdate: %v", err)
	}
	if got := res.c.SendWindow(); got != InitialWindow {
		t.Fatalf("send window = %d, want the unchanged %d", got, InitialWindow)
	}
}

// TestHandleResetUnknownReasonIsProtocol covers the inbound half of the unknown
// reason contract: the frame stays decodable so HandleReset can terminate the
// stream and report the protocol violation.
func TestHandleResetUnknownReasonIsProtocol(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)

	payload := make([]byte, controlRPCHeaderSize+resetPayloadSize)
	binary.BigEndian.PutUint16(payload[0:2], uint16(RPCStreamReset))
	copy(payload[controlRPCHeaderSize:], h.circuit[:])
	binary.BigEndian.PutUint32(payload[controlRPCHeaderSize+16:], FirstAttempt)
	binary.BigEndian.PutUint32(payload[controlRPCHeaderSize+20:], 0x99)
	decoded, err := DecodeResetMessage(payload)
	if err != nil {
		t.Fatalf("DecodeResetMessage: %v", err)
	}
	if decoded.Reason.Valid() {
		t.Fatalf("reason 0x%04x decoded as valid", uint32(decoded.Reason))
	}
	decoded.FromNodeID = h.peer
	if err := h.mgr.HandleReset(decoded); !errors.Is(err, ErrProtocol) {
		t.Fatalf("HandleReset err = %v, want ErrProtocol", err)
	}
	if snap := h.mgr.Snapshot(); snap.Circuits[0].State != StateClosed {
		t.Fatalf("state = %s, want Closed", snap.Circuits[0].State)
	}
	res := mustRecv(t, ch)
	if res.c != nil || !errors.Is(res.err, ErrProtocol) {
		t.Fatalf("Open = %v, %v; want a nil handle and ErrProtocol", res.c, res.err)
	}
}

// TestStreamDataSeqFinAndResource drives the receive side: in-order DATA is
// delivered, a complete duplicate is discarded, FIN closes the remote direction,
// and a protocol or credit violation terminates the stream.
func TestStreamDataSeqFinAndResource(t *testing.T) {
	// newTarget admits one inbound stream and Accepts it.
	newTarget := func(t *testing.T) (*harness, *Circuit) {
		t.Helper()
		h := newHarness(t, nil)
		if _, err := h.mgr.HandleOpen(h.openMessage(FirstAttempt, 1)); err != nil {
			t.Fatalf("HandleOpen: %v", err)
		}
		c, err := h.mgr.Accept(context.Background())
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		return h, c
	}

	t.Run("data duplicate and fin", func(t *testing.T) {
		h, c := newTarget(t)
		if c.Role() != RoleTarget {
			t.Fatalf("role = %s, want Target", c.Role())
		}
		data := StreamDataMessage{FromNodeID: h.peer, CircuitID: h.circuit, Flags: FlagData, StreamSeq: 0, Payload: []byte("hello")}
		n, err := h.mgr.HandleStreamData(data)
		if err != nil || n != 5 {
			t.Fatalf("HandleStreamData = %d, %v; want 5, nil", n, err)
		}
		if got := c.Buffered(); got != 5 {
			t.Fatalf("buffered = %d, want 5", got)
		}
		if n, err := h.mgr.HandleStreamData(data); err != nil || n != 0 {
			t.Fatalf("duplicate = %d, %v; want 0, nil", n, err)
		}
		if n, err := h.mgr.HandleStreamData(StreamDataMessage{FromNodeID: h.peer, CircuitID: h.circuit, Flags: FlagFin, StreamSeq: 5}); err != nil || n != 0 {
			t.Fatalf("FIN = %d, %v; want 0, nil", n, err)
		}
		if got := c.State(); got != StateRemoteWriteClosed {
			t.Fatalf("state = %s, want RemoteWriteClosed", got)
		}
		if _, err := h.mgr.HandleStreamData(StreamDataMessage{FromNodeID: h.peer, CircuitID: h.circuit, Flags: FlagData, StreamSeq: 5, Payload: []byte("x")}); !errors.Is(err, ErrProtocol) {
			t.Fatalf("DATA after FIN err = %v, want ErrProtocol", err)
		}
	})

	t.Run("forward gap", func(t *testing.T) {
		h, c := newTarget(t)
		if _, err := h.mgr.HandleStreamData(StreamDataMessage{FromNodeID: h.peer, CircuitID: h.circuit, Flags: FlagData, StreamSeq: 9, Payload: []byte("gap")}); !errors.Is(err, ErrProtocol) {
			t.Fatalf("forward gap err = %v, want ErrProtocol", err)
		}
		if got := c.State(); !got.Finished() {
			t.Fatalf("state = %s, want a finished state", got)
		}
	})

	t.Run("credit beyond the advertised window", func(t *testing.T) {
		h, _ := newTarget(t)
		full := make([]byte, MaxStreamDataPayload)
		if n, err := h.mgr.HandleStreamData(StreamDataMessage{FromNodeID: h.peer, CircuitID: h.circuit, Flags: FlagData, StreamSeq: 0, Payload: full}); err != nil || n != len(full) {
			t.Fatalf("first frame = %d, %v; want %d, nil", n, err, len(full))
		}
		if _, err := h.mgr.HandleStreamData(StreamDataMessage{FromNodeID: h.peer, CircuitID: h.circuit, Flags: FlagData, StreamSeq: uint64(len(full)), Payload: full}); !errors.Is(err, ErrResource) {
			t.Fatalf("credit violation err = %v, want ErrResource", err)
		}
	})
}

// TestCanceledResetRecordsTombstoneAndRefusesLateOpen covers the target-side
// tombstone: a CANCELED inbound reset opens a bounded rejection window, a late
// CIRCUIT_OPEN for that CircuitID is refused with CANCELED, and a local Dial
// never re-reserves a tombstoned key.
func TestCanceledResetRecordsTombstoneAndRefusesLateOpen(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.mgr.HandleOpen(h.openMessage(FirstAttempt, 1)); err != nil {
		t.Fatalf("HandleOpen: %v", err)
	}
	if err := h.mgr.HandleReset(ResetMessage{FromNodeID: h.peer, CircuitID: h.circuit, Attempt: FirstAttempt, Reason: ResetReasonCanceled}); err != nil {
		t.Fatalf("HandleReset: %v", err)
	}
	snap := h.mgr.Snapshot()
	if len(snap.Tombstones) != 1 {
		t.Fatalf("tombstones = %+v, want exactly one", snap.Tombstones)
	}
	wantKey := Key{ContextID: h.ctx, SrcNodeID: h.peer, CircuitID: h.circuit}
	if snap.Tombstones[0].Key != wantKey {
		t.Fatalf("tombstone key = %s, want %s", snap.Tombstones[0].Key, wantKey)
	}
	if want := h.clock.Now().Add(DefaultTombstoneTTL); !snap.Tombstones[0].Until.Equal(want) {
		t.Fatalf("tombstone until = %s, want %s", snap.Tombstones[0].Until, want)
	}
	if got := snap.Circuits[0].State; got != StateClosed {
		t.Fatalf("state = %s, want Closed", got)
	}

	// A late CIRCUIT_OPEN for the same CircuitID never creates a second stream.
	res, err := h.mgr.HandleOpen(h.openMessage(1, 2))
	if err != nil {
		t.Fatalf("late HandleOpen: %v", err)
	}
	if res.Status != StatusRefused {
		t.Fatalf("late Open status = %s, want Refused", res.Status)
	}
	after := h.mgr.Snapshot()
	if len(after.Circuits) != 1 || after.Circuits[0].Attempt != FirstAttempt || after.Circuits[0].Accepted {
		t.Fatalf("late Open changed the record: %+v", after.Circuits)
	}
	if after.Counters.Refused != snap.Counters.Refused+1 {
		t.Fatalf("refused counter = %d, want %d", after.Counters.Refused, snap.Counters.Refused+1)
	}

	// The reservation path must reject a tombstoned key instead of reusing it.
	h.mgr.mu.Lock()
	h.mgr.tombstones[h.key()] = h.clock.Now().Add(DefaultTombstoneTTL)
	h.mgr.mu.Unlock()
	if _, err := h.mgr.newKeyLocked(h.circuit); !errors.Is(err, ErrResource) {
		t.Fatalf("newKeyLocked on a tombstoned id err = %v, want ErrResource", err)
	}

	// The rejection window is bounded: the tombstone expires with its TTL.
	h.clock.Advance(DefaultTombstoneTTL + time.Second)
	h.mgr.Expire()
	if got := h.mgr.Snapshot().Tombstones; len(got) != 0 {
		t.Fatalf("tombstones after the TTL = %+v, want none", got)
	}
}

// TestCloseWriteSendsFinOnceAndClosesLocalDirection covers the local FIN: the
// frame carries the current send offset, the state becomes LocalWriteClosed, a
// second CloseWrite is idempotent, and the write side is then refused.
func TestCloseWriteSendsFinOnceAndClosesLocalDirection(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)
	if err := h.mgr.HandleReady(h.readyMessage()); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	res := mustRecv(t, ch)
	if res.err != nil {
		t.Fatalf("Open err = %v", res.err)
	}
	before := h.egress.count()
	if err := h.mgr.CloseWrite(h.key()); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if got := h.egress.count(); got != before+1 {
		t.Fatalf("frames = %d, want %d", got, before+1)
	}
	fin := h.egress.at(before)
	if fin.admitted || fin.sub.Kind != KindStreamData || fin.sub.Dest != h.peer {
		t.Fatalf("FIN submission = %+v", fin.sub)
	}
	decoded, err := DecodeStreamData(decodeFrame(t, fin))
	if err != nil {
		t.Fatalf("decode FIN: %v", err)
	}
	if decoded.Flags != FlagFin || decoded.StreamSeq != 0 || decoded.CircuitID != h.circuit {
		t.Fatalf("FIN = %+v", decoded)
	}
	if got := res.c.State(); got != StateLocalWriteClosed {
		t.Fatalf("state = %s, want LocalWriteClosed", got)
	}
	// Idempotent: the second FIN changes no state and sends nothing.
	if err := h.mgr.CloseWrite(h.key()); err != nil {
		t.Fatalf("second CloseWrite: %v", err)
	}
	if got := h.egress.count(); got != before+1 {
		t.Fatalf("second CloseWrite sent %d frames, want %d", got, before+1)
	}
	// The write side is closed afterwards.
	if _, err := h.mgr.WriteData(ctx, h.key(), []byte("x")); !errors.Is(err, ErrWriteClosed) {
		t.Fatalf("write after FIN err = %v, want ErrWriteClosed", err)
	}
}

// TestConcurrentManagerUseIsRaceFree exercises the handler and observation paths
// from several goroutines at once. It is only meaningful under -race.
func TestConcurrentManagerUseIsRaceFree(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)
	if err := h.mgr.HandleReady(h.readyMessage()); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	res := mustRecv(t, ch)
	if res.err != nil {
		t.Fatalf("Open err = %v", res.err)
	}
	c := res.c

	const workers, rounds = 8, 64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				switch (i + j) % 7 {
				case 0:
					if err := h.mgr.HandleReady(h.readyMessage()); err != nil {
						t.Errorf("concurrent HandleReady: %v", err)
					}
				case 1:
					if err := h.mgr.HandleWindowUpdate(WindowUpdateMessage{FromNodeID: h.peer, CircuitID: h.circuit, Window: InitialWindow + 1}); err != nil {
						t.Errorf("concurrent HandleWindowUpdate: %v", err)
					}
				case 2:
					if got := h.mgr.Snapshot(); got.ContextID != h.ctx {
						t.Errorf("snapshot context = %s", got.ContextID)
					}
				case 3:
					if _, err := h.mgr.Lookup(h.key()); err != nil {
						t.Errorf("concurrent Lookup: %v", err)
					}
				case 4:
					_, _ = c.State(), c.SendWindow()
					_, _ = c.RecvWindow(), c.Buffered()
					_, _ = c.SendNext(), c.RecvNext()
				case 5:
					_ = h.mgr.Len()
					_ = h.egress.count()
				case 6:
					// A stale credit is ignored, never an error.
					if err := h.mgr.HandleWindowUpdate(WindowUpdateMessage{FromNodeID: h.peer, CircuitID: h.circuit, Window: InitialWindow}); err != nil {
						t.Errorf("stale HandleWindowUpdate: %v", err)
					}
				}
			}
		}(i)
	}
	wg.Wait()

	if got := c.SendWindow(); got != InitialWindow+1 {
		t.Fatalf("send window = %d, want %d", got, InitialWindow+1)
	}
	if got := c.State(); got != StateReady {
		t.Fatalf("state = %s, want Ready", got)
	}
}

// ---------------------------------------------------------------------------
// terminal-reset delivery regression
// ---------------------------------------------------------------------------

// newReadySource dials one source-side Circuit to Ready with the standard fake
// crypto/egress harness, so a test can drive its receive direction with inbound
// frames exactly as the Link dispatcher would.
func newReadySource(t *testing.T, mutate func(cfg *Config)) (*harness, *Circuit) {
	t.Helper()
	h := newHarness(t, mutate)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := h.openAsync(ctx, h.openReq)
	waitState(t, h.mgr, h.key(), StateOpenCommitted)
	if err := h.mgr.HandleReady(h.readyMessage()); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	res := mustRecv(t, ch)
	if res.err != nil {
		t.Fatalf("Open err = %v", res.err)
	}
	return h, res.c
}

// TestTerminalResetDrainsAcceptedDataBeforeCause is the regression for the
// CONNECT response loss: the peer's DATA frames were already accepted into the
// receive buffer when a later inbound RESET(CANCELED) - an ordinary net.Conn
// Close on the target side - made the direction terminal. Accepted bytes are an
// already delivered prefix of the reliable byte stream, so the reader must
// still receive them FIFO; only the read after the drain reports the reset
// cause. Releasing the buffer at the terminal transition returned ErrCanceled
// with n=0 and silently truncated the accepted HTTP response.
func TestTerminalResetDrainsAcceptedDataBeforeCause(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

	t.Run("data then reset", func(t *testing.T) {
		h, c := newReadySource(t, nil)
		h.pushData(t, h.circuit, 0, response)
		if got := c.Buffered(); got != len(response) {
			t.Fatalf("buffered = %d, want %d", got, len(response))
		}
		if err := h.mgr.HandleReset(ResetMessage{FromNodeID: h.peer, CircuitID: h.circuit, Attempt: FirstAttempt, Reason: ResetReasonCanceled}); err != nil {
			t.Fatalf("HandleReset(CANCELED): %v", err)
		}

		buf := make([]byte, len(response)+32)
		n, err := h.mgr.ReadData(context.Background(), h.key(), buf)
		if n != len(response) || err != nil {
			t.Fatalf("ReadData = %d, %v; want %d bytes and nil for an accepted prefix", n, err, len(response))
		}
		if !bytes.Equal(buf[:n], response) {
			t.Fatalf("ReadData delivered %q, want %q", buf[:n], response)
		}
		if got := c.Buffered(); got != 0 {
			t.Fatalf("buffered after drain = %d, want 0", got)
		}
		n, err = h.mgr.ReadData(context.Background(), h.key(), buf)
		if n != 0 || !errors.Is(err, ErrCanceled) {
			t.Fatalf("ReadData after drain = %d, %v; want 0, ErrCanceled", n, err)
		}
	})

	t.Run("partial drain keeps bytes before the cause", func(t *testing.T) {
		h, _ := newReadySource(t, nil)
		h.pushData(t, h.circuit, 0, response)
		if err := h.mgr.HandleReset(ResetMessage{FromNodeID: h.peer, CircuitID: h.circuit, Attempt: FirstAttempt, Reason: ResetReasonCanceled}); err != nil {
			t.Fatalf("HandleReset(CANCELED): %v", err)
		}
		first := make([]byte, 8)
		n, err := h.mgr.ReadData(context.Background(), h.key(), first)
		if err != nil || n != 8 {
			t.Fatalf("partial ReadData = %d, %v; want 8, nil", n, err)
		}
		if !bytes.Equal(first, response[:8]) {
			t.Fatalf("partial read = %q, want %q", first, response[:8])
		}
		rest := make([]byte, len(response))
		n, err = h.mgr.ReadData(context.Background(), h.key(), rest)
		if err != nil || n != len(response)-8 {
			t.Fatalf("remaining ReadData = %d, %v; want %d, nil", n, err, len(response)-8)
		}
		if !bytes.Equal(rest[:n], response[8:]) {
			t.Fatalf("remaining read = %q, want %q", rest[:n], response[8:])
		}
		if _, err := h.mgr.ReadData(context.Background(), h.key(), rest); !errors.Is(err, ErrCanceled) {
			t.Fatalf("ReadData after full drain err = %v, want ErrCanceled", err)
		}
	})

	t.Run("fin then reset reports the reset cause", func(t *testing.T) {
		h, _ := newReadySource(t, nil)
		h.pushData(t, h.circuit, 0, response)
		h.pushFin(t, h.circuit, uint64(len(response)))
		if err := h.mgr.HandleReset(ResetMessage{FromNodeID: h.peer, CircuitID: h.circuit, Attempt: FirstAttempt, Reason: ResetReasonCanceled}); err != nil {
			t.Fatalf("HandleReset(CANCELED): %v", err)
		}
		buf := make([]byte, len(response)+8)
		n, err := h.mgr.ReadData(context.Background(), h.key(), buf)
		if err != nil || n != len(response) {
			t.Fatalf("ReadData = %d, %v; want %d, nil", n, err, len(response))
		}
		if !bytes.Equal(buf[:n], response) {
			t.Fatalf("ReadData delivered %q, want %q", buf[:n], response)
		}
		if _, err := h.mgr.ReadData(context.Background(), h.key(), buf); !errors.Is(err, ErrCanceled) {
			t.Fatalf("ReadData after a FIN+RESET drain err = %v, want ErrCanceled", err)
		}
	})
}

// TestTerminalResetRetainsRecvReservationUntilDrain pins the accounting
// boundary of the regression: a terminal reset must not return the shared
// receive charge while accepted bytes are still readable, the reader's last
// drain returns it exactly once, and a reader that never returns is released by
// the TTL reaper and by Manager.Close.
func TestTerminalResetRetainsRecvReservationUntilDrain(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\n\r\nok")

	t.Run("released once by the draining read", func(t *testing.T) {
		b := newFakeBudget(recvInitialChunk)
		h, _ := newReadySource(t, func(cfg *Config) { cfg.BufferBudget = b })
		h.pushData(t, h.circuit, 0, response)
		if err := h.mgr.HandleReset(ResetMessage{FromNodeID: h.peer, CircuitID: h.circuit, Attempt: FirstAttempt, Reason: ResetReasonCanceled}); err != nil {
			t.Fatalf("HandleReset(CANCELED): %v", err)
		}
		if got := b.stats(); got.reserves != 1 || got.releases != 0 || got.bytes != recvInitialChunk || got.held != 1 {
			t.Fatalf("ledger after the terminal reset = %+v; want the accepted buffer still charged", got)
		}
		buf := make([]byte, len(response)+8)
		if n, err := h.mgr.ReadData(context.Background(), h.key(), buf); err != nil || n != len(response) {
			t.Fatalf("ReadData = %d, %v; want %d, nil", n, err, len(response))
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 || got.held != 0 {
			t.Fatalf("ledger after the draining read = %+v; want exactly one release", got)
		}
		if _, err := h.mgr.ReadData(context.Background(), h.key(), buf); !errors.Is(err, ErrCanceled) {
			t.Fatalf("ReadData after drain err = %v, want ErrCanceled", err)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 {
			t.Fatalf("cause read double-released the charge: %+v", got)
		}
	})

	t.Run("reaper force-releases an undrained terminal buffer", func(t *testing.T) {
		b := newFakeBudget(recvInitialChunk)
		h, _ := newReadySource(t, func(cfg *Config) { cfg.BufferBudget = b })
		h.pushData(t, h.circuit, 0, response)
		if err := h.mgr.HandleReset(ResetMessage{FromNodeID: h.peer, CircuitID: h.circuit, Attempt: FirstAttempt, Reason: ResetReasonCanceled}); err != nil {
			t.Fatalf("HandleReset(CANCELED): %v", err)
		}
		if got := b.stats(); got.releases != 0 {
			t.Fatalf("premature release before the TTL: %+v", got)
		}
		h.clock.Advance(DefaultTombstoneTTL + time.Second)
		if removed := h.mgr.Expire(); removed != 1 {
			t.Fatalf("Expire removed %d records, want 1", removed)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 || got.held != 0 {
			t.Fatalf("reaper ledger = %+v; want the undrained terminal charge returned once", got)
		}
		if _, err := h.mgr.Lookup(h.key()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Lookup after reap err = %v, want ErrNotFound", err)
		}
	})

	t.Run("manager close force-releases", func(t *testing.T) {
		b := newFakeBudget(recvInitialChunk)
		h, _ := newReadySource(t, func(cfg *Config) { cfg.BufferBudget = b })
		h.pushData(t, h.circuit, 0, response)
		if err := h.mgr.HandleReset(ResetMessage{FromNodeID: h.peer, CircuitID: h.circuit, Attempt: FirstAttempt, Reason: ResetReasonCanceled}); err != nil {
			t.Fatalf("HandleReset(CANCELED): %v", err)
		}
		if err := h.mgr.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := h.mgr.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if got := b.stats(); got.releases != 1 || got.bytes != 0 || got.held != 0 {
			t.Fatalf("Close ledger = %+v; want exactly one release", got)
		}
		if _, err := h.mgr.ReadData(context.Background(), h.key(), make([]byte, 8)); !errors.Is(err, ErrClosed) {
			t.Fatalf("ReadData after Manager.Close err = %v, want ErrClosed", err)
		}
	})
}

// ---------------------------------------------------------------------------
// FailSession: local, session-scoped terminal failure
// ---------------------------------------------------------------------------

func failRef(id byte, pathID uint64, gen uint32) SessionRef {
	return SessionRef{ID: testSessionID(id), PathID: pathID, PathGeneration: gen}
}

// waitSnapshot polls until the record reaches want and returns its snapshot.
func waitSnapshot(t *testing.T, m *Manager, key Key, want State) CircuitSnapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last State
	found := false
	for time.Now().Before(deadline) {
		for _, cs := range m.Snapshot().Circuits {
			if cs.Key != key {
				continue
			}
			found = true
			last = cs.State
			if cs.State == want {
				return cs
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("circuit %s never reached %s (last %s, found=%v)", key, want, last, found)
	return CircuitSnapshot{}
}

func (h *harness) requestOn(id CircuitID, ref SessionRef) OpenRequest {
	return OpenRequest{
		CircuitID:    id,
		TargetNodeID: h.peer,
		TargetPort:   8080,
		Candidates: []Candidate{{
			PathID:           ref.PathID,
			PathGeneration:   ref.PathGeneration,
			RouteViewVersion: 11,
			PathDigest:       [32]byte{0x01, 0x02},
			Session:          ref,
		}},
	}
}

// openReadyOn dials id on ref through the real public Open and drives the
// record to Ready with the matching CIRCUIT_READY.
func (h *harness) openReadyOn(t *testing.T, id CircuitID, ref SessionRef) *Circuit {
	t.Helper()
	ch := h.openAsync(context.Background(), h.requestOn(id, ref))
	cs := waitSnapshot(t, h.mgr, h.mgr.LocalKey(id), StateOpenCommitted)
	if err := h.mgr.HandleReady(ReadyMessage{
		FromNodeID:    h.peer,
		CircuitID:     id,
		Attempt:       cs.Attempt,
		RequestID:     cs.RequestID,
		Status:        StatusReady,
		InitialWindow: InitialWindow,
	}); err != nil {
		t.Fatalf("HandleReady: %v", err)
	}
	r := mustRecv(t, ch)
	if r.err != nil {
		t.Fatalf("Open: %v", r.err)
	}
	if r.c == nil {
		t.Fatal("Open returned a nil circuit")
	}
	if got := r.c.State(); got != StateReady {
		t.Fatalf("Open state = %s, want Ready", got)
	}
	return r.c
}

type failRead struct {
	n    int
	data []byte
	err  error
}

// startRead parks one public ReadData(context.Background()) call. The started
// channel closes immediately before the call so a caller can order work after
// the goroutine exists; the 1 s bound in requireSessionLost is only a hang
// detector, never the pass condition.
func startRead(c *Circuit) (<-chan failRead, <-chan struct{}) {
	started := make(chan struct{})
	out := make(chan failRead, 1)
	go func() {
		buf := make([]byte, 64)
		close(started)
		n, err := c.ReadData(context.Background(), buf)
		out <- failRead{n: n, data: append([]byte(nil), buf[:n]...), err: err}
	}()
	return out, started
}

// requireParked proves the read has not returned yet: it is blocked, not
// failing early.
func requireParked(t *testing.T, ch <-chan failRead, d time.Duration) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("ReadData returned early: n=%d err=%v", r.n, r.err)
	case <-time.After(d):
	}
}

// requireSessionLost fails the test if the blocked read does not come back with
// ErrSessionLost (and no bytes of this direction) inside the hang-detector
// bound.
func requireSessionLost(t *testing.T, ch <-chan failRead) failRead {
	t.Helper()
	select {
	case r := <-ch:
		if !errors.Is(r.err, ErrSessionLost) {
			t.Fatalf("ReadData err = %v, want ErrSessionLost", r.err)
		}
		if r.n != 0 {
			t.Fatalf("ReadData n = %d, want 0", r.n)
		}
		return r
	case <-time.After(time.Second):
		t.Fatal("ReadData did not wake within the 1s hang-detector bound")
		return failRead{}
	}
}

func requireData(t *testing.T, ch <-chan failRead, want []byte) {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("ReadData err = %v, want nil", r.err)
		}
		if !bytes.Equal(r.data, want) {
			t.Fatalf("ReadData = %q, want %q", r.data, want)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadData did not wake within the 1s hang-detector bound")
	}
}

func TestFailSessionWakesEveryMatchingReader(t *testing.T) {
	h := newHarness(t, nil)
	ref := failRef(0x31, 7, 3)
	idA := testCircuitID(0x61)
	idB := testCircuitID(0x62)
	a := h.openReadyOn(t, idA, ref)
	b := h.openReadyOn(t, idB, ref)

	ra, sa := startRead(a)
	rb, sb := startRead(b)
	<-sa
	<-sb
	requireParked(t, ra, 50*time.Millisecond)
	requireParked(t, rb, 50*time.Millisecond)

	frames := h.egress.count()
	if err := h.mgr.FailSession(ref, nil); err != nil {
		t.Fatalf("FailSession: %v", err)
	}
	if got := h.egress.count(); got != frames {
		t.Fatalf("FailSession submitted %d frame(s): it must not touch the wire", got-frames)
	}
	requireSessionLost(t, ra)
	requireSessionLost(t, rb)

	for _, c := range []*Circuit{a, b} {
		if got := c.State(); got != StateFailed {
			t.Fatalf("state = %s, want Failed", got)
		}
		if !errors.Is(c.Cause(), ErrSessionLost) {
			t.Fatalf("cause = %v, want ErrSessionLost", c.Cause())
		}
	}
}

func TestFailSessionLeavesOtherSessionsHealthy(t *testing.T) {
	h := newHarness(t, nil)
	refA := failRef(0x31, 7, 3)
	refB := failRef(0x32, 9, 5)
	idA := testCircuitID(0x63)
	idB := testCircuitID(0x64)
	a := h.openReadyOn(t, idA, refA)
	b := h.openReadyOn(t, idB, refB)

	ra, sa := startRead(a)
	rb, sb := startRead(b)
	<-sa
	<-sb
	requireParked(t, ra, 50*time.Millisecond)
	requireParked(t, rb, 50*time.Millisecond)

	if err := h.mgr.FailSession(refA, nil); err != nil {
		t.Fatalf("FailSession: %v", err)
	}
	requireSessionLost(t, ra)
	requireParked(t, rb, 50*time.Millisecond)

	payload := []byte("healthy")
	if n, err := h.mgr.HandleStreamData(StreamDataMessage{
		FromNodeID: h.peer,
		CircuitID:  idB,
		Flags:      FlagData,
		StreamSeq:  0,
		Payload:    payload,
	}); err != nil || n != len(payload) {
		t.Fatalf("HandleStreamData = %d, %v", n, err)
	}
	requireData(t, rb, payload)
}

func TestFailSessionRefusesFutureOpenOnTheSameRef(t *testing.T) {
	h := newHarness(t, nil)
	ref := failRef(0x31, 7, 3)
	if err := h.mgr.FailSession(ref, nil); err != nil {
		t.Fatalf("FailSession: %v", err)
	}
	frames := h.egress.count()
	id := testCircuitID(0x65)
	c, err := h.mgr.Open(context.Background(), h.requestOn(id, ref))
	if c != nil {
		t.Fatalf("Open returned circuit %s, want nil", c.Key())
	}
	if !errors.Is(err, ErrSessionLost) {
		t.Fatalf("Open err = %v, want ErrSessionLost", err)
	}
	if !errors.Is(err, ErrSessionRefFailed) {
		t.Fatalf("Open err = %v, want it to carry ErrSessionRefFailed", err)
	}
	if got := h.egress.count(); got != frames {
		t.Fatalf("Open submitted %d frame(s) on a failed session", got-frames)
	}
	cs := waitSnapshot(t, h.mgr, h.mgr.LocalKey(id), StateFailed)
	if cs.State == StateReady {
		t.Fatal("a circuit on a failed session reached Ready")
	}
}

func TestFailSessionRacingOpenCannotPublish(t *testing.T) {
	h := newHarness(t, nil)
	ref := failRef(0x31, 7, 3)
	id := testCircuitID(0x66)
	var once sync.Once
	h.egress.admitHook = func(Submission) {
		once.Do(func() {
			if err := h.mgr.FailSession(ref, nil); err != nil {
				t.Errorf("FailSession: %v", err)
			}
		})
	}
	r := mustRecv(t, h.openAsync(context.Background(), h.requestOn(id, ref)))
	if r.c != nil {
		t.Fatal("Open published a circuit after the session failed")
	}
	if !errors.Is(r.err, ErrSessionLost) {
		t.Fatalf("Open err = %v, want ErrSessionLost", r.err)
	}
	cs := waitSnapshot(t, h.mgr, h.mgr.LocalKey(id), StateFailed)
	if cs.State == StateReady {
		t.Fatal("a circuit on a failed session reached Ready")
	}
	// The only Egress activity may be the single admitted CIRCUIT_OPEN: no
	// STREAM_RESET or any other teardown may be submitted over the aborted
	// Session.
	if got := h.egress.count(); got != 1 {
		t.Fatalf("egress frames = %d, want 1 (the OPEN)", got)
	}
	if f := h.egress.at(0); !f.admitted {
		t.Fatalf("the only frame was not the admitted OPEN: admitted=%v kind=%v", f.admitted, f.sub.Kind)
	}
}

func TestFailSessionMatchesTheFullSessionRef(t *testing.T) {
	h := newHarness(t, nil)
	base := failRef(0x31, 7, 3)
	otherGen := failRef(0x31, 7, 4)
	otherID := failRef(0x32, 7, 3)
	idA := testCircuitID(0x67)
	idB := testCircuitID(0x68)
	idC := testCircuitID(0x69)
	a := h.openReadyOn(t, idA, base)
	b := h.openReadyOn(t, idB, otherGen)
	c := h.openReadyOn(t, idC, otherID)

	if err := h.mgr.FailSession(base, nil); err != nil {
		t.Fatalf("FailSession: %v", err)
	}
	if !errors.Is(a.Cause(), ErrSessionLost) {
		t.Fatalf("base circuit cause = %v, want ErrSessionLost", a.Cause())
	}
	for _, tc := range []struct {
		name string
		circ *Circuit
		id   CircuitID
	}{
		{"different PathGeneration", b, idB},
		{"different SessionID", c, idC},
	} {
		if got := tc.circ.State(); got != StateReady {
			t.Fatalf("%s: state = %s, want Ready", tc.name, got)
		}
		out, started := startRead(tc.circ)
		<-started
		requireParked(t, out, 50*time.Millisecond)
		payload := []byte(tc.name)
		if n, err := h.mgr.HandleStreamData(StreamDataMessage{
			FromNodeID: h.peer,
			CircuitID:  tc.id,
			Flags:      FlagData,
			StreamSeq:  0,
			Payload:    payload,
		}); err != nil || n != len(payload) {
			t.Fatalf("%s: HandleStreamData = %d, %v", tc.name, n, err)
		}
		requireData(t, out, payload)
	}
	if err := h.mgr.FailSession(otherGen, nil); err != nil {
		t.Fatalf("FailSession(otherGen): %v", err)
	}
	if !errors.Is(b.Cause(), ErrSessionLost) {
		t.Fatalf("other-generation circuit cause = %v, want ErrSessionLost", b.Cause())
	}
	if got := c.State(); got != StateReady {
		t.Fatalf("different-SessionID circuit state = %s, want Ready", got)
	}
}

func TestFailSessionWakesBlockedWriter(t *testing.T) {
	h := newHarness(t, nil)
	ref := failRef(0x31, 7, 3)
	c := h.openReadyOn(t, testCircuitID(0x81), ref)
	if n, err := c.WriteData(context.Background(), make([]byte, InitialWindow)); err != nil || n != int(InitialWindow) {
		t.Fatalf("WriteData = %d, %v", n, err)
	}
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, err := c.WriteData(context.Background(), []byte("x"))
		done <- err
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("WriteData returned early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := h.mgr.FailSession(ref, nil); err != nil {
		t.Fatalf("FailSession: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrSessionLost) {
			t.Fatalf("WriteData err = %v, want ErrSessionLost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked WriteData did not wake within the 1s hang-detector bound")
	}
}

func TestFailSessionFailsPendingDialAndQueuedTarget(t *testing.T) {
	h := newHarness(t, nil)
	ref := failRef(0x31, 7, 3)

	// A Dial blocked in waitReady is failed by the matching Session.
	id := testCircuitID(0x6A)
	ch := h.openAsync(context.Background(), h.requestOn(id, ref))
	waitSnapshot(t, h.mgr, h.mgr.LocalKey(id), StateOpenCommitted)
	if err := h.mgr.FailSession(ref, nil); err != nil {
		t.Fatalf("FailSession: %v", err)
	}
	if r := mustRecv(t, ch); r.c != nil || !errors.Is(r.err, ErrSessionLost) {
		t.Fatalf("Open = (%v, %v), want (nil, ErrSessionLost)", r.c, r.err)
	}

	// A target-side stream queued for Accept is failed and never delivered.
	refT := failRef(0x33, 11, 2)
	idT := testCircuitID(0x6B)
	msg := OpenMessage{
		FromNodeID:          h.peer,
		CircuitID:           idT,
		Attempt:             0,
		TargetPort:          8080,
		PathID:              refT.PathID,
		PathGeneration:      refT.PathGeneration,
		RouteViewVersion:    11,
		PathDigest:          [32]byte{0x01, 0x02},
		SourceInitialWindow: InitialWindow,
		RequestID:           1,
		Session:             refT,
	}
	res, err := h.mgr.HandleOpen(msg)
	if err != nil || !res.Created {
		t.Fatalf("HandleOpen = %+v, %v", res, err)
	}
	if err := h.mgr.FailSession(refT, nil); err != nil {
		t.Fatalf("FailSession(refT): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if c, err := h.mgr.Accept(ctx); c != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Accept = (%v, %v), want (nil, deadline exceeded)", c, err)
	}

	// An inbound OPEN on a failed Session is refused locally with no frame at
	// all (no READY, no RESET).
	frames := h.egress.count()
	msg2 := msg
	msg2.CircuitID = testCircuitID(0x6C)
	if _, err := h.mgr.HandleOpen(msg2); !errors.Is(err, ErrSessionLost) {
		t.Fatalf("HandleOpen on a failed session err = %v, want ErrSessionLost", err)
	}
	if got := h.egress.count(); got != frames {
		t.Fatalf("HandleOpen submitted %d frame(s) over a failed session", got-frames)
	}
}

func TestFailSessionReleasesReceiveReservationExactlyOnce(t *testing.T) {
	t.Run("accepted prefix drains then frees the lease", func(t *testing.T) {
		budget := newFakeBudget(1 << 20)
		h := newHarness(t, func(cfg *Config) { cfg.BufferBudget = budget })
		ref := failRef(0x31, 7, 3)
		id := testCircuitID(0x6D)
		c := h.openReadyOn(t, id, ref)
		payload := []byte("abcdefgh")
		if n, err := h.mgr.HandleStreamData(StreamDataMessage{
			FromNodeID: h.peer,
			CircuitID:  id,
			Flags:      FlagData,
			StreamSeq:  0,
			Payload:    payload,
		}); err != nil || n != len(payload) {
			t.Fatalf("HandleStreamData = %d, %v", n, err)
		}
		if got := budget.stats(); got.reserves != 1 || got.releases != 0 || got.bytes != uint64(recvInitialChunk) {
			t.Fatalf("after DATA stats = %+v, want 1 reserve, 0 releases, %d bytes", got, recvInitialChunk)
		}
		if err := h.mgr.FailSession(ref, nil); err != nil {
			t.Fatalf("FailSession: %v", err)
		}
		// The accepted prefix stays readable: a terminal session must not
		// truncate bytes the peer already delivered.
		if got := budget.stats(); got.releases != 0 || got.bytes != uint64(recvInitialChunk) {
			t.Fatalf("after FailSession stats = %+v, want the lease retained", got)
		}
		out, started := startRead(c)
		<-started
		requireData(t, out, payload)
		if got := budget.stats(); got.releases != 1 || got.bytes != 0 {
			t.Fatalf("after draining stats = %+v, want 1 release and 0 bytes", got)
		}
		out2, started2 := startRead(c)
		<-started2
		requireSessionLost(t, out2)
		if err := h.mgr.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if got := budget.stats(); got.releases != 1 || got.bytes != 0 || got.held != 0 {
			t.Fatalf("after Close stats = %+v, want exactly one release and nothing held", got)
		}
	})
	t.Run("undrained prefix is returned by Manager.Close", func(t *testing.T) {
		budget := newFakeBudget(1 << 20)
		h := newHarness(t, func(cfg *Config) { cfg.BufferBudget = budget })
		ref := failRef(0x31, 7, 3)
		id := testCircuitID(0x6E)
		h.openReadyOn(t, id, ref)
		if n, err := h.mgr.HandleStreamData(StreamDataMessage{
			FromNodeID: h.peer,
			CircuitID:  id,
			Flags:      FlagData,
			StreamSeq:  0,
			Payload:    []byte("abc"),
		}); err != nil || n != 3 {
			t.Fatalf("HandleStreamData = %d, %v", n, err)
		}
		if err := h.mgr.FailSession(ref, nil); err != nil {
			t.Fatalf("FailSession: %v", err)
		}
		if got := budget.stats(); got.releases != 0 || got.bytes != uint64(recvInitialChunk) {
			t.Fatalf("after FailSession stats = %+v, want the lease retained", got)
		}
		if err := h.mgr.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if got := budget.stats(); got.reserves != 1 || got.releases != 1 || got.bytes != 0 || got.held != 0 {
			t.Fatalf("after Close stats = %+v, want exactly one release and nothing held", got)
		}
	})
}

func TestFailSessionValidationAndIdempotency(t *testing.T) {
	h := newHarness(t, nil)
	for _, ref := range []SessionRef{
		{},
		{ID: testSessionID(1)},
		{ID: testSessionID(1), PathID: 7},
		{ID: testSessionID(1), PathGeneration: 3},
	} {
		if err := h.mgr.FailSession(ref, nil); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("FailSession(%v) err = %v, want ErrInvalidSession", ref, err)
		}
	}
	h.mgr.mu.Lock()
	entries := len(h.mgr.failedSessions)
	h.mgr.mu.Unlock()
	if entries != 0 {
		t.Fatalf("invalid refs stored %d terminal entries, want 0", entries)
	}

	ref := failRef(0x31, 7, 3)
	if err := h.mgr.FailSession(failRef(0x35, 7, 3), nil); err != nil {
		t.Fatalf("FailSession with no circuits: %v", err)
	}
	c := h.openReadyOn(t, testCircuitID(0x6F), ref)
	if err := h.mgr.FailSession(ref, nil); err != nil {
		t.Fatalf("FailSession: %v", err)
	}
	first := c.Snapshot().Failure
	if err := h.mgr.FailSession(ref, errors.New("second cause")); err != nil {
		t.Fatalf("repeat FailSession: %v", err)
	}
	if got := c.Snapshot().Failure; got != first {
		t.Fatalf("terminal cause = %q, want the first cause %q", got, first)
	}
	if !errors.Is(c.Cause(), ErrSessionLost) {
		t.Fatalf("cause = %v, want ErrSessionLost", c.Cause())
	}

	// A caller-supplied cause is retained as diagnostics but the observable
	// terminal reason is always ErrSessionLost.
	ref2 := failRef(0x34, 8, 4)
	c2 := h.openReadyOn(t, testCircuitID(0x82), ref2)
	if err := h.mgr.FailSession(ref2, errors.New("transport gone")); err != nil {
		t.Fatalf("FailSession(ref2): %v", err)
	}
	if !errors.Is(c2.Cause(), ErrSessionLost) {
		t.Fatalf("cause = %v, want it to wrap ErrSessionLost", c2.Cause())
	}
	if !strings.Contains(c2.Cause().Error(), "transport gone") {
		t.Fatalf("cause %q lost the caller detail", c2.Cause().Error())
	}

	closed := newHarness(t, nil)
	if err := closed.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := closed.mgr.FailSession(failRef(0x31, 7, 3), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("FailSession after Close err = %v, want ErrClosed", err)
	}
}

func TestFailSessionConcurrentOpenNeverLeavesAUsableCircuit(t *testing.T) {
	h := newHarness(t, nil)
	ref := failRef(0x31, 7, 3)
	for i := 0; i < 20; i++ {
		id := testCircuitID(byte(0x90 + i))
		// Open and FailSession race on the manager lock: whether the failure
		// scan wins, the candidate check wins, or the Session is attached
		// between them, no usable Circuit may survive the failed reference.
		ch := h.openAsync(context.Background(), h.requestOn(id, ref))
		if err := h.mgr.FailSession(ref, nil); err != nil {
			t.Fatalf("FailSession: %v", err)
		}
		_ = mustRecv(t, ch)
		for _, cs := range h.mgr.Snapshot().Circuits {
			if cs.Session == ref && !cs.State.Finished() {
				t.Fatalf("iteration %d left usable circuit %s in %s", i, cs.Key, cs.State)
			}
		}
		// Expire the window so the next iteration starts from a clean table.
		h.clock.Advance(DefaultTombstoneTTL + time.Second)
		h.mgr.Expire()
	}
}

func TestFailSessionFenceRefusesInboundAsResourceNotLost(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.Limits = Limits{MaxTombstones: 1} })
	stored := failRef(0x31, 7, 3)
	if err := h.mgr.FailSession(stored, nil); err != nil {
		t.Fatalf("FailSession(stored): %v", err)
	}
	// The second failure cannot be stored and arms the manager-wide fence.
	if err := h.mgr.FailSession(failRef(0x32, 7, 3), nil); err != nil {
		t.Fatalf("FailSession(overflow): %v", err)
	}
	h.mgr.mu.Lock()
	fenced := !h.mgr.sessionFence.IsZero()
	h.mgr.mu.Unlock()
	if !fenced {
		t.Fatal("the overflowed registry did not arm the manager-wide session fence")
	}

	// A healthy Session under the fence: ordinary resource exhaustion, answered
	// over that same healthy Session with REFUSED(RESOURCE). It must not be
	// reported as a lost Session, or the frame handler would tear down the
	// shared Link.
	healthy := failRef(0x40, 5, 2)
	before := h.mgr.Snapshot().Counters
	frames := h.egress.count()
	msg := OpenMessage{
		FromNodeID:          h.peer,
		CircuitID:           testCircuitID(0xA1),
		Attempt:             0,
		TargetPort:          8080,
		PathID:              healthy.PathID,
		PathGeneration:      healthy.PathGeneration,
		RouteViewVersion:    11,
		PathDigest:          [32]byte{0x01, 0x02},
		SourceInitialWindow: InitialWindow,
		RequestID:           1,
		Session:             healthy,
	}
	res, err := h.mgr.HandleOpen(msg)
	if err != nil {
		t.Fatalf("HandleOpen under the fence returned %v; a healthy Session must be refused as a normal result, not a Link failure", err)
	}
	if errors.Is(err, ErrSessionLost) || errors.Is(err, ErrSessionRefFailed) {
		t.Fatalf("HandleOpen under the fence mislabelled a healthy Session: %v", err)
	}
	if res.Status != StatusRefused || res.Created {
		t.Fatalf("HandleOpen = %+v, want a REFUSED result that created nothing", res)
	}
	if got := h.egress.count(); got != frames+1 {
		t.Fatalf("egress frames = %d, want exactly one more (the READY refusal)", got-frames)
	}
	refusal := h.egress.at(frames)
	if refusal.sub.Kind != KindControlRPC {
		t.Fatalf("refusal kind = %v, want KindControlRPC", refusal.sub.Kind)
	}
	if refusal.sub.Session != healthy || refusal.sub.Direction != DirectionTargetToSource {
		t.Fatalf("refusal went to %v/%v, want the healthy Session target->source", refusal.sub.Session, refusal.sub.Direction)
	}
	decoded, derr := DecodeReadyMessage(plain(refusal.sub.Body))
	if derr != nil {
		t.Fatalf("DecodeReadyMessage: %v", derr)
	}
	if decoded.Status != StatusRefused || decoded.ErrorCode != ReadyErrorResource {
		t.Fatalf("READY = %s/%s, want Refused/Resource", decoded.Status, decoded.ErrorCode)
	}
	after := h.mgr.Snapshot().Counters
	if after.Refused != before.Refused+1 || after.Fenced != before.Fenced+1 {
		t.Fatalf("counters = %+v, want Refused and Fenced each +1 over %+v", after, before)
	}
	if cs := h.mgr.Snapshot().Circuits; len(cs) != 0 {
		t.Fatalf("the REFUSED Open created %d record(s), want none", len(cs))
	}

	// The exactly failed SessionRef still refuses locally with the dedicated
	// sentinel and keeps the wire silent.
	frames = h.egress.count()
	msg.CircuitID = testCircuitID(0xA2)
	msg.Session = stored
	msg.PathID, msg.PathGeneration = stored.PathID, stored.PathGeneration
	if _, err := h.mgr.HandleOpen(msg); !errors.Is(err, ErrSessionLost) || !errors.Is(err, ErrSessionRefFailed) {
		t.Fatalf("HandleOpen on the exact failed ref err = %v, want ErrSessionLost+ErrSessionRefFailed", err)
	}
	if got := h.egress.count(); got != frames {
		t.Fatalf("HandleOpen sent %d frame(s) over an aborted Session", got-frames)
	}
}

func TestFailSessionRegistryIsBoundedAndReaped(t *testing.T) {
	h := newHarness(t, func(cfg *Config) { cfg.Limits = Limits{MaxTombstones: 4} })
	refs := make([]SessionRef, 0, 6)
	for i := 0; i < 6; i++ {
		ref := failRef(byte(0x40+i), 7, 3)
		refs = append(refs, ref)
		if err := h.mgr.FailSession(ref, nil); err != nil {
			t.Fatalf("FailSession(%d): %v", i, err)
		}
	}
	h.mgr.mu.Lock()
	held, fenced := len(h.mgr.failedSessions), !h.mgr.sessionFence.IsZero()
	h.mgr.mu.Unlock()
	if held != 4 {
		t.Fatalf("terminal SessionRef registry holds %d entries, want the bound 4", held)
	}
	if !fenced {
		t.Fatal("an overflowed registry must arm the manager-wide session fence, not evict a live entry")
	}
	// Fail closed: while the fence is armed even a ref that was never failed is
	// refused — but as ordinary local resource exhaustion, never as a lost
	// Session, because the Session carrying the Open is healthy.
	fresh := failRef(0x50, 7, 3)
	_, err := h.mgr.Open(context.Background(), h.requestOn(testCircuitID(0x80), fresh))
	if !errors.Is(err, ErrResource) {
		t.Fatalf("Open on a fresh ref under the session fence err = %v, want ErrResource", err)
	}
	if errors.Is(err, ErrSessionRefFailed) {
		t.Fatalf("a manager-wide fence must not be reported as a failed SessionRef: %v", err)
	}
	if _, err := h.mgr.Open(context.Background(), h.requestOn(testCircuitID(0x7F), refs[5])); !errors.Is(err, ErrResource) {
		t.Fatalf("Open on an unstored failed ref err = %v, want ErrResource", err)
	}
	h.clock.Advance(DefaultTombstoneTTL + time.Second)
	h.mgr.Expire()
	h.mgr.mu.Lock()
	held, fenced = len(h.mgr.failedSessions), !h.mgr.sessionFence.IsZero()
	h.mgr.mu.Unlock()
	if held != 0 || fenced {
		t.Fatalf("after the TTL: %d entries, fenced=%v; want 0 and unfenced", held, fenced)
	}
	// A fresh ref is admissible again once the window has expired.
	ch := h.openAsync(context.Background(), h.requestOn(testCircuitID(0x81), fresh))
	waitSnapshot(t, h.mgr, h.mgr.LocalKey(testCircuitID(0x81)), StateOpenCommitted)
	_ = h.mgr.Close()
	_ = mustRecv(t, ch)
}

func TestFailSessionCloseRaceIsRaceFree(t *testing.T) {
	h := newHarness(t, nil)
	refs := []SessionRef{failRef(0x31, 7, 3), failRef(0x32, 7, 3)}
	circuits := make([]*Circuit, 0, 8)
	for i := 0; i < 8; i++ {
		circuits = append(circuits, h.openReadyOn(t, testCircuitID(byte(0x70+i)), refs[i%len(refs)]))
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, c := range circuits {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			buf := make([]byte, 8)
			for {
				if _, err := c.ReadData(context.Background(), buf); err != nil {
					return
				}
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = c.WriteData(context.Background(), []byte("x"))
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_ = h.mgr.FailSession(refs[0], nil)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_ = h.mgr.FailSession(refs[1], errors.New("transport gone"))
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, _ = h.mgr.Accept(ctx)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_ = h.mgr.Close()
	}()
	close(start)
	wg.Wait()
	for _, c := range circuits {
		if !c.State().Finished() {
			t.Fatalf("circuit %s state = %s after the race, want a finished state", c.Key(), c.State())
		}
	}
}
