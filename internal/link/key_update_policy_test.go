package link

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/wire"
)

// configureKeyUpdatePolicyPair installs the update configuration with an
// explicit built-in policy on both sides of an established Link.
func configureKeyUpdatePolicyPair(t *testing.T, pair controlPair, policy KeyUpdatePolicy) {
	t.Helper()
	if err := pair.a.ConfigureKeyUpdate(KeyUpdateConfig{
		Identity: pair.alice, PeerStatic: pair.ar.PeerStatic, PSK: pair.psk, Descriptor: pair.descriptor,
		TargetLinkID: pair.ar.LinkID, TargetLinkEpoch: pair.ar.LinkEpoch, LaneID: pair.ar.LaneID,
		PeerAdvertisedKeyUpdate: true, Policy: policy,
	}); err != nil {
		t.Fatalf("configure A: %v", err)
	}
	if err := pair.b.ConfigureKeyUpdate(KeyUpdateConfig{
		Identity: pair.bob, PeerStatic: pair.br.PeerStatic, PSK: pair.psk, Descriptor: pair.descriptor,
		TargetLinkID: pair.ar.LinkID, TargetLinkEpoch: pair.ar.LinkEpoch, LaneID: pair.ar.LaneID,
		PeerAdvertisedKeyUpdate: true, Policy: policy,
	}); err != nil {
		t.Fatalf("configure B: %v", err)
	}
}

// writeControlDrained writes one LINK_CTRL message from sender and reads it on
// receiver, so the two synchronous net.Pipe directions never deadlock.
func writeControlDrained(t *testing.T, sender, receiver *ProtectedControlIO, typ uint8, payload []byte) {
	t.Helper()
	written := make(chan error, 1)
	go func() { written <- sender.WriteControl(ControlMessage{Type: typ, Payload: payload}) }()
	if _, err := receiver.ReadControl(); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func writeRouteDrained(t *testing.T, sender, receiver *ProtectedControlIO, envelope, payload []byte) {
	t.Helper()
	written := make(chan error, 1)
	go func() { written <- sender.WriteRoute(envelope, payload, testHop) }()
	if _, err := receiver.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func writeEndToEndDrained(t *testing.T, sender, receiver *ProtectedControlIO, envelope, ciphertext []byte) {
	t.Helper()
	written := make(chan error, 1)
	go func() { written <- sender.WriteEndToEnd(envelope, ciphertext, testHop) }()
	if _, err := receiver.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

// wrongKeyControlProtector builds a structurally valid protector whose root is
// not this Link's TX root, so every frame it seals fails the peer's AEAD.
func wrongKeyControlProtector(t *testing.T, pair controlPair) *FrameProtector {
	t.Helper()
	root := pair.ar.TxRoot
	root[0] ^= 0x5a
	protector, err := NewFrameProtector(root, pair.descriptor, pair.ar.LinkID, [16]byte{}, SessionClassStream, pair.a.txDirection)
	if err != nil {
		t.Fatal(err)
	}
	return protector
}

// writeBadControlFrame sends one wrong-key LINK_CTRL frame and reads it on B.
// It returns the read error so the caller can assert the rejection shape.
func writeBadControlFrame(t *testing.T, pair controlPair, protector *FrameProtector, counter uint64) error {
	t.Helper()
	frame := sealControl(t, protector, 1, bytes.Repeat([]byte{0x55}, 16), pair.b.rxGen, counter)
	written := sendRawFrame(pair.left, frame)
	_, err := pair.b.ReadMessage()
	if werr := <-written; werr != nil {
		t.Fatal(werr)
	}
	if err == nil {
		t.Fatal("wrong-key control frame was accepted")
	}
	return err
}

// writeBadRouteFrame sends one wrong-key ROUTE_CTRL frame and reads it on B.
func writeBadRouteFrame(t *testing.T, pair controlPair, protector *FrameProtector, counter uint64) error {
	t.Helper()
	payload := bytes.Repeat([]byte{0x66}, 32)
	envelope := routeEnvelope(wire.MessageTypeSessionCtrl, testSessionID(0x77), 7, 3, len(payload))
	frame := wire.Frame{Kind: wire.FrameKindRouteControl, HopHeader: makeHopHeader(7, 3, testHop), Envelope: envelope}
	sealed, err := protector.Seal(frame, payload, pair.b.rxGen, counter)
	if err != nil {
		t.Fatal(err)
	}
	written := sendRawFrame(pair.left, sealed)
	_, err = pair.b.ReadMessage()
	if werr := <-written; werr != nil {
		t.Fatal(werr)
	}
	if err == nil {
		t.Fatal("wrong-key route frame was accepted")
	}
	return err
}

// TestKeyUpdatePolicyBuiltInDefaults pins the coordinator-approved operational
// defaults and the headroom arithmetic derived from them. It makes no claim
// that these numbers are a cryptographic universal.
func TestKeyUpdatePolicyBuiltInDefaults(t *testing.T) {
	defaults := DefaultKeyUpdatePolicy()
	if defaults.SealLimit != 1<<32 || defaults.ByteLimit != 1<<48 ||
		defaults.AgeSeconds != 24*60*60 || defaults.FailedAuthLimit != 1024 {
		t.Fatalf("built-in defaults = %+v", defaults)
	}
	if got := resolveKeyUpdatePolicy(KeyUpdatePolicy{}); got != defaults {
		t.Fatalf("zero policy resolved to %+v; want %+v", got, defaults)
	}
	// A partially specified policy keeps the defaults for untouched fields.
	overridden := resolveKeyUpdatePolicy(KeyUpdatePolicy{SealLimit: 64})
	if overridden.SealLimit != 64 || overridden.ByteLimit != defaults.ByteLimit ||
		overridden.AgeSeconds != defaults.AgeSeconds || overridden.FailedAuthLimit != defaults.FailedAuthLimit {
		t.Fatalf("partial override = %+v", overridden)
	}
	// The soft trigger is derived as 7/8 of each listed hard limit.
	if got, want := keyUpdateSoftThreshold(defaults.SealLimit), uint64(1<<32)-(1<<32)/8; got != want {
		t.Fatalf("seal soft = %d; want %d", got, want)
	}
	if got, want := keyUpdateSoftThreshold(defaults.ByteLimit), uint64(1<<48)-(1<<48)/8; got != want {
		t.Fatalf("byte soft = %d; want %d", got, want)
	}
	if got, want := keyUpdateSoftThreshold(defaults.FailedAuthLimit), uint64(896); got != want {
		t.Fatalf("failed-auth soft = %d; want %d", got, want)
	}
	if got, want := keyUpdateSoftThresholdInt(defaults.AgeSeconds), int64(75600); got != want {
		t.Fatalf("age soft = %d; want %d", got, want)
	}
	// Saturation: a limit below the control reserve may not underflow.
	if got := satSubUint64(keyUpdateSoftThreshold(8), keyUpdateControlHandshakeReserve); got != 0 {
		t.Fatalf("saturated control soft = %d; want 0", got)
	}
	// The default policy is installed at Link construction; no caller has to
	// opt in to have usage accounted.
	pair := establishedControlPair(t)
	if got := pair.a.KeyUpdateUsageSnapshot().Limits; got != defaults {
		t.Fatalf("constructed Limits = %+v; want %+v", got, defaults)
	}
	if got := pair.a.KeyUpdateUsageSnapshot(); got.Control.Seals != 0 || got.Route.Seals != 0 || got.Stream.Seals != 0 {
		t.Fatalf("fresh Link already counted usage: %+v", got)
	}
}

// TestKeyUsageCountersSplitByDomainAndPlaintext proves each key domain counts
// its own successful seals and sealed plaintext bytes, and that receiving a
// frame is not a local seal.
func TestKeyUsageCountersSplitByDomainAndPlaintext(t *testing.T) {
	pair := establishedControlPair(t)
	sessionID := testSessionID(0x31)
	for _, side := range []*ProtectedControlIO{pair.a, pair.b} {
		if err := side.AdmitSession(sessionID, SessionClassStream); err != nil {
			t.Fatal(err)
		}
	}
	ping := bytes.Repeat([]byte{0x11}, 16)
	writeControlDrained(t, pair.a, pair.b, 1, ping)

	routePayload := bytes.Repeat([]byte{0x22}, 48)
	writeRouteDrained(t, pair.a, pair.b,
		routeEnvelope(wire.MessageTypeSessionCtrl, sessionID, 7, 3, len(routePayload)), routePayload)

	ciphertext := bytes.Repeat([]byte{0x33}, 64)
	inner := len(ciphertext) - e2eTagSize
	writeEndToEndDrained(t, pair.a, pair.b,
		newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 7, 3, inner), ciphertext)

	status := pair.a.KeyUpdateUsageSnapshot()
	// Control plaintext includes the leading ControlType byte.
	if status.Control.Seals != 1 || status.Control.PlaintextBytes != uint64(len(ping)+1) {
		t.Fatalf("control usage = %+v; want 1 seal / %d bytes", status.Control, len(ping)+1)
	}
	if status.Route.Seals != 1 || status.Route.PlaintextBytes != uint64(len(routePayload)) {
		t.Fatalf("route usage = %+v; want 1 seal / %d bytes", status.Route, len(routePayload))
	}
	if status.Stream.Seals != 1 || status.Stream.PlaintextBytes != uint64(len(ciphertext)) {
		t.Fatalf("stream usage = %+v; want 1 seal / %d bytes", status.Stream, len(ciphertext))
	}
	if status.FailedAuth != 0 {
		t.Fatalf("successful frames counted as failed auth: %d", status.FailedAuth)
	}
	// Direction split: the receiver verified but never sealed.
	if got := pair.b.KeyUpdateUsageSnapshot(); got.Control.Seals != 0 || got.Route.Seals != 0 || got.Stream.Seals != 0 {
		t.Fatalf("receiver counted local seals: %+v", got)
	}
}

// TestKeyUsageCountersNeverResetAndBaselineAdvances proves a completed update
// keeps the lifetime counters (it does not clear them) while advancing the
// policy baseline the trigger measures from.
func TestKeyUsageCountersNeverResetAndBaselineAdvances(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{SealLimit: 4096})
	for i := 0; i < 4; i++ {
		writeControlDrained(t, pair.a, pair.b, 1, bytes.Repeat([]byte{0x44}, 16))
	}
	before := pair.a.KeyUpdateUsageSnapshot()
	if before.Control.Seals != 4 {
		t.Fatalf("pre-update seals = %d; want 4", before.Control.Seals)
	}
	if before.Soft != 0 || before.NeedsUpdate {
		t.Fatalf("policy asked for an update before any threshold: %+v", before)
	}
	if before.RemainingSeals != 4096-4 {
		t.Fatalf("pre-update headroom = %d; want %d", before.RemainingSeals, 4096-4)
	}

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
		t.Fatal(err)
	}
	if err := driverB.failure(); err != nil {
		t.Fatal(err)
	}
	if pair.a.KeyUpdateStatus().State != KuStateStable {
		t.Fatalf("A state = %s; want Stable", pair.a.KeyUpdateStatus().State)
	}

	after := pair.a.KeyUpdateUsageSnapshot()
	if after.Control.Seals < before.Control.Seals || after.Control.Seals == 0 {
		t.Fatalf("lifetime counters were reset: before %d after %d", before.Control.Seals, after.Control.Seals)
	}
	if after.Soft != 0 || after.NeedsUpdate {
		t.Fatalf("policy still asks for an update after a completed one: %+v", after)
	}
	if after.RemainingSeals != 4096 {
		t.Fatalf("baseline did not advance to a fresh budget: remaining %d; want 4096", after.RemainingSeals)
	}
	if after.StableGeneration == 0 {
		t.Fatal("the completed generation was not recorded as the baseline")
	}
}

// TestKeyUpdatePolicyAgeMonotonicAndTrigger proves age is measured from the
// stable generation, uses the default 24h limit, triggers at its 7/8 soft
// point, fails hard at the limit, and can never move backwards.
func TestKeyUpdatePolicyAgeMonotonicAndTrigger(t *testing.T) {
	pair := establishedControlPair(t)
	var mu sync.Mutex
	now := time.Now()
	pair.a.usage.setClock(func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	})
	pair.a.usage.noteStable(0)
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	advance(20 * time.Hour)
	status := pair.a.KeyUpdateUsageSnapshot()
	if status.AgeSeconds != int64(20*time.Hour/time.Second) {
		t.Fatalf("age = %d; want %d", status.AgeSeconds, int64(20*time.Hour/time.Second))
	}
	if status.Soft&KeyUpdateTriggerAge != 0 {
		t.Fatalf("age triggered below the soft threshold: %+v", status)
	}

	advance(time.Hour) // 21h == 7/8 of 24h
	status = pair.a.KeyUpdateUsageSnapshot()
	if status.Soft&KeyUpdateTriggerAge == 0 || !status.NeedsUpdate {
		t.Fatalf("age did not trigger at the soft threshold: %+v", status)
	}
	if status.Hard&KeyUpdateTriggerAge != 0 {
		t.Fatalf("age reported hard at the soft threshold: %+v", status)
	}
	if status.RemainingAgeSeconds != int64(3*time.Hour/time.Second) {
		t.Fatalf("age headroom = %d; want %d", status.RemainingAgeSeconds, int64(3*time.Hour/time.Second))
	}

	advance(3 * time.Hour) // 24h == hard
	status = pair.a.KeyUpdateUsageSnapshot()
	if status.Hard&KeyUpdateTriggerAge == 0 || status.RemainingAgeSeconds != 0 {
		t.Fatalf("age did not reach the hard boundary: %+v", status)
	}
	previous := status.AgeSeconds

	// A backwards wall-clock jump must not lower the reported age.
	advance(-time.Hour)
	if got := pair.a.KeyUpdateUsageSnapshot().AgeSeconds; got < previous {
		t.Fatalf("age moved backwards: %d -> %d", previous, got)
	}
}

// TestKeyUpdateFailedAuthAggregateSoftAndHard proves the rejected-auth counter
// aggregates across domains, triggers at its 7/8 soft point and fails the Link
// closed at the hard boundary.
func TestKeyUpdateFailedAuthAggregateSoftAndHard(t *testing.T) {
	t.Run("control-only", func(t *testing.T) {
		pair := establishedControlPair(t)
		configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{FailedAuthLimit: 8})
		protector := wrongKeyControlProtector(t, pair)
		for i := 0; i < 7; i++ {
			if err := writeBadControlFrame(t, pair, protector, uint64(100+i)); errors.Is(err, ErrKeyUpdateRequired) {
				t.Fatalf("failure %d reported ErrKeyUpdateRequired before the hard boundary", i)
			}
		}
		status := pair.b.KeyUpdateUsageSnapshot()
		if status.FailedAuth != 7 {
			t.Fatalf("aggregate failed auth = %d; want 7", status.FailedAuth)
		}
		if status.Soft&KeyUpdateTriggerFailedAuth == 0 || status.Hard&KeyUpdateTriggerFailedAuth != 0 {
			t.Fatalf("failed-auth boundary state = %+v at the soft threshold", status)
		}
		if !status.NeedsUpdate {
			t.Fatal("soft failed-auth crossing did not ask for an update")
		}
		if pair.b.terminal.Load() {
			t.Fatal("the soft boundary failed the Link closed")
		}
		// The sender sealed nothing wrong, so its own counters stay clean.
		if sender := pair.a.KeyUpdateUsageSnapshot(); sender.FailedAuth != 0 || sender.Control.Seals != 0 {
			t.Fatalf("sender counters moved on rejected frames: %+v", sender)
		}

		if err := writeBadControlFrame(t, pair, protector, 200); err == nil {
			t.Fatal("8th wrong-key frame was accepted")
		}
		if !pair.b.terminal.Load() {
			t.Fatal("the hard failed-auth boundary did not fail the Link closed")
		}
		if got := pair.b.KeyUpdateUsageSnapshot(); got.Hard&KeyUpdateTriggerFailedAuth == 0 {
			t.Fatalf("hard failed-auth not reported: %+v", got)
		}
	})

	t.Run("aggregate-across-domains", func(t *testing.T) {
		pair := establishedControlPair(t)
		configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{FailedAuthLimit: 8})
		protector := wrongKeyControlProtector(t, pair)
		for i := 0; i < 4; i++ {
			if err := writeBadControlFrame(t, pair, protector, uint64(300+i)); err != nil && errors.Is(err, ErrKeyUpdateRequired) {
				t.Fatalf("control failure %d crossed hard early", i)
			}
		}
		for i := 0; i < 3; i++ {
			if err := writeBadRouteFrame(t, pair, protector, uint64(400+i)); errors.Is(err, ErrKeyUpdateRequired) {
				t.Fatalf("route failure %d crossed hard early", i)
			}
		}
		status := pair.b.KeyUpdateUsageSnapshot()
		if status.FailedAuth != 7 || status.Control.FailedAuth != 4 || status.Route.FailedAuth != 3 {
			t.Fatalf("per-domain failed auth = %+v; want control 4 route 3 aggregate 7", status)
		}
		if status.Soft&KeyUpdateTriggerFailedAuth == 0 {
			t.Fatalf("aggregate soft threshold not reached: %+v", status)
		}
		if err := writeBadRouteFrame(t, pair, protector, 500); err == nil {
			t.Fatal("8th wrong-key frame was accepted")
		}
		if !pair.b.terminal.Load() {
			t.Fatal("the aggregated hard boundary did not fail the Link closed")
		}
	})

	// The built-in (zero-policy) failed-auth limit is exercised at its actual
	// value: soft at 896 rejected authentications and hard at 1024.
	t.Run("default-limit-1024", func(t *testing.T) {
		pair := establishedControlPair(t)
		if got := pair.b.KeyUpdateUsageSnapshot().Limits.FailedAuthLimit; got != 1024 {
			t.Fatalf("constructed failed-auth limit = %d; want 1024", got)
		}
		protector := wrongKeyControlProtector(t, pair)
		for i := 0; i < 895; i++ {
			_ = writeBadControlFrame(t, pair, protector, uint64(1000+i))
		}
		if status := pair.b.KeyUpdateUsageSnapshot(); status.FailedAuth != 895 || status.Soft&KeyUpdateTriggerFailedAuth != 0 {
			t.Fatalf("just below the built-in soft threshold: %+v", status)
		}
		_ = writeBadControlFrame(t, pair, protector, 3000)
		if status := pair.b.KeyUpdateUsageSnapshot(); status.FailedAuth != 896 || status.Soft&KeyUpdateTriggerFailedAuth == 0 || status.Hard&KeyUpdateTriggerFailedAuth != 0 {
			t.Fatalf("built-in soft threshold state: %+v", status)
		}
		for i := 0; i < 127; i++ {
			_ = writeBadControlFrame(t, pair, protector, uint64(4000+i))
		}
		if status := pair.b.KeyUpdateUsageSnapshot(); status.FailedAuth != 1023 || status.Hard&KeyUpdateTriggerFailedAuth != 0 {
			t.Fatalf("just below the built-in hard threshold: %+v", status)
		}
		if pair.b.terminal.Load() {
			t.Fatal("the Link closed before the built-in hard threshold")
		}
		_ = writeBadControlFrame(t, pair, protector, 5000)
		if !pair.b.terminal.Load() {
			t.Fatal("the built-in 1024 hard threshold did not fail the Link closed")
		}
	})
}

// TestKeyUpdateNoAutomaticTriggerWithoutActionOwner proves nothing is started
// while no action sink is wired, and that wiring one makes the next safe point
// emit exactly one update attempt.
func TestKeyUpdateNoAutomaticTriggerWithoutActionOwner(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{SealLimit: 64})
	// Control soft = 64 - 64/8 - 16 = 40.
	for i := 0; i < 41; i++ {
		writeControlDrained(t, pair.a, pair.b, 1, bytes.Repeat([]byte{0x77}, 16))
	}
	status := pair.a.KeyUpdateUsageSnapshot()
	if status.Soft&KeyUpdateTriggerControl == 0 || !status.NeedsUpdate {
		t.Fatalf("policy did not reach the control soft threshold: %+v", status)
	}
	if status.Hard != 0 {
		t.Fatalf("policy crossed the hard boundary on tiny usage: %+v", status)
	}
	if got := pair.a.KeyUpdateStatus().State; got != KuStateIdle {
		t.Fatalf("state = %s; want Idle with no action owner", got)
	}
	if got := pair.a.KeyUpdateStatus().Usage.Requests; got != 0 {
		t.Fatalf("requests = %d; want 0 with no action owner", got)
	}
	if pair.a.KeyUpdateTriggerError() != nil {
		t.Fatal("a trigger error was recorded without any trigger")
	}
	if pair.a.txNext != 42 {
		t.Fatalf("txNext = %d; want 42 (no extra write was generated)", pair.a.txNext)
	}

	var mu sync.Mutex
	var emitted [][]KeyUpdateAction
	pair.a.SetKeyUpdateActionSink(func(actions []KeyUpdateAction) error {
		mu.Lock()
		emitted = append(emitted, actions)
		mu.Unlock()
		return nil
	})
	writeControlDrained(t, pair.a, pair.b, 1, bytes.Repeat([]byte{0x78}, 16))

	mu.Lock()
	calls := len(emitted)
	var first []KeyUpdateAction
	if calls > 0 {
		first = emitted[0]
	}
	mu.Unlock()
	if calls != 1 {
		t.Fatalf("sink calls = %d; want exactly 1", calls)
	}
	if len(first) == 0 || first[0].Kind != ActionSendUpdate || first[0].Phase != KeyUpdateXX1 {
		t.Fatalf("first automatic action = %+v; want one XX1 send", first)
	}
	if err := pair.a.KeyUpdateTriggerError(); err != nil {
		t.Fatalf("trigger error: %v", err)
	}
	if got := pair.a.KeyUpdateStatus().Usage.Requests; got != 1 {
		t.Fatalf("requests = %d; want 1", got)
	}
}

// TestKeyUpdateHardBoundaryFailsClosed proves a key domain at the hard boundary
// refuses another non-recovery key use before spending a nonce, that an
// arbitrary (never-prepared) 0x09 cannot bypass it, and that a 0x09 this Link
// actually prepared for its transaction is the recovery channel: it is permitted
// and consumes exactly one shared recovery permit.
func TestKeyUpdateHardBoundaryFailsClosed(t *testing.T) {
	pair := establishedControlPair(t)
	configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{SealLimit: 8})
	for i := 0; i < 8; i++ {
		writeControlDrained(t, pair.a, pair.b, 1, bytes.Repeat([]byte{0x88}, 16))
	}
	if status := pair.a.KeyUpdateUsageSnapshot(); status.Hard&KeyUpdateTriggerControl == 0 {
		t.Fatalf("hard control boundary not reported: %+v", status)
	}

	before := pair.a.txNext
	if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: bytes.Repeat([]byte{0x99}, 16)}); !errors.Is(err, ErrKeyUpdateRequired) {
		t.Fatalf("hard control write error = %v; want ErrKeyUpdateRequired", err)
	}
	if pair.a.txNext != before {
		t.Fatal("a refused write spent a nonce")
	}

	// An arbitrary 0x09 that this Link never prepared is NOT an unconditional
	// bypass: it is refused before a nonce and without spending a permit.
	body, err := EncodeKeyUpdate(KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateRequest, Lane: pair.ar.LaneID,
		TargetLinkID: pair.ar.LinkID, TargetLinkEpoch: pair.ar.LinkEpoch, UpdateSeq: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pair.a.WriteControl(ControlMessage{Type: ControlTypeKeyUpdate, Payload: body}); !errors.Is(err, ErrKeyUpdateRequired) {
		t.Fatalf("arbitrary 0x09 at the hard boundary = %v; want ErrKeyUpdateRequired", err)
	}
	if pair.a.txNext != before {
		t.Fatal("a refused arbitrary 0x09 spent a nonce")
	}
	if got := recoveryReserve(pair.a); got != 0 {
		t.Fatalf("a refused arbitrary 0x09 spent a permit: %d", got)
	}

	// The prepared 0x09 of the owned transaction is the recovery channel. Arming
	// is idempotent, so it cannot refresh the finite per-transaction budget.
	pair.a.armKeyUpdateRecoveryReserve()
	pair.a.armKeyUpdateRecoveryReserve()
	if got := recoveryReserve(pair.a); got != uint32(keyUpdateControlHandshakeReserve) {
		t.Fatalf("armed reserve = %d; want %d", got, keyUpdateControlHandshakeReserve)
	}
	xx1, err := pair.a.RequestKeyUpdate()
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if len(xx1) != 1 || xx1[0].Phase != KeyUpdateXX1 {
		t.Fatalf("request actions = %+v; want one XX1", xx1)
	}
	if got := recoveryReserve(pair.a); got != uint32(keyUpdateControlHandshakeReserve) {
		t.Fatalf("preparing XX1 spent a permit early: %d", got)
	}
	written := make(chan error, 1)
	go func() {
		written <- pair.a.WriteControl(ControlMessage{Type: ControlTypeKeyUpdate, Payload: xx1[0].Payload})
	}()
	if _, err := pair.b.ReadControl(); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatalf("prepared XX1 refused at the hard boundary: %v", err)
	}
	if got := recoveryReserve(pair.a); got != uint32(keyUpdateControlHandshakeReserve)-1 {
		t.Fatalf("prepared XX1 did not consume exactly one permit: %d", got)
	}
	// A same-tuple body this Link did not prepare is still refused, even with a
	// permit left.
	tampered := append([]byte(nil), xx1[0].Payload...)
	tampered[len(tampered)-1] ^= 0xff
	if err := pair.a.WriteControl(ControlMessage{Type: ControlTypeKeyUpdate, Payload: tampered}); !errors.Is(err, ErrKeyUpdateRequired) {
		t.Fatalf("tampered prepared body error = %v; want ErrKeyUpdateRequired", err)
	}
	if got := recoveryReserve(pair.a); got != uint32(keyUpdateControlHandshakeReserve)-1 {
		t.Fatalf("a refused tampered body spent a permit: %d", got)
	}
}

// keyUpdateHookDriver is the runtime shape built only from the new driver
// hooks: one reader per Link calls HandleKeyUpdateControl, one shared writer
// calls ApplyAndCompleteKeyUpdate.
type keyUpdateHookDriver struct {
	io       *ProtectedControlIO
	actions  chan KeyUpdateAction
	quit     chan struct{}
	quitOnce sync.Once
	mu       sync.Mutex
	seen     []ProtectedMessage
	err      error
}

func newKeyUpdateHookDriver(io *ProtectedControlIO) *keyUpdateHookDriver {
	return &keyUpdateHookDriver{io: io, actions: make(chan KeyUpdateAction, testKeyUpdateQueueCapacity), quit: make(chan struct{})}
}

func (d *keyUpdateHookDriver) start(t *testing.T) {
	t.Helper()
	go d.writeLoop(t)
	go d.readLoop(t)
}

// stop ends the driver without closing the action channel, so a stop can never
// race a reader that is still delivering a follow-up action.
func (d *keyUpdateHookDriver) stop() { d.quitOnce.Do(func() { close(d.quit) }) }

func (d *keyUpdateHookDriver) enqueue(action KeyUpdateAction) bool {
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

func (d *keyUpdateHookDriver) writeLoop(t *testing.T) {
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
		follow, err := d.io.ApplyAndCompleteKeyUpdate(action)
		for _, next := range follow {
			if !d.enqueue(next) {
				return
			}
		}
		if errors.Is(err, ErrKeyUpdateAbort) {
			continue
		}
		if err != nil {
			d.fail(err)
			return
		}
	}
}

func (d *keyUpdateHookDriver) readLoop(t *testing.T) {
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
			actions, handled, err := d.io.HandleKeyUpdateControl(ControlMessage{Type: ControlTypeKeyUpdate, Payload: message.Payload[1:]})
			if err != nil {
				d.fail(err)
				return
			}
			if !handled {
				continue
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

func (d *keyUpdateHookDriver) fail(err error) {
	d.mu.Lock()
	if d.err == nil {
		d.err = err
	}
	d.mu.Unlock()
}

func (d *keyUpdateHookDriver) failure() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

// awaitKind returns the first delivered frame of the wanted kind, ignoring the
// other frames the same reader observed.
func awaitKind(t *testing.T, driver *keyUpdateHookDriver, kind wire.FrameKind, timeout time.Duration) ProtectedMessage {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		driver.mu.Lock()
		for index, message := range driver.seen {
			if message.Kind == kind {
				driver.seen = append(driver.seen[:index], driver.seen[index+1:]...)
				driver.mu.Unlock()
				return message
			}
		}
		driver.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("frame kind 0x%02x was not delivered", uint8(kind))
	return ProtectedMessage{}
}

// TestKeyUpdateAutomaticTriggerLongFlowOverNetPipe is the production-shaped
// end-to-end driver test: a real net.Pipe Link runs long enough to cross a
// configured tiny seal threshold, the built-in policy emits the update actions
// through the action sink, the transaction completes to Stable over the same
// physical stream, and encrypted traffic keeps flowing afterwards.
func TestKeyUpdateAutomaticTriggerLongFlowOverNetPipe(t *testing.T) {
	pair := establishedControlPair(t)
	const sealLimit = 128
	configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{SealLimit: sealLimit})
	sessionID := testSessionID(0x51)
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

	var triggerMu sync.Mutex
	triggers := 0
	pair.a.SetKeyUpdateActionSink(func(actions []KeyUpdateAction) error {
		triggerMu.Lock()
		triggers++
		triggerMu.Unlock()
		for _, action := range actions {
			driverA.actions <- action
		}
		return nil
	})

	// Control soft = 128 - 128/8 - 16 = 96. The 96th successful control seal is
	// the safe point that starts the update automatically. The hook drivers are
	// the only readers, so each blocking write is drained by driverB.
	for i := 0; i < 96; i++ {
		if err := pair.a.WriteControl(ControlMessage{Type: 1, Payload: bytes.Repeat([]byte{0xa5}, 16)}); err != nil {
			t.Fatalf("control write %d: %v", i, err)
		}
	}
	if status := pair.a.KeyUpdateUsageSnapshot(); status.Soft&KeyUpdateTriggerControl == 0 {
		t.Fatalf("control soft threshold not reached at the configured tiny limit: %+v", status)
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
	triggerMu.Lock()
	automatic := triggers
	triggerMu.Unlock()
	if automatic != 1 {
		t.Fatalf("automatic trigger count = %d; want exactly 1", automatic)
	}
	if err := pair.a.KeyUpdateTriggerError(); err != nil {
		t.Fatalf("automatic trigger error: %v", err)
	}
	if status := pair.a.KeyUpdateUsageSnapshot(); status.Soft != 0 {
		t.Fatalf("policy still asks for an update after Stable: %+v", status)
	}

	// The encrypted path continues over the same physical stream after Stable.
	ciphertext := bytes.Repeat([]byte{0x6a}, 32)
	inner := len(ciphertext) - e2eTagSize
	envelope := newEndToEndEnvelope(sessionID, wire.MessageTypeStreamData, 1, 1, 4, 2, inner)
	written := make(chan error, 1)
	go func() { written <- pair.a.WriteEndToEnd(envelope, ciphertext, testHop) }()
	delivered := awaitKind(t, driverB, wire.FrameKindEndToEnd, 3*time.Second)
	if err := <-written; err != nil {
		t.Fatalf("E2E write after Stable: %v", err)
	}
	if len(delivered.Payload) != len(ciphertext) {
		t.Fatalf("E2E payload after Stable = %d bytes; want %d", len(delivered.Payload), len(ciphertext))
	}
	if err := driverA.failure(); err != nil {
		t.Fatalf("driver A after Stable: %v", err)
	}
	if err := driverB.failure(); err != nil {
		t.Fatalf("driver B after Stable: %v", err)
	}
}

// TestKeyUpdateTriggerRearmsWhenEngineInstalledLate covers the production
// ordering hazard: the policy may cross its soft threshold before the update
// engine or the action sink exists. A failed attempt is recorded, not retried
// forever, and installing the engine re-arms exactly one further attempt.
func TestKeyUpdateTriggerRearmsWhenEngineInstalledLate(t *testing.T) {
	pair := establishedControlPair(t)
	pair.a.usage.setPolicy(KeyUpdatePolicy{SealLimit: 64})
	for i := 0; i < 41; i++ {
		writeControlDrained(t, pair.a, pair.b, 1, bytes.Repeat([]byte{0xab}, 16))
	}
	if !pair.a.NeedsKeyUpdate() {
		t.Fatal("policy did not cross the control soft threshold")
	}

	var mu sync.Mutex
	emitted := 0
	pair.a.SetKeyUpdateActionSink(func([]KeyUpdateAction) error {
		mu.Lock()
		emitted++
		mu.Unlock()
		return nil
	})
	// The sink exists but no engine does: the attempt fails and is recorded.
	writeControlDrained(t, pair.a, pair.b, 1, bytes.Repeat([]byte{0xac}, 16))
	if err := pair.a.KeyUpdateTriggerError(); err == nil {
		t.Fatal("a trigger attempt without an engine recorded no error")
	}
	mu.Lock()
	calls := emitted
	mu.Unlock()
	if calls != 0 {
		t.Fatalf("sink called %d times without an engine", calls)
	}

	// Installing the engine re-arms; the next safe point emits exactly once.
	configureKeyUpdatePolicyPair(t, pair, KeyUpdatePolicy{SealLimit: 64})
	writeControlDrained(t, pair.a, pair.b, 1, bytes.Repeat([]byte{0xad}, 16))
	mu.Lock()
	calls = emitted
	mu.Unlock()
	if calls != 1 {
		t.Fatalf("sink calls after the late engine install = %d; want 1", calls)
	}
	if err := pair.a.KeyUpdateTriggerError(); err != nil {
		t.Fatalf("trigger error after re-arm: %v", err)
	}
}

// TestKeyUpdateHookIgnoresOtherControlTypes proves the reader hook is a single
// branch: any control type other than 0x09 is reported as not handled.
func TestKeyUpdateHookIgnoresOtherControlTypes(t *testing.T) {
	pair := establishedControlPair(t)
	actions, handled, err := pair.a.HandleKeyUpdateControl(ControlMessage{Type: 1, Payload: make([]byte, 16)})
	if handled || err != nil || actions != nil {
		t.Fatalf("PING through the key-update hook: handled=%v actions=%v err=%v", handled, actions, err)
	}
}
