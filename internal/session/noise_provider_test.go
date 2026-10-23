package session

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/security"
)

// ---- shared crypto test helpers (names are prefixed to avoid the helpers in
// session_test.go) ----

func cryptoTestPolicy() ProviderPolicy {
	return ProviderPolicy{PendingMax: 8, PendingTTL: time.Minute}
}

func cryptoTestContext(t *testing.T) security.NetworkContext {
	t.Helper()
	nc, err := security.NewNetworkContext("simpletier-crypto-test", "10.20.0.0/24")
	if err != nil {
		t.Fatalf("network context: %v", err)
	}
	return nc
}

func cryptoTestIdentity(t *testing.T) security.Identity {
	t.Helper()
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return identity
}

func cryptoTestNodeID(seed byte) [16]byte {
	var out [16]byte
	full := pattern32(seed)
	copy(out[:], full[:16])
	return out
}

func cryptoTestKey(contextID [32]byte, src, dst [16]byte) Key {
	return Key{
		ContextID:      contextID,
		SrcNodeID:      src,
		DstNodeID:      dst,
		PathID:         0x0102030405060708,
		PathGeneration: 0x0a0b0c0d,
		Class:          SessionClassStream,
		Lane:           LaneStream,
	}
}

// cryptoTestRebind returns params for the same binding scope but a new
// SessionID/attempt/epoch, with the canonical 102-byte PrologueBinding rebuilt
// so the provider's full-value prologue check still passes.
func cryptoTestRebind(t *testing.T, params HandshakeParams, id SessionID, attempt, epoch uint32) HandshakeParams {
	t.Helper()
	src, dst := params.LocalNodeID, params.PeerNodeID
	if !params.Initiator {
		src, dst = params.PeerNodeID, params.LocalNodeID
	}
	key := Key{
		ContextID:      params.ContextID,
		SrcNodeID:      src,
		DstNodeID:      dst,
		PathID:         params.PathID,
		PathGeneration: params.PathGeneration,
		Class:          params.Class,
		Lane:           params.DataLaneID,
	}
	binding, err := PrologueBinding(key, id, attempt, epoch)
	if err != nil {
		t.Fatalf("rebind prologue: %v", err)
	}
	params.SessionID = id
	params.Attempt = attempt
	params.TargetEpoch = epoch
	params.Prologue = binding
	return params
}

func cryptoTestParams(t *testing.T, key Key, id SessionID, attempt, epoch uint32, psk [32]byte, local security.Identity, peerStatic [32]byte, initiator bool) HandshakeParams {
	t.Helper()
	binding, err := PrologueBinding(key, id, attempt, epoch)
	if err != nil {
		t.Fatalf("prologue binding: %v", err)
	}
	localNode, peerNode := key.SrcNodeID, key.DstNodeID
	if !initiator {
		localNode, peerNode = key.DstNodeID, key.SrcNodeID
	}
	return HandshakeParams{
		ContextID:      key.ContextID,
		Prologue:       binding,
		PSK:            psk,
		LocalNodeID:    localNode,
		PeerNodeID:     peerNode,
		LocalStatic:    local.PublicKey,
		PeerStatic:     peerStatic,
		SessionID:      id,
		Class:          key.Class,
		DataLaneID:     key.Lane,
		Attempt:        attempt,
		TargetEpoch:    epoch,
		PathID:         key.PathID,
		PathGeneration: key.PathGeneration,
		Initiator:      initiator,
	}
}

// testHKDF is an independent HKDF-SHA256 (extract then expand) used only by
// tests, so a KDF vector does not reuse the production helper.
func testHKDF(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)
	var okm, block []byte
	for counter := byte(1); len(okm) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(block)
		mac.Write(info)
		mac.Write([]byte{counter})
		block = mac.Sum(nil)
		okm = append(okm, block...)
	}
	return okm[:length]
}

func testLP32(dst, value []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}

func TestSessionRootKDFIndependentVector(t *testing.T) {
	splitI2R := pattern32(0x10)
	splitR2I := pattern32(0x90)
	descriptor := []byte("simpletier-v1/network-context-independent-vector")
	binding := byteRange(0x40, 48)
	psk := pattern32(0x77)

	gotI2R, err := deriveSessionRoot(splitI2R, DirectionInitiatorToResponder, descriptor, binding, psk[:])
	if err != nil {
		t.Fatalf("derive i2r: %v", err)
	}
	gotR2I, err := deriveSessionRoot(splitR2I, DirectionResponderToInitiator, descriptor, binding, psk[:])
	if err != nil {
		t.Fatalf("derive r2i: %v", err)
	}

	// Independent construction of the exact info serialization from the
	// documented contract, then an independent HKDF implementation.
	wantI2RInfo := append([]byte("simpletier/v2/session-root/i2r"), 0)
	wantI2RInfo = testLP32(wantI2RInfo, descriptor)
	wantI2RInfo = testLP32(wantI2RInfo, binding)
	wantI2R := testHKDF(splitI2R[:], psk[:], wantI2RInfo, 32)
	wantR2IInfo := append([]byte("simpletier/v2/session-root/r2i"), 0)
	wantR2IInfo = testLP32(wantR2IInfo, descriptor)
	wantR2IInfo = testLP32(wantR2IInfo, binding)
	wantR2I := testHKDF(splitR2I[:], psk[:], wantR2IInfo, 32)

	if !bytes.Equal(gotI2R[:], wantI2R) {
		t.Fatalf("i2r root mismatch:\n got %x\nwant %x", gotI2R[:], wantI2R)
	}
	if !bytes.Equal(gotR2I[:], wantR2I) {
		t.Fatalf("r2i root mismatch:\n got %x\nwant %x", gotR2I[:], wantR2I)
	}
	if gotI2R == gotR2I {
		t.Fatal("distinct split keys produced the same directional root")
	}

	// The split keys must never be concatenated as HKDF IKM. Show that a
	// concatenation-based derivation yields something else.
	concat := append(append([]byte(nil), splitI2R[:]...), splitR2I[:]...)
	concatRoot := testHKDF(concat, psk[:], wantI2RInfo, 32)
	if bytes.Equal(concatRoot, wantI2R) {
		t.Fatal("concatenated split keys reproduced the directional root")
	}
}

func TestSessionRootEncodeParseAndDirection(t *testing.T) {
	root := SessionRoot{I2R: pattern32(0x01), R2I: pattern32(0x81)}
	encoded := root.Encode()
	if len(encoded) != SessionRootSize {
		t.Fatalf("encoded root is %d bytes, want %d", len(encoded), SessionRootSize)
	}
	parsed, err := ParseSessionRoot(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed != root {
		t.Fatalf("round trip mismatch: %+v vs %+v", parsed, root)
	}
	if parsed.Direction(DirectionInitiatorToResponder) != root.I2R {
		t.Fatal("i2r accessor mismatch")
	}
	if parsed.Direction(DirectionResponderToInitiator) != root.R2I {
		t.Fatal("r2i accessor mismatch")
	}
	if _, err := ParseSessionRoot(encoded[:63]); err == nil {
		t.Fatal("short root accepted")
	}
	if !(SessionRoot{}).IsZero() {
		t.Fatal("zero root not reported as zero")
	}
}

func TestDirectionForRoleIsUnambiguous(t *testing.T) {
	cases := []struct {
		role    Role
		sending bool
		want    Direction
	}{
		{RoleInitiator, true, DirectionInitiatorToResponder},
		{RoleInitiator, false, DirectionResponderToInitiator},
		{RoleResponder, true, DirectionResponderToInitiator},
		{RoleResponder, false, DirectionInitiatorToResponder},
	}
	for _, tc := range cases {
		if got := DirectionForRole(tc.role, tc.sending); got != tc.want {
			t.Fatalf("DirectionForRole(%s, %v) = %s, want %s", tc.role, tc.sending, got, tc.want)
		}
	}
	if DirectionInitiatorToResponder.String() != "i2r" || DirectionResponderToInitiator.String() != "r2i" {
		t.Fatal("direction strings are not canonical")
	}
	if DirectionInitiatorToResponder.Opposite() != DirectionResponderToInitiator {
		t.Fatal("opposite direction mismatch")
	}
}

// cryptoTestPair runs a real Noise IK handshake between two generated
// identities using two providers, and returns both canonical roots.
func cryptoTestPair(t *testing.T, nc security.NetworkContext, psk [32]byte) (SessionRoot, SessionRoot) {
	t.Helper()
	ctx := context.Background()
	idA := cryptoTestIdentity(t)
	idB := cryptoTestIdentity(t)
	pi, err := NewNoiseProvider(idA, nc, cryptoTestPolicy())
	if err != nil {
		t.Fatalf("provider A: %v", err)
	}
	pr, err := NewNoiseProvider(idB, nc, cryptoTestPolicy())
	if err != nil {
		t.Fatalf("provider B: %v", err)
	}
	key := cryptoTestKey(nc.ID(), idA.NodeID, idB.NodeID)
	id := sessionID(0x40)
	pI := cryptoTestParams(t, key, id, FirstAttempt, FirstTargetEpoch, psk, idA, idB.PublicKey, true)
	pR := cryptoTestParams(t, key, id, FirstAttempt, FirstTargetEpoch, psk, idB, idA.PublicKey, false)

	msg1, err := pi.Initiate(ctx, pI)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	msg2, rootR, err := pr.Respond(ctx, pR, msg1)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	rootIBytes, err := pi.Finish(ctx, pI, msg2)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	rootI, err := ParseSessionRoot(rootIBytes)
	if err != nil {
		t.Fatalf("parse initiator root: %v", err)
	}
	rootResponder, err := ParseSessionRoot(rootR)
	if err != nil {
		t.Fatalf("parse responder root: %v", err)
	}
	return rootI, rootResponder
}

func TestNoiseProviderRealHandshakeRootsMatch(t *testing.T) {
	nc := cryptoTestContext(t)
	psk := pattern32(0x55)
	rootI, rootR := cryptoTestPair(t, nc, psk)
	if rootI != rootR {
		t.Fatalf("roots diverge:\n initiator %x\n responder %x", rootI.Encode(), rootR.Encode())
	}
	if rootI.IsZero() {
		t.Fatal("zero root")
	}
}

func TestNoiseProviderRejectsWrongBindings(t *testing.T) {
	ctx := context.Background()
	nc := cryptoTestContext(t)
	psk := pattern32(0x55)
	idA := cryptoTestIdentity(t)
	idB := cryptoTestIdentity(t)
	key := cryptoTestKey(nc.ID(), idA.NodeID, idB.NodeID)
	id := sessionID(0x40)
	pI := cryptoTestParams(t, key, id, FirstAttempt, FirstTargetEpoch, psk, idA, idB.PublicKey, true)
	pR := cryptoTestParams(t, key, id, FirstAttempt, FirstTargetEpoch, psk, idB, idA.PublicKey, false)

	newProvider := func(identity security.Identity) *NoiseProvider {
		p, err := NewNoiseProvider(identity, nc, cryptoTestPolicy())
		if err != nil {
			t.Fatalf("provider: %v", err)
		}
		return p
	}

	// Wrong context id is rejected before any crypto.
	bad := pI
	bad.ContextID = pattern32(0xEE)
	if _, err := newProvider(idA).Initiate(ctx, bad); !errors.Is(err, ErrNoiseConfig) {
		t.Fatalf("wrong context: %v", err)
	}
	// Short prologue binding is rejected.
	bad = pI
	bad.Prologue = bad.Prologue[:len(bad.Prologue)-1]
	if _, err := newProvider(idA).Initiate(ctx, bad); !errors.Is(err, ErrNoiseConfig) {
		t.Fatalf("short prologue: %v", err)
	}
	// Role mismatch is rejected.
	bad = pI
	bad.Initiator = false
	if _, err := newProvider(idA).Initiate(ctx, bad); !errors.Is(err, ErrNoiseConfig) {
		t.Fatalf("role mismatch: %v", err)
	}
	// Zero PSK is rejected.
	bad = pI
	bad.PSK = [32]byte{}
	if _, err := newProvider(idA).Initiate(ctx, bad); !errors.Is(err, ErrNoiseConfig) {
		t.Fatalf("zero psk: %v", err)
	}
	// A same-length but non-canonical binding byte is rejected, not hashed.
	bad = pI
	bad.Prologue = append([]byte(nil), pI.Prologue...)
	bad.Prologue[0] ^= 0xFF
	if _, err := newProvider(idA).Initiate(ctx, bad); !errors.Is(err, ErrNoiseConfig) {
		t.Fatalf("non-canonical prologue: %v", err)
	}
	// A PeerStatic that does not hash to PeerNodeID is rejected.
	bad = pI
	bad.PeerNodeID = nodeIDFor(pattern32(0xAB))
	if _, err := newProvider(idA).Initiate(ctx, bad); !errors.Is(err, ErrNoiseConfig) {
		t.Fatalf("peer node id mismatch: %v", err)
	}

	// A wrong non-zero PSK is not detectable by the responder when it reads
	// msg1 (psk2 lives in msg2); the initiator detects it when it reads msg2.
	pi := newProvider(idA)
	pr := newProvider(idB)
	msg1, err := pi.Initiate(ctx, pI)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	wrongPSK := pR
	wrongPSK.PSK = pattern32(0x66)
	msg2, _, err := pr.Respond(ctx, wrongPSK, msg1)
	if err != nil {
		t.Fatalf("respond with wrong psk should still produce msg2: %v", err)
	}
	if _, err := pi.Finish(ctx, pI, msg2); !errors.Is(err, ErrNoiseMessage) {
		t.Fatalf("wrong psk finish: %v", err)
	}

	// Pinning a different responder static (with its matching NodeID so the
	// binding stays canonical) fails Noise authentication on the responder.
	idC := cryptoTestIdentity(t)
	wrongPeer := cryptoTestParams(t, cryptoTestKey(nc.ID(), idA.NodeID, idC.NodeID), sessionID(0x40), FirstAttempt, FirstTargetEpoch, psk, idA, idC.PublicKey, true)
	pi2 := newProvider(idA)
	msg1, err = pi2.Initiate(ctx, wrongPeer)
	if err != nil {
		t.Fatalf("initiate wrong peer: %v", err)
	}
	if _, _, err := pr.Respond(ctx, pR, msg1); !errors.Is(err, ErrNoiseMessage) {
		t.Fatalf("wrong peer static: %v", err)
	}

	// A resolved PeerStatic that disagrees with PeerNodeID cannot even reach
	// the authenticated-peer check: the canonical prologue binds Src to
	// PeerNodeID, so the mismatch is rejected as invalid config first.
	wrongResolved := pR
	wrongResolved.PeerStatic = pattern32(0xCD)
	if _, _, err := pr.Respond(ctx, wrongResolved, []byte("unused")); !errors.Is(err, ErrNoiseConfig) {
		t.Fatalf("resolved peer static mismatch: %v", err)
	}
}

func TestNoiseProviderPendingBoundedCancellableAndExpired(t *testing.T) {
	ctx := context.Background()
	nc := cryptoTestContext(t)
	psk := pattern32(0x55)
	idA := cryptoTestIdentity(t)
	idB := cryptoTestIdentity(t)
	key := cryptoTestKey(nc.ID(), idA.NodeID, idB.NodeID)
	pI := cryptoTestParams(t, key, sessionID(0x40), FirstAttempt, FirstTargetEpoch, psk, idA, idB.PublicKey, true)

	now := time.Now()
	policy := ProviderPolicy{PendingMax: 1, PendingTTL: 50 * time.Millisecond, Clock: func() time.Time { return now }}
	p, err := NewNoiseProvider(idA, nc, policy)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	if _, err := p.Initiate(ctx, pI); err != nil {
		t.Fatalf("first initiate: %v", err)
	}
	// A second, distinct identity cannot start while the bounded table is full.
	pI2 := cryptoTestRebind(t, pI, sessionID(0x50), FirstAttempt, FirstTargetEpoch)
	if _, err := p.Initiate(ctx, pI2); !errors.Is(err, ErrHandshakeLimit) {
		t.Fatalf("pending limit: %v", err)
	}
	// Duplicate Initiate for the same identity is refused, not silently reused.
	if _, err := p.Initiate(ctx, pI); !errors.Is(err, ErrHandshakePending) {
		t.Fatalf("duplicate pending: %v", err)
	}
	// Finish without Initiate is explicit.
	orphan := cryptoTestRebind(t, pI, sessionID(0x60), FirstAttempt, FirstTargetEpoch)
	if _, err := p.Finish(ctx, orphan, []byte("x")); !errors.Is(err, ErrHandshakeNotFound) {
		t.Fatalf("missing pending: %v", err)
	}
	// Cancellation does not consume the pending entry.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	pI3 := pI2
	if _, err := p.Initiate(cancelled, pI3); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled initiate: %v", err)
	}
	// Expiry purges the entry and Finish reports it.
	now = now.Add(2 * policy.PendingTTL)
	if _, err := p.Initiate(ctx, pI3); err != nil {
		t.Fatalf("initiate after purge: %v", err)
	}
	now = now.Add(2 * policy.PendingTTL)
	if _, err := p.Finish(ctx, pI3, []byte("late")); !errors.Is(err, ErrHandshakeExpired) {
		t.Fatalf("expired pending: %v", err)
	}
}

// TestManagersRealNoiseAndDuplicateCaching drives two real Managers with real
// providers and real AEAD, and confirms duplicate control traffic is answered
// from the Manager cache without re-consuming Noise state.
func TestManagersRealNoiseAndDuplicateCaching(t *testing.T) {
	ctx := context.Background()
	nc := cryptoTestContext(t)
	psk := pattern32(0x55)
	idA := cryptoTestIdentity(t)
	idB := cryptoTestIdentity(t)

	providerA, err := NewNoiseProvider(idA, nc, cryptoTestPolicy())
	if err != nil {
		t.Fatalf("provider A: %v", err)
	}
	providerB, err := NewNoiseProvider(idB, nc, cryptoTestPolicy())
	if err != nil {
		t.Fatalf("provider B: %v", err)
	}
	managerA, err := NewManager(Config{ContextID: nc.ID(), PSK: psk, LocalStatic: idA.PublicKey, PeerStatic: idB.PublicKey, Crypto: providerA})
	if err != nil {
		t.Fatalf("manager A: %v", err)
	}
	managerB, err := NewManager(Config{ContextID: nc.ID(), PSK: psk, LocalStatic: idB.PublicKey, PeerStatic: idA.PublicKey, Crypto: providerB})
	if err != nil {
		t.Fatalf("manager B: %v", err)
	}

	sessionA, err := managerA.Open(ctx, e2eTestPathID, e2eTestPathGeneration, SessionClassStream, LaneStream)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	attempt := sessionA.Attempt()
	ctrl := SessionCtrl{
		SessionID:      sessionA.ID(),
		Class:          SessionClassStream,
		DataLaneID:     LaneStream,
		Attempt:        attempt.Attempt,
		TargetEpoch:    attempt.TargetEpoch,
		PathID:         e2eTestPathID,
		PathGeneration: e2eTestPathGeneration,
		SrcNodeID:      idA.NodeID,
		DstNodeID:      idB.NodeID,
		Payload:        attempt.Bytes,
	}
	sessionB, reply, err := managerB.HandleOpen(ctx, ctrl)
	if err != nil {
		t.Fatalf("handle open B: %v", err)
	}
	// Duplicate bootstrap is answered byte-identically from the cache and does
	// not re-consume Noise state (which would fail: msg1 must not be read twice).
	sessionB2, reply2, err := managerB.HandleOpen(ctx, ctrl)
	if err != nil {
		t.Fatalf("duplicate handle open B: %v", err)
	}
	if sessionB2 != sessionB || !bytes.Equal(reply, reply2) {
		t.Fatal("duplicate bootstrap did not replay the cached reply")
	}
	// Different bytes for the same attempt are a conflict.
	conflict := ctrl
	conflict.Payload = append([]byte(nil), ctrl.Payload...)
	conflict.Payload[0] ^= 0xFF
	if _, _, err := managerB.HandleOpen(ctx, conflict); !errors.Is(err, ErrAttemptConflict) {
		t.Fatalf("conflicting bootstrap: %v", err)
	}

	replyCtrl := SessionCtrl{
		SessionID:      sessionA.ID(),
		Class:          SessionClassStream,
		DataLaneID:     LaneStream,
		Attempt:        attempt.Attempt,
		TargetEpoch:    attempt.TargetEpoch,
		PathID:         e2eTestPathID,
		PathGeneration: e2eTestPathGeneration,
		SrcNodeID:      idA.NodeID,
		DstNodeID:      idB.NodeID,
		Payload:        reply,
	}
	if _, _, err := managerA.HandleOpen(ctx, replyCtrl); err != nil {
		t.Fatalf("initiator finish: %v", err)
	}
	// Idempotent replay of the responder message.
	if _, _, err := managerA.HandleOpen(ctx, replyCtrl); err != nil {
		t.Fatalf("duplicate initiator finish: %v", err)
	}

	readyA := SessionReady{SessionID: sessionA.ID(), Class: SessionClassStream, DataLaneID: LaneStream, Attempt: attempt.Attempt, TargetEpoch: attempt.TargetEpoch, PathID: e2eTestPathID, PathGeneration: e2eTestPathGeneration, SrcNodeID: idA.NodeID, DstNodeID: idB.NodeID}
	readyB := readyA
	if err := managerA.HandleReady(readyA); err != nil {
		t.Fatalf("ready A: %v", err)
	}
	if err := managerB.HandleReady(readyB); err != nil {
		t.Fatalf("ready B: %v", err)
	}
	rootA := sessionA.Root()
	rootB := sessionB.Root()
	if len(rootA) != SessionRootSize || !bytes.Equal(rootA, rootB) {
		t.Fatalf("committed roots differ or wrong size: %d/%d", len(rootA), len(rootB))
	}

	// Real end-to-end AEAD both ways on the committed root. One protector per
	// direction: A-TX/B-RX share the I->R key, B-TX/A-RX share the R->I key.
	aTx := newE2EProtectorForTest(t, rootA, DirectionInitiatorToResponder, idA.NodeID, idB.NodeID, sessionA.ID(), SessionClassStream)
	bRx := newE2EProtectorForTest(t, rootA, DirectionInitiatorToResponder, idA.NodeID, idB.NodeID, sessionA.ID(), SessionClassStream)
	bTx := newE2EProtectorForTest(t, rootA, DirectionResponderToInitiator, idA.NodeID, idB.NodeID, sessionA.ID(), SessionClassStream)
	aRx := newE2EProtectorForTest(t, rootA, DirectionResponderToInitiator, idA.NodeID, idB.NodeID, sessionA.ID(), SessionClassStream)
	for name, p := range map[string]*E2EProtector{"aTx": aTx, "bRx": bRx, "bTx": bTx, "aRx": aRx} {
		if err := p.InstallEpoch(1, rootA); err != nil {
			t.Fatalf("install %s: %v", name, err)
		}
	}
	txFR := newE2EFrameForTest(e2eTestWireID, idA.NodeID, idB.NodeID, sessionA.ID(), 1, 0, len([]byte("hello-from-A")))
	sealed, err := aTx.Seal(txFR, []byte("hello-from-A"))
	if err != nil {
		t.Fatalf("seal A: %v", err)
	}
	plain, err := bRx.Open(sealed)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	if string(plain) != "hello-from-A" {
		t.Fatalf("plaintext mismatch: %q", plain)
	}
	txFR2 := newE2EFrameForTest(e2eTestWireID, idB.NodeID, idA.NodeID, sessionA.ID(), 1, 0, len([]byte("hello-from-B")))
	sealed2, err := bTx.Seal(txFR2, []byte("hello-from-B"))
	if err != nil {
		t.Fatalf("seal B: %v", err)
	}
	plain2, err := aRx.Open(sealed2)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	if string(plain2) != "hello-from-B" {
		t.Fatalf("plaintext mismatch: %q", plain2)
	}

	// Concurrent Opens of the same fresh valid frame commit exactly once.
	raceFrame := newE2EFrameForTest(e2eTestWireID, idA.NodeID, idB.NodeID, sessionA.ID(), 1, 1, len([]byte("race")))
	raceSealed, err := aTx.Seal(raceFrame, []byte("race"))
	if err != nil {
		t.Fatalf("seal race: %v", err)
	}
	var wg sync.WaitGroup
	var successes int
	var mu sync.Mutex
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := bRx.Open(raceSealed); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent replay committed %d times, want 1", successes)
	}
}

func TestNewNoiseProviderValidatesConfig(t *testing.T) {
	nc := cryptoTestContext(t)
	id := cryptoTestIdentity(t)
	if _, err := NewNoiseProvider(id, nc, ProviderPolicy{}); !errors.Is(err, ErrNoiseConfig) {
		t.Fatalf("zero policy: %v", err)
	}
	if _, err := NewNoiseProvider(id, nc, ProviderPolicy{PendingMax: 1}); !errors.Is(err, ErrNoiseConfig) {
		t.Fatalf("zero ttl: %v", err)
	}
	if _, err := NewNoiseProvider(security.Identity{}, nc, cryptoTestPolicy()); !errors.Is(err, ErrNoiseConfig) {
		t.Fatalf("zero identity: %v", err)
	}
	uninitialized := id
	uninitialized.PublicKey = pattern32(0xEE)
	uninitialized.NodeID = nodeIDFor(uninitialized.PublicKey)
	// A mismatched public/private pair must be rejected.
	if _, err := NewNoiseProvider(uninitialized, nc, cryptoTestPolicy()); !errors.Is(err, ErrNoiseConfig) {
		t.Fatalf("mismatched identity: %v", err)
	}
}

// TestNoisePrologueWrapperFixedVector pins the full provider prologue wrapper:
// ASCII "simpletier-v1/prologue" || LP32(domain) || LP32(descriptor) ||
// LP32(binding), where binding is the frozen 102-byte PrologueBinding. The
// provider must never hand the bare binding to Noise.
func TestNoisePrologueWrapperFixedVector(t *testing.T) {
	nc := cryptoTestContext(t)
	key := cryptoTestKey(nc.ID(), cryptoTestNodeID(0x20), cryptoTestNodeID(0x30))
	binding, err := PrologueBinding(key, sessionID(0x40), FirstAttempt, FirstTargetEpoch)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	if len(binding) != PrologueBindingSize {
		t.Fatalf("binding is %d bytes, want %d", len(binding), PrologueBindingSize)
	}
	got, err := nc.Prologue(PrologueDomain, binding)
	if err != nil {
		t.Fatalf("prologue: %v", err)
	}
	want := []byte("simpletier-v1/prologue")
	want = testLP32(want, []byte(PrologueDomain))
	want = testLP32(want, nc.Descriptor())
	want = testLP32(want, binding)
	if !bytes.Equal(got, want) {
		t.Fatalf("prologue wrapper mismatch:\n got %x\nwant %x", got, want)
	}
	if len(got) != 22+4+len(PrologueDomain)+4+len(nc.Descriptor())+4+PrologueBindingSize {
		t.Fatalf("unexpected wrapper length %d", len(got))
	}
	if bytes.Equal(got, binding) {
		t.Fatal("provider prologue is the bare binding, not the full wrapper")
	}

	// The provider itself must produce exactly this wrapper. The binding's
	// SrcNodeID must be the provider's NodeID so the bound-field check passes.
	id := cryptoTestIdentity(t)
	peer := cryptoTestIdentity(t)
	key = cryptoTestKey(nc.ID(), id.NodeID, peer.NodeID)
	params := cryptoTestParams(t, key, sessionID(0x40), FirstAttempt, FirstTargetEpoch, pattern32(0x55), id, peer.PublicKey, true)
	provider, err := NewNoiseProvider(id, nc, cryptoTestPolicy())
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	providerPrologue, err := provider.prologue(params, true)
	if err != nil {
		t.Fatalf("provider prologue: %v", err)
	}
	wantProvider := []byte("simpletier-v1/prologue")
	wantProvider = testLP32(wantProvider, []byte(PrologueDomain))
	wantProvider = testLP32(wantProvider, nc.Descriptor())
	wantProvider = testLP32(wantProvider, params.Prologue)
	if !bytes.Equal(providerPrologue, wantProvider) {
		t.Fatalf("provider wrapper mismatch:\n got %x\nwant %x", providerPrologue, wantProvider)
	}
}

func TestNoiseProviderCloseFailsClosedAndWipes(t *testing.T) {
	ctx := context.Background()
	nc := cryptoTestContext(t)
	psk := pattern32(0x55)
	idA := cryptoTestIdentity(t)
	idB := cryptoTestIdentity(t)
	key := cryptoTestKey(nc.ID(), idA.NodeID, idB.NodeID)
	pI := cryptoTestParams(t, key, sessionID(0x40), FirstAttempt, FirstTargetEpoch, psk, idA, idB.PublicKey, true)
	pR := cryptoTestParams(t, key, sessionID(0x40), FirstAttempt, FirstTargetEpoch, psk, idB, idA.PublicKey, false)

	p, err := NewNoiseProvider(idA, nc, cryptoTestPolicy())
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	if _, err := p.Initiate(ctx, pI); err != nil {
		t.Fatalf("initiate: %v", err)
	}
	p.Close()
	p.Close() // idempotent
	if _, err := p.Initiate(ctx, pI); !errors.Is(err, ErrProviderClosed) {
		t.Fatalf("initiate after close: %v", err)
	}
	if _, _, err := p.Respond(ctx, pR, []byte("x")); !errors.Is(err, ErrProviderClosed) {
		t.Fatalf("respond after close: %v", err)
	}
	if _, err := p.Finish(ctx, pI, []byte("x")); !errors.Is(err, ErrProviderClosed) {
		t.Fatalf("finish after close: %v", err)
	}
	allZero := true
	for _, b := range p.static.Private {
		if b != 0 {
			allZero = false
		}
	}
	if !allZero {
		t.Fatal("private key was not wiped by Close")
	}
	if len(p.pending) != 0 {
		t.Fatalf("%d pending handshakes survived Close", len(p.pending))
	}
}

func TestNoiseProviderCloseConcurrentWithHandshakes(t *testing.T) {
	ctx := context.Background()
	nc := cryptoTestContext(t)
	psk := pattern32(0x55)
	idA := cryptoTestIdentity(t)
	idB := cryptoTestIdentity(t)
	key := cryptoTestKey(nc.ID(), idA.NodeID, idB.NodeID)
	p, err := NewNoiseProvider(idA, nc, cryptoTestPolicy())
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	params := make([]HandshakeParams, 0, 16)
	for i := 0; i < 16; i++ {
		params = append(params, cryptoTestParams(t, key, sessionID(byte(0x40+i)), FirstAttempt, FirstTargetEpoch, psk, idA, idB.PublicKey, true))
	}
	var wg sync.WaitGroup
	for i := range params {
		wg.Add(1)
		go func(pm HandshakeParams) {
			defer wg.Done()
			_, _ = p.Initiate(ctx, pm) // may win or observe ErrProviderClosed
		}(params[i])
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.Close()
	}()
	wg.Wait()
	p.Close()
}
