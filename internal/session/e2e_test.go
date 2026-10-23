package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/yiiilin/simpletier/internal/wire"
)

const (
	e2eTestWireID         uint64 = 0x1122334455667788
	e2eTestPathID         uint64 = 0x0102030405060708
	e2eTestPathGeneration uint32 = 0x0a0b0c0d
)

var e2eTestDescriptor = []byte("simpletier-v1/network-context/e2e-test")

func buildE2EFrame(wireID uint64, src, dst [16]byte, class SessionClass, id SessionID, epoch uint32, number uint64, pathID uint64, generation uint32, msgType wire.MessageType, inner int) wire.Frame {
	env := make([]byte, wire.EnvelopeSize)
	binary.BigEndian.PutUint64(env[0:8], wireID)
	copy(env[8:24], src[:])
	copy(env[24:40], dst[:])
	env[wire.EnvelopeMessageTypeOffset] = byte(msgType)
	copy(env[wire.EnvelopeSessionIDOffset:wire.EnvelopeKeyEpochOffset], id[:])
	binary.BigEndian.PutUint32(env[wire.EnvelopeKeyEpochOffset:], epoch)
	binary.BigEndian.PutUint64(env[wire.EnvelopeMessageNumberOffset:], number)
	binary.BigEndian.PutUint64(env[wire.EnvelopePathIDOffset:], pathID)
	binary.BigEndian.PutUint32(env[wire.EnvelopePathGenerationOffset:], generation)
	binary.BigEndian.PutUint32(env[wire.EnvelopeInnerLengthOffset:], uint32(inner))
	return wire.Frame{Kind: wire.FrameKindEndToEnd, Envelope: env}
}

func newE2EFrameForTest(wireID uint64, src, dst [16]byte, id SessionID, epoch uint32, number uint64, inner int) wire.Frame {
	return buildE2EFrame(wireID, src, dst, SessionClassStream, id, epoch, number, e2eTestPathID, e2eTestPathGeneration, wire.MessageTypeStreamData, inner)
}

func e2eTestConfig(root []byte, dir Direction, src, dst [16]byte, id SessionID, class SessionClass) E2EConfig {
	return E2EConfig{
		Root:           root,
		Descriptor:     e2eTestDescriptor,
		WireID:         e2eTestWireID,
		SrcNodeID:      src,
		DstNodeID:      dst,
		PathID:         e2eTestPathID,
		PathGeneration: e2eTestPathGeneration,
		SessionID:      id,
		Class:          class,
		Direction:      dir,
	}
}

func newE2EProtectorForTest(t *testing.T, root []byte, dir Direction, src, dst [16]byte, id SessionID, class SessionClass) *E2EProtector {
	t.Helper()
	p, err := NewE2EProtector(e2eTestConfig(root, dir, src, dst, id, class), E2EPolicy{})
	if err != nil {
		t.Fatalf("new protector: %v", err)
	}
	return p
}

func e2eTestRoot(seed byte) SessionRoot {
	return SessionRoot{I2R: pattern32(seed), R2I: pattern32(seed + 0x80)}
}

// TestE2EEnvelopeAADAndNonceIndependentVector pins the exact envelope AAD, the
// KeyEpochBE32|MessageNumberBE64 nonce and the v2/session-traffic info against
// an independently constructed HKDF and a direct ChaCha20-Poly1305 call.
func TestE2EEnvelopeAADAndNonceIndependentVector(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := SessionRoot{I2R: pattern32(0x21), R2I: pattern32(0xA1)}
	encoded := root.Encode()
	p := newE2EProtectorForTest(t, encoded, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	const epoch uint32 = 0x01020304
	if err := p.InstallEpoch(epoch, encoded); err != nil {
		t.Fatalf("install epoch: %v", err)
	}
	plaintext := []byte("independent-envelope-vector")
	const number uint64 = 0x05060708090a0b0c
	frame := buildE2EFrame(e2eTestWireID, srcID, dstID, SessionClassStream, id, epoch, number, e2eTestPathID, e2eTestPathGeneration, wire.MessageTypeStreamData, len(plaintext))

	sealed, err := p.Seal(frame, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(sealed.Body) != len(plaintext)+chacha20poly1305.Overhead {
		t.Fatalf("body is %d bytes", len(sealed.Body))
	}

	// Nonce bytes.
	wantNonce := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	if got := e2eNonce(epoch, number); got != wantNonce {
		t.Fatalf("nonce mismatch: %x", got)
	}

	// Independent traffic-key derivation and AEAD.
	info := append([]byte("simpletier/v2/session-traffic"), byte(DirectionInitiatorToResponder))
	info = append(info, id[:]...)
	info = append(info, byte(SessionClassStream))
	info = binary.BigEndian.AppendUint32(info, epoch)
	info = testLP32(info, e2eTestDescriptor)
	wantKey := testHKDF(root.I2R[:], e2eTestDescriptor, info, 32)
	aead, err := chacha20poly1305.New(wantKey)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	wantBody := aead.Seal(nil, wantNonce[:], plaintext, frame.Envelope)
	if !bytes.Equal(sealed.Body, wantBody) {
		t.Fatalf("ciphertext mismatch:\n got %x\nwant %x", sealed.Body, wantBody)
	}

	// The R2I root derives a different key: independent direction domains.
	wantR2IKey := testHKDF(root.R2I[:], e2eTestDescriptor, info, 32)
	if bytes.Equal(wantKey, wantR2IKey) {
		t.Fatal("directional traffic keys are not independent")
	}
}

func TestE2EReplayWindowOutOfOrderAndAtomicAntiPoison(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()

	tx := newE2EProtectorForTest(t, root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	rx := newE2EProtectorForTest(t, root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	if err := tx.InstallEpoch(1, root); err != nil {
		t.Fatalf("install tx: %v", err)
	}
	if err := rx.InstallEpoch(1, root); err != nil {
		t.Fatalf("install rx: %v", err)
	}

	const count = 2000
	frames := make([]wire.Frame, count)
	for i := 0; i < count; i++ {
		pt := []byte{byte(i), byte(i >> 8)}
		frame := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, uint64(i), len(pt))
		sealed, err := tx.Seal(frame, pt)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		frames[i] = sealed
	}

	// Out-of-order within the 1024-bit window is accepted.
	for _, n := range []int{1000, 10, 900, 500, 999} {
		if _, err := rx.Open(frames[n]); err != nil {
			t.Fatalf("out-of-order %d: %v", n, err)
		}
	}
	// Sliding forward accepts a higher number and moves the floor.
	if _, err := rx.Open(frames[1500]); err != nil {
		t.Fatalf("advance: %v", err)
	}
	// A duplicate inside the window is rejected.
	if _, err := rx.Open(frames[1500]); !errors.Is(err, ErrE2EReplay) {
		t.Fatalf("duplicate: %v", err)
	}
	// A message below the floor is rejected.
	if _, err := rx.Open(frames[400]); !errors.Is(err, ErrE2EReplay) {
		t.Fatalf("below floor: %v", err)
	}

	// Anti-poison: a tampered high-number frame fails authentication and must
	// not move the window, so the genuine frame still opens afterwards.
	poison := frames[1700]
	poison = wire.Frame{Kind: poison.Kind, Envelope: append([]byte(nil), poison.Envelope...), Body: append([]byte(nil), poison.Body...)}
	binary.BigEndian.PutUint64(poison.Envelope[wire.EnvelopeMessageNumberOffset:], 5000)
	if _, err := rx.Open(poison); !errors.Is(err, ErrE2EAuthentication) {
		t.Fatalf("tampered frame: %v", err)
	}
	genuine := frames[1700]
	if _, err := rx.Open(genuine); err != nil {
		t.Fatalf("genuine frame after poison: %v", err)
	}
	// A forward jump still works after the genuine frame committed.
	if _, err := rx.Open(frames[1999]); err != nil {
		t.Fatalf("forward frame: %v", err)
	}
}

func TestE2EEnvelopeBindingRejections(t *testing.T) {
	id := sessionID(0x40)
	var srcID, dstID [16]byte
	srcID = cryptoTestNodeID(0x20)
	dstID = cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	p := newE2EProtectorForTest(t, root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	if err := p.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	pt := []byte("payload")
	good := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, len(pt))
	sealed, err := p.Seal(good, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	mutate := func(fn func(f wire.Frame) wire.Frame) wire.Frame {
		return fn(wire.Frame{Kind: sealed.Kind, Envelope: append([]byte(nil), sealed.Envelope...), Body: append([]byte(nil), sealed.Body...)})
	}
	cases := map[string]wire.Frame{
		"wrong kind": mutate(func(f wire.Frame) wire.Frame { f.Kind = wire.FrameKindLinkControl; return f }),
		"short envelope": mutate(func(f wire.Frame) wire.Frame {
			f.Envelope = f.Envelope[:wire.EnvelopeSize-1]
			return f
		}),
		"wrong network": mutate(func(f wire.Frame) wire.Frame {
			binary.BigEndian.PutUint64(f.Envelope[0:8], e2eTestWireID+1)
			return f
		}),
		"swapped endpoints": mutate(func(f wire.Frame) wire.Frame {
			copy(f.Envelope[8:24], dstID[:])
			copy(f.Envelope[24:40], srcID[:])
			return f
		}),
		"wrong session": mutate(func(f wire.Frame) wire.Frame {
			other := sessionID(0x50)
			copy(f.Envelope[wire.EnvelopeSessionIDOffset:wire.EnvelopeKeyEpochOffset], other[:])
			return f
		}),
		"wrong path": mutate(func(f wire.Frame) wire.Frame {
			binary.BigEndian.PutUint64(f.Envelope[wire.EnvelopePathIDOffset:], e2eTestPathID+1)
			return f
		}),
		"wrong generation": mutate(func(f wire.Frame) wire.Frame {
			binary.BigEndian.PutUint32(f.Envelope[wire.EnvelopePathGenerationOffset:], e2eTestPathGeneration+1)
			return f
		}),
		"wrong message type": mutate(func(f wire.Frame) wire.Frame {
			f.Envelope[wire.EnvelopeMessageTypeOffset] = byte(wire.MessageTypeIPPacket)
			return f
		}),
		"zero epoch": mutate(func(f wire.Frame) wire.Frame {
			binary.BigEndian.PutUint32(f.Envelope[wire.EnvelopeKeyEpochOffset:], 0)
			return f
		}),
		"inner length mismatch": mutate(func(f wire.Frame) wire.Frame {
			binary.BigEndian.PutUint32(f.Envelope[wire.EnvelopeInnerLengthOffset:], uint32(len(pt)+1))
			return f
		}),
	}
	for name, frame := range cases {
		if _, err := p.Open(frame); !errors.Is(err, ErrE2EEnvelope) {
			t.Fatalf("%s: got %v, want ErrE2EEnvelope", name, err)
		}
	}
	// The unmodified frame still opens, so the rejections did not consume it.
	if _, err := p.Open(sealed); err != nil {
		t.Fatalf("good frame: %v", err)
	}
}

func TestE2EDirectionKeysAndRootsIndependent(t *testing.T) {
	id := sessionID(0x40)
	var srcID, dstID [16]byte
	srcID = cryptoTestNodeID(0x20)
	dstID = cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	other := e2eTestRoot(0x71).Encode()

	i2r := newE2EProtectorForTest(t, root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	r2i := newE2EProtectorForTest(t, root, DirectionResponderToInitiator, srcID, dstID, id, SessionClassStream)
	otherI2R := newE2EProtectorForTest(t, other, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	for _, p := range []*E2EProtector{i2r, r2i} {
		if err := p.InstallEpoch(1, root); err != nil {
			t.Fatalf("install: %v", err)
		}
	}
	if err := otherI2R.InstallEpoch(1, other); err != nil {
		t.Fatalf("install other: %v", err)
	}

	pt := []byte("direction")
	frame := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, len(pt))
	sealed, err := i2r.Seal(frame, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// A different root is a different key.
	if _, err := otherI2R.Open(sealed); !errors.Is(err, ErrE2EAuthentication) {
		t.Fatalf("other root: %v", err)
	}
	// A protector for the opposite direction expects the swapped endpoints and
	// rejects the envelope before touching a key.
	if _, err := r2i.Open(sealed); !errors.Is(err, ErrE2EEnvelope) {
		t.Fatalf("wrong direction: %v", err)
	}
	// The correct direction opens.
	if got, err := i2r.Open(sealed); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("correct direction: %v", err)
	}
	// The R2I direction works with swapped endpoints.
	rFrame := newE2EFrameForTest(e2eTestWireID, dstID, srcID, id, 1, 0, len(pt))
	rSealed, err := r2i.Seal(rFrame, pt)
	if err != nil {
		t.Fatalf("seal r2i: %v", err)
	}
	if got, err := r2i.Open(rSealed); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open r2i: %v", err)
	}
	if _, err := i2r.Open(rSealed); !errors.Is(err, ErrE2EEnvelope) {
		t.Fatalf("i2r on r2i frame: %v", err)
	}
}

func TestE2ERekeyGraceAndEpochNoWrap(t *testing.T) {
	id := sessionID(0x40)
	var srcID, dstID [16]byte
	srcID = cryptoTestNodeID(0x20)
	dstID = cryptoTestNodeID(0x30)

	now := time.Now()
	root1 := e2eTestRoot(0x11).Encode()
	root2 := e2eTestRoot(0x21).Encode()
	root3 := e2eTestRoot(0x31).Encode()
	policy := E2EPolicy{GracePeriod: time.Minute, Clock: func() time.Time { return now }}
	p, err := NewE2EProtector(e2eTestConfig(root1, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), policy)
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := p.InstallEpoch(1, root1); err != nil {
		t.Fatalf("install epoch1: %v", err)
	}
	// Epoch 1 round trip.
	f1 := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, 4)
	s1, err := p.Seal(f1, []byte("e1-0"))
	if err != nil {
		t.Fatalf("seal e1: %v", err)
	}
	if _, err := p.Open(s1); err != nil {
		t.Fatalf("open e1: %v", err)
	}
	// Rekey to epoch 2; the old epoch must still be usable before the first
	// successfully authenticated target-epoch frame.
	if err := p.InstallEpoch(2, root2); err != nil {
		t.Fatalf("install epoch2: %v", err)
	}
	oldBefore := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 1, 4)
	sOld, err := p.Seal(oldBefore, []byte("e1-1"))
	if err != nil {
		t.Fatalf("seal old before grace: %v", err)
	}
	if _, err := p.Open(sOld); err != nil {
		t.Fatalf("open old before grace: %v", err)
	}
	// First epoch-2 frame starts the grace clock.
	newFrame := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 2, 0, 4)
	sNew, err := p.Seal(newFrame, []byte("e2-0"))
	if err != nil {
		t.Fatalf("seal new: %v", err)
	}
	if _, err := p.Open(sNew); err != nil {
		t.Fatalf("open new: %v", err)
	}
	// Still inside grace.
	oldInGrace := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 2, 4)
	sOld2, err := p.Seal(oldInGrace, []byte("e1-2"))
	if err != nil {
		t.Fatalf("seal old in grace: %v", err)
	}
	if _, err := p.Open(sOld2); err != nil {
		t.Fatalf("open old in grace: %v", err)
	}
	// Past grace the old epoch is gone.
	now = now.Add(2 * time.Minute)
	oldExpired := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 3, 4)
	if _, err := p.Seal(oldExpired, []byte("e1-3")); !errors.Is(err, ErrE2EEpochMismatch) {
		t.Fatalf("seal old past grace: %v", err)
	}
	// A third epoch ring keeps only current+onePrevious.
	if err := p.InstallEpoch(3, root3); err != nil {
		t.Fatalf("install epoch3: %v", err)
	}
	epoch1Again := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 4, 4)
	epoch1Again.Body = make([]byte, 4+chacha20poly1305.Overhead)
	if _, err := p.Open(epoch1Again); !errors.Is(err, ErrE2EEpochMismatch) {
		t.Fatalf("epoch1 after third install: %v", err)
	}
	// Epoch no wrap and no gaps.
	if err := p.InstallEpoch(^uint32(0), root3); !errors.Is(err, ErrEpochExhausted) {
		t.Fatalf("wrap: %v", err)
	}
	if err := p.InstallEpoch(5, root3); !errors.Is(err, ErrE2EEpochMismatch) {
		t.Fatalf("gap: %v", err)
	}
}

func TestE2EUsageCeilingsAndNonceExhaustion(t *testing.T) {
	id := sessionID(0x40)
	var srcID, dstID [16]byte
	srcID = cryptoTestNodeID(0x20)
	dstID = cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()

	p, err := NewE2EProtector(e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Usage: UsagePolicy{MaxInvocations: 2}})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := p.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	for i := 0; i < 2; i++ {
		f := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, uint64(i), 2)
		if _, err := p.Seal(f, []byte("ok")); err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
	}
	third := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 2, 2)
	if _, err := p.Seal(third, []byte("no")); !errors.Is(err, ErrKeyUsageExhausted) {
		t.Fatalf("invocation ceiling: %v", err)
	}
	if usage, ok := p.Usage(1); !ok || usage.SealInvocations != 2 || usage.SealBytes != 4 {
		t.Fatalf("usage = %+v, ok=%v", usage, ok)
	}

	// MessageNumber u64Max is never a nonce.
	last := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, ^uint64(0), 1)
	if _, err := p.Seal(last, []byte("x")); !errors.Is(err, ErrE2ENonceExhausted) {
		t.Fatalf("nonce exhaustion: %v", err)
	}
}

func TestE2EConcurrentOpenCommitsExactlyOnce(t *testing.T) {
	id := sessionID(0x40)
	var srcID, dstID [16]byte
	srcID = cryptoTestNodeID(0x20)
	dstID = cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()

	tx := newE2EProtectorForTest(t, root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	rx := newE2EProtectorForTest(t, root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	if err := tx.InstallEpoch(1, root); err != nil {
		t.Fatalf("install tx: %v", err)
	}
	if err := rx.InstallEpoch(1, root); err != nil {
		t.Fatalf("install rx: %v", err)
	}
	pt := []byte("race")
	frame := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, len(pt))
	sealed, err := tx.Seal(frame, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := rx.Open(sealed); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("committed %d times, want 1", successes)
	}
}

func TestNewE2EProtectorValidatesConfig(t *testing.T) {
	id := sessionID(0x40)
	var srcID, dstID [16]byte
	srcID = cryptoTestNodeID(0x20)
	dstID = cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()

	bad := func(mutate func(cfg *E2EConfig)) error {
		cfg := e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
		mutate(&cfg)
		_, err := NewE2EProtector(cfg, E2EPolicy{})
		return err
	}
	if err := bad(func(cfg *E2EConfig) { cfg.Direction = 7 }); !errors.Is(err, ErrE2EConfig) {
		t.Fatalf("direction: %v", err)
	}
	if err := bad(func(cfg *E2EConfig) { cfg.Class = 0 }); !errors.Is(err, ErrE2EConfig) {
		t.Fatalf("class: %v", err)
	}
	if err := bad(func(cfg *E2EConfig) { cfg.DstNodeID = cfg.SrcNodeID }); !errors.Is(err, ErrE2EConfig) {
		t.Fatalf("endpoints: %v", err)
	}
	if err := bad(func(cfg *E2EConfig) { cfg.PathID = 0 }); !errors.Is(err, ErrE2EConfig) {
		t.Fatalf("path: %v", err)
	}
	if err := bad(func(cfg *E2EConfig) { cfg.SessionID = SessionID{} }); !errors.Is(err, ErrE2EConfig) {
		t.Fatalf("session: %v", err)
	}
	if err := bad(func(cfg *E2EConfig) { cfg.Descriptor = nil }); !errors.Is(err, ErrE2EConfig) {
		t.Fatalf("descriptor: %v", err)
	}
	if err := bad(func(cfg *E2EConfig) { cfg.Root = root[:32] }); !errors.Is(err, ErrE2EConfig) {
		t.Fatalf("root size: %v", err)
	}
}

func TestE2EThirdInstallRetainedUntilPreviousGraceExpires(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	now := time.Now()
	root1 := e2eTestRoot(0x11).Encode()
	root2 := e2eTestRoot(0x21).Encode()
	root3 := e2eTestRoot(0x31).Encode()
	policy := E2EPolicy{GracePeriod: time.Minute, Clock: func() time.Time { return now }}
	p, err := NewE2EProtector(e2eTestConfig(root1, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), policy)
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := p.InstallEpoch(1, root1); err != nil {
		t.Fatalf("install epoch1: %v", err)
	}
	if err := p.InstallEpoch(2, root2); err != nil {
		t.Fatalf("install epoch2: %v", err)
	}
	// Before any new-epoch authentication the grace clock has not started, yet
	// the previous epoch must still be retained: the third install is refused.
	if err := p.InstallEpoch(3, root3); !errors.Is(err, ErrEpochRetained) {
		t.Fatalf("third install before grace start: %v", err)
	}
	if got := p.CurrentEpoch(); got != 2 {
		t.Fatalf("current epoch mutated to %d after refusal", got)
	}
	// Epoch 1 is still usable, proving it was not dropped.
	old := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, 4)
	sealedOld, err := p.Seal(old, []byte("e1-0"))
	if err != nil {
		t.Fatalf("seal epoch1: %v", err)
	}
	if _, err := p.Open(sealedOld); err != nil {
		t.Fatalf("open epoch1: %v", err)
	}
	// First epoch-2 authentication starts the grace clock; the third install is
	// still refused while the window is open.
	newer := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 2, 0, 4)
	sealedNew, err := p.Seal(newer, []byte("e2-0"))
	if err != nil {
		t.Fatalf("seal epoch2: %v", err)
	}
	if _, err := p.Open(sealedNew); err != nil {
		t.Fatalf("open epoch2: %v", err)
	}
	if err := p.InstallEpoch(3, root3); !errors.Is(err, ErrEpochRetained) {
		t.Fatalf("third install during grace: %v", err)
	}
	if got := p.CurrentEpoch(); got != 2 {
		t.Fatalf("current epoch mutated to %d after second refusal", got)
	}
	// After the frozen grace expiry the third install succeeds and epoch 1 is
	// finally released.
	now = now.Add(2 * time.Minute)
	if err := p.InstallEpoch(3, root3); err != nil {
		t.Fatalf("third install after grace: %v", err)
	}
	if got := p.CurrentEpoch(); got != 3 {
		t.Fatalf("current epoch = %d, want 3", got)
	}
	epoch1 := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 1, 4)
	epoch1.Body = make([]byte, 4+chacha20poly1305.Overhead)
	if _, err := p.Open(epoch1); !errors.Is(err, ErrE2EEpochMismatch) {
		t.Fatalf("epoch1 after release: %v", err)
	}
}

func TestE2ECloseFailsClosedAndWipes(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	p := newE2EProtectorForTest(t, root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	if err := p.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	pt := []byte("x")
	frame := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, len(pt))
	sealed, err := p.Seal(frame, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := p.Open(sealed); err != nil {
		t.Fatalf("open: %v", err)
	}
	p.Close()
	p.Close() // idempotent
	if _, err := p.Seal(frame, pt); !errors.Is(err, ErrE2EClosed) {
		t.Fatalf("seal after close: %v", err)
	}
	if _, err := p.Open(sealed); !errors.Is(err, ErrE2EClosed) {
		t.Fatalf("open after close: %v", err)
	}
	if err := p.InstallEpoch(2, root); !errors.Is(err, ErrE2EClosed) {
		t.Fatalf("install after close: %v", err)
	}
	if len(p.keys) != 0 {
		t.Fatalf("%d epoch keys survived Close", len(p.keys))
	}
}

func TestE2EUsageReportsAuthFailuresSeparately(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	p := newE2EProtectorForTest(t, root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	if err := p.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	pt := []byte("payload")
	frame := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, len(pt))
	sealed, err := p.Seal(frame, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	tampered := wire.Frame{Kind: sealed.Kind, Envelope: append([]byte(nil), sealed.Envelope...), Body: append([]byte(nil), sealed.Body...)}
	tampered.Body[0] ^= 0xFF
	if _, err := p.Open(tampered); !errors.Is(err, ErrE2EAuthentication) {
		t.Fatalf("tampered: %v", err)
	}
	usage, ok := p.Usage(1)
	if !ok {
		t.Fatal("usage missing")
	}
	if usage.AuthFailures != 1 || usage.OpenInvocations != 0 || usage.OpenBytes != 0 || usage.SealInvocations != 1 || usage.SealBytes != uint64(len(pt)) {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestNewE2EProtectorForContext(t *testing.T) {
	nc := cryptoTestContext(t)
	root := e2eTestRoot(0x11).Encode()
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)

	cfg := e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	cfg.Descriptor = nil
	cfg.WireID = 0
	p, err := NewE2EProtectorForContext(nc, cfg, E2EPolicy{})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if p.wireID != nc.WireID() || !bytes.Equal(p.descriptor, nc.Descriptor()) {
		t.Fatal("context descriptor/wire id not filled")
	}

	mismatched := cfg
	mismatched.Descriptor = []byte("not-the-context-descriptor")
	if _, err := NewE2EProtectorForContext(nc, mismatched, E2EPolicy{}); !errors.Is(err, ErrE2EConfig) {
		t.Fatalf("descriptor mismatch: %v", err)
	}
	badWire := nc.WireID() + 1
	if badWire == 0 {
		badWire = 2
	}
	mismatched = cfg
	mismatched.WireID = badWire
	if _, err := NewE2EProtectorForContext(nc, mismatched, E2EPolicy{}); !errors.Is(err, ErrE2EConfig) {
		t.Fatalf("wire mismatch: %v", err)
	}
}

func TestE2EUsageCountersDoNotWrapPastCeilings(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	frame := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, 2)

	// A saturated byte counter must not wrap the total below MaxBytes.
	byteGuard, err := NewE2EProtector(e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Usage: UsagePolicy{MaxBytes: 16}})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := byteGuard.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	byteGuard.mu.Lock()
	byteGuard.usage[1].SealBytes = ^uint64(0)
	byteGuard.mu.Unlock()
	if _, err := byteGuard.Seal(frame, []byte("ok")); !errors.Is(err, ErrKeyUsageExhausted) {
		t.Fatalf("saturated byte counter bypassed the ceiling: %v", err)
	}

	// TX+RX invocation counters whose sum overflows must fail closed.
	callGuard, err := NewE2EProtector(e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Usage: UsagePolicy{MaxInvocations: 4}})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := callGuard.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	callGuard.mu.Lock()
	callGuard.usage[1].SealInvocations = ^uint64(0)
	callGuard.usage[1].OpenInvocations = 1
	callGuard.mu.Unlock()
	if _, err := callGuard.Seal(frame, []byte("ok")); !errors.Is(err, ErrKeyUsageExhausted) {
		t.Fatalf("overflowing invocation sum bypassed the ceiling: %v", err)
	}
}

func TestE2EUsageBoundaryExactCeiling(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	p, err := NewE2EProtector(e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Usage: UsagePolicy{MaxBytes: 2}})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := p.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	first := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, 2)
	if _, err := p.Seal(first, []byte("ok")); err != nil {
		t.Fatalf("exact-ceiling seal: %v", err)
	}
	second := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 1, 2)
	if _, err := p.Seal(second, []byte("ok")); !errors.Is(err, ErrKeyUsageExhausted) {
		t.Fatalf("second seal over exact ceiling: %v", err)
	}
}

func TestE2EAuthFailuresSaturateAndStayObservable(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	p, err := NewE2EProtector(e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Usage: UsagePolicy{MaxAuthFailures: ^uint64(0)}})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := p.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	pt := []byte("payload")
	frame := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, len(pt))
	sealed, err := p.Seal(frame, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	tampered := wire.Frame{Kind: sealed.Kind, Envelope: append([]byte(nil), sealed.Envelope...), Body: append([]byte(nil), sealed.Body...)}
	tampered.Body[0] ^= 0xFF

	p.mu.Lock()
	p.usage[1].AuthFailures = ^uint64(0) - 1
	p.mu.Unlock()
	if _, err := p.Open(tampered); !errors.Is(err, ErrE2EAuthentication) {
		t.Fatalf("tampered: %v", err)
	}
	usage, ok := p.Usage(1)
	if !ok || usage.AuthFailures != ^uint64(0) {
		t.Fatalf("auth failures did not saturate: %+v ok=%v", usage, ok)
	}
	// At the saturated maximum the key fails closed: no further AEAD runs and
	// the counter stays observable.
	if _, err := p.Open(tampered); !errors.Is(err, ErrKeyUsageExhausted) {
		t.Fatalf("second tampered: %v", err)
	}
	usage, _ = p.Usage(1)
	if usage.AuthFailures != ^uint64(0) {
		t.Fatalf("saturated auth failures changed: %d", usage.AuthFailures)
	}
	if usage.OpenInvocations != 0 || usage.OpenBytes != 0 {
		t.Fatalf("failed auth moved success counters: %+v", usage)
	}
}

func TestE2ECloseClearsRootAndDescriptor(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	p := newE2EProtectorForTest(t, root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	if err := p.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	p.Close()
	if p.root.I2R != ([32]byte{}) || p.root.R2I != ([32]byte{}) {
		t.Fatal("derived directional roots survived Close")
	}
	if len(p.descriptor) != 0 {
		t.Fatalf("descriptor copy survived Close: %d bytes", len(p.descriptor))
	}
	if len(p.keys) != 0 {
		t.Fatalf("%d epoch keys survived Close", len(p.keys))
	}
}

func TestDefaultE2EPolicyAndNormalization(t *testing.T) {
	defaults := DefaultE2EPolicy()
	want := UsagePolicy{MaxInvocations: 1 << 32, MaxBytes: 1 << 48, MaxAge: 24 * time.Hour, MaxAuthFailures: 1024}
	if defaults.Usage != want {
		t.Fatalf("DefaultE2EPolicy = %+v, want %+v", defaults.Usage, want)
	}

	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	// A zero policy is normalized to the built-in operational defaults rather
	// than leaving the key unbounded.
	zero := newE2EProtectorForTest(t, root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream)
	if zero.policy.Usage != want {
		t.Fatalf("zero policy not normalized: %+v", zero.policy.Usage)
	}
	// Explicit non-zero fields win; remaining zero fields take the default.
	explicit, err := NewE2EProtector(e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Usage: UsagePolicy{MaxInvocations: 8}})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if explicit.policy.Usage.MaxInvocations != 8 || explicit.policy.Usage.MaxBytes != want.MaxBytes ||
		explicit.policy.Usage.MaxAge != want.MaxAge || explicit.policy.Usage.MaxAuthFailures != want.MaxAuthFailures {
		t.Fatalf("explicit override lost: %+v", explicit.policy.Usage)
	}
}

func TestE2ESoftRekeyAndHardLimit(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	p, err := NewE2EProtector(e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Usage: UsagePolicy{MaxInvocations: 8}})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := p.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	if snap, ok := p.UsageSnapshot(); !ok || snap.NeedsRekey || snap.SoftInvocations != 7 {
		t.Fatalf("initial snapshot = %+v ok=%v", snap, ok)
	}
	pt := []byte{1, 2}
	for i := 0; i < 7; i++ {
		frame := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, uint64(i), len(pt))
		if _, err := p.Seal(frame, pt); err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
	}
	if !p.NeedsRekey() {
		t.Fatal("NeedsRekey false at the 7/8 soft threshold")
	}
	// The top eighth is control headroom: one more seal still succeeds.
	headroom := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 7, len(pt))
	if _, err := p.Seal(headroom, pt); err != nil {
		t.Fatalf("headroom seal: %v", err)
	}
	// Then the hard ceiling fails closed.
	over := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 8, len(pt))
	if _, err := p.Seal(over, pt); !errors.Is(err, ErrKeyUsageExhausted) {
		t.Fatalf("hard limit: %v", err)
	}
	snap, _ := p.UsageSnapshot()
	// At/over the hard ceiling NeedsRekey is also true; AtHardLimit is the
	// distinguishing state.
	if !snap.AtHardLimit || snap.SealInvocations != 8 {
		t.Fatalf("snapshot at hard limit = %+v", snap)
	}
}

func TestE2EAuthFailureCeilingFailsClosed(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	p, err := NewE2EProtector(e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Usage: UsagePolicy{MaxAuthFailures: 2}})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := p.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	pt := []byte("payload")
	first, err := p.Seal(newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, len(pt)), pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	tampered := wire.Frame{Kind: first.Kind, Envelope: append([]byte(nil), first.Envelope...), Body: append([]byte(nil), first.Body...)}
	tampered.Body[0] ^= 0xFF
	for i := 0; i < 2; i++ {
		if _, err := p.Open(tampered); !errors.Is(err, ErrE2EAuthentication) {
			t.Fatalf("failed tag %d: %v", i, err)
		}
	}
	// Both directions now fail closed at the auth ceiling: no new seal, and a
	// previously sealed valid frame is rejected before any AEAD runs.
	if _, err := p.Seal(newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 1, len(pt)), pt); !errors.Is(err, ErrKeyUsageExhausted) {
		t.Fatalf("seal at auth ceiling: %v", err)
	}
	if _, err := p.Open(first); !errors.Is(err, ErrKeyUsageExhausted) {
		t.Fatalf("open at auth ceiling: %v", err)
	}
}

func TestE2EUsageSnapshotPerEpochAndDirection(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	p := newE2EProtectorForTest(t, root, DirectionResponderToInitiator, srcID, dstID, id, SessionClassStream)
	if _, ok := p.UsageSnapshot(); ok {
		t.Fatal("snapshot before InstallEpoch should not be ok")
	}
	if err := p.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	pt := []byte("ab")
	if _, err := p.Seal(newE2EFrameForTest(e2eTestWireID, dstID, srcID, id, 1, 0, len(pt)), pt); err != nil {
		t.Fatalf("seal: %v", err)
	}
	snap, ok := p.UsageSnapshot()
	if !ok || snap.Epoch != 1 || snap.Direction != DirectionResponderToInitiator {
		t.Fatalf("snapshot = %+v ok=%v", snap, ok)
	}
	if snap.SealInvocations != 1 || snap.SealBytes != uint64(len(pt)) || snap.OpenInvocations != 0 {
		t.Fatalf("snapshot counters = %+v", snap)
	}
}

func TestE2EGraceDefault30sVersusPolicy60s(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root1 := e2eTestRoot(0x11).Encode()
	root2 := e2eTestRoot(0x21).Encode()

	now := time.Now()
	clock := func() time.Time { return now }
	// Default grace is the frozen 30s.
	def, err := NewE2EProtector(e2eTestConfig(root1, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Clock: clock})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := def.InstallEpoch(1, root1); err != nil {
		t.Fatalf("install1: %v", err)
	}
	if err := def.InstallEpoch(2, root2); err != nil {
		t.Fatalf("install2: %v", err)
	}
	// First authenticated epoch-2 frame starts the grace clock.
	n2 := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 2, 0, 2)
	s2, err := def.Seal(n2, []byte("ab"))
	if err != nil {
		t.Fatalf("seal e2: %v", err)
	}
	if _, err := def.Open(s2); err != nil {
		t.Fatalf("open e2: %v", err)
	}
	now = now.Add(31 * time.Second)
	old := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, 2)
	if _, err := def.Seal(old, []byte("ab")); !errors.Is(err, ErrE2EEpochMismatch) {
		t.Fatalf("default grace did not expire at 31s: %v", err)
	}

	// A 60s policy keeps the previous epoch at 31s and releases it after 61s.
	now = time.Now()
	long, err := NewE2EProtector(e2eTestConfig(root1, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{GracePeriod: time.Minute, Clock: clock})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := long.InstallEpoch(1, root1); err != nil {
		t.Fatalf("install1: %v", err)
	}
	if err := long.InstallEpoch(2, root2); err != nil {
		t.Fatalf("install2: %v", err)
	}
	ls, err := long.Seal(n2, []byte("ab"))
	if err != nil {
		t.Fatalf("seal e2: %v", err)
	}
	if _, err := long.Open(ls); err != nil {
		t.Fatalf("open e2: %v", err)
	}
	now = now.Add(31 * time.Second)
	o1 := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, 2)
	sealedOld, err := long.Seal(o1, []byte("ab"))
	if err != nil {
		t.Fatalf("60s policy dropped previous too early: %v", err)
	}
	if _, err := long.Open(sealedOld); err != nil {
		t.Fatalf("60s policy previous open: %v", err)
	}
	now = now.Add(30 * time.Second)
	o2 := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 1, 2)
	if _, err := long.Seal(o2, []byte("ab")); !errors.Is(err, ErrE2EEpochMismatch) {
		t.Fatalf("60s policy did not expire after 61s: %v", err)
	}
}

func TestE2ERepeatedThirdInstallRetainedAndTwoEpochContinuity(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	now := time.Now()
	root1 := e2eTestRoot(0x11).Encode()
	root2 := e2eTestRoot(0x21).Encode()
	root3 := e2eTestRoot(0x31).Encode()
	p, err := NewE2EProtector(e2eTestConfig(root1, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{GracePeriod: time.Minute, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := p.InstallEpoch(1, root1); err != nil {
		t.Fatalf("install1: %v", err)
	}
	// Epoch 1 continuity.
	e1 := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, 2)
	s1, err := p.Seal(e1, []byte("ab"))
	if err != nil {
		t.Fatalf("seal e1: %v", err)
	}
	if _, err := p.Open(s1); err != nil {
		t.Fatalf("open e1: %v", err)
	}
	if err := p.InstallEpoch(2, root2); err != nil {
		t.Fatalf("install2: %v", err)
	}
	e2 := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 2, 0, 2)
	s2, err := p.Seal(e2, []byte("ab"))
	if err != nil {
		t.Fatalf("seal e2: %v", err)
	}
	if _, err := p.Open(s2); err != nil {
		t.Fatalf("open e2: %v", err)
	}
	// Old epoch 1 still works inside grace, i.e. continuity across two epochs.
	old := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 1, 2)
	sold, err := p.Seal(old, []byte("ab"))
	if err != nil {
		t.Fatalf("seal old: %v", err)
	}
	if _, err := p.Open(sold); err != nil {
		t.Fatalf("open old: %v", err)
	}
	// Repeated third installs are all refused without mutating state.
	for i := 0; i < 4; i++ {
		if err := p.InstallEpoch(3, root3); !errors.Is(err, ErrEpochRetained) {
			t.Fatalf("repeated third install %d: %v", i, err)
		}
		if got := p.CurrentEpoch(); got != 2 {
			t.Fatalf("current epoch mutated to %d", got)
		}
	}
	now = now.Add(2 * time.Minute)
	if err := p.InstallEpoch(3, root3); err != nil {
		t.Fatalf("third install after grace: %v", err)
	}
	released := newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 2, 2)
	released.Body = make([]byte, 2+chacha20poly1305.Overhead)
	if _, err := p.Open(released); !errors.Is(err, ErrE2EEpochMismatch) {
		t.Fatalf("epoch1 after release: %v", err)
	}
}

func TestSessionRootEpochAtomicAPI(t *testing.T) {
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
	if _, ok := sessionA.RootEpoch(); ok {
		t.Fatal("RootEpoch before READY should not be ok")
	}
	attempt := sessionA.Attempt()
	ctrl := SessionCtrl{SessionID: sessionA.ID(), Class: SessionClassStream, DataLaneID: LaneStream, Attempt: attempt.Attempt, TargetEpoch: attempt.TargetEpoch, PathID: e2eTestPathID, PathGeneration: e2eTestPathGeneration, SrcNodeID: idA.NodeID, DstNodeID: idB.NodeID, Payload: attempt.Bytes}
	sessionB, reply, err := managerB.HandleOpen(ctx, ctrl)
	if err != nil {
		t.Fatalf("handle open B: %v", err)
	}
	replyCtrl := ctrl
	replyCtrl.Payload = reply
	if _, _, err := managerA.HandleOpen(ctx, replyCtrl); err != nil {
		t.Fatalf("finish A: %v", err)
	}
	ready := SessionReady{SessionID: sessionA.ID(), Class: SessionClassStream, DataLaneID: LaneStream, Attempt: attempt.Attempt, TargetEpoch: attempt.TargetEpoch, PathID: e2eTestPathID, PathGeneration: e2eTestPathGeneration, SrcNodeID: idA.NodeID, DstNodeID: idB.NodeID}
	if err := managerA.HandleReady(ready); err != nil {
		t.Fatalf("ready A: %v", err)
	}
	if err := managerB.HandleReady(ready); err != nil {
		t.Fatalf("ready B: %v", err)
	}
	re, ok := sessionA.RootEpoch()
	if !ok || re.Epoch != 1 || len(re.Root) != SessionRootSize || !bytes.Equal(re.Root, sessionA.Root()) {
		t.Fatalf("RootEpoch = %+v ok=%v", re, ok)
	}
	// The typed pair installs the matching protector epoch directly.
	protector := newE2EProtectorForTest(t, re.Root, DirectionInitiatorToResponder, idA.NodeID, idB.NodeID, sessionA.ID(), SessionClassStream)
	if err := protector.InstallEpoch(re.Epoch, re.Root); err != nil {
		t.Fatalf("install from RootEpoch: %v", err)
	}
	_ = sessionB
}

type e2eTestBudget struct {
	mu       sync.Mutex
	limit    int
	failures int
}

func (b *e2eTestBudget) RecordFailure() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	return b.failures <= b.limit
}

func (b *e2eTestBudget) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failures
}

func TestE2ETXOnlyMarkPeerNewEpochStartsRetirement(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	now := time.Now()
	root1 := e2eTestRoot(0x11).Encode()
	root2 := e2eTestRoot(0x21).Encode()
	root3 := e2eTestRoot(0x31).Encode()
	clock := func() time.Time { return now }

	// A TX-only protector never Opens, so the frozen RX-grace trigger never
	// fires and the third install would be stuck forever.
	tx, err := NewE2EProtector(e2eTestConfig(root1, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Clock: clock})
	if err != nil {
		t.Fatalf("tx protector: %v", err)
	}
	if err := tx.InstallEpoch(1, root1); err != nil {
		t.Fatalf("tx install1: %v", err)
	}
	if err := tx.InstallEpoch(2, root2); err != nil {
		t.Fatalf("tx install2: %v", err)
	}
	if err := tx.CanInstallEpoch(3); !errors.Is(err, ErrEpochRetained) {
		t.Fatalf("TX third install should be retained before peer evidence: %v", err)
	}
	if err := tx.InstallEpoch(3, root3); !errors.Is(err, ErrEpochRetained) {
		t.Fatalf("TX third install: %v", err)
	}
	// Only the trusted current-epoch event is accepted.
	if err := tx.MarkPeerNewEpochAuthenticated(1); !errors.Is(err, ErrE2EEpochMismatch) {
		t.Fatalf("stale peer epoch: %v", err)
	}
	if err := tx.MarkPeerNewEpochAuthenticated(3); !errors.Is(err, ErrE2EEpochMismatch) {
		t.Fatalf("future peer epoch: %v", err)
	}
	if err := tx.MarkPeerNewEpochAuthenticated(2); err != nil {
		t.Fatalf("peer epoch event: %v", err)
	}
	if err := tx.MarkPeerNewEpochAuthenticated(2); err != nil {
		t.Fatalf("idempotent peer epoch event: %v", err)
	}
	// The 30s retirement window is now running.
	if err := tx.CanInstallEpoch(3); !errors.Is(err, ErrEpochRetained) {
		t.Fatalf("TX third install inside grace: %v", err)
	}
	now = now.Add(31 * time.Second)
	if err := tx.CanInstallEpoch(3); err != nil {
		t.Fatalf("TX third install after grace: %v", err)
	}
	if err := tx.InstallEpoch(3, root3); err != nil {
		t.Fatalf("TX install3: %v", err)
	}
	if got := tx.CurrentEpoch(); got != 3 {
		t.Fatalf("TX current epoch = %d", got)
	}

	// RX baseline: an RX protector reaches the same state by opening the first
	// authenticated current-epoch frame.
	now2 := time.Now()
	rx, err := NewE2EProtector(e2eTestConfig(root1, DirectionResponderToInitiator, srcID, dstID, id, SessionClassStream), E2EPolicy{Clock: func() time.Time { return now2 }})
	if err != nil {
		t.Fatalf("rx protector: %v", err)
	}
	if err := rx.InstallEpoch(1, root1); err != nil {
		t.Fatalf("rx install1: %v", err)
	}
	if err := rx.InstallEpoch(2, root2); err != nil {
		t.Fatalf("rx install2: %v", err)
	}
	if err := rx.CanInstallEpoch(3); !errors.Is(err, ErrEpochRetained) {
		t.Fatalf("RX third install before new-epoch RX: %v", err)
	}
	peer, err := NewE2EProtector(e2eTestConfig(root2, DirectionResponderToInitiator, srcID, dstID, id, SessionClassStream), E2EPolicy{Clock: func() time.Time { return now2 }})
	if err != nil {
		t.Fatalf("peer protector: %v", err)
	}
	if err := peer.InstallEpoch(2, root2); err != nil {
		t.Fatalf("peer install: %v", err)
	}
	frame := newE2EFrameForTest(e2eTestWireID, dstID, srcID, id, 2, 0, 2)
	sealed, err := peer.Seal(frame, []byte("ab"))
	if err != nil {
		t.Fatalf("peer seal: %v", err)
	}
	if _, err := rx.Open(sealed); err != nil {
		t.Fatalf("rx open new epoch: %v", err)
	}
	if err := rx.CanInstallEpoch(3); !errors.Is(err, ErrEpochRetained) {
		t.Fatalf("RX third install inside grace: %v", err)
	}
	now2 = now2.Add(31 * time.Second)
	if err := rx.CanInstallEpoch(3); err != nil {
		t.Fatalf("RX third install after grace: %v", err)
	}
}

func TestE2ECanInstallEpochPreflightNonMutating(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	now := time.Now()
	root1 := e2eTestRoot(0x11).Encode()
	root2 := e2eTestRoot(0x21).Encode()
	root3 := e2eTestRoot(0x31).Encode()
	p, err := NewE2EProtector(e2eTestConfig(root1, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if err := p.InstallEpoch(1, root1); err != nil {
		t.Fatalf("install1: %v", err)
	}
	if err := p.InstallEpoch(2, root2); err != nil {
		t.Fatalf("install2: %v", err)
	}
	if err := p.CanInstallEpoch(4); !errors.Is(err, ErrE2EEpochMismatch) {
		t.Fatalf("gap preflight: %v", err)
	}
	if err := p.CanInstallEpoch(^uint32(0)); !errors.Is(err, ErrEpochExhausted) {
		t.Fatalf("wrap preflight: %v", err)
	}
	if err := p.CanInstallEpoch(3); !errors.Is(err, ErrEpochRetained) {
		t.Fatalf("retained preflight: %v", err)
	}
	// Preflight must not mutate: a repeated real install still behaves.
	if got := p.CurrentEpoch(); got != 2 {
		t.Fatalf("preflight mutated current epoch to %d", got)
	}
	if err := p.InstallEpoch(3, root3); !errors.Is(err, ErrEpochRetained) {
		t.Fatalf("install after preflight: %v", err)
	}
	// Trusted peer-epoch evidence starts the retirement window; only then does
	// time release it. Preflight changed neither.
	if err := p.MarkPeerNewEpochAuthenticated(2); err != nil {
		t.Fatalf("peer epoch event: %v", err)
	}
	now = now.Add(31 * time.Second)
	if err := p.CanInstallEpoch(3); err != nil {
		t.Fatalf("preflight after grace: %v", err)
	}
	if err := p.InstallEpoch(3, root3); err != nil {
		t.Fatalf("install after grace: %v", err)
	}
	p.Close()
	if err := p.CanInstallEpoch(4); !errors.Is(err, ErrE2EClosed) {
		t.Fatalf("closed preflight: %v", err)
	}
}

func TestE2EVerificationBudgetSharedAcrossProtectors(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	budget := &e2eTestBudget{limit: 2}

	tx, err := NewE2EProtector(e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{})
	if err != nil {
		t.Fatalf("tx protector: %v", err)
	}
	rx, err := NewE2EProtector(e2eTestConfig(root, DirectionResponderToInitiator, srcID, dstID, id, SessionClassStream), E2EPolicy{})
	if err != nil {
		t.Fatalf("rx protector: %v", err)
	}
	// Inject the same budget object into both protectors.
	tx.budget = budget
	rx.budget = budget
	if err := tx.InstallEpoch(1, root); err != nil {
		t.Fatalf("tx install: %v", err)
	}
	if err := rx.InstallEpoch(1, root); err != nil {
		t.Fatalf("rx install: %v", err)
	}

	pt := []byte("ab")
	genuine, err := tx.Seal(newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, len(pt)), pt)
	if err != nil {
		t.Fatalf("tx seal: %v", err)
	}
	tampered1 := wire.Frame{Kind: genuine.Kind, Envelope: append([]byte(nil), genuine.Envelope...), Body: append([]byte(nil), genuine.Body...)}
	tampered1.Body[0] ^= 0xFF

	rxGenuine, err := rx.Seal(newE2EFrameForTest(e2eTestWireID, dstID, srcID, id, 1, 0, len(pt)), pt)
	if err != nil {
		t.Fatalf("rx seal: %v", err)
	}
	tampered2 := wire.Frame{Kind: rxGenuine.Kind, Envelope: append([]byte(nil), rxGenuine.Envelope...), Body: append([]byte(nil), rxGenuine.Body...)}
	tampered2.Body[0] ^= 0xFF

	// Two failures on two protectors stay inside the shared ceiling.
	if _, err := tx.Open(tampered1); !errors.Is(err, ErrE2EAuthentication) {
		t.Fatalf("first shared failure: %v", err)
	}
	if _, err := rx.Open(tampered2); !errors.Is(err, ErrE2EAuthentication) {
		t.Fatalf("second shared failure: %v", err)
	}
	// The third failure exhausts the shared budget and fails closed.
	if _, err := tx.Open(tampered1); !errors.Is(err, ErrKeyUsageExhausted) {
		t.Fatalf("shared budget exhaustion: %v", err)
	}
	if got := budget.count(); got != 3 {
		t.Fatalf("budget recorded %d failures", got)
	}
	// No replay/epoch/root state was touched by the failed attempts: the
	// genuine frame still opens.
	if _, err := tx.Open(genuine); err != nil {
		t.Fatalf("genuine frame after exhausted budget: %v", err)
	}
	if got := tx.CurrentEpoch(); got != 1 {
		t.Fatalf("epoch advanced after budget exhaustion: %d", got)
	}
}

func TestE2EVerificationBudgetNilUsesPerKeyCeiling(t *testing.T) {
	id := sessionID(0x40)
	srcID := cryptoTestNodeID(0x20)
	dstID := cryptoTestNodeID(0x30)
	root := e2eTestRoot(0x11).Encode()
	p, err := NewE2EProtector(e2eTestConfig(root, DirectionInitiatorToResponder, srcID, dstID, id, SessionClassStream), E2EPolicy{Usage: UsagePolicy{MaxAuthFailures: 2}})
	if err != nil {
		t.Fatalf("protector: %v", err)
	}
	if p.budget != nil {
		t.Fatal("nil-cfg budget should stay nil")
	}
	if err := p.InstallEpoch(1, root); err != nil {
		t.Fatalf("install: %v", err)
	}
	pt := []byte("ab")
	sealed, err := p.Seal(newE2EFrameForTest(e2eTestWireID, srcID, dstID, id, 1, 0, len(pt)), pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	tampered := wire.Frame{Kind: sealed.Kind, Envelope: append([]byte(nil), sealed.Envelope...), Body: append([]byte(nil), sealed.Body...)}
	tampered.Body[0] ^= 0xFF
	for i := 0; i < 2; i++ {
		if _, err := p.Open(tampered); !errors.Is(err, ErrE2EAuthentication) {
			t.Fatalf("per-key failure %d: %v", i, err)
		}
	}
	if _, err := p.Open(tampered); !errors.Is(err, ErrKeyUsageExhausted) {
		t.Fatalf("per-key ceiling did not fail closed: %v", err)
	}
}
