package link

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/wire"
)

func TestHandshakeResponderAdoptsWireMetadata(t *testing.T) {
	alice, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	psk := sha256.Sum256([]byte("adopt metadata"))
	descriptor := []byte("descriptor-adopt")
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	results := make(chan result, 2)
	go func() {
		results <- runHandshake(left, LinkConfig{Descriptor: descriptor, PSK: psk, Identity: alice, LinkID: 41, LinkEpoch: 7, Generation: 9, LaneID: 2, Initiator: true, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	go func() {
		results <- runHandshake(right, LinkConfig{Descriptor: descriptor, PSK: psk, Identity: bob, Initiator: false, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("adopted metadata handshake errors: %v / %v", first.err, second.err)
	}
	for _, got := range []LinkResult{first.value, second.value} {
		if got.LinkID != 41 || got.LinkEpoch != 7 || got.Generation != 9 || got.LaneID != 2 {
			t.Fatalf("adopted metadata = %d/%d/%d/%d", got.LinkID, got.LinkEpoch, got.Generation, got.LaneID)
		}
	}
}

func TestHandshakeResponderRejectsExpectedMetadataMismatch(t *testing.T) {
	alice, _ := security.GenerateIdentity()
	bob, _ := security.GenerateIdentity()
	psk := sha256.Sum256([]byte("metadata mismatch"))
	left, right := net.Pipe()
	results := make(chan result, 2)
	go func() {
		results <- runHandshake(left, LinkConfig{Descriptor: []byte("descriptor"), PSK: psk, Identity: alice, LinkID: 41, LinkEpoch: 7, Generation: 9, LaneID: 2, Initiator: true, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	go func() {
		results <- runHandshake(right, LinkConfig{Descriptor: []byte("descriptor"), PSK: psk, Identity: bob, LinkID: 99, LinkEpoch: 7, Generation: 9, LaneID: 2, HasExpectedMetadata: true, Initiator: false, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	select {
	case first := <-results:
		if first.err == nil {
			t.Fatal("metadata mismatch was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("metadata mismatch handshake did not fail promptly")
	}
	_ = left.Close()
	_ = right.Close()
	select {
	case <-results:
	case <-time.After(time.Second):
		t.Fatal("peer handshake did not unblock after mismatch close")
	}
}

func TestHandshakeResponderStrictlyRejectsControlLaneMismatch(t *testing.T) {
	alice, _ := security.GenerateIdentity()
	bob, _ := security.GenerateIdentity()
	psk := sha256.Sum256([]byte("strict lane mismatch"))
	left, right := net.Pipe()
	results := make(chan result, 2)
	go func() {
		results <- runHandshake(left, LinkConfig{Descriptor: []byte("descriptor"), PSK: psk, Identity: alice, LinkID: 41, LinkEpoch: 7, Generation: 9, LaneID: 1, Initiator: true, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	go func() {
		results <- runHandshake(right, LinkConfig{Descriptor: []byte("descriptor"), PSK: psk, Identity: bob, LinkID: 41, LinkEpoch: 7, Generation: 9, LaneID: 0, HasExpectedMetadata: true, Initiator: false, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	first, second := <-results, <-results
	if first.err == nil && second.err == nil {
		t.Fatal("strict lane mismatch was accepted")
	}
}

func TestHandshakeResponderRejectsMalformedInitialRecord(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	identity, _ := security.GenerateIdentity()
	result := make(chan error, 1)
	go func() {
		_, err := Handshake(context.Background(), right, LinkConfig{Descriptor: []byte("descriptor"), PSK: sha256.Sum256([]byte("psk")), Identity: identity, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
		result <- err
	}()
	if _, err := left.Write([]byte{0, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}
	_ = left.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("malformed initial record was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("malformed initial record did not fail promptly")
	}
}

func TestLinkPrologueMatchesNetworkContextLayout(t *testing.T) {
	network, err := security.NewNetworkContext("mesh-a", "10.30.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cfg := LinkConfig{Descriptor: network.Descriptor(), NetworkID: 0x95678609d624abc7, LinkID: 0x0102030405060708, LinkEpoch: 0x1112131415161718, Generation: 0x19202122, LaneID: 2}
	got := makePrologue(cfg)
	wantPrefix := []byte("simpletier-v1/prologue")
	if !bytes.HasPrefix(got, wantPrefix) {
		t.Fatal("Link prologue prefix differs from NetworkContext")
	}
	offset := len(wantPrefix)
	readField := func(want []byte) {
		t.Helper()
		if len(got) < offset+4 {
			t.Fatal("prologue ended before field length")
		}
		length := int(binary.BigEndian.Uint32(got[offset : offset+4]))
		offset += 4
		if length != len(want) || len(got) < offset+length || !bytes.Equal(got[offset:offset+length], want) {
			t.Fatalf("prologue field length=%d, want %d", length, len(want))
		}
		offset += length
	}
	readField([]byte("simpletier-v1/link"))
	readField(network.Descriptor())
	// Independent fixed bytes: NetworkID8 | LinkID8 | Epoch8 | Generation4 | Lane1.
	binding := []byte{0x95, 0x67, 0x86, 0x09, 0xd6, 0x24, 0xab, 0xc7, 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 2}
	if len(binding) != 29 {
		t.Fatal("invalid independent binding fixture")
	}
	readField(binding)
	if offset != len(got) {
		t.Fatalf("prologue has %d trailing bytes", len(got)-offset)
	}
	want, err := network.Prologue("simpletier-v1/link", binding)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("Link prologue differs from the exact NetworkContext contract")
	}
	changed := cfg
	changed.NetworkID ^= 1
	if bytes.Equal(makePrologue(changed), got) {
		t.Fatal("wire locator was not bound into prologue")
	}
	changed.NetworkID = 0
	zeroBinding := append([]byte(nil), binding...)
	clear(zeroBinding[:8])
	want, err = network.Prologue("simpletier-v1/link", zeroBinding)
	if err != nil || !bytes.Equal(makePrologue(changed), want) {
		t.Fatal("zero wire locator must remain an explicit valid binding")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestHandshakeOverPipeAuthenticatesBothDirections(t *testing.T) {
	alice, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	psk := sha256.Sum256([]byte("test network token"))
	descriptor := []byte("simpletier/v1/network\x00mesh\x0010.20.0.0/24")
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	results := make(chan result, 2)
	go func() {
		results <- runHandshake(left, LinkConfig{Descriptor: descriptor, PSK: psk, Identity: alice, LinkID: 1, LinkEpoch: 1, Generation: 7, LaneID: 0, Initiator: true, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	go func() {
		results <- runHandshake(right, LinkConfig{Descriptor: descriptor, PSK: psk, Identity: bob, LinkID: 1, LinkEpoch: 1, Generation: 7, LaneID: 0, Initiator: false, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("handshake errors: %v / %v", first.err, second.err)
	}
	if first.value.PeerNodeID == first.value.LocalNodeID || second.value.PeerNodeID == second.value.LocalNodeID {
		t.Fatal("peer identity not authenticated")
	}
	if first.value.PeerNodeID != second.value.LocalNodeID || second.value.PeerNodeID != first.value.LocalNodeID {
		t.Fatal("peer NodeID mismatch")
	}
	if first.value.TxRoot != second.value.RxRoot || first.value.RxRoot != second.value.TxRoot {
		t.Fatal("directional roots are not reversed")
	}
	if string(first.value.ChannelBinding) != string(second.value.ChannelBinding) {
		t.Fatal("channel bindings differ")
	}
}

func TestHandshakeRejectsMismatchedContext(t *testing.T) {
	alice, _ := security.GenerateIdentity()
	bob, _ := security.GenerateIdentity()
	psk := sha256.Sum256([]byte("shared context token"))
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	results := make(chan result, 2)
	go func() {
		results <- runHandshake(left, LinkConfig{Descriptor: []byte("descriptor-a"), PSK: psk, Identity: alice, LinkID: 4, LinkEpoch: 1, Generation: 10, LaneID: 0, Initiator: true, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	go func() {
		results <- runHandshake(right, LinkConfig{Descriptor: []byte("descriptor-b"), PSK: psk, Identity: bob, LinkID: 4, LinkEpoch: 1, Generation: 10, LaneID: 0, Initiator: false, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	first, second := <-results, <-results
	if first.err == nil && second.err == nil {
		t.Fatal("mismatched NetworkContext descriptor was accepted")
	}
}

func TestHandshakeRejectsWrongPSKAndStaticPeer(t *testing.T) {
	alice, _ := security.GenerateIdentity()
	bob, _ := security.GenerateIdentity()
	psk := sha256.Sum256([]byte("right"))
	wrong := sha256.Sum256([]byte("wrong"))
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	results := make(chan result, 2)
	go func() {
		results <- runHandshake(left, LinkConfig{Descriptor: []byte("ctx"), PSK: psk, Identity: alice, LinkID: 2, LinkEpoch: 1, Generation: 8, Initiator: true, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	go func() {
		results <- runHandshake(right, LinkConfig{Descriptor: []byte("ctx"), PSK: wrong, Identity: bob, LinkID: 2, LinkEpoch: 1, Generation: 8, Initiator: false, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	if a, b := <-results, <-results; a.err == nil && b.err == nil {
		t.Fatal("wrong PSK was accepted")
	}
}

func TestHandshakeRejectsCapabilityMismatch(t *testing.T) {
	alice, _ := security.GenerateIdentity()
	bob, _ := security.GenerateIdentity()
	psk := sha256.Sum256([]byte("psk"))
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	results := make(chan result, 2)
	go func() {
		results <- runHandshake(left, LinkConfig{Descriptor: []byte("ctx"), PSK: psk, Identity: alice, LinkID: 3, LinkEpoch: 1, Generation: 9, Initiator: true, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	go func() {
		results <- runHandshake(right, LinkConfig{Descriptor: []byte("ctx"), PSK: psk, Identity: bob, LinkID: 3, LinkEpoch: 1, Generation: 9, Initiator: false, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask &^ 1, RequiredCapabilityMask: RequiredCapabilityMask})
	}()
	if a, b := <-results, <-results; a.err == nil && b.err == nil {
		t.Fatal("capability mismatch was accepted")
	}
}

func TestHandshakeRejectsMalformedConfig(t *testing.T) {
	identity, _ := security.GenerateIdentity()
	mismatched := identity
	mismatched.NodeID[0] ^= 1
	if _, err := Handshake(context.Background(), &stubStream{}, LinkConfig{Descriptor: []byte("ctx"), PSK: sha256.Sum256([]byte("psk")), Identity: mismatched, LinkID: 1, LinkEpoch: 1, Generation: 1, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask}); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("inconsistent identity = %v", err)
	}
	var typedNil *stubStream
	if _, err := Handshake(context.Background(), typedNil, LinkConfig{Descriptor: []byte("ctx"), PSK: sha256.Sum256([]byte("psk")), Identity: identity, LinkID: 1, LinkEpoch: 1, Generation: 1, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask}); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("typed-nil stream = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Handshake(ctx, &stubStream{}, LinkConfig{Identity: identity}); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("invalid config = %v", err)
	}
}

func TestCapabilityUsesFrozenLinkControlFrame(t *testing.T) {
	cfg := testRealLinkConfig(t, true)
	root := sha256.Sum256([]byte("capability test root"))
	var encoded capabilityBuffer
	if err := writeCapability(context.Background(), &encoded, root, cfg, nil); err != nil {
		t.Fatal(err)
	}
	frame, err := wire.ReadFrame(&encoded)
	if err != nil {
		t.Fatal("capability was not a normal bounded LINK_CTRL frame:", err)
	}
	if frame.Kind != wire.FrameKindLinkControl || frame.Envelope != nil || binary.BigEndian.Uint32(frame.HopHeader[:4]) != cfg.Generation || binary.BigEndian.Uint64(frame.HopHeader[4:12]) != 0 || !bytes.Equal(frame.HopHeader[12:], make([]byte, 20)) {
		t.Fatal("invalid initial control header")
	}
	protector, err := NewFrameProtector(root, cfg.Descriptor, cfg.LinkID, [16]byte{}, SessionClassStream, DirectionInitiatorToResponder)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := protector.Open(frame)
	if err != nil || !bytes.Equal(plain, []byte{4, 2, 0, 0, 0, 0, 0, 0, 0, 0x7f}) {
		t.Fatalf("authenticated capability payload=%x error=%v", plain, err)
	}
}

func TestHandshakeRejectsSubsetCapabilityBeforeOwnership(t *testing.T) {
	cfg := testRealLinkConfig(t, true)
	cfg.CapabilityMask, cfg.RequiredCapabilityMask = 3, 1
	stream := &ownedTestStream{}
	if _, err := Handshake(context.Background(), stream, cfg); !errors.Is(err, ErrInvalidLink) || stream.closes.Load() != 0 {
		t.Fatalf("subset capability validation=%v closes=%d", err, stream.closes.Load())
	}
}

func TestHandshakeGenericStreamCancelClosesOwnedAttempt(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	cfg := testRealLinkConfig(t, false)
	stream := &ownedTestStream{stream: right, entered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Handshake(ctx, stream, cfg); done <- err }()
	select {
	case <-stream.entered:
	case <-time.After(time.Second):
		t.Fatal("generic stream did not enter read")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || stream.closes.Load() != 1 {
			t.Fatalf("generic cancellation=%v closes=%d", err, stream.closes.Load())
		}
	case <-time.After(time.Second):
		_ = stream.Close()
		t.Fatal("generic stream cancel did not interrupt read")
	}
}

func TestHandshakeRealContextAndSuccessLifetime(t *testing.T) {
	a, b := testRealLinkConfig(t, true), testRealLinkConfig(t, false)
	network, err := security.NewNetworkContext("mesh-a", "10.30.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	binding := make([]byte, 29)
	binary.BigEndian.PutUint64(binding[:8], network.WireID())
	binary.BigEndian.PutUint64(binding[8:16], a.LinkID)
	binary.BigEndian.PutUint64(binding[16:24], a.LinkEpoch)
	binary.BigEndian.PutUint32(binding[24:28], a.Generation)
	binding[28] = a.LaneID
	want, err := network.Prologue("simpletier-v1/link", binding)
	if err != nil || !bytes.Equal(makePrologue(a), want) {
		t.Fatal("Link prologue differs from full NetworkContext")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	first, second := &ownedTestStream{stream: left}, &ownedTestStream{stream: right}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ar, br := handshakePair(t, ctx, first, second, a, b)
	if ar.err != nil || br.err != nil {
		t.Fatalf("real context handshake: %v / %v", ar.err, br.err)
	}
	if ar.value.PeerStatic != b.Identity.PublicKey || br.value.PeerStatic != a.Identity.PublicKey || ar.value.TxRoot != br.value.RxRoot || ar.value.RxRoot != br.value.TxRoot || !bytes.Equal(ar.value.ChannelBinding, br.value.ChannelBinding) {
		t.Fatal("identity/key direction/transcript not bound")
	}
	cancel()
	if first.closes.Load() != 0 || second.closes.Load() != 0 {
		t.Fatal("successful establishment context owns stream lifetime")
	}
	if err := left.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := right.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { _, err := first.Write([]byte{0xab}); written <- err }()
	var data [1]byte
	if _, err := io.ReadFull(second, data[:]); err != nil || data[0] != 0xab {
		t.Fatalf("successful stream handoff: %x %v", data, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeRealContextFailuresCloseBothAttempts(t *testing.T) {
	for _, scenario := range []string{"token", "name", "cidr", "peer-static"} {
		t.Run(scenario, func(t *testing.T) {
			a, b := testRealLinkConfig(t, true), testRealLinkConfig(t, false)
			if scenario == "peer-static" {
				a.HasExpectedPeer = true
				a.ExpectedPeerStatic = a.Identity.PublicKey
			} else {
				name, cidr, token := "mesh-a", "10.30.0.0/24", "0123456789abcdef0123456789abcdef"
				switch scenario {
				case "token":
					token = "wrong-token"
				case "name":
					name = "mesh-b"
				case "cidr":
					cidr = "10.31.0.0/24"
				}
				network, err := security.NewNetworkContext(name, cidr)
				if err != nil {
					t.Fatal(err)
				}
				b.Descriptor = network.Descriptor()
				b.PSK, err = network.DerivePSK(token)
				if err != nil {
					t.Fatal(err)
				}
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			first, second := &ownedTestStream{stream: left}, &ownedTestStream{stream: right}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ar, br := handshakePair(t, ctx, first, second, a, b)
			if ar.err == nil || br.err == nil || first.closes.Load() != 1 || second.closes.Load() != 1 {
				t.Fatalf("%s failure ownership: %v / %v counts %d/%d", scenario, ar.err, br.err, first.closes.Load(), second.closes.Load())
			}
		})
	}
}

func TestHandshakeGenericDeadlineAndTruncationClose(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "truncated"}[truncated], func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			cfg := testRealLinkConfig(t, false)
			stream := &ownedTestStream{stream: right}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := Handshake(ctx, stream, cfg); done <- err }()
			if truncated {
				if _, err := left.Write([]byte{0, 0}); err != nil {
					t.Fatal(err)
				}
				_ = left.Close()
			}
			select {
			case err := <-done:
				if err == nil || stream.closes.Load() != 1 {
					t.Fatalf("failed attempt=%v closes=%d", err, stream.closes.Load())
				}
				if !truncated && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("deadline error=%v", err)
				}
				if truncated && !errors.Is(err, wire.ErrTruncatedHandshake) {
					t.Fatalf("truncation error=%v", err)
				}
			case <-time.After(time.Second):
				_ = stream.Close()
				t.Fatal("failed generic attempt did not finish")
			}
		})
	}
}

func handshakePair(t *testing.T, ctx context.Context, left, right linkStream, a, b LinkConfig) (result, result) {
	t.Helper()
	first, second := make(chan result, 1), make(chan result, 1)
	go func() { value, err := Handshake(ctx, left, a); first <- result{value, err} }()
	go func() { value, err := Handshake(ctx, right, b); second <- result{value, err} }()
	var ar, br result
	select {
	case ar = <-first:
	case <-time.After(2 * time.Second):
		_ = left.Close()
		_ = right.Close()
		t.Fatal("initiator did not finish")
	}
	select {
	case br = <-second:
	case <-time.After(2 * time.Second):
		_ = left.Close()
		_ = right.Close()
		t.Fatal("responder did not finish")
	}
	return ar, br
}

func TestCapabilityRejectsTamperingAndReservedHeader(t *testing.T) {
	cfg := testRealLinkConfig(t, true)
	root := sha256.Sum256([]byte("cap mutation root"))
	var buffer capabilityBuffer
	if err := writeCapability(context.Background(), &buffer, root, cfg, nil); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), buffer.Bytes()...)
	cfg.Initiator = false
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"tag", func(data []byte) { data[len(data)-1] ^= 1 }},
		{"reserved-hop", func(data []byte) { data[5+12] = 1 }},
		{"generation", func(data []byte) { data[5] ^= 1 }},
		{"counter", func(data []byte) { data[5+11] = 1 }},
		{"oversized-prefix", func(data []byte) { binary.BigEndian.PutUint32(data[:4], wire.MaxFrameLength) }},
		{"wrong-kind", func(data []byte) { data[4] = byte(wire.FrameKindRouteControl) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := append([]byte(nil), original...)
			test.mutate(data)
			reader := &capabilityBuffer{}
			_, _ = reader.Write(data)
			if _, err := readCapability(context.Background(), reader, root, cfg, nil); err == nil {
				t.Fatal("tampered capability accepted")
			}
		})
	}
	truncated := &capabilityBuffer{}
	_, _ = truncated.Write(original[:len(original)-1])
	if _, err := readCapability(context.Background(), truncated, root, cfg, nil); err == nil {
		t.Fatal("truncated capability accepted")
	}
}

// TestCapabilityRejectsAuthenticatedVersion1Record proves the v1 gate is the
// CAPABILITY codec, not LinkConfig validation: a correctly AEAD-authenticated
// LINK_CTRL record that differs from v2 only in the frozen version byte must be
// rejected by readCapability with ErrCapabilityVersion.
func TestCapabilityRejectsAuthenticatedVersion1Record(t *testing.T) {
	cfg := testRealLinkConfig(t, true)
	root := sha256.Sum256([]byte("capability version mismatch root"))
	// Hand-build the v1 payload because EncodeCapability refuses it.
	payload := make([]byte, capabilityPayloadSize)
	payload[0] = 1
	binary.BigEndian.PutUint64(payload[1:], RequiredCapabilityMask)
	// Same direction/root/nonce the peer would use for its CAPABILITY record.
	protector, err := capabilityProtector(root, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{0x04}, payload...), cfg.Generation, 0)
	if err != nil {
		t.Fatal(err)
	}
	var encoded capabilityBuffer
	if err := wire.WriteFrame(&encoded, frame); err != nil {
		t.Fatal(err)
	}
	_, err = readCapability(context.Background(), &encoded, root, cfg, nil)
	if errors.Is(err, ErrInvalidLink) {
		t.Fatal("v1 record was rejected before the encrypted CAPABILITY was read")
	}
	if !errors.Is(err, ErrCapabilityVersion) {
		t.Fatalf("authenticated v1 capability error = %v; want ErrCapabilityVersion", err)
	}
}

func testRealLinkConfig(t *testing.T, initiator bool) LinkConfig {
	t.Helper()
	context, err := security.NewNetworkContext("mesh-a", "10.30.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	psk, err := context.DerivePSK("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return LinkConfig{Descriptor: context.Descriptor(), NetworkID: context.WireID(), PSK: psk, Identity: identity, LinkID: 41, LinkEpoch: 7, Generation: 9, Initiator: initiator, CapabilityVersion: uint16(CapabilityVersion), CapabilityMask: RequiredCapabilityMask, RequiredCapabilityMask: RequiredCapabilityMask}
}

type capabilityBuffer struct{ bytes.Buffer }

func (*capabilityBuffer) Close() error { return nil }

type ownedTestStream struct {
	stream   io.ReadWriteCloser
	entered  chan struct{}
	readOnce sync.Once
	closes   atomic.Int32
}

func (s *ownedTestStream) Read(p []byte) (int, error) {
	if s.entered != nil {
		s.readOnce.Do(func() { close(s.entered) })
	}
	if s.stream == nil {
		return 0, io.EOF
	}
	return s.stream.Read(p)
}
func (s *ownedTestStream) Write(p []byte) (int, error) {
	if s.stream == nil {
		return 0, io.ErrClosedPipe
	}
	return s.stream.Write(p)
}
func (s *ownedTestStream) Close() error {
	s.closes.Add(1)
	if s.stream == nil {
		return nil
	}
	return s.stream.Close()
}

type result struct {
	value LinkResult
	err   error
}

func runHandshake(stream ioReadWriteCloser, cfg LinkConfig) result {
	value, err := Handshake(context.Background(), stream, cfg)
	if err != nil {
		_ = stream.Close()
	}
	return result{value, err}
}

type ioReadWriteCloser interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}
type stubStream struct{}

func (*stubStream) Read([]byte) (int, error)  { return 0, errors.New("stub") }
func (*stubStream) Write([]byte) (int, error) { return 0, errors.New("stub") }
func (*stubStream) Close() error              { return nil }
