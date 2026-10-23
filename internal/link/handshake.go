package link

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"github.com/flynn/noise"

	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/wire"
)

var (
	ErrInvalidLink        = errors.New("invalid link handshake")
	ErrLinkAuthentication = errors.New("link authentication failed")
	ErrCapabilityMismatch = errors.New("link capability mismatch")
)

type LinkConfig struct {
	Descriptor             []byte
	NetworkID              uint64
	PSK                    [32]byte
	Identity               security.Identity
	LinkID                 uint64
	LinkEpoch              uint64
	Generation             uint32
	LaneID                 uint8
	Initiator              bool
	ExpectedPeerStatic     [32]byte
	HasExpectedPeer        bool
	HasExpectedMetadata    bool
	CapabilityVersion      uint16
	CapabilityMask         uint64
	RequiredCapabilityMask uint64
}

type LinkResult struct {
	// The successful CAPABILITY exchange consumed LINK_CTRL counter 0 in both
	// directions under these roots. Subsequent control transmission starts at 1,
	// and ingress replay tracking must retain the authenticated counter-0 floor.
	PeerStatic  [32]byte
	PeerNodeID  [16]byte
	LocalNodeID [16]byte
	// LocalStatic is the local X25519 static public key of the established
	// Link; the key-update prologue pins both static keys by canonical role.
	LocalStatic       [32]byte
	TxRoot            [32]byte
	RxRoot            [32]byte
	ChannelBinding    []byte
	CapabilityVersion uint16
	CapabilityMask    uint64
	LinkID            uint64
	LinkEpoch         uint64
	Generation        uint32
	LaneID            uint8
}

type linkStream interface {
	io.Reader
	io.Writer
	io.Closer
}

// Handshake performs context-bound Noise XXpsk3 and the frozen encrypted
// LINK_CTRL capability exchange. Validation rejection leaves stream ownership
// unchanged. Once I/O begins, any failure/cancellation closes the stream exactly
// once; success detaches the establishment context and leaves the stream owned by
// the caller. Stream.Close must unblock concurrent I/O. Existing caller deadlines
// are never modified. Split states are exported once into application roots.
func Handshake(ctx context.Context, stream linkStream, cfg LinkConfig) (result LinkResult, err error) {
	if err := validateLinkConfig(ctx, stream, cfg); err != nil {
		return LinkResult{}, err
	}
	cfg.Descriptor = append([]byte(nil), cfg.Descriptor...)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	owned := &handshakeStream{linkStream: stream}
	stream = owned
	var gate sync.Mutex
	detached := false
	stop := context.AfterFunc(ctx, func() {
		gate.Lock()
		defer gate.Unlock()
		if !detached {
			_ = owned.Close()
		}
	})
	defer func() {
		stop()
		gate.Lock()
		contextErr := ctx.Err()
		detached = true
		gate.Unlock()
		if err == nil && contextErr != nil {
			err = contextErr
			result = LinkResult{}
		}
		if err != nil {
			err = errors.Join(err, contextErr, owned.Close())
		}
		cancel()
	}()
	var sequence wire.HandshakeSequence
	var firstPayload []byte
	if !cfg.Initiator {
		if err := checkContext(ctx, stream); err != nil {
			return LinkResult{}, err
		}
		first, err := sequence.Read(stream)
		if err != nil {
			return LinkResult{}, err
		}
		if first.Kind != wire.HandshakeXXMsg1 {
			return LinkResult{}, fmt.Errorf("expected initial XX message: %w", ErrLinkAuthentication)
		}
		if cfg.HasExpectedMetadata {
			if cfg.LinkID != first.LinkID || cfg.LinkEpoch != first.LinkEpoch || cfg.Generation != first.Generation || cfg.LaneID != first.LaneID {
				return LinkResult{}, fmt.Errorf("initiator Link metadata differs from responder expectation: %w", ErrLinkAuthentication)
			}
		} else if (cfg.LinkID != 0 && cfg.LinkID != first.LinkID) ||
			(cfg.LinkEpoch != 0 && cfg.LinkEpoch != first.LinkEpoch) ||
			(cfg.Generation != 0 && cfg.Generation != first.Generation) ||
			(cfg.LaneID != 0 && cfg.LaneID != first.LaneID) {
			return LinkResult{}, fmt.Errorf("initiator Link metadata differs from responder expectation: %w", ErrLinkAuthentication)
		}
		cfg.LinkID, cfg.LinkEpoch, cfg.Generation, cfg.LaneID = first.LinkID, first.LinkEpoch, first.Generation, first.LaneID
		firstPayload = first.Payload
	}
	prologue := makePrologue(cfg)
	static := noise.DHKey{Private: cfg.Identity.PrivateKey.Bytes(), Public: append([]byte(nil), cfg.Identity.PublicKey[:]...)}
	psk := append([]byte(nil), cfg.PSK[:]...)
	defer clear(static.Private)
	defer clear(psk)
	defer clear(cfg.PSK[:])
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:               noise.HandshakeXX,
		Initiator:             cfg.Initiator,
		Prologue:              prologue,
		PresharedKey:          psk,
		PresharedKeyPlacement: 3,
		StaticKeypair:         static,
	})
	if err != nil {
		return LinkResult{}, fmt.Errorf("create Noise state: %w", err)
	}
	var tx, rx *noise.CipherState
	if cfg.Initiator {
		if tx, rx, err = noiseWrite(ctx, stream, &sequence, hs, cfg, wire.HandshakeXXMsg1); err != nil {
			return LinkResult{}, err
		}
		if err = noiseRead(ctx, stream, &sequence, hs, cfg, wire.HandshakeXXMsg2); err != nil {
			return LinkResult{}, err
		}
		var finalTx, finalRx *noise.CipherState
		finalTx, finalRx, err = noiseWrite(ctx, stream, &sequence, hs, cfg, wire.HandshakeXXMsg3)
		if err != nil {
			return LinkResult{}, err
		}
		tx, rx = finalTx, finalRx
	} else {
		if _, _, _, err = hs.ReadMessage(nil, firstPayload); err != nil {
			return LinkResult{}, fmt.Errorf("Noise read %d: %w", wire.HandshakeXXMsg1, err)
		}
		if tx, rx, err = noiseWrite(ctx, stream, &sequence, hs, cfg, wire.HandshakeXXMsg2); err != nil {
			return LinkResult{}, err
		}
		var finalTx, finalRx *noise.CipherState
		finalTx, finalRx, err = noiseReadFinal(ctx, stream, &sequence, hs, cfg, wire.HandshakeXXMsg3)
		if err != nil {
			return LinkResult{}, err
		}
		tx, rx = finalRx, finalTx
	}
	if tx == nil || rx == nil {
		return LinkResult{}, ErrLinkAuthentication
	}
	peer := hs.PeerStatic()
	if len(peer) != 32 {
		return LinkResult{}, fmt.Errorf("peer static key missing: %w", ErrLinkAuthentication)
	}
	var peerStatic [32]byte
	copy(peerStatic[:], peer)
	if cfg.HasExpectedPeer && peerStatic != cfg.ExpectedPeerStatic {
		return LinkResult{}, fmt.Errorf("peer static key mismatch: %w", ErrLinkAuthentication)
	}
	peerNode, err := nodeID(peerStatic[:])
	if err != nil {
		return LinkResult{}, err
	}
	binding := append([]byte(nil), hs.ChannelBinding()...)
	txRoot, rxRoot, err := exportRoots(tx, rx, cfg, binding)
	if err != nil {
		return LinkResult{}, err
	}
	if cfg.Initiator {
		if err := writeCapability(ctx, stream, txRoot, cfg, binding); err != nil {
			return LinkResult{}, err
		}
		remote, err := readCapability(ctx, stream, rxRoot, cfg, binding)
		if err != nil {
			return LinkResult{}, err
		}
		return makeResult(cfg, peerStatic, peerNode, txRoot, rxRoot, binding, remote), nil
	}
	remote, err := readCapability(ctx, stream, rxRoot, cfg, binding)
	if err != nil {
		return LinkResult{}, err
	}
	if err := writeCapability(ctx, stream, txRoot, cfg, binding); err != nil {
		return LinkResult{}, err
	}
	return makeResult(cfg, peerStatic, peerNode, txRoot, rxRoot, binding, remote), nil
}

func validateLinkConfig(ctx context.Context, stream linkStream, cfg LinkConfig) error {
	if ctx == nil || nilLinkStream(stream) || cfg.Identity.PrivateKey == nil || len(cfg.Descriptor) == 0 || cfg.LaneID > 2 || cfg.CapabilityVersion != uint16(CapabilityVersion) || cfg.RequiredCapabilityMask != RequiredCapabilityMask || cfg.CapabilityMask != RequiredCapabilityMask || zeroKey(cfg.PSK) {
		return ErrInvalidLink
	}
	if cfg.Initiator && (cfg.LinkID == 0 || cfg.LinkEpoch == 0 || cfg.Generation == 0) {
		return ErrInvalidLink
	}
	if !cfg.Initiator && cfg.HasExpectedMetadata && (cfg.LinkID == 0 || cfg.LinkEpoch == 0 || cfg.Generation == 0) {
		return ErrInvalidLink
	}
	if !bytes.Equal(cfg.Identity.PrivateKey.PublicKey().Bytes(), cfg.Identity.PublicKey[:]) {
		return ErrInvalidLink
	}
	derivedNode, err := nodeID(cfg.Identity.PublicKey[:])
	if err != nil || derivedNode != cfg.Identity.NodeID {
		return ErrInvalidLink
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func nilLinkStream(stream linkStream) bool {
	if stream == nil {
		return true
	}
	value := reflect.ValueOf(stream)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func makePrologue(cfg LinkConfig) []byte {
	binding := make([]byte, 0, 29)
	binding = binary.BigEndian.AppendUint64(binding, cfg.NetworkID)
	binding = binary.BigEndian.AppendUint64(binding, cfg.LinkID)
	binding = binary.BigEndian.AppendUint64(binding, cfg.LinkEpoch)
	binding = binary.BigEndian.AppendUint32(binding, cfg.Generation)
	binding = append(binding, cfg.LaneID)
	out := []byte("simpletier-v1/prologue")
	out = appendLen(out, []byte("simpletier-v1/link"))
	out = appendLen(out, cfg.Descriptor)
	return appendLen(out, binding)
}

func noiseWrite(ctx context.Context, stream linkStream, seq *wire.HandshakeSequence, hs *noise.HandshakeState, cfg LinkConfig, kind wire.HandshakeKind) (*noise.CipherState, *noise.CipherState, error) {
	if err := checkContext(ctx, stream); err != nil {
		return nil, nil, err
	}
	payload, tx, rx, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("Noise write %d: %w", kind, err)
	}
	record := wire.HandshakeRecord{Kind: kind, LinkID: cfg.LinkID, LinkEpoch: cfg.LinkEpoch, Generation: cfg.Generation, LaneID: cfg.LaneID, Payload: payload}
	if err := seq.Write(stream, record); err != nil {
		return nil, nil, err
	}
	return tx, rx, nil
}

func noiseRead(ctx context.Context, stream linkStream, seq *wire.HandshakeSequence, hs *noise.HandshakeState, cfg LinkConfig, kind wire.HandshakeKind) error {
	if err := checkContext(ctx, stream); err != nil {
		return err
	}
	record, err := seq.Read(stream)
	if err != nil {
		return err
	}
	if record.Kind != kind {
		return ErrLinkAuthentication
	}
	_, _, _, err = hs.ReadMessage(nil, record.Payload)
	if err != nil {
		return fmt.Errorf("Noise read %d: %w", kind, err)
	}
	return nil
}

func noiseReadFinal(ctx context.Context, stream linkStream, seq *wire.HandshakeSequence, hs *noise.HandshakeState, cfg LinkConfig, kind wire.HandshakeKind) (*noise.CipherState, *noise.CipherState, error) {
	if err := checkContext(ctx, stream); err != nil {
		return nil, nil, err
	}
	record, err := seq.Read(stream)
	if err != nil {
		return nil, nil, err
	}
	if record.Kind != kind {
		return nil, nil, ErrLinkAuthentication
	}
	_, tx, rx, err := hs.ReadMessage(nil, record.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("Noise read %d: %w", kind, err)
	}
	return tx, rx, nil
}

type handshakeStream struct {
	linkStream
	once     sync.Once
	closeErr error
}

func (s *handshakeStream) Close() error {
	s.once.Do(func() { s.closeErr = s.linkStream.Close() })
	return s.closeErr
}

func checkContext(ctx context.Context, stream linkStream) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func exportRoots(tx, rx *noise.CipherState, cfg LinkConfig, binding []byte) ([32]byte, [32]byte, error) {
	var outTx, outRx [32]byte
	txKey, rxKey := tx.UnsafeKey(), rx.UnsafeKey()
	defer clear(txKey[:])
	defer clear(rxKey[:])
	outTx, err := deriveRoot(txKey, cfg, binding, capabilityDirection(cfg, true))
	if err != nil {
		return outTx, outRx, err
	}
	outRx, err = deriveRoot(rxKey, cfg, binding, capabilityDirection(cfg, false))
	return outTx, outRx, err
}

func deriveRoot(key [32]byte, cfg LinkConfig, binding []byte, direction string) ([32]byte, error) {
	info := append([]byte("simpletier/v1/link-root/"+direction), 0)
	info = appendLen(info, cfg.Descriptor)
	info = appendLen(info, binding)
	derived, err := hkdf.Key(sha256.New, key[:], cfg.PSK[:], string(info), 32)
	var out [32]byte
	if err == nil {
		copy(out[:], derived)
	}
	clear(derived)
	return out, err
}

func writeCapability(ctx context.Context, stream linkStream, root [32]byte, cfg LinkConfig, _ []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, err := EncodeCapability(Capability{Version: uint8(cfg.CapabilityVersion), Bits: cfg.CapabilityMask})
	if err != nil {
		return err
	}
	protector, err := capabilityProtector(root, cfg, true)
	if err != nil {
		return err
	}
	frame, err := protector.Seal(wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{0x04}, payload...), cfg.Generation, 0)
	if err != nil {
		return err
	}
	return wire.WriteFrame(stream, frame)
}

func readCapability(ctx context.Context, stream linkStream, root [32]byte, cfg LinkConfig, _ []byte) (Capability, error) {
	if err := ctx.Err(); err != nil {
		return Capability{}, err
	}
	// CAPABILITY has exactly 59 bytes after its prefix: kind+hop+type+payload+tag.
	// Reject another record length before the general codec can allocate its body.
	var prefix [4]byte
	if _, err := io.ReadFull(stream, prefix[:]); err != nil {
		return Capability{}, err
	}
	if binary.BigEndian.Uint32(prefix[:]) != 1+wire.HopHeaderSize+1+capabilityPayloadSize+16 {
		return Capability{}, ErrCapabilityMismatch
	}
	frame, err := wire.ReadFrame(io.MultiReader(bytes.NewReader(prefix[:]), stream))
	if err != nil {
		return Capability{}, err
	}
	if frame.Kind != wire.FrameKindLinkControl || len(frame.Envelope) != 0 || binary.BigEndian.Uint32(frame.HopHeader[:4]) != cfg.Generation || binary.BigEndian.Uint64(frame.HopHeader[4:12]) != 0 || !bytes.Equal(frame.HopHeader[12:], make([]byte, wire.HopHeaderSize-12)) {
		return Capability{}, ErrCapabilityMismatch
	}
	protector, err := capabilityProtector(root, cfg, false)
	if err != nil {
		return Capability{}, err
	}
	plain, err := protector.Open(frame)
	if err != nil {
		return Capability{}, fmt.Errorf("capability authentication: %w", errors.Join(ErrLinkAuthentication, err))
	}
	if len(plain) != 1+capabilityPayloadSize || plain[0] != 0x04 {
		return Capability{}, ErrCapabilityMismatch
	}
	remote, err := DecodeCapability(plain[1:])
	if err != nil {
		return Capability{}, errors.Join(ErrCapabilityMismatch, err)
	}
	return remote, nil
}

func capabilityProtector(root [32]byte, cfg LinkConfig, sending bool) (*FrameProtector, error) {
	direction := DirectionResponderToInitiator
	if cfg.Initiator == sending {
		direction = DirectionInitiatorToResponder
	}
	return NewFrameProtector(root, cfg.Descriptor, cfg.LinkID, [16]byte{}, SessionClassStream, direction)
}

func capabilityDirection(cfg LinkConfig, sending bool) string {
	if cfg.Initiator == sending {
		return "i2r"
	}
	return "r2i"
}

func makeResult(cfg LinkConfig, peer [32]byte, node [16]byte, tx, rx [32]byte, binding []byte, cap Capability) LinkResult {
	return LinkResult{PeerStatic: peer, PeerNodeID: node, LocalNodeID: cfg.Identity.NodeID, LocalStatic: cfg.Identity.PublicKey, TxRoot: tx, RxRoot: rx, ChannelBinding: append([]byte(nil), binding...), CapabilityVersion: uint16(cap.Version), CapabilityMask: cap.Bits, LinkID: cfg.LinkID, LinkEpoch: cfg.LinkEpoch, Generation: cfg.Generation, LaneID: cfg.LaneID}
}

func nodeID(public []byte) ([16]byte, error) {
	if len(public) != 32 {
		return [16]byte{}, ErrLinkAuthentication
	}
	digest := sha256.Sum256(public)
	var out [16]byte
	copy(out[:], digest[:16])
	return out, nil
}
func zeroKey(key [32]byte) bool { var zero [32]byte; return key == zero }
func appendLen(dst, b []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	dst = append(dst, n[:]...)
	return append(dst, b...)
}
