package link

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/yiiilin/simpletier/internal/wire"
)

var (
	ErrInvalidProtector = errors.New("invalid frame protector")
	ErrCounterExhausted = errors.New("frame counter exhausted")
	ErrReplay           = errors.New("replayed or out-of-order frame")
	ErrHopNonceMismatch = errors.New("E2E hop nonce does not match envelope key epoch/message number")
)

const (
	DirectionInitiatorToResponder byte = 0
	DirectionResponderToInitiator byte = 1
	SessionClassPacket            byte = 1
	SessionClassStream            byte = 2
)

type framePurpose byte

const (
	purposeLink  framePurpose = 1
	purposeRoute framePurpose = 2
	purposeE2E   framePurpose = 3
)

// FrameProtector performs one direction's application AEAD. It is deliberately
// below the Link/Network layers: it does not authenticate identities, inspect
// ControlType, route, or encode frames. A protector rejects counters that do
// not strictly advance in each purpose/generation replay domain; callers that
// need intentional reordering must add a reviewed window above this module.
//
// A protector may be Destroyed once its session is retired: the keys are zeroed
// and every later Seal/Open/Verify fails with ErrInvalidProtector, so retired key
// material cannot be reused even by a caller that kept the pointer.
type FrameProtector struct {
	keys      map[framePurpose][chacha20poly1305.KeySize]byte
	mu        sync.Mutex
	last      map[replayKey]uint64
	destroyed bool
}

type replayKey struct {
	purpose    framePurpose
	generation uint32
}

// NewFrameProtector derives independent LINK_CTRL, ROUTE_CTRL and E2E keys from
// a directional post-authentication root. descriptor is the full versioned
// network descriptor; it is copied and participates in key separation. The
// root must be a direction-specific 32-byte key exported only after a complete
// authentication handshake. This constructor does not establish a Link.
// HKDF-SHA256 uses root as IKM and descriptor as salt. Its info is the fixed
// "simpletier/v1/frame-key" label, purpose:u8, direction:u8, then class:u8 only
// for E2E, LinkID:u64be, SessionID:16B only for E2E, and descriptor:u32be length
// plus bytes. Purpose fixes the layout; control/route keys ignore session fields.
// SessionClass must still be valid Packet/Stream for construction.
func NewFrameProtector(root [32]byte, descriptor []byte, linkID uint64, sessionID [16]byte, sessionClass, direction byte) (*FrameProtector, error) {
	defer clear(root[:])
	if len(descriptor) == 0 || direction > DirectionResponderToInitiator || sessionClass < SessionClassPacket || sessionClass > SessionClassStream || root == ([32]byte{}) {
		return nil, ErrInvalidProtector
	}
	p := &FrameProtector{keys: make(map[framePurpose][32]byte, 3), last: make(map[replayKey]uint64)}
	for _, purpose := range []framePurpose{purposeLink, purposeRoute, purposeE2E} {
		info := make([]byte, 0, 64+len(descriptor))
		info = append(info, []byte("simpletier/v1/frame-key")...)
		info = append(info, byte(purpose), direction)
		if purpose == purposeE2E {
			info = append(info, sessionClass)
		}
		var link [8]byte
		binary.BigEndian.PutUint64(link[:], linkID)
		info = append(info, link[:]...)
		if purpose == purposeE2E {
			info = append(info, sessionID[:]...)
		}
		info = appendLengthPrefixed(info, descriptor)
		derived, err := hkdf.Key(sha256.New, root[:], descriptor, string(info), chacha20poly1305.KeySize)
		if err != nil {
			return nil, err
		}
		var key [32]byte
		copy(key[:], derived)
		clear(derived)
		clear(info)
		p.keys[purpose] = key
		clear(key[:])
	}
	return p, nil
}

// Seal encrypts plaintext into frame.Body. frame.Body is ignored. generation
// and counter form the public 96-bit nonce GenerationBE32|CounterBE64; callers
// own allocation and must never reuse a pair for a purpose/direction key.
//
// The nonce domain is kind-specific and is enforced, not assumed. E2E frames
// must carry generation/counter byte-identical to the envelope's
// key_epoch:u32be|message_number:u64be; the Link generation is never a
// substitute. ROUTE_CTRL and LINK_CTRL keep the LinkGeneration nonce domain and
// are not compared against their envelope. A mismatch is rejected before any
// body is produced, so a failed Seal spends nothing.
func (p *FrameProtector) Seal(frame wire.Frame, plaintext []byte, generation uint32, counter uint64) (wire.Frame, error) {
	if p == nil || len(plaintext) == 0 {
		return wire.Frame{}, ErrInvalidProtector
	}
	if counter == ^uint64(0) {
		return wire.Frame{}, ErrCounterExhausted
	}
	purpose, err := purposeFor(frame.Kind)
	if err != nil {
		return wire.Frame{}, err
	}
	if generation == 0 {
		return wire.Frame{}, ErrInvalidProtector
	}
	if err := checkHopNonce(frame, generation, counter); err != nil {
		return wire.Frame{}, err
	}
	// The key is copied under the lock so Destroy cannot zero it concurrently.
	// A frame that already copied its key still finishes; a later Seal fails.
	p.mu.Lock()
	if p.destroyed {
		p.mu.Unlock()
		return wire.Frame{}, ErrInvalidProtector
	}
	key := p.keys[purpose]
	p.mu.Unlock()
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return wire.Frame{}, err
	}
	frame.HopHeader[0] = byte(generation >> 24)
	frame.HopHeader[1] = byte(generation >> 16)
	frame.HopHeader[2] = byte(generation >> 8)
	frame.HopHeader[3] = byte(generation)
	binary.BigEndian.PutUint64(frame.HopHeader[4:12], counter)
	bodyLength := len(plaintext) + aead.Overhead()
	length, aad, err := frameAAD(frame, bodyLength)
	if err != nil {
		return wire.Frame{}, err
	}
	_ = length
	nonce := makeNonce(generation, counter)
	sealed := aead.Seal(nil, nonce[:], plaintext, aad)
	frame.Body = sealed
	return frame, nil
}

// Open authenticates and decrypts frame.Body. The replay high-water mark moves
// only after successful authentication. A duplicate or lower counter returns
// ErrReplay and never exposes plaintext.
func (p *FrameProtector) Open(frame wire.Frame) ([]byte, error) {
	if p == nil {
		return nil, ErrInvalidProtector
	}
	purpose, generation, counter, err := openScope(frame)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.destroyed {
		return nil, ErrInvalidProtector
	}
	replay := replayKey{purpose: purpose, generation: generation}
	if previous, ok := p.last[replay]; ok && counter <= previous {
		return nil, ErrReplay
	}
	plaintext, err := p.openBody(frame, purpose, generation, counter)
	if err != nil {
		return nil, err
	}
	p.last[replay] = counter
	return plaintext, nil
}

// Verify authenticates and decrypts frame.Body exactly like Open, including the
// read-only replay precheck against this protector's own high-water mark, but
// leaves that mark untouched. It exists so a caller that owns replay state can
// commit that state only after its own semantic checks:
//
//   - LINK_CTRL/ROUTE_CTRL must not commit the counter before the decoded
//     payload is validated, so a malformed frame cannot skip past the floor it
//     would otherwise claim (Wire C-WIRE-003 step 3).
//   - E2E hop plaintext is opaque session ciphertext whose inner AEAD this
//     protector never runs, so the hop layer must not advance any E2E replay
//     state at all: Wire C-WIRE-003 requires the E2E tag to be verified before
//     replay/window/epoch state moves, and a caller drives that commit
//     separately (ProtectedControlIO.CommitEndToEnd).
//
// The caller must serialise Verify (and any later floor commit) per protector;
// FrameProtector itself stays unchanged for callers of Open. The returned
// plaintext is caller-owned.
func (p *FrameProtector) Verify(frame wire.Frame) ([]byte, error) {
	if p == nil {
		return nil, ErrInvalidProtector
	}
	purpose, generation, counter, err := openScope(frame)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.destroyed {
		return nil, ErrInvalidProtector
	}
	replay := replayKey{purpose: purpose, generation: generation}
	if previous, ok := p.last[replay]; ok && counter <= previous {
		return nil, ErrReplay
	}
	return p.openBody(frame, purpose, generation, counter)
}

// Destroy zeroes this protector's key material and permanently makes Seal, Open
// and Verify fail with ErrInvalidProtector. It is the retirement primitive for a
// session whose hop subkeys must not be rebuilt from zero: a retained protector
// would restart the replay floor under an unchanged key, so the caller keeps a
// keyless tombstone instead of re-deriving. Destroy is idempotent and safe
// concurrently with Seal/Open/Verify; a frame that already copied its key
// finishes, and nothing can be sealed or opened afterwards.
func (p *FrameProtector) Destroy() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for purpose, key := range p.keys {
		clear(key[:])
		p.keys[purpose] = key
	}
	clear(p.keys)
	clear(p.last)
	p.destroyed = true
}

// openScope decodes the purpose/nonce scope shared by Open and Verify. It runs
// every check that must precede AEAD, including the E2E envelope/hop nonce copy.
func openScope(frame wire.Frame) (framePurpose, uint32, uint64, error) {
	purpose, err := purposeFor(frame.Kind)
	if err != nil {
		return 0, 0, 0, err
	}
	generation, counter, err := nonceFromHop(frame.HopHeader)
	if err != nil {
		return 0, 0, 0, err
	}
	if err := checkHopNonce(frame, generation, counter); err != nil {
		return 0, 0, 0, err
	}
	if len(frame.Body) < chacha20poly1305.Overhead || generation == 0 {
		return 0, 0, 0, ErrInvalidProtector
	}
	return purpose, generation, counter, nil
}

// openBody performs the AAD construction and AEAD open for an already scoped
// frame. It never touches replay state.
func (p *FrameProtector) openBody(frame wire.Frame, purpose framePurpose, generation uint32, counter uint64) ([]byte, error) {
	_, aad, err := frameAAD(frame, len(frame.Body))
	if err != nil {
		return nil, err
	}
	key := p.keys[purpose]
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := makeNonce(generation, counter)
	return aead.Open(nil, nonce[:], frame.Body, aad)
}

func purposeFor(kind wire.FrameKind) (framePurpose, error) {
	switch kind {
	case wire.FrameKindLinkControl:
		return purposeLink, nil
	case wire.FrameKindRouteControl:
		return purposeRoute, nil
	case wire.FrameKindEndToEnd:
		return purposeE2E, nil
	default:
		return 0, wire.ErrFrameMalformed
	}
}

// validMessageTypeForKind is the frozen FrameKind<->MessageType mapping:
// E2E carries IP_PACKET/UDP_DATAGRAM/STREAM_DATA/CONTROL_RPC and ROUTE_CTRL
// carries SESSION_CTRL/PATH_OPEN/PATH_READY/PATH_BROKEN/SESSION_READY. It
// mirrors the wire codec's unexported check so frameAAD can validate without
// re-encoding the frame.
func validMessageTypeForKind(kind wire.FrameKind, messageType wire.MessageType) bool {
	switch kind {
	case wire.FrameKindEndToEnd:
		return messageType >= wire.MessageTypeIPPacket && messageType <= wire.MessageTypeControlRPC
	case wire.FrameKindRouteControl:
		return messageType >= wire.MessageTypeSessionCtrl && messageType <= wire.MessageTypeSessionReady
	default:
		return false
	}
}

// frameAAD builds the frozen hop AAD byte string
// `length:u32be | FrameKind:u8 | hop_hdr:32B | optional envelope:85B` and returns
// the length it encodes.
//
// It validates the same frame-layout rules the wire codec enforces, without
// materialising a body-sized buffer or re-encoding the whole frame through
// wire.WriteFrame: a data frame would otherwise allocate and copy its entire
// body on every seal/open just to discard the body. The checks replicated are
// wire.FrameKind validity, the per-kind envelope presence, the
// FrameKind<->MessageType mapping, the non-empty protected body, the per-kind
// minimum `length` and `length <= MaxFrameLength`. ErrFrameMalformed /
// ErrFrameTooLarge identity is preserved so callers cannot tell the two paths
// apart; TestFrameAADMatchesWireCodec proves byte and error equivalence against
// wire.WriteFrame for a boundary matrix.
func frameAAD(frame wire.Frame, bodyLength int) (uint32, []byte, error) {
	if bodyLength <= 0 {
		return 0, nil, ErrInvalidProtector
	}
	// Minimum protected body per FrameKind: LINK_CTRL/ROUTE_CTRL carry at least
	// one payload byte, E2E at least the inner tag, and every kind carries the
	// hop tag (Wire C-WIRE-001 minimums 50 / 135 / 150).
	minimumBody := 1 + chacha20poly1305.Overhead
	envelopeLength := 0
	switch frame.Kind {
	case wire.FrameKindLinkControl:
		if len(frame.Envelope) != 0 {
			return 0, nil, fmt.Errorf("FrameKind 0x%02x requires no envelope: %w", uint8(frame.Kind), wire.ErrFrameMalformed)
		}
	case wire.FrameKindRouteControl, wire.FrameKindEndToEnd:
		if len(frame.Envelope) != wire.EnvelopeSize {
			return 0, nil, fmt.Errorf("FrameKind 0x%02x requires envelope length %d: %w", uint8(frame.Kind), wire.EnvelopeSize, wire.ErrFrameMalformed)
		}
		envelopeLength = wire.EnvelopeSize
		messageType := wire.MessageType(frame.Envelope[wire.EnvelopeMessageTypeOffset])
		if !validMessageTypeForKind(frame.Kind, messageType) {
			return 0, nil, fmt.Errorf("MessageType 0x%02x invalid for FrameKind 0x%02x: %w", uint8(messageType), uint8(frame.Kind), wire.ErrFrameMalformed)
		}
		if frame.Kind == wire.FrameKindEndToEnd {
			minimumBody = 2 * chacha20poly1305.Overhead
		}
	default:
		return 0, nil, fmt.Errorf("unknown FrameKind 0x%02x: %w", uint8(frame.Kind), wire.ErrFrameMalformed)
	}
	if bodyLength < minimumBody {
		return 0, nil, fmt.Errorf("protected body %d below minimum %d: %w", bodyLength, minimumBody, wire.ErrFrameMalformed)
	}
	length64 := uint64(wire.FrameKindSize + wire.HopHeaderSize + envelopeLength + bodyLength)
	if length64 > uint64(wire.MaxFrameLength) {
		return 0, nil, fmt.Errorf("length %d exceeds %d: %w", length64, wire.MaxFrameLength, wire.ErrFrameTooLarge)
	}
	length := uint32(length64)
	header := wire.FrameLengthPrefixSize + wire.FrameKindSize + wire.HopHeaderSize
	aad := make([]byte, header+envelopeLength)
	binary.BigEndian.PutUint32(aad[:wire.FrameLengthPrefixSize], length)
	aad[wire.FrameLengthPrefixSize] = byte(frame.Kind)
	copy(aad[wire.FrameLengthPrefixSize+wire.FrameKindSize:], frame.HopHeader[:])
	if envelopeLength != 0 {
		copy(aad[header:], frame.Envelope)
	}
	return length, aad, nil
}

func makeNonce(generation uint32, counter uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[:4], generation)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

func nonceFromHop(header [wire.HopHeaderSize]byte) (uint32, uint64, error) {
	generation := binary.BigEndian.Uint32(header[:4])
	counter := binary.BigEndian.Uint64(header[4:12])
	if generation == 0 {
		return 0, 0, ErrInvalidProtector
	}
	return generation, counter, nil
}

// checkHopNonce enforces the approved nonce-domain invariant without touching
// the wire layout or KDF. E2E hop nonces are a byte-for-byte copy of the
// envelope key_epoch|message_number; ROUTE_CTRL/LINK_CTRL stay in the
// LinkGeneration domain, so their envelope (all-zero reserved fields) is not a
// nonce source. It runs before AEAD in both directions, so a rejected frame
// never advances the replay high-water mark.
func checkHopNonce(frame wire.Frame, generation uint32, counter uint64) error {
	if frame.Kind != wire.FrameKindEndToEnd {
		return nil
	}
	if len(frame.Envelope) != wire.EnvelopeSize {
		return wire.ErrFrameMalformed
	}
	envelopeGeneration := binary.BigEndian.Uint32(frame.Envelope[wire.EnvelopeKeyEpochOffset:])
	envelopeCounter := binary.BigEndian.Uint64(frame.Envelope[wire.EnvelopeMessageNumberOffset:])
	if envelopeGeneration != generation || envelopeCounter != counter {
		return ErrHopNonceMismatch
	}
	return nil
}

func appendLengthPrefixed(dst, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}
