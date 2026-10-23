package session

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/flynn/noise"

	"github.com/yiiilin/simpletier/internal/security"
)

// This file is the production end-to-end Session crypto boundary. It implements
// the approved Noise_IKpsk2_25519_ChaChaPoly_SHA256 handshake and derives the
// two directional session roots. It fills the CryptoProvider seam declared in
// session.go without changing that seam.
//
// DESIGN-CONTRACT (concrete bytes; independent review required for the choices
// marked REVIEW):
//
//   - Pattern: Noise IK, PSK placement 2 (psk token at the end of message 2),
//     cipher suite DH25519/ChaChaPoly/SHA256. Messages: initiator sends
//     e, es, s, ss (msg1); responder sends e, ee, se (msg2). This is REVIEW: the
//     approved branch names "Noise_IKpsk2" but does not itself contain the
//     library, the placement integer or the byte encodings below.
//   - Prologue: NetworkContext.Prologue(PrologueDomain, params.Prologue), i.e.
//     ASCII "simpletier-v1/prologue" || LP32(domain) || LP32(descriptor) ||
//     LP32(binding). params.Prologue is the frozen PrologueBinding
//     (ContextID:32B | Src:16B | Dst:16B | SessionID:16B | class:u8 | lane:u8 |
//     attempt:u32be | target_epoch:u32be | PathID:u64be | PathGeneration:u32be,
//     PrologueBindingSize bytes). The provider re-derives that canonical
//     102-byte binding from the parsed fields and compares the whole value, not
//     just its length. The full descriptor wrapper is applied here, by the
//     provider, exactly as the Manager documentation requires.
//   - Directional session root (one independent HKDF per direction; the split
//     keys are never concatenated as keying material):
//
//     session_root_key[dir] = HKDF-Key-SHA256(
//     IKM  = split[dir],
//     salt = PSK,
//     info = ASCII("simpletier/v2/session-root/" + dir) || 0x00
//     || LP32(descriptor) || LP32(NoiseChannelBinding),
//     L    = 32)
//
//     dir is "i2r" or "r2i", split[0] is initiator->responder and split[1] is
//     responder->initiator as returned by the Noise Split.
//   - Opaque Root: Root() returns the canonical two-root encoding
//     session_root_key[i2r] || session_root_key[r2i] (64 bytes). That
//     concatenation is an encoding only; it is never an HKDF IKM.
//   - Lifecycle: Initiate/Respond/Finish and Close share one mutex, so Close
//     only drops the pending table and zeroes the private key after every
//     in-flight use has drained. After Close every call fails closed with
//     ErrProviderClosed and Close itself is idempotent.
//
// REVIEW items needing independent sign-off: the library/pattern integers, the
// exact info field order above, the root encoding order, and the pending-state
// policy numbers (which are caller-supplied and never defaulted here).

// Errors for the production Noise provider. They are distinct from the
// placeholder's ErrCryptoUnavailable so tests can tell "not wired" from
// "authentication failed".
var (
	// ErrNoiseConfig reports an unusable provider configuration or handshake
	// binding (wrong context, empty binding, zero PSK, role mismatch, a
	// non-canonical 102-byte prologue, or a peer NodeID that does not hash from
	// the peer static key).
	ErrNoiseConfig = errors.New("session: invalid noise provider config")
	// ErrNoiseMessage reports a Noise message that is structurally invalid or
	// fails authentication.
	ErrNoiseMessage = errors.New("session: invalid noise handshake message")
	// ErrPeerStaticMismatch reports an authenticated peer static key that is not
	// the resolved PeerStatic for the scope.
	ErrPeerStaticMismatch = errors.New("session: authenticated peer static key mismatch")
	// ErrHandshakePending reports an unexpired pending initiator handshake that
	// already exists for the same session identity.
	ErrHandshakePending = errors.New("session: handshake already pending")
	// ErrHandshakeNotFound reports Finish without a matching Initiate.
	ErrHandshakeNotFound = errors.New("session: no pending handshake state")
	// ErrHandshakeExpired reports a pending initiator handshake whose TTL passed.
	ErrHandshakeExpired = errors.New("session: pending handshake expired")
	// ErrHandshakeLimit reports that the bounded pending-handshake table is full.
	ErrHandshakeLimit = errors.New("session: pending handshake limit reached")
	// ErrProviderClosed reports any handshake call after Close. It is terminal:
	// the private key is already wiped and no transcript may be produced.
	ErrProviderClosed = errors.New("session: noise provider closed")
)

// ProviderPolicy bounds the initiator-side pending handshake table. Every field
// is mandatory: the provider refuses to invent a production ceiling.
type ProviderPolicy struct {
	// PendingMax is the maximum number of concurrent pending initiator
	// handshakes. Must be >= 1.
	PendingMax int
	// PendingTTL is how long a pending initiator handshake may wait for its
	// Finish. Must be > 0.
	PendingTTL time.Duration
	// Clock is an optional time source for tests. Nil means time.Now.
	Clock func() time.Time
}

func (p ProviderPolicy) validate() error {
	if p.PendingMax < 1 {
		return fmt.Errorf("%w: PendingMax %d", ErrNoiseConfig, p.PendingMax)
	}
	if p.PendingTTL <= 0 {
		return fmt.Errorf("%w: PendingTTL %s", ErrNoiseConfig, p.PendingTTL)
	}
	return nil
}

// pendingHandshakeKey identifies one initiator attempt awaiting Finish.
type pendingHandshakeKey struct {
	contextID      [32]byte
	sessionID      SessionID
	attempt        uint32
	targetEpoch    uint32
	pathID         uint64
	pathGeneration uint32
	class          SessionClass
	lane           Lane
	initiator      bool
}

type pendingHandshake struct {
	hs      *noise.HandshakeState
	expires time.Time
}

// NoiseProvider is the production CryptoProvider. It owns the static identity,
// the network context and a bounded table of initiator handshake state. It is
// safe for concurrent use. Responder handshakes are stateless.
type NoiseProvider struct {
	nc         security.NetworkContext
	contextID  [32]byte
	nodeID     [16]byte
	static     noise.DHKey
	descriptor []byte
	policy     ProviderPolicy
	clock      func() time.Time

	// mu is the single synchronization domain for pending state, identity use
	// and Close: a handshake holds it for its whole Noise exchange, so Close
	// can only wipe the private key after every in-flight use drained.
	mu      sync.Mutex
	closed  bool
	pending map[pendingHandshakeKey]pendingHandshake
}

// NewNoiseProvider builds the production provider from an in-memory X25519
// identity and the initialized NetworkContext whose descriptor is bound into
// every prologue. policy is required; the provider never substitutes defaults
// for the pending-state ceilings.
func NewNoiseProvider(identity security.Identity, nc security.NetworkContext, policy ProviderPolicy) (*NoiseProvider, error) {
	if identity.PrivateKey == nil {
		return nil, fmt.Errorf("%w: nil private key", ErrNoiseConfig)
	}
	if identity.PublicKey == ([32]byte{}) || identity.NodeID == ([16]byte{}) {
		return nil, fmt.Errorf("%w: empty identity key or node id", ErrNoiseConfig)
	}
	if !bytes.Equal(identity.PrivateKey.PublicKey().Bytes(), identity.PublicKey[:]) {
		return nil, fmt.Errorf("%w: public key does not match private key", ErrNoiseConfig)
	}
	derivedNode, err := nodeIDFromStaticKey(identity.PublicKey)
	if err != nil || derivedNode != identity.NodeID {
		return nil, fmt.Errorf("%w: node id does not match public key", ErrNoiseConfig)
	}
	descriptor := nc.Descriptor()
	if len(descriptor) == 0 || nc.ID() == ([32]byte{}) {
		return nil, fmt.Errorf("%w: uninitialized network context", ErrNoiseConfig)
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	clock := policy.Clock
	if clock == nil {
		clock = time.Now
	}
	return &NoiseProvider{
		nc:         nc,
		contextID:  nc.ID(),
		nodeID:     identity.NodeID,
		static:     noise.DHKey{Private: append([]byte(nil), identity.PrivateKey.Bytes()...), Public: append([]byte(nil), identity.PublicKey[:]...)},
		descriptor: append([]byte(nil), descriptor...),
		policy:     policy,
		clock:      clock,
		pending:    make(map[pendingHandshakeKey]pendingHandshake),
	}, nil
}

// Close drops the pending table and zeroes the provider's own copy of the
// static private key. It is idempotent and terminal: because it shares the
// provider mutex with Initiate/Respond/Finish, it can only wipe the key after
// every in-flight Noise use has drained, and every later handshake call fails
// closed with ErrProviderClosed.
func (p *NoiseProvider) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	p.pending = make(map[pendingHandshakeKey]pendingHandshake)
	clear(p.static.Private)
}

// Initiate starts the initiator side and returns the opaque msg1. The state
// needed by Finish is stored under a bounded, TTL-limited entry; a fresh
// ephemeral keypair is generated for every attempt by the Noise library.
func (p *NoiseProvider) Initiate(ctx context.Context, params HandshakeParams) ([]byte, error) {
	if p == nil {
		return nil, ErrNoiseConfig
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrNoiseConfig)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrProviderClosed
	}
	prologue, err := p.prologue(params, true)
	if err != nil {
		return nil, err
	}
	defer clear(prologue)
	hs, err := p.newHandshake(params, prologue, true)
	if err != nil {
		return nil, err
	}
	first, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: initiate: %v", ErrNoiseMessage, err)
	}
	if len(first) == 0 {
		return nil, fmt.Errorf("%w: empty initiator message", ErrNoiseMessage)
	}
	key := pendingHandshakeKeyOf(params)
	now := p.clock()
	p.purgeLocked(now)
	if _, exists := p.pending[key]; exists {
		return nil, ErrHandshakePending
	}
	if len(p.pending) >= p.policy.PendingMax {
		return nil, fmt.Errorf("%w: %d pending", ErrHandshakeLimit, len(p.pending))
	}
	p.pending[key] = pendingHandshake{hs: hs, expires: now.Add(p.policy.PendingTTL)}
	return first, nil
}

// Respond consumes msg1 for the responder side, returns msg2 and this side's
// canonical root. It keeps no state: the responder's Noise state completes on
// WriteMessage and is dropped.
func (p *NoiseProvider) Respond(ctx context.Context, params HandshakeParams, first []byte) ([]byte, []byte, error) {
	if p == nil {
		return nil, nil, ErrNoiseConfig
	}
	if ctx == nil {
		return nil, nil, fmt.Errorf("%w: nil context", ErrNoiseConfig)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if len(first) == 0 {
		return nil, nil, fmt.Errorf("%w: empty initiator message", ErrNoiseMessage)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, nil, ErrProviderClosed
	}
	prologue, err := p.prologue(params, false)
	if err != nil {
		return nil, nil, err
	}
	defer clear(prologue)
	hs, err := p.newHandshake(params, prologue, false)
	if err != nil {
		return nil, nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, append([]byte(nil), first...)); err != nil {
		return nil, nil, fmt.Errorf("%w: respond read: %v", ErrNoiseMessage, err)
	}
	response, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: respond write: %v", ErrNoiseMessage, err)
	}
	if len(response) == 0 || cs1 == nil || cs2 == nil {
		return nil, nil, fmt.Errorf("%w: incomplete responder handshake", ErrNoiseMessage)
	}
	if err := p.checkPeerStatic(hs, params); err != nil {
		return nil, nil, err
	}
	binding := append([]byte(nil), hs.ChannelBinding()...)
	defer clear(binding)
	root, err := p.sessionRoot(cs1, cs2, params, binding)
	if err != nil {
		return nil, nil, err
	}
	return response, root.Encode(), nil
}

// Finish consumes msg2 for the initiator side, returns this side's canonical
// root and removes the pending entry. A cancelled context or an unknown TTL
// entry never consumes state. The mutex is held across the Noise read so a
// concurrent Close cannot wipe the static key mid-exchange.
func (p *NoiseProvider) Finish(ctx context.Context, params HandshakeParams, response []byte) ([]byte, error) {
	if p == nil {
		return nil, ErrNoiseConfig
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrNoiseConfig)
	}
	if len(response) == 0 {
		return nil, fmt.Errorf("%w: empty responder message", ErrNoiseMessage)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrProviderClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.prologueCheck(params, true); err != nil {
		return nil, err
	}
	key := pendingHandshakeKeyOf(params)
	entry, ok := p.pending[key]
	if !ok {
		return nil, ErrHandshakeNotFound
	}
	delete(p.pending, key)
	now := p.clock()
	if now.After(entry.expires) {
		return nil, ErrHandshakeExpired
	}
	_, cs1, cs2, err := entry.hs.ReadMessage(nil, append([]byte(nil), response...))
	if err != nil {
		return nil, fmt.Errorf("%w: finish read: %v", ErrNoiseMessage, err)
	}
	if cs1 == nil || cs2 == nil {
		return nil, fmt.Errorf("%w: incomplete initiator handshake", ErrNoiseMessage)
	}
	if err := p.checkPeerStatic(entry.hs, params); err != nil {
		return nil, err
	}
	binding := append([]byte(nil), entry.hs.ChannelBinding()...)
	defer clear(binding)
	root, err := p.sessionRoot(cs1, cs2, params, binding)
	if err != nil {
		return nil, err
	}
	return root.Encode(), nil
}

// prologue builds the full NetworkContext prologue wrapper around the frozen
// binding carried by params.
func (p *NoiseProvider) prologue(params HandshakeParams, initiator bool) ([]byte, error) {
	if err := p.prologueCheck(params, initiator); err != nil {
		return nil, err
	}
	full, err := p.nc.Prologue(PrologueDomain, params.Prologue)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoiseConfig, err)
	}
	return full, nil
}

// prologueCheck validates every bound field before any key material is touched.
// It rebuilds the canonical 102-byte PrologueBinding from the parsed fields and
// compares the whole value, so a same-length but non-canonical binding is
// rejected rather than hashed into the transcript.
func (p *NoiseProvider) prologueCheck(params HandshakeParams, initiator bool) error {
	if params.Initiator != initiator {
		return fmt.Errorf("%w: role mismatch", ErrNoiseConfig)
	}
	if params.ContextID != p.contextID {
		return fmt.Errorf("%w: context id does not match the provider", ErrNoiseConfig)
	}
	if params.LocalNodeID != p.nodeID {
		return fmt.Errorf("%w: local node id does not match the provider", ErrNoiseConfig)
	}
	if params.LocalStatic != ([32]byte{}) && !bytes.Equal(params.LocalStatic[:], p.static.Public) {
		return fmt.Errorf("%w: local static key does not match the provider", ErrNoiseConfig)
	}
	if params.PeerNodeID == ([16]byte{}) || params.PeerStatic == ([32]byte{}) {
		return fmt.Errorf("%w: empty peer identity", ErrNoiseConfig)
	}
	derivedPeer, err := nodeIDFromStaticKey(params.PeerStatic)
	if err != nil || derivedPeer != params.PeerNodeID {
		return fmt.Errorf("%w: peer node id does not match the peer static key", ErrNoiseConfig)
	}
	if params.PSK == ([32]byte{}) {
		return fmt.Errorf("%w: zero PSK", ErrNoiseConfig)
	}
	if params.SessionID.IsZero() {
		return fmt.Errorf("%w: zero session id", ErrNoiseConfig)
	}
	if !params.Class.Valid() || params.DataLaneID != params.Class.Lane() {
		return fmt.Errorf("%w: class/lane %s/%s", ErrNoiseConfig, params.Class, params.DataLaneID)
	}
	if params.TargetEpoch == 0 {
		return fmt.Errorf("%w: target epoch 0", ErrNoiseConfig)
	}
	if params.PathID == 0 || params.PathGeneration == 0 {
		return fmt.Errorf("%w: path %d/%d", ErrNoiseConfig, params.PathID, params.PathGeneration)
	}
	if len(params.Prologue) != PrologueBindingSize {
		return fmt.Errorf("%w: prologue binding is %d bytes, want %d", ErrNoiseConfig, len(params.Prologue), PrologueBindingSize)
	}
	src, dst := params.LocalNodeID, params.PeerNodeID
	if !initiator {
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
	canonical, err := PrologueBinding(key, params.SessionID, params.Attempt, params.TargetEpoch)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoiseConfig, err)
	}
	if subtle.ConstantTimeCompare(canonical, params.Prologue) != 1 {
		return fmt.Errorf("%w: prologue binding is not the canonical 102-byte encoding", ErrNoiseConfig)
	}
	return nil
}

func (p *NoiseProvider) newHandshake(params HandshakeParams, prologue []byte, initiator bool) (*noise.HandshakeState, error) {
	psk := append([]byte(nil), params.PSK[:]...)
	defer clear(psk)
	var peer []byte
	if initiator {
		// IK carries the responder static as a pre-message, so the initiator
		// must pin it. The responder learns the initiator static from msg1.
		peer = append([]byte(nil), params.PeerStatic[:]...)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:               noise.HandshakeIK,
		Initiator:             initiator,
		Prologue:              append([]byte(nil), prologue...),
		PresharedKey:          psk,
		PresharedKeyPlacement: 2,
		StaticKeypair:         p.static,
		PeerStatic:            peer,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoiseConfig, err)
	}
	return hs, nil
}

// checkPeerStatic requires the authenticated remote static key to equal the
// resolved peer of the scope.
func (p *NoiseProvider) checkPeerStatic(hs *noise.HandshakeState, params HandshakeParams) error {
	peer := hs.PeerStatic()
	if len(peer) != 32 || !bytes.Equal(peer, params.PeerStatic[:]) {
		return fmt.Errorf("%w: for %s", ErrPeerStaticMismatch, params.SessionID)
	}
	return nil
}

// sessionRoot derives the two independent directional roots from the Noise
// split cipher states and the authenticated ChannelBinding. cs1 is
// initiator->responder (Split[0]) and cs2 is responder->initiator (Split[1]);
// the split keys are never concatenated.
func (p *NoiseProvider) sessionRoot(cs1, cs2 *noise.CipherState, params HandshakeParams, binding []byte) (SessionRoot, error) {
	key1 := cs1.UnsafeKey()
	key2 := cs2.UnsafeKey()
	defer clear(key1[:])
	defer clear(key2[:])
	i2r, err := deriveSessionRoot(key1, DirectionInitiatorToResponder, p.descriptor, binding, params.PSK[:])
	if err != nil {
		return SessionRoot{}, err
	}
	r2i, err := deriveSessionRoot(key2, DirectionResponderToInitiator, p.descriptor, binding, params.PSK[:])
	if err != nil {
		return SessionRoot{}, err
	}
	return SessionRoot{I2R: i2r, R2I: r2i}, nil
}

// deriveSessionRoot computes one directional application root:
//
//	HKDF-Key-SHA256(IKM=split, salt=PSK,
//	  info = ASCII("simpletier/v2/session-root/"+dir) || 0x00
//	         || LP32(descriptor) || LP32(binding), L=32)
func deriveSessionRoot(split [32]byte, dir Direction, descriptor, binding, psk []byte) ([32]byte, error) {
	var out [32]byte
	info := append([]byte("simpletier/v2/session-root/"+dir.String()), 0)
	info = appendLengthPrefixed(info, descriptor)
	info = appendLengthPrefixed(info, binding)
	derived, err := hkdf.Key(sha256.New, split[:], psk, string(info), 32)
	clear(info)
	if err != nil {
		return out, fmt.Errorf("session: derive %s root: %w", dir, err)
	}
	copy(out[:], derived)
	clear(derived)
	return out, nil
}

func pendingHandshakeKeyOf(params HandshakeParams) pendingHandshakeKey {
	return pendingHandshakeKey{
		contextID:      params.ContextID,
		sessionID:      params.SessionID,
		attempt:        params.Attempt,
		targetEpoch:    params.TargetEpoch,
		pathID:         params.PathID,
		pathGeneration: params.PathGeneration,
		class:          params.Class,
		lane:           params.DataLaneID,
		initiator:      params.Initiator,
	}
}

func (p *NoiseProvider) purgeLocked(now time.Time) {
	for key, entry := range p.pending {
		if now.After(entry.expires) {
			delete(p.pending, key)
		}
	}
}

// appendLengthPrefixed appends value as u32be length followed by its bytes.
func appendLengthPrefixed(dst, value []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}
