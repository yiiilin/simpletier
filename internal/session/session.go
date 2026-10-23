// Package session owns the SimpleTier P1 end-to-end Session state machine.
//
// A Session is the per-Path/SessionClass state that a Noise IK handshake
// establishes and that SESSION_READY commits. This package owns:
//
//   - the Session identity Key: the full ContextID, both selected-handshake
//     endpoints (SrcNodeID/DstNodeID), PathID/PathGeneration and
//     SessionClass/lane, plus the local Path role, the CSPRNG SessionID chosen
//     by the Path owner, and the mode-independent attempt/target_epoch
//     baseline;
//   - the Pending/Ready/Broken/Closed lifecycle, the single-pending-attempt
//     rule, byte-identical retransmission caching per role/step/attempt, and
//     conflict/stale/future rejection for attempt and epoch;
//   - the bounded termination tombstone: an Abort or a pending-deadline failure
//     remembers the dead SessionID for 30 seconds, so a late or replayed
//     SESSION_CTRL for it is rejected with ErrStaleSessionID instead of
//     rebuilding a Session under the failed identity;
//   - the session binding bytes ("prologue") and the mode-independent
//     SESSION_CTRL/SESSION_READY payload codec;
//   - the frozen bounds: MaxSessions entries per manager (live Sessions plus
//     termination tombstones) and MaxPendingBytes pending wire bytes per
//     session, plus the 30-second pending deadline.
//
// End-to-end crypto is an injected CryptoProvider boundary. A review-approved
// production provider is available in this package (NewNoiseProvider), together
// with the envelope85 end-to-end protector (NewE2EProtector /
// NewE2EProtectorForContext). When Config.Crypto is nil the unavailable
// placeholder is still installed, so a manager without an explicit provider
// claims no end-to-end encryption.
//
// Integration boundary: this package is standalone. It imports only the Go
// standard library and is wired into neither the network runtime nor the
// Circuit layer: it opens no links, encodes/sends no FrameKind frames, does not
// wrap the prologue in NetworkContext.Prologue, owns no data-lane queue, and
// never opens, accepts or resets a Circuit. The wiring owner resolves the peer,
// frames the returned SessionCtrl/SessionReady payloads, drains its own
// ReadyPending/RekeyPending queue, and calls ReservePending/ReleasePending for
// the bytes it holds. Relay-hop observation of SESSION_CTRL for a Path this
// node is not an endpoint of is likewise out of scope.
//
// Spec anchors: security.md C-SEC-003 (scope, first attempt=0/target_epoch=1,
// one pending rekey, byte-identical retransmission, SessionAttemptConflict),
// wire-protocol.md C-WIRE-003/C-WIRE-004 (attempt/epoch rejection, 30 s pending
// deadline, 65,897-byte pending queue, ReadyPending/RekeyPending commit) and
// C-WIRE-005 (SESSION_CTRL/SESSION_READY payload schemas).
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// PrologueDomain is the NetworkContext.Prologue domain this module's binding
// bytes belong to. The wiring owner calls
// NetworkContext.Prologue(session.PrologueDomain, binding) so that the complete
// versioned network descriptor is bound as well; this package never sees the
// descriptor and never guesses the surrounding label encoding.
const PrologueDomain = "simpletier-v1/session"

const (
	// MaxSessions is the per-manager Session table ceiling. It bounds live
	// Sessions and termination tombstones together: a tombstone occupies one
	// table slot until it expires, so the table never holds more than
	// MaxSessions entries in total.
	MaxSessions = 1024
	// MaxPendingBytes is the per-Session pending wire-byte ceiling (65,897),
	// covering one maximum Flow UDP datagram's two wire frames or one 64 KiB
	// Stream credit window in a single direction.
	MaxPendingBytes = 65897
	// MaxControlPayload is the SESSION_CTRL/SESSION_READY bootstrap payload
	// ceiling: non-empty and no larger than 8 KiB.
	MaxControlPayload = 8 << 10
	// DefaultPendingTTL is how long a pending attempt may stay uncommitted
	// before the session fails. SESSION_READY outside it must be rejected.
	DefaultPendingTTL = 30 * time.Second

	// tombstoneTTL is how long a SessionID terminated by Abort or by the
	// pending deadline keeps rejecting a late SESSION_CTRL. It is exactly the
	// frozen pending deadline: every retransmission of the failed attempt is
	// still inside that window, after which the dead identity is forgotten and
	// its table slot is reclaimed.
	tombstoneTTL = DefaultPendingTTL

	// FirstAttempt is the frozen first SESSION_CTRL attempt number: the initial
	// handshake is explicitly attempt=0, not an implicit zero value.
	FirstAttempt uint32 = 0
	// FirstTargetEpoch is the frozen first target_epoch: the initial handshake
	// targets epoch 1 while current_epoch is 0, so a successful first commit
	// installs KeyEpoch=1.
	FirstTargetEpoch uint32 = 1

	// PrologueBindingSize is the exact size of the bytes returned by
	// Session.Prologue:
	// ContextID:32B | SrcNodeID:16B | DstNodeID:16B | SessionID:16B |
	// SessionClass:u8 | data_lane_id:u8 | attempt:u32be | target_epoch:u32be |
	// PathID:u64be | PathGeneration:u32be.
	PrologueBindingSize = 32 + 16 + 16 + 16 + 1 + 1 + 4 + 4 + 8 + 4

	// sessionCtrlHeaderSize is SessionID:16B | class:u8 | lane:u8 |
	// attempt:u32be | target_epoch:u32be; the opaque handshake body follows as
	// noise_len:u16be | noise_message.
	sessionCtrlHeaderSize = 16 + 1 + 1 + 4 + 4
	sessionCtrlLengthSize = 2
	// sessionReadySize is SessionID:16B | class:u8 | lane:u8 | attempt:u32be |
	// target_epoch:u32be | PathID:u64be | PathGeneration:u32be.
	sessionReadySize = 16 + 1 + 1 + 4 + 4 + 8 + 4

	maxSessionIDAttempts = 8
)

// Public errors. Every rejection this package returns matches exactly one of
// these sentinels through errors.Is.
var (
	// ErrInvalidConfig reports a manager config that cannot be used.
	ErrInvalidConfig = errors.New("session: invalid manager config")
	// ErrInvalidScope reports a zero PathID/Generation or an unusable scope.
	ErrInvalidScope = errors.New("session: invalid path scope")
	// ErrInvalidClass reports a SessionClass other than PACKET/STREAM.
	ErrInvalidClass = errors.New("session: invalid session class")
	// ErrInvalidLane reports a Lane other than PACKET/STREAM.
	ErrInvalidLane = errors.New("session: invalid data lane")
	// ErrLaneClassMismatch reports a data lane that is not the lane of its class.
	ErrLaneClassMismatch = errors.New("session: data lane does not match session class")
	// ErrUnknownPeer reports a resolver failure for a Path scope.
	ErrUnknownPeer = errors.New("session: peer resolution failed")
	// ErrInvalidPeer reports resolved peer material that is empty or whose
	// NodeID does not match SHA-256(StaticKey)[0:16].
	ErrInvalidPeer = errors.New("session: invalid resolved peer")
	// ErrResourceLimit reports the MaxSessions table ceiling, counting live
	// Sessions and termination tombstones together.
	ErrResourceLimit = errors.New("session: session table limit reached")
	// ErrSessionNotFound reports a control message for a scope this manager does
	// not own, including a replayed message after local timeout/abort.
	ErrSessionNotFound = errors.New("session: session not found")
	// ErrSessionIDMismatch reports a control message carrying another SessionID.
	ErrSessionIDMismatch = errors.New("session: session id mismatch")
	// ErrSessionState reports an operation that the current lifecycle state does
	// not allow.
	ErrSessionState = errors.New("session: invalid session state transition")
	// ErrSessionClosed reports an operation after Close.
	ErrSessionClosed = errors.New("session: session closed")
	// ErrSessionAborted reports an operation after Abort.
	ErrSessionAborted = errors.New("session: session aborted")
	// ErrStaleSessionID reports a SESSION_CTRL for a SessionID that Abort or the
	// pending deadline already terminated. The dead identity stays remembered
	// for tombstoneTTL and must never be rebuilt; recovery starts a new
	// handshake with a fresh SessionID.
	ErrStaleSessionID = errors.New("session: stale session id")
	// ErrSessionTimeout reports that a pending attempt exceeded its deadline and
	// the session was failed.
	ErrSessionTimeout = errors.New("session: pending attempt deadline exceeded")
	// ErrHandshakeIncomplete reports a READY commit before the injected handshake
	// produced session root material.
	ErrHandshakeIncomplete = errors.New("session: handshake not complete")
	// ErrAttemptConflict reports an existing attempt re-sent with different
	// handshake bytes (SessionAttemptConflict).
	ErrAttemptConflict = errors.New("session: same attempt with different handshake bytes")
	// ErrStaleAttempt reports an attempt at or below the committed one.
	ErrStaleAttempt = errors.New("session: stale attempt")
	// ErrFutureAttempt reports an attempt above the next allowed one.
	ErrFutureAttempt = errors.New("session: future attempt")
	// ErrStaleEpoch reports a target epoch at or below the committed epoch.
	ErrStaleEpoch = errors.New("session: stale target epoch")
	// ErrFutureEpoch reports a target epoch above current_epoch+1.
	ErrFutureEpoch = errors.New("session: future target epoch")
	// ErrEpochExhausted reports that KeyEpoch reached the u32 ceiling; the
	// session must end and a new SessionID/root must be used instead of wrapping.
	ErrEpochExhausted = errors.New("session: key epoch exhausted")
	// ErrReplay reports a control message that repeats a step which can no
	// longer be answered byte-identically.
	ErrReplay = errors.New("session: replayed session control")
	// ErrPendingLimit reports a reservation above MaxPendingBytes.
	ErrPendingLimit = errors.New("session: pending byte limit reached")
	// ErrInvalidPending reports a negative pending reservation.
	ErrInvalidPending = errors.New("session: invalid pending byte count")
	// ErrPayloadTooLarge reports an encoded or opaque payload above 8 KiB.
	ErrPayloadTooLarge = errors.New("session: control payload too large")
	// ErrMalformedMessage reports a structurally invalid control payload.
	ErrMalformedMessage = errors.New("session: malformed session control message")
	// ErrInvalidCryptoResult reports an injected handshake returning empty
	// material where non-empty bytes are required.
	ErrInvalidCryptoResult = errors.New("session: invalid crypto handshake result")
	// ErrClosed reports an operation on a closed manager.
	ErrClosed = errors.New("session: manager closed")
	// ErrCryptoUnavailable is returned by the default placeholder
	// CryptoProvider until the exact KDF/transcript implementation is
	// independently validated and frozen. It is not a temporary failure and
	// callers must not treat it as evidence that end-to-end crypto works.
	ErrCryptoUnavailable = errors.New("session: crypto provider unavailable")
)

// SessionID is the 16-byte CSPRNG session identifier chosen by the Path's
// logical source and echoed by every hop.
type SessionID [16]byte

// IsZero reports whether the identifier is unset.
func (id SessionID) IsZero() bool { return id == SessionID{} }

// String renders the identifier as lowercase hex for diagnostics.
func (id SessionID) String() string { return hex.EncodeToString(id[:]) }

// SessionClass selects which data plane a Session carries. The numeric values
// are the frozen LaneID values; CONTROL is never a SessionClass.
type SessionClass uint8

const (
	// SessionClassPacket carries IP_PACKET/UDP_DATAGRAM on the PACKET lane.
	SessionClassPacket SessionClass = 0x01
	// SessionClassStream carries STREAM_DATA/CONTROL_RPC on the STREAM lane.
	SessionClassStream SessionClass = 0x02
)

// Valid reports whether the class may own a Session.
func (c SessionClass) Valid() bool { return c == SessionClassPacket || c == SessionClassStream }

// Lane returns the single data lane this class is bound to.
func (c SessionClass) Lane() Lane {
	switch c {
	case SessionClassPacket:
		return LanePacket
	case SessionClassStream:
		return LaneStream
	default:
		return 0
	}
}

func (c SessionClass) String() string {
	switch c {
	case SessionClassPacket:
		return "PACKET"
	case SessionClassStream:
		return "STREAM"
	default:
		return fmt.Sprintf("SESSION_CLASS(0x%02x)", uint8(c))
	}
}

// Lane is a data lane. The values mirror the frozen LaneID enum; Paths and
// Sessions never use the CONTROL lane.
type Lane uint8

const (
	// LanePacket is the low-latency PACKET lane.
	LanePacket Lane = 0x01
	// LaneStream is the STREAM/Bulk lane.
	LaneStream Lane = 0x02
)

// Valid reports whether the lane may carry a Path or Session.
func (l Lane) Valid() bool { return l == LanePacket || l == LaneStream }

func (l Lane) String() string {
	switch l {
	case LanePacket:
		return "PACKET"
	case LaneStream:
		return "STREAM"
	default:
		return fmt.Sprintf("LANE(0x%02x)", uint8(l))
	}
}

// Key is the complete local identity of one Session: the full ContextID, the
// two selected-handshake endpoints, the Path scope (PathID/PathGeneration) and
// the SessionClass with its single data lane. The Manager table is keyed by
// this whole tuple, so a SESSION_CTRL/SESSION_READY that disagrees in any field
// - another ContextID, the reversed or a different endpoint pair, another Path
// generation, class or lane - can never match or overwrite an existing Session.
//
// SrcNodeID/DstNodeID are the logical endpoints of the selected handshake
// (initiator and responder), i.e. the Path's source and target rather than the
// adjacent physical neighbour.
type Key struct {
	// ContextID is the full NetworkContext.ID() (SHA-256 of the versioned
	// descriptor), not the u64 wire locator.
	ContextID [32]byte
	// SrcNodeID is the handshake initiator (the PATH_OPEN logical source).
	SrcNodeID [16]byte
	// DstNodeID is the handshake responder (the Path target).
	DstNodeID [16]byte
	// PathID is the Path this Session belongs to. Never zero.
	PathID uint64
	// PathGeneration is the Path generation. Never zero.
	PathGeneration uint32
	// Class is the SessionClass. Only PACKET/STREAM may own a Session.
	Class SessionClass
	// Lane is the data lane, which must equal Class.Lane().
	Lane Lane
}

// Validate rejects a Key that cannot identify a Session. The sentinel matches
// the field that is wrong so callers can tell a bad ContextID from a bad Path
// scope, class or lane.
func (k Key) Validate() error {
	if k.ContextID == ([32]byte{}) {
		return fmt.Errorf("%w: zero context id in session key", ErrInvalidConfig)
	}
	if k.SrcNodeID == ([16]byte{}) || k.DstNodeID == ([16]byte{}) {
		return fmt.Errorf("%w: empty session endpoint", ErrInvalidScope)
	}
	if k.SrcNodeID == k.DstNodeID {
		return fmt.Errorf("%w: session endpoints are equal", ErrInvalidScope)
	}
	if k.PathID == 0 || k.PathGeneration == 0 {
		return fmt.Errorf("%w: path %d/%d", ErrInvalidScope, k.PathID, k.PathGeneration)
	}
	if !k.Class.Valid() {
		return fmt.Errorf("%w: class 0x%02x", ErrInvalidClass, uint8(k.Class))
	}
	if !k.Lane.Valid() {
		return fmt.Errorf("%w: lane 0x%02x", ErrInvalidLane, uint8(k.Lane))
	}
	if k.Lane != k.Class.Lane() {
		return fmt.Errorf("%w: lane %s for class %s", ErrLaneClassMismatch, k.Lane, k.Class)
	}
	return nil
}

// String renders the identity for diagnostics.
func (k Key) String() string {
	return fmt.Sprintf("context %x path %d/%d %s/%s src %x dst %x",
		k.ContextID[:4], k.PathID, k.PathGeneration, k.Class, k.Lane, k.SrcNodeID[:4], k.DstNodeID[:4])
}

// scopeKey is the per-Path uniqueness scope: at most one live Session may exist
// for one (PathID, PathGeneration, SessionClass). The endpoint pair and lane
// are checked against it, but they do not widen the scope.
type scopeKey struct {
	pathID     uint64
	generation uint32
	class      SessionClass
}

func (k scopeKey) String() string {
	return fmt.Sprintf("path %d/%d %s", k.pathID, k.generation, k.class)
}

func scopeOf(k Key) scopeKey {
	return scopeKey{pathID: k.PathID, generation: k.PathGeneration, class: k.Class}
}

// Role is the local node's position in the selected session handshake.
type Role uint8

const (
	// RoleInitiator is the PATH_OPEN logical source: it owns the SessionID and
	// is the only side allowed to start a rekey.
	RoleInitiator Role = iota + 1
	// RoleResponder is a hop or the target of the Path.
	RoleResponder
)

func (r Role) String() string {
	switch r {
	case RoleInitiator:
		return "Initiator"
	case RoleResponder:
		return "Responder"
	default:
		return fmt.Sprintf("ROLE(%d)", uint8(r))
	}
}

// State is the Session lifecycle state. The zero value is not a valid state.
type State uint8

const (
	// StatePending: an attempt is in flight and no epoch has been committed yet.
	StatePending State = iota + 1
	// StateReady: at least one epoch was committed by SESSION_READY; a rekey
	// attempt may still be in flight while the committed epoch keeps working.
	StateReady
	// StateBroken: terminal failure (deadline exceeded or local abort). A later
	// session for the same scope must use a fresh SessionID.
	StateBroken
	// StateClosed: terminal, released by Close.
	StateClosed
)

func (s State) String() string {
	switch s {
	case StatePending:
		return "Pending"
	case StateReady:
		return "Ready"
	case StateBroken:
		return "Broken"
	case StateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("STATE(%d)", uint8(s))
	}
}

// Attempt is one session handshake attempt. Bytes is the cached outgoing
// SESSION_CTRL payload (initiator: the first message; responder: the reply) so
// a retransmission of the same role/step/attempt is byte-identical. Bytes is
// nil once the attempt is committed, aborted, timed out or closed.
type Attempt struct {
	Attempt     uint32
	TargetEpoch uint32
	Bytes       []byte
}

// Peer is the authenticated remote endpoint of a Path: the remote NodeID and
// the X25519 static public key the NodeID was derived from.
type Peer struct {
	NodeID    [16]byte
	StaticKey [32]byte
}

// PeerResolver resolves the authenticated peer of a Path scope. Implementations
// must only read an in-memory authenticated view, perform no network I/O and be
// safe for concurrent use; they are never called while a manager lock is held.
type PeerResolver interface {
	ResolvePeer(pathID uint64, pathGeneration uint32, class SessionClass) (Peer, error)
}

// HandshakeParams is the complete mode-independent binding handed to the
// injected CryptoProvider. It deliberately contains no private key material:
// the crypto implementation owns its private keys, CSPRNG and transcript.
type HandshakeParams struct {
	ContextID      [32]byte
	Prologue       []byte
	PSK            [32]byte
	LocalNodeID    [16]byte
	PeerNodeID     [16]byte
	LocalStatic    [32]byte
	PeerStatic     [32]byte
	SessionID      SessionID
	Class          SessionClass
	DataLaneID     Lane
	Attempt        uint32
	TargetEpoch    uint32
	PathID         uint64
	PathGeneration uint32
	// Initiator is true for the Path's source side (Noise IK initiator).
	Initiator bool
}

// CryptoProvider is the opaque session-crypto boundary. A review-approved
// concrete implementation is provided by NewNoiseProvider; this interface
// remains the only seam the Manager uses, and a nil Config.Crypto installs the
// unavailable placeholder so nothing pretends to encrypt.
//
// Implementations must be local, non-blocking computation: they are called
// while the manager serialises this scope, must honour ctx cancellation before
// consuming state, must not call back into Manager or Session, and must not
// retain the Prologue/first/response slices. A two-message IK exchange is
// expressed as Initiate -> Respond -> Finish.
type CryptoProvider interface {
	// Initiate returns the initiator's first opaque SESSION_CTRL payload.
	Initiate(ctx context.Context, p HandshakeParams) (first []byte, err error)
	// Respond consumes the initiator's first payload and returns the responder's
	// opaque payload plus its opaque session root material.
	Respond(ctx context.Context, p HandshakeParams, first []byte) (response []byte, root []byte, err error)
	// Finish consumes the responder's payload and returns the initiator's opaque
	// session root material.
	Finish(ctx context.Context, p HandshakeParams, response []byte) (root []byte, err error)
}

// Config holds the immutable inputs of a Manager.
type Config struct {
	// ContextID is the full NetworkContext.ID() (SHA-256 of the versioned
	// descriptor), not the u64 wire locator. Required.
	ContextID [32]byte
	// PSK is the network-wide Noise PSK. Required.
	PSK [32]byte
	// LocalStatic is the local X25519 static public key; the local NodeID is
	// derived as SHA-256(LocalStatic)[0:16]. Required.
	LocalStatic [32]byte
	// PeerStatic is the static public key of the only peer this manager talks
	// to. Optional: when zero, Resolver must resolve the peer per Path.
	PeerStatic [32]byte
	// Resolver resolves the authenticated peer for each Path scope. Optional
	// when PeerStatic is set; when both are set, Resolver wins.
	Resolver PeerResolver
	// Crypto is the injected opaque handshake boundary. A production provider
	// is available via NewNoiseProvider. When nil, the placeholder returning
	// ErrCryptoUnavailable is installed, so the session table, codec and
	// lifecycle still work but no handshake can start.
	Crypto CryptoProvider
}

// Manager owns the local Session table and its bounded resources. It is safe
// for concurrent use.
type Manager struct {
	contextID   [32]byte
	psk         [32]byte
	localStatic [32]byte
	localNodeID [16]byte
	peerStatic  [32]byte
	peerNodeID  [16]byte
	resolver    PeerResolver
	crypto      CryptoProvider
	rand        func([]byte) error

	mu       sync.Mutex
	sessions map[Key]*Session
	scopes   map[scopeKey]Key
	// tombstones holds the SessionIDs terminated by Abort or by the pending
	// deadline, mapped to the time their rejection window ends. They share the
	// MaxSessions table budget with live Sessions and are dropped by the same
	// lazy expiry pass.
	tombstones map[SessionID]time.Time
	closed     bool
}

// NewManager validates the immutable inputs and returns a Manager. A nil Crypto
// installs the unavailable placeholder; it does not silently pick a KDF.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.ContextID == ([32]byte{}) {
		return nil, fmt.Errorf("%w: zero context id", ErrInvalidConfig)
	}
	if cfg.PSK == ([32]byte{}) {
		return nil, fmt.Errorf("%w: zero PSK", ErrInvalidConfig)
	}
	if cfg.LocalStatic == ([32]byte{}) {
		return nil, fmt.Errorf("%w: zero local static key", ErrInvalidConfig)
	}
	if cfg.Resolver == nil && cfg.PeerStatic == ([32]byte{}) {
		return nil, fmt.Errorf("%w: neither peer static key nor resolver", ErrInvalidConfig)
	}
	localNodeID, err := nodeIDFromStaticKey(cfg.LocalStatic)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		contextID:   cfg.ContextID,
		psk:         cfg.PSK,
		localStatic: cfg.LocalStatic,
		localNodeID: localNodeID,
		resolver:    cfg.Resolver,
		crypto:      cfg.Crypto,
		rand: func(b []byte) error {
			_, err := rand.Read(b)
			return err
		},
		sessions:   make(map[Key]*Session),
		scopes:     make(map[scopeKey]Key),
		tombstones: make(map[SessionID]time.Time),
	}
	if m.crypto == nil {
		m.crypto = unavailableCryptoProvider{}
	}
	if cfg.PeerStatic != ([32]byte{}) {
		peerNodeID, err := nodeIDFromStaticKey(cfg.PeerStatic)
		if err != nil {
			return nil, err
		}
		if peerNodeID == localNodeID {
			return nil, fmt.Errorf("%w: peer static key is the local static key", ErrInvalidConfig)
		}
		m.peerStatic, m.peerNodeID = cfg.PeerStatic, peerNodeID
	}
	return m, nil
}

// Open starts the initiator side of a new Session for (pathID, generation,
// class) with the frozen baseline attempt=0, target_epoch=1, or returns the
// already existing Session for that scope unchanged (retries reuse the attempt
// and its byte-identical cached payload). The caller sends
// Session.Attempt().Bytes as the SESSION_CTRL payload.
//
// The created identity is the full Key: ContextID, the local NodeID as Src,
// the resolved peer NodeID as Dst, and the Path/class/lane scope. A scope that
// is already owned by a different identity (for example the peer also claimed
// to be the Path source) is rejected instead of creating a second SessionID.
//
// A SessionID that is still tombstoned is never handed out again, while the
// tombstone itself does not block reopening the scope: a terminated Session is
// replaced by a new handshake under a fresh SessionID. The MaxSessions ceiling
// covers live Sessions and termination tombstones together, so a table
// saturated with unexpired tombstones fails here with ErrResourceLimit until
// they expire.
//
// context cancellation and deadlines are honoured before any state is created
// and are also passed to the injected handshake; the pending deadline is the
// earlier of the context deadline and DefaultPendingTTL.
func (m *Manager) Open(ctx context.Context, pathID uint64, pathGeneration uint32, class SessionClass, lane Lane) (*Session, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidScope)
	}
	if err := validateScope(pathID, pathGeneration, class, lane); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	peer, err := m.resolvePeer(pathID, pathGeneration, class)
	if err != nil {
		return nil, err
	}
	key := Key{
		ContextID:      m.contextID,
		SrcNodeID:      m.localNodeID,
		DstNodeID:      peer.NodeID,
		PathID:         pathID,
		PathGeneration: pathGeneration,
		Class:          class,
		Lane:           lane,
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	now := time.Now()
	m.expireLocked(now)
	if existing, ok := m.sessions[key]; ok {
		return existing, nil
	}
	if err := m.checkScopeLocked(key); err != nil {
		return nil, err
	}
	if m.tableEntriesLocked() >= MaxSessions {
		return nil, fmt.Errorf("%w: table limit %d (live %d, tombstones %d)",
			ErrResourceLimit, MaxSessions, len(m.sessions), len(m.tombstones))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, err := m.newSessionIDLocked()
	if err != nil {
		return nil, err
	}
	s := &Session{
		mgr:      m,
		key:      key,
		id:       id,
		role:     RoleInitiator,
		peer:     peer,
		state:    StatePending,
		deadline: deadlineFrom(ctx, now),
	}
	if err := s.startAttemptLocked(ctx, FirstAttempt, FirstTargetEpoch); err != nil {
		return nil, err
	}
	m.insertLocked(s)
	return s, nil
}

// HandleOpen processes one inbound SESSION_CTRL message.
//
// For a scope with no local Session the local node is the responder: the
// message must be the initiator's first attempt (attempt=0, target_epoch=1),
// the injected handshake produces the reply, and the returned bytes are the
// SESSION_CTRL payload to send back. For an existing initiator Session the
// message is the responder's reply and completes the local handshake (no reply
// bytes). Repeating the same role/step/attempt bytes is idempotent and returns
// the same cached bytes without consuming handshake state again; different
// bytes for that attempt return ErrAttemptConflict; a lower/higher attempt or
// epoch returns ErrStaleAttempt/ErrStaleEpoch/ErrFutureAttempt/ErrFutureEpoch.
//
// A SESSION_CTRL that carries a SessionID terminated by Abort or by the pending
// deadline is rejected with ErrStaleSessionID for the 30-second tombstone
// window, whatever role and endpoints it claims: a replayed bootstrap message
// must never rebuild a Session under the failed identity. Recovery uses a new
// handshake with a fresh SessionID.
func (m *Manager) HandleOpen(ctx context.Context, msg SessionCtrl) (*Session, []byte, error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("%w: nil context", ErrInvalidScope)
	}
	if err := msg.validate(); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	peer, err := m.resolvePeer(msg.PathID, msg.PathGeneration, msg.Class)
	if err != nil {
		return nil, nil, err
	}
	key := Key{
		ContextID:      m.contextID,
		SrcNodeID:      msg.SrcNodeID,
		DstNodeID:      msg.DstNodeID,
		PathID:         msg.PathID,
		PathGeneration: msg.PathGeneration,
		Class:          msg.Class,
		Lane:           msg.DataLaneID,
	}
	if err := key.Validate(); err != nil {
		return nil, nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, nil, ErrClosed
	}
	now := time.Now()
	m.expireLocked(now)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if expires, tombstoned := m.tombstones[msg.SessionID]; tombstoned {
		return nil, nil, fmt.Errorf("%w: SESSION_CTRL %s for %s is rejected until %s",
			ErrStaleSessionID, msg.SessionID, scopeOf(key), expires.UTC().Format(time.RFC3339Nano))
	}
	if s, ok := m.sessions[key]; ok {
		if s.peer.NodeID != peer.NodeID || s.peer.StaticKey != peer.StaticKey {
			return nil, nil, fmt.Errorf("%w: resolved peer changed for %s", ErrInvalidPeer, scopeOf(key))
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.role == RoleInitiator {
			return s, nil, s.finishInitiatorLocked(ctx, msg, now)
		}
		out, err := s.respondLocked(ctx, msg, now)
		return s, out, err
	}
	// No local Session for this identity: only the responder role is possible
	// here, and only for the Path target (the local node), never for a scope
	// that is already owned by another identity.
	if err := m.checkScopeLocked(key); err != nil {
		return nil, nil, err
	}
	if msg.SrcNodeID == m.localNodeID {
		return nil, nil, fmt.Errorf("%w: no initiator session for %s", ErrSessionNotFound, scopeOf(key))
	}
	if msg.DstNodeID != m.localNodeID {
		return nil, nil, fmt.Errorf("%w: SESSION_CTRL destination is not the local node", ErrInvalidScope)
	}
	if msg.SrcNodeID != peer.NodeID {
		return nil, nil, fmt.Errorf("%w: SESSION_CTRL source is not the resolved peer", ErrInvalidPeer)
	}
	if m.tableEntriesLocked() >= MaxSessions {
		return nil, nil, fmt.Errorf("%w: table limit %d (live %d, tombstones %d)",
			ErrResourceLimit, MaxSessions, len(m.sessions), len(m.tombstones))
	}
	s := &Session{
		mgr:   m,
		key:   key,
		id:    msg.SessionID,
		role:  RoleResponder,
		peer:  peer,
		state: StatePending,
	}
	s.mu.Lock()
	out, err := s.respondLocked(ctx, msg, now)
	s.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	m.insertLocked(s)
	return s, out, nil
}

// HandleReady applies an inbound SESSION_READY to the matching Session,
// committing its pending attempt and target epoch. The complete identity
// (SessionID, class, lane, Path scope and both endpoints) is checked before any
// state changes, so a READY for another identity can never commit this
// Session. A duplicate READY for the committed attempt/epoch is idempotent;
// stale or future attempts/epochs are rejected without touching the committed
// epoch.
func (m *Manager) HandleReady(msg SessionReady) error {
	if err := msg.validate(); err != nil {
		return err
	}
	key := Key{
		ContextID:      m.contextID,
		SrcNodeID:      msg.SrcNodeID,
		DstNodeID:      msg.DstNodeID,
		PathID:         msg.PathID,
		PathGeneration: msg.PathGeneration,
		Class:          msg.Class,
		Lane:           msg.DataLaneID,
	}
	if err := key.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.expireLocked(time.Now())
	s, ok := m.sessions[key]
	if !ok {
		if _, owned := m.scopes[scopeOf(key)]; owned {
			return fmt.Errorf("%w: SESSION_READY endpoints do not match the selected handshake", ErrInvalidScope)
		}
		return fmt.Errorf("%w: SESSION_READY for %s", ErrSessionNotFound, scopeOf(key))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if msg.SessionID != s.id {
		return fmt.Errorf("%w: SESSION_READY %s for session %s", ErrSessionIDMismatch, msg.SessionID, s.id)
	}
	if msg.DataLaneID != s.key.Lane {
		return fmt.Errorf("%w: SESSION_READY lane %s for lane %s", ErrLaneClassMismatch, msg.DataLaneID, s.key.Lane)
	}
	return s.markReadyLocked(msg.Attempt, msg.TargetEpoch)
}

// Lookup returns the live Session of the (pathID, generation, class) scope.
// The Path scope owns at most one Session identity, so no endpoint argument is
// needed; LookupKey resolves an exact full identity instead.
func (m *Manager) Lookup(pathID uint64, generation uint32, class SessionClass) (*Session, error) {
	if pathID == 0 || generation == 0 || !class.Valid() {
		return nil, ErrInvalidScope
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	m.expireLocked(time.Now())
	key, ok := m.scopes[scopeKey{pathID: pathID, generation: generation, class: class}]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return m.sessions[key], nil
}

// LookupKey returns the live Session with exactly this identity, or
// ErrSessionNotFound. A Key from another ContextID can never match because the
// manager only owns Sessions of its own ContextID.
func (m *Manager) LookupKey(key Key) (*Session, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	m.expireLocked(time.Now())
	s, ok := m.sessions[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, key)
	}
	return s, nil
}

// Len returns the number of live Sessions; termination tombstones are not
// counted.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	return len(m.sessions)
}

// ExpirePending fails every Session whose pending attempt passed its deadline
// and removes it from the table, returning how many were failed. Each failure
// leaves a termination tombstone. Expired tombstones are dropped by the same
// pass and are not counted in the return value. Handshake attempts that
// complete in time are unaffected.
func (m *Manager) ExpirePending(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.expireLocked(now)
}

// Close releases every Session and marks the Manager closed. It is idempotent;
// existing Session handles keep reporting their terminal state. Every
// termination tombstone is dropped as well: a closed manager rejects all
// further control messages with ErrClosed, so no dead identity needs to be
// remembered.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	for _, s := range m.sessions {
		s.mu.Lock()
		s.releaseLocked(StateClosed, ErrSessionClosed)
		s.mu.Unlock()
	}
	m.sessions = make(map[Key]*Session)
	m.scopes = make(map[scopeKey]Key)
	m.tombstones = make(map[SessionID]time.Time)
	return nil
}

// expireLocked marks overdue pending attempts Broken, drops the tombstones
// whose rejection window passed and returns how many Sessions were failed. A
// failed attempt leaves a tombstone behind so its SessionID cannot be rebuilt
// from a late SESSION_CTRL. It is called with the manager lock held and takes
// each session lock in the fixed manager-then-session order.
func (m *Manager) expireLocked(now time.Time) int {
	m.expireTombstonesLocked(now)
	expired := 0
	for _, s := range m.sessions {
		s.mu.Lock()
		if s.attemptPending && !s.deadline.IsZero() && !now.Before(s.deadline) {
			s.releaseLocked(StateBroken, ErrSessionTimeout)
			m.deleteLocked(s)
			m.tombstones[s.id] = now.Add(tombstoneTTL)
			expired++
		}
		s.mu.Unlock()
	}
	return expired
}

// tableEntriesLocked is the MaxSessions-accounted table size: live Sessions
// plus termination tombstones. Called with the manager lock held.
func (m *Manager) tableEntriesLocked() int {
	return len(m.sessions) + len(m.tombstones)
}

// addTombstoneLocked remembers that id was terminated at now and must reject a
// late SESSION_CTRL until now+tombstoneTTL. Expired records are dropped first,
// so repeated termination cannot grow the map beyond the MaxSessions table
// budget it shares with live Sessions. Called with the manager lock held.
func (m *Manager) addTombstoneLocked(id SessionID, now time.Time) {
	m.expireTombstonesLocked(now)
	m.tombstones[id] = now.Add(tombstoneTTL)
}

// expireTombstonesLocked drops the termination records whose rejection window
// ended at or before now. Called with the manager lock held.
func (m *Manager) expireTombstonesLocked(now time.Time) {
	for id, expires := range m.tombstones {
		if !now.Before(expires) {
			delete(m.tombstones, id)
		}
	}
}

// insertLocked registers a Session in both the identity table and the
// per-Path uniqueness scope. Called with the manager lock held.
func (m *Manager) insertLocked(s *Session) {
	m.sessions[s.key] = s
	m.scopes[scopeOf(s.key)] = s.key
}

// deleteLocked removes the Session from the table if it is still the registered
// one, and drops the scope entry it owns. Called with the manager lock held.
func (m *Manager) deleteLocked(s *Session) {
	if current, ok := m.sessions[s.key]; ok && current == s {
		delete(m.sessions, s.key)
	}
	if key, ok := m.scopes[scopeOf(s.key)]; ok && key == s.key {
		delete(m.scopes, scopeOf(s.key))
	}
}

// checkScopeLocked rejects a Session whose Path scope is already owned by a
// different identity, which keeps "at most one SessionID per
// Path/Generation/SessionClass" true even if a peer claims the same scope.
// Called with the manager lock held.
func (m *Manager) checkScopeLocked(key Key) error {
	scope := scopeOf(key)
	if owner, ok := m.scopes[scope]; ok && owner != key {
		return fmt.Errorf("%w: scope %s already owned by src %x dst %x", ErrInvalidScope, scope, owner.SrcNodeID[:4], owner.DstNodeID[:4])
	}
	return nil
}

func (m *Manager) resolvePeer(pathID uint64, generation uint32, class SessionClass) (Peer, error) {
	peer := Peer{NodeID: m.peerNodeID, StaticKey: m.peerStatic}
	if m.resolver != nil {
		resolved, err := m.resolver.ResolvePeer(pathID, generation, class)
		if err != nil {
			return Peer{}, fmt.Errorf("%w: %s: %w", ErrUnknownPeer, scopeKey{pathID, generation, class}, err)
		}
		peer = resolved
	}
	if peer.StaticKey == ([32]byte{}) {
		return Peer{}, fmt.Errorf("%w: empty peer static key", ErrInvalidPeer)
	}
	nodeID, err := nodeIDFromStaticKey(peer.StaticKey)
	if err != nil {
		return Peer{}, err
	}
	if peer.NodeID != nodeID {
		return Peer{}, fmt.Errorf("%w: peer NodeID does not match its static key", ErrInvalidPeer)
	}
	if peer.NodeID == m.localNodeID {
		return Peer{}, fmt.Errorf("%w: peer is the local node", ErrInvalidPeer)
	}
	return peer, nil
}

func (m *Manager) newSessionIDLocked() (SessionID, error) {
	for attempt := 0; attempt < maxSessionIDAttempts; attempt++ {
		var id SessionID
		if err := m.rand(id[:]); err != nil {
			return SessionID{}, fmt.Errorf("session id: %w", err)
		}
		if id.IsZero() || m.sessionIDUsedLocked(id) {
			continue
		}
		return id, nil
	}
	return SessionID{}, fmt.Errorf("%w: no unique session id after %d attempts", ErrInvalidConfig, maxSessionIDAttempts)
}

// sessionIDUsedLocked reports whether id is already a live Session identity or
// is still inside a termination tombstone, so neither a generated nor an
// accepted SessionID can collide with a dead one. Called with the manager lock
// held.
func (m *Manager) sessionIDUsedLocked(id SessionID) bool {
	for _, s := range m.sessions {
		if s.id == id {
			return true
		}
	}
	_, tombstoned := m.tombstones[id]
	return tombstoned
}

// Session is one end-to-end Session handle. It is safe for concurrent use; a
// handle stays readable after the Session leaves the manager table.
type Session struct {
	mgr  *Manager
	key  Key
	id   SessionID
	role Role
	peer Peer

	mu             sync.Mutex
	state          State
	cause          error
	prologue       []byte
	attempt        Attempt
	attemptPending bool
	haveAttempt    bool
	epoch          uint32
	committed      uint32
	inboundSeen    bool
	inboundDigest  [32]byte
	// root is the committed root material of the current KeyEpoch. It keeps
	// serving the old epoch while a rekey attempt is pending.
	root []byte
	// pendingRoot/attemptRoot hold the root material of the in-flight attempt
	// until the matching SESSION_READY commits it.
	pendingRoot []byte
	attemptRoot bool
	pending     int
	deadline    time.Time
}

// Key returns the complete identity this Session was registered under.
func (s *Session) Key() Key { return s.key }

// ContextID returns the full NetworkContext ID of this Session.
func (s *Session) ContextID() [32]byte { return s.key.ContextID }

// ID returns the SessionID.
func (s *Session) ID() SessionID { return s.id }

// Class returns the SessionClass.
func (s *Session) Class() SessionClass { return s.key.Class }

// Lane returns the data lane this Session is bound to.
func (s *Session) Lane() Lane { return s.key.Lane }

// Role returns the local side of the selected handshake.
func (s *Session) Role() Role { return s.role }

// PathID returns the Path this Session belongs to.
func (s *Session) PathID() uint64 { return s.key.PathID }

// PathGeneration returns the Path generation this Session belongs to.
func (s *Session) PathGeneration() uint32 { return s.key.PathGeneration }

// SrcNodeID returns the selected handshake initiator (Path source).
func (s *Session) SrcNodeID() [16]byte { return s.key.SrcNodeID }

// DstNodeID returns the selected handshake responder (Path target).
func (s *Session) DstNodeID() [16]byte { return s.key.DstNodeID }

// Peer returns the authenticated remote endpoint bound at creation.
func (s *Session) Peer() Peer { return s.peer }

// State returns the lifecycle state after failing any overdue pending attempt.
func (s *Session) State() State {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Epoch returns the committed KeyEpoch, or 0 before the first READY commit.
func (s *Session) Epoch() uint32 {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch
}

// PendingAttempt reports whether an attempt is in flight (initial handshake or
// rekey) and therefore awaiting a matching SESSION_READY.
func (s *Session) PendingAttempt() bool {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attemptPending
}

// Deadline returns the pending-attempt deadline. It is the zero time before an
// attempt starts and after the session stops accepting one.
func (s *Session) Deadline() time.Time {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline
}

// Attempt returns a defensive copy of the current attempt record. Bytes is the
// cached outgoing SESSION_CTRL payload for byte-identical retransmission and is
// nil when no attempt is in flight.
func (s *Session) Attempt() Attempt {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attemptCopyLocked()
}

// Prologue returns a defensive copy of the mode-independent session binding of
// the current (or last) attempt, or nil before an attempt exists. The wiring
// owner must pass these bytes as the binding of
// NetworkContext.Prologue(PrologueDomain, binding) so the complete descriptor
// is bound by the frozen Prologue encoder; this package does not re-encode that
// wrapper.
func (s *Session) Prologue() []byte {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.prologue...)
}

// PrologueDigest returns SHA-256 over exactly the bytes Prologue returns, or
// the zero digest before an attempt exists. It is a local identity/retransmit
// digest of the binding bytes, not a substitute for any KDF: the digest covers
// this package's binding only, not the surrounding NetworkContext.Prologue
// wrapper, which the wiring owner applies.
func (s *Session) PrologueDigest() [32]byte {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prologue == nil {
		return [32]byte{}
	}
	return sha256.Sum256(s.prologue)
}

// Root returns a defensive copy of the committed session root material
// produced by the injected CryptoProvider, or nil before the first SESSION_READY
// commit (and after Abort/Close). Root material of an in-flight attempt stays
// internal until the matching READY commits it, so no caller can install a
// traffic key before the frozen commit point. During a rekey the committed
// (old-epoch) root keeps being returned until the new epoch commits. The root's
// internal structure and the traffic-key derivation from it are NOT defined
// here: that KDF is still unfrozen and must not be guessed.
func (s *Session) Root() []byte {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateBroken || s.state == StateClosed || s.root == nil {
		return nil
	}
	return append([]byte(nil), s.root...)
}

// RootEpoch is a typed (epoch, root) pair returned by Session.RootEpoch. Root
// is owned by the caller.
type RootEpoch struct {
	// Epoch is the committed KeyEpoch (>= 1 after the first SESSION_READY).
	Epoch uint32
	// Root is the canonical opaque root material of that epoch.
	Root []byte
}

// RootEpoch returns the committed epoch and its root material in one atomic
// read. A runtime installs the matching key epoch with
// E2EProtector.InstallEpoch(result.Epoch, result.Root) only after a matching
// SESSION_READY; it never recreates the protector and never resets the other
// epoch's counters or replay window. ok is false before the first READY commit
// and after Abort/Close. The manager/root material is unchanged by this call.
func (s *Session) RootEpoch() (RootEpoch, bool) {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateBroken || s.state == StateClosed || s.root == nil || s.epoch == 0 {
		return RootEpoch{}, false
	}
	return RootEpoch{Epoch: s.epoch, Root: append([]byte(nil), s.root...)}, true
}

// MarkReady commits the given attempt/target_epoch locally after a successful
// handshake and inbound READY validation. The attempt and epoch must match the
// pending attempt exactly; a duplicate commit is idempotent; anything else is
// ErrStaleAttempt/ErrFutureAttempt/ErrStaleEpoch/ErrFutureEpoch. A commit
// before the injected handshake produced root material is
// ErrHandshakeIncomplete, and never moves a committed epoch backwards.
func (s *Session) MarkReady(attempt, targetEpoch uint32) error {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.markReadyLocked(attempt, targetEpoch)
}

// Rekey starts the next attempt (attempt+1, target_epoch=current+1) as the Path
// owner. While an attempt is already pending this merges into it and returns
// the same byte-identical payload instead of starting a second attempt.
func (s *Session) Rekey(ctx context.Context) (Attempt, error) {
	if ctx == nil {
		return Attempt{}, fmt.Errorf("%w: nil context", ErrSessionState)
	}
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Attempt{}, ErrClosed
	}
	now := time.Now()
	m.expireLocked(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.state {
	case StateBroken, StateClosed:
		return Attempt{}, s.terminalLocked()
	case StatePending:
		return Attempt{}, fmt.Errorf("%w: rekey before the first READY commit", ErrSessionState)
	}
	if s.role != RoleInitiator {
		return Attempt{}, fmt.Errorf("%w: only the Path owner starts a rekey", ErrSessionState)
	}
	if s.attemptPending {
		return s.attemptCopyLocked(), nil
	}
	if s.epoch == ^uint32(0) || s.committed == ^uint32(0) {
		return Attempt{}, fmt.Errorf("%w: epoch %d attempt %d", ErrEpochExhausted, s.epoch, s.committed)
	}
	if err := s.startAttemptLocked(ctx, s.committed+1, s.epoch+1); err != nil {
		return Attempt{}, err
	}
	return s.attemptCopyLocked(), nil
}

// Abort fails the Session locally (terminal, idempotent) and removes it from
// the manager table so the scope can be reopened with a fresh SessionID. A
// failed transcript is never reused: the dead SessionID stays tombstoned for
// tombstoneTTL, a late SESSION_CTRL for it is rejected with ErrStaleSessionID,
// and one MaxSessions table slot stays occupied until the tombstone expires.
func (s *Session) Abort() error {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateClosed || s.state == StateBroken {
		return nil
	}
	s.releaseLocked(StateBroken, ErrSessionAborted)
	m.deleteLocked(s)
	m.addTombstoneLocked(s.id, time.Now())
	return nil
}

// Close releases the Session and removes it from the manager table. It is
// idempotent; key material and the pending queue accounting are dropped.
//
// A cleanly closed Session leaves no tombstone: the local side ended it
// deliberately, so its SessionID and scope are released immediately. Abort and
// the pending deadline are the failures a late SESSION_CTRL could rebuild, and
// only those leave a tombstone. Closing an already aborted handle keeps the
// tombstone its Abort created.
func (s *Session) Close() error {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateClosed {
		return nil
	}
	s.releaseLocked(StateClosed, ErrSessionClosed)
	m.deleteLocked(s)
	return nil
}

// PendingBytes returns the currently reserved pending wire bytes.
func (s *Session) PendingBytes() int {
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending
}

// ReservePending accounts n pending wire bytes (the ReadyPending/RekeyPending
// queue that a later data path drains). The reservation fails with
// ErrPendingLimit above MaxPendingBytes and with ErrSessionClosed once the
// session is terminal.
func (s *Session) ReservePending(n int) error {
	if n < 0 {
		return fmt.Errorf("%w: %d", ErrInvalidPending, n)
	}
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateBroken || s.state == StateClosed {
		return s.terminalLocked()
	}
	if n == 0 {
		return nil
	}
	if n > MaxPendingBytes {
		return fmt.Errorf("%w: %d > %d", ErrPendingLimit, n, MaxPendingBytes)
	}
	if s.pending > MaxPendingBytes-n {
		return fmt.Errorf("%w: %d + %d > %d", ErrPendingLimit, s.pending, n, MaxPendingBytes)
	}
	s.pending += n
	return nil
}

// ReleasePending returns n previously reserved bytes. Releasing more than is
// reserved clamps to zero; terminal sessions simply drop the accounting.
func (s *Session) ReleasePending(n int) {
	if n <= 0 {
		return
	}
	m := s.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if n >= s.pending {
		s.pending = 0
		return
	}
	s.pending -= n
}

// startAttemptLocked allocates attempt/targetEpoch, builds the binding bytes,
// asks the injected handshake for its first payload and installs the pending
// attempt. Called with the manager and session locks held.
func (s *Session) startAttemptLocked(ctx context.Context, attempt, targetEpoch uint32) error {
	m := s.mgr
	prologue, err := PrologueBinding(s.key, s.id, attempt, targetEpoch)
	if err != nil {
		return err
	}
	params := m.params(s, prologue, attempt, targetEpoch, true)
	first, err := m.crypto.Initiate(ctx, params)
	if err != nil {
		return fmt.Errorf("session initiate: %w", err)
	}
	if len(first) == 0 {
		return fmt.Errorf("%w: empty initiator payload", ErrInvalidCryptoResult)
	}
	if len(first) > MaxControlPayload-sessionCtrlHeaderSize-sessionCtrlLengthSize {
		return fmt.Errorf("%w: initiator payload %d bytes", ErrPayloadTooLarge, len(first))
	}
	s.prologue = prologue
	s.attempt = Attempt{Attempt: attempt, TargetEpoch: targetEpoch, Bytes: append([]byte(nil), first...)}
	s.attemptPending = true
	s.haveAttempt = true
	s.inboundSeen = false
	s.inboundDigest = [32]byte{}
	s.pendingRoot = nil
	s.attemptRoot = false
	s.deadline = deadlineFrom(ctx, time.Now())
	return nil
}

// finishInitiatorLocked consumes the responder's reply for an initiator
// session, deriving root material through the injected handshake exactly once
// per attempt. Called with the manager and session locks held.
func (s *Session) finishInitiatorLocked(ctx context.Context, msg SessionCtrl, now time.Time) error {
	if err := s.terminalErrLocked(); err != nil {
		return err
	}
	if err := s.matchMessageLocked(msg); err != nil {
		return err
	}
	if !s.attemptPending {
		return fmt.Errorf("%w: no pending attempt for session %s", ErrReplay, s.id)
	}
	if err := s.matchAttemptLocked(msg.Attempt, msg.TargetEpoch); err != nil {
		return err
	}
	digest := sha256.Sum256(msg.Payload)
	if s.attemptRoot {
		if !s.inboundSeen || digest != s.inboundDigest {
			return fmt.Errorf("%w: attempt %d replayed with different bytes", ErrAttemptConflict, msg.Attempt)
		}
		return nil
	}
	params := s.mgr.params(s, s.prologue, s.attempt.Attempt, s.attempt.TargetEpoch, true)
	root, err := s.mgr.crypto.Finish(ctx, params, append([]byte(nil), msg.Payload...))
	if err != nil {
		return fmt.Errorf("session finish: %w", err)
	}
	if len(root) == 0 {
		return fmt.Errorf("%w: empty session root", ErrInvalidCryptoResult)
	}
	s.pendingRoot = append([]byte(nil), root...)
	s.attemptRoot = true
	s.inboundSeen = true
	s.inboundDigest = digest
	s.deadline = deadlineFrom(ctx, now)
	return nil
}

// respondLocked accepts the initiator's first payload for a responder session,
// starting the attempt when necessary and otherwise answering a byte-identical
// retransmission from the cache. Called with the manager and session locks held.
func (s *Session) respondLocked(ctx context.Context, msg SessionCtrl, now time.Time) ([]byte, error) {
	if err := s.terminalErrLocked(); err != nil {
		return nil, err
	}
	if err := s.matchMessageLocked(msg); err != nil {
		return nil, err
	}
	wantAttempt, wantEpoch := FirstAttempt, FirstTargetEpoch
	switch {
	case s.attemptPending:
		wantAttempt, wantEpoch = s.attempt.Attempt, s.attempt.TargetEpoch
	case s.haveAttempt:
		wantAttempt, wantEpoch = s.committed+1, s.epoch+1
	}
	if msg.Attempt < wantAttempt {
		return nil, fmt.Errorf("%w: attempt %d < %d for session %s", ErrStaleAttempt, msg.Attempt, wantAttempt, s.id)
	}
	if msg.Attempt > wantAttempt {
		return nil, fmt.Errorf("%w: attempt %d > %d for session %s", ErrFutureAttempt, msg.Attempt, wantAttempt, s.id)
	}
	if msg.TargetEpoch < wantEpoch {
		return nil, fmt.Errorf("%w: target epoch %d < %d for session %s", ErrStaleEpoch, msg.TargetEpoch, wantEpoch, s.id)
	}
	if msg.TargetEpoch > wantEpoch {
		return nil, fmt.Errorf("%w: target epoch %d > %d for session %s", ErrFutureEpoch, msg.TargetEpoch, wantEpoch, s.id)
	}
	digest := sha256.Sum256(msg.Payload)
	if s.inboundSeen {
		if digest != s.inboundDigest {
			return nil, fmt.Errorf("%w: attempt %d replayed with different bytes", ErrAttemptConflict, msg.Attempt)
		}
		return append([]byte(nil), s.attempt.Bytes...), nil
	}
	prologue, err := PrologueBinding(s.key, s.id, msg.Attempt, msg.TargetEpoch)
	if err != nil {
		return nil, err
	}
	params := s.mgr.params(s, prologue, msg.Attempt, msg.TargetEpoch, false)
	response, root, err := s.mgr.crypto.Respond(ctx, params, append([]byte(nil), msg.Payload...))
	if err != nil {
		return nil, fmt.Errorf("session respond: %w", err)
	}
	if len(response) == 0 {
		return nil, fmt.Errorf("%w: empty responder payload", ErrInvalidCryptoResult)
	}
	if len(response) > MaxControlPayload-sessionCtrlHeaderSize-sessionCtrlLengthSize {
		return nil, fmt.Errorf("%w: responder payload %d bytes", ErrPayloadTooLarge, len(response))
	}
	if len(root) == 0 {
		return nil, fmt.Errorf("%w: empty session root", ErrInvalidCryptoResult)
	}
	s.prologue = prologue
	s.attempt = Attempt{Attempt: msg.Attempt, TargetEpoch: msg.TargetEpoch, Bytes: append([]byte(nil), response...)}
	s.attemptPending = true
	s.haveAttempt = true
	s.inboundSeen = true
	s.inboundDigest = digest
	s.pendingRoot = append([]byte(nil), root...)
	s.attemptRoot = true
	s.deadline = deadlineFrom(ctx, now)
	return append([]byte(nil), response...), nil
}

// markReadyLocked commits the pending attempt at targetEpoch. Called with the
// manager and session locks held.
func (s *Session) markReadyLocked(attempt, targetEpoch uint32) error {
	if err := s.terminalErrLocked(); err != nil {
		return err
	}
	if s.attemptPending {
		if err := s.matchAttemptLocked(attempt, targetEpoch); err != nil {
			return err
		}
		if !s.attemptRoot {
			return fmt.Errorf("%w: session %s attempt %d", ErrHandshakeIncomplete, s.id, attempt)
		}
		if targetEpoch <= s.epoch {
			return fmt.Errorf("%w: target epoch %d for current %d", ErrStaleEpoch, targetEpoch, s.epoch)
		}
		if targetEpoch > s.epoch+1 {
			return fmt.Errorf("%w: target epoch %d for current %d", ErrFutureEpoch, targetEpoch, s.epoch)
		}
		s.epoch = targetEpoch
		s.committed = attempt
		s.state = StateReady
		s.attemptPending = false
		s.attempt.Bytes = nil
		s.root = s.pendingRoot
		s.pendingRoot = nil
		s.attemptRoot = false
		s.inboundSeen = false
		s.inboundDigest = [32]byte{}
		s.deadline = time.Time{}
		return nil
	}
	if !s.haveAttempt {
		return fmt.Errorf("%w: session %s has no attempt", ErrSessionState, s.id)
	}
	if attempt == s.committed && targetEpoch == s.epoch {
		return nil
	}
	if attempt < s.committed {
		return fmt.Errorf("%w: attempt %d < committed %d", ErrStaleAttempt, attempt, s.committed)
	}
	if attempt > s.committed {
		return fmt.Errorf("%w: attempt %d > committed %d", ErrFutureAttempt, attempt, s.committed)
	}
	if targetEpoch < s.epoch {
		return fmt.Errorf("%w: target epoch %d < committed %d", ErrStaleEpoch, targetEpoch, s.epoch)
	}
	if targetEpoch > s.epoch {
		return fmt.Errorf("%w: target epoch %d > committed %d", ErrFutureEpoch, targetEpoch, s.epoch)
	}
	return fmt.Errorf("%w: SESSION_READY attempt %d epoch %d for session %s", ErrReplay, attempt, targetEpoch, s.id)
}

// matchMessageLocked checks that a SESSION_CTRL belongs to this session and to
// the endpoints of the selected handshake. Called with the session lock held.
func (s *Session) matchMessageLocked(msg SessionCtrl) error {
	if msg.SessionID != s.id {
		return fmt.Errorf("%w: SESSION_CTRL %s for session %s", ErrSessionIDMismatch, msg.SessionID, s.id)
	}
	if msg.Class != s.key.Class || msg.DataLaneID != s.key.Lane {
		return fmt.Errorf("%w: SESSION_CTRL %s/%s for %s/%s", ErrLaneClassMismatch, msg.Class, msg.DataLaneID, s.key.Class, s.key.Lane)
	}
	if msg.SrcNodeID != s.key.SrcNodeID || msg.DstNodeID != s.key.DstNodeID {
		return fmt.Errorf("%w: SESSION_CTRL endpoints do not match the selected handshake", ErrInvalidScope)
	}
	return nil
}

func (s *Session) matchAttemptLocked(attempt, targetEpoch uint32) error {
	if attempt < s.attempt.Attempt {
		return fmt.Errorf("%w: attempt %d < %d for session %s", ErrStaleAttempt, attempt, s.attempt.Attempt, s.id)
	}
	if attempt > s.attempt.Attempt {
		return fmt.Errorf("%w: attempt %d > %d for session %s", ErrFutureAttempt, attempt, s.attempt.Attempt, s.id)
	}
	if targetEpoch < s.attempt.TargetEpoch {
		return fmt.Errorf("%w: target epoch %d < %d for session %s", ErrStaleEpoch, targetEpoch, s.attempt.TargetEpoch, s.id)
	}
	if targetEpoch > s.attempt.TargetEpoch {
		return fmt.Errorf("%w: target epoch %d > %d for session %s", ErrFutureEpoch, targetEpoch, s.attempt.TargetEpoch, s.id)
	}
	return nil
}

func (s *Session) terminalErrLocked() error {
	switch s.state {
	case StateBroken, StateClosed:
		return s.terminalLocked()
	default:
		return nil
	}
}

func (s *Session) terminalLocked() error {
	if s.cause != nil {
		return s.cause
	}
	if s.state == StateClosed {
		return ErrSessionClosed
	}
	return ErrSessionAborted
}

func (s *Session) attemptCopyLocked() Attempt {
	copied := Attempt{Attempt: s.attempt.Attempt, TargetEpoch: s.attempt.TargetEpoch}
	if s.attempt.Bytes != nil {
		copied.Bytes = append([]byte(nil), s.attempt.Bytes...)
	}
	return copied
}

// releaseLocked moves the session to a terminal state and drops every buffer it
// owns. Called with the manager and session locks held.
func (s *Session) releaseLocked(state State, cause error) {
	s.state = state
	s.cause = cause
	s.attemptPending = false
	s.attempt = Attempt{Attempt: s.attempt.Attempt, TargetEpoch: s.attempt.TargetEpoch}
	s.inboundSeen = false
	s.inboundDigest = [32]byte{}
	s.root = nil
	s.pendingRoot = nil
	s.attemptRoot = false
	s.pending = 0
	s.deadline = time.Time{}
}

// PrologueBinding encodes the canonical mode-independent session binding of
// exactly PrologueBindingSize bytes:
//
//	ContextID:32B | SrcNodeID:16B | DstNodeID:16B | SessionID:16B |
//	SessionClass:u8 | data_lane_id:u8 | attempt:u32be | target_epoch:u32be |
//	PathID:u64be | PathGeneration:u32be
//
// The field order after the SessionID is the frozen SESSION_CTRL/prologue
// layout from security.md C-SEC-003, with the full ContextID standing in for
// the u64 network locator. Nothing here is a KDF: these bytes are the exact
// input a frozen implementation consumes through
// NetworkContext.Prologue(PrologueDomain, binding).
func PrologueBinding(key Key, id SessionID, attempt, targetEpoch uint32) ([]byte, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if id.IsZero() {
		return nil, fmt.Errorf("%w: zero session id", ErrMalformedMessage)
	}
	if targetEpoch == 0 {
		return nil, fmt.Errorf("%w: target epoch 0", ErrStaleEpoch)
	}
	out := make([]byte, 0, PrologueBindingSize)
	out = append(out, key.ContextID[:]...)
	out = append(out, key.SrcNodeID[:]...)
	out = append(out, key.DstNodeID[:]...)
	out = append(out, id[:]...)
	out = append(out, byte(key.Class), byte(key.Lane))
	out = binary.BigEndian.AppendUint32(out, attempt)
	out = binary.BigEndian.AppendUint32(out, targetEpoch)
	out = binary.BigEndian.AppendUint64(out, key.PathID)
	out = binary.BigEndian.AppendUint32(out, key.PathGeneration)
	return out, nil
}

// params builds the mode-independent handshake binding for one attempt. The
// prologue is passed explicitly so the injected provider always receives the
// bytes of the attempt being started (or finished), never a stale one.
func (m *Manager) params(s *Session, prologue []byte, attempt, targetEpoch uint32, initiator bool) HandshakeParams {
	return HandshakeParams{
		ContextID:      m.contextID,
		Prologue:       append([]byte(nil), prologue...),
		PSK:            m.psk,
		LocalNodeID:    m.localNodeID,
		PeerNodeID:     s.peer.NodeID,
		LocalStatic:    m.localStatic,
		PeerStatic:     s.peer.StaticKey,
		SessionID:      s.id,
		Class:          s.key.Class,
		DataLaneID:     s.key.Lane,
		Attempt:        attempt,
		TargetEpoch:    targetEpoch,
		PathID:         s.key.PathID,
		PathGeneration: s.key.PathGeneration,
		Initiator:      initiator,
	}
}

// SessionCtrl is a decoded SESSION_CTRL message. PathID, PathGeneration,
// SrcNodeID and DstNodeID are copied from the authenticated ROUTE_CTRL frame
// envelope (and hop header); they are not part of the SESSION_CTRL payload. The
// fixed SessionID/Class/Lane/attempt/target_epoch fields and the trailing
// opaque handshake bytes are encoded exactly as the frozen payload row.
type SessionCtrl struct {
	SessionID      SessionID
	Class          SessionClass
	DataLaneID     Lane
	Attempt        uint32
	TargetEpoch    uint32
	PathID         uint64
	PathGeneration uint32
	SrcNodeID      [16]byte
	DstNodeID      [16]byte
	Payload        []byte
}

// SessionReady is a decoded SESSION_READY message. Every field below the
// SessionID prefix is part of the SESSION_READY payload; Src/Dst come from the
// ROUTE_CTRL envelope.
type SessionReady struct {
	SessionID      SessionID
	Class          SessionClass
	DataLaneID     Lane
	Attempt        uint32
	TargetEpoch    uint32
	PathID         uint64
	PathGeneration uint32
	SrcNodeID      [16]byte
	DstNodeID      [16]byte
}

// Encode returns the SESSION_CTRL payload:
// SessionID:16B | SessionClass:u8 | data_lane_id:u8 | attempt:u32be |
// target_epoch:u32be | noise_len:u16be | noise_message. The envelope-owned
// PathID/Generation/Src/Dst fields are not part of this payload.
func (c SessionCtrl) Encode() ([]byte, error) {
	if c.SessionID.IsZero() {
		return nil, fmt.Errorf("%w: zero session id", ErrMalformedMessage)
	}
	if !c.Class.Valid() {
		return nil, fmt.Errorf("%w: class 0x%02x", ErrInvalidClass, uint8(c.Class))
	}
	if c.DataLaneID != c.Class.Lane() {
		return nil, fmt.Errorf("%w: lane %s for class %s", ErrLaneClassMismatch, c.DataLaneID, c.Class)
	}
	if len(c.Payload) == 0 {
		return nil, fmt.Errorf("%w: empty handshake payload", ErrMalformedMessage)
	}
	total := sessionCtrlHeaderSize + sessionCtrlLengthSize + len(c.Payload)
	if total > MaxControlPayload {
		return nil, fmt.Errorf("%w: %d bytes", ErrPayloadTooLarge, total)
	}
	out := make([]byte, 0, total)
	out = append(out, c.SessionID[:]...)
	out = append(out, byte(c.Class), byte(c.DataLaneID))
	out = binary.BigEndian.AppendUint32(out, c.Attempt)
	out = binary.BigEndian.AppendUint32(out, c.TargetEpoch)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c.Payload)))
	out = append(out, c.Payload...)
	return out, nil
}

// DecodeSessionCtrl parses a SESSION_CTRL payload. Envelope-owned fields stay
// zero and must be filled from the authenticated frame before HandleOpen.
func DecodeSessionCtrl(payload []byte) (SessionCtrl, error) {
	if len(payload) > MaxControlPayload {
		return SessionCtrl{}, fmt.Errorf("%w: %d bytes", ErrPayloadTooLarge, len(payload))
	}
	if len(payload) < sessionCtrlHeaderSize+sessionCtrlLengthSize {
		return SessionCtrl{}, fmt.Errorf("%w: SESSION_CTRL payload %d bytes", ErrMalformedMessage, len(payload))
	}
	var c SessionCtrl
	copy(c.SessionID[:], payload[:16])
	c.Class = SessionClass(payload[16])
	c.DataLaneID = Lane(payload[17])
	c.Attempt = binary.BigEndian.Uint32(payload[18:22])
	c.TargetEpoch = binary.BigEndian.Uint32(payload[22:26])
	declared := int(binary.BigEndian.Uint16(payload[26:28]))
	rest := payload[28:]
	if declared != len(rest) {
		return SessionCtrl{}, fmt.Errorf("%w: noise_len %d with %d remaining bytes", ErrMalformedMessage, declared, len(rest))
	}
	if declared == 0 {
		return SessionCtrl{}, fmt.Errorf("%w: empty handshake payload", ErrMalformedMessage)
	}
	if !c.Class.Valid() {
		return SessionCtrl{}, fmt.Errorf("%w: class 0x%02x", ErrInvalidClass, uint8(c.Class))
	}
	if c.DataLaneID != c.Class.Lane() {
		return SessionCtrl{}, fmt.Errorf("%w: lane %s for class %s", ErrLaneClassMismatch, c.DataLaneID, c.Class)
	}
	c.Payload = append([]byte(nil), rest...)
	return c, nil
}

// Encode returns the SESSION_READY payload:
// SessionID:16B | SessionClass:u8 | data_lane_id:u8 | attempt:u32be |
// target_epoch:u32be | PathID:u64be | PathGeneration:u32be.
func (r SessionReady) Encode() ([]byte, error) {
	if r.SessionID.IsZero() {
		return nil, fmt.Errorf("%w: zero session id", ErrMalformedMessage)
	}
	if !r.Class.Valid() {
		return nil, fmt.Errorf("%w: class 0x%02x", ErrInvalidClass, uint8(r.Class))
	}
	if r.DataLaneID != r.Class.Lane() {
		return nil, fmt.Errorf("%w: lane %s for class %s", ErrLaneClassMismatch, r.DataLaneID, r.Class)
	}
	if r.PathID == 0 || r.PathGeneration == 0 {
		return nil, fmt.Errorf("%w: path %d/%d", ErrInvalidScope, r.PathID, r.PathGeneration)
	}
	if r.TargetEpoch == 0 {
		return nil, fmt.Errorf("%w: target epoch 0", ErrStaleEpoch)
	}
	out := make([]byte, 0, sessionReadySize)
	out = append(out, r.SessionID[:]...)
	out = append(out, byte(r.Class), byte(r.DataLaneID))
	out = binary.BigEndian.AppendUint32(out, r.Attempt)
	out = binary.BigEndian.AppendUint32(out, r.TargetEpoch)
	out = binary.BigEndian.AppendUint64(out, r.PathID)
	out = binary.BigEndian.AppendUint32(out, r.PathGeneration)
	return out, nil
}

// DecodeSessionReady parses a SESSION_READY payload. Src/Dst stay zero and must
// be filled from the authenticated envelope before HandleReady.
func DecodeSessionReady(payload []byte) (SessionReady, error) {
	if len(payload) != sessionReadySize {
		return SessionReady{}, fmt.Errorf("%w: SESSION_READY payload %d bytes", ErrMalformedMessage, len(payload))
	}
	var r SessionReady
	copy(r.SessionID[:], payload[:16])
	r.Class = SessionClass(payload[16])
	r.DataLaneID = Lane(payload[17])
	r.Attempt = binary.BigEndian.Uint32(payload[18:22])
	r.TargetEpoch = binary.BigEndian.Uint32(payload[22:26])
	r.PathID = binary.BigEndian.Uint64(payload[26:34])
	r.PathGeneration = binary.BigEndian.Uint32(payload[34:38])
	if !r.Class.Valid() {
		return SessionReady{}, fmt.Errorf("%w: class 0x%02x", ErrInvalidClass, uint8(r.Class))
	}
	if r.DataLaneID != r.Class.Lane() {
		return SessionReady{}, fmt.Errorf("%w: lane %s for class %s", ErrLaneClassMismatch, r.DataLaneID, r.Class)
	}
	return r, nil
}

func (c SessionCtrl) validate() error {
	if c.SessionID.IsZero() {
		return fmt.Errorf("%w: zero session id", ErrMalformedMessage)
	}
	if !c.Class.Valid() {
		return fmt.Errorf("%w: class 0x%02x", ErrInvalidClass, uint8(c.Class))
	}
	if c.DataLaneID != c.Class.Lane() {
		return fmt.Errorf("%w: lane %s for class %s", ErrLaneClassMismatch, c.DataLaneID, c.Class)
	}
	if len(c.Payload) == 0 {
		return fmt.Errorf("%w: empty handshake payload", ErrMalformedMessage)
	}
	if len(c.Payload) > MaxControlPayload-sessionCtrlHeaderSize-sessionCtrlLengthSize {
		return fmt.Errorf("%w: handshake payload %d bytes", ErrPayloadTooLarge, len(c.Payload))
	}
	return validateRouting(c.PathID, c.PathGeneration, c.SrcNodeID, c.DstNodeID)
}

func (r SessionReady) validate() error {
	if r.SessionID.IsZero() {
		return fmt.Errorf("%w: zero session id", ErrMalformedMessage)
	}
	if !r.Class.Valid() {
		return fmt.Errorf("%w: class 0x%02x", ErrInvalidClass, uint8(r.Class))
	}
	if r.DataLaneID != r.Class.Lane() {
		return fmt.Errorf("%w: lane %s for class %s", ErrLaneClassMismatch, r.DataLaneID, r.Class)
	}
	if r.TargetEpoch == 0 {
		return fmt.Errorf("%w: target epoch 0", ErrStaleEpoch)
	}
	return validateRouting(r.PathID, r.PathGeneration, r.SrcNodeID, r.DstNodeID)
}

func validateRouting(pathID uint64, generation uint32, src, dst [16]byte) error {
	if pathID == 0 || generation == 0 {
		return fmt.Errorf("%w: path %d/%d", ErrInvalidScope, pathID, generation)
	}
	if src == ([16]byte{}) || dst == ([16]byte{}) {
		return fmt.Errorf("%w: empty endpoint", ErrInvalidScope)
	}
	if src == dst {
		return fmt.Errorf("%w: SrcNodeID equals DstNodeID", ErrInvalidScope)
	}
	return nil
}

func validateScope(pathID uint64, pathGeneration uint32, class SessionClass, lane Lane) error {
	if pathID == 0 || pathGeneration == 0 {
		return fmt.Errorf("%w: path %d/%d", ErrInvalidScope, pathID, pathGeneration)
	}
	if !class.Valid() {
		return fmt.Errorf("%w: class 0x%02x", ErrInvalidClass, uint8(class))
	}
	if !lane.Valid() {
		return fmt.Errorf("%w: lane 0x%02x", ErrInvalidLane, uint8(lane))
	}
	if lane != class.Lane() {
		return fmt.Errorf("%w: lane %s for class %s", ErrLaneClassMismatch, lane, class)
	}
	return nil
}

func nodeIDFromStaticKey(staticKey [32]byte) ([16]byte, error) {
	if staticKey == ([32]byte{}) {
		return [16]byte{}, fmt.Errorf("%w: empty static key", ErrInvalidPeer)
	}
	digest := sha256.Sum256(staticKey[:])
	var nodeID [16]byte
	copy(nodeID[:], digest[:16])
	return nodeID, nil
}

func deadlineFrom(ctx context.Context, now time.Time) time.Time {
	deadline := now.Add(DefaultPendingTTL)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return deadline
}

// unavailableCryptoProvider is the default CryptoProvider. It exists so the
// state machine, bounds and codec can be wired and tested while the exact Noise
// IK/KDF implementation is still unfrozen; it never invents key material, never
// falls back to a weaker mode and never claims end-to-end encryption.
type unavailableCryptoProvider struct{}

func (unavailableCryptoProvider) Initiate(context.Context, HandshakeParams) ([]byte, error) {
	return nil, ErrCryptoUnavailable
}

func (unavailableCryptoProvider) Respond(context.Context, HandshakeParams, []byte) ([]byte, []byte, error) {
	return nil, nil, ErrCryptoUnavailable
}

func (unavailableCryptoProvider) Finish(context.Context, HandshakeParams, []byte) ([]byte, error) {
	return nil, ErrCryptoUnavailable
}
