package link

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/yiiilin/simpletier/internal/wire"
)

var (
	ErrInvalidControlIO = errors.New("invalid protected control IO")
	ErrControlMessage   = errors.New("invalid post-handshake control message")
	ErrControlTerminal  = errors.New("protected control IO is terminal")

	// ErrUnexpectedKind reports a fully read frame whose FrameKind the caller's
	// strict reader does not accept. The frame was consumed from the stream; no
	// further frame is read or drained to look for an acceptable one.
	ErrUnexpectedKind = errors.New("unexpected protected frame kind")
	// ErrRouteMessage reports a ROUTE_CTRL frame or payload that violates the
	// frozen envelope/hop-header redundancy, reserved-value or length rules.
	ErrRouteMessage = errors.New("invalid route control message")
	// ErrEndToEndMessage reports an E2E frame or payload that violates the
	// frozen envelope/hop-header redundancy or length rules. The session
	// ciphertext itself is never interpreted here.
	ErrEndToEndMessage = errors.New("invalid end-to-end message")
	// ErrSessionNotAdmitted reports an E2E frame for a SessionID this Link has
	// not explicitly admitted. No admission, key or replay state is ever created
	// from an inbound envelope.
	ErrSessionNotAdmitted = errors.New("end-to-end session is not admitted on this link")
	// ErrSessionRetired reports a SessionID that was explicitly retired. A
	// retired SessionID is never re-admitted on the same Link: the hop key's
	// replay domain could otherwise be rebuilt from zero.
	ErrSessionRetired = errors.New("end-to-end session id retired on this link")
	// ErrSessionLimit reports the MaxAdmittedSessions ceiling, counting live
	// admissions and retired tombstones together.
	ErrSessionLimit = errors.New("admitted end-to-end session limit reached")
	// ErrSessionConflict reports an admission that disagrees with an existing
	// live admission of the same SessionID (another session class).
	ErrSessionConflict = errors.New("end-to-end session admission conflict")
	// ErrNonceReuse reports an outbound E2E (KeyEpoch,MessageNumber) that does
	// not strictly advance the admitted session's TX floor, so sealing it would
	// reuse a hop nonce.
	ErrNonceReuse = errors.New("end-to-end nonce was already used on this link")
	// ErrInvalidHopRoute reports hop-header fields (cursor/hop limit) outside the
	// frozen Path bounds, so the frame could never be forwarded legitimately.
	ErrInvalidHopRoute = errors.New("invalid hop route fields")

	// errSealSpent wraps an outbound E2E seal failure that happened after the TX
	// nonce floor was already spent. It is internal: such a failure must end the
	// object rather than let a caller retry uncertain bytes, and it is not part
	// of the public rejection vocabulary.
	errSealSpent = errors.New("end-to-end hop seal failed after spending a nonce")
)

// HopRoute carries the three ROUTE_CTRL/E2E hop-header fields a relay is
// allowed to rewrite (Wire C-WIRE-002). PathID/PathGeneration are not part of
// it: they are redundant copies of the envelope and are always taken from the
// envelope, so a writer cannot make the two disagree. Pad is always zero.
type HopRoute struct {
	Cursor          uint8
	HopLimit        uint8
	RemainingBudget uint32
}

// VerificationBudget aggregates failed hop-AEAD tag verifications so a caller
// can bound them across more than one Link (or across a Link and the inner E2E
// session layer). RecordFailure records one actual AEAD tag failure and reports
// whether the shared budget still allows the connection to continue; false means
// the aggregate boundary is reached. A Link invokes it only after a failed hop
// AEAD open, never for a replay, schema or shape rejection, and no key update
// ever resets it.
type VerificationBudget interface {
	RecordFailure() bool
}

// maxKeyUpdatePrepared bounds the immutable prepared-message whitelist. One
// transaction prepares at most the eleven 0x09 phases it can author plus the
// follower solicitation, so twice the recovery reserve is a generous ceiling
// while still being a hard bound.
const maxKeyUpdatePrepared = 2 * int(keyUpdateControlHandshakeReserve)

// kuPreparedControl is one immutable snapshot of an encoded ControlType 0x09
// body this Link itself prepared as a writer action, with the phase and the
// locked target tuple it was prepared for. It is the exact-message whitelist the
// hard-boundary precheck consults, so an arbitrary or foreign 0x09 can never
// bypass the usage policy.
type kuPreparedControl struct {
	phase     KeyUpdatePhase
	seq       uint64
	linkID    uint64
	linkEpoch uint64
	lane      uint8
	body      []byte
}

// ControlMessage contains an authenticated control type and owned payload bytes.
// FACT payload semantics are the future fact codec's responsibility. CAPABILITY
// is not accepted here: Handshake already exchanged and consumed it at counter 0.
type ControlMessage struct {
	Type    uint8
	Payload []byte
}

// ProtectedMessage is one fully hop-authenticated inbound outer frame.
//
// Payload is the owned hop-AEAD plaintext, i.e. exactly what this Link
// authenticated:
//
//   - LINK_CTRL: ControlType byte followed by the control payload; ReadControl
//     is the compatibility wrapper that splits it.
//   - ROUTE_CTRL: the bootstrap payload (SESSION_CTRL/PATH_*).
//   - E2E: the OPAQUE session ciphertext. This seam never runs the inner
//     end-to-end AEAD and never switches to decrypting it: the session layer
//     owns that key schedule and must call CommitEndToEnd after its own tag
//     verification before the hop replay floor moves.
//
// Envelope is nil for LINK_CTRL and an owned 85-byte copy for ROUTE_CTRL/E2E.
// HopHeader is the authenticated hop header (a relay reads its cursor/hop
// limit/budget through Hop). Class is the admitted SessionClass for E2E and 0
// otherwise.
type ProtectedMessage struct {
	Kind      wire.FrameKind
	Envelope  []byte
	Payload   []byte
	HopHeader [wire.HopHeaderSize]byte
	Class     byte
	// VerifiedLinkGeneration is the LinkGeneration of the root slot that
	// authenticated this frame. A frame held across a key update is drained from
	// its verified bytes, never re-opened under a removed root.
	VerifiedLinkGeneration uint32
}

// Hop returns the hop-header route fields of a received message.
func (m ProtectedMessage) Hop() HopRoute {
	return HopRoute{
		Cursor:          m.HopHeader[24],
		HopLimit:        m.HopHeader[25],
		RemainingBudget: binary.BigEndian.Uint32(m.HopHeader[26:30]),
	}
}

const (
	// MaxAdmittedSessions bounds the end-to-end sessions one ProtectedControlIO
	// may explicitly admit on one Link, counting live admissions and retired
	// keyless tombstones together. It mirrors the frozen per-node Session table
	// ceiling (session.MaxSessions / Wire C-WIRE-004 "每节点 Path 表项≤1024") so
	// this hop seam never becomes the widest session table in the node.
	// Exhaustion is an explicit resource failure (ErrSessionLimit), never silent
	// eviction. This seam does not implement a non-disruptive recovery for it:
	// see AdmitSession for why the budget only grows for the life of the Link.
	MaxAdmittedSessions = 1024

	// maxRoutePayload is the frozen ROUTE_CTRL bootstrap payload ceiling: it
	// must be non-empty and at most 8 KiB (Wire C-WIRE-001). It is enforced on
	// both the TX and the RX side: a hop-authenticated ROUTE_CTRL frame above it
	// could be read but never legitimately relayed, so it is rejected before any
	// floor movement instead of being accepted as usable state.
	maxRoutePayload = 8 << 10

	// maxEndToEndPayload is the largest opaque session ciphertext this seam can
	// place in one outer frame: MaxFrameLength minus kind, hop header, envelope
	// and the hop AEAD tag. Oversize is a local FrameTooLarge rejection before
	// any nonce or floor state moves, not a terminal transport failure, so a
	// caller can re-chunk without rebuilding the Link.
	maxEndToEndPayload = int(wire.MaxFrameLength) - wire.FrameKindSize - wire.HopHeaderSize - wire.EnvelopeSize - chacha20poly1305.Overhead

	// maxHopLimit and maxPathCursor are the frozen Path bounds: at most 16
	// nodes, so OverlayHopLimit starts at 16 and a cursor is at most 15.
	maxHopLimit   = 16
	maxPathCursor = 15

	// e2eTagSize is the frozen inner end-to-end ChaCha20-Poly1305 tag width. It
	// is the only relation between the E2E envelope's inner_len and the opaque
	// session-ciphertext length this hop seam carries, and it is checked without
	// ever opening that inner layer. A future inner AEAD with a different tag
	// width would require revising this seam, not guessing here.
	e2eTagSize = chacha20poly1305.Overhead

	// MaxVerifiedPendingFrames/MaxVerifiedPendingBytes bound the holder the
	// runtime uses to keep already-verified frames across a root switch (the
	// frozen per-Link control reservation).
	MaxVerifiedPendingFrames = 64
	MaxVerifiedPendingBytes  = 256 << 10

	// hopPadOffset is the hop header's 2-byte reserved pad field, which every
	// sender must emit as zero and every receiver must reject otherwise.
	hopPadOffset = 30
)

const maxControlPayload = int(wire.MaxFrameLength) - wire.FrameKindSize - wire.HopHeaderSize - 16 - 1

// sessionAdmission is the explicit, caller-installed state of one end-to-end
// session on this Link. The per-session hop keys are derived exactly like the
// LINK_CTRL/ROUTE_CTRL keys (same constructor, same descriptor, same direction
// labels) with the admitted SessionID and SessionClass added to the E2E info,
// so the hop replay domain is (LinkID, SessionID, class, direction).
//
// txEpoch/txCounter and rxEpoch/rxCounter are the ordered per-direction replay
// floors. Mutations are serialised by the owning writer/reader lock; the
// admission table only guards membership, class and the retired flag.
//
// Invariant: while retired is false both protectors are live; RetireSession sets
// retired and Destroys both protectors under the table's write lock. Every
// TX/RX path holds sessionMu.RLock across its seal/verify, so a retired entry is
// never sealed or opened (and a frame already holding the fence finishes first).
type sessionAdmission struct {
	sessionID [16]byte
	class     byte
	tx        *FrameProtector
	rx        *FrameProtector
	retired   bool
	// retiredTxGeneration/retiredRxGeneration are the Link generations in force
	// in each direction when this admission was retired.
	retiredTxGeneration uint32
	retiredRxGeneration uint32
	// retiredTxSerial/retiredRxSerial are the per-direction root serials in force
	// when this admission was retired. They are the monotonic evidence that the
	// tombstone's hop key can never authenticate a replay again: a tombstone is
	// reclaimable only once BOTH directions have advanced to a strictly newer
	// root serial at a mutually completed update. Generations are random and are
	// never compared for order.
	retiredTxSerial uint64
	retiredRxSerial uint64

	txEpoch   uint32
	txCounter uint64
	rxEpoch   uint32
	rxCounter uint64
	rxSeen    bool
}

// keyUpdateDirectionSlot is an immutable per-direction root snapshot. One is
// published atomically whenever that direction's root or generation changes, so
// an admission can derive a hop cipher from the exact root of each direction
// without acquiring txMu/rxMu (and therefore without waiting on a reader that is
// blocked in a network read).
//
// serial is the monotonic identity of this direction's root: 1 for the
// established root, then exactly one increment per actual direction switch. Root
// freshness is proved by this serial, never by the numeric generation, because a
// fresh generation is a random uint32 and may be lower than the one it replaced.
type keyUpdateDirectionSlot struct {
	root       [32]byte
	generation uint32
	direction  byte
	serial     uint64
}

// ProtectedControlIO performs bounded, synchronous protected frame I/O after
// Handshake. The caller exclusively hands off an established stream and owns its
// Close; this object never closes it, owns no queues/goroutines, and has no
// context watcher. Transport/semantic failures are terminal for the strict
// LINK_CTRL path, so the caller must close the Link to interrupt any other
// in-flight I/O. Aligned authentication/replay errors are returned without
// advancing the RX floor or silently retrying.
//
// It is one physical reader/writer for one Link direction pair and carries
// LINK_CTRL (WriteControl/ReadControl), ROUTE_CTRL (WriteRoute) and explicitly
// admitted hop-only E2E frames (WriteEndToEnd with AdmitSession). True
// end-to-end confidentiality is the separate session crypto layer: an E2E payload
// here is opaque session ciphertext that this object never decrypts.
//
// It is not a Network, fact store, routing loop or key-update implementation.
type ProtectedControlIO struct {
	stream      io.ReadWriteCloser
	tx          *FrameProtector
	rx          *FrameProtector
	txRoot      [32]byte
	rxRoot      [32]byte
	descriptor  []byte
	linkID      uint64
	linkEpoch   uint64
	txGen       uint32
	rxGen       uint32
	atomicTxGen atomic.Uint32
	atomicRxGen atomic.Uint32
	// atomicTxSlot/atomicRxSlot are immutable per-direction root snapshots
	// published atomically at each direction's switch. An admission loads both
	// pointers and derives its hop ciphers from them, so it never takes txMu/rxMu
	// and can never wait on a reader blocked in a network read.
	atomicTxSlot   atomic.Pointer[keyUpdateDirectionSlot]
	atomicRxSlot   atomic.Pointer[keyUpdateDirectionSlot]
	txDirection    byte
	rxDirection    byte
	initiator      bool
	localNodeID    [16]byte
	peerNodeID     [16]byte
	localStatic    [32]byte
	peerStatic     [32]byte
	capabilityMask uint64
	channelBinding []byte
	linkLane       uint8
	// rtt holds the round-trip estimate for this Link's control probes. Route costs are
	// derived from it, so it lives on the Link rather than on any one consumer.
	rtt                  rttEstimator
	kuMu                 sync.Mutex
	ku                   *keyUpdateEngine
	pendingSlot          *KeyUpdateSlot
	pendingAdmission     *sessionAdmission
	pendingRevisionValue [32]byte
	pendingGeneration    uint32
	// stableGeneration is the new generation recorded when a key update reached
	// mutual DONE. Zero means no update has ever completed on this Link.
	stableGeneration uint32
	// The stable proof records the exact mutual-DONE completion for THIS carrier:
	// the completed update sequence, the negotiated target tuple and the
	// per-direction root serials in force at completion. Reclaiming retired
	// tombstones is gated on this proof, never on a numeric generation order,
	// because a fresh generation is a random uint32 and may be numerically lower
	// than the one it replaced.
	stableProofValid      bool
	stableSeq             uint64
	stableTargetLinkID    uint64
	stableTargetLinkEpoch uint64
	stableLane            uint8
	stableTxSerial        uint64
	stableRxSerial        uint64
	fenceStartedFlag      bool
	cancelPendingFlag     bool
	// kuRecoveryReserve is the bounded number of non-key-update old-domain
	// control/route frames still permitted while a key-update transaction is in
	// flight. The policy's soft threshold starts an update before its hard
	// boundary, but the correlated control the handshake still needs (for example
	// an admission PING/PONG) would otherwise hit that hard boundary first. It is
	// armed when a transaction becomes active and cleared when it finishes, and
	// it never covers business E2E frames; exhaustion fails closed.
	kuRecoveryReserve uint32
	// kuReserveArmed records that the reserve was armed for the current
	// transaction. Arming is idempotent while it is set, so a follower that
	// repeats RequestKeyUpdate can never refresh the finite per-transaction
	// permit budget.
	kuReserveArmed bool
	// kuPrepared is the bounded, immutable whitelist of 0x09 bodies this Link
	// itself encoded as writer actions (sendAction). At the hard boundary a
	// control 0x09 is permitted only when it exactly matches one of these
	// snapshots.
	kuPrepared []kuPreparedControl
	// verifyBudget is the optional caller-installed shared failed-tag ledger,
	// consulted in addition to the built-in per-Link failed-auth limit.
	verifyBudget VerificationBudget
	// usage is the built-in operational key-use policy tracker. The constructor
	// installs the documented defaults, so it is never nil on a constructed
	// object and no caller has to configure a policy to get it.
	usage *keyUsageTracker
	// triggerMu guards the automatic-trigger action sink and its
	// once-per-stable-generation arming. It is never held while the sink runs.
	triggerMu      sync.Mutex
	kuSink         func([]KeyUpdateAction) error
	kuTriggerArmed bool
	kuTriggerErr   error
	// rxExpect is the armed post-FENCE RX obligation (guarded by rxMu): the next
	// physical frame must be the new-key CONFIRM. It is set only by switchRX.
	rxExpect             *keyUpdateRxExpectation
	resumedFlag          bool
	localFenceSentFlag   bool
	localConfirmSentFlag bool
	verifiedPending      []ProtectedMessage
	verifiedBytes        int
	txMu                 sync.Mutex
	rxMu                 sync.Mutex
	sessionMu            sync.RWMutex
	sessions             map[[16]byte]*sessionAdmission
	txNext               uint64
	rxLast               uint64
	rxSeen               bool
	routeNext            uint64
	routeLast            uint64
	routeSeen            bool
	terminal             atomic.Bool
}

// NewProtectedControlIO preserves the authenticated CAPABILITY counter-0 floor.
// initiator must be the role used by Handshake; roots are already local TX/RX,
// while KDF direction labels remain canonical initiator->responder or reverse.
// Success/rejection leaves stream ownership with the caller. The supplied result
// must come from successful Handshake; shape validation is not authentication.
//
// LINK_CTRL and ROUTE_CTRL share one directional protector per direction
// (purpose is part of the KDF and of the replay key); ROUTE_CTRL therefore does
// not inherit the CAPABILITY counter and starts its own RouteCtrlCounter at 0
// under the same LinkGeneration, as Wire C-WIRE-003 requires. No session is
// admitted at construction.
func NewProtectedControlIO(stream io.ReadWriteCloser, result LinkResult, descriptor []byte, initiator bool) (*ProtectedControlIO, error) {
	if nilValue(stream) || !validLinkResult(result) || len(descriptor) == 0 || result.CapabilityVersion != uint16(CapabilityVersion) || result.CapabilityMask != RequiredCapabilityMask {
		return nil, ErrInvalidControlIO
	}
	txDirection, rxDirection := DirectionInitiatorToResponder, DirectionResponderToInitiator
	if !initiator {
		txDirection, rxDirection = rxDirection, txDirection
	}
	ownedDescriptor := append([]byte(nil), descriptor...)
	tx, err := NewFrameProtector(result.TxRoot, ownedDescriptor, result.LinkID, [16]byte{}, SessionClassStream, txDirection)
	if err != nil {
		return nil, errors.Join(ErrInvalidControlIO, err)
	}
	// Validate the RX inputs now rather than delaying constructor rejection.
	rx, err := NewFrameProtector(result.RxRoot, ownedDescriptor, result.LinkID, [16]byte{}, SessionClassStream, rxDirection)
	if err != nil {
		return nil, errors.Join(ErrInvalidControlIO, err)
	}
	io := &ProtectedControlIO{
		stream:         stream,
		tx:             tx,
		rx:             rx,
		txRoot:         result.TxRoot,
		rxRoot:         result.RxRoot,
		descriptor:     ownedDescriptor,
		linkID:         result.LinkID,
		linkEpoch:      result.LinkEpoch,
		txGen:          result.Generation,
		rxGen:          result.Generation,
		txDirection:    txDirection,
		rxDirection:    rxDirection,
		initiator:      initiator,
		localNodeID:    result.LocalNodeID,
		peerNodeID:     result.PeerNodeID,
		localStatic:    result.LocalStatic,
		peerStatic:     result.PeerStatic,
		capabilityMask: result.CapabilityMask,
		channelBinding: append([]byte(nil), result.ChannelBinding...),
		linkLane:       result.LaneID,
		sessions:       make(map[[16]byte]*sessionAdmission),
		txNext:         1,
		rxSeen:         true,
		usage:          newKeyUsageTracker(DefaultKeyUpdatePolicy()),
	}
	io.atomicTxGen.Store(result.Generation)
	io.atomicRxGen.Store(result.Generation)
	// Publish the initial immutable direction snapshots. They are the only root
	// view an admission needs, so the constructor already makes it lock-free. Both
	// directions start at root serial 1.
	io.atomicTxSlot.Store(&keyUpdateDirectionSlot{root: result.TxRoot, generation: result.Generation, direction: txDirection, serial: 1})
	io.atomicRxSlot.Store(&keyUpdateDirectionSlot{root: result.RxRoot, generation: result.Generation, direction: rxDirection, serial: 1})
	return io, nil
}

// WriteControl validates before spending a nonce. The sole directional writer
// reserves each nonce in wire selection order, including failed/partial writes;
// no error path retries the unknown already-emitted bytes or rolls back a counter.
// The caller must not mutate message.Payload until this method returns.
func (c *ProtectedControlIO) WriteControl(message ControlMessage) (err error) {
	if c == nil {
		return ErrControlTerminal
	}
	c.txMu.Lock()
	defer func() {
		c.txMu.Unlock()
		// The policy trigger runs only after the direction lock is released, so
		// its sink may enqueue on this same writer without a nested lock.
		if err == nil {
			c.pollKeyUpdateTrigger()
		}
	}()
	if c.terminal.Load() {
		return ErrControlTerminal
	}
	if err := validateControlMessage(message); err != nil {
		return err
	}
	// The usage policy refuses to spend another control key once its hard
	// boundary is reached. The key-update opcode is the recovery channel and is
	// exempt, so a Link at the wall can still complete the update that makes it
	// safe again.
	if c.keyUsageHardStop(KeyDomainControl) {
		// The update opcode is the recovery channel, but it is NOT an unconditional
		// bypass: at the hard boundary a 0x09 body is allowed only when it is a
		// prepared action of the owned in-flight transaction (or the bounded
		// follower solicitation/terminal retransmission), and it consumes the same
		// finite shared recovery permit as any other control/route frame. A
		// malformed or arbitrary 0x09 owned by no transaction is refused before a
		// nonce is spent. Once the permit budget is exhausted the Link fails closed.
		if message.Type == ControlTypeKeyUpdate && !c.keyUpdateControlPermitted(message.Payload) {
			return ErrKeyUpdateRequired
		}
		if !c.spendKeyUpdateRecoveryReserve() {
			return ErrKeyUpdateRequired
		}
	}
	if c.txNext == ^uint64(0) {
		c.terminal.Store(true)
		return ErrCounterExhausted
	}
	counter := c.txNext
	c.txNext++
	plaintext := make([]byte, 1+len(message.Payload))
	plaintext[0] = message.Type
	copy(plaintext[1:], message.Payload)
	err = c.sealAndWriteLocked(c.tx, wire.Frame{Kind: wire.FrameKindLinkControl}, plaintext, c.txGen, counter, KeyDomainControl)
	clear(plaintext)
	return err
}

// WriteRoute seals and writes one ROUTE_CTRL frame under the LinkGeneration
// nonce domain with a strictly increasing per-direction RouteCtrlCounter that
// starts at 0.
//
// envelope must be exactly wire.EnvelopeSize bytes and is validated before a
// nonce is spent: MessageType must be a ROUTE_CTRL type, KeyEpoch and
// MessageNumber are reserved zero, PATH_OPEN/PATH_READY/PATH_BROKEN reserve a
// zero SessionID while SESSION_CTRL/SESSION_READY require a non-zero one, the
// envelope inner_len must equal len(payload), and the hop-header
// PathID/PathGeneration are the envelope copies. payload is the bootstrap
// plaintext: non-empty and at most 8 KiB.
//
// The caller must not mutate envelope, payload or hop until this returns. A
// partial or failed transport write leaves this object terminal with the counter
// already spent, so the uncertain bytes are never retried.
func (c *ProtectedControlIO) WriteRoute(envelope, payload []byte, hop HopRoute) (err error) {
	if c == nil {
		return ErrControlTerminal
	}
	c.txMu.Lock()
	defer func() {
		c.txMu.Unlock()
		if err == nil {
			c.pollKeyUpdateTrigger()
		}
	}()
	if c.terminal.Load() {
		return ErrControlTerminal
	}
	if c.keyUsageHardStop(KeyDomainRoute) {
		if !c.spendKeyUpdateRecoveryReserve() {
			return ErrKeyUpdateRequired
		}
	}
	pathID, pathGeneration, err := validateRouteEnvelope(envelope)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > maxRoutePayload {
		return fmt.Errorf("%w: bootstrap payload length %d", ErrRouteMessage, len(payload))
	}
	// A frame whose inner_len disagrees with the payload it carries could never
	// be accepted by the peer, so reject it locally before spending a counter.
	if inner := binary.BigEndian.Uint32(envelope[wire.EnvelopeInnerLengthOffset:]); uint64(inner) != uint64(len(payload)) {
		return fmt.Errorf("%w: inner_len %d does not match bootstrap payload %d", ErrRouteMessage, inner, len(payload))
	}
	if err := validateHopRoute(hop); err != nil {
		return err
	}
	if c.routeNext == ^uint64(0) {
		c.terminal.Store(true)
		return ErrCounterExhausted
	}
	counter := c.routeNext
	c.routeNext++
	frame := wire.Frame{Kind: wire.FrameKindRouteControl, HopHeader: makeHopHeader(pathID, pathGeneration, hop), Envelope: envelope}
	return c.sealAndWriteLocked(c.tx, frame, payload, c.txGen, counter, KeyDomainRoute)
}

// WriteEndToEnd seals and writes one E2E frame through the hop AEAD of an
// explicitly admitted session. The payload is OPAQUE session ciphertext: this
// method does not run, guess or fall back to the inner end-to-end AEAD.
//
// The 96-bit hop nonce is the envelope's KeyEpoch|MessageNumber byte-for-byte,
// and the hop key is the admitted session's (LinkID, SessionID, class,
// direction, descriptor) subkey. envelope must be exactly wire.EnvelopeSize
// bytes; SessionID must be non-zero and admitted; MessageType must belong to the
// admitted class's data lane (PACKET: IP_PACKET/UDP_DATAGRAM, STREAM:
// STREAM_DATA/CONTROL_RPC); KeyEpoch is non-zero; inner_len must equal
// len(payload)-16 for the frozen E2E AEAD tag; hop-header PathID/PathGeneration
// are the envelope copies.
//
// (KeyEpoch,MessageNumber) must strictly advance the session's TX floor or the
// call fails with ErrNonceReuse before any byte is sealed, so an outbound nonce
// is never reused and a retry of uncertain bytes is impossible: a failed
// transport write makes the object terminal with the nonce already spent.
//
// A ciphertext above maxEndToEndPayload is a local wire.ErrFrameTooLarge
// rejection before the session is even looked up: it spends no nonce, moves no
// floor and does not end the Link.
func (c *ProtectedControlIO) WriteEndToEnd(envelope, payload []byte, hop HopRoute) (err error) {
	if c == nil {
		return ErrControlTerminal
	}
	c.txMu.Lock()
	defer func() {
		c.txMu.Unlock()
		if err == nil {
			c.pollKeyUpdateTrigger()
		}
	}()
	if c.terminal.Load() {
		return ErrControlTerminal
	}
	if c.keyUsageHardStop(KeyDomainStream) {
		return ErrKeyUpdateRequired
	}
	if len(payload) > maxEndToEndPayload {
		return fmt.Errorf("%w: %d-byte session ciphertext exceeds %d", wire.ErrFrameTooLarge, len(payload), maxEndToEndPayload)
	}
	decoded, err := decodeEndToEndEnvelope(envelope, len(payload))
	if err != nil {
		return err
	}
	if err := validateHopRoute(hop); err != nil {
		return err
	}
	var frame wire.Frame
	// The sessionMu read fence is held across the seal so RetireSession cannot
	// destroy this session's keys mid-seal. A frame whose seal already completed
	// may still finish its transport write below; no later frame can.
	if err := c.withSession(decoded.sessionID, func(entry *sessionAdmission) error {
		if !classCarriesMessageType(entry.class, decoded.messageType) {
			return fmt.Errorf("%w: MessageType 0x%02x is not valid for session class 0x%02x", ErrEndToEndMessage, uint8(decoded.messageType), entry.class)
		}
		// The TX floor is guarded by txMu, so this check and the commit below are
		// one atomic allocation: concurrent writers of the same session cannot
		// both take the same (KeyEpoch,MessageNumber).
		if !advances(decoded.keyEpoch, decoded.messageNumber, entry.txEpoch, entry.txCounter, true) {
			return fmt.Errorf("%w: epoch %d counter %d is not above %d/%d", ErrNonceReuse, decoded.keyEpoch, decoded.messageNumber, entry.txEpoch, entry.txCounter)
		}
		entry.txEpoch, entry.txCounter = decoded.keyEpoch, decoded.messageNumber
		frame = wire.Frame{
			Kind:      wire.FrameKindEndToEnd,
			HopHeader: makeHopHeader(decoded.pathID, decoded.pathGeneration, hop),
			Envelope:  envelope,
		}
		sealed, err := entry.tx.Seal(frame, payload, decoded.keyEpoch, decoded.messageNumber)
		if err != nil {
			return fmt.Errorf("%w: %w", errSealSpent, err)
		}
		// One successful hop-AEAD seal of this domain, counted whether or not
		// the transport write below completes: the session nonce is spent.
		c.usage.seal(KeyDomainStream, len(payload))
		frame = sealed
		return nil
	}); err != nil {
		// A seal failure happens after the TX floor was spent, so the nonce can
		// never be retried: end the object rather than risk reusing uncertain
		// bytes. Rejections that spend nothing (nonce reuse, class mismatch,
		// retirement) leave the Link usable.
		if errors.Is(err, errSealSpent) {
			c.terminal.Store(true)
		}
		return err
	}
	if err := wire.WriteFrame(c.stream, frame); err != nil {
		c.terminal.Store(true)
		return err
	}
	return nil
}

// AdmitSession explicitly installs one end-to-end session on this Link and
// derives its directional hop subkeys. Nothing is ever admitted implicitly from
// an inbound envelope: ReadMessage only looks up this table.
//
// Admitting an already admitted SessionID with the same class is idempotent.
// A different class is ErrSessionConflict, a retired SessionID is
// ErrSessionRetired, and a full table is ErrSessionLimit.
//
// The table counts live admissions plus keyless retired tombstones for the whole
// life of the Link, because a retired SessionID must never be re-admitted under
// the same hop key. Exhausting MaxAdmittedSessions is therefore an explicit
// resource failure, and this seam deliberately does not paper over it: it
// implements no non-disruptive (rekey-style) recovery, and a caller reaching the
// limit has no in-band path to admit another session on this Link. Wiring a
// bounded, session/root-preserving lifecycle for that case remains open work and
// is not claimed here.
func (c *ProtectedControlIO) AdmitSession(sessionID [16]byte, class byte) error {
	if c == nil {
		return ErrControlTerminal
	}
	if sessionID == ([16]byte{}) {
		return fmt.Errorf("%w: zero SessionID", ErrSessionNotAdmitted)
	}
	if class != SessionClassPacket && class != SessionClassStream {
		return fmt.Errorf("%w: class 0x%02x", ErrSessionConflict, class)
	}
	// The snapshot load and both derivations run under sessionMu, the same lock
	// every direction's refreshSessionTX/refreshSessionRX takes. A publisher
	// (FENCE/switchRX) atomically stores the new direction snapshot BEFORE it
	// takes sessionMu to refresh the table, so serialising on this lock means an
	// admission can only derive from a snapshot the refresh has already accounted
	// for (or will account for immediately after release). Deriving outside the
	// lock let a new-generation leaf be inserted after the refresh had already
	// walked past the absent entry, so business sealed with the new root failed
	// the peer's AEAD open.
	//
	// This still takes no txMu/rxMu: a reader may hold rxMu across a blocking
	// network read, and an admission must never wait on network input. The lock
	// is held only for the two leaf KDFs and the table write, and NewFrameProtector
	// takes no direction lock.
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if existing, ok := c.sessions[sessionID]; ok {
		// The admission already exists: report the idempotent/conflict/retired
		// outcome without building a key pair that would only be discarded.
		if existing.retired {
			return fmt.Errorf("%w: session %x", ErrSessionRetired, sessionID)
		}
		if existing.class != class {
			return fmt.Errorf("%w: session %x is class 0x%02x", ErrSessionConflict, sessionID, existing.class)
		}
		return nil
	}
	if len(c.sessions) >= MaxAdmittedSessions {
		return fmt.Errorf("%w: %d sessions (live and retired)", ErrSessionLimit, MaxAdmittedSessions)
	}
	txSlot, rxSlot := c.atomicTxSlot.Load(), c.atomicRxSlot.Load()
	if txSlot == nil || rxSlot == nil {
		return ErrInvalidControlIO
	}
	tx, txErr := NewFrameProtector(txSlot.root, c.descriptor, c.linkID, sessionID, class, txSlot.direction)
	var rx *FrameProtector
	var rxErr error
	if txErr == nil {
		rx, rxErr = NewFrameProtector(rxSlot.root, c.descriptor, c.linkID, sessionID, class, rxSlot.direction)
	}
	if txErr != nil {
		return errors.Join(ErrInvalidControlIO, txErr)
	}
	if rxErr != nil {
		tx.Destroy()
		return errors.Join(ErrInvalidControlIO, rxErr)
	}
	c.sessions[sessionID] = &sessionAdmission{sessionID: sessionID, class: class, tx: tx, rx: rx}
	return nil
}

// RetireSession terminates the explicit admission of a SessionID, zeroes its
// directional hop subkeys (FrameProtector.Destroy) and keeps only keyless
// tombstone metadata (identity, class and the last replay floors) under the same
// MaxAdmittedSessions budget. It is idempotent.
//
// A retired SessionID is never re-admitted on this Link, and ReadMessage rejects
// its E2E frames with ErrSessionRetired. This is deliberate: the hop subkey for
// (LinkID, SessionID, class, direction) is unchanged by a re-admission, so
// re-deriving it would restart the replay floor under the same key and accept
// replayed frames. Recovery needs a fresh SessionID (Wire C-WIRE-003 requires a
// new SessionID/root for a closed Session) or a full re-establishment of the
// physical Link with new roots and Generation.
//
// Retirement is fenced against in-flight frames: Admit/Retire take the table's
// write lock, while TX seal and RX verify hold the read lock across the AEAD, so
// a frame that already acquired the fence finishes and no frame is sealed or
// opened with destroyed keys afterwards.
func (c *ProtectedControlIO) RetireSession(sessionID [16]byte) error {
	if c == nil {
		return ErrControlTerminal
	}
	if sessionID == ([16]byte{}) {
		return fmt.Errorf("%w: zero SessionID", ErrSessionNotAdmitted)
	}
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	entry, ok := c.sessions[sessionID]
	if !ok {
		return fmt.Errorf("%w: session %x", ErrSessionNotAdmitted, sessionID)
	}
	if entry.retired {
		return nil
	}
	entry.retired = true
	entry.retiredTxGeneration = c.atomicTxGen.Load()
	entry.retiredRxGeneration = c.atomicRxGen.Load()
	if slot := c.atomicTxSlot.Load(); slot != nil {
		entry.retiredTxSerial = slot.serial
	}
	if slot := c.atomicRxSlot.Load(); slot != nil {
		entry.retiredRxSerial = slot.serial
	}
	entry.tx.Destroy()
	entry.rx.Destroy()
	return nil
}

// FinalizeKeyUpdate releases the carrier state of exactly the transaction named
// by the proof: the target tuple, update sequence and new generation must match
// the installed pending slot. It clears the pending slot, admission, revision
// and generation, and zeroes the unused pending protectors only when no FENCE
// ever started (after a fence those protectors are the live c.tx/c.rx). Roots,
// generations, counters, the session table and the cancel gate are untouched. A
// missing slot is idempotent; a differing slot is a conflict and is left
// installed.
func (c *ProtectedControlIO) FinalizeKeyUpdate(seq, targetLinkID, targetLinkEpoch uint64, lane uint8, newGeneration uint32) error {
	if c == nil {
		return ErrControlTerminal
	}
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	slot := c.pendingSlot
	if slot == nil {
		return nil
	}
	if slot.Seq != seq || slot.NewGeneration != newGeneration ||
		slot.TargetLinkID != targetLinkID || slot.TargetLinkEpoch != targetLinkEpoch || slot.Lane != lane {
		return fmt.Errorf("%w: finalize seq %d gen %d target %d/%d; installed seq %d gen %d target %d/%d",
			ErrKeyUpdateConflict, seq, newGeneration, targetLinkID, targetLinkEpoch,
			slot.Seq, slot.NewGeneration, slot.TargetLinkID, slot.TargetLinkEpoch)
	}
	if !c.fenceStartedFlag && c.pendingAdmission != nil {
		c.pendingAdmission.tx.Destroy()
		c.pendingAdmission.rx.Destroy()
	}
	c.pendingSlot, c.pendingAdmission = nil, nil
	c.pendingRevisionValue, c.pendingGeneration = [32]byte{}, 0
	return nil
}

// beginKeyUpdateTransaction clears a finished transaction's carrier gate so the
// next transaction can install and fence on this carrier. It is the runtime's
// reset hook: it never touches roots, generations, counters or the session table,
// and it never clears an armed post-FENCE CONFIRM obligation.
func (c *ProtectedControlIO) beginKeyUpdateTransaction() {
	if c == nil {
		return
	}
	c.kuMu.Lock()
	c.fenceStartedFlag = false
	c.cancelPendingFlag = false
	c.kuMu.Unlock()
}

// armKeyUpdateRecoveryReserve grants the bounded reserve of non-key-update
// old-domain control/route frames that an in-flight transaction may still need
// (correlated admission probe, control-plane work). It never exempts business
// E2E frames and never resets a usage counter. Arming is idempotent for the life
// of one transaction, so repeating a follower solicitation cannot refresh the
// finite per-transaction permit budget.
func (c *ProtectedControlIO) armKeyUpdateRecoveryReserve() {
	if c == nil {
		return
	}
	c.kuMu.Lock()
	if !c.kuReserveArmed {
		c.kuReserveArmed = true
		c.kuRecoveryReserve = uint32(keyUpdateControlHandshakeReserve)
	}
	c.kuMu.Unlock()
}

// clearKeyUpdateRecoveryReserve drops the reserve and the prepared-message
// whitelist once the transaction ends.
func (c *ProtectedControlIO) clearKeyUpdateRecoveryReserve() {
	if c == nil {
		return
	}
	c.kuMu.Lock()
	c.kuReserveArmed = false
	c.kuRecoveryReserve = 0
	c.kuPrepared = nil
	c.kuMu.Unlock()
}

// notePreparedControl records one encoded 0x09 body this Link prepared as a
// writer action. It runs before the action is returned, so the hard-boundary
// precheck can accept exactly the messages this Link authored and nothing else.
// The snapshot owns its bytes and the whitelist is bounded with FIFO eviction,
// so it is immutable and cannot grow without bound.
func (c *ProtectedControlIO) notePreparedControl(message KeyUpdateMessage, body []byte) {
	if c == nil || len(body) == 0 {
		return
	}
	entry := kuPreparedControl{
		phase: message.Phase, seq: message.UpdateSeq,
		linkID: message.TargetLinkID, linkEpoch: message.TargetLinkEpoch, lane: message.Lane,
		body: append([]byte(nil), body...),
	}
	c.kuMu.Lock()
	if len(c.kuPrepared) >= maxKeyUpdatePrepared {
		c.kuPrepared = append(c.kuPrepared[:0], c.kuPrepared[1:]...)
	}
	c.kuPrepared = append(c.kuPrepared, entry)
	c.kuMu.Unlock()
}

// keyUpdateControlPermitted reports whether this exact encoded 0x09 body is one
// this Link prepared as a writer action for the locked target tuple. It consults
// only the immutable kuMu-guarded snapshot and never the engine lock, so it runs
// on the writer path without a lock-order inversion against engine.mu. A
// malformed body, an arbitrary 0x09 or a body prepared for another
// tuple/phase/seq is refused before the caller spends a nonce or a permit.
func (c *ProtectedControlIO) keyUpdateControlPermitted(payload []byte) bool {
	if c == nil {
		return false
	}
	decoded, err := DecodeKeyUpdate(payload)
	if err != nil {
		return false
	}
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	for index := range c.kuPrepared {
		prepared := &c.kuPrepared[index]
		if prepared.phase != decoded.Phase || prepared.seq != decoded.UpdateSeq ||
			prepared.linkID != decoded.TargetLinkID || prepared.linkEpoch != decoded.TargetLinkEpoch ||
			prepared.lane != decoded.Lane {
			continue
		}
		if sameControlBytes(prepared.body, payload) {
			return true
		}
	}
	return false
}

// sameControlBytes compares two encoded control bodies for exact equality
// without allocating.
func sameControlBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

// SetVerificationBudget installs an optional shared failed-tag ledger. It is
// consulted in addition to the built-in per-Link failed-auth limit, and a nil
// budget restores the standalone per-Link behaviour. The ledger is never reset
// by a completed key update.
func (c *ProtectedControlIO) SetVerificationBudget(budget VerificationBudget) {
	if c == nil {
		return
	}
	c.kuMu.Lock()
	c.verifyBudget = budget
	c.kuMu.Unlock()
}

// spendKeyUpdateRecoveryReserve consumes one reserved frame, reporting false
// once the reserve is exhausted so the caller fails closed.
func (c *ProtectedControlIO) spendKeyUpdateRecoveryReserve() bool {
	if c == nil {
		return false
	}
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	if c.kuRecoveryReserve == 0 {
		return false
	}
	c.kuRecoveryReserve--
	return true
}

// ReclaimRetiredSessions removes keyless retired tombstones whose hop key can
// never authenticate a replay again, freeing their MaxAdmittedSessions budget.
//
// Eligibility is deliberately conservative and explicit:
//
//   - this carrier holds an exact mutual-DONE proof (a completed update sequence,
//     this carrier's own target tuple and the per-direction root serials taken at
//     completion), and
//   - both directions are still exactly on those committed root serials (so the
//     proof still describes the roots in force), and
//   - a tombstone's recorded per-direction root serials are both strictly older
//     than them.
//
// Freshness is proved by the monotonic root serial, never by the numeric
// generation: a fresh generation is a random uint32 and may be lower than the one
// it replaced, so a numeric comparison would both strand eligible tombstones and
// is not evidence of a newer root. It never removes live admissions, never
// removes all tombstones, never resets the MaxAdmittedSessions budget and never
// rebuilds or re-keys the physical Link. There is no timer or automatic trigger:
// the operator/runtime calls it explicitly once the update is Stable.
func (c *ProtectedControlIO) ReclaimRetiredSessions() int {
	if c == nil {
		return 0
	}
	c.kuMu.Lock()
	valid := c.stableProofValid
	seq := c.stableSeq
	stableGeneration := c.stableGeneration
	targetLinkID, targetLinkEpoch, lane := c.stableTargetLinkID, c.stableTargetLinkEpoch, c.stableLane
	proofTxSerial, proofRxSerial := c.stableTxSerial, c.stableRxSerial
	c.kuMu.Unlock()
	if !valid || seq == 0 || stableGeneration == 0 {
		return 0
	}
	// The proof must be for this carrier's own exact target tuple, so a proof
	// recorded for a different Link can never reclaim this table.
	if targetLinkID != c.linkID || targetLinkEpoch != c.linkEpoch || lane != c.linkLane {
		return 0
	}
	txSlot, rxSlot := c.atomicTxSlot.Load(), c.atomicRxSlot.Load()
	if txSlot == nil || rxSlot == nil {
		return 0
	}
	// Both directions must still be exactly on the committed mutual-DONE roots;
	// the proof names serials, never a numeric generation order.
	if txSlot.serial != proofTxSerial || rxSlot.serial != proofRxSerial {
		return 0
	}
	if txSlot.generation != stableGeneration || rxSlot.generation != stableGeneration {
		return 0
	}
	txSerial, rxSerial := proofTxSerial, proofRxSerial
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	reclaimed := 0
	for sessionID, entry := range c.sessions {
		if !entry.retired {
			continue
		}
		if entry.retiredTxSerial >= txSerial || entry.retiredRxSerial >= rxSerial {
			continue
		}
		delete(c.sessions, sessionID)
		reclaimed++
	}
	return reclaimed
}

// markKeyUpdateStable records this carrier's exact mutual-DONE proof: the
// completed update sequence, the negotiated target tuple and the per-direction
// root serials in force at completion. It records nothing and returns false when
// the carrier is not the transaction's target, when the tuple disagrees, or when
// either direction is not currently on the completed generation, so a stale or
// misrouted completion can never claim a proof, advance a policy baseline or
// enable reclamation. It is internal state only: no wire field, no public
// configuration and no generation ordering assumption.
func (c *ProtectedControlIO) markKeyUpdateStable(generation uint32, seq, targetLinkID, targetLinkEpoch uint64, lane uint8) bool {
	if c == nil || generation == 0 || seq == 0 {
		return false
	}
	if targetLinkID != c.linkID || targetLinkEpoch != c.linkEpoch || lane != c.linkLane {
		return false
	}
	txSlot, rxSlot := c.atomicTxSlot.Load(), c.atomicRxSlot.Load()
	if txSlot == nil || rxSlot == nil || txSlot.generation != generation || rxSlot.generation != generation {
		return false
	}
	c.kuMu.Lock()
	c.stableGeneration = generation
	c.stableProofValid = true
	c.stableSeq = seq
	c.stableTargetLinkID, c.stableTargetLinkEpoch, c.stableLane = targetLinkID, targetLinkEpoch, lane
	c.stableTxSerial, c.stableRxSerial = txSlot.serial, rxSlot.serial
	c.kuMu.Unlock()
	return true
}

// CommitEndToEnd advances the admitted session's RX replay floor to
// (keyEpoch,messageNumber) after the session layer has authenticated the inner
// end-to-end AEAD tag of that frame. The hop seam cannot do this itself: the
// ciphertext is opaque here, and Wire C-WIRE-003 forbids moving E2E replay,
// window or epoch state before the end-to-end tag succeeds (otherwise a hop
// could poison the floor with one forged high MessageNumber).
//
// The commit must not go backwards: a pair at or below the current floor is
// ErrReplay. Until a caller commits, ReadMessage keeps delivering frames that
// pass the read-only precheck, so an uncommitted caller loses only the hop-layer
// early rejection; authoritative window/epoch state stays with the session
// layer, which owns the end-to-end keys.
func (c *ProtectedControlIO) CommitEndToEnd(sessionID [16]byte, keyEpoch uint32, messageNumber uint64) error {
	if c == nil {
		return ErrControlTerminal
	}
	if keyEpoch == 0 || messageNumber == ^uint64(0) {
		return fmt.Errorf("%w: epoch %d counter %d", ErrEndToEndMessage, keyEpoch, messageNumber)
	}
	c.rxMu.Lock()
	defer c.rxMu.Unlock()
	if err := c.withSession(sessionID, func(entry *sessionAdmission) error {
		if !advances(keyEpoch, messageNumber, entry.rxEpoch, entry.rxCounter, entry.rxSeen) {
			return fmt.Errorf("%w: epoch %d counter %d is not above %d/%d", ErrReplay, keyEpoch, messageNumber, entry.rxEpoch, entry.rxCounter)
		}
		entry.rxEpoch, entry.rxCounter, entry.rxSeen = keyEpoch, messageNumber, true
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// ReadControl reads exactly one bounded outer frame, authenticates it and checks
// LINK_CTRL semantics before committing the monotonic RX floor. It is a strict
// wrapper: a frame of any other kind is an error (ErrControlMessage wrapping
// ErrUnexpectedKind) that ends this object instead of being skipped or drained in
// search of a LINK_CTRL frame. Use ReadMessage to carry ROUTE_CTRL/E2E.
//
// Normal EOF remains io.EOF, but ends this object's stream. Returned Payload is
// caller-owned.
func (c *ProtectedControlIO) ReadControl() (ControlMessage, error) {
	if c == nil {
		return ControlMessage{}, ErrControlTerminal
	}
	message, err := c.ReadMessage()
	if message.Kind == 0 {
		// No frame was decoded (terminal object, I/O error or truncation).
		return ControlMessage{}, err
	}
	if message.Kind != wire.FrameKindLinkControl {
		c.terminal.Store(true)
		return ControlMessage{}, fmt.Errorf("%w: frame kind 0x%02x: %w", ErrControlMessage, uint8(message.Kind), ErrUnexpectedKind)
	}
	if err != nil {
		return ControlMessage{}, err
	}
	if len(message.Payload) == 0 {
		c.terminal.Store(true)
		return ControlMessage{}, ErrControlMessage
	}
	typ := message.Payload[0]
	payload := append([]byte(nil), message.Payload[1:]...)
	clear(message.Payload)
	return ControlMessage{Type: typ, Payload: payload}, nil
}

// ReadMessage reads and hop-authenticates exactly one outer frame of any carried
// kind. LINK_CTRL still enforces the complete post-handshake control schema
// (including the CAPABILITY counter-0 floor), ROUTE_CTRL enforces the frozen
// envelope/hop-header redundancy and reserved values, and E2E is delivered as
// opaque session ciphertext for an explicitly admitted SessionID only.
//
// A semantic rejection of a ROUTE_CTRL/E2E frame is not terminal and does not
// move any floor: the caller may keep reading, and only link-layer failures
// (I/O, truncation) or a LINK_CTRL semantic failure end the object. On such a
// rejection the returned ProtectedMessage still carries the frame's Kind so a
// strict wrapper can report the kind before the cause.
func (c *ProtectedControlIO) ReadMessage() (message ProtectedMessage, err error) {
	if c == nil {
		return ProtectedMessage{}, ErrControlTerminal
	}
	c.rxMu.Lock()
	defer func() {
		c.rxMu.Unlock()
		// The read path is the other safe trigger point: a read-driven policy
		// crossing (rejected authentications) is observed here, with rxMu
		// released so the sink can enqueue on the same writer.
		if err == nil {
			c.pollKeyUpdateTrigger()
		}
	}()
	return c.readMessageLocked()
}

func (c *ProtectedControlIO) readMessageLocked() (ProtectedMessage, error) {
	if c.terminal.Load() {
		return ProtectedMessage{}, ErrControlTerminal
	}
	frame, err := wire.ReadFrame(c.stream)
	if err != nil {
		c.terminal.Store(true)
		return ProtectedMessage{}, err
	}
	generation := c.rxGen
	// Once the peer's old-root FENCE switched this RX direction, the next frame
	// must be the new-key CONFIRM. Any other frame kind is refused before it can
	// move a route floor, be forwarded or be delivered, rather than deferred to a
	// later CONFIRM.
	if c.rxExpect != nil && frame.Kind != wire.FrameKindLinkControl {
		c.terminal.Store(true)
		return ProtectedMessage{Kind: frame.Kind}, fmt.Errorf("%w: frame kind 0x%02x before the new-key CONFIRM", ErrKeyUpdateMessage, uint8(frame.Kind))
	}
	var decoded ProtectedMessage
	switch frame.Kind {
	case wire.FrameKindLinkControl:
		decoded, err = c.readLinkControlLocked(frame)
	case wire.FrameKindRouteControl:
		decoded, err = c.readRouteLocked(frame)
	case wire.FrameKindEndToEnd:
		decoded, err = c.readEndToEndLocked(frame)
	default:
		c.terminal.Store(true)
		return ProtectedMessage{Kind: frame.Kind}, fmt.Errorf("%w: kind 0x%02x: %w", ErrControlMessage, uint8(frame.Kind), ErrUnexpectedKind)
	}
	if err == nil {
		decoded.VerifiedLinkGeneration = generation
	}
	return decoded, err
}

// readLinkControlLocked preserves the exact post-handshake LINK_CTRL contract:
// shape and generation are checked before the read-only replay precheck, the
// decoded schema is validated before the floor commits, and any semantic failure
// is terminal for this object.
func (c *ProtectedControlIO) readLinkControlLocked(frame wire.Frame) (ProtectedMessage, error) {
	generation := binary.BigEndian.Uint32(frame.HopHeader[:4])
	counter := binary.BigEndian.Uint64(frame.HopHeader[4:12])
	message := ProtectedMessage{Kind: frame.Kind, HopHeader: frame.HopHeader}
	if len(frame.Envelope) != 0 || generation != c.rxGen || !zeroControlRouting(frame.HopHeader) {
		c.terminal.Store(true)
		return message, ErrControlMessage
	}
	if c.rxSeen && counter <= c.rxLast {
		return message, ErrReplay
	}
	if counter == ^uint64(0) {
		c.terminal.Store(true)
		return message, ErrCounterExhausted
	}
	// Verify does not move the protector's own floor: this wrapper commits
	// c.rxLast only after the decoded control schema is accepted.
	plaintext, err := c.rx.Verify(frame)
	if err != nil {
		c.noteVerifyFailure(KeyDomainControl)
		return message, err
	}
	if len(plaintext) == 0 {
		c.terminal.Store(true)
		return message, ErrControlMessage
	}
	control := ControlMessage{Type: plaintext[0], Payload: plaintext[1:]}
	if err := validateControlMessage(control); err != nil {
		c.terminal.Store(true)
		return message, err
	}
	// The post-FENCE CONFIRM obligation is checked before the replay floor
	// commits: the frame was already AEAD-verified under the new root above.
	if c.rxExpect != nil {
		if err := c.checkConfirmFirstLocked(frame, control, counter); err != nil {
			c.terminal.Store(true)
			return message, err
		}
		c.rxExpect = nil
	}
	c.rxLast, c.rxSeen = counter, true
	message.Payload = plaintext
	return message, nil
}

// readRouteLocked validates the frozen ROUTE_CTRL invariants before any floor
// movement: LinkGeneration domain, redundant hop/envelope PathID/Generation
// copies, zero pad, non-empty bounded bootstrap payload and inner_len equal to
// the hop plaintext length. Failures are frame-local: they neither commit the
// RouteCtrlCounter floor nor end the Link.
func (c *ProtectedControlIO) readRouteLocked(frame wire.Frame) (ProtectedMessage, error) {
	message := ProtectedMessage{Kind: frame.Kind, Envelope: frame.Envelope, HopHeader: frame.HopHeader}
	pathID, pathGeneration, err := validateRouteEnvelope(frame.Envelope)
	if err != nil {
		return message, err
	}
	generation := binary.BigEndian.Uint32(frame.HopHeader[:4])
	counter := binary.BigEndian.Uint64(frame.HopHeader[4:12])
	if generation != c.rxGen {
		return message, fmt.Errorf("%w: generation %d; want LinkGeneration %d", ErrRouteMessage, generation, c.rxGen)
	}
	hopPathID, hopPathGeneration := hopPathOf(frame.HopHeader)
	if hopPathID != pathID || hopPathGeneration != pathGeneration {
		return message, fmt.Errorf("%w: hop path %d/%d does not match envelope %d/%d", ErrRouteMessage, hopPathID, hopPathGeneration, pathID, pathGeneration)
	}
	if frame.HopHeader[hopPadOffset] != 0 || frame.HopHeader[hopPadOffset+1] != 0 {
		return message, fmt.Errorf("%w: non-zero hop pad", ErrRouteMessage)
	}
	if err := checkRoutePayloadLength(frame); err != nil {
		return message, err
	}
	if c.routeSeen && counter <= c.routeLast {
		return message, ErrReplay
	}
	if counter == ^uint64(0) {
		return message, ErrCounterExhausted
	}
	plaintext, err := c.rx.Verify(frame)
	if err != nil {
		c.noteVerifyFailure(KeyDomainRoute)
		return message, err
	}
	c.routeLast, c.routeSeen = counter, true
	message.Payload = plaintext
	return message, nil
}

// readEndToEndLocked delivers one hop-authenticated E2E frame of an explicitly
// admitted session. It never decrypts the session ciphertext and never allocates
// session state from the envelope. The replay floor is only prechecked here (not
// committed): the caller must verify the inner end-to-end tag and then call
// CommitEndToEnd.
func (c *ProtectedControlIO) readEndToEndLocked(frame wire.Frame) (ProtectedMessage, error) {
	message := ProtectedMessage{Kind: frame.Kind, Envelope: frame.Envelope, HopHeader: frame.HopHeader}
	decoded, err := decodeEndToEndEnvelope(frame.Envelope, len(frame.Body)-chacha20poly1305.Overhead)
	if err != nil {
		return message, err
	}
	generation := binary.BigEndian.Uint32(frame.HopHeader[:4])
	counter := binary.BigEndian.Uint64(frame.HopHeader[4:12])
	if generation != decoded.keyEpoch || counter != decoded.messageNumber {
		return message, fmt.Errorf("%w: hop nonce %d/%d does not copy envelope %d/%d", ErrEndToEndMessage, generation, counter, decoded.keyEpoch, decoded.messageNumber)
	}
	hopPathID, hopPathGeneration := hopPathOf(frame.HopHeader)
	if hopPathID != decoded.pathID || hopPathGeneration != decoded.pathGeneration {
		return message, fmt.Errorf("%w: hop path %d/%d does not match envelope %d/%d", ErrEndToEndMessage, hopPathID, hopPathGeneration, decoded.pathID, decoded.pathGeneration)
	}
	if frame.HopHeader[hopPadOffset] != 0 || frame.HopHeader[hopPadOffset+1] != 0 {
		return message, fmt.Errorf("%w: non-zero hop pad", ErrEndToEndMessage)
	}
	// The read fence is held across the hop AEAD so RetireSession cannot destroy
	// this session's RX keys mid-verify.
	var plaintext []byte
	if err := c.withSession(decoded.sessionID, func(entry *sessionAdmission) error {
		if !classCarriesMessageType(entry.class, decoded.messageType) {
			return fmt.Errorf("%w: MessageType 0x%02x is not valid for session class 0x%02x", ErrEndToEndMessage, uint8(decoded.messageType), entry.class)
		}
		if !advances(decoded.keyEpoch, decoded.messageNumber, entry.rxEpoch, entry.rxCounter, entry.rxSeen) {
			return ErrReplay
		}
		verified, err := entry.rx.Verify(frame)
		if err != nil {
			c.noteVerifyFailure(KeyDomainStream)
			return err
		}
		plaintext = verified
		message.Class = entry.class
		return nil
	}); err != nil {
		return message, err
	}
	message.Payload = plaintext
	return message, nil
}

// sealAndWriteLocked seals one frame and writes every byte while the caller holds
// txMu, so concurrent producers cannot interleave frames or reorder nonce
// allocation against the wire. Any seal or transport failure is terminal: the
// nonce was allocated and possibly partially emitted, so it is never retried.
func (c *ProtectedControlIO) sealAndWriteLocked(protector *FrameProtector, frame wire.Frame, plaintext []byte, generation uint32, counter uint64, domain KeyUsageDomain) error {
	sealed, err := protector.Seal(frame, plaintext, generation, counter)
	if err != nil {
		c.terminal.Store(true)
		return err
	}
	// The AEAD Seal above spent the nonce even if the transport write fails, so
	// the domain's usage is counted before the write result is known.
	c.usage.seal(domain, len(plaintext))
	if err := wire.WriteFrame(c.stream, sealed); err != nil {
		c.terminal.Store(true)
		return err
	}
	return nil
}

// withSession runs fn while holding the admission table's read fence, so the
// session's protectors cannot be Destroyed by RetireSession underneath fn.
// Lookups never create an admission. Lock order is txMu/rxMu (already held by
// the caller) then sessionMu.RLock; RetireSession takes sessionMu.Lock and then
// each protector's leaf lock, so no cycle exists.
func (c *ProtectedControlIO) withSession(sessionID [16]byte, fn func(*sessionAdmission) error) error {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	entry, ok := c.sessions[sessionID]
	if !ok {
		return fmt.Errorf("%w: session %x", ErrSessionNotAdmitted, sessionID)
	}
	if entry.retired {
		return fmt.Errorf("%w: session %x", ErrSessionRetired, sessionID)
	}
	return fn(entry)
}

// endToEndEnvelope is the validated, hop-visible subset of an E2E envelope.
type endToEndEnvelope struct {
	sessionID      [16]byte
	messageType    wire.MessageType
	keyEpoch       uint32
	messageNumber  uint64
	pathID         uint64
	pathGeneration uint32
	innerLength    uint32
}

// decodeEndToEndEnvelope validates an E2E envelope against the frozen layout and
// the known hop plaintext length. hopPlaintextLen is the session ciphertext
// length, which the frozen inner AEAD makes exactly inner_len+16. Reserved or
// reversed context values are rejected before any key is used.
func decodeEndToEndEnvelope(envelope []byte, hopPlaintextLen int) (endToEndEnvelope, error) {
	var decoded endToEndEnvelope
	if len(envelope) != wire.EnvelopeSize {
		return decoded, fmt.Errorf("%w: envelope length %d; want %d", ErrEndToEndMessage, len(envelope), wire.EnvelopeSize)
	}
	decoded.messageType = wire.MessageType(envelope[wire.EnvelopeMessageTypeOffset])
	if !isEndToEndMessageType(decoded.messageType) {
		return decoded, fmt.Errorf("%w: MessageType 0x%02x is not an E2E type", ErrEndToEndMessage, uint8(decoded.messageType))
	}
	copy(decoded.sessionID[:], envelope[wire.EnvelopeSessionIDOffset:wire.EnvelopeKeyEpochOffset])
	if decoded.sessionID == ([16]byte{}) {
		return decoded, fmt.Errorf("%w: zero SessionID", ErrEndToEndMessage)
	}
	decoded.keyEpoch = binary.BigEndian.Uint32(envelope[wire.EnvelopeKeyEpochOffset:])
	decoded.messageNumber = binary.BigEndian.Uint64(envelope[wire.EnvelopeMessageNumberOffset:])
	decoded.pathID = binary.BigEndian.Uint64(envelope[wire.EnvelopePathIDOffset:])
	decoded.pathGeneration = binary.BigEndian.Uint32(envelope[wire.EnvelopePathGenerationOffset:])
	decoded.innerLength = binary.BigEndian.Uint32(envelope[wire.EnvelopeInnerLengthOffset:])
	if decoded.keyEpoch == 0 {
		return decoded, fmt.Errorf("%w: KeyEpoch 0 is not a nonce domain", ErrEndToEndMessage)
	}
	if decoded.pathID == 0 || decoded.pathGeneration == 0 {
		return decoded, fmt.Errorf("%w: envelope path %d/%d must be non-zero", ErrEndToEndMessage, decoded.pathID, decoded.pathGeneration)
	}
	if decoded.messageNumber == ^uint64(0) {
		return decoded, errors.Join(ErrEndToEndMessage, ErrCounterExhausted)
	}
	if hopPlaintextLen < e2eTagSize || uint64(decoded.innerLength)+e2eTagSize != uint64(hopPlaintextLen) {
		return decoded, fmt.Errorf("%w: inner_len %d does not match %d ciphertext bytes", ErrEndToEndMessage, decoded.innerLength, hopPlaintextLen)
	}
	return decoded, nil
}

// validateRouteEnvelope returns the envelope's PathID/Generation and enforces the
// frozen ROUTE_CTRL reserved values. SrcNodeID/DstNodeID are intentionally NOT
// checked against the local Link peers, and NetworkID is not checked against the
// local descriptor: this hop seam carries ROUTE_CTRL transparently for relays
// that are not Path endpoints, and it does not own the descriptor/NetworkID
// layout or the installed Path. Endpoint binding (envelope NetworkID/Src/Dst
// versus the authenticated descriptor, resolved peer and selected Path) belongs
// to the Network/Path layer, which must verify it before mutating Path/Session
// state; this seam only rejects the hop-local redundancy and type-bound reserved
// values that must hold on every hop.
func validateRouteEnvelope(envelope []byte) (uint64, uint32, error) {
	if len(envelope) != wire.EnvelopeSize {
		return 0, 0, fmt.Errorf("%w: envelope length %d; want %d", ErrRouteMessage, len(envelope), wire.EnvelopeSize)
	}
	messageType := wire.MessageType(envelope[wire.EnvelopeMessageTypeOffset])
	sessionID := envelope[wire.EnvelopeSessionIDOffset:wire.EnvelopeKeyEpochOffset]
	switch messageType {
	case wire.MessageTypeSessionCtrl, wire.MessageTypeSessionReady:
		if allZero(sessionID) {
			return 0, 0, fmt.Errorf("%w: %s requires a non-zero SessionID", ErrRouteMessage, messageTypeName(messageType))
		}
	case wire.MessageTypePathOpen, wire.MessageTypePathReady, wire.MessageTypePathBroken:
		if !allZero(sessionID) {
			return 0, 0, fmt.Errorf("%w: %s reserves SessionID=0^16", ErrRouteMessage, messageTypeName(messageType))
		}
	default:
		return 0, 0, fmt.Errorf("%w: MessageType 0x%02x is not a ROUTE_CTRL type", ErrRouteMessage, uint8(messageType))
	}
	if epoch := binary.BigEndian.Uint32(envelope[wire.EnvelopeKeyEpochOffset:]); epoch != 0 {
		return 0, 0, fmt.Errorf("%w: ROUTE_CTRL reserves KeyEpoch 0, got %d", ErrRouteMessage, epoch)
	}
	if number := binary.BigEndian.Uint64(envelope[wire.EnvelopeMessageNumberOffset:]); number != 0 {
		return 0, 0, fmt.Errorf("%w: ROUTE_CTRL reserves MessageNumber 0, got %d", ErrRouteMessage, number)
	}
	pathID := binary.BigEndian.Uint64(envelope[wire.EnvelopePathIDOffset:])
	pathGeneration := binary.BigEndian.Uint32(envelope[wire.EnvelopePathGenerationOffset:])
	if pathID == 0 || pathGeneration == 0 {
		return 0, 0, fmt.Errorf("%w: envelope path %d/%d must be non-zero", ErrRouteMessage, pathID, pathGeneration)
	}
	return pathID, pathGeneration, nil
}

// checkRoutePayloadLength verifies, before any floor movement, that a ROUTE_CTRL
// frame's envelope inner_len equals its hop plaintext length and lies inside the
// frozen non-empty 1..8 KiB bootstrap bound. The upper bound matters on ingress
// too: a hop-authenticated 65 KiB bootstrap could be read but never legitimately
// relayed, so accepting it would create unusable state instead of a clear
// ErrRouteMessage.
func checkRoutePayloadLength(frame wire.Frame) error {
	if len(frame.Envelope) != wire.EnvelopeSize {
		return fmt.Errorf("%w: envelope length %d", ErrRouteMessage, len(frame.Envelope))
	}
	plaintextLength := len(frame.Body) - chacha20poly1305.Overhead
	inner := binary.BigEndian.Uint32(frame.Envelope[wire.EnvelopeInnerLengthOffset:])
	if uint64(inner) != uint64(plaintextLength) {
		return fmt.Errorf("%w: inner_len %d does not match %d hop plaintext bytes", ErrRouteMessage, inner, plaintextLength)
	}
	if inner == 0 || inner > maxRoutePayload {
		return fmt.Errorf("%w: inner_len %d outside the 1..%d bootstrap bound", ErrRouteMessage, inner, maxRoutePayload)
	}
	return nil
}

func validateHopRoute(hop HopRoute) error {
	if hop.HopLimit == 0 || hop.HopLimit > maxHopLimit {
		return fmt.Errorf("%w: hop limit %d outside 1..%d", ErrInvalidHopRoute, hop.HopLimit, maxHopLimit)
	}
	if hop.Cursor > maxPathCursor {
		return fmt.Errorf("%w: cursor %d outside 0..%d", ErrInvalidHopRoute, hop.Cursor, maxPathCursor)
	}
	return nil
}

func makeHopHeader(pathID uint64, pathGeneration uint32, hop HopRoute) [wire.HopHeaderSize]byte {
	var header [wire.HopHeaderSize]byte
	binary.BigEndian.PutUint64(header[12:20], pathID)
	binary.BigEndian.PutUint32(header[20:24], pathGeneration)
	header[24] = hop.Cursor
	header[25] = hop.HopLimit
	binary.BigEndian.PutUint32(header[26:30], hop.RemainingBudget)
	return header
}

func hopPathOf(header [wire.HopHeaderSize]byte) (uint64, uint32) {
	return binary.BigEndian.Uint64(header[12:20]), binary.BigEndian.Uint32(header[20:24])
}

// advances reports whether (epoch,counter) is strictly above the floor. seen is
// false before any floor was committed, when any valid pair is above "nothing".
func advances(epoch uint32, counter uint64, floorEpoch uint32, floorCounter uint64, seen bool) bool {
	if !seen {
		return true
	}
	return epoch > floorEpoch || (epoch == floorEpoch && counter > floorCounter)
}

func classCarriesMessageType(class byte, messageType wire.MessageType) bool {
	switch class {
	case SessionClassPacket:
		return messageType == wire.MessageTypeIPPacket || messageType == wire.MessageTypeUDPDatagram
	case SessionClassStream:
		return messageType == wire.MessageTypeStreamData || messageType == wire.MessageTypeControlRPC
	default:
		return false
	}
}

func isEndToEndMessageType(messageType wire.MessageType) bool {
	return validMessageTypeForKind(wire.FrameKindEndToEnd, messageType)
}

func messageTypeName(messageType wire.MessageType) string {
	switch messageType {
	case wire.MessageTypeSessionCtrl:
		return "SESSION_CTRL"
	case wire.MessageTypeSessionReady:
		return "SESSION_READY"
	case wire.MessageTypePathOpen:
		return "PATH_OPEN"
	case wire.MessageTypePathReady:
		return "PATH_READY"
	case wire.MessageTypePathBroken:
		return "PATH_BROKEN"
	default:
		return fmt.Sprintf("MessageType(0x%02x)", uint8(messageType))
	}
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func zeroControlRouting(header [wire.HopHeaderSize]byte) bool {
	for _, value := range header[12:] {
		if value != 0 {
			return false
		}
	}
	return true
}

func validateControlMessage(message ControlMessage) error {
	if len(message.Payload) > maxControlPayload {
		return errors.Join(ErrControlMessage, wire.ErrFrameTooLarge)
	}
	switch message.Type {
	case 1, 2:
		if len(message.Payload) == 16 {
			return nil
		}
	case 3:
		if len(message.Payload) >= 4 && int(binary.BigEndian.Uint16(message.Payload[2:4])) == len(message.Payload)-4 {
			return nil
		}
	case 5:
		if len(message.Payload) == 10 {
			return nil
		}
	case 6, 7, 8:
		// FACT_* interpretation/admission remains outside this transport layer.
		if len(message.Payload) != 0 {
			return nil
		}
	case ControlTypeKeyUpdate:
		// The update phase schema is transport-validated here; the semantic
		// transaction is the key-update engine's responsibility.
		if _, err := DecodeKeyUpdate(message.Payload); err == nil {
			return nil
		}
	}
	return fmt.Errorf("control type 0x%02x has invalid or prohibited payload: %w", message.Type, ErrControlMessage)
}

// NoteProbeSent records that a control probe with this id left at the given time. The
// caller pairs it with NoteProbeAcknowledged when the peer's PONG returns.
func (p *ProtectedControlIO) NoteProbeSent(probe [16]byte, at time.Time) {
	if p == nil {
		return
	}
	p.rtt.noteSent(probe, at)
}

// NoteProbeAcknowledged folds one returned probe into this Link's round-trip estimate. A
// probe this end never sent, or already consumed, is ignored.
func (p *ProtectedControlIO) NoteProbeAcknowledged(probe [16]byte, at time.Time) {
	if p == nil {
		return
	}
	p.rtt.noteAcknowledged(probe, at)
}

// RTT returns the smoothed round-trip time for this Link, or zero before the first probe
// returns. Route cost uses it; a zero value means "not measured yet", not "instant".
func (p *ProtectedControlIO) RTT() time.Duration {
	if p == nil {
		return 0
	}
	return p.rtt.estimate()
}

// RTTVariation returns the smoothed mean deviation of the round-trip samples.
func (p *ProtectedControlIO) RTTVariation() time.Duration {
	if p == nil {
		return 0
	}
	return p.rtt.variation()
}
