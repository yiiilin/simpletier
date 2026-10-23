package link

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/flynn/noise"

	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/wire"
)

// ControlTypeKeyUpdate is the approved in-Link key update opcode. It rides the
// existing encrypted LINK_CTRL frame: the hop header keeps the carrier's current
// LinkGeneration and the carrier's own ControlCounter, so the update never adds
// a plaintext handshake or a new outer-frame field. The payload after the
// ControlType byte is version|phase|lane|flags|target_link_id|target_link_epoch|
// update_seq|old_generation|new_generation plus the phase extension.
const ControlTypeKeyUpdate uint8 = 0x09

// KeyUpdateVersion is the only accepted update payload schema version.
const KeyUpdateVersion uint8 = 1

// CapabilityBitKeyUpdate is capability v2 bit6 link-key-update.v1. It is part of
// RequiredCapabilityMask (0x7f): a peer that does not advertise it fails the
// CAPABILITY handshake before any update can be requested, with no downgrade.
const CapabilityBitKeyUpdate uint64 = 1 << 6

const (
	keyUpdatePublicSize    = 4 + 8 + 8 + 8 + 4 + 4 // version,phase,lane,flags + 3x u64 + 2x u32
	keyUpdatePrologueLabel = "simpletier-v2/link-key-update"
	keyUpdateConfirmLabel  = "simpletier/v2/link-key-update/confirm"
	keyUpdateProofLabel    = "simpletier/v2/link-key-update/proof"
	keyUpdatePSKLabel      = "simpletier/v2/link-key-update/psk-binding"
	// MaxKeyUpdateNoise bounds one update handshake message. It mirrors the
	// frozen initial HANDSHAKE per-message bound; no larger update payload is
	// approved by this seam.
	MaxKeyUpdateNoise = 8192
	// DefaultKuStatePendingTTL is the default operator-visible deadline for a
	// pending update. A deadline never rolls back or discards keys: it only marks
	// the transaction as eligible for an explicit coordinated ABORT.
	DefaultKuStatePendingTTL = 30 * keyUpdateSecond
	keyUpdateSecond          = int64(1)
)

// Public key-update errors. Every rejection matches exactly one sentinel.
var (
	// ErrKeyUpdateConfig reports a missing or inconsistent update configuration.
	ErrKeyUpdateConfig = errors.New("link: invalid key update config")
	// ErrKeyUpdateUnsupported reports a peer that did not negotiate
	// link-key-update.v1 (capability bit6): the update is refused, never
	// downgraded.
	ErrKeyUpdateUnsupported = errors.New("link: peer did not negotiate link-key-update.v1")
	// ErrKeyUpdateState reports a phase that the current transaction state does
	// not allow (second transaction, third generation, rollback after fence).
	ErrKeyUpdateState = errors.New("link: invalid key update state transition")
	// ErrKeyUpdateMessage reports a malformed or wrongly targeted update payload.
	ErrKeyUpdateMessage = errors.New("link: malformed key update message")
	// ErrKeyUpdateConflict reports a same-seq message with different bytes or a
	// tuple/generation that disagrees with the locked target.
	ErrKeyUpdateConflict = errors.New("link: key update transcript conflict")
	// ErrKeyUpdateProof reports a failed new-direction confirmation MAC.
	ErrKeyUpdateProof = errors.New("link: key update proof rejected")
	// ErrKeyUpdateReplay reports a stale seq/step or a resurrected aborted seq.
	ErrKeyUpdateReplay = errors.New("link: replayed or retired key update")
	// ErrKeyUpdateAbort reports an update rejected because its cancel gate won
	// the CAS, or an ABORT_ACK for an already fenced transaction.
	ErrKeyUpdateAbort = errors.New("link: key update cancelled")
	// ErrKeyUpdateTarget reports a target carrier/lookup failure.
	ErrKeyUpdateTarget = errors.New("link: key update target unavailable")
	// ErrKuStatePending reports that the bounded verified-frame holder is full.
	ErrKuStatePending = errors.New("link: pending verified frames exceeded")
)

// KeyUpdatePhase is the update control phase. Numeric values are frozen by the
// approved contract (REQUEST=1 .. ABORT_REJECT=13).
type KeyUpdatePhase uint8

const (
	KeyUpdateRequest     KeyUpdatePhase = 1
	KeyUpdateXX1         KeyUpdatePhase = 2
	KeyUpdateXX2         KeyUpdatePhase = 3
	KeyUpdateXX3         KeyUpdatePhase = 4
	KeyUpdateReady       KeyUpdatePhase = 5
	KeyUpdateCommit      KeyUpdatePhase = 6
	KeyUpdateArmed       KeyUpdatePhase = 7
	KeyUpdateFence       KeyUpdatePhase = 8
	KeyUpdateConfirm     KeyUpdatePhase = 9
	KeyUpdateDone        KeyUpdatePhase = 10
	KeyUpdateAbort       KeyUpdatePhase = 11
	KeyUpdateAbortAck    KeyUpdatePhase = 12
	KeyUpdateAbortReject KeyUpdatePhase = 13
)

func (p KeyUpdatePhase) String() string {
	switch p {
	case KeyUpdateRequest:
		return "REQUEST"
	case KeyUpdateXX1:
		return "XX1"
	case KeyUpdateXX2:
		return "XX2"
	case KeyUpdateXX3:
		return "XX3"
	case KeyUpdateReady:
		return "READY"
	case KeyUpdateCommit:
		return "COMMIT"
	case KeyUpdateArmed:
		return "ARMED"
	case KeyUpdateFence:
		return "FENCE"
	case KeyUpdateConfirm:
		return "CONFIRM"
	case KeyUpdateDone:
		return "DONE"
	case KeyUpdateAbort:
		return "ABORT"
	case KeyUpdateAbortAck:
		return "ABORT_ACK"
	case KeyUpdateAbortReject:
		return "ABORT_REJECT"
	default:
		return fmt.Sprintf("PHASE(%d)", uint8(p))
	}
}

// KeyUpdateMessage is one decoded ControlType 0x09 payload body (without the
// leading ControlType byte).
type KeyUpdateMessage struct {
	Version          uint8
	Phase            KeyUpdatePhase
	Lane             uint8
	Flags            uint8
	TargetLinkID     uint64
	TargetLinkEpoch  uint64
	UpdateSeq        uint64
	OldGeneration    uint32
	NewGeneration    uint32
	PreviousRevision [32]byte
	NewRevision      [32]byte
	Proof            [32]byte
	Noise            []byte
	DirectionMask    uint8
}

// EncodeKeyUpdate returns the update payload body WITHOUT the leading
// ControlType byte, for use as WriteControl(ControlMessage{Type:
// ControlTypeKeyUpdate, Payload: body}). Keeping the opcode out of the body
// prevents an accidental 0x09|0x09 frame.
func EncodeKeyUpdate(message KeyUpdateMessage) ([]byte, error) {
	if message.Version != KeyUpdateVersion || message.Flags != 0 {
		return nil, fmt.Errorf("%w: version %d flags 0x%02x", ErrKeyUpdateMessage, message.Version, message.Flags)
	}
	if message.TargetLinkID == 0 || message.TargetLinkEpoch == 0 {
		return nil, fmt.Errorf("%w: target %d/%d", ErrKeyUpdateMessage, message.TargetLinkID, message.TargetLinkEpoch)
	}
	if message.UpdateSeq == 0 {
		return nil, fmt.Errorf("%w: zero update seq", ErrKeyUpdateMessage)
	}
	extra, err := keyUpdateExtra(message)
	if err != nil {
		return nil, err
	}
	body := make([]byte, keyUpdatePublicSize+len(extra))
	body[0] = message.Version
	body[1] = byte(message.Phase)
	body[2] = message.Lane
	body[3] = message.Flags
	binary.BigEndian.PutUint64(body[4:], message.TargetLinkID)
	binary.BigEndian.PutUint64(body[12:], message.TargetLinkEpoch)
	binary.BigEndian.PutUint64(body[20:], message.UpdateSeq)
	binary.BigEndian.PutUint32(body[28:], message.OldGeneration)
	binary.BigEndian.PutUint32(body[32:], message.NewGeneration)
	copy(body[keyUpdatePublicSize:], extra)
	return body, nil
}

func keyUpdateExtra(message KeyUpdateMessage) ([]byte, error) {
	switch message.Phase {
	case KeyUpdateRequest:
		return nil, nil
	case KeyUpdateXX1, KeyUpdateXX2, KeyUpdateXX3:
		if len(message.Noise) == 0 || len(message.Noise) > MaxKeyUpdateNoise {
			return nil, fmt.Errorf("%w: noise length %d", ErrKeyUpdateMessage, len(message.Noise))
		}
		extra := make([]byte, 0, 34+len(message.Noise))
		extra = append(extra, message.PreviousRevision[:]...)
		extra = binary.BigEndian.AppendUint16(extra, uint16(len(message.Noise)))
		return append(extra, message.Noise...), nil
	case KeyUpdateReady, KeyUpdateCommit, KeyUpdateArmed, KeyUpdateConfirm:
		extra := make([]byte, 0, 64)
		extra = append(extra, message.NewRevision[:]...)
		return append(extra, message.Proof[:]...), nil
	case KeyUpdateFence, KeyUpdateAbort, KeyUpdateAbortAck, KeyUpdateAbortReject:
		return append([]byte(nil), message.NewRevision[:]...), nil
	case KeyUpdateDone:
		extra := make([]byte, 33)
		copy(extra, message.NewRevision[:])
		extra[32] = message.DirectionMask
		return extra, nil
	default:
		return nil, fmt.Errorf("%w: unknown phase %d", ErrKeyUpdateMessage, uint8(message.Phase))
	}
}

// DecodeKeyUpdate parses a ControlType 0x09 body (without the opcode byte).
func DecodeKeyUpdate(body []byte) (KeyUpdateMessage, error) {
	var message KeyUpdateMessage
	if len(body) < keyUpdatePublicSize {
		return message, fmt.Errorf("%w: length %d", ErrKeyUpdateMessage, len(body))
	}
	message.Version = body[0]
	message.Phase = KeyUpdatePhase(body[1])
	message.Lane = body[2]
	message.Flags = body[3]
	message.TargetLinkID = binary.BigEndian.Uint64(body[4:])
	message.TargetLinkEpoch = binary.BigEndian.Uint64(body[12:])
	message.UpdateSeq = binary.BigEndian.Uint64(body[20:])
	message.OldGeneration = binary.BigEndian.Uint32(body[28:])
	message.NewGeneration = binary.BigEndian.Uint32(body[32:])
	if message.Version != KeyUpdateVersion || message.Flags != 0 || message.UpdateSeq == 0 || message.TargetLinkID == 0 || message.TargetLinkEpoch == 0 {
		return KeyUpdateMessage{}, fmt.Errorf("%w: version %d flags 0x%02x target %d/%d seq %d",
			ErrKeyUpdateMessage, message.Version, message.Flags, message.TargetLinkID, message.TargetLinkEpoch, message.UpdateSeq)
	}
	rest := body[keyUpdatePublicSize:]
	switch message.Phase {
	case KeyUpdateRequest:
		if len(rest) != 0 {
			return KeyUpdateMessage{}, fmt.Errorf("%w: REQUEST carries %d trailing bytes", ErrKeyUpdateMessage, len(rest))
		}
	case KeyUpdateXX1, KeyUpdateXX2, KeyUpdateXX3:
		if len(rest) < 34 {
			return KeyUpdateMessage{}, fmt.Errorf("%w: %s truncated", ErrKeyUpdateMessage, message.Phase)
		}
		copy(message.PreviousRevision[:], rest[:32])
		noiseLength := int(binary.BigEndian.Uint16(rest[32:34]))
		if noiseLength == 0 || noiseLength > MaxKeyUpdateNoise || len(rest) != 34+noiseLength {
			return KeyUpdateMessage{}, fmt.Errorf("%w: %s noise length %d in %d bytes", ErrKeyUpdateMessage, message.Phase, noiseLength, len(rest))
		}
		message.Noise = append([]byte(nil), rest[34:]...)
	case KeyUpdateReady, KeyUpdateCommit, KeyUpdateArmed, KeyUpdateConfirm:
		if len(rest) != 64 {
			return KeyUpdateMessage{}, fmt.Errorf("%w: %s length %d", ErrKeyUpdateMessage, message.Phase, len(rest))
		}
		copy(message.NewRevision[:], rest[:32])
		copy(message.Proof[:], rest[32:64])
	case KeyUpdateFence, KeyUpdateAbort, KeyUpdateAbortAck, KeyUpdateAbortReject:
		if len(rest) != 32 {
			return KeyUpdateMessage{}, fmt.Errorf("%w: %s length %d", ErrKeyUpdateMessage, message.Phase, len(rest))
		}
		copy(message.NewRevision[:], rest[:32])
	case KeyUpdateDone:
		if len(rest) != 33 {
			return KeyUpdateMessage{}, fmt.Errorf("%w: DONE length %d", ErrKeyUpdateMessage, len(rest))
		}
		copy(message.NewRevision[:], rest[:32])
		message.DirectionMask = rest[32]
		if message.DirectionMask != 0x03 {
			return KeyUpdateMessage{}, fmt.Errorf("%w: DONE direction mask 0x%02x", ErrKeyUpdateMessage, message.DirectionMask)
		}
	default:
		return KeyUpdateMessage{}, fmt.Errorf("%w: unknown phase %d", ErrKeyUpdateMessage, uint8(message.Phase))
	}
	return message, nil
}

// KeyUpdateSlot is the installed pending root pair for one target Link. It is
// explicit so a DATA update can install the negotiated slot on the target
// carrier before ARMED/FENCE; no carrier may emit a new-key CONFIRM without an
// installed slot.
type KeyUpdateSlot struct {
	Seq             uint64
	TargetLinkID    uint64
	TargetLinkEpoch uint64
	Lane            uint8
	OldGeneration   uint32
	NewGeneration   uint32
	Descriptor      []byte
	TxRoot          [32]byte
	RxRoot          [32]byte
	TxDirection     byte
	RxDirection     byte
	// Revision is the transcript revision this slot was negotiated at. It is
	// stored on the slot so a carrier that only holds an installed slot does not
	// depend on a separately published revision value.
	Revision [32]byte
	// Trusted peer-CONFIRM verification material. It is derived from this side's
	// own completed Noise XX split (never from a peer FENCE) and it lets a
	// carrier that only holds an installed slot verify the peer's new-key CONFIRM
	// with the same canonical construction the negotiating engine uses.
	RxConfirmKey         [32]byte
	PeerConfirmDirection byte
	CoordinatorNode      [16]byte
	FollowerNode         [16]byte
	CoordinatorStatic    [32]byte
	FollowerStatic       [32]byte
}

// sameKeyUpdateSlot reports whether two slots describe the identical trusted
// transaction: tuple, generations, revision, descriptor and every derived key
// and role binding. A re-install with the same seq but different material is a
// conflict, never a silent overwrite.
func sameKeyUpdateSlot(a, b *KeyUpdateSlot) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Seq == b.Seq && a.TargetLinkID == b.TargetLinkID && a.TargetLinkEpoch == b.TargetLinkEpoch &&
		a.Lane == b.Lane && a.OldGeneration == b.OldGeneration && a.NewGeneration == b.NewGeneration &&
		a.TxRoot == b.TxRoot && a.RxRoot == b.RxRoot && a.TxDirection == b.TxDirection && a.RxDirection == b.RxDirection &&
		a.Revision == b.Revision && a.RxConfirmKey == b.RxConfirmKey && a.PeerConfirmDirection == b.PeerConfirmDirection &&
		a.CoordinatorNode == b.CoordinatorNode && a.FollowerNode == b.FollowerNode &&
		a.CoordinatorStatic == b.CoordinatorStatic && a.FollowerStatic == b.FollowerStatic &&
		string(a.Descriptor) == string(b.Descriptor)
}

// KeyUpdateCarrier is the unique writer of a target stream. ProtectedControlIO
// implements it; a caller executes every action through
// action.Carrier.ApplyKeyUpdateAction(action).
type KeyUpdateCarrier interface {
	ApplyKeyUpdateAction(action KeyUpdateAction) error
}

// KeyUpdateTargetLookup resolves the DATA target carrier for a tuple. It must
// return the target Link's own ProtectedControlIO (or an equivalent single
// writer), never a fresh stream.
type KeyUpdateTargetLookup func(targetLinkID, targetLinkEpoch uint64, lane uint8) (KeyUpdateCarrier, error)

// KeyUpdateConfig installs the local identity, the pinned peer and the target
// tuple. Identity/PSK/Descriptor must equal the established Link's; the seam
// refuses an update that would rebind identity or context.
type KeyUpdateConfig struct {
	Identity        security.Identity
	PeerStatic      [32]byte
	PSK             [32]byte
	Descriptor      []byte
	TargetLinkID    uint64
	TargetLinkEpoch uint64
	LaneID          uint8
	// NegotiationCarrier carries REQUEST/XX/READY/COMMIT/ARMED. nil means this
	// object (CONTROL self-update).
	NegotiationCarrier KeyUpdateCarrier
	// TargetLookup resolves the target carrier for FENCE/CONFIRM/DONE when the
	// target is a DATA stream. nil keeps FENCE/CONFIRM on the negotiation carrier.
	TargetLookup KeyUpdateTargetLookup
	// PeerAdvertisedKeyUpdate records the authenticated capability bit6 of the
	// established Link. false hard-rejects every update.
	PeerAdvertisedKeyUpdate bool
	// Policy installs the built-in operational key-use policy on this Link.
	// Every zero field keeps its built-in default, so the zero policy resolves
	// to DefaultKeyUpdatePolicy(). Policy accounting is always active (it is
	// installed at Link construction); Policy only overrides the limits.
	Policy KeyUpdatePolicy
}

// KeyUpdateActionKind enumerates the writer commands returned by the read side.
// ReadMessage/HandleUpdate never perform I/O; the runtime's single writer
// executes these in order.
type KeyUpdateActionKind uint8

const (
	// ActionSendUpdate asks the writer to WriteControl the encoded 0x09 body.
	ActionSendUpdate KeyUpdateActionKind = iota + 1
	// ActionInstallPendingTarget installs the pending slot on a target carrier.
	ActionInstallPendingTarget
	// ActionFenceTarget writes old-key FENCE, switches TX and writes new-key
	// CONFIRM on the carrier, atomically.
	ActionFenceTarget
	// ActionAbortTarget writes an ABORT-phase control message.
	ActionAbortTarget
)

// KeyUpdateTargetRef pins an action to the exact carrier instance and its own
// Link tuple at resolution time. It is deliberately explicit rather than
// inferred from the Owner pointer: a delayed action that is executed against a
// reconnected peer's new Link (identical LinkID/Epoch/Lane but a different
// instance) is rejected before any state changes.
type KeyUpdateTargetRef struct {
	Instance  *ProtectedControlIO
	LinkID    uint64
	LinkEpoch uint64
	Lane      uint8
}

// targetRefOf builds the binding for a resolved carrier. A carrier that is not a
// ProtectedControlIO leaves the instance nil; the tuple is then unavailable and
// the caller owns whatever identity check it needs.
func targetRefOf(carrier KeyUpdateCarrier) KeyUpdateTargetRef {
	if io, ok := carrier.(*ProtectedControlIO); ok {
		return KeyUpdateTargetRef{Instance: io, LinkID: io.linkID, LinkEpoch: io.linkEpoch, Lane: io.linkLane}
	}
	return KeyUpdateTargetRef{}
}

// KeyUpdateAction is one serialized writer command.
type KeyUpdateAction struct {
	Kind          KeyUpdateActionKind
	Carrier       KeyUpdateCarrier
	Phase         KeyUpdatePhase
	Seq           uint64
	ControlType   uint8
	Payload       []byte
	Slot          *KeyUpdateSlot
	NewRevision   [32]byte
	NewGeneration uint32
	Proof         [32]byte
	// Owner is the object whose engine owns the transaction; the runtime's
	// writer completes the action on it after the physical write.
	Owner *ProtectedControlIO
	// Target is the exact carrier instance/tuple this action was resolved for.
	Target KeyUpdateTargetRef
}

// KeyUpdateUsage counts update-transaction events for the life of this engine.
// The built-in operational key-use budget and its trigger are separate
// accounting: see KeyUpdatePolicyStatus and KeyUpdateUsageSnapshot, which are
// measured against the last stable generation rather than against this engine.
type KeyUpdateUsage struct {
	Requests           uint64
	XxCompleted        uint64
	ProofsAccepted     uint64
	ProofsRejected     uint64
	FencesSent         uint64
	ConfirmsSent       uint64
	Aborts             uint64
	AbortAcks          uint64
	AbortRejects       uint64
	GenerationSwitches uint64
}

// KeyUpdateState is the coarse lifecycle state.
type KeyUpdateState string

const (
	KuStateIdle    KeyUpdateState = "Idle"
	KuStatePending KeyUpdateState = "Pending"
	KuStateArmed   KeyUpdateState = "Armed"
	KuStateFenced  KeyUpdateState = "Fenced"
	KuStateStable  KeyUpdateState = "Stable"
	KuStateAborted KeyUpdateState = "Aborted"
)

// KeyUpdateStatus is a snapshot for the runtime and for tests.
type KeyUpdateStatus struct {
	Configured       bool
	Coordinator      bool
	State            KeyUpdateState
	Phase            KeyUpdatePhase
	Seq              uint64
	OldGeneration    uint32
	NewGeneration    uint32
	FenceStarted     bool
	LocalFenceSent   bool
	LocalConfirmSent bool
	PeerFenceSeen    bool
	PeerConfirmSeen  bool
	RxSwitched       bool
	DirectionMask    uint8
	Aborted          bool
	AbortedSeq       uint64
	Usage            KeyUpdateUsage
	// Policy is the built-in operational key-use accounting and trigger state,
	// always present because the default policy is installed at construction.
	Policy KeyUpdatePolicyStatus
}

// keyUpdateEngine holds one Link's at-most-one pending update transaction.
type keyUpdateEngine struct {
	mu          sync.Mutex
	io          *ProtectedControlIO
	cfg         KeyUpdateConfig
	coordinator bool

	active        bool
	state         KeyUpdateState
	phase         KeyUpdatePhase
	seq           uint64
	oldGeneration uint32
	newGeneration uint32
	slot          KeyUpdateSlot
	hs            *noise.HandshakeState
	// requestPending records a follower solicitation that was prepared and not
	// yet superseded by the coordinator's XX1. It bounds a follower to one
	// outstanding REQUEST per transaction so the finite permit budget cannot be
	// refreshed by repeating it.
	requestPending bool
	// target is the pinned target carrier for this transaction. It is resolved
	// once (first use) and never re-resolved, so a lookup cannot move the
	// transaction onto a reconnected peer's instance.
	target KeyUpdateCarrier
	// noiseStaticPrivate is the owned private-key slice handed to
	// noise.NewHandshakeState, which retains it by reference. It must stay valid
	// across every XX Read/WriteMessage step (XX2/XX3 need the static DH) and is
	// cleared once the split is derived or the transaction becomes terminal.
	noiseStaticPrivate               []byte
	newRevision                      [32]byte
	prevRevision                     [32]byte
	confirmI2R, confirmR2I           [32]byte
	xx1, xx2, xx3                    []byte
	ready, commit, armed             []byte
	localFenceSent, localConfirmSent bool
	peerFenceSeen, peerConfirmSeen   bool
	// peerDoneSeen records a validated peer DONE independently of the local
	// writer's completion events. A peer DONE can arrive before this side's
	// FENCE/CONFIRM write completes, so dropping it would leave the transaction
	// Fenced forever.
	peerDoneSeen bool
	// doneQueued/doneSent separate "a DONE action was handed to the writer" from
	// "the physical DONE write succeeded", so DONE is emitted at most once and
	// never counted as written on a failed or partial write.
	doneQueued        bool
	doneSent          bool
	rxSwitched        bool
	committed         bool
	stable            bool
	cancelPending     bool
	aborted           bool
	abortedSeq        uint64
	tombstoneSeq      uint64
	tombstoneRevision [32]byte
	// completedSeq/completedRevision name the last transaction this engine
	// finished (Stable, or retired because the peer had already moved to a newer
	// generation). They exist only to tolerate that transaction's late DONE
	// idempotently; no other old sequence is ever accepted.
	completedSeq      uint64
	completedRevision [32]byte
	usage             KeyUpdateUsage
	deadline          int64
}

func (e *keyUpdateEngine) statusLocked() KeyUpdateStatus {
	mask := uint8(0)
	if e.localConfirmSent {
		mask |= 0x01
	}
	if e.peerConfirmSeen {
		mask |= 0x02
	}
	return KeyUpdateStatus{
		Configured: true, Coordinator: e.coordinator, State: e.state, Phase: e.phase,
		Seq: e.seq, OldGeneration: e.oldGeneration, NewGeneration: e.newGeneration,
		FenceStarted: e.localFenceSent, LocalFenceSent: e.localFenceSent, LocalConfirmSent: e.localConfirmSent,
		PeerFenceSeen: e.peerFenceSeen, PeerConfirmSeen: e.peerConfirmSeen, RxSwitched: e.rxSwitched,
		DirectionMask: mask, Aborted: e.aborted, AbortedSeq: e.abortedSeq, Usage: e.usage,
	}
}

// ConfigureKeyUpdate installs the update configuration on an established Link.
// It validates that the pinned identity/context match the Link's own metadata
// and that the handshake actually negotiated capability bit6.
func (c *ProtectedControlIO) ConfigureKeyUpdate(cfg KeyUpdateConfig) error {
	if c == nil {
		return ErrControlTerminal
	}
	if !cfg.PeerAdvertisedKeyUpdate || c.capabilityMask&CapabilityBitKeyUpdate == 0 {
		return ErrKeyUpdateUnsupported
	}
	if cfg.Identity.PrivateKey == nil || cfg.PeerStatic == ([32]byte{}) || cfg.PSK == ([32]byte{}) || len(cfg.Descriptor) == 0 {
		return fmt.Errorf("%w: missing identity/peer/psk/descriptor", ErrKeyUpdateConfig)
	}
	if cfg.TargetLinkID == 0 || cfg.TargetLinkEpoch == 0 || cfg.LaneID > 2 {
		return fmt.Errorf("%w: target %d/%d lane %d", ErrKeyUpdateConfig, cfg.TargetLinkID, cfg.TargetLinkEpoch, cfg.LaneID)
	}
	if cfg.Identity.NodeID != c.localNodeID {
		return fmt.Errorf("%w: local identity does not match the established Link", ErrKeyUpdateConfig)
	}
	if cfg.PeerStatic != c.peerStatic {
		return fmt.Errorf("%w: peer static key does not match the established Link", ErrKeyUpdateConfig)
	}
	if string(cfg.Descriptor) != string(c.descriptor) {
		return fmt.Errorf("%w: descriptor does not match the established Link", ErrKeyUpdateConfig)
	}
	owned := cfg
	owned.Descriptor = append([]byte(nil), cfg.Descriptor...)
	owned.PeerStatic = cfg.PeerStatic
	engine := &keyUpdateEngine{io: c, cfg: owned, coordinator: c.initiator, state: KuStateIdle}
	if c.usage != nil {
		c.usage.setPolicy(cfg.Policy)
	}
	// Installing the engine re-arms the automatic trigger, so a policy crossing
	// observed before this call can still start one update now.
	c.rearmKeyUpdateTrigger()
	c.kuMu.Lock()
	c.ku = engine
	c.kuMu.Unlock()
	return nil
}

// RequestKeyUpdate starts (coordinator) or requests (follower) one update. It is
// the explicit entry point, and the built-in usage policy also calls it through
// StartKeyUpdateIfNeeded/SetKeyUpdateActionSink. A finished transaction is reset
// with beginLocked so the same long-lived Link can run another in-place update.
func (c *ProtectedControlIO) RequestKeyUpdate() ([]KeyUpdateAction, error) {
	if c == nil {
		return nil, ErrControlTerminal
	}
	engine, err := c.keyUpdateEngine()
	if err != nil {
		return nil, err
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.active {
		// Concurrent requests coalesce onto the in-flight transaction rather than
		// starting a second one.
		return nil, fmt.Errorf("%w: transaction %d already pending", ErrKeyUpdateState, engine.seq)
	}
	if engine.stable || engine.aborted {
		// The previous transaction is finished: reset only its scratch state so
		// this long-lived Link can run another update.
		engine.beginLocked()
	}
	engine.usage.Requests++
	if engine.coordinator {
		return engine.startLocked()
	}
	// Follower: ask the coordinator. REQUEST never authorizes a switch and
	// carries new_generation=0. At most one solicitation is outstanding at a
	// time: a second RequestKeyUpdate before the coordinator's XX1 supersedes it
	// coalesces instead of emitting another REQUEST, so the finite per-transaction
	// permit budget can never be refreshed by repeating it. The bounded recovery
	// reserve is armed before the physical REQUEST so a Link already at its hard
	// boundary can still send this solicitation.
	if engine.requestPending {
		return nil, fmt.Errorf("%w: follower solicitation already pending", ErrKeyUpdateState)
	}
	c.armKeyUpdateRecoveryReserve()
	request := KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateRequest, Lane: engine.cfg.LaneID,
		TargetLinkID: engine.cfg.TargetLinkID, TargetLinkEpoch: engine.cfg.TargetLinkEpoch,
		UpdateSeq: c.nextUpdateSeqHint(),
	}
	action, err := engine.sendAction(request)
	if err != nil {
		return nil, err
	}
	engine.requestPending = true
	return []KeyUpdateAction{action}, nil
}

// setCancelPending arms the shared cancel gate. applyFenceLocked observes it
// under kuMu before any mutation, so a FENCE that has not started is paused
// rather than written; a FENCE that already started is unaffected.
func (c *ProtectedControlIO) setCancelPending() {
	c.kuMu.Lock()
	c.cancelPendingFlag = true
	c.kuMu.Unlock()
}

// clearCancelPending releases the cancel gate (used when the peer rejects the
// abort because it already fenced, so this side continues forward).
func (c *ProtectedControlIO) clearCancelPending() {
	c.kuMu.Lock()
	c.cancelPendingFlag = false
	c.kuMu.Unlock()
}

// CancelKeyUpdate is the explicit local cancel gate. It pauses a queued FENCE
// before it mutates or writes anything and marks the transaction cancel-pending
// so a peer ABORT_ACK/ABORT_REJECT is accepted. It never rolls back a FENCE that
// already started and returns no writer actions: RequestAbort additionally asks
// the peer to abandon the transaction.
func (c *ProtectedControlIO) CancelKeyUpdate() ([]KeyUpdateAction, error) {
	if c == nil {
		return nil, ErrControlTerminal
	}
	engine, err := c.keyUpdateEngine()
	if err != nil {
		return nil, err
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if !engine.active || engine.stable || engine.aborted {
		return nil, fmt.Errorf("%w: %s", ErrKeyUpdateState, engine.state)
	}
	gate := engine.gateCarrier()
	if engine.localFenceSent || gate.fenceStarted() {
		// The FENCE outcome is already observable: it can never be cancelled.
		return nil, ErrKeyUpdateAbort
	}
	gate.setCancelPending()
	engine.cancelPending = true
	return nil, nil
}

// RequestAbort is the operator-triggered coordinated abort. It takes the local
// cancel gate first (pausing any not-yet-applied FENCE) and returns the ABORT
// control message the single writer must send. The transaction becomes terminal
// only when the peer's ABORT_ACK arrives, which is an irreversible promise that
// no FENCE will follow. A peer that already fenced answers ABORT_REJECT; the
// gate is then released and the transaction continues forward with no rollback.
func (c *ProtectedControlIO) RequestAbort() ([]KeyUpdateAction, error) {
	if c == nil {
		return nil, ErrControlTerminal
	}
	engine, err := c.keyUpdateEngine()
	if err != nil {
		return nil, err
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if !engine.active || engine.stable || engine.aborted {
		return nil, fmt.Errorf("%w: %s", ErrKeyUpdateState, engine.state)
	}
	gate := engine.gateCarrier()
	if engine.localFenceSent || gate.fenceStarted() {
		return nil, ErrKeyUpdateAbort
	}
	gate.setCancelPending()
	engine.cancelPending = true
	engine.usage.Aborts++
	action, err := engine.sendAction(KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateAbort, Lane: engine.cfg.LaneID,
		TargetLinkID: engine.cfg.TargetLinkID, TargetLinkEpoch: engine.cfg.TargetLinkEpoch,
		UpdateSeq: engine.seq, OldGeneration: engine.oldGeneration, NewGeneration: engine.newGeneration,
		NewRevision: engine.newRevision,
	})
	if err != nil {
		return nil, err
	}
	return []KeyUpdateAction{action}, nil
}

// KeyUpdateStatus returns a snapshot of the transaction, usage counters and the
// built-in key-use policy accounting.
func (c *ProtectedControlIO) KeyUpdateStatus() KeyUpdateStatus {
	if c == nil {
		return KeyUpdateStatus{}
	}
	engine, err := c.keyUpdateEngine()
	if err != nil {
		// No engine configured: policy accounting is still live because the
		// defaults are installed at construction, but no transaction exists.
		return KeyUpdateStatus{Policy: c.usage.status(false)}
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	status := engine.statusLocked()
	// engine.active is read under engine.mu here, so it must be passed in
	// rather than re-derived (re-locking the same mutex would deadlock).
	status.Policy = c.usage.status(engine.active)
	return status
}

func (c *ProtectedControlIO) keyUpdateEngine() (*keyUpdateEngine, error) {
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	if c.ku == nil {
		return nil, fmt.Errorf("%w: ConfigureKeyUpdate was not called", ErrKeyUpdateConfig)
	}
	return c.ku, nil
}

func (c *ProtectedControlIO) nextUpdateSeqHint() uint64 {
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	if c.ku == nil {
		return 1
	}
	if c.ku.tombstoneSeq > 0 {
		return c.ku.tombstoneSeq + 1
	}
	if c.ku.seq > 0 {
		return c.ku.seq + 1
	}
	return 1
}

// startLocked begins a coordinator transaction: allocate the official seq and a
// fresh non-zero CSPRNG generation, bind the prologue and produce XX1.
func (e *keyUpdateEngine) startLocked() ([]KeyUpdateAction, error) {
	seq := e.nextSeqLocked()
	if seq == ^uint64(0) {
		return nil, fmt.Errorf("%w: update seq exhausted", ErrKeyUpdateState)
	}
	// Pin the target carrier for the whole transaction before anything is
	// derived, so a lookup that would resolve a reconnected peer later cannot
	// split the transaction across two instances.
	target := e.targetCarrier()
	generation, err := e.freshGeneration()
	if err != nil {
		return nil, err
	}
	e.seq = seq
	// The old generation is the TARGET direction's generation, which may differ
	// from the negotiation carrier's own generation (CarrierGen != TargetGen).
	e.oldGeneration = carrierTxGeneration(target, e.io)
	e.newGeneration = generation
	e.slot = KeyUpdateSlot{
		Seq: seq, TargetLinkID: e.cfg.TargetLinkID, TargetLinkEpoch: e.cfg.TargetLinkEpoch,
		Lane: e.cfg.LaneID, OldGeneration: e.oldGeneration, NewGeneration: generation,
		Descriptor: append([]byte(nil), e.cfg.Descriptor...),
	}
	e.prevRevision = sha256.Sum256(e.io.channelBinding)
	if err := e.noiseInit(true); err != nil {
		return nil, err
	}
	payload, _, _, err := e.hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("key update XX1: %w", err)
	}
	e.xx1 = append([]byte(nil), payload...)
	e.active, e.state, e.phase = true, KuStatePending, KeyUpdateXX1
	e.armRecoveryReserveLocked()
	action, err := e.sendAction(KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateXX1, Lane: e.cfg.LaneID,
		TargetLinkID: e.cfg.TargetLinkID, TargetLinkEpoch: e.cfg.TargetLinkEpoch,
		UpdateSeq: seq, OldGeneration: e.oldGeneration, NewGeneration: generation,
		PreviousRevision: e.prevRevision, Noise: e.xx1,
	})
	if err != nil {
		return nil, err
	}
	return []KeyUpdateAction{action}, nil
}

// beginLocked clears the scratch state of a FINISHED transaction so this Link
// can run another in-place update. It preserves the sequence high-water mark, the
// completed generation, usage counters, abort/retire tombstones and, on the
// carriers, every root, generation, counter and session leaf key. It also clears
// the carriers' transaction gate so the next FENCE can install and start.
func (e *keyUpdateEngine) beginLocked() {
	if e.active {
		return
	}
	e.state, e.phase = KuStateIdle, 0
	e.slot = KeyUpdateSlot{}
	e.hs = nil
	e.releaseNoiseLocked()
	e.confirmI2R, e.confirmR2I = [32]byte{}, [32]byte{}
	e.newRevision, e.prevRevision = [32]byte{}, [32]byte{}
	e.xx1, e.xx2, e.xx3 = nil, nil, nil
	e.ready, e.commit, e.armed = nil, nil, nil
	e.localFenceSent, e.localConfirmSent = false, false
	e.peerFenceSeen, e.peerConfirmSeen = false, false
	e.peerDoneSeen, e.doneQueued, e.doneSent = false, false, false
	e.rxSwitched, e.committed, e.stable = false, false, false
	e.cancelPending, e.aborted = false, false
	// A follower solicitation is superseded by the transaction that follows it.
	e.requestPending = false
	// Re-pin the target for the next transaction and reset both carriers' gates.
	e.target = nil
	e.io.beginKeyUpdateTransaction()
	if target := e.targetIO(); target != nil && target != e.io {
		target.beginKeyUpdateTransaction()
	}
}

// finalizeCarrierLocked releases the pending carrier state of exactly this
// transaction, proving the target tuple, sequence and new generation.
func (e *keyUpdateEngine) finalizeCarrierLocked() error {
	target := e.targetIO()
	if target == nil {
		return nil
	}
	err := target.FinalizeKeyUpdate(e.seq, e.cfg.TargetLinkID, e.cfg.TargetLinkEpoch, e.cfg.LaneID, e.newGeneration)
	e.clearRecoveryReserveLocked()
	return err
}

// adoptNewerSequenceLocked retires the current transaction so a newer XX1 can be
// adopted, but only when the local side is provably finished with it: the peer
// started a strictly newer sequence, both directions are confirmed locally and
// our DONE has already been written (Stable-equivalent, except that the peer's
// DONE may still be in flight), so the old transaction cannot fence or confirm
// anything further. The old generation is recorded as stable only if the peer's
// DONE was actually observed; otherwise it is only retired for late-DONE
// tolerance. It preserves the transcript proof, target tuple and TargetRef of
// the new request, which is handled by the normal XX1 path afterwards.
func (e *keyUpdateEngine) adoptNewerSequenceLocked(message KeyUpdateMessage) error {
	if message.UpdateSeq <= e.seq || !e.localConfirmSent || !e.peerConfirmSeen || !e.doneSent {
		return nil
	}
	e.completedSeq, e.completedRevision = e.seq, e.newRevision
	if e.peerDoneSeen {
		e.markMutualDoneLocked()
	}
	if err := e.finalizeCarrierLocked(); err != nil {
		return err
	}
	e.stable, e.aborted, e.active = false, false, false
	return nil
}

// armRecoveryReserveLocked arms the bounded old-domain recovery reserve on every
// carrier this transaction writes through, for as long as it is in flight.
func (e *keyUpdateEngine) armRecoveryReserveLocked() {
	if e.io != nil {
		e.io.armKeyUpdateRecoveryReserve()
	}
	if target := e.targetIO(); target != nil && target != e.io {
		target.armKeyUpdateRecoveryReserve()
	}
}

// clearRecoveryReserveLocked drops the reserve once the transaction ends.
func (e *keyUpdateEngine) clearRecoveryReserveLocked() {
	if e.io != nil {
		e.io.clearKeyUpdateRecoveryReserve()
	}
	if target := e.targetIO(); target != nil && target != e.io {
		target.clearKeyUpdateRecoveryReserve()
	}
}

// markMutualDoneLocked records the mutual-DONE completion on the carrier whose
// own roots this transaction actually advanced (the pinned target: the
// negotiation owner itself for a self-update, or the distinct DATA carrier), and
// advances THAT carrier's policy baseline. A carrier whose roots did not switch
// keeps its entire usage baseline (base/baseTime and every lifetime counter,
// including the aggregate failed-auth observer) and is only re-armed for the next
// automatic trigger. This matters because a DATA-only rotation must never refresh
// the CONTROL/ROUTE key-use accounting of a Link whose control root never changed.
func (e *keyUpdateEngine) markMutualDoneLocked() {
	target := e.targetIO()
	if target == nil {
		return
	}
	switched := target.markKeyUpdateStable(e.newGeneration, e.seq, e.cfg.TargetLinkID, e.cfg.TargetLinkEpoch, e.cfg.LaneID)
	if e.io != nil && e.io != target {
		// The negotiation owner's roots did not change: keep its usage baseline
		// and status, and only allow a later crossing to start another update.
		e.io.rearmKeyUpdateTrigger()
	}
	if switched {
		// Only a carrier whose roots actually switched gets a fresh budget
		// measured from those roots. For a self-target this is the same object,
		// advanced exactly once.
		target.noteStableGeneration(e.newGeneration)
	}
}

func (e *keyUpdateEngine) nextSeqLocked() uint64 {
	next := uint64(1)
	if e.tombstoneSeq > 0 {
		next = e.tombstoneSeq + 1
	} else if e.seq > 0 {
		next = e.seq + 1
	}
	return next
}

// keyUpdateRandomGeneration reads one fresh generation candidate. It is a
// package variable only so a test can force the exact numeric relation between an
// old and a new generation; the wire value is still a random non-zero uint32, and
// no eligibility rule ever compares generations for order.
var keyUpdateRandomGeneration = func() (uint32, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(raw[:]), nil
}

// freshGeneration returns a non-zero CSPRNG generation that differs from the
// current TX/RX generations and the pending one of BOTH the negotiation carrier
// and the target carrier, so the new domain is distinct on the carrier that will
// actually switch. The value is random and may be numerically lower than the
// generation it replaces; root freshness is tracked by the per-direction root
// serial, never by this number.
func (e *keyUpdateEngine) freshGeneration() (uint32, error) {
	guarded := []*ProtectedControlIO{e.io}
	if target, ok := e.targetCarrier().(*ProtectedControlIO); ok && target != nil && target != e.io {
		guarded = append(guarded, target)
	}
	for attempt := 0; attempt < 8; attempt++ {
		generation, err := keyUpdateRandomGeneration()
		if err != nil {
			return 0, fmt.Errorf("key update generation: %w", err)
		}
		if generation == 0 {
			continue
		}
		clash := false
		for _, carrier := range guarded {
			if generation == carrier.txGeneration() || generation == carrier.rxGeneration() || generation == carrier.pendingNewGeneration() {
				clash = true
				break
			}
		}
		if clash {
			continue
		}
		return generation, nil
	}
	return 0, fmt.Errorf("%w: no fresh generation", ErrKeyUpdateConfig)
}

// carrierTxGeneration returns the TX generation of a resolved carrier, falling
// back to the negotiation carrier for a carrier that is not a
// ProtectedControlIO.
func carrierTxGeneration(carrier KeyUpdateCarrier, fallback *ProtectedControlIO) uint32 {
	if io, ok := carrier.(*ProtectedControlIO); ok && io != nil {
		return io.txGeneration()
	}
	return fallback.txGeneration()
}

// sendAction encodes one control message into a writer action on the
// negotiation carrier and registers the exact encoded body in the carrier's
// prepared-message whitelist, so the hard-boundary precheck can accept exactly
// the messages this Link authored and nothing else.
func (e *keyUpdateEngine) sendAction(message KeyUpdateMessage) (KeyUpdateAction, error) {
	body, err := EncodeKeyUpdate(message)
	if err != nil {
		return KeyUpdateAction{}, err
	}
	carrier := e.cfg.NegotiationCarrier
	if carrier == nil {
		carrier = e.io
	}
	if io, ok := carrier.(*ProtectedControlIO); ok && io != nil {
		io.notePreparedControl(message, body)
	}
	return KeyUpdateAction{
		Kind: ActionSendUpdate, Carrier: carrier, Owner: e.io, Phase: message.Phase, Seq: message.UpdateSeq,
		ControlType: ControlTypeKeyUpdate, Payload: body, NewRevision: message.NewRevision,
		Target: targetRefOf(carrier),
	}, nil
}

// noiseState builds a fresh update Noise state for an explicit prologue
// transcript without touching any engine field, so a candidate XX1 can be fully
// staged and rejected without mutating live state. The returned private slice is
// owned by the caller and must be cleared if the state is discarded.
func (e *keyUpdateEngine) noiseState(initiator bool, seq uint64, oldGeneration, newGeneration uint32, prevRevision [32]byte) (*noise.HandshakeState, []byte, error) {
	prologue, err := e.prologueFor(seq, oldGeneration, newGeneration, prevRevision)
	if err != nil {
		return nil, nil, err
	}
	private := append([]byte(nil), e.cfg.Identity.PrivateKey.Bytes()...)
	static := noise.DHKey{
		Private: private,
		Public:  append([]byte(nil), e.cfg.Identity.PublicKey[:]...),
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       noise.HandshakeXX,
		Initiator:     initiator,
		Prologue:      prologue,
		StaticKeypair: static,
	})
	if err != nil {
		clear(private)
		return nil, nil, fmt.Errorf("key update noise: %w", err)
	}
	return hs, private, nil
}

// noiseInit creates the update Noise state (real XX over the established,
// old-key-protected LINK_CTRL carrier) for the committed transaction.
func (e *keyUpdateEngine) noiseInit(initiator bool) error {
	if e.noiseStaticPrivate != nil {
		clear(e.noiseStaticPrivate)
		e.noiseStaticPrivate = nil
	}
	hs, private, err := e.noiseState(initiator, e.seq, e.oldGeneration, e.newGeneration, e.prevRevision)
	if err != nil {
		return err
	}
	e.hs, e.noiseStaticPrivate = hs, private
	return nil
}

// prologueFor builds the handshake binding for an explicit transcript: the
// complete descriptor, the target tuple, seq/generations, the canonical
// role-ordered identities and the previous transcript, plus a PSK binding so only
// holders of the network PSK can reproduce the handshake hash. Taking the
// transcript as arguments lets a candidate XX1 be validated before any live field
// is committed.
func (e *keyUpdateEngine) prologueFor(seq uint64, oldGeneration, newGeneration uint32, prevRevision [32]byte) ([]byte, error) {
	coordinatorNode, followerNode := e.canonicalNodes()
	coordinatorStatic, followerStatic := e.canonicalStatics()
	out := []byte(keyUpdatePrologueLabel)
	out = appendLengthPrefixed(out, e.cfg.Descriptor)
	var head [8 + 8 + 1 + 8 + 4 + 4]byte
	binary.BigEndian.PutUint64(head[0:], e.cfg.TargetLinkID)
	binary.BigEndian.PutUint64(head[8:], e.cfg.TargetLinkEpoch)
	head[16] = e.cfg.LaneID
	binary.BigEndian.PutUint64(head[17:], seq)
	binary.BigEndian.PutUint32(head[25:], oldGeneration)
	binary.BigEndian.PutUint32(head[29:], newGeneration)
	out = append(out, head[:]...)
	out = append(out, coordinatorNode[:]...)
	out = append(out, followerNode[:]...)
	out = append(out, coordinatorStatic[:]...)
	out = append(out, followerStatic[:]...)
	out = append(out, prevRevision[:]...)
	mac := hmac.New(sha256.New, e.cfg.PSK[:])
	mac.Write([]byte(keyUpdatePSKLabel))
	mac.Write(out)
	out = append(out, mac.Sum(nil)...)
	return out, nil
}

// canonicalNodes returns (coordinator, follower) NodeIDs. Every party orders
// them by role, never by local/peer, so both ends compute identical prologues
// and proofs.
func (e *keyUpdateEngine) canonicalNodes() ([16]byte, [16]byte) {
	if e.coordinator {
		return e.io.localNodeID, e.io.peerNodeID
	}
	return e.io.peerNodeID, e.io.localNodeID
}

func (e *keyUpdateEngine) canonicalStatics() ([32]byte, [32]byte) {
	if e.coordinator {
		return e.io.localStatic, e.io.peerStatic
	}
	return e.io.peerStatic, e.io.localStatic
}

// confirmKeys derives the two directional confirmation subkeys from the new
// split. They are independent of the hop/control/route keys.
func (e *keyUpdateEngine) confirmKeys(txRoot, rxRoot [32]byte) error {
	coordinator := e.coordinator
	i2r, r2i := txRoot, rxRoot
	if !coordinator {
		i2r, r2i = rxRoot, txRoot
	}
	first, err := deriveConfirmKey(i2r, 0, e.cfg.TargetLinkID)
	if err != nil {
		return err
	}
	second, err := deriveConfirmKey(r2i, 1, e.cfg.TargetLinkID)
	if err != nil {
		return err
	}
	e.confirmI2R, e.confirmR2I = first, second
	return nil
}

func deriveConfirmKey(root [32]byte, direction byte, linkID uint64) ([32]byte, error) {
	info := append([]byte(keyUpdateConfirmLabel), direction)
	var link [8]byte
	binary.BigEndian.PutUint64(link[:], linkID)
	info = append(info, link[:]...)
	derived, err := hkdf.Key(sha256.New, root[:], nil, string(info), 32)
	var out [32]byte
	if err == nil {
		copy(out[:], derived)
	}
	clear(derived)
	return out, err
}

func appendLengthPrefixedTo(w interface{ Write([]byte) (int, error) }, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = w.Write(length[:])
	_, _ = w.Write(value)
}

// HandleUpdate processes one inbound LINK_CTRL ControlType 0x09 message and
// returns the writer actions it requires. It never performs I/O itself, so the
// reading goroutine can never block on a write and two TCP peers cannot
// deadlock. The runtime's unique writer executes the actions in order.
func (c *ProtectedControlIO) HandleUpdate(message ProtectedMessage) ([]KeyUpdateAction, error) {
	if c == nil {
		return nil, ErrControlTerminal
	}
	if message.Kind != wire.FrameKindLinkControl || len(message.Payload) < 2 || message.Payload[0] != ControlTypeKeyUpdate {
		return nil, fmt.Errorf("%w: not a LINK_CTRL key update frame", ErrKeyUpdateMessage)
	}
	decoded, err := DecodeKeyUpdate(message.Payload[1:])
	if err != nil {
		return nil, err
	}
	if decoded.Lane != c.lane() {
		return nil, fmt.Errorf("%w: lane %d", ErrKeyUpdateMessage, decoded.Lane)
	}
	engine, err := c.keyUpdateEngine()
	if err != nil {
		// A carrier that only hosts FENCE/CONFIRM/DONE for a negotiated DATA
		// target needs an installed slot but no full negotiation config.
		switch decoded.Phase {
		case KeyUpdateFence, KeyUpdateConfirm, KeyUpdateDone, KeyUpdateAbort, KeyUpdateAbortAck, KeyUpdateAbortReject:
			return c.handleInstalledPhase(decoded)
		default:
			return nil, err
		}
	}
	if decoded.TargetLinkID != engine.cfg.TargetLinkID || decoded.TargetLinkEpoch != engine.cfg.TargetLinkEpoch {
		return nil, fmt.Errorf("%w: target %d/%d", ErrKeyUpdateMessage, decoded.TargetLinkID, decoded.TargetLinkEpoch)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	switch decoded.Phase {
	case KeyUpdateRequest:
		return engine.handleRequestLocked()
	case KeyUpdateXX1, KeyUpdateXX2, KeyUpdateXX3, KeyUpdateReady, KeyUpdateCommit, KeyUpdateArmed:
		return engine.handleNegotiationLocked(decoded)
	case KeyUpdateFence, KeyUpdateConfirm, KeyUpdateDone, KeyUpdateAbort, KeyUpdateAbortAck, KeyUpdateAbortReject:
		return engine.handleDataPhaseLocked(decoded)
	default:
		return nil, fmt.Errorf("%w: unknown phase %d", ErrKeyUpdateMessage, uint8(decoded.Phase))
	}
}

func (c *ProtectedControlIO) lane() uint8 {
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	if c.ku != nil {
		return c.ku.cfg.LaneID
	}
	return c.linkLane
}

// handleInstalledPhase serves FENCE/CONFIRM/DONE and abort phases on a carrier
// that has an installed pending target slot but no negotiation engine.
func (c *ProtectedControlIO) handleInstalledPhase(message KeyUpdateMessage) ([]KeyUpdateAction, error) {
	c.kuMu.Lock()
	slot := c.pendingSlot
	c.kuMu.Unlock()
	if slot == nil || slot.Seq != message.UpdateSeq || slot.NewGeneration != message.NewGeneration {
		return nil, fmt.Errorf("%w: no installed pending slot for seq %d", ErrKeyUpdateState, message.UpdateSeq)
	}
	switch message.Phase {
	case KeyUpdateFence:
		if message.NewRevision != c.pendingRevision() {
			return nil, fmt.Errorf("%w: FENCE revision", ErrKeyUpdateConflict)
		}
		if err := c.switchRX(slot); err != nil {
			return nil, err
		}
		return nil, nil
	case KeyUpdateConfirm:
		if err := c.verifyInstalledConfirm(slot, message); err != nil {
			return nil, err
		}
		return nil, nil
	case KeyUpdateDone:
		if message.NewRevision != c.pendingRevision() {
			return nil, fmt.Errorf("%w: DONE revision", ErrKeyUpdateConflict)
		}
		return nil, nil
	case KeyUpdateAbort, KeyUpdateAbortAck, KeyUpdateAbortReject:
		return nil, c.installedAbort(message)
	default:
		return nil, fmt.Errorf("%w: phase %s needs a negotiation engine", ErrKeyUpdateState, message.Phase)
	}
}

func (e *keyUpdateEngine) handleRequestLocked() ([]KeyUpdateAction, error) {
	if e.active {
		e.usage.Requests++
		return nil, nil
	}
	e.usage.Requests++
	e.beginLocked()
	return e.startLocked()
}

// handleNegotiationLocked advances REQUEST/XX/READY/COMMIT/ARMED.
func (e *keyUpdateEngine) handleNegotiationLocked(message KeyUpdateMessage) ([]KeyUpdateAction, error) {
	if message.UpdateSeq < e.seq || (e.tombstoneSeq != 0 && message.UpdateSeq <= e.tombstoneSeq) {
		return nil, fmt.Errorf("%w: seq %d", ErrKeyUpdateReplay, message.UpdateSeq)
	}
	switch message.Phase {
	case KeyUpdateXX1:
		// Role first: a coordinator never accepts an inbound XX1, and this
		// rejection must not touch any engine field, the carrier's pending slot
		// or the stable generation.
		if e.coordinator {
			return nil, fmt.Errorf("%w: coordinator received XX1", ErrKeyUpdateConflict)
		}
		if e.active && message.UpdateSeq <= e.seq {
			return nil, fmt.Errorf("%w: duplicate XX1", ErrKeyUpdateReplay)
		}
		// Stage the complete candidate transaction on local scratch: generation
		// validation, the XX1 Noise read and the XX2 production all run before
		// anything live is mutated, so a malformed, high-sequenced or otherwise
		// rejected XX1 leaves the engine, the pending slot and the generation
		// exactly as they were and a later legitimate XX1 is still accepted.
		staged, err := e.stageXX1Locked(message)
		if err != nil {
			return nil, err
		}
		// The peer may start the next generation while we are still finishing
		// the previous one: we become Stable on its DONE, but it only becomes
		// Stable on ours, so its new XX1 can legitimately arrive while we are
		// still active. Retire the old transaction only when our part of it is
		// provably complete (local CONFIRM written, peer CONFIRM seen, local DONE
		// written) and only after the candidate above validated.
		if e.active {
			if err := e.adoptNewerSequenceLocked(message); err != nil {
				staged.release()
				return nil, err
			}
		}
		if e.active {
			staged.release()
			return nil, fmt.Errorf("%w: duplicate XX1", ErrKeyUpdateReplay)
		}
		// Commit: reset the finished scratch, then adopt the staged transcript.
		e.beginLocked()
		e.seq, e.oldGeneration, e.newGeneration = message.UpdateSeq, message.OldGeneration, message.NewGeneration
		e.prevRevision = message.PreviousRevision
		e.slot = staged.slot
		e.hs, e.noiseStaticPrivate = staged.hs, staged.private
		e.xx2 = staged.xx2
		// XX1 reveals only the initiator ephemeral: the peer static is not
		// available yet and is checked when the pattern reveals it (XX2 at the
		// initiator, XX3 at the responder).
		e.active, e.state, e.phase = true, KuStatePending, KeyUpdateXX2
		e.armRecoveryReserveLocked()
		action, err := e.sendAction(KeyUpdateMessage{
			Version: KeyUpdateVersion, Phase: KeyUpdateXX2, Lane: e.cfg.LaneID,
			TargetLinkID: e.cfg.TargetLinkID, TargetLinkEpoch: e.cfg.TargetLinkEpoch,
			UpdateSeq: e.seq, OldGeneration: e.oldGeneration, NewGeneration: e.newGeneration,
			PreviousRevision: e.prevRevision, Noise: e.xx2,
		})
		if err != nil {
			return nil, err
		}
		return []KeyUpdateAction{action}, nil
	case KeyUpdateXX2:
		if !e.coordinator {
			return nil, fmt.Errorf("%w: follower received XX2", ErrKeyUpdateConflict)
		}
		if err := e.checkLocked(message); err != nil {
			return nil, err
		}
		if _, _, _, err := e.hs.ReadMessage(nil, message.Noise); err != nil {
			return nil, fmt.Errorf("key update XX2 read: %w", err)
		}
		if err := e.checkPeerStaticLocked(); err != nil {
			return nil, err
		}
		payload, cs1, cs2, err := e.hs.WriteMessage(nil, nil)
		if err != nil {
			return nil, fmt.Errorf("key update XX3: %w", err)
		}
		if cs1 == nil || cs2 == nil {
			return nil, fmt.Errorf("%w: XX3 did not split", ErrKeyUpdateState)
		}
		e.xx3 = append([]byte(nil), payload...)
		if err := e.installSplitLocked(cs1, cs2); err != nil {
			return nil, err
		}
		e.phase = KeyUpdateXX3
		action, err := e.sendAction(KeyUpdateMessage{
			Version: KeyUpdateVersion, Phase: KeyUpdateXX3, Lane: e.cfg.LaneID,
			TargetLinkID: e.cfg.TargetLinkID, TargetLinkEpoch: e.cfg.TargetLinkEpoch,
			UpdateSeq: e.seq, OldGeneration: e.oldGeneration, NewGeneration: e.newGeneration,
			PreviousRevision: e.prevRevision, Noise: e.xx3,
		})
		if err != nil {
			return nil, err
		}
		return []KeyUpdateAction{action}, nil
	case KeyUpdateXX3:
		if e.coordinator {
			return nil, fmt.Errorf("%w: coordinator received XX3", ErrKeyUpdateConflict)
		}
		if err := e.checkLocked(message); err != nil {
			return nil, err
		}
		_, cs1, cs2, err := e.hs.ReadMessage(nil, message.Noise)
		if err != nil {
			return nil, fmt.Errorf("key update XX3 read: %w", err)
		}
		if err := e.checkPeerStaticLocked(); err != nil {
			return nil, err
		}
		if cs1 == nil || cs2 == nil {
			return nil, fmt.Errorf("%w: XX3 did not split", ErrKeyUpdateState)
		}
		if err := e.installSplitLocked(cs1, cs2); err != nil {
			return nil, err
		}
		e.usage.XxCompleted++
		proof, err := e.proof(KeyUpdateReady, e.newRevision)
		if err != nil {
			return nil, err
		}
		e.phase = KeyUpdateReady
		action, err := e.sendAction(KeyUpdateMessage{
			Version: KeyUpdateVersion, Phase: KeyUpdateReady, Lane: e.cfg.LaneID,
			TargetLinkID: e.cfg.TargetLinkID, TargetLinkEpoch: e.cfg.TargetLinkEpoch,
			UpdateSeq: e.seq, OldGeneration: e.oldGeneration, NewGeneration: e.newGeneration,
			NewRevision: e.newRevision, Proof: toArray32(proof),
		})
		if err != nil {
			return nil, err
		}
		return []KeyUpdateAction{action}, nil
	case KeyUpdateReady:
		if !e.coordinator {
			return nil, fmt.Errorf("%w: follower received READY", ErrKeyUpdateConflict)
		}
		if err := e.checkLocked(message); err != nil {
			return nil, err
		}
		if message.NewRevision != e.newRevision {
			return nil, fmt.Errorf("%w: READY revision", ErrKeyUpdateConflict)
		}
		if err := e.verifyProof(KeyUpdateReady, message.NewRevision, message.Proof[:]); err != nil {
			e.usage.ProofsRejected++
			return nil, err
		}
		e.usage.ProofsAccepted++
		proof, err := e.proof(KeyUpdateCommit, e.newRevision)
		if err != nil {
			return nil, err
		}
		// Publish the pending TX/RX slot before authorizing COMMIT so a peer
		// FENCE that arrives first already finds it; publication takes only the
		// short state lock and never waits on rxMu/txMu.
		if err := e.publishPendingLocked(); err != nil {
			return nil, err
		}
		e.committed, e.phase = true, KeyUpdateCommit
		action, err := e.sendAction(KeyUpdateMessage{
			Version: KeyUpdateVersion, Phase: KeyUpdateCommit, Lane: e.cfg.LaneID,
			TargetLinkID: e.cfg.TargetLinkID, TargetLinkEpoch: e.cfg.TargetLinkEpoch,
			UpdateSeq: e.seq, OldGeneration: e.oldGeneration, NewGeneration: e.newGeneration,
			NewRevision: e.newRevision, Proof: toArray32(proof),
		})
		if err != nil {
			return nil, err
		}
		return []KeyUpdateAction{action}, nil
	case KeyUpdateCommit:
		if e.coordinator {
			return nil, fmt.Errorf("%w: coordinator received COMMIT", ErrKeyUpdateConflict)
		}
		if err := e.checkLocked(message); err != nil {
			return nil, err
		}
		if message.NewRevision != e.newRevision {
			return nil, fmt.Errorf("%w: COMMIT revision", ErrKeyUpdateConflict)
		}
		if err := e.verifyProof(KeyUpdateCommit, message.NewRevision, message.Proof[:]); err != nil {
			e.usage.ProofsRejected++
			return nil, err
		}
		e.usage.ProofsAccepted++
		proof, err := e.proof(KeyUpdateArmed, e.newRevision)
		if err != nil {
			return nil, err
		}
		// Publish before ARMED: the coordinator may FENCE immediately after
		// receiving ARMED, so the pending slot must already be visible.
		if err := e.publishPendingLocked(); err != nil {
			return nil, err
		}
		e.committed, e.state, e.phase = true, KuStateArmed, KeyUpdateArmed
		action, err := e.sendAction(KeyUpdateMessage{
			Version: KeyUpdateVersion, Phase: KeyUpdateArmed, Lane: e.cfg.LaneID,
			TargetLinkID: e.cfg.TargetLinkID, TargetLinkEpoch: e.cfg.TargetLinkEpoch,
			UpdateSeq: e.seq, OldGeneration: e.oldGeneration, NewGeneration: e.newGeneration,
			NewRevision: e.newRevision, Proof: toArray32(proof),
		})
		if err != nil {
			return nil, err
		}
		// The follower may fence immediately: sending ARMED proves it installed
		// the pending RX/TX slots.
		fence, err := e.installAndFenceLocked()
		if err != nil {
			return nil, err
		}
		return append([]KeyUpdateAction{action}, fence...), nil
	case KeyUpdateArmed:
		if !e.coordinator {
			return nil, fmt.Errorf("%w: follower received ARMED", ErrKeyUpdateConflict)
		}
		if err := e.checkLocked(message); err != nil {
			return nil, err
		}
		if message.NewRevision != e.newRevision {
			return nil, fmt.Errorf("%w: ARMED revision", ErrKeyUpdateConflict)
		}
		if err := e.verifyProof(KeyUpdateArmed, message.NewRevision, message.Proof[:]); err != nil {
			e.usage.ProofsRejected++
			return nil, err
		}
		e.usage.ProofsAccepted++
		e.state, e.phase = KuStateArmed, KeyUpdateArmed
		return e.installAndFenceLocked()
	default:
		return nil, fmt.Errorf("%w: negotiation phase %s", ErrKeyUpdateMessage, message.Phase)
	}
}

// stagedXX1 is a fully validated candidate transaction that has not touched any
// live engine field yet. Committing it transfers hs/private to the engine.
type stagedXX1 struct {
	hs      *noise.HandshakeState
	private []byte
	xx2     []byte
	slot    KeyUpdateSlot
}

// release discards a staged candidate that was never committed, zeroing the
// owned static private key.
func (s *stagedXX1) release() {
	if s == nil {
		return
	}
	if s.private != nil {
		clear(s.private)
		s.private = nil
	}
	s.hs, s.xx2 = nil, nil
}

// stageXX1Locked validates an inbound XX1 and builds the XX2 response entirely
// on local scratch without mutating any engine field. A rejected candidate
// therefore cannot poison the live transaction, the carrier's pending slot or
// the stable generation; the caller adopts the returned values only on success.
func (e *keyUpdateEngine) stageXX1Locked(message KeyUpdateMessage) (*stagedXX1, error) {
	if message.NewGeneration == 0 {
		return nil, fmt.Errorf("%w: zero new generation", ErrKeyUpdateConflict)
	}
	if message.NewGeneration == e.io.txGeneration() || message.NewGeneration == e.io.rxGeneration() {
		return nil, fmt.Errorf("%w: new generation %d", ErrKeyUpdateConflict, message.NewGeneration)
	}
	// A generation already installed as the pending target belongs to a live
	// transaction and must never be re-staged.
	if pending := e.io.pendingNewGeneration(); pending != 0 && pending == message.NewGeneration {
		return nil, fmt.Errorf("%w: new generation %d already pending", ErrKeyUpdateConflict, message.NewGeneration)
	}
	hs, private, err := e.noiseState(false, message.UpdateSeq, message.OldGeneration, message.NewGeneration, message.PreviousRevision)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, message.Noise); err != nil {
		clear(private)
		return nil, fmt.Errorf("key update XX1 read: %w", err)
	}
	payload, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		clear(private)
		return nil, fmt.Errorf("key update XX2: %w", err)
	}
	return &stagedXX1{
		hs:      hs,
		private: private,
		xx2:     append([]byte(nil), payload...),
		slot: KeyUpdateSlot{
			Seq: message.UpdateSeq, TargetLinkID: e.cfg.TargetLinkID, TargetLinkEpoch: e.cfg.TargetLinkEpoch,
			Lane: e.cfg.LaneID, OldGeneration: message.OldGeneration, NewGeneration: message.NewGeneration,
			Descriptor: append([]byte(nil), e.cfg.Descriptor...),
		},
	}, nil
}

// installAndFenceLocked queues the target install followed by the atomic fence.
func (e *keyUpdateEngine) installAndFenceLocked() ([]KeyUpdateAction, error) {
	slot := e.slot
	slot.TxRoot, slot.RxRoot = e.slot.TxRoot, e.slot.RxRoot
	slot.TxDirection, slot.RxDirection = e.slot.TxDirection, e.slot.RxDirection
	proof, err := e.proof(KeyUpdateConfirm, e.newRevision)
	if err != nil {
		return nil, err
	}
	// Resolve the target carrier exactly once and bind both actions to that
	// instance and its own tuple, so a delayed execution after a reconnect can
	// only be applied to the Link the transaction was negotiated against.
	target := e.targetCarrier()
	ref := targetRefOf(target)
	install := KeyUpdateAction{Kind: ActionInstallPendingTarget, Carrier: target, Owner: e.io, Slot: &slot, Seq: e.seq, NewRevision: e.newRevision, NewGeneration: e.newGeneration, Target: ref}
	fence := KeyUpdateAction{Kind: ActionFenceTarget, Carrier: target, Owner: e.io, Slot: &slot, Seq: e.seq, NewRevision: e.newRevision, NewGeneration: e.newGeneration, Phase: KeyUpdateFence, Proof: toArray32(proof), Target: ref}
	return []KeyUpdateAction{install, fence}, nil
}

// targetCarrier resolves and PINS the target carrier for this transaction. The
// first resolution wins, so a lookup that would return a reconnected peer's new
// Link later cannot move the transaction onto a different instance.
func (e *keyUpdateEngine) targetCarrier() KeyUpdateCarrier {
	if e.target != nil {
		return e.target
	}
	target := KeyUpdateCarrier(e.io)
	if e.cfg.TargetLookup != nil {
		if carrier, err := e.cfg.TargetLookup(e.cfg.TargetLinkID, e.cfg.TargetLinkEpoch, e.cfg.LaneID); err == nil && carrier != nil {
			target = carrier
		}
	}
	e.target = target
	return target
}

// targetIO returns the pinned target as a ProtectedControlIO, or the negotiation
// carrier when the target is not one.
func (e *keyUpdateEngine) targetIO() *ProtectedControlIO {
	if io, ok := e.targetCarrier().(*ProtectedControlIO); ok && io != nil {
		return io
	}
	return e.io
}

// gateCarrier is the carrier that will apply this transaction's FENCE, and
// therefore the carrier whose shared cancel gate must be armed and checked.
func (e *keyUpdateEngine) gateCarrier() *ProtectedControlIO {
	return e.targetIO()
}

// checkLocked rejects a message that disagrees with the locked target tuple.
func (e *keyUpdateEngine) checkLocked(message KeyUpdateMessage) error {
	if message.UpdateSeq != e.seq {
		return fmt.Errorf("%w: seq %d; locked %d", ErrKeyUpdateConflict, message.UpdateSeq, e.seq)
	}
	if message.OldGeneration != e.oldGeneration || message.NewGeneration != e.newGeneration {
		return fmt.Errorf("%w: generation %d->%d; locked %d->%d", ErrKeyUpdateConflict, message.OldGeneration, message.NewGeneration, e.oldGeneration, e.newGeneration)
	}
	if message.Lane != e.cfg.LaneID {
		return fmt.Errorf("%w: lane %d", ErrKeyUpdateConflict, message.Lane)
	}
	return nil
}

// installSplitLocked derives the two directional roots, the control protectors
// and the confirmation subkeys, and stores the pending slot.
func (e *keyUpdateEngine) installSplitLocked(cs1, cs2 *noise.CipherState) error {
	c1, c2 := cs1.UnsafeKey(), cs2.UnsafeKey()
	defer clear(c1[:])
	defer clear(c2[:])
	txRoot, rxRoot := c1, c2
	txDirection, rxDirection := DirectionInitiatorToResponder, DirectionResponderToInitiator
	if !e.coordinator {
		txRoot, rxRoot = c2, c1
		txDirection, rxDirection = DirectionResponderToInitiator, DirectionInitiatorToResponder
	}
	if err := e.confirmKeys(txRoot, rxRoot); err != nil {
		return err
	}
	e.newRevision = sha256.Sum256(e.hs.ChannelBinding())
	e.slot.TxRoot, e.slot.RxRoot = txRoot, rxRoot
	e.slot.TxDirection, e.slot.RxDirection = txDirection, rxDirection
	e.slot.Revision = e.newRevision
	// Bind the canonical roles and the peer's CONFIRM verification key into the
	// trusted slot, so an installed-only carrier verifies the peer CONFIRM MAC
	// with no access to this engine's Noise state or confirmation subkeys.
	coordinatorNode, followerNode := e.canonicalNodes()
	coordinatorStatic, followerStatic := e.canonicalStatics()
	e.slot.CoordinatorNode, e.slot.FollowerNode = coordinatorNode, followerNode
	e.slot.CoordinatorStatic, e.slot.FollowerStatic = coordinatorStatic, followerStatic
	if e.coordinator {
		e.slot.RxConfirmKey, e.slot.PeerConfirmDirection = e.confirmR2I, DirectionResponderToInitiator
	} else {
		e.slot.RxConfirmKey, e.slot.PeerConfirmDirection = e.confirmI2R, DirectionInitiatorToResponder
	}
	if _, err := e.buildPending(e.slot); err != nil {
		return err
	}
	// The three XX messages are complete; the static private key is no longer
	// needed now that the split roots and confirmation subkeys are derived.
	e.releaseNoiseLocked()
	return nil
}

func (e *keyUpdateEngine) buildPending(slot KeyUpdateSlot) (*sessionAdmission, error) {
	tx, err := NewFrameProtector(slot.TxRoot, slot.Descriptor, slot.TargetLinkID, [16]byte{}, SessionClassStream, slot.TxDirection)
	if err != nil {
		return nil, err
	}
	rx, err := NewFrameProtector(slot.RxRoot, slot.Descriptor, slot.TargetLinkID, [16]byte{}, SessionClassStream, slot.RxDirection)
	if err != nil {
		return nil, err
	}
	return &sessionAdmission{sessionID: [16]byte{}, class: SessionClassStream, tx: tx, rx: rx}, nil
}

// toArray32 copies a MAC result, rejecting anything that is not exactly 32 bytes.
func toArray32(value []byte) [32]byte {
	var out [32]byte
	if len(value) == 32 {
		copy(out[:], value)
	}
	return out
}

// keyUpdateProofMAC is the single canonical directional confirmation MAC. Both
// the negotiating engine and an installed target carrier use it, so a proof
// never depends on which object computes it.
func keyUpdateProofMAC(key [32]byte, phase KeyUpdatePhase, lane uint8, targetLinkID, targetLinkEpoch, seq uint64,
	oldGeneration, newGeneration uint32, revision [32]byte, direction byte,
	coordinatorNode, followerNode [16]byte, coordinatorStatic, followerStatic [32]byte, descriptor []byte) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(keyUpdateProofLabel))
	mac.Write([]byte{KeyUpdateVersion, byte(phase), lane, 0})
	var head [8 + 8 + 8 + 4 + 4]byte
	binary.BigEndian.PutUint64(head[0:], targetLinkID)
	binary.BigEndian.PutUint64(head[8:], targetLinkEpoch)
	binary.BigEndian.PutUint64(head[16:], seq)
	binary.BigEndian.PutUint32(head[24:], oldGeneration)
	binary.BigEndian.PutUint32(head[28:], newGeneration)
	mac.Write(head[:])
	mac.Write(revision[:])
	mac.Write([]byte{direction})
	mac.Write(coordinatorNode[:])
	mac.Write(followerNode[:])
	mac.Write(coordinatorStatic[:])
	mac.Write(followerStatic[:])
	appendLengthPrefixedTo(mac, descriptor)
	return toArray32(mac.Sum(nil))
}

func (e *keyUpdateEngine) proof(phase KeyUpdatePhase, revision [32]byte) ([]byte, error) {
	key, direction := e.confirmR2I, DirectionResponderToInitiator
	if e.coordinator {
		key, direction = e.confirmI2R, DirectionInitiatorToResponder
	}
	coordinatorNode, followerNode := e.canonicalNodes()
	coordinatorStatic, followerStatic := e.canonicalStatics()
	mac := keyUpdateProofMAC(key, phase, e.cfg.LaneID, e.cfg.TargetLinkID, e.cfg.TargetLinkEpoch, e.seq,
		e.oldGeneration, e.newGeneration, revision, direction, coordinatorNode, followerNode, coordinatorStatic, followerStatic, e.cfg.Descriptor)
	return mac[:], nil
}

func (e *keyUpdateEngine) verifyProof(phase KeyUpdatePhase, revision [32]byte, proof []byte) error {
	key, direction := e.confirmI2R, DirectionInitiatorToResponder
	if e.coordinator {
		key, direction = e.confirmR2I, DirectionResponderToInitiator
	}
	coordinatorNode, followerNode := e.canonicalNodes()
	coordinatorStatic, followerStatic := e.canonicalStatics()
	want := keyUpdateProofMAC(key, phase, e.cfg.LaneID, e.cfg.TargetLinkID, e.cfg.TargetLinkEpoch, e.seq,
		e.oldGeneration, e.newGeneration, revision, direction, coordinatorNode, followerNode, coordinatorStatic, followerStatic, e.cfg.Descriptor)
	if subtle.ConstantTimeCompare(want[:], proof) != 1 {
		return ErrKeyUpdateProof
	}
	return nil
}

// handleDataPhaseLocked serves FENCE/CONFIRM/DONE and the abort phases on the
// negotiating carrier (CONTROL self-update) or on any carrier whose engine owns
// the transaction.
func (e *keyUpdateEngine) handleDataPhaseLocked(message KeyUpdateMessage) ([]KeyUpdateAction, error) {
	if !e.active && !e.stable {
		return nil, fmt.Errorf("%w: no pending transaction", ErrKeyUpdateState)
	}
	switch message.Phase {
	case KeyUpdateFence:
		if message.UpdateSeq != e.seq {
			return nil, fmt.Errorf("%w: FENCE seq %d", ErrKeyUpdateReplay, message.UpdateSeq)
		}
		if message.NewRevision != e.newRevision {
			return nil, fmt.Errorf("%w: FENCE revision", ErrKeyUpdateConflict)
		}
		if err := e.targetIO().installAndSwitchRX(e.slot); err != nil {
			return nil, err
		}
		e.peerFenceSeen, e.rxSwitched, e.state = true, true, KuStateFenced
		return e.tryStableLocked()
	case KeyUpdateConfirm:
		if message.UpdateSeq != e.seq || message.NewRevision != e.newRevision {
			return nil, fmt.Errorf("%w: CONFIRM identity", ErrKeyUpdateConflict)
		}
		if err := e.verifyPeerConfirm(message); err != nil {
			return nil, err
		}
		e.peerConfirmSeen = true
		e.usage.ProofsAccepted++
		return e.tryStableLocked()
	case KeyUpdateDone:
		if message.UpdateSeq != e.seq || message.NewRevision != e.newRevision {
			// A DONE for the sequence we retired because the peer already moved on
			// to a newer generation is idempotent. It is tolerated only for the
			// exactly known completed sequence/revision and only once this engine
			// has moved on; every other mismatch is still a replay.
			if e.seq > e.completedSeq && message.UpdateSeq == e.completedSeq && message.NewRevision == e.completedRevision {
				return nil, nil
			}
			return nil, fmt.Errorf("%w: DONE identity", ErrKeyUpdateReplay)
		}
		// A valid DONE (seq/revision bound, DirectionMask 0x03 enforced by the
		// decoder) is recorded even when this side has not observed its own
		// CONFIRM write completion yet, then the unified stability check runs.
		e.peerDoneSeen = true
		return e.tryStableLocked()
	case KeyUpdateAbort:
		return e.handleAbortLocked()
	case KeyUpdateAbortAck:
		if !e.cancelPending {
			return nil, fmt.Errorf("%w: unsolicited ABORT_ACK", ErrKeyUpdateState)
		}
		e.usage.AbortAcks++
		e.aborted, e.active, e.state = true, false, KuStateAborted
		e.abortedSeq = e.seq
		e.tombstoneSeq, e.tombstoneRevision = e.seq, e.newRevision
		if err := e.finalizeCarrierLocked(); err != nil {
			return nil, err
		}
		return nil, nil
	case KeyUpdateAbortReject:
		if !e.cancelPending {
			return nil, fmt.Errorf("%w: unsolicited ABORT_REJECT", ErrKeyUpdateState)
		}
		e.usage.AbortRejects++
		// The peer already fenced: release the cancel gate and finish forward.
		// A FENCE that was never written is re-queued here, not rolled back.
		e.cancelPending = false
		e.gateCarrier().clearCancelPending()
		return e.installAndFenceLocked()
	default:
		return nil, fmt.Errorf("%w: data phase %s", ErrKeyUpdateMessage, message.Phase)
	}
}

// tryStableLocked is the single stability evaluation for every actionable event:
// a verified peer CONFIRM, the local FENCE/CONFIRM write completion, the local
// DONE write completion and a validated peer DONE all converge here. It emits
// the local DONE at most once (doneQueued before the write, doneSent only after
// the writer reports success) and declares Stable only when both directions are
// confirmed and both DONE messages are accounted for, so no ACK chain or second
// Noise run can occur.
func (e *keyUpdateEngine) tryStableLocked() ([]KeyUpdateAction, error) {
	if e.stable || e.aborted {
		return nil, nil
	}
	if e.localConfirmSent && e.peerConfirmSeen && !e.doneQueued && !e.doneSent {
		action, err := e.sendAction(KeyUpdateMessage{
			Version: KeyUpdateVersion, Phase: KeyUpdateDone, Lane: e.cfg.LaneID,
			TargetLinkID: e.cfg.TargetLinkID, TargetLinkEpoch: e.cfg.TargetLinkEpoch,
			UpdateSeq: e.seq, OldGeneration: e.oldGeneration, NewGeneration: e.newGeneration,
			NewRevision: e.newRevision, DirectionMask: 0x03,
		})
		if err != nil {
			return nil, err
		}
		e.doneQueued = true
		return []KeyUpdateAction{action}, nil
	}
	if e.localConfirmSent && e.peerConfirmSeen && e.doneSent && e.peerDoneSeen {
		e.stable, e.state = true, KuStateStable
		e.aborted, e.active = false, false
		// Record the exact mutual-DONE proof (completed sequence, target tuple and
		// per-direction root serials) on this Link and on the DATA target carrier
		// when they are distinct, and advance this Link's policy baseline. The
		// proof is what later allows retired tombstones to be reclaimed: freshness
		// is the monotonic root serial, never a numeric generation order.
		e.markMutualDoneLocked()
		// Release the completed transaction's carrier state so this Link can
		// start another update. The proof binds the release to this exact seq,
		// target tuple and new generation.
		if err := e.finalizeCarrierLocked(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return nil, nil
}

// verifyPeerConfirm verifies the peer's new-direction confirmation MAC.
func (e *keyUpdateEngine) verifyPeerConfirm(message KeyUpdateMessage) error {
	key, direction := e.confirmI2R, DirectionInitiatorToResponder
	if e.coordinator {
		key, direction = e.confirmR2I, DirectionResponderToInitiator
	}
	coordinatorNode, followerNode := e.canonicalNodes()
	coordinatorStatic, followerStatic := e.canonicalStatics()
	want := keyUpdateProofMAC(key, KeyUpdateConfirm, e.cfg.LaneID, e.cfg.TargetLinkID, e.cfg.TargetLinkEpoch, e.seq,
		e.oldGeneration, e.newGeneration, message.NewRevision, direction, coordinatorNode, followerNode, coordinatorStatic, followerStatic, e.cfg.Descriptor)
	if subtle.ConstantTimeCompare(want[:], message.Proof[:]) != 1 {
		e.usage.ProofsRejected++
		return ErrKeyUpdateProof
	}
	return nil
}

// handleAbortLocked implements the responder side of the cancel CAS. It takes
// the shared gate before deciding, so a concurrent FENCE either already started
// (reject) or observes the gate and is paused (ack); the two can never both win.
func (e *keyUpdateEngine) handleAbortLocked() ([]KeyUpdateAction, error) {
	e.usage.Aborts++
	gate := e.gateCarrier()
	gate.setCancelPending()
	if e.localFenceSent || gate.fenceStarted() || e.rxSwitched {
		// A FENCE may already have been serialized: refuse, never ACK, and
		// release the gate so the forward path can still complete.
		e.io.clearCancelPending()
		e.usage.AbortRejects++
		action, err := e.sendAction(KeyUpdateMessage{
			Version: KeyUpdateVersion, Phase: KeyUpdateAbortReject, Lane: e.cfg.LaneID,
			TargetLinkID: e.cfg.TargetLinkID, TargetLinkEpoch: e.cfg.TargetLinkEpoch,
			UpdateSeq: e.seq, OldGeneration: e.oldGeneration, NewGeneration: e.newGeneration,
			NewRevision: e.newRevision,
		})
		if err != nil {
			return nil, err
		}
		return []KeyUpdateAction{action}, nil
	}
	// The gate stays armed permanently: the ACK is an irreversible promise that
	// no FENCE for this transaction will ever be applied locally.
	e.aborted, e.active, e.state = true, false, KuStateAborted
	e.abortedSeq = e.seq
	e.tombstoneSeq, e.tombstoneRevision = e.seq, e.newRevision
	if err := e.finalizeCarrierLocked(); err != nil {
		return nil, err
	}
	e.usage.AbortAcks++
	action, err := e.sendAction(KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateAbortAck, Lane: e.cfg.LaneID,
		TargetLinkID: e.cfg.TargetLinkID, TargetLinkEpoch: e.cfg.TargetLinkEpoch,
		UpdateSeq: e.seq, OldGeneration: e.oldGeneration, NewGeneration: e.newGeneration,
		NewRevision: e.newRevision,
	})
	if err != nil {
		return nil, err
	}
	return []KeyUpdateAction{action}, nil
}

// pendingRevision returns the installed pending revision.
func (c *ProtectedControlIO) pendingRevision() [32]byte {
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	return c.pendingRevisionValue
}

// pendingNewGeneration returns the installed pending generation, or 0.
func (c *ProtectedControlIO) pendingNewGeneration() uint32 {
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	return c.pendingGeneration
}

func (c *ProtectedControlIO) txGeneration() uint32 { return c.atomicTxGen.Load() }

func (c *ProtectedControlIO) rxGeneration() uint32 { return c.atomicRxGen.Load() }

func (c *ProtectedControlIO) fenceStarted() bool {
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	return c.fenceStartedFlag
}

// ApplyKeyUpdateAction executes one writer action on this carrier. It is the
// KeyUpdateCarrier method: the runtime's unique writer calls it in the order the
// read side returned the actions, and it is the only place that seals/writes
// update frames.
func (c *ProtectedControlIO) ApplyKeyUpdateAction(action KeyUpdateAction) error {
	if c == nil {
		return ErrControlTerminal
	}
	// Exact-binding check before any mutation: an action resolved for another
	// carrier instance (or a Link whose tuple no longer matches) is refused, so a
	// delayed action can never install a slot, spend a nonce or move a gate on a
	// reconnected peer.
	if action.Target.Instance != nil {
		if action.Target.Instance != c {
			return fmt.Errorf("%w: action is bound to another carrier instance", ErrKeyUpdateTarget)
		}
		if action.Target.LinkID != c.linkID || action.Target.LinkEpoch != c.linkEpoch || action.Target.Lane != c.linkLane {
			return fmt.Errorf("%w: action tuple %d/%d/%d; carrier %d/%d/%d", ErrKeyUpdateTarget,
				action.Target.LinkID, action.Target.LinkEpoch, action.Target.Lane, c.linkID, c.linkEpoch, c.linkLane)
		}
	}
	switch action.Kind {
	case ActionSendUpdate:
		controlType := action.ControlType
		if controlType == 0 {
			controlType = ControlTypeKeyUpdate
		}
		return c.WriteControl(ControlMessage{Type: controlType, Payload: action.Payload})
	case ActionInstallPendingTarget:
		if action.Slot == nil {
			return fmt.Errorf("%w: install without slot", ErrKeyUpdateState)
		}
		return c.installPendingSlot(*action.Slot, action.NewRevision)
	case ActionFenceTarget:
		return c.applyFenceLocked(action)
	case ActionAbortTarget:
		return c.WriteControl(ControlMessage{Type: ControlTypeKeyUpdate, Payload: action.Payload})
	default:
		return fmt.Errorf("%w: action kind %d", ErrKeyUpdateState, action.Kind)
	}
}

// InstallPendingKeyUpdate is the explicit target-side install command: a DATA
// target carrier must have its pending RX/TX slots before it can process a peer
// FENCE or emit a new-key CONFIRM.
func (c *ProtectedControlIO) InstallPendingKeyUpdate(slot KeyUpdateSlot) error {
	return c.installPendingSlot(slot, [32]byte{})
}

func (c *ProtectedControlIO) installPendingSlot(slot KeyUpdateSlot, revision [32]byte) error {
	if slot.NewGeneration == 0 || slot.TargetLinkID == 0 || slot.Seq == 0 || len(slot.Descriptor) == 0 {
		return fmt.Errorf("%w: incomplete slot", ErrKeyUpdateConfig)
	}
	// The installing carrier must own the slot's target tuple. This is what
	// stops a slot negotiated for one Link from being installed on a
	// reconnected peer's instance that happens to carry the same generation.
	if slot.TargetLinkID != c.linkID || slot.TargetLinkEpoch != c.linkEpoch || slot.Lane != c.linkLane {
		return fmt.Errorf("%w: slot target %d/%d/%d; carrier %d/%d/%d", ErrKeyUpdateTarget,
			slot.TargetLinkID, slot.TargetLinkEpoch, slot.Lane, c.linkID, c.linkEpoch, c.linkLane)
	}
	// A trusted slot carries its own negotiated revision. The separate revision
	// argument is a legacy completion value and must never contradict the slot.
	if slot.Revision != ([32]byte{}) && revision != ([32]byte{}) && slot.Revision != revision {
		return fmt.Errorf("%w: slot revision disagrees with the completion event", ErrKeyUpdateConflict)
	}
	if slot.Revision == ([32]byte{}) {
		slot.Revision = revision
	}
	admission, err := (&keyUpdateEngine{coordinator: true}).buildPending(slot)
	if err != nil {
		return err
	}
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	// Idempotent for the same transaction: a re-published slot (or a queued
	// ActionInstallPendingTarget arriving after an early publication) must not
	// fail or overwrite, but it must be the exact same trusted material. A
	// different seq may not overwrite while one is pending.
	if c.pendingSlot != nil {
		if c.pendingSlot.Seq == slot.Seq {
			if !sameKeyUpdateSlot(c.pendingSlot, &slot) {
				return fmt.Errorf("%w: pending slot %d differs from the re-install", ErrKeyUpdateConflict, slot.Seq)
			}
			return nil
		}
		return fmt.Errorf("%w: pending seq %d; refusing %d", ErrKeyUpdateConflict, c.pendingSlot.Seq, slot.Seq)
	}
	// Each direction is validated against the slot it may already have moved to:
	// RX and TX switch independently, so a late install must tolerate a direction
	// that is already on the new generation. The generation reads use the atomic
	// mirrors because the TX/RX switch paths write the plain fields under txMu/
	// rxMu, which this kuMu-guarded installer does not hold.
	if txGen := c.atomicTxGen.Load(); txGen != slot.OldGeneration && txGen != slot.NewGeneration {
		return fmt.Errorf("%w: TX generation %d for slot %d->%d", ErrKeyUpdateConflict, txGen, slot.OldGeneration, slot.NewGeneration)
	}
	if rxGen := c.atomicRxGen.Load(); rxGen != slot.OldGeneration && rxGen != slot.NewGeneration {
		return fmt.Errorf("%w: RX generation %d for slot %d->%d", ErrKeyUpdateConflict, rxGen, slot.OldGeneration, slot.NewGeneration)
	}
	owned := slot
	owned.Descriptor = append([]byte(nil), slot.Descriptor...)
	c.pendingSlot = &owned
	c.pendingAdmission = admission
	c.pendingRevisionValue = owned.Revision
	c.pendingGeneration = slot.NewGeneration
	return nil
}

// applyFenceLocked performs the atomic TX switch: FENCE under the old control
// key, then install the new TX slot and write CONFIRM as its first control
// frame. Nothing can interleave because the whole sequence holds txMu.
//
// This is the update's own recovery path and deliberately does not spend the
// shared recovery reserve: it writes at most exactly one FENCE plus one CONFIRM
// per transaction, it is gated by the pending-slot CAS and the fenceStartedFlag
// CAS, and each action is executed at most once. The count is therefore bounded
// at 2 control frames per transaction, not an unlimited exemption.
func (c *ProtectedControlIO) applyFenceLocked(action KeyUpdateAction) error {
	c.txMu.Lock()
	defer c.txMu.Unlock()
	if c.terminal.Load() {
		return ErrControlTerminal
	}
	c.kuMu.Lock()
	slot, admission := c.pendingSlot, c.pendingAdmission
	revision := c.pendingRevisionValue
	// The cancel gate is checked FIRST: a completed ABORT_ACK arms it and releases
	// the pending slot, and the promise is that no FENCE for this transaction is
	// ever applied, so the refusal must be the gate rather than a missing slot.
	if c.cancelPendingFlag {
		c.kuMu.Unlock()
		return ErrKeyUpdateAbort
	}
	if slot == nil || admission == nil {
		c.kuMu.Unlock()
		return fmt.Errorf("%w: no installed pending slot", ErrKeyUpdateState)
	}
	if c.fenceStartedFlag {
		c.kuMu.Unlock()
		return fmt.Errorf("%w: fence already started", ErrKeyUpdateState)
	}
	// Phase CAS: every field is checked BEFORE any state mutation, so a stale or
	// mismatched FENCE action cannot corrupt the transaction's gate state.
	if action.Seq != 0 && slot.Seq != action.Seq {
		c.kuMu.Unlock()
		return fmt.Errorf("%w: fence seq %d; want %d", ErrKeyUpdateConflict, action.Seq, slot.Seq)
	}
	if action.NewRevision != ([32]byte{}) && action.NewRevision != revision {
		c.kuMu.Unlock()
		return fmt.Errorf("%w: fence revision", ErrKeyUpdateConflict)
	}
	// The TX root serial is the monotonic identity of this direction's root. This
	// atomic fence advances it exactly once; exhaustion fails closed rather than
	// wrapping. It is checked before the FENCE is written so a switch that could
	// not be completed emits nothing.
	currentTxSlot := c.atomicTxSlot.Load()
	if currentTxSlot == nil {
		c.kuMu.Unlock()
		return ErrInvalidControlIO
	}
	if currentTxSlot.serial == ^uint64(0) {
		c.kuMu.Unlock()
		c.terminal.Store(true)
		return ErrCounterExhausted
	}
	txSerial := currentTxSlot.serial + 1
	c.fenceStartedFlag = true
	c.kuMu.Unlock()
	// 1. Last old-key frames: FENCE carries the new revision, sealed under the
	// current TX slot and counter.
	fencePayload, err := EncodeKeyUpdate(KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateFence, Lane: slot.Lane,
		TargetLinkID: slot.TargetLinkID, TargetLinkEpoch: slot.TargetLinkEpoch,
		UpdateSeq: slot.Seq, OldGeneration: slot.OldGeneration, NewGeneration: slot.NewGeneration,
		NewRevision: revision,
	})
	if err != nil {
		return err
	}
	if c.txNext == ^uint64(0) {
		c.terminal.Store(true)
		return ErrCounterExhausted
	}
	fenceCounter := c.txNext
	c.txNext++
	if err := c.sealAndWriteLocked(c.tx, wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{ControlTypeKeyUpdate}, fencePayload...), c.txGen, fenceCounter, KeyDomainControl); err != nil {
		return err
	}
	// 2. Install the new TX slot: fresh root, fresh generation, counters restart
	// at 0 so CONFIRM is the first control frame of the new domain. Only the TX
	// half of the ROUTE_CTRL domain is reset here (routeNext); the RX half
	// (routeLast/routeSeen) is reset by switchRX under rxMu, because TX and RX
	// advance independently.
	c.tx, c.txGen, c.txNext, c.routeNext = admission.tx, slot.NewGeneration, 0, 0
	c.atomicTxGen.Store(slot.NewGeneration)
	// Renew the link root and every admitted session's TX hop cipher so E2E leaf
	// keys follow the new root; TX and RX advance independently.
	c.txRoot = slot.TxRoot
	c.atomicTxSlot.Store(&keyUpdateDirectionSlot{root: slot.TxRoot, generation: slot.NewGeneration, direction: c.txDirection, serial: txSerial})
	c.refreshSessionTX()
	// 3. CONFIRM as the first new-key control frame.
	confirmPayload, err := EncodeKeyUpdate(KeyUpdateMessage{
		Version: KeyUpdateVersion, Phase: KeyUpdateConfirm, Lane: slot.Lane,
		TargetLinkID: slot.TargetLinkID, TargetLinkEpoch: slot.TargetLinkEpoch,
		UpdateSeq: slot.Seq, OldGeneration: slot.OldGeneration, NewGeneration: slot.NewGeneration,
		NewRevision: revision, Proof: action.Proof,
	})
	if err != nil {
		return err
	}
	if err := c.sealAndWriteLocked(c.tx, wire.Frame{Kind: wire.FrameKindLinkControl}, append([]byte{ControlTypeKeyUpdate}, confirmPayload...), c.txGen, c.txNext, KeyDomainControl); err != nil {
		return err
	}
	c.txNext++
	return nil
}

// keyUpdateRxExpectation is the armed post-FENCE RX obligation: after the peer's
// old-root FENCE switched this direction to the new generation, the very next
// physical frame must be that transaction's new-key CONFIRM. It is guarded by
// rxMu and consumed exactly once.
type keyUpdateRxExpectation struct {
	slot KeyUpdateSlot
}

// switchRX installs the pending RX slot after a peer FENCE verified under the
// old control root. TX and RX advance independently. The installed trusted slot
// (never a caller-supplied copy) becomes the authority for the CONFIRM that must
// immediately follow, so no other frame kind can be forwarded before it.
func (c *ProtectedControlIO) switchRX(slot *KeyUpdateSlot) error {
	c.kuMu.Lock()
	admission, installed := c.pendingAdmission, c.pendingSlot
	c.kuMu.Unlock()
	if admission == nil || installed == nil {
		return fmt.Errorf("%w: no installed pending RX slot", ErrKeyUpdateState)
	}
	trusted := *installed
	if slot != nil && (slot.Seq != trusted.Seq || slot.NewGeneration != trusted.NewGeneration) {
		return fmt.Errorf("%w: FENCE slot %d/%d; installed %d/%d", ErrKeyUpdateConflict,
			slot.Seq, slot.NewGeneration, trusted.Seq, trusted.NewGeneration)
	}
	c.rxMu.Lock()
	if c.rxGen != trusted.OldGeneration {
		c.rxMu.Unlock()
		return fmt.Errorf("%w: RX generation %d; want %d", ErrKeyUpdateConflict, c.rxGen, trusted.OldGeneration)
	}
	// The RX root serial is the monotonic identity of this direction's root. This
	// switch advances it exactly once; exhaustion fails closed rather than
	// wrapping, and the check precedes every mutation.
	currentRxSlot := c.atomicRxSlot.Load()
	if currentRxSlot == nil {
		c.rxMu.Unlock()
		return ErrInvalidControlIO
	}
	if currentRxSlot.serial == ^uint64(0) {
		c.rxMu.Unlock()
		c.terminal.Store(true)
		return ErrCounterExhausted
	}
	rxSerial := currentRxSlot.serial + 1
	c.rx, c.rxGen, c.rxLast, c.rxSeen = admission.rx, trusted.NewGeneration, 0, false
	c.routeLast, c.routeSeen = 0, false
	c.atomicRxGen.Store(trusted.NewGeneration)
	c.rxRoot = trusted.RxRoot
	c.atomicRxSlot.Store(&keyUpdateDirectionSlot{root: trusted.RxRoot, generation: trusted.NewGeneration, direction: c.rxDirection, serial: rxSerial})
	// The next physical frame in this direction must be the new-key CONFIRM,
	// authenticated under the new AEAD before any floor, route or E2E delivery.
	c.rxExpect = &keyUpdateRxExpectation{slot: trusted}
	c.rxMu.Unlock()
	// Renew the admitted sessions' RX hop ciphers after releasing rxMu, so a
	// blocked reader can never be held behind this walk. The CONFIRM-first
	// obligation above means no session frame can be delivered in between.
	c.refreshSessionRX()
	return nil
}

func (c *ProtectedControlIO) installAndSwitchRX(slot KeyUpdateSlot) error {
	return c.switchRX(&slot)
}

// checkConfirmFirstLocked enforces the armed post-FENCE obligation: the first
// frame of the new RX domain must be this transaction's CONFIRM, with the new
// generation, control counter 0, the exact tuple/seq/revision of the installed
// trusted slot and a valid directional MAC derived from the slot. It runs after
// the hop AEAD verify (so the bytes were sealed under the actual new root) and
// before any replay floor is committed or the frame is delivered.
func (c *ProtectedControlIO) checkConfirmFirstLocked(frame wire.Frame, control ControlMessage, counter uint64) error {
	slot := &c.rxExpect.slot
	generation := binary.BigEndian.Uint32(frame.HopHeader[:4])
	if generation != slot.NewGeneration || generation != c.rxGen {
		return fmt.Errorf("%w: first new-domain frame generation %d; want %d", ErrKeyUpdateMessage, generation, slot.NewGeneration)
	}
	if counter != 0 {
		return fmt.Errorf("%w: first new-domain control counter %d; want 0", ErrKeyUpdateMessage, counter)
	}
	if control.Type != ControlTypeKeyUpdate {
		return fmt.Errorf("%w: control 0x%02x before the new-key CONFIRM", ErrKeyUpdateMessage, control.Type)
	}
	decoded, err := DecodeKeyUpdate(control.Payload)
	if err != nil {
		return err
	}
	if decoded.Phase != KeyUpdateConfirm {
		return fmt.Errorf("%w: phase %s before the new-key CONFIRM", ErrKeyUpdateMessage, decoded.Phase)
	}
	if decoded.TargetLinkID != slot.TargetLinkID || decoded.TargetLinkEpoch != slot.TargetLinkEpoch ||
		decoded.Lane != slot.Lane || decoded.UpdateSeq != slot.Seq ||
		decoded.OldGeneration != slot.OldGeneration || decoded.NewGeneration != slot.NewGeneration ||
		decoded.NewRevision != slot.Revision {
		return fmt.Errorf("%w: first new-key CONFIRM tuple", ErrKeyUpdateConflict)
	}
	want := keyUpdateProofMAC(slot.RxConfirmKey, KeyUpdateConfirm, slot.Lane, slot.TargetLinkID, slot.TargetLinkEpoch,
		slot.Seq, slot.OldGeneration, slot.NewGeneration, decoded.NewRevision, slot.PeerConfirmDirection,
		slot.CoordinatorNode, slot.FollowerNode, slot.CoordinatorStatic, slot.FollowerStatic, slot.Descriptor)
	if subtle.ConstantTimeCompare(want[:], decoded.Proof[:]) != 1 {
		return ErrKeyUpdateProof
	}
	return nil
}

// verifyInstalledConfirm checks a peer CONFIRM's identity and its directional
// new-key MAC on a carrier that only has the installed trusted pending slot. It
// re-derives the expected MAC from the slot's own confirm key and canonical role
// binding, so the CONFIRM is authenticated against the authenticated slot rather
// than merely compared field by field.
func (c *ProtectedControlIO) verifyInstalledConfirm(slot *KeyUpdateSlot, message KeyUpdateMessage) error {
	if message.UpdateSeq != slot.Seq || message.NewRevision != slot.Revision {
		return fmt.Errorf("%w: CONFIRM identity", ErrKeyUpdateConflict)
	}
	if message.NewGeneration != slot.NewGeneration || message.OldGeneration != slot.OldGeneration ||
		message.Lane != slot.Lane || message.TargetLinkID != slot.TargetLinkID || message.TargetLinkEpoch != slot.TargetLinkEpoch {
		return fmt.Errorf("%w: CONFIRM tuple", ErrKeyUpdateConflict)
	}
	want := keyUpdateProofMAC(slot.RxConfirmKey, KeyUpdateConfirm, slot.Lane, slot.TargetLinkID, slot.TargetLinkEpoch,
		slot.Seq, slot.OldGeneration, slot.NewGeneration, message.NewRevision, slot.PeerConfirmDirection,
		slot.CoordinatorNode, slot.FollowerNode, slot.CoordinatorStatic, slot.FollowerStatic, slot.Descriptor)
	if subtle.ConstantTimeCompare(want[:], message.Proof[:]) != 1 {
		return ErrKeyUpdateProof
	}
	return nil
}

// installedAbort serves abort phases on a carrier without a negotiation engine.
func (c *ProtectedControlIO) installedAbort(message KeyUpdateMessage) error {
	return fmt.Errorf("%w: abandon on an installed-only carrier needs the negotiation engine", ErrKeyUpdateState)
}

// HoldVerified stores an already hop-verified frame for a later drain without
// re-opening old ciphertext after a root switch. The holder is bounded by the
// frozen per-Link control reservation (64 frames / 256 KiB); data-plane queueing
// stays with the runtime's own 4 MiB budget.
func (c *ProtectedControlIO) HoldVerified(message ProtectedMessage) error {
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	if len(c.verifiedPending) >= MaxVerifiedPendingFrames || c.verifiedBytes+len(message.Payload)+len(message.Envelope) > MaxVerifiedPendingBytes {
		return ErrKuStatePending
	}
	owned := message
	owned.Payload = append([]byte(nil), message.Payload...)
	owned.Envelope = append([]byte(nil), message.Envelope...)
	c.verifiedPending = append(c.verifiedPending, owned)
	c.verifiedBytes += len(owned.Payload) + len(owned.Envelope)
	return nil
}

// DrainVerified returns every held frame and releases the accounting. The
// payloads were authenticated before the root switch, so no old key is needed.
func (c *ProtectedControlIO) DrainVerified() []ProtectedMessage {
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	out := c.verifiedPending
	c.verifiedPending, c.verifiedBytes = nil, 0
	return out
}

// VerifiedPending reports the held frame and byte counts.
func (c *ProtectedControlIO) VerifiedPending() (int, int) {
	c.kuMu.Lock()
	defer c.kuMu.Unlock()
	return len(c.verifiedPending), c.verifiedBytes
}

// releaseNoiseLocked zeroes the owned Noise static private key. It is called
// once the three XX messages completed (split derived) and on every terminal
// abort path; the Noise state retains no key material afterwards.
func (e *keyUpdateEngine) releaseNoiseLocked() {
	if e.noiseStaticPrivate != nil {
		clear(e.noiseStaticPrivate)
		e.noiseStaticPrivate = nil
	}
}

// checkPeerStaticLocked enforces that the update handshake authenticated the
// pinned static key. A prologue that merely contains the known public key is not
// proof of possession, so the exchanged static must be compared after every step
// that reveals it, before any split is derived or slot installed.
func (e *keyUpdateEngine) checkPeerStaticLocked() error {
	peer := e.hs.PeerStatic()
	if len(peer) != 32 {
		return fmt.Errorf("%w: update peer static key missing", ErrKeyUpdateConfig)
	}
	if !hmac.Equal(peer, e.cfg.PeerStatic[:]) {
		return fmt.Errorf("%w: update peer static key does not match the established Link", ErrKeyUpdateConfig)
	}
	return nil
}

// CompleteKeyUpdateAction is the writer-completion event. The runtime's unique
// writer calls it after ApplyKeyUpdateAction has fully written the frame (or
// failed), so a partial write can never be mistaken for a completed CONFIRM.
// It runs without txMu, so it may safely enqueue further actions; it may emit
// DONE even when the peer CONFIRM arrived first.
func (c *ProtectedControlIO) CompleteKeyUpdateAction(action KeyUpdateAction, applyErr error) ([]KeyUpdateAction, error) {
	if c == nil {
		return nil, ErrControlTerminal
	}
	owner := action.Owner
	if owner == nil {
		owner = c
	}
	engine, err := owner.keyUpdateEngine()
	if err != nil {
		if action.Kind == ActionFenceTarget && applyErr != nil {
			return nil, applyErr
		}
		return nil, err
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	switch action.Kind {
	case ActionFenceTarget:
		if errors.Is(applyErr, ErrKeyUpdateAbort) {
			// The cancel gate paused a FENCE that had not started: nothing was
			// written, no direction is confirmed, and the transaction now awaits
			// the peer's ABORT_ACK (terminal) or ABORT_REJECT (continue forward).
			return nil, nil
		}
		if applyErr != nil {
			// A partial or uncertain FENCE/CONFIRM write is terminal: the
			// transaction may already be observable to the peer, so it never
			// rolls back and never claims a confirmed direction.
			engine.localFenceSent = true
			return nil, applyErr
		}
		engine.localFenceSent = true
		engine.localConfirmSent = true
		engine.usage.FencesSent++
		engine.usage.ConfirmsSent++
		engine.usage.GenerationSwitches++
		return engine.tryStableLocked()
	case ActionSendUpdate:
		if action.Phase != KeyUpdateDone {
			return nil, applyErr
		}
		if applyErr != nil {
			// The DONE write is partial or uncertain: doneQueued stays set so the
			// possibly emitted bytes are never retried, and doneSent stays false
			// so Stable is never claimed on an unconfirmed write.
			return nil, applyErr
		}
		engine.doneSent = true
		return engine.tryStableLocked()
	default:
		return nil, applyErr
	}
}

// refreshSessionTX re-derives every live admitted session's TX hop cipher from
// the installed TX root; RX is renewed separately at its own FENCE. It takes the
// session table's write lock because it replaces entry.tx, which TX paths read
// under the read lock.
func (c *ProtectedControlIO) refreshSessionTX() {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	for _, entry := range c.sessions {
		if entry.retired {
			continue
		}
		if tx, err := NewFrameProtector(c.txRoot, c.descriptor, c.linkID, entry.sessionID, entry.class, c.txDirection); err == nil {
			entry.tx = tx
		}
	}
}

// refreshSessionRX re-derives every live admitted session's RX hop cipher from
// the installed RX root. It takes the session table's write lock because it
// replaces entry.rx, which RX paths read under the read lock.
func (c *ProtectedControlIO) refreshSessionRX() {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	for _, entry := range c.sessions {
		if entry.retired {
			continue
		}
		if rx, err := NewFrameProtector(c.rxRoot, c.descriptor, c.linkID, entry.sessionID, entry.class, c.rxDirection); err == nil {
			entry.rx = rx
		}
	}
}

// publishPendingLocked installs the trusted pending slot on the carrier before
// the transaction is authorized (COMMIT at the coordinator, ARMED at the
// follower). The slot comes from this side's completed Noise XX split, never
// from a peer FENCE, which carries no key material. It takes only the short
// state lock, so it never blocks on a reader holding rxMu or a writer holding
// txMu.
func (e *keyUpdateEngine) publishPendingLocked() error {
	// Publish the trusted slot on the carrier that will fence: the DATA target
	// when one is configured, otherwise the negotiation carrier itself. It takes
	// only the short state lock and never rxMu/txMu, so a blocked reader cannot
	// stall publication.
	target := e.targetIO()
	if target == nil {
		return fmt.Errorf("%w: no carrier", ErrKeyUpdateState)
	}
	return target.installPendingSlot(e.slot, e.newRevision)
}
