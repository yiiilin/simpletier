// Package circuit owns the SimpleTier P1 Circuit state machine.
//
// A Circuit is one logical, ordered byte stream between a source node and the
// final target node. This package owns:
//
//   - the active key (ContextID, SrcNodeID, CircuitID): a new Dial draws a
//     non-zero 16-byte CSPRNG CircuitID, redraws it on collision with an active
//     or tombstoned record, and fails with ErrResource once the bounded redraws
//     are exhausted;
//   - the frozen open_attempt/request_id rules: the first candidate is
//     attempt 0, a higher attempt is only allowed while the Open is
//     uncommitted, a same-attempt retransmission keeps the original
//     request_id/content, a different same-attempt payload is a conflict that
//     never creates a second target stream, and a late or mismatched
//     CIRCUIT_READY is ignored;
//   - the 30-second cancel/terminal tombstones over (ContextID, SrcNodeID,
//     CircuitID), the per-peer pre-READY reservation pool (64) with its
//     independent CircuitOpenBlockedUntil fence and the 4096 active-circuit
//     ceiling;
//   - the frozen flow control: a 65,536-byte initial window, absolute
//     WINDOW_UPDATE credit, the 256 KiB credit-frontier cap and the 64 KiB
//     per-flow receive buffer bound;
//   - STREAM_DATA stream_seq handling: in-order delivery, complete duplicates
//     discarded and counted, partial overlap and forward gaps answered with
//     STREAM_RESET(PROTOCOL), FIN with an empty payload at next_byte and no
//     DATA accepted after FIN;
//   - the half-close/Reset state machine behind the CloseWrite/Reset/Close
//     operations, each idempotent;
//   - the local, wire-silent session-scoped terminal failure behind FailSession:
//     an exact (SessionID, PathID, PathGeneration) reference is marked terminal
//     under the manager lock, every Circuit it carries fails with
//     ErrSessionLost, and later local Opens on that reference are refused
//     without submitting any frame;
//   - the strict internal codec for the frozen CONTROL_RPC payloads this slice
//     implements (CIRCUIT_OPEN, CIRCUIT_READY, STREAM_RESET, WINDOW_UPDATE) and
//     for STREAM_DATA, plus the optional RESOURCE_ERROR boundary below.
//
// No wire enum is (re)defined here. The numeric rpc_code/status/error/reason
// and flag values mirror wire-protocol.md; this package only owns the payload
// inside the E2E envelope. RESOURCE_ERROR (0x0004) is recognised but
// deliberately unsupported in this slice: the confirmed decision records its
// `resource:u8` as not yet implemented, so resource failures are reported with
// ResetReasonResource instead of a new opcode. See ResourceErrorMessage.
//
// Deliberately out of scope: this package is standalone. It imports only the Go
// standard library and is wired into neither the network runtime nor the
// Path/Session layers: it opens no links, resolves no routes, picks no
// candidate, allocates no MessageNumber, encodes no FrameKind/envelope frame,
// owns no replay window, performs no end-to-end AEAD and derives no key. All of
// that is an injected boundary:
//
//   - CryptoProvider protects one encoded Circuit payload for one
//     (SessionRef, Direction). The default placeholder returns
//     ErrCryptoUnavailable, so nothing here claims that end-to-end encryption
//     works and no KDF is guessed;
//   - Egress owns LinkWriter admission (the synchronous all-or-none
//     CIRCUIT_OPEN admission that is the retry linearization point) and the
//     actual submission. The default placeholder returns ErrEgressUnavailable.
//
// Consequently a Manager built from Config alone can exercise the table, the
// codec, the lifecycle and the flow control, but cannot complete a Dial: the
// real data plane is not implemented by this package and its tests do not claim
// that it is.
//
// Spec anchors: tcp-overlay-network.md 3.2 (Circuit state flow, cancel
// tombstone, accept/cancel winner, per-peer pre-READY pool, 30 s budget),
// 3.1.3 (CircuitOpen/CircuitReady control objects), wire-protocol.md
// C-WIRE-004/C-WIRE-005 (CONTROL_RPC/STREAM_DATA payloads, initial window
// 65,536, 256 KiB credit frontier, 64 KiB per-flow buffer, cancel fence) and
// multiprotocol-overlay.md 3.8 (4096 active streams per node).
package circuit

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"time"
)

// Frozen protocol constants. The wire numbers mirror wire-protocol.md and are
// not redefined as a second wire enum: this package only decodes/encodes the
// CONTROL_RPC and STREAM_DATA payloads that the envelope carries.
const (
	// MaxActive is the per-manager active-circuit ceiling (an implementation
	// may configure a lower Limits.MaxActive, never a higher one).
	MaxActive = 4096
	// MaxPreReadyPerPeer is the per-peer ceiling of pre-READY OpenRecords plus
	// cancel tombstones. Overflow sets the peer's admission fence.
	MaxPreReadyPerPeer = 64
	// MaxTombstones bounds the whole tombstone table. A tombstone that cannot
	// be stored because its own peer pool is full or the table is full sets the
	// independent per-peer admission fence instead.
	MaxTombstones = 4096
	// DefaultTombstoneTTL is the fixed 30-second rejection window of a cancel
	// or terminal record.
	DefaultTombstoneTTL = 30 * time.Second
	// MaxOpenBudget is the frozen maximum source-side Dial budget.
	MaxOpenBudget = 30 * time.Second
	// MaxCandidates is the per-target/lane candidate ceiling (D-ROUTE-003).
	MaxCandidates = 3
	// InitialWindow is the frozen initial credit advertised by CIRCUIT_OPEN and
	// CIRCUIT_READY. A zero or over-cap initial window is rejected before
	// Open/Ready, so a zero-window deadlock cannot be created.
	InitialWindow uint64 = 65536
	// MaxBuffer is the per-flow actual buffer bound, and it doubles as the credit
	// frontier: throughput on a long-fat link is bounded by frontier/RTT, so this
	// number sets the per-stream ceiling at a given round-trip time. At 8 MiB a
	// 300 ms link can carry about 27 MB/s and a 500 ms link about 16 MB/s.
	//
	// It is a ceiling, not a reservation: the buffer starts at recvInitialChunk
	// and grows only as bytes actually arrive, so an idle or slow flow costs 64 KiB
	// while a fully loaded one can hold the full 8 MiB. That is why the 64 MiB
	// data pool still admits many streams rather than only eight.
	MaxBuffer = 8 << 20
	// MaxCreditAhead is the credit frontier cap: a receiver never advertises more
	// than its next_byte plus this many bytes, and a sender rejects a credit
	// beyond its own send frontier plus this bound.
	//
	// It is deliberately larger than InitialWindow. A one-window frontier costs a
	// round trip per window, which caps a stream at window/RTT: 64 KiB against a
	// 500 ms link is 128 KB/s no matter how fast the CPU is. A wider frontier lets
	// the sender keep that much in flight, which is the same bandwidth-delay
	// product reasoning TCP uses when it grows its window. Buffers are still
	// charged as they are actually used (see recvBuf accounting), so raising this
	// does not pre-allocate per flow.
	MaxCreditAhead uint64 = 8 << 20
	// MaxStreamDataPayload is the largest STREAM_DATA payload one E2E frame can
	// carry: the frozen E2E plaintext ceiling (65,536 - 1 kind - 32 hop header
	// - 85 envelope - 32 for the two AEAD tags = 65,386) minus the STREAM_DATA
	// header CircuitID:16B|flags:u8|stream_seq:u64.
	MaxStreamDataPayload = 65361
	// e2eTagHeadroom is the space left at the end of an encoded Circuit payload so
	// the E2E protector can seal in place. It matches the ChaCha20-Poly1305 tag the
	// session protector appends.
	e2eTagHeadroom = 16
	// recvInitialChunk is the first receive-buffer reservation. Growth is doubled,
	// so a flow that only ever moves a few kilobytes never charges the pool for
	// the full MaxBuffer ceiling.
	recvInitialChunk = 64 << 10
	// cwndInitial is the starting congestion window for a peer with no history.
	// Slow start doubles per round trip, so the starting point decides how much of
	// a short transfer is spent ramping rather than transferring: at 256 KiB a
	// 1 MiB transfer over a 100 ms link is almost entirely ramp. 1 MiB is still
	// conservative enough not to overrun a modest path, and peers that have
	// already proved fast start higher (see Manager.initialCwndFor).
	cwndInitial uint64 = 1 << 20
	// cwndMax caps growth so a single flow cannot pin the whole data pool.
	cwndMax uint64 = 8 << 20
	// cwndSlowStartLimit ends slow start. Below it the window doubles per round
	// trip; above it growth drops to about one segment per window, which is the
	// congestion-avoidance phase.
	cwndSlowStartLimit uint64 = 2 << 20
	// FirstAttempt is the frozen first open_attempt: the initial Open is
	// explicitly attempt 0, never an implicit zero value.
	FirstAttempt uint32 = 0
	// controlRPCHeaderSize is rpc_code:u16be | request_id:u64be.
	controlRPCHeaderSize = 2 + 8

	// openPayloadSize is CircuitID:16B | open_attempt:u32be | target_port:u16be
	// | PathID:u64be | PathGeneration:u32be | RouteViewVersion:u64be |
	// PathDigest:32B | source_initial_window:u64be.
	openPayloadSize = 16 + 4 + 2 + 8 + 4 + 8 + 32 + 8
	// readyPayloadSize is CircuitID:16B | open_attempt:u32be | status:u8 |
	// error_code:u16be | initial_window:u64be.
	readyPayloadSize = 16 + 4 + 1 + 2 + 8
	// resetPayloadSize is CircuitID:16B | open_attempt:u32be | reason:u32be.
	resetPayloadSize = 16 + 4 + 4
	// windowPayloadSize is CircuitID:16B | window:u64be.
	windowPayloadSize = 16 + 8
	// resourceErrorPayloadSize is CircuitID:16B | resource:u8 |
	// retry_after_ms:u32be. Decoded only to be rejected as unsupported.
	resourceErrorPayloadSize = 16 + 1 + 4
	// streamDataHeaderSize is CircuitID:16B | flags:u8 | stream_seq:u64be.
	streamDataHeaderSize = 16 + 1 + 8

	maxCircuitIDAttempts    = 8
	maxRequestIDAllocations = 1 << 20
)

// Public errors. Every rejection this package returns matches exactly one of
// these sentinels through errors.Is.
var (
	// ErrInvalidConfig reports unusable manager configuration or a nil context.
	ErrInvalidConfig = errors.New("circuit: invalid config")
	// ErrInvalidKey reports a zero ContextID/CircuitID or an empty endpoint.
	ErrInvalidKey = errors.New("circuit: invalid circuit key")
	// ErrInvalidPort reports a target port outside 1..65535.
	ErrInvalidPort = errors.New("circuit: invalid target port")
	// ErrInvalidBudget reports a Dial budget above the frozen 30-second maximum.
	ErrInvalidBudget = errors.New("circuit: invalid open budget")
	// ErrInvalidWindow reports a zero or over-cap initial window, or an
	// initial window that is not the frozen 65,536 bytes.
	ErrInvalidWindow = errors.New("circuit: invalid initial window")
	// ErrInvalidCandidate reports an unusable or excessive candidate list.
	ErrInvalidCandidate = errors.New("circuit: invalid candidate")
	// ErrNoCandidates reports an Open without any candidate to try.
	ErrNoCandidates = errors.New("circuit: no candidate path")
	// ErrInvalidSession reports a SessionRef that cannot carry a Circuit.
	ErrInvalidSession = errors.New("circuit: invalid session reference")
	// ErrNotFound reports an operation for a CircuitID this manager does not own.
	ErrNotFound = errors.New("circuit: circuit not found")
	// ErrClosed reports an operation after Manager.Close.
	ErrClosed = errors.New("circuit: manager closed")
	// ErrCircuitClosed reports an operation on a Circuit that already ended.
	ErrCircuitClosed = errors.New("circuit: circuit closed")
	// ErrState reports an operation the current lifecycle state does not allow.
	ErrState = errors.New("circuit: invalid state transition")
	// ErrResource reports a limit: active-circuit ceiling, pre-READY pool,
	// admission fence, CircuitID collision after bounded redraw, or a stream
	// buffer/credit overflow.
	ErrResource = errors.New("circuit: resource limit reached")
	// ErrRequestIDExhausted reports that the per-Session request_id counter
	// would wrap. The Session must be closed; ids are never reused.
	ErrRequestIDExhausted = errors.New("circuit: request id exhausted")
	// ErrCanceled reports a Dial or stream ended by cancel/CANCELED.
	ErrCanceled = errors.New("circuit: canceled")
	// ErrOpenTimeout reports that the total Dial budget expired before READY.
	ErrOpenTimeout = errors.New("circuit: open budget exceeded")
	// ErrOutcomeUnknown reports that the target may have created the stream but
	// the source did not confirm READY. The attempt stays fixed afterwards.
	ErrOutcomeUnknown = errors.New("circuit: open outcome unknown")
	// ErrNoRoute reports NO_ROUTE.
	ErrNoRoute = errors.New("circuit: no route")
	// ErrLinkDown reports LINK_DOWN.
	ErrLinkDown = errors.New("circuit: link down")
	// ErrPermissionDenied reports PERMISSION.
	ErrPermissionDenied = errors.New("circuit: permission denied")
	// ErrTargetRefused reports TARGET_REFUSED.
	ErrTargetRefused = errors.New("circuit: target refused")
	// ErrSessionLost reports a Link/Session failure while frames were in flight.
	ErrSessionLost = errors.New("circuit: session lost")
	// ErrSessionRefFailed reports that an operation was refused because the
	// exact SessionRef that carried it is locally terminal (see FailSession).
	//
	// The refused operation always wraps both this sentinel and ErrSessionLost,
	// so errors.Is(err, ErrSessionLost) keeps holding for every caller that
	// already keys on it. This sentinel exists because the injected Egress
	// boundary also reports its own I/O failures as ErrSessionLost (see submit
	// and sendReady): a frame handler may classify only ErrSessionRefFailed as a
	// frame-local Session failure. A bare ErrSessionLost is an I/O/write failure
	// and must stay terminal for the Link, never silently swallowed.
	ErrSessionRefFailed = errors.New("circuit: session reference failed")
	// ErrProtocol reports a peer protocol violation (unknown reset reason,
	// partial overlap, forward gap, FIN mismatch, credit violation).
	ErrProtocol = errors.New("circuit: protocol violation")
	// ErrStreamReset reports a stream terminated by a peer reset.
	ErrStreamReset = errors.New("circuit: stream reset by peer")
	// ErrWriteClosed reports a write after the local FIN or after Close.
	ErrWriteClosed = errors.New("circuit: write side closed")
	// ErrWindowRegressed reports a non-increasing local window advertisement.
	ErrWindowRegressed = errors.New("circuit: window did not advance")
	// ErrCreditExceeded reports credit beyond the frozen frontier or the local
	// receive buffer bound.
	ErrCreditExceeded = errors.New("circuit: credit exceeds cap")
	// ErrMalformedMessage reports a structurally invalid payload.
	ErrMalformedMessage = errors.New("circuit: malformed message")
	// ErrPayloadTooLarge reports an encoded payload above the frozen frame cap.
	ErrPayloadTooLarge = errors.New("circuit: payload too large")
	// ErrUnsupportedControl reports a frozen CONTROL_RPC whose semantics this
	// slice does not implement (currently RESOURCE_ERROR).
	ErrUnsupportedControl = errors.New("circuit: unsupported control rpc")
	// ErrEgressContract reports that the injected Egress refused an Open whose
	// response was already delivered: all-or-none admission was violated.
	ErrEgressContract = errors.New("circuit: egress admission contract violated")
	// ErrCryptoUnavailable is returned by the default CryptoProvider
	// placeholder. It is not a temporary failure and callers must not treat it
	// as evidence that end-to-end protection works.
	ErrCryptoUnavailable = errors.New("circuit: crypto provider unavailable")
	// ErrEgressUnavailable is returned by the default Egress placeholder. No
	// LinkWriter admission or frame submission happens through it.
	ErrEgressUnavailable = errors.New("circuit: egress provider unavailable")
)

// CircuitID is the 16-byte CSPRNG identifier of one logical byte stream. It is
// stable for one Dial and never reused: a new Dial draws a new CircuitID.
type CircuitID [16]byte

// IsZero reports whether the identifier is unset.
func (id CircuitID) IsZero() bool { return id == CircuitID{} }

// String renders the identifier as lowercase hex for diagnostics.
func (id CircuitID) String() string { return hex.EncodeToString(id[:]) }

// NewCircuitID draws a non-zero CSPRNG CircuitID.
func NewCircuitID() (CircuitID, error) {
	for attempt := 0; attempt < maxCircuitIDAttempts; attempt++ {
		var id CircuitID
		if _, err := rand.Read(id[:]); err != nil {
			return CircuitID{}, fmt.Errorf("circuit id: %w", err)
		}
		if !id.IsZero() {
			return id, nil
		}
	}
	return CircuitID{}, fmt.Errorf("%w: no non-zero circuit id after %d attempts", ErrResource, maxCircuitIDAttempts)
}

// ContextID is the full NetworkContext.ID() (SHA-256 of the versioned
// descriptor), not the u64 wire locator.
type ContextID [32]byte

// IsZero reports whether the context is unset.
func (id ContextID) IsZero() bool { return id == ContextID{} }

// String renders the context as lowercase hex for diagnostics.
func (id ContextID) String() string { return hex.EncodeToString(id[:]) }

// NodeID is the 16-byte stable node identity used for the authenticated
// endpoints of a Circuit.
type NodeID [16]byte

// IsZero reports whether the node identity is unset.
func (id NodeID) IsZero() bool { return id == NodeID{} }

// String renders the node identity as lowercase hex for diagnostics.
func (id NodeID) String() string { return hex.EncodeToString(id[:]) }

// SessionID is the 16-byte CSPRNG end-to-end session identifier.
type SessionID [16]byte

// IsZero reports whether the session identifier is unset.
func (id SessionID) IsZero() bool { return id == SessionID{} }

// String renders the session identifier as lowercase hex for diagnostics.
func (id SessionID) String() string { return hex.EncodeToString(id[:]) }

// SessionRef names the Session/lane a Circuit is carried on. The Circuit never
// owns the session keys, epoch, MessageNumber or replay window; it only records
// which session a committed candidate uses so Egress and CryptoProvider receive
// an unambiguous reference.
type SessionRef struct {
	// ID is the session identifier chosen by the logical Path source.
	ID SessionID
	// PathID is the Path that carries the session. Never zero.
	PathID uint64
	// PathGeneration is the Path generation. Never zero.
	PathGeneration uint32
}

// IsZero reports whether the reference is unset.
func (r SessionRef) IsZero() bool {
	return r.ID.IsZero() && r.PathID == 0 && r.PathGeneration == 0
}

// Validate rejects a reference that cannot carry a Circuit.
func (r SessionRef) Validate() error {
	if r.ID.IsZero() {
		return fmt.Errorf("%w: zero session id", ErrInvalidSession)
	}
	if r.PathID == 0 || r.PathGeneration == 0 {
		return fmt.Errorf("%w: path %d/%d", ErrInvalidSession, r.PathID, r.PathGeneration)
	}
	return nil
}

// String renders the reference for diagnostics.
func (r SessionRef) String() string {
	return fmt.Sprintf("session %x path %d/%d", r.ID[:4], r.PathID, r.PathGeneration)
}

// Direction is one E2E key direction of the Session that carries a Circuit.
type Direction uint8

const (
	// DirectionSourceToTarget is the Dial source's outbound direction.
	DirectionSourceToTarget Direction = iota + 1
	// DirectionTargetToSource is the target's outbound direction.
	DirectionTargetToSource
)

func (d Direction) String() string {
	switch d {
	case DirectionSourceToTarget:
		return "source->target"
	case DirectionTargetToSource:
		return "target->source"
	default:
		return fmt.Sprintf("DIRECTION(%d)", uint8(d))
	}
}

// Key is the active identity of one Circuit: the full ContextID, the logical
// Circuit source NodeID and the CircuitID. The manager table, the tombstones
// and the per-peer admission fence all use this triple, so a CANCELED reset (or
// a terminal record) for one CircuitID can never affect another stream.
//
// SrcNodeID is the origin of the Circuit (the Dial source), not the adjacent
// physical neighbour: on the target side it is the authenticated remote source.
type Key struct {
	// ContextID is the full NetworkContext.ID(). Required.
	ContextID ContextID
	// SrcNodeID is the Circuit source. Required.
	SrcNodeID NodeID
	// CircuitID is the stream identifier. Never zero.
	CircuitID CircuitID
}

// Validate rejects a Key that cannot identify a Circuit.
func (k Key) Validate() error {
	if k.ContextID.IsZero() {
		return fmt.Errorf("%w: zero context id", ErrInvalidKey)
	}
	if k.SrcNodeID.IsZero() {
		return fmt.Errorf("%w: empty source node id", ErrInvalidKey)
	}
	if k.CircuitID.IsZero() {
		return fmt.Errorf("%w: zero circuit id", ErrInvalidKey)
	}
	return nil
}

// String renders the identity for diagnostics.
func (k Key) String() string {
	return fmt.Sprintf("context %x src %x circuit %x", k.ContextID[:4], k.SrcNodeID[:4], k.CircuitID[:4])
}

// peerKey scopes the pre-READY pool and the admission fence to one remote peer
// inside one network context.
type peerKey struct {
	contextID ContextID
	nodeID    NodeID
}

func (p peerKey) String() string {
	return fmt.Sprintf("context %x peer %x", p.contextID[:4], p.nodeID[:4])
}

// Role is the local role of one Circuit record.
type Role uint8

const (
	// RoleSource is the local Dial side: it chooses the CircuitID, submits
	// CIRCUIT_OPEN and waits for CIRCUIT_READY.
	RoleSource Role = iota + 1
	// RoleTarget is the accepting side: it admits or refuses an inbound
	// CIRCUIT_OPEN and owns the pending-delivery stream.
	RoleTarget
)

func (r Role) String() string {
	switch r {
	case RoleSource:
		return "Source"
	case RoleTarget:
		return "Target"
	default:
		return fmt.Sprintf("ROLE(%d)", uint8(r))
	}
}

// State is the Circuit lifecycle state. The zero value is not a valid state.
type State uint8

const (
	// StateRequested exists only inside a local Dial before the first candidate
	// is submitted; it is never observable as a successful remote stream.
	StateRequested State = iota + 1
	// StateOpenUncommitted means a candidate is being submitted or was
	// definitively refused, so a higher attempt may still be used.
	StateOpenUncommitted
	// StateOpenCommitted means the injected Egress accepted the complete
	// CIRCUIT_OPEN frame: attempt and request_id are frozen and the Circuit
	// waits for the matching CIRCUIT_READY.
	StateOpenCommitted
	// StateReady means the stream is usable in both directions: the source
	// matched CIRCUIT_READY, or the target created the stream and emitted
	// CIRCUIT_READY.
	StateReady
	// StateLocalWriteClosed means the local FIN was sent; reads still work.
	StateLocalWriteClosed
	// StateRemoteWriteClosed means the peer FIN arrived; writes still work.
	StateRemoteWriteClosed
	// StateBothClosed is the normal data-plane terminal state after both FINs.
	// A Close releases it to StateClosed.
	StateBothClosed
	// StateCancelSent means the source canceled the Dial with
	// STREAM_RESET(CANCELED); it is terminal for this CircuitID and late READY
	// responses are ignored.
	StateCancelSent
	// StateResetting means a reset frame is being submitted; it settles on
	// StateClosed or StateFailed.
	StateResetting
	// StateFailed is a terminal failure (refusal, protocol, resource,
	// OutcomeUnknown, Link/Session loss).
	StateFailed
	// StateClosed is terminal: released by Close or by a completed reset.
	StateClosed
)

// String returns the state name used by the confirmed state flow.
func (s State) String() string {
	switch s {
	case StateRequested:
		return "Requested"
	case StateOpenUncommitted:
		return "OpenUncommitted"
	case StateOpenCommitted:
		return "OpenCommitted"
	case StateReady:
		return "Ready"
	case StateLocalWriteClosed:
		return "LocalWriteClosed"
	case StateRemoteWriteClosed:
		return "RemoteWriteClosed"
	case StateBothClosed:
		return "BothClosed"
	case StateCancelSent:
		return "CancelSent"
	case StateResetting:
		return "Resetting"
	case StateFailed:
		return "Failed"
	case StateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("STATE(%d)", uint8(s))
	}
}

// Terminal reports whether the state allows no further lifecycle progress.
func (s State) Terminal() bool {
	switch s {
	case StateCancelSent, StateResetting, StateFailed, StateClosed:
		return true
	default:
		return false
	}
}

// Finished reports whether the circuit can no longer carry stream data: it is
// Terminal or both directions completed their FIN (StateBothClosed).
func (s State) Finished() bool { return s.Terminal() || s == StateBothClosed }

// writable reports whether new stream bytes may still be sent.
func (s State) writable() bool { return s == StateReady || s == StateRemoteWriteClosed }

// readable reports whether the receive direction can still hand out bytes.
func (s State) readable() bool {
	switch s {
	case StateReady, StateLocalWriteClosed, StateRemoteWriteClosed, StateBothClosed:
		return true
	default:
		return false
	}
}

// ResetReason is the frozen STREAM_RESET reason. An unknown local reason is
// rejected with ErrProtocol and no frame is sent; an unknown received reason
// terminates the stream and is reported as ErrProtocol.
type ResetReason uint32

const (
	// ResetReasonNoRoute is NO_ROUTE.
	ResetReasonNoRoute ResetReason = 0x0001
	// ResetReasonLinkDown is LINK_DOWN.
	ResetReasonLinkDown ResetReason = 0x0002
	// ResetReasonResource is RESOURCE. This slice reports resource failures with
	// this reason instead of the unsupported RESOURCE_ERROR opcode.
	ResetReasonResource ResetReason = 0x0003
	// ResetReasonProtocol is PROTOCOL.
	ResetReasonProtocol ResetReason = 0x0004
	// ResetReasonCanceled is CANCELED: the CircuitID-wide terminal reason.
	ResetReasonCanceled ResetReason = 0x0005
)

// Valid reports whether the reason is defined by the frozen wire schema.
func (r ResetReason) Valid() bool {
	switch r {
	case ResetReasonNoRoute, ResetReasonLinkDown, ResetReasonResource, ResetReasonProtocol, ResetReasonCanceled:
		return true
	default:
		return false
	}
}

// Err maps a reason to the public error a local observer sees.
func (r ResetReason) Err() error {
	switch r {
	case ResetReasonNoRoute:
		return ErrNoRoute
	case ResetReasonLinkDown:
		return ErrLinkDown
	case ResetReasonResource:
		return ErrResource
	case ResetReasonProtocol:
		return ErrProtocol
	case ResetReasonCanceled:
		return ErrCanceled
	default:
		return ErrProtocol
	}
}

func (r ResetReason) String() string {
	switch r {
	case ResetReasonNoRoute:
		return "NO_ROUTE"
	case ResetReasonLinkDown:
		return "LINK_DOWN"
	case ResetReasonResource:
		return "RESOURCE"
	case ResetReasonProtocol:
		return "PROTOCOL"
	case ResetReasonCanceled:
		return "CANCELED"
	default:
		return fmt.Sprintf("RESET_REASON(0x%04x)", uint32(r))
	}
}

// ReadyStatus is the CIRCUIT_READY status.
type ReadyStatus uint8

const (
	// StatusReady accepts the Open; error_code must be 0.
	StatusReady ReadyStatus = 0x01
	// StatusRefused definitively refuses the Open with a refusal error code.
	StatusRefused ReadyStatus = 0x02
	// StatusExpired means the result cannot be determined; error_code must be
	// OUTCOME_UNKNOWN and maps to ErrOutcomeUnknown.
	StatusExpired ReadyStatus = 0x03
)

// Valid reports whether the status is defined by the frozen wire schema.
func (s ReadyStatus) Valid() bool {
	return s == StatusReady || s == StatusRefused || s == StatusExpired
}

func (s ReadyStatus) String() string {
	switch s {
	case StatusReady:
		return "READY"
	case StatusRefused:
		return "REFUSED"
	case StatusExpired:
		return "EXPIRED"
	default:
		return fmt.Sprintf("STATUS(0x%02x)", uint8(s))
	}
}

// ReadyError is the frozen CIRCUIT_READY error_code. Zero means no error and is
// only valid with StatusReady.
type ReadyError uint16

const (
	// ReadyErrorNone is the successful READY code (0).
	ReadyErrorNone ReadyError = 0x0000
	// ReadyErrorNoRoute is NO_ROUTE.
	ReadyErrorNoRoute ReadyError = 0x0001
	// ReadyErrorLinkDown is LINK_DOWN.
	ReadyErrorLinkDown ReadyError = 0x0002
	// ReadyErrorPermission is PERMISSION.
	ReadyErrorPermission ReadyError = 0x0003
	// ReadyErrorTargetRefused is TARGET_REFUSED.
	ReadyErrorTargetRefused ReadyError = 0x0004
	// ReadyErrorResource is RESOURCE.
	ReadyErrorResource ReadyError = 0x0005
	// ReadyErrorOutcomeUnknown is OUTCOME_UNKNOWN; EXPIRED must use it.
	ReadyErrorOutcomeUnknown ReadyError = 0x0006
	// ReadyErrorCanceled is CANCELED.
	ReadyErrorCanceled ReadyError = 0x0007
)

// Valid reports whether the code is defined by the frozen wire schema.
func (e ReadyError) Valid() bool { return e >= ReadyErrorNone && e <= ReadyErrorCanceled }

// refusal reports whether the code may appear with StatusRefused.
func (e ReadyError) refusal() bool {
	switch e {
	case ReadyErrorNoRoute, ReadyErrorLinkDown, ReadyErrorPermission, ReadyErrorTargetRefused, ReadyErrorResource, ReadyErrorCanceled:
		return true
	default:
		return false
	}
}

// Err maps a ready error code to the public error.
func (e ReadyError) Err() error {
	switch e {
	case ReadyErrorNone:
		return nil
	case ReadyErrorNoRoute:
		return ErrNoRoute
	case ReadyErrorLinkDown:
		return ErrLinkDown
	case ReadyErrorPermission:
		return ErrPermissionDenied
	case ReadyErrorTargetRefused:
		return ErrTargetRefused
	case ReadyErrorResource:
		return ErrResource
	case ReadyErrorOutcomeUnknown:
		return ErrOutcomeUnknown
	case ReadyErrorCanceled:
		return ErrCanceled
	default:
		return ErrProtocol
	}
}

func (e ReadyError) String() string {
	switch e {
	case ReadyErrorNone:
		return "NONE"
	case ReadyErrorNoRoute:
		return "NO_ROUTE"
	case ReadyErrorLinkDown:
		return "LINK_DOWN"
	case ReadyErrorPermission:
		return "PERMISSION"
	case ReadyErrorTargetRefused:
		return "TARGET_REFUSED"
	case ReadyErrorResource:
		return "RESOURCE"
	case ReadyErrorOutcomeUnknown:
		return "OUTCOME_UNKNOWN"
	case ReadyErrorCanceled:
		return "CANCELED"
	default:
		return fmt.Sprintf("READY_ERROR(0x%04x)", uint16(e))
	}
}

// RPCCode is the frozen CONTROL_RPC opcode.
type RPCCode uint16

const (
	// RPCOpen is CIRCUIT_OPEN.
	RPCOpen RPCCode = 0x0001
	// RPCReady is CIRCUIT_READY.
	RPCReady RPCCode = 0x0002
	// RPCStreamReset is STREAM_RESET.
	RPCStreamReset RPCCode = 0x0003
	// RPCResourceError is RESOURCE_ERROR. It is recognised so callers can name
	// it, but this slice implements no RESOURCE_ERROR semantics: see
	// ResourceErrorMessage.
	RPCResourceError RPCCode = 0x0004
	// RPCWindowUpdate is WINDOW_UPDATE.
	RPCWindowUpdate RPCCode = 0x0005
)

// Valid reports whether the opcode is defined by the frozen wire schema.
func (c RPCCode) Valid() bool { return c >= RPCOpen && c <= RPCWindowUpdate }

func (c RPCCode) String() string {
	switch c {
	case RPCOpen:
		return "CIRCUIT_OPEN"
	case RPCReady:
		return "CIRCUIT_READY"
	case RPCStreamReset:
		return "STREAM_RESET"
	case RPCResourceError:
		return "RESOURCE_ERROR"
	case RPCWindowUpdate:
		return "WINDOW_UPDATE"
	default:
		return fmt.Sprintf("RPC(0x%04x)", uint16(c))
	}
}

// MessageKind mirrors the frozen envelope MessageType numbers this package can
// emit. It is not a second wire enum: no MessageType is (re)defined here.
type MessageKind uint8

const (
	// KindStreamData is MessageType STREAM_DATA (0x03).
	KindStreamData MessageKind = 0x03
	// KindControlRPC is MessageType CONTROL_RPC (0x04).
	KindControlRPC MessageKind = 0x04
)

// StreamFlags is the frozen STREAM_DATA flags byte.
type StreamFlags uint8

const (
	// FlagData marks a non-empty DATA frame.
	FlagData StreamFlags = 0x01
	// FlagFin marks the empty FIN frame.
	FlagFin StreamFlags = 0x02
)

// Valid reports whether the flags value is exactly DATA or FIN.
func (f StreamFlags) Valid() bool { return f == FlagData || f == FlagFin }

func (f StreamFlags) String() string {
	switch f {
	case FlagData:
		return "DATA"
	case FlagFin:
		return "FIN"
	default:
		return fmt.Sprintf("STREAM_FLAGS(0x%02x)", uint8(f))
	}
}

// OpenMessage is a decoded CIRCUIT_OPEN. Only the payload fields below are part
// of the frozen E2E payload; SrcNodeID, FromNodeID and Session are filled by
// the wiring owner from the authenticated envelope and the arrival session.
//
// The doc-level CircuitOpen control object also lists hops/cursor/hop
// limit/remaining_budget_us. Those fields are not present in the frozen E2E
// CIRCUIT_OPEN payload, so they are not encoded here and the total budget stays
// a local source-side deadline.
type OpenMessage struct {
	// FromNodeID is the authenticated envelope source, i.e. the Circuit source.
	FromNodeID NodeID
	// CircuitID is the stream identifier chosen by the source.
	CircuitID CircuitID
	// Attempt is open_attempt.
	Attempt uint32
	// TargetPort is the virtual target port.
	TargetPort uint16
	// PathID is the candidate Path.
	PathID uint64
	// PathGeneration is the candidate Path generation.
	PathGeneration uint32
	// RouteViewVersion is the RouteView version the candidate came from.
	RouteViewVersion uint64
	// PathDigest is the candidate path digest.
	PathDigest [32]byte
	// SourceInitialWindow is the source's initial credit; it must be exactly
	// InitialWindow.
	SourceInitialWindow uint64
	// RequestID is the CONTROL_RPC request id the response must echo.
	RequestID uint64
	// Session is the session the OPEN arrived on.
	Session SessionRef
}

// Encode returns the CIRCUIT_OPEN CONTROL_RPC payload:
// rpc_code:u16be | request_id:u64be | CircuitID:16B | open_attempt:u32be |
// target_port:u16be | PathID:u64be | PathGeneration:u32be |
// RouteViewVersion:u64be | PathDigest:32B | source_initial_window:u64be.
// Envelope-owned fields (SrcNodeID/DstNodeID/MessageType/SessionID/PathID
// copies) are not part of this payload.
func (o OpenMessage) Encode() ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, controlRPCHeaderSize+openPayloadSize+e2eTagHeadroom)
	out = binary.BigEndian.AppendUint16(out, uint16(RPCOpen))
	out = binary.BigEndian.AppendUint64(out, o.RequestID)
	out = append(out, o.CircuitID[:]...)
	out = binary.BigEndian.AppendUint32(out, o.Attempt)
	out = binary.BigEndian.AppendUint16(out, o.TargetPort)
	out = binary.BigEndian.AppendUint64(out, o.PathID)
	out = binary.BigEndian.AppendUint32(out, o.PathGeneration)
	out = binary.BigEndian.AppendUint64(out, o.RouteViewVersion)
	out = append(out, o.PathDigest[:]...)
	out = binary.BigEndian.AppendUint64(out, o.SourceInitialWindow)
	return out, nil
}

// DecodeOpenMessage parses a CIRCUIT_OPEN CONTROL_RPC payload. Envelope-owned
// fields stay zero and must be filled from the authenticated frame before
// HandleOpen.
func DecodeOpenMessage(payload []byte) (OpenMessage, error) {
	body, err := splitControlRPC(payload, RPCOpen, openPayloadSize)
	if err != nil {
		return OpenMessage{}, err
	}
	var o OpenMessage
	o.RequestID = binary.BigEndian.Uint64(payload[2:10])
	copy(o.CircuitID[:], body[0:16])
	o.Attempt = binary.BigEndian.Uint32(body[16:20])
	o.TargetPort = binary.BigEndian.Uint16(body[20:22])
	o.PathID = binary.BigEndian.Uint64(body[22:30])
	o.PathGeneration = binary.BigEndian.Uint32(body[30:34])
	o.RouteViewVersion = binary.BigEndian.Uint64(body[34:42])
	copy(o.PathDigest[:], body[42:74])
	o.SourceInitialWindow = binary.BigEndian.Uint64(body[74:82])
	if err := o.validate(); err != nil {
		return OpenMessage{}, err
	}
	return o, nil
}

func (o OpenMessage) validate() error {
	if o.CircuitID.IsZero() {
		return fmt.Errorf("%w: zero circuit id", ErrMalformedMessage)
	}
	if o.TargetPort == 0 {
		return fmt.Errorf("%w: target port 0", ErrInvalidPort)
	}
	if o.PathID == 0 || o.PathGeneration == 0 {
		return fmt.Errorf("%w: path %d/%d", ErrInvalidCandidate, o.PathID, o.PathGeneration)
	}
	if o.SourceInitialWindow != InitialWindow {
		return fmt.Errorf("%w: source initial window %d", ErrInvalidWindow, o.SourceInitialWindow)
	}
	return nil
}

// ReadyMessage is a decoded CIRCUIT_READY.
type ReadyMessage struct {
	// FromNodeID is the authenticated envelope source, i.e. the target node. It
	// is optional; when set it must match the record's target node.
	FromNodeID NodeID
	// CircuitID is the stream identifier being answered.
	CircuitID CircuitID
	// Attempt is the echoed open_attempt.
	Attempt uint32
	// Status is READY/REFUSED/EXPIRED.
	Status ReadyStatus
	// ErrorCode is the frozen error_code.
	ErrorCode ReadyError
	// InitialWindow is the target's initial credit for a successful READY.
	InitialWindow uint64
	// RequestID is the echoed request id.
	RequestID uint64
}

// Encode returns the CIRCUIT_READY CONTROL_RPC payload:
// rpc_code:u16be | request_id:u64be | CircuitID:16B | open_attempt:u32be |
// status:u8 | error_code:u16be | initial_window:u64be.
func (r ReadyMessage) Encode() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, controlRPCHeaderSize+readyPayloadSize+e2eTagHeadroom)
	out = binary.BigEndian.AppendUint16(out, uint16(RPCReady))
	out = binary.BigEndian.AppendUint64(out, r.RequestID)
	out = append(out, r.CircuitID[:]...)
	out = binary.BigEndian.AppendUint32(out, r.Attempt)
	out = append(out, byte(r.Status))
	out = binary.BigEndian.AppendUint16(out, uint16(r.ErrorCode))
	out = binary.BigEndian.AppendUint64(out, r.InitialWindow)
	return out, nil
}

// DecodeReadyMessage parses a CIRCUIT_READY CONTROL_RPC payload. FromNodeID
// stays zero and must be filled from the authenticated envelope.
func DecodeReadyMessage(payload []byte) (ReadyMessage, error) {
	body, err := splitControlRPC(payload, RPCReady, readyPayloadSize)
	if err != nil {
		return ReadyMessage{}, err
	}
	var r ReadyMessage
	r.RequestID = binary.BigEndian.Uint64(payload[2:10])
	copy(r.CircuitID[:], body[0:16])
	r.Attempt = binary.BigEndian.Uint32(body[16:20])
	r.Status = ReadyStatus(body[20])
	r.ErrorCode = ReadyError(binary.BigEndian.Uint16(body[21:23]))
	r.InitialWindow = binary.BigEndian.Uint64(body[23:31])
	if err := r.validate(); err != nil {
		return ReadyMessage{}, err
	}
	return r, nil
}

func (r ReadyMessage) validate() error {
	if r.CircuitID.IsZero() {
		return fmt.Errorf("%w: zero circuit id", ErrMalformedMessage)
	}
	if !r.ErrorCode.Valid() {
		return fmt.Errorf("%w: error code 0x%04x", ErrMalformedMessage, uint16(r.ErrorCode))
	}
	switch r.Status {
	case StatusReady:
		if r.ErrorCode != ReadyErrorNone {
			return fmt.Errorf("%w: READY with error %s", ErrMalformedMessage, r.ErrorCode)
		}
		if r.InitialWindow != InitialWindow {
			return fmt.Errorf("%w: READY initial window %d", ErrInvalidWindow, r.InitialWindow)
		}
	case StatusRefused:
		if !r.ErrorCode.refusal() {
			return fmt.Errorf("%w: REFUSED with error %s", ErrMalformedMessage, r.ErrorCode)
		}
		if r.InitialWindow != 0 && r.InitialWindow != InitialWindow {
			return fmt.Errorf("%w: REFUSED initial window %d", ErrInvalidWindow, r.InitialWindow)
		}
	case StatusExpired:
		if r.ErrorCode != ReadyErrorOutcomeUnknown {
			return fmt.Errorf("%w: EXPIRED with error %s", ErrMalformedMessage, r.ErrorCode)
		}
		if r.InitialWindow != 0 && r.InitialWindow != InitialWindow {
			return fmt.Errorf("%w: EXPIRED initial window %d", ErrInvalidWindow, r.InitialWindow)
		}
	default:
		return fmt.Errorf("%w: status 0x%02x", ErrMalformedMessage, uint8(r.Status))
	}
	return nil
}

// ResetMessage is a decoded STREAM_RESET.
type ResetMessage struct {
	// FromNodeID is the authenticated envelope source.
	FromNodeID NodeID
	// CircuitID is the stream being reset.
	CircuitID CircuitID
	// Attempt is open_attempt, used for association and diagnostics only: a
	// CANCELED reset is terminal for every attempt of the CircuitID.
	Attempt uint32
	// Reason is the frozen reset reason.
	Reason ResetReason
}

// Encode returns the STREAM_RESET CONTROL_RPC payload:
// rpc_code:u16be | request_id:u64be | CircuitID:16B | open_attempt:u32be |
// reason:u32be.
func (r ResetMessage) Encode() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, controlRPCHeaderSize+resetPayloadSize+e2eTagHeadroom)
	out = binary.BigEndian.AppendUint16(out, uint16(RPCStreamReset))
	out = binary.BigEndian.AppendUint64(out, 0)
	out = append(out, r.CircuitID[:]...)
	out = binary.BigEndian.AppendUint32(out, r.Attempt)
	out = binary.BigEndian.AppendUint32(out, uint32(r.Reason))
	return out, nil
}

// DecodeResetMessage parses a STREAM_RESET CONTROL_RPC payload. FromNodeID
// stays zero and must be filled from the authenticated envelope.
func DecodeResetMessage(payload []byte) (ResetMessage, error) {
	body, err := splitControlRPC(payload, RPCStreamReset, resetPayloadSize)
	if err != nil {
		return ResetMessage{}, err
	}
	var r ResetMessage
	copy(r.CircuitID[:], body[0:16])
	r.Attempt = binary.BigEndian.Uint32(body[16:20])
	r.Reason = ResetReason(binary.BigEndian.Uint32(body[20:24]))
	if r.CircuitID.IsZero() {
		return ResetMessage{}, fmt.Errorf("%w: zero circuit id", ErrMalformedMessage)
	}
	return r, nil
}

func (r ResetMessage) validate() error {
	if r.CircuitID.IsZero() {
		return fmt.Errorf("%w: zero circuit id", ErrMalformedMessage)
	}
	if !r.Reason.Valid() {
		return fmt.Errorf("%w: reset reason 0x%04x", ErrMalformedMessage, uint32(r.Reason))
	}
	return nil
}

// WindowUpdateMessage is a decoded WINDOW_UPDATE.
type WindowUpdateMessage struct {
	// FromNodeID is the authenticated envelope source.
	FromNodeID NodeID
	// CircuitID is the stream whose credit changes.
	CircuitID CircuitID
	// Window is the absolute next-byte credit: the sender may not send beyond
	// this offset. Values at or below the current credit are ignored.
	Window uint64
}

// Encode returns the WINDOW_UPDATE CONTROL_RPC payload:
// rpc_code:u16be | request_id:u64be | CircuitID:16B | window:u64be.
func (w WindowUpdateMessage) Encode() ([]byte, error) {
	if w.CircuitID.IsZero() {
		return nil, fmt.Errorf("%w: zero circuit id", ErrMalformedMessage)
	}
	out := make([]byte, 0, controlRPCHeaderSize+windowPayloadSize+e2eTagHeadroom)
	out = binary.BigEndian.AppendUint16(out, uint16(RPCWindowUpdate))
	out = binary.BigEndian.AppendUint64(out, 0)
	out = append(out, w.CircuitID[:]...)
	out = binary.BigEndian.AppendUint64(out, w.Window)
	return out, nil
}

// DecodeWindowUpdate parses a WINDOW_UPDATE CONTROL_RPC payload. FromNodeID
// stays zero and must be filled from the authenticated envelope.
func DecodeWindowUpdate(payload []byte) (WindowUpdateMessage, error) {
	body, err := splitControlRPC(payload, RPCWindowUpdate, windowPayloadSize)
	if err != nil {
		return WindowUpdateMessage{}, err
	}
	var w WindowUpdateMessage
	copy(w.CircuitID[:], body[0:16])
	w.Window = binary.BigEndian.Uint64(body[16:24])
	if w.CircuitID.IsZero() {
		return WindowUpdateMessage{}, fmt.Errorf("%w: zero circuit id", ErrMalformedMessage)
	}
	return w, nil
}

// ResourceErrorMessage is the frozen RESOURCE_ERROR body
// (CircuitID:16B | resource:u8 | retry_after_ms:u32be). The confirmed decision
// for this slice records `resource:u8` as not yet supported, so this package
// implements no RESOURCE_ERROR behaviour: Encode and Decode both return
// ErrUnsupportedControl, and resource failures are reported with
// ResetReasonResource. The type exists so the frozen opcode is named instead of
// being silently reinterpreted.
type ResourceErrorMessage struct {
	CircuitID    CircuitID
	Resource     uint8
	RetryAfterMS uint32
}

// Encode always reports ErrUnsupportedControl.
func (ResourceErrorMessage) Encode() ([]byte, error) {
	return nil, fmt.Errorf("%w: RESOURCE_ERROR resource:u8 is not supported; use ResetReasonResource", ErrUnsupportedControl)
}

// DecodeResourceError validates the frozen length and then reports
// ErrUnsupportedControl rather than pretending to interpret `resource:u8`.
func DecodeResourceError(payload []byte) (ResourceErrorMessage, error) {
	if len(payload) != controlRPCHeaderSize+resourceErrorPayloadSize {
		return ResourceErrorMessage{}, fmt.Errorf("%w: RESOURCE_ERROR payload %d bytes", ErrMalformedMessage, len(payload))
	}
	if code := RPCCode(binary.BigEndian.Uint16(payload[0:2])); code != RPCResourceError {
		return ResourceErrorMessage{}, fmt.Errorf("%w: rpc code %s", ErrMalformedMessage, code)
	}
	var msg ResourceErrorMessage
	copy(msg.CircuitID[:], payload[controlRPCHeaderSize:controlRPCHeaderSize+16])
	msg.Resource = payload[controlRPCHeaderSize+16]
	msg.RetryAfterMS = binary.BigEndian.Uint32(payload[controlRPCHeaderSize+17:])
	return ResourceErrorMessage{}, fmt.Errorf("%w: RESOURCE_ERROR for circuit %s", ErrUnsupportedControl, msg.CircuitID)
}

// DecodeControlRPCCode returns the opcode of a CONTROL_RPC payload without
// interpreting its body. A RESOURCE_ERROR payload is reported as
// ErrUnsupportedControl because this slice implements none of its semantics.
func DecodeControlRPCCode(payload []byte) (RPCCode, error) {
	if len(payload) < 2 {
		return 0, fmt.Errorf("%w: CONTROL_RPC payload %d bytes", ErrMalformedMessage, len(payload))
	}
	code := RPCCode(binary.BigEndian.Uint16(payload[0:2]))
	if !code.Valid() {
		return 0, fmt.Errorf("%w: rpc code 0x%04x", ErrMalformedMessage, uint16(code))
	}
	if code == RPCResourceError {
		return code, fmt.Errorf("%w: RESOURCE_ERROR is not supported; use ResetReasonResource", ErrUnsupportedControl)
	}
	return code, nil
}

// splitControlRPC validates the CONTROL_RPC header and returns the body slice.
func splitControlRPC(payload []byte, want RPCCode, bodySize int) ([]byte, error) {
	wantLen := controlRPCHeaderSize + bodySize
	if len(payload) > wantLen {
		return nil, fmt.Errorf("%w: %s payload %d bytes, want %d", ErrMalformedMessage, want, len(payload), wantLen)
	}
	if len(payload) < wantLen {
		return nil, fmt.Errorf("%w: %s payload %d bytes, want %d", ErrMalformedMessage, want, len(payload), wantLen)
	}
	code := RPCCode(binary.BigEndian.Uint16(payload[0:2]))
	if code != want {
		return nil, fmt.Errorf("%w: rpc code %s, want %s", ErrMalformedMessage, code, want)
	}
	return payload[controlRPCHeaderSize:], nil
}

// StreamDataMessage is a decoded STREAM_DATA payload. stream_seq is the
// per-direction byte offset: the first DATA starts at 0 and advances by the
// payload length; FIN is a separate empty-payload frame whose stream_seq equals
// the final byte count and consumes no offset.
type StreamDataMessage struct {
	// FromNodeID is the authenticated envelope source.
	FromNodeID NodeID
	// CircuitID is the stream.
	CircuitID CircuitID
	// Flags is DATA or FIN.
	Flags StreamFlags
	// StreamSeq is the byte offset of this frame.
	StreamSeq uint64
	// Payload carries the bytes for a DATA frame and is empty for FIN.
	Payload []byte
}

// Encode returns the STREAM_DATA payload:
// CircuitID:16B | flags:u8 | stream_seq:u64be | payload.
func (s StreamDataMessage) Encode() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	// Reserve room for the E2E AEAD tag so the protector can seal in place instead
	// of allocating a whole ciphertext buffer per frame.
	out := make([]byte, 0, streamDataHeaderSize+len(s.Payload)+e2eTagHeadroom)
	out = append(out, s.CircuitID[:]...)
	out = append(out, byte(s.Flags))
	out = binary.BigEndian.AppendUint64(out, s.StreamSeq)
	out = append(out, s.Payload...)
	return out, nil
}

// DecodeStreamData parses a STREAM_DATA payload. FromNodeID stays zero and must
// be filled from the authenticated envelope.
func DecodeStreamData(payload []byte) (StreamDataMessage, error) {
	if len(payload) < streamDataHeaderSize {
		return StreamDataMessage{}, fmt.Errorf("%w: STREAM_DATA payload %d bytes", ErrMalformedMessage, len(payload))
	}
	if len(payload) > streamDataHeaderSize+MaxStreamDataPayload {
		return StreamDataMessage{}, fmt.Errorf("%w: STREAM_DATA payload %d bytes", ErrPayloadTooLarge, len(payload))
	}
	var s StreamDataMessage
	copy(s.CircuitID[:], payload[0:16])
	s.Flags = StreamFlags(payload[16])
	s.StreamSeq = binary.BigEndian.Uint64(payload[17:25])
	s.Payload = append([]byte(nil), payload[streamDataHeaderSize:]...)
	if err := s.validate(); err != nil {
		return StreamDataMessage{}, err
	}
	return s, nil
}

func (s StreamDataMessage) validate() error {
	if s.CircuitID.IsZero() {
		return fmt.Errorf("%w: zero circuit id", ErrMalformedMessage)
	}
	if !s.Flags.Valid() {
		return fmt.Errorf("%w: stream flags 0x%02x", ErrMalformedMessage, uint8(s.Flags))
	}
	if s.Flags == FlagData && len(s.Payload) == 0 {
		return fmt.Errorf("%w: DATA with empty payload", ErrMalformedMessage)
	}
	if s.Flags == FlagFin && len(s.Payload) != 0 {
		return fmt.Errorf("%w: FIN with %d payload bytes", ErrMalformedMessage, len(s.Payload))
	}
	if len(s.Payload) > MaxStreamDataPayload {
		return fmt.Errorf("%w: stream payload %d bytes", ErrPayloadTooLarge, len(s.Payload))
	}
	return nil
}

// CryptoProvider is the injected end-to-end protection boundary. The Circuit
// encodes a CONTROL_RPC or STREAM_DATA payload and asks the provider to protect
// it for one (session, direction); the returned body is what Egress submits.
// This package never derives a key, allocates a MessageNumber or owns a replay
// window. Implementations must be safe for concurrent use.
type CryptoProvider interface {
	ProtectPayload(ref SessionRef, dir Direction, plaintext []byte) ([]byte, error)
}

// Admission is the synchronous all-or-none result of submitting CIRCUIT_OPEN.
type Admission uint8

const (
	// AdmissionCommitted means the complete E2E frame was accepted: the frame
	// may reach the target and the attempt/request_id are frozen.
	AdmissionCommitted Admission = iota + 1
	// AdmissionRefused means the frame is definitively not queued and will
	// never be sent, so another candidate may be tried within the same budget.
	AdmissionRefused
)

func (a Admission) String() string {
	switch a {
	case AdmissionCommitted:
		return "Committed"
	case AdmissionRefused:
		return "Refused"
	default:
		return fmt.Sprintf("ADMISSION(%d)", uint8(a))
	}
}

// Submission is one protected E2E body handed to Egress.
type Submission struct {
	// Dest is the envelope destination node.
	Dest NodeID
	// Session is the session/lane the frame must use.
	Session SessionRef
	// Direction is the E2E key direction of this frame.
	Direction Direction
	// Kind is CONTROL_RPC or STREAM_DATA.
	Kind MessageKind
	// FlowControl marks a CONTROL_RPC that is receive-side credit feedback
	// (WINDOW_UPDATE) rather than a session-lifecycle request. The distinction
	// exists because credit feedback is bounded by how fast the receiver drains
	// its own buffer, so it cannot be amplified by a peer, while open/ready/reset
	// can. Charging both from the same control budget made a 64 KiB window cost
	// one token per frame and pinned bulk throughput at a few MB/s.
	FlowControl bool
	// Body is the protected body returned by CryptoProvider.ProtectPayload.
	Body []byte
	// PlainLen is the encoded plaintext length before protection, for budget
	// accounting and diagnostics.
	PlainLen int
}

// Egress is the injected LinkWriter boundary. AdmitOpen is the frozen
// synchronous all-or-none admission that linearizes Dial retries: it must not
// return until the frame is queued (Committed) or provably unsent (Refused),
// must honour ctx, and must be safe for concurrent use. Send submits one
// already-protected frame; a Send failure fails the stream with ErrSessionLost.
//
// This package never writes a frame itself: no FrameKind, envelope, AEAD tag,
// MessageNumber or TCP carrier is produced here.
type Egress interface {
	AdmitOpen(ctx context.Context, sub Submission) (Admission, error)
	Send(ctx context.Context, sub Submission) error
}

// OpenRequest is one local Dial.
type OpenRequest struct {
	// CircuitID optionally pins the stream identifier. Zero draws a fresh
	// non-zero CSPRNG id; a caller-supplied id is validated and rejected with
	// ErrResource on collision instead of being redrawn.
	CircuitID CircuitID
	// TargetNodeID is the final target node (envelope destination). Required:
	// it scopes the pre-READY peer pool and the submission destination.
	TargetNodeID NodeID
	// TargetPort is the virtual target port, 1..65535.
	TargetPort uint16
	// Candidates are the ordered candidate paths of one data lane. At least one
	// and at most MaxCandidates. The slice is copied.
	Candidates []Candidate
	// Budget is the total Dial budget. Zero selects the configured maximum
	// (30 seconds); a higher value is rejected.
	Budget time.Duration
	// InitialWindow must be zero (selects the frozen 65,536 bytes) or exactly
	// InitialWindow. A zero credit window cannot be requested.
	InitialWindow uint64
}

// Candidate is one immutable RouteView candidate captured when the Dial
// started. The manager never consults a RouteView itself.
type Candidate struct {
	// PathID is the candidate Path. Never zero.
	PathID uint64
	// PathGeneration is the candidate Path generation. Never zero.
	PathGeneration uint32
	// RouteViewVersion is the version this candidate was captured from.
	RouteViewVersion uint64
	// PathDigest is the canonical candidate digest.
	PathDigest [32]byte
	// Session is the session that carries this candidate.
	Session SessionRef
}

// Validate rejects an unusable candidate.
func (c Candidate) Validate() error {
	if c.PathID == 0 || c.PathGeneration == 0 {
		return fmt.Errorf("%w: path %d/%d", ErrInvalidCandidate, c.PathID, c.PathGeneration)
	}
	if err := c.Session.Validate(); err != nil {
		return err
	}
	if c.Session.PathID != c.PathID || c.Session.PathGeneration != c.PathGeneration {
		return fmt.Errorf("%w: session path %d/%d does not match candidate path %d/%d",
			ErrInvalidCandidate, c.Session.PathID, c.Session.PathGeneration, c.PathID, c.PathGeneration)
	}
	return nil
}

// OpenResult reports the decision taken for one inbound CIRCUIT_OPEN.
type OpenResult struct {
	// Key is the active key of the affected Circuit.
	Key Key
	// Status is the CIRCUIT_READY status that was submitted.
	Status ReadyStatus
	// Created reports that this call created the target-side stream and queued
	// it for Accept.
	Created bool
	// Duplicate reports a byte-identical same-attempt retransmission: the
	// cached CIRCUIT_READY was resubmitted and no second stream was created.
	Duplicate bool
}

// Limits are the implementation bounds. Every field may only lower the frozen
// maximum; a higher value is rejected by NewManager because raising a limit
// would require a spec revision. The zero value selects the frozen maximum.
type Limits struct {
	// MaxActive is the active-circuit ceiling, at most MaxActive (4096).
	MaxActive int
	// MaxPreReadyPerPeer is the pre-READY pool per peer, at most 64.
	MaxPreReadyPerPeer int
	// MaxTombstones is the tombstone table bound, at most 4096.
	MaxTombstones int
	// TombstoneTTL is the cancel/terminal rejection window, at most 30s.
	TombstoneTTL time.Duration
	// MaxOpenBudget is the Dial budget ceiling, at most 30s.
	MaxOpenBudget time.Duration
}

// resolve fills the defaults and rejects limits above the frozen maximum.
func (l Limits) resolve() (Limits, error) {
	if l.MaxActive == 0 {
		l.MaxActive = MaxActive
	}
	if l.MaxPreReadyPerPeer == 0 {
		l.MaxPreReadyPerPeer = MaxPreReadyPerPeer
	}
	if l.MaxTombstones == 0 {
		l.MaxTombstones = MaxTombstones
	}
	if l.TombstoneTTL == 0 {
		l.TombstoneTTL = DefaultTombstoneTTL
	}
	if l.MaxOpenBudget == 0 {
		l.MaxOpenBudget = MaxOpenBudget
	}
	if l.MaxActive < 0 || l.MaxActive > MaxActive {
		return Limits{}, fmt.Errorf("%w: MaxActive %d above the frozen %d", ErrInvalidConfig, l.MaxActive, MaxActive)
	}
	if l.MaxPreReadyPerPeer < 0 || l.MaxPreReadyPerPeer > MaxPreReadyPerPeer {
		return Limits{}, fmt.Errorf("%w: MaxPreReadyPerPeer %d above the frozen %d", ErrInvalidConfig, l.MaxPreReadyPerPeer, MaxPreReadyPerPeer)
	}
	if l.MaxTombstones < 0 || l.MaxTombstones > MaxTombstones {
		return Limits{}, fmt.Errorf("%w: MaxTombstones %d above the frozen %d", ErrInvalidConfig, l.MaxTombstones, MaxTombstones)
	}
	if l.TombstoneTTL < 0 || l.TombstoneTTL > DefaultTombstoneTTL {
		return Limits{}, fmt.Errorf("%w: TombstoneTTL %s above the frozen %s", ErrInvalidConfig, l.TombstoneTTL, DefaultTombstoneTTL)
	}
	if l.MaxOpenBudget < 0 || l.MaxOpenBudget > MaxOpenBudget {
		return Limits{}, fmt.Errorf("%w: MaxOpenBudget %s above the frozen %s", ErrInvalidConfig, l.MaxOpenBudget, MaxOpenBudget)
	}
	return l, nil
}

// BufferBudget is the optional injected shared-Network buffer allocator port
// for receiver-owned Circuit buffers. It is deliberately not internal/budget:
// this package still imports no ledger, and the runtime wires an adapter that
// books one CategoryData charge (and one frame) per accepted Reservation, so
// the owner is counted in the shared category and heap totals automatically.
//
// ReserveData is all-or-none. On a nil error it returns a non-nil Reservation
// the Manager releases exactly once; on any other result the ledger must be
// unchanged. The call is made with the Manager's own lock held (see
// reserveRecvLocked), so it must not block on external I/O and must never call
// back into this Manager. bytes is the explicit accounted size, never an
// estimate the Manager derives on the allocator's behalf.
//
// Scope: the port accounts the receive buffer this package owns. It does not
// charge control/slot metadata or cached READY bytes, and it does not claim the
// temporary codec copies the outbound path hands to Egress: those belong to the
// runtime's own Egress accounting.
type BufferBudget interface {
	ReserveData(bytes uint64) (Reservation, error)
}

// Reservation is one accepted shared-buffer charge. Release returns it to the
// issuing allocator; the Manager calls it exactly once per successful
// ReserveData, also with the Manager's lock held, so it must not re-enter the
// Manager either.
type Reservation interface {
	Release()
}

// Config is the immutable manager configuration.
type Config struct {
	// ContextID is the full NetworkContext.ID(). Required.
	ContextID ContextID
	// LocalNodeID is the local node identity: the Circuit source for local
	// Dials and the responder for inbound Opens. Required.
	LocalNodeID NodeID
	// Crypto is the injected protection boundary. When nil the placeholder
	// returning ErrCryptoUnavailable is installed.
	Crypto CryptoProvider
	// Egress is the injected LinkWriter boundary. When nil the placeholder
	// returning ErrEgressUnavailable is installed.
	Egress Egress
	// BufferBudget is the injected shared Network allocator for receive
	// buffers. When nil the Manager keeps the component-local self-bound: each
	// Circuit appends into its own slice bounded by MaxBuffer and books no
	// shared bytes, so the frozen 256 MiB heap / 64 MiB data budgets are not
	// claimed. A production runtime must inject one, because only then is every
	// receiver-owned buffer counted in the shared ledger.
	BufferBudget BufferBudget
	// Limits lowers the frozen bounds. Zero fields use the frozen maximum.
	Limits Limits
	// Now is the clock used for tombstones, fences and deadlines. Nil uses
	// time.Now.
	Now func() time.Time
}

// Counters are diagnostic counters. They never change behaviour.
type Counters struct {
	// Opens counts local Dials that created a record.
	Opens uint64
	// Accepts counts streams handed to the application by Accept.
	Accepts uint64
	// LateReady counts CIRCUIT_READY messages ignored as late/stale/unknown.
	LateReady uint64
	// DuplicateData counts complete duplicate DATA frames discarded.
	DuplicateData uint64
	// IgnoredData counts stream data for unknown or finished Circuits.
	IgnoredData uint64
	// ResetsSent counts STREAM_RESET frames submitted.
	ResetsSent uint64
	// ResetsReceived counts STREAM_RESET frames handled.
	ResetsReceived uint64
	// Refused counts inbound Opens answered with REFUSED/EXPIRED.
	Refused uint64
	// Fenced counts Opens rejected because the peer admission fence was set.
	Fenced uint64
	// BytesSent counts stream payload bytes submitted.
	BytesSent uint64
	// BytesReceived counts stream payload bytes accepted.
	BytesReceived uint64
}

// Manager owns the Circuit table, the tombstones and the bounded resources. It
// is safe for concurrent use.
//
// Lock order: a Circuit's ioMu is always acquired before m.mu, and m.mu is
// never held while calling an injected CryptoProvider/Egress method. m.mu alone
// guards the table, tombstones, fences and every lifecycle field; blocking
// operations release it and wait on a broadcast channel instead.
type Manager struct {
	contextID   ContextID
	localNodeID NodeID
	crypto      CryptoProvider
	egress      Egress
	budget      BufferBudget
	limits      Limits
	clock       func() time.Time
	rand        func([]byte) error

	mu       sync.Mutex
	circuits map[Key]*Circuit
	// peerCwnd remembers the congestion window each peer last reached, so a new
	// circuit to a peer that has already demonstrated a fast path does not start
	// again at the initial window. Slow start costs five round trips to fill the
	// ceiling, which at 100 ms RTT is half a second: a small transfer finishes
	// before the window ever grows, so without this history every short transfer
	// on a fast link is limited by the ramp rather than by the link.
	peerCwnd   map[NodeID]uint64
	tombstones map[Key]time.Time
	fences     map[peerKey]time.Time
	pending    []*Circuit
	requestIDs map[SessionID]uint64
	// failedSessions is the bounded terminal SessionRef registry written by
	// FailSession: a ref listed here is refused for every later local
	// Open/admit until its rejection window expires. It is bounded to
	// Limits.MaxTombstones, the same total-owned metadata budget as the
	// CircuitID tombstone table, and reaped with the other windows.
	failedSessions map[SessionRef]time.Time
	// sessionFence is the manager-wide session admission fence armed when a
	// terminal SessionRef cannot be stored because failedSessions is full: it
	// refuses every new local Open/admit with ErrResource (REFUSED(RESOURCE) on
	// the inbound path) for the same rejection window instead of evicting a live
	// failure entry, so no ref can be resurrected before its window ends. It is
	// deliberately not an ErrSessionLost: it fences healthy Sessions too.
	sessionFence time.Time
	counters     Counters
	acceptWoke   chan struct{}
	done         chan struct{}
	closed       bool
}

// NewManager validates the immutable inputs and returns a Manager. A nil Crypto
// or Egress installs the placeholder that returns the corresponding
// Err*Unavailable, so a misconfigured wiring fails closed instead of silently
// sending or protecting nothing.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.ContextID.IsZero() {
		return nil, fmt.Errorf("%w: zero context id", ErrInvalidConfig)
	}
	if cfg.LocalNodeID.IsZero() {
		return nil, fmt.Errorf("%w: zero local node id", ErrInvalidConfig)
	}
	limits, err := cfg.Limits.resolve()
	if err != nil {
		return nil, err
	}
	m := &Manager{
		contextID:   cfg.ContextID,
		localNodeID: cfg.LocalNodeID,
		budget:      cfg.BufferBudget,
		limits:      limits,
		clock:       cfg.Now,
		rand: func(b []byte) error {
			_, err := rand.Read(b)
			return err
		},
		circuits:       make(map[Key]*Circuit),
		peerCwnd:       make(map[NodeID]uint64),
		tombstones:     make(map[Key]time.Time),
		fences:         make(map[peerKey]time.Time),
		requestIDs:     make(map[SessionID]uint64),
		failedSessions: make(map[SessionRef]time.Time),
		acceptWoke:     make(chan struct{}),
		done:           make(chan struct{}),
	}
	m.crypto = cfg.Crypto
	if m.crypto == nil {
		m.crypto = unavailableCryptoProvider{}
	}
	m.egress = cfg.Egress
	if m.egress == nil {
		m.egress = unavailableEgress{}
	}
	return m, nil
}

// ContextID returns the network context this manager is bound to.
func (m *Manager) ContextID() ContextID { return m.contextID }

// LocalNodeID returns the local node identity.
func (m *Manager) LocalNodeID() NodeID { return m.localNodeID }

// Limits returns the resolved bounds.
func (m *Manager) Limits() Limits { return m.limits }

// Done is closed after Close completed. It is closed synchronously by Close.
func (m *Manager) Done() <-chan struct{} { return m.done }

// now returns the injected clock value.
func (m *Manager) now() time.Time {
	if m.clock != nil {
		return m.clock()
	}
	return time.Now()
}

// unavailableCryptoProvider is the placeholder installed when no
// CryptoProvider is injected. It never derives a key.
type unavailableCryptoProvider struct{}

func (unavailableCryptoProvider) ProtectPayload(SessionRef, Direction, []byte) ([]byte, error) {
	return nil, ErrCryptoUnavailable
}

// unavailableEgress is the placeholder installed when no Egress is injected. It
// never queues or sends a frame.
type unavailableEgress struct{}

func (unavailableEgress) AdmitOpen(context.Context, Submission) (Admission, error) {
	return 0, ErrEgressUnavailable
}

func (unavailableEgress) Send(context.Context, Submission) error { return ErrEgressUnavailable }

// Circuit is one Circuit record and the handle returned to callers. It is safe
// for concurrent use. Lifecycle fields are guarded by the owning manager's mu;
// ioMu serializes the submission of frames for this Circuit so that stream_seq
// order, the FIN offset and the reset ordering always match wire order, and so
// that no injected CryptoProvider/Egress call is ever made while m.mu is held.
//
// Lock order: ioMu is acquired before m.mu; m.mu is never held while acquiring
// ioMu and never held across an injected call.
type Circuit struct {
	mgr  *Manager
	key  Key
	role Role
	// peer is the remote peer this record occupies a pre-READY slot for: the
	// target node for a source-side record, the Circuit source for a target.
	peer peerKey

	ioMu sync.Mutex

	// Immutable after publication.
	targetNode    NodeID
	targetPort    uint16
	created       time.Time
	deadline      time.Time
	candidates    []Candidate
	initialWindow uint64

	// Guarded by mgr.mu.
	state      State
	cause      error
	attempt    uint32
	requestID  uint64
	candidate  Candidate
	committed  bool
	session    SessionRef
	sendNext   uint64
	sendWindow uint64
	// cwnd bounds how much unacknowledged data this sender keeps in flight,
	// independently of the credit the peer advertises. Without it the sender
	// always fills the peer's whole window, so any loss means a full window of
	// retransmission and the receive buffer is a queue that never drains. It
	// starts at cwndInitial, grows on acknowledged progress and is halved when the
	// path signals loss by stalling.
	cwnd uint64
	// cwndAcked tracks the highest acknowledged stream offset used to grow cwnd,
	// so growth is per acknowledged byte rather than per call.
	cwndAcked uint64
	// sendMarkedAt and sendMarkedOffset record when a byte offset was handed to
	// the carrier, so a later WINDOW_UPDATE naming that offset yields a round-trip
	// sample without adding probe traffic.
	sendMarkedAt     time.Time
	sendMarkedOffset uint64
	// srtt is the smoothed round-trip time. The credit frontier is sized from it: a
	// link with a long round trip needs more data in flight to stay busy, and one
	// with a short round trip needs less, so a fixed frontier is either wasteful or
	// too small depending on the path.
	srtt     time.Duration
	rttValid bool
	// ackedSpan is how long the acknowledged bytes took, used with cwndAcked to
	// estimate the achieved rate.
	ackedSpan time.Duration
	// ackedSince is when the first acknowledgement was seen, so ackedSpan covers
	// the whole acknowledged interval rather than one sample.
	ackedSince time.Time
	recvBase   uint64
	recvBuf    []byte
	// recvOff is the read cursor inside recvBuf. Reads advance it instead of
	// shifting the remaining bytes down on every call: with a 64 KiB buffer and a
	// 64 KiB reader, shifting moved up to 64 KiB per Read, which made large
	// transfers quadratic in the number of frames. recvBuf[recvOff:] is exactly
	// the unread bytes, so every len(recvBuf) check below keeps its meaning once
	// the cursor is folded in by compactRecvLocked.
	recvOff int
	// recvRes is the shared charge covering recvBuf's owned MaxBuffer
	// capacity. It is non-nil exactly while an injected BufferBudget accounts
	// the array, and is released once when the array is dropped.
	recvRes Reservation
	// recvReserved is how many bytes of the data pool this Circuit's receive
	// buffer currently holds reserved. It grows with the buffer and is released
	// with it.
	recvReserved int
	recvWindow   uint64
	finSent      bool
	finRecv      bool
	resetSent    bool
	resetRecv    bool
	terminalAt   time.Time
	queued       bool
	accepted     bool
	cachedOpen   *OpenMessage
	cachedReady  []byte
	woke         chan struct{}
}

// Key returns the active key of the Circuit.
func (c *Circuit) Key() Key { return c.key }

// ID returns the CircuitID.
func (c *Circuit) ID() CircuitID { return c.key.CircuitID }

// Role returns the local role.
func (c *Circuit) Role() Role { return c.role }

// TargetNode returns the remote peer node: the final target for a source-side
// record and the Circuit source for a target-side record.
func (c *Circuit) TargetNode() NodeID {
	if c.role == RoleTarget {
		return c.key.SrcNodeID
	}
	return c.targetNode
}

// TargetPort returns the virtual target port.
func (c *Circuit) TargetPort() uint16 { return c.targetPort }

// Created returns when the record was created.
func (c *Circuit) Created() time.Time { return c.created }

// Deadline returns the source-side total Dial deadline. It is zero for a
// target-side record.
func (c *Circuit) Deadline() time.Time { return c.deadline }

// InitialWindow returns the frozen initial credit.
func (c *Circuit) InitialWindow() uint64 { return c.initialWindow }

// State returns the current lifecycle state.
func (c *Circuit) State() State {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.state
}

// Cause returns the terminal cause, if any.
func (c *Circuit) Cause() error {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.cause
}

// Attempt returns the current open_attempt.
func (c *Circuit) Attempt() uint32 {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.attempt
}

// RequestID returns the request_id of the current Open attempt.
func (c *Circuit) RequestID() uint64 {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.requestID
}

// Candidate returns the candidate of the current attempt (its zero value before
// the first submission).
func (c *Circuit) Candidate() Candidate {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.candidate
}

// Session returns the session of the current attempt.
func (c *Circuit) Session() SessionRef {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.session
}

// Accepted reports whether a target-side stream was handed to the application.
func (c *Circuit) Accepted() bool {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.accepted
}

// SendNext returns the next stream_seq this side will send.
func (c *Circuit) SendNext() uint64 {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.sendNext
}

// SendWindow returns the absolute credit the peer granted (exclusive bound).
func (c *Circuit) SendWindow() uint64 {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.sendWindow
}

// RecvNext returns the receive frontier: the next byte offset expected from the
// peer, i.e. every accepted byte below it.
func (c *Circuit) RecvNext() uint64 {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.recvBase + uint64(recvUnreadLocked(c))
}

// RecvWindow returns the absolute credit this side advertised.
func (c *Circuit) RecvWindow() uint64 {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.recvWindow
}

// Buffered returns the number of accepted bytes not yet read by the
// application.
func (c *Circuit) Buffered() int {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return recvUnreadLocked(c)
}

// LocalKey builds the active key for a Circuit whose source is the local node.
func (m *Manager) LocalKey(id CircuitID) Key {
	return Key{ContextID: m.contextID, SrcNodeID: m.localNodeID, CircuitID: id}
}

// Lookup returns the record for an active key.
func (m *Manager) Lookup(key Key) (*Circuit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	c := m.circuits[key]
	if c == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	return c, nil
}

// Len returns the number of records held, including terminal records that are
// still inside their rejection window.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.circuits)
}

// Expire drops expired tombstones/fences and fails source-side records whose
// Dial budget expired, returning the number of removed records. It exists so a
// caller with an injected clock can advance time deterministically; every
// mutating entry point also reaps lazily.
func (m *Manager) Expire() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reapLocked(m.now())
}

// activeCountLocked counts records that are not in a finished state.
func (m *Manager) activeCountLocked() int {
	n := 0
	for _, c := range m.circuits {
		if !c.state.Finished() {
			n++
		}
	}
	return n
}

// preReadyCountLocked counts one peer's pre-READY pool: source-side records
// before Ready plus cancel tombstones. Target-side streams that are waiting for
// Accept are not reservations (the READY was already emitted) and are bounded
// by the active ceiling instead.
func (m *Manager) preReadyCountLocked(peer peerKey) int {
	n := 0
	for _, c := range m.circuits {
		if c.peer != peer || c.role != RoleSource {
			continue
		}
		switch c.state {
		case StateRequested, StateOpenUncommitted, StateOpenCommitted:
			n++
		}
	}
	for key := range m.tombstones {
		if key.ContextID == peer.contextID && key.SrcNodeID == peer.nodeID {
			n++
		}
	}
	return n
}

// fencedLocked reports whether the peer's independent admission fence is set.
func (m *Manager) fencedLocked(peer peerKey, now time.Time) bool {
	until, ok := m.fences[peer]
	return ok && now.Before(until)
}

// setFenceLocked arms or extends the peer's admission fence for the frozen
// tombstone TTL. The fence is never cleared early by unrelated reservation
// expiry; only its own deadline ends it.
func (m *Manager) setFenceLocked(peer peerKey, now time.Time) {
	until := now.Add(m.limits.TombstoneTTL)
	if existing, ok := m.fences[peer]; ok && existing.After(until) {
		return
	}
	m.fences[peer] = until
}

// tombstonedLocked reports whether a CircuitID is inside its rejection window.
func (m *Manager) tombstonedLocked(key Key, now time.Time) bool {
	until, ok := m.tombstones[key]
	return ok && now.Before(until)
}

// recordTombstoneLocked stores the cancel/terminal tombstone of a target-side
// record. Tombstones exist to reject late CIRCUIT_OPEN for a CircuitID that the
// receiver already ended, so only the target side records one. A tombstone that
// cannot be stored because the peer pool or the table is full arms the peer
// fence instead: the fence rejects the same late Opens without unbounded state.
func (m *Manager) recordTombstoneLocked(c *Circuit, now time.Time) {
	if c.role != RoleTarget {
		return
	}
	key := c.key
	if _, ok := m.tombstones[key]; ok {
		return
	}
	if m.preReadyCountLocked(c.peer) >= m.limits.MaxPreReadyPerPeer || len(m.tombstones) >= m.limits.MaxTombstones {
		m.setFenceLocked(c.peer, now)
		m.counters.Fenced++
		return
	}
	m.tombstones[key] = now.Add(m.limits.TombstoneTTL)
}

// failSessionLocked stores one terminal SessionRef rejection window. The
// registry is bounded to Limits.MaxTombstones, the same total-owned metadata
// budget as the CircuitID tombstone table. When it is full the entry is not
// stored: the manager-wide session fence is armed for the same TTL instead, so
// no live failure entry is ever evicted and no ref can slip into a fresh Open
// before its window ends (fail closed). m.mu must be held.
func (m *Manager) failSessionLocked(ref SessionRef, now time.Time) {
	until := now.Add(m.limits.TombstoneTTL)
	if existing, ok := m.failedSessions[ref]; ok {
		if existing.After(until) {
			return
		}
		m.failedSessions[ref] = until
		return
	}
	if len(m.failedSessions) >= m.limits.MaxTombstones {
		if m.sessionFence.Before(until) {
			m.sessionFence = until
		}
		return
	}
	m.failedSessions[ref] = until
}

// sessionFailedLocked reports whether one SessionRef's own terminal window is
// open, i.e. that exact reference was passed to FailSession and has not yet
// expired. It is the only predicate that may be reported as ErrSessionLost.
// m.mu must be held.
func (m *Manager) sessionFailedLocked(ref SessionRef, now time.Time) bool {
	until, ok := m.failedSessions[ref]
	return ok && now.Before(until)
}

// sessionFencedLocked reports whether the manager-wide session admission fence
// is open because the terminal SessionRef registry overflowed. A fenced manager
// refuses every new local Open/admit, but that is ordinary local resource
// exhaustion: it says nothing about the health of the Session carrying the
// Open, so it must never be reported as ErrSessionLost. m.mu must be held.
func (m *Manager) sessionFencedLocked(now time.Time) bool {
	return now.Before(m.sessionFence)
}

// newKeyLocked reserves the active key for a new source-side record. A pinned
// CircuitID is validated and rejected on collision; a generated one is redrawn
// up to maxCircuitIDAttempts times and then fails with ErrResource.
func (m *Manager) newKeyLocked(pinned CircuitID) (Key, error) {
	if !pinned.IsZero() {
		key := Key{ContextID: m.contextID, SrcNodeID: m.localNodeID, CircuitID: pinned}
		if _, ok := m.circuits[key]; ok {
			return Key{}, fmt.Errorf("%w: circuit id %s is active", ErrResource, pinned)
		}
		if _, ok := m.tombstones[key]; ok {
			return Key{}, fmt.Errorf("%w: circuit id %s is tombstoned", ErrResource, pinned)
		}
		return key, nil
	}
	for attempt := 0; attempt < maxCircuitIDAttempts; attempt++ {
		var id CircuitID
		if err := m.rand(id[:]); err != nil {
			return Key{}, fmt.Errorf("circuit id: %w", err)
		}
		if id.IsZero() {
			continue
		}
		key := Key{ContextID: m.contextID, SrcNodeID: m.localNodeID, CircuitID: id}
		if _, ok := m.circuits[key]; ok {
			continue
		}
		if _, ok := m.tombstones[key]; ok {
			continue
		}
		return key, nil
	}
	return Key{}, fmt.Errorf("%w: no unique circuit id after %d attempts", ErrResource, maxCircuitIDAttempts)
}

// nextRequestIDLocked allocates the next monotonic request_id for the session.
// Ids are never reused: reaching the u64 ceiling fails instead of wrapping, so
// the Session must be closed.
func (m *Manager) nextRequestIDLocked(ref SessionRef) (uint64, error) {
	if err := ref.Validate(); err != nil {
		return 0, err
	}
	current := m.requestIDs[ref.ID]
	if current == math.MaxUint64 {
		return 0, fmt.Errorf("%w: %s", ErrRequestIDExhausted, ref.ID)
	}
	if _, tracked := m.requestIDs[ref.ID]; !tracked && len(m.requestIDs) >= m.limits.MaxActive {
		// Keep the table bounded: drop counters of sessions no record refers to.
		m.dropUnreferencedRequestIDsLocked()
		if len(m.requestIDs) >= m.limits.MaxActive {
			return 0, fmt.Errorf("%w: request id table full", ErrResource)
		}
	}
	next := current + 1
	m.requestIDs[ref.ID] = next
	return next, nil
}

// dropUnreferencedRequestIDsLocked removes counters whose session no record
// still uses. A live session counter is never dropped, so an id cannot be
// reused while its Session can still carry an Open.
func (m *Manager) dropUnreferencedRequestIDsLocked() {
	used := make(map[SessionID]struct{}, len(m.circuits))
	for _, c := range m.circuits {
		if !c.session.ID.IsZero() {
			used[c.session.ID] = struct{}{}
		}
	}
	for id := range m.requestIDs {
		if _, ok := used[id]; !ok {
			delete(m.requestIDs, id)
		}
	}
}

// reapLocked drops expired copies and fails source-side records whose Dial
// budget expired without an owner left to observe it.
func (m *Manager) reapLocked(now time.Time) int {
	removed := 0
	for key, c := range m.circuits {
		if c.state.Finished() && !c.terminalAt.IsZero() && now.Sub(c.terminalAt) >= m.limits.TombstoneTTL {
			// The record becomes unreachable through Lookup, so its owned
			// receive array and the shared charge covering it are reclaimed
			// here; no later path can reach them.
			m.releaseRecvLocked(c)
			delete(m.circuits, key)
			removed++
		}
	}
	for key, until := range m.tombstones {
		if !now.Before(until) {
			delete(m.tombstones, key)
			removed++
		}
	}
	for peer, until := range m.fences {
		if !now.Before(until) {
			delete(m.fences, peer)
		}
	}
	for ref, until := range m.failedSessions {
		if !now.Before(until) {
			delete(m.failedSessions, ref)
		}
	}
	if !m.sessionFence.IsZero() && !now.Before(m.sessionFence) {
		m.sessionFence = time.Time{}
	}
	for _, c := range m.circuits {
		if c.role != RoleSource || c.state.Finished() || c.deadline.IsZero() {
			continue
		}
		switch c.state {
		case StateRequested, StateOpenUncommitted, StateOpenCommitted:
		default:
			continue
		}
		if now.Before(c.deadline) {
			continue
		}
		cause := error(ErrOpenTimeout)
		if c.committed {
			cause = fmt.Errorf("%w: %w", ErrOutcomeUnknown, ErrOpenTimeout)
		}
		m.failLocked(c, StateCancelSent, cause)
	}
	if len(m.requestIDs) > m.limits.MaxActive {
		m.dropUnreferencedRequestIDsLocked()
	}
	return removed
}

// signalLocked wakes every waiter of one Circuit and the Accept waiters. The
// wake channels are broadcast channels rebuilt under m.mu, so a waiter that
// missed the state change still observes it on its next loop.
func (m *Manager) signalLocked(c *Circuit) {
	if c != nil {
		close(c.woke)
		c.woke = make(chan struct{})
	}
	close(m.acceptWoke)
	m.acceptWoke = make(chan struct{})
}

// reserveRecvLocked books the shared receive-buffer charge for c on its first
// accepted payload: exactly MaxBuffer accounted bytes plus an owned array of
// exactly that capacity. Because the array is allocated once at the full
// bound, append never reallocates or doubles it and the accounted capacity
// stays stable for the whole stream.
//
// m.mu must be held, so the injected BufferBudget runs under m.mu: it must be
// non-blocking and must never call back into this Manager, or the manager lock
// would be re-entered. It is a no-op when no port is injected (the legacy
// component-local append path) and after the first reservation for a Circuit.

// recvUnreadLocked reports the unread byte count of a Circuit's receive buffer.
func recvUnreadLocked(c *Circuit) int { return len(c.recvBuf) - c.recvOff }

// compactRecvLocked folds the read cursor back into the buffer by shifting the
// unread tail to the front. It runs only when a write needs the headroom, so the
// shift is amortized over a full buffer's worth of appends instead of happening
// on every Read.
func compactRecvLocked(c *Circuit) {
	if c.recvOff == 0 {
		return
	}
	if c.recvOff >= len(c.recvBuf) {
		c.recvBuf = c.recvBuf[:0]
		c.recvOff = 0
		return
	}
	n := copy(c.recvBuf, c.recvBuf[c.recvOff:])
	c.recvBuf = c.recvBuf[:n]
	c.recvOff = 0
}

func (m *Manager) reserveRecvLocked(c *Circuit) error {
	if m.budget == nil || c.recvRes != nil || c.recvBuf != nil {
		return nil
	}
	// Reserve and allocate one chunk, not the whole ceiling: the buffer is a
	// ceiling that grows with actual traffic, so an idle or small flow does not
	// hold a MaxBuffer-sized reservation that other flows cannot use.
	res, err := m.budget.ReserveData(uint64(recvInitialChunk))
	if err != nil {
		return err
	}
	if res == nil {
		return fmt.Errorf("%w: buffer budget returned a nil reservation", ErrInvalidConfig)
	}
	c.recvRes = res
	c.recvReserved = recvInitialChunk
	c.recvBuf = make([]byte, 0, recvInitialChunk)
	return nil
}

// growRecvLocked reserves capacity for a receive buffer that needs to hold at
// least want bytes, doubling up to the MaxBuffer ceiling and charging the data
// pool only for the additional capacity. The reservation and the backing array
// therefore track real traffic instead of the ceiling.
func (m *Manager) growRecvLocked(c *Circuit, want int) error {
	if want <= cap(c.recvBuf) {
		return nil
	}
	target := cap(c.recvBuf) * 2
	if target < recvInitialChunk {
		target = recvInitialChunk
	}
	if target < want {
		target = want
	}
	if target > MaxBuffer {
		target = MaxBuffer
	}
	if target < want {
		return fmt.Errorf("receive buffer needs %d bytes, ceiling is %d", want, MaxBuffer)
	}
	if m.budget == nil {
		grown := make([]byte, len(c.recvBuf), target)
		copy(grown, c.recvBuf)
		c.recvBuf = grown
		return nil
	}
	add := target - c.recvReserved
	if add > 0 {
		res, err := m.budget.ReserveData(uint64(add))
		if err != nil {
			return err
		}
		if res == nil {
			return fmt.Errorf("%w: nil reservation", ErrInvalidConfig)
		}
		if c.recvRes == nil {
			c.recvRes = res
		} else {
			c.recvRes = combinedReservation{parts: []Reservation{c.recvRes, res}}
		}
		c.recvReserved = target
	}
	grown := make([]byte, len(c.recvBuf), target)
	copy(grown, c.recvBuf)
	c.recvBuf = grown
	return nil
}

// combinedReservation releases several reservations as one.
type combinedReservation struct {
	parts []Reservation
}

func (r combinedReservation) Release() {
	for _, part := range r.parts {
		if part != nil {
			part.Release()
		}
	}
}

// releaseRecvLocked returns c's shared charge, if any, exactly once and drops
// the owned array. It is idempotent, so every terminal and reclaim path may
// call it. m.mu must be held; Release runs under m.mu and must not re-enter
// the Manager.
func (m *Manager) releaseRecvLocked(c *Circuit) {
	if c.recvRes != nil {
		res := c.recvRes
		c.recvRes = nil
		res.Release()
	}
	c.recvBuf = nil
}

// retireRecvLocked is the terminal-transition counterpart of
// releaseRecvLocked. While accepted bytes are still unread the owned array and
// its shared charge are kept, so a reader can still drain the prefix the peer's
// DATA frames already delivered; dropping them here would silently truncate the
// reliable byte stream at a RESET or failure. Once the reader drains the last
// byte, readData releases the charge. A reader that never returns is bounded by
// the terminal TTL reaper and by Manager.Close, which call releaseRecvLocked
// directly because no later read can succeed.
func (m *Manager) retireRecvLocked(c *Circuit) {
	if recvUnreadLocked(c) > 0 {
		return
	}
	m.releaseRecvLocked(c)
}

// failLocked moves a Circuit to a terminal state. The first terminal cause
// wins: a later failure never overwrites the reason the application already
// observed.
func (m *Manager) failLocked(c *Circuit, state State, cause error) {
	if c.state.Finished() {
		return
	}
	c.state = state
	c.cause = cause
	m.retireRecvLocked(c)
	c.queued = false
	c.terminalAt = m.now()
	m.signalLocked(c)
}

// protect returns the protected body of one payload for a session direction.
func (m *Manager) protect(ref SessionRef, dir Direction, plaintext []byte) ([]byte, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	body, err := m.crypto.ProtectPayload(ref, dir, plaintext)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: crypto provider returned an empty body", ErrInvalidConfig)
	}
	return body, nil
}

// submitFlowControl is submit for receive-side credit feedback. It carries the
// FlowControl marker so the egress path can exempt it from the per-Link control
// budget, which is sized for open/ready/reset traffic rather than for the one
// update a full window requires.
func (m *Manager) submitFlowControl(ctx context.Context, ref SessionRef, dir Direction, dest NodeID, kind MessageKind, plaintext []byte) error {
	body, err := m.protect(ref, dir, plaintext)
	if err != nil {
		return err
	}
	sub := Submission{Dest: dest, Session: ref, Direction: dir, Kind: kind, FlowControl: true, Body: body, PlainLen: len(plaintext)}
	if err := m.egress.Send(ctx, sub); err != nil {
		return fmt.Errorf("%w: %w", ErrSessionLost, err)
	}
	return nil
}

// submit protects and sends one payload. It never runs while m.mu is held.
func (m *Manager) submit(ctx context.Context, ref SessionRef, dir Direction, dest NodeID, kind MessageKind, plaintext []byte) error {
	body, err := m.protect(ref, dir, plaintext)
	if err != nil {
		return err
	}
	sub := Submission{Dest: dest, Session: ref, Direction: dir, Kind: kind, Body: body, PlainLen: len(plaintext)}
	if err := m.egress.Send(ctx, sub); err != nil {
		return fmt.Errorf("%w: %w", ErrSessionLost, err)
	}
	return nil
}

// unsentBoundary reports whether an admission error proves that no frame was
// handed to a LinkWriter: the injected placeholders never submit anything, so
// such a failure is known-local rather than an ambiguous outcome.
func unsentBoundary(err error) bool {
	return errors.Is(err, ErrEgressUnavailable) || errors.Is(err, ErrCryptoUnavailable)
}

// admitOpen runs the synchronous all-or-none CIRCUIT_OPEN admission.
func (m *Manager) admitOpen(ctx context.Context, c *Circuit, ref SessionRef, dir Direction, dest NodeID, plaintext []byte) (Admission, error) {
	body, err := m.protect(ref, dir, plaintext)
	if err != nil {
		return 0, err
	}
	sub := Submission{Dest: dest, Session: ref, Direction: dir, Kind: KindControlRPC, Body: body, PlainLen: len(plaintext)}
	adm, err := m.egress.AdmitOpen(ctx, sub)
	if err != nil {
		return 0, err
	}
	if adm != AdmissionCommitted && adm != AdmissionRefused {
		return 0, fmt.Errorf("%w: admission result %d", ErrInvalidConfig, uint8(adm))
	}
	_ = c
	return adm, nil
}

// Open runs one local Dial: it validates the request, reserves the active key
// and the pre-READY slot, submits candidates in order while the Open is
// uncommitted, and blocks until the Circuit reaches Ready, fails terminally, or
// the context or the total budget expires.
//
// A definitive LinkWriter refusal tries the next candidate with a higher
// attempt and a fresh request_id inside the same budget. An ambiguous admission
// result, a commit, or a Link/Session failure never switches candidate: after
// EgressCommitted the attempt is fixed and the only allowed retry is the same
// attempt/request_id/content on the same usable Session, which the wiring can
// request through the returned handle's attempt metadata.
//
// On context/budget expiry before commit the Dial is canceled with
// STREAM_RESET(CANCELED) and the context/timeout error is returned. After commit
// the same cancel is submitted best-effort but ErrOutcomeUnknown is returned,
// because the target may already have created the stream.
func (m *Manager) Open(ctx context.Context, req OpenRequest) (*Circuit, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.TargetNodeID.IsZero() {
		return nil, fmt.Errorf("%w: empty target node", ErrInvalidKey)
	}
	if req.TargetPort == 0 {
		return nil, fmt.Errorf("%w: target port 0", ErrInvalidPort)
	}
	if len(req.Candidates) == 0 {
		return nil, ErrNoCandidates
	}
	if len(req.Candidates) > MaxCandidates {
		return nil, fmt.Errorf("%w: %d candidates", ErrInvalidCandidate, len(req.Candidates))
	}
	candidates := make([]Candidate, len(req.Candidates))
	copy(candidates, req.Candidates)
	for i, cand := range candidates {
		if err := cand.Validate(); err != nil {
			return nil, fmt.Errorf("candidate %d: %w", i, err)
		}
	}
	if req.InitialWindow != 0 && req.InitialWindow != InitialWindow {
		return nil, fmt.Errorf("%w: %d", ErrInvalidWindow, req.InitialWindow)
	}
	budget := req.Budget
	if budget == 0 {
		budget = m.limits.MaxOpenBudget
	}
	if budget < 0 || budget > m.limits.MaxOpenBudget {
		return nil, fmt.Errorf("%w: %s above %s", ErrInvalidBudget, budget, m.limits.MaxOpenBudget)
	}

	now := m.now()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrClosed
	}
	m.reapLocked(now)
	key, err := m.newKeyLocked(req.CircuitID)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	peer := peerKey{contextID: m.contextID, nodeID: req.TargetNodeID}
	if m.fencedLocked(peer, now) {
		m.counters.Fenced++
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: peer %s admission fenced", ErrResource, req.TargetNodeID)
	}
	if m.preReadyCountLocked(peer) >= m.limits.MaxPreReadyPerPeer {
		m.setFenceLocked(peer, now)
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: per-peer pre-READY pool full", ErrResource)
	}
	if m.activeCountLocked() >= m.limits.MaxActive {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: active circuit ceiling %d", ErrResource, m.limits.MaxActive)
	}
	if len(m.circuits) >= m.limits.MaxActive+m.limits.MaxTombstones {
		m.reapLocked(now)
		if len(m.circuits) >= m.limits.MaxActive+m.limits.MaxTombstones {
			m.mu.Unlock()
			return nil, fmt.Errorf("%w: circuit record table full", ErrResource)
		}
	}
	c := &Circuit{
		mgr:           m,
		key:           key,
		role:          RoleSource,
		peer:          peer,
		targetNode:    req.TargetNodeID,
		targetPort:    req.TargetPort,
		created:       now,
		deadline:      now.Add(budget),
		candidates:    candidates,
		initialWindow: InitialWindow,
		state:         StateRequested,
		// The source sends too: an upload is exactly this side pushing data. Leaving
		// cwnd at zero disabled congestion control entirely for that direction,
		// because the send path only bounds in-flight bytes when cwnd is non-zero.
		// The two directions then behaved differently: target-to-source traffic was
		// windowed while source-to-target was not.
		cwnd:       m.initialCwndFor(req.TargetNodeID),
		recvWindow: InitialWindow,
		woke:       make(chan struct{}),
	}
	m.circuits[key] = c
	m.counters.Opens++
	m.mu.Unlock()

	// sessionDead counts candidates skipped because their Session is locally
	// terminal; deadRef is the last such reference.
	sessionDead := 0
	var deadRef SessionRef
	for i := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, m.abortDial(c, err)
		}
		cand := candidates[i]
		c.ioMu.Lock()
		m.mu.Lock()
		if c.state.Finished() {
			cause := c.cause
			m.mu.Unlock()
			c.ioMu.Unlock()
			return nil, cause
		}
		if m.sessionFailedLocked(cand.Session, now) {
			// FailSession marked this Session terminal: it cannot carry a frame,
			// so the candidate is skipped exactly like a definitive refusal,
			// without consuming a request_id. FailSession publishes the marker
			// under m.mu before it scans the table, so a record whose Session is
			// attached below can never be published after that scan.
			sessionDead++
			deadRef = cand.Session
			m.mu.Unlock()
			c.ioMu.Unlock()
			continue
		}
		if m.sessionFencedLocked(now) {
			// The manager-wide session fence was armed (the terminal SessionRef
			// registry overflowed) while this Dial was being admitted. This is
			// local resource exhaustion, not this Session's loss, so the Dial is
			// failed with ErrResource rather than mislabelled ErrSessionLost.
			m.counters.Fenced++
			m.failLocked(c, StateFailed, fmt.Errorf("%w: session admission fenced", ErrResource))
			cause := c.cause
			m.mu.Unlock()
			c.ioMu.Unlock()
			return nil, cause
		}
		requestID, err := m.nextRequestIDLocked(cand.Session)
		if err != nil {
			m.mu.Unlock()
			c.ioMu.Unlock()
			m.mu.Lock()
			m.failLocked(c, StateFailed, err)
			m.mu.Unlock()
			return nil, err
		}
		attempt := uint32(i)
		c.state = StateOpenUncommitted
		c.attempt = attempt
		c.requestID = requestID
		c.candidate = cand
		c.session = cand.Session
		c.committed = false
		msg := OpenMessage{
			FromNodeID:          m.localNodeID,
			CircuitID:           key.CircuitID,
			Attempt:             attempt,
			TargetPort:          req.TargetPort,
			PathID:              cand.PathID,
			PathGeneration:      cand.PathGeneration,
			RouteViewVersion:    cand.RouteViewVersion,
			PathDigest:          cand.PathDigest,
			SourceInitialWindow: InitialWindow,
			RequestID:           requestID,
		}
		plaintext, encErr := msg.Encode()
		if encErr != nil {
			m.failLocked(c, StateFailed, encErr)
			m.mu.Unlock()
			c.ioMu.Unlock()
			return nil, encErr
		}
		m.mu.Unlock()

		admission, admErr := m.admitOpen(ctx, c, cand.Session, DirectionSourceToTarget, req.TargetNodeID, plaintext)

		m.mu.Lock()
		if c.state == StateReady {
			// An early CIRCUIT_READY arrived while the admission call was in
			// flight: the frame was delivered, so the stream is usable.
			m.mu.Unlock()
			c.ioMu.Unlock()
			return c, nil
		}
		if c.state.Finished() {
			cause := c.cause
			m.mu.Unlock()
			c.ioMu.Unlock()
			return nil, cause
		}
		switch {
		case admErr != nil:
			if unsentBoundary(admErr) {
				// The injected placeholder (or a provider reporting its own
				// unavailability) never handed a frame to a LinkWriter, so the
				// frame provably did not leave this node: a known local failure
				// rather than an ambiguous outcome.
				m.failLocked(c, StateFailed, admErr)
				m.mu.Unlock()
				c.ioMu.Unlock()
				return nil, admErr
			}
			cause := fmt.Errorf("%w: %w", ErrOutcomeUnknown, admErr)
			m.failLocked(c, StateFailed, cause)
			m.mu.Unlock()
			c.ioMu.Unlock()
			return nil, cause
		case admission == AdmissionCommitted:
			c.committed = true
			c.state = StateOpenCommitted
			m.mu.Unlock()
			c.ioMu.Unlock()
			return m.waitReady(ctx, c)
		default:
			// Definitive all-or-none refusal: the frame will never be sent, so
			// the same budget may try the next candidate with a higher attempt.
			c.state = StateOpenUncommitted
			m.mu.Unlock()
			c.ioMu.Unlock()
		}
	}

	m.mu.Lock()
	if !c.state.Finished() {
		cause := fmt.Errorf("%w: all %d candidates refused", ErrNoRoute, len(candidates))
		if sessionDead == len(candidates) {
			// Every candidate was carried by a locally terminal Session, so the
			// Dial reports the Session failure rather than a route refusal. The
			// error carries ErrSessionRefFailed too, so a caller can tell a
			// failed SessionRef apart from an Egress I/O failure.
			cause = fmt.Errorf("%w: %w: %s is terminal", ErrSessionLost, ErrSessionRefFailed, deadRef)
		}
		m.failLocked(c, StateFailed, cause)
	}
	cause := c.cause
	m.mu.Unlock()
	return nil, cause
}

// RetransmitOpen resubmits the byte-identical CIRCUIT_OPEN of the current
// committed attempt on the same Session: same attempt, same request_id, same
// candidate and content. It is the only operation allowed after
// EgressCommitted, and it never changes the attempt. Each resubmission is a new
// frame (the injected Egress/Session owns MessageNumber allocation).
//
// A definitive refusal means the Session is no longer usable, so the Dial ends
// with ErrOutcomeUnknown: the target may already have created the stream and no
// higher attempt may be used.
func (m *Manager) RetransmitOpen(ctx context.Context, key Key) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidConfig)
	}
	c, err := m.Lookup(key)
	if err != nil {
		return err
	}
	c.ioMu.Lock()
	defer c.ioMu.Unlock()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if c.role != RoleSource {
		m.mu.Unlock()
		return fmt.Errorf("%w: retransmit requires the Dial side", ErrState)
	}
	if c.state != StateOpenCommitted {
		state := c.state
		m.mu.Unlock()
		return fmt.Errorf("%w: retransmit in state %s", ErrState, state)
	}
	msg := OpenMessage{
		FromNodeID:          m.localNodeID,
		CircuitID:           c.key.CircuitID,
		Attempt:             c.attempt,
		TargetPort:          c.targetPort,
		PathID:              c.candidate.PathID,
		PathGeneration:      c.candidate.PathGeneration,
		RouteViewVersion:    c.candidate.RouteViewVersion,
		PathDigest:          c.candidate.PathDigest,
		SourceInitialWindow: InitialWindow,
		RequestID:           c.requestID,
	}
	plaintext, encErr := msg.Encode()
	ref, dest := c.session, c.targetNode
	m.mu.Unlock()
	if encErr != nil {
		return encErr
	}
	admission, admErr := m.admitOpen(ctx, c, ref, DirectionSourceToTarget, dest, plaintext)
	if admErr != nil {
		if unsentBoundary(admErr) {
			m.mu.Lock()
			m.failLocked(c, StateFailed, admErr)
			m.mu.Unlock()
			return admErr
		}
		cause := fmt.Errorf("%w: %w", ErrOutcomeUnknown, admErr)
		m.mu.Lock()
		m.failLocked(c, StateFailed, cause)
		m.mu.Unlock()
		return cause
	}
	if admission == AdmissionRefused {
		cause := fmt.Errorf("%w: retransmission refused on %s", ErrOutcomeUnknown, ref)
		m.mu.Lock()
		m.failLocked(c, StateFailed, cause)
		m.mu.Unlock()
		return cause
	}
	return nil
}

// waitReady blocks until the Circuit is Ready, fails, or the context/budget
// expires.
func (m *Manager) waitReady(ctx context.Context, c *Circuit) (*Circuit, error) {
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, ErrClosed
		}
		switch {
		case c.state == StateReady:
			m.mu.Unlock()
			return c, nil
		case c.state.Finished() || c.state == StateBothClosed:
			cause := c.cause
			m.mu.Unlock()
			return nil, cause
		}
		woke := c.woke
		remaining := c.deadline.Sub(m.now())
		m.mu.Unlock()
		if remaining <= 0 {
			return nil, m.abortDial(c, ErrOpenTimeout)
		}
		timer := time.NewTimer(remaining)
		select {
		case <-woke:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return nil, m.abortDial(c, ctx.Err())
		case <-timer.C:
			return nil, m.abortDial(c, ErrOpenTimeout)
		}
	}
}

// abortDial cancels a Dial that did not reach Ready and reports the cause. After
// EgressCommitted the result is OutcomeUnknown because the target may already
// have created the stream.
func (m *Manager) abortDial(c *Circuit, cause error) error {
	m.mu.Lock()
	committed := c.committed
	m.mu.Unlock()
	report := cause
	if committed {
		report = fmt.Errorf("%w: %w", ErrOutcomeUnknown, cause)
	}
	_ = m.resetCircuit(c, ResetReasonCanceled, report, nil)
	return report
}

// HandleOpen processes one inbound CIRCUIT_OPEN from the authenticated envelope
// source. It either creates the target-side stream, re-sends the byte-identical
// cached CIRCUIT_READY for a same-attempt retransmission, or refuses the Open
// with REFUSED(CANCELED), REFUSED(RESOURCE) or EXPIRED(OUTCOME_UNKNOWN). A
// mismatching attempt for an existing OpenRecord never creates a second stream.
//
// The CIRCUIT_READY response is submitted through the injected Egress before
// this call returns, so a wiring owner does not have to frame it.
func (m *Manager) HandleOpen(msg OpenMessage) (OpenResult, error) {
	if msg.FromNodeID.IsZero() {
		return OpenResult{}, fmt.Errorf("%w: empty source node", ErrInvalidKey)
	}
	if msg.FromNodeID == m.localNodeID {
		return OpenResult{}, fmt.Errorf("%w: open claims the local node as source", ErrInvalidKey)
	}
	if err := msg.Session.Validate(); err != nil {
		return OpenResult{}, err
	}
	if err := msg.validate(); err != nil {
		return OpenResult{}, err
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return OpenResult{}, ErrClosed
	}
	now := m.now()
	m.reapLocked(now)
	key := Key{ContextID: m.contextID, SrcNodeID: msg.FromNodeID, CircuitID: msg.CircuitID}
	peer := peerKey{contextID: m.contextID, nodeID: msg.FromNodeID}

	if m.sessionFailedLocked(msg.Session, now) {
		// FailSession marked this Session terminal: the Open cannot be admitted,
		// and no response may be submitted over the aborted Session (not even a
		// REFUSED CIRCUIT_READY). The record is not created.
		//
		// The error wraps ErrSessionRefFailed as well as ErrSessionLost: a frame
		// handler classifies only the former as frame-local, so this refusal
		// cannot be confused with an Egress I/O failure that must tear the Link
		// down.
		m.mu.Unlock()
		return OpenResult{Key: key}, fmt.Errorf("%w: %w: %s", ErrSessionLost, ErrSessionRefFailed, msg.Session)
	}

	if existing := m.circuits[key]; existing != nil {
		switch {
		case existing.state.Finished():
			m.counters.Refused++
			m.mu.Unlock()
			return m.sendReady(msg, ReadyMessage{
				CircuitID: msg.CircuitID,
				Attempt:   msg.Attempt,
				RequestID: msg.RequestID,
				Status:    StatusRefused,
				ErrorCode: ReadyErrorCanceled,
			})
		case existing.cachedOpen != nil && *existing.cachedOpen == msg && existing.attempt == msg.Attempt:
			payload := append([]byte(nil), existing.cachedReady...)
			ref, dir := existing.session, existing.outboundDirection()
			m.mu.Unlock()
			if err := m.submit(context.Background(), ref, dir, msg.FromNodeID, KindControlRPC, payload); err != nil {
				return OpenResult{Key: key, Status: StatusReady, Duplicate: true}, err
			}
			return OpenResult{Key: key, Status: StatusReady, Duplicate: true}, nil
		default:
			m.counters.Refused++
			m.mu.Unlock()
			return m.sendReady(msg, ReadyMessage{
				CircuitID: msg.CircuitID,
				Attempt:   msg.Attempt,
				RequestID: msg.RequestID,
				Status:    StatusExpired,
				ErrorCode: ReadyErrorOutcomeUnknown,
			})
		}
	}
	if m.tombstonedLocked(key, now) {
		m.counters.Refused++
		m.mu.Unlock()
		return m.sendReady(msg, ReadyMessage{
			CircuitID: msg.CircuitID,
			Attempt:   msg.Attempt,
			RequestID: msg.RequestID,
			Status:    StatusRefused,
			ErrorCode: ReadyErrorCanceled,
		})
	}
	if m.fencedLocked(peer, now) {
		m.counters.Fenced++
		m.counters.Refused++
		m.mu.Unlock()
		return m.sendReady(msg, ReadyMessage{
			CircuitID: msg.CircuitID,
			Attempt:   msg.Attempt,
			RequestID: msg.RequestID,
			Status:    StatusRefused,
			ErrorCode: ReadyErrorResource,
		})
	}
	if m.sessionFencedLocked(now) {
		// The terminal SessionRef registry overflowed and armed the
		// manager-wide session fence. For this healthy Session that is ordinary
		// local resource exhaustion, so the Open is refused with
		// REFUSED(RESOURCE) through the normal path: it is not a lost Session
		// and must never be reported as ErrSessionLost, which would make the
		// frame handler tear the shared Link down.
		m.counters.Fenced++
		m.counters.Refused++
		m.mu.Unlock()
		return m.sendReady(msg, ReadyMessage{
			CircuitID: msg.CircuitID,
			Attempt:   msg.Attempt,
			RequestID: msg.RequestID,
			Status:    StatusRefused,
			ErrorCode: ReadyErrorResource,
		})
	}
	if m.preReadyCountLocked(peer) >= m.limits.MaxPreReadyPerPeer {
		m.setFenceLocked(peer, now)
		m.counters.Fenced++
		m.counters.Refused++
		m.mu.Unlock()
		return m.sendReady(msg, ReadyMessage{
			CircuitID: msg.CircuitID,
			Attempt:   msg.Attempt,
			RequestID: msg.RequestID,
			Status:    StatusRefused,
			ErrorCode: ReadyErrorResource,
		})
	}
	if m.activeCountLocked() >= m.limits.MaxActive {
		m.counters.Refused++
		m.mu.Unlock()
		return m.sendReady(msg, ReadyMessage{
			CircuitID: msg.CircuitID,
			Attempt:   msg.Attempt,
			RequestID: msg.RequestID,
			Status:    StatusRefused,
			ErrorCode: ReadyErrorResource,
		})
	}
	if len(m.circuits) >= m.limits.MaxActive+m.limits.MaxTombstones {
		m.reapLocked(now)
		if len(m.circuits) >= m.limits.MaxActive+m.limits.MaxTombstones {
			m.counters.Refused++
			m.mu.Unlock()
			return m.sendReady(msg, ReadyMessage{
				CircuitID: msg.CircuitID,
				Attempt:   msg.Attempt,
				RequestID: msg.RequestID,
				Status:    StatusRefused,
				ErrorCode: ReadyErrorResource,
			})
		}
	}

	response := ReadyMessage{
		CircuitID:     msg.CircuitID,
		Attempt:       msg.Attempt,
		RequestID:     msg.RequestID,
		Status:        StatusReady,
		InitialWindow: InitialWindow,
	}
	payload, err := response.Encode()
	if err != nil {
		m.mu.Unlock()
		return OpenResult{}, err
	}
	cached := msg
	c := &Circuit{
		mgr:           m,
		key:           key,
		role:          RoleTarget,
		peer:          peer,
		targetNode:    msg.FromNodeID,
		targetPort:    msg.TargetPort,
		created:       now,
		candidates:    []Candidate{{PathID: msg.PathID, PathGeneration: msg.PathGeneration, RouteViewVersion: msg.RouteViewVersion, PathDigest: msg.PathDigest, Session: msg.Session}},
		initialWindow: InitialWindow,
		state:         StateOpenCommitted,
		attempt:       msg.Attempt,
		requestID:     msg.RequestID,
		candidate:     Candidate{PathID: msg.PathID, PathGeneration: msg.PathGeneration, RouteViewVersion: msg.RouteViewVersion, PathDigest: msg.PathDigest, Session: msg.Session},
		session:       msg.Session,
		sendWindow:    msg.SourceInitialWindow,
		cwnd:          m.initialCwndFor(msg.FromNodeID),
		recvWindow:    InitialWindow,
		cachedOpen:    &cached,
		cachedReady:   append([]byte(nil), payload...),
		woke:          make(chan struct{}),
	}
	m.circuits[key] = c
	m.mu.Unlock()

	if err := m.submit(context.Background(), msg.Session, DirectionTargetToSource, msg.FromNodeID, KindControlRPC, payload); err != nil {
		m.mu.Lock()
		m.failLocked(c, StateFailed, err)
		m.mu.Unlock()
		return OpenResult{Key: key, Status: StatusReady}, err
	}

	m.mu.Lock()
	if m.closed || c.state.Finished() {
		// The stream was canceled or the manager closed while the READY was in
		// flight; the response is already gone and the caller must not Accept.
		m.mu.Unlock()
		return OpenResult{Key: key, Status: StatusReady}, nil
	}
	c.state = StateReady
	c.queued = true
	m.pending = append(m.pending, c)
	m.signalLocked(c)
	m.mu.Unlock()
	return OpenResult{Key: key, Status: StatusReady, Created: true}, nil
}

// sendReady submits a refusal/expiry CIRCUIT_READY response.
func (m *Manager) sendReady(msg OpenMessage, response ReadyMessage) (OpenResult, error) {
	payload, err := response.Encode()
	if err != nil {
		return OpenResult{Key: Key{ContextID: m.contextID, SrcNodeID: msg.FromNodeID, CircuitID: msg.CircuitID}, Status: response.Status}, err
	}
	key := Key{ContextID: m.contextID, SrcNodeID: msg.FromNodeID, CircuitID: msg.CircuitID}
	if err := m.submit(context.Background(), msg.Session, DirectionTargetToSource, msg.FromNodeID, KindControlRPC, payload); err != nil {
		return OpenResult{Key: key, Status: response.Status}, err
	}
	return OpenResult{Key: key, Status: response.Status}, nil
}

// Accept returns the oldest target-side stream waiting for the application. The
// pending-delivery queue and a CANCELED reset race on the same manager lock:
// whichever wins, the other observes a deleted or already-delivered stream.
func (m *Manager) Accept(ctx context.Context) (*Circuit, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidConfig)
	}
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, ErrClosed
		}
		for len(m.pending) > 0 {
			c := m.pending[0]
			m.pending = m.pending[1:]
			if !c.queued || c.accepted || c.state != StateReady {
				continue
			}
			c.accepted = true
			m.counters.Accepts++
			m.mu.Unlock()
			return c, nil
		}
		woke := m.acceptWoke
		m.mu.Unlock()
		select {
		case <-woke:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// HandleReady processes one inbound CIRCUIT_READY on the source side. A READY
// for another CircuitID, another peer, a stale attempt/request_id, or a Circuit
// that is already terminal/Ready is ignored, not an error: it is a late
// response that must not change local state.
func (m *Manager) HandleReady(msg ReadyMessage) error {
	if err := msg.validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	now := m.now()
	m.reapLocked(now)
	c := m.circuits[m.LocalKey(msg.CircuitID)]
	if c == nil || c.role != RoleSource {
		m.counters.LateReady++
		return nil
	}
	if !msg.FromNodeID.IsZero() && !c.targetNode.IsZero() && msg.FromNodeID != c.targetNode {
		m.counters.LateReady++
		return nil
	}
	switch c.state {
	case StateReady:
		// Duplicate READY: idempotent. A successful duplicate must not regress
		// the credit the peer already granted.
		if msg.Status == StatusReady && msg.Attempt == c.attempt && msg.RequestID == c.requestID && msg.InitialWindow == InitialWindow {
			return nil
		}
		m.counters.LateReady++
		return nil
	case StateOpenUncommitted, StateOpenCommitted:
	default:
		m.counters.LateReady++
		return nil
	}
	if msg.Attempt != c.attempt || msg.RequestID != c.requestID {
		m.counters.LateReady++
		return nil
	}
	if msg.Status == StatusReady {
		c.state = StateReady
		c.sendWindow = msg.InitialWindow
		c.cause = nil
		m.signalLocked(c)
		return nil
	}
	m.counters.Refused++
	m.failLocked(c, StateFailed, msg.ErrorCode.Err())
	return nil
}

// HandleReset processes one inbound STREAM_RESET. CANCELED is terminal for the
// whole (ContextID, SrcNodeID, CircuitID) across every attempt and creates the
// 30-second cancel tombstone even when no OpenRecord exists. An unknown reason
// terminates the stream and is reported as ErrProtocol.
func (m *Manager) HandleReset(msg ResetMessage) error {
	if msg.CircuitID.IsZero() {
		return fmt.Errorf("%w: zero circuit id", ErrMalformedMessage)
	}
	known := msg.Reason.Valid()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	now := m.now()
	m.reapLocked(now)
	c := m.lookupInboundLocked(msg.FromNodeID, msg.CircuitID)
	if !known {
		if c != nil {
			c.resetRecv = true
			m.counters.ResetsReceived++
			m.failLocked(c, StateClosed, ErrProtocol)
		}
		m.mu.Unlock()
		return fmt.Errorf("%w: reset reason 0x%08x", ErrProtocol, uint32(msg.Reason))
	}
	m.counters.ResetsReceived++
	if msg.Reason == ResetReasonCanceled {
		key := Key{ContextID: m.contextID, SrcNodeID: msg.FromNodeID, CircuitID: msg.CircuitID}
		if c == nil {
			c = m.circuits[key]
		}
		if c == nil {
			stub := &Circuit{mgr: m, key: key, role: RoleTarget, peer: peerKey{contextID: m.contextID, nodeID: msg.FromNodeID}}
			m.recordTombstoneLocked(stub, now)
		} else {
			m.recordTombstoneLocked(c, now)
		}
	}
	if c != nil {
		c.resetRecv = true
		m.failLocked(c, StateClosed, msg.Reason.Err())
	}
	m.mu.Unlock()
	return nil
}

// lookupInboundLocked resolves the record an inbound frame belongs to. Frames
// from the target resolve to the local source-side record; frames from a
// Circuit source resolve to the target-side record keyed by that source.
func (m *Manager) lookupInboundLocked(from NodeID, id CircuitID) *Circuit {
	if from.IsZero() || from == m.localNodeID {
		return nil
	}
	if c := m.circuits[m.LocalKey(id)]; c != nil {
		if c.targetNode.IsZero() || c.targetNode == from {
			return c
		}
	}
	return m.circuits[Key{ContextID: m.contextID, SrcNodeID: from, CircuitID: id}]
}

// HandleWindowUpdate applies peer credit on the send side. A value at or below
// the current credit is an old window and is ignored. Credit beyond this side's
// send frontier plus the frozen 256 KiB cap is a protocol violation: the stream
// is terminated with STREAM_RESET(PROTOCOL) and ErrProtocol is returned.
func (m *Manager) HandleWindowUpdate(msg WindowUpdateMessage) error {
	if msg.CircuitID.IsZero() {
		return fmt.Errorf("%w: zero circuit id", ErrMalformedMessage)
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	now := m.now()
	m.reapLocked(now)
	c := m.lookupInboundLocked(msg.FromNodeID, msg.CircuitID)
	if c == nil {
		m.mu.Unlock()
		return nil
	}
	if c.state.Finished() {
		m.mu.Unlock()
		return nil
	}
	if msg.Window <= c.sendWindow {
		// Old window value: ignored, never regresses credit.
		m.mu.Unlock()
		return nil
	}
	// A WINDOW_UPDATE means the peer drained bytes, which is the only delivery
	// signal this transport has. Grow cwnd by the newly acknowledged amount, capped
	// so one acknowledgement cannot jump the window arbitrarily.
	// Round-trip sample: the peer's credit names bytes it has consumed, so once it
	// reaches the offset marked at send time, that mark's age is one round trip.
	if !c.sendMarkedAt.IsZero() && msg.Window >= c.sendMarkedOffset {
		if sample := m.now().Sub(c.sendMarkedAt); sample > 0 {
			if !c.rttValid {
				c.srtt = sample
				c.rttValid = true
			} else {
				// RFC 6298 style smoothing: mostly the established estimate, partly
				// the newest sample, so one outlier does not resize the frontier.
				c.srtt = (c.srtt*7 + sample) / 8
			}
		}
		c.sendMarkedAt = time.Time{}
	}
	if acked := msg.Window - c.sendWindow; acked > 0 {
		if c.ackedSince.IsZero() {
			c.ackedSince = m.now()
		} else {
			c.ackedSpan = m.now().Sub(c.ackedSince)
		}
		if c.cwnd < cwndMax {
			// Slow start doubles the window per acknowledged window; congestion
			// avoidance adds roughly one segment per window. The previous version
			// added `acked` in both phases, which is only "+1 per ack" and never
			// doubles, so the window crept up linearly and short transfers never
			// reached the ceiling.
			grow := acked
			if c.cwnd >= cwndSlowStartLimit {
				grow = acked / c.cwnd
				if grow == 0 {
					grow = 1
				}
			}
			if limit := c.cwndCeiling(); c.cwnd+grow > limit {
				grow = limit - c.cwnd
			}
			if grow > 0 {
				c.cwnd += grow
			}
		}
		if msg.Window > c.cwndAcked {
			c.cwndAcked = msg.Window
		}
		// Remember what this peer's path proved it can carry, so the next circuit
		// to the same peer starts where this one got to instead of ramping again.
		if c.cwnd > m.peerCwnd[c.peerNode()] {
			m.peerCwnd[c.peerNode()] = c.cwnd
		}
	}
	if c.sendNext > math.MaxUint64-MaxCreditAhead || msg.Window > c.sendNext+MaxCreditAhead {
		m.mu.Unlock()
		_ = m.resetCircuit(c, ResetReasonProtocol, ErrProtocol, nil)
		return fmt.Errorf("%w: window %d beyond send frontier %d + %d", ErrProtocol, msg.Window, c.sendNext, MaxCreditAhead)
	}
	c.sendWindow = msg.Window
	m.signalLocked(c)
	m.mu.Unlock()
	return nil
}

// HandleStreamData processes one inbound STREAM_DATA frame (DATA or FIN) and
// returns the number of newly delivered bytes. In-order DATA is accepted,
// complete duplicates are discarded and counted, and a partial overlap or a
// forward gap is answered with STREAM_RESET(PROTOCOL). Credit beyond the
// advertised window or beyond the 64 KiB buffer is answered with
// STREAM_RESET(RESOURCE). Data for an unknown or finished Circuit is ignored.
func (m *Manager) HandleStreamData(msg StreamDataMessage) (int, error) {
	if err := msg.validate(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, ErrClosed
	}
	now := m.now()
	m.reapLocked(now)
	c := m.lookupInboundLocked(msg.FromNodeID, msg.CircuitID)
	if c == nil || !c.state.readable() {
		m.counters.IgnoredData++
		m.mu.Unlock()
		return 0, nil
	}
	next := c.recvBase + uint64(recvUnreadLocked(c))
	if msg.Flags == FlagFin {
		if msg.StreamSeq != next {
			m.mu.Unlock()
			_ = m.resetCircuit(c, ResetReasonProtocol, ErrProtocol, nil)
			return 0, fmt.Errorf("%w: FIN at %d, receive frontier %d", ErrProtocol, msg.StreamSeq, next)
		}
		if c.finRecv {
			// Duplicate FIN at the same final offset: idempotent.
			m.counters.DuplicateData++
			m.mu.Unlock()
			return 0, nil
		}
		c.finRecv = true
		switch c.state {
		case StateReady:
			c.state = StateRemoteWriteClosed
		case StateLocalWriteClosed:
			c.state = StateBothClosed
			c.terminalAt = now
		}
		m.signalLocked(c)
		m.mu.Unlock()
		return 0, nil
	}
	size := uint64(len(msg.Payload))
	if msg.StreamSeq > math.MaxUint64-size {
		m.mu.Unlock()
		_ = m.resetCircuit(c, ResetReasonProtocol, ErrProtocol, nil)
		return 0, fmt.Errorf("%w: stream_seq %d overflows with %d bytes", ErrProtocol, msg.StreamSeq, size)
	}
	if msg.StreamSeq > next {
		m.mu.Unlock()
		_ = m.resetCircuit(c, ResetReasonProtocol, ErrProtocol, nil)
		return 0, fmt.Errorf("%w: forward gap at %d, receive frontier %d", ErrProtocol, msg.StreamSeq, next)
	}
	if msg.StreamSeq+size <= next {
		m.counters.DuplicateData++
		m.mu.Unlock()
		return 0, nil
	}
	if msg.StreamSeq < next {
		m.mu.Unlock()
		_ = m.resetCircuit(c, ResetReasonProtocol, ErrProtocol, nil)
		return 0, fmt.Errorf("%w: partial overlap at %d..%d, receive frontier %d", ErrProtocol, msg.StreamSeq, msg.StreamSeq+size, next)
	}
	if c.finRecv {
		m.mu.Unlock()
		_ = m.resetCircuit(c, ResetReasonProtocol, ErrProtocol, nil)
		return 0, fmt.Errorf("%w: DATA after FIN at %d", ErrProtocol, msg.StreamSeq)
	}
	if msg.StreamSeq+size > c.recvWindow {
		m.mu.Unlock()
		_ = m.resetCircuit(c, ResetReasonResource, ErrResource, nil)
		return 0, fmt.Errorf("%w: data to %d beyond advertised window %d", ErrResource, msg.StreamSeq+size, c.recvWindow)
	}
	if recvUnreadLocked(c)+len(msg.Payload) > MaxBuffer {
		// The peer overran the credit we advertised. That is a flow-control
		// violation, but killing the Circuit punishes the whole transfer for one
		// frame, so the frame is refused and the credit is re-advertised: the peer
		// then retries within the window it was actually given.
		m.mu.Unlock()
		return 0, fmt.Errorf("%w: receive buffer %d bytes", ErrResource, recvUnreadLocked(c)+len(msg.Payload))
	}
	// Book the shared charge before the first accepted byte becomes owned. A
	// refusal is local to this Circuit: it is reset with ErrResource and no
	// other stream, the Manager or its Link is touched.
	if err := m.reserveRecvLocked(c); err != nil {
		m.mu.Unlock()
		_ = m.resetCircuit(c, ResetReasonResource, ErrResource, nil)
		return 0, fmt.Errorf("%w: receive buffer reservation: %v", ErrResource, err)
	}
	// Fold the read cursor back only when the tail lacks the headroom, so the
	// shift is amortized over a full buffer of appends rather than per Read.
	if c.recvOff > 0 && len(c.recvBuf)+len(msg.Payload) > cap(c.recvBuf) {
		compactRecvLocked(c)
		if err := m.growRecvLocked(c, recvUnreadLocked(c)+len(msg.Payload)); err != nil {
			m.mu.Unlock()
			_ = m.resetCircuit(c, ResetReasonResource, ErrResource, nil)
			return 0, fmt.Errorf("%w: receive buffer growth: %v", ErrResource, err)
		}
	} else if len(c.recvBuf)+len(msg.Payload) > cap(c.recvBuf) {
		if err := m.growRecvLocked(c, len(c.recvBuf)+len(msg.Payload)); err != nil {
			m.mu.Unlock()
			_ = m.resetCircuit(c, ResetReasonResource, ErrResource, nil)
			return 0, fmt.Errorf("%w: receive buffer growth: %v", ErrResource, err)
		}
	}
	c.recvBuf = append(c.recvBuf, msg.Payload...)
	m.counters.BytesReceived += size
	m.signalLocked(c)
	m.mu.Unlock()
	return len(msg.Payload), nil
}

// outboundDirection returns the E2E direction of frames this side sends.
func (c *Circuit) outboundDirection() Direction {
	if c.role == RoleTarget {
		return DirectionTargetToSource
	}
	return DirectionSourceToTarget
}

// peerNode returns the envelope destination of frames this side sends.
func (c *Circuit) peerNode() NodeID {
	if c.role == RoleTarget {
		return c.key.SrcNodeID
	}
	return c.targetNode
}

// writeStateLocked reports whether new stream bytes may be submitted.
func (m *Manager) writeStateLocked(c *Circuit) error {
	if m.closed {
		return ErrClosed
	}
	switch c.state {
	case StateReady, StateRemoteWriteClosed:
		return nil
	case StateBothClosed, StateLocalWriteClosed:
		return ErrWriteClosed
	}
	if c.state.Finished() {
		if c.cause != nil {
			return c.cause
		}
		return ErrCircuitClosed
	}
	return fmt.Errorf("%w: write in state %s", ErrState, c.state)
}

// readStateLocked reports whether the receive direction may be read.
func (m *Manager) readStateLocked(c *Circuit) error {
	if m.closed {
		return ErrClosed
	}
	if c.state.readable() {
		return nil
	}
	if c.state.Finished() {
		if c.cause != nil {
			return c.cause
		}
		return ErrCircuitClosed
	}
	return fmt.Errorf("%w: read in state %s", ErrState, c.state)
}

// writeData submits stream bytes as far as the peer credit allows and blocks
// for credit otherwise. A partial write with a nil error is impossible: either
// every byte was handed to the injected Egress or the reported error explains
// why the rest was not. Nothing is buffered here, so the only per-flow buffer
// is the bounded receive buffer.
func (m *Manager) writeData(ctx context.Context, c *Circuit, p []byte) (int, error) {
	if ctx == nil {
		return 0, fmt.Errorf("%w: nil context", ErrInvalidConfig)
	}
	if len(p) == 0 {
		m.mu.Lock()
		err := m.writeStateLocked(c)
		m.mu.Unlock()
		return 0, err
	}
	written := 0
	for written < len(p) {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		c.ioMu.Lock()
		m.mu.Lock()
		if err := m.writeStateLocked(c); err != nil {
			m.mu.Unlock()
			c.ioMu.Unlock()
			return written, err
		}
		// Two independent limits: the peer's advertised credit (how much it can
		// buffer) and our congestion window (how much the path can absorb). Sending
		// is bounded by whichever is smaller. Without the second one the sender
		// fills the peer's whole receive window on the first burst, so the receiver
		// becomes a queue and a single loss costs a full window of retransmission.
		available := c.sendWindow - c.sendNext
		// cwnd bounds unacknowledged bytes. cwndAcked starts at zero and only moves
		// when the peer advertises credit it has actually consumed, so inFlight is
		// measured from the stream origin, not from the window's base.
		if c.cwnd > 0 {
			var inFlight uint64
			if c.sendNext > c.cwndAcked {
				inFlight = c.sendNext - c.cwndAcked
			}
			var room uint64
			if inFlight < c.cwnd {
				room = c.cwnd - inFlight
			}
			if room < available {
				available = room
			}
		}
		if available == 0 {
			woke := c.woke
			m.mu.Unlock()
			c.ioMu.Unlock()
			select {
			case <-woke:
			case <-ctx.Done():
				return written, ctx.Err()
			}
			continue
		}
		size := len(p) - written
		if uint64(size) > available {
			size = int(available)
		}
		if size > MaxStreamDataPayload {
			size = MaxStreamDataPayload
		}
		msg := StreamDataMessage{
			FromNodeID: m.localNodeID,
			CircuitID:  c.key.CircuitID,
			Flags:      FlagData,
			StreamSeq:  c.sendNext,
			Payload:    p[written : written+size],
		}
		plaintext, encErr := msg.Encode()
		c.sendNext += uint64(size)
		// Mark this offset's send time. A later WINDOW_UPDATE naming it gives a
		// round-trip sample from normal traffic, with no probe frames.
		c.sendMarkedAt = m.now()
		c.sendMarkedOffset = c.sendNext
		ref, dir, dest := c.session, c.outboundDirection(), c.peerNode()
		m.counters.BytesSent += uint64(size)
		m.mu.Unlock()
		if encErr != nil {
			c.ioMu.Unlock()
			return written, encErr
		}
		if err := m.submit(ctx, ref, dir, dest, KindStreamData, plaintext); err != nil {
			m.mu.Lock()
			m.failLocked(c, StateFailed, err)
			m.mu.Unlock()
			c.ioMu.Unlock()
			return written, err
		}
		c.ioMu.Unlock()
		written += size
	}
	return written, nil
}

// readData copies accepted bytes to the caller, returns io.EOF after the peer
// FIN drained the buffer, and blocks while the stream is open but empty.
//
// Accepted bytes are delivered FIFO even when the receive direction already
// became terminal (a later RESET after DATA, or a Manager.Close): a terminal
// reset must not silently truncate a prefix the peer's DATA frames already
// delivered. The buffer is drained first and only the following read reports
// the terminal cause. The read that drains the last accepted byte of a
// terminal or FIN-closed direction returns the shared receive charge exactly
// once; a reader that never returns leaves the charge to the TTL reaper or
// Manager.Close, which force-release it once no later read can succeed.
func (m *Manager) readData(ctx context.Context, c *Circuit, p []byte) (int, error) {
	if ctx == nil {
		return 0, fmt.Errorf("%w: nil context", ErrInvalidConfig)
	}
	for {
		m.mu.Lock()
		if len(p) == 0 {
			// Preserve the empty-read contract: it only reports whether the
			// receive direction can still be read.
			err := m.readStateLocked(c)
			m.mu.Unlock()
			return 0, err
		}
		if recvUnreadLocked(c) > 0 {
			n := copy(p, c.recvBuf[c.recvOff:])
			c.recvBase += uint64(n)
			c.recvOff += n
			// Keep len(recvBuf) meaning "unread bytes", which the buffer-budget
			// contract and the ledger both assert. A read that drains the buffer
			// only resets the cursor; a partial read folds the tail down, which is
			// the rare case here because callers read whole frames.
			if c.recvOff >= len(c.recvBuf) {
				c.recvBuf = c.recvBuf[:0]
				c.recvOff = 0
				if c.recvRes == nil {
					c.recvBuf = nil
				}
			} else {
				compactRecvLocked(c)
			}
			if recvUnreadLocked(c) == 0 && (c.finRecv || c.state.Finished() || m.closed) {
				// The direction can never regain accepted bytes: FIN forbids
				// later DATA, a terminal state refuses the receive direction,
				// and a closed Manager rejects every read. The read that
				// drained the last byte also returns the shared charge.
				m.releaseRecvLocked(c)
			}
			m.mu.Unlock()
			return n, nil
		}
		if err := m.readStateLocked(c); err != nil {
			m.mu.Unlock()
			return 0, err
		}
		if c.finRecv {
			// A FIN with an already empty buffer ends the receive direction
			// too, so the charge can never be used again.
			m.releaseRecvLocked(c)
			m.mu.Unlock()
			return 0, io.EOF
		}
		woke := c.woke
		m.mu.Unlock()
		select {
		case <-woke:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

// WriteData submits stream bytes for an active key.
func (m *Manager) WriteData(ctx context.Context, key Key, p []byte) (int, error) {
	c, err := m.Lookup(key)
	if err != nil {
		return 0, err
	}
	return m.writeData(ctx, c, p)
}

// ReadData copies received stream bytes for an active key.
func (m *Manager) ReadData(ctx context.Context, key Key, p []byte) (int, error) {
	c, err := m.Lookup(key)
	if err != nil {
		return 0, err
	}
	return m.readData(ctx, c, p)
}

// AcceptData is the receive-side alias of ReadData: it hands the caller the
// bytes delivered for one Circuit.
func (m *Manager) AcceptData(ctx context.Context, key Key, p []byte) (int, error) {
	return m.ReadData(ctx, key, p)
}

// cwndCeiling bounds this circuit's window by the path's round-trip time.
//
// Throughput is bounded by in-flight bytes over round-trip time, so the useful
// window is the bandwidth-delay product: a long-fat link needs a large window to
// stay busy, while a short link reaches the same rate with far less. A fixed
// ceiling therefore either idles on a long link or queues far too much on a short
// one. This estimates the product from the observed round trip and the rate the
// transfer is actually achieving, and clamps it to the configured maximum.
func (c *Circuit) cwndCeiling() uint64 {
	if !c.rttValid || c.srtt <= 0 {
		return cwndMax
	}
	// The rate this circuit is actually achieving: acknowledged bytes over the time
	// they took. That is the bandwidth half of the bandwidth-delay product.
	elapsed := c.ackedSpan
	if elapsed <= 0 {
		return cwndMax
	}
	rate := float64(c.cwndAcked) / elapsed.Seconds() // bytes/second
	if rate <= 0 {
		return cwndMax
	}
	// In-flight bytes needed to keep this rate over one round trip.
	want := uint64(rate * c.srtt.Seconds())
	// Never below the initial window: a slow path should not collapse the window to
	// nothing, and never above the configured ceiling.
	if want < cwndInitial {
		want = cwndInitial
	}
	if want > cwndMax {
		want = cwndMax
	}
	return want
}

// initialCwndFor returns the congestion window a new circuit should start with.
// A peer that has already carried a fast path starts at the window it last
// reached, so a short transfer is not limited by slow start on a link that has
// already proved itself. The history only ever raises the start; a peer with no
// history uses the conservative default.
func (m *Manager) initialCwndFor(peer NodeID) uint64 {
	if m.peerCwnd != nil {
		if seen := m.peerCwnd[peer]; seen > cwndInitial {
			return seen
		}
	}
	return cwndInitial
}

// PeerCwndSnapshot reports the remembered congestion window per peer, for
// diagnostics and tests.
func (m *Manager) PeerCwndSnapshot() map[NodeID]uint64 {
	out := make(map[NodeID]uint64, len(m.peerCwnd))
	m.mu.Lock()
	for peer, cwnd := range m.peerCwnd {
		out[peer] = cwnd
	}
	m.mu.Unlock()
	return out
}

// windowUpdate advertises a new absolute next-byte credit for the receive
// direction. The value must strictly advance, may never exceed the 64 KiB
// per-flow buffer bound (recvBase + MaxBuffer) nor the 256 KiB credit frontier
// cap, and is submitted as WINDOW_UPDATE.
func (m *Manager) windowUpdate(c *Circuit, absWindow uint64) error {
	c.ioMu.Lock()
	defer c.ioMu.Unlock()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if !c.state.readable() {
		err := error(ErrCircuitClosed)
		if c.cause != nil {
			err = c.cause
		}
		m.mu.Unlock()
		return err
	}
	if absWindow <= c.recvWindow {
		m.mu.Unlock()
		return fmt.Errorf("%w: %d at or below current %d", ErrWindowRegressed, absWindow, c.recvWindow)
	}
	if c.recvBase > math.MaxUint64-MaxBuffer {
		m.mu.Unlock()
		return fmt.Errorf("%w: receive offset exhausted", ErrResource)
	}
	if absWindow > c.recvBase+MaxBuffer {
		m.mu.Unlock()
		return fmt.Errorf("%w: window %d beyond buffer bound %d", ErrCreditExceeded, absWindow, c.recvBase+MaxBuffer)
	}
	next := c.recvBase + uint64(recvUnreadLocked(c))
	if next > math.MaxUint64-MaxCreditAhead {
		m.mu.Unlock()
		return fmt.Errorf("%w: receive frontier exhausted", ErrResource)
	}
	if absWindow > next+MaxCreditAhead {
		m.mu.Unlock()
		return fmt.Errorf("%w: window %d beyond credit frontier %d", ErrCreditExceeded, absWindow, next+MaxCreditAhead)
	}
	c.recvWindow = absWindow
	msg := WindowUpdateMessage{FromNodeID: m.localNodeID, CircuitID: c.key.CircuitID, Window: absWindow}
	plaintext, err := msg.Encode()
	ref, dir, dest := c.session, c.outboundDirection(), c.peerNode()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if err := m.submitFlowControl(context.Background(), ref, dir, dest, KindControlRPC, plaintext); err != nil {
		m.mu.Lock()
		m.failLocked(c, StateFailed, err)
		m.mu.Unlock()
		return err
	}
	return nil
}

// WindowUpdate advertises a new absolute credit for one active key.
func (m *Manager) WindowUpdate(key Key, absWindow uint64) error {
	c, err := m.Lookup(key)
	if err != nil {
		return err
	}
	return m.windowUpdate(c, absWindow)
}

// closeWrite sends the FIN frame. It is idempotent: a second call after the FIN
// was submitted returns nil and sends nothing.
func (m *Manager) closeWrite(c *Circuit) error {
	c.ioMu.Lock()
	defer c.ioMu.Unlock()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if c.finSent {
		m.mu.Unlock()
		return nil
	}
	now := m.now()
	switch c.state {
	case StateReady:
		c.state = StateLocalWriteClosed
	case StateRemoteWriteClosed:
		c.state = StateBothClosed
		c.terminalAt = now
	case StateBothClosed:
		m.mu.Unlock()
		return nil
	default:
		if c.state.Finished() {
			err := error(ErrCircuitClosed)
			if c.cause != nil {
				err = c.cause
			}
			m.mu.Unlock()
			return err
		}
		m.mu.Unlock()
		return fmt.Errorf("%w: close write in state %s", ErrState, c.state)
	}
	c.finSent = true
	msg := StreamDataMessage{
		FromNodeID: m.localNodeID,
		CircuitID:  c.key.CircuitID,
		Flags:      FlagFin,
		StreamSeq:  c.sendNext,
	}
	plaintext, encErr := msg.Encode()
	ref, dir, dest := c.session, c.outboundDirection(), c.peerNode()
	m.signalLocked(c)
	m.mu.Unlock()
	if encErr != nil {
		return encErr
	}
	if err := m.submit(context.Background(), ref, dir, dest, KindStreamData, plaintext); err != nil {
		m.mu.Lock()
		m.failLocked(c, StateFailed, err)
		m.mu.Unlock()
		return err
	}
	return nil
}

// CloseWrite sends the FIN for one active key.
func (m *Manager) CloseWrite(key Key) error {
	c, err := m.Lookup(key)
	if err != nil {
		return err
	}
	return m.closeWrite(c)
}

// beginResetLocked marks the Circuit terminal and returns the STREAM_RESET
// payload that must be submitted. It is called with m.mu held and never calls
// an injected boundary.
func (m *Manager) beginResetLocked(c *Circuit, reason ResetReason, cause error) ([]byte, error) {
	now := m.now()
	c.resetSent = true
	m.retireRecvLocked(c)
	c.cause = cause
	if reason == ResetReasonCanceled {
		c.state = StateCancelSent
	} else {
		c.state = StateResetting
	}
	c.queued = false
	c.terminalAt = now
	m.recordTombstoneLocked(c, now)
	m.counters.ResetsSent++
	m.signalLocked(c)
	if c.session.ID.IsZero() {
		return nil, nil
	}
	msg := ResetMessage{FromNodeID: m.localNodeID, CircuitID: c.key.CircuitID, Attempt: c.attempt, Reason: reason}
	return msg.Encode()
}

// resetCircuit terminates one Circuit with an idempotent STREAM_RESET. The
// teardown frame is best-effort: the record is terminal regardless of the
// submission result, and the first terminal cause is never overwritten.
func (m *Manager) resetCircuit(c *Circuit, reason ResetReason, cause error, check func(*Circuit) error) error {
	if !reason.Valid() {
		return fmt.Errorf("%w: reset reason 0x%04x", ErrProtocol, uint32(reason))
	}
	c.ioMu.Lock()
	defer c.ioMu.Unlock()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if c.resetSent {
		m.mu.Unlock()
		return nil
	}
	if check != nil {
		if err := check(c); err != nil {
			m.mu.Unlock()
			return err
		}
	}
	payload, err := m.beginResetLocked(c, reason, cause)
	ref, dir, dest := c.session, c.outboundDirection(), c.peerNode()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if payload != nil {
		_ = m.submit(context.Background(), ref, dir, dest, KindControlRPC, payload)
	}
	if reason != ResetReasonCanceled {
		m.mu.Lock()
		if c.state == StateResetting {
			c.state = StateClosed
		}
		m.mu.Unlock()
	}
	return nil
}

// Reset terminates one active key with an idempotent STREAM_RESET. An unknown
// reason is rejected with ErrProtocol before any state change or frame.
func (m *Manager) Reset(key Key, reason ResetReason) error {
	if !reason.Valid() {
		return fmt.Errorf("%w: reset reason 0x%04x", ErrProtocol, uint32(reason))
	}
	c, err := m.Lookup(key)
	if err != nil {
		return err
	}
	return m.resetCircuit(c, reason, reason.Err(), nil)
}

// Cancel aborts a source-side Dial that has not reached Ready. It is the
// local cancellation that makes StateCancelSent observable: the STREAM_RESET
// (CANCELED) is submitted best-effort and any late CIRCUIT_READY is ignored.
func (m *Manager) Cancel(key Key) error {
	c, err := m.Lookup(key)
	if err != nil {
		return err
	}
	return m.cancelCircuit(c)
}

func (m *Manager) cancelCircuit(c *Circuit) error {
	return m.resetCircuit(c, ResetReasonCanceled, ErrCanceled, func(c *Circuit) error {
		if c.role != RoleSource {
			return fmt.Errorf("%w: cancel requires the Dial side", ErrState)
		}
		switch c.state {
		case StateRequested, StateOpenUncommitted, StateOpenCommitted:
			return nil
		}
		return fmt.Errorf("%w: cancel in state %s", ErrState, c.state)
	})
}

// CloseCircuit closes both directions of one active stream: it is equivalent to
// Reset(CANCELED) and closes the local directions, so later Read/Write return
// ErrClosed and the peer observes CANCELED.
func (m *Manager) CloseCircuit(key Key) error {
	c, err := m.Lookup(key)
	if err != nil {
		return err
	}
	return m.resetCircuit(c, ResetReasonCanceled, ErrClosed, nil)
}

// FailSession marks one E2E SessionRef terminal for every local Circuit it
// carries and refuses every later local Open/admit on that exact reference. It
// is the local-only counterpart of a Session/Link loss: the source Session is
// already dead and its failure budget may forbid control traffic, so this
// method deliberately submits no frame at all — no STREAM_RESET, no
// CIRCUIT_READY and no Link close — and never touches a peer.
//
// Match is exact over the full reference: SessionID, PathID and PathGeneration
// must all be equal. A Circuit carried by another generation or another
// SessionID is untouched.
//
// cause is diagnostic only. A nil cause reports ErrSessionLost; a cause that
// already wraps ErrSessionLost is kept as-is; any other error is wrapped, so
// every observable terminal reason satisfies errors.Is(err, ErrSessionLost)
// and a caller can never substitute an unrelated terminal state.
//
// Every matching record is moved to StateFailed through the same failLocked
// path as any terminal failure, so its active slot is released, its pending
// Accept slot is invalidated, and every blocked ReadData/WriteData/credit
// waiter is woken by the manager broadcast: a read returns the accepted prefix
// first (a terminal session never truncates already-delivered bytes) and then
// the ErrSessionLost cause. The owned receive-buffer charge is released exactly
// once, here when the buffer is empty and otherwise on the draining read or on
// Manager.Close. A matching record that is already terminal keeps its first
// cause. No CircuitID tombstone is recorded: the failure is session-scoped, and
// a late inbound CIRCUIT_OPEN on the failed reference is refused locally.
//
// Because the reference is marked under the manager lock before the table scan,
// a Circuit whose Session is attached by a concurrent Open can never be
// published after the scan: the Open candidate loop observes the marker and
// skips the candidate without consuming a request_id, and if the Session dies
// after the record attached, the scan itself fails that record.
//
// The terminal registry is bounded to Limits.MaxTombstones entries for
// Limits.TombstoneTTL (30 s by default) and reaped with the other rejection
// windows. When it is full a live entry is never evicted; the manager-wide
// session admission fence is armed for the same window instead, refusing every
// local Open until it expires. Manager.Close ends the registry with the
// manager. A repeated call is idempotent and extends the window.
func (m *Manager) FailSession(ref SessionRef, cause error) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	failure := sessionLostCause(cause)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	now := m.now()
	m.reapLocked(now)
	// Publish the rejection window before the scan: a Circuit that is still
	// being admitted must not be able to attach to the Session afterwards.
	m.failSessionLocked(ref, now)
	for _, c := range m.circuits {
		if c.session != ref {
			continue
		}
		// The Session is aborted: no teardown may be submitted over it, and a
		// later Reset/Close on this handle must not overwrite the cause with one
		// of its own. This mirrors Manager.Close's own handling.
		c.resetSent = true
		m.failLocked(c, StateFailed, failure)
	}
	return nil
}

// sessionLostCause normalizes a FailSession cause: the observable terminal
// reason is always ErrSessionLost, and a caller-supplied error is retained only
// as diagnostic detail.
func sessionLostCause(cause error) error {
	switch {
	case cause == nil:
		return ErrSessionLost
	case errors.Is(cause, ErrSessionLost):
		return cause
	default:
		return fmt.Errorf("%w: %w", ErrSessionLost, cause)
	}
}

// Close releases every Circuit, wakes every blocked waiter with ErrClosed and
// closes Done. It is idempotent; a repeated call waits for the same Done. The
// CANCELED teardown frames are submitted best-effort after the state change.
func (m *Manager) Close() error {
	type teardown struct {
		ref     SessionRef
		dir     Direction
		dest    NodeID
		payload []byte
	}
	m.mu.Lock()
	if m.closed {
		done := m.done
		m.mu.Unlock()
		<-done
		return nil
	}
	m.closed = true
	var teardowns []teardown
	for _, c := range m.circuits {
		if c.state.Finished() {
			// A terminal record may still own a receive array; Close returns
			// that charge too, so the manager leaves no shared bytes behind.
			m.releaseRecvLocked(c)
			continue
		}
		if !c.session.ID.IsZero() {
			msg := ResetMessage{FromNodeID: m.localNodeID, CircuitID: c.key.CircuitID, Attempt: c.attempt, Reason: ResetReasonCanceled}
			if payload, err := msg.Encode(); err == nil {
				teardowns = append(teardowns, teardown{ref: c.session, dir: c.outboundDirection(), dest: c.peerNode(), payload: payload})
			}
		}
		c.resetSent = true
		m.releaseRecvLocked(c)
		m.counters.ResetsSent++
		m.failLocked(c, StateClosed, ErrClosed)
	}
	m.pending = nil
	m.signalLocked(nil)
	m.mu.Unlock()
	for _, td := range teardowns {
		_ = m.submit(context.Background(), td.ref, td.dir, td.dest, KindControlRPC, td.payload)
	}
	m.mu.Lock()
	close(m.done)
	m.mu.Unlock()
	return nil
}

// CircuitSnapshot is a deep-copied observation of one Circuit.
type CircuitSnapshot struct {
	Key          Key
	Role         Role
	State        State
	Attempt      uint32
	RequestID    uint64
	TargetNodeID NodeID
	TargetPort   uint16
	Candidate    Candidate
	Session      SessionRef
	Committed    bool
	Created      time.Time
	Deadline     time.Time
	SendNext     uint64
	SendWindow   uint64
	RecvBase     uint64
	RecvNext     uint64
	RecvWindow   uint64
	Buffered     int
	FinSent      bool
	FinRecv      bool
	ResetSent    bool
	ResetRecv    bool
	Queued       bool
	Accepted     bool
	TerminalAt   time.Time
	Failure      string
}

// TombstoneSnapshot is one cancel/terminal rejection window.
type TombstoneSnapshot struct {
	Key   Key
	Until time.Time
}

// FenceSnapshot is one peer's independent admission fence.
type FenceSnapshot struct {
	ContextID ContextID
	NodeID    NodeID
	Until     time.Time
}

// Snapshot is a deep copy of the manager observation. It never aliases internal
// buffers, so a caller may keep or mutate it.
type Snapshot struct {
	ContextID   ContextID
	LocalNodeID NodeID
	Closed      bool
	Limits      Limits
	Counters    Counters
	Circuits    []CircuitSnapshot
	Tombstones  []TombstoneSnapshot
	Fences      []FenceSnapshot
}

// snapshotLocked copies one record. m.mu must be held.
func (c *Circuit) snapshotLocked() CircuitSnapshot {
	s := CircuitSnapshot{
		Key:          c.key,
		Role:         c.role,
		State:        c.state,
		Attempt:      c.attempt,
		RequestID:    c.requestID,
		TargetNodeID: c.targetNode,
		TargetPort:   c.targetPort,
		Candidate:    c.candidate,
		Session:      c.session,
		Committed:    c.committed,
		Created:      c.created,
		Deadline:     c.deadline,
		SendNext:     c.sendNext,
		SendWindow:   c.sendWindow,
		RecvBase:     c.recvBase,
		RecvNext:     c.recvBase + uint64(recvUnreadLocked(c)),
		RecvWindow:   c.recvWindow,
		Buffered:     recvUnreadLocked(c),
		FinSent:      c.finSent,
		FinRecv:      c.finRecv,
		ResetSent:    c.resetSent,
		ResetRecv:    c.resetRecv,
		Queued:       c.queued,
		Accepted:     c.accepted,
		TerminalAt:   c.terminalAt,
	}
	if c.cause != nil {
		s.Failure = c.cause.Error()
	}
	return s
}

// Snapshot returns a deep copy of the current observation.
func (c *Circuit) Snapshot() CircuitSnapshot {
	c.mgr.mu.Lock()
	defer c.mgr.mu.Unlock()
	return c.snapshotLocked()
}

// Snapshot returns a deep copy of the manager state.
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Snapshot{
		ContextID:   m.contextID,
		LocalNodeID: m.localNodeID,
		Closed:      m.closed,
		Limits:      m.limits,
		Counters:    m.counters,
	}
	s.Circuits = make([]CircuitSnapshot, 0, len(m.circuits))
	for _, c := range m.circuits {
		s.Circuits = append(s.Circuits, c.snapshotLocked())
	}
	sort.Slice(s.Circuits, func(i, j int) bool {
		if s.Circuits[i].Key.SrcNodeID != s.Circuits[j].Key.SrcNodeID {
			return string(s.Circuits[i].Key.SrcNodeID[:]) < string(s.Circuits[j].Key.SrcNodeID[:])
		}
		return string(s.Circuits[i].Key.CircuitID[:]) < string(s.Circuits[j].Key.CircuitID[:])
	})
	s.Tombstones = make([]TombstoneSnapshot, 0, len(m.tombstones))
	for key, until := range m.tombstones {
		s.Tombstones = append(s.Tombstones, TombstoneSnapshot{Key: key, Until: until})
	}
	sort.Slice(s.Tombstones, func(i, j int) bool {
		return string(s.Tombstones[i].Key.CircuitID[:]) < string(s.Tombstones[j].Key.CircuitID[:])
	})
	s.Fences = make([]FenceSnapshot, 0, len(m.fences))
	for peer, until := range m.fences {
		s.Fences = append(s.Fences, FenceSnapshot{ContextID: peer.contextID, NodeID: peer.nodeID, Until: until})
	}
	sort.Slice(s.Fences, func(i, j int) bool {
		return string(s.Fences[i].NodeID[:]) < string(s.Fences[j].NodeID[:])
	})
	return s
}

// WriteData submits stream bytes on the handle.
func (c *Circuit) WriteData(ctx context.Context, p []byte) (int, error) {
	return c.mgr.writeData(ctx, c, p)
}

// ReadData copies received bytes on the handle.
func (c *Circuit) ReadData(ctx context.Context, p []byte) (int, error) {
	return c.mgr.readData(ctx, c, p)
}

// AcceptData is the receive-side alias of ReadData.
func (c *Circuit) AcceptData(ctx context.Context, p []byte) (int, error) {
	return c.mgr.readData(ctx, c, p)
}

// WindowUpdate advertises a new absolute credit on the handle.
func (c *Circuit) WindowUpdate(absWindow uint64) error {
	return c.mgr.windowUpdate(c, absWindow)
}

// CloseWrite sends the FIN on the handle. It is idempotent.
func (c *Circuit) CloseWrite() error { return c.mgr.closeWrite(c) }

// Reset terminates the handle with a STREAM_RESET. It is idempotent and rejects
// an unknown reason without sending anything.
func (c *Circuit) Reset(reason ResetReason) error {
	return c.mgr.resetCircuit(c, reason, reason.Err(), nil)
}

// Cancel aborts a source-side Dial that has not reached Ready.
func (c *Circuit) Cancel() error { return c.mgr.cancelCircuit(c) }

// Close is equivalent to Reset(CANCELED): later local Read/Write return
// ErrClosed and the peer observes CANCELED.
func (c *Circuit) Close() error {
	return c.mgr.resetCircuit(c, ResetReasonCanceled, ErrClosed, nil)
}
