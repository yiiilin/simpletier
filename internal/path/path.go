// Package path owns the SimpleTier P1 Path lifecycle.
//
// A Path is built from exactly one RouteView candidate for one data Lane
// (PACKET or STREAM). This package validates that candidate hop by hop,
// allocates the source-side PathID/Generation, binds the immutable path
// geometry into a PathDigest, installs the path transactionally, and tracks the
// Created/OpenPending/Ready/Active/Broken/Closed state machine. It also encodes
// and decodes the PATH_OPEN/PATH_READY/PATH_BROKEN ROUTE_CTRL payloads.
//
// Deliberately out of scope: the Noise IK handshake, SESSION_CTRL/SESSION_READY,
// Circuit/STREAM data frames, per-hop cursor forwarding and forwarding tables,
// FrameKind/envelope wire framing, key/replay state, and the RouteView graph
// itself. Those owners consume this package instead of reimplementing it. No
// FrameKind or MessageType opcode is (re)defined here: MessageType values mirror
// the frozen wire-protocol.md numbers, and the payloads below are the ROUTE_CTRL
// bootstrap payloads that carry no envelope.
//
// Spec anchors: topology-routing.md C-ROUTE-002/003/004 (candidate filtering,
// bounded candidates/hops, view binding), wire-protocol.md PATH_OPEN/PATH_READY/
// PATH_BROKEN payload schemas and redundant-field checks, tcp-overlay-network.md
// path-before-session ordering.
package path

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/yiiilin/simpletier/internal/topology"
)

// Vocabulary shared with the topology owner. Aliases keep the Path API
// readable without inventing a second NodeID/LinkRef type.
type (
	NodeID      = topology.NodeID
	LinkRef     = topology.LinkRef
	RoutePolicy = topology.RoutePolicy
	RouteView   = topology.RouteView
	Freshness   = topology.RouteFreshness
)

const (
	// MaxCandidates is the per-target/lane candidate ceiling (C-ROUTE-004).
	MaxCandidates = 3
	// MaxHops is the topology hop ceiling (D-ROUTE-003).
	MaxHops = 16
	// MaxNodes is the frozen PATH_OPEN node ceiling
	// (wire-protocol.md: 2 <= node_count <= 16). It is the stricter of the two
	// bounds, so a path installed today has at most 15 hops.
	MaxNodes = 16
	// MaxPaths is the per-node Path table ceiling (wire-protocol.md resource
	// limits: 每节点 Path 表项≤1024).
	MaxPaths = 1024
	// MaxIssuedPathIDs bounds the in-process PathID ledger. The ledger exists so
	// a PathID can never be reused in this process; when it is exhausted the
	// manager fails closed with ErrResourceLimit instead of reusing an ID.
	MaxIssuedPathIDs = 1 << 16
	// MaxConcurrentRebuilds is the graph rebuild concurrency ceiling
	// (C-ROUTE-004). Overflow fails without queueing.
	MaxConcurrentRebuilds = 2
	// MaxRouteControlPayload is the frozen ROUTE_CTRL bootstrap payload
	// ceiling (wire-protocol.md: SESSION_CTRL/PATH bootstrap payloads must be
	// non-empty and no larger than 8 KiB).
	MaxRouteControlPayload = 8 << 10

	digestDomain = "simpletier-path-v1"

	// maxPathIDAttempts bounds retries when the CSPRNG hands back a zero or
	// already-issued PathID.
	maxPathIDAttempts = 8
)

// Public errors. RouteView and codec errors wrap their own sentinels; every
// error this package returns matches exactly one of the sentinels below through
// errors.Is.
var (
	// ErrInvalidPath reports a structurally invalid path (node/link counts,
	// endpoints, zero IDs, missing connection type).
	ErrInvalidPath = errors.New("path: invalid path")
	// ErrInvalidLane reports a lane other than PACKET or STREAM, or a link whose
	// lane does not match the requested data lane.
	ErrInvalidLane = errors.New("path: invalid lane")
	// ErrInvalidNode reports an empty node, or a destination that is empty or
	// local.
	ErrInvalidNode = errors.New("path: invalid node")
	// ErrDuplicateNode reports a node that appears twice in one candidate.
	ErrDuplicateNode = errors.New("path: duplicate node")
	// ErrHopLimit reports a candidate above the hop or node ceiling.
	ErrHopLimit = errors.New("path: hop limit exceeded")
	// ErrInactiveLink reports a hop whose LinkRef is not confirmed active by the
	// local synchronous callback.
	ErrInactiveLink = errors.New("path: hop link is not active")
	// ErrLinkMismatch reports resolved LinkRefs that do not match the
	// (LinkID, LinkEpoch) pairs carried by PATH_OPEN.
	ErrLinkMismatch = errors.New("path: resolved link does not match PATH_OPEN")
	// ErrPathDigestMismatch reports a PathDigest that does not match the
	// canonical node/link list.
	ErrPathDigestMismatch = errors.New("path: path digest mismatch")
	// ErrPathMismatch reports a control message for a different PathID, lane or
	// generation than the referenced path.
	ErrPathMismatch = errors.New("path: path identity mismatch")
	// ErrPathConflict reports two different installs claiming the same
	// PathID/Generation.
	ErrPathConflict = errors.New("path: conflicting path install")
	// ErrPathGenerationExpired reports a stale Generation, including a PathID
	// that was retired by generation exhaustion.
	ErrPathGenerationExpired = errors.New("path: path generation expired")
	// ErrState reports an illegal state transition for the current state.
	ErrState = errors.New("path: invalid path state transition")
	// ErrClosed reports an operation on a closed Path or Manager.
	ErrClosed = errors.New("path: closed")
	// ErrNotFound reports a PathID that this manager never installed.
	ErrNotFound = errors.New("path: path not found")
	// ErrResourceLimit reports a conservative bound: candidate count, path table,
	// PathID ledger, concurrent rebuilds or payload size.
	ErrResourceLimit = errors.New("path: resource limit")
	// ErrProtocol reports a malformed or unknown ROUTE_CTRL payload field.
	ErrProtocol = errors.New("path: route control protocol violation")
	// ErrEntropy reports a failing CSPRNG while allocating a PathID.
	ErrEntropy = errors.New("path: CSPRNG failure")
)

// Lane is the data lane a Path carries. Paths never carry the CONTROL lane.
type Lane uint8

const (
	LanePacket Lane = 0x01
	LaneStream Lane = 0x02
)

// Valid reports whether the lane may carry a Path.
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

// MarshalText makes Lane printable in diagnostics without changing its number.
func (l Lane) MarshalText() ([]byte, error) {
	if !l.Valid() {
		return nil, fmt.Errorf("%w: lane 0x%02x", ErrInvalidLane, uint8(l))
	}
	return []byte(l.String()), nil
}

// State is the Path lifecycle state owned by this module.
type State uint8

const (
	// StateCreated: the candidate is installed and validated, PATH_OPEN has not
	// been emitted yet.
	StateCreated State = iota
	// StateOpenPending: PATH_OPEN was emitted (or a matching PATH_OPEN was
	// accepted) and PATH_READY/SESSION_READY is still outstanding.
	StateOpenPending
	// StateReady: the PATH_READY exchange completed and the path is installed.
	StateReady
	// StateActive: the upper layer committed the matching SESSION_READY on this
	// path; data may flow.
	StateActive
	// StateBroken: terminal path failure (PATH_BROKEN, local failure or a
	// rejected PATH_READY). Broken paths are never reused; open a new one.
	StateBroken
	// StateClosed: terminal, released by Close.
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateCreated:
		return "Created"
	case StateOpenPending:
		return "OpenPending"
	case StateReady:
		return "Ready"
	case StateActive:
		return "Active"
	case StateBroken:
		return "Broken"
	case StateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("STATE(%d)", uint8(s))
	}
}

// MessageType mirrors the frozen wire-protocol.md MessageType numbers for the
// ROUTE_CTRL messages this package owns. It is a typed internal enum: the wire
// package keeps the authoritative opcodes, and this package never redefines
// FrameKind or non-Path MessageTypes.
type MessageType uint8

const (
	MessagePathOpen   MessageType = 0x06
	MessagePathReady  MessageType = 0x07
	MessagePathBroken MessageType = 0x08
)

func (t MessageType) Valid() bool {
	return t == MessagePathOpen || t == MessagePathReady || t == MessagePathBroken
}

func (t MessageType) String() string {
	switch t {
	case MessagePathOpen:
		return "PATH_OPEN"
	case MessagePathReady:
		return "PATH_READY"
	case MessagePathBroken:
		return "PATH_BROKEN"
	default:
		return fmt.Sprintf("MESSAGE(0x%02x)", uint8(t))
	}
}

// ReadyStatus is the PATH_READY status enum (wire-protocol.md).
type ReadyStatus uint8

const (
	ReadyStatusReady      ReadyStatus = 0x01
	ReadyStatusReject     ReadyStatus = 0x02
	ReadyStatusAlready    ReadyStatus = 0x03
	ReadyStatusRolledBack ReadyStatus = 0x04
)

func (s ReadyStatus) Valid() bool {
	return s >= ReadyStatusReady && s <= ReadyStatusRolledBack
}

func (s ReadyStatus) String() string {
	switch s {
	case ReadyStatusReady:
		return "READY"
	case ReadyStatusReject:
		return "REJECT"
	case ReadyStatusAlready:
		return "ALREADY"
	case ReadyStatusRolledBack:
		return "ROLLED_BACK"
	default:
		return fmt.Sprintf("STATUS(0x%02x)", uint8(s))
	}
}

// ErrorCode is the PATH_READY error_code enum (wire-protocol.md). Unknown
// values are rejected.
type ErrorCode uint16

const (
	ErrorCodeNone     ErrorCode = 0x0000
	ErrorCodeNoRoute  ErrorCode = 0x0001
	ErrorCodeLinkDown ErrorCode = 0x0002
	ErrorCodeResource ErrorCode = 0x0003
	ErrorCodeProtocol ErrorCode = 0x0004
)

func (c ErrorCode) Valid() bool { return c >= ErrorCodeNone && c <= ErrorCodeProtocol }

func (c ErrorCode) String() string {
	switch c {
	case ErrorCodeNone:
		return "NONE"
	case ErrorCodeNoRoute:
		return "NO_ROUTE"
	case ErrorCodeLinkDown:
		return "LINK_DOWN"
	case ErrorCodeResource:
		return "RESOURCE"
	case ErrorCodeProtocol:
		return "PROTOCOL"
	default:
		return fmt.Sprintf("ERROR(0x%04x)", uint16(c))
	}
}

// BrokenReason is the PATH_BROKEN reason code. wire-protocol.md fixes
// reason:u16 but does not yet enumerate it, so this module uses the documented
// PATH_READY error-code space and rejects everything else: extending the space
// requires a spec revision, not a silent accept.
type BrokenReason uint16

const (
	BrokenReasonNoRoute  BrokenReason = 0x0001
	BrokenReasonLinkDown BrokenReason = 0x0002
	BrokenReasonResource BrokenReason = 0x0003
	BrokenReasonProtocol BrokenReason = 0x0004
)

func (r BrokenReason) Valid() bool {
	return r >= BrokenReasonNoRoute && r <= BrokenReasonProtocol
}

func (r BrokenReason) String() string {
	switch r {
	case BrokenReasonNoRoute:
		return "NO_ROUTE"
	case BrokenReasonLinkDown:
		return "LINK_DOWN"
	case BrokenReasonResource:
		return "RESOURCE"
	case BrokenReasonProtocol:
		return "PROTOCOL"
	default:
		return fmt.Sprintf("REASON(0x%04x)", uint16(r))
	}
}

// LinkInstance is one (LinkID, LinkEpoch) pair exactly as PATH_OPEN carries it.
// It is not a LinkRef: PATH_OPEN never carries Lane or ConnectionType, so a
// receiver must resolve those from its own authenticated LinkFacts before it can
// recompute the PathDigest.
type LinkInstance struct {
	ID    uint64
	Epoch uint64
}

// PathOpen is the PATH_OPEN ROUTE_CTRL payload:
//
//	PathID:u64be | Generation:u32be | LaneID:u8 | ViewVersion:u64be |
//	node_count:u8 | node_ids[16B] | link_count:u8 |
//	(LinkID:u64be, LinkEpoch:u64be)* | PathDigest:32B
//
// Nodes are ordered source-first; node_count is 2..16 and
// link_count == node_count-1.
type PathOpen struct {
	PathID      uint64
	Generation  uint32
	Lane        Lane
	ViewVersion uint64
	Nodes       []NodeID
	Links       []LinkInstance
	Digest      [32]byte
}

// PathReady is the PATH_READY ROUTE_CTRL payload:
//
//	PathID:u64be | Generation:u32be | LaneID:u8 | PathDigest:32B |
//	status:u8 | error_code:u16be
type PathReady struct {
	PathID     uint64
	Generation uint32
	Lane       Lane
	Digest     [32]byte
	Status     ReadyStatus
	Code       ErrorCode
}

// PathBroken is the PATH_BROKEN ROUTE_CTRL payload:
//
//	PathID:u64be | Generation:u32be | LaneID:u8 | PathDigest:32B |
//	reason:u16be | failed_cursor:u8
type PathBroken struct {
	PathID       uint64
	Generation   uint32
	Lane         Lane
	Digest       [32]byte
	Reason       BrokenReason
	FailedCursor uint8
}

// RouteControl is one decoded ROUTE_CTRL bootstrap payload with its typed
// message discriminator. Exactly one payload field matches Type; the others stay
// zero. The discriminator comes from the ROUTE_CTRL envelope, which the wire
// owner parses; this package never re-encodes the envelope.
type RouteControl struct {
	Type   MessageType
	Open   PathOpen
	Ready  PathReady
	Broken PathBroken
}

// Encode returns the ROUTE_CTRL payload bytes for the control message.
func (rc RouteControl) Encode() ([]byte, error) {
	switch rc.Type {
	case MessagePathOpen:
		return rc.Open.Encode()
	case MessagePathReady:
		return rc.Ready.Encode()
	case MessagePathBroken:
		return rc.Broken.Encode()
	default:
		return nil, fmt.Errorf("%w: unsupported ROUTE_CTRL message type 0x%02x", ErrProtocol, uint8(rc.Type))
	}
}

// DecodeRouteControl strictly decodes one non-empty ROUTE_CTRL bootstrap payload
// of at most MaxRouteControlPayload bytes. messageType is the envelope
// discriminator; only PATH_OPEN/PATH_READY/PATH_BROKEN are accepted, every other
// value (including SESSION_CTRL/SESSION_READY, which belong to the session
// owner) is rejected. Integers are big-endian, field order is frozen, and any
// unknown enum value, count mismatch, duplicate node or trailing byte is an
// error. Decoding performs no state mutation.
func DecodeRouteControl(messageType MessageType, payload []byte) (RouteControl, error) {
	if !messageType.Valid() {
		return RouteControl{}, fmt.Errorf("%w: message type 0x%02x is not a Path control message", ErrProtocol, uint8(messageType))
	}
	if len(payload) == 0 {
		return RouteControl{}, fmt.Errorf("%w: empty %s payload", ErrProtocol, messageType)
	}
	if len(payload) > MaxRouteControlPayload {
		return RouteControl{}, fmt.Errorf("%w: %s payload %d bytes > %d", ErrResourceLimit, messageType, len(payload), MaxRouteControlPayload)
	}
	switch messageType {
	case MessagePathOpen:
		open, err := decodePathOpen(payload)
		if err != nil {
			return RouteControl{}, err
		}
		return RouteControl{Type: MessagePathOpen, Open: open}, nil
	case MessagePathReady:
		ready, err := decodePathReady(payload)
		if err != nil {
			return RouteControl{}, err
		}
		return RouteControl{Type: MessagePathReady, Ready: ready}, nil
	default:
		broken, err := decodePathBroken(payload)
		if err != nil {
			return RouteControl{}, err
		}
		return RouteControl{Type: MessagePathBroken, Broken: broken}, nil
	}
}

// Encode returns the PATH_OPEN payload. The payload carries no envelope and its
// size is bounded by MaxRouteControlPayload.
func (m PathOpen) Encode() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	size := pathOpenSize(len(m.Nodes))
	if size > MaxRouteControlPayload {
		return nil, fmt.Errorf("%w: PATH_OPEN payload %d bytes > %d", ErrResourceLimit, size, MaxRouteControlPayload)
	}
	buf := make([]byte, 0, size)
	buf = binary.BigEndian.AppendUint64(buf, m.PathID)
	buf = binary.BigEndian.AppendUint32(buf, m.Generation)
	buf = append(buf, byte(m.Lane))
	buf = binary.BigEndian.AppendUint64(buf, m.ViewVersion)
	buf = append(buf, byte(len(m.Nodes)))
	for _, node := range m.Nodes {
		buf = append(buf, node[:]...)
	}
	buf = append(buf, byte(len(m.Links)))
	for _, link := range m.Links {
		buf = binary.BigEndian.AppendUint64(buf, link.ID)
		buf = binary.BigEndian.AppendUint64(buf, link.Epoch)
	}
	return append(buf, m.Digest[:]...), nil
}

// Encode returns the PATH_READY payload.
func (m PathReady) Encode() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 48)
	buf = binary.BigEndian.AppendUint64(buf, m.PathID)
	buf = binary.BigEndian.AppendUint32(buf, m.Generation)
	buf = append(buf, byte(m.Lane))
	buf = append(buf, m.Digest[:]...)
	buf = append(buf, byte(m.Status))
	return binary.BigEndian.AppendUint16(buf, uint16(m.Code)), nil
}

// Encode returns the PATH_BROKEN payload.
func (m PathBroken) Encode() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 48)
	buf = binary.BigEndian.AppendUint64(buf, m.PathID)
	buf = binary.BigEndian.AppendUint32(buf, m.Generation)
	buf = append(buf, byte(m.Lane))
	buf = append(buf, m.Digest[:]...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(m.Reason))
	return append(buf, m.FailedCursor), nil
}

func (m PathOpen) validate() error {
	if m.PathID == 0 {
		return fmt.Errorf("%w: zero PathID", ErrInvalidPath)
	}
	if m.Generation == 0 {
		return fmt.Errorf("%w: zero Generation", ErrInvalidPath)
	}
	if !m.Lane.Valid() {
		return fmt.Errorf("%w: PATH_OPEN lane 0x%02x", ErrInvalidLane, uint8(m.Lane))
	}
	if len(m.Nodes) < 2 {
		return fmt.Errorf("%w: PATH_OPEN with %d nodes", ErrInvalidPath, len(m.Nodes))
	}
	if len(m.Nodes) > MaxNodes {
		return fmt.Errorf("%w: PATH_OPEN with %d nodes > %d (frozen node_count ceiling)", ErrHopLimit, len(m.Nodes), MaxNodes)
	}
	if len(m.Links) != len(m.Nodes)-1 {
		return fmt.Errorf("%w: PATH_OPEN with %d links for %d nodes", ErrInvalidPath, len(m.Links), len(m.Nodes))
	}
	seen := make(map[NodeID]struct{}, len(m.Nodes))
	for index, node := range m.Nodes {
		if node == (NodeID{}) {
			return fmt.Errorf("%w: PATH_OPEN node %d is empty", ErrInvalidNode, index)
		}
		if _, duplicate := seen[node]; duplicate {
			return fmt.Errorf("%w: PATH_OPEN node %d", ErrDuplicateNode, index)
		}
		seen[node] = struct{}{}
	}
	for index, link := range m.Links {
		if link.ID == 0 || link.Epoch == 0 {
			return fmt.Errorf("%w: PATH_OPEN hop %d has a zero LinkID/LinkEpoch", ErrInvalidPath, index)
		}
	}
	return nil
}

func (m PathReady) validate() error {
	if m.PathID == 0 {
		return fmt.Errorf("%w: zero PathID", ErrInvalidPath)
	}
	if m.Generation == 0 {
		return fmt.Errorf("%w: zero Generation", ErrInvalidPath)
	}
	if !m.Lane.Valid() {
		return fmt.Errorf("%w: PATH_READY lane 0x%02x", ErrInvalidLane, uint8(m.Lane))
	}
	if !m.Status.Valid() {
		return fmt.Errorf("%w: PATH_READY status 0x%02x", ErrProtocol, uint8(m.Status))
	}
	if !m.Code.Valid() {
		return fmt.Errorf("%w: PATH_READY error code 0x%04x", ErrProtocol, uint16(m.Code))
	}
	if m.Status == ReadyStatusReady && m.Code != ErrorCodeNone {
		return fmt.Errorf("%w: PATH_READY status READY requires error_code 0", ErrProtocol)
	}
	return nil
}

func (m PathBroken) validate() error {
	if m.PathID == 0 {
		return fmt.Errorf("%w: zero PathID", ErrInvalidPath)
	}
	if m.Generation == 0 {
		return fmt.Errorf("%w: zero Generation", ErrInvalidPath)
	}
	if !m.Lane.Valid() {
		return fmt.Errorf("%w: PATH_BROKEN lane 0x%02x", ErrInvalidLane, uint8(m.Lane))
	}
	if !m.Reason.Valid() {
		return fmt.Errorf("%w: PATH_BROKEN reason 0x%04x", ErrProtocol, uint16(m.Reason))
	}
	if m.FailedCursor > MaxNodes-1 {
		return fmt.Errorf("%w: PATH_BROKEN failed_cursor %d > %d", ErrProtocol, m.FailedCursor, MaxNodes-1)
	}
	return nil
}

func pathOpenSize(nodes int) int {
	return 8 + 4 + 1 + 8 + 1 + nodes*16 + 1 + (nodes-1)*16 + 32
}

type controlReader struct {
	buf []byte
	off int
}

func (r *controlReader) take(n int) ([]byte, error) {
	if n < 0 || len(r.buf)-r.off < n {
		return nil, fmt.Errorf("%w: truncated ROUTE_CTRL payload", ErrProtocol)
	}
	out := r.buf[r.off : r.off+n]
	r.off += n
	return out, nil
}

func (r *controlReader) u8() (uint8, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *controlReader) u16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *controlReader) u32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (r *controlReader) u64() (uint64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

func (r *controlReader) node() (NodeID, error) {
	var node NodeID
	b, err := r.take(len(node))
	if err != nil {
		return node, err
	}
	copy(node[:], b)
	return node, nil
}

func (r *controlReader) digest() ([32]byte, error) {
	var digest [32]byte
	b, err := r.take(len(digest))
	if err != nil {
		return digest, err
	}
	copy(digest[:], b)
	return digest, nil
}

func (r *controlReader) done() error {
	if r.off != len(r.buf) {
		return fmt.Errorf("%w: %d trailing ROUTE_CTRL payload bytes", ErrProtocol, len(r.buf)-r.off)
	}
	return nil
}

func decodePathOpen(payload []byte) (PathOpen, error) {
	r := &controlReader{buf: payload}
	pathID, err := r.u64()
	if err != nil {
		return PathOpen{}, err
	}
	generation, err := r.u32()
	if err != nil {
		return PathOpen{}, err
	}
	lane, err := r.u8()
	if err != nil {
		return PathOpen{}, err
	}
	viewVersion, err := r.u64()
	if err != nil {
		return PathOpen{}, err
	}
	count, err := r.u8()
	if err != nil {
		return PathOpen{}, err
	}
	if count < 2 || int(count) > MaxNodes {
		return PathOpen{}, fmt.Errorf("%w: PATH_OPEN node_count %d outside 2..%d", ErrProtocol, count, MaxNodes)
	}
	nodes := make([]NodeID, 0, count)
	for index := 0; index < int(count); index++ {
		node, err := r.node()
		if err != nil {
			return PathOpen{}, err
		}
		nodes = append(nodes, node)
	}
	links, err := r.u8()
	if err != nil {
		return PathOpen{}, err
	}
	if int(links) != int(count)-1 {
		return PathOpen{}, fmt.Errorf("%w: PATH_OPEN link_count %d for node_count %d", ErrProtocol, links, count)
	}
	instances := make([]LinkInstance, 0, links)
	for index := 0; index < int(links); index++ {
		id, err := r.u64()
		if err != nil {
			return PathOpen{}, err
		}
		epoch, err := r.u64()
		if err != nil {
			return PathOpen{}, err
		}
		instances = append(instances, LinkInstance{ID: id, Epoch: epoch})
	}
	digest, err := r.digest()
	if err != nil {
		return PathOpen{}, err
	}
	if err := r.done(); err != nil {
		return PathOpen{}, err
	}
	message := PathOpen{PathID: pathID, Generation: generation, Lane: Lane(lane), ViewVersion: viewVersion, Nodes: nodes, Links: instances, Digest: digest}
	if err := message.validate(); err != nil {
		return PathOpen{}, err
	}
	return message, nil
}

func decodePathReady(payload []byte) (PathReady, error) {
	r := &controlReader{buf: payload}
	pathID, err := r.u64()
	if err != nil {
		return PathReady{}, err
	}
	generation, err := r.u32()
	if err != nil {
		return PathReady{}, err
	}
	lane, err := r.u8()
	if err != nil {
		return PathReady{}, err
	}
	digest, err := r.digest()
	if err != nil {
		return PathReady{}, err
	}
	status, err := r.u8()
	if err != nil {
		return PathReady{}, err
	}
	code, err := r.u16()
	if err != nil {
		return PathReady{}, err
	}
	if err := r.done(); err != nil {
		return PathReady{}, err
	}
	message := PathReady{PathID: pathID, Generation: generation, Lane: Lane(lane), Digest: digest, Status: ReadyStatus(status), Code: ErrorCode(code)}
	if err := message.validate(); err != nil {
		return PathReady{}, err
	}
	return message, nil
}

func decodePathBroken(payload []byte) (PathBroken, error) {
	r := &controlReader{buf: payload}
	pathID, err := r.u64()
	if err != nil {
		return PathBroken{}, err
	}
	generation, err := r.u32()
	if err != nil {
		return PathBroken{}, err
	}
	lane, err := r.u8()
	if err != nil {
		return PathBroken{}, err
	}
	digest, err := r.digest()
	if err != nil {
		return PathBroken{}, err
	}
	reason, err := r.u16()
	if err != nil {
		return PathBroken{}, err
	}
	cursor, err := r.u8()
	if err != nil {
		return PathBroken{}, err
	}
	if err := r.done(); err != nil {
		return PathBroken{}, err
	}
	message := PathBroken{PathID: pathID, Generation: generation, Lane: Lane(lane), Digest: digest, Reason: BrokenReason(reason), FailedCursor: cursor}
	if err := message.validate(); err != nil {
		return PathBroken{}, err
	}
	return message, nil
}

// ComputeDigest returns the canonical PathDigest
//
//	SHA-256("simpletier-path-v1" || PathID:u64be || Generation:u32be ||
//	        LaneID:u8 || ViewVersion:u64be || node_count:u8 ||
//	        node_ids[16B] || link_count:u8 ||
//	        (LinkID:u64be || LinkEpoch:u64be || LaneID:u8 ||
//	         type_len:u16be || connection_type_utf8)*)
//
// It binds the exact authenticated link instances, including each hop's
// ConnectionType, so a hop that resolves a different LinkFact for a
// (LinkID, LinkEpoch) pair computes a different digest. The geometry is
// validated first; an invalid path has no digest.
func ComputeDigest(pathID uint64, generation uint32, lane Lane, viewVersion uint64, nodes []NodeID, links []LinkRef) ([32]byte, error) {
	if pathID == 0 {
		return [32]byte{}, fmt.Errorf("%w: zero PathID", ErrInvalidPath)
	}
	if generation == 0 {
		return [32]byte{}, fmt.Errorf("%w: zero Generation", ErrInvalidPath)
	}
	if err := validateGeometry(lane, nodes, links); err != nil {
		return [32]byte{}, err
	}
	buf := make([]byte, 0, len(digestDomain)+8+4+1+8+1+len(nodes)*16+1+len(links)*19)
	buf = append(buf, digestDomain...)
	buf = binary.BigEndian.AppendUint64(buf, pathID)
	buf = binary.BigEndian.AppendUint32(buf, generation)
	buf = append(buf, byte(lane))
	buf = binary.BigEndian.AppendUint64(buf, viewVersion)
	buf = append(buf, byte(len(nodes)))
	for _, node := range nodes {
		buf = append(buf, node[:]...)
	}
	buf = append(buf, byte(len(links)))
	for _, link := range links {
		buf = binary.BigEndian.AppendUint64(buf, link.ID)
		buf = binary.BigEndian.AppendUint64(buf, link.Epoch)
		buf = append(buf, link.LaneID)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(link.ConnectionType)))
		buf = append(buf, link.ConnectionType...)
	}
	return sha256.Sum256(buf), nil
}

// validateGeometry enforces the candidate invariants shared by Open, Accept,
// Replace and ComputeDigest: a PACKET/STREAM lane, 2..MaxNodes unique non-empty
// nodes, exactly one link per hop, and every hop a non-zero same-lane link with a
// usable literal ConnectionType.
func validateGeometry(lane Lane, nodes []NodeID, links []LinkRef) error {
	if !lane.Valid() {
		return fmt.Errorf("%w: lane 0x%02x", ErrInvalidLane, uint8(lane))
	}
	if len(nodes) < 2 {
		return fmt.Errorf("%w: %d nodes", ErrInvalidPath, len(nodes))
	}
	if len(nodes)-1 > MaxHops {
		return fmt.Errorf("%w: %d hops > %d", ErrHopLimit, len(nodes)-1, MaxHops)
	}
	if len(nodes) > MaxNodes {
		return fmt.Errorf("%w: %d nodes > %d (frozen PATH_OPEN node_count ceiling)", ErrHopLimit, len(nodes), MaxNodes)
	}
	if len(links) != len(nodes)-1 {
		return fmt.Errorf("%w: %d links for %d nodes", ErrInvalidPath, len(links), len(nodes))
	}
	seen := make(map[NodeID]struct{}, len(nodes))
	for index, node := range nodes {
		if node == (NodeID{}) {
			return fmt.Errorf("%w: node %d is empty", ErrInvalidNode, index)
		}
		if _, duplicate := seen[node]; duplicate {
			return fmt.Errorf("%w: node %d", ErrDuplicateNode, index)
		}
		seen[node] = struct{}{}
	}
	for index, link := range links {
		if link.ID == 0 || link.Epoch == 0 {
			return fmt.Errorf("%w: hop %d has a zero LinkID/LinkEpoch", ErrInvalidPath, index)
		}
		if link.LaneID != byte(lane) {
			return fmt.Errorf("%w: hop %d lane 0x%02x does not match path lane %s", ErrInvalidLane, index, link.LaneID, lane)
		}
		if err := validateConnectionType(link.ConnectionType); err != nil {
			return fmt.Errorf("%w: hop %d: %v", ErrInvalidPath, index, err)
		}
	}
	return nil
}

// validateConnectionType mirrors the authenticated LinkFact literal type rule:
// non-empty, valid UTF-8, no NUL, never normalized. ConnectionType is
// descriptive metadata, not identity or a permission grant.
func validateConnectionType(connectionType string) error {
	if connectionType == "" {
		return errors.New("empty link connection type")
	}
	if len(connectionType) > math.MaxUint16 {
		return fmt.Errorf("link connection type length %d", len(connectionType))
	}
	if !utf8.ValidString(connectionType) {
		return errors.New("link connection type is not valid UTF-8")
	}
	if strings.IndexByte(connectionType, 0) >= 0 {
		return errors.New("link connection type contains NUL")
	}
	return nil
}

func sameNodes(a, b []NodeID) bool {
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

// Path is an immutable handle for one installed path generation. Getters return
// caller-owned copies, so a handle never aliases manager state. A handle whose
// generation was replaced keeps the geometry it was created with; State reports
// Closed once the path is closed.
type Path struct {
	manager     *Manager
	id          uint64
	generation  uint32
	lane        Lane
	viewVersion uint64
	freshness   Freshness
	nodes       []NodeID
	links       []LinkRef
	digest      [32]byte
	state       State
}

// ID returns the PathID.
func (p Path) ID() uint64 { return p.id }

// Generation returns the PathGeneration.
func (p Path) Generation() uint32 { return p.generation }

// Lane returns the data lane.
func (p Path) Lane() Lane { return p.lane }

// ViewVersion returns the RouteView version this path was selected from.
func (p Path) ViewVersion() uint64 { return p.viewVersion }

// Freshness returns the RouteView freshness recorded at selection time.
func (p Path) Freshness() Freshness { return p.freshness }

// Digest returns the PathDigest bound to this generation.
func (p Path) Digest() [32]byte { return p.digest }

// Nodes returns a copy of the ordered node list (source first).
func (p Path) Nodes() []NodeID { return append([]NodeID(nil), p.nodes...) }

// Links returns a copy of the ordered hop LinkRefs.
func (p Path) Links() []LinkRef { return append([]LinkRef(nil), p.links...) }

// Destination returns the target node of this path.
func (p Path) Destination() NodeID {
	if len(p.nodes) == 0 {
		return NodeID{}
	}
	return p.nodes[len(p.nodes)-1]
}

// State returns the current state of this exact (PathID, Generation). Once the
// generation was replaced (Replace advanced it, or Accept installed a higher
// one), retired by generation exhaustion, or closed, the handle reports
// StateClosed: that generation is no longer installed. A handle for an unknown
// PathID reports the state it was created with.
func (p Path) State() State {
	if p.manager == nil {
		return p.state
	}
	manager := p.manager
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if record, ok := manager.records[p.id]; ok {
		if record.generation == p.generation {
			return record.state
		}
		return StateClosed
	}
	if _, known := manager.ledger[p.id]; known {
		return StateClosed
	}
	return p.state
}

// OpenFrame returns the PATH_OPEN ROUTE_CTRL payload for this path and arms the
// local open attempt: the first call moves Created to OpenPending. Re-encoding
// while OpenPending is idempotent and returns identical bytes, which is what a
// PATH_OPEN retransmission needs. PATH_OPEN is only valid before the path is
// Ready/Active/Broken/Closed.
func (p Path) OpenFrame() ([]byte, error) {
	if p.manager == nil {
		return nil, ErrNotFound
	}
	manager := p.manager
	manager.mu.Lock()
	defer manager.mu.Unlock()
	record, err := manager.recordLocked(p.id, p.generation)
	if err != nil {
		return nil, err
	}
	switch record.state {
	case StateCreated:
		record.state = StateOpenPending
	case StateOpenPending:
		// Idempotent PATH_OPEN retransmission.
	case StateClosed:
		return nil, ErrClosed
	default:
		return nil, fmt.Errorf("%w: PATH_OPEN from %s", ErrState, record.state)
	}
	return PathOpen{
		PathID:      record.id,
		Generation:  record.generation,
		Lane:        record.lane,
		ViewVersion: record.viewVersion,
		Nodes:       append([]NodeID(nil), record.nodes...),
		Links:       linkInstances(record.links),
		Digest:      record.digest,
	}.Encode()
}

// ReadyFrame returns the PATH_READY ROUTE_CTRL payload this hop sends for the
// path. It is a pure encoder: the local transition is explicit through
// MarkReady (source side) or MarkActive (target/hop side). It is valid while the
// path is OpenPending/Ready/Active so a duplicate PATH_READY can be re-sent.
func (p Path) ReadyFrame(status ReadyStatus, code ErrorCode) ([]byte, error) {
	if p.manager == nil {
		return nil, ErrNotFound
	}
	manager := p.manager
	manager.mu.Lock()
	defer manager.mu.Unlock()
	record, err := manager.recordLocked(p.id, p.generation)
	if err != nil {
		return nil, err
	}
	switch record.state {
	case StateOpenPending, StateReady, StateActive:
	case StateClosed:
		return nil, ErrClosed
	default:
		return nil, fmt.Errorf("%w: PATH_READY from %s", ErrState, record.state)
	}
	return PathReady{
		PathID:     record.id,
		Generation: record.generation,
		Lane:       record.lane,
		Digest:     record.digest,
		Status:     status,
		Code:       code,
	}.Encode()
}

// BrokenFrame returns the PATH_BROKEN ROUTE_CTRL payload for the path. It is a
// pure encoder; use Fail or MarkBroken for the local transition. failedCursor
// must address a node of this path.
func (p Path) BrokenFrame(reason BrokenReason, failedCursor uint8) ([]byte, error) {
	if p.manager == nil {
		return nil, ErrNotFound
	}
	manager := p.manager
	manager.mu.Lock()
	defer manager.mu.Unlock()
	record, err := manager.recordLocked(p.id, p.generation)
	if err != nil {
		return nil, err
	}
	if record.state == StateClosed {
		return nil, ErrClosed
	}
	if !reason.Valid() {
		return nil, fmt.Errorf("%w: PATH_BROKEN reason 0x%04x", ErrProtocol, uint16(reason))
	}
	if int(failedCursor) >= len(record.nodes) {
		return nil, fmt.Errorf("%w: PATH_BROKEN failed_cursor %d outside 0..%d", ErrProtocol, failedCursor, len(record.nodes)-1)
	}
	return PathBroken{
		PathID:       record.id,
		Generation:   record.generation,
		Lane:         record.lane,
		Digest:       record.digest,
		Reason:       reason,
		FailedCursor: failedCursor,
	}.Encode()
}

// MarkReady applies a received PATH_READY to this source-side path. READY and
// ALREADY move OpenPending to Ready; REJECT and ROLLED_BACK move it to Broken.
// A duplicate READY on an already Ready/Active path is a no-op and never
// downgrades it. The message identity (PathID, Generation, Lane, PathDigest) is
// checked before any state change.
func (p Path) MarkReady(message PathReady) error {
	if err := message.validate(); err != nil {
		return err
	}
	if p.manager == nil {
		return ErrNotFound
	}
	if message.PathID != p.id || message.Lane != p.lane {
		return fmt.Errorf("%w: PATH_READY %d/%d %s does not match path %d/%d %s",
			ErrPathMismatch, message.PathID, message.Generation, message.Lane, p.id, p.generation, p.lane)
	}
	if message.Generation != p.generation {
		if message.Generation < p.generation {
			return fmt.Errorf("%w: PATH_READY generation %d < %d", ErrPathGenerationExpired, message.Generation, p.generation)
		}
		return fmt.Errorf("%w: PATH_READY generation %d > %d", ErrPathMismatch, message.Generation, p.generation)
	}
	manager := p.manager
	manager.mu.Lock()
	defer manager.mu.Unlock()
	record, err := manager.recordLocked(p.id, p.generation)
	if err != nil {
		return err
	}
	if message.Digest != record.digest {
		return fmt.Errorf("%w: PATH_READY digest does not match installed path", ErrPathDigestMismatch)
	}
	switch record.state {
	case StateOpenPending:
		if message.Status == ReadyStatusReady || message.Status == ReadyStatusAlready {
			record.state = StateReady
			return nil
		}
		record.state = StateBroken
		return nil
	case StateReady, StateActive:
		// Duplicate READY: idempotent, never a downgrade.
		return nil
	case StateClosed:
		return ErrClosed
	default:
		return fmt.Errorf("%w: PATH_READY in state %s", ErrState, record.state)
	}
}

// MarkActive records that the upper layer committed the matching SESSION_READY
// on this path. OpenPending (hop/target role) and Ready (source role) both
// promote to Active; Active is idempotent; Broken and Closed never resurrect.
func (p Path) MarkActive() error {
	if p.manager == nil {
		return ErrNotFound
	}
	manager := p.manager
	manager.mu.Lock()
	defer manager.mu.Unlock()
	record, err := manager.recordLocked(p.id, p.generation)
	if err != nil {
		return err
	}
	switch record.state {
	case StateOpenPending, StateReady:
		record.state = StateActive
		return nil
	case StateActive:
		return nil
	case StateClosed:
		return ErrClosed
	default:
		return fmt.Errorf("%w: mark active from %s", ErrState, record.state)
	}
}

// MarkBroken applies a received PATH_BROKEN to this path. The message identity
// and digest are checked first; the failed cursor must address a node of this
// path. Broken is terminal and idempotent.
func (p Path) MarkBroken(message PathBroken) error {
	if err := message.validate(); err != nil {
		return err
	}
	if p.manager == nil {
		return ErrNotFound
	}
	if message.PathID != p.id || message.Lane != p.lane {
		return fmt.Errorf("%w: PATH_BROKEN %d/%d %s does not match path %d/%d %s",
			ErrPathMismatch, message.PathID, message.Generation, message.Lane, p.id, p.generation, p.lane)
	}
	if message.Generation != p.generation {
		if message.Generation < p.generation {
			return fmt.Errorf("%w: PATH_BROKEN generation %d < %d", ErrPathGenerationExpired, message.Generation, p.generation)
		}
		return fmt.Errorf("%w: PATH_BROKEN generation %d > %d", ErrPathMismatch, message.Generation, p.generation)
	}
	manager := p.manager
	manager.mu.Lock()
	defer manager.mu.Unlock()
	record, err := manager.recordLocked(p.id, p.generation)
	if err != nil {
		return err
	}
	if message.Digest != record.digest {
		return fmt.Errorf("%w: PATH_BROKEN digest does not match installed path", ErrPathDigestMismatch)
	}
	if int(message.FailedCursor) >= len(record.nodes) {
		return fmt.Errorf("%w: PATH_BROKEN failed_cursor %d outside 0..%d", ErrProtocol, message.FailedCursor, len(record.nodes)-1)
	}
	if record.state == StateClosed {
		return ErrClosed
	}
	record.state = StateBroken
	return nil
}

// Fail records a locally detected path failure without a received message.
// Broken is terminal and idempotent; Closed stays closed.
func (p Path) Fail(reason BrokenReason, failedCursor uint8) error {
	if !reason.Valid() {
		return fmt.Errorf("%w: broken reason 0x%04x", ErrProtocol, uint16(reason))
	}
	if p.manager == nil {
		return ErrNotFound
	}
	manager := p.manager
	manager.mu.Lock()
	defer manager.mu.Unlock()
	record, err := manager.recordLocked(p.id, p.generation)
	if err != nil {
		return err
	}
	if int(failedCursor) >= len(record.nodes) {
		return fmt.Errorf("%w: failed cursor %d outside 0..%d", ErrProtocol, failedCursor, len(record.nodes)-1)
	}
	switch record.state {
	case StateBroken:
		return nil
	case StateClosed:
		return ErrClosed
	default:
		record.state = StateBroken
		return nil
	}
}

// Replace re-selects a candidate from the current RouteView for the same
// destination and lane and installs it as the next generation of this path: the
// PathID is kept and Generation increments, except at the u32 ceiling where this
// path is retired and a brand-new PathID with Generation 1 is allocated (the old
// PathID is never reused). The previous generation is only replaced after the
// new candidate validated, so a failure leaves the installed path untouched.
// RouteView updates never migrate a path on their own; existing streams are the
// upper layer's responsibility.
func (p Path) Replace(ctx context.Context, policy RoutePolicy) (Path, error) {
	if ctx == nil {
		return Path{}, fmt.Errorf("%w: nil context", ErrInvalidPath)
	}
	if p.manager == nil {
		return Path{}, ErrNotFound
	}
	manager := p.manager
	if err := ctx.Err(); err != nil {
		return Path{}, err
	}
	manager.mu.Lock()
	entry, err := manager.recordLocked(p.id, p.generation)
	if err != nil {
		manager.mu.Unlock()
		return Path{}, err
	}
	if !replaceable(entry.state) {
		state := entry.state
		manager.mu.Unlock()
		return Path{}, fmt.Errorf("%w: replace from %s", ErrState, state)
	}
	if entry.accepted {
		manager.mu.Unlock()
		return Path{}, fmt.Errorf("%w: a path installed from PATH_OPEN is replaced by the source's next PATH_OPEN", ErrState)
	}
	destination := entry.nodes[len(entry.nodes)-1]
	lane := entry.lane
	beforeGeneration := entry.generation
	beforeDigest := entry.digest
	manager.mu.Unlock()

	candidate, err := manager.selectCandidate(ctx, destination, lane, policy)
	if err != nil {
		return Path{}, err
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	entry, err = manager.recordLocked(p.id, p.generation)
	if err != nil {
		return Path{}, err
	}
	// Another Replace or a peer PATH_OPEN may have moved this path while the
	// RouteView was queried: never overwrite that newer generation.
	if entry.generation != beforeGeneration {
		return Path{}, fmt.Errorf("%w: path %d moved to generation %d while replacing", ErrPathGenerationExpired, entry.id, entry.generation)
	}
	if entry.digest != beforeDigest {
		return Path{}, fmt.Errorf("%w: path %d changed while replacing", ErrState, entry.id)
	}
	if !replaceable(entry.state) {
		return Path{}, fmt.Errorf("%w: replace from %s", ErrState, entry.state)
	}
	nextID, nextGeneration := entry.id, entry.generation
	retireOld := false
	if nextGeneration == math.MaxUint32 {
		allocated, err := manager.allocateIDLocked()
		if err != nil {
			return Path{}, err
		}
		nextID, nextGeneration = allocated, 1
		retireOld = true
	} else {
		nextGeneration++
	}
	next := &record{
		id:          nextID,
		generation:  nextGeneration,
		lane:        lane,
		viewVersion: candidate.viewVersion,
		freshness:   candidate.freshness,
		nodes:       candidate.nodes,
		links:       candidate.links,
		state:       StateCreated,
	}
	next.digest, err = ComputeDigest(nextID, nextGeneration, lane, candidate.viewVersion, next.nodes, next.links)
	if err != nil {
		return Path{}, err
	}
	if retireOld {
		delete(manager.records, entry.id)
		manager.ledger[entry.id] = ledgerRetired
	}
	manager.records[nextID] = next
	manager.ledger[nextID] = ledgerLive
	return manager.handleLocked(next), nil
}

// Close releases this path. Closed is terminal and Close is idempotent: closing
// an already closed path returns nil. A retired (generation-exhausted) path also
// reports success, because it is already gone.
func (p Path) Close() error {
	if p.manager == nil {
		return ErrNotFound
	}
	manager := p.manager
	manager.mu.Lock()
	defer manager.mu.Unlock()
	record, ok := manager.records[p.id]
	if !ok {
		switch manager.ledger[p.id] {
		case ledgerLive, ledgerRetired, ledgerClosed:
			return nil
		default:
			return fmt.Errorf("%w: path %d", ErrNotFound, p.id)
		}
	}
	if record.generation != p.generation {
		return fmt.Errorf("%w: close generation %d, installed %d", ErrPathGenerationExpired, p.generation, record.generation)
	}
	record.state = StateClosed
	delete(manager.records, p.id)
	manager.ledger[p.id] = ledgerClosed
	return nil
}

type ledgerState uint8

const (
	ledgerLive ledgerState = iota
	ledgerRetired
	ledgerClosed
)

type record struct {
	id          uint64
	generation  uint32
	lane        Lane
	viewVersion uint64
	freshness   Freshness
	nodes       []NodeID
	links       []LinkRef
	digest      [32]byte
	state       State
	// accepted marks a hop/target-side path installed from a received
	// PATH_OPEN. Its candidate is chosen by the source, so a local Replace
	// would be meaningless and is rejected.
	accepted bool
}

// replaceable reports whether Replace may install the next generation from the
// current state. Created/OpenPending/Ready/Active may be replaced; Broken and
// Closed are terminal.
func replaceable(state State) bool {
	switch state {
	case StateCreated, StateOpenPending, StateReady, StateActive:
		return true
	default:
		return false
	}
}

// candidate is a validated RouteView candidate owned by the manager.
type candidate struct {
	lane        Lane
	viewVersion uint64
	freshness   Freshness
	nodes       []NodeID
	links       []LinkRef
}

// Manager owns the local Path table and the PathID ledger. It is safe for
// concurrent use. It never migrates an installed path on its own: RouteView
// updates only affect later Open/Replace selections.
type Manager struct {
	local  NodeID
	view   *RouteView
	active func(LinkRef) bool
	rand   func([]byte) error

	rebuild chan struct{}

	mu      sync.Mutex
	records map[uint64]*record
	ledger  map[uint64]ledgerState
	closed  bool
}

// NewManager builds a Path manager for the local node. view must be the current
// RouteView for this node, and active is the synchronous local check for one
// hop's LinkRef instance: it must only inspect an in-memory active-link snapshot,
// perform no network I/O, and be safe for concurrent use. It is called for every
// hop before a path is installed, in addition to the RouteView's own CONTROL
// bootstrap check.
func NewManager(local NodeID, view *RouteView, active func(LinkRef) bool) (*Manager, error) {
	if local == (NodeID{}) {
		return nil, fmt.Errorf("%w: empty local node", ErrInvalidNode)
	}
	if view == nil {
		return nil, fmt.Errorf("%w: nil RouteView", ErrInvalidPath)
	}
	if active == nil {
		return nil, fmt.Errorf("%w: nil active-link callback", ErrInvalidPath)
	}
	return &Manager{
		local:   local,
		view:    view,
		active:  active,
		rand:    readCSPRNG,
		rebuild: make(chan struct{}, MaxConcurrentRebuilds),
		records: make(map[uint64]*record),
		ledger:  make(map[uint64]ledgerState),
	}, nil
}

// Open selects the first candidate the RouteView returns for dst and lane,
// validates every hop, allocates a fresh non-zero CSPRNG PathID with
// Generation 1, and installs the path in Created state. The candidate's
// ViewVersion, nodes, LinkRefs and PathDigest are bound to the new path. A
// rejected candidate installs nothing. context cancellation and deadlines are
// honored before selection, during hop confirmation, and before the install.
func (m *Manager) Open(ctx context.Context, dst NodeID, lane Lane, policy RoutePolicy) (Path, error) {
	if ctx == nil {
		return Path{}, fmt.Errorf("%w: nil context", ErrInvalidPath)
	}
	if !lane.Valid() {
		return Path{}, fmt.Errorf("%w: lane 0x%02x", ErrInvalidLane, uint8(lane))
	}
	if dst == (NodeID{}) {
		return Path{}, fmt.Errorf("%w: empty destination", ErrInvalidNode)
	}
	if dst == m.local {
		return Path{}, fmt.Errorf("%w: destination is the local node", ErrInvalidNode)
	}
	if err := ctx.Err(); err != nil {
		return Path{}, err
	}
	selected, err := m.selectCandidate(ctx, dst, lane, policy)
	if err != nil {
		return Path{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Path{}, ErrClosed
	}
	if len(m.records) >= MaxPaths {
		return Path{}, fmt.Errorf("%w: path table limit %d", ErrResourceLimit, MaxPaths)
	}
	id, err := m.allocateIDLocked()
	if err != nil {
		return Path{}, err
	}
	installed := &record{
		id:          id,
		generation:  1,
		lane:        lane,
		viewVersion: selected.viewVersion,
		freshness:   selected.freshness,
		nodes:       selected.nodes,
		links:       selected.links,
		state:       StateCreated,
	}
	installed.digest, err = ComputeDigest(id, installed.generation, lane, selected.viewVersion, installed.nodes, installed.links)
	if err != nil {
		return Path{}, err
	}
	m.records[id] = installed
	m.ledger[id] = ledgerLive
	return m.handleLocked(installed), nil
}

// Accept installs the target-side path described by a received PATH_OPEN. The
// caller must resolve one LinkRef per hop from its own authenticated LinkFacts
// (PATH_OPEN only carries LinkID/LinkEpoch), in hop order; Accept then checks the
// pairs, the lane, the geometry, the local target role and the recomputed
// PathDigest, and confirms every hop with the active callback before any state
// change. A repeated PATH_OPEN with the same generation and digest is idempotent;
// a higher generation of the same PathID replaces the installed record. Per-hop
// relay forwarding state (cursor advance) is not part of this module.
func (m *Manager) Accept(ctx context.Context, open PathOpen, links []LinkRef) (Path, error) {
	if ctx == nil {
		return Path{}, fmt.Errorf("%w: nil context", ErrInvalidPath)
	}
	if err := ctx.Err(); err != nil {
		return Path{}, err
	}
	if err := open.validate(); err != nil {
		return Path{}, err
	}
	if len(links) != len(open.Links) {
		return Path{}, fmt.Errorf("%w: %d resolved links for %d hops", ErrInvalidPath, len(links), len(open.Links))
	}
	resolved := make([]LinkRef, len(links))
	copy(resolved, links)
	for index, pair := range open.Links {
		if resolved[index].ID != pair.ID || resolved[index].Epoch != pair.Epoch {
			return Path{}, fmt.Errorf("%w: hop %d resolved %d/%d, PATH_OPEN %d/%d",
				ErrLinkMismatch, index, resolved[index].ID, resolved[index].Epoch, pair.ID, pair.Epoch)
		}
	}
	if err := validateGeometry(open.Lane, open.Nodes, resolved); err != nil {
		return Path{}, err
	}
	if open.Nodes[len(open.Nodes)-1] != m.local {
		return Path{}, fmt.Errorf("%w: PATH_OPEN target is not the local node", ErrInvalidPath)
	}
	digest, err := ComputeDigest(open.PathID, open.Generation, open.Lane, open.ViewVersion, open.Nodes, resolved)
	if err != nil {
		return Path{}, err
	}
	if digest != open.Digest {
		return Path{}, fmt.Errorf("%w: PATH_OPEN digest does not match the resolved nodes/links", ErrPathDigestMismatch)
	}
	if err := ctx.Err(); err != nil {
		return Path{}, err
	}
	for index, link := range resolved {
		if err := ctx.Err(); err != nil {
			return Path{}, err
		}
		if !m.active(link) {
			return Path{}, fmt.Errorf("%w: hop %d link %d epoch %d", ErrInactiveLink, index, link.ID, link.Epoch)
		}
	}
	nodes := append([]NodeID(nil), open.Nodes...)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Path{}, ErrClosed
	}
	if existing, ok := m.records[open.PathID]; ok {
		if open.Generation == existing.generation {
			if open.Lane != existing.lane || digest != existing.digest || !sameNodes(existing.nodes, nodes) {
				return Path{}, fmt.Errorf("%w: PATH_OPEN %d/%d conflicts with the installed path", ErrPathConflict, open.PathID, open.Generation)
			}
			return m.handleLocked(existing), nil
		}
		if open.Generation < existing.generation {
			return Path{}, fmt.Errorf("%w: PATH_OPEN generation %d < installed %d", ErrPathGenerationExpired, open.Generation, existing.generation)
		}
		existing.generation = open.Generation
		existing.lane = open.Lane
		existing.viewVersion = open.ViewVersion
		existing.freshness = topology.RouteViewFresh
		existing.nodes = nodes
		existing.links = resolved
		existing.digest = digest
		existing.state = StateOpenPending
		existing.accepted = true
		return m.handleLocked(existing), nil
	}
	switch m.ledger[open.PathID] {
	case ledgerClosed:
		return Path{}, fmt.Errorf("%w: path %d", ErrClosed, open.PathID)
	case ledgerRetired:
		return Path{}, fmt.Errorf("%w: path %d was retired", ErrPathGenerationExpired, open.PathID)
	}
	if len(m.records) >= MaxPaths {
		return Path{}, fmt.Errorf("%w: path table limit %d", ErrResourceLimit, MaxPaths)
	}
	if len(m.ledger) >= MaxIssuedPathIDs {
		return Path{}, fmt.Errorf("%w: path id ledger limit %d", ErrResourceLimit, MaxIssuedPathIDs)
	}
	installed := &record{
		id:          open.PathID,
		generation:  open.Generation,
		lane:        open.Lane,
		viewVersion: open.ViewVersion,
		freshness:   topology.RouteViewFresh,
		nodes:       nodes,
		links:       resolved,
		digest:      digest,
		state:       StateOpenPending,
		accepted:    true,
	}
	m.records[installed.id] = installed
	m.ledger[installed.id] = ledgerLive
	return m.handleLocked(installed), nil
}

// Lookup returns the handle for one installed (PathID, Generation).
func (m *Manager) Lookup(id uint64, generation uint32) (Path, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, err := m.recordLocked(id, generation)
	if err != nil {
		return Path{}, err
	}
	return m.handleLocked(record), nil
}

// Snapshot returns deep copies of the live paths ordered by PathID. Closed and
// retired paths are not included.
func (m *Manager) Snapshot() []Path {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]uint64, 0, len(m.records))
	for id := range m.records {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	paths := make([]Path, 0, len(ids))
	for _, id := range ids {
		paths = append(paths, m.handleLocked(m.records[id]))
	}
	return paths
}

// Close releases every installed path and the manager. It is idempotent;
// afterwards every Open/Accept/Replace attempt fails with ErrClosed and
// Snapshot is empty.
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	for id, record := range m.records {
		record.state = StateClosed
		m.ledger[id] = ledgerClosed
		delete(m.records, id)
	}
	return nil
}

// selectCandidate consumes one rebuild slot, queries the RouteView for the
// destination and lane, and validates the first candidate. It returns an owned
// candidate copy: no slice aliases the RouteView.
func (m *Manager) selectCandidate(ctx context.Context, dst NodeID, lane Lane, policy RoutePolicy) (candidate, error) {
	if err := ctx.Err(); err != nil {
		return candidate{}, err
	}
	if !m.acquireRebuild() {
		return candidate{}, fmt.Errorf("%w: %d concurrent rebuilds in progress", ErrResourceLimit, MaxConcurrentRebuilds)
	}
	defer m.releaseRebuild()

	paths, err := m.view.Candidates(dst, uint8(lane), policy)
	if err != nil {
		return candidate{}, fmt.Errorf("path: candidates for %s: %w", lane, err)
	}
	if err := ctx.Err(); err != nil {
		return candidate{}, err
	}
	selected, err := m.firstCandidate(paths, dst, lane)
	if err != nil {
		return candidate{}, err
	}
	for index, link := range selected.links {
		if err := ctx.Err(); err != nil {
			return candidate{}, err
		}
		if !m.active(link) {
			return candidate{}, fmt.Errorf("%w: hop %d link %d epoch %d", ErrInactiveLink, index, link.ID, link.Epoch)
		}
	}
	return selected, nil
}

// firstCandidate validates the first RouteView candidate for this node and lane.
// The returned slices are owned copies; nothing aliases the RouteView result.
func (m *Manager) firstCandidate(paths []topology.CandidatePath, dst NodeID, lane Lane) (candidate, error) {
	if len(paths) == 0 {
		return candidate{}, fmt.Errorf("%w: no candidate for %s", ErrInvalidPath, dst)
	}
	if len(paths) > MaxCandidates {
		return candidate{}, fmt.Errorf("%w: %d candidates > %d", ErrResourceLimit, len(paths), MaxCandidates)
	}
	first := paths[0]
	if first.LaneID != uint8(lane) {
		return candidate{}, fmt.Errorf("%w: candidate lane 0x%02x", ErrInvalidLane, first.LaneID)
	}
	selected := candidate{
		lane:        lane,
		viewVersion: first.ViewVersion,
		freshness:   first.Freshness,
		nodes:       append([]NodeID(nil), first.Nodes...),
		links:       append([]LinkRef(nil), first.Links...),
	}
	if err := validateGeometry(lane, selected.nodes, selected.links); err != nil {
		return candidate{}, err
	}
	if selected.nodes[0] != m.local {
		return candidate{}, fmt.Errorf("%w: candidate starts at %v, not the local node", ErrInvalidPath, selected.nodes[0])
	}
	if selected.nodes[len(selected.nodes)-1] != dst {
		return candidate{}, fmt.Errorf("%w: candidate ends at %v, not %v", ErrInvalidPath, selected.nodes[len(selected.nodes)-1], dst)
	}
	return selected, nil
}

func (m *Manager) acquireRebuild() bool {
	select {
	case m.rebuild <- struct{}{}:
		return true
	default:
		return false
	}
}

func (m *Manager) releaseRebuild() {
	select {
	case <-m.rebuild:
	default:
	}
}

// allocateIDLocked draws a non-zero PathID that was never issued in this process.
func (m *Manager) allocateIDLocked() (uint64, error) {
	if len(m.ledger) >= MaxIssuedPathIDs {
		return 0, fmt.Errorf("%w: path id ledger limit %d", ErrResourceLimit, MaxIssuedPathIDs)
	}
	for attempt := 0; attempt < maxPathIDAttempts; attempt++ {
		var buf [8]byte
		if err := m.rand(buf[:]); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrEntropy, err)
		}
		id := binary.BigEndian.Uint64(buf[:])
		if id == 0 {
			continue
		}
		if _, issued := m.ledger[id]; issued {
			continue
		}
		return id, nil
	}
	return 0, fmt.Errorf("%w: no unused PathID after %d attempts", ErrEntropy, maxPathIDAttempts)
}

// recordLocked resolves one handle identity against the live table and ledger.
func (m *Manager) recordLocked(id uint64, generation uint32) (*record, error) {
	if record, ok := m.records[id]; ok {
		if record.generation != generation {
			return nil, fmt.Errorf("%w: path %d generation %d, installed %d", ErrPathGenerationExpired, id, generation, record.generation)
		}
		return record, nil
	}
	switch m.ledger[id] {
	case ledgerClosed:
		return nil, fmt.Errorf("%w: path %d", ErrClosed, id)
	case ledgerRetired:
		return nil, fmt.Errorf("%w: path %d was retired", ErrPathGenerationExpired, id)
	default:
		return nil, fmt.Errorf("%w: path %d", ErrNotFound, id)
	}
}

// handleLocked builds a detached handle. The caller must hold m.mu.
func (m *Manager) handleLocked(entry *record) Path {
	return Path{
		manager:     m,
		id:          entry.id,
		generation:  entry.generation,
		lane:        entry.lane,
		viewVersion: entry.viewVersion,
		freshness:   entry.freshness,
		nodes:       append([]NodeID(nil), entry.nodes...),
		links:       append([]LinkRef(nil), entry.links...),
		digest:      entry.digest,
		state:       entry.state,
	}
}

// readCSPRNG is the CSPRNG adapter for the PathID ledger. It is a package-level
// variable-sized wrapper so tests can inject a deterministic or failing source.
func readCSPRNG(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}

func linkInstances(links []LinkRef) []LinkInstance {
	instances := make([]LinkInstance, len(links))
	for index, link := range links {
		instances[index] = LinkInstance{ID: link.ID, Epoch: link.Epoch}
	}
	return instances
}
