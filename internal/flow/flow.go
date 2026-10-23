// Package flow owns the P1 Flow-plane UDP datagram core: bounded
// fragmentation, reassembly, endpoint-ownership validation, DatagramID
// consumption and buffer accounting for MessageType=UDP_DATAGRAM E2E frames.
//
// It implements the frozen Flow UDP_DATAGRAM segmentation v1 of
// docs/domains/overlay/modules/wire-protocol.md and R-MESH-010 / 3.5 / 3.8 of
// docs/domains/overlay/features/multiprotocol-overlay.md. It adds no wire
// field, no MessageType and no FrameKind, and it never touches L3 IP_PACKET
// fragmentation/MTU handling.
//
// Boundaries. This package performs no cryptography, no frame encoding and no
// network I/O. A caller may only hand it fragments that already passed hop
// AEAD, E2E AEAD, envelope authentication and session auth; nothing here ever
// sees an unauthenticated frame, and a Relay never instantiates a Manager or
// reassembles/decrypts anything. Everything that performs I/O is an injected
// port: egress dispatch (Sender), target endpoint delivery (Delivery), the
// current VirtualIP /32 owner map (EndpointDirectory), the pinned PACKET-lane
// route (RouteResolver) and shared buffer accounting (BufferBudget).
package flow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/topology"
)

// Frozen P1 Flow UDP bounds (wire-protocol.md segmentation v1, R-MESH-010,
// multiprotocol-overlay.md 3.8 table). Values may only be lowered by an
// implementation, never raised.
const (
	// FixedMetadataLen is the fixed UDP_DATAGRAM metadata:
	// AssociationID16|flags1|DatagramID8|fragment_index1|fragment_count1|
	// total_payload_len2|source IPv4 4|source port2|destination IPv4 4|
	// destination port2.
	FixedMetadataLen = 41
	// MaxFragmentPayload is the frozen per-fragment payload ceiling: the
	// 65,386-byte E2E plaintext payload cap minus the 41-byte metadata.
	MaxFragmentPayload = 65345
	// MaxDatagramPayload is the largest IPv4 UDP socket payload: 65,507 bytes.
	MaxDatagramPayload = 65507
	// MaxFramePayload is the largest complete UDP_DATAGRAM plaintext payload;
	// the E2E layer adds its own AEAD tag beyond this.
	MaxFramePayload = FixedMetadataLen + MaxFragmentPayload
	// MaxFragmentsPerDatagram is the frozen segmentation arity.
	MaxFragmentsPerDatagram = 2
	// MaxUDPAssociations is the frozen per-Network UDP association cap.
	MaxUDPAssociations = 256
	// AssociationIdleTTL is both the UDP association idle bound and the
	// incomplete-assembly TTL measured from the first fragment (never extended
	// by later fragments).
	AssociationIdleTTL = 120 * time.Second
	// MaxNetworkAssemblies is the frozen reassembly distribution bound: 256
	// associations x at most one incomplete assembly per direction = 512
	// outstanding buffers, whose payload ceiling is 256*2*65,507 = 33,539,584
	// bytes (R-MESH-010, multiprotocol-overlay.md 3.8).
	MaxNetworkAssemblies = 2 * MaxUDPAssociations
	// DefaultLocalBufferBudget is a local self-bound only: the frozen
	// 33,539,584-byte reassembly payload ceiling (256*2*65,507). It bounds
	// reassembly payload bytes and does NOT claim to enforce the shared Network
	// 64 MiB data / 256 MiB heap budgets; a runtime must inject BufferBudget for
	// that. Peer state (1024-bit replay windows and the peer map) is
	// Network-owned heap/state that the future runtime adapter must charge to
	// the 256 MiB heap budget; this package does not account it yet.
	DefaultLocalBufferBudget = uint64(MaxDatagramPayload) * 2 * MaxUDPAssociations
	// MaxClosedAssociationLedger is a LOCAL record limit for recently-closed
	// AssociationIDs, not a frozen or approved spec figure; a runtime may lower
	// it to fit the Network state budget. It must never be raised by silently
	// evicting an entry that has not yet reached AssociationIdleTTL: while it is
	// full, association creation fails with ErrResourceLimit until an entry
	// expires.
	MaxClosedAssociationLedger = 4096
	// MaxPeersPerAssociation bounds the per-peer inbound state one association
	// keeps. It is an implementation bound derived from the shared 256-association
	// cap, not a frozen value, and it is NOT the aggregate limit: the aggregate
	// is MaxNetworkAssemblies buffers plus the buffer budget above.
	MaxPeersPerAssociation = MaxUDPAssociations
)

// Frozen sentinels. Callers classify with errors.Is.
var (
	ErrInvalidConfig       = errors.New("flow: invalid configuration")
	ErrClosed              = errors.New("flow: manager closed")
	ErrAssociationClosed   = errors.New("flow: association closed")
	ErrDatagramTooLarge    = errors.New("flow: datagram exceeds the 65,507-byte IPv4 UDP payload limit")
	ErrFrameMalformed      = errors.New("flow: UDP_DATAGRAM frame malformed")
	ErrOwnership           = errors.New("flow: endpoint ownership or direction rejected")
	ErrUnknownAssociation  = errors.New("flow: no local association for the inbound direction")
	ErrResourceLimit       = errors.New("flow: flow resource limit exceeded")
	ErrRouteChanged        = errors.New("flow: pinned route changed before egress")
	ErrDatagramIDExhausted = errors.New("flow: DatagramID exhausted; an association must never wrap")
	ErrNoReplyAuthority    = errors.New("flow: datagram carries no reply authority")
	ErrReplyUnavailable    = errors.New("flow: reply association is no longer available")
)

// Flags is the frozen UDP_DATAGRAM flags byte: REQUEST=0x00 from the
// association originator, REPLY=0x01 back to it. Any other value rejects the
// datagram.
type Flags uint8

const (
	FlagRequest Flags = 0x00
	FlagReply   Flags = 0x01
)

func (f Flags) valid() bool { return f == FlagRequest || f == FlagReply }

func (f Flags) String() string {
	switch f {
	case FlagRequest:
		return "REQUEST"
	case FlagReply:
		return "REPLY"
	default:
		return fmt.Sprintf("flags(0x%02x)", uint8(f))
	}
}

// AssocID is the 16-byte CSPRNG UDP association identifier.
type AssocID [16]byte

func (id AssocID) String() string { return fmt.Sprintf("%x", id[:]) }

// AuthenticatedEnvelope is the already-verified identity of one inbound E2E
// frame. Constructing it asserts that hop AEAD, E2E AEAD, replay and origin
// authentication all succeeded; this package performs none of that.
type AuthenticatedEnvelope struct {
	NetworkID uint64
	SrcNodeID topology.NodeID
	DstNodeID topology.NodeID
}

// EndpointOwner is the current owner of one VirtualIP /32 in the authenticated
// Fact owner map, together with that AddressFact version.
type EndpointOwner struct {
	Owner   topology.NodeID
	Version topology.FactVersion
}

// EndpointDirectory is the injected ownership port: the current unique /32
// owner and AddressFact version for a metadata address. The future runtime
// adapts topology.RouteView.ResolveVirtualIP onto it. It must be safe for
// concurrent use and must not perform network I/O.
type EndpointDirectory interface {
	LookupEndpoint(ctx context.Context, ip netip.Addr) (EndpointOwner, bool)
}

// DatagramRoute is one pinned PACKET-lane result for a logical datagram. It is
// immutable for that datagram: a changed owner, version or lane drops the
// datagram instead of re-routing it.
type DatagramRoute struct {
	DestinationNode    topology.NodeID
	AddressFactVersion topology.FactVersion
	PathID             uint64
	PathGeneration     uint32
	Lane               path.Lane
}

// RouteResolver is the egress routing port, mirroring internal/packet's
// RouteResolver for the PACKET lane. It is called once to pin the datagram and
// again immediately before every fragment egress; the pin never changes.
type RouteResolver interface {
	ResolveDatagramRoute(ctx context.Context, destination netip.Addr) (DatagramRoute, error)
}

// OutboundDatagram is one complete logical UDP datagram to fragment and send.
// Source is the local VirtualIP and source port the adapter owns, Destination
// the peer VirtualIP and destination port. Payload length 0..65,507.
type OutboundDatagram struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	Payload     []byte
}

// SendRequest is one encoded UDP_DATAGRAM plaintext payload on its pinned
// PACKET-lane Path. The caller-provided Sender owns SessionID, KeyEpoch,
// MessageNumber, the E2E AEAD and the Link write; this package never retries
// and never re-routes a lost fragment (UDP has no business ACK).
type SendRequest struct {
	NetworkID       uint64
	SrcNodeID       topology.NodeID
	DstNodeID       topology.NodeID
	AssociationID   AssocID
	Flags           Flags
	DatagramID      uint64
	FragmentIndex   uint8
	FragmentCount   uint8
	TotalPayloadLen uint16
	PathID          uint64
	PathGeneration  uint32
	Lane            path.Lane
	// Payload is the complete 41-byte metadata plus fragment bytes, identical
	// to the E2E plaintext body. It aliases the caller's buffer only until
	// SendFragment returns; a Sender that retains it must copy it.
	Payload []byte
}

// Sender is the session egress port. Contract: exactly one dispatch attempt
// per fragment, no automatic retransmit and no re-route when a fragment is
// lost; a nil error only means the egress boundary accepted the fragment.
type Sender interface {
	SendFragment(ctx context.Context, request SendRequest) error
}

// Datagram is one reassembled logical UDP datagram handed to the destination
// endpoint exactly once. The boundary is the single call: Payload is one UDP
// socket payload with the metadata destination port and logical source peer,
// never a byte stream.
type Datagram struct {
	NetworkID     uint64
	SrcNodeID     topology.NodeID
	DstNodeID     topology.NodeID
	AssociationID AssocID
	Flags         Flags
	DatagramID    uint64
	Source        netip.AddrPort
	Destination   netip.AddrPort
	// Payload is the reassembled datagram, 0..65,507 bytes. It aliases the
	// receiver's assembly buffer and is valid only for the duration of the
	// call; a port that retains it (socket endpoint, SDK/SOCKS UDP adapter)
	// must copy it.
	Payload []byte

	// receipt is the private reply capability. Only the flow core sets it, in
	// deliver, and only for an authenticated REQUEST delivered to a live target
	// association. It never crosses a package boundary as a value the caller can
	// build or mutate.
	receipt *replyReceipt
}

// replyReceipt binds one delivered REQUEST to the exact target association
// object and the original authenticated request tuple. Reply re-checks the live
// map entry by pointer identity (manager and association), so a target
// association recreated with the same AssociationID after the 120-second window
// can never be driven by an old receipt, and it re-checks current address
// ownership so an endpoint application cannot fabricate reply authority or
// re-target a changed address. A receipt creates no manager-side registry: an
// application that retains a Datagram retains this small struct and its own
// payload copy in application scope, never Network-owned heap.
type replyReceipt struct {
	manager       *Manager
	association   *Association
	networkID     uint64
	origin        topology.NodeID
	associationID AssocID
	datagramID    uint64
	source        netip.AddrPort
	destination   netip.AddrPort
}

// Delivery is the target-endpoint write port. It is called only after
// authentication and only for a complete reassembled datagram on the owning
// endpoint; it must preserve one datagram boundary and the real destination
// port/source peer. A Delivery error does not un-consume the DatagramID.
type Delivery interface {
	DeliverDatagram(ctx context.Context, datagram Datagram) error
}

// BufferBudget is the injected shared Network allocator port (internal/budget
// is being implemented separately and is deliberately not imported here).
// Reserve is all-or-none; Release must balance exactly one successful Reserve.
type BufferBudget interface {
	Reserve(bytes uint64) error
	Release(bytes uint64)
}

// Config configures one Manager. NetworkID/ContextID/LocalNode scope the
// instance; the four I/O ports are mandatory and BufferBudget is optional.
type Config struct {
	// NetworkID is the authenticated network identity every inbound frame must
	// carry.
	NetworkID uint64
	// ContextID is the full local security context identifier (not the u64
	// wire locator). AssociationID uniqueness is scoped to
	// (ContextID, originNode).
	ContextID [32]byte
	// LocalNode is this node's authenticated NodeID.
	LocalNode topology.NodeID

	Endpoints EndpointDirectory
	Routes    RouteResolver
	Sender    Sender
	Delivery  Delivery

	// Budget is the shared allocator; nil uses a local self-bound that does not
	// claim the global Network limits.
	Budget BufferBudget
	// ClosedAssociationLedgerLimit lowers this instance's recently-closed
	// AssociationID ledger to fit the Network state budget. Zero uses
	// MaxClosedAssociationLedger; a larger value is rejected because
	// MaxClosedAssociationLedger is a local default, not a frozen budget to
	// exceed.
	ClosedAssociationLedgerLimit int
	// Rand is the CSPRNG source for AssociationID; nil uses crypto/rand.
	Rand io.Reader
	// Now is the clock; nil uses time.Now. Tests inject it for TTL bounds.
	Now func() time.Time
}

// DropReason classifies a terminal fragment/datagram discard. Successful
// delivery and any terminal discard consume the DatagramID; a failed E2E tag
// never reaches this package and never consumes anything.
type DropReason uint8

const (
	DropSchema DropReason = iota
	DropOwnership
	DropUnknownAssociation
	DropDuplicate
	DropConflict
	DropTimeout
	DropSuperseded
	DropResource
	DropTooLarge
	DropClosed
	DropRoute
	DropSend
	DropDelivery
	DropReply
	dropReasonCount
)

var dropReasonNames = [dropReasonCount]string{
	DropSchema:             "schema",
	DropOwnership:          "ownership",
	DropUnknownAssociation: "unknown-association",
	DropDuplicate:          "duplicate",
	DropConflict:           "conflict",
	DropTimeout:            "timeout",
	DropSuperseded:         "superseded",
	DropResource:           "resource",
	DropTooLarge:           "too-large",
	DropClosed:             "closed",
	DropRoute:              "route",
	DropSend:               "send",
	DropDelivery:           "delivery",
	DropReply:              "reply",
}

func (r DropReason) String() string {
	if r < dropReasonCount {
		return dropReasonNames[r]
	}
	return fmt.Sprintf("drop(%d)", uint8(r))
}

// Stats is a consistent-enough snapshot of one Manager.
type Stats struct {
	Associations       int
	Origins            int
	Targets            int
	Peers              int
	Assemblies         int
	TargetTombstones   int
	ClosedIDs          int
	LedgerReserved     int
	LedgerLimit        int
	BytesHeld          uint64
	SentDatagrams      uint64
	SentFragments      uint64
	ReceivedFragments  uint64
	DeliveredDatagrams uint64
	DeliveredBytes     uint64
	Drops              [dropReasonCount]uint64
}
