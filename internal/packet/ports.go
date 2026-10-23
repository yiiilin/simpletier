package packet

import (
	"context"
	"net/netip"

	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/topology"
)

// RouteResolver is the route/ownership port of the packet plane. The future
// runtime worker adapts the owner's topology.RouteView onto it, for example
// ResolvePacketRoute -> RouteView.PacketCandidates and a source-ownership check
// built from RouteView.ResolveVirtualIP.
//
// The implementation must return the address owner pinned to the current unique
// IPv4 /32 AddressFact together with that fact's version, and select only the
// PACKET lane. Route errors must keep their identity so this package can count
// and classify them: the topology sentinels ErrNoRoute, ErrPolicyDenied,
// ErrRouteConflict, ErrRouteStale and ErrResourceLimit are re-exported below
// and are matched with errors.Is.
//
// ResolvePacketRoute is called at least twice per Send: once to pin the attempt
// and once immediately before egress to revalidate the owner. It must be safe
// for concurrent calls and must not perform network I/O beyond the local view.
type RouteResolver interface {
	ResolvePacketRoute(ctx context.Context, destination netip.Addr) (PacketRoute, error)
}

// PacketRoute is one pinned PACKET-lane result. The packet plane treats it as
// immutable for the duration of one attempt: after pinning, a changed owner,
// version or lane drops the packet as RouteStale instead of retargeting it.
type PacketRoute struct {
	// DestinationNode is the unique current owner of the destination /32.
	DestinationNode topology.NodeID
	// AddressFactVersion pins the exact AddressFact mapping that produced
	// DestinationNode. A later, different version means the owner changed.
	AddressFactVersion topology.FactVersion
	// Lane is always path.LanePacket; any other lane is a resolver defect.
	Lane path.Lane
	// PathID and PathGeneration pin the already-installed data Path this attempt
	// egresses on. A Path failure after pinning is the runtime's concern; this
	// package never re-routes the current packet.
	PathID         uint64
	PathGeneration uint32
}

// SendRequest is one pinned PACKET-lane egress carrying a complete IPv4 packet.
// It is the payload half of the frozen E2E envelope (MessageType=IP_PACKET,
// wire-protocol.md): the caller-provided Sender owns SessionID, KeyEpoch,
// MessageNumber, the E2E AEAD and the actual Link write.
type SendRequest struct {
	DestinationNode    topology.NodeID
	AddressFactVersion topology.FactVersion
	PathID             uint64
	PathGeneration     uint32
	Lane               path.Lane
	// Payload is the complete IPv4 packet, byte-identical to what the packet
	// plane validated. It aliases the caller's slice only until Send returns;
	// a Sender that retains it must copy it.
	Payload []byte
}

// Sender is the session egress port supplied by the caller: the real E2E
// payload dispatch onto the pinned PACKET-lane Path. The packet plane does not
// encrypt, frame, schedule or retry.
//
// Contract: exactly one dispatch attempt per Send; the Sender must not replay
// or retry a packet (D-L3-004/R-L3-002 UDP/ICMP failure semantics). It must
// honour ctx cancellation and return an error only for a dispatch failure, not
// for an application-level outcome. A nil error means the packet was accepted
// by the egress boundary, never that the far side received it.
type Sender interface {
	SendPacket(ctx context.Context, request SendRequest) error
}

// ReceiverDevice is the local device write port. It is satisfied structurally
// by internal/agent.PacketDevice, but this package deliberately does not import
// that package outside tests: the device stays owned by the host adapter.
type ReceiverDevice interface {
	// WritePacket writes exactly one complete IPv4 packet. The packet plane
	// passes the validated bytes unchanged.
	WritePacket(ctx context.Context, packet []byte) error
	// MTU reports the current device MTU. Zero means the frozen default and a
	// value above DefaultDeviceMTU is clamped to the frozen ceiling. It is
	// re-read per packet so a runtime internal down-adjust is observed (the
	// value is never user configurable), and it must be safe for concurrent
	// use.
	MTU() int
}
