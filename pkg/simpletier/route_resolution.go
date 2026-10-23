package simpletier

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/yiiilin/simpletier/internal/topology"
)

// packetLaneRoute is one pinned PACKET-lane route resolution: the unique current
// owner of the destination /32, the exact AddressFact version that produced it,
// and the already-installed class-1 Path this flow egresses on. It is neutral
// between the Packet and Flow planes, which each map it onto their own port type.
// The two planes deliberately share one resolution policy so the frozen
// steady-flow-versus-new-flow rule cannot drift between them. Lane is always
// path.LanePacket and is therefore not a field.
type packetLaneRoute struct {
	destinationNode    topology.NodeID
	addressFactVersion topology.FactVersion
	pathID             uint64
	pathGeneration     uint32
}

// destinationOwner resolves the unique current owner of one destination /32 from
// the live FactStore entries, never from the immutable RouteView snapshot: a
// renewed AddressFact of the same owner must be visible to a steady flow without
// waiting for a view rebuild, and a conflict or a withdrawal must fail here
// instead of being masked by a stale view. This helper owns the route-view guard
// (rt == nil || rt.n == nil || rt.n.facts == nil || rt.n.facts.routes == nil)
// for all three of its call sites: the Packet adapter, the Flow adapter and the
// Flow endpoint directory. Keeping the guard here means it cannot be forgotten
// in one of them.
func (rt *streamRuntime) destinationOwner(destination netip.Addr) (topology.AddressResolution, error) {
	if rt == nil || rt.n == nil || rt.n.facts == nil || rt.n.facts.routes == nil {
		return topology.AddressResolution{}, fmt.Errorf("%w: no route view", topology.ErrRouteStale)
	}
	return rt.currentAddressOwner(destination)
}

// resolvePacketLaneRoute is the one PACKET-lane resolution policy the Packet and
// Flow planes share. A steady flow keeps the class-1 pair it already owns, so a
// same-owner fact renewal is not misread as route-stale; a genuinely new flow
// still selects its Path from the strict candidate graph, so an affected target
// keeps failing closed until the immutable view is rebuilt. Exact-hop and
// pinned-fact health is enforced at egress by each plane's sender immediately
// before the frame is sealed, which is why this resolver stays read-only and
// usable on the receive path too.
func (rt *streamRuntime) resolvePacketLaneRoute(ctx context.Context, destination netip.Addr) (packetLaneRoute, error) {
	owner, err := rt.destinationOwner(destination)
	if err != nil {
		return packetLaneRoute{}, err
	}
	// Checked before the pair lookup below: a Session this node answers on is
	// matched by either of its logical endpoints, so the local node must never be
	// looked up as a target.
	if [16]byte(owner.NodeID) == rt.localID {
		return packetLaneRoute{}, fmt.Errorf("%w: destination %s is the local node", topology.ErrNoRoute, destination)
	}
	// A steady flow already owns its class-1 pair: every fragment of a logical
	// datagram re-resolves the route, so requiring a rebuilt view per fragment
	// would fail the datagram as route-stale across a same-owner fact renewal.
	// This fast path is also the receive path's ownership validation: a renewed
	// same-owner NODE/LINK fact must not make an inbound packet whose inner
	// source is correctly owned look route-stale, and the exact-hop/pinned-fact
	// health is re-validated by packetSender.SendPacket immediately before the
	// frame is sealed.
	if pair, ok := rt.existingPacketPair(owner.NodeID); ok {
		return packetLaneRoute{
			destinationNode:    owner.NodeID,
			addressFactVersion: owner.FactVersion,
			pathID:             pair.ps.scope.id,
			pathGeneration:     pair.ps.scope.gen,
		}, nil
	}
	// A genuinely new flow still selects its Path from the strict PACKET
	// candidate graph, so an affected target keeps returning
	// RouteStale/RouteConflict until the immutable view is rebuilt. No candidate
	// is ever taken from a stale view: this is the frozen rule C-ROUTE-003 (view
	// changes affect only new flows), which is the spec rule this whole split
	// preserves.
	resolved, err := rt.n.facts.routes.PacketCandidates(destination, topology.RoutePolicy{AllowRelay: rt.relay})
	if err != nil {
		return packetLaneRoute{}, err
	}
	if len(resolved.Candidates) == 0 {
		return packetLaneRoute{}, fmt.Errorf("%w: no PACKET candidate for %s", topology.ErrNoRoute, destination)
	}
	target := resolved.DestinationNode
	// The candidate query resolves the owner against the same live store, so a
	// disagreement means the mapping moved between the two reads. Failing closed
	// keeps one owner's version from being paired with another owner's Path; the
	// flow is never re-routed to the newer NodeID.
	if target != owner.NodeID {
		return packetLaneRoute{}, fmt.Errorf("%w: owner %x became %x while resolving %s",
			topology.ErrRouteStale, owner.NodeID, target, destination)
	}
	pair, err := rt.packetPairFor(ctx, target)
	if err != nil {
		return packetLaneRoute{}, err
	}
	return packetLaneRoute{
		destinationNode:    target,
		addressFactVersion: owner.FactVersion,
		pathID:             pair.ps.scope.id,
		pathGeneration:     pair.ps.scope.gen,
	}, nil
}
