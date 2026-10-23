package simpletier

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/flow"
	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/topology"
	"github.com/yiiilin/simpletier/internal/wire"
)

// flowBufferBudget adapts the byte-only flow.BufferBudget port onto the shared
// internal/budget Allocator. Every successful Reserve holds one real
// *budget.Lease, so Flow assembly/association buffers are accounted inside the
// Network's frozen heap instead of a local self-bound; Release returns the
// matching lease and is idempotent per reservation. Close releases everything
// still held so a Network close leaks no bytes.
type flowBufferBudget struct {
	alloc  *budget.Allocator
	net    budget.NetworkID
	mu     sync.Mutex
	leases map[uint64][]*budget.Lease
	closed bool
}

func newFlowBufferBudget(alloc *budget.Allocator, net budget.NetworkID) *flowBufferBudget {
	return &flowBufferBudget{alloc: alloc, net: net, leases: make(map[uint64][]*budget.Lease)}
}

func (b *flowBufferBudget) Reserve(bytes uint64) error {
	if b == nil || b.alloc == nil || bytes == 0 {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return flow.ErrClosed
	}
	b.mu.Unlock()
	lease, err := b.alloc.Reserve(budget.Request{Charges: []budget.Charge{{
		Owner:    budget.NetworkPool(b.net),
		Category: budget.CategoryData,
		Bytes:    bytes,
		Frames:   1,
	}}})
	if err != nil {
		return fmt.Errorf("%w: %v", flow.ErrResourceLimit, err)
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = lease.Release()
		return flow.ErrClosed
	}
	b.leases[bytes] = append(b.leases[bytes], lease)
	b.mu.Unlock()
	return nil
}

// Release returns one reservation of exactly the reserved byte size. This port
// is byte-only, so an individual reservation cannot be identified: callers must
// balance Reserve and Release one-for-one per reserved size. Release is not
// idempotent (a second call for the same size would consume another reservation
// or be a no-op), while Close is idempotent and drains everything still held.
func (b *flowBufferBudget) Release(bytes uint64) {
	if b == nil || bytes == 0 {
		return
	}
	b.mu.Lock()
	var lease *budget.Lease
	if queue := b.leases[bytes]; len(queue) > 0 {
		last := len(queue) - 1
		lease = queue[last]
		// Clear the popped slot before reslicing so the backing array does not
		// retain the released lease, and drop the map key entirely when its queue
		// is empty so the map keeps no stale key or capacity.
		queue[last] = nil
		if last == 0 {
			delete(b.leases, bytes)
		} else {
			b.leases[bytes] = queue[:last]
		}
	}
	b.mu.Unlock()
	if lease != nil {
		_ = lease.Release()
	}
}

// Close releases every reservation still held. It is idempotent.
func (b *flowBufferBudget) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	var held []*budget.Lease
	for _, queue := range b.leases {
		held = append(held, queue...)
	}
	b.leases = make(map[uint64][]*budget.Lease)
	b.mu.Unlock()
	for _, lease := range held {
		_ = lease.Release()
	}
}

// flowEndpointDirectory adapts the Network RouteView onto the Flow plane's
// endpoint-owner port. It resolves only the pinned AddressFact owner and its
// version; a conflicting address has no single owner and is reported absent so
// the Flow plane drops the datagram instead of guessing.
type flowEndpointDirectory struct{ rt *streamRuntime }

func (d *flowEndpointDirectory) LookupEndpoint(_ context.Context, ip netip.Addr) (flow.EndpointOwner, bool) {
	if d == nil || d.rt == nil {
		return flow.EndpointOwner{}, false
	}
	// The owner and its version come from the current live fact entries via the
	// shared resolver. The Flow plane re-checks this before every fragment;
	// reading a possibly stale RouteView snapshot here would make a renewed
	// AddressFact of the same owner look like an owner change and fail a steady
	// datagram flow as route-stale. Any failure — no view, no owner or a
	// conflict — is reported absent so the Flow plane drops the datagram instead
	// of guessing.
	resolution, err := d.rt.destinationOwner(ip)
	if err != nil {
		return flow.EndpointOwner{}, false
	}
	return flow.EndpointOwner{Owner: resolution.NodeID, Version: resolution.FactVersion}, true
}

// flowRouteResolver adapts the Network RouteView onto the Flow plane's pinned
// route port for the PACKET lane, using the same class-1 Path+Session as the
// packet plane so a datagram and a packet toward one peer share one session.
type flowRouteResolver struct{ rt *streamRuntime }

func (r *flowRouteResolver) ResolveDatagramRoute(ctx context.Context, destination netip.Addr) (flow.DatagramRoute, error) {
	// The nil receiver is answered here, not delegated: the shared resolver is a
	// method on the runtime and must not be reached through a nil adapter.
	if r == nil {
		return flow.DatagramRoute{}, fmt.Errorf("%w: no route view", topology.ErrRouteStale)
	}
	route, err := r.rt.resolvePacketLaneRoute(ctx, destination)
	if err != nil {
		return flow.DatagramRoute{}, err
	}
	return flow.DatagramRoute{
		DestinationNode:    route.destinationNode,
		AddressFactVersion: route.addressFactVersion,
		PathID:             route.pathID,
		PathGeneration:     route.pathGeneration,
		Lane:               path.LanePacket,
	}, nil
}

// flowSender dispatches one encoded UDP_DATAGRAM fragment as a real E2E frame on
// the pinned class-1 Path/Session, sharing the packet plane's seal+enqueue
// sequencing so fragments of one datagram never interleave with packets.
type flowSender struct{ rt *streamRuntime }

func (s *flowSender) SendFragment(ctx context.Context, request flow.SendRequest) error {
	if s == nil || s.rt == nil {
		return ErrLinkDown
	}
	pair, err := s.rt.packetPairFor(ctx, request.DstNodeID)
	if err != nil {
		return err
	}
	if pair.ps.scope.id != request.PathID || pair.ps.scope.gen != request.PathGeneration {
		return fmt.Errorf("%w: PACKET path %d/%d changed to %d/%d after pinning",
			flow.ErrRouteChanged, request.PathID, request.PathGeneration, pair.ps.scope.id, pair.ps.scope.gen)
	}
	// A datagram is never re-routed behind the caller's back: the pinned pair
	// must still be exactly healthy at the moment its fragment egresses.
	if err := s.rt.validatePinnedPair(pair); err != nil {
		return err
	}
	return s.rt.sendEndToEndFrame(pair, wire.MessageTypeUDPDatagram, request.Payload)
}

// enableFlowService installs the Flow UDP plane on this runtime with the
// caller-provided target-endpoint delivery port. The Flow plane rides the
// PACKET lane, so the dedicated PACKET lane adjacency is enabled here too.
func (rt *streamRuntime) enableFlowService(delivery flow.Delivery) error {
	if rt == nil || rt.n == nil || delivery == nil {
		return invalidConfig("flow.delivery", "must not be nil")
	}
	budgetPort := newFlowBufferBudget(rt.budgets, budget.NetworkID(rt.wireID))
	manager, err := flow.NewManager(flow.Config{
		NetworkID: rt.wireID,
		ContextID: rt.ctxID,
		LocalNode: topology.NodeID(rt.localID),
		Endpoints: &flowEndpointDirectory{rt: rt},
		Routes:    &flowRouteResolver{rt: rt},
		Sender:    &flowSender{rt: rt},
		Delivery:  delivery,
		Budget:    budgetPort,
	})
	if err != nil {
		budgetPort.Close()
		return err
	}
	rt.mu.Lock()
	if rt.flow != nil || rt.closed {
		rt.mu.Unlock()
		_ = manager.Close()
		budgetPort.Close()
		return ErrResource
	}
	rt.flow = manager
	rt.flowBudget = budgetPort
	rt.flowDelivery = delivery
	rt.mu.Unlock()
	rt.n.mu.Lock()
	rt.n.packetLanesEnabled = true
	rt.n.mu.Unlock()
	return nil
}
