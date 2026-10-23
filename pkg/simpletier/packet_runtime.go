package simpletier

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/yiiilin/simpletier/internal/flow"
	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/packet"
	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/session"
	"github.com/yiiilin/simpletier/internal/topology"
	"github.com/yiiilin/simpletier/internal/wire"
)

// packetDevicePort is the full local device port of the packet runtime: the
// packet plane needs only the write side (packet.ReceiverDevice), while the
// runtime pump also needs the read side. internal/agent.PacketDevice satisfies
// this structurally.
type packetDevicePort interface {
	packet.ReceiverDevice
	ReadPacket(ctx context.Context, buf []byte) (int, error)
}

// packetRuntime is the production L3 packet plane of one Network. It binds
// internal/packet's decision core to the Network's RouteView (PACKET-lane
// candidates and AddressFact ownership), to the class-1 PACKET-lane
// Path/Session E2E egress and to the local host device.
type packetRuntime struct {
	rt      *streamRuntime
	service *packet.Service
	device  packetDevicePort

	mu     sync.Mutex
	closed bool
}

// enablePacketService installs the packet plane on this runtime. It is
// all-or-none: a second call or a closed runtime is refused. The device stays
// owned by the caller; closing it belongs to the host adapter.
func (rt *streamRuntime) enablePacketService(device packetDevicePort) error {
	if rt == nil || rt.n == nil || device == nil {
		return invalidConfig("packet.device", "must not be nil")
	}
	service, err := packet.New(packet.Config{
		LocalNode: topology.NodeID(rt.localID),
		VirtualIP: rt.n.localVirtualIP(),
		CIDR:      rt.n.normalized.networkPrefix,
		Device:    device,
		Resolver:  &packetRouteResolver{rt: rt},
		Sender:    &packetSender{rt: rt},
	})
	if err != nil {
		return err
	}
	pr := &packetRuntime{rt: rt, service: service, device: device}
	rt.mu.Lock()
	if rt.packets != nil || rt.closed {
		rt.mu.Unlock()
		_ = service.Close()
		return ErrResource
	}
	rt.packets = pr
	rt.mu.Unlock()
	// The PACKET lane adjacency is established on demand from here: the upstream
	// loop dials it for every target once this gate is set.
	rt.n.mu.Lock()
	rt.n.packetLanesEnabled = true
	rt.n.mu.Unlock()
	return nil
}

// startPacketDevice reads complete IPv4 packets from the attached device and
// hands each to the packet service until the Network context ends or the device
// fails. It is the production device pump used by the Agent wrapper.
func (rt *streamRuntime) startPacketDevice() {
	rt.mu.Lock()
	pr := rt.packets
	rt.mu.Unlock()
	if pr == nil {
		return
	}
	rt.n.workers.Add(1)
	go func() {
		defer rt.n.workers.Done()
		buf := make([]byte, packet.DefaultDeviceMTU)
		for {
			n, err := pr.device.ReadPacket(rt.n.ctx, buf)
			if n > 0 {
				if sendErr := pr.service.Send(rt.n.ctx, buf[:n]); sendErr != nil {
					traceDataPlane("packet send failed", "err", sendErr.Error())
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

func (pr *packetRuntime) close() error {
	if pr == nil {
		return nil
	}
	pr.mu.Lock()
	if pr.closed {
		pr.mu.Unlock()
		return nil
	}
	pr.closed = true
	pr.mu.Unlock()
	if pr.service == nil {
		return nil
	}
	return pr.service.Close()
}

// allowInboundPacket charges the frozen per-peer PACKET budget for one
// authenticated inbound logical packet. The peer key is the authenticated
// envelope sender NodeID, never the inner packet's claimed source and never the
// per-hop frame header. A nil limiter (a directly built runtime) is permissive.
func (rt *streamRuntime) allowInboundPacket(message link.ProtectedMessage) bool {
	if rt == nil || rt.n == nil {
		return true
	}
	return rt.n.rates.allowPacket(envelopeNode(message.Envelope, envelopeSrcOffset))
}

// deliverPacketFrame hands one authenticated inner IPv4 packet to the packet
// plane. The authenticated source node and the destination check are re-derived
// from the frozen envelope, never from the packet itself.
//
// The frozen IP_PACKET over-limit disposition is drop + count, never a Link
// teardown (MOD-WIRE-PROTOCOL C-WIRE-004), and every refusal of the packet
// Service is a per-packet terminal outcome that must never fail a Link or the
// Agent (internal/packet's own contract, FEAT-L3-VPN 3.4). A packet the Service
// refuses -- malformed or oversized IPv4, a broadcast/multicast destination, an
// inner source the authenticated sender does not own, no route, a route
// conflict/stale pin, a destination this node no longer owns, the bounded device
// budget or a local device write failure -- has therefore already been counted
// under its own DropReason by the Service, and this function converts it into a
// local, counted drop instead of returning it to the control pump. Returning it
// would let one authenticated IP_PACKET reach controlPump.read() as an
// unclassified error, whose fatal return closes the shared physical Link and
// discards every queued frame of every Session on it.
//
// Only the packet Service call boundary is treated this way. Hop/E2E
// authentication, envelope decode, the Session/Path binding checks and the pump
// itself all run before this point and keep their fatal disposition.
func (rt *streamRuntime) deliverPacketFrame(message link.ProtectedMessage, plaintext []byte) error {
	if !rt.allowInboundPacket(message) {
		traceDataPlane("packet rate exceeded", "kind", uint8(wire.MessageTypeIPPacket))
		return nil
	}
	rt.mu.Lock()
	pr := rt.packets
	rt.mu.Unlock()
	if pr == nil || pr.service == nil {
		// No local L3 consumer: drop rather than tear down the adjacency.
		return nil
	}
	authenticatedSource := topology.NodeID(envelopeNode(message.Envelope, envelopeSrcOffset))
	if err := pr.service.Receive(rt.n.ctx, authenticatedSource, topology.NodeID(rt.localID), plaintext); err != nil {
		// The Service counted the specific DropReason; the Link, the Session and
		// the Agent stay up. Traced so the drop is never invisible.
		traceDataPlane("packet dropped; Link retained", "kind", uint8(wire.MessageTypeIPPacket), "err", err.Error())
	}
	return nil
}

// deliverDatagramFrame hands one authenticated inner UDP_DATAGRAM payload to the
// Flow plane after reassembly.
//
// One logical datagram is charged once: the frozen per-peer PACKET budget counts
// the first fragment of a two-fragment datagram and does not double charge its
// tail. A payload that does not decode as the tail of a datagram is charged,
// because it cannot be proven to belong to an already charged datagram (fail
// closed). The over-limit disposition is drop + count, never a Link teardown.
//
// Like deliverPacketFrame, a refusal of the Flow manager is one datagram's
// terminal outcome and is already counted by the manager under its own
// DropReason: a malformed fragment, a foreign/unowned endpoint, an unknown or
// expired association, a tombstoned window, a duplicate/superseded datagram, a
// bounded resource refusal or a closed manager. Returning it would reach
// controlPump.read() as an unclassified error and close the shared Link, so it
// is a local, counted drop here. Only the manager.Receive call boundary is
// classified this way.
func (rt *streamRuntime) deliverDatagramFrame(message link.ProtectedMessage, plaintext []byte) error {
	charge := true
	if fragment, err := flow.DecodeFragment(plaintext); err == nil && fragment.FragmentIndex > 0 {
		charge = false
	}
	if charge && !rt.allowInboundPacket(message) {
		traceDataPlane("packet rate exceeded", "kind", uint8(wire.MessageTypeUDPDatagram))
		return nil
	}
	rt.mu.Lock()
	manager := rt.flow
	rt.mu.Unlock()
	if manager == nil {
		return nil
	}
	err := manager.Receive(rt.n.ctx, flow.AuthenticatedEnvelope{
		NetworkID: rt.wireID,
		SrcNodeID: topology.NodeID(envelopeNode(message.Envelope, envelopeSrcOffset)),
		DstNodeID: topology.NodeID(rt.localID),
	}, plaintext)
	if err != nil {
		// The manager counted the specific DropReason; the Link, the Session and
		// the Agent stay up. Traced so the drop is never invisible.
		traceDataPlane("datagram dropped; Link retained", "kind", uint8(wire.MessageTypeUDPDatagram), "err", err.Error())
	}
	return nil
}

// packetRouteResolver adapts the Network RouteView onto the packet plane's
// pinned route/ownership port. It selects only PACKET-lane candidates and maps
// the shared PACKET-lane resolution policy (resolvePacketLaneRoute) onto
// packet.PacketRoute, pinning the address owner's fact version and the installed
// class-1 Path scope.
type packetRouteResolver struct{ rt *streamRuntime }

func (r *packetRouteResolver) ResolvePacketRoute(ctx context.Context, destination netip.Addr) (packet.PacketRoute, error) {
	// The nil receiver is answered here, not delegated: the shared resolver is a
	// method on the runtime and must not be reached through a nil adapter.
	if r == nil {
		return packet.PacketRoute{}, fmt.Errorf("%w: no route view", packet.ErrRouteStale)
	}
	route, err := r.rt.resolvePacketLaneRoute(ctx, destination)
	if err != nil {
		return packet.PacketRoute{}, err
	}
	return packet.PacketRoute{
		DestinationNode:    route.destinationNode,
		AddressFactVersion: route.addressFactVersion,
		Lane:               path.LanePacket,
		PathID:             route.pathID,
		PathGeneration:     route.pathGeneration,
	}, nil
}

// packetSender dispatches one already-validated IPv4 packet as a real IP_PACKET
// E2E frame on the pinned class-1 Path/Session, preserving the single egress
// sequence owner and the seal+enqueue critical section.
type packetSender struct{ rt *streamRuntime }

func (s *packetSender) SendPacket(ctx context.Context, request packet.SendRequest) error {
	if s == nil || s.rt == nil {
		return ErrLinkDown
	}
	pair, err := s.rt.packetPairFor(ctx, request.DestinationNode)
	if err != nil {
		return err
	}
	if pair.ps.scope.id != request.PathID || pair.ps.scope.gen != request.PathGeneration {
		return fmt.Errorf("%w: PACKET path %d/%d changed to %d/%d after pinning",
			packet.ErrRouteStale, request.PathID, request.PathGeneration, pair.ps.scope.id, pair.ps.scope.gen)
	}
	// Last check before the frame is sealed: the pinned pair's live NODE/LINK
	// facts, exact installed local hop and peer static key must all still hold.
	if err := s.rt.validatePinnedPair(pair); err != nil {
		return err
	}
	return s.rt.sendEndToEndFrame(pair, wire.MessageTypeIPPacket, request.Payload)
}

// sessionPacketPairLocked returns the committed class-1 (PACKET) Path+Session
// whose logical peer is target, or nil when this node has none. A pair this node
// answers on is not cached in rt.pairs until it is first used, so both the
// establishing lookup and the steady-state lookup have to find it in the Session
// table. The caller holds rt.mu.
func (rt *streamRuntime) sessionPacketPairLocked(target topology.NodeID) *readyPair {
	for _, entry := range rt.sessionsByID {
		if entry == nil || entry.relay || entry.class != session.SessionClassPacket || !entry.isReady() {
			continue
		}
		if [16]byte(entry.src) != [16]byte(target) && [16]byte(entry.dst) != [16]byte(target) {
			continue
		}
		ps := rt.pathsByScope[entry.scope]
		if ps == nil || ps.broken.Load() {
			continue
		}
		pair := &readyPair{ps: ps, entry: entry, ready: make(chan struct{})}
		close(pair.ready)
		return pair
	}
	return nil
}

// existingPacketPair returns the already-established class-1 (PACKET)
// Path+Session pair toward target while it is still usable, and never establishes
// one.
//
// The packet and flow route resolvers use it as their steady-state lookup. A
// running flow already owns its pinned pair, so its next frame must not depend on
// the immutable RouteView having been rebuilt: the 15s local re-advertisement
// renews this node's own NODE/ADDRESS/initiator-LINK facts with a higher durable
// version, which is exactly what C-ROUTE-003 requires the strict candidate query
// to mask, so re-deriving a route from the view for every frame would fail the
// flow closed for the whole window between that commit and the next rebuild.
// Ownership is resolved from the live fact by the caller, and exact-hop and
// pinned-fact health is re-validated by packetSender.SendPacket /
// flowSender.SendFragment immediately before the frame is sealed, so this lookup
// only has to answer "is there a live pair".
//
// A genuinely new flow gets false here and must still select a Path from the
// strict PacketCandidates graph: no route is ever selected from a stale view.
func (rt *streamRuntime) existingPacketPair(target topology.NodeID) (*readyPair, bool) {
	if rt == nil || rt.n == nil {
		return nil, false
	}
	key := pairKey{node: target, class: session.SessionClassPacket}
	rt.mu.Lock()
	pair, cached := rt.pairs[key]
	if !cached {
		// No entry at all: a pair this node answers on lives only in the Session
		// table. An entry that exists but is not established yet is deliberately
		// not replaced here, so the caller keeps blocking on it through
		// packetPairFor instead of racing it with a different pair.
		pair = rt.sessionPacketPairLocked(target)
	}
	rt.mu.Unlock()
	if pair == nil || pair.ps == nil || pair.entry == nil || !rt.pairUsable(pair) {
		return nil, false
	}
	return pair, true
}

// packetPairFor returns the class-1 (PACKET/lane 1) Path+Session pair toward
// target. It reuses an established source-side pair first, then a committed
// responder-side session whose peer is target, and only then establishes a new
// pair as the initiator. The pair is always the same one for every packet of the
// session; packet sends never open a per-packet Path.
func (rt *streamRuntime) packetPairFor(ctx context.Context, target topology.NodeID) (*readyPair, error) {
	key := pairKey{node: target, class: session.SessionClassPacket}
	rt.mu.Lock()
	if pair, ok := rt.pairs[key]; ok {
		rt.mu.Unlock()
		select {
		case <-pair.ready:
			if pair.err != nil {
				return nil, pair.err
			}
			if rt.pairUsable(pair) {
				return pair, nil
			}
			// Drop only this exact stale entry; an in-flight establishment has a
			// nil ps and is never dropped by a concurrent waiter.
			rt.mu.Lock()
			if current := rt.pairs[key]; current == pair {
				delete(rt.pairs, key)
			}
			rt.mu.Unlock()
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-rt.n.ctx.Done():
			return nil, ErrClosed
		}
	} else {
		rt.mu.Unlock()
	}
	rt.mu.Lock()
	if pair := rt.sessionPacketPairLocked(target); pair != nil {
		rt.pairs[key] = pair
		rt.mu.Unlock()
		return pair, nil
	}
	rt.mu.Unlock()
	return rt.readyPairFor(ctx, target, session.SessionClassPacket, session.LanePacket)
}

// sendEndToEndFrame seals one E2E frame of any data class under the session's
// single egress sequence owner and enqueues it on the class lane's adjacent
// pump. src/dst are derived from which logical endpoint this node is, so a
// responder can send on the same session as the initiator.
func (rt *streamRuntime) sendEndToEndFrame(pair *readyPair, kind wire.MessageType, payload []byte) error {
	if pair == nil || pair.ps == nil || pair.entry == nil {
		return errNoDataPath
	}
	ps, entry := pair.ps, pair.entry
	entry.protMu.Lock()
	tx := entry.tx
	entry.protMu.Unlock()
	if tx == nil {
		return traceSealLost("packet/protectors-nil", entry, fmt.Errorf("session protectors are not installed"))
	}
	var src, dst [16]byte
	if [16]byte(entry.src) == rt.localID {
		src, dst = entry.src, entry.dst
	} else {
		src, dst = entry.dst, entry.src
	}
	dstIndex := -1
	for index, node := range ps.nodes {
		if [16]byte(node) == dst {
			dstIndex = index
			break
		}
	}
	if dstIndex < 0 {
		return errNoDataPath
	}
	outIndex := ps.hopIndexToward(dstIndex)
	if outIndex < 0 || outIndex >= len(ps.nodes) {
		return errNoDataPath
	}
	pump := rt.dataPumpOnPath(ps, outIndex)
	if pump == nil {
		// The pinned hop is gone. Failing closed as a lost session (rather than
		// falling back to a sibling Link, or another data lane) keeps the
		// class-1 Path/Session pinned for this datagram and its Circuit.
		return traceSealLost("packet/pinned-hop", entry, fmt.Errorf("pinned PACKET hop is not the installed Link instance"))
	}
	class, err := classOfLane(ps.lane)
	if err != nil {
		return err
	}
	if err := pump.control.AdmitSession([16]byte(entry.id), byte(class)); err != nil {
		return err
	}
	if err := rt.awaitSealHeadroom(entry, tx); err != nil {
		return err
	}
	entry.txMu.Lock()
	defer entry.txMu.Unlock()
	// The KeyEpoch is the installed TX protector's CurrentEpoch under the same
	// lock the install path takes, so a rekey install cannot race the seal and
	// already-queued ciphertext keeps its epoch. Never a hardcoded 1.
	epoch, number, err := rt.nextSealIdentity(entry, tx)
	if err != nil {
		return err
	}
	envelope := buildEnvelope(rt.wireID, src, dst, kind, [16]byte(entry.id), epoch, number, entry.scope.id, entry.scope.gen, len(payload))
	sealed, err := tx.Seal(wire.Frame{Kind: wire.FrameKindEndToEnd, Envelope: envelope}, payload)
	if err != nil {
		return err
	}
	traceDataPlane("E2E sealed", "kind", uint8(kind), "number", number, "plain_len", len(payload), "session", hexNode([16]byte(entry.id))[:8])
	return pump.sendEndToEnd(sealed.Envelope, sealed.Body, link.HopRoute{Cursor: uint8(outIndex), HopLimit: overlayHopLimit, RemainingBudget: ps.pathBudget()})
}
