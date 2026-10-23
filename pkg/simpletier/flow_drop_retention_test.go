package simpletier

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/flow"
	"github.com/yiiilin/simpletier/internal/topology"
	"github.com/yiiilin/simpletier/internal/wire"
)

// expectFlowDatagram reads one reassembled datagram from the target delivery
// sink and requires the exact payload and destination the source sent. It uses a
// fixed bounded deadline instead of sleeping, so a missing delivery fails
// deterministically rather than flaking.
func expectFlowDatagram(t *testing.T, delivery *captureFlowDelivery, want []byte, wantDst netip.AddrPort, what string) {
	t.Helper()
	select {
	case got := <-delivery.datagrams:
		if !bytes.Equal(got.Payload, want) {
			t.Fatalf("%s: delivered %d bytes, want the sent %d bytes unchanged", what, len(got.Payload), len(want))
		}
		if got.Destination != wantDst {
			t.Fatalf("%s: delivered to destination %s, want %s", what, got.Destination, wantDst)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: the target endpoint never received the datagram", what)
	}
}

// TestFlowPlaneDatagramDropRetainsLinkAndSession is the product regression for
// the UDP_DATAGRAM / Flow half of the confirmed fatal propagation of a
// per-datagram refusal. It is the exact sibling of
// TestPacketPlaneDropRetainsLinkAndSession, which only covers the IP_PACKET
// half.
//
// One authenticated UDP_DATAGRAM whose decoded fragment is a REPLY for an
// AssociationID this node never created as an origin makes flow.Manager.Receive
// return flow.ErrUnknownAssociation, counted under flow.DropUnknownAssociation.
// The frozen per-MessageType disposition (MOD-WIRE-PROTOCOL C-WIRE-004:
// IP_PACKET / UDP_DATAGRAM overflow = drop + count) and the Flow plane's own
// contract require the physical PACKET Link, its class-1 Session and the Agent
// to survive one datagram's terminal outcome. Before the fix the bare
// ErrUnknownAssociation travelled back through deliverDatagramFrame ->
// deliverOpenedFrame -> openLocalEndToEnd -> handleEndToEndFrame ->
// consumeFrame, matched no frameLocalSemanticClassOf entry and made
// controlPump.read() take its fatal return, closing the shared physical Link and
// discarding every queued frame of every Session on it.
//
// Nothing here is a mock: two real Networks, the real class-1 PACKET-lane
// Path/Session, real hop + E2E sealing and the real ingress pump. The test only
// plays a peer that signs one REPLY for a foreign association, which is exactly
// the authority an authenticated peer already holds.
//
// Timing discipline: the chosen refusal is time-independent (it turns on
// association identity, not an idle TTL), the two refusals are ordered by
// waiting on the counted drop after each send, and every wait uses the same
// fixed bounded deadline as the sibling tests. There is no clock seam on the
// runtime Flow install (enableFlowService injects no Now), so the fixed-clock
// discipline used by the rate/rekey tests is not reachable at this boundary;
// determinism is instead bought by picking a refusal with no clock dependency.
func TestFlowPlaneDatagramDropRetainsLinkAndSession(t *testing.T) {
	const (
		name  = "flow-drop-retains"
		cidr  = "10.99.0.0/24"
		token = "flow-drop-token-0123456789"
	)
	sourceIP := netip.MustParseAddr("10.99.0.1")
	targetIP := netip.MustParseAddr("10.99.0.3")

	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, sourceIP.String(), relayCarrierURL(target))

	// A real delivery sink on both sides, exactly as flow_relay_test.go wires it.
	targetDelivery := newCaptureFlowDelivery()
	if err := target.streams.enableFlowService(targetDelivery); err != nil {
		t.Fatalf("enable target flow plane: %v", err)
	}
	if err := source.streams.enableFlowService(newCaptureFlowDelivery()); err != nil {
		t.Fatalf("enable source flow plane: %v", err)
	}

	// Installing flow enables the dedicated PACKET lane on both sides.
	waitRelayLinks(t, target, 3, 30*time.Second)
	waitRelayLinks(t, source, 3, 30*time.Second)
	// Both directions must be converged: the target resolves the metadata source
	// and destination of an inbound fragment from its own live owner map.
	waitPacketRoute(t, source, targetIP, 30*time.Second)
	waitPacketRoute(t, target, sourceIP, 30*time.Second)

	association, err := source.streams.flow.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	defer association.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A first real REQUEST datagram establishes the class-1 PACKET Path/Session
	// and proves the plane is healthy before the hostile frame.
	baseline := []byte("flow-drop-retains-baseline")
	baselineDst := netip.AddrPortFrom(targetIP, 40201)
	if err := association.Fragment(ctx, flow.OutboundDatagram{
		Source:      netip.AddrPortFrom(sourceIP, 40200),
		Destination: baselineDst,
		Payload:     baseline,
	}); err != nil {
		t.Fatalf("baseline Fragment: %v", err)
	}
	expectFlowDatagram(t, targetDelivery, baseline, baselineDst, "baseline datagram")

	linksBefore := packetLaneLinks(target)
	if len(linksBefore) == 0 {
		t.Fatal("target has no Ready PACKET-lane Link before the hostile datagram")
	}

	targetIdentity, err := target.identityStore.Identity()
	if err != nil {
		t.Fatalf("target identity: %v", err)
	}
	pair, err := source.streams.packetPairFor(ctx, topology.NodeID(targetIdentity.NodeID))
	if err != nil {
		t.Fatalf("resolve the established PACKET pair: %v", err)
	}
	manager := target.streams.flowManager()
	if manager == nil {
		t.Fatal("target flow Manager is not installed")
	}
	unknownDropsBefore := manager.Stats().Drops[flow.DropUnknownAssociation]
	if unknownDropsBefore != 0 {
		t.Fatalf("target counted %d unknown-association drops before the hostile frame", unknownDropsBefore)
	}

	// A real, fully encoded REPLY fragment carrying an AssociationID the target
	// never created as a local origin. It is sealed and framed by the same
	// established class-1 Session as the baseline datagram, so it is exactly what
	// one authenticated peer can already send.
	var unknownAssoc flow.AssocID
	copy(unknownAssoc[:], "unknown-assoc-01")
	hostilePayload := []byte("unknown-association-reply")
	hostile, err := flow.EncodeFragment(flow.Fragment{
		AssociationID:   unknownAssoc,
		Flags:           flow.FlagReply,
		DatagramID:      1,
		FragmentIndex:   0,
		FragmentCount:   1,
		TotalPayloadLen: uint16(len(hostilePayload)),
		Source:          netip.AddrPortFrom(sourceIP, 40202),
		Destination:     netip.AddrPortFrom(targetIP, 40203),
		Payload:         hostilePayload,
	})
	if err != nil {
		t.Fatalf("EncodeFragment(hostile REPLY): %v", err)
	}

	// Two identical hostile frames on the same established Session. The second
	// one is the deterministic discriminator: only a reader that survived the
	// first can still hand it to the Flow manager, so a fatal first refusal
	// leaves the second refusal uncounted.
	for i := 1; i <= 2; i++ {
		if err := source.streams.sendEndToEndFrame(pair, wire.MessageTypeUDPDatagram, hostile); err != nil {
			t.Fatalf("hostile UDP_DATAGRAM %d: a per-datagram drop killed the PACKET Session: %v", i, err)
		}
		waitForCondition(t, fmt.Sprintf("flow Manager counted unknown-association drop %d", i), 15*time.Second, func() bool {
			return manager.Stats().Drops[flow.DropUnknownAssociation] >= uint64(i)
		})
	}

	// The refusal was a counted drop, never a silent one and never a delivery.
	stats := manager.Stats()
	if stats.Drops[flow.DropUnknownAssociation] != 2 {
		t.Fatalf("unknown-association drops = %d, want exactly 2", stats.Drops[flow.DropUnknownAssociation])
	}
	if stats.DeliveredDatagrams != 1 {
		t.Fatalf("delivered datagrams = %d after the refusals, want only the one baseline datagram", stats.DeliveredDatagrams)
	}

	// The exact physical PACKET Link instances that carried the refused frames are
	// still admitted, and no replacement was needed.
	for id, established := range linksBefore {
		if !established.Ready() {
			t.Fatalf("the PACKET Link %d was torn down by a per-datagram drop", id)
		}
		target.mu.Lock()
		current := target.activeLinks[id]
		target.mu.Unlock()
		if current != established {
			t.Fatalf("the PACKET Link %d was replaced after a per-datagram drop", id)
		}
	}
	// The class-1 PACKET Session is also retained, not re-established.
	reused, err := source.streams.packetPairFor(ctx, topology.NodeID(targetIdentity.NodeID))
	if err != nil {
		t.Fatalf("the established PACKET pair is gone after a per-datagram drop: %v", err)
	}
	if reused.entry != pair.entry {
		t.Fatal("the class-1 PACKET Session was replaced after a per-datagram drop")
	}
	if target.streams.flowManager() != manager {
		t.Fatal("the Flow Manager was reinstalled after a per-datagram drop")
	}
	if source.isClosed() || target.isClosed() {
		t.Fatal("a per-datagram drop closed a Network")
	}

	// A later valid datagram is still delivered end to end on the surviving plane.
	after := []byte("flow-after-the-drop")
	afterDst := netip.AddrPortFrom(targetIP, 40205)
	if err := association.Fragment(ctx, flow.OutboundDatagram{
		Source:      netip.AddrPortFrom(sourceIP, 40204),
		Destination: afterDst,
		Payload:     after,
	}); err != nil {
		t.Fatalf("Fragment after the drop: %v", err)
	}
	expectFlowDatagram(t, targetDelivery, after, afterDst, "datagram after the drop")
}
