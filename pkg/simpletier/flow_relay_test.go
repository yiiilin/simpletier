package simpletier

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/flow"
)

// TestRelayRootlessUDPDatagram runs the production Flow UDP plane across a real
// two-hop A -> R -> B topology: A and B install the flow plane, R never does, and
// one REQUEST datagram is fragmented at A, relayed opaquely by R and reassembled
// at B. It asserts the relay stays rootless (no flow manager, no Session object,
// no E2E protector) and never sees plaintext.
func TestRelayRootlessUDPDatagram(t *testing.T) {
	source, relay, target := newRelayTopology(t)

	targetDelivery := newCaptureFlowDelivery()
	if err := target.streams.enableFlowService(targetDelivery); err != nil {
		t.Fatalf("enable target flow plane: %v", err)
	}
	if err := source.streams.enableFlowService(newCaptureFlowDelivery()); err != nil {
		t.Fatalf("enable source flow plane: %v", err)
	}
	// The relay must never be given a flow plane.
	if relay.streams.flow != nil {
		t.Fatal("relay installed a flow manager before any traffic")
	}

	// Installing flow on A/B establishes the dedicated PACKET lane on both hops.
	waitRelayLinks(t, source, 3, 30*time.Second)
	waitRelayLinks(t, target, 3, 30*time.Second)
	waitRelayLinks(t, relay, 6, 30*time.Second)

	sourceIP := source.LocalVirtualIP()
	targetIP := netip.MustParseAddr(relayTargetIP)
	waitPacketRoute(t, source, targetIP, 30*time.Second)
	// The target must also have converged the PACKET-lane graph in the reverse
	// direction before it can resolve every hop link of an inbound PATH_OPEN.
	waitPacketRoute(t, target, sourceIP, 30*time.Second)

	association, err := source.streams.flow.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	defer association.Close()

	payload := make([]byte, 2000)
	for i := range payload {
		payload[i] = byte((i*19 + 3) % 251)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := association.Fragment(ctx, flow.OutboundDatagram{
		Source:      netip.AddrPortFrom(sourceIP, 40100),
		Destination: netip.AddrPortFrom(targetIP, 40101),
		Payload:     payload,
	}); err != nil {
		t.Fatalf("Fragment(relay): %v", err)
	}
	select {
	case got := <-targetDelivery.datagrams:
		if !bytes.Equal(got.Payload, payload) {
			t.Fatalf("relayed datagram = %d bytes, want %d identical", len(got.Payload), len(payload))
		}
		if got.Destination.Port() != 40101 {
			t.Fatalf("relayed datagram destination port = %d; want 40101", got.Destination.Port())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("target never delivered the relayed datagram")
	}

	// The relay stays rootless: no flow manager, no Session object/root and no
	// E2E protector for the relayed session.
	if relay.streams.flow != nil {
		t.Fatal("relay created a flow manager (must stay rootless)")
	}
	relaySession(t, relay)
}
