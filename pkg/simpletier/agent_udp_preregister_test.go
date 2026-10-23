package simpletier

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/flow"
)

// TestAgentUDPAuthorizesReplyPeerBeforeFirstFragment pins the ordering that makes
// a fast REPLY legal: SendTo authorizes the resolved overlay destination before
// the first fragment can be admitted, and it does not retract that authorization
// when the fragment fails (a partial admission may still be on the wire).
//
// The test forces Fragment to fail deterministically by closing the underlying
// association directly, then proves the peer is already authorized: a REPLY from
// exactly that peer and association is delivered instead of being dropped as
// foreign.
func TestAgentUDPAuthorizesReplyPeerBeforeFirstFragment(t *testing.T) {
	const (
		name  = "agent-udp-preregister"
		cidr  = "10.117.0.0/24"
		token = "agent-udp-preregister-token-01"
	)
	sourceIP := netip.MustParseAddr("10.117.0.1")
	targetIP := netip.MustParseAddr("10.117.0.3")
	targetPort := uint16(41020)
	destination := netip.AddrPortFrom(targetIP, targetPort)

	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, sourceIP.String(), relayCarrierURL(target))
	waitRelayLinks(t, source, 3, 30*time.Second)
	waitRelayLinks(t, target, 3, 30*time.Second)
	waitPacketRoute(t, source, targetIP, 30*time.Second)

	backend := newAgentDatagramBackend(source.streams)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	channel, err := backend.NewAssociation(ctx)
	if err != nil {
		t.Fatalf("NewAssociation: %v", err)
	}
	defer channel.Close()
	agentChannel, ok := channel.(*agentDatagramChannel)
	if !ok {
		t.Fatalf("NewAssociation returned %T; want *agentDatagramChannel", channel)
	}
	mux := agentChannel.backend.mux
	if mux == nil {
		t.Fatal("association has no mux")
	}
	associationID := agentChannel.association.ID()

	// A closed association makes Fragment fail after resolution (and therefore
	// after the peer must already have been authorized).
	if err := agentChannel.association.Close(); err != nil {
		t.Fatalf("close association: %v", err)
	}
	if err := channel.SendTo(ctx, targetIP.String(), targetPort, []byte("request")); err == nil {
		t.Fatal("SendTo with a closed association succeeded; want a Fragment failure")
	}
	if !agentChannel.peers.includes(destination) {
		t.Fatal("the resolved destination was not authorized before the fragment attempt")
	}

	// A REPLY from that exact peer and association is now legal, not foreign.
	foreignBefore := mux.droppedForeign.Load()
	local := netip.AddrPortFrom(source.localVirtualIP(), agentChannel.localPort)
	agentChannel.deliverReply(flow.Datagram{
		Flags:         flow.FlagReply,
		AssociationID: associationID,
		Source:        destination,
		Destination:   local,
		Payload:       []byte("late-reply"),
	})
	if got := mux.droppedForeign.Load(); got != foreignBefore {
		t.Fatalf("a REPLY from the authorized peer was classified foreign (%d -> %d)", foreignBefore, got)
	}
	host, port, payload, err := channel.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if host != targetIP.String() || port != targetPort || !bytes.Equal(payload, []byte("late-reply")) {
		t.Fatalf("delivered reply = %s:%d %q; want %s:%d %q", host, port, payload, targetIP, targetPort, "late-reply")
	}
}
