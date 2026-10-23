package simpletier

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/flow"
)

// TestAgentDatagramBackendSendTo proves the pkg SOCKS5 UDP backend is Flow-backed
// and never dials an OS UDP socket: NewAssociation lazily installs the Flow
// plane, SendTo resolves the target inside the overlay and fragments through the
// class-1 session, the peer's Flow Delivery receives the exact payload, and
// Close unblocks a pending Receive.
func TestAgentDatagramBackendSendTo(t *testing.T) {
	const (
		name  = "agent-udp"
		cidr  = "10.104.0.0/24"
		token = "agent-udp-token-0123456789"
	)
	sourceIP := netip.MustParseAddr("10.104.0.1")
	targetIP := netip.MustParseAddr("10.104.0.3")

	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, sourceIP.String(), relayCarrierURL(target))

	targetDelivery := newCaptureFlowDelivery()
	if err := target.streams.enableFlowService(targetDelivery); err != nil {
		t.Fatalf("enable target flow: %v", err)
	}

	backend := newAgentDatagramBackend(source.streams)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	channel, err := backend.NewAssociation(ctx)
	if err != nil {
		t.Fatalf("NewAssociation: %v", err)
	}
	defer channel.Close()

	// The backend must have installed the Flow plane on first use.
	if source.streams.flow == nil {
		t.Fatal("NewAssociation did not enable the Flow plane")
	}

	waitRelayLinks(t, source, 3, 30*time.Second)
	waitRelayLinks(t, target, 3, 30*time.Second)
	waitPacketRoute(t, source, targetIP, 30*time.Second)

	payload := []byte("socks-udp-over-flow")
	if err := channel.SendTo(ctx, targetIP.String(), 41001, payload); err != nil {
		t.Fatalf("SendTo: %v", err)
	}
	select {
	case got := <-targetDelivery.datagrams:
		if !bytes.Equal(got.Payload, payload) {
			t.Fatalf("target received %q; want %q", got.Payload, payload)
		}
		if got.Destination.Port() != 41001 || got.Destination.Addr() != targetIP {
			t.Fatalf("target destination = %s; want %s:41001", got.Destination, targetIP)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("target Flow Delivery never received the SOCKS UDP datagram")
	}

	// An out-of-overlay target is refused before any send: no OS UDP dial exists.
	if err := channel.SendTo(ctx, "203.0.113.9", 53, payload); err == nil {
		t.Fatal("SendTo to a public address succeeded; want overlay-only rejection")
	}

	// Close unblocks a pending Receive.
	receiveErr := make(chan error, 1)
	go func() {
		_, _, _, err := channel.Receive(context.Background())
		receiveErr <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := channel.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-receiveErr:
		if err == nil {
			t.Fatal("Receive returned success after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Receive")
	}
}

// TestAgentDatagramBackendReceivesTargetReply is the Agent-side completion of the
// UDP business path: the SOCKS5 backend's origin association sends a REQUEST to
// a real public-SDK Network.ListenPacket target, the target answers the exact
// peer it received from through flow.Manager.Reply, and the Agent channel
// Receive returns that REPLY payload from the real target endpoint. No capture
// delivery or internal mock is involved.
//
// The overlay datagram path has no protocol-level retransmission: a REQUEST or
// its REPLY can be lost while the PACKET route converges, and the target's reply
// WriteTo can transiently fail with "no route: no route" for one datagram. The
// client therefore re-sends and re-receives under one bounded 30s budget until it
// observes an exact echo from the exact target endpoint. Each Receive attempt is
// bounded by its own context, which neither closes the association nor discards a
// datagram already queued for it; only a terminal backend error fails early.
func TestAgentDatagramBackendReceivesTargetReply(t *testing.T) {
	const (
		name  = "agent-udp-reply"
		cidr  = "10.116.0.0/24"
		token = "agent-udp-reply-token-01234"

		// One overall budget bounds the acceptance scenario. Every receive
		// attempt is bounded separately so a lost datagram is retried instead
		// of consuming the whole budget in one blocking Receive.
		overallBudget        = 30 * time.Second
		receiveAttemptBudget = time.Second
		retryPause           = 50 * time.Millisecond
	)
	sourceIP := netip.MustParseAddr("10.116.0.1")
	targetIP := netip.MustParseAddr("10.116.0.3")
	targetAddr := netip.AddrPortFrom(targetIP, 41010)

	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, sourceIP.String(), relayCarrierURL(target))

	// The target is an ordinary SDK application: it listens on its own VIP and
	// echoes every datagram back to its real source.
	targetConn, err := target.ListenPacket("udp", targetAddr.String())
	if err != nil {
		t.Fatalf("target ListenPacket: %v", err)
	}
	defer targetConn.Close()

	waitRelayLinks(t, source, 3, 30*time.Second)
	waitRelayLinks(t, target, 3, 30*time.Second)
	waitPacketRoute(t, source, targetIP, 30*time.Second)
	waitPacketRoute(t, target, sourceIP, 30*time.Second)

	// A reply WriteTo failure is a transient failure of that one datagram's
	// return route, so the echo loop drops only that datagram and keeps echoing:
	// the client's own re-send covers it. The first WriteTo error is recorded for
	// diagnostics, and a terminal ReadFrom failure is recorded on a separate
	// channel so the transient error can never hide it.
	echoWriteErr := make(chan error, 1)
	echoReadErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, flow.MaxDatagramPayload)
		for {
			n, from, err := targetConn.ReadFrom(buffer)
			if err != nil {
				select {
				case echoReadErr <- err:
				default:
				}
				return
			}
			if _, err := targetConn.WriteTo(buffer[:n], from); err != nil {
				select {
				case echoWriteErr <- err:
				default:
				}
				continue
			}
		}
	}()
	firstEchoWriteErr := func() error {
		select {
		case err := <-echoWriteErr:
			return err
		default:
			return nil
		}
	}

	backend := newAgentDatagramBackend(source.streams)
	ctx, cancel := context.WithTimeout(context.Background(), overallBudget)
	defer cancel()
	channel, err := backend.NewAssociation(ctx)
	if err != nil {
		t.Fatalf("NewAssociation: %v", err)
	}
	defer channel.Close()

	payload := []byte("agent-udp-reply-payload")
	// A terminal backend error can never succeed inside this scenario and fails
	// immediately; route convergence errors (no route / route stale / resource)
	// stay retryable until the overall budget is spent.
	terminal := func(err error) bool {
		return errors.Is(err, ErrClosed) ||
			errors.Is(err, flow.ErrClosed) ||
			errors.Is(err, flow.ErrAssociationClosed) ||
			errors.Is(err, flow.ErrDatagramTooLarge) ||
			errors.Is(err, ErrPermissionDenied) ||
			errors.Is(err, ErrInvalidConfig)
	}

	var lastSendErr, lastRecvErr error
	attempts := 0
	received := false
	for !received {
		if ctx.Err() != nil {
			t.Fatalf("Agent never received the target echo within %s after %d attempts; last SendTo error: %v; last Receive error: %v; first target echo WriteTo error: %v",
				overallBudget, attempts, lastSendErr, lastRecvErr, firstEchoWriteErr())
		}
		attempts++
		// SendTo and Receive share the one overall context; only the receive
		// attempt gets a shorter derived context, whose cancellation is scoped
		// to that call and never closes the association or drops a queued reply.
		if err := channel.SendTo(ctx, targetIP.String(), targetAddr.Port(), payload); err != nil {
			lastSendErr = err
			if terminal(err) {
				t.Fatalf("SendTo failed terminally on attempt %d: %v; first target echo WriteTo error: %v", attempts, err, firstEchoWriteErr())
			}
			select {
			case <-ctx.Done():
			case <-time.After(retryPause):
			}
			continue
		}
		recvCtx, recvCancel := context.WithTimeout(ctx, receiveAttemptBudget)
		host, port, echoed, err := channel.Receive(recvCtx)
		recvCancel()
		if err != nil {
			lastRecvErr = err
			if errors.Is(err, ErrClosed) {
				t.Fatalf("Receive failed terminally on attempt %d: %v; last SendTo error: %v; first target echo WriteTo error: %v", attempts, err, lastSendErr, firstEchoWriteErr())
			}
			continue
		}
		if !bytes.Equal(echoed, payload) {
			t.Fatalf("Agent received %q; want %q", echoed, payload)
		}
		if host != targetIP.String() || port != targetAddr.Port() {
			t.Fatalf("reply source = %s:%d; want %s:%d", host, port, targetIP, targetAddr.Port())
		}
		received = true
	}

	// The echo loop's own terminal error is never hidden by the transient one; a
	// single lost datagram alone never fails the test.
	select {
	case err := <-echoReadErr:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, ErrClosed) {
			t.Fatalf("target echo loop: %v", err)
		}
	default:
	}
	select {
	case err := <-echoWriteErr:
		t.Logf("target echo WriteTo failed at least once (that datagram was dropped and the client retried); first error: %v", err)
	default:
	}
}
