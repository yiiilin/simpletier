package simpletier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/packet"
	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/topology"
)

// withRateLimits installs one lowered budget for the duration of one test and
// restores the frozen production defaults at cleanup. It is the only test seam
// of the rate controls: it is unexported, package-level and serial (the mutex is
// held for the whole override), and production never reads it. There is no
// Config field that can replace the frozen limits.
func withRateLimits(t *testing.T, limits rateLimits) {
	t.Helper()
	rateLimitSeam.mu.Lock()
	previous := rateLimitSeam.current.Load()
	rateLimitSeam.current.Store(&limits)
	t.Cleanup(func() {
		rateLimitSeam.current.Store(previous)
		rateLimitSeam.mu.Unlock()
	})
}

// waitForCondition polls one predicate until it holds or the deadline expires.
func waitForCondition(t *testing.T, what string, timeout time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !predicate() {
		t.Fatalf("%s never happened within %s", what, timeout)
	}
}

// countReadyLinks reports how many authenticated Links of the Network are still
// Ready. A packet-drop disposition must leave this unchanged.
func countReadyLinks(n *network) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	ready := 0
	for _, established := range n.activeLinks {
		if established != nil && established.Ready() {
			ready++
		}
	}
	return ready
}

// expectDevicePacket reads exactly one packet from device and requires it to be
// byte-identical to the injected one. It is defined in this file rather than
// borrowed from packet_runtime_test.go so that this rate test compiles on its
// own; the read is one bounded wait with no retry, so a packet that never
// arrives is a failure instead of a tolerated loss.
func expectDevicePacket(t *testing.T, device *testPacketDevice, want []byte, what string) {
	t.Helper()
	select {
	case got := <-device.outbound:
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: device received %d bytes, want the injected %d bytes unchanged", what, len(got), len(want))
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("%s: the device never received the packet", what)
	}
}

// TestRatePeerPacketIngressDropsAndCounts exercises the real two-Network packet
// path with a lowered per-peer PACKET budget: the source device injects eight
// complete IPv4 packets, exactly the burst reaches the target device, the rest
// are dropped and counted at the authenticated ingress hook, and the physical
// Link stays Ready (the frozen IP_PACKET disposition is drop + count, never a
// teardown). Only the numeric budget is a test seam; the Networks, the PACKET
// lane Path/Session, the sealing, the ingress classification and the counter are
// production code.
func TestRatePeerPacketIngressDropsAndCounts(t *testing.T) {
	limits := defaultRateLimits()
	// A zero refill makes the test deterministic: the burst is the whole budget
	// for the duration of the test.
	limits.peerPacketPerSecond = 0
	limits.peerPacketBurst = 3
	withRateLimits(t, limits)

	const (
		name  = "rate-packet-dataplane"
		cidr  = "10.96.0.0/24"
		token = "rate-packet-token-0123456789"
	)
	sourceIP := netip.MustParseAddr("10.96.0.1")
	targetIP := netip.MustParseAddr("10.96.0.3")

	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, sourceIP.String(), relayCarrierURL(target))

	sourceDevice := newTestPacketDevice(packet.DefaultDeviceMTU)
	targetDevice := newTestPacketDevice(packet.DefaultDeviceMTU)
	t.Cleanup(sourceDevice.close)
	t.Cleanup(targetDevice.close)
	if err := source.streams.enablePacketService(sourceDevice); err != nil {
		t.Fatalf("enable source packet plane: %v", err)
	}
	if err := target.streams.enablePacketService(targetDevice); err != nil {
		t.Fatalf("enable target packet plane: %v", err)
	}
	source.streams.startPacketDevice()
	target.streams.startPacketDevice()

	waitRelayLinks(t, target, 3, 30*time.Second)
	waitRelayLinks(t, source, 3, 30*time.Second)
	waitPacketRoute(t, source, targetIP, 30*time.Second)
	// The target must also have converged the reverse PACKET-lane graph before
	// the flood: Receive resolves the inner source /32 from the target's own
	// RouteView, and a packet whose source is not yet resolvable there is a
	// counted no-route drop that would consume a token of the burst and make the
	// delivery count nondeterministic. This matches flow_relay_test.go,
	// udp_socket_test.go and agent_udp_test.go.
	waitPacketRoute(t, target, sourceIP, 30*time.Second)
	if ready := countReadyLinks(target); ready == 0 {
		t.Fatal("target owns no Ready Link before the flood")
	}

	// Both endpoints must answer that route from a settled RouteView, and the
	// class-1 PACKET Path/Session the flood reuses must already be established.
	// A route lookup that races the fact plane's last settling commits fails as
	// route-stale; on the target's receive path that failure is charged against
	// the per-peer PACKET budget before the packet Service refuses the packet, so
	// a flood that races the settling window spends burst tokens on packets that
	// are dropped instead of delivered. That is the nondeterminism this test used
	// to show, and it is removed by waiting for the settled view rather than by
	// tolerating the lost delivery.
	waitPacketViewFresh(t, source, "source egress PACKET view", 30*time.Second)
	waitPacketViewFresh(t, target, "target receive-path PACKET view", 30*time.Second)
	targetIdentity, err := target.identityStore.Identity()
	if err != nil {
		t.Fatalf("target identity: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := source.streams.packetPairFor(ctx, topology.NodeID(targetIdentity.NodeID)); err != nil {
		t.Fatalf("establish the class-1 PACKET pair before the flood: %v", err)
	}
	if _, err := (&packetRouteResolver{rt: target.streams}).ResolvePacketRoute(ctx, sourceIP); err != nil {
		t.Fatalf("target cannot resolve the inner source %s before the flood: %v", sourceIP, err)
	}

	sourceService := packetServiceOf(source.streams)
	targetService := packetServiceOf(target.streams)
	if sourceService == nil || targetService == nil {
		t.Fatal("both Networks must have a packet plane installed")
	}

	const injected = 8
	raw := buildIPv4Packet(sourceIP, targetIP, 1 /* ICMP */, []byte("rate-packet-payload"))
	// Drive the flood one packet at a time and require the target's
	// authenticated ingress hook to account for each injected packet before the
	// next injection. The per-peer limiter is charged on INGRESS, so a packet
	// lost before that hook would silently reduce the delivered count and make
	// "the burst was delivered" unsound. Every injected packet is accounted
	// exactly once: rejected by the peer limiter, or admitted and handed to the
	// packet Service (written to the device, or dropped under its own
	// DropReason).
	for i := 1; i <= injected; i++ {
		sourceDevice.inject(raw)
		deadline := time.Now().Add(15 * time.Second)
		for {
			targetStats := targetService.Stats()
			if target.rates.stats().PacketRejected+targetStats.Received+targetStats.Dropped >= uint64(i) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("injected packet %d was never accounted at the target ingress: source=%+v target=%+v rates=%+v",
					i, sourceService.Stats(), targetStats, target.rates.stats())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	// The source dispatched every injection on the established pair: no
	// injection may be lost before the target's ingress hook.
	if sent := sourceService.Stats(); sent.Sent != injected || sent.Dropped != 0 {
		t.Fatalf("source packet Service stats = %+v; want %d dispatched packets and no drop", sent, injected)
	}
	// Exactly the burst was admitted by the per-peer limiter and reached the
	// device; no admitted packet was dropped past the limiter.
	targetStats := targetService.Stats()
	if targetStats.Received != uint64(limits.peerPacketBurst) || targetStats.Dropped != 0 {
		t.Fatalf("target packet Service stats = %+v; want exactly %v packets received and no admitted packet dropped",
			targetStats, limits.peerPacketBurst)
	}
	for i := 1; i <= int(limits.peerPacketBurst); i++ {
		expectDevicePacket(t, targetDevice, raw, fmt.Sprintf("burst packet %d", i))
	}
	// No further packet may arrive: the budget is exhausted and never refills.
	select {
	case <-targetDevice.outbound:
		t.Fatal("a packet past the exhausted per-peer budget was delivered")
	case <-time.After(300 * time.Millisecond):
	}
	// The limiter rejected exactly the packets past the burst.
	rejected := target.rates.stats().PacketRejected
	if rejected != injected-uint64(limits.peerPacketBurst) {
		t.Fatalf("PacketRejected = %d; want %d", rejected, injected-uint64(limits.peerPacketBurst))
	}
	// The drop disposition must never tear down the physical Link.
	if ready := countReadyLinks(target); ready == 0 {
		t.Fatal("the packet rate limit tore down the physical Link")
	}
	if source.isClosed() || target.isClosed() {
		t.Fatal("the packet rate limit closed a Network")
	}
	// The source is the authenticated peer, so the target's peer bucket must be
	// keyed by the source NodeID only.
	sourceIdentity, err := source.identityStore.Identity()
	if err != nil {
		t.Fatalf("source identity: %v", err)
	}
	target.rates.mu.Lock()
	_, sourceBucketExists := target.rates.peers[sourceIdentity.NodeID]
	target.rates.mu.Unlock()
	if !sourceBucketExists {
		t.Fatal("the per-peer PACKET bucket is not keyed by the authenticated envelope sender NodeID")
	}
}

// TestRateListenerPreauthCeilingClosesBeforeAuth exercises the real carrier
// listener with a lowered per-listener pre-auth ceiling: carriers inside the
// ceiling are admitted into the pending pool, a carrier past it is closed before
// any identity/Noise work and counted, and the refusal is never attributed to the
// separate 16-way handshake concurrency gate.
func TestRateListenerPreauthCeilingClosesBeforeAuth(t *testing.T) {
	limits := defaultRateLimits()
	limits.preauthTotal = 4
	// Keep the per-source budget out of the way so this test is about the
	// per-listener ceiling only.
	limits.sourceConnectPerSec = 1000
	limits.sourceConnectBurst = 1000
	withRateLimits(t, limits)

	n := admissionNetworkAt(t, filepath.Join(t.TempDir(), "state"), nil)
	address := n.carrierListeners[0].Addr().String()

	pending := make([]net.Conn, 0, 4)
	t.Cleanup(func() {
		for _, conn := range pending {
			_ = conn.Close()
		}
	})
	for i := 0; i < 4; i++ {
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			t.Fatalf("carrier %d dial: %v", i, err)
		}
		pending = append(pending, conn)
	}
	// PreauthActive is raised by admission.begin() (network.go:1378) and
	// HandshakePending by admitHandshake() a few lines later in the same loop
	// iteration (network.go:1382; network.go:1379-1381 is admission.begin()'s
	// refusal branch), and stats() loads the two atomics separately. Waiting on
	// PreauthActive alone can therefore snapshot the moment before the fourth
	// carrier reaches the gate. Wait for the invariant this test means instead:
	// all four carriers admitted into the pending pool AND all four occupying the
	// separate 16-way handshake gate.
	waitForCondition(t, "4 carriers admitted into the pending pool (PreauthActive == 4) and holding the separate 16-way handshake gate (HandshakePending == 4)", 10*time.Second, func() bool {
		stats := n.rates.stats()
		return stats.PreauthActive == 4 && stats.HandshakePending == 4
	})
	// One snapshot for the remaining assertions, so they read a consistent view.
	inside := n.rates.stats()
	if inside.HandshakePending != 4 || inside.PreauthActive != 4 {
		t.Fatalf("PreauthActive = %d, HandshakePending = %d; want both 4 (the 16-way gate is separate)",
			inside.PreauthActive, inside.HandshakePending)
	}
	if inside.PreauthReject != 0 {
		t.Fatalf("PreauthReject = %d before the overflow carrier; want 0", inside.PreauthReject)
	}

	overflow, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("overflow dial: %v", err)
	}
	defer overflow.Close()
	if err := overflow.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := overflow.Read(data[:]); err == nil {
		t.Fatal("a carrier past the per-listener pre-auth ceiling stayed open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("a carrier past the per-listener pre-auth ceiling was not promptly closed")
	}
	waitForCondition(t, "pre-auth refusal counted", 2*time.Second, func() bool {
		return n.rates.stats().PreauthReject == 1
	})
	after := n.rates.stats()
	if after.PreauthActive != 4 {
		t.Fatalf("PreauthActive = %d after the refusal; want the 4 pending carriers", after.PreauthActive)
	}
	if after.HandshakeReject != 0 {
		t.Fatalf("HandshakeReject = %d; the refusal must not be attributed to the 16-way gate", after.HandshakeReject)
	}

	if err := n.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitForCondition(t, "pre-auth carriers released", 2*time.Second, func() bool {
		return n.rates.stats().PreauthActive == 0
	})
}

// TestRateHandshakeGateAndPreauthAreSeparate proves the two frozen bounds are
// independent counters: the 16-way handshake concurrency gate and the
// per-listener 128 active pre-auth ceiling. It also records the honest residual:
// while the no-queue 16-way gate closes the 17th carrier, the 128 ceiling is a
// real per-listener check but cannot become the binding bound.
func TestRateHandshakeGateAndPreauthAreSeparate(t *testing.T) {
	n := admissionNetworkAt(t, filepath.Join(t.TempDir(), "state"), nil)
	address := n.carrierListeners[0].Addr().String()

	pending := make([]net.Conn, 0, rateHandshakeConcurrent)
	t.Cleanup(func() {
		for _, conn := range pending {
			_ = conn.Close()
		}
	})
	// Sixteen same-source carriers: the default per-source budget (4/s burst 8)
	// paces the last eight, and every one of them still holds its handshake slot
	// while it waits, so the 16-way pool fills.
	for i := 0; i < rateHandshakeConcurrent; i++ {
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			t.Fatalf("carrier %d dial: %v", i, err)
		}
		pending = append(pending, conn)
	}
	waitForCondition(t, "16-way handshake gate filled", 15*time.Second, func() bool {
		stats := n.rates.stats()
		return stats.HandshakePending == rateHandshakeConcurrent && stats.PreauthActive == rateHandshakeConcurrent
	})
	stats := n.rates.stats()
	if stats.PreauthReject != 0 {
		t.Fatalf("PreauthReject = %d with 16 carriers; want 0 (the ceiling is 128)", stats.PreauthReject)
	}

	overflow, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("overflow dial: %v", err)
	}
	defer overflow.Close()
	if err := overflow.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := overflow.Read(data[:]); err == nil {
		t.Fatal("the 17th carrier stayed open past the 16-way gate")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("the 17th carrier was not promptly closed")
	}
	waitForCondition(t, "concurrency refusal counted", 2*time.Second, func() bool {
		return n.rates.stats().HandshakeReject >= 1
	})
	// The 17th refusal came from the 16-way gate; the 128-connection ceiling
	// stayed untouched and non-binding (reported residual, not a false claim).
	if stats := n.rates.stats(); stats.PreauthReject != 0 {
		t.Fatalf("PreauthReject = %d after the 17th carrier; want 0", stats.PreauthReject)
	}
}

// TestRateSourceKeyIsIPv4HostOnly proves the production source normalization on
// real accepted carriers: two connections from the same host on different
// ephemeral ports share one key, an unparsable/non-IPv4 address falls into the one
// shared invalid-source bucket, and the real limiter over that key replenishes
// from an injected clock (the burst is shared, so rotating ports cannot refill
// it).
func TestRateSourceKeyIsIPv4HostOnly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	first, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer first.Close()
	second, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer second.Close()
	keyA := rateSourceKey(first.LocalAddr())
	keyB := rateSourceKey(second.LocalAddr())
	if keyA != "127.0.0.1" || keyB != "127.0.0.1" {
		t.Fatalf("normalized keys = %q/%q; want the IPv4 host only", keyA, keyB)
	}
	if keyA != keyB {
		t.Fatalf("two ports of one host normalized to different keys %q/%q", keyA, keyB)
	}
	if got := rateSourceKey(nil); got != sourceInvalidKey {
		t.Fatalf("nil address key = %q; want %q", got, sourceInvalidKey)
	}
	if got := rateSourceKey(&net.TCPAddr{IP: net.ParseIP("::1"), Port: 4000}); got != sourceInvalidKey {
		t.Fatalf("IPv6 address key = %q; want the shared invalid-source bucket", got)
	}
	if got := rateSourceKey(&net.TCPAddr{}); got != sourceInvalidKey {
		t.Fatalf("hostless address key = %q; want the shared invalid-source bucket", got)
	}

	limits := defaultRateLimits()
	limits.sourceConnectBurst = 1
	limits.sourceConnectPerSec = 2
	withRateLimits(t, limits)
	clock := &rateTestClock{now: time.Unix(1_700_000_000, 0)}
	rates := newNetworkRatesWithClock(clock.Now)
	if ok, _ := rates.trySourceConnect(keyA); !ok {
		t.Fatal("the first connect of the shared source bucket was refused")
	}
	// The second ephemeral port of the same host must not have its own budget.
	if ok, wait := rates.trySourceConnect(keyB); ok {
		t.Fatal("a second ephemeral port of the same host obtained a fresh burst")
	} else if wait <= 0 {
		t.Fatalf("shared-bucket refusal reported wait %s; want a positive refill wait", wait)
	}
	clock.Advance(500 * time.Millisecond)
	if ok, _ := rates.trySourceConnect(keyB); !ok {
		t.Fatal("2/s bucket did not replenish one token after 500ms")
	}
	if ok, _ := rates.trySourceConnect(keyA); ok {
		t.Fatal("the replenished token was admitted twice")
	}
}

// TestRateSourceBudgetClosesCarrierBeforeAuth exercises the per-source budget on
// the real listener: the first carrier of a host is admitted into the pending
// pool, and the next carrier of the same host on a different ephemeral port is
// closed before any identity/Noise work once the bounded wait expires.
func TestRateSourceBudgetClosesCarrierBeforeAuth(t *testing.T) {
	limits := defaultRateLimits()
	limits.sourceConnectPerSec = 0
	limits.sourceConnectBurst = 1
	limits.sourceConnectWait = 150 * time.Millisecond
	withRateLimits(t, limits)

	n := admissionNetworkAt(t, filepath.Join(t.TempDir(), "state"), nil)
	address := n.carrierListeners[0].Addr().String()

	first, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("first carrier dial: %v", err)
	}
	defer first.Close()
	waitForCondition(t, "first carrier admitted into the pending pool", 5*time.Second, func() bool {
		return n.rates.stats().PreauthActive == 1
	})

	second, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("second carrier dial: %v", err)
	}
	defer second.Close()
	if err := second.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := second.Read(data[:]); err == nil {
		t.Fatal("an over-budget source carrier stayed open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("an over-budget source carrier was not closed inside the bounded wait")
	}
	waitForCondition(t, "source refusal counted", 2*time.Second, func() bool {
		return n.rates.stats().SourceRejected == 1
	})
	// The refused carrier released its handshake slot; the first one is untouched.
	waitForCondition(t, "refused carrier released its handshake slot", 2*time.Second, func() bool {
		stats := n.rates.stats()
		return stats.HandshakePending == 1 && stats.PreauthActive == 1
	})
	if stats := n.rates.stats(); stats.ControlWaitTimeout != 0 {
		t.Fatalf("ControlWaitTimeout = %d; the source gate must not touch the control budget", stats.ControlWaitTimeout)
	}
}

// TestRateControlBudgetTearsDownFloodingLink exercises the real inbound control
// path of an authenticated Link. A manual initiator performs a real
// Noise/CAPABILITY handshake against a real listening Network and then floods
// LINK_CTRL frames past the frozen per-Link budget. The Link reader paces the
// flood, the bounded wait expires, the offending Link is retired with a counted
// outcome, and the second healthy Link of the same peer stays Ready: the failure
// is scoped to the offending Link, never to the peer or the Network.
func TestRateControlBudgetTearsDownFloodingLink(t *testing.T) {
	limits := defaultRateLimits()
	limits.linkControlPerSecond = 1
	limits.linkControlBurst = 8
	// Keep the Network-wide aggregate out of the way: this test is about the
	// per-Link bound.
	limits.networkControlPerSec = 100
	limits.networkControlBurst = 100
	limits.controlWait = 25 * time.Millisecond
	withRateLimits(t, limits)

	server := admissionNetwork(t, admissionOrderToken)
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	offender := dialManualInitiator(t, server, identity, 0x5151, 51, 515)
	dialManualInitiator(t, server, identity, 0x6161, 61, 616)
	waitAdmissionLinks(t, server, 2)

	server.mu.Lock()
	offendingPump := server.controlPumps[0x5151]
	healthyLink := server.activeLinks[0x6161]
	server.mu.Unlock()
	if offendingPump == nil {
		t.Fatal("the offending Link has no registered pump")
	}

	// Flood the real authenticated control path well past the burst.
	frame := link.ControlMessage{Type: 1, Payload: bytes.Repeat([]byte{0x5a}, 16)}
	for i := 0; i < 60; i++ {
		// A write failure is expected once the server retires the Link.
		_ = offender.control.WriteControl(frame)
	}

	waitForCondition(t, "offending Link retired", 10*time.Second, func() bool {
		select {
		case <-offendingPump.link.Done():
			return true
		default:
		}
		return false
	})
	waitForCondition(t, "bounded control wait outcome counted", 5*time.Second, func() bool {
		return server.rates.stats().ControlWaitTimeout >= 1
	})
	// The server closes the offending carrier; the read may first drain any
	// already-delivered frames, so poll for an actual close rather than a timeout.
	waitForCondition(t, "offending carrier closed by the server", 5*time.Second, func() bool {
		if err := offender.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return false
		}
		var data [1]byte
		_, err := offender.conn.Read(data[:])
		if err == nil {
			return false
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return false
		}
		return true
	})

	// The healthy Link of the same peer survives, and the Network itself is open.
	if healthyLink == nil || !healthyLink.Ready() {
		t.Fatal("a sibling Link of the same peer was torn down with the offender")
	}
	if server.isClosed() {
		t.Fatal("the control budget closed the Network instead of the offending Link")
	}
	// The charge was keyed by the exact pinned Link tuple.
	server.rates.mu.Lock()
	_, bucketExists := server.rates.links[[2]uint64{offendingPump.linkKey.LinkID, offendingPump.linkKey.Epoch}]
	server.rates.mu.Unlock()
	if !bucketExists {
		t.Fatal("the per-Link control bucket is not keyed by the exact LinkID/LinkEpoch")
	}
	if stats := server.rates.stats(); stats.ControlWaitTimeout == 0 {
		t.Fatal("no control wait-timeout outcome was counted")
	}
}

// TestRateControlHelperChargesPinnedLinkBudget pins the Network-level control
// helper contract the circuit plane calls for a CONTROL_RPC frame: the charge is
// keyed by the exact pinned pump's LinkID/LinkEpoch, an admitted frame returns
// nil, a frame the bounded budget never admits returns ErrResource and counts
// exactly one ControlWaitTimeout, and the helper never touches another Link's
// bucket. The RPC call site itself lives in circuit_runtime.go, outside this
// slice; this test proves the helper's exact-key charge on a real authenticated
// Link.
func TestRateControlHelperChargesPinnedLinkBudget(t *testing.T) {
	limits := defaultRateLimits()
	limits.linkControlPerSecond = 0
	limits.linkControlBurst = 4
	limits.networkControlPerSec = 100
	limits.networkControlBurst = 100
	limits.controlWait = 10 * time.Millisecond
	withRateLimits(t, limits)

	server := admissionNetwork(t, admissionOrderToken)
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dialManualInitiator(t, server, identity, 0x7171, 71, 717)
	waitAdmissionLinks(t, server, 1)

	server.mu.Lock()
	pump := server.controlPumps[0x7171]
	server.mu.Unlock()
	if pump == nil {
		t.Fatal("no registered pump for the control Link")
	}
	linkID, epoch := pump.linkKey.LinkID, pump.linkKey.Epoch

	admitted, refused := 0, 0
	for i := 0; i < 8; i++ {
		err := server.awaitIngressControl(context.Background(), linkID, epoch)
		switch {
		case err == nil:
			admitted++
		case errors.Is(err, ErrResource):
			refused++
		default:
			t.Fatalf("awaitIngressControl returned %v; want nil or ErrResource", err)
		}
	}
	if admitted == 0 {
		t.Fatal("no control frame was admitted inside the burst")
	}
	if refused == 0 {
		t.Fatal("the exhausted control budget admitted every frame")
	}
	stats := server.rates.stats()
	// The Link's own control traffic shares this budget, and a frame refused while a
	// concurrent pump frame is also waiting can charge more than one timeout for the
	// same window. What must hold is that no refusal went unrecorded: the counter
	// covers every refused frame, and never reports fewer refusals than happened.
	if stats.ControlWaitTimeout < uint64(refused) {
		t.Fatalf("ControlWaitTimeout = %d; want at least one per refused frame (%d)", stats.ControlWaitTimeout, refused)
	}
	// The egress twin charges the same frozen budget, so it must observe the
	// exhaustion too.
	if err := server.awaitEgressControl(context.Background(), linkID, epoch); err == nil {
		t.Fatal("awaitEgressControl admitted a frame after the budget was exhausted")
	}
	// The charge is keyed by the exact pinned tuple and no other bucket exists.
	server.rates.mu.Lock()
	buckets := len(server.rates.links)
	_, exact := server.rates.links[[2]uint64{linkID, epoch}]
	server.rates.mu.Unlock()
	if !exact {
		t.Fatal("the control bucket is not keyed by the exact pinned LinkID/LinkEpoch")
	}
	if buckets != 1 {
		t.Fatalf("limiter holds %d per-Link buckets; want exactly the pinned one", buckets)
	}
}

// TestRatePreauthReservationNeverOvershoots hammers one listener admission object
// from many goroutines with a low ceiling: the compare-and-swap reservation must
// admit exactly the ceiling and reject the rest, never overshoot it. The object is
// the production per-listener accounting of rejectUnauthenticatedCarriers, so this
// is the concurrency proof of the ceiling itself, independent of any OS accept
// backlog.
func TestRatePreauthReservationNeverOvershoots(t *testing.T) {
	const limit = 8
	limits := defaultRateLimits()
	limits.preauthTotal = limit
	withRateLimits(t, limits)
	rates := newNetworkRatesWithClock(time.Now)
	admission := &listenerAdmission{rates: rates}

	const callers = 64
	start := make(chan struct{})
	results := make(chan bool, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- admission.begin()
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	admitted, refused := 0, 0
	for ok := range results {
		if ok {
			admitted++
		} else {
			refused++
		}
	}
	if admitted != limit {
		t.Fatalf("admitted %d carriers; want exactly the ceiling %d", admitted, limit)
	}
	if refused != callers-limit {
		t.Fatalf("refused %d carriers; want %d", refused, callers-limit)
	}
	if active := admission.active.Load(); active != limit {
		t.Fatalf("per-listener active counter = %d; want %d", active, limit)
	}
	stats := rates.stats()
	if stats.PreauthActive != limit || stats.PreauthTotal != limit || stats.PreauthReject != callers-limit {
		t.Fatalf("pre-auth stats = %+v; want active=%d total=%d reject=%d", stats, limit, limit, callers-limit)
	}
	// A release must not free a slot when it has no matching reservation.
	admission.release()
	if active := admission.active.Load(); active != limit-1 {
		t.Fatalf("release left %d; want %d", active, limit-1)
	}
	for i := 0; i < limit+4; i++ {
		admission.release()
	}
	if active := admission.active.Load(); active != 0 {
		t.Fatalf("saturating release left %d; want 0", active)
	}
}

// TestRatePreauthBoundaryIsTheConcurrencyGate pins the actual enforcement
// boundary of this runtime instead of a slogan. With a lowered non-queue
// handshake gate (2 slots) the per-listener pre-auth counter can never exceed the
// gate, because a carrier that loses the gate releases its pre-auth reservation
// immediately. All three carriers still pass the 128 check (PreauthTotal==3,
// PreauthReject==0), so the binding bound is the gate (PreauthActive==2,
// HandshakeReject>=1), never the 128 ceiling. It also proves the bounded
// per-source pacing runs inside the per-carrier goroutine and outside the accept
// loop: the two stalled carriers do not delay the prompt rejection of the third.
func TestRatePreauthBoundaryIsTheConcurrencyGate(t *testing.T) {
	limits := defaultRateLimits()
	limits.handshakeConcurrent = 2
	// Stall the pacing of the carriers that hold a gate slot, so the prompt
	// rejection of the next carrier can only come from the non-queue gate.
	limits.sourceConnectPerSec = 0
	limits.sourceConnectBurst = 1
	limits.sourceConnectWait = 5 * time.Second
	withRateLimits(t, limits)

	n := admissionNetworkAt(t, filepath.Join(t.TempDir(), "state"), nil)
	address := n.carrierListeners[0].Addr().String()

	held := make([]net.Conn, 0, 2)
	t.Cleanup(func() {
		for _, conn := range held {
			_ = conn.Close()
		}
	})
	for i := 0; i < 2; i++ {
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			t.Fatalf("carrier %d dial: %v", i, err)
		}
		held = append(held, conn)
	}
	waitForCondition(t, "both gate slots filled and pre-auth accounted", 5*time.Second, func() bool {
		stats := n.rates.stats()
		return stats.PreauthActive == 2 && stats.HandshakePending == 2
	})

	started := time.Now()
	overflow, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("overflow dial: %v", err)
	}
	defer overflow.Close()
	if err := overflow.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := overflow.Read(data[:]); err == nil {
		t.Fatal("a carrier past the non-queue gate stayed open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("a carrier past the non-queue gate was not promptly rejected")
	}
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("overflow carrier was rejected after %s; the accept loop must not wait on per-source pacing", elapsed)
	}
	waitForCondition(t, "gate refusal counted", 2*time.Second, func() bool {
		return n.rates.stats().HandshakeReject >= 1
	})
	stats := n.rates.stats()
	if stats.PreauthTotal != 3 {
		t.Fatalf("PreauthTotal = %d; want 3 (all three carriers passed the 128 check)", stats.PreauthTotal)
	}
	if stats.PreauthReject != 0 {
		t.Fatalf("PreauthReject = %d; the 128 ceiling must not be the binding bound here", stats.PreauthReject)
	}
	if stats.PreauthActive != 2 {
		t.Fatalf("PreauthActive = %d; want the gate size 2 (pre-auth is released with a lost gate slot)", stats.PreauthActive)
	}
	if stats.HandshakePending != 2 {
		t.Fatalf("HandshakePending = %d; want 2", stats.HandshakePending)
	}
}
