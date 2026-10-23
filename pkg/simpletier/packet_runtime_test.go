package simpletier

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/packet"
	"github.com/yiiilin/simpletier/internal/topology"
	"github.com/yiiilin/simpletier/internal/wire"
)

// testPacketDevice is a production-shaped virtual L3 device: it yields exactly
// one complete IPv4 packet per ReadPacket and records every WritePacket. It
// deliberately performs no kernel routing, so the two-Network test cannot pass
// through the same-namespace kernel local-address path.
type testPacketDevice struct {
	mtu      int
	inbound  chan []byte
	outbound chan []byte
	closed   chan struct{}
	once     sync.Once
}

func newTestPacketDevice(mtu int) *testPacketDevice {
	return &testPacketDevice{
		mtu:      mtu,
		inbound:  make(chan []byte, 8),
		outbound: make(chan []byte, 8),
		closed:   make(chan struct{}),
	}
}

func (d *testPacketDevice) MTU() int { return d.mtu }

func (d *testPacketDevice) WritePacket(ctx context.Context, raw []byte) error {
	select {
	case d.outbound <- append([]byte(nil), raw...):
		return nil
	case <-d.closed:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *testPacketDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	select {
	case raw := <-d.inbound:
		return copy(buf, raw), nil
	case <-d.closed:
		return 0, net.ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (d *testPacketDevice) inject(raw []byte) { d.inbound <- append([]byte(nil), raw...) }
func (d *testPacketDevice) close()            { d.once.Do(func() { close(d.closed) }) }

func newPacketPlaneNode(t *testing.T, name, cidr, token, fixedIP, upstream string) *network {
	t.Helper()
	listenURL, _ := freeTCPListenAddress(t)
	cfg := Config{
		Listen:  []string{listenURL},
		Network: NetworkConfig{Name: name, CIDR: cidr, Token: token},
		Options: RuntimeOptions{FixedIP: fixedIP},
	}
	if upstream != "" {
		cfg.Upstreams = []string{upstream}
	}
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork(fixed_ip=%s) error = %v", fixedIP, err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle.(*network)
}

// waitPacketRoute waits until the source RouteView can pin a PACKET-lane path to
// the destination VirtualIP. The PACKET lane adjacency and its facts converge
// asynchronously, so dialing before this only burns retry backoff.
func waitPacketRoute(t *testing.T, n *network, dst netip.Addr, timeout time.Duration) {
	t.Helper()
	policy := topology.RoutePolicy{AllowRelay: true}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if route, err := n.facts.routes.PacketCandidates(dst, policy); err == nil && len(route.Candidates) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("packet route to %s never converged", dst)
}

// packetViewQuietWindow is how long one endpoint's FactStore must stop advancing
// before its published RouteView counts as settled for a timed PACKET
// injection. The fact plane commits its last settling frames right after an
// adjacency converges, and the next local re-advertisement is a whole
// localFactRefreshInterval (15s) away, so this window separates the two by two
// orders of magnitude.
const packetViewQuietWindow = 250 * time.Millisecond

// waitPacketViewFresh waits until n's PACKET RouteView is published from the
// current FactStore version and that version has stopped advancing for
// packetViewQuietWindow.
//
// Every PACKET route lookup -- egress in packetSender and, on the receive side,
// the ownership check in packet.Service.Receive -- reads the immutable RouteView
// and revalidates it against the live FactStore. Between a fact commit and the
// refresh worker's rebuild the lookup fails as topology.ErrRouteStale. On the
// receive path that failure is charged against the per-peer PACKET budget
// *before* the packet Service can refuse the packet, so a flood that races the
// settling fact plane spends burst tokens on packets that are then dropped
// instead of delivered: the packet counts as a limiter admission and never
// reaches the device. Waiting for a settled view on both endpoints is what makes
// the injected count deterministic.
func waitPacketViewFresh(t *testing.T, n *network, what string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var settledSince time.Time
	var version uint64
	for time.Now().Before(deadline) {
		store, view := n.facts.store.Version(), n.facts.routes.Version()
		if store == view && store == version && n.facts.routes.Freshness() == topology.RouteViewFresh {
			if settledSince.IsZero() {
				settledSince = time.Now()
			}
			if time.Since(settledSince) >= packetViewQuietWindow {
				return
			}
		} else {
			settledSince = time.Time{}
			version = store
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: the PACKET route view never settled (FactStore %d, view %d, freshness %v)",
		what, n.facts.store.Version(), n.facts.routes.Version(), n.facts.routes.Freshness())
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func buildIPv4Packet(src, dst netip.Addr, protocol uint8, payload []byte) []byte {
	raw := make([]byte, 20+len(payload))
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	binary.BigEndian.PutUint16(raw[4:6], 0x1234)
	raw[8] = 64
	raw[9] = protocol
	copy(raw[12:16], src.AsSlice())
	copy(raw[16:20], dst.AsSlice())
	copy(raw[20:], payload)
	binary.BigEndian.PutUint16(raw[10:12], ipv4Checksum(raw[:20]))
	return raw
}

// TestDirectPacketDeliveryOverTwoNetworks exercises the full production packet
// path across two real SDK Networks: the source device injects one complete IPv4
// packet, the class-1 PACKET-lane Path/Session is established as the same pair
// every packet reuses, the inner packet is sealed as IP_PACKET E2E, the target
// opens it and the target device receives byte-identical bytes. Nothing here
// fakes the Network: only the L3 device is virtual.
func TestDirectPacketDeliveryOverTwoNetworks(t *testing.T) {
	const (
		name  = "packet-dataplane"
		cidr  = "10.94.0.0/24"
		token = "packet-token-0123456789abcdef"
	)
	sourceIP := netip.MustParseAddr("10.94.0.1")
	targetIP := netip.MustParseAddr("10.94.0.3")

	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, sourceIP.String(), relayCarrierURL(target))

	sourceDevice := newTestPacketDevice(packet.DefaultDeviceMTU)
	targetDevice := newTestPacketDevice(packet.DefaultDeviceMTU)
	t.Cleanup(sourceDevice.close)
	t.Cleanup(targetDevice.close)
	// Installing the packet plane is what makes the Network establish the
	// dedicated PACKET lane; wait for it after enabling.
	if err := source.streams.enablePacketService(sourceDevice); err != nil {
		t.Fatalf("enable source packet plane: %v", err)
	}
	if err := target.streams.enablePacketService(targetDevice); err != nil {
		t.Fatalf("enable target packet plane: %v", err)
	}
	source.streams.startPacketDevice()
	target.streams.startPacketDevice()

	// Each adjacency now owns CONTROL + STREAM + PACKET lanes.
	waitRelayLinks(t, target, 3, 30*time.Second)
	waitRelayLinks(t, source, 3, 30*time.Second)

	waitPacketRoute(t, source, targetIP, 30*time.Second)
	// Both directions must be converged before the first packet is injected.
	// The target resolves the inner source /32 from its own PACKET-lane graph
	// before it may commit an authenticated packet to the device, so an
	// injection that races that convergence is a counted no-route drop at the
	// target and never a delivery -- exactly the failure this test used to
	// report as "target device never received the packet". The sibling packet
	// tests wait both directions for the same reason.
	waitPacketRoute(t, target, sourceIP, 30*time.Second)

	// The class-1 PACKET Path/Session must also be established and reusable
	// before the packet is injected, so the first packet is a plain E2E send
	// and not the establishment attempt itself. Completing this on the source
	// proves the target committed its responder Session too: the source only
	// commits after it has processed the target's SESSION_READY.
	targetIdentity, err := target.identityStore.Identity()
	if err != nil {
		t.Fatalf("target identity: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := source.streams.packetPairFor(ctx, topology.NodeID(targetIdentity.NodeID)); err != nil {
		t.Fatalf("establish the class-1 PACKET pair before injecting: %v", err)
	}

	// Both endpoints must also answer that route from a settled RouteView: a
	// lookup that races the fact plane's last settling commits fails as
	// route-stale, and on the target's receive path that drop is charged against
	// the per-peer PACKET budget before the packet Service refuses the packet,
	// so the injection would be lost instead of delivered.
	waitPacketViewFresh(t, source, "source egress PACKET view", 30*time.Second)
	waitPacketViewFresh(t, target, "target receive-path PACKET view", 30*time.Second)
	if _, err := (&packetRouteResolver{rt: target.streams}).ResolvePacketRoute(ctx, sourceIP); err != nil {
		t.Fatalf("target cannot resolve the inner source %s before injecting: %v", sourceIP, err)
	}

	raw := buildIPv4Packet(sourceIP, targetIP, 1 /* ICMP */, []byte("packet-plane-payload"))
	sourceDevice.inject(raw)

	select {
	case got := <-targetDevice.outbound:
		if !bytes.Equal(got, raw) {
			t.Fatalf("target device received %d bytes, want the injected %d bytes unchanged", len(got), len(raw))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("target device never received the packet")
	}
}

// packetServiceOf returns the packet Service installed on rt, or nil when the
// runtime has no packet plane. It takes the same lock the install path takes, so
// a test never races the field.
func packetServiceOf(rt *streamRuntime) *packet.Service {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.packets == nil {
		return nil
	}
	return rt.packets.service
}

// packetLaneLinks snapshots the currently Ready PACKET-lane Link instances of n,
// keyed by LinkID. A regression test can then require the exact instance that
// carried a dropped packet to stay Ready instead of accepting a replacement Link
// as "still up".
func packetLaneLinks(n *network) map[uint64]*link.Link {
	n.mu.Lock()
	defer n.mu.Unlock()
	links := make(map[uint64]*link.Link)
	for id, established := range n.activeLinks {
		if established != nil && established.Ready() && established.Metadata().LaneID == lanePacket {
			links[id] = established
		}
	}
	return links
}

// expectPacketDelivered reads one packet from the device and requires it to be
// byte-identical to the injected one. It performs exactly one bounded read: a
// caller that must survive a transient stale RouteView window uses
// injectPacketUntilDelivered (or waits for a settled view) instead.
func expectPacketDelivered(t *testing.T, device *testPacketDevice, want []byte, what string) {
	t.Helper()
	select {
	case got := <-device.outbound:
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: device received %d bytes, want the injected %d bytes unchanged", what, len(got), len(want))
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: the device never received the packet", what)
	}
}

// drainPackets discards every packet already queued at the device, so a retry
// never reads a copy left behind by a previous attempt.
func drainPackets(device *testPacketDevice) {
	for {
		select {
		case <-device.outbound:
		default:
			return
		}
	}
}

// injectPacketUntilDelivered injects one complete IPv4 packet at the source
// device and requires the byte-identical packet at the target device, retrying
// inside one bounded deadline.
//
// The retry does not weaken the regression. packet.Service performs exactly one
// dispatch attempt with no replay and no retry, so a packet that lands in a
// transiently stale RouteView window is a legitimate, counted DropRouteStale and
// is simply lost until the single RouteView refresh worker rebuilds the view. A
// real sender re-sends. Retrying here keeps this test about the Link and Session
// surviving a packet-plane drop instead of about RouteView refresh timing.
func injectPacketUntilDelivered(t *testing.T, sourceDevice, targetDevice *testPacketDevice, raw []byte, what string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		drainPackets(targetDevice)
		sourceDevice.inject(raw)
		select {
		case got := <-targetDevice.outbound:
			if !bytes.Equal(got, raw) {
				t.Fatalf("%s: device received %d bytes, want the injected %d bytes unchanged", what, len(got), len(raw))
			}
			return
		case <-time.After(time.Second):
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the device never received the packet within 30s of bounded retries", what)
		}
	}
}

// TestPacketPlaneDropRetainsLinkAndSession is the product regression for the
// confirmed fatal propagation of a packet-plane per-packet drop.
//
// One authenticated IP_PACKET whose inner source /32 the target cannot resolve
// makes packet.Service.Receive return topology.ErrNoRoute. The frozen
// per-MessageType disposition (MOD-WIRE-PROTOCOL C-WIRE-004: IP_PACKET /
// UDP_DATAGRAM overflow = drop + count) and FEAT-L3-VPN 3.4 (Dropped is a
// single-packet terminal state) require the physical PACKET Link, its Session and
// the Agent to survive. Before the fix the bare ErrNoRoute travelled back through
// deliverOpenedFrame -> openLocalEndToEnd -> handleEndToEndFrame -> consumeFrame,
// matched no frameLocalSemanticClassOf entry and made controlPump.read() take its
// fatal return, closing the shared PACKET Link and discarding every queued frame
// of every Session on it.
//
// Nothing here is a mock: two real Networks, the real class-1 PACKET-lane
// Path/Session, real hop + E2E sealing and the real ingress pump. The test only
// plays a peer that signs one packet whose inner source it does not own, which is
// exactly the authority an authenticated peer already has.
func TestPacketPlaneDropRetainsLinkAndSession(t *testing.T) {
	const (
		name  = "packet-drop-retains"
		cidr  = "10.95.0.0/24"
		token = "packet-drop-token-0123456789"
	)
	sourceIP := netip.MustParseAddr("10.95.0.1")
	targetIP := netip.MustParseAddr("10.95.0.3")
	// No node owns this /32, so the target's Receive resolves the inner source
	// and fails with ErrNoRoute: the confirmed defect's exact shape.
	unownedIP := netip.MustParseAddr("10.95.0.222")

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
	// Both directions must be converged: the target resolves the inner source of
	// an inbound packet from its own RouteView.
	waitPacketRoute(t, source, targetIP, 30*time.Second)
	waitPacketRoute(t, target, sourceIP, 30*time.Second)

	// A first real packet establishes the class-1 PACKET Path/Session and proves
	// the plane is healthy before the hostile frame.
	before := buildIPv4Packet(sourceIP, targetIP, 1 /* ICMP */, []byte("before-the-drop"))
	injectPacketUntilDelivered(t, sourceDevice, targetDevice, before, "first valid packet")

	linksBefore := packetLaneLinks(target)
	if len(linksBefore) == 0 {
		t.Fatal("target has no Ready PACKET-lane Link before the hostile packet")
	}

	targetIdentity, err := target.identityStore.Identity()
	if err != nil {
		t.Fatalf("target identity: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pair, err := source.streams.packetPairFor(ctx, topology.NodeID(targetIdentity.NodeID))
	if err != nil {
		t.Fatalf("resolve the established PACKET pair: %v", err)
	}
	service := packetServiceOf(target.streams)
	if service == nil {
		t.Fatal("target packet Service is not installed")
	}

	// Two hostile frames on the same established Session. The second one is the
	// deterministic discriminator: only a reader that survived the first can still
	// hand it to the packet plane, so a fatal first drop leaves the second drop
	// uncounted.
	hostile := buildIPv4Packet(unownedIP, targetIP, 1 /* ICMP */, []byte("unowned-source"))
	for i := 1; i <= 2; i++ {
		if err := source.streams.sendEndToEndFrame(pair, wire.MessageTypeIPPacket, hostile); err != nil {
			t.Fatalf("hostile IP_PACKET %d: a per-packet drop killed the PACKET Session: %v", i, err)
		}
		waitForCondition(t, fmt.Sprintf("packet Service counted drop %d", i), 15*time.Second, func() bool {
			return service.Stats().Drops[packet.DropNoRoute] >= uint64(i)
		})
	}
	if stats := service.Stats(); stats.Dropped != 2 || stats.Received != 1 {
		t.Fatalf("packet Service stats = %+v; want exactly 2 counted drops and the one delivered packet", stats)
	}

	// The exact physical PACKET Link instance that carried the dropped frames is
	// still admitted, and no replacement was needed.
	for id, established := range linksBefore {
		if !established.Ready() {
			t.Fatalf("the PACKET Link %d was torn down by a per-packet drop", id)
		}
		target.mu.Lock()
		current := target.activeLinks[id]
		target.mu.Unlock()
		if current != established {
			t.Fatalf("the PACKET Link %d was replaced after a per-packet drop", id)
		}
	}
	// The class-1 PACKET Session itself is retained, not re-established: the
	// same pair must still resolve to the same Session entry. This half of the
	// assertion is clock-free and independent of any RouteView refresh.
	reused, err := source.streams.packetPairFor(ctx, topology.NodeID(targetIdentity.NodeID))
	if err != nil {
		t.Fatalf("the established PACKET pair is gone after a per-packet drop: %v", err)
	}
	if reused.entry != pair.entry {
		t.Fatal("the class-1 PACKET Session was replaced after a per-packet drop")
	}
	if source.isClosed() || target.isClosed() {
		t.Fatal("a per-packet drop closed a Network")
	}

	// A later valid packet is still delivered on the surviving plane.
	after := buildIPv4Packet(sourceIP, targetIP, 1 /* ICMP */, []byte("after-the-drop"))
	injectPacketUntilDelivered(t, sourceDevice, targetDevice, after, "packet after the drop")
}
