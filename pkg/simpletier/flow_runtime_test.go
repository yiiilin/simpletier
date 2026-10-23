package simpletier

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/flow"
	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/packet"
	"github.com/yiiilin/simpletier/internal/session"
	"github.com/yiiilin/simpletier/internal/topology"
)

// captureFlowDelivery is the injected target-endpoint delivery port: it records
// every reassembled datagram boundary it is handed. It never reassembles or
// reorders anything itself; that is the Flow plane's job.
type captureFlowDelivery struct {
	datagrams chan flow.Datagram
}

func newCaptureFlowDelivery() *captureFlowDelivery {
	return &captureFlowDelivery{datagrams: make(chan flow.Datagram, 8)}
}

func (d *captureFlowDelivery) DeliverDatagram(ctx context.Context, datagram flow.Datagram) error {
	datagram.Payload = append([]byte(nil), datagram.Payload...)
	select {
	case d.datagrams <- datagram:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TestDirectUDPDatagramOverTwoNetworks exercises the production Flow UDP plane
// across two real SDK Networks: a REQUEST association fragments one maximum
// 65,507-byte datagram (two fragments) and one empty datagram over the shared
// class-1 PACKET-lane Path/Session as real UDP_DATAGRAM E2E frames, and the
// target Flow manager reassembles them and delivers each complete datagram once.
// Nothing here fakes the Network or the reassembly.
func TestDirectUDPDatagramOverTwoNetworks(t *testing.T) {
	const (
		name  = "flow-dataplane"
		cidr  = "10.98.0.0/24"
		token = "flow-token-0123456789abcdef"
	)
	sourceIP := netip.MustParseAddr("10.98.0.1")
	targetIP := netip.MustParseAddr("10.98.0.3")

	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, sourceIP.String(), relayCarrierURL(target))

	targetDelivery := newCaptureFlowDelivery()
	if err := target.streams.enableFlowService(targetDelivery); err != nil {
		t.Fatalf("enable target flow plane: %v", err)
	}
	if err := source.streams.enableFlowService(newCaptureFlowDelivery()); err != nil {
		t.Fatalf("enable source flow plane: %v", err)
	}

	waitRelayLinks(t, target, 3, 30*time.Second)
	waitRelayLinks(t, source, 3, 30*time.Second)
	waitPacketRoute(t, source, targetIP, 30*time.Second)

	association, err := source.streams.flow.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	defer association.Close()

	maxPayload := make([]byte, 65507)
	for i := range maxPayload {
		maxPayload[i] = byte((i*17 + 11) % 251)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := association.Fragment(ctx, flow.OutboundDatagram{
		Source:      netip.AddrPortFrom(sourceIP, 40000),
		Destination: netip.AddrPortFrom(targetIP, 40001),
		Payload:     maxPayload,
	}); err != nil {
		t.Fatalf("Fragment(max): %v", err)
	}
	select {
	case got := <-targetDelivery.datagrams:
		if !bytes.Equal(got.Payload, maxPayload) {
			t.Fatalf("reassembled max datagram = %d bytes, want %d identical", len(got.Payload), len(maxPayload))
		}
		if got.Destination.Port() != 40001 || got.Destination.Addr() != targetIP {
			t.Fatalf("max datagram destination = %s; want %s:40001", got.Destination, targetIP)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("target never delivered the maximum datagram")
	}

	if err := association.Fragment(ctx, flow.OutboundDatagram{
		Source:      netip.AddrPortFrom(sourceIP, 40000),
		Destination: netip.AddrPortFrom(targetIP, 40002),
		Payload:     nil,
	}); err != nil {
		t.Fatalf("Fragment(empty): %v", err)
	}
	select {
	case got := <-targetDelivery.datagrams:
		if len(got.Payload) != 0 {
			t.Fatalf("empty datagram delivered %d bytes; want 0", len(got.Payload))
		}
		if got.Destination.Port() != 40002 {
			t.Fatalf("empty datagram destination port = %d; want 40002", got.Destination.Port())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("target never delivered the empty datagram")
	}
}

// --- same-owner fact renewal window ------------------------------------------

// renewLocalFactsWithoutViewRefresh re-advertises n's own NODE/ADDRESS facts and
// every initiator LINK instance exactly the way the 15s local re-advertisement
// tick (localFactRefreshInterval) does, but without waking the RouteView rebuild
// worker. n's live FactStore is therefore ahead of its published immutable view
// -- the real window between a fact commit and the next rebuild -- and it stays
// that way for the whole assertion instead of depending on goroutine scheduling.
func renewLocalFactsWithoutViewRefresh(t *testing.T, n *network) {
	t.Helper()
	now := time.Now()
	nowMillis, ok := factMillis(now)
	if !ok {
		t.Fatal("renewal time is outside the fact time base")
	}
	identity, err := n.identityStore.Identity()
	if err != nil {
		t.Fatalf("local identity: %v", err)
	}
	records := make([]topology.FactRecord, 0, len(n.facts.links)+2)
	node, err := n.facts.nodeRecord(identity, nowMillis)
	if err != nil {
		t.Fatalf("build NODE re-advertisement: %v", err)
	}
	records = append(records, node)
	if n.localVirtualIP().IsValid() {
		address, err := n.facts.addressRecord(identity, nowMillis)
		if err != nil {
			t.Fatalf("build ADDRESS re-advertisement: %v", err)
		}
		records = append(records, address)
	}
	n.facts.localMu.Lock()
	links := make([]*link.Link, 0, len(n.facts.links))
	for _, established := range n.facts.links {
		links = append(links, established)
	}
	n.facts.localMu.Unlock()
	for _, established := range links {
		if established == nil || !established.Ready() {
			continue
		}
		instance, err := n.facts.linkRecord(identity, established, nil, nowMillis)
		if err != nil {
			t.Fatalf("build LINK re-advertisement: %v", err)
		}
		records = append(records, instance)
	}
	if err := n.facts.store.PublishLocal(records, now); err != nil {
		t.Fatalf("re-advertise local facts without a view rebuild: %v", err)
	}
}

// staleCandidateWindow reports whether n's published RouteView is behind its live
// FactStore AND the strict PACKET candidate query for dst still fails closed with
// RouteStale. Both conditions are read together on purpose: the rebuild worker can
// complete a rebuild between any two statements, so a single Freshness() sample is
// not a usable observation of the renewal window.
func staleCandidateWindow(n *network, dst netip.Addr) bool {
	if n.facts.routes.Freshness() != topology.RouteViewStale {
		return false
	}
	_, err := n.facts.routes.PacketCandidates(dst, topology.RoutePolicy{AllowRelay: true})
	return errors.Is(err, topology.ErrRouteStale)
}

// resolveAcrossRenewalWindow calls resolve while n's published view is stale for
// dst, re-creating the renewal window until one iteration observes the stale view
// both immediately before and immediately after the call. That bracket is what
// makes the observation conclusive rather than an artifact of a rebuild racing the
// assertion: the strict C-ROUTE-003 candidate query fails closed in the same
// window in which resolve must still succeed.
func resolveAcrossRenewalWindow(t *testing.T, n *network, dst netip.Addr, what string, resolve func() error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		renewLocalFactsWithoutViewRefresh(t, n)
		if !staleCandidateWindow(n, dst) {
			continue
		}
		err := resolve()
		if !staleCandidateWindow(n, dst) {
			// The rebuild completed during the call; this iteration proves nothing.
			continue
		}
		if err != nil {
			t.Fatalf("%s: the resolver failed while the strict candidate query was route-stale: %v", what, err)
		}
		return
	}
	t.Fatalf("%s: never observed a stale PACKET view around the resolve", what)
}

// dropNewFlowPacketPair retires the class-1 PACKET pair this runtime holds toward
// target so the next strictness observation again starts from a genuinely new
// flow. A strictness iteration can race a RouteView rebuild: if the rebuild
// completes inside the resolve, the new-flow path selects a candidate from the
// now-fresh view and establishes (and caches) a real Path+Session pair. That pair
// is a legitimate steady-state pair, but it is not a "new flow", so a later
// iteration would take the steady-state fast path and turn this test-state
// artifact into a false failure.
//
// Only the local Path is retired and the cached pair dropped; the Session entry
// is deliberately left READY and never terminated, because the steady half after
// the strictness half still receives on that Session (and re-establishes its own
// pair). Retiring the Path is exactly what a PATH_BROKEN does here.
func dropNewFlowPacketPair(rt *streamRuntime, target topology.NodeID) {
	if rt == nil {
		return
	}
	key := pairKey{node: target, class: session.SessionClassPacket}
	rt.mu.Lock()
	pair := rt.pairs[key]
	delete(rt.pairs, key)
	if pair == nil {
		pair = rt.sessionPacketPairLocked(target)
	}
	rt.mu.Unlock()
	if pair == nil || pair.ps == nil {
		return
	}
	pair.ps.broken.Store(true)
}

// requireNewFlowFailsOnStaleView is the strictness half of the same bracket: with
// no established pair, resolve must keep failing closed with RouteStale for as long
// as the renewed key is masked. It is the discriminator that the steady-state fast
// path is not blanket tolerance of a stale view.
//
// The loop must not destroy its own "genuinely new flow" precondition: a rebuild
// that completes inside the resolve lets the new-flow path establish a pair, and
// that pair would persist. Every iteration therefore retires any such pair first
// and re-checks the RouteView version around the call, so a rebuild that landed
// inside it is treated as an inconclusive iteration instead of a product
// violation. The assertion itself is unchanged: a new flow must fail closed with
// RouteStale while the renewed key is masked and no rebuild landed.
func requireNewFlowFailsOnStaleView(t *testing.T, n *network, dst netip.Addr, what string, resolve func() error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		owner, err := n.streams.currentAddressOwner(dst)
		if err != nil {
			t.Fatalf("%s: the live owner of %s is not resolvable: %v", what, dst, err)
		}
		// Re-establish the new-flow precondition before every observation.
		dropNewFlowPacketPair(n.streams, owner.NodeID)
		renewLocalFactsWithoutViewRefresh(t, n)
		if !staleCandidateWindow(n, dst) {
			continue
		}
		viewBefore := n.facts.routes.Version()
		err = resolve()
		if n.facts.routes.Version() != viewBefore {
			// A rebuild completed inside the call, so the resolver was allowed
			// to select a candidate from a fresh view and may have established a
			// pair. This iteration is not a new-flow observation; the next one
			// retires that pair first.
			continue
		}
		if !staleCandidateWindow(n, dst) {
			continue
		}
		if !errors.Is(err, topology.ErrRouteStale) {
			t.Fatalf("%s: a new flow did not fail closed on a stale view: error = %v; want topology.ErrRouteStale", what, err)
		}
		return
	}
	t.Fatalf("%s: never observed a stale PACKET view around the resolve", what)
}

// injectPacketAcrossRenewalWindow injects raw at the source device and requires the
// target to deliver it byte-identically, retrying until one attempt starts in the
// renewal window. Before the fix the target's receive-path ownership check resolves
// the inner source from the stale view and drops the packet as DropRouteStale after
// the per-peer limiter was already charged.
func injectPacketAcrossRenewalWindow(t *testing.T, n *network, dst netip.Addr, sourceDevice, targetDevice *testPacketDevice, raw []byte, what string) {
	t.Helper()
	service := packetServiceOf(n.streams)
	if service == nil {
		t.Fatal("the target packet Service is not installed")
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		renewLocalFactsWithoutViewRefresh(t, n)
		if !staleCandidateWindow(n, dst) {
			continue
		}
		before := service.Stats()
		drainPackets(targetDevice)
		sourceDevice.inject(raw)
		if !staleCandidateWindow(n, dst) {
			// The rebuild landed before the packet could arrive; retry.
			continue
		}
		select {
		case got := <-targetDevice.outbound:
			if !bytes.Equal(got, raw) {
				t.Fatalf("%s: the device received %d bytes, want the injected %d bytes unchanged", what, len(got), len(raw))
			}
			if after := service.Stats(); after.Drops[packet.DropRouteStale] != before.Drops[packet.DropRouteStale] {
				t.Fatalf("%s: a correctly owned inbound packet was dropped as route-stale during the renewal window", what)
			}
			return
		case <-time.After(2 * time.Second):
		}
	}
	t.Fatalf("%s: the packet was never delivered inside a stale PACKET view window", what)
}

// fragmentAcrossRenewalWindow sends one datagram on the established pair while the
// source's published view is stale for the destination, retrying until one attempt
// both starts and ends in the renewal window. Fragment is synchronous, so the
// bracket is exact: the strict candidate query fails closed while the fragment is
// dispatched on the already-established pair.
func fragmentAcrossRenewalWindow(t *testing.T, n *network, dst netip.Addr, delivery *captureFlowDelivery, association *flow.Association, datagram flow.OutboundDatagram, what string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		renewLocalFactsWithoutViewRefresh(t, n)
		if !staleCandidateWindow(n, dst) {
			continue
		}
		err := association.Fragment(context.Background(), datagram)
		if !staleCandidateWindow(n, dst) {
			continue
		}
		if err != nil {
			t.Fatalf("%s: a fragment on an established PACKET pair failed during the renewal window: %v", what, err)
		}
		expectFlowDatagram(t, delivery, datagram.Payload, datagram.Destination, what)
		return
	}
	t.Fatalf("%s: never observed a stale PACKET view around the fragment", what)
}

// publishLocalAddressClaim publishes an ADDRESS fact owned by n's own node for ip.
// Claiming a /32 that another live owner already advertises is exactly the address
// conflict D-OVERLAY-004 defines, so the live FactStore reports ErrRouteConflict.
func publishLocalAddressClaim(t *testing.T, n *network, ip netip.Addr) {
	t.Helper()
	now := time.Now()
	nowMillis, ok := factMillis(now)
	if !ok {
		t.Fatal("claim time is outside the fact time base")
	}
	identity, err := n.identityStore.Identity()
	if err != nil {
		t.Fatalf("local identity: %v", err)
	}
	version, err := n.facts.nextVersion()
	if err != nil {
		t.Fatalf("claim version: %v", err)
	}
	record := topology.FactRecord{
		Envelope: n.facts.envelope(topology.FactAddress, identity.NodeID, version, nowMillis),
		Payload:  topology.AddressPayload{NodeID: topology.NodeID(identity.NodeID), IP: ip, PrefixLen: 32},
	}
	if err := n.facts.store.PublishLocal([]topology.FactRecord{record}, now); err != nil {
		t.Fatalf("publish local ADDRESS claim for %s: %v", ip, err)
	}
}

// withdrawPeerFacts withdraws every fact the authenticated peer advertises into n,
// through the same FactStore entry point a Link teardown uses. The peer's
// NODE/ADDRESS/LINK facts stop being live in n's store while the class-1 pair
// itself stays installed.
func withdrawPeerFacts(t *testing.T, n *network, peer topology.NodeID) {
	t.Helper()
	n.mu.Lock()
	var control *link.Link
	for _, established := range n.activeLinks {
		if established == nil || !established.Ready() {
			continue
		}
		if established.Metadata().LaneID == topology.FactLaneControl && established.PeerNodeID() == [16]byte(peer) {
			control = established
			break
		}
	}
	n.mu.Unlock()
	if control == nil {
		t.Fatalf("no authenticated CONTROL Link to %x", peer)
	}
	source, ok := n.facts.sourceFor(control)
	if !ok {
		t.Fatal("the authenticated CONTROL Link has no fact ingress identity")
	}
	if err := n.facts.store.WithdrawSource(source, time.Now()); err != nil {
		t.Fatalf("withdraw the peer's facts: %v", err)
	}
}

// TestSteadyFlowSurvivesSameOwnerFactRenewal is the product regression for the
// window between a same-owner fact renewal and the next RouteView rebuild.
//
// Every node re-advertises its own NODE/ADDRESS/initiator-LINK facts with a new
// durable version every localFactRefreshInterval (15s). C-ROUTE-003 requires the
// strict PacketCandidates query to keep masking a renewed key until the view is
// rebuilt, so re-deriving a route from the view for every frame of a running flow
// fails the flow closed for that whole window: an inbound packet whose inner source
// is correctly owned is dropped as DropRouteStale after the per-peer limiter was
// already charged, and a datagram fragment fails as route-stale mid-transfer.
//
// The fix under test is the documented one (C-ROUTE-001 / C-ROUTE-005): resolve
// ownership for an EXISTING ready path from the live fact, use the
// already-established class-1 pair, and keep the strict candidate query -- and its
// invalidation semantics -- for a genuinely new flow. Nothing here is a mock: two
// real Networks, the real fact plane, the real class-1 PACKET Path/Session and the
// real packet/flow services.
func TestSteadyFlowSurvivesSameOwnerFactRenewal(t *testing.T) {
	const (
		name  = "fact-renewal-steady-flow"
		cidr  = "10.102.0.0/24"
		token = "fact-renewal-token-0123456789"
	)
	sourceIP := netip.MustParseAddr("10.102.0.1")
	targetIP := netip.MustParseAddr("10.102.0.3")

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

	targetDelivery := newCaptureFlowDelivery()
	if err := target.streams.enableFlowService(targetDelivery); err != nil {
		t.Fatalf("enable target flow plane: %v", err)
	}
	if err := source.streams.enableFlowService(newCaptureFlowDelivery()); err != nil {
		t.Fatalf("enable source flow plane: %v", err)
	}

	waitRelayLinks(t, target, 3, 30*time.Second)
	waitRelayLinks(t, source, 3, 30*time.Second)
	waitPacketRoute(t, source, targetIP, 30*time.Second)
	waitPacketRoute(t, target, sourceIP, 30*time.Second)

	targetIdentity, err := target.identityStore.Identity()
	if err != nil {
		t.Fatalf("target identity: %v", err)
	}
	targetNode := topology.NodeID(targetIdentity.NodeID)
	sourceIdentity, err := source.identityStore.Identity()
	if err != nil {
		t.Fatalf("source identity: %v", err)
	}
	sourceNode := topology.NodeID(sourceIdentity.NodeID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// --- a genuinely NEW flow must still fail closed on a stale view ---------
	// No class-1 pair exists yet, so the resolver has to select a Path from the
	// strict candidate graph. A renewed key is masked there until the rebuild, and
	// that must not be weakened: this is the C-ROUTE-003 behaviour the fix has to
	// preserve, and the discriminator that the fast path is not blanket tolerance.
	waitPacketViewFresh(t, target, "target view before the renewal", 30*time.Second)
	// The new-flow condition is a white-box precondition of this half: no
	// class-1 pair toward the source exists yet, so the resolver really has to
	// select a Path from the strict candidate graph.
	if _, ok := target.streams.existingPacketPair(sourceNode); ok {
		t.Fatal("the target already owns a class-1 pair toward the source; the new-flow half is not exercised")
	}
	requireNewFlowFailsOnStaleView(t, target, sourceIP, "target receive path, new packet flow", func() error {
		_, err := (&packetRouteResolver{rt: target.streams}).ResolvePacketRoute(ctx, sourceIP)
		return err
	})
	requireNewFlowFailsOnStaleView(t, target, sourceIP, "target receive path, new datagram flow", func() error {
		_, err := (&flowRouteResolver{rt: target.streams}).ResolveDatagramRoute(ctx, sourceIP)
		return err
	})
	// Restore a published view so the steady state starts healthy.
	target.facts.signalRefresh()
	waitPacketViewFresh(t, target, "target view after the forced rebuild", 30*time.Second)

	// --- healthy steady state ------------------------------------------------
	if _, err := source.streams.packetPairFor(ctx, targetNode); err != nil {
		t.Fatalf("establish the class-1 PACKET pair: %v", err)
	}
	waitPacketViewFresh(t, source, "source egress view", 30*time.Second)
	waitPacketViewFresh(t, target, "target receive view", 30*time.Second)

	before := buildIPv4Packet(sourceIP, targetIP, 1 /* ICMP */, []byte("before-renewal"))
	injectPacketUntilDelivered(t, sourceDevice, targetDevice, before, "packet before the renewal")

	association, err := source.streams.flow.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	defer association.Close()
	beforePayload := []byte("datagram-before-renewal")
	if err := association.Fragment(ctx, flow.OutboundDatagram{
		Source:      netip.AddrPortFrom(sourceIP, 40000),
		Destination: netip.AddrPortFrom(targetIP, 40001),
		Payload:     beforePayload,
	}); err != nil {
		t.Fatalf("Fragment before the renewal: %v", err)
	}
	expectFlowDatagram(t, targetDelivery, beforePayload, netip.AddrPortFrom(targetIP, 40001), "datagram before the renewal")

	// --- (a) the receive path survives the target's own renewal --------------
	// The target re-advertises its own NODE/ADDRESS facts, so its published view
	// masks the local node and PacketCandidates fails as route-stale -- while the
	// live fact still names the source as the owner of sourceIP.
	var route packet.PacketRoute
	resolveAcrossRenewalWindow(t, target, sourceIP, "target receive path, steady packet flow", func() error {
		var resolveErr error
		route, resolveErr = (&packetRouteResolver{rt: target.streams}).ResolvePacketRoute(ctx, sourceIP)
		return resolveErr
	})
	if route.DestinationNode != sourceNode {
		t.Fatalf("receive-path owner = %x; want the live owner %x", route.DestinationNode, sourceNode)
	}
	targetService := packetServiceOf(target.streams)
	if targetService == nil {
		t.Fatal("target packet Service is not installed")
	}
	receivedBefore := targetService.Stats().Received
	injectPacketAcrossRenewalWindow(t, target, sourceIP, sourceDevice, targetDevice,
		buildIPv4Packet(sourceIP, targetIP, 1 /* ICMP */, []byte("during-renewal")), "packet during the renewal window")
	if got := targetService.Stats().Received; got <= receivedBefore {
		t.Fatalf("target Received = %d; want the inbound packet delivered during the renewal window", got)
	}

	// --- (b) a Flow fragment on the existing pair still sends ----------------
	// The source now re-advertises its own facts, so the source's egress view is
	// stale exactly the way it is on the 15s tick.
	pinned, err := source.streams.packetPairFor(ctx, targetNode)
	if err != nil {
		t.Fatalf("re-read the established PACKET pair: %v", err)
	}
	var pinnedRoute flow.DatagramRoute
	resolveAcrossRenewalWindow(t, source, targetIP, "source egress path, steady datagram flow", func() error {
		var resolveErr error
		pinnedRoute, resolveErr = (&flowRouteResolver{rt: source.streams}).ResolveDatagramRoute(ctx, targetIP)
		return resolveErr
	})
	if pinnedRoute.DestinationNode != targetNode || pinnedRoute.PathID != pinned.ps.scope.id || pinnedRoute.PathGeneration != pinned.ps.scope.gen {
		t.Fatalf("steady flow route = %+v; want the established pair %d/%d toward %x",
			pinnedRoute, pinned.ps.scope.id, pinned.ps.scope.gen, targetNode)
	}
	flowBefore := source.streams.flow.Stats()
	fragmentAcrossRenewalWindow(t, source, targetIP, targetDelivery, association, flow.OutboundDatagram{
		Source:      netip.AddrPortFrom(sourceIP, 40000),
		Destination: netip.AddrPortFrom(targetIP, 40002),
		Payload:     []byte("datagram-during-renewal"),
	}, "datagram during the renewal window")
	if flowAfter := source.streams.flow.Stats(); flowAfter.Drops[flow.DropRoute] != flowBefore.Drops[flow.DropRoute] {
		t.Fatalf("the renewal window counted %d flow route drops; want none",
			flowAfter.Drops[flow.DropRoute]-flowBefore.Drops[flow.DropRoute])
	}

	// --- (c1) a withdrawn owner fact still fails closed ----------------------
	// The class-1 pair is still installed, so only the live owner fact decides.
	withdrawPeerFacts(t, target, sourceNode)
	if _, err := target.facts.store.ResolveAddressOwner(sourceIP, time.Now()); err == nil {
		t.Fatal("the withdrawn owner is still live in the target store")
	}
	if _, err := (&packetRouteResolver{rt: target.streams}).ResolvePacketRoute(ctx, sourceIP); err == nil {
		t.Fatal("the receive path resolved an owner whose facts were withdrawn")
	}
	deliveredBefore := targetService.Stats().Received
	droppedBefore := targetService.Stats().Dropped
	drainPackets(targetDevice)
	sourceDevice.inject(buildIPv4Packet(sourceIP, targetIP, 1 /* ICMP */, []byte("withdrawn-owner")))
	waitForCondition(t, "withdrawn owner counted as a drop", 15*time.Second, func() bool {
		return targetService.Stats().Dropped > droppedBefore
	})
	if got := targetService.Stats().Received; got != deliveredBefore {
		t.Fatalf("a packet from a withdrawn owner was delivered: Received = %d; want %d", got, deliveredBefore)
	}

	// --- (c2) a real live address conflict still fails closed ----------------
	// The source claims the target's own /32, so the address has two live owners.
	// The established pair must not grant a route, and no packet may be retargeted.
	publishLocalAddressClaim(t, source, targetIP)
	if _, err := source.facts.store.ResolveAddressOwner(targetIP, time.Now()); !errors.Is(err, topology.ErrRouteConflict) {
		t.Fatalf("the source store does not report the conflicting owners: %v", err)
	}
	if _, err := (&flowRouteResolver{rt: source.streams}).ResolveDatagramRoute(ctx, targetIP); !errors.Is(err, topology.ErrRouteConflict) {
		t.Fatalf("a live address conflict was not reported as route-conflict: %v", err)
	}
	if _, err := (&packetRouteResolver{rt: source.streams}).ResolvePacketRoute(ctx, targetIP); !errors.Is(err, topology.ErrRouteConflict) {
		t.Fatalf("a live address conflict was not reported as route-conflict on the packet path: %v", err)
	}
	if err := association.Fragment(ctx, flow.OutboundDatagram{
		Source:      netip.AddrPortFrom(sourceIP, 40000),
		Destination: netip.AddrPortFrom(targetIP, 40003),
		Payload:     []byte("conflicted-owner"),
	}); !errors.Is(err, topology.ErrRouteConflict) {
		t.Fatalf("a datagram toward a conflicting owner was not refused: %v", err)
	}
	sourceService := packetServiceOf(source.streams)
	if sourceService == nil {
		t.Fatal("source packet Service is not installed")
	}
	conflictBefore := sourceService.Stats()
	drainPackets(targetDevice)
	sourceDevice.inject(buildIPv4Packet(sourceIP, targetIP, 1 /* ICMP */, []byte("conflicted-owner")))
	waitForCondition(t, "conflicting owner counted as a route-conflict drop", 15*time.Second, func() bool {
		return sourceService.Stats().Drops[packet.DropRouteConflict] > conflictBefore.Drops[packet.DropRouteConflict]
	})
	if sourceService.Stats().Sent != conflictBefore.Sent {
		t.Fatal("a packet toward a conflicting owner was dispatched")
	}
	select {
	case <-targetDevice.outbound:
		t.Fatal("a packet toward a conflicting owner reached the target device")
	case <-time.After(300 * time.Millisecond):
	}
}
