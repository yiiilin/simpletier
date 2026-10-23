package simpletier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yiiilin/simpletier/internal/topology"
)

// The tests in this file are the end-to-end acceptance of the outbound FACT v2
// sender. Every node below is a real SDK Network with its own durable identity,
// its own FactStore/RouteView and its own listener/upstream (or host-attached
// WebSocket). Facts travel over real loopback TCP/WS Noise Links through the
// production protected control pump; nothing here mocks the sender, the
// consumer, the route view or the wire codec.

const factSenderTestToken = "0123456789abcdef0123456789abcdef"

const factSenderTestCIDR = "10.30.0.0/16"

// factSenderNode is one real SDK Network in a sender acceptance topology.
type factSenderNode struct {
	network *network
	nodeID  topology.NodeID
	ip      netip.Addr
}

func newFactSenderNode(t *testing.T, cidr, fixedIP, upstream string, incomingOnly bool) *factSenderNode {
	t.Helper()
	cfg := Config{
		Network: NetworkConfig{Name: "fact-sender-acceptance", CIDR: cidr, Token: factSenderTestToken},
		Options: RuntimeOptions{FixedIP: fixedIP},
	}
	if !incomingOnly {
		listenURL, _ := freeTCPListenAddress(t)
		cfg.Listen = []string{listenURL}
	}
	if upstream != "" {
		cfg.Upstreams = []string{upstream}
	}
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork(fixed_ip=%s) error = %v", fixedIP, err)
	}
	t.Cleanup(func() {
		if err := handle.Close(); err != nil {
			t.Errorf("Network.Close(%s) error = %v", fixedIP, err)
		}
	})
	n := handle.(*network)
	identity, err := n.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	return &factSenderNode{network: n, nodeID: topology.NodeID(identity.NodeID), ip: n.localIP}
}

func (node *factSenderNode) upstreamURL() string {
	return "tcp://" + node.network.carrierListeners[0].Addr().String()
}

// waitFactSenderVisible waits until this node's durable store contains a visible
// NODE fact for every wanted origin and, when wantLink is set, at least one link
// fact.
func waitFactSenderVisible(t *testing.T, node *factSenderNode, timeout time.Duration, wantNodes []topology.NodeID, wantLink bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		records, _, err := node.network.facts.store.Snapshot(time.Now())
		if err == nil {
			nodes := map[topology.NodeID]bool{}
			links := 0
			for _, record := range records {
				switch record.Envelope.Kind {
				case topology.FactNode:
					nodes[record.Envelope.Origin] = true
				case topology.FactLink:
					if _, ok := record.Payload.(topology.LinkPayload); ok {
						links++
					}
				}
			}
			missing := false
			for _, want := range wantNodes {
				if !nodes[want] {
					missing = true
					break
				}
			}
			if !missing && (!wantLink || links > 0) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("FACT sender did not converge for %s: %+v", node.ip, node.network.factStatus())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitFactSenderResolves waits until this node resolves addr to the wanted owner
// through its published RouteView.
func waitFactSenderResolves(t *testing.T, node *factSenderNode, addr netip.Addr, want topology.NodeID, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		resolved, err := node.network.facts.routes.ResolveVirtualIP(addr)
		if err == nil && resolved.NodeID == want {
			return
		}
		lastErr = err
		if time.Now().After(deadline) {
			t.Fatalf("ResolveVirtualIP(%s) on %s did not reach %x: last error %v", addr, node.ip, want, lastErr)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitFactSenderWithdrawn waits until addr resolves fresh as ErrNoRoute, which is
// what a real ingress-provenance withdrawal produces. A stale view (ErrRouteStale)
// is not accepted as withdrawal because the old view may still name the peer.
func waitFactSenderWithdrawn(t *testing.T, node *factSenderNode, addr netip.Addr, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if _, err := node.network.facts.routes.ResolveVirtualIP(addr); errors.Is(err, topology.ErrNoRoute) {
			return
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			t.Fatalf("ResolveVirtualIP(%s) on %s did not reach a fresh ErrNoRoute after withdrawal: last error %v", addr, node.ip, lastErr)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func waitFactSenderLinks(t *testing.T, node *factSenderNode, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if got := len(node.network.controlPumpSnapshot()); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Network %s active Links = %d; want %d", node.ip, len(node.network.controlPumpSnapshot()), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitFactSenderCompleted waits until this node's sender recorded at least min
// peer-completed outbound snapshots. Convergence of the peer's facts can be
// observable before its own next snapshot transfer finishes, so a test that
// wants both transfer directions proven must wait rather than assert instantly.
func waitFactSenderCompleted(t *testing.T, node *factSenderNode, min uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if status := node.network.factStatus(); status.SenderCompleted >= min {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Network %s sender completed %d snapshots; want >= %d: %+v", node.ip, node.network.factStatus().SenderCompleted, min, node.network.factStatus())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestFactSenderTwoNetworksExchangeFactsOverTCP(t *testing.T) {
	server := newFactSenderNode(t, factSenderTestCIDR, "10.30.0.2", "", false)
	client := newFactSenderNode(t, factSenderTestCIDR, "10.30.0.3", server.upstreamURL(), false)
	waitFactSenderLinks(t, server, 1, 10*time.Second)
	waitFactSenderLinks(t, client, 1, 10*time.Second)

	// Node, Address and Link facts must be visible on both sides: the initiator
	// publishes this exact Link instance and the responder learns it through the
	// FACT snapshot, while both exchange NODE and ADDRESS facts.
	waitFactSenderVisible(t, server, 10*time.Second, []topology.NodeID{server.nodeID, client.nodeID}, true)
	waitFactSenderVisible(t, client, 10*time.Second, []topology.NodeID{server.nodeID, client.nodeID}, true)

	// Each RouteView resolves the other node's advertised VirtualIP.
	waitFactSenderResolves(t, server, client.ip, client.nodeID, 10*time.Second)
	waitFactSenderResolves(t, client, server.ip, server.nodeID, 10*time.Second)

	// Both directions actually completed at least one outbound snapshot. Store
	// convergence can be observable a moment before a side's own next transfer
	// finishes, so completion is awaited rather than asserted instantly.
	waitFactSenderCompleted(t, server, 1, 10*time.Second)
	waitFactSenderCompleted(t, client, 1, 10*time.Second)
	if status := server.network.factStatus(); status.SenderSnapshots == 0 {
		t.Fatal("no outbound snapshot was built on the server")
	}
	if status := client.network.factStatus(); status.SenderSnapshots == 0 {
		t.Fatal("no outbound snapshot was built on the client")
	}
}

func TestFactSenderRelayDiscoveryOverTCP(t *testing.T) {
	relay := newFactSenderNode(t, factSenderTestCIDR, "10.30.1.2", "", false)
	left := newFactSenderNode(t, factSenderTestCIDR, "10.30.1.3", relay.upstreamURL(), false)
	right := newFactSenderNode(t, factSenderTestCIDR, "10.30.1.4", relay.upstreamURL(), false)

	waitFactSenderLinks(t, relay, 2, 10*time.Second)
	waitFactSenderLinks(t, left, 1, 10*time.Second)
	waitFactSenderLinks(t, right, 1, 10*time.Second)

	// A-R-B: neither leaf has a direct Link to the other, so the only way A can
	// know B is that R forwarded B's facts verbatim to A (and the reverse).
	waitFactSenderResolves(t, left, right.ip, right.nodeID, 20*time.Second)
	waitFactSenderResolves(t, right, left.ip, left.nodeID, 20*time.Second)
	waitFactSenderVisible(t, left, 10*time.Second, []topology.NodeID{left.nodeID, relay.nodeID, right.nodeID}, true)
	waitFactSenderVisible(t, right, 10*time.Second, []topology.NodeID{left.nodeID, relay.nodeID, right.nodeID}, true)
	waitFactSenderVisible(t, relay, 10*time.Second, []topology.NodeID{relay.nodeID, left.nodeID, right.nodeID}, true)

	// The relay resolves both leaves and the leaves still hold only one Link each.
	waitFactSenderResolves(t, relay, left.ip, left.nodeID, 10*time.Second)
	waitFactSenderResolves(t, relay, right.ip, right.nodeID, 10*time.Second)
	if got := len(left.network.controlPumpSnapshot()); got != 1 {
		t.Fatalf("discovery created %d Links on A; want the single relay Link", got)
	}
}

func TestFactSenderOverWebSocketTarget(t *testing.T) {
	responder := newFactSenderNode(t, factSenderTestCIDR, "10.30.2.2", "", true)
	handlerErr := make(chan error, 2)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		socket, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			handlerErr <- err
			return
		}
		conn, err := NewWebSocketConnection(socket)
		if err != nil {
			handlerErr <- err
			_ = socket.Close()
			return
		}
		attached, err := responder.network.AttachConnection(context.Background(), conn, AttachOptions{Role: LinkRoleResponder, Lane: laneControl})
		if err != nil {
			handlerErr <- err
			return
		}
		<-attached.Done()
		handlerErr <- nil
	}))
	t.Cleanup(server.Close)

	// The initiator uses the production typed-Target path: its retry worker dials
	// the WebSocketConnector and admits the stream as an authenticated CONTROL
	// Link, exactly like a TCP upstream.
	wsEndpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	listenURL, _ := freeTCPListenAddress(t)
	cfg := Config{
		Listen:  []string{listenURL},
		Targets: []ConnectionTarget{{Connector: &WebSocketConnector{}, Endpoint: wsEndpoint}},
		Network: NetworkConfig{Name: "fact-sender-acceptance", CIDR: factSenderTestCIDR, Token: factSenderTestToken},
		Options: RuntimeOptions{FixedIP: "10.30.2.3"},
	}
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork(websocket target) error = %v", err)
	}
	t.Cleanup(func() {
		if err := handle.Close(); err != nil {
			t.Errorf("Network.Close(ws initiator) error = %v", err)
		}
	})
	initiatorNetwork := handle.(*network)
	initiatorIdentity, err := initiatorNetwork.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	initiator := &factSenderNode{network: initiatorNetwork, nodeID: topology.NodeID(initiatorIdentity.NodeID), ip: initiatorNetwork.localIP}

	waitFactSenderLinks(t, initiator, 1, 10*time.Second)
	waitFactSenderLinks(t, responder, 1, 10*time.Second)
	waitFactSenderVisible(t, responder, 10*time.Second, []topology.NodeID{responder.nodeID, initiator.nodeID}, true)
	waitFactSenderVisible(t, initiator, 10*time.Second, []topology.NodeID{responder.nodeID, initiator.nodeID}, true)
	waitFactSenderResolves(t, initiator, responder.ip, responder.nodeID, 10*time.Second)
	waitFactSenderResolves(t, responder, initiator.ip, initiator.nodeID, 10*time.Second)
}

func TestFactSenderWrongTokenExchangesNothing(t *testing.T) {
	server := newFactSenderNode(t, factSenderTestCIDR, "10.30.3.2", "", false)

	listenURL, _ := freeTCPListenAddress(t)
	cfg := Config{
		Listen:    []string{listenURL},
		Upstreams: []string{server.upstreamURL()},
		Network:   NetworkConfig{Name: "fact-sender-acceptance", CIDR: factSenderTestCIDR, Token: "ffffffffffffffffffffffffffffffff"},
		Options:   RuntimeOptions{FixedIP: "10.30.3.3"},
	}
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client := handle.(*network)
	defer client.Close()
	clientIdentity, err := client.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}

	// The mismatching token fails the Noise/PSK gate, so neither side registers a
	// Link and neither side ever exchanges a Node/Address/Link fact.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.controlPumpSnapshot()) != 0 || len(server.network.controlPumpSnapshot()) != 0 {
			t.Fatal("wrong token produced an authenticated Link")
		}
		time.Sleep(5 * time.Millisecond)
	}
	records, _, err := server.network.facts.store.Snapshot(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	peer := topology.NodeID(clientIdentity.NodeID)
	for _, record := range records {
		if record.Envelope.Origin == peer {
			t.Fatalf("wrong-token peer fact %d became visible on the server", record.Envelope.Kind)
		}
	}
}

func TestFactSenderCloseWithdrawsPeerFacts(t *testing.T) {
	server := newFactSenderNode(t, factSenderTestCIDR, "10.30.4.2", "", false)
	client := newFactSenderNode(t, factSenderTestCIDR, "10.30.4.3", server.upstreamURL(), false)
	waitFactSenderLinks(t, server, 1, 10*time.Second)
	waitFactSenderResolves(t, server, client.ip, client.nodeID, 10*time.Second)

	// Make the peer's echo deterministic before testing retention: wait until the
	// client has learned the server's facts and then completed a snapshot built
	// after that, so the server's own facts have gained this authenticated ingress
	// source. Withdrawing that source must not delete facts this node owns.
	waitFactSenderVisible(t, client, 10*time.Second, []topology.NodeID{client.nodeID, server.nodeID}, false)
	beforeSnapshots := client.network.factStatus().SenderSnapshots
	beforeCompleted := client.network.factStatus().SenderCompleted
	echoDeadline := time.Now().Add(10 * time.Second)
	for {
		status := client.network.factStatus()
		if status.SenderSnapshots > beforeSnapshots && status.SenderCompleted > beforeCompleted {
			break
		}
		if time.Now().After(echoDeadline) {
			t.Fatalf("client did not complete a post-discovery snapshot: %+v", status)
		}
		time.Sleep(2 * time.Millisecond)
	}

	if err := client.network.Close(); err != nil {
		t.Fatal(err)
	}
	waitFactSenderLinks(t, server, 0, 10*time.Second)
	// The Link withdrawal removes exactly this ingress provenance, so the closed
	// peer's address stops resolving fresh (not merely stale) and its facts leave
	// the store.
	waitFactSenderWithdrawn(t, server, client.ip, 10*time.Second)
	records, _, err := server.network.facts.store.Snapshot(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ownNode, ownAddress := false, false
	for _, record := range records {
		if record.Envelope.Origin == client.nodeID {
			t.Fatalf("peer fact %d survived its Link withdrawal", record.Envelope.Kind)
		}
		if record.Envelope.Origin != server.nodeID {
			continue
		}
		switch record.Envelope.Kind {
		case topology.FactNode:
			ownNode = true
		case topology.FactAddress:
			ownAddress = true
		}
	}
	// Locally-owned facts must survive an authenticated peer's ingress
	// withdrawal. This is strict and stays red until the internal topology store
	// honours local ownership (tracked as #566); it must never be relaxed to a
	// refresh/recovery check.
	if !ownNode || !ownAddress {
		t.Fatalf("server lost its own facts on peer withdrawal: node=%v address=%v", ownNode, ownAddress)
	}
}

func TestFactSenderConcurrentExchangeAndCloseIsRaceFree(t *testing.T) {
	relay := newFactSenderNode(t, factSenderTestCIDR, "10.30.5.2", "", false)
	left := newFactSenderNode(t, factSenderTestCIDR, "10.30.5.3", relay.upstreamURL(), false)
	right := newFactSenderNode(t, factSenderTestCIDR, "10.30.5.4", relay.upstreamURL(), false)
	waitFactSenderLinks(t, relay, 2, 10*time.Second)
	waitFactSenderResolves(t, left, right.ip, right.nodeID, 20*time.Second)

	// Poll facts and close every node concurrently while the sender, the RouteView
	// rebuild worker and the Link readers/writers are all live. This test is
	// meaningful primarily under -race.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for _, node := range []*factSenderNode{left, right, relay} {
		wg.Add(1)
		go func(node *factSenderNode) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _, _ = node.network.facts.store.Snapshot(time.Now())
				_, _ = node.network.facts.routes.ResolveVirtualIP(node.ip)
			}
		}(node)
	}
	time.Sleep(50 * time.Millisecond)
	var closers sync.WaitGroup
	for _, node := range []*factSenderNode{left, right, relay} {
		closers.Add(1)
		go func(node *factSenderNode) {
			defer closers.Done()
			_ = node.network.Close()
		}(node)
	}
	closers.Wait()
	close(stop)
	wg.Wait()
}

// serveOutboundFacts reads and answers the Network's own outbound FACT frames
// until done reports the wanted transfer state. Reads are deadline-bounded
// because the bounded sender keeps retrying, so a live transfer never stalls a
// test for long.
func (p *factTestPeer) serveOutboundFacts(t *testing.T, done func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("outbound FACT transfer did not reach the wanted state: completed=%d maxPages=%d pageFrames=%d",
				p.skipper.completed, p.skipper.maxPages, p.skipper.pageFrames)
		}
		p.armDeadline(t)
		message, err := p.control.ReadControl()
		if err != nil {
			t.Fatalf("serve outbound FACT: %v", err)
		}
		p.skipper.skip(t, message)
	}
}

// TestFactSenderSnapshotBuilderAcceptsZeroNetworkLocator pins that the u64
// NetworkID is an outer locator, not an isolation root: a zero derived locator
// is legal inside the frozen v2 container and must be built, encoded and
// validated like any other.
func TestFactSenderSnapshotBuilderAcceptsZeroNetworkLocator(t *testing.T) {
	now := time.Now()
	issued, expires := factTestMillisWindow(now)
	records := []topology.FactRecord{
		factTestNodeRecord(0, [32]byte{7, 7, 7}, topology.FactVersion{Incarnation: 4, Sequence: 1}, issued, expires),
		factTestAddressRecord(0, [16]byte{1, 2, 3}, "10.62.0.9", topology.FactVersion{Incarnation: 4, Sequence: 2}, issued, expires),
	}
	snapshot, err := buildFactSnapshot(0, 9, 2, 1, records)
	if err != nil {
		t.Fatalf("buildFactSnapshot(zero locator) error = %v", err)
	}
	if snapshot.summary.NetworkID != 0 || snapshot.summary.SenderIncarnation != 9 || snapshot.summary.SnapshotVersion != 2 {
		t.Fatalf("zero-locator summary = %+v", snapshot.summary)
	}
	if err := topology.ValidateSnapshot(snapshot.summary, snapshot.pages); err != nil {
		t.Fatalf("zero-locator snapshot failed the frozen validator: %v", err)
	}
	encoded, err := topology.EncodeFactSummary(snapshot.summary)
	if err != nil {
		t.Fatalf("EncodeFactSummary(zero locator) error = %v", err)
	}
	decoded, err := topology.DecodeFactSummary(encoded)
	if err != nil || decoded.NetworkID != 0 {
		t.Fatalf("zero-locator summary round trip = (%+v, %v)", decoded, err)
	}
	for _, record := range records {
		if err := topology.ValidateFactForNetwork(record, 0); err != nil {
			t.Fatalf("zero-locator record admission error = %v", err)
		}
	}
	// A zero incarnation/version remains invalid: those counters must be durable
	// and non-zero.
	if _, err := buildFactSnapshot(0, 0, 2, 1, records); err == nil {
		t.Fatal("buildFactSnapshot accepted a zero sender incarnation")
	}
	if _, err := buildFactSnapshot(0, 9, 0, 1, records); err == nil {
		t.Fatal("buildFactSnapshot accepted a zero snapshot version")
	}
}

// TestFactSenderBudgetAccountsPeakReferences pins that the network-wide
// outbound budget counts every immutable snapshot still referenced by a Link,
// and only drops the cached snapshot from the peak once no Link holds it.
func TestFactSenderBudgetAccountsPeakReferences(t *testing.T) {
	// Every candidate stays inside the frozen per-snapshot bound (3 MiB) so the
	// check exercises the network-wide peak budget, not the per-snapshot ceiling.
	cached := &factSnapshot{bytes: 6 << 20}
	pump := &controlPump{sender: &factLinkSender{}}
	pump.sender.offered = cached
	n := &network{controlPumps: map[uint64]*controlPump{1: pump}}
	f := &factRuntime{network: n}

	if f.senderBudgetAllows(cached, 3<<20) {
		t.Fatal("peak including a Link-referenced cached snapshot overshot the budget but was allowed")
	}
	if !f.senderBudgetAllows(cached, 1<<20) {
		t.Fatal("a candidate that fits the peak was rejected")
	}
	pump.sender.offered = nil
	if !f.senderBudgetAllows(cached, 3<<20) {
		t.Fatal("an unreferenced cached snapshot should be superseded by the candidate, not counted")
	}
}

// TestFactLinkSenderKeepsProgressingTransferAndSupersedesStalled pins the
// anti-starvation rule: a newer snapshot may not restart a transfer that is
// still receiving matched page requests, but it does replace a stalled one.
func TestFactLinkSenderKeepsProgressingTransferAndSupersedesStalled(t *testing.T) {
	s := &factLinkSender{}
	first := &factSnapshot{version: 1, summary: topology.FactSummary{PageCount: 2}, pages: make([]topology.FactPage, 2)}
	second := &factSnapshot{version: 2, summary: topology.FactSummary{PageCount: 1}, pages: make([]topology.FactPage, 1)}
	now := time.Now()

	plan := s.plan(first, now)
	if !plan.send || plan.action.snapshot != first || plan.action.isPage {
		t.Fatalf("first offer = %+v; want the SUMMARY of snapshot 1", plan)
	}
	result := s.onAck(topology.FactAck{
		ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: 1, NetworkID: 7,
		SnapshotVersion: 1, Status: topology.AckNeedPage, MissingPage: 1,
	}, 7, 1, now)
	if !result.correlated || !result.send || result.action.snapshot != first || !result.action.isPage {
		t.Fatalf("page request result = %+v; want the requested page of snapshot 1", result)
	}

	progressing := s.plan(second, now.Add(time.Second))
	if progressing.send && progressing.action.snapshot == second {
		t.Fatalf("a newer snapshot superseded a still-progressing transfer: %+v", progressing)
	}

	stalled := s.plan(second, now.Add(factSenderProgressTimeout+time.Second))
	if !stalled.send || stalled.action.snapshot != second || stalled.action.isPage {
		t.Fatalf("stalled transfer was not superseded by the newer snapshot: %+v", stalled)
	}
}

// TestFactRuntimeStagingExpiresWithinFrozenTTL pins the staging expiration: a
// partial snapshot older than one frozen advertisement TTL is dropped and the
// peer is asked for a fresh SUMMARY instead of committing late.
func TestFactRuntimeStagingExpiresWithinFrozenTTL(t *testing.T) {
	n := admissionNetwork(t, factRuntimeTestToken)
	peer := newFactTestPeer(t, n, 0x6001)
	networkID := n.networkContext.WireID()
	now := time.Now()
	issued, expires := factTestMillisWindow(now)
	first := factTestNodeRecord(networkID, peer.identity.PublicKey, topology.FactVersion{Incarnation: 4, Sequence: 1}, issued, expires)
	second := factTestAddressRecord(networkID, peer.nodeID, "10.60.0.21", topology.FactVersion{Incarnation: 4, Sequence: 2}, issued, expires)
	// One record per page so the fixture really produces two pages: page 1
	// arrives only after the staging outlived the frozen TTL.
	summary, pages := factTestSnapshot(t, networkID, 4, 1, 1, []topology.FactRecord{first, second})
	if len(pages) != 2 {
		t.Fatalf("fixture produced %d pages; want 2", len(pages))
	}
	versionBefore := factTestSettledVersion(t, n)

	peer.sendSummary(t, summary)
	peer.expectAck(t, topology.AckNeedPage, 0)
	peer.sendPage(t, pages[0])
	peer.expectAck(t, topology.AckNeedPage, 0)

	// Age the staging of this exact Link past the frozen TTL without sleeping.
	n.facts.mu.Lock()
	for _, state := range n.facts.staging {
		state.started = time.Now().Add(-2 * factStagingTTL)
	}
	n.facts.mu.Unlock()

	peer.sendPage(t, pages[1])
	// Whichever release path wins (the next-page TTL check or the sender sweep),
	// the peer must be told to start over rather than see a commit.
	message := peer.readControl(t)
	if message.Type != 8 {
		t.Fatalf("control type after expired staging = %d; want 8 (FACT_ACK)", message.Type)
	}
	ack, err := topology.DecodeFactAck(message.Payload)
	if err != nil {
		t.Fatalf("decode FACT_ACK after expired staging: %v", err)
	}
	if ack.Status != topology.AckNeedSummary {
		t.Fatalf("expired staging answer = status %d; want %d (NEED_SUMMARY)", ack.Status, topology.AckNeedSummary)
	}
	if ack.SenderIncarnation != summary.SenderIncarnation || ack.SnapshotVersion != summary.SnapshotVersion {
		t.Fatalf("expired staging echo = %d/%d; want the staged sender %d/%d",
			ack.SenderIncarnation, ack.SnapshotVersion, summary.SenderIncarnation, summary.SnapshotVersion)
	}

	if status := n.factStatus(); status.StagingLinks != 0 || status.StagedBytes != 0 || status.Committed != 0 {
		t.Fatalf("expired staging was retained or committed: %+v", status)
	}
	if n.facts.store.Version() != versionBefore {
		t.Fatal("an expired staging advanced the FactStore version")
	}
	for _, record := range []topology.FactRecord{first, second} {
		if factTestIsCurrent(t, n, record, now) {
			t.Fatalf("expired staging committed %T version %+v", record.Payload, record.Envelope.Version)
		}
	}
}

// TestFactSenderCompletesMultiPageSnapshotOverRealControl drives a real
// multi-page outbound snapshot to COMPLETE over the authenticated protected
// control stream. The Network's store is enlarged through the real FACT_PAGE
// path, then the test answers every page request the production sender issues;
// nothing about the completion is mocked.
func TestFactSenderCompletesMultiPageSnapshotOverRealControl(t *testing.T) {
	n := admissionNetwork(t, factRuntimeTestToken)
	peer := newFactTestPeer(t, n, 0x7001)
	networkID := n.networkContext.WireID()
	now := time.Now()
	issued, expires := factTestMillisWindow(now)

	// Let the initial one-page offer settle so the next transfer is the enlarged
	// multi-page one.
	peer.serveOutboundFacts(t, func() bool { return peer.skipper.completed >= 1 }, 10*time.Second)

	records := make([]topology.FactRecord, 0, 301)
	records = append(records, factTestNodeRecord(networkID, peer.identity.PublicKey, topology.FactVersion{Incarnation: 5, Sequence: 1}, issued, expires))
	for index := 0; index < 300; index++ {
		address := fmt.Sprintf("10.61.%d.%d", index/250, index%250+1)
		records = append(records, factTestAddressRecord(networkID, peer.nodeID, address,
			topology.FactVersion{Incarnation: 5, Sequence: uint64(index + 2)}, issued, expires))
	}
	summary, pages := factTestSnapshot(t, networkID, 5, 1, 128, records)
	if len(pages) < 2 {
		t.Fatalf("fixture produced %d pages; want at least 2", len(pages))
	}
	peer.sendSummary(t, summary)
	peer.expectAck(t, topology.AckNeedPage, 0)
	for index, page := range pages {
		peer.sendPage(t, page)
		if index == len(pages)-1 {
			peer.expectAck(t, topology.AckComplete, uint32(index))
		} else {
			peer.expectAck(t, topology.AckNeedPage, uint32(index))
		}
	}

	// The Network must now complete a multi-page outbound transfer, page by page,
	// answering its own repeated summary notices. The peer's skipper serves them.
	peer.serveOutboundFacts(t, func() bool {
		return peer.skipper.completed >= 2 && peer.skipper.maxPages >= 2
	}, 15*time.Second)
	if peer.skipper.pageFrames < 2 {
		t.Fatalf("served %d page frames; want a real multi-page transfer", peer.skipper.pageFrames)
	}
	waitFactSenderCompleted(t, &factSenderNode{network: n, nodeID: topology.NodeID(peer.nodeID), ip: n.localIP}, 2, 10*time.Second)
	if got := n.factStatus(); got.SenderCompleted < 2 {
		t.Fatalf("sender completed %d snapshots; want at least 2", got.SenderCompleted)
	}
	// The injected facts are current in the durable store.
	for _, record := range records[:1] {
		if !factTestIsCurrent(t, n, record, now) {
			t.Fatal("injected record is not current")
		}
	}
}

// TestFactSenderSweepsExpiredStagingWithoutNextPage pins F2: a peer that stages
// part of a snapshot and then goes silent must not hold the bounded staging
// budget until it speaks again. The sender worker sweeps the expired staging and
// sends the matching NEED_SUMMARY without any further peer frame.
func TestFactSenderSweepsExpiredStagingWithoutNextPage(t *testing.T) {
	n := admissionNetwork(t, factRuntimeTestToken)
	peer := newFactTestPeer(t, n, 0x6101)
	networkID := n.networkContext.WireID()
	now := time.Now()
	issued, expires := factTestMillisWindow(now)
	first := factTestNodeRecord(networkID, peer.identity.PublicKey, topology.FactVersion{Incarnation: 6, Sequence: 1}, issued, expires)
	second := factTestAddressRecord(networkID, peer.nodeID, "10.60.0.31", topology.FactVersion{Incarnation: 6, Sequence: 2}, issued, expires)
	summary, pages := factTestSnapshot(t, networkID, 6, 1, 1, []topology.FactRecord{first, second})
	if len(pages) != 2 {
		t.Fatalf("fixture produced %d pages; want 2", len(pages))
	}
	versionBefore := factTestSettledVersion(t, n)

	peer.sendSummary(t, summary)
	peer.expectAck(t, topology.AckNeedPage, 0)
	peer.sendPage(t, pages[0])
	peer.expectAck(t, topology.AckNeedPage, 0)

	// The peer now stops. Age the staged snapshot past the frozen TTL and let only
	// the sender worker release it.
	n.facts.mu.Lock()
	for _, state := range n.facts.staging {
		state.started = time.Now().Add(-2 * factStagingTTL)
	}
	n.facts.mu.Unlock()

	message := peer.readControl(t)
	if message.Type != 8 {
		t.Fatalf("control type from the staging sweep = %d; want 8 (FACT_ACK)", message.Type)
	}
	ack, err := topology.DecodeFactAck(message.Payload)
	if err != nil {
		t.Fatalf("decode sweep FACT_ACK: %v", err)
	}
	if ack.Status != topology.AckNeedSummary {
		t.Fatalf("sweep answer = status %d; want %d (NEED_SUMMARY)", ack.Status, topology.AckNeedSummary)
	}
	if ack.SenderIncarnation != summary.SenderIncarnation || ack.SnapshotVersion != summary.SnapshotVersion {
		t.Fatalf("sweep echo = %d/%d; want the staged sender %d/%d",
			ack.SenderIncarnation, ack.SnapshotVersion, summary.SenderIncarnation, summary.SnapshotVersion)
	}
	if status := n.factStatus(); status.StagingLinks != 0 || status.StagedBytes != 0 || status.Committed != 0 {
		t.Fatalf("silent peer staging was not reclaimed: %+v", status)
	}
	if n.facts.store.Version() != versionBefore {
		t.Fatal("the staging sweep advanced the FactStore version")
	}
}

// TestFactLinkSenderRepeatedCompleteCountsOnce pins F5: the completion counter
// must be raised at most once per offer even if the peer repeats COMPLETE.
func TestFactLinkSenderRepeatedCompleteCountsOnce(t *testing.T) {
	s := &factLinkSender{}
	const networkID, incarnation = 9, 2
	snapshot := &factSnapshot{version: 4, networkID: networkID, incarnation: incarnation, summary: topology.FactSummary{PageCount: 1}, pages: make([]topology.FactPage, 1)}
	now := time.Now()
	s.plan(snapshot, now)
	ack := topology.FactAck{
		ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: incarnation,
		NetworkID: networkID, SnapshotVersion: 4, Status: topology.AckComplete,
	}
	if first := s.onAck(ack, networkID, incarnation, now); !first.completed || !first.correlated {
		t.Fatalf("first COMPLETE = %+v; want a correlated completion", first)
	}
	for repeat := 0; repeat < 3; repeat++ {
		result := s.onAck(ack, networkID, incarnation, now.Add(time.Duration(repeat+1)*time.Second))
		if result.completed {
			t.Fatalf("repeat COMPLETE %d raised the completion counter again", repeat)
		}
		if !result.correlated {
			t.Fatalf("repeat COMPLETE %d was not correlated", repeat)
		}
	}
}

// TestFactLinkSenderRepeatedPageRequestIsBoundedAndDoesNotRefreshProgress pins
// F8: repeating the same NEED_PAGE neither resends without bound nor slides the
// progress clock, so a newer snapshot can still supersede a stalled transfer.
func TestFactLinkSenderRepeatedPageRequestIsBoundedAndDoesNotRefreshProgress(t *testing.T) {
	s := &factLinkSender{}
	const networkID, incarnation = 7, 3
	snapshot := &factSnapshot{version: 1, networkID: networkID, incarnation: incarnation, summary: topology.FactSummary{PageCount: 3}, pages: make([]topology.FactPage, 3)}
	now := time.Now()
	s.plan(snapshot, now)

	request := topology.FactAck{
		ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: incarnation,
		NetworkID: networkID, SnapshotVersion: 1, Status: topology.AckNeedPage, MissingPage: 2,
	}
	first := s.onAck(request, networkID, incarnation, now)
	if !first.correlated || !first.send || first.action.page != 2 {
		t.Fatalf("first page request = %+v; want an immediate page 2 send", first)
	}
	for repeat := 0; repeat < 3; repeat++ {
		result := s.onAck(request, networkID, incarnation, now.Add(5*time.Second))
		if result.send {
			t.Fatalf("repeated page request %d triggered an unbounded resend", repeat)
		}
		if !result.correlated {
			t.Fatalf("repeated page request %d was not correlated", repeat)
		}
	}

	clock := now
	sent := 0
	for attempt := 0; attempt < factSenderMaxAttempts+2; attempt++ {
		clock = clock.Add(factSenderRetryInterval + time.Millisecond)
		if plan := s.plan(nil, clock); plan.send {
			sent++
		}
	}
	if sent != factSenderMaxAttempts {
		t.Fatalf("bounded retries sent %d frames; want exactly %d", sent, factSenderMaxAttempts)
	}
	if s.state != factSenderFailed {
		t.Fatalf("state after exhausted retries = %d; want failed", s.state)
	}

	newer := &factSnapshot{version: 2, networkID: networkID, incarnation: incarnation, summary: topology.FactSummary{PageCount: 1}, pages: make([]topology.FactPage, 1)}
	superseding := s.plan(newer, clock)
	if !superseding.send || superseding.action.snapshot != newer {
		t.Fatalf("stalled repeated-page transfer was not superseded: %+v", superseding)
	}
}

// TestFactSenderSnapshotByteUnitMatchesBudgetEstimator pins F4: the candidate
// estimator and the built snapshot must be in the same canonical record-byte
// unit, so the network-wide budget never mixes record and page bytes.
func TestFactSenderSnapshotByteUnitMatchesBudgetEstimator(t *testing.T) {
	now := time.Now()
	issued, expires := factTestMillisWindow(now)
	records := []topology.FactRecord{
		factTestNodeRecord(0, [32]byte{4}, topology.FactVersion{Incarnation: 1, Sequence: 1}, issued, expires),
	}
	for index := 0; index < 200; index++ {
		records = append(records, factTestAddressRecord(0, [16]byte{5},
			fmt.Sprintf("10.63.%d.%d", index/250, index%250+1),
			topology.FactVersion{Incarnation: 1, Sequence: uint64(index + 2)}, issued, expires))
	}
	estimate, err := factSnapshotCanonicalBytes(records)
	if err != nil {
		t.Fatalf("factSnapshotCanonicalBytes() error = %v", err)
	}
	snapshot, err := buildFactSnapshot(0, 3, 1, 1, records)
	if err != nil {
		t.Fatalf("buildFactSnapshot() error = %v", err)
	}
	if snapshot.summary.PageCount < 2 {
		t.Fatalf("fixture produced %d pages; want a multi-page snapshot", snapshot.summary.PageCount)
	}
	if snapshot.bytes != estimate {
		t.Fatalf("snapshot.bytes = %d; canonical estimator = %d; want one consistent unit", snapshot.bytes, estimate)
	}
}
