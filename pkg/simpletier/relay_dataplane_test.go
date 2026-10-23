package simpletier

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yiiilin/simpletier/internal/topology"
)

// init enables the phase-only data-plane trace for this package's acceptance
// tests when SIMPLETIER_TRACE=1, matching the external runtime harness. It never
// logs keys or payload bytes.
func init() {
	if os.Getenv("SIMPLETIER_TRACE") == "1" {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
}

// The A-R-B acceptance: A and B are only reachable through the relay R. A dials a
// virtual listener on B, the two-hop Path/Session is bootstrapped over the
// CONTROL lane, and business bytes travel A -> R -> B and back as opaque E2E
// ciphertext the relay never opens. It also asserts the relay holds no Session
// object, root or E2E protector.
const (
	relayTestName  = "relay-dataplane"
	relayTestCIDR  = "10.92.0.0/24"
	relayTestToken = "relay-token-0123456789abcdef"
	relaySourceIP  = "10.92.0.1"
	relayHopIP     = "10.92.0.2"
	relayTargetIP  = "10.92.0.3"
)

func newRelayTestNode(t *testing.T, fixedIP, upstream string) *network {
	t.Helper()
	cfg := Config{
		Network: NetworkConfig{Name: relayTestName, CIDR: relayTestCIDR, Token: relayTestToken},
		Options: RuntimeOptions{FixedIP: fixedIP},
	}
	listenURL, _ := freeTCPListenAddress(t)
	cfg.Listen = []string{listenURL}
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

func relayCarrierURL(n *network) string {
	return "tcp://" + n.carrierListeners[0].Addr().String()
}

// waitRelayLinks waits until a node owns at least want authenticated Links. Every
// adjacency needs its CONTROL and dedicated STREAM lane before a two-hop Path can
// resolve both segments, so dialing before this just burns retry backoff.
func waitRelayLinks(t *testing.T, n *network, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n.mu.Lock()
		got := len(n.activeLinks)
		n.mu.Unlock()
		if got >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	n.mu.Lock()
	got := len(n.activeLinks)
	n.mu.Unlock()
	t.Fatalf("active Links never reached %d (got %d)", want, got)
}

// waitRelayRoute waits until the source's RouteView resolves the target's
// VirtualIP and offers a relayed candidate path. The two-hop facts propagate
// asynchronously, so dialing before this only burns DialContext retry backoff.
func waitRelayRoute(t *testing.T, source *network, targetNode topology.NodeID, timeout time.Duration) {
	t.Helper()
	addr := netip.MustParseAddr(relayTargetIP)
	policy := topology.RoutePolicy{AllowRelay: true}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := source.facts.routes.ResolveVirtualIP(addr); err == nil {
			if paths, err := source.facts.routes.Candidates(targetNode, laneStream, policy); err == nil && len(paths) > 0 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("relay route to %x never converged", targetNode[:4])
}

// newRelayTopology builds the A -> R -> B chain (B target, R relay, A source) and
// waits until each node owns the CONTROL plus dedicated STREAM Link of every
// adjacency and the source can route the two-hop path.
func newRelayTopology(t *testing.T) (source, relay, target *network) {
	t.Helper()
	target = newRelayTestNode(t, relayTargetIP, "")
	relay = newRelayTestNode(t, relayHopIP, relayCarrierURL(target))
	source = newRelayTestNode(t, relaySourceIP, relayCarrierURL(relay))
	waitRelayLinks(t, target, 2, 30*time.Second)
	waitRelayLinks(t, relay, 4, 30*time.Second)
	waitRelayLinks(t, source, 2, 30*time.Second)
	identity, err := target.identityStore.Identity()
	if err != nil {
		t.Fatalf("target identity: %v", err)
	}
	waitRelayRoute(t, source, topology.NodeID(identity.NodeID), 30*time.Second)
	return source, relay, target
}

// relayDialUntil retries DialContext until the two-hop route and the dedicated
// STREAM lane have converged through the relay. dialTimeout bounds each attempt;
// it also seeds the Path hop budget (hopBudgetMicros caps by the caller
// deadline), so a small value gives the idle test a short budget to outlive.
func relayDialUntil(t *testing.T, n *network, address string, dialTimeout, timeout time.Duration) Stream {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		stream, err := n.DialContext(ctx, "tcp", address)
		cancel()
		if err == nil {
			return stream
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("relay DialContext(%s) never succeeded: %v", address, lastErr)
	return nil
}

// relaySession asserts the relay observed the session but holds no endpoint
// state: no Session object/root, no E2E protector, and its own session manager
// created no local Session.
func relaySession(t *testing.T, r *network) *sessionEntry {
	t.Helper()
	r.streams.mu.Lock()
	defer r.streams.mu.Unlock()
	var found *sessionEntry
	for _, entry := range r.streams.sessionsByID {
		if entry != nil && entry.relay {
			found = entry
			break
		}
	}
	if found == nil {
		t.Fatalf("relay never observed a session")
	}
	if found.sess != nil {
		t.Fatalf("relay holds a Session object/root")
	}
	found.protMu.Lock()
	tx, rx := found.tx, found.rx
	found.protMu.Unlock()
	if tx != nil || rx != nil {
		t.Fatalf("relay holds E2E protectors")
	}
	if got := r.streams.sessions.Len(); got != 0 {
		t.Fatalf("relay opened %d local Session(s), want 0", got)
	}
	return found
}

func TestRelayTCPEchoOver64KiB(t *testing.T) {
	source, relay, target := newRelayTopology(t)

	listener, err := target.Listen("tcp", relayTargetIP+":19021")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()

	const total = 80 << 10
	serverRelease := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		stream, err := listener.Accept()
		if err != nil {
			return
		}
		defer stream.Close()
		buf := make([]byte, 4<<10)
		read := 0
		for read < total {
			n, err := stream.Read(buf)
			if n > 0 {
				read += n
				if _, werr := stream.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = stream.CloseWrite()
		<-serverRelease
	}()

	stream := relayDialUntil(t, source, relayTargetIP+":19021", 5*time.Second, 30*time.Second)
	defer stream.Close()

	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte((i*7 + 3) % 251)
	}
	written := 0
	for written < total {
		end := written + (16 << 10)
		if end > total {
			end = total
		}
		n, err := stream.Write(payload[written:end])
		if err != nil {
			t.Fatalf("write at %d: %v", written, err)
		}
		written += n
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	echoed := make([]byte, total)
	if _, err := io.ReadFull(stream, echoed); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	close(serverRelease)
	<-serverDone
	if !bytes.Equal(payload, echoed) {
		t.Fatalf("relay echo mismatch over %d bytes", total)
	}
	entry := relaySession(t, relay)
	if entry.attempt != 0 || entry.targetEpoch == 0 {
		t.Fatalf("relay session identity = %d/%d", entry.attempt, entry.targetEpoch)
	}
	// The relay must not have installed a target path handle for this scope.
	if ps := relay.streams.pathByScope(entry.scope); ps == nil || !ps.relay {
		t.Fatalf("relay path entry missing or not relay-owned")
	}
}

// TestRelayIdleBeyondBudgetKeepsFlowing proves the hop budget meters one frame's
// traversal, not the idle lifetime of a Ready path: after idling longer than the
// Path's initial budget, a new DATA frame is still forwarded. The old
// accumulation of time.Since(previous frame) made this fail with a torn Link.
func TestRelayIdleBeyondBudgetKeepsFlowing(t *testing.T) {
	source, relay, target := newRelayTopology(t)

	listener, err := target.Listen("tcp", relayTargetIP+":19022")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()

	serverRelease := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		stream, err := listener.Accept()
		if err != nil {
			return
		}
		defer stream.Close()
		_, _ = io.Copy(stream, stream)
		<-serverRelease
	}()

	stream := relayDialUntil(t, source, relayTargetIP+":19022", 1*time.Second, 30*time.Second)
	defer stream.Close()

	first := []byte("first-chunk-before-idle")
	if _, err := stream.Write(first); err != nil {
		t.Fatalf("first write: %v", err)
	}
	got := make([]byte, len(first))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("first echo: %v", err)
	}
	if !bytes.Equal(first, got) {
		t.Fatalf("first echo mismatch")
	}

	// The Dial context that seeded the Path budget is bounded well under this.
	time.Sleep(3 * time.Second)

	second := []byte("second-chunk-after-idle")
	if _, err := stream.Write(second); err != nil {
		t.Fatalf("post-idle write: %v", err)
	}
	got2 := make([]byte, len(second))
	if _, err := io.ReadFull(stream, got2); err != nil {
		t.Fatalf("post-idle echo: %v", err)
	}
	if !bytes.Equal(second, got2) {
		t.Fatalf("post-idle echo mismatch")
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	close(serverRelease)
	<-serverDone
	relaySession(t, relay)
}

// newRelayTestNodeWS builds a node whose only peer entry point is a typed
// WebSocket Target, exercising the production typed-connector initiator path.
func newRelayTestNodeWS(t *testing.T, fixedIP, wsEndpoint string) *network {
	t.Helper()
	listenURL, _ := freeTCPListenAddress(t)
	cfg := Config{
		Listen:  []string{listenURL},
		Targets: []ConnectionTarget{{Connector: &WebSocketConnector{}, Endpoint: wsEndpoint}},
		Network: NetworkConfig{Name: relayTestName, CIDR: relayTestCIDR, Token: relayTestToken},
		Options: RuntimeOptions{FixedIP: fixedIP},
	}
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork(ws fixed_ip=%s) error = %v", fixedIP, err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle.(*network)
}

// relayWebSocketServer accepts the initiator's dedicated WebSocket connections
// into the relay through the public AttachConnection entry, negotiating the lane
// from the peer's authenticated HANDSHAKE exactly like the built-in accepted
// carrier. One endpoint therefore carries both the CONTROL adjacency and the
// dedicated STREAM lane.
func relayWebSocketServer(t *testing.T, relay *network) string {
	t.Helper()
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		socket, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn, err := NewWebSocketConnection(socket)
		if err != nil {
			_ = socket.Close()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		attached, err := relay.AttachConnection(ctx, conn, AttachOptions{Role: LinkRoleResponder, Negotiate: true})
		if err != nil {
			_ = conn.Close()
			return
		}
		<-attached.Done()
	}))
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http")
}

// TestRelayMixedTCPWebSocketTwoHop runs the two-hop data plane with a WebSocket
// A-R hop and a TCP R-B hop: A dials a typed WebSocket Target, R accepts the
// CONTROL and STREAM lanes through public AttachConnection, forwards over its
// built-in TCP upstream, and 80 KiB is echoed and FIN-closed end to end.
func TestRelayMixedTCPWebSocketTwoHop(t *testing.T) {
	target := newRelayTestNode(t, relayTargetIP, "")
	relay := newRelayTestNode(t, relayHopIP, relayCarrierURL(target))
	wsEndpoint := relayWebSocketServer(t, relay)
	source := newRelayTestNodeWS(t, relaySourceIP, wsEndpoint)
	waitRelayLinks(t, target, 2, 30*time.Second)
	waitRelayLinks(t, relay, 4, 30*time.Second)
	waitRelayLinks(t, source, 2, 30*time.Second)
	identity, err := target.identityStore.Identity()
	if err != nil {
		t.Fatalf("target identity: %v", err)
	}
	waitRelayRoute(t, source, topology.NodeID(identity.NodeID), 30*time.Second)

	listener, err := target.Listen("tcp", relayTargetIP+":19023")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()

	const total = 80 << 10
	serverRelease := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		stream, err := listener.Accept()
		if err != nil {
			return
		}
		defer stream.Close()
		buf := make([]byte, 4<<10)
		read := 0
		for read < total {
			n, err := stream.Read(buf)
			if n > 0 {
				read += n
				if _, werr := stream.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = stream.CloseWrite()
		<-serverRelease
	}()

	stream := relayDialUntil(t, source, relayTargetIP+":19023", 5*time.Second, 30*time.Second)
	defer stream.Close()
	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte((i*11 + 5) % 251)
	}
	written := 0
	for written < total {
		end := written + (16 << 10)
		if end > total {
			end = total
		}
		n, err := stream.Write(payload[written:end])
		if err != nil {
			t.Fatalf("write at %d: %v", written, err)
		}
		written += n
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	echoed := make([]byte, total)
	if _, err := io.ReadFull(stream, echoed); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	close(serverRelease)
	<-serverDone
	if !bytes.Equal(payload, echoed) {
		t.Fatalf("mixed TCP/WS relay echo mismatch over %d bytes", total)
	}
	relaySession(t, relay)
}
