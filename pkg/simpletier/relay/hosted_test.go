package relay_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/relay"
	"github.com/yiiilin/simpletier/pkg/simpletier/room"
)

// TestAttachOnHostOwnedServer proves the relay can be mounted inside a host's own
// HTTP server: the host owns routing, the path and the authentication check, and
// only hands an upgraded connection to the relay with a room token.
//
// This is the shape a business system needs — its own gin (or net/http) route, its
// own auth, no relay-owned listener.
func TestAttachOnHostOwnedServer(t *testing.T) {
	base := t.TempDir()
	const name, cidr, token = "hosted", "10.198.0.0/24", "hosted-room-token"

	r := relay.New(relay.Options{Rooms: room.Options{
		Name: name, CIDR: cidr, LogLevel: "error",
	}})
	for _, d := range []string{base + "/relay", base + "/a", base + "/b"} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The host's own server and routing: nothing here belongs to the relay.
	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{
		ReadBufferSize:  64 << 10,
		WriteBufferSize: 64 << 10,
		CheckOrigin:     func(*http.Request) bool { return true },
	}
	mux.HandleFunc("/app/rooms/ws", func(w http.ResponseWriter, req *http.Request) {
		// Host-defined first gate. The relay never sees this decision.
		if req.Header.Get("X-Auth") != "let-me-in" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		roomToken := req.URL.Query().Get("room")
		if roomToken == "" {
			http.Error(w, "missing room token", http.StatusBadRequest)
			return
		}
		ws, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()

		conn, err := simpletier.NewWebSocketConnection(ws)
		if err != nil {
			return
		}
		link, err := r.Attach(ctx, conn, roomToken)
		if err != nil {
			return
		}
		defer func() { _ = link.Close() }()
		select {
		case <-link.Done():
		case <-req.Context().Done():
		}
	})

	serverAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	server := &http.Server{Addr: serverAddr, Handler: mux}
	listener, err := net.Listen("tcp", serverAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()
	time.Sleep(200 * time.Millisecond)

	// A client joins the room over the host's WebSocket route.
	wsURL := fmt.Sprintf("ws://%s/app/rooms/ws?room=%s", serverAddr, token)
	dialer := websocket.Dialer{}
	header := http.Header{}
	header.Set("X-Auth", "let-me-in")

	joinWs := func(label string) simpletier.Network {
		ws, _, err := dialer.Dial(wsURL, header)
		if err != nil {
			t.Fatalf("%s websocket dial: %v", label, err)
		}
		n, err := simpletier.NewNetwork(simpletier.Config{
			Network: simpletier.NetworkConfig{Name: name, CIDR: cidr, Token: token},
			Options: simpletier.RuntimeOptions{},
		})
		if err != nil {
			t.Fatalf("%s network: %v", label, err)
		}
		conn, err := simpletier.NewWebSocketConnection(ws)
		if err != nil {
			t.Fatalf("%s wrap: %v", label, err)
		}
		if _, err := n.AttachConnection(ctx, conn, simpletier.AttachOptions{
			Role: simpletier.LinkRoleInitiator,
			Lane: 0,
		}); err != nil {
			t.Fatalf("%s attach: %v", label, err)
		}
		return n
	}

	// One peer is enough here: the assertion is that a host-owned handler can mount
	// the relay at all, which the successful attach above already decided.
	inA := joinWs("a")

	// Facts arrive asynchronously over the attached carrier, so wait for the relay
	// peer instead of sampling once.
	var peers []simpletier.PeerFact
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		peers, _ = inA.Peers()
		if len(peers) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(peers) == 0 {
		t.Fatal("client attached through the host handler but never learned the relay peer")
	}
	t.Logf("hosted attach works: %d peers via the host's own route", len(peers))

	// And the host's gate is the host's: without the header the upgrade is refused.
	if _, resp, err := dialer.Dial(wsURL, nil); err == nil {
		t.Fatal("websocket dial without X-Auth succeeded; the host gate did not run")
	} else if resp != nil && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 from the host gate", resp.StatusCode)
	}
}
