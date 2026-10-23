package relay_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/relay"
	"github.com/yiiilin/simpletier/pkg/simpletier/room"
)

// TestTwoFacesAreIndependentListeners proves the ingress shape: ServeTCP and
// ServeWebSocket each own their own address, and a peer may use either one to reach
// the same room.
func TestTwoFacesAreIndependentListeners(t *testing.T) {
	base := t.TempDir()
	const name, cidr, token = "twofaces", "10.205.0.0/24", "two-faces-token"

	r := relay.New(relay.Options{Rooms: room.Options{
		Name: name, CIDR: cidr, LogLevel: "error",
	}})
	for _, d := range []string{base + "/relay", base + "/tcp", base + "/ws"} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Two distinct addresses, one per face.
	tcpAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	wsAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	tcpDone := make(chan error, 1)
	wsDone := make(chan error, 1)
	go func() { tcpDone <- r.ServeTCP(ctx, tcpAddr) }()
	go func() { wsDone <- r.ServeWebSocket(ctx, wsAddr) }()
	waitListening(t, tcpAddr)
	waitListening(t, wsAddr)

	// Peer over TCP.
	tcpPeer, err := simpletier.NewNetwork(simpletier.Config{
		Network: simpletier.NetworkConfig{Name: name, CIDR: cidr, Token: token},
		Options: simpletier.RuntimeOptions{LogLevel: "error"},
	})
	if err != nil {
		t.Fatalf("tcp peer: %v", err)
	}
	defer func() { _ = tcpPeer.Close() }()
	tcpLink, err := relay.JoinRoom(ctx, tcpPeer, tcpAddr, token)
	if err != nil {
		t.Fatalf("join over TCP: %v", err)
	}
	defer func() { _ = tcpLink.Close() }()

	// Peer over WebSocket, on the other address.
	wsPeer, err := simpletier.NewNetwork(simpletier.Config{
		Network: simpletier.NetworkConfig{Name: name, CIDR: cidr, Token: token},
		Options: simpletier.RuntimeOptions{LogLevel: "error"},
	})
	if err != nil {
		t.Fatalf("ws peer: %v", err)
	}
	defer func() { _ = wsPeer.Close() }()

	wsURL := fmt.Sprintf("ws://%s/ws?room=%s", wsAddr, token)
	ws, _, err := (&websocket.Dialer{}).Dial(wsURL, http.Header{})
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	conn, err := simpletier.NewWebSocketConnection(ws)
	if err != nil {
		t.Fatalf("wrap websocket: %v", err)
	}
	if _, err := wsPeer.AttachConnection(ctx, conn, simpletier.AttachOptions{
		Role: simpletier.LinkRoleInitiator,
		Lane: 0,
	}); err != nil {
		t.Fatalf("attach over websocket: %v", err)
	}

	// A peer from either face lands in the same room.
	waitPeersAtLeast(t, tcpPeer, 2)
	waitPeersAtLeast(t, wsPeer, 2)
	if got := r.Count(); got != 1 {
		t.Fatalf("Count() = %d; want 1 shared room", got)
	}

	// healthz belongs to the WebSocket face only, since that face owns an HTTP server.
	resp, err := http.Get("http://" + wsAddr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz status = %d; want 200", resp.StatusCode)
	}

	cancel()
	for _, ch := range []chan error{tcpDone, wsDone} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("serve returned %v; want nil on ctx cancel", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("serve did not return after ctx cancel")
		}
	}
}

// waitPeersAtLeast waits for the overlay view to reach want peers.
func waitPeersAtLeast(t *testing.T, n simpletier.Network, want int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if peers, err := n.Peers(); err == nil && len(peers) >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	peers, _ := n.Peers()
	t.Fatalf("network saw %d peers; want at least %d", len(peers), want)
}
