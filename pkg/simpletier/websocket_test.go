package simpletier

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yiiilin/simpletier/internal/wire"
)

func websocketPair(t *testing.T, header http.Header) (Connection, *websocket.Conn) {
	t.Helper()
	accepted := make(chan *websocket.Conn, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header.Get("Authorization") != "" && r.Header.Get("Authorization") != header.Get("Authorization") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		accepted <- conn
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := (&WebSocketConnector{Header: header}).Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	select {
	case peer := <-accepted:
		if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		return client, peer
	case <-time.After(time.Second):
		t.Fatal("WebSocket was not accepted")
		return nil, nil
	}
}

func TestWebSocketConnectorExistingPeerAndStreamBoundaries(t *testing.T) {
	client, peer := websocketPair(t, http.Header{"Authorization": {"Bearer host-test-token"}})
	if client.Info().Type != "websocket" {
		t.Fatal("WebSocket metadata was lost")
	}
	// The Dial helper's context has already been canceled. Success lifetime is independent.
	if _, err := client.Write([]byte("client")); err != nil {
		t.Fatal(err)
	}
	kind, payload, err := peer.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || string(payload) != "client" {
		t.Fatalf("client binary message = %d %q %v", kind, payload, err)
	}
	for _, segment := range []string{"", "ab", "c", "def"} {
		if err := peer.WriteMessage(websocket.BinaryMessage, []byte(segment)); err != nil {
			t.Fatal(err)
		}
	}
	var combined [6]byte
	if _, err := io.ReadFull(client, combined[:]); err != nil || string(combined[:]) != "abcdef" {
		t.Fatalf("message boundaries leaked into byte stream: %q %v", combined, err)
	}
	serverSide, err := NewWebSocketConnection(peer)
	if err != nil {
		t.Fatal(err)
	}
	if serverSide.Info().Type != "websocket" {
		t.Fatal("accepted existing WebSocket lost its type")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketCarriesOpaqueFramesBothDirections(t *testing.T) {
	client, peer := websocketPair(t, nil)
	server, err := NewWebSocketConnection(peer)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, err := NewStreamCarrier(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewStreamCarrier(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	frame := CarrierFrame{Kind: FrameKindLinkControl, Body: bytes.Repeat([]byte{0xa5}, 32)}
	for _, pair := range [][2]*StreamCarrier{{a, b}, {b, a}} {
		written := make(chan error, 1)
		go func() { written <- pair[0].WriteFrame(frame) }()
		got, err := pair[1].ReadFrame()
		if err != nil || !bytes.Equal(got.Body, frame.Body) || got.Kind != frame.Kind {
			t.Fatalf("WebSocket framing = %#v %v", got, err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}
}

func TestWebSocketTextMessageFailsClosed(t *testing.T) {
	client, peer := websocketPair(t, nil)
	if err := peer.WriteMessage(websocket.TextMessage, []byte("not a binary stream")); err != nil {
		t.Fatal(err)
	}
	var buffer [16]byte
	if _, err := client.Read(buffer[:]); !errors.Is(err, ErrWebSocketMessageType) {
		t.Fatalf("text message = %v", err)
	}
	if _, err := client.Write(buffer[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after text protocol failure = %v", err)
	}
}

func TestWebSocketCloseUnblocksRead(t *testing.T) {
	client, _ := websocketPair(t, nil)
	result := make(chan error, 1)
	go func() { var data [1]byte; _, err := client.Read(data[:]); result <- err }()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("closed WebSocket read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("WebSocket Close blocked on its read lock")
	}
}

func TestWebSocketConnectorRejectsInvalidAndUnauthorized(t *testing.T) {
	connector := &WebSocketConnector{}
	if _, err := connector.Dial(nil, "ws://unused"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil context = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := connector.Dial(ctx, "ws://unused"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Dial = %v", err)
	}
	if _, err := NewWebSocketConnection(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil accepted WebSocket = %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer server.Close()
	if conn, err := connector.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http")); conn != nil || err == nil {
		t.Fatal("unauthorized HTTP handshake was accepted")
	}
	if conn, err := connector.Dial(context.Background(), "http://invalid"); conn != nil || err == nil {
		t.Fatal("non-WebSocket URL was accepted")
	}
}

func TestWebSocketNetworkTargetIsRealButNotAuthenticated(t *testing.T) {
	peerResult := make(chan error, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer host-fixture" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			peerResult <- err
			return
		}
		defer conn.Close()
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			peerResult <- err
			return
		}
		kind, payload, err := conn.ReadMessage()
		if err != nil {
			peerResult <- err
			return
		}
		if kind != websocket.BinaryMessage {
			peerResult <- errors.New("initial Link handshake was not a binary message")
			return
		}
		reader := bytes.NewReader(payload)
		record, err := wire.ReadHandshake(reader)
		if err != nil {
			peerResult <- err
			return
		}
		if reader.Len() != 0 || record.Kind != wire.HandshakeXXMsg1 || record.LinkID == 0 || record.LinkEpoch == 0 || record.Generation == 0 || record.LaneID != 0 || len(record.Payload) < 32 {
			peerResult <- errors.New("invalid initial CONTROL XX_MSG1 record")
			return
		}
		// HTTP authentication is not mesh authentication: never answer XX_MSG1.
		peerResult <- conn.Close()
	}))
	defer server.Close()
	cfg := validConfig()
	cfg.Listen, cfg.Upstreams = nil, nil
	closed := make(chan struct{})
	connector := &WebSocketConnector{Header: http.Header{"Authorization": {"Bearer host-fixture"}}}
	cfg.Targets = []ConnectionTarget{{Endpoint: "ws" + strings.TrimPrefix(server.URL, "http"), Connector: ConnectorFunc(func(ctx context.Context, endpoint string) (Connection, error) {
		conn, err := connector.Dial(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		return &webSocketTargetCloseObserver{Connection: conn, closed: closed}, nil
	})}}
	n, err := NewNetwork(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	select {
	case err := <-peerResult:
		if err != nil {
			t.Fatal("WebSocket Target did not send valid XX_MSG1:", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WebSocket Target did not send initial Link handshake")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("aborted WebSocket handshake was not rejected and closed")
	}
	runtime := n.(*network)
	runtime.mu.Lock()
	activeLinks := len(runtime.activeLinks)
	runtime.mu.Unlock()
	if activeLinks != 0 {
		t.Fatal("HTTP authentication admitted a Link without Noise confirmation")
	}
	if _, err := n.DialContext(context.Background(), "tcp", "10.20.0.8:8080"); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("HTTP auth incorrectly granted a mesh route: %v", err)
	}
}

type webSocketTargetCloseObserver struct {
	Connection
	closed chan struct{}
	once   sync.Once
}

func (c *webSocketTargetCloseObserver) Close() error {
	err := c.Connection.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestWebSocketFragmentedCoalescedFramesAndControl(t *testing.T) {
	client, peer := websocketPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	carrier, err := NewStreamCarrier(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	defer carrier.Close()
	frame := CarrierFrame{Kind: FrameKindLinkControl, Body: bytes.Repeat([]byte{0xa5}, 10000)}
	var encoded bytes.Buffer
	if err := wire.WriteFrame(&encoded, frame); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteFrame(&encoded, frame); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() {
		writer, err := peer.NextWriter(websocket.BinaryMessage)
		if err != nil {
			written <- err
			return
		}
		data := encoded.Bytes()
		_, firstErr := writer.Write(data[:12000])
		pingErr := peer.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(time.Second))
		_, lastErr := writer.Write(data[12000:])
		written <- errors.Join(firstErr, pingErr, lastErr, writer.Close())
	}()
	for range 2 {
		got, err := carrier.ReadFrame()
		if err != nil || !bytes.Equal(got.Body, frame.Body) {
			t.Fatalf("fragmented/coalesced frame = %d %v", len(got.Body), err)
		}
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketNormalCloseIsEOF(t *testing.T) {
	client, peer := websocketPair(t, nil)
	if err := peer.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := client.Read(data[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("normal WebSocket close = %v", err)
	}
}

func TestWebSocketConnectorTrustedWSS(t *testing.T) {
	accepted := make(chan *websocket.Conn, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			accepted <- conn
		}
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport)
	connector := &WebSocketConnector{Dialer: &websocket.Dialer{TLSClientConfig: transport.TLSClientConfig.Clone()}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := connector.Dial(ctx, "wss"+strings.TrimPrefix(server.URL, "https"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := <-accepted
	defer peer.Close()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := conn.Write([]byte("tls")); err != nil {
		t.Fatal("completed WSS Dial context closed established transport:", err)
	}
	kind, data, err := peer.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || string(data) != "tls" {
		t.Fatalf("WSS payload = %d %q %v", kind, data, err)
	}
}

func TestWebSocketCancelStalledUpgrade(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
	}))
	defer server.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := (&WebSocketConnector{Dialer: &websocket.Dialer{}}).Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"))
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("HTTP upgrade did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled upgrade = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt stalled HTTP upgrade")
	}
}

func TestWebSocketDefaultDoesNotUseProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	client, _ := websocketPair(t, nil)
	if client.Info().Type != "websocket" {
		t.Fatal("environment settings changed SDK connection selection")
	}
}
