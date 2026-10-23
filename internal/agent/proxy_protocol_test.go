package agent

// Protocol-level tests for the proxy transports that agent_test.go does not
// cover: the streamed HTTP forward path, opaque WebSocket-over-CONNECT, and
// SOCKS5 UDP ASSOCIATE against a real local UDP client and a real datagram
// channel double.
//
// Every outbound TCP connection here goes through a test Dialer; the only real
// OS sockets are the local test client, the local origin listener and the UDP
// relay socket the proxy binds for an association. Nothing in this file dials a
// default of its own.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- raw HTTP origin -------------------------------------------------------

// startOrigin runs a raw TCP origin that parses exactly one well-framed HTTP
// request per connection with http.ReadRequest (no net/http server
// interpretation) and then hands the connection to handle. It lets the tests see
// the byte-exact request the proxy produced and stream responses by hand.
func startOrigin(t *testing.T, handle func(conn net.Conn, request *http.Request, reader *bufio.Reader)) (net.Addr, chan *http.Request) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	requests := make(chan *http.Request, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				select {
				case requests <- request:
				default:
				}
				handle(conn, request, reader)
			}()
		}
	}()
	return listener.Addr(), requests
}

func readOriginRequest(t *testing.T, requests chan *http.Request) *http.Request {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(testTimeout):
		t.Fatal("the origin never received a request")
		return nil
	}
}

// readResponseObject parses the proxy's reply with net/http so the test client
// de-chunks it exactly like a real HTTP client would.
func (c *httpProxyClient) readResponseObject(request *http.Request) *http.Response {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(testTimeout))
	response, err := http.ReadResponse(c.reader, request)
	if err != nil {
		c.t.Fatalf("read proxied response: %v", err)
	}
	return response
}

func (c *httpProxyClient) writeRaw(payload string) {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, payload); err != nil {
		c.t.Fatalf("http proxy raw write: %v", err)
	}
}

func forwardLines(authority string, headers ...string) []string {
	lines := []string{"GET http://" + authority + "/path?q=1 HTTP/1.1", "Host: " + authority}
	return append(lines, headers...)
}

// --- HTTP forward proxy ----------------------------------------------------

func TestHTTPForwardStreamsAbsoluteURIRequest(t *testing.T) {
	originAddr, requests := startOrigin(t, func(conn net.Conn, request *http.Request, reader *bufio.Reader) {
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello")
	})
	dialer := newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var direct net.Dialer
		return direct.DialContext(ctx, network, address)
	})
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))

	client.writeRequest(forwardLines(originAddr.String(), "Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"))...)
	response := client.readResponseObject(&http.Request{Method: http.MethodGet})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", response.StatusCode)
	}
	if !response.Close {
		t.Fatal("the single-exchange adapter must announce Connection: close")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("body %q, want hello", body)
	}

	origin := readOriginRequest(t, requests)
	if origin.RequestURI != "/path?q=1" {
		t.Fatalf("origin request target %q, want origin-form /path?q=1", origin.RequestURI)
	}
	if origin.Host != originAddr.String() {
		t.Fatalf("origin Host %q, want %q (the original authority)", origin.Host, originAddr.String())
	}
	if calls := dialer.recorded(); len(calls) != 1 || calls[0] != "tcp "+originAddr.String() {
		t.Fatalf("dialer calls %v, want [tcp %s]", calls, originAddr.String())
	}
	if stats := agent.Stats(); stats.Accepted != 1 || stats.DialFailures != 0 || stats.PolicyDenied != 0 {
		t.Fatalf("unexpected stats %+v", stats)
	}
}

func TestHTTPForwardStripsHopHeadersAndCredentials(t *testing.T) {
	originAddr, requests := startOrigin(t, func(conn net.Conn, request *http.Request, reader *bufio.Reader) {
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	})
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var direct net.Dialer
		return direct.DialContext(ctx, network, address)
	})})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))

	client.writeRequest(
		"GET http://"+originAddr.String()+"/leak HTTP/1.1",
		"Host: "+originAddr.String(),
		"Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"),
		"Proxy-Connection: keep-alive",
		"Connection: X-Private-Hop",
		"X-Private-Hop: must-not-reach-the-target",
		"X-End-To-End: must-reach-the-target",
	)
	response := client.readResponseObject(&http.Request{Method: http.MethodGet})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", response.StatusCode)
	}

	origin := readOriginRequest(t, requests)
	// net/http's client-side ReadRequest keeps a Connection header and strips
	// only the tokens it names, so an empty Connection here proves the proxy
	// removed it rather than the origin discarding it.
	for _, name := range []string{"Connection", "Proxy-Authorization", "Proxy-Connection", "X-Private-Hop", "Proxy-Authenticate"} {
		if value := origin.Header.Get(name); value != "" {
			t.Fatalf("origin received hop-by-hop/private header %s: %q", name, value)
		}
	}
	if value := origin.Header.Get("X-End-To-End"); value != "must-reach-the-target" {
		t.Fatalf("end-to-end header X-End-To-End = %q, want it forwarded", value)
	}
}

func TestHTTPForwardStreamsChunkedRequestBody(t *testing.T) {
	type upload struct {
		target string
		header http.Header
		body   []byte
	}
	uploads := make(chan upload, 1)
	originAddr, _ := startOrigin(t, func(conn net.Conn, request *http.Request, reader *bufio.Reader) {
		body, _ := io.ReadAll(request.Body)
		uploads <- upload{target: request.RequestURI, header: request.Header.Clone(), body: body}
		_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\n\r\n")
	})
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var direct net.Dialer
		return direct.DialContext(ctx, network, address)
	})})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))

	client.writeRequest(
		"POST http://"+originAddr.String()+"/upload HTTP/1.1",
		"Host: "+originAddr.String(),
		"Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"),
		"Transfer-Encoding: chunked",
	)
	client.writeRaw("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")

	response := client.readResponseObject(&http.Request{Method: http.MethodPost})
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d, want 204", response.StatusCode)
	}
	select {
	case received := <-uploads:
		if received.target != "/upload" {
			t.Fatalf("origin target %q, want /upload", received.target)
		}
		if string(received.body) != "hello world" {
			t.Fatalf("origin body %q, want the reassembled chunked payload", received.body)
		}
		if received.header.Get("Proxy-Authorization") != "" {
			t.Fatal("Proxy-Authorization reached the origin on a chunked upload")
		}
	case <-time.After(testTimeout):
		t.Fatal("the origin never received the chunked upload")
	}
}

func TestHTTPForwardStreamsChunkedResponseIncrementally(t *testing.T) {
	release := make(chan struct{})
	originAddr, _ := startOrigin(t, func(conn net.Conn, request *http.Request, reader *bufio.Reader) {
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
		_, _ = io.WriteString(conn, "5\r\nfirst\r\n")
		<-release
		_, _ = io.WriteString(conn, "6\r\nsecond\r\n0\r\n\r\n")
	})
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var direct net.Dialer
		return direct.DialContext(ctx, network, address)
	})})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))

	client.writeRequest("GET http://"+originAddr.String()+"/stream HTTP/1.1",
		"Host: "+originAddr.String(),
		"Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"))
	response := client.readResponseObject(&http.Request{Method: http.MethodGet})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", response.StatusCode)
	}
	if !hasChunkedTransfer(response.TransferEncoding) {
		t.Fatalf("TransferEncoding %v, want chunked re-encoding", response.TransferEncoding)
	}

	// The first chunk must arrive while the origin is still blocked, which is
	// only possible if the proxy streams instead of buffering the whole body.
	first := make([]byte, 5)
	if _, err := io.ReadFull(response.Body, first); err != nil {
		t.Fatalf("read first streamed chunk: %v", err)
	}
	if string(first) != "first" {
		t.Fatalf("first chunk %q, want first", first)
	}
	close(release)
	rest, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read second streamed chunk: %v", err)
	}
	if string(rest) != "second" {
		t.Fatalf("second chunk %q, want second", rest)
	}
}

func TestHTTPForwardHandlesExpectContinue(t *testing.T) {
	type posted struct {
		body   []byte
		expect string
	}
	posts := make(chan posted, 1)
	originAddr, _ := startOrigin(t, func(conn net.Conn, request *http.Request, reader *bufio.Reader) {
		body, _ := io.ReadAll(request.Body)
		posts <- posted{body: body, expect: request.Header.Get("Expect")}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var direct net.Dialer
		return direct.DialContext(ctx, network, address)
	})})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))

	client.writeRequest(
		"POST http://"+originAddr.String()+"/expect HTTP/1.1",
		"Host: "+originAddr.String(),
		"Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"),
		"Content-Length: 5",
		"Expect: 100-continue",
	)
	status, _ := client.readResponse()
	if status != http.StatusContinue {
		t.Fatalf("interim status %d, want 100", status)
	}
	client.writeRaw("hello")
	status, _ = client.readResponse()
	if status != http.StatusOK {
		t.Fatalf("final status %d, want 200", status)
	}
	select {
	case received := <-posts:
		if string(received.body) != "hello" {
			t.Fatalf("origin body %q, want hello", received.body)
		}
		if received.expect != "" {
			t.Fatalf("origin received Expect %q; the proxy must answer it itself", received.expect)
		}
	case <-time.After(testTimeout):
		t.Fatal("the origin never received the expected body")
	}
}

func TestHTTPForwardWrongAuth407(t *testing.T) {
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))

	client.writeRequest("GET http://example.test/path HTTP/1.1", "Host: example.test",
		"Proxy-Authorization: "+basicValue("proxy-user", "wrong"))
	status, header := client.readResponse()
	if status != http.StatusProxyAuthRequired {
		t.Fatalf("status %d, want 407", status)
	}
	if !strings.HasPrefix(header.Get("Proxy-Authenticate"), "Basic ") {
		t.Fatalf("Proxy-Authenticate %q, want a Basic challenge", header.Get("Proxy-Authenticate"))
	}
	client.expectClosed()
	waitFor(t, func() bool { return agent.Stats().AuthFailures == 1 }, "forward auth failure counted")
	if calls := dialer.recorded(); len(calls) != 0 {
		t.Fatalf("dialer was called for an unauthenticated forward request: %v", calls)
	}
}

func TestHTTPForwardRejectsUnroutableTargetsWithoutDialing(t *testing.T) {
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})
	proxy := mustHTTPAddr(t, agent)

	cases := []struct {
		name   string
		lines  []string
		status int
	}{
		{
			name:   "https absolute uri needs CONNECT",
			lines:  []string{"GET https://example.test/ HTTP/1.1", "Host: example.test"},
			status: http.StatusBadRequest,
		},
		{
			name:   "origin form without Host",
			lines:  []string{"GET / HTTP/1.1"},
			status: http.StatusBadRequest,
		},
		{
			name:   "ipv6 literal",
			lines:  []string{"GET http://[2001:db8::1]:8443/ HTTP/1.1", "Host: [2001:db8::1]:8443"},
			status: http.StatusBadRequest,
		},
		{
			name:   "port zero",
			lines:  []string{"GET http://example.test:0/ HTTP/1.1", "Host: example.test:0"},
			status: http.StatusBadRequest,
		},
		{
			name:   "port out of range",
			lines:  []string{"GET http://example.test:70000/ HTTP/1.1", "Host: example.test:70000"},
			status: http.StatusBadRequest,
		},
		{
			name:   "non decimal port",
			lines:  []string{"GET http://example.test:https/ HTTP/1.1", "Host: example.test:https"},
			status: http.StatusBadRequest,
		},
		{
			name:   "asterisk target",
			lines:  []string{"OPTIONS * HTTP/1.1", "Host: example.test"},
			status: http.StatusBadRequest,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			before := len(dialer.recorded())
			client := dialHTTPProxy(t, proxy)
			lines := append(append([]string(nil), testCase.lines...), "Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"))
			client.writeRequest(lines...)
			status, _ := client.readResponse()
			if status != testCase.status {
				t.Fatalf("status %d, want %d", status, testCase.status)
			}
			client.expectClosed()
			if after := len(dialer.recorded()); after != before {
				t.Fatalf("dialer was called for a refused target: %v", dialer.recorded()[before:])
			}
		})
	}
}

// --- CONNECT WebSocket -----------------------------------------------------

func TestHTTPConnectCarriesOpaqueWebSocketUpgrade(t *testing.T) {
	upgrades := make(chan string, 1)
	originAddr, _ := startOrigin(t, func(conn net.Conn, request *http.Request, reader *bufio.Reader) {
		upgrades <- request.Header.Get("Upgrade")
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		frame := make([]byte, 4)
		if _, err := io.ReadFull(reader, frame); err != nil {
			return
		}
		_, _ = conn.Write(frame)
	})
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var direct net.Dialer
		return direct.DialContext(ctx, network, address)
	})})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))

	client.writeRequest(client.connectLines(originAddr.String(), "Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"))...)
	status, _ := client.readResponse()
	if status != http.StatusOK {
		t.Fatalf("CONNECT status %d, want 200", status)
	}

	// Everything after the 200 is opaque: a WebSocket upgrade and its 101 pass
	// through the tunnel without the proxy interpreting HTTP.
	client.writeRaw("GET /chat HTTP/1.1\r\nHost: " + originAddr.String() +
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	status, header := client.readResponse()
	if status != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d, want 101", status)
	}
	if header.Get("Upgrade") != "websocket" || header.Get("Sec-WebSocket-Accept") == "" {
		t.Fatalf("101 headers %v, want a websocket upgrade", header)
	}
	select {
	case upgrade := <-upgrades:
		if upgrade != "websocket" {
			t.Fatalf("origin saw Upgrade %q, want websocket", upgrade)
		}
	case <-time.After(testTimeout):
		t.Fatal("the origin never saw the upgrade request")
	}

	frame := []byte{0x81, 0x02, 'h', 'i'}
	_ = client.conn.SetDeadline(time.Now().Add(testTimeout))
	if _, err := client.conn.Write(frame); err != nil {
		t.Fatalf("write websocket frame through the tunnel: %v", err)
	}
	echo := make([]byte, len(frame))
	if _, err := io.ReadFull(client.reader, echo); err != nil {
		t.Fatalf("read websocket frame through the tunnel: %v", err)
	}
	if string(echo) != string(frame) {
		t.Fatalf("tunnel echoed %v, want %v", echo, frame)
	}
}

// --- target resolver -------------------------------------------------------

type targetResolverFunc func(ctx context.Context, host string, port uint16) (netip.AddrPort, error)

func (f targetResolverFunc) ResolveTarget(ctx context.Context, host string, port uint16) (netip.AddrPort, error) {
	return f(ctx, host, port)
}

func TestSOCKS5TargetResolverPinsValidatedIPv4(t *testing.T) {
	echo := startEchoServer(t)
	var (
		mu    sync.Mutex
		calls []string
	)
	dialer := newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var direct net.Dialer
		return direct.DialContext(ctx, network, address)
	})
	resolver := targetResolverFunc(func(ctx context.Context, host string, port uint16) (netip.AddrPort, error) {
		mu.Lock()
		calls = append(calls, net.JoinHostPort(host, strconv.Itoa(int(port))))
		mu.Unlock()
		return netip.MustParseAddrPort(echo.String()), nil
	})
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{}), Deps{Dialer: dialer, TargetResolver: resolver})
	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()

	reply := client.connect(socksAddressDomain, []byte("example.test"), 8443)
	if reply.reply != socksReplySucceeded {
		t.Fatalf("CONNECT reply 0x%02x, want success", reply.reply)
	}
	tunnelEcho(t, client.conn, client.conn, "pinned address round trip")

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 || calls[0] != "example.test:8443" {
		t.Fatalf("resolver calls %v, want [example.test:8443]", calls)
	}
	if got := dialer.recorded(); len(got) != 1 || got[0] != "tcp "+echo.String() {
		t.Fatalf("dialer calls %v, want the resolver-pinned endpoint [tcp %s]", got, echo.String())
	}
}

func TestProxyTargetResolverDenialIsFailClosed(t *testing.T) {
	resolverErr := errors.New("target is outside the virtual CIDR")
	resolver := targetResolverFunc(func(ctx context.Context, host string, port uint16) (netip.AddrPort, error) {
		return netip.AddrPort{}, resolverErr
	})
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{}), Deps{Dialer: dialer, TargetResolver: resolver})
	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()
	reply := client.connect(socksAddressIPv4, []byte{10, 9, 0, 1}, 80)
	if reply.reply != socksReplyNotAllowed {
		t.Fatalf("CONNECT reply 0x%02x, want 0x%02x (not allowed by ruleset)", reply.reply, socksReplyNotAllowed)
	}
	client.expectClosed()
	waitFor(t, func() bool { return agent.Stats().PolicyDenied == 1 }, "policy denial counted")
	if calls := dialer.recorded(); len(calls) != 0 {
		t.Fatalf("dialer was called for a denied target: %v", calls)
	}

	httpAgent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: dialer, TargetResolver: resolver})
	httpClient := dialHTTPProxy(t, mustHTTPAddr(t, httpAgent))
	httpClient.writeRequest(forwardLines("example.test", "Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"))...)
	if status, _ := httpClient.readResponse(); status != http.StatusForbidden {
		t.Fatalf("forward status %d, want 403 for a denied target", status)
	}
	httpClient.expectClosed()
	waitFor(t, func() bool { return httpAgent.Stats().PolicyDenied == 1 }, "forward policy denial counted")
}

// --- SOCKS5 UDP ASSOCIATE doubles ------------------------------------------

type testDatagram struct {
	channel *testUDPChannel
	host    string
	port    uint16
	payload []byte
}

// testDatagramBackend is a DatagramBackend double. Each association gets its own
// receive/closed channels; every SendTo lands on the backend-wide send channel
// together with the channel that produced it, so a test can reply on exactly the
// association it is serving.
type testDatagramBackend struct {
	mu      sync.Mutex
	newErr  error
	created int
	send    chan testDatagram
	channel chan *testUDPChannel
}

func newTestDatagramBackend() *testDatagramBackend {
	return &testDatagramBackend{
		send:    make(chan testDatagram, 64),
		channel: make(chan *testUDPChannel, 64),
	}
}

func (b *testDatagramBackend) NewAssociation(ctx context.Context) (UDPDgramChannel, error) {
	if b.newErr != nil {
		return nil, b.newErr
	}
	association := &testUDPChannel{
		backend: b,
		receive: make(chan testDatagram, 64),
		closed:  make(chan struct{}),
	}
	b.mu.Lock()
	b.created++
	b.mu.Unlock()
	select {
	case b.channel <- association:
	default:
	}
	return association, nil
}

func (b *testDatagramBackend) createdCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.created
}

func (b *testDatagramBackend) association(t *testing.T) *testUDPChannel {
	t.Helper()
	select {
	case association := <-b.channel:
		return association
	case <-time.After(testTimeout):
		t.Fatal("NewAssociation was never called")
		return nil
	}
}

func (b *testDatagramBackend) nextSend(t *testing.T) testDatagram {
	t.Helper()
	select {
	case datagram := <-b.send:
		return datagram
	case <-time.After(testTimeout):
		t.Fatal("the backend never received a datagram")
		return testDatagram{}
	}
}

type testUDPChannel struct {
	backend   *testDatagramBackend
	receive   chan testDatagram
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *testUDPChannel) SendTo(ctx context.Context, host string, port uint16, payload []byte) error {
	select {
	case c.backend.send <- testDatagram{channel: c, host: host, port: port, payload: append([]byte(nil), payload...)}:
		return nil
	case <-c.closed:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *testUDPChannel) Receive(ctx context.Context) (string, uint16, []byte, error) {
	select {
	case datagram := <-c.receive:
		return datagram.host, datagram.port, datagram.payload, nil
	case <-c.closed:
		return "", 0, nil, net.ErrClosed
	case <-ctx.Done():
		return "", 0, nil, ctx.Err()
	}
}

func (c *testUDPChannel) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// socksUDPClient is a real local IPv4 UDP socket acting as a SOCKS5 UDP client.
type socksUDPClient struct {
	t     *testing.T
	conn  *net.UDPConn
	relay *net.UDPAddr
}

func newSOCKSUDPClient(t *testing.T, host string, port int) *socksUDPClient {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp client listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	relay, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("resolve relay %s:%d: %v", host, port, err)
	}
	return &socksUDPClient{t: t, conn: conn, relay: relay}
}

func (c *socksUDPClient) localPort() uint16 {
	c.t.Helper()
	address, ok := c.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		c.t.Fatalf("unexpected udp local address %T", c.conn.LocalAddr())
	}
	return uint16(address.Port)
}

func (c *socksUDPClient) sendDatagram(host string, port uint16, payload []byte) {
	c.t.Helper()
	datagram, err := encodeSOCKSUDPReply(host, port, payload)
	if err != nil {
		c.t.Fatalf("encode client datagram: %v", err)
	}
	c.sendRaw(datagram)
}

func (c *socksUDPClient) sendRaw(datagram []byte) {
	c.t.Helper()
	if _, err := c.conn.WriteToUDP(datagram, c.relay); err != nil {
		c.t.Fatalf("udp client send: %v", err)
	}
}

func (c *socksUDPClient) receive() (string, uint16, []byte) {
	c.t.Helper()
	host, port, payload, ok := c.receiveWithin(testTimeout)
	if !ok {
		c.t.Fatal("udp client received no datagram")
	}
	return host, port, payload
}

func (c *socksUDPClient) receiveWithin(timeout time.Duration) (string, uint16, []byte, bool) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 65535)
	count, _, err := c.conn.ReadFromUDP(buffer)
	if err != nil {
		return "", 0, nil, false
	}
	request, err := parseSOCKSUDPRequest(buffer[:count])
	if err != nil {
		c.t.Fatalf("decode reply: %v", err)
	}
	return request.host, request.port, append([]byte(nil), request.payload...), true
}

func socksUDPAssociateRequest(port uint16) []byte {
	return []byte{socksVersion, socksCommandUDPAssociate, 0x00, socksAddressIPv4, 0, 0, 0, 0, byte(port >> 8), byte(port)}
}

func associateSOCKS5UDP(t *testing.T, proxy net.Addr) (*socksClient, socksReply) {
	t.Helper()
	client := dialSOCKS5(t, proxy)
	client.login()
	reply := client.connectRaw(socksUDPAssociateRequest(0))
	return client, reply
}

func newUDPProxyAgent(t *testing.T, backend DatagramBackend, options ProxyOptions) *Agent {
	t.Helper()
	if options.HandshakeTimeout <= 0 {
		options.HandshakeTimeout = 30 * time.Second
	}
	config := socksAgentConfig(options)
	return newTestAgent(t, config, Deps{Dialer: newScriptedDialer(nil), DatagramBackend: backend})
}

// --- SOCKS5 UDP ASSOCIATE --------------------------------------------------

func TestSOCKS5UDPAssociateRoundTrip(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	_, reply := associateSOCKS5UDP(t, mustSocksAddr(t, agent))
	if reply.reply != socksReplySucceeded {
		t.Fatalf("UDP ASSOCIATE reply 0x%02x, want success", reply.reply)
	}
	if reply.addressType != socksAddressIPv4 || reply.host == "0.0.0.0" || reply.host == "" || reply.port == 0 {
		t.Fatalf("BND %s:%d, want a reachable non-wildcard IPv4 endpoint", reply.host, reply.port)
	}
	association := backend.association(t)

	udpClient := newSOCKSUDPClient(t, reply.host, reply.port)
	udpClient.sendDatagram("203.0.113.7", 53, []byte("query"))
	forwarded := backend.nextSend(t)
	if forwarded.host != "203.0.113.7" || forwarded.port != 53 || string(forwarded.payload) != "query" {
		t.Fatalf("backend received %s:%d %q, want 203.0.113.7:53 query", forwarded.host, forwarded.port, forwarded.payload)
	}

	association.receive <- testDatagram{host: "203.0.113.7", port: 53, payload: []byte("answer")}
	host, port, payload := udpClient.receive()
	if host != "203.0.113.7" || port != 53 || string(payload) != "answer" {
		t.Fatalf("client received %s:%d %q, want 203.0.113.7:53 answer", host, port, payload)
	}

	waitFor(t, func() bool {
		return agent.Stats().UDPAssociations == 1 && agent.Stats().UDPRequests == 1 && agent.Stats().UDPReplies == 1
	}, "udp association counters")
	if stats := agent.Stats(); stats.UDPDropped != 0 || stats.UDPFailures != 0 {
		t.Fatalf("unexpected drops/failures %+v", stats)
	}
}

func TestSOCKS5UDPAssociateDomainAndEmptyPayloads(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	_, reply := associateSOCKS5UDP(t, mustSocksAddr(t, agent))
	association := backend.association(t)
	udpClient := newSOCKSUDPClient(t, reply.host, reply.port)

	// A domain destination passes through unresolved, like the CONNECT contract.
	udpClient.sendDatagram("example.test", 5353, nil)
	forwarded := backend.nextSend(t)
	if forwarded.host != "example.test" || forwarded.port != 5353 || len(forwarded.payload) != 0 {
		t.Fatalf("backend received %s:%d len=%d, want example.test:5353 with an empty payload", forwarded.host, forwarded.port, len(forwarded.payload))
	}
	// A zero-length reply is a legal datagram and must come back as such.
	association.receive <- testDatagram{host: "example.test", port: 5353, payload: nil}
	host, port, payload := udpClient.receive()
	if host != "example.test" || port != 5353 || len(payload) != 0 {
		t.Fatalf("client received %s:%d len=%d, want an empty reply", host, port, len(payload))
	}
}

func TestSOCKS5UDPAssociateDropsMalformedFragmentsAndIPv6(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	_, reply := associateSOCKS5UDP(t, mustSocksAddr(t, agent))
	_ = backend.association(t)
	udpClient := newSOCKSUDPClient(t, reply.host, reply.port)

	ipv6 := make([]byte, 4+16+2)
	ipv6[3] = socksAddressIPv6

	cases := []struct {
		name     string
		datagram []byte
	}{
		{name: "reserved bytes", datagram: []byte{0x01, 0x00, 0x00, socksAddressIPv4, 127, 0, 0, 1, 0, 53}},
		{name: "fragment", datagram: []byte{0x00, 0x00, 0x01, socksAddressIPv4, 127, 0, 0, 1, 0, 53}},
		{name: "truncated", datagram: []byte{0x00, 0x00, 0x00, socksAddressIPv4, 127, 0}},
		{name: "ipv6 address type", datagram: ipv6},
		{name: "unknown address type", datagram: []byte{0x00, 0x00, 0x00, 0x09, 0, 53}},
		{name: "target port zero", datagram: []byte{0x00, 0x00, 0x00, socksAddressIPv4, 127, 0, 0, 1, 0, 0}},
		{name: "empty domain", datagram: []byte{0x00, 0x00, 0x00, socksAddressDomain, 0x00, 0, 53}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			udpClient.sendRaw(testCase.datagram)
		})
	}
	waitFor(t, func() bool { return agent.Stats().UDPDropped == uint64(len(cases)) }, "malformed datagrams dropped")
	if extra := len(backend.channel); extra != 0 {
		t.Fatalf("backend opened %d extra associations", extra)
	}
	select {
	case datagram := <-backend.send:
		t.Fatalf("backend received a malformed datagram: %+v", datagram)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSOCKS5UDPAssociateAssociationBinding(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	_, reply := associateSOCKS5UDP(t, mustSocksAddr(t, agent))
	_ = backend.association(t)

	pinned := newSOCKSUDPClient(t, reply.host, reply.port)
	pinned.sendDatagram("203.0.113.7", 53, []byte("first"))
	first := backend.nextSend(t)
	if first.channel == nil || string(first.payload) != "first" {
		t.Fatalf("first datagram %+v, want it forwarded", first)
	}

	// A second local socket is a different source port and must not piggyback on
	// the association once the first valid datagram pinned the port.
	spoofer := newSOCKSUDPClient(t, reply.host, reply.port)
	spoofer.sendDatagram("203.0.113.7", 53, []byte("spoofed"))
	waitFor(t, func() bool { return agent.Stats().UDPDropped == 1 }, "spoofed source port dropped")
	select {
	case datagram := <-backend.send:
		t.Fatalf("backend received a datagram from an unpinned source port: %+v", datagram)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSOCKS5UDPAssociatePinsSourcePortFromRequest(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	proxy := mustSocksAddr(t, agent)
	client := dialSOCKS5(t, proxy)
	client.login()
	// The client declares the source port it will use; the relay must accept
	// exactly that port and nothing else.
	clientUDP := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	conn, err := net.ListenUDP("udp4", clientUDP)
	if err != nil {
		t.Fatalf("udp client listen: %v", err)
	}
	defer conn.Close()
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	reply := client.connectRaw(socksUDPAssociateRequest(port))
	if reply.reply != socksReplySucceeded {
		t.Fatalf("UDP ASSOCIATE reply 0x%02x, want success", reply.reply)
	}
	_ = backend.association(t)
	relay, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(reply.host, strconv.Itoa(reply.port)))
	if err != nil {
		t.Fatalf("resolve relay: %v", err)
	}
	datagram, err := encodeSOCKSUDPReply("203.0.113.7", 53, []byte("pinned"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := conn.WriteToUDP(datagram, relay); err != nil {
		t.Fatalf("send from the pinned port: %v", err)
	}
	forwarded := backend.nextSend(t)
	if string(forwarded.payload) != "pinned" || forwarded.port != 53 {
		t.Fatalf("backend received %+v, want the pinned-port datagram", forwarded)
	}
}

func TestSOCKS5UDPAssociateRejectsForeignSourceIP(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	defer relay.Close()
	backend := newTestDatagramBackend()
	association, err := backend.NewAssociation(context.Background())
	if err != nil {
		t.Fatalf("NewAssociation: %v", err)
	}
	server := &proxyServer{}
	bound := newUDPAssociation(server, nil, relay, association, netip.MustParseAddr("127.0.0.1"), 40000)
	bound.ctx = context.Background()

	datagram, err := encodeSOCKSUDPReply("203.0.113.7", 53, []byte("stolen"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	bound.handleClientDatagram(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.9"), 40000), datagram)
	if dropped := server.stats.udpDropped.Load(); dropped != 1 {
		t.Fatalf("UDPDropped = %d, want the foreign source IP dropped", dropped)
	}
	select {
	case forwarded := <-backend.send:
		t.Fatalf("backend received a datagram from a foreign source IP: %+v", forwarded)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSOCKS5UDPAssociateLargeEmptyAndBoundaryPayloads(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	_, reply := associateSOCKS5UDP(t, mustSocksAddr(t, agent))
	association := backend.association(t)
	udpClient := newSOCKSUDPClient(t, reply.host, reply.port)

	// 65,497 payload bytes + the 10-byte IPv4 SOCKS header is exactly the
	// 65,507-byte local IPv4 UDP wire limit.
	maximum := make([]byte, maxSOCKSUDPIPv4Payload)
	for index := range maximum {
		maximum[index] = byte(index)
	}
	udpClient.sendDatagram("203.0.113.7", 53, maximum)
	forwarded := backend.nextSend(t)
	if len(forwarded.payload) != len(maximum) {
		t.Fatalf("backend received %d payload bytes, want %d", len(forwarded.payload), len(maximum))
	}
	association.receive <- testDatagram{host: "203.0.113.7", port: 53, payload: maximum}
	_, _, payload := udpClient.receive()
	if len(payload) != len(maximum) {
		t.Fatalf("client received %d payload bytes, want %d", len(payload), len(maximum))
	}

	// One byte more cannot fit in a single local IPv4 UDP packet, so the reply
	// is dropped and counted instead of truncated.
	association.receive <- testDatagram{host: "203.0.113.7", port: 53, payload: make([]byte, maxSOCKSUDPIPv4Payload+1)}
	waitFor(t, func() bool { return agent.Stats().UDPDropped == 1 }, "oversized reply dropped")
	if _, _, _, ok := udpClient.receiveWithin(150 * time.Millisecond); ok {
		t.Fatal("an oversized reply reached the client")
	}
}

func TestSOCKS5UDPAssociateClosedByControlConnection(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	client, reply := associateSOCKS5UDP(t, mustSocksAddr(t, agent))
	if reply.reply != socksReplySucceeded {
		t.Fatalf("UDP ASSOCIATE reply 0x%02x, want success", reply.reply)
	}
	association := backend.association(t)

	if err := client.conn.Close(); err != nil {
		t.Fatalf("close control connection: %v", err)
	}
	waitFor(t, func() bool {
		select {
		case <-association.closed:
			return true
		default:
			return false
		}
	}, "association channel released when the control connection ends")
	waitFor(t, func() bool { return agent.Stats().Active == 0 }, "admission slot released")
}

func TestSOCKS5UDPAssociateBackendLossEndsAssociation(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	client, reply := associateSOCKS5UDP(t, mustSocksAddr(t, agent))
	if reply.reply != socksReplySucceeded {
		t.Fatalf("UDP ASSOCIATE reply 0x%02x, want success", reply.reply)
	}
	association := backend.association(t)

	// The datagram channel disappearing ends the association and closes the
	// control connection instead of leaving a half-live relay.
	if err := association.Close(); err != nil {
		t.Fatalf("close backend channel: %v", err)
	}
	waitFor(t, func() bool { return agent.Stats().UDPFailures == 1 }, "backend loss counted")
	client.expectClosed()
}

func TestSOCKS5UDPAssociateUnwiredReturnsCommandNotSupported(t *testing.T) {
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{}), Deps{Dialer: newScriptedDialer(nil)})
	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()
	reply := client.connectRaw(socksUDPAssociateRequest(0))
	if reply.reply != socksReplyCommandNotSupported {
		t.Fatalf("UDP ASSOCIATE reply 0x%02x, want 0x%02x without a DatagramBackend", reply.reply, socksReplyCommandNotSupported)
	}
	client.expectClosed()
	waitFor(t, func() bool { return agent.Stats().Unsupported == 1 }, "unwired UDP ASSOCIATE counted")
}

func TestSOCKS5UDPAssociateBackendSetupFailure(t *testing.T) {
	backend := newTestDatagramBackend()
	backend.newErr = errors.New("flow udp plane unavailable")
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	client, reply := associateSOCKS5UDP(t, mustSocksAddr(t, agent))
	if reply.reply != socksReplyGeneralFailure {
		t.Fatalf("UDP ASSOCIATE reply 0x%02x, want general failure", reply.reply)
	}
	client.expectClosed()
	waitFor(t, func() bool { return agent.Stats().UDPFailures == 1 }, "association setup failure counted")
}

func TestSOCKS5UDPAssociateRequiresAuthentication(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	if method := client.negotiate(socksMethodUserPass); method != socksMethodUserPass {
		t.Fatalf("negotiated method 0x%02x, want username/password", method)
	}
	if status := client.authenticate("proxy-user", "wrong"); status != socksAuthFailure {
		t.Fatalf("authentication status 0x%02x, want failure", status)
	}
	client.expectClosed()
	if created := backend.createdCount(); created != 0 {
		t.Fatalf("the backend was opened for an unauthenticated client (%d associations)", created)
	}
}

func TestSOCKS5UDPAssociateHandshakeDeadline(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{HandshakeTimeout: 200 * time.Millisecond})
	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()
	// The client never sends the ASSOCIATE request: the handshake must stay
	// bounded and must not open an association.
	started := time.Now()
	client.expectClosed()
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("a stalled ASSOCIATE request was held for %s", elapsed)
	}
	if created := backend.createdCount(); created != 0 {
		t.Fatalf("the backend was opened before the ASSOCIATE request (%d associations)", created)
	}
}

func TestSOCKS5UDPAssociateTornDownByAgentClose(t *testing.T) {
	backend := newTestDatagramBackend()
	config := socksAgentConfig(ProxyOptions{HandshakeTimeout: 30 * time.Second})
	agent, err := New(config, Deps{Dialer: newScriptedDialer(nil), DatagramBackend: backend, Listen: testListenFunc()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	client, reply := associateSOCKS5UDP(t, mustSocksAddr(t, agent))
	if reply.reply != socksReplySucceeded {
		t.Fatalf("UDP ASSOCIATE reply 0x%02x, want success", reply.reply)
	}
	association := backend.association(t)

	done := make(chan error, 1)
	go func() { done <- agent.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Close did not return while an association was live")
	}
	select {
	case <-association.closed:
	default:
		t.Fatal("Close left the datagram channel open")
	}
	client.expectClosed()
	select {
	case <-agent.Done():
	default:
		t.Fatal("Done was not closed")
	}
}

func TestSOCKS5UDPAssociateConcurrentAssociations(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{MaxConnections: 8})
	proxy := mustSocksAddr(t, agent)

	const associations = 6
	type clientState struct {
		client *socksClient
		udp    *socksUDPClient
	}
	clients := make([]clientState, 0, associations)
	for index := 0; index < associations; index++ {
		client, reply := associateSOCKS5UDP(t, proxy)
		if reply.reply != socksReplySucceeded {
			t.Fatalf("association %d reply 0x%02x, want success", index, reply.reply)
		}
		clients = append(clients, clientState{client: client, udp: newSOCKSUDPClient(t, reply.host, reply.port)})
	}
	waitFor(t, func() bool { return backend.createdCount() == associations }, "every association opened a channel")

	for index, state := range clients {
		state.udp.sendDatagram("203.0.113.7", uint16(1000+index), []byte(fmt.Sprintf("payload-%d", index)))
	}
	seen := map[string]bool{}
	for index := 0; index < associations; index++ {
		forwarded := backend.nextSend(t)
		seen[string(forwarded.payload)] = true
		forwarded.channel.receive <- testDatagram{host: "203.0.113.7", port: forwarded.port, payload: []byte("reply-" + string(forwarded.payload))}
	}
	if len(seen) != associations {
		t.Fatalf("backend saw %d distinct payloads, want %d", len(seen), associations)
	}
	for index, state := range clients {
		host, port, payload := state.udp.receive()
		if host != "203.0.113.7" || port != uint16(1000+index) || string(payload) != fmt.Sprintf("reply-payload-%d", index) {
			t.Fatalf("association %d received %s:%d %q", index, host, port, payload)
		}
	}
	waitFor(t, func() bool {
		stats := agent.Stats()
		return stats.UDPAssociations == associations && stats.UDPRequests == associations && stats.UDPReplies == associations
	}, "concurrent association counters")
}

func TestSOCKS5UDPAssociateJoinsEveryGoroutine(t *testing.T) {
	backend := newTestDatagramBackend()
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	proxy := mustSocksAddr(t, agent)
	baseline := runtime.NumGoroutine()

	client, reply := associateSOCKS5UDP(t, proxy)
	if reply.reply != socksReplySucceeded {
		t.Fatalf("UDP ASSOCIATE reply 0x%02x, want success", reply.reply)
	}
	_ = backend.association(t)
	// Prove the association is actually running: one datagram crosses the relay.
	udpClient := newSOCKSUDPClient(t, reply.host, reply.port)
	udpClient.sendDatagram("203.0.113.7", 53, []byte("live"))
	_ = backend.nextSend(t)

	if err := client.conn.Close(); err != nil {
		t.Fatalf("close control connection: %v", err)
	}
	waitFor(t, func() bool { return agent.Stats().Active == 0 }, "association handler released")
	// The handler plus the three association goroutines must all have exited; a
	// leaked relay/control/backend reader would keep the count above the baseline.
	waitFor(t, func() bool { return runtime.NumGoroutine() <= baseline }, "association goroutines joined")
}

// realUDPBackend is a DatagramBackend whose channel owns a real local UDP socket
// and forwards to a real local UDP upstream. It is the end-to-end counterpart of
// the in-memory channel double: client -> SOCKS5 relay -> real UDP socket ->
// real upstream and back, with no Flow plane involved.
type realUDPBackend struct {
	upstream *net.UDPAddr

	mu      sync.Mutex
	created int
	closed  int
}

func (b *realUDPBackend) NewAssociation(ctx context.Context) (UDPDgramChannel, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.created++
	b.mu.Unlock()
	return &realUDPChannel{backend: b, conn: conn}, nil
}

type realUDPChannel struct {
	backend   *realUDPBackend
	conn      *net.UDPConn
	closeOnce sync.Once
}

func (c *realUDPChannel) SendTo(ctx context.Context, host string, port uint16, payload []byte) error {
	address, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return err
	}
	_, err = c.conn.WriteToUDP(payload, address)
	return err
}

func (c *realUDPChannel) Receive(ctx context.Context) (string, uint16, []byte, error) {
	// No read deadline: Receive blocks until a datagram arrives, Close unblocks
	// it, or ctx is cancelled. Returning a synthetic timeout would be
	// indistinguishable from channel loss to the relay.
	buffer := make([]byte, maxSOCKSUDPWirePayload)
	count, from, err := c.conn.ReadFromUDP(buffer)
	if err != nil {
		if ctx.Err() != nil {
			return "", 0, nil, ctx.Err()
		}
		return "", 0, nil, err
	}
	host, port, ok := splitUDPAddress(from)
	if !ok {
		return "", 0, nil, fmt.Errorf("unexpected udp source %v", from)
	}
	return host, port, append([]byte(nil), buffer[:count]...), nil
}

func (c *realUDPChannel) Close() error {
	c.closeOnce.Do(func() {
		c.backend.mu.Lock()
		c.backend.closed++
		c.backend.mu.Unlock()
		_ = c.conn.Close()
	})
	return nil
}

func splitUDPAddress(address *net.UDPAddr) (string, uint16, bool) {
	if address == nil || address.IP == nil {
		return "", 0, false
	}
	ipv4 := address.IP.To4()
	if ipv4 == nil {
		return "", 0, false
	}
	return net.IP(ipv4).String(), uint16(address.Port), true
}

func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, maxSOCKSUDPWirePayload)
		for {
			count, from, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:count], from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

func TestSOCKS5UDPAssociateRealUDPUpstream(t *testing.T) {
	echo := startUDPEcho(t)
	backend := &realUDPBackend{upstream: echo}
	agent := newUDPProxyAgent(t, backend, ProxyOptions{})
	_, reply := associateSOCKS5UDP(t, mustSocksAddr(t, agent))
	if reply.reply != socksReplySucceeded {
		t.Fatalf("UDP ASSOCIATE reply 0x%02x, want success", reply.reply)
	}
	client := newSOCKSUDPClient(t, reply.host, reply.port)

	payload := []byte("hello real udp upstream")
	client.sendDatagram(echo.IP.String(), uint16(echo.Port), payload)
	host, port, got := client.receive()
	if host != echo.IP.String() || port != uint16(echo.Port) || string(got) != string(payload) {
		t.Fatalf("client received %s:%d %q, want the echoed %s:%d %q", host, port, got, echo.IP, echo.Port, payload)
	}
	waitFor(t, func() bool {
		stats := agent.Stats()
		return stats.UDPAssociations == 1 && stats.UDPRequests == 1 && stats.UDPReplies == 1
	}, "real upstream association counters")

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.created != 1 || backend.closed != 0 {
		t.Fatalf("backend created=%d closed=%d, want one live association", backend.created, backend.closed)
	}
}

// --- SOCKS5 UDP codec and budget -------------------------------------------

func TestSOCKSUDPDatagramCodec(t *testing.T) {
	request, err := parseSOCKSUDPRequest([]byte{0, 0, 0, socksAddressIPv4, 203, 0, 113, 7, 0x00, 0x35, 'h', 'i'})
	if err != nil {
		t.Fatalf("parse IPv4 datagram: %v", err)
	}
	if request.host != "203.0.113.7" || request.port != 53 || string(request.payload) != "hi" {
		t.Fatalf("parsed %+v, want 203.0.113.7:53 hi", request)
	}

	domainRequest, err := parseSOCKSUDPRequest(append([]byte{0, 0, 0, socksAddressDomain, 11}, append([]byte("example.com"), 0x00, 0x35)...))
	if err != nil {
		t.Fatalf("parse domain datagram: %v", err)
	}
	if domainRequest.host != "example.com" || domainRequest.port != 53 {
		t.Fatalf("parsed domain %+v, want example.com:53", domainRequest)
	}

	if _, err := parseSOCKSUDPRequest([]byte{0, 0, 1, socksAddressIPv4, 203, 0, 113, 7, 0, 53}); !errors.Is(err, errSOCKSUDPFragment) {
		t.Fatalf("FRAG=1 error %v, want errSOCKSUDPFragment", err)
	}
	if _, err := parseSOCKSUDPRequest([]byte{0, 0, 0, socksAddressIPv6}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("IPv6 datagram error %v, want ErrUnsupported", err)
	}

	maximum := make([]byte, maxSOCKSUDPIPv4Payload)
	reply, err := encodeSOCKSUDPReply("203.0.113.7", 53, maximum)
	if err != nil {
		t.Fatalf("encode maximum IPv4 reply: %v", err)
	}
	if len(reply) != maxSOCKSUDPWirePayload {
		t.Fatalf("maximum reply is %d bytes, want %d", len(reply), maxSOCKSUDPWirePayload)
	}
	if _, err := encodeSOCKSUDPReply("203.0.113.7", 53, append(maximum, 0)); !errors.Is(err, errDatagramTooLarge) {
		t.Fatalf("oversized IPv4 reply error %v, want errDatagramTooLarge", err)
	}
	if _, err := encodeSOCKSUDPReply("example.com", 53, maximum); !errors.Is(err, errDatagramTooLarge) {
		t.Fatalf("oversized domain reply error %v, want errDatagramTooLarge", err)
	}
	if _, err := encodeSOCKSUDPReply("2001:db8::1", 53, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("IPv6 reply error %v, want ErrUnsupported", err)
	}
}

func TestAuthFailureBudget(t *testing.T) {
	budget := newAuthFailureBudget(2, time.Minute)
	now := time.Now()
	if !budget.allow(now) {
		t.Fatal("a fresh budget must allow the first attempt")
	}
	budget.record(now)
	if !budget.allow(now) {
		t.Fatal("a budget with room must allow the second attempt")
	}
	budget.record(now)
	if budget.allow(now) {
		t.Fatal("an exhausted budget must refuse further attempts in the same window")
	}
	if !budget.allow(now.Add(time.Minute)) {
		t.Fatal("a rolled-over window must allow attempts again")
	}

	degenerate := newAuthFailureBudget(0, 0)
	if !degenerate.allow(time.Now()) {
		t.Fatal("a degenerate budget must still allow one attempt")
	}
	degenerate.record(time.Now())
	if degenerate.allow(time.Now()) {
		t.Fatal("a degenerate budget must bound attempts to one per window")
	}
}

func TestProxyAuthBudgetThrottlesAfterRepeatedFailures(t *testing.T) {
	// The budget capacity is the entry's connection limit, so a limit of two
	// allows exactly two credential rejections before throttling.
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{MaxConnections: 2, HandshakeTimeout: 30 * time.Second}), Deps{Dialer: newScriptedDialer(nil)})
	proxy := mustSocksAddr(t, agent)

	for attempt := 0; attempt < 2; attempt++ {
		client := dialSOCKS5(t, proxy)
		if method := client.negotiate(socksMethodUserPass); method != socksMethodUserPass {
			t.Fatalf("attempt %d negotiated method 0x%02x", attempt, method)
		}
		if status := client.authenticate("proxy-user", "wrong"); status != socksAuthFailure {
			t.Fatalf("attempt %d authentication status 0x%02x, want failure", attempt, status)
		}
		client.expectClosed()
	}
	waitFor(t, func() bool { return agent.Stats().AuthFailures == 2 }, "two credential rejections counted")

	throttled := dialSOCKS5(t, proxy)
	throttled.expectClosed()
	waitFor(t, func() bool { return agent.Stats().Throttled == 1 }, "exhausted budget throttled")
	if stats := agent.Stats(); stats.AuthFailures != 2 {
		t.Fatalf("throttling must not count as a credential rejection: %+v", stats)
	}
}
