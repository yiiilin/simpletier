package agent

// The tests in this file drive the real proxy handlers over local TCP listeners
// and net.Pipe connections. They cover RFC 1928/1929 method negotiation,
// authentication, CONNECT and the unsupported-command replies, HTTP CONNECT with
// Basic credentials, listener lifecycle, bounded admission and the port shapes.
// The streamed HTTP forward path, WebSocket-over-CONNECT and SOCKS5 UDP
// ASSOCIATE, including the datagram channel contract, are covered in
// proxy_protocol_test.go.
//
// They do not prove overlay reachability: pkg/simpletier Network.DialContext
// still returns ErrNoRoute, the pkg-level Agent wiring does not exist, and the
// L3 packet plane does not forward packets between devices. Every Dialer used
// here is a test double or a local net.Dialer. The real platform device runtime
// is covered separately by device_linux_test.go.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
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
	"syscall"
	"testing"
	"time"
)

const (
	testTimeout      = 5 * time.Second
	testWaitInterval = 5 * time.Millisecond
)

func boolPointer(value bool) *bool {
	return &value
}

func testListenFunc() ListenFunc {
	return func(ctx context.Context, network, address string) (net.Listener, error) {
		var config net.ListenConfig
		return config.Listen(ctx, "tcp", "127.0.0.1:0")
	}
}

func socksProxyConfig(options ProxyOptions) ProxyConfig {
	return ProxyConfig{
		Listen:   "127.0.0.1:1080",
		Username: "proxy-user",
		Password: "proxy-pass",
		Options:  options,
	}
}

func socksAgentConfig(options ProxyOptions) AgentConfig {
	config := socksProxyConfig(options)
	return AgentConfig{Inbounds: Inbounds{SOCKS5: &config}}
}

func httpProxyConfig(options ProxyOptions) ProxyConfig {
	return ProxyConfig{
		Listen:   "127.0.0.1:8080",
		Username: "proxy-user",
		Password: "proxy-pass",
		Options:  options,
	}
}

func httpAgentConfig(options ProxyOptions) AgentConfig {
	config := httpProxyConfig(options)
	return AgentConfig{Inbounds: Inbounds{HTTPProxy: &config}}
}

func newTestAgent(t *testing.T, config AgentConfig, deps Deps) *Agent {
	t.Helper()
	if deps.Listen == nil {
		deps.Listen = testListenFunc()
	}
	agent, err := New(config, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := agent.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return agent
}

func mustSocksAddr(t *testing.T, agent *Agent) net.Addr {
	t.Helper()
	socks5, _ := agent.ListenAddrs()
	if socks5 == nil {
		t.Fatal("socks5 listener was not bound")
	}
	return socks5
}

func mustHTTPAddr(t *testing.T, agent *Agent) net.Addr {
	t.Helper()
	_, httpProxy := agent.ListenAddrs()
	if httpProxy == nil {
		t.Fatal("http proxy listener was not bound")
	}
	return httpProxy
}

func startEchoServer(t *testing.T) net.Addr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr()
}

func waitFor(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(testWaitInterval)
	}
	t.Fatalf("timed out waiting for %s", message)
}

// expectConnClosed asserts that the peer closed the connection within the test
// timeout rather than leaving it open.
func expectConnClosed(t *testing.T, conn net.Conn, reader io.Reader) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(testTimeout))
	var buffer [1]byte
	_, err := reader.Read(buffer[:])
	if err == nil {
		t.Fatal("expected the proxy to close the connection, but read a byte")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("proxy did not close the connection within %s", testTimeout)
	}
}

// expectConnDrained asserts that the peer terminated the connection within the
// test timeout, tolerating protocol bytes still in flight. It is used where the
// handler races a final reply against the teardown: Agent.Close cancels an
// in-flight dial and closes the admitted connection concurrently, so the client
// may observe the reply, an immediate EOF, or the reply followed by EOF. A
// connection left open is the only failure.
func expectConnDrained(t *testing.T, conn net.Conn, reader io.Reader) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(testTimeout))
	buffer := make([]byte, 64)
	for {
		if _, err := reader.Read(buffer); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Fatalf("proxy did not close the connection within %s", testTimeout)
			}
			return
		}
	}
}

func tunnelEcho(t *testing.T, conn net.Conn, reader io.Reader, payload string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(testTimeout))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if string(echo) != payload {
		t.Fatalf("tunnel echoed %q, want %q", echo, payload)
	}
}

// scriptedDialer records every target it is asked for and either runs a script
// or returns one end of a net.Pipe with the peer offered on peers.
type scriptedDialer struct {
	mu    sync.Mutex
	calls []string
	dial  func(ctx context.Context, network, address string) (net.Conn, error)
	peers chan net.Conn
}

func newScriptedDialer(dial func(ctx context.Context, network, address string) (net.Conn, error)) *scriptedDialer {
	return &scriptedDialer{dial: dial, peers: make(chan net.Conn, 8)}
}

func (d *scriptedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, network+" "+address)
	dial := d.dial
	d.mu.Unlock()
	if dial != nil {
		return dial(ctx, network, address)
	}
	client, peer := net.Pipe()
	select {
	case d.peers <- peer:
	default:
		_ = peer.Close()
	}
	return client, nil
}

func (d *scriptedDialer) recorded() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

func (d *scriptedDialer) peer(t *testing.T) net.Conn {
	t.Helper()
	select {
	case peer := <-d.peers:
		return peer
	case <-time.After(testTimeout):
		t.Fatal("the Dialer was not asked to connect")
		return nil
	}
}

// --- SOCKS5 client helpers -------------------------------------------------

type socksClient struct {
	t    *testing.T
	conn net.Conn
}

func dialSOCKS5(t *testing.T, proxy net.Addr) *socksClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy.String(), testTimeout)
	if err != nil {
		t.Fatalf("dial socks5 proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(testTimeout))
	t.Cleanup(func() { _ = conn.Close() })
	return &socksClient{t: t, conn: conn}
}

func (c *socksClient) write(payload []byte) {
	c.t.Helper()
	if _, err := c.conn.Write(payload); err != nil {
		c.t.Fatalf("socks5 write: %v", err)
	}
}

func (c *socksClient) read(length int) []byte {
	c.t.Helper()
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		c.t.Fatalf("socks5 read %d bytes: %v", length, err)
	}
	return payload
}

// readAuthReply reads the two-byte RFC 1929 sub-negotiation reply. The server
// writes the reply and closes immediately, so on Windows the reset can reach the
// client before the buffered reply is drained and io.ReadFull surfaces
// "wsarecv: An existing connection was forcibly closed". Treat "closed before
// both bytes arrived" as a rejected exchange — that is what the close means, and
// asserting on the reply byte would be asserting on scheduling.
func (c *socksClient) readAuthReply() (byte, bool) {
	c.t.Helper()
	var reply [2]byte
	n, err := io.ReadFull(c.conn, reply[:])
	if err != nil {
		if n > 0 || errors.Is(err, net.ErrClosed) || isConnReset(err) {
			return socksAuthFailure, false
		}
		c.t.Fatalf("socks5 read auth reply: %v", err)
	}
	if reply[0] != socksAuthVersion {
		c.t.Fatalf("sub-negotiation reply version 0x%02x, want 0x%02x", reply[0], socksAuthVersion)
	}
	return reply[1], true
}

// isConnReset reports whether err is the platform's "peer reset the connection".
// Windows reports WSAECONNRESET through a different type than POSIX ECONNRESET,
// so the check matches the message as a fallback.
func isConnReset(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		err = opErr.Err
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "forcibly closed") || strings.Contains(message, "connection reset")
}

func (c *socksClient) readByte() byte {
	c.t.Helper()
	return c.read(1)[0]
}

// readMethod reads the two-byte method-selection reply (VER, METHOD).
func (c *socksClient) readMethod() byte {
	c.t.Helper()
	reply := c.read(2)
	if reply[0] != socksVersion {
		c.t.Fatalf("method reply version 0x%02x, want 0x%02x", reply[0], socksVersion)
	}
	return reply[1]
}

func (c *socksClient) negotiate(methods ...byte) byte {
	c.t.Helper()
	c.write(append([]byte{socksVersion, byte(len(methods))}, methods...))
	return c.readMethod()
}

func (c *socksClient) negotiateRaw(head []byte, methods []byte) byte {
	c.t.Helper()
	c.write(append(append([]byte(nil), head...), methods...))
	return c.readMethod()
}

// authenticateRaw writes one raw RFC 1929 sub-negotiation request and reads the
// complete two-byte VER/STATUS reply, returning the STATUS byte. Reading only
// one byte would return VER (always 0x01, which coincides with the failure code)
// and leave STATUS in the stream to corrupt the next read.
func (c *socksClient) authenticateRaw(payload []byte) byte {
	c.t.Helper()
	c.write(payload)
	status, _ := c.readAuthReply()
	return status
}

func (c *socksClient) authenticate(username, password string) byte {
	c.t.Helper()
	payload := []byte{socksAuthVersion, byte(len(username))}
	payload = append(payload, username...)
	payload = append(payload, byte(len(password)))
	payload = append(payload, password...)
	return c.authenticateRaw(payload)
}

func (c *socksClient) login() {
	c.t.Helper()
	if method := c.negotiate(socksMethodNoAuth, socksMethodUserPass); method != socksMethodUserPass {
		c.t.Fatalf("negotiated method 0x%02x, want username/password", method)
	}
	if status := c.authenticate("proxy-user", "proxy-pass"); status != socksAuthSuccess {
		c.t.Fatalf("authentication status 0x%02x, want success", status)
	}
}

type socksReply struct {
	reply       byte
	addressType byte
	host        string
	port        int
}

func (c *socksClient) readReply() socksReply {
	c.t.Helper()
	head := c.read(3)
	if head[0] != socksVersion || head[2] != 0x00 {
		c.t.Fatalf("malformed SOCKS5 reply header %v", head)
	}
	reply := socksReply{reply: head[1], addressType: c.readByte()}
	switch reply.addressType {
	case socksAddressIPv4:
		reply.host = net.IP(c.read(4)).String()
	case socksAddressDomain:
		reply.host = string(c.read(int(c.readByte())))
	case socksAddressIPv6:
		reply.host = net.IP(c.read(16)).String()
	default:
		c.t.Fatalf("unexpected bound address type 0x%02x", reply.addressType)
	}
	rawPort := c.read(2)
	reply.port = int(rawPort[0])<<8 | int(rawPort[1])
	return reply
}

func (c *socksClient) connect(addressType byte, host []byte, port int) socksReply {
	c.t.Helper()
	request := []byte{socksVersion, socksCommandConnect, 0x00, addressType}
	if addressType == socksAddressDomain {
		request = append(request, byte(len(host)))
	}
	request = append(request, host...)
	request = append(request, byte(port>>8), byte(port))
	c.write(request)
	return c.readReply()
}

func (c *socksClient) connectRaw(payload []byte) socksReply {
	c.t.Helper()
	c.write(payload)
	return c.readReply()
}

func (c *socksClient) expectClosed() {
	c.t.Helper()
	expectConnClosed(c.t, c.conn, c.conn)
}

func ipv4Bytes(t *testing.T, address string) []byte {
	t.Helper()
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split target address %q: %v", address, err)
	}
	parsed := net.ParseIP(host).To4()
	if parsed == nil {
		t.Fatalf("target %q is not an IPv4 address", address)
	}
	return parsed
}

func portOf(t *testing.T, address string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split target address %q: %v", address, err)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse target port %q: %v", port, err)
	}
	return number
}

// --- HTTP proxy client helpers ---------------------------------------------

type httpProxyClient struct {
	t      *testing.T
	conn   net.Conn
	reader *bufio.Reader
}

func dialHTTPProxy(t *testing.T, proxy net.Addr) *httpProxyClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy.String(), testTimeout)
	if err != nil {
		t.Fatalf("dial http proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(testTimeout))
	t.Cleanup(func() { _ = conn.Close() })
	return &httpProxyClient{t: t, conn: conn, reader: bufio.NewReader(conn)}
}

func (c *httpProxyClient) writeRequest(lines ...string) {
	c.t.Helper()
	payload := strings.Join(lines, "\r\n") + "\r\n\r\n"
	if _, err := io.WriteString(c.conn, payload); err != nil {
		c.t.Fatalf("http proxy write: %v", err)
	}
}

func (c *httpProxyClient) readResponse() (int, http.Header) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(testTimeout))
	statusLine, err := c.reader.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read status line: %v", err)
	}
	fields := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(fields) < 2 {
		c.t.Fatalf("malformed status line %q", statusLine)
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		c.t.Fatalf("malformed status line %q", statusLine)
	}
	header := http.Header{}
	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read response header: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			c.t.Fatalf("malformed response header %q", line)
		}
		header.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	return status, header
}

func (c *httpProxyClient) connectLines(authority string, headers ...string) []string {
	lines := []string{"CONNECT " + authority + " HTTP/1.1", "Host: " + authority}
	return append(lines, headers...)
}

func basicValue(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

func (c *httpProxyClient) expectClosed() {
	c.t.Helper()
	expectConnClosed(c.t, c.conn, c.reader)
}

// --- SOCKS5 behaviour ------------------------------------------------------

func TestSOCKS5ConnectIPv4EndToEnd(t *testing.T) {
	echo := startEchoServer(t)
	dialer := newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var direct net.Dialer
		return direct.DialContext(ctx, network, address)
	})
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})

	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()
	reply := client.connect(socksAddressIPv4, ipv4Bytes(t, echo.String()), portOf(t, echo.String()))
	if reply.reply != socksReplySucceeded {
		t.Fatalf("CONNECT reply 0x%02x, want success", reply.reply)
	}
	if reply.addressType != socksAddressIPv4 || reply.port == 0 {
		t.Fatalf("bound endpoint %s:%d, want a usable IPv4 endpoint", reply.host, reply.port)
	}
	if calls := dialer.recorded(); len(calls) != 1 || calls[0] != "tcp "+echo.String() {
		t.Fatalf("dialer calls %v, want [tcp %s]", calls, echo.String())
	}
	tunnelEcho(t, client.conn, client.conn, "hello through the socks5 tunnel")
	tunnelEcho(t, client.conn, client.conn, "second round trip")

	stats := agent.Stats()
	if stats.Accepted != 1 || stats.AuthFailures != 0 || stats.DialFailures != 0 || stats.Unsupported != 0 {
		t.Fatalf("unexpected stats %+v", stats)
	}
}

func TestSOCKS5MethodNegotiation(t *testing.T) {
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})

	cases := []struct {
		name    string
		methods []byte
		want    byte
	}{
		{name: "only no-auth is refused", methods: []byte{socksMethodNoAuth}, want: socksMethodNoAcceptable},
		{name: "no-auth and user-pass chooses user-pass", methods: []byte{socksMethodNoAuth, socksMethodUserPass}, want: socksMethodUserPass},
		{name: "only user-pass", methods: []byte{socksMethodUserPass}, want: socksMethodUserPass},
		{name: "unsupported methods only", methods: []byte{0x01, 0x03}, want: socksMethodNoAcceptable},
	}
	refused := 0
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := dialSOCKS5(t, mustSocksAddr(t, agent))
			if method := client.negotiate(testCase.methods...); method != testCase.want {
				t.Fatalf("negotiated method 0x%02x, want 0x%02x", method, testCase.want)
			}
			if testCase.want == socksMethodNoAcceptable {
				client.expectClosed()
			}
		})
		if testCase.want == socksMethodNoAcceptable {
			refused++
		}
	}
	waitFor(t, func() bool { return agent.Stats().AuthFailures == uint64(refused) }, "refused negotiations counted")
	if calls := dialer.recorded(); len(calls) != 0 {
		t.Fatalf("dialer was called without a request: %v", calls)
	}
}

func TestSOCKS5AuthRejections(t *testing.T) {
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})

	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "wrong password", payload: []byte{socksAuthVersion, 10, 'p', 'r', 'o', 'x', 'y', '-', 'u', 's', 'e', 'r', 9, 'w', 'r', 'o', 'n', 'g', '-', 'p', 'a', 's', 's'}},
		{name: "wrong username", payload: []byte{socksAuthVersion, 9, 'o', 't', 'h', 'e', 'r', '-', 'u', 's', 'r', 10, 'p', 'r', 'o', 'x', 'y', '-', 'p', 'a', 's', 's'}},
		{name: "case sensitive username", payload: []byte{socksAuthVersion, 10, 'P', 'r', 'o', 'x', 'y', '-', 'u', 's', 'e', 'r', 10, 'p', 'r', 'o', 'x', 'y', '-', 'p', 'a', 's', 's'}},
		{name: "trailing space in password", payload: []byte{socksAuthVersion, 10, 'p', 'r', 'o', 'x', 'y', '-', 'u', 's', 'e', 'r', 11, 'p', 'r', 'o', 'x', 'y', '-', 'p', 'a', 's', 's', ' '}},
		{name: "sub-negotiation version mismatch", payload: []byte{0x02, 10, 'p', 'r', 'o', 'x', 'y', '-', 'u', 's', 'e', 'r', 10, 'p', 'r', 'o', 'x', 'y', '-', 'p', 'a', 's', 's'}},
		{name: "empty username", payload: []byte{socksAuthVersion, 0, 10, 'p', 'r', 'o', 'x', 'y', '-', 'p', 'a', 's', 's'}},
		{name: "empty password", payload: []byte{socksAuthVersion, 10, 'p', 'r', 'o', 'x', 'y', '-', 'u', 's', 'e', 'r', 0}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := dialSOCKS5(t, mustSocksAddr(t, agent))
			if method := client.negotiate(socksMethodUserPass); method != socksMethodUserPass {
				t.Fatalf("negotiated method 0x%02x, want username/password", method)
			}
			if status := client.authenticateRaw(testCase.payload); status != socksAuthFailure {
				t.Fatalf("authentication status 0x%02x, want 0x%02x", status, socksAuthFailure)
			}
			client.expectClosed()
		})
	}
	waitFor(t, func() bool { return agent.Stats().AuthFailures == uint64(len(cases)) }, "authentication failures counted")
	if calls := dialer.recorded(); len(calls) != 0 {
		t.Fatalf("dialer was called despite failed authentication: %v", calls)
	}
}

func TestSOCKS5AcceptsExactCredentials(t *testing.T) {
	config := ProxyConfig{Listen: "127.0.0.1:1080", Username: "user:name", Password: "p:a:ss"}
	agent := newTestAgent(t, AgentConfig{Inbounds: Inbounds{SOCKS5: &config}}, Deps{Dialer: newScriptedDialer(nil)})

	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	if method := client.negotiate(socksMethodNoAuth, socksMethodUserPass); method != socksMethodUserPass {
		t.Fatalf("negotiated method 0x%02x, want username/password", method)
	}
	if status := client.authenticate("user:name", "p:a:ss"); status != socksAuthSuccess {
		t.Fatalf("authentication status 0x%02x, want success", status)
	}
}

func TestSOCKS5DomainTargetPassthrough(t *testing.T) {
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})

	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()
	reply := client.connect(socksAddressDomain, []byte("example.test"), 8443)
	if reply.reply != socksReplySucceeded {
		t.Fatalf("CONNECT reply 0x%02x, want success", reply.reply)
	}
	// A net.Pipe reports no parseable local address, so the reply falls back to
	// the RFC 1928 placeholder endpoint instead of inventing one.
	if reply.addressType != socksAddressIPv4 || reply.host != "0.0.0.0" || reply.port != 0 {
		t.Fatalf("bound endpoint %s:%d, want the 0.0.0.0:0 fallback", reply.host, reply.port)
	}
	if calls := dialer.recorded(); len(calls) != 1 || calls[0] != "tcp example.test:8443" {
		t.Fatalf("dialer calls %v, want [tcp example.test:8443]; name resolution belongs to the Dialer", calls)
	}
	peer := dialer.peer(t)
	defer peer.Close()

	// The Dialer returned one end of a net.Pipe and the test holds the other, so
	// this test plays the target: a payload written by the client must arrive
	// unchanged on the peer end. Nothing here may call tunnelEcho, because a
	// proxy relays and never echoes on its own.
	payload := "domain target round trip"
	if _, err := client.conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	forwarded := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, forwarded); err != nil {
		t.Fatalf("read at the target side: %v", err)
	}
	if string(forwarded) != payload {
		t.Fatalf("target side received %q, want %q", forwarded, payload)
	}

	_ = client.conn.SetReadDeadline(time.Now().Add(testTimeout))
	if _, err := peer.Write([]byte("pong")); err != nil {
		t.Fatalf("write from the target side: %v", err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(client.conn, echo); err != nil {
		t.Fatalf("read from the target side: %v", err)
	}
	if string(echo) != "pong" {
		t.Fatalf("target side delivered %q, want %q", echo, "pong")
	}
}

func TestSOCKS5RejectsIPv6AndUnknownAddressTypes(t *testing.T) {
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})

	ipv6 := net.ParseIP("2001:db8::1").To16()
	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()
	if reply := client.connect(socksAddressIPv6, ipv6, 443); reply.reply != socksReplyAddressTypeNotSupported {
		t.Fatalf("IPv6 CONNECT reply 0x%02x, want 0x%02x", reply.reply, socksReplyAddressTypeNotSupported)
	}
	client.expectClosed()

	client = dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()
	if reply := client.connect(socksAddressDomain, []byte("::1"), 443); reply.reply != socksReplyAddressTypeNotSupported {
		t.Fatalf("IPv6-as-domain CONNECT reply 0x%02x, want 0x%02x", reply.reply, socksReplyAddressTypeNotSupported)
	}
	client.expectClosed()

	client = dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()
	if reply := client.connectRaw([]byte{socksVersion, socksCommandConnect, 0x00, 0x09, 0x00, 0x50}); reply.reply != socksReplyAddressTypeNotSupported {
		t.Fatalf("unknown ATYP reply 0x%02x, want 0x%02x", reply.reply, socksReplyAddressTypeNotSupported)
	}
	client.expectClosed()

	waitFor(t, func() bool { return agent.Stats().Unsupported == 3 }, "unsupported address types counted")
	if calls := dialer.recorded(); len(calls) != 0 {
		t.Fatalf("dialer was called for a refused address type: %v", calls)
	}
}

func TestSOCKS5UnsupportedCommands(t *testing.T) {
	// BIND is never implemented. UDP ASSOCIATE is reachable and is reported as
	// unsupported here only because this entry has no DatagramBackend; the wired
	// association path is covered in proxy_protocol_test.go.
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})

	for _, command := range []byte{socksCommandBind, socksCommandUDPAssociate, 0x09} {
		client := dialSOCKS5(t, mustSocksAddr(t, agent))
		client.login()
		reply := client.connectRaw([]byte{socksVersion, command, 0x00, socksAddressIPv4, 127, 0, 0, 1, 0x00, 0x50})
		if reply.reply != socksReplyCommandNotSupported {
			t.Fatalf("command 0x%02x reply 0x%02x, want 0x%02x", command, reply.reply, socksReplyCommandNotSupported)
		}
		client.expectClosed()
	}
	waitFor(t, func() bool { return agent.Stats().Unsupported == 3 }, "unsupported commands counted")
	if calls := dialer.recorded(); len(calls) != 0 {
		t.Fatalf("dialer was called for an unsupported command: %v", calls)
	}
}

func TestSOCKS5MalformedRequests(t *testing.T) {
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})

	cases := []struct {
		name      string
		negotiate []byte
		request   []byte
		reply     byte
		silent    bool
	}{
		{
			name:      "wrong version is closed without a reply",
			negotiate: []byte{0x04, 1, socksMethodUserPass},
			silent:    true,
		},
		{
			name:      "zero methods is closed without a reply",
			negotiate: []byte{socksVersion, 0},
			silent:    true,
		},
		{
			name:    "reserved byte set",
			request: []byte{socksVersion, socksCommandConnect, 0x01, socksAddressIPv4, 127, 0, 0, 1, 0x00, 0x50},
			reply:   socksReplyGeneralFailure,
		},
		{
			name:    "wrong request version is closed without a reply",
			request: []byte{0x04, socksCommandConnect, 0x00, socksAddressIPv4, 127, 0, 0, 1, 0x00, 0x50},
			silent:  true,
		},
		{
			name:    "empty domain name",
			request: []byte{socksVersion, socksCommandConnect, 0x00, socksAddressDomain, 0x00, 0x00, 0x50},
			reply:   socksReplyGeneralFailure,
		},
		{
			name:    "non printable domain name",
			request: []byte{socksVersion, socksCommandConnect, 0x00, socksAddressDomain, 0x03, 'a', 0x00, 'b', 0x00, 0x50},
			reply:   socksReplyGeneralFailure,
		},
		{
			name:    "port zero",
			request: []byte{socksVersion, socksCommandConnect, 0x00, socksAddressIPv4, 127, 0, 0, 1, 0x00, 0x00},
			reply:   socksReplyGeneralFailure,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := dialSOCKS5(t, mustSocksAddr(t, agent))
			if testCase.negotiate != nil {
				client.write(testCase.negotiate)
			} else {
				if method := client.negotiate(socksMethodUserPass); method != socksMethodUserPass {
					t.Fatalf("negotiated method 0x%02x, want username/password", method)
				}
				if status := client.authenticate("proxy-user", "proxy-pass"); status != socksAuthSuccess {
					t.Fatalf("authentication status 0x%02x, want success", status)
				}
			}
			if testCase.request != nil {
				client.write(testCase.request)
			}
			if testCase.silent {
				client.expectClosed()
				return
			}
			if reply := client.readReply(); reply.reply != testCase.reply {
				t.Fatalf("reply 0x%02x, want 0x%02x", reply.reply, testCase.reply)
			}
			client.expectClosed()
		})
	}
	if calls := dialer.recorded(); len(calls) != 0 {
		t.Fatalf("dialer was called for a malformed request: %v", calls)
	}
	stats := agent.Stats()
	if stats.Unsupported != 0 {
		t.Fatalf("malformed requests must not be counted as unsupported: %+v", stats)
	}
}

func TestSOCKS5HandshakeDeadline(t *testing.T) {
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{HandshakeTimeout: 200 * time.Millisecond}), Deps{Dialer: dialer})
	proxy := mustSocksAddr(t, agent)

	t.Run("silent client", func(t *testing.T) {
		client := dialSOCKS5(t, proxy)
		start := time.Now()
		client.expectClosed()
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("silent client was held for %s, want a bounded handshake", elapsed)
		}
	})

	t.Run("truncated credentials", func(t *testing.T) {
		client := dialSOCKS5(t, proxy)
		client.write([]byte{socksVersion, 1, socksMethodUserPass})
		if method := client.readMethod(); method != socksMethodUserPass {
			t.Fatalf("negotiated method 0x%02x, want username/password", method)
		}
		client.write([]byte{socksAuthVersion, 10, 'p', 'r', 'o', 'x', 'y'})
		start := time.Now()
		client.expectClosed()
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("truncated credentials were held for %s, want a bounded handshake", elapsed)
		}
	})
}

func TestSOCKS5DialDeadline(t *testing.T) {
	var (
		mu              sync.Mutex
		observedTimeout time.Duration
		sawDeadline     bool
	)
	dialer := newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		mu.Lock()
		sawDeadline = ok
		if ok {
			observedTimeout = time.Until(deadline)
		}
		mu.Unlock()
		if !ok {
			return nil, errors.New("dial context has no deadline")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{DialTimeout: 200 * time.Millisecond}), Deps{Dialer: dialer})

	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()
	reply := client.connect(socksAddressIPv4, []byte{127, 0, 0, 1}, 9)
	if reply.reply != socksReplyHostUnreachable {
		t.Fatalf("CONNECT reply 0x%02x, want host unreachable for a dial timeout", reply.reply)
	}
	client.expectClosed()

	mu.Lock()
	defer mu.Unlock()
	if !sawDeadline {
		t.Fatal("the Dialer received no deadline")
	}
	if observedTimeout > time.Second {
		t.Fatalf("dial deadline %s is not bounded by the configured 200ms", observedTimeout)
	}
	waitFor(t, func() bool { return agent.Stats().DialFailures == 1 }, "dial failure counted")
}

func TestSOCKS5DialCancelledByAgentClose(t *testing.T) {
	entered := make(chan struct{})
	once := sync.Once{}
	dialErr := make(chan error, 1)
	dialer := newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		dialErr <- ctx.Err()
		return nil, ctx.Err()
	})
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{HandshakeTimeout: 30 * time.Second}), Deps{Dialer: dialer})

	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()
	client.write([]byte{socksVersion, socksCommandConnect, 0x00, socksAddressIPv4, 127, 0, 0, 1, 0x00, 0x50})
	select {
	case <-entered:
	case <-time.After(testTimeout):
		t.Fatal("the Dialer was not called")
	}

	closed := make(chan error, 1)
	go func() { closed <- agent.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Close did not return while a dial was blocked")
	}
	select {
	case err := <-dialErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial error %v, want context.Canceled", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("the blocked dial was not cancelled by Close")
	}
	// Close cancels the dial and closes the admitted connection at the same
	// time, so the handler's final "general failure" reply may or may not make
	// it onto the wire before the teardown. Only a connection left open fails.
	expectConnDrained(t, client.conn, client.conn)
}

func TestSOCKS5DialFailureReply(t *testing.T) {
	dialer := newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, syscall.ECONNREFUSED
	})
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})

	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	client.login()
	reply := client.connect(socksAddressIPv4, []byte{127, 0, 0, 1}, 9)
	if reply.reply != socksReplyConnectionRefused {
		t.Fatalf("CONNECT reply 0x%02x, want connection refused", reply.reply)
	}
	client.expectClosed()
	waitFor(t, func() bool { return agent.Stats().DialFailures == 1 }, "dial failure counted")
}

func TestSOCKS5ConnectionLimit(t *testing.T) {
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{MaxConnections: 1, HandshakeTimeout: 30 * time.Second}), Deps{Dialer: dialer})
	proxy := mustSocksAddr(t, agent)

	first := dialSOCKS5(t, proxy)
	waitFor(t, func() bool { return agent.Stats().Active == 1 }, "first connection admitted")

	second := dialSOCKS5(t, proxy)
	second.expectClosed()
	waitFor(t, func() bool { return agent.Stats().Rejected == 1 }, "over-limit connection rejected")

	_ = first.conn.Close()
	waitFor(t, func() bool { return agent.Stats().Active == 0 }, "released slot")

	third := dialSOCKS5(t, proxy)
	if method := third.negotiate(socksMethodUserPass); method != socksMethodUserPass {
		t.Fatalf("negotiated method 0x%02x after the slot was released, want username/password", method)
	}
}

// --- HTTP CONNECT behaviour ------------------------------------------------

func TestHTTPConnectEndToEnd(t *testing.T) {
	echo := startEchoServer(t)
	dialer := newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var direct net.Dialer
		return direct.DialContext(ctx, network, address)
	})
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})

	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))
	client.writeRequest(client.connectLines(echo.String(), "Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"))...)
	status, header := client.readResponse()
	if status != http.StatusOK {
		t.Fatalf("CONNECT status %d, want 200", status)
	}
	if header.Get("Content-Length") != "" {
		t.Fatalf("tunnel response must not announce a body: %v", header)
	}
	if calls := dialer.recorded(); len(calls) != 1 || calls[0] != "tcp "+echo.String() {
		t.Fatalf("dialer calls %v, want [tcp %s]", calls, echo.String())
	}
	tunnelEcho(t, client.conn, client.reader, "hello through the http tunnel")

	stats := agent.Stats()
	if stats.Accepted != 1 || stats.AuthFailures != 0 || stats.DialFailures != 0 {
		t.Fatalf("unexpected stats %+v", stats)
	}
}

func TestHTTPConnectAuthentication(t *testing.T) {
	config := ProxyConfig{Listen: "127.0.0.1:8080", Username: "user", Password: "p:ass"}
	agent := newTestAgent(t, AgentConfig{Inbounds: Inbounds{HTTPProxy: &config}}, Deps{Dialer: newScriptedDialer(nil)})
	proxy := mustHTTPAddr(t, agent)
	rejected := 0

	cases := []struct {
		name   string
		header string
	}{
		{name: "missing header", header: ""},
		{name: "wrong password", header: "Proxy-Authorization: " + basicValue("user", "wrong")},
		{name: "wrong username", header: "Proxy-Authorization: " + basicValue("other", "p:ass")},
		{name: "wrong scheme", header: "Proxy-Authorization: Bearer dXNlcjpwYXNz"},
		{name: "invalid base64", header: "Proxy-Authorization: Basic !!!not-base64!!!"},
		{name: "missing colon", header: "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("user"))},
		{name: "empty username", header: "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(":p:ass"))},
		{name: "oversized credentials", header: "Proxy-Authorization: Basic " + strings.Repeat("A", maxProxyAuthorizationBytes+16)},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			client := dialHTTPProxy(t, proxy)
			lines := client.connectLines("example.test:443")
			if testCase.header != "" {
				lines = append(lines, testCase.header)
			}
			client.writeRequest(lines...)
			status, header := client.readResponse()
			if status != http.StatusProxyAuthRequired {
				t.Fatalf("status %d, want 407", status)
			}
			if !strings.HasPrefix(header.Get("Proxy-Authenticate"), "Basic ") {
				t.Fatalf("Proxy-Authenticate %q, want a Basic challenge", header.Get("Proxy-Authenticate"))
			}
			client.expectClosed()
		})
		rejected++
	}
	waitFor(t, func() bool { return agent.Stats().AuthFailures == uint64(rejected) }, "authentication failures counted")

	// A password containing a colon is transmitted intact: only the first colon
	// separates the user from the password.
	client := dialHTTPProxy(t, proxy)
	client.writeRequest(client.connectLines("example.test:443", "Proxy-Authorization: "+basicValue("user", "p:ass"))...)
	if status, _ := client.readResponse(); status == http.StatusProxyAuthRequired {
		t.Fatal("valid credentials with a colon in the password were rejected")
	}
}

// TestHTTPForwardRejectsNonHTTPOrigin pins the boundary of the normal forward
// path: a request whose target form needs another scheme (or CONNECT) is refused
// with a bounded 400 before any dial, and the old blanket 405 is gone. The
// successful http absolute-form and origin-form paths are covered by
// proxy_protocol_test.go.
func TestHTTPForwardRejectsNonHTTPOrigin(t *testing.T) {
	dialer := newScriptedDialer(nil)
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))
	client.writeRequest(
		"GET ftp://example.test/file HTTP/1.1",
		"Host: example.test",
		"Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"),
	)
	status, _ := client.readResponse()
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for a non-http origin", status)
	}
	client.expectClosed()
	if calls := dialer.recorded(); len(calls) != 0 {
		t.Fatalf("dialer was called for a non-http origin: %v", calls)
	}
}

func TestHTTPConnectWithRequestBody(t *testing.T) {
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: newScriptedDialer(nil)})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))
	client.writeRequest(
		"CONNECT example.test:443 HTTP/1.1",
		"Host: example.test:443",
		"Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"),
		"Content-Length: 4",
	)
	status, _ := client.readResponse()
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for a CONNECT request with a body", status)
	}
	client.expectClosed()
}

func TestHTTPConnectTargetValidation(t *testing.T) {
	// The Dialer refuses every target, so a well-formed authority is observable
	// as a 502 while refused authorities never reach the Dialer at all.
	dialer := newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, syscall.ECONNREFUSED
	})
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})
	proxy := mustHTTPAddr(t, agent)

	cases := []struct {
		name      string
		authority string
		want      int
	}{
		{name: "missing port", authority: "example.test", want: http.StatusBadRequest},
		{name: "empty host", authority: ":443", want: http.StatusBadRequest},
		{name: "port zero", authority: "example.test:0", want: http.StatusBadRequest},
		{name: "non numeric port", authority: "example.test:https", want: http.StatusBadRequest},
		{name: "out of range port", authority: "example.test:70000", want: http.StatusBadRequest},
		{name: "ipv4 literal", authority: "127.0.0.1:9", want: http.StatusBadGateway},
		{name: "ipv6 literal", authority: "[::1]:443", want: http.StatusForbidden},
		{name: "ipv6 literal with port", authority: "[2001:db8::1]:8443", want: http.StatusForbidden},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			before := len(dialer.recorded())
			client := dialHTTPProxy(t, proxy)
			client.writeRequest(client.connectLines(testCase.authority, "Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"))...)
			status, _ := client.readResponse()
			if status != testCase.want {
				t.Fatalf("status %d, want %d", status, testCase.want)
			}
			client.expectClosed()
			after := len(dialer.recorded())
			switch testCase.want {
			case http.StatusForbidden, http.StatusBadRequest:
				if after != before {
					t.Fatalf("dialer was called for a refused target %q", testCase.authority)
				}
			}
		})
	}
}

func TestHTTPConnectDialFailure(t *testing.T) {
	dialer := newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, syscall.ECONNREFUSED
	})
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{DialTimeout: time.Second}), Deps{Dialer: dialer})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))
	client.writeRequest(client.connectLines("127.0.0.1:9", "Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass"))...)
	status, _ := client.readResponse()
	if status != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", status)
	}
	client.expectClosed()
	waitFor(t, func() bool { return agent.Stats().DialFailures == 1 }, "dial failure counted")
}

func TestHTTPConnectForwardPipelinedData(t *testing.T) {
	echo := startEchoServer(t)
	dialer := newScriptedDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var direct net.Dialer
		return direct.DialContext(ctx, network, address)
	})
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: dialer})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))

	payload := "pipelined-payload"
	request := strings.Join(client.connectLines(echo.String(), "Proxy-Authorization: "+basicValue("proxy-user", "proxy-pass")), "\r\n") + "\r\n\r\n" + payload
	if _, err := io.WriteString(client.conn, request); err != nil {
		t.Fatalf("write CONNECT plus payload: %v", err)
	}
	status, _ := client.readResponse()
	if status != http.StatusOK {
		t.Fatalf("CONNECT status %d, want 200", status)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(client.reader, echoed); err != nil {
		t.Fatalf("read pipelined echo: %v", err)
	}
	if string(echoed) != payload {
		t.Fatalf("pipelined payload echoed as %q, want %q", echoed, payload)
	}
}

func TestHTTPConnectOversizeHeader(t *testing.T) {
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{}), Deps{Dialer: newScriptedDialer(nil)})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))

	var builder strings.Builder
	builder.WriteString("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nX-Filler: ")
	builder.WriteString(strings.Repeat("a", maxHTTPRequestBytes+1024))
	builder.WriteString("\r\n\r\n")
	// The proxy stops reading at the header limit; write from a goroutine so the
	// client can read the bounded response without waiting for the whole write.
	go func() { _, _ = io.WriteString(client.conn, builder.String()) }()

	status, _ := client.readResponse()
	if status != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status %d, want 431 for an oversized header block", status)
	}
}

func TestHTTPConnectHandshakeDeadline(t *testing.T) {
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{HandshakeTimeout: 200 * time.Millisecond}), Deps{Dialer: newScriptedDialer(nil)})
	client := dialHTTPProxy(t, mustHTTPAddr(t, agent))
	start := time.Now()
	// A client that never finishes the request head gets the bounded 400 answer
	// and is then closed; it must not hold the admission slot.
	status, _ := client.readResponse()
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for an incomplete request head", status)
	}
	client.expectClosed()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("silent client was held for %s, want a bounded handshake", elapsed)
	}
}

func TestHTTPConnectionLimitReplies503(t *testing.T) {
	agent := newTestAgent(t, httpAgentConfig(ProxyOptions{MaxConnections: 1, HandshakeTimeout: 30 * time.Second}), Deps{Dialer: newScriptedDialer(nil)})
	proxy := mustHTTPAddr(t, agent)

	first := dialHTTPProxy(t, proxy)
	waitFor(t, func() bool { return agent.Stats().Active == 1 }, "first connection admitted")

	second := dialHTTPProxy(t, proxy)
	status, _ := second.readResponse()
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 for an over-limit connection", status)
	}
	second.expectClosed()

	_ = first.conn.Close()
	waitFor(t, func() bool { return agent.Stats().Active == 0 }, "released slot")
}

// --- Agent lifecycle -------------------------------------------------------

func TestAgentLifecycleAndIdempotentClose(t *testing.T) {
	agent, err := New(socksAgentConfig(ProxyOptions{}), Deps{Dialer: newScriptedDialer(nil), Listen: testListenFunc()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := agent.Start(context.Background()); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start error %v, want ErrAlreadyStarted", err)
	}
	if socks5, _ := agent.ListenAddrs(); socks5 == nil {
		t.Fatal("socks5 listener address is missing after Start")
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-agent.Done():
	default:
		t.Fatal("Done was not closed by Close")
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("second Close error %v, want the same idempotent result", err)
	}
	if err := agent.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close error %v, want ErrClosed", err)
	}
}

func TestAgentCloseBeforeStart(t *testing.T) {
	agent, err := New(socksAgentConfig(ProxyOptions{}), Deps{Dialer: newScriptedDialer(nil), Listen: testListenFunc()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
	select {
	case <-agent.Done():
	default:
		t.Fatal("Done was not closed by Close before Start")
	}
	if err := agent.Start(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close error %v, want ErrClosed", err)
	}
}

func TestAgentConcurrentClose(t *testing.T) {
	agent := newTestAgent(t, socksAgentConfig(ProxyOptions{HandshakeTimeout: 30 * time.Second}), Deps{Dialer: newScriptedDialer(nil)})
	client := dialSOCKS5(t, mustSocksAddr(t, agent))
	waitFor(t, func() bool { return agent.Stats().Active == 1 }, "connection admitted")

	const closers = 8
	results := make([]error, closers)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for index := 0; index < closers; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			results[index] = agent.Close()
		}(index)
	}
	close(start)
	finished := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(testTimeout):
		t.Fatal("concurrent Close calls did not return")
	}
	for index, err := range results {
		if err != nil {
			t.Fatalf("Close %d returned %v, want nil", index, err)
		}
	}
	select {
	case <-agent.Done():
	default:
		t.Fatal("Done was not closed")
	}
	expectConnClosed(t, client.conn, client.conn)
}

func TestAgentStartBindFailureRollsBack(t *testing.T) {
	var (
		mu       sync.Mutex
		bound    net.Listener
		attempts int
	)
	deps := Deps{
		Dialer: newScriptedDialer(nil),
		Listen: func(ctx context.Context, network, address string) (net.Listener, error) {
			mu.Lock()
			defer mu.Unlock()
			attempts++
			if attempts == 1 {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				bound = listener
				return listener, err
			}
			return nil, errors.New("bind refused by the test")
		},
	}
	socks5 := socksProxyConfig(ProxyOptions{})
	httpProxy := httpProxyConfig(ProxyOptions{})
	config := AgentConfig{Inbounds: Inbounds{SOCKS5: &socks5, HTTPProxy: &httpProxy}}
	agent, err := New(config, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Start(context.Background()); err == nil {
		t.Fatal("Start succeeded although the second inbound could not bind")
	}
	mu.Lock()
	listener := bound
	mu.Unlock()
	if listener == nil {
		t.Fatal("the first inbound was never bound")
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("first listener was left open after the rollback: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("Close after a failed Start: %v", err)
	}
}

func TestAgentTUNUnavailablePlatformFailsBeforeBinding(t *testing.T) {
	var foreign []Platform
	for _, platform := range []Platform{PlatformLinux, PlatformWindows, PlatformDarwin} {
		if platform != CurrentPlatform() {
			foreign = append(foreign, platform)
		}
	}
	for _, platform := range foreign {
		t.Run(string(platform), func(t *testing.T) {
			listenCalls := 0
			deps := Deps{
				Dialer: newScriptedDialer(nil),
				Listen: func(ctx context.Context, network, address string) (net.Listener, error) {
					listenCalls++
					var config net.ListenConfig
					return config.Listen(ctx, "tcp", "127.0.0.1:0")
				},
			}
			config := AgentConfig{Inbounds: Inbounds{TUN: boolPointer(true)}, Platform: platform}
			agent, err := New(config, deps)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			err = agent.Start(context.Background())
			if !errors.Is(err, ErrPlatformUnavailable) {
				t.Fatalf("Start error %v, want ErrPlatformUnavailable", err)
			}
			if !strings.Contains(err.Error(), "build") {
				t.Fatalf("Start error %q must name the required GOOS build", err)
			}
			if listenCalls != 0 {
				t.Fatal("Start bound a listener before resolving the TUN backend")
			}
			if err := agent.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		})
	}
	if _, err := ResolveHostAdapter("plan9"); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("ResolveHostAdapter(plan9) error %v, want ErrPlatformUnavailable", err)
	}
}

func TestAgentTUNDisabledStartsWithoutDevice(t *testing.T) {
	agent := newTestAgent(t, AgentConfig{Inbounds: Inbounds{TUN: boolPointer(false)}}, Deps{})
	socks5, httpProxy := agent.ListenAddrs()
	if socks5 != nil || httpProxy != nil {
		t.Fatalf("no listener was expected, got %v and %v", socks5, httpProxy)
	}
	if stats := agent.Stats(); stats != (Stats{}) {
		t.Fatalf("unexpected stats without inbounds: %+v", stats)
	}
}

func TestAgentNoInbounds(t *testing.T) {
	agent, err := New(AgentConfig{}, Deps{})
	if err != nil {
		t.Fatalf("New without inbounds: %v", err)
	}
	if err := agent.Start(context.Background()); err != nil {
		t.Fatalf("Start without inbounds: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("Close without inbounds: %v", err)
	}
}

func TestAgentPerEntryCredentials(t *testing.T) {
	socks5 := ProxyConfig{Listen: "127.0.0.1:1080", Username: "socks-user", Password: "socks-pass"}
	httpProxy := ProxyConfig{Listen: "127.0.0.1:8080", Username: "http-user", Password: "http-pass"}
	config := AgentConfig{Inbounds: Inbounds{SOCKS5: &socks5, HTTPProxy: &httpProxy}}
	agent := newTestAgent(t, config, Deps{Dialer: newScriptedDialer(nil)})

	socksClient := dialSOCKS5(t, mustSocksAddr(t, agent))
	if method := socksClient.negotiate(socksMethodUserPass); method != socksMethodUserPass {
		t.Fatalf("negotiated method 0x%02x, want username/password", method)
	}
	if status := socksClient.authenticate("http-user", "http-pass"); status != socksAuthFailure {
		t.Fatalf("the HTTP entry credential was accepted by the SOCKS5 entry (status 0x%02x)", status)
	}
	socksClient.expectClosed()

	httpClient := dialHTTPProxy(t, mustHTTPAddr(t, agent))
	httpClient.writeRequest(httpClient.connectLines("example.test:443", "Proxy-Authorization: "+basicValue("socks-user", "socks-pass"))...)
	if status, _ := httpClient.readResponse(); status != http.StatusProxyAuthRequired {
		t.Fatalf("status %d, want 407: credentials are per entry", status)
	}
	httpClient.expectClosed()
}

// --- typed configuration ---------------------------------------------------

func TestAgentConfigValidation(t *testing.T) {
	validSocks5 := socksProxyConfig(ProxyOptions{})
	validHTTP := httpProxyConfig(ProxyOptions{})
	valid := AgentConfig{Inbounds: Inbounds{
		TUN:       boolPointer(false),
		SOCKS5:    &validSocks5,
		HTTPProxy: &validHTTP,
	}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*ProxyConfig)
	}{
		{name: "missing listen", mutate: func(config *ProxyConfig) { config.Listen = "" }},
		{name: "listen without port", mutate: func(config *ProxyConfig) { config.Listen = "127.0.0.1" }},
		{name: "empty host", mutate: func(config *ProxyConfig) { config.Listen = ":1080" }},
		{name: "non numeric port", mutate: func(config *ProxyConfig) { config.Listen = "127.0.0.1:http" }},
		{name: "out of range port", mutate: func(config *ProxyConfig) { config.Listen = "127.0.0.1:70000" }},
		{name: "missing username", mutate: func(config *ProxyConfig) { config.Username = "" }},
		{name: "missing password", mutate: func(config *ProxyConfig) { config.Password = "" }},
		{name: "oversized password", mutate: func(config *ProxyConfig) { config.Password = strings.Repeat("x", 256) }},
		{name: "connection limit above the P1 cap", mutate: func(config *ProxyConfig) { config.Options.MaxConnections = MaxProxyConnections + 1 }},
		{name: "negative connection limit", mutate: func(config *ProxyConfig) { config.Options.MaxConnections = -1 }},
		{name: "negative handshake timeout", mutate: func(config *ProxyConfig) { config.Options.HandshakeTimeout = -time.Second }},
		{name: "negative dial timeout", mutate: func(config *ProxyConfig) { config.Options.DialTimeout = -time.Second }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := socksProxyConfig(ProxyOptions{})
			testCase.mutate(&config)
			for _, kind := range []ProxyKind{ProxySOCKS5, ProxyHTTP} {
				if err := config.Validate(kind); !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("%s validation error %v, want ErrInvalidConfig", kind, err)
				}
			}
			agentConfig := AgentConfig{Inbounds: Inbounds{SOCKS5: &config}}
			if err := agentConfig.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("AgentConfig validation error %v, want ErrInvalidConfig", err)
			}
		})
	}

	t.Run("unknown platform", func(t *testing.T) {
		config := AgentConfig{Platform: "plan9"}
		if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("validation error %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("ephemeral port is allowed for embedding", func(t *testing.T) {
		config := socksProxyConfig(ProxyOptions{})
		config.Listen = "127.0.0.1:0"
		if err := config.Validate(ProxySOCKS5); err != nil {
			t.Fatalf("port 0 rejected: %v", err)
		}
		agent := newTestAgent(t, AgentConfig{Inbounds: Inbounds{SOCKS5: &config}}, Deps{Dialer: newScriptedDialer(nil)})
		if socks5, _ := agent.ListenAddrs(); socks5 == nil || socks5.String() == "" || strings.HasSuffix(socks5.String(), ":0") {
			t.Fatalf("bound address %v, want a real ephemeral port", socks5)
		}
	})
}

func TestNewRequiresDialerForProxyInbounds(t *testing.T) {
	config := socksAgentConfig(ProxyOptions{})
	if _, err := New(config, Deps{}); !errors.Is(err, ErrNoDialer) {
		t.Fatalf("New without a Dialer error %v, want ErrNoDialer", err)
	}
	tunOnly := AgentConfig{Inbounds: Inbounds{TUN: boolPointer(true)}}
	if _, err := New(tunOnly, Deps{}); err != nil {
		t.Fatalf("New with only a TUN inbound: %v", err)
	}
	// The platform is still unavailable at Start time, and that is reported
	// there rather than at construction.
	if err := tunOnly.Validate(); err != nil {
		t.Fatalf("TUN-only configuration rejected: %v", err)
	}
}

func TestCredentialsValidator(t *testing.T) {
	valid := Credentials{Username: "user", Password: "pass"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid credentials rejected: %v", err)
	}
	for _, testCase := range []struct {
		name        string
		credentials Credentials
	}{
		{name: "empty username", credentials: Credentials{Password: "pass"}},
		{name: "empty password", credentials: Credentials{Username: "user"}},
		{name: "empty pair", credentials: Credentials{}},
		{name: "oversized username", credentials: Credentials{Username: strings.Repeat("u", 256), Password: "pass"}},
		{name: "oversized password", credentials: Credentials{Username: "user", Password: strings.Repeat("p", 256)}},
	} {
		if err := testCase.credentials.Validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s validation error %v, want ErrInvalidConfig", testCase.name, err)
		}
	}
	cases := []struct {
		name     string
		username string
		password string
		want     bool
	}{
		{name: "exact", username: "user", password: "pass", want: true},
		{name: "case sensitivity", username: "User", password: "pass", want: false},
		{name: "trailing whitespace", username: "user", password: "pass ", want: false},
		{name: "empty password", username: "user", password: "", want: false},
		{name: "empty pair", username: "", password: "", want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := valid.Matches(testCase.username, testCase.password); got != testCase.want {
				t.Fatalf("Matches(%q, %q) = %v, want %v", testCase.username, testCase.password, got, testCase.want)
			}
		})
	}
	// An unvalidated, empty configuration must never authenticate an empty pair.
	if (Credentials{}).Matches("", "") {
		t.Fatal("empty credentials authenticated an empty client pair")
	}
}

func TestLimiterBounds(t *testing.T) {
	bounded := newLimiter(2)
	if !bounded.acquire() || !bounded.acquire() {
		t.Fatal("two slots must be available")
	}
	if bounded.acquire() {
		t.Fatal("the limiter admitted more connections than its capacity")
	}
	bounded.release()
	if !bounded.acquire() {
		t.Fatal("a released slot must be reusable")
	}
	degenerate := newLimiter(0)
	if !degenerate.acquire() || degenerate.acquire() {
		t.Fatal("a degenerate limiter must still bound admission to one")
	}
}

// --- ports without backends ------------------------------------------------

// portShapeDevice is a test double that exercises the PacketDevice contract. It
// is not a TUN backend and creates no system device.
type portShapeDevice struct {
	mu      sync.Mutex
	packets chan []byte
	events  chan DeviceEvent
	mtu     int
	closed  bool
}

func (d *portShapeDevice) ReadPacket(ctx context.Context, buffer []byte) (int, error) {
	select {
	case packet := <-d.packets:
		return copy(buffer, packet), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (d *portShapeDevice) WritePacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case d.packets <- append([]byte(nil), packet...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *portShapeDevice) MTU() int { return d.mtu }

func (d *portShapeDevice) Events() <-chan DeviceEvent { return d.events }

func (d *portShapeDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		close(d.events)
	}
	return nil
}

// portShapeAdapter is a test double for the HostAdapter port.
type portShapeAdapter struct {
	device PacketDevice
}

func (a *portShapeAdapter) Platform() Platform { return PlatformLinux }

func (a *portShapeAdapter) Open(ctx context.Context, options DeviceOptions) (PacketDevice, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.MTU != DefaultDeviceMTU {
		return nil, fmt.Errorf("unexpected MTU %d", options.MTU)
	}
	return a.device, nil
}

// portShapeSystemNetwork is a test double for the SystemNetwork transaction port.
type portShapeSystemNetwork struct {
	state SystemNetworkState
}

func (s *portShapeSystemNetwork) State() SystemNetworkState { return s.state }

func (s *portShapeSystemNetwork) Prepare(context.Context) error {
	s.state = SystemNetworkPrepared
	return nil
}

func (s *portShapeSystemNetwork) Apply(context.Context) error {
	s.state = SystemNetworkApplied
	return nil
}

func (s *portShapeSystemNetwork) Rollback(context.Context) error {
	s.state = SystemNetworkRollback
	return nil
}

func (s *portShapeSystemNetwork) Close() error {
	s.state = SystemNetworkClosed
	return nil
}

var (
	_ PacketDevice  = (*portShapeDevice)(nil)
	_ HostAdapter   = (*portShapeAdapter)(nil)
	_ SystemNetwork = (*portShapeSystemNetwork)(nil)
	_ Dialer        = DialerFunc(nil)
	_ Dialer        = (*net.Dialer)(nil)
	_ ListenFunc    = (*net.ListenConfig)(nil).Listen
)

func TestPlatformPortsAndAdapterResolution(t *testing.T) {
	if DefaultDeviceMTU != 1380 {
		t.Fatalf("DefaultDeviceMTU = %d, want the internal 1380 default", DefaultDeviceMTU)
	}
	if MaxProxyConnections != 256 {
		t.Fatalf("MaxProxyConnections = %d, want the P1 hard initial value 256", MaxProxyConnections)
	}
	for _, platform := range []Platform{"plan9", ""} {
		if _, err := ResolveHostAdapter(platform); !errors.Is(err, ErrPlatformUnavailable) {
			t.Fatalf("ResolveHostAdapter(%q) error %v, want ErrPlatformUnavailable", platform, err)
		}
	}
	switch CurrentPlatform() {
	case PlatformLinux, PlatformWindows, PlatformDarwin:
		adapter, err := ResolveHostAdapter(CurrentPlatform())
		if err != nil {
			t.Fatalf("ResolveHostAdapter(%s): %v", CurrentPlatform(), err)
		}
		if adapter.Platform() != CurrentPlatform() {
			t.Fatalf("adapter platform %q, want %q", adapter.Platform(), CurrentPlatform())
		}
		info, err := InspectHostAdapter(CurrentPlatform())
		if err != nil {
			t.Fatalf("InspectHostAdapter(%s): %v", CurrentPlatform(), err)
		}
		if info.Platform != CurrentPlatform() {
			t.Fatalf("inspection platform %q, want %q", info.Platform, CurrentPlatform())
		}
		if !info.Available && info.Detail == "" {
			t.Fatalf("an unavailable current-platform adapter must explain itself: %+v", info)
		}
	default:
		if _, err := ResolveHostAdapter(CurrentPlatform()); !errors.Is(err, ErrPlatformUnavailable) {
			t.Fatalf("ResolveHostAdapter(%q) error %v, want ErrPlatformUnavailable", CurrentPlatform(), err)
		}
	}

	// The PacketDevice port carries exactly one complete IP packet per call.
	device := &portShapeDevice{
		packets: make(chan []byte, 4),
		events:  make(chan DeviceEvent, 1),
		mtu:     DefaultDeviceMTU,
	}
	adapter := &portShapeAdapter{device: device}
	ctx := context.Background()
	opened, err := adapter.Open(ctx, DeviceOptions{MTU: DefaultDeviceMTU})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.MTU() != DefaultDeviceMTU {
		t.Fatalf("MTU() = %d, want %d", opened.MTU(), DefaultDeviceMTU)
	}
	packet := []byte{0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00}
	if err := opened.WritePacket(ctx, packet); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	buffer := make([]byte, opened.MTU())
	read, err := opened.ReadPacket(ctx, buffer)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if read != len(packet) || !bytes.Equal(buffer[:read], packet) {
		t.Fatalf("ReadPacket returned %d bytes %v, want one complete packet %v", read, buffer[:read], packet)
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The SystemNetwork transaction vocabulary matches the documented states.
	for state, want := range map[SystemNetworkState]string{
		SystemNetworkAbsent:    "absent",
		SystemNetworkPrepared:  "prepared",
		SystemNetworkApplied:   "applied",
		SystemNetworkRunning:   "running",
		SystemNetworkReconcile: "reconcile",
		SystemNetworkRollback:  "rollback",
		SystemNetworkDegraded:  "degraded",
		SystemNetworkClosed:    "closed",
	} {
		if string(state) != want {
			t.Fatalf("state %q, want %q", state, want)
		}
	}
	network := &portShapeSystemNetwork{state: SystemNetworkAbsent}
	if err := network.Prepare(ctx); err != nil || network.State() != SystemNetworkPrepared {
		t.Fatalf("Prepare left state %q (err %v)", network.State(), err)
	}
	if err := network.Apply(ctx); err != nil || network.State() != SystemNetworkApplied {
		t.Fatalf("Apply left state %q (err %v)", network.State(), err)
	}
	if err := network.Rollback(ctx); err != nil || network.State() != SystemNetworkRollback {
		t.Fatalf("Rollback left state %q (err %v)", network.State(), err)
	}
	if err := network.Close(); err != nil || network.State() != SystemNetworkClosed {
		t.Fatalf("Close left state %q (err %v)", network.State(), err)
	}
}

// --- Agent.RetargetAddress --------------------------------------------------

// retargetTestDevice is the minimal PacketDevice an Agent-level retarget test
// needs. It opens no kernel device.
type retargetTestDevice struct {
	mu     sync.Mutex
	closed bool
}

func (d *retargetTestDevice) ReadPacket(context.Context, []byte) (int, error) { return 0, io.EOF }

func (d *retargetTestDevice) WritePacket(context.Context, []byte) error { return nil }

func (d *retargetTestDevice) MTU() int { return DefaultDeviceMTU }

func (d *retargetTestDevice) Events() <-chan DeviceEvent { return nil }

func (d *retargetTestDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

// retargetTestOwner is a SystemNetwork double that also implements
// addressRetargeter, so the Agent can move a live address through it.
type retargetTestOwner struct {
	state   SystemNetworkState
	calls   int
	movedTo netip.Prefix
	err     error
}

func (o *retargetTestOwner) State() SystemNetworkState { return o.state }

func (o *retargetTestOwner) Prepare(context.Context) error {
	o.state = SystemNetworkPrepared
	return nil
}

func (o *retargetTestOwner) Apply(context.Context) error {
	o.state = SystemNetworkApplied
	return nil
}

func (o *retargetTestOwner) Rollback(context.Context) error {
	o.state = SystemNetworkRollback
	return nil
}

func (o *retargetTestOwner) Close() error {
	o.state = SystemNetworkClosed
	return nil
}

func (o *retargetTestOwner) RetargetAddress(_ context.Context, address netip.Prefix) error {
	o.calls++
	if o.err != nil {
		return o.err
	}
	o.movedTo = address
	return nil
}

var (
	_ PacketDevice      = (*retargetTestDevice)(nil)
	_ SystemNetwork     = (*retargetTestOwner)(nil)
	_ addressRetargeter = (*retargetTestOwner)(nil)
)

// retargetTestAgent builds an Agent whose device and host network owner are
// already wired, without opening a real device: the retarget path only inspects
// those two fields.
func retargetTestAgent(t *testing.T, owner SystemNetwork, address netip.Prefix) *Agent {
	t.Helper()
	agent, err := New(AgentConfig{
		Platform: PlatformLinux,
		Device:   DeviceConfig{Name: "st-retarget0", Address: address},
	}, Deps{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	agent.mu.Lock()
	agent.device = &retargetTestDevice{}
	agent.sysnet = owner
	agent.mu.Unlock()
	return agent
}

// TestAgentRetargetAddressBeforeStartUpdatesConfigOnly proves the not-started
// path only updates the configuration Start will consume and has no owner to
// call.
func TestAgentRetargetAddressBeforeStartUpdatesConfigOnly(t *testing.T) {
	ctx := context.Background()
	addressA := netip.MustParsePrefix("10.209.61.1/32")
	addressB := netip.MustParsePrefix("10.209.61.2/32")
	agent, err := New(AgentConfig{
		Platform: PlatformLinux,
		Device:   DeviceConfig{Name: "st-retarget0", Address: addressA},
	}, Deps{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = agent.Close() }()
	if agent.SystemNetwork() != nil {
		t.Fatal("a not-started agent must not have a host network owner")
	}
	if err := agent.RetargetAddress(ctx, addressB); err != nil {
		t.Fatalf("RetargetAddress before Start: %v", err)
	}
	if agent.config.Device.Address != addressB {
		t.Fatalf("configuration address %s, want %s", agent.config.Device.Address, addressB)
	}
}

// TestAgentRetargetAddressUsesLiveOwner proves the started path delegates to the
// owner capability and only then commits the new configuration.
func TestAgentRetargetAddressUsesLiveOwner(t *testing.T) {
	ctx := context.Background()
	addressA := netip.MustParsePrefix("10.209.62.1/32")
	addressB := netip.MustParsePrefix("10.209.62.2/32")
	owner := &retargetTestOwner{state: SystemNetworkApplied}
	agent := retargetTestAgent(t, owner, addressA)
	defer func() { _ = agent.Close() }()
	if err := agent.RetargetAddress(ctx, addressB); err != nil {
		t.Fatalf("RetargetAddress: %v", err)
	}
	if owner.calls != 1 || owner.movedTo != addressB {
		t.Fatalf("owner calls=%d movedTo=%s, want one move to %s", owner.calls, owner.movedTo, addressB)
	}
	if agent.config.Device.Address != addressB {
		t.Fatalf("configuration address %s, want %s", agent.config.Device.Address, addressB)
	}
}

// TestAgentRetargetAddressWithoutCapabilityFailsClosed proves an owner that
// cannot retarget a live address is refused rather than reopened.
func TestAgentRetargetAddressWithoutCapabilityFailsClosed(t *testing.T) {
	ctx := context.Background()
	addressA := netip.MustParsePrefix("10.209.63.1/32")
	addressB := netip.MustParsePrefix("10.209.63.2/32")
	agent := retargetTestAgent(t, &portShapeSystemNetwork{state: SystemNetworkApplied}, addressA)
	defer func() { _ = agent.Close() }()
	err := agent.RetargetAddress(ctx, addressB)
	if !errors.Is(err, ErrNetworkConfigUnavailable) {
		t.Fatalf("RetargetAddress error %v, want ErrNetworkConfigUnavailable", err)
	}
	if agent.config.Device.Address != addressA {
		t.Fatalf("a refused retarget changed the configuration to %s", agent.config.Device.Address)
	}
}

// TestAgentRetargetAddressOwnerErrorPreservesConfig proves an owner failure
// leaves the previous configured address in place for the caller to keep
// publishing.
func TestAgentRetargetAddressOwnerErrorPreservesConfig(t *testing.T) {
	ctx := context.Background()
	addressA := netip.MustParsePrefix("10.209.64.1/32")
	addressB := netip.MustParsePrefix("10.209.64.2/32")
	ownerErr := errors.New("owner refused the retarget")
	owner := &retargetTestOwner{state: SystemNetworkApplied, err: ownerErr}
	agent := retargetTestAgent(t, owner, addressA)
	defer func() { _ = agent.Close() }()
	err := agent.RetargetAddress(ctx, addressB)
	if !errors.Is(err, ownerErr) {
		t.Fatalf("RetargetAddress error %v, want the owner error", err)
	}
	if agent.config.Device.Address != addressA {
		t.Fatalf("a failed retarget changed the configuration to %s", agent.config.Device.Address)
	}
}

// TestAgentRetargetAddressNoOpDoesNotCallOwner proves the no-op comparison
// happens before the owner capability is consulted.
func TestAgentRetargetAddressNoOpDoesNotCallOwner(t *testing.T) {
	ctx := context.Background()
	addressA := netip.MustParsePrefix("10.209.65.1/32")
	owner := &retargetTestOwner{state: SystemNetworkApplied}
	agent := retargetTestAgent(t, owner, addressA)
	defer func() { _ = agent.Close() }()
	if err := agent.RetargetAddress(ctx, addressA); err != nil {
		t.Fatalf("no-op RetargetAddress: %v", err)
	}
	if owner.calls != 0 {
		t.Fatalf("a no-op retarget called the owner %d times", owner.calls)
	}
	if agent.config.Device.Address != addressA {
		t.Fatalf("a no-op retarget changed the configuration to %s", agent.config.Device.Address)
	}
}

// TestAgentRetargetAddressNilAndClosed proves both terminal states are refused.
func TestAgentRetargetAddressNilAndClosed(t *testing.T) {
	ctx := context.Background()
	addressB := netip.MustParsePrefix("10.209.66.2/32")
	var nilAgent *Agent
	if err := nilAgent.RetargetAddress(ctx, addressB); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil agent error %v, want ErrClosed", err)
	}
	agent, err := New(AgentConfig{Platform: PlatformLinux}, Deps{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := agent.RetargetAddress(ctx, addressB); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed agent error %v, want ErrClosed", err)
	}
}

// --- byte relay lifecycle --------------------------------------------------

// TestRelayNonEOFErrorUnblocksBothDirections reproduces the observed hang: one
// direction of the byte relay fails with a non-EOF source Read error while the
// sibling copy is parked in a Read on the opposite endpoint. relay must close
// both endpoints to interrupt the parked sibling and return, instead of waiting
// for a copy that will never end. Both trigger shapes matter: an endpoint pulled
// away under the read (the reset class) and a read deadline that fires.
func TestRelayNonEOFErrorUnblocksBothDirections(t *testing.T) {
	cases := []struct {
		name   string
		broken func(upstream net.Conn)
	}{
		{
			name: "source endpoint closed",
			// Closing the relay-side endpoint turns the pending Read on that
			// source into io.ErrClosedPipe, the same non-EOF failure class as
			// the circuit reset (ErrCanceled) that produced the hang.
			broken: func(upstream net.Conn) { _ = upstream.Close() },
		},
		{
			name:   "source read deadline exceeded",
			broken: func(upstream net.Conn) { _ = upstream.SetReadDeadline(time.Now()) },
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			baseline := runtime.NumGoroutine()
			client, clientPeer := net.Pipe()
			upstream, upstreamPeer := net.Pipe()
			defer func() { _ = clientPeer.Close() }()
			defer func() { _ = upstreamPeer.Close() }()

			done := make(chan struct{})
			go func() {
				relay(context.Background(), client, upstream)
				close(done)
			}()

			// The upstream->client copy fails on its parked Read (or on its
			// next one); the client->upstream copy is parked in Read on the
			// still-open client endpoint and can only be released by relay
			// closing that endpoint.
			testCase.broken(upstream)

			select {
			case <-done:
			case <-time.After(testTimeout):
				t.Fatal("relay did not return after a non-EOF error; the sibling copy is still parked in Read")
			}
			// Both peers observe the teardown, which proves relay closed the
			// client endpoint the sibling Read was blocked on.
			expectConnClosed(t, clientPeer, clientPeer)
			expectConnClosed(t, upstreamPeer, upstreamPeer)
			// Neither copy goroutine may outlive the relay call.
			waitFor(t, func() bool { return runtime.NumGoroutine() <= baseline }, "relay copy goroutines to exit")
		})
	}
}

// TestRelayContextCancellationClosesBothDirections proves the Agent context
// still tears down a relay whose copies are both parked.
func TestRelayContextCancellationClosesBothDirections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, clientPeer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer func() { _ = clientPeer.Close() }()
	defer func() { _ = upstreamPeer.Close() }()

	done := make(chan struct{})
	go func() {
		relay(ctx, client, upstream)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("relay did not return after context cancellation")
	}
	expectConnClosed(t, clientPeer, clientPeer)
	expectConnClosed(t, upstreamPeer, upstreamPeer)
}

// tcpPair returns the relay-side and peer-side ends of one loopback TCP
// connection. The half-close test needs a real CloseWrite (a FIN on one
// direction only), which net.Pipe cannot express.
func tcpPair(t *testing.T) (proxySide, peerSide *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pair listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn.(*net.TCPConn)
	}()
	dialed, err := net.DialTimeout("tcp", listener.Addr().String(), testTimeout)
	if err != nil {
		t.Fatalf("pair dial: %v", err)
	}
	select {
	case conn := <-accepted:
		return conn, dialed.(*net.TCPConn)
	case err := <-acceptErr:
		_ = dialed.Close()
		t.Fatalf("pair accept: %v", err)
	case <-time.After(testTimeout):
		_ = dialed.Close()
		t.Fatal("pair accept timed out")
	}
	return nil, nil
}

// TestRelayCleanEOFPreservesHalfCloseAndDrainsResponse proves a clean EOF is
// still a half-close, not a tunnel teardown: after the client shuts down its
// write side, the target sees EOF and can still send its response, which reaches
// the client; relay returns only once both directions have ended.
func TestRelayCleanEOFPreservesHalfCloseAndDrainsResponse(t *testing.T) {
	clientProxy, clientPeer := tcpPair(t)
	upstreamProxy, upstreamPeer := tcpPair(t)
	defer func() { _ = clientPeer.Close() }()
	defer func() { _ = upstreamProxy.Close() }()
	defer func() { _ = upstreamPeer.Close() }()

	done := make(chan struct{})
	go func() {
		relay(context.Background(), clientProxy, upstreamProxy)
		close(done)
	}()

	_ = clientPeer.SetDeadline(time.Now().Add(testTimeout))
	_ = upstreamPeer.SetDeadline(time.Now().Add(testTimeout))

	// Request direction: client -> relay -> target.
	if _, err := clientPeer.Write([]byte("ping")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	request := make([]byte, len("ping"))
	if _, err := io.ReadFull(upstreamPeer, request); err != nil {
		t.Fatalf("read request at target: %v", err)
	}
	if string(request) != "ping" {
		t.Fatalf("target read %q, want %q", request, "ping")
	}

	// The client half-closes its write side: the relay must propagate that as a
	// half-close to the target, not as a full teardown.
	if err := clientPeer.CloseWrite(); err != nil {
		t.Fatalf("client half-close: %v", err)
	}
	var eof [1]byte
	if _, err := upstreamPeer.Read(eof[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("target read after the client half-close = %v, want io.EOF", err)
	}

	// The response direction must still drain: the client's read side is open,
	// so relay must not have closed it when the request direction ended.
	if _, err := upstreamPeer.Write([]byte("pong")); err != nil {
		t.Fatalf("write response: %v", err)
	}
	response := make([]byte, len("pong"))
	if _, err := io.ReadFull(clientPeer, response); err != nil {
		t.Fatalf("read response at client after half-close: %v", err)
	}
	if string(response) != "pong" {
		t.Fatalf("client read %q, want %q", response, "pong")
	}

	// Both directions have now ended cleanly, so relay returns.
	if err := upstreamPeer.Close(); err != nil {
		t.Fatalf("close target: %v", err)
	}
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("relay did not return after both directions ended")
	}
}
