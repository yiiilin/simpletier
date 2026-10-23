package network_runtime_test

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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// This file is the real HTTP proxy business acceptance: a public Agent exposes a
// credentialed HTTP proxy inbound, and GET, a streaming POST and a CONNECT tunnel
// all reach a real target HTTP server that is served on the target Network's
// virtual NetListener. Authentication failures and non-overlay gateway targets
// are refused before any upstream connection.

const (
	httpProxyUser = "http-user"
	httpProxyPass = "http-pass"
	httpProxyPort = 43000
)

// newHTTPProxyAgent starts a public Agent whose only inbound is an HTTP proxy.
func newHTTPProxyAgent(t *testing.T, carrierPort int) *simpletier.Agent {
	t.Helper()
	tun := false
	agent, err := simpletier.NewAgent(simpletier.AgentConfig{
		Config: simpletier.Config{
			Listen:    []string{fmt.Sprintf("tcp://127.0.0.1:%d", freePort(t))},
			Upstreams: []string{fmt.Sprintf("tcp://127.0.0.1:%d", carrierPort)},
			Network: simpletier.NetworkConfig{
				Name:  testNetworkName,
				CIDR:  testCIDR,
				Token: testToken,
			},
			Options: simpletier.RuntimeOptions{
				FixedIP: socksUDPSourceIP,
			},
		},
		Inbounds: simpletier.AgentInbounds{
			TUN: &tun,
			HTTPProxy: &simpletier.ProxyConfig{
				Listen:   "127.0.0.1:0",
				Username: httpProxyUser,
				Password: httpProxyPass,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	t.Cleanup(func() { _ = agent.Close() })
	if err := agent.Start(context.Background()); err != nil {
		t.Fatalf("Agent.Start: %v", err)
	}
	return agent
}

// serveHTTPOnTarget publishes one real HTTP server on the target Network's
// virtual NetListener, so every request that reaches the handler travelled the
// whole authenticated overlay data plane.
func serveHTTPOnTarget(t *testing.T, target simpletier.Network, address string) {
	t.Helper()
	listener, err := target.Listen("tcp", address)
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Target-Path", r.URL.Path)
		w.Header().Set("X-Target-Query", r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(target.NetListener(listener)) }()
	t.Cleanup(func() { _ = server.Close() })
}

func proxyClient(proxyAddr net.Addr, withAuth bool) *http.Client {
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr.String()}
	if withAuth {
		proxyURL.User = url.UserPassword(httpProxyUser, httpProxyPass)
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
}

// TestAgentHTTPProxyGETPOSTAndCONNECT is the HTTP business acceptance: an
// authenticated GET and a streaming POST are forwarded to the target virtual
// HTTP server, a CONNECT tunnel carries a raw HTTP exchange, a missing credential
// is refused with 407, and a non-overlay destination is refused instead of being
// used as a gateway.
func TestAgentHTTPProxyGETPOSTAndCONNECT(t *testing.T) {
	carrierPort := freePort(t)
	target := newTarget(t, carrierPort)
	targetAddr := netip.AddrPortFrom(netip.MustParseAddr(socksUDPTargetIP), httpProxyPort)
	serveHTTPOnTarget(t, target, targetAddr.String())

	agent := newHTTPProxyAgent(t, carrierPort)
	_, proxyAddr := agent.ProxyAddrs()
	if proxyAddr == nil {
		t.Fatal("Agent has no bound HTTP proxy listener")
	}
	client := proxyClient(proxyAddr, true)

	// GET: retry through the topology convergence window.
	targetURL := fmt.Sprintf("http://%s/echo?probe=1", targetAddr)
	var response *http.Response
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		response, lastErr = client.Get(targetURL)
		if lastErr == nil && response.StatusCode == http.StatusOK {
			break
		}
		if response != nil {
			_ = response.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("proxied GET never succeeded: %v", lastErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("proxied GET status = %d; want 200", response.StatusCode)
	}
	if got := response.Header.Get("X-Target-Query"); got != "probe=1" {
		t.Fatalf("target query = %q; want probe=1", got)
	}
	_ = response.Body.Close()

	// Streaming POST: the body is produced incrementally and must arrive whole.
	streamed := make([]byte, 512*1024)
	for i := range streamed {
		streamed[i] = byte(i % 251)
	}
	postResponse, err := client.Post(targetURL, "application/octet-stream", &chunkReader{data: streamed, chunk: 16 * 1024})
	if err != nil {
		t.Fatalf("proxied streaming POST: %v", err)
	}
	echoed, err := io.ReadAll(postResponse.Body)
	_ = postResponse.Body.Close()
	if err != nil {
		t.Fatalf("read POST echo: %v", err)
	}
	if postResponse.StatusCode != http.StatusOK || !bytes.Equal(echoed, streamed) {
		t.Fatalf("proxied POST = (%d, %d bytes echoed); want (200, %d identical)", postResponse.StatusCode, len(echoed), len(streamed))
	}

	// CONNECT: open a raw tunnel through the proxy and speak HTTP/1.1 inside it.
	tunnel, err := net.DialTimeout("tcp", proxyAddr.String(), 10*time.Second)
	if err != nil {
		t.Fatalf("dial proxy for CONNECT: %v", err)
	}
	defer tunnel.Close()
	authorization := base64.StdEncoding.EncodeToString([]byte(httpProxyUser + ":" + httpProxyPass))
	connectRequest := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		targetAddr, targetAddr, authorization)
	if _, err := tunnel.Write([]byte(connectRequest)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(tunnel)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("CONNECT status line = %q; want 200", strings.TrimSpace(statusLine))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	inside := fmt.Sprintf("GET /echo?tunnel=1 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetAddr)
	if _, err := tunnel.Write([]byte(inside)); err != nil {
		t.Fatalf("write tunneled request: %v", err)
	}
	tunneled, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read tunneled response: %v", err)
	}
	tunneledBody, _ := io.ReadAll(tunneled.Body)
	_ = tunneled.Body.Close()
	if tunneled.StatusCode != http.StatusOK || tunneled.Header.Get("X-Target-Query") != "tunnel=1" {
		t.Fatalf("tunneled response = (%d, query %q); want (200, tunnel=1)", tunneled.StatusCode, tunneled.Header.Get("X-Target-Query"))
	}
	_ = tunneledBody

	// A request without credentials is refused before any upstream work.
	noAuth := proxyClient(proxyAddr, false)
	unauthorized, err := noAuth.Get(targetURL)
	if err != nil {
		t.Fatalf("unauthenticated GET transport error: %v", err)
	}
	defer unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated GET status = %d; want 407", unauthorized.StatusCode)
	}

	// A public/LAN destination is denied: this proxy is not a general gateway.
	gateway, err := client.Get("http://203.0.113.9/echo")
	if err != nil {
		t.Fatalf("gateway-deny GET transport error: %v", err)
	}
	defer gateway.Body.Close()
	if gateway.StatusCode != http.StatusForbidden && gateway.StatusCode != http.StatusBadGateway {
		t.Fatalf("non-overlay GET status = %d; want 403 or 502", gateway.StatusCode)
	}
}

// chunkReader streams a fixed payload in bounded chunks so the POST body is
// genuinely produced incrementally instead of handed over as one buffer.
type chunkReader struct {
	data  []byte
	chunk int
	read  int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.read >= len(r.data) {
		return 0, io.EOF
	}
	size := r.chunk
	if size > len(p) {
		size = len(p)
	}
	if remaining := len(r.data) - r.read; size > remaining {
		size = remaining
	}
	copy(p, r.data[r.read:r.read+size])
	r.read += size
	return size, nil
}

var _ = errors.Is
