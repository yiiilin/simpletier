// Package benchmarks_test holds the reproducible P1 business-path performance
// harness of the public SimpleTier SDK.
//
// Every topology here is built from independent SDK Networks that each own a
// private identity StateDir (a child directory created 0700 by the SDK), a real
// loopback TCP carrier, and an explicit fixed VirtualIP. Nothing here uses a
// component MAC micro-benchmark, a mock carrier, a plaintext path, or the
// control lane as a business workaround: all measured traffic is real
// DialContext/Listen Stream and ListenPacket datagram traffic.
//
// The benchmarks are deterministic by construction: fixed network name, CIDR,
// token and VirtualIPs; only the loopback carrier port and the CSPRNG payload
// differ per run. Route convergence (the ~14s baseline startup cost) is warmed
// before b.ResetTimer, so it is excluded from the business measurement unless a
// separate startup benchmark reports it.
package benchmarks_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

const (
	benchNetworkName = "p1-performance-benchmarks"
	benchCIDR        = "10.221.0.0/24"
	benchToken       = "p1-performance-benchmark-token-0123456789abcdef"

	nodeAIP = "10.221.0.1" // source (dialer)
	nodeBIP = "10.221.0.2" // target (listener)
	nodeRIP = "10.221.0.3" // relay (A-R-B only, never a direct A-B carrier)

	// routeTimeout bounds the pre-timer warm-up that waits for the
	// authenticated topology and the dedicated STREAM/PACKET lane to converge.
	// The observed baseline is ~14s in the acceptance tests, so this is a
	// generous ceiling that is never part of a measured interval.
	routeTimeout = 90 * time.Second
	// closeWait must stay strictly above the SDK's internal 5s
	// networkCloseTimeout; tightening it to force green is explicitly not
	// allowed, so a real leak fails the benchmark instead.
	closeWait   = 20 * time.Second
	dialTimeout = 5 * time.Second

	// maxBuffer is the bounded copy buffer of the low-reader path. No payload
	// proportional to b.N is ever allocated by the memory benchmark.
	maxBuffer = 64 << 10

	udpTargetPort = 21001
	udpSourcePort = 21002
)

// benchSizes lives in canonical_bench_test.go: one matrix for every suite, so
// numbers from different suites can be compared directly.

// freeLoopbackPort returns a currently unused loopback TCP port. The tiny
// bind/close race is acceptable because the SDK immediately rebinds it; this is
// the same contract the SDK acceptance tests rely on.
func freeLoopbackPort(tb testing.TB) int {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("reserve loopback port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		tb.Fatalf("release loopback port: %v", err)
	}
	return port
}

// benchStateDir returns a not-yet-existing private child directory. The SDK's
// IdentityStore creates it itself with 0700, so the temporary parent is never
// weakened and no host directory permission is modified.
func benchStateDir(tb testing.TB) string {
	tb.Helper()
	return filepath.Join(tb.TempDir(), "state")
}

// newBenchNetwork starts one independent SDK Network with its own StateDir,
// real loopback carrier and explicit fixed VirtualIP.
// newBenchNetworkURL is newBenchNetwork with the upstream expressed as a full
// carrier URL, so a benchmark can put something between the two nodes (for
// example a latency proxy) without teaching newBenchNetwork about it.
func newBenchNetworkURL(tb testing.TB, listenPort int, upstreams []string, fixedIP string) simpletier.Network {
	tb.Helper()
	n, err := simpletier.NewNetwork(simpletier.Config{
		Listen:    []string{fmt.Sprintf("tcp://127.0.0.1:%d", listenPort)},
		Upstreams: upstreams,
		Network: simpletier.NetworkConfig{
			Name:  benchNetworkName,
			CIDR:  benchCIDR,
			Token: benchToken,
		},
		Options: simpletier.RuntimeOptions{
			FixedIP:  fixedIP,
			LogLevel: "error",
		},
	})
	if err != nil {
		tb.Fatalf("NewNetwork(%s): %v", fixedIP, err)
	}
	tb.Cleanup(func() { closeNetwork(tb, n) })
	return n
}

func newBenchNetwork(tb testing.TB, listenPort int, upstreamPorts []int, fixedIP string) simpletier.Network {
	tb.Helper()
	upstreams := make([]string, 0, len(upstreamPorts))
	for _, port := range upstreamPorts {
		upstreams = append(upstreams, fmt.Sprintf("tcp://127.0.0.1:%d", port))
	}
	n, err := simpletier.NewNetwork(simpletier.Config{
		Listen:    []string{fmt.Sprintf("tcp://127.0.0.1:%d", listenPort)},
		Upstreams: upstreams,
		Network: simpletier.NetworkConfig{
			Name:  benchNetworkName,
			CIDR:  benchCIDR,
			Token: benchToken,
		},
		Options: simpletier.RuntimeOptions{
			FixedIP:  fixedIP,
			LogLevel: "error",
		},
	})
	if err != nil {
		tb.Fatalf("NewNetwork(%s): %v", fixedIP, err)
	}
	tb.Cleanup(func() { closeNetwork(tb, n) })
	return n
}

// newTargetsNetwork starts one SDK Network that reaches its peer through a
// host-provided ConnectionTarget/Connector instead of a tcp:// upstream URL.
func newTargetsNetwork(tb testing.TB, listenPort, targetCarrierPort int, fixedIP string) simpletier.Network {
	tb.Helper()
	n, err := simpletier.NewNetwork(simpletier.Config{
		Listen: []string{fmt.Sprintf("tcp://127.0.0.1:%d", listenPort)},
		Targets: []simpletier.ConnectionTarget{{
			Connector: &simpletier.TCPConnector{},
			Endpoint:  fmt.Sprintf("127.0.0.1:%d", targetCarrierPort),
		}},
		Network: simpletier.NetworkConfig{
			Name:  benchNetworkName,
			CIDR:  benchCIDR,
			Token: benchToken,
		},
		Options: simpletier.RuntimeOptions{
			FixedIP:  fixedIP,
			LogLevel: "error",
		},
	})
	if err != nil {
		tb.Fatalf("NewNetwork(targets, %s): %v", fixedIP, err)
	}
	tb.Cleanup(func() { closeNetwork(tb, n) })
	return n
}

// closeNetwork closes one Network under a bounded wait and verifies that Done
// closes afterwards. A timeout or an unexpected typed error is always a real
// leak/session/resource bug: the wait bound is never relaxed to force green.
func closeNetwork(tb testing.TB, n simpletier.Network) {
	tb.Helper()
	if n == nil {
		return
	}
	done := make(chan error, 1)
	go func() { done <- n.Close() }()
	select {
	case err := <-done:
		if err != nil {
			classifyFatal(tb, "Network.Close", err)
		}
	case <-time.After(closeWait):
		tb.Fatalf("UNEXPECTED: Network.Close did not return within %s (wait bound is not relaxed)", closeWait)
	}
	select {
	case <-n.Done():
	case <-time.After(closeWait):
		tb.Fatalf("UNEXPECTED: Network.Done did not close within %s after Close returned", closeWait)
	}
}

// classifyFatal reports an unexpected SDK typed error as a real bug. It never
// downgrades ErrSessionLost/ErrResource/ErrCloseTimeout to a warning.
func classifyFatal(tb testing.TB, op string, err error) {
	tb.Helper()
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, simpletier.ErrCloseTimeout):
		tb.Fatalf("UNEXPECTED %s: ErrCloseTimeout, real close/leak bug: %v", op, err)
	case errors.Is(err, simpletier.ErrSessionLost):
		tb.Fatalf("UNEXPECTED %s: ErrSessionLost, real session bug: %v", op, err)
	case errors.Is(err, simpletier.ErrResource):
		tb.Fatalf("UNEXPECTED %s: ErrResource, real resource bug: %v", op, err)
	default:
		tb.Fatalf("UNEXPECTED %s: %v", op, err)
	}
}

// randPayload returns a fresh CSPRNG payload. Randomness is the uniqueness
// marker: byte equality against the echo is a real proof that the exact bytes
// traversed the business path, not a static or truncated buffer.
func randPayload(tb testing.TB, size int) []byte {
	tb.Helper()
	payload := make([]byte, size)
	if size == 0 {
		return payload
	}
	if _, err := rand.Read(payload); err != nil {
		tb.Fatalf("CSPRNG payload: %v", err)
	}
	return payload
}

// pairEnv is a direct A-B topology: A upstreams to B's carrier. There is no
// relay and no third node.
type pairEnv struct {
	target   simpletier.Network
	source   simpletier.Network
	targetIP string
	sourceIP string
}

func newPairEnv(tb testing.TB) *pairEnv {
	tb.Helper()
	carrierPort := freeLoopbackPort(tb)
	target := newBenchNetwork(tb, carrierPort, nil, nodeBIP)
	source := newBenchNetwork(tb, freeLoopbackPort(tb), []int{carrierPort}, nodeAIP)
	return &pairEnv{target: target, source: source, targetIP: nodeBIP, sourceIP: nodeAIP}
}

// relayEnv is an A-R-B topology: A and B each upstream only to R. A and B share
// no carrier address, so any A-to-B reachability is relayed by R.
type relayEnv struct {
	relay   simpletier.Network
	a       simpletier.Network
	b       simpletier.Network
	aIP     string
	bIP     string
	relayIP string
}

func newRelayEnv(tb testing.TB) *relayEnv {
	tb.Helper()
	relayCarrier := freeLoopbackPort(tb)
	relay := newBenchNetwork(tb, relayCarrier, nil, nodeRIP)
	a := newBenchNetwork(tb, freeLoopbackPort(tb), []int{relayCarrier}, nodeAIP)
	b := newBenchNetwork(tb, freeLoopbackPort(tb), []int{relayCarrier}, nodeBIP)
	return &relayEnv{relay: relay, a: a, b: b, aIP: nodeAIP, bIP: nodeBIP, relayIP: nodeRIP}
}

// dialUntil warms the actual route and dial before the timer starts. It is the
// only place startup convergence is paid for; the measured loop then sees an
// established customer stream.
func dialUntil(tb testing.TB, n simpletier.Network, address string) simpletier.Stream {
	tb.Helper()
	deadline := time.Now().Add(routeTimeout)
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
	tb.Fatalf("DialContext(%s) never succeeded within %s: %v", address, routeTimeout, lastErr)
	return nil
}

// listenVirtual binds one virtual TCP listener on the given node VirtualIP.
func listenVirtual(tb testing.TB, n simpletier.Network, ip string, port int) simpletier.StreamListener {
	tb.Helper()
	listener, err := n.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		tb.Fatalf("Listen(%s:%d): %v", ip, port, err)
	}
	tb.Cleanup(func() { _ = listener.Close() })
	return listener
}

// streamServer is one in-process virtual target service. It only touches
// Streams returned by the public StreamListener; it never opens an OS socket
// towards a target.
type streamServer struct {
	name string
	done chan struct{}
	read atomic.Int64

	mu  sync.Mutex
	err error
}

func (s *streamServer) fail(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
}

func (s *streamServer) errOrNil() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// wait blocks until the service goroutine ended and reports any failure. It is
// deliberately bounded by closeWait, which is never shortened.
func (s *streamServer) wait(tb testing.TB, timeout time.Duration) {
	tb.Helper()
	select {
	case <-s.done:
	case <-time.After(timeout):
		tb.Fatalf("UNEXPECTED: %s server did not finish within %s", s.name, timeout)
	}
	if err := s.errOrNil(); err != nil {
		classifyFatal(tb, s.name+" server", err)
	}
}

// awaitConsumed blocks until the service has consumed expected bytes, bounded
// by closeWait. It is the remote-delivery acknowledgement for the one-way
// discard paths: a short count is a real delivery bug, never a warning, so a
// local queue credit can never be reported as consumed data.
func (s *streamServer) awaitConsumed(tb testing.TB, expected int64) {
	tb.Helper()
	deadline := time.Now().Add(closeWait)
	for time.Now().Before(deadline) {
		if s.read.Load() >= expected {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	tb.Fatalf("UNEXPECTED: %s consumed %d of %d bytes before the bound (remote delivery short)", s.name, s.read.Load(), expected)
}

// startEchoServer accepts one Stream and echoes every received chunk. Reading
// and writing happen in the same goroutine, so the client side must read
// concurrently; that is what keeps the write window advancing.
func startEchoServer(tb testing.TB, listener simpletier.StreamListener) *streamServer {
	tb.Helper()
	server := &streamServer{name: "echo", done: make(chan struct{})}
	go func() {
		defer close(server.done)
		stream, err := listener.Accept()
		if err != nil {
			server.fail(err)
			return
		}
		defer func() { _ = stream.Close() }()
		buf := make([]byte, maxBuffer)
		for {
			n, readErr := stream.Read(buf)
			if n > 0 {
				server.read.Add(int64(n))
				if _, writeErr := stream.Write(buf[:n]); writeErr != nil {
					server.fail(writeErr)
					return
				}
			}
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, net.ErrClosed) && !errors.Is(readErr, simpletier.ErrClosed) {
					server.fail(readErr)
				}
				_ = stream.CloseWrite()
				return
			}
		}
	}()
	return server
}

// startDiscardServer accepts one Stream, consumes it with a fixed 64 KiB buffer
// and discards the bytes. Consumption is what produces the window updates that
// let the sender keep writing.
func startDiscardServer(tb testing.TB, listener simpletier.StreamListener) *streamServer {
	tb.Helper()
	server := &streamServer{name: "discard", done: make(chan struct{})}
	go func() {
		defer close(server.done)
		stream, err := listener.Accept()
		if err != nil {
			server.fail(err)
			return
		}
		defer func() { _ = stream.Close() }()
		buf := make([]byte, maxBuffer)
		for {
			n, readErr := stream.Read(buf)
			if n > 0 {
				server.read.Add(int64(n))
			}
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, net.ErrClosed) && !errors.Is(readErr, simpletier.ErrClosed) {
					server.fail(readErr)
				}
				_ = stream.CloseWrite()
				return
			}
		}
	}()
	return server
}

// writeAll is io.Writer.Full with short-write detection.
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// consumeN consumes exactly total bytes into the scratch buffer buf, which may
// be smaller than total and is deliberately reused from offset 0. It is only
// for paths that discard the payload (throughput/discard); code that needs the
// exact bytes uses io.ReadFull into a correctly sized destination.
func consumeN(r io.Reader, buf []byte, total int) error {
	remaining := total
	for remaining > 0 {
		window := buf
		if len(window) > remaining {
			window = window[:remaining]
		}
		n, err := r.Read(window)
		if n > 0 {
			remaining -= n
		}
		if err != nil {
			if errors.Is(err, io.EOF) && remaining == 0 {
				return nil
			}
			return err
		}
	}
	return nil
}

// echoRoundTrip writes payload and consumes the same number of echoed bytes
// concurrently. The concurrent reader is required: a large write would
// otherwise fill the receive window and block forever.
func echoRoundTrip(stream simpletier.Stream, payload, readBuf []byte) error {
	readErr := make(chan error, 1)
	go func() { readErr <- consumeN(stream, readBuf, len(payload)) }()
	writeErr := writeAll(stream, payload)
	received := <-readErr
	if writeErr != nil {
		return writeErr
	}
	return received
}

// echoHandshake proves the virtual listener accepted and the echo service is
// live before any timer starts.
func echoHandshake(tb testing.TB, stream simpletier.Stream) {
	tb.Helper()
	marker := randPayload(tb, 1)
	buf := make([]byte, 1)
	if err := writeAll(stream, marker); err != nil {
		tb.Fatalf("echo handshake write: %v", err)
	}
	if _, err := io.ReadFull(stream, buf); err != nil {
		tb.Fatalf("echo handshake read: %v", err)
	}
	if !bytes.Equal(marker, buf) {
		tb.Fatalf("echo handshake mismatch: %x != %x", marker, buf)
	}
}

// discardHandshake proves the discard service is consuming before any timer
// starts, so the measured writes cannot block on an unconsumed window.
func discardHandshake(tb testing.TB, stream simpletier.Stream, server *streamServer) {
	tb.Helper()
	if err := writeAll(stream, []byte{0xa5}); err != nil {
		tb.Fatalf("discard handshake write: %v", err)
	}
	deadline := time.Now().Add(routeTimeout)
	for time.Now().Before(deadline) {
		if server.read.Load() >= 1 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	tb.Fatalf("discard server never consumed the handshake byte")
}

// warmTCPRoute establishes and warms the authenticated topology in both
// directions before an overlay service is created. Address facts propagate over
// the admitted CONTROL adjacency, so a following ListenPacket reply can be
// routed instead of racing an unresolved destination.
func warmTCPRoute(tb testing.TB, source, target simpletier.Network, targetIP string, port int) {
	tb.Helper()
	listener := listenVirtual(tb, target, targetIP, port)
	server := startEchoServer(tb, listener)
	stream := dialUntil(tb, source, fmt.Sprintf("%s:%d", targetIP, port))
	echoHandshake(tb, stream)
	closeStream(tb, stream)
	server.wait(tb, closeWait)
}

// closeStream performs the graceful FIN path: CloseWrite, then Close.
func closeStream(tb testing.TB, stream simpletier.Stream) error {
	tb.Helper()
	if stream == nil {
		return nil
	}
	if err := stream.CloseWrite(); err != nil &&
		!errors.Is(err, net.ErrClosed) &&
		!errors.Is(err, simpletier.ErrClosed) {
		tb.Errorf("Stream.CloseWrite: %v", err)
	}
	err := stream.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		tb.Errorf("Stream.Close: %v", err)
	}
	return err
}

// zeroReader is the bounded zero source of the low-reader memory benchmark. It
// yields at most the configured remaining bytes and never allocates.
type zeroReader struct{ remaining int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > z.remaining {
		n = int(z.remaining)
	}
	clear(p[:n])
	z.remaining -= int64(n)
	return n, nil
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := (len(sorted) - 1) * p / 100
	return sorted[index]
}

func sortDurations(samples []time.Duration) {
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
}

func addr4(ip string) netip.Addr { return netip.MustParseAddr(ip) }
