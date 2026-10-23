package benchmarks_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/topology"
	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// udpEchoServer is one virtual UDP target service built only from the public
// net.PacketConn returned by ListenPacket. It never creates an OS UDP socket
// towards a target and never inspects internal framing.
type udpEchoServer struct {
	done chan struct{}
	read atomic.Int64

	// warm is true only during the pre-timer topology warm-up. Outside that
	// phase every Send/Reply error is fatal, so a hidden ErrResource/SessionLost
	// or protocol failure can never be masked by a retry.
	warm  atomic.Bool
	drops atomic.Int64

	mu  sync.Mutex
	err error
}

// endWarm closes the warm-up tolerance window. It must be called immediately
// after the topology is confirmed reachable and before any timed iteration.
func (s *udpEchoServer) endWarm() { s.warm.Store(false) }

// routeNotReady reports whether err is exactly the native/public route-missing
// or route-stale sentinel. Only these exact identities are retried, and only
// during warm-up; everything else stays fatal.
func routeNotReady(err error) bool {
	return errors.Is(err, simpletier.ErrNoRoute) ||
		errors.Is(err, topology.ErrNoRoute) ||
		errors.Is(err, topology.ErrRouteStale)
}

func (s *udpEchoServer) fail(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
}

func (s *udpEchoServer) errOrNil() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *udpEchoServer) wait(tb testing.TB, timeout time.Duration) {
	tb.Helper()
	select {
	case <-s.done:
	case <-time.After(timeout):
		tb.Fatalf("UNEXPECTED: udp echo server did not finish within %s", timeout)
	}
	if err := s.errOrNil(); err != nil {
		classifyFatal(tb, "udp echo server", err)
	}
}

func startUDPEcho(tb testing.TB, conn net.PacketConn) *udpEchoServer {
	tb.Helper()
	server := &udpEchoServer{done: make(chan struct{})}
	server.warm.Store(true)
	go func() {
		defer close(server.done)
		buf := make([]byte, 65507)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) && !errors.Is(err, simpletier.ErrClosed) {
					server.fail(err)
				}
				return
			}
			server.read.Add(int64(n))
			// The write is synchronous with the read, so buf[:n] is still the
			// exact received datagram and can be echoed without a copy.
			if _, err := conn.WriteTo(buf[:n], from); err != nil {
				// Warm-up only: the peer's address fact or PACKET pair may not
				// have converged yet. Only the exact route sentinels are
				// retried and counted; after endWarm every reply error is fatal.
				if server.warm.Load() && routeNotReady(err) {
					server.drops.Add(1)
					continue
				}
				server.fail(err)
				return
			}
		}
	}()
	return server
}

// udpWarm waits for the virtual route and the UDP origin association to be
// usable before any timer starts.
func udpWarm(tb testing.TB, conn net.PacketConn, target net.Addr) {
	tb.Helper()
	payload := randPayload(tb, 32)
	buf := make([]byte, 65507)
	deadline := time.Now().Add(routeTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := conn.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			tb.Fatalf("SetDeadline: %v", err)
		}
		if _, err := conn.WriteTo(payload, target); err != nil {
			lastErr = err
			continue
		}
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			lastErr = err
			continue
		}
		if n != len(payload) || !bytes.Equal(payload, buf[:n]) {
			lastErr = fmt.Errorf("warm reply length %d, want %d", n, len(payload))
			continue
		}
		if from.String() != target.String() {
			tb.Fatalf("UDP warm reply from %s, want %s", from, target)
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			tb.Fatalf("clear deadline: %v", err)
		}
		return
	}
	tb.Fatalf("UDP warm roundtrip never succeeded within %s: %v", routeTimeout, lastErr)
}

// udpRoundTrip sends one datagram and proves the exact bytes came back from the
// exact target. Length and byte equality together preserve the datagram
// boundary and are the proof of a real reply rather than a locally synthesized
// success.
func udpRoundTrip(conn net.PacketConn, payload, buf []byte, target net.Addr) error {
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.WriteTo(payload, target); err != nil {
		return err
	}
	n, from, err := conn.ReadFrom(buf)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return fmt.Errorf("reply length %d, want %d: datagram boundary not preserved", n, len(payload))
	}
	if !bytes.Equal(payload, buf[:n]) {
		return fmt.Errorf("reply payload mismatch over %d bytes: datagram boundary not preserved", n)
	}
	if from.String() != target.String() {
		return fmt.Errorf("reply from %s, want %s", from, target)
	}
	return nil
}

// BenchmarkUDPDatagram is the public ListenPacket business path: an empty
// datagram, a 64-byte datagram and the 65,507-byte IPv4 UDP maximum all make a
// real overlay round trip with an echo proof reply.
func BenchmarkUDPDatagram(b *testing.B) {
	env := newPairEnv(b)
	// Warm the authenticated topology first so both address facts are
	// propagated before the datagram reply path resolves a destination.
	warmTCPRoute(b, env.source, env.target, env.targetIP, 29501)
	targetConn, err := env.target.ListenPacket("udp", fmt.Sprintf("%s:%d", env.targetIP, udpTargetPort))
	if err != nil {
		b.Fatalf("target ListenPacket: %v", err)
	}
	sourceConn, err := env.source.ListenPacket("udp", fmt.Sprintf("%s:%d", env.sourceIP, udpSourcePort))
	if err != nil {
		b.Fatalf("source ListenPacket: %v", err)
	}
	server := startUDPEcho(b, targetConn)
	b.Cleanup(func() {
		_ = sourceConn.Close()
		_ = targetConn.Close()
		server.wait(b, closeWait)
	})
	targetAddr := &net.UDPAddr{IP: net.ParseIP(env.targetIP), Port: udpTargetPort}
	udpWarm(b, sourceConn, targetAddr)
	// The topology is reachable now: close the warm-up window so every timed
	// Send/Reply error below is fatal, and record how many startup requests the
	// target had to drop while its route was still converging.
	server.endWarm()
	for _, tc := range []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"64B", 64},
		{"65507B", 65507},
	} {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			payload := randPayload(b, tc.size)
			buf := make([]byte, 65507)
			// Cumulative warm-up drops: only exact route sentinels were retried,
			// and only before endWarm. Timed iterations retry nothing.
			b.ReportMetric(float64(server.drops.Load()), "udp-warm-drops")
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := udpRoundTrip(sourceConn, payload, buf, targetAddr); err != nil {
					classifyFatal(b, "udp roundtrip", err)
				}
			}
			b.StopTimer()
		})
	}
}
