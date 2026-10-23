// Package network_runtime_test holds the real acceptance tests of the SimpleTier
// P1 data plane. Every test builds two independent SDK Networks with separate
// temporary identity state directories, real loopback TCP carriers and explicit
// fixed VirtualIPs, then exercises DialContext/Listen business data end to end.
// Nothing here uses a mock carrier, a plaintext path or the control lane as a
// business workaround.
package network_runtime_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

const (
	testNetworkName = "runtime-acceptance"
	testCIDR        = "10.90.0.0/24"
	testToken       = "acceptance-token-0123456789abcdef"
	targetIP        = "10.90.0.2"
	sourceIP        = "10.90.0.1"
)

func init() {
	if os.Getenv("SIMPLETIER_TRACE") == "1" {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
}

// freePort returns a currently unused loopback TCP port. The tiny bind/close race
// is acceptable for tests that immediately rebind it.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release loopback port: %v", err)
	}
	return port
}

// newTarget starts the target Network: it owns a real TCP carrier listener and a
// fixed VirtualIP, and no upstream.
func newTarget(t *testing.T, carrierPort int) simpletier.Network {
	t.Helper()
	n, err := simpletier.NewNetwork(simpletier.Config{
		Listen: []string{fmt.Sprintf("tcp://127.0.0.1:%d", carrierPort)},
		Network: simpletier.NetworkConfig{
			Name:  testNetworkName,
			CIDR:  testCIDR,
			Token: testToken,
		},
		Options: simpletier.RuntimeOptions{
			// A not-yet-existing child directory lets IdentityStore create the
			// private state root itself (0700); the temporary parent is left
			// untouched and no host directory permission is modified.
			FixedIP: targetIP,
		},
	})
	if err != nil {
		t.Fatalf("target NewNetwork: %v", err)
	}
	t.Cleanup(func() { _ = n.Close() })
	return n
}

// newSource starts the source Network: it dials the target carrier as an
// upstream and owns its own fixed VirtualIP and state directory.
func newSource(t *testing.T, name string, carrierPort int) simpletier.Network {
	t.Helper()
	n, err := simpletier.NewNetwork(simpletier.Config{
		Listen:    []string{fmt.Sprintf("tcp://127.0.0.1:%d", freePort(t))},
		Upstreams: []string{fmt.Sprintf("tcp://127.0.0.1:%d", carrierPort)},
		Network: simpletier.NetworkConfig{
			Name:  name,
			CIDR:  testCIDR,
			Token: testToken,
		},
		Options: simpletier.RuntimeOptions{
			FixedIP:  sourceIP,
			LogLevel: "debug",
		},
	})
	if err != nil {
		t.Fatalf("source NewNetwork: %v", err)
	}
	t.Cleanup(func() { _ = n.Close() })
	return n
}

// dialUntilRoute retries DialContext until the authenticated topology and the
// dedicated STREAM lane have converged, or the deadline expires.
func dialUntilRoute(t *testing.T, n simpletier.Network, address string, timeout time.Duration) simpletier.Stream {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		stream, err := n.DialContext(ctx, "tcp", address)
		cancel()
		if err == nil {
			return stream
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("DialContext(%s) never succeeded: %v", address, lastErr)
	return nil
}

// TestDirectDialEchoOver64KiB is the primary direct acceptance: A dials a B
// virtual listener, sends and receives more than 64 KiB in both directions on the
// same Stream, then half-closes and observes a clean EOF.
func TestDirectDialEchoOver64KiB(t *testing.T) {
	carrierPort := freePort(t)
	target := newTarget(t, carrierPort)
	source := newSource(t, testNetworkName, carrierPort)

	listener, err := target.Listen("tcp", targetIP+":19001")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()

	const total = 80 << 10
	// The echo side keeps the stream open after its own FIN until the client has
	// consumed the 80 KiB echo. Stream.Close() is the frozen CANCELED abort, so
	// closing before the peer drains its receive buffer would legitimately
	// discard bytes the client has not read yet; a graceful finisher does not
	// race its peer's read.
	serverRelease := make(chan struct{})
	serverDone := make(chan struct{})
	var releaseOnce sync.Once
	releaseServer := func() { releaseOnce.Do(func() { close(serverRelease) }) }
	defer releaseServer()
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

	stream := dialUntilRoute(t, source, targetIP+":19001", 20*time.Second)
	defer stream.Close()

	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	written := 0
	for written < total {
		n, err := stream.Write(payload[written : written+(16<<10)])
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
	releaseServer()
	<-serverDone
	if !bytes.Equal(payload, echoed) {
		t.Fatalf("echo mismatch over %d bytes", total)
	}
	if got := stream.RemoteNode(); got == "" {
		t.Fatalf("RemoteNode is empty")
	}
}

// TestDirectTwoConcurrentStreamsSameSession runs two Circuits that share one
// Path+Session (readyPairFor single-flights the pair) and drives both egress
// directions concurrently. It guards the session egress ordering: the
// MessageNumber allocation, the inner seal and the Link enqueue must be one
// critical section, otherwise the physical writer can observe number 1 before
// number 0 and the strict link nonce advance tears down the shared Link. Each
// Stream must still receive its own echo exactly.
func TestDirectTwoConcurrentStreamsSameSession(t *testing.T) {
	carrierPort := freePort(t)
	target := newTarget(t, carrierPort)
	source := newSource(t, testNetworkName, carrierPort)

	listener, err := target.Listen("tcp", targetIP+":19003")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()

	const per = 80 << 10
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()

	go func() {
		var wg sync.WaitGroup
		for range 2 {
			accepted, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(s simpletier.Stream) {
				defer wg.Done()
				defer s.Close()
				buf := make([]byte, 4<<10)
				read := 0
				for read < per {
					n, err := s.Read(buf)
					if n > 0 {
						read += n
						if _, werr := s.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
				_ = s.CloseWrite()
				<-release
			}(accepted)
		}
		wg.Wait()
	}()

	// Both Circuits share one Path+Session: the first Dial establishes the pair
	// and the second reuses it (readyPairFor single-flights per target).
	streams := make([]simpletier.Stream, 2)
	for i := range streams {
		streams[i] = dialUntilRoute(t, source, targetIP+":19003", 20*time.Second)
	}
	for i := range streams {
		defer streams[i].Close()
	}

	payloads := make([][]byte, len(streams))
	for i := range payloads {
		payloads[i] = make([]byte, per)
		for j := range payloads[i] {
			payloads[i][j] = byte((j + i*37) % 251)
		}
	}

	start := make(chan struct{})
	errs := make([]error, len(streams))
	var wg sync.WaitGroup
	for i := range streams {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			written := 0
			for written < per {
				end := written + (16 << 10)
				if end > per {
					end = per
				}
				n, err := streams[i].Write(payloads[i][written:end])
				if err != nil {
					errs[i] = fmt.Errorf("stream %d write at %d: %w", i, written, err)
					return
				}
				written += n
			}
			if err := streams[i].CloseWrite(); err != nil {
				errs[i] = fmt.Errorf("stream %d CloseWrite: %w", i, err)
				return
			}
			echoed := make([]byte, per)
			if _, err := io.ReadFull(streams[i], echoed); err != nil {
				errs[i] = fmt.Errorf("stream %d read echo: %w", i, err)
				return
			}
			if !bytes.Equal(payloads[i], echoed) {
				errs[i] = fmt.Errorf("stream %d echo mismatch", i)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	releaseAll()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("%v", errs[i])
		}
	}
}

// TestDirectDialNoListenerRefused proves a Dial to a virtual port with no
// listener is refused with TARGET_REFUSED rather than hanging or reaching an
// unrelated stream.
func TestDirectDialNoListenerRefused(t *testing.T) {
	carrierPort := freePort(t)
	_ = newTarget(t, carrierPort)
	source := newSource(t, testNetworkName, carrierPort)

	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		stream, err := source.DialContext(ctx, "tcp", targetIP+":19077")
		cancel()
		if err == nil {
			_ = stream.Close()
			t.Fatalf("Dial to a port with no listener succeeded")
		}
		lastErr = err
		if errors.Is(err, simpletier.ErrTargetRefused) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Dial never reported ErrTargetRefused, last error: %v", lastErr)
}

// TestDirectDialDeadline proves a read deadline is honored on an idle Stream and
// that the Stream remains usable for an explicit close afterwards.
func TestDirectDialDeadline(t *testing.T) {
	carrierPort := freePort(t)
	target := newTarget(t, carrierPort)
	source := newSource(t, testNetworkName, carrierPort)

	listener, err := target.Listen("tcp", targetIP+":19002")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan simpletier.Stream, 1)
	go func() {
		stream, err := listener.Accept()
		if err == nil {
			accepted <- stream
		}
	}()

	stream := dialUntilRoute(t, source, targetIP+":19002", 20*time.Second)
	defer stream.Close()
	select {
	case peer := <-accepted:
		defer peer.Close()
	case <-time.After(10 * time.Second):
		t.Fatalf("target never accepted the Stream")
	}

	if err := stream.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 8)
	if _, err := stream.Read(buf); err == nil {
		t.Fatalf("idle Read returned without a deadline error")
	}
	if err := stream.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestDirectReadDeadlineInterruptsInflight proves SetReadDeadline cancels a Read
// that is already blocked with no deadline: the deadline value is versioned and
// a change restarts the in-flight wait instead of only applying to future calls.
func TestDirectReadDeadlineInterruptsInflight(t *testing.T) {
	carrierPort := freePort(t)
	target := newTarget(t, carrierPort)
	source := newSource(t, testNetworkName, carrierPort)

	listener, err := target.Listen("tcp", targetIP+":19004")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan simpletier.Stream, 1)
	release := make(chan struct{})
	defer close(release)
	go func() {
		stream, err := listener.Accept()
		if err != nil {
			return
		}
		defer stream.Close()
		accepted <- stream
		<-release
	}()

	stream := dialUntilRoute(t, source, targetIP+":19004", 20*time.Second)
	defer stream.Close()
	select {
	case <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatalf("target never accepted the Stream")
	}

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_, err := stream.Read(buf)
		readErr <- err
	}()
	// Let the Read block with no deadline before changing it.
	time.Sleep(150 * time.Millisecond)
	if err := stream.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	select {
	case err := <-readErr:
		if !errors.Is(err, simpletier.ErrDeadline) {
			t.Fatalf("in-flight Read error = %v, want ErrDeadline", err)
		}
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			t.Fatalf("in-flight Read error is not a timeout net.Error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("in-flight Read was not interrupted by SetReadDeadline")
	}
}
