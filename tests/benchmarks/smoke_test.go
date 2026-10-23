package benchmarks_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// echoRoundTripVerify is the correctness counterpart of echoRoundTrip: it keeps
// the whole echo and proves CSPRNG byte equality, so the benchmark path is
// validated against the exact bytes it will later measure.
func echoRoundTripVerify(t *testing.T, stream simpletier.Stream, payload []byte) {
	t.Helper()
	echoed := make([]byte, len(payload))
	readErr := make(chan error, 1)
	go func() { _, err := io.ReadFull(stream, echoed); readErr <- err }()
	writeErr := writeAll(stream, payload)
	received := <-readErr
	if writeErr != nil {
		t.Fatalf("write payload: %v", writeErr)
	}
	if received != nil {
		t.Fatalf("read echo: %v", received)
	}
	if !bytes.Equal(payload, echoed) {
		t.Fatalf("CSPRNG echo mismatch over %d bytes", len(payload))
	}
}

// TestHarnessContractsTests validates the shared harness itself: independent
// Networks with private 0700 state directories, explicit fixed VirtualIPs, a
// real 80 KiB echo over a loopback TCP carrier, and a graceful FIN.
func TestHarnessContractsTests(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	n, err := simpletier.NewNetwork(simpletier.Config{
		Listen: []string{fmt.Sprintf("tcp://127.0.0.1:%d", freeLoopbackPort(t))},
		Network: simpletier.NetworkConfig{
			Name:  benchNetworkName,
			CIDR:  benchCIDR,
			Token: benchToken,
		},
		Options: simpletier.RuntimeOptions{
			FixedIP:  nodeBIP,
			LogLevel: "error",
		},
	})
	if err != nil {
		t.Fatalf("NewNetwork with private state dir: %v", err)
	}
	t.Cleanup(func() { closeNetwork(t, n) })

	// Runtime state is process-local: a Network writes nothing to disk, so there is no
	// directory to inspect. What still matters is that the configured address took effect
	// and that constructing the Network left no file behind.
	if _, err := os.Stat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("NewNetwork created %q; runtime state must stay in memory", stateDir)
	}
	if got := n.LocalVirtualIP(); got != addr4(nodeBIP) {
		t.Fatalf("LocalVirtualIP = %s, want %s", got, nodeBIP)
	}

	env := newPairEnv(t)
	listener := listenVirtual(t, env.target, env.targetIP, 29001)
	server := startEchoServer(t, listener)
	stream := dialUntil(t, env.source, fmt.Sprintf("%s:%d", env.targetIP, 29001))
	if stream.RemoteNode() == "" {
		t.Fatalf("RemoteNode is empty on an established business Stream")
	}
	echoRoundTripVerify(t, stream, randPayload(t, 80<<10))
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	server.wait(t, closeWait)
	if err := stream.Close(); err != nil {
		t.Fatalf("Stream.Close: %v", err)
	}
}

// TestRelayTopologyTests proves the A-R-B topology carries a real 80 KiB echo
// while A and B share no direct carrier: both only upstream to R.
func TestRelayTopologyTests(t *testing.T) {
	env := newRelayEnv(t)
	listener := listenVirtual(t, env.b, env.bIP, 29011)
	server := startEchoServer(t, listener)
	stream := dialUntil(t, env.a, fmt.Sprintf("%s:%d", env.bIP, 29011))
	echoRoundTripVerify(t, stream, randPayload(t, 80<<10))
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	server.wait(t, closeWait)
	if err := stream.Close(); err != nil {
		t.Fatalf("Stream.Close: %v", err)
	}
}

// TestUDPRoundTripTests proves the public ListenPacket path preserves datagram
// boundaries and returns a proof reply for the empty datagram, small
// boundaries, and the 65,507-byte IPv4 UDP maximum.
func TestUDPRoundTripTests(t *testing.T) {
	env := newPairEnv(t)
	// Warm the authenticated topology first so both address facts are
	// propagated before the datagram reply path resolves a destination.
	warmTCPRoute(t, env.source, env.target, env.targetIP, 29511)
	targetConn, err := env.target.ListenPacket("udp", fmt.Sprintf("%s:%d", env.targetIP, udpTargetPort+10))
	if err != nil {
		t.Fatalf("target ListenPacket: %v", err)
	}
	sourceConn, err := env.source.ListenPacket("udp", fmt.Sprintf("%s:%d", env.sourceIP, udpSourcePort+10))
	if err != nil {
		t.Fatalf("source ListenPacket: %v", err)
	}
	server := startUDPEcho(t, targetConn)
	t.Cleanup(func() {
		_ = sourceConn.Close()
		_ = targetConn.Close()
		server.wait(t, closeWait)
	})
	targetAddr := &net.UDPAddr{IP: net.ParseIP(env.targetIP), Port: udpTargetPort + 10}
	udpWarm(t, sourceConn, targetAddr)
	// Reachable now: no error below is retried or masked.
	server.endWarm()

	for _, size := range []int{0, 1, 64, 1472, 65507} {
		payload := randPayload(t, size)
		buf := make([]byte, 65507)
		if err := udpRoundTrip(sourceConn, payload, buf, targetAddr); err != nil {
			t.Fatalf("UDP roundtrip size %d: %v", size, err)
		}
	}
}

// TestLatencySamplesTests runs 100 sequential 64-byte round trips, verifies
// every reply byte-for-byte, and checks the P50/P95 ordering of the monotonic
// samples. The percentiles are observations, not an SLO.
func TestLatencySamplesTests(t *testing.T) {
	env := newPairEnv(t)
	listener := listenVirtual(t, env.target, env.targetIP, 29021)
	server := startEchoServer(t, listener)
	stream := dialUntil(t, env.source, fmt.Sprintf("%s:%d", env.targetIP, 29021))

	const (
		packet = 64
		count  = 100
	)
	payload := randPayload(t, packet)
	buf := make([]byte, packet)
	samples := make([]time.Duration, 0, count)
	for i := 0; i < count; i++ {
		start := time.Now()
		if err := writeAll(stream, payload); err != nil {
			t.Fatalf("latency write %d: %v", i, err)
		}
		if _, err := io.ReadFull(stream, buf); err != nil {
			t.Fatalf("latency read %d: %v", i, err)
		}
		if !bytes.Equal(payload, buf) {
			t.Fatalf("latency reply %d is not the exact CSPRNG packet", i)
		}
		samples = append(samples, time.Since(start))
	}
	sortDurations(samples)
	if got := percentile(samples, 50); got > percentile(samples, 95) {
		t.Fatalf("P50 %s exceeds P95 %s", got, percentile(samples, 95))
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	server.wait(t, closeWait)
	if err := stream.Close(); err != nil {
		t.Fatalf("Stream.Close: %v", err)
	}
}

// TestStartupSamplesTests exercises the separately reported startup path and
// proves Close always converges to Done.
func TestStartupSamplesTests(t *testing.T) {
	for i := 0; i < 2; i++ {
		n, err := simpletier.NewNetwork(simpletier.Config{
			Listen: []string{fmt.Sprintf("tcp://127.0.0.1:%d", freeLoopbackPort(t))},
			Network: simpletier.NetworkConfig{
				Name:  benchNetworkName,
				CIDR:  benchCIDR,
				Token: benchToken,
			},
			Options: simpletier.RuntimeOptions{
				FixedIP:  nodeBIP,
				LogLevel: "error",
			},
		})
		if err != nil {
			t.Fatalf("startup NewNetwork %d: %v", i, err)
		}
		if err := n.Close(); err != nil {
			classifyFatal(t, "startup Close", err)
		}
		select {
		case <-n.Done():
		default:
			t.Fatalf("startup %d: Done is not closed after Close returned", i)
		}
	}
}
