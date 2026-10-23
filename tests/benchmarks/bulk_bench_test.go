package benchmarks_test

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// Bulk payload sizes, chosen to cover the shapes real applications move: a
// small file, a photo, a video chunk, and a whole large file. The default
// benchmark suites top out at 8 MiB, which hides the queueing behaviour that
// only appears once the transfer outlives a single flow-control window.
var bulkSizes = []struct {
	name  string
	bytes int64
}{
	{"5MiB", 5 << 20},
	{"10MiB", 10 << 20},
	{"50MiB", 50 << 20},
	{"100MiB", 100 << 20},
}

// BenchmarkBulk measures a single echo stream moving whole-payload sizes, with
// one 60 KiB write per frame — the shape of a file copy rather than a
// request/response exchange.
func BenchmarkBulk(b *testing.B) {
	env := newPairEnv(b)
	for _, size := range bulkSizes {
		b.Run(size.name, func(b *testing.B) {
			runBulkEcho(b, env.source, env.target, env.targetIP, 19501, frameChunk, size.bytes)
		})
	}
}

// BenchmarkBulkLatency is the same transfer, reporting time to first byte and
// the per-frame round trip so a regression in either shows up separately from
// a change in total throughput.
func BenchmarkBulkLatency(b *testing.B) {
	env := newPairEnv(b)
	for _, size := range bulkSizes[:3] {
		b.Run(size.name, func(b *testing.B) {
			runBulkLatency(b, env.source, env.target, env.targetIP, 19511, frameChunk, size.bytes)
		})
	}
}

// BenchmarkStreamLatencyImpact measures one echo stream over a carrier with a
// fixed one-way delay injected on each side, so one round trip costs 2×delay.
// The payload is 60 KiB — one window — so the measurement isolates per-frame
// round trips rather than window growth.
func BenchmarkStreamLatencyImpact(b *testing.B) {
	for _, delay := range []time.Duration{0, time.Millisecond, 10 * time.Millisecond} {
		b.Run(delay.String(), func(b *testing.B) {
			env := newDelayEnv(b, delay)
			runBulkEcho(b, env.source, env.target, env.targetIP, 19521, frameChunk, frameChunk)
		})
	}
}

// BenchmarkRawTCPLatencyImpact is the bare-TCP control for the benchmark above:
// same delay, same payload, no overlay.
func BenchmarkRawTCPLatencyImpact(b *testing.B) {
	for _, delay := range []time.Duration{0, time.Millisecond, 10 * time.Millisecond} {
		b.Run(delay.String(), func(b *testing.B) {
			runRawTCPBulk(b, delay, frameChunk)
		})
	}
}

// runBulkEcho writes total bytes in chunk-sized pieces and reads each echo back
// before writing the next, which is what a synchronous file copy does.
func runBulkEcho(b *testing.B, source, target simpletier.Network, targetIP string, port, chunk int, total int64) {
	b.Helper()
	listener := listenVirtual(b, target, targetIP, port)
	server := startEchoServer(b, listener)
	stream := dialUntil(b, source, fmt.Sprintf("%s:%d", targetIP, port))
	echoHandshake(b, stream)

	payload := randPayload(b, chunk)
	buf := make([]byte, chunk)

	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var moved int64
		for moved < total {
			readErr := make(chan error, 1)
			go func() { readErr <- consumeInto(stream, buf, buf) }()
			writeErr := writeAll(stream, payload)
			received := <-readErr
			if writeErr != nil {
				b.Fatalf("bulk write: %v", writeErr)
			}
			if received != nil {
				b.Fatalf("bulk read: %v", received)
			}
			if !bytes.Equal(payload, buf) {
				b.Fatal("bulk payload mismatch")
			}
			moved += int64(chunk)
		}
	}
	b.StopTimer()
	_ = stream.Close()
	server.wait(b, 5*time.Second)
}

// runBulkLatency reports the first-byte and per-frame round trip alongside the
// throughput the harness already records.
func runBulkLatency(b *testing.B, source, target simpletier.Network, targetIP string, port, chunk int, total int64) {
	b.Helper()
	listener := listenVirtual(b, target, targetIP, port)
	server := startEchoServer(b, listener)
	stream := dialUntil(b, source, fmt.Sprintf("%s:%d", targetIP, port))
	echoHandshake(b, stream)

	payload := randPayload(b, chunk)
	buf := make([]byte, chunk)

	b.SetBytes(total)
	b.ResetTimer()
	var ttfb, perFrame time.Duration
	for i := 0; i < b.N; i++ {
		start := time.Now()
		var moved int64
		first := true
		for moved < total {
			frameStart := time.Now()
			readErr := make(chan error, 1)
			go func() { readErr <- consumeInto(stream, buf, buf) }()
			writeErr := writeAll(stream, payload)
			received := <-readErr
			if writeErr != nil {
				b.Fatalf("latency write: %v", writeErr)
			}
			if received != nil {
				b.Fatalf("latency read: %v", received)
			}
			if first {
				ttfb = time.Since(start)
				first = false
			}
			perFrame += time.Since(frameStart)
			moved += int64(chunk)
		}
	}
	b.StopTimer()
	frames := int64(0)
	if chunk > 0 {
		frames = total / int64(chunk)
	}
	if b.N > 0 && frames > 0 {
		b.ReportMetric(float64(ttfb.Microseconds()), "ttfb-µs")
		b.ReportMetric(float64((perFrame / time.Duration(frames*int64(b.N))).Microseconds()), "frame-rtt-µs")
	}
	_ = stream.Close()
	server.wait(b, 5*time.Second)
}

// runRawTCPBulk is the bare-TCP control: a loopback echo server with the same
// delay schedule, measured the same way.
func runRawTCPBulk(b *testing.B, delay time.Duration, chunk int) {
	b.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("raw listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, chunk)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					if _, err := conn.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		b.Fatalf("raw dial: %v", err)
	}
	defer conn.Close()

	payload := randPayload(b, chunk)
	buf := make([]byte, chunk)
	total := int64(chunk)

	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if delay > 0 {
			time.Sleep(delay)
		}
		if err := writeAllRaw(conn, payload); err != nil {
			b.Fatalf("raw write: %v", err)
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		if _, err := readFullRaw(conn, buf); err != nil {
			b.Fatalf("raw read: %v", err)
		}
		_ = start
	}
}

func writeAllRaw(conn net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := conn.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func readFullRaw(conn net.Conn, p []byte) (int, error) {
	read := 0
	for read < len(p) {
		n, err := conn.Read(p[read:])
		if err != nil {
			return read, err
		}
		read += n
	}
	return read, nil
}

// delayEnv is a direct A-B topology whose carrier path runs through a loopback
// proxy that holds every byte for the configured one-way delay on each side, so
// one round trip costs 2×delay — the RTT basis of 10-data-plane.md.
type delayEnv struct {
	*pairEnv
}

// newDelayEnv builds the pair topology with the carrier path delayed in both
// directions: source upstreams into the proxy, which forwards to the target's
// carrier after holding each chunk for one-way delay. One round trip therefore
// crosses the proxy twice, costing 2×delay.
func newDelayEnv(tb testing.TB, delay time.Duration) *delayEnv {
	tb.Helper()
	carrierPort := freeLoopbackPort(tb)
	target := newBenchNetwork(tb, carrierPort, nil, nodeBIP)
	proxy := startDelayProxy(tb, delay, fmt.Sprintf("127.0.0.1:%d", carrierPort))
	source := newBenchNetworkURL(tb, freeLoopbackPort(tb), []string{"tcp://" + proxy.addr()}, nodeAIP)
	return &delayEnv{pairEnv: &pairEnv{
		target: target, source: source, targetIP: nodeBIP, sourceIP: nodeAIP,
	}}
}

// delayProxy accepts loopback TCP and echoes it back after holding each chunk
// for the configured delay.
type delayProxy struct {
	listener net.Listener
	delay    time.Duration
	upstream string
}

func startDelayProxy(tb testing.TB, delay time.Duration, upstream string) *delayProxy {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("delay proxy listen: %v", err)
	}
	p := &delayProxy{listener: listener, delay: delay, upstream: upstream}
	tb.Cleanup(func() { _ = listener.Close() })
	go p.serve()
	return p
}

func (p *delayProxy) addr() string { return p.listener.Addr().String() }

func (p *delayProxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *delayProxy) handle(conn net.Conn) {
	defer conn.Close()
	upstream, err := net.Dial("tcp", p.upstream)
	if err != nil {
		return
	}
	defer upstream.Close()

	pipe := func(src, dst net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, rerr := src.Read(buf)
			if n > 0 {
				if p.delay > 0 {
					time.Sleep(p.delay)
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}
	go pipe(upstream, conn)
	pipe(conn, upstream)
}
