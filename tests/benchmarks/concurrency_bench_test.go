package benchmarks_test

// Concurrency and bandwidth benchmarks.
//
// stream_bench_test.go measures one Stream at a time across payload sizes. This
// file answers the other two questions an operator asks about a network:
//
//   - how does throughput scale as concurrent Streams are added, and where does
//     it stop scaling;
//   - what bandwidth a single Stream actually sustains while it is running, and
//     what the extra relay hop costs relative to a direct carrier.
//
// Both are measured on the same harness as the single-Stream suites, so the
// numbers are comparable: N real SDK Networks over real loopback TCP carriers,
// no mock transport.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// concurrencyLevels are the concurrent Stream counts. They are deliberately
// spaced so the shape of the curve is visible: a single Stream, a handful that
// still fit one machine's parallelism, then levels that force queueing.
var concurrencyLevels = []int{1, 2, 4}

// concurrencyPayload is the per-Stream payload for the concurrency matrix. It is
// small enough that many Streams finish inside a benchmark iteration, so the
// reported figure reflects steady-state concurrency rather than startup.
const concurrencyPayload = 60 << 10

// bandwidthPayload is the payload the bandwidth benchmarks move per iteration.
// It is large enough that the transfer dominates fixed per-Stream costs.
const bandwidthPayload = 4 << 20

// frameChunk is the per-round-trip transfer size used by the bandwidth suites.
// It equals the per-flow window, so each round trip moves exactly one window and
// the measured rate is not distorted by window stalls.
const frameChunk = 60 << 10

// concurrentEchoServer accepts Streams continuously and echoes every one of them
// until the listener closes. The single-accept startEchoServer in the harness is
// right for the one-Stream suites; a concurrency benchmark needs a server that
// keeps accepting, otherwise only the first of N Streams can ever complete and
// the remaining N-1 block in DialContext forever.
type concurrentEchoServer struct {
	listener simpletier.StreamListener
	accepted atomic.Int64
	done     chan struct{}
	closeOne sync.Once
}

func startConcurrentEchoServer(tb testing.TB, listener simpletier.StreamListener) *concurrentEchoServer {
	tb.Helper()
	server := &concurrentEchoServer{listener: listener, done: make(chan struct{})}
	go func() {
		defer server.closeOne.Do(func() { close(server.done) })
		var handlers sync.WaitGroup
		for {
			stream, err := listener.Accept()
			if err != nil {
				handlers.Wait()
				return
			}
			server.accepted.Add(1)
			handlers.Add(1)
			go func(s simpletier.Stream) {
				defer handlers.Done()
				defer func() { _ = s.Close() }()
				// Stream the echo exactly like the harness's single-Stream server:
				// read a window and write it straight back. The client drains the
				// return path in its own goroutine, so both directions make
				// progress together and neither side waits for the other to finish
				// a whole payload first.
				buf := make([]byte, maxBuffer)
				for {
					n, readErr := s.Read(buf)
					if n > 0 {
						if _, writeErr := s.Write(buf[:n]); writeErr != nil {
							return
						}
					}
					if readErr != nil {
						_ = s.CloseWrite()
						return
					}
				}
			}(stream)
		}
	}()
	return server
}

// wait blocks until every accepted Stream finished and the listener was closed.
func (s *concurrentEchoServer) wait(tb testing.TB, timeout time.Duration) {
	tb.Helper()
	select {
	case <-s.done:
	case <-time.After(timeout):
		tb.Fatalf("concurrent echo server did not finish within %s", timeout)
	}
}

// runConcurrentEcho starts level Streams that each echo a payload of size bytes
// at the same time, waits for all of them, and reports the aggregate.
//
// Each Stream gets its own virtual port so the target-side listener is shared
// but the Streams are independent: this measures concurrency of the data plane,
// not the accept loop's ability to multiplex one port.
func runConcurrentEcho(b *testing.B, source, target simpletier.Network, targetIP string, level, size int) {
	b.Helper()

	// One listener per concurrent Stream, so the measurement isolates data-plane
	// concurrency from the accept loop's ability to serve many Streams on one
	// virtual port.
	listeners := make([]simpletier.StreamListener, level)
	servers := make([]*concurrentEchoServer, level)
	addresses := make([]string, level)
	for i := 0; i < level; i++ {
		port := 19300 + level*100 + i
		listeners[i] = listenVirtual(b, target, targetIP, port)
		servers[i] = startConcurrentEchoServer(b, listeners[i])
		addresses[i] = fmt.Sprintf("%s:%d", targetIP, port)
	}

	payload := randPayload(b, size)

	// Establish every Stream before the timer starts. Opening a Stream publishes a
	// FACT change, so doing it inside the timed region would measure the control
	// plane's fact-snapshot cost rather than the data plane's concurrency. The
	// streams stay open for the whole benchmark and each iteration drives them
	// concurrently, which is the shape a real concurrent workload has.
	streams := make([]simpletier.Stream, level)
	for i := 0; i < level; i++ {
		streams[i] = dialUntil(b, source, addresses[i])
		echoHandshake(b, streams[i])
	}

	b.SetBytes(int64(size) * int64(level))
	b.ResetTimer()

	for iteration := 0; iteration < b.N; iteration++ {
		var wg sync.WaitGroup
		var failed atomic.Int64
		var firstErr atomic.Value

		for streamIndex := 0; streamIndex < level; streamIndex++ {
			wg.Add(1)
			go func(streamIndex int) {
				defer wg.Done()
				stream := streams[streamIndex]

				// Read into a dedicated buffer and write concurrently: writing
				// the whole payload before reading deadlocks as soon as both
				// directions' windows fill, because the peer echoes into a return
				// path nobody is draining.
				got := make([]byte, len(payload))
				window := make([]byte, len(payload))
				readErr := make(chan error, 1)
				go func() { readErr <- consumeInto(stream, got, window) }()
				writeErr := writeAll(stream, payload)
				received := <-readErr
				if writeErr != nil {
					if failed.Add(1) == 1 {
						firstErr.CompareAndSwap(nil, writeErr)
					}
					return
				}
				if received != nil {
					if failed.Add(1) == 1 {
						firstErr.CompareAndSwap(nil, received)
					}
					return
				}
				if !bytes.Equal(payload, got) {
					if failed.Add(1) == 1 {
						firstErr.CompareAndSwap(nil, fmt.Errorf("echo payload mismatch on concurrent stream"))
					}
				}
			}(streamIndex)
		}
		wg.Wait()

		if n := failed.Load(); n > 0 {
			b.Fatalf("level %d: %d of %d streams failed: %v", level, n, level, firstErr.Load())
		}
	}

	b.StopTimer()
	for i := 0; i < level; i++ {
		_ = closeStream(b, streams[i])
	}
	for i := 0; i < level; i++ {
		_ = listeners[i].Close()
		servers[i].wait(b, closeWait)
	}
}

// BenchmarkStreamConcurrency measures how aggregate throughput changes as
// concurrent Streams are added, over a direct carrier.
//
// bandwidth is bytes/op per Stream times the level, so MB/s already accounts for
// the concurrency: a level that doubles the Stream count but halves MB/s has
// gained nothing.
func BenchmarkStreamConcurrency(b *testing.B) {
	env := newPairEnv(b)
	for _, level := range concurrencyLevels {
		level := level
		b.Run(fmt.Sprintf("streams-%02d", level), func(b *testing.B) {
			runConcurrentEcho(b, env.source, env.target, env.targetIP, level, concurrencyPayload)
		})
	}
}

// BenchmarkStreamConcurrencyRelay is the same matrix across the A-R-B path, so
// the cost of the extra hop is visible per concurrency level rather than only in
// the single-Stream case.
func BenchmarkStreamConcurrencyRelay(b *testing.B) {
	env := newRelayEnv(b)
	for _, level := range concurrencyLevels {
		level := level
		b.Run(fmt.Sprintf("streams-%02d", level), func(b *testing.B) {
			runConcurrentEcho(b, env.a, env.b, env.bIP, level, concurrencyPayload)
		})
	}
}

// measureLatencies returns the sorted round-trip times of n small exchanges, so
// the caller can report percentiles instead of only a mean.
func measureLatencies(b *testing.B, stream simpletier.Stream, n int) []time.Duration {
	b.Helper()
	const probe = 64
	payload := randPayload(b, probe)
	buf := make([]byte, probe)
	samples := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if err := writeAll(stream, payload); err != nil {
			b.Fatalf("latency write: %v", err)
		}
		if _, err := io.ReadFull(stream, buf); err != nil {
			b.Fatalf("latency read: %v", err)
		}
		samples = append(samples, time.Since(start))
	}
	sortDurations(samples)
	return samples
}

// runBandwidthEcho moves total bytes through one echo Stream in frame-sized
// pieces and reports the sustained rate.
//
// It deliberately does not write one huge buffer: the per-flow window is 64 KiB,
// so a single multi-megabyte Write would spend its time waiting for window
// updates rather than measuring throughput, and the benchmark would look like a
// timeout. Chunking into frame-sized round trips measures the rate this runtime
// actually sustains.
func runBandwidthEcho(b *testing.B, source, target simpletier.Network, targetIP string, port int, chunk int, total int64) {
	b.Helper()
	listener := listenVirtual(b, target, targetIP, port)
	server := startEchoServer(b, listener)
	stream := dialUntil(b, source, fmt.Sprintf("%s:%d", targetIP, port))
	echoHandshake(b, stream)

	payload := randPayload(b, chunk)
	buf := make([]byte, chunk)
	window := make([]byte, chunk)

	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var moved int64
		for moved < total {
			readErr := make(chan error, 1)
			go func() { readErr <- consumeInto(stream, buf, window) }()
			writeErr := writeAll(stream, payload)
			received := <-readErr
			if writeErr != nil {
				b.Fatalf("bandwidth write: %v", writeErr)
			}
			if received != nil {
				b.Fatalf("bandwidth read: %v", received)
			}
			if !bytes.Equal(payload, buf) {
				b.Fatal("bandwidth payload mismatch")
			}
			moved += int64(chunk)
		}
	}
	b.StopTimer()

	if err := closeStream(b, stream); err != nil {
		b.Fatalf("close stream: %v", err)
	}
	if err := server.errOrNil(); err != nil {
		b.Fatalf("target server: %v", err)
	}
	server.wait(b, closeWait)
}

// BenchmarkStreamBandwidth measures the sustained rate of one Stream over a
// direct carrier with echo semantics: every byte makes the round trip, so the
// figure is the achievable end-to-end rate, not the one-way line rate.
func BenchmarkStreamBandwidth(b *testing.B) {
	env := newPairEnv(b)
	b.Run("echo-4MiB", func(b *testing.B) {
		runBandwidthEcho(b, env.source, env.target, env.targetIP, 19401, frameChunk, bandwidthPayload)
	})
}

// BenchmarkStreamBandwidthRelay is the same transfer across A-R-B.
func BenchmarkStreamBandwidthRelay(b *testing.B) {
	env := newRelayEnv(b)
	b.Run("echo-4MiB", func(b *testing.B) {
		runBandwidthEcho(b, env.a, env.b, env.bIP, 19402, frameChunk, bandwidthPayload)
	})
}

// runBandwidthDiscard measures a one-way transfer: the source writes and the
// target consumes without echoing. No bytes come back, so this exposes the
// sender-bound ceiling that the echo benchmarks hide behind the return path.
func runBandwidthDiscard(b *testing.B, source, target simpletier.Network, targetIP string, port int, chunk int, total int64) {
	b.Helper()
	listener := listenVirtual(b, target, targetIP, port)
	server := startDiscardServer(b, listener)
	stream := dialUntil(b, source, fmt.Sprintf("%s:%d", targetIP, port))
	discardHandshake(b, stream, server)

	payload := randPayload(b, chunk)

	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var written int64
		for written < total {
			if err := writeAll(stream, payload); err != nil {
				b.Fatalf("discard write: %v", err)
			}
			written += int64(len(payload))
		}
		b.StopTimer()
		server.awaitConsumed(b, total*int64(i+1))
		b.StartTimer()
	}
	b.StopTimer()

	if err := closeStream(b, stream); err != nil {
		b.Fatalf("close stream: %v", err)
	}
	if err := server.errOrNil(); err != nil {
		b.Fatalf("target server: %v", err)
	}
	server.wait(b, closeWait)
}

// BenchmarkStreamBandwidthOneWay measures the sender-bound one-way ceiling on a
// direct carrier. 16 MiB per iteration keeps the transfer long enough that the
// per-iteration setup does not dominate.
func BenchmarkStreamBandwidthOneWay(b *testing.B) {
	const total = 16 << 20
	env := newPairEnv(b)
	b.Run("discard-16MiB", func(b *testing.B) {
		runBandwidthDiscard(b, env.source, env.target, env.targetIP, 19501, maxBuffer, total)
	})
}

// BenchmarkStreamBandwidthOneWayRelay is the same one-way transfer across A-R-B,
// which is where a relay hop's extra copy and re-framing shows up most directly.
func BenchmarkStreamBandwidthOneWayRelay(b *testing.B) {
	const total = 16 << 20
	env := newRelayEnv(b)
	b.Run("discard-16MiB", func(b *testing.B) {
		runBandwidthDiscard(b, env.a, env.b, env.bIP, 19502, maxBuffer, total)
	})
}

// BenchmarkStreamLatency measures small-message round-trip latency on both
// topologies. Percentiles rather than a mean, because tail latency is what a
// control-plane operation actually feels.
func BenchmarkStreamLatency(b *testing.B) {
	const samples = 200
	env := newPairEnv(b)

	b.Run("direct", func(b *testing.B) {
		listener := listenVirtual(b, env.target, env.targetIP, 19601)
		server := startEchoServer(b, listener)
		stream := dialUntil(b, env.source, fmt.Sprintf("%s:%d", env.targetIP, 19601))
		echoHandshake(b, stream)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			latencies := measureLatencies(b, stream, samples)
			b.ReportMetric(float64(percentile(latencies, 50).Nanoseconds()), "p50-ns")
			b.ReportMetric(float64(percentile(latencies, 95).Nanoseconds()), "p95-ns")
			b.ReportMetric(float64(percentile(latencies, 99).Nanoseconds()), "p99-ns")
		}
		b.StopTimer()

		_ = closeStream(b, stream)
		server.wait(b, closeWait)
	})
}

// BenchmarkStreamLatencyRelay is the same probe across the relay hop.
func BenchmarkStreamLatencyRelay(b *testing.B) {
	const samples = 200
	env := newRelayEnv(b)

	b.Run("relay", func(b *testing.B) {
		listener := listenVirtual(b, env.b, env.bIP, 19602)
		server := startEchoServer(b, listener)
		stream := dialUntil(b, env.a, fmt.Sprintf("%s:%d", env.bIP, 19602))
		echoHandshake(b, stream)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			latencies := measureLatencies(b, stream, samples)
			b.ReportMetric(float64(percentile(latencies, 50).Nanoseconds()), "p50-ns")
			b.ReportMetric(float64(percentile(latencies, 95).Nanoseconds()), "p95-ns")
			b.ReportMetric(float64(percentile(latencies, 99).Nanoseconds()), "p99-ns")
		}
		b.StopTimer()

		_ = closeStream(b, stream)
		server.wait(b, closeWait)
	})
}

// consumeInto fills dst from r using a smaller window, so a large payload can be
// compared byte for byte without requiring the reader to hold the whole transfer
// in one buffer sized read.
func consumeInto(r io.Reader, dst, window []byte) error {
	filled := 0
	for filled < len(dst) {
		slice := window
		if remaining := len(dst) - filled; remaining < len(slice) {
			slice = slice[:remaining]
		}
		n, err := r.Read(slice)
		if n > 0 {
			copy(dst[filled:], slice[:n])
			filled += n
		}
		if err != nil {
			if errors.Is(err, io.EOF) && filled == len(dst) {
				return nil
			}
			return err
		}
	}
	return nil
}
