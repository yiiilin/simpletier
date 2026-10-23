package benchmarks_test

// The six dimensions that matter for deployment decisions, each measured on a
// direct two-node path and on a three-node relayed path:
//
//	download throughput   target sends, source receives
//	upload throughput     source sends, target receives
//	download latency      time to first byte and steady block cost, target sends
//	upload latency        same, source sends
//	concurrency           N streams at once, aggregate throughput
//
// Both directions are measured because they are not symmetric: a relay forwards
// in one direction with a different number of AEAD operations per byte, and the
// credit frontier is per direction.
//
// Every throughput case is pipelined. Latency cases use the same payload and
// report both TTFB and the steady block cost, so "slow to start" and "slow
// throughout" stay distinguishable.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// benchTopologies are the two paths every dimension is measured on.
//
// direct: source --carrier--> target
// relay:  source --carrier--> relay --carrier--> target
type benchTopology struct {
	name     string
	source   simpletier.Network
	target   simpletier.Network
	targetIP string
}

// withTopologies runs fn once per topology, so every dimension reports both paths.
func withTopologies(b *testing.B, fn func(b *testing.B, topo benchTopology, port int)) {
	b.Helper()
	b.Run("direct", func(b *testing.B) {
		env := newPairEnv(b)
		fn(b, benchTopology{name: "direct", source: env.source, target: env.target, targetIP: env.targetIP}, 26000)
	})
	b.Run("relay", func(b *testing.B) {
		env := newRelayEnv(b)
		fn(b, benchTopology{name: "relay", source: env.a, target: env.b, targetIP: env.bIP}, 26200)
	})
}

// downloadHandshake signals the sending peer that the receiver is ready. The
// sender holds its payload until this byte arrives, so the first payload block
// cannot be mistaken for handshake traffic.
func downloadHandshake(tb testing.TB, stream simpletier.Stream) {
	tb.Helper()
	if err := writeAll(stream, []byte{0x5a}); err != nil {
		tb.Fatalf("download handshake write: %v", err)
	}
}

// benchRTTs is the round-trip matrix the latency suites cover. Latency on a real
// deployment is dominated by round-trip time, so loopback alone says very little
// about it.
var benchRTTs = []time.Duration{
	0,
	1 * time.Millisecond,
	10 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	200 * time.Millisecond,
	500 * time.Millisecond,
	1 * time.Second,
}

// withLatencyTopologies runs fn for every topology at every round-trip time. The
// proxy injects one-way delay on each carrier, so a direct path pays 2*delay per
// round trip and a relayed path pays it on both hops.
func withLatencyTopologies(b *testing.B, fn func(b *testing.B, topo benchTopology, port int)) {
	b.Helper()
	for _, rtt := range benchRTTs {
		rtt := rtt
		b.Run("rtt-"+rtt.String()+"/direct", func(b *testing.B) {
			env := newLatencyPairEnv(b, rtt/2)
			fn(b, benchTopology{name: "direct", source: env.source, target: env.target, targetIP: env.targetIP}, 27000)
		})
		if rtt > 0 {
			// A relayed path with two delayed hops takes twice as long per round
			// trip, so the slowest entries are skipped to keep the suite runnable.
			if rtt >= 500*time.Millisecond {
				continue
			}
			b.Run("rtt-"+rtt.String()+"/relay", func(b *testing.B) {
				source, target := newLatencyRelayEnv(b, rtt/2)
				fn(b, benchTopology{name: "relay", source: source, target: target, targetIP: nodeBIP}, 27200)
			})
		}
	}
}

// BenchmarkRawTCPLatency is the plain net.Conn control for the latency suites: the
// same RTT matrix over the same proxy, with no overlay. The gap between the two is
// the overlay's latency cost at that round-trip time.
func BenchmarkRawTCPLatency(b *testing.B) {
	for _, rtt := range benchRTTs {
		rtt := rtt
		b.Run("rtt-"+rtt.String(), func(b *testing.B) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatalf("listen: %v", err)
			}
			server := startRawEchoServer(b, listener)
			proxy := startLatencyProxy(b, listener.Addr().String(), rtt/2)

			conn, err := net.Dial("tcp", proxy.addr())
			if err != nil {
				b.Fatalf("dial: %v", err)
			}

			block := make([]byte, benchFrameChunk)
			got := make([]byte, benchFrameChunk)

			b.SetBytes(benchLatencyPayload)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchPattern(block, 0)
				firstStart := time.Now()
				rawEchoRoundTrip(b, conn, block, got, got)
				ttfb := time.Since(firstStart)

				rest := benchLatencyPayload - int64(len(block))
				steadyStart := time.Now()
				var moved int64
				for moved < rest {
					n := int64(len(block))
					if remaining := rest - moved; remaining < n {
						n = remaining
					}
					benchPattern(block[:n], int64(len(block))+moved)
					rawEchoRoundTrip(b, conn, block[:n], got[:n], got[:n])
					moved += n
				}
				steady := time.Since(steadyStart)

				blocks := float64(rest) / float64(benchFrameChunk)
				b.ReportMetric(float64(ttfb.Microseconds()), "ttfb-us")
				b.ReportMetric(float64(steady.Microseconds())/blocks, "block-us")
				b.ReportMetric(float64(benchLatencyPayload)/steady.Seconds()/1e6, "MB/s")
			}
			b.StopTimer()

			_ = conn.Close()
			_ = listener.Close()
			server.wait(b)
		})
	}
}

// startSendServer accepts one stream and writes total bytes to it, which is the
// shape of a download from the target's point of view.
func startSendServer(tb testing.TB, listener simpletier.StreamListener, total int64, rounds *int64) *sendServer {
	tb.Helper()
	server := &sendServer{done: make(chan struct{})}
	go func() {
		defer close(server.done)
		stream, err := listener.Accept()
		if err != nil {
			server.fail(err)
			return
		}
		defer func() { _ = stream.Close() }()
		// Wait for the receiver's ready byte before sending anything. Without this
		// the first payload bytes race the handshake marker and the receiver sees
		// shifted data, which looks like a payload mismatch rather than a race.
		ready := make([]byte, 1)
		if _, err := io.ReadFull(stream, ready); err != nil {
			server.fail(fmt.Errorf("send server ready byte: %w", err))
			return
		}
		block := make([]byte, benchFrameChunk)
		// Wait for the benchmark to publish how many rounds it will run. Reading 0
		// here would close the stream before the first timed iteration and the
		// client would see EOF at byte zero.
		want := int64(1)
		if rounds != nil {
			// Wait for the benchmark to publish its round count; reading 0 would
			// close the stream before the first timed iteration and the client
			// would see EOF at byte zero.
			for atomic.LoadInt64(rounds) == 0 {
				time.Sleep(time.Millisecond)
			}
			want = atomic.LoadInt64(rounds)
		}
		for round := int64(0); round < want; round++ {
			var written int64
			for written < total {
				n := int64(len(block))
				if remaining := total - written; remaining < n {
					n = remaining
				}
				chunk := block[:n]
				benchPattern(chunk, written)
				if err := writeAll(stream, chunk); err != nil {
					server.fail(err)
					return
				}
				written += n
			}
		}
		if err := stream.CloseWrite(); err != nil {
			server.fail(err)
			return
		}
		// Drain until the peer closes so the sender's CloseWrite is observable.
		drain := make([]byte, maxBuffer)
		for {
			if _, err := stream.Read(drain); err != nil {
				return
			}
		}
	}()
	return server
}

type sendServer struct {
	done chan struct{}
	err  error
	mu   sync.Mutex
}

func (s *sendServer) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
}

func (s *sendServer) errOrNil() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *sendServer) wait(tb testing.TB) {
	tb.Helper()
	<-s.done
	if err := s.errOrNil(); err != nil {
		tb.Fatalf("send server: %v", err)
	}
}

// BenchmarkDownloadThroughput: target sends, source receives and verifies.
func BenchmarkDownloadThroughput(b *testing.B) {
	withTopologies(b, func(b *testing.B, topo benchTopology, port int) {
		listener := listenVirtual(b, topo.target, topo.targetIP, port)
		rounds := new(int64)
		server := startSendServer(b, listener, benchSteadySize, rounds)
		stream := dialUntil(b, topo.source, addr4String(topo.targetIP, port))
		downloadHandshake(b, stream)

		buf := make([]byte, benchFrameChunk)
		expected := make([]byte, benchFrameChunk)

		b.SetBytes(benchSteadySize)
		b.ResetTimer()
		atomic.StoreInt64(rounds, int64(b.N))
		for i := 0; i < b.N; i++ {
			start := time.Now()
			downloadReader(b, stream, benchSteadySize, buf, expected)
			b.ReportMetric(float64(time.Since(start).Milliseconds()), "total-ms")
		}
		b.StopTimer()

		_ = closeStream(b, stream)
		_ = listener.Close()
		server.wait(b)
	})
}

// BenchmarkUploadThroughput: source sends, target receives and discards.
func BenchmarkUploadThroughput(b *testing.B) {
	withTopologies(b, func(b *testing.B, topo benchTopology, port int) {
		listener := listenVirtual(b, topo.target, topo.targetIP, port)
		server := startDiscardServer(b, listener)
		stream := dialUntil(b, topo.source, addr4String(topo.targetIP, port))
		discardHandshake(b, stream, server)

		block := make([]byte, benchFrameChunk)

		b.SetBytes(benchSteadySize)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			start := time.Now()
			// The sink stays open across iterations; only CloseWrite ends the
			// stream, which happens after the last round.
			uploadWriter(b, stream, benchSteadySize, block)
			server.awaitConsumed(b, benchSteadySize*int64(i+1))
			b.ReportMetric(float64(time.Since(start).Milliseconds()), "total-ms")
		}
		b.StopTimer()

		if err := stream.CloseWrite(); err != nil {
			b.Fatalf("CloseWrite: %v", err)
		}
		_ = closeStream(b, stream)
		_ = listener.Close()
		server.wait(b, closeWait)
	})
}

// uploadWriter streams total bytes without closing the write side, so the same
// stream can serve every timed iteration.
func uploadWriter(tb testing.TB, stream simpletier.Stream, total int64, block []byte) {
	tb.Helper()
	var written int64
	for written < total {
		n := int64(len(block))
		if remaining := total - written; remaining < n {
			n = remaining
		}
		chunk := block[:n]
		benchPattern(chunk, written)
		if err := writeAll(stream, chunk); err != nil {
			tb.Fatalf("upload write at %d of %d: %v", written, total, err)
		}
		written += n
	}
}

// BenchmarkDownloadLatency: the target sends; the source reports time to first
// byte and the steady per-block cost.
func BenchmarkDownloadLatency(b *testing.B) {
	withLatencyTopologies(b, func(b *testing.B, topo benchTopology, port int) {
		listener := listenVirtual(b, topo.target, topo.targetIP, port)
		rounds := new(int64)
		server := startSendServer(b, listener, benchLatencyPayload, rounds)
		stream := dialUntil(b, topo.source, addr4String(topo.targetIP, port))
		downloadHandshake(b, stream)

		buf := make([]byte, benchFrameChunk)
		expected := make([]byte, benchFrameChunk)

		b.SetBytes(benchLatencyPayload)
		b.ResetTimer()
		atomic.StoreInt64(rounds, int64(b.N))
		for i := 0; i < b.N; i++ {
			firstStart := time.Now()
			if _, err := io.ReadFull(stream, buf); err != nil {
				b.Fatalf("first block: %v", err)
			}
			ttfb := time.Since(firstStart)

			rest := benchLatencyPayload - int64(len(buf))
			steadyStart := time.Now()
			var read int64
			for read < rest {
				n := int64(len(buf))
				if remaining := rest - read; remaining < n {
					n = remaining
				}
				if _, err := io.ReadFull(stream, buf[:n]); err != nil {
					b.Fatalf("steady read: %v", err)
				}
				benchPattern(expected[:n], int64(len(buf))+read)
				if !bytesEqual(buf[:n], expected[:n]) {
					b.Fatalf("payload mismatch at %d", read)
				}
				read += n
			}
			steady := time.Since(steadyStart)

			blocks := float64(rest) / float64(benchFrameChunk)
			b.ReportMetric(float64(ttfb.Microseconds()), "ttfb-us")
			b.ReportMetric(float64(steady.Microseconds())/blocks, "block-us")
			b.ReportMetric(float64(benchLatencyPayload)/steady.Seconds()/1e6, "MB/s")
		}
		b.StopTimer()

		_ = closeStream(b, stream)
		_ = listener.Close()
		server.wait(b)
	})
}

// BenchmarkUploadLatency: the source sends; time to first byte is when the sink
// reports the first block, and the steady cost is the rest of the payload.
func BenchmarkUploadLatency(b *testing.B) {
	withLatencyTopologies(b, func(b *testing.B, topo benchTopology, port int) {
		listener := listenVirtual(b, topo.target, topo.targetIP, port)
		server := startDiscardServer(b, listener)
		stream := dialUntil(b, topo.source, addr4String(topo.targetIP, port))
		discardHandshake(b, stream, server)

		block := make([]byte, benchFrameChunk)

		b.SetBytes(benchLatencyPayload)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			base := benchLatencyPayload * int64(i)

			benchPattern(block, 0)
			firstStart := time.Now()
			uploadWriter(b, stream, int64(len(block)), block)
			// TTFB is the first block reaching the sink; the rest is measured without
			// per-block confirmation, which would turn this into a stop-and-wait
			// measurement of the round trip rather than of the transfer.
			server.awaitConsumed(b, base+int64(len(block)))
			ttfb := time.Since(firstStart)

			rest := benchLatencyPayload - int64(len(block))
			steadyStart := time.Now()
			var written int64
			for written < rest {
				n := int64(len(block))
				if remaining := rest - written; remaining < n {
					n = remaining
				}
				chunk := block[:n]
				benchPattern(chunk, int64(len(block))+written)
				if err := writeAll(stream, chunk); err != nil {
					b.Fatalf("steady write: %v", err)
				}
				written += n
			}
			server.awaitConsumed(b, base+benchLatencyPayload)
			steady := time.Since(steadyStart)

			blocks := float64(rest) / float64(benchFrameChunk)
			b.ReportMetric(float64(ttfb.Microseconds()), "ttfb-us")
			b.ReportMetric(float64(steady.Microseconds())/blocks, "block-us")
			b.ReportMetric(float64(benchLatencyPayload)/steady.Seconds()/1e6, "MB/s")
		}
		b.StopTimer()

		_ = closeStream(b, stream)
		_ = listener.Close()
		server.wait(b, closeWait)
	})
}

// BenchmarkConcurrency: N streams transferring at once, reported as aggregate
// throughput. Per-stream work is benchConcurrentSize so the case finishes in a
// few seconds even at level 16.
func BenchmarkConcurrency(b *testing.B) {
	// 20 MiB per stream: past the start-up share and beyond the point where the
	// throughput curve flattens, so a level's number reflects sustained transfer
	// rather than connection setup.
	const concurrentSize int64 = 20 << 20

	for _, level := range []int{1, 4, 16, 32, 64, 128} {
		level := level
		b.Run(fmt.Sprintf("streams-%02d", level), func(b *testing.B) {
			withTopologies(b, func(b *testing.B, topo benchTopology, port int) {
				rounds := new(int64)
				listeners := make([]simpletier.StreamListener, level)
				servers := make([]*sendServer, level)
				addresses := make([]string, level)
				for i := 0; i < level; i++ {
					listeners[i] = listenVirtual(b, topo.target, topo.targetIP, port+i)
					servers[i] = startSendServer(b, listeners[i], concurrentSize, rounds)
					addresses[i] = addr4String(topo.targetIP, port+i)
				}

				streams := make([]simpletier.Stream, level)
				for i := 0; i < level; i++ {
					streams[i] = dialUntil(b, topo.source, addresses[i])
					downloadHandshake(b, streams[i])
				}

				b.SetBytes(concurrentSize * int64(level))
				atomic.StoreInt64(rounds, int64(b.N))
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					var wg sync.WaitGroup
					var failed sync.Once
					var firstErr error
					for i := 0; i < level; i++ {
						wg.Add(1)
						go func(i int) {
							defer wg.Done()
							buf := make([]byte, benchFrameChunk)
							expected := make([]byte, benchFrameChunk)
							if _, err := downloadReaderNoFatal(streams[i], concurrentSize, buf, expected); err != nil {
								failed.Do(func() { firstErr = err })
							}
						}(i)
					}
					wg.Wait()
					if firstErr != nil {
						b.Fatalf("level %d: %v", level, firstErr)
					}
				}
				b.StopTimer()

				for i := 0; i < level; i++ {
					_ = closeStream(b, streams[i])
				}
				for i := 0; i < level; i++ {
					_ = listeners[i].Close()
					servers[i].wait(b)
				}
			})
		})
	}
}

// downloadReaderNoFatal is downloadReader for goroutines that cannot call Fatalf.
func downloadReaderNoFatal(stream simpletier.Stream, total int64, buf, expected []byte) (int64, error) {
	var read int64
	for read < total {
		size := int64(len(buf))
		if remaining := total - read; remaining < size {
			size = remaining
		}
		block := buf[:size]
		if _, err := io.ReadFull(stream, block); err != nil {
			return read, err
		}
		benchPattern(expected[:size], read)
		if !bytesEqual(block, expected[:size]) {
			return read, fmt.Errorf("payload mismatch at offset %d", read)
		}
		read += size
	}
	return read, nil
}

// BenchmarkBidirectional measures a full-duplex transfer: both nodes send and
// receive at the same time, which is what a tunnel carrying interactive traffic
// actually looks like.
//
// One-way numbers cannot be added to predict this. Each direction has its own
// credit frontier, and both share the physical carrier, the session egress order
// and the AEAD work, so contention shows up here and nowhere else.
func BenchmarkBidirectional(b *testing.B) {
	const perDirection int64 = 10 << 20

	withTopologies(b, func(b *testing.B, topo benchTopology, port int) {
		listener := listenVirtual(b, topo.target, topo.targetIP, port)
		// The target sends its own stream of data while consuming the source's.
		rounds := new(int64)
		server := startBidirectionalServer(b, listener, perDirection, rounds)
		stream := dialUntil(b, topo.source, addr4String(topo.targetIP, port))
		downloadHandshake(b, stream)

		block := make([]byte, benchFrameChunk)
		buf := make([]byte, benchFrameChunk)
		expected := make([]byte, benchFrameChunk)

		b.SetBytes(perDirection * 2)
		b.ResetTimer()
		atomic.StoreInt64(rounds, int64(b.N))
		for i := 0; i < b.N; i++ {
			var wg sync.WaitGroup
			var firstErr error
			var errOnce sync.Once

			// Receive the target's direction.
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := downloadReaderNoFatal(stream, perDirection, buf, expected); err != nil {
					errOnce.Do(func() { firstErr = fmt.Errorf("receive: %w", err) })
				}
			}()
			// Send our own direction at the same time.
			wg.Add(1)
			go func() {
				defer wg.Done()
				var written int64
				for written < perDirection {
					n := int64(len(block))
					if remaining := perDirection - written; remaining < n {
						n = remaining
					}
					chunk := block[:n]
					benchPattern(chunk, written)
					if err := writeAll(stream, chunk); err != nil {
						errOnce.Do(func() { firstErr = fmt.Errorf("send: %w", err) })
						return
					}
					written += n
				}
			}()
			wg.Wait()
			if firstErr != nil {
				b.Fatalf("bidirectional: %v", firstErr)
			}
		}
		b.StopTimer()

		_ = closeStream(b, stream)
		_ = listener.Close()
		server.wait(b)
	})
}

// startBidirectionalServer accepts one stream, then both sends its own payload
// and consumes the peer's until it half-closes.
//
// It reads in a goroutine so the two directions make progress together: a server
// that sent its whole payload before reading would stall as soon as both credit
// frontiers filled.
func startBidirectionalServer(tb testing.TB, listener simpletier.StreamListener, total int64, rounds *int64) *sendServer {
	tb.Helper()
	server := &sendServer{done: make(chan struct{})}
	go func() {
		defer close(server.done)
		stream, err := listener.Accept()
		if err != nil {
			server.fail(err)
			return
		}
		defer func() { _ = stream.Close() }()

		ready := make([]byte, 1)
		if _, err := io.ReadFull(stream, ready); err != nil {
			server.fail(fmt.Errorf("bidirectional ready byte: %w", err))
			return
		}

		want := int64(1)
		if rounds != nil {
			for atomic.LoadInt64(rounds) == 0 {
				time.Sleep(time.Millisecond)
			}
			want = atomic.LoadInt64(rounds)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			block := make([]byte, benchFrameChunk)
			for round := int64(0); round < want; round++ {
				var written int64
				for written < total {
					n := int64(len(block))
					if remaining := total - written; remaining < n {
						n = remaining
					}
					chunk := block[:n]
					benchPattern(chunk, written)
					if err := writeAll(stream, chunk); err != nil {
						server.fail(fmt.Errorf("bidirectional send: %w", err))
						return
					}
					written += n
				}
			}
			if err := stream.CloseWrite(); err != nil {
				server.fail(fmt.Errorf("bidirectional CloseWrite: %w", err))
			}
		}()
		go func() {
			defer wg.Done()
			buf := make([]byte, benchFrameChunk)
			var read int64
			for {
				n, err := stream.Read(buf)
				read += int64(n)
				if err != nil {
					if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, simpletier.ErrClosed) {
						server.fail(fmt.Errorf("bidirectional receive: %w", err))
					}
					return
				}
			}
		}()
		wg.Wait()
	}()
	return server
}

// BenchmarkPacketLoss measures throughput when the carrier loses packets.
//
// Loss is modelled as retransmission delay rather than dropped bytes: TCP is a
// reliable stream, so a lost segment still arrives, just one RTO later. That is
// what an application on top actually experiences, and it is what a congestion
// control loop reacts to.
//
// A percentage of chunks is delayed by one RTO, so the throughput drop reflects
// how the overlay's credit and egress path respond to late data rather than to
// missing data.
func BenchmarkPacketLoss(b *testing.B) {
	const total = 10 << 20

	for _, lossPct := range []int{0, 1, 5, 10} {
		lossPct := lossPct
		b.Run(fmt.Sprintf("loss-%02d%%", lossPct), func(b *testing.B) {
			b.Run("direct", func(b *testing.B) {
				runLossCase(b, lossPct, false)
			})
			b.Run("relay", func(b *testing.B) {
				runLossCase(b, lossPct, true)
			})
		})
	}
}

// runLossCase builds a two- or three-node topology whose carriers cross a
// retransmit proxy, then moves a fixed payload through it.
func runLossCase(b *testing.B, lossPct int, relay bool) {
	const total = 10 << 20
	const port = 29000

	targetCarrier := freeLoopbackPort(b)
	target := newBenchNetwork(b, targetCarrier, nil, nodeBIP)
	proxy := startRetransmitProxy(b, fmt.Sprintf("127.0.0.1:%d", targetCarrier), 0, lossPct)

	var source simpletier.Network
	if relay {
		// The relay must reach the target on its own carrier, so the target listens
		// on the relay's upstream rather than on the lossy proxy in front of the
		// source. A relay with no route to the target would fail to converge and
		// the source's dial would report no route.
		relayCarrier := freeLoopbackPort(b)
		relayNode := newBenchNetwork(b, relayCarrier, nil, nodeRIP)
		relayProxy := startRetransmitProxy(b, fmt.Sprintf("127.0.0.1:%d", relayCarrier), 0, lossPct)
		// Replace the target with one that dials the relay.
		closeNetwork(b, target)
		proxy.stop()
		target = newBenchNetworkURL(b, freeLoopbackPort(b), []string{"tcp://" + relayProxy.addr()}, nodeBIP)
		source = newBenchNetworkURL(b, freeLoopbackPort(b), []string{"tcp://" + relayProxy.addr()}, nodeAIP)
		b.Cleanup(func() { closeNetwork(b, source); closeNetwork(b, relayNode); closeNetwork(b, target) })
	} else {
		source = newBenchNetworkURL(b, freeLoopbackPort(b), []string{"tcp://" + proxy.addr()}, nodeAIP)
		b.Cleanup(func() { closeNetwork(b, source); closeNetwork(b, target) })
	}

	listener := listenVirtual(b, target, nodeBIP, port)
	server := startDiscardServer(b, listener)
	stream := dialUntil(b, source, addr4String(nodeBIP, port))
	discardHandshake(b, stream, server)

	block := make([]byte, benchFrameChunk)
	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		var written int64
		for written < total {
			n := int64(len(block))
			if remaining := total - written; remaining < n {
				n = remaining
			}
			benchPattern(block[:n], written)
			if err := writeAll(stream, block[:n]); err != nil {
				b.Fatalf("loss write: %v", err)
			}
			written += n
		}
		server.awaitConsumed(b, total*int64(i+1))
		b.ReportMetric(float64(time.Since(start).Milliseconds()), "total-ms")
	}
	b.StopTimer()

	_ = closeStream(b, stream)
	_ = listener.Close()
	server.wait(b, closeWait)
}
