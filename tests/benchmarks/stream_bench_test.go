package benchmarks_test

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// benchEchoStream measures the full business round trip of one payload size on
// an already-warm Stream. The concurrent reader inside echoRoundTrip keeps the
// receive window open, so the measurement is stream throughput rather than a
// deadlock or a window stall. b.SetBytes makes the benchmark report bytes/s.
func benchEchoStream(b *testing.B, stream simpletier.Stream, size int) {
	b.Helper()
	payload := randPayload(b, size)
	readBuf := make([]byte, maxBuffer)
	if len(readBuf) > size {
		readBuf = readBuf[:size]
	}
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := echoRoundTrip(stream, payload, readBuf); err != nil {
			classifyFatal(b, "echo roundtrip", err)
		}
	}
	b.StopTimer()
}

// benchDiscardStream measures one-way stream throughput into the real discard
// service. The service consumes concurrently, which is what advances the send
// window; the payload buffer is allocated once and reused for every iteration.
// ns/op covers local egress into the Stream; after b.StopTimer the benchmark
// confirms the remote service actually consumed every byte, so a queue credit
// can never be reported as delivery. Echo/discard MB/s counts logical request
// payload bytes, not wire bytes (the wire carries ~2x plus frame headers).
func benchDiscardStream(b *testing.B, stream simpletier.Stream, server *streamServer, payload []byte) {
	b.Helper()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := writeAll(stream, payload); err != nil {
			classifyFatal(b, "discard write", err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(len(payload)), "localEgress-bytes/op")
	server.awaitConsumed(b, int64(b.N)*int64(len(payload)))
	b.ReportMetric(float64(server.read.Load())/float64(b.N), "remoteConsumed-bytes/op")
}

// benchZeroChild runs an indefinite b.N loop through a 64 KiB MaxBuffer with a
// zero-value low reader. Memory is constant in b.N: the payload is never
// materialized per iteration. The whole-process GC counters are reported with
// an explicit wholeProcessGC label, not presented as a managed-heap number, and
// they are never used as a pass threshold. Local egress and confirmed remote
// consumption are reported separately for the same reason as the discard case.
func benchZeroChild(b *testing.B, stream simpletier.Stream, server *streamServer) {
	b.Helper()
	buf := make([]byte, maxBuffer)
	reader := &zeroReader{}
	b.SetBytes(int64(maxBuffer))
	b.ReportAllocs()
	b.ResetTimer()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < b.N; i++ {
		reader.remaining = maxBuffer
		if _, err := io.CopyBuffer(stream, reader, buf); err != nil {
			classifyFatal(b, "zero-child copy", err)
		}
	}
	runtime.ReadMemStats(&after)
	b.StopTimer()
	b.ReportMetric(float64(maxBuffer), "localEgress-bytes/op")
	server.awaitConsumed(b, int64(b.N)*int64(maxBuffer))
	b.ReportMetric(float64(server.read.Load())/float64(b.N), "remoteConsumed-bytes/op")
	b.ReportMetric(float64(after.TotalAlloc-before.TotalAlloc)/float64(b.N), "wholeProcessGC-alloc-B/op")
	b.ReportMetric(float64(after.Mallocs-before.Mallocs)/float64(b.N), "wholeProcessGC-mallocs/op")
}

// benchLatency64B performs 100 sequential 64-byte round trips per iteration and
// reports P50/P95 from the monotonic clock. The sample count is reported as a
// plain ratioCount bound; the percentiles are observations, not an SLO.
func benchLatency64B(b *testing.B, stream simpletier.Stream) {
	b.Helper()
	const (
		packet = 64
		perOp  = 100
	)
	payload := randPayload(b, packet)
	buf := make([]byte, packet)
	for i := 0; i < perOp; i++ {
		if err := writeAll(stream, payload); err != nil {
			b.Fatalf("latency warmup write: %v", err)
		}
		if _, err := io.ReadFull(stream, buf); err != nil {
			b.Fatalf("latency warmup read: %v", err)
		}
	}
	samples := make([]time.Duration, 0, perOp*b.N)
	// b.SetBytes is per b.N iteration, and one iteration is perOp round trips of
	// `packet` logical one-way request bytes each (100 packets). Echo MB/s
	// therefore counts REQUEST payload per round trip (one-way logical bytes);
	// the physical wire carries roughly 2x plus frame headers, which is not
	// claimed. ns/op is the 100-roundtrip batch; p50/p95 stay per packet.
	b.SetBytes(int64(packet * perOp))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < perOp; j++ {
			start := time.Now()
			if err := writeAll(stream, payload); err != nil {
				classifyFatal(b, "latency write", err)
			}
			if _, err := io.ReadFull(stream, buf); err != nil {
				classifyFatal(b, "latency read", err)
			}
			samples = append(samples, time.Since(start))
		}
	}
	b.StopTimer()
	if !bytes.Equal(payload, buf) {
		b.Fatalf("latency echo mismatch on the final packet")
	}
	sortDurations(samples)
	b.ReportMetric(float64(percentile(samples, 50).Nanoseconds()), "p50-ns")
	b.ReportMetric(float64(percentile(samples, 95).Nanoseconds()), "p95-ns")
	b.ReportMetric(float64(len(samples)), "samples")
}

// BenchmarkStreamDirect is the A-B business baseline: echo and discard stream
// throughput at 80 KiB, 1 MiB and 8 MiB, the 64 KiB bounded-memory low-reader
// path, and the 64-byte latency profile. Every Stream is established and warmed
// before its timer starts, so SDK startup is not part of these numbers.
func BenchmarkStreamDirect(b *testing.B) {
	env := newPairEnv(b)
	runStreamMatrix(b, env.source, env.target, env.targetIP)
}

// BenchmarkStreamRelay is the A-R-B business path. A and B each upstream only
// to R, so the measured Stream is relayed by R and never crosses a direct A-B
// carrier.
func BenchmarkStreamRelay(b *testing.B) {
	env := newRelayEnv(b)
	runStreamMatrix(b, env.a, env.b, env.bIP)
}

// runStreamMatrix drives the shared per-topology benchmark matrix against one
// source Network and one target Network.
func runStreamMatrix(b *testing.B, source, target simpletier.Network, targetIP string) {
	b.Helper()
	for i, size := range benchSizes {
		size := size
		port := 19101 + i
		b.Run("echo/"+size.name, func(b *testing.B) {
			listener := listenVirtual(b, target, targetIP, port)
			server := startEchoServer(b, listener)
			stream := dialUntil(b, source, fmt.Sprintf("%s:%d", targetIP, port))
			closed := false
			defer func() {
				if !closed {
					_ = stream.Close()
				}
			}()
			echoHandshake(b, stream)
			benchEchoStream(b, stream, int(size.bytes))
			closeStream(b, stream)
			closed = true
			server.wait(b, closeWait)
		})
	}
	for i, size := range benchSizes {
		size := size
		port := 19201 + i
		b.Run("discard/"+size.name, func(b *testing.B) {
			listener := listenVirtual(b, target, targetIP, port)
			server := startDiscardServer(b, listener)
			stream := dialUntil(b, source, fmt.Sprintf("%s:%d", targetIP, port))
			closed := false
			defer func() {
				if !closed {
					_ = stream.Close()
				}
			}()
			discardHandshake(b, stream, server)
			payload := randPayload(b, int(size.bytes))
			benchDiscardStream(b, stream, server, payload)
			closeStream(b, stream)
			closed = true
			server.wait(b, closeWait)
		})
	}
	b.Run("zerobuffer/64KiB", func(b *testing.B) {
		const port = 19301
		listener := listenVirtual(b, target, targetIP, port)
		server := startDiscardServer(b, listener)
		stream := dialUntil(b, source, fmt.Sprintf("%s:%d", targetIP, port))
		closed := false
		defer func() {
			if !closed {
				_ = stream.Close()
			}
		}()
		discardHandshake(b, stream, server)
		benchZeroChild(b, stream, server)
		closeStream(b, stream)
		closed = true
		server.wait(b, closeWait)
	})
	b.Run("latency/64Bx100", func(b *testing.B) {
		const port = 19401
		listener := listenVirtual(b, target, targetIP, port)
		server := startEchoServer(b, listener)
		stream := dialUntil(b, source, fmt.Sprintf("%s:%d", targetIP, port))
		closed := false
		defer func() {
			if !closed {
				_ = stream.Close()
			}
		}()
		echoHandshake(b, stream)
		benchLatency64B(b, stream)
		closeStream(b, stream)
		closed = true
		server.wait(b, closeWait)
	})
}

// BenchmarkStreamTargetsConnector exercises the host-provided
// ConnectionTarget/Connector business entry instead of a tcp:// upstream URL.
func BenchmarkStreamTargetsConnector(b *testing.B) {
	carrierPort := freeLoopbackPort(b)
	target := newBenchNetwork(b, carrierPort, nil, nodeBIP)
	source := newTargetsNetwork(b, freeLoopbackPort(b), carrierPort, nodeAIP)
	runStreamMatrix(b, source, target, nodeBIP)
}
