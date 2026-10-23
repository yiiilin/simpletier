package benchmarks_test

// The canonical data-plane benchmark suite, following STANDARD.md.
//
// Three shapes, kept apart because they answer different questions:
//
//	BenchmarkDownloadThroughput   one-way, pipelined   the headline number
//	BenchmarkDownloadLatency      one-way, instrumented ttfb and steady frame RTT
//	BenchmarkEchoCorrectness      echo                  correctness only
//
// Every throughput case is pipelined: the writer streams continuously while a
// reader drains the far side, which is what a real transfer does. Stop-and-wait
// is only used inside the latency suite, where the round trip is the measurement.

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"sync"
	"testing"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// benchFrameChunk is the per-write block for every throughput suite. It is large
// enough that a single write spans several flow-control windows, which is how a
// real bulk writer behaves, and small enough that the reader and writer together
// stay under a megabyte regardless of payload size.
const benchFrameChunk = 256 << 10

// benchSizes is the payload matrix the throughput suites use. 1 MiB shows the
// start-up share, 10 MiB is the first size that is essentially steady state, and
// 50 MiB confirms the plateau. 100 MiB was dropped after measuring it at 172.92
// MB/s against 50 MiB's 181.44: same plateau, twice the wall time, no extra
// information.
var benchSizes = []struct {
	name  string
	bytes int64
}{
	{"80KiB", 80 << 10},
	{"1MiB", 1 << 20},
	{"8MiB", 8 << 20},
	{"10MiB", 10 << 20},
	{"50MiB", 50 << 20},
}

// benchSteadySize is the payload the throughput suites use.
const benchSteadySize int64 = 10 << 20

// benchLatencyPayload is what the latency suites move per iteration. Latency is
// a per-block and first-byte property, so a handful of blocks is enough, and a
// small payload keeps a 1s-RTT case to a few seconds instead of minutes.
const benchLatencyPayload int64 = 4 * benchFrameChunk

// benchPattern fills dst with a position-dependent pattern so a receiver can
// verify any block without holding the whole payload. The offset makes the
// pattern non-repeating across blocks, so a misordered or duplicated block is
// caught rather than silently matching.
func benchPattern(dst []byte, offset int64) {
	for i := range dst {
		dst[i] = byte((offset + int64(i)) * 31)
	}
}

// downloadWriter streams total bytes from one reused block and half-closes when
// it is done, which is the shape of a file send.
func downloadWriter(tb testing.TB, stream simpletier.Stream, total int64, block []byte) {
	tb.Helper()
	var written int64
	for written < total {
		size := int64(len(block))
		if remaining := total - written; remaining < size {
			size = remaining
		}
		chunk := block[:size]
		benchPattern(chunk, written)
		if err := writeAll(stream, chunk); err != nil {
			tb.Fatalf("download write at %d of %d: %v", written, total, err)
		}
		written += size
	}
	if err := stream.CloseWrite(); err != nil {
		tb.Fatalf("download CloseWrite: %v", err)
	}
}

// downloadReader drains total bytes and verifies each block against the pattern.
func downloadReader(tb testing.TB, stream simpletier.Stream, total int64, buf, expected []byte) int64 {
	tb.Helper()
	var read int64
	for read < total {
		size := int64(len(buf))
		if remaining := total - read; remaining < size {
			size = remaining
		}
		block := buf[:size]
		if _, err := io.ReadFull(stream, block); err != nil {
			tb.Fatalf("download read at %d of %d: %v", read, total, err)
		}
		benchPattern(expected[:size], read)
		if !bytesEqual(block, expected[:size]) {
			tb.Fatalf("payload mismatch at offset %d (%d-byte block)", read, size)
		}
		read += size
	}
	return read
}

// bytesEqual compares two byte slices without importing bytes in a hot loop.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// BenchmarkEchoCorrectness is a correctness anchor, not a performance metric:
// it round-trips every byte and verifies it, and reports the SHA-256 prefix of
// what came back so runs can be compared across machines.
//
// Echo costs twice the AEAD work per byte of a one-way transfer, so its MB/s must
// not be quoted as throughput. Use BenchmarkDownloadThroughput for that.
func BenchmarkEchoCorrectness(b *testing.B) {
	env := newPairEnv(b)

	for _, size := range benchSizes {
		size := size
		b.Run(size.name, func(b *testing.B) {
			port := 25400 + int(size.bytes>>20)
			listener := listenVirtual(b, env.target, env.targetIP, port)
			server := startConcurrentEchoServer(b, listener)
			stream := dialUntil(b, env.source, addr4String(env.targetIP, port))
			echoHandshake(b, stream)

			block := make([]byte, benchFrameChunk)
			buf := make([]byte, benchFrameChunk)
			expected := make([]byte, benchFrameChunk)

			b.SetBytes(size.bytes)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var digest hash.Hash = sha256.New()
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					var read int64
					for read < size.bytes {
						n := int64(len(buf))
						if remaining := size.bytes - read; remaining < n {
							n = remaining
						}
						chunk := buf[:n]
						if _, err := io.ReadFull(stream, chunk); err != nil {
							b.Errorf("echo read at %d: %v", read, err)
							return
						}
						benchPattern(expected[:n], read)
						if !bytesEqual(chunk, expected[:n]) {
							b.Errorf("echo payload mismatch at offset %d", read)
							return
						}
						digest.Write(chunk)
						read += n
					}
				}()
				var written int64
				for written < size.bytes {
					n := int64(len(block))
					if remaining := size.bytes - written; remaining < n {
						n = remaining
					}
					chunk := block[:n]
					benchPattern(chunk, written)
					if err := writeAll(stream, chunk); err != nil {
						b.Fatalf("echo write: %v", err)
					}
					written += n
				}
				wg.Wait()
				b.ReportMetric(0, fmt.Sprintf("sha256-%x", digest.Sum(nil)[:4]))
			}
			b.StopTimer()

			_ = closeStream(b, stream)
			_ = listener.Close()
			server.wait(b, closeWait)
		})
	}
}
