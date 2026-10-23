package benchmarks_test

// Raw loopback TCP baseline.
//
// The SDK benchmarks in this package all run over real loopback TCP carriers but
// add the overlay on top: Noise handshakes, the per-frame E2E AEAD, the circuit
// flow control with its 64 KiB window and WINDOW_UPDATE, and the session egress
// lock. This file measures the same shapes with none of that, so the difference
// between the two is the overlay's own cost rather than the network's.
//
// Every case here is plain net.Conn over 127.0.0.1 with the same payload sizes
// and concurrency levels the SDK suites use, so the numbers are directly
// comparable.

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
)

// rawEchoServer accepts connections on a loopback listener and echoes each one
// until the peer half-closes. It is the plain-TCP counterpart of the harness's
// echo server.
type rawEchoServer struct {
	listener net.Listener
	done     chan struct{}
	once     sync.Once
}

func startRawEchoServer(tb testing.TB, listener net.Listener) *rawEchoServer {
	tb.Helper()
	server := &rawEchoServer{listener: listener, done: make(chan struct{})}
	go func() {
		defer server.once.Do(func() { close(server.done) })
		var handlers sync.WaitGroup
		for {
			conn, err := listener.Accept()
			if err != nil {
				handlers.Wait()
				return
			}
			handlers.Add(1)
			go func(c net.Conn) {
				defer handlers.Done()
				defer func() { _ = c.Close() }()
				buf := make([]byte, maxBuffer)
				for {
					n, readErr := c.Read(buf)
					if n > 0 {
						if _, writeErr := c.Write(buf[:n]); writeErr != nil {
							return
						}
					}
					if readErr != nil {
						if tcp, ok := c.(*net.TCPConn); ok {
							_ = tcp.CloseWrite()
						}
						return
					}
				}
			}(conn)
		}
	}()
	return server
}

func (s *rawEchoServer) wait(tb testing.TB) {
	tb.Helper()
	<-s.done
}

// rawLoopbackListener reserves a loopback port and returns a live listener.
func rawLoopbackListener(tb testing.TB) net.Listener {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("raw loopback listen: %v", err)
	}
	return listener
}

// rawEchoRoundTrip writes payload and reads the same number of bytes back,
// reading and writing concurrently so neither direction can starve the other.
func rawEchoRoundTrip(tb testing.TB, conn net.Conn, payload, got, window []byte) {
	tb.Helper()
	readErr := make(chan error, 1)
	go func() { readErr <- rawConsumeInto(conn, got, window) }()
	writeErr := rawWriteAll(conn, payload)
	received := <-readErr
	if writeErr != nil {
		tb.Fatalf("raw write: %v", writeErr)
	}
	if received != nil {
		tb.Fatalf("raw read: %v", received)
	}
	if !bytes.Equal(payload, got) {
		tb.Fatal("raw echo payload mismatch")
	}
}

func rawWriteAll(w io.Writer, p []byte) error {
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

// rawConsumeInto fills dst from r through a smaller window, so a large payload can
// be compared byte for byte without a single buffer sized read.
func rawConsumeInto(r io.Reader, dst, window []byte) error {
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
			if err == io.EOF && filled == len(dst) {
				return nil
			}
			return err
		}
	}
	return nil
}

// BenchmarkRawTCPEcho is the pure baseline for BenchmarkStreamDirect/echo: one
// connection, the same payload sizes, nothing but net.Conn on loopback.
func BenchmarkRawTCPEcho(b *testing.B) {
	listener := rawLoopbackListener(b)
	defer listener.Close()
	server := startRawEchoServer(b, listener)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		b.Fatalf("raw dial: %v", err)
	}
	defer conn.Close()

	for _, size := range benchSizes {
		size := size
		b.Run("echo/"+size.name, func(b *testing.B) {
			payload := randPayload(b, int(size.bytes))
			got := make([]byte, int(size.bytes))
			window := make([]byte, maxBuffer)
			if int64(len(window)) > size.bytes {
				window = window[:size.bytes]
			}
			b.SetBytes(size.bytes)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rawEchoRoundTrip(b, conn, payload, got, window)
			}
			b.StopTimer()
		})
	}

	_ = conn.Close()
	_ = listener.Close()
	server.wait(b)
}

// BenchmarkRawTCPConcurrency is the pure baseline for
// BenchmarkStreamConcurrency: level plain connections, each moving one payload,
// all at the same time.
func BenchmarkRawTCPConcurrency(b *testing.B) {
	listener := rawLoopbackListener(b)
	defer listener.Close()
	server := startRawEchoServer(b, listener)
	address := listener.Addr().String()

	for _, level := range concurrencyLevels {
		level := level
		b.Run(fmt.Sprintf("streams-%02d", level), func(b *testing.B) {
			conns := make([]net.Conn, level)
			for i := 0; i < level; i++ {
				conn, err := net.Dial("tcp", address)
				if err != nil {
					b.Fatalf("raw dial %d: %v", i, err)
				}
				conns[i] = conn
			}

			payload := randPayload(b, concurrencyPayload)
			b.SetBytes(int64(concurrencyPayload) * int64(level))
			b.ResetTimer()

			for iteration := 0; iteration < b.N; iteration++ {
				var wg sync.WaitGroup
				for i := 0; i < level; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						got := make([]byte, len(payload))
						window := make([]byte, maxBuffer)
						rawEchoRoundTrip(b, conns[i], payload, got, window)
					}(i)
				}
				wg.Wait()
			}

			b.StopTimer()
			for i := 0; i < level; i++ {
				_ = conns[i].Close()
			}
		})
	}

	_ = listener.Close()
	server.wait(b)
}

// BenchmarkRawTCPBandwidth is the pure baseline for BenchmarkStreamBandwidth: one
// connection moving a total in frame-sized round trips.
func BenchmarkRawTCPBandwidth(b *testing.B) {
	listener := rawLoopbackListener(b)
	defer listener.Close()
	server := startRawEchoServer(b, listener)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		b.Fatalf("raw dial: %v", err)
	}
	defer conn.Close()

	payload := randPayload(b, frameChunk)
	got := make([]byte, frameChunk)
	window := make([]byte, frameChunk)

	b.SetBytes(bandwidthPayload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var moved int64
		for moved < bandwidthPayload {
			rawEchoRoundTrip(b, conn, payload, got, window)
			moved += int64(frameChunk)
		}
	}
	b.StopTimer()

	_ = conn.Close()
	_ = listener.Close()
	server.wait(b)
}
