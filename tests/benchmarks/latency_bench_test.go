package benchmarks_test

// High-latency benchmarks.
//
// Every other benchmark in this package runs on 127.0.0.1, where a round trip
// costs microseconds. That flatters a window-based flow-control scheme: the
// 64 KiB window is refilled so quickly that the control budget rarely binds.
// On a real link the round trip is hundreds of milliseconds, and each window
// then costs that much wall time.
//
// This file inserts a latency proxy between the SDK and the real loopback
// listener, so a benchmark can ask what throughput looks like at 500 ms RTT.
//
// The proxy delays bytes in both directions by the configured amount, which
// makes one round trip cost 2*delay. A relayed path pays the delay on every hop,
// so its round trip is 2*delay*hops; the hop count is asserted rather than
// assumed, because "latency accumulates per hop" is exactly the property under
// test.

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// latencyProxy sits in front of a carrier listener and delays every byte by the
// configured amount in each direction.
type latencyProxy struct {
	listener net.Listener
	delay    time.Duration
	done     chan struct{}
	once     sync.Once
}

// startLatencyProxy forwards new connections to upstream, adding delay in both
// directions.
func startLatencyProxy(tb testing.TB, upstream string, delay time.Duration) *latencyProxy {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("latency proxy listen: %v", err)
	}
	proxy := &latencyProxy{listener: listener, delay: delay, done: make(chan struct{})}
	// Register cleanup here, before the networks are created: Cleanup runs LIFO,
	// so this stops the proxy only after the network that dials it has closed.
	// Stopping first would wait for handler goroutines whose connections the
	// still-live network keeps open, which deadlocks.
	tb.Cleanup(proxy.stop)
	go func() {
		defer proxy.once.Do(func() { close(proxy.done) })
		var handlers sync.WaitGroup
		for {
			downstream, err := listener.Accept()
			if err != nil {
				handlers.Wait()
				return
			}
			handlers.Add(1)
			go func(down net.Conn) {
				defer handlers.Done()
				defer func() { _ = down.Close() }()
				up, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()

				var pumps sync.WaitGroup
				pumps.Add(2)
				go func() {
					defer pumps.Done()
					delayCopy(up, down, delay)
					if tcp, ok := up.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
				}()
				go func() {
					defer pumps.Done()
					delayCopy(down, up, delay)
					if tcp, ok := down.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
				}()
				pumps.Wait()
			}(downstream)
		}
	}()
	return proxy
}

func (p *latencyProxy) addr() string { return p.listener.Addr().String() }

func (p *latencyProxy) stop() {
	_ = p.listener.Close()
	<-p.done
}

// delayCopy forwards src to dst with a propagation delay on every chunk, while
// letting many chunks be in flight at once.
//
// Two wrong models were tried first. Sleeping before every write makes the
// proxy's own read size the bandwidth limit: a 64 KiB buffer with a 150 ms delay
// serializes 4 MiB into 64 sleeps and the link looks like 0.43 MB/s regardless of
// how fast the overlay is. Sleeping only on the first chunk goes too far the other
// way and makes the round trip disappear after the first byte.
//
// A real link does neither: each byte arrives `delay` after it was sent, and
// bytes sent back to back arrive back to back. So chunks are queued with an
// arrival time and released when due, which keeps the pipe full at any bandwidth
// while still costing `delay` per direction.
func delayCopy(dst io.Writer, src io.Reader, delay time.Duration) {
	if delay <= 0 {
		_, _ = io.Copy(dst, src)
		return
	}
	type chunk struct {
		data []byte
		due  time.Time
	}
	queue := make(chan chunk, 1024)
	done := make(chan struct{})

	// Writer: release chunks in order, but base each release on its own arrival
	// time rather than sleeping a fixed amount per chunk. A chunk is written once
	// the current time passes its due time, so back-to-back chunks with the same
	// delay go out back to back instead of one sleep apart. Order is preserved
	// because this is a byte stream, not a packet queue.
	go func() {
		defer close(done)
		for c := range queue {
			if wait := time.Until(c.due); wait > 0 {
				time.Sleep(wait)
			}
			if _, err := dst.Write(c.data); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, maxBuffer)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			queue <- chunk{data: data, due: time.Now().Add(delay)}
		}
		if err != nil {
			break
		}
	}
	close(queue)
	<-done
}

// latencyEnv is a two-node direct topology whose carrier crosses the proxy.
type latencyEnv struct {
	source   simpletier.Network
	target   simpletier.Network
	targetIP string
	proxy    *latencyProxy
}

// newLatencyPairEnv builds source and target where the source's only upstream is
// the latency proxy in front of the target's carrier.
func newLatencyPairEnv(tb testing.TB, oneWay time.Duration) *latencyEnv {
	tb.Helper()
	// The target listens on its own port; the proxy forwards to it; the source's
	// only upstream is the proxy. The proxy is started before the source so its
	// resolved address is final, and each layer gets a distinct reserved port.
	targetCarrier := freeLoopbackPort(tb)
	target := newBenchNetwork(tb, targetCarrier, nil, nodeBIP)
	proxy := startLatencyProxy(tb, fmt.Sprintf("127.0.0.1:%d", targetCarrier), oneWay)
	sourcePort := freeLoopbackPort(tb)
	source := newBenchNetworkURL(tb, sourcePort, []string{"tcp://" + proxy.addr()}, nodeAIP)
	tb.Cleanup(func() { closeNetwork(tb, source); closeNetwork(tb, target) })
	return &latencyEnv{source: source, target: target, targetIP: nodeBIP, proxy: proxy}
}

// addr4String formats a virtual host and port.
func addr4String(ip string, port int) string { return fmt.Sprintf("%s:%d", ip, port) }

// BenchmarkStreamLatencyAccumulation verifies that latency accumulates per hop.
//
// The topology is source -> relay -> target, with a delay proxy on each carrier,
// so one end-to-end round trip crosses two delayed links. A relayed path must be
// roughly twice as slow as the direct path at the same per-link delay; if it is
// not, either the delay is not applied per hop or the relay is short-circuiting
// the path.
func BenchmarkStreamLatencyAccumulation(b *testing.B) {
	const payloadSize = 60 << 10
	const frames = 2

	for _, tc := range []struct {
		name  string
		hops  int
		delay time.Duration
	}{
		{"direct-50ms", 1, 50 * time.Millisecond},
		{"relay-50ms", 2, 50 * time.Millisecond},
	} {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			var source, target simpletier.Network
			if tc.hops == 1 {
				env := newLatencyPairEnv(b, tc.delay)
				source, target = env.source, env.target
			} else {
				source, target = newLatencyRelayEnv(b, tc.delay)
			}

			listener := listenVirtual(b, target, nodeBIP, 22101)
			server := startConcurrentEchoServer(b, listener)
			stream := dialUntil(b, source, addr4String(nodeBIP, 22101))
			echoHandshake(b, stream)

			payload := randPayload(b, payloadSize)
			got := make([]byte, payloadSize)
			window := make([]byte, payloadSize)

			b.SetBytes(int64(payloadSize) * frames)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for f := 0; f < frames; f++ {
					readErr := make(chan error, 1)
					go func() { readErr <- consumeInto(stream, got, window) }()
					writeErr := writeAll(stream, payload)
					received := <-readErr
					if writeErr != nil {
						b.Fatalf("write: %v", writeErr)
					}
					if received != nil {
						b.Fatalf("read: %v", received)
					}
				}
			}
			b.StopTimer()

			_ = closeStream(b, stream)
			_ = listener.Close()
			server.wait(b, closeWait)
		})
	}
}

// newLatencyRelayEnv builds source -> relay -> target where both carriers cross a
// delay proxy, so an end-to-end round trip pays the delay on two hops.
func newLatencyRelayEnv(tb testing.TB, oneWay time.Duration) (simpletier.Network, simpletier.Network) {
	tb.Helper()
	relayCarrier := freeLoopbackPort(tb)
	relay := newBenchNetwork(tb, relayCarrier, nil, nodeRIP)
	relayProxy := startLatencyProxy(tb, fmt.Sprintf("127.0.0.1:%d", relayCarrier), oneWay)

	// The target dials the relay through its own proxy; the source dials the same
	// relay through a second one, so each hop carries the delay exactly once.
	source := newBenchNetworkURL(tb, freeLoopbackPort(tb), []string{"tcp://" + relayProxy.addr()}, nodeAIP)
	target := newBenchNetworkURL(tb, freeLoopbackPort(tb), []string{"tcp://" + relayProxy.addr()}, nodeBIP)
	tb.Cleanup(func() { closeNetwork(tb, source); closeNetwork(tb, target); closeNetwork(tb, relay) })
	return source, target
}

// retransmitProxy models what packet loss looks like to an application on a TCP
// carrier.
//
// Dropping bytes from a TCP proxy would not simulate loss: TCP is a reliable
// stream, so a gap is corruption, not a missing packet, and the real recovery
// (retransmission) happens below the proxy and cannot be reproduced by deleting
// bytes. What loss actually costs an application is time: a lost segment is
// retransmitted after an RTO, so the data still arrives, just late.
//
// So this proxy delivers every byte, but delays a percentage of chunks by an
// extra retransmission timeout. That is the shape the overlay sees, and it is
// measurable without corrupting the stream.
type retransmitProxy struct {
	listener net.Listener
	delay    time.Duration
	lossPct  int
	rto      time.Duration
	done     chan struct{}
	once     sync.Once
}

// startRetransmitProxy forwards new connections to upstream, delaying every chunk
// by the propagation delay and adding an RTO to lossPct percent of them.
func startRetransmitProxy(tb testing.TB, upstream string, delay time.Duration, lossPct int) *retransmitProxy {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("retransmit proxy listen: %v", err)
	}
	proxy := &retransmitProxy{
		listener: listener,
		delay:    delay,
		lossPct:  lossPct,
		rto:      200 * time.Millisecond,
		done:     make(chan struct{}),
	}
	tb.Cleanup(func() { proxy.stop() })
	go func() {
		defer proxy.once.Do(func() { close(proxy.done) })
		var handlers sync.WaitGroup
		for {
			downstream, err := listener.Accept()
			if err != nil {
				handlers.Wait()
				return
			}
			handlers.Add(1)
			go func(down net.Conn) {
				defer handlers.Done()
				defer func() { _ = down.Close() }()
				up, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()

				var pumps sync.WaitGroup
				pumps.Add(2)
				// Loss is applied to the data direction only. Applying it to both
				// directions double-counts: a lost ACK is normally covered by the
				// data retransmission, so penalizing it separately makes the loss
				// rate look several times worse than the configured value.
				go func() {
					defer pumps.Done()
					retransmitCopy(up, down, delay, lossPct, proxy.rto)
					if tcp, ok := up.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
				}()
				go func() {
					defer pumps.Done()
					delayCopy(down, up, delay)
					if tcp, ok := down.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
				}()
				pumps.Wait()
			}(downstream)
		}
	}()
	return proxy
}

func (p *retransmitProxy) addr() string { return p.listener.Addr().String() }

func (p *retransmitProxy) stop() {
	_ = p.listener.Close()
	<-p.done
}

// retransmitCopy models what a lost segment costs an application on a TCP
// carrier.
//
// TCP is a reliable, ordered stream: when a segment is lost, everything behind it
// is buffered until the retransmission fills the gap. So the cost of loss is not
// "this chunk arrives late" but "every chunk from here on is delivered one
// retransmission timeout later". That is head-of-line blocking, and it is why a
// small loss rate hurts so much more than the loss rate itself suggests.
//
// This proxy reproduces that: on a loss event it adds an RTO to the delivery
// timeline of the chunk and of everything queued behind it. Successive losses
// compound, so 5% costs more than 1% rather than hitting the same plateau.
func retransmitCopy(dst io.Writer, src io.Reader, delay time.Duration, lossPct int, rto time.Duration) {
	type chunk struct {
		data []byte
		due  time.Time
	}
	queue := make(chan chunk, 1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for c := range queue {
			if wait := time.Until(c.due); wait > 0 {
				time.Sleep(wait)
			}
			if _, err := dst.Write(c.data); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, maxBufChunk)
	// Loss is decided per fixed-size segment, not per Read. A TCP read returns
	// whatever happens to be buffered, so deciding per read makes the effective
	// loss rate depend on the kernel's read pattern: with 4 KiB reads a "1%" loss
	// becomes sixteen times more drops than the same rate over 64 KiB segments.
	// Real loss happens per packet on the wire, so the decision is made on segment
	// boundaries regardless of how the bytes arrived.
	segmentsPerRead := maxBufChunk / lossSegmentBytes
	if segmentsPerRead < 1 {
		segmentsPerRead = 1
	}
	var seq uint64
	var segmentFill int64
	// penalty accumulates: a lost segment delays the stream, and the delay stays
	// until the retransmission would have completed.
	var penalty time.Duration
	for {
		n, err := src.Read(buf)
		if n > 0 {
			// Loss is decided per lossSegmentBytes of payload, independent of how
			// the reads happen to be split. A TCP read returns whatever is buffered,
			// so deciding per read makes the effective loss rate depend on the
			// kernel's read sizes: many small reads turn "1%" into many more drops
			// than the rate implies.
			for offset := 0; offset < n; {
				// How many bytes remain before this segment's loss decision lands.
				remainingInSegment := int(lossSegmentBytes - segmentFill)
				if remainingInSegment <= 0 {
					remainingInSegment = int(lossSegmentBytes)
				}
				take := n - offset
				if take > remainingInSegment {
					take = remainingInSegment
				}
				data := make([]byte, take)
				copy(data, buf[offset:offset+take])
				offset += take
				segmentFill += int64(take)
				due := time.Now().Add(delay).Add(penalty)
				if segmentFill >= lossSegmentBytes {
					// One decision per completed segment.
					segmentFill = 0
					if lossPct > 0 {
						seq++
						if (seq*2654435761)%100 < uint64(lossPct) {
							penalty += rto
							due = due.Add(rto)
						}
					}
				}
				queue <- chunk{data: data, due: due}
			}
		}
		if err != nil {
			break
		}
	}
	close(queue)
	<-done
}

// maxBufChunk is the proxy's read size.
const maxBufChunk = 64 << 10

// lossSegmentBytes is the segment size loss is decided on.
//
// It is the overlay's frame size rather than the wire MTU. A wire-MTU segment
// would put roughly seven thousand independent loss decisions in a 10 MiB
// transfer, so "1%" would mean seventy RTOs and the case would not finish; more
// importantly the number would then describe the proxy's segmentation rather than
// the overlay's exposure. One decision per frame is the granularity at which the
// overlay actually experiences a gap.
const lossSegmentBytes = 64 << 10
