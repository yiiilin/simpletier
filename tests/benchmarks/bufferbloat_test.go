package benchmarks_test

import (
	"io"
	"sync"
	"testing"
	"time"
)

// TestBufferbloatReport measures latency while a bulk transfer saturates the
// link. A large credit window lets the sender put a lot of data in flight; if the
// receive buffer holds it, queued bytes delay every later frame. That is the cost
// of throughput that a plain MB/s number hides.
//
// The probe uses its own stream so it is not interleaved with the bulk payload on
// the same circuit. Both share one carrier, which is where queueing happens.
func TestBufferbloatReport(t *testing.T) {
	for _, rtt := range []time.Duration{10 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 300 * time.Millisecond} {
		rtt := rtt
		t.Run("rtt-"+rtt.String(), func(t *testing.T) {
			env := newLatencyPairEnv(t, rtt/2)

			// Bulk circuit on its own port.
			bulkPort := 35000 + int(rtt/time.Millisecond)
			bulkListener := listenVirtual(t, env.target, env.targetIP, bulkPort)
			bulkServer := startDiscardServer(t, bulkListener)
			bulkStream := dialUntil(t, env.source, addr4String(env.targetIP, bulkPort))
			discardHandshake(t, bulkStream, bulkServer)

			// Probe circuit on a second port, same carrier.
			probePort := bulkPort + 100
			probeListener := listenVirtual(t, env.target, env.targetIP, probePort)
			probeServer := startEchoServer(t, probeListener)
			probeStream := dialUntil(t, env.source, addr4String(env.targetIP, probePort))
			echoHandshake(t, probeStream)

			probe := make([]byte, 64)
			reply := make([]byte, 64)
			measure := func() time.Duration {
				start := time.Now()
				readErr := make(chan error, 1)
				go func() {
					_, err := io.ReadFull(probeStream, reply)
					readErr <- err
				}()
				if err := writeAll(probeStream, probe); err != nil {
					t.Fatalf("probe write: %v", err)
				}
				if err := <-readErr; err != nil {
					t.Fatalf("probe read: %v", err)
				}
				return time.Since(start)
			}

			idle1 := measure()
			idle2 := measure()
			idle := (idle1 + idle2) / 2

			// Saturate the carrier with a bulk transfer.
			const bulk = 32 << 20
			block := make([]byte, benchFrameChunk)
			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				var written int64
				for written < bulk {
					select {
					case <-stop:
						return
					default:
					}
					n := int64(len(block))
					if r := bulk - written; r < n {
						n = r
					}
					benchPattern(block[:n], written)
					if err := writeAll(bulkStream, block[:n]); err != nil {
						return
					}
					written += n
				}
			}()

			// Sample several probes while the link is busy.
			time.Sleep(30 * time.Millisecond)
			var total time.Duration
			const samples = 5
			for i := 0; i < samples; i++ {
				total += measure()
				time.Sleep(5 * time.Millisecond)
			}
			loaded := total / samples
			close(stop)
			wg.Wait()

			t.Logf("RTT=%v  idle=%v  loaded=%v  bloat=+%v",
				rtt, idle, loaded, loaded-idle)

			_ = closeStream(t, bulkStream)
			_ = closeStream(t, probeStream)
			_ = bulkListener.Close()
			_ = probeListener.Close()
			bulkServer.wait(t, closeWait)
			probeServer.wait(t, closeWait)
		})
	}
}
