package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/relay"
)

// streamScenario is the load shape a relay actually carries: every room holds one
// pair of peers exchanging data at a fixed rate, and the question is whether each
// exchange still meets its target while a thousand peers are moving data at once.
//
// Each pair runs a paced sender and an echo responder, and every echo is timed end to
// end from one virtual peer, through the relay, and back. The rate is per pair, so
// the aggregate is pairs x rate.
type streamScenario struct {
	rooms    int
	perRoom  int
	rate     int // bytes per second per pair
	cidr     string
	tcpAddr  string
	base     string
	duration time.Duration
}

// streamResult is the outcome of one measured run.
type streamResult struct {
	pairs     int
	joined    int
	joinTime  time.Duration
	delivered int64
	expected  int64
	latencies []time.Duration
}

func (s streamScenario) run(ctx context.Context, r *relay.Relay) (streamResult, error) {
	if err := os.MkdirAll(s.base, 0o700); err != nil {
		return streamResult{}, err
	}

	formatted := fmt.Sprintf("%d rooms x %d peers, %s/pair", s.rooms, s.perRoom, humanBytes(int64(s.rate)))
	fmt.Printf("joining %s (%d peers)...\n", formatted, s.rooms*s.perRoom)
	joinedAt := time.Now()

	members := make([][]roomMember, s.rooms)
	var failures atomic.Int64
	var wg sync.WaitGroup
	// Bound concurrency: thousands of simultaneous Noise handshakes would measure the
	// scheduler, not the relay.
	sem := make(chan struct{}, 16)
	for i := 0; i < s.rooms; i++ {
		wg.Add(1)
		go func(roomIndex int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			token := fmt.Sprintf("stream-room-%04d", roomIndex)
			list := make([]roomMember, 0, s.perRoom)
			for m := 0; m < s.perRoom; m++ {
				n, err := simpletier.NewNetwork(simpletier.Config{
					Network: simpletier.NetworkConfig{Name: "stream", CIDR: s.cidr, Token: token},
					Options: simpletier.RuntimeOptions{
						LogLevel:  "error",
						RateLimit: boolPtr(false),
					},
				})
				if err != nil {
					failures.Add(1)
					continue
				}
				link, err := relay.JoinRoom(ctx, n, s.tcpAddr, token)
				if err != nil {
					_ = n.Close()
					failures.Add(1)
					continue
				}
				list = append(list, roomMember{network: n, link: link})
			}
			members[roomIndex] = list
		}(i)
	}
	wg.Wait()
	joinTime := time.Since(joinedAt)

	total := s.rooms * s.perRoom
	pairs := 0
	for _, list := range members {
		if len(list) >= 2 {
			pairs++
		}
	}
	result := streamResult{
		pairs:     pairs,
		joined:    total - int(failures.Load()),
		joinTime:  joinTime,
		expected:  int64(pairs) * int64(s.rate) * int64(s.duration.Seconds()),
		latencies: make([]time.Duration, 0, 1024),
	}
	fmt.Printf("joined %d/%d peers in %v, %d usable pairs\n",
		result.joined, total, joinTime.Round(time.Millisecond), pairs)
	if pairs == 0 {
		return result, fmt.Errorf("no usable pair: nothing to measure")
	}

	// Run every pair concurrently for the whole window.
	runCtx, cancel := context.WithTimeout(ctx, s.duration)
	defer cancel()

	var delivered atomic.Int64
	var samples sync.Mutex
	latencyCh := make(chan time.Duration, 4096)
	done := make(chan struct{})
	// One collector owns the latency slice: appending from every pair would need the
	// same lock anyway, and this keeps the sender path allocation-free.
	go func() {
		defer close(done)
		for d := range latencyCh {
			samples.Lock()
			if len(result.latencies) < 200_000 {
				result.latencies = append(result.latencies, d)
			}
			samples.Unlock()
		}
	}()

	var failed atomic.Int64
	var runWG sync.WaitGroup
	for i := 0; i < s.rooms; i++ {
		if len(members[i]) < 2 {
			continue
		}
		runWG.Add(1)
		go func(client, server roomMember, port int) {
			defer runWG.Done()
			n, err := runPair(runCtx, client.network, server.network, port, s.rate, latencyCh)
			delivered.Add(n)
			if err != nil && ctx.Err() == nil {
				failed.Add(1)
			}
		}(members[i][0], members[i][1], streamPortBase+i)
	}
	runWG.Wait()
	close(latencyCh)
	<-done

	result.delivered = delivered.Load()
	if f := failed.Load(); f > 0 {
		fmt.Printf("WARN: %d pairs failed to stream\n", f)
	}
	return result, nil
}

// streamPortBase offsets the per-pair virtual port so no two pairs collide. Port 0 is
// rejected by Listen (it requires 1..65535), so each pair takes its own.
const streamPortBase = 20000

// runPair serves echo on one peer and drives a paced stream from the other, returning
// the bytes that completed a round trip.
func runPair(ctx context.Context, client, server simpletier.Network, port int, rate int, latencyCh chan<- time.Duration) (int64, error) {
	ln, err := server.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return 0, err
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			stream, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = stream.Close() }()
				_, _ = io.Copy(stream, stream)
			}()
		}
	}()

	address := ln.Addr().String()
	var stream simpletier.Stream
	for ctx.Err() == nil {
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		stream, err = client.DialContext(dialCtx, "tcp", address)
		cancel()
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if stream == nil {
		return 0, err
	}
	defer func() { _ = stream.Close() }()

	// One write per 100 ms of budget keeps the pacing coarse enough not to flood the
	// scheduler with timers while still averaging the requested rate.
	const tick = 100 * time.Millisecond
	chunk := rate / 10
	if chunk < 1 {
		chunk = 1
	}
	payload := make([]byte, chunk)
	echo := make([]byte, chunk)
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	var completed int64
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return completed, nil
		case <-ticker.C:
		}
		started := time.Now()
		if _, err := stream.Write(payload); err != nil {
			return completed, err
		}
		if _, err := io.ReadFull(stream, echo); err != nil {
			return completed, err
		}
		completed += int64(chunk)
		select {
		case latencyCh <- time.Since(started):
		default: // drop a sample rather than stall the sender
		}
	}
	return completed, nil
}

// report prints the outcome and computes latency percentiles.
func (s streamScenario) report(res streamResult) {
	elapsed := s.duration.Seconds()
	if elapsed <= 0 {
		return
	}
	aggregate := float64(res.delivered) / elapsed
	target := float64(res.expected) / elapsed
	fmt.Printf("delivered %.2f MB/s aggregate across %d pairs (target %.2f MB/s)",
		aggregate/1e6, res.pairs, target/1e6)
	if target > 0 {
		fmt.Printf(", %.1f%% of target", aggregate/target*100)
	}
	fmt.Println()
	fmt.Printf("per-pair effective: %.2f MB/s (target %.2f MB/s)\n",
		aggregate/float64(res.pairs)/1e6, float64(s.rate)/1e6)

	if len(res.latencies) == 0 {
		fmt.Println("latency: no samples")
		return
	}
	sort.Slice(res.latencies, func(i, j int) bool { return res.latencies[i] < res.latencies[j] })
	pct := func(p float64) time.Duration {
		idx := int(float64(len(res.latencies)-1) * p)
		return res.latencies[idx]
	}
	fmt.Printf("round-trip latency (%d samples): p50=%v p90=%v p99=%v max=%v\n",
		len(res.latencies),
		pct(0.50).Round(time.Microsecond),
		pct(0.90).Round(time.Microsecond),
		pct(0.99).Round(time.Microsecond),
		res.latencies[len(res.latencies)-1].Round(time.Microsecond))
}

// humanBytes formats a byte count for one-line progress output.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
