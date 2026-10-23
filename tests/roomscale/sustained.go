package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/relay"
)

// sustainedScenario is the full concurrent shape: every room split into pairs, every
// pair streaming for the whole window while one side of each pair sits behind a delay.
//
// The earlier transferScenario sent one pair per room, which left most members idle and
// never exercised contention between pairs. This one runs all of them at once and asks
// whether throughput holds steady rather than whether a single pair can hit a peak.
type sustainedScenario struct {
	rooms    int
	perRoom  int
	rate     int // per-pair target bytes per second, 0 = unthrottled
	duration time.Duration
	delay    time.Duration
	jitter   time.Duration
	cidr     string
	tcpAddr  string
	base     string
}

// pairResult is one pair's outcome over the window.
type pairResult struct {
	room       int
	pair       int
	uploaded   int64
	downloaded int64
	latencies  []time.Duration
	err        error
}

func (s sustainedScenario) run(ctx context.Context, r *relay.Relay) error {
	if err := os.MkdirAll(s.base, 0o700); err != nil {
		return err
	}
	pairsPerRoom := s.perRoom / 2
	if pairsPerRoom < 1 {
		return fmt.Errorf("need at least 2 members per room, got %d", s.perRoom)
	}

	slowAddr, slowPort, err := slowPortAddr(s.tcpAddr)
	if err != nil {
		return err
	}
	fmt.Printf("applying netem: one-way %v +/- %v on %s port %d\n",
		s.delay, s.jitter, netemIface, slowPort)
	netem, err := applyNetemDelay(netemIface, slowPort, s.delay.String(), s.jitter.String())
	if err != nil {
		return fmt.Errorf("apply netem delay: %w", err)
	}
	defer func() {
		if rmErr := netem.remove(); rmErr != nil {
			fmt.Printf("WARN: removing netem: %v\n", rmErr)
		}
	}()
	// Both ingresses must be listening before any peer dials. Starting the second one
	// asynchronously without waiting made the first slow peers connect while it was still
	// binding, which surfaces as "attach control lane: EOF" and silently empties rooms.
	go func() { _ = r.ServeTCP(ctx, slowAddr) }()
	if err := waitListening(slowAddr, 10*time.Second); err != nil {
		return fmt.Errorf("slow ingress %s: %w", slowAddr, err)
	}

	totalPeers := s.rooms * s.perRoom
	totalPairs := s.rooms * pairsPerRoom
	fmt.Printf("joining %d rooms x %d peers = %d peers (%d pairs will stream for %v)\n",
		s.rooms, s.perRoom, totalPeers, totalPairs, s.duration)

	joinedAt := time.Now()
	members := make([][]roomMember, s.rooms)
	var failures atomic.Int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, joinConcurrency)
	for i := 0; i < s.rooms; i++ {
		wg.Add(1)
		go func(roomIndex int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			members[roomIndex] = joinRoomMembers(ctx, "sustained", s.cidr, roomIndex, s.perRoom, s.tcpAddr, slowAddr, &failures)
		}(i)
	}
	wg.Wait()
	fmt.Printf("joined %d/%d peers in %v, relay holds %d rooms\n",
		totalPeers-int(failures.Load()), totalPeers,
		time.Since(joinedAt).Round(time.Millisecond), r.Count())
	reportJoinErrors()

	// Every pair streams for the same wall-clock window so rates are comparable, and the
	// window starts only after all pairs are connected. Starting it before the dials would
	// bill fact convergence to the measurement and shorten it by however long the slowest
	// room took to become routable.
	startGate := make(chan struct{})
	results := make([]pairResult, 0, totalPairs)
	var mu sync.Mutex
	var runWG sync.WaitGroup
	var pairsWG sync.WaitGroup

	windowDuration = s.duration
	startedAt := time.Now()
	for i := 0; i < s.rooms; i++ {
		list := members[i]
		if len(list) < 2 {
			continue
		}
		for p := 0; p < pairsPerRoom && 2*p+1 < len(list); p++ {
			client, server := list[2*p], list[2*p+1]
			runWG.Add(1)
			pairsWG.Add(1)
			go func(roomIndex, pairIndex int, client, server roomMember) {
				defer runWG.Done()
				result := streamPair(ctx, startGate, &pairsWG, roomIndex, pairIndex,
					client.network, server.network, 40000+roomIndex*8+pairIndex, s.rate)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}(i, p, client, server)
		}
	}
	go func() {
		pairsWG.Wait()
		close(startGate)
	}()
	runWG.Wait()
	wall := time.Since(startedAt)

	s.report(results, wall)
	return nil
}

// streamPair echoes on the server and pushes from the client until ctx ends, sampling
// round-trip latency throughout.
// windowDuration is how long each pair streams after the shared start gate opens. Set per
// run by the scenario before launching pairs.
var windowDuration = 60 * time.Second

func streamPair(dialCtx context.Context, startGate <-chan struct{}, ready *sync.WaitGroup, roomIndex, pairIndex int, client, server simpletier.Network, port, rate int) pairResult {
	result := pairResult{room: roomIndex, pair: pairIndex}

	ln, err := server.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		result.err = fmt.Errorf("listen: %w", err)
		return result
	}
	defer func() { _ = ln.Close() }()

	// Accept the bulk stream, then echo on it for the whole window.
	accepted := make(chan simpletier.Stream, 1)
	go func() {
		stream, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- stream
	}()

	// Facts propagate before a virtual address is routable, so the first dials routinely
	// report "no route". Retrying with a fresh deadline per attempt is what distinguishes
	// a slow convergence from a real failure.
	address := ln.Addr().String()
	var stream simpletier.Stream
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && dialCtx.Err() == nil {
		attemptCtx, attemptCancel := context.WithTimeout(dialCtx, 5*time.Second)
		stream, err = client.DialContext(attemptCtx, "tcp", address)
		attemptCancel()
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if stream == nil {
		ready.Done()
		result.err = fmt.Errorf("dial %s: %w", address, err)
		return result
	}
	defer func() { _ = stream.Close() }()

	serverSide, ok := <-accepted
	if !ok {
		ready.Done()
		result.err = fmt.Errorf("server accepted nothing")
		return result
	}
	defer func() { _ = serverSide.Close() }()

	// Connected and accepted: the pair is up. The measurement window opens once every
	// pair reports the same.
	ready.Done()
	<-startGate

	// Timed from here, not from the dial: every pair then measures the same window
	// regardless of how long its own connection took to establish.
	runCtx, cancelRun := context.WithTimeout(dialCtx, windowDuration)
	defer cancelRun()

	// Server echoes continuously on its side.
	var echoWG sync.WaitGroup
	echoWG.Add(1)
	go func() {
		defer echoWG.Done()
		buf := make([]byte, 256<<10)
		for {
			n, err := serverSide.Read(buf)
			if n > 0 {
				if _, werr := serverSide.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// One write/read buffer per direction. The size is a throughput/overhead tradeoff, not
	// a protocol limit: anything below the socket buffer keeps the pipe full.
	const chunk = 64 << 10

	// Closing the stream is the only reliable way to break a blocked Write or ReadFull:
	// ctx cancellation does not interrupt them, and a few stuck pairs would otherwise hold
	// the whole run open well past its window.
	go func() {
		<-runCtx.Done()
		_ = stream.Close()
		_ = serverSide.Close()
	}()

	// Write continuously and read the echo on its own goroutine. Waiting for each echo
	// before sending the next chunk would cap the pair at chunk/RTT — stop-and-wait — and
	// measure the round trip rather than the achievable throughput.
	var sent, received int64
	var writeErr, readErr error
	var ioWG sync.WaitGroup

	ioWG.Add(2)
	go func() {
		defer ioWG.Done()
		buf := make([]byte, chunk)
		for runCtx.Err() == nil {
			n, err := stream.Write(buf)
			sent += int64(n)
			if err != nil {
				if runCtx.Err() == nil {
					writeErr = err
				}
				return
			}
		}
	}()
	go func() {
		defer ioWG.Done()
		buf := make([]byte, chunk)
		for runCtx.Err() == nil {
			n, err := stream.Read(buf)
			received += int64(n)
			if err != nil {
				if runCtx.Err() == nil {
					readErr = err
				}
				return
			}
		}
	}()

	// One latency sample per 100 ms on the same connection, so the reported round trip
	// reflects the path the bulk data is using.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for runCtx.Err() == nil {
		select {
		case <-runCtx.Done():
		case <-ticker.C:
		}
	}
	ioWG.Wait()
	_ = cancelRun

	if writeErr != nil {
		result.err = fmt.Errorf("write: %w", writeErr)
	}
	if readErr != nil && result.err == nil {
		result.err = fmt.Errorf("read: %w", readErr)
	}
	result.uploaded = sent
	result.downloaded = received

	return result
}

// report prints steady-state rates and latency across all pairs.
func (s sustainedScenario) report(results []pairResult, wall time.Duration) {
	var ok []pairResult
	failed := 0
	for _, res := range results {
		if res.err != nil {
			failed++
			continue
		}
		ok = append(ok, res)
	}
	fmt.Printf("\nmeasured %d/%d pairs over %v (%d failed)\n",
		len(ok), len(results), wall.Round(time.Millisecond), failed)
	if len(ok) == 0 {
		return
	}

	seconds := wall.Seconds()
	upRates := make([]float64, 0, len(ok))
	downRates := make([]float64, 0, len(ok))
	var allLat []time.Duration
	var totalUp, totalDown int64
	for _, res := range ok {
		up := float64(res.uploaded) / seconds / 1e6
		down := float64(res.downloaded) / seconds / 1e6
		upRates = append(upRates, up)
		downRates = append(downRates, down)
		totalUp += res.uploaded
		totalDown += res.downloaded
		allLat = append(allLat, res.latencies...)
	}

	summary := func(name string, rates []float64, total int64) {
		sort.Float64s(rates)
		var sum float64
		for _, v := range rates {
			sum += v
		}
		mean := sum / float64(len(rates))
		pct := func(p float64) float64 { return rates[int(float64(len(rates)-1)*p)] }
		// Spread is the stability signal: a steady run has a narrow p50-to-p10 gap.
		fmt.Printf("%s per pair: mean %.2f MB/s  p10 %.2f  p50 %.2f  p90 %.2f  max %.2f MB/s\n",
			name, mean, pct(0.10), pct(0.50), pct(0.90), rates[len(rates)-1])
		fmt.Printf("  aggregate %.2f MB/s (%s over %v)\n",
			float64(total)/seconds/1e6, humanBytes(total), wall.Round(time.Second))
	}
	summary("upload", upRates, totalUp)
	summary("download", downRates, totalDown)

	if len(allLat) > 0 {
		sort.Slice(allLat, func(i, j int) bool { return allLat[i] < allLat[j] })
		pct := func(p float64) time.Duration { return allLat[int(float64(len(allLat)-1)*p)] }
		fmt.Printf("round-trip latency (%d samples): p50=%v p90=%v p99=%v max=%v\n",
			len(allLat), pct(0.50).Round(time.Millisecond), pct(0.90).Round(time.Millisecond),
			pct(0.99).Round(time.Millisecond), allLat[len(allLat)-1].Round(time.Millisecond))
	}
}
