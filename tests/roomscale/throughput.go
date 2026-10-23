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

// joinConcurrency bounds how many rooms join at once during the setup phase.
const joinConcurrency = 64

// transferScenario is the acceptance shape for a relay deployment: many rooms, each
// with a few members, and one pair per room moving a large file in both directions
// while one side of that pair sits behind a high-latency path.
type transferScenario struct {
	rooms    int
	perRoom  int
	size     int64
	delay    time.Duration
	jitter   time.Duration
	cidr     string
	tcpAddr  string
	base     string
	parallel int
}

// transferSample is one room's measured result.
type transferSample struct {
	upload, download float64 // bytes per second
	uploadElapsed    time.Duration
	downloadElapsed  time.Duration
	// idleLatency is measured on a quiet connection before any bulk data flows.
	idleLatency time.Duration
	// loadedLatencies are probes sent while bulk data is in flight, which is what a
	// client actually experiences. Reporting only the idle figure hides queueing: a run
	// can show a perfect 300 ms and still deliver multi-second waits under load.
	loadedLatencies []time.Duration
}

func (s transferScenario) run(ctx context.Context, r *relay.Relay) error {
	if err := os.MkdirAll(s.base, 0o700); err != nil {
		return err
	}

	// One peer per room sits behind a kernel-level delay on a dedicated port; the rest
	// connect to the plain port. See netem.go for why the delay is not a userspace proxy.
	slowAddr, slowPort, err := slowPortAddr(s.tcpAddr)
	if err != nil {
		return err
	}
	fmt.Printf("applying netem: one-way %v +/- %v on %s port %d (round trip ~%v)\n",
		s.delay, s.jitter, netemIface, slowPort, 2*s.delay)
	netem, err := applyNetemDelay(netemIface, slowPort,
		s.delay.String(), s.jitter.String())
	if err != nil {
		return fmt.Errorf("apply netem delay: %w", err)
	}
	defer func() {
		if rmErr := netem.remove(); rmErr != nil {
			fmt.Printf("WARN: removing netem: %v\n", rmErr)
		}
	}()

	// The relay must accept carriers on both ports: the delayed one and the plain one.
	go func() { _ = r.ServeTCP(ctx, slowAddr) }()

	total := s.rooms * s.perRoom
	fmt.Printf("joining %d rooms x %d peers = %d peers (%d pairs will transfer %s each)\n",
		s.rooms, s.perRoom, total, s.rooms, humanBytes(s.size))

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
			members[roomIndex] = joinRoomMembers(ctx, "transfer", s.cidr, roomIndex, s.perRoom, s.tcpAddr, slowAddr, &failures)
		}(i)
	}
	wg.Wait()

	joined := total - int(failures.Load())
	fmt.Printf("joined %d/%d peers in %v, relay holds %d rooms\n",
		joined, total, time.Since(joinedAt).Round(time.Millisecond), r.Count())
	reportJoinErrors()
	if joined == 0 {
		return fmt.Errorf("no peer joined")
	}

	// Measure every room's pair concurrently, bounded so the run does not measure the
	// scheduler.
	parallel := s.parallel
	if parallel <= 0 {
		parallel = 32
	}
	samples := make([]transferSample, s.rooms)
	var sampleErr atomic.Int64
	var runWG sync.WaitGroup
	slot := make(chan struct{}, parallel)
	measureStart := time.Now()
	for i := 0; i < s.rooms; i++ {
		if len(members[i]) < 2 {
			sampleErr.Add(1)
			continue
		}
		runWG.Add(1)
		go func(roomIndex int) {
			defer runWG.Done()
			slot <- struct{}{}
			defer func() { <-slot }()
			sample, err := measureRoomTransfer(ctx, members[roomIndex][0].network, members[roomIndex][1].network, s.size)
			if err != nil {
				sampleErr.Add(1)
				fmt.Printf("  room %d transfer error: %v\n", roomIndex, err)
				return
			}
			samples[roomIndex] = sample
		}(i)
	}
	runWG.Wait()
	wall := time.Since(measureStart)

	s.report(samples, int(sampleErr.Load()), wall)
	return nil
}

// joinRoomMembers creates one room's peers. The first member connects through the slow
// proxy, the rest directly.
func joinRoomMembers(ctx context.Context, name, cidr string, roomIndex, perRoom int, relayAddr, slowAddr string, failures *atomic.Int64) []roomMember {
	token := fmt.Sprintf("transfer-room-%04d", roomIndex)
	// Member 0 is the slow-path peer. It must be present and must have joined through
	// the proxy: falling back to a directly connected peer would silently measure the
	// loopback path and report it as the 150 ms path.
	// Members alternate: even indexes join through the delayed ingress, odd indexes
	// directly. That way every pair has exactly one delayed side, so each pair measures
	// the same path instead of only the first one carrying the latency.
	list := make([]roomMember, 0, perRoom)
	for m := 0; m < perRoom; m++ {
		throughSlow := m%2 == 0
		addr := relayAddr
		if throughSlow {
			addr = slowAddr
		}
		n, err := simpletier.NewNetwork(simpletier.Config{
			Network: simpletier.NetworkConfig{Name: name, CIDR: cidr, Token: token},
			Options: simpletier.RuntimeOptions{LogLevel: "error", RateLimit: boolPtr(false)},
		})
		if err != nil {
			failures.Add(1)
			continue
		}
		link, err := relay.JoinRoom(ctx, n, addr, token)
		if err != nil {
			_ = n.Close()
			recordJoinError("join", err)
			failures.Add(1)
			continue
		}
		list = append(list, roomMember{network: n, link: link})
	}
	return list
}

// joinMember creates one peer and joins it through addr, reporting whether it worked.
func joinMember(ctx context.Context, name, cidr, token, addr string) (roomMember, bool) {
	n, err := simpletier.NewNetwork(simpletier.Config{
		Network: simpletier.NetworkConfig{Name: name, CIDR: cidr, Token: token},
		Options: simpletier.RuntimeOptions{LogLevel: "error", RateLimit: boolPtr(false)},
	})
	if err != nil {
		recordJoinError("network", err)
		return roomMember{}, false
	}
	link, err := relay.JoinRoom(ctx, n, addr, token)
	if err != nil {
		_ = n.Close()
		recordJoinError("join", err)
		return roomMember{}, false
	}
	return roomMember{network: n, link: link}, true
}

// joinErrorCounts tallies join failures by class so a run reports why peers were lost
// instead of only how many.
var joinErrorCounts sync.Map

func recordJoinError(stage string, err error) {
	if err == nil {
		err = fmt.Errorf("nil error")
	}
	key := stage + ": " + err.Error()
	// LoadOrStore keeps the stored value a single *atomic.Int64. Storing Add's int64
	// back would change the entry's type and panic the next assertion.
	counter, _ := joinErrorCounts.LoadOrStore(key, &atomic.Int64{})
	counter.(*atomic.Int64).Add(1)
}

// reportJoinErrors prints the failure classes, most frequent first.
func reportJoinErrors() {
	type entry struct {
		key   string
		count int64
	}
	var all []entry
	joinErrorCounts.Range(func(k, v any) bool {
		all = append(all, entry{k.(string), v.(*atomic.Int64).Load()})
		return true
	})
	if len(all) == 0 {
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].count > all[j].count })
	fmt.Println("join failures by class:")
	for _, e := range all {
		fmt.Printf("  %4d  %s\n", e.count, e.key)
	}
}

// measureRoomTransfer sends size bytes each way between one pair and samples latency.
func measureRoomTransfer(ctx context.Context, client, server simpletier.Network, size int64) (transferSample, error) {
	ln, err := server.Listen("tcp", fmt.Sprintf(":%d", 30000))
	if err != nil {
		return transferSample{}, err
	}
	defer func() { _ = ln.Close() }()

	// The server accepts one connection and echoes, so a round trip is one write and
	// one read from the client's point of view.
	// Two connections arrive: the bulk stream and the latency probe. Both need a peer, so
	// the accept loop echoes on whichever is not claimed as the bulk stream. Accepting only
	// once left the probe unanswered, and its writer then blocked forever.
	accepted := make(chan simpletier.Stream, 1)
	stopAccept := make(chan struct{})
	go func() {
		bulkClaimed := false
		for {
			stream, err := ln.Accept()
			if err != nil {
				close(accepted)
				return
			}
			if !bulkClaimed {
				bulkClaimed = true
				select {
				case accepted <- stream:
				case <-stopAccept:
					_ = stream.Close()
					return
				}
				continue
			}
			go func(s simpletier.Stream) {
				defer func() { _ = s.Close() }()
				_, _ = io.Copy(s, s)
			}(stream)
		}
	}()
	defer close(stopAccept)

	// The listener address is the server's virtual address, which the client can only
	// reach after facts converge. Retry with a fresh per-attempt deadline.
	address := ln.Addr().String()
	var stream simpletier.Stream
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		attemptCtx, attemptCancel := context.WithTimeout(ctx, 3*time.Second)
		stream, err = client.DialContext(attemptCtx, "tcp", address)
		attemptCancel()
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if stream == nil {
		return transferSample{}, fmt.Errorf("dial room peer %s: %w", address, err)
	}
	defer func() { _ = stream.Close() }()

	serverSide, ok := <-accepted
	if !ok {
		return transferSample{}, fmt.Errorf("server accepted no connection")
	}
	defer func() { _ = serverSide.Close() }()

	// A second connection carries latency probes for the whole transfer. Probing on the
	// bulk connection would measure its own queue rather than the path, and probing once
	// before the transfer would measure an idle network the user never sees.
	probeStop := make(chan struct{})
	probeDone := make(chan []time.Duration, 1)
	go func() {
		samples := probeLatencyWhileLoaded(ctx, client, ln.Addr().String(), probeStop)
		probeDone <- samples
	}()

	// Latency first, on a quiet path: one tiny write and its echo.
	var sample transferSample
	probe := []byte("probe")
	echo := make([]byte, len(probe))
	started := time.Now()
	if _, err := stream.Write(probe); err != nil {
		return sample, err
	}
	if _, err := io.ReadFull(serverSide, echo); err != nil {
		return sample, err
	}
	if _, err := serverSide.Write(echo); err != nil {
		return sample, err
	}
	if _, err := io.ReadFull(stream, echo); err != nil {
		return sample, err
	}
	sample.idleLatency = time.Since(started)

	// Upload: client writes, server drains.
	sample.upload, sample.uploadElapsed, err = timedUpload(stream, serverSide, size)
	if err != nil {
		return sample, err
	}
	// Download: server writes, client drains, over the same connection.
	sample.download, sample.downloadElapsed, err = timedUpload(serverSide, stream, size)
	if err != nil {
		close(probeStop)
		return sample, err
	}
	close(probeStop)
	sample.loadedLatencies = <-probeDone
	return sample, nil
}

// timedUpload writes size bytes from src and reads them on dst, returning the rate.
func timedUpload(src, dst simpletier.Stream, size int64) (float64, time.Duration, error) {
	const chunkSize = 256 << 10
	done := make(chan error, 1)
	started := time.Now()
	go func() {
		buf := make([]byte, chunkSize)
		remaining := size
		for remaining > 0 {
			n := int64(chunkSize)
			if remaining < n {
				n = remaining
			}
			if _, err := io.ReadFull(dst, buf[:n]); err != nil {
				done <- err
				return
			}
			remaining -= n
		}
		done <- nil
	}()

	payload := make([]byte, chunkSize)
	written := int64(0)
	for written < size {
		n := int64(chunkSize)
		if size-written < n {
			n = size - written
		}
		if _, err := src.Write(payload[:n]); err != nil {
			return 0, 0, err
		}
		written += n
	}
	if err := <-done; err != nil {
		return 0, 0, err
	}
	elapsed := time.Since(started)
	return float64(size) / elapsed.Seconds(), elapsed, nil
}

// report prints aggregate and per-room statistics.
func (s transferScenario) report(samples []transferSample, failed int, wall time.Duration) {
	valid := make([]transferSample, 0, len(samples))
	for _, sample := range samples {
		if sample.upload > 0 && sample.download > 0 {
			valid = append(valid, sample)
		}
	}
	fmt.Printf("\nmeasured %d/%d rooms in %v (%d failed)\n",
		len(valid), s.rooms, wall.Round(time.Millisecond), failed)
	if len(valid) == 0 {
		return
	}

	up := make([]float64, len(valid))
	down := make([]float64, len(valid))
	idle := make([]time.Duration, len(valid))
	var loaded []time.Duration
	for i, sample := range valid {
		up[i] = sample.upload / 1e6
		down[i] = sample.download / 1e6
		idle[i] = sample.idleLatency
		loaded = append(loaded, sample.loadedLatencies...)
	}
	reportDirection := func(name string, rates []float64) {
		sort.Float64s(rates)
		sum := 0.0
		for _, v := range rates {
			sum += v
		}
		fmt.Printf("%s over %s, one path with ~%v RTT:\n", name, humanBytes(s.size),
			2*s.delay)
		fmt.Printf("  mean %.2f MB/s  p50 %.2f  p90 %.2f  min %.2f  max %.2f  aggregate %.2f MB/s\n",
			sum/float64(len(rates)),
			rates[len(rates)/2],
			rates[int(float64(len(rates)-1)*0.9)],
			rates[0], rates[len(rates)-1], sum)
	}
	reportDirection("upload", up)
	reportDirection("download", down)

	// Idle latency is one probe per room on a quiet connection; loaded latency is sampled
	// throughout the bulk transfer. The gap between them is the queueing cost.
	sort.Slice(idle, func(i, j int) bool { return idle[i] < idle[j] })
	idlePct := func(p float64) time.Duration { return idle[int(float64(len(idle)-1)*p)] }
	fmt.Printf("idle round-trip latency (%d rooms): p50=%v p90=%v max=%v\n",
		len(idle), idlePct(0.50).Round(time.Millisecond),
		idlePct(0.90).Round(time.Millisecond), idle[len(idle)-1].Round(time.Millisecond))

	if len(loaded) > 0 {
		sort.Slice(loaded, func(i, j int) bool { return loaded[i] < loaded[j] })
		loadedPct := func(p float64) time.Duration {
			return loaded[int(float64(len(loaded)-1)*p)]
		}
		fmt.Printf("loaded round-trip latency (%d probes during transfer): p50=%v p90=%v p99=%v max=%v\n",
			len(loaded), loadedPct(0.50).Round(time.Millisecond),
			loadedPct(0.90).Round(time.Millisecond), loadedPct(0.99).Round(time.Millisecond),
			loaded[len(loaded)-1].Round(time.Millisecond))
		if median := loadedPct(0.50); median > 0 {
			fmt.Printf("queueing cost: p50 loaded is %.2fx idle\n",
				float64(median)/float64(idlePct(0.50)))
		}
	}
}

// probeLatencyWhileLoaded opens its own connection to the same listener and measures a
// round trip every probeInterval until stop closes. It exists because latency under load
// is the number that matters and it is not observable on an idle connection.
func probeLatencyWhileLoaded(ctx context.Context, client simpletier.Network, address string, stop <-chan struct{}) []time.Duration {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := client.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil
	}
	defer func() { _ = stream.Close() }()

	const probeInterval = 100 * time.Millisecond
	payload := []byte("probe")
	echo := make([]byte, len(payload))
	var samples []time.Duration
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return samples
		case <-ctx.Done():
			return samples
		case <-ticker.C:
		}
		started := time.Now()
		if _, err := stream.Write(payload); err != nil {
			return samples
		}
		if _, err := io.ReadFull(stream, echo); err != nil {
			return samples
		}
		samples = append(samples, time.Since(started))
	}
}
