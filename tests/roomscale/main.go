// Command roomscale measures a relay under a growing population of room members.
//
// It starts one relay, joins N peers to a room, reports how long that took and what
// it cost, then measures throughput between two members to show the effect of
// population on the data plane.
//
// Every peer here connects from 127.0.0.1, so the per-source handshake limiter
// (rateSourceConnectPerSec, 64/s with a 256 burst) applies to all of them as one
// source. A run above roughly that rate will see "peer link admission was not
// confirmed" — that is the limiter working, not a relay capacity ceiling. Real
// deployments have peers on distinct addresses and do not collide this way.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/relay"
	"github.com/yiiilin/simpletier/pkg/simpletier/room"
)

func main() {
	runtime.SetBlockProfileRate(1)
	defer func() {
		f, _ := os.Create("/tmp/rooms_block.prof")
		if f != nil {
			_ = pprof.Lookup("block").WriteTo(f, 0)
			f.Close()
		}
	}()
	peers := flag.Int("peers", 100, "how many members to join into ONE room (single-room mode)")
	rooms := flag.Int("rooms", 0, "how many independent rooms to join (room-count mode); takes precedence over -peers")
	perRoom := flag.Int("per-room", 2, "members per room in room-count mode")
	sustainedMode := flag.Bool("sustained", false, "stream every room's pairs concurrently for -duration and report stability")
	transferMode := flag.Bool("transfer", false, "probe one pair per room with a large file in both directions")
	size := flag.Int64("size", 50<<20, "bytes per direction in transfer mode")
	delay := flag.Duration("delay", 150*time.Millisecond, "one-way delay for the slow peer in transfer mode")
	jitter := flag.Duration("jitter", 50*time.Millisecond, "one-way delay jitter for the slow peer in transfer mode")
	parallel := flag.Int("parallel", 32, "how many rooms transfer at once in transfer mode")
	streamMode := flag.Bool("stream", false, "measure sustained per-pair throughput and latency instead of just joining")
	rate := flag.Int("rate", 1<<20, "bytes per second per pair in stream mode")
	hold := flag.Duration("duration", 10*time.Second, "measurement window in stream mode")
	cidr := flag.String("cidr", "10.210.0.0/16", "room CIDR; must fit the peer count")
	tcpAddr := flag.String("tcp", "127.0.0.1:22120", "relay TCP ingress address")
	base := flag.String("base", "/tmp/roomscale", "state directory base")
	token := flag.String("token", "scale-token-0123456789", "room token")
	flag.Parse()

	if *sustainedMode {
		if err := runSustained(*rooms, *perRoom, *rate, *hold, *delay, *jitter, *cidr, *tcpAddr, *base); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *transferMode {
		if err := runTransfer(*rooms, *perRoom, *size, *delay, *jitter, *parallel, *cidr, *tcpAddr, *base); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *streamMode {
		if err := runStream(*rooms, *perRoom, *rate, *hold, *cidr, *tcpAddr, *base); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *rooms > 0 {
		if err := runRoomCount(*rooms, *perRoom, *cidr, *tcpAddr, *base); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(*peers, *cidr, *tcpAddr, *base, *token); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(peers int, cidr, tcpAddr, base, token string) error {
	if err := os.RemoveAll(base); err != nil {
		return err
	}
	for _, d := range []string{base + "/relay", base + "/peers"} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := relay.New(relay.Options{Rooms: room.Options{
		Name: "scale", CIDR: cidr, LogLevel: "error",
		RateLimit: boolPtr(false),
	}})
	defer func() { _ = r.Close() }()

	go func() { _ = r.ServeTCP(ctx, tcpAddr) }()
	if err := waitListening(tcpAddr, 10*time.Second); err != nil {
		return err
	}

	var rssBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&rssBefore)

	fmt.Printf("joining %d peers into one room...\n", peers)
	started := time.Now()

	type joined struct {
		network simpletier.Network
		link    simpletier.AttachedLink
	}
	joinedPeers := make([]joined, peers)
	var failures atomic.Int64

	var wg sync.WaitGroup
	sem := make(chan struct{}, 32) // bound concurrent handshakes
	for i := 0; i < peers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			dir := fmt.Sprintf("%s/peers/%04d", base, index)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				failures.Add(1)
				return
			}
			n, err := simpletier.NewNetwork(simpletier.Config{
				Network: simpletier.NetworkConfig{Name: "scale", CIDR: cidr, Token: token},
				Options: simpletier.RuntimeOptions{
					LogLevel:  "error",
					RateLimit: boolPtr(false),
				},
			})
			if err != nil {
				fmt.Printf("  peer %d network: %v\n", index, err)
				failures.Add(1)
				return
			}
			link, err := relay.JoinRoom(ctx, n, tcpAddr, token)
			if err != nil {
				fmt.Printf("  peer %d join: %v\n", index, err)
				_ = n.Close()
				failures.Add(1)
				return
			}
			joinedPeers[index] = joined{network: n, link: link}
		}(i)
	}
	wg.Wait()
	joinElapsed := time.Since(started)

	var afterJoin runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&afterJoin)

	fmt.Printf("joined %d/%d peers in %v (%.1f/s), failures=%d\n",
		peers-int(failures.Load()), peers, joinElapsed,
		float64(peers-int(failures.Load()))/joinElapsed.Seconds(), failures.Load())
	fmt.Printf("heap: %.1f MiB -> %.1f MiB (+%.1f MiB, %.1f KiB/peer)\n",
		float64(rssBefore.HeapAlloc)/(1<<20), float64(afterJoin.HeapAlloc)/(1<<20),
		float64(afterJoin.HeapAlloc-rssBefore.HeapAlloc)/(1<<20),
		float64(afterJoin.HeapAlloc-rssBefore.HeapAlloc)/float64(max(peers, 1))/1024)

	// Room view from the relay's own side.
	rooms := r.List()
	if len(rooms) != 1 {
		fmt.Printf("WARN: relay reports %d rooms\n", len(rooms))
	} else {
		fmt.Printf("relay: room=%s carriers=%d vip=%s\n",
			rooms[0].ID[:12], rooms[0].Carriers, rooms[0].VirtualIP)
	}

	// Throughput between two members of this now-populated room.
	first := joinedPeers[0].network
	second := joinedPeers[1].network
	if first != nil && second != nil {
		rate, err := measureEcho(ctx, first, second)
		if err != nil {
			fmt.Printf("echo failed: %v\n", err)
		} else {
			fmt.Printf("echo throughput with %d peers in the room: %.2f MB/s\n", peers, rate)
		}
	}

	var final runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&final)
	fmt.Printf("final heap %.1f MiB, goroutines %d\n",
		float64(final.HeapAlloc)/(1<<20), runtime.NumGoroutine())
	return nil
}

// runRoomCount measures the deployment shape the relay exists for: many independent
// rooms with a few members each.
func runRoomCount(rooms, perRoom int, cidr, tcpAddr, base string) error {
	base = base + "-rooms"
	if err := os.RemoveAll(base); err != nil {
		return err
	}
	if err := os.MkdirAll(base+"/relay", 0o700); err != nil {
		return err
	}

	ctx := context.Background()
	r := relay.New(relay.Options{Rooms: room.Options{
		Name:      "roomscale",
		CIDR:      cidr,
		LogLevel:  "error",
		RateLimit: boolPtr(false),
	}})
	defer func() { _ = r.Close() }()

	go func() { _ = r.ServeTCP(ctx, tcpAddr) }()
	if err := waitListening(tcpAddr, 10*time.Second); err != nil {
		return err
	}

	scenario := roomCountScenario{
		rooms: rooms, perRoom: perRoom, cidr: cidr, tcpAddr: tcpAddr, base: base + "/peers",
	}
	return scenario.run(ctx, r)
}

// runSustained streams every room's pairs at once for the whole window.
func runSustained(rooms, perRoom, rate int, hold, delay, jitter time.Duration, cidr, tcpAddr, base string) error {
	if rooms <= 0 || perRoom < 2 {
		return fmt.Errorf("sustained mode needs -rooms and -per-room of at least 2")
	}
	base = base + "-sustained"
	if err := os.RemoveAll(base); err != nil {
		return err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}

	ctx := context.Background()
	r := relay.New(relay.Options{Rooms: room.Options{
		Name: "sustained", CIDR: cidr, LogLevel: "error", RateLimit: boolPtr(false),
	}})
	defer func() { _ = r.Close() }()

	go func() { _ = r.ServeTCP(ctx, tcpAddr) }()
	if err := waitListening(tcpAddr, 10*time.Second); err != nil {
		return err
	}

	scenario := sustainedScenario{
		rooms: rooms, perRoom: perRoom, rate: rate, duration: hold,
		delay: delay, jitter: jitter, cidr: cidr, tcpAddr: tcpAddr, base: base,
	}
	return scenario.run(ctx, r)
}

// runTransfer probes one pair per room with a large file in both directions, with one
// side of each pair behind a high-latency path.
func runTransfer(rooms, perRoom int, size int64, delay, jitter time.Duration, parallel int, cidr, tcpAddr, base string) error {
	if rooms <= 0 {
		return fmt.Errorf("transfer mode needs -rooms")
	}
	if perRoom < 2 {
		return fmt.Errorf("transfer mode needs -per-room of at least 2")
	}
	base = base + "-transfer"
	if err := os.RemoveAll(base); err != nil {
		return err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}

	ctx := context.Background()
	r := relay.New(relay.Options{Rooms: room.Options{
		Name: "transfer", CIDR: cidr, LogLevel: "error", RateLimit: boolPtr(false),
	}})
	defer func() { _ = r.Close() }()

	go func() { _ = r.ServeTCP(ctx, tcpAddr) }()
	if err := waitListening(tcpAddr, 10*time.Second); err != nil {
		return err
	}

	scenario := transferScenario{
		rooms: rooms, perRoom: perRoom, size: size,
		delay: delay, jitter: jitter,
		cidr: cidr, tcpAddr: tcpAddr, base: base, parallel: parallel,
	}
	return scenario.run(ctx, r)
}

// runStream measures sustained throughput and latency with every room carrying data.
func runStream(rooms, perRoom, rate int, hold time.Duration, cidr, tcpAddr, base string) error {
	if rooms <= 0 {
		return fmt.Errorf("stream mode needs -rooms")
	}
	base = base + "-stream"
	if err := os.RemoveAll(base); err != nil {
		return err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}

	ctx := context.Background()
	r := relay.New(relay.Options{Rooms: room.Options{
		Name: "stream", CIDR: cidr, LogLevel: "error", RateLimit: boolPtr(false),
	}})
	defer func() { _ = r.Close() }()

	go func() { _ = r.ServeTCP(ctx, tcpAddr) }()
	if err := waitListening(tcpAddr, 10*time.Second); err != nil {
		return err
	}

	scenario := streamScenario{
		rooms: rooms, perRoom: perRoom, rate: rate,
		cidr: cidr, tcpAddr: tcpAddr, base: base, duration: hold,
	}
	result, err := scenario.run(ctx, r)
	if err != nil {
		return err
	}
	scenario.report(result)
	return nil
}

// measureEcho runs a 8 MiB echo between two peers through the relay.
func measureEcho(ctx context.Context, client, server simpletier.Network) (float64, error) {
	const (
		payloadSize = 8 << 20
		chunk       = 256 << 10
	)
	ln, err := server.Listen("tcp", ":9800")
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

	address := fmt.Sprintf("%s:9800", server.LocalVirtualIP())
	var stream simpletier.Stream
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
		stream, err = client.DialContext(dialCtx, "tcp", address)
		dialCancel()
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = stream.Close() }()

	payload := make([]byte, chunk)
	got := make([]byte, chunk)

	readDone := make(chan error, 1)
	go func() {
		var read int
		for read < payloadSize {
			n, err := io.ReadFull(stream, got)
			read += n
			if err != nil {
				readDone <- err
				return
			}
		}
		readDone <- nil
	}()

	started := time.Now()
	written := 0
	for written < payloadSize {
		n, err := stream.Write(payload)
		written += n
		if err != nil {
			return 0, err
		}
	}
	if err := <-readDone; err != nil {
		return 0, err
	}
	return float64(payloadSize) / time.Since(started).Seconds() / 1e6, nil
}

// boolPtr returns a pointer to v.
func boolPtr(v bool) *bool { return &v }

func waitListening(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("%s never started listening", addr)
}
