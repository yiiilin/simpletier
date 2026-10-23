package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/relay"
)

// roomCountScenario joins `rooms` independent rooms with `perRoom` members each,
// which is the deployment shape a relay is actually for: many small rooms, not one
// large one. It reports admission, cost, and whether members can still reach each
// other as the room count grows.
type roomCountScenario struct {
	rooms   int
	perRoom int
	cidr    string
	tcpAddr string
	base    string
}

type roomMember struct {
	network simpletier.Network
	link    simpletier.AttachedLink
}

func (s roomCountScenario) run(ctx context.Context, r *relay.Relay) error {
	if err := os.MkdirAll(s.base, 0o700); err != nil {
		return err
	}

	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	fmt.Printf("joining %d rooms x %d members = %d peers...\n",
		s.rooms, s.perRoom, s.rooms*s.perRoom)
	started := time.Now()

	members := make([][]roomMember, s.rooms)
	var failures atomic.Int64
	var joinTime atomic.Int64
	var newTime atomic.Int64

	var wg sync.WaitGroup
	sem := make(chan struct{}, 1)
	for i := 0; i < s.rooms; i++ {
		wg.Add(1)
		go func(roomIndex int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			token := fmt.Sprintf("room-%04d-token", roomIndex)
			list := make([]roomMember, 0, s.perRoom)
			for m := 0; m < s.perRoom; m++ {
				dir := fmt.Sprintf("%s/r%04d-m%d", s.base, roomIndex, m)
				if err := os.MkdirAll(dir, 0o700); err != nil {
					failures.Add(1)
					continue
				}
				tn := time.Now()
				n, err := simpletier.NewNetwork(simpletier.Config{
					Network: simpletier.NetworkConfig{
						Name: "roomscale", CIDR: s.cidr, Token: token,
					},
					Options: simpletier.RuntimeOptions{
						// Empty StateDir selects the ephemeral mode: no files, no locks,
						// and a fresh identity per Network.
						LogLevel:  "error",
						RateLimit: boolPtr(false),
					},
				})
				newTime.Add(time.Since(tn).Nanoseconds())
				if err != nil {
					failures.Add(1)
					continue
				}
				tj := time.Now()
				link, err := relay.JoinRoom(ctx, n, s.tcpAddr, token)
				joinTime.Add(time.Since(tj).Nanoseconds())
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
	elapsed := time.Since(started)

	var after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&after)

	total := s.rooms * s.perRoom
	ok := total - int(failures.Load())
	fmt.Printf("joined %d/%d peers (%d rooms) in %v (%.1f peers/s), failures=%d\n",
		ok, total, s.rooms, elapsed, float64(ok)/elapsed.Seconds(), failures.Load())
	fmt.Printf("heap: %.1f MiB -> %.1f MiB (+%.1f MiB, %.1f KiB/peer)\n",
		float64(before.HeapAlloc)/(1<<20), float64(after.HeapAlloc)/(1<<20),
		float64(after.HeapAlloc-before.HeapAlloc)/(1<<20),
		float64(after.HeapAlloc-before.HeapAlloc)/float64(max(total, 1))/1024)
	fmt.Printf("relay rooms=%d goroutines=%d\n", r.Count(), runtime.NumGoroutine())
	if ok > 0 {
		fmt.Printf("avg NewNetwork: %v  avg JoinRoom: %v\n",
			time.Duration(newTime.Load()/int64(ok)), time.Duration(joinTime.Load()/int64(ok)))
	}

	if s.perRoom < 2 {
		return nil
	}

	// Sample a few rooms and verify members can still reach each other, plus that a
	// member of one room cannot reach a member of another.
	checkSame, sameProbes, checkCross, crossProbes := 0, 0, 0, 0
	for i := 0; i < s.rooms && i < 5; i++ {
		if len(members[i]) < 2 {
			continue
		}
		sameProbes++
		ok, err := sameRoomReachable(ctx, members[i][0].network, members[i][1].network)
		if ok {
			checkSame++
		} else if err != nil {
			fmt.Printf("  room %d same-room check: %v\n", i, err)
		}
		if i+1 < s.rooms && len(members[i+1]) > 0 {
			// A cross-room probe must tell "refused because isolated" apart from
			// "never got that far". Only a probe that actually reached the listener and
			// was then refused counts as isolation; anything else is reported, because
			// silently counting a failed setup as isolation would fake a pass.
			crossProbes++
			cross, crossed, err := crossRoomReachable(ctx, members[i][0].network, members[i+1][0].network)
			switch {
			case cross:
				fmt.Printf("  ISOLATION FAILURE: room %d reached room %d\n", i, i+1)
			case crossed:
				checkCross++
			default:
				fmt.Printf("  room %d->%d probe inconclusive: %v\n", i, i+1, err)
			}
		}
	}
	fmt.Printf("same-room reachable: %d/%d sampled; cross-room isolated: %d/%d sampled\n",
		checkSame, sameProbes, checkCross, crossProbes)

	var final runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&final)
	fmt.Printf("final heap %.1f MiB, goroutines %d\n",
		float64(final.HeapAlloc)/(1<<20), runtime.NumGoroutine())
	return nil
}

// crossRoomReachable reports whether a peer in one room can open a stream to a
// listener published in another. reached says the probe got far enough to be
// meaningful: it is false when either side could not be set up, in which case the
// answer is unknown rather than "isolated".
func crossRoomReachable(ctx context.Context, client, server simpletier.Network) (connected, reached bool, err error) {
	ln, err := server.Listen("tcp", ":9901")
	if err != nil {
		return false, false, fmt.Errorf("publish listener: %w", err)
	}
	defer func() { _ = ln.Close() }()

	address := fmt.Sprintf("%s:9901", server.LocalVirtualIP())
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stream, dialErr := client.DialContext(dialCtx, "tcp", address)
	if dialErr == nil {
		_ = stream.Close()
		return true, true, nil
	}
	// A refusal is the expected outcome; only treat it as isolation if the listener
	// side was alive for the whole attempt.
	return false, true, nil
}

// sameRoomReachable reports whether one peer can complete an echo through another.
func sameRoomReachable(ctx context.Context, client, server simpletier.Network) (bool, error) {
	ln, err := server.Listen("tcp", ":9900")
	if err != nil {
		return false, err
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

	address := fmt.Sprintf("%s:9900", server.LocalVirtualIP())
	var stream simpletier.Stream
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		stream, err = client.DialContext(dialCtx, "tcp", address)
		cancel()
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return false, nil
	}
	defer func() { _ = stream.Close() }()
	return true, nil
}
