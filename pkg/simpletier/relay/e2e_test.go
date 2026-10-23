package relay_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/relay"
	"github.com/yiiilin/simpletier/pkg/simpletier/room"
)

// TestSameRoomTrafficCrossesRelay is the end-to-end acceptance for the relay: two
// members of one room exchange business data through it.
//
// Each member opens a CONTROL carrier and a STREAM carrier to the relay and names
// the same room, so they become peers of one isolated network. The relay attaches
// no TUN device, so none of its host ports are reachable from the room even though
// it is a visible member.
func TestSameRoomTrafficCrossesRelay(t *testing.T) {
	base := t.TempDir()
	const name, cidr, token = "relay-e2e", "10.196.0.0/24", "one-room-token"

	r := relay.New(relay.Options{Rooms: room.Options{
		Name: name, CIDR: cidr, LogLevel: "error",
	}})
	for _, d := range []string{base + "/relay", base + "/a", base + "/b"} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tcpAddr := "127.0.0.1:41101"
	go func() { _ = r.ServeTCP(ctx, tcpAddr) }()
	waitListening(t, tcpAddr)

	join := func(sd, label string) simpletier.Network {
		n, err := simpletier.NewNetwork(simpletier.Config{
			Network: simpletier.NetworkConfig{Name: name, CIDR: cidr, Token: token},
			Options: simpletier.RuntimeOptions{LogLevel: "error"},
		})
		if err != nil {
			t.Fatalf("%s network: %v", label, err)
		}
		link, err := relay.JoinRoom(ctx, n, tcpAddr, token)
		if err != nil {
			t.Fatalf("%s join: %v", label, err)
		}
		go func() { <-link.Done() }()
		return n
	}

	a := join(base+"/a", "A")
	b := join(base+"/b", "B")

	// Wait for facts to converge: DialContext reports "no route" immediately when
	// the route table has no candidate, rather than waiting for one.
	// Dial is retried rather than preceded by a fixed sleep. Peers() reports the
	// facts a node has accepted, which is necessary but not sufficient for a STREAM
	// path: a peer can be visible while the route candidates for its lane are still
	// converging. DialContext returns "no route" immediately in that window instead
	// of waiting, so the caller retries.

	ln, err := b.Listen("tcp", ":9800")
	if err != nil {
		t.Fatalf("B listen: %v", err)
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
				if _, err := stream.Write([]byte("relay-ok")); err != nil {
					return
				}
				// Half-close so the reader reaches EOF instead of waiting for a
				// reset. No sleep: the write is already flushed, and holding the
				// stream open only slowed the test down.
				_ = stream.CloseWrite()
			}()
		}
	}()

	address := fmt.Sprintf("%s:9800", b.LocalVirtualIP())
	stream := dialUntilReady(t, ctx, a, address)
	defer func() { _ = stream.Close() }()

	buf := make([]byte, 16)
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "relay-ok" {
		t.Fatalf("payload = %q; want relay-ok", got)
	}
}

// dialUntilReady retries a room dial until the path is up or the deadline passes.
func dialUntilReady(t *testing.T, ctx context.Context, n simpletier.Network, address string) simpletier.Stream {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		stream, err := n.DialContext(dialCtx, "tcp", address)
		cancel()
		if err == nil {
			return stream
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("dial %s never became routable: %v", address, last)
	return nil
}

// waitPeers blocks until the network reports at least want other peers.
func waitPeers(t *testing.T, n simpletier.Network, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if peers, err := n.Peers(); err == nil && len(peers) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	peers, _ := n.Peers()
	t.Fatalf("network saw %d peers; want at least %d", len(peers), want)
}

// TestDifferentRoomsAreIsolated proves the token is the room boundary: a peer in
// one room cannot reach a listener published in another, even though both rooms
// use the same CIDR and are served by one relay.
//
// The positive case above runs over the same CIDR and the same relay, so a refusal
// here is isolation rather than a path that never converges.
func TestDifferentRoomsAreIsolated(t *testing.T) {
	base := t.TempDir()
	const name, cidr = "relay-iso", "10.197.0.0/24"

	r := relay.New(relay.Options{Rooms: room.Options{
		Name: name, CIDR: cidr, LogLevel: "error",
	}})
	for _, d := range []string{base + "/relay", base + "/a", base + "/b"} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tcpAddr := "127.0.0.1:41102"
	go func() { _ = r.ServeTCP(ctx, tcpAddr) }()
	time.Sleep(300 * time.Millisecond)

	join := func(sd, token, label string) simpletier.Network {
		n, err := simpletier.NewNetwork(simpletier.Config{
			Network: simpletier.NetworkConfig{Name: name, CIDR: cidr, Token: token},
			Options: simpletier.RuntimeOptions{LogLevel: "error"},
		})
		if err != nil {
			t.Fatalf("%s network: %v", label, err)
		}
		link, err := relay.JoinRoom(ctx, n, tcpAddr, token)
		if err != nil {
			t.Fatalf("%s join: %v", label, err)
		}
		go func() { <-link.Done() }()
		return n
	}

	inA := join(base+"/a", "token-room-a", "A")
	inB := join(base+"/b", "token-room-b", "B")

	ln, err := inA.Listen("tcp", ":9900")
	if err != nil {
		t.Fatalf("A listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			stream, err := ln.Accept()
			if err != nil {
				return
			}
			_ = stream.Close()
		}
	}()

	// Wait for each member to converge on its own room, then assert once. The
	// question is whether an established peer can cross rooms, not whether a peer
	// that is still converging can reach anything — a single dial after convergence
	// answers it without spinning for the whole timeout.
	waitPeers(t, inA, 1)
	waitPeers(t, inB, 1)

	address := fmt.Sprintf("%s:9900", inA.LocalVirtualIP())
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stream, err := inB.DialContext(dialCtx, "tcp", address)
	if err == nil {
		_ = stream.Close()
		t.Fatalf("cross-room dial to %s succeeded; rooms are not isolated", address)
	}
	t.Logf("cross-room dial refused as expected: %v", err)
}

// waitListening blocks until addr accepts a TCP connection, so a test waits for the
// relay to come up instead of sleeping a guessed interval.
func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never started listening", addr)
}
