// Command room-relay runs one process that serves many isolated rooms, and can also
// join one as a member.
//
// A room is named by a token. Peers sharing the token reach each other; peers with a
// different token cannot see or reach each other at all, even though every room uses
// the same CIDR. The relay never attaches a TUN device, so its own host ports are not
// reachable from any room.
//
// Relay mode: TCP on 22020 and WebSocket on 22021 by default.
//
//	go run ./examples/room-relay
//
// With token issuance enabled, only tokens this process minted can create a room:
//
//	go run ./examples/room-relay -require-issued -issue demo-token
//
// Member mode, joining a room over the relay:
//
//	go run ./examples/room-relay -join 127.0.0.1:22020 -room demo-token -virtual-listen :9000
//	go run ./examples/room-relay -join 127.0.0.1:22020 -room demo-token -virtual-dial 10.100.0.2:9000
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/relay"
	"github.com/yiiilin/simpletier/pkg/simpletier/room"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	tcpAddr := flag.String("tcp", fmt.Sprintf(":%d", relay.DefaultTCPPort), "TCP ingress address; empty address uses the default port")
	wsAddr := flag.String("ws", fmt.Sprintf(":%d", relay.DefaultWebSocketPort), "WebSocket ingress address; empty address uses the default port")
	stateDir := flag.String("state-dir", "", "base directory for per-room state")
	roomName := flag.String("name", "DefaultRoom", "overlay network name shared by all rooms")
	roomCIDR := flag.String("cidr", "10.100.0.0/24", "virtual CIDR used by every room")
	idle := flag.Duration("idle", time.Minute, "how long an empty room is kept before teardown")
	logLevel := flag.String("log-level", "error", "per-room network log level")
	requireIssued := flag.Bool("require-issued", false, "only accept room tokens this process issued")
	issue := flag.String("issue", "", "issue this room token at startup and keep it valid")

	join := flag.String("join", "", "member mode: relay host:port to join")
	joinRoom := flag.String("room", "", "member mode: room token")
	joinListen := flag.String("virtual-listen", "", "member mode: virtual address to listen on, e.g. :9000")
	joinDial := flag.String("virtual-dial", "", "member mode: virtual address to dial, e.g. 10.100.0.2:9000")
	flag.Parse()

	if *join != "" {
		return runMember(*join, *joinRoom, *joinListen, *joinDial, *stateDir, *roomName, *roomCIDR)
	}
	return runRelay(*tcpAddr, *wsAddr, *stateDir, *roomName, *roomCIDR, *idle, *logLevel, *requireIssued, *issue)
}

// runRelay serves rooms on the configured ingress ports until interrupted.
func runRelay(tcpAddr, wsAddr, stateDir, name, cidr string, idle time.Duration, logLevel string, requireIssued bool, issue string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	r := relay.New(relay.Options{Rooms: room.Options{
		Name:          name,
		CIDR:          cidr,
		IdleTimeout:   idle,
		LogLevel:      logLevel,
		RequireIssued: requireIssued,
	}})
	defer func() { _ = r.Close() }()

	if issue != "" {
		if err := r.Issue(issue); err != nil {
			return fmt.Errorf("issue token: %w", err)
		}
		fmt.Printf("relay: issued room token %q\n", issue)
	}

	// Periodic operator view: which rooms are live and who is in them.
	go reportLoop(ctx, r)

	fmt.Printf("relay: tcp %s  websocket %s  (require-issued=%t)\n", tcpAddr, wsAddr, requireIssued)

	errs := make(chan error, 2)
	go func() { errs <- r.ServeTCP(ctx, tcpAddr) }()
	go func() { errs <- r.ServeWebSocket(ctx, wsAddr) }()
	return <-errs
}

// reportLoop prints the live room list every 15 seconds until ctx is done.
func reportLoop(ctx context.Context, r *relay.Relay) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rooms := r.List()
			if len(rooms) == 0 {
				continue
			}
			fmt.Printf("relay: %d live room(s)\n", len(rooms))
			for _, info := range rooms {
				fmt.Printf("  room=%s carriers=%d vip=%s created=%s\n",
					shortID(info.ID), info.Carriers, info.VirtualIP,
					info.Created.Format(time.RFC3339))
				members, _ := r.Members(info.ID)
				for _, member := range members {
					fmt.Printf("    node=%s vip=%v from=%s\n",
						shortID(member.NodeID), member.VirtualIPs, member.PhysicalAddr)
				}
			}
		}
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// runMember joins one room and exercises the virtual network from the member side.
func runMember(relayAddr, token, listenAddr, dialAddr, stateDir, name, cidr string) error {
	if token == "" {
		return errors.New("-room is required in member mode")
	}
	if listenAddr == "" && dialAddr == "" {
		return errors.New("at least one of -virtual-listen or -virtual-dial is required in member mode")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	network, err := simpletier.NewNetwork(simpletier.Config{
		Network: simpletier.NetworkConfig{Name: name, CIDR: cidr, Token: token},
		Options: simpletier.RuntimeOptions{LogLevel: "error"},
	})
	if err != nil {
		return fmt.Errorf("member network: %w", err)
	}
	defer func() { _ = network.Close() }()

	link, err := relay.JoinRoom(ctx, network, relayAddr, token)
	if err != nil {
		return fmt.Errorf("join room: %w", err)
	}
	defer func() { _ = link.Close() }()
	fmt.Printf("member: joined room, virtual IP %s\n", network.LocalVirtualIP())

	if listenAddr != "" {
		go serveVirtualEcho(network, listenAddr)
	}
	if dialAddr != "" {
		go dialVirtual(ctx, network, dialAddr)
	}

	<-ctx.Done()
	return nil
}

// serveVirtualEcho listens on a virtual port and echoes what it receives.
func serveVirtualEcho(network simpletier.Network, address string) {
	ln, err := network.Listen("tcp", address)
	if err != nil {
		log.Printf("virtual listen %s: %v", address, err)
		return
	}
	fmt.Printf("member: listening on virtual %s\n", ln.Addr())
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
}

// dialVirtual retries a dial to a room peer, then echoes once to prove reachability.
func dialVirtual(ctx context.Context, network simpletier.Network, address string) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		stream, err := network.DialContext(dialCtx, "tcp", address)
		cancel()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		defer func() { _ = stream.Close() }()
		payload := []byte("hello from a room peer\n")
		if _, err := stream.Write(payload); err != nil {
			log.Printf("virtual dial %s: write: %v", address, err)
			return
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(stream, reply); err != nil {
			log.Printf("virtual dial %s: read: %v", address, err)
			return
		}
		fmt.Printf("member: reached %s and echoed %q\n", address, string(reply))
		return
	}
	log.Printf("virtual dial %s: never became routable", address)
}
