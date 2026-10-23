package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/relay"
	"github.com/yiiilin/simpletier/pkg/simpletier/room"
)

// TestRelayAcceptsOnTwoPorts checks that a relay serving two ingress ports accepts a
// carrier on either of them. The benchmark depends on this: one port carries the delayed
// peers and the other carries the rest, so a relay that only serves the first bind would
// silently fail every delayed peer.
func TestRelayAcceptsOnTwoPorts(t *testing.T) {
	ctx := context.Background()
	r := relay.New(relay.Options{Rooms: room.Options{
		Name: "dual", CIDR: "10.240.0.0/24", LogLevel: "error", RateLimit: boolPtr(false),
	}})
	defer func() { _ = r.Close() }()

	plain, err := freeLoopbackAddr()
	if err != nil {
		t.Fatal(err)
	}
	slow, err := freeLoopbackAddr()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = r.ServeTCP(ctx, plain) }()
	go func() { _ = r.ServeTCP(ctx, slow) }()
	if err := waitListening(plain, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := waitListening(slow, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	for _, addr := range []string{plain, slow} {
		n, err := simpletier.NewNetwork(simpletier.Config{
			Network: simpletier.NetworkConfig{Name: "dual", CIDR: "10.240.0.0/24", Token: "dual-token"},
			Options: simpletier.RuntimeOptions{LogLevel: "error", RateLimit: boolPtr(false)},
		})
		if err != nil {
			t.Fatalf("%s: network: %v", addr, err)
		}
		link, err := relay.JoinRoom(ctx, n, addr, "dual-token")
		if err != nil {
			_ = n.Close()
			t.Fatalf("join through %s: %v", addr, err)
		}
		if link == nil {
			t.Fatalf("%s: join returned no link", addr)
		}
		_ = link.Close()
		_ = n.Close()
	}
}

// freeLoopbackAddr returns an unused 127.0.0.1 address.
func freeLoopbackAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		return "", err
	}
	return addr, nil
}
