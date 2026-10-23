package main

import (
	"context"
	"fmt"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// Verifies that the two-node code in docs/sdk-guide.md actually works.
//
// The guide is executable documentation: if this stops printing GUIDE-OK, the
// guide has drifted from the API and one of them is wrong.
//
// Run with: go run ./examples/sdk-guide-check
func main() {
	cfg := func(name, cidr, token string) simpletier.NetworkConfig {
		return simpletier.NetworkConfig{Name: name, CIDR: cidr, Token: token}
	}
	const name, cidr = "guide-demo", "10.177.0.0/24"
	const token = "shared-secret-at-least-16-bytes"

	a, err := simpletier.NewNetwork(simpletier.Config{
		Listen:  []string{"tcp://127.0.0.1:39901"},
		Network: cfg(name, cidr, token),
		Options: simpletier.RuntimeOptions{FixedIP: "10.177.0.2", LogLevel: "error"},
	})
	if err != nil {
		panic(err)
	}
	defer a.Close()

	ln, err := a.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			s, err := ln.Accept()
			if err != nil {
				return
			}
			go func(s simpletier.Stream) {
				defer s.Close()
				s.Write([]byte("hello from A\n"))
			}(s)
		}
	}()

	b, err := simpletier.NewNetwork(simpletier.Config{
		Upstreams: []string{"tcp://127.0.0.1:39901"},
		Network:   cfg(name, cidr, token),
		Options:   simpletier.RuntimeOptions{FixedIP: "10.177.0.3", LogLevel: "error"},
	})
	if err != nil {
		panic(err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		s, err := b.DialContext(ctx, "tcp", "10.177.0.2:8080")
		if err == nil {
			buf := make([]byte, 64)
			n, _ := s.Read(buf)
			fmt.Printf("GUIDE-OK got %q\n", string(buf[:n]))
			s.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
		if ctx.Err() != nil {
			peers, _ := b.Peers()
			fmt.Printf("GUIDE-FAIL dial=%v peers=%d\n", err, len(peers))
			return
		}
	}
}
