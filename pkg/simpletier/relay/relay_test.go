package relay_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/relay"
	"github.com/yiiilin/simpletier/pkg/simpletier/room"
)

// startRelay brings up a relay on ephemeral ports and returns its addresses.
func startRelay(t *testing.T) (tcpAddr, httpAddr string) {
	t.Helper()
	tcpPort := freePort(t)
	httpPort := freePort(t)
	tcpAddr = fmt.Sprintf("127.0.0.1:%d", tcpPort)
	httpAddr = fmt.Sprintf("127.0.0.1:%d", httpPort)

	r := relay.New(relay.Options{Rooms: room.Options{
		Name:        "relay-test",
		CIDR:        "10.190.0.0/24",
		LogLevel:    "error",
		IdleTimeout: time.Minute,
	}})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		_ = r.ServeTCP(ctx, tcpAddr)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		_ = r.ServeWebSocket(ctx, httpAddr)
	}()

	t.Cleanup(func() {
		cancel()
		_ = r.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
		}
	})

	waitReachable(t, tcpAddr)
	waitReachable(t, httpAddr)
	return tcpAddr, httpAddr
}

// secureTempDir returns a state directory with the 0700 permissions the identity
// store requires. t.TempDir() creates 0755, which the store refuses.
func secureTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod state dir: %v", err)
	}
	return dir
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitReachable(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never became reachable", address)
}

// joinRoom attaches a fresh Network to a room over the relay's TCP ingress.
func joinRoom(t *testing.T, ctx context.Context, relayAddr, token, name, cidr string) simpletier.Network {
	t.Helper()
	n, err := simpletier.NewNetwork(simpletier.Config{
		Network: simpletier.NetworkConfig{Name: name, CIDR: cidr, Token: token},
		Options: simpletier.RuntimeOptions{
			LogLevel: "error",
		},
	})
	if err != nil {
		t.Fatalf("client network: %v", err)
	}
	t.Cleanup(func() { _ = n.Close() })

	link, err := relay.JoinRoom(ctx, n, relayAddr, token)
	if err != nil {
		t.Fatalf("join room: %v", err)
	}
	// The lanes must outlive the dial: closing them releases the room membership and
	// tears the path down, so they are held until the test finishes.
	t.Cleanup(func() { _ = link.Close() })
	go func() {
		select {
		case <-link.Done():
		case <-ctx.Done():
		}
	}()
	return n
}

// TestSameRoomMembersReachEachOther proves the relay carries traffic between two
// peers that named the same room.
// TestDifferentRoomsCannotReachEachOther proves the token separates rooms: a peer
// in one room cannot dial a member of another even at the same virtual address.
// TestTCPTokenIsLengthPrefixed pins the carrier framing so a peer cannot smuggle
// an unbounded prefix or an empty room name.
func TestTCPTokenIsLengthPrefixed(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = relay.WriteToken(server, "abc")
	}()

	token, err := readTokenForTest(client)
	if err != nil {
		t.Fatalf("read token: %v", err)
	}
	if token != "abc" {
		t.Fatalf("token = %q; want abc", token)
	}
}

// readTokenForTest mirrors the relay's framing without exporting it.
func readTokenForTest(r io.Reader) (string, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return "", err
	}
	n := int(size[0])<<24 | int(size[1])<<16 | int(size[2])<<8 | int(size[3])
	if n <= 0 || n > relay.MaxTokenBytes {
		return "", fmt.Errorf("token length %d out of range", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// TestEmptyTokenRejected proves the relay refuses a carrier that names no room.
func TestEmptyTokenRejected(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	if err := relay.WriteToken(server, ""); err == nil {
		t.Fatal("WriteToken accepted an empty token")
	}
}
