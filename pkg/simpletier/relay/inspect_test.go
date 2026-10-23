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

// TestListAndMembersReportLiveRoom proves the operator view: rooms can be enumerated
// without knowing their tokens, and each room's attached peers can be inspected by
// overlay identity, virtual address and the physical address the carrier came from.
func TestListAndMembersReportLiveRoom(t *testing.T) {
	base := t.TempDir()
	const name, cidr, token = "inspect", "10.203.0.0/24", "inspect-room-token"

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
	tcpAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	go func() { _ = r.ServeTCP(ctx, tcpAddr) }()
	waitListening(t, tcpAddr)

	join := func(label string) simpletier.Network {
		n, err := simpletier.NewNetwork(simpletier.Config{
			Network: simpletier.NetworkConfig{Name: name, CIDR: cidr, Token: token},
			Options: simpletier.RuntimeOptions{LogLevel: "error"},
		})
		if err != nil {
			t.Fatalf("%s network: %v", label, err)
		}
		t.Cleanup(func() { _ = n.Close() })
		link, err := relay.JoinRoom(ctx, n, tcpAddr, token)
		if err != nil {
			t.Fatalf("%s join: %v", label, err)
		}
		t.Cleanup(func() { _ = link.Close() })
		return n
	}

	join("a")
	join("b")

	// One room, holding both members.
	if got := r.Count(); got != 1 {
		t.Fatalf("Count() = %d; want 1", got)
	}
	rooms := r.List()
	if len(rooms) != 1 {
		t.Fatalf("List() returned %d rooms; want 1", len(rooms))
	}
	info := rooms[0]
	if info.ID == "" {
		t.Fatal("RoomInfo.ID is empty")
	}
	if info.VirtualIP == "" {
		t.Fatal("RoomInfo.VirtualIP is empty")
	}
	// Two peers, each with a CONTROL and a STREAM carrier.
	if info.Carriers < 4 {
		t.Fatalf("RoomInfo.Carriers = %d; want at least 4", info.Carriers)
	}
	if info.ID == token {
		t.Fatal("RoomInfo.ID exposes the token; it must be the hash")
	}

	// Both carriers are visible with an overlay identity and a physical address.
	var members []room.Member
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		got, ok := r.Members(info.ID)
		if ok && len(got) >= 2 {
			members = got
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(members) < 2 {
		t.Fatalf("Members() reported %d carriers; want at least 2", len(members))
	}
	for _, m := range members {
		if m.NodeID == "" {
			t.Fatal("Member.NodeID is empty")
		}
		if len(m.VirtualIPs) == 0 {
			t.Fatalf("Member %s has no VirtualIPs", m.NodeID)
		}
		if m.PhysicalAddr == "" {
			t.Fatalf("Member %s has no PhysicalAddr", m.NodeID)
		}
		host, _, err := net.SplitHostPort(m.PhysicalAddr)
		if err != nil {
			t.Fatalf("Member %s physical addr %q is not host:port: %v", m.NodeID, m.PhysicalAddr, err)
		}
		if host != "127.0.0.1" {
			t.Fatalf("Member %s physical host = %q; want 127.0.0.1", m.NodeID, host)
		}
	}

	// An unknown room id is reported as absent rather than an empty success.
	if _, ok := r.Members("no-such-room"); ok {
		t.Fatal("Members(unknown) returned ok=true")
	}
}

// TestDefaultPorts pins the documented defaults.
func TestDefaultPorts(t *testing.T) {
	if relay.DefaultTCPPort != 22020 {
		t.Fatalf("DefaultTCPPort = %d; want 22020", relay.DefaultTCPPort)
	}
	if relay.DefaultWebSocketPort != 22021 {
		t.Fatalf("DefaultWebSocketPort = %d; want 22021", relay.DefaultWebSocketPort)
	}
}
