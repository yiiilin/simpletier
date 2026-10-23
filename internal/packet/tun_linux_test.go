//go:build linux

package packet

// Real Linux device roundtrip through the production packet service.
//
// This test uses the internal/agent host adapter (a test-only dependency) to
// open a real /dev/net/tun interface, configures the interface through the
// production SystemNetwork transaction, and moves real IPv4/UDP packets through
// the host kernel stack in both directions:
//
//	Service.Receive -> real TUN -> kernel -> UDP socket on the local VirtualIP
//	UDP socket -> kernel -> real TUN -> Service.Send -> captured PACKET egress
//
// It requires CAP_NET_ADMIN (or root) and a present /dev/net/tun. When the
// environment does not provide that, the production open/apply call fails and
// the test skips with the exact external condition instead of pretending to
// pass. It is not a Network E2E test: no Link, Session, Path or overlay peer is
// involved.

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/agent"
	"github.com/yiiilin/simpletier/internal/path"
)

var packetTUNCounter atomic.Uint32

func packetTUNName() string {
	return "k" + itoa(packetTUNCounter.Add(1))
}

// itoa is a tiny decimal helper so the interface name stays short without
// pulling strconv formatting into the name twice.
func itoa(value uint32) string {
	if value == 0 {
		return "0"
	}
	var buffer [10]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

// externalBlocker reports an environment that cannot run a real TUN test.
func externalBlocker(err error) bool {
	return errors.Is(err, agent.ErrPlatformUnavailable) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EACCES) ||
		os.IsPermission(err)
}

type staticResolver struct {
	routes map[netip.Addr]PacketRoute
}

func (r staticResolver) ResolvePacketRoute(_ context.Context, destination netip.Addr) (PacketRoute, error) {
	route, ok := r.routes[destination]
	if !ok {
		return PacketRoute{}, ErrNoRoute
	}
	return route, nil
}

type captureSender struct {
	requests []SendRequest
}

func (s *captureSender) SendPacket(_ context.Context, request SendRequest) error {
	copied := request
	copied.Payload = append([]byte(nil), request.Payload...)
	s.requests = append(s.requests, copied)
	return nil
}

func udpSegment(sourcePort, destinationPort uint16, payload []byte) []byte {
	segment := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], destinationPort)
	binary.BigEndian.PutUint16(segment[4:6], uint16(len(segment)))
	// A zero UDP checksum means "not computed", which is legal for IPv4.
	copy(segment[8:], payload)
	return segment
}

func TestLinuxKernelRoundTripThroughPacketService(t *testing.T) {
	adapter, err := agent.ResolveHostAdapter(agent.PlatformLinux)
	if err != nil {
		t.Skipf("external blocker: %v", err)
	}
	device, err := adapter.Open(context.Background(), agent.DeviceOptions{MTU: agent.DefaultDeviceMTU, Name: packetTUNName()})
	if err != nil {
		if externalBlocker(err) {
			t.Skipf("external blocker: cannot open a real TUN device: %v", err)
		}
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = device.Close() })

	reporter, ok := device.(agent.DeviceReporter)
	if !ok {
		t.Fatalf("the linux adapter returned %T without DeviceReporter", device)
	}
	info := reporter.DeviceInfo()
	if info.Name == "" {
		t.Fatal("the opened device reported an empty interface name")
	}

	vip := netip.MustParseAddr("10.207.11.1")
	cidr := netip.MustParsePrefix("10.207.11.0/24")
	remotePrefix := netip.MustParsePrefix("10.207.12.0/24")
	remote := netip.MustParseAddr("10.207.12.5")

	network, err := agent.NewSystemNetwork(agent.PlatformLinux, info.Name, agent.SystemNetworkOptions{
		MTU:     agent.DefaultDeviceMTU,
		Address: netip.PrefixFrom(vip, 32),
		Routes:  []netip.Prefix{remotePrefix},
	})
	if err != nil {
		if externalBlocker(err) {
			t.Skipf("external blocker: %v", err)
		}
		t.Fatalf("NewSystemNetwork: %v", err)
	}
	t.Cleanup(func() {
		_ = network.Rollback(context.Background())
		_ = network.Close()
	})
	if err := network.Prepare(context.Background()); err != nil {
		if externalBlocker(err) {
			t.Skipf("external blocker: %v", err)
		}
		t.Fatalf("Prepare: %v", err)
	}
	if err := network.Apply(context.Background()); err != nil {
		if externalBlocker(err) {
			t.Skipf("external blocker: cannot configure host networking: %v", err)
		}
		t.Fatalf("Apply: %v", err)
	}

	localNode := testNode(0x11)
	remoteNode := testNode(0x22)
	sender := &captureSender{}
	service, err := New(Config{
		LocalNode: localNode,
		VirtualIP: vip,
		CIDR:      cidr,
		Device:    device,
		Resolver: staticResolver{routes: map[netip.Addr]PacketRoute{
			remote: {DestinationNode: remoteNode, AddressFactVersion: testVersion(1, 1), Lane: path.LanePacket, PathID: 7, PathGeneration: 1},
			vip:    {DestinationNode: localNode, AddressFactVersion: testVersion(1, 1), Lane: path.LanePacket, PathID: 7, PathGeneration: 1},
		}},
		Sender: sender,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if service.MTU() != agent.DefaultDeviceMTU {
		t.Fatalf("service MTU = %d, want %d", service.MTU(), agent.DefaultDeviceMTU)
	}

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(vip.AsSlice()), Port: 0})
	if err != nil {
		t.Fatalf("bind a UDP socket on %s: %v", vip, err)
	}
	defer listener.Close()
	localPort := listener.LocalAddr().(*net.UDPAddr).Port

	// Ingress half: Service.Receive writes a real IPv4/UDP packet into the TUN;
	// the kernel must deliver it to the socket bound to the local VirtualIP.
	ingress := testIPv4(remote, vip, 17, 64, 0, 0, nil, udpSegment(40000, uint16(localPort), []byte("kernel-in")))
	if err := service.Receive(context.Background(), remoteNode, localNode, ingress); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	payload := make([]byte, 2048)
	read, from, err := listener.ReadFromUDP(payload)
	if err != nil {
		t.Fatalf("the kernel stack did not deliver the received packet: %v", err)
	}
	if string(payload[:read]) != "kernel-in" || !from.IP.Equal(net.IP(remote.AsSlice())) {
		t.Fatalf("delivered %q from %v, want kernel-in from %s", payload[:read], from, remote)
	}

	// Egress half: the kernel routes the reply to the remote prefix out the TUN;
	// the service must validate and forward it byte-for-byte.
	if _, err := listener.WriteToUDP([]byte("kernel-out"), &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: 40000}); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	readContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buffer := make([]byte, agent.DefaultDeviceMTU)
	var egress []byte
	for {
		count, err := device.ReadPacket(readContext, buffer)
		if err != nil {
			t.Fatalf("ReadPacket after reading no IPv4 packet: %v", err)
		}
		candidate := buffer[:count]
		if len(candidate) == 0 || candidate[0]>>4 != 4 {
			continue // a fresh interface also emits IPv6 link-local traffic
		}
		egress = append([]byte(nil), candidate...)
		break
	}
	before := append([]byte(nil), egress...)
	if err := service.Send(context.Background(), egress); err != nil {
		t.Fatalf("Send(real kernel packet): %v", err)
	}
	if len(sender.requests) != 1 {
		t.Fatalf("sender calls = %d, want 1", len(sender.requests))
	}
	forwarded := sender.requests[0]
	if string(forwarded.Payload) != string(before) {
		t.Fatalf("the forwarded packet differs from the kernel egress packet")
	}
	parsed, err := ParseIPv4(forwarded.Payload)
	if err != nil {
		t.Fatalf("the forwarded packet no longer parses: %v", err)
	}
	if parsed.Source != vip || parsed.Destination != remote {
		t.Fatalf("forwarded %s -> %s, want %s -> %s", parsed.Source, parsed.Destination, vip, remote)
	}
	if parsed.TTL != before[8] {
		t.Fatalf("forwarded TTL = %d, want the original %d", parsed.TTL, before[8])
	}
	if forwarded.DestinationNode != remoteNode || forwarded.Lane != path.LanePacket {
		t.Fatalf("forwarded route = %+v", forwarded)
	}
	stats := service.Stats()
	if stats.Received != 1 || stats.Sent != 1 || stats.Dropped != 0 {
		t.Fatalf("stats = %+v, want received=1 sent=1 dropped=0", stats)
	}
}
