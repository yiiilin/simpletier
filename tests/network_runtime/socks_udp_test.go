package network_runtime_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// This file is the real Agent UDP business acceptance: a raw RFC 1928/1929
// SOCKS5 client authenticates, opens a UDP ASSOCIATE, and sends FRAG=0 datagrams
// through a real local UDP socket. The Agent forwards each payload through its
// Flow-backed DatagramBackend; the target is a plain public-SDK
// Network.ListenPacket echo application whose WriteTo answer goes back through
// flow.Manager.Reply. No mock delivery, no OS UDP dial towards the target and no
// capture device are involved.

const (
	socksUDPTargetIP = "10.90.0.2"
	socksUDPSourceIP = "10.90.0.1"
	socksUDPPort     = uint16(42010)
	socksUDPUser     = "proxy-user"
	socksUDPPass     = "proxy-pass"
)

// newSOCKS5UDPAgent starts a public Agent whose only inbound is a SOCKS5 proxy:
// TUN is explicitly off, so no host device is opened, and the Agent reaches the
// target over its real carrier upstream.
func newSOCKS5UDPAgent(t *testing.T, carrierPort int) *simpletier.Agent {
	t.Helper()
	tun := false
	agent, err := simpletier.NewAgent(simpletier.AgentConfig{
		Config: simpletier.Config{
			Listen:    []string{fmt.Sprintf("tcp://127.0.0.1:%d", freePort(t))},
			Upstreams: []string{fmt.Sprintf("tcp://127.0.0.1:%d", carrierPort)},
			Network: simpletier.NetworkConfig{
				Name:  testNetworkName,
				CIDR:  testCIDR,
				Token: testToken,
			},
			Options: simpletier.RuntimeOptions{
				FixedIP: socksUDPSourceIP,
			},
		},
		Inbounds: simpletier.AgentInbounds{
			TUN: &tun,
			SOCKS5: &simpletier.ProxyConfig{
				Listen:   "127.0.0.1:0",
				Username: socksUDPUser,
				Password: socksUDPPass,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	t.Cleanup(func() { _ = agent.Close() })
	if err := agent.Start(context.Background()); err != nil {
		t.Fatalf("Agent.Start: %v", err)
	}
	return agent
}

// socksUDPClient is one raw SOCKS5 control connection plus its local UDP relay
// socket.
type socksUDPClient struct {
	t       *testing.T
	control net.Conn
	relay   *net.UDPConn
	bound   netip.AddrPort
}

func dialSOCKS5UDP(t *testing.T, proxy net.Addr) *socksUDPClient {
	t.Helper()
	control, err := net.DialTimeout("tcp", proxy.String(), 10*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 proxy: %v", err)
	}
	client := &socksUDPClient{t: t, control: control}
	if _, err := control.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write method offer: %v", err)
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(control, head); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if head[0] != 0x05 || head[1] != 0x02 {
		t.Fatalf("method selection = % x; want 05 02 (username/password)", head)
	}
	auth := []byte{0x01, byte(len(socksUDPUser))}
	auth = append(auth, socksUDPUser...)
	auth = append(auth, byte(len(socksUDPPass)))
	auth = append(auth, socksUDPPass...)
	if _, err := control.Write(auth); err != nil {
		t.Fatalf("write RFC1929 auth: %v", err)
	}
	if _, err := io.ReadFull(control, head); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if head[0] != 0x01 || head[1] != 0x00 {
		t.Fatalf("auth reply = % x; want 01 00", head)
	}
	// UDP ASSOCIATE with DST 0.0.0.0:0: the association binds the client's real
	// UDP source port on its first valid datagram.
	if _, err := control.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write UDP ASSOCIATE: %v", err)
	}
	if _, err := io.ReadFull(control, head); err != nil {
		t.Fatalf("read associate reply: %v", err)
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE reply = % x; want success", head)
	}
	// VER REP RSV ATYP ADDR PORT: the two bytes above were VER/REP, so consume
	// the reserved byte before the address type.
	if _, err := io.ReadFull(control, head[:1]); err != nil {
		t.Fatalf("read BND reserved byte: %v", err)
	}
	if head[0] != 0x00 {
		t.Fatalf("BND reserved byte = %#x; want 0", head[0])
	}
	if _, err := io.ReadFull(control, head[:1]); err != nil {
		t.Fatalf("read BND address type: %v", err)
	}
	if head[0] != 0x01 {
		t.Fatalf("BND address type = %#x; want IPv4", head[0])
	}
	raw := make([]byte, 6)
	if _, err := io.ReadFull(control, raw); err != nil {
		t.Fatalf("read BND address: %v", err)
	}
	var ip [4]byte
	copy(ip[:], raw[:4])
	client.bound = netip.AddrPortFrom(netip.AddrFrom4(ip), binary.BigEndian.Uint16(raw[4:]))
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("bind local UDP relay client: %v", err)
	}
	client.relay = relay
	t.Cleanup(func() {
		_ = relay.Close()
		_ = control.Close()
	})
	return client
}

// exchange sends one FRAG=0 SOCKS5 UDP datagram to destination and returns the
// echoed payload with the source header the Agent reported.
func (c *socksUDPClient) exchange(payload []byte, destination netip.AddrPort) ([]byte, netip.AddrPort, error) {
	c.t.Helper()
	header := []byte{0x00, 0x00, 0x00, 0x01}
	raw := destination.Addr().As4()
	header = append(header, raw[:]...)
	header = binary.BigEndian.AppendUint16(header, destination.Port())
	if _, err := c.relay.WriteToUDPAddrPort(append(header, payload...), c.bound); err != nil {
		return nil, netip.AddrPort{}, err
	}
	if err := c.relay.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, netip.AddrPort{}, err
	}
	buffer := make([]byte, 65535)
	n, _, err := c.relay.ReadFromUDPAddrPort(buffer)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	reply := buffer[:n]
	if len(reply) < 10 || reply[0] != 0 || reply[1] != 0 || reply[2] != 0 || reply[3] != 0x01 {
		return nil, netip.AddrPort{}, fmt.Errorf("malformed SOCKS5 UDP reply header % x", reply[:min(10, len(reply))])
	}
	var source [4]byte
	copy(source[:], reply[4:8])
	port := binary.BigEndian.Uint16(reply[8:10])
	return reply[10:], netip.AddrPortFrom(netip.AddrFrom4(source), port), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestAgentSOCKS5UDPAssociateEchoPublicTarget is the full UDP business path: raw
// SOCKS5 auth + UDP ASSOCIATE, a real local UDP client, the Agent's Flow backend,
// the target's public Network.ListenPacket echo (answered with Manager.Reply),
// and the SOCKS5 UDP reply back to the exact client endpoint. Payloads cover the
// exact maximum a SOCKS5 UDP reply can carry (65,497 = 65,507 - 10 header bytes)
// and the empty datagram.
func TestAgentSOCKS5UDPAssociateEchoPublicTarget(t *testing.T) {
	carrierPort := freePort(t)
	target := newTarget(t, carrierPort)
	targetAddr := netip.AddrPortFrom(netip.MustParseAddr(socksUDPTargetIP), socksUDPPort)

	echoReady := make(chan struct{})
	// A reply WriteTo failure is a transient failure of that datagram's return
	// route only: drop the datagram, keep echoing and let the client's own
	// retry cover it. The first error is kept for diagnostics without blocking
	// the echo loop; ListenPacket/ReadFrom failures still end the loop.
	writeErr := make(chan error, 1)
	go func() {
		conn, err := target.ListenPacket("udp", targetAddr.String())
		if err != nil {
			t.Logf("target ListenPacket: %v", err)
			close(echoReady)
			return
		}
		close(echoReady)
		defer conn.Close()
		buffer := make([]byte, 65507)
		for {
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			if _, err := conn.WriteTo(buffer[:n], from); err != nil {
				select {
				case writeErr <- err:
				default:
				}
				continue
			}
		}
	}()
	<-echoReady

	agent := newSOCKS5UDPAgent(t, carrierPort)
	socksAddr, _ := agent.ProxyAddrs()
	if socksAddr == nil {
		t.Fatal("Agent has no bound SOCKS5 listener")
	}
	// The Agent's own carrier/topology must converge before the target accepts
	// its datagrams; the client retries through that window.
	waitStream(t, agent.Network(), carrierPort, targetAddr)

	client := dialSOCKS5UDP(t, socksAddr)

	maxPayload := make([]byte, 65497)
	for i := range maxPayload {
		maxPayload[i] = byte((i*29 + 5) % 251)
	}
	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "small", payload: []byte("socks5-udp-business")},
		{name: "empty", payload: nil},
		{name: "max-65497", payload: maxPayload},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			deadline := time.Now().Add(60 * time.Second)
			var lastErr error
			for time.Now().Before(deadline) {
				payload, source, err := client.exchange(testCase.payload, targetAddr)
				if err != nil {
					lastErr = err
					continue
				}
				if !bytes.Equal(payload, testCase.payload) {
					t.Fatalf("SOCKS5 UDP echo = %d bytes, want %d identical", len(payload), len(testCase.payload))
				}
				if source != targetAddr {
					t.Fatalf("SOCKS5 UDP reply source = %s; want %s", source, targetAddr)
				}
				return
			}
			t.Fatalf("SOCKS5 UDP exchange never completed: %v", lastErr)
		})
	}
	select {
	case err := <-writeErr:
		t.Logf("target echo WriteTo failed at least once; first error: %v", err)
	default:
	}
}

// waitStream retries a real virtual TCP dial through the Agent's Network until
// the STREAM lane and the target route have converged, then closes it.
func waitStream(t *testing.T, n simpletier.Network, _ int, target netip.AddrPort) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		stream, err := n.DialContext(ctx, "tcp", netip.AddrPortFrom(target.Addr(), 1).String())
		cancel()
		if err == nil {
			_ = stream.Close()
			return
		}
		// A refusal proves the target route is live: the exact UDP port listener
		// does not exist on the TCP side.
		if errors.Is(err, simpletier.ErrTargetRefused) {
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("Agent Network never reached the target: %v", lastErr)
}

// dirState returns a fresh private state directory for one Agent. The helper
// lives here so the UDP acceptance does not depend on the stream test helpers.
func dirState(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/state"
}
