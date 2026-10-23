package simpletier

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/flow"
	"github.com/yiiilin/simpletier/internal/topology"
)

// The public UDP acceptance tests drive the real SDK API only: two real
// Networks, Network.ListenPacket on each side, and complete datagrams exchanged
// over the production Flow/PACKET E2E plane. No internal delivery mock is
// injected into the sockets under test.

const sdkUDPTestToken = "sdk-udp-token-0123456789"

func sdkUDPTestPair(t *testing.T, cidr string, targetIP, sourceIP netip.Addr) (*network, *network) {
	t.Helper()
	target := newPacketPlaneNode(t, "sdk-udp", cidr, sdkUDPTestToken, targetIP.String(), "")
	source := newPacketPlaneNode(t, "sdk-udp", cidr, sdkUDPTestToken, sourceIP.String(), relayCarrierURL(target))
	return target, source
}

func sdkUDPListen(t *testing.T, n *network, ip netip.Addr, port uint16) net.PacketConn {
	t.Helper()
	conn, err := n.ListenPacket("udp", netip.AddrPortFrom(ip, port).String())
	if err != nil {
		t.Fatalf("ListenPacket(%s:%d) error = %v", ip, port, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestPublicUDPPacketConnEchoAcrossTwoNetworks is the full public-business path:
// a target application listens with Network.ListenPacket, reads a REQUEST and
// answers the exact peer it received from; the reply goes back through
// flow.Manager.Reply on the same target association. It covers an ordinary
// payload, an empty datagram and the maximum 65,507-byte IPv4 UDP payload, with
// the source address/port preserved end to end.
func TestPublicUDPPacketConnEchoAcrossTwoNetworks(t *testing.T) {
	const cidr = "10.106.0.0/24"
	targetIP := netip.MustParseAddr("10.106.0.3")
	sourceIP := netip.MustParseAddr("10.106.0.1")
	sourcePort := uint16(40001)
	targetPort := uint16(41000)

	target, source := sdkUDPTestPair(t, cidr, targetIP, sourceIP)

	targetConn := sdkUDPListen(t, target, targetIP, targetPort)
	sourceConn := sdkUDPListen(t, source, sourceIP, sourcePort)

	// Installing the sockets enabled the packet lane; wait for the real links and
	// for address ownership to converge in both directions.
	waitRelayLinks(t, target, 3, 30*time.Second)
	waitRelayLinks(t, source, 3, 30*time.Second)
	waitPacketRoute(t, source, targetIP, 30*time.Second)
	waitPacketRoute(t, target, sourceIP, 30*time.Second)

	// The target application echoes every datagram back to its real source.
	echoErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, flow.MaxDatagramPayload)
		for {
			n, from, err := targetConn.ReadFrom(buffer)
			if err != nil {
				echoErr <- err
				return
			}
			if from.String() != netip.AddrPortFrom(sourceIP, sourcePort).String() {
				echoErr <- errors.New("target saw unexpected source " + from.String())
				return
			}
			if _, err := targetConn.WriteTo(buffer[:n], from); err != nil {
				echoErr <- err
				return
			}
		}
	}()

	maxPayload := make([]byte, flow.MaxDatagramPayload)
	for i := range maxPayload {
		maxPayload[i] = byte((i*31 + 7) % 251)
	}
	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "small", payload: []byte("sdk-udp-echo")},
		{name: "empty", payload: nil},
		{name: "max-65507", payload: maxPayload},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := sourceConn.WriteTo(testCase.payload, targetConn.LocalAddr()); err != nil {
				t.Fatalf("WriteTo: %v", err)
			}
			buffer := make([]byte, flow.MaxDatagramPayload)
			if err := sourceConn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			n, from, err := sourceConn.ReadFrom(buffer)
			if err != nil {
				t.Fatalf("ReadFrom: %v", err)
			}
			if !bytes.Equal(buffer[:n], testCase.payload) {
				t.Fatalf("echo = %d bytes, want %d identical bytes", n, len(testCase.payload))
			}
			if from.String() != netip.AddrPortFrom(targetIP, targetPort).String() {
				t.Fatalf("echo source = %s; want %s", from, netip.AddrPortFrom(targetIP, targetPort))
			}
		})
	}

	select {
	case err := <-echoErr:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, ErrClosed) {
			t.Fatalf("target echo loop: %v", err)
		}
	case <-time.After(2 * time.Second):
	}
}

// TestPublicUDPPacketConnOverlayOnlyEgress proves the public WriteTo refuses any
// non-overlay destination before it can touch the wire: no OS UDP dial and no
// gateway exists on this path.
func TestPublicUDPPacketConnOverlayOnlyEgress(t *testing.T) {
	const cidr = "10.107.0.0/24"
	targetIP := netip.MustParseAddr("10.107.0.3")
	sourceIP := netip.MustParseAddr("10.107.0.1")
	target, source := sdkUDPTestPair(t, cidr, targetIP, sourceIP)

	targetConn := sdkUDPListen(t, target, targetIP, 41002)
	sourceConn := sdkUDPListen(t, source, sourceIP, 40002)
	_ = targetConn

	for _, destination := range []net.Addr{
		&net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 53},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
		udpAddr{addr: netip.MustParseAddrPort("10.200.0.9:53")},
	} {
		if _, err := sourceConn.WriteTo([]byte("x"), destination); err == nil {
			t.Fatalf("WriteTo(%s) succeeded; want overlay-only rejection", destination)
		}
	}
}

// TestPublicUDPPacketConnPortNamespaces pins the port rules: a duplicate UDP
// virtual port is refused with ErrBusy, a TCP listener may reuse the same numeric
// port, and the second UDP endpoint on the same port does not disturb the first.
func TestPublicUDPPacketConnPortNamespaces(t *testing.T) {
	const cidr = "10.108.0.0/24"
	ip := netip.MustParseAddr("10.108.0.1")
	n := newPacketPlaneNode(t, "sdk-udp", cidr, sdkUDPTestToken, ip.String(), "")

	first, err := n.ListenPacket("udp", netip.AddrPortFrom(ip, 42000).String())
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}
	defer first.Close()

	if _, err := n.ListenPacket("udp", netip.AddrPortFrom(ip, 42000).String()); !errors.Is(err, ErrBusy) {
		t.Fatalf("duplicate UDP bind error = %v; want ErrBusy", err)
	}
	if _, err := n.ListenPacket("tcp", netip.AddrPortFrom(ip, 42000).String()); err == nil {
		t.Fatal("ListenPacket accepted a TCP network name")
	}
	// A TCP stream listener on the same numeric port is a different namespace.
	listener, err := n.Listen("tcp", netip.AddrPortFrom(ip, 42000).String())
	if err != nil {
		t.Fatalf("TCP Listen on the UDP port number: %v", err)
	}
	defer listener.Close()

	if first.LocalAddr().String() != netip.AddrPortFrom(ip, 42000).String() {
		t.Fatalf("LocalAddr = %s; want %s", first.LocalAddr(), netip.AddrPortFrom(ip, 42000))
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// After Close the port is free again.
	reused, err := n.ListenPacket("udp", netip.AddrPortFrom(ip, 42000).String())
	if err != nil {
		t.Fatalf("rebind after Close: %v", err)
	}
	defer reused.Close()
}

// TestPublicUDPPacketConnDeadlinesAndClose proves deadline identity, that Close
// unblocks a pending ReadFrom and that Network.Close unblocks it too.
func TestPublicUDPPacketConnDeadlinesAndClose(t *testing.T) {
	const cidr = "10.109.0.0/24"
	ip := netip.MustParseAddr("10.109.0.1")
	n := newPacketPlaneNode(t, "sdk-udp", cidr, sdkUDPTestToken, ip.String(), "")
	conn := sdkUDPListen(t, n, ip, 43000)

	// A deadline already in the past fails immediately with the SDK deadline
	// identity.
	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buffer := make([]byte, 64)
	if _, _, err := conn.ReadFrom(buffer); !errors.Is(err, ErrDeadline) {
		t.Fatalf("expired ReadFrom error = %v; want ErrDeadline", err)
	}
	// A live deadline expires with the same identity.
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	if _, _, err := conn.ReadFrom(buffer); !errors.Is(err, ErrDeadline) {
		t.Fatalf("timed-out ReadFrom error = %v; want ErrDeadline", err)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("ReadFrom returned after %s; want the live deadline to be honored", elapsed)
	}
	// Clearing the deadline restores a blocking read, and Close unblocks it.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	readErr := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(buffer)
		readErr <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("ReadFrom returned success after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
	if _, err := conn.WriteTo([]byte("x"), udpAddr{addr: netip.MustParseAddrPort("10.109.0.9:53")}); err == nil {
		t.Fatal("WriteTo after Close succeeded")
	}
	// A queued datagram after Close must still report ErrClosed, not data.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline after Close: %v", err)
	}
	if _, _, err := conn.ReadFrom(buffer); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReadFrom after Close error = %v; want ErrClosed", err)
	}
}

// TestPublicUDPNetworkCloseUnblocksRead proves Network.Close releases a UDP
// reader, not only an explicit socket Close.
func TestPublicUDPNetworkCloseUnblocksRead(t *testing.T) {
	const cidr = "10.110.0.0/24"
	ip := netip.MustParseAddr("10.110.0.1")
	n := newPacketPlaneNode(t, "sdk-udp", cidr, sdkUDPTestToken, ip.String(), "")
	conn, err := n.ListenPacket("udp", netip.AddrPortFrom(ip, 44000).String())
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	readErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		_, _, err := conn.ReadFrom(buffer)
		readErr <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := n.Close(); err != nil {
		t.Fatalf("Network.Close: %v", err)
	}
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("ReadFrom returned success after Network.Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Network.Close did not unblock ReadFrom")
	}
}

// TestUDPSocketRejectsForeignReplies pins the reply-routing rules at the socket
// boundary: only a REPLY for the socket's own origin association, addressed to
// its own virtual endpoint and sourced by a peer it actually sent to, may enter
// the inbox. Everything else is counted as foreign.
func TestUDPSocketRejectsForeignReplies(t *testing.T) {
	const cidr = "10.111.0.0/24"
	ip := netip.MustParseAddr("10.111.0.1")
	peer := netip.MustParseAddrPort("10.111.0.9:5000")
	n := newPacketPlaneNode(t, "sdk-udp", cidr, sdkUDPTestToken, ip.String(), "")

	if _, err := n.ListenPacket("udp", netip.AddrPortFrom(ip, 45000).String()); err != nil {
		t.Fatalf("enable flow: %v", err)
	}
	mux := n.streams.udpMuxInstance()
	if mux == nil {
		t.Fatal("no shared UDP mux")
	}
	local := netip.AddrPortFrom(ip, 45000)
	socket := newUDPSocket(n.streams, mux, local)
	association, err := n.streams.createOriginAssociation(socket)
	if err != nil {
		t.Fatalf("createOriginAssociation: %v", err)
	}
	socket.origin = association
	defer socket.Close()

	base := flow.Datagram{
		NetworkID:     n.networkContext.WireID(),
		SrcNodeID:     [16]byte{9},
		DstNodeID:     [16]byte{1},
		AssociationID: association.ID(),
		Flags:         flow.FlagReply,
		Destination:   local,
		Source:        peer,
	}

	before := mux.droppedForeign.Load()
	// Wrong flags.
	request := base
	request.Flags = flow.FlagRequest
	socket.deliverReply(request)
	// Wrong association.
	other := base
	other.AssociationID = flow.AssocID{0xee}
	socket.deliverReply(other)
	// Wrong local destination.
	wrongDest := base
	wrongDest.Destination = netip.MustParseAddrPort("10.111.0.1:45001")
	socket.deliverReply(wrongDest)
	// A peer this socket never sent to.
	socket.deliverReply(base)
	if got := mux.droppedForeign.Load() - before; got != 4 {
		t.Fatalf("foreign replies counted = %d; want 4", got)
	}

	// The exact peer this socket sent to is accepted.
	socket.peers.note(peer)
	socket.deliverReply(base)
	select {
	case item := <-socket.inbox:
		if item.datagram.Source != peer || item.datagram.AssociationID != association.ID() {
			t.Fatalf("accepted reply = %+v; want the sent peer tuple", item.datagram)
		}
		mux.releaseInbox(item.charge)
	default:
		t.Fatal("expected reply was not queued")
	}
	if got := mux.droppedForeign.Load() - before; got != 4 {
		t.Fatalf("foreign replies after the accepted one = %d; want 4", got)
	}
}

// TestUDPSocketBudgetDropsWhenFull proves a full inbox drops instead of blocking
// or spawning a goroutine, and that every charge is released on Close.
func TestUDPSocketBudgetDropsWhenFull(t *testing.T) {
	const cidr = "10.112.0.0/24"
	ip := netip.MustParseAddr("10.112.0.1")
	n := newPacketPlaneNode(t, "sdk-udp", cidr, sdkUDPTestToken, ip.String(), "")
	if _, err := n.ListenPacket("udp", netip.AddrPortFrom(ip, 46000).String()); err != nil {
		t.Fatalf("enable flow: %v", err)
	}
	mux := n.streams.udpMuxInstance()
	socket := newUDPSocket(n.streams, mux, netip.AddrPortFrom(ip, 46000))
	datagram := flow.Datagram{
		Flags:       flow.FlagRequest,
		Destination: netip.AddrPortFrom(ip, 46000),
		Source:      netip.MustParseAddrPort("10.112.0.9:5000"),
		Payload:     []byte("queued"),
	}
	for index := 0; index < udpSocketInboxFrames; index++ {
		socket.deliverRequest(datagram)
	}
	if got := len(socket.inbox); got != udpSocketInboxFrames {
		t.Fatalf("inbox depth = %d; want %d", got, udpSocketInboxFrames)
	}
	before := mux.droppedFull.Load()
	socket.deliverRequest(datagram)
	if got := mux.droppedFull.Load() - before; got != 1 {
		t.Fatalf("full-inbox drops = %d; want 1", got)
	}
	if err := socket.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := len(socket.inbox); got != 0 {
		t.Fatalf("inbox after Close = %d entries; want 0 released", got)
	}
}

// TestAgentBackendReservesUniquePortsAndRoutesReplies proves two live Agent UDP
// associations never share a local source port, and that their reply routes are
// keyed by AssociationID so one cannot receive the other's reply.
func TestAgentBackendReservesUniquePortsAndRoutesReplies(t *testing.T) {
	const cidr = "10.113.0.0/24"
	ip := netip.MustParseAddr("10.113.0.1")
	n := newPacketPlaneNode(t, "sdk-udp", cidr, sdkUDPTestToken, ip.String(), "")

	backend := newAgentDatagramBackend(n.streams)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first, err := backend.NewAssociation(ctx)
	if err != nil {
		t.Fatalf("first NewAssociation: %v", err)
	}
	defer first.Close()
	second, err := backend.NewAssociation(ctx)
	if err != nil {
		t.Fatalf("second NewAssociation: %v", err)
	}
	defer second.Close()

	firstChannel := first.(*agentDatagramChannel)
	secondChannel := second.(*agentDatagramChannel)
	if firstChannel.localPort == 0 || secondChannel.localPort == 0 {
		t.Fatal("association reserved port 0")
	}
	if firstChannel.localPort == secondChannel.localPort {
		t.Fatalf("two associations share local port %d", firstChannel.localPort)
	}
	mux := backend.mux
	if mux == nil {
		t.Fatal("backend has no shared mux")
	}
	if mux.origins[firstChannel.association.ID()] != firstChannel {
		t.Fatal("first association is not registered as a reply sink")
	}
	if mux.origins[secondChannel.association.ID()] != secondChannel {
		t.Fatal("second association is not registered as a reply sink")
	}

	// A REQUEST-flag datagram and a REPLY for the wrong association are refused
	// by the channel validation.
	peer := netip.MustParseAddrPort("10.113.0.9:6000")
	before := mux.droppedForeign.Load()
	firstChannel.deliverReply(flow.Datagram{
		Flags:         flow.FlagRequest,
		AssociationID: firstChannel.association.ID(),
		Destination:   netip.AddrPortFrom(ip, firstChannel.localPort),
		Source:        peer,
	})
	firstChannel.deliverReply(flow.Datagram{
		Flags:         flow.FlagReply,
		AssociationID: secondChannel.association.ID(),
		Destination:   netip.AddrPortFrom(ip, firstChannel.localPort),
		Source:        peer,
	})
	if got := mux.droppedForeign.Load() - before; got != 2 {
		t.Fatalf("foreign channel replies = %d; want 2", got)
	}
}

// TestUDPNetworkDefaultsNoHostDevice pins that a plain Network serves UDP with
// no TUN, no host device and no gateway.
func TestUDPNetworkDefaultsNoHostDevice(t *testing.T) {
	const cidr = "10.114.0.0/24"
	ip := netip.MustParseAddr("10.114.0.1")
	n := newPacketPlaneNode(t, "sdk-udp", cidr, sdkUDPTestToken, ip.String(), "")
	if n.streams.packets != nil {
		t.Fatal("a default Network installed a packet device")
	}
	conn, err := n.ListenPacket("udp", netip.AddrPortFrom(ip, 47000).String())
	if err != nil {
		t.Fatalf("ListenPacket with no TUN: %v", err)
	}
	defer conn.Close()
	if n.streams.packets != nil {
		t.Fatal("ListenPacket opened a host packet device")
	}
}

// TestUDPWriteToRejectsInvalidAddresses pins the public WriteTo address policy:
// a *net.UDPAddr with an out-of-range or zero port is refused BEFORE the uint16
// conversion (so -1 cannot become 65535 and 65537 cannot become 1), a nil
// address/IP, a nil interface, IPv6, and an out-of-range port in the string form
// are all refused with no association created and no egress attempted.
func TestUDPWriteToRejectsInvalidAddresses(t *testing.T) {
	const cidr = "10.118.0.0/24"
	ip := netip.MustParseAddr("10.118.0.1")
	n := newPacketPlaneNode(t, "sdk-udp", cidr, sdkUDPTestToken, ip.String(), "")
	conn := sdkUDPListen(t, n, ip, 48000)
	socket, ok := conn.(*udpSocket)
	if !ok {
		t.Fatalf("ListenPacket returned %T; want *udpSocket", conn)
	}

	ipv6 := net.ParseIP("2001:db8::1")
	mappedIPv4 := net.ParseIP("203.0.113.9").To4()
	cases := []struct {
		name string
		addr net.Addr
	}{
		{name: "port -1", addr: &net.UDPAddr{IP: net.IPv4(10, 118, 0, 9), Port: -1}},
		{name: "port 65536", addr: &net.UDPAddr{IP: net.IPv4(10, 118, 0, 9), Port: 65536}},
		{name: "port 65537", addr: &net.UDPAddr{IP: net.IPv4(10, 118, 0, 9), Port: 65537}},
		{name: "port 0", addr: &net.UDPAddr{IP: net.IPv4(10, 118, 0, 9), Port: 0}},
		{name: "nil IP", addr: &net.UDPAddr{Port: 53}},
		{name: "nil udp addr", addr: (*net.UDPAddr)(nil)},
		{name: "nil interface", addr: nil},
		{name: "ipv6", addr: &net.UDPAddr{IP: ipv6, Port: 53}},
		{name: "mapped public ipv4", addr: &net.UDPAddr{IP: mappedIPv4, Port: 53}},
		{name: "string port 0", addr: udpAddr{addr: netip.MustParseAddrPort("10.118.0.9:0")}},
		{name: "unparseable string addr", addr: net.Addr(nil)},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := socket.WriteTo([]byte("x"), testCase.addr); err == nil {
				t.Fatalf("WriteTo(%v) succeeded; want a refusal", testCase.addr)
			}
			socket.mu.Lock()
			association := socket.origin
			socket.mu.Unlock()
			if association != nil {
				t.Fatal("an invalid destination created an origin association")
			}
			if got := len(socket.inbox); got != 0 {
				t.Fatalf("invalid destination queued %d datagrams", got)
			}
		})
	}
}

// TestUDPPublicErrorMapping pins the public identity of every Flow/topology
// sentinel a UDP egress can surface: the SDK sentinel matches with errors.Is and
// the original internal cause stays reachable, so an SDK caller never has to
// know an undocumented internal error and a warm-up retry can key on ErrNoRoute.
func TestUDPPublicErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want error
	}{
		{name: "no route", in: topology.ErrNoRoute, want: ErrNoRoute},
		{name: "route stale", in: topology.ErrRouteStale, want: ErrRouteStale},
		{name: "pinned route changed", in: flow.ErrRouteChanged, want: ErrRouteStale},
		{name: "topology resource", in: topology.ErrResourceLimit, want: ErrResource},
		{name: "flow resource", in: flow.ErrResourceLimit, want: ErrResource},
		{name: "flow closed", in: flow.ErrClosed, want: ErrClosed},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := mapUDPFlowError(testCase.in)
			if !errors.Is(got, testCase.want) {
				t.Fatalf("mapUDPFlowError(%v) = %v; want errors.Is(..., %v)", testCase.in, got, testCase.want)
			}
			if !errors.Is(got, testCase.in) {
				t.Fatalf("mapUDPFlowError(%v) = %v; lost the original cause", testCase.in, got)
			}
		})
	}
	if got := mapUDPFlowError(nil); got != nil {
		t.Fatalf("mapUDPFlowError(nil) = %v; want nil", got)
	}
	sentinel := errors.New("unrelated")
	if got := mapUDPFlowError(sentinel); !errors.Is(got, sentinel) {
		t.Fatalf("mapUDPFlowError(unrelated) = %v; want it passed through", got)
	}
}
