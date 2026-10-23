package agent

// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Requirement: R-MESH-006 (SOCKS5 UDP ASSOCIATE is an association, not a
// reliable byte stream) and R-MESH-010 (the SOCKS5 relay's own single local IPv4
// UDP packet bound is independent of the Flow UDP_DATAGRAM 65,507-byte core,
// which belongs to internal/flow).
//
// # Ownership and transport boundary
//
// A SOCKS5 UDP ASSOCIATE is owned by its TCP control connection: the association
// lives exactly as long as that connection, and closing it releases the local
// relay socket, the datagram channel and every goroutine this file starts. The
// local relay socket is inbound-facing: it is the UDP endpoint reported to the
// client as BND.ADDR/BND.PORT. Outbound target traffic never touches an OS UDP
// socket created here; it goes only through the injected DatagramBackend, whose
// runtime adapter is expected to implement the Flow UDP_DATAGRAM plane
// (Network.Session PacketClass). This package cannot know the virtual CIDR, so
// when no DatagramBackend is wired the command is reported as unsupported
// instead of dialling the OS.
//
// # One datagram, one SOCKS5 message
//
// The relay implements no SOCKS5 fragmentation: FRAG != 0 is dropped and
// counted, never reassembled and never confused with Flow-level datagram
// fragments. Each client datagram is decoded into exactly one destination and
// payload; each backend reply is encoded into exactly one client datagram. The
// local IPv4 UDP wire limit is 65,507 bytes, so an IPv4 SOCKS5 header (10 bytes)
// leaves at most 65,497 payload bytes, and a domain header leaves correspondingly
// less. A reply that cannot fit is dropped and counted rather than truncated.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	// maxSOCKSUDPWirePayload is the largest payload one local IPv4 UDP packet can
	// carry: 65,535 (IPv4 total length) - 20 (IPv4 header) - 8 (UDP header).
	maxSOCKSUDPWirePayload = 65507
	// socksUDPIPv4HeaderLen is RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2).
	socksUDPIPv4HeaderLen = 10
	// maxSOCKSUDPIPv4Payload is the largest backend reply payload that still fits
	// in one SOCKS5 UDP reply with an IPv4 header. A domain header is larger.
	maxSOCKSUDPIPv4Payload = maxSOCKSUDPWirePayload - socksUDPIPv4HeaderLen
	// socksUDPHeaderReserve bounds the address header size used when sizing the
	// reply encoder's scratch space before the real header length is known.
	socksUDPHeaderReserve = socksUDPIPv4HeaderLen
)

var (
	// errSOCKSUDPFragment reports a client datagram with FRAG != 0. It is never
	// exposed to the client (UDP has no error reply); the relay drops and counts.
	errSOCKSUDPFragment = errors.New("agent: SOCKS5 UDP fragmentation is not implemented")
	// errDatagramTooLarge reports a backend reply that cannot fit in one local
	// IPv4 UDP packet once the SOCKS5 address header is added.
	errDatagramTooLarge = errors.New("agent: SOCKS5 UDP reply exceeds one local IPv4 UDP packet")
)

// DatagramBackend opens the UDP association channel for one SOCKS5 UDP
// ASSOCIATE inbound.
//
// It is the only outbound datagram port of this package: the Agent never creates
// an OS UDP socket towards a target and never dials a default of its own, so an
// entry without a DatagramBackend reports UDP ASSOCIATE as unsupported (0x07)
// instead of half working. The runtime adapter implements this on the Flow
// UDP_DATAGRAM plane; see targetResolver in agent.go for the TCP-side analogue.
//
// NewAssociation must observe ctx cancellation and return promptly; the
// association is created only after the RFC 1929 exchange and a parsed
// UDP ASSOCIATE request, and its channel lives until the TCP control connection
// ends, the Agent closes or Close is called.
type DatagramBackend interface {
	NewAssociation(ctx context.Context) (UDPDgramChannel, error)
}

// UDPDgramChannel is one association's datagram egress/ingress port. It is not a
// byte stream and it does not promise reliable, ordered or exactly-once
// delivery.
//
// SendTo sends one datagram towards host:port. Payload aliases caller-owned
// storage that is reused as soon as SendTo returns, so an implementation must
// copy anything it retains. SendTo returning nil only means the local bounded
// queue accepted the datagram, not that the destination received it.
//
// Receive returns one datagram and its real source. The returned payload belongs
// to the caller and must not be reused by the implementation. Receive must
// observe ctx cancellation and return promptly after Close.
//
// Close releases the channel exactly once and must unblock a pending Receive.
type UDPDgramChannel interface {
	SendTo(ctx context.Context, host string, port uint16, payload []byte) error
	Receive(ctx context.Context) (host string, port uint16, payload []byte, err error)
	Close() error
}

// socksUDPRequest is one decoded client datagram.
type socksUDPRequest struct {
	host    string
	port    uint16
	payload []byte
}

// parseSOCKSUDPRequest decodes the fixed SOCKS5 UDP request header defined by RFC
// 1928 section 7. The payload is a subslice of datagram and is reused by the
// caller as soon as the next datagram is read.
//
// Every rejection is a silent drop because a UDP datagram has no error reply.
// errSOCKSUDPFragment distinguishes FRAG != 0 so the caller can count it
// separately from malformed headers; unsupported address types wrap
// ErrUnsupported and malformed framing wraps errMalformedRequest.
func parseSOCKSUDPRequest(datagram []byte) (socksUDPRequest, error) {
	if len(datagram) < 4 {
		return socksUDPRequest{}, fmt.Errorf("%w: UDP header shorter than 4 bytes", errMalformedRequest)
	}
	if datagram[0] != 0x00 || datagram[1] != 0x00 {
		return socksUDPRequest{}, fmt.Errorf("%w: UDP reserved bytes are 0x%02x%02x", errMalformedRequest, datagram[0], datagram[1])
	}
	if datagram[2] != 0x00 {
		return socksUDPRequest{}, fmt.Errorf("%w: FRAG 0x%02x", errSOCKSUDPFragment, datagram[2])
	}
	switch datagram[3] {
	case socksAddressIPv4:
		if len(datagram) < socksUDPIPv4HeaderLen {
			return socksUDPRequest{}, fmt.Errorf("%w: truncated IPv4 UDP header", errMalformedRequest)
		}
		var raw [4]byte
		copy(raw[:], datagram[4:8])
		port := binary.BigEndian.Uint16(datagram[8:10])
		if port == 0 {
			return socksUDPRequest{}, fmt.Errorf("%w: UDP target port 0", errMalformedRequest)
		}
		return socksUDPRequest{host: netip.AddrFrom4(raw).String(), port: port, payload: datagram[10:]}, nil
	case socksAddressDomain:
		if len(datagram) < 5 {
			return socksUDPRequest{}, fmt.Errorf("%w: truncated domain UDP header", errMalformedRequest)
		}
		length := int(datagram[4])
		if length == 0 {
			return socksUDPRequest{}, fmt.Errorf("%w: empty domain name", errMalformedRequest)
		}
		if len(datagram) < 5+length+2 {
			return socksUDPRequest{}, fmt.Errorf("%w: truncated domain UDP header", errMalformedRequest)
		}
		host := string(datagram[5 : 5+length])
		if !printableHost(host) {
			return socksUDPRequest{}, fmt.Errorf("%w: non-printable domain name", errMalformedRequest)
		}
		if ipv6LiteralHost(host) {
			return socksUDPRequest{}, fmt.Errorf("%w: IPv6 UDP target %q", ErrUnsupported, host)
		}
		port := binary.BigEndian.Uint16(datagram[5+length : 7+length])
		if port == 0 {
			return socksUDPRequest{}, fmt.Errorf("%w: UDP target port 0", errMalformedRequest)
		}
		return socksUDPRequest{host: host, port: port, payload: datagram[7+length:]}, nil
	case socksAddressIPv6:
		return socksUDPRequest{}, fmt.Errorf("%w: IPv6 UDP target", ErrUnsupported)
	default:
		return socksUDPRequest{}, fmt.Errorf("%w: UDP address type 0x%02x", ErrUnsupported, datagram[3])
	}
}

// encodeSOCKSUDPReply builds one client-facing SOCKS5 UDP reply. The address
// header uses an IPv4 literal when the source is one and a domain header
// otherwise; an IPv6 source is refused because IPv6 is out of scope. The reply
// must fit in a single local IPv4 UDP packet because SOCKS5 fragmentation is not
// implemented.
func encodeSOCKSUDPReply(host string, port uint16, payload []byte) ([]byte, error) {
	header := make([]byte, 0, socksUDPHeaderReserve+len(host))
	header = append(header, 0x00, 0x00, 0x00)
	if address, err := netip.ParseAddr(host); err == nil && address.Is4() {
		raw := address.As4()
		header = append(header, socksAddressIPv4)
		header = append(header, raw[:]...)
	} else {
		if ipv6LiteralHost(host) {
			return nil, fmt.Errorf("%w: IPv6 UDP source %q", ErrUnsupported, host)
		}
		if host == "" || len(host) > 255 || !printableHost(host) {
			return nil, fmt.Errorf("%w: unusable UDP source %q", errMalformedRequest, host)
		}
		header = append(header, socksAddressDomain, byte(len(host)))
		header = append(header, host...)
	}
	header = binary.BigEndian.AppendUint16(header, port)
	if len(header)+len(payload) > maxSOCKSUDPWirePayload {
		return nil, fmt.Errorf("%w: %d address bytes + %d payload bytes", errDatagramTooLarge, len(header), len(payload))
	}
	return append(header, payload...), nil
}

// ipv4AddrPort parses one net.Addr into a definite IPv4 endpoint. A wildcard,
// IPv6 or unparseable address reports false, which is how the relay refuses to
// report 0.0.0.0 as BND.ADDR or to bind a source to a non-IPv4 TCP peer.
func ipv4AddrPort(addr net.Addr) (netip.AddrPort, bool) {
	if addr == nil {
		return netip.AddrPort{}, false
	}
	parsed, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	parsed = netip.AddrPortFrom(parsed.Addr().Unmap(), parsed.Port())
	if !parsed.Addr().Is4() {
		return netip.AddrPort{}, false
	}
	return parsed, true
}

// udpAssociation is one live SOCKS5 UDP ASSOCIATE. It is created only after the
// authenticated ASSOCIATE request has been accepted and torn down by the control
// connection or the Agent context.
//
// Association binding is deliberately not a membership ACL: it only pins the
// single source endpoint allowed to use this association (the TCP peer's IPv4
// address, plus the port pinned by the request or by the first valid datagram),
// so a second client cannot piggyback on someone else's relay.
type udpAssociation struct {
	server  *proxyServer
	control net.Conn
	relay   *net.UDPConn
	backend UDPDgramChannel

	// clientIP is the TCP control peer's IPv4 address.
	clientIP netip.Addr
	// clientPort is the pinned UDP source port; zero until the first valid
	// datagram binds it when the ASSOCIATE request did not pin a nonzero port.
	clientPort uint16

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.Mutex
	closeOnce sync.Once
}

func newUDPAssociation(server *proxyServer, control net.Conn, relay *net.UDPConn, backend UDPDgramChannel, clientIP netip.Addr, clientPort uint16) *udpAssociation {
	return &udpAssociation{
		server:     server,
		control:    control,
		relay:      relay,
		backend:    backend,
		clientIP:   clientIP,
		clientPort: clientPort,
	}
}

// run drives the association until the control connection ends, the backend is
// lost or ctx is cancelled, then joins every goroutine it started. It never
// returns with a live goroutine or a live socket.
func (a *udpAssociation) run(ctx context.Context) {
	a.ctx, a.cancel = context.WithCancel(ctx)
	a.wg.Add(3)
	go func() {
		defer a.wg.Done()
		a.controlLoop()
	}()
	go func() {
		defer a.wg.Done()
		a.backendLoop()
	}()
	go func() {
		defer a.wg.Done()
		<-a.ctx.Done()
		a.shutdown()
	}()
	a.relayLoop()
	a.shutdown()
	a.wg.Wait()
}

// shutdown releases the association exactly once and unblocks every blocking
// read: the control connection, the local relay socket and the datagram channel.
func (a *udpAssociation) shutdown() {
	a.closeOnce.Do(func() {
		if a.cancel != nil {
			a.cancel()
		}
		_ = a.relay.Close()
		_ = a.backend.Close()
		_ = a.control.Close()
	})
}

// controlLoop holds the association open. The client sends no more TCP data on
// the control connection, so any read error or EOF ends the association. The
// handshake deadline has already been cleared, so the read blocks until the
// client closes or shutdown closes the connection.
func (a *udpAssociation) controlLoop() {
	var discard [64]byte
	for {
		if _, err := a.control.Read(discard[:]); err != nil {
			a.shutdown()
			return
		}
	}
}

// relayLoop reads client datagrams from the local relay socket until the socket
// is closed by shutdown.
func (a *udpAssociation) relayLoop() {
	buffer := make([]byte, maxSOCKSUDPWirePayload)
	for {
		count, from, err := a.relay.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		a.handleClientDatagram(from, buffer[:count])
	}
}

// handleClientDatagram validates the association binding, decodes one SOCKS5 UDP
// request and hands the payload to the datagram backend. Every rejection is a
// counted drop; nothing in this path can panic on hostile input.
func (a *udpAssociation) handleClientDatagram(from netip.AddrPort, datagram []byte) {
	if !from.Addr().Is4() || from.Addr() != a.clientIP {
		a.server.stats.udpDropped.Add(1)
		return
	}
	request, err := parseSOCKSUDPRequest(datagram)
	if err != nil {
		// Malformed framing, FRAG != 0, IPv6 and unknown address types are all
		// silent, counted drops: UDP has no error reply.
		a.server.stats.udpDropped.Add(1)
		return
	}
	if !a.bindClientPort(from.Port()) {
		a.server.stats.udpDropped.Add(1)
		return
	}
	host, port := request.host, request.port
	if a.server.resolver != nil {
		resolved, err := a.server.resolver.ResolveTarget(a.ctx, host, port)
		if err != nil {
			a.server.stats.policyDenied.Add(1)
			return
		}
		if !resolved.IsValid() || !resolved.Addr().Is4() {
			a.server.stats.policyDenied.Add(1)
			return
		}
		host = resolved.Addr().String()
		port = resolved.Port()
	}
	if err := a.backend.SendTo(a.ctx, host, port, request.payload); err != nil {
		if a.ctx.Err() != nil {
			return
		}
		a.server.stats.udpFailures.Add(1)
		return
	}
	a.server.stats.udpRequests.Add(1)
}

// bindClientPort pins the association's UDP source port. A port pinned by the
// ASSOCIATE request is authoritative; otherwise the first valid datagram binds
// it. A datagram from any other port is refused so no second client can inject
// traffic into this association.
func (a *udpAssociation) bindClientPort(port uint16) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.clientPort == 0 {
		a.clientPort = port
		return true
	}
	return a.clientPort == port
}

// backendLoop returns target datagrams to the client until the channel is closed
// or ctx is cancelled.
func (a *udpAssociation) backendLoop() {
	for {
		host, port, payload, err := a.backend.Receive(a.ctx)
		if err != nil {
			if a.ctx.Err() != nil {
				return
			}
			a.server.stats.udpFailures.Add(1)
			a.shutdown()
			return
		}
		a.handleBackendDatagram(host, port, payload)
	}
}

// handleBackendDatagram encodes one reply and writes it to the pinned client
// endpoint. A reply without a pinned client port, an IPv6 source or a reply that
// cannot fit in one local IPv4 UDP packet is dropped and counted.
func (a *udpAssociation) handleBackendDatagram(host string, port uint16, payload []byte) {
	a.mu.Lock()
	clientPort := a.clientPort
	a.mu.Unlock()
	if clientPort == 0 {
		a.server.stats.udpDropped.Add(1)
		return
	}
	reply, err := encodeSOCKSUDPReply(host, port, payload)
	if err != nil {
		a.server.stats.udpDropped.Add(1)
		return
	}
	if _, err := a.relay.WriteToUDPAddrPort(reply, netip.AddrPortFrom(a.clientIP, clientPort)); err != nil {
		if a.ctx.Err() != nil {
			return
		}
		a.server.stats.udpFailures.Add(1)
		return
	}
	a.server.stats.udpReplies.Add(1)
}

// serveSOCKS5UDPAssociate handles the RFC 1928 UDP ASSOCIATE command. The
// success reply is written before the association starts reading, because the
// client waits for BND.ADDR/BND.PORT before sending any datagram.
func serveSOCKS5UDPAssociate(ctx context.Context, server *proxyServer, conn net.Conn, request socksRequest) {
	if server.datagram == nil {
		// An unwired entry reports the command as unsupported instead of half
		// succeeding. The runtime adapter must inject a DatagramBackend.
		server.stats.unsupported.Add(1)
		_ = conn.SetWriteDeadline(time.Now().Add(replyWriteTimeout))
		_ = writeSOCKSReply(conn, socksReplyCommandNotSupported, nil)
		return
	}
	clientAddr, ok := ipv4AddrPort(conn.RemoteAddr())
	if !ok {
		server.stats.udpFailures.Add(1)
		_ = conn.SetWriteDeadline(time.Now().Add(replyWriteTimeout))
		_ = writeSOCKSReply(conn, socksReplyGeneralFailure, nil)
		return
	}
	localAddr, ok := ipv4AddrPort(conn.LocalAddr())
	if !ok || localAddr.Addr().IsUnspecified() {
		// A wildcard listener still reports the concrete local address on the
		// accepted connection; if it does not, the relay cannot report a
		// reachable BND.ADDR and must fail closed instead of returning 0.0.0.0.
		server.stats.udpFailures.Add(1)
		_ = conn.SetWriteDeadline(time.Now().Add(replyWriteTimeout))
		_ = writeSOCKSReply(conn, socksReplyGeneralFailure, nil)
		return
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localAddr.Addr().AsSlice(), Port: 0})
	if err != nil {
		server.stats.udpFailures.Add(1)
		_ = conn.SetWriteDeadline(time.Now().Add(replyWriteTimeout))
		_ = writeSOCKSReply(conn, socksReplyGeneralFailure, nil)
		return
	}
	backend, err := server.datagram.NewAssociation(ctx)
	if err != nil {
		_ = relay.Close()
		server.stats.udpFailures.Add(1)
		_ = conn.SetWriteDeadline(time.Now().Add(replyWriteTimeout))
		_ = writeSOCKSReply(conn, socksReplyGeneralFailure, nil)
		return
	}
	association := newUDPAssociation(server, conn, relay, backend, clientAddr.Addr(), request.port)
	if err := conn.SetWriteDeadline(time.Now().Add(replyWriteTimeout)); err != nil {
		association.shutdown()
		return
	}
	if err := writeSOCKSReply(conn, socksReplySucceeded, relay.LocalAddr()); err != nil {
		association.shutdown()
		return
	}
	// The handshake deadline must not bound the association.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		association.shutdown()
		return
	}
	server.stats.udpAssociations.Add(1)
	association.run(ctx)
}
