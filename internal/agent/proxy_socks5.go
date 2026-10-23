package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Requirement: R-MESH-006 (SOCKS5 proxy ingress: CONNECT, UDP ASSOCIATE,
// mandatory RFC 1929 authentication, BIND unsupported, IPv6 out of scope).
//
// RFC 1928 constants. CONNECT and UDP ASSOCIATE are implemented; BIND is
// answered with the standard "command not supported" reply instead of being half
// implemented. UDP ASSOCIATE additionally requires an injected DatagramBackend
// and is reported as unsupported without one (see proxy_udp.go).
const (
	socksVersion     = 0x05
	socksAuthVersion = 0x01

	socksMethodNoAuth       = 0x00
	socksMethodUserPass     = 0x02
	socksMethodNoAcceptable = 0xFF

	socksAuthSuccess = 0x00
	socksAuthFailure = 0x01

	socksCommandConnect      = 0x01
	socksCommandBind         = 0x02
	socksCommandUDPAssociate = 0x03

	socksAddressIPv4   = 0x01
	socksAddressDomain = 0x03
	socksAddressIPv6   = 0x04

	socksReplySucceeded               = 0x00
	socksReplyGeneralFailure          = 0x01
	socksReplyNotAllowed              = 0x02
	socksReplyNetworkUnreachable      = 0x03
	socksReplyHostUnreachable         = 0x04
	socksReplyConnectionRefused       = 0x05
	socksReplyCommandNotSupported     = 0x07
	socksReplyAddressTypeNotSupported = 0x08

	// socksReplyNone marks "close without sending a reply": either the framing
	// is already lost or the failure happened before a request was parsed. It is
	// not an RFC 1928 reply code.
	socksReplyNone = 0xFF

	replyWriteTimeout = 2 * time.Second

	// rejectedDrainTimeout bounds the effort to consume a refused request before
	// closing, and rejectedDrainLimit bounds the bytes consumed. The request
	// bytes are normally already buffered when the refusal is written, so the
	// drain returns immediately; the deadline only bounds a peer that sends
	// nothing further.
	rejectedDrainTimeout = 100 * time.Millisecond
	rejectedDrainLimit   = 64 << 10
)

// drainRejectedRequest consumes the remainder of a request this server refused
// before the connection is closed.
//
// Writing a reply and then closing while unread bytes remain in the receive
// buffer makes Windows abort the connection with RST rather than closing it with
// FIN, and that RST discards whatever the peer has not read yet — including the
// RFC 1928 failure reply just written. Draining first keeps the teardown
// graceful so the reply is actually delivered. The drain is strictly bounded in
// time and bytes so a peer that keeps sending cannot hold the handler open.
func drainRejectedRequest(conn net.Conn) {
	if err := conn.SetReadDeadline(time.Now().Add(rejectedDrainTimeout)); err != nil {
		return
	}
	var scratch [256]byte
	for total := 0; total < rejectedDrainLimit; {
		n, err := conn.Read(scratch[:])
		total += n
		if err != nil {
			return
		}
	}
}

// errMalformedRequest is the internal identity of a protocol violation. It is
// never exposed as an API error; the client observes the close or the RFC 1928
// general-failure reply.
var errMalformedRequest = errors.New("agent: malformed proxy request")

// socksRequest is one parsed SOCKS5 request. host is either an IPv4 literal or a
// domain name; resolution stays with the outbound policy port and the Dialer.
type socksRequest struct {
	command byte
	host    string
	port    uint16
}

// serveSOCKS5 runs one SOCKS5 ingress connection: bounded failure budget,
// mandatory RFC 1929 username/password sub-negotiation, then CONNECT or UDP
// ASSOCIATE. NO AUTH is never offered.
func serveSOCKS5(ctx context.Context, server *proxyServer, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(server.config.handshakeTimeout()))

	if !server.authBudget.allow(time.Now()) {
		// The entry's failure budget is exhausted for this window, so no
		// credential work is done and no method is offered.
		server.stats.throttled.Add(1)
		return
	}
	if err := negotiateSOCKSMethod(conn); err != nil {
		if errors.Is(err, ErrAuthentication) {
			server.noteAuthFailure()
		}
		return
	}
	if err := authenticateSOCKSUserPass(conn, server.credentials); err != nil {
		if errors.Is(err, ErrAuthentication) {
			server.noteAuthFailure()
		}
		return
	}

	request, reply, err := readSOCKSRequest(conn)
	if err != nil {
		if reply != socksReplyNone {
			_ = conn.SetWriteDeadline(time.Now().Add(replyWriteTimeout))
			_ = writeSOCKSReply(conn, reply, nil)
			// Discard the rest of the refused request so the close is graceful
			// and the reply is not lost to a Windows RST.
			drainRejectedRequest(conn)
		}
		if errors.Is(err, ErrUnsupported) {
			server.stats.unsupported.Add(1)
		}
		return
	}

	switch request.command {
	case socksCommandConnect:
		serveSOCKS5Connect(ctx, server, conn, request)
	case socksCommandUDPAssociate:
		serveSOCKS5UDPAssociate(ctx, server, conn, request)
	}
}

// serveSOCKS5Connect resolves (when a policy port is configured), dials and
// relays one TCP flow. The success reply carries the endpoint the proxy actually
// used to reach the target, not the requested destination.
func serveSOCKS5Connect(ctx context.Context, server *proxyServer, conn net.Conn, request socksRequest) {
	upstream, reply, err := server.dialProxyTarget(ctx, request.host, request.port)
	if err != nil {
		if errors.Is(err, ErrTargetDenied) {
			server.stats.policyDenied.Add(1)
		} else {
			server.stats.dialFailures.Add(1)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(replyWriteTimeout))
		_ = writeSOCKSReply(conn, reply, nil)
		return
	}
	defer upstream.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(replyWriteTimeout)); err != nil {
		return
	}
	if err := writeSOCKSReply(conn, socksReplySucceeded, upstream.LocalAddr()); err != nil {
		return
	}
	// The handshake deadline must not bound the established tunnel.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}
	relay(ctx, conn, upstream)
}

// negotiateSOCKSMethod performs the RFC 1928 method negotiation. It selects the
// username/password method when offered and otherwise answers 0xFF; NO AUTH is
// never selected even when the client offers it (R-MESH-006).
func negotiateSOCKSMethod(conn net.Conn) error {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[0] != socksVersion {
		return fmt.Errorf("%w: version 0x%02x", errMalformedRequest, head[0])
	}
	count := int(head[1])
	if count == 0 {
		return fmt.Errorf("%w: no authentication methods offered", errMalformedRequest)
	}
	methods := make([]byte, count)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == socksMethodUserPass {
			return writeAll(conn, []byte{socksVersion, socksMethodUserPass})
		}
	}
	_ = writeAll(conn, []byte{socksVersion, socksMethodNoAcceptable})
	return fmt.Errorf("%w: client offered no username/password method", ErrAuthentication)
}

// authenticateSOCKSUserPass performs the RFC 1929 sub-negotiation. Lengths are
// bounded by the single-byte ULEN/PLEN fields, so the exchange cannot exceed
// 513 bytes. Every rejected exchange answers 0x01 0x01 and counts as an
// authentication failure; the caller closes the connection.
func authenticateSOCKSUserPass(conn net.Conn, credentials Credentials) error {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	fail := func(format string, args ...any) error {
		_ = writeAll(conn, []byte{socksAuthVersion, socksAuthFailure})
		return fmt.Errorf("%w: %s", ErrAuthentication, fmt.Sprintf(format, args...))
	}
	if head[0] != socksAuthVersion {
		return fail("sub-negotiation version 0x%02x", head[0])
	}
	usernameLength := int(head[1])
	if usernameLength == 0 {
		return fail("empty username")
	}
	username := make([]byte, usernameLength)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	var rawPasswordLength [1]byte
	if _, err := io.ReadFull(conn, rawPasswordLength[:]); err != nil {
		return err
	}
	passwordLength := int(rawPasswordLength[0])
	if passwordLength == 0 {
		return fail("empty password")
	}
	password := make([]byte, passwordLength)
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}
	if !credentials.Matches(string(username), string(password)) {
		return fail("credentials do not match this inbound")
	}
	return writeAll(conn, []byte{socksAuthVersion, socksAuthSuccess})
}

// readSOCKSRequest parses one SOCKS5 request. A non-nil error always means the
// connection must be closed; when reply is not socksReplyNone the handler sends
// that RFC 1928 reply first.
//
// CONNECT requires a nonzero port. UDP ASSOCIATE accepts port 0 because the
// request's DST.ADDR/DST.PORT may be 0.0.0.0:0, meaning "the client has not
// chosen a source port yet".
func readSOCKSRequest(conn net.Conn) (socksRequest, byte, error) {
	var request socksRequest
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return request, socksReplyNone, err
	}
	if head[0] != socksVersion {
		return request, socksReplyNone, fmt.Errorf("%w: version 0x%02x", errMalformedRequest, head[0])
	}
	if head[2] != 0x00 {
		return request, socksReplyGeneralFailure, fmt.Errorf("%w: reserved byte 0x%02x", errMalformedRequest, head[2])
	}
	switch head[1] {
	case socksCommandConnect, socksCommandUDPAssociate:
		request.command = head[1]
	case socksCommandBind:
		return request, socksReplyCommandNotSupported, fmt.Errorf("%w: SOCKS5 BIND is not implemented", ErrUnsupported)
	default:
		return request, socksReplyCommandNotSupported, fmt.Errorf("%w: SOCKS5 command 0x%02x", ErrUnsupported, head[1])
	}
	host, reply, err := readSOCKSAddress(conn, head[3])
	if err != nil {
		return request, reply, err
	}
	var rawPort [2]byte
	if _, err := io.ReadFull(conn, rawPort[:]); err != nil {
		return request, socksReplyNone, err
	}
	request.host = host
	request.port = binary.BigEndian.Uint16(rawPort[:])
	if request.command == socksCommandConnect && request.port == 0 {
		return socksRequest{}, socksReplyGeneralFailure, fmt.Errorf("%w: target port 0", errMalformedRequest)
	}
	return request, socksReplyNone, nil
}

// readSOCKSAddress reads one ATYP/DST.ADDR pair. IPv4 literals and domain names
// are accepted (resolution is the outbound policy port's or the Dialer's job);
// IPv6 literals and unknown address types are refused with "address type not
// supported" before any dial.
func readSOCKSAddress(conn net.Conn, addressType byte) (string, byte, error) {
	switch addressType {
	case socksAddressIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(conn, raw[:]); err != nil {
			return "", socksReplyNone, err
		}
		return netip.AddrFrom4(raw).String(), socksReplyNone, nil
	case socksAddressDomain:
		var rawLength [1]byte
		if _, err := io.ReadFull(conn, rawLength[:]); err != nil {
			return "", socksReplyNone, err
		}
		length := int(rawLength[0])
		if length == 0 {
			return "", socksReplyGeneralFailure, fmt.Errorf("%w: empty domain name", errMalformedRequest)
		}
		raw := make([]byte, length)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return "", socksReplyNone, err
		}
		host := string(raw)
		if !printableHost(host) {
			return "", socksReplyGeneralFailure, fmt.Errorf("%w: non-printable domain name", errMalformedRequest)
		}
		if ipv6LiteralHost(host) {
			return "", socksReplyAddressTypeNotSupported, fmt.Errorf("%w: IPv6 target %q", ErrUnsupported, host)
		}
		return host, socksReplyNone, nil
	case socksAddressIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(conn, raw[:]); err != nil {
			return "", socksReplyNone, err
		}
		return "", socksReplyAddressTypeNotSupported, fmt.Errorf("%w: IPv6 target %s", ErrUnsupported, netip.AddrFrom16(raw))
	default:
		return "", socksReplyAddressTypeNotSupported, fmt.Errorf("%w: address type 0x%02x", ErrUnsupported, addressType)
	}
}

// writeSOCKSReply writes VER/REP/RSV plus one bound endpoint.
func writeSOCKSReply(conn net.Conn, reply byte, bound net.Addr) error {
	payload := []byte{socksVersion, reply, 0x00}
	address, ok := parseBoundAddress(bound)
	switch {
	case !ok:
		// No usable bound endpoint (failure reply, or a Dialer whose connection
		// reports no parseable local address): encode 0.0.0.0:0. RFC 1928 does
		// not require a meaningful BND endpoint for CONNECT.
		payload = append(payload, socksAddressIPv4, 0, 0, 0, 0, 0, 0)
	case address.Addr().Is4():
		raw := address.Addr().As4()
		payload = append(payload, socksAddressIPv4)
		payload = append(payload, raw[:]...)
		payload = binary.BigEndian.AppendUint16(payload, address.Port())
	default:
		raw := address.Addr().As16()
		payload = append(payload, socksAddressIPv6)
		payload = append(payload, raw[:]...)
		payload = binary.BigEndian.AppendUint16(payload, address.Port())
	}
	return writeAll(conn, payload)
}

func parseBoundAddress(bound net.Addr) (netip.AddrPort, bool) {
	if bound == nil {
		return netip.AddrPort{}, false
	}
	address, err := netip.ParseAddrPort(bound.String())
	if err != nil || !address.IsValid() {
		return netip.AddrPort{}, false
	}
	return address, true
}

// socksReplyForDialError maps a Dialer failure onto the closest RFC 1928 reply
// code. A policy denial is "connection not allowed by ruleset"; anything
// unrecognised is the general failure code rather than a guess.
func socksReplyForDialError(err error) byte {
	switch {
	case errors.Is(err, ErrTargetDenied):
		return socksReplyNotAllowed
	case errors.Is(err, syscall.ECONNREFUSED):
		return socksReplyConnectionRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return socksReplyNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, context.DeadlineExceeded):
		return socksReplyHostUnreachable
	default:
		return socksReplyGeneralFailure
	}
}
