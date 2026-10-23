//go:build linux

package agent

// Minimal RTNETLINK route client for the Linux SystemNetwork transaction.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Only IPv4 unicast device routes are handled: RTM_NEWROUTE/RTM_DELROUTE with
// RTA_DST + RTA_OIF and no gateway, plus an RTM_GETROUTE dump used to verify a
// route's full fingerprint before rollback or recovery removes it. The default
// route, DNS, policy rules and the firewall are never touched. No shell command
// is used.
//
// Ownership is proven on the whole rtmsg tuple, not on the prefix alone:
// destination, prefix length, output interface, table, protocol, scope, type,
// metric and the presence of a gateway all have to match the canonical device
// route this transaction creates. A route that only shares the prefix with an
// external route is never deleted.
//
// The numeric constants below are the stable Linux uapi values from
// <linux/rtnetlink.h>. They are declared here because x/sys/unix exposes the
// message helpers but not every route attribute constant.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const (
	rtaDst      = 1
	rtaOif      = 4
	rtaGateway  = 5
	rtaPriority = 6
	rtTableMain = 254
	rtScopeLink = 253
	rtnUnicast  = 1

	ifaAddress = 1
	ifaLocal   = 2

	rtmsgHeaderLen  = 12
	ifaddrmsgHeader = 8
	// ifinfomsgHeader is sizeof(struct ifinfomsg): family, pad, type, index, flags, change.
	ifinfomsgHeader    = 16
	nlmsgAlignTo       = 4
	rtaAlignTo         = 4
	rtmsgScopeUniverse = 0
)

var netlinkSequence atomic.Uint32

func nlmsgAlign(length int) int { return (length + nlmsgAlignTo - 1) &^ (nlmsgAlignTo - 1) }
func rtaAlign(length int) int   { return (length + rtaAlignTo - 1) &^ (rtaAlignTo - 1) }

// buildRouteRequest encodes one RTM_*ROUTE message. A zero prefix produces a
// dump request without route attributes.
func buildRouteRequest(route netip.Prefix, ifindex int, messageType uint16, flags uint16) []byte {
	body := make([]byte, rtmsgHeaderLen)
	body[0] = unix.AF_INET
	if route.IsValid() {
		body[1] = byte(route.Bits())
	}
	body[4] = rtTableMain
	body[5] = unix.RTPROT_BOOT
	body[6] = rtScopeLink
	body[7] = rtnUnicast
	if route.IsValid() && route.Bits() > 0 {
		body = appendRouteAttr(body, rtaDst, route.Addr().AsSlice())
	}
	if ifindex > 0 {
		oif := make([]byte, 4)
		binary.NativeEndian.PutUint32(oif, uint32(ifindex))
		body = appendRouteAttr(body, rtaOif, oif)
	}
	header := make([]byte, unix.NLMSG_HDRLEN)
	sequence := netlinkSequence.Add(1)
	binary.NativeEndian.PutUint32(header[0:4], uint32(unix.NLMSG_HDRLEN+len(body)))
	binary.NativeEndian.PutUint16(header[4:6], messageType)
	binary.NativeEndian.PutUint16(header[6:8], flags)
	binary.NativeEndian.PutUint32(header[8:12], sequence)
	return append(header, body...)
}

func appendRouteAttr(buffer []byte, kind uint16, payload []byte) []byte {
	length := unix.SizeofRtAttr + len(payload)
	attr := make([]byte, rtaAlign(length))
	binary.NativeEndian.PutUint16(attr[0:2], uint16(length))
	binary.NativeEndian.PutUint16(attr[2:4], kind)
	copy(attr[unix.SizeofRtAttr:], payload)
	return append(buffer, attr...)
}

// routeExchange sends one request and reads until the kernel acknowledges it or
// finishes a dump. Collected message bodies are returned for dump requests.
func routeExchange(message []byte) ([][]byte, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	// A bounded receive timeout keeps a missing kernel reply from hanging the
	// Apply/Rollback transaction forever.
	timeout := unix.Timeval{Sec: 5}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	if err := unix.Sendto(fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var results [][]byte
	buffer := make([]byte, 128<<10)
	for {
		read, _, err := unix.Recvfrom(fd, buffer, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for offset := 0; offset+unix.NLMSG_HDRLEN <= read; {
			length := int(binary.NativeEndian.Uint32(buffer[offset : offset+4]))
			if length < unix.NLMSG_HDRLEN || offset+length > read {
				return nil, fmt.Errorf("agent: malformed netlink reply (length %d of %d bytes)", length, read)
			}
			messageType := binary.NativeEndian.Uint16(buffer[offset+4 : offset+6])
			payload := buffer[offset+unix.NLMSG_HDRLEN : offset+length]
			switch messageType {
			case unix.NLMSG_ERROR:
				if len(payload) < 4 {
					return nil, fmt.Errorf("agent: truncated netlink error reply")
				}
				code := int32(binary.NativeEndian.Uint32(payload[0:4]))
				if code != 0 {
					return nil, unix.Errno(-code)
				}
				return results, nil
			case unix.NLMSG_DONE:
				return results, nil
			default:
				results = append(results, append([]byte(nil), payload...))
			}
			offset += nlmsgAlign(length)
		}
	}
}

// buildAddressRequest encodes one RTM_NEWADDR/RTM_DELADDR message. Linux 6.x no
// longer dispatches SIOCDIFADDR through inet_ioctl, so interface addresses use
// the netlink path that iproute2 itself uses.
func buildAddressRequest(prefix netip.Prefix, ifindex int, messageType uint16, flags uint16) []byte {
	body := make([]byte, ifaddrmsgHeader)
	body[0] = unix.AF_INET
	if prefix.IsValid() {
		body[1] = byte(prefix.Bits())
	}
	body[2] = 0 // flags
	body[3] = rtmsgScopeUniverse
	binary.NativeEndian.PutUint32(body[4:8], uint32(ifindex))
	if prefix.IsValid() {
		address := prefix.Addr().AsSlice()
		body = appendRouteAttr(body, ifaLocal, address)
		body = appendRouteAttr(body, ifaAddress, address)
	}
	header := make([]byte, unix.NLMSG_HDRLEN)
	sequence := netlinkSequence.Add(1)
	binary.NativeEndian.PutUint32(header[0:4], uint32(unix.NLMSG_HDRLEN+len(body)))
	binary.NativeEndian.PutUint16(header[4:6], messageType)
	binary.NativeEndian.PutUint16(header[6:8], flags)
	binary.NativeEndian.PutUint32(header[8:12], sequence)
	return append(header, body...)
}

// addIPv4Address assigns one IPv4 prefix to an interface through RTM_NEWADDR.
// The exclusive-create flags make a duplicate assignment fail with EEXIST
// instead of silently replacing an address this transaction does not own.
func addIPv4Address(prefix netip.Prefix, ifindex int) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL)
	_, err := routeExchange(buildAddressRequest(prefix, ifindex, unix.RTM_NEWADDR, flags))
	return err
}

// deleteIPv4Address removes one IPv4 prefix from an interface through
// RTM_DELADDR. Create/exclusive flags are invalid on a delete and the kernel
// answers EOPNOTSUPP, so only request+ack are set.
func deleteIPv4Address(prefix netip.Prefix, ifindex int) error {
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	_, err := routeExchange(buildAddressRequest(prefix, ifindex, unix.RTM_DELADDR, flags))
	return err
}

// addRoute installs one IPv4 unicast device route. EEXIST is returned to the
// caller, which treats an already-present identical route as someone else's.
func addRoute(route netip.Prefix, ifindex int) error {
	message := buildRouteRequest(route, ifindex, unix.RTM_NEWROUTE,
		unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	_, err := routeExchange(message)
	return err
}

// deleteRoute removes one IPv4 unicast device route. The request carries the
// same table/protocol/scope/type tuple the route was created with, so the
// kernel can only match the exact canonical route.
func deleteRoute(route netip.Prefix, ifindex int) error {
	message := buildRouteRequest(route, ifindex, unix.RTM_DELROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	_, err := routeExchange(message)
	return err
}

// linuxRouteFields is the full resource identity of one IPv4 device route. It is
// the fingerprint this transaction records and the only shape recovery accepts.
type linuxRouteFields struct {
	destination netip.Addr
	bits        int
	ifindex     int
	table       int
	protocol    int
	scope       int
	routeType   int
	metric      int
	gateway     netip.Addr
}

// canonicalRouteFields is the tuple every route this transaction creates has:
// main table, boot protocol, link scope, unicast type, no gateway and metric 0
// on the given output interface.
func canonicalRouteFields(route netip.Prefix, ifindex int) linuxRouteFields {
	return linuxRouteFields{
		destination: route.Addr(),
		bits:        route.Bits(),
		ifindex:     ifindex,
		table:       rtTableMain,
		protocol:    unix.RTPROT_BOOT,
		scope:       rtScopeLink,
		routeType:   rtnUnicast,
		metric:      0,
	}
}

// fingerprint encodes the tuple into the additive journal form.
func (f linuxRouteFields) fingerprint() string {
	gateway := "none"
	if f.gateway.IsValid() {
		gateway = f.gateway.String()
	}
	return encodeJournalFields(
		[2]string{"dst", netip.PrefixFrom(f.destination, f.bits).String()},
		[2]string{"oif", strconv.Itoa(f.ifindex)},
		[2]string{"table", strconv.Itoa(f.table)},
		[2]string{"proto", strconv.Itoa(f.protocol)},
		[2]string{"scope", strconv.Itoa(f.scope)},
		[2]string{"gateway", gateway},
		[2]string{"metric", strconv.Itoa(f.metric)},
	)
}

// parseRouteFields decodes a recorded tuple. A missing or malformed field is
// unprovable ownership, never a wildcard.
func parseRouteFields(raw string) (linuxRouteFields, bool) {
	fields := decodeJournalFields(raw)
	prefix, err := netip.ParsePrefix(fields["dst"])
	if err != nil {
		return linuxRouteFields{}, false
	}
	ifindex, err := strconv.Atoi(fields["oif"])
	if err != nil {
		return linuxRouteFields{}, false
	}
	table, err := strconv.Atoi(fields["table"])
	if err != nil {
		return linuxRouteFields{}, false
	}
	protocol, err := strconv.Atoi(fields["proto"])
	if err != nil {
		return linuxRouteFields{}, false
	}
	scope, err := strconv.Atoi(fields["scope"])
	if err != nil {
		return linuxRouteFields{}, false
	}
	metric, err := strconv.Atoi(fields["metric"])
	if err != nil {
		return linuxRouteFields{}, false
	}
	var gateway netip.Addr
	if rawGateway := fields["gateway"]; rawGateway != "" && rawGateway != "none" {
		parsed, err := netip.ParseAddr(rawGateway)
		if err != nil {
			return linuxRouteFields{}, false
		}
		gateway = parsed
	}
	return linuxRouteFields{
		destination: prefix.Addr(),
		bits:        prefix.Bits(),
		ifindex:     ifindex,
		table:       table,
		protocol:    protocol,
		scope:       scope,
		routeType:   rtnUnicast,
		metric:      metric,
		gateway:     gateway,
	}, true
}

// routeEntry is one decoded RTM_GETROUTE payload.
type routeEntry struct {
	destination     netip.Addr
	destinationBits int
	ifindex         int
	table           int
	protocol        int
	scope           int
	routeType       int
	metric          int
	gateway         netip.Addr
}

// fields projects a decoded entry onto the comparable tuple shape.
func (e routeEntry) fields() linuxRouteFields {
	return linuxRouteFields{
		destination: e.destination,
		bits:        e.destinationBits,
		ifindex:     e.ifindex,
		table:       e.table,
		protocol:    e.protocol,
		scope:       e.scope,
		routeType:   e.routeType,
		metric:      e.metric,
		gateway:     e.gateway,
	}
}

// linuxRouteState is the result of looking a canonical route up in the kernel.
type linuxRouteState struct {
	// Found reports a route with the same destination, prefix length and output
	// interface exists.
	Found bool
	// Exact reports that same route also matches table, protocol, scope, type,
	// metric and gateway.
	Exact bool
	// Entry is the first matching route the kernel reported.
	Entry routeEntry
}

// routeState looks one canonical route up and classifies it as absent, owned
// (exact full-tuple match) or foreign (same prefix and interface, different
// attributes). The lookup is an RTM_GETROUTE dump filtered locally, so a
// longer-prefix or default-route lookup can never be mistaken for the route.
func routeState(route netip.Prefix, ifindex int) (linuxRouteState, error) {
	expected := canonicalRouteFields(route, ifindex)
	message := buildRouteRequest(netip.Prefix{}, 0, unix.RTM_GETROUTE, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	messages, err := routeExchange(message)
	if err != nil {
		return linuxRouteState{}, err
	}
	var state linuxRouteState
	for _, payload := range messages {
		entry, ok := parseRoutePayload(payload)
		if !ok {
			continue
		}
		if entry.destination != expected.destination || entry.destinationBits != expected.bits || entry.ifindex != expected.ifindex {
			continue
		}
		if !state.Found {
			state.Found = true
			state.Entry = entry
		}
		if entry.fields() == expected {
			state.Exact = true
			state.Entry = entry
			return state, nil
		}
	}
	return state, nil
}

// routePresent reports whether the exact canonical device route this owner
// creates exists on ifindex, together with the gateway the kernel reports.
func routePresent(route netip.Prefix, ifindex int) (bool, netip.Addr, error) {
	state, err := routeState(route, ifindex)
	if err != nil {
		return false, netip.Addr{}, err
	}
	return state.Exact, state.Entry.gateway, nil
}

// parseRoutePayload decodes the rtmsg header and the RTA_DST/RTA_OIF/RTA_GATEWAY
// and RTA_PRIORITY attributes of one route payload.
func parseRoutePayload(payload []byte) (routeEntry, bool) {
	var entry routeEntry
	if len(payload) < rtmsgHeaderLen {
		return entry, false
	}
	if payload[0] != unix.AF_INET {
		return entry, false
	}
	entry.destinationBits = int(payload[1])
	entry.table = int(payload[4])
	entry.protocol = int(payload[5])
	entry.scope = int(payload[6])
	entry.routeType = int(payload[7])
	rest := payload[rtmsgHeaderLen:]
	for len(rest) >= unix.SizeofRtAttr {
		length := int(binary.NativeEndian.Uint16(rest[0:2]))
		kind := binary.NativeEndian.Uint16(rest[2:4])
		if length < unix.SizeofRtAttr || length > len(rest) {
			break
		}
		value := rest[unix.SizeofRtAttr:length]
		switch kind {
		case rtaDst:
			if address, ok := netip.AddrFromSlice(value); ok {
				entry.destination = address.Unmap()
			}
		case rtaOif:
			if len(value) == 4 {
				entry.ifindex = int(binary.NativeEndian.Uint32(value))
			}
		case rtaGateway:
			if address, ok := netip.AddrFromSlice(value); ok {
				entry.gateway = address.Unmap()
			}
		case rtaPriority:
			if len(value) == 4 {
				entry.metric = int(binary.NativeEndian.Uint32(value))
			}
		}
		rest = rest[rtaAlign(length):]
	}
	return entry, true
}

// linuxAddressEntry is one decoded RTM_GETADDR payload.
type linuxAddressEntry struct {
	ifindex int
	prefix  netip.Prefix
}

// parseAddressPayload decodes the ifaddrmsg header and the IFA_LOCAL/IFA_ADDRESS
// attributes of one address payload. IFA_LOCAL is the address assigned to the
// interface; IFA_ADDRESS is its peer (for IPv4 point-to-point) so it is only a
// fallback.
func parseAddressPayload(payload []byte) (linuxAddressEntry, bool) {
	var entry linuxAddressEntry
	if len(payload) < ifaddrmsgHeader || payload[0] != unix.AF_INET {
		return entry, false
	}
	bits := int(payload[1])
	entry.ifindex = int(binary.NativeEndian.Uint32(payload[4:8]))
	var local, address netip.Addr
	rest := payload[ifaddrmsgHeader:]
	for len(rest) >= unix.SizeofRtAttr {
		length := int(binary.NativeEndian.Uint16(rest[0:2]))
		kind := binary.NativeEndian.Uint16(rest[2:4])
		if length < unix.SizeofRtAttr || length > len(rest) {
			break
		}
		value := rest[unix.SizeofRtAttr:length]
		switch kind {
		case ifaLocal:
			if parsed, ok := netip.AddrFromSlice(value); ok {
				local = parsed.Unmap()
			}
		case ifaAddress:
			if parsed, ok := netip.AddrFromSlice(value); ok {
				address = parsed.Unmap()
			}
		}
		rest = rest[rtaAlign(length):]
	}
	chosen := local
	if !chosen.IsValid() {
		chosen = address
	}
	if !chosen.IsValid() || bits > 32 {
		return entry, false
	}
	entry.prefix = netip.PrefixFrom(chosen, bits)
	return entry, true
}

// interfacePrefixes lists the IPv4 prefixes of one interface with their exact
// prefix lengths through an RTM_GETADDR dump. The net.Interface view masks the
// host address of a prefix, so ownership decisions that must tell /32 from /24
// use this exact view.
func interfacePrefixes(ifindex int) ([]netip.Prefix, error) {
	message := buildAddressRequest(netip.Prefix{}, ifindex, unix.RTM_GETADDR, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	messages, err := routeExchange(message)
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, 0, len(messages))
	for _, payload := range messages {
		entry, ok := parseAddressPayload(payload)
		if !ok || entry.ifindex != ifindex {
			continue
		}
		prefixes = append(prefixes, entry.prefix)
	}
	return prefixes, nil
}

// addressState classifies one local prefix: present on the interface (possibly
// with another prefix length) and exact (the prefix length matches too).
func addressState(want netip.Prefix, ifindex int) (present bool, exact bool, err error) {
	prefixes, err := interfacePrefixes(ifindex)
	if err != nil {
		return false, false, err
	}
	for _, prefix := range prefixes {
		if prefix.Addr() != want.Addr() {
			continue
		}
		present = true
		if prefix.Bits() == want.Bits() {
			exact = true
		}
	}
	return present, exact, nil
}

// buildLinkDeleteRequest asks the kernel to remove one interface by index
// (RTM_DELLINK). The request carries only the interface index; the kernel removes the
// interface together with its addresses and routes.
func buildLinkDeleteRequest(ifindex int) []byte {
	body := make([]byte, ifinfomsgHeader)
	body[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(body[4:8], uint32(ifindex))
	header := make([]byte, unix.NLMSG_HDRLEN)
	sequence := netlinkSequence.Add(1)
	binary.NativeEndian.PutUint32(header[0:4], uint32(unix.NLMSG_HDRLEN+len(body)))
	binary.NativeEndian.PutUint16(header[4:6], unix.RTM_DELLINK)
	binary.NativeEndian.PutUint16(header[6:8], uint16(unix.NLM_F_REQUEST|unix.NLM_F_ACK))
	binary.NativeEndian.PutUint32(header[8:12], sequence)
	return append(header, body...)
}

// removeStaleDevice deletes an interface left behind by a previous run that did not shut
// down cleanly. The caller has already established that the interface carries this node's
// own virtual address, so it is this program's to remove.
func removeStaleDevice(name string) error {
	// Already gone is the outcome this function wants; anything else is a real failure.
	// net exposes the not-found case as a plain error with no sentinel, so the interface
	// list is the only portable way to tell the two apart.
	iface, err := findInterfaceByName(name)
	if err != nil {
		if errors.Is(err, errInterfaceNotFound) {
			return nil
		}
		return err
	}
	_, err = routeExchange(buildLinkDeleteRequest(iface.Index))
	return err
}

// errInterfaceNotFound reports that no interface carries the requested name.
var errInterfaceNotFound = errors.New("agent: interface not found")

// findInterfaceByName reports the interface with this name, if any.
func findInterfaceByName(name string) (net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return iface, nil
		}
	}
	return net.Interface{}, errInterfaceNotFound
}
