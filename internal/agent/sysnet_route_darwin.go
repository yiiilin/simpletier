//go:build darwin

package agent

// macOS SystemNetwork primitives: interface ioctls and the PF_ROUTE routing
// socket.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Every operation here is a real kernel interface, never a shell command:
//
//	MTU      SIOCGIFMTU / SIOCSIFMTU               (struct ifreq)
//	flags    SIOCGIFFLAGS / SIOCSIFFLAGS           (struct ifreq)
//	address  SIOCAIFADDR / SIOCDIFADDR             (struct ifaliasreq)
//	routes   PF_ROUTE RTM_ADD / RTM_DELETE / RTM_GET (struct rt_msghdr)
//	table    sysctl CTL_NET/PF_ROUTE/NET_RT_DUMP   (bounded parse)
//
// A PF_ROUTE descriptor has no cancellation of its own, so every exchange is
// bounded three independent ways: SO_RCVTIMEO/SO_SNDTIMEO on the descriptor, a
// poll timeout derived from the caller's context (with a default bound when the
// context carries no deadline) and a hard cap on the number of messages one
// query consumes. A query therefore cannot queue forever behind an unread
// routing message.
//
// README for the ABI: the structs below are the Darwin wire layouts. Their sizes
// are asserted at compile time; changing one without changing the other is a
// build failure, not a silent endianness or offset bug. The Go structs are
// written through unsafe.Pointer, so byte order is native by construction (both
// supported Darwin architectures are little-endian).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// darwinRTMVersion is RTM_VERSION from <net/route.h>.
	darwinRTMVersion = 5
	// darwinSockaddrSize is sizeof(struct sockaddr) on Darwin.
	darwinSockaddrSize = 16
	// darwinRouteFlagsStatic is RTF_UP|RTF_STATIC: a statically installed,
	// usable route, which is what an overlay interface route is.
	darwinRouteFlagsStatic = unix.RTF_UP | unix.RTF_STATIC
	// darwinRouteBufferSize is the largest single routing-socket read this slice
	// accepts. A complete RTM_GET reply is well under 1 KiB; a truncated message
	// is rejected rather than misparsed.
	darwinRouteBufferSize = 4096
	// darwinRouteReadLimit caps how many routing messages one query consumes
	// before giving up, so a stream of unrelated messages cannot queue forever.
	darwinRouteReadLimit = 64
	// darwinRouteTableLimit caps how many routes the bounded sysctl dump is
	// parsed into.
	darwinRouteTableLimit = 4096
	// darwinRouteTableByteLimit caps the dump before it is parsed. A routing
	// table beyond 1 MiB of IPv4 routes is far outside this slice's scope.
	darwinRouteTableByteLimit = 1 << 20
	// darwinRouteAddressBits is the number of RTA_* address bits in a routing
	// message (RTA_DST..RTA_BRD).
	darwinRouteAddressBits = 8
	// darwinRouteDefaultTimeout bounds a query whose context has no deadline.
	darwinRouteDefaultTimeout = 2 * time.Second
)

// The wire structs must keep the C ABI. These declarations fail to compile if a
// future edit changes a size.
var (
	_ [unsafe.Sizeof(darwinSockaddr{})]byte      = [16]byte{}
	_ [unsafe.Sizeof(darwinSockaddrInet4{})]byte = [16]byte{}
	_ [unsafe.Sizeof(darwinIfaliasreq{})]byte    = [64]byte{}
	_ [unsafe.Sizeof(darwinIfreqFlags{})]byte    = [32]byte{}
	_ [unix.SizeofRtMsghdr]byte                  = [92]byte{}
	_ [unix.IFNAMSIZ]byte                        = [16]byte{}
)

// darwinSockaddr mirrors struct sockaddr: the 16-byte address container every
// Darwin routing message and interface request carries.
type darwinSockaddr struct {
	Len    uint8
	Family uint8
	Data   [14]int8
}

// darwinSockaddrInet4 mirrors struct sockaddr_in. It is the same 16 bytes as
// darwinSockaddr, so an IPv4 address is written into a generic sockaddr slot by
// reinterpreting the struct, exactly like the C union does.
type darwinSockaddrInet4 struct {
	Len    uint8
	Family uint8
	Port   uint16
	Addr   [4]byte
	Zero   [8]int8
}

// darwinIfaliasreq mirrors struct ifaliasreq, the payload of SIOCAIFADDR and
// SIOCDIFADDR (<net/if.h>): name, address, the broadaddr/dstaddr union member,
// and the netmask.
type darwinIfaliasreq struct {
	Name      [unix.IFNAMSIZ]byte
	Addr      darwinSockaddr
	Broadaddr darwinSockaddr
	Mask      darwinSockaddr
}

// darwinIfreqFlags is the struct ifreq view used by SIOCGIFFLAGS/SIOCSIFFLAGS:
// the interface name followed by the short flags member of the ifr_ifru union.
type darwinIfreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [14]byte
}

// darwinRouteEntry is one row of the bounded sysctl routing-table dump.
type darwinRouteEntry struct {
	Prefix         netip.Prefix
	InterfaceIndex int
	Gateway        netip.Addr
}

// darwinRouteInfo is the exact observed state of one prefix.
type darwinRouteInfo struct {
	Present        bool
	InterfaceIndex int
	Gateway        netip.Addr
}

// darwinSockaddrInet4Of encodes one IPv4 address in the sockaddr_in layout:
// length, AF_INET, a zero port, the four address bytes in network order and the
// eight zero bytes of sin_zero.
func darwinSockaddrInet4Of(address netip.Addr) darwinSockaddr {
	sockaddr := darwinSockaddrInet4{
		Len:    darwinSockaddrSize,
		Family: uint8(unix.AF_INET),
	}
	if address.Is4() {
		sockaddr.Addr = address.As4()
	}
	return *(*darwinSockaddr)(unsafe.Pointer(&sockaddr))
}

// darwinSockaddrInet4Addr reads the IPv4 address out of a generic sockaddr slot.
func darwinSockaddrInet4Addr(sockaddr darwinSockaddr) netip.Addr {
	inet := *(*darwinSockaddrInet4)(unsafe.Pointer(&sockaddr))
	return netip.AddrFrom4(inet.Addr)
}

// darwinNetmaskAddr converts a prefix length into the IPv4 netmask address
// (255.255.255.0 for /24, 0.0.0.0 for the default route).
func darwinNetmaskAddr(prefix netip.Prefix) netip.Addr {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return netip.AddrFrom4([4]byte{})
	}
	full := netip.PrefixFrom(netip.AddrFrom4([4]byte{0xff, 0xff, 0xff, 0xff}), prefix.Bits())
	return full.Masked().Addr()
}

// darwinMaskBits counts the leading one bits of an IPv4 netmask (255.255.0.0 is
// 16). The kernel always reports a contiguous mask; a non-contiguous one still
// yields the count of its leading ones, which can never equal a real prefix.
func darwinMaskBits(mask netip.Addr) int {
	if !mask.Is4() {
		return 0
	}
	bits := 0
	for _, octet := range mask.As4() {
		for shift := 7; shift >= 0; shift-- {
			if octet&(1<<uint(shift)) == 0 {
				return bits
			}
			bits++
		}
	}
	return bits
}

// darwinRoundUp rounds a routing-message length to the next 4-byte boundary,
// which is how the sockaddrs inside one message are packed.
func darwinRoundUp(length int) int {
	return (length + 3) &^ 3
}

// writeDarwinSockaddr copies one sockaddr into a routing-message buffer.
func writeDarwinSockaddr(buffer []byte, sockaddr darwinSockaddr) {
	copy(buffer[:darwinSockaddrSize], unsafe.Slice((*byte)(unsafe.Pointer(&sockaddr)), darwinSockaddrSize))
}

// darwinIoctlPtr performs one struct-pointer ioctl. x/sys exposes typed helpers
// for MTU only, so the generic request path goes through the raw syscall.
func darwinIoctlPtr(fd int, request uintptr, argument unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, uintptr(argument))
	if errno != 0 {
		return errno
	}
	return nil
}

// darwinControlSocket opens the short-lived datagram socket every interface
// ioctl needs. It is never kept open.
func darwinControlSocket() (int, error) {
	return unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
}

// getInterfaceMTU reads the interface MTU through SIOCGIFMTU.
func getInterfaceMTU(name string) (int, error) {
	socket, err := darwinControlSocket()
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(socket) }()
	request, err := unix.IoctlGetIfreqMTU(socket, name)
	if err != nil {
		return 0, err
	}
	return int(request.MTU), nil
}

// setInterfaceMTU sets the interface MTU through SIOCSIFMTU. It is only ever
// called by the journaled transaction.
func setInterfaceMTU(name string, mtu int) error {
	socket, err := darwinControlSocket()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(socket) }()
	request := &unix.IfreqMTU{MTU: int32(mtu)}
	copy(request.Name[:], name)
	return unix.IoctlSetIfreqMTU(socket, request)
}

// getInterfaceFlags reads the interface flags through SIOCGIFFLAGS.
func getInterfaceFlags(name string) (int16, error) {
	socket, err := darwinControlSocket()
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(socket) }()
	var request darwinIfreqFlags
	copy(request.Name[:], name)
	if err := darwinIoctlPtr(socket, uintptr(unix.SIOCGIFFLAGS), unsafe.Pointer(&request)); err != nil {
		return 0, err
	}
	return request.Flags, nil
}

// setLinkUp sets or clears IFF_UP through SIOCGIFFLAGS/SIOCSIFFLAGS.
func setLinkUp(name string, up bool) error {
	socket, err := darwinControlSocket()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(socket) }()
	var request darwinIfreqFlags
	copy(request.Name[:], name)
	if err := darwinIoctlPtr(socket, uintptr(unix.SIOCGIFFLAGS), unsafe.Pointer(&request)); err != nil {
		return err
	}
	flags := request.Flags
	if up {
		flags |= unix.IFF_UP
	} else {
		flags &^= unix.IFF_UP
	}
	request.Flags = flags
	return darwinIoctlPtr(socket, uintptr(unix.SIOCSIFFLAGS), unsafe.Pointer(&request))
}

// darwinInterfaceName resolves an interface index to its name, which is what the
// SIOCAIFADDR/SIOCDIFADDR ifaliasreq needs.
func darwinInterfaceName(index int) (string, error) {
	link, err := net.InterfaceByIndex(index)
	if err != nil {
		return "", err
	}
	return link.Name, nil
}

// addIPv4Address assigns one IPv4 prefix through SIOCAIFADDR. The
// broadaddr/dstaddr union member carries the local address, matching
// "ifconfig utunN inet <addr> <addr> netmask <mask>".
func addIPv4Address(prefix netip.Prefix, ifindex int) error {
	name, err := darwinInterfaceName(ifindex)
	if err != nil {
		return err
	}
	socket, err := darwinControlSocket()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(socket) }()
	var request darwinIfaliasreq
	copy(request.Name[:], name)
	request.Addr = darwinSockaddrInet4Of(prefix.Addr())
	request.Broadaddr = request.Addr
	request.Mask = darwinSockaddrInet4Of(darwinNetmaskAddr(prefix))
	return darwinIoctlPtr(socket, uintptr(unix.SIOCAIFADDR), unsafe.Pointer(&request))
}

// deleteIPv4Address removes one IPv4 address through SIOCDIFADDR. Only the
// address member is significant for a delete.
func deleteIPv4Address(prefix netip.Prefix, ifindex int) error {
	name, err := darwinInterfaceName(ifindex)
	if err != nil {
		return err
	}
	socket, err := darwinControlSocket()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(socket) }()
	var request darwinIfaliasreq
	copy(request.Name[:], name)
	request.Addr = darwinSockaddrInet4Of(prefix.Addr())
	return darwinIoctlPtr(socket, uintptr(unix.SIOCDIFADDR), unsafe.Pointer(&request))
}

// mustAddrs reads the interface's current addresses, discarding any entry the
// net package cannot parse. It mirrors the Linux helper so both owners snapshot
// addresses the same way.
func mustAddrs(link *net.Interface) []netip.Prefix {
	addrs, err := link.Addrs()
	if err != nil {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

// hasInterfaceAddress reports whether the interface currently carries want.
func hasInterfaceAddress(link *net.Interface, want netip.Addr) bool {
	for _, address := range mustAddrs(link) {
		if address.Addr() == want {
			return true
		}
	}
	return false
}

// darwinRouteSocket is one open PF_ROUTE descriptor. It is used for exactly one
// query and then closed.
type darwinRouteSocket struct {
	fd  int
	seq int32
}

// openDarwinRouteSocket opens PF_ROUTE/SOCK_RAW and bounds both directions with
// SO_RCVTIMEO and SO_SNDTIMEO so no read or write can queue indefinitely.
func openDarwinRouteSocket() (*darwinRouteSocket, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	timeout := unix.Timeval{
		Sec:  int64(darwinRouteDefaultTimeout / time.Second),
		Usec: int32((darwinRouteDefaultTimeout % time.Second) / time.Microsecond),
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &darwinRouteSocket{fd: fd}, nil
}

// close releases the descriptor. It is idempotent.
func (s *darwinRouteSocket) close() {
	if s == nil || s.fd < 0 {
		return
	}
	_ = unix.Close(s.fd)
	s.fd = -1
}

// nextSeq allocates the sequence number that identifies this query's reply.
func (s *darwinRouteSocket) nextSeq() int32 {
	s.seq++
	if s.seq == 0 {
		s.seq = 1
	}
	return s.seq
}

// darwinRouteDeadline bounds one query: the caller's deadline when it is sooner,
// otherwise a fixed default. It is never the zero time, so poll never blocks
// forever.
func darwinRouteDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(darwinRouteDefaultTimeout)
	if ctx != nil {
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
	}
	return deadline
}

// darwinRoutePollTimeout converts the remaining budget into a poll timeout.
func darwinRoutePollTimeout(deadline time.Time) (int, error) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, errors.New("agent: the routing query deadline passed before a reply")
	}
	millis := int(remaining / time.Millisecond)
	if millis <= 0 {
		millis = 1
	}
	return millis, nil
}

// request writes one routing-socket message and returns the write error.
//
// The kernel reports RTM_ADD/RTM_DELETE/RTM_GET failures through write: a route
// that already exists is EEXIST and a lookup that finds nothing is ESRCH. A
// successful add or delete sends no reply at all, so this reads nothing; not
// reading also keeps the descriptor queue empty. SO_SNDTIMEO bounds the write.
func (s *darwinRouteSocket) request(ctx context.Context, message []byte) error {
	if err := packetDeviceContextErr(ctx); err != nil {
		return err
	}
	_, err := unix.Write(s.fd, message)
	return err
}

// query writes one RTM_GET request and returns its reply.
//
// It filters by message type, not by sequence number: this descriptor is used
// for exactly one query and then closed, so the only RTM_GET message that can
// arrive is this query's reply, while route-change notifications
// (RTM_ADD/RTM_DELETE for other processes) may be broadcast to every routing
// socket and must be skipped. Reads are bounded by the poll deadline, the
// descriptor timeout and darwinRouteReadLimit messages.
func (s *darwinRouteSocket) query(ctx context.Context, message []byte) ([]byte, error) {
	if err := s.request(ctx, message); err != nil {
		return nil, err
	}
	deadline := darwinRouteDeadline(ctx)
	buffer := make([]byte, darwinRouteBufferSize)
	for read := 0; read < darwinRouteReadLimit; read++ {
		timeout, err := darwinRoutePollTimeout(deadline)
		if err != nil {
			return nil, err
		}
		descriptors := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(descriptors, timeout)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if ready == 0 {
			continue // the deadline is recomputed and enforced at the top
		}
		if err := packetDeviceContextErr(ctx); err != nil {
			return nil, err
		}
		count, err := unix.Read(s.fd, buffer)
		switch {
		case err == nil && count == 0:
			return nil, errors.New("agent: routing socket returned an empty message")
		case err == nil:
			messages, walkErr := darwinRouteMessages(buffer[:count], darwinRouteReadLimit)
			if walkErr != nil {
				return nil, walkErr
			}
			for _, candidate := range messages {
				header := (*unix.RtMsghdr)(unsafe.Pointer(&candidate[0]))
				if header.Type != unix.RTM_GET && header.Type != unix.RTM_GET2 {
					continue // a route-change notification for someone else's mutation
				}
				if header.Errno != 0 {
					return nil, syscall.Errno(header.Errno)
				}
				return candidate, nil
			}
		case errors.Is(err, unix.EAGAIN):
			continue
		case errors.Is(err, unix.EINTR):
			continue
		default:
			return nil, err
		}
	}
	return nil, fmt.Errorf("agent: no routing reply after %d reads", darwinRouteReadLimit)
}

// darwinRouteMessage builds one RTM_ADD/RTM_DELETE/RTM_GET message for one IPv4
// interface route: struct rt_msghdr followed by the destination sockaddr_in and
// the netmask sockaddr_in that RTA_DST|RTA_NETMASK declare.
func darwinRouteMessage(kind int, prefix netip.Prefix, ifindex int, seq int32, flags int32) []byte {
	message := make([]byte, unix.SizeofRtMsghdr+2*darwinSockaddrSize)
	header := (*unix.RtMsghdr)(unsafe.Pointer(&message[0]))
	header.Msglen = uint16(len(message))
	header.Version = darwinRTMVersion
	header.Type = uint8(kind)
	header.Index = uint16(ifindex)
	header.Flags = flags
	header.Addrs = unix.RTA_DST | unix.RTA_NETMASK
	header.Pid = int32(os.Getpid())
	header.Seq = seq
	writeDarwinSockaddr(message[unix.SizeofRtMsghdr:], darwinSockaddrInet4Of(prefix.Addr()))
	writeDarwinSockaddr(message[unix.SizeofRtMsghdr+darwinSockaddrSize:], darwinSockaddrInet4Of(darwinNetmaskAddr(prefix)))
	return message
}

// darwinRouteMessages splits a routing-socket buffer (or a sysctl route dump)
// into messages. Every message must declare a length of at least one
// rt_msghdr, fit in the buffer and carry RTM_VERSION; anything else is an
// error, because a truncated or foreign message would make an ownership check
// unsound. At most limit messages are accepted.
func darwinRouteMessages(buffer []byte, limit int) ([][]byte, error) {
	var messages [][]byte
	for offset := 0; offset < len(buffer); {
		if len(messages) >= limit {
			return nil, fmt.Errorf("agent: routing buffer declares more than %d messages", limit)
		}
		remaining := buffer[offset:]
		if len(remaining) < unix.SizeofRtMsghdr {
			if darwinBufferIsPadding(remaining) {
				break
			}
			return nil, fmt.Errorf("agent: routing buffer has %d trailing bytes that are not a message", len(remaining))
		}
		header := (*unix.RtMsghdr)(unsafe.Pointer(&remaining[0]))
		length := int(header.Msglen)
		if length < unix.SizeofRtMsghdr || length > len(remaining) {
			return nil, fmt.Errorf("agent: routing message declares %d bytes, %d available", length, len(remaining))
		}
		if header.Version != darwinRTMVersion {
			return nil, fmt.Errorf("agent: routing message version %d, want %d", header.Version, darwinRTMVersion)
		}
		messages = append(messages, remaining[:length])
		offset += darwinRoundUp(length)
	}
	return messages, nil
}

// darwinBufferIsPadding reports whether the tail of a dump is only zero bytes.
func darwinBufferIsPadding(buffer []byte) bool {
	for _, value := range buffer {
		if value != 0 {
			return false
		}
	}
	return true
}

// darwinParseSockaddrs walks the sockaddr list one routing message declares and
// returns its IPv4 addresses by RTA_* bit. A malformed list is an error: an
// address that cannot be read would make the ownership proof unsound.
func darwinParseSockaddrs(message []byte, addrs int32) (map[int32]netip.Addr, error) {
	offset := unix.SizeofRtMsghdr
	parsed := make(map[int32]netip.Addr)
	for bit := 0; bit < darwinRouteAddressBits; bit++ {
		flag := int32(1) << uint(bit)
		if addrs&flag == 0 {
			continue
		}
		if offset+darwinSockaddrSize > len(message) {
			return nil, fmt.Errorf("agent: routing message addrs=0x%x declares an address beyond its %d bytes", addrs, len(message))
		}
		sockaddr := (*darwinSockaddr)(unsafe.Pointer(&message[offset]))
		length := int(sockaddr.Len)
		if length < darwinSockaddrSize || offset+length > len(message) {
			return nil, fmt.Errorf("agent: routing address bit 0x%x declares %d bytes, %d available", flag, length, len(message)-offset)
		}
		if sockaddr.Family == uint8(unix.AF_INET) {
			parsed[flag] = darwinSockaddrInet4Addr(*sockaddr)
		}
		offset += darwinRoundUp(length)
	}
	return parsed, nil
}

// darwinPrefixFromMessage reconstructs the exact prefix one routing message
// describes. A host route (RTF_HOST) without an explicit netmask is a /32; a
// route without a destination is the default route.
func darwinPrefixFromMessage(header *unix.RtMsghdr, addrs map[int32]netip.Addr) netip.Prefix {
	destination, ok := addrs[unix.RTA_DST]
	if !ok {
		destination = netip.IPv4Unspecified()
	}
	bits := 0
	if mask, ok := addrs[unix.RTA_NETMASK]; ok {
		bits = darwinMaskBits(mask)
	} else if header.Flags&unix.RTF_HOST != 0 {
		bits = 32
	}
	return netip.PrefixFrom(destination, bits).Masked()
}

// darwinRouteGet performs one RTM_GET lookup. Present is true only when the
// kernel's reply names exactly this prefix: a longer or shorter covering route
// is a different resource and is reported as absent, never as proof.
func darwinRouteGet(ctx context.Context, prefix netip.Prefix) (darwinRouteInfo, error) {
	prefix = prefix.Masked()
	socket, err := openDarwinRouteSocket()
	if err != nil {
		return darwinRouteInfo{}, err
	}
	defer socket.close()
	message := darwinRouteMessage(unix.RTM_GET, prefix, 0, socket.nextSeq(), unix.RTF_UP)
	reply, err := socket.query(ctx, message)
	if err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) {
			return darwinRouteInfo{}, nil
		}
		return darwinRouteInfo{}, err
	}
	header := (*unix.RtMsghdr)(unsafe.Pointer(&reply[0]))
	addrs, err := darwinParseSockaddrs(reply, header.Addrs)
	if err != nil {
		return darwinRouteInfo{}, err
	}
	if darwinPrefixFromMessage(header, addrs) != prefix {
		return darwinRouteInfo{}, nil
	}
	info := darwinRouteInfo{Present: true, InterfaceIndex: int(header.Index)}
	if gateway, ok := addrs[unix.RTA_GATEWAY]; ok {
		info.Gateway = gateway
	}
	return info, nil
}

// darwinRouteTable reads the IPv4 routing table through
// sysctl CTL_NET/PF_ROUTE/NET_RT_DUMP and parses it with hard bounds on both the
// buffer size and the number of messages.
func darwinRouteTable(ctx context.Context) ([]darwinRouteEntry, error) {
	if err := packetDeviceContextErr(ctx); err != nil {
		return nil, err
	}
	buffer, err := unix.SysctlRaw("net", unix.AF_ROUTE, 0, unix.AF_INET, unix.NET_RT_DUMP, 0)
	if err != nil {
		return nil, fmt.Errorf("agent: sysctl NET_RT_DUMP: %w", err)
	}
	if len(buffer) > darwinRouteTableByteLimit {
		return nil, fmt.Errorf("agent: routing table dump is %d bytes, beyond the %d-byte bound", len(buffer), darwinRouteTableByteLimit)
	}
	messages, err := darwinRouteMessages(buffer, darwinRouteTableLimit)
	if err != nil {
		return nil, err
	}
	entries := make([]darwinRouteEntry, 0, len(messages))
	for _, message := range messages {
		header := (*unix.RtMsghdr)(unsafe.Pointer(&message[0]))
		if header.Type != unix.RTM_GET && header.Type != unix.RTM_GET2 {
			continue
		}
		addrs, err := darwinParseSockaddrs(message, header.Addrs)
		if err != nil {
			return nil, err
		}
		entry := darwinRouteEntry{
			Prefix:         darwinPrefixFromMessage(header, addrs),
			InterfaceIndex: int(header.Index),
		}
		if gateway, ok := addrs[unix.RTA_GATEWAY]; ok {
			entry.Gateway = gateway
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// darwinRouteState reports the exact state of one prefix. RTM_GET answers most
// lookups directly; a reply that only covers the prefix is not proof, so the
// bounded sysctl dump is then consulted. Ownership stays exact: a longer or
// shorter prefix is a different resource.
func darwinRouteState(ctx context.Context, prefix netip.Prefix) (darwinRouteInfo, error) {
	prefix = prefix.Masked()
	quick, err := darwinRouteGet(ctx, prefix)
	if err != nil {
		return darwinRouteInfo{}, err
	}
	if quick.Present {
		return quick, nil
	}
	entries, err := darwinRouteTable(ctx)
	if err != nil {
		return darwinRouteInfo{}, err
	}
	for _, entry := range entries {
		if entry.Prefix == prefix {
			return darwinRouteInfo{Present: true, InterfaceIndex: entry.InterfaceIndex, Gateway: entry.Gateway}, nil
		}
	}
	return darwinRouteInfo{}, nil
}

// routePresent reports whether prefix is installed on the interface with
// linkIndex. It mirrors the Linux helper's contract so both owners share the
// same transaction shape.
func routePresent(ctx context.Context, prefix netip.Prefix, linkIndex int) (bool, netip.Addr, error) {
	state, err := darwinRouteState(ctx, prefix.Masked())
	if err != nil {
		return false, netip.Addr{}, err
	}
	if !state.Present || state.InterfaceIndex != linkIndex {
		return false, netip.Addr{}, nil
	}
	return true, state.Gateway, nil
}

// addRoute installs one interface route with RTM_ADD. The kernel answers EEXIST
// through the write when a route for the prefix already exists (on this
// interface or another one), which the transaction treats as "not owned by this
// transaction".
func addRoute(ctx context.Context, route netip.Prefix, linkIndex int) error {
	route = route.Masked()
	socket, err := openDarwinRouteSocket()
	if err != nil {
		return err
	}
	defer socket.close()
	message := darwinRouteMessage(unix.RTM_ADD, route, linkIndex, socket.nextSeq(), darwinRouteFlagsStatic)
	return socket.request(ctx, message)
}

// deleteRoute removes one interface route with RTM_DELETE. The caller has
// already proved that the exact prefix belongs to this interface, so the
// dst/netmask lookup cannot remove someone else's route.
func deleteRoute(ctx context.Context, route netip.Prefix, linkIndex int) error {
	route = route.Masked()
	socket, err := openDarwinRouteSocket()
	if err != nil {
		return err
	}
	defer socket.close()
	message := darwinRouteMessage(unix.RTM_DELETE, route, linkIndex, socket.nextSeq(), darwinRouteFlagsStatic)
	return socket.request(ctx, message)
}
