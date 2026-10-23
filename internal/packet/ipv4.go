package packet

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Frozen IPv4 structural constants. P1 is IPv4-only (D-L3-002): no IPv6, no
// extension-header parsing, and no ICMPv6. The header length is a well-formed
// IHL of 5..15 32-bit words, i.e. 20..60 bytes including options.
const (
	ipv4Version       = 4
	ipv4MinHeaderLen  = 20
	ipv4MaxHeaderLen  = 60
	ipv4FlagReserved  = 0x4 // bit 7 of the flags/offset word: RFC 791 "must be zero"
	ipv4FlagDontFrag  = 0x2 // DF
	ipv4FlagMoreFrags = 0x1 // MF
)

// IPv4Packet is the validated structural view of exactly one complete IPv4
// packet. Raw and Payload alias the caller's slice; the packet plane never
// copies or rewrites them.
//
// Fragmentation is parsed but never acted on: P1 forwards legal fragments
// opaquely and never reassembles (D-L3-004 "隧道层不分片/重组"). TTL is parsed
// and never rewritten: an overlay relay decrements only OverlayHopLimit, so the
// inner header and payload leave this package byte-identical to what entered.
type IPv4Packet struct {
	// Raw is the complete packet, exactly TotalLength bytes.
	Raw []byte
	// HeaderLength is IHL*4 (20..60), including options.
	HeaderLength int
	// TotalLength is the header's total-length field. It always equals len(Raw):
	// one complete packet per call, no trailing bytes and no truncation.
	TotalLength int
	Source      netip.Addr
	Destination netip.Addr
	Protocol    uint8
	TTL         uint8
	DSCP        uint8
	// Flags holds the three low bits of the flags/fragment-offset word:
	// ipv4FlagReserved, ipv4FlagDontFrag, ipv4FlagMoreFrags.
	Flags          uint8
	FragmentOffset uint16
	// Payload is the L4 payload (or fragment body) starting at HeaderLength.
	Payload []byte
}

// DontFragment reports DF. DF changes nothing here: the packet plane never
// fragments, and P1 does not synthesize ICMP fragment-needed replies.
func (p IPv4Packet) DontFragment() bool { return p.Flags&ipv4FlagDontFrag != 0 }

// MoreFragments reports MF.
func (p IPv4Packet) MoreFragments() bool { return p.Flags&ipv4FlagMoreFrags != 0 }

// Fragmented reports that the packet is a non-initial or non-final fragment.
// Such packets are forwarded unchanged; they are never reassembled.
func (p IPv4Packet) Fragmented() bool {
	return p.MoreFragments() || p.FragmentOffset != 0
}

// ParseIPv4 validates the exact IPv4 header and returns its structural view.
//
// Accepted: version 4; IHL 5..15 with options included in the header checksum;
// total length exactly equal to len(raw) (one complete packet); header checksum
// valid; reserved flag clear. Legal fragments (MF and/or a non-zero fragment
// offset) are accepted and reported, never reassembled. Any upper-layer
// protocol is carried (P1 requires TCP/UDP/ICMP but does not forbid others).
//
// Rejected: IPv6 (ErrIPv6Unsupported), truncated/trailing/bad-IHL/bad-total/
// bad-checksum/reserved-flag headers (ErrPacketMalformed). No rejection rule is
// invented beyond the frozen IPv4 header validity rules: in particular TTL is
// never a rejection reason here (the inner TTL is opaque payload for the
// overlay), and a fragment is never rejected for being a fragment.
func ParseIPv4(raw []byte) (IPv4Packet, error) {
	if len(raw) < ipv4MinHeaderLen {
		return IPv4Packet{}, fmt.Errorf("%w: %d bytes is shorter than the 20-byte IPv4 header", ErrPacketMalformed, len(raw))
	}
	switch version := raw[0] >> 4; version {
	case ipv4Version:
	case 6:
		return IPv4Packet{}, fmt.Errorf("%w: IPv6 is out of scope for P1 (D-L3-002)", ErrIPv6Unsupported)
	default:
		return IPv4Packet{}, fmt.Errorf("%w: IP version %d is not IPv4", ErrPacketMalformed, version)
	}
	ihl := int(raw[0] & 0x0f)
	if ihl < 5 {
		return IPv4Packet{}, fmt.Errorf("%w: IHL %d is below the 5-word minimum", ErrPacketMalformed, ihl)
	}
	headerLength := ihl * 4
	if headerLength > len(raw) {
		return IPv4Packet{}, fmt.Errorf("%w: IHL declares a %d-byte header in a %d-byte packet", ErrPacketMalformed, headerLength, len(raw))
	}
	totalLength := int(binary.BigEndian.Uint16(raw[2:4]))
	if totalLength < headerLength {
		return IPv4Packet{}, fmt.Errorf("%w: total length %d is shorter than the %d-byte header", ErrPacketMalformed, totalLength, headerLength)
	}
	if totalLength > len(raw) {
		return IPv4Packet{}, fmt.Errorf("%w: total length %d exceeds the %d-byte packet", ErrPacketMalformed, totalLength, len(raw))
	}
	if totalLength < len(raw) {
		return IPv4Packet{}, fmt.Errorf("%w: %d trailing bytes after the declared total length %d", ErrPacketMalformed, len(raw)-totalLength, totalLength)
	}
	if sum := headerChecksum(raw[:headerLength]); sum != 0 {
		return IPv4Packet{}, fmt.Errorf("%w: IPv4 header checksum is invalid (residual 0x%04x)", ErrPacketMalformed, sum)
	}
	flags := raw[6] >> 5
	if flags&ipv4FlagReserved != 0 {
		return IPv4Packet{}, fmt.Errorf("%w: the reserved IPv4 flag is set", ErrPacketMalformed)
	}
	return IPv4Packet{
		Raw:            raw,
		HeaderLength:   headerLength,
		TotalLength:    totalLength,
		Source:         netip.AddrFrom4([4]byte(raw[12:16])),
		Destination:    netip.AddrFrom4([4]byte(raw[16:20])),
		Protocol:       raw[9],
		TTL:            raw[8],
		DSCP:           raw[1],
		Flags:          flags,
		FragmentOffset: binary.BigEndian.Uint16(raw[6:8]) & 0x1fff,
		Payload:        raw[headerLength:totalLength],
	}, nil
}

// headerChecksum returns the one's-complement sum of a 16-bit big-endian byte
// range. Over a valid IPv4 header (checksum field included) it returns 0;
// over a header whose checksum field is zero it returns the value to store.
func headerChecksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// isForbiddenDestination reports an address the P1 packet plane never routes:
// the limited broadcast, the unspecified address, multicast (224.0.0.0/4), and
// the directed broadcast of the configured overlay prefix. Broadcast/multicast
// is explicitly out of scope (D-L3-005), and the /32-only ownership model has no
// ARP/NDP proxy behind it. This is not a subnet-proxy or ACL feature.
func isForbiddenDestination(addr netip.Addr, cidr netip.Prefix) bool {
	if !addr.Is4() {
		return true
	}
	if addr.IsMulticast() {
		return true
	}
	if addr == netip.IPv4Unspecified() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true
	}
	if cidr.IsValid() && cidr.Addr().Is4() {
		if bits := cidr.Bits(); bits >= 1 && bits <= 30 {
			if addr == prefixBroadcast(cidr) {
				return true
			}
		}
	}
	return false
}

// prefixBroadcast returns the directed broadcast address of an IPv4 prefix with
// at least one host bit. Callers must only pass /1../30 (or /31, which has no
// broadcast under the /31 point-to-point rule and is treated as its first
// address).
func prefixBroadcast(prefix netip.Prefix) netip.Addr {
	address := prefix.Masked().Addr().As4()
	bits := prefix.Bits()
	value := binary.BigEndian.Uint32(address[:])
	if bits < 31 {
		value |= ^uint32(0) >> uint(bits)
	}
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], value)
	return netip.AddrFrom4(out)
}
