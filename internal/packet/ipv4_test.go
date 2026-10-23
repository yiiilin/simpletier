package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// testIPv4 builds one syntactically valid IPv4 packet with a correct header
// checksum. options must be a multiple of 4 bytes (0..40).
func testIPv4(source, destination netip.Addr, protocol, ttl, flags uint8, fragmentOffset uint16, options, payload []byte) []byte {
	if len(options)%4 != 0 {
		panic("test options must be a multiple of 4 bytes")
	}
	headerLength := ipv4MinHeaderLen + len(options)
	total := headerLength + len(payload)
	raw := make([]byte, total)
	raw[0] = 0x40 | byte(headerLength/4)
	raw[1] = 0
	binary.BigEndian.PutUint16(raw[2:4], uint16(total))
	binary.BigEndian.PutUint16(raw[4:6], 0x1234)
	raw[6] = flags<<5 | byte(fragmentOffset>>8)
	raw[7] = byte(fragmentOffset)
	raw[8] = ttl
	raw[9] = protocol
	copy(raw[12:16], source.AsSlice())
	copy(raw[16:20], destination.AsSlice())
	copy(raw[20:], options)
	copy(raw[headerLength:], payload)
	binary.BigEndian.PutUint16(raw[10:12], headerChecksum(raw[:headerLength]))
	return raw
}

func mustAddr(t *testing.T, text string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", text, err)
	}
	return address
}

func TestParseIPv4ValidatesHeaderAndOptions(t *testing.T) {
	source := mustAddr(t, "10.9.0.1")
	destination := mustAddr(t, "10.9.0.2")

	t.Run("minimal header", func(t *testing.T) {
		raw := testIPv4(source, destination, 17, 64, 0, 0, nil, []byte("hello"))
		packet, err := ParseIPv4(raw)
		if err != nil {
			t.Fatalf("ParseIPv4: %v", err)
		}
		if packet.HeaderLength != 20 || packet.TotalLength != len(raw) || len(packet.Payload) != 5 {
			t.Fatalf("header %d total %d payload %d, want 20/%d/5", packet.HeaderLength, packet.TotalLength, len(packet.Payload), len(raw))
		}
		if packet.Source != source || packet.Destination != destination {
			t.Fatalf("endpoints %s -> %s, want %s -> %s", packet.Source, packet.Destination, source, destination)
		}
		if packet.Protocol != 17 || packet.TTL != 64 {
			t.Fatalf("protocol %d ttl %d, want 17/64", packet.Protocol, packet.TTL)
		}
	})

	t.Run("header options are included in IHL and checksum", func(t *testing.T) {
		options := []byte{0x01, 0x01, 0x01, 0x00} // NOP x3 + EOL
		raw := testIPv4(source, destination, 6, 63, 0, 0, options, []byte("tcp"))
		packet, err := ParseIPv4(raw)
		if err != nil {
			t.Fatalf("ParseIPv4 with options: %v", err)
		}
		if packet.HeaderLength != 24 {
			t.Fatalf("HeaderLength = %d, want 24", packet.HeaderLength)
		}
		if !bytes.Equal(packet.Payload, []byte("tcp")) {
			t.Fatalf("payload %q, want tcp", packet.Payload)
		}
	})

	t.Run("TTL and bytes are never rewritten", func(t *testing.T) {
		raw := testIPv4(source, destination, 1, 7, ipv4FlagDontFrag, 0, nil, []byte("icmp"))
		before := append([]byte(nil), raw...)
		packet, err := ParseIPv4(raw)
		if err != nil {
			t.Fatalf("ParseIPv4: %v", err)
		}
		if packet.TTL != 7 || !packet.DontFragment() {
			t.Fatalf("ttl %d df %v, want 7/true", packet.TTL, packet.DontFragment())
		}
		if !bytes.Equal(raw, before) {
			t.Fatal("ParseIPv4 must not rewrite the packet bytes")
		}
		if !bytes.Equal(packet.Raw, before) {
			t.Fatal("Raw must alias the exact input bytes")
		}
	})

	t.Run("legal fragments are accepted, never reassembled", func(t *testing.T) {
		raw := testIPv4(source, destination, 17, 64, ipv4FlagMoreFrags, 185, nil, make([]byte, 8))
		packet, err := ParseIPv4(raw)
		if err != nil {
			t.Fatalf("ParseIPv4(fragment): %v", err)
		}
		if !packet.Fragmented() || !packet.MoreFragments() || packet.FragmentOffset != 185 {
			t.Fatalf("fragment view = %+v, want MF with offset 185", packet)
		}
	})
}

func TestParseIPv4RejectsMalformedPackets(t *testing.T) {
	source := mustAddr(t, "10.9.0.1")
	destination := mustAddr(t, "10.9.0.2")
	valid := testIPv4(source, destination, 17, 64, 0, 0, nil, []byte("payload"))

	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"short packet", valid[:19], ErrPacketMalformed},
		{"ipv6", func() []byte {
			raw := make([]byte, 40)
			raw[0] = 0x60
			binary.BigEndian.PutUint16(raw[4:6], 40)
			return raw
		}(), ErrIPv6Unsupported},
		{"unknown version", func() []byte {
			raw := append([]byte(nil), valid...)
			raw[0] = 0x50
			return raw
		}(), ErrPacketMalformed},
		{"ihl below minimum", func() []byte {
			raw := append([]byte(nil), valid...)
			raw[0] = 0x44
			return raw
		}(), ErrPacketMalformed},
		{"ihl beyond packet", func() []byte {
			raw := append([]byte(nil), valid...)
			raw[0] = 0x4f
			return raw
		}(), ErrPacketMalformed},
		{"total length below header", func() []byte {
			raw := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(raw[2:4], 10)
			return raw
		}(), ErrPacketMalformed},
		{"truncated payload", func() []byte {
			raw := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)+20))
			return raw
		}(), ErrPacketMalformed},
		{"trailing bytes after total length", func() []byte {
			raw := append(append([]byte(nil), valid...), 0x00)
			return raw
		}(), ErrPacketMalformed},
		{"bad header checksum", func() []byte {
			raw := append([]byte(nil), valid...)
			raw[10] ^= 0xff
			return raw
		}(), ErrPacketMalformed},
		{"reserved flag set", func() []byte {
			raw := append([]byte(nil), valid...)
			raw[6] |= ipv4FlagReserved << 5
			return raw
		}(), ErrPacketMalformed},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := ParseIPv4(testCase.raw)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("ParseIPv4 error %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestForbiddenDestinations(t *testing.T) {
	cidr := netip.MustParsePrefix("10.9.0.0/24")
	cases := []struct {
		address netip.Addr
		want    bool
	}{
		{netip.MustParseAddr("10.9.0.2"), false},
		{netip.MustParseAddr("224.0.0.1"), true},
		{netip.MustParseAddr("255.255.255.255"), true},
		{netip.MustParseAddr("0.0.0.0"), true},
		{netip.MustParseAddr("10.9.0.255"), true},
		{netip.MustParseAddr("10.9.1.255"), false},
	}
	for _, testCase := range cases {
		if got := isForbiddenDestination(testCase.address, cidr); got != testCase.want {
			t.Fatalf("isForbiddenDestination(%s) = %v, want %v", testCase.address, got, testCase.want)
		}
	}
}
