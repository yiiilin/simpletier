package flow

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// schemaError marks every strict codec rejection as ErrFrameMalformed.
func schemaError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrFrameMalformed}, args...)...)
}

// Fragment is one decoded or encodable UDP_DATAGRAM plaintext payload. The
// field order here is exactly the frozen wire order.
type Fragment struct {
	AssociationID   AssocID
	Flags           Flags
	DatagramID      uint64
	FragmentIndex   uint8
	FragmentCount   uint8
	TotalPayloadLen uint16
	Source          netip.AddrPort
	Destination     netip.AddrPort
	// Payload is the fragment slice, not the whole datagram.
	Payload []byte
}

// FragmentCount returns the frozen segmentation arity for one payload length:
// 0..65,345 is one fragment, 65,346..65,507 is exactly two.
func FragmentCount(total int) (uint8, error) {
	switch {
	case total < 0:
		return 0, fmt.Errorf("%w: negative payload length %d", ErrDatagramTooLarge, total)
	case total <= MaxFragmentPayload:
		return 1, nil
	case total <= MaxDatagramPayload:
		return 2, nil
	default:
		return 0, fmt.Errorf("%w: %d bytes exceeds %d", ErrDatagramTooLarge, total, MaxDatagramPayload)
	}
}

// expectedFragmentLen applies the frozen segmentation arithmetic to one index.
func expectedFragmentLen(total uint16, index, count uint8) (int, error) {
	switch {
	case count == 1 && index == 0:
		if total > MaxFragmentPayload {
			return 0, schemaError("single fragment declares total_payload_len %d above %d", total, MaxFragmentPayload)
		}
		return int(total), nil
	case count == 2 && index == 0:
		if int(total) <= MaxFragmentPayload || int(total) > MaxDatagramPayload {
			return 0, schemaError("first of two fragments declares total_payload_len %d outside %d..%d", total, MaxFragmentPayload+1, MaxDatagramPayload)
		}
		return MaxFragmentPayload, nil
	case count == 2 && index == 1:
		if int(total) <= MaxFragmentPayload || int(total) > MaxDatagramPayload {
			return 0, schemaError("second of two fragments declares total_payload_len %d outside %d..%d", total, MaxFragmentPayload+1, MaxDatagramPayload)
		}
		return int(total) - MaxFragmentPayload, nil
	default:
		return 0, schemaError("fragment_count %d with fragment_index %d is not a frozen segmentation", count, index)
	}
}

// fragmentSlice returns the payload slice of one fragment of a validated
// datagram.
func fragmentSlice(total, index int) (offset, length int) {
	if index == 0 {
		if total <= MaxFragmentPayload {
			return 0, total
		}
		return 0, MaxFragmentPayload
	}
	return MaxFragmentPayload, total - MaxFragmentPayload
}

// validateEndpoint enforces the frozen nonzero IPv4 endpoint rules: metadata
// addresses must be unicast IPv4 and both ports nonzero. The SOCKS5 UDP source
// binding is a separate adapter concern and is decided there, not here.
func validateEndpoint(addr netip.AddrPort) error {
	ip := addr.Addr()
	switch {
	case !ip.Is4():
		return schemaError("address %s is not IPv4 (D-MESH-001)", ip)
	case ip.IsUnspecified():
		return schemaError("address %s is the unspecified address", ip)
	case ip.IsMulticast():
		return schemaError("address %s is multicast", ip)
	case addr.Port() == 0:
		return schemaError("address %s has port 0", addr)
	}
	return nil
}

// Validate checks one fragment against the frozen schema, including the exact
// per-index length implied by total_payload_len and fragment_count.
func (f Fragment) Validate() error {
	if f.AssociationID == (AssocID{}) {
		return schemaError("AssociationID is zero")
	}
	if !f.Flags.valid() {
		return schemaError("unknown flags 0x%02x (REQUEST=0x00/REPLY=0x01)", uint8(f.Flags))
	}
	if f.DatagramID == 0 {
		return schemaError("DatagramID 0 is not a valid monotonic association ID (starts at 1)")
	}
	if f.FragmentCount < 1 || f.FragmentCount > MaxFragmentsPerDatagram {
		return schemaError("fragment_count %d is outside 1..%d", f.FragmentCount, MaxFragmentsPerDatagram)
	}
	if f.FragmentIndex >= f.FragmentCount {
		return schemaError("fragment_index %d is not below fragment_count %d", f.FragmentIndex, f.FragmentCount)
	}
	if f.TotalPayloadLen > MaxDatagramPayload {
		return schemaError("total_payload_len %d exceeds the %d-byte IPv4 UDP limit", f.TotalPayloadLen, MaxDatagramPayload)
	}
	if err := validateEndpoint(f.Source); err != nil {
		return err
	}
	if err := validateEndpoint(f.Destination); err != nil {
		return err
	}
	want, err := expectedFragmentLen(f.TotalPayloadLen, f.FragmentIndex, f.FragmentCount)
	if err != nil {
		return err
	}
	if len(f.Payload) != want {
		return schemaError("fragment %d/%d carries %d payload bytes, expected %d for total_payload_len %d",
			f.FragmentIndex, f.FragmentCount, len(f.Payload), want, f.TotalPayloadLen)
	}
	return nil
}

// EncodeFragment validates and encodes one UDP_DATAGRAM plaintext payload. The
// result is 41 metadata bytes plus the fragment payload; total_payload_len is
// written big-endian as given and is not recomputed from len(Payload).
func EncodeFragment(f Fragment) ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	out := make([]byte, FixedMetadataLen+len(f.Payload))
	copy(out[0:16], f.AssociationID[:])
	out[16] = byte(f.Flags)
	binary.BigEndian.PutUint64(out[17:25], f.DatagramID)
	out[25] = f.FragmentIndex
	out[26] = f.FragmentCount
	binary.BigEndian.PutUint16(out[27:29], f.TotalPayloadLen)
	source := f.Source.Addr().As4()
	copy(out[29:33], source[:])
	binary.BigEndian.PutUint16(out[33:35], f.Source.Port())
	destination := f.Destination.Addr().As4()
	copy(out[35:39], destination[:])
	binary.BigEndian.PutUint16(out[39:41], f.Destination.Port())
	copy(out[FixedMetadataLen:], f.Payload)
	return out, nil
}

// DecodeFragment strictly decodes one UDP_DATAGRAM plaintext payload. The
// returned Payload aliases raw.
func DecodeFragment(raw []byte) (Fragment, error) {
	if len(raw) < FixedMetadataLen {
		return Fragment{}, schemaError("%d bytes is shorter than the %d-byte fixed metadata", len(raw), FixedMetadataLen)
	}
	var f Fragment
	copy(f.AssociationID[:], raw[0:16])
	f.Flags = Flags(raw[16])
	f.DatagramID = binary.BigEndian.Uint64(raw[17:25])
	f.FragmentIndex = raw[25]
	f.FragmentCount = raw[26]
	f.TotalPayloadLen = binary.BigEndian.Uint16(raw[27:29])
	f.Source = netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[29:33])), binary.BigEndian.Uint16(raw[33:35]))
	f.Destination = netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[35:39])), binary.BigEndian.Uint16(raw[39:41]))
	f.Payload = raw[FixedMetadataLen:]
	if err := f.Validate(); err != nil {
		return Fragment{}, err
	}
	return f, nil
}

// headerIdentity extracts the association identity of a possibly malformed
// frame (AssociationID, flags, DatagramID) so a schema drop can consume an
// already-known DatagramID. It requires only the first 25 bytes.
func headerIdentity(raw []byte) (AssocID, Flags, uint64, bool) {
	if len(raw) < 25 {
		return AssocID{}, 0, 0, false
	}
	var id AssocID
	copy(id[:], raw[0:16])
	flags := Flags(raw[16])
	if !flags.valid() {
		return AssocID{}, 0, 0, false
	}
	return id, flags, binary.BigEndian.Uint64(raw[17:25]), true
}
