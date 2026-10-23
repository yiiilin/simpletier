package simpletier

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"

	"github.com/yiiilin/simpletier/internal/security"
)

// addressRecordName is the NetworkState record holding this node's durable
// (VirtualIP, attempt) allocator state. It survives restart so an automatic
// address is reused and a collision re-derivation advances from the stored
// attempt instead of restarting at 0.
const addressRecordName = "address"

// addressRecordBytes is the fixed record layout: IPv4(4) || attempt u32be.
const addressRecordBytes = 8

// addressRecordLimit bounds the record read/write.
const addressRecordLimit = 64

func encodeAddressState(vip netip.Addr, attempt uint32) []byte {
	out := make([]byte, addressRecordBytes)
	copy(out[:4], vip.AsSlice())
	binary.BigEndian.PutUint32(out[4:8], attempt)
	return out
}

func decodeAddressState(data []byte) (netip.Addr, uint32, bool) {
	if len(data) != addressRecordBytes {
		return netip.Addr{}, 0, false
	}
	var raw [4]byte
	copy(raw[:], data[:4])
	return netip.AddrFrom4(raw), binary.BigEndian.Uint32(data[4:8]), true
}

// usableOverlayHost reports whether ip is an allocatable host address of prefix:
// inside the prefix and, for a prefix with a distinct network/broadcast pair
// (length <= 30), neither of them. A /31 or /32 has no reserved pair.
func usableOverlayHost(prefix netip.Prefix, ip netip.Addr) bool {
	if !prefix.IsValid() || !ip.IsValid() || !ip.Is4() || !prefix.Contains(ip) {
		return false
	}
	if prefix.Bits() > 30 {
		return true
	}
	return ip != prefix.Masked().Addr() && ip != prefixBroadcast(prefix)
}

// prefixBroadcast returns the all-ones host address of one canonical IPv4
// prefix.
func prefixBroadcast(prefix netip.Prefix) netip.Addr {
	network := prefix.Masked().Addr().As4()
	value := binary.BigEndian.Uint32(network[:])
	hostBits := uint(32 - prefix.Bits())
	var mask uint32
	if hostBits >= 32 {
		mask = ^uint32(0)
	} else {
		mask = (uint32(1) << hostBits) - 1
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value|mask)
	return netip.AddrFrom4(raw)
}

// readAddressState returns the persisted allocator state. A missing record is
// reported as ok=false, but a real read failure or a corrupt record is returned
// as an error: silently re-deriving attempt 0 would hide a corrupt record and could
// publish an address the node never owned.
func readAddressState(state *security.NetworkState) (netip.Addr, uint32, bool, error) {
	if state == nil {
		return netip.Addr{}, 0, false, nil
	}
	data, err := state.ReadRecord(addressRecordName, addressRecordLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return netip.Addr{}, 0, false, nil
		}
		return netip.Addr{}, 0, false, fmt.Errorf("read address state: %w", err)
	}
	vip, attempt, ok := decodeAddressState(data)
	if !ok {
		return netip.Addr{}, 0, false, fmt.Errorf("address state record is corrupt: %d bytes", len(data))
	}
	return vip, attempt, true, nil
}

// writeAddressState durably installs the allocator state so a restart reuses the
// same address and attempt.
func writeAddressState(state *security.NetworkState, vip netip.Addr, attempt uint32) error {
	if state == nil {
		return nil
	}
	return state.WriteRecord(addressRecordName, encodeAddressState(vip, attempt), addressRecordLimit)
}

// usableHostTotal returns the number of allocatable host addresses of one
// canonical IPv4 prefix: every host for a /31 or /32, and every host except the
// network and broadcast pair otherwise. It is the search space size the
// allocator reasons about; it is not a precomputed enumeration.
func usableHostTotal(prefix netip.Prefix) uint64 {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return 0
	}
	bits := prefix.Bits()
	if bits < 1 || bits > 32 {
		return 0
	}
	hosts := uint64(1) << uint(32-bits)
	if bits <= 30 {
		hosts -= 2
	}
	return hosts
}

// chooseProvisionalVirtualIP walks the frozen D-OVERLAY-004 sequence from a
// volatile cursor and returns the first candidate host that is not in skip.
//
// Every candidate is provisionalVirtualIP(prefix, nodeID, baseAttempt+offset)
// for one consecutive offset: the persisted (VirtualIP, attempt) pair always
// satisfies the frozen derivation, never a linear host paired with an unrelated
// attempt. At most budget offsets are evaluated, so one tick is bounded.
//
// Contract: ok=true means chosen/attempt were found. ok=false with nextCursor>0
// means the chunk budget was consumed and the caller must resume from nextCursor
// on a later tick. ok=false with nextCursor==0 means the attempt counter u32
// space wrapped, which is permanent exhaustion.
func chooseProvisionalVirtualIP(prefix netip.Prefix, nodeID [16]byte, baseAttempt, cursor uint32, budget int, skip map[netip.Addr]struct{}) (chosen netip.Addr, attempt, nextCursor uint32, ok bool) {
	if budget <= 0 {
		budget = 1
	}
	offset := cursor
	for step := 0; step < budget; step++ {
		next := offset + 1
		if next == 0 || next < offset {
			return netip.Addr{}, 0, 0, false
		}
		offset = next
		candidateAttempt := baseAttempt + offset
		if candidateAttempt < baseAttempt || candidateAttempt < offset {
			return netip.Addr{}, 0, 0, false
		}
		candidate, err := provisionalVirtualIP(prefix, nodeID, candidateAttempt)
		if err != nil {
			return netip.Addr{}, 0, 0, false
		}
		if _, taken := skip[candidate]; taken {
			continue
		}
		return candidate, candidateAttempt, 0, true
	}
	return netip.Addr{}, 0, offset, false
}

// allocateLocalVirtualIP selects this node's VirtualIP. An explicit fixed_ip is
// used verbatim, is never persisted and is never silently rewritten. Without
// one, a persisted (VirtualIP, attempt) that is a usable host of the prefix is
// reused; otherwise attempt 0 is derived from the frozen D-OVERLAY-004 formula
// and persisted so a later restart does not re-derive a different address.
func allocateLocalVirtualIP(state *security.NetworkState, prefix netip.Prefix, nodeID [16]byte, fixed netip.Addr) (netip.Addr, uint32, error) {
	if fixed.IsValid() {
		return fixed, 0, nil
	}
	vip, attempt, ok, err := readAddressState(state)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if ok && usableOverlayHost(prefix, vip) {
		return vip, attempt, nil
	}
	vip, err = provisionalVirtualIP(prefix, nodeID, 0)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if err := writeAddressState(state, vip, 0); err != nil {
		return netip.Addr{}, 0, fmt.Errorf("persist address state: %w", err)
	}
	return vip, 0, nil
}
