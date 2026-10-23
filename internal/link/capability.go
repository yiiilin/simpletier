package link

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// CapabilityVersion is the only accepted CAPABILITY schema version. Version 2
	// keeps the exact version:u8 | bits:u64be payload: bit0 frame.v1-framing
	// semantics, bit1 fact-sync.v2, bits 2..5 path/session/packet-lane/stream-lane
	// v1 semantics, bit6 link-key-update.v1 and bits 7..63 reserved zero. Version
	// 1, a missing required bit or any reserved bit is rejected without a
	// compatibility layer or downgrade: the approved coordinated upgrade to the
	// in-Link key update (ControlType 0x09) fails closed on old nodes instead of
	// silently disabling the update capability. Payload width is unchanged
	// (version:u8 | bits:u64be, 9 bytes; LINK_CTRL frame length stays 59).
	CapabilityVersion      uint8  = 2
	RequiredCapabilityMask uint64 = 0x7f
	capabilityPayloadSize         = 1 + 8
)

var (
	ErrCapabilityMalformed = errors.New("malformed capability payload")
	ErrCapabilityVersion   = errors.New("unsupported capability version")
	ErrCapabilityBits      = errors.New("invalid capability bits")
)

// Capability is the authenticated Link CAPABILITY v2 payload. It grants no
// membership by itself; callers must invoke it only after the selected Link
// authentication handshake has completed.
type Capability struct {
	Version uint8
	Bits    uint64
}

// EncodeCapability returns the exact v2 payload: version:u8 | bits:u64be.
func EncodeCapability(capability Capability) ([]byte, error) {
	if err := validateCapability(capability); err != nil {
		return nil, err
	}
	payload := make([]byte, capabilityPayloadSize)
	payload[0] = capability.Version
	binary.BigEndian.PutUint64(payload[1:], capability.Bits)
	return payload, nil
}

// DecodeCapability validates and decodes exactly one v2 capability payload.
func DecodeCapability(payload []byte) (Capability, error) {
	if len(payload) != capabilityPayloadSize {
		return Capability{}, fmt.Errorf("capability payload length %d; want %d: %w", len(payload), capabilityPayloadSize, ErrCapabilityMalformed)
	}
	capability := Capability{Version: payload[0], Bits: binary.BigEndian.Uint64(payload[1:])}
	if err := validateCapability(capability); err != nil {
		return Capability{}, err
	}
	return capability, nil
}

func validateCapability(capability Capability) error {
	if capability.Version != CapabilityVersion {
		return fmt.Errorf("capability version %d; want %d: %w", capability.Version, CapabilityVersion, ErrCapabilityVersion)
	}
	if capability.Bits&RequiredCapabilityMask != RequiredCapabilityMask || capability.Bits&^RequiredCapabilityMask != 0 {
		return fmt.Errorf("capability bits 0x%016x are missing required or contain reserved bits: %w", capability.Bits, ErrCapabilityBits)
	}
	return nil
}
