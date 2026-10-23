package session

import (
	"errors"
	"fmt"
)

// Direction identifies which side of a selected session handshake produced or
// consumes a frame. The numeric values match the link layer's
// DirectionInitiatorToResponder/DirectionResponderToInitiator so a single
// direction byte can cross the package boundary without a second convention.
//
// The mapping from a local Role is deliberate and unambiguous:
//
//	DirectionForRole(RoleInitiator, sending=true)  == DirectionInitiatorToResponder
//	DirectionForRole(RoleInitiator, sending=false) == DirectionResponderToInitiator
//	DirectionForRole(RoleResponder, sending=true)  == DirectionResponderToInitiator
//	DirectionForRole(RoleResponder, sending=false) == DirectionInitiatorToResponder
type Direction uint8

const (
	// DirectionInitiatorToResponder is the initiator -> responder direction,
	// i.e. Noise Split[0].
	DirectionInitiatorToResponder Direction = 0x00
	// DirectionResponderToInitiator is the responder -> initiator direction,
	// i.e. Noise Split[1].
	DirectionResponderToInitiator Direction = 0x01
)

// ErrInvalidDirection reports a direction other than the two canonical values.
var ErrInvalidDirection = errors.New("session: invalid direction")

// Valid reports whether the direction is one of the two canonical values.
func (d Direction) Valid() bool {
	return d == DirectionInitiatorToResponder || d == DirectionResponderToInitiator
}

// String renders the direction as the ASCII suffix used inside the session-root
// KDF info, matching the link layer's i2r/r2i convention.
func (d Direction) String() string {
	switch d {
	case DirectionInitiatorToResponder:
		return "i2r"
	case DirectionResponderToInitiator:
		return "r2i"
	default:
		return fmt.Sprintf("DIRECTION(%d)", uint8(d))
	}
}

// Opposite returns the other direction.
func (d Direction) Opposite() Direction {
	if d == DirectionInitiatorToResponder {
		return DirectionResponderToInitiator
	}
	return DirectionInitiatorToResponder
}

// DirectionForRole returns the wire direction of a frame that the local Role is
// either sending or receiving.
func DirectionForRole(role Role, sending bool) Direction {
	if (role == RoleInitiator) == sending {
		return DirectionInitiatorToResponder
	}
	return DirectionResponderToInitiator
}

// SessionRootSize is the exact size of the canonical opaque root material the
// Noise provider returns and the Manager stores:
//
//	session_root_key[Initiator->Responder] : 32B
//	session_root_key[Responder->Initiator] : 32B
//
// The two halves are independently derived keys (see
// NoiseProvider.deriveSessionRoot). Concatenation is only an encoding for the
// Manager's opaque Root() API; it is never used as HKDF input keying material.
const SessionRootSize = 2 * 32

// SessionRoot is the typed, canonical view of the opaque bytes returned by a
// NoiseProvider handshake. I2R is Split[0]'s application root and R2I is
// Split[1]'s application root.
type SessionRoot struct {
	I2R [32]byte
	R2I [32]byte
}

// DirectionalRoots is the review-facing name for the typed, exactly-64-byte
// pair of independent directional roots. It is an alias of SessionRoot so the
// two names cannot drift.
type DirectionalRoots = SessionRoot

// ParseDirectionalRoots decodes exactly SessionRootSize bytes into the typed
// directional pair. It is the review-facing alias of ParseSessionRoot.
func ParseDirectionalRoots(root []byte) (DirectionalRoots, error) {
	return ParseSessionRoot(root)
}

// ParseSessionRoot decodes exactly SessionRootSize canonical root bytes.
// Anything else is rejected rather than truncated or padded.
func ParseSessionRoot(root []byte) (SessionRoot, error) {
	var parsed SessionRoot
	if len(root) != SessionRootSize {
		return parsed, fmt.Errorf("session: root is %d bytes, want %d", len(root), SessionRootSize)
	}
	copy(parsed.I2R[:], root[:32])
	copy(parsed.R2I[:], root[32:])
	return parsed, nil
}

// Encode returns the canonical opaque encoding of the two directional roots:
// I2R first, then R2I. The returned slice is caller-owned.
func (r SessionRoot) Encode() []byte {
	out := make([]byte, 0, SessionRootSize)
	out = append(out, r.I2R[:]...)
	out = append(out, r.R2I[:]...)
	return out
}

// Direction returns the root half for one direction.
func (r SessionRoot) Direction(d Direction) [32]byte {
	if d == DirectionResponderToInitiator {
		return r.R2I
	}
	return r.I2R
}

// IsZero reports whether both halves are unset.
func (r SessionRoot) IsZero() bool {
	return r.I2R == ([32]byte{}) && r.R2I == ([32]byte{})
}
