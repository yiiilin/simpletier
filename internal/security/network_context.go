package security

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"unicode/utf8"
)

var ErrInvalidNetworkContext = errors.New("invalid network context")

const (
	networkDescriptorV1 = "simpletier-v1/network-context"
	networkPrologueV1   = "simpletier-v1/prologue"
	networkPSKDomainV1  = "simpletier-v1/psk"
)

// NetworkContext is immutable public network identity, independent of token
// rotation. The zero value is invalid and is rejected by key/prologue operations.
// ID is the full local context identifier, not the u64 wire NetworkID locator.
type NetworkContext struct {
	name       string
	descriptor string
	id         [32]byte
	wireID     uint64
}

// NewNetworkContext preserves the exact name bytes, including case, whitespace
// and Unicode normalization. CIDR must be a canonical IPv4 prefix of length 1..32.
// Descriptor v1 is ASCII "simpletier-v1/network-context", then name and CIDR,
// each encoded as u32be byte length followed by its literal UTF-8 bytes.
func NewNetworkContext(name, cidr string) (NetworkContext, error) {
	if uint64(len(networkDescriptorV1))+8+uint64(len(name))+uint64(len(cidr)) > math.MaxUint32 {
		return NetworkContext{}, fmt.Errorf("network descriptor exceeds u32 encoding: %w", ErrInvalidNetworkContext)
	}
	if name == "" || !utf8.ValidString(name) || strings.IndexByte(name, 0) >= 0 {
		return NetworkContext{}, fmt.Errorf("network name must be nonempty valid UTF-8 without NUL: %w", ErrInvalidNetworkContext)
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 1 || prefix.Bits() > 32 || prefix != prefix.Masked() || prefix.String() != cidr {
		return NetworkContext{}, fmt.Errorf("network CIDR must be a canonical IPv4 prefix of length 1..32: %w", ErrInvalidNetworkContext)
	}
	descriptor, err := encodeNetworkContextRecord(networkDescriptorV1, []byte(name), []byte(cidr))
	if err != nil {
		return NetworkContext{}, err
	}
	locator := sha256.New()
	_, _ = locator.Write([]byte("simpletier-v1\x00"))
	_, _ = locator.Write([]byte(name))
	_, _ = locator.Write([]byte{0})
	_, _ = locator.Write([]byte(cidr))
	wireID := binary.BigEndian.Uint64(locator.Sum(nil)[:8])
	return NetworkContext{name: name, descriptor: string(descriptor), id: sha256.Sum256(descriptor), wireID: wireID}, nil
}

// Descriptor returns a defensive copy of the versioned public context bytes.
// The invalid zero context returns nil.
func (n NetworkContext) Descriptor() []byte {
	if n.descriptor == "" {
		return nil
	}
	return []byte(n.descriptor)
}

func (n NetworkContext) ID() [32]byte { return n.id }

// WireID is the legacy u64 envelope locator: the big-endian first eight bytes of
// SHA256("simpletier-v1" || 0x00 || raw name || 0x00 || canonical CIDR).
// It is not an isolation root; callers retain the full ID/Descriptor for that.
// Zero is a valid hash-derived locator, not an unset sentinel.
func (n NetworkContext) WireID() uint64 { return n.wireID }

// DerivePSK retains HKDF-Extract(SHA256, salt=raw name, IKM=token) and expands
// exactly 32 bytes with info=Prologue("simpletier-v1/psk", nil). Token is opaque
// nonempty material; the caller remains responsible for its CSPRNG entropy.
// This derivation performs no file/environment reads and does not authenticate.
func (n NetworkContext) DerivePSK(token string) ([32]byte, error) {
	if n.descriptor == "" || token == "" {
		return [32]byte{}, fmt.Errorf("PSK derivation needs an initialized context and nonempty token: %w", ErrInvalidNetworkContext)
	}
	info, err := n.Prologue(networkPSKDomainV1, nil)
	if err != nil {
		return [32]byte{}, err
	}
	prk, err := hkdf.Extract(sha256.New, []byte(token), []byte(n.name))
	if err != nil {
		return [32]byte{}, fmt.Errorf("extract network PSK: %w", err)
	}
	defer clear(prk)
	key, err := hkdf.Expand(sha256.New, prk, string(info), 32)
	if err != nil {
		return [32]byte{}, fmt.Errorf("expand network PSK: %w", err)
	}
	var psk [32]byte
	copy(psk[:], key)
	clear(key)
	return psk, nil
}

// Prologue returns owned bytes: ASCII "simpletier-v1/prologue", then domain,
// full Descriptor and binding, each as u32be byte length plus exact bytes. Domain
// must be nonempty valid UTF-8 without NUL; no normalization is performed.
// Binding is arbitrary binary data and is copied, never stored or retained.
func (n NetworkContext) Prologue(domain string, binding []byte) ([]byte, error) {
	if n.descriptor == "" {
		return nil, fmt.Errorf("prologue requires an initialized context: %w", ErrInvalidNetworkContext)
	}
	if uint64(len(domain)) > math.MaxUint32 {
		return nil, fmt.Errorf("prologue domain exceeds u32 encoding: %w", ErrInvalidNetworkContext)
	}
	if domain == "" || !utf8.ValidString(domain) || strings.IndexByte(domain, 0) >= 0 {
		return nil, fmt.Errorf("prologue domain must be nonempty valid UTF-8 without NUL: %w", ErrInvalidNetworkContext)
	}
	return encodeNetworkContextRecord(networkPrologueV1, []byte(domain), []byte(n.descriptor), binding)
}

func encodeNetworkContextRecord(label string, fields ...[]byte) ([]byte, error) {
	size := uint64(len(label))
	for _, field := range fields {
		if uint64(len(field)) > math.MaxUint32 {
			return nil, fmt.Errorf("context field exceeds u32 encoding: %w", ErrInvalidNetworkContext)
		}
		size += 4 + uint64(len(field))
	}
	if size > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("context record exceeds platform allocation size: %w", ErrInvalidNetworkContext)
	}
	out := make([]byte, 0, int(size))
	out = append(out, label...)
	for _, field := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out, nil
}
