// Package topology encodes canonical FACT v2 records. Decoding is structural and
// semantic validation, not proof of authenticated ingress or network membership.
package topology

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const (
	// FactProtocolVersion is the only accepted FACT sync-container version
	// (SUMMARY/PAGE/ACK). Version 1 is rejected with no downgrade or
	// re-interpretation. NODE/ADDRESS payloads carry no independent version and
	// are only meaningful inside the v2 sync container.
	FactProtocolVersion uint8 = 2

	RevocationTargetPrefix = 33 // Revoker:16 + TargetOrigin:16 + TargetKind:1

	FactEnvelopeSize = 62
	MaxFactPayload   = 4096
	MaxFactKey       = 93
	MaxFactRecord    = 4253
	// MaxRevocationTarget is the largest REVOCATION target slot:
	// Revoker:16B | TargetOrigin:16B | TargetKind:u8 | target_key (41B max LINK
	// instance key). FactKey then stays within MaxFactKey.
	MaxRevocationTarget = 74
	// MaxRevocationTargetKey is the largest nested target_key inside a
	// REVOCATION (RevocationTargetPrefix excludes it).
	MaxRevocationTargetKey = MaxRevocationTarget - RevocationTargetPrefix
	FactSummarySize        = 65
	FactPageHeaderSize     = 67
	FactAckSize            = 36
	MaxPageRecords         = 128
	MaxPageBytes           = 48 * 1024
	MaxSnapshotRecords     = 8192
	MaxSnapshotPages       = 64
	MaxSnapshotBytes       = 3 * 1024 * 1024
)

var (
	ErrFactMalformed = errors.New("malformed FACT v2")
	ErrFactTooLarge  = errors.New("FACT v2 resource limit")
	ErrFactTruncated = errors.New("truncated FACT v2")
	ErrFactNetwork   = errors.New("FACT v2 network mismatch")
)

type NodeID [16]byte
type FactKind uint8

const (
	FactNode       FactKind = 1
	FactLink       FactKind = 2
	FactAddress    FactKind = 3
	FactRevocation FactKind = 4
)

type FactVersion struct{ Incarnation, Sequence uint64 }
type FactEnvelope struct {
	NetworkID           uint64
	Kind                FactKind
	Origin              NodeID
	Version             FactVersion
	IssuedAt, ExpiresAt uint64 // Unix milliseconds, never durations.
}
type NodePayload struct {
	NodeID          NodeID
	StaticPublicKey [32]byte
	Capabilities    []string
}
type LinkCost struct{ RTTMillis, JitterMicros, LossPPM, QueueMicros, ReconnectsLast5m uint32 }
type LinkPayload struct {
	LinkID, LinkEpoch uint64
	LaneID            uint8
	From, To          NodeID
	Cost              LinkCost
	Capabilities      []string
	// ConnectionType is the literal ConnectionInfo.Type: non-empty, valid UTF-8,
	// no NUL, never trimmed/case-folded/normalized. It is descriptive metadata,
	// not identity, LaneID, LinkID, cost, endpoint or credential material.
	ConnectionType string
}
type AddressPayload struct {
	NodeID           NodeID
	IP               netip.Addr
	PrefixLen, Flags uint8
}
type RevocationPayload struct {
	Revoker, TargetOrigin           NodeID
	TargetKind                      FactKind
	TargetKey                       []byte
	TargetVersion, TombstoneVersion FactVersion
}
type FactRecord struct {
	Envelope FactEnvelope
	Payload  any
}

func validVersion(v FactVersion) bool { return v.Incarnation != 0 && v.Sequence != 0 }
func validateEnvelope(e FactEnvelope) error {
	if e.Kind < FactNode || e.Kind > FactRevocation || !validVersion(e.Version) || e.ExpiresAt <= e.IssuedAt || e.ExpiresAt-e.IssuedAt > 45000 {
		return fmt.Errorf("%w: kind=%d inc=%d seq=%d issued=%d expires=%d",
			ErrFactMalformed, e.Kind, e.Version.Incarnation, e.Version.Sequence, e.IssuedAt, e.ExpiresAt)
	}
	return nil
}
func capsBytes(caps []string) ([]byte, error) {
	if len(caps) > 4 {
		return nil, ErrFactMalformed
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(len(caps)))
	for i, c := range caps {
		if c != "endpoint.tcp" && c != "endpoint.udp" && c != "packet.ipv4" && c != "relay" {
			return nil, ErrFactMalformed
		}
		if i > 0 && caps[i-1] >= c {
			return nil, ErrFactMalformed
		}
		b = binary.BigEndian.AppendUint16(b, uint16(len(c)))
		b = append(b, c...)
	}
	return b, nil
}

// validConnectionType reports whether the literal ConnectionInfo.Type is
// admissible on the wire. It never normalizes the input: bytes are compared and
// transmitted exactly as supplied.
func validConnectionType(connectionType string) bool {
	return connectionType != "" && utf8.ValidString(connectionType) && strings.IndexByte(connectionType, 0) < 0
}

// validateTarget checks one nested REVOCATION target_key. Each concrete kind has
// an exact key length (LINK's 41B instance key is the largest), so the wrapped
// REVOCATION target can never exceed MaxRevocationTarget=74B.
func validateTarget(kind FactKind, origin NodeID, key []byte) error {
	switch kind {
	case FactNode:
		if len(key) != 16 || !bytes.Equal(key, origin[:]) {
			return ErrFactMalformed
		}
	case FactLink:
		if len(key) != 41 || !bytes.Equal(key[:16], origin[:]) || bytes.Equal(key[:16], key[16:32]) || key[32] > 2 || binary.BigEndian.Uint64(key[33:41]) == 0 {
			return ErrFactMalformed
		}
	case FactAddress:
		if len(key) != 20 || !bytes.Equal(key[:16], origin[:]) {
			return ErrFactMalformed
		}
	default:
		return ErrFactMalformed
	}
	return nil
}

// DeriveTargetKey returns owned v2 target bytes, never a hash. The LINK instance
// key is From:16B | To:16B | LaneID:u8 | LinkID:u64be (41B) so distinct LinkIDs
// on the same peer/lane stay independently revocable; ConnectionType is not part
// of the key.
func DeriveTargetKey(kind FactKind, payload any) ([]byte, error) {
	switch kind {
	case FactNode:
		p, ok := payload.(NodePayload)
		if !ok {
			return nil, ErrFactMalformed
		}
		h := sha256.Sum256(p.StaticPublicKey[:])
		if !bytes.Equal(p.NodeID[:], h[:16]) {
			return nil, ErrFactMalformed
		}
		if _, err := capsBytes(p.Capabilities); err != nil {
			return nil, err
		}
		return append([]byte(nil), p.NodeID[:]...), nil
	case FactLink:
		p, ok := payload.(LinkPayload)
		if !ok || p.LinkID == 0 || p.LinkEpoch == 0 || p.From == p.To || p.LaneID > 2 || p.Cost.LossPPM > 1000000 || !validConnectionType(p.ConnectionType) {
			return nil, fmt.Errorf("%w: @fact_codec:182 linkID=%d epoch=%d fromEqTo=%v lane=%d loss=%d",
				ErrFactMalformed, p.LinkID, p.LinkEpoch, p.From == p.To, p.LaneID, p.Cost.LossPPM)
		}
		if _, err := capsBytes(p.Capabilities); err != nil {
			return nil, err
		}
		b := append([]byte(nil), p.From[:]...)
		b = append(b, p.To[:]...)
		b = append(b, p.LaneID)
		return binary.BigEndian.AppendUint64(b, p.LinkID), nil
	case FactAddress:
		p, ok := payload.(AddressPayload)
		if !ok || !p.IP.Is4() || p.PrefixLen != 32 || p.Flags != 0 {
			return nil, ErrFactMalformed
		}
		ip := p.IP.As4()
		b := append([]byte(nil), p.NodeID[:]...)
		return append(b, ip[:]...), nil
	case FactRevocation:
		p, ok := payload.(RevocationPayload)
		if !ok || !validVersion(p.TargetVersion) || !validVersion(p.TombstoneVersion) {
			return nil, ErrFactMalformed
		}
		if err := validateTarget(p.TargetKind, p.TargetOrigin, p.TargetKey); err != nil {
			return nil, err
		}
		b := append([]byte(nil), p.Revoker[:]...)
		b = append(b, p.TargetOrigin[:]...)
		b = append(b, byte(p.TargetKind))
		return append(b, p.TargetKey...), nil
	default:
		return nil, ErrFactMalformed
	}
}
func EncodeFactPayload(kind FactKind, payload any) ([]byte, error) {
	if _, err := DeriveTargetKey(kind, payload); err != nil {
		return nil, err
	}
	var b []byte
	switch p := payload.(type) {
	case NodePayload:
		b = append(b, p.NodeID[:]...)
		b = append(b, p.StaticPublicKey[:]...)
		caps, _ := capsBytes(p.Capabilities)
		b = append(b, caps...)
	case LinkPayload:
		b = binary.BigEndian.AppendUint64(b, p.LinkID)
		b = binary.BigEndian.AppendUint64(b, p.LinkEpoch)
		b = append(b, p.LaneID)
		b = append(b, p.From[:]...)
		b = append(b, p.To[:]...)
		for _, v := range []uint32{p.Cost.RTTMillis, p.Cost.JitterMicros, p.Cost.LossPPM, p.Cost.QueueMicros, p.Cost.ReconnectsLast5m} {
			b = binary.BigEndian.AppendUint32(b, v)
		}
		caps, _ := capsBytes(p.Capabilities)
		b = append(b, caps...)
		// TypeLen:u16be | Type appended after all existing LINK fields; TypeLen
		// counts UTF-8 bytes and stays inside the 4096-byte Payload limit.
		b = binary.BigEndian.AppendUint16(b, uint16(len(p.ConnectionType)))
		b = append(b, p.ConnectionType...)
	case AddressPayload:
		b = append(b, p.NodeID[:]...)
		ip := p.IP.As4()
		b = append(b, ip[:]...)
		b = append(b, p.PrefixLen, p.Flags)
	case RevocationPayload:
		b = append(b, p.Revoker[:]...)
		b = append(b, p.TargetOrigin[:]...)
		b = append(b, byte(p.TargetKind))
		b = binary.BigEndian.AppendUint16(b, uint16(len(p.TargetKey)))
		b = append(b, p.TargetKey...)
		for _, v := range []uint64{p.TargetVersion.Incarnation, p.TargetVersion.Sequence, p.TombstoneVersion.Incarnation, p.TombstoneVersion.Sequence} {
			b = binary.BigEndian.AppendUint64(b, v)
		}
	default:
		return nil, ErrFactMalformed
	}
	if len(b) > MaxFactPayload {
		return nil, ErrFactTooLarge
	}
	return b, nil
}

type factDecoder struct {
	b   []byte
	pos int
	err error
}

func (d *factDecoder) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b)-d.pos {
		d.err = ErrFactTruncated
		return nil
	}
	v := d.b[d.pos : d.pos+n]
	d.pos += n
	return v
}
func (d *factDecoder) u8() uint8 {
	b := d.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (d *factDecoder) u16() uint16 {
	b := d.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (d *factDecoder) u32() uint32 {
	b := d.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (d *factDecoder) u64() uint64 {
	b := d.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (d *factDecoder) node() NodeID { var id NodeID; copy(id[:], d.take(16)); return id }
func (d *factDecoder) caps() []string {
	count := int(d.u16())
	if d.err != nil {
		return nil
	}
	if count > 4 {
		d.err = ErrFactMalformed
		return nil
	}
	caps := make([]string, 0, count)
	for i := 0; i < count; i++ {
		length := int(d.u16())
		raw := d.take(length)
		if d.err != nil {
			return nil
		}
		caps = append(caps, string(raw))
	}
	if _, err := capsBytes(caps); err != nil {
		d.err = err
	}
	return caps
}
func DecodeFactPayload(kind FactKind, b []byte) (any, error) {
	if len(b) > MaxFactPayload {
		return nil, ErrFactTooLarge
	}
	d := factDecoder{b: b}
	var payload any
	switch kind {
	case FactNode:
		p := NodePayload{NodeID: d.node()}
		copy(p.StaticPublicKey[:], d.take(32))
		p.Capabilities = d.caps()
		payload = p
	case FactLink:
		p := LinkPayload{LinkID: d.u64(), LinkEpoch: d.u64(), LaneID: d.u8(), From: d.node(), To: d.node()}
		p.Cost = LinkCost{d.u32(), d.u32(), d.u32(), d.u32(), d.u32()}
		p.Capabilities = d.caps()
		typeLen := int(d.u16())
		if d.err == nil && typeLen > MaxFactPayload {
			d.err = ErrFactMalformed
		}
		p.ConnectionType = string(d.take(typeLen))
		payload = p
	case FactAddress:
		p := AddressPayload{NodeID: d.node()}
		var ip [4]byte
		copy(ip[:], d.take(4))
		p.IP = netip.AddrFrom4(ip)
		p.PrefixLen, p.Flags = d.u8(), d.u8()
		payload = p
	case FactRevocation:
		p := RevocationPayload{Revoker: d.node(), TargetOrigin: d.node(), TargetKind: FactKind(d.u8())}
		length := int(d.u16())
		// Nested target_key is one of the concrete kinds (LINK's 41B instance
		// key is the largest); the wrapped REVOCATION target stays <= 74B.
		if length > MaxRevocationTargetKey {
			return nil, ErrFactMalformed
		}
		p.TargetKey = append([]byte(nil), d.take(length)...)
		p.TargetVersion = FactVersion{d.u64(), d.u64()}
		p.TombstoneVersion = FactVersion{d.u64(), d.u64()}
		payload = p
	default:
		return nil, ErrFactMalformed
	}
	if d.err != nil {
		return nil, d.err
	}
	if d.pos != len(b) {
		return nil, ErrFactMalformed
	}
	if _, err := DeriveTargetKey(kind, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
func FactKey(r FactRecord) ([]byte, error) {
	if err := validateEnvelope(r.Envelope); err != nil {
		return nil, err
	}
	key, err := DeriveTargetKey(r.Envelope.Kind, r.Payload)
	if err != nil {
		return nil, err
	}
	switch p := r.Payload.(type) {
	case NodePayload:
		if p.NodeID != r.Envelope.Origin {
			return nil, ErrFactMalformed
		}
	case LinkPayload:
		if p.From != r.Envelope.Origin {
			return nil, ErrFactMalformed
		}
	case AddressPayload:
		if p.NodeID != r.Envelope.Origin {
			return nil, ErrFactMalformed
		}
	case RevocationPayload:
		if p.Revoker != r.Envelope.Origin || p.TombstoneVersion != r.Envelope.Version {
			return nil, ErrFactMalformed
		}
	}
	b := []byte{byte(r.Envelope.Kind)}
	b = append(b, r.Envelope.Origin[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(key)))
	b = append(b, key...)
	if len(b) > MaxFactKey {
		return nil, ErrFactTooLarge
	}
	return b, nil
}
func EncodeFactRecord(r FactRecord) ([]byte, error) {
	key, err := FactKey(r)
	if err != nil {
		return nil, err
	}
	payload, err := EncodeFactPayload(r.Envelope.Kind, r.Payload)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 2+len(key)+FactEnvelopeSize+len(payload))
	b = binary.BigEndian.AppendUint16(b, uint16(len(key)))
	b = append(b, key...)
	e := r.Envelope
	b = binary.BigEndian.AppendUint64(b, e.NetworkID)
	b = append(b, byte(e.Kind))
	b = append(b, e.Origin[:]...)
	for _, v := range []uint64{e.Version.Incarnation, e.Version.Sequence, e.IssuedAt, e.ExpiresAt} {
		b = binary.BigEndian.AppendUint64(b, v)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint32(b, uint32(len(payload)))
	b = append(b, payload...)
	if len(b) > MaxFactRecord {
		return nil, ErrFactTooLarge
	}
	return b, nil
}
func decodeFactRecordPrefix(b []byte) (FactRecord, int, error) {
	if len(b) < 2 {
		return FactRecord{}, 0, ErrFactTruncated
	}
	keyLen := int(binary.BigEndian.Uint16(b[:2]))
	if keyLen < 19 || keyLen > MaxFactKey {
		return FactRecord{}, 0, ErrFactMalformed
	}
	if len(b) < 2+keyLen+FactEnvelopeSize {
		return FactRecord{}, 0, ErrFactTruncated
	}
	key := b[2 : 2+keyLen]
	d := factDecoder{b: b[2+keyLen:]}
	e := FactEnvelope{NetworkID: d.u64(), Kind: FactKind(d.u8()), Origin: d.node(), Version: FactVersion{d.u64(), d.u64()}, IssuedAt: d.u64(), ExpiresAt: d.u64()}
	if d.u8() != 0 {
		return FactRecord{}, 0, ErrFactMalformed
	}
	payloadLen := d.u32()
	if payloadLen > MaxFactPayload {
		return FactRecord{}, 0, ErrFactTooLarge
	}
	total := 2 + keyLen + FactEnvelopeSize + int(payloadLen)
	if total > MaxFactRecord {
		return FactRecord{}, 0, ErrFactTooLarge
	}
	if len(b) < total {
		return FactRecord{}, 0, ErrFactTruncated
	}
	if err := validateEnvelope(e); err != nil {
		return FactRecord{}, 0, err
	}
	payload, err := DecodeFactPayload(e.Kind, d.take(int(payloadLen)))
	if err != nil {
		return FactRecord{}, 0, err
	}
	r := FactRecord{e, payload}
	derived, err := FactKey(r)
	if err != nil {
		return FactRecord{}, 0, err
	}
	if !bytes.Equal(derived, key) {
		return FactRecord{}, 0, fmt.Errorf("%w: key mismatch kind=%d derivedLen=%d keyLen=%d", ErrFactMalformed, e.Kind, len(derived), len(key))
	}
	return r, total, nil
}
func DecodeFactRecord(b []byte) (FactRecord, error) {
	if len(b) > MaxFactRecord {
		return FactRecord{}, ErrFactTooLarge
	}
	r, n, err := decodeFactRecordPrefix(b)
	if err != nil {
		return FactRecord{}, err
	}
	if n != len(b) {
		return FactRecord{}, ErrFactMalformed
	}
	return r, nil
}

// ValidateFactForNetwork is admission-side context validation. Its expected locator must
// come from an already authenticated full-context Link; no codec can prove that a public
// u64 locator identifies a trusted network.
//
// It deliberately does not compare the envelope's timestamps against the local clock.
// IssuedAt and ExpiresAt are written with the publisher's clock, and peers on different
// private networks routinely disagree by minutes; comparing them here rejected every fact
// from a peer whose clock ran fast, and dropped every fact as stale from a peer whose
// clock ran slow, with nothing logged either way. Freshness is decided where the fact is
// stored, from the lifetime it declares, so no two clocks are ever compared.
//
// Self-consistency is still enforced: FactKey runs validateEnvelope, which requires
// ExpiresAt > IssuedAt and caps the declared lifetime.
func ValidateFactForNetwork(r FactRecord, expectedNetwork uint64) error {
	if _, err := FactKey(r); err != nil {
		return err
	}
	if r.Envelope.NetworkID != expectedNetwork {
		return ErrFactNetwork
	}
	return nil
}

type FactSummary struct {
	ProtocolVersion                               uint8
	SenderIncarnation, NetworkID, SnapshotVersion uint64
	FactCount, PageCount                          uint32
	Digest                                        [32]byte
}
type FactPage struct {
	ProtocolVersion                               uint8
	SenderIncarnation, NetworkID, SnapshotVersion uint64
	PageNo, PageCount                             uint32
	PageDigest                                    [32]byte
	Facts                                         []FactRecord
}
type AckStatus uint8

const (
	AckOK          AckStatus = 1
	AckNeedPage    AckStatus = 2
	AckComplete    AckStatus = 3
	AckReject      AckStatus = 4
	AckNeedSummary AckStatus = 5
)

type FactAck struct {
	ProtocolVersion                               uint8
	SenderIncarnation, NetworkID, SnapshotVersion uint64
	PageNo                                        uint32
	Status                                        AckStatus
	Reason                                        uint16
	MissingPage                                   uint32
}

func validSync(version uint8, incarnation, snapshot uint64) error {
	if version != FactProtocolVersion || incarnation == 0 || snapshot == 0 {
		return ErrFactMalformed
	}
	return nil
}
func validSummary(s FactSummary) error {
	if err := validSync(s.ProtocolVersion, s.SenderIncarnation, s.SnapshotVersion); err != nil {
		return err
	}
	if s.FactCount > MaxSnapshotRecords || s.PageCount > MaxSnapshotPages {
		return ErrFactTooLarge
	}
	if (s.PageCount == 0) != (s.FactCount == 0) || s.FactCount < s.PageCount || uint64(s.FactCount) > uint64(s.PageCount)*MaxPageRecords {
		return ErrFactMalformed
	}
	if s.PageCount == 0 {
		digest, _ := SnapshotDigest(s.SenderIncarnation, s.SnapshotVersion, nil)
		if s.Digest != digest {
			return ErrFactMalformed
		}
	}
	return nil
}
func syncPrefix(version uint8, incarnation, network, snapshot uint64) []byte {
	b := []byte{version}
	for _, v := range []uint64{incarnation, network, snapshot} {
		b = binary.BigEndian.AppendUint64(b, v)
	}
	return b
}
func EncodeFactSummary(s FactSummary) ([]byte, error) {
	if err := validSummary(s); err != nil {
		return nil, err
	}
	b := syncPrefix(s.ProtocolVersion, s.SenderIncarnation, s.NetworkID, s.SnapshotVersion)
	b = binary.BigEndian.AppendUint32(b, s.FactCount)
	b = binary.BigEndian.AppendUint32(b, s.PageCount)
	return append(b, s.Digest[:]...), nil
}
func DecodeFactSummary(b []byte) (FactSummary, error) {
	if len(b) != FactSummarySize {
		return FactSummary{}, ErrFactMalformed
	}
	d := factDecoder{b: b}
	s := FactSummary{ProtocolVersion: d.u8(), SenderIncarnation: d.u64(), NetworkID: d.u64(), SnapshotVersion: d.u64(), FactCount: d.u32(), PageCount: d.u32()}
	copy(s.Digest[:], d.take(32))
	if err := validSummary(s); err != nil {
		return FactSummary{}, err
	}
	return s, nil
}
func encodePageRecords(p FactPage) ([]byte, error) {
	if err := validSync(p.ProtocolVersion, p.SenderIncarnation, p.SnapshotVersion); err != nil {
		return nil, err
	}
	if p.PageCount == 0 || p.PageCount > MaxSnapshotPages || p.PageNo >= p.PageCount || len(p.Facts) == 0 {
		return nil, ErrFactMalformed
	}
	if len(p.Facts) > MaxPageRecords {
		return nil, ErrFactTooLarge
	}
	var b, previous []byte
	for _, r := range p.Facts {
		if r.Envelope.NetworkID != p.NetworkID {
			return nil, ErrFactNetwork
		}
		key, err := FactKey(r)
		if err != nil {
			return nil, err
		}
		if previous != nil && bytes.Compare(previous, key) >= 0 {
			return nil, ErrFactMalformed
		}
		record, err := EncodeFactRecord(r)
		if err != nil {
			return nil, err
		}
		if len(b)+len(record) > MaxPageBytes {
			return nil, ErrFactTooLarge
		}
		b = append(b, record...)
		previous = key
	}
	return b, nil
}
func pageDigest(incarnation, snapshot uint64, page uint32, count uint16, records []byte) [32]byte {
	b := []byte("simpletier-fact-page-v2")
	b = binary.BigEndian.AppendUint64(b, incarnation)
	b = binary.BigEndian.AppendUint64(b, snapshot)
	b = binary.BigEndian.AppendUint32(b, page)
	b = binary.BigEndian.AppendUint16(b, count)
	h := sha256.New()
	_, _ = h.Write(b)
	_, _ = h.Write(records)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// EncodeFactPage always computes the digest from canonical records; PageDigest
// is a received description, not a caller-supplied replacement for record bytes.
func EncodeFactPage(p FactPage) ([]byte, error) {
	records, err := encodePageRecords(p)
	if err != nil {
		return nil, err
	}
	digest := pageDigest(p.SenderIncarnation, p.SnapshotVersion, p.PageNo, uint16(len(p.Facts)), records)
	b := syncPrefix(p.ProtocolVersion, p.SenderIncarnation, p.NetworkID, p.SnapshotVersion)
	b = binary.BigEndian.AppendUint32(b, p.PageNo)
	b = binary.BigEndian.AppendUint32(b, p.PageCount)
	b = binary.BigEndian.AppendUint16(b, uint16(len(p.Facts)))
	b = append(b, digest[:]...)
	return append(b, records...), nil
}
func DecodeFactPage(b []byte) (FactPage, error) {
	if len(b) < FactPageHeaderSize {
		return FactPage{}, ErrFactTruncated
	}
	if len(b) > FactPageHeaderSize+MaxPageBytes {
		return FactPage{}, ErrFactTooLarge
	}
	d := factDecoder{b: b}
	p := FactPage{ProtocolVersion: d.u8(), SenderIncarnation: d.u64(), NetworkID: d.u64(), SnapshotVersion: d.u64(), PageNo: d.u32(), PageCount: d.u32()}
	count := int(d.u16())
	copy(p.PageDigest[:], d.take(32))
	if err := validSync(p.ProtocolVersion, p.SenderIncarnation, p.SnapshotVersion); err != nil {
		return FactPage{}, err
	}
	if count == 0 || count > MaxPageRecords || p.PageCount == 0 || p.PageCount > MaxSnapshotPages || p.PageNo >= p.PageCount {
		return FactPage{}, ErrFactMalformed
	}
	recordBytes := b[FactPageHeaderSize:]
	if p.PageDigest != pageDigest(p.SenderIncarnation, p.SnapshotVersion, p.PageNo, uint16(count), recordBytes) {
		return FactPage{}, ErrFactMalformed
	}
	p.Facts = make([]FactRecord, 0, count)
	pos := 0
	var previous []byte
	for i := 0; i < count; i++ {
		r, n, err := decodeFactRecordPrefix(recordBytes[pos:])
		if err != nil {
			return FactPage{}, err
		}
		if r.Envelope.NetworkID != p.NetworkID {
			return FactPage{}, ErrFactNetwork
		}
		key, err := FactKey(r)
		if err != nil {
			return FactPage{}, err
		}
		if previous != nil && bytes.Compare(previous, key) >= 0 {
			return FactPage{}, ErrFactMalformed
		}
		p.Facts = append(p.Facts, r)
		previous = key
		pos += n
	}
	if pos != len(recordBytes) {
		return FactPage{}, ErrFactMalformed
	}
	return p, nil
}
func validAck(a FactAck) error {
	if err := validSync(a.ProtocolVersion, a.SenderIncarnation, a.SnapshotVersion); err != nil {
		return err
	}
	if a.Status < AckOK || a.Status > AckNeedSummary || a.PageNo >= MaxSnapshotPages || a.MissingPage >= MaxSnapshotPages {
		return ErrFactMalformed
	}
	return nil
}
func EncodeFactAck(a FactAck) ([]byte, error) {
	if err := validAck(a); err != nil {
		return nil, err
	}
	b := syncPrefix(a.ProtocolVersion, a.SenderIncarnation, a.NetworkID, a.SnapshotVersion)
	b = binary.BigEndian.AppendUint32(b, a.PageNo)
	b = append(b, byte(a.Status))
	b = binary.BigEndian.AppendUint16(b, a.Reason)
	return binary.BigEndian.AppendUint32(b, a.MissingPage), nil
}
func DecodeFactAck(b []byte) (FactAck, error) {
	if len(b) != FactAckSize {
		return FactAck{}, ErrFactMalformed
	}
	d := factDecoder{b: b}
	a := FactAck{ProtocolVersion: d.u8(), SenderIncarnation: d.u64(), NetworkID: d.u64(), SnapshotVersion: d.u64(), PageNo: d.u32(), Status: AckStatus(d.u8()), Reason: d.u16(), MissingPage: d.u32()}
	if err := validAck(a); err != nil {
		return FactAck{}, err
	}
	return a, nil
}
func SnapshotDigest(incarnation, snapshot uint64, pages [][32]byte) ([32]byte, error) {
	if incarnation == 0 || snapshot == 0 {
		return [32]byte{}, ErrFactMalformed
	}
	if len(pages) > MaxSnapshotPages {
		return [32]byte{}, ErrFactTooLarge
	}
	b := []byte("simpletier-fact-snapshot-v2")
	b = binary.BigEndian.AppendUint64(b, incarnation)
	b = binary.BigEndian.AppendUint64(b, snapshot)
	b = binary.BigEndian.AppendUint32(b, uint32(len(pages)))
	h := sha256.New()
	_, _ = h.Write(b)
	for _, p := range pages {
		_, _ = h.Write(p[:])
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

// ValidateSnapshot checks global key order/counts/digests without changing a
// staging store. The caller still owns authenticated ingress and atomic commit.
func ValidateSnapshot(s FactSummary, pages []FactPage) error {
	if err := validSummary(s); err != nil {
		return err
	}
	if len(pages) != int(s.PageCount) {
		return ErrFactMalformed
	}
	digests := make([][32]byte, 0, len(pages))
	var previous []byte
	count, total := 0, 0
	for i, p := range pages {
		if p.PageNo != uint32(i) || p.PageCount != s.PageCount || p.NetworkID != s.NetworkID || p.SenderIncarnation != s.SenderIncarnation || p.SnapshotVersion != s.SnapshotVersion || p.ProtocolVersion != s.ProtocolVersion {
			return ErrFactMalformed
		}
		records, err := encodePageRecords(p)
		if err != nil {
			return err
		}
		digest := pageDigest(p.SenderIncarnation, p.SnapshotVersion, p.PageNo, uint16(len(p.Facts)), records)
		if digest != p.PageDigest {
			return ErrFactMalformed
		}
		for _, r := range p.Facts {
			key, err := FactKey(r)
			if err != nil {
				return err
			}
			if previous != nil && bytes.Compare(previous, key) >= 0 {
				return ErrFactMalformed
			}
			previous = key
		}
		count += len(p.Facts)
		total += len(records)
		if count > MaxSnapshotRecords || total > MaxSnapshotBytes {
			return ErrFactTooLarge
		}
		digests = append(digests, digest)
	}
	if uint32(count) != s.FactCount {
		return ErrFactMalformed
	}
	digest, err := SnapshotDigest(s.SenderIncarnation, s.SnapshotVersion, digests)
	if err != nil {
		return err
	}
	if digest != s.Digest {
		return ErrFactMalformed
	}
	return nil
}
