package topology

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func addressFixture() FactRecord {
	var id NodeID
	for i := range id {
		id[i] = 1
	}
	return FactRecord{Envelope: FactEnvelope{NetworkID: 0x0102030405060708, Kind: FactAddress, Origin: id, Version: FactVersion{1, 2}, IssuedAt: 1000, ExpiresAt: 2000}, Payload: AddressPayload{NodeID: id, IP: netip.MustParseAddr("10.20.0.7"), PrefixLen: 32}}
}
func nodeFixture() FactRecord {
	var pub [32]byte
	pub[0] = 9
	hash := sha256.Sum256(pub[:])
	var id NodeID
	copy(id[:], hash[:16])
	return FactRecord{Envelope: FactEnvelope{NetworkID: 7, Kind: FactNode, Origin: id, Version: FactVersion{1, 1}, IssuedAt: 1000, ExpiresAt: 46000}, Payload: NodePayload{NodeID: id, StaticPublicKey: pub, Capabilities: []string{"endpoint.tcp", "packet.ipv4", "relay"}}}
}

func TestFactRecordIndependentAddressVector(t *testing.T) {
	r := addressFixture()
	expected := "002703" + strings.Repeat("01", 16) + "0014" + strings.Repeat("01", 16) + "0a140007" +
		"010203040506070803" + strings.Repeat("01", 16) + "0000000000000001000000000000000200000000000003e800000000000007d00000000016" +
		strings.Repeat("01", 16) + "0a1400072000"
	want, err := hex.DecodeString(expected)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeFactRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || len(got) != 125 {
		t.Fatalf("record mismatch: %x, len=%d", got, len(got))
	}
	decoded, err := DecodeFactRecord(want)
	if err != nil || !reflect.DeepEqual(decoded, r) {
		t.Fatalf("decode=%#v %v", decoded, err)
	}
	want[3] ^= 0xff
	if decoded.Envelope.Origin != r.Envelope.Origin {
		t.Fatal("decoded data aliases input")
	}
}
func TestFactRecordPayloadFamilies(t *testing.T) {
	node := nodeFixture()
	from := node.Envelope.Origin
	to := NodeID{2}
	link := FactRecord{Envelope: node.Envelope, Payload: LinkPayload{LinkID: 3, LinkEpoch: 4, LaneID: 2, From: from, To: to, Cost: LinkCost{1, 2, 3, 4, 5}, Capabilities: []string{"relay"}, ConnectionType: "tcp"}}
	link.Envelope.Kind = FactLink
	target, err := DeriveTargetKey(FactLink, link.Payload)
	if err != nil {
		t.Fatal(err)
	}
	rev := FactRecord{Envelope: node.Envelope, Payload: RevocationPayload{Revoker: from, TargetOrigin: from, TargetKind: FactLink, TargetKey: target, TargetVersion: FactVersion{1, 2}, TombstoneVersion: FactVersion{1, 1}}}
	rev.Envelope.Kind = FactRevocation
	for _, r := range []FactRecord{node, link, addressFixture(), rev} {
		data, err := EncodeFactRecord(r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeFactRecord(data)
		if err != nil || !reflect.DeepEqual(got, r) {
			t.Fatalf("roundtrip kind=%d: %#v %v", r.Envelope.Kind, got, err)
		}
	}
}
func TestFactRecordRejectsMalformedAndTrailing(t *testing.T) {
	valid, err := EncodeFactRecord(addressFixture())
	if err != nil {
		t.Fatal(err)
	}
	for cut := 0; cut < len(valid); cut++ {
		if _, err := DecodeFactRecord(valid[:cut]); err == nil {
			t.Fatalf("accepted truncation %d", cut)
		}
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] = 0xff; b[1] = 0xff },
		func(b []byte) { b[2] = 0x7f },
		func(b []byte) { b[3] ^= 1 },
		func(b []byte) { b[2+39+8] = 0x7f },
		func(b []byte) { b[2+39+57] = 1 },
		func(b []byte) { b[2+39+58] = 0xff },
		func(b []byte) { b[len(b)-2] = 31 },
		func(b []byte) { b[len(b)-1] = 1 },
	} {
		b := append([]byte(nil), valid...)
		mutate(b)
		if _, err := DecodeFactRecord(b); err == nil {
			t.Fatal("accepted malformed record")
		}
	}
	if _, err := DecodeFactRecord(append(valid, 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
}
func TestFactRecordSemanticValidation(t *testing.T) {
	for _, mutate := range []func(*FactRecord){
		func(r *FactRecord) { r.Envelope.Version.Sequence = 0 },
		func(r *FactRecord) { r.Envelope.Version.Incarnation = 0 },
		func(r *FactRecord) { r.Envelope.ExpiresAt = r.Envelope.IssuedAt },
		func(r *FactRecord) { r.Envelope.ExpiresAt = r.Envelope.IssuedAt + 45001 },
		func(r *FactRecord) { r.Envelope.Origin[0] ^= 1 },
		func(r *FactRecord) { r.Payload = NodePayload{} },
	} {
		r := addressFixture()
		mutate(&r)
		if _, err := EncodeFactRecord(r); err == nil {
			t.Fatal("accepted invalid record")
		}
	}
	for _, caps := range [][]string{{"relay", "packet.ipv4"}, {"relay", "relay"}, {"unknown"}} {
		r := nodeFixture()
		n := r.Payload.(NodePayload)
		n.Capabilities = caps
		r.Payload = n
		if _, err := EncodeFactRecord(r); err == nil {
			t.Fatal("accepted noncanonical/unknown capability")
		}
	}
	r := nodeFixture()
	n := r.Payload.(NodePayload)
	n.StaticPublicKey[0] ^= 1
	r.Payload = n
	if _, err := EncodeFactRecord(r); err == nil {
		t.Fatal("accepted NodeID/public mismatch")
	}
	r = addressFixture()
	if err := ValidateFactForNetwork(r, r.Envelope.NetworkID); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFactForNetwork(r, 9); !errors.Is(err, ErrFactNetwork) {
		t.Fatalf("wrong network=%v", err)
	}
	// Expiry is decided where the fact is stored, from the lifetime it declares, so
	// admission no longer rejects a fact for looking old against the local clock.
	if err := ValidateFactForNetwork(r, r.Envelope.NetworkID); err != nil {
		t.Fatal("valid skew rejected")
	}
}
func TestFactSyncVectorsAndDigest(t *testing.T) {
	r := addressFixture()
	p := FactPage{ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, NetworkID: r.Envelope.NetworkID, SnapshotVersion: 2, PageNo: 0, PageCount: 1, Facts: []FactRecord{r}}
	data, err := EncodeFactPage(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != FactPageHeaderSize+125 || data[0] != FactProtocolVersion || data[34] != 1 {
		t.Fatalf("page layout len=%d header=%x", len(data), data[:67])
	}
	decoded, err := DecodeFactPage(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Facts, p.Facts) {
		t.Fatal("page facts changed")
	}
	digest, err := SnapshotDigest(1, 2, [][32]byte{decoded.PageDigest})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(decoded.PageDigest[:]) != "7acc055dd211076475fb0f1f5f1797aa9d8eb4005b37f789e2db1f59999c101a" {
		t.Fatal("page digest differs from independent Node SHA256 fixture")
	}
	if hex.EncodeToString(digest[:]) != "4ab63254de9281149853e3359a09ec8360470e2bd5b19bfdb0a688565e761d29" {
		t.Fatal("snapshot digest differs from independent Node SHA256 fixture")
	}
	summary := FactSummary{ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, NetworkID: r.Envelope.NetworkID, SnapshotVersion: 2, FactCount: 1, PageCount: 1, Digest: digest}
	sbytes, err := EncodeFactSummary(summary)
	if err != nil || len(sbytes) != 65 {
		t.Fatalf("summary %x %v", sbytes, err)
	}
	if hex.EncodeToString(sbytes) != "0200000000000000010102030405060708000000000000000200000001000000014ab63254de9281149853e3359a09ec8360470e2bd5b19bfdb0a688565e761d29" {
		t.Fatal("summary header vector mismatch")
	}
	sgot, err := DecodeFactSummary(sbytes)
	if err != nil || sgot != summary {
		t.Fatal(sgot, err)
	}
	ack := FactAck{ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, NetworkID: r.Envelope.NetworkID, SnapshotVersion: 2, PageNo: 0, Status: AckComplete}
	abytes, err := EncodeFactAck(ack)
	if err != nil || len(abytes) != 36 {
		t.Fatal(abytes, err)
	}
	if hex.EncodeToString(abytes) != "020000000000000001010203040506070800000000000000020000000003000000000000" {
		t.Fatal("ACK byte vector mismatch")
	}
	agot, err := DecodeFactAck(abytes)
	if err != nil || agot != ack {
		t.Fatal(agot, err)
	}
	data[len(data)-1] ^= 1
	if _, err := DecodeFactPage(data); err == nil {
		t.Fatal("tampered page digest accepted")
	}
}
func TestFactLimitsRevocationAndSyncMetadata(t *testing.T) {
	if _, err := DecodeFactRecord(make([]byte, MaxFactRecord+1)); !errors.Is(err, ErrFactTooLarge) {
		t.Fatal("record byte cap", err)
	}
	if _, err := DecodeFactPayload(FactNode, make([]byte, MaxFactPayload+1)); !errors.Is(err, ErrFactTooLarge) {
		t.Fatal("payload byte cap", err)
	}
	if _, err := DecodeFactPage(make([]byte, FactPageHeaderSize+MaxPageBytes+1)); !errors.Is(err, ErrFactTooLarge) {
		t.Fatal("page byte cap", err)
	}
	if _, err := SnapshotDigest(1, 1, make([][32]byte, MaxSnapshotPages+1)); !errors.Is(err, ErrFactTooLarge) {
		t.Fatal("snapshot page cap", err)
	}
	node := nodeFixture()
	origin := node.Envelope.Origin
	target, _ := DeriveTargetKey(FactNode, node.Payload)
	rev := FactRecord{Envelope: node.Envelope, Payload: RevocationPayload{Revoker: origin, TargetOrigin: origin, TargetKind: FactNode, TargetKey: target, TargetVersion: FactVersion{2, 3}, TombstoneVersion: node.Envelope.Version}}
	rev.Envelope.Kind = FactRevocation
	data, err := EncodeFactRecord(rev)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFactRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	target[0] ^= 1
	if got.Payload.(RevocationPayload).TargetKey[0] != origin[0] {
		t.Fatal("revocation key aliases caller")
	}
	for _, mutate := range []func(*RevocationPayload){
		func(p *RevocationPayload) { p.TargetKind = FactRevocation },
		func(p *RevocationPayload) { p.TargetVersion.Incarnation = 0 },
		func(p *RevocationPayload) { p.TombstoneVersion.Sequence++ },
		func(p *RevocationPayload) { p.Revoker[0] ^= 1 },
		func(p *RevocationPayload) { p.TargetKey = []byte{1} },
	} {
		r := got
		p := r.Payload.(RevocationPayload)
		mutate(&p)
		r.Payload = p
		if _, err := EncodeFactRecord(r); err == nil {
			t.Fatal("invalid revoke accepted")
		}
	}
	for _, ack := range []FactAck{{ProtocolVersion: 1, SenderIncarnation: 1, SnapshotVersion: 1, Status: AckOK}, {ProtocolVersion: FactProtocolVersion, SenderIncarnation: 0, SnapshotVersion: 1, Status: AckOK}, {ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, SnapshotVersion: 1, Status: 6}, {ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, SnapshotVersion: 1, Status: AckNeedPage, MissingPage: 64}} {
		if _, err := EncodeFactAck(ack); err == nil {
			t.Fatal("invalid sync ack accepted")
		}
	}
	for _, s := range []FactSummary{{ProtocolVersion: 1, SenderIncarnation: 1, SnapshotVersion: 1}, {ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, SnapshotVersion: 0}, {ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, SnapshotVersion: 1, FactCount: 8193, PageCount: 64}, {ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, SnapshotVersion: 1, FactCount: 1, PageCount: 2}, {ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, SnapshotVersion: 1, FactCount: 129, PageCount: 1}} {
		if _, err := EncodeFactSummary(s); err == nil {
			t.Fatal("invalid sync summary accepted")
		}
	}
}

func FuzzFactV2Decoders(f *testing.F) {
	record, err := EncodeFactRecord(addressFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(record)
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := DecodeFactRecord(b); err == nil {
			encoded, err := EncodeFactRecord(r)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("accepted noncanonical record")
			}
		}
		if s, err := DecodeFactSummary(b); err == nil {
			encoded, err := EncodeFactSummary(s)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("accepted noncanonical summary")
			}
		}
		if p, err := DecodeFactPage(b); err == nil {
			encoded, err := EncodeFactPage(p)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("accepted noncanonical page")
			}
		}
		if a, err := DecodeFactAck(b); err == nil {
			encoded, err := EncodeFactAck(a)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("accepted noncanonical ack")
			}
		}
		for kind := FactNode; kind <= FactRevocation; kind++ {
			if p, err := DecodeFactPayload(kind, b); err == nil {
				encoded, err := EncodeFactPayload(kind, p)
				if err != nil || !bytes.Equal(encoded, b) {
					t.Fatal("accepted noncanonical payload")
				}
			}
		}
	})
}

func TestFactSyncBoundsOrderAndCrossPageKeys(t *testing.T) {
	r := addressFixture()
	r2 := r
	payload := r2.Payload.(AddressPayload)
	payload.IP = netip.MustParseAddr("10.20.0.8")
	r2.Payload = payload
	p := FactPage{ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, NetworkID: r.Envelope.NetworkID, SnapshotVersion: 1, PageCount: 2, Facts: []FactRecord{r2, r}}
	if _, err := EncodeFactPage(p); err == nil {
		t.Fatal("unsorted keys accepted")
	}
	p.Facts = []FactRecord{r, r}
	if _, err := EncodeFactPage(p); err == nil {
		t.Fatal("duplicate keys accepted")
	}
	p.Facts = make([]FactRecord, 129)
	if _, err := EncodeFactPage(p); err == nil {
		t.Fatal("over-count accepted")
	}
	p.Facts = []FactRecord{r}
	a, err := EncodeFactPage(p)
	if err != nil {
		t.Fatal(err)
	}
	p.PageNo = 1
	p.Facts = []FactRecord{r2}
	b, err := EncodeFactPage(p)
	if err != nil {
		t.Fatal(err)
	}
	pa, _ := DecodeFactPage(a)
	pb, _ := DecodeFactPage(b)
	dig, _ := SnapshotDigest(1, 1, [][32]byte{pa.PageDigest, pb.PageDigest})
	sum := FactSummary{FactProtocolVersion, 1, r.Envelope.NetworkID, 1, 2, 2, dig}
	if err := ValidateSnapshot(sum, []FactPage{pa, pb}); err != nil {
		t.Fatal(err)
	}
	pb.Facts = []FactRecord{r}
	b, err = EncodeFactPage(pb)
	if err != nil {
		t.Fatal(err)
	}
	pb, _ = DecodeFactPage(b)
	sum.Digest, _ = SnapshotDigest(1, 1, [][32]byte{pa.PageDigest, pb.PageDigest})
	if err := ValidateSnapshot(sum, []FactPage{pa, pb}); err == nil {
		t.Fatal("cross-page duplicate accepted")
	}
	emptyDigest, err := SnapshotDigest(1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(emptyDigest[:]) != "af76f677f767810a74f24a476518b5f918abf6e63f35103e6b8306dc47ad92d4" {
		t.Fatal("empty snapshot digest mismatch")
	}
	empty := FactSummary{FactProtocolVersion, 1, r.Envelope.NetworkID, 1, 0, 0, emptyDigest}
	if err := ValidateSnapshot(empty, nil); err != nil {
		t.Fatal(err)
	}
	for _, bytes := range [][]byte{nil, make([]byte, 64), make([]byte, 66)} {
		if _, err := DecodeFactSummary(bytes); err == nil {
			t.Fatal("summary size accepted")
		}
	}
	for _, bytes := range [][]byte{nil, make([]byte, 35), make([]byte, 37)} {
		if _, err := DecodeFactAck(bytes); err == nil {
			t.Fatal("ack size accepted")
		}
	}
}

// TestValidateFactToleratesPeerClockSkew covers peers whose clocks disagree. Two
// private networks joined over the internet routinely differ by minutes, and a fact that
// is dropped for looking "early" or "late" makes the overlay silently unreachable with no
// error anywhere.
//
// A fact's own IssuedAt/ExpiresAt stay absolute — the publisher writes them with its
// clock — so the receiver must judge freshness by the fact's declared lifetime rather
// than by comparing that clock against its own.
func TestValidateFactToleratesPeerClockSkew(t *testing.T) {
	for _, skew := range []time.Duration{
		-5 * time.Minute,
		5 * time.Minute,
		-1 * time.Hour,
		1 * time.Hour,
	} {
		t.Run(skew.String(), func(t *testing.T) {
			r := addressFixture()
			// The publisher's clock is `skew` ahead of the receiver's.
			publisherNow := factTestNow.Add(skew)
			r.Envelope.IssuedAt = uint64(publisherNow.UnixMilli())
			r.Envelope.ExpiresAt = r.Envelope.IssuedAt + 45_000 // the frozen publisher validity

			if err := ValidateFactForNetwork(r, r.Envelope.NetworkID); err != nil {
				t.Fatalf("peer clock off by %v: %v", skew, err)
			}
		})
	}
}
