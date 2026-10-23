package topology

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// The expected bytes below are assembled field-by-field from the confirmed
// FACT v2 layout in docs/domains/overlay/modules/topology-routing.md line 332
// and wire-protocol.md line 293/295, and independently cross-checked with a
// standalone Python/SHA-256 script. They never call the codec under test.

var (
	v2From = func() NodeID {
		var id NodeID
		for i := range id {
			id[i] = byte(i)
		}
		return id
	}()
	v2To = func() NodeID {
		var id NodeID
		for i := range id {
			id[i] = byte(0x10 + i)
		}
		return id
	}()
)

const (
	v2LinkTCPHex            = "003c02000102030405060708090a0b0c0d0e0f0029000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f021122334455667788000000000000000702000102030405060708090a0b0c0d0e0f0000000000000003000000000000000400000000000010000000000000002000000000004c1122334455667788000000000000000902000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000010000000200000003000000040000000500000003746370"
	v2LinkWebsocketHex      = "003c02000102030405060708090a0b0c0d0e0f0029000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f021122334455667788000000000000000702000102030405060708090a0b0c0d0e0f000000000000000300000000000000040000000000001000000000000000200000000000521122334455667788000000000000000902000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000010000000200000003000000040000000500000009776562736f636b6574"
	v2RevLinkHex            = "005d04000102030405060708090a0b0c0d0e0f004a000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f02000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f021122334455667788000000000000000704000102030405060708090a0b0c0d0e0f0000000000000007000000000000000800000000000030000000000000004000000000006c000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f020029000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0211223344556677880000000000000005000000000000000600000000000000070000000000000008"
	v2SummaryHex            = "0200000000000000010102030405060708000000000000000200000001000000014ab63254de9281149853e3359a09ec8360470e2bd5b19bfdb0a688565e761d29"
	v2AckHex                = "020000000000000001010203040506070800000000000000020000000003000000000000"
	v2AddrPageDigestHex     = "7acc055dd211076475fb0f1f5f1797aa9d8eb4005b37f789e2db1f59999c101a"
	v2AddrSnapshotDigestHex = "4ab63254de9281149853e3359a09ec8360470e2bd5b19bfdb0a688565e761d29"
	v2EmptySnapshotDigest   = "af76f677f767810a74f24a476518b5f918abf6e63f35103e6b8306dc47ad92d4"
)

const (
	v2LinkID  uint64 = 0x1122334455667788
	v2TestNet uint64 = 7
)

func v2LinkRecord(ctype string) FactRecord {
	return FactRecord{
		Envelope: FactEnvelope{NetworkID: v2TestNet, Kind: FactLink, Origin: v2From, Version: FactVersion{3, 4}, IssuedAt: 0x1000, ExpiresAt: 0x2000},
		Payload: LinkPayload{
			LinkID: v2LinkID, LinkEpoch: 9, LaneID: 2, From: v2From, To: v2To,
			Cost: LinkCost{1, 2, 3, 4, 5}, Capabilities: []string{}, ConnectionType: ctype,
		},
	}
}

func v2LinkTargetBytes() []byte {
	b := append([]byte{}, v2From[:]...)
	b = append(b, v2To[:]...)
	b = append(b, 2)
	return binary.BigEndian.AppendUint64(b, v2LinkID)
}

// v2LinkRecordBytes hand-builds the LINK record: key_len:u16 | Kind | Origin | target_key_len:u16 |
// From16|To16|Lane1|LinkID8 | Envelope | LinkID8|Epoch8|Lane1|From16|To16|5*u32|caps|TypeLen:u16|Type.
func v2LinkRecordBytes(ctype string) []byte {
	target := v2LinkTargetBytes()
	key := append([]byte{byte(FactLink)}, v2From[:]...)
	key = binary.BigEndian.AppendUint16(key, uint16(len(target)))
	key = append(key, target...)
	payload := binary.BigEndian.AppendUint64(nil, v2LinkID)
	payload = binary.BigEndian.AppendUint64(payload, 9)
	payload = append(payload, 2)
	payload = append(payload, v2From[:]...)
	payload = append(payload, v2To[:]...)
	for _, v := range []uint32{1, 2, 3, 4, 5} {
		payload = binary.BigEndian.AppendUint32(payload, v)
	}
	payload = binary.BigEndian.AppendUint16(payload, 0) // capability_count
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(ctype)))
	payload = append(payload, ctype...)

	rec := binary.BigEndian.AppendUint16(nil, uint16(len(key)))
	rec = append(rec, key...)
	rec = binary.BigEndian.AppendUint64(rec, v2TestNet)
	rec = append(rec, byte(FactLink))
	rec = append(rec, v2From[:]...)
	for _, v := range []uint64{3, 4, 0x1000, 0x2000} {
		rec = binary.BigEndian.AppendUint64(rec, v)
	}
	rec = append(rec, 0)
	rec = binary.BigEndian.AppendUint32(rec, uint32(len(payload)))
	return append(rec, payload...)
}

func TestFactV2LinkRecordsIndependentVectors(t *testing.T) {
	for _, tc := range []struct {
		ctype   string
		golden  string
		wantLen int
	}{
		{"tcp", v2LinkTCPHex, 200},
		{"websocket", v2LinkWebsocketHex, 206},
	} {
		rec := v2LinkRecord(tc.ctype)
		got, err := EncodeFactRecord(rec)
		if err != nil {
			t.Fatalf("%s: encode: %v", tc.ctype, err)
		}
		if hex.EncodeToString(got) != tc.golden {
			t.Fatalf("%s: record bytes differ from independent fixture:\n got %x\nwant %s", tc.ctype, got, tc.golden)
		}
		if hand := v2LinkRecordBytes(tc.ctype); !bytes.Equal(hand, got) {
			t.Fatalf("%s: hand-assembled spec layout differs", tc.ctype)
		}
		if len(got) != tc.wantLen {
			t.Fatalf("%s: len=%d want %d", tc.ctype, len(got), tc.wantLen)
		}
		target, err := DeriveTargetKey(FactLink, rec.Payload)
		if err != nil || len(target) != 41 || !bytes.Equal(target, v2LinkTargetBytes()) {
			t.Fatalf("%s: target=%x err=%v", tc.ctype, target, err)
		}
		if target == nil || binary.BigEndian.Uint64(target[33:41]) != v2LinkID {
			t.Fatalf("%s: target does not end in LinkID", tc.ctype)
		}
		decoded, err := DecodeFactRecord(got)
		if err != nil || !reflect.DeepEqual(decoded, rec) {
			t.Fatalf("%s: decode=%#v err=%v", tc.ctype, decoded, err)
		}
		if decoded.Payload.(LinkPayload).ConnectionType != tc.ctype {
			t.Fatalf("%s: Type not preserved", tc.ctype)
		}
	}
}

func TestFactV2RevocationIndependentVector(t *testing.T) {
	target := v2LinkTargetBytes()
	revTarget := append(append([]byte{}, v2From[:]...), v2From[:]...)
	revTarget = append(revTarget, byte(FactLink))
	revTarget = append(revTarget, target...)
	if len(revTarget) != MaxRevocationTarget {
		t.Fatalf("rev target len=%d want %d", len(revTarget), MaxRevocationTarget)
	}
	key := append([]byte{byte(FactRevocation)}, v2From[:]...)
	key = binary.BigEndian.AppendUint16(key, uint16(len(revTarget)))
	key = append(key, revTarget...)
	if len(key) != MaxFactKey {
		t.Fatalf("rev fact key len=%d want %d", len(key), MaxFactKey)
	}

	rec := FactRecord{
		Envelope: FactEnvelope{NetworkID: v2TestNet, Kind: FactRevocation, Origin: v2From, Version: FactVersion{7, 8}, IssuedAt: 0x3000, ExpiresAt: 0x4000},
		Payload: RevocationPayload{
			Revoker: v2From, TargetOrigin: v2From, TargetKind: FactLink, TargetKey: target,
			TargetVersion: FactVersion{5, 6}, TombstoneVersion: FactVersion{7, 8},
		},
	}
	got, err := EncodeFactRecord(rec)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if hex.EncodeToString(got) != v2RevLinkHex {
		t.Fatalf("revocation bytes differ from independent fixture:\n got %x\nwant %s", got, v2RevLinkHex)
	}
	decoded, err := DecodeFactRecord(got)
	if err != nil || !reflect.DeepEqual(decoded, rec) {
		t.Fatalf("decode=%#v err=%v", decoded, err)
	}
	if p := decoded.Payload.(RevocationPayload); len(p.TargetKey) != 41 || !bytes.Equal(p.TargetKey, target) {
		t.Fatalf("revoked target=%x", p.TargetKey)
	}

	// A padded REVOCATION must not be accepted just to reach the 4253 schema cap.
	padded := rec
	paddedPayload := rec.Payload.(RevocationPayload)
	paddedPayload.TargetKey = append(append([]byte{}, target...), 0) // 42B nested key
	padded.Payload = paddedPayload
	if _, err := EncodeFactRecord(padded); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("padded rev target accepted: %v", err)
	}
	// Raw decode with an inflated nested target_key_len (>41) is rejected.
	raw := append([]byte(nil), got...)
	lenOff := 2 + len(key) + FactEnvelopeSize + 16 + 16 + 1
	binary.BigEndian.PutUint16(raw[lenOff:lenOff+2], 74)
	if _, err := DecodeFactRecord(raw); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("inflated rev target length accepted: %v", err)
	}
	// Trailing padding after a legal REV is rejected, and 4253 stays the upper
	// bound rather than a padding target.
	if len(got) >= MaxFactRecord {
		t.Fatalf("legal rev record unexpectedly at cap: %d", len(got))
	}
	if _, err := DecodeFactRecord(append(append([]byte(nil), got...), 0)); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("trailing padded rev accepted: %v", err)
	}
}

func v2PageDigestDomain(domain string, inc, snap uint64, page uint32, count uint16, records []byte) [32]byte {
	b := []byte(domain)
	b = binary.BigEndian.AppendUint64(b, inc)
	b = binary.BigEndian.AppendUint64(b, snap)
	b = binary.BigEndian.AppendUint32(b, page)
	b = binary.BigEndian.AppendUint16(b, count)
	h := sha256.New()
	_, _ = h.Write(b)
	_, _ = h.Write(records)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func v2SnapshotDigestDomain(domain string, inc, snap uint64, pages [][32]byte) [32]byte {
	b := []byte(domain)
	b = binary.BigEndian.AppendUint64(b, inc)
	b = binary.BigEndian.AppendUint64(b, snap)
	b = binary.BigEndian.AppendUint32(b, uint32(len(pages)))
	h := sha256.New()
	_, _ = h.Write(b)
	for _, p := range pages {
		_, _ = h.Write(p[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func TestFactV2SyncContainerVectors(t *testing.T) {
	r := addressFixture()
	recordBytes, err := EncodeFactRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	pd := v2PageDigestDomain("simpletier-fact-page-v2", 1, 2, 0, 1, recordBytes)
	if hex.EncodeToString(pd[:]) != v2AddrPageDigestHex {
		t.Fatalf("independent page digest %x", pd)
	}
	sd := v2SnapshotDigestDomain("simpletier-fact-snapshot-v2", 1, 2, [][32]byte{pd})
	if hex.EncodeToString(sd[:]) != v2AddrSnapshotDigestHex {
		t.Fatalf("independent snapshot digest %x", sd)
	}

	summary := FactSummary{ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, NetworkID: r.Envelope.NetworkID, SnapshotVersion: 2, FactCount: 1, PageCount: 1, Digest: sd}
	sbytes, err := EncodeFactSummary(summary)
	if err != nil || hex.EncodeToString(sbytes) != v2SummaryHex {
		t.Fatalf("summary=%x err=%v", sbytes, err)
	}
	if got, err := DecodeFactSummary(sbytes); err != nil || got != summary {
		t.Fatalf("summary decode=%#v err=%v", got, err)
	}

	page := FactPage{ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, NetworkID: r.Envelope.NetworkID, SnapshotVersion: 2, PageNo: 0, PageCount: 1, Facts: []FactRecord{r}}
	pbytes, err := EncodeFactPage(page)
	if err != nil {
		t.Fatal(err)
	}
	if len(pbytes) != FactPageHeaderSize+len(recordBytes) {
		t.Fatalf("page len=%d", len(pbytes))
	}
	gotPage, err := DecodeFactPage(pbytes)
	if err != nil || gotPage.PageDigest != pd || !reflect.DeepEqual(gotPage.Facts, page.Facts) {
		t.Fatalf("page decode=%#v err=%v", gotPage, err)
	}

	ack := FactAck{ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, NetworkID: r.Envelope.NetworkID, SnapshotVersion: 2, PageNo: 0, Status: AckComplete}
	abytes, err := EncodeFactAck(ack)
	if err != nil || hex.EncodeToString(abytes) != v2AckHex {
		t.Fatalf("ack=%x err=%v", abytes, err)
	}
	if got, err := DecodeFactAck(abytes); err != nil || got != ack {
		t.Fatalf("ack decode=%#v err=%v", got, err)
	}

	// Version 1 is rejected with no downgrade on every sync container.
	for name, in := range map[string][]byte{
		"summary": append([]byte{1}, sbytes[1:]...),
		"page":    append([]byte{1}, pbytes[1:]...),
		"ack":     append([]byte{1}, abytes[1:]...),
	} {
		var err error
		switch name {
		case "summary":
			_, err = DecodeFactSummary(in)
		case "page":
			_, err = DecodeFactPage(in)
		case "ack":
			_, err = DecodeFactAck(in)
		}
		if !errors.Is(err, ErrFactMalformed) {
			t.Fatalf("v1 %s accepted: %v", name, err)
		}
	}

	// Old v1 digest domains are not silently reused: a v1-domain page digest is
	// rejected, and an empty snapshot summary carrying a v1-domain digest fails.
	v1pd := v2PageDigestDomain("simpletier-fact-page-v1", 1, 2, 0, 1, recordBytes)
	stalePage := append([]byte(nil), pbytes...)
	copy(stalePage[35:67], v1pd[:])
	if _, err := DecodeFactPage(stalePage); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("v1 page digest accepted: %v", err)
	}
	v1empty := v2SnapshotDigestDomain("simpletier-fact-snapshot-v1", 1, 1, nil)
	if _, err := EncodeFactSummary(FactSummary{ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, NetworkID: r.Envelope.NetworkID, SnapshotVersion: 1, FactCount: 0, PageCount: 0, Digest: v1empty}); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("v1 empty snapshot digest accepted: %v", err)
	}

	// Empty snapshot digest is independent of the codec.
	empty := v2SnapshotDigestDomain("simpletier-fact-snapshot-v2", 1, 1, nil)
	if hex.EncodeToString(empty[:]) != v2EmptySnapshotDigest {
		t.Fatalf("empty snapshot digest %x", empty)
	}
	if err := ValidateSnapshot(FactSummary{ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, NetworkID: r.Envelope.NetworkID, SnapshotVersion: 1, FactCount: 0, PageCount: 0, Digest: empty}, nil); err != nil {
		t.Fatalf("empty snapshot rejected: %v", err)
	}

	// Stale per-page digest inside a snapshot is rejected before commit.
	stale := page
	stale.PageDigest = v1pd
	staleSummary := FactSummary{ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, NetworkID: r.Envelope.NetworkID, SnapshotVersion: 2, FactCount: 1, PageCount: 1, Digest: sd}
	if err := ValidateSnapshot(staleSummary, []FactPage{stale}); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("stale page digest committed: %v", err)
	}
}

func TestFactV2LinkTypeBoundaries(t *testing.T) {
	// Literal Type bytes are transmitted verbatim: no trim, case-fold or
	// normalization, and arbitrary descriptive values stay legal.
	for _, ctype := range []string{"tcp", "websocket", " TCP ", "WebSocket", "custom-link-type"} {
		rec := v2LinkRecord(ctype)
		data, err := EncodeFactRecord(rec)
		if err != nil {
			t.Fatalf("%q encode: %v", ctype, err)
		}
		if !bytes.Contains(data, []byte(ctype)) {
			t.Fatalf("%q not transmitted literally", ctype)
		}
		decoded, err := DecodeFactRecord(data)
		if err != nil {
			t.Fatalf("%q decode: %v", ctype, err)
		}
		if got := decoded.Payload.(LinkPayload).ConnectionType; got != ctype {
			t.Fatalf("Type %q normalized to %q", ctype, got)
		}
	}

	for name, ctype := range map[string]string{
		"empty":       "",
		"invalidUtf8": string([]byte{0xff, 0xfe}),
		"NUL":         "tc\x00p",
	} {
		rec := v2LinkRecord(ctype)
		if _, err := EncodeFactRecord(rec); !errors.Is(err, ErrFactMalformed) {
			t.Fatalf("%s Type accepted: %v", name, err)
		}
	}

	// Payload exactly 4096 is accepted; the +1 byte is rejected and the record
	// still fits MaxFactRecord.
	const base = 8 + 8 + 1 + 16 + 16 + 5*4 + 2 + 2
	rec := v2LinkRecord(strings.Repeat("a", MaxFactPayload-base))
	data, err := EncodeFactRecord(rec)
	if err != nil {
		t.Fatalf("4096 payload rejected: %v", err)
	}
	if len(data) > MaxFactRecord {
		t.Fatalf("record %d exceeds %d", len(data), MaxFactRecord)
	}
	if _, err := DecodeFactRecord(data); err != nil {
		t.Fatalf("4096 payload decode: %v", err)
	}
	if _, err := EncodeFactRecord(v2LinkRecord(strings.Repeat("a", MaxFactPayload-base+1))); !errors.Is(err, ErrFactTooLarge) {
		t.Fatalf("4097 payload accepted: %v", err)
	}

	// Truncation anywhere, including the Type tail, and trailing bytes reject.
	base2, err := EncodeFactRecord(v2LinkRecord("tcp"))
	if err != nil {
		t.Fatal(err)
	}
	for cut := 0; cut < len(base2); cut++ {
		if _, err := DecodeFactRecord(base2[:cut]); err == nil {
			t.Fatalf("accepted truncated link record at %d", cut)
		}
	}
	if _, err := DecodeFactRecord(append(append([]byte(nil), base2...), 0)); err == nil {
		t.Fatal("accepted trailing byte after link record")
	}
	// TypeLen larger than the remainder is rejected.
	short := append([]byte(nil), base2...)
	short[len(short)-4] = 0x7f
	if _, err := DecodeFactRecord(short); err == nil {
		t.Fatal("accepted oversized TypeLen")
	}
}

func TestFactV2LinkInstanceKeyIndependence(t *testing.T) {
	linkA := v2LinkRecord("tcp")
	linkB := v2LinkRecord("tcp")
	pb := linkB.Payload.(LinkPayload)
	pb.LinkID = v2LinkID + 1
	linkB.Payload = pb

	keyA, err := DeriveTargetKey(FactLink, linkA.Payload)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := DeriveTargetKey(FactLink, linkB.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keyA, keyB) {
		t.Fatal("distinct LinkIDs on same From/To/Lane share a key")
	}
	fa, _ := FactKey(linkA)
	fb, _ := FactKey(linkB)
	if bytes.Equal(fa, fb) || bytes.Compare(fa, fb) >= 0 {
		t.Fatalf("FactKey order/independence broken: %x vs %x", fa, fb)
	}
	// ConnectionType is descriptive metadata, not part of the instance key.
	typed := v2LinkRecord("websocket")
	if key, _ := DeriveTargetKey(FactLink, typed.Payload); !bytes.Equal(key, keyA) {
		t.Fatal("ConnectionType changed the instance key")
	}

	// A REVOCATION carries exactly the targeted instance key.
	rev := FactRecord{
		Envelope: FactEnvelope{NetworkID: v2TestNet, Kind: FactRevocation, Origin: v2From, Version: FactVersion{9, 9}, IssuedAt: 0x1000, ExpiresAt: 0x2000},
		Payload: RevocationPayload{
			Revoker: v2From, TargetOrigin: v2From, TargetKind: FactLink, TargetKey: keyA,
			TargetVersion: FactVersion{3, 4}, TombstoneVersion: FactVersion{9, 9},
		},
	}
	data, err := EncodeFactRecord(rev)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeFactRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	got := decoded.Payload.(RevocationPayload).TargetKey
	if !bytes.Equal(got, keyA) {
		t.Fatalf("revocation target %x want %x", got, keyA)
	}
	if bytes.Equal(got, keyB) {
		t.Fatal("revocation leaked onto a different LinkID")
	}
}

func TestFactV2SchemaLimitsUnchanged(t *testing.T) {
	if FactProtocolVersion != 2 || MaxFactPayload != 4096 || MaxFactKey != 93 || MaxFactRecord != 4253 ||
		MaxPageRecords != 128 || MaxPageBytes != 48*1024 || MaxSnapshotRecords != 8192 ||
		MaxSnapshotPages != 64 || MaxSnapshotBytes != 3*1024*1024 ||
		FactSummarySize != 65 || FactPageHeaderSize != 67 || FactAckSize != 36 ||
		MaxRevocationTarget != 74 || MaxRevocationTargetKey != 41 {
		t.Fatal("FACT v2 schema bounds changed")
	}

	// A page at the 128-record maximum is accepted; 129 is rejected.
	id := v2From
	env := FactEnvelope{NetworkID: v2TestNet, Kind: FactAddress, Origin: id, Version: FactVersion{1, 1}, IssuedAt: 0x1000, ExpiresAt: 0x2000}
	facts := func(n int) []FactRecord {
		out := make([]FactRecord, 0, n)
		for i := 0; i < n; i++ {
			ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
			out = append(out, FactRecord{Envelope: env, Payload: AddressPayload{NodeID: id, IP: ip, PrefixLen: 32}})
		}
		return out
	}
	page := FactPage{ProtocolVersion: FactProtocolVersion, SenderIncarnation: 1, NetworkID: v2TestNet, SnapshotVersion: 1, PageCount: 1, Facts: facts(MaxPageRecords)}
	data, err := EncodeFactPage(page)
	if err != nil {
		t.Fatalf("128 records rejected: %v", err)
	}
	if _, err := DecodeFactPage(data); err != nil {
		t.Fatalf("128-record page decode: %v", err)
	}
	page.Facts = facts(MaxPageRecords + 1)
	if _, err := EncodeFactPage(page); !errors.Is(err, ErrFactTooLarge) {
		t.Fatalf("129 records accepted: %v", err)
	}

	// Exactly the page byte budget is not "too large"; +1 is.
	if _, err := DecodeFactPage(make([]byte, FactPageHeaderSize+MaxPageBytes)); errors.Is(err, ErrFactTooLarge) {
		t.Fatal("48KiB page budget treated as exceeded")
	}
	if _, err := DecodeFactPage(make([]byte, FactPageHeaderSize+MaxPageBytes+1)); !errors.Is(err, ErrFactTooLarge) {
		t.Fatal("48KiB+1 page accepted")
	}
	// Snapshot page/size budgets stay fixed.
	if _, err := SnapshotDigest(1, 1, make([][32]byte, MaxSnapshotPages)); err != nil {
		t.Fatalf("64 pages rejected: %v", err)
	}
	if _, err := SnapshotDigest(1, 1, make([][32]byte, MaxSnapshotPages+1)); !errors.Is(err, ErrFactTooLarge) {
		t.Fatal("65 pages accepted")
	}
}
