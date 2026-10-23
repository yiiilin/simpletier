package topology

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/security"
)

// These tests use the real OpenIdentityStore/OpenNetworkState on a temp filesystem
// with fixed private keys. Peer identities are derived exactly like the security
// package derives them (SHA256 of the X25519 public key). No authentication is
// faked: the tests only exercise the trusted-caller shape of FactSource.

const factTestWireID uint64 = 0x1122334455667788

var (
	factTestContextA = func() [32]byte {
		var context [32]byte
		for index := range context {
			context[index] = byte(index + 1)
		}
		return context
	}()
	factTestContextB = func() [32]byte {
		var context [32]byte
		for index := range context {
			context[index] = byte(index + 101)
		}
		return context
	}()

	factTestIssued  uint64 = 1_700_000_000_000
	factTestExpires        = factTestIssued + 45_000
	factTestNow            = time.UnixMilli(int64(factTestIssued + 1_000))
)

type factTestEnv struct {
	t          *testing.T
	dir        string
	contextID  [32]byte
	privateKey [32]byte
	localNode  NodeID
	store      *security.IdentityStore
	state      *security.NetworkState
	fs         *FactStore
}

func factTestKey(label string) [32]byte {
	return sha256.Sum256([]byte("simpletier-fact-store-test/" + label))
}

func factTestLocalPublic(privateKey [32]byte) [32]byte {
	private, err := ecdh.X25519().NewPrivateKey(privateKey[:])
	if err != nil {
		panic(err)
	}
	var public [32]byte
	copy(public[:], private.PublicKey().Bytes())
	return public
}

func factTestLocalNode(privateKey [32]byte) NodeID {
	public := factTestLocalPublic(privateKey)
	digest := sha256.Sum256(public[:])
	var node NodeID
	copy(node[:], digest[:16])
	return node
}

func factTestWriteIdentity(t *testing.T, dir string, privateKey [32]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create state dir: %v", err)
	}
	// t.TempDir may hand back a 0755 directory; the identity store requires an
	// owner-private 0700 state directory.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("secure state dir: %v", err)
	}
	path := filepath.Join(dir, "identity.key")
	if _, err := os.Stat(path); err == nil {
		return
	}
	record := make([]byte, 40)
	copy(record[0:4], "STID")
	record[4] = 1
	record[5] = 1
	copy(record[8:], privateKey[:])
	if err := os.WriteFile(path, record, 0o600); err != nil {
		t.Fatalf("write fixed identity: %v", err)
	}
}

func factTestOpenState(t *testing.T, dir string, contextID [32]byte, privateKey [32]byte) (*security.IdentityStore, *security.NetworkState) {
	t.Helper()
	store, err := security.NewIdentityStoreForTest(privateKey)
	if err != nil {
		t.Fatalf("open identity store: %v", err)
	}
	state, err := security.OpenNetworkState(store, contextID)
	if err != nil {
		_ = store.Close()
		t.Fatalf("open network state: %v", err)
	}
	return store, state
}

func newFactTestEnv(t *testing.T, dir string, contextID [32]byte, privateKey [32]byte) *factTestEnv {
	t.Helper()
	store, state := factTestOpenState(t, dir, contextID, privateKey)
	fs, err := NewFactStore(state, factTestWireID)
	if err != nil {
		_ = state.Close()
		_ = store.Close()
		t.Fatalf("new fact store: %v", err)
	}
	env := &factTestEnv{
		t:          t,
		dir:        dir,
		contextID:  contextID,
		privateKey: privateKey,
		localNode:  factTestLocalNode(privateKey),
		store:      store,
		state:      state,
		fs:         fs,
	}
	t.Cleanup(env.close)
	return env
}

func (env *factTestEnv) close() {
	if env.state != nil {
		_ = env.state.Close()
	}
	if env.store != nil {
		_ = env.store.Close()
	}
}

func (env *factTestEnv) reopen() *factTestEnv {
	env.close()
	return newFactTestEnv(env.t, env.dir, env.contextID, env.privateKey)
}

func factTestContextDir(dir string, contextID [32]byte) string {
	return filepath.Join(dir, "network-state", hex.EncodeToString(contextID[:]))
}

func factTestWatermarksPath(dir string, contextID [32]byte) string {
	return filepath.Join(factTestContextDir(dir, contextID), "fact-watermarks")
}

func factTestPeerStatic(peerSeed uint64) [32]byte {
	var static [32]byte
	binary.BigEndian.PutUint64(static[0:8], peerSeed)
	static[8] = 0x5A
	static[16] = 0xAB
	static[24] = 0xC3
	return static
}

func factTestSourceForStatic(static [32]byte, contextID [32]byte, linkID, epoch uint64) FactSource {
	digest := sha256.Sum256(static[:])
	var peer NodeID
	copy(peer[:], digest[:16])
	return FactSource{
		ContextID:         contextID,
		AuthenticatedPeer: peer,
		PeerStatic:        static,
		LinkID:            linkID,
		Epoch:             epoch,
		LaneID:            FactLaneControl,
	}
}

func factTestSource(contextID [32]byte, linkID, epoch uint64) FactSource {
	return factTestSourceForStatic(factTestPeerStatic(linkID), contextID, linkID, epoch)
}

func factTestPub(seed uint64) [32]byte {
	var public [32]byte
	binary.BigEndian.PutUint64(public[0:8], seed)
	binary.BigEndian.PutUint64(public[8:16], seed*2+1)
	binary.BigEndian.PutUint64(public[16:24], seed*3+7)
	binary.BigEndian.PutUint64(public[24:32], seed*5+11)
	return public
}

func factTestNodeID(public [32]byte) NodeID {
	digest := sha256.Sum256(public[:])
	var node NodeID
	copy(node[:], digest[:16])
	return node
}

func factTestNodeRecord(public [32]byte, capabilities []string, version FactVersion, issuedAt, expiresAt uint64) FactRecord {
	node := factTestNodeID(public)
	return FactRecord{
		Envelope: FactEnvelope{NetworkID: factTestWireID, Kind: FactNode, Origin: node, Version: version, IssuedAt: issuedAt, ExpiresAt: expiresAt},
		Payload:  NodePayload{NodeID: node, StaticPublicKey: public, Capabilities: capabilities},
	}
}

func factTestLinkRecord(from, to NodeID, linkID, epoch uint64, lane uint8, connectionType string, version FactVersion, issuedAt, expiresAt uint64) FactRecord {
	return FactRecord{
		Envelope: FactEnvelope{NetworkID: factTestWireID, Kind: FactLink, Origin: from, Version: version, IssuedAt: issuedAt, ExpiresAt: expiresAt},
		Payload: LinkPayload{
			LinkID: linkID, LinkEpoch: epoch, LaneID: lane, From: from, To: to,
			Cost: LinkCost{}, Capabilities: []string{}, ConnectionType: connectionType,
		},
	}
}

func factTestLinkTarget(from, to NodeID, lane uint8, linkID uint64) []byte {
	target := append([]byte(nil), from[:]...)
	target = append(target, to[:]...)
	target = append(target, lane)
	return binary.BigEndian.AppendUint64(target, linkID)
}

func factTestRevocationRecord(revoker, targetOrigin NodeID, targetKind FactKind, targetKey []byte, targetVersion, tombstoneVersion FactVersion, issuedAt, expiresAt uint64) FactRecord {
	return FactRecord{
		Envelope: FactEnvelope{NetworkID: factTestWireID, Kind: FactRevocation, Origin: revoker, Version: tombstoneVersion, IssuedAt: issuedAt, ExpiresAt: expiresAt},
		Payload: RevocationPayload{
			Revoker: revoker, TargetOrigin: targetOrigin, TargetKind: targetKind, TargetKey: targetKey,
			TargetVersion: targetVersion, TombstoneVersion: tombstoneVersion,
		},
	}
}

func factTestFactKey(t *testing.T, record FactRecord) []byte {
	t.Helper()
	key, err := FactKey(record)
	if err != nil {
		t.Fatalf("derive fact key: %v", err)
	}
	return key
}

func factTestChunk(t *testing.T, records []FactRecord) [][]FactRecord {
	t.Helper()
	var chunks [][]FactRecord
	var current []FactRecord
	currentBytes := 0
	for _, record := range records {
		canon, err := EncodeFactRecord(record)
		if err != nil {
			t.Fatalf("encode record for chunking: %v", err)
		}
		if len(current) == MaxPageRecords || currentBytes+len(canon) > MaxPageBytes {
			chunks = append(chunks, current)
			current = nil
			currentBytes = 0
		}
		current = append(current, record)
		currentBytes += len(canon)
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}
	return chunks
}

func factTestSnapshot(t *testing.T, netID, incarnation, snapshotVersion uint64, records []FactRecord) (FactSummary, []FactPage) {
	t.Helper()
	sorted := make([]FactRecord, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(factTestFactKey(t, sorted[i]), factTestFactKey(t, sorted[j])) < 0
	})
	chunks := factTestChunk(t, sorted)
	pages := make([]FactPage, 0, len(chunks))
	digests := make([][32]byte, 0, len(chunks))
	for number, chunk := range chunks {
		raw, err := EncodeFactPage(FactPage{
			ProtocolVersion: FactProtocolVersion, SenderIncarnation: incarnation, NetworkID: netID,
			SnapshotVersion: snapshotVersion, PageNo: uint32(number), PageCount: uint32(len(chunks)), Facts: chunk,
		})
		if err != nil {
			t.Fatalf("encode page: %v", err)
		}
		page, err := DecodeFactPage(raw)
		if err != nil {
			t.Fatalf("decode page: %v", err)
		}
		pages = append(pages, page)
		digests = append(digests, page.PageDigest)
	}
	digest, err := SnapshotDigest(incarnation, snapshotVersion, digests)
	if err != nil {
		t.Fatalf("snapshot digest: %v", err)
	}
	return FactSummary{
		ProtocolVersion: FactProtocolVersion, SenderIncarnation: incarnation, NetworkID: netID,
		SnapshotVersion: snapshotVersion, FactCount: uint32(len(sorted)), PageCount: uint32(len(chunks)), Digest: digest,
	}, pages
}

func factTestCommit(t *testing.T, fs *FactStore, incarnation, snapshotVersion uint64, source FactSource, records []FactRecord, now time.Time) error {
	t.Helper()
	summary, pages := factTestSnapshot(t, factTestWireID, incarnation, snapshotVersion, records)
	return fs.CommitSnapshot(source, summary, pages, now)
}

func TestFactStoreMalformedLastPageIsAtomic(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-a"))
	source := factTestSource(env.contextID, 1, 1)

	first := factTestNodeRecord(factTestPub(1), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, source, []FactRecord{first}, factTestNow); err != nil {
		t.Fatalf("commit first fact: %v", err)
	}
	if !env.fs.IsCurrent(factTestFactKey(t, first), first.Envelope.Version, factTestNow) {
		t.Fatal("first fact is not current after a valid commit")
	}

	records := make([]FactRecord, 0, 130)
	for index := 0; index < 130; index++ {
		records = append(records, factTestNodeRecord(factTestPub(uint64(100+index)), nil, FactVersion{2, uint64(index + 1)}, factTestIssued, factTestExpires))
	}
	summary, pages := factTestSnapshot(t, factTestWireID, 2, 2, records)
	if len(pages) < 2 {
		t.Fatalf("expected a multi-page snapshot, got %d pages", len(pages))
	}
	pages[len(pages)-1].PageDigest[0] ^= 0xff

	if err := env.fs.CommitSnapshot(source, summary, pages, factTestNow); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("malformed last page error = %v; want ErrFactMalformed", err)
	}
	for _, record := range records {
		if env.fs.IsCurrent(factTestFactKey(t, record), record.Envelope.Version, factTestNow) {
			t.Fatal("malformed snapshot was partially committed")
		}
	}
	if !env.fs.IsCurrent(factTestFactKey(t, first), first.Envelope.Version, factTestNow) {
		t.Fatal("previously committed fact changed after a rejected snapshot")
	}
	if visible, _, err := env.fs.Snapshot(factTestNow); err != nil || len(visible) != 1 {
		t.Fatalf("snapshot after rejected commit = %d records, %v; want 1, nil", len(visible), err)
	}
}

func TestFactStoreVersionOrderingNoRenewalAndExpiry(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-b"))
	public := factTestPub(2)
	record := factTestNodeRecord(public, nil, FactVersion{1, 5}, factTestIssued, factTestExpires)
	key := factTestFactKey(t, record)

	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1, 1), []FactRecord{record}, factTestNow); err != nil {
		t.Fatalf("commit v5: %v", err)
	}
	entry := env.fs.entries[string(key)]
	if entry == nil {
		t.Fatal("v5 entry missing")
	}
	expiryBefore := entry.expiresAt

	// Same version, identical canonical bytes from a second source: no-op plus a
	// new provenance source, and never a lifetime extension.
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 2, 1), []FactRecord{record}, factTestNow); err != nil {
		t.Fatalf("re-commit identical v5: %v", err)
	}
	entry = env.fs.entries[string(key)]
	if entry.expiresAt != expiryBefore {
		t.Fatalf("expiry was renewed: %d -> %d", expiryBefore, entry.expiresAt)
	}
	if len(entry.sources) != 2 {
		t.Fatalf("identical re-commit did not retain the second provenance source: %d", len(entry.sources))
	}

	// Older version is discarded.
	older := factTestNodeRecord(public, nil, FactVersion{1, 2}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 3, 1), []FactRecord{older}, factTestNow); err != nil {
		t.Fatalf("commit older v2: %v", err)
	}
	if !env.fs.IsCurrent(key, FactVersion{1, 5}, factTestNow) || env.fs.IsCurrent(key, FactVersion{1, 2}, factTestNow) {
		t.Fatal("older version replaced the newer current fact")
	}

	// Higher incarnation replaces the same key.
	newer := factTestNodeRecord(public, nil, FactVersion{2, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 2, 1, factTestSource(env.contextID, 4, 1), []FactRecord{newer}, factTestNow); err != nil {
		t.Fatalf("commit higher incarnation: %v", err)
	}
	if !env.fs.IsCurrent(key, FactVersion{2, 1}, factTestNow) {
		t.Fatal("higher incarnation did not become current")
	}
	if env.fs.IsCurrent(key, FactVersion{1, 5}, factTestNow) {
		t.Fatal("older version is still reported current")
	}

	// Expired same version cannot be revived: a replayed record fails admission
	// once it is past expires+30s, and the store stops reporting it.
	expiring := factTestNodeRecord(factTestPub(3), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	expiringKey := factTestFactKey(t, expiring)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 5, 1), []FactRecord{expiring}, factTestNow); err != nil {
		t.Fatalf("commit expiring fact: %v", err)
	}
	expiredNow := time.UnixMilli(int64(uint64(factTestNow.UnixMilli()) + (factTestExpires - factTestIssued) + 31_000))
	// A replay is refused by the version floor, not by comparing the record's timestamp
	// against the local clock, and a refused record is dropped silently — the snapshot
	// itself was well formed. What must hold is that it does not come back.
	if err := factTestCommit(t, env.fs, 1, 2, factTestSource(env.contextID, 6, 1), []FactRecord{expiring}, expiredNow); err != nil {
		t.Fatalf("commit expired replay: %v", err)
	}
	if env.fs.IsCurrent(expiringKey, FactVersion{1, 1}, expiredNow) {
		t.Fatal("expired same version was revived")
	}
	visible, _, err := env.fs.Snapshot(expiredNow)
	if err != nil {
		t.Fatalf("snapshot at expired time: %v", err)
	}
	for _, record := range visible {
		if bytes.Equal(factTestFactKey(t, record), expiringKey) {
			t.Fatal("expired fact is still visible")
		}
	}
}

func TestFactStoreEquivocationChoosesSmallestCanonicalBytes(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-c"))
	public := factTestPub(4)
	first := factTestNodeRecord(public, nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	second := factTestNodeRecord(public, []string{"relay"}, FactVersion{1, 1}, factTestIssued, factTestExpires)
	key := factTestFactKey(t, first)

	firstBytes, err := EncodeFactRecord(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := EncodeFactRecord(second)
	if err != nil {
		t.Fatal(err)
	}
	winnerBytes, loser := firstBytes, second
	if bytes.Compare(secondBytes, firstBytes) < 0 {
		winnerBytes, loser = secondBytes, first
	}

	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1, 1), []FactRecord{first}, factTestNow); err != nil {
		t.Fatalf("commit first variant: %v", err)
	}
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 2, 1), []FactRecord{second}, factTestNow); err != nil {
		t.Fatalf("commit equivocating variant: %v", err)
	}
	entry := env.fs.entries[string(key)]
	if entry == nil || !bytes.Equal(entry.canon, winnerBytes) {
		t.Fatal("equivocation did not converge on the smallest canonical bytes")
	}
	if env.fs.Equivocations() != 1 {
		t.Fatalf("equivocation count = %d; want 1", env.fs.Equivocations())
	}
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 3, 1), []FactRecord{loser}, factTestNow); err != nil {
		t.Fatalf("re-commit loser: %v", err)
	}
	entry = env.fs.entries[string(key)]
	if !bytes.Equal(entry.canon, winnerBytes) {
		t.Fatal("loser bytes replaced the deterministic winner")
	}
	if env.fs.Equivocations() != 2 {
		t.Fatalf("equivocation count = %d; want 2", env.fs.Equivocations())
	}
}

func TestFactStoreRevocationSuppressesOnlyTargetInstance(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-d"))
	from := factTestNodeID(factTestPub(20))
	to := factTestNodeID(factTestPub(21))
	revoker := factTestNodeID(factTestPub(22))

	linkOne := factTestLinkRecord(from, to, 7, 1, FactLanePacket, "tcp", FactVersion{1, 1}, factTestIssued, factTestExpires)
	linkTwo := factTestLinkRecord(from, to, 8, 1, FactLanePacket, "tcp", FactVersion{1, 2}, factTestIssued, factTestExpires)
	oneKey := factTestFactKey(t, linkOne)
	twoKey := factTestFactKey(t, linkTwo)

	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1, 1), []FactRecord{linkOne, linkTwo}, factTestNow); err != nil {
		t.Fatalf("commit links: %v", err)
	}
	revocation := factTestRevocationRecord(revoker, from, FactLink, factTestLinkTarget(from, to, FactLanePacket, 7), FactVersion{1, 1}, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 2, 1), []FactRecord{revocation}, factTestNow); err != nil {
		t.Fatalf("commit revocation: %v", err)
	}
	if env.fs.IsCurrent(oneKey, FactVersion{1, 1}, factTestNow) {
		t.Fatal("revoked LINK instance is still current")
	}
	if !env.fs.IsCurrent(twoKey, FactVersion{1, 2}, factTestNow) {
		t.Fatal("revoking one LinkID suppressed a different LinkID")
	}

	visible, _, err := env.fs.Snapshot(factTestNow)
	if err != nil {
		t.Fatalf("snapshot with revocation: %v", err)
	}
	revocationKey := factTestFactKey(t, revocation)
	found := false
	for _, record := range visible {
		if bytes.Equal(factTestFactKey(t, record), revocationKey) {
			found = true
		}
	}
	if !found {
		t.Fatal("snapshot does not advertise the live revocation fact")
	}

	// A higher target version recovers the same instance.
	recovered := factTestLinkRecord(from, to, 7, 2, FactLanePacket, "tcp", FactVersion{1, 5}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 3, 1), []FactRecord{recovered}, factTestNow); err != nil {
		t.Fatalf("commit recovered link: %v", err)
	}
	if !env.fs.IsCurrent(oneKey, FactVersion{1, 5}, factTestNow) {
		t.Fatal("higher target version did not recover the revoked instance")
	}
	// A version at or below the tombstone floor never comes back, and it must not
	// disturb the recovered current version.
	stale := factTestLinkRecord(from, to, 7, 3, FactLanePacket, "tcp", FactVersion{1, 2}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 4, 1), []FactRecord{stale}, factTestNow); err != nil {
		t.Fatalf("commit stale link: %v", err)
	}
	if env.fs.IsCurrent(oneKey, FactVersion{1, 2}, factTestNow) || !env.fs.IsCurrent(oneKey, FactVersion{1, 5}, factTestNow) {
		t.Fatal("stale revoked version disturbed the recovered current fact")
	}
	if !env.fs.IsCurrent(twoKey, FactVersion{1, 2}, factTestNow) {
		t.Fatal("other LinkID was affected by an unrelated revocation")
	}
}

func TestFactStoreSaturationRetainsUntilExpiry(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-e"))
	record := factTestNodeRecord(factTestPub(30), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	key := factTestFactKey(t, record)
	static := factTestPeerStatic(0x77)

	sources := make([]FactSource, 0, maxFactSources+1)
	for index := 0; index <= maxFactSources; index++ {
		source := factTestSourceForStatic(static, env.contextID, uint64(index+1), 1)
		sources = append(sources, source)
		if err := factTestCommit(t, env.fs, 1, uint64(index+1), source, []FactRecord{record}, factTestNow); err != nil {
			t.Fatalf("commit from source %d: %v", index, err)
		}
	}
	entry := env.fs.entries[string(key)]
	if entry == nil {
		t.Fatal("saturated fact missing")
	}
	if len(entry.sources) != maxFactSources || !entry.saturated {
		t.Fatalf("saturation = %d sources, saturated=%v; want %d, true", len(entry.sources), entry.saturated, maxFactSources)
	}

	for _, source := range sources {
		if err := env.fs.WithdrawSource(source, factTestNow); err != nil {
			t.Fatalf("withdraw source: %v", err)
		}
	}
	entry = env.fs.entries[string(key)]
	if entry == nil {
		t.Fatal("saturated fact was withdrawn when its exact sources closed")
	}
	if !env.fs.IsCurrent(key, FactVersion{1, 1}, factTestNow) {
		t.Fatal("saturated fact is not current before its original expiry")
	}

	// Expiry is anchored to this node's commit time plus the declared lifetime, so it does
	// not depend on the publisher's clock agreeing with this one.
	expiredNow := time.UnixMilli(int64(uint64(factTestNow.UnixMilli()) + (factTestExpires - factTestIssued) + 31_000))
	if env.fs.IsCurrent(key, FactVersion{1, 1}, expiredNow) {
		t.Fatal("saturated fact outlived its declared lifetime plus skew")
	}
	if visible, _, err := env.fs.Snapshot(expiredNow); err != nil || len(visible) != 0 {
		t.Fatalf("snapshot after saturation expiry = %d records, %v; want 0, nil", len(visible), err)
	}
}

func TestFactStoreSnapshotReplacesOnlyIngressProvenance(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-f"))
	record := factTestNodeRecord(factTestPub(31), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	key := factTestFactKey(t, record)
	sourceA := factTestSource(env.contextID, 11, 1)
	sourceB := factTestSource(env.contextID, 12, 1)

	if err := factTestCommit(t, env.fs, 1, 1, sourceA, []FactRecord{record}, factTestNow); err != nil {
		t.Fatalf("commit A: %v", err)
	}
	if err := factTestCommit(t, env.fs, 1, 1, sourceB, []FactRecord{record}, factTestNow); err != nil {
		t.Fatalf("commit B: %v", err)
	}
	if len(env.fs.entries[string(key)].sources) != 2 {
		t.Fatal("expected two provenance sources")
	}

	// A's complete snapshot no longer carries the key: only A's provenance goes.
	if err := factTestCommit(t, env.fs, 1, 2, sourceA, nil, factTestNow); err != nil {
		t.Fatalf("empty snapshot from A: %v", err)
	}
	entry := env.fs.entries[string(key)]
	if entry == nil || len(entry.sources) != 1 || entry.sources[0] != sourceB {
		t.Fatalf("source replacement removed the wrong provenance: %+v", entry)
	}
	if !env.fs.IsCurrent(key, FactVersion{1, 1}, factTestNow) {
		t.Fatal("fact was withdrawn while another source still relays it")
	}

	// B's complete snapshot no longer carries the key either: no sources and not
	// saturated, so the fact becomes Withdrawn.
	if err := factTestCommit(t, env.fs, 1, 2, sourceB, nil, factTestNow); err != nil {
		t.Fatalf("empty snapshot from B: %v", err)
	}
	if _, present := env.fs.entries[string(key)]; present {
		t.Fatal("fact with no source and no saturation was not withdrawn")
	}
	if env.fs.IsCurrent(key, FactVersion{1, 1}, factTestNow) {
		t.Fatal("withdrawn fact is still current")
	}
}

func TestFactStoreAllowsRelayedOriginDifferentFromIngress(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-g"))
	source := factTestSource(env.contextID, 21, 1)
	relayed := factTestNodeRecord(factTestPub(40), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if bytes.Equal(relayed.Envelope.Origin[:], source.AuthenticatedPeer[:]) {
		t.Fatal("test setup: relayed origin equals the ingress peer")
	}
	if err := factTestCommit(t, env.fs, 1, 1, source, []FactRecord{relayed}, factTestNow); err != nil {
		t.Fatalf("relayed fact from a different origin was rejected: %v", err)
	}
	if !env.fs.IsCurrent(factTestFactKey(t, relayed), relayed.Envelope.Version, factTestNow) {
		t.Fatal("relayed fact is not current")
	}
}

func TestFactStoreRejectsUnboundFactSource(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-h"))
	record := factTestNodeRecord(factTestPub(50), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	good := factTestSource(env.contextID, 31, 1)

	variants := map[string]FactSource{"ok": good}
	wrongContext := good
	wrongContext.ContextID = factTestContextB
	variants["context"] = wrongContext
	zeroLink := good
	zeroLink.LinkID = 0
	variants["zero-link"] = zeroLink
	zeroEpoch := good
	zeroEpoch.Epoch = 0
	variants["zero-epoch"] = zeroEpoch
	dataLane := good
	dataLane.LaneID = FactLanePacket
	variants["data-lane"] = dataLane
	unboundPeer := good
	unboundPeer.AuthenticatedPeer[0] ^= 0xff
	variants["unbound-peer"] = unboundPeer

	summary, pages := factTestSnapshot(t, factTestWireID, 1, 1, []FactRecord{record})
	for name, source := range variants {
		err := env.fs.CommitSnapshot(source, summary, pages, factTestNow)
		if name == "ok" {
			if err != nil {
				t.Fatalf("valid source rejected: %v", err)
			}
			continue
		}
		if !errors.Is(err, ErrFactMalformed) {
			t.Fatalf("source %q error = %v; want ErrFactMalformed", name, err)
		}
	}
	if visible, _, err := env.fs.Snapshot(factTestNow); err != nil || len(visible) != 1 {
		t.Fatalf("rejected source changed the store: %d records, %v", len(visible), err)
	}
}

func TestFactStorePublishLocalAndForeignWithdraw(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-j"))
	localRecord := factTestNodeRecord(factTestLocalPublic(env.privateKey), nil, FactVersion{2, 1}, factTestIssued, factTestExpires)
	key := factTestFactKey(t, localRecord)

	if err := env.fs.PublishLocal([]FactRecord{localRecord}, factTestNow); err != nil {
		t.Fatalf("publish local: %v", err)
	}
	if !env.fs.IsCurrent(key, localRecord.Envelope.Version, factTestNow) {
		t.Fatal("local fact is not current")
	}
	if err := env.fs.WithdrawSource(factTestSource(env.contextID, 51, 1), factTestNow); err != nil {
		t.Fatalf("withdraw foreign source: %v", err)
	}
	if !env.fs.IsCurrent(key, localRecord.Envelope.Version, factTestNow) {
		t.Fatal("a foreign source withdrawal removed a local fact")
	}
	foreign := factTestNodeRecord(factTestPub(70), nil, FactVersion{2, 2}, factTestIssued, factTestExpires)
	if err := env.fs.PublishLocal([]FactRecord{foreign}, factTestNow); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("publish foreign origin error = %v; want ErrFactMalformed", err)
	}
}

// factTestLocalRecords builds the exact NODE, ADDRESS and initiator LINK records
// this node publishes for itself, so the local-ownership tests exercise the same
// three own-origin kinds the runtime advertises.
func factTestLocalRecords(env *factTestEnv, peer NodeID) (FactRecord, FactRecord, FactRecord) {
	node := factTestNodeRecord(factTestLocalPublic(env.privateKey), nil, FactVersion{2, 1}, factTestIssued, factTestExpires)
	address := FactRecord{
		Envelope: FactEnvelope{NetworkID: factTestWireID, Kind: FactAddress, Origin: env.localNode, Version: FactVersion{2, 2}, IssuedAt: factTestIssued, ExpiresAt: factTestExpires},
		Payload:  AddressPayload{NodeID: env.localNode, IP: netip.MustParseAddr("10.20.0.7"), PrefixLen: 32},
	}
	link := factTestLinkRecord(env.localNode, peer, 901, 1, FactLaneControl, "tcp", FactVersion{2, 3}, factTestIssued, factTestExpires)
	return node, address, link
}

func factTestLocalEntry(t *testing.T, env *factTestEnv, record FactRecord) *factEntry {
	t.Helper()
	return env.fs.entries[string(factTestFactKey(t, record))]
}

// TestFactStoreIngressCannotReplaceOrOwnLocalEntry covers the other two ways an
// ingress record can collide with a locally published key: a forged higher
// own-origin version and a same-version equivocation whose canonical bytes sort
// lower. Both snapshots are valid and must commit, but neither may replace the
// locally published bytes, clear the local flag or add a source that a later
// WithdrawSource could use to delete the fact.
func TestFactStoreIngressCannotReplaceOrOwnLocalEntry(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-ingress-local"))
	localNode, _, _ := factTestLocalRecords(env, factTestNodeID(factTestPub(910)))
	nodeKey := factTestFactKey(t, localNode)
	if err := env.fs.PublishLocal([]FactRecord{localNode}, factTestNow); err != nil {
		t.Fatalf("publish local: %v", err)
	}
	localCanon, err := EncodeFactRecord(localNode)
	if err != nil {
		t.Fatalf("encode local record: %v", err)
	}

	higher := localNode
	higher.Envelope.Version = FactVersion{2, 5}
	equivocation := localNode
	equivocation.Envelope.IssuedAt = factTestIssued - 1_000
	equivocation.Envelope.ExpiresAt = factTestExpires - 1_000
	equivocationCanon, err := EncodeFactRecord(equivocation)
	if err != nil {
		t.Fatalf("encode equivocation: %v", err)
	}
	if bytes.Compare(equivocationCanon, localCanon) >= 0 {
		t.Fatal("test setup: equivocation canonical bytes do not sort below the local record")
	}

	ingress := factTestSource(env.contextID, 911, 1)
	if err := factTestCommit(t, env.fs, 1, 1, ingress, []FactRecord{higher}, factTestNow); err != nil {
		t.Fatalf("commit higher own-origin version: %v", err)
	}
	if err := factTestCommit(t, env.fs, 1, 2, ingress, []FactRecord{equivocation}, factTestNow); err != nil {
		t.Fatalf("commit own-origin equivocation: %v", err)
	}

	entry := env.fs.entries[string(nodeKey)]
	if entry == nil || !entry.local || len(entry.sources) != 0 || entry.saturated {
		t.Fatalf("ingress changed local ownership: %+v", entry)
	}
	if compareFactVersion(entry.version, localNode.Envelope.Version) != 0 || !bytes.Equal(entry.canon, localCanon) {
		t.Fatalf("ingress replaced the locally published version/bytes: version %+v", entry.version)
	}
	if !env.fs.IsCurrent(nodeKey, localNode.Envelope.Version, factTestNow) {
		t.Fatal("locally published fact is not current after ingress collisions")
	}
	if env.fs.IsCurrent(nodeKey, higher.Envelope.Version, factTestNow) {
		t.Fatal("forged higher own-origin version became the current fact")
	}
	if visible, _, err := env.fs.Snapshot(factTestNow); err != nil || len(visible) != 1 || !bytes.Equal(visible[0].Envelope.Origin[:], env.localNode[:]) {
		t.Fatalf("snapshot after ingress collisions = %d records, %v", len(visible), err)
	}
	canon, err := EncodeFactRecord(mustFactTestSnapshotRecord(t, env.fs, factTestNow))
	if err != nil {
		t.Fatalf("encode snapshot record: %v", err)
	}
	if !bytes.Equal(canon, localCanon) {
		t.Fatal("snapshot served ingress bytes for a locally published fact")
	}

	if err := env.fs.WithdrawSource(ingress, factTestNow); err != nil {
		t.Fatalf("withdraw ingress: %v", err)
	}
	if !env.fs.IsCurrent(nodeKey, localNode.Envelope.Version, factTestNow) {
		t.Fatal("withdrawal removed a locally published fact after ingress collisions")
	}
}

// TestFactStoreLocalRefreshReclaimsIngressAdmittedOwnOriginFact covers the
// remaining collision: this node's own fact was first admitted as ordinary
// ingress provenance (the store had no entry and no floor yet), then the node
// itself publishes the very same fact. PublishLocal must reclaim ownership, so a
// later WithdrawSource of that ingress cannot delete the locally published fact.
func TestFactStoreLocalRefreshReclaimsIngressAdmittedOwnOriginFact(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-local-refresh"))
	localNode, _, _ := factTestLocalRecords(env, factTestNodeID(factTestPub(920)))
	nodeKey := factTestFactKey(t, localNode)
	ingress := factTestSource(env.contextID, 921, 1)

	if err := factTestCommit(t, env.fs, 1, 1, ingress, []FactRecord{localNode}, factTestNow); err != nil {
		t.Fatalf("commit relayed own-origin fact: %v", err)
	}
	setup := env.fs.entries[string(nodeKey)]
	if setup == nil || setup.local || len(setup.sources) != 1 {
		t.Fatalf("test setup: relayed own-origin fact not admitted as ingress: %+v", setup)
	}

	if err := env.fs.PublishLocal([]FactRecord{localNode}, factTestNow); err != nil {
		t.Fatalf("publish local refresh: %v", err)
	}
	entry := env.fs.entries[string(nodeKey)]
	if entry == nil || !entry.local || len(entry.sources) != 0 || entry.saturated {
		t.Fatalf("local refresh did not reclaim ownership: %+v", entry)
	}
	if err := env.fs.WithdrawSource(ingress, factTestNow); err != nil {
		t.Fatalf("withdraw ingress: %v", err)
	}
	if !env.fs.IsCurrent(nodeKey, localNode.Envelope.Version, factTestNow) {
		t.Fatal("withdrawal removed a locally refreshed fact")
	}
}

func mustFactTestSnapshotRecord(t *testing.T, fs *FactStore, now time.Time) FactRecord {
	t.Helper()
	visible, _, err := fs.Snapshot(now)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(visible) != 1 {
		t.Fatalf("snapshot returned %d records; want 1", len(visible))
	}
	return visible[0]
}

func TestFactStoreQuotaRejectionIsAtomic(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-l"))
	source := factTestSource(env.contextID, 71, 1)

	records := make([]FactRecord, 0, maxNodeFacts+1)
	for index := 0; index <= maxNodeFacts; index++ {
		records = append(records, factTestNodeRecord(factTestPub(uint64(1000+index)), nil, FactVersion{1, 1}, factTestIssued, factTestExpires))
	}
	if err := factTestCommit(t, env.fs, 1, 1, source, records, factTestNow); !errors.Is(err, ErrFactTooLarge) {
		t.Fatalf("over-quota snapshot error = %v; want ErrFactTooLarge", err)
	}
	if visible, _, err := env.fs.Snapshot(factTestNow); err != nil || len(visible) != 0 {
		t.Fatalf("over-quota snapshot left %d records, %v; want 0, nil", len(visible), err)
	}

	if err := factTestCommit(t, env.fs, 1, 1, source, records[:maxNodeFacts], factTestNow); err != nil {
		t.Fatalf("commit within quota: %v", err)
	}
	if visible, _, err := env.fs.Snapshot(factTestNow); err != nil || len(visible) != maxNodeFacts {
		t.Fatalf("within-quota snapshot has %d records, %v; want %d", len(visible), err, maxNodeFacts)
	}
	extra := records[maxNodeFacts]
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 72, 1), []FactRecord{extra}, factTestNow); !errors.Is(err, ErrFactTooLarge) {
		t.Fatalf("incremental over-quota error = %v; want ErrFactTooLarge", err)
	}
	if visible, _, err := env.fs.Snapshot(factTestNow); err != nil || len(visible) != maxNodeFacts {
		t.Fatalf("incremental over-quota left %d records, %v; want %d (no partial)", len(visible), err, maxNodeFacts)
	}
}

func TestFactStorePersistenceFailureIsSticky(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-m"))
	oldRecord := factTestNodeRecord(factTestPub(90), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 81, 1), []FactRecord{oldRecord}, factTestNow); err != nil {
		t.Fatalf("commit before failure: %v", err)
	}
	versionBefore := env.fs.Version()

	// Force the next record write to fail. State is in memory now, so the seam is a
	// refused write rather than an unusable path on disk.
	security.SetRecordWriteFailureForTest(t, true)

	newRecord := factTestNodeRecord(factTestPub(91), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	err := factTestCommit(t, env.fs, 1, 2, factTestSource(env.contextID, 82, 1), []FactRecord{newRecord}, factTestNow)
	if !errors.Is(err, ErrFactStoreFailed) {
		t.Fatalf("persistence failure error = %v; want ErrFactStoreFailed", err)
	}
	if !errors.Is(err, security.ErrInvalidNetworkState) {
		t.Fatalf("persistence failure does not wrap the real NetworkState error: %v", err)
	}
	if _, _, snapshotErr := env.fs.Snapshot(factTestNow); !errors.Is(snapshotErr, ErrFactStoreFailed) {
		t.Fatalf("query after persistence failure = %v; want explicit ErrFactStoreFailed", snapshotErr)
	}
	if env.fs.IsCurrent(factTestFactKey(t, newRecord), newRecord.Envelope.Version, factTestNow) {
		t.Fatal("unpersisted candidate was claimed committed")
	}
	if env.fs.Version() != versionBefore {
		t.Fatalf("view version advanced on a failed persist: %d -> %d", versionBefore, env.fs.Version())
	}
}

func TestFactStoreSnapshotOverThreeMiBErrors(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-n"))
	from := factTestNodeID(factTestPub(95))
	to := factTestNodeID(factTestPub(96))
	// 16 records per 48 KiB page times 64 pages keeps each commit just under the
	// 3 MiB snapshot bound, while the accumulated store is over it.
	connectionType := strings.Repeat("x", 2870)

	first := make([]FactRecord, 0, 1024)
	for index := 0; index < 1024; index++ {
		first = append(first, factTestLinkRecord(from, to, uint64(10000+index), 1, FactLanePacket, connectionType, FactVersion{1, 1}, factTestIssued, factTestExpires))
	}
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 91, 1), first, factTestNow); err != nil {
		t.Fatalf("commit first 3 MiB page set: %v", err)
	}
	second := make([]FactRecord, 0, 1024)
	for index := 0; index < 1024; index++ {
		second = append(second, factTestLinkRecord(from, to, uint64(20000+index), 1, FactLanePacket, connectionType, FactVersion{1, 1}, factTestIssued, factTestExpires))
	}
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 92, 1), second, factTestNow); err != nil {
		t.Fatalf("commit second 3 MiB page set: %v", err)
	}
	if _, _, err := env.fs.Snapshot(factTestNow); !errors.Is(err, ErrFactTooLarge) {
		t.Fatalf("oversized snapshot error = %v; want ErrFactTooLarge (never a truncated fake snapshot)", err)
	}
}

// factTestTargetTombstoneKey returns the aggregate-tombstone map key for one
// revoked fact key, matching tombstoneEntry identity (Kind|TargetOrigin|len|key).
func factTestTargetTombstoneKey(kind FactKind, origin NodeID, targetKey []byte) string {
	return string(targetFactKey(kind, origin, targetKey))
}

func factTestAddressRecord(origin NodeID, ip netip.Addr, version FactVersion, issuedAt, expiresAt uint64) FactRecord {
	return FactRecord{
		Envelope: FactEnvelope{NetworkID: factTestWireID, Kind: FactAddress, Origin: origin, Version: version, IssuedAt: issuedAt, ExpiresAt: expiresAt},
		Payload:  AddressPayload{NodeID: origin, IP: ip, PrefixLen: 32},
	}
}

func TestFactStoreMemoryAccountingIsConservative(t *testing.T) {
	// FactSource grew to 104 bytes (32+16+32+8+8+1 rounded to 8-byte alignment);
	// the old 64-byte estimate under-counts provenance by 40 bytes per slot.
	if factSourceStructBytes != 104 {
		t.Fatalf("FactSource size = %d; want 104", factSourceStructBytes)
	}

	public := factTestPub(600)
	base := factTestNodeRecord(public, nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	withCaps := factTestNodeRecord(public, []string{"relay"}, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if grew := factRecordBytes(withCaps) - factRecordBytes(base); grew < int64(len("relay"))+stringHeaderBytes {
		t.Fatalf("payload/capability bytes not counted: grew %d", grew)
	}

	entry := &factEntry{
		canon:   make([]byte, 8, 64),
		record:  base,
		sources: make([]FactSource, 0, maxFactSources),
	}
	if got, want := factEntryBytes(entry), factEntryStructBytes+64+int64(maxFactSources)*factSourceStructBytes; got < want {
		t.Fatalf("entry accounting = %d; want at least %d (canon and source capacity must count)", got, want)
	}

	tombstone := &tombstoneEntry{
		targetKey:    make([]byte, MaxRevocationTargetKey),
		contributors: map[string]revocationContribution{"contributor": {}},
	}
	if got, want := tombstoneBytes(tombstone), tombstoneStructBytes+int64(MaxRevocationTargetKey)+factMapEntryOverhead+stringHeaderBytes+int64(len("contributor"))+contributionStructByte; got < want {
		t.Fatalf("tombstone accounting = %d; want at least %d (contributors must count)", got, want)
	}

	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-mem"))
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1, 1), []FactRecord{base}, factTestNow); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got := ownedFactStoreBytes(env.fs.newCandidate()); got <= 0 {
		t.Fatalf("ownedFactStoreBytes = %d; want a positive conservative bound", got)
	}
	if envelopeStructBytes < int64(FactEnvelopeSize) {
		t.Fatalf("envelope accounting = %d; want at least the wire envelope size %d", envelopeStructBytes, FactEnvelopeSize)
	}
}

func TestFactStoreConcurrentCommitAndSnapshot(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-o"))
	const workers = 4

	type work struct {
		source  FactSource
		summary FactSummary
		pages   []FactPage
	}
	workItems := make([]work, 0, workers)
	for worker := 0; worker < workers; worker++ {
		source := factTestSource(env.contextID, uint64(200+worker), 1)
		record := factTestNodeRecord(factTestPub(uint64(2000+worker)), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
		summary, pages := factTestSnapshot(t, factTestWireID, 1, uint64(worker+1), []FactRecord{record})
		workItems = append(workItems, work{source: source, summary: summary, pages: pages})
	}

	var wait sync.WaitGroup
	for _, item := range workItems {
		wait.Add(1)
		go func(item work) {
			defer wait.Done()
			for round := 0; round < 10; round++ {
				if err := env.fs.CommitSnapshot(item.source, item.summary, item.pages, factTestNow); err != nil {
					t.Errorf("concurrent commit: %v", err)
					return
				}
				if _, _, err := env.fs.Snapshot(factTestNow); err != nil {
					t.Errorf("concurrent snapshot: %v", err)
					return
				}
				if env.fs.Version() == 0 {
					t.Error("view version stayed zero")
					return
				}
			}
		}(item)
	}
	wait.Wait()

	visible, _, err := env.fs.Snapshot(factTestNow)
	if err != nil {
		t.Fatalf("final snapshot: %v", err)
	}
	if len(visible) != workers {
		t.Fatalf("final snapshot has %d records; want %d", len(visible), workers)
	}
}

// --- regression coverage for the confirmed release gaps -----------------------

func TestFactStoreOlderRevocationCannotRaiseFloorOrRetention(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-rev-older"))
	from := factTestNodeID(factTestPub(510))
	to := factTestNodeID(factTestPub(511))
	revoker := factTestNodeID(factTestPub(512))
	targetKey := factTestLinkTarget(from, to, FactLanePacket, 7)
	tombKey := factTestTargetTombstoneKey(FactLink, from, targetKey)

	winnerExpires := factTestIssued + 10_000
	winner := factTestRevocationRecord(revoker, from, FactLink, targetKey, FactVersion{1, 5}, FactVersion{1, 2}, factTestIssued, winnerExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1, 1), []FactRecord{winner}, factTestNow); err != nil {
		t.Fatalf("commit winner revocation: %v", err)
	}
	before := env.fs.tombstones[tombKey]
	if before == nil {
		t.Fatal("winner did not create a tombstone")
	}
	if before.retentionUntil != winnerExpires+factTombstoneRetentionMillis {
		t.Fatalf("winner retention = %d; want %d", before.retentionUntil, winnerExpires+factTombstoneRetentionMillis)
	}

	// Same revoker + target (same own FactKey), but an older tombstone version
	// carrying a higher target version and a longer local expiry. It must not be
	// admitted as a contributor, so neither the aggregate floor nor retention move.
	olderExpires := factTestIssued + 44_000
	older := factTestRevocationRecord(revoker, from, FactLink, targetKey, FactVersion{1, 9}, FactVersion{1, 1}, factTestIssued+1_000, olderExpires)
	if err := factTestCommit(t, env.fs, 1, 2, factTestSource(env.contextID, 2, 1), []FactRecord{older}, factTestNow); err != nil {
		t.Fatalf("commit older revocation: %v", err)
	}
	after := env.fs.tombstones[tombKey]
	if after == nil {
		t.Fatal("tombstone disappeared after an older revocation")
	}
	if compareFactVersion(after.revokedThrough, FactVersion{1, 5}) != 0 {
		t.Fatalf("older revocation raised the floor to %+v; want {1 5}", after.revokedThrough)
	}
	if after.retentionUntil != winnerExpires+factTombstoneRetentionMillis {
		t.Fatalf("older revocation changed retention to %d; want %d", after.retentionUntil, winnerExpires+factTombstoneRetentionMillis)
	}
	if len(after.contributors) != 1 {
		t.Fatalf("older revocation added a contributor: %d", len(after.contributors))
	}
}

func TestFactStoreRevocationEquivocationConvergesBothArrivalOrders(t *testing.T) {
	shortExpires := factTestIssued + 10_000
	longExpires := factTestIssued + 20_000
	revoker := factTestNodeID(factTestPub(522))
	from := factTestNodeID(factTestPub(520))
	to := factTestNodeID(factTestPub(521))
	targetKey := factTestLinkTarget(from, to, FactLanePacket, 9)
	makeRev := func(target FactVersion, expires uint64) FactRecord {
		return factTestRevocationRecord(revoker, from, FactLink, targetKey, target, FactVersion{1, 2}, factTestIssued, expires)
	}
	// In both conflicts the canonical winner carries the lower target version:
	// one decides ordering in the envelope (ExpiresAt), the other inside the
	// REVOCATION payload (TargetVersion).
	conflicts := []struct {
		name   string
		winner FactRecord
		loser  FactRecord
	}{
		{"expiry-conflict", makeRev(FactVersion{1, 5}, shortExpires), makeRev(FactVersion{1, 9}, longExpires)},
		{"payload-conflict", makeRev(FactVersion{1, 5}, shortExpires), makeRev(FactVersion{1, 9}, shortExpires)},
	}

	type outcome struct {
		floor        FactVersion
		canon        string
		expiresAt    uint64
		contributors int
		equivocation uint64
	}
	run := func(arrival []FactRecord) outcome {
		env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-rev-equiv"))
		payload := arrival[0].Payload.(RevocationPayload)
		tombKey := factTestTargetTombstoneKey(payload.TargetKind, payload.TargetOrigin, payload.TargetKey)
		for index, record := range arrival {
			if err := factTestCommit(t, env.fs, 1, uint64(index+1), factTestSource(env.contextID, uint64(index+10), 1), []FactRecord{record}, factTestNow); err != nil {
				t.Fatalf("commit variant %d: %v", index, err)
			}
		}
		key := string(factTestFactKey(t, arrival[0]))
		entry := env.fs.entries[key]
		tomb := env.fs.tombstones[tombKey]
		if entry == nil || tomb == nil {
			t.Fatalf("entry/tombstone missing: %+v %+v", entry, tomb)
		}
		return outcome{
			floor:        tomb.revokedThrough,
			canon:        string(entry.canon),
			expiresAt:    entry.expiresAt,
			contributors: len(tomb.contributors),
			equivocation: env.fs.Equivocations(),
		}
	}

	for _, conflict := range conflicts {
		t.Run(conflict.name, func(t *testing.T) {
			winnerBytes, err := EncodeFactRecord(conflict.winner)
			if err != nil {
				t.Fatal(err)
			}
			loserBytes, err := EncodeFactRecord(conflict.loser)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Compare(winnerBytes, loserBytes) >= 0 {
				t.Fatal("fixture: the lower target version is not the smaller canonical record")
			}
			winnerFirst := run([]FactRecord{conflict.winner, conflict.loser})
			loserFirst := run([]FactRecord{conflict.loser, conflict.winner})
			if winnerFirst.expiresAt != loserFirst.expiresAt {
				t.Fatalf("entry expiry depends on arrival order: winner-first=%d loser-first=%d",
					winnerFirst.expiresAt, loserFirst.expiresAt)
			}
			for name, got := range map[string]outcome{"winner-first": winnerFirst, "loser-first": loserFirst} {
				if compareFactVersion(got.floor, FactVersion{1, 9}) != 0 {
					t.Fatalf("%s: aggregate floor = %+v; want max observed target {1 9}", name, got.floor)
				}
				if got.canon != winnerFirst.canon {
					t.Fatalf("%s: canonical winner differs across arrival order", name)
				}
				// The stored expiry is anchored locally: the winner's declared lifetime
				// counted from when this node stored it, not the publisher's absolute time.
				wantExpiry := uint64(factTestNow.UnixMilli()) +
					(conflict.winner.Envelope.ExpiresAt - conflict.winner.Envelope.IssuedAt)
				if got.expiresAt != wantExpiry {
					t.Fatalf("%s: entry expiry = %d; want the winner's lifetime from the local anchor %d",
						name, got.expiresAt, wantExpiry)
				}
				if got.contributors != 1 {
					t.Fatalf("%s: contributors = %d; want 1", name, got.contributors)
				}
				if got.equivocation != 1 {
					t.Fatalf("%s: equivocations = %d; want 1", name, got.equivocation)
				}
			}
		})
	}
}

func TestFactStoreDistinctRevokersStayIndependentAndAggregate(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-rev-two"))
	from := factTestNodeID(factTestPub(530))
	to := factTestNodeID(factTestPub(531))
	revokerOne := factTestNodeID(factTestPub(532))
	revokerTwo := factTestNodeID(factTestPub(533))
	targetKey := factTestLinkTarget(from, to, FactLanePacket, 7)
	tombKey := factTestTargetTombstoneKey(FactLink, from, targetKey)

	target := factTestLinkRecord(from, to, 7, 1, FactLanePacket, "tcp", FactVersion{1, 5}, factTestIssued, factTestExpires)
	revOne := factTestRevocationRecord(revokerOne, from, FactLink, targetKey, FactVersion{1, 5}, FactVersion{1, 1}, factTestIssued, factTestExpires)
	revTwo := factTestRevocationRecord(revokerTwo, from, FactLink, targetKey, FactVersion{1, 5}, FactVersion{1, 2}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1, 1), []FactRecord{target, revOne, revTwo}, factTestNow); err != nil {
		t.Fatalf("commit two revokers: %v", err)
	}

	// Two distinct revokers keep two first-class REVOCATION records; they must not
	// be collapsed by comparing Sequence across different Origins.
	for _, record := range []FactRecord{revOne, revTwo} {
		if env.fs.entries[string(factTestFactKey(t, record))] == nil {
			t.Fatal("a distinct revoker's REVOCATION record was dropped")
		}
	}
	tomb := env.fs.tombstones[tombKey]
	if tomb == nil || len(tomb.contributors) != 2 {
		t.Fatalf("aggregate contributors = %+v; want 2 independent revokers", tomb)
	}
	if compareFactVersion(tomb.revokedThrough, FactVersion{1, 5}) != 0 {
		t.Fatalf("aggregate floor = %+v; want {1 5}", tomb.revokedThrough)
	}
	visible, _, err := env.fs.Snapshot(factTestNow)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	advertised := map[string]bool{}
	for _, record := range visible {
		advertised[string(factTestFactKey(t, record))] = true
	}
	for index, record := range []FactRecord{revOne, revTwo} {
		if !advertised[string(factTestFactKey(t, record))] {
			t.Fatalf("revoker %d's live revocation is not gossiped", index)
		}
	}
	if env.fs.IsCurrent(factTestFactKey(t, target), FactVersion{1, 5}, factTestNow) {
		t.Fatal("aggregate floor did not suppress target version 5")
	}

	recovered := factTestLinkRecord(from, to, 7, 1, FactLanePacket, "tcp", FactVersion{1, 7}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 2, factTestSource(env.contextID, 2, 1), []FactRecord{recovered}, factTestNow); err != nil {
		t.Fatalf("commit recovery: %v", err)
	}
	if !env.fs.IsCurrent(factTestFactKey(t, recovered), FactVersion{1, 7}, factTestNow) {
		t.Fatal("a target version above the aggregate floor did not recover")
	}
}

func TestFactStoreExpiredRevocationIsNotExportedButFloorHeld(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-rev-expiry"))
	from := factTestNodeID(factTestPub(540))
	to := factTestNodeID(factTestPub(541))
	revoker := factTestNodeID(factTestPub(542))
	targetKey := factTestLinkTarget(from, to, FactLanePacket, 7)
	tombKey := factTestTargetTombstoneKey(FactLink, from, targetKey)

	revExpires := factTestIssued + 5_000
	target := factTestLinkRecord(from, to, 7, 1, FactLanePacket, "tcp", FactVersion{1, 7}, factTestIssued, factTestIssued+44_000)
	node := factTestNodeRecord(factTestPub(543), nil, FactVersion{1, 1}, factTestIssued, factTestIssued+44_000)
	revocation := factTestRevocationRecord(revoker, from, FactLink, targetKey, FactVersion{1, 5}, FactVersion{1, 2}, factTestIssued, revExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1, 1), []FactRecord{target, node, revocation}, factTestNow); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Anchored to this node's commit time plus the declared lifetime.
	now := time.UnixMilli(int64(uint64(factTestNow.UnixMilli()) + (revExpires - factTestIssued) + factClockSkewMillis + 1))
	visible, _, err := env.fs.Snapshot(now)
	if err != nil {
		t.Fatalf("snapshot after revocation expiry: %v", err)
	}
	revocationKey := factTestFactKey(t, revocation)
	for _, record := range visible {
		if bytes.Equal(factTestFactKey(t, record), revocationKey) {
			t.Fatal("an expired REVOCATION record was exported in the snapshot")
		}
		if err := ValidateFactForNetwork(record, factTestWireID); err != nil {
			t.Fatalf("snapshot exported a record that fails network validation: %v", err)
		}
	}
	tomb := env.fs.tombstones[tombKey]
	if tomb == nil {
		t.Fatal("tombstone floor was dropped before its 90s retention")
	}
	if tomb.retentionUntil < revExpires+factTombstoneRetentionMillis || tomb.retentionUntil <= uint64(now.UnixMilli()) {
		t.Fatalf("tombstone retention = %d; want at least %d, still in force at %d", tomb.retentionUntil, revExpires+factTombstoneRetentionMillis, now.UnixMilli())
	}
	if compareFactVersion(tomb.revokedThrough, FactVersion{1, 5}) != 0 {
		t.Fatalf("tombstone floor = %+v; want {1 5}", tomb.revokedThrough)
	}
	if !env.fs.IsCurrent(factTestFactKey(t, target), FactVersion{1, 7}, now) {
		t.Fatal("a target above the floor should still be current")
	}
}

func TestFactStoreEquivocationWinnerMetadataAndExpiry(t *testing.T) {
	shortExpires := factTestIssued + 10_000
	longExpires := factTestIssued + 20_000
	from := factTestNodeID(factTestPub(550))
	to := factTestNodeID(factTestPub(551))
	public := factTestPub(552)
	addressOrigin := factTestNodeID(factTestPub(553))
	ip := netip.MustParseAddr("10.99.0.1")

	builders := map[string]func(expires uint64) FactRecord{
		"node": func(expires uint64) FactRecord {
			return factTestNodeRecord(public, nil, FactVersion{1, 1}, factTestIssued, expires)
		},
		"link": func(expires uint64) FactRecord {
			return factTestLinkRecord(from, to, 7, 1, FactLanePacket, "tcp", FactVersion{1, 1}, factTestIssued, expires)
		},
		"address": func(expires uint64) FactRecord {
			return factTestAddressRecord(addressOrigin, ip, FactVersion{1, 1}, factTestIssued, expires)
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			winner := build(shortExpires)
			loser := build(longExpires)
			winnerBytes, err := EncodeFactRecord(winner)
			if err != nil {
				t.Fatal(err)
			}
			loserBytes, err := EncodeFactRecord(loser)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Compare(winnerBytes, loserBytes) >= 0 {
				t.Fatal("fixture: the shorter expiry is not the smaller canonical record")
			}
			key := factTestFactKey(t, winner)
			for orderIndex, order := range [][]FactRecord{{winner, loser}, {loser, winner}} {
				env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-eq-"+name))
				for index, record := range order {
					if err := factTestCommit(t, env.fs, 1, uint64(index+1), factTestSource(env.contextID, uint64(index+20), 1), []FactRecord{record}, factTestNow); err != nil {
						t.Fatalf("order %d commit %d: %v", orderIndex, index, err)
					}
				}
				entry := env.fs.entries[string(key)]
				if entry == nil {
					t.Fatal("entry missing")
				}
				// Metadata is anchored when this node stored the fact; the declared
				// lifetime is what must survive, not the publisher's absolute timestamps.
				wantIssued := uint64(factTestNow.UnixMilli())
				wantExpires := wantIssued + (shortExpires - factTestIssued)
				if entry.issuedAt != wantIssued || entry.expiresAt != wantExpires {
					t.Fatalf("order %d: entry metadata = issued %d expires %d; want %d/%d",
						orderIndex, entry.issuedAt, entry.expiresAt, wantIssued, wantExpires)
				}
				if !bytes.Equal(entry.canon, winnerBytes) {
					t.Fatalf("order %d: canonical winner is not the shorter-expiry record", orderIndex)
				}
				if env.fs.Equivocations() != 1 {
					t.Fatalf("order %d: equivocations = %d; want 1", orderIndex, env.fs.Equivocations())
				}

				after := time.UnixMilli(int64(uint64(factTestNow.UnixMilli()) + (shortExpires - factTestIssued) + factClockSkewMillis + 1))
				if env.fs.IsCurrent(key, FactVersion{1, 1}, after) {
					t.Fatalf("order %d: winner outlived its own expiry (loser expiry reused)", orderIndex)
				}
				visible, _, err := env.fs.Snapshot(after)
				if err != nil {
					t.Fatalf("order %d snapshot: %v", orderIndex, err)
				}
				for _, record := range visible {
					if bytes.Equal(factTestFactKey(t, record), key) {
						t.Fatalf("order %d: expired winner still exported", orderIndex)
					}
				}
			}
		})
	}
}

func TestFactStoreLosingOrOlderSourceIsNotCurrentProvenance(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-prov-loser"))
	public := factTestPub(560)
	winner := factTestNodeRecord(public, nil, FactVersion{1, 2}, factTestIssued, factTestIssued+10_000)
	loser := factTestNodeRecord(public, nil, FactVersion{1, 2}, factTestIssued, factTestIssued+20_000)
	older := factTestNodeRecord(public, nil, FactVersion{1, 1}, factTestIssued, factTestIssued+10_000)
	winnerBytes, err := EncodeFactRecord(winner)
	if err != nil {
		t.Fatal(err)
	}
	loserBytes, err := EncodeFactRecord(loser)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(winnerBytes, loserBytes) >= 0 {
		t.Fatal("fixture: the current version is not the smaller canonical record")
	}
	key := factTestFactKey(t, winner)
	sourceA := factTestSource(env.contextID, 1, 1)

	if err := factTestCommit(t, env.fs, 1, 1, sourceA, []FactRecord{winner}, factTestNow); err != nil {
		t.Fatalf("commit winner: %v", err)
	}
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 2, 1), []FactRecord{loser}, factTestNow); err != nil {
		t.Fatalf("commit losing canonical: %v", err)
	}
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 3, 1), []FactRecord{older}, factTestNow); err != nil {
		t.Fatalf("commit older version: %v", err)
	}
	entry := env.fs.entries[string(key)]
	if entry == nil {
		t.Fatal("winner entry missing")
	}
	if len(entry.sources) != 1 || entry.sources[0] != sourceA {
		t.Fatalf("losing/older sources became current provenance: %+v", entry.sources)
	}
	if !env.fs.IsCurrent(key, FactVersion{1, 2}, factTestNow) {
		t.Fatal("winner is no longer current")
	}
}

func TestFactStoreSourceDeclaringOlderVersionLosesProvenance(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-prov-replace"))
	public := factTestPub(570)
	current := factTestNodeRecord(public, nil, FactVersion{1, 2}, factTestIssued, factTestExpires)
	older := factTestNodeRecord(public, nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	key := factTestFactKey(t, current)
	sourceA := factTestSource(env.contextID, 1, 1)
	sourceB := factTestSource(env.contextID, 2, 1)

	if err := factTestCommit(t, env.fs, 1, 1, sourceA, []FactRecord{current}, factTestNow); err != nil {
		t.Fatalf("commit A: %v", err)
	}
	if err := factTestCommit(t, env.fs, 1, 1, sourceB, []FactRecord{current}, factTestNow); err != nil {
		t.Fatalf("commit B: %v", err)
	}
	if entry := env.fs.entries[string(key)]; entry == nil || len(entry.sources) != 2 {
		t.Fatalf("expected two provenance sources: %+v", entry)
	}

	// B's next complete snapshot declares the older version: B no longer
	// contributes to the current winner and must lose its provenance.
	if err := factTestCommit(t, env.fs, 1, 2, sourceB, []FactRecord{older}, factTestNow); err != nil {
		t.Fatalf("commit B older declaration: %v", err)
	}
	entry := env.fs.entries[string(key)]
	if entry == nil || len(entry.sources) != 1 || entry.sources[0] != sourceA {
		t.Fatalf("source declaring an older version kept current provenance: %+v", entry)
	}
	if !env.fs.IsCurrent(key, FactVersion{1, 2}, factTestNow) {
		t.Fatal("current version changed after a losing source declaration")
	}

	// With the only remaining correct source gone, the fact is Withdrawn.
	if err := env.fs.WithdrawSource(sourceA, factTestNow); err != nil {
		t.Fatalf("withdraw A: %v", err)
	}
	if _, present := env.fs.entries[string(key)]; present {
		t.Fatal("fact was not Withdrawn when its last correct source closed")
	}
	if env.fs.IsCurrent(key, FactVersion{1, 2}, factTestNow) {
		t.Fatal("Withdrawn fact is still current")
	}
}

func TestFactStoreHigherVersionResetsSaturation(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-prov-reset"))
	record := factTestNodeRecord(factTestPub(580), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	key := factTestFactKey(t, record)
	static := factTestPeerStatic(0x91)
	for index := 0; index <= maxFactSources; index++ {
		source := factTestSourceForStatic(static, env.contextID, uint64(index+1), 1)
		if err := factTestCommit(t, env.fs, 1, uint64(index+1), source, []FactRecord{record}, factTestNow); err != nil {
			t.Fatalf("commit saturated source %d: %v", index, err)
		}
	}
	entry := env.fs.entries[string(key)]
	if entry == nil || !entry.saturated || len(entry.sources) != maxFactSources {
		t.Fatalf("saturation state = %+v; want %d sources saturated", entry, maxFactSources)
	}

	// Only a genuinely current, higher version starts a fresh provenance set.
	higher := factTestNodeRecord(factTestPub(580), nil, FactVersion{1, 2}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 99, factTestSource(env.contextID, 99, 1), []FactRecord{higher}, factTestNow); err != nil {
		t.Fatalf("commit higher version: %v", err)
	}
	entry = env.fs.entries[string(key)]
	if entry == nil || entry.saturated || len(entry.sources) != 1 {
		t.Fatalf("higher version did not reset saturation: %+v", entry)
	}
	if !env.fs.IsCurrent(key, FactVersion{1, 2}, factTestNow) {
		t.Fatal("higher version is not current")
	}
}

// factTestHWMKeyBatch builds a batch of unique NODE/LINK/ADDRESS facts, staying
// inside the per-kind and per-origin live limits.
func factTestHWMKeyBatch(base uint64, links, nodes, addresses int) []FactRecord {
	to := factTestNodeID(factTestPub(9_000_000))
	records := make([]FactRecord, 0, links+nodes+addresses)
	for index := 0; index < links; index++ {
		from := factTestNodeID(factTestPub(base + uint64(index)))
		records = append(records, factTestLinkRecord(from, to, uint64(index+1), 1, FactLanePacket, "tcp", FactVersion{1, 1}, factTestIssued, factTestExpires))
	}
	for index := 0; index < nodes; index++ {
		records = append(records, factTestNodeRecord(factTestPub(base+1_000_000+uint64(index)), nil, FactVersion{1, 1}, factTestIssued, factTestExpires))
	}
	for index := 0; index < addresses; index++ {
		origin := factTestNodeID(factTestPub(base + 2_000_000 + uint64(index)))
		ip := netip.AddrFrom4([4]byte{10, byte(base % 250), byte(index >> 8), byte(index)})
		records = append(records, factTestAddressRecord(origin, ip, FactVersion{1, 1}, factTestIssued, factTestExpires))
	}
	return records
}

func TestFactStoreHWMCapacityRetentionAndReclaim(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-hwm"))
	base := uint64(700_000)
	batches := []struct{ links, nodes, addresses int }{
		{4096, 1024, 1024},
		{4096, 1024, 1024},
		{4096, 0, 0},
	}
	var firstKey string
	total := 0
	for index, batch := range batches {
		source := factTestSource(env.contextID, uint64(300+index), 1)
		records := factTestHWMKeyBatch(base+uint64(index)*100_000, batch.links, batch.nodes, batch.addresses)
		if index == 0 {
			firstKey = string(factTestFactKey(t, records[0]))
		}
		total += len(records)
		if err := factTestCommit(t, env.fs, 1, 1, source, records, factTestNow); err != nil {
			t.Fatalf("commit batch %d: %v", index, err)
		}
		if err := env.fs.WithdrawSource(source, factTestNow); err != nil {
			t.Fatalf("withdraw batch %d: %v", index, err)
		}
	}
	if total != maxFactHWMEntries {
		t.Fatalf("fixture built %d floors; want %d", total, maxFactHWMEntries)
	}
	if got := len(env.fs.hwm); got != maxFactHWMEntries {
		t.Fatalf("hwm entries = %d; want %d", got, maxFactHWMEntries)
	}
	if len(env.fs.entries) != 0 {
		t.Fatalf("withdrawn entries remain live: %d", len(env.fs.entries))
	}
	floor := env.fs.hwm[firstKey]
	if !floor.retentionKnown || floor.retentionUntil <= uint64(factTestNow.UnixMilli()) {
		t.Fatalf("withdrawn floor = %+v; want a known future retention", floor)
	}

	// The old version must not revive while the floor's real retention is unmet.
	replayOld := factTestHWMKeyBatch(base, 1, 0, 0)[0]
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 400, 1), []FactRecord{replayOld}, factTestNow); err != nil {
		t.Fatalf("replay after withdraw: %v", err)
	}
	if env.fs.IsCurrent(factTestFactKey(t, replayOld), replayOld.Envelope.Version, factTestNow) {
		t.Fatal("withdrawn old version revived while its floor retention is unmet")
	}

	// A 16385th unique key is refused atomically: no reclaim, no partial publish.
	versionBefore := env.fs.Version()
	extra := factTestNodeRecord(factTestPub(base+9_000_000), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	hwmBefore := len(env.fs.hwm)
	commitErr := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 401, 1), []FactRecord{extra}, factTestNow)
	t.Logf("16385th: err=%v hwm %d -> %d", commitErr, hwmBefore, len(env.fs.hwm))
	if !errors.Is(commitErr, ErrFactTooLarge) {
		t.Fatalf("16385th key error = %v; want ErrFactTooLarge", commitErr)
	}
	if got := len(env.fs.hwm); got != maxFactHWMEntries {
		t.Fatalf("hwm grew on rejection: %d", got)
	}
	if env.fs.Version() != versionBefore {
		t.Fatalf("view version advanced on rejection: %d -> %d", versionBefore, env.fs.Version())
	}
	if visible, _, err := env.fs.Snapshot(factTestNow); err != nil || len(visible) != 0 {
		t.Fatalf("rejected 16385th key left %d records, %v; want 0, nil", len(visible), err)
	}
	if _, present := env.fs.hwm[firstKey]; !present {
		t.Fatal("floor reclaimed before its recorded retention elapsed")
	}

	// Past every retention deadline the table may still reclaim, but only because it is
	// over its cap — never because a wall-clock deadline passed. Floors are what refuse
	// replayed versions, and they must not depend on two hosts agreeing about the time.
	// Retention is anchored when this node stored the fact, so the deadline is derived from
	// factTestNow rather than from the publisher's ExpiresAt. The publisher's own deadline
	// falls 1 s earlier here, so a store that used envelope time would reclaim too soon —
	// which is exactly what the check just below catches.
	reclaimNow := time.UnixMilli(int64(uint64(factTestNow.UnixMilli()) + 45_000 + factTombstoneRetentionMillis + 1))
	fresh := factTestNodeRecord(factTestPub(base+9_100_000), nil, FactVersion{1, 1}, uint64(reclaimNow.UnixMilli())-1_000, uint64(reclaimNow.UnixMilli())+1_000)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 402, 1), []FactRecord{fresh}, reclaimNow); err != nil {
		t.Fatalf("commit after real retention: %v", err)
	}
	if got := len(env.fs.hwm); got != maxFactHWMEntries {
		t.Fatalf("HWM count after reclaim = %d; want %d", got, maxFactHWMEntries)
	}
	if !env.fs.IsCurrent(factTestFactKey(t, fresh), fresh.Envelope.Version, reclaimNow) {
		t.Fatal("fresh fact is not current after reclaim")
	}
	// The replay is refused because its floor survived, not because of a timestamp.
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 403, 1), []FactRecord{replayOld}, reclaimNow); err != nil {
		t.Fatalf("commit stale replay: %v", err)
	}
	if env.fs.IsCurrent(factTestFactKey(t, replayOld), replayOld.Envelope.Version, reclaimNow) {
		t.Fatal("stale record revived after reclaim")
	}
}

// factTestV1Watermarks hand-builds the pre-retention STFW v1 record: it has no
// per-key retention and no sender digest.
func factTestV1Watermarks(contextID [32]byte, wireID uint64, hwm map[string]FactVersion, senders map[string]senderFloor) []byte {
	record := []byte(factPersistenceMagic)
	record = append(record, factPersistenceVersionV1, 0, 0, 0)
	record = append(record, contextID[:]...)
	record = binary.BigEndian.AppendUint64(record, wireID)
	record = binary.BigEndian.AppendUint64(record, 1)

	keys := make([]string, 0, len(hwm))
	for key := range hwm {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	record = binary.BigEndian.AppendUint32(record, uint32(len(keys)))
	for _, key := range keys {
		version := hwm[key]
		record = binary.BigEndian.AppendUint16(record, uint16(len(key)))
		record = append(record, key...)
		record = binary.BigEndian.AppendUint64(record, version.Incarnation)
		record = binary.BigEndian.AppendUint64(record, version.Sequence)
	}

	senderKeys := make([]string, 0, len(senders))
	for key := range senders {
		senderKeys = append(senderKeys, key)
	}
	sort.Strings(senderKeys)
	record = binary.BigEndian.AppendUint32(record, uint32(len(senderKeys)))
	for _, key := range senderKeys {
		sender := senders[key]
		record = append(record, key...)
		record = binary.BigEndian.AppendUint64(record, sender.Incarnation)
		record = binary.BigEndian.AppendUint64(record, sender.SnapshotVersion)
	}
	record = binary.BigEndian.AppendUint32(record, 0)
	return record
}

func TestFactStoreSenderSnapshotDigestMismatchIsRejected(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-sender-digest"))
	source := factTestSource(env.contextID, 600, 1)
	first := factTestNodeRecord(factTestPub(601), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, source, []FactRecord{first}, factTestNow); err != nil {
		t.Fatalf("commit first snapshot: %v", err)
	}
	versionAfter := env.fs.Version()

	// Same sender incarnation and snapshot version with different bytes/digest.
	other := factTestNodeRecord(factTestPub(602), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, source, []FactRecord{other}, factTestNow); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("same version different digest error = %v; want ErrFactMalformed", err)
	}
	if env.fs.IsCurrent(factTestFactKey(t, other), other.Envelope.Version, factTestNow) {
		t.Fatal("a mismatched-digest snapshot was partially published")
	}
	if env.fs.Version() != versionAfter {
		t.Fatalf("view version advanced on a digest mismatch: %d -> %d", versionAfter, env.fs.Version())
	}

	// An exact repeat is idempotent.
	if err := factTestCommit(t, env.fs, 1, 1, source, []FactRecord{first}, factTestNow); err != nil {
		t.Fatalf("idempotent repeat rejected: %v", err)
	}
	if !env.fs.IsCurrent(factTestFactKey(t, first), first.Envelope.Version, factTestNow) {
		t.Fatal("idempotent repeat changed the published fact")
	}
}

func TestFactStoreRejectionsPreservePublishedView(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-reject-view"))
	good := factTestNodeRecord(factTestPub(610), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1, 1), []FactRecord{good}, factTestNow); err != nil {
		t.Fatalf("commit good: %v", err)
	}
	versionBefore := env.fs.Version()

	// Byte-level failure: a tampered page digest.
	tampered := factTestNodeRecord(factTestPub(611), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
	summary, pages := factTestSnapshot(t, factTestWireID, 1, 2, []FactRecord{tampered})
	pages[0].PageDigest[0] ^= 0xff
	if err := env.fs.CommitSnapshot(factTestSource(env.contextID, 2, 1), summary, pages, factTestNow); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("tampered snapshot error = %v; want ErrFactMalformed", err)
	}

	// Resource failure: one record over the NODE count ceiling.
	over := make([]FactRecord, 0, maxNodeFacts+1)
	for index := 0; index <= maxNodeFacts; index++ {
		over = append(over, factTestNodeRecord(factTestPub(uint64(2000+index)), nil, FactVersion{1, 1}, factTestIssued, factTestExpires))
	}
	if err := factTestCommit(t, env.fs, 1, 3, factTestSource(env.contextID, 3, 1), over, factTestNow); !errors.Is(err, ErrFactTooLarge) {
		t.Fatalf("over-quota snapshot error = %v; want ErrFactTooLarge", err)
	}

	if env.fs.Version() != versionBefore {
		t.Fatalf("view version advanced on a rejected snapshot: %d -> %d", versionBefore, env.fs.Version())
	}
	visible, _, err := env.fs.Snapshot(factTestNow)
	if err != nil || len(visible) != 1 || !bytes.Equal(factTestFactKey(t, visible[0]), factTestFactKey(t, good)) {
		t.Fatalf("published view changed after rejections: %d records, %v", len(visible), err)
	}
}

func factTestV1TombstoneWatermarks(contextID [32]byte, wireID uint64, kind FactKind, targetOrigin NodeID, targetKey []byte, revoker NodeID, targetVersion, tombstoneVersion FactVersion, retentionUntil uint64) []byte {
	record := []byte(factPersistenceMagic)
	record = append(record, factPersistenceVersionV1, 0, 0, 0)
	record = append(record, contextID[:]...)
	record = binary.BigEndian.AppendUint64(record, wireID)
	record = binary.BigEndian.AppendUint64(record, 1)
	record = binary.BigEndian.AppendUint32(record, 0) // high-watermarks
	record = binary.BigEndian.AppendUint32(record, 0) // sender floors
	record = binary.BigEndian.AppendUint32(record, 1) // tombstones
	record = append(record, byte(kind))
	record = append(record, targetOrigin[:]...)
	record = binary.BigEndian.AppendUint16(record, uint16(len(targetKey)))
	record = append(record, targetKey...)
	record = append(record, revoker[:]...)
	record = binary.BigEndian.AppendUint64(record, targetVersion.Incarnation)
	record = binary.BigEndian.AppendUint64(record, targetVersion.Sequence)
	record = binary.BigEndian.AppendUint64(record, tombstoneVersion.Incarnation)
	record = binary.BigEndian.AppendUint64(record, tombstoneVersion.Sequence)
	return binary.BigEndian.AppendUint64(record, retentionUntil)
}

func TestFactStorePeakReplacementBudgetRejectsAtomically(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-peak-replacement"))
	const storeFacts = 3500
	const replacementFacts = 500
	connectionType := strings.Repeat("x", 3700)
	sourceA := factTestSource(env.contextID, 801, 1)
	sourceB := factTestSource(env.contextID, 802, 1)
	oldRecords := make([]FactRecord, 0, replacementFacts)
	for index := 0; index < storeFacts; index++ {
		from := factTestNodeID(factTestPub(uint64(30_000 + index)))
		to := factTestNodeID(factTestPub(uint64(40_000 + index)))
		record := factTestLinkRecord(from, to, uint64(index+1), 1, FactLanePacket, connectionType, FactVersion{1, 1}, factTestIssued, factTestExpires)
		key := string(factTestFactKey(t, record))
		canon, err := EncodeFactRecord(record)
		if err != nil {
			t.Fatalf("encode seeded fact %d: %v", index, err)
		}
		source := sourceB
		if index < replacementFacts {
			source = sourceA
			oldRecords = append(oldRecords, record)
		}
		env.fs.entries[key] = makeFactEntry(key, record, canon, &source, uint64(factTestNow.UnixMilli()))
		env.fs.hwm[key] = hwmEntry{
			version:        record.Envelope.Version,
			retentionUntil: record.Envelope.ExpiresAt + factTombstoneRetentionMillis,
			retentionKnown: true,
		}
	}
	env.fs.viewVersion = 41

	oldCandidate := &factStoreCandidate{
		entries: env.fs.entries, tombstones: env.fs.tombstones,
		hwm: env.fs.hwm, senders: env.fs.senders,
	}
	oldWatermarks, err := encodeFactWatermarks(env.contextID, factTestWireID, env.state.Incarnation(), env.fs.hwm, env.fs.tombstones, env.fs.senders)
	if err != nil {
		t.Fatalf("encode seeded watermarks: %v", err)
	}
	if err := env.state.WriteRecord(factWatermarksRecord, oldWatermarks, factPersistenceMaxBytes); err != nil {
		t.Fatalf("persist seeded watermarks: %v", err)
	}
	if accounted := ownedFactStoreBytes(oldCandidate) + int64(len(oldWatermarks)); accounted >= maxFactOwnedBytes-500_000 {
		t.Fatalf("test fixture does not leave staging room under the existing single-candidate estimate: %d bytes", accounted)
	}

	beforeVersion := env.fs.Version()
	_, _, beforeSnapshotErr := env.fs.Snapshot(factTestNow)
	if !errors.Is(beforeSnapshotErr, ErrFactTooLarge) {
		t.Fatalf("baseline snapshot error = %v; want ErrFactTooLarge for the seeded store", beforeSnapshotErr)
	}
	updates := make([]FactRecord, 0, replacementFacts)
	for _, old := range oldRecords {
		payload := old.Payload.(LinkPayload)
		updates = append(updates, factTestLinkRecord(
			old.Envelope.Origin, payload.To, payload.LinkID, payload.LinkEpoch+1,
			FactLanePacket, connectionType, FactVersion{1, 2}, factTestIssued, factTestExpires,
		))
	}
	summary, pages := factTestSnapshot(t, factTestWireID, 1, 1, updates)
	if err := ValidateSnapshot(summary, pages); err != nil {
		t.Fatalf("replacement snapshot is not legal: %v", err)
	}
	projected := &factStoreCandidate{
		entries:    make(map[string]*factEntry, len(env.fs.entries)),
		tombstones: make(map[string]*tombstoneEntry, len(env.fs.tombstones)),
		hwm:        make(map[string]hwmEntry, len(env.fs.hwm)),
		senders:    make(map[string]senderFloor, len(env.fs.senders)+1),
	}
	for key, entry := range env.fs.entries {
		projected.entries[key] = entry
	}
	for key, floor := range env.fs.hwm {
		projected.hwm[key] = floor
	}
	for key, floor := range env.fs.senders {
		projected.senders[key] = floor
	}
	for key, tombstone := range env.fs.tombstones {
		projected.tombstones[key] = tombstone
	}
	for _, update := range updates {
		key := string(factTestFactKey(t, update))
		canon, err := EncodeFactRecord(update)
		if err != nil {
			t.Fatalf("encode projected update: %v", err)
		}
		projected.entries[key] = makeFactEntry(key, update, canon, &sourceA, uint64(factTestNow.UnixMilli()))
		floor := projected.hwm[key]
		floor.version = update.Envelope.Version
		floor.retentionUntil = update.Envelope.ExpiresAt + factTombstoneRetentionMillis
		projected.hwm[key] = floor
	}
	projected.senders[senderIdentity(sourceA)] = senderFloor{
		Incarnation: summary.SenderIncarnation, SnapshotVersion: summary.SnapshotVersion,
		Digest: summary.Digest, DigestKnown: true,
	}
	projectedWatermarks, err := encodeFactWatermarks(env.contextID, factTestWireID, env.state.Incarnation(), projected.hwm, projected.tombstones, projected.senders)
	if err != nil {
		t.Fatalf("encode projected watermarks: %v", err)
	}
	candidateOnly := ownedFactStoreBytes(projected) + int64(len(projectedWatermarks))
	peak := factStorePeakBytes(env.fs, projected) + int64(len(projectedWatermarks))
	if candidateOnly >= maxFactOwnedBytes || peak <= maxFactOwnedBytes {
		t.Fatalf("fixture estimates candidate=%d peak=%d; want candidate below and peak above %d bytes", candidateOnly, peak, maxFactOwnedBytes)
	}
	if err := env.fs.CommitSnapshot(sourceA, summary, pages, factTestNow); !errors.Is(err, ErrFactTooLarge) {
		t.Fatalf("replacement peak error = %v; want ErrFactTooLarge", err)
	}
	durableAfter, err := env.state.ReadRecord(factWatermarksRecord, factPersistenceMaxBytes)
	if err != nil {
		t.Fatalf("read watermarks after rejection: %v", err)
	}
	if !bytes.Equal(durableAfter, oldWatermarks) {
		t.Fatal("persisted watermarks changed on peak-budget rejection")
	}
	if env.fs.Version() != beforeVersion {
		t.Fatalf("view version changed on peak-budget rejection: %d -> %d", beforeVersion, env.fs.Version())
	}
	if len(env.fs.entries) != storeFacts || len(env.fs.senders) != 0 {
		t.Fatalf("published map sizes changed on rejection: entries=%d senders=%d", len(env.fs.entries), len(env.fs.senders))
	}
	for _, old := range oldRecords {
		key := factTestFactKey(t, old)
		if !env.fs.IsCurrent(key, FactVersion{1, 1}, factTestNow) {
			t.Fatalf("old fact %x was replaced despite peak-budget rejection", key)
		}
		if got := env.fs.hwm[string(key)]; got.version != (FactVersion{1, 1}) ||
			got.retentionUntil != old.Envelope.ExpiresAt+factTombstoneRetentionMillis || !got.retentionKnown {
			t.Fatalf("watermark for %x changed on rejection: %+v", key, got)
		}
	}
	if _, _, afterSnapshotErr := env.fs.Snapshot(factTestNow); !errors.Is(afterSnapshotErr, beforeSnapshotErr) {
		t.Fatalf("snapshot result changed after peak-budget rejection: before %v, after %v", beforeSnapshotErr, afterSnapshotErr)
	}
}

func TestFactStoreSharedEntriesAreNotDoubleCharged(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-shared-memory"))
	const storeFacts = 2000
	connectionType := strings.Repeat("x", 3700)
	source := factTestSource(env.contextID, 811, 1)
	for index := 0; index < storeFacts; index++ {
		from := factTestNodeID(factTestPub(uint64(50_000 + index)))
		to := factTestNodeID(factTestPub(uint64(60_000 + index)))
		record := factTestLinkRecord(from, to, uint64(index+1), 1, FactLanePacket, connectionType, FactVersion{1, 1}, factTestIssued, factTestExpires)
		key := string(factTestFactKey(t, record))
		canon, err := EncodeFactRecord(record)
		if err != nil {
			t.Fatalf("encode seeded fact %d: %v", index, err)
		}
		env.fs.entries[key] = makeFactEntry(key, record, canon, &source, uint64(factTestNow.UnixMilli()))
		env.fs.hwm[key] = hwmEntry{version: record.Envelope.Version, retentionUntil: record.Envelope.ExpiresAt + factTombstoneRetentionMillis, retentionKnown: true}
	}
	oldCandidate := &factStoreCandidate{entries: env.fs.entries, tombstones: env.fs.tombstones, hwm: env.fs.hwm, senders: env.fs.senders}
	data, err := encodeFactWatermarks(env.contextID, factTestWireID, env.state.Incarnation(), env.fs.hwm, env.fs.tombstones, env.fs.senders)
	if err != nil {
		t.Fatalf("encode seeded watermarks: %v", err)
	}
	accounted := ownedFactStoreBytes(oldCandidate) + int64(len(data))
	if accounted <= maxFactOwnedBytes/2 || accounted >= maxFactOwnedBytes-100_000 {
		t.Fatalf("fixture estimate = %d; want a shared store above half-budget but below the limit", accounted)
	}

	versionBefore := env.fs.Version()
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 812, 1), nil, factTestNow); err != nil {
		t.Fatalf("unchanged shared entries were charged twice: %v", err)
	}
	if env.fs.Version() != versionBefore {
		t.Fatalf("empty snapshot changed view version: %d -> %d", versionBefore, env.fs.Version())
	}
	from := factTestNodeID(factTestPub(50_000))
	to := factTestNodeID(factTestPub(60_000))
	shared := factTestLinkRecord(from, to, 1, 1, FactLanePacket, connectionType, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if !env.fs.IsCurrent(factTestFactKey(t, shared), FactVersion{1, 1}, factTestNow) {
		t.Fatal("shared fact was lost after an empty snapshot")
	}
}

func TestFactStoreRetainedRevocationFloorsDoNotConsumeLiveFactQuota(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-live-tombstones"))
	const nodeCount = maxNodeFacts
	const linkCount = maxLinkFacts
	const addressCount = maxAddressFacts
	const revocationCount = maxRevocationFacts
	const expiredRevocationCount = maxRevocationFacts
	nowMillis := factTestIssued + 71_001
	now := time.UnixMilli(int64(nowMillis))
	source := factTestSource(env.contextID, 821, 1)
	installLive := func(record FactRecord) string {
		t.Helper()
		keyBytes := factTestFactKey(t, record)
		key := string(keyBytes)
		canon, err := EncodeFactRecord(record)
		if err != nil {
			t.Fatalf("encode live fact: %v", err)
		}
		env.fs.entries[key] = makeFactEntry(key, record, canon, &source, uint64(factTestNow.UnixMilli()))
		env.fs.hwm[key] = hwmEntry{version: record.Envelope.Version, retentionUntil: record.Envelope.ExpiresAt + factTombstoneRetentionMillis, retentionKnown: true}
		return key
	}
	for index := 0; index < nodeCount; index++ {
		installLive(factTestNodeRecord(factTestPub(uint64(70_000+index)), nil, FactVersion{1, 1}, nowMillis, nowMillis+45_000))
	}
	for index := 0; index < linkCount; index++ {
		from := factTestNodeID(factTestPub(uint64(80_000 + index)))
		to := factTestNodeID(factTestPub(uint64(90_000 + index)))
		installLive(factTestLinkRecord(from, to, uint64(index+1), 1, FactLanePacket, "tcp", FactVersion{1, 1}, nowMillis, nowMillis+45_000))
	}
	for index := 0; index < addressCount; index++ {
		origin := factTestNodeID(factTestPub(uint64(100_000 + index)))
		ip := netip.AddrFrom4([4]byte{10, 100, byte(index >> 8), byte(index)})
		installLive(factTestAddressRecord(origin, ip, FactVersion{1, 1}, nowMillis, nowMillis+45_000))
	}

	for index := 0; index < revocationCount+expiredRevocationCount; index++ {
		targetOrigin := factTestNodeID(factTestPub(uint64(110_000 + index)))
		targetTo := factTestNodeID(factTestPub(uint64(120_000 + index)))
		targetKey := factTestLinkTarget(targetOrigin, targetTo, FactLanePacket, uint64(index+1))
		revoker := factTestNodeID(factTestPub(uint64(130_000 + index)))
		issuedAt, expiresAt := nowMillis, nowMillis+45_000
		if index >= revocationCount {
			issuedAt, expiresAt = factTestIssued, factTestIssued+40_000
		}
		revocation := factTestRevocationRecord(revoker, targetOrigin, FactLink, targetKey, FactVersion{1, 1}, FactVersion{1, 1}, issuedAt, expiresAt)
		ownKey := string(factTestFactKey(t, revocation))
		if index < revocationCount {
			installLive(revocation)
		} else {
			env.fs.hwm[ownKey] = hwmEntry{version: revocation.Envelope.Version, retentionUntil: expiresAt + factTombstoneRetentionMillis, retentionKnown: true}
		}
		identity := string(targetFactKey(FactLink, targetOrigin, targetKey))
		env.fs.tombstones[identity] = &tombstoneEntry{
			kind: FactLink, targetOrigin: targetOrigin, targetKey: append([]byte(nil), targetKey...),
			revokedThrough: FactVersion{1, 1}, retentionUntil: expiresAt + factTombstoneRetentionMillis,
			contributors: map[string]revocationContribution{ownKey: {targetVersion: FactVersion{1, 1}, retentionUntil: expiresAt + factTombstoneRetentionMillis}},
		}
	}
	env.fs.viewVersion = 52
	if got := len(env.fs.entries); got != maxNodeFacts+maxLinkFacts+maxAddressFacts+maxRevocationFacts {
		t.Fatalf("fixture live entries = %d; want 7168", got)
	}
	if got := len(env.fs.tombstones); got != 2*maxRevocationFacts {
		t.Fatalf("fixture retained tombstones = %d; want 2048", got)
	}

	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 822, 1), nil, now); err != nil {
		t.Fatalf("retained floors incorrectly consumed the live-fact quota: %v", err)
	}
	if got := len(env.fs.entries); got != 7168 {
		t.Fatalf("live facts after commit = %d; want 7168", got)
	}
	if got := len(env.fs.tombstones); got != 2048 {
		t.Fatalf("retained floors after commit = %d; want 2048", got)
	}
	if got := len(env.fs.hwm); got > maxFactHWMEntries {
		t.Fatalf("HWM count = %d; want <= %d", got, maxFactHWMEntries)
	}
	if visible, _, err := env.fs.Snapshot(now); err != nil || len(visible) != 7168 {
		t.Fatalf("snapshot after retained-floor commit = %d records, %v; want 7168, nil", len(visible), err)
	}
}

func TestFactStoreHWMCapacityCountsTombstoneIdentityUnion(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-hwm-union"))
	for index := 0; index < maxFactHWMEntries; index++ {
		record := factTestNodeRecord(factTestPub(uint64(200_000+index)), nil, FactVersion{1, 1}, factTestIssued, factTestExpires)
		key := string(factTestFactKey(t, record))
		env.fs.hwm[key] = hwmEntry{version: record.Envelope.Version, retentionUntil: record.Envelope.ExpiresAt + factTombstoneRetentionMillis, retentionKnown: true}
	}
	from := factTestNodeID(factTestPub(400_001))
	to := factTestNodeID(factTestPub(400_002))
	targetKey := factTestLinkTarget(from, to, FactLanePacket, 77)
	revoker := factTestNodeID(factTestPub(400_003))
	revocation := factTestRevocationRecord(revoker, from, FactLink, targetKey, FactVersion{1, 1}, FactVersion{1, 1}, factTestIssued, factTestExpires)
	ownKey := string(factTestFactKey(t, revocation))
	tombstoneKey := string(targetFactKey(FactLink, from, targetKey))
	if _, exists := env.fs.hwm[tombstoneKey]; exists {
		t.Fatal("fixture target tombstone identity unexpectedly exists in HWM")
	}
	env.fs.tombstones[tombstoneKey] = &tombstoneEntry{
		kind: FactLink, targetOrigin: from, targetKey: append([]byte(nil), targetKey...),
		revokedThrough: FactVersion{1, 1}, retentionUntil: factTestExpires + factTombstoneRetentionMillis,
		contributors: map[string]revocationContribution{ownKey: {targetVersion: FactVersion{1, 1}, retentionUntil: factTestExpires + factTombstoneRetentionMillis}},
	}
	oldWatermarks, err := encodeFactWatermarks(env.contextID, factTestWireID, env.state.Incarnation(), env.fs.hwm, env.fs.tombstones, env.fs.senders)
	if err != nil {
		t.Fatalf("encode union fixture watermarks: %v", err)
	}
	if err := env.state.WriteRecord(factWatermarksRecord, oldWatermarks, factPersistenceMaxBytes); err != nil {
		t.Fatalf("persist union fixture watermarks: %v", err)
	}
	versionBefore := env.fs.Version()
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 831, 1), nil, factTestNow); !errors.Is(err, ErrFactTooLarge) {
		t.Fatalf("HWM/tombstone union error = %v; want ErrFactTooLarge", err)
	}
	durableAfter, err := env.state.ReadRecord(factWatermarksRecord, factPersistenceMaxBytes)
	if err != nil {
		t.Fatalf("read union watermarks after rejection: %v", err)
	}
	if !bytes.Equal(durableAfter, oldWatermarks) {
		t.Fatal("persisted HWM union changed on rejection")
	}
	if got := len(env.fs.hwm); got != maxFactHWMEntries {
		t.Fatalf("HWM count changed on union rejection: %d; want %d", got, maxFactHWMEntries)
	}
	if env.fs.Version() != versionBefore {
		t.Fatalf("view version changed on union rejection: %d -> %d", versionBefore, env.fs.Version())
	}
	if _, exists := env.fs.tombstones[tombstoneKey]; !exists {
		t.Fatal("retained tombstone was changed on union rejection")
	}
}

// TestFactStoreRetentionUsesLocalAnchor pins where a floor's retention deadline comes from.
//
// The publisher writes IssuedAt/ExpiresAt with its own clock. If retention were computed
// from those, a peer whose clock runs ahead would have every floor expire immediately, and
// a peer behind would have them live too long. The deadline must be anchored to when this
// node stored the fact, so a skewed envelope neither shortens nor lengthens it.
func TestFactStoreRetentionUsesLocalAnchor(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("retention/local-anchor"))

	const publisherSkew = time.Hour
	record := factTestNodeRecord(factTestPub(0x00C0FFEE00000001), nil, FactVersion{1, 1},
		uint64(factTestNow.Add(publisherSkew).UnixMilli()),
		uint64(factTestNow.Add(publisherSkew).UnixMilli())+45_000)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 431, 1), []FactRecord{record}, factTestNow); err != nil {
		t.Fatalf("commit with skewed publisher clock: %v", err)
	}

	hwmKey := string(factTestFactKey(t, record))
	floor, ok := env.fs.hwm[hwmKey]
	if !ok {
		t.Fatal("no floor recorded")
	}

	localDeadline := uint64(factTestNow.UnixMilli()) + 45_000 + factTombstoneRetentionMillis
	if floor.retentionUntil > localDeadline+1_000 {
		t.Fatalf("retention %d stretches past the local deadline %d: anchored to the publisher clock",
			floor.retentionUntil, localDeadline)
	}
	if floor.retentionUntil < localDeadline-1_000 {
		t.Fatalf("retention %d is far below the local deadline %d: anchored to the publisher clock",
			floor.retentionUntil, localDeadline)
	}
}
