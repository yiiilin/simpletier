package topology

import (
	"errors"
	"github.com/yiiilin/simpletier/internal/security"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// These tests cover the current-authoritative address-owner seam used by an
// already established PACKET/STREAM pair. It reads the live FactStore entries
// under one lock, so it is deliberately independent of any RouteView refresh.

func factTestResolveOwner(t *testing.T, fs *FactStore, ip netip.Addr, now time.Time) (AddressResolution, error) {
	t.Helper()
	return fs.ResolveAddressOwner(ip, now)
}

func TestFactStoreResolveAddressOwnerCurrentVersionWithoutViewRefresh(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-current-owner"))
	ip := netip.MustParseAddr("10.20.0.7")
	owner := factTestNodeID(factTestPub(1200))
	source := factTestSource(env.contextID, 1201, 1)

	first := factTestAddressRecord(owner, ip, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, source, []FactRecord{first}, factTestNow); err != nil {
		t.Fatalf("commit address v1: %v", err)
	}
	resolution, err := factTestResolveOwner(t, env.fs, ip, factTestNow)
	if err != nil {
		t.Fatalf("resolve owner v1: %v", err)
	}
	if resolution.NodeID != owner || compareFactVersion(resolution.FactVersion, FactVersion{1, 1}) != 0 {
		t.Fatalf("owner v1 = %+v; want %x version 1.1", resolution, owner)
	}
	if want := netip.PrefixFrom(ip, 32); resolution.Prefix != want {
		t.Fatalf("owner prefix = %s; want %s", resolution.Prefix, want)
	}
	if resolution.Freshness != RouteViewFresh {
		t.Fatalf("owner freshness = %v; want RouteViewFresh", resolution.Freshness)
	}

	// A stale RouteView exists but is never refreshed: the direct query must not
	// depend on it to observe the newer version of the same owner's fact.
	view, err := NewRouteView(env.fs, func(uint64, uint64, uint8, NodeID) bool { return true })
	if err != nil {
		t.Fatalf("new route view: %v", err)
	}
	if view.Freshness() != RouteViewFresh {
		t.Fatalf("test setup: fresh view expected, got %v", view.Freshness())
	}
	second := factTestAddressRecord(owner, ip, FactVersion{1, 2}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 2, source, []FactRecord{second}, factTestNow); err != nil {
		t.Fatalf("commit address v2: %v", err)
	}
	resolution, err = factTestResolveOwner(t, env.fs, ip, factTestNow)
	if err != nil {
		t.Fatalf("resolve owner v2: %v", err)
	}
	if resolution.NodeID != owner || compareFactVersion(resolution.FactVersion, FactVersion{1, 2}) != 0 {
		t.Fatalf("owner after v2 = %+v; want %x version 1.2", resolution, owner)
	}

	// An unrelated fact committed afterwards must not invalidate the answer.
	unrelated := factTestNodeRecord(factTestPub(1210), nil, FactVersion{5, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1211, 1), []FactRecord{unrelated}, factTestNow); err != nil {
		t.Fatalf("commit unrelated node fact: %v", err)
	}
	resolution, err = factTestResolveOwner(t, env.fs, ip, factTestNow)
	if err != nil {
		t.Fatalf("resolve owner after unrelated commit: %v", err)
	}
	if resolution.NodeID != owner || compareFactVersion(resolution.FactVersion, FactVersion{1, 2}) != 0 {
		t.Fatalf("unrelated publish changed the owner result: %+v", resolution)
	}
}

func TestFactStoreResolveAddressOwnerLocalOwner(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-current-local"))
	ip := netip.MustParseAddr("10.20.0.9")
	local := factTestAddressRecord(env.localNode, ip, FactVersion{3, 1}, factTestIssued, factTestExpires)
	if err := env.fs.PublishLocal([]FactRecord{local}, factTestNow); err != nil {
		t.Fatalf("publish local address: %v", err)
	}
	resolution, err := factTestResolveOwner(t, env.fs, ip, factTestNow)
	if err != nil {
		t.Fatalf("resolve local owner: %v", err)
	}
	if resolution.NodeID != env.localNode || compareFactVersion(resolution.FactVersion, FactVersion{3, 1}) != 0 {
		t.Fatalf("local owner = %+v; want local %x version 3.1", resolution, env.localNode)
	}
}

func TestFactStoreResolveAddressOwnerConflictThenRevocation(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-current-conflict"))
	ip := netip.MustParseAddr("10.20.0.11")
	ownerA := factTestNodeID(factTestPub(1220))
	ownerB := factTestNodeID(factTestPub(1221))
	sourceA := factTestSource(env.contextID, 1222, 1)
	sourceB := factTestSource(env.contextID, 1223, 1)

	recordA := factTestAddressRecord(ownerA, ip, FactVersion{1, 1}, factTestIssued, factTestExpires)
	recordB := factTestAddressRecord(ownerB, ip, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, sourceA, []FactRecord{recordA}, factTestNow); err != nil {
		t.Fatalf("commit owner A: %v", err)
	}
	if err := factTestCommit(t, env.fs, 1, 1, sourceB, []FactRecord{recordB}, factTestNow); err != nil {
		t.Fatalf("commit owner B: %v", err)
	}
	if _, err := factTestResolveOwner(t, env.fs, ip, factTestNow); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("two live owners error = %v; want ErrRouteConflict", err)
	}

	// A third party's accepted revocation of A's fact removes A; B stays the only
	// live owner and the query must return B, not the revoked ref.
	revoker := factTestNodeID(factTestPub(1224))
	ipBytes := ip.As4()
	targetKey := make([]byte, 0, len(ownerA)+len(ipBytes))
	targetKey = append(targetKey, ownerA[:]...)
	targetKey = append(targetKey, ipBytes[:]...)
	revocation := factTestRevocationRecord(revoker, ownerA, FactAddress, targetKey, FactVersion{1, 1}, FactVersion{1, 3}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1225, 1), []FactRecord{revocation}, factTestNow); err != nil {
		t.Fatalf("commit revocation: %v", err)
	}
	resolution, err := factTestResolveOwner(t, env.fs, ip, factTestNow)
	if err != nil {
		t.Fatalf("resolve after revocation: %v", err)
	}
	if resolution.NodeID != ownerB {
		t.Fatalf("owner after revocation = %x; want %x", resolution.NodeID, ownerB)
	}
}

func TestFactStoreResolveAddressOwnerExpiryAndWithdrawal(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-current-expiry"))
	ip := netip.MustParseAddr("10.20.0.13")
	shortLived := factTestNodeID(factTestPub(1230))
	longLived := factTestNodeID(factTestPub(1231))
	sourceShort := factTestSource(env.contextID, 1232, 1)
	sourceLong := factTestSource(env.contextID, 1233, 1)

	shortExpires := factTestIssued + 5_000
	if err := factTestCommit(t, env.fs, 1, 1, sourceShort, []FactRecord{factTestAddressRecord(shortLived, ip, FactVersion{1, 1}, factTestIssued, shortExpires)}, factTestNow); err != nil {
		t.Fatalf("commit short-lived owner: %v", err)
	}
	if err := factTestCommit(t, env.fs, 1, 1, sourceLong, []FactRecord{factTestAddressRecord(longLived, ip, FactVersion{1, 1}, factTestIssued, factTestExpires)}, factTestNow); err != nil {
		t.Fatalf("commit long-lived owner: %v", err)
	}
	if _, err := factTestResolveOwner(t, env.fs, ip, factTestNow); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("live conflict error = %v; want ErrRouteConflict", err)
	}

	// After the short-lived fact's effective expiry only the long-lived owner is
	// live: the expired ref must not be selected or reported as a conflict.
	// Expiry is anchored when this node stored the fact, so it is the local commit time
	// plus the declared lifetime — not the publisher's absolute timestamp.
	afterShortExpiry := time.UnixMilli(int64(uint64(factTestNow.UnixMilli()) + (shortExpires - factTestIssued) + factClockSkewMillis + 1))
	resolution, err := factTestResolveOwner(t, env.fs, ip, afterShortExpiry)
	if err != nil {
		t.Fatalf("resolve after short expiry: %v", err)
	}
	if resolution.NodeID != longLived {
		t.Fatalf("owner after short expiry = %x; want %x", resolution.NodeID, longLived)
	}

	// Withdrawing the only remaining source removes the last live owner.
	if err := env.fs.WithdrawSource(sourceLong, afterShortExpiry); err != nil {
		t.Fatalf("withdraw long-lived source: %v", err)
	}
	if _, err := factTestResolveOwner(t, env.fs, ip, afterShortExpiry); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("withdrawn owner error = %v; want ErrNoRoute", err)
	}
}

func TestFactStoreResolveAddressOwnerShapeAndIsolation(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-current-shape"))
	ip := netip.MustParseAddr("10.20.0.17")
	owner := factTestNodeID(factTestPub(1240))
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1241, 1), []FactRecord{factTestAddressRecord(owner, ip, FactVersion{1, 1}, factTestIssued, factTestExpires)}, factTestNow); err != nil {
		t.Fatalf("commit address: %v", err)
	}

	if _, err := factTestResolveOwner(t, env.fs, ip, factTestNow); err != nil {
		t.Fatalf("exact address lookup: %v", err)
	}
	if _, err := factTestResolveOwner(t, env.fs, netip.MustParseAddr("10.20.0.18"), factTestNow); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("neighbour address error = %v; want ErrNoRoute", err)
	}
	if _, err := factTestResolveOwner(t, env.fs, netip.MustParseAddr("2001:db8::1"), factTestNow); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("non-IPv4 error = %v; want ErrFactMalformed", err)
	}
	if _, err := factTestResolveOwner(t, env.fs, netip.Addr{}, factTestNow); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("invalid address error = %v; want ErrFactMalformed", err)
	}
	var nilStore *FactStore
	if _, err := nilStore.ResolveAddressOwner(ip, factTestNow); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("nil store error = %v; want ErrFactMalformed", err)
	}

	// A different ContextID must never see this owner.
	other := newFactTestEnv(t, t.TempDir(), factTestContextB, factTestKey("identity-current-other"))
	if _, err := factTestResolveOwner(t, other.fs, ip, factTestNow); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("cross-context lookup error = %v; want ErrNoRoute", err)
	}
}

func TestFactStoreResolveAddressOwnerStickyFailureAndFloorsUnchanged(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-current-sticky"))
	ip := netip.MustParseAddr("10.20.0.19")
	owner := factTestNodeID(factTestPub(1250))
	record := factTestAddressRecord(owner, ip, FactVersion{1, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1251, 1), []FactRecord{record}, factTestNow); err != nil {
		t.Fatalf("commit address: %v", err)
	}

	floors := make(map[string]hwmEntry, len(env.fs.hwm))
	for key, floor := range env.fs.hwm {
		floors[key] = floor
	}
	entriesBefore := len(env.fs.entries)
	for attempt := 0; attempt < 4; attempt++ {
		if _, err := factTestResolveOwner(t, env.fs, ip, factTestNow); err != nil {
			t.Fatalf("resolve attempt %d: %v", attempt, err)
		}
	}
	if !reflect.DeepEqual(floors, env.fs.hwm) {
		t.Fatal("address owner lookup changed the high-watermark floors")
	}
	if len(env.fs.entries) != entriesBefore {
		t.Fatal("address owner lookup changed the live entry set")
	}

	// A real persistence failure must surface as the sticky store error, never as
	// an absent or conflicting route.
	// Inject a persistence failure through the state store's test seam. The disk
	// path used to be broken by removing the watermark file; state is now in memory,
	// so the equivalent is a refused write.
	security.SetRecordWriteFailureForTest(t, true)
	failing := factTestNodeRecord(factTestPub(1251), nil, FactVersion{9, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 2, factTestSource(env.contextID, 1252, 1), []FactRecord{failing}, factTestNow); !errors.Is(err, ErrFactStoreFailed) {
		t.Fatalf("setup persistence failure = %v; want ErrFactStoreFailed", err)
	}
	if _, err := factTestResolveOwner(t, env.fs, ip, factTestNow); !errors.Is(err, ErrFactStoreFailed) || errors.Is(err, ErrNoRoute) || errors.Is(err, ErrRouteConflict) {
		t.Fatalf("sticky failure lookup error = %v; want ErrFactStoreFailed only", err)
	}
}

func factTestLinkRef(id, epoch uint64, lane uint8) LinkRef {
	return LinkRef{ID: id, Epoch: epoch, LaneID: lane, ConnectionType: "tcp"}
}

// factTestPinnedPath commits one live NODE fact per public key and one live LINK
// fact per segment from one authenticated source, returning the derived path.
func factTestPinnedPath(t *testing.T, env *factTestEnv, source FactSource, snapshotVersion uint64, publics [][32]byte, linkIDs []uint64, epoch uint64, lane uint8, version FactVersion, issuedAt, expiresAt uint64, now time.Time) ([]NodeID, []LinkRef) {
	t.Helper()
	nodes := make([]NodeID, 0, len(publics))
	records := make([]FactRecord, 0, len(publics)+len(linkIDs))
	for _, public := range publics {
		records = append(records, factTestNodeRecord(public, nil, version, issuedAt, expiresAt))
		nodes = append(nodes, factTestNodeID(public))
	}
	refs := make([]LinkRef, 0, len(linkIDs))
	for index, linkID := range linkIDs {
		records = append(records, factTestLinkRecord(nodes[index], nodes[index+1], linkID, epoch, lane, "tcp", version, issuedAt, expiresAt))
		refs = append(refs, factTestLinkRef(linkID, epoch, lane))
	}
	if err := factTestCommit(t, env.fs, 1, snapshotVersion, source, records, now); err != nil {
		t.Fatalf("commit pinned path: %v", err)
	}
	return nodes, refs
}

func TestFactStoreResolvePinnedLinksCurrentAndRenewal(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-pinned-current"))
	source := factTestSource(env.contextID, 1300, 1)
	publicA := factTestPub(1301)
	publicB := factTestPub(1302)
	nodes, refs := factTestPinnedPath(t, env, source, 1, [][32]byte{publicA, publicB}, []uint64{7}, 1, FactLanePacket, FactVersion{1, 1}, factTestIssued, factTestExpires, factTestNow)
	if err := env.fs.ResolvePinnedLinks(nodes, refs, FactLanePacket, factTestNow); err != nil {
		t.Fatalf("current pinned path: %v", err)
	}

	// The same instances renewed with higher versions and a new TTL must still
	// match: the check compares instance identity, never a fact version.
	renewedIssued := factTestIssued + 10_000
	renewedExpires := renewedIssued + 45_000
	renewedNow := time.UnixMilli(int64(renewedIssued))
	renewedNodes, renewedRefs := factTestPinnedPath(t, env, source, 2, [][32]byte{publicA, publicB}, []uint64{7}, 1, FactLanePacket, FactVersion{1, 2}, renewedIssued, renewedExpires, renewedNow)
	if err := env.fs.ResolvePinnedLinks(renewedNodes, renewedRefs, FactLanePacket, renewedNow); err != nil {
		t.Fatalf("renewed same instances: %v", err)
	}

	// A LINK fact may be authored by either physical side of the same instance.
	// A second source contributes it so the first source's complete snapshot is
	// not partially replaced.
	second := factTestSource(env.contextID, 1303, 1)
	reverse := factTestLinkRecord(nodes[1], nodes[0], 7, 1, FactLanePacket, "tcp", FactVersion{1, 3}, renewedIssued, renewedExpires)
	if err := factTestCommit(t, env.fs, 1, 3, second, []FactRecord{reverse}, renewedNow); err != nil {
		t.Fatalf("commit reverse-authored link: %v", err)
	}
	if err := env.fs.ResolvePinnedLinks(nodes, refs, FactLanePacket, renewedNow); err != nil {
		t.Fatalf("reverse-authored link instance: %v", err)
	}

	// The STREAM lane uses the same seam with its own lane value.
	streamIssued := factTestIssued + 20_000
	streamNow := time.UnixMilli(int64(streamIssued))
	streamSource := factTestSource(env.contextID, 1304, 1)
	streamNodes, streamRefs := factTestPinnedPath(t, env, streamSource, 1, [][32]byte{publicA, publicB}, []uint64{8}, 1, FactLaneStream, FactVersion{1, 4}, streamIssued, streamIssued+45_000, streamNow)
	if err := env.fs.ResolvePinnedLinks(streamNodes, streamRefs, FactLaneStream, streamNow); err != nil {
		t.Fatalf("stream lane pinned path: %v", err)
	}
	if err := env.fs.ResolvePinnedLinks(streamNodes, streamRefs, FactLanePacket, streamNow); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("lane mismatch error = %v; want ErrFactMalformed", err)
	}
}

func TestFactStoreResolvePinnedLinksRejectsMissingRevokedExpiredWithdrawn(t *testing.T) {
	type pinnedFixture struct {
		env     *factTestEnv
		source  FactSource
		publics [][32]byte
		nodes   []NodeID
		refs    []LinkRef
	}
	newPath := func(t *testing.T) pinnedFixture {
		t.Helper()
		env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-pinned-reject"))
		source := factTestSource(env.contextID, 1310, 1)
		publics := [][32]byte{factTestPub(1311), factTestPub(1312)}
		nodes, refs := factTestPinnedPath(t, env, source, 1, publics, []uint64{9}, 1, FactLanePacket, FactVersion{1, 1}, factTestIssued, factTestExpires, factTestNow)
		return pinnedFixture{env: env, source: source, publics: publics, nodes: nodes, refs: refs}
	}

	t.Run("missing node", func(t *testing.T) {
		fixture := newPath(t)
		strangerPublic := factTestPub(1313)
		stranger := factTestNodeID(strangerPublic)
		link := factTestLinkRecord(fixture.nodes[0], stranger, 9, 1, FactLanePacket, "tcp", FactVersion{1, 1}, factTestIssued, factTestExpires)
		if err := factTestCommit(t, fixture.env.fs, 1, 1, factTestSource(fixture.env.contextID, 1340, 1), []FactRecord{link}, factTestNow); err != nil {
			t.Fatalf("commit stranger link: %v", err)
		}
		path := []NodeID{fixture.nodes[0], stranger}
		if err := fixture.env.fs.ResolvePinnedLinks(path, fixture.refs, FactLanePacket, factTestNow); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("missing node error = %v; want ErrNoRoute", err)
		}
	})

	t.Run("missing link", func(t *testing.T) {
		fixture := newPath(t)
		otherPublic := factTestPub(1314)
		other := factTestNodeID(otherPublic)
		if err := factTestCommit(t, fixture.env.fs, 1, 1, factTestSource(fixture.env.contextID, 1341, 1), []FactRecord{factTestNodeRecord(otherPublic, nil, FactVersion{1, 1}, factTestIssued, factTestExpires)}, factTestNow); err != nil {
			t.Fatalf("commit extra node: %v", err)
		}
		path := []NodeID{fixture.nodes[0], other}
		if err := fixture.env.fs.ResolvePinnedLinks(path, []LinkRef{factTestLinkRef(9, 1, FactLanePacket)}, FactLanePacket, factTestNow); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("missing link error = %v; want ErrNoRoute", err)
		}
	})

	t.Run("revoked node", func(t *testing.T) {
		fixture := newPath(t)
		target := fixture.nodes[1]
		revoker := factTestNodeID(factTestPub(1315))
		revocation := factTestRevocationRecord(revoker, target, FactNode, target[:], FactVersion{1, 1}, FactVersion{1, 3}, factTestIssued, factTestExpires)
		if err := factTestCommit(t, fixture.env.fs, 1, 1, factTestSource(fixture.env.contextID, 1316, 1), []FactRecord{revocation}, factTestNow); err != nil {
			t.Fatalf("commit node revocation: %v", err)
		}
		if err := fixture.env.fs.ResolvePinnedLinks(fixture.nodes, fixture.refs, FactLanePacket, factTestNow); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("revoked node error = %v; want ErrNoRoute", err)
		}
	})

	t.Run("expired node", func(t *testing.T) {
		env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-pinned-expired"))
		source := factTestSource(env.contextID, 1317, 1)
		publics := [][32]byte{factTestPub(1318), factTestPub(1319)}
		nodeA := factTestNodeID(publics[0])
		nodeB := factTestNodeID(publics[1])
		shortExpires := factTestIssued + 5_000
		records := []FactRecord{
			factTestNodeRecord(publics[0], nil, FactVersion{1, 1}, factTestIssued, factTestExpires),
			factTestNodeRecord(publics[1], nil, FactVersion{1, 1}, factTestIssued, shortExpires),
			factTestLinkRecord(nodeA, nodeB, 9, 1, FactLanePacket, "tcp", FactVersion{1, 1}, factTestIssued, factTestExpires),
		}
		if err := factTestCommit(t, env.fs, 1, 1, source, records, factTestNow); err != nil {
			t.Fatalf("commit short-lived node: %v", err)
		}
		nodes := []NodeID{nodeA, nodeB}
		refs := []LinkRef{factTestLinkRef(9, 1, FactLanePacket)}
		if err := env.fs.ResolvePinnedLinks(nodes, refs, FactLanePacket, factTestNow); err != nil {
			t.Fatalf("live path before expiry: %v", err)
		}
		afterExpiry := time.UnixMilli(int64(uint64(factTestNow.UnixMilli()) + (shortExpires - factTestIssued) + factClockSkewMillis + 1))
		if err := env.fs.ResolvePinnedLinks(nodes, refs, FactLanePacket, afterExpiry); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("expired node error = %v; want ErrNoRoute", err)
		}
	})

	t.Run("withdrawn source", func(t *testing.T) {
		fixture := newPath(t)
		if err := fixture.env.fs.WithdrawSource(fixture.source, factTestNow); err != nil {
			t.Fatalf("withdraw source: %v", err)
		}
		if err := fixture.env.fs.ResolvePinnedLinks(fixture.nodes, fixture.refs, FactLanePacket, factTestNow); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("withdrawn path error = %v; want ErrNoRoute", err)
		}
	})

	t.Run("changed link epoch", func(t *testing.T) {
		fixture := newPath(t)
		changed := factTestLinkRecord(fixture.nodes[0], fixture.nodes[1], 9, 2, FactLanePacket, "tcp", FactVersion{1, 2}, factTestIssued, factTestExpires)
		if err := factTestCommit(t, fixture.env.fs, 1, 1, factTestSource(fixture.env.contextID, 1342, 1), []FactRecord{changed}, factTestNow); err != nil {
			t.Fatalf("commit changed epoch: %v", err)
		}
		if err := fixture.env.fs.ResolvePinnedLinks(fixture.nodes, fixture.refs, FactLanePacket, factTestNow); !errors.Is(err, ErrRouteStale) {
			t.Fatalf("changed LinkEpoch error = %v; want ErrRouteStale", err)
		}
	})
}

func TestFactStoreResolvePinnedLinksMultiSegmentShapeAndStickyFailure(t *testing.T) {
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-pinned-shape"))
	source := factTestSource(env.contextID, 1320, 1)
	publics := [][32]byte{factTestPub(1321), factTestPub(1322), factTestPub(1323)}
	nodes, refs := factTestPinnedPath(t, env, source, 1, publics, []uint64{11, 12}, 1, FactLanePacket, FactVersion{1, 1}, factTestIssued, factTestExpires, factTestNow)
	if err := env.fs.ResolvePinnedLinks(nodes, refs, FactLanePacket, factTestNow); err != nil {
		t.Fatalf("multi-segment path: %v", err)
	}

	// A single live but stale segment makes the whole pinned path stale.
	changed := factTestLinkRecord(nodes[1], nodes[2], 12, 2, FactLanePacket, "tcp", FactVersion{1, 2}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, env.fs, 1, 1, factTestSource(env.contextID, 1343, 1), []FactRecord{changed}, factTestNow); err != nil {
		t.Fatalf("commit changed segment: %v", err)
	}
	if err := env.fs.ResolvePinnedLinks(nodes, refs, FactLanePacket, factTestNow); !errors.Is(err, ErrRouteStale) {
		t.Fatalf("multi-segment changed epoch error = %v; want ErrRouteStale", err)
	}

	// A single live node with no segment is the degenerate valid path.
	if err := env.fs.ResolvePinnedLinks([]NodeID{nodes[0]}, nil, FactLanePacket, factTestNow); err != nil {
		t.Fatalf("degenerate single-node path: %v", err)
	}
	missing := factTestNodeID(factTestPub(1324))
	if err := env.fs.ResolvePinnedLinks([]NodeID{missing}, nil, FactLanePacket, factTestNow); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("degenerate missing node error = %v; want ErrNoRoute", err)
	}

	manyNodes := make([]NodeID, 0, maxRouteHops+2)
	manyRefs := make([]LinkRef, 0, maxRouteHops+1)
	for index := 0; index <= maxRouteHops+1; index++ {
		manyNodes = append(manyNodes, factTestNodeID(factTestPub(uint64(1400+index))))
		if index > 0 {
			manyRefs = append(manyRefs, factTestLinkRef(uint64(1400+index), 1, FactLanePacket))
		}
	}
	shape := []struct {
		name  string
		nodes []NodeID
		refs  []LinkRef
		lane  uint8
	}{
		{"empty path", nil, nil, FactLanePacket},
		{"refs one too many", nodes[:2], []LinkRef{factTestLinkRef(11, 1, FactLanePacket), factTestLinkRef(12, 1, FactLanePacket)}, FactLanePacket},
		{"empty node", []NodeID{{}, nodes[1]}, []LinkRef{factTestLinkRef(11, 1, FactLanePacket)}, FactLanePacket},
		{"repeated node", []NodeID{nodes[0], nodes[1], nodes[0]}, []LinkRef{factTestLinkRef(11, 1, FactLanePacket), factTestLinkRef(12, 1, FactLanePacket)}, FactLanePacket},
		{"self loop", []NodeID{nodes[0], nodes[0]}, []LinkRef{factTestLinkRef(11, 1, FactLanePacket)}, FactLanePacket},
		{"control lane", nodes, refs, FactLaneControl},
		{"ref lane mismatch", nodes, []LinkRef{factTestLinkRef(11, 1, FactLaneStream), factTestLinkRef(12, 1, FactLanePacket)}, FactLanePacket},
		{"zero link id", nodes, []LinkRef{factTestLinkRef(0, 1, FactLanePacket), factTestLinkRef(12, 1, FactLanePacket)}, FactLanePacket},
		{"zero epoch", nodes, []LinkRef{factTestLinkRef(11, 0, FactLanePacket), factTestLinkRef(12, 1, FactLanePacket)}, FactLanePacket},
		{"too many hops", manyNodes, manyRefs, FactLanePacket},
	}
	for _, test := range shape {
		if err := env.fs.ResolvePinnedLinks(test.nodes, test.refs, test.lane, factTestNow); !errors.Is(err, ErrFactMalformed) {
			t.Fatalf("%s error = %v; want ErrFactMalformed", test.name, err)
		}
	}
	var nilStore *FactStore
	if err := nilStore.ResolvePinnedLinks(nodes, refs, FactLanePacket, factTestNow); !errors.Is(err, ErrFactMalformed) {
		t.Fatalf("nil store error = %v; want ErrFactMalformed", err)
	}

	// A real persistence failure must surface as the sticky store error, never as
	// a missing route.
	fresh := newFactTestEnv(t, t.TempDir(), factTestContextA, factTestKey("identity-pinned-sticky"))
	stickyNodes, stickyRefs := factTestPinnedPath(t, fresh, factTestSource(fresh.contextID, 1330, 1), 1, publics[:2], []uint64{13}, 1, FactLanePacket, FactVersion{1, 1}, factTestIssued, factTestExpires, factTestNow)
	security.SetRecordWriteFailureForTest(t, true)
	failing := factTestNodeRecord(factTestPub(1331), nil, FactVersion{9, 1}, factTestIssued, factTestExpires)
	if err := factTestCommit(t, fresh.fs, 1, 2, factTestSource(fresh.contextID, 1332, 1), []FactRecord{failing}, factTestNow); !errors.Is(err, ErrFactStoreFailed) {
		t.Fatalf("setup persistence failure = %v; want ErrFactStoreFailed", err)
	}
	if err := fresh.fs.ResolvePinnedLinks(stickyNodes, stickyRefs, FactLanePacket, factTestNow); !errors.Is(err, ErrFactStoreFailed) || errors.Is(err, ErrNoRoute) {
		t.Fatalf("sticky pinned path error = %v; want ErrFactStoreFailed only", err)
	}
}
