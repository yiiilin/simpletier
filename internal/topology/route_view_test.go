package topology

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"testing"
	"time"
)

type routeViewFixture struct {
	t         *testing.T
	env       *factTestEnv
	now       time.Time
	issuedAt  uint64
	expiresAt uint64
	source    FactSource
	snapshot  uint64
	facts     map[string]FactRecord
	nodes     map[string]NodeID
	active    LocalLinkValidator
}

func newRouteViewFixture(t *testing.T) *routeViewFixture {
	t.Helper()
	key := factTestKey("route-view/" + t.Name())
	env := newFactTestEnv(t, t.TempDir(), factTestContextA, key)
	now := time.Now().UTC().Truncate(time.Millisecond)
	issuedAt := uint64(now.Add(-time.Second).UnixMilli())
	fixture := &routeViewFixture{
		t:         t,
		env:       env,
		now:       now,
		issuedAt:  issuedAt,
		expiresAt: issuedAt + 45_000,
		source:    factTestSource(env.contextID, 9001, 1),
		facts:     make(map[string]FactRecord),
		nodes:     make(map[string]NodeID),
		active:    func(uint64, uint64, uint8, NodeID) bool { return true },
	}
	fixture.addNode("local", factTestLocalPublic(env.privateKey), "endpoint.tcp", "packet.ipv4")
	return fixture
}

func (f *routeViewFixture) addNode(name string, public [32]byte, capabilities ...string) NodeID {
	f.t.Helper()
	sort.Strings(capabilities)
	record := factTestNodeRecord(public, capabilities, FactVersion{Incarnation: 1, Sequence: 1}, f.issuedAt, f.expiresAt)
	f.put(record)
	f.nodes[name] = factTestNodeID(public)
	return f.nodes[name]
}

func (f *routeViewFixture) remote(name string, seed uint64, relay bool) NodeID {
	capabilities := []string{}
	if relay {
		capabilities = append(capabilities, "relay")
	}
	return f.addNode(name, factTestPub(seed), capabilities...)
}

func (f *routeViewFixture) link(from, to NodeID, id uint64, lane uint8, connectionType string, cost LinkCost) FactRecord {
	f.t.Helper()
	record := factTestLinkRecord(from, to, id, id+10_000, lane, connectionType, FactVersion{Incarnation: 1, Sequence: 1}, f.issuedAt, f.expiresAt)
	payload := record.Payload.(LinkPayload)
	payload.Cost = cost
	record.Payload = payload
	f.put(record)
	return record
}

func (f *routeViewFixture) connected(from, to NodeID, dataID uint64, lane uint8, connectionType string, cost LinkCost) FactRecord {
	f.link(from, to, dataID+100_000, FactLaneControl, "control", LinkCost{})
	return f.link(from, to, dataID, lane, connectionType, cost)
}

func (f *routeViewFixture) address(node NodeID, ip netip.Addr, version FactVersion) FactRecord {
	f.t.Helper()
	record := factTestAddressRecord(node, ip, version, f.issuedAt, f.expiresAt)
	f.put(record)
	return record
}

func (f *routeViewFixture) put(record FactRecord) {
	f.t.Helper()
	f.facts[string(factTestFactKey(f.t, record))] = copyFactRecord(record)
}

func (f *routeViewFixture) commit() {
	f.t.Helper()
	f.snapshot++
	records := make([]FactRecord, 0, len(f.facts))
	for _, record := range f.facts {
		records = append(records, copyFactRecord(record))
	}
	if err := factTestCommit(f.t, f.env.fs, 1, f.snapshot, f.source, records, f.now); err != nil {
		f.t.Fatalf("commit route facts: %v", err)
	}
}

func (f *routeViewFixture) view() *RouteView {
	f.t.Helper()
	view, err := NewRouteView(f.env.fs, f.active)
	if err != nil {
		f.t.Fatalf("NewRouteView: %v", err)
	}
	return view
}

func TestRouteViewRequiresLocalValidatorAndDataLane(t *testing.T) {
	fixture := newRouteViewFixture(t)
	if _, err := NewRouteView(fixture.env.fs, nil); !errors.Is(err, ErrInvalidFact) {
		t.Fatalf("nil active-link validator error = %v; want ErrInvalidFact", err)
	}
	destination := fixture.remote("destination", 1, false)
	fixture.link(fixture.nodes["local"], destination, 1, FactLaneControl, "unknown-control-type", LinkCost{})
	fixture.commit()
	view := fixture.view()
	if _, err := view.Candidates(destination, FactLanePacket, RoutePolicy{}); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("control-only facts produced a data route: %v", err)
	}
	if _, err := view.Candidates(destination, FactLaneControl, RoutePolicy{}); !errors.Is(err, ErrInvalidFact) {
		t.Fatalf("CONTROL route query error = %v; want ErrInvalidFact", err)
	}
}

func TestRouteViewParallelLinkInstancesAndRevocation(t *testing.T) {
	fixture := newRouteViewFixture(t)
	destination := fixture.remote("destination", 2, false)
	fixture.link(fixture.nodes["local"], destination, 100, FactLaneControl, "ctl-a", LinkCost{})
	first := fixture.link(fixture.nodes["local"], destination, 10, FactLanePacket, "unknown-literal", LinkCost{})
	fixture.link(fixture.nodes["local"], destination, 20, FactLanePacket, "tcp", LinkCost{})
	fixture.link(fixture.nodes["local"], destination, 5, FactLanePacket, "expensive", LinkCost{RTTMillis: 50})
	fixture.commit()
	view := fixture.view()

	paths, err := view.Candidates(destination, FactLanePacket, RoutePolicy{})
	if err != nil {
		t.Fatalf("Candidates before revoke: %v", err)
	}
	if len(paths) != 3 || paths[0].Links[0].ID != 10 || paths[0].Links[0].ConnectionType != "unknown-literal" || paths[1].Links[0].ID != 20 || paths[2].Links[0].ID != 5 {
		t.Fatalf("parallel paths = %+v; want cost order 10, 20, then higher-cost ID 5", paths)
	}

	payload := first.Payload.(LinkPayload)
	revocation := factTestRevocationRecord(destination, first.Envelope.Origin, FactLink,
		factTestLinkTarget(payload.From, payload.To, payload.LaneID, payload.LinkID), first.Envelope.Version,
		FactVersion{Incarnation: 1, Sequence: 2}, fixture.issuedAt, fixture.expiresAt)
	fixture.put(revocation)
	fixture.commit()
	paths, err = view.Candidates(destination, FactLanePacket, RoutePolicy{})
	if err != nil || len(paths) != 2 || paths[0].Links[0].ID != 20 || paths[1].Links[0].ID != 5 || paths[0].Freshness != RouteViewStale || paths[1].Freshness != RouteViewStale {
		t.Fatalf("stale view after revocation = %+v, %v; want unaffected LinkIDs 20 and 5 marked stale", paths, err)
	}
	if err := view.Refresh(time.Now()); err != nil {
		t.Fatalf("Refresh after revocation: %v", err)
	}
	paths, err = view.Candidates(destination, FactLanePacket, RoutePolicy{})
	if err != nil {
		t.Fatalf("Candidates after revoking one instance: %v", err)
	}
	if len(paths) != 2 || paths[0].Links[0].ID != 20 || paths[1].Links[0].ID != 5 {
		t.Fatalf("remaining paths = %+v; revoking LinkID 10 must retain LinkIDs 20 and 5", paths)
	}
}

func TestRouteViewFiltersLaneBeforeThreeCandidateLimit(t *testing.T) {
	fixture := newRouteViewFixture(t)
	destination := fixture.remote("destination", 3, false)
	fixture.link(fixture.nodes["local"], destination, 700, FactLaneControl, "ctl", LinkCost{})
	for id := uint64(1); id <= 3; id++ {
		fixture.link(fixture.nodes["local"], destination, id, FactLaneStream, "stream", LinkCost{})
	}
	fixture.link(fixture.nodes["local"], destination, 900, FactLanePacket, "packet", LinkCost{RTTMillis: 50})
	fixture.commit()
	view := fixture.view()

	paths, err := view.Candidates(destination, FactLanePacket, RoutePolicy{})
	if err != nil {
		t.Fatalf("PACKET candidates: %v", err)
	}
	if len(paths) != 1 || paths[0].LaneID != FactLanePacket || paths[0].Links[0].ID != 900 {
		t.Fatalf("PACKET candidates = %+v; STREAM links must not consume the cap", paths)
	}
	streamPaths, err := view.Candidates(destination, FactLaneStream, RoutePolicy{})
	if err != nil {
		t.Fatalf("STREAM candidates: %v", err)
	}
	if len(streamPaths) != 3 {
		t.Fatalf("STREAM candidate count = %d; want 3", len(streamPaths))
	}
}

func TestRouteViewCostAndStableTieBreaks(t *testing.T) {
	t.Run("fixed integer cost", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		destination := fixture.remote("destination", 4, false)
		cost := LinkCost{RTTMillis: 10, JitterMicros: 20_000, LossPPM: 50_000, QueueMicros: 40_000, ReconnectsLast5m: 2}
		fixture.connected(fixture.nodes["local"], destination, 15, FactLanePacket, "future-type", cost)
		fixture.commit()
		paths, err := fixture.view().Candidates(destination, FactLanePacket, RoutePolicy{})
		if err != nil {
			t.Fatalf("Candidates: %v", err)
		}
		if got, want := paths[0].Cost, PathCost(7_700_000); got != want {
			t.Fatalf("Cost = %d; want %d", got, want)
		}
	})

	t.Run("stable node and link tie breaks with copies", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		middleA := fixture.remote("middle-a", 5, true)
		middleB := fixture.remote("middle-b", 6, true)
		if bytes.Compare(middleA[:], middleB[:]) > 0 {
			middleA, middleB = middleB, middleA
		}
		destination := fixture.remote("destination", 7, false)
		fixture.connected(fixture.nodes["local"], middleA, 41, FactLanePacket, "x", LinkCost{})
		fixture.connected(middleA, destination, 42, FactLanePacket, "x", LinkCost{})
		fixture.connected(fixture.nodes["local"], middleB, 51, FactLanePacket, "x", LinkCost{})
		fixture.connected(middleB, destination, 52, FactLanePacket, "x", LinkCost{})
		fixture.commit()
		view := fixture.view()
		paths, err := view.Candidates(destination, FactLanePacket, RoutePolicy{AllowRelay: true})
		if err != nil {
			t.Fatalf("Candidates: %v", err)
		}
		if len(paths) != 2 || paths[0].Nodes[1] != middleA || paths[1].Nodes[1] != middleB {
			t.Fatalf("equal-cost paths are not ordered by NodeID: %+v", paths)
		}
		paths[0].Nodes[0] = NodeID{}
		paths[0].Links[0].ID = 999_999
		again, err := view.Candidates(destination, FactLanePacket, RoutePolicy{AllowRelay: true})
		if err != nil {
			t.Fatalf("Candidates after mutating returned slices: %v", err)
		}
		if again[0].Nodes[0] != fixture.nodes["local"] || again[0].Links[0].ID != 41 {
			t.Fatalf("caller mutation leaked into RouteView: %+v", again[0])
		}
	})
}

func TestRouteViewRelayLoopsAndHopLimit(t *testing.T) {
	t.Run("policy and relay capability", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		middle := fixture.remote("middle", 8, false)
		destination := fixture.remote("destination", 9, false)
		fixture.connected(fixture.nodes["local"], middle, 1, FactLanePacket, "x", LinkCost{})
		fixture.connected(middle, destination, 2, FactLanePacket, "x", LinkCost{})
		fixture.commit()
		view := fixture.view()
		if _, err := view.Candidates(destination, FactLanePacket, RoutePolicy{AllowRelay: true}); !errors.Is(err, ErrPolicyDenied) {
			t.Fatalf("non-relay intermediate error = %v; want ErrPolicyDenied", err)
		}

	})

	t.Run("simple paths and 16 hop maximum", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		middle := fixture.remote("middle", 10, true)
		destination := fixture.remote("destination", 11, false)
		fixture.connected(fixture.nodes["local"], middle, 11, FactLanePacket, "x", LinkCost{})
		fixture.connected(middle, destination, 12, FactLanePacket, "x", LinkCost{})
		fixture.connected(fixture.nodes["local"], destination, 13, FactLanePacket, "x", LinkCost{RTTMillis: 10})
		fixture.commit()
		paths, err := fixture.view().Candidates(destination, FactLanePacket, RoutePolicy{AllowRelay: true})
		if err != nil {
			t.Fatalf("Candidates: %v", err)
		}
		for _, path := range paths {
			if len(path.Nodes) != len(path.Links)+1 || len(path.Links) > maxRouteHops {
				t.Fatalf("malformed path lengths: %+v", path)
			}
			seen := make(map[NodeID]bool)
			for _, node := range path.Nodes {
				if seen[node] {
					t.Fatalf("route contains loop: %+v", path)
				}
				seen[node] = true
			}
		}

		long := newRouteViewFixture(t)
		previous := long.nodes["local"]
		var target NodeID
		for index := 1; index <= maxRouteHops+1; index++ {
			target = long.remote(fmt.Sprintf("node-%d", index), uint64(100+index), index != maxRouteHops+1)
			long.connected(previous, target, uint64(index), FactLanePacket, "x", LinkCost{})
			previous = target
		}
		long.commit()
		if _, err := long.view().Candidates(target, FactLanePacket, RoutePolicy{AllowRelay: true}); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("17-hop route error = %v; want ErrNoRoute", err)
		}
	})
}

func TestRouteViewYenSpurRespectsRemainingHopBudget(t *testing.T) {
	fixture := newRouteViewFixture(t)
	start := fixture.nodes["local"]
	first := fixture.remote("first", 30, true)
	destination := fixture.remote("destination", 31, false)
	linkID := uint64(1)
	connect := func(from, to NodeID, cost LinkCost) {
		fixture.connected(from, to, linkID, FactLanePacket, "tcp", cost)
		linkID++
	}
	connect(start, first, LinkCost{})

	addBranch := func(seed uint64, intermediateCount int, cost LinkCost) {
		previous := first
		for index := 0; index < intermediateCount; index++ {
			node := fixture.remote(fmt.Sprintf("branch-%d-%d", seed, index), seed+uint64(index)+1, true)
			connect(previous, node, cost)
			previous = node
		}
		connect(previous, destination, cost)
	}
	addBranch(100, 14, LinkCost{})              // Main route: 16 hops including start -> first.
	addBranch(200, 15, LinkCost{})              // Cheapest spur: 17 total hops, must be skipped.
	addBranch(300, 14, LinkCost{RTTMillis: 50}) // More expensive spur: exactly 16 total hops.
	fixture.commit()

	paths, err := fixture.view().Candidates(destination, FactLanePacket, RoutePolicy{AllowRelay: true})
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(paths) != 2 || len(paths[0].Links) != maxRouteHops || len(paths[1].Links) != maxRouteHops {
		t.Fatalf("Yen candidates = %+v; want two legal 16-hop paths", paths)
	}
	if paths[0].Cost >= paths[1].Cost {
		t.Fatalf("candidates are not ordered by cost: first=%d second=%d", paths[0].Cost, paths[1].Cost)
	}
}

func TestRouteViewHopBudgetKeepsShorterPrefixLabels(t *testing.T) {
	fixture := newRouteViewFixture(t)
	source := fixture.nodes["local"]
	join := fixture.remote("join", 40, true)
	queue := fixture.remote("queue", 41, true)
	destination := fixture.remote("destination", 42, false)
	linkID := uint64(1)
	connect := func(from, to NodeID, cost LinkCost) {
		fixture.connected(from, to, linkID, FactLanePacket, "tcp", cost)
		linkID++
	}

	previous := source
	for index := 0; index < 14; index++ {
		middle := fixture.remote(fmt.Sprintf("cheap-%d", index), uint64(100+index), true)
		connect(previous, middle, LinkCost{})
		previous = middle
	}
	connect(previous, join, LinkCost{})
	connect(join, queue, LinkCost{})
	connect(queue, destination, LinkCost{})

	short := fixture.remote("short", 200, true)
	expensive := LinkCost{RTTMillis: 1_000}
	connect(source, short, expensive)
	connect(short, join, expensive)
	fixture.commit()

	paths, err := fixture.view().Candidates(destination, FactLanePacket, RoutePolicy{AllowRelay: true})
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(paths) != 1 || len(paths[0].Links) != 4 || paths[0].Nodes[1] != short {
		t.Fatalf("hop-constrained candidate = %+v; want the expensive four-hop route", paths)
	}
}

func TestRouteViewControlInstancesLocalValidationAndNoDataMock(t *testing.T) {
	fixture := newRouteViewFixture(t)
	peer := fixture.remote("peer", 12, false)
	local := fixture.nodes["local"]
	fixture.link(local, peer, 101, FactLaneControl, "control-1", LinkCost{})
	fixture.link(local, peer, 102, FactLaneControl, "control-2", LinkCost{})
	fixture.link(local, peer, 103, FactLanePacket, "packet", LinkCost{})
	fixture.commit()
	active := map[uint64]bool{101: false, 102: true, 103: false}
	fixture.active = func(linkID, epoch uint64, lane uint8, gotPeer NodeID) bool {
		return gotPeer == peer && active[linkID]
	}
	view := fixture.view()
	if _, err := view.Candidates(peer, FactLanePacket, RoutePolicy{}); !errors.Is(err, ErrRouteStale) {
		t.Fatalf("inactive local PACKET link error = %v; want ErrRouteStale", err)
	}
	active[103] = true
	paths, err := view.Candidates(peer, FactLanePacket, RoutePolicy{})
	if err != nil || len(paths) != 1 {
		t.Fatalf("route did not recover when the local PACKET link became active: paths=%v err=%v", paths, err)
	}
	active[103] = false
	if _, err := view.Candidates(peer, FactLanePacket, RoutePolicy{}); !errors.Is(err, ErrRouteStale) {
		t.Fatalf("inactive local PACKET link error = %v; want ErrRouteStale", err)
	}
	active[103] = true
	active[102] = false
	if _, err := view.Candidates(peer, FactLanePacket, RoutePolicy{}); !errors.Is(err, ErrRouteStale) {
		t.Fatalf("inactive local CONTROL link error = %v; want ErrRouteStale", err)
	}

	noData := newRouteViewFixture(t)
	remote := noData.remote("remote", 13, false)
	noData.link(noData.nodes["local"], remote, 201, FactLaneControl, "control", LinkCost{})
	noData.commit()
	if _, err := noData.view().Candidates(remote, FactLanePacket, RoutePolicy{}); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("CONTROL-only fact graph error = %v; want ErrNoRoute", err)
	}
}

func TestRouteViewAddressConflictVersionPinAndPacketRoute(t *testing.T) {
	t.Run("packet route pins unique IPv4 owner", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		destination := fixture.remote("destination", 14, false)
		ip := netip.MustParseAddr("10.20.30.40")
		address := fixture.address(destination, ip, FactVersion{1, 1})
		fixture.connected(fixture.nodes["local"], destination, 301, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		view := fixture.view()
		resolution, err := view.ResolveVirtualIP(ip)
		if err != nil || resolution.NodeID != destination || resolution.Prefix != netip.PrefixFrom(ip, 32) || resolution.FactVersion != address.Envelope.Version {
			t.Fatalf("ResolveVirtualIP = %+v, %v", resolution, err)
		}
		route, err := view.PacketCandidates(ip, RoutePolicy{})
		if err != nil || route.LaneID != FactLanePacket || route.AddressFactVersion != address.Envelope.Version || len(route.Candidates) != 1 {
			t.Fatalf("PacketCandidates = %+v, %v", route, err)
		}

		updated := address
		updated.Envelope.Version = FactVersion{1, 2}
		fixture.put(updated)
		fixture.commit()
		// A renewed AddressFact of the SAME owner is a normal re-advertisement,
		// not a change of mapping: it carries a higher version but still names the
		// same /32 owner, so the lookup must succeed with the live version pinned
		// even though the immutable view has not been rebuilt yet.
		renewed, err := view.ResolveVirtualIP(ip)
		if err != nil || renewed.NodeID != destination || compareFactVersion(renewed.FactVersion, FactVersion{1, 2}) != 0 {
			t.Fatalf("renewed same-owner AddressFact = %+v, %v; want owner %x pinned at version 1.2", renewed, err, destination)
		}
	})

	t.Run("conflicting live owners never select lower NodeID", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		ownerA := fixture.remote("owner-a", 15, false)
		ownerB := fixture.remote("owner-b", 16, false)
		ip := netip.MustParseAddr("10.20.30.41")
		fixture.address(ownerA, ip, FactVersion{1, 1})
		fixture.connected(fixture.nodes["local"], ownerA, 311, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		view := fixture.view()
		fixture.address(ownerB, ip, FactVersion{1, 1})
		fixture.connected(fixture.nodes["local"], ownerB, 312, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		if _, err := view.ResolveVirtualIP(ip); !errors.Is(err, ErrRouteConflict) {
			t.Fatalf("conflicting address resolution error = %v; want ErrRouteConflict", err)
		}
		if _, err := view.PacketCandidates(ip, RoutePolicy{}); !errors.Is(err, ErrRouteConflict) {
			t.Fatalf("conflicting PacketRoute error = %v; want ErrRouteConflict", err)
		}
	})
}

func TestRouteViewStaleRefreshInvalidationAndExpiry(t *testing.T) {
	t.Run("stale preserves unaffected paths and blocks changed facts", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		changed := fixture.remote("changed", 17, false)
		unaffected := fixture.remote("unaffected", 18, false)
		changedLink := fixture.connected(fixture.nodes["local"], changed, 401, FactLanePacket, "packet", LinkCost{})
		fixture.connected(fixture.nodes["local"], unaffected, 402, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		view := fixture.view()
		originalVersion := view.Version()
		if err := view.Refresh(time.Time{}); !errors.Is(err, ErrInvalidFact) {
			t.Fatalf("invalid-time Refresh error = %v; want ErrInvalidFact", err)
		}
		if view.Freshness() != RouteViewStale || view.Version() != originalVersion {
			t.Fatalf("failed refresh did not preserve and stale old view: version=%d freshness=%d", view.Version(), view.Freshness())
		}
		changedLink.Envelope.Version = FactVersion{1, 2}
		fixture.put(changedLink)
		fixture.commit()
		if _, err := view.Candidates(changed, FactLanePacket, RoutePolicy{}); !errors.Is(err, ErrRouteStale) {
			t.Fatalf("changed stale path error = %v; want ErrRouteStale", err)
		}
		paths, err := view.Candidates(unaffected, FactLanePacket, RoutePolicy{})
		if err != nil || len(paths) != 1 || paths[0].Freshness != RouteViewStale {
			t.Fatalf("unaffected stale route = %+v, %v; want one stale candidate", paths, err)
		}
	})

	t.Run("expired facts are omitted on refresh", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		destination := fixture.remote("destination", 19, false)
		fixture.connected(fixture.nodes["local"], destination, 501, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		view := fixture.view()
		// Expiry is anchored when the fact is stored, so it is the local commit time plus
		// the declared lifetime, not the publisher's absolute timestamp. Peers' clocks are
		// never compared.
		expiredAt := time.UnixMilli(int64(uint64(fixture.now.UnixMilli()) + 45_000 + 30_001))
		if err := view.Refresh(expiredAt); err != nil {
			t.Fatalf("Refresh at absolute expiry: %v", err)
		}
		if _, err := view.Candidates(destination, FactLanePacket, RoutePolicy{}); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("expired route error = %v; want ErrNoRoute", err)
		}
	})
}

// TestRouteViewRenewedAddressOwnerIsNotStale freezes the same-owner renewal
// contract of C-ROUTE-005: the live FactStore owner is authoritative for a /32
// mapping, so a re-advertised AddressFact of the SAME owner (higher version,
// identical mapping) must stay routable during the window before the immutable
// view is rebuilt, while a genuine owner change, a conflict, a view that is
// behind a brand-new address and a withdrawn/expired/revoked fact still fail
// closed. It uses a real FactStore and never mocks the view.
func TestRouteViewRenewedAddressOwnerIsNotStale(t *testing.T) {
	t.Run("renewed same-owner address resolves before the view rebuilds", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		destination := fixture.remote("destination", 60, false)
		ip := netip.MustParseAddr("10.40.0.60")
		first := fixture.address(destination, ip, FactVersion{1, 1})
		fixture.connected(fixture.nodes["local"], destination, 601, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		view := fixture.view()
		if view.Freshness() != RouteViewFresh {
			t.Fatalf("test setup: fresh view expected, got %v", view.Freshness())
		}

		// localFactRefreshPeriod in the runtime re-advertises the same owner with
		// the next durable sequence and deliberately does not wait for a rebuild.
		renewed := first
		renewed.Envelope.Version = FactVersion{1, 2}
		fixture.put(renewed)
		fixture.commit()
		if view.Freshness() != RouteViewStale {
			t.Fatalf("test setup: the view must still pin the previous fact version before a rebuild")
		}

		resolution, err := view.ResolveVirtualIP(ip)
		if err != nil {
			t.Fatalf("ResolveVirtualIP on a renewed same-owner AddressFact = %v; want the same owner", err)
		}
		if resolution.NodeID != destination || compareFactVersion(resolution.FactVersion, FactVersion{1, 2}) != 0 {
			t.Fatalf("renewed resolution = %+v; want owner %x pinned at live version 1.2", resolution, destination)
		}
		if resolution.Freshness != RouteViewStale {
			t.Fatalf("renewed resolution freshness = %v; want RouteViewStale while the view is behind", resolution.Freshness)
		}

		route, err := view.PacketCandidates(ip, RoutePolicy{})
		if err != nil {
			t.Fatalf("PacketCandidates on a renewed same-owner AddressFact = %v; want the same owner with PACKET candidates", err)
		}
		if route.DestinationNode != destination || compareFactVersion(route.AddressFactVersion, FactVersion{1, 2}) != 0 {
			t.Fatalf("renewed PacketRoute = %+v; want owner %x pinned at live version 1.2", route, destination)
		}
		if route.LaneID != FactLanePacket || len(route.Candidates) != 1 || route.Freshness != RouteViewStale {
			t.Fatalf("renewed PacketRoute shape = %+v; want one stale PACKET candidate", route)
		}
	})

	t.Run("renewed same-owner node fact resolves", func(t *testing.T) {
		// The owner's NODE fact is re-advertised the same way as its AddressFact.
		// Liveness, not the view's pinned node version, decides staleness.
		fixture := newRouteViewFixture(t)
		destination := fixture.remote("destination", 61, false)
		ip := netip.MustParseAddr("10.40.0.61")
		fixture.address(destination, ip, FactVersion{1, 1})
		fixture.connected(fixture.nodes["local"], destination, 611, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		view := fixture.view()

		fixture.put(factTestNodeRecord(factTestPub(61), nil, FactVersion{1, 2}, fixture.issuedAt, fixture.expiresAt))
		fixture.commit()

		resolution, err := view.ResolveVirtualIP(ip)
		if err != nil {
			t.Fatalf("ResolveVirtualIP on a renewed same-owner NODE fact = %v; want the same owner", err)
		}
		if resolution.NodeID != destination || compareFactVersion(resolution.FactVersion, FactVersion{1, 1}) != 0 {
			t.Fatalf("resolution after node renewal = %+v; want owner %x at the unchanged AddressFact version", resolution, destination)
		}
	})

	t.Run("a genuine owner change still fails closed", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		ownerA := fixture.remote("owner-a", 62, false)
		ownerB := fixture.remote("owner-b", 63, false)
		ip := netip.MustParseAddr("10.40.0.62")
		oldRecord := fixture.address(ownerA, ip, FactVersion{1, 1})
		fixture.connected(fixture.nodes["local"], ownerA, 621, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		view := fixture.view()
		if _, err := view.ResolveVirtualIP(ip); err != nil {
			t.Fatalf("test setup: initial owner resolution = %v", err)
		}

		// Owner A's fact is withdrawn and B's live fact now owns the same /32: the
		// mapping genuinely changed and must not silently retarget to B.
		delete(fixture.facts, string(factTestFactKey(t, oldRecord)))
		fixture.address(ownerB, ip, FactVersion{1, 1})
		fixture.connected(fixture.nodes["local"], ownerB, 622, FactLanePacket, "packet", LinkCost{})
		fixture.commit()

		if _, err := view.ResolveVirtualIP(ip); !errors.Is(err, ErrRouteStale) {
			t.Fatalf("changed-owner resolution error = %v; want ErrRouteStale, never owner B", err)
		}
		if _, err := view.PacketCandidates(ip, RoutePolicy{}); !errors.Is(err, ErrRouteStale) {
			t.Fatalf("changed-owner PacketCandidates error = %v; want ErrRouteStale", err)
		}

		// Only a published rebuild may adopt the new owner.
		if err := view.Refresh(time.Now()); err != nil {
			t.Fatalf("Refresh after owner change: %v", err)
		}
		resolution, err := view.ResolveVirtualIP(ip)
		if err != nil || resolution.NodeID != ownerB {
			t.Fatalf("post-rebuild resolution = %+v, %v; want owner %x", resolution, err, ownerB)
		}
	})

	t.Run("two live owners still conflict", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		ownerA := fixture.remote("owner-a", 64, false)
		ownerB := fixture.remote("owner-b", 65, false)
		ip := netip.MustParseAddr("10.40.0.63")
		fixture.address(ownerA, ip, FactVersion{1, 1})
		fixture.connected(fixture.nodes["local"], ownerA, 631, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		view := fixture.view()

		fixture.address(ownerB, ip, FactVersion{1, 1})
		fixture.connected(fixture.nodes["local"], ownerB, 632, FactLanePacket, "packet", LinkCost{})
		fixture.commit()

		if _, err := view.ResolveVirtualIP(ip); !errors.Is(err, ErrRouteConflict) {
			t.Fatalf("two-live-owner resolution error = %v; want ErrRouteConflict", err)
		}
		if _, err := view.PacketCandidates(ip, RoutePolicy{}); !errors.Is(err, ErrRouteConflict) {
			t.Fatalf("two-live-owner PacketCandidates error = %v; want ErrRouteConflict", err)
		}

		// A view that itself already holds both owners is still a conflict, and the
		// lower NodeID is never selected as a winner.
		if err := view.Refresh(time.Now()); err != nil {
			t.Fatalf("Refresh with conflicting owners: %v", err)
		}
		if _, err := view.ResolveVirtualIP(ip); !errors.Is(err, ErrRouteConflict) {
			t.Fatalf("rebuilt conflict resolution error = %v; want ErrRouteConflict", err)
		}
		if _, err := view.PacketCandidates(ip, RoutePolicy{}); !errors.Is(err, ErrRouteConflict) {
			t.Fatalf("rebuilt conflict PacketCandidates error = %v; want ErrRouteConflict", err)
		}
	})

	t.Run("an address absent from the view stays stale", func(t *testing.T) {
		// A brand-new address is genuinely behind the view (not merely renewed) and
		// must not be resolved from the old snapshot.
		fixture := newRouteViewFixture(t)
		destination := fixture.remote("destination", 66, false)
		fixture.connected(fixture.nodes["local"], destination, 641, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		view := fixture.view()

		ip := netip.MustParseAddr("10.40.0.64")
		fixture.address(destination, ip, FactVersion{1, 1})
		fixture.commit()

		if _, err := view.ResolveVirtualIP(ip); !errors.Is(err, ErrRouteStale) {
			t.Fatalf("new-address resolution error = %v; want ErrRouteStale", err)
		}
		if _, err := view.PacketCandidates(ip, RoutePolicy{}); !errors.Is(err, ErrRouteStale) {
			t.Fatalf("new-address PacketCandidates error = %v; want ErrRouteStale", err)
		}
		// An address that is absent from both the view and the live store is a
		// fresh NoRoute, not a staleness condition.
		if _, err := view.ResolveVirtualIP(netip.MustParseAddr("10.40.0.99")); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("unknown-address error = %v; want ErrNoRoute", err)
		}
		if _, err := view.PacketCandidates(netip.MustParseAddr("10.40.0.99"), RoutePolicy{}); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("unknown-address PacketCandidates error = %v; want ErrNoRoute", err)
		}
	})

	t.Run("a withdrawn owner still fails closed", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		destination := fixture.remote("destination", 67, false)
		ip := netip.MustParseAddr("10.40.0.65")
		fixture.address(destination, ip, FactVersion{1, 1})
		fixture.connected(fixture.nodes["local"], destination, 651, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		view := fixture.view()

		if err := fixture.env.fs.WithdrawSource(fixture.source, fixture.now); err != nil {
			t.Fatalf("withdraw source: %v", err)
		}
		if _, err := view.ResolveVirtualIP(ip); err == nil {
			t.Fatal("a withdrawn owner resolved successfully; want a fail-closed error")
		}
		if _, err := view.PacketCandidates(ip, RoutePolicy{}); err == nil {
			t.Fatal("a withdrawn owner produced PacketCandidates; want a fail-closed error")
		}
		if err := view.Refresh(time.Now()); err != nil {
			t.Fatalf("Refresh after withdrawal: %v", err)
		}
		if _, err := view.ResolveVirtualIP(ip); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("post-withdrawal resolution error = %v; want ErrNoRoute", err)
		}
	})

	t.Run("a revoked owner still fails closed", func(t *testing.T) {
		fixture := newRouteViewFixture(t)
		destination := fixture.remote("destination", 68, false)
		ip := netip.MustParseAddr("10.40.0.66")
		address := fixture.address(destination, ip, FactVersion{1, 1})
		fixture.connected(fixture.nodes["local"], destination, 661, FactLanePacket, "packet", LinkCost{})
		fixture.commit()
		view := fixture.view()

		targetKey, err := DeriveTargetKey(FactAddress, AddressPayload{NodeID: destination, IP: ip, PrefixLen: 32})
		if err != nil {
			t.Fatalf("derive address target key: %v", err)
		}
		revoker := factTestNodeID(factTestPub(69))
		fixture.put(factTestRevocationRecord(revoker, address.Envelope.Origin, FactAddress, targetKey,
			address.Envelope.Version, FactVersion{1, 2}, fixture.issuedAt, fixture.expiresAt))
		fixture.commit()

		if _, err := view.ResolveVirtualIP(ip); err == nil {
			t.Fatal("a revoked owner resolved successfully; want a fail-closed error")
		}
		if _, err := view.PacketCandidates(ip, RoutePolicy{}); err == nil {
			t.Fatal("a revoked owner produced PacketCandidates; want a fail-closed error")
		}
		if err := view.Refresh(time.Now()); err != nil {
			t.Fatalf("Refresh after revocation: %v", err)
		}
		if _, err := view.ResolveVirtualIP(ip); !errors.Is(err, ErrNoRoute) {
			t.Fatalf("post-revocation resolution error = %v; want ErrNoRoute", err)
		}
	})
}

func TestRouteViewMaximumGraphBounds(t *testing.T) {
	fixture := newRouteViewFixture(t)
	nodes := make([]NodeID, maxRouteNodes)
	nodes[0] = fixture.nodes["local"]
	for index := 1; index < len(nodes); index++ {
		nodes[index] = fixture.remote(fmt.Sprintf("node-%d", index), uint64(20_000+index), true)
	}
	linkID := uint64(1)
	for index := 0; index < maxRouteLinks/2; index++ {
		from := nodes[index%len(nodes)]
		to := nodes[(index+1)%len(nodes)]
		fixture.link(from, to, linkID+100_000, FactLaneControl, "control", LinkCost{})
		fixture.link(from, to, linkID, FactLanePacket, "packet", LinkCost{})
		linkID++
	}
	fixture.commit()
	view := fixture.view()
	if got := len(view.snapshot().graph.nodes); got != maxRouteNodes {
		t.Fatalf("built node count = %d; want %d", got, maxRouteNodes)
	}
	if got := len(view.snapshot().graph.edges); got != maxRouteLinks/2 {
		t.Fatalf("built data edge count = %d; want %d", got, maxRouteLinks/2)
	}
	paths, err := view.Candidates(nodes[1], FactLanePacket, RoutePolicy{})
	if err != nil || len(paths) == 0 {
		t.Fatalf("bounded maximum graph query: paths=%d err=%v", len(paths), err)
	}
}
