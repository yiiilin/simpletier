//go:build linux || darwin

package path

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"reflect"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/topology"
)

const (
	fixtureEpochBase uint64 = 5000

	linkControlLocalB uint64 = 101
	linkStreamLocalB  uint64 = 102
	linkPacketLocalB  uint64 = 103
	linkControlBC     uint64 = 104
	linkStreamBC      uint64 = 105
	linkPacketBC      uint64 = 106
	linkControlLocalD uint64 = 107
)

var (
	relayPolicy  = topology.RoutePolicy{AllowRelay: true}
	directPolicy = topology.RoutePolicy{AllowRelay: false}
)

// pathFixture builds a real RouteView from a real FactStore over a real
// NetworkState: A(local) -- B(relay) -- C(target), with CONTROL/PACKET/STREAM
// LinkFacts per hop plus a CONTROL-only node D. Tests toggle hop activity and
// advance the FactStore to exercise the real topology code paths.
type pathFixture struct {
	t *testing.T

	store *security.IdentityStore
	state *security.NetworkState
	facts *topology.FactStore
	view  *RouteView

	local       topology.NodeID
	relay       topology.NodeID
	target      topology.NodeID
	controlOnly topology.NodeID

	contextID [32]byte
	wireID    uint64

	now       time.Time
	issuedAt  uint64
	expiresAt uint64

	source      topology.FactSource
	localFacts  []topology.FactRecord
	remoteFacts []topology.FactRecord
	snapshot    uint64

	mu       sync.Mutex
	inactive map[uint64]bool
}

func newPathFixture(t *testing.T) *pathFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("secure state dir: %v", err)
	}
	store, err := security.OpenIdentityStore()
	if err != nil {
		t.Fatalf("open identity store: %v", err)
	}
	identity, err := store.Identity()
	if err != nil {
		_ = store.Close()
		t.Fatalf("identity: %v", err)
	}
	network, err := security.NewNetworkContext("path-tests", "10.42.0.0/24")
	if err != nil {
		_ = store.Close()
		t.Fatalf("network context: %v", err)
	}
	state, err := security.OpenNetworkState(store, network.ID())
	if err != nil {
		_ = store.Close()
		t.Fatalf("open network state: %v", err)
	}
	facts, err := topology.NewFactStore(state, network.WireID())
	if err != nil {
		_ = state.Close()
		_ = store.Close()
		t.Fatalf("new fact store: %v", err)
	}
	t.Cleanup(func() {
		_ = state.Close()
		_ = store.Close()
	})

	now := time.Now().UTC().Truncate(time.Millisecond)
	issuedAt := uint64(now.Add(-time.Second).UnixMilli())
	fixture := &pathFixture{
		t:         t,
		store:     store,
		state:     state,
		facts:     facts,
		local:     topology.NodeID(identity.NodeID),
		contextID: network.ID(),
		wireID:    network.WireID(),
		now:       now,
		issuedAt:  issuedAt,
		expiresAt: issuedAt + 45_000,
		inactive:  make(map[uint64]bool),
	}
	fixture.source = fixture.factSource(nodeStatic(77), 9001, 1)
	fixture.localFacts = append(fixture.localFacts, fixture.nodeRecord(fixture.local, identity.PublicKey, []string{"endpoint.tcp", "packet.ipv4"}))
	fixture.buildTopology()
	return fixture
}

func (f *pathFixture) buildTopology() {
	f.relay = f.remoteNode(2, true)
	f.target = f.remoteNode(3, false)
	f.controlOnly = f.remoteNode(4, false)

	f.localEdge(linkControlLocalB, f.relay, topology.FactLaneControl, "control")
	f.localEdge(linkStreamLocalB, f.relay, topology.FactLaneStream, "tcp")
	f.localEdge(linkPacketLocalB, f.relay, topology.FactLanePacket, "tcp")
	f.remoteEdge(f.relay, f.target, linkControlBC, topology.FactLaneControl, "control")
	f.remoteEdge(f.relay, f.target, linkStreamBC, topology.FactLaneStream, "ws")
	f.remoteEdge(f.relay, f.target, linkPacketBC, topology.FactLanePacket, "ws")
	f.localEdge(linkControlLocalD, f.controlOnly, topology.FactLaneControl, "control")

	f.publish()
	f.view = f.newView()
}

func nodeStatic(seed uint64) [32]byte {
	var static [32]byte
	binary.BigEndian.PutUint64(static[0:8], seed)
	static[8] = 0x5A
	static[16] = 0xAB
	static[24] = 0xC3
	return static
}

func nodeIDFromStatic(static [32]byte) topology.NodeID {
	digest := sha256.Sum256(static[:])
	var id topology.NodeID
	copy(id[:], digest[:16])
	return id
}

func (f *pathFixture) remoteNode(seed uint64, relay bool) topology.NodeID {
	static := nodeStatic(seed)
	id := nodeIDFromStatic(static)
	var capabilities []string
	if relay {
		capabilities = []string{"relay"}
	}
	f.remoteFacts = append(f.remoteFacts, f.nodeRecord(id, static, capabilities))
	return id
}

func (f *pathFixture) nodeRecord(origin topology.NodeID, public [32]byte, capabilities []string) topology.FactRecord {
	sort.Strings(capabilities)
	return topology.FactRecord{
		Envelope: topology.FactEnvelope{
			NetworkID: f.wireID,
			Kind:      topology.FactNode,
			Origin:    origin,
			Version:   topology.FactVersion{Incarnation: 1, Sequence: 1},
			IssuedAt:  f.issuedAt,
			ExpiresAt: f.expiresAt,
		},
		Payload: topology.NodePayload{NodeID: origin, StaticPublicKey: public, Capabilities: capabilities},
	}
}

func (f *pathFixture) edgeRecord(from, to topology.NodeID, linkID uint64, lane uint8, connectionType string) topology.FactRecord {
	return topology.FactRecord{
		Envelope: topology.FactEnvelope{
			NetworkID: f.wireID,
			Kind:      topology.FactLink,
			Origin:    from,
			Version:   topology.FactVersion{Incarnation: 1, Sequence: 1},
			IssuedAt:  f.issuedAt,
			ExpiresAt: f.expiresAt,
		},
		Payload: topology.LinkPayload{
			LinkID:         linkID,
			LinkEpoch:      linkID + fixtureEpochBase,
			LaneID:         lane,
			From:           from,
			To:             to,
			ConnectionType: connectionType,
		},
	}
}

func (f *pathFixture) localEdge(linkID uint64, to topology.NodeID, lane uint8, connectionType string) {
	f.localFacts = append(f.localFacts, f.edgeRecord(f.local, to, linkID, lane, connectionType))
}

func (f *pathFixture) remoteEdge(from, to topology.NodeID, linkID uint64, lane uint8, connectionType string) {
	f.remoteFacts = append(f.remoteFacts, f.edgeRecord(from, to, linkID, lane, connectionType))
}

func (f *pathFixture) factSource(static [32]byte, linkID, epoch uint64) topology.FactSource {
	return topology.FactSource{
		ContextID:         f.contextID,
		AuthenticatedPeer: nodeIDFromStatic(static),
		PeerStatic:        static,
		LinkID:            linkID,
		Epoch:             epoch,
		LaneID:            topology.FactLaneControl,
	}
}

func (f *pathFixture) publish() {
	f.t.Helper()
	if len(f.localFacts) > 0 {
		if err := f.facts.PublishLocal(f.localFacts, f.now); err != nil {
			f.t.Fatalf("publish local facts: %v", err)
		}
	}
	f.commitRemote(f.remoteFacts)
}

func (f *pathFixture) commitRemote(records []topology.FactRecord) {
	f.t.Helper()
	sorted := make([]topology.FactRecord, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		left, err := topology.FactKey(sorted[i])
		if err != nil {
			f.t.Fatalf("fact key: %v", err)
		}
		right, err := topology.FactKey(sorted[j])
		if err != nil {
			f.t.Fatalf("fact key: %v", err)
		}
		return bytes.Compare(left, right) < 0
	})
	if len(sorted) > topology.MaxPageRecords {
		f.t.Fatalf("fixture snapshot has %d records", len(sorted))
	}
	f.snapshot++
	encoded, err := topology.EncodeFactPage(topology.FactPage{
		ProtocolVersion:   topology.FactProtocolVersion,
		SenderIncarnation: 1,
		NetworkID:         f.wireID,
		SnapshotVersion:   f.snapshot,
		PageNo:            0,
		PageCount:         1,
		Facts:             sorted,
	})
	if err != nil {
		f.t.Fatalf("encode fact page: %v", err)
	}
	page, err := topology.DecodeFactPage(encoded)
	if err != nil {
		f.t.Fatalf("decode fact page: %v", err)
	}
	digest, err := topology.SnapshotDigest(1, f.snapshot, [][32]byte{page.PageDigest})
	if err != nil {
		f.t.Fatalf("snapshot digest: %v", err)
	}
	summary := topology.FactSummary{
		ProtocolVersion:   topology.FactProtocolVersion,
		SenderIncarnation: 1,
		NetworkID:         f.wireID,
		SnapshotVersion:   f.snapshot,
		FactCount:         uint32(len(sorted)),
		PageCount:         1,
		Digest:            digest,
	}
	if err := f.facts.CommitSnapshot(f.source, summary, []topology.FactPage{page}, f.now); err != nil {
		f.t.Fatalf("commit remote facts: %v", err)
	}
}

// commitUnrelatedNode advances the FactStore (and with it RouteView freshness)
// without touching any fact the installed path depends on.
func (f *pathFixture) commitUnrelatedNode(seed uint64) topology.NodeID {
	static := nodeStatic(seed)
	id := nodeIDFromStatic(static)
	f.remoteFacts = append(f.remoteFacts, f.nodeRecord(id, static, nil))
	f.commitRemote(f.remoteFacts)
	return id
}

func (f *pathFixture) newView() *RouteView {
	f.t.Helper()
	view, err := topology.NewRouteView(f.facts, func(linkID, epoch uint64, lane uint8, peer topology.NodeID) bool {
		return f.linkActive(linkID)
	})
	if err != nil {
		f.t.Fatalf("new route view: %v", err)
	}
	return view
}

func (f *pathFixture) linkActive(linkID uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.inactive[linkID]
}

func (f *pathFixture) setInactive(linkID uint64, inactive bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inactive[linkID] = inactive
}

func (f *pathFixture) manager() *Manager {
	f.t.Helper()
	manager, err := NewManager(f.local, f.view, func(ref LinkRef) bool { return f.linkActive(ref.ID) })
	if err != nil {
		f.t.Fatalf("new manager: %v", err)
	}
	return manager
}

func (f *pathFixture) managerAt(local topology.NodeID) *Manager {
	f.t.Helper()
	manager, err := NewManager(local, f.view, func(ref LinkRef) bool { return f.linkActive(ref.ID) })
	if err != nil {
		f.t.Fatalf("new manager at %v: %v", local, err)
	}
	return manager
}

func (f *pathFixture) linkRef(linkID uint64, lane uint8, connectionType string) LinkRef {
	return LinkRef{ID: linkID, Epoch: linkID + fixtureEpochBase, LaneID: lane, ConnectionType: connectionType}
}

func (f *pathFixture) streamLinks() []LinkRef {
	return []LinkRef{
		f.linkRef(linkStreamLocalB, topology.FactLaneStream, "tcp"),
		f.linkRef(linkStreamBC, topology.FactLaneStream, "ws"),
	}
}

func (f *pathFixture) streamNodes() []NodeID {
	return []NodeID{f.local, f.relay, f.target}
}

func readyFor(p Path, status ReadyStatus, code ErrorCode) PathReady {
	return PathReady{PathID: p.ID(), Generation: p.Generation(), Lane: p.Lane(), Digest: p.Digest(), Status: status, Code: code}
}

func brokenFor(p Path, reason BrokenReason, cursor uint8) PathBroken {
	return PathBroken{PathID: p.ID(), Generation: p.Generation(), Lane: p.Lane(), Digest: p.Digest(), Reason: reason, FailedCursor: cursor}
}

func fixedNode(start byte) NodeID {
	var node NodeID
	for index := range node {
		node[index] = start + byte(index)
	}
	return node
}

func fixedNodeBytes(start byte) []byte {
	node := fixedNode(start)
	return node[:]
}

func repeatNode(value byte) NodeID {
	var node NodeID
	for index := range node {
		node[index] = value
	}
	return node
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return raw
}

// manualDigest is an independent implementation of the documented canonical
// byte layout, kept in the test so a drift in ComputeDigest cannot silently
// agree with itself.
func manualDigest(t *testing.T, pathID uint64, generation uint32, lane Lane, viewVersion uint64, nodes []NodeID, links []LinkRef) [32]byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("simpletier-path-v1")
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], pathID)
	buf.Write(scratch[:])
	binary.BigEndian.PutUint32(scratch[:4], generation)
	buf.Write(scratch[:4])
	buf.WriteByte(byte(lane))
	binary.BigEndian.PutUint64(scratch[:], viewVersion)
	buf.Write(scratch[:])
	buf.WriteByte(byte(len(nodes)))
	for _, node := range nodes {
		buf.Write(node[:])
	}
	buf.WriteByte(byte(len(links)))
	for _, link := range links {
		binary.BigEndian.PutUint64(scratch[:], link.ID)
		buf.Write(scratch[:])
		binary.BigEndian.PutUint64(scratch[:], link.Epoch)
		buf.Write(scratch[:])
		buf.WriteByte(link.LaneID)
		binary.BigEndian.PutUint16(scratch[:2], uint16(len(link.ConnectionType)))
		buf.Write(scratch[:2])
		buf.WriteString(link.ConnectionType)
	}
	return sha256.Sum256(buf.Bytes())
}

func TestComputeDigestFixedVector(t *testing.T) {
	nodes := []NodeID{fixedNode(0x00), fixedNode(0x10), fixedNode(0x20)}
	links := []LinkRef{
		{ID: 0x1112131415161718, Epoch: 0x2122232425262728, LaneID: byte(LaneStream), ConnectionType: "tcp"},
		{ID: 0x3132333435363738, Epoch: 0x4142434445464748, LaneID: byte(LaneStream), ConnectionType: "ws"},
	}
	got, err := ComputeDigest(0x0102030405060708, 2, LaneStream, 0x1122334455667788, nodes, links)
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	const want = "ab74dbb7dbe4eba1183b0018db6299157f251338b721066ececd63cebfb40001"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("stream digest = %s; want %s", hex.EncodeToString(got[:]), want)
	}
	if manual := manualDigest(t, 0x0102030405060708, 2, LaneStream, 0x1122334455667788, nodes, links); manual != got {
		t.Fatalf("independent digest = %x; ComputeDigest = %x", manual, got)
	}

	packetNodes := []NodeID{repeatNode(0xAA), repeatNode(0xBB)}
	packetLinks := []LinkRef{{ID: 0xA1A2A3A4A5A6A7A8, Epoch: 0xB1B2B3B4B5B6B7B8, LaneID: byte(LanePacket), ConnectionType: "udp"}}
	got, err = ComputeDigest(0x00000000000000FF, 1, LanePacket, 0, packetNodes, packetLinks)
	if err != nil {
		t.Fatalf("ComputeDigest packet: %v", err)
	}
	const packetWant = "1827b34f81f8f90a62fdddbe6186dd3af7cb69f47447bbc32f9275bd0fe3b631"
	if hex.EncodeToString(got[:]) != packetWant {
		t.Fatalf("packet digest = %s; want %s", hex.EncodeToString(got[:]), packetWant)
	}
	if manual := manualDigest(t, 0x00000000000000FF, 1, LanePacket, 0, packetNodes, packetLinks); manual != got {
		t.Fatalf("independent packet digest = %x; ComputeDigest = %x", manual, got)
	}
}

func TestComputeDigestRejectsInvalidGeometry(t *testing.T) {
	baseNodes := []NodeID{fixedNode(0x00), fixedNode(0x10)}
	baseLinks := []LinkRef{{ID: 7, Epoch: 9, LaneID: byte(LaneStream), ConnectionType: "tcp"}}
	tooManyNodes := make([]NodeID, 17)
	tooManyLinks := make([]LinkRef, 16)
	for index := range tooManyNodes {
		tooManyNodes[index] = fixedNode(byte(index * 16))
	}
	for index := range tooManyLinks {
		tooManyLinks[index] = LinkRef{ID: uint64(index + 1), Epoch: uint64(index + 100), LaneID: byte(LaneStream), ConnectionType: "tcp"}
	}
	cases := []struct {
		name   string
		lane   Lane
		nodes  []NodeID
		links  []LinkRef
		pathID uint64
		gen    uint32
		want   error
	}{
		{"zero path id", LaneStream, baseNodes, baseLinks, 0, 1, ErrInvalidPath},
		{"zero generation", LaneStream, baseNodes, baseLinks, 1, 0, ErrInvalidPath},
		{"control lane", Lane(0), baseNodes, baseLinks, 1, 1, ErrInvalidLane},
		{"unknown lane", Lane(9), baseNodes, baseLinks, 1, 1, ErrInvalidLane},
		{"single node", LaneStream, baseNodes[:1], nil, 1, 1, ErrInvalidPath},
		{"duplicate node", LaneStream, []NodeID{fixedNode(0), fixedNode(0)}, baseLinks, 1, 1, ErrDuplicateNode},
		{"empty node", LaneStream, []NodeID{{}, fixedNode(0x10)}, baseLinks, 1, 1, ErrInvalidNode},
		{"missing link", LaneStream, baseNodes, nil, 1, 1, ErrInvalidPath},
		{"too many hops", LaneStream, tooManyNodes, tooManyLinks, 1, 1, ErrHopLimit},
		{"zero link id", LaneStream, baseNodes, []LinkRef{{ID: 0, Epoch: 9, LaneID: byte(LaneStream), ConnectionType: "tcp"}}, 1, 1, ErrInvalidPath},
		{"zero link epoch", LaneStream, baseNodes, []LinkRef{{ID: 7, Epoch: 0, LaneID: byte(LaneStream), ConnectionType: "tcp"}}, 1, 1, ErrInvalidPath},
		{"link lane mismatch", LaneStream, baseNodes, []LinkRef{{ID: 7, Epoch: 9, LaneID: byte(LanePacket), ConnectionType: "tcp"}}, 1, 1, ErrInvalidLane},
		{"empty connection type", LaneStream, baseNodes, []LinkRef{{ID: 7, Epoch: 9, LaneID: byte(LaneStream)}}, 1, 1, ErrInvalidPath},
		{"invalid utf8 connection type", LaneStream, baseNodes, []LinkRef{{ID: 7, Epoch: 9, LaneID: byte(LaneStream), ConnectionType: "\xff\xfe"}}, 1, 1, ErrInvalidPath},
		{"nul connection type", LaneStream, baseNodes, []LinkRef{{ID: 7, Epoch: 9, LaneID: byte(LaneStream), ConnectionType: "a\x00b"}}, 1, 1, ErrInvalidPath},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ComputeDigest(testCase.pathID, testCase.gen, testCase.lane, 1, testCase.nodes, testCase.links); !errors.Is(err, testCase.want) {
				t.Fatalf("ComputeDigest error = %v; want %v", err, testCase.want)
			}
		})
	}
}

func fixedGeometry(t *testing.T) (PathOpen, [32]byte) {
	t.Helper()
	digest := mustHex(t, "ab74dbb7dbe4eba1183b0018db6299157f251338b721066ececd63cebfb40001")
	var bound [32]byte
	copy(bound[:], digest)
	nodes := []NodeID{fixedNode(0x00), fixedNode(0x10), fixedNode(0x20)}
	links := []LinkRef{
		{ID: 0x1112131415161718, Epoch: 0x2122232425262728, LaneID: byte(LaneStream), ConnectionType: "tcp"},
		{ID: 0x3132333435363738, Epoch: 0x4142434445464748, LaneID: byte(LaneStream), ConnectionType: "ws"},
	}
	computed, err := ComputeDigest(0x0102030405060708, 2, LaneStream, 0x1122334455667788, nodes, links)
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	if computed != bound {
		t.Fatalf("fixed geometry digest = %x; want %x", computed, bound)
	}
	open := PathOpen{
		PathID:      0x0102030405060708,
		Generation:  2,
		Lane:        LaneStream,
		ViewVersion: 0x1122334455667788,
		Nodes:       nodes,
		Links: []LinkInstance{
			{ID: 0x1112131415161718, Epoch: 0x2122232425262728},
			{ID: 0x3132333435363738, Epoch: 0x4142434445464748},
		},
		Digest: bound,
	}
	return open, bound
}

func TestControlCodecFixedVectors(t *testing.T) {
	open, digest := fixedGeometry(t)

	encoded, err := open.Encode()
	if err != nil {
		t.Fatalf("PathOpen.Encode: %v", err)
	}
	const openHex = "01020304050607080000000202112233445566778803000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f021112131415161718212223242526272831323334353637384142434445464748ab74dbb7dbe4eba1183b0018db6299157f251338b721066ececd63cebfb40001"
	if hex.EncodeToString(encoded) != openHex {
		t.Fatalf("PATH_OPEN bytes = %s; want %s", hex.EncodeToString(encoded), openHex)
	}
	decoded, err := DecodeRouteControl(MessagePathOpen, encoded)
	if err != nil {
		t.Fatalf("DecodeRouteControl(PATH_OPEN): %v", err)
	}
	if decoded.Type != MessagePathOpen || !reflect.DeepEqual(decoded.Open, open) {
		t.Fatalf("decoded PATH_OPEN = %+v; want %+v", decoded.Open, open)
	}

	ready := PathReady{PathID: open.PathID, Generation: open.Generation, Lane: LaneStream, Digest: digest, Status: ReadyStatusReady, Code: ErrorCodeNone}
	encoded, err = ready.Encode()
	if err != nil {
		t.Fatalf("PathReady.Encode: %v", err)
	}
	const readyHex = "01020304050607080000000202ab74dbb7dbe4eba1183b0018db6299157f251338b721066ececd63cebfb40001010000"
	if hex.EncodeToString(encoded) != readyHex {
		t.Fatalf("PATH_READY bytes = %s; want %s", hex.EncodeToString(encoded), readyHex)
	}
	decodedReady, err := DecodeRouteControl(MessagePathReady, encoded)
	if err != nil {
		t.Fatalf("DecodeRouteControl(PATH_READY): %v", err)
	}
	if !reflect.DeepEqual(decodedReady.Ready, ready) {
		t.Fatalf("decoded PATH_READY = %+v; want %+v", decodedReady.Ready, ready)
	}

	broken := PathBroken{PathID: open.PathID, Generation: open.Generation, Lane: LaneStream, Digest: digest, Reason: BrokenReasonLinkDown, FailedCursor: 1}
	encoded, err = broken.Encode()
	if err != nil {
		t.Fatalf("PathBroken.Encode: %v", err)
	}
	const brokenHex = "01020304050607080000000202ab74dbb7dbe4eba1183b0018db6299157f251338b721066ececd63cebfb40001000201"
	if hex.EncodeToString(encoded) != brokenHex {
		t.Fatalf("PATH_BROKEN bytes = %s; want %s", hex.EncodeToString(encoded), brokenHex)
	}
	decodedBroken, err := DecodeRouteControl(MessagePathBroken, encoded)
	if err != nil {
		t.Fatalf("DecodeRouteControl(PATH_BROKEN): %v", err)
	}
	if !reflect.DeepEqual(decodedBroken.Broken, broken) {
		t.Fatalf("decoded PATH_BROKEN = %+v; want %+v", decodedBroken.Broken, broken)
	}
}

func TestControlCodecRouteControlRoundTrip(t *testing.T) {
	open, digest := fixedGeometry(t)
	ready := PathReady{PathID: open.PathID, Generation: open.Generation, Lane: LaneStream, Digest: digest, Status: ReadyStatusAlready, Code: ErrorCodeNone}
	broken := PathBroken{PathID: open.PathID, Generation: open.Generation, Lane: LaneStream, Digest: digest, Reason: BrokenReasonProtocol, FailedCursor: 0}
	cases := []RouteControl{
		{Type: MessagePathOpen, Open: open},
		{Type: MessagePathReady, Ready: ready},
		{Type: MessagePathBroken, Broken: broken},
	}
	for _, control := range cases {
		encoded, err := control.Encode()
		if err != nil {
			t.Fatalf("%s Encode: %v", control.Type, err)
		}
		decoded, err := DecodeRouteControl(control.Type, encoded)
		if err != nil {
			t.Fatalf("%s DecodeRouteControl: %v", control.Type, err)
		}
		if decoded.Type != control.Type || !reflect.DeepEqual(decoded, control) {
			t.Fatalf("%s round trip = %+v; want %+v", control.Type, decoded, control)
		}
	}
	if _, err := (RouteControl{Type: MessagePathReady}).Encode(); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("empty PATH_READY encode error = %v; want ErrInvalidPath", err)
	}
	if _, err := (RouteControl{Type: 0x09}).Encode(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unknown message type encode error = %v; want ErrProtocol", err)
	}
}

func TestControlCodecRejectsUnknownAndMalformed(t *testing.T) {
	open, digest := fixedGeometry(t)
	openBytes, err := open.Encode()
	if err != nil {
		t.Fatalf("PathOpen.Encode: %v", err)
	}
	ready := PathReady{PathID: open.PathID, Generation: open.Generation, Lane: LaneStream, Digest: digest, Status: ReadyStatusReady, Code: ErrorCodeNone}
	readyBytes, err := ready.Encode()
	if err != nil {
		t.Fatalf("PathReady.Encode: %v", err)
	}
	broken := PathBroken{PathID: open.PathID, Generation: open.Generation, Lane: LaneStream, Digest: digest, Reason: BrokenReasonNoRoute, FailedCursor: 2}
	brokenBytes, err := broken.Encode()
	if err != nil {
		t.Fatalf("PathBroken.Encode: %v", err)
	}
	patched := func(payload []byte, offset int, values ...byte) []byte {
		out := append([]byte(nil), payload...)
		copy(out[offset:], values)
		return out
	}
	const (
		openNodeCount = 21
		openLinkCount = 22 + 3*16
		openNode0     = 22
		readyStatus   = 45
		readyCode     = 46
		brokenReason  = 45
		brokenCursor  = 47
	)
	cases := []struct {
		name        string
		messageType MessageType
		payload     []byte
		want        error
	}{
		{"empty payload", MessagePathOpen, nil, ErrProtocol},
		{"oversized payload", MessagePathOpen, make([]byte, MaxRouteControlPayload+1), ErrResourceLimit},
		{"session ctrl type", MessageType(0x05), []byte{1}, ErrProtocol},
		{"session ready type", MessageType(0x09), []byte{1}, ErrProtocol},
		{"unknown type", MessageType(0x7f), []byte{1}, ErrProtocol},
		{"open truncated", MessagePathOpen, openBytes[:len(openBytes)-1], ErrProtocol},
		{"open trailing byte", MessagePathOpen, append(append([]byte(nil), openBytes...), 0), ErrProtocol},
		{"open zero path id", MessagePathOpen, patched(openBytes, 0, 0, 0, 0, 0, 0, 0, 0, 0), ErrInvalidPath},
		{"open zero generation", MessagePathOpen, patched(openBytes, 8, 0, 0, 0, 0), ErrInvalidPath},
		{"open control lane", MessagePathOpen, patched(openBytes, 12, 0), ErrInvalidLane},
		{"open unknown lane", MessagePathOpen, patched(openBytes, 12, 3), ErrInvalidLane},
		{"open node count one", MessagePathOpen, patched(openBytes, openNodeCount, 1), ErrProtocol},
		{"open node count overflow", MessagePathOpen, patched(openBytes, openNodeCount, 17), ErrProtocol},
		{"open link count mismatch", MessagePathOpen, patched(openBytes, openLinkCount, 3), ErrProtocol},
		{"open duplicate node", MessagePathOpen, patched(openBytes, openNode0+16, fixedNodeBytes(0x00)...), ErrDuplicateNode},
		{"open zero link id", MessagePathOpen, patched(openBytes, openLinkCount+1, 0, 0, 0, 0, 0, 0, 0, 0), ErrInvalidPath},
		{"open zero link epoch", MessagePathOpen, patched(openBytes, openLinkCount+9, 0, 0, 0, 0, 0, 0, 0, 0), ErrInvalidPath},
		{"ready truncated", MessagePathReady, readyBytes[:len(readyBytes)-1], ErrProtocol},
		{"ready trailing byte", MessagePathReady, append(append([]byte(nil), readyBytes...), 0), ErrProtocol},
		{"ready zero path id", MessagePathReady, patched(readyBytes, 0, 0, 0, 0, 0, 0, 0, 0, 0), ErrInvalidPath},
		{"ready zero generation", MessagePathReady, patched(readyBytes, 8, 0, 0, 0, 0), ErrInvalidPath},
		{"ready unknown lane", MessagePathReady, patched(readyBytes, 12, 3), ErrInvalidLane},
		{"ready unknown status", MessagePathReady, patched(readyBytes, readyStatus, 0x09), ErrProtocol},
		{"ready unknown code", MessagePathReady, patched(readyBytes, readyCode, 0x00, 0x09), ErrProtocol},
		{"ready without zero code", MessagePathReady, patched(readyBytes, readyCode, 0x00, 0x01), ErrProtocol},
		{"broken truncated", MessagePathBroken, brokenBytes[:len(brokenBytes)-1], ErrProtocol},
		{"broken trailing byte", MessagePathBroken, append(append([]byte(nil), brokenBytes...), 0), ErrProtocol},
		{"broken unknown lane", MessagePathBroken, patched(brokenBytes, 12, 0), ErrInvalidLane},
		{"broken zero reason", MessagePathBroken, patched(brokenBytes, brokenReason, 0x00, 0x00), ErrProtocol},
		{"broken unknown reason", MessagePathBroken, patched(brokenBytes, brokenReason, 0x00, 0x09), ErrProtocol},
		{"broken cursor overflow", MessagePathBroken, patched(brokenBytes, brokenCursor, 0xff), ErrProtocol},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := DecodeRouteControl(testCase.messageType, testCase.payload); !errors.Is(err, testCase.want) {
				t.Fatalf("DecodeRouteControl error = %v; want %v", err, testCase.want)
			}
		})
	}
}

func TestManagerOpenLifecycle(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.ID() == 0 {
		t.Fatal("Open returned a zero PathID")
	}
	if opened.Generation() != 1 {
		t.Fatalf("initial generation = %d; want 1", opened.Generation())
	}
	if opened.Lane() != LaneStream || opened.State() != StateCreated {
		t.Fatalf("opened path = %s/%s; want STREAM/Created", opened.Lane(), opened.State())
	}
	if !slices.Equal(opened.Nodes(), fixture.streamNodes()) {
		t.Fatalf("nodes = %v; want %v", opened.Nodes(), fixture.streamNodes())
	}
	if !slices.Equal(opened.Links(), fixture.streamLinks()) {
		t.Fatalf("links = %v; want %v", opened.Links(), fixture.streamLinks())
	}
	expected, err := ComputeDigest(opened.ID(), 1, LaneStream, opened.ViewVersion(), opened.Nodes(), opened.Links())
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	if expected != opened.Digest() {
		t.Fatalf("digest = %x; want %x", opened.Digest(), expected)
	}
	if opened.ViewVersion() != fixture.view.Version() {
		t.Fatalf("view version = %d; want %d", opened.ViewVersion(), fixture.view.Version())
	}
	if opened.Freshness() != topology.RouteViewFresh {
		t.Fatalf("freshness = %v; want fresh", opened.Freshness())
	}
	if len(manager.Snapshot()) != 1 {
		t.Fatalf("snapshot size = %d; want 1", len(manager.Snapshot()))
	}
	if _, err := manager.Lookup(opened.ID(), 1); err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	frame, err := opened.OpenFrame()
	if err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	if opened.State() != StateOpenPending {
		t.Fatalf("state after OpenFrame = %s; want OpenPending", opened.State())
	}
	again, err := opened.OpenFrame()
	if err != nil {
		t.Fatalf("duplicate OpenFrame: %v", err)
	}
	if !bytes.Equal(frame, again) {
		t.Fatal("duplicate OpenFrame returned different bytes")
	}
	control, err := DecodeRouteControl(MessagePathOpen, frame)
	if err != nil {
		t.Fatalf("DecodeRouteControl: %v", err)
	}
	if control.Open.PathID != opened.ID() || control.Open.Generation != 1 || control.Open.Lane != LaneStream {
		t.Fatalf("decoded PATH_OPEN = %+v", control.Open)
	}
	if control.Open.Digest != opened.Digest() || !slices.Equal(control.Open.Nodes, opened.Nodes()) {
		t.Fatalf("decoded PATH_OPEN geometry = %+v", control.Open)
	}
	wantLinks := []LinkInstance{{ID: linkStreamLocalB, Epoch: linkStreamLocalB + fixtureEpochBase}, {ID: linkStreamBC, Epoch: linkStreamBC + fixtureEpochBase}}
	if !slices.Equal(control.Open.Links, wantLinks) {
		t.Fatalf("decoded PATH_OPEN links = %v; want %v", control.Open.Links, wantLinks)
	}
	if control.Open.ViewVersion != opened.ViewVersion() {
		t.Fatalf("decoded view version = %d; want %d", control.Open.ViewVersion, opened.ViewVersion())
	}

	if err := opened.MarkReady(readyFor(opened, ReadyStatusReady, ErrorCodeNone)); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	if opened.State() != StateReady {
		t.Fatalf("state after READY = %s; want Ready", opened.State())
	}
	if err := opened.MarkReady(readyFor(opened, ReadyStatusAlready, ErrorCodeNone)); err != nil {
		t.Fatalf("duplicate MarkReady(ALREADY): %v", err)
	}
	if err := opened.MarkReady(readyFor(opened, ReadyStatusReject, ErrorCodeLinkDown)); err != nil {
		t.Fatalf("late MarkReady(REJECT) must not fail: %v", err)
	}
	if opened.State() != StateReady {
		t.Fatalf("late REJECT downgraded state to %s", opened.State())
	}
	if err := opened.MarkActive(); err != nil {
		t.Fatalf("MarkActive: %v", err)
	}
	if opened.State() != StateActive {
		t.Fatalf("state after MarkActive = %s; want Active", opened.State())
	}
	if err := opened.MarkActive(); err != nil {
		t.Fatalf("duplicate MarkActive: %v", err)
	}

	readyFrame, err := opened.ReadyFrame(ReadyStatusReady, ErrorCodeNone)
	if err != nil {
		t.Fatalf("ReadyFrame: %v", err)
	}
	decodedReady, err := DecodeRouteControl(MessagePathReady, readyFrame)
	if err != nil {
		t.Fatalf("DecodeRouteControl(PATH_READY): %v", err)
	}
	if decodedReady.Ready.Digest != opened.Digest() || decodedReady.Ready.Status != ReadyStatusReady {
		t.Fatalf("decoded PATH_READY = %+v", decodedReady.Ready)
	}
	brokenFrame, err := opened.BrokenFrame(BrokenReasonLinkDown, 1)
	if err != nil {
		t.Fatalf("BrokenFrame: %v", err)
	}
	decodedBroken, err := DecodeRouteControl(MessagePathBroken, brokenFrame)
	if err != nil {
		t.Fatalf("DecodeRouteControl(PATH_BROKEN): %v", err)
	}
	if decodedBroken.Broken.Reason != BrokenReasonLinkDown || decodedBroken.Broken.FailedCursor != 1 {
		t.Fatalf("decoded PATH_BROKEN = %+v", decodedBroken.Broken)
	}
	if _, err := opened.BrokenFrame(BrokenReasonLinkDown, 3); !errors.Is(err, ErrProtocol) {
		t.Fatalf("out-of-range failed cursor error = %v; want ErrProtocol", err)
	}
	if _, err := opened.ReadyFrame(ReadyStatusReady, ErrorCodeNoRoute); !errors.Is(err, ErrProtocol) {
		t.Fatalf("READY with a nonzero error code = %v; want ErrProtocol", err)
	}

	snapshot := manager.Snapshot()
	if len(snapshot) != 1 || snapshot[0].State() != StateActive || snapshot[0].ID() != opened.ID() {
		t.Fatalf("snapshot = %+v", snapshot)
	}

	if err := opened.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if opened.State() != StateClosed {
		t.Fatalf("state after Close = %s; want Closed", opened.State())
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("duplicate Close: %v", err)
	}
	if len(manager.Snapshot()) != 0 {
		t.Fatalf("snapshot after Close = %d paths; want 0", len(manager.Snapshot()))
	}
	for name, call := range map[string]func() error{
		"OpenFrame":  func() error { _, err := opened.OpenFrame(); return err },
		"ReadyFrame": func() error { _, err := opened.ReadyFrame(ReadyStatusReady, ErrorCodeNone); return err },
		"MarkActive": opened.MarkActive,
		"MarkReady":  func() error { return opened.MarkReady(readyFor(opened, ReadyStatusReady, ErrorCodeNone)) },
		"Fail":       func() error { return opened.Fail(BrokenReasonLinkDown, 0) },
	} {
		if err := call(); !errors.Is(err, ErrClosed) {
			t.Fatalf("%s after Close error = %v; want ErrClosed", name, err)
		}
	}
}

func TestManagerOpenArgumentValidation(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()
	cases := []struct {
		name string
		ctx  context.Context
		dst  NodeID
		lane Lane
		want error
	}{
		{"nil context", nil, fixture.target, LaneStream, ErrInvalidPath},
		{"control lane", ctx, fixture.target, Lane(0), ErrInvalidLane},
		{"unknown lane", ctx, fixture.target, Lane(3), ErrInvalidLane},
		{"empty destination", ctx, NodeID{}, LaneStream, ErrInvalidNode},
		{"local destination", ctx, fixture.local, LaneStream, ErrInvalidNode},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := manager.Open(testCase.ctx, testCase.dst, testCase.lane, relayPolicy); !errors.Is(err, testCase.want) {
				t.Fatalf("Open error = %v; want %v", err, testCase.want)
			}
		})
	}
	if len(manager.Snapshot()) != 0 {
		t.Fatalf("rejected Opens installed %d paths", len(manager.Snapshot()))
	}
	if _, err := NewManager(NodeID{}, fixture.view, func(LinkRef) bool { return true }); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("NewManager empty local error = %v; want ErrInvalidNode", err)
	}
	if _, err := NewManager(fixture.local, nil, func(LinkRef) bool { return true }); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("NewManager nil view error = %v; want ErrInvalidPath", err)
	}
	if _, err := NewManager(fixture.local, fixture.view, nil); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("NewManager nil callback error = %v; want ErrInvalidPath", err)
	}
}

func TestManagerOpenCandidateFailures(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	if _, err := manager.Open(ctx, fixture.controlOnly, LaneStream, relayPolicy); !errors.Is(err, topology.ErrNoRoute) {
		t.Fatalf("Open to a CONTROL-only node error = %v; want ErrNoRoute", err)
	}
	if _, err := manager.Open(ctx, fixture.target, LaneStream, directPolicy); !errors.Is(err, topology.ErrPolicyDenied) {
		t.Fatalf("Open with relay denied error = %v; want ErrPolicyDenied", err)
	}
	if _, err := manager.Open(ctx, nodeIDFromStatic(nodeStatic(4242)), LaneStream, relayPolicy); !errors.Is(err, topology.ErrNoRoute) {
		t.Fatalf("Open to an unknown node error = %v; want ErrNoRoute", err)
	}

	// The hop callback rejects the second hop even though RouteView still lists it.
	fixture.setInactive(linkStreamBC, true)
	if _, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy); !errors.Is(err, ErrInactiveLink) {
		t.Fatalf("Open with an inactive hop error = %v; want ErrInactiveLink", err)
	}
	fixture.setInactive(linkStreamBC, false)

	// RouteView's own synchronous validator removes the first hop entirely and
	// marks the view invalidated, so the query reports the documented stale
	// result instead of a plain no-route.
	fixture.setInactive(linkStreamLocalB, true)
	if _, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy); !errors.Is(err, topology.ErrRouteStale) {
		t.Fatalf("Open with an inactive first hop error = %v; want ErrRouteStale", err)
	}
	fixture.setInactive(linkStreamLocalB, false)

	if len(manager.Snapshot()) != 0 {
		t.Fatalf("failed Opens installed %d paths", len(manager.Snapshot()))
	}
	if packets, err := manager.Open(ctx, fixture.target, LanePacket, relayPolicy); err != nil {
		t.Fatalf("Open PACKET: %v", err)
	} else {
		if packets.Lane() != LanePacket || !slices.Equal(packets.Links(), []LinkRef{
			fixture.linkRef(linkPacketLocalB, topology.FactLanePacket, "tcp"),
			fixture.linkRef(linkPacketBC, topology.FactLanePacket, "ws"),
		}) {
			t.Fatalf("PACKET path = %+v", packets.Links())
		}
	}
}

func TestManagerFirstCandidateLimits(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	nodes := fixture.streamNodes()
	links := fixture.streamLinks()
	candidate := func() topology.CandidatePath {
		return topology.CandidatePath{
			Nodes:       nodes,
			Links:       links,
			LaneID:      uint8(LaneStream),
			Cost:        1,
			ViewVersion: 1,
			Freshness:   topology.RouteViewFresh,
		}
	}
	sixteenNodes := make([]NodeID, MaxNodes+1)
	sixteenLinks := make([]LinkRef, MaxNodes)
	for index := range sixteenNodes {
		sixteenNodes[index] = fixedNode(byte(index * 16))
	}
	for index := range sixteenLinks {
		sixteenLinks[index] = LinkRef{ID: uint64(index + 1), Epoch: uint64(index + 100), LaneID: byte(LaneStream), ConnectionType: "tcp"}
	}
	single := func(nodes []NodeID, links []LinkRef) []topology.CandidatePath {
		path := candidate()
		path.Nodes = nodes
		path.Links = links
		return []topology.CandidatePath{path}
	}
	packetLane := candidate()
	packetLane.LaneID = uint8(LanePacket)
	cases := []struct {
		name  string
		paths []topology.CandidatePath
		lane  Lane
		want  error
	}{
		{"no candidate", nil, LaneStream, ErrInvalidPath},
		{"candidate overflow", []topology.CandidatePath{candidate(), candidate(), candidate(), candidate()}, LaneStream, ErrResourceLimit},
		{"lane mismatch", []topology.CandidatePath{packetLane}, LaneStream, ErrInvalidLane},
		{"duplicate node", single([]NodeID{fixture.local, fixture.relay, fixture.relay}, links), LaneStream, ErrDuplicateNode},
		{"node overflow", single(sixteenNodes, sixteenLinks), LaneStream, ErrHopLimit},
		{"endpoint mismatch", single([]NodeID{fixedNode(0x30), fixture.relay, fixture.target}, links), LaneStream, ErrInvalidPath},
		{"zero link id", single(nodes, []LinkRef{{ID: 0, Epoch: 9, LaneID: byte(LaneStream), ConnectionType: "tcp"}, links[1]}), LaneStream, ErrInvalidPath},
		{"empty connection type", single(nodes, []LinkRef{{ID: 1, Epoch: 2, LaneID: byte(LaneStream)}, links[1]}), LaneStream, ErrInvalidPath},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := manager.firstCandidate(testCase.paths, fixture.target, testCase.lane); !errors.Is(err, testCase.want) {
				t.Fatalf("firstCandidate error = %v; want %v", err, testCase.want)
			}
		})
	}
	if _, err := manager.firstCandidate(single(nodes, links), fixture.local, LaneStream); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("candidate ending at the local node error = %v; want ErrInvalidPath", err)
	}
}

func TestManagerOpenContext(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := manager.Open(cancelled, fixture.target, LaneStream, relayPolicy); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open with a cancelled context error = %v; want context.Canceled", err)
	}
	expired, expire := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer expire()
	if _, err := manager.Open(expired, fixture.target, LaneStream, relayPolicy); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Open with an expired deadline error = %v; want context.DeadlineExceeded", err)
	}

	// Cancel from inside the synchronous hop callback: the manager must observe
	// it after validation and install nothing.
	midCtx, midCancel := context.WithCancel(ctx)
	defer midCancel()
	midManager, err := NewManager(fixture.local, fixture.view, func(LinkRef) bool {
		midCancel()
		return true
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := midManager.Open(midCtx, fixture.target, LaneStream, relayPolicy); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-flight cancellation error = %v; want context.Canceled", err)
	}
	if len(midManager.Snapshot()) != 0 {
		t.Fatalf("mid-flight cancellation installed %d paths", len(midManager.Snapshot()))
	}
	if len(manager.Snapshot()) != 0 {
		t.Fatalf("context failures installed %d paths", len(manager.Snapshot()))
	}
}

func TestManagerAcceptPathOpen(t *testing.T) {
	fixture := newPathFixture(t)
	source := fixture.manager()
	ctx := context.Background()

	opened, err := source.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	frame, err := opened.OpenFrame()
	if err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	control, err := DecodeRouteControl(MessagePathOpen, frame)
	if err != nil {
		t.Fatalf("DecodeRouteControl: %v", err)
	}

	target := fixture.managerAt(fixture.target)
	installed, err := target.Accept(ctx, control.Open, fixture.streamLinks())
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if installed.ID() != opened.ID() || installed.Generation() != 1 || installed.Digest() != opened.Digest() {
		t.Fatalf("accepted path = %+v; want the PATH_OPEN identity", installed)
	}
	if installed.State() != StateOpenPending {
		t.Fatalf("accepted state = %s; want OpenPending", installed.State())
	}
	if !slices.Equal(installed.Nodes(), fixture.streamNodes()) {
		t.Fatalf("accepted nodes = %v", installed.Nodes())
	}
	readyFrame, err := installed.ReadyFrame(ReadyStatusReady, ErrorCodeNone)
	if err != nil {
		t.Fatalf("ReadyFrame: %v", err)
	}
	decodedReady, err := DecodeRouteControl(MessagePathReady, readyFrame)
	if err != nil {
		t.Fatalf("DecodeRouteControl(PATH_READY): %v", err)
	}
	if decodedReady.Ready.Digest != opened.Digest() {
		t.Fatalf("target PATH_READY digest = %x; want %x", decodedReady.Ready.Digest, opened.Digest())
	}
	if err := installed.MarkActive(); err != nil {
		t.Fatalf("MarkActive: %v", err)
	}
	if installed.State() != StateActive {
		t.Fatalf("state = %s; want Active", installed.State())
	}

	duplicate, err := target.Accept(ctx, control.Open, fixture.streamLinks())
	if err != nil {
		t.Fatalf("duplicate Accept: %v", err)
	}
	if duplicate.ID() != installed.ID() || duplicate.State() != StateActive {
		t.Fatalf("duplicate Accept returned %+v", duplicate)
	}
	if len(target.Snapshot()) != 1 {
		t.Fatalf("duplicate Accept produced %d paths", len(target.Snapshot()))
	}

	// ConnectionType is part of the digest binding: a hop that resolves a
	// different LinkFact for the same (LinkID, LinkEpoch) must be rejected.
	typeMismatch := fixture.streamLinks()
	typeMismatch[1].ConnectionType = "tcp"
	if _, err := target.Accept(ctx, control.Open, typeMismatch); !errors.Is(err, ErrPathDigestMismatch) {
		t.Fatalf("ConnectionType mismatch error = %v; want ErrPathDigestMismatch", err)
	}
	// Lane is part of the digest binding too.
	laneMismatch := fixture.streamLinks()
	laneMismatch[0].LaneID = byte(LanePacket)
	if _, err := target.Accept(ctx, control.Open, laneMismatch); !errors.Is(err, ErrInvalidLane) {
		t.Fatalf("lane mismatch error = %v; want ErrInvalidLane", err)
	}
	// Unresolved or wrongly resolved instances are rejected before the digest.
	unresolved := fixture.streamLinks()
	unresolved[0].Epoch++
	if _, err := target.Accept(ctx, control.Open, unresolved); !errors.Is(err, ErrLinkMismatch) {
		t.Fatalf("unresolved link error = %v; want ErrLinkMismatch", err)
	}
	if _, err := target.Accept(ctx, control.Open, fixture.streamLinks()[:1]); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("missing resolved link error = %v; want ErrInvalidPath", err)
	}
	// The source node must not accept its own PATH_OPEN as the target.
	if _, err := source.Accept(ctx, control.Open, fixture.streamLinks()); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Accept on a non-target node error = %v; want ErrInvalidPath", err)
	}
	if len(target.Snapshot()) != 1 {
		t.Fatalf("rejected Accepts changed the table to %d paths", len(target.Snapshot()))
	}

	// Same PathID/Generation with a different digest is a conflict.
	conflict := control.Open
	conflict.ViewVersion++
	conflict.Digest, err = ComputeDigest(conflict.PathID, conflict.Generation, conflict.Lane, conflict.ViewVersion, conflict.Nodes, fixture.streamLinks())
	if err != nil {
		t.Fatalf("ComputeDigest conflict: %v", err)
	}
	if _, err := target.Accept(ctx, conflict, fixture.streamLinks()); !errors.Is(err, ErrPathConflict) {
		t.Fatalf("conflicting PATH_OPEN error = %v; want ErrPathConflict", err)
	}

	// A higher generation installs a replacement; a lower one is expired.
	higher := control.Open
	higher.Generation = 2
	higher.Digest, err = ComputeDigest(higher.PathID, higher.Generation, higher.Lane, higher.ViewVersion, higher.Nodes, fixture.streamLinks())
	if err != nil {
		t.Fatalf("ComputeDigest generation 2: %v", err)
	}
	replaced, err := target.Accept(ctx, higher, fixture.streamLinks())
	if err != nil {
		t.Fatalf("Accept generation 2: %v", err)
	}
	if replaced.Generation() != 2 || replaced.State() != StateOpenPending {
		t.Fatalf("replacement = %+v", replaced)
	}
	if installed.State() != StateClosed {
		t.Fatalf("superseded generation reports %s; want Closed", installed.State())
	}
	lower := control.Open
	if _, err := target.Accept(ctx, lower, fixture.streamLinks()); !errors.Is(err, ErrPathGenerationExpired) {
		t.Fatalf("stale generation error = %v; want ErrPathGenerationExpired", err)
	}
}

func TestManagerReplaceGeneration(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := opened.OpenFrame(); err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	if err := opened.MarkReady(readyFor(opened, ReadyStatusReady, ErrorCodeNone)); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	if err := opened.MarkActive(); err != nil {
		t.Fatalf("MarkActive: %v", err)
	}
	firstDigest := opened.Digest()

	next, err := opened.Replace(ctx, relayPolicy)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if next.ID() != opened.ID() {
		t.Fatalf("Replace changed the PathID: %d -> %d", opened.ID(), next.ID())
	}
	if next.Generation() != 2 {
		t.Fatalf("generation after Replace = %d; want 2", next.Generation())
	}
	if next.State() != StateCreated {
		t.Fatalf("state after Replace = %s; want Created", next.State())
	}
	if next.Digest() == firstDigest {
		t.Fatal("Replace kept the generation-1 digest")
	}
	expected, err := ComputeDigest(next.ID(), 2, LaneStream, next.ViewVersion(), next.Nodes(), next.Links())
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	if expected != next.Digest() {
		t.Fatalf("digest after Replace = %x; want %x", next.Digest(), expected)
	}
	if opened.State() != StateClosed {
		t.Fatalf("superseded handle state = %s; want Closed", opened.State())
	}
	if err := opened.MarkActive(); !errors.Is(err, ErrPathGenerationExpired) {
		t.Fatalf("MarkActive on a superseded generation = %v; want ErrPathGenerationExpired", err)
	}
	if err := opened.MarkReady(readyFor(opened, ReadyStatusReady, ErrorCodeNone)); !errors.Is(err, ErrPathGenerationExpired) {
		t.Fatalf("MarkReady on a superseded generation = %v; want ErrPathGenerationExpired", err)
	}
	if err := opened.Close(); !errors.Is(err, ErrPathGenerationExpired) {
		t.Fatalf("Close on a superseded generation = %v; want ErrPathGenerationExpired", err)
	}
	snapshot := manager.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Generation() != 2 || snapshot[0].State() != StateCreated {
		t.Fatalf("snapshot after Replace = %+v", snapshot)
	}
	if _, err := next.OpenFrame(); err != nil {
		t.Fatalf("OpenFrame after Replace: %v", err)
	}
	if err := next.Close(); err != nil {
		t.Fatalf("Close replacement: %v", err)
	}
}

func TestManagerReplaceRollbackAndStateGuards(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := opened.OpenFrame(); err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	if err := opened.MarkReady(readyFor(opened, ReadyStatusReady, ErrorCodeNone)); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	before := manager.Snapshot()[0]

	// Policy denial inside the RouteView query must leave the installed path
	// exactly as it was: no half install, no generation bump.
	if _, err := opened.Replace(ctx, directPolicy); !errors.Is(err, topology.ErrPolicyDenied) {
		t.Fatalf("Replace with relay denied error = %v; want ErrPolicyDenied", err)
	}
	after := manager.Snapshot()[0]
	if after.Generation() != before.Generation() || after.Digest() != before.Digest() || after.State() != StateReady {
		t.Fatalf("failed Replace changed the path: %+v -> %+v", before, after)
	}
	if opened.State() != StateReady {
		t.Fatalf("handle state after failed Replace = %s; want Ready", opened.State())
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := opened.Replace(cancelled, relayPolicy); !errors.Is(err, context.Canceled) {
		t.Fatalf("Replace with a cancelled context error = %v; want context.Canceled", err)
	}
	if current := manager.Snapshot()[0]; current.Generation() != 1 || current.Digest() != before.Digest() {
		t.Fatalf("cancelled Replace changed the path: %+v", current)
	}

	// Broken and Closed paths never replace; a new path must be opened instead.
	if err := opened.Fail(BrokenReasonLinkDown, 1); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	if _, err := opened.Replace(ctx, relayPolicy); !errors.Is(err, ErrState) {
		t.Fatalf("Replace on a broken path error = %v; want ErrState", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := opened.Replace(ctx, relayPolicy); !errors.Is(err, ErrClosed) {
		t.Fatalf("Replace on a closed path error = %v; want ErrClosed", err)
	}
}

func TestManagerGenerationExhaustionRetiresPathID(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	oldID := opened.ID()
	manager.mu.Lock()
	manager.records[oldID].generation = math.MaxUint32
	manager.mu.Unlock()
	last, err := manager.Lookup(oldID, math.MaxUint32)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	const replacementID uint64 = 0xDEADBEEFCAFEF00D
	manager.rand = func(buf []byte) error {
		binary.BigEndian.PutUint64(buf, replacementID)
		return nil
	}
	next, err := last.Replace(ctx, relayPolicy)
	if err != nil {
		t.Fatalf("Replace at the generation ceiling: %v", err)
	}
	if next.ID() != replacementID {
		t.Fatalf("replacement PathID = %d; want %d", next.ID(), replacementID)
	}
	if next.Generation() != 1 {
		t.Fatalf("replacement generation = %d; want 1", next.Generation())
	}
	if _, err := manager.Lookup(oldID, math.MaxUint32); !errors.Is(err, ErrPathGenerationExpired) {
		t.Fatalf("retired PathID lookup error = %v; want ErrPathGenerationExpired", err)
	}
	if last.State() != StateClosed {
		t.Fatalf("retired handle state = %s; want Closed", last.State())
	}
	if err := last.Close(); err != nil {
		t.Fatalf("Close on a retired PathID = %v; want nil", err)
	}
	snapshot := manager.Snapshot()
	if len(snapshot) != 1 || snapshot[0].ID() != replacementID {
		t.Fatalf("snapshot after retirement = %+v", snapshot)
	}
	// The retired PathID stays in the in-process ledger, so the CSPRNG cannot
	// hand it back out: a source that only produces it fails closed.
	if _, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy); !errors.Is(err, ErrEntropy) {
		t.Fatalf("reused PathID draw error = %v; want ErrEntropy", err)
	}
	if len(manager.Snapshot()) != 1 {
		t.Fatalf("failed Open installed a path: %d", len(manager.Snapshot()))
	}
}

func TestManagerBrokenAndCloseLifecycle(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := opened.OpenFrame(); err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	if err := opened.MarkBroken(brokenFor(opened, BrokenReasonLinkDown, 1)); err != nil {
		t.Fatalf("MarkBroken: %v", err)
	}
	if opened.State() != StateBroken {
		t.Fatalf("state after PATH_BROKEN = %s; want Broken", opened.State())
	}
	if err := opened.MarkBroken(brokenFor(opened, BrokenReasonLinkDown, 1)); err != nil {
		t.Fatalf("duplicate MarkBroken: %v", err)
	}
	if err := opened.MarkReady(readyFor(opened, ReadyStatusReady, ErrorCodeNone)); !errors.Is(err, ErrState) {
		t.Fatalf("MarkReady on a broken path = %v; want ErrState", err)
	}
	if _, err := opened.OpenFrame(); !errors.Is(err, ErrState) {
		t.Fatalf("OpenFrame on a broken path = %v; want ErrState", err)
	}
	if err := opened.Fail(BrokenReasonProtocol, 0); err != nil {
		t.Fatalf("Fail on a broken path must be idempotent: %v", err)
	}
	if _, err := opened.BrokenFrame(BrokenReasonLinkDown, 1); err != nil {
		t.Fatalf("BrokenFrame on a broken path: %v", err)
	}
	if err := opened.MarkBroken(brokenFor(opened, BrokenReasonLinkDown, 0)); err != nil {
		t.Fatalf("MarkBroken with cursor 0: %v", err)
	}
	if err := opened.Fail(BrokenReasonLinkDown, 0); err != nil {
		t.Fatalf("Fail with cursor 0: %v", err)
	}

	// Identity mismatches never mutate state.
	mismatch := readyFor(opened, ReadyStatusReady, ErrorCodeNone)
	mismatch.Digest[0] ^= 0xff
	if err := opened.MarkReady(mismatch); !errors.Is(err, ErrPathDigestMismatch) {
		t.Fatalf("digest mismatch error = %v; want ErrPathDigestMismatch", err)
	}
	mismatchID := readyFor(opened, ReadyStatusReady, ErrorCodeNone)
	mismatchID.PathID++
	if err := opened.MarkReady(mismatchID); !errors.Is(err, ErrPathMismatch) {
		t.Fatalf("PathID mismatch error = %v; want ErrPathMismatch", err)
	}
	beyondGeneration := readyFor(opened, ReadyStatusReady, ErrorCodeNone)
	beyondGeneration.Generation++
	if err := opened.MarkReady(beyondGeneration); !errors.Is(err, ErrPathMismatch) {
		t.Fatalf("future generation error = %v; want ErrPathMismatch", err)
	}
	// Structural validation precedes the identity check: a zero Generation is
	// not a stale generation, it is not a valid message at all.
	zeroGeneration := readyFor(opened, ReadyStatusReady, ErrorCodeNone)
	zeroGeneration.Generation = 0
	if err := opened.MarkReady(zeroGeneration); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("zero generation error = %v; want ErrInvalidPath", err)
	}
	brokenCursor := brokenFor(opened, BrokenReasonLinkDown, 9)
	if err := opened.MarkBroken(brokenCursor); !errors.Is(err, ErrProtocol) {
		t.Fatalf("out-of-range PATH_BROKEN cursor error = %v; want ErrProtocol", err)
	}
	if err := opened.Fail(BrokenReason(0), 0); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unknown broken reason error = %v; want ErrProtocol", err)
	}

	if err := opened.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("duplicate Close: %v", err)
	}
	if opened.State() != StateClosed {
		t.Fatalf("state after Close = %s; want Closed", opened.State())
	}
	if err := opened.MarkBroken(brokenFor(opened, BrokenReasonLinkDown, 0)); !errors.Is(err, ErrClosed) {
		t.Fatalf("MarkBroken after Close = %v; want ErrClosed", err)
	}
	if err := opened.Fail(BrokenReasonLinkDown, 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("Fail after Close = %v; want ErrClosed", err)
	}
	if _, err := opened.BrokenFrame(BrokenReasonLinkDown, 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("BrokenFrame after Close = %v; want ErrClosed", err)
	}
	if _, err := opened.ReadyFrame(ReadyStatusReady, ErrorCodeNone); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReadyFrame after Close = %v; want ErrClosed", err)
	}
	if len(manager.Snapshot()) != 0 {
		t.Fatalf("snapshot after Close = %d paths", len(manager.Snapshot()))
	}
}

func TestManagerPathIDAllocation(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	issued := opened.ID()
	const fresh = 0x0000000012345678
	calls := 0
	manager.rand = func(buf []byte) error {
		calls++
		switch calls {
		case 1:
			binary.BigEndian.PutUint64(buf, issued) // already issued: retry
		case 2:
			binary.BigEndian.PutUint64(buf, 0) // zero: retry
		default:
			binary.BigEndian.PutUint64(buf, fresh)
		}
		return nil
	}
	second, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open with an injected CSPRNG: %v", err)
	}
	if second.ID() != fresh {
		t.Fatalf("injected PathID = %#x; want %#x", second.ID(), uint64(fresh))
	}
	if calls != 3 {
		t.Fatalf("CSPRNG draws = %d; want 3 (issued, zero, fresh)", calls)
	}

	manager.rand = func([]byte) error { return errors.New("no entropy") }
	if _, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy); !errors.Is(err, ErrEntropy) {
		t.Fatalf("failing CSPRNG error = %v; want ErrEntropy", err)
	}

	// The in-process ledger is a hard bound: never reuse an ID, fail closed.
	manager.ledger = make(map[uint64]ledgerState, MaxIssuedPathIDs)
	for index := 0; index < MaxIssuedPathIDs; index++ {
		manager.ledger[uint64(index)+1] = ledgerClosed
	}
	if _, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("exhausted ledger error = %v; want ErrResourceLimit", err)
	}
}

func TestManagerRebuildLimit(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	manager.rebuild <- struct{}{}
	manager.rebuild <- struct{}{}
	if _, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("Open with both rebuild slots busy = %v; want ErrResourceLimit", err)
	}
	if _, err := opened.Replace(ctx, relayPolicy); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("Replace with both rebuild slots busy = %v; want ErrResourceLimit", err)
	}
	if opened.State() != StateCreated || len(manager.Snapshot()) != 1 {
		t.Fatalf("rebuild-limited Replace changed the table: %+v", manager.Snapshot())
	}
	<-manager.rebuild
	if _, err := opened.Replace(ctx, relayPolicy); err != nil {
		t.Fatalf("Replace after releasing one slot: %v", err)
	}
	<-manager.rebuild
	if _, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy); err != nil {
		t.Fatalf("Open after releasing both slots: %v", err)
	}
}

func TestManagerConcurrentLifecycle(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	var wait sync.WaitGroup
	failures := make(chan error, 64)
	for worker := 0; worker < 6; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 6; iteration++ {
				opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
				if err != nil {
					if !errors.Is(err, ErrResourceLimit) {
						failures <- err
					}
					continue
				}
				if _, err := opened.OpenFrame(); err != nil {
					failures <- err
					continue
				}
				if err := opened.MarkActive(); err != nil {
					failures <- err
					continue
				}
				if _, err := opened.Replace(ctx, relayPolicy); err != nil && !errors.Is(err, ErrResourceLimit) {
					failures <- err
					continue
				}
				if _, err := manager.Lookup(opened.ID(), opened.Generation()); err != nil && !errors.Is(err, ErrPathGenerationExpired) {
					failures <- err
					continue
				}
				_ = manager.Snapshot()
				if err := opened.Close(); err != nil && !errors.Is(err, ErrPathGenerationExpired) {
					failures <- err
				}
			}
		}()
	}
	wait.Wait()
	close(failures)
	for err := range failures {
		t.Fatalf("concurrent lifecycle error: %v", err)
	}
	for _, live := range manager.Snapshot() {
		if live.ID() == 0 || live.Generation() == 0 {
			t.Fatalf("snapshot entry with a zero identity: %+v", live)
		}
		expected, err := ComputeDigest(live.ID(), live.Generation(), live.Lane(), live.ViewVersion(), live.Nodes(), live.Links())
		if err != nil {
			t.Fatalf("snapshot digest: %v", err)
		}
		if expected != live.Digest() {
			t.Fatalf("snapshot digest mismatch for %d/%d", live.ID(), live.Generation())
		}
	}
}

func TestManagerCloseAndLookup(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	if _, err := manager.Lookup(1, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Lookup of an unknown PathID = %v; want ErrNotFound", err)
	}
	opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := manager.Lookup(opened.ID(), opened.Generation()+1); !errors.Is(err, ErrPathGenerationExpired) {
		t.Fatalf("Lookup with a wrong generation = %v; want ErrPathGenerationExpired", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("duplicate Close: %v", err)
	}
	if len(manager.Snapshot()) != 0 {
		t.Fatalf("snapshot after Close = %d paths", len(manager.Snapshot()))
	}
	if opened.State() != StateClosed {
		t.Fatalf("handle state after manager Close = %s; want Closed", opened.State())
	}
	if _, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy); !errors.Is(err, ErrClosed) {
		t.Fatalf("Open after Close = %v; want ErrClosed", err)
	}
	if _, err := manager.Lookup(opened.ID(), opened.Generation()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Lookup after Close = %v; want ErrClosed", err)
	}
	control, err := DecodeRouteControl(MessagePathOpen, func() []byte {
		nodes := fixture.streamNodes()
		links := fixture.streamLinks()
		digest, digestErr := ComputeDigest(99, 1, LaneStream, fixture.view.Version(), nodes, links)
		if digestErr != nil {
			t.Fatalf("ComputeDigest: %v", digestErr)
		}
		frame, encodeErr := PathOpen{
			PathID:      99,
			Generation:  1,
			Lane:        LaneStream,
			ViewVersion: fixture.view.Version(),
			Nodes:       nodes,
			Links:       []LinkInstance{{ID: links[0].ID, Epoch: links[0].Epoch}, {ID: links[1].ID, Epoch: links[1].Epoch}},
			Digest:      digest,
		}.Encode()
		if encodeErr != nil {
			t.Fatalf("PathOpen.Encode: %v", encodeErr)
		}
		return frame
	}())
	if err != nil {
		t.Fatalf("DecodeRouteControl: %v", err)
	}
	if _, err := fixture.managerAt(fixture.target).Accept(ctx, control.Open, fixture.streamLinks()); err != nil {
		t.Fatalf("Accept on a healthy manager: %v", err)
	}
}

func TestManagerStateGuards(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	// A PATH_READY/SESSION_READY without an emitted PATH_OPEN is a protocol
	// violation, not a silent promotion.
	created, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := created.MarkReady(readyFor(created, ReadyStatusReady, ErrorCodeNone)); !errors.Is(err, ErrState) {
		t.Fatalf("MarkReady before PATH_OPEN = %v; want ErrState", err)
	}
	if err := created.MarkActive(); !errors.Is(err, ErrState) {
		t.Fatalf("MarkActive before PATH_OPEN = %v; want ErrState", err)
	}
	if _, err := created.ReadyFrame(ReadyStatusReady, ErrorCodeNone); !errors.Is(err, ErrState) {
		t.Fatalf("ReadyFrame before PATH_OPEN = %v; want ErrState", err)
	}
	if _, err := created.OpenFrame(); err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	if err := created.MarkReady(readyFor(created, ReadyStatusReady, ErrorCodeNone)); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	if _, err := created.OpenFrame(); !errors.Is(err, ErrState) {
		t.Fatalf("OpenFrame after READY = %v; want ErrState", err)
	}
	if err := created.MarkActive(); err != nil {
		t.Fatalf("MarkActive: %v", err)
	}
	if err := created.Fail(BrokenReasonResource, 0); err != nil {
		t.Fatalf("Fail from Active: %v", err)
	}
	if created.State() != StateBroken {
		t.Fatalf("state = %s; want Broken", created.State())
	}
	if err := created.MarkBroken(brokenFor(created, BrokenReasonResource, 0)); err != nil {
		t.Fatalf("MarkBroken on a locally broken path must be idempotent: %v", err)
	}

	// Rejected PATH_READY outcomes break the path.
	rejected, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := rejected.OpenFrame(); err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	if err := rejected.MarkReady(readyFor(rejected, ReadyStatusReject, ErrorCodeResource)); err != nil {
		t.Fatalf("MarkReady(REJECT): %v", err)
	}
	if rejected.State() != StateBroken {
		t.Fatalf("state after REJECT = %s; want Broken", rejected.State())
	}
	rolledBack, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := rolledBack.OpenFrame(); err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	if err := rolledBack.MarkReady(readyFor(rolledBack, ReadyStatusRolledBack, ErrorCodeProtocol)); err != nil {
		t.Fatalf("MarkReady(ROLLED_BACK): %v", err)
	}
	if rolledBack.State() != StateBroken {
		t.Fatalf("state after ROLLED_BACK = %s; want Broken", rolledBack.State())
	}
}

func TestManagerAcceptedPathRoles(t *testing.T) {
	fixture := newPathFixture(t)
	source := fixture.manager()
	ctx := context.Background()

	opened, err := source.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	frame, err := opened.OpenFrame()
	if err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	control, err := DecodeRouteControl(MessagePathOpen, frame)
	if err != nil {
		t.Fatalf("DecodeRouteControl: %v", err)
	}
	target := fixture.managerAt(fixture.target)
	installed, err := target.Accept(ctx, control.Open, fixture.streamLinks())
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	// The source owns candidate selection, so a hop/target-side path is not
	// replaced locally: the next PATH_OPEN does that.
	if _, err := installed.Replace(ctx, relayPolicy); !errors.Is(err, ErrState) {
		t.Fatalf("Replace on an accepted path = %v; want ErrState", err)
	}
	if installed.State() != StateOpenPending {
		t.Fatalf("state after rejected Replace = %s; want OpenPending", installed.State())
	}
	if _, err := opened.Replace(ctx, relayPolicy); err != nil {
		t.Fatalf("Replace on a source-side path: %v", err)
	}
}

func TestManagerConcurrentReplaceKeepsOneGeneration(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := opened.OpenFrame(); err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for attempt := 0; attempt < 2; attempt++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := opened.Replace(ctx, relayPolicy)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrPathGenerationExpired), errors.Is(err, ErrState), errors.Is(err, ErrResourceLimit):
		default:
			t.Fatalf("concurrent Replace error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent Replace successes = %d; want exactly 1", successes)
	}
	snapshot := manager.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Generation() != 2 {
		t.Fatalf("concurrent Replace left generation %+v; want exactly generation 2", snapshot)
	}
	expected, err := ComputeDigest(snapshot[0].ID(), 2, LaneStream, snapshot[0].ViewVersion(), snapshot[0].Nodes(), snapshot[0].Links())
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	if expected != snapshot[0].Digest() {
		t.Fatal("concurrent Replace left a digest that does not match its geometry")
	}
}

func TestManagerPathTableLimit(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	for index := 0; index < MaxPaths; index++ {
		if _, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy); err != nil {
			t.Fatalf("Open %d: %v", index, err)
		}
	}
	if _, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("Open past the path table limit = %v; want ErrResourceLimit", err)
	}
	if len(manager.Snapshot()) != MaxPaths {
		t.Fatalf("snapshot = %d paths; want %d", len(manager.Snapshot()), MaxPaths)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(manager.Snapshot()) != 0 {
		t.Fatal("Close did not release the path table")
	}
}

func TestManagerReplaceDetectsConcurrentChange(t *testing.T) {
	fixture := newPathFixture(t)
	ctx := context.Background()

	// A local failure that lands while the RouteView is being queried must not
	// be overwritten by the replacement candidate.
	armed := false
	var failing Path
	failingManager, err := NewManager(fixture.local, fixture.view, func(LinkRef) bool {
		if armed {
			_ = failing.Fail(BrokenReasonLinkDown, 0)
		}
		return true
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	failing, err = failingManager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	armed = true
	if _, err := failing.Replace(ctx, relayPolicy); !errors.Is(err, ErrState) {
		t.Fatalf("Replace over a concurrently broken path = %v; want ErrState", err)
	}
	if snapshot := failingManager.Snapshot(); len(snapshot) != 1 || snapshot[0].State() != StateBroken || snapshot[0].Generation() != 1 {
		t.Fatalf("snapshot after the rejected Replace = %+v", snapshot)
	}

	// A nested Replace that advances the generation while the outer query runs
	// makes the outer attempt stale instead of silently overwriting it.
	nestedArmed := false
	var current Path
	nestedManager, err := NewManager(fixture.local, fixture.view, func(LinkRef) bool {
		if nestedArmed {
			nestedArmed = false
			if _, err := current.Replace(ctx, relayPolicy); err != nil {
				t.Errorf("nested Replace: %v", err)
			}
		}
		return true
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	current, err = nestedManager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	nestedArmed = true
	if _, err := current.Replace(ctx, relayPolicy); !errors.Is(err, ErrPathGenerationExpired) {
		t.Fatalf("Replace overtaken by a newer generation = %v; want ErrPathGenerationExpired", err)
	}
	snapshot := nestedManager.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Generation() != 2 {
		t.Fatalf("snapshot after the nested Replace = %+v", snapshot)
	}
	if fixture.local != snapshot[0].Nodes()[0] || snapshot[0].Destination() != fixture.target {
		t.Fatalf("path endpoints = %v..%v", snapshot[0].Nodes()[0], snapshot[0].Destination())
	}
}

func TestManagerAcceptGuards(t *testing.T) {
	fixture := newPathFixture(t)
	source := fixture.manager()
	ctx := context.Background()

	opened, err := source.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	frame, err := opened.OpenFrame()
	if err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	control, err := DecodeRouteControl(MessagePathOpen, frame)
	if err != nil {
		t.Fatalf("DecodeRouteControl: %v", err)
	}
	target := fixture.managerAt(fixture.target)
	installed, err := target.Accept(ctx, control.Open, fixture.streamLinks())
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := target.Accept(cancelled, control.Open, fixture.streamLinks()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Accept with a cancelled context = %v; want context.Canceled", err)
	}
	fixture.setInactive(linkStreamBC, true)
	if _, err := target.Accept(ctx, control.Open, fixture.streamLinks()); !errors.Is(err, ErrInactiveLink) {
		t.Fatalf("Accept with an inactive hop = %v; want ErrInactiveLink", err)
	}
	fixture.setInactive(linkStreamBC, false)

	if err := installed.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := target.Accept(ctx, control.Open, fixture.streamLinks()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Accept for a closed PathID = %v; want ErrClosed", err)
	}
	target.mu.Lock()
	target.ledger[control.Open.PathID] = ledgerRetired
	target.mu.Unlock()
	if _, err := target.Accept(ctx, control.Open, fixture.streamLinks()); !errors.Is(err, ErrPathGenerationExpired) {
		t.Fatalf("Accept for a retired PathID = %v; want ErrPathGenerationExpired", err)
	}

	other := fixture.managerAt(fixture.target)
	other.mu.Lock()
	other.ledger = make(map[uint64]ledgerState, MaxIssuedPathIDs)
	for index := 0; index < MaxIssuedPathIDs; index++ {
		other.ledger[uint64(index)+1] = ledgerClosed
	}
	other.mu.Unlock()
	if _, err := other.Accept(ctx, control.Open, fixture.streamLinks()); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("Accept with an exhausted PathID ledger = %v; want ErrResourceLimit", err)
	}
}

func TestManagerStaleViewDoesNotMigrateReadyPath(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := opened.OpenFrame(); err != nil {
		t.Fatalf("OpenFrame: %v", err)
	}
	if err := opened.MarkReady(readyFor(opened, ReadyStatusReady, ErrorCodeNone)); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	before := manager.Snapshot()[0]

	fixture.commitUnrelatedNode(4242)
	if fixture.view.Freshness() != topology.RouteViewStale {
		t.Fatalf("freshness after an unrelated commit = %v; want stale", fixture.view.Freshness())
	}
	current := manager.Snapshot()[0]
	if current.Generation() != before.Generation() || current.Digest() != before.Digest() || current.State() != StateReady {
		t.Fatalf("a RouteView update migrated the Ready path: %+v -> %+v", before, current)
	}
	if opened.State() != StateReady {
		t.Fatalf("handle state after the view update = %s; want Ready", opened.State())
	}

	// Unaffected targets still get candidates from the stale view; the result
	// carries the stale freshness instead of silently pretending to be fresh.
	stale, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open from a stale view: %v", err)
	}
	if stale.Freshness() != topology.RouteViewStale {
		t.Fatalf("stale selection freshness = %v; want stale", stale.Freshness())
	}
	if stale.ID() == opened.ID() {
		t.Fatal("a new Open reused the installed PathID")
	}
	fixture.view.Refresh(fixture.now.Add(time.Second))
	if fixture.view.Freshness() != topology.RouteViewFresh {
		t.Fatalf("freshness after Refresh = %v; want fresh", fixture.view.Freshness())
	}
	if reopened := manager.Snapshot(); len(reopened) != 2 {
		t.Fatalf("snapshot = %d paths; want 2", len(reopened))
	}
}

func TestManagerSnapshotIsDetached(t *testing.T) {
	fixture := newPathFixture(t)
	manager := fixture.manager()
	ctx := context.Background()

	opened, err := manager.Open(ctx, fixture.target, LaneStream, relayPolicy)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	originalNodes := opened.Nodes()
	originalLinks := opened.Links()
	originalNodes[0] = NodeID{}
	originalLinks[0].ConnectionType = "mutated"
	originalLinks[0].Epoch = 0

	snapshot := manager.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot = %d paths", len(snapshot))
	}
	if !slices.Equal(snapshot[0].Nodes(), fixture.streamNodes()) {
		t.Fatalf("snapshot nodes were aliased: %v", snapshot[0].Nodes())
	}
	if !slices.Equal(snapshot[0].Links(), fixture.streamLinks()) {
		t.Fatalf("snapshot links were aliased: %v", snapshot[0].Links())
	}
	returned := manager.Snapshot()[0].Links()
	returned[0].ConnectionType = "mutated-again"
	if manager.Snapshot()[0].Links()[0].ConnectionType != "tcp" {
		t.Fatal("Snapshot aliases its own link slice")
	}
	if opened.Nodes()[0] != fixture.local || opened.Links()[0].ConnectionType != "tcp" {
		t.Fatal("handle getters alias manager state")
	}
}
