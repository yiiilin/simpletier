package simpletier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/topology"
)

// The tests in this file drive the authenticated FACT v2 consumer through the
// real protected control IO. Every SUMMARY/PAGE/ACK below is encoded by the
// frozen v2 codec and carried as an authenticated LINK_CTRL frame of a real
// Noise Link established by the production carrier admission path: the peer is a
// host-started initiator, the Network under test is the responder, and the
// assertions read the production FactStore, RouteView and fact runtime status.
// Nothing here is mocked, and no production file is touched by these tests.

const (
	factRuntimeTestToken = "0123456789abcdef0123456789abcdef"
	factRuntimeIOTimeout = 5 * time.Second
)

// factTestPeer is one authenticated peer of the Network under test. It owns the
// initiator side of a real link.ProtectedControlIO, so the FACT records it sends
// travel through the same protected framing the production control pump reads.
type factTestPeer struct {
	network  *network
	conn     net.Conn
	control  *link.ProtectedControlIO
	identity security.Identity
	nodeID   topology.NodeID
	timeout  time.Duration
	skipper  *factFrameSkipper
}

// newFactTestPeer authenticates one host-started initiator against n's carrier
// listener and waits until the Network registered that exact Link.
func newFactTestPeer(t *testing.T, n *network, linkID uint64) *factTestPeer {
	t.Helper()
	if len(n.carrierListeners) == 0 {
		t.Fatal("FACT test peer requires a Network with a carrier listener")
	}
	conn, err := net.DialTimeout("tcp", n.carrierListeners[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := link.Handshake(ctx, conn, link.LinkConfig{
		Descriptor: n.networkContext.Descriptor(), NetworkID: n.networkContext.WireID(),
		PSK: n.networkPSK, Identity: identity, Initiator: true,
		LinkID: linkID, LinkEpoch: 1, Generation: 21, LaneID: laneControl,
		CapabilityVersion: uint16(link.CapabilityVersion), CapabilityMask: link.RequiredCapabilityMask,
		RequiredCapabilityMask: link.RequiredCapabilityMask,
	})
	if err != nil {
		t.Fatalf("peer handshake: %v", err)
	}
	control, err := link.NewProtectedControlIO(conn, result, n.networkContext.Descriptor(), true)
	if err != nil {
		t.Fatalf("peer protected control IO: %v", err)
	}
	waitAdmissionLinks(t, n, 1)
	return &factTestPeer{
		network:  n,
		conn:     conn,
		control:  control,
		identity: identity,
		nodeID:   identity.NodeID,
		timeout:  factRuntimeIOTimeout,
		skipper:  newFactFrameSkipper(n, control),
	}
}

// factFrameSkipper answers the Network's own legal outbound FACT_SUMMARY and
// FACT_PAGE frames on an authenticated raw test peer. The production Network now
// advertises snapshots automatically, so a raw peer that expects PONGs or its
// own ACKs must complete those transfers instead of condemning or disabling the
// sender.
type factFrameSkipper struct {
	network *network
	control *link.ProtectedControlIO
	summary *topology.FactSummary
	pages   map[uint32]topology.FactPage
	// Observability for tests that assert the Network actually drove a
	// multi-page outbound transfer: completed snapshots, the largest declared
	// page count and how many page frames were served.
	completed  int
	maxPages   uint32
	pageFrames int
}

func newFactFrameSkipper(n *network, control *link.ProtectedControlIO) *factFrameSkipper {
	return &factFrameSkipper{network: n, control: control}
}

// skip consumes one outbound FACT frame when it is part of the Network's own
// snapshot transfer and reports whether the caller must keep reading.
func (s *factFrameSkipper) skip(t *testing.T, message link.ControlMessage) bool {
	t.Helper()
	switch message.Type {
	case 6:
		summary, err := topology.DecodeFactSummary(message.Payload)
		if err != nil {
			t.Fatalf("decode the Network's outbound FACT_SUMMARY: %v", err)
		}
		if summary.NetworkID != s.network.networkContext.WireID() {
			t.Fatalf("outbound FACT_SUMMARY NetworkID = %d; want this Network's locator %d", summary.NetworkID, s.network.networkContext.WireID())
		}
		s.summary = &summary
		s.pages = nil
		if summary.PageCount > s.maxPages {
			s.maxPages = summary.PageCount
		}
		if summary.PageCount == 0 {
			s.ack(t, topology.FactAck{
				ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: summary.SenderIncarnation,
				NetworkID: summary.NetworkID, SnapshotVersion: summary.SnapshotVersion,
				Status: topology.AckComplete,
			})
			s.completed++
			return true
		}
		s.pages = make(map[uint32]topology.FactPage, summary.PageCount)
		s.ack(t, topology.FactAck{
			ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: summary.SenderIncarnation,
			NetworkID: summary.NetworkID, SnapshotVersion: summary.SnapshotVersion,
			Status: topology.AckNeedPage, MissingPage: 0,
		})
		return true
	case 7:
		page, err := topology.DecodeFactPage(message.Payload)
		if err != nil {
			t.Fatalf("decode the Network's outbound FACT_PAGE: %v", err)
		}
		if s.summary == nil || page.SnapshotVersion != s.summary.SnapshotVersion {
			// A page of a snapshot this peer never saw is answered with
			// NEED_SUMMARY by a real receiver; the test peer simply ignores it
			// and the bounded sender retries the SUMMARY.
			return true
		}
		if s.pages == nil {
			s.pages = make(map[uint32]topology.FactPage, page.PageCount)
		}
		s.pages[page.PageNo] = page
		s.pageFrames++
		missing := -1
		for index := uint32(0); index < page.PageCount; index++ {
			if _, ok := s.pages[index]; !ok {
				missing = int(index)
				break
			}
		}
		status, missingPage := topology.AckComplete, uint32(0)
		if missing >= 0 {
			status, missingPage = topology.AckNeedPage, uint32(missing)
		}
		s.ack(t, topology.FactAck{
			ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: page.SenderIncarnation,
			NetworkID: page.NetworkID, SnapshotVersion: page.SnapshotVersion,
			PageNo: page.PageNo, Status: status, MissingPage: missingPage,
		})
		if status == topology.AckComplete {
			s.completed++
		}
		return true
	default:
		return false
	}
}

func (s *factFrameSkipper) ack(t *testing.T, ack topology.FactAck) {
	t.Helper()
	payload, err := topology.EncodeFactAck(ack)
	if err != nil {
		t.Fatalf("encode outbound FACT_ACK: %v", err)
	}
	if err := s.control.WriteControl(link.ControlMessage{Type: 8, Payload: payload}); err != nil {
		t.Fatalf("write outbound FACT_ACK: %v", err)
	}
}

// readSkippingFacts reads one authenticated control frame, transparently
// serving any of the Network's own outbound FACT frames, and returns the next
// frame that is not part of that transfer.
func readSkippingFacts(t *testing.T, skipper *factFrameSkipper, control *link.ProtectedControlIO) link.ControlMessage {
	t.Helper()
	for {
		message, err := control.ReadControl()
		if err != nil {
			t.Fatalf("read authenticated control: %v", err)
		}
		if skipper.skip(t, message) {
			continue
		}
		return message
	}
}

func (p *factTestPeer) armDeadline(t *testing.T) {
	t.Helper()
	if err := p.conn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
		t.Fatal(err)
	}
}

func (p *factTestPeer) send(t *testing.T, typ uint8, payload []byte) {
	t.Helper()
	p.armDeadline(t)
	if err := p.control.WriteControl(link.ControlMessage{Type: typ, Payload: payload}); err != nil {
		t.Fatalf("write authenticated control type %d: %v", typ, err)
	}
}

func (p *factTestPeer) sendSummary(t *testing.T, summary topology.FactSummary) {
	t.Helper()
	payload, err := topology.EncodeFactSummary(summary)
	if err != nil {
		t.Fatalf("encode FACT_SUMMARY: %v", err)
	}
	p.send(t, 6, payload)
}

func (p *factTestPeer) sendPage(t *testing.T, page topology.FactPage) {
	t.Helper()
	payload, err := topology.EncodeFactPage(page)
	if err != nil {
		t.Fatalf("encode FACT_PAGE: %v", err)
	}
	p.send(t, 7, payload)
}

func (p *factTestPeer) sendAck(t *testing.T, ack topology.FactAck) {
	t.Helper()
	payload, err := topology.EncodeFactAck(ack)
	if err != nil {
		t.Fatalf("encode FACT_ACK: %v", err)
	}
	p.send(t, 8, payload)
}

// readControl reads the next authenticated control message the test owns,
// transparently completing the Network's own legal outbound FACT transfer.
func (p *factTestPeer) readControl(t *testing.T) link.ControlMessage {
	t.Helper()
	for {
		p.armDeadline(t)
		message, err := p.control.ReadControl()
		if err != nil {
			t.Fatalf("read authenticated control: %v", err)
		}
		if p.skipper.skip(t, message) {
			continue
		}
		return message
	}
}

// expectAck reads one FACT_ACK and pins its echo of the frozen container
// identity: the protocol version and the local NetworkID are never substituted.
func (p *factTestPeer) expectAck(t *testing.T, status topology.AckStatus, pageNo uint32) topology.FactAck {
	t.Helper()
	message := p.readControl(t)
	if message.Type != 8 {
		t.Fatalf("control type = %d; want 8 (FACT_ACK)", message.Type)
	}
	ack, err := topology.DecodeFactAck(message.Payload)
	if err != nil {
		t.Fatalf("decode FACT_ACK: %v", err)
	}
	if ack.ProtocolVersion != topology.FactProtocolVersion {
		t.Fatalf("FACT_ACK protocol version = %d; want %d", ack.ProtocolVersion, topology.FactProtocolVersion)
	}
	if want := p.network.networkContext.WireID(); ack.NetworkID != want {
		t.Fatalf("FACT_ACK NetworkID = %d; want this Network's locator %d", ack.NetworkID, want)
	}
	if ack.Status != status || ack.PageNo != pageNo {
		t.Fatalf("FACT_ACK = status %d page %d reason %d missing %d; want status %d page %d",
			ack.Status, ack.PageNo, ack.Reason, ack.MissingPage, status, pageNo)
	}
	return ack
}

// expectLinkRetired proves the Network withdrew this peer's Link, which is what
// a terminal protected-control failure must do.
func (p *factTestPeer) expectLinkRetired(t *testing.T) {
	t.Helper()
	waitAdmissionLinks(t, p.network, 0)
	if err := p.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// The pump may already have queued frames before it retired — a FACT ACK for a
	// summary that arrived earlier, for instance. Drain until the stream ends instead
	// of requiring the very next read to be EOF.
	buf := make([]byte, 512)
	for {
		_, err := p.conn.Read(buf)
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			t.Fatalf("peer did not observe the retired Link: %v", err)
		}
	}
}

func factTestMillisWindow(now time.Time) (uint64, uint64) {
	return uint64(now.Add(-time.Second).UnixMilli()), uint64(now.Add(40 * time.Second).UnixMilli())
}

func factTestNodeRecord(networkID uint64, public [32]byte, version topology.FactVersion, issued, expires uint64) topology.FactRecord {
	digest := sha256.Sum256(public[:])
	var node topology.NodeID
	copy(node[:], digest[:16])
	return topology.FactRecord{
		Envelope: topology.FactEnvelope{
			NetworkID: networkID, Kind: topology.FactNode, Origin: node, Version: version, IssuedAt: issued, ExpiresAt: expires,
		},
		Payload: topology.NodePayload{NodeID: node, StaticPublicKey: public},
	}
}

func factTestAddressRecord(networkID uint64, node topology.NodeID, address string, version topology.FactVersion, issued, expires uint64) topology.FactRecord {
	return topology.FactRecord{
		Envelope: topology.FactEnvelope{
			NetworkID: networkID, Kind: topology.FactAddress, Origin: node, Version: version, IssuedAt: issued, ExpiresAt: expires,
		},
		Payload: topology.AddressPayload{NodeID: node, IP: netip.MustParseAddr(address), PrefixLen: 32},
	}
}

func factTestLinkRecord(networkID uint64, from, to topology.NodeID, linkID, epoch uint64, lane uint8, connectionType string, version topology.FactVersion, issued, expires uint64) topology.FactRecord {
	return topology.FactRecord{
		Envelope: topology.FactEnvelope{
			NetworkID: networkID, Kind: topology.FactLink, Origin: from, Version: version, IssuedAt: issued, ExpiresAt: expires,
		},
		Payload: topology.LinkPayload{
			LinkID: linkID, LinkEpoch: epoch, LaneID: lane, From: from, To: to,
			Capabilities: []string{}, ConnectionType: connectionType,
		},
	}
}

// factTestEmptySnapshot builds the zero-page snapshot: it declares no fact and
// no page, so the receiver has nothing to request and commits it directly.
func factTestEmptySnapshot(t *testing.T, networkID, incarnation, version uint64) topology.FactSummary {
	t.Helper()
	digest, err := topology.SnapshotDigest(incarnation, version, nil)
	if err != nil {
		t.Fatalf("empty snapshot digest: %v", err)
	}
	return topology.FactSummary{
		ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: incarnation,
		NetworkID: networkID, SnapshotVersion: version, Digest: digest,
	}
}

// factTestSnapshot splits records into digest-bound pages of at most perPage
// records each, honouring the frozen 48 KiB page bound, and returns the summary
// whose digest binds exactly those pages.
func factTestSnapshot(t *testing.T, networkID, incarnation, version uint64, perPage int, records []topology.FactRecord) (topology.FactSummary, []topology.FactPage) {
	t.Helper()
	if perPage <= 0 || perPage > topology.MaxPageRecords {
		perPage = topology.MaxPageRecords
	}
	sorted := make([]topology.FactRecord, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		left, err := topology.FactKey(sorted[i])
		if err != nil {
			t.Fatalf("fact key: %v", err)
		}
		right, err := topology.FactKey(sorted[j])
		if err != nil {
			t.Fatalf("fact key: %v", err)
		}
		return bytes.Compare(left, right) < 0
	})
	var chunks [][]topology.FactRecord
	var current []topology.FactRecord
	currentBytes := 0
	for _, record := range sorted {
		canonical, err := topology.EncodeFactRecord(record)
		if err != nil {
			t.Fatalf("encode record for chunking: %v", err)
		}
		if len(current) == perPage || currentBytes+len(canonical) > topology.MaxPageBytes {
			chunks = append(chunks, current)
			current, currentBytes = nil, 0
		}
		current = append(current, record)
		currentBytes += len(canonical)
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}
	pages := make([]topology.FactPage, 0, len(chunks))
	digests := make([][32]byte, 0, len(chunks))
	for number, chunk := range chunks {
		raw, err := topology.EncodeFactPage(topology.FactPage{
			ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: incarnation,
			NetworkID: networkID, SnapshotVersion: version, PageNo: uint32(number),
			PageCount: uint32(len(chunks)), Facts: chunk,
		})
		if err != nil {
			t.Fatalf("encode page %d: %v", number, err)
		}
		page, err := topology.DecodeFactPage(raw)
		if err != nil {
			t.Fatalf("decode page %d: %v", number, err)
		}
		pages = append(pages, page)
		digests = append(digests, page.PageDigest)
	}
	digest, err := topology.SnapshotDigest(incarnation, version, digests)
	if err != nil {
		t.Fatalf("snapshot digest: %v", err)
	}
	return topology.FactSummary{
		ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: incarnation,
		NetworkID: networkID, SnapshotVersion: version,
		FactCount: uint32(len(sorted)), PageCount: uint32(len(chunks)), Digest: digest,
	}, pages
}

func factTestKey(t *testing.T, record topology.FactRecord) []byte {
	t.Helper()
	key, err := topology.FactKey(record)
	if err != nil {
		t.Fatalf("fact key: %v", err)
	}
	return key
}

// factTestIsCurrent asks the durable FactStore whether this exact record version
// is the visible fact for its key.
func factTestIsCurrent(t *testing.T, n *network, record topology.FactRecord, now time.Time) bool {
	t.Helper()
	return n.facts.store.IsCurrent(factTestKey(t, record), record.Envelope.Version, now)
}

// factTestSnapshotContains counts how many visible facts equal one record
// version. The caller decides whether it must be exactly one or zero.
func factTestSnapshotContains(t *testing.T, records []topology.FactRecord, want topology.FactRecord) int {
	t.Helper()
	wantKey := factTestKey(t, want)
	found := 0
	for _, record := range records {
		if bytes.Equal(factTestKey(t, record), wantKey) && record.Envelope.Version == want.Envelope.Version {
			found++
		}
	}
	return found
}

// waitFactLocalPublication waits until the Network's own NODE fact is visible,
// which the admission path publishes before any Link is reported as admitted.
func waitFactLocalPublication(t *testing.T, n *network, localNode topology.NodeID) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		records, _, err := n.facts.store.Snapshot(time.Now())
		if err == nil {
			for _, record := range records {
				if record.Envelope.Kind == topology.FactNode && record.Envelope.Origin == localNode {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("local NODE fact was not published: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

// factTestSettledVersion waits for the admission-time local publication and
// returns the FactStore version it settled on, so a test can tell a later
// advance caused by a peer snapshot apart from the Network's own advertisement.
func factTestSettledVersion(t *testing.T, n *network) uint64 {
	t.Helper()
	identity, err := n.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	waitFactLocalPublication(t, n, topology.NodeID(identity.NodeID))
	return n.facts.store.Version()
}

// waitFactRouteFresh waits until the RouteView rebuild worker published a view
// that matches the current FactStore version.
func waitFactRouteFresh(t *testing.T, n *network) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if status := n.factStatus(); status.RouteFresh {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("RouteView did not become fresh: %+v", n.factStatus())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFactRuntimeProtectedControlSummaryPageComplete(t *testing.T) {
	n := admissionNetwork(t, factRuntimeTestToken)
	peer := newFactTestPeer(t, n, 0x1001)
	networkID := n.networkContext.WireID()
	localIdentity, err := n.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	localNode := topology.NodeID(localIdentity.NodeID)
	waitFactLocalPublication(t, n, localNode)

	// The Network's own configured fixed_ip is already a resolvable ADDRESS fact
	// published by the admission path, before any peer snapshot exists.
	waitFactRouteFresh(t, n)
	localAddress := netip.MustParseAddr("10.20.0.7")
	resolvedLocal, err := n.facts.routes.ResolveVirtualIP(localAddress)
	if err != nil {
		t.Fatalf("ResolveVirtualIP(local fixed ip) error = %v", err)
	}
	if resolvedLocal.NodeID != localNode {
		t.Fatalf("local address owner = %x; want %x", resolvedLocal.NodeID, localNode)
	}

	now := time.Now()
	issued, expires := factTestMillisWindow(now)
	records := []topology.FactRecord{
		factTestNodeRecord(networkID, peer.identity.PublicKey, topology.FactVersion{Incarnation: 3, Sequence: 1}, issued, expires),
		factTestAddressRecord(networkID, peer.nodeID, "10.60.0.9", topology.FactVersion{Incarnation: 3, Sequence: 2}, issued, expires),
		factTestAddressRecord(networkID, peer.nodeID, "10.60.0.10", topology.FactVersion{Incarnation: 3, Sequence: 3}, issued, expires),
		factTestLinkRecord(networkID, peer.nodeID, localNode, 0x7001, 1, topology.FactLaneControl, "host-fact-pipe", topology.FactVersion{Incarnation: 3, Sequence: 4}, issued, expires),
	}
	summary, pages := factTestSnapshot(t, networkID, 3, 1, 2, records)
	if len(pages) != 2 {
		t.Fatalf("fixture produced %d pages; want 2", len(pages))
	}

	versionBefore := n.facts.store.Version()
	peer.sendSummary(t, summary)
	ack := peer.expectAck(t, topology.AckNeedPage, 0)
	if ack.SenderIncarnation != 3 || ack.SnapshotVersion != 1 || ack.MissingPage != 0 {
		t.Fatalf("NEED_PAGE echo = incarnation %d version %d missing %d; want the sender's 3/1/0",
			ack.SenderIncarnation, ack.SnapshotVersion, ack.MissingPage)
	}
	if status := n.factStatus(); status.StagingLinks != 1 || status.Committed != 0 || status.Rejected != 0 {
		t.Fatalf("staging after SUMMARY = %+v; want one staged Link and no commit", status)
	}
	if n.facts.store.Version() != versionBefore {
		t.Fatal("requesting a page committed a fact")
	}

	// Out-of-order transfer: page 1 is staged while page 0 is still missing, so
	// the receiver asks for the first missing page instead of completing.
	peer.sendPage(t, pages[1])
	ack = peer.expectAck(t, topology.AckNeedPage, 1)
	if ack.MissingPage != 0 {
		t.Fatalf("NEED_PAGE missing page = %d; want 0", ack.MissingPage)
	}
	if status := n.factStatus(); status.StagingLinks != 1 || status.Committed != 0 {
		t.Fatalf("staging after out-of-order page = %+v", status)
	}

	peer.sendPage(t, pages[0])
	peer.expectAck(t, topology.AckComplete, 1)

	status := n.factStatus()
	if status.StagingLinks != 0 || status.StagedBytes != 0 {
		t.Fatalf("staging after COMPLETE = %d Links / %d bytes; want fully released", status.StagingLinks, status.StagedBytes)
	}
	if status.Committed != 1 || status.Rejected != 0 || status.Withdrawals != 0 || status.IgnoredAcks != 0 || status.StoreFailed {
		t.Fatalf("counters after COMPLETE = %+v", status)
	}
	if status.LocalLinks != 0 {
		t.Fatalf("responder published %d initiator Link instances; want none", status.LocalLinks)
	}

	// FactStore: exactly the committed records and versions are visible, the
	// local facts survived the remote commit, and no partial state leaked.
	committedVersion := n.facts.store.Version()
	if committedVersion == versionBefore {
		t.Fatal("COMPLETE did not advance the FactStore version")
	}
	visible, viewVersion, err := n.facts.store.Snapshot(now)
	if err != nil {
		t.Fatalf("FactStore Snapshot() error = %v", err)
	}
	if viewVersion != committedVersion {
		t.Fatalf("Snapshot version = %d; want %d", viewVersion, committedVersion)
	}
	for _, record := range records {
		if !factTestIsCurrent(t, n, record, now) {
			t.Fatalf("committed fact %T version %+v is not current", record.Payload, record.Envelope.Version)
		}
		if got := factTestSnapshotContains(t, visible, record); got != 1 {
			t.Fatalf("visible copies of %T version %+v = %d; want exactly 1", record.Payload, record.Envelope.Version, got)
		}
	}
	localVisible := 0
	for _, record := range visible {
		if record.Envelope.Origin == localNode && record.Envelope.Kind == topology.FactNode {
			localVisible++
		}
	}
	if localVisible != 1 {
		t.Fatalf("local NODE facts after a remote commit = %d; want exactly 1", localVisible)
	}

	// RouteView: fresh, tracking the committed store version, resolving the
	// committed ADDRESS to its authenticated owner and pinned fact version.
	waitFactRouteFresh(t, n)
	if status := n.factStatus(); status.RouteVersion != status.FactVersion {
		t.Fatalf("RouteView version %d != FactStore version %d", status.RouteVersion, status.FactVersion)
	}
	peerAddress := netip.MustParseAddr("10.60.0.9")
	resolved, err := n.facts.routes.ResolveVirtualIP(peerAddress)
	if err != nil {
		t.Fatalf("ResolveVirtualIP(%s) error = %v", peerAddress, err)
	}
	if resolved.NodeID != peer.nodeID {
		t.Fatalf("address owner = %x; want authenticated peer %x", resolved.NodeID, peer.nodeID)
	}
	if resolved.Prefix != netip.PrefixFrom(peerAddress, 32) {
		t.Fatalf("address prefix = %s; want %s/32", resolved.Prefix, peerAddress)
	}
	if want := (topology.FactVersion{Incarnation: 3, Sequence: 2}); resolved.FactVersion != want {
		t.Fatalf("address fact version = %+v; want %+v", resolved.FactVersion, want)
	}
	if resolved.Freshness != topology.RouteViewFresh {
		t.Fatalf("address freshness = %d; want fresh", resolved.Freshness)
	}

	// Deliberate boundary of this slice: a published, queryable RouteView still
	// installs no data lane, so an authenticated peer is reachable by address
	// resolution but has no candidate path, and DialContext has no route.
	if candidates, err := n.facts.routes.Candidates(peer.nodeID, lanePacket, topology.RoutePolicy{}); !errors.Is(err, topology.ErrNoRoute) {
		t.Fatalf("PACKET candidates to the authenticated peer = (%v, %v); want ErrNoRoute", candidates, err)
	}
	if _, err := n.DialContext(context.Background(), "tcp", "10.60.0.9:80"); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("DialContext after committed facts = %v; want ErrNoRoute", err)
	}
	if err := n.facts.refreshLocal(time.Now()); err != nil {
		t.Fatalf("refreshLocal() error = %v", err)
	}
}

func TestFactRuntimeSenderFloorRejectsStaleAndConflictingSnapshots(t *testing.T) {
	n := admissionNetwork(t, factRuntimeTestToken)
	peer := newFactTestPeer(t, n, 0x2001)
	networkID := n.networkContext.WireID()
	now := time.Now()
	issued, expires := factTestMillisWindow(now)

	// A zero-page snapshot has no page to request and is committed directly.
	peer.sendSummary(t, factTestEmptySnapshot(t, networkID, 9, 1))
	peer.expectAck(t, topology.AckComplete, 0)

	// An older sender incarnation is stale even though every container field is
	// well formed: the sender already moved on, and the receiver says so.
	staleRecord := factTestNodeRecord(networkID, peer.identity.PublicKey, topology.FactVersion{Incarnation: 8, Sequence: 1}, issued, expires)
	stale, _ := factTestSnapshot(t, networkID, 8, 1, 0, []topology.FactRecord{staleRecord})
	peer.sendSummary(t, stale)
	ack := peer.expectAck(t, topology.AckReject, 0)
	if ack.Reason != factAckReasonVersion {
		t.Fatalf("stale summary reason = %d; want %d (version)", ack.Reason, factAckReasonVersion)
	}
	if ack.SenderIncarnation != 8 || ack.SnapshotVersion != 1 {
		t.Fatalf("REJECT echo = incarnation %d version %d; want the sender's 8/1", ack.SenderIncarnation, ack.SnapshotVersion)
	}
	if status := n.factStatus(); status.StagingLinks != 0 {
		t.Fatalf("stale summary staged %d Links; want none", status.StagingLinks)
	}

	// The already committed incarnation/version with different bytes cannot be a
	// repeat of that snapshot, so it is rejected on its digest.
	otherDigest := sha256.Sum256([]byte("not-the-committed-snapshot"))
	peer.sendSummary(t, topology.FactSummary{
		ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: 9, NetworkID: networkID,
		SnapshotVersion: 1, FactCount: 1, PageCount: 1, Digest: otherDigest,
	})
	ack = peer.expectAck(t, topology.AckReject, 0)
	if ack.Reason != factAckReasonDigest {
		t.Fatalf("same-version different-bytes reason = %d; want %d (digest)", ack.Reason, factAckReasonDigest)
	}

	// A newer snapshot commits normally, and the identical retry of that exact
	// digest-bound version is accepted idempotently instead of being duplicated.
	record := factTestNodeRecord(networkID, peer.identity.PublicKey, topology.FactVersion{Incarnation: 9, Sequence: 1}, issued, expires)
	summary, pages := factTestSnapshot(t, networkID, 9, 2, 0, []topology.FactRecord{record})
	for attempt := 1; attempt <= 2; attempt++ {
		peer.sendSummary(t, summary)
		peer.expectAck(t, topology.AckNeedPage, 0)
		peer.sendPage(t, pages[0])
		peer.expectAck(t, topology.AckComplete, 0)
		if !factTestIsCurrent(t, n, record, now) {
			t.Fatalf("attempt %d: committed fact is not current", attempt)
		}
	}
	visible, _, err := n.facts.store.Snapshot(now)
	if err != nil {
		t.Fatalf("FactStore Snapshot() error = %v", err)
	}
	if got := factTestSnapshotContains(t, visible, record); got != 1 {
		t.Fatalf("visible copies after an idempotent repeat = %d; want exactly 1", got)
	}
	status := n.factStatus()
	if status.Committed != 3 || status.Rejected != 2 {
		t.Fatalf("counters = committed %d rejected %d; want 3/2", status.Committed, status.Rejected)
	}
	if status.StoreFailed {
		t.Fatal("a sender-floor rejection was reported as a store failure")
	}
}

// factTestRawSummary lays out the frozen 65-byte SUMMARY container by hand, so a
// test can present a shape the encoder itself would refuse to produce.
func factTestRawSummary(version uint8, incarnation, networkID, snapshot uint64, factCount, pageCount uint32, digest [32]byte) []byte {
	b := []byte{version}
	b = binary.BigEndian.AppendUint64(b, incarnation)
	b = binary.BigEndian.AppendUint64(b, networkID)
	b = binary.BigEndian.AppendUint64(b, snapshot)
	b = binary.BigEndian.AppendUint32(b, factCount)
	b = binary.BigEndian.AppendUint32(b, pageCount)
	return append(b, digest[:]...)
}

func TestFactRuntimeUnknownPageAndDuplicateConflictReject(t *testing.T) {
	n := admissionNetwork(t, factRuntimeTestToken)
	peer := newFactTestPeer(t, n, 0x3001)
	networkID := n.networkContext.WireID()
	now := time.Now()
	issued, expires := factTestMillisWindow(now)
	first := factTestNodeRecord(networkID, peer.identity.PublicKey, topology.FactVersion{Incarnation: 4, Sequence: 1}, issued, expires)
	second := factTestAddressRecord(networkID, peer.nodeID, "10.60.0.11", topology.FactVersion{Incarnation: 4, Sequence: 2}, issued, expires)
	third := factTestAddressRecord(networkID, peer.nodeID, "10.60.0.12", topology.FactVersion{Incarnation: 4, Sequence: 3}, issued, expires)
	summary, pages := factTestSnapshot(t, networkID, 4, 1, 2, []topology.FactRecord{first, second, third})
	if len(pages) != 2 {
		t.Fatalf("fixture produced %d pages; want 2", len(pages))
	}
	waitFactRouteFresh(t, n)
	versionBefore := factTestSettledVersion(t, n)

	// A page for a snapshot this Link never described is answered with
	// NEED_SUMMARY: nothing is staged, nothing is rejected and nothing commits.
	peer.sendPage(t, pages[0])
	ack := peer.expectAck(t, topology.AckNeedSummary, 0)
	if ack.SenderIncarnation != 4 || ack.SnapshotVersion != 1 || ack.MissingPage != 0 {
		t.Fatalf("NEED_SUMMARY echo = incarnation %d version %d missing %d", ack.SenderIncarnation, ack.SnapshotVersion, ack.MissingPage)
	}
	if status := n.factStatus(); status.StagingLinks != 0 || status.Rejected != 0 || status.Committed != 0 {
		t.Fatalf("unknown page changed runtime state: %+v", status)
	}
	if n.facts.store.Version() != versionBefore {
		t.Fatal("unknown page advanced the FactStore version")
	}

	// A declared snapshot requests its first page, and the first staged page
	// makes the receiver ask for the still missing one.
	peer.sendSummary(t, summary)
	peer.expectAck(t, topology.AckNeedPage, 0)
	peer.sendPage(t, pages[0])
	ack = peer.expectAck(t, topology.AckNeedPage, 0)
	if ack.MissingPage != 1 {
		t.Fatalf("NEED_PAGE missing page = %d; want 1", ack.MissingPage)
	}

	// The same page number with different bytes cannot belong to the digest-bound
	// snapshot being staged: REJECT(digest), and the staged transfer is dropped.
	conflictRaw, err := topology.EncodeFactPage(topology.FactPage{
		ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: 4, NetworkID: networkID,
		SnapshotVersion: 1, PageNo: 0, PageCount: 2, Facts: []topology.FactRecord{second},
	})
	if err != nil {
		t.Fatalf("encode conflicting page: %v", err)
	}
	conflictPage, err := topology.DecodeFactPage(conflictRaw)
	if err != nil {
		t.Fatalf("decode conflicting page: %v", err)
	}
	if conflictPage.PageDigest == pages[0].PageDigest {
		t.Fatal("fixture built two identical page digests")
	}
	peer.sendPage(t, conflictPage)
	ack = peer.expectAck(t, topology.AckReject, 0)
	if ack.Reason != factAckReasonDigest {
		t.Fatalf("conflicting duplicate reason = %d; want %d (digest)", ack.Reason, factAckReasonDigest)
	}
	if status := n.factStatus(); status.StagingLinks != 0 || status.Rejected != 1 || status.Committed != 0 {
		t.Fatalf("rejected conflict left state behind: %+v", status)
	}

	// The dropped staging can never be completed by the remaining page, and no
	// record of the rejected transfer becomes visible.
	peer.sendPage(t, pages[1])
	peer.expectAck(t, topology.AckNeedSummary, 1)
	if n.facts.store.Version() != versionBefore {
		t.Fatal("a rejected transfer advanced the FactStore version")
	}
	for _, record := range []topology.FactRecord{first, second, third} {
		if factTestIsCurrent(t, n, record, now) {
			t.Fatalf("record %T version %+v of a rejected transfer became visible", record.Payload, record.Envelope.Version)
		}
	}
	visible, _, err := n.facts.store.Snapshot(now)
	if err != nil {
		t.Fatalf("FactStore Snapshot() error = %v", err)
	}
	for _, record := range []topology.FactRecord{first, second, third} {
		if got := factTestSnapshotContains(t, visible, record); got != 0 {
			t.Fatalf("visible copies of a rejected record = %d; want 0", got)
		}
	}
}

func TestFactRuntimeMalformedControlPayloadIsTerminal(t *testing.T) {
	validDigest := sha256.Sum256([]byte("over-limit-declaration"))
	for _, tt := range []struct {
		name    string
		typ     uint8
		payload func(networkID uint64) []byte
	}{
		{
			name: "summary-unsupported-version",
			typ:  6,
			payload: func(networkID uint64) []byte {
				return factTestRawSummary(1, 5, networkID, 1, 0, 0, [32]byte{})
			},
		},
		{
			name: "summary-over-limit-declaration",
			typ:  6,
			payload: func(networkID uint64) []byte {
				// 65 pages is one past the frozen bound: the container itself is
				// refused, so the Link is retired instead of inventing an ACK.
				return factTestRawSummary(topology.FactProtocolVersion, 5, networkID, 1, 65, 65, validDigest)
			},
		},
		{
			name: "page-truncated",
			typ:  7,
			payload: func(uint64) []byte {
				return make([]byte, topology.FactPageHeaderSize-1)
			},
		},
		{
			name: "ack-truncated",
			typ:  8,
			payload: func(uint64) []byte {
				return make([]byte, topology.FactAckSize-1)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n := admissionNetwork(t, factRuntimeTestToken)
			peer := newFactTestPeer(t, n, 0x4001)
			versionBefore := factTestSettledVersion(t, n)
			peer.send(t, tt.typ, tt.payload(n.networkContext.WireID()))

			// An authenticated peer that emits a broken protected control
			// container has a broken stream: the Link is retired, no error detail
			// is echoed back and no fake ACK is invented.
			peer.expectLinkRetired(t)
			if n.facts.store.Version() != versionBefore {
				t.Fatal("malformed control changed published facts")
			}
			if status := n.factStatus(); status.StagingLinks != 0 || status.Committed != 0 || status.Rejected != 0 {
				t.Fatalf("malformed control changed runtime state: %+v", status)
			}
		})
	}
}

func TestFactRuntimeWellFormedAckIsIgnoredWithoutClosingLink(t *testing.T) {
	n := admissionNetwork(t, factRuntimeTestToken)
	peer := newFactTestPeer(t, n, 0x4501)

	// This ACK does not correlate with any snapshot this Link offered (wrong
	// sender incarnation): it is counted and ignored, never treated as a Link
	// failure and never as a route. A matching ACK now drives the outbound sender.
	peer.sendAck(t, topology.FactAck{
		ProtocolVersion: topology.FactProtocolVersion, SenderIncarnation: 9,
		NetworkID: n.networkContext.WireID(), SnapshotVersion: 1,
		PageNo: 0, Status: topology.AckOK, MissingPage: 0,
	})
	waitAdmissionLinks(t, n, 1)
	probe := bytes.Repeat([]byte{0x7a}, 16)
	peer.send(t, 1, probe)
	message := peer.readControl(t)
	if message.Type != 2 || !bytes.Equal(message.Payload, probe) {
		t.Fatalf("link after an ignored ACK: control type %d, payload %x", message.Type, message.Payload)
	}
	status := n.factStatus()
	if status.IgnoredAcks != 1 || status.Committed != 0 || status.Rejected != 0 || status.StagingLinks != 0 {
		t.Fatalf("status after an ignored ACK = %+v", status)
	}
}

func TestFactRuntimeSnapshotRejectReasons(t *testing.T) {
	n := admissionNetwork(t, factRuntimeTestToken)
	peer := newFactTestPeer(t, n, 0x5001)
	networkID := n.networkContext.WireID()
	now := time.Now()
	issued, expires := factTestMillisWindow(now)
	versionBefore := factTestSettledVersion(t, n)

	// A well-formed summary for another network locator is answered explicitly,
	// never silently dropped and never staged.
	peer.sendSummary(t, factTestEmptySnapshot(t, networkID^1, 1, 1))
	ack := peer.expectAck(t, topology.AckReject, 0)
	if ack.Reason != factAckReasonSemantic {
		t.Fatalf("foreign-network summary reason = %d; want %d (semantic)", ack.Reason, factAckReasonSemantic)
	}

	// A record whose envelope timestamps already passed is still admissible: the receiver
	// cannot tell how long it spent in flight, because the timestamps carry the publisher's
	// clock and the two clocks are never compared. It is accepted and given its declared
	// lifetime from arrival. A peer never forwards an already-expired record in the first
	// place — the exporter filters on its own anchored expiry — so this path only sees
	// records that are genuinely current.
	stale := factTestNodeRecord(networkID, peer.identity.PublicKey, topology.FactVersion{Incarnation: 11, Sequence: 1},
		uint64(now.Add(-90*time.Second).UnixMilli()), uint64(now.Add(-50*time.Second).UnixMilli()))
	staleSummary, stalePages := factTestSnapshot(t, networkID, 11, 1, 0, []topology.FactRecord{stale})
	peer.sendSummary(t, staleSummary)
	peer.expectAck(t, topology.AckNeedPage, 0)
	peer.sendPage(t, stalePages[0])
	peer.expectAck(t, topology.AckComplete, 0)

	// A publisher whose clock runs ahead is not rejected either: its timestamps are not
	// compared against ours, so they carry no meaning here. Only the declared lifetime is
	// enforced, and it is valid on this record.
	ahead := factTestNodeRecord(networkID, peer.identity.PublicKey, topology.FactVersion{Incarnation: 12, Sequence: 1},
		uint64(now.Add(2*time.Minute).UnixMilli()), uint64(now.Add(150*time.Second).UnixMilli()))
	aheadSummary, aheadPages := factTestSnapshot(t, networkID, 12, 1, 0, []topology.FactRecord{ahead})
	peer.sendSummary(t, aheadSummary)
	peer.expectAck(t, topology.AckNeedPage, 0)
	peer.sendPage(t, aheadPages[0])
	peer.expectAck(t, topology.AckComplete, 0)

	// A snapshot whose declared record count does not match its pages fails whole
	// snapshot validation at the completing page: no partial commit, no page kept.
	mismatch := factTestNodeRecord(networkID, peer.identity.PublicKey, topology.FactVersion{Incarnation: 13, Sequence: 1}, issued, expires)
	mismatchAddress := factTestAddressRecord(networkID, peer.nodeID, "10.60.0.13", topology.FactVersion{Incarnation: 13, Sequence: 2}, issued, expires)
	mismatchSummary, mismatchPages := factTestSnapshot(t, networkID, 13, 1, 0, []topology.FactRecord{mismatch, mismatchAddress})
	mismatchSummary.FactCount = 5
	peer.sendSummary(t, mismatchSummary)
	peer.expectAck(t, topology.AckNeedPage, 0)
	peer.sendPage(t, mismatchPages[0])
	ack = peer.expectAck(t, topology.AckReject, 0)
	if ack.Reason != factAckReasonSemantic {
		t.Fatalf("mismatched count reason = %d; want %d (semantic)", ack.Reason, factAckReasonSemantic)
	}

	// Two snapshots were committed in full (a stale one and one from a peer whose clock
	// runs ahead — neither is refused for its timestamps any more) and two were rejected on
	// structural grounds.
	status := n.factStatus()
	if status.Committed != 2 || status.Rejected != 2 || status.StagingLinks != 0 || status.StagedBytes != 0 {
		t.Fatalf("status after the reject-reason sweep = %+v", status)
	}
	// Version advances for the two accepted snapshots and not for the rejected ones; the
	// rejected pair is what this assertion is about, so assert the exact count.
	if got := n.facts.store.Version() - versionBefore; got != 2 {
		t.Fatalf("version advanced by %d; want one per accepted snapshot", got)
	}
	for _, record := range []topology.FactRecord{mismatch, mismatchAddress} {
		if factTestIsCurrent(t, n, record, now) {
			t.Fatalf("rejected record %T version %+v became current", record.Payload, record.Envelope.Version)
		}
	}
}

func TestFactRuntimeControlPumpWithoutAuthenticatedLinkFailsClosed(t *testing.T) {
	n := admissionNetwork(t, factRuntimeTestToken)
	pump := &controlPump{network: n}
	now := time.Now()
	issued, expires := factTestMillisWindow(now)
	record := factTestNodeRecord(n.networkContext.WireID(), [32]byte{1, 2, 3}, topology.FactVersion{Incarnation: 1, Sequence: 1}, issued, expires)
	summary, pages := factTestSnapshot(t, n.networkContext.WireID(), 1, 1, 0, []topology.FactRecord{record})
	summaryPayload, err := topology.EncodeFactSummary(summary)
	if err != nil {
		t.Fatal(err)
	}
	pagePayload, err := topology.EncodeFactPage(pages[0])
	if err != nil {
		t.Fatal(err)
	}

	// A pump without an authenticated Link can never be the ingress identity of
	// a fact: both FACT consumers fail closed instead of staging or answering.
	if err := pump.consumeFactSummary(summaryPayload); !errors.Is(err, errFactControlMalformed) || !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("unauthenticated SUMMARY error = %v; want a malformed/permission failure", err)
	}
	if err := pump.consumeFactPage(pagePayload); !errors.Is(err, errFactControlMalformed) || !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("unauthenticated PAGE error = %v; want a malformed/permission failure", err)
	}
	if status := n.factStatus(); status.StagingLinks != 0 || status.Committed != 0 || status.Rejected != 0 {
		t.Fatalf("unauthenticated FACT consumer changed state: %+v", status)
	}
}

// TestLinkCostCarriesMeasuredRTT covers the join between the estimator and the fact that
// routes read. They were written separately, and without this the published cost could
// stay zero while the estimator worked perfectly.
func TestLinkCostCarriesMeasuredRTT(t *testing.T) {
	// No pump, or a pump with no protected IO, must be a zero cost rather than a panic:
	// a LINK fact is built for links whose pump has already retired.
	if got := linkCost(nil); got != (topology.LinkCost{}) {
		t.Fatalf("linkCost(nil) = %+v; want the zero cost", got)
	}

	n := admissionNetwork(t, factRuntimeTestToken)
	peer := newFactTestPeer(t, n, 0x7101)
	waitAdmissionLinks(t, n, 1)

	var pump *controlPump
	for _, candidate := range n.controlPumps {
		pump = candidate
		break
	}
	if pump == nil || pump.control == nil {
		t.Fatal("no control pump for the admitted Link")
	}

	if got := linkCost(pump); got.RTTMillis != 0 {
		t.Fatalf("cost before any probe = %+v; want an unmeasured zero", got)
	}

	probe := [16]byte{4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2, 4, 2}
	pump.control.NoteProbeSent(probe, time.Now().Add(-40*time.Millisecond))
	pump.control.NoteProbeAcknowledged(probe, time.Now())

	cost := linkCost(pump)
	if cost.RTTMillis < 30 || cost.RTTMillis > 60 {
		t.Fatalf("cost.RTTMillis = %d; want about 40", cost.RTTMillis)
	}
	if cost.JitterMicros == 0 {
		t.Fatal("cost.JitterMicros = 0; want the measured deviation (one sample means half)")
	}
	_ = peer
}
