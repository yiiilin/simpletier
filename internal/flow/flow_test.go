package flow

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/topology"
)

const testNetworkID uint64 = 0x2a

var (
	nodeA = topology.NodeID{0x0a}
	nodeB = topology.NodeID{0x0b}
	vipA  = netip.AddrFrom4([4]byte{100, 64, 0, 1})
	vipB  = netip.AddrFrom4([4]byte{100, 64, 0, 2})
	vipC  = netip.AddrFrom4([4]byte{100, 64, 0, 3})
	ctxID = [32]byte{0x11}
)

func patternedPayload(n int) []byte {
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	return payload
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock { return &testClock{now: time.Unix(1_700_000_000, 0)} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type testEndpoints map[netip.Addr]EndpointOwner

func (e testEndpoints) LookupEndpoint(_ context.Context, ip netip.Addr) (EndpointOwner, bool) {
	owner, ok := e[ip]
	return owner, ok
}

type testRoutes struct {
	mu     sync.Mutex
	routes []DatagramRoute
	err    error
	calls  int
}

func (r *testRoutes) ResolveDatagramRoute(_ context.Context, _ netip.Addr) (DatagramRoute, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := r.calls
	r.calls++
	if r.err != nil {
		return DatagramRoute{}, r.err
	}
	if len(r.routes) == 0 {
		return DatagramRoute{}, errors.New("testRoutes: no route configured")
	}
	if index >= len(r.routes) {
		index = len(r.routes) - 1
	}
	return r.routes[index], nil
}

func (r *testRoutes) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type captureSender struct {
	mu     sync.Mutex
	sent   []SendRequest
	fail   error
	failAt int
	calls  int
}

func (s *captureSender) SendFragment(ctx context.Context, request SendRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail != nil && (s.failAt == 0 || s.calls == s.failAt) {
		return s.fail
	}
	copied := request
	copied.Payload = append([]byte(nil), request.Payload...)
	s.sent = append(s.sent, copied)
	return nil
}

func (s *captureSender) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type collectingDelivery struct {
	mu  sync.Mutex
	got []Datagram
	err error
}

func (d *collectingDelivery) DeliverDatagram(_ context.Context, datagram Datagram) error {
	if d.err != nil {
		return d.err
	}
	copied := datagram
	copied.Payload = append([]byte(nil), datagram.Payload...)
	d.mu.Lock()
	d.got = append(d.got, copied)
	d.mu.Unlock()
	return nil
}

func (d *collectingDelivery) datagrams() []Datagram {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Datagram(nil), d.got...)
}

type failingBudget struct {
	released uint64
	reserves int
}

func (b *failingBudget) Reserve(uint64) error {
	b.reserves++
	return errors.New("shared budget exhausted")
}

func (b *failingBudget) Release(bytes uint64) { b.released += bytes }

func testEndpointsMap() testEndpoints {
	return testEndpoints{
		vipA: {Owner: nodeA, Version: topology.FactVersion{Incarnation: 1, Sequence: 1}},
		vipB: {Owner: nodeB, Version: topology.FactVersion{Incarnation: 1, Sequence: 2}},
	}
}

func testRouteA() DatagramRoute {
	return DatagramRoute{
		DestinationNode:    nodeB,
		AddressFactVersion: topology.FactVersion{Incarnation: 1, Sequence: 2},
		PathID:             7,
		PathGeneration:     3,
		Lane:               path.LanePacket,
	}
}

func testRouteB() DatagramRoute {
	return DatagramRoute{
		DestinationNode:    nodeA,
		AddressFactVersion: topology.FactVersion{Incarnation: 1, Sequence: 1},
		PathID:             9,
		PathGeneration:     1,
		Lane:               path.LanePacket,
	}
}

func newTestManager(t *testing.T, local topology.NodeID, endpoints EndpointDirectory, routes RouteResolver, sender Sender, delivery Delivery, now func() time.Time, budget BufferBudget) *Manager {
	t.Helper()
	manager, err := NewManager(Config{
		NetworkID: testNetworkID,
		ContextID: ctxID,
		LocalNode: local,
		Endpoints: endpoints,
		Routes:    routes,
		Sender:    sender,
		Delivery:  delivery,
		Budget:    budget,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

type pair struct {
	t         *testing.T
	a, b      *Manager
	senderA   *captureSender
	senderB   *captureSender
	deliveryA *collectingDelivery
	deliveryB Delivery
	routesA   *testRoutes
	routesB   *testRoutes
	endpoints testEndpoints
	clock     *testClock
}

func newPair(t *testing.T, deliveryA, deliveryB Delivery) *pair {
	t.Helper()
	clock := newTestClock()
	endpoints := testEndpointsMap()
	routesA := &testRoutes{routes: []DatagramRoute{testRouteA()}}
	routesB := &testRoutes{routes: []DatagramRoute{testRouteB()}}
	senderA := &captureSender{}
	senderB := &captureSender{}
	collectA, _ := deliveryA.(*collectingDelivery)
	if deliveryA == nil {
		collectA = &collectingDelivery{}
		deliveryA = collectA
	}
	p := &pair{
		t:         t,
		senderA:   senderA,
		senderB:   senderB,
		deliveryA: collectA,
		deliveryB: deliveryB,
		routesA:   routesA,
		routesB:   routesB,
		endpoints: endpoints,
		clock:     clock,
	}
	p.a = newTestManager(t, nodeA, endpoints, routesA, senderA, deliveryA, clock.Now, nil)
	p.b = newTestManager(t, nodeB, endpoints, routesB, senderB, deliveryB, clock.Now, nil)
	return p
}

func (p *pair) envToB() AuthenticatedEnvelope {
	return AuthenticatedEnvelope{NetworkID: testNetworkID, SrcNodeID: nodeA, DstNodeID: nodeB}
}

func (p *pair) envToA() AuthenticatedEnvelope {
	return AuthenticatedEnvelope{NetworkID: testNetworkID, SrcNodeID: nodeB, DstNodeID: nodeA}
}

func (p *pair) takeSentA() []SendRequest {
	p.senderA.mu.Lock()
	defer p.senderA.mu.Unlock()
	sent := append([]SendRequest(nil), p.senderA.sent...)
	p.senderA.sent = nil
	return sent
}

func (p *pair) takeSentB() []SendRequest {
	p.senderB.mu.Lock()
	defer p.senderB.mu.Unlock()
	sent := append([]SendRequest(nil), p.senderB.sent...)
	p.senderB.sent = nil
	return sent
}

func (p *pair) feedToA(requests []SendRequest, order ...int) error {
	for _, index := range order {
		if err := p.a.Receive(context.Background(), p.envToA(), requests[index].Payload); err != nil {
			return err
		}
	}
	return nil
}

// receivedByB returns the most recent datagram B delivered to its endpoint.
func (p *pair) receivedByB() Datagram {
	p.t.Helper()
	collect, ok := p.deliveryB.(*collectingDelivery)
	if !ok {
		p.t.Fatalf("receivedByB needs a collecting delivery")
	}
	got := collect.datagrams()
	if len(got) == 0 {
		p.t.Fatal("B delivered no datagram")
	}
	return got[len(got)-1]
}

// requestThenReceive sends one request from A, feeds it to B and returns the
// delivered datagram so a test can exercise Reply.
func (p *pair) requestThenReceive(payload []byte) Datagram {
	p.t.Helper()
	_, requests := p.sendA(payload, 53)
	order := []int{0}
	if len(requests) == 2 {
		order = []int{1, 0}
	}
	if err := p.feedToB(requests, order...); err != nil {
		p.t.Fatalf("feedToB: %v", err)
	}
	return p.receivedByB()
}

func (p *pair) sendOn(association *Association, payload []byte, destPort uint16) []SendRequest {
	p.t.Helper()
	datagram := OutboundDatagram{
		Source:      netip.AddrPortFrom(vipA, 40000),
		Destination: netip.AddrPortFrom(vipB, destPort),
		Payload:     payload,
	}
	if err := association.Fragment(context.Background(), datagram); err != nil {
		p.t.Fatalf("Fragment: %v", err)
	}
	return p.takeSentA()
}

func (p *pair) sendA(payload []byte, destPort uint16) (*Association, []SendRequest) {
	p.t.Helper()
	association, err := p.a.CreateAssociation()
	if err != nil {
		p.t.Fatalf("CreateAssociation: %v", err)
	}
	return association, p.sendOn(association, payload, destPort)
}

func (p *pair) feedToB(requests []SendRequest, order ...int) error {
	for _, index := range order {
		if err := p.b.Receive(context.Background(), p.envToB(), requests[index].Payload); err != nil {
			return err
		}
	}
	return nil
}

func (p *pair) deliverB(payload []byte, order ...int) []Datagram {
	p.t.Helper()
	_, requests := p.sendA(payload, 53)
	if err := p.feedToB(requests, order...); err != nil {
		p.t.Fatalf("feedToB: %v", err)
	}
	collect, ok := p.deliveryB.(*collectingDelivery)
	if !ok {
		p.t.Fatalf("deliverB needs a collecting delivery")
	}
	return collect.datagrams()
}

func TestCodecRoundTrip(t *testing.T) {
	fragment := Fragment{
		AssociationID:   AssocID{1, 2, 3},
		Flags:           FlagRequest,
		DatagramID:      7,
		FragmentIndex:   0,
		FragmentCount:   1,
		TotalPayloadLen: 3,
		Source:          netip.AddrPortFrom(vipA, 40000),
		Destination:     netip.AddrPortFrom(vipB, 53),
		Payload:         []byte("abc"),
	}
	raw, err := EncodeFragment(fragment)
	if err != nil {
		t.Fatalf("EncodeFragment: %v", err)
	}
	if len(raw) != FixedMetadataLen+3 {
		t.Fatalf("encoded length %d, want %d", len(raw), FixedMetadataLen+3)
	}
	if raw[16] != 0x00 {
		t.Fatalf("flags byte %#x, want REQUEST 0x00", raw[16])
	}
	if got := binary.BigEndian.Uint64(raw[17:25]); got != 7 {
		t.Fatalf("datagram id %d, want 7 big-endian", got)
	}
	if got := binary.BigEndian.Uint16(raw[27:29]); got != 3 {
		t.Fatalf("total_payload_len %d, want 3 big-endian", got)
	}
	decoded, err := DecodeFragment(raw)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	if decoded.AssociationID != fragment.AssociationID || decoded.Flags != fragment.Flags ||
		decoded.DatagramID != fragment.DatagramID || decoded.FragmentIndex != fragment.FragmentIndex ||
		decoded.FragmentCount != fragment.FragmentCount || decoded.TotalPayloadLen != fragment.TotalPayloadLen ||
		decoded.Source != fragment.Source || decoded.Destination != fragment.Destination ||
		!bytes.Equal(decoded.Payload, fragment.Payload) {
		t.Fatalf("round trip mismatch: %+v", decoded)
	}
}

func TestCodecRejectsStrictSchema(t *testing.T) {
	base := func() Fragment {
		return Fragment{
			AssociationID:   AssocID{9},
			Flags:           FlagReply,
			DatagramID:      1,
			FragmentIndex:   0,
			FragmentCount:   1,
			TotalPayloadLen: 3,
			Source:          netip.AddrPortFrom(vipA, 40000),
			Destination:     netip.AddrPortFrom(vipB, 53),
			Payload:         []byte("abc"),
		}
	}
	cases := []struct {
		name   string
		mutate func(*Fragment)
	}{
		{"zero association id", func(f *Fragment) { f.AssociationID = AssocID{} }},
		{"unknown flags", func(f *Fragment) { f.Flags = 0x02 }},
		{"zero datagram id", func(f *Fragment) { f.DatagramID = 0 }},
		{"zero fragment count", func(f *Fragment) { f.FragmentCount = 0 }},
		{"three fragments", func(f *Fragment) { f.FragmentCount = 3 }},
		{"index not below count", func(f *Fragment) { f.FragmentIndex = 1 }},
		{"total above udp limit", func(f *Fragment) { f.TotalPayloadLen = 65508 }},
		{"unspecified source", func(f *Fragment) { f.Source = netip.AddrPortFrom(netip.IPv4Unspecified(), 1) }},
		{"multicast destination", func(f *Fragment) { f.Destination = netip.AddrPortFrom(netip.MustParseAddr("239.1.1.1"), 53) }},
		{"source port zero", func(f *Fragment) { f.Source = netip.AddrPortFrom(vipA, 0) }},
		{"destination port zero", func(f *Fragment) { f.Destination = netip.AddrPortFrom(vipB, 0) }},
		{"length disagrees with total", func(f *Fragment) { f.TotalPayloadLen = 2 }},
		{"single fragment claims two-fragment total", func(f *Fragment) {
			f.TotalPayloadLen = 65346
			f.Payload = make([]byte, 65346)
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fragment := base()
			testCase.mutate(&fragment)
			if _, err := EncodeFragment(fragment); !errors.Is(err, ErrFrameMalformed) {
				t.Fatalf("EncodeFragment error = %v, want ErrFrameMalformed", err)
			}
		})
	}
	raw, err := EncodeFragment(base())
	if err != nil {
		t.Fatalf("EncodeFragment: %v", err)
	}
	if _, err := DecodeFragment(raw[:FixedMetadataLen-1]); !errors.Is(err, ErrFrameMalformed) {
		t.Fatalf("truncated decode error = %v, want ErrFrameMalformed", err)
	}
}

func TestFragmentCountAndSlices(t *testing.T) {
	cases := []struct {
		total int
		want  uint8
		fail  bool
	}{
		{0, 1, false}, {1, 1, false}, {65345, 1, false},
		{65346, 2, false}, {65507, 2, false},
		{65508, 0, true}, {-1, 0, true},
	}
	for _, testCase := range cases {
		count, err := FragmentCount(testCase.total)
		if testCase.fail {
			if !errors.Is(err, ErrDatagramTooLarge) {
				t.Fatalf("FragmentCount(%d) error = %v, want ErrDatagramTooLarge", testCase.total, err)
			}
			continue
		}
		if err != nil || count != testCase.want {
			t.Fatalf("FragmentCount(%d) = (%d, %v), want (%d, nil)", testCase.total, count, err, testCase.want)
		}
	}
	if offset, length := fragmentSlice(65507, 0); offset != 0 || length != MaxFragmentPayload {
		t.Fatalf("first slice = (%d,%d)", offset, length)
	}
	if offset, length := fragmentSlice(65507, 1); offset != MaxFragmentPayload || length != 65507-MaxFragmentPayload {
		t.Fatalf("second slice = (%d,%d)", offset, length)
	}
}

func TestMaximumDatagramTwoFragmentsReordered(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	payload := patternedPayload(MaxDatagramPayload)
	association, requests := p.sendA(payload, 53)

	if len(requests) != 2 {
		t.Fatalf("sent %d fragments, want 2", len(requests))
	}
	if requests[0].FragmentIndex != 0 || requests[1].FragmentIndex != 1 {
		t.Fatalf("fragment indices %d/%d, want 0/1", requests[0].FragmentIndex, requests[1].FragmentIndex)
	}
	if len(requests[0].Payload) != FixedMetadataLen+MaxFragmentPayload {
		t.Fatalf("first fragment payload %d, want %d", len(requests[0].Payload), FixedMetadataLen+MaxFragmentPayload)
	}
	if len(requests[1].Payload) != FixedMetadataLen+(MaxDatagramPayload-MaxFragmentPayload) {
		t.Fatalf("second fragment payload %d", len(requests[1].Payload))
	}
	for _, request := range requests {
		if request.DatagramID != 1 || request.PathID != 7 || request.PathGeneration != 3 {
			t.Fatalf("fragment lost the pinned route/ID: %+v", request)
		}
		if request.DstNodeID != nodeB || request.SrcNodeID != nodeA || request.AssociationID != association.ID() {
			t.Fatalf("fragment identity mismatch: %+v", request)
		}
	}
	// Deliberately reordered: fragment 1 before fragment 0.
	if err := p.feedToB(requests, 1, 0); err != nil {
		t.Fatalf("feedToB: %v", err)
	}
	got := delivery.datagrams()
	if len(got) != 1 {
		t.Fatalf("delivered %d datagrams, want 1", len(got))
	}
	if !bytes.Equal(got[0].Payload, payload) {
		t.Fatalf("reassembled payload differs from the original %d bytes", len(payload))
	}
	if got[0].Destination.Port() != 53 || got[0].Source != netip.AddrPortFrom(vipA, 40000) {
		t.Fatalf("delivery lost endpoint metadata: %+v", got[0])
	}
	if got[0].DatagramID != 1 || got[0].AssociationID != association.ID() {
		t.Fatalf("delivery identity mismatch: %+v", got[0])
	}
	stats := p.b.Stats()
	if stats.DeliveredDatagrams != 1 || stats.DeliveredBytes != MaxDatagramPayload {
		t.Fatalf("receiver stats %+v", stats)
	}
	if stats.BytesHeld != 0 {
		t.Fatalf("reassembly reservation leaked: %d bytes held", stats.BytesHeld)
	}
	if sender := p.a.Stats(); sender.SentDatagrams != 1 || sender.SentFragments != 2 {
		t.Fatalf("sender stats %+v", sender)
	}
}

func TestEmptyDatagramIsLegalSingleFragment(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	_, requests := p.sendA([]byte{}, 53)
	if len(requests) != 1 || requests[0].FragmentCount != 1 || requests[0].TotalPayloadLen != 0 {
		t.Fatalf("empty datagram framed as %+v", requests)
	}
	if len(requests[0].Payload) != FixedMetadataLen {
		t.Fatalf("empty datagram payload %d, want %d", len(requests[0].Payload), FixedMetadataLen)
	}
	if got := p.deliverB([]byte{}, 0); len(got) != 1 || len(got[0].Payload) != 0 {
		t.Fatalf("empty datagram delivery = %+v", got)
	}
}

func TestDuplicateFragmentsAreIdempotent(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	_, requests := p.sendA(patternedPayload(MaxDatagramPayload), 53)
	if err := p.feedToB(requests, 0, 0, 1, 1); err != nil {
		t.Fatalf("feedToB: %v", err)
	}
	if got := delivery.datagrams(); len(got) != 1 {
		t.Fatalf("duplicates produced %d deliveries, want 1", len(got))
	}
	if drops := p.b.Stats().Drops; drops[DropDuplicate] != 2 {
		t.Fatalf("duplicate drops = %d, want 2", drops[DropDuplicate])
	}
	// Replay of an already consumed datagram is dropped without redelivery.
	if err := p.feedToB(requests, 0, 1); err != nil {
		t.Fatalf("replay feedToB: %v", err)
	}
	if got := delivery.datagrams(); len(got) != 1 {
		t.Fatalf("replay produced %d deliveries, want 1", len(got))
	}
}

func TestConflictingFragmentBytesTerminalDrop(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	_, requests := p.sendA(patternedPayload(MaxDatagramPayload), 53)

	if err := p.feedToB(requests, 0); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	conflicting := append([]byte(nil), requests[0].Payload...)
	conflicting[FixedMetadataLen] ^= 0xff
	if err := p.b.Receive(context.Background(), p.envToB(), conflicting); !errors.Is(err, ErrFrameMalformed) {
		t.Fatalf("conflicting duplicate error = %v, want ErrFrameMalformed", err)
	}
	if err := p.feedToB(requests, 1); err != nil {
		t.Fatalf("late second fragment: %v", err)
	}
	if got := delivery.datagrams(); len(got) != 0 {
		t.Fatalf("conflicting assembly delivered %d datagrams", len(got))
	}
	stats := p.b.Stats()
	if stats.Drops[DropConflict] != 1 {
		t.Fatalf("conflict drops = %d, want 1", stats.Drops[DropConflict])
	}
	if stats.BytesHeld != 0 {
		t.Fatalf("conflict leaked %d reserved bytes", stats.BytesHeld)
	}
}

func TestConflictingMetadataTerminalDrop(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	_, requests := p.sendA(patternedPayload(65346), 53)

	if err := p.feedToB(requests, 0); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	// Same index and bytes, but total_payload_len now claims a different
	// logical datagram length: metadata conflict.
	decoded, err := DecodeFragment(requests[0].Payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	decoded.TotalPayloadLen = 65347
	conflicting, err := EncodeFragment(decoded)
	if err != nil {
		t.Fatalf("encode conflicting: %v", err)
	}
	if err := p.b.Receive(context.Background(), p.envToB(), conflicting); !errors.Is(err, ErrFrameMalformed) {
		t.Fatalf("metadata conflict error = %v, want ErrFrameMalformed", err)
	}
	if got := delivery.datagrams(); len(got) != 0 {
		t.Fatalf("metadata conflict delivered %d datagrams", len(got))
	}
	if drops := p.b.Stats().Drops; drops[DropConflict] != 1 {
		t.Fatalf("conflict drops = %d, want 1", drops[DropConflict])
	}
}

func TestMissingFragmentTimesOutWithoutExtension(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	_, requests := p.sendA(patternedPayload(MaxDatagramPayload), 53)

	if err := p.feedToB(requests, 0); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	if held := p.b.Stats().BytesHeld; held != MaxDatagramPayload {
		t.Fatalf("reserved %d bytes, want %d", held, MaxDatagramPayload)
	}
	// A matching duplicate must not extend the 120-second TTL from the first
	// fragment.
	p.clock.Advance(60 * time.Second)
	if err := p.feedToB(requests, 0); err != nil {
		t.Fatalf("duplicate first fragment: %v", err)
	}
	p.clock.Advance(61 * time.Second)
	p.b.Sweep()
	stats := p.b.Stats()
	if stats.Drops[DropTimeout] != 1 {
		t.Fatalf("timeout drops = %d, want 1", stats.Drops[DropTimeout])
	}
	if stats.BytesHeld != 0 {
		t.Fatalf("timeout leaked %d reserved bytes", stats.BytesHeld)
	}
	// The assembled datagram's TTL and the idle target association's TTL both
	// elapsed, so the association is tombstoned and the late fragment is refused
	// as an unknown association rather than reopening the closed window.
	if stats.Targets != 0 || stats.TargetTombstones != 1 {
		t.Fatalf("target cleanup stats %+v", stats)
	}
	if err := p.feedToB(requests, 1); !errors.Is(err, ErrUnknownAssociation) {
		t.Fatalf("late fragment error = %v, want ErrUnknownAssociation", err)
	}
	if got := delivery.datagrams(); len(got) != 0 {
		t.Fatalf("timed-out datagram delivered %d datagrams", len(got))
	}
}

func TestIdleTargetAssociationRefusedWithoutSweep(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	association, requests := p.sendA(patternedPayload(4), 53)
	if err := p.feedToB(requests, 0); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	if got := delivery.datagrams(); len(got) != 1 {
		t.Fatalf("first delivery = %d, want 1", len(got))
	}
	if stats := p.b.Stats(); stats.Targets != 1 {
		t.Fatalf("targets = %d, want 1", stats.Targets)
	}
	// No Sweep: an idle target association is expired by Receive itself.
	p.clock.Advance(AssociationIdleTTL)
	later := p.sendOn(association, patternedPayload(4), 53)
	if err := p.feedToB(later, 0); !errors.Is(err, ErrUnknownAssociation) {
		t.Fatalf("idle target fragment error = %v, want ErrUnknownAssociation", err)
	}
	stats := p.b.Stats()
	if stats.Targets != 0 || stats.TargetTombstones != 1 {
		t.Fatalf("idle target cleanup stats %+v", stats)
	}
	if stats.BytesHeld != 0 || stats.Assemblies != 0 {
		t.Fatalf("idle target leaked buffers: %+v", stats)
	}
	if got := delivery.datagrams(); len(got) != 1 {
		t.Fatalf("idle target delivered again: %d", len(got))
	}
	// The closed-window tombstone also refuses stale replay of the old ID.
	if err := p.feedToB(requests, 0); !errors.Is(err, ErrUnknownAssociation) {
		t.Fatalf("stale replay error = %v, want ErrUnknownAssociation", err)
	}
}

func TestHigherDatagramIDSupersedesIncomplete(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	firstPayload := patternedPayload(MaxDatagramPayload)
	for i := range firstPayload {
		firstPayload[i] = 0xa1
	}
	secondPayload := patternedPayload(MaxDatagramPayload)
	for i := range secondPayload {
		secondPayload[i] = 0xb2
	}
	association, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	first := p.sendOn(association, firstPayload, 53)
	second := p.sendOn(association, secondPayload, 53)
	if first[0].DatagramID != 1 || second[0].DatagramID != 2 {
		t.Fatalf("datagram IDs %d/%d, want 1/2", first[0].DatagramID, second[0].DatagramID)
	}

	if err := p.feedToB(first, 0); err != nil {
		t.Fatalf("first datagram fragment 0: %v", err)
	}
	if err := p.feedToB(second, 0, 1); err != nil {
		t.Fatalf("second datagram: %v", err)
	}
	got := delivery.datagrams()
	if len(got) != 1 || !bytes.Equal(got[0].Payload, secondPayload) {
		t.Fatalf("supersede delivery = %d datagrams, id %v", len(got), datagramIDs(got))
	}
	stats := p.b.Stats()
	if stats.Drops[DropSuperseded] != 1 {
		t.Fatalf("superseded drops = %d, want 1", stats.Drops[DropSuperseded])
	}
	if stats.BytesHeld != 0 {
		t.Fatalf("supersede leaked %d reserved bytes", stats.BytesHeld)
	}
	// The superseded datagram can never complete.
	if err := p.feedToB(first, 1); err != nil {
		t.Fatalf("late superseded fragment: %v", err)
	}
	if got := delivery.datagrams(); len(got) != 1 {
		t.Fatalf("superseded datagram delivered after the fact")
	}
}

func TestOlderDatagramFragmentIsSuperseded(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	association, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	first := p.sendOn(association, patternedPayload(MaxDatagramPayload), 53)
	second := p.sendOn(association, patternedPayload(MaxDatagramPayload), 53)

	if err := p.feedToB(second, 0); err != nil {
		t.Fatalf("newer fragment 0: %v", err)
	}
	if err := p.feedToB(first, 0); err != nil {
		t.Fatalf("older fragment 0: %v", err)
	}
	if err := p.feedToB(second, 1); err != nil {
		t.Fatalf("newer fragment 1: %v", err)
	}
	got := delivery.datagrams()
	if len(got) != 1 || got[0].DatagramID != 2 {
		t.Fatalf("older supersede delivery = %v", datagramIDs(got))
	}
	if drops := p.b.Stats().Drops; drops[DropSuperseded] != 1 {
		t.Fatalf("superseded drops = %d, want 1", drops[DropSuperseded])
	}
}

func TestOwnershipRejectsUnconfiguredTargetAndSpoof(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	association, requests := p.sendA(patternedPayload(5), 53)
	_ = association

	// Destination VIP is not owned by anyone: no endpoint is injected.
	fragment, err := DecodeFragment(requests[0].Payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	fragment.Destination = netip.AddrPortFrom(vipC, 53)
	unowned, err := EncodeFragment(fragment)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := p.b.Receive(context.Background(), p.envToB(), unowned); !errors.Is(err, ErrOwnership) {
		t.Fatalf("unconfigured target error = %v, want ErrOwnership", err)
	}

	// Source VIP is owned by nodeB but the envelope claims nodeA.
	fragment.Destination = netip.AddrPortFrom(vipB, 53)
	fragment.Source = netip.AddrPortFrom(vipB, 40000)
	spoofed, err := EncodeFragment(fragment)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := p.b.Receive(context.Background(), p.envToB(), spoofed); !errors.Is(err, ErrOwnership) {
		t.Fatalf("source spoof error = %v, want ErrOwnership", err)
	}
	stats := p.b.Stats()
	if stats.Drops[DropOwnership] != 2 {
		t.Fatalf("ownership drops = %d, want 2", stats.Drops[DropOwnership])
	}
	if stats.Targets != 0 || len(delivery.datagrams()) != 0 {
		t.Fatalf("rejected fragments created state: %+v", stats)
	}
}

func TestReplyForUnknownAssociationIsRejected(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	fragment := Fragment{
		AssociationID:   AssocID{0x44},
		Flags:           FlagReply,
		DatagramID:      1,
		FragmentIndex:   0,
		FragmentCount:   1,
		TotalPayloadLen: 4,
		Source:          netip.AddrPortFrom(vipB, 53),
		Destination:     netip.AddrPortFrom(vipA, 40000),
		Payload:         []byte("pong"),
	}
	raw, err := EncodeFragment(fragment)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := p.a.Receive(context.Background(), p.envToA(), raw); !errors.Is(err, ErrUnknownAssociation) {
		t.Fatalf("unknown reply error = %v, want ErrUnknownAssociation", err)
	}
	if drops := p.a.Stats().Drops; drops[DropUnknownAssociation] != 1 {
		t.Fatalf("unknown association drops = %d, want 1", drops[DropUnknownAssociation])
	}
}

func TestDirectionMustMatchAssociationRole(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	association, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	fragment := Fragment{
		AssociationID:   association.ID(),
		Flags:           FlagRequest, // an origin association only accepts REPLY
		DatagramID:      1,
		FragmentIndex:   0,
		FragmentCount:   1,
		TotalPayloadLen: 4,
		Source:          netip.AddrPortFrom(vipB, 53),
		Destination:     netip.AddrPortFrom(vipA, 40000),
		Payload:         []byte("ping"),
	}
	raw, err := EncodeFragment(fragment)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := association.Receive(context.Background(), p.envToA(), raw); !errors.Is(err, ErrOwnership) {
		t.Fatalf("direction mismatch error = %v, want ErrOwnership", err)
	}
}

func TestResourceLimitRejectsFragment(t *testing.T) {
	endpoints := testEndpointsMap()
	sender := &captureSender{}
	budget := &failingBudget{}
	manager := newTestManager(t, nodeB, endpoints, &testRoutes{routes: []DatagramRoute{testRouteB()}}, sender, &collectingDelivery{}, time.Now, budget)

	fragment := Fragment{
		AssociationID:   AssocID{0x55},
		Flags:           FlagRequest,
		DatagramID:      1,
		FragmentIndex:   0,
		FragmentCount:   2,
		TotalPayloadLen: 65507,
		Source:          netip.AddrPortFrom(vipA, 40000),
		Destination:     netip.AddrPortFrom(vipB, 53),
		Payload:         make([]byte, MaxFragmentPayload),
	}
	raw, err := EncodeFragment(fragment)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	envelope := AuthenticatedEnvelope{NetworkID: testNetworkID, SrcNodeID: nodeA, DstNodeID: nodeB}
	if err := manager.Receive(context.Background(), envelope, raw); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("resource error = %v, want ErrResourceLimit", err)
	}
	stats := manager.Stats()
	if stats.Drops[DropResource] != 1 || stats.BytesHeld != 0 {
		t.Fatalf("resource stats %+v", stats)
	}
	if budget.reserves != 1 {
		t.Fatalf("budget reserves = %d, want 1", budget.reserves)
	}
}

func TestSendPathOwnershipAndRoutePin(t *testing.T) {
	endpoints := testEndpointsMap()
	clock := newTestClock()
	sender := &captureSender{}
	datagram := OutboundDatagram{
		Source:      netip.AddrPortFrom(vipA, 40000),
		Destination: netip.AddrPortFrom(vipB, 53),
		Payload:     patternedPayload(5),
	}

	// Source not owned locally.
	manager := newTestManager(t, nodeA, endpoints, &testRoutes{routes: []DatagramRoute{testRouteA()}}, sender, &collectingDelivery{}, clock.Now, nil)
	association, err := manager.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	foreign := datagram
	foreign.Source = netip.AddrPortFrom(vipC, 40000)
	if err := association.Fragment(context.Background(), foreign); !errors.Is(err, ErrOwnership) {
		t.Fatalf("source ownership error = %v, want ErrOwnership", err)
	}

	// Route changes between pin and pre-egress recheck: no fragment is sent and
	// the datagram is not re-routed.
	changing := &testRoutes{routes: []DatagramRoute{testRouteA(), {DestinationNode: nodeB, PathID: 8, PathGeneration: 4, Lane: path.LanePacket}}}
	manager2 := newTestManager(t, nodeA, endpoints, changing, sender, &collectingDelivery{}, clock.Now, nil)
	association2, err := manager2.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	if err := association2.Fragment(context.Background(), datagram); !errors.Is(err, ErrRouteChanged) {
		t.Fatalf("route change error = %v, want ErrRouteChanged", err)
	}
	if sender.callCount() != 0 {
		t.Fatalf("route change still dispatched %d fragments", sender.callCount())
	}

	// A resolver defect that selects the wrong lane is rejected at pin time.
	wrongLane := &testRoutes{routes: []DatagramRoute{{DestinationNode: nodeB, PathID: 7, PathGeneration: 3, Lane: path.LaneStream}}}
	manager3 := newTestManager(t, nodeA, endpoints, wrongLane, sender, &collectingDelivery{}, clock.Now, nil)
	association3, err := manager3.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	if err := association3.Fragment(context.Background(), datagram); !errors.Is(err, ErrRouteChanged) {
		t.Fatalf("wrong lane error = %v, want ErrRouteChanged", err)
	}

	// Sender failure is not retried.
	failing := &captureSender{fail: errors.New("egress down")}
	manager4 := newTestManager(t, nodeA, endpoints, &testRoutes{routes: []DatagramRoute{testRouteA()}}, failing, &collectingDelivery{}, clock.Now, nil)
	association4, err := manager4.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	if err := association4.Fragment(context.Background(), OutboundDatagram{Source: datagram.Source, Destination: datagram.Destination, Payload: patternedPayload(MaxDatagramPayload)}); err == nil {
		t.Fatal("sender failure was swallowed")
	}
	if failing.callCount() != 1 {
		t.Fatalf("sender calls = %d, want exactly 1 (no retry)", failing.callCount())
	}
}

// TestSendSameOwnerVersionRenewalIsNotARouteChange pins the recheck contract for
// a same-owner ADDRESS fact renewal: the only difference between the pinned
// route and the pre-egress recheck is AddressFactVersion (Sequence 2 -> 3),
// while DestinationNode, PathID, PathGeneration and Lane are identical.
//
// An ADDRESS fact's key binds the owner NodeID and the exact /32, so a higher
// version of the same key is provably the same owner and the same address, and
// this node's own fact plane spends a new version every refresh interval for
// every peer. A same-owner renewal must therefore be delivered rather than
// dropped as ErrRouteChanged; comparing the exact version would drop a steady
// datagram on a routine renewal that changed no mapping.
func TestSendSameOwnerVersionRenewalIsNotARouteChange(t *testing.T) {
	// Call 1 pins testRouteA() (AddressFactVersion Sequence 2); call 2 is the
	// pre-egress recheck with Sequence 3 and every routing field identical.
	routes := &testRoutes{routes: []DatagramRoute{
		testRouteA(),
		{DestinationNode: nodeB, AddressFactVersion: topology.FactVersion{Incarnation: 1, Sequence: 3}, PathID: 7, PathGeneration: 3, Lane: path.LanePacket},
	}}
	endpoints := testEndpointsMap()
	clock := newTestClock()
	sender := &captureSender{}
	manager := newTestManager(t, nodeA, endpoints, routes, sender, &collectingDelivery{}, clock.Now, nil)
	association, err := manager.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}

	datagram := OutboundDatagram{
		Source:      netip.AddrPortFrom(vipA, 40000),
		Destination: netip.AddrPortFrom(vipB, 53),
		Payload:     patternedPayload(5),
	}
	if err := association.Fragment(context.Background(), datagram); err != nil {
		t.Fatalf("same-owner version renewal error = %v, want nil (renewal is not a route change)", err)
	}
	if got := sender.callCount(); got != 1 {
		t.Fatalf("sender calls = %d, want 1 (the single fragment must egress)", got)
	}
	// The pin plus the pre-egress recheck must both have run, otherwise this
	// test would pass vacuously without exercising the comparison at all.
	if got := routes.callCount(); got != 2 {
		t.Fatalf("resolver calls = %d, want 2 (pin then pre-egress recheck)", got)
	}
	if got := manager.Stats().Drops[DropRoute]; got != 0 {
		t.Fatalf("DropRoute = %d, want 0 (a same-owner renewal must not be counted as a route drop)", got)
	}
}

func TestDatagramIDIsMonotonicAndNeverWraps(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	association, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	ids := make([]uint64, 0, 3)
	for i := 0; i < 3; i++ {
		datagram := OutboundDatagram{
			Source:      netip.AddrPortFrom(vipA, 40000),
			Destination: netip.AddrPortFrom(vipB, 53),
			Payload:     patternedPayload(8),
		}
		if err := association.Fragment(context.Background(), datagram); err != nil {
			t.Fatalf("Fragment %d: %v", i, err)
		}
		for _, request := range p.takeSentA() {
			ids = append(ids, request.DatagramID)
		}
	}
	want := []uint64{1, 2, 3}
	if fmt.Sprint(ids) != fmt.Sprint(want) {
		t.Fatalf("DatagramIDs = %v, want %v (same ID for both fragments of one datagram)", ids, want)
	}

	association.nextID = math.MaxUint64
	if err := association.Fragment(context.Background(), OutboundDatagram{
		Source:      netip.AddrPortFrom(vipA, 40000),
		Destination: netip.AddrPortFrom(vipB, 53),
		Payload:     patternedPayload(1),
	}); !errors.Is(err, ErrDatagramIDExhausted) {
		t.Fatalf("exhaustion error = %v, want ErrDatagramIDExhausted", err)
	}
	if err := association.Fragment(context.Background(), OutboundDatagram{
		Source:      netip.AddrPortFrom(vipA, 40000),
		Destination: netip.AddrPortFrom(vipB, 53),
		Payload:     patternedPayload(1),
	}); !errors.Is(err, ErrAssociationClosed) {
		t.Fatalf("post-exhaustion error = %v, want ErrAssociationClosed", err)
	}
}

func TestDatagramTooLargeRejectedBeforeFragmentation(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	association, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	datagram := OutboundDatagram{
		Source:      netip.AddrPortFrom(vipA, 40000),
		Destination: netip.AddrPortFrom(vipB, 53),
		Payload:     make([]byte, MaxDatagramPayload+1),
	}
	if err := association.Fragment(context.Background(), datagram); !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("oversize error = %v, want ErrDatagramTooLarge", err)
	}
	if p.senderA.callCount() != 0 || p.routesA.callCount() != 0 {
		t.Fatalf("oversize datagram reached route/dispatch: sender=%d routes=%d", p.senderA.callCount(), p.routesA.callCount())
	}
	if drops := p.a.Stats().Drops; drops[DropTooLarge] != 1 {
		t.Fatalf("too-large drops = %d, want 1", drops[DropTooLarge])
	}
}

func TestSchemaDropConsumesKnownDatagram(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	_, requests := p.sendA(patternedPayload(MaxDatagramPayload), 53)
	if err := p.feedToB(requests, 0); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	if held := p.b.Stats().BytesHeld; held != MaxDatagramPayload {
		t.Fatalf("reserved %d bytes", held)
	}
	// Truncated frame: the header identity is readable, the schema is not.
	if err := p.b.Receive(context.Background(), p.envToB(), requests[0].Payload[:25]); !errors.Is(err, ErrFrameMalformed) {
		t.Fatalf("schema error = %v, want ErrFrameMalformed", err)
	}
	stats := p.b.Stats()
	if stats.Drops[DropSchema] != 1 {
		t.Fatalf("schema drops = %d, want 1", stats.Drops[DropSchema])
	}
	if stats.BytesHeld != 0 {
		t.Fatalf("schema drop leaked %d reserved bytes", stats.BytesHeld)
	}
	if err := p.feedToB(requests, 1); err != nil {
		t.Fatalf("second fragment: %v", err)
	}
	if got := delivery.datagrams(); len(got) != 0 {
		t.Fatalf("consumed datagram was delivered")
	}
}

func TestAssociationCapAndClosedLedger(t *testing.T) {
	endpoints := testEndpointsMap()
	sender := &captureSender{}
	manager := newTestManager(t, nodeA, endpoints, &testRoutes{routes: []DatagramRoute{testRouteA()}}, sender, &collectingDelivery{}, time.Now, nil)
	first, err := manager.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	for i := 1; i < MaxUDPAssociations; i++ {
		if _, err := manager.CreateAssociation(); err != nil {
			t.Fatalf("association %d: %v", i, err)
		}
	}
	if _, err := manager.CreateAssociation(); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("cap error = %v, want ErrResourceLimit", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := manager.CreateAssociation(); err != nil {
		t.Fatalf("CreateAssociation after Close: %v", err)
	}
}

type seqRand struct {
	mu  sync.Mutex
	ids []AssocID
	pos int
}

func (r *seqRand) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(p) != 16 {
		return 0, fmt.Errorf("seqRand: unexpected read of %d bytes", len(p))
	}
	if r.pos >= len(r.ids) {
		return 0, io.EOF
	}
	id := r.ids[r.pos]
	r.pos++
	copy(p, id[:])
	return 16, nil
}

func TestAssociationIDNeverReusesRecentlyClosedID(t *testing.T) {
	endpoints := testEndpointsMap()
	first := AssocID{0x01}
	second := AssocID{0x02}
	manager, err := NewManager(Config{
		NetworkID: testNetworkID,
		ContextID: ctxID,
		LocalNode: nodeA,
		Endpoints: endpoints,
		Routes:    &testRoutes{routes: []DatagramRoute{testRouteA()}},
		Sender:    &captureSender{},
		Delivery:  &collectingDelivery{},
		Rand:      &seqRand{ids: []AssocID{first, first, first, second}},
		Now:       newTestClock().Now,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer manager.Close()

	association, err := manager.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	if association.ID() != first {
		t.Fatalf("first association id = %s, want %s", association.ID(), first)
	}
	if err := association.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	replacement, err := manager.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	if replacement.ID() != second {
		t.Fatalf("replacement reused a recently-closed id: %s", replacement.ID())
	}
}

func TestZeroCSPRNGAssociationIDIsRejected(t *testing.T) {
	manager, err := NewManager(Config{
		NetworkID: testNetworkID,
		ContextID: ctxID,
		LocalNode: nodeA,
		Endpoints: testEndpointsMap(),
		Routes:    &testRoutes{routes: []DatagramRoute{testRouteA()}},
		Sender:    &captureSender{},
		Delivery:  &collectingDelivery{},
		Rand:      &seqRand{ids: make([]AssocID, assocIDAttempts)},
		Now:       time.Now,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer manager.Close()
	if _, err := manager.CreateAssociation(); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("zero CSPRNG error = %v, want ErrResourceLimit", err)
	}
}

func TestManagerAndAssociationClose(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	association, requests := p.sendA(patternedPayload(4), 53)

	if err := p.a.Close(); err != nil {
		t.Fatalf("manager Close: %v", err)
	}
	if err := p.a.Close(); err != nil {
		t.Fatalf("second manager Close: %v", err)
	}
	datagram := OutboundDatagram{
		Source:      netip.AddrPortFrom(vipA, 40000),
		Destination: netip.AddrPortFrom(vipB, 53),
		Payload:     patternedPayload(4),
	}
	if err := association.Fragment(context.Background(), datagram); !errors.Is(err, ErrClosed) {
		t.Fatalf("fragment after manager close = %v, want ErrClosed", err)
	}
	if err := p.b.Close(); err != nil {
		t.Fatalf("receiver manager Close: %v", err)
	}
	if err := p.b.Receive(context.Background(), p.envToB(), requests[0].Payload); !errors.Is(err, ErrClosed) {
		t.Fatalf("receive after manager close = %v, want ErrClosed", err)
	}
}

func TestManagerRejectsIncompleteConfig(t *testing.T) {
	valid := Config{
		NetworkID: testNetworkID,
		ContextID: ctxID,
		LocalNode: nodeA,
		Endpoints: testEndpointsMap(),
		Routes:    &testRoutes{routes: []DatagramRoute{testRouteA()}},
		Sender:    &captureSender{},
		Delivery:  &collectingDelivery{},
	}
	cases := map[string]func(*Config){
		"zero context":  func(c *Config) { c.ContextID = [32]byte{} },
		"zero node":     func(c *Config) { c.LocalNode = topology.NodeID{} },
		"nil endpoints": func(c *Config) { c.Endpoints = nil },
		"nil routes":    func(c *Config) { c.Routes = nil },
		"nil sender":    func(c *Config) { c.Sender = nil },
		"nil delivery":  func(c *Config) { c.Delivery = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := NewManager(config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewManager error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func datagramIDs(datagrams []Datagram) []uint64 {
	ids := make([]uint64, 0, len(datagrams))
	for _, datagram := range datagrams {
		ids = append(ids, datagram.DatagramID)
	}
	return ids
}

// TestPeerIsolationForSameAssociationID verifies that two authenticated source
// nodes reusing the identical AssociationID and DatagramID keep independent
// replay windows and assemblies, so the second is not a duplicate of the first.
func TestPeerIsolationForSameAssociationID(t *testing.T) {
	nodeC := topology.NodeID{0x0c}
	endpoints := testEndpointsMap()
	endpoints[vipC] = EndpointOwner{Owner: nodeC, Version: topology.FactVersion{Incarnation: 1, Sequence: 3}}
	delivery := &collectingDelivery{}
	manager := newTestManager(t, nodeA, endpoints, &testRoutes{routes: []DatagramRoute{testRouteA()}}, &captureSender{}, delivery, newTestClock().Now, nil)
	association, err := manager.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	reply := func(source netip.Addr) []byte {
		raw, err := EncodeFragment(Fragment{
			AssociationID:   association.ID(),
			Flags:           FlagReply,
			DatagramID:      1,
			FragmentIndex:   0,
			FragmentCount:   1,
			TotalPayloadLen: 4,
			Source:          netip.AddrPortFrom(source, 53),
			Destination:     netip.AddrPortFrom(vipA, 40000),
			Payload:         []byte("pong"),
		})
		if err != nil {
			t.Fatalf("encode reply: %v", err)
		}
		return raw
	}
	fromB := AuthenticatedEnvelope{NetworkID: testNetworkID, SrcNodeID: nodeB, DstNodeID: nodeA}
	fromC := AuthenticatedEnvelope{NetworkID: testNetworkID, SrcNodeID: nodeC, DstNodeID: nodeA}
	if err := manager.Receive(context.Background(), fromB, reply(vipB)); err != nil {
		t.Fatalf("peer B reply: %v", err)
	}
	if err := manager.Receive(context.Background(), fromC, reply(vipC)); err != nil {
		t.Fatalf("peer C reply with identical ID treated as duplicate: %v", err)
	}
	if got := delivery.datagrams(); len(got) != 2 {
		t.Fatalf("peer-isolated delivery = %d datagrams, want 2", len(got))
	}
	// The same DatagramID from B is a duplicate only in B's own window.
	if err := manager.Receive(context.Background(), fromB, reply(vipB)); err != nil {
		t.Fatalf("peer B replay: %v", err)
	}
	if got := delivery.datagrams(); len(got) != 2 {
		t.Fatalf("peer B replay delivered again: %d datagrams", len(got))
	}
	stats := manager.Stats()
	if stats.Peers != 2 {
		t.Fatalf("peer states = %d, want 2", stats.Peers)
	}
	if stats.Drops[DropDuplicate] != 1 {
		t.Fatalf("duplicate drops = %d, want 1", stats.Drops[DropDuplicate])
	}
}

// TestTargetAssociationRejectsForeignOriginator verifies the target-side role
// check: a target association belongs to the originator that created it, and
// another authenticated node cannot drive it with the same AssociationID.
func TestTargetAssociationRejectsForeignOriginator(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	_, requests := p.sendA(patternedPayload(4), 53)
	if err := p.feedToB(requests, 0); err != nil {
		t.Fatalf("feedToB: %v", err)
	}
	fragment, err := DecodeFragment(requests[0].Payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	target := p.b.targets[targetKey{origin: nodeA, id: fragment.AssociationID}]
	if target == nil {
		t.Fatal("target association was not created on B")
	}
	foreign := fragment
	foreign.DatagramID = 2
	foreign.Source = netip.AddrPortFrom(vipC, 40000)
	raw, err := EncodeFragment(foreign)
	if err != nil {
		t.Fatalf("encode foreign: %v", err)
	}
	foreignEnvelope := AuthenticatedEnvelope{NetworkID: testNetworkID, SrcNodeID: topology.NodeID{0x0c}, DstNodeID: nodeB}
	before := len(delivery.datagrams())
	if err := target.Receive(context.Background(), foreignEnvelope, raw); !errors.Is(err, ErrOwnership) {
		t.Fatalf("foreign originator error = %v, want ErrOwnership", err)
	}
	if got := len(delivery.datagrams()); got != before {
		t.Fatalf("foreign originator added a delivery: %d -> %d", before, got)
	}
}

// TestConsumedDatagramIDTombstonePreventsRedelivery verifies that a terminal
// discard permanently consumes its DatagramID: replaying the complete original
// fragments cannot deliver, while a newer DatagramID still works.
func TestConsumedDatagramIDTombstonePreventsRedelivery(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	association, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	first := p.sendOn(association, patternedPayload(MaxDatagramPayload), 53)
	if err := p.feedToB(first, 0); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	conflicting := append([]byte(nil), first[0].Payload...)
	conflicting[FixedMetadataLen] ^= 0xff
	if err := p.b.Receive(context.Background(), p.envToB(), conflicting); !errors.Is(err, ErrFrameMalformed) {
		t.Fatalf("conflict error = %v, want ErrFrameMalformed", err)
	}
	if err := p.feedToB(first, 0, 1); err != nil {
		t.Fatalf("replay after tombstone: %v", err)
	}
	if got := delivery.datagrams(); len(got) != 0 {
		t.Fatalf("tombstoned datagram was delivered: %v", datagramIDs(got))
	}
	second := p.sendOn(association, patternedPayload(16), 53)
	if second[0].DatagramID != 2 {
		t.Fatalf("next DatagramID = %d, want 2", second[0].DatagramID)
	}
	if err := p.feedToB(second, 0); err != nil {
		t.Fatalf("newer datagram: %v", err)
	}
	got := delivery.datagrams()
	if len(got) != 1 || got[0].DatagramID != 2 {
		t.Fatalf("newer datagram delivery = %v, want exactly ID 2", datagramIDs(got))
	}
	stats := p.b.Stats()
	if stats.Drops[DropConflict] != 1 || stats.Drops[DropDuplicate] < 2 {
		t.Fatalf("tombstone drops %+v", stats.Drops)
	}
}

// TestAggregateReassemblyBounds pins the frozen aggregate arithmetic: 256
// associations x 2 directions = 512 buffers, payload ceiling 33,539,584 bytes,
// and enforces both the byte budget and the buffer-count gate.
func TestAggregateReassemblyBounds(t *testing.T) {
	if MaxNetworkAssemblies != 512 {
		t.Fatalf("MaxNetworkAssemblies = %d, want 256*2", MaxNetworkAssemblies)
	}
	const wantPayload = 256 * 2 * 65507
	if DefaultLocalBufferBudget != wantPayload {
		t.Fatalf("DefaultLocalBufferBudget = %d, want %d", DefaultLocalBufferBudget, wantPayload)
	}
	budget := &localBudget{limit: DefaultLocalBufferBudget}
	if err := budget.Reserve(DefaultLocalBufferBudget); err != nil {
		t.Fatalf("reserve ceiling: %v", err)
	}
	if err := budget.Reserve(1); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("over-ceiling reserve error = %v, want ErrResourceLimit", err)
	}
	budget.Release(DefaultLocalBufferBudget)
	if err := budget.Reserve(DefaultLocalBufferBudget); err != nil {
		t.Fatalf("reserve after release: %v", err)
	}

	// The 513th outstanding buffer is refused even when bytes remain.
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	_, requests := p.sendA(patternedPayload(MaxDatagramPayload), 53)
	p.b.mu.Lock()
	p.b.assemblies = MaxNetworkAssemblies
	p.b.mu.Unlock()
	if err := p.b.Receive(context.Background(), p.envToB(), requests[0].Payload); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("513th assembly error = %v, want ErrResourceLimit", err)
	}
	stats := p.b.Stats()
	if stats.Assemblies != MaxNetworkAssemblies || stats.Drops[DropResource] != 1 {
		t.Fatalf("aggregate gate stats %+v", stats)
	}
}

// TestIdentityLedgerHoldsEachWindowIndependently creates two associations whose
// closes are one second apart under a two-record budget: after the first
// identity's 120 seconds elapse, the second identity must still be retained and
// neither its ID nor a new record may appear until the second window passes.
func TestIdentityLedgerHoldsEachWindowIndependently(t *testing.T) {
	clock := newTestClock()
	id1 := AssocID{0x01}
	id2 := AssocID{0x02}
	id3 := AssocID{0x03}
	id4 := AssocID{0x04}
	manager, err := NewManager(Config{
		NetworkID:                    testNetworkID,
		ContextID:                    ctxID,
		LocalNode:                    nodeA,
		Endpoints:                    testEndpointsMap(),
		Routes:                       &testRoutes{routes: []DatagramRoute{testRouteA()}},
		Sender:                       &captureSender{},
		Delivery:                     &collectingDelivery{},
		Rand:                         &seqRand{ids: []AssocID{id1, id2, id2, id3, id4}},
		Now:                          clock.Now,
		ClosedAssociationLedgerLimit: 2,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer manager.Close()

	first, err := manager.CreateAssociation()
	if err != nil {
		t.Fatalf("first association: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first: %v", err)
	}
	clock.Advance(time.Second)
	second, err := manager.CreateAssociation()
	if err != nil {
		t.Fatalf("second association: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second: %v", err)
	}
	if stats := manager.Stats(); stats.ClosedIDs != 2 || stats.LedgerReserved != 0 {
		t.Fatalf("identity ledger after two closes %+v", stats)
	}
	// Both records are unexpired: a third association must be refused.
	clock.Advance(60 * time.Second)
	if _, err := manager.CreateAssociation(); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("full identity ledger create error = %v, want ErrResourceLimit", err)
	}
	// The first identity expires at t0+120s; the second (closed at t0+1s) has
	// 119 seconds of its own window left.
	clock.Advance(59 * time.Second)
	manager.Sweep()
	if stats := manager.Stats(); stats.ClosedIDs != 1 {
		t.Fatalf("ClosedIDs after first expiry = %d, want 1", stats.ClosedIDs)
	}
	// The allocator must skip the still-retained id2 and pick a fresh ID.
	third, err := manager.CreateAssociation()
	if err != nil {
		t.Fatalf("third association after first expiry: %v", err)
	}
	if third.ID() != id3 {
		t.Fatalf("third association reused a still-retained identity %s, want %s", third.ID(), id3)
	}
	// The retained identity plus the live reservation fill the budget again.
	if _, err := manager.CreateAssociation(); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("reserved+closed budget error = %v, want ErrResourceLimit", err)
	}
	// Only after the second identity's own 120 seconds elapse is a fourth
	// association admitted.
	clock.Advance(time.Second)
	manager.Sweep()
	fourth, err := manager.CreateAssociation()
	if err != nil {
		t.Fatalf("fourth association after second expiry: %v", err)
	}
	if fourth.ID() != id4 {
		t.Fatalf("fourth association id = %s, want %s", fourth.ID(), id4)
	}
}

// TestNoReuseFenceBlocksAllocation proves the defensive path: if an identity
// record ever cannot be written, every new AssociationID is fenced for that
// identity's full 120-second window instead of being forgotten.
func TestNoReuseFenceBlocksAllocation(t *testing.T) {
	clock := newTestClock()
	manager, err := NewManager(Config{
		NetworkID:                    testNetworkID,
		ContextID:                    ctxID,
		LocalNode:                    nodeA,
		Endpoints:                    testEndpointsMap(),
		Routes:                       &testRoutes{routes: []DatagramRoute{testRouteA()}},
		Sender:                       &captureSender{},
		Delivery:                     &collectingDelivery{},
		Rand:                         &seqRand{ids: []AssocID{{0x11}, {0x12}}},
		Now:                          clock.Now,
		ClosedAssociationLedgerLimit: 1,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer manager.Close()

	manager.mu.Lock()
	manager.recent[AssocID{0x09}] = clock.Now()
	if recorded := manager.noteClosedLocked(AssocID{0x08}); recorded {
		manager.mu.Unlock()
		t.Fatal("noteClosedLocked recorded into a full ledger")
	}
	// Free the record but keep the fence: the unrecorded identity must still
	// block reuse for its full window.
	delete(manager.recent, AssocID{0x09})
	manager.mu.Unlock()

	if _, err := manager.CreateAssociation(); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("fenced create error = %v, want ErrResourceLimit", err)
	}
	clock.Advance(AssociationIdleTTL)
	manager.Sweep()
	association, err := manager.CreateAssociation()
	if err != nil {
		t.Fatalf("create after fence expiry: %v", err)
	}
	if association.ID() == (AssocID{0x08}) {
		t.Fatal("fence expired but the unrecorded identity was reused")
	}
}

// TestSingleFragmentCannotSkipRetainedAssemblyConflict is the F1 regression: a
// legal single-fragment descriptor reusing the AssociationID and DatagramID of
// an in-flight two-fragment assembly must be a terminal conflict, must not be
// delivered to the real UDP endpoint, must release the payload lease and the
// aggregate assembly slot immediately, and must tombstone the DatagramID.
func TestSingleFragmentCannotSkipRetainedAssemblyConflict(t *testing.T) {
	target := newUDPTarget(t)
	p := newPair(t, &collectingDelivery{}, target)
	association, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	inflight := p.sendOn(association, patternedPayload(MaxDatagramPayload), target.port())
	if len(inflight) != 2 {
		t.Fatalf("in-flight fragments = %d, want 2", len(inflight))
	}
	if err := p.feedToB(inflight, 0); err != nil {
		t.Fatalf("in-flight fragment 0: %v", err)
	}
	if stats := p.b.Stats(); stats.BytesHeld != MaxDatagramPayload || stats.Assemblies != 1 {
		t.Fatalf("retained assembly stats %+v", stats)
	}

	held, err := DecodeFragment(inflight[0].Payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	conflicting, err := EncodeFragment(Fragment{
		AssociationID:   held.AssociationID,
		Flags:           held.Flags,
		DatagramID:      held.DatagramID,
		FragmentIndex:   0,
		FragmentCount:   1,
		TotalPayloadLen: 100,
		Source:          held.Source,
		Destination:     held.Destination,
		Payload:         patternedPayload(100),
	})
	if err != nil {
		t.Fatalf("encode conflicting single fragment: %v", err)
	}
	if err := p.b.Receive(context.Background(), p.envToB(), conflicting); !errors.Is(err, ErrFrameMalformed) {
		t.Fatalf("single-fragment shortcut error = %v, want ErrFrameMalformed", err)
	}
	stats := p.b.Stats()
	if stats.Drops[DropConflict] != 1 {
		t.Fatalf("conflict drops = %d, want 1", stats.Drops[DropConflict])
	}
	if stats.BytesHeld != 0 || stats.Assemblies != 0 {
		t.Fatalf("conflict did not release lease/slot: %+v", stats)
	}
	target.expectSilence(300 * time.Millisecond)
	if stats.DeliveredDatagrams != 0 {
		t.Fatalf("conflicting single fragment was delivered: %+v", stats)
	}
	// The original second fragment cannot revive the tombstoned datagram.
	if err := p.feedToB(inflight, 1); err != nil {
		t.Fatalf("original fragment 1: %v", err)
	}
	stats = p.b.Stats()
	if stats.Assemblies != 0 || stats.DeliveredDatagrams != 0 || stats.BytesHeld != 0 {
		t.Fatalf("tombstoned datagram revived: %+v", stats)
	}
	target.expectSilence(300 * time.Millisecond)
}

// TestIdleTargetAssociationSweepReclaimsCapAndTombstones is the F2 regression:
// Sweep closes an idle implicit target association, records a 120-second identity
// tombstone, and the reclaimed capacity accepts a fresh AssociationID.
func TestIdleTargetAssociationSweepReclaimsCapAndTombstones(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	_, requests := p.sendA(patternedPayload(4), 53)
	if err := p.feedToB(requests, 0); err != nil {
		t.Fatalf("first target: %v", err)
	}
	if stats := p.b.Stats(); stats.Targets != 1 {
		t.Fatalf("targets = %d, want 1", stats.Targets)
	}
	p.clock.Advance(AssociationIdleTTL)
	p.b.Sweep()
	stats := p.b.Stats()
	if stats.Targets != 0 || stats.TargetTombstones != 1 {
		t.Fatalf("sweep target cleanup %+v", stats)
	}
	if stats.BytesHeld != 0 || stats.Assemblies != 0 {
		t.Fatalf("sweep leaked buffers: %+v", stats)
	}
	// The reclaimed slot accepts a new target association.
	second, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	later := p.sendOn(second, patternedPayload(4), 53)
	if err := p.feedToB(later, 0); err != nil {
		t.Fatalf("fresh target: %v", err)
	}
	if stats := p.b.Stats(); stats.Targets != 1 {
		t.Fatalf("reclaimed targets = %d, want 1", stats.Targets)
	}
	if got := delivery.datagrams(); len(got) != 2 {
		t.Fatalf("deliveries = %d, want 2", len(got))
	}
}

// TestDatagramIDExhaustionRunsFullCloseCleanup is the F3 regression: exhausting
// the u64 DatagramID space must run the same close-once cleanup as Close, so the
// cap slot, the ledger reservation and the identity record stay consistent and a
// later Close does not leak.
func TestDatagramIDExhaustionRunsFullCloseCleanup(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	association, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	if stats := p.a.Stats(); stats.Origins != 1 || stats.LedgerReserved != 1 || stats.ClosedIDs != 0 {
		t.Fatalf("pre-exhaustion stats %+v", stats)
	}
	association.nextID = math.MaxUint64
	datagram := OutboundDatagram{
		Source:      netip.AddrPortFrom(vipA, 40000),
		Destination: netip.AddrPortFrom(vipB, 53),
		Payload:     patternedPayload(4),
	}
	if err := association.Fragment(context.Background(), datagram); !errors.Is(err, ErrDatagramIDExhausted) {
		t.Fatalf("exhaustion error = %v, want ErrDatagramIDExhausted", err)
	}
	stats := p.a.Stats()
	if stats.Origins != 0 || stats.Associations != 0 || stats.ClosedIDs != 1 || stats.LedgerReserved != 0 {
		t.Fatalf("exhaustion did not fully clean up: %+v", stats)
	}
	if _, present := p.a.origins[association.ID()]; present {
		t.Fatal("exhausted association still occupies the origin map")
	}
	if _, retired := p.a.recent[association.ID()]; !retired {
		t.Fatal("exhausted AssociationID was not retired in the recently-closed ledger")
	}
	if err := association.Close(); err != nil {
		t.Fatalf("post-exhaustion Close: %v", err)
	}
	if stats := p.a.Stats(); stats.ClosedIDs != 1 || stats.LedgerReserved != 0 {
		t.Fatalf("post-Close leak: %+v", stats)
	}
	next, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation after drain: %v", err)
	}
	if next.ID() == association.ID() {
		t.Fatal("exhausted AssociationID was reused")
	}
}

// TestReplyRoundTripRealUDP drives a request through B's real endpoint, replies
// through Reply, and proves the peer receives the reply as exactly one datagram
// over real UDP for both the maximum 65,507-byte two-fragment payload and an
// empty payload (duplicate callback also checks the REPLY DatagramID counter).
func TestReplyRoundTripRealUDP(t *testing.T) {
	targetA := newUDPTarget(t) // A's endpoint receives the reply
	targetB := newUDPTarget(t) // B's endpoint receives the request
	p := newPair(t, targetA, targetB)

	association, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	requestPayload := patternedPayload(MaxDatagramPayload)
	inflight := p.sendOn(association, requestPayload, targetB.port())
	if len(inflight) != 2 {
		t.Fatalf("request fragments = %d, want 2", len(inflight))
	}
	if err := p.feedToB(inflight, 1, 0); err != nil {
		t.Fatalf("feedToB: %v", err)
	}
	if got := targetB.readOne(5 * time.Second); !bytes.Equal(got, requestPayload) {
		t.Fatalf("request datagram differs (%d bytes)", len(got))
	}
	received := targetB.lastDatagram()
	if received.Flags != FlagRequest || received.receipt == nil {
		t.Fatalf("delivered request lacks reply authority: %+v", received)
	}

	replyPayload := patternedPayload(MaxDatagramPayload)
	for i := range replyPayload {
		replyPayload[i] ^= 0xa5
	}
	if err := p.b.Reply(context.Background(), received, replyPayload); err != nil {
		t.Fatalf("Reply: %v", err)
	}
	replyFragments := p.takeSentB()
	if len(replyFragments) != 2 {
		t.Fatalf("reply fragments = %d, want 2", len(replyFragments))
	}
	for _, fragment := range replyFragments {
		if fragment.Flags != FlagReply || fragment.DatagramID != 1 ||
			fragment.SrcNodeID != nodeB || fragment.DstNodeID != nodeA {
			t.Fatalf("reply fragment identity mismatch: %+v", fragment)
		}
	}
	if err := p.feedToA(replyFragments, 1, 0); err != nil {
		t.Fatalf("feedToA: %v", err)
	}
	got := targetA.readOne(5 * time.Second)
	if len(got) != MaxDatagramPayload || !bytes.Equal(got, replyPayload) {
		t.Fatalf("reply datagram differs (%d bytes)", len(got))
	}
	targetA.expectSilence(200 * time.Millisecond)
	targetB.expectSilence(200 * time.Millisecond)

	// Duplicate callback: an empty reply is a legal single fragment with the next
	// REPLY DatagramID, and the peer receives one empty datagram.
	if err := p.b.Reply(context.Background(), received, []byte{}); err != nil {
		t.Fatalf("duplicate Reply: %v", err)
	}
	emptyFragments := p.takeSentB()
	if len(emptyFragments) != 1 || emptyFragments[0].DatagramID != 2 ||
		emptyFragments[0].FragmentCount != 1 || emptyFragments[0].TotalPayloadLen != 0 {
		t.Fatalf("empty reply framing = %+v", emptyFragments)
	}
	if err := p.feedToA(emptyFragments, 0); err != nil {
		t.Fatalf("feedToA empty: %v", err)
	}
	if got := targetA.readOne(5 * time.Second); len(got) != 0 {
		t.Fatalf("empty reply delivered %d bytes", len(got))
	}
	targetA.expectSilence(200 * time.Millisecond)
	if stats := p.b.Stats(); stats.SentDatagrams != 2 || stats.BytesHeld != 0 {
		t.Fatalf("sender reply stats %+v", stats)
	}
	if stats := p.a.Stats(); stats.DeliveredDatagrams != 2 || stats.BytesHeld != 0 {
		t.Fatalf("receiver reply stats %+v", stats)
	}
}

// TestReplyRejectsFabricatedAndMutatedMetadata proves reply authority cannot be
// fabricated and no field of the delivered Datagram may be rewritten.
func TestReplyRejectsFabricatedAndMutatedMetadata(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	received := p.requestThenReceive(patternedPayload(8))
	ctx := context.Background()

	if err := p.b.Reply(ctx, Datagram{}, []byte("x")); !errors.Is(err, ErrNoReplyAuthority) {
		t.Fatalf("fabricated datagram error = %v, want ErrNoReplyAuthority", err)
	}
	mutated := received
	mutated.Destination = netip.AddrPortFrom(mutated.Destination.Addr(), mutated.Destination.Port()+1)
	if err := p.b.Reply(ctx, mutated, []byte("x")); !errors.Is(err, ErrNoReplyAuthority) {
		t.Fatalf("mutated destination error = %v, want ErrNoReplyAuthority", err)
	}
	mutated = received
	mutated.Source = netip.AddrPortFrom(mutated.Source.Addr(), mutated.Source.Port()+1)
	if err := p.b.Reply(ctx, mutated, []byte("x")); !errors.Is(err, ErrNoReplyAuthority) {
		t.Fatalf("mutated source error = %v, want ErrNoReplyAuthority", err)
	}
	mutated = received
	mutated.Flags = FlagReply
	if err := p.b.Reply(ctx, mutated, []byte("x")); !errors.Is(err, ErrNoReplyAuthority) {
		t.Fatalf("mutated flags error = %v, want ErrNoReplyAuthority", err)
	}
	mutated = received
	mutated.AssociationID = AssocID{0xff}
	if err := p.b.Reply(ctx, mutated, []byte("x")); !errors.Is(err, ErrNoReplyAuthority) {
		t.Fatalf("mutated association error = %v, want ErrNoReplyAuthority", err)
	}
	if p.senderB.callCount() != 0 {
		t.Fatalf("rejected replies reached the sender: %d calls", p.senderB.callCount())
	}
	if drops := p.b.Stats().Drops; drops[DropReply] != 5 {
		t.Fatalf("reply drops = %d, want 5", drops[DropReply])
	}
}

// TestReplyRefusesClosedTarget refuses a reply once the target association is
// closed.
func TestReplyRefusesClosedTarget(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	received := p.requestThenReceive(patternedPayload(4))
	target := p.b.targets[targetKey{origin: nodeA, id: received.AssociationID}]
	if target == nil {
		t.Fatal("target association was not created")
	}
	if err := target.Close(); err != nil {
		t.Fatalf("target Close: %v", err)
	}
	if err := p.b.Reply(context.Background(), received, []byte("x")); !errors.Is(err, ErrReplyUnavailable) {
		t.Fatalf("closed target error = %v, want ErrReplyUnavailable", err)
	}
	if p.senderB.callCount() != 0 {
		t.Fatalf("closed target reply reached the sender")
	}
}

// TestReplyRefusesExpiredTargetAndStaleReceiptAfterRecreate is the generation
// identity regression: an old receipt is refused after the 120-second expiry
// even when a new target association with the same AssociationID exists.
func TestReplyRefusesExpiredTargetAndStaleReceiptAfterRecreate(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	association, requests := p.sendA(patternedPayload(4), 53)
	if err := p.feedToB(requests, 0); err != nil {
		t.Fatalf("first request: %v", err)
	}
	stale := p.receivedByB()

	p.clock.Advance(AssociationIdleTTL)
	if err := p.b.Reply(context.Background(), stale, []byte("x")); !errors.Is(err, ErrReplyUnavailable) {
		t.Fatalf("expired target error = %v, want ErrReplyUnavailable", err)
	}
	if stats := p.b.Stats(); stats.Targets != 0 || stats.TargetTombstones != 1 {
		t.Fatalf("expiry cleanup stats %+v", stats)
	}
	// Inside the closed-window tombstone the same AssociationID is refused.
	blocked := p.sendOn(association, patternedPayload(4), 53)
	if err := p.feedToB(blocked, 0); !errors.Is(err, ErrUnknownAssociation) {
		t.Fatalf("tombstoned request error = %v, want ErrUnknownAssociation", err)
	}
	// Past the tombstone window a NEW target association with the SAME
	// AssociationID is created; the stale receipt must still be refused.
	p.clock.Advance(AssociationIdleTTL)
	p.b.Sweep()
	if stats := p.b.Stats(); stats.TargetTombstones != 0 {
		t.Fatalf("tombstone not pruned: %+v", stats)
	}
	recreated := p.sendOn(association, patternedPayload(4), 53)
	if err := p.feedToB(recreated, 0); err != nil {
		t.Fatalf("recreated target request: %v", err)
	}
	if stats := p.b.Stats(); stats.Targets != 1 {
		t.Fatalf("recreated target missing: %+v", stats)
	}
	if err := p.b.Reply(context.Background(), stale, []byte("x")); !errors.Is(err, ErrReplyUnavailable) {
		t.Fatalf("stale receipt accepted after recreate: %v", err)
	}
	if p.senderB.callCount() != 0 {
		t.Fatalf("stale receipt reached the sender")
	}
	// The fresh delivery's receipt is authorized.
	fresh := p.receivedByB()
	if err := p.b.Reply(context.Background(), fresh, []byte("ok")); err != nil {
		t.Fatalf("fresh reply: %v", err)
	}
	if p.senderB.callCount() != 1 {
		t.Fatalf("fresh reply sender calls = %d, want 1", p.senderB.callCount())
	}
}

// TestReplyOwnershipChangeDoesNotRetarget refuses a reply when the original
// requester no longer owns the reply destination.
func TestReplyOwnershipChangeDoesNotRetarget(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	received := p.requestThenReceive(patternedPayload(4))
	p.endpoints[vipA] = EndpointOwner{Owner: topology.NodeID{0x0c}, Version: topology.FactVersion{Incarnation: 1, Sequence: 9}}
	if err := p.b.Reply(context.Background(), received, []byte("x")); !errors.Is(err, ErrOwnership) {
		t.Fatalf("changed owner error = %v, want ErrOwnership", err)
	}
	if p.senderB.callCount() != 0 {
		t.Fatalf("retargeting reply reached the sender")
	}
	if drops := p.b.Stats().Drops; drops[DropOwnership] != 1 {
		t.Fatalf("ownership drops = %d, want 1", drops[DropOwnership])
	}
}

// TestReplyContextCanceled propagates context cancellation and sends nothing.
func TestReplyContextCanceled(t *testing.T) {
	delivery := &collectingDelivery{}
	p := newPair(t, &collectingDelivery{}, delivery)
	received := p.requestThenReceive(patternedPayload(4))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.b.Reply(ctx, received, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reply error = %v, want context.Canceled", err)
	}
	if p.senderB.callCount() != 0 {
		t.Fatalf("canceled reply reached the sender")
	}
}
