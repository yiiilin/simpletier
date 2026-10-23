package packet

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/topology"
)

func testNode(fill byte) topology.NodeID {
	var node topology.NodeID
	for index := range node {
		node[index] = fill
	}
	return node
}

func testVersion(incarnation, sequence uint64) topology.FactVersion {
	return topology.FactVersion{Incarnation: incarnation, Sequence: sequence}
}

type fakeResolver struct {
	mu     sync.Mutex
	routes map[netip.Addr]PacketRoute
	errs   map[netip.Addr]error
	hook   func(ctx context.Context, call int, destination netip.Addr) (PacketRoute, error)
	calls  int
}

func (f *fakeResolver) ResolvePacketRoute(ctx context.Context, destination netip.Addr) (PacketRoute, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	hook := f.hook
	route, ok := f.routes[destination]
	err := f.errs[destination]
	f.mu.Unlock()
	if hook != nil {
		return hook(ctx, call, destination)
	}
	if err != nil {
		return PacketRoute{}, err
	}
	if !ok {
		return PacketRoute{}, ErrNoRoute
	}
	return route, nil
}

func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeSender struct {
	mu       sync.Mutex
	requests []SendRequest
	err      error
	called   chan struct{}
	release  chan struct{}
	onSend   func(ctx context.Context, request SendRequest) error
}

func (f *fakeSender) SendPacket(ctx context.Context, request SendRequest) error {
	copied := request
	copied.Payload = append([]byte(nil), request.Payload...)
	f.mu.Lock()
	f.requests = append(f.requests, copied)
	err := f.err
	called := f.called
	release := f.release
	onSend := f.onSend
	f.mu.Unlock()
	if called != nil {
		select {
		case called <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	if onSend != nil {
		return onSend(ctx, request)
	}
	return err
}

func (f *fakeSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeSender) last(t *testing.T) SendRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		t.Fatal("the sender was never called")
	}
	return f.requests[len(f.requests)-1]
}

type fakeDevice struct {
	mu      sync.Mutex
	packets [][]byte
	mtu     int
	err     error
}

func (d *fakeDevice) WritePacket(_ context.Context, packet []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.packets = append(d.packets, append([]byte(nil), packet...))
	return d.err
}

func (d *fakeDevice) MTU() int { return d.mtu }

func (d *fakeDevice) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.packets)
}

type harness struct {
	t          *testing.T
	service    *Service
	resolver   *fakeResolver
	sender     *fakeSender
	device     *fakeDevice
	localNode  topology.NodeID
	remoteNode topology.NodeID
	vip        netip.Addr
	remote     netip.Addr
	cidr       netip.Prefix
}

func newHarness(t *testing.T, adjust func(*Config)) *harness {
	t.Helper()
	h := &harness{
		t:          t,
		localNode:  testNode(0x11),
		remoteNode: testNode(0x22),
		vip:        netip.MustParseAddr("10.9.0.1"),
		remote:     netip.MustParseAddr("10.9.0.2"),
		cidr:       netip.MustParsePrefix("10.9.0.0/24"),
		sender:     &fakeSender{},
		device:     &fakeDevice{mtu: DefaultDeviceMTU},
	}
	route := PacketRoute{
		DestinationNode:    h.remoteNode,
		AddressFactVersion: testVersion(1, 1),
		Lane:               path.LanePacket,
		PathID:             7,
		PathGeneration:     1,
	}
	localRoute := route
	localRoute.DestinationNode = h.localNode
	h.resolver = &fakeResolver{
		routes: map[netip.Addr]PacketRoute{h.remote: route, h.vip: localRoute},
		errs:   map[netip.Addr]error{},
	}
	config := Config{
		LocalNode: h.localNode,
		VirtualIP: h.vip,
		CIDR:      h.cidr,
		Device:    h.device,
		Resolver:  h.resolver,
		Sender:    h.sender,
	}
	if adjust != nil {
		adjust(&config)
	}
	service, err := New(config)
	if err != nil {
		t.Fatalf("New(%+v): %v", config, err)
	}
	h.service = service
	return h
}

func (h *harness) assertDropped(err error, want error, reason DropReason) {
	h.t.Helper()
	if !errors.Is(err, want) {
		h.t.Fatalf("Send/Receive error %v, want %v", err, want)
	}
	stats := h.service.Stats()
	if stats.Drops[reason] == 0 {
		h.t.Fatalf("drop reason %s was not counted (drops=%v)", reason, stats.Drops)
	}
}

func TestNewValidation(t *testing.T) {
	h := newHarness(t, nil)
	base := Config{
		LocalNode: h.localNode,
		VirtualIP: h.vip,
		CIDR:      h.cidr,
		Device:    h.device,
		Resolver:  h.resolver,
		Sender:    h.sender,
	}
	cases := []struct {
		name   string
		adjust func(*Config)
	}{
		{"empty node", func(c *Config) { c.LocalNode = topology.NodeID{} }},
		{"invalid cidr", func(c *Config) { c.CIDR = netip.Prefix{} }},
		{"ipv6 cidr", func(c *Config) { c.CIDR = netip.MustParsePrefix("fd00::/64") }},
		{"vip outside cidr", func(c *Config) { c.VirtualIP = netip.MustParseAddr("10.10.0.1") }},
		{"vip is broadcast", func(c *Config) { c.VirtualIP = netip.MustParseAddr("10.9.0.255") }},
		{"nil device", func(c *Config) { c.Device = nil }},
		{"nil resolver", func(c *Config) { c.Resolver = nil }},
		{"nil sender", func(c *Config) { c.Sender = nil }},
		{"mtu too small", func(c *Config) { c.Device = &fakeDevice{mtu: 20} }},
		{"mtu above frozen ceiling", func(c *Config) { c.Device = &fakeDevice{mtu: DefaultDeviceMTU + 1} }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := base
			testCase.adjust(&config)
			if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New error %v, want ErrInvalidConfig", err)
			}
		})
	}

	t.Run("zero device MTU means the frozen default", func(t *testing.T) {
		config := base
		config.Device = &fakeDevice{}
		service, err := New(config)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if service.MTU() != DefaultDeviceMTU {
			t.Fatalf("MTU() = %d, want %d", service.MTU(), DefaultDeviceMTU)
		}
	})

	t.Run("a down-adjusted MTU is accepted", func(t *testing.T) {
		config := base
		config.Device = &fakeDevice{mtu: 1200}
		service, err := New(config)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if service.MTU() != 1200 {
			t.Fatalf("MTU() = %d, want 1200", service.MTU())
		}
	})
}

func TestSendForwardsValidatedPacketOpaque(t *testing.T) {
	h := newHarness(t, nil)
	raw := testIPv4(h.vip, h.remote, 17, 64, ipv4FlagDontFrag, 0, nil, []byte("udp-in"))
	before := append([]byte(nil), raw...)

	if err := h.service.Send(context.Background(), raw); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if h.sender.count() != 1 {
		t.Fatalf("sender calls = %d, want 1", h.sender.count())
	}
	request := h.sender.last(t)
	if !bytes.Equal(request.Payload, before) {
		t.Fatalf("forwarded payload differs from the input packet")
	}
	if request.Payload[8] != 64 {
		t.Fatalf("forwarded TTL = %d, want the original 64", request.Payload[8])
	}
	if request.Lane != path.LanePacket || request.DestinationNode != h.remoteNode {
		t.Fatalf("lane/node = %v/%x", request.Lane, request.DestinationNode)
	}
	if request.AddressFactVersion != testVersion(1, 1) || request.PathID != 7 || request.PathGeneration != 1 {
		t.Fatalf("pinned route = %+v", request)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("Send must not rewrite the packet bytes")
	}
	if stats := h.service.Stats(); stats.Sent != 1 || stats.Dropped != 0 {
		t.Fatalf("stats = %+v, want one sent and nothing dropped", stats)
	}
}

func TestSendDrops(t *testing.T) {
	h := newHarness(t, nil)

	t.Run("malformed checksum", func(t *testing.T) {
		raw := testIPv4(h.vip, h.remote, 17, 64, 0, 0, nil, []byte("x"))
		raw[10] ^= 0xff
		h.assertDropped(h.service.Send(context.Background(), raw), ErrPacketMalformed, DropMalformed)
	})

	t.Run("ipv6", func(t *testing.T) {
		raw := make([]byte, 40)
		raw[0] = 0x60
		h.assertDropped(h.service.Send(context.Background(), raw), ErrIPv6Unsupported, DropIPv6Unsupported)
	})

	t.Run("above the virtual MTU", func(t *testing.T) {
		raw := testIPv4(h.vip, h.remote, 17, 64, 0, 0, nil, make([]byte, DefaultDeviceMTU))
		h.assertDropped(h.service.Send(context.Background(), raw), ErrPacketTooLarge, DropTooLarge)
	})

	t.Run("directed broadcast", func(t *testing.T) {
		raw := testIPv4(h.vip, netip.MustParseAddr("10.9.0.255"), 17, 64, 0, 0, nil, []byte("x"))
		h.assertDropped(h.service.Send(context.Background(), raw), ErrForbiddenAddress, DropBroadcast)
	})

	t.Run("multicast", func(t *testing.T) {
		raw := testIPv4(h.vip, netip.MustParseAddr("224.0.0.1"), 17, 64, 0, 0, nil, []byte("x"))
		h.assertDropped(h.service.Send(context.Background(), raw), ErrForbiddenAddress, DropBroadcast)
	})

	t.Run("spoofed source", func(t *testing.T) {
		raw := testIPv4(netip.MustParseAddr("10.9.0.9"), h.remote, 17, 64, 0, 0, nil, []byte("x"))
		h.assertDropped(h.service.Send(context.Background(), raw), ErrSourceNotOwned, DropSourceNotOwned)
	})

	if h.sender.count() != 0 {
		t.Fatalf("a dropped packet must never reach the sender (calls=%d)", h.sender.count())
	}
	if stats := h.service.Stats(); stats.Sent != 0 {
		t.Fatalf("stats.Sent = %d, want 0", stats.Sent)
	}
}

func TestSendClassifiesRouteErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		reason DropReason
	}{
		{"no route", ErrNoRoute, DropNoRoute},
		{"policy denied", ErrPolicyDenied, DropPolicyDenied},
		{"conflict", ErrRouteConflict, DropRouteConflict},
		{"stale", ErrRouteStale, DropRouteStale},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.resolver.errs[h.remote] = testCase.err
			raw := testIPv4(h.vip, h.remote, 17, 64, 0, 0, nil, []byte("x"))
			h.assertDropped(h.service.Send(context.Background(), raw), testCase.err, testCase.reason)
			if h.sender.count() != 0 {
				t.Fatal("a route failure must not reach the sender")
			}
		})
	}
}

func TestSendRevalidatesOwnerAndNeverRetargets(t *testing.T) {
	other := testNode(0x33)
	raw := testIPv4(netip.MustParseAddr("10.9.0.1"), netip.MustParseAddr("10.9.0.2"), 17, 64, 0, 0, nil, []byte("x"))

	t.Run("owner changed after pinning", func(t *testing.T) {
		h := newHarness(t, nil)
		h.resolver.hook = func(_ context.Context, call int, _ netip.Addr) (PacketRoute, error) {
			if call == 1 {
				return PacketRoute{DestinationNode: h.remoteNode, AddressFactVersion: testVersion(1, 1), Lane: path.LanePacket, PathID: 7, PathGeneration: 1}, nil
			}
			return PacketRoute{DestinationNode: other, AddressFactVersion: testVersion(2, 1), Lane: path.LanePacket, PathID: 7, PathGeneration: 1}, nil
		}
		h.assertDropped(h.service.Send(context.Background(), raw), ErrRouteStale, DropRouteStale)
		if h.sender.count() != 0 {
			t.Fatal("a changed owner must not be retargeted to the new NodeID")
		}
		if calls := h.resolver.callCount(); calls != 2 {
			t.Fatalf("resolver calls = %d, want the pin plus the pre-egress recheck", calls)
		}
	})

	t.Run("same-owner version renewal is not a route change", func(t *testing.T) {
		h := newHarness(t, nil)
		h.resolver.hook = func(_ context.Context, call int, _ netip.Addr) (PacketRoute, error) {
			version := testVersion(1, 1)
			if call > 1 {
				// A same-owner renewal advances only the version. The ADDRESS fact
				// key binds the owner and the /32, so the mapping is unchanged and
				// the packet must still be delivered.
				version = testVersion(1, 2)
			}
			return PacketRoute{DestinationNode: h.remoteNode, AddressFactVersion: version, Lane: path.LanePacket, PathID: 7, PathGeneration: 1}, nil
		}
		if err := h.service.Send(context.Background(), raw); err != nil {
			t.Fatalf("Send across a same-owner renewal: %v", err)
		}
		if h.sender.count() != 1 {
			t.Fatalf("sender calls = %d; want 1 (a renewal must not drop the packet)", h.sender.count())
		}
		if calls := h.resolver.callCount(); calls != 2 {
			t.Fatalf("resolver calls = %d; want the pin plus the pre-egress recheck", calls)
		}
	})

	t.Run("owner gone before egress", func(t *testing.T) {
		h := newHarness(t, nil)
		h.resolver.hook = func(_ context.Context, call int, _ netip.Addr) (PacketRoute, error) {
			if call == 1 {
				return PacketRoute{DestinationNode: h.remoteNode, AddressFactVersion: testVersion(1, 1), Lane: path.LanePacket, PathID: 7, PathGeneration: 1}, nil
			}
			return PacketRoute{}, ErrRouteConflict
		}
		h.assertDropped(h.service.Send(context.Background(), raw), ErrRouteConflict, DropRouteConflict)
	})
}

func TestSendRejectsInvalidRouteShape(t *testing.T) {
	base := PacketRoute{DestinationNode: testNode(0x22), AddressFactVersion: testVersion(1, 1), Lane: path.LanePacket, PathID: 7, PathGeneration: 1}
	cases := []struct {
		name   string
		mutate func(*PacketRoute)
	}{
		{"empty node", func(r *PacketRoute) { r.DestinationNode = topology.NodeID{} }},
		{"zero version", func(r *PacketRoute) { r.AddressFactVersion = topology.FactVersion{} }},
		{"stream lane", func(r *PacketRoute) { r.Lane = path.LaneStream }},
		{"zero path", func(r *PacketRoute) { r.PathID = 0 }},
		{"zero generation", func(r *PacketRoute) { r.PathGeneration = 0 }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t, nil)
			route := base
			testCase.mutate(&route)
			h.resolver.hook = func(context.Context, int, netip.Addr) (PacketRoute, error) { return route, nil }
			raw := testIPv4(h.vip, h.remote, 17, 64, 0, 0, nil, []byte("x"))
			h.assertDropped(h.service.Send(context.Background(), raw), ErrInvalidConfig, DropRouteInvalid)
		})
	}
}

func TestSendHonoursContext(t *testing.T) {
	t.Run("nil context", func(t *testing.T) {
		h := newHarness(t, nil)
		raw := testIPv4(h.vip, h.remote, 17, 64, 0, 0, nil, []byte("x"))
		if err := h.service.Send(nil, raw); !errors.Is(err, ErrNilContext) {
			t.Fatalf("Send(nil) error %v, want ErrNilContext", err)
		}
	})

	t.Run("cancelled before validation", func(t *testing.T) {
		h := newHarness(t, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		raw := testIPv4(h.vip, h.remote, 17, 64, 0, 0, nil, []byte("x"))
		if err := h.service.Send(ctx, raw); !errors.Is(err, context.Canceled) {
			t.Fatalf("Send(cancelled) error %v, want context.Canceled", err)
		}
		if h.sender.count() != 0 || h.resolver.callCount() != 0 {
			t.Fatal("a cancelled Send must not resolve or dispatch")
		}
	})

	t.Run("resolver observes the deadline", func(t *testing.T) {
		h := newHarness(t, nil)
		h.resolver.hook = func(ctx context.Context, _ int, _ netip.Addr) (PacketRoute, error) {
			<-ctx.Done()
			return PacketRoute{}, ctx.Err()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		raw := testIPv4(h.vip, h.remote, 17, 64, 0, 0, nil, []byte("x"))
		if err := h.service.Send(ctx, raw); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Send error %v, want context.DeadlineExceeded", err)
		}
	})

	t.Run("sender observes the deadline", func(t *testing.T) {
		h := newHarness(t, nil)
		h.sender.onSend = func(ctx context.Context, _ SendRequest) error {
			<-ctx.Done()
			return ctx.Err()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		raw := testIPv4(h.vip, h.remote, 17, 64, 0, 0, nil, []byte("x"))
		if err := h.service.Send(ctx, raw); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Send error %v, want context.DeadlineExceeded", err)
		}
		h.assertDropped(context.DeadlineExceeded, context.DeadlineExceeded, DropSender)
	})
}

func TestSendOverflowIsACountedDrop(t *testing.T) {
	h := newHarness(t, nil)
	h.sender.called = make(chan struct{}, 1)
	h.sender.release = make(chan struct{})
	raw := testIPv4(h.vip, h.remote, 17, 64, 0, 0, nil, []byte("x"))

	results := make(chan error, MaxPendingFrames)
	for index := 0; index < MaxPendingFrames; index++ {
		go func() { results <- h.service.Send(context.Background(), raw) }()
		select {
		case <-h.sender.called:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d packets reached the sender", index, MaxPendingFrames)
		}
	}
	if err := h.service.Send(context.Background(), raw); !errors.Is(err, ErrOverflow) {
		t.Fatalf("Send past the budget error %v, want ErrOverflow", err)
	}
	if stats := h.service.Stats(); stats.Drops[DropOverflow] != 1 {
		t.Fatalf("overflow drops = %d, want 1", stats.Drops[DropOverflow])
	}
	close(h.sender.release)
	for index := 0; index < MaxPendingFrames; index++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("admitted Send %d failed: %v", index, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("admitted Send %d never returned", index)
		}
	}
	if stats := h.service.Stats(); stats.Sent != MaxPendingFrames {
		t.Fatalf("sent = %d, want %d", stats.Sent, MaxPendingFrames)
	}
}

func TestReceiveWritesValidatedPacket(t *testing.T) {
	h := newHarness(t, nil)
	raw := testIPv4(h.remote, h.vip, 6, 64, 0, 0, nil, []byte("syn"))
	before := append([]byte(nil), raw...)

	if err := h.service.Receive(context.Background(), h.remoteNode, h.localNode, raw); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if h.device.count() != 1 {
		t.Fatalf("device writes = %d, want 1", h.device.count())
	}
	if !bytes.Equal(h.device.packets[0], before) {
		t.Fatal("Receive must write the packet unchanged")
	}
	if stats := h.service.Stats(); stats.Received != 1 || stats.Dropped != 0 {
		t.Fatalf("stats = %+v, want one received and nothing dropped", stats)
	}
}

func TestReceiveDrops(t *testing.T) {
	h := newHarness(t, nil)
	valid := func() []byte { return testIPv4(h.remote, h.vip, 6, 64, 0, 0, nil, []byte("x")) }

	t.Run("foreign envelope destination", func(t *testing.T) {
		h.assertDropped(h.service.Receive(context.Background(), h.remoteNode, testNode(0x44), valid()), ErrForeignDestination, DropForeignDestination)
	})

	t.Run("zero envelope destination", func(t *testing.T) {
		h.assertDropped(h.service.Receive(context.Background(), h.remoteNode, topology.NodeID{}, valid()), ErrForeignDestination, DropForeignDestination)
	})

	t.Run("empty authenticated source", func(t *testing.T) {
		h.assertDropped(h.service.Receive(context.Background(), topology.NodeID{}, h.localNode, valid()), ErrInvalidConfig, DropRouteInvalid)
	})

	t.Run("source is not owned by the authenticated node", func(t *testing.T) {
		spoofed := testIPv4(h.remote, h.vip, 6, 64, 0, 0, nil, []byte("x"))
		h.assertDropped(h.service.Receive(context.Background(), testNode(0x55), h.localNode, spoofed), ErrSourceNotOwned, DropSourceNotOwned)
	})

	t.Run("source has no unique owner", func(t *testing.T) {
		h.resolver.errs[h.remote] = ErrRouteConflict
		defer delete(h.resolver.errs, h.remote)
		h.assertDropped(h.service.Receive(context.Background(), h.remoteNode, h.localNode, valid()), ErrRouteConflict, DropRouteConflict)
	})

	t.Run("malformed", func(t *testing.T) {
		raw := valid()
		raw[10] ^= 0xff
		h.assertDropped(h.service.Receive(context.Background(), h.remoteNode, h.localNode, raw), ErrPacketMalformed, DropMalformed)
	})

	t.Run("above the virtual MTU", func(t *testing.T) {
		raw := testIPv4(h.remote, h.vip, 6, 64, 0, 0, nil, make([]byte, DefaultDeviceMTU))
		h.assertDropped(h.service.Receive(context.Background(), h.remoteNode, h.localNode, raw), ErrPacketTooLarge, DropTooLarge)
	})

	t.Run("broadcast destination", func(t *testing.T) {
		raw := testIPv4(h.remote, netip.MustParseAddr("10.9.0.255"), 6, 64, 0, 0, nil, []byte("x"))
		h.assertDropped(h.service.Receive(context.Background(), h.remoteNode, h.localNode, raw), ErrForbiddenAddress, DropBroadcast)
	})

	if h.device.count() != 0 {
		t.Fatalf("a dropped packet must never reach the device (writes=%d)", h.device.count())
	}
}

func TestReceiveRejectsDestinationOwnershipChanges(t *testing.T) {
	h := newHarness(t, nil)
	raw := testIPv4(h.remote, h.vip, 6, 64, 0, 0, nil, []byte("x"))

	if err := h.service.SetOwnedVirtualIP(netip.MustParseAddr("10.9.0.9")); err != nil {
		t.Fatalf("SetOwnedVirtualIP: %v", err)
	}
	h.assertDropped(h.service.Receive(context.Background(), h.remoteNode, h.localNode, raw), ErrDestinationNotOwned, DropDestinationNotOwned)
	if h.device.count() != 0 {
		t.Fatal("a packet for an address this node no longer owns must not reach the device")
	}

	if err := h.service.SetOwnedVirtualIP(netip.Addr{}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	h.assertDropped(h.service.Receive(context.Background(), h.remoteNode, h.localNode, raw), ErrDestinationNotOwned, DropDestinationNotOwned)
}

func TestReceiveDeviceErrorIsCounted(t *testing.T) {
	h := newHarness(t, nil)
	h.device.err = errors.New("device write failed")
	raw := testIPv4(h.remote, h.vip, 6, 64, 0, 0, nil, []byte("x"))
	err := h.service.Receive(context.Background(), h.remoteNode, h.localNode, raw)
	if !errors.Is(err, h.device.err) {
		t.Fatalf("Receive error %v, want the device error", err)
	}
	stats := h.service.Stats()
	if stats.Drops[DropDevice] != 1 || stats.Received != 0 {
		t.Fatalf("stats = %+v, want one device drop and no receive", stats)
	}
}

func TestClosedServiceRejectsWork(t *testing.T) {
	h := newHarness(t, nil)
	raw := testIPv4(h.vip, h.remote, 17, 64, 0, 0, nil, []byte("x"))
	if err := h.service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.service.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}
	if !h.service.Closed() {
		t.Fatal("Closed() = false after Close")
	}
	h.assertDropped(h.service.Send(context.Background(), raw), ErrClosed, DropClosed)
	h.assertDropped(h.service.Receive(context.Background(), h.remoteNode, h.localNode, raw), ErrClosed, DropClosed)
	if err := h.service.SetOwnedVirtualIP(h.vip); !errors.Is(err, ErrClosed) {
		t.Fatalf("SetOwnedVirtualIP after Close error %v, want ErrClosed", err)
	}
}

func TestSetOwnedVirtualIPValidation(t *testing.T) {
	h := newHarness(t, nil)
	cases := []struct {
		name    string
		address netip.Addr
	}{
		{"outside the CIDR", netip.MustParseAddr("10.10.0.1")},
		{"ipv6", netip.MustParseAddr("fd00::1")},
		{"multicast", netip.MustParseAddr("224.0.0.1")},
		{"broadcast", netip.MustParseAddr("10.9.0.255")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := h.service.SetOwnedVirtualIP(testCase.address); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("SetOwnedVirtualIP(%s) error %v, want ErrInvalidConfig", testCase.address, err)
			}
		})
	}
	if err := h.service.SetOwnedVirtualIP(netip.MustParseAddr("10.9.0.5")); err != nil {
		t.Fatalf("valid SetOwnedVirtualIP: %v", err)
	}
	if got := h.service.OwnedVirtualIP(); got != netip.MustParseAddr("10.9.0.5") {
		t.Fatalf("OwnedVirtualIP = %s", got)
	}
}

func TestRuntimeMTUDownAdjustIsObserved(t *testing.T) {
	h := newHarness(t, nil)
	raw := testIPv4(h.vip, h.remote, 17, 64, 0, 0, nil, make([]byte, 1200-ipv4MinHeaderLen))
	if len(raw) != 1200 {
		t.Fatalf("test packet is %d bytes, want 1200", len(raw))
	}

	h.device.mtu = 1000
	if got := h.service.MTU(); got != 1000 {
		t.Fatalf("MTU() = %d after the runtime down-adjust, want 1000", got)
	}
	h.assertDropped(h.service.Send(context.Background(), raw), ErrPacketTooLarge, DropTooLarge)

	h.device.mtu = DefaultDeviceMTU * 4
	if got := h.service.MTU(); got != DefaultDeviceMTU {
		t.Fatalf("MTU() = %d above the frozen ceiling, want %d", got, DefaultDeviceMTU)
	}
	if err := h.service.Send(context.Background(), raw); err != nil {
		t.Fatalf("Send under the clamped ceiling: %v", err)
	}
}

func TestConcurrentSendAndReceive(t *testing.T) {
	h := newHarness(t, nil)
	sendPacket := testIPv4(h.vip, h.remote, 17, 64, ipv4FlagDontFrag, 0, nil, []byte("load"))
	receivePacket := testIPv4(h.remote, h.vip, 17, 64, 0, 0, nil, []byte("load"))

	const workers = 32
	const iterations = 25
	var wait sync.WaitGroup
	wait.Add(workers * 2)
	for index := 0; index < workers; index++ {
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				if err := h.service.Send(context.Background(), sendPacket); err != nil {
					t.Errorf("Send: %v", err)
					return
				}
			}
		}()
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				if err := h.service.Receive(context.Background(), h.remoteNode, h.localNode, receivePacket); err != nil {
					t.Errorf("Receive: %v", err)
					return
				}
			}
		}()
	}
	wait.Wait()
	stats := h.service.Stats()
	if stats.Sent != workers*iterations || stats.Received != workers*iterations {
		t.Fatalf("sent/received = %d/%d, want %d/%d", stats.Sent, stats.Received, workers*iterations, workers*iterations)
	}
	if stats.Dropped != 0 {
		t.Fatalf("dropped = %d, want 0", stats.Dropped)
	}
}
