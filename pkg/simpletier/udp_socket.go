package simpletier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/flow"
	"github.com/yiiilin/simpletier/internal/topology"
)

// The public virtual UDP plane. Network.ListenPacket("udp", ownVIP:port) returns
// a net.PacketConn whose ReadFrom/WriteTo exchange complete UDP datagrams with
// peers inside the overlay over the same class-1 Flow/PACKET lane machinery as
// every other Flow datagram. No OS UDP socket is ever created towards a target,
// no host device is opened and no gateway is used: the only egress is the
// authenticated Flow path.
//
// Two delivery shapes share one runtime multiplexer:
//
//   - a target endpoint (ListenPacket socket or the Agent's SOCKS5 UDP
//     association) receives complete REQUESTs routed by the virtual destination
//     port;
//   - an origin association (outbound SDK WriteTo, Agent SOCKS5 UDP egress)
//     receives REPLYs routed by the exact AssociationID it created.
//
// A socket answering a peer it actually received from calls flow.Manager.Reply
// with the opaque receipt carried by the delivered datagram, so the reply reuses
// that exact target association and cannot forge authority or re-target a
// changed address. A socket sending a new datagram creates (at most one) origin
// association of its own.
const (
	// udpSocketInboxFrames bounds one endpoint's inbox depth. A full inbox drops
	// and counts instead of blocking the Flow delivery call, and never spawns a
	// goroutine per datagram.
	udpSocketInboxFrames = 32
	// udpInboxMetadataBytes is the per-datagram metadata charge booked on top of
	// the payload bytes, so a zero-length datagram still accounts for its queued
	// cell instead of being free.
	udpInboxMetadataBytes = 64
	// udpReplyTupleLimit bounds the retained reply tuples of one socket. The
	// tuple map is what turns a ReadFrom peer into a same-association Reply.
	udpReplyTupleLimit = 64
	// udpReplyTupleTTL bounds how long a retained reply tuple may be spent. It
	// matches the Flow target association idle window: a tuple older than the
	// association could only produce a refused reply.
	udpReplyTupleTTL = 120 * time.Second
	// udpSourcePortFirst is the first dynamic local source port handed to an
	// origin association that owns no explicit virtual listener.
	udpSourcePortFirst = 40000
	// udpSendPeerLimit bounds the remembered send destinations of one origin
	// association, so a reply is only accepted from a peer this association
	// actually sent to. It matches the Flow per-association peer cap.
	udpSendPeerLimit = flow.MaxPeersPerAssociation
)

// udpAddr is the net.Addr identity of one virtual UDP endpoint. It carries the
// real overlay IPv4 address and port, never a wildcard.
type udpAddr struct{ addr netip.AddrPort }

func (a udpAddr) Network() string { return "udp" }

func (a udpAddr) String() string {
	if !a.addr.IsValid() {
		return ""
	}
	return a.addr.String()
}

// udpDestination converts one caller-supplied net.Addr into a definite IPv4
// virtual endpoint. Only a concrete IPv4 address inside the overlay CIDR is
// accepted; a wildcard, IPv6, unparseable or out-of-overlay address is refused
// before any route or fragment work.
func udpDestination(addr net.Addr) (netip.AddrPort, error) {
	if addr == nil {
		return netip.AddrPort{}, invalidConfig("udp.address", "must not be nil")
	}
	switch typed := addr.(type) {
	case udpAddr:
		if typed.addr.Port() == 0 {
			return netip.AddrPort{}, invalidConfig("udp.address", "port must be in range 1..65535")
		}
		return typed.addr, nil
	case *net.UDPAddr:
		if typed == nil || typed.IP == nil {
			return netip.AddrPort{}, invalidConfig("udp.address", "must be an IPv4 address and port")
		}
		// Reject an out-of-range port BEFORE the uint16 conversion: -1 would
		// become 65535 and 65537 would become 1, silently retargeting the
		// datagram to a different virtual endpoint.
		if typed.Port <= 0 || typed.Port > 65535 {
			return netip.AddrPort{}, invalidConfig("udp.address", "port must be in range 1..65535")
		}
		ip, ok := netip.AddrFromSlice(typed.IP)
		if !ok {
			return netip.AddrPort{}, invalidConfig("udp.address", "must be an IPv4 address and port")
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(typed.Port)), nil
	}
	parsed, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}, invalidConfig("udp.address", "must be an IPv4 address and port")
	}
	if parsed.Port() == 0 {
		return netip.AddrPort{}, invalidConfig("udp.address", "port must be in range 1..65535")
	}
	return netip.AddrPortFrom(parsed.Addr().Unmap(), parsed.Port()), nil
}

// udpRequestSink receives one complete inbound REQUEST datagram addressed to a
// virtual port this endpoint bound.
type udpRequestSink interface {
	deliverRequest(datagram flow.Datagram)
}

// udpReplySink receives one complete inbound REPLY datagram for the exact
// association it created.
type udpReplySink interface {
	deliverReply(datagram flow.Datagram)
}

// udpPeerTracker remembers the destinations one origin association sent to, so
// an inbound REPLY is only accepted from a peer that association actually
// talked to.
type udpPeerTracker struct {
	mu    sync.Mutex
	peers map[netip.AddrPort]struct{}
}

func (p *udpPeerTracker) note(peer netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.peers == nil {
		p.peers = make(map[netip.AddrPort]struct{})
	}
	if len(p.peers) >= udpSendPeerLimit {
		if _, exists := p.peers[peer]; !exists {
			return
		}
	}
	p.peers[peer] = struct{}{}
}

func (p *udpPeerTracker) includes(peer netip.AddrPort) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.peers[peer]
	return ok
}

// udpMux is the single runtime delivery multiplexer of the UDP plane. It is
// created once per streamRuntime and installed as the Flow plane's Delivery, so
// a public ListenPacket socket and the Agent SOCKS5 UDP backend share exactly
// one routing table instead of racing to install two deliveries.
type udpMux struct {
	rt     *streamRuntime
	budget *flowBufferBudget

	mu       sync.Mutex
	closed   bool
	requests map[uint16]udpRequestSink
	origins  map[flow.AssocID]udpReplySink
	reserved map[uint16]struct{}
	nextPort uint16

	droppedNoSink  atomic.Uint64
	droppedFull    atomic.Uint64
	droppedBudget  atomic.Uint64
	droppedForeign atomic.Uint64
}

func newUDPMux(rt *streamRuntime) *udpMux {
	mux := &udpMux{
		rt:       rt,
		requests: make(map[uint16]udpRequestSink),
		origins:  make(map[flow.AssocID]udpReplySink),
		reserved: make(map[uint16]struct{}),
		nextPort: udpSourcePortFirst,
	}
	var allocator *budget.Allocator
	var networkID budget.NetworkID
	if rt != nil {
		allocator = rt.budgets
		networkID = budget.NetworkID(rt.wireID)
	}
	// A nil allocator keeps the byte-only adapter self-bound and unaccounted,
	// which is what a runtime under test with no shared budget expects.
	mux.budget = newFlowBufferBudget(allocator, networkID)
	return mux
}

// DeliverDatagram implements flow.Delivery. It routes one complete datagram to
// the endpoint that owns it. An unowned datagram is counted and dropped, never
// answered: an unregistered virtual port has no local listener.
func (m *udpMux) DeliverDatagram(_ context.Context, datagram flow.Datagram) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	var request udpRequestSink
	var reply udpReplySink
	if datagram.Flags == flow.FlagReply {
		reply = m.origins[datagram.AssociationID]
	} else {
		request = m.requests[datagram.Destination.Port()]
	}
	m.mu.Unlock()
	if reply != nil {
		reply.deliverReply(datagram)
		return nil
	}
	if request != nil {
		request.deliverRequest(datagram)
		return nil
	}
	m.droppedNoSink.Add(1)
	return nil
}

// bindPort reserves one virtual UDP port for a request endpoint. It refuses a
// port already bound or already reserved as an association source port with
// ErrBusy. TCP and UDP keep separate namespaces, so the same numeric port may be
// a TCP listener and a UDP socket.
func (m *udpMux) bindPort(port uint16, sink udpRequestSink) error {
	if m == nil || sink == nil || port == 0 {
		return invalidConfig("udp.port", "must be in range 1..65535")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	if _, exists := m.requests[port]; exists {
		return ErrBusy
	}
	if _, exists := m.reserved[port]; exists {
		return ErrBusy
	}
	m.requests[port] = sink
	return nil
}

func (m *udpMux) unbindPort(port uint16, sink udpRequestSink) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.requests[port] == sink {
		delete(m.requests, port)
	}
	m.mu.Unlock()
}

// allocateSourcePort reserves one unique local source port for an origin
// association that has no explicit virtual listener.
func (m *udpMux) allocateSourcePort() (uint16, error) {
	if m == nil {
		return 0, ErrClosed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.allocateSourcePortLocked()
}

func (m *udpMux) allocateSourcePortLocked() (uint16, error) {
	if m.closed {
		return 0, ErrClosed
	}
	for attempts := 0; attempts < 1<<16; attempts++ {
		port := m.nextPort
		m.nextPort++
		if m.nextPort < udpSourcePortFirst {
			m.nextPort = udpSourcePortFirst
		}
		if port < udpSourcePortFirst {
			continue
		}
		if _, exists := m.requests[port]; exists {
			continue
		}
		if _, exists := m.reserved[port]; exists {
			continue
		}
		m.reserved[port] = struct{}{}
		return port, nil
	}
	return 0, ErrResource
}

// reserveOrigin reserves a source port and registers the origin association
// sink in one critical section, so the port a channel reports can never be
// claimed by another channel between the two steps.
func (m *udpMux) reserveOrigin(id flow.AssocID, sink udpReplySink) (uint16, error) {
	if m == nil || sink == nil {
		return 0, ErrClosed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	port, err := m.allocateSourcePortLocked()
	if err != nil {
		return 0, err
	}
	if _, exists := m.origins[id]; exists {
		delete(m.reserved, port)
		return 0, ErrResource
	}
	m.origins[id] = sink
	return port, nil
}

// registerOrigin registers an origin sink that already owns a bound virtual
// port (a public ListenPacket socket sending its own REQUESTs).
func (m *udpMux) registerOrigin(id flow.AssocID, sink udpReplySink) error {
	if m == nil || sink == nil {
		return ErrClosed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	if _, exists := m.origins[id]; exists {
		return ErrResource
	}
	m.origins[id] = sink
	return nil
}

func (m *udpMux) unregisterOrigin(id flow.AssocID, sink udpReplySink) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.origins[id] == sink {
		delete(m.origins, id)
	}
	m.mu.Unlock()
}

// releasePort returns one reserved source port to the namespace.
func (m *udpMux) releasePort(port uint16) {
	if m == nil || port == 0 {
		return
	}
	m.mu.Lock()
	delete(m.reserved, port)
	m.mu.Unlock()
}

// close releases every endpoint. It is idempotent and unblocks every pending
// ReadFrom/WriteTo through the endpoint's own done channel.
func (m *udpMux) close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	requests := make([]udpRequestSink, 0, len(m.requests))
	for _, sink := range m.requests {
		requests = append(requests, sink)
	}
	m.requests = make(map[uint16]udpRequestSink)
	m.origins = make(map[flow.AssocID]udpReplySink)
	m.reserved = make(map[uint16]struct{})
	budgetPort := m.budget
	m.budget = nil
	m.mu.Unlock()
	for _, sink := range requests {
		if socket, ok := sink.(*udpSocket); ok {
			_ = socket.Close()
		}
	}
	if budgetPort != nil {
		budgetPort.Close()
	}
}

// reserveInbox charges one inbound datagram inside the Network allocator before
// its payload is copied. A failed reservation drops the datagram and is counted
// by the caller.
func (m *udpMux) reserveInbox(bytes uint64) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	budgetPort := m.budget
	closed := m.closed
	m.mu.Unlock()
	if closed || budgetPort == nil {
		return false
	}
	return budgetPort.Reserve(bytes) == nil
}

func (m *udpMux) releaseInbox(bytes uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	budgetPort := m.budget
	m.mu.Unlock()
	if budgetPort != nil {
		budgetPort.Release(bytes)
	}
}

// udpDeadline is the read/write deadline state of one virtual UDP socket. A
// SetDeadline bumps a generation and closes the wake channel so an in-flight
// wait re-reads the new value instead of sleeping on the old one.
type udpDeadline struct {
	mu        sync.Mutex
	readDL    time.Time
	writeDL   time.Time
	readGen   uint64
	writeGen  uint64
	readWake  chan struct{}
	writeWake chan struct{}
}

func newUDPDeadline() *udpDeadline {
	return &udpDeadline{readWake: make(chan struct{}), writeWake: make(chan struct{})}
}

// netPacketConnSetDL installs one deadline value on the read and/or write side.
// It is the net.PacketConn analogue of circuitStream.SetDeadline and cancels any
// in-flight wait exactly once.
func netPacketConnSetDL(deadline *udpDeadline, read, write bool, value time.Time) {
	if deadline == nil {
		return
	}
	deadline.mu.Lock()
	defer deadline.mu.Unlock()
	if read {
		deadline.readDL = value
		deadline.readGen++
		close(deadline.readWake)
		deadline.readWake = make(chan struct{})
	}
	if write {
		deadline.writeDL = value
		deadline.writeGen++
		close(deadline.writeWake)
		deadline.writeWake = make(chan struct{})
	}
}

func (d *udpDeadline) readState() (time.Time, uint64, chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.readDL, d.readGen, d.readWake
}

func (d *udpDeadline) writeValue() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.writeDL
}

// udpInboxItem is one queued inbound datagram plus the exact budget charge held
// for its copied payload.
type udpInboxItem struct {
	datagram flow.Datagram
	payload  []byte
	charge   uint64
}

// udpReplyTuple is one retained reply capability keyed by the peer it answers.
type udpReplyTuple struct {
	datagram flow.Datagram
	at       time.Time
}

// udpSocket is one public virtual UDP endpoint. It implements net.PacketConn and
// reads/writes only complete datagrams on the overlay.
type udpSocket struct {
	rt    *streamRuntime
	mux   *udpMux
	local netip.AddrPort

	inbox  chan udpInboxItem
	done   chan struct{}
	closed atomic.Bool
	once   sync.Once
	peers  udpPeerTracker
	dead   *udpDeadline

	mu         sync.Mutex
	origin     *flow.Association
	replies    map[netip.AddrPort]udpReplyTuple
	replyOrder []netip.AddrPort
	closeErr   error
}

func newUDPSocket(rt *streamRuntime, mux *udpMux, local netip.AddrPort) *udpSocket {
	return &udpSocket{
		rt:      rt,
		mux:     mux,
		local:   local,
		inbox:   make(chan udpInboxItem, udpSocketInboxFrames),
		done:    make(chan struct{}),
		replies: make(map[netip.AddrPort]udpReplyTuple),
		dead:    newUDPDeadline(),
	}
}

// LocalAddr returns the bound virtual endpoint.
func (s *udpSocket) LocalAddr() net.Addr { return udpAddr{addr: s.local} }

// ReadFrom returns one complete datagram and the real overlay peer it came from.
// It honors the read deadline and is unblocked by Close, by Network.Close and by
// Agent.Close.
func (s *udpSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	if s == nil {
		return 0, nil, ErrClosed
	}
	for {
		if s.closed.Load() {
			return 0, nil, ErrClosed
		}
		deadline, _, wake := s.dead.readState()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, nil, ErrDeadline
			}
			timer = time.NewTimer(remaining)
			timeout = timer.C
		}
		select {
		case <-s.done:
			stopUDPTimer(timer)
			return 0, nil, ErrClosed
		case <-wake:
			stopUDPTimer(timer)
			continue
		case <-timeout:
			return 0, nil, ErrDeadline
		case item := <-s.inbox:
			stopUDPTimer(timer)
			s.mux.releaseInbox(item.charge)
			if s.closed.Load() {
				return 0, nil, ErrClosed
			}
			n := copy(p, item.payload)
			return n, udpAddr{addr: item.datagram.Source}, nil
		}
	}
}

func stopUDPTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

// WriteTo sends one complete datagram. A destination that is an exact peer this
// socket actually received a reply-capable REQUEST from spends that receipt
// through flow.Manager.Reply on the same target association; any other live
// virtual IPv4 destination goes through this socket's own origin association.
func (s *udpSocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	if s == nil {
		return 0, ErrClosed
	}
	if s.closed.Load() {
		return 0, ErrClosed
	}
	if len(p) > flow.MaxDatagramPayload {
		return 0, fmt.Errorf("%w: %d bytes exceeds the %d-byte IPv4 UDP limit", flow.ErrDatagramTooLarge, len(p), flow.MaxDatagramPayload)
	}
	destination, err := udpDestination(addr)
	if err != nil {
		return 0, err
	}
	if err := s.validateVirtualDestination(destination); err != nil {
		return 0, err
	}
	ctx, cancel, deadlineBound := s.writeContext()
	defer cancel()
	if retained, ok := s.replyFor(destination); ok {
		if err := s.rt.replyDatagram(ctx, retained, p); err != nil {
			return 0, s.mapWriteError(mapUDPFlowError(err), deadlineBound)
		}
		return len(p), nil
	}
	association, err := s.originAssociation()
	if err != nil {
		return 0, mapUDPFlowError(err)
	}
	if err := association.Fragment(ctx, flow.OutboundDatagram{
		Source:      s.local,
		Destination: destination,
		Payload:     p,
	}); err != nil {
		return 0, s.mapWriteError(mapUDPFlowError(err), deadlineBound)
	}
	s.peers.note(destination)
	return len(p), nil
}

// validateVirtualDestination enforces the overlay-only egress policy: only an
// IPv4 address inside the configured virtual CIDR that currently has a single
// address-fact owner may be written to. No public, LAN or gateway destination is
// ever selected.
func (s *udpSocket) validateVirtualDestination(destination netip.AddrPort) error {
	if !destination.IsValid() || !destination.Addr().Is4() || destination.Port() == 0 {
		return fmt.Errorf("%w: destination must be an IPv4 virtual address and port", ErrNoRoute)
	}
	n := s.rt.n
	if n == nil || !n.normalized.networkPrefix.Contains(destination.Addr()) {
		return fmt.Errorf("%w: destination %s is outside the overlay CIDR", ErrPermissionDenied, destination)
	}
	if n.facts == nil || n.facts.routes == nil {
		return ErrNoRoute
	}
	if _, err := n.facts.routes.ResolveVirtualIP(destination.Addr()); err != nil {
		return mapUDPFlowError(fmt.Errorf("%w: %v", ErrNoRoute, err))
	}
	return nil
}

func (s *udpSocket) writeContext() (context.Context, context.CancelFunc, bool) {
	base := context.Background()
	if s.rt != nil && s.rt.n != nil && s.rt.n.ctx != nil {
		base = s.rt.n.ctx
	}
	deadline := s.dead.writeValue()
	if deadline.IsZero() {
		ctx, cancel := context.WithCancel(base)
		return ctx, cancel, false
	}
	if remaining := time.Until(deadline); remaining > 0 {
		ctx, cancel := context.WithTimeout(base, remaining)
		return ctx, cancel, true
	}
	ctx, cancel := context.WithCancel(base)
	cancel()
	return ctx, func() {}, true
}

// mapUDPFlowError translates the Flow/topology sentinels a UDP egress can
// surface into the public SDK identities. It joins the public sentinel with the
// original error, so errors.Is matches both the SDK identity and the underlying
// cause instead of leaking an undocumented internal error to an SDK caller.
func mapUDPFlowError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, topology.ErrNoRoute):
		return fmt.Errorf("%w: %w", ErrNoRoute, err)
	case errors.Is(err, topology.ErrRouteStale), errors.Is(err, flow.ErrRouteChanged):
		return fmt.Errorf("%w: %w", ErrRouteStale, err)
	case errors.Is(err, topology.ErrResourceLimit), errors.Is(err, flow.ErrResourceLimit):
		return fmt.Errorf("%w: %w", ErrResource, err)
	case errors.Is(err, flow.ErrClosed):
		return fmt.Errorf("%w: %w", ErrClosed, err)
	}
	return err
}

func (s *udpSocket) mapWriteError(err error, deadlineBound bool) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) && deadlineBound {
		return ErrDeadline
	}
	if errors.Is(err, context.Canceled) && s.closed.Load() {
		return ErrClosed
	}
	return err
}

// originAssociation returns this socket's single origin association, creating it
// on first outbound use. The Flow plane itself bounds the total per Network.
func (s *udpSocket) originAssociation() (*flow.Association, error) {
	s.mu.Lock()
	if s.origin != nil {
		association := s.origin
		s.mu.Unlock()
		return association, nil
	}
	s.mu.Unlock()
	association, err := s.rt.createOriginAssociation(s)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.origin != nil {
		existing := s.origin
		s.mu.Unlock()
		s.rt.discardOriginAssociation(association, s)
		return existing, nil
	}
	if s.closed.Load() {
		s.mu.Unlock()
		s.rt.discardOriginAssociation(association, s)
		return nil, ErrClosed
	}
	s.origin = association
	s.mu.Unlock()
	return association, nil
}

// deliverRequest queues one authenticated REQUEST addressed to this socket. The
// payload is charged inside the shared allocator and copied only after the
// reservation succeeds; a full inbox drops and counts instead of blocking.
func (s *udpSocket) deliverRequest(datagram flow.Datagram) {
	if s == nil || s.closed.Load() {
		return
	}
	if datagram.Destination != s.local {
		s.mux.droppedForeign.Add(1)
		return
	}
	charge := uint64(len(datagram.Payload)) + udpInboxMetadataBytes
	if !s.mux.reserveInbox(charge) {
		s.mux.droppedBudget.Add(1)
		return
	}
	payload := append([]byte(nil), datagram.Payload...)
	item := udpInboxItem{datagram: datagram, payload: payload, charge: charge}
	item.datagram.Payload = payload
	select {
	case s.inbox <- item:
		s.noteReplyTuple(item.datagram)
	case <-s.done:
		s.mux.releaseInbox(charge)
		return
	default:
		s.mux.releaseInbox(charge)
		s.mux.droppedFull.Add(1)
	}
}

// deliverReply queues one REPLY for this socket's origin association. Only a
// REPLY for that exact association, addressed to this socket's own virtual
// endpoint and sourced by a peer this socket sent to, is accepted.
func (s *udpSocket) deliverReply(datagram flow.Datagram) {
	if s == nil || s.closed.Load() {
		return
	}
	if datagram.Flags != flow.FlagReply {
		s.mux.droppedForeign.Add(1)
		return
	}
	s.mu.Lock()
	association := s.origin
	s.mu.Unlock()
	if association == nil || datagram.AssociationID != association.ID() {
		s.mux.droppedForeign.Add(1)
		return
	}
	if datagram.Destination != s.local {
		s.mux.droppedForeign.Add(1)
		return
	}
	if !s.peers.includes(datagram.Source) {
		s.mux.droppedForeign.Add(1)
		return
	}
	charge := uint64(len(datagram.Payload)) + udpInboxMetadataBytes
	if !s.mux.reserveInbox(charge) {
		s.mux.droppedBudget.Add(1)
		return
	}
	payload := append([]byte(nil), datagram.Payload...)
	item := udpInboxItem{datagram: datagram, payload: payload, charge: charge}
	item.datagram.Payload = payload
	select {
	case s.inbox <- item:
	case <-s.done:
		s.mux.releaseInbox(charge)
	default:
		s.mux.releaseInbox(charge)
		s.mux.droppedFull.Add(1)
	}
}

// noteReplyTuple retains the reply capability of one delivered REQUEST keyed by
// the exact peer tuple. The map is bounded and evicts oldest-first.
func (s *udpSocket) noteReplyTuple(datagram flow.Datagram) {
	if datagram.Flags != flow.FlagRequest {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replies[datagram.Source] = udpReplyTuple{datagram: datagram, at: now}
	for index, existing := range s.replyOrder {
		if existing == datagram.Source {
			s.replyOrder = append(s.replyOrder[:index], s.replyOrder[index+1:]...)
			break
		}
	}
	s.replyOrder = append(s.replyOrder, datagram.Source)
	for len(s.replyOrder) > udpReplyTupleLimit {
		oldest := s.replyOrder[0]
		s.replyOrder = s.replyOrder[1:]
		delete(s.replies, oldest)
	}
}

// replyFor returns the retained reply capability for one exact peer tuple. An
// entry older than the association idle window is discarded rather than spent.
func (s *udpSocket) replyFor(peer netip.AddrPort) (flow.Datagram, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.replies[peer]
	if !ok {
		return flow.Datagram{}, false
	}
	if time.Since(entry.at) > udpReplyTupleTTL {
		delete(s.replies, peer)
		return flow.Datagram{}, false
	}
	return entry.datagram, true
}

func (s *udpSocket) SetDeadline(t time.Time) error {
	if s == nil {
		return ErrClosed
	}
	netPacketConnSetDL(s.dead, true, true, t)
	return nil
}

func (s *udpSocket) SetReadDeadline(t time.Time) error {
	if s == nil {
		return ErrClosed
	}
	netPacketConnSetDL(s.dead, true, false, t)
	return nil
}

func (s *udpSocket) SetWriteDeadline(t time.Time) error {
	if s == nil {
		return ErrClosed
	}
	netPacketConnSetDL(s.dead, false, true, t)
	return nil
}

// Close unregisters the virtual port and origin association, closes the Flow
// association, releases every held budget charge and unblocks ReadFrom/WriteTo
// exactly once.
func (s *udpSocket) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		s.closed.Store(true)
		close(s.done)
		s.mux.unbindPort(s.local.Port(), s)
		s.mu.Lock()
		association := s.origin
		s.origin = nil
		s.replies = make(map[netip.AddrPort]udpReplyTuple)
		s.replyOrder = nil
		s.mu.Unlock()
		if association != nil {
			s.mux.unregisterOrigin(association.ID(), s)
			s.closeErr = association.Close()
		}
		for {
			select {
			case item := <-s.inbox:
				s.mux.releaseInbox(item.charge)
				continue
			default:
			}
			break
		}
	})
	return s.closeErr
}

var _ net.PacketConn = (*udpSocket)(nil)

// ListenPacket binds one virtual UDP endpoint on this Network's own VirtualIP
// and returns a net.PacketConn over the overlay Flow plane. It shares the UDP
// port namespace with other UDP sockets, refuses a duplicate with ErrBusy, and
// never collides with the TCP listener namespace.
func (n *network) ListenPacket(networkName, address string) (net.PacketConn, error) {
	if networkName != "udp" && networkName != "udp4" {
		return nil, invalidConfig("network", "only udp is supported")
	}
	if n == nil || n.isClosed() {
		return nil, ErrClosed
	}
	localIP := n.localVirtualIP()
	if !localIP.IsValid() {
		return nil, ErrLinkDown
	}
	addr, err := parseListenAddress(address, localIP)
	if err != nil {
		return nil, err
	}
	if addr.Addr() != localIP {
		return nil, ErrPermissionDenied
	}
	mux, err := n.streams.ensureUDPFlow()
	if err != nil {
		return nil, err
	}
	socket := newUDPSocket(n.streams, mux, addr)
	if err := mux.bindPort(addr.Port(), socket); err != nil {
		return nil, err
	}
	if n.isClosed() {
		_ = socket.Close()
		return nil, ErrClosed
	}
	return socket, nil
}

// ensureUDPFlow installs the Flow plane with this runtime's single shared UDP
// mux as its Delivery, creating the mux on first use. A runtime whose Flow plane
// is already owned by a different Delivery fails closed instead of silently
// routing nothing.
func (rt *streamRuntime) ensureUDPFlow() (*udpMux, error) {
	if rt == nil || rt.n == nil {
		return nil, ErrClosed
	}
	mux := rt.udpMuxInstance()
	if mux == nil {
		return nil, ErrClosed
	}
	if err := rt.installUDPFlow(mux); err != nil {
		return nil, err
	}
	return mux, nil
}

// udpMuxInstance returns the runtime's shared mux, creating it under rt.mu.
func (rt *streamRuntime) udpMuxInstance() *udpMux {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return nil
	}
	if rt.udpMux == nil {
		rt.udpMux = newUDPMux(rt)
	}
	return rt.udpMux
}

// installUDPFlow installs the flow plane with mux when none is installed yet,
// and is idempotent when the installed delivery already is that mux.
func (rt *streamRuntime) installUDPFlow(mux *udpMux) error {
	if mux == nil {
		return ErrClosed
	}
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return ErrClosed
	}
	if rt.flow != nil {
		installed := rt.flowDelivery == flow.Delivery(mux)
		rt.mu.Unlock()
		if installed {
			return nil
		}
		return ErrResource
	}
	rt.mu.Unlock()
	if err := rt.enableFlowService(mux); err != nil {
		if !errors.Is(err, ErrResource) {
			return err
		}
		rt.mu.Lock()
		installed := rt.flow != nil && rt.flowDelivery == flow.Delivery(mux)
		rt.mu.Unlock()
		if installed {
			return nil
		}
		return err
	}
	return nil
}

// createOriginAssociation creates one origin association and registers it in the
// shared mux under its exact AssociationID.
func (rt *streamRuntime) createOriginAssociation(sink udpReplySink) (*flow.Association, error) {
	mux, err := rt.ensureUDPFlow()
	if err != nil {
		return nil, err
	}
	manager := rt.flowManager()
	if manager == nil {
		return nil, ErrClosed
	}
	association, err := manager.CreateAssociation()
	if err != nil {
		return nil, err
	}
	if err := mux.registerOrigin(association.ID(), sink); err != nil {
		_ = association.Close()
		return nil, err
	}
	return association, nil
}

func (rt *streamRuntime) discardOriginAssociation(association *flow.Association, sink udpReplySink) {
	if association == nil {
		return
	}
	rt.mu.Lock()
	mux := rt.udpMux
	rt.mu.Unlock()
	if mux != nil {
		mux.unregisterOrigin(association.ID(), sink)
	}
	_ = association.Close()
}

// replyDatagram spends one delivered REQUEST's opaque receipt through the Flow
// plane's only reply entry point. It never creates an association.
func (rt *streamRuntime) replyDatagram(ctx context.Context, received flow.Datagram, payload []byte) error {
	manager := rt.flowManager()
	if manager == nil {
		return ErrClosed
	}
	return manager.Reply(ctx, received, payload)
}

func (rt *streamRuntime) flowManager() *flow.Manager {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.flow
}
