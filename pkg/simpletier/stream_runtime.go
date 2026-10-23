package simpletier

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/circuit"
	"github.com/yiiilin/simpletier/internal/flow"
	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/session"
	"github.com/yiiilin/simpletier/internal/topology"
	"github.com/yiiilin/simpletier/internal/wire"
)

// The P1 data plane binds one authenticated Path to one Session (Noise_IKpsk2)
// and carries Circuits on the separate STREAM Lane. Bootstrap ROUTE_CTRL frames
// (PATH_*/SESSION_*) travel hop by hop over the CONTROL adjacency; business
// frames are inner-AEAD protected once by the endpoint pair and outer-AEAD
// protected per hop on the dedicated STREAM links. A relay hop only ever
// decrypts its own hop ciphertext (for ROUTE_CTRL bootstrap) and forwards opaque
// E2E ciphertext without touching the inner layer.
const (
	// defaultHopBudgetMicros is the initial remaining hop budget of a Path. A
	// relay only ever subtracts measured elapsed microseconds; the budget is
	// never refilled per hop.
	defaultHopBudgetMicros = 30_000_000
	// overlayHopLimit is the frozen Path hop ceiling (2..16 nodes).
	overlayHopLimit = 16
	// pendingSessionFrames bounds the reorder buffer that holds already
	// hop-authenticated inner ciphertext until the local Session commits its
	// READY. The authoritative byte budget is the frozen per-Session
	// session.MaxPendingBytes reservation; this count is only a secondary bound.
	pendingSessionFrames = 64
)

// traceDataPlane emits one phase-only data-plane diagnostic. It never logs key
// material, ciphertext or peer payload bytes, so a failing acceptance test can
// be followed step by step without leaking secrets.
func traceDataPlane(msg string, args ...any) {
	slog.Default().Debug("data plane: "+msg, args...)
}

// pathScope is the (PathID, Generation) key shared by Path, Session and Circuit.
type pathScope struct {
	id  uint64
	gen uint32
}

// pathState is the local view of one installed Path generation. The source and
// target own a path.Manager record; a relay hop owns only this forwarding entry.
type pathState struct {
	scope       pathScope
	lane        path.Lane
	nodes       []topology.NodeID
	links       []topology.LinkRef
	digest      [32]byte
	viewVersion uint64
	localIndex  int
	source      bool
	handle      path.Path

	readyOnce sync.Once
	ready     chan struct{}
	broken    atomic.Bool

	// budget is the remaining hop budget in microseconds. A source path seeds it
	// from min(the caller's remaining deadline, the 30s ceiling); a relay or
	// target seeds it from the received hop header. It only ever decreases.
	budget uint32

	// Relay forwarding state. inCtrl is the CONTROL pump the frame arrived on.
	// The hop budget is metered per forwarded frame (forwardElapsedMicros), not
	// accumulated across a Ready path's idle time.
	inCtrl *controlPump
	// relay marks a rootless intermediate-hop path: this node owns no path
	// handle, Session root or E2E protector for it, and only forwards.
	relay bool
	// relayPending records that the reverse PATH_READY passed through, so this
	// hop knows the target accepted the path.
	relayPending atomic.Bool
}

func (ps *pathState) dstIndex() int {
	if ps.localIndex == 0 {
		return len(ps.nodes) - 1
	}
	return 0
}

func (ps *pathState) hopIndexToward(dstIndex int) int {
	if dstIndex > ps.localIndex {
		return ps.localIndex + 1
	}
	return ps.localIndex - 1
}

func (ps *pathState) signalReady() {
	ps.readyOnce.Do(func() { close(ps.ready) })
}

// sessionEntry binds one committed or pending Session to its directional E2E
// protectors. src/dst are always the canonical logical Path endpoints
// (source/target), never the physical neighbour; the wire envelope swaps them
// per direction.
type sessionEntry struct {
	id        session.SessionID
	scope     pathScope
	class     session.SessionClass
	lane      session.Lane
	src, dst  [16]byte
	initiator bool
	// attempt/targetEpoch are the frozen handshake identity of this session
	// (initiator: 0/1; responder: as received). They are captured once so a
	// committed Session whose cached attempt bytes were released can still
	// encode the symmetric SESSION_READY.
	attempt     uint32
	targetEpoch uint32
	sess        *session.Session
	// peerStatic is the authenticated X25519 static key of the logical peer this
	// Session was bound to at establishment. A later query that resolves a
	// different key for the same node invalidates the pinned Path/Session rather
	// than silently continuing against a re-keyed identity.
	peerStatic [32]byte
	// relay marks a rootless intermediate-hop session record: the relay holds no
	// Session object, root or E2E protector, admits the keyless hop session on
	// both adjacent STREAM Links and only forwards opaque ciphertext in order.
	relay bool

	protMu sync.Mutex
	tx     *session.E2EProtector
	rx     *session.E2EProtector
	// installedEpoch is the KeyEpoch the current tx/rx pair was installed with.
	// It is written under protMu+txMu by the install path and read under protMu;
	// it is the authoritative committed installed epoch the envelope builders
	// stamp, never a hardcoded 1.
	installedEpoch uint32

	// txMu is the single E2E egress sequence owner of this (session, direction)
	// domain: it allocates MessageNumber, seals the inner AEAD and orders the
	// resulting frame ahead of any later frame of the same session.
	txMu     sync.Mutex
	txNumber uint64

	// rekeyMu guards the source-driven rekey staging of this entry. rekeyPending
	// marks exactly one coalesced next attempt in flight; rekeyAttempt/rekeyEpoch
	// are that attempt's frozen identity. deferredEpoch/deferredRoot hold a
	// committed epoch whose protector install was refused with ErrEpochRetained
	// (the frozen 30s third-install grace) so a later poll can complete it
	// without dropping the old key or mutating either protector early.
	//
	// deferredDeadline is the one bounded window of that deferral: it is stamped
	// when the deferral is first recorded and NEVER refreshed by a retry, so a
	// committed epoch whose install can never legally complete (the retained
	// previous epoch's grace clock never started) fails this one Session scoped
	// after one frozen epoch-grace budget instead of deferring forever.
	rekeyMu          sync.Mutex
	rekeyPending     bool
	rekeyAttempt     uint32
	rekeyEpoch       uint32
	rekeySent        time.Time
	deferredEpoch    uint32
	deferredRoot     []byte
	deferredDeadline time.Time

	// relayEpoch is the highest KeyEpoch whose matching SESSION_READY has
	// committed forwarding on a rootless relay entry. Ciphertext of a later
	// epoch is staged opaquely (bounded) until that READY arrives; older epoch
	// ciphertext keeps flowing so established business is never interrupted. It
	// is guarded by pendMu.
	relayEpoch uint32

	readyOnce sync.Once
	ready     chan struct{}

	pendMu    sync.Mutex
	pendReady bool
	// stagedClosed latches once the staged queue has been released by its
	// terminal path (Session/Network close). While it is set no new frame may be
	// staged, and a drain that already owns a snapshot must release rather than
	// re-stage: every outstanding lease under this entry has been returned, so a
	// re-queued frame would own ciphertext and a shared lease that nothing would
	// ever release. It is guarded by pendMu.
	stagedClosed bool
	// pendDraining serializes staged processing. Different lane/Link reader
	// goroutines may append while one goroutine opens and delivers a snapshot,
	// so a single drainer owns the hand-off and the others return immediately;
	// the owner loops until no appended frame is left behind. Guarded by pendMu.
	pendDraining bool
	// stagedRefused latches once a relay staged ciphertext could not be admitted
	// by the shared allocator. It is a scoped terminal state of this relay
	// Session's forwarding path: no further frame of it is staged or forwarded,
	// while the physical Link and every other Session stay healthy. Guarded by
	// pendMu.
	stagedRefused bool
	pending       []pendingFrame
	pendBytes     int

	closeOnce sync.Once
	// terminated latches once this entry's Session has been failed by a scoped
	// resource refusal. isReady() stays true (its channel stays closed) and the
	// tx/rx protectors stay installed, so every circuit-facing boundary must also
	// consult this flag: otherwise outgoing Circuits would keep sealing and
	// sending on a Session that no longer exists, silently swallowing the
	// failure. Guard-free (atomic) so it can be read on the send path.
	terminated atomic.Bool
}

// markTerminated latches this entry's Session terminal after a scoped resource
// refusal failed it, so every circuit-facing boundary observes the failure
// instead of continuing on a dead Session.
func (se *sessionEntry) markTerminated() {
	if se == nil {
		return
	}
	se.terminated.Store(true)
}

// isTerminated reports whether a scoped resource refusal already failed this
// entry's Session.
func (se *sessionEntry) isTerminated() bool {
	return se != nil && se.terminated.Load()
}

// pendingFrame is one hop-authenticated inbound E2E frame staged until the local
// Session commits its READY. The inner AEAD is deliberately NOT opened here: the
// ciphertext is retained and the endpoint decrypts it (and then commits the hop
// floor) only after the Session is ready, so the Session root is never used
// before its READY gate.
type pendingFrame struct {
	pump     *controlPump
	envelope []byte
	body     []byte
	message  wire.MessageType
	hop      link.HopRoute
	reserved int
	// hasSessionReservation records that `reserved` bytes were actually booked
	// against the owning Session's per-Session pending counter. A rootless relay
	// entry has no *session.Session and books only the shared allocator lease, so
	// it must never call Session.ReleasePending for bytes it never reserved.
	hasSessionReservation bool
	// lease is the one shared allocator reservation that owns this frame's copied
	// envelope+body and its pendingFrame metadata. It is released exactly once,
	// on drain, drop, close or terminal release, and never after the frame has
	// been wiped.
	lease *budget.Lease
	// protected is the hop-authenticated inbound message this frame was staged
	// from. The generic drain path delivers it through deliverOpenedFrame so a
	// Packet/Flow/Circuit frame is routed by its own endpoint core after the
	// matching epoch is installed.
	protected link.ProtectedMessage
}

func (se *sessionEntry) signalReady() {
	se.readyOnce.Do(func() { close(se.ready) })
}

func (se *sessionEntry) isReady() bool {
	select {
	case <-se.ready:
		return true
	default:
		return false
	}
}

// streamRuntime owns the data plane of one Network.
type streamRuntime struct {
	n          *network
	localID    [16]byte
	ctxID      [32]byte
	descriptor []byte
	wireID     uint64
	relay      bool
	// packets is the L3 packet plane, enabled only when a host device is
	// attached. flow is the UDP datagram plane.
	packets *packetRuntime
	flow    *flow.Manager
	// flowBudget holds the Flow plane's ledger reservations so a Network close
	// releases any association still holding bytes.
	flowBudget *flowBufferBudget
	// budgets is the shared Network allocator that owns every data/control/state
	// byte of this Network inside the frozen 256 MiB heap.
	budgets *budget.Allocator
	// udpMux is the single UDP delivery multiplexer of this runtime. It is
	// installed as the Flow plane's Delivery so public ListenPacket sockets and
	// the Agent SOCKS5 UDP backend share one routing table instead of each
	// installing its own. flowDelivery records which Delivery the installed Flow
	// manager actually owns, so a second, incompatible install fails closed.
	udpMux       *udpMux
	flowDelivery flow.Delivery
	// circuitBudget is the injected shared-Network allocator for receiver-owned
	// Circuit buffers. It is the same *budget.Allocator as budgets, wrapped so
	// the circuit package stays ledger-free.
	circuitBudget *circuitBufferBudget

	sessions *session.Manager
	paths    *path.Manager
	circuits *circuit.Manager
	// provider owns the Noise private-key use state; it is closed exactly once
	// when this runtime closes or when construction fails.
	provider *session.NoiseProvider

	mu           sync.Mutex
	pathsByScope map[pathScope]*pathState
	sessionsByID map[session.SessionID]*sessionEntry
	listenByPort map[uint16]*streamListener
	// pairs single-flights one ready Path+Session per (target node, class). Keying
	// by node alone would make a PACKET-class pair and a STREAM-class pair toward
	// the same peer share one data Path/Session; the class pins the lane
	// (PACKET->lane 1, STREAM->lane 2), so the two are independent pairs.
	pairs  map[pairKey]*readyPair
	closed bool

	// e2ePolicy is the injectable E2E protector policy for this runtime. The
	// zero value resolves to the production SDK defaults inside the session
	// package, so production never runs unbounded; tests lower the ceilings (and
	// inject a clock) to drive a real source rekey without sleeping. It is read
	// under mu by every protector construction/install.
	e2ePolicy session.E2EPolicy
	// rekeySlots bounds the number of concurrent source-rekey workers this
	// runtime may own. It is the "own bounded worker" reservation: a tick that
	// cannot take a slot simply leaves the rekey to the next tick instead of
	// growing unbounded work.
	rekeySlots chan struct{}
}

// pairKey identifies one reusable data Path+Session: the logical target node and
// the session class that pins its data lane.
type pairKey struct {
	node  topology.NodeID
	class session.SessionClass
}

// readyPair is one established Path+Session reused by every Circuit toward the
// same target node and class. A remote target costs one Path table entry and one
// Session per class, not one per Dial, so many Circuits share the pair.
type readyPair struct {
	ps    *pathState
	entry *sessionEntry
	ready chan struct{}
	err   error
}

func newStreamRuntime(n *network, identity security.Identity) (*streamRuntime, error) {
	if n == nil || n.runtimeState == nil {
		return nil, errors.New("stream runtime requires the network runtime state")
	}
	prov, err := session.NewNoiseProvider(identity, n.networkContext, session.ProviderPolicy{
		PendingMax: 1024,
		PendingTTL: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("open session Noise provider: %w", err)
	}
	// One shared allocator accounts every Network-owned buffer: packet/flow data
	// bytes, control metadata and state, inside the frozen 256 MiB heap. It is
	// created before any manager so no owner can reserve outside it.
	limits := budget.DefaultLimits()
	if testNetworkBudgetLimits != nil {
		limits = *testNetworkBudgetLimits
	}
	allocator, err := budget.New(budget.NetworkID(n.networkContext.WireID()), limits)
	if err != nil {
		prov.Close()
		return nil, fmt.Errorf("open budget allocator: %w", err)
	}
	rt := &streamRuntime{
		n:            n,
		localID:      identity.NodeID,
		ctxID:        n.networkContext.ID(),
		descriptor:   n.networkContext.Descriptor(),
		wireID:       n.networkContext.WireID(),
		relay:        n.relayEnabled(),
		provider:     prov,
		budgets:      allocator,
		pathsByScope: make(map[pathScope]*pathState),
		sessionsByID: make(map[session.SessionID]*sessionEntry),
		listenByPort: make(map[uint16]*streamListener),
		pairs:        make(map[pairKey]*readyPair),
		rekeySlots:   make(chan struct{}, 4),
	}
	rt.sessions, err = session.NewManager(session.Config{
		ContextID:   rt.ctxID,
		PSK:         n.networkPSK,
		LocalStatic: identity.PublicKey,
		Resolver:    rt,
		Crypto:      prov,
	})
	if err != nil {
		allocator.Close()
		prov.Close()
		return nil, fmt.Errorf("open session manager: %w", err)
	}
	rt.paths, err = path.NewManager(path.NodeID(rt.localID), n.facts.routes, rt.activeHop)
	if err != nil {
		_ = rt.sessions.Close()
		allocator.Close()
		prov.Close()
		return nil, fmt.Errorf("open path manager: %w", err)
	}
	adapter := &circuitAdapter{rt: rt}
	rt.circuitBudget = &circuitBufferBudget{alloc: allocator, net: budget.NetworkID(rt.wireID)}
	rt.circuits, err = circuit.NewManager(circuit.Config{
		ContextID:    circuit.ContextID(rt.ctxID),
		LocalNodeID:  circuit.NodeID(rt.localID),
		Crypto:       adapter,
		Egress:       adapter,
		BufferBudget: rt.circuitBudget,
	})
	if err != nil {
		_ = rt.paths.Close()
		_ = rt.sessions.Close()
		allocator.Close()
		prov.Close()
		return nil, fmt.Errorf("open circuit manager: %w", err)
	}
	return rt, nil
}

func (rt *streamRuntime) close() error {
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return nil
	}
	rt.closed = true
	entries := make([]*sessionEntry, 0, len(rt.sessionsByID))
	for _, entry := range rt.sessionsByID {
		entries = append(entries, entry)
	}
	rt.sessionsByID = make(map[session.SessionID]*sessionEntry)
	rt.pathsByScope = make(map[pathScope]*pathState)
	rt.pairs = make(map[pairKey]*readyPair)
	listeners := make([]*streamListener, 0, len(rt.listenByPort))
	for _, listener := range rt.listenByPort {
		listeners = append(listeners, listener)
	}
	rt.listenByPort = make(map[uint16]*streamListener)
	rt.mu.Unlock()

	for _, listener := range listeners {
		listener.closeFromNetwork()
	}
	// Wipe every directional session key before the managers release their
	// tables: the pending ciphertext of an unfinished Session is dropped, never
	// delivered after close.
	for _, entry := range entries {
		entry.releasePending()
		entry.closeProtectors()
	}
	rt.mu.Lock()
	packets := rt.packets
	rt.packets = nil
	flowManager := rt.flow
	rt.flow = nil
	flowBudget := rt.flowBudget
	rt.flowBudget = nil
	udpMux := rt.udpMux
	rt.udpMux = nil
	rt.flowDelivery = nil
	allocator := rt.budgets
	rt.budgets = nil
	rt.mu.Unlock()
	if packets != nil {
		_ = packets.close()
	}
	if flowManager != nil {
		_ = flowManager.Close()
	}
	// The UDP mux is closed after the Flow manager so no delivery can enqueue a
	// datagram into an endpoint that is tearing down, and before the shared
	// allocator so every inbox reservation is released inside the live budget.
	if udpMux != nil {
		udpMux.close()
	}
	if flowBudget != nil {
		flowBudget.Close()
	}
	var errs []error
	if rt.circuits != nil {
		errs = append(errs, rt.circuits.Close())
	}
	if rt.paths != nil {
		errs = append(errs, rt.paths.Close())
	}
	if rt.sessions != nil {
		errs = append(errs, rt.sessions.Close())
	}
	if rt.provider != nil {
		rt.provider.Close()
	}
	if allocator != nil {
		errs = append(errs, allocator.Close())
	}
	return errors.Join(errs...)
}

// releasePending drops staged inbound ciphertext, returns every reservation it
// owns and latches the entry terminal. It is the close path: after it, no new
// frame may be staged and a concurrent drain releases its snapshot instead of
// re-queuing it. Each frame's shared lease and per-Session reservation are
// released exactly once, then the sensitive cipher bytes are zeroed.
func (se *sessionEntry) releasePending() {
	se.pendMu.Lock()
	pending := se.pending
	se.pending = nil
	se.pendBytes = 0
	se.stagedClosed = true
	se.pendMu.Unlock()
	for i := range pending {
		releaseStagedFrame(se, &pending[i])
	}
}

// releaseStagedReservation returns one staged frame's shared allocator lease
// and, when the frame actually booked the per-Session counter, its Session
// pending reservation. It is idempotent and deliberately does NOT touch the
// ciphertext: the caller decides whether the bytes are dropped (and must then be
// wiped) or whether their ownership has been transferred to a queued outbound
// write that still aliases the same backing.
func releaseStagedReservation(entry *sessionEntry, frame *pendingFrame) {
	if frame == nil {
		return
	}
	if frame.lease != nil {
		_ = frame.lease.Release()
		frame.lease = nil
	}
	if frame.hasSessionReservation {
		if entry != nil && entry.sess != nil && frame.reserved > 0 {
			entry.sess.ReleasePending(frame.reserved)
		}
		frame.hasSessionReservation = false
	}
	frame.reserved = 0
}

// releaseStagedFrame returns one staged frame's reservations and then wipes the
// copied ciphertext. It is the drop/close path: the bytes are provably no longer
// referenced by any queued write, so zeroing them cannot corrupt a live frame.
func releaseStagedFrame(entry *sessionEntry, frame *pendingFrame) {
	if frame == nil {
		return
	}
	releaseStagedReservation(entry, frame)
	// Zero the ciphertext only after the lease is returned, so no copy claimed
	// by the ledger is still readable.
	clear(frame.envelope)
	clear(frame.body)
	frame.envelope, frame.body = nil, nil
}

// closeProtectors wipes both directional E2E keys. It is idempotent.
func (se *sessionEntry) closeProtectors() {
	// Drop any deferred rekey root before the protectors go away, so no root
	// material outlives the entry.
	se.clearRekeyPending()
	se.protMu.Lock()
	tx, rx := se.tx, se.rx
	se.tx, se.rx = nil, nil
	se.protMu.Unlock()
	if tx != nil {
		tx.Close()
	}
	if rx != nil {
		rx.Close()
	}
}

func (rt *streamRuntime) pathByScope(scope pathScope) *pathState {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.pathsByScope[scope]
}

func (rt *streamRuntime) registerPath(ps *pathState) {
	rt.mu.Lock()
	rt.pathsByScope[ps.scope] = ps
	rt.mu.Unlock()
}

func (rt *streamRuntime) unregisterPath(scope pathScope) {
	rt.mu.Lock()
	delete(rt.pathsByScope, scope)
	rt.mu.Unlock()
}

func (rt *streamRuntime) sessionEntryByID(id session.SessionID) *sessionEntry {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.sessionsByID[id]
}

func (rt *streamRuntime) registerSession(se *sessionEntry) {
	rt.mu.Lock()
	rt.sessionsByID[se.id] = se
	rt.mu.Unlock()
}

func (rt *streamRuntime) registerPort(port uint16, listener *streamListener) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return ErrClosed
	}
	if _, exists := rt.listenByPort[port]; exists {
		return ErrResource
	}
	rt.listenByPort[port] = listener
	return nil
}

func (rt *streamRuntime) unregisterPort(port uint16, listener *streamListener) {
	rt.mu.Lock()
	if rt.listenByPort[port] == listener {
		delete(rt.listenByPort, port)
	}
	rt.mu.Unlock()
}

func (rt *streamRuntime) listenerForPort(port uint16) *streamListener {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.listenByPort[port]
}

// --- transport lookup --------------------------------------------------------

// controlPumpTo returns the registered CONTROL pump of the exact adjacent peer.
func (rt *streamRuntime) controlPumpTo(node topology.NodeID) *controlPump {
	n := rt.n
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, pump := range n.controlPumps {
		if pump == nil || pump.link == nil {
			continue
		}
		if pump.lane != laneControl {
			continue
		}
		if pump.link.PeerNodeID() == [16]byte(node) && pump.link.Ready() {
			return pump
		}
	}
	return nil
}

// dataPumpOnPath returns the registered data pump of the exact installed hop
// between this node and the adjacent Path node at nextIdx. The edge index is
// min(localIndex, nextIdx), so the pump is looked up by the LinkID recorded in
// that Path hop instead of by scanning for the first Ready Link to the same
// peer. A peer-based scan silently picks a sibling parallel Link (for example a
// second authenticated attachment between the same two nodes on the same lane),
// which breaks the Path's pinned physical instance; an exact lookup cannot.
//
// The looked-up pump is verified against the recorded instance (LinkID,
// LinkEpoch, Lane), the adjacent peer and the Ready state. A missing, closed or
// changed instance fails closed with nil rather than falling back to another
// Link to the same peer, so business egress is never re-pathed onto an
// un-pinned sibling hop.
func (rt *streamRuntime) dataPumpOnPath(ps *pathState, nextIdx int) *controlPump {
	if rt == nil || ps == nil || nextIdx < 0 || nextIdx >= len(ps.nodes) || nextIdx == ps.localIndex {
		return nil
	}
	edge := ps.localIndex
	if nextIdx < edge {
		edge = nextIdx
	}
	if edge < 0 || edge >= len(ps.links) {
		return nil
	}
	ref := ps.links[edge]
	n := rt.n
	if n == nil {
		return nil
	}
	n.mu.Lock()
	pump := n.controlPumps[ref.ID]
	n.mu.Unlock()
	if pump == nil || pump.link == nil || pump.control == nil {
		return nil
	}
	if !pump.link.Ready() {
		return nil
	}
	if pump.lane != uint8(ps.lane) {
		return nil
	}
	if pump.link.PeerNodeID() != [16]byte(ps.nodes[nextIdx]) {
		return nil
	}
	metadata := pump.link.Metadata()
	if metadata.LinkID != ref.ID || metadata.LinkEpoch != ref.Epoch || metadata.LaneID != ref.LaneID {
		return nil
	}
	return pump
}

// factStore returns the live FactStore backing this Network, or nil when the
// runtime has no fact plane. It is only a borrow: callers never mutate it.
func (rt *streamRuntime) factStore() *topology.FactStore {
	if rt == nil || rt.n == nil || rt.n.facts == nil {
		return nil
	}
	return rt.n.facts.store
}

// currentAddressOwner resolves the live unambiguous owner of one exact IPv4 /32
// directly from the current fact entries. Unlike a RouteView lookup it never
// consults (or requires a refresh of) the immutable view snapshot, so a renewed
// AddressFact of the same owner with a higher version is visible immediately and
// a steady datagram flow cannot fail as route-stale merely because the view has
// not been rebuilt yet.
func (rt *streamRuntime) currentAddressOwner(addr netip.Addr) (topology.AddressResolution, error) {
	store := rt.factStore()
	if store == nil {
		return topology.AddressResolution{}, topology.ErrNoRoute
	}
	return store.ResolveAddressOwner(addr, time.Now())
}

// pairUsable reports whether one cached ready pair may be handed out again. It
// requires the Path/Session to still be active and every local adjacent hop to
// still resolve to the exact installed Link instance. Without the second half a
// pair whose pinned Link died would keep being reused, and the next frame would
// fail closed as a lost Session even though a fresh Path over a replacement Link
// is installable.
func (rt *streamRuntime) pairUsable(pair *readyPair) bool {
	if !rt.pairActive(pair) {
		return false
	}
	return rt.pinnedHopsReady(rt.pathByScope(pair.ps.scope))
}

// pairActive reports whether one cached ready pair is still usable: the local
// Path generation is registered and not broken, and its Session entry exists,
// has committed its READY and is still in the ready state. The ready channel
// alone is not enough: it stays closed after the Session is broken or closed, so
// a terminal Session must be reported inactive instead of being handed to the
// next frame. Exact-hop and live-fact health is validated separately so this
// cheap check never clones facts or takes a store lock.
func (rt *streamRuntime) pairActive(pair *readyPair) bool {
	if pair == nil || pair.ps == nil || pair.entry == nil {
		return false
	}
	ps := rt.pathByScope(pair.ps.scope)
	if ps == nil || ps.broken.Load() {
		return false
	}
	entry := rt.sessionEntryByID(pair.entry.id)
	if entry == nil || !entry.isReady() {
		return false
	}
	if entry.sess != nil && entry.sess.State() != session.StateReady {
		return false
	}
	return true
}

// pinnedHopsReady reports whether every local adjacent hop of ps still resolves
// to the exact installed Link instance through a Ready pump. It is the local
// half of the pinned-path check; the fact half is ResolvePinnedLinks.
func (rt *streamRuntime) pinnedHopsReady(ps *pathState) bool {
	if ps == nil {
		return false
	}
	for index := range ps.nodes {
		if index == ps.localIndex {
			continue
		}
		if index != ps.localIndex-1 && index != ps.localIndex+1 {
			continue
		}
		if rt.dataPumpOnPath(ps, index) == nil {
			return false
		}
	}
	return true
}

// validatePinnedPair re-checks one already-READY class-1 pair before it is
// handed to a packet or datagram send: the local Path/Session is still active,
// every local hop is still the exact installed Link instance, every path node
// and every segment still has a current live NODE/LINK fact of the pinned
// instance, and the peer static key is still resolvable. A failure is returned
// as-is (route stale / no route) and never repaired by re-pointing the caller at
// a different Path, so an existing Circuit or a pinned datagram keeps its scope.
func (rt *streamRuntime) validatePinnedPair(pair *readyPair) error {
	if !rt.pairActive(pair) {
		return fmt.Errorf("%w: pinned Path/Session is no longer active", circuit.ErrSessionLost)
	}
	ps := rt.pathByScope(pair.ps.scope)
	if ps == nil {
		return fmt.Errorf("%w: pinned Path is no longer installed", circuit.ErrSessionLost)
	}
	if !rt.pinnedHopsReady(ps) {
		return fmt.Errorf("%w: pinned hop is not the installed Link instance", circuit.ErrSessionLost)
	}
	if store := rt.factStore(); store != nil {
		if err := store.ResolvePinnedLinks(ps.nodes, ps.links, uint8(ps.lane), time.Now()); err != nil {
			return err
		}
	}
	peer := ps.nodes[ps.dstIndex()]
	current, ok := rt.peerStatic(peer)
	if !ok {
		return fmt.Errorf("%w: no authenticated static key for the pinned peer", topology.ErrNoRoute)
	}
	// The Session was authenticated against one exact static key. Resolving a
	// different key for the same node means the peer identity behind the pinned
	// Path changed, which retires the Session instead of continuing on it.
	if expected := pair.entry.peerStatic; expected != ([32]byte{}) && current != expected {
		return fmt.Errorf("%w: peer static key changed for the pinned Session", circuit.ErrSessionLost)
	}
	return nil
}

// activeHop is the path.Manager local-activeness callback. A hop this node owns
// locally must be registered and Ready with the exact epoch/lane. A hop with no
// local registry entry is only acceptable when its authenticated LINK fact says
// it is NOT adjacent to this node (a remote hop); an adjacent hop that is missing
// from the registry is an inactive local link and fails closed. The remote case
// still requires the hop to be visible in the current FactStore snapshot, so a
// withdrawn fact cannot keep a route usable.
func (rt *streamRuntime) activeHop(ref topology.LinkRef) bool {
	n := rt.n
	n.mu.Lock()
	established := n.activeLinks[ref.ID]
	n.mu.Unlock()
	if established != nil {
		if !established.Ready() {
			return false
		}
		metadata := established.Metadata()
		return metadata.LinkEpoch == ref.Epoch && metadata.LaneID == ref.LaneID
	}
	payload, ok := rt.linkFactPayload(ref.ID, ref.Epoch)
	if !ok {
		return false
	}
	if payload.LaneID != ref.LaneID {
		return false
	}
	if [16]byte(payload.From) == rt.localID || [16]byte(payload.To) == rt.localID {
		// Adjacent to this node but not open locally: fail closed rather than
		// treating a missing local link as a remote hop.
		return false
	}
	return true
}

// currentLinkFact returns the visible LINK fact payload of one exact instance
// from the current FactStore snapshot.
func (rt *streamRuntime) linkFactPayload(linkID, epoch uint64) (topology.LinkPayload, bool) {
	if rt.n.facts == nil || rt.n.facts.store == nil {
		return topology.LinkPayload{}, false
	}
	records, _, err := rt.n.facts.store.Snapshot(time.Now())
	if err != nil {
		return topology.LinkPayload{}, false
	}
	for _, record := range records {
		payload, ok := record.Payload.(topology.LinkPayload)
		if !ok {
			continue
		}
		if payload.LinkID == linkID && payload.LinkEpoch == epoch {
			return payload, true
		}
	}
	return topology.LinkPayload{}, false
}

// ResolvePeer implements session.PeerResolver for the canonical logical peer of
// one Path scope.
func (rt *streamRuntime) ResolvePeer(pathID uint64, pathGeneration uint32, class session.SessionClass) (session.Peer, error) {
	ps := rt.pathByScope(pathScope{id: pathID, gen: pathGeneration})
	if ps == nil {
		return session.Peer{}, fmt.Errorf("%w: path %d/%d", path.ErrNotFound, pathID, pathGeneration)
	}
	other := ps.nodes[ps.dstIndex()]
	static, ok := rt.peerStatic(other)
	if !ok {
		return session.Peer{}, fmt.Errorf("%w: no authenticated static key for node %x", path.ErrInvalidNode, other[:4])
	}
	return session.Peer{NodeID: [16]byte(other), StaticKey: static}, nil
}

func (rt *streamRuntime) peerStatic(node topology.NodeID) ([32]byte, bool) {
	n := rt.n
	n.mu.Lock()
	for _, established := range n.activeLinks {
		if established.PeerNodeID() == [16]byte(node) {
			static := established.PeerStatic()
			n.mu.Unlock()
			return static, true
		}
	}
	n.mu.Unlock()
	return rt.factStatic(node)
}

// factStatic resolves a non-adjacent peer's X25519 static key from its
// authenticated NODE fact. Facts are the only source for a non-adjacent peer and
// they were validated by FactStore before becoming visible.
func (rt *streamRuntime) factStatic(node topology.NodeID) ([32]byte, bool) {
	if rt.n.facts == nil || rt.n.facts.store == nil {
		return [32]byte{}, false
	}
	records, _, err := rt.n.facts.store.Snapshot(time.Now())
	if err != nil {
		return [32]byte{}, false
	}
	for _, record := range records {
		payload, ok := record.Payload.(topology.NodePayload)
		if !ok {
			continue
		}
		if payload.NodeID == node {
			return payload.StaticPublicKey, true
		}
	}
	return [32]byte{}, false
}

// --- envelope helpers --------------------------------------------------------

// Envelope node offsets in the frozen 85-byte envelope: wire_id:u64 at 0,
// src:16B at 8, dst:16B at 24.
const (
	envelopeSrcOffset = 8
	envelopeDstOffset = 24
)

// buildEnvelope returns the exact 85-byte frozen envelope. ROUTE_CTRL frames
// carry epoch/counter zero and PATH_* carry a zero SessionID; E2E frames carry
// the session nonce domain and a non-zero SessionID.
func buildEnvelope(wireID uint64, src, dst [16]byte, messageType wire.MessageType, sessionID [16]byte, epoch uint32, number uint64, pathID uint64, pathGen uint32, innerLen int) []byte {
	envelope := make([]byte, wire.EnvelopeSize)
	binary.BigEndian.PutUint64(envelope[0:8], wireID)
	copy(envelope[8:24], src[:])
	copy(envelope[24:40], dst[:])
	envelope[wire.EnvelopeMessageTypeOffset] = byte(messageType)
	copy(envelope[wire.EnvelopeSessionIDOffset:wire.EnvelopeKeyEpochOffset], sessionID[:])
	binary.BigEndian.PutUint32(envelope[wire.EnvelopeKeyEpochOffset:wire.EnvelopeMessageNumberOffset], epoch)
	binary.BigEndian.PutUint64(envelope[wire.EnvelopeMessageNumberOffset:wire.EnvelopePathIDOffset], number)
	binary.BigEndian.PutUint64(envelope[wire.EnvelopePathIDOffset:wire.EnvelopePathGenerationOffset], pathID)
	binary.BigEndian.PutUint32(envelope[wire.EnvelopePathGenerationOffset:wire.EnvelopeInnerLengthOffset], pathGen)
	binary.BigEndian.PutUint32(envelope[wire.EnvelopeInnerLengthOffset:], uint32(innerLen))
	return envelope
}

func envelopeNode(envelope []byte, offset int) [16]byte {
	var node [16]byte
	if len(envelope) < offset+16 {
		return node
	}
	copy(node[:], envelope[offset:offset+16])
	return node
}

func envelopeMessageType(envelope []byte) wire.MessageType {
	if len(envelope) < wire.EnvelopeSize {
		return 0
	}
	return wire.MessageType(envelope[wire.EnvelopeMessageTypeOffset])
}

func envelopeSessionID(envelope []byte) [16]byte {
	return envelopeNode(envelope, wire.EnvelopeSessionIDOffset)
}

func envelopePath(envelope []byte) (uint64, uint32) {
	if len(envelope) < wire.EnvelopeSize {
		return 0, 0
	}
	return binary.BigEndian.Uint64(envelope[wire.EnvelopePathIDOffset:wire.EnvelopePathGenerationOffset]),
		binary.BigEndian.Uint32(envelope[wire.EnvelopePathGenerationOffset:wire.EnvelopeInnerLengthOffset])
}

func envelopeEpoch(envelope []byte) uint32 {
	if len(envelope) < wire.EnvelopeSize {
		return 0
	}
	return binary.BigEndian.Uint32(envelope[wire.EnvelopeKeyEpochOffset:wire.EnvelopeMessageNumberOffset])
}

func envelopeNumber(envelope []byte) uint64 {
	if len(envelope) < wire.EnvelopeSize {
		return 0
	}
	return binary.BigEndian.Uint64(envelope[wire.EnvelopeMessageNumberOffset:wire.EnvelopePathIDOffset])
}

// --- network frame entry points ---------------------------------------------

func (n *network) handleRouteFrame(pump *controlPump, message link.ProtectedMessage) error {
	if n == nil || n.streams == nil {
		return ErrLinkDown
	}
	return n.streams.handleRouteFrame(pump, message)
}

func (n *network) handleEndToEndFrame(pump *controlPump, message link.ProtectedMessage) error {
	if n == nil || n.streams == nil {
		return ErrLinkDown
	}
	return n.streams.handleEndToEndFrame(pump, message)
}

// --- ROUTE_CTRL dispatch -----------------------------------------------------

// envelopeWireID returns the network locator bound into the frozen envelope. The
// full-context hop KDF is the real isolation root, but a frame for another
// network must be rejected before any state is touched; wireID 0 is a legal
// equality, not a wildcard.
func envelopeWireID(envelope []byte) uint64 {
	if len(envelope) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(envelope[:8])
}

// directionOnPath reports whether envelope src/dst are exactly the forward
// (source -> target) or reverse (target -> source) logical endpoints of ps.
func (ps *pathState) directionOnPath(envelope []byte) (forward, reverse bool) {
	src := envelopeNode(envelope, envelopeSrcOffset)
	dst := envelopeNode(envelope, envelopeDstOffset)
	source, target := [16]byte(ps.nodes[0]), [16]byte(ps.nodes[len(ps.nodes)-1])
	return src == source && dst == target, src == target && dst == source
}

// checkIngressPeer verifies the frame was read from the authenticated adjacent
// node the direction requires, so a cursor from another neighbour can never
// impersonate a hop. data additionally requires the exact installed STREAM hop
// instance; a control frame must arrive on the CONTROL lane.
func (rt *streamRuntime) checkIngressPeer(ps *pathState, pump *controlPump, forward, data bool) error {
	if pump == nil || pump.link == nil {
		return link.ErrInvalidHopRoute
	}
	expectedIdx, hopIdx := ps.localIndex-1, ps.localIndex-1
	if !forward {
		expectedIdx, hopIdx = ps.localIndex+1, ps.localIndex
	}
	if expectedIdx < 0 || expectedIdx >= len(ps.nodes) {
		return link.ErrInvalidHopRoute
	}
	if pump.link.PeerNodeID() != [16]byte(ps.nodes[expectedIdx]) {
		return link.ErrInvalidHopRoute
	}
	if !pump.link.Ready() {
		return ErrLinkDown
	}
	if data {
		if pump.lane != uint8(ps.lane) {
			return link.ErrUnexpectedKind
		}
		if hopIdx < 0 || hopIdx >= len(ps.links) {
			return link.ErrInvalidHopRoute
		}
		ref := ps.links[hopIdx]
		meta := pump.link.Metadata()
		if meta.LinkID != ref.ID || meta.LinkEpoch != ref.Epoch || meta.LaneID != ref.LaneID {
			return link.ErrInvalidHopRoute
		}
	} else if pump.lane != laneControl {
		return link.ErrUnexpectedKind
	}
	return nil
}

func (rt *streamRuntime) handleRouteFrame(pump *controlPump, message link.ProtectedMessage) error {
	envelope := message.Envelope
	if len(envelope) != wire.EnvelopeSize {
		return link.ErrRouteMessage
	}
	if envelopeWireID(envelope) != rt.wireID {
		return link.ErrRouteMessage
	}
	messageType := envelopeMessageType(envelope)
	dst := envelopeNode(envelope, envelopeDstOffset)
	pathID, pathGen := envelopePath(envelope)
	if dst == rt.localID {
		if err := rt.handleLocalRoute(pump, message, messageType, pathID, pathGen); err != nil {
			traceDataPlane("local ROUTE frame failed", "local", hexNode(rt.localID)[:8], "type", uint8(messageType), "path", pathID, "gen", pathGen, "err", err.Error())
			return err
		}
		return nil
	}
	return rt.forwardRoute(pump, envelope, message.Payload, message.Hop(), messageType, pathID, pathGen)
}

func (rt *streamRuntime) handleLocalRoute(pump *controlPump, message link.ProtectedMessage, messageType wire.MessageType, pathID uint64, pathGen uint32) error {
	// A frame addressed to this endpoint must have been read from the physical
	// neighbour the wire direction requires. PATH_OPEN is the one frame with no
	// installed path yet; handlePathOpen proves its own adjacency before Accept.
	if ps := rt.pathByScope(pathScope{id: pathID, gen: pathGen}); ps != nil {
		forward, reverse := ps.directionOnPath(message.Envelope)
		if !forward && !reverse {
			return link.ErrRouteMessage
		}
		if int(message.Hop().Cursor) != ps.localIndex {
			return link.ErrInvalidHopRoute
		}
		if err := rt.checkIngressPeer(ps, pump, forward, false); err != nil {
			return err
		}
	}
	switch messageType {
	case wire.MessageTypePathOpen:
		return rt.handlePathOpen(pump, message, pathID, pathGen)
	case wire.MessageTypePathReady:
		return rt.handlePathReady(message.Payload, pathID, pathGen)
	case wire.MessageTypePathBroken:
		return rt.handlePathBroken(message.Payload, pathID, pathGen)
	case wire.MessageTypeSessionCtrl:
		return rt.handleSessionCtrl(pump, message, pathID, pathGen)
	case wire.MessageTypeSessionReady:
		return rt.handleSessionReady(message, pathID, pathGen)
	default:
		return link.ErrRouteMessage
	}
}

// handlePathOpen accepts a target-side PATH_OPEN (the local node is the final
// target), replies PATH_READY through the reverse hop and marks the path active.
func (rt *streamRuntime) handlePathOpen(pump *controlPump, message link.ProtectedMessage, pathID uint64, pathGen uint32) error {
	rc, err := path.DecodeRouteControl(path.MessagePathOpen, message.Payload)
	if err != nil {
		return err
	}
	open := rc.Open
	// The payload must name exactly the envelope's Path, its endpoints must be
	// the wire src/dst this node accepted, and the frame must have arrived from
	// the immediately preceding hop, before path.Accept mutates any state.
	if open.PathID != pathID || open.Generation != pathGen {
		return link.ErrRouteMessage
	}
	if len(open.Nodes) < 2 {
		return link.ErrRouteMessage
	}
	if [16]byte(open.Nodes[0]) != envelopeNode(message.Envelope, envelopeSrcOffset) ||
		[16]byte(open.Nodes[len(open.Nodes)-1]) != envelopeNode(message.Envelope, envelopeDstOffset) {
		return link.ErrRouteMessage
	}
	proof := &pathState{nodes: append([]topology.NodeID(nil), open.Nodes...), localIndex: len(open.Nodes) - 1}
	if int(message.Hop().Cursor) != proof.localIndex {
		return link.ErrInvalidHopRoute
	}
	if err := rt.checkIngressPeer(proof, pump, true, false); err != nil {
		return err
	}
	hops, err := rt.resolveHopLinks(open.Nodes, open.Links)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(rt.n.ctx, 10*time.Second)
	defer cancel()
	installed, err := rt.paths.Accept(ctx, open, hops)
	if err != nil {
		return err
	}
	ps := &pathState{
		scope:       pathScope{id: installed.ID(), gen: installed.Generation()},
		lane:        installed.Lane(),
		nodes:       installed.Nodes(),
		links:       installed.Links(),
		digest:      installed.Digest(),
		viewVersion: installed.ViewVersion(),
		localIndex:  len(installed.Nodes()) - 1,
		source:      false,
		handle:      installed,
		ready:       make(chan struct{}),
		inCtrl:      pump,
		budget:      message.Hop().RemainingBudget,
	}
	rt.registerPath(ps)
	// Accept installs the path in OpenPending. The state machine is not
	// bypassed: the target records its own local READY transition first, then
	// sends PATH_READY. Active is only recorded later, when the matching
	// SESSION_READY commits this target's session (handleSessionReady).
	readyMsg := path.PathReady{
		PathID:     installed.ID(),
		Generation: installed.Generation(),
		Lane:       installed.Lane(),
		Digest:     installed.Digest(),
		Status:     path.ReadyStatusReady,
		Code:       path.ErrorCodeNone,
	}
	if err := installed.MarkReady(readyMsg); err != nil {
		return err
	}
	traceDataPlane("PATH_OPEN accepted", "path", pathID, "gen", pathGen, "local_index", ps.localIndex, "nodes", len(ps.nodes))
	payload, err := installed.ReadyFrame(path.ReadyStatusReady, path.ErrorCodeNone)
	if err != nil {
		return err
	}
	// PATH_READY travels back toward the logical source; the envelope src/dst
	// describe the actual sender/receiver so a relay can route it in reverse.
	src := ps.nodes[ps.localIndex]
	dst := ps.nodes[ps.dstIndex()]
	out := rt.controlPumpTo(ps.nodes[ps.hopIndexToward(ps.dstIndex())])
	if out == nil {
		return ErrLinkDown
	}
	envelope := buildEnvelope(rt.wireID, [16]byte(src), [16]byte(dst), wire.MessageTypePathReady, [16]byte{}, 0, 0, pathID, pathGen, len(payload))
	return out.sendRoute(envelope, payload, link.HopRoute{Cursor: uint8(ps.hopIndexToward(ps.dstIndex())), HopLimit: overlayHopLimit, RemainingBudget: ps.pathBudget()})
}

func (rt *streamRuntime) handlePathReady(payload []byte, pathID uint64, pathGen uint32) error {
	rc, err := path.DecodeRouteControl(path.MessagePathReady, payload)
	if err != nil {
		return err
	}
	ps := rt.pathByScope(pathScope{id: pathID, gen: pathGen})
	if ps == nil {
		return nil
	}
	if err := ps.handle.MarkReady(rc.Ready); err != nil {
		return err
	}
	traceDataPlane("PATH_READY received", "path", pathID, "gen", pathGen, "status", rc.Ready.Status.String())
	ps.signalReady()
	return nil
}

func (rt *streamRuntime) handlePathBroken(payload []byte, pathID uint64, pathGen uint32) error {
	rc, err := path.DecodeRouteControl(path.MessagePathBroken, payload)
	if err != nil {
		return err
	}
	ps := rt.pathByScope(pathScope{id: pathID, gen: pathGen})
	if ps == nil {
		return nil
	}
	ps.broken.Store(true)
	_ = ps.handle.MarkBroken(rc.Broken)
	ps.signalReady()
	return nil
}

// resolveHopLinks maps every hop (LinkID, LinkEpoch) of a received PATH_OPEN to
// the exact authenticated LinkRef this node knows, including the connection type
// bound into the PathDigest. Local links are authoritative; a remote hop comes
// from its authenticated FACT.
func (rt *streamRuntime) resolveHopLinks(nodes []path.NodeID, links []path.LinkInstance) ([]topology.LinkRef, error) {
	resolved := make([]topology.LinkRef, 0, len(links))
	for index, pair := range links {
		ref, ok := rt.linkRefFor(pair.ID, pair.Epoch)
		if !ok {
			return nil, fmt.Errorf("%w: hop %d link %d/%d is not locally known", path.ErrLinkMismatch, index, pair.ID, pair.Epoch)
		}
		resolved = append(resolved, ref)
	}
	return resolved, nil
}

func (rt *streamRuntime) linkRefFor(linkID, epoch uint64) (topology.LinkRef, bool) {
	n := rt.n
	n.mu.Lock()
	for _, established := range n.activeLinks {
		metadata := established.Metadata()
		if metadata.LinkID == linkID && metadata.LinkEpoch == epoch {
			ref := topology.LinkRef{ID: linkID, Epoch: epoch, LaneID: metadata.LaneID, ConnectionType: established.ConnectionType()}
			n.mu.Unlock()
			return ref, true
		}
	}
	n.mu.Unlock()
	payload, ok := rt.linkFactPayload(linkID, epoch)
	if !ok {
		return topology.LinkRef{}, false
	}
	return topology.LinkRef{ID: linkID, Epoch: epoch, LaneID: payload.LaneID, ConnectionType: payload.ConnectionType}, true
}

// forwardRoute relays one ROUTE_CTRL bootstrap frame for a path this node
// installed as an intermediate hop. The first PATH_OPEN installs the rootless
// relay path; every later frame is validated against it and forwarded
// byte-for-byte with only the hop cursor/limit/budget changed. The envelope
// src/dst stay the real logical endpoints: rewriting them would change the E2E
// AAD and fail every inner tag.
func (rt *streamRuntime) forwardRoute(pump *controlPump, envelope, payload []byte, hop link.HopRoute, messageType wire.MessageType, pathID uint64, pathGen uint32) error {
	ps := rt.pathByScope(pathScope{id: pathID, gen: pathGen})
	if ps == nil {
		if messageType != wire.MessageTypePathOpen {
			return link.ErrRouteMessage
		}
		installed, err := rt.installRelayPath(pump, payload, hop, pathID, pathGen)
		if err != nil {
			return err
		}
		ps = installed
	}
	if !ps.relay {
		return link.ErrRouteMessage
	}
	if int(hop.Cursor) != ps.localIndex {
		return link.ErrInvalidHopRoute
	}
	forward, reverse := ps.directionOnPath(envelope)
	if !forward && !reverse {
		return link.ErrRouteMessage
	}
	if err := rt.checkIngressPeer(ps, pump, forward, false); err != nil {
		return err
	}
	switch messageType {
	case wire.MessageTypePathOpen:
		if err := rt.validateRelayPathOpenRepeat(ps, payload); err != nil {
			return err
		}
	case wire.MessageTypePathReady:
		if reverse {
			// The target accepted the path; this hop is ready-pending until the
			// matching Session READY commits relay data forwarding.
			ps.relayPending.Store(true)
		}
	case wire.MessageTypeSessionCtrl:
		if err := rt.observeRelaySessionCtrl(ps, envelope, payload); err != nil {
			return err
		}
	case wire.MessageTypeSessionReady:
		if err := rt.observeRelaySessionReady(ps, envelope, payload); err != nil {
			return err
		}
	case wire.MessageTypePathBroken:
		// Forwarded opaquely; this hop owns no endpoint path state to retire.
	default:
		// An unrecognised ROUTE_CTRL type is never forwarded.
		return link.ErrRouteMessage
	}

	start := time.Now()
	dst := envelopeNode(envelope, envelopeDstOffset)
	dstIndex := -1
	for index, node := range ps.nodes {
		if [16]byte(node) == dst {
			dstIndex = index
			break
		}
	}
	if dstIndex < 0 {
		return link.ErrInvalidHopRoute
	}
	next := ps.hopIndexToward(dstIndex)
	if next < 0 || next >= len(ps.nodes) {
		return link.ErrInvalidHopRoute
	}
	out := rt.controlPumpTo(ps.nodes[next])
	if out == nil {
		return ErrLinkDown
	}
	elapsed := forwardElapsedMicros(start)
	if elapsed >= hop.RemainingBudget {
		return ErrLinkDown
	}
	return out.sendRoute(envelope, payload, link.HopRoute{Cursor: uint8(next), HopLimit: hop.HopLimit, RemainingBudget: hop.RemainingBudget - elapsed})
}

// installRelayPath decodes one PATH_OPEN addressed to a final target this node is
// not, validates every frozen geometry/ownership field and installs a rootless
// forwarding entry. It deliberately never calls path.Accept: that transition is
// target-only and would reject an intermediate hop.
func (rt *streamRuntime) installRelayPath(pump *controlPump, payload []byte, hop link.HopRoute, pathID uint64, pathGen uint32) (*pathState, error) {
	rc, err := path.DecodeRouteControl(path.MessagePathOpen, payload)
	if err != nil {
		return nil, err
	}
	open := rc.Open
	if open.PathID != pathID || open.Generation != pathGen {
		return nil, link.ErrRouteMessage
	}
	if !open.Lane.Valid() || len(open.Nodes) < 3 || len(open.Nodes) > overlayHopLimit {
		return nil, link.ErrRouteMessage
	}
	if len(open.Links) != len(open.Nodes)-1 {
		return nil, link.ErrRouteMessage
	}
	ownIdx := -1
	seen := make(map[topology.NodeID]struct{}, len(open.Nodes))
	for index, node := range open.Nodes {
		if _, dup := seen[node]; dup {
			return nil, link.ErrRouteMessage
		}
		seen[node] = struct{}{}
		if [16]byte(node) == rt.localID {
			ownIdx = index
		}
	}
	if ownIdx <= 0 || ownIdx >= len(open.Nodes)-1 {
		// Not an intermediate hop of this path: this node is an endpoint or absent.
		return nil, link.ErrRouteMessage
	}
	if int(hop.Cursor) != ownIdx || hop.HopLimit == 0 || int(hop.HopLimit) > overlayHopLimit || hop.RemainingBudget == 0 {
		return nil, link.ErrInvalidHopRoute
	}
	// The frame must have arrived from the node immediately before this hop on
	// the authenticated CONTROL link it was read from.
	if pump == nil || pump.link == nil {
		return nil, link.ErrRouteMessage
	}
	if pump.link.PeerNodeID() != [16]byte(open.Nodes[ownIdx-1]) {
		return nil, link.ErrInvalidHopRoute
	}
	links, err := rt.resolveHopLinks(open.Nodes, open.Links)
	if err != nil {
		return nil, err
	}
	for index, ref := range links {
		if ref.LaneID != uint8(open.Lane) {
			return nil, fmt.Errorf("%w: hop %d lane 0x%02x for path lane 0x%02x", link.ErrRouteMessage, index, ref.LaneID, uint8(open.Lane))
		}
		if !rt.activeHop(ref) {
			return nil, fmt.Errorf("%w: hop %d link %d/%d is not the current active instance", link.ErrRouteMessage, index, ref.ID, ref.Epoch)
		}
	}
	digest, err := path.ComputeDigest(open.PathID, open.Generation, open.Lane, open.ViewVersion, open.Nodes, links)
	if err != nil {
		return nil, err
	}
	if digest != open.Digest {
		return nil, fmt.Errorf("%w: relay PATH_OPEN digest does not match the resolved nodes/links", link.ErrRouteMessage)
	}
	ps := &pathState{
		scope:       pathScope{id: open.PathID, gen: open.Generation},
		lane:        open.Lane,
		nodes:       append([]topology.NodeID(nil), open.Nodes...),
		links:       links,
		digest:      digest,
		viewVersion: open.ViewVersion,
		localIndex:  ownIdx,
		source:      false,
		relay:       true,
		ready:       make(chan struct{}),
		budget:      hop.RemainingBudget,
		inCtrl:      pump,
	}
	rt.registerPath(ps)
	if open.Lane == path.LanePacket {
		// A rootless relay that forwards a PACKET-lane path must also own the
		// dedicated PACKET lane adjacency on its own upstream side; it holds no
		// flow/packet endpoint plane, just the data lane.
		rt.n.mu.Lock()
		rt.n.packetLanesEnabled = true
		rt.n.mu.Unlock()
	}
	traceDataPlane("relay PATH_OPEN installed", "path", pathID, "gen", pathGen, "local_index", ownIdx, "nodes", len(open.Nodes))
	return ps, nil
}

// validateRelayPathOpenRepeat checks a retransmitted PATH_OPEN against the
// installed relay entry without reinstalling it.
func (rt *streamRuntime) validateRelayPathOpenRepeat(ps *pathState, payload []byte) error {
	rc, err := path.DecodeRouteControl(path.MessagePathOpen, payload)
	if err != nil {
		return err
	}
	if rc.Open.PathID != ps.scope.id || rc.Open.Generation != ps.scope.gen || rc.Open.Digest != ps.digest {
		return link.ErrRouteMessage
	}
	return nil
}

// observeRelaySessionCtrl records the bound identity of one relayed SESSION_CTRL
// and admits the keyless hop session on both adjacent STREAM Links. The relay
// creates no Session object, holds no root and builds no E2E protector.
func (rt *streamRuntime) observeRelaySessionCtrl(ps *pathState, envelope, payload []byte) error {
	ctrl, err := session.DecodeSessionCtrl(payload)
	if err != nil {
		return err
	}
	if ctrl.SessionID != envelopeSessionID(envelope) {
		return link.ErrRouteMessage
	}
	ctrl.PathID = ps.scope.id
	ctrl.PathGeneration = ps.scope.gen
	ctrl.SrcNodeID = [16]byte(ps.nodes[0])
	ctrl.DstNodeID = [16]byte(ps.nodes[len(ps.nodes)-1])
	entry := rt.sessionEntryByID(ctrl.SessionID)
	if entry == nil {
		entry = &sessionEntry{
			id:          ctrl.SessionID,
			scope:       ps.scope,
			class:       ctrl.Class,
			lane:        ctrl.DataLaneID,
			src:         ctrl.SrcNodeID,
			dst:         ctrl.DstNodeID,
			relay:       true,
			attempt:     ctrl.Attempt,
			targetEpoch: ctrl.TargetEpoch,
			ready:       make(chan struct{}),
		}
		rt.registerSession(entry)
		traceDataPlane("relay SESSION_CTRL observed", "session", hexNode([16]byte(entry.id))[:8], "attempt", ctrl.Attempt)
	} else if !entry.relay || entry.scope != ps.scope || entry.class != ctrl.Class ||
		entry.lane != ctrl.DataLaneID {
		// A duplicate SessionID that disagrees on any frozen identity is a
		// conflict, never a silent re-bind of the relay's forwarding state.
		return link.ErrRouteMessage
	} else {
		attempt, epoch, _, _ := entry.attemptIdentity()
		switch {
		case ctrl.Attempt == attempt && ctrl.TargetEpoch == epoch:
			// Byte-identical retransmission of the attempt already recorded.
		case attempt != ^uint32(0) && ctrl.Attempt == attempt+1 && ctrl.TargetEpoch == epoch+1:
			// The next attempt of the SAME SessionID/scope/class/lane. The relay
			// stays rootless and keyless: it records the identity and keeps
			// forwarding opaque ciphertext; only the matching SESSION_READY
			// completes the new epoch.
			entry.noteRelayAttempt(ctrl.Attempt, ctrl.TargetEpoch)
			traceDataPlane("relay SESSION_CTRL next attempt", "session", hexNode([16]byte(entry.id))[:8], "attempt", ctrl.Attempt)
		default:
			return link.ErrRouteMessage
		}
	}
	return rt.admitSessionOnDataPumps(entry)
}

// observeRelaySessionReady commits the matching relay session and drains staged
// opaque frames in order. The relay never inspects or decrypts the inner bytes.
func (rt *streamRuntime) observeRelaySessionReady(ps *pathState, envelope, payload []byte) error {
	ready, err := session.DecodeSessionReady(payload)
	if err != nil {
		return err
	}
	if ready.SessionID != envelopeSessionID(envelope) {
		return link.ErrRouteMessage
	}
	// A relay commits forwarding only after the target's reverse PATH_READY has
	// passed through this hop: no READY may create relay authority before the
	// path it rides was accepted end to end.
	if !ps.relayPending.Load() {
		return link.ErrRouteMessage
	}
	entry := rt.sessionEntryByID(ready.SessionID)
	if entry == nil || !entry.relay {
		return nil
	}
	if entry.scope != ps.scope || entry.class != ready.Class || entry.lane != ready.DataLaneID {
		return link.ErrRouteMessage
	}
	attempt, epoch, _, _ := entry.attemptIdentity()
	if ready.Attempt != attempt || ready.TargetEpoch != epoch {
		// A READY that does not name the attempt the relay recorded (stale or
		// future) never completes the new epoch.
		return nil
	}
	rt.commitRelaySession(entry)
	return nil
}

// commitRelaySession records the READY's epoch and forwards every staged frame
// in arrival order. It is idempotent and re-entrant across epochs: the first
// READY signals readiness and drains staging, a later rekey READY only advances
// the committed relay epoch. The relay never inspects or decrypts the bytes.
func (rt *streamRuntime) commitRelaySession(entry *sessionEntry) {
	_, epoch, _, _ := entry.attemptIdentity()
	entry.pendMu.Lock()
	if epoch > entry.relayEpoch {
		entry.relayEpoch = epoch
	}
	if entry.pendReady {
		entry.pendMu.Unlock()
		return
	}
	entry.pendReady = true
	pending := entry.pending
	entry.pending = nil
	entry.pendBytes = 0
	entry.pendMu.Unlock()
	entry.signalReady()
	traceDataPlane("relay SESSION_READY committed", "session", hexNode([16]byte(entry.id))[:8], "staged", len(pending))
	for i := range pending {
		frame := &pending[i]
		if err := rt.forwardRelayFrame(entry.scope, *frame); err != nil {
			// A frame that was never enqueued is dropped and wiped; every frame
			// still after it was never forwarded either, so it is dropped too.
			// The relay path is latched broken, so nothing further is staged or
			// forwarded for this Session while the physical Link stays healthy.
			releaseStagedFrame(entry, frame)
			for j := i + 1; j < len(pending); j++ {
				releaseStagedFrame(entry, &pending[j])
			}
			entry.markRelayPathBroken()
			traceDataPlane("relay staged forward failed", "session", hexNode([16]byte(entry.id))[:8], "err", err.Error())
			return
		}
		// Enqueue transferred the bytes to the outbound write's own reservation,
		// which still aliases the same backing until the writer completes; return
		// the staged lease without wiping a buffer that is about to be sent.
		releaseStagedReservation(entry, frame)
	}
}

// forwardRelayFrame forwards one staged opaque frame along the installed path.
func (rt *streamRuntime) forwardRelayFrame(scope pathScope, frame pendingFrame) error {
	ps := rt.pathByScope(scope)
	if ps == nil {
		return link.ErrEndToEndMessage
	}
	return rt.forwardOpaque(ps, frame.envelope, frame.body, frame.hop)
}

// forwardOpaque relays one already hop-authenticated E2E body toward the next hop
// without touching the inner layer. The envelope is forwarded byte-for-byte so
// the endpoints' E2E AAD is unchanged.
func (rt *streamRuntime) forwardOpaque(ps *pathState, envelope, body []byte, hop link.HopRoute) error {
	start := time.Now()
	dst := envelopeNode(envelope, envelopeDstOffset)
	dstIndex := -1
	for index, node := range ps.nodes {
		if [16]byte(node) == dst {
			dstIndex = index
			break
		}
	}
	if dstIndex < 0 {
		return link.ErrInvalidHopRoute
	}
	next := ps.hopIndexToward(dstIndex)
	if next < 0 || next >= len(ps.nodes) {
		return link.ErrInvalidHopRoute
	}
	out := rt.dataPumpOnPath(ps, next)
	if out == nil {
		return errNoDataPath
	}
	// The egress half of an opaque relay CONTROL_RPC is charged exactly once on
	// the exact outbound physical Link, whether this is the immediate forward or
	// the later drain of a staged frame, so a staged frame is never re-counted.
	// A refusal drops only this control frame and leaves the Link healthy.
	if envelopeMessageType(envelope) == wire.MessageTypeControlRPC {
		if err := rt.chargeRelayControlRPC(out, false); err != nil {
			return errRelayStagedRefused
		}
	}
	sessionID := envelopeSessionID(envelope)
	class, err := classOfLane(ps.lane)
	if err != nil {
		return err
	}
	if err := out.control.AdmitSession(sessionID, byte(class)); err != nil {
		return err
	}
	elapsed := forwardElapsedMicros(start)
	if elapsed >= hop.RemainingBudget {
		return ErrLinkDown
	}
	return out.sendEndToEnd(envelope, body, link.HopRoute{Cursor: uint8(next), HopLimit: hop.HopLimit, RemainingBudget: hop.RemainingBudget - elapsed})
}

// errRelayStagedRefused reports that a relay staged ciphertext could not be
// admitted by the shared allocator. It is a scoped failure of one relay
// Session's forwarding path, never a physical Link failure: the caller breaks
// the forwarding of that Session and leaves the Link Ready.
var errRelayStagedRefused = errors.New("relay staged ciphertext refused")

// relayPathBroken reports whether this relay Session's forwarding path has been
// latched terminal by a scoped resource refusal.
func (entry *sessionEntry) relayPathBroken() bool {
	if entry == nil {
		return false
	}
	entry.pendMu.Lock()
	defer entry.pendMu.Unlock()
	return entry.stagedRefused
}

// markRelayPathBroken latches this relay Session's forwarding path terminal, so
// no further frame of it is charged, staged or forwarded. The physical Link and
// every other Session are untouched.
func (entry *sessionEntry) markRelayPathBroken() {
	if entry == nil {
		return
	}
	entry.pendMu.Lock()
	entry.stagedRefused = true
	entry.pendMu.Unlock()
	entry.markTerminated()
}

// failStagedInboundRefusal fails only the offending Session when a staged
// inbound ciphertext cannot be admitted by the shared allocator or by its own
// per-Session reservation. The physical Link stays healthy. It is never a silent
// drop: the caller traces the refusal first, and markTerminated makes the failure
// observable to every circuit-facing boundary that would otherwise keep sending
// on a dead Session. The Session's already-open Circuits are failed locally
// through the Manager-owned FailSession API, which wakes their blocked readers
// with ErrSessionLost and refuses later Opens for the same scope without
// submitting a wire frame or closing the Link.
func (rt *streamRuntime) failStagedInboundRefusal(entry *sessionEntry) {
	if entry == nil || entry.sess == nil {
		return
	}
	_ = entry.sess.Abort()
	entry.markTerminated()
	if err := rt.circuits.FailSession(circuit.SessionRef{
		ID:             circuit.SessionID(entry.id),
		PathID:         entry.scope.id,
		PathGeneration: entry.scope.gen,
	}, circuit.ErrSessionLost); err != nil {
		traceDataPlane("scoped Session Circuits not failed",
			"session", hexNode([16]byte(entry.id))[:8], "err", err.Error())
	}
}

// stageRelayFrame holds one hop-authenticated E2E frame until the matching
// SESSION_READY commits this relay, bounded by the frozen pending-frame count and
// an explicit per-session byte ceiling. It never opens the inner ciphertext.
//
// A rootless relay holds no *session.Session, so there is no per-Session pending
// reservation to take or release: the queue is bounded here directly against the
// same frozen session.MaxPendingBytes ceiling, and the copied envelope+body plus
// one pendingFrame metadata allowance are booked as one shared all-or-none
// composite under the exact physical ingress Link before either copy. The
// reservation is released on forward (ownership transferred to the outbound
// write), on drop, and on the terminal close.
//
// A shared-allocator refusal is never a silent drop: it latches this relay
// Session's forwarding path terminal and returns errRelayStagedRefused, so the
// caller stops forwarding this Session without tearing down the physical Link.
func (rt *streamRuntime) stageRelayFrame(entry *sessionEntry, pump *controlPump, envelope, body []byte, hop link.HopRoute) error {
	if entry == nil {
		return link.ErrSessionNotAdmitted
	}
	entry.pendMu.Lock()
	if entry.stagedRefused {
		entry.pendMu.Unlock()
		return errRelayStagedRefused
	}
	if entry.stagedClosed {
		entry.pendMu.Unlock()
		return nil
	}
	if entry.pendReady {
		entry.pendMu.Unlock()
		return rt.forwardRelayFrame(entry.scope, pendingFrame{envelope: envelope, body: body, hop: hop})
	}
	if len(entry.pending) >= pendingSessionFrames || entry.pendBytes+len(body) > session.MaxPendingBytes {
		entry.pendMu.Unlock()
		return nil
	}
	// Book the shared composite before either copy. A refusal latches the relay
	// Session's forwarding path terminal with a typed scoped error rather than
	// dropping business ciphertext invisibly.
	lease, err := rt.n.reservePendingCiphertext(pump, len(envelope), len(body))
	if err != nil {
		entry.stagedRefused = true
		entry.pendMu.Unlock()
		// Mark the Session terminal after releasing pendMu, so every
		// circuit-facing boundary observes the scoped failure.
		entry.markTerminated()
		traceDataPlane("relay staged frame refused; relay path terminal", "session", hexNode([16]byte(entry.id))[:8], "err", err.Error())
		return errRelayStagedRefused
	}
	entry.pending = append(entry.pending, pendingFrame{
		pump:     pump,
		envelope: append([]byte(nil), envelope...),
		body:     append([]byte(nil), body...),
		message:  envelopeMessageType(envelope),
		hop:      hop,
		lease:    lease,
	})
	entry.pendBytes += len(body)
	entry.pendMu.Unlock()
	return nil
}

// --- Session bootstrap -------------------------------------------------------

// handleSessionCtrl processes one SESSION_CTRL. The internal canonical Src/Dst
// always describe the logical Path source/target so both sides build the same
// session table key; the wire envelope is routed by its actual src/dst.
func (rt *streamRuntime) handleSessionCtrl(pump *controlPump, message link.ProtectedMessage, pathID uint64, pathGen uint32) error {
	ctrl, err := session.DecodeSessionCtrl(message.Payload)
	if err != nil {
		return err
	}
	// The envelope SessionID is the session table key, and the wire src/dst must
	// be exactly the logical A/B endpoints of this direction (a responder's
	// reply legitimately arrives B->A). The payload must not be able to name a
	// different session or direction than the envelope it arrived in.
	if ctrl.SessionID != envelopeSessionID(message.Envelope) {
		return link.ErrRouteMessage
	}
	ps := rt.pathByScope(pathScope{id: pathID, gen: pathGen})
	if ps == nil {
		return link.ErrRouteMessage
	}
	if forward, reverse := ps.directionOnPath(message.Envelope); !forward && !reverse {
		return link.ErrRouteMessage
	}
	// PathID/PathGeneration are envelope-owned and DecodeSessionCtrl leaves them
	// zero; the session table key and peer resolution need the authenticated Path
	// scope, so fill them from this frame before HandleOpen.
	ctrl.PathID = pathID
	ctrl.PathGeneration = pathGen
	traceDataPlane("SESSION_CTRL received", "session", hexNode([16]byte(ctrl.SessionID))[:8], "attempt", ctrl.Attempt)
	src := [16]byte(ps.nodes[0])
	dst := [16]byte(ps.nodes[len(ps.nodes)-1])
	if existing := rt.sessionEntryByID(ctrl.SessionID); existing != nil && existing.initiator {
		// The responder's reply completes this initiator handshake (NoiseFinish).
		// Root material is only staged (Session.pendingRoot); Session.Root() is
		// still nil until the peer's SESSION_READY commits the attempt, so the
		// local E2E protectors must not be built here. Answer with SESSION_READY
		// first: that message needs no root, and the peer's reply READY is what
		// commits this side (handleSessionReady -> ensureProtectors).
		ctrl.SrcNodeID = src
		ctrl.DstNodeID = dst
		ctx, cancel := context.WithTimeout(rt.n.ctx, 10*time.Second)
		defer cancel()
		if _, _, err := rt.sessions.HandleOpen(ctx, ctrl); err != nil {
			return err
		}
		return rt.sendSessionReady(ps, existing)
	}
	ctrl.SrcNodeID = src
	ctrl.DstNodeID = dst
	ctx, cancel := context.WithTimeout(rt.n.ctx, 10*time.Second)
	defer cancel()
	sess, out, err := rt.sessions.HandleOpen(ctx, ctrl)
	if err != nil {
		return err
	}
	entry := rt.sessionEntryFor(sess, ps, false)
	// The responder freezes the accepted attempt identity (committedAttempt+1
	// for a rekey); the session package already rejected a stale or future
	// attempt before HandleOpen returned, so this only records what HandleOpen
	// legalized.
	entry.acceptAttempt(ctrl.Attempt, ctrl.TargetEpoch)
	// The responder root is only staged by NoiseRespond; it is committed by the
	// initiator's SESSION_READY. Do not build protectors before that commit.
	reply := session.SessionCtrl{
		SessionID:   sess.ID(),
		Class:       ctrl.Class,
		DataLaneID:  ctrl.DataLaneID,
		Attempt:     ctrl.Attempt,
		TargetEpoch: ctrl.TargetEpoch,
		Payload:     out,
	}
	payload, err := reply.Encode()
	if err != nil {
		return err
	}
	return rt.sendRoutePayload(ps, wire.MessageTypeSessionCtrl, [16]byte(sess.ID()), payload, true, ps.pathBudget())
}

func (rt *streamRuntime) handleSessionReady(message link.ProtectedMessage, pathID uint64, pathGen uint32) error {
	ready, err := session.DecodeSessionReady(message.Payload)
	if err != nil {
		return err
	}
	// The envelope SessionID and Path scope, plus the frozen class/lane/attempt/
	// target-epoch identity, must all match the local session before HandleReady
	// or MarkActive may change any state.
	if ready.SessionID != envelopeSessionID(message.Envelope) {
		return link.ErrRouteMessage
	}
	entry := rt.sessionEntryByID(ready.SessionID)
	if entry == nil {
		return nil
	}
	if entry.scope.id != pathID || entry.scope.gen != pathGen {
		return link.ErrRouteMessage
	}
	if ready.Class != entry.class || ready.DataLaneID != entry.lane {
		return link.ErrRouteMessage
	}
	// The READY must name exactly the committed identity (a duplicate or
	// retransmitted READY) or the coalesced next attempt staged by a valid
	// HandleOpen/Session.Rekey. Anything else — including any attempt or epoch
	// above the committed one that no local attempt registered — is refused as
	// a route error before any session state is mutated.
	committedAttempt, committedEpoch, rekeyPending, rekeyAttempt, rekeyEpoch := entry.identityView()
	matchesCommitted := ready.Attempt == committedAttempt && ready.TargetEpoch == committedEpoch
	matchesPending := rekeyPending && ready.Attempt == rekeyAttempt && ready.TargetEpoch == rekeyEpoch
	if !matchesCommitted && !matchesPending {
		traceDataPlane("SESSION_READY identity mismatch", "session", hexNode([16]byte(entry.id))[:8],
			"attempt", ready.Attempt, "want", committedAttempt, "epoch", ready.TargetEpoch, "want_epoch", committedEpoch)
		return link.ErrRouteMessage
	}
	// Src/Dst are envelope-owned on the wire; the session table is keyed by the
	// canonical logical endpoints so both directions resolve the same entry. The
	// envelope only routed the frame here; validate the internal identity
	// independently instead of trusting the envelope to name the session scope.
	ready.SrcNodeID = entry.src
	ready.DstNodeID = entry.dst
	if err := rt.sessions.HandleReady(ready); err != nil {
		// A duplicate READY (same committed attempt/epoch) is idempotent in the
		// session package; a stale one must be dropped, not turned into a Link
		// failure.
		traceDataPlane("SESSION_READY not committed", "session", hexNode([16]byte(entry.id))[:8], "err", err.Error())
		return nil
	}
	traceDataPlane("SESSION_READY received", "session", hexNode([16]byte(entry.id))[:8], "initiator", entry.initiator, "epoch", ready.TargetEpoch)
	// HandleReady committed the root; only now may the directional E2E
	// protectors install that committed epoch (the same pair on a rekey) and the
	// staged inbound ciphertext drain. ensureProtectors never recreates a
	// protector and never resets the other epoch's counters or replay window.
	if err := rt.ensureProtectors(entry); err != nil {
		return err
	}
	rt.traceInstalledEpoch(entry, ready.TargetEpoch)
	rt.commitSession(entry)
	if err := rt.admitSessionOnDataPumps(entry); err != nil {
		return err
	}
	if !entry.initiator {
		// Target side: the matching SESSION_READY promotes the accepted
		// OpenPending Path to Active, then answer toward the logical source so
		// the source can commit its own root.
		ps := rt.pathByScope(pathScope{id: pathID, gen: pathGen})
		if ps != nil {
			if err := ps.handle.MarkActive(); err != nil {
				return err
			}
			return rt.sendSessionReady(ps, entry)
		}
	}
	return nil
}

func (rt *streamRuntime) sessionEntryFor(sess *session.Session, ps *pathState, initiator bool) *sessionEntry {
	if existing := rt.sessionEntryByID(sess.ID()); existing != nil {
		return existing
	}
	entry := &sessionEntry{
		id:        sess.ID(),
		scope:     ps.scope,
		class:     sess.Class(),
		lane:      sess.Lane(),
		src:       [16]byte(ps.nodes[0]),
		dst:       [16]byte(ps.nodes[len(ps.nodes)-1]),
		initiator: initiator,
		sess:      sess,
		ready:     make(chan struct{}),
	}
	if static, ok := rt.peerStatic(ps.nodes[ps.dstIndex()]); ok {
		entry.peerStatic = static
	}
	rt.registerSession(entry)
	return entry
}

// ensureProtectors installs the committed Session root's KeyEpoch into this
// entry's directional protectors. On the first commit it creates the pair; on a
// rekey commit it installs the newly committed epoch into the SAME protectors.
// It never recreates a protector, never resets a replay window and never drops
// the previous epoch's key before its frozen grace expires.
func (rt *streamRuntime) ensureProtectors(entry *sessionEntry) error {
	re, ok := entry.sess.RootEpoch()
	if !ok {
		return ErrLinkDown
	}
	defer clear(re.Root)
	entry.protMu.Lock()
	havePair := entry.tx != nil && entry.rx != nil
	entry.protMu.Unlock()
	if !havePair {
		return rt.createProtectors(entry, re)
	}
	return rt.installCommittedEpoch(entry, re)
}

// createProtectors builds the tx/rx pair once from the committed root and
// installs the committed epoch (never a hardcoded 1). Creation is single-flight:
// a concurrent commit that already built the pair is left untouched.
func (rt *streamRuntime) createProtectors(entry *sessionEntry, re session.RootEpoch) error {
	policy := rt.e2ePolicySnapshot()
	txDirection := session.DirectionInitiatorToResponder
	if !entry.initiator {
		txDirection = session.DirectionResponderToInitiator
	}
	base := session.E2EConfig{
		Root:           append([]byte(nil), re.Root...),
		SrcNodeID:      entry.src,
		DstNodeID:      entry.dst,
		PathID:         entry.scope.id,
		PathGeneration: entry.scope.gen,
		SessionID:      entry.id,
		Class:          entry.class,
		// The one Network-lifetime failed-tag ledger is injected into every
		// directional E2E protector of this Network, exactly as it is into every
		// hop protector, so a rejected inner tag aggregates across Sessions and
		// across a rekey instead of restarting per key. Without this the E2E
		// plane would enforce only each protector's private per-key ceiling.
		VerificationBudget: rt.n.verificationBudget(),
	}
	txCfg := base
	txCfg.Direction = txDirection
	rxCfg := base
	rxCfg.Direction = txDirection.Opposite()

	entry.txMu.Lock()
	entry.protMu.Lock()
	if entry.tx != nil && entry.rx != nil {
		entry.protMu.Unlock()
		entry.txMu.Unlock()
		return nil
	}
	tx, err := session.NewE2EProtectorForContext(rt.n.networkContext, txCfg, policy)
	if err != nil {
		entry.protMu.Unlock()
		entry.txMu.Unlock()
		return err
	}
	if err := tx.InstallEpoch(re.Epoch, re.Root); err != nil {
		tx.Close()
		entry.protMu.Unlock()
		entry.txMu.Unlock()
		return err
	}
	rx, err := session.NewE2EProtectorForContext(rt.n.networkContext, rxCfg, policy)
	if err != nil {
		tx.Close()
		entry.protMu.Unlock()
		entry.txMu.Unlock()
		return err
	}
	if err := rx.InstallEpoch(re.Epoch, re.Root); err != nil {
		tx.Close()
		rx.Close()
		entry.protMu.Unlock()
		entry.txMu.Unlock()
		return err
	}
	entry.tx, entry.rx = tx, rx
	entry.installedEpoch = re.Epoch
	entry.protMu.Unlock()
	entry.txMu.Unlock()
	entry.finishRekeyInstall(re.Epoch)
	return nil
}

// installCommittedEpoch installs one newly committed epoch into the EXISTING
// tx/rx pair under txMu+protMu. Both protectors are preflighted with
// CanInstallEpoch before either is mutated, so a refused install (the frozen
// third-install grace, a closed protector or a malformed root) leaves both old
// keys and both replay windows completely untouched. An ErrEpochRetained
// refusal is deferred, not failed: the runtime keeps sealing the old epoch and a
// later poll completes the install once the grace expires, but the deferral is
// bounded by one frozen epoch-grace budget — if the retained previous epoch's
// grace clock never starts, the retry path fails only this Session/Path scoped
// instead of leaving an active Session committed ahead of its protectors.
func (rt *streamRuntime) installCommittedEpoch(entry *sessionEntry, re session.RootEpoch) error {
	entry.txMu.Lock()
	entry.protMu.Lock()
	tx, rx := entry.tx, entry.rx
	if tx == nil || rx == nil {
		entry.protMu.Unlock()
		entry.txMu.Unlock()
		return ErrLinkDown
	}
	txAt, rxAt := tx.CurrentEpoch() == re.Epoch, rx.CurrentEpoch() == re.Epoch
	if !txAt || !rxAt {
		var preflightErr error
		if !txAt {
			preflightErr = tx.CanInstallEpoch(re.Epoch)
		}
		if preflightErr == nil && !rxAt {
			preflightErr = rx.CanInstallEpoch(re.Epoch)
		}
		if preflightErr != nil {
			entry.protMu.Unlock()
			entry.txMu.Unlock()
			if errors.Is(preflightErr, session.ErrEpochRetained) {
				// Third-install retention: old key/drop is NOT taken early.
				// The deferral is recorded with its one bounded window; the
				// retry path fails this Session scoped if the retained
				// previous epoch's grace never lets the install complete.
				entry.deferRekeyInstall(re.Epoch, re.Root, rt.rekeyInstallClock())
				return nil
			}
			return preflightErr
		}
		if !txAt {
			if err := tx.InstallEpoch(re.Epoch, re.Root); err != nil {
				entry.protMu.Unlock()
				entry.txMu.Unlock()
				return err
			}
		}
		if !rxAt {
			if err := rx.InstallEpoch(re.Epoch, re.Root); err != nil {
				entry.protMu.Unlock()
				entry.txMu.Unlock()
				return err
			}
		}
	}
	entry.installedEpoch = re.Epoch
	entry.protMu.Unlock()
	entry.txMu.Unlock()
	entry.finishRekeyInstall(re.Epoch)
	return nil
}

// commitSession marks the local Session committed and drains the bounded
// staging buffer. Staged frames hold hop-authenticated inner ciphertext: each is
// decrypted with the now-unlocked Session root, its inner tag is verified, the
// hop replay floor is committed only after that success, and only then is the
// business plaintext delivered to its endpoint core.
func (rt *streamRuntime) commitSession(entry *sessionEntry) {
	entry.pendMu.Lock()
	entry.pendReady = true
	entry.pendMu.Unlock()
	entry.signalReady()
	rt.drainStaged(entry)
}

// drainStaged opens and delivers every staged inbound frame in arrival order
// through the generic opened-frame dispatcher (Packet/Flow/Circuit). A frame of
// an epoch that is not installed yet (a deferred third install) is re-staged
// rather than dropped or opened under the wrong key. Each reservation is
// released exactly once, whether it was delivered, re-staged or dropped.
//
// Different lane/Link reader goroutines may append while this drainer works, so
// one drainer owns the hand-off (pendDraining) and loops until no appended frame
// is left behind. A terminal release (stagedClosed) that races the drain wins:
// the snapshot and every re-stage candidate are dropped and wiped instead of
// being re-queued onto a ledger that no longer owns them.
func (rt *streamRuntime) drainStaged(entry *sessionEntry) {
	if entry == nil {
		return
	}
	entry.pendMu.Lock()
	if entry.stagedClosed {
		pending := entry.pending
		entry.pending = nil
		entry.pendBytes = 0
		entry.pendMu.Unlock()
		for i := range pending {
			releaseStagedFrame(entry, &pending[i])
		}
		return
	}
	if entry.pendDraining {
		entry.pendMu.Unlock()
		return
	}
	entry.pendDraining = true
	entry.pendMu.Unlock()
	defer func() {
		entry.pendMu.Lock()
		entry.pendDraining = false
		entry.pendMu.Unlock()
	}()

	entry.protMu.Lock()
	rx := entry.rx
	rxEpoch := uint32(0)
	if rx != nil {
		rxEpoch = rx.CurrentEpoch()
	}
	entry.protMu.Unlock()

	for {
		entry.pendMu.Lock()
		pending := entry.pending
		entry.pending = nil
		entry.pendBytes = 0
		closed := entry.stagedClosed
		entry.pendMu.Unlock()
		if len(pending) == 0 {
			return
		}
		if closed || rx == nil {
			for i := range pending {
				releaseStagedFrame(entry, &pending[i])
			}
			return
		}
		var requeue []pendingFrame
		for i := range pending {
			frame := &pending[i]
			epoch := envelopeEpoch(frame.envelope)
			if epoch != 0 && rxEpoch != 0 && epoch > rxEpoch {
				requeue = append(requeue, *frame)
				continue
			}
			plaintext, err := rx.Open(wire.Frame{Kind: wire.FrameKindEndToEnd, Envelope: frame.envelope, Body: frame.body})
			if err == nil {
				rt.recordAuthenticatedEpoch(entry, frame.envelope, rxEpoch)
				if commitErr := frame.pump.control.CommitEndToEnd(envelopeSessionID(frame.envelope), epoch, envelopeNumber(frame.envelope)); commitErr == nil {
					if deliverErr := rt.deliverOpenedFrame(frame.protected, entry, plaintext, frame.pump); deliverErr != nil {
						traceDataPlane("staged frame delivery failed", "kind", uint8(frame.message))
					}
				}
			}
			releaseStagedFrame(entry, frame)
		}
		if len(requeue) > 0 {
			entry.pendMu.Lock()
			if entry.stagedClosed {
				entry.pendMu.Unlock()
				for i := range requeue {
					releaseStagedFrame(entry, &requeue[i])
				}
				return
			}
			entry.pending = append(requeue, entry.pending...)
			for i := range requeue {
				entry.pendBytes += len(requeue[i].body)
			}
			entry.pendMu.Unlock()
			return
		}
	}
}

// recordAuthenticatedEpoch forwards the trusted "peer committed this epoch"
// lifecycle event to the TX protector, but ONLY when the authenticated
// envelope's epoch is exactly the RX protector's current epoch. A frame opened
// under an old (grace) epoch never starts the new epoch's retirement clock.
func (rt *streamRuntime) recordAuthenticatedEpoch(entry *sessionEntry, envelope []byte, rxEpoch uint32) {
	if rxEpoch == 0 || envelopeEpoch(envelope) != rxEpoch {
		return
	}
	entry.protMu.Lock()
	tx := entry.tx
	entry.protMu.Unlock()
	if tx != nil {
		_ = tx.MarkPeerNewEpochAuthenticated(rxEpoch)
	}
}

// e2ePolicySnapshot returns the runtime's E2E protector policy under mu so a
// test seam update is race-free with protector construction.
func (rt *streamRuntime) e2ePolicySnapshot() session.E2EPolicy {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.e2ePolicy
}

// admitSessionOnDataPumps installs the keyless hop admission of one committed
// Session on every adjacent STREAM Link of its installed Path. The link layer
// never admits a session implicitly from an inbound envelope (it derives the
// per-hop subkey from the admission), so the runtime must admit before the peer
// can send or receive any E2E frame. No Session root is involved: a relay can
// admit the same SessionID/class without holding inner keys.
func (rt *streamRuntime) admitSessionOnDataPumps(entry *sessionEntry) error {
	if entry == nil {
		return nil
	}
	ps := rt.pathByScope(entry.scope)
	if ps == nil {
		return nil
	}
	class, err := classOfLane(ps.lane)
	if err != nil {
		return err
	}
	for index := 0; index < len(ps.nodes); index++ {
		if index == ps.localIndex {
			continue
		}
		if index != ps.localIndex-1 && index != ps.localIndex+1 {
			continue
		}
		pump := rt.dataPumpOnPath(ps, index)
		if pump == nil {
			continue
		}
		if err := pump.control.AdmitSession([16]byte(entry.id), byte(class)); err != nil {
			return err
		}
	}
	return nil
}

func (rt *streamRuntime) sendSessionReady(ps *pathState, entry *sessionEntry) error {
	// The READY names the identity being negotiated: the coalesced next attempt
	// while it is staged, otherwise the committed identity. The committed
	// identity is promoted only after the matching READY installs.
	attempt, epoch := entry.negotiatingIdentity()
	ready := session.SessionReady{
		SessionID:      entry.id,
		Class:          entry.class,
		DataLaneID:     entry.lane,
		Attempt:        attempt,
		TargetEpoch:    epoch,
		PathID:         ps.scope.id,
		PathGeneration: ps.scope.gen,
	}
	payload, err := ready.Encode()
	if err != nil {
		return err
	}
	// Direction follows the logical role: an initiator (source) sends READY
	// toward the target, a responder sends it back toward the source.
	// entry.initiator is the authoritative flag; assuming "always reverse" sends
	// an initiator's READY away from the target and stalls the handshake.
	return rt.sendRoutePayload(ps, wire.MessageTypeSessionReady, [16]byte(entry.id), payload, !entry.initiator, ps.pathBudget())
}

// hopBudgetMicros caps one Path attempt's budget by the caller's remaining
// deadline and the frozen 30s overlay ceiling. Without a caller deadline the
// ceiling applies.
func hopBudgetMicros(ctx context.Context) uint32 {
	remaining := uint32(defaultHopBudgetMicros)
	if deadline, ok := ctx.Deadline(); ok {
		left := time.Until(deadline).Microseconds()
		if left <= 0 {
			return 1
		}
		// Compare through uint64 so a negative remainder can never wrap into a
		// huge positive budget, and never exceed the frozen 30s ceiling.
		if uint64(left) < uint64(remaining) {
			remaining = uint32(left)
		}
	}
	if remaining == 0 {
		return 1
	}
	return remaining
}

// pathBudget returns the remaining budget of an established path, never zero so
// a reply cannot be sent with an exhausted (and thus unmetered) budget.
func (ps *pathState) pathBudget() uint32 {
	if ps.budget == 0 {
		return 1
	}
	return ps.budget
}

// sendRoutePayload sends one bootstrap ROUTE_CTRL frame from this node. reverse
// selects the logical direction: false sends toward the Path target (forward
// hop from the source), true sends toward the logical source. The envelope dst
// is always the final logical endpoint (not the immediate hop) so a relay can
// derive the direction from envelope src/dst; the hop cursor is the immediate
// next hop.
func (rt *streamRuntime) sendRoutePayload(ps *pathState, messageType wire.MessageType, sessionID [16]byte, payload []byte, reverse bool, budget uint32) error {
	outIndex := rt.routeOutIndex(ps, reverse)
	if outIndex < 0 || outIndex >= len(ps.nodes) {
		return ErrLinkDown
	}
	out := rt.controlPumpTo(ps.nodes[outIndex])
	if out == nil {
		return ErrLinkDown
	}
	dstIndex := len(ps.nodes) - 1
	if reverse {
		dstIndex = 0
	}
	src := ps.nodes[ps.localIndex]
	dst := ps.nodes[dstIndex]
	if budget == 0 {
		budget = ps.pathBudget()
	}
	envelope := buildEnvelope(rt.wireID, [16]byte(src), [16]byte(dst), messageType, sessionID, 0, 0, ps.scope.id, ps.scope.gen, len(payload))
	return out.sendRoute(envelope, payload, link.HopRoute{Cursor: uint8(outIndex), HopLimit: overlayHopLimit, RemainingBudget: budget})
}

// routeOutIndex returns the hop index one frame must leave through. Forward
// frames go toward the Path target; reverse frames go back toward the logical
// source. The envelope dst is always that next hop's node.
func (rt *streamRuntime) routeOutIndex(ps *pathState, reverse bool) int {
	local := ps.localIndex
	if len(ps.nodes) < 2 {
		return -1
	}
	if reverse {
		if local == 0 {
			return 1
		}
		return local - 1
	}
	if local == len(ps.nodes)-1 {
		return local - 1
	}
	return local + 1
}

// --- dial -------------------------------------------------------------------

func (rt *streamRuntime) dialStream(ctx context.Context, address netip.AddrPort) (Stream, error) {
	if ctx == nil {
		return nil, invalidConfig("context", "must not be nil")
	}
	resolution, err := rt.n.facts.routes.ResolveVirtualIP(address.Addr())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoRoute, err)
	}
	target := resolution.NodeID
	if [16]byte(target) == rt.localID {
		return nil, fmt.Errorf("%w: destination is the local node", ErrPermissionDenied)
	}
	pair, err := rt.readyPairFor(ctx, target, session.SessionClassStream, session.LaneStream)
	if err != nil {
		return nil, err
	}
	candidate := circuit.Candidate{
		PathID:           pair.ps.scope.id,
		PathGeneration:   pair.ps.scope.gen,
		RouteViewVersion: pair.ps.viewVersion,
		PathDigest:       pair.ps.digest,
		Session: circuit.SessionRef{
			ID:             circuit.SessionID(pair.entry.id),
			PathID:         pair.ps.scope.id,
			PathGeneration: pair.ps.scope.gen,
		},
	}
	c, err := rt.circuits.Open(ctx, circuit.OpenRequest{
		TargetNodeID: circuit.NodeID(target),
		TargetPort:   address.Port(),
		Candidates:   []circuit.Candidate{candidate},
		Budget:       circuit.MaxOpenBudget,
	})
	if err != nil {
		return nil, mapCircuitError(err)
	}
	return newCircuitStream(rt, c, NodeID(hexNode([16]byte(target)))), nil
}

// readyPairFor single-flights one Path+Session per (target node, class) and
// reuses it for every later Circuit of that class. A successful pair is
// intentionally retained for the Network lifetime (its Path/Session tables hold
// the shared state); only a failed establishment is removed so a later Dial can
// retry.
func (rt *streamRuntime) readyPairFor(ctx context.Context, target topology.NodeID, class session.SessionClass, lane session.Lane) (*readyPair, error) {
	key := pairKey{node: target, class: class}
	for {
		rt.mu.Lock()
		if rt.closed {
			rt.mu.Unlock()
			return nil, ErrClosed
		}
		if pair, ok := rt.pairs[key]; ok {
			rt.mu.Unlock()
			select {
			case <-pair.ready:
				if pair.err != nil {
					return nil, pair.err
				}
				if rt.pairUsable(pair) {
					return pair, nil
				}
				// The cached Path/Session is no longer usable. Drop only this
				// exact stale entry so the next iteration establishes a fresh
				// pair; a Circuit that already pinned the old scope keeps
				// failing closed instead of being silently re-pointed at a new
				// Path. An entry still being established has a nil ps and is
				// never dropped by a concurrent waiter.
				rt.mu.Lock()
				if current := rt.pairs[key]; current == pair {
					delete(rt.pairs, key)
				}
				rt.mu.Unlock()
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-rt.n.ctx.Done():
				return nil, ErrClosed
			}
		}
		pair := &readyPair{ready: make(chan struct{})}
		rt.pairs[key] = pair
		rt.mu.Unlock()

		ps, entry, err := rt.establishPair(ctx, target, class, lane)
		rt.mu.Lock()
		if err != nil {
			pair.err = err
			delete(rt.pairs, key)
		} else {
			pair.ps, pair.entry = ps, entry
		}
		rt.mu.Unlock()
		close(pair.ready)
		if err != nil {
			return nil, err
		}
		return pair, nil
	}
}

// establishPair opens one Path and one Session of the requested class/lane toward
// a target and leaves both installed so many Circuits share them.
func (rt *streamRuntime) establishPair(ctx context.Context, target topology.NodeID, class session.SessionClass, lane session.Lane) (*pathState, *sessionEntry, error) {
	policy := topology.RoutePolicy{AllowRelay: rt.relay}
	p, err := rt.paths.Open(ctx, target, path.Lane(lane), policy)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNoRoute, err)
	}
	ps := &pathState{
		scope:       pathScope{id: p.ID(), gen: p.Generation()},
		lane:        p.Lane(),
		nodes:       p.Nodes(),
		links:       p.Links(),
		digest:      p.Digest(),
		viewVersion: p.ViewVersion(),
		localIndex:  0,
		source:      true,
		handle:      p,
		ready:       make(chan struct{}),
		budget:      hopBudgetMicros(ctx),
	}
	rt.registerPath(ps)

	open, err := p.OpenFrame()
	if err != nil {
		rt.unregisterPath(ps.scope)
		return nil, nil, err
	}
	if err := rt.sendPathOpen(ps, open, ps.budget); err != nil {
		rt.unregisterPath(ps.scope)
		return nil, nil, err
	}
	if err := rt.waitPathReady(ctx, ps); err != nil {
		rt.unregisterPath(ps.scope)
		return nil, nil, err
	}

	sess, err := rt.sessions.Open(ctx, ps.scope.id, ps.scope.gen, class, lane)
	if err != nil {
		rt.unregisterPath(ps.scope)
		return nil, nil, err
	}
	entry := rt.sessionEntryFor(sess, ps, true)
	attempt := sess.Attempt()
	entry.attempt = attempt.Attempt
	entry.targetEpoch = attempt.TargetEpoch
	ctrl := session.SessionCtrl{
		SessionID:   sess.ID(),
		Class:       class,
		DataLaneID:  lane,
		Attempt:     attempt.Attempt,
		TargetEpoch: attempt.TargetEpoch,
		Payload:     attempt.Bytes,
	}
	payload, err := ctrl.Encode()
	if err != nil {
		rt.unregisterPath(ps.scope)
		return nil, nil, err
	}
	if err := rt.sendRoutePayload(ps, wire.MessageTypeSessionCtrl, [16]byte(sess.ID()), payload, false, ps.budget); err != nil {
		rt.unregisterPath(ps.scope)
		return nil, nil, err
	}
	if err := rt.waitSessionReady(ctx, entry); err != nil {
		rt.unregisterPath(ps.scope)
		return nil, nil, err
	}
	if err := rt.admitSessionOnDataPumps(entry); err != nil {
		rt.unregisterPath(ps.scope)
		return nil, nil, err
	}
	if err := p.MarkActive(); err != nil {
		rt.unregisterPath(ps.scope)
		return nil, nil, err
	}
	traceDataPlane("path+session established", "path", ps.scope.id, "session", hexNode([16]byte(entry.id))[:8], "target", hexNode([16]byte(target))[:8])
	return ps, entry, nil
}

func (rt *streamRuntime) sendPathOpen(ps *pathState, payload []byte, budget uint32) error {
	next := ps.hopIndexToward(ps.dstIndex())
	out := rt.controlPumpTo(ps.nodes[next])
	if out == nil {
		return ErrLinkDown
	}
	// The envelope dst is the FINAL logical target, not the immediate hop: an
	// intermediate hop must see dst != self to forward, and only the target may
	// accept and answer PATH_READY. The hop cursor selects the immediate hop.
	src := ps.nodes[ps.localIndex]
	dst := ps.nodes[ps.dstIndex()]
	if budget == 0 {
		budget = ps.pathBudget()
	}
	envelope := buildEnvelope(rt.wireID, [16]byte(src), [16]byte(dst), wire.MessageTypePathOpen, [16]byte{}, 0, 0, ps.scope.id, ps.scope.gen, len(payload))
	return out.sendRoute(envelope, payload, link.HopRoute{Cursor: uint8(next), HopLimit: overlayHopLimit, RemainingBudget: budget})
}

func (rt *streamRuntime) waitPathReady(ctx context.Context, ps *pathState) error {
	select {
	case <-ps.ready:
		if ps.broken.Load() {
			return ErrNoRoute
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-rt.n.ctx.Done():
		return ErrClosed
	}
}

func (rt *streamRuntime) waitSessionReady(ctx context.Context, entry *sessionEntry) error {
	select {
	case <-entry.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-rt.n.ctx.Done():
		return ErrClosed
	}
}

func hexNode(node [16]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 32)
	for _, b := range node {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

// mapCircuitError maps circuit-layer sentinels onto the SDK error surface
// without inventing new behavior.
func mapCircuitError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, circuit.ErrTargetRefused):
		return fmt.Errorf("%w: %v", ErrTargetRefused, err)
	case errors.Is(err, circuit.ErrNoRoute):
		return fmt.Errorf("%w: %v", ErrNoRoute, err)
	case errors.Is(err, circuit.ErrPermissionDenied):
		return fmt.Errorf("%w: %v", ErrPermissionDenied, err)
	case errors.Is(err, circuit.ErrResource):
		return fmt.Errorf("%w: %v", ErrResource, err)
	case errors.Is(err, circuit.ErrCanceled):
		return fmt.Errorf("%w: %v", ErrClosed, err)
	case errors.Is(err, circuit.ErrSessionLost):
		return fmt.Errorf("%w: %v", ErrSessionLost, err)
	case errors.Is(err, circuit.ErrOutcomeUnknown):
		return fmt.Errorf("%w: %v", ErrOutcomeUnknown, err)
	case errors.Is(err, circuit.ErrLinkDown):
		return fmt.Errorf("%w: %v", ErrLinkDown, err)
	default:
		return err
	}
}
