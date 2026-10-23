package flow

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/topology"
)

// assocIDAttempts bounds the CSPRNG retry loop for a nonzero, unused
// AssociationID; 16 consecutive collisions are treated as resource exhaustion.
const assocIDAttempts = 16

// targetKey isolates inbound REQUEST associations by authenticated originator:
// two SrcNodeIDs may legitimately use the same AssociationID, and their
// replay/assembly state must stay distinct (wire-protocol.md 3.1).
type targetKey struct {
	origin topology.NodeID
	id     AssocID
}

// Manager is the concurrency-safe Flow UDP datagram core for one local node and
// security context. It owns the bounded association set, the recently-closed
// AssociationID ledger, the reassembly state and the injected buffer budget.
type Manager struct {
	cfg   Config
	now   func() time.Time
	rnd   io.Reader
	local *localBudget

	mu             sync.Mutex
	closed         bool
	origins        map[AssocID]*Association
	targets        map[targetKey]*Association
	recent         map[AssocID]time.Time
	tombstones     map[targetKey]time.Time
	assemblies     int
	ledgerLimit    int
	ledgerReserved int
	fullFenceUntil time.Time

	held               atomic.Int64
	sentDatagrams      atomic.Uint64
	sentFragments      atomic.Uint64
	receivedFragments  atomic.Uint64
	deliveredDatagrams atomic.Uint64
	deliveredBytes     atomic.Uint64
	drops              [dropReasonCount]atomic.Uint64
}

// NewManager validates the configuration and builds an empty Manager.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.ContextID == ([32]byte{}) {
		return nil, fmt.Errorf("%w: ContextID is required for AssociationID scope", ErrInvalidConfig)
	}
	if cfg.LocalNode == (topology.NodeID{}) {
		return nil, fmt.Errorf("%w: LocalNode is required", ErrInvalidConfig)
	}
	if cfg.Endpoints == nil {
		return nil, fmt.Errorf("%w: Endpoints is required", ErrInvalidConfig)
	}
	if cfg.Routes == nil {
		return nil, fmt.Errorf("%w: Routes is required", ErrInvalidConfig)
	}
	if cfg.Sender == nil {
		return nil, fmt.Errorf("%w: Sender is required", ErrInvalidConfig)
	}
	if cfg.Delivery == nil {
		return nil, fmt.Errorf("%w: Delivery is required", ErrInvalidConfig)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	source := cfg.Rand
	if source == nil {
		source = rand.Reader
	}
	ledgerLimit := cfg.ClosedAssociationLedgerLimit
	switch {
	case ledgerLimit == 0:
		ledgerLimit = MaxClosedAssociationLedger
	case ledgerLimit < 0 || ledgerLimit > MaxClosedAssociationLedger:
		return nil, fmt.Errorf("%w: ClosedAssociationLedgerLimit %d must be in 1..%d", ErrInvalidConfig, ledgerLimit, MaxClosedAssociationLedger)
	}
	local := &localBudget{limit: DefaultLocalBufferBudget}
	if cfg.Budget == nil {
		cfg.Budget = local
	}
	return &Manager{
		cfg:         cfg,
		now:         now,
		rnd:         source,
		local:       local,
		ledgerLimit: ledgerLimit,
		origins:     make(map[AssocID]*Association),
		targets:     make(map[targetKey]*Association),
		recent:      make(map[AssocID]time.Time),
		tombstones:  make(map[targetKey]time.Time),
	}, nil
}

func (m *Manager) drop(reason DropReason) { m.drops[reason].Add(1) }

// CreateAssociation allocates a nonzero CSPRNG AssociationID that is unused by
// every active association and by every association closed within the last
// AssociationIdleTTL in this (ContextID, originator) scope, then registers a
// REQUEST-origin association. The caller owns the returned Association and must
// Close it.
func (m *Manager) CreateAssociation() (*Association, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	if len(m.origins)+len(m.targets) >= MaxUDPAssociations {
		m.drop(DropResource)
		return nil, fmt.Errorf("%w: %d UDP associations per Network", ErrResourceLimit, MaxUDPAssociations)
	}
	// Reserve the recently-closed record slot up front so Close can always
	// retain this AssociationID's identity: a full identity budget refuses the
	// new association instead of losing the ID at close time.
	if err := m.reserveLedgerLocked(); err != nil {
		m.drop(DropResource)
		return nil, err
	}
	id, err := m.allocAssocIDLocked()
	if err != nil {
		m.releaseLedgerLocked()
		m.drop(DropResource)
		return nil, err
	}
	a := newAssociation(m, id, RoleOrigin, topology.NodeID{})
	a.ledgerHeld = true
	m.origins[id] = a
	return a, nil
}

// reserveLedgerLocked admits one live-or-closed AssociationID identity record.
// A live origin association holds its slot from creation until Close records
// the identity, so the identity budget can never be lost at closing time.
func (m *Manager) reserveLedgerLocked() error {
	m.pruneRecentLocked()
	if now := m.now(); now.Before(m.fullFenceUntil) {
		return fmt.Errorf("%w: AssociationID no-reuse fence active until %s", ErrResourceLimit, m.fullFenceUntil.Format(time.RFC3339Nano))
	}
	if used := len(m.recent) + m.ledgerReserved; used >= m.ledgerLimit {
		return fmt.Errorf("%w: AssociationID identity ledger holds %d of %d records (live reservations plus 120-second closed identities)", ErrResourceLimit, used, m.ledgerLimit)
	}
	m.ledgerReserved++
	return nil
}

func (m *Manager) releaseLedgerLocked() {
	if m.ledgerReserved > 0 {
		m.ledgerReserved--
	}
}

func (m *Manager) allocAssocIDLocked() (AssocID, error) {
	m.pruneRecentLocked()
	var id AssocID
	for attempt := 0; attempt < assocIDAttempts; attempt++ {
		if _, err := io.ReadFull(m.rnd, id[:]); err != nil {
			return AssocID{}, fmt.Errorf("%w: CSPRNG: %v", ErrResourceLimit, err)
		}
		if id == (AssocID{}) {
			continue
		}
		if _, active := m.origins[id]; active {
			continue
		}
		if _, closed := m.recent[id]; closed {
			continue
		}
		return id, nil
	}
	return AssocID{}, fmt.Errorf("%w: no unused AssociationID after %d CSPRNG attempts", ErrResourceLimit, assocIDAttempts)
}

// pruneRecentLocked drops ledger entries older than the 120-second closed-ID
// window. It is the only way an identity record leaves the ledger.
func (m *Manager) pruneRecentLocked() {
	now := m.now()
	for id, closedAt := range m.recent {
		if now.Sub(closedAt) >= AssociationIdleTTL {
			delete(m.recent, id)
		}
	}
}

// noteClosedLocked records id as recently closed. The caller holds a reservation,
// so a slot is available; if the invariant is ever broken it fences ALL new
// AssociationID allocation until this identity's full 120-second window passed,
// and returns false so the caller can report the anomaly. It never evicts an
// unexpired record and never lets an ID be reused early.
func (m *Manager) noteClosedLocked(id AssocID) bool {
	m.pruneRecentLocked()
	if len(m.recent) >= m.ledgerLimit {
		until := m.now().Add(AssociationIdleTTL)
		if until.After(m.fullFenceUntil) {
			m.fullFenceUntil = until
		}
		return false
	}
	m.recent[id] = m.now()
	return true
}

// reserveAssemblySlot admits one more outstanding reassembly buffer. The frozen
// distribution bound is 256 associations x one incomplete assembly per
// direction = 512, whose payload ceiling is 256*2*65,507 = 33,539,584 bytes;
// the payload itself is additionally bounded by the injected buffer budget.
func (m *Manager) reserveAssemblySlot() error {
	if m.assemblies >= MaxNetworkAssemblies {
		return fmt.Errorf("%w: %d outstanding reassembly buffers per Network", ErrResourceLimit, MaxNetworkAssemblies)
	}
	m.assemblies++
	return nil
}

func (m *Manager) releaseAssemblySlot() {
	if m.assemblies > 0 {
		m.assemblies--
	}
}

// Receive is the inbound entry point for one already-authenticated
// UDP_DATAGRAM plaintext frame. envelope must come from the verified E2E frame;
// raw is that frame's payload. Reordered fragments are accepted; the caller
// must have already rejected a failed E2E tag without calling here.
func (m *Manager) Receive(ctx context.Context, envelope AuthenticatedEnvelope, raw []byte) error {
	fragment, err := DecodeFragment(raw)
	if err != nil {
		m.drop(DropSchema)
		m.consumeSchemaDrop(envelope, raw)
		return err
	}
	a, err := m.associationFor(ctx, envelope, fragment)
	if err != nil {
		return err
	}
	return a.receive(ctx, envelope, fragment)
}

// associationFor validates ownership and resolves the association an inbound
// fragment belongs to, creating the target-side association for a REQUEST from
// an authenticated originator. A target association that idled past
// AssociationIdleTTL is expired here (no Sweep required), tombstoned for the
// same window and refused, so a peer cannot permanently jam the association cap
// and stale-metadata fragments cannot reopen a closed window.
func (m *Manager) associationFor(ctx context.Context, envelope AuthenticatedEnvelope, fragment Fragment) (*Association, error) {
	if err := m.validateInbound(ctx, envelope, fragment); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		m.drop(DropClosed)
		return nil, ErrClosed
	}
	now := m.now()
	if fragment.Flags == FlagReply {
		if a := m.origins[fragment.AssociationID]; a != nil {
			return a, nil
		}
		m.drop(DropUnknownAssociation)
		return nil, fmt.Errorf("%w: no local origin association %s for a REPLY from %s",
			ErrUnknownAssociation, fragment.AssociationID, envelope.SrcNodeID)
	}
	key := targetKey{origin: envelope.SrcNodeID, id: fragment.AssociationID}
	if until, ok := m.tombstones[key]; ok {
		if now.Before(until) {
			m.drop(DropUnknownAssociation)
			return nil, fmt.Errorf("%w: target association %s is inside its closed-window tombstone until %s",
				ErrUnknownAssociation, fragment.AssociationID, until.Format(time.RFC3339Nano))
		}
		delete(m.tombstones, key)
	}
	if a := m.targets[key]; a != nil {
		if now.Before(a.lastActivity.Add(AssociationIdleTTL)) {
			return a, nil
		}
		m.expireTargetLocked(a)
		m.drop(DropUnknownAssociation)
		return nil, fmt.Errorf("%w: target association %s expired after %s idle", ErrUnknownAssociation, fragment.AssociationID, AssociationIdleTTL)
	}
	if len(m.origins)+len(m.targets) >= MaxUDPAssociations {
		m.drop(DropResource)
		return nil, fmt.Errorf("%w: %d UDP associations per Network", ErrResourceLimit, MaxUDPAssociations)
	}
	if len(m.tombstones) >= m.ledgerLimit {
		m.drop(DropResource)
		return nil, fmt.Errorf("%w: target identity tombstone ledger holds %d records", ErrResourceLimit, len(m.tombstones))
	}
	a := newAssociation(m, fragment.AssociationID, RoleTarget, envelope.SrcNodeID)
	m.targets[key] = a
	return a, nil
}

// noteTargetTombstoneLocked records an expired target association's identity for
// AssociationIdleTTL. It prunes expired tombstones first.
func (m *Manager) noteTargetTombstoneLocked(key targetKey) {
	now := m.now()
	for k, until := range m.tombstones {
		if !now.Before(until) {
			delete(m.tombstones, k)
		}
	}
	m.tombstones[key] = now.Add(AssociationIdleTTL)
}

// expireTargetLocked closes an idle target association, removes it from the cap
// and tombstones its identity. It is pure cleanup, not a datagram terminal drop,
// so it does not count a drop reason. The caller holds m.mu.
func (m *Manager) expireTargetLocked(a *Association) {
	key := targetKey{origin: a.peer, id: a.id}
	a.closeLocked()
	delete(m.targets, key)
	m.noteTargetTombstoneLocked(key)
}

// Reply sends one UDP reply for a REQUEST datagram previously delivered to this
// node's endpoint. It is the only reply entry point: it requires the opaque
// receipt the core attached to that delivery, so an application cannot fabricate
// reply authority by assembling a Datagram by hand. The presented metadata must
// match the delivered request exactly; the exact live target association is
// re-found and refused if it is closed, expired or tombstoned; and the current
// address ownership is revalidated (reply source still a local VIP, reply
// destination still owned by the original authenticated requester), so a changed
// address refuses the reply instead of re-targeting it.
//
// It never creates an association. The reply reuses the target association's
// REPLY direction (flags=0x01, DatagramID from 1) and reaches the wire through
// the same Sender adapter; the reply payload is 0..65,507 bytes.
//
// The receipt is bound to the association object and its manager, not merely the
// AssociationID: if the target association expired and a new one with the same
// AssociationID was created for the same originator, an old receipt is still
// refused, because the live map entry must be the very association the receipt
// came from.
func (m *Manager) Reply(ctx context.Context, received Datagram, payload []byte) error {
	receipt := received.receipt
	if receipt == nil {
		m.drop(DropReply)
		return fmt.Errorf("%w: datagram was not produced by this manager's delivery", ErrNoReplyAuthority)
	}
	if receipt.manager != m || receipt.association == nil {
		m.drop(DropReply)
		return fmt.Errorf("%w: datagram reply authority belongs to a different manager or generation", ErrNoReplyAuthority)
	}
	if received.Flags != FlagRequest {
		m.drop(DropReply)
		return fmt.Errorf("%w: only a REQUEST datagram carries reply authority", ErrNoReplyAuthority)
	}
	if received.NetworkID != receipt.networkID || received.SrcNodeID != receipt.origin ||
		received.AssociationID != receipt.associationID || received.DatagramID != receipt.datagramID ||
		received.Source != receipt.source || received.Destination != receipt.destination ||
		received.DstNodeID != m.cfg.LocalNode {
		m.drop(DropReply)
		return fmt.Errorf("%w: presented metadata does not match the delivered request", ErrNoReplyAuthority)
	}
	if received.NetworkID != m.cfg.NetworkID {
		m.drop(DropOwnership)
		return fmt.Errorf("%w: datagram NetworkID %d is not this manager's %d", ErrOwnership, received.NetworkID, m.cfg.NetworkID)
	}
	// Ownership is current, not historical: the reply source is the request
	// destination (a local VIP) and the reply destination is the request source,
	// which must still be owned by the original authenticated requester.
	source, ok := m.cfg.Endpoints.LookupEndpoint(ctx, received.Destination.Addr())
	if !ok || source.Owner != m.cfg.LocalNode {
		m.drop(DropOwnership)
		return fmt.Errorf("%w: reply source %s is not a currently owned local endpoint", ErrOwnership, received.Destination)
	}
	destination, ok := m.cfg.Endpoints.LookupEndpoint(ctx, received.Source.Addr())
	if !ok || destination.Owner != receipt.origin {
		m.drop(DropOwnership)
		return fmt.Errorf("%w: reply destination %s is no longer owned by the authenticated requester %s", ErrOwnership, received.Source, receipt.origin)
	}
	key := targetKey{origin: receipt.origin, id: receipt.associationID}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		m.drop(DropClosed)
		return ErrClosed
	}
	now := m.now()
	if until, ok := m.tombstones[key]; ok {
		if now.Before(until) {
			m.mu.Unlock()
			m.drop(DropReply)
			return fmt.Errorf("%w: target association %s is inside its closed-window tombstone", ErrReplyUnavailable, receipt.associationID)
		}
		delete(m.tombstones, key)
	}
	a := m.targets[key]
	// Pointer identity: the live target must be the very association the receipt
	// came from. A recreated association with the same AssociationID after the
	// 120-second window is a different object and refuses the stale receipt.
	if a == nil || a != receipt.association || a.closed || a.role != RoleTarget {
		m.mu.Unlock()
		m.drop(DropReply)
		return fmt.Errorf("%w: target association %s is not the live generation that issued the receipt", ErrReplyUnavailable, receipt.associationID)
	}
	if !now.Before(a.lastActivity.Add(AssociationIdleTTL)) {
		m.expireTargetLocked(a)
		m.mu.Unlock()
		m.drop(DropReply)
		return fmt.Errorf("%w: target association %s expired after %s idle", ErrReplyUnavailable, receipt.associationID, AssociationIdleTTL)
	}
	m.mu.Unlock()
	// Fragment performs the egress and runs outside the manager lock. The reply
	// tuple is the reverse of the request: reply source is the local endpoint,
	// reply destination is the original requester.
	return a.Fragment(ctx, OutboundDatagram{
		Source:      received.Destination,
		Destination: received.Source,
		Payload:     payload,
	})
}

// lookupLocked resolves an existing association by authenticated source and
// inbound direction: REQUEST is the target side (per originator), REPLY is a
// locally created origin association (any responder).
func (m *Manager) lookupLocked(peer topology.NodeID, id AssocID, flags Flags) *Association {
	if flags == FlagReply {
		return m.origins[id]
	}
	return m.targets[targetKey{origin: peer, id: id}]
}

// validateInbound checks the authenticated envelope and the metadata
// ownership: the frame must be addressed to this node, the metadata source must
// be owned by the authenticated envelope source, and the metadata destination
// must be owned by this node according to the current Fact owner map.
func (m *Manager) validateInbound(ctx context.Context, envelope AuthenticatedEnvelope, fragment Fragment) error {
	if envelope.NetworkID != m.cfg.NetworkID {
		m.drop(DropOwnership)
		return fmt.Errorf("%w: envelope NetworkID %d is not this manager's %d", ErrOwnership, envelope.NetworkID, m.cfg.NetworkID)
	}
	if envelope.DstNodeID != m.cfg.LocalNode {
		m.drop(DropOwnership)
		return fmt.Errorf("%w: envelope destination %s is not this local node", ErrOwnership, envelope.DstNodeID)
	}
	owner, ok := m.cfg.Endpoints.LookupEndpoint(ctx, fragment.Source.Addr())
	if !ok || owner.Owner != envelope.SrcNodeID {
		m.drop(DropOwnership)
		return fmt.Errorf("%w: metadata source %s is not owned by authenticated source %s", ErrOwnership, fragment.Source, envelope.SrcNodeID)
	}
	destination, ok := m.cfg.Endpoints.LookupEndpoint(ctx, fragment.Destination.Addr())
	if !ok || destination.Owner != m.cfg.LocalNode {
		m.drop(DropOwnership)
		return fmt.Errorf("%w: metadata destination %s is not a currently owned local endpoint", ErrOwnership, fragment.Destination)
	}
	return nil
}

// consumeSchemaDrop consumes a DatagramID that can still be read from a
// malformed frame when the association is already known. A malformed frame for
// an unknown association leaves no state behind.
func (m *Manager) consumeSchemaDrop(envelope AuthenticatedEnvelope, raw []byte) {
	id, flags, datagramID, ok := headerIdentity(raw)
	if !ok || datagramID == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.lookupLocked(envelope.SrcNodeID, id, flags)
	if a == nil {
		return
	}
	ps := a.peers[envelope.SrcNodeID]
	if ps == nil {
		return
	}
	direction := int(flags)
	if as := ps.assemblies[direction]; as != nil && as.id == datagramID {
		a.discardLocked(ps, direction)
		return
	}
	ps.replay[direction].consume(datagramID)
}

// reserve and release funnel every reassembly buffer through the injected
// shared allocator, or the local self-bound when none was injected.
func (m *Manager) reserve(bytes uint64) error {
	if m.cfg.Budget != nil {
		if err := m.cfg.Budget.Reserve(bytes); err != nil {
			return fmt.Errorf("%w: %v", ErrResourceLimit, err)
		}
	}
	m.held.Add(int64(bytes))
	return nil
}

func (m *Manager) release(bytes uint64) {
	if bytes == 0 {
		return
	}
	if m.cfg.Budget != nil {
		m.cfg.Budget.Release(bytes)
	}
	m.held.Add(-int64(bytes))
}

// Sweep expires incomplete assemblies whose 120-second TTL elapsed, closes idle
// target associations (their identity stays tombstoned for the same window so
// stale metadata cannot reopen the closed window) and prunes the ledgers.
// Assembly expiry is terminal: the DatagramID is consumed and the reservation
// released. Safe to call concurrently with Receive.
func (m *Manager) Sweep() {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.origins {
		a.sweepLocked(now)
	}
	for _, a := range m.targets {
		a.sweepLocked(now)
		if !now.Before(a.lastActivity.Add(AssociationIdleTTL)) {
			m.expireTargetLocked(a)
		}
	}
	for key, until := range m.tombstones {
		if !now.Before(until) {
			delete(m.tombstones, key)
		}
	}
	for id, closedAt := range m.recent {
		if now.Sub(closedAt) >= AssociationIdleTTL {
			delete(m.recent, id)
		}
	}
}

// Stats returns a snapshot of the manager counters and current association
// counts.
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	stats := Stats{
		Associations:     len(m.origins) + len(m.targets),
		Origins:          len(m.origins),
		Targets:          len(m.targets),
		TargetTombstones: len(m.tombstones),
		Assemblies:       m.assemblies,
		ClosedIDs:        len(m.recent),
		LedgerReserved:   m.ledgerReserved,
		LedgerLimit:      m.ledgerLimit,
	}
	for _, a := range m.origins {
		stats.Peers += len(a.peers)
	}
	for _, a := range m.targets {
		stats.Peers += len(a.peers)
	}
	m.mu.Unlock()
	if held := m.held.Load(); held > 0 {
		stats.BytesHeld = uint64(held)
	}
	stats.SentDatagrams = m.sentDatagrams.Load()
	stats.SentFragments = m.sentFragments.Load()
	stats.ReceivedFragments = m.receivedFragments.Load()
	stats.DeliveredDatagrams = m.deliveredDatagrams.Load()
	stats.DeliveredBytes = m.deliveredBytes.Load()
	for i := range m.drops {
		stats.Drops[i] = m.drops[i].Load()
	}
	return stats
}

// Close terminates every association and refuses new inbound or outbound work.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	for _, a := range m.origins {
		a.closeLocked()
	}
	for _, a := range m.targets {
		a.closeLocked()
	}
	m.origins = nil
	m.targets = nil
	return nil
}

// localBudget is the default self-bound used when no shared allocator is
// injected. It never claims the global Network 64 MiB / 256 MiB limits.
type localBudget struct {
	mu    sync.Mutex
	held  uint64
	limit uint64
}

func (b *localBudget) Reserve(bytes uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.held+bytes > b.limit {
		return fmt.Errorf("%w: local flow buffer bound %d exceeded", ErrResourceLimit, b.limit)
	}
	b.held += bytes
	return nil
}

func (b *localBudget) Release(bytes uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if bytes > b.held {
		b.held = 0
		return
	}
	b.held -= bytes
}

// pinRoute resolves and validates the PACKET-lane route pinned for one logical
// datagram before its first fragment.
func (m *Manager) pinRoute(ctx context.Context, destination netip.Addr) (DatagramRoute, error) {
	route, err := m.cfg.Routes.ResolveDatagramRoute(ctx, destination)
	if err != nil {
		m.drop(DropRoute)
		return DatagramRoute{}, err
	}
	if route.DestinationNode == (topology.NodeID{}) {
		m.drop(DropRoute)
		return DatagramRoute{}, fmt.Errorf("%w: resolver returned an empty destination node", ErrRouteChanged)
	}
	if route.Lane != path.LanePacket {
		m.drop(DropRoute)
		return DatagramRoute{}, fmt.Errorf("%w: resolver selected lane %s instead of the PACKET lane", ErrRouteChanged, route.Lane)
	}
	return route, nil
}

// recheckRoute revalidates the pinned owner and Path before each fragment
// egress. A changed owner or Path drops the datagram; it never re-routes.
//
// AddressFactVersion is deliberately NOT compared. An ADDRESS fact's key binds
// the owner NodeID and the exact /32, so a higher version of the same key is
// provably the same owner and the same address, and this node's own fact plane
// advances that version on every local refresh for every peer. Comparing it
// would drop a steady datagram for a renewal that changed no mapping, which the
// frozen C-ROUTE-005 drop criterion (owner changed or conflict) does not ask
// for. A genuinely changed owner still fails closed on DestinationNode below,
// and a withdrawal or address conflict still fails at the resolver.
func (m *Manager) recheckRoute(ctx context.Context, destination netip.Addr, pinned DatagramRoute) error {
	current, err := m.cfg.Routes.ResolveDatagramRoute(ctx, destination)
	if err != nil {
		m.drop(DropRoute)
		return err
	}
	if current.DestinationNode != pinned.DestinationNode ||
		current.PathID != pinned.PathID ||
		current.PathGeneration != pinned.PathGeneration ||
		current.Lane != pinned.Lane {
		m.drop(DropRoute)
		return fmt.Errorf("%w: pinned node %x path %d/%d lane %s is now node %x path %d/%d lane %s",
			ErrRouteChanged,
			pinned.DestinationNode, pinned.PathID, pinned.PathGeneration, pinned.Lane,
			current.DestinationNode, current.PathID, current.PathGeneration, current.Lane)
	}
	return nil
}
