package simpletier

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/topology"
)

// This file wires the authenticated FACT v2 consumer, the outbound snapshot
// sender and the derived RouteView into one running Network. The consumer only
// accepts whole sender snapshots over an already authenticated CONTROL Link: it
// stages the exact pages of one summary, validates page/snapshot digests, key
// order, counts and record semantics, and only then commits atomically. Nothing
// becomes visible unless the durable high-watermark write succeeded, and
// FACT_ACK COMPLETE is sent only after that commit. A Link that leaves the
// registry withdraws exactly its own authenticated ingress provenance. The
// sender (see fact_sender.go) offers immutable whole-store snapshots to every
// registered Link over the same single protected reader/writer.
//
// Boundaries kept deliberately: no PACKET/STREAM data lanes, no
// Path/Session/Circuit, no remote Stream and no Dial route. The RouteView is
// published and queryable but Network.DialContext still returns ErrNoRoute
// because no data lane is implemented.

const (
	// factAdvertisementTTLMillis is the frozen publisher validity. The approved
	// P1 advertisement refresh/validity pair is 15 s / 45 s, and reception adds
	// only the fixed 30 s clock tolerance: a fact is never re-stamped on receipt.
	factAdvertisementTTLMillis uint64 = 45_000

	// localFactRefreshInterval re-advertises this node's own facts inside their
	// 45 s validity while the Network runs, so an active node never lets its own
	// NODE/ADDRESS/LINK facts lapse silently.
	localFactRefreshInterval = 15 * time.Second

	// factStagingGlobalBytes bounds the aggregate canonical record bytes staged
	// across all ingress Links. It reuses the approved per-sender staging bound
	// (8 MiB) as this slice's Network-wide guard instead of inventing a new
	// budget; it is a ceiling, not a preallocation, and exceeding it produces an
	// explicit FACT_ACK REJECT(resource), never a silent drop. It is a secondary
	// bound: the authoritative Network-wide bound is the shared 256 MiB heap
	// ledger, which stagePage books before retaining a page's bytes.
	factStagingGlobalBytes int64 = 8 << 20

	// FACT_ACK reason codes. The frozen schema defines a u16 reason and the
	// approved categories (expired, version, digest, resource, semantic) but does
	// not number them; these values are this implementation's local encoding and
	// are echoed unchanged for the peer's diagnostics.
	factAckReasonExpired  uint16 = 1
	factAckReasonVersion  uint16 = 2
	factAckReasonDigest   uint16 = 3
	factAckReasonResource uint16 = 4
	factAckReasonSemantic uint16 = 5
)

var (
	// errFactControlMalformed is terminal for the Link. An authenticated peer
	// that emits a LINK_CTRL FACT record which is not a valid frozen v2 container
	// has a broken protected control stream, and the receiver cannot even echo
	// the snapshot identity back: fail closed instead of inventing an ACK.
	errFactControlMalformed = errors.New("malformed authenticated FACT control payload")
	// errFactStagingUnknown reports a page for a snapshot this Link has not
	// staged (or a different snapshot than the staged one). The answer is
	// NEED_SUMMARY after discarding the unknown staging, never a partial commit.
	errFactStagingUnknown = errors.New("no staged FACT snapshot for this Link")
	// errFactPageConflict reports the same page number with different bytes,
	// which cannot belong to the digest-bound snapshot being staged.
	errFactPageConflict = errors.New("duplicate FACT page number with different bytes")
)

// factRuntimeStatus is the minimal read-only view of the authenticated FACT
// runtime. It exposes versions, staged state and counters; it never returns
// fact payloads, peer identity material or configuration.
type factRuntimeStatus struct {
	FactVersion  uint64
	RouteVersion uint64
	RouteFresh   bool
	StagingLinks int
	StagedBytes  int64
	LocalLinks   int
	Committed    uint64
	Rejected     uint64
	Withdrawals  uint64
	IgnoredAcks  uint64
	StoreFailed  bool
	// Outbound sender counters: snapshots built, peer COMPLETE/REJECT outcomes
	// and bounded frame resends. SenderPending counts Links with an
	// unacknowledged offer.
	SenderSnapshots uint64
	SenderCompleted uint64
	SenderRejected  uint64
	SenderRetries   uint64
	SenderPending   int
}

// factRuntime owns one FactStore and one RouteView for a running Network, plus
// the bounded per-Link staging of the authenticated FACT consumer. The FactStore
// borrows the Network's runtime state handle: this object never closes it and
// never opens a second durable owner.
type factRuntime struct {
	network *network
	store   *topology.FactStore
	routes  *topology.RouteView

	// refresh coalesces RouteView rebuild requests. Capacity 1 means a signal
	// raised while a rebuild is running is kept for the next iteration instead of
	// queueing one rebuild per commit.
	refresh chan struct{}

	// senderWake coalesces outbound snapshot work: a commit, withdrawal or
	// admission raises one signal and the single sender worker serves it.
	senderWake chan struct{}
	// sender owns the immutable outbound snapshot cache and the network-wide
	// outbound byte accounting.
	sender senderState
	// senderBudget books the canonical bytes of the snapshots the outbound
	// sender keeps live into the Network's shared allocator, so the frozen
	// 256 MiB heap sees this plane instead of only the private
	// factSenderGlobalBytes sub-cap. It is constructed here, before the Network
	// publishes that allocator, and resolves the allocator on every call exactly
	// like newFactStateBudget.
	senderBudget *factSenderBudget

	// localMu serializes local fact publication and guards the published
	// initiator instances, so a concurrent Link admission and the advertisement
	// worker can never spend durable sequence numbers twice for one advertisement.
	localMu        sync.Mutex
	localPublished bool
	// addressVersion is the exact version of this node's currently published
	// ADDRESS fact. It is the revocation target when an automatic loser
	// reallocates; guarded by localMu.
	addressVersion topology.FactVersion
	// addressSearchCursor is the volatile resume cursor of an in-progress bounded
	// address reallocation search. It lives only in memory: a restart re-derives
	// from the persisted (VirtualIP, attempt) and resumes a fresh search, and a
	// chunk that yields changes no durable state. Guarded by addressMu.
	addressSearchCursor uint32
	// addressMu serializes an automatic loser reallocation (detect, revoke,
	// persist, swap, republish) so two workers can never interleave it.
	addressMu sync.Mutex
	links     map[uint64]*link.Link

	// mu guards per-Link staging and the in-memory sender floor mirror. It is
	// never held across the FactStore's own locks: staging and commits are
	// separate steps.
	mu          sync.Mutex
	staging     map[uint64]*factStaging
	stagedBytes int64
	senders     map[topology.NodeID]factSenderFloor

	committed   atomic.Uint64
	rejected    atomic.Uint64
	withdrawals atomic.Uint64
	ignoredAcks atomic.Uint64
	storeFailed atomic.Bool

	senderSnapshots atomic.Uint64
	senderCompleted atomic.Uint64
	senderRejected  atomic.Uint64
	senderRetries   atomic.Uint64
}

// factStaging is one bounded, single-snapshot staging buffer for one exact
// authenticated ingress Link. A new FACT_SUMMARY replaces it entirely, so a Link
// at most ever holds one snapshot inside the approved per-sender staging budget.
type factStaging struct {
	source  topology.FactSource
	summary topology.FactSummary
	pages   []topology.FactPage
	present []bool
	records int
	bytes   int64
	started time.Time
	// leases holds exactly one shared-ledger lease per accepted page, each
	// booking that page's canonical record bytes as CategoryState. Retained
	// inbound fact state is state, not data, so it belongs in the Network's
	// shared 256 MiB owned-heap ledger beside the local per-Link and aggregate
	// byte ceilings (which stay as secondary bounds).
	//
	// One lease per page, not one per snapshot: a *budget.Lease exposes only
	// Release (the Allocator's Resize is not a Lease method), and a per-page
	// Reserve is both the simplest shape and provably exact - every accepted
	// page books precisely its own bytes once, growing a snapshot never has to
	// hold old+candidate bytes against the heap at once, and every lifecycle end
	// releases exactly the pages that were accepted. The slice is guarded by
	// factRuntime.mu and is emptied in the same critical section that releases
	// it, so a lease is released exactly once.
	leases []*budget.Lease
}

// factSenderFloor mirrors the last snapshot this process committed for one
// authenticated sender. It is a diagnostic mirror only: the durable FactStore
// floor stays authoritative, and an empty mirror simply skips the early reject
// so the store decides.
type factSenderFloor struct {
	incarnation uint64
	version     uint64
	digest      [32]byte
	known       bool
}

// factPageOutcome reports how one FACT_PAGE changed the Link's staging.
type factPageOutcome struct {
	duplicate bool
	complete  bool
	missing   int // first missing page index, -1 when complete
}

// newFactRuntime opens the durable FactStore on the already reserved runtime
// state and publishes the first RouteView from an activeLinks-only validator.
// Failure leaves the caller responsible for closing the runtime state and
// identity handles it passed in.
func newFactRuntime(n *network) (*factRuntime, error) {
	if n == nil || n.runtimeState == nil || n.networkContext.ID() == ([32]byte{}) {
		return nil, errors.New("FACT runtime requires the network runtime state")
	}
	store, err := topology.NewFactStore(n.runtimeState, n.networkContext.WireID())
	if err != nil {
		return nil, fmt.Errorf("open authenticated FACT store: %w", err)
	}
	runtime := &factRuntime{
		network:      n,
		store:        store,
		senderBudget: newFactSenderBudget(n),
		refresh:      make(chan struct{}, 1),
		senderWake:   make(chan struct{}, 1),
		links:        make(map[uint64]*link.Link),
		staging:      make(map[uint64]*factStaging),
		senders:      make(map[topology.NodeID]factSenderFloor),
	}
	view, err := topology.NewRouteView(store, n.localActiveLink)
	if err != nil {
		return nil, fmt.Errorf("build RouteView: %w", err)
	}
	runtime.routes = view
	return runtime, nil
}

// signalRefresh requests one RouteView rebuild without blocking the caller and
// wakes the outbound snapshot worker, which coalesces store changes by itself.
func (f *factRuntime) signalRefresh() {
	if f == nil {
		return
	}
	select {
	case f.refresh <- struct{}{}:
	default:
	}
	if f.senderWake != nil {
		select {
		case f.senderWake <- struct{}{}:
		default:
		}
	}
}

// refreshRouteView is the single RouteView rebuild worker. It is registered with
// the Network worker gate before it starts, so Close cancels it and waits only
// for the rebuild already in progress. A failed rebuild keeps the last complete
// view and marks it stale; the next commit or withdrawal retries.
func (n *network) refreshRouteView() {
	defer n.workers.Done()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-n.facts.refresh:
			if n.facts.routesCurrent() {
				continue
			}
			if err := n.facts.routes.Refresh(time.Now()); err != nil {
				// Never log fact bytes or peer payload: only the phase.
				slog.Default().Debug("RouteView refresh failed", "phase", "facts")
			}
		}
	}
}

// refreshLocalFacts re-advertises this node's own facts inside their validity
// window. Nothing is published before the first authenticated Link admission, so
// a constructed-but-unconnected Network spends no durable sequence numbers.
func (n *network) refreshLocalFacts() {
	defer n.workers.Done()
	ticker := time.NewTicker(localFactRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			if err := n.facts.refreshLocal(time.Now()); err != nil {
				slog.Default().Debug("local fact re-advertisement failed", "phase", "facts")
			}
			if err := n.facts.checkAddressConflict(time.Now()); err != nil {
				slog.Default().Debug("local address ownership failed", "phase", "address", "conflict", errors.Is(err, ErrAddressConflict))
				// An explicit fixed_ip conflict is fail-closed: stop this
				// Network rather than silently re-address. The close runs on its
				// own goroutine because Close waits for this worker.
				go func() { _ = n.Close() }()
			}
		}
	}
}

// refreshFactSenders is the single outbound FACT sender worker. It is reserved
// with the Network worker gate before it starts, so Close cancels it and waits
// for the sender step already in progress; no per-Link goroutine is added and
// the Link keeps exactly one protected reader and one protected writer.
func (n *network) refreshFactSenders() {
	defer n.workers.Done()
	ticker := time.NewTicker(factSenderTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-n.facts.senderWake:
		case <-ticker.C:
		}
		n.facts.pumpSenders(time.Now())
	}
}

// localActiveLink is the RouteView LocalLinkValidator. It only reads this
// Network's activeLinks registry snapshot: no socket I/O, no fact lookup and no
// lock held across the FactStore. An edge is locally usable only while the exact
// LinkID/Epoch/Lane/peer tuple is still registered and open, so a fact-only or
// already retired Link can never become a route.
func (n *network) localActiveLink(linkID, epoch uint64, lane uint8, peer topology.NodeID) bool {
	if n == nil {
		return false
	}
	n.mu.Lock()
	established := n.activeLinks[linkID]
	n.mu.Unlock()
	if established == nil || !established.Ready() {
		return false
	}
	metadata := established.Metadata()
	return metadata.LinkEpoch == epoch && metadata.LaneID == lane && established.PeerNodeID() == [16]byte(peer)
}

// --- local publication -------------------------------------------------------

// linkAdmitted publishes this node's own facts once one authenticated Link is
// registered. The first admission advertises the NODE fact and, only when a
// fixed_ip is configured, the ADDRESS fact; an initiator admission additionally
// advertises that exact Link instance. The provisional attempt-0 VirtualIP is
// never published as an AddressFact. A durable-sequence or FactStore failure
// rejects this admission instead of pretending the facts were published.
func (f *factRuntime) linkAdmitted(established *link.Link, initiator bool, now time.Time) error {
	if f == nil || f.network == nil || established == nil {
		return ErrLinkDown
	}
	nowMillis, ok := factMillis(now)
	if !ok {
		return fmt.Errorf("%w: invalid publication time", topology.ErrFactMalformed)
	}
	metadata := established.Metadata()
	if initiator && metadata.LaneID != topology.FactLaneControl && metadata.LaneID != topology.FactLaneStream && metadata.LaneID != topology.FactLanePacket {
		// Only the CONTROL, STREAM and PACKET lanes have a runtime consumer; an
		// initiator never publishes a fact for a lane this Network cannot serve.
		return ErrPermissionDenied
	}

	f.localMu.Lock()
	defer f.localMu.Unlock()
	identity, err := f.network.identityStore.Identity()
	if err != nil {
		return err
	}

	records := make([]topology.FactRecord, 0, 3)
	if !f.localPublished {
		node, err := f.nodeRecord(identity, nowMillis)
		if err != nil {
			return err
		}
		records = append(records, node)
		if f.network.localVirtualIP().IsValid() {
			address, err := f.addressRecord(identity, nowMillis)
			if err != nil {
				return err
			}
			f.addressVersion = address.Envelope.Version
			records = append(records, address)
		}
	}
	if initiator {
		instance, err := f.linkRecord(identity, established, f.network.controlPumpFor(established.Metadata().LinkID), nowMillis)
		if err != nil {
			return err
		}
		records = append(records, instance)
	}
	if len(records) == 0 {
		return nil
	}
	if err := f.store.PublishLocal(records, now); err != nil {
		f.observeStoreError(err)
		return fmt.Errorf("publish local facts: %w", err)
	}
	f.localPublished = true
	if initiator {
		f.links[metadata.LinkID] = established
	}
	f.signalRefresh()
	return nil
}

// refreshLocal re-advertises the local NODE/ADDRESS facts and every initiator
// Link instance this Network published and still holds open. Facts of an exited
// instance are simply not refreshed; they retire through their own validity. A
// failure is diagnosable but does not disturb existing Links.
func (f *factRuntime) refreshLocal(now time.Time) error {
	if f == nil || f.network == nil {
		return nil
	}
	nowMillis, ok := factMillis(now)
	if !ok {
		return fmt.Errorf("%w: invalid advertisement time", topology.ErrFactMalformed)
	}
	f.localMu.Lock()
	defer f.localMu.Unlock()
	if !f.localPublished {
		// The first authenticated Link admission performs the initial
		// advertisement.
		return nil
	}
	identity, err := f.network.identityStore.Identity()
	if err != nil {
		return err
	}
	records := make([]topology.FactRecord, 0, len(f.links)+2)
	node, err := f.nodeRecord(identity, nowMillis)
	if err != nil {
		return err
	}
	records = append(records, node)
	if f.network.localVirtualIP().IsValid() {
		address, err := f.addressRecord(identity, nowMillis)
		if err != nil {
			return err
		}
		f.addressVersion = address.Envelope.Version
		records = append(records, address)
	}
	for _, established := range f.links {
		if established == nil || !established.Ready() {
			continue
		}
		instance, err := f.linkRecord(identity, established, f.network.controlPumpFor(established.Metadata().LinkID), nowMillis)
		if err != nil {
			return err
		}
		records = append(records, instance)
	}
	if err := f.store.PublishLocal(records, now); err != nil {
		f.observeStoreError(err)
		return fmt.Errorf("re-advertise local facts: %w", err)
	}
	f.signalRefresh()
	return nil
}

// nodeRecord builds this node's own NODE fact. No capability is advertised:
// PACKET/STREAM lanes, relay forwarding and host adapters are not implemented,
// so claiming endpoint/packet/relay capabilities here would be false.
// nodeRecord builds this node's own NODE fact. The advertised capabilities are
// the ones this runtime can actually honor: the P1 data plane serves the STREAM
// lane, and "relay" is advertised only when Config.Options.Relay enables
// forwarding for other nodes. A capability is never claimed for an unimplemented
// lane (PACKET) or a disabled role.
func (f *factRuntime) nodeRecord(identity security.Identity, nowMillis uint64) (topology.FactRecord, error) {
	version, err := f.nextVersion()
	if err != nil {
		return topology.FactRecord{}, err
	}
	// The FACT v2 codec admits only the frozen capability tokens
	// (endpoint.tcp, endpoint.udp, packet.ipv4, relay) in strictly ascending
	// order, so a new token cannot be invented here. "relay" is advertised only
	// when Config.Options.Relay actually enables forwarding for other nodes.
	var capabilities []string
	if f.network.relayEnabled() {
		capabilities = []string{"relay"}
	}
	return topology.FactRecord{
		Envelope: f.envelope(topology.FactNode, identity.NodeID, version, nowMillis),
		Payload: topology.NodePayload{
			NodeID:          topology.NodeID(identity.NodeID),
			StaticPublicKey: identity.PublicKey,
			Capabilities:    capabilities,
		},
	}, nil
}

// nodeIDLess compares two 16-byte node identities bytewise; the lowest NodeID
// keeps a contested automatically allocated address (D-OVERLAY-004).
func nodeIDLess(a, b topology.NodeID) bool {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// addressOwners returns the set of live AddressFact owners of one VirtualIP as
// visible in the current FactStore snapshot.
func (f *factRuntime) addressOwners(now time.Time, ip netip.Addr) (map[topology.NodeID]struct{}, error) {
	owners := make(map[topology.NodeID]struct{})
	if f == nil || f.store == nil {
		return owners, nil
	}
	records, _, err := f.store.Snapshot(now)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		payload, ok := record.Payload.(topology.AddressPayload)
		if !ok || payload.IP != ip || payload.PrefixLen != 32 || payload.Flags != 0 {
			continue
		}
		owners[payload.NodeID] = struct{}{}
	}
	return owners, nil
}

// checkAddressConflict enforces D-OVERLAY-004 ownership for this node's own
// VirtualIP. Two or more live owners of one address is a conflict: an explicit
// fixed_ip fails closed with ErrAddressConflict and is never silently
// re-addressed; an automatically allocated address keeps the lowest NodeID and
// the losing (higher NodeID) node reports ErrAddressConflict so the caller can
// re-derive from its persisted attempt+1.
func (f *factRuntime) checkAddressConflict(now time.Time) error {
	if f == nil || f.network == nil {
		return nil
	}
	ip := f.network.localVirtualIP()
	if !ip.IsValid() || !ip.Is4() {
		return nil
	}
	// Cheap gate first: only a RouteView conflict can require the full owner
	// scan, so the common no-conflict tick stays O(1) and never contends with
	// the FACT sender's snapshot.
	if _, resolveErr := f.network.facts.routes.ResolveVirtualIP(ip); resolveErr == nil {
		return nil
	} else if !errors.Is(resolveErr, topology.ErrRouteConflict) {
		return nil
	}
	owners, err := f.addressOwners(now, ip)
	if err != nil || len(owners) < 2 {
		return nil
	}
	if f.network.normalized.fixedIP.IsValid() {
		return fmt.Errorf("%w: fixed_ip %s has %d live owners", ErrAddressConflict, ip, len(owners))
	}
	identity, err := f.network.identityStore.Identity()
	if err != nil {
		return nil
	}
	own := topology.NodeID(identity.NodeID)
	for owner := range owners {
		if owner == own {
			continue
		}
		if nodeIDLess(owner, own) {
			// A lower NodeID owns this address; this node is the loser and must
			// re-derive from its persisted attempt+1.
			return f.reallocateAddress(now, ip)
		}
	}
	// This node holds the lowest NodeID and keeps the address; the conflicting
	// owner re-derives on its side.
	return nil
}

// reallocateAddress is the automatic-allocation loser path. Under the local
// address transaction it: derives the next attempt whose VirtualIP is not owned
// by another live owner, persists it, publishes a local REVOCATION of the old
// AddressFact key, atomically swaps the local snapshot, updates the packet
// plane's owned VIP and republishes the new AddressFact. It never touches any
// Circuit/Path/Session, which stay NodeID-pinned.
func (f *factRuntime) reallocateAddress(now time.Time, oldIP netip.Addr) error {
	if f == nil || f.network == nil {
		return nil
	}
	f.addressMu.Lock()
	defer f.addressMu.Unlock()

	identity, err := f.network.identityStore.Identity()
	if err != nil {
		return err
	}
	nowMillis, ok := factMillis(now)
	if !ok {
		return fmt.Errorf("%w: invalid reallocation time", topology.ErrFactMalformed)
	}
	current := f.network.localAddressSnapshot()
	prefix := f.network.normalized.networkPrefix
	// One FactStore snapshot decides the whole search: the occupied-foreign set is
	// built once and every candidate is tested against it, instead of re-reading
	// the store per candidate.
	foreign, err := f.occupiedForeignHosts(now, topology.NodeID(identity.NodeID))
	if err != nil {
		return err
	}
	// Pool exhaustion is provable only when that single snapshot already shows
	// every usable host owned by another node (our own old address accounts for
	// the one host we hold). Otherwise free space may still exist and the search
	// continues from its volatile cursor on a later tick.
	if total := usableHostTotal(prefix); total == 0 || uint64(len(foreign))+1 >= total {
		return fmt.Errorf("%w: no free VirtualIP in %s (%d usable hosts)", topology.ErrResourceLimit, prefix, total)
	}
	skip := make(map[netip.Addr]struct{}, len(foreign)+1)
	for occupied := range foreign {
		skip[occupied] = struct{}{}
	}
	if current.ip.IsValid() {
		skip[current.ip] = struct{}{}
	}
	chosenIP, chosenAttempt, nextCursor, found := chooseProvisionalVirtualIP(
		prefix, identity.NodeID, current.attempt, f.addressSearchCursor, addressSearchChunk, skip)
	if !found {
		// A chunk budget, not a pool exhaustion: remember the volatile cursor and
		// yield this tick. The Network, its NodeID and every Circuit/Path/Session
		// stay untouched; the conflict tick resumes the search later.
		f.addressSearchCursor = nextCursor
		return fmt.Errorf("%w: no free VirtualIP in %d candidate attempts (cursor %d)", topology.ErrResourceLimit, addressSearchChunk, nextCursor)
	}
	f.addressSearchCursor = 0

	// Move the live host /32 FIRST, before anything durable or published is
	// changed. A failure here means the host still owns the old address, so the
	// new VirtualIP must not be persisted, must not be published as a NODE/ADDRESS
	// fact and must not be swapped into the local snapshot: the reallocation fails
	// closed and the previous address, facts and external routes stay untouched.
	// With no host device attached this is a no-op.
	if err := f.network.applyHostAddress(f.network.ctx, chosenIP); err != nil {
		return fmt.Errorf("retarget host network address to %s: %w", chosenIP, err)
	}

	// Persist the new allocation before publishing anything, so a restart
	// resumes from the advanced attempt.
	if err := writeAddressState(f.network.runtimeState, chosenIP, chosenAttempt); err != nil {
		return err
	}

	records := make([]topology.FactRecord, 0, 2)
	// Revoke the old AddressFact key so only the unique new fact stays live.
	f.localMu.Lock()
	oldVersion := f.addressVersion
	f.localMu.Unlock()
	if oldVersion != (topology.FactVersion{}) {
		targetKey, err := topology.DeriveTargetKey(topology.FactAddress, topology.AddressPayload{
			NodeID:    topology.NodeID(identity.NodeID),
			IP:        oldIP,
			PrefixLen: 32,
			Flags:     0,
		})
		if err != nil {
			return err
		}
		tombstone, err := f.nextVersion()
		if err != nil {
			return err
		}
		records = append(records, topology.FactRecord{
			Envelope: f.envelope(topology.FactRevocation, identity.NodeID, tombstone, nowMillis),
			Payload: topology.RevocationPayload{
				Revoker:          topology.NodeID(identity.NodeID),
				TargetOrigin:     topology.NodeID(identity.NodeID),
				TargetKind:       topology.FactAddress,
				TargetKey:        targetKey,
				TargetVersion:    oldVersion,
				TombstoneVersion: tombstone,
			},
		})
	}
	newVersion, err := f.nextVersion()
	if err != nil {
		return err
	}
	records = append(records, topology.FactRecord{
		Envelope: f.envelope(topology.FactAddress, identity.NodeID, newVersion, nowMillis),
		Payload: topology.AddressPayload{
			NodeID:    topology.NodeID(identity.NodeID),
			IP:        chosenIP,
			PrefixLen: 32,
			Flags:     0,
		},
	})
	if err := f.store.PublishLocal(records, now); err != nil {
		f.observeStoreError(err)
		return fmt.Errorf("publish reallocated address: %w", err)
	}
	f.localMu.Lock()
	f.addressVersion = newVersion
	f.localMu.Unlock()

	f.network.setLocalAddress(chosenIP, chosenAttempt)
	if streams := f.network.streams; streams != nil {
		streams.mu.Lock()
		packets := streams.packets
		streams.mu.Unlock()
		if packets != nil && packets.service != nil {
			_ = packets.service.SetOwnedVirtualIP(chosenIP)
		}
	}
	f.signalRefresh()
	traceDataPlane("address reallocated", "old", oldIP.String(), "new", chosenIP.String(), "attempt", chosenAttempt)
	return nil
}

// addressSearchChunk bounds how many candidate attempts one reallocation tick
// evaluates before yielding its volatile cursor to a later conflict tick. It is
// a work budget, not a claim that the prefix is exhausted: a chunk that finds
// nothing returns a retryable resource limit and the next tick resumes from the
// cursor. The attempt counter is u32, so the search can never leave the frozen
// D-OVERLAY-004 sequence.
const addressSearchChunk = 32

// occupiedForeignHosts returns every usable host of this Network's prefix that
// the current FactStore snapshot shows as owned by another node. The snapshot is
// read exactly once, so a whole search chunk is decided against one consistent
// view and one candidate never costs another store scan.
func (f *factRuntime) occupiedForeignHosts(now time.Time, self topology.NodeID) (map[netip.Addr]struct{}, error) {
	foreign := make(map[netip.Addr]struct{})
	if f == nil || f.store == nil {
		return foreign, nil
	}
	records, _, err := f.store.Snapshot(now)
	if err != nil {
		return nil, err
	}
	prefix := f.network.normalized.networkPrefix
	for _, record := range records {
		payload, ok := record.Payload.(topology.AddressPayload)
		if !ok || payload.PrefixLen != 32 || payload.Flags != 0 {
			continue
		}
		if payload.NodeID == self {
			continue
		}
		if !usableOverlayHost(prefix, payload.IP) {
			continue
		}
		foreign[payload.IP] = struct{}{}
	}
	return foreign, nil
}

// whether that address came from an explicit fixed_ip or from the persisted
// deterministic D-OVERLAY-004 allocation. The key is bound to the NodeID and the
// address; changing the address republishes a new key for the same Origin.
func (f *factRuntime) addressRecord(identity security.Identity, nowMillis uint64) (topology.FactRecord, error) {
	version, err := f.nextVersion()
	if err != nil {
		return topology.FactRecord{}, err
	}
	return topology.FactRecord{
		Envelope: f.envelope(topology.FactAddress, identity.NodeID, version, nowMillis),
		Payload: topology.AddressPayload{
			NodeID:    topology.NodeID(identity.NodeID),
			IP:        f.network.localVirtualIP(),
			PrefixLen: 32,
			Flags:     0,
		},
	}, nil
}

// linkRecord builds the LINK fact of one instance this node initiated. The
// instance key keeps the exact LinkID, so a different LinkID on the same peer or
// Lane stays independently revocable.
func (f *factRuntime) linkRecord(identity security.Identity, established *link.Link, pump *controlPump, nowMillis uint64) (topology.FactRecord, error) {
	metadata := established.Metadata()
	version, err := f.nextVersion()
	if err != nil {
		return topology.FactRecord{}, err
	}
	return topology.FactRecord{
		Envelope: f.envelope(topology.FactLink, identity.NodeID, version, nowMillis),
		Payload: topology.LinkPayload{
			LinkID:         metadata.LinkID,
			LinkEpoch:      metadata.LinkEpoch,
			LaneID:         metadata.LaneID,
			From:           topology.NodeID(identity.NodeID),
			To:             topology.NodeID(established.PeerNodeID()),
			ConnectionType: established.ConnectionType(),
			Cost:           linkCost(pump),
		},
	}, nil
}

// linkCost fills the advertised cost of one Link from its own measurements. A Link that
// has not answered a probe yet reports a zero latency, which route cost treats as
// "unmeasured" rather than "instantaneous" — every other term in that sum is positive, so
// a fresh Link sorts below a measured one instead of above it.
func linkCost(pump *controlPump) topology.LinkCost {
	if pump == nil || pump.control == nil {
		return topology.LinkCost{}
	}
	return topology.LinkCost{
		RTTMillis:    uint32(pump.control.RTT().Milliseconds()),
		JitterMicros: uint32(pump.control.RTTVariation().Microseconds()),
	}
}

func (f *factRuntime) envelope(kind topology.FactKind, origin [16]byte, version topology.FactVersion, nowMillis uint64) topology.FactEnvelope {
	return topology.FactEnvelope{
		NetworkID: f.network.networkContext.WireID(),
		Kind:      kind,
		Origin:    topology.NodeID(origin),
		Version:   version,
		IssuedAt:  nowMillis,
		ExpiresAt: nowMillis + factAdvertisementTTLMillis,
	}
}

// nextVersion spends one durable sequence number. Persistence happens before the
// value is returned, so a published fact can never reuse an earlier version
// after a restart; a failed increment publishes nothing.
func (f *factRuntime) nextVersion() (topology.FactVersion, error) {
	sequence, err := f.network.runtimeState.NextSequence()
	if err != nil {
		return topology.FactVersion{}, err
	}
	return topology.FactVersion{Incarnation: f.network.runtimeState.Incarnation(), Sequence: sequence}, nil
}

// --- link exit ---------------------------------------------------------------

// linkExited drops the staging of one exact Link and withdraws its authenticated
// ingress provenance from the FactStore. A fact that no other source still
// advertises becomes Withdrawn; local facts have no ingress source and are not
// affected. Withdrawal is keyed by the exact (LinkID, Epoch, peer) tuple, so an
// exiting Link can never detach a newer instance's facts.
func (f *factRuntime) linkExited(established *link.Link) {
	if f == nil || established == nil {
		return
	}
	metadata := established.Metadata()
	f.dropStaging(metadata.LinkID)

	f.localMu.Lock()
	if f.links[metadata.LinkID] == established {
		delete(f.links, metadata.LinkID)
	}
	f.localMu.Unlock()

	source, ok := f.sourceFor(established)
	if !ok {
		return
	}
	if err := f.store.WithdrawSource(source, time.Now()); err != nil {
		f.observeStoreError(err)
		slog.Default().Debug("FACT source withdrawal failed", "phase", "facts")
		return
	}
	f.withdrawals.Add(1)
	f.signalRefresh()
}

// dropAllStaging releases every staged page at Network shutdown. It returns each
// accepted page's shared-ledger lease as well as dropping the map, so a shutdown
// never strands a reservation in the Network's ledger.
func (f *factRuntime) dropAllStaging() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, state := range f.staging {
		f.releaseStagingLeasesLocked(state)
	}
	f.staging = make(map[uint64]*factStaging)
	f.stagedBytes = 0
}

// --- per-Link staging --------------------------------------------------------

// beginStaging replaces any staging of this Link with the described snapshot.
// Exactly one snapshot is staged per Link, inside the approved per-sender
// staging bound. An over-limit declaration is rejected before allocation.
func (f *factRuntime) beginStaging(source topology.FactSource, summary topology.FactSummary) error {
	if f == nil {
		return ErrClosed
	}
	if summary.PageCount > topology.MaxSnapshotPages || summary.FactCount > topology.MaxSnapshotRecords {
		return topology.ErrFactTooLarge
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropStagingLocked(source.LinkID)
	f.staging[source.LinkID] = &factStaging{
		source:  source,
		summary: summary,
		pages:   make([]topology.FactPage, summary.PageCount),
		present: make([]bool, summary.PageCount),
		started: time.Now(),
	}
	return nil
}

// stagePage records one decoded page of the staged snapshot. It is idempotent
// for an identical repeat, rejects a conflicting repeat, enforces the per-Link
// and Network-wide record-byte bounds before keeping anything, books the page's
// exact canonical bytes against the Network's shared heap ledger before
// retaining them, and drops a staging attempt that outlived one frozen
// advertisement TTL so a stalled transfer can never be committed with
// already-expired facts.
func (f *factRuntime) stagePage(source topology.FactSource, page topology.FactPage, recordBytes int64, now time.Time) (factPageOutcome, error) {
	if f == nil {
		return factPageOutcome{}, ErrClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state := f.staging[source.LinkID]
	if state == nil || state.source != source {
		return factPageOutcome{}, errFactStagingUnknown
	}
	if !state.started.IsZero() && now.Sub(state.started) > factStagingTTL {
		f.dropStagingLocked(source.LinkID)
		return factPageOutcome{}, errFactStagingUnknown
	}
	if page.SenderIncarnation != state.summary.SenderIncarnation ||
		page.SnapshotVersion != state.summary.SnapshotVersion ||
		page.PageCount != state.summary.PageCount ||
		page.NetworkID != state.summary.NetworkID ||
		page.ProtocolVersion != state.summary.ProtocolVersion {
		return factPageOutcome{}, errFactStagingUnknown
	}
	index := int(page.PageNo)
	if state.present[index] {
		if state.pages[index].PageDigest != page.PageDigest {
			return factPageOutcome{}, errFactPageConflict
		}
		return factPageOutcome{duplicate: true, missing: firstMissingPage(state)}, nil
	}
	if state.records+len(page.Facts) > topology.MaxSnapshotRecords ||
		state.bytes+recordBytes > topology.MaxSnapshotBytes ||
		f.stagedBytes+recordBytes > factStagingGlobalBytes {
		return factPageOutcome{}, topology.ErrFactTooLarge
	}
	// Book this page's exact canonical record bytes against the Network's shared
	// 256 MiB owned-heap ledger BEFORE the page is retained: retained inbound
	// fact state is state, not data. The local ceilings above stay as secondary
	// bounds. The reservation is all-or-none, so a refusal leaves the ledger
	// untouched; it is reported through topology.ErrFactTooLarge so the page
	// takes exactly the same explicit FACT_ACK REJECT(resource) path as a
	// locally over-limit page, and the caller then drops this Link's staging,
	// returning every earlier page's lease too.
	lease, err := f.network.reserveState(uint64(recordBytes))
	if err != nil {
		return factPageOutcome{}, errors.Join(topology.ErrFactTooLarge, err)
	}
	state.pages[index] = page
	state.present[index] = true
	state.records += len(page.Facts)
	state.bytes += recordBytes
	f.stagedBytes += recordBytes
	state.leases = append(state.leases, lease)
	missing := firstMissingPage(state)
	return factPageOutcome{complete: missing < 0, missing: missing}, nil
}

// takeStaged removes and returns the complete staged snapshot of one Link.
func (f *factRuntime) takeStaged(linkID uint64) (topology.FactSummary, []topology.FactPage, bool) {
	if f == nil {
		return topology.FactSummary{}, nil, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state := f.staging[linkID]
	if state == nil || len(state.pages) == 0 {
		return topology.FactSummary{}, nil, false
	}
	pages := make([]topology.FactPage, len(state.pages))
	copy(pages, state.pages)
	summary := state.summary
	f.dropStagingLocked(linkID)
	return summary, pages, true
}

// dropStaging discards the staging of one Link, releasing its staged bytes and
// every shared-ledger lease the staging holds.
func (f *factRuntime) dropStaging(linkID uint64) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropStagingLocked(linkID)
}

// dropStagingLocked removes one Link's staging and returns its shared-ledger
// leases to the Network allocator. It is the single lifecycle end shared by
// replacement (beginStaging), TTL expiry (stagePage and the sender's expired
// sweep), conflict/unknown discard and successful take, so every end releases
// the leases exactly once. The caller must hold f.mu.
func (f *factRuntime) dropStagingLocked(linkID uint64) {
	state := f.staging[linkID]
	if state == nil {
		return
	}
	delete(f.staging, linkID)
	f.releaseStagingLeasesLocked(state)
	f.stagedBytes -= state.bytes
	if f.stagedBytes < 0 {
		f.stagedBytes = 0
	}
}

// releaseStagingLeasesLocked returns every lease this staging owns and empties
// the slice in the same critical section, so a second lifecycle end on the same
// staging releases nothing twice. The caller must hold f.mu.
//
// Releasing here (rather than after the unlock) is required: the TTL sweep in
// fact_sender.go and the conflict/unknown discards all end staging through
// dropStagingLocked while f.mu is held. It is safe because the allocator is a
// leaf ledger - it runs no callback and never calls back into this runtime - so
// the f.mu -> allocator.mu order is consistent on every path (stagePage's
// reservation takes the same order) and no inverse order exists to deadlock on.
// releaseState tolerates a nil lease and a release after Network Close.
func (f *factRuntime) releaseStagingLeasesLocked(state *factStaging) {
	if state == nil || len(state.leases) == 0 {
		return
	}
	leases := state.leases
	state.leases = nil
	for _, lease := range leases {
		f.network.releaseState(lease)
	}
}

func firstMissingPage(state *factStaging) int {
	for index, present := range state.present {
		if !present {
			return index
		}
	}
	return -1
}

// senderFloorDecision rejects a snapshot that is strictly older than the
// last snapshot this process committed for that authenticated sender, or that
// reuses the committed version with different bytes. The durable FactStore floor
// remains authoritative; an empty mirror simply lets the store decide.
func (f *factRuntime) senderFloorDecision(peer topology.NodeID, summary topology.FactSummary) (uint16, bool) {
	if f == nil {
		return 0, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	floor, exists := f.senders[peer]
	if !exists || !floor.known {
		return 0, false
	}
	switch {
	case summary.SenderIncarnation < floor.incarnation,
		summary.SenderIncarnation == floor.incarnation && summary.SnapshotVersion < floor.version:
		return factAckReasonVersion, true
	case summary.SenderIncarnation == floor.incarnation && summary.SnapshotVersion == floor.version && floor.digest != summary.Digest:
		return factAckReasonDigest, true
	}
	return 0, false
}

// commitSnapshot applies one complete validated snapshot. The FactStore persists
// the advanced high-watermarks before anything is published, so a failure leaves
// the previous facts untouched.
func (f *factRuntime) commitSnapshot(source topology.FactSource, summary topology.FactSummary, pages []topology.FactPage, now time.Time) error {
	if f == nil {
		return ErrClosed
	}
	if err := f.store.CommitSnapshot(source, summary, pages, now); err != nil {
		f.observeStoreError(err)
		return err
	}
	f.mu.Lock()
	f.senders[source.AuthenticatedPeer] = factSenderFloor{
		incarnation: summary.SenderIncarnation,
		version:     summary.SnapshotVersion,
		digest:      summary.Digest,
		known:       true,
	}
	f.mu.Unlock()
	f.committed.Add(1)
	f.signalRefresh()
	return nil
}

// routesCurrent reports whether the published RouteView already matches the
// current FactStore version.
func (f *factRuntime) routesCurrent() bool {
	if f == nil {
		return true
	}
	return f.routes.Freshness() == topology.RouteViewFresh
}

// sourceFor builds the exact ingress identity of one authenticated CONTROL Link.
// It is descriptive plumbing only: the FactStore re-derives
// AuthenticatedPeer == SHA256(PeerStatic)[:16] and rejects any mismatch.
func (f *factRuntime) sourceFor(established *link.Link) (topology.FactSource, bool) {
	if f == nil || f.network == nil || established == nil {
		return topology.FactSource{}, false
	}
	metadata := established.Metadata()
	peer := established.PeerNodeID()
	if metadata.LinkID == 0 || metadata.LinkEpoch == 0 || metadata.LaneID != topology.FactLaneControl || peer == ([16]byte{}) {
		return topology.FactSource{}, false
	}
	return topology.FactSource{
		ContextID:         f.network.networkContext.ID(),
		AuthenticatedPeer: topology.NodeID(peer),
		PeerStatic:        established.PeerStatic(),
		LinkID:            metadata.LinkID,
		Epoch:             metadata.LinkEpoch,
		LaneID:            topology.FactLaneControl,
	}, true
}

func (f *factRuntime) observeStoreError(err error) {
	if f == nil {
		return
	}
	if errors.Is(err, topology.ErrFactStoreFailed) || errors.Is(err, topology.ErrFactStoreReset) {
		f.storeFailed.Store(true)
	}
}

// factStatus is the minimal read-only status query of the authenticated FACT
// runtime. It performs no I/O and mutates nothing.
func (n *network) factStatus() factRuntimeStatus {
	if n == nil || n.facts == nil {
		return factRuntimeStatus{}
	}
	f := n.facts
	f.mu.Lock()
	stagingLinks := len(f.staging)
	stagedBytes := f.stagedBytes
	f.mu.Unlock()
	f.localMu.Lock()
	localLinks := len(f.links)
	f.localMu.Unlock()
	pending := 0
	for _, pump := range n.controlPumpSnapshot() {
		if pump.sender.pending() {
			pending++
		}
	}
	return factRuntimeStatus{
		FactVersion:  f.store.Version(),
		RouteVersion: f.routes.Version(),
		RouteFresh:   f.routes.Freshness() == topology.RouteViewFresh,
		StagingLinks: stagingLinks,
		StagedBytes:  stagedBytes,
		LocalLinks:   localLinks,
		Committed:    f.committed.Load(),
		Rejected:     f.rejected.Load(),
		Withdrawals:  f.withdrawals.Load(),
		IgnoredAcks:  f.ignoredAcks.Load(),
		StoreFailed:  f.storeFailed.Load(),

		SenderSnapshots: f.senderSnapshots.Load(),
		SenderCompleted: f.senderCompleted.Load(),
		SenderRejected:  f.senderRejected.Load(),
		SenderRetries:   f.senderRetries.Load(),
		SenderPending:   pending,
	}
}

// --- control pump: FACT_SUMMARY / FACT_PAGE / FACT_ACK ------------------------

// consumeFactSummary handles one authenticated FACT_SUMMARY. A container that is
// not the frozen v2 shape is terminal for the Link; a well-formed summary for
// another network locator, an older sender version or an over-limit declaration
// is answered with an explicit ACK instead of being dropped. Page transfer is
// request/response, so a non-empty snapshot starts by requesting page 0.
func (p *controlPump) consumeFactSummary(payload []byte) error {
	summary, err := topology.DecodeFactSummary(payload)
	if err != nil {
		return errors.Join(errFactControlMalformed, err)
	}
	source, ok := p.factSource()
	if !ok {
		return errors.Join(errFactControlMalformed, ErrPermissionDenied)
	}
	if summary.NetworkID != p.network.networkContext.WireID() {
		return p.rejectSnapshot(source, summary, 0, factAckReasonSemantic)
	}
	if reason, stale := p.network.facts.senderFloorDecision(source.AuthenticatedPeer, summary); stale {
		return p.rejectSnapshot(source, summary, 0, reason)
	}
	if summary.PageCount == 0 {
		// An empty snapshot has no page to request: it is validated and
		// committed atomically exactly like a paged one.
		return p.commitStagedSnapshot(source, summary, nil)
	}
	if err := p.network.facts.beginStaging(source, summary); err != nil {
		return p.rejectSnapshot(source, summary, 0, factAckReasonResource)
	}
	return p.sendFactAck(summary.SenderIncarnation, summary.SnapshotVersion, 0, topology.AckNeedPage, 0, 0)
}

// consumeFactPage handles one authenticated FACT_PAGE. Unknown snapshots are
// discarded and answered with NEED_SUMMARY, a conflicting repeat or an
// over-budget page with REJECT, an incomplete snapshot with NEED_PAGE for the
// first missing page, and a complete one is validated and committed atomically
// before COMPLETE is sent.
func (p *controlPump) consumeFactPage(payload []byte) error {
	page, err := topology.DecodeFactPage(payload)
	if err != nil {
		return errors.Join(errFactControlMalformed, err)
	}
	source, ok := p.factSource()
	if !ok {
		return errors.Join(errFactControlMalformed, ErrPermissionDenied)
	}
	recordBytes := int64(len(payload)) - int64(topology.FactPageHeaderSize)
	outcome, err := p.network.facts.stagePage(source, page, recordBytes, time.Now())
	switch {
	case errors.Is(err, errFactStagingUnknown):
		p.network.facts.dropStaging(source.LinkID)
		return p.sendFactAck(page.SenderIncarnation, page.SnapshotVersion, page.PageNo, topology.AckNeedSummary, 0, 0)
	case errors.Is(err, errFactPageConflict):
		return p.rejectPage(source, page, factAckReasonDigest)
	case err != nil:
		reason := factAckReasonSemantic
		if errors.Is(err, topology.ErrFactTooLarge) {
			reason = factAckReasonResource
		}
		return p.rejectPage(source, page, reason)
	}
	if outcome.complete {
		summary, pages, ok := p.network.facts.takeStaged(source.LinkID)
		if !ok {
			return p.sendFactAck(page.SenderIncarnation, page.SnapshotVersion, page.PageNo, topology.AckNeedSummary, 0, 0)
		}
		return p.commitStagedSnapshot(source, summary, pages)
	}
	if outcome.missing >= 0 {
		return p.sendFactAck(page.SenderIncarnation, page.SnapshotVersion, page.PageNo, topology.AckNeedPage, 0, uint32(outcome.missing))
	}
	// Idempotent repeat with nothing missing can only be an already complete
	// snapshot; acknowledge it without pretending it was newly staged.
	return p.sendFactAck(page.SenderIncarnation, page.SnapshotVersion, page.PageNo, topology.AckOK, 0, 0)
}

// consumeFactAck handles one authenticated FACT_ACK. A container that is not the
// frozen v2 shape is terminal for the Link. A well-formed ACK is correlated with
// this Link's own outbound offer: a matching COMPLETE/REJECT/NEED_PAGE/
// NEED_SUMMARY/OK advances or retires exactly that offer, while an unsolicited or
// stale ACK is counted and ignored rather than closing a healthy CONTROL Link.
func (p *controlPump) consumeFactAck(payload []byte) error {
	ack, err := topology.DecodeFactAck(payload)
	if err != nil {
		return errors.Join(errFactControlMalformed, err)
	}
	return p.consumeOutboundFactAck(ack, time.Now())
}

// commitStagedSnapshot validates and atomically commits one complete snapshot.
// Snapshot and record validation run before the commit so the REJECT reason
// reflects the approved category; the FactStore revalidates and persists before
// publishing, so a failure can never leave a partial snapshot visible.
func (p *controlPump) commitStagedSnapshot(source topology.FactSource, summary topology.FactSummary, pages []topology.FactPage) error {
	now := time.Now()
	nowMillis, ok := factMillis(now)
	if !ok {
		return errors.Join(errFactControlMalformed, topology.ErrFactMalformed)
	}
	if err := topology.ValidateSnapshot(summary, pages); err != nil {
		reason := factAckReasonSemantic
		if errors.Is(err, topology.ErrFactTooLarge) {
			reason = factAckReasonResource
		}
		return p.rejectSnapshot(source, summary, lastPageNo(summary), reason)
	}
	for _, page := range pages {
		for _, record := range page.Facts {
			if err := topology.ValidateFactForNetwork(record, p.network.networkContext.WireID()); err != nil {
				return p.rejectSnapshot(source, summary, page.PageNo, factRecordReason(record, nowMillis, err))
			}
		}
	}
	if err := p.network.facts.commitSnapshot(source, summary, pages, now); err != nil {
		return p.rejectSnapshot(source, summary, lastPageNo(summary), factCommitReason(err))
	}
	// COMPLETE is sent only after the atomic commit succeeded. If it is lost,
	// the sender retries the identical digest-bound version and the FactStore
	// accepts that repeat idempotently.
	return p.sendFactAck(summary.SenderIncarnation, summary.SnapshotVersion, lastPageNo(summary), topology.AckComplete, 0, 0)
}

// rejectSnapshot clears any staging of this exact Link and answers with REJECT.
// The staged snapshot is discarded, so a rejected transfer can never be
// completed by a later page of the same attempt.
func (p *controlPump) rejectSnapshot(source topology.FactSource, summary topology.FactSummary, pageNo uint32, reason uint16) error {
	p.network.facts.dropStaging(source.LinkID)
	p.network.facts.rejected.Add(1)
	return p.sendFactAck(summary.SenderIncarnation, summary.SnapshotVersion, pageNo, topology.AckReject, reason, 0)
}

// rejectPage clears the staging of one exact Link and answers REJECT for a page.
func (p *controlPump) rejectPage(source topology.FactSource, page topology.FactPage, reason uint16) error {
	p.network.facts.dropStaging(source.LinkID)
	p.network.facts.rejected.Add(1)
	return p.sendFactAck(page.SenderIncarnation, page.SnapshotVersion, page.PageNo, topology.AckReject, reason, 0)
}

// sendFactAck enqueues one FACT_ACK through the unique protected writer. The
// peer's own sender incarnation is echoed; this node's incarnation is never
// substituted. A full queue is an explicit ErrResource, never a silent drop.
func (p *controlPump) sendFactAck(senderIncarnation, snapshotVersion uint64, pageNo uint32, status topology.AckStatus, reason uint16, missing uint32) error {
	ack := topology.FactAck{
		ProtocolVersion:   topology.FactProtocolVersion,
		SenderIncarnation: senderIncarnation,
		NetworkID:         p.network.networkContext.WireID(),
		SnapshotVersion:   snapshotVersion,
		PageNo:            pageNo,
		Status:            status,
		Reason:            reason,
		MissingPage:       missing,
	}
	payload, err := topology.EncodeFactAck(ack)
	if err != nil {
		// Fields are echoed from a decoded peer message, so a failure here is an
		// internal invariant violation: fail the Link closed.
		return errors.Join(errFactControlMalformed, err)
	}
	return p.sendControl(link.ControlMessage{Type: 8, Payload: payload})
}

// factSource is the authenticated ingress identity of this pump's Link.
func (p *controlPump) factSource() (topology.FactSource, bool) {
	if p == nil || p.network == nil {
		return topology.FactSource{}, false
	}
	return p.network.facts.sourceFor(p.link)
}

func lastPageNo(summary topology.FactSummary) uint32 {
	if summary.PageCount == 0 {
		return 0
	}
	return summary.PageCount - 1
}

// factRecordReason classifies one record-level admission failure. The frozen
// 30-second clock tolerance is applied by ValidateFactForNetwork; a record whose
// validity already ended is reported as expired rather than generic-semantic.
func factRecordReason(record topology.FactRecord, nowMillis uint64, err error) uint16 {
	if errors.Is(err, topology.ErrFactNetwork) {
		return factAckReasonSemantic
	}
	if nowMillis > record.Envelope.ExpiresAt {
		return factAckReasonExpired
	}
	return factAckReasonSemantic
}

// factCommitReason classifies a FactStore commit failure. Resource and durable
// state failures are reported as resource rejection; the store keeps the
// previous published facts and nothing partial becomes visible.
func factCommitReason(err error) uint16 {
	switch {
	case errors.Is(err, topology.ErrFactTooLarge),
		errors.Is(err, topology.ErrFactStoreFailed),
		errors.Is(err, topology.ErrFactStoreReset),
		errors.Is(err, ErrClosed):
		return factAckReasonResource
	default:
		return factAckReasonSemantic
	}
}

// factMillis converts one publication/admission time into the protocol's
// millisecond clock, refusing a pre-epoch time instead of publishing it.
func factMillis(now time.Time) (uint64, bool) {
	millis := now.UnixMilli()
	if millis < 0 {
		return 0, false
	}
	return uint64(millis), true
}
