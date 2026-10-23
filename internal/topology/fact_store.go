package topology

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/yiiilin/simpletier/internal/security"
)

// LaneID v1 enumeration is frozen in the wire protocol: CONTROL=0x00,
// PACKET=0x01, STREAM=0x02. A FACT ingress source must be an authenticated,
// established CONTROL link, so FactSource only admits FactLaneControl.
const (
	FactLaneControl uint8 = 0x00
	FactLanePacket  uint8 = 0x01
	FactLaneStream  uint8 = 0x02
)

const (
	// Hard resource bounds from topology-routing.md 3.3.1 / wire-protocol.md.
	// They are ceilings shared by all simultaneous constraints, never a
	// preallocation.
	maxFactLiveRecords   = 8192
	maxFactOriginRecords = 4096
	maxNodeFacts         = 1024
	maxLinkFacts         = 4096
	maxAddressFacts      = 1024
	maxRevocationFacts   = 1024
	maxFactSources       = 8
	maxFactHWMEntries    = 16384
	maxFactOwnedBytes    = 32 << 20

	// Effective expiry is the original publisher ExpiresAt plus the fixed
	// 30-second clock skew. It is never re-stamped on reception or relay.
	factClockSkewMillis = 30_000

	// A tombstone is retained for at least two 45-second advertisement TTLs
	// (90 seconds) and until max(targetExpiresAt, tombstoneExpiresAt) + 90s.
	factTombstoneRetentionMillis = 90_000

	// factMapEntryOverhead is a conservative per-entry Go map overhead (bucket
	// slot, hash and alignment slack). It is an upper bound, not a measurement.
	factMapEntryOverhead int64 = 96
)

// ErrFactStoreFailed is the sticky failure a FactStore reports after a durable
// write really failed. It means no later query may present a candidate as
// committed: Snapshot returns this error and IsCurrent returns false. The
// wrapped underlying error (usually a security.NetworkState error) remains
// available through errors.Is/As.
var ErrFactStoreFailed = errors.New("fact store persistence failure")

// ErrFactStoreReset reports that the durable high-watermark record is missing
// after this store was already established. It is never interpreted as a
// fresh, empty state; the caller must inspect the state directory instead.
var ErrFactStoreReset = errors.New("fact store high-watermark record missing after initialization")

// StateBudget books a FactStore's owned bytes against the Network's one shared
// allocator, so the frozen Network heap bound sees FACT state instead of a
// private ceiling. The store holds a single reservation sized to its current
// owned bytes and resizes it as the published state changes; a nil StateBudget
// keeps only the store's own maxFactOwnedBytes bound.
//
// This package deliberately imports no ledger: the runtime injects one adapter
// that books the bytes as Network state. ResizeState and ReleaseState run with
// the store's own mutex held, so an implementation must not call back into the
// store, must not block on I/O and must not take a lock the store's callers
// already hold.
type StateBudget interface {
	// ResizeState books want bytes of FACT state for this store, replacing the
	// store's previous reservation. It reports false when the shared allocator
	// refuses, in which case the previous reservation stays in force and the
	// store must not publish.
	ResizeState(want uint64) bool
	// ReleaseState drops this store's reservation. It is idempotent.
	ReleaseState()
}

// FactSource identifies one exact authenticated ingress for a FACT snapshot.
// The factory checks its shape only; it is not identity authentication. The
// real caller must be the CONTROL Link admission path, which sets
// AuthenticatedPeer from the already authenticated established link and
// PeerStatic from the peer identity proven by that link. FactStore therefore
// requires AuthenticatedPeer == SHA256(PeerStatic)[:16], a non-zero LinkID and
// Epoch, LaneID == CONTROL, and ContextID == the store's full ContextID.
type FactSource struct {
	ContextID         [32]byte
	AuthenticatedPeer NodeID
	PeerStatic        [32]byte
	LinkID            uint64
	Epoch             uint64
	LaneID            uint8
}

// hwmEntry is one persisted high-watermark floor plus the retention metadata
// that decides when the floor may safely be reclaimed. retentionKnown=false is
// the conservative legacy state: the floor is kept forever (never inferred
// deletable), so a replay of an old version can never revive it.
type hwmEntry struct {
	version        FactVersion
	retentionUntil uint64 // Unix ms; 0 with retentionKnown=false means forever
	retentionKnown bool
}

// factEntry is one current fact keyed by its own canonical FactKey bytes.
// A REVOCATION fact is stored here exactly like every other fact: its own
// FactKey, Origin (the revoker), FactVersion, expiry and provenance; the
// per-target suppression floor is aggregated separately in tombstoneEntry.
type factEntry struct {
	key       string
	kind      FactKind
	origin    NodeID
	version   FactVersion
	issuedAt  uint64
	expiresAt uint64 // original publisher expiry; never extended locally
	canon     []byte
	record    FactRecord
	sources   []FactSource // at most maxFactSources exact ingress sources
	saturated bool
	local     bool // published by this node through PublishLocal
}

// revocationContribution is one revoker's canonical, accepted revocation of a
// target. Keeping contributions per revoker FactKey lets the aggregate floor be
// decided by the winning records only, while retention outlives a reaped or
// withdrawn REV record.
type revocationContribution struct {
	targetVersion  FactVersion
	retentionUntil uint64
}

// tombstoneEntry is the aggregate revocation floor of one target fact key
// (Kind|TargetOrigin|len|target). It holds no fact bytes of its own: the live
// REVOCATION records are first-class entries, so every distinct revoker stays
// independently visible and gossiped.
type tombstoneEntry struct {
	kind           FactKind
	targetOrigin   NodeID
	targetKey      []byte
	revokedThrough FactVersion // suppresses target facts with version <= this
	retentionUntil uint64      // Unix ms; floor survives sourceDown/expiry until then
	contributors   map[string]revocationContribution
}

// senderFloor is the last accepted snapshot version of one authenticated peer.
// It is persisted so a replayed older snapshot cannot re-open already-closed
// provenance or re-stage older facts after a restart. Digest binds the floor to
// the exact accepted snapshot so the same version with different bytes is
// rejected instead of being accepted blind.
type senderFloor struct {
	Incarnation     uint64
	SnapshotVersion uint64
	Digest          [32]byte
	DigestKnown     bool
}

// FactStore is the atomic, bounded, persistent FACT consumer. It validates a
// complete sender snapshot (all pages, digests, global key order and per-record
// semantics/time), stages one whole candidate, persists the advanced
// high-watermarks, and only then publishes. Any shape or resource error leaves
// the previously published state untouched.
//
// It never reads configuration or writes PSK/token material. It only uses the
// borrowed security.NetworkState for its full ContextID, NodeID and durable
// records, and never closes that handle.
type FactStore struct {
	mu sync.RWMutex

	state     *security.NetworkState
	contextID [32]byte
	localNode NodeID
	wireID    uint64 // expected u64 NetworkID locator, not an isolation root

	entries    map[string]*factEntry
	tombstones map[string]*tombstoneEntry
	hwm        map[string]hwmEntry
	senders    map[string]senderFloor

	// stateBudget books this store's owned bytes against the Network's one
	// shared allocator; nil keeps only maxFactOwnedBytes in force. It is
	// attached before the store is shared and guarded by mu.
	stateBudget StateBudget

	viewVersion   uint64
	equivocations uint64
	failure       error
}

// NewFactStore binds a store to the exact full 32-byte ContextID and local
// NodeID already opened on state, plus the expected u64 NetworkID locator. It
// loads and strictly validates persisted high-watermarks/tombstones/sender
// floors before returning. A missing high-watermark record is a first
// initialization only when the established marker is also absent; otherwise it
// fails closed with ErrFactStoreReset.
func NewFactStore(state *security.NetworkState, wireID uint64) (*FactStore, error) {
	if state == nil {
		return nil, ErrFactMalformed
	}
	contextID, err := state.ContextID()
	if err != nil {
		return nil, err
	}
	rawNode, err := state.NodeID()
	if err != nil {
		return nil, err
	}
	store := &FactStore{
		state:      state,
		contextID:  contextID,
		localNode:  NodeID(rawNode),
		wireID:     wireID,
		entries:    make(map[string]*factEntry),
		tombstones: make(map[string]*tombstoneEntry),
		hwm:        make(map[string]hwmEntry),
		senders:    make(map[string]senderFloor),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	if factHWMUnionCount(store.entries, store.tombstones, store.hwm) > maxFactHWMEntries {
		return nil, ErrFactTooLarge
	}
	return store, nil
}

// SetStateBudget attaches the shared Network allocator port this store books its
// owned bytes against, replacing any port already attached (whose reservation is
// released first). A nil port detaches it, leaving only maxFactOwnedBytes in
// force, which is exactly the behaviour of a store that was never attached.
//
// It is an exported setter rather than a NewFactStore option because the
// runtime's shared allocator exists only after the store is constructed: the
// Network opens the store first and publishes its ledger afterwards, so the port
// can only be attached at that later moment. Keeping NewFactStore's signature
// also leaves every existing caller unchanged.
func (fs *FactStore) SetStateBudget(budget StateBudget) {
	if fs == nil {
		return
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.stateBudget != nil {
		fs.stateBudget.ReleaseState()
	}
	fs.stateBudget = budget
}

// Close releases this store's shared state reservation. It is idempotent and
// safe when no StateBudget is attached. It does not close the borrowed
// security.NetworkState, which this store never owned, and it deliberately keeps
// the port attached: a publish attempted after Close is refused by the shared
// allocator instead of becoming live unaccounted.
func (fs *FactStore) Close() {
	if fs == nil {
		return
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.stateBudget != nil {
		fs.stateBudget.ReleaseState()
	}
}

// Version returns the monotonic view version. Every committed version change,
// withdrawal or suppression raises it; it never wraps or decreases.
func (fs *FactStore) Version() uint64 {
	if fs == nil {
		return 0
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.viewVersion
}

// Equivocations returns how many same-key/same-version records carried
// different canonical bytes. The lexicographically smallest bytes win.
func (fs *FactStore) Equivocations() uint64 {
	if fs == nil {
		return 0
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.equivocations
}

// Snapshot returns the current visible fact set sorted by canonical FactKey,
// the view version it belongs to, and an error when the store has a sticky
// persistence failure. A set whose canonical records exceed the 3 MiB snapshot
// bound fails with ErrFactTooLarge instead of being truncated into a fake
// complete snapshot.
//
// Live REVOCATION records are exported with their own original ExpiresAt+30s
// visibility, never their longer local floor retention, so a receiver's
// ValidateFactForNetwork cannot reject the whole snapshot for an expired REV.
// Returned record copies are caller-owned and excluded from this store's 32 MiB
// budget; callers remain responsible for any network-wide accounting.
func (fs *FactStore) Snapshot(now time.Time) ([]FactRecord, uint64, error) {
	if fs == nil {
		return nil, 0, ErrFactMalformed
	}
	nowMillis, ok := factNowMillis(now)
	if !ok {
		return nil, 0, ErrFactMalformed
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	if fs.failure != nil {
		return nil, fs.viewVersion, fs.failure
	}

	type item struct {
		key    string
		record FactRecord
	}
	items := make([]item, 0, len(fs.entries))
	for key, entry := range fs.entries {
		if !fs.visibleLocked(entry, nowMillis) {
			continue
		}
		items = append(items, item{key: key, record: copyFactRecord(entry.record)})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })

	total := 0
	records := make([]FactRecord, 0, len(items))
	for _, item := range items {
		canon, err := EncodeFactRecord(item.record)
		if err != nil {
			return nil, fs.viewVersion, err
		}
		if total+len(canon) > MaxSnapshotBytes {
			return nil, fs.viewVersion, ErrFactTooLarge
		}
		total += len(canon)
		records = append(records, item.record)
	}
	return records, fs.viewVersion, nil
}

// IsCurrent reports whether key still has exactly version as a visible fact at
// now. A sticky persistence failure, expiry, suppression, withdrawal or a
// different current version all return false.
func (fs *FactStore) IsCurrent(key []byte, version FactVersion, now time.Time) bool {
	if fs == nil || len(key) == 0 {
		return false
	}
	nowMillis, ok := factNowMillis(now)
	if !ok {
		return false
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	if fs.failure != nil {
		return false
	}
	entry := fs.entries[string(key)]
	if entry == nil {
		return false
	}
	if compareFactVersion(entry.version, version) != 0 {
		return false
	}
	return fs.visibleLocked(entry, nowMillis)
}

// ResolveAddressOwner returns the current unambiguous owner of one exact IPv4
// /32 directly from the live entries, without building or consulting a
// RouteView: one RLock over the current facts, tombstone floors and expiry
// clocks decides the answer. A higher version of the same owner's AddressFact is
// therefore visible immediately and needs no view refresh, and the query never
// re-reads the view version, reuses an older or revoked ref, or clones the
// store (it scans the current live map under the existing 8192-record ceiling
// and allocates nothing per lookup).
//
// Two different live owners of the same address are ErrRouteConflict and are
// never collapsed into one; an address with no live owner is ErrNoRoute. A
// sticky persistence failure is propagated as-is so a caller cannot mistake a
// failed store for an absent route.
func (fs *FactStore) ResolveAddressOwner(addr netip.Addr, now time.Time) (AddressResolution, error) {
	if fs == nil {
		return AddressResolution{}, ErrFactMalformed
	}
	if !addr.Is4() {
		return AddressResolution{}, fmt.Errorf("%w: address owner lookup requires an IPv4 /32", ErrFactMalformed)
	}
	nowMillis, ok := factNowMillis(now)
	if !ok {
		return AddressResolution{}, ErrFactMalformed
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()
	if fs.failure != nil {
		return AddressResolution{}, fs.failure
	}

	found := false
	var owner AddressResolution
	for _, entry := range fs.entries {
		if entry.kind != FactAddress {
			continue
		}
		payload, ok := entry.record.Payload.(AddressPayload)
		if !ok || payload.IP != addr {
			continue
		}
		if !fs.visibleLocked(entry, nowMillis) {
			continue
		}
		if found {
			if owner.NodeID != payload.NodeID {
				return AddressResolution{}, ErrRouteConflict
			}
			continue
		}
		owner = AddressResolution{
			NodeID:      payload.NodeID,
			Prefix:      netip.PrefixFrom(addr, 32),
			FactVersion: entry.version,
			Freshness:   RouteViewFresh,
		}
		found = true
	}
	if !found {
		return AddressResolution{}, ErrNoRoute
	}
	return owner, nil
}

// sameRoutePair reports whether the LINK endpoints {from,to} span the pinned
// path segment {first,second}. A LINK fact is authored by whichever physical
// side initiated it, so either orientation is the same instance.
func sameRoutePair(from, to, first, second NodeID) bool {
	return (from == first && to == second) || (from == second && to == first)
}

// ResolvePinnedLinks checks one already pinned path against the current live
// facts under a single store RLock: every node must have a current live NODE
// fact and every segment must match a current live LINK fact with the exact
// instance identity (LinkID, LinkEpoch, Lane) between the two path nodes, in
// either physical orientation. It reads the live entries directly and never
// compares a version or the global store version, so an unchanged instance that
// is merely renewed with a higher version and a new TTL still matches; only
// expiry, revocation, withdrawal or a changed instance rejects it.
//
// Absence (missing, withdrawn, reaped or revoked) of a required NODE or LINK
// fact is ErrNoRoute; a live LINK for the segment whose LinkEpoch no longer
// matches the pinned ref is ErrRouteStale, as is a sticky persistence failure
// (which is propagated as-is). The caller still validates the local Path/Session
// readiness, LinkID/Epoch/Lane and the peer static key itself.
func (fs *FactStore) ResolvePinnedLinks(nodes []NodeID, refs []LinkRef, lane uint8, now time.Time) error {
	if fs == nil {
		return ErrFactMalformed
	}
	if lane != FactLanePacket && lane != FactLaneStream {
		return fmt.Errorf("%w: pinned path requires the PACKET or STREAM lane", ErrFactMalformed)
	}
	if len(nodes) == 0 || len(refs) != len(nodes)-1 || len(nodes) > maxRouteHops+1 {
		return fmt.Errorf("%w: pinned path requires len(nodes) == len(refs)+1 within %d hops", ErrFactMalformed, maxRouteHops)
	}
	for index, node := range nodes {
		if node == (NodeID{}) {
			return fmt.Errorf("%w: pinned path node %d is empty", ErrFactMalformed, index)
		}
		for earlier := 0; earlier < index; earlier++ {
			if nodes[earlier] == node {
				return fmt.Errorf("%w: pinned path repeats node %d", ErrFactMalformed, index)
			}
		}
	}
	for index, ref := range refs {
		if ref.ID == 0 || ref.Epoch == 0 || ref.LaneID != lane {
			return fmt.Errorf("%w: pinned link ref %d does not describe a %d-lane instance", ErrFactMalformed, index, lane)
		}
	}
	nowMillis, ok := factNowMillis(now)
	if !ok {
		return ErrFactMalformed
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()
	if fs.failure != nil {
		return fs.failure
	}

	var nodeLive [maxRouteHops + 1]bool
	var linkLive [maxRouteHops]bool
	var linkStale [maxRouteHops]bool
	for _, entry := range fs.entries {
		if !fs.visibleLocked(entry, nowMillis) {
			continue
		}
		switch entry.kind {
		case FactNode:
			payload, ok := entry.record.Payload.(NodePayload)
			if !ok {
				continue
			}
			for index, node := range nodes {
				if node == payload.NodeID {
					nodeLive[index] = true
				}
			}
		case FactLink:
			payload, ok := entry.record.Payload.(LinkPayload)
			if !ok || payload.LaneID != lane {
				continue
			}
			for index, ref := range refs {
				if payload.LinkID != ref.ID || !sameRoutePair(payload.From, payload.To, nodes[index], nodes[index+1]) {
					continue
				}
				if payload.LinkEpoch == ref.Epoch {
					linkLive[index] = true
				} else {
					linkStale[index] = true
				}
			}
		}
	}
	for index := range nodes {
		if !nodeLive[index] {
			return fmt.Errorf("%w: pinned node %d has no current live NODE fact", ErrNoRoute, index)
		}
	}
	for index := range refs {
		switch {
		case linkLive[index]:
		case linkStale[index]:
			return fmt.Errorf("%w: pinned link %d changed its LinkEpoch", ErrRouteStale, index)
		default:
			return fmt.Errorf("%w: pinned link %d has no current live LINK fact", ErrNoRoute, index)
		}
	}
	return nil
}

// CommitSnapshot atomically applies one complete sender snapshot from one exact
// authenticated ingress source. It first validates every page, digest, the
// global strict FactKey order, and each record's network/time semantics; then
// merges tombstones ahead of facts, stages one whole candidate, persists the
// advanced high-watermarks, and only then publishes. Shape, time or resource
// rejection leaves the current facts untouched.
//
// The snapshot replaces only this exact source's previously contributed
// provenance; other ingress links keep their own sources. A repeated snapshot
// version is accepted only when its digest is known and identical.
func (fs *FactStore) CommitSnapshot(source FactSource, summary FactSummary, pages []FactPage, now time.Time) error {
	if fs == nil {
		return ErrFactMalformed
	}
	nowMillis, ok := factNowMillis(now)
	if !ok {
		return ErrFactMalformed
	}
	if err := validateFactSource(source, fs.contextID); err != nil {
		return err
	}
	if summary.NetworkID != fs.wireID {
		return ErrFactNetwork
	}
	if err := ValidateSnapshot(summary, pages); err != nil {
		return err
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.failure != nil {
		return fs.failure
	}
	for _, page := range pages {
		for _, record := range page.Facts {
			if err := ValidateFactForNetwork(record, fs.wireID); err != nil {
				return err
			}
		}
	}

	candidate := fs.newCandidate()
	if candidate.budgetErr != nil {
		return candidate.budgetErr
	}
	candidate.reap(nowMillis)
	if candidate.budgetErr != nil {
		return candidate.budgetErr
	}

	senderKey := senderIdentity(source)
	if floor, exists := candidate.senders[senderKey]; exists {
		switch {
		case summary.SenderIncarnation < floor.Incarnation,
			summary.SenderIncarnation == floor.Incarnation && summary.SnapshotVersion < floor.SnapshotVersion:
			return ErrFactMalformed
		case summary.SenderIncarnation == floor.Incarnation && summary.SnapshotVersion == floor.SnapshotVersion:
			// A repeated snapshot version must prove it is the same complete
			// snapshot. A legacy floor has no digest, so it cannot be accepted
			// on version equality alone.
			if !floor.DigestKnown || floor.Digest != summary.Digest {
				return ErrFactMalformed
			}
		}
	}
	if _, exists := candidate.senders[senderKey]; !exists {
		growth := factMapEntryOverhead + stringHeaderBytes + int64(len(senderKey)) + senderStructBytes
		if !candidate.reserveGrowth(growth, 16+8+8+factPersistenceDigestSize+factPersistenceBooleanWidth) {
			return candidate.budgetErr
		}
	}
	candidate.senders[senderKey] = senderFloor{
		Incarnation:     summary.SenderIncarnation,
		SnapshotVersion: summary.SnapshotVersion,
		Digest:          summary.Digest,
		DigestKnown:     true,
	}
	candidate.persistNeeded = true

	// Revocations merge first so tombstone floors suppress facts from the same
	// snapshot and from the current store. Each REVOCATION is a first-class fact
	// in its own right; accepted same-version variants may raise the target
	// floor without changing the canonical REV record.
	targetExpiryReservation, targetExpiryCount := factTargetExpiryMapReservationPages(pages)
	if !candidate.reserveTransient(targetExpiryReservation) {
		return candidate.budgetErr
	}
	targetExpiries := make(map[string]uint64, targetExpiryCount)
	for _, page := range pages {
		for _, record := range page.Facts {
			if _, isRevocation := record.Payload.(RevocationPayload); isRevocation {
				continue
			}
			key, err := FactKey(record)
			if err != nil {
				return err
			}
			targetExpiries[string(key)] = record.Envelope.ExpiresAt
		}
	}
	for _, page := range pages {
		for _, record := range page.Facts {
			payload, isRevocation := record.Payload.(RevocationPayload)
			if !isRevocation {
				continue
			}
			key, err := FactKey(record)
			if err != nil {
				return err
			}
			target := string(targetFactKey(payload.TargetKind, payload.TargetOrigin, payload.TargetKey))
			candidate.mergeRevocation(record, payload, string(key), &source, nowMillis, targetExpiries[target])
			if candidate.budgetErr != nil {
				return candidate.budgetErr
			}
		}
	}
	candidate.releaseTransient(targetExpiryReservation)
	targetExpiries = nil
	for _, page := range pages {
		for _, record := range page.Facts {
			if _, isRevocation := record.Payload.(RevocationPayload); isRevocation {
				continue
			}
			key, err := FactKey(record)
			if err != nil {
				return err
			}
			candidate.mergeFact(record, string(key), &source, nowMillis)
			if candidate.budgetErr != nil {
				return candidate.budgetErr
			}
		}
	}
	candidate.replaceSourceProvenance(source, pages)

	if err := fs.finalise(candidate, nowMillis); err != nil {
		return err
	}
	fs.publishCandidate(candidate)
	return nil
}

// PublishLocal atomically admits this node's own facts. Records must carry the
// local NodeID as Origin and are persisted before they become visible. Local
// facts have no ingress provenance, so WithdrawSource never removes them and an
// ingress snapshot that relays them back (A -> B -> A) may not take provenance
// on them, replace their bytes or clear their local flag. A refresh also
// reclaims a key a peer relayed first; local facts leave only through expiry or
// a versioned revocation.
func (fs *FactStore) PublishLocal(records []FactRecord, now time.Time) error {
	if fs == nil {
		return ErrFactMalformed
	}
	nowMillis, ok := factNowMillis(now)
	if !ok {
		return ErrFactMalformed
	}

	staged := make([]FactRecord, 0, len(records))
	for _, record := range records {
		if record.Envelope.Origin != fs.localNode {
			return ErrFactMalformed
		}
		if err := ValidateFactForNetwork(record, fs.wireID); err != nil {
			return err
		}
		if _, err := EncodeFactRecord(record); err != nil {
			return err
		}
		staged = append(staged, copyFactRecord(record))
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.failure != nil {
		return fs.failure
	}
	candidate := fs.newCandidate()
	if candidate.budgetErr != nil {
		return candidate.budgetErr
	}
	candidate.reap(nowMillis)
	if candidate.budgetErr != nil {
		return candidate.budgetErr
	}
	targetExpiryReservation, targetExpiryCount := factTargetExpiryMapReservation(staged)
	if !candidate.reserveTransient(targetExpiryReservation) {
		return candidate.budgetErr
	}
	targetExpiries := make(map[string]uint64, targetExpiryCount)
	for _, record := range staged {
		if _, isRevocation := record.Payload.(RevocationPayload); isRevocation {
			continue
		}
		key, err := FactKey(record)
		if err != nil {
			return err
		}
		targetExpiries[string(key)] = record.Envelope.ExpiresAt
	}
	for _, record := range staged {
		key, err := FactKey(record)
		if err != nil {
			return err
		}
		if payload, isRevocation := record.Payload.(RevocationPayload); isRevocation {
			target := string(targetFactKey(payload.TargetKind, payload.TargetOrigin, payload.TargetKey))
			candidate.mergeRevocation(record, payload, string(key), nil, nowMillis, targetExpiries[target])
			if candidate.budgetErr != nil {
				return candidate.budgetErr
			}
			continue
		}
		candidate.mergeFact(record, string(key), nil, nowMillis)
		if candidate.budgetErr != nil {
			return candidate.budgetErr
		}
	}
	candidate.releaseTransient(targetExpiryReservation)
	targetExpiries = nil
	candidate.claimLocalOwnership(staged)
	if err := fs.finalise(candidate, nowMillis); err != nil {
		return err
	}
	fs.publishCandidate(candidate)
	return nil
}

// WithdrawSource removes one exact authenticated ingress source from all
// provenance sets. A fact with no remaining source, Saturated=false and not
// locally published becomes Withdrawn; a saturated fact is retained until its
// original expiry or tombstone, and a fact this node published itself is never
// removed by provenance. Revocation floors are never lowered here: a closed
// source may withdraw its live REVOCATION record but the accepted revokedThrough
// and its retention stay in force.
func (fs *FactStore) WithdrawSource(source FactSource, now time.Time) error {
	if fs == nil {
		return ErrFactMalformed
	}
	_ = now
	if err := validateFactSource(source, fs.contextID); err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.failure != nil {
		return fs.failure
	}

	entries := maps.Clone(fs.entries)
	viewChanged := false
	for key, entry := range entries {
		if !hasFactSource(entry.sources, source) {
			continue
		}
		next := *entry
		next.sources = removeFactSource(entry.sources, source)
		if len(next.sources) == 0 && !next.saturated && !next.local {
			delete(entries, key)
		} else {
			entries[key] = &next
		}
		viewChanged = true
	}
	fs.entries = entries
	if viewChanged {
		fs.bumpViewLocked()
	}
	return nil
}

// --- candidate staging -------------------------------------------------------

type factStoreCandidate struct {
	store          *FactStore
	budgetErr      error
	transientBytes int64
	entries        map[string]*factEntry
	tombstones     map[string]*tombstoneEntry
	hwm            map[string]hwmEntry
	senders        map[string]senderFloor
	equivocations  uint64
	persistNeeded  bool
	viewChanged    bool
}

func (fs *FactStore) newCandidate() *factStoreCandidate {
	candidate := &factStoreCandidate{store: fs}
	if factStoreClonePeakBytes(fs)+factWatermarkSerializedBytes(fs.hwm, fs.tombstones, fs.senders) > maxFactOwnedBytes {
		candidate.budgetErr = ErrFactTooLarge
		return candidate
	}
	// Tombstones are deep-copied because a candidate mutates their contributor
	// set in place; a shallow map clone would leak staged floors into the live
	// store before the durable write succeeds.
	tombstones := make(map[string]*tombstoneEntry, len(fs.tombstones))
	for key, tombstone := range fs.tombstones {
		next := *tombstone
		next.targetKey = make([]byte, len(tombstone.targetKey))
		copy(next.targetKey, tombstone.targetKey)
		next.contributors = maps.Clone(tombstone.contributors)
		tombstones[key] = &next
	}
	candidate.entries = maps.Clone(fs.entries)
	candidate.tombstones = tombstones
	candidate.hwm = maps.Clone(fs.hwm)
	candidate.senders = maps.Clone(fs.senders)
	candidate.equivocations = fs.equivocations
	return candidate
}

func (c *factStoreCandidate) reserveGrowth(memoryBytes, watermarkBytes int64) bool {
	if c.budgetErr != nil {
		return false
	}
	if c.store == nil {
		return true
	}
	if factStorePeakBytes(c.store, c)+c.transientBytes+memoryBytes+
		factWatermarkSerializedBytes(c.hwm, c.tombstones, c.senders)+watermarkBytes > maxFactOwnedBytes {
		c.budgetErr = ErrFactTooLarge
		return false
	}
	return true
}

func (c *factStoreCandidate) reserveTransient(memoryBytes int64) bool {
	if !c.reserveGrowth(memoryBytes, 0) {
		return false
	}
	c.transientBytes += memoryBytes
	return true
}

func (c *factStoreCandidate) releaseTransient(memoryBytes int64) {
	c.transientBytes -= memoryBytes
}

// reap drops entries past their absolute effective expiry and reassesses every
// aggregate revocation floor against the contributor retention. It never
// extends a lifetime and never re-admits a version.
func (c *factStoreCandidate) reap(nowMillis uint64) {
	if c.budgetErr != nil {
		return
	}
	for key, entry := range c.entries {
		if nowMillis > entry.expiresAt+factClockSkewMillis {
			delete(c.entries, key)
			c.viewChanged = true
		}
	}
	for target := range c.tombstones {
		c.recomputeTombstone(target, nowMillis)
		if c.budgetErr != nil {
			return
		}
	}
}

// mergeRevocation stages one REVOCATION. The REV record is merged as a
// first-class canonical fact under its own FactKey (Revoker included), while
// every valid variant at that own version can raise the independent target floor.
func (c *factStoreCandidate) mergeRevocation(record FactRecord, payload RevocationPayload, ownKey string, source *FactSource, nowMillis, targetExpiresAt uint64) {
	target := string(targetFactKey(payload.TargetKind, payload.TargetOrigin, payload.TargetKey))
	entry, changed := c.mergeCanonicalFact(record, ownKey, source, nowMillis)
	if entry == nil || compareFactVersion(entry.version, record.Envelope.Version) != 0 {
		return
	}
	tombstoneChanged := c.applyRevocationContribution(target, ownKey, payload, record.Envelope.ExpiresAt, targetExpiresAt, nowMillis)
	if changed || tombstoneChanged {
		c.persistNeeded = true
		c.viewChanged = true
	}
	if tombstone := c.tombstones[target]; tombstone != nil {
		c.extendHWMRetention(ownKey, tombstone.retentionUntil)
		c.extendHWMRetention(target, tombstone.retentionUntil)
	}
	if targetEntry := c.entries[target]; targetEntry != nil {
		if tombstone := c.tombstones[target]; tombstone != nil && compareFactVersion(targetEntry.version, tombstone.revokedThrough) <= 0 {
			delete(c.entries, target)
			c.viewChanged = true
			c.persistNeeded = true
		}
	}
}

// applyRevocationContribution records the maximum target version and retention
// observed for one revoker FactKey. Canonical REV bytes are tracked separately;
// an equivocation loser can still raise the suppression floor.
func (c *factStoreCandidate) applyRevocationContribution(target, ownKey string, payload RevocationPayload, revExpiresAt, targetExpiresAt, nowMillis uint64) bool {
	if c.budgetErr != nil {
		return false
	}
	tombstone := c.tombstones[target]
	previous, had := revocationContribution{}, false
	if tombstone != nil {
		previous, had = tombstone.contributors[ownKey]
	}
	growth, watermarkGrowth := int64(0), int64(0)
	if tombstone == nil {
		growth = factMapEntryOverhead + stringHeaderBytes + int64(len(target)) +
			tombstoneStructBytes + int64(len(payload.TargetKey)) + factMapEntryOverhead +
			stringHeaderBytes + int64(len(ownKey)) + contributionStructByte
		watermarkGrowth = 47 + int64(len(payload.TargetKey)) + 26 + int64(len(ownKey))
	} else if !had {
		growth = factMapEntryOverhead + stringHeaderBytes + int64(len(ownKey)) + contributionStructByte
		watermarkGrowth = 26 + int64(len(ownKey))
	}
	if !c.reserveGrowth(growth, watermarkGrowth) {
		return false
	}
	if tombstone == nil {
		targetKey := make([]byte, len(payload.TargetKey))
		copy(targetKey, payload.TargetKey)
		tombstone = &tombstoneEntry{
			kind:         payload.TargetKind,
			targetOrigin: payload.TargetOrigin,
			targetKey:    targetKey,
			contributors: make(map[string]revocationContribution, 1),
		}
		c.tombstones[target] = tombstone
	}
	retention := revExpiresAt + factTombstoneRetentionMillis
	if targetExpiresAt > 0 && targetExpiresAt+factTombstoneRetentionMillis > retention {
		retention = targetExpiresAt + factTombstoneRetentionMillis
	}
	if entry := c.entries[target]; entry != nil && entry.expiresAt+factTombstoneRetentionMillis > retention {
		retention = entry.expiresAt + factTombstoneRetentionMillis
	}
	if floor := c.hwm[target]; floor.retentionKnown && floor.retentionUntil > retention {
		retention = floor.retentionUntil
	}
	if !had && nowMillis+factTombstoneRetentionMillis > retention {
		retention = nowMillis + factTombstoneRetentionMillis
	}
	beforeFloor, beforeRetention, beforeCount := tombstone.revokedThrough, tombstone.retentionUntil, len(tombstone.contributors)
	contribution := revocationContribution{targetVersion: payload.TargetVersion, retentionUntil: retention}
	if had {
		contribution.targetVersion = maxFactVersion(previous.targetVersion, contribution.targetVersion)
		if previous.retentionUntil > contribution.retentionUntil {
			contribution.retentionUntil = previous.retentionUntil
		}
	}
	tombstone.contributors[ownKey] = contribution
	c.recomputeTombstone(target, nowMillis)
	after := c.tombstones[target]
	if after == nil {
		return true
	}
	current, stillPresent := after.contributors[ownKey]
	return !had || !stillPresent || beforeCount != len(after.contributors) ||
		compareFactVersion(beforeFloor, after.revokedThrough) != 0 ||
		beforeRetention != after.retentionUntil ||
		compareFactVersion(previous.targetVersion, current.targetVersion) != 0
}

// recomputeTombstone rebuilds the aggregate floor and retention of one target
// from its live contributions, dropping contributions whose retention has
// elapsed. A target with no live contribution loses its tombstone entirely.
func (c *factStoreCandidate) recomputeTombstone(target string, nowMillis uint64) bool {
	tombstone := c.tombstones[target]
	if tombstone == nil {
		return false
	}
	changed := false
	var floor FactVersion
	var retention uint64
	for ownKey, contribution := range tombstone.contributors {
		if contribution.retentionUntil != 0 && nowMillis > contribution.retentionUntil {
			delete(tombstone.contributors, ownKey)
			changed = true
			continue
		}
		if compareFactVersion(contribution.targetVersion, floor) > 0 {
			floor = contribution.targetVersion
		}
		if contribution.retentionUntil > retention {
			retention = contribution.retentionUntil
		}
	}
	if len(tombstone.contributors) == 0 {
		delete(c.tombstones, target)
		c.viewChanged = true
		c.persistNeeded = true
		return true
	}
	if compareFactVersion(floor, tombstone.revokedThrough) < 0 {
		var first string
		for ownKey := range tombstone.contributors {
			if first == "" || ownKey < first {
				first = ownKey
			}
		}
		contribution := tombstone.contributors[first]
		contribution.targetVersion = tombstone.revokedThrough
		tombstone.contributors[first] = contribution
		floor = tombstone.revokedThrough
	}
	if compareFactVersion(floor, tombstone.revokedThrough) != 0 {
		tombstone.revokedThrough = floor
		c.viewChanged = true
		changed = true
	}
	if retention != tombstone.retentionUntil {
		tombstone.retentionUntil = retention
		changed = true
	}
	if changed {
		c.persistNeeded = true
	}
	return changed
}

func (c *factStoreCandidate) mergeFact(record FactRecord, key string, source *FactSource, nowMillis uint64) {
	c.mergeCanonicalFact(record, key, source, nowMillis)
}

// mergeCanonicalFact merges one non-suppressed fact into the canonical entry for
// its own FactKey. It returns the resulting entry (nil when the record was not
// admitted) and whether the canonical winner changed.
//
// Only a record that matches the current winning version and canonical bytes is
// a provenance contribution for that winner. A lower version, a replay at or
// below the persisted floor, or a losing equivocation is not a current source.
func (c *factStoreCandidate) mergeCanonicalFact(record FactRecord, key string, source *FactSource, nowMillis uint64) (*factEntry, bool) {
	if c.budgetErr != nil {
		return nil, false
	}
	version := record.Envelope.Version
	if tombstone := c.tombstones[key]; tombstone != nil && compareFactVersion(version, tombstone.revokedThrough) <= 0 {
		if entry := c.entries[key]; entry != nil {
			delete(c.entries, key)
			c.viewChanged = true
		}
		return nil, false
	}

	entry := c.entries[key]
	// A fact published by this node is owned by this node. An ingress snapshot may
	// relay it straight back (A -> B -> A), but that self-echo may never take
	// provenance on the local entry, replace its canonical bytes with an ingress
	// variant or a forged higher own-origin version, or hand WithdrawSource a
	// source it could later delete the local fact with. Only this contribution is
	// ignored; the rest of the otherwise-valid snapshot still merges.
	if entry != nil && entry.local && source != nil {
		return entry, false
	}
	floor := c.hwm[key]
	switch {
	case entry == nil:
		if validVersion(floor.version) && compareFactVersion(version, floor.version) <= 0 {
			return nil, false
		}
		// No absolute-expiry check here: the envelope's timestamps come from the
		// publisher's clock, and admission already rejects a lifetime that is negative or
		// longer than the protocol allows. Whether this fact is still useful is decided
		// after it is stored, against the arrival time recorded there.
	case compareFactVersion(version, entry.version) < 0:
		return entry, false
	case compareFactVersion(version, entry.version) > 0:
		if validVersion(floor.version) && compareFactVersion(version, floor.version) <= 0 {
			return entry, false
		}
	}

	keyBytes, payloadBytes, canonicalBytes := factRecordEncodedSizes(record)
	if !c.reserveGrowth(factRecordEncodingScratchBytes(keyBytes, payloadBytes, canonicalBytes), 0) {
		return entry, false
	}
	canon, err := EncodeFactRecord(record)
	if err != nil {
		return entry, false
	}

	watermarkGrowth := int64(0)
	if _, exists := c.hwm[key]; !exists {
		watermarkGrowth = 2 + int64(len(key)) + 8 + 8 + 8 + factPersistenceBooleanWidth
	}
	switch {
	case entry == nil:
		entryBytes := factEntryStructBytes + canonicalBytes + factRecordBytes(record)
		if source != nil {
			entryBytes += factSourceStructBytes
		}
		growth := factMapEntryOverhead + stringHeaderBytes + int64(len(key)) + entryBytes
		if watermarkGrowth != 0 {
			growth += factMapEntryOverhead + stringHeaderBytes + int64(len(key)) + hwmStructBytes
		}
		if !c.reserveGrowth(growth, watermarkGrowth) {
			return nil, false
		}
		next := makeFactEntry(key, record, canon, source, nowMillis)
		c.entries[key] = next
		// Retention runs from this node's own record of the fact, not the publisher's
		// timestamp: the floor must never depend on two clocks agreeing.
		c.setHWM(key, version, next.expiresAt+factTombstoneRetentionMillis)
		c.persistNeeded = true
		c.viewChanged = true
		return next, true
	case compareFactVersion(version, entry.version) > 0:
		entryBytes := factEntryStructBytes + canonicalBytes + factRecordBytes(record)
		if source != nil {
			entryBytes += factSourceStructBytes
		}
		growth := entryBytes + int64(len(key))
		if watermarkGrowth != 0 {
			growth += factMapEntryOverhead + stringHeaderBytes + int64(len(key)) + hwmStructBytes
		}
		if !c.reserveGrowth(growth, watermarkGrowth) {
			return entry, false
		}
		next := makeFactEntry(key, record, canon, source, nowMillis)
		if entry.local {
			// A winning replacement must never turn a locally published entry
			// nonlocal or attach an ingress source to it.
			next.local = true
			next.sources = nil
			next.saturated = false
		}
		c.entries[key] = next
		// Retention runs from this node's own record of the fact, not the publisher's
		// timestamp: the floor must never depend on two clocks agreeing.
		c.setHWM(key, version, next.expiresAt+factTombstoneRetentionMillis)
		c.persistNeeded = true
		c.viewChanged = true
		return next, true
	case compareFactVersion(version, entry.version) == 0:
		if !bytes.Equal(canon, entry.canon) {
			c.equivocations++
			if bytes.Compare(canon, entry.canon) < 0 {
				growth := factEntryStructBytes + canonicalBytes + factRecordBytes(record) + int64(len(key))
				if watermarkGrowth != 0 {
					growth += factMapEntryOverhead + stringHeaderBytes + int64(len(key)) + hwmStructBytes
				}
				if !c.reserveGrowth(growth, watermarkGrowth) {
					return entry, false
				}
				next := *entry
				next.kind = record.Envelope.Kind
				next.origin = record.Envelope.Origin
				// Re-anchor on the entry's original anchor, not on this arrival. Same version
				// means either record is equally valid, so which one arrived last must not
				// change when the fact expires; the declared lifetime comes from the record
				// being kept.
				lifetime := record.Envelope.ExpiresAt - record.Envelope.IssuedAt
				next.issuedAt = entry.issuedAt
				next.expiresAt = entry.issuedAt + lifetime
				next.canon = canon
				next.record = copyFactRecord(record)
				c.entries[key] = &next
				c.setHWM(key, version, next.expiresAt+factTombstoneRetentionMillis)
				c.addSource(key, source)
				c.persistNeeded = true
				c.viewChanged = true
				return c.entries[key], true
			}
			return entry, false
		}
		canon = nil
		c.addSource(key, source)
		return entry, false
	default:
		return entry, false
	}
}

func (c *factStoreCandidate) addSource(key string, source *FactSource) {
	if source == nil || c.budgetErr != nil {
		return
	}
	entry := c.entries[key]
	// A locally published entry has no ingress provenance, whatever kind of
	// snapshot the source happens to carry.
	if entry == nil || entry.local || hasFactSource(entry.sources, *source) {
		return
	}
	growth := factEntryStructBytes
	if len(entry.sources) < maxFactSources {
		growth += int64(len(entry.sources)+1) * factSourceStructBytes
	}
	if !c.reserveGrowth(growth, 0) {
		return
	}
	next := *entry
	next.sources, next.saturated = addFactSource(entry.sources, entry.saturated, *source)
	if next.saturated == entry.saturated && sameFactSources(next.sources, entry.sources) {
		return
	}
	c.entries[key] = &next
}

// replaceSourceProvenance implements the complete-snapshot rule: after staging,
// this exact source's contribution is atomically replaced. A source keeps
// provenance only on entries whose current winning version and canonical bytes
// it still advertises; a source that now advertises an older or losing variant
// loses that contribution. Keys the source no longer advertises lose that
// source, and a non-saturated fact with no source left becomes Withdrawn
// (deleted). Other sources are untouched.
func (c *factStoreCandidate) replaceSourceProvenance(source FactSource, pages []FactPage) {
	reservation := factSnapshotIncomingReservation(pages)
	if !c.reserveTransient(reservation) {
		return
	}
	defer c.releaseTransient(reservation)
	incoming := make(map[string][]byte)
	for _, page := range pages {
		for _, record := range page.Facts {
			key, err := FactKey(record)
			if err != nil {
				continue
			}
			canon, err := EncodeFactRecord(record)
			if err != nil {
				continue
			}
			incoming[string(key)] = canon
		}
	}
	for key, entry := range c.entries {
		if entry.local || !hasFactSource(entry.sources, source) {
			continue
		}
		if canon, present := incoming[key]; present && bytes.Equal(canon, entry.canon) {
			continue
		}
		if len(entry.sources) == 1 && !entry.saturated {
			delete(c.entries, key)
			c.viewChanged = true
			continue
		}
		growth := factEntryStructBytes + int64(len(entry.sources)-1)*factSourceStructBytes
		if !c.reserveGrowth(growth, 0) {
			return
		}
		next := *entry
		next.sources = removeFactSource(entry.sources, source)
		c.entries[key] = &next
		c.viewChanged = true
	}
}

// claimLocalOwnership makes every key published through PublishLocal owned by
// this node. A key can already exist as ordinary ingress provenance (this
// node's own fact relayed back before this store published it), so the local
// refresh must reclaim it: the entry keeps its current canonical winner but
// loses every ingress source, which makes WithdrawSource unable to erase a fact
// this node published itself. A forgotten locally published fact is what leaves
// the node unreachable until its next refresh.
func (c *factStoreCandidate) claimLocalOwnership(records []FactRecord) {
	if c.budgetErr != nil {
		return
	}
	for _, record := range records {
		key, err := FactKey(record)
		if err != nil {
			continue
		}
		entry := c.entries[string(key)]
		if entry == nil || (entry.local && len(entry.sources) == 0 && !entry.saturated) {
			continue
		}
		next := *entry
		next.local = true
		next.sources = nil
		next.saturated = false
		c.entries[string(key)] = &next
		// Ownership is in-memory only: the entry's floor was already persisted
		// when the entry was admitted, so this needs no durable write.
		c.viewChanged = true
	}
}

// --- finalise / publish ------------------------------------------------------

func (fs *FactStore) finalise(candidate *factStoreCandidate, nowMillis uint64) error {
	if candidate.budgetErr != nil {
		return candidate.budgetErr
	}
	candidate.reclaimHWM(nowMillis)
	if factHWMUnionCount(candidate.entries, candidate.tombstones, candidate.hwm) > maxFactHWMEntries {
		return ErrFactTooLarge
	}
	if len(candidate.entries) > maxFactLiveRecords {
		return ErrFactTooLarge
	}
	quotaScratch := int64(len(candidate.entries))*(int64(unsafe.Sizeof(NodeID{}))+int64(unsafe.Sizeof(int(0)))+factMapEntryOverhead) +
		4*(factMapEntryOverhead+int64(unsafe.Sizeof(int(0))))
	if !candidate.reserveTransient(quotaScratch) {
		return candidate.budgetErr
	}
	kindCounts := map[FactKind]int{}
	originCounts := make(map[NodeID]int, len(candidate.entries))
	for _, entry := range candidate.entries {
		kindCounts[entry.kind]++
		originCounts[entry.origin]++
	}
	kindOverLimit := kindCounts[FactNode] > maxNodeFacts || kindCounts[FactLink] > maxLinkFacts ||
		kindCounts[FactAddress] > maxAddressFacts || kindCounts[FactRevocation] > maxRevocationFacts
	originOverLimit := false
	for _, count := range originCounts {
		if count > maxFactOriginRecords {
			originOverLimit = true
			break
		}
	}
	candidate.releaseTransient(quotaScratch)
	kindCounts = nil
	originCounts = nil
	if kindOverLimit || originOverLimit {
		return ErrFactTooLarge
	}

	watermarkBytes := factWatermarkSerializedBytes(candidate.hwm, candidate.tombstones, candidate.senders)
	if watermarkBytes > factPersistenceMaxBytes {
		return ErrFactTooLarge
	}
	encodeScratch := factWatermarkEncodingScratchBytes(candidate.tombstones, candidate.hwm, candidate.senders)
	if !candidate.reserveTransient(encodeScratch) {
		return candidate.budgetErr
	}
	data, err := encodeFactWatermarks(fs.contextID, fs.wireID, fs.state.Incarnation(), candidate.hwm, candidate.tombstones, candidate.senders)
	candidate.releaseTransient(encodeScratch)
	if err != nil {
		return err
	}
	if int64(len(data)) != watermarkBytes || factStorePeakBytes(fs, candidate)+int64(len(data)) > maxFactOwnedBytes {
		return ErrFactTooLarge
	}
	// The candidate's owned bytes become live with the publish that follows, so
	// they are booked in the Network's one shared allocator first. This is the
	// last gate before anything is committed: the durable write and the publish
	// both come after it, so a refusal leaves the previously published state and
	// the durable floors exactly as they were. A nil port keeps only
	// maxFactOwnedBytes in force. The ledger's own peak rule books this candidate
	// while the store's previous charges are still held, so the committed (not
	// peak) owned bytes are what gets passed.
	if fs.stateBudget != nil && !fs.stateBudget.ResizeState(uint64(ownedFactStoreBytes(candidate))) {
		return ErrFactTooLarge
	}
	if candidate.persistNeeded {
		if err := fs.persistWatermarks(data); err != nil {
			return err
		}
	}
	return nil
}

// reclaimHWM frees high-watermark keys that are neither live facts nor retained
// tombstones when the 16384-entry table is full. A floor may be freed only once
// its recorded retention has elapsed; an unknown/legacy retention is treated as
// forever, so an already-seen version can never revive. Withdrawing a source
// immediately does not make a fresh floor reclaimable.
// reclaimHWM keeps the floor table inside its hard cap.
//
// A floor refuses replayed versions, so it is the one replay guard that does not need a
// clock: the version counter is monotonic no matter how far apart two hosts' clocks are.
// It therefore does not expire on wall-clock time. Retention timestamps are written from
// the publisher's clock and a peer with a slow clock would have made every floor look
// expired at once, re-admitting records the floor existed to refuse.
//
// The cap bounds memory, and retention is measured against this node's own clock: a floor
// is stamped from the moment the fact was stored here, never from the publisher's
// timestamp. That keeps the guard usable between hosts whose clocks disagree, which is the
// whole reason it cannot lean on envelope time.
//
// Reclaiming is only safe once the retention has elapsed, and the oldest retention goes
// first so recently seen keys keep their guard longest.
func (c *factStoreCandidate) reclaimHWM(nowMillis uint64) {
	for factHWMUnionCount(c.entries, c.tombstones, c.hwm) > maxFactHWMEntries {
		reclaimed := false
		oldestKey := ""
		var oldestRetention uint64
		for key, floor := range c.hwm {
			if _, live := c.entries[key]; live {
				continue
			}
			if _, retained := c.tombstones[key]; retained {
				continue
			}
			if !floor.retentionKnown || nowMillis <= floor.retentionUntil {
				continue
			}
			if !reclaimed || floor.retentionUntil < oldestRetention {
				oldestKey = key
				oldestRetention = floor.retentionUntil
				reclaimed = true
			}
		}
		if !reclaimed {
			return
		}
		delete(c.hwm, oldestKey)
		c.persistNeeded = true
	}
}

// setHWM advances one key's persisted floor and retention. A missing or
// zero-version entry starts a known retention; an existing legacy entry keeps
// its unknown/forever retention so an upgrade never infers deletable state.
func (c *factStoreCandidate) setHWM(key string, version FactVersion, retentionUntil uint64) {
	current, exists := c.hwm[key]
	if !exists || !validVersion(current.version) {
		c.hwm[key] = hwmEntry{version: version, retentionUntil: retentionUntil, retentionKnown: true}
		return
	}
	if compareFactVersion(version, current.version) > 0 {
		current.version = version
	}
	if current.retentionKnown && retentionUntil > current.retentionUntil {
		current.retentionUntil = retentionUntil
	}
	c.hwm[key] = current
}

// extendHWMRetention raises an existing, known floor's retention so a related
// tombstone (or a longer original expiry) keeps the floor longer than the fact
// record itself.
func (c *factStoreCandidate) extendHWMRetention(key string, retentionUntil uint64) {
	current, exists := c.hwm[key]
	if !exists || !current.retentionKnown || retentionUntil <= current.retentionUntil {
		return
	}
	current.retentionUntil = retentionUntil
	c.hwm[key] = current
}

func (fs *FactStore) publishCandidate(candidate *factStoreCandidate) {
	fs.entries = candidate.entries
	fs.tombstones = candidate.tombstones
	fs.hwm = candidate.hwm
	fs.senders = candidate.senders
	fs.equivocations = candidate.equivocations
	if candidate.viewChanged {
		fs.bumpViewLocked()
	}
}

func (fs *FactStore) bumpViewLocked() {
	if fs.viewVersion == math.MaxUint64 {
		if fs.failure == nil {
			fs.failure = fmt.Errorf("%w: view version exhausted", ErrFactStoreFailed)
		}
		return
	}
	fs.viewVersion++
}

func (fs *FactStore) visibleLocked(entry *factEntry, nowMillis uint64) bool {
	if nowMillis > entry.expiresAt+factClockSkewMillis {
		return false
	}
	if tombstone := fs.tombstones[entry.key]; tombstone != nil && compareFactVersion(entry.version, tombstone.revokedThrough) <= 0 {
		return false
	}
	return true
}

// --- small helpers -----------------------------------------------------------

func factNowMillis(now time.Time) (uint64, bool) {
	millis := now.UnixMilli()
	if millis < 0 {
		return 0, false
	}
	return uint64(millis), true
}

func validateFactSource(source FactSource, contextID [32]byte) error {
	if source.ContextID != contextID || source.LinkID == 0 || source.Epoch == 0 || source.LaneID != FactLaneControl {
		return ErrFactMalformed
	}
	digest := sha256.Sum256(source.PeerStatic[:])
	if !bytes.Equal(digest[:16], source.AuthenticatedPeer[:]) {
		return ErrFactMalformed
	}
	return nil
}

func senderIdentity(source FactSource) string {
	return string(source.AuthenticatedPeer[:])
}

// makeFactEntry stores one fact, re-anchoring its expiry to the local clock.
//
// The envelope's ExpiresAt is written with the publisher's clock. Keeping it verbatim and
// comparing it against the local clock made two peers with skewed clocks unable to hold
// each other's facts: a fast publisher's facts looked already expired, a slow one's looked
// permanent. Storing "arrival + declared lifetime" keeps a single clock in the comparison.
// The declared lifetime is unchanged, so a fact still lives exactly as long as its
// publisher said, just counted from when this node learned it.
func makeFactEntry(key string, record FactRecord, canon []byte, source *FactSource, nowMillis uint64) *factEntry {
	lifetime := record.Envelope.ExpiresAt - record.Envelope.IssuedAt
	entry := &factEntry{
		key:       key,
		kind:      record.Envelope.Kind,
		origin:    record.Envelope.Origin,
		version:   record.Envelope.Version,
		issuedAt:  nowMillis,
		expiresAt: nowMillis + lifetime,
		canon:     canon,
		record:    copyFactRecord(record),
	}
	if source != nil {
		entry.sources = []FactSource{*source}
	} else {
		entry.local = true
	}
	return entry
}

func compareFactVersion(a, b FactVersion) int {
	switch {
	case a.Incarnation < b.Incarnation:
		return -1
	case a.Incarnation > b.Incarnation:
		return 1
	case a.Sequence < b.Sequence:
		return -1
	case a.Sequence > b.Sequence:
		return 1
	default:
		return 0
	}
}

func maxFactVersion(a, b FactVersion) FactVersion {
	if compareFactVersion(a, b) >= 0 {
		return a
	}
	return b
}

// targetFactKey rebuilds the revoked fact's canonical FactKey bytes from the
// revoked kind/origin/target. LINK keeps its full 41B instance key, so revoking
// one LinkID can never suppress another instance.
func targetFactKey(kind FactKind, origin NodeID, targetKey []byte) []byte {
	key := make([]byte, 0, 1+len(origin)+2+len(targetKey))
	key = append(key, byte(kind))
	key = append(key, origin[:]...)
	key = binary.BigEndian.AppendUint16(key, uint16(len(targetKey)))
	return append(key, targetKey...)
}

// revocationOwnKey rebuilds the canonical FactKey of a REVOCATION from its
// revoker and the revoked fact's canonical key bytes. It matches FactKey() for a
// REVOCATION record exactly: 4 | revoker:16 | target_len:u16 |
// revoker:16|targetOrigin:16|targetKind:1|targetKey. The persistence layer keys
// contributors by this value, so a legacy record is upgraded into the same shape.
func revocationOwnKey(revoker NodeID, target []byte) []byte {
	if len(target) < 1+16+2 {
		return nil
	}
	kind := FactKind(target[0])
	var targetOrigin NodeID
	copy(targetOrigin[:], target[1:17])
	targetKey := target[19:]
	revTarget := make([]byte, 0, RevocationTargetPrefix+len(targetKey))
	revTarget = append(revTarget, revoker[:]...)
	revTarget = append(revTarget, targetOrigin[:]...)
	revTarget = append(revTarget, byte(kind))
	revTarget = append(revTarget, targetKey...)
	key := make([]byte, 0, 1+16+2+len(revTarget))
	key = append(key, byte(FactRevocation))
	key = append(key, revoker[:]...)
	key = binary.BigEndian.AppendUint16(key, uint16(len(revTarget)))
	return append(key, revTarget...)
}

func addFactSource(sources []FactSource, saturated bool, source FactSource) ([]FactSource, bool) {
	for _, existing := range sources {
		if existing == source {
			return sources, saturated
		}
	}
	if len(sources) >= maxFactSources {
		return sources, true
	}
	next := make([]FactSource, len(sources)+1)
	copy(next, sources)
	next[len(sources)] = source
	return next, saturated
}

func hasFactSource(sources []FactSource, source FactSource) bool {
	for _, existing := range sources {
		if existing == source {
			return true
		}
	}
	return false
}

func removeFactSource(sources []FactSource, source FactSource) []FactSource {
	if !hasFactSource(sources, source) {
		return sources
	}
	next := make([]FactSource, 0, len(sources)-1)
	for _, existing := range sources {
		if existing == source {
			continue
		}
		next = append(next, existing)
	}
	return next
}

func sameFactSources(a, b []FactSource) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func copyFactRecord(record FactRecord) FactRecord {
	switch payload := record.Payload.(type) {
	case NodePayload:
		capabilities := payload.Capabilities
		payload.Capabilities = make([]string, len(capabilities))
		copy(payload.Capabilities, capabilities)
		return FactRecord{Envelope: record.Envelope, Payload: payload}
	case LinkPayload:
		capabilities := payload.Capabilities
		payload.Capabilities = make([]string, len(capabilities))
		copy(payload.Capabilities, capabilities)
		return FactRecord{Envelope: record.Envelope, Payload: payload}
	case AddressPayload:
		return FactRecord{Envelope: record.Envelope, Payload: payload}
	case RevocationPayload:
		targetKey := payload.TargetKey
		payload.TargetKey = make([]byte, len(targetKey))
		copy(payload.TargetKey, targetKey)
		return FactRecord{Envelope: record.Envelope, Payload: payload}
	default:
		return FactRecord{Envelope: record.Envelope, Payload: record.Payload}
	}
}

// --- conservative owned-memory accounting ------------------------------------

var (
	factSourceStructBytes  = int64(unsafe.Sizeof(FactSource{}))
	factEntryStructBytes   = int64(unsafe.Sizeof(factEntry{}))
	tombstoneStructBytes   = int64(unsafe.Sizeof(tombstoneEntry{}))
	hwmStructBytes         = int64(unsafe.Sizeof(hwmEntry{}))
	senderStructBytes      = int64(unsafe.Sizeof(senderFloor{}))
	envelopeStructBytes    = int64(unsafe.Sizeof(FactEnvelope{}))
	stringHeaderBytes      = int64(unsafe.Sizeof(""))
	byteSliceHeaderBytes   = int64(unsafe.Sizeof([]byte(nil)))
	contributionStructByte = int64(unsafe.Sizeof(revocationContribution{}))
)

// ownedFactStoreBytes counts one candidate's objects and map entries. Peak
// accounting adds the old store separately while deduplicating shared entries.
func ownedFactStoreBytes(candidate *factStoreCandidate) int64 {
	var total int64
	for key, entry := range candidate.entries {
		total += factMapEntryOverhead + stringHeaderBytes + int64(len(key)) + factEntryBytes(entry) + separateEntryKeyBytes(key, entry)
	}
	for key, tombstone := range candidate.tombstones {
		total += factMapEntryOverhead + stringHeaderBytes + int64(len(key)) + tombstoneBytes(tombstone)
	}
	for key := range candidate.hwm {
		total += factMapEntryOverhead + stringHeaderBytes + int64(len(key)) + hwmStructBytes
	}
	for key := range candidate.senders {
		total += factMapEntryOverhead + stringHeaderBytes + int64(len(key)) + senderStructBytes
	}
	return total
}

func factStorePeakBytes(fs *FactStore, candidate *factStoreCandidate) int64 {
	total := ownedFactStoreBytes(candidate)
	total += factMapCloneExtra(len(fs.entries), len(candidate.entries))
	total += factMapCloneExtra(len(fs.tombstones), len(candidate.tombstones))
	total += factMapCloneExtra(len(fs.hwm), len(candidate.hwm))
	total += factMapCloneExtra(len(fs.senders), len(candidate.senders))

	for key, entry := range fs.entries {
		if candidate.entries[key] != entry {
			total += factEntryBytes(entry) + separateEntryKeyBytes(key, entry)
		}
		if _, present := candidate.entries[key]; !present {
			total += stringHeaderBytes + int64(len(key))
		}
	}
	for key, tombstone := range fs.tombstones {
		other := candidate.tombstones[key]
		total += tombstoneBackingBytes(tombstone, other)
		if other == nil {
			total += stringHeaderBytes + int64(len(key))
		}
	}
	for key := range fs.hwm {
		total += hwmStructBytes
		if _, present := candidate.hwm[key]; !present {
			total += stringHeaderBytes + int64(len(key))
		}
	}
	for key := range fs.senders {
		total += senderStructBytes
		if _, present := candidate.senders[key]; !present {
			total += stringHeaderBytes + int64(len(key))
		}
	}
	return total
}

func factStoreClonePeakBytes(fs *FactStore) int64 {
	candidate := &factStoreCandidate{
		entries: fs.entries, tombstones: fs.tombstones, hwm: fs.hwm, senders: fs.senders,
	}
	return factStorePeakBytes(fs, candidate)
}

func factMapCloneExtra(oldCount, candidateCount int) int64 {
	candidateSlots := oldCount
	if candidateCount > candidateSlots {
		candidateSlots = candidateCount
	}
	return factMapEntryOverhead * int64(oldCount+candidateSlots-candidateCount)
}

func separateEntryKeyBytes(mapKey string, entry *factEntry) int64 {
	if entry.key != "" && unsafe.StringData(mapKey) != unsafe.StringData(entry.key) {
		return int64(len(entry.key))
	}
	return 0
}

func tombstoneBackingBytes(tombstone, candidate *tombstoneEntry) int64 {
	total := tombstoneStructBytes + int64(cap(tombstone.targetKey))
	total += factMapEntryOverhead * int64(len(tombstone.contributors))
	total += contributionStructByte * int64(len(tombstone.contributors))
	if candidate != nil && len(candidate.contributors) < len(tombstone.contributors) {
		total += factMapEntryOverhead * int64(len(tombstone.contributors)-len(candidate.contributors))
	}
	for key := range tombstone.contributors {
		if candidate == nil {
			total += stringHeaderBytes + int64(len(key))
			continue
		}
		if _, present := candidate.contributors[key]; !present {
			total += stringHeaderBytes + int64(len(key))
		}
	}
	return total
}

func factEntryBytes(entry *factEntry) int64 {
	total := factEntryStructBytes
	total += int64(cap(entry.canon))
	total += factRecordBytes(entry.record)
	total += int64(cap(entry.sources)) * factSourceStructBytes
	return total
}

func tombstoneBytes(tombstone *tombstoneEntry) int64 {
	total := tombstoneStructBytes
	total += int64(cap(tombstone.targetKey))
	total += factMapEntryOverhead * int64(len(tombstone.contributors))
	for ownKey, contribution := range tombstone.contributors {
		total += stringHeaderBytes + int64(len(ownKey)) + contributionStructByte
		_ = contribution
	}
	return total
}

// factRecordBytes bounds one decoded record: the envelope plus the decoded
// payload's value struct, owned strings and owned target bytes.
func factRecordBytes(record FactRecord) int64 {
	total := envelopeStructBytes
	switch payload := record.Payload.(type) {
	case NodePayload:
		total += int64(unsafe.Sizeof(payload))
		total += ownedStringSliceBytes(payload.Capabilities)
	case LinkPayload:
		total += int64(unsafe.Sizeof(payload))
		total += ownedStringSliceBytes(payload.Capabilities)
		total += int64(len(payload.ConnectionType))
	case AddressPayload:
		total += int64(unsafe.Sizeof(payload))
	case RevocationPayload:
		total += int64(unsafe.Sizeof(payload))
		total += int64(cap(payload.TargetKey))
	default:
		total += 64
	}
	return total
}

func ownedStringSliceBytes(values []string) int64 {
	total := int64(cap(values)) * stringHeaderBytes
	for _, value := range values {
		total += int64(len(value))
	}
	return total
}

func factRecordEncodedSizes(record FactRecord) (keyBytes, payloadBytes, canonicalBytes int64) {
	switch payload := record.Payload.(type) {
	case NodePayload:
		keyBytes = 35
		payloadBytes = 16 + 32 + factCapabilitiesEncodedBytes(payload.Capabilities)
	case LinkPayload:
		keyBytes = 60
		payloadBytes = 8 + 8 + 1 + 16 + 16 + 20 + factCapabilitiesEncodedBytes(payload.Capabilities) + 2 + int64(len(payload.ConnectionType))
	case AddressPayload:
		keyBytes = 39
		payloadBytes = 16 + 4 + 1 + 1
	case RevocationPayload:
		keyBytes = 52 + int64(len(payload.TargetKey))
		payloadBytes = 16 + 16 + 1 + 2 + int64(len(payload.TargetKey)) + 4*8
	}
	canonicalBytes = 2 + keyBytes + FactEnvelopeSize + payloadBytes
	return keyBytes, payloadBytes, canonicalBytes
}

func factCapabilitiesEncodedBytes(values []string) int64 {
	total := int64(2)
	for _, value := range values {
		total += 2 + int64(len(value))
	}
	return total
}

func factRecordEncodingScratchBytes(keyBytes, payloadBytes, canonicalBytes int64) int64 {
	targetBytes := keyBytes - 19
	peak := keyBytes + payloadBytes + canonicalBytes
	if targetBytes+keyBytes > peak {
		peak = targetBytes + keyBytes
	}
	if targetBytes+payloadBytes > peak {
		peak = targetBytes + payloadBytes
	}
	return peak
}

func factTargetExpiryMapReservationPages(pages []FactPage) (int64, int) {
	reservation, count := 4*int64(MaxFactKey), 0
	for _, page := range pages {
		for _, record := range page.Facts {
			if _, isRevocation := record.Payload.(RevocationPayload); isRevocation {
				continue
			}
			keyBytes, _, _ := factRecordEncodedSizes(record)
			reservation += factMapEntryOverhead + stringHeaderBytes + keyBytes + 8
			count++
		}
	}
	return reservation, count
}

func factTargetExpiryMapReservation(records []FactRecord) (int64, int) {
	reservation, count := 4*int64(MaxFactKey), 0
	for _, record := range records {
		if _, isRevocation := record.Payload.(RevocationPayload); isRevocation {
			continue
		}
		keyBytes, _, _ := factRecordEncodedSizes(record)
		reservation += factMapEntryOverhead + stringHeaderBytes + keyBytes + 8
		count++
	}
	return reservation, count
}

func factSnapshotIncomingReservation(pages []FactPage) int64 {
	reservation, scratch := int64(0), int64(0)
	for _, page := range pages {
		for _, record := range page.Facts {
			keyBytes, payloadBytes, canonicalBytes := factRecordEncodedSizes(record)
			reservation += factMapEntryOverhead + stringHeaderBytes + keyBytes + byteSliceHeaderBytes + canonicalBytes
			currentScratch := factRecordEncodingScratchBytes(keyBytes, payloadBytes, canonicalBytes) - canonicalBytes
			if currentScratch > scratch {
				scratch = currentScratch
			}
		}
	}
	return reservation + scratch
}

func factWatermarkSerializedBytes(hwm map[string]hwmEntry, tombstones map[string]*tombstoneEntry, senders map[string]senderFloor) int64 {
	total := int64(factWatermarkHeaderSize + 3*4)
	for key := range hwm {
		total += 2 + int64(len(key)) + 8 + 8 + 8 + factPersistenceBooleanWidth
	}
	for range senders {
		total += 16 + 8 + 8 + factPersistenceDigestSize + factPersistenceBooleanWidth
	}
	for _, tombstone := range tombstones {
		total += 1 + 16 + 2 + int64(len(tombstone.targetKey)) + 8 + 8 + 8 + 4
		for ownKey := range tombstone.contributors {
			total += 2 + int64(len(ownKey)) + 8 + 8 + 8
		}
	}
	return total
}

func factWatermarkEncodingScratchBytes(tombstones map[string]*tombstoneEntry, hwm map[string]hwmEntry, senders map[string]senderFloor) int64 {
	outerKeys := len(tombstones) + len(hwm) + len(senders)
	maxContributors := 0
	for _, tombstone := range tombstones {
		if len(tombstone.contributors) > maxContributors {
			maxContributors = len(tombstone.contributors)
		}
	}
	return stringHeaderBytes * int64(outerKeys+maxContributors)
}

func factHWMUnionCount(entries map[string]*factEntry, tombstones map[string]*tombstoneEntry, hwm map[string]hwmEntry) int {
	count := len(hwm)
	for key := range entries {
		if _, present := hwm[key]; !present {
			count++
		}
	}
	for key := range tombstones {
		if _, present := hwm[key]; present {
			continue
		}
		if _, present := entries[key]; present {
			continue
		}
		count++
	}
	return count
}
