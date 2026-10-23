package simpletier

import (
	"bytes"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/topology"
)

// This file is the outbound half of the authenticated FACT v2 synchronization:
// every registered CONTROL Link of a running Network offers whole, immutable
// snapshots of this node's FactStore and the peer drives the page transfer with
// FACT_ACK. The sender is deliberately built on the existing single protected
// reader/writer: it only enqueues into controlPump.outbound and never opens a
// second reader, writer or protector.
//
// Boundaries: no data lane, no crypto, no PACKET/STREAM, no RouteView/Dial
// change. Facts learned from a peer are forwarded verbatim to other peers, so an
// A-R-B topology discovers A and B without a direct Link; forwarding never
// allocates a new durable fact sequence because the records keep their original
// publisher version and Origin.

const (
	// factSenderRetryInterval bounds how long one outstanding SUMMARY or page
	// waits for its matching ACK before the identical immutable frame is retried.
	factSenderRetryInterval = 2 * time.Second

	// factSenderMaxAttempts bounds resends of one frame. Exhaustion stops this
	// attempt instead of flooding; the next FactStore change or the periodic local
	// re-advertisement starts a fresh snapshot version.
	factSenderMaxAttempts = 5

	// factSenderTickInterval drives adoption of a newer snapshot and bounded
	// retries. Commits, withdrawals and admissions also wake the worker directly.
	factSenderTickInterval = 250 * time.Millisecond

	// factSenderGlobalBytes bounds the aggregate canonical bytes of the immutable
	// outbound snapshots currently referenced by Link senders. It is a ceiling,
	// not a preallocation: exceeding it defers the next snapshot and is
	// diagnosable, never a silent truncation of the current one.
	factSenderGlobalBytes int64 = 8 << 20

	// factSenderProgressTimeout is how long an actively progressing transfer may
	// go without a correlated ACK before a newer snapshot may supersede it. A
	// multi-page transfer that keeps receiving page requests is therefore never
	// starved by periodic store churn, while a stalled transfer is replaced.
	factSenderProgressTimeout = 3 * factSenderRetryInterval

	// factStagingTTL is the frozen advertisement validity reused as the inbound
	// staging TTL. A partially transferred snapshot older than one advertisement
	// window can only advertise already-expired facts, so it is dropped and the
	// peer is asked for a fresh SUMMARY instead of being committed late.
	factStagingTTL = time.Duration(factAdvertisementTTLMillis) * time.Millisecond
)

// factSenderState is the per-Link progress of one outbound snapshot offer.
type factSenderState uint8

const (
	// factSenderIdle is a Link that has never offered a snapshot and has no
	// current snapshot to offer.
	factSenderIdle factSenderState = iota
	// factSenderOffered means the SUMMARY was sent and is waiting for the first
	// matching ACK.
	factSenderOffered
	// factSenderTransferring means a page was requested and the requested page
	// (or a resend of it) is outstanding.
	factSenderTransferring
	// factSenderComplete means the peer atomically committed this snapshot
	// version.
	factSenderComplete
	// factSenderRejected means the peer answered REJECT for this snapshot
	// version. The version is not retried; a newer snapshot may still be offered.
	factSenderRejected
	// factSenderFailed means the bounded retries of the current frame were
	// exhausted. No further frame of this version is sent.
	factSenderFailed
)

// factSnapshot is one immutable, canonical outbound snapshot shared by every
// Link that has not completed it. records and pages are never mutated after
// construction, so a Link can hold the exact bytes it was acknowledged against
// even while the FactStore publishes newer versions.
//
// bytes is the exact canonical FactRecord byte total (the same unit as
// factSnapshotCanonicalBytes), used only for the network-wide admission budget.
// It is an accounting unit, not a claim about Go heap occupancy: the FactStore's
// caller-owned record copies, the decoded page copies and the encoder scratch
// are outside this number.
type factSnapshot struct {
	incarnation  uint64
	version      uint64
	networkID    uint64
	summary      topology.FactSummary
	pages        []topology.FactPage
	bytes        int64
	storeVersion uint64
}

// factOutbound is one frame to send for a snapshot: a SUMMARY when isPage is
// false, otherwise one FACT_PAGE.
type factOutbound struct {
	snapshot *factSnapshot
	page     uint32
	isPage   bool
}

// factSendPlan is the outcome of one Link tick.
type factSendPlan struct {
	send   bool
	retry  bool
	action factOutbound
}

// factAckResult is the outcome of correlating one inbound FACT_ACK.
type factAckResult struct {
	correlated bool
	send       bool
	completed  bool
	rejected   bool
	action     factOutbound
}

// factLinkSender owns the bounded outbound offer state of exactly one
// authenticated CONTROL Link. It references at most one immutable snapshot at a
// time, so a Link's outbound memory is bounded by one snapshot even when the
// shared snapshot is replaced.
type factLinkSender struct {
	mu       sync.Mutex
	offered  *factSnapshot
	state    factSenderState
	attempts int
	retryAt  time.Time
	// lastProgress is the most recent correlated forward progress (offer adoption
	// or a matched page/complete ACK). It gates newer-snapshot adoption so a slow
	// but live multi-page transfer can finish instead of being restarted forever.
	lastProgress time.Time
	nextPage     uint32
	reason       uint16
}

// maySupersede reports whether a newer snapshot may replace the current offer.
// A transfer that is still receiving matched ACKs keeps its snapshot; a
// completed, rejected, failed or stalled one yields to the newer version.
func (s *factLinkSender) maySupersede(now time.Time) bool {
	if s.offered == nil || s.state == factSenderIdle {
		return true
	}
	switch s.state {
	case factSenderComplete, factSenderRejected, factSenderFailed:
		return true
	}
	return s.lastProgress.IsZero() || now.Sub(s.lastProgress) > factSenderProgressTimeout
}

// plan decides whether this Link must (re)send a frame now. A strictly newer
// snapshot supersedes the current offer only when that offer is finished,
// failed, rejected or stalled; an in-progress transfer that keeps making
// progress is allowed to complete, so periodic store churn cannot starve a
// bounded 64-page transfer.
func (s *factLinkSender) plan(snapshot *factSnapshot, now time.Time) factSendPlan {
	if s == nil {
		return factSendPlan{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snapshot != nil && (s.offered == nil || snapshot.version > s.offered.version) && s.maySupersede(now) {
		s.offered = snapshot
		s.state = factSenderOffered
		s.attempts = 0
		s.retryAt = now
		s.lastProgress = now
		s.nextPage = 0
		s.reason = 0
	}
	if s.offered == nil {
		return factSendPlan{}
	}
	switch s.state {
	case factSenderOffered, factSenderTransferring:
	default:
		return factSendPlan{}
	}
	if now.Before(s.retryAt) {
		return factSendPlan{}
	}
	if s.attempts >= factSenderMaxAttempts {
		s.state = factSenderFailed
		return factSendPlan{}
	}
	s.attempts++
	s.retryAt = now.Add(factSenderRetryInterval)
	retry := s.attempts > 1
	if s.state == factSenderOffered {
		return factSendPlan{send: true, retry: retry, action: factOutbound{snapshot: s.offered}}
	}
	page := s.nextPage
	if int(page) >= len(s.offered.pages) {
		page = 0
	}
	return factSendPlan{send: true, retry: retry, action: factOutbound{snapshot: s.offered, page: page, isPage: true}}
}

// onAck correlates one inbound FACT_ACK against this Link's current offer. A
// mismatching NetworkID, sender incarnation or snapshot version is stale and is
// ignored without touching any state; a status that no longer applies to an
// already completed/rejected offer is correlated but inert.
func (s *factLinkSender) onAck(ack topology.FactAck, networkID, incarnation uint64, now time.Time) factAckResult {
	if s == nil {
		return factAckResult{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ack.NetworkID != networkID || ack.SenderIncarnation != incarnation {
		return factAckResult{}
	}
	if s.offered == nil || ack.SnapshotVersion != s.offered.version {
		return factAckResult{}
	}
	if ack.Status == topology.AckComplete {
		// A late COMPLETE still proves the peer committed this exact version,
		// even after a retry bound expired locally. The completion counter must be
		// raised at most once per offer, so a repeated COMPLETE reports
		// completed=false.
		already := s.state == factSenderComplete
		s.state = factSenderComplete
		s.attempts = 0
		s.lastProgress = now
		return factAckResult{correlated: true, completed: !already}
	}
	switch s.state {
	case factSenderComplete, factSenderRejected, factSenderFailed:
		return factAckResult{correlated: true}
	}
	switch ack.Status {
	case topology.AckNeedPage:
		if ack.MissingPage >= s.offered.summary.PageCount {
			return factAckResult{correlated: true}
		}
		if s.state == factSenderTransferring && s.nextPage == ack.MissingPage {
			// A repeated request for the page already outstanding is not forward
			// progress: it must not reset the attempt budget or slide the progress
			// clock. The bounded retry in plan() resends it, so a peer that only
			// repeats itself can neither gain unlimited quota nor keep a stalled
			// transfer alive against a newer snapshot.
			return factAckResult{correlated: true}
		}
		s.nextPage = ack.MissingPage
		s.state = factSenderTransferring
		s.attempts = 0
		s.retryAt = now.Add(factSenderRetryInterval)
		s.lastProgress = now
		return factAckResult{
			correlated: true,
			send:       true,
			action:     factOutbound{snapshot: s.offered, page: ack.MissingPage, isPage: true},
		}
	case topology.AckNeedSummary:
		if s.state == factSenderOffered {
			// The SUMMARY is already outstanding: a repeat request is served by the
			// bounded retry, not by a fresh attempt budget.
			return factAckResult{correlated: true}
		}
		s.state = factSenderOffered
		s.attempts = 0
		s.retryAt = now.Add(factSenderRetryInterval)
		s.lastProgress = now
		return factAckResult{correlated: true, send: true, action: factOutbound{snapshot: s.offered}}
	case topology.AckOK:
		// The peer kept the page but the snapshot is not complete yet. An OK is an
		// acknowledgement, not forward progress: it never resets the attempt
		// budget and never slides the progress clock.
		if s.state != factSenderTransferring {
			s.state = factSenderTransferring
		}
		if s.retryAt.Before(now) {
			s.retryAt = now.Add(factSenderRetryInterval)
		}
		return factAckResult{correlated: true}
	case topology.AckReject:
		s.state = factSenderRejected
		s.reason = ack.Reason
		s.attempts = 0
		s.lastProgress = now
		return factAckResult{correlated: true, rejected: true}
	}
	return factAckResult{}
}

// pendingReports whether this Link currently has an unacknowledged offer.
func (s *factLinkSender) pending() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == factSenderOffered || s.state == factSenderTransferring
}

// offeredBytes returns the canonical bytes of the snapshot this Link currently
// references; it is used for the network-wide outbound memory accounting.
func (s *factLinkSender) offeredBytes() int64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.offered == nil {
		return 0
	}
	return s.offered.bytes
}

// offeredSnapshot returns the snapshot this Link currently references.
func (s *factLinkSender) offeredSnapshot() *factSnapshot {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.offered
}

// buildFactSnapshot turns one already sorted-by-key FactStore snapshot into a
// digest-bound, page-chunked immutable snapshot. Page boundaries are derived
// deterministically from the canonical record bytes, so the receiver's
// ValidateSnapshot recomputation matches byte for byte.
//
// The u64 NetworkID is an outer locator, not an isolation root: a zero value is
// a legal derived locator and must be transmitted exactly like any other.
func buildFactSnapshot(networkID, incarnation, version, storeVersion uint64, records []topology.FactRecord) (*factSnapshot, error) {
	if incarnation == 0 || version == 0 {
		return nil, errors.New("outbound FACT snapshot requires a durable incarnation and version")
	}
	type keyedRecord struct {
		key    []byte
		record topology.FactRecord
	}
	items := make([]keyedRecord, 0, len(records))
	var canonicalTotal int64
	for _, record := range records {
		key, err := topology.FactKey(record)
		if err != nil {
			return nil, err
		}
		canonical, err := topology.EncodeFactRecord(record)
		if err != nil {
			return nil, err
		}
		canonicalTotal += int64(len(canonical))
		items = append(items, keyedRecord{key: key, record: record})
	}
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].key, items[j].key) < 0 })
	for i := 1; i < len(items); i++ {
		if bytes.Equal(items[i].key, items[i-1].key) {
			return nil, topology.ErrFactMalformed
		}
	}

	var chunks [][]topology.FactRecord
	start := 0
	for start < len(items) {
		end := start
		pageBytes := 0
		for end < len(items) && end-start < topology.MaxPageRecords {
			canonical, err := topology.EncodeFactRecord(items[end].record)
			if err != nil {
				return nil, err
			}
			if pageBytes+len(canonical) > topology.MaxPageBytes && end > start {
				break
			}
			pageBytes += len(canonical)
			end++
		}
		if end == start {
			end++
		}
		chunk := make([]topology.FactRecord, 0, end-start)
		for _, item := range items[start:end] {
			chunk = append(chunk, item.record)
		}
		chunks = append(chunks, chunk)
		start = end
	}
	if len(chunks) > topology.MaxSnapshotPages {
		return nil, topology.ErrFactTooLarge
	}

	pages := make([]topology.FactPage, 0, len(chunks))
	digests := make([][32]byte, 0, len(chunks))
	for number, chunk := range chunks {
		encoded, err := topology.EncodeFactPage(topology.FactPage{
			ProtocolVersion:   topology.FactProtocolVersion,
			SenderIncarnation: incarnation,
			NetworkID:         networkID,
			SnapshotVersion:   version,
			PageNo:            uint32(number),
			PageCount:         uint32(len(chunks)),
			Facts:             chunk,
		})
		if err != nil {
			return nil, err
		}
		page, err := topology.DecodeFactPage(encoded)
		if err != nil {
			return nil, err
		}
		pages = append(pages, page)
		digests = append(digests, page.PageDigest)
	}
	digest, err := topology.SnapshotDigest(incarnation, version, digests)
	if err != nil {
		return nil, err
	}
	summary := topology.FactSummary{
		ProtocolVersion:   topology.FactProtocolVersion,
		SenderIncarnation: incarnation,
		NetworkID:         networkID,
		SnapshotVersion:   version,
		FactCount:         uint32(len(items)),
		PageCount:         uint32(len(pages)),
		Digest:            digest,
	}
	if err := topology.ValidateSnapshot(summary, pages); err != nil {
		return nil, err
	}
	return &factSnapshot{
		incarnation:  incarnation,
		version:      version,
		networkID:    networkID,
		summary:      summary,
		pages:        pages,
		bytes:        canonicalTotal,
		storeVersion: storeVersion,
	}, nil
}

// --- network-level outbound snapshot cache -----------------------------------

// senderState is the mutable sender half of the FACT runtime. It is embedded in
// factRuntime so the existing single owner of the FactStore also owns the
// outbound snapshot cache and its wake channel.
type senderState struct {
	// mu guards the cached immutable snapshot and its build bookkeeping. It is
	// never held across FactStore calls or socket work.
	mu                sync.Mutex
	outbound          *factSnapshot
	builtStoreVersion uint64
	built             bool
	nonEmptyBuilt     bool
	backpressureAt    time.Time
}

// ensureOutbound returns the immutable snapshot every Link should offer now,
// rebuilding it only when the FactStore view advanced. A snapshot version is
// spent only for an actual rebuild, so redundant forwarding cannot churn the
// durable counter.
func (f *factRuntime) ensureOutbound(now time.Time) *factSnapshot {
	if f == nil || f.network == nil || f.network.runtimeState == nil {
		return nil
	}
	storeVersion := f.store.Version()
	f.sender.mu.Lock()
	cached := f.sender.outbound
	if f.sender.built && f.sender.builtStoreVersion == storeVersion {
		f.sender.mu.Unlock()
		return cached
	}
	if !f.sender.backpressureAt.IsZero() && now.Before(f.sender.backpressureAt) {
		f.sender.mu.Unlock()
		return cached
	}
	f.sender.mu.Unlock()

	records, version, err := f.store.Snapshot(now)
	if err != nil {
		f.observeStoreError(err)
		slog.Default().Debug("outbound FACT snapshot unavailable", "phase", "facts")
		f.deferOutbound(now)
		return cached
	}
	if len(records) == 0 && !f.senderNonEmptyBuilt() {
		// Nothing was ever advertised: an empty snapshot would only spend a
		// durable version to describe an empty set. This no-offer outcome is a
		// successful cache commit, so it is not rebuilt on every tick.
		f.commitOutboundCache(version, nil, false)
		return nil
	}
	// The candidate's canonical size is measured and checked against the peak
	// outbound budget before a durable snapshot version is spent, so a
	// budget-rejected snapshot cannot burn the counter. A later failure (durable
	// version allocation or snapshot build/validation) may leave a conservative
	// version hole; gaps are permitted and a version is never reused.
	candidateBytes, err := factSnapshotCanonicalBytes(records)
	if err != nil {
		slog.Default().Debug("outbound FACT snapshot rejected", "phase", "facts")
		f.deferOutbound(now)
		return cached
	}
	if !f.senderBudgetAllows(cached, candidateBytes) {
		slog.Default().Debug("outbound FACT snapshot deferred by network budget", "phase", "facts")
		f.deferOutbound(now)
		return cached
	}
	incarnation := f.network.runtimeState.Incarnation()
	snapshotVersion, err := f.network.runtimeState.NextSnapshotVersion()
	if err != nil {
		slog.Default().Debug("outbound FACT snapshot version unavailable", "phase", "facts")
		f.deferOutbound(now)
		return cached
	}
	snapshot, err := buildFactSnapshot(f.network.networkContext.WireID(), incarnation, snapshotVersion, version, records)
	if err != nil {
		slog.Default().Debug("outbound FACT snapshot rejected", "phase", "facts")
		f.deferOutbound(now)
		return cached
	}
	// Only a successful build commits the cache bookkeeping. An empty withdrawal
	// snapshot is therefore retried after backoff instead of being mistaken for
	// an already-built version.
	f.commitOutboundCache(version, snapshot, len(records) > 0)
	// The committed cache plus every snapshot a Link still offers is the
	// sender's live referenced set, so book it against the Network's shared
	// allocator and let the frozen heap see this plane. A refused reservation is
	// an accounting failure only: the built snapshot is still published and only
	// the next rebuild is deferred, so booking can never fail a build.
	if !f.senderBudget.resize(f.referencedSnapshotBytes(snapshot) + snapshot.bytes) {
		slog.Default().Debug("outbound FACT snapshot reservation deferred", "phase", "facts")
		f.deferOutbound(now)
	}
	f.senderSnapshots.Add(1)
	return snapshot
}

// senderNonEmptyBuilt reports whether any non-empty snapshot was ever built.
func (f *factRuntime) senderNonEmptyBuilt() bool {
	f.sender.mu.Lock()
	defer f.sender.mu.Unlock()
	return f.sender.nonEmptyBuilt
}

// commitOutboundCache installs a successfully built snapshot (or records the
// successful no-offer decision for a never-advertised empty store) as the cache
// for storeVersion.
func (f *factRuntime) commitOutboundCache(storeVersion uint64, snapshot *factSnapshot, nonEmpty bool) {
	f.sender.mu.Lock()
	if snapshot != nil {
		f.sender.outbound = snapshot
	}
	f.sender.built = true
	f.sender.builtStoreVersion = storeVersion
	if nonEmpty {
		f.sender.nonEmptyBuilt = true
	}
	f.sender.mu.Unlock()
}

// factSnapshotCanonicalBytes measures the canonical record bytes of a candidate
// snapshot without binding it to a sender incarnation/version yet.
func factSnapshotCanonicalBytes(records []topology.FactRecord) (int64, error) {
	var total int64
	for _, record := range records {
		encoded, err := topology.EncodeFactRecord(record)
		if err != nil {
			return 0, err
		}
		total += int64(len(encoded))
		if total > topology.MaxSnapshotBytes {
			return 0, topology.ErrFactTooLarge
		}
	}
	return total, nil
}

// deferOutbound delays the next rebuild attempt so a transient snapshot,
// version or budget failure does not turn into a busy rebuild loop.
func (f *factRuntime) deferOutbound(now time.Time) {
	f.sender.mu.Lock()
	f.sender.backpressureAt = now.Add(factSenderRetryInterval)
	f.sender.mu.Unlock()
}

// senderBudgetAllows reports whether building and publishing the candidate keeps
// the outbound snapshot set inside factSenderGlobalBytes. Both the candidate and
// every referenced snapshot are measured in the same canonical FactRecord byte
// unit (factSnapshot.bytes).
//
// This is an explicit admission budget, NOT a true heap-peak budget. It does not
// model retained Go heap beyond canonical record bytes: the caller-owned record
// copies returned by FactStore.Snapshot, the per-page FactRecord value copies and
// FactPage containers, and the transient encoder scratch (canonical page bytes,
// sorted key/plan records, page digests) are not counted. A same-unit owned
// estimate covering records/pages/scratch is still missing.
//
// Each referenced immutable snapshot is counted exactly once by pointer: the
// cached snapshot is live during the build and every snapshot a Link still
// references stays live, so the cached bytes may only be omitted when no Link
// references them and the build releases its own reference.
func (f *factRuntime) senderBudgetAllows(cached *factSnapshot, next int64) bool {
	if next > topology.MaxSnapshotBytes {
		return false
	}
	return f.referencedSnapshotBytes(cached)+next <= factSenderGlobalBytes
}

// referencedSnapshotBytes totals the canonical bytes of every immutable snapshot
// the outbound sender keeps live, counting each snapshot exactly once by
// pointer. cached is the snapshot the cache holds (nil when nothing was built);
// every snapshot a Link still offers is added unless it is already counted, and
// the cached bytes are dropped only when no Link references them, because a
// published candidate releases the build's own reference.
func (f *factRuntime) referencedSnapshotBytes(cached *factSnapshot) int64 {
	referenced := map[*factSnapshot]struct{}{}
	var total int64
	if cached != nil {
		referenced[cached] = struct{}{}
		total += cached.bytes
	}
	links := f.network.controlPumpSnapshot()
	cachedStillReferenced := false
	for _, pump := range links {
		offered := pump.sender.offeredSnapshot()
		if offered == nil {
			continue
		}
		if offered == cached {
			cachedStillReferenced = true
		}
		if _, seen := referenced[offered]; seen {
			continue
		}
		referenced[offered] = struct{}{}
		total += offered.bytes
	}
	if cached != nil && !cachedStillReferenced {
		// The cached snapshot is superseded once the new one is published and no
		// Link holds it, so its bytes leave the referenced set after this build.
		total -= cached.bytes
	}
	return total
}

// sweepExpiredStaging releases every inbound staging that outlived the frozen
// advertisement TTL and asks its owning Link for a fresh SUMMARY. Without this
// sweep an authenticated peer that stops mid-transfer (or goes silent) would hold
// the bounded staging budget until it speaks again. The release happens under
// f.mu and the matching NEED_SUMMARY is enqueued outside the lock through the
// owning pump, so staged bytes are reclaimed even when the Link's control queue
// is full or the Link already left the registry.
func (f *factRuntime) sweepExpiredStaging(now time.Time) {
	if f == nil || f.network == nil {
		return
	}
	type releasedStaging struct {
		linkID  uint64
		summary topology.FactSummary
	}
	var released []releasedStaging
	f.mu.Lock()
	for linkID, state := range f.staging {
		if state == nil || state.started.IsZero() || now.Sub(state.started) <= factStagingTTL {
			continue
		}
		released = append(released, releasedStaging{linkID: linkID, summary: state.summary})
		f.dropStagingLocked(linkID)
	}
	f.mu.Unlock()
	if len(released) == 0 {
		return
	}
	pumps := make(map[uint64]*controlPump)
	for _, pump := range f.network.controlPumpSnapshot() {
		if pump == nil || pump.link == nil {
			continue
		}
		pumps[pump.link.Metadata().LinkID] = pump
	}
	for _, item := range released {
		pump := pumps[item.linkID]
		if pump == nil {
			continue
		}
		if err := pump.sendFactAck(item.summary.SenderIncarnation, item.summary.SnapshotVersion, 0, topology.AckNeedSummary, 0, 0); err != nil {
			slog.Default().Debug("expired FACT staging notice not queued", "phase", "facts")
		}
	}
}

// pumpSenders is the single outbound FACT worker step. It first sweeps expired
// inbound staging, then rebuilds the shared snapshot at most once per FactStore
// version and advances every registered Link independently.
func (f *factRuntime) pumpSenders(now time.Time) {
	if f == nil || f.network == nil {
		return
	}
	f.sweepExpiredStaging(now)
	snapshot := f.ensureOutbound(now)
	for _, pump := range f.network.controlPumpSnapshot() {
		pump.tickFactSender(snapshot, now)
	}
}

// tickFactSender advances one Link's outbound offer and enqueues at most one
// frame into the existing protected writer queue.
func (p *controlPump) tickFactSender(snapshot *factSnapshot, now time.Time) {
	if p == nil || p.sender == nil {
		return
	}
	plan := p.sender.plan(snapshot, now)
	if !plan.send {
		return
	}
	if plan.retry {
		p.network.facts.senderRetries.Add(1)
	}
	if err := p.sendFactOutbound(plan.action); err != nil {
		// The bounded retry and the next store change are the recovery path; no
		// payload, peer identity or error detail is logged.
		slog.Default().Debug("outbound FACT frame not queued", "phase", "facts")
	}
}

// sendFactOutbound encodes and enqueues one SUMMARY or PAGE through the unique
// protected writer. It never blocks: a full queue is an explicit resource error
// handled by the bounded retry.
func (p *controlPump) sendFactOutbound(out factOutbound) error {
	if p == nil || out.snapshot == nil {
		return ErrLinkDown
	}
	if !out.isPage {
		payload, err := topology.EncodeFactSummary(out.snapshot.summary)
		if err != nil {
			return errors.Join(errFactControlMalformed, err)
		}
		return p.sendControl(link.ControlMessage{Type: 6, Payload: payload})
	}
	if int(out.page) >= len(out.snapshot.pages) {
		return errors.Join(errFactControlMalformed, topology.ErrFactMalformed)
	}
	payload, err := topology.EncodeFactPage(out.snapshot.pages[out.page])
	if err != nil {
		return errors.Join(errFactControlMalformed, err)
	}
	return p.sendControl(link.ControlMessage{Type: 7, Payload: payload})
}

// consumeOutboundFactAck correlates one decoded FACT_ACK with this Link's
// outbound offer. A stale or unsolicited ACK is counted and ignored, never a
// Link failure: an unexpected acknowledgement must not close healthy control.
func (p *controlPump) consumeOutboundFactAck(ack topology.FactAck, now time.Time) error {
	if p == nil || p.network == nil || p.network.facts == nil {
		return nil
	}
	facts := p.network.facts
	if p.sender == nil {
		facts.ignoredAcks.Add(1)
		return nil
	}
	result := p.sender.onAck(ack, p.network.networkContext.WireID(), p.network.runtimeState.Incarnation(), now)
	if !result.correlated {
		facts.ignoredAcks.Add(1)
		slog.Default().Debug("FACT ACK did not correlate with an outbound snapshot",
			"status", uint8(ack.Status), "network_match", ack.NetworkID == p.network.networkContext.WireID())
		return nil
	}
	if result.completed {
		facts.senderCompleted.Add(1)
	}
	if result.rejected {
		facts.senderRejected.Add(1)
	}
	if !result.send {
		return nil
	}
	return p.sendFactOutbound(result.action)
}

// outboundSnapshotIsEmpty reports whether the cached outbound snapshot carries
// no fact. It is a diagnostics helper for status queries.
func (f *factRuntime) outboundSnapshotIsEmpty() bool {
	if f == nil {
		return true
	}
	f.sender.mu.Lock()
	defer f.sender.mu.Unlock()
	return f.sender.outbound == nil || f.sender.outbound.summary.FactCount == 0
}
