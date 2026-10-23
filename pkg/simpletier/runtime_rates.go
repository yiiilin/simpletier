package simpletier

import (
	"sync"
	"sync/atomic"
	"time"
)

// Frozen MESH 3.8 runtime rate limits. These are internal defaults: no SDK
// configuration field is required or added, and a caller cannot raise them.
// Every limit is enforced by one shared Network-wide limiter; the counters are
// never a separately cached snapshot.
const (
	ratePeerPacketPerSecond  = 10_000
	ratePeerPacketBurst      = 2_000
	rateLinkControlPerSecond = 100
	rateLinkControlBurst     = 200
	rateNetworkControlPerSec = 10_000
	rateNetworkControlBurst  = 20_000
	rateListenerPreauthTotal = 128
	rateHandshakeConcurrent  = 16
	// Connection admission is a flood guard, not a throughput knob: it exists so a
	// peer cannot open unbounded Links per second. The burst is what a single
	// client opening many streams at once legitimately needs, so it has to cover a
	// realistic concurrent workload rather than the handful a control-plane client
	// opens. At burst 8 a 16-stream client waited 2s and a 128-stream client 30s
	// just to establish, which dominated any measurement that opened streams
	// before timing transfer.
	rateSourceConnectPerSec   = 64
	rateSourceConnectBurst    = 256
	ratePeerMapLimit          = 4096
	rateSourceMapLimit        = 1024
	rateBucketPruneInterval   = 30 * time.Second
	networkRatesDefaultBucket = 1
	// rateMetadataEstimateBytes is the single inclusive upper-bound estimate of
	// the limiter's bounded metadata: ratePeerMapLimit + rateSourceMapLimit
	// bucket entries, each a bucket struct plus a map node and (for a source) a
	// short string key, plus the handshake semaphore and its counters. Derivation:
	// (4096 + 4096 links + 1024 sources) entries * ~64 B per bucket/node < 640 KiB,
	// plus fixed counters and the 16-slot semaphore, rounded up to 1 MiB. The map
	// capacities are internal bounded caches, never a user-visible admission slot
	// count, and this figure is an estimate, not a kernel or whole-process
	// measurement.
	rateMetadataEstimateBytes uint64 = 1 << 20
)

// tokenBucket is the minimal standard token bucket: a capacity, a refill rate
// and the last refill instant. It has no dependency and takes its clock by
// injection so tests are deterministic while production uses time.Now.
type tokenBucket struct {
	mu        sync.Mutex
	now       func() time.Time
	capacity  float64
	perSecond float64
	tokens    float64
	last      time.Time
}

func newTokenBucket(now func() time.Time, perSecond, burst float64) *tokenBucket {
	if now == nil {
		now = time.Now
	}
	if burst < 1 {
		burst = 1
	}
	return &tokenBucket{now: now, capacity: burst, perSecond: perSecond, tokens: burst, last: now()}
}

// allow consumes one token if the bucket is not empty.
func (b *tokenBucket) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * b.perSecond
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// refillLocked advances the bucket to now and returns the time until one token
// becomes available; zero means a token is available right now. The caller holds
// b.mu, so a caller that must consume several buckets as one all-or-none decision
// (the per-Link and Network control budgets) can probe and then take without a
// second refill. It never changes the configured rate, so a debt bucket cannot
// reset itself.
func (b *tokenBucket) refillLocked(now time.Time) time.Duration {
	if b == nil {
		return 0
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * b.perSecond
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens >= 1 {
		return 0
	}
	if b.perSecond <= 0 {
		// A zero refill rate never admits another frame: report an unbounded
		// wait instead of a zero (which the caller reads as "available now").
		return time.Duration(1<<62 - 1)
	}
	return time.Duration((1 - b.tokens) / b.perSecond * float64(time.Second))
}

// takeLocked consumes one token the caller already proved available.
func (b *tokenBucket) takeLocked() {
	if b != nil {
		b.tokens--
	}
}

// refundLocked returns one previously taken token, never above capacity. It is
// how a connection that completed authentication stops counting against the
// per-source flood budget: the budget exists to slow down failures, not to
// throttle a peer that is legitimately opening many links.
func (b *tokenBucket) refundLocked() {
	if b == nil {
		return
	}
	b.tokens++
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
}

// idle reports whether the bucket is full again, so a bounded map may evict it.
func (b *tokenBucket) idle() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if elapsed := now.Sub(b.last); elapsed > 0 {
		tokens := b.tokens + elapsed.Seconds()*b.perSecond
		return tokens >= b.capacity
	}
	return b.tokens >= b.capacity
}

// networkRates is the one bounded rate limiter of a Network. It carries the
// per-peer PACKET, per-Link LINK_CTRL, Network-wide control, handshake
// admission and per-source connect limits. Every map is bounded and every
// counter is a plain atomic: there is no second, cached aggregate.
type networkRates struct {
	now func() time.Time

	mu       sync.Mutex
	peers    map[[16]byte]*tokenBucket
	links    map[[2]uint64]*tokenBucket
	sources  map[string]*tokenBucket
	prunedAt time.Time

	networkControl *tokenBucket
	handshakes     chan struct{}
	// limits is the effective numeric budget resolved once at construction. In
	// production it is exactly the frozen MESH 3.8 constants; only the unexported
	// test seam may replace it, and there is no Config field that reads it.
	limits rateLimits

	handshakePending atomic.Uint64
	handshakeTotal   atomic.Uint64
	handshakeReject  atomic.Uint64
	preauthActive    atomic.Uint64
	preauthTotal     atomic.Uint64
	preauthRejected  atomic.Uint64
	packetRejected   atomic.Uint64
	controlRejected  atomic.Uint64
	// controlWaitTimeout counts Links that were torn down because the frozen
	// control budget did not admit a frame inside the bounded wait, and
	// controlRecoveryExempt counts in-place key-update frames that used the
	// limited recovery allowance of a paused writer. Neither is a silent drop.
	controlWaitTimeout    atomic.Uint64
	controlRecoveryExempt atomic.Uint64
	sourceRejected        atomic.Uint64
	// frameLocalRejected is the bounded aggregate counter of pre-E2E-auth frames
	// a local ingress classifier refused and dropped (the frozen attribution rule
	// of wire-protocol.md 3.3 item 5: TamperDetected/FrameMalformed/
	// ReplaySuspected/EpochMismatch are dropped AND counted before end-to-end
	// authentication, isolated per ingress Link). It is one atomic, never a
	// per-Link map, so recording every classified drop cannot grow any state.
	frameLocalRejected atomic.Uint64
}

// newNetworkRates builds the limiter of one Network.
func newNetworkRates() *networkRates {
	return newNetworkRatesWithClock(time.Now)
}

// newNetworkRatesFor builds the limiter described by options, honoring an explicit
// RuntimeOptions.RateLimit.
//
// A test that installed a budget through the seam always gets a guarded limiter,
// whatever the option says: the seam exists precisely to exercise the guard, and
// silently ignoring an installed budget would turn every rate test into a no-op.
func newNetworkRatesFor(enabled bool) *networkRates {
	rates := newNetworkRatesWithClock(time.Now)
	if rateLimitSeam.current.Load() != nil {
		enabled = true
	}
	if !enabled {
		rates.limits = unlimitedRateLimits()
		// Rebuild the buckets and semaphore from the replaced budget: they were
		// sized by effectiveRateLimits above.
		limits := rates.limits
		concurrent := limits.handshakeConcurrent
		if concurrent < 1 {
			concurrent = 1
		}
		rates.networkControl = newTokenBucket(rates.now, limits.networkControlPerSec, limits.networkControlBurst)
		rates.handshakes = make(chan struct{}, concurrent)
	}
	return rates
}

// newNetworkRatesWithClock is the test seam: production always uses time.Now.
func newNetworkRatesWithClock(now func() time.Time) *networkRates {
	if now == nil {
		now = time.Now
	}
	limits := effectiveRateLimits()
	concurrent := limits.handshakeConcurrent
	if concurrent < 1 {
		concurrent = 1
	}
	return &networkRates{
		now:            now,
		limits:         limits,
		peers:          make(map[[16]byte]*tokenBucket),
		links:          make(map[[2]uint64]*tokenBucket),
		sources:        make(map[string]*tokenBucket),
		networkControl: newTokenBucket(now, limits.networkControlPerSec, limits.networkControlBurst),
		handshakes:     make(chan struct{}, concurrent),
		prunedAt:       now(),
	}
}

// rateBucket returns the bucket of one key, creating it while the map has room.
// A full map evicts idle buckets first; if none is idle the request is refused
// (fail closed) instead of growing without bound.
func rateBucket[K comparable](r *networkRates, m map[K]*tokenBucket, key K, limit int, perSecond, burst float64) *tokenBucket {
	r.mu.Lock()
	defer r.mu.Unlock()
	return rateBucketLocked(r, m, key, limit, perSecond, burst)
}

// rateBucketLocked is the same lookup with r.mu already held, so a caller may
// decide the per-Link and the Network-wide control budgets as one all-or-none
// step. A full map is still refused (fail closed) rather than grown.
func rateBucketLocked[K comparable](r *networkRates, m map[K]*tokenBucket, key K, limit int, perSecond, burst float64) *tokenBucket {
	if r.now().Sub(r.prunedAt) >= rateBucketPruneInterval {
		r.pruneLocked()
	}
	if bucket, ok := m[key]; ok {
		return bucket
	}
	if len(m) >= limit {
		for candidate, bucket := range m {
			if bucket.idle() {
				delete(m, candidate)
			}
		}
	}
	if len(m) >= limit {
		return nil
	}
	bucket := newTokenBucket(r.now, perSecond, burst)
	m[key] = bucket
	return bucket
}

// pruneLocked drops idle entries from every bounded map.
func (r *networkRates) pruneLocked() {
	r.prunedAt = r.now()
	for key, bucket := range r.peers {
		if bucket.idle() {
			delete(r.peers, key)
		}
	}
	for key, bucket := range r.links {
		if bucket.idle() {
			delete(r.links, key)
		}
	}
	for key, bucket := range r.sources {
		if bucket.idle() {
			delete(r.sources, key)
		}
	}
}

// allowPacket enforces the per-peer PACKET rate. A nil peer key uses the shared
// default bucket, so an unauthenticated caller can never bypass the limit.
func (r *networkRates) allowPacket(peer [16]byte) bool {
	if r == nil {
		return true
	}
	bucket := rateBucket(r, r.peers, peer, ratePeerMapLimit, r.limits.peerPacketPerSecond, r.limits.peerPacketBurst)
	if bucket != nil && bucket.allow() {
		return true
	}
	r.packetRejected.Add(1)
	return false
}

// allowLinkControl enforces the per-Link LINK_CTRL message rate. It counts
// LINK_CTRL messages including in-place key-update control and FACT frames; it
// never charges inner session RPC credit. It shares the limiter-mutex protocol
// of tryControl, so the same bucket is never touched under two lock protocols.
func (r *networkRates) allowLinkControl(linkID, epoch uint64) bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	bucket := rateBucketLocked(r, r.links, [2]uint64{linkID, epoch}, ratePeerMapLimit, r.limits.linkControlPerSecond, r.limits.linkControlBurst)
	allowed := false
	if bucket != nil && bucket.refillLocked(r.now()) <= 0 {
		bucket.takeLocked()
		allowed = true
	}
	r.mu.Unlock()
	if !allowed {
		r.controlRejected.Add(1)
	}
	return allowed
}

// allowNetworkControl enforces the single Network-wide control rate. It shares
// the limiter-mutex protocol of tryControl.
func (r *networkRates) allowNetworkControl() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	allowed := false
	if r.networkControl != nil && r.networkControl.refillLocked(r.now()) <= 0 {
		r.networkControl.takeLocked()
		allowed = true
	}
	r.mu.Unlock()
	if !allowed {
		r.controlRejected.Add(1)
	}
	return allowed
}

// admitHandshake is the Network-wide pre-auth handshake concurrency gate: at
// most rateHandshakeConcurrent (frozen 16) accepted carriers may be inside
// identity/Noise work at once. It is a non-blocking, no-queue gate, exactly as
// before: a refusal happens before any handshake side effect. The frozen
// per-listener ceiling of rateListenerPreauthTotal (128) active pre-auth
// connections is a separate counter in listenerAdmission and is deliberately NOT
// conflated with this 16-way gate. The returned release function is idempotent
// and must only be called after a true result.
func (r *networkRates) admitHandshake() (func(), bool) {
	if r == nil {
		return func() {}, true
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			<-r.handshakes
			r.handshakePending.Add(^uint64(0))
		})
	}
	select {
	case r.handshakes <- struct{}{}:
		r.handshakePending.Add(1)
		r.handshakeTotal.Add(1)
		return release, true
	default:
		r.handshakeReject.Add(1)
		return release, false
	}
}

// allowSourceConnect enforces the per-source connect rate over a bounded source
// map. source is opaque canonical metadata supplied by the host adapter; it is
// never used as an authentication membership test.
func (r *networkRates) allowSourceConnect(source string) bool {
	if r == nil {
		return true
	}
	bucket := rateBucket(r, r.sources, source, rateSourceMapLimit, r.limits.sourceConnectPerSec, r.limits.sourceConnectBurst)
	if bucket != nil && bucket.allow() {
		return true
	}
	r.sourceRejected.Add(1)
	return false
}

// networkRateStats is the observable aggregate of the limiter. It is an internal
// snapshot for the Network's own accounting and tests; this slice adds no public
// telemetry surface.
type networkRateStats struct {
	HandshakePending      uint64
	HandshakeTotal        uint64
	HandshakeReject       uint64
	PreauthActive         uint64
	PreauthTotal          uint64
	PreauthReject         uint64
	PacketRejected        uint64
	ControlRejected       uint64
	ControlWaitTimeout    uint64
	ControlRecoveryExempt uint64
	SourceRejected        uint64
	// FrameLocalRejected counts ingress frames a local classifier dropped before
	// end-to-end authentication completed. It is an aggregate, so it never
	// reports which Link or Session produced the violation.
	FrameLocalRejected uint64
	PeerBuckets        int64
	SourceBuckets      int64
}

// stats snapshots the aggregate counters directly, never a cached copy.
func (r *networkRates) stats() networkRateStats {
	if r == nil {
		return networkRateStats{}
	}
	r.mu.Lock()
	peers, sources := int64(len(r.peers)), int64(len(r.sources))
	r.mu.Unlock()
	return networkRateStats{
		HandshakePending:      r.handshakePending.Load(),
		HandshakeTotal:        r.handshakeTotal.Load(),
		HandshakeReject:       r.handshakeReject.Load(),
		PreauthActive:         r.preauthActive.Load(),
		PreauthTotal:          r.preauthTotal.Load(),
		PreauthReject:         r.preauthRejected.Load(),
		PacketRejected:        r.packetRejected.Load(),
		ControlRejected:       r.controlRejected.Load(),
		ControlWaitTimeout:    r.controlWaitTimeout.Load(),
		ControlRecoveryExempt: r.controlRecoveryExempt.Load(),
		SourceRejected:        r.sourceRejected.Load(),
		FrameLocalRejected:    r.frameLocalRejected.Load(),
		PeerBuckets:           peers,
		SourceBuckets:         sources,
	}
}

// notePreauthAdmitted/Released/Rejected are the per-listener pre-auth accounting
// hooks of the frozen 128-connection ceiling. listenerAdmission owns the
// per-listener counter that is actually compared; these mirror the same events
// into the shared aggregate so the limiter has one observable snapshot.
func (r *networkRates) notePreauthAdmitted() {
	if r == nil {
		return
	}
	r.preauthActive.Add(1)
	r.preauthTotal.Add(1)
}

func (r *networkRates) notePreauthReleased() {
	if r == nil {
		return
	}
	r.preauthActive.Add(^uint64(0))
}

func (r *networkRates) notePreauthRejected() {
	if r == nil {
		return
	}
	r.preauthRejected.Add(1)
}

// noteControlWaitTimeout records one Link torn down because the bounded control
// budget never admitted a frame, and noteControlRecoveryExempt records one
// in-place key-update frame that used the paused-writer recovery allowance.
func (r *networkRates) noteControlWaitTimeout() {
	if r == nil {
		return
	}
	r.controlWaitTimeout.Add(1)
}

func (r *networkRates) noteControlRecoveryExempt() {
	if r == nil {
		return
	}
	r.controlRecoveryExempt.Add(1)
}

// recordFrameLocalReject counts exactly one pre-E2E-auth frame that a local
// ingress classifier refused and dropped. The frozen attribution rule requires
// drop AND count before end-to-end authentication for TamperDetected,
// FrameMalformed, ReplaySuspected and EpochMismatch, and forbids closing a
// Session from a forgeable SessionID: this hook is the count half, while the
// caller keeps the drop local to the ingress Link. It is a bounded aggregate
// (one atomic, no per-Link map) and is nil-safe, so an ingress classifier may
// call it once per classified frame without adding state or a public setting.
func (r *networkRates) recordFrameLocalReject() {
	if r == nil {
		return
	}
	r.frameLocalRejected.Add(1)
}
