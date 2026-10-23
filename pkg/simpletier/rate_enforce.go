package simpletier

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// This file is the enforcement layer of the frozen MESH 3.8 rate controls. It
// owns the effective numeric budget, the unexported test seam that may lower it
// for one test, the per-listener pre-authentication admission accounting and the
// source-key normalization. The limiter primitives live in runtime_rates.go and
// the three production call sites are:
//   - per-peer PACKET:        streamRuntime.deliverPacketFrame / deliverDatagramFrame
//   - per-Link + Network ctrl: controlPump.read / controlPump.write
//   - handshake + per-source: network.rejectUnauthenticatedCarriers
const (
	// rateControlWait bounds how long one control frame waits for a token of the
	// per-Link/Network control budget before its Link is failed closed. At the
	// frozen per-Link ceiling (100 msg/s, burst 200) one token refills within
	// 10 ms, so a short wait absorbs a burst just over the limit while a
	// sustained flood still reaches an explicit teardown instead of a silent
	// drop. It is a policy timeout, never a user setting.
	rateControlWait = 250 * time.Millisecond
	// rateSourceConnectWait bounds how long one accepted raw carrier waits for
	// its per-source new-connection token (frozen 4/s, burst 8) before it is
	// closed before any identity/Noise work. It reuses the existing bounded
	// handshake timeout: a carrier that cannot be paced inside the same window
	// the handshake itself is allowed fails closed.
	rateSourceConnectWait = upstreamDialTimeout
)

// rateLimits is the effective numeric budget of one Network limiter. Production
// always derives it from the frozen MESH 3.8 constants; only the unexported test
// seam below may replace it, and no Config field exposes it.
type rateLimits struct {
	peerPacketPerSecond  float64
	peerPacketBurst      float64
	linkControlPerSecond float64
	linkControlBurst     float64
	networkControlPerSec float64
	networkControlBurst  float64
	sourceConnectPerSec  float64
	sourceConnectBurst   float64
	preauthTotal         uint64
	handshakeConcurrent  int
	controlWait          time.Duration
	sourceConnectWait    time.Duration
}

// defaultRateLimits is the frozen MESH 3.8 budget, lowerable only by an
// implementation, never raisable.
func defaultRateLimits() rateLimits {
	return rateLimits{
		peerPacketPerSecond:  ratePeerPacketPerSecond,
		peerPacketBurst:      ratePeerPacketBurst,
		linkControlPerSecond: rateLinkControlPerSecond,
		linkControlBurst:     rateLinkControlBurst,
		networkControlPerSec: rateNetworkControlPerSec,
		networkControlBurst:  rateNetworkControlBurst,
		sourceConnectPerSec:  rateSourceConnectPerSec,
		sourceConnectBurst:   rateSourceConnectBurst,
		preauthTotal:         rateListenerPreauthTotal,
		handshakeConcurrent:  rateHandshakeConcurrent,
		controlWait:          rateControlWait,
		sourceConnectWait:    rateSourceConnectWait,
	}
}

// rateLimitSeam is the only way a test may replace the frozen budget. It is a
// package-level seam, not a Config option: production never sets it, and the
// mutex is held for the whole lifetime of one override so two tests can never
// interleave a lowered budget.
var rateLimitSeam struct {
	mu      sync.Mutex
	current atomic.Pointer[rateLimits]
}

// effectiveRateLimits resolves the budget of a newly built limiter. A nil seam
// is exactly the frozen production defaults.
func effectiveRateLimits() rateLimits {
	if override := rateLimitSeam.current.Load(); override != nil {
		return *override
	}
	return defaultRateLimits()
}

// unlimitedRateLimits is the budget of a Network with RuntimeOptions.RateLimit
// disabled: every per-second rate and burst is effectively infinite, so no token
// bucket can refuse and the handshake semaphore never blocks.
//
// It is not "zero limits": a zero rate would refuse every request. The point is to
// remove the guard, not to invert it. Resource caps that protect against memory
// exhaustion (queue depths, buffer ceilings, fact-store size) are untouched — those
// are correctness bounds, not flood guards.
func unlimitedRateLimits() rateLimits {
	const unbounded = 1 << 40
	return rateLimits{
		peerPacketPerSecond:  unbounded,
		peerPacketBurst:      unbounded,
		linkControlPerSecond: unbounded,
		linkControlBurst:     unbounded,
		networkControlPerSec: unbounded,
		networkControlBurst:  unbounded,
		sourceConnectPerSec:  unbounded,
		sourceConnectBurst:   unbounded,
		preauthTotal:         unbounded,
		handshakeConcurrent:  unboundedInt,
		controlWait:          0,
		sourceConnectWait:    0,
	}
}

// unboundedInt is the semaphore capacity used when the handshake limit is disabled.
// It is a large finite number rather than a zero (which would block forever); the
// channel still bounds memory at a size no real deployment reaches.
const unboundedInt = 1 << 20

// sourceInvalidKey is the single shared bucket of carriers whose remote address
// cannot be normalized. Every such carrier is charged to this one bucket, so an
// unparsable or non-IPv4 source can never refill a private budget by rotating
// addresses: it fails closed into the same debt.
const sourceInvalidKey = "invalid-source"

// rateSourceKey normalizes one carrier remote address to the frozen per-source
// key: the IPv4 host alone, never the ephemeral port, because an attacker
// rotates source ports. A non-IPv4, hostless or unparsable address maps to the
// shared invalid-source bucket. The value is metadata only and is never an
// authentication membership test.
func rateSourceKey(addr net.Addr) string {
	if addr == nil {
		return sourceInvalidKey
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return sourceInvalidKey
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return sourceInvalidKey
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	if !ip.Is4() {
		// The frozen overlay is IPv4-only: a non-IPv4 carrier cannot be given a
		// private budget.
		return sourceInvalidKey
	}
	return ip.String()
}

// tryControl consumes one token from the per-Link and the Network-wide control
// budget as a single all-or-none decision, so a refusal never burns the other
// budget. It returns the time until the next token when it refuses; a zero wait
// with ok==false means no bucket can ever be created (the bounded link map is
// full of debt buckets), which the caller must treat as fail closed.
func (r *networkRates) tryControl(linkID, epoch uint64) (bool, time.Duration) {
	if r == nil {
		return true, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	link := rateBucketLocked(r, r.links, [2]uint64{linkID, epoch}, ratePeerMapLimit, r.limits.linkControlPerSecond, r.limits.linkControlBurst)
	if r.networkControl == nil || link == nil {
		return false, 0
	}
	now := r.now()
	networkWait := r.networkControl.refillLocked(now)
	linkWait := link.refillLocked(now)
	if wait := maxRateWait(networkWait, linkWait); wait > 0 {
		return false, wait
	}
	r.networkControl.takeLocked()
	link.takeLocked()
	return true, 0
}

// returnSourceConnect refunds one per-source connect token after a connection
// proves itself. Admission charges the token before the handshake because that is
// the only point where a flood can be stopped cheaply, but a peer that completes
// authentication is not a flood: refunding keeps legitimate bursts from being
// throttled by their own success. Only repeated failures keep a source in debt.
func (r *networkRates) returnSourceConnect(source string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	bucket, ok := r.sources[source]
	if !ok || bucket == nil {
		return
	}
	bucket.refundLocked()
}

// trySourceConnect consumes one per-source connect token when it is available. It
// never counts a refusal, because the caller owns the wait policy. A zero wait
// with ok==false means the bounded source map is full of debt buckets, which is
// fail closed.
func (r *networkRates) trySourceConnect(source string) (bool, time.Duration) {
	if r == nil {
		return true, 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	bucket := rateBucketLocked(r, r.sources, source, rateSourceMapLimit, r.limits.sourceConnectPerSec, r.limits.sourceConnectBurst)
	if bucket == nil {
		return false, 0
	}
	if wait := bucket.refillLocked(r.now()); wait > 0 {
		return false, wait
	}
	bucket.takeLocked()
	return true, 0
}

// maxRateWait returns the longer of two token waits.
func maxRateWait(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// awaitControl is the single Network-level control-budget admission used by every
// control caller: the LINK_CTRL/ROUTE_CTRL reader and writer of a Link, and the
// CONTROL_RPC frame of the circuit plane. It charges exactly one token of the
// frozen per-Link and Network-wide control budget. It returns nil when the frame
// is admitted; on a bounded-wait expiry it counts one controlWaitTimeout and
// returns ErrResource so the caller can fail the offending Link/session closed
// instead of dropping the control message silently.
//
// done is the exact physical Link teardown signal of the pinned Link (the caller
// passes the pinned pump's own Link), so the wait is interrupted by the Link it
// would otherwise charge.
func (n *network) awaitControl(ctx context.Context, done <-chan struct{}, linkID, epoch uint64) error {
	if n == nil || n.rates == nil {
		return nil
	}
	if !n.rates.admitControlWait(ctx, done, linkID, epoch) {
		n.rates.noteControlWaitTimeout()
		return fmt.Errorf("%w: control budget exhausted for LinkID %d epoch %d", ErrResource, linkID, epoch)
	}
	return nil
}

// awaitIngressControl charges one inbound control frame of a Link that is not
// addressed through the pump API (the CONTROL_RPC messages the circuit plane
// decodes after the E2E open). The caller must pass the exact pinned Link's
// LinkID/LinkEpoch; the charge is the same per-Link/Network control budget as an
// inbound LINK_CTRL/ROUTE_CTRL frame. A nil error means admitted; ErrResource
// means the bounded budget expired and the caller must fail the offending
// Link/session closed.
func (n *network) awaitIngressControl(ctx context.Context, linkID, epoch uint64) error {
	return n.awaitControl(ctx, n.controlLinkDone(linkID), linkID, epoch)
}

// awaitEgressControl is the outbound twin of awaitIngressControl, for a control
// frame a caller enqueues itself. It charges the same frozen per-Link and
// Network-wide control budget: the frozen datum counts one control budget per
// authenticated Link, so ingress and egress control frames share it rather than
// each getting a private doubling of the ceiling.
func (n *network) awaitEgressControl(ctx context.Context, linkID, epoch uint64) error {
	return n.awaitControl(ctx, n.controlLinkDone(linkID), linkID, epoch)
}

// controlLinkDone returns the teardown signal of the registered pump of one
// LinkID, or nil when no pump is registered for it (the caller then waits only on
// its context and the bounded timeout).
func (n *network) controlLinkDone(linkID uint64) <-chan struct{} {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if pump := n.controlPumps[linkID]; pump != nil && pump.link != nil {
		return pump.link.Done()
	}
	return nil
}

// admitControlWait is the bounded control admission of one authenticated control
// frame: it waits up to the frozen bounded policy timeout for the per-Link and
// Network budget to admit the frame, and refuses (fail closed) when the budget
// never does. It blocks the calling reader/writer only, never a queue producer,
// and it is interrupted by context cancellation, Link teardown or the timeout.
func (r *networkRates) admitControlWait(ctx context.Context, done <-chan struct{}, linkID, epoch uint64) bool {
	if r == nil {
		return true
	}
	if ctx == nil {
		ctx = context.Background()
	}
	budget := r.limits.controlWait
	if budget <= 0 {
		if ok, _ := r.tryControl(linkID, epoch); ok {
			return true
		}
		r.controlRejected.Add(1)
		return false
	}
	deadline := time.NewTimer(budget)
	defer deadline.Stop()
	for {
		ok, wait := r.tryControl(linkID, epoch)
		if ok {
			return true
		}
		if wait <= 0 {
			// No bucket can be created: the bounded map holds only debt. Fail
			// closed now instead of waiting for a token that cannot appear.
			r.controlRejected.Add(1)
			return false
		}
		sleep := time.NewTimer(wait)
		select {
		case <-sleep.C:
		case <-ctx.Done():
			sleep.Stop()
			r.controlRejected.Add(1)
			return false
		case <-done:
			sleep.Stop()
			r.controlRejected.Add(1)
			return false
		case <-deadline.C:
			sleep.Stop()
			r.controlRejected.Add(1)
			return false
		}
	}
}

// listenerAdmission is the pre-authentication admission accounting of exactly one
// registered carrier listener. It keeps the frozen per-listener 128 active
// pre-auth ceiling as its own counter (never the 16-way handshake concurrency
// gate, and never conflated with it) and paces every accepted carrier against the
// frozen per-source new-connection budget before any identity/Noise work.
type listenerAdmission struct {
	rates  *networkRates
	active atomic.Uint64
}

// newListenerAdmission creates the admission accounting of one listener. A nil
// limiter (a directly built Network value) stays permissive.
func (n *network) newListenerAdmission() *listenerAdmission {
	if n == nil {
		return &listenerAdmission{}
	}
	return &listenerAdmission{rates: n.rates}
}

// begin accounts one accepted carrier against the frozen per-listener pre-auth
// ceiling. It is a real per-listener gate and returns false, counted, before the
// caller takes the handshake concurrency slot, so an over-ceiling carrier is
// closed before identity/Noise. The reservation is a compare-and-swap loop, so
// concurrent callers can never overshoot the ceiling: a lost race retries
// instead of admitting on a stale read.
func (a *listenerAdmission) begin() bool {
	if a == nil || a.rates == nil {
		return true
	}
	limit := a.rates.limits.preauthTotal
	for {
		current := a.active.Load()
		if current >= limit {
			a.rates.notePreauthRejected()
			return false
		}
		if a.active.CompareAndSwap(current, current+1) {
			a.rates.notePreauthAdmitted()
			return true
		}
	}
}

// release returns one pre-auth slot with a saturating compare-and-swap, so a
// spurious extra release can never underflow the counter (and with it the shared
// aggregate). The caller reserves and releases exactly once per carrier.
func (a *listenerAdmission) release() {
	if a == nil || a.rates == nil {
		return
	}
	for {
		current := a.active.Load()
		if current == 0 {
			// No matching reservation: saturate at zero and never touch the
			// separate aggregate counter.
			return
		}
		if a.active.CompareAndSwap(current, current-1) {
			a.rates.notePreauthReleased()
			return
		}
	}
}

// awaitSource is the frozen per-source new-connection budget of one accepted raw
// carrier, charged before any identity/Noise work. The wait is bounded by the
// frozen policy timeout: a source that cannot be paced inside it is refused here,
// counted, and its carrier is closed before the handshake starts.
func (a *listenerAdmission) refundSource(source string) {
	if a == nil || a.rates == nil {
		return
	}
	a.rates.returnSourceConnect(source)
}

func (a *listenerAdmission) awaitSource(ctx context.Context, source string) bool {
	if a == nil || a.rates == nil {
		return true
	}
	if ctx == nil {
		ctx = context.Background()
	}
	budget := a.rates.limits.sourceConnectWait
	if budget <= 0 {
		if ok, _ := a.rates.trySourceConnect(source); ok {
			return true
		}
		a.refuseSource()
		return false
	}
	deadline := time.NewTimer(budget)
	defer deadline.Stop()
	for {
		ok, wait := a.rates.trySourceConnect(source)
		if ok {
			return true
		}
		if wait <= 0 {
			a.refuseSource()
			return false
		}
		sleep := time.NewTimer(wait)
		select {
		case <-sleep.C:
		case <-ctx.Done():
			sleep.Stop()
			a.refuseSource()
			return false
		case <-deadline.C:
			sleep.Stop()
			a.refuseSource()
			return false
		}
	}
}

// refuseSource counts one carrier refused by the per-source budget.
func (a *listenerAdmission) refuseSource() {
	if a == nil || a.rates == nil {
		return
	}
	a.rates.sourceRejected.Add(1)
}
