package simpletier

import (
	"sync"
	"testing"
	"time"
)

// rateTestClock is a manually advanced clock, so every rate assertion is
// deterministic and owns no real-time dependency.
type rateTestClock struct{ now time.Time }

func (c *rateTestClock) Now() time.Time          { return c.now }
func (c *rateTestClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newRateTestLimiter() (*networkRates, *rateTestClock) {
	clock := &rateTestClock{now: time.Unix(1_700_000_000, 0)}
	return newNetworkRatesWithClock(clock.Now), clock
}

// TestRatesPeerPacketBurstFromFrozenDefaults proves the per-peer PACKET limit is
// the frozen 10kpps / burst 2000 bucket and refills at the configured rate.
func TestRatesPeerPacketBurstFromFrozenDefaults(t *testing.T) {
	rates, clock := newRateTestLimiter()
	peer := [16]byte{1}
	for i := 0; i < ratePeerPacketBurst; i++ {
		if !rates.allowPacket(peer) {
			t.Fatalf("packet %d refused inside the burst %d", i, ratePeerPacketBurst)
		}
	}
	if rates.allowPacket(peer) {
		t.Fatal("burst+1 packet admitted")
	}
	// One second of refill restores exactly the per-second rate, capped by burst.
	clock.Advance(time.Second)
	allowed := 0
	for rates.allowPacket(peer) {
		allowed++
		if allowed > ratePeerPacketBurst {
			t.Fatal("refill admitted more than the bucket capacity")
		}
	}
	if allowed != ratePeerPacketBurst {
		t.Fatalf("after one second refill admitted %d; want %d", allowed, ratePeerPacketBurst)
	}
}

// TestRatesLinkControlAndNetworkControlAreSeparateBuckets proves the per-Link
// LINK_CTRL bucket (100/s burst 200) and the Network-wide control bucket
// (10k/s burst 20k) are independent, and that a per-Link refusal does not spend
// another Link's tokens.
func TestRatesLinkControlAndNetworkControlAreSeparateBuckets(t *testing.T) {
	rates, clock := newRateTestLimiter()
	for i := 0; i < rateLinkControlBurst; i++ {
		if !rates.allowLinkControl(1, 1) {
			t.Fatalf("link control %d refused inside burst %d", i, rateLinkControlBurst)
		}
	}
	if rates.allowLinkControl(1, 1) {
		t.Fatal("link control burst+1 admitted on the same Link")
	}
	if !rates.allowLinkControl(2, 1) {
		t.Fatal("a saturated Link bucket refused another Link instance")
	}
	if !rates.allowNetworkControl() {
		t.Fatal("the Network control bucket was drained by a per-Link refusal")
	}
	clock.Advance(time.Second)
	if !rates.allowLinkControl(1, 1) {
		t.Fatal("link control did not refill after one second")
	}
	if got := rates.stats().ControlRejected; got != 1 {
		t.Fatalf("ControlRejected = %d; want 1", got)
	}
}

// TestRatesHandshakeAdmissionBounds proves the concurrent handshake semaphore is
// rateHandshakeConcurrent and that release is idempotent, so a double release can
// never over-admit.
func TestRatesHandshakeAdmissionBounds(t *testing.T) {
	rates, _ := newRateTestLimiter()
	releases := make([]func(), 0, rateHandshakeConcurrent)
	for i := 0; i < rateHandshakeConcurrent; i++ {
		release, ok := rates.admitHandshake()
		if !ok {
			t.Fatalf("handshake %d refused inside the concurrent bound %d", i, rateHandshakeConcurrent)
		}
		releases = append(releases, release)
	}
	if _, ok := rates.admitHandshake(); ok {
		t.Fatal("handshake admitted past the concurrent bound")
	}
	releases[0]()
	releases[0]() // idempotent: must not free a second slot
	if _, ok := rates.admitHandshake(); !ok {
		t.Fatal("a released handshake slot was not reusable")
	}
	if _, ok := rates.admitHandshake(); ok {
		t.Fatal("a double release over-admitted a handshake slot")
	}
	stats := rates.stats()
	if stats.HandshakePending != rateHandshakeConcurrent || stats.HandshakeReject != 2 {
		t.Fatalf("handshake stats = %+v; want pending=%d reject=2", stats, rateHandshakeConcurrent)
	}
}

// TestRatesSourceConnectBoundedMap proves the per-source connect limiter uses the
// frozen 4/s burst 8 bucket, that distinct sources are independent, and that
// pruning never reclaims a bucket that still owes tokens: a debt bucket is
// retained (so an adversarial source cannot reset its burst by overflowing the
// map), while an idle/full bucket is reclaimed.
func TestRatesSourceConnectBoundedMap(t *testing.T) {
	rates, clock := newRateTestLimiter()
	for i := 0; i < rateSourceConnectBurst; i++ {
		if !rates.allowSourceConnect("source-a") {
			t.Fatalf("source-a connect %d refused inside burst %d", i, rateSourceConnectBurst)
		}
	}
	if rates.allowSourceConnect("source-a") {
		t.Fatal("source-a burst+1 admitted")
	}
	if !rates.allowSourceConnect("source-b") {
		t.Fatal("source-b was charged for source-a's usage")
	}
	// One second later source-a still owes tokens (only 4 of its 8-burst debt
	// refilled) but source-b is idle/full.
	clock.Advance(time.Second)
	rates.mu.Lock()
	rates.pruneLocked()
	entries := len(rates.sources)
	rates.mu.Unlock()
	if entries != 1 {
		t.Fatalf("prune left %d source entries; want 1 (the debt bucket only)", entries)
	}
	if _, ok := rates.sources["source-a"]; !ok {
		t.Fatal("prune reclaimed a source bucket that still owed tokens")
	}
	if _, ok := rates.sources["source-b"]; ok {
		t.Fatal("prune kept an idle/full source bucket")
	}
	// The retained debt bucket refills at exactly the configured rate: being
	// pruned must not have reset it to a fresh burst of 8.
	refilled := 0
	for rates.allowSourceConnect("source-a") {
		refilled++
		if refilled > rateSourceConnectBurst {
			t.Fatal("source-a was reset to a fresh burst instead of its debt refill")
		}
	}
	if refilled != rateSourceConnectPerSec {
		t.Fatalf("source-a refilled %d tokens; want %d", refilled, rateSourceConnectPerSec)
	}
	// Enough refill to restore the full burst, computed from the configured rate
	// so this does not pin the numbers: a bucket is reclaimable only once it is
	// back to a full burst.
	clock.Advance(time.Duration(float64(rateSourceConnectBurst)/float64(rateSourceConnectPerSec)*float64(time.Second)) + time.Second)
	rates.mu.Lock()
	rates.pruneLocked()
	entries = len(rates.sources)
	rates.mu.Unlock()
	if entries != 0 {
		t.Fatalf("prune left %d full source entries; want 0", entries)
	}
	// Two refusals were observed: the initial burst+1 and the post-refill
	// burst+1.
	if got := rates.stats().SourceRejected; got != 2 {
		t.Fatalf("SourceRejected = %d; want 2", got)
	}
}

// TestRatesNilLimiterIsPermissive pins that an absent limiter (a directly built
// Network value) never blocks, so the limiter stays an additive gate.
func TestRatesNilLimiterIsPermissive(t *testing.T) {
	var rates *networkRates
	if !rates.allowPacket([16]byte{}) || !rates.allowLinkControl(1, 1) || !rates.allowNetworkControl() {
		t.Fatal("a nil limiter refused traffic")
	}
	if !rates.allowSourceConnect("s") {
		t.Fatal("a nil limiter refused a source connect")
	}
	release, ok := rates.admitHandshake()
	if !ok {
		t.Fatal("a nil limiter refused a handshake")
	}
	release()
}

// TestRatesFrameLocalRejectIsBoundedAggregate pins the count half of the frozen
// pre-E2E-auth attribution rule: every classified drop is counted immediately in
// the aggregate snapshot, a nil limiter is permissive (the counter is additive
// observation, never a gate), and recording many drops grows no bounded map.
func TestRatesFrameLocalRejectIsBoundedAggregate(t *testing.T) {
	rates, _ := newRateTestLimiter()
	if got := rates.stats().FrameLocalRejected; got != 0 {
		t.Fatalf("FrameLocalRejected = %d before any record; want 0", got)
	}
	// The hook is observation only: it must never change any admission decision.
	before := rates.stats()
	rates.recordFrameLocalReject()
	if got := rates.stats().FrameLocalRejected; got != 1 {
		t.Fatalf("FrameLocalRejected = %d after one record; want 1 (direct snapshot, not cached)", got)
	}
	after := rates.stats()
	if after.PacketRejected != before.PacketRejected ||
		after.ControlRejected != before.ControlRejected ||
		after.SourceRejected != before.SourceRejected ||
		after.HandshakeReject != before.HandshakeReject ||
		after.PreauthReject != before.PreauthReject {
		t.Fatalf("recording a local frame reject changed an admission counter: %+v -> %+v", before, after)
	}
	// A nil limiter (a directly built Network value) must not panic and must stay
	// permissive.
	var nilRates *networkRates
	nilRates.recordFrameLocalReject()
	if got := nilRates.stats().FrameLocalRejected; got != 0 {
		t.Fatalf("nil limiter recorded %d rejects; want 0", got)
	}
	// The counter is a bounded aggregate: a thousand drops create no bucket and
	// no per-Link entry.
	rates.mu.Lock()
	peers, links, sources := len(rates.peers), len(rates.links), len(rates.sources)
	rates.mu.Unlock()
	for i := 0; i < 1000; i++ {
		rates.recordFrameLocalReject()
	}
	if got := rates.stats().FrameLocalRejected; got != 1001 {
		t.Fatalf("FrameLocalRejected = %d after 1001 records; want 1001", got)
	}
	rates.mu.Lock()
	peersAfter, linksAfter, sourcesAfter := len(rates.peers), len(rates.links), len(rates.sources)
	rates.mu.Unlock()
	if peersAfter != peers || linksAfter != links || sourcesAfter != sources {
		t.Fatalf("frame-local rejects grew bounded state: peers %d->%d links %d->%d sources %d->%d",
			peers, peersAfter, links, linksAfter, sources, sourcesAfter)
	}
}

// TestRatesFrameLocalRejectIsAtomic exercises the aggregate from concurrent
// ingress classifiers: the total must be exact, so a dropped frame can never be
// lost or double counted by a racing recorder.
func TestRatesFrameLocalRejectIsAtomic(t *testing.T) {
	rates, _ := newRateTestLimiter()
	const goroutines, perGoroutine = 8, 250
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				rates.recordFrameLocalReject()
			}
		}()
	}
	wg.Wait()
	if got := rates.stats().FrameLocalRejected; got != goroutines*perGoroutine {
		t.Fatalf("FrameLocalRejected = %d; want %d", got, goroutines*perGoroutine)
	}
}

// TestRatesAuthenticatedConnectionRefundsSourceToken pins the admission policy: a
// connection that completes authentication gives its per-source token back, so a
// peer opening many legitimate links is not throttled by its own success. Only
// repeated failures are meant to slow a source down.
func TestRatesAuthenticatedConnectionRefundsSourceToken(t *testing.T) {
	rates, _ := newRateTestLimiter()
	const source = "source-refund"

	// Drain the burst, then prove a refund makes room again.
	admitted := 0
	for rates.allowSourceConnect(source) {
		admitted++
		if admitted > rateSourceConnectBurst {
			t.Fatalf("admitted %d connections; burst is %d", admitted, rateSourceConnectBurst)
		}
	}
	if admitted != rateSourceConnectBurst {
		t.Fatalf("admitted %d connections; want the full burst %d", admitted, rateSourceConnectBurst)
	}
	if ok, _ := rates.trySourceConnect(source); ok {
		t.Fatal("a drained source still admitted a connection")
	}

	rates.returnSourceConnect(source)

	if ok, _ := rates.trySourceConnect(source); !ok {
		t.Fatal("refunded token was not available for the next connection")
	}
}
