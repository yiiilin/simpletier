package simpletier

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/topology"
)

// The authenticated FACT staging plane retains the canonical record bytes of one
// inbound sender snapshot per authenticated Link. These tests prove those bytes
// are booked in the Network's shared internal/budget ledger as CategoryState
// exactly once, that every staging lifecycle end returns the lease, and that a
// refusal on the shared ledger takes the existing explicit FACT_ACK
// REJECT(resource) path.
//
// Every assertion reads the production allocator the Network was built with - no
// mock ledger and no injected counter - and the refusal cases run through the
// real protected CONTROL Link and the real control pump.

// The Network's own fixed reservations decide how much shared heap a test has to
// play with: construction books rateMetadataEstimateBytes of state, and admitting
// one peer books exactly one control pump's receive allowance. Admitting that
// peer also publishes its local NODE/ADDRESS facts, so the FactStore books its
// owned bytes into that same heap before the test's baseline is taken. Lowering
// the ceiling to the fixed reservations, the store's reservation and a chosen
// headroom makes the shared heap, not a local FACT ceiling, the refusing bound.
const (
	// factStagingRefusalHeadroom is deliberately smaller than one 128-record
	// page's canonical bytes (about 11 KiB), so the very first page cannot be
	// booked.
	factStagingRefusalHeadroom = 8 << 10
	// factStagingReleaseHeadroom fits one 128-record page (about 16 KiB) plus the
	// FactStore's own roughly 1.6 KiB reservation and leaves a few KiB for the
	// small control-write leases the ACKs need, so the second page is refused
	// after the first was accepted.
	factStagingReleaseHeadroom = 24 << 10
)

// factStagingTestHeapLimit is the lowered shared heap ceiling for one refusal
// test: the Network's fixed construction and single-peer admission reservations
// plus the caller's headroom.
func factStagingTestHeapLimit(headroom uint64) uint64 {
	return rateMetadataEstimateBytes + pumpRecvFrameAllowance + pumpRecvScratchAllowance + headroom
}

// baselineAfterFactStoreBooked returns the shared ledger snapshot taken once the
// admission's local FACT publish has booked the FactStore's owned bytes. The
// frozen accounting rule books FACT state into the same Network heap, so the
// staging plane's usable headroom is the lowered ceiling minus the Network's
// fixed reservations AND the store's reservation; capturing the baseline here
// makes a later delta the staging charge alone.
func baselineAfterFactStoreBooked(t *testing.T, n *network) stagingLedger {
	t.Helper()
	alloc := n.stateBudgetPtr()
	fixed := factStagingTestHeapLimit(0)
	var baseline stagingLedger
	waitForCondition(t, "the FactStore's owned bytes are booked in the shared ledger", 10*time.Second, func() bool {
		baseline = snapshotStagingLedger(alloc)
		return baseline.heapBytes > fixed
	})
	return baseline
}

// factStagingTestSource builds one synthetic authenticated ingress identity for
// the direct staging calls below. Only LinkID and the exact struct identity
// matter to beginStaging/stagePage; the peer identity is opaque here.
func factStagingTestSource(n *network, linkID uint64) topology.FactSource {
	return topology.FactSource{
		ContextID:         n.networkContext.ID(),
		AuthenticatedPeer: topology.NodeID{0x11},
		PeerStatic:        [32]byte{0x22},
		LinkID:            linkID,
		Epoch:             1,
		LaneID:            topology.FactLaneControl,
	}
}

// factStagingTestRecords builds count distinct ADDRESS facts, so a snapshot can
// be split into several genuinely different digest-bound pages.
func factStagingTestRecords(t *testing.T, networkID uint64, origin topology.NodeID, count int) []topology.FactRecord {
	t.Helper()
	issued, expires := factTestMillisWindow(time.Now())
	records := make([]topology.FactRecord, 0, count)
	for i := 0; i < count; i++ {
		address := fmt.Sprintf("10.70.%d.%d", i/200, i%200+1)
		records = append(records, factTestAddressRecord(networkID, origin, address,
			topology.FactVersion{Incarnation: 7, Sequence: uint64(i + 1)}, issued, expires))
	}
	return records
}

// factStagingPageBytes is exactly the charge the production control pump hands to
// stagePage: the encoded page payload minus its fixed header, i.e. the canonical
// record bytes the page contributes.
func factStagingPageBytes(t *testing.T, page topology.FactPage) int64 {
	t.Helper()
	payload, err := topology.EncodeFactPage(page)
	if err != nil {
		t.Fatalf("encode FACT_PAGE: %v", err)
	}
	if len(payload) <= topology.FactPageHeaderSize {
		t.Fatalf("encoded page payload = %d bytes; want more than the %d-byte header",
			len(payload), topology.FactPageHeaderSize)
	}
	return int64(len(payload) - topology.FactPageHeaderSize)
}

// factStagingStageAll drives one complete staging attempt through the production
// methods and returns the exact canonical bytes it booked.
func factStagingStageAll(t *testing.T, n *network, source topology.FactSource, summary topology.FactSummary, pages []topology.FactPage, now time.Time) int64 {
	t.Helper()
	if err := n.facts.beginStaging(source, summary); err != nil {
		t.Fatalf("beginStaging: %v", err)
	}
	var staged int64
	for index, page := range pages {
		bytes := factStagingPageBytes(t, page)
		if _, err := n.facts.stagePage(source, page, bytes, now); err != nil {
			t.Fatalf("stagePage(%d): %v", index, err)
		}
		staged += bytes
	}
	return staged
}

// TestFactStagingPageChargedAsExactStateOnce proves one accepted page books
// exactly its canonical record bytes, once, as CategoryState (never Data), and
// that an identical repeat of that page books nothing further.
func TestFactStagingPageChargedAsExactStateOnce(t *testing.T) {
	n := stagingTestNetwork(t, "fact-staging-charge-token-0123456789", nil)
	alloc := n.stateBudgetPtr()
	networkID := n.networkContext.WireID()
	now := time.Now()
	origin := topology.NodeID{0x33}
	summary, pages := factTestSnapshot(t, networkID, 7, 1, 2,
		factStagingTestRecords(t, networkID, origin, 4))
	if len(pages) != 2 {
		t.Fatalf("fixture produced %d pages; want 2", len(pages))
	}
	source := factStagingTestSource(n, 0x4101)

	baseline := snapshotStagingLedger(alloc)
	if err := n.facts.beginStaging(source, summary); err != nil {
		t.Fatalf("beginStaging: %v", err)
	}
	// Declaring a snapshot retains no canonical page bytes, so it books nothing.
	if got := snapshotStagingLedger(alloc); got != baseline {
		t.Fatalf("beginStaging changed the ledger: %+v -> %+v", baseline, got)
	}

	first := factStagingPageBytes(t, pages[0])
	if first <= 0 {
		t.Fatalf("page 0 canonical bytes = %d; want > 0", first)
	}
	if _, err := n.facts.stagePage(source, pages[0], first, now); err != nil {
		t.Fatalf("stagePage(0): %v", err)
	}
	after := snapshotStagingLedger(alloc)
	if got := after.stateBytes - baseline.stateBytes; got != uint64(first) {
		t.Fatalf("State bytes charged %d; want exactly %d", got, first)
	}
	if got := after.dataBytes - baseline.dataBytes; got != 0 {
		t.Fatalf("Data bytes charged %d; retained fact state must be State, not Data", got)
	}
	if got := after.heapBytes - baseline.heapBytes; got != uint64(first) {
		t.Fatalf("heap bytes charged %d; want exactly %d", got, first)
	}
	if got := after.leases - baseline.leases; got != 1 {
		t.Fatalf("outstanding leases %d; want exactly 1 for one accepted page", got)
	}
	if got := after.rejected; got != baseline.rejected {
		t.Fatalf("an accepted page refused %d request(s)", got-baseline.rejected)
	}

	// The identical repeat is idempotent: it retains nothing new and books
	// nothing new.
	outcome, err := n.facts.stagePage(source, pages[0], first, now)
	if err != nil {
		t.Fatalf("duplicate stagePage: %v", err)
	}
	if !outcome.duplicate {
		t.Fatal("identical repeat was not reported as a duplicate")
	}
	if got := snapshotStagingLedger(alloc); got != after {
		t.Fatalf("duplicate repeat changed the ledger: %+v -> %+v", after, got)
	}

	// A conflicting repeat of the same page number is refused without touching
	// the ledger.
	conflicting := pages[0]
	conflicting.PageDigest[0] ^= 0xFF
	if _, err := n.facts.stagePage(source, conflicting, first, now); !errors.Is(err, errFactPageConflict) {
		t.Fatalf("conflicting repeat error = %v; want errFactPageConflict", err)
	}
	if got := snapshotStagingLedger(alloc); got != after {
		t.Fatalf("conflicting repeat changed the ledger: %+v -> %+v", after, got)
	}

	n.facts.dropStaging(source.LinkID)
	if got := snapshotStagingLedger(alloc); got != baseline {
		t.Fatalf("ledger after drop = %+v; want baseline %+v", got, baseline)
	}
}

// TestFactStagingReleasedOnEveryLifecycleEnd proves each staging end returns the
// shared-ledger leases exactly once: replacement by the next FACT_SUMMARY, TTL
// expiry through both the sweep and an in-line stagePage, successful take, an
// unknown-staging discard, and shutdown.
func TestFactStagingReleasedOnEveryLifecycleEnd(t *testing.T) {
	n := stagingTestNetwork(t, "fact-staging-lifecycle-token-0123456789", nil)
	alloc := n.stateBudgetPtr()
	networkID := n.networkContext.WireID()
	now := time.Now()
	origin := topology.NodeID{0x44}
	summary, pages := factTestSnapshot(t, networkID, 7, 1, 2,
		factStagingTestRecords(t, networkID, origin, 4))
	if len(pages) != 2 {
		t.Fatalf("fixture produced %d pages; want 2", len(pages))
	}
	baseline := snapshotStagingLedger(alloc)

	// assertReleased proves the ledger is back at its baseline and no canonical
	// page bytes are still retained. Replacement deliberately leaves a fresh,
	// empty staging entry behind, so the entry count is asserted separately.
	assertReleased := func(t *testing.T, phase string) {
		t.Helper()
		if got := snapshotStagingLedger(alloc); got != baseline {
			t.Fatalf("ledger after %s = %+v; want baseline %+v", phase, got, baseline)
		}
		if status := n.factStatus(); status.StagedBytes != 0 {
			t.Fatalf("staged bytes after %s = %d; want none", phase, status.StagedBytes)
		}
	}
	// assertDropped additionally proves the staging entry itself is gone.
	assertDropped := func(t *testing.T, phase string) {
		t.Helper()
		assertReleased(t, phase)
		if status := n.factStatus(); status.StagingLinks != 0 {
			t.Fatalf("staging links after %s = %d; want none", phase, status.StagingLinks)
		}
	}

	t.Run("replacement", func(t *testing.T) {
		source := factStagingTestSource(n, 0x4201)
		staged := factStagingStageAll(t, n, source, summary, pages, now)
		if staged <= 0 {
			t.Fatalf("staged bytes = %d; want > 0", staged)
		}
		if got := snapshotStagingLedger(alloc).stateBytes - baseline.stateBytes; got != uint64(staged) {
			t.Fatalf("State bytes charged %d; want %d", got, staged)
		}
		// The next FACT_SUMMARY replaces the staging entirely: the old page
		// leases come back and only a fresh, empty staging entry remains.
		if err := n.facts.beginStaging(source, summary); err != nil {
			t.Fatalf("replacement beginStaging: %v", err)
		}
		assertReleased(t, "replacement")
	})

	t.Run("ttl sweep", func(t *testing.T) {
		source := factStagingTestSource(n, 0x4202)
		factStagingStageAll(t, n, source, summary, pages, now)
		n.facts.sweepExpiredStaging(now.Add(factStagingTTL + time.Second))
		assertDropped(t, "TTL sweep")
	})

	t.Run("ttl in-line stagePage", func(t *testing.T) {
		source := factStagingTestSource(n, 0x4203)
		factStagingStageAll(t, n, source, summary, pages, now)
		expired := now.Add(factStagingTTL + time.Second)
		_, err := n.facts.stagePage(source, pages[0], factStagingPageBytes(t, pages[0]), expired)
		if !errors.Is(err, errFactStagingUnknown) {
			t.Fatalf("expired stagePage error = %v; want errFactStagingUnknown", err)
		}
		assertDropped(t, "in-line TTL drop")
	})

	t.Run("take", func(t *testing.T) {
		source := factStagingTestSource(n, 0x4204)
		factStagingStageAll(t, n, source, summary, pages, now)
		gotSummary, gotPages, ok := n.facts.takeStaged(source.LinkID)
		if !ok || len(gotPages) != len(pages) || gotSummary.SnapshotVersion != summary.SnapshotVersion {
			t.Fatalf("takeStaged = %v/%d pages/%v; want the staged snapshot", ok, len(gotPages), gotSummary)
		}
		assertDropped(t, "take")
	})

	t.Run("unknown staging discard", func(t *testing.T) {
		source := factStagingTestSource(n, 0x4205)
		factStagingStageAll(t, n, source, summary, pages, now)
		// A page for a snapshot this Link never staged is discarded, taking the
		// staged bytes with it.
		stranger := factStagingTestSource(n, 0x4206)
		if _, err := n.facts.stagePage(stranger, pages[0], factStagingPageBytes(t, pages[0]), now); !errors.Is(err, errFactStagingUnknown) {
			t.Fatalf("unknown staging error = %v; want errFactStagingUnknown", err)
		}
		n.facts.dropStaging(source.LinkID)
		assertDropped(t, "unknown-staging discard")
	})

	t.Run("shutdown dropAllStaging", func(t *testing.T) {
		source := factStagingTestSource(n, 0x4207)
		factStagingStageAll(t, n, source, summary, pages, now)
		n.facts.dropAllStaging()
		assertDropped(t, "dropAllStaging")
	})
}

// TestFactStagingReleasedByNetworkClose proves the production shutdown path
// releases staged leases: a Network closed with a live inbound staging leaves
// nothing owned in the ledger instead of stranding the charge.
func TestFactStagingReleasedByNetworkClose(t *testing.T) {
	n := stagingTestNetwork(t, "fact-staging-close-token-0123456789", nil)
	alloc := n.stateBudgetPtr()
	networkID := n.networkContext.WireID()
	now := time.Now()
	origin := topology.NodeID{0x55}
	summary, pages := factTestSnapshot(t, networkID, 7, 1, 2,
		factStagingTestRecords(t, networkID, origin, 4))
	source := factStagingTestSource(n, 0x4301)

	// The post-construction baseline: only the Network's own fixed reservations
	// (rate metadata) are booked, so the staging charge is the only delta.
	baseline := snapshotStagingLedger(alloc)
	staged := factStagingStageAll(t, n, source, summary, pages, now)
	if got := snapshotStagingLedger(alloc).stateBytes - baseline.stateBytes; got != uint64(staged) {
		t.Fatalf("State bytes charged %d; want %d", got, staged)
	}

	if err := n.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Network Close drains the whole ledger - the staging leases and the
	// Network's own fixed reservations alike - so the honest assertion is that
	// nothing is left owned: a staged lease that survived shutdown would show up
	// as leaked bytes and an outstanding lease.
	stats := alloc.Stats()
	if !stats.Closed {
		t.Fatal("allocator was not closed by Network Close")
	}
	if stats.LeakedBytes != 0 || stats.LeakedFrames != 0 || stats.Leases != 0 || stats.State.Bytes != 0 {
		t.Fatalf("after Close the ledger still owns %d bytes/%d frames across %d leases (state %d); want nothing",
			stats.LeakedBytes, stats.LeakedFrames, stats.Leases, stats.State.Bytes)
	}
}

// TestFactStagingSharedLedgerRefusalRejectsResource proves an inbound page that
// the shared heap ledger refuses takes the existing explicit FACT_ACK
// REJECT(resource) path: the peer observes the rejection, nothing is retained,
// and the ledger stays at its baseline.
func TestFactStagingSharedLedgerRefusalRejectsResource(t *testing.T) {
	n := stagingTestNetwork(t, "fact-staging-refusal-token-0123456789", func(limits *budget.Limits) {
		limits.HeapBytes = factStagingTestHeapLimit(factStagingRefusalHeadroom)
	})
	alloc := n.stateBudgetPtr()
	networkID := n.networkContext.WireID()
	peer := newFactTestPeer(t, n, 0x4401)

	summary, pages := factTestSnapshot(t, networkID, 7, 1, topology.MaxPageRecords,
		factStagingTestRecords(t, networkID, peer.nodeID, 2*topology.MaxPageRecords))
	if len(pages) != 2 {
		t.Fatalf("fixture produced %d pages; want 2", len(pages))
	}
	first := factStagingPageBytes(t, pages[0])
	if first <= factStagingRefusalHeadroom {
		t.Fatalf("page 0 canonical bytes = %d; the lowered heap must leave less headroom (%d) than one page for this test to refuse",
			first, factStagingRefusalHeadroom)
	}

	// Admitting the peer booked the Network's fixed reservations AND the
	// FactStore's owned bytes, so the free heap is the chosen headroom minus the
	// store's reservation.
	baseline := baselineAfterFactStoreBooked(t, n)
	free := factStagingTestHeapLimit(factStagingRefusalHeadroom) - baseline.heapBytes
	if free == 0 || free >= uint64(first) {
		t.Fatalf("free heap headroom = %d; want more than zero and less than one page (%d) so the shared ledger, not a local FACT ceiling, is the refusing bound",
			free, first)
	}

	peer.sendSummary(t, summary)
	if ack := peer.expectAck(t, topology.AckNeedPage, 0); ack.MissingPage != 0 {
		t.Fatalf("FACT_ACK missing page = %d; want 0", ack.MissingPage)
	}
	peer.sendPage(t, pages[0])
	ack := peer.expectAck(t, topology.AckReject, 0)
	if ack.Reason != factAckReasonResource {
		t.Fatalf("FACT_ACK reject reason = %d; want %d (resource)", ack.Reason, factAckReasonResource)
	}

	if status := n.factStatus(); status.StagingLinks != 0 || status.StagedBytes != 0 {
		t.Fatalf("refused page left staging = %d links/%d bytes; want none",
			status.StagingLinks, status.StagedBytes)
	}
	after := snapshotStagingLedger(alloc)
	if after.stateBytes != baseline.stateBytes || after.heapBytes != baseline.heapBytes ||
		after.leases != baseline.leases {
		t.Fatalf("refused page changed the ledger: %+v -> %+v", baseline, after)
	}
	if got := after.rejected - baseline.rejected; got != 1 {
		t.Fatalf("allocator refused %d request(s); want exactly 1", got)
	}
}

// TestFactStagingRefusalReleasesEarlierPages proves the reject path also returns
// the lease of a page that was already accepted: the first page fits and is
// charged, the second page exceeds the shared ledger, and the REJECT drops the
// whole staging so the ledger returns to baseline.
func TestFactStagingRefusalReleasesEarlierPages(t *testing.T) {
	n := stagingTestNetwork(t, "fact-staging-refusal-release-token-0123456789", func(limits *budget.Limits) {
		limits.HeapBytes = factStagingTestHeapLimit(factStagingReleaseHeadroom)
	})
	alloc := n.stateBudgetPtr()
	networkID := n.networkContext.WireID()
	peer := newFactTestPeer(t, n, 0x4501)

	summary, pages := factTestSnapshot(t, networkID, 7, 1, topology.MaxPageRecords,
		factStagingTestRecords(t, networkID, peer.nodeID, 2*topology.MaxPageRecords))
	if len(pages) != 2 {
		t.Fatalf("fixture produced %d pages; want 2", len(pages))
	}
	first := factStagingPageBytes(t, pages[0])
	second := factStagingPageBytes(t, pages[1])
	baseline := baselineAfterFactStoreBooked(t, n)
	free := factStagingTestHeapLimit(factStagingReleaseHeadroom) - baseline.heapBytes
	if uint64(first) > free {
		t.Fatalf("page 0 canonical bytes = %d; want at most the %d bytes of free heap so it is accepted", first, free)
	}
	if uint64(first+second) <= free {
		t.Fatalf("pages total %d bytes; want more than the %d bytes of free heap so the second is refused", first+second, free)
	}

	peer.sendSummary(t, summary)
	peer.expectAck(t, topology.AckNeedPage, 0)
	peer.sendPage(t, pages[0])
	// The pump echoes the page it just received and names the first missing one.
	if ack := peer.expectAck(t, topology.AckNeedPage, 0); ack.MissingPage != 1 {
		t.Fatalf("FACT_ACK missing page = %d; want 1 after page 0 was accepted", ack.MissingPage)
	}

	charged := snapshotStagingLedger(alloc)
	if got := charged.stateBytes - baseline.stateBytes; got != uint64(first) {
		t.Fatalf("accepted page charged %d State bytes; want %d", got, first)
	}
	if got := charged.leases - baseline.leases; got != 1 {
		t.Fatalf("outstanding leases %d; want exactly 1 for the accepted page", got)
	}

	peer.sendPage(t, pages[1])
	ack := peer.expectAck(t, topology.AckReject, 1)
	if ack.Reason != factAckReasonResource {
		t.Fatalf("FACT_ACK reject reason = %d; want %d (resource)", ack.Reason, factAckReasonResource)
	}
	if status := n.factStatus(); status.StagingLinks != 0 || status.StagedBytes != 0 {
		t.Fatalf("refused snapshot left staging = %d links/%d bytes; want none",
			status.StagingLinks, status.StagedBytes)
	}

	// The accepted page's lease came back with the rejected snapshot. Only the
	// allocator's monotonic refused-request counter is expected to differ.
	after := snapshotStagingLedger(alloc)
	if after.dataBytes != baseline.dataBytes || after.stateBytes != baseline.stateBytes ||
		after.heapBytes != baseline.heapBytes || after.leases != baseline.leases {
		t.Fatalf("ledger after rejection = %+v; want the baseline charges %+v", after, baseline)
	}
	if got := after.rejected - baseline.rejected; got != 1 {
		t.Fatalf("allocator refused %d request(s); want exactly 1", got)
	}
}

// TestFactStagingConcurrentIngestionAndCloseReleasesExactlyOnce drives concurrent
// ingestion, replacement, take, discard and shutdown over one real ledger. Exact
// equality with the baseline at the end proves every lease was released exactly
// once: a leak leaves the ledger high and a double release underflows it.
func TestFactStagingConcurrentIngestionAndCloseReleasesExactlyOnce(t *testing.T) {
	n := stagingTestNetwork(t, "fact-staging-concurrent-token-0123456789", nil)
	alloc := n.stateBudgetPtr()
	networkID := n.networkContext.WireID()
	now := time.Now()
	origin := topology.NodeID{0x66}
	summary, pages := factTestSnapshot(t, networkID, 7, 1, 2,
		factStagingTestRecords(t, networkID, origin, 4))
	if len(pages) != 2 {
		t.Fatalf("fixture produced %d pages; want 2", len(pages))
	}
	// Encoding reports through t, which is not safe from a worker goroutine, so
	// the exact per-page charge is computed once up front.
	pageBytes := make([]int64, len(pages))
	for index, page := range pages {
		pageBytes[index] = factStagingPageBytes(t, page)
	}
	baseline := snapshotStagingLedger(alloc)

	const workers = 8
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			source := factStagingTestSource(n, uint64(0x5000+id))
			for round := 0; round < 25; round++ {
				if err := n.facts.beginStaging(source, summary); err != nil {
					return
				}
				for index, page := range pages {
					if _, err := n.facts.stagePage(source, page, pageBytes[index], now); err != nil {
						break
					}
				}
				switch round % 3 {
				case 0:
					_ = n.facts.beginStaging(source, summary)
				case 1:
					n.facts.takeStaged(source.LinkID)
				default:
					n.facts.dropStaging(source.LinkID)
				}
			}
		}(worker)
	}
	// A concurrent shutdown-style sweep races every ingestion path.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			n.facts.dropAllStaging()
			runtime.Gosched()
		}
	}()
	wg.Wait()

	// Every worker has stopped; the final shutdown releases whatever a worker
	// staged after the last sweep.
	n.facts.dropAllStaging()
	if status := n.factStatus(); status.StagingLinks != 0 || status.StagedBytes != 0 {
		t.Fatalf("staging after shutdown = %d links/%d bytes; want none",
			status.StagingLinks, status.StagedBytes)
	}
	if got := snapshotStagingLedger(alloc); got != baseline {
		t.Fatalf("ledger after concurrent staging = %+v; want baseline %+v", got, baseline)
	}
}

// TestFactStagingChargeLeavesAnotherNetworkLedgerUntouched proves the staging
// charge is booked to its own Network's ledger: a second, unrelated Network sees
// no byte, frame or lease movement.
func TestFactStagingChargeLeavesAnotherNetworkLedgerUntouched(t *testing.T) {
	charged := stagingTestNetwork(t, "fact-staging-net-a-token-0123456789", nil)
	other := stagingTestNetwork(t, "fact-staging-net-b-token-0123456789", nil)
	chargedAlloc := charged.stateBudgetPtr()
	otherAlloc := other.stateBudgetPtr()

	networkID := charged.networkContext.WireID()
	now := time.Now()
	origin := topology.NodeID{0x77}
	summary, pages := factTestSnapshot(t, networkID, 7, 1, 2,
		factStagingTestRecords(t, networkID, origin, 4))
	source := factStagingTestSource(charged, 0x4601)

	otherBaseline := snapshotStagingLedger(otherAlloc)
	staged := factStagingStageAll(t, charged, source, summary, pages, now)
	if staged <= 0 {
		t.Fatalf("staged bytes = %d; want > 0", staged)
	}
	if got := snapshotStagingLedger(chargedAlloc).stateBytes; got == 0 {
		t.Fatal("no State bytes were charged to the staging Network")
	}
	if got := snapshotStagingLedger(otherAlloc); got != otherBaseline {
		t.Fatalf("unrelated Network ledger changed: %+v -> %+v", otherBaseline, got)
	}

	charged.facts.dropAllStaging()
	if got := snapshotStagingLedger(otherAlloc); got != otherBaseline {
		t.Fatalf("unrelated Network ledger changed after release: %+v -> %+v", otherBaseline, got)
	}
}
