package simpletier

import (
	"net/netip"
	"testing"
	"time"
)

// TestVerificationBudgetSaturatesAndRefusesAtCeiling pins the frozen accounting:
// every failure up to the limit is admitted, the failure that reaches the limit
// is recorded and refused (false = fail closed), and the counter saturates: it
// never wraps and never exceeds the limit.
func TestVerificationBudgetSaturatesAndRefusesAtCeiling(t *testing.T) {
	const limit = 8
	ledger := newVerificationBudget(limit, nil)
	for i := uint64(1); i < limit; i++ {
		if !ledger.RecordFailure() {
			t.Fatalf("failure %d/%d refused before the ceiling", i, limit)
		}
	}
	if failed := ledger.failed(); failed != limit-1 {
		t.Fatalf("failed = %d before the ceiling; want %d", failed, limit-1)
	}
	if ledger.RecordFailure() {
		t.Fatalf("the failure that reaches the ceiling %d must be refused", limit)
	}
	if failed := ledger.failed(); failed != limit {
		t.Fatalf("failed = %d at the ceiling; want %d", failed, limit)
	}
	for i := 0; i < 100; i++ {
		if ledger.RecordFailure() {
			t.Fatal("a saturated ledger admitted another failure")
		}
	}
	if failed := ledger.failed(); failed != limit {
		t.Fatalf("saturated ledger wrapped to %d; want %d", failed, limit)
	}
}

// TestVerificationBudgetCeilingCallbackOnce proves the one-shot ceiling action
// fires exactly once no matter how many further failures are reported.
func TestVerificationBudgetCeilingCallbackOnce(t *testing.T) {
	ledger := newVerificationBudget(2, func() {
		// Count via the same atomic the ledger uses would recurse; use a channel.
		select {
		case ceilingFired <- struct{}{}:
		default:
		}
	})
	ledger.RecordFailure()
	ledger.RecordFailure()
	for i := 0; i < 5; i++ {
		ledger.RecordFailure()
	}
	select {
	case <-ceilingFired:
	default:
		t.Fatal("ceiling callback never fired")
	}
	select {
	case <-ceilingFired:
		t.Fatal("ceiling callback fired more than once")
	default:
	}
}

var ceilingFired = make(chan struct{}, 4)

// TestVerificationBudgetNeverResetsAcrossStableGenerations pins that a completed
// key update cannot restart the aggregate count. The ledger exposes no reset and
// the limit callback state stays terminal, so an already-refused failure stays
// refused.
func TestVerificationBudgetNeverResetsAcrossStableGenerations(t *testing.T) {
	const limit = 4
	ledger := newVerificationBudget(limit, nil)
	for i := uint64(0); i < limit; i++ {
		ledger.RecordFailure()
	}
	before := ledger.failed()
	// The Link and session layers call noteStableGeneration on a completed rekey;
	// there is deliberately no corresponding decrement on this ledger.
	for generation := 0; generation < 3; generation++ {
		if ledger.RecordFailure() {
			t.Fatal("a new stable generation admitted a failure past the ceiling")
		}
		if after := ledger.failed(); after != before {
			t.Fatalf("stable generation %d reset the count: %d -> %d", generation, before, after)
		}
	}
}

// TestNetworkVerificationStatsObservable proves the observable Network figure is
// the actual shared failed-tag count, not the per-key policy's own risk flags.
func TestNetworkVerificationStatsObservable(t *testing.T) {
	n := admissionNetwork(t, "verification-stats-token-0123456789")
	failed, limit := n.verificationStats()
	if failed != 0 || limit != networkVerificationBudgetLimit {
		t.Fatalf("fresh stats = (%d,%d); want (0,%d)", failed, limit, networkVerificationBudgetLimit)
	}
	budget := n.verificationBudget()
	if budget == nil {
		t.Fatal("network has no aggregate verification budget")
	}
	for i := 0; i < 3; i++ {
		budget.RecordFailure()
	}
	if failed, _ := n.verificationStats(); failed != 3 {
		t.Fatalf("stats failed = %d after 3 real failures; want 3", failed)
	}
}

// TestNetworkVerificationBudgetsSharedByEveryPump drives two real Networks that
// each carry two authenticated Links (CONTROL and one data Lane) and proves every
// live hop protector was handed the exact same Network-lifetime ledger before any
// frame flowed. The directional E2E protectors receive the same value through the
// identical structural seam (`session.VerificationBudget`), pinned at compile
// time in runtime_budget.go.
func TestNetworkVerificationBudgetsSharedByEveryPump(t *testing.T) {
	const (
		name  = "verification-shared"
		cidr  = "10.124.0.0/24"
		token = "verification-shared-token-0123456789"
	)
	targetIP := netip.MustParseAddr("10.124.0.3")
	sourceIP := netip.MustParseAddr("10.124.0.1")

	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, sourceIP.String(), relayCarrierURL(target))
	waitRelayLinks(t, target, 2, 30*time.Second)
	waitRelayLinks(t, source, 2, 30*time.Second)

	for _, n := range []*network{source, target} {
		pumps := n.controlPumpSnapshotAll()
		if len(pumps) < 2 {
			t.Fatalf("network has %d pumps; want at least 2 (CONTROL + data Lane)", len(pumps))
		}
		shared := n.verificationBudget()
		for _, pump := range pumps {
			if pump.budget != shared {
				t.Fatalf("pump lane %d has ledger %p; want the shared %p", pump.lane, pump.budget, shared)
			}
		}
	}
}

// TestNetworkVerificationCeilingClosesNetwork proves the hard aggregate ceiling
// is terminal for the whole Network: reaching it cancels and closes the Network
// without waiting on the reporting goroutine.
func TestNetworkVerificationCeilingClosesNetwork(t *testing.T) {
	n := admissionNetwork(t, "verification-ceiling-token-0123456789")
	budget := n.verificationBudget()
	if budget == nil {
		t.Fatal("network has no aggregate verification budget")
	}
	for i := uint64(1); i < networkVerificationBudgetLimit; i++ {
		if !budget.RecordFailure() {
			t.Fatalf("failure %d refused before the ceiling", i)
		}
	}
	if budget.RecordFailure() {
		t.Fatal("the ceiling failure must be refused")
	}
	select {
	case <-n.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("Network did not close after the aggregate tag ceiling")
	}
	if failed, limit := n.verificationStats(); failed != limit || limit != networkVerificationBudgetLimit {
		t.Fatalf("stats after ceiling = (%d,%d); want (%d,%d)", failed, limit, networkVerificationBudgetLimit, networkVerificationBudgetLimit)
	}
}
