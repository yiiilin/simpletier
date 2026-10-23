package simpletier

import (
	"net/netip"
	"testing"
)

// TestFactStateBudgetChargesCategoryState proves the production adapter books a
// FactStore's owned bytes as CategoryState in the Network's one shared
// allocator: exactly one lease for the whole store, sized to the store's owned
// bytes, resized in place (never stacked) as the store grows, and released when
// the Network closes so the ledger ends owning nothing and reports no leak.
func TestFactStateBudgetChargesCategoryState(t *testing.T) {
	n := admissionNetwork(t, "fact-state-budget-token-0123456789")
	alloc := n.stateBudgetPtr()
	if alloc == nil {
		t.Fatal("network has no published state allocator")
	}
	before := snapshotStagingLedger(alloc)

	publishLocalAddressClaim(t, n, netip.MustParseAddr("10.88.0.7"))
	after := snapshotStagingLedger(alloc)
	stateCharged := after.stateBytes - before.stateBytes
	if stateCharged == 0 {
		t.Fatal("publishing local FACT state charged no CategoryState bytes")
	}
	if after.dataBytes != before.dataBytes {
		t.Fatalf("Data bytes changed by %d; FACT state must be State, not Data", after.dataBytes-before.dataBytes)
	}
	if got := after.heapBytes - before.heapBytes; got != stateCharged {
		t.Fatalf("heap charged %d bytes; want %d (state counts once)", got, stateCharged)
	}
	if got := after.leases - before.leases; got != 1 {
		t.Fatalf("outstanding leases %d; want exactly 1 for the store's single reservation", got)
	}

	// A larger published state resizes that same single reservation instead of
	// taking a second one.
	publishLocalAddressClaim(t, n, netip.MustParseAddr("10.88.0.8"))
	grown := snapshotStagingLedger(alloc)
	if got := grown.leases - before.leases; got != 1 {
		t.Fatalf("outstanding leases after growth = %d; want still exactly 1", got)
	}
	if grown.stateBytes <= after.stateBytes {
		t.Fatalf("State bytes did not grow with the published FACT state: %d -> %d", after.stateBytes, grown.stateBytes)
	}

	// Network Close releases the store's reservation: the ledger ends owning
	// nothing and reports no leak.
	if err := n.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	stats := alloc.Stats()
	if !stats.Closed {
		t.Fatal("allocator was not closed by Network Close")
	}
	if stats.State.Bytes != 0 || stats.Heap.Bytes != 0 || stats.Leases != 0 || stats.LeakedBytes != 0 {
		t.Fatalf("after Close the ledger still owns state %d / heap %d bytes across %d leases (leaked %d); want nothing",
			stats.State.Bytes, stats.Heap.Bytes, stats.Leases, stats.LeakedBytes)
	}
}
