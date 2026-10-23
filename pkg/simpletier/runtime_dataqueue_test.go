package simpletier

import (
	"testing"

	"github.com/yiiilin/simpletier/internal/budget"
)

// TestDataQueueCategoryAndPerLink4MiBIncludesPrefix pins the outbound queue
// accounting of one physical Link: a hop-protected E2E body is a Data charge on
// the exact Link instance, its size is the complete wire size including the
// 4-byte length prefix and the 16-byte outer tag, and the frozen per-Link
// 4 MiB cap therefore holds only 63 maximum-size frames (64 * 65556 > 4 MiB),
// which would silently be 64 if the length prefix were omitted.
func TestDataQueueCategoryAndPerLink4MiBIncludesPrefix(t *testing.T) {
	n := admissionNetwork(t, "data-queue-token-0123456789")
	alloc := n.stateBudgetPtr()
	key := budget.LinkKey{LinkID: 0xABCDEF, Epoch: 1}
	if err := n.registerPhysicalLinkKey(key.LinkID, key.Epoch); err != nil {
		t.Fatalf("registerPhysicalLinkKey: %v", err)
	}
	pump := &controlPump{network: n, linkKey: key}

	const payload = 65536
	write := pendingWrite{kind: writeEndToEnd, payload: make([]byte, payload)}
	const wantWire = 4 + payload + 16
	if got := write.wireBytes(); got != wantWire {
		t.Fatalf("E2E wire estimate = %d; want %d (4 prefix + payload + 16 tag)", got, wantWire)
	}
	if wantWire*64 <= budget.DefaultLinkDataBytes {
		t.Fatalf("test premise broken: 64 max frames = %d must exceed the %d per-Link cap",
			wantWire*64, budget.DefaultLinkDataBytes)
	}

	before := alloc.Stats()
	leases := make([]*budget.Lease, 0, 64)
	for i := 0; i < 63; i++ {
		lease, err := pump.reserveWrite(write)
		if err != nil {
			t.Fatalf("frame %d/%d refused inside the per-Link cap: %v", i, 63, err)
		}
		leases = append(leases, lease)
	}
	if _, err := pump.reserveWrite(write); err == nil {
		t.Fatal("the 64th maximum-size E2E frame was admitted; the 4 MiB per-Link cap must include the 4-byte prefix")
	}
	stats := alloc.Stats()
	if got := stats.Data.Bytes - before.Data.Bytes; got != 63*wantWire {
		t.Fatalf("Data bytes delta = %d; want %d", got, 63*wantWire)
	}
	if stats.State.Bytes != before.State.Bytes {
		t.Fatalf("E2E queue charged State (%d -> %d) instead of Data", before.State.Bytes, stats.State.Bytes)
	}
	if stats.Control.Bytes != before.Control.Bytes {
		t.Fatalf("E2E queue charged Control (%d -> %d)", before.Control.Bytes, stats.Control.Bytes)
	}
	for _, lease := range leases {
		if err := lease.Release(); err != nil {
			t.Fatalf("release queued lease: %v", err)
		}
	}
	if after := alloc.Stats(); after.Data.Bytes != before.Data.Bytes {
		t.Fatalf("Data bytes after releasing every queued lease = %d; want baseline %d", after.Data.Bytes, before.Data.Bytes)
	}
}

// TestControlQueueChargesControlCategory pins that LINK_CTRL/ROUTE_CTRL/
// key-update writes are Control charges, not Data, so the two categories stay
// separately bounded.
func TestControlQueueChargesControlCategory(t *testing.T) {
	n := admissionNetwork(t, "control-queue-token-0123456789")
	alloc := n.stateBudgetPtr()
	key := budget.LinkKey{LinkID: 0x1234, Epoch: 2}
	if err := n.registerPhysicalLinkKey(key.LinkID, key.Epoch); err != nil {
		t.Fatalf("registerPhysicalLinkKey: %v", err)
	}
	pump := &controlPump{network: n, linkKey: key}
	before := alloc.Stats()
	lease, err := pump.reserveWrite(pendingWrite{kind: writeRoute, payload: make([]byte, 1024)})
	if err != nil {
		t.Fatalf("reserveWrite(route): %v", err)
	}
	stats := alloc.Stats()
	if stats.Control.Bytes <= before.Control.Bytes {
		t.Fatal("a ROUTE_CTRL queue write did not charge the control category")
	}
	if stats.Data.Bytes != before.Data.Bytes {
		t.Fatal("a ROUTE_CTRL queue write charged the data category")
	}
	n.releaseState(lease)
}
