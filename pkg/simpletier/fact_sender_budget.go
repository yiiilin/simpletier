package simpletier

import (
	"log/slog"

	"github.com/yiiilin/simpletier/internal/budget"
)

// factSenderBudget adapts the shared internal/budget allocator onto the outbound
// FACT sender's live referenced snapshots, booking them as CategoryState on the
// Network pool as well as the sender's private factSenderGlobalBytes sub-cap. It
// holds one reservation for the sender's whole life: the first non-zero resize
// reserves it, every later call resizes it in place, and a refused resize leaves
// the previous reservation in force because the ledger books the candidate while
// the old charges are still held (its peak rule). Booking happens when the
// snapshot cache commits, so the reservation may exceed the live set until the
// next commit: that is deliberate over-accounting in the safe direction.
//
// The sender calls resize from ensureOutbound while NOT holding sender.mu: it
// unlocks before the FactStore call. The single outbound sender worker
// (network.refreshFactSenders -> factRuntime.pumpSenders -> ensureOutbound) is
// the only caller of resize, and this budget only ever takes the allocator's own
// leaf mutex, so the lock chain is budget.Allocator.mu as a leaf: the ledger runs
// no callback and takes no other lock under that mutex, and nothing that holds it
// ever waits on sender.mu or network.mu. No cycle exists. release runs on the
// Network teardown path once every worker stopped, so the lease field needs no
// lock of its own.
type factSenderBudget struct {
	network *network
	lease   *budget.Lease
}

// newFactSenderBudget returns the port for one Network's outbound sender. The
// allocator is resolved from the Network on every call, exactly like
// reserveState, so the port is correct even though the Network publishes its
// ledger only after the FACT runtime has been constructed.
func newFactSenderBudget(n *network) *factSenderBudget {
	return &factSenderBudget{network: n}
}

// resize books want bytes as CategoryState against the Network pool, replacing
// this sender's previous reservation. A refusal (heap exhausted, allocator
// closed, no allocator) returns false and leaves the previous reservation in
// force; the caller then defers the rebuild, a Debug-logged soft deferral. A
// refusal does NOT fail a Link or a Session and does NOT return ErrFactTooLarge.
func (b *factSenderBudget) resize(want int64) bool {
	if b == nil || b.network == nil {
		return true
	}
	if want <= 0 {
		b.release()
		return true
	}
	if b.lease == nil {
		lease, err := b.network.reserveState(uint64(want))
		if err != nil {
			slog.Default().Debug("FACT sender reservation refused", "phase", "facts", "error", err)
			return false
		}
		b.lease = lease
		return true
	}
	alloc := b.network.stateBudgetPtr()
	if alloc == nil {
		slog.Default().Debug("FACT sender reservation resize refused", "phase", "facts",
			"error", "network state allocator is not available")
		return false
	}
	if err := alloc.Resize(b.lease, budget.Request{Charges: []budget.Charge{{
		Owner:    budget.NetworkPool(budget.NetworkID(b.network.networkContext.WireID())),
		Category: budget.CategoryState,
		Bytes:    uint64(want),
	}}}); err != nil {
		slog.Default().Debug("FACT sender reservation resize refused", "phase", "facts", "error", err)
		return false
	}
	return true
}

// release drops the sender's reservation. It is idempotent and safe after the
// allocator closed, which returns the lease to the ledger's leak accounting
// instead of leaving it outstanding.
func (b *factSenderBudget) release() {
	if b == nil || b.lease == nil {
		return
	}
	lease := b.lease
	b.lease = nil
	b.network.releaseState(lease)
}
