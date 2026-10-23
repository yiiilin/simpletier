package simpletier

import (
	"log/slog"

	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/topology"
)

// factStateBudget adapts the shared internal/budget Allocator onto the topology
// package's StateBudget port, so every byte a FactStore owns is booked as
// CategoryState against the Network's one 256 MiB heap instead of only the
// store's private 32 MiB ceiling. It holds exactly one reservation for the
// store's whole life: the first ResizeState reserves it, every later call
// resizes it in place, and a refused resize leaves the previous reservation in
// force because the ledger books the candidate while the old charges are still
// held (its peak rule, which mirrors the store's own factStorePeakBytes).
//
// The store calls both methods with its own mutex held (the booking happens in
// finalise, immediately before the durable write and the publish). They only
// ever take the allocator's own leaf mutex, so the lock chain is
// FactStore.mu -> budget.Allocator.mu: the ledger runs no callback and takes no
// other lock under that mutex, and nothing that holds it ever waits on
// FactStore.mu or network.mu. No cycle exists.
type factStateBudget struct {
	network *network
	lease   *budget.Lease
}

var _ topology.StateBudget = (*factStateBudget)(nil)

// newFactStateBudget returns the port for one Network's FactStore. The allocator
// is resolved from the Network on every call, exactly like reserveState, so the
// port is correct even though the Network publishes its ledger only after the
// FactStore has been constructed.
func newFactStateBudget(n *network) *factStateBudget {
	return &factStateBudget{network: n}
}

// ResizeState books want bytes of FACT state as CategoryState against the
// Network pool, replacing this store's previous reservation. A refusal (heap
// exhausted, allocator closed, no allocator) is reported as false and leaves the
// previous reservation in force; the store then refuses to publish with
// ErrFactTooLarge rather than publishing unaccounted state.
func (b *factStateBudget) ResizeState(want uint64) bool {
	if b == nil || b.network == nil {
		return true
	}
	if want == 0 {
		b.ReleaseState()
		return true
	}
	if b.lease == nil {
		lease, err := b.network.reserveState(want)
		if err != nil {
			slog.Default().Debug("FACT state reservation refused", "phase", "facts", "error", err)
			return false
		}
		b.lease = lease
		return true
	}
	alloc := b.network.stateBudgetPtr()
	if alloc == nil {
		slog.Default().Debug("FACT state reservation resize refused", "phase", "facts",
			"error", "network state allocator is not available")
		return false
	}
	if err := alloc.Resize(b.lease, budget.Request{Charges: []budget.Charge{{
		Owner:    budget.NetworkPool(budget.NetworkID(b.network.networkContext.WireID())),
		Category: budget.CategoryState,
		Bytes:    want,
	}}}); err != nil {
		slog.Default().Debug("FACT state reservation resize refused", "phase", "facts", "error", err)
		return false
	}
	return true
}

// ReleaseState drops this store's reservation. It is idempotent and works after
// the allocator closed, which is the Network teardown order: the store releases
// last, once no publish can reserve again.
func (b *factStateBudget) ReleaseState() {
	if b == nil || b.lease == nil {
		return
	}
	lease := b.lease
	b.lease = nil
	b.network.releaseState(lease)
}
