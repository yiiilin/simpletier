package simpletier

import (
	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/circuit"
)

// testNetworkBudgetLimits optionally lowers the shared allocator limits of every
// Network built while it is set. It is a test seam only: production leaves it
// nil, and a test that sets it still gets the real allocator, the real ledger
// and the real Resource refusal path - only the frozen ceiling is lowered so a
// handful of circuits can exhaust it deterministically.
var testNetworkBudgetLimits *budget.Limits

// circuitBufferBudget adapts the shared internal/budget Allocator onto the
// circuit package's receiver-buffer port. It books one CategoryData charge (and
// one frame) per accepted reservation, so every receiver-owned Circuit buffer is
// counted in the Network's shared category and heap totals.
//
// ReserveData and Release run with circuit.Manager.mu held. They only touch the
// allocator's own leaf lock, perform no I/O and never call back into the
// Manager, which is exactly the contract the port requires.
type circuitBufferBudget struct {
	alloc *budget.Allocator
	net   budget.NetworkID
}

// circuitBufferReservation is one accepted shared charge. Release is idempotent
// from the caller's point of view because the Manager releases it exactly once.
type circuitBufferReservation struct {
	lease *budget.Lease
}

func (r circuitBufferReservation) Release() {
	if r.lease != nil {
		_ = r.lease.Release()
	}
}

// ReserveData is all-or-none: on a nil error the returned Reservation holds one
// real *budget.Lease, and on any other result the ledger is unchanged.
func (b *circuitBufferBudget) ReserveData(bytes uint64) (circuit.Reservation, error) {
	if b == nil || b.alloc == nil || bytes == 0 {
		return circuitBufferReservation{}, nil
	}
	lease, err := b.alloc.Reserve(budget.Request{Charges: []budget.Charge{{
		Owner:    budget.NetworkPool(b.net),
		Category: budget.CategoryData,
		Bytes:    bytes,
		Frames:   1,
	}}})
	if err != nil {
		return nil, err
	}
	return circuitBufferReservation{lease: lease}, nil
}

var _ circuit.BufferBudget = (*circuitBufferBudget)(nil)
var _ circuit.Reservation = circuitBufferReservation{}
