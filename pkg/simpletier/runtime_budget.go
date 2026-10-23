package simpletier

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/session"
)

// The two protector packages accept the same structural seam. These assertions
// pin that one value satisfies both, so the very same ledger can be injected
// into every hop protector and every directional E2E protector of a Network
// without an adapter and without either package importing the other.
var (
	_ link.VerificationBudget    = (*verificationBudget)(nil)
	_ session.VerificationBudget = (*verificationBudget)(nil)
)

// networkVerificationBudgetLimit is the frozen Network-lifetime ceiling on
// actual failed hop/E2E AEAD tag verifications. The internal Link and session
// packages already default each key to the same 1024 limit; this ledger is the
// aggregate across every Link and every directional E2E protector of one
// Network, so a peer cannot restart the count by forcing a rekey.
const networkVerificationBudgetLimit uint64 = 1024

// verificationBudget is the one Network-lifetime failed-tag ledger shared by
// every hop protector (internal/link.ProtectedControlIO) and every directional
// E2E protector (internal/session) of this Network. It has the structural shape
// both packages accept (`RecordFailure() bool`), so one value is injected into
// all of them and no per-Link ceiling can mask network-wide tag abuse.
//
// The counter is checked and saturating: it never wraps, never resets on a
// Stable key generation, and RecordFailure reports false (fail closed) at and
// beyond the ceiling. The ceiling callback runs at most once.
type verificationBudget struct {
	limit uint64
	count atomic.Uint64
	once  sync.Once
	// onCeiling is invoked exactly once when the limit is first reached. It must
	// not block on this ledger's own accounting path.
	onCeiling func()
}

// newVerificationBudget returns a Network-lifetime ledger. A zero limit resolves
// to the frozen default. onCeiling may be nil.
func newVerificationBudget(limit uint64, onCeiling func()) *verificationBudget {
	if limit == 0 {
		limit = networkVerificationBudgetLimit
	}
	return &verificationBudget{limit: limit, onCeiling: onCeiling}
}

// RecordFailure records one actually failed authentication tag and reports
// whether traffic may continue. It is safe for concurrent use and does no I/O
// beyond the one-shot ceiling callback.
func (b *verificationBudget) RecordFailure() bool {
	if b == nil {
		return true
	}
	for {
		current := b.count.Load()
		if current >= b.limit {
			b.trip()
			return false
		}
		if !b.count.CompareAndSwap(current, current+1) {
			continue
		}
		if current+1 >= b.limit {
			b.trip()
			return false
		}
		return true
	}
}

// trip fires the one-shot ceiling callback. A nil callback is a legal standalone
// ledger (local package tests); the count still saturates.
func (b *verificationBudget) trip() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		if b.onCeiling != nil {
			b.onCeiling()
		}
	})
}

// failed returns the current saturating count, never above the limit.
func (b *verificationBudget) failed() uint64 {
	if b == nil {
		return 0
	}
	return b.count.Load()
}

// verificationBudget returns the Network-lifetime aggregate failed-tag ledger of
// this Network. It is the getter the control pumps, the E2E protectors and the
// observable stats use; every caller shares this one value, so failures
// aggregate instead of restarting per Link or per key.
func (n *network) verificationBudget() *verificationBudget {
	if n == nil {
		return nil
	}
	return n.verification
}

// verificationStats reports the observable aggregate: the current saturating
// failed-tag count and its Network-lifetime limit. It is the honest figure —
// actual rejected hop/E2E tags — and is deliberately not the per-key policy's
// own Soft/Hard risk flags, which are reported separately by the Link usage
// snapshot and must not be conflated with the shared ledger.
func (n *network) verificationStats() (failed, limit uint64) {
	budget := n.verificationBudget()
	if budget == nil {
		return 0, 0
	}
	return budget.failed(), budget.limit
}

// stateBudgetPtr returns the shared Network allocator, or nil before the stream
// runtime published it. Callers must translate nil into an explicit resource
// failure; nothing is ever admitted unaccounted.
func (n *network) stateBudgetPtr() *budget.Allocator {
	if n == nil {
		return nil
	}
	return n.stateBudget.Load()
}

// reserveState books one Network-state estimate against the shared 256 MiB heap
// exactly once (CategoryState). The caller owns the returned lease and must
// Release it when the backing buffer is dropped, so the ledger returns to its
// baseline. A zero-byte request is a no-op returning (nil, nil).
//
// The estimate is a caller-supplied inclusive upper bound: this helper makes no
// claim about kernel, GC or whole-process memory. A nil/missing allocator is an
// explicit ErrResource, never a silent unaccounted admission.
func (n *network) reserveState(bytes uint64) (*budget.Lease, error) {
	if bytes == 0 {
		return nil, nil
	}
	if n == nil {
		return nil, fmt.Errorf("%w: no network for a state reservation", ErrResource)
	}
	alloc := n.stateBudgetPtr()
	if alloc == nil {
		return nil, fmt.Errorf("%w: network state allocator is not available", ErrResource)
	}
	lease, err := alloc.Reserve(budget.Request{Charges: []budget.Charge{{
		Owner:    budget.NetworkPool(budget.NetworkID(n.networkContext.WireID())),
		Category: budget.CategoryState,
		Bytes:    bytes,
	}}})
	if err != nil {
		return nil, fmt.Errorf("%w: state reservation of %d bytes: %v", ErrResource, bytes, err)
	}
	return lease, nil
}

// releaseState returns one state lease to the shared allocator. A nil lease and
// a late release after Close are both no-ops, so every cleanup path is
// idempotent.
func (n *network) releaseState(lease *budget.Lease) {
	if lease == nil {
		return
	}
	_ = lease.Release()
}

// pendingFrameMetadataBytes is the bounded fixed per-staged-frame state
// allowance for the ownership metadata of one pending inbound/relay frame: the
// pendingFrame record itself today and its slot in the per-Session pending
// slice, plus the slice's bounded capacity growth. It is charged once per
// staged ciphertext as CategoryState, so the metadata of the reorder buffer is
// inside the shared heap instead of riding unaccounted on the Data bytes. It is
// a documented inclusive upper-bound estimate of runtime-owned metadata, not a
// kernel, GC or whole-process measurement, and 64 frames per Session keeps the
// worst case far below any frozen ceiling.
const pendingFrameMetadataBytes uint64 = 512

// reservePendingCiphertext books the one shared all-or-none reservation for a
// staged inbound or relayed SESSION ciphertext copy: the exact envelope and body
// bytes this path is about to copy, one frame, under the physical ingress Link
// instance, plus the bounded fixed ownership metadata of one pendingFrame.
//
// It must run BEFORE either slice is copied, from inside the pendMu critical
// section that appends the frame, so an admitted lease always has exactly one
// owner and a refused reservation never has a copy to unwind. Nothing here
// estimates on the caller's behalf: the byte counts are the caller's exact copy
// lengths.
//
// The composite is deliberately two charges, not three: a LinkPool charge is a
// strict refinement of the Network pool in this allocator (every charge is
// booked into its Network category pool and the heap AND, additionally, into the
// owning Link account), so ONE LinkPool data charge already covers both the
// 64 MiB Network Data pool and this Link's 4 MiB / 64 frame data bound and must
// not be duplicated as a separate NetworkPool data charge. The pendingFrame
// metadata is charged separately as Network state, so the ownership metadata can
// never hide inside the data bytes' allowance.
//
// A missing Network, allocator or ingress physical Link is an explicit
// ErrResource: a staged ciphertext is never admitted unaccounted, and a Link is
// never silently downgraded to a Network-only charge. The byte counts are the
// caller's exact copy lengths; nothing here estimates on their behalf.
func (n *network) reservePendingCiphertext(pump *controlPump, envelopeLen, bodyLen int) (*budget.Lease, error) {
	if envelopeLen < 0 || bodyLen < 0 {
		return nil, fmt.Errorf("%w: negative pending ciphertext length", ErrResource)
	}
	if n == nil {
		return nil, fmt.Errorf("%w: no network for a pending ciphertext reservation", ErrResource)
	}
	alloc := n.stateBudgetPtr()
	if alloc == nil {
		return nil, fmt.Errorf("%w: network budget allocator is not available", ErrResource)
	}
	if pump == nil || pump.network == nil {
		return nil, fmt.Errorf("%w: pending ciphertext without an ingress physical Link", ErrResource)
	}
	bytes := uint64(envelopeLen) + uint64(bodyLen)
	if bytes == 0 {
		return nil, fmt.Errorf("%w: a staged ciphertext owns no bytes", ErrResource)
	}
	net := budget.NetworkID(n.networkContext.WireID())
	lease, err := alloc.Reserve(budget.Request{Charges: []budget.Charge{
		{
			// The LinkPool owner is a strict refinement of the Network pool in
			// this allocator: admit() merges every charge into its Network
			// category pool and the heap, and additionally into the owning Link
			// account. So ONE LinkPool data charge already consumes the 64 MiB
			// Network Data pool and this Link's 4 MiB / 64 frame data bound
			// exactly once each; a second NetworkPool data charge would
			// double-charge the Network cap and the heap.
			Owner:    budget.LinkPool(net, pump.linkKey),
			Category: budget.CategoryData,
			Bytes:    bytes,
			Frames:   1,
		},
		{
			// The ownership metadata of the staged frame is state, not
			// ciphertext: charge it separately so a Data cap can never be escaped
			// by metadata.
			Owner:    budget.NetworkPool(net),
			Category: budget.CategoryState,
			Bytes:    pendingFrameMetadataBytes,
		},
	}})
	if err != nil {
		return nil, fmt.Errorf("%w: pending ciphertext reservation of %d bytes: %v", ErrResource, bytes, err)
	}
	return lease, nil
}

// Per-pump receive state. The CoreWire reader owns a fixed maximum frame buffer
// and a decode scratch buffer per pump (not per SDK hook); on top of that a
// maximum complete frame can be simultaneously retained as the raw read body,
// the hop-opened plaintext and the inner E2E-opened plaintext while a decode is
// in flight, so the conservative allowance counts three maximum-frame arrays
// plus fixed metadata. These are documented inclusive upper-bound estimates of
// arrays this Network owns, not kernel, GC or whole-process measurements.
const (
	// pumpRecvMaxFrameBytes is 4-byte length prefix + a 65535-byte payload + a
	// frame-kind byte + the outer tag, rounded up.
	pumpRecvMaxFrameBytes    uint64 = 66 << 10
	pumpRecvFrameAllowance   uint64 = 3 * pumpRecvMaxFrameBytes
	pumpRecvScratchAllowance uint64 = 8 << 10
)

// reservePumpRecvState books the fixed receive-state allowance of one control
// pump. It fails closed: a Network without a shared allocator refuses the pump
// instead of running unaccounted.
func (n *network) reservePumpRecvState() (*budget.Lease, error) {
	return n.reserveState(pumpRecvFrameAllowance + pumpRecvScratchAllowance)
}

// registerPhysicalLinkKey makes one physical Link instance chargeable under its
// exact (LinkID, Epoch). It is called before the pump can enqueue anything.
func (n *network) registerPhysicalLinkKey(linkID, epoch uint64) error {
	alloc := n.stateBudgetPtr()
	if alloc == nil {
		return fmt.Errorf("%w: physical Link budget allocator is not available", ErrResource)
	}
	if err := alloc.RegisterLink(budget.LinkKey{LinkID: linkID, Epoch: epoch}); err != nil {
		return fmt.Errorf("%w: register physical Link %d/%d: %v", ErrResource, linkID, epoch, err)
	}
	return nil
}

// dropPhysicalLinkKey marks one physical Link instance gone. Outstanding leases
// stay visible and releasable by their owner; a later instance with a new Epoch
// starts empty.
func (n *network) dropPhysicalLinkKey(linkID, epoch uint64) {
	if n == nil {
		return
	}
	if alloc := n.stateBudgetPtr(); alloc != nil {
		_ = alloc.DropLink(budget.LinkKey{LinkID: linkID, Epoch: epoch})
	}
}
