// Package budget owns the SimpleTier P1 Network resource ledger: the one
// accounting point a packet buffer, control frame, or state allocation passes
// before it owns memory. It implements the frozen upper bounds of
// multiprotocol-overlay.md 3.8 (D-L3-007) and nothing else:
//
//   - one Network-owned heap total of 256 MiB over everything the Network
//     owns: data buffers, control, and state, each category counted once;
//   - category caps inside it: owned data buffers 64 MiB and the shared
//     control pool 8 MiB;
//   - per Link instance (LinkID, Epoch): queued data 4 MiB / 64 frames and
//     control reserve 256 KiB / 64 frames;
//   - every charge is complete wire bytes including the 4-byte length prefix,
//     plus a frame count.
//
// A request is a composite of charges and is all-or-none: Reserve, Resize and
// Transfer admit only when the peak (owned plus every candidate charge held at
// once) fits every pool and counter. Nothing is evicted and only Release lowers
// a counter. Close refuses new reservations; outstanding leases stay visible
// and releasable by the allocator that issued them. One sync.Mutex guards all
// state and no callback runs under it. Scope: this accounts caller-supplied
// estimates, not kernel, GC or whole-process memory, so wiring real buffers to
// these counters stays the runtime's job.
package budget

import (
	"errors"
	"fmt"
	"sync"
)

// FrameLengthPrefix is the 4-byte length prefix of every complete wire frame;
// every charged byte count must include it.
const FrameLengthPrefix uint64 = 4

// Frozen P1 upper bounds (multiprotocol-overlay.md 3.8, D-L3-007). Limits may
// only be lowered.
const (
	DefaultHeapBytes         uint64 = 256 << 20
	DefaultDataBytes         uint64 = 64 << 20
	DefaultControlBytes      uint64 = 8 << 20
	DefaultLinkDataBytes     uint64 = 4 << 20
	DefaultLinkDataFrames    uint64 = 64
	DefaultLinkControlBytes  uint64 = 256 << 10
	DefaultLinkControlFrames uint64 = 64
)

// unlimited marks a dimension the frozen table bounds only in aggregate.
const unlimited = ^uint64(0)

var (
	ErrResource = errors.New("budget: resource limit exceeded")
	ErrInvalid  = errors.New("budget: invalid reservation")
	ErrClosed   = errors.New("budget: allocator closed")
)

// Category is one accounted resource class; the zero value is invalid.
type Category uint8

const (
	CategoryData Category = iota + 1
	CategoryControl
	CategoryState
)

var catNames = [3]string{"data", "control", "state"}

// NetworkID identifies the Network a ledger accounts.
type NetworkID uint64

// LinkKey is the explicit identity of one physical Link instance; a new
// instance with the same LinkID but a new Epoch gets a fresh, empty account.
type LinkKey struct{ LinkID, Epoch uint64 }

// Owner names the pool a charge is booked to: the Network pool or one
// registered Link instance.
type Owner struct {
	Network NetworkID
	Link    LinkKey

	link bool
}

func NetworkPool(net NetworkID) Owner         { return Owner{Network: net} }
func LinkPool(net NetworkID, k LinkKey) Owner { return Owner{Network: net, Link: k, link: true} }

// Charge is one explicit byte and frame reservation booked to one owner.
type Charge struct {
	Owner         Owner
	Category      Category
	Bytes, Frames uint64
}

// Request is a composite, all-or-none reservation.
type Request struct{ Charges []Charge }

// Limits are the per-Network and per-Link upper bounds in force. HeapBytes is
// the frozen 256 MiB total of everything the Network owns: DataBytes and
// ControlBytes are the 64 MiB and 8 MiB category caps inside it and count once
// each, while state is bounded by HeapBytes alone. Every field is non-zero and
// no greater than its frozen default.
type Limits struct {
	HeapBytes, DataBytes, ControlBytes  uint64
	LinkDataBytes, LinkDataFrames       uint64
	LinkControlBytes, LinkControlFrames uint64
}

// DefaultLimits returns the frozen P1 upper bounds verbatim.
func DefaultLimits() Limits {
	return Limits{DefaultHeapBytes, DefaultDataBytes, DefaultControlBytes,
		DefaultLinkDataBytes, DefaultLinkDataFrames, DefaultLinkControlBytes, DefaultLinkControlFrames}
}

// Validate rejects a zero field and any value above the frozen default.
func (l Limits) Validate() error {
	names := [...]string{"HeapBytes", "DataBytes", "ControlBytes", "LinkDataBytes", "LinkDataFrames", "LinkControlBytes", "LinkControlFrames"}
	vals := [...]uint64{l.HeapBytes, l.DataBytes, l.ControlBytes, l.LinkDataBytes, l.LinkDataFrames, l.LinkControlBytes, l.LinkControlFrames}
	maxs := [...]uint64{DefaultHeapBytes, DefaultDataBytes, DefaultControlBytes, DefaultLinkDataBytes, DefaultLinkDataFrames, DefaultLinkControlBytes, DefaultLinkControlFrames}
	for i, v := range vals {
		if v == 0 || v > maxs[i] {
			return fmt.Errorf("%w: %s=%d outside (0,%d]", ErrInvalid, names[i], v, maxs[i])
		}
	}
	return nil
}

// account is the per-category byte and frame ledger. peakBytes is the high
// water mark of admitted ownership: because Resize and Transfer book the
// candidate before unbooking the old charges, it records old+candidate, the
// peak the request was admitted against, not just the committed total.
type account struct {
	bytes, frames uint64
	peakBytes     uint64
}

func (a *account) book(bytes, frames uint64) {
	a.bytes += bytes
	a.frames += frames
	if a.bytes > a.peakBytes {
		a.peakBytes = a.bytes
	}
}

// linkState is one registered Link instance. Its counters are keyed explicitly
// by (LinkID, Epoch), so dropping the instance never erases what it owns.
type linkState struct {
	acc     [3]account
	dropped bool
}

func (st *linkState) empty() bool {
	for i := range st.acc {
		if st.acc[i].bytes != 0 || st.acc[i].frames != 0 {
			return false
		}
	}
	return true
}

// Allocator is the ledger of one Network; one mutex makes every method safe for
// concurrent use. catCap/heapCap/linkCap/linkFrameCap mirror the validated
// Limits per dimension; the state category has no cap of its own, only the
// heap total, and pool/heap are the committed counters behind Stats.
type Allocator struct {
	mu           sync.Mutex
	net          NetworkID
	catCap       [2]uint64
	heapCap      uint64
	linkCap      [3]uint64
	linkFrameCap [3]uint64
	pool         [3]account
	heap         account
	links        map[LinkKey]*linkState
	leases       int
	rejected     uint64
	closed       bool
}

// New returns an allocator for net whose limits are already validated.
func New(net NetworkID, limits Limits) (*Allocator, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	return &Allocator{
		net: net, links: make(map[LinkKey]*linkState),
		catCap:       [2]uint64{limits.DataBytes, limits.ControlBytes},
		heapCap:      limits.HeapBytes,
		linkCap:      [3]uint64{limits.LinkDataBytes, limits.LinkControlBytes, unlimited},
		linkFrameCap: [3]uint64{limits.LinkDataFrames, limits.LinkControlFrames, unlimited},
	}, nil
}

// RegisterLink makes one physical Link instance current and chargeable. It is
// idempotent and never touches another (LinkID, Epoch) account.
func (a *Allocator) RegisterLink(key LinkKey) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	if st, ok := a.links[key]; ok {
		st.dropped = false
		return nil
	}
	a.links[key] = &linkState{}
	return nil
}

// DropLink marks one Link instance gone, idempotently. The account and every
// outstanding charge under the same (LinkID, Epoch) stay visible and
// releasable; a later instance with a new Epoch starts empty.
func (a *Allocator) DropLink(key LinkKey) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if st, ok := a.links[key]; ok {
		st.dropped = true
		if st.empty() {
			delete(a.links, key)
		}
	}
	return nil
}

// Reserve books every charge of req or none of them.
func (a *Allocator) Reserve(req Request) (*Lease, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.apply(nil, req.Charges)
}

// Resize replaces the lease's charges with req.Charges under the peak rule: old
// and candidate are both held for admission, so the caller keeps real headroom.
// On refusal the lease and the ledger are unchanged.
func (a *Allocator) Resize(l *Lease, req Request) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if l == nil {
		return fmt.Errorf("%w: nil lease", ErrInvalid)
	}
	_, err := a.apply(l, req.Charges)
	return err
}

// Transfer re-books the lease's charges to another owner under the same peak
// rule, so moving bytes between Link instances needs room in both.
func (a *Allocator) Transfer(l *Lease, to Owner) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if l == nil || l.a != a {
		return fmt.Errorf("%w: lease belongs to this allocator only", ErrInvalid)
	}
	charges := make([]Charge, 0, len(l.charges))
	for _, c := range l.charges {
		c.Owner = to
		charges = append(charges, c)
	}
	_, err := a.apply(l, charges)
	return err
}

// Release returns every charge of l. It is idempotent, works after Close, and
// only the allocator that issued the lease may release it.
func (a *Allocator) Release(l *Lease) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if l == nil || l.a != a {
		return fmt.Errorf("%w: lease belongs to this allocator only", ErrInvalid)
	}
	if l.released {
		return nil
	}
	for _, c := range l.charges {
		a.unbook(c)
	}
	l.released, l.charges = true, nil
	a.leases--
	return nil
}

// Close refuses every new reservation; outstanding leases stay visible and
// releasable until Release. It is idempotent.
func (a *Allocator) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	return nil
}

// apply validates, admits and commits one composite reservation with a.mu held.
// old is the lease being replaced, or nil for a fresh reservation.
func (a *Allocator) apply(old *Lease, charges []Charge) (*Lease, error) {
	if a.closed {
		return nil, ErrClosed
	}
	if old != nil && (old.a != a || old.released) {
		return nil, fmt.Errorf("%w: lease already released or foreign", ErrInvalid)
	}
	if err := a.admit(charges); err != nil {
		if errors.Is(err, ErrResource) {
			a.rejected++
		}
		return nil, err
	}
	// Book the candidate first. While the old charges are still booked the
	// ledger owns old+candidate, the peak this request was admitted against,
	// and book records that as the high-water mark.
	for _, c := range charges {
		a.book(c)
	}
	if old == nil {
		a.leases++
		return &Lease{a: a, charges: append([]Charge(nil), charges...)}, nil
	}
	for _, c := range old.charges {
		a.unbook(c)
	}
	old.charges = append([]Charge(nil), charges...)
	return old, nil
}

// admit validates every charge and admits the whole composite only if the peak
// (owned plus all candidate charges) fits every pool and counter.
func (a *Allocator) admit(charges []Charge) error {
	if len(charges) == 0 {
		return fmt.Errorf("%w: empty request", ErrInvalid)
	}
	var netCand [3]account
	linkCand := make(map[LinkKey][3]account)
	for _, c := range charges {
		switch {
		case c.Category < CategoryData || c.Category > CategoryState:
			return fmt.Errorf("%w: unknown category %d", ErrInvalid, uint8(c.Category))
		case c.Bytes == 0 && c.Frames == 0:
			return fmt.Errorf("%w: charge owns no bytes and no frames", ErrInvalid)
		case c.Owner.Network != a.net:
			return fmt.Errorf("%w: charge for another Network", ErrInvalid)
		}
		i := int(c.Category) - 1
		if c.Owner.link {
			if st, ok := a.links[c.Owner.Link]; !ok || st.dropped {
				return fmt.Errorf("%w: link %d/%d is stale", ErrInvalid, c.Owner.Link.LinkID, c.Owner.Link.Epoch)
			}
			acc := linkCand[c.Owner.Link]
			if err := merge(&acc[i], i, c.Bytes, c.Frames, "link"); err != nil {
				return err
			}
			linkCand[c.Owner.Link] = acc
		}
		if err := merge(&netCand[i], i, c.Bytes, c.Frames, "network"); err != nil {
			return err
		}
	}
	// The 64 MiB data and 8 MiB control category caps are independent of the
	// heap total below.
	for i := range a.catCap {
		if !within(a.pool[i].bytes, netCand[i].bytes, a.catCap[i]) {
			return resErr("network %s bytes over limit", catNames[i])
		}
	}
	// The 256 MiB Network-owned heap bounds Data+Control+State together, each
	// category once. The sum is checked, so a wrapped total fails closed; that
	// also subsumes every per-category frame-overflow case.
	var heapCand account
	for i := range netCand {
		if err := merge(&heapCand, i, netCand[i].bytes, netCand[i].frames, "heap"); err != nil {
			return err
		}
	}
	if !within(a.heap.bytes, heapCand.bytes, a.heapCap) || !within(a.heap.frames, heapCand.frames, unlimited) {
		return resErr("network heap over limit")
	}
	for k, cand := range linkCand {
		st := a.links[k]
		for i := range st.acc {
			if !within(st.acc[i].bytes, cand[i].bytes, a.linkCap[i]) {
				return resErr("link %d/%d %s bytes over limit", k.LinkID, k.Epoch, catNames[i])
			}
			if !within(st.acc[i].frames, cand[i].frames, a.linkFrameCap[i]) {
				return resErr("link %d/%d %s frames over limit", k.LinkID, k.Epoch, catNames[i])
			}
		}
	}
	return nil
}

// merge adds one candidate's bytes and frames to an account with checked adds,
// so a wrapped aggregate is a resource failure instead of a silent truncation.
func merge(acc *account, cat int, bytes, frames uint64, scope string) error {
	b, okB := addChecked(acc.bytes, bytes)
	f, okF := addChecked(acc.frames, frames)
	if !okB || !okF {
		return resErr("%s %s overflow", scope, catNames[cat])
	}
	acc.bytes, acc.frames = b, f
	return nil
}

func (a *Allocator) book(c Charge) {
	i := int(c.Category) - 1
	a.pool[i].book(c.Bytes, c.Frames)
	a.heap.book(c.Bytes, c.Frames)
	if st, ok := a.links[c.Owner.Link]; c.Owner.link && ok {
		st.acc[i].book(c.Bytes, c.Frames)
	}
}

func (a *Allocator) unbook(c Charge) {
	i := int(c.Category) - 1
	a.pool[i].bytes -= c.Bytes
	a.pool[i].frames -= c.Frames
	a.heap.bytes -= c.Bytes
	a.heap.frames -= c.Frames
	st, ok := a.links[c.Owner.Link]
	if !c.Owner.link || !ok {
		return
	}
	st.acc[i].bytes -= c.Bytes
	st.acc[i].frames -= c.Frames
	if st.dropped && st.empty() {
		delete(a.links, c.Owner.Link)
	}
}

// Lease is an accepted composite reservation; release it through its issuing
// allocator, every other path is refused.
type Lease struct {
	a        *Allocator
	charges  []Charge
	released bool
}

// Release returns the lease to its allocator. It is idempotent.
func (l *Lease) Release() error {
	if l == nil {
		return fmt.Errorf("%w: nil lease", ErrInvalid)
	}
	return l.a.Release(l)
}

// CategoryStats reports one category's owned and high-water bytes and frames.
type CategoryStats struct{ Bytes, Frames, PeakBytes uint64 }

// Stats is a snapshot. Data/Control/State are the per-category counters; Heap
// is their aggregate, the quantity the frozen 256 MiB bounds, current and peak.
// Leaked* is everything still owned after Close, which only a late Release
// returns; Rejected counts requests refused with ErrResource; the bytes are
// caller estimates, never whole-process figures.
type Stats struct {
	Data, Control, State, Heap          CategoryStats
	LeakedBytes, LeakedFrames, Rejected uint64
	Leases, Links                       int
	Closed                              bool
}

// Stats snapshots the ledger.
func (a *Allocator) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Stats{
		Data:     CategoryStats{a.pool[0].bytes, a.pool[0].frames, a.pool[0].peakBytes},
		Control:  CategoryStats{a.pool[1].bytes, a.pool[1].frames, a.pool[1].peakBytes},
		State:    CategoryStats{a.pool[2].bytes, a.pool[2].frames, a.pool[2].peakBytes},
		Heap:     CategoryStats{a.heap.bytes, a.heap.frames, a.heap.peakBytes},
		Rejected: a.rejected, Leases: a.leases, Links: len(a.links), Closed: a.closed}
	if a.closed {
		s.LeakedBytes, s.LeakedFrames = a.heap.bytes, a.heap.frames
	}
	return s
}

// WireBytes reports the accounted bytes of frames complete wire frames of
// payload bytes each: frames*(payload+FrameLengthPrefix), checked so it can
// never wrap. This is the explicit estimate port for callers deriving charge
// sizes; the allocator never estimates on their behalf.
func WireBytes(frames, payload uint64) (uint64, error) {
	per, ok := addChecked(payload, FrameLengthPrefix)
	if !ok || (frames != 0 && per > ^uint64(0)/frames) {
		return 0, fmt.Errorf("%w: wire byte estimate overflow", ErrInvalid)
	}
	return frames * per, nil
}

// addChecked reports x+y, false when the unsigned sum wraps.
func addChecked(x, y uint64) (uint64, bool) {
	sum := x + y
	return sum, sum >= x
}

// within reports whether cur+add fits under cap, where a wrapped sum never fits.
func within(cur, add, cap uint64) bool {
	sum, ok := addChecked(cur, add)
	return ok && sum <= cap
}

func resErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrResource, fmt.Sprintf(format, args...))
}
