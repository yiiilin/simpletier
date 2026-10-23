package budget

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	netA NetworkID = 1
	netB NetworkID = 2
)

func newTestAllocator(t *testing.T, net NetworkID) *Allocator {
	t.Helper()
	a, err := New(net, DefaultLimits())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func mustRegister(t *testing.T, a *Allocator, key LinkKey) Owner {
	t.Helper()
	if err := a.RegisterLink(key); err != nil {
		t.Fatalf("RegisterLink(%+v): %v", key, err)
	}
	return LinkPool(a.net, key)
}

// linkAccount reads one Link instance's counters without going through Stats.
func linkAccount(a *Allocator, key LinkKey) ([3]account, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.links[key]
	if !ok {
		return [3]account{}, false
	}
	return st.acc, true
}

func wantInvalid(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("%s: want ErrInvalid, got %v", what, err)
	}
}

func wantResource(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrResource) {
		t.Fatalf("%s: want ErrResource, got %v", what, err)
	}
}

// heldState drops the Rejected diagnostic counter so two snapshots can be
// compared for "every owned byte and frame is unchanged".
func heldState(s Stats) Stats {
	s.Rejected = 0
	return s
}

// TestFrozenBudgetsMatchSpec pins every default to the multiprotocol-overlay.md
// 3.8 table. A change here is a spec change, not a code change.
func TestFrozenBudgetsMatchSpec(t *testing.T) {
	if DefaultHeapBytes != 256<<20 || DefaultDataBytes != 64<<20 || DefaultControlBytes != 8<<20 {
		t.Fatalf("network limits: %d %d %d", DefaultHeapBytes, DefaultDataBytes, DefaultControlBytes)
	}
	if DefaultLinkDataBytes != 4<<20 || DefaultLinkDataFrames != 64 {
		t.Fatalf("link data: %d bytes %d frames", DefaultLinkDataBytes, DefaultLinkDataFrames)
	}
	if DefaultLinkControlBytes != 256<<10 || DefaultLinkControlFrames != 64 {
		t.Fatalf("link control: %d bytes %d frames", DefaultLinkControlBytes, DefaultLinkControlFrames)
	}
	if FrameLengthPrefix != 4 {
		t.Fatalf("prefix = %d", FrameLengthPrefix)
	}
	// HeapBytes is the frozen 256 MiB Network-owned total; DataBytes and
	// ControlBytes are the category caps inside it.
	if got := DefaultLimits(); got != (Limits{256 << 20, 64 << 20, 8 << 20, 4 << 20, 64, 256 << 10, 64}) {
		t.Fatalf("DefaultLimits = %+v", got)
	}
	// The exact 4 MiB / 64 frame link data queue only holds max frames when
	// every payload is 65,532 bytes: 64*(65532+4) == 4 MiB.
	wire, err := WireBytes(DefaultLinkDataFrames, 65532)
	if err != nil || wire != DefaultLinkDataBytes {
		t.Fatalf("WireBytes(64,65532) = %d,%v", wire, err)
	}
}

func TestLimitsMayOnlyLower(t *testing.T) {
	if err := DefaultLimits().Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	if _, err := New(netA, Limits{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero limits: want ErrInvalid, got %v", err)
	}
	raised := DefaultLimits()
	raised.DataBytes = DefaultDataBytes + 1
	if _, err := New(netA, raised); !errors.Is(err, ErrInvalid) {
		t.Fatalf("raised DataBytes: want ErrInvalid, got %v", err)
	}
	raised = DefaultLimits()
	raised.HeapBytes = DefaultHeapBytes + 1
	if _, err := New(netA, raised); !errors.Is(err, ErrInvalid) {
		t.Fatalf("raised HeapBytes: want ErrInvalid, got %v", err)
	}
	raised = DefaultLimits()
	raised.LinkDataFrames = DefaultLinkDataFrames + 1
	if _, err := New(netA, raised); !errors.Is(err, ErrInvalid) {
		t.Fatalf("raised LinkDataFrames: want ErrInvalid, got %v", err)
	}
	raised = DefaultLimits()
	raised.LinkControlBytes = DefaultLinkControlBytes + 1
	if _, err := New(netA, raised); !errors.Is(err, ErrInvalid) {
		t.Fatalf("raised LinkControlBytes: want ErrInvalid, got %v", err)
	}
	lowered := DefaultLimits()
	lowered.DataBytes, lowered.LinkDataBytes = 1<<20, 1<<20
	a, err := New(netA, lowered)
	if err != nil {
		t.Fatalf("lowered limits must be accepted: %v", err)
	}
	key := LinkKey{LinkID: 1, Epoch: 1}
	owner := mustRegister(t, a, key)
	if _, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, 1 << 20, 1}}}); err != nil {
		t.Fatalf("lowered cap reserve: %v", err)
	}
	if _, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, 1, 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("past lowered cap: want ErrResource, got %v", err)
	}
}

func TestWireBytesCountsPrefix(t *testing.T) {
	if n, err := WireBytes(1, 0); err != nil || n != 4 {
		t.Fatalf("one empty frame must count the 4-byte prefix, got %d,%v", n, err)
	}
	if n, err := WireBytes(0, 1<<40); err != nil || n != 0 {
		t.Fatalf("zero frames: %d,%v", n, err)
	}
	if _, err := WireBytes(math.MaxUint64, math.MaxUint64); !errors.Is(err, ErrInvalid) {
		t.Fatalf("byte overflow: want ErrInvalid, got %v", err)
	}
	if _, err := WireBytes(2, math.MaxUint64-3); !errors.Is(err, ErrInvalid) {
		t.Fatalf("prefix overflow: want ErrInvalid, got %v", err)
	}
}

// TestCompositeAllOrNone requires that a request with one unsatisfiable charge
// books nothing at all.
func TestCompositeAllOrNone(t *testing.T) {
	a := newTestAllocator(t, netA)
	key := LinkKey{LinkID: 7, Epoch: 3}
	owner := mustRegister(t, a, key)
	good := Charge{owner, CategoryData, 1 << 20, 4}
	bad := Charge{owner, CategoryData, DefaultLinkDataBytes + 1, 1}
	if _, err := a.Reserve(Request{Charges: []Charge{good, bad}}); !errors.Is(err, ErrResource) {
		t.Fatalf("want ErrResource, got %v", err)
	}
	s := a.Stats()
	if s.Data.Bytes != 0 || s.Data.Frames != 0 || s.Leases != 0 {
		t.Fatalf("refused composite booked state: %+v", s)
	}
	if s.Rejected != 1 {
		t.Fatalf("Rejected = %d, want 1", s.Rejected)
	}
	if acc, ok := linkAccount(a, key); !ok || acc[0] != (account{}) {
		t.Fatalf("refused composite touched the link account: %+v", acc)
	}
	// The same composite with the bad charge removed must succeed whole.
	other := mustRegister(t, a, LinkKey{LinkID: 8, Epoch: 1})
	state := Charge{NetworkPool(netA), CategoryState, 1 << 20, 2}
	l, err := a.Reserve(Request{Charges: []Charge{good, state, {other, CategoryControl, 1024, 1}}})
	if err != nil {
		t.Fatalf("composite: %v", err)
	}
	s = a.Stats()
	if s.Data.Bytes != 1<<20 || s.Data.Frames != 4 || s.State.Bytes != 1<<20 || s.State.Frames != 2 || s.Control.Bytes != 1024 || s.Control.Frames != 1 {
		t.Fatalf("composite booking wrong: %+v", s)
	}
	if s.Leases != 1 {
		t.Fatalf("Leases = %d", s.Leases)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if s = a.Stats(); s.Data.Bytes|s.State.Bytes|s.Control.Bytes|uint64(s.Leases) != 0 {
		t.Fatalf("release left state: %+v", s)
	}
}

// TestExactLinkDataBound probes the 64 frame / 4 MiB link bound to the byte.
func TestExactLinkDataBound(t *testing.T) {
	mk := func() (*Allocator, Owner) {
		a := newTestAllocator(t, netA)
		key := LinkKey{LinkID: 1, Epoch: 1}
		return a, mustRegister(t, a, key)
	}
	a, owner := mk()
	exact := Charge{owner, CategoryData, DefaultLinkDataBytes, DefaultLinkDataFrames}
	l, err := a.Reserve(Request{Charges: []Charge{exact}})
	if err != nil {
		t.Fatalf("exact 4 MiB / 64 frames: %v", err)
	}
	release(t, l)

	for _, tc := range []struct {
		name  string
		bytes uint64
		frame uint64
	}{
		{"one byte past 4 MiB", DefaultLinkDataBytes + 1, 1},
		{"65 frames", 65 * 4, 65},
		{"prefix pushes the byte count over", DefaultLinkDataBytes + FrameLengthPrefix, DefaultLinkDataFrames},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, owner := mk()
			_, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, tc.bytes, tc.frame}}})
			wantResource(t, tc.name, err)
			if s := a.Stats(); s.Data.Bytes != 0 {
				t.Fatalf("refusal booked %d bytes", s.Data.Bytes)
			}
		})
	}
}

// TestControlNotCarvedUnlimitedPerLink proves the per-Link 256 KiB reserve is a
// cap, not a guarantee: one Link cannot hold 8 MiB, and the shared Network
// control pool binds at 32 full reserves.
func TestControlNotCarvedUnlimitedPerLink(t *testing.T) {
	a := newTestAllocator(t, netA)
	one := mustRegister(t, a, LinkKey{LinkID: 100, Epoch: 1})
	if _, err := a.Reserve(Request{Charges: []Charge{{one, CategoryControl, DefaultControlBytes, 64}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("one Link holding the whole shared pool: want ErrResource, got %v", err)
	}
	leases := make([]*Lease, 0, 32)
	for i := 0; i < 32; i++ {
		owner := mustRegister(t, a, LinkKey{LinkID: uint64(i), Epoch: 1})
		l, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryControl, DefaultLinkControlBytes, DefaultLinkControlFrames}}})
		if err != nil {
			t.Fatalf("link %d full control reserve: %v", i, err)
		}
		leases = append(leases, l)
	}
	if s := a.Stats(); s.Control.Bytes != DefaultControlBytes || s.Control.Frames != 32*DefaultLinkControlFrames {
		t.Fatalf("32 full reserves should reach the shared pool exactly: %+v", s.Control)
	}
	over := mustRegister(t, a, LinkKey{LinkID: 999, Epoch: 1})
	if _, err := a.Reserve(Request{Charges: []Charge{{over, CategoryControl, 1, 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("shared control pool must bind: want ErrResource, got %v", err)
	}
	// Control frames are not silently dropped by a byte failure: the exact
	// per-Link frame bound is enforced independently of bytes.
	a2 := newTestAllocator(t, netA)
	small := mustRegister(t, a2, LinkKey{LinkID: 1, Epoch: 1})
	if _, err := a2.Reserve(Request{Charges: []Charge{{small, CategoryControl, 1, DefaultLinkControlFrames + 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("control frame bound: want ErrResource, got %v", err)
	}
	for _, l := range leases {
		release(t, l)
	}
}

// TestNetworkPoolsAggregate verifies the Network pools bind across Links.
func TestNetworkPoolsAggregate(t *testing.T) {
	a := newTestAllocator(t, netA)
	leases := make([]*Lease, 0, 16)
	for i := 0; i < 16; i++ {
		owner := mustRegister(t, a, LinkKey{LinkID: uint64(i), Epoch: 1})
		l, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, DefaultLinkDataBytes, DefaultLinkDataFrames}}})
		if err != nil {
			t.Fatalf("link %d: %v", i, err)
		}
		leases = append(leases, l)
	}
	if s := a.Stats(); s.Data.Bytes != DefaultDataBytes || s.Data.PeakBytes != DefaultDataBytes {
		t.Fatalf("16 x 4 MiB should fill the data pool: %+v", s.Data)
	}
	over := mustRegister(t, a, LinkKey{LinkID: 77, Epoch: 1})
	if _, err := a.Reserve(Request{Charges: []Charge{{over, CategoryData, 1, 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("data pool must bind: got %v", err)
	}
	// State is Network-owned: it has no cap of its own or per Link, only the
	// 256 MiB heap total, and state frame counts have no invented cap.
	big := mustRegister(t, a, LinkKey{LinkID: 78, Epoch: 1})
	l, err := a.Reserve(Request{Charges: []Charge{{big, CategoryState, DefaultHeapBytes - DefaultDataBytes, 1 << 40}}})
	if err != nil {
		t.Fatalf("state pool: %v", err)
	}
	if s := a.Stats(); s.State.Bytes != DefaultHeapBytes-DefaultDataBytes || s.State.Frames != 1<<40 || s.Heap.Bytes != DefaultHeapBytes {
		t.Fatalf("state booking: %+v heap %+v", s.State, s.Heap)
	}
	if _, err := a.Reserve(Request{Charges: []Charge{{big, CategoryState, 1, 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("heap pool must bind at 256 MiB: got %v", err)
	}
	release(t, l)
	for _, l := range leases {
		release(t, l)
	}
}

// TestHeapAggregateCoversAllCategories pins the frozen 256 MiB row as the
// Network-owned heap: Data+Control+State counted once each, with Data 64 MiB
// and Control 8 MiB still independent category caps.
func TestHeapAggregateCoversAllCategories(t *testing.T) {
	// 64 MiB data + 192 MiB state is exactly the 256 MiB heap. Data goes to the
	// Network pool: it has no per-Link cap, and the category/heap caps are what
	// this test is about.
	a := newTestAllocator(t, netA)
	net, owner := NetworkPool(netA), mustRegister(t, a, LinkKey{LinkID: 1, Epoch: 1})
	l, err := a.Reserve(Request{Charges: []Charge{
		{net, CategoryData, DefaultDataBytes, 1},
		{owner, CategoryState, DefaultHeapBytes - DefaultDataBytes, 1},
	}})
	if err != nil {
		t.Fatalf("64 MiB data + 192 MiB state: %v", err)
	}
	if s := a.Stats(); s.Heap.Bytes != DefaultHeapBytes || s.Heap.PeakBytes != DefaultHeapBytes {
		t.Fatalf("heap at the frozen total: %+v", s.Heap)
	}
	// One control byte more cannot fit, and the refusal changes nothing.
	before := a.Stats()
	if _, err := a.Reserve(Request{Charges: []Charge{{net, CategoryControl, 1, 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("heap must bind above 256 MiB: got %v", err)
	}
	if after := a.Stats(); heldState(after) != heldState(before) {
		t.Fatalf("refusal changed the ledger:\nbefore %+v\nafter  %+v", before, after)
	}
	// Shrink and same-size Resize still need old+candidate heap headroom.
	if err := a.Resize(l, Request{Charges: []Charge{{net, CategoryData, DefaultDataBytes, 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("heap peak must include old+candidate: got %v", err)
	}
	if after := a.Stats(); heldState(after) != heldState(before) {
		t.Fatalf("refused resize changed the ledger:\nbefore %+v\nafter  %+v", before, after)
	}
	// Control 8 MiB + data 64 MiB + state 184 MiB is also exactly 256 MiB.
	b := newTestAllocator(t, netA)
	netB, ownerB := NetworkPool(netA), mustRegister(t, b, LinkKey{LinkID: 1, Epoch: 1})
	if _, err := b.Reserve(Request{Charges: []Charge{
		{netB, CategoryControl, DefaultControlBytes, 1},
		{netB, CategoryData, DefaultDataBytes, 1},
		{ownerB, CategoryState, DefaultHeapBytes - DefaultControlBytes - DefaultDataBytes, 1},
	}}); err != nil {
		t.Fatalf("8 MiB control + 64 MiB data + 184 MiB state: %v", err)
	}
	if s := b.Stats(); s.Heap.Bytes != DefaultHeapBytes || s.Control.Bytes != DefaultControlBytes {
		t.Fatalf("heap with control: %+v", s.Heap)
	}
	if _, err := b.Reserve(Request{Charges: []Charge{{ownerB, CategoryState, 1, 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("heap must bind with control included: got %v", err)
	}
	// A category cap still binds on its own: 64 MiB + 1 data byte is refused
	// on an empty ledger, and so is 8 MiB + 1 control byte.
	c := newTestAllocator(t, netA)
	netC := NetworkPool(netA)
	if _, err := c.Reserve(Request{Charges: []Charge{{netC, CategoryData, DefaultDataBytes + 1, 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("data category cap: got %v", err)
	}
	if _, err := c.Reserve(Request{Charges: []Charge{{netC, CategoryControl, DefaultControlBytes + 1, 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("control category cap: got %v", err)
	}
	// An overflowing heap sum fails closed even though each category passes.
	// State has no category cap, so 1 data byte + MaxUint64 state bytes only
	// the checked Data+Control+State sum can reject.
	d := newTestAllocator(t, netA)
	netD, ownerD := NetworkPool(netA), mustRegister(t, d, LinkKey{LinkID: 1, Epoch: 1})
	if _, err := d.Reserve(Request{Charges: []Charge{
		{netD, CategoryData, 1, 1},
		{ownerD, CategoryState, math.MaxUint64, 1},
	}}); !errors.Is(err, ErrResource) {
		t.Fatalf("wrapped heap sum: want ErrResource, got %v", err)
	}
	if s := d.Stats(); s.Heap != (CategoryStats{}) || s.Data.Bytes != 0 || s.State.Bytes != 0 {
		t.Fatalf("wrapped heap sum booked state: %+v", s)
	}
}

// TestResizePeakAndRefusal pins the documented conservative peak: old and
// candidate are both held for admission, and a refusal leaves the old lease
// exactly as it was.
func TestResizePeakAndRefusal(t *testing.T) {
	a := newTestAllocator(t, netA)
	key := LinkKey{LinkID: 5, Epoch: 2}
	owner := mustRegister(t, a, key)
	l, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, 2 << 20, 32}}})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// Same size: peak 2+2 == 4 MiB fits the per-Link cap exactly, and the
	// admitted peak (old+candidate) is what Stats reports.
	if err := a.Resize(l, Request{Charges: []Charge{{owner, CategoryData, 2 << 20, 32}}}); err != nil {
		t.Fatalf("exact peak resize: %v", err)
	}
	if s := a.Stats(); s.Data.PeakBytes != DefaultLinkDataBytes {
		t.Fatalf("peak after resize = %d, want the admitted old+candidate %d", s.Data.PeakBytes, DefaultLinkDataBytes)
	}
	if acc, _ := linkAccount(a, key); acc[0].peakBytes != DefaultLinkDataBytes {
		t.Fatalf("link peak = %d", acc[0].peakBytes)
	}
	// One byte more: 2 MiB + (2 MiB + 1) exceeds the 4 MiB Link cap.
	if err := a.Resize(l, Request{Charges: []Charge{{owner, CategoryData, 2<<20 + 1, 32}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("over-peak resize: want ErrResource, got %v", err)
	}
	if acc, _ := linkAccount(a, key); acc[0].bytes != 2<<20 || acc[0].frames != 32 {
		t.Fatalf("refused resize changed the lease: %+v", acc[0])
	}
	if s := a.Stats(); s.Data.Bytes != 2<<20 || s.Data.Frames != 32 {
		t.Fatalf("refused resize changed the ledger: %+v", s)
	}
	// Shrinking through the Network state pool also needs old+candidate room:
	// 200 MiB -> 100 MiB peaks at 300 MiB > 256 MiB and is refused, so the
	// caller must release first.
	state := mustRegister(t, a, LinkKey{LinkID: 6, Epoch: 1})
	sl, err := a.Reserve(Request{Charges: []Charge{{state, CategoryState, 200 << 20, 1}}})
	if err != nil {
		t.Fatalf("state reserve: %v", err)
	}
	if err := a.Resize(sl, Request{Charges: []Charge{{state, CategoryState, 100 << 20, 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("shrinking resize peak: want ErrResource, got %v", err)
	}
	if s := a.Stats(); s.State.Bytes != 200<<20 {
		t.Fatalf("refused shrink changed state: %+v", s)
	}
	release(t, sl)
	if _, err := a.Reserve(Request{Charges: []Charge{{state, CategoryState, 100 << 20, 1}}}); err != nil {
		t.Fatalf("release then re-reserve: %v", err)
	}
	release(t, l)
}

// TestTransferPeakAndOwnerMove requires a transfer to move the counters to the
// explicit (LinkID, Epoch) key and to need room in both owners.
func TestTransferPeakAndOwnerMove(t *testing.T) {
	a := newTestAllocator(t, netA)
	k1, k2 := LinkKey{LinkID: 1, Epoch: 1}, LinkKey{LinkID: 2, Epoch: 1}
	o1, o2 := mustRegister(t, a, k1), mustRegister(t, a, k2)
	l1, err := a.Reserve(Request{Charges: []Charge{{o1, CategoryState, 150 << 20, 1}}})
	if err != nil {
		t.Fatalf("reserve l1: %v", err)
	}
	l2, err := a.Reserve(Request{Charges: []Charge{{o2, CategoryState, 100 << 20, 1}}})
	if err != nil {
		t.Fatalf("reserve l2: %v", err)
	}
	if err := a.Transfer(l1, o2); !errors.Is(err, ErrResource) {
		t.Fatalf("transfer past the Network pool: want ErrResource, got %v", err)
	}
	if acc, _ := linkAccount(a, k1); acc[2].bytes != 150<<20 {
		t.Fatalf("refused transfer moved l1: %+v", acc[2])
	}
	if acc, _ := linkAccount(a, k2); acc[2].bytes != 100<<20 {
		t.Fatalf("refused transfer touched l2: %+v", acc[2])
	}
	release(t, l2)
	// 150+150 still exceeds 256 MiB, so the conservative peak keeps refusing.
	if err := a.Transfer(l1, o2); !errors.Is(err, ErrResource) {
		t.Fatalf("transfer at half pool: want ErrResource, got %v", err)
	}
	release(t, l1)

	small, err := a.Reserve(Request{Charges: []Charge{{o1, CategoryState, 100 << 20, 1}}})
	if err != nil {
		t.Fatalf("reserve small: %v", err)
	}
	if err := a.Transfer(small, o2); err != nil {
		t.Fatalf("transfer 100 MiB: %v", err)
	}
	if acc, _ := linkAccount(a, k1); acc[2].bytes != 0 {
		t.Fatalf("source link kept %d state bytes", acc[2].bytes)
	}
	if acc, _ := linkAccount(a, k2); acc[2].bytes != 100<<20 {
		t.Fatalf("target link holds %d state bytes", acc[2].bytes)
	}
	if s := a.Stats(); s.State.Bytes != 100<<20 {
		t.Fatalf("transfer changed the Network total: %+v", s)
	}
	// The owner must be a live instance of this Network.
	if err := a.Transfer(small, NetworkPool(netB)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign Network transfer: want ErrInvalid, got %v", err)
	}
	release(t, small)
}

// TestCrossNetworkLeaseCannotRelease is the ownership check: a lease is only
// releasable, resizable or transferable by the allocator that issued it.
func TestCrossNetworkLeaseCannotRelease(t *testing.T) {
	a, b := newTestAllocator(t, netA), newTestAllocator(t, netB)
	owner := mustRegister(t, a, LinkKey{LinkID: 1, Epoch: 1})
	l, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, 1 << 20, 4}}})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	wantInvalid(t, "foreign release", b.Release(l))
	if s := a.Stats(); s.Data.Bytes != 1<<20 || s.Leases != 1 {
		t.Fatalf("foreign release touched the issuer: %+v", s)
	}
	wantInvalid(t, "foreign resize", b.Resize(l, Request{Charges: []Charge{{owner, CategoryData, 2 << 20, 4}}}))
	wantInvalid(t, "foreign transfer", b.Transfer(l, owner))
	if s := a.Stats(); s.Data.Bytes != 1<<20 || s.Leases != 1 {
		t.Fatalf("foreign ops touched the issuer: %+v", s)
	}
	// A charge for another Network is refused before anything is booked.
	foreign := LinkPool(netB, LinkKey{LinkID: 1, Epoch: 1})
	wantInvalid(t, "foreign charge", mustReserveErr(a, Request{Charges: []Charge{{foreign, CategoryData, 1, 1}}}))
	wantInvalid(t, "foreign network pool", mustReserveErr(a, Request{Charges: []Charge{{NetworkPool(netB), CategoryData, 1, 1}}}))
	// Only the issuer releases, idempotently.
	if err := a.Release(l); err != nil {
		t.Fatalf("issuer release: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
	if s := a.Stats(); s.Data.Bytes != 0 || s.Leases != 0 {
		t.Fatalf("release left state: %+v", s)
	}
	wantInvalid(t, "resize released", a.Resize(l, Request{Charges: []Charge{{owner, CategoryData, 1, 1}}}))
}

func mustReserveErr(a *Allocator, req Request) error {
	_, err := a.Reserve(req)
	return err
}

// TestCloseKeepsOutstandingLeases: Close refuses new admissions but every
// outstanding lease stays visible as Leaked -- all categories, all owners --
// resize/transfer stop, and a late release still returns the bytes.
func TestCloseKeepsOutstandingLeases(t *testing.T) {
	a := newTestAllocator(t, netA)
	key := LinkKey{LinkID: 1, Epoch: 1}
	owner := mustRegister(t, a, key)
	l, err := a.Reserve(Request{Charges: []Charge{
		{owner, CategoryData, 1 << 20, 8},
		{owner, CategoryControl, 256 << 10, 64},
		{owner, CategoryState, 3 << 20, 2},
	}})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	l2, err := a.Reserve(Request{Charges: []Charge{{NetworkPool(netA), CategoryState, 1 << 20, 1}}})
	if err != nil {
		t.Fatalf("reserve state: %v", err)
	}
	const (
		wantBytes  = 1<<20 + 256<<10 + 3<<20 + 1<<20
		wantFrames = 8 + 64 + 2 + 1
	)
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	s := a.Stats()
	if !s.Closed || s.LeakedBytes != wantBytes || s.LeakedFrames != wantFrames || s.Leases != 2 {
		t.Fatalf("closed snapshot: %+v, want %d bytes %d frames", s, wantBytes, wantFrames)
	}
	// Leaked is exactly the aggregate heap and the sum of the categories: what
	// every still-outstanding lease really holds.
	if s.LeakedBytes != s.Heap.Bytes || s.LeakedBytes != s.Data.Bytes+s.Control.Bytes+s.State.Bytes {
		t.Fatalf("Leaked is not the held total: %+v", s)
	}
	if s.Heap.Bytes != wantBytes || s.Data.Bytes != 1<<20 || s.Control.Bytes != 256<<10 || s.State.Bytes != 4<<20 {
		t.Fatalf("per-category counters: %+v", s)
	}
	if _, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, 1, 1}}}); !errors.Is(err, ErrClosed) {
		t.Fatalf("reserve after close: want ErrClosed, got %v", err)
	}
	if err := a.Resize(l, Request{Charges: []Charge{{owner, CategoryData, 2 << 20, 8}}}); !errors.Is(err, ErrClosed) {
		t.Fatalf("resize after close: want ErrClosed, got %v", err)
	}
	if err := a.Transfer(l, owner); !errors.Is(err, ErrClosed) {
		t.Fatalf("transfer after close: want ErrClosed, got %v", err)
	}
	if err := a.RegisterLink(LinkKey{LinkID: 2, Epoch: 1}); !errors.Is(err, ErrClosed) {
		t.Fatalf("register after close: want ErrClosed, got %v", err)
	}
	if after := a.Stats(); heldState(after) != heldState(s) {
		t.Fatalf("refused ops changed the closed ledger:\nwant %+v\ngot  %+v", s, after)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("late release: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("idempotent late release: %v", err)
	}
	if s := a.Stats(); s.LeakedBytes != 1<<20 || s.LeakedFrames != 1 || s.Leases != 1 {
		t.Fatalf("one lease still held: %+v", s)
	}
	if err := l2.Release(); err != nil {
		t.Fatalf("late release state: %v", err)
	}
	s = a.Stats()
	if s.Data.Bytes|s.Control.Bytes|s.State.Bytes|s.Heap.Bytes|s.LeakedBytes|s.LeakedFrames != 0 || s.Leases != 0 || !s.Closed {
		t.Fatalf("late release snapshot: %+v", s)
	}
}

// TestDropLinkKeepsOutstandingAndNewEpochIsFresh: dropping an instance must not
// erase its charges, and a new Epoch with the same LinkID starts empty.
func TestDropLinkKeepsOutstandingAndNewEpochIsFresh(t *testing.T) {
	a := newTestAllocator(t, netA)
	e1, e2 := LinkKey{LinkID: 4, Epoch: 1}, LinkKey{LinkID: 4, Epoch: 2}
	owner := mustRegister(t, a, e1)
	l, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, 1 << 20, 16}}})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := a.DropLink(e1); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if err := a.DropLink(e1); err != nil {
		t.Fatalf("idempotent drop: %v", err)
	}
	if err := a.DropLink(LinkKey{LinkID: 4, Epoch: 9}); err != nil {
		t.Fatalf("drop of unknown instance: %v", err)
	}
	if acc, ok := linkAccount(a, e1); !ok || acc[0].bytes != 1<<20 {
		t.Fatalf("drop erased the outstanding lease: ok=%v acc=%+v", ok, acc)
	}
	owner1 := LinkPool(netA, e1)
	if _, err := a.Reserve(Request{Charges: []Charge{{owner1, CategoryData, 1, 1}}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("charge to a dropped instance: want ErrInvalid, got %v", err)
	}
	owner2 := mustRegister(t, a, e2)
	full, err := a.Reserve(Request{Charges: []Charge{{owner2, CategoryData, DefaultLinkDataBytes, DefaultLinkDataFrames}}})
	if err != nil {
		t.Fatalf("new epoch must start empty: %v", err)
	}
	if s := a.Stats(); s.Data.Bytes != 1<<20+DefaultLinkDataBytes {
		t.Fatalf("network total across epochs: %+v", s)
	}
	if acc, _ := linkAccount(a, e2); acc[0].bytes != DefaultLinkDataBytes {
		t.Fatalf("new epoch inherited: %+v", acc[0])
	}
	// The dropped instance's lease still releases, and only then is the emptied
	// account collected.
	if err := a.Release(l); err != nil {
		t.Fatalf("late release after drop: %v", err)
	}
	if _, ok := linkAccount(a, e1); ok {
		t.Fatalf("emptied dropped account was not collected")
	}
	if s := a.Stats(); s.Data.Bytes != DefaultLinkDataBytes || s.Leases != 1 {
		t.Fatalf("after late release: %+v", s)
	}
	release(t, full)
}

func TestInvalidRequests(t *testing.T) {
	a := newTestAllocator(t, netA)
	owner := mustRegister(t, a, LinkKey{LinkID: 1, Epoch: 1})
	for _, tc := range []struct {
		name string
		req  Request
	}{
		{"empty", Request{}},
		{"unknown category", Request{Charges: []Charge{{owner, Category(9), 1, 1}}}},
		{"zero category", Request{Charges: []Charge{{owner, 0, 1, 1}}}},
		{"owns nothing", Request{Charges: []Charge{{owner, CategoryData, 0, 0}}}},
		{"unregistered link", Request{Charges: []Charge{{LinkPool(netA, LinkKey{LinkID: 42, Epoch: 1}), CategoryData, 1, 1}}}},
		{"foreign network", Request{Charges: []Charge{{NetworkPool(netB), CategoryData, 1, 1}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := a.Reserve(tc.req); !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
	if s := a.Stats(); s.Rejected != 0 || s.Data.Bytes != 0 {
		t.Fatalf("invalid requests must not count as rejected resources: %+v", s)
	}
	// Bytes-only and frames-only charges are both meaningful.
	if _, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, 1, 0}}}); err != nil {
		t.Fatalf("bytes-only charge: %v", err)
	}
	if _, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryControl, 0, 1}}}); err != nil {
		t.Fatalf("frames-only charge: %v", err)
	}
	wantInvalid(t, "nil resize", a.Resize(nil, Request{Charges: []Charge{{owner, CategoryData, 1, 1}}}))
	wantInvalid(t, "nil release", a.Release(nil))
	wantInvalid(t, "nil transfer", a.Transfer(nil, owner))
	var nilLease *Lease
	wantInvalid(t, "nil method release", nilLease.Release())
	if _, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, math.MaxUint64, 1}}}); !errors.Is(err, ErrResource) {
		t.Fatalf("byte overflow charge: want ErrResource, got %v", err)
	}
	if s := a.Stats(); s.Rejected != 1 {
		t.Fatalf("Rejected = %d, want 1 (only the overflow)", s.Rejected)
	}
}

func TestPeakTracksHighWater(t *testing.T) {
	a := newTestAllocator(t, netA)
	owner := mustRegister(t, a, LinkKey{LinkID: 1, Epoch: 1})
	l, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, 3 << 20, 3}}})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if s := a.Stats(); s.Data.PeakBytes != 3<<20 {
		t.Fatalf("peak: %+v", s.Data)
	}
	release(t, l)
	l2, err := a.Reserve(Request{Charges: []Charge{{owner, CategoryData, 1 << 20, 1}}})
	if err != nil {
		t.Fatalf("re-reserve: %v", err)
	}
	if s := a.Stats(); s.Data.Bytes != 1<<20 || s.Data.PeakBytes != 3<<20 {
		t.Fatalf("high-water must survive a release: %+v", s.Data)
	}
	release(t, l2)
	if s := a.Stats(); s.Data.Bytes != 0 || s.Data.PeakBytes != 3<<20 {
		t.Fatalf("final: %+v", s.Data)
	}
}

// TestConcurrentAllCapsAndOverflow hammers every pool at once: exactly the caps
// fill, the rest are refused, and an overflowing charge can never wrap a
// counter. Run with -race.
func TestConcurrentAllCapsAndOverflow(t *testing.T) {
	a := newTestAllocator(t, netA)
	const workers = 64
	var okCount, rejected int64
	leases := make([]*Lease, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := LinkKey{LinkID: uint64(i), Epoch: 1}
			if err := a.RegisterLink(key); err != nil {
				t.Errorf("register %d: %v", i, err)
				return
			}
			l, err := a.Reserve(Request{Charges: []Charge{
				{LinkPool(netA, key), CategoryData, DefaultLinkDataBytes, DefaultLinkDataFrames},
				{LinkPool(netA, key), CategoryControl, DefaultLinkControlBytes, DefaultLinkControlFrames},
			}})
			switch {
			case err == nil:
				leases[i] = l
				atomic.AddInt64(&okCount, 1)
			case errors.Is(err, ErrResource):
				atomic.AddInt64(&rejected, 1)
			default:
				t.Errorf("reserve %d: unexpected %v", i, err)
			}
		}(i)
	}
	const overflowers = 8
	for i := 0; i < overflowers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := a.Reserve(Request{Charges: []Charge{
				{NetworkPool(netA), CategoryData, math.MaxUint64, 1},
				{NetworkPool(netA), CategoryControl, math.MaxUint64, 1},
				{NetworkPool(netA), CategoryState, math.MaxUint64, 1},
			}})
			if !errors.Is(err, ErrResource) {
				t.Errorf("overflow charge: want ErrResource, got %v", err)
			}
		}()
	}
	wg.Wait()
	// 16 x 4 MiB is the whole data pool, so exactly 16 composites fit; the other
	// 48 fail on data, and the 8 overflowing requests fail on arithmetic.
	if okCount != 16 || rejected != workers-16 {
		t.Fatalf("ok=%d rejected=%d", okCount, rejected)
	}
	s := a.Stats()
	if s.Data.Bytes != DefaultDataBytes || s.Control.Bytes != 16*DefaultLinkControlBytes {
		t.Fatalf("caps: %+v", s)
	}
	if s.Data.Frames != 16*DefaultLinkDataFrames || s.Control.Frames != 16*DefaultLinkControlFrames {
		t.Fatalf("frames: %+v", s)
	}
	if s.Rejected != uint64(workers-16+overflowers) {
		t.Fatalf("Rejected = %d", s.Rejected)
	}
	// Every Link counter still matches the Network total: no composite was
	// half-applied and no charge was double-counted.
	var linkBytes, linkFrames uint64
	for i := 0; i < workers; i++ {
		if acc, ok := linkAccount(a, LinkKey{LinkID: uint64(i), Epoch: 1}); ok {
			for j := range acc {
				linkBytes += acc[j].bytes
				linkFrames += acc[j].frames
			}
		}
	}
	if linkBytes != s.Data.Bytes+s.Control.Bytes+s.State.Bytes {
		t.Fatalf("link bytes %d != network %d", linkBytes, s.Data.Bytes+s.Control.Bytes+s.State.Bytes)
	}
	if linkFrames != s.Data.Frames+s.Control.Frames+s.State.Frames {
		t.Fatalf("link frames %d != network %d", linkFrames, s.Data.Frames+s.Control.Frames+s.State.Frames)
	}
	for _, l := range leases {
		if l != nil {
			release(t, l)
		}
	}
	if s := a.Stats(); s.Data.Bytes|s.Control.Bytes|s.State.Bytes|s.Data.Frames|s.Control.Frames|s.State.Frames != 0 || s.Leases != 0 {
		t.Fatalf("release did not drain: %+v", s)
	}
}

func release(t *testing.T, l *Lease) {
	t.Helper()
	if err := l.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
}
