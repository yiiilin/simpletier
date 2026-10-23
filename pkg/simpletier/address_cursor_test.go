package simpletier

import (
	"math"
	"net/netip"
	"testing"
)

func TestUsableHostTotal(t *testing.T) {
	cases := []struct {
		cidr string
		want uint64
	}{
		{"10.0.0.0/24", 254},
		{"10.0.0.0/30", 2},
		{"10.0.0.0/31", 2},
		{"10.0.0.1/32", 1},
		{"10.0.0.0/16", 65534},
		{"10.0.0.0/8", 1<<24 - 2},
	}
	for _, tc := range cases {
		prefix := netip.MustParsePrefix(tc.cidr)
		if got := usableHostTotal(prefix); got != tc.want {
			t.Fatalf("usableHostTotal(%s) = %d; want %d", tc.cidr, got, tc.want)
		}
	}
	if got := usableHostTotal(netip.Prefix{}); got != 0 {
		t.Fatalf("usableHostTotal(invalid) = %d; want 0", got)
	}
}

// TestChooseProvisionalVirtualIPYieldsAndResumes proves one chunk is bounded and
// that a budget-exhausted search returns a positive resume cursor instead of
// declaring exhaustion or doing unbounded work.
func TestChooseProvisionalVirtualIPYieldsAndResumes(t *testing.T) {
	prefix := netip.MustParsePrefix("10.77.0.0/24")
	nodeID := [16]byte{0x42}
	var first, second, third netip.Addr
	for attempt, target := range map[uint32]*netip.Addr{1: &first, 2: &second, 3: &third} {
		candidate, err := provisionalVirtualIP(prefix, nodeID, attempt)
		if err != nil {
			t.Fatalf("provisionalVirtualIP(%d): %v", attempt, err)
		}
		*target = candidate
	}
	skip := map[netip.Addr]struct{}{first: {}, second: {}}

	chosen, attempt, cursor, ok := chooseProvisionalVirtualIP(prefix, nodeID, 0, 0, 2, skip)
	if ok {
		t.Fatalf("first chunk found %s/%d; want a bounded yield", chosen, attempt)
	}
	if cursor != 2 {
		t.Fatalf("yield cursor = %d; want 2", cursor)
	}

	chosen, attempt, cursor, ok = chooseProvisionalVirtualIP(prefix, nodeID, 0, cursor, 2, skip)
	if !ok {
		t.Fatalf("resumed chunk found nothing; want candidate at the third offset (cursor %d)", cursor)
	}
	if chosen != third || attempt != 3 {
		t.Fatalf("resumed chunk = %s/%d; want %s/3", chosen, attempt, third)
	}
	if cursor != 0 {
		t.Fatalf("successful search returned cursor %d; want 0", cursor)
	}
}

// TestChooseProvisionalVirtualIPStaysOnFrozenSequence proves every candidate is
// provisionalVirtualIP(prefix, nodeID, attempt) for the consecutive attempt, not
// a linear host paired with an unrelated attempt.
func TestChooseProvisionalVirtualIPStaysOnFrozenSequence(t *testing.T) {
	prefix := netip.MustParsePrefix("10.78.0.0/24")
	nodeID := [16]byte{0x7, 0x7}
	skip := make(map[netip.Addr]struct{})
	for attempt := uint32(1); attempt <= 5; attempt++ {
		candidate, err := provisionalVirtualIP(prefix, nodeID, attempt)
		if err != nil {
			t.Fatal(err)
		}
		skip[candidate] = struct{}{}
	}
	chosen, attempt, _, ok := chooseProvisionalVirtualIP(prefix, nodeID, 0, 0, 6, skip)
	if !ok {
		t.Fatal("search found no candidate past the skipped prefix of the sequence")
	}
	want, err := provisionalVirtualIP(prefix, nodeID, 6)
	if err != nil {
		t.Fatal(err)
	}
	if chosen != want || attempt != 6 {
		t.Fatalf("chosen = %s/%d; want %s/6", chosen, attempt, want)
	}
}

// TestChooseProvisionalVirtualIPReportsAttemptWrap proves a u32 attempt overflow
// is reported as permanent exhaustion (cursor 0), never as a resume.
func TestChooseProvisionalVirtualIPReportsAttemptWrap(t *testing.T) {
	prefix := netip.MustParsePrefix("10.79.0.0/24")
	nodeID := [16]byte{0x9}
	const lastAttempt = math.MaxUint32
	last, err := provisionalVirtualIP(prefix, nodeID, lastAttempt)
	if err != nil {
		t.Fatal(err)
	}
	skip := map[netip.Addr]struct{}{last: {}}
	_, _, cursor, ok := chooseProvisionalVirtualIP(prefix, nodeID, lastAttempt-1, 0, 4, skip)
	if ok {
		t.Fatal("search past the u32 attempt ceiling reported success")
	}
	if cursor != 0 {
		t.Fatalf("attempt wrap returned resume cursor %d; want 0 (permanent exhaustion)", cursor)
	}
}

// TestChooseProvisionalVirtualIPRespectsBaseAttempt proves the cursor is an
// offset from the persisted attempt, so a resumed search never restarts the
// persisted D-OVERLAY-004 pair at attempt 0.
func TestChooseProvisionalVirtualIPRespectsBaseAttempt(t *testing.T) {
	prefix := netip.MustParsePrefix("10.80.0.0/24")
	nodeID := [16]byte{0x5}
	const base = 100
	skip := map[netip.Addr]struct{}{}
	chosen, attempt, _, ok := chooseProvisionalVirtualIP(prefix, nodeID, base, 0, 4, skip)
	if !ok {
		t.Fatal("first offset of a nonzero base attempt found nothing")
	}
	want, err := provisionalVirtualIP(prefix, nodeID, base+1)
	if err != nil {
		t.Fatal(err)
	}
	if chosen != want || attempt != base+1 {
		t.Fatalf("chosen = %s/%d; want %s/%d", chosen, attempt, want, base+1)
	}
}
