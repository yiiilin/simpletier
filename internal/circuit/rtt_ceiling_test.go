package circuit

import (
	"testing"
	"time"
)

// TestCwndCeilingScalesWithRTT pins the adaptive rule: the ceiling follows the
// bandwidth-delay product, so a slow path with a long round trip is allowed more
// data in flight than a short one achieving the same rate, and the ceiling never
// leaves the [cwndInitial, cwndMax] range.
func TestCwndCeilingScalesWithRTT(t *testing.T) {
	cases := []struct {
		name  string
		rtt   time.Duration
		acked uint64
		span  time.Duration
		valid bool
	}{
		{"no-sample", 0, 0, 0, false},
		// 4 MiB acknowledged over 1s = 4 MB/s, 10ms RTT -> 40 KB needed, floors at initial.
		{"fast-10ms", 10 * time.Millisecond, 4 << 20, time.Second, true},
		// Same rate, 300ms RTT -> 1.2 MB needed.
		{"long-300ms", 300 * time.Millisecond, 4 << 20, time.Second, true},
		// Fast rate with long RTT -> large BDP, capped at max.
		{"long-fast", 300 * time.Millisecond, 400 << 20, time.Second, true},
	}
	for _, tc := range cases {
		c := &Circuit{
			cwndAcked: tc.acked,
			ackedSpan: tc.span,
			srtt:      tc.rtt,
			rttValid:  tc.valid,
		}
		got := c.cwndCeiling()
		if got < cwndInitial || got > cwndMax {
			t.Fatalf("%s: ceiling %d outside [%d,%d]", tc.name, got, uint64(cwndInitial), uint64(cwndMax))
		}
		t.Logf("%-11s ceiling = %8d bytes", tc.name, got)
	}

	// A long round trip at the same rate must allow more in flight than a short one.
	short := (&Circuit{cwndAcked: 4 << 20, ackedSpan: time.Second, srtt: 10 * time.Millisecond, rttValid: true}).cwndCeiling()
	long := (&Circuit{cwndAcked: 4 << 20, ackedSpan: time.Second, srtt: 300 * time.Millisecond, rttValid: true}).cwndCeiling()
	if long <= short {
		t.Fatalf("300ms ceiling %d not larger than 10ms ceiling %d", long, short)
	}
}
