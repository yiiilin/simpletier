package link

import (
	"testing"
	"time"
)

// TestControlProbeRoundTripYieldsRTT covers the measurement a cost-aware route needs:
// the time a PING spends going out and its PONG coming back. The protocol already carries
// PING/PONG with a 16-byte ProbeID; until now nothing measured the round trip, so the
// LinkCost.RTTMillis every route decision reads was always zero.
//
// The seam is the round trip itself, not a helper: a test that called a "record an RTT of
// 12 ms" function would pass even if nothing ever timed a real frame.
func TestControlProbeRoundTripYieldsRTT(t *testing.T) {
	pair := establishedControlPair(t)

	// Before any probe the estimator has nothing to say.
	if got := pair.a.RTT(); got != 0 {
		t.Fatalf("RTT before any probe = %v; want 0", got)
	}

	probe := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	started := time.Now()
	pair.a.NoteProbeSent(probe, started)

	// The peer's PONG comes back on the same probe id.
	pair.a.NoteProbeAcknowledged(probe, started.Add(20*time.Millisecond))

	got := pair.a.RTT()
	if got < 15*time.Millisecond || got > 30*time.Millisecond {
		t.Fatalf("RTT after one 20 ms probe = %v; want about 20 ms", got)
	}

	// An unknown probe id must not disturb the estimate: a PONG for something this end
	// never sent is not a sample.
	before := pair.a.RTT()
	pair.a.NoteProbeAcknowledged([16]byte{0xFF}, started.Add(time.Second))
	if after := pair.a.RTT(); after != before {
		t.Fatalf("RTT changed by an unknown probe: %v -> %v", before, after)
	}
}

// TestControlProbeRoundTripSmoothsSamples covers the estimator, not the transport: one
// sample sets the estimate, and later samples move it gradually. A route cost that
// followed the last sample would flap with every delayed frame.
func TestControlProbeRoundTripSmoothsSamples(t *testing.T) {
	var estimator rttEstimator
	base := time.Unix(0, 0)

	first := [16]byte{1}
	estimator.noteSent(first, base)
	estimator.noteAcknowledged(first, base.Add(100*time.Millisecond))
	if got := estimator.estimate(); got != 100*time.Millisecond {
		t.Fatalf("first sample = %v; want exactly 100 ms", got)
	}

	// A second sample an order of magnitude smaller must move the estimate toward it, but
	// not all the way: that is what makes it an average rather than the last reading.
	second := [16]byte{2}
	estimator.noteSent(second, base)
	estimator.noteAcknowledged(second, base.Add(10*time.Millisecond))
	smoothed := estimator.estimate()
	if smoothed >= 100*time.Millisecond {
		t.Fatalf("estimate %v did not move toward the newer sample", smoothed)
	}
	if smoothed <= 10*time.Millisecond {
		t.Fatalf("estimate %v jumped straight to the newest sample", smoothed)
	}
	if got := estimator.variation(); got <= 0 {
		t.Fatalf("variation = %v; want positive after two differing samples", got)
	}

	// The oldest outstanding probe is dropped once the window is full, so a peer that
	// never answers cannot grow the map without bound.
	for index := 0; index < maxOutstandingProbes*2; index++ {
		estimator.noteSent([16]byte{byte(index), 0xAA}, base)
	}
	estimator.mu.Lock()
	outstanding := len(estimator.outstanding)
	estimator.mu.Unlock()
	if outstanding > maxOutstandingProbes {
		t.Fatalf("outstanding probes = %d; want at most %d", outstanding, maxOutstandingProbes)
	}
}
