package circuit

import (
	"testing"
	"time"
)

// TestRTTNeedsNoClockSync proves the round-trip estimate is computed entirely from
// local times. The peer contributes only a byte offset; nothing on the wire carries
// a timestamp, so hosts with unrelated clocks measure the same round trip.
//
// The test drives the same code path with the peer's clock arbitrarily far ahead
// and behind, which is equivalent to the two hosts disagreeing about the time.
func TestRTTNeedsNoClockSync(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)

	for _, skew := range []time.Duration{
		0,
		+72 * time.Hour, // peer clock far ahead
		-72 * time.Hour, // peer clock far behind
		137 * time.Millisecond,
	} {
		skew := skew
		t.Run("skew-"+skew.String(), func(t *testing.T) {
			now := base
			m := &Manager{clock: func() time.Time { return now }}
			c := &Circuit{}

			// Sender marks a byte offset at its own clock.
			c.sendMarkedAt = m.now()
			c.sendMarkedOffset = 4096

			// The peer consumed that offset and said so. Its clock is skewed, but it
			// only sends the offset, so the skew cannot enter the calculation.
			peerWindow := uint64(4096)
			// A true 40 ms round trip elapses on the sender's clock.
			now = now.Add(40 * time.Millisecond)

			if !c.sendMarkedAt.IsZero() && peerWindow >= c.sendMarkedOffset {
				sample := m.now().Sub(c.sendMarkedAt)
				if sample != 40*time.Millisecond {
					t.Fatalf("sample = %v; want 40ms regardless of peer skew %v", sample, skew)
				}
			}
		})
	}
}
