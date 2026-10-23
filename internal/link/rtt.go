package link

import (
	"sync"
	"time"
)

// rttEstimator tracks one Link's round-trip time from PING/PONG probes.
//
// It follows the same shape TCP uses: an exponentially weighted mean plus a mean
// deviation, so a single delayed probe moves the estimate a little and a persistent
// change moves it quickly. A raw last-sample value would make every route cost read
// spike and settle on noise.
type rttEstimator struct {
	mu        sync.Mutex
	smoothed  time.Duration
	deviation time.Duration
	sampled   bool
	// outstanding maps a probe id to when it was sent. A PONG for an id this end never
	// sent is not a sample, and an id that is still outstanding must not be reused.
	outstanding map[[16]byte]time.Time
}

// maxOutstandingProbes bounds the map. A peer that never answers must not grow it without
// limit; probes are dropped oldest-first when it is full.
const maxOutstandingProbes = 64

// noteSent records that a probe with this id left at the given time.
func (e *rttEstimator) noteSent(probe [16]byte, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.outstanding == nil {
		e.outstanding = make(map[[16]byte]time.Time, maxOutstandingProbes)
	}
	if len(e.outstanding) >= maxOutstandingProbes {
		var oldestID [16]byte
		var oldestAt time.Time
		first := true
		for id, sentAt := range e.outstanding {
			if first || sentAt.Before(oldestAt) {
				oldestID, oldestAt, first = id, sentAt, false
			}
		}
		delete(e.outstanding, oldestID)
	}
	e.outstanding[probe] = at
}

// noteAcknowledged folds one returned probe into the estimate. A probe this end did not
// send, or already consumed, contributes nothing.
func (e *rttEstimator) noteAcknowledged(probe [16]byte, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	sentAt, ok := e.outstanding[probe]
	if !ok {
		return
	}
	delete(e.outstanding, probe)
	sample := at.Sub(sentAt)
	if sample <= 0 {
		return
	}
	if !e.sampled {
		e.smoothed = sample
		e.deviation = sample / 2
		e.sampled = true
		return
	}
	// TCP's alpha/beta, expressed with integer arithmetic: srtt = 7/8 srtt + 1/8 sample,
	// rttvar = 3/4 rttvar + 1/4 |srtt - sample|.
	diff := e.smoothed - sample
	if diff < 0 {
		diff = -diff
	}
	e.smoothed = e.smoothed - e.smoothed/8 + sample/8
	e.deviation = e.deviation - e.deviation/4 + diff/4
}

// estimate returns the smoothed round-trip time, or zero if no probe has returned.
func (e *rttEstimator) estimate() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.sampled {
		return 0
	}
	return e.smoothed
}

// variation returns the smoothed mean deviation.
func (e *rttEstimator) variation() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.deviation
}
