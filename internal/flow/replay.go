package flow

// replayWindowBits is the frozen 1024-bit duplicate/consumption window for one
// (NetworkID, authenticated SrcNodeID, AssociationID, direction) key.
const replayWindowBits = 1024

// replayWindow records which DatagramIDs of one direction were consumed:
// delivered, or terminally discarded (schema/conflict/resource/timeout/
// superseded). A failed E2E tag never reaches this package, so it never
// mutates the window. IDs outside the 1024-bit span are treated as consumed
// (too old to track), which is the bounded behaviour the frozen rule requires.
type replayWindow struct {
	newest uint64
	seen   bool
	bits   [replayWindowBits / 64]uint64
}

// consumed reports whether id was already consumed or has aged out of the
// window. It never mutates the window.
func (w *replayWindow) consumed(id uint64) bool {
	if !w.seen || id > w.newest {
		return false
	}
	if w.newest-id >= replayWindowBits {
		return true
	}
	return w.bits[(id/64)%(replayWindowBits/64)]&(1<<(id%64)) != 0
}

// consume marks id consumed and advances the window. Consuming an ID already
// outside the window is a no-op: it can no longer be distinguished.
func (w *replayWindow) consume(id uint64) {
	if !w.seen {
		w.seen = true
		w.newest = id
		w.bits[(id/64)%(replayWindowBits/64)] = 1 << (id % 64)
		return
	}
	if id > w.newest {
		w.shift(id - w.newest)
		w.newest = id
	} else if w.newest-id >= replayWindowBits {
		return
	}
	w.bits[(id/64)%(replayWindowBits/64)] |= 1 << (id % 64)
}

// shift moves the window forward by n < replayWindowBits bits.
func (w *replayWindow) shift(n uint64) {
	words := int(n / 64)
	bits := n % 64
	var next [replayWindowBits / 64]uint64
	for i := len(next) - 1; i >= 0; i-- {
		j := i - words
		if j < 0 {
			continue
		}
		next[i] = w.bits[j] << bits
		if bits != 0 && j > 0 {
			next[i] |= w.bits[j-1] >> (64 - bits)
		}
	}
	w.bits = next
}
