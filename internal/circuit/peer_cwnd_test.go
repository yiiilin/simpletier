package circuit

import (
	"testing"
)

// TestPeerCwndIsRemembered checks that the window history is actually written
// when a peer advertises credit, since the adaptive start depends on it.
func TestPeerCwndIsRemembered(t *testing.T) {
	m := &Manager{
		peerCwnd: make(map[NodeID]uint64),
	}
	peer := NodeID{0x11}
	if got := m.initialCwndFor(peer); got != cwndInitial {
		t.Fatalf("cold initial cwnd = %d; want %d", got, cwndInitial)
	}
	m.peerCwnd[peer] = 4 << 20
	if got := m.initialCwndFor(peer); got != 4<<20 {
		t.Fatalf("warm initial cwnd = %d; want %d", got, uint64(4<<20))
	}
}
