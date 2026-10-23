package simpletier

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/topology"
)

func addressOwnerCount(t *testing.T, n *network, ip netip.Addr) int {
	t.Helper()
	owners, err := n.facts.addressOwners(time.Now(), ip)
	if err != nil {
		return 0
	}
	return len(owners)
}

// TestFixedIPConflictFailsClosed proves D-OVERLAY-004 fixed-address handling: two
// nodes that explicitly claim the same fixed_ip both observe two live owners and
// each reports ErrAddressConflict instead of silently re-addressing.
func TestFixedIPConflictFailsClosed(t *testing.T) {
	const (
		name  = "addr-conflict"
		cidr  = "10.102.0.0/24"
		token = "addr-conflict-token-0123456789"
	)
	shared := "10.102.0.5"
	target := newPacketPlaneNode(t, name, cidr, token, shared, "")
	source := newPacketPlaneNode(t, name, cidr, token, shared, relayCarrierURL(target))

	waitRelayLinks(t, target, 2, 30*time.Second)
	waitRelayLinks(t, source, 2, 30*time.Second)

	ip := netip.MustParseAddr(shared)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if addressOwnerCount(t, source, ip) >= 2 && addressOwnerCount(t, target, ip) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if addressOwnerCount(t, source, ip) < 2 || addressOwnerCount(t, target, ip) < 2 {
		t.Fatalf("both owners of %s never became visible in both FactStores", shared)
	}

	if err := source.facts.checkAddressConflict(time.Now()); !errors.Is(err, ErrAddressConflict) {
		t.Fatalf("fixed_ip conflict on source = %v; want ErrAddressConflict", err)
	}
	if err := target.facts.checkAddressConflict(time.Now()); !errors.Is(err, ErrAddressConflict) {
		t.Fatalf("fixed_ip conflict on target = %v; want ErrAddressConflict", err)
	}
}

// TestNodeIDLessOrdersDeterministically pins the D-OVERLAY-004 tie-break the
// automatic allocator uses: the strict bytewise-lowest NodeID wins, and equal
// identities are not "less".
func TestNodeIDLessOrdersDeterministically(t *testing.T) {
	var low, high topology.NodeID
	low[0], low[15] = 0x01, 0xFF
	high[0] = 0x02
	if !nodeIDLess(low, high) {
		t.Fatal("low NodeID must be less than high NodeID")
	}
	if nodeIDLess(high, low) {
		t.Fatal("high NodeID must not be less than low NodeID")
	}
	if nodeIDLess(low, low) {
		t.Fatal("equal NodeIDs must not be less")
	}
	// A difference in the last byte must still decide the order.
	var a, b topology.NodeID
	a[0], a[15] = 0x05, 0x00
	b[0], b[15] = 0x05, 0x01
	if !nodeIDLess(a, b) || nodeIDLess(b, a) {
		t.Fatal("trailing-byte difference must decide the order")
	}
}
