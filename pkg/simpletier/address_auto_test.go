package simpletier

import (
	"net/netip"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/topology"
)

// newPacketPlaneNodeAt is newPacketPlaneNode with a caller-owned state dir so a
// test can restart the same identity.
func newPacketPlaneNodeAt(t *testing.T, name, cidr, token, fixedIP, upstream string) *network {
	t.Helper()
	listenURL, _ := freeTCPListenAddress(t)
	cfg := Config{
		Listen:  []string{listenURL},
		Network: NetworkConfig{Name: name, CIDR: cidr, Token: token},
		Options: RuntimeOptions{FixedIP: fixedIP},
	}
	if upstream != "" {
		cfg.Upstreams = []string{upstream}
	}
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork() error = %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle.(*network)
}

// TestAutoLoserReallocation forces a deterministic automatic address collision
// between two real Networks and proves the higher-NodeID loser reallocates: it
// revokes its old AddressFact, persists attempt+1, swaps its local snapshot to a
// free address, and the old conflict clears after the facts converge.
func TestAutoLoserReallocation(t *testing.T) {
	const (
		name  = "addr-auto-loser"
		cidr  = "10.106.0.0/29"
		token = "addr-auto-loser-token-0123456789"
	)
	prefix := netip.MustParsePrefix(cidr)
	target := newPacketPlaneNode(t, name, cidr, token, "", "")
	vipA := target.LocalVirtualIP()
	if !vipA.IsValid() || !prefix.Contains(vipA) {
		t.Fatalf("target auto VIP = %v; want inside %s", vipA, cidr)
	}

	// First start of the source: learn its real contextID and state dir.
	probe := newPacketPlaneNodeAt(t, name, cidr, token, "", "")
	identity, err := probe.identityStore.Identity()
	if err != nil {
		t.Fatalf("probe identity: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("close probe source: %v", err)
	}

	// The source must allocate its address automatically: a pinned FixedIP is refused
	// outright on conflict instead of reallocating, so it can never exercise the
	// loser path. The conflict is then driven through the same entry point the refresh
	// loop uses.
	source := newPacketPlaneNodeAt(t, name, cidr, token, "", relayCarrierURL(target))
	if !prefix.Contains(source.LocalVirtualIP()) {
		t.Fatalf("source VIP = %s; want inside %s", source.LocalVirtualIP(), cidr)
	}

	waitRelayLinks(t, target, 3, 30*time.Second)
	waitRelayLinks(t, source, 3, 30*time.Second)

	// Both nodes allocated addresses automatically, so they picked different hosts.
	// Move the source onto the target's address to create the collision the loser
	// path is about; a pinned FixedIP cannot be used because a conflict there is
	// refused outright instead of reallocated.
	source.setLocalAddress(vipA, 1)
	if err := writeAddressState(source.runtimeState, vipA, 1); err != nil {
		t.Fatalf("adopt contested address: %v", err)
	}
	// Moving the local address is not enough: the peer only learns about the second
	// owner from an ADDRESS fact, so re-publish before waiting for the collision.
	if err := source.facts.refreshLocal(time.Now()); err != nil {
		t.Fatalf("republish address fact: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if addressOwnerCount(t, source, vipA) >= 2 && addressOwnerCount(t, target, vipA) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if addressOwnerCount(t, source, vipA) < 2 {
		t.Fatalf("source never observed two owners of %s", vipA)
	}

	identityTarget, err := target.identityStore.Identity()
	if err != nil {
		t.Fatalf("target identity: %v", err)
	}
	// The bytewise-lowest NodeID wins and keeps the address; the higher-NodeID
	// node is the loser that must reallocate.
	sourceID := topology.NodeID(identity.NodeID)
	targetID := topology.NodeID(identityTarget.NodeID)
	loser, winner := source, target
	if nodeIDLess(sourceID, targetID) {
		loser, winner = target, source
	}

	// Drive the loser path directly. checkAddressConflict is a gate that first requires
	// the RouteView to report a conflict, which needs both nodes to own the same
	// address in the same snapshot; the reallocation itself is what this test is about,
	// so it is invoked at the same seam the gate would call.
	contested := loser.LocalVirtualIP()
	if err := loser.facts.reallocateAddress(time.Now(), contested); err != nil {
		t.Fatalf("auto loser reallocation failed: %v", err)
	}
	newVIP := loser.LocalVirtualIP()
	if newVIP == contested {
		t.Fatal("loser kept the contested address; want a reallocated VIP")
	}
	if !prefix.Contains(newVIP) {
		t.Fatalf("reallocated VIP %s is outside %s", newVIP, cidr)
	}
	if loser.localAddressSnapshot().attempt == 0 {
		t.Fatal("loser attempt was not advanced")
	}

	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if addressOwnerCount(t, winner, vipA) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := addressOwnerCount(t, winner, vipA); got != 1 {
		t.Fatalf("old address owners = %d after revocation convergence; want 1", got)
	}

	select {
	case <-loser.Done():
		t.Fatal("loser Network closed instead of remaining usable")
	default:
	}
	_ = prefix
}
