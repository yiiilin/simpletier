package simpletier

import (
	"net/netip"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/topology"
)

// TestDefaultVirtualIPIsPublished proves a Network created without fixed_ip
// selects the deterministic D-OVERLAY-004 VirtualIP, persists it and actually
// publishes an ADDRESS fact that a peer's FactStore observes. Before this, the
// provisional candidate was a local-only value and no peer could route to it.
func TestDefaultVirtualIPIsPublished(t *testing.T) {
	const (
		name  = "addr-publish"
		cidr  = "10.96.0.0/24"
		token = "addr-token-0123456789abcdef"
	)
	target := newPacketPlaneNode(t, name, cidr, token, "10.96.0.3", "")
	source := newPacketPlaneNode(t, name, cidr, token, "", relayCarrierURL(target))

	// No packet service is installed, so each adjacency keeps exactly the
	// CONTROL and STREAM lanes; the ADDRESS fact still propagates.
	waitRelayLinks(t, target, 2, 30*time.Second)
	waitRelayLinks(t, source, 2, 30*time.Second)

	vip := source.LocalVirtualIP()
	if !vip.IsValid() || !netip.MustParsePrefix(cidr).Contains(vip) {
		t.Fatalf("LocalVirtualIP = %v; want a valid address inside %s", vip, cidr)
	}
	identity, err := source.identityStore.Identity()
	if err != nil {
		t.Fatalf("source identity: %v", err)
	}
	want, err := provisionalVirtualIP(netip.MustParsePrefix(cidr), identity.NodeID, 0)
	if err != nil {
		t.Fatalf("provisional VirtualIP: %v", err)
	}
	if vip != want {
		t.Fatalf("LocalVirtualIP = %s; want deterministic attempt-0 %s", vip, want)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		records, _, err := target.facts.store.Snapshot(time.Now())
		if err == nil {
			for _, record := range records {
				payload, ok := record.Payload.(topology.AddressPayload)
				if ok && payload.IP == vip && payload.NodeID == topology.NodeID(identity.NodeID) {
					return
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("target never observed source ADDRESS fact for %s", vip)
}

// TestDefaultVirtualIPRecordPersists proves the selected (VirtualIP, attempt) is
// durably recorded in the NetworkState so a restart can reuse it instead of
// re-deriving, and that an explicit fixed_ip is not rewritten.
func TestDefaultVirtualIPRecordPersists(t *testing.T) {
	const token = "addr-token-0123456789abcdef"
	listenURL, _ := freeTCPListenAddress(t)
	handle, err := NewNetwork(Config{
		Listen:  []string{listenURL},
		Network: NetworkConfig{Name: "addr-persist", CIDR: "10.97.0.0/24", Token: token},
		Options: RuntimeOptions{},
	})
	if err != nil {
		t.Fatalf("NewNetwork(no fixed_ip): %v", err)
	}
	defer handle.Close()
	n := handle.(*network)

	vip := n.LocalVirtualIP()
	if !vip.IsValid() {
		t.Fatal("LocalVirtualIP is invalid without fixed_ip")
	}
	data, err := n.runtimeState.ReadRecord(addressRecordName, addressRecordLimit)
	if err != nil {
		t.Fatalf("address state record: %v", err)
	}
	recorded, attempt, ok := decodeAddressState(data)
	if !ok || recorded != vip || attempt != 0 {
		t.Fatalf("record = %v/attempt %d ok=%v; want %v/attempt 0", recorded, attempt, ok, vip)
	}
	if n.localAddressSnapshot().attempt != 0 {
		t.Fatalf("network attempt = %d; want 0", n.localAddressSnapshot().attempt)
	}

	// An explicit fixed_ip is used verbatim and never persisted as derived state.
	fixedListen, _ := freeTCPListenAddress(t)
	fixedHandle, err := NewNetwork(Config{
		Listen:  []string{fixedListen},
		Network: NetworkConfig{Name: "addr-persist-fixed", CIDR: "10.97.0.0/24", Token: token},
		Options: RuntimeOptions{FixedIP: "10.97.0.9"},
	})
	if err != nil {
		t.Fatalf("NewNetwork(fixed_ip): %v", err)
	}
	defer fixedHandle.Close()
	if got := fixedHandle.LocalVirtualIP(); got != netip.MustParseAddr("10.97.0.9") {
		t.Fatalf("fixed LocalVirtualIP = %s; want 10.97.0.9", got)
	}
}
