//go:build linux || darwin

package simpletier

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/topology"
)

// writePinnedOwnerIdentity writes the same fixed 40-byte identity record the
// security and topology packages read, so the test controls the local node ID.
func writePinnedOwnerIdentity(t *testing.T, dir string, privateKey [32]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir identity dir: %v", err)
	}
	record := make([]byte, 40)
	copy(record[0:4], "STID")
	record[4] = 1
	record[5] = 1
	copy(record[8:], privateKey[:])
	if err := os.WriteFile(filepath.Join(dir, "identity.key"), record, 0o600); err != nil {
		t.Fatalf("write fixed identity: %v", err)
	}
}

// TestFlowDirectoryReadsCurrentAddressOwnerNotStaleView is the regression for
// the steady UDP route-stale failure: flowEndpointDirectory resolved the address
// owner through the immutable RouteView snapshot, so a renewed AddressFact of the
// same owner was invisible until the view rebuild and a running datagram flow
// failed as route-stale. The adapter must read the current live fact entries
// instead.
func TestFlowDirectoryReadsCurrentAddressOwnerNotStaleView(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod state dir: %v", err)
	}
	var privateKey [32]byte
	for index := range privateKey {
		privateKey[index] = byte(index + 1)
	}
	writePinnedOwnerIdentity(t, dir, privateKey)
	identity, err := security.OpenIdentityStore()
	if err != nil {
		t.Fatalf("open identity store: %v", err)
	}
	t.Cleanup(func() { _ = identity.Close() })
	state, err := security.OpenNetworkState(identity, [32]byte{0x51})
	if err != nil {
		t.Fatalf("open network state: %v", err)
	}
	t.Cleanup(func() { _ = state.Close() })
	rawNode, err := state.NodeID()
	if err != nil {
		t.Fatalf("local node id: %v", err)
	}
	localNode := topology.NodeID(rawNode)
	fs, err := topology.NewFactStore(state, 0x9a)
	if err != nil {
		t.Fatalf("new fact store: %v", err)
	}
	view, err := topology.NewRouteView(fs, func(uint64, uint64, uint8, topology.NodeID) bool { return true })
	if err != nil {
		t.Fatalf("new route view: %v", err)
	}

	ip := netip.MustParseAddr("10.77.0.9")
	base := time.Now().Truncate(time.Second)
	addressRecord := func(version topology.FactVersion) topology.FactRecord {
		return topology.FactRecord{
			Envelope: topology.FactEnvelope{
				NetworkID: 0x9a,
				Kind:      topology.FactAddress,
				Origin:    localNode,
				Version:   version,
				IssuedAt:  uint64(base.UnixMilli()),
				ExpiresAt: uint64(base.Add(30 * time.Second).UnixMilli()),
			},
			Payload: topology.AddressPayload{NodeID: localNode, IP: ip, PrefixLen: 32},
		}
	}
	if err := fs.PublishLocal([]topology.FactRecord{addressRecord(topology.FactVersion{Incarnation: 1, Sequence: 1})}, base); err != nil {
		t.Fatalf("publish address v1: %v", err)
	}
	if err := fs.PublishLocal([]topology.FactRecord{addressRecord(topology.FactVersion{Incarnation: 1, Sequence: 2})}, base); err != nil {
		t.Fatalf("publish address v2: %v", err)
	}
	want, err := fs.ResolveAddressOwner(ip, base)
	if err != nil {
		t.Fatalf("resolve current owner: %v", err)
	}
	if want.FactVersion != (topology.FactVersion{Incarnation: 1, Sequence: 2}) {
		t.Fatalf("current owner version = %+v; want 1/2", want.FactVersion)
	}
	// The view was built before the renewal and is never refreshed here; it may
	// report the older version or refuse as stale. Either way it must not be the
	// source of truth for the adapter.
	if stale, staleErr := view.ResolveVirtualIP(ip); staleErr == nil && stale.FactVersion == want.FactVersion {
		t.Log("route view already reports the renewed version; adapter test stays valid but is not discriminating")
	}

	directory := &flowEndpointDirectory{rt: &streamRuntime{n: &network{facts: &factRuntime{store: fs, routes: view}}}}
	owner, ok := directory.LookupEndpoint(context.Background(), ip)
	if !ok {
		t.Fatal("LookupEndpoint dropped a live, unambiguously owned address")
	}
	if owner.Owner != localNode || owner.Version != want.FactVersion {
		t.Fatalf("LookupEndpoint = %+v; want owner %x version %+v (current live fact)", owner, localNode, want.FactVersion)
	}
}
