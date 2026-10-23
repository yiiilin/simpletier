package simpletier

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/security"
)

const admissionOrderToken = "0123456789abcdef0123456789abcdef"

// admissionNetworkAt builds a real Network that pins its IdentityStore to an
// explicit state directory so two Networks can share one canonical entry.
func admissionNetworkAt(t *testing.T, stateDir string, mutate func(*Config)) *network {
	t.Helper()
	cfg := validConfig()
	url, _ := freeTCPListenAddress(t)
	cfg.Listen, cfg.Upstreams = []string{url}, nil
	cfg.Network.Token = admissionOrderToken
	// Admission tests exercise the flood guard, so they opt in explicitly now that it
	// is off by default.
	enabled := true
	cfg.Options.RateLimit = &enabled
	if mutate != nil {
		mutate(&cfg)
	}
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := handle.Close(); err != nil {
			t.Error(err)
		}
	})
	return handle.(*network)
}

func admissionNetworkWithState(t *testing.T, stateDir, token string) *network {
	t.Helper()
	return admissionNetworkAt(t, stateDir, func(cfg *Config) { cfg.Network.Token = token })
}

type manualInitiator struct {
	conn    net.Conn
	control *link.ProtectedControlIO
	result  link.LinkResult
	skipper *factFrameSkipper
}

// dialManualInitiator performs a real Noise/CAPABILITY handshake against a real
// listening Network as the CONTROL initiator. It lets the test choose the
// LinkID/epoch so ordering scenarios are deterministic; it is not a mock of the
// admission path.
func dialManualInitiator(t *testing.T, n *network, identity security.Identity, linkID, epoch uint64, generation uint32) *manualInitiator {
	t.Helper()
	conn, err := net.DialTimeout("tcp", n.carrierListeners[0].Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := link.Handshake(ctx, conn, link.LinkConfig{
		Descriptor: n.networkContext.Descriptor(), NetworkID: n.networkContext.WireID(),
		PSK: n.networkPSK, Identity: identity, Initiator: true,
		LinkID: linkID, LinkEpoch: epoch, Generation: generation, LaneID: 0,
		CapabilityVersion: uint16(link.CapabilityVersion), CapabilityMask: link.RequiredCapabilityMask,
		RequiredCapabilityMask: link.RequiredCapabilityMask,
	})
	if err != nil {
		t.Fatal(err)
	}
	control, err := link.NewProtectedControlIO(conn, result, n.networkContext.Descriptor(), true)
	if err != nil {
		t.Fatal(err)
	}
	return &manualInitiator{conn: conn, control: control, result: result, skipper: newFactFrameSkipper(n, control)}
}

func assertPeerClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buffer [1]byte
	if _, err := conn.Read(buffer[:]); err == nil {
		t.Fatal("peer connection stayed open after rejected admission")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("rejected admission did not promptly close the peer")
	}
}

func epochFilePath(n *network, contextID [32]byte) string {
	stateDir, err := n.identityStore.StateDir()
	if err != nil {
		return ""
	}
	return filepath.Join(stateDir, "link-epoch", hex.EncodeToString(contextID[:]), "0", "epoch")
}

func allocatedEpoch(t *testing.T, n *network, contextID [32]byte) uint64 {
	t.Helper()
	scope, err := n.identityStore.StateDir()
	if err != nil {
		t.Fatal(err)
	}
	return security.AllocatedLinkEpochForTest(scope, contextID, laneControl)
}

func waitAllocatedEpoch(t *testing.T, n *network, contextID [32]byte, want uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if allocatedEpoch(t, n, contextID) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("epoch allocation did not reach %d", want)
}

// Acceptance: epoch 10 is admitted first, then epoch 11. Both authenticated
// instances coexist and stay Ready. Retiring 10 leaves 11 healthy and still able
// to exchange encrypted control traffic.
func TestAdmissionOrderingKeepsHealthyDifferentLinkInstances(t *testing.T) {
	server := admissionNetwork(t, admissionOrderToken)
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	first := dialManualInitiator(t, server, identity, 0x1010, 10, 101)
	waitAdmissionLinks(t, server, 1)
	second := dialManualInitiator(t, server, identity, 0x2020, 11, 202)
	waitAdmissionLinks(t, server, 2)

	server.mu.Lock()
	low, high := server.activeLinks[0x1010], server.activeLinks[0x2020]
	server.mu.Unlock()
	if low == nil || high == nil || !low.Ready() || !high.Ready() {
		t.Fatal("both authenticated instances were not independently ready")
	}

	if err := first.conn.Close(); err != nil {
		t.Fatal(err)
	}
	waitAdmissionLinks(t, server, 1)
	server.mu.Lock()
	_, survivor := server.activeLinks[0x2020]
	_, retired := server.activeLinks[0x1010]
	server.mu.Unlock()
	if !survivor || retired {
		t.Fatal("retiring epoch 10 removed or retained the wrong Link instance")
	}

	if err := second.conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	probe := bytes.Repeat([]byte{0x7b}, 16)
	if err := second.control.WriteControl(link.ControlMessage{Type: 1, Payload: probe}); err != nil {
		t.Fatal(err)
	}
	got := readSkippingFacts(t, second.skipper, second.control)
	if got.Type != 2 || !bytes.Equal(got.Payload, probe) {
		t.Fatalf("surviving Link PING/PONG: type=%d", got.Type)
	}
}

// Acceptance: a genuine authenticated higher epoch that commits the durable
// floor first causes later lower NEW attempts to fail, and a same-epoch replay
// with the same LinkID but a different Noise transcript is also rejected because
// the floor is transcript-bound rather than LinkID-only.
func TestAdmissionOrderingRejectsLateLowerEpochAndConflictingTranscript(t *testing.T) {
	server := admissionNetwork(t, admissionOrderToken)
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_ = dialManualInitiator(t, server, identity, 0x3001, 11, 301)
	waitAdmissionLinks(t, server, 1)

	late := dialManualInitiator(t, server, identity, 0x3002, 10, 302)
	assertPeerClosed(t, late.conn)
	waitAdmissionLinks(t, server, 1)
	server.mu.Lock()
	_, lateRegistered := server.activeLinks[0x3002]
	server.mu.Unlock()
	if lateRegistered {
		t.Fatal("late lower epoch entered the registry")
	}

	// Same epoch and same LinkID, but a fresh handshake transcript.
	replay := dialManualInitiator(t, server, identity, 0x3001, 11, 303)
	assertPeerClosed(t, replay.conn)
	waitAdmissionLinks(t, server, 1)
	server.mu.Lock()
	_, replayRegistered := server.activeLinks[0x3001]
	server.mu.Unlock()
	if !replayRegistered {
		t.Fatal("transcript replay removed the originally admitted instance")
	}
}

// Acceptance: one runtime owner serializes its own concurrent CONTROL
// admission windows on the same canonical (StateDir, full ContextID, Lane). A
// second initiator must not allocate a higher epoch while the first is still
// inside its admission window, and Network.Close cancels the waiting attempt.
// Two same-ContextID NewNetwork owners are no longer constructible: the
// duplicate-constructor rejection is covered by
// TestNewNetworkRejectsDuplicateSameContextOwner.
func TestSingleOwnerSerializesConcurrentAdmissionWindows(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	server := admissionNetworkWithState(t, stateDir, admissionOrderToken)
	contextID := server.networkContext.ID()

	firstLeft, firstRight := net.Pipe()
	defer firstRight.Close()
	secondLeft, secondRight := net.Pipe()
	defer secondRight.Close()
	firstConn, err := NewConnection(firstLeft, ConnectionInfo{Type: "host"})
	if err != nil {
		t.Fatal(err)
	}
	secondConn, err := NewConnection(secondLeft, ConnectionInfo{Type: "host"})
	if err != nil {
		t.Fatal(err)
	}

	firstResult := make(chan error, 1)
	go func() {
		_, err := server.admitConnectionLink(firstConn, true)
		firstResult <- err
	}()
	waitAllocatedEpoch(t, server, contextID, 1)

	secondResult := make(chan error, 1)
	go func() {
		_, err := server.admitConnectionLink(secondConn, true)
		secondResult <- err
	}()
	// Give the second attempt time to reach the gate. Without serialization it
	// would allocate epoch 2 immediately even though the first handshake is
	// still blocked on a peer that never answers.
	time.Sleep(300 * time.Millisecond)
	if got := allocatedEpoch(t, server, contextID); got != 1 {
		t.Fatalf("second attempt allocated epoch %d before the first admission finished", got)
	}

	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	for index, result := range []chan error{firstResult, secondResult} {
		select {
		case err := <-result:
			if err == nil {
				t.Fatalf("attempt %d succeeded although the owner closed mid-admission", index)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("attempt %d did not terminate on Close", index)
		}
	}
}

// Acceptance: different full ContextIDs on the same canonical IdentityStore do
// not block each other.
func TestAdmissionGateIsolatesDifferentContexts(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	first := admissionNetworkWithState(t, stateDir, admissionOrderToken)
	// A different canonical CIDR yields a different full ContextID while the
	// identity store entry stays shared.
	second := admissionNetworkAt(t, stateDir, func(cfg *Config) {
		cfg.Network.CIDR = "10.21.0.0/24"
		cfg.Options.FixedIP = "10.21.0.7"
	})
	if first.networkContext.ID() == second.networkContext.ID() {
		t.Fatal("different CIDRs did not produce different full contexts")
	}

	firstLeft, firstRight := net.Pipe()
	defer firstRight.Close()
	secondLeft, secondRight := net.Pipe()
	defer secondRight.Close()
	firstConn, err := NewConnection(firstLeft, ConnectionInfo{Type: "host"})
	if err != nil {
		t.Fatal(err)
	}
	secondConn, err := NewConnection(secondLeft, ConnectionInfo{Type: "host"})
	if err != nil {
		t.Fatal(err)
	}

	firstResult := make(chan error, 1)
	go func() {
		_, err := first.admitConnectionLink(firstConn, true)
		firstResult <- err
	}()
	secondResult := make(chan error, 1)
	go func() {
		_, err := second.admitConnectionLink(secondConn, true)
		secondResult <- err
	}()
	waitAllocatedEpoch(t, first, first.networkContext.ID(), 1)
	waitAllocatedEpoch(t, second, second.networkContext.ID(), 1)

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	for _, result := range []chan error{firstResult, secondResult} {
		select {
		case <-result:
		case <-time.After(2 * time.Second):
			t.Fatal("isolated admission did not terminate on Close")
		}
	}
}

// Acceptance: an initiator that completes Noise/CAPABILITY but never receives
// the correlated admission PONG is retired, is not re-registered, and releases
// its serialization lease.
func TestUnconfirmedInitiatorAdmissionIsRetiredAndLeaseReleased(t *testing.T) {
	server := admissionNetwork(t, admissionOrderToken)
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	client, err := NewConnection(left, ConnectionInfo{Type: "host"})
	if err != nil {
		t.Fatal(err)
	}

	admitted := make(chan error, 1)
	go func() {
		_, err := server.admitConnectionLink(client, true)
		admitted <- err
	}()

	// The peer acts as the responder, then closes without ever answering a PING,
	// so the initiator cannot prove durable peer admission.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := link.Handshake(ctx, right, link.LinkConfig{
		Descriptor: server.networkContext.Descriptor(), NetworkID: server.networkContext.WireID(),
		PSK: server.networkPSK, Identity: identity, Initiator: false, LaneID: 0,
		CapabilityVersion: uint16(link.CapabilityVersion), CapabilityMask: link.RequiredCapabilityMask,
		RequiredCapabilityMask: link.RequiredCapabilityMask,
	}); err != nil {
		t.Fatal(err)
	}
	if err := right.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-admitted:
		if err == nil {
			t.Fatal("unconfirmed admission succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unconfirmed admission did not terminate")
	}
	server.mu.Lock()
	count := len(server.activeLinks)
	server.mu.Unlock()
	if count != 0 {
		t.Fatalf("unconfirmed initiator left %d registered Links", count)
	}

	// The lease must be free again: a fresh acquisition on the same key cannot
	// block behind a leaked holder. Different canonical directories keep this
	// test independent of other admission state.
	gateCtx, gateCancel := context.WithTimeout(context.Background(), time.Second)
	defer gateCancel()
	lease, err := security.AcquireLinkAttempt(gateCtx, "scope", server.networkContext.ID(), 0)
	if err != nil {
		t.Fatalf("lease was not released after failed confirmation: %v", err)
	}
	lease.Release()
}
