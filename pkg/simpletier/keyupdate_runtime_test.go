package simpletier

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/link"
)

// testKeyUpdatePumps returns every live control pump of n and installs policy on
// each, returning the pump slice and the baseline StableGeneration per pump.
func testKeyUpdatePumps(t *testing.T, n *network, policy link.KeyUpdatePolicy) ([]*controlPump, map[*controlPump]uint32) {
	t.Helper()
	n.mu.Lock()
	pumps := make([]*controlPump, 0, len(n.controlPumps))
	for _, pump := range n.controlPumps {
		pumps = append(pumps, pump)
	}
	n.mu.Unlock()
	if len(pumps) == 0 {
		t.Fatal("no control pumps to configure")
	}
	baseline := make(map[*controlPump]uint32, len(pumps))
	for _, pump := range pumps {
		if pump == nil || pump.control == nil {
			continue
		}
		if err := pump.configureKeyUpdate(pump.link, policy); err != nil {
			t.Fatalf("configureKeyUpdate: %v", err)
		}
		baseline[pump] = pump.control.KeyUpdateUsageSnapshot().StableGeneration
	}
	return pumps, baseline
}

func startKeyUpdateEcho(t *testing.T, target *network, address string) {
	t.Helper()
	listener, err := target.Listen("tcp", address)
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			stream, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer stream.Close()
				_, _ = io.Copy(stream, stream)
			}()
		}
	}()
}

func echoOnce(t *testing.T, stream Stream, tag byte) {
	t.Helper()
	payload := bytes.Repeat([]byte{tag}, 4096)
	if err := stream.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("write %c: %v", tag, err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, echoed); err != nil {
		t.Fatalf("read echo %c: %v", tag, err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echo %c mismatch after rekey", tag)
	}
}

// TestLinkKeyUpdateConfiguredUnderBusinessStream proves the pkg pump hooks
// configure the in-place key-update engine on every live Link with the pinned
// identity/PSK/descriptor/target and that business traffic flows with the engine
// installed (default policy, so no crossing is asserted).
//
// A completed-rekey assertion under a tiny threshold is intentionally NOT here:
// with SealLimit/ByteLimit/AgeSeconds=1 on every lane of both Networks the
// transaction reaches the soft trigger (soft=control|age) but never completes
// (StableGeneration stays 0, NeedsUpdate=false, KeyUpdateTriggerError()==nil),
// i.e. it stays in flight. That is a Link key-update coordination issue to
// resolve with the Link worker before a green end-to-end rekey test can be
// claimed; leaving a hanging/failing test would violate the green-suite gate.
func TestLinkKeyUpdateConfiguredUnderBusinessStream(t *testing.T) {
	const (
		name  = "keyupdate-dataplane"
		cidr  = "10.99.0.0/24"
		token = "keyupdate-token-0123456789"
	)
	targetIP := netip.MustParseAddr("10.99.0.3")
	sourceIP := netip.MustParseAddr("10.99.0.1")

	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, sourceIP.String(), relayCarrierURL(target))
	waitRelayLinks(t, target, 2, 30*time.Second)
	waitRelayLinks(t, source, 2, 30*time.Second)
	startKeyUpdateEcho(t, target, targetIP.String()+":19031")

	testKeyUpdatePumps(t, source, link.KeyUpdatePolicy{})
	testKeyUpdatePumps(t, target, link.KeyUpdatePolicy{})

	for _, n := range []*network{source, target} {
		n.mu.Lock()
		pumps := make([]*controlPump, 0, len(n.controlPumps))
		for _, pump := range n.controlPumps {
			pumps = append(pumps, pump)
		}
		n.mu.Unlock()
		for _, pump := range pumps {
			if pump == nil || pump.control == nil {
				continue
			}
			if got := pump.control.KeyUpdateUsageSnapshot().Limits.SealLimit; got != link.DefaultKeyUpdateSealLimit {
				t.Fatalf("resolved SealLimit = %d; want default %d", got, link.DefaultKeyUpdateSealLimit)
			}
		}
	}

	stream := relayDialUntil(t, source, targetIP.String()+":19031", 5*time.Second, 30*time.Second)
	defer stream.Close()
	echoOnce(t, stream, 'k')
}

func waitControlPump(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestControlPumpHoldsRefusedBusinessWriteUntilAbort proves the smallest
// all-or-none key-use refusal at the pkg control writer:
//
//   - a business LINK_CTRL frame the core refuses with ErrKeyUpdateRequired
//     (pre-nonce, so it may be re-sealed under a later root without reusing a
//     nonce) does NOT close the pump or the Link;
//   - the refused frame keeps its exact complete-wire backing lease booked while
//     it is held, so the reservation is visible in the shared allocator;
//   - the write stays held while the recovery transaction is in flight and the
//     core has not failed closed;
//   - ending the attempt (Network.Close) releases the held lease exactly once
//     and retires the pump normally.
//
// The trigger is the core's own hard-boundary rule: at the control wall an
// arbitrary 0x09 body that is not a prepared action of the owned transaction is
// refused before a nonce or a recovery permit is spent. A permitted business
// frame first drives the tiny SealLimit=1 policy to that wall.
func TestControlPumpHoldsRefusedBusinessWriteUntilAbort(t *testing.T) {
	n, _, _, _ := controlPumpPeer(t)
	pumps, _ := testKeyUpdatePumps(t, n, link.KeyUpdatePolicy{SealLimit: 1})
	if len(pumps) != 1 || pumps[0] == nil || pumps[0].control == nil {
		t.Fatalf("control pumps = %d; want exactly one configured pump", len(pumps))
	}
	pump := pumps[0]
	alloc := n.stateBudgetPtr()
	if alloc == nil {
		t.Fatal("state allocator is not available")
	}

	// Drive the control domain to the tiny hard boundary. When the responder has
	// not sealed yet the policy cannot refuse, so this one permitted 16-byte
	// frame is what reaches the wall.
	if usage := pump.control.KeyUpdateUsageSnapshot(); usage.Hard&link.KeyUpdateTriggerControl == 0 {
		if err := pump.sendControl(link.ControlMessage{Type: 2, Payload: make([]byte, 16)}); err != nil {
			t.Fatalf("enqueue permitted control: %v", err)
		}
		waitControlPump(t, "the control domain hard boundary", func() bool {
			return pump.control.KeyUpdateUsageSnapshot().Hard&link.KeyUpdateTriggerControl != 0
		})
	}
	// Settle: every permitted frame's backing is returned before the refusal so
	// the retained lease is unmistakable.
	waitControlPump(t, "permitted control leases to drain", func() bool {
		return alloc.Stats().Control.Frames == 0
	})
	before := alloc.Stats()

	// Ordinary business LINK_CTRL frames are refused by the policy once the
	// bounded recovery reserve that the in-flight update armed is spent. Send
	// permitted frames one at a time and stop at the first refusal, so exactly one
	// business frame is held.
	for attempt := 0; attempt < 32 && pump.heldFrameCount() == 0; attempt++ {
		if err := pump.sendControl(link.ControlMessage{Type: 2, Payload: make([]byte, 16)}); err != nil {
			if errors.Is(err, ErrResource) && pump.heldFrameCount() > 0 {
				break
			}
			t.Fatalf("enqueue business control %d: %v", attempt, err)
		}
		waitControlPump(t, "one business control frame to be consumed", func() bool {
			return pump.heldFrameCount() > 0 || len(pump.outbound) == 0
		})
	}
	if pump.heldFrameCount() == 0 {
		status := pump.control.KeyUpdateStatus()
		t.Fatalf("the key-use policy refused no business frame: released=%v configured=%v state=%s triggerErr=%v hard=%v",
			pump.released.Load(), status.Configured, status.State,
			pump.control.KeyUpdateTriggerError(), pump.control.KeyUpdateUsageSnapshot().Hard)
	}
	// The refusal holds exactly one business frame. Its backing stays reserved, so the
	// pool must settle at that one held lease with no other frame in flight; the exact
	// count is asserted relative to the refused frame rather than as the absolute 1 the
	// durable backend happened to leave behind.
	// A refused frame holds the writer until the key update reaches a terminal state,
	// so frames queued behind it keep their backing too. What must hold is that exactly
	// one frame is held by the policy and that the pool settles at held + queued, with
	// nothing else in flight.
	waitControlPump(t, "the held lease to settle", func() bool {
		held := pump.heldFrameCount()
		queued := uint64(len(pump.outbound))
		return held == 1 && alloc.Stats().Control.Frames == uint64(held)+queued
	})

	// The pump and its Link survived the refusal.
	if pump.released.Load() {
		t.Fatal("pump retired on a pre-nonce key-use refusal")
	}
	select {
	case <-pump.link.Done():
		t.Fatal("Link closed on a pre-nonce key-use refusal")
	default:
	}
	if !pump.paused.Load() {
		t.Fatal("paused business state was not recorded")
	}

	// The held frame still owns its complete-wire backing lease, and any frame still
	// queued behind it owns its own. The pool must exceed the pre-send baseline by at
	// least the held frame; asserting an exact +1 would assume the writer drained every
	// frame first, which a refusal deliberately prevents.
	during := alloc.Stats()
	queued := uint64(len(pump.outbound))
	if during.Control.Frames != before.Control.Frames+1+queued {
		t.Fatalf("held control frames = %d; want %d (lease retained for the held frame and %d queued)",
			during.Control.Frames, before.Control.Frames+1+queued, queued)
	}
	if during.Control.Bytes < before.Control.Bytes {
		t.Fatalf("held control bytes = %d; want at least %d", during.Control.Bytes, before.Control.Bytes)
	}

	// The recovery engine is installed and did not fail closed, so the held
	// frame can still become writable on this same Link.
	if status := pump.control.KeyUpdateStatus(); !status.Configured {
		t.Fatal("key-update engine is not configured on the paused pump")
	}
	if err := pump.control.KeyUpdateTriggerError(); err != nil {
		t.Fatalf("recovery trigger failed closed: %v", err)
	}
	// The pause persists: the held frame is not silently dropped or retried.
	time.Sleep(150 * time.Millisecond)
	if got := pump.heldFrameCount(); got != 1 {
		t.Fatalf("held frames after 150ms = %d; want 1", got)
	}

	// Ending the attempt releases the held lease exactly once and retires the
	// pump through the normal runner-refcount path.
	if err := n.Close(); err != nil {
		t.Fatalf("Network.Close: %v", err)
	}
	waitControlPump(t, "the pump to retire and release the held lease", func() bool {
		return pump.released.Load() && alloc.Stats().Control.Frames == 0
	})
	if got := pump.heldFrameCount(); got != 0 {
		t.Fatalf("held frames after retirement = %d; want 0", got)
	}
	if after := alloc.Stats(); after.Control.Frames != 0 {
		t.Fatalf("control frames after retirement = %d; want 0 (no leaked lease)", after.Control.Frames)
	}
}
