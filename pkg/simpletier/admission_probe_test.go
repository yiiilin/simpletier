package simpletier

import (
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/link"
)

// newProbeTestPump returns a real controlPump value used as the ownership token
// for admission probes. Probe registration and PONG resolution only compare the
// owner pointer, so this drives the exact binding logic of the unique protected
// reader without faking that reader or its Link.
func newProbeTestPump(n *network) *controlPump {
	return &controlPump{network: n}
}

func pendingProbeCount(n *network) int {
	n.probeMu.Lock()
	defer n.probeMu.Unlock()
	return len(n.pendingProbes)
}

func probePayload(fill byte) [16]byte {
	var probe [16]byte
	for index := range probe {
		probe[index] = fill
	}
	return probe
}

// assertProbeNotDone fails if a probe completed. Resolution is synchronous on
// the consuming goroutine, so a wrong owner would close the channel before this
// check; the timeout only guards a hang.
func assertProbeNotDone(t *testing.T, done <-chan struct{}, context string) {
	t.Helper()
	select {
	case <-done:
		t.Fatalf("%s: probe was completed by a non-owning or unsolicited PONG", context)
	case <-time.After(50 * time.Millisecond):
	}
}

func assertProbeDone(t *testing.T, done <-chan struct{}, context string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s: owning pump PONG did not complete the probe", context)
	}
}

// Acceptance: a PONG only completes the probe registered by the pump that read
// it. A foreign pump seeing the same ProbeID leaves the probe pending and does
// not mutate Network state; the owning pump then completes it.
func TestAdmissionProbePongRequiresOwningPump(t *testing.T) {
	n := admissionNetwork(t, "probe-owner-token")
	owner := newProbeTestPump(n)
	foreign := newProbeTestPump(n)
	probe := probePayload(0x11)

	done, ok := n.registerAdmissionProbe(probe, owner)
	if !ok {
		t.Fatal("registerAdmissionProbe() rejected a fresh owned probe")
	}
	if got := pendingProbeCount(n); got != 1 {
		t.Fatalf("pending probes after register = %d; want 1", got)
	}

	if err := foreign.consume(link.ControlMessage{Type: 2, Payload: probe[:]}); err != nil {
		t.Fatalf("foreign pump PONG consume error = %v", err)
	}
	assertProbeNotDone(t, done, "foreign pump PONG")
	if got := pendingProbeCount(n); got != 1 {
		t.Fatalf("foreign pump PONG changed pending probes to %d; want 1", got)
	}

	if err := owner.consume(link.ControlMessage{Type: 2, Payload: probe[:]}); err != nil {
		t.Fatalf("owning pump PONG consume error = %v", err)
	}
	assertProbeDone(t, done, "owning pump PONG")
	if got := pendingProbeCount(n); got != 0 {
		t.Fatalf("owning pump PONG left %d pending probes; want 0", got)
	}
}

// Acceptance: cancel is owner-scoped. A foreign pump cannot cancel an owned
// probe, and after an owning cancel a late PONG read by the old pump cannot
// complete the ProbeID newly registered by a different owner.
func TestAdmissionProbeCancelIsOwnerScoped(t *testing.T) {
	n := admissionNetwork(t, "probe-cancel-token")
	oldPump := newProbeTestPump(n)
	newPump := newProbeTestPump(n)
	probe := probePayload(0x22)

	if _, ok := n.registerAdmissionProbe(probe, oldPump); !ok {
		t.Fatal("registerAdmissionProbe() rejected the first owner")
	}
	n.cancelAdmissionProbe(probe, newPump)
	if got := pendingProbeCount(n); got != 1 {
		t.Fatalf("foreign cancel removed the owned probe: pending=%d; want 1", got)
	}

	n.cancelAdmissionProbe(probe, oldPump)
	if got := pendingProbeCount(n); got != 0 {
		t.Fatalf("owning cancel left pending probes=%d; want 0", got)
	}

	// The same ProbeID is now owned by a new pump. A late PONG read by the old
	// pump must not complete the new owner's probe, and the new owner still can.
	done, ok := n.registerAdmissionProbe(probe, newPump)
	if !ok {
		t.Fatal("registerAdmissionProbe() failed to reuse a cancelled ProbeID")
	}
	if err := oldPump.consume(link.ControlMessage{Type: 2, Payload: probe[:]}); err != nil {
		t.Fatalf("old pump PONG consume error = %v", err)
	}
	assertProbeNotDone(t, done, "old pump PONG after cancel")
	if got := pendingProbeCount(n); got != 1 {
		t.Fatalf("old pump PONG after cancel changed pending probes to %d; want 1", got)
	}
	if err := newPump.consume(link.ControlMessage{Type: 2, Payload: probe[:]}); err != nil {
		t.Fatalf("new owning pump PONG consume error = %v", err)
	}
	assertProbeDone(t, done, "new owning pump PONG")
}

// Acceptance: an unsolicited PONG with no matching probe creates no state,
// grants nothing, and does not poison later legitimate use of the same ProbeID.
func TestAdmissionProbeUnsolicitedPongChangesNoState(t *testing.T) {
	n := admissionNetwork(t, "probe-unsolicited-token")
	pump := newProbeTestPump(n)
	probe := probePayload(0x33)

	if n.resolveAdmissionProbe(probe, pump) {
		t.Fatal("resolveAdmissionProbe() reported completion for an unregistered probe")
	}
	if err := pump.consume(link.ControlMessage{Type: 2, Payload: probe[:]}); err != nil {
		t.Fatalf("unsolicited PONG consume error = %v", err)
	}
	if got := pendingProbeCount(n); got != 0 {
		t.Fatalf("unsolicited PONG created %d pending probes; want 0", got)
	}

	done, ok := n.registerAdmissionProbe(probe, pump)
	if !ok {
		t.Fatal("registerAdmissionProbe() rejected a probe after an unsolicited PONG")
	}
	if err := pump.consume(link.ControlMessage{Type: 2, Payload: probe[:]}); err != nil {
		t.Fatalf("legitimate PONG consume error = %v", err)
	}
	assertProbeDone(t, done, "legitimate PONG after unsolicited PONG")
}

// Acceptance: registration is owner-bound. A nil owner is rejected, and a
// ProbeID still pending under one pump cannot be re-registered by another.
func TestAdmissionProbeRegistrationsAreOwnerBound(t *testing.T) {
	n := admissionNetwork(t, "probe-register-token")
	owner := newProbeTestPump(n)
	probe := probePayload(0x44)

	if done, ok := n.registerAdmissionProbe(probe, nil); ok || done != nil {
		t.Fatal("registerAdmissionProbe() accepted a nil owner")
	}
	if got := pendingProbeCount(n); got != 0 {
		t.Fatalf("nil-owner registration created %d pending probes; want 0", got)
	}
	if _, ok := n.registerAdmissionProbe(probe, owner); !ok {
		t.Fatal("registerAdmissionProbe() rejected the real owner")
	}
	if _, ok := n.registerAdmissionProbe(probe, newProbeTestPump(n)); ok {
		t.Fatal("registerAdmissionProbe() reused an ID pending under another owner")
	}
}
