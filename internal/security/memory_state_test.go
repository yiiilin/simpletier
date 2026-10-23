package security

import (
	"testing"
)

// TestEphemeralEpochIsMonotonicPerScope pins the counter contract: strictly
// increasing per (context, lane), independent across lanes.
func TestEphemeralEpochIsMonotonicPerScope(t *testing.T) {
	ctxA := [32]byte{1}
	ctxB := [32]byte{2}

	first, err := NextLinkEpoch("ephemeral-test", ctxA, 0)
	if err != nil {
		t.Fatalf("NextLinkEpoch: %v", err)
	}
	second, err := NextLinkEpoch("ephemeral-test", ctxA, 0)
	if err != nil {
		t.Fatalf("NextLinkEpoch: %v", err)
	}
	if second <= first {
		t.Fatalf("epochs did not advance: %d then %d", first, second)
	}

	// A different lane must not observe the first lane's counter.
	otherLane, err := NextLinkEpoch("ephemeral-test", ctxA, 1)
	if err != nil {
		t.Fatalf("NextLinkEpoch lane 1: %v", err)
	}
	if otherLane != 1 {
		t.Fatalf("lane 1 started at %d; want 1 (lanes are independent)", otherLane)
	}

	// A different context must not observe the first context's counter.
	otherCtx, err := NextLinkEpoch("ephemeral-test", ctxB, 0)
	if err != nil {
		t.Fatalf("NextLinkEpoch ctx B: %v", err)
	}
	if otherCtx != 1 {
		t.Fatalf("context B started at %d; want 1 (contexts are independent)", otherCtx)
	}
}

// TestEphemeralFloorRejectsRollbackAndReplay pins the receiver side: an epoch below
// the admitted floor is refused, an exact retry is idempotent, and a same-epoch
// attempt with different launch details is a replay.
func TestEphemeralFloorRejectsRollbackAndReplay(t *testing.T) {
	contextID := [32]byte{7}
	initiator := [16]byte{9}
	transcript := [32]byte{3}

	if err := AcceptLinkEpoch("ephemeral-test", contextID, initiator, 0, 10, 5, transcript); err != nil {
		t.Fatalf("first accept: %v", err)
	}

	// Exact retry of the same launch is idempotent.
	if err := AcceptLinkEpoch("ephemeral-test", contextID, initiator, 0, 10, 5, transcript); err != nil {
		t.Fatalf("exact retry: %v", err)
	}

	// A lower epoch is a rollback attempt.
	if err := AcceptLinkEpoch("ephemeral-test", contextID, initiator, 0, 11, 4, transcript); err == nil {
		t.Fatal("rollback to epoch 4 was accepted")
	}

	// Same epoch, different transcript: replayed under a new launch.
	otherTranscript := [32]byte{4}
	if err := AcceptLinkEpoch("ephemeral-test", contextID, initiator, 0, 10, 5, otherTranscript); err == nil {
		t.Fatal("same epoch with a different transcript was accepted")
	}

	// A higher epoch advances the floor.
	if err := AcceptLinkEpoch("ephemeral-test", contextID, initiator, 0, 12, 6, transcript); err != nil {
		t.Fatalf("advance to epoch 6: %v", err)
	}
}

// TestEphemeralRejectsZeroScope pins the input guards, which the disk path also
// enforces.
func TestEphemeralRejectsZeroScope(t *testing.T) {
	contextID := [32]byte{1}
	initiator := [16]byte{1}
	transcript := [32]byte{1}

	if _, err := NextLinkEpoch("ephemeral-test", [32]byte{}, 0); err == nil {
		t.Fatal("NextLinkEpoch accepted a zero context")
	}
	if err := AcceptLinkEpoch("ephemeral-test", contextID, [16]byte{}, 0, 1, 1, transcript); err == nil {
		t.Fatal("AcceptLinkEpoch accepted a zero initiator")
	}
	if err := AcceptLinkEpoch("ephemeral-test", contextID, initiator, 0, 0, 1, transcript); err == nil {
		t.Fatal("AcceptLinkEpoch accepted a zero link id")
	}
	if err := AcceptLinkEpoch("ephemeral-test", contextID, initiator, 0, 1, 0, transcript); err == nil {
		t.Fatal("AcceptLinkEpoch accepted a zero epoch")
	}
	if err := AcceptLinkEpoch("ephemeral-test", contextID, initiator, 0, 1, 1, [32]byte{}); err == nil {
		t.Fatal("AcceptLinkEpoch accepted an empty transcript")
	}
}
