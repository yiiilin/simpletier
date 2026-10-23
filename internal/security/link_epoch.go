package security

import (
	"errors"
)

// Link epoch state is process-local. It was previously persisted under a state
// directory so a restart could not forget the receiver floor, but that mode is
// gone: a Network now keeps no files, and a restart renegotiates every Link.
//
// The invariants that protect against replay are unchanged and still enforced
// here. Only durability is dropped, which means an attacker who recorded a
// handshake could replay it after the process restarts. That is the accepted
// trade of the ephemeral mode: it fits a trusted deployment where peers rejoin
// rather than resume, and it is not appropriate where an attacker can both
// record traffic and force a restart.

var (
	// ErrInvalidLinkEpoch reports an invalid scope, counter or transcript input.
	ErrInvalidLinkEpoch = errors.New("invalid link epoch state")
	// ErrLinkEpochExhausted reports that the monotonic counter reached its ceiling.
	ErrLinkEpochExhausted = errors.New("link epoch exhausted")
	// ErrLinkEpochReplay reports an authenticated Link attempt below the admitted
	// receiver floor, or a conflicting LinkID/transcript at the same epoch.
	ErrLinkEpochReplay = errors.New("replayed link epoch")
	// ErrLinkEpochUnbound reports a same-epoch attempt whose remembered floor has no
	// transcript binding, so admission fails closed.
	ErrLinkEpochUnbound = errors.New("link epoch floor lacks transcript binding")
)

// NextLinkEpoch allocates the next epoch for one (scope, context, lane).
//
// The counter is strictly monotonic per key and never repeats. Gaps are allowed;
// zero and wraparound are not. scope separates independent Networks in one
// process, so two peers cannot consume each other's sequence.
func NextLinkEpoch(scope string, contextID [32]byte, laneID uint8) (uint64, error) {
	if scope == "" || contextID == [32]byte{} || laneID > 2 {
		return 0, ErrInvalidLinkEpoch
	}
	return ephemeral.nextEpoch(scope, contextID, laneID)
}

// AcceptLinkEpoch admits an already authenticated incoming Link.
//
// The floor is isolated by (scope, context, initiator, lane) and never moves
// backwards. An exact retry of the admitted launch is idempotent; the same epoch
// with different launch details is a replay. transcriptHash must be SHA-256 of the
// authenticated Noise ChannelBinding, which binds the full descriptor and Link
// tuple, so a same-epoch replay cannot forge it.
func AcceptLinkEpoch(scope string, contextID [32]byte, initiatorNodeID [16]byte, laneID uint8, linkID, epoch uint64, transcriptHash [32]byte) error {
	if scope == "" || contextID == [32]byte{} || initiatorNodeID == [16]byte{} || laneID > 2 ||
		linkID == 0 || epoch == 0 || transcriptHash == [32]byte{} {
		return ErrInvalidLinkEpoch
	}
	return ephemeral.acceptFloor(scope, contextID, initiatorNodeID, laneID, linkID, epoch, transcriptHash)
}
