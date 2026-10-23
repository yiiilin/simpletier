package security

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
)

// ErrInvalidLinkAttempt reports an invalid serialization-gate key. It is a
// caller bug, not a replay: the gate never invents a key.
var ErrInvalidLinkAttempt = errors.New("invalid link attempt")

// linkAttemptGateEntry is one in-process serialization slot. token has capacity
// one and is filled while the slot is free, so a waiter blocks in a select that
// can also observe context cancellation. refs counts the current holder plus
// every waiting acquirer; the entry is deleted from the global map as soon as
// refs reaches zero, so the map cannot grow without bound.
type linkAttemptGateEntry struct {
	token chan struct{}
	refs  int
}

var linkAttemptGates = struct {
	mu      sync.Mutex
	entries map[string]*linkAttemptGateEntry
}{entries: make(map[string]*linkAttemptGateEntry)}

// LinkAttemptLease is the right to allocate and admit one CONTROL Link attempt
// for a (runtime scope, full ContextID, Lane) key. Release is idempotent; the zero
// value is not a valid lease.
//
// The lease owns a heap-allocated state rather than embedding sync.Once, so a
// value copy of the lease shares one Once and Release stays idempotent across
// copies.
type LinkAttemptLease struct {
	state *linkAttemptLeaseState
}

// linkAttemptLeaseState is shared by every copy of a LinkAttemptLease.
type linkAttemptLeaseState struct {
	once sync.Once
	gate *linkAttemptGateEntry
	key  string
}

// AcquireLinkAttempt serializes sender-side epoch allocation through admission
// completion for one runtime scope, full ContextID and Lane. It is process-wide
// because two handles onto the same runtime must share one ordering even when they
// are separate values.
//
// Waiting is cancellable through ctx and holds no identity-store or Network
// lock while blocked. Different ContextIDs or Lanes use different slots and do
// not block each other. A failed acquisition leaves no map entry behind.
func AcquireLinkAttempt(ctx context.Context, scope string, contextID [32]byte, laneID uint8) (*LinkAttemptLease, error) {
	if ctx == nil || scope == "" || contextID == [32]byte{} || laneID > 2 {
		return nil, ErrInvalidLinkAttempt
	}
	key := linkAttemptKey(scope, contextID, laneID)

	linkAttemptGates.mu.Lock()
	entry := linkAttemptGates.entries[key]
	if entry == nil {
		entry = &linkAttemptGateEntry{token: make(chan struct{}, 1)}
		entry.token <- struct{}{}
		linkAttemptGates.entries[key] = entry
	}
	entry.refs++
	linkAttemptGates.mu.Unlock()

	select {
	case <-entry.token:
		// A cancellation that races with the token must not leak the slot: this
		// acquirer did win the token, so it returns it as the holder.
		if err := ctx.Err(); err != nil {
			releaseLinkAttempt(entry, key, true)
			return nil, err
		}
		return &LinkAttemptLease{state: &linkAttemptLeaseState{gate: entry, key: key}}, nil
	case <-ctx.Done():
		// This waiter never owned the token, so dropping its reference must not
		// manufacture one while the current holder still owns the slot.
		releaseLinkAttempt(entry, key, false)
		return nil, ctx.Err()
	}
}

// Release hands the slot to the next waiter or deletes the map entry when no
// waiter remains. It is safe to call more than once, including on a value copy.
func (l *LinkAttemptLease) Release() {
	if l == nil || l.state == nil {
		return
	}
	l.state.once.Do(func() { releaseLinkAttempt(l.state.gate, l.state.key, true) })
}

// releaseLinkAttempt drops one reference held by the caller. held reports
// whether that reference owned the token. Only a token owner may hand the slot
// to the next waiter; a waiter that cancelled (or timed out) before taking the
// token must not push a token, because doing so while the holder still owns the
// slot lets two acquirers hold it concurrently.
func releaseLinkAttempt(entry *linkAttemptGateEntry, key string, held bool) {
	linkAttemptGates.mu.Lock()
	defer linkAttemptGates.mu.Unlock()
	entry.refs--
	if entry.refs <= 0 {
		if linkAttemptGates.entries[key] == entry {
			delete(linkAttemptGates.entries, key)
		}
		return
	}
	if !held {
		return
	}
	// The holder owned the only token, so this is the single handoff. The channel
	// is buffered for a waiter that has not reached its select yet; the default is
	// unreachable while at most one holder exists and is not a correctness
	// mechanism, only a guard against blocking under the gate lock.
	select {
	case entry.token <- struct{}{}:
	default:
	}
}

// linkAttemptKey scopes the serialization gate by the caller's own runtime scope, not
// just by context and lane. Two Networks can share a context — the same name and CIDR
// derive the same ContextID — while being independent peers; keying only on the context
// made every such Network serialize its CONTROL handshakes behind one another, which
// presented as a fixed per-peer delay under load.
func linkAttemptKey(scope string, contextID [32]byte, laneID uint8) string {
	var lane [1]byte
	lane[0] = laneID
	return scope + "\x00" + hex.EncodeToString(contextID[:]) + "\x00" + string(lane[:])
}
