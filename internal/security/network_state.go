package security

import (
	"errors"
	"sync"
	"sync/atomic"
)

// Network runtime state is process-local: counters, records and the network
// incarnation live in memory and disappear with the process. It was previously
// written to a state directory so a restart resumed the same incarnation and
// sequence; that mode is gone, and a restart now begins a fresh incarnation.
//
// What remains enforced is everything that keeps one process consistent: a single
// owner per (scope, context), strictly monotonic counters that never repeat, record
// names and sizes bounded, and a closed handle refusing further use.

var (
	// ErrNetworkStateInUse reports that this process already owns the runtime state
	// for the same scope and full ContextID.
	ErrNetworkStateInUse = errors.New("network runtime state already in use")
	// ErrNetworkStateClosed reports use of a NetworkState handle after Close.
	ErrNetworkStateClosed = errors.New("network runtime state is closed")
	// ErrInvalidNetworkState reports invalid arguments or an unknown record.
	ErrInvalidNetworkState = errors.New("invalid network runtime state")
	// ErrNetworkVersionExhausted reports a u64 counter at its maximum. The counter
	// never wraps around; publication stops instead.
	ErrNetworkVersionExhausted = errors.New("network runtime version exhausted")
)

const (
	// maxNetworkStateRecordBytes is the upper bound a caller may request for a
	// bounded runtime record. It is a limit, not a preallocation.
	maxNetworkStateRecordBytes int64 = 32 << 20
	// networkStateRecordNameMax bounds record identifiers to short, single-segment
	// ASCII names.
	networkStateRecordNameMax = 64
)

// networkStateOwner is the single in-process reservation for one
// (scope, full ContextID) runtime state.
type networkStateOwner struct {
	key       string
	stateDir  string
	contextID [32]byte
	nodeID    [16]byte
}

// networkStateOwners is the same-process owner registry.
var networkStateOwners = struct {
	mu      sync.Mutex
	entries map[string]*networkStateOwner
}{entries: make(map[string]*networkStateOwner)}

// networkStateHandle is the shared close state behind every NetworkState copy.
type networkStateHandle struct {
	mu          sync.Mutex
	owner       *networkStateOwner
	identity    *IdentityStore // borrowed; Close never closes it
	closed      bool
	incarnation atomic.Uint64
}

// NetworkState is the one active runtime owner for a scope and a full ContextID.
// Copies of the value share one close state and one set of counters.
type NetworkState struct {
	handle *networkStateHandle
}

// OpenNetworkState reserves the single in-process runtime owner for
// (store scope, full ContextID) and fixes the network incarnation. The first
// incarnation is 1 and sequence/snapshot start at 0. A second owner for the same
// scope and ContextID fails with ErrNetworkStateInUse instead of sharing state.
// Different ContextIDs on one IdentityStore are independent. The identity handle is
// only borrowed and is never closed here.
func OpenNetworkState(store *IdentityStore, contextID [32]byte) (*NetworkState, error) {
	if store == nil || contextID == ([32]byte{}) {
		return nil, ErrInvalidNetworkState
	}
	scope, err := store.StateDir()
	if err != nil {
		return nil, err
	}
	identity, err := store.Identity()
	if err != nil {
		return nil, err
	}

	owner := &networkStateOwner{
		key:       scope + "\x00" + string(contextID[:]),
		stateDir:  scope,
		contextID: contextID,
		nodeID:    identity.NodeID,
	}

	networkStateOwners.mu.Lock()
	if _, exists := networkStateOwners.entries[owner.key]; exists {
		networkStateOwners.mu.Unlock()
		return nil, ErrNetworkStateInUse
	}
	networkStateOwners.entries[owner.key] = owner
	networkStateOwners.mu.Unlock()

	handle := &networkStateHandle{owner: owner, identity: store}
	// A zero incarnation is treated as "unset" by the fact store, so the first
	// incarnation is 1, matching the value the durable path used to write first.
	handle.incarnation.Store(1)
	return &NetworkState{handle: handle}, nil
}

// Incarnation returns the incarnation this handle was opened with.
func (s *NetworkState) Incarnation() uint64 {
	if s == nil || s.handle == nil {
		return 0
	}
	return s.handle.incarnation.Load()
}

// NextSequence advances the per-context sequence counter and returns the new value.
func (s *NetworkState) NextSequence() (uint64, error) {
	if s == nil || s.handle == nil {
		return 0, ErrNetworkStateClosed
	}
	if err := s.handle.checkOpen(); err != nil {
		return 0, err
	}
	return ephemeral.nextCounter(s.handle.owner.stateDir, s.handle.owner.contextID, 's')
}

// NextSnapshotVersion advances the per-context snapshot counter and returns the new
// value.
func (s *NetworkState) NextSnapshotVersion() (uint64, error) {
	if s == nil || s.handle == nil {
		return 0, ErrNetworkStateClosed
	}
	if err := s.handle.checkOpen(); err != nil {
		return 0, err
	}
	return ephemeral.nextCounter(s.handle.owner.stateDir, s.handle.owner.contextID, 'v')
}

// checkOpen reports whether this handle may still be used.
func (h *networkStateHandle) checkOpen() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return ErrNetworkStateClosed
	}
	return nil
}

// ReadRecord returns a stored record. An absent record reports fs.ErrNotExist so
// callers can tell "not written yet" from a real failure.
func (s *NetworkState) ReadRecord(name string, maxBytes int64) ([]byte, error) {
	if s == nil || s.handle == nil {
		return nil, ErrNetworkStateClosed
	}
	if err := s.handle.checkOpen(); err != nil {
		return nil, err
	}
	return ephemeral.readRecord(s.handle.owner.key, name, maxBytes)
}

// WriteRecord stores one bounded record under this owner.
func (s *NetworkState) WriteRecord(name string, data []byte, maxBytes int64) error {
	if s == nil || s.handle == nil {
		return ErrNetworkStateClosed
	}
	if err := s.handle.checkOpen(); err != nil {
		return err
	}
	return ephemeral.writeRecord(s.handle.owner.key, name, data, maxBytes)
}

// Close releases this handle. The owner slot is freed only when the last reference
// goes, so a second owner cannot be created while a copy is still live.
func (s *NetworkState) Close() error {
	if s == nil || s.handle == nil {
		return nil
	}
	h := s.handle
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	owner := h.owner
	h.mu.Unlock()

	networkStateOwners.mu.Lock()
	if current := networkStateOwners.entries[owner.key]; current == owner {
		delete(networkStateOwners.entries, owner.key)
	}
	networkStateOwners.mu.Unlock()
	return nil
}

// validateNetworkRecordName accepts a short single-segment ASCII name.
func validateNetworkRecordName(name string) error {
	if name == "" || len(name) > networkStateRecordNameMax {
		return ErrInvalidNetworkState
	}
	if name[0] == '.' || name[len(name)-1] == '.' {
		return ErrInvalidNetworkState
	}
	for index := 0; index < len(name); index++ {
		c := name[index]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return ErrInvalidNetworkState
		}
	}
	return nil
}

// validateNetworkRecordLimit rejects a nonsensical or unbounded request.
func validateNetworkRecordLimit(maxBytes int64) error {
	if maxBytes <= 0 || maxBytes > maxNetworkStateRecordBytes {
		return ErrInvalidNetworkState
	}
	return nil
}
