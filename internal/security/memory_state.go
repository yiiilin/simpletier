package security

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"sync"
	"sync/atomic"
)

// memoryState is the process-wide store behind every Network runtime.
//
// It exists so an ephemeral deployment pays no filesystem cost while keeping every
// validation rule intact. The rules that matter for correctness — monotonic link
// epochs, the receiver floor, per-lane serialization, record size limits — are
// enforced exactly as before; only the medium changes, from files to process
// memory. The trade is durability: nothing here survives the process, so a restart
// forgets identities, epochs and sequences and the peers renegotiate from scratch.
// That is the documented contract of the ephemeral mode, not a silent weakening.
//
// Keys embed the caller's scope, so two Networks in one process never observe each
// other's counters.
type memoryState struct {
	mu          sync.Mutex
	epochs      map[[32]byte]uint64   // initiator: next link epoch per (context, lane)
	floors      map[[32]byte]floorKey // receiver: admitted floor per (context, initiator, lane)
	floorValues map[[32]byte]floorValue
	sequences   map[[32]byte]uint64 // per (context) counter sets
	records     map[[32]byte]map[string][]byte
	// ephemeralSeq distinguishes ephemeral NetworkState owners, which have no state
	// directory to key them by.
	ephemeralSeq uint64
}

// floorKey names the receiver-side floor scope: context, initiator and lane.
type floorKey struct {
	context   [32]byte
	initiator [16]byte
	lane      uint8
}

var ephemeral = &memoryState{
	epochs:      make(map[[32]byte]uint64),
	floors:      make(map[[32]byte]floorKey),
	floorValues: make(map[[32]byte]floorValue),
	sequences:   make(map[[32]byte]uint64),
	records:     make(map[[32]byte]map[string][]byte),
}

// errEphemeralExhausted reports that a monotonic counter reached its ceiling. It
// mirrors ErrLinkEpochExhausted for the in-memory path.
var errEphemeralExhausted = errors.New("security: monotonic counter exhausted")

// scopeKey derives a map key that includes the caller's scope, so two Networks in
// one process never share a counter or a floor. The scope stands in for the state
// directory the disk path keys by, and omitting it is not a cosmetic difference: it
// would let one peer's epoch allocation advance another peer's floor.
func scopeKey(scope string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(scope))
	for _, part := range parts {
		h.Write(part)
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

// nextEpoch allocates the next initiator epoch for (context, lane).
func (m *memoryState) nextEpoch(scope string, contextID [32]byte, laneID uint8) (uint64, error) {
	key := scopeKey(scope, contextID[:], []byte{laneID})
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.epochs[key]
	if current == ^uint64(0) {
		return 0, errEphemeralExhausted
	}
	next := current + 1
	m.epochs[key] = next
	return next, nil
}

// acceptFloor admits an incoming epoch for (context, initiator, lane) if it is
// strictly above the remembered floor. Semantics match the on-disk receiver floor:
// the value never moves backwards, and a retry at the current epoch is refused
// because the LinkID and transcript must match exactly.
func (m *memoryState) acceptFloor(scope string, contextID [32]byte, initiator [16]byte, laneID uint8, linkID, epoch uint64, transcript [32]byte) error {
	key := scopeKey(scope, contextID[:], initiator[:], []byte{laneID})
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.floors[key]; ok {
		previous := m.floorValues[key]
		if epoch < previous.epoch {
			// Below the admitted floor is the replay case the disk path also rejects.
			return ErrLinkEpochReplay
		}
		if epoch == previous.epoch {
			switch {
			case previous.linkID == linkID && previous.transcript == transcript:
				// An exact retry of the admitted launch is idempotent.
				return nil
			case !previous.hasTranscript:
				return ErrLinkEpochUnbound
			default:
				return ErrLinkEpochReplay
			}
		}
	}
	m.floors[key] = floorKey{context: contextID, initiator: initiator, lane: laneID}
	m.floorValues[key] = floorValue{
		epoch: epoch, linkID: linkID, transcript: transcript, hasTranscript: true,
	}
	return nil
}

// newIdentity generates a fresh ephemeral identity.
//
// One identity per store, never one per process: the disk path gives每个 state
// directory its own key, and a shared key would make two Networks in one process
// claim the same NodeID. Two peers that present the same identity cannot form a
// LINK fact at all - From and To would be the same node - so this is not a
// cosmetic difference.
func (m *memoryState) newIdentity() (Identity, error) {
	return GenerateIdentity()
}

// readRecord returns a stored record, or ErrInvalidNetworkState when absent.
func (m *memoryState) readRecord(ownerKey, name string, maxBytes int64) ([]byte, error) {
	if err := validateNetworkRecordName(name); err != nil {
		return nil, err
	}
	if err := validateNetworkRecordLimit(maxBytes); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	byOwner := m.records[recordOwnerKey(ownerKey)]
	if byOwner == nil {
		// Match the disk path: an absent record is "not there yet", which callers use
		// to decide this is the first use of the state.
		return nil, fs.ErrNotExist
	}
	stored, ok := byOwner[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	if int64(len(stored)) > maxBytes {
		return nil, ErrInvalidNetworkState
	}
	return append([]byte(nil), stored...), nil
}

// failWrites is the test seam for injecting a write failure. Production never sets
// it; a test sets it to prove that a persistence failure surfaces as a sticky store
// error instead of being silently ignored.
var failWrites atomic.Bool

// writeRecord stores a record under one owner, enforcing the same size ceiling the
// disk path enforces.
func (m *memoryState) writeRecord(ownerKey, name string, data []byte, maxBytes int64) error {
	if err := validateNetworkRecordName(name); err != nil {
		return err
	}
	if err := validateNetworkRecordLimit(maxBytes); err != nil {
		return err
	}
	if int64(len(data)) > maxBytes {
		return ErrInvalidNetworkState
	}
	if failWrites.Load() {
		// Wrap the same error a real state failure produces, so callers that classify
		// on ErrInvalidNetworkState keep working.
		return fmt.Errorf("injected record write failure: %w", ErrInvalidNetworkState)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := recordOwnerKey(ownerKey)
	byOwner := m.records[key]
	if byOwner == nil {
		byOwner = make(map[string][]byte)
		m.records[key] = byOwner
	}
	byOwner[name] = append([]byte(nil), data...)
	return nil
}

// recordOwnerKey maps an owner key string to a fixed-size map key.
func recordOwnerKey(ownerKey string) [32]byte {
	return sha256.Sum256([]byte(ownerKey))
}

// nextScopeName returns a unique token identifying one identity store. It is not a
// path: callers that key per-network state by it must not open a file under it.
func (m *memoryState) nextScopeName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ephemeralSeq++
	return "ephemeral://" + strconv.FormatUint(m.ephemeralSeq, 10)
}

// nextEphemeralScope returns a fresh identifier for one runtime owner. Owners used to
// be keyed by their state directory; with no directory, this counter is what keeps two
// Networks on the same context from colliding.
func (m *memoryState) nextEphemeralScope() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ephemeralSeq++
	return m.ephemeralSeq
}

// nextCounter advances one monotonic counter for a (context, kind) scope. kind
// separates the sequence and snapshot counters of the same context.
func (m *memoryState) nextCounter(scope string, contextID [32]byte, kind byte) (uint64, error) {
	key := scopeKey(scope, contextID[:], []byte{kind})
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.sequences[key]
	if current == ^uint64(0) {
		return 0, errEphemeralExhausted
	}
	next := current + 1
	m.sequences[key] = next
	return next, nil
}

// floorValue is the remembered admission for one scope.
type floorValue struct {
	epoch         uint64
	linkID        uint64
	transcript    [32]byte
	hasTranscript bool
}

// SetRecordWriteFailureForTest makes every subsequent record write fail until the
// test ends, which is how a test proves a persistence failure becomes a sticky store
// error rather than a silently ignored one.
func SetRecordWriteFailureForTest(t interface{ Cleanup(func()) }, enabled bool) {
	if !enabled {
		return
	}
	previous := failWrites.Swap(true)
	t.Cleanup(func() { failWrites.Store(previous) })
}

// NewIdentityStoreForTest builds a store from a caller-supplied identity, so a test
// can pin a deterministic NodeID instead of accepting a random one. Production uses
// OpenIdentityStore, which always generates a fresh key.
func NewIdentityStoreForTest(privateKey [32]byte) (*IdentityStore, error) {
	identity, err := identityFromPrivateKey(privateKey[:])
	if err != nil {
		return nil, err
	}
	return &IdentityStore{
		identity: &identity,
		scope:    ephemeral.nextScopeName(),
	}, nil
}

// AllocatedLinkEpochForTest reports the last epoch allocated for one scope, context
// and lane. It exists so an admission test can observe the allocation the same way it
// used to observe the record that used to be written to disk.
func AllocatedLinkEpochForTest(scope string, contextID [32]byte, laneID uint8) uint64 {
	key := scopeKey(scope, contextID[:], []byte{laneID})
	ephemeral.mu.Lock()
	defer ephemeral.mu.Unlock()
	return ephemeral.epochs[key]
}

// ReceiverFloorForTest reports the admitted receiver floor for one scope, context,
// initiator and lane. It exists so a test can observe the floor the way it used to
// observe the receiver floor; the zero value means nothing was admitted yet.
func ReceiverFloorForTest(scope string, contextID [32]byte, initiator [16]byte, laneID uint8) (epoch, linkID uint64, ok bool) {
	key := scopeKey(scope, contextID[:], initiator[:], []byte{laneID})
	ephemeral.mu.Lock()
	defer ephemeral.mu.Unlock()
	value, found := ephemeral.floorValues[key]
	return value.epoch, value.linkID, found
}

// RuntimeOwnerHeldForTest reports whether the runtime owner behind a NetworkState is
// still registered. A test uses it to prove the reservation survives a CloseTimeout.
func RuntimeOwnerHeldForTest(state *NetworkState) bool {
	if state == nil || state.handle == nil || state.handle.owner == nil {
		return false
	}
	key := state.handle.owner.key
	networkStateOwners.mu.Lock()
	defer networkStateOwners.mu.Unlock()
	_, held := networkStateOwners.entries[key]
	return held
}
