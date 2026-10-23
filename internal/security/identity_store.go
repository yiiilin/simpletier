package security

import (
	"errors"
	"sync"
)

// ErrIdentityStoreClosed reports use of an IdentityStore after Close.
var ErrIdentityStoreClosed = errors.New("identity store is closed")

// IdentityStore is one process-local identity.
//
// It used to be a lock over a state directory holding an on-disk keypair, so every
// Network in a process that shared that directory presented the same NodeID across
// restarts. That mode is gone: each store now generates its own keypair in memory,
// which means a restart presents a new NodeID and peers see a new node. That is the
// accepted trade of the ephemeral mode, and it is why a deployment that needs a
// stable identity must pin its address with RuntimeOptions.FixedIP instead of
// relying on a remembered NodeID.
//
// What is preserved is the in-process guarantee: two stores never share a key, so
// two Networks in one process are always distinct peers. Sharing one key would make
// a LINK fact name the same node on both ends, which the codec refuses outright.
type IdentityStore struct {
	mu       sync.Mutex
	identity *Identity
	scope    string
	closed   bool
}

// OpenIdentityStore creates a new in-memory identity with its own scope.
//
// scope stands in for the state directory that used to key the per-network counters
// and the link-epoch sequences. It must be unique per store: sharing it would let one
// Network consume another's epoch counter.
func OpenIdentityStore(_ ...string) (*IdentityStore, error) {
	identity, err := GenerateIdentity()
	if err != nil {
		return nil, err
	}
	return &IdentityStore{
		identity: &identity,
		scope:    ephemeral.nextScopeName(),
	}, nil
}

// Identity returns this store's identity.
func (s *IdentityStore) Identity() (Identity, error) {
	if s == nil {
		return Identity{}, ErrIdentityStoreClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.identity == nil {
		return Identity{}, ErrIdentityStoreClosed
	}
	return *s.identity, nil
}

// StateDir reports the scope this store keys its counters by. The name is kept so
// callers that thread a per-network key keep working; it is not a filesystem path
// and nothing is ever written to it.
func (s *IdentityStore) StateDir() (string, error) {
	if s == nil {
		return "", ErrIdentityStoreClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", ErrIdentityStoreClosed
	}
	return s.scope, nil
}

// Close releases this store. A closed store refuses further use.
func (s *IdentityStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.identity = nil
	return nil
}
