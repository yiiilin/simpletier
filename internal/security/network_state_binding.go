package security

// ContextID returns a value copy of the full 32-byte ContextID this runtime
// state was opened with. It lets later owners (for example a FactStore) reuse
// the exact local partition root that OpenNetworkState was opened with, instead of
// accepting a second caller-supplied ContextID that could silently disagree with it.
//
// The result is always a copy, never a pointer into the handle, and the handle
// lock is held only for the copy: no other method, disk or I/O call runs while
// it is held. A nil state, a zero value, a closed state or a state whose owner
// reservation is already gone fails with ErrNetworkStateClosed.
func (s *NetworkState) ContextID() ([32]byte, error) {
	if s == nil || s.handle == nil {
		return [32]byte{}, ErrNetworkStateClosed
	}
	h := s.handle
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.owner == nil {
		return [32]byte{}, ErrNetworkStateClosed
	}
	return h.owner.contextID, nil
}

// NodeID returns a value copy of the 16-byte NodeID bound from the borrowed
// IdentityStore when this runtime state was opened. Different ContextIDs on one
// store share this NodeID because they share the store identity, while the
// ContextID stays the isolation root.
//
// It has the same copy-only, short-lock and ErrNetworkStateClosed properties as
// ContextID.
func (s *NetworkState) NodeID() ([16]byte, error) {
	if s == nil || s.handle == nil {
		return [16]byte{}, ErrNetworkStateClosed
	}
	h := s.handle
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.owner == nil {
		return [16]byte{}, ErrNetworkStateClosed
	}
	return h.owner.nodeID, nil
}
