package flow

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/yiiilin/simpletier/internal/topology"
)

// Role is the association's position: the originator generated the
// AssociationID and sends REQUESTs, the target spends REPLYs.
type Role uint8

const (
	RoleOrigin Role = iota + 1
	RoleTarget
)

func (r Role) String() string {
	switch r {
	case RoleOrigin:
		return "origin"
	case RoleTarget:
		return "target"
	default:
		return fmt.Sprintf("role(%d)", uint8(r))
	}
}

// peerState is the inbound state of one authenticated remote node for one
// association and direction: at most one incomplete assembly (per the frozen
// "one incomplete per (NetworkID,SrcNodeID,AssociationID,direction)") and its
// 1024-bit DatagramID window.
type peerState struct {
	assemblies [2]*assembly
	replay     [2]replayWindow
}

// assembly is one in-progress two-fragment reassembly. first is the TTL origin
// and is never extended by later fragments.
type assembly struct {
	id       uint64
	flags    Flags
	count    uint8
	total    uint16
	source   netip.AddrPort
	dest     netip.AddrPort
	first    time.Time
	reserved uint64
	buf      []byte
	filled   [2]bool
	received int
}

func newAssembly(fragment Fragment, now time.Time) *assembly {
	return &assembly{
		id:       fragment.DatagramID,
		flags:    fragment.Flags,
		count:    fragment.FragmentCount,
		total:    fragment.TotalPayloadLen,
		source:   fragment.Source,
		dest:     fragment.Destination,
		first:    now,
		reserved: uint64(fragment.TotalPayloadLen),
		buf:      make([]byte, int(fragment.TotalPayloadLen)),
	}
}

// matches reports whether a fragment's metadata agrees with the retained
// assembly; any disagreement, including the declared fragment_count, is a
// terminal conflict.
func (a *assembly) matches(fragment Fragment) bool {
	return a.flags == fragment.Flags &&
		a.count == fragment.FragmentCount &&
		a.total == fragment.TotalPayloadLen &&
		a.source == fragment.Source &&
		a.dest == fragment.Destination
}

// Association is one UDP association on one node. All exported methods are safe
// for concurrent use.
type Association struct {
	mgr      *Manager
	id       AssocID
	role     Role
	peer     topology.NodeID // originator for a target association
	inbound  Flags
	outbound Flags

	nextID       uint64
	peers        map[topology.NodeID]*peerState
	lastActivity time.Time
	ledgerHeld   bool
	closed       bool
}

func newAssociation(m *Manager, id AssocID, role Role, peer topology.NodeID) *Association {
	a := &Association{
		mgr:          m,
		id:           id,
		role:         role,
		peer:         peer,
		peers:        make(map[topology.NodeID]*peerState),
		lastActivity: m.now(),
	}
	switch role {
	case RoleOrigin:
		a.inbound, a.outbound = FlagReply, FlagRequest
	case RoleTarget:
		a.inbound, a.outbound = FlagRequest, FlagReply
	}
	return a
}

// ID returns the association's CSPRNG identifier.
func (a *Association) ID() AssocID { return a.id }

// Role returns origin or target.
func (a *Association) Role() Role { return a.role }

// Fragment validates one complete logical UDP datagram, assigns the next
// monotonic DatagramID, pins one PACKET-lane route and dispatches each of the
// one or two fragments through the Sender. Both fragments always use the same
// pinned Path/Session; the Sender never retransmits or re-routes a lost
// fragment.
func (a *Association) Fragment(ctx context.Context, datagram OutboundDatagram) error {
	m := a.mgr
	if err := validateEndpoint(datagram.Source); err != nil {
		m.drop(DropSchema)
		return err
	}
	if err := validateEndpoint(datagram.Destination); err != nil {
		m.drop(DropSchema)
		return err
	}
	if len(datagram.Payload) > MaxDatagramPayload {
		m.drop(DropTooLarge)
		return fmt.Errorf("%w: %d bytes exceeds %d", ErrDatagramTooLarge, len(datagram.Payload), MaxDatagramPayload)
	}
	owner, ok := m.cfg.Endpoints.LookupEndpoint(ctx, datagram.Source.Addr())
	if !ok || owner.Owner != m.cfg.LocalNode {
		m.drop(DropOwnership)
		return fmt.Errorf("%w: source %s is not a currently owned local endpoint", ErrOwnership, datagram.Source)
	}
	route, err := m.pinRoute(ctx, datagram.Destination.Addr())
	if err != nil {
		return err
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		m.drop(DropClosed)
		return ErrClosed
	}
	if a.closed {
		m.mu.Unlock()
		m.drop(DropClosed)
		return ErrAssociationClosed
	}
	if a.nextID == uint64(math.MaxUint64) {
		// Exhaustion is terminal and must run the same close-once cleanup as
		// Close: release every assembly and the reservation, retire the identity
		// and leave the maps, so a later Close cannot see an early-returned
		// closed flag while the slot or ledger record leaks.
		a.closeLocked()
		if a.role == RoleOrigin {
			delete(m.origins, a.id)
		} else {
			key := targetKey{origin: a.peer, id: a.id}
			delete(m.targets, key)
			m.noteTargetTombstoneLocked(key)
		}
		m.mu.Unlock()
		m.drop(DropResource)
		return ErrDatagramIDExhausted
	}
	a.lastActivity = m.now()
	a.nextID++
	datagramID := a.nextID
	m.mu.Unlock()

	count, err := FragmentCount(len(datagram.Payload))
	if err != nil {
		m.drop(DropTooLarge)
		return err
	}
	for index := 0; index < int(count); index++ {
		offset, length := fragmentSlice(len(datagram.Payload), index)
		fragment := Fragment{
			AssociationID:   a.id,
			Flags:           a.outbound,
			DatagramID:      datagramID,
			FragmentIndex:   uint8(index),
			FragmentCount:   count,
			TotalPayloadLen: uint16(len(datagram.Payload)),
			Source:          datagram.Source,
			Destination:     datagram.Destination,
			Payload:         datagram.Payload[offset : offset+length],
		}
		if err := m.recheckRoute(ctx, datagram.Destination.Addr(), route); err != nil {
			return err
		}
		encoded, err := EncodeFragment(fragment)
		if err != nil {
			m.drop(DropSchema)
			return err
		}
		request := SendRequest{
			NetworkID:       m.cfg.NetworkID,
			SrcNodeID:       m.cfg.LocalNode,
			DstNodeID:       route.DestinationNode,
			AssociationID:   a.id,
			Flags:           a.outbound,
			DatagramID:      datagramID,
			FragmentIndex:   uint8(index),
			FragmentCount:   count,
			TotalPayloadLen: uint16(len(datagram.Payload)),
			PathID:          route.PathID,
			PathGeneration:  route.PathGeneration,
			Lane:            route.Lane,
			Payload:         encoded,
		}
		if err := m.cfg.Sender.SendFragment(ctx, request); err != nil {
			m.drop(DropSend)
			return err
		}
		m.sentFragments.Add(1)
	}
	m.sentDatagrams.Add(1)
	return nil
}

// Receive is the inbound entry for one already-authenticated UDP_DATAGRAM
// plaintext frame addressed to this association. It revalidates ownership, then
// reassembles.
func (a *Association) Receive(ctx context.Context, envelope AuthenticatedEnvelope, raw []byte) error {
	fragment, err := DecodeFragment(raw)
	if err != nil {
		a.mgr.drop(DropSchema)
		a.mgr.consumeSchemaDrop(envelope, raw)
		return err
	}
	if fragment.AssociationID != a.id {
		a.mgr.drop(DropOwnership)
		return fmt.Errorf("%w: fragment association %s is not this association %s", ErrOwnership, fragment.AssociationID, a.id)
	}
	if a.role == RoleTarget && envelope.SrcNodeID != a.peer {
		a.mgr.drop(DropOwnership)
		return fmt.Errorf("%w: target association %s belongs to originator %s, not %s", ErrOwnership, a.id, a.peer, envelope.SrcNodeID)
	}
	if err := a.mgr.validateInbound(ctx, envelope, fragment); err != nil {
		return err
	}
	return a.receive(ctx, envelope, fragment)
}

// receive applies the frozen reassembly rules under the manager lock and calls
// Delivery outside it.
func (a *Association) receive(ctx context.Context, envelope AuthenticatedEnvelope, fragment Fragment) error {
	m := a.mgr
	m.mu.Lock()
	if m.closed || a.closed {
		m.mu.Unlock()
		m.drop(DropClosed)
		return ErrAssociationClosed
	}
	if fragment.Flags != a.inbound {
		m.mu.Unlock()
		m.drop(DropOwnership)
		return fmt.Errorf("%w: flags %s do not match the %s association's inbound direction %s",
			ErrOwnership, fragment.Flags, a.role, a.inbound)
	}
	m.receivedFragments.Add(1)
	direction := int(fragment.Flags)
	ps := a.peers[envelope.SrcNodeID]
	if ps == nil {
		if len(a.peers) >= MaxPeersPerAssociation {
			m.mu.Unlock()
			m.drop(DropResource)
			return fmt.Errorf("%w: %d peers per association", ErrResourceLimit, MaxPeersPerAssociation)
		}
		ps = &peerState{}
		a.peers[envelope.SrcNodeID] = ps
	}
	now := m.now()
	if as := ps.assemblies[direction]; as != nil && !now.Before(as.first.Add(AssociationIdleTTL)) {
		a.terminateLocked(ps, direction, DropTimeout)
	}
	window := &ps.replay[direction]
	if window.consumed(fragment.DatagramID) {
		m.mu.Unlock()
		m.drop(DropDuplicate)
		return nil
	}
	if as := ps.assemblies[direction]; as != nil && as.id != fragment.DatagramID {
		if fragment.DatagramID > as.id {
			a.terminateLocked(ps, direction, DropSuperseded)
		} else {
			window.consume(fragment.DatagramID)
			m.mu.Unlock()
			m.drop(DropSuperseded)
			return nil
		}
	}
	// A same-DatagramID fragment must agree with the retained assembly before
	// any delivery path, including a single-fragment descriptor: a count=1
	// frame can otherwise deliver and consume the ID while the original
	// two-fragment assembly stays reserved. Any metadata disagreement is a
	// terminal conflict.
	if as := ps.assemblies[direction]; as != nil && as.id == fragment.DatagramID && !as.matches(fragment) {
		a.terminateLocked(ps, direction, DropConflict)
		m.mu.Unlock()
		return fmt.Errorf("%w: fragment metadata conflicts with the retained assembly of datagram %d", ErrFrameMalformed, fragment.DatagramID)
	}
	if fragment.FragmentCount == 1 {
		a.lastActivity = now
		window.consume(fragment.DatagramID)
		m.mu.Unlock()
		a.deliver(ctx, envelope, fragment, fragment.Payload)
		return nil
	}

	as := ps.assemblies[direction]
	if as == nil || as.id != fragment.DatagramID {
		if err := m.reserveAssemblySlot(); err != nil {
			window.consume(fragment.DatagramID)
			m.mu.Unlock()
			m.drop(DropResource)
			return err
		}
		if err := m.reserve(uint64(fragment.TotalPayloadLen)); err != nil {
			m.releaseAssemblySlot()
			window.consume(fragment.DatagramID)
			m.mu.Unlock()
			m.drop(DropResource)
			return err
		}
		as = newAssembly(fragment, now)
		ps.assemblies[direction] = as
	} else if !as.matches(fragment) {
		a.terminateLocked(ps, direction, DropConflict)
		m.mu.Unlock()
		return fmt.Errorf("%w: fragment metadata conflicts with datagram %d", ErrFrameMalformed, fragment.DatagramID)
	}

	index := int(fragment.FragmentIndex)
	offset, _ := fragmentSlice(int(as.total), index)
	if as.filled[index] {
		if !bytes.Equal(as.buf[offset:offset+len(fragment.Payload)], fragment.Payload) {
			a.terminateLocked(ps, direction, DropConflict)
			m.mu.Unlock()
			return fmt.Errorf("%w: duplicate fragment index %d carries different bytes", ErrFrameMalformed, index)
		}
		m.mu.Unlock()
		m.drop(DropDuplicate)
		return nil
	}
	copy(as.buf[offset:], fragment.Payload)
	a.lastActivity = now
	as.filled[index] = true
	as.received++
	if as.received < int(fragment.FragmentCount) {
		m.mu.Unlock()
		return nil
	}

	payload := as.buf
	reserved := as.reserved
	ps.assemblies[direction] = nil
	m.releaseAssemblySlot()
	window.consume(fragment.DatagramID)
	m.mu.Unlock()
	a.deliver(ctx, envelope, fragment, payload)
	m.release(reserved)
	return nil
}

// discardLocked removes the retained incomplete assembly of one direction:
// the DatagramID is consumed, the buffer reservation released and the aggregate
// assembly slot returned.
func (a *Association) discardLocked(ps *peerState, direction int) *assembly {
	as := ps.assemblies[direction]
	if as == nil {
		return nil
	}
	ps.assemblies[direction] = nil
	ps.replay[direction].consume(as.id)
	a.mgr.releaseAssemblySlot()
	a.mgr.release(as.reserved)
	return as
}

// terminateLocked terminal-discards the retained incomplete assembly and counts
// the reason.
func (a *Association) terminateLocked(ps *peerState, direction int, reason DropReason) {
	if a.discardLocked(ps, direction) != nil {
		a.mgr.drop(reason)
	}
}

// deliver hands one complete datagram to the endpoint port. It runs outside the
// manager lock because Delivery performs I/O; the DatagramID is already
// consumed whether or not the write succeeds.
func (a *Association) deliver(ctx context.Context, envelope AuthenticatedEnvelope, fragment Fragment, payload []byte) {
	datagram := Datagram{
		NetworkID:     envelope.NetworkID,
		SrcNodeID:     envelope.SrcNodeID,
		DstNodeID:     envelope.DstNodeID,
		AssociationID: a.id,
		Flags:         fragment.Flags,
		DatagramID:    fragment.DatagramID,
		Source:        fragment.Source,
		Destination:   fragment.Destination,
		Payload:       payload,
	}
	// Only an authenticated REQUEST delivered to a live target association
	// carries reply authority; the receipt binds that exact tuple.
	if fragment.Flags == FlagRequest && a.role == RoleTarget {
		datagram.receipt = &replyReceipt{
			manager:       a.mgr,
			association:   a,
			networkID:     envelope.NetworkID,
			origin:        envelope.SrcNodeID,
			associationID: a.id,
			datagramID:    fragment.DatagramID,
			source:        fragment.Source,
			destination:   fragment.Destination,
		}
	}
	if err := a.mgr.cfg.Delivery.DeliverDatagram(ctx, datagram); err != nil {
		a.mgr.drop(DropDelivery)
		return
	}
	a.mgr.deliveredDatagrams.Add(1)
	a.mgr.deliveredBytes.Add(uint64(len(payload)))
}

// sweepLocked expires every retained assembly of this association.
func (a *Association) sweepLocked(now time.Time) {
	for _, ps := range a.peers {
		for direction := 0; direction < 2; direction++ {
			if as := ps.assemblies[direction]; as != nil && !now.Before(as.first.Add(AssociationIdleTTL)) {
				a.terminateLocked(ps, direction, DropTimeout)
			}
		}
	}
}

// Close releases the association. An originator's AssociationID stays recorded
// as a recently-closed identity for AssociationIdleTTL so it is never reused
// early; the record slot was reserved at creation, so Close cannot lose it. The
// error return is defensive only.
func (a *Association) Close() error {
	m := a.mgr
	m.mu.Lock()
	defer m.mu.Unlock()
	if a.closed {
		return nil
	}
	recorded := a.closeLocked()
	if a.role == RoleOrigin {
		delete(m.origins, a.id)
	} else {
		key := targetKey{origin: a.peer, id: a.id}
		delete(m.targets, key)
		m.noteTargetTombstoneLocked(key)
	}
	if !recorded {
		m.drop(DropResource)
		return fmt.Errorf("%w: closed AssociationID %s kept under a no-reuse fence instead of a ledger record", ErrResourceLimit, a.id)
	}
	return nil
}

func (a *Association) closeLocked() bool {
	if a.closed {
		return true
	}
	a.closed = true
	for _, ps := range a.peers {
		for direction := 0; direction < 2; direction++ {
			a.terminateLocked(ps, direction, DropClosed)
		}
	}
	if a.role != RoleOrigin {
		return true
	}
	if a.ledgerHeld {
		a.ledgerHeld = false
		a.mgr.releaseLedgerLocked()
	}
	return a.mgr.noteClosedLocked(a.id)
}
