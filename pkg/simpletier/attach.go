package simpletier

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/yiiilin/simpletier/internal/link"
)

// Lane identifiers of the frozen v1 Wire enumeration. AttachConnection always
// wires CONTROL directly; a PACKET or STREAM data Lane is admitted only for an
// initiator that pins it to an already active same-peer CONTROL Link through
// AttachOptions.Control, so a data Lane is never established on a guessed or
// unauthenticated adjacency.
const (
	laneControl uint8 = 0x00
	lanePacket  uint8 = 0x01
	laneStream  uint8 = 0x02
)

// ErrUnsupported reports a requested capability that this runtime slice does not
// implement, so it must never be mistaken for partial success. An unsupported
// request is rejected before any I/O or ownership transfer; a peer that
// negotiates an unsupported capability fails the attempt after the handshake,
// under the normal ownership contract, without returning a handle.
var ErrUnsupported = errors.New("unsupported")

// LinkRole is the Noise handshake role of one attached CONTROL Link. The role is
// not a trust level: both roles authenticate the same descriptor, PSK and
// capability gate. It decides who allocates the durable sender epoch and who
// commits the receiver floor.
type LinkRole uint8

const (
	// LinkRoleInitiator writes the first Noise XX message and owns the durable
	// per-(ContextID, Lane) sender epoch and attempt lease of the attempt.
	LinkRoleInitiator LinkRole = iota + 1
	// LinkRoleResponder answers an initiator and durably commits its authenticated
	// receiver floor before the Link becomes active.
	LinkRoleResponder
)

func (r LinkRole) valid() bool {
	return r == LinkRoleInitiator || r == LinkRoleResponder
}

func (r LinkRole) String() string {
	switch r {
	case LinkRoleInitiator:
		return "initiator"
	case LinkRoleResponder:
		return "responder"
	default:
		return fmt.Sprintf("LinkRole(%d)", uint8(r))
	}
}

// AttachOptions configures one AttachConnection attempt.
type AttachOptions struct {
	// Role selects the handshake role for this Connection. It must be
	// LinkRoleInitiator or LinkRoleResponder; every other value is rejected
	// before the Connection is taken over.
	Role LinkRole
	// Lane selects the protocol lane of the Link. A responder may instead set
	// Negotiate; then Lane must be CONTROL and the LaneID is taken from the
	// peer's authenticated HANDSHAKE, exactly like the built-in accepted carrier.
	// An initiator PACKET or STREAM Lane requires Control and is admitted only
	// with an active same-peer CONTROL Link; without it the attempt is a legal
	// request that is refused with ErrMissingControlDependency. Values above the
	// frozen enumeration are rejected as invalid configuration.
	Lane uint8
	// Negotiate asks a responder to take the LaneID from the authenticated peer
	// HANDSHAKE instead of Lane. It is rejected for an initiator.
	Negotiate bool
	// Control is the active CONTROL Link a data-lane initiator is pinned to. It
	// is required for an initiator PACKET or STREAM Attach and must be a handle
	// this Network returned for an open CONTROL Lane: its authenticated peer
	// static key becomes the exact peer the data Link may reach. A typed nil,
	// foreign implementation or broken (closed or never-established) handle is
	// rejected as invalid configuration before the Connection is taken over, and
	// a non-nil Control on a CONTROL Lane or on a responder is rejected the same
	// way. A nil Control preserves the original behavior: a data-lane initiator
	// with no pinned CONTROL peer is refused with ErrMissingControlDependency.
	Control AttachedLink
}

// AttachedLinkInfo is a stable, non-secret snapshot of one authenticated Link,
// CONTROL or data lane. It carries identity and epoch metadata only: no key
// material, derived root, transcript, probe payload or endpoint bytes.
// PeerNodeID is the authenticated 16-byte NodeID (the first 16 bytes of SHA-256
// over the peer's static public key) in lowercase hex.
type AttachedLinkInfo struct {
	PeerNodeID     NodeID
	LinkID         uint64
	LinkEpoch      uint64
	Generation     uint32
	Lane           uint8
	Role           LinkRole
	ConnectionType string
}

// AttachedLink is the public handle for one authenticated Link that the Network
// owns: a CONTROL Link, or a PACKET/STREAM data Link pinned to an active CONTROL
// dependency. Done closes when the Link stops being usable, including after
// Close, peer EOF, authentication failure, Network.Close or a runtime resource
// failure. Close is idempotent and unblocks concurrent I/O. The handle exposes
// no data-plane reads or writes: it carries lane metadata and lifetime only.
type AttachedLink interface {
	Info() AttachedLinkInfo
	Done() <-chan struct{}
	Close() error
}

type attachedLink struct {
	established *link.Link
	info        AttachedLinkInfo
}

func (a *attachedLink) Info() AttachedLinkInfo {
	if a == nil {
		return AttachedLinkInfo{}
	}
	return a.info
}

func (a *attachedLink) Done() <-chan struct{} {
	if a == nil || a.established == nil {
		return nil
	}
	return a.established.Done()
}

func (a *attachedLink) Close() error {
	if a == nil || a.established == nil {
		return nil
	}
	return a.established.Close()
}

// controlPeerStatic validates a caller-supplied CONTROL dependency handle and
// returns the authenticated static key of the exact CONTROL Link it wraps. A nil
// handle is not an error: it preserves the original behavior, where a data-lane
// initiator has no pinned peer and admitLink refuses it with
// ErrMissingControlDependency. A non-nil handle must be a live CONTROL handle
// this package produced; a typed nil, a foreign AttachedLink implementation, a
// closed or never-established handle and a data-lane handle are all illegal
// requests rejected before any ownership transfer.
func controlPeerStatic(control AttachedLink) ([32]byte, bool, error) {
	if control == nil {
		return [32]byte{}, false, nil
	}
	handle, ok := control.(*attachedLink)
	if !ok || handle == nil {
		return [32]byte{}, false, invalidConfig("attach.control", "must be an AttachedLink returned by AttachConnection")
	}
	if handle.established == nil || !handle.established.Ready() {
		return [32]byte{}, false, invalidConfig("attach.control", "must wrap an open CONTROL Link")
	}
	if handle.info.Lane != laneControl {
		return [32]byte{}, false, invalidConfig("attach.control", "must be a CONTROL Link")
	}
	return handle.established.PeerStatic(), true, nil
}

func laneName(lane uint8) string {
	switch lane {
	case laneControl:
		return "CONTROL"
	case lanePacket:
		return "PACKET"
	case laneStream:
		return "STREAM"
	default:
		return "unknown"
	}
}

// AttachConnection admits one host-established, dedicated, reliable,
// full-duplex Connection as an authenticated Link of this Network's network
// context. It runs the same admission path as the built-in carrier entry
// points: Noise XXpsk3 with the full descriptor, the encrypted CAPABILITY gate,
// the durable sender epoch/receiver floor for the requested Lane, the single
// protected control reader and writer, and, for an initiator, the correlated
// admission PONG that proves the peer durably admitted this exact Link. CONTROL
// is wired directly. An initiator PACKET or STREAM data Lane is admitted only
// when AttachOptions.Control pins it to an already active same-peer CONTROL
// Link: that authenticated peer static key is enforced in the handshake, so a
// data Link can never reach a peer this Network has no CONTROL adjacency to, and
// a peer-declared data Lane is never admitted as CONTROL.
//
// Ownership: an illegal request - a nil context, a nil Connection, an unknown
// Role, invalid Connection metadata, an invalid Lane, or an invalid Control
// handle - returns an error and leaves the Connection with the caller, unchanged
// and open. Once the request is valid the Network owns the Connection: any later
// failure closes it exactly once, and success returns an AttachedLink that owns
// it. A data-lane initiator without a valid CONTROL dependency is a legal
// request that is refused with ErrMissingControlDependency under that same
// ownership contract.
//
// Lifetime: ctx bounds lease acquisition, the handshake and the initiator's
// admission PONG, and Network.Close also aborts the attempt. After success the
// Link is independent of ctx: cancelling or expiring the caller context neither
// closes nor degrades the returned Link, which lives until Close, peer failure
// or Network.Close.
func (n *network) AttachConnection(ctx context.Context, conn Connection, options AttachOptions) (AttachedLink, error) {
	if ctx == nil {
		return nil, invalidConfig("context", "must not be nil")
	}
	if nilValue(conn) {
		return nil, invalidConfig("connection", "must not be nil")
	}
	if !options.Role.valid() {
		return nil, invalidConfig("attach.role", "must be LinkRoleInitiator or LinkRoleResponder")
	}
	if options.Negotiate {
		if options.Role != LinkRoleResponder {
			return nil, invalidConfig("attach.negotiate", "only a responder may negotiate the peer LaneID")
		}
		if options.Lane != laneControl {
			return nil, invalidConfig("attach.lane", "must be 0 (CONTROL) when negotiating the peer LaneID")
		}
	} else {
		switch options.Lane {
		case laneControl:
		case laneStream, lanePacket:
			// A manually attached data Lane (STREAM or PACKET) is admitted only
			// when AttachOptions.Control names an active same-peer CONTROL Link.
			// admitLink enforces that dependency (and the pinned handshake peer)
			// after authenticating the peer and reports ErrMissingControlDependency
			// when no such dependency exists: a transient ordering failure, not a
			// permanent unsupported capability.
		default:
			return nil, invalidConfig("attach.lane", "must be 0 (CONTROL), 1 (PACKET) or 2 (STREAM)")
		}
	}
	// The Control handle is a request parameter, so it is validated here, before
	// any ownership transfer: a data-lane initiator pins the exact CONTROL peer
	// the data Link may reach, and only an initiator PACKET/STREAM request may
	// name one. A nil handle keeps the original unpinned behavior.
	pinnedPeer, pinned, err := controlPeerStatic(options.Control)
	if err != nil {
		return nil, err
	}
	if pinned && (options.Role != LinkRoleInitiator || (options.Lane != laneStream && options.Lane != lanePacket)) {
		return nil, invalidConfig("attach.control", "is only valid for an initiator PACKET or STREAM Attach")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Sample untrusted provider metadata before taking ownership so a rejected
	// Connection stays caller-owned rather than being closed by the SDK.
	info := conn.Info()
	if err := validateConnectionInfo(info); err != nil {
		return nil, err
	}
	if n.isClosed() {
		return nil, ErrClosed
	}
	established, err := n.admitLink(ctx, conn, info, linkAdmission{
		role:               options.Role,
		lane:               options.Lane,
		negotiate:          options.Negotiate,
		expectedPeerStatic: pinnedPeer,
		hasExpectedPeer:    pinned,
	})
	if err != nil {
		return nil, err
	}
	metadata := established.Metadata()
	return &attachedLink{
		established: established,
		info: AttachedLinkInfo{
			PeerNodeID:     NodeID(hex.EncodeToString(metadata.PeerNodeID[:])),
			LinkID:         metadata.LinkID,
			LinkEpoch:      metadata.LinkEpoch,
			Generation:     metadata.Generation,
			Lane:           metadata.LaneID,
			Role:           options.Role,
			ConnectionType: established.ConnectionType(),
		},
	}, nil
}
