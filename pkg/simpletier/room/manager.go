// Package room multiplexes several isolated overlay networks over one relay
// process.
//
// The deployment shape it serves: one host with a public address accepts peers
// over WebSocket and over TCP. A peer names the room it wants with a token it
// shares out of band with the other members of that room; the token is the room
// key. Peers in the same room can reach each other, peers in different rooms
// cannot see or reach each other at all.
//
// Rooms are temporary. The first member creates the room and the last member to
// leave schedules its teardown, so an idle relay does not accumulate networks for
// tokens nobody uses any more.
package room

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// MaxTokenBytes bounds a room token, so a peer cannot make the relay buffer an
// unbounded prefix.
const MaxTokenBytes = 4096

// ErrClosed reports that the manager is shutting down.
var ErrClosed = errors.New("room: manager closed")

// ErrNotIssued reports a join attempt with a token this host never issued. It is
// returned only when Options.RequireIssued is set.
var ErrNotIssued = errors.New("room: token was not issued by this relay")

// Options configures a Manager.
type Options struct {
	// Name is the overlay network name shared by every room. Rooms are separated
	// by token, not by name, so one name for all of them is correct.
	Name string
	// CIDR is the virtual network every room uses. Rooms do not share a virtual
	// address space: each is its own Network, so the same CIDR in two rooms does
	// not conflict.
	CIDR string
	// IdleTimeout is how long an empty room is kept before it is torn down. It
	// absorbs a member's brief reconnect without destroying and rebuilding the
	// network. Zero uses a one-minute default.
	IdleTimeout time.Duration
	// RateLimit enables the connection-admission flood guard on each room's network.
	// Nil means off. A relay admitting many peers at once is one of the deployments
	// that legitimately turns it off and relies on its own upstream protection.
	RateLimit *bool
	// RequireIssued restricts joining to tokens the host has issued itself.
	//
	// With it set, Join refuses a token that was never passed to Issue, so a peer
	// cannot create a room by inventing a name. That is the shape a business system
	// needs: it authenticates the caller, mints the room token, hands it out, and
	// only then does the peer connect with it. Off by default, which keeps the
	// open-relay behaviour where any agreed token makes a room.
	RequireIssued bool
	// LogLevel is passed to each room's Network.
	LogLevel string
}

func (o Options) withDefaults() Options {
	if o.Name == "" {
		o.Name = "DefaultRoom"
	}
	if o.CIDR == "" {
		o.CIDR = "10.100.0.0/24"
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = time.Minute
	}
	return o
}

// roomKey is the stable identifier of a room for a token.
//
// The token itself is never stored or logged: only its hash names the room, so a
// leaked log or a room listing does not leak room keys.
func roomKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:16])
}

// room is one isolated overlay network plus its membership count.
type room struct {
	key     string
	network simpletier.Network
	created time.Time

	mu      sync.Mutex
	members int
	idle    *time.Timer
	closed  bool
}

// Manager owns the rooms of one relay process.
type Manager struct {
	opts Options

	mu    sync.Mutex
	rooms map[string]*room
	// issued holds the room keys this host has minted. It is only consulted when
	// Options.RequireIssued is set, so an open relay never pays for it.
	issued map[string]struct{}
	// peers records the carrier address each NodeID arrived from, per room key. It is
	// populated by ObserveCarrier and read by Members; a relay that never calls it
	// simply reports no physical addresses.
	peers  map[string]map[string]string
	closed bool
}

// NewManager creates a manager. It starts no networks until a peer joins.
func NewManager(opts Options) *Manager {
	return &Manager{
		opts:   opts.withDefaults(),
		rooms:  make(map[string]*room),
		issued: make(map[string]struct{}),
		peers:  make(map[string]map[string]string),
	}
}

// Issue records a room token as host-issued and returns it unchanged.
//
// Callers mint the token however they like (a random value, a token tied to a
// tenant, a signed handle) and register it here before handing it to a peer. When
// Options.RequireIssued is set, this is what makes the token usable.
func (m *Manager) Issue(token string) error {
	if token == "" {
		return errors.New("room: empty token")
	}
	if len(token) > MaxTokenBytes {
		return fmt.Errorf("room: token exceeds %d bytes", MaxTokenBytes)
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	m.issued[roomKey(token)] = struct{}{}
	m.mu.Unlock()
	return nil
}

// Revoke forgets a token, so no further carrier may join with it. Members already
// attached keep running until their room is torn down.
func (m *Manager) Revoke(token string) {
	m.mu.Lock()
	delete(m.issued, roomKey(token))
	m.mu.Unlock()
}

// Join returns the room for token, creating it if this is the first member.
//
// The caller must call Leave exactly once for a successful Join.
func (m *Manager) Join(token string) (simpletier.Network, error) {
	if token == "" {
		return nil, errors.New("room: empty token")
	}
	key := roomKey(token)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	if m.opts.RequireIssued {
		if _, ok := m.issued[key]; !ok {
			return nil, ErrNotIssued
		}
	}

	if existing, ok := m.rooms[key]; ok {
		existing.mu.Lock()
		if !existing.closed {
			existing.members++
			if existing.idle != nil {
				existing.idle.Stop()
				existing.idle = nil
			}
			existing.mu.Unlock()
			return existing.network, nil
		}
		existing.mu.Unlock()
		delete(m.rooms, key)
	}

	network, err := simpletier.NewNetwork(simpletier.Config{
		Network: simpletier.NetworkConfig{
			Name:  m.opts.Name,
			CIDR:  m.opts.CIDR,
			Token: token,
		},
		Options: simpletier.RuntimeOptions{
			LogLevel:  m.opts.LogLevel,
			RateLimit: m.opts.RateLimit,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("room: create network for room %s: %w", key, err)
	}

	created := &room{key: key, network: network, members: 1, created: time.Now()}
	m.rooms[key] = created
	return network, nil
}

// Leave releases one membership. The last member to leave schedules the room's
// teardown after IdleTimeout rather than destroying it immediately, so a client
// that reconnects right away finds the room still there.
func (m *Manager) Leave(token string) {
	key := roomKey(token)

	m.mu.Lock()
	existing, ok := m.rooms[key]
	if !ok {
		m.mu.Unlock()
		return
	}
	existing.mu.Lock()
	if existing.members > 0 {
		existing.members--
	}
	empty := existing.members == 0
	if empty && existing.idle == nil {
		existing.idle = time.AfterFunc(m.opts.IdleTimeout, func() {
			m.reap(key)
		})
	}
	existing.mu.Unlock()
	m.mu.Unlock()
}

// reap tears a room down if it is still empty.
func (m *Manager) reap(key string) {
	m.mu.Lock()
	existing, ok := m.rooms[key]
	if !ok {
		m.mu.Unlock()
		return
	}
	existing.mu.Lock()
	if existing.members > 0 || existing.closed {
		// A member rejoined while the timer ran.
		existing.idle = nil
		existing.mu.Unlock()
		m.mu.Unlock()
		return
	}
	existing.closed = true
	delete(m.rooms, key)
	existing.mu.Unlock()
	m.mu.Unlock()

	_ = existing.network.Close()
}

// RoomInfo describes one live room. It deliberately omits the token: callers see
// the room by its short id, never the key that opens it.
type RoomInfo struct {
	// ID is the room token's hash prefix, unique within this relay and stable for the
	// token's lifetime. The token itself is never stored or logged.
	ID string
	// Carriers is the number of attached carrier connections. A peer needs one carrier
	// per lane (a CONTROL and a STREAM), so this is typically twice the peer count. Use
	// Members() for the peer view.
	Carriers int
	// Created is when the room was first created by this process.
	Created time.Time
	// VirtualIP is the room network's own address inside its CIDR. Every room has the
	// same CIDR, so this value is only meaningful together with ID.
	VirtualIP string
}

// Member is one carrier attached to a room, as seen from the room's network.
type Member struct {
	// NodeID identifies the peer in the overlay.
	NodeID string
	// VirtualIPs are the overlay addresses the peer owns.
	VirtualIPs []string
	// AdvertisesRelay reports that the peer can act as a transit hop.
	AdvertisesRelay bool
	// PhysicalAddr is the carrier address the peer connected from, as reported by
	// ObserveCarrier. It is empty when the carrier type does not expose one.
	PhysicalAddr string
}

// List returns a snapshot of every live room, ordered by creation time. It never
// blocks on room I/O: each network's peer view is read through a store snapshot.
func (m *Manager) List() []RoomInfo {
	m.mu.Lock()
	live := make([]*room, 0, len(m.rooms))
	for _, existing := range m.rooms {
		live = append(live, existing)
	}
	m.mu.Unlock()

	out := make([]RoomInfo, 0, len(live))
	for _, existing := range live {
		existing.mu.Lock()
		carriers, created, closed := existing.members, existing.created, existing.closed
		existing.mu.Unlock()
		if closed {
			continue
		}
		info := RoomInfo{
			ID:       existing.key,
			Carriers: carriers,
			Created:  created,
		}
		if existing.network != nil {
			if ip := existing.network.LocalVirtualIP(); ip.IsValid() {
				info.VirtualIP = ip.String()
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// Members returns the peers currently attached to the room keyed by id, where id is
// the RoomInfo.ID from List. ok is false when no such room is live.
//
// A peer becomes visible only after its facts have converged, which is asynchronous:
// a carrier that just attached may not appear yet.
func (m *Manager) Members(id string) (members []Member, ok bool) {
	m.mu.Lock()
	existing, found := m.rooms[id]
	m.mu.Unlock()
	if !found {
		return nil, false
	}

	existing.mu.Lock()
	network := existing.network
	closed := existing.closed
	existing.mu.Unlock()
	if closed || network == nil {
		return nil, false
	}

	peers, err := network.Peers()
	if err != nil {
		return nil, false
	}

	m.mu.Lock()
	physical := make(map[string]string, len(m.peers[id]))
	for nodeID, addr := range m.peers[id] {
		physical[nodeID] = addr
	}
	m.mu.Unlock()

	out := make([]Member, 0, len(peers))
	for _, peer := range peers {
		nodeID := string(peer.NodeID)
		out = append(out, Member{
			NodeID:          nodeID,
			VirtualIPs:      append([]string(nil), peer.VirtualIPs...),
			AdvertisesRelay: peer.AdvertisesRelay,
			PhysicalAddr:    physical[nodeID],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out, true
}

// ObserveCarrier records the physical address a peer's carrier arrived from, so
// Members can report it. nodeID is the authenticated peer identity from the attached
// link; addr is a host:port or any carrier-specific string.
//
// Call it after Attach succeeds and ForgetCarrier when the carrier is done. A relay
// that only wants the overlay view can skip both.
func (m *Manager) ObserveCarrier(token, nodeID, addr string) {
	if token == "" || nodeID == "" || addr == "" {
		return
	}
	key := roomKey(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	byNode := m.peers[key]
	if byNode == nil {
		byNode = make(map[string]string)
		m.peers[key] = byNode
	}
	byNode[nodeID] = addr
}

// ForgetCarrier drops a recorded carrier address.
func (m *Manager) ForgetCarrier(token, nodeID string) {
	if token == "" || nodeID == "" {
		return
	}
	key := roomKey(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	byNode := m.peers[key]
	if byNode == nil {
		return
	}
	delete(byNode, nodeID)
	if len(byNode) == 0 {
		delete(m.peers, key)
	}
}

// Rooms reports how many rooms are currently live.
func (m *Manager) Rooms() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rooms)
}

// Close tears down every room and refuses further joins.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	live := make([]*room, 0, len(m.rooms))
	for key, existing := range m.rooms {
		live = append(live, existing)
		delete(m.rooms, key)
	}
	m.mu.Unlock()

	var errs []error
	for _, existing := range live {
		existing.mu.Lock()
		existing.closed = true
		if existing.idle != nil {
			existing.idle.Stop()
		}
		existing.mu.Unlock()
		if err := existing.network.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
