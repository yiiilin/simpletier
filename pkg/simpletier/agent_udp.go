package simpletier

import (
	"context"
	"net/netip"
	"sync"

	"github.com/yiiilin/simpletier/internal/agent"
	"github.com/yiiilin/simpletier/internal/flow"
)

// agentDatagramBackend is the pkg SOCKS5 UDP ASSOCIATE egress port. It is backed
// exclusively by this Network's Flow UDP plane and by the runtime's single
// shared udpMux: it never creates an OS UDP socket towards a target, and every
// datagram is authenticated and fragmented by the same class-1 PACKET-lane
// session machinery as any other Flow traffic.
//
// Because the mux is the one Delivery installed on the Flow manager, the backend
// never races another consumer to install a second delivery, and it can never
// silently ride a foreign delivery that would swallow its replies.
type agentDatagramBackend struct {
	rt  *streamRuntime
	mux *udpMux

	mu      sync.Mutex
	started bool
}

func newAgentDatagramBackend(rt *streamRuntime) *agentDatagramBackend {
	return &agentDatagramBackend{rt: rt}
}

// ensureFlow installs the runtime's shared UDP Flow plane on first use. It is
// idempotent and it never replaces an already installed, incompatible delivery.
func (b *agentDatagramBackend) ensureFlow() error {
	if b == nil || b.rt == nil {
		return ErrClosed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started && b.mux != nil {
		return nil
	}
	mux, err := b.rt.ensureUDPFlow()
	if err != nil {
		return err
	}
	b.mux = mux
	b.started = true
	return nil
}

// NewAssociation implements agent.DatagramBackend. It creates one Flow origin
// association and reserves its unique local source port and reply route in one
// critical section, so two concurrent associations can never report the same
// port or mis-route each other's replies. ctx bounds only this creation.
func (b *agentDatagramBackend) NewAssociation(ctx context.Context) (agent.UDPDgramChannel, error) {
	if b == nil || b.rt == nil {
		return nil, ErrClosed
	}
	if ctx == nil {
		return nil, invalidConfig("ctx", "must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := b.ensureFlow(); err != nil {
		return nil, err
	}
	mux := b.mux
	if mux == nil {
		return nil, ErrClosed
	}
	manager := b.rt.flowManager()
	if manager == nil {
		return nil, ErrClosed
	}
	association, err := manager.CreateAssociation()
	if err != nil {
		return nil, err
	}
	channel := &agentDatagramChannel{
		backend:     b,
		association: association,
		inbox:       make(chan flow.Datagram, udpSocketInboxFrames),
		closed:      make(chan struct{}),
	}
	port, err := mux.reserveOrigin(association.ID(), channel)
	if err != nil {
		_ = association.Close()
		return nil, err
	}
	channel.localPort = port
	if err := ctx.Err(); err != nil {
		_ = channel.Close()
		return nil, err
	}
	return channel, nil
}

// agentDatagramChannel implements agent.UDPDgramChannel over one Flow origin
// association. Outbound datagrams are REQUESTs on that association; inbound
// datagrams are REPLYs for exactly that association and from a peer this channel
// actually sent to.
type agentDatagramChannel struct {
	backend     *agentDatagramBackend
	association *flow.Association
	localPort   uint16

	inbox  chan flow.Datagram
	closed chan struct{}
	once   sync.Once

	peers udpPeerTracker

	// chargeMu guards charges, the per-datagram inbox budget held for the
	// payloads currently queued in inbox. It is released on Receive and on Close
	// so a closed channel leaks no reserved bytes.
	chargeMu sync.Mutex
	charges  []uint64
}

func (c *agentDatagramChannel) releaseOne() {
	c.chargeMu.Lock()
	var charge uint64
	if len(c.charges) > 0 {
		charge = c.charges[0]
		c.charges = c.charges[1:]
	}
	c.chargeMu.Unlock()
	if charge > 0 && c.backend != nil && c.backend.mux != nil {
		c.backend.mux.releaseInbox(charge)
	}
}

func (c *agentDatagramChannel) releaseAll() {
	c.chargeMu.Lock()
	charges := c.charges
	c.charges = nil
	c.chargeMu.Unlock()
	if c.backend == nil || c.backend.mux == nil {
		return
	}
	for _, charge := range charges {
		c.backend.mux.releaseInbox(charge)
	}
}

// deliverReply routes one inbound REPLY to this channel's inbox. It requires the
// REPLY flag, the exact AssociationID, the correct local virtual destination and
// a source peer this channel sent to; anything else is a foreign datagram and is
// dropped by the mux accounting.
func (c *agentDatagramChannel) deliverReply(datagram flow.Datagram) {
	if c == nil || c.association == nil || c.backend == nil || c.backend.mux == nil {
		return
	}
	mux := c.backend.mux
	if datagram.Flags != flow.FlagReply || datagram.AssociationID != c.association.ID() {
		mux.droppedForeign.Add(1)
		return
	}
	local := netip.AddrPortFrom(c.backend.rt.n.localVirtualIP(), c.localPort)
	if datagram.Destination != local {
		mux.droppedForeign.Add(1)
		return
	}
	if !c.peers.includes(datagram.Source) {
		mux.droppedForeign.Add(1)
		return
	}
	if c.isClosed() {
		return
	}
	charge := uint64(len(datagram.Payload)) + udpInboxMetadataBytes
	if !mux.reserveInbox(charge) {
		mux.droppedBudget.Add(1)
		return
	}
	payload := append([]byte(nil), datagram.Payload...)
	item := flow.Datagram{
		NetworkID:     datagram.NetworkID,
		SrcNodeID:     datagram.SrcNodeID,
		DstNodeID:     datagram.DstNodeID,
		AssociationID: datagram.AssociationID,
		Flags:         datagram.Flags,
		DatagramID:    datagram.DatagramID,
		Source:        datagram.Source,
		Destination:   datagram.Destination,
		Payload:       payload,
	}
	select {
	case c.inbox <- item:
		c.chargeMu.Lock()
		c.charges = append(c.charges, charge)
		c.chargeMu.Unlock()
	case <-c.closed:
		mux.releaseInbox(charge)
	default:
		mux.releaseInbox(charge)
		mux.droppedFull.Add(1)
	}
}

func (c *agentDatagramChannel) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// SendTo resolves the target inside the overlay (never an OS UDP dial) and
// fragments one datagram through this association's class-1 Flow session.
func (c *agentDatagramChannel) SendTo(ctx context.Context, host string, port uint16, payload []byte) error {
	if c == nil || c.backend == nil || c.association == nil {
		return ErrClosed
	}
	if c.isClosed() {
		return ErrClosed
	}
	if ctx == nil {
		return invalidConfig("ctx", "must not be nil")
	}
	resolver := &agentTargetResolver{n: c.backend.rt.n}
	destination, err := resolver.ResolveTarget(ctx, host, port)
	if err != nil {
		return err
	}
	source := netip.AddrPortFrom(c.backend.rt.n.localVirtualIP(), c.localPort)
	// Authorize the reply peer BEFORE the first fragment can be admitted. A
	// REQUEST and its REPLY can cross on the wire: a fast target may answer while
	// Fragment is still enqueueing the datagram, so recording the peer only after
	// Fragment returned would classify that legal REPLY as foreign and drop it.
	// The destination is a resolved overlay target, i.e. an authenticated Network
	// member, so no arbitrary IP is ever authorized.
	//
	// The registration is deliberately NOT retracted when Fragment fails: a
	// failed fragment may already have been partially admitted, so a later legal
	// REPLY must stay acceptable for this association's lifetime. The authorized
	// set is bounded by udpSendPeerLimit, so this cannot grow without limit.
	c.peers.note(destination)
	if err := c.association.Fragment(ctx, flow.OutboundDatagram{
		Source:      source,
		Destination: destination,
		Payload:     payload,
	}); err != nil {
		return err
	}
	return nil
}

// Receive returns one complete datagram and its real virtual source. It returns
// ErrClosed as soon as the channel is closed, even when a queued datagram is
// still buffered.
func (c *agentDatagramChannel) Receive(ctx context.Context) (string, uint16, []byte, error) {
	if c == nil {
		return "", 0, nil, ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.isClosed() {
		return "", 0, nil, ErrClosed
	}
	select {
	case datagram := <-c.inbox:
		c.releaseOne()
		if c.isClosed() {
			return "", 0, nil, ErrClosed
		}
		return datagram.Source.Addr().String(), datagram.Source.Port(), datagram.Payload, nil
	case <-c.closed:
		return "", 0, nil, ErrClosed
	case <-ctx.Done():
		return "", 0, nil, ctx.Err()
	}
}

// Close releases the association, the reserved port and the reply route exactly
// once, and unblocks a pending Receive.
func (c *agentDatagramChannel) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.once.Do(func() {
		close(c.closed)
		if c.backend != nil && c.backend.mux != nil {
			c.backend.mux.unregisterOrigin(c.association.ID(), c)
			c.backend.mux.releasePort(c.localPort)
		}
		if c.association != nil {
			err = c.association.Close()
		}
		c.releaseAll()
	})
	return err
}

var _ agent.DatagramBackend = (*agentDatagramBackend)(nil)
var _ agent.UDPDgramChannel = (*agentDatagramChannel)(nil)
