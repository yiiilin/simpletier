package simpletier

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/circuit"
	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/topology"
)

var (
	ErrClosed  = errors.New("network closed")
	ErrNoRoute = errors.New("no route")
	// ErrRouteStale reports that a pinned Flow/PACKET route changed (address
	// owner, Path generation or lane) before the datagram egressed. The
	// datagram was not re-routed and must be retried by the caller.
	ErrRouteStale       = errors.New("route stale")
	ErrLinkDown         = errors.New("link down")
	ErrPermissionDenied = errors.New("permission denied")
	ErrResource         = errors.New("resource limit")
	ErrCloseTimeout     = errors.New("network close timeout")
	// ErrBusy reports that a virtual port is already bound in the same
	// namespace. TCP and UDP ports are separate namespaces, so a UDP port may
	// equal a bound TCP port; a duplicate port inside one namespace is ErrBusy.
	ErrBusy = errors.New("address already in use")
	// ErrDeadline reports that a Stream operation hit its configured deadline.
	// It is the identity net.Conn users already check as os.ErrDeadlineExceeded
	// and implements net.Error with Timeout() == true.
	ErrDeadline = os.ErrDeadlineExceeded
	// ErrTargetRefused reports that the target node refused a virtual port
	// because no listener is registered there. It is the SDK identity of the
	// frozen CIRCUIT_READY TARGET_REFUSED code.
	ErrTargetRefused = circuit.ErrTargetRefused
	// ErrSessionLost reports that the Session carrying a Stream ended, so the
	// call is not safe to retry blindly.
	ErrSessionLost = circuit.ErrSessionLost
	// ErrOutcomeUnknown reports that an Open may or may not have reached the
	// target; it must not be automatically replayed.
	ErrOutcomeUnknown = circuit.ErrOutcomeUnknown
	// ErrStreamReset reports a peer-initiated reset that is not one of the
	// classified reasons.
	ErrStreamReset = circuit.ErrStreamReset
	// ErrMissingControlDependency reports that a DATA-lane connection was
	// offered before an active same-peer CONTROL Link existed. It is a transient
	// ordering/dependency failure, not a permanent unsupported capability: the
	// caller retries once the CONTROL adjacency is ready.
	ErrMissingControlDependency = errors.New("missing active control dependency")
	// ErrAddressConflict reports that this node's own VirtualIP is claimed by
	// more than one live AddressFact owner. An explicit fixed_ip that conflicts
	// fails closed instead of silently re-addressing; an automatically
	// allocated address is re-derived by the losing (higher NodeID) node.
	ErrAddressConflict = errors.New("virtual address conflict")
	// ErrNetworkInUse is the stable exported identity of the runtime-owner
	// rejection. NewNetwork returns an error wrapping it when this process
	// already owns a running Network for the same canonical IdentityStore state
	// directory and full ContextID: the second caller must reuse the existing
	// Network instead of cloning a second publisher, and the durable state is
	// never shared, truncated or deleted by the rejected constructor. It is
	// deliberately the same value as security.ErrNetworkStateInUse so external
	// SDK users can match it with errors.Is without importing internal packages.
	ErrNetworkInUse = security.ErrNetworkStateInUse
)

type NodeID string

type Stream interface {
	net.Conn
	CloseWrite() error
	Reset(code uint32) error
	RemoteNode() NodeID
}

type StreamListener interface {
	Accept() (Stream, error)
	Addr() net.Addr
	Close() error
}

type Network interface {
	DialContext(context.Context, string, string) (Stream, error)
	Listen(string, string) (StreamListener, error)
	NetListener(StreamListener) net.Listener
	// ListenPacket binds one virtual UDP endpoint on this Network's own
	// VirtualIP and returns a net.PacketConn whose ReadFrom/WriteTo exchange
	// complete datagrams inside the overlay over the Flow/PACKET lane. It never
	// opens an OS UDP socket towards a target and never uses a gateway.
	ListenPacket(networkName, address string) (net.PacketConn, error)
	// AttachConnection admits one host-established Connection through the same
	// authenticated admission path as the built-in entry points: a CONTROL lane
	// Link, or a PACKET/STREAM data lane that an initiator pins through
	// AttachOptions.Control to an already active same-peer CONTROL Link (a
	// responder may instead Negotiate the peer's authenticated LaneID). See
	// AttachOptions for the lane, ownership and lifetime contract.
	AttachConnection(context.Context, Connection, AttachOptions) (AttachedLink, error)
	Close() error
	Done() <-chan struct{}
	// LocalVirtualIP returns this instance's selected IPv4 VirtualIP/32. With an
	// explicit fixed_ip it is that address; otherwise it is the persisted
	// deterministic D-OVERLAY-004 allocation. It is stable for the Network
	// lifetime.
	LocalVirtualIP() netip.Addr
	// Peers reports the authenticated facts this Network holds about other
	// nodes. It is the diagnostic companion to a failed DialContext: it says
	// whether the peer was never learned, learned without a static key, or
	// learned and merely unreachable on the requested lane.
	Peers() ([]PeerFact, error)
}

type network struct {
	mu             sync.Mutex
	closed         bool
	closeOnce      sync.Once
	closeErr       error
	done           chan struct{}
	ctx            context.Context
	cancel         context.CancelFunc
	identityStore  *security.IdentityStore
	normalized     normalizedConfig
	networkContext security.NetworkContext
	networkPSK     [32]byte
	runtimeState   *security.NetworkState
	// localIP is a compatibility mirror of the current VirtualIP. Production
	// code must read localVirtualIP()/localAddressSnapshot(); the mirror exists
	// only for the excluded fact_sender test helpers and is updated on swap.
	localIP netip.Addr
	// localAddr is the immutable local VirtualIP snapshot. Data-plane readers
	// (packet, fact, listen, agent) load it atomically, so an automatic loser
	// reallocation can swap it without a lock-free field race.
	localAddr *atomic.Pointer[localAddress]
	// packetLanesEnabled is set once a packet (L3) service is installed on this
	// Network. Only then does the upstream loop establish the dedicated PACKET
	// lane, so a Network that never serves packet traffic keeps exactly the
	// CONTROL and STREAM lanes.
	packetLanesEnabled bool
	carrierListeners   []net.Listener
	streamListeners    map[netip.AddrPort]*streamListener
	activeLinks        map[uint64]*link.Link
	// controlPumps publishes the unique authenticated control pump of each
	// registered Link, keyed by the same LinkID as activeLinks. The outbound FACT
	// sender iterates it; it is registered and removed under the same Close gate
	// as activeLinks so a Link returned to a caller always has exactly one pump.
	controlPumps     map[uint64]*controlPump
	inboundAdmission chan struct{}
	// probeMu guards pendingProbes, the pending admission-confirmation probes of
	// this Network. It is deliberately separate from mu: the control reader
	// resolves a PONG while the admission goroutine waits outside every Network
	// lock for handshake and socket I/O. Each probe is bound to the exact
	// controlPump that registered it, so only a PONG read from that owning pump
	// may complete or cancel it.
	probeMu       sync.Mutex
	pendingProbes map[[16]byte]admissionProbe
	workers       sync.WaitGroup
	// facts is the authenticated FACT consumer and RouteView owner of this
	// Network. It is created from the already reserved runtimeState before any
	// Link can be admitted, so no authenticated control payload can ever be
	// interpreted without a durable FactStore behind it.
	facts *factRuntime
	// streams owns the data plane: Path/Session/Circuit tables, the directional
	// E2E protectors and the virtual Stream listeners. It is created after facts
	// because Path selection reads the RouteView.
	streams *streamRuntime
	// verification is the one Network-lifetime aggregate failed-tag ledger. It is
	// created before any Link can be admitted and shared by every hop protector
	// and every directional E2E protector of this Network; it never resets.
	verification *verificationBudget
	// stateBudget is the shared Network allocator, published by NewNetwork right
	// after the stream runtime created it. reserveState reads it lock-free; a nil
	// pointer is an explicit resource failure, never an unaccounted admission.
	stateBudget atomic.Pointer[budget.Allocator]
	// rates is the one bounded frozen-MESH-3.8 rate limiter of this Network. It
	// carries the default limits only; no SDK field raises them.
	rates *networkRates
	// ratesLease is the single Network-state estimate booking the limiter's
	// bounded metadata; it is released when the runtime owner closes.
	ratesLease *budget.Lease
	// addressApplyMu guards addressApply. The public Agent installs one optional
	// host-address mover here; an automatic loser reallocation calls it before the
	// new VirtualIP is persisted or published, so a failed host retarget leaves
	// the old address, facts and routes untouched.
	addressApplyMu sync.Mutex
	addressApply   func(ctx context.Context, vip netip.Addr) error
}

// relayEnabled reports whether this Network is willing to relay traffic for
// other nodes, honoring the confirmed Config.Options.Relay switch.
func (n *network) relayEnabled() bool {
	if n == nil {
		return false
	}
	if n.normalized.config.Options.Relay == nil {
		return true
	}
	return *n.normalized.config.Options.Relay
}

func NewNetwork(cfg Config) (Network, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	identityStore, err := security.OpenIdentityStore()
	if err != nil {
		return nil, fmt.Errorf("open Network identity: %w", err)
	}

	identity, err := identityStore.Identity()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("read Network identity: %w", err), identityStore.Close())
	}

	// Reserve the single in-process runtime owner for this scope and full
	// ContextID before binding any listener or starting any background worker.
	// A second owner for the same scope+ContextID is rejected here instead of
	// silently publishing
	// a second owner. Failure closes only this identity handle; the durable
	// identity/runtime state is left in place.
	runtimeState, err := security.OpenNetworkState(identityStore, normalized.networkContext.ID())
	if err != nil {
		return nil, errors.Join(fmt.Errorf("open Network runtime state: %w", err), identityStore.Close())
	}

	// Select this node's VirtualIP only after the durable runtime state exists:
	// without fixed_ip the deterministic D-OVERLAY-004 candidate is persisted so
	// a restart reuses the same address and attempt instead of re-deriving.
	localIP, addressAttempt, err := allocateLocalVirtualIP(runtimeState, normalized.networkPrefix, identity.NodeID, normalized.fixedIP)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("allocate VirtualIP: %w", err), runtimeState.Close(), identityStore.Close())
	}

	listeners := make([]net.Listener, 0, len(normalized.listen))
	for index, endpoint := range normalized.listen {
		address := net.JoinHostPort(endpoint.host, strconv.Itoa(int(endpoint.port)))
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("bind listen[%d] %s: %w", index, address, err),
				closeNetworkListeners(listeners),
				runtimeState.Close(),
				identityStore.Close(),
			)
		}
		listeners = append(listeners, listener)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// The one bounded rate limiter of this Network is built before the Network
	// value so the accept path, the packet plane and every control pump share the
	// same limiter instance and the same 16-way pre-auth handshake semaphore.
	rates := newNetworkRatesFor(normalized.config.Options.rateLimitEnabled())
	n := &network{
		done:             make(chan struct{}),
		ctx:              ctx,
		cancel:           cancel,
		identityStore:    identityStore,
		normalized:       normalized,
		networkContext:   normalized.networkContext,
		networkPSK:       normalized.networkPSK,
		runtimeState:     runtimeState,
		localAddr:        &atomic.Pointer[localAddress]{},
		carrierListeners: listeners,
		streamListeners:  make(map[netip.AddrPort]*streamListener),
		activeLinks:      make(map[uint64]*link.Link),
		controlPumps:     make(map[uint64]*controlPump),
		inboundAdmission: rates.handshakes,
		pendingProbes:    make(map[[16]byte]admissionProbe),
	}
	// The compatibility mirror is frozen here, before the Network is published to
	// any goroutine: an automatic loser reallocation later only republishes the
	// atomic localAddr snapshot that production readers use.
	n.localIP = localIP
	n.setLocalAddress(localIP, addressAttempt)
	// The one Network-lifetime aggregate failed-tag ledger exists before any Link
	// can be admitted, so every hop/E2E protector of this Network can share it.
	// Reaching its ceiling cancels the Network and closes it from a separate
	// goroutine: the ledger callback is a leaf and must never wait on the worker
	// that reported the failure.
	n.verification = newVerificationBudget(networkVerificationBudgetLimit, n.tripVerificationCeiling)
	// The authenticated FACT consumer and its RouteView are created from the
	// runtime state reserved above, before any Link can be admitted and before any
	// background worker starts. The store borrows runtimeState; it is never a
	// second owner. A failure here closes only what this constructor opened.
	factRuntime, err := newFactRuntime(n)
	if err != nil {
		cancel()
		return nil, errors.Join(
			fmt.Errorf("open authenticated FACT runtime: %w", err),
			closeNetworkListeners(listeners),
			runtimeState.Close(),
			identityStore.Close(),
		)
	}
	n.facts = factRuntime
	// The data plane (Path/Session/Circuit/E2E) is created from the same
	// reserved runtime state and the already published RouteView. A failure here
	// closes only what this constructor opened and never leaves a half data
	// plane behind.
	streams, err := newStreamRuntime(n, identity)
	if err != nil {
		cancel()
		return nil, errors.Join(
			fmt.Errorf("open stream data plane: %w", err),
			closeNetworkListeners(listeners),
			runtimeState.Close(),
			identityStore.Close(),
		)
	}
	n.streams = streams
	// Publish the shared allocator the stream runtime created so the Network-level
	// helpers (reserveState, physical Link registration, per-pump receive state)
	// book against the same 256 MiB heap instead of a second ledger. This is the
	// earliest moment it exists; no Link can be admitted before the constructor
	// returns.
	n.stateBudget.Store(streams.budgets)
	// The authenticated FACT store books its owned bytes against this same
	// ledger, so the frozen 256 MiB Network heap sees FACT state instead of only
	// the store's private 32 MiB ceiling. The store was constructed above, before
	// this allocator existed, so the port is attached here. A Network without an
	// allocator attaches nothing and keeps exactly the store's own bound.
	if n.stateBudgetPtr() != nil {
		n.facts.store.SetStateBudget(newFactStateBudget(n))
	}
	// The one bounded rate limiter of this Network. Its bounded map/bucket and
	// handshake-admission metadata is booked as a single Network-state estimate
	// against the same heap, so the limiter itself is accounted and not an
	// invisible allocation. A failure here closes exactly what this constructor
	// opened. The limiter instance is the one already published into the Network
	// value above; there is deliberately no second instance.
	n.rates = rates
	ratesLease, reserveErr := n.reserveState(rateMetadataEstimateBytes)
	if reserveErr != nil {
		cancel()
		return nil, errors.Join(
			fmt.Errorf("reserve rate metadata state: %w", reserveErr),
			streams.close(),
			closeNetworkListeners(listeners),
			runtimeState.Close(),
			identityStore.Close(),
		)
	}
	n.ratesLease = ratesLease
	for _, listener := range listeners {
		n.workers.Add(1)
		go n.rejectUnauthenticatedCarriers(listener)
	}
	if len(normalized.upstreams) > 0 || len(normalized.config.Targets) > 0 {
		n.workers.Add(1)
		go n.retryUpstreams()
	}
	// One accept loop hands target-side Circuits to their virtual listeners.
	n.workers.Add(1)
	go n.acceptIncomingCircuits()
	// The RouteView rebuild worker, the local advertisement worker and the
	// outbound FACT sender worker live under the same Close gate as the Link
	// workers: Close cancels them and waits for the step already in progress.
	n.workers.Add(3)
	go n.refreshRouteView()
	go n.refreshLocalFacts()
	go n.refreshFactSenders()
	// One bounded Network policy tick evaluates the in-place key-update policy of
	// every live Link and asks the data plane to poll its session rekeys. It adds
	// no reader, no writer and no goroutine per pump: it only calls the existing
	// callback-safe policy hooks, which do no I/O.
	n.workers.Add(1)
	go n.pollNetworkPolicy()
	return n, nil
}

const (
	maxActiveLinksPerPeer = 6
	networkCloseTimeout   = 5 * time.Second
	upstreamDialTimeout   = 5 * time.Second
	upstreamRetryInitial  = time.Second
	upstreamRetryMax      = 30 * time.Second
	// linkAttemptGateTimeout bounds how long one initiator waits behind an
	// in-flight same-(state dir, ContextID, Lane) attempt before giving up. The
	// wait is also cancelled immediately by Network.Close.
	linkAttemptGateTimeout = 5 * time.Second
)

func (n *network) retryUpstreams() {
	defer n.workers.Done()
	delay := upstreamRetryInitial
	tcp := &TCPConnector{}
	targets := make([]ConnectionTarget, 0, len(n.normalized.upstreams)+len(n.normalized.config.Targets))
	for _, endpoint := range n.normalized.upstreams {
		targets = append(targets, ConnectionTarget{
			Connector: tcp,
			Endpoint:  net.JoinHostPort(endpoint.host, strconv.Itoa(int(endpoint.port))),
		})
	}
	targets = append(targets, n.normalized.config.Targets...)
	occupied := make([]*link.Link, len(targets))
	streamStarted := make([]bool, len(targets))
	packetStarted := make([]bool, len(targets))

	for {
		for index, target := range targets {
			if n.ctx.Err() != nil {
				return
			}
			if occupied[index] != nil && occupied[index].Ready() {
				// A healthy CONTROL adjacenc y keeps running its own dedicated
				// STREAM lane. A failed STREAM attempt never drains CONTROL.
				if !streamStarted[index] {
					streamStarted[index] = true
					control := occupied[index]
					n.workers.Add(1)
					go n.streamLinkLoop(target, control)
				}
				n.mu.Lock()
				packetLanes := n.packetLanesEnabled || n.relayEnabled()
				n.mu.Unlock()
				if packetLanes && !packetStarted[index] {
					packetStarted[index] = true
					control := occupied[index]
					n.workers.Add(1)
					go n.packetLinkLoop(target, control)
				}
				// A healthy CONTROL adjacency must not sit in a long failed-dial
				// backoff: poll the on-demand PACKET-lane gate promptly.
				delay = upstreamRetryInitial
				continue
			}
			established, err := n.tryConnectionTargetLink(target)
			if err == nil {
				occupied[index] = established
			}
			if n.ctx.Err() != nil {
				return
			}
			if err != nil {
				// Endpoint and provider errors may contain credentials, so neither
				// the endpoint nor the raw error is logged: only the credential-free
				// classification below is safe.
				slog.Default().Debug("connection attempt failed", "target_index", index, "phase", "dial-or-cleanup", "reason", connectionAttemptLogReason(err))
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-n.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay >= upstreamRetryMax/2 {
			delay = upstreamRetryMax
		} else {
			delay *= 2
		}
	}
}

func (n *network) tryConnectionTarget(target ConnectionTarget) error {
	_, err := n.tryConnectionTargetLink(target)
	return err
}

// connectionAttemptLogReason returns a credential-free classification of one
// failed connection attempt. A Connector error, endpoint or provider message can
// embed credentials (tokens, wss URLs, private keys), so the raw error must never
// reach a log; only this closed set of classes is reported.
func connectionAttemptLogReason(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, ErrInvalidConfig):
		return "invalid-config"
	case errors.Is(err, ErrPermissionDenied):
		return "permission"
	case errors.Is(err, ErrClosed):
		return "closed"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "dial-failed"
	}
}

// streamLinkLoop owns the dedicated STREAM Lane connection to one target. It
// dials the same Connector/Endpoint as the CONTROL link, pins the exact
// authenticated CONTROL peer static key, and retries without ever disturbing a
// healthy CONTROL adjacency. Each retry is a fresh Connection; a failed STREAM
// attempt only backs off.
func (n *network) streamLinkLoop(target ConnectionTarget, control *link.Link) {
	defer n.workers.Done()
	delay := upstreamRetryInitial
	for {
		if n.ctx.Err() != nil || control == nil || !control.Ready() {
			return
		}
		ctx, cancel := context.WithTimeout(n.ctx, upstreamDialTimeout)
		conn, dialErr := target.Connector.Dial(ctx, target.Endpoint)
		establishmentErr := ctx.Err()
		cancel()
		if nilValue(conn) {
			if dialErr == nil {
				dialErr = invalidConfig("connector", "returned a nil Connection without an error")
			}
		} else if dialErr == nil && establishmentErr == nil && n.ctx.Err() == nil {
			admitted, admitErr := n.admitLink(n.ctx, conn, conn.Info(), linkAdmission{
				role:               LinkRoleInitiator,
				lane:               laneStream,
				expectedPeerStatic: control.PeerStatic(),
				hasExpectedPeer:    true,
			})
			if admitErr == nil {
				// A healthy data lane runs until the Link (or the Network) ends.
				select {
				case <-admitted.Done():
				case <-n.ctx.Done():
				}
			}
		} else {
			_ = conn.Close()
		}
		timer := time.NewTimer(delay)
		select {
		case <-n.ctx.Done():
			timer.Stop()
			return
		case <-control.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay >= upstreamRetryMax/2 {
			delay = upstreamRetryMax
		} else {
			delay *= 2
		}
	}
}

// packetLinkLoop owns the dedicated PACKET Lane connection to one target. It is
// the class-1 data lane analogue of streamLinkLoop: it dials the same
// Connector/Endpoint as the CONTROL link, pins the exact authenticated CONTROL
// peer static key, and retries without disturbing a healthy CONTROL adjacency.
func (n *network) packetLinkLoop(target ConnectionTarget, control *link.Link) {
	defer n.workers.Done()
	delay := upstreamRetryInitial
	for {
		if n.ctx.Err() != nil || control == nil || !control.Ready() {
			return
		}
		ctx, cancel := context.WithTimeout(n.ctx, upstreamDialTimeout)
		conn, dialErr := target.Connector.Dial(ctx, target.Endpoint)
		establishmentErr := ctx.Err()
		cancel()
		if nilValue(conn) {
			if dialErr == nil {
				dialErr = invalidConfig("connector", "returned a nil Connection without an error")
			}
		} else if dialErr == nil && establishmentErr == nil && n.ctx.Err() == nil {
			admitted, admitErr := n.admitLink(n.ctx, conn, conn.Info(), linkAdmission{
				role:               LinkRoleInitiator,
				lane:               lanePacket,
				expectedPeerStatic: control.PeerStatic(),
				hasExpectedPeer:    true,
			})
			if admitErr == nil {
				select {
				case <-admitted.Done():
				case <-n.ctx.Done():
				}
			}
		} else {
			_ = conn.Close()
		}
		timer := time.NewTimer(delay)
		select {
		case <-n.ctx.Done():
			timer.Stop()
			return
		case <-control.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay >= upstreamRetryMax/2 {
			delay = upstreamRetryMax
		} else {
			delay *= 2
		}
	}
}

func (n *network) tryConnectionTargetLink(target ConnectionTarget) (*link.Link, error) {
	ctx, cancel := context.WithTimeout(n.ctx, upstreamDialTimeout)
	conn, dialErr := target.Connector.Dial(ctx, target.Endpoint)
	establishmentErr := ctx.Err()
	cancel()
	if nilValue(conn) {
		if dialErr == nil {
			dialErr = invalidConfig("connector", "returned a nil Connection without an error")
		}
		return nil, errors.Join(dialErr, establishmentErr, n.ctx.Err())
	}
	if dialErr != nil || establishmentErr != nil || n.ctx.Err() != nil {
		return nil, errors.Join(dialErr, establishmentErr, n.ctx.Err(), conn.Close())
	}
	return n.admitConnectionLink(conn, true)
}

func (n *network) admitConnection(conn Connection, initiator bool) error {
	_, err := n.admitConnectionLink(conn, initiator)
	return err
}

// admitConnectionLink is the built-in admission entry used by TCP upstreams,
// typed Targets and accepted carriers. It runs under the Network lifetime. A
// built-in initiator requests the CONTROL Lane explicitly; a built-in accepted
// carrier negotiates the LaneID the peer declared in its authenticated HANDSHAKE
// record, so one listener can carry both CONTROL and dedicated STREAM
// connections without guessing from the socket. The public Attach entry point
// stays strict: it always requests an explicit Lane.
func (n *network) admitConnectionLink(conn Connection, initiator bool) (*link.Link, error) {
	if nilValue(conn) {
		return nil, invalidConfig("connection", "must not be nil")
	}
	if initiator {
		return n.admitLink(n.ctx, conn, conn.Info(), linkAdmission{role: LinkRoleInitiator, lane: laneControl})
	}
	return n.admitLink(n.ctx, conn, conn.Info(), linkAdmission{role: LinkRoleResponder, negotiate: true})
}

// linkAdmission describes one dedicated-connection admission request. lane 0
// means "negotiate the LaneID declared by the peer", which is only valid for a
// responder accepted by the built-in listener; the public Attach entry point
// always requests an explicit lane.
type linkAdmission struct {
	role               LinkRole
	lane               uint8
	negotiate          bool
	expectedPeerStatic [32]byte
	hasExpectedPeer    bool
}

// admitControlLink preserves the original built-in CONTROL admission entry.
func (n *network) admitControlLink(ctx context.Context, conn Connection, info ConnectionInfo, role LinkRole, lane uint8) (*link.Link, error) {
	return n.admitLink(ctx, conn, info, linkAdmission{role: role, lane: lane})
}

// admitLink authenticates one dedicated Connection and publishes it in
// activeLinks. CONTROL, STREAM and PACKET lanes share this path; only an unknown
// lane is rejected before any byte is written. A STREAM or PACKET data lane
// additionally requires an already active same-peer CONTROL adjacency and is
// refused with ErrMissingControlDependency without one.
//
// Ownership: the caller must already have decided to hand conn to the Network,
// including a validated metadata snapshot. Provider metadata is sampled exactly
// once here, and cleanup from that point on closes the same idempotent owned
// wrapper: every error path closes it exactly once, success returns a Link that
// owns it. A rejection of the parameters themselves (nil context, nil
// Connection, unknown role, unsupported Lane) takes no ownership at all.
//
// Lifetime: ctx bounds the sender lease, the Noise/CAPABILITY handshake and the
// correlated admission PONG, and n.ctx additionally aborts the attempt while the
// Network is closing. A legal attempt reserves exactly one Network worker before
// its first I/O and holds it until the whole admission returns, so Network.Close
// waits for the in-flight attempt (or reports ErrCloseTimeout) instead of
// releasing the runtime owner underneath it. Success detaches from the caller
// context: the returned Link is bound to the Network lifetime only, and its own
// workers are reserved separately by the registration step.
func (n *network) admitLink(ctx context.Context, conn Connection, info ConnectionInfo, opts linkAdmission) (*link.Link, error) {
	if ctx == nil {
		return nil, invalidConfig("context", "must not be nil")
	}
	if nilValue(conn) {
		return nil, invalidConfig("connection", "must not be nil")
	}
	if !opts.role.valid() {
		return nil, invalidConfig("attach.role", "must be LinkRoleInitiator or LinkRoleResponder")
	}
	if opts.negotiate && opts.role != LinkRoleResponder {
		return nil, invalidConfig("attach.lane", "only a responder may negotiate the peer LaneID")
	}
	if !opts.negotiate && opts.lane != laneControl && opts.lane != laneStream && opts.lane != lanePacket {
		// Only lanes with a runtime consumer are accepted; an unsupported Lane
		// must fail before any byte is written.
		return nil, fmt.Errorf("attach.lane %d (%s): %w", opts.lane, laneName(opts.lane), ErrUnsupported)
	}
	owned, err := NewConnection(conn, info)
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	conn = owned
	// The request is legal and the Network now owns the stream, so this attempt
	// is accounted for before it performs any lease, durable epoch, handshake or
	// admission-PONG work. The reservation is taken under the same mutex gate
	// that checks closed and that publishes Links, so Network.Close either wins
	// the gate and is reported here as ErrClosed, or observes this attempt and
	// waits for it in finishClose instead of releasing the runtime owner while a
	// handshake is still in flight. The reservation covers exactly this attempt
	// and is released when the whole admission returns; the workers of a
	// successfully registered Link are still reserved separately, exactly once,
	// by registerAuthenticatedControlLink. Only the counter is touched here: no
	// I/O and no caller work happens under n.mu.
	n.mu.Lock()
	if n.closed || n.ctx.Err() != nil {
		n.mu.Unlock()
		return nil, errors.Join(ErrClosed, conn.Close())
	}
	n.workers.Add(1)
	n.mu.Unlock()
	defer n.workers.Done()
	stateDir, err := n.identityStore.StateDir()
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	identity, err := n.identityStore.Identity()
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	initiator := opts.role == LinkRoleInitiator
	cfg := link.LinkConfig{
		Descriptor:             n.networkContext.Descriptor(),
		NetworkID:              n.networkContext.WireID(),
		PSK:                    n.networkPSK,
		Identity:               identity,
		Initiator:              initiator,
		LaneID:                 opts.lane,
		ExpectedPeerStatic:     opts.expectedPeerStatic,
		HasExpectedPeer:        opts.hasExpectedPeer,
		CapabilityVersion:      uint16(link.CapabilityVersion),
		CapabilityMask:         link.RequiredCapabilityMask,
		RequiredCapabilityMask: link.RequiredCapabilityMask,
	}
	// A data-lane initiator must never open a Link that cannot be used: it
	// requires an already active same-peer CONTROL adjacency, the only carrier of
	// the Path/Session bootstrap. A missing CONTROL dependency is a typed
	// permission failure, not a permanent unsupported capability.
	if initiator && (opts.lane == laneStream || opts.lane == lanePacket) && !n.hasActiveControlPeer(opts.expectedPeerStatic, opts.hasExpectedPeer) {
		return nil, errors.Join(ErrMissingControlDependency, conn.Close())
	}
	// A CONTROL initiator serializes epoch allocation through admission
	// completion, keyed by the shared canonical IdentityStore directory, the full
	// ContextID and the Lane. Waiting is cancellable, is bounded by the caller's
	// context, and never holds the identity-stores registry or network.mu while
	// blocked; other ContextIDs/Lanes are not affected. The lease is released
	// only after the peer has proven durable admission, or on terminal failure.
	var attemptLease *security.LinkAttemptLease
	if initiator {
		leaseCtx, cancelLease := n.controlAttemptContext(ctx, linkAttemptGateTimeout)
		attemptLease, err = security.AcquireLinkAttempt(leaseCtx, stateDir, n.networkContext.ID(), cfg.LaneID)
		cancelLease()
		if err != nil {
			return nil, errors.Join(err, conn.Close())
		}
		defer attemptLease.Release()
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, conn.Close())
		}
		if err := n.ctx.Err(); err != nil {
			return nil, errors.Join(err, conn.Close())
		}
		// The durable allocation must exist before any HANDSHAKE record is sent.
		// Gaps are allowed; persistence failure means no Link is built.
		cfg.LinkEpoch, err = security.NextLinkEpoch(stateDir, n.networkContext.ID(), cfg.LaneID)
		if err != nil {
			return nil, errors.Join(err, conn.Close())
		}
		for cfg.LinkID == 0 {
			var random [8]byte
			if _, err := rand.Read(random[:]); err != nil {
				return nil, errors.Join(err, conn.Close())
			}
			cfg.LinkID = binary.BigEndian.Uint64(random[:])
		}
		for cfg.Generation == 0 {
			var random [4]byte
			if _, err := rand.Read(random[:]); err != nil {
				return nil, errors.Join(err, conn.Close())
			}
			cfg.Generation = binary.BigEndian.Uint32(random[:])
		}
	}
	handshakeCtx, cancelHandshake := n.controlAttemptContext(ctx, upstreamDialTimeout)
	var handoffMu sync.Mutex
	detached := false
	stop := context.AfterFunc(handshakeCtx, func() {
		handoffMu.Lock()
		defer handoffMu.Unlock()
		if !detached {
			_ = conn.Close()
		}
	})
	result, err := link.Handshake(handshakeCtx, conn, cfg)
	stop()
	handoffMu.Lock()
	contextErr := handshakeCtx.Err()
	detached = true
	handoffMu.Unlock()
	cancelHandshake()
	if err != nil || contextErr != nil {
		return nil, errors.Join(err, contextErr, conn.Close())
	}
	// A negotiated lane is whatever the peer declared in the authenticated
	// HANDSHAKE record. CONTROL, STREAM and PACKET all have a runtime consumer;
	// only an unknown lane is rejected after the handshake, before the Link is
	// published. A negotiated STREAM or PACKET lane is also refused before
	// registration unless an active same-peer CONTROL pump exists.
	negotiatedLane := result.LaneID
	if negotiatedLane != laneControl && negotiatedLane != laneStream && negotiatedLane != lanePacket {
		return nil, errors.Join(
			fmt.Errorf("negotiated attach.lane %d (%s): %w", negotiatedLane, laneName(negotiatedLane), ErrUnsupported),
			ErrPermissionDenied,
			conn.Close(),
		)
	}
	if !opts.negotiate && negotiatedLane != opts.lane {
		return nil, errors.Join(
			fmt.Errorf("negotiated attach.lane %d (%s): %w", negotiatedLane, laneName(negotiatedLane), ErrUnsupported),
			ErrPermissionDenied,
			conn.Close(),
		)
	}
	if !initiator {
		// The receiver floor must bind the authenticated transcript, not only the
		// LinkID. ChannelBinding already covers the full descriptor and Link
		// tuple; hashing it gives the storage layer a fixed 32-byte value that a
		// same-epoch replay cannot forge. This runs before registration and
		// before the responder control pump can answer any probe.
		transcriptHash := sha256.Sum256(result.ChannelBinding)
		if err := security.AcceptLinkEpoch(stateDir, n.networkContext.ID(), result.PeerNodeID, result.LaneID, result.LinkID, result.LinkEpoch, transcriptHash); err != nil {
			return nil, errors.Join(err, conn.Close())
		}
		if (negotiatedLane == laneStream || negotiatedLane == lanePacket) && n.controlPumpToPeer(result.PeerNodeID) == nil {
			// A STREAM connection that arrives before an active same-peer CONTROL
			// Link has no bootstrap carrier and must not be registered.
			return nil, errors.Join(ErrMissingControlDependency, conn.Close())
		}
	}
	authenticated, err := link.NewEstablishedLink(conn, result, conn.Info().Type)
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	pump, err := n.newControlPump(authenticated, initiator)
	if err != nil {
		return nil, errors.Join(err, authenticated.Close())
	}
	if err := n.registerAuthenticatedControlLink(ctx, authenticated, pump, initiator); err != nil {
		// The Link is retired before its pump ever ran: release the pump's
		// receive-state reservation and drop its physical Link instance here.
		pump.releaseResources()
		return nil, err
	}
	return authenticated, nil
}

// hasActiveControlPeer reports whether this Network already carries an active
// CONTROL Link to the peer whose static key it expects. Without an expected peer
// nothing can be proven and the data lane is refused.
func (n *network) hasActiveControlPeer(expected [32]byte, has bool) bool {
	if !has {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, established := range n.activeLinks {
		if established.Metadata().LaneID != laneControl || !established.Ready() {
			continue
		}
		if established.PeerStatic() == expected {
			return true
		}
	}
	return false
}

// controlPumpFor returns the authenticated control pump registered for one LinkID,
// or nil. The registry is guarded by n.mu: callers outside the lock must not index
// controlPumps directly, or a concurrent admission on another Lane races the map.
func (n *network) controlPumpFor(linkID uint64) *controlPump {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.controlPumps[linkID]
}

// controlPumpToPeer returns the CONTROL pump of one authenticated peer, or nil.
func (n *network) controlPumpToPeer(peer [16]byte) *controlPump {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, pump := range n.controlPumps {
		if pump == nil || pump.link == nil {
			continue
		}
		if pump.lane == laneControl && pump.link.PeerNodeID() == peer && pump.link.Ready() {
			return pump
		}
	}
	return nil
}

// controlAttemptContext bounds one CONTROL admission phase by the caller's
// context, a fixed phase timeout and the Network lifetime, so that a failed
// caller context and Network.Close both abort the attempt. The returned
// CancelFunc must be called when the phase ends: once it returns, nothing
// watches the caller's context any more, which is what lets a successful
// admission outlive the context that started it.
func (n *network) controlAttemptContext(caller context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(caller, timeout)
	stopNetwork := context.AfterFunc(n.ctx, cancel)
	return ctx, func() {
		stopNetwork()
		cancel()
	}
}

// registerAuthenticatedLink publishes an authenticated Link admitted under the
// Network lifetime. See registerAuthenticatedControlLink.
func (n *network) registerAuthenticatedLink(authenticated *link.Link, pump *controlPump, initiator bool) error {
	return n.registerAuthenticatedControlLink(n.ctx, authenticated, pump, initiator)
}

// registerAuthenticatedControlLink publishes only authenticated Links. n owns
// exactly one full NetworkContext, so this count is scoped to that context and
// groups solely by the authenticated PeerNodeID, across lane, role, Type and
// LinkID. The registry publication and every worker reservation happen under the
// same Close gate, so a Link returned to a caller is already accounted for by
// worker tracking. ctx bounds the initiator's correlated admission PONG.
func (n *network) registerAuthenticatedControlLink(ctx context.Context, authenticated *link.Link, pump *controlPump, initiator bool) error {
	metadata := authenticated.Metadata()
	peerNodeID := authenticated.PeerNodeID()
	n.mu.Lock()
	if n.closed || n.ctx.Err() != nil {
		n.mu.Unlock()
		pump.releaseResources()
		return errors.Join(ErrClosed, authenticated.Close())
	}
	if n.activeLinks[metadata.LinkID] != nil {
		n.mu.Unlock()
		pump.releaseResources()
		return errors.Join(ErrResource, authenticated.Close())
	}
	peerLinks := 0
	for _, active := range n.activeLinks {
		if active.PeerNodeID() == peerNodeID {
			peerLinks++
		}
	}
	if peerLinks >= maxActiveLinksPerPeer {
		n.mu.Unlock()
		pump.releaseResources()
		return errors.Join(ErrResource, authenticated.Close())
	}
	if n.activeLinks == nil {
		n.activeLinks = make(map[uint64]*link.Link)
	}
	if n.controlPumps == nil {
		n.controlPumps = make(map[uint64]*controlPump)
	}
	n.activeLinks[metadata.LinkID] = authenticated
	n.controlPumps[metadata.LinkID] = pump
	// Registry publication and all worker reservations share the Close gate.
	// The authenticated control pump is the only post-CAPABILITY stream reader.
	n.workers.Add(3)
	n.mu.Unlock()

	pump.start()
	go func() {
		defer n.workers.Done()
		select {
		case <-authenticated.Done():
		case <-n.ctx.Done():
			// Network.Close cancels first and then snapshots the registry. Do not
			// remove an open stream before that snapshot can take ownership.
			return
		}
		n.removeActiveLink(metadata.LinkID, authenticated)
	}()
	if initiator {
		// Local registry publication alone does not prove the responder durably
		// committed its receiver floor. Keep the sender lease and require a
		// correlated authenticated PONG before reporting success. Failure retires
		// this exact instance; it is never re-registered.
		if err := n.confirmAdmission(ctx, pump); err != nil {
			n.removeActiveLink(metadata.LinkID, authenticated)
			return errors.Join(err, authenticated.Close())
		}
	}
	// Only an established, durably admitted instance may advertise itself: the
	// responder publishes its NODE/ADDRESS facts on first admission, and the
	// initiator additionally publishes this exact Link instance. A publication
	// failure (durable sequence or FactStore) retires the instance instead of
	// admitting a Link whose facts were never published.
	if err := n.facts.linkAdmitted(authenticated, initiator, time.Now()); err != nil {
		n.removeActiveLink(metadata.LinkID, authenticated)
		return errors.Join(err, authenticated.Close())
	}
	return nil
}

func (n *network) removeActiveLink(linkID uint64, established *link.Link) {
	n.mu.Lock()
	removed := n.activeLinks[linkID] == established
	if removed {
		delete(n.activeLinks, linkID)
		delete(n.controlPumps, linkID)
	}
	n.mu.Unlock()
	if !removed {
		return
	}
	// The registry no longer offers this instance to the RouteView validator, and
	// exactly this Link's authenticated ingress provenance is withdrawn. A local
	// fact has no ingress source and is never removed here.
	n.facts.linkExited(established)
}

// controlPumpSnapshot returns the currently registered CONTROL-lane pumps. The
// FACT exchange is a CONTROL-lane protocol: a STREAM pump has no fact sender and
// its peer terminal-rejects any FACT frame, so handing a data pump to the fact
// runtime would advertise facts on a lane that closes the Link and leaves the
// route permanently stale. Callers that need a data pump enumerate
// n.controlPumps directly (see streamRuntime.dataPumpTo) under the same gate.
// This only reads the registry under the Close gate: no socket I/O, no fact
// lookup and no sender lock is taken while n.mu is held, so an exiting Link
// cannot block it.
func (n *network) controlPumpSnapshot() []*controlPump {
	n.mu.Lock()
	defer n.mu.Unlock()
	pumps := make([]*controlPump, 0, len(n.controlPumps))
	for _, pump := range n.controlPumps {
		if pump == nil || pump.lane != laneControl || pump.sender == nil {
			continue
		}
		pumps = append(pumps, pump)
	}
	return pumps
}

// sessionRekeyPoller is the optional data-plane policy hook the Network tick
// calls. It is implemented by *streamRuntime (the data worker's file); the
// Network only invokes it through this interface, so the policy tick never
// depends on a specific streamRuntime method existing at compile time and never
// performs session I/O itself.
type sessionRekeyPoller interface {
	pollSessionRekeys()
}

// networkPolicyTickInterval is the bounded period of the one Network policy
// worker. It matches the existing LINK_CTRL/fact cadence and is short enough that
// an idle-time key update starts long before the per-key hard boundary.
const networkPolicyTickInterval = 250 * time.Millisecond

// pollNetworkPolicy is the one bounded Network policy worker. It performs no
// socket I/O, owns no reader or writer, and adds no goroutine per Link or pump:
// each tick it snapshots the live pumps and calls their callback-safe policy
// hook, which at most enqueues writer-owned actions on the existing single
// writer.
func (n *network) pollNetworkPolicy() {
	defer n.workers.Done()
	if n == nil {
		return
	}
	ticker := time.NewTicker(networkPolicyTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.pollNetworkPolicyOnce()
		}
	}
}

// controlPumpSnapshotAll returns every registered pump, data and control lanes
// alike. The key-update policy is configured per Link instance, so a data-lane
// pump must be polled too; the FACT-only snapshot deliberately stays CONTROL.
func (n *network) controlPumpSnapshotAll() []*controlPump {
	n.mu.Lock()
	defer n.mu.Unlock()
	pumps := make([]*controlPump, 0, len(n.controlPumps))
	for _, pump := range n.controlPumps {
		if pump == nil || pump.control == nil {
			continue
		}
		pumps = append(pumps, pump)
	}
	return pumps
}

// pollNetworkPolicyOnce evaluates the in-place key-update policy of every live
// Link and asks the data plane to poll its session rekeys. Both calls are
// callback-safe and do no I/O; enqueued key-update actions go through each
// pump's existing single writer, never through the tick.
func (n *network) pollNetworkPolicyOnce() {
	if n == nil {
		return
	}
	for _, pump := range n.controlPumpSnapshotAll() {
		if pump.control != nil {
			pump.control.PollKeyUpdatePolicy()
		}
	}
	if n.streams == nil {
		return
	}
	if poller, ok := any(n.streams).(sessionRekeyPoller); ok && poller != nil {
		poller.pollSessionRekeys()
	}
}

func (n *network) DialContext(ctx context.Context, networkName, address string) (Stream, error) {
	if ctx == nil {
		return nil, invalidConfig("context", "must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if networkName != "tcp" {
		return nil, invalidConfig("network", "only tcp is supported")
	}
	virtual, err := parseVirtualAddress(address)
	if err != nil {
		return nil, err
	}
	if n.isClosed() {
		return nil, ErrClosed
	}
	if n.streams == nil {
		return nil, ErrNoRoute
	}
	return n.streams.dialStream(ctx, virtual)
}

func (n *network) Listen(networkName, address string) (StreamListener, error) {
	if networkName != "tcp" {
		return nil, invalidConfig("network", "only tcp is supported")
	}
	addr, err := parseListenAddress(address, n.localVirtualIP())
	if err != nil {
		return nil, err
	}
	if n.isClosed() {
		return nil, ErrClosed
	}
	if !n.localVirtualIP().IsValid() {
		return nil, ErrLinkDown
	}
	if addr.Addr() != n.localVirtualIP() {
		return nil, ErrPermissionDenied
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, ErrClosed
	}
	if _, exists := n.streamListeners[addr]; exists {
		return nil, ErrResource
	}
	listener := &streamListener{
		network:  n,
		address:  addr,
		done:     make(chan struct{}),
		incoming: make(chan *circuit.Circuit, streamListenerQueue),
	}
	if err := n.streams.registerPort(addr.Port(), listener); err != nil {
		return nil, err
	}
	n.streamListeners[addr] = listener
	return listener, nil
}

func (n *network) NetListener(listener StreamListener) net.Listener {
	if listener == nil {
		return nil
	}
	return streamNetListener{listener: listener}
}

func (n *network) Close() error {
	if n == nil {
		return nil
	}
	n.closeOnce.Do(func() {
		n.cancel()
		n.mu.Lock()
		n.closed = true
		carrierListeners := append([]net.Listener(nil), n.carrierListeners...)
		activeLinks := make([]*link.Link, 0, len(n.activeLinks))
		for id, established := range n.activeLinks {
			activeLinks = append(activeLinks, established)
			delete(n.activeLinks, id)
		}
		streamListeners := make([]*streamListener, 0, len(n.streamListeners))
		for _, listener := range n.streamListeners {
			streamListeners = append(streamListeners, listener)
		}
		n.streamListeners = make(map[netip.AddrPort]*streamListener)
		n.controlPumps = make(map[uint64]*controlPump)
		n.mu.Unlock()

		var closeErrors []error
		for _, listener := range streamListeners {
			listener.closeFromNetwork()
		}
		for _, listener := range carrierListeners {
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				closeErrors = append(closeErrors, err)
			}
		}
		// Every instance Close took ownership of withdraws exactly its own
		// authenticated ingress provenance before the streams are closed. Links
		// whose Done monitor already removed them were withdrawn there.
		for _, established := range activeLinks {
			n.facts.linkExited(established)
		}
		n.facts.dropAllStaging()
		for _, established := range activeLinks {
			if err := established.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				closeErrors = append(closeErrors, err)
			}
		}
		// The data plane releases its Path/Session/Circuit tables, wipes every
		// directional E2E key, drops staged unverified ciphertext and closes the
		// Noise private-key use state. It runs after the Links are closed so no
		// reader can stage one more frame, and before the runtime owner is
		// released.
		if n.streams != nil {
			if err := n.streams.close(); err != nil {
				closeErrors = append(closeErrors, err)
			}
		}
		// The FACT store releases its shared state reservation last, after the
		// allocator is closed: a publish that raced the teardown cannot reserve
		// again behind the release, so the ledger ends owning nothing and reports
		// no leak. The store's borrowed runtime state is closed by the caller
		// below, never here.
		if n.facts != nil {
			n.facts.store.Close()
		}
		go n.finishClose(closeErrors)
	})

	timer := time.NewTimer(networkCloseTimeout)
	defer timer.Stop()
	select {
	case <-n.done:
		return n.closeErr
	case <-timer.C:
		return ErrCloseTimeout
	}
}

func (n *network) finishClose(closeErrors []error) {
	n.workers.Wait()
	// The limiter's bounded metadata estimate is returned to the heap before the
	// runtime owner is released, so the ledger drains with the owner.
	n.releaseState(n.ratesLease)
	// The outbound FACT sender's shared reservation is dropped with it, after
	// every worker stopped: the single sender worker is the only resizer, so
	// releasing beside store.Close in the Close body could race a sender step
	// still in flight. A release after the allocator closed is still meaningful
	// (it returns the lease to the ledger's leak accounting) and idempotent.
	if n.facts != nil && n.facts.senderBudget != nil {
		n.facts.senderBudget.release()
	}
	// The runtime owner is released only after every worker has stopped and
	// before Done closes. Until then, including for the whole CloseTimeout
	// window, this Network still owns the StateDir+ContextID runtime state.
	if n.runtimeState != nil {
		closeErrors = append(closeErrors, n.runtimeState.Close())
	}
	if n.identityStore != nil {
		closeErrors = append(closeErrors, n.identityStore.Close())
	}
	n.closeErr = errors.Join(closeErrors...)
	close(n.done)
}

// tripVerificationCeiling is the one-shot callback of the Network-lifetime
// aggregate failed-tag ledger. It cancels the Network context immediately, so
// every pump and worker wakes, and then closes the Network from a separate
// goroutine: the reporting worker must never call Network.Close synchronously
// (Close waits for its own workers), which would turn a bounded authentication
// failure into a self-wait. The close is idempotent and coalesced by Close's own
// closeOnce.
func (n *network) tripVerificationCeiling() {
	if n == nil {
		return
	}
	n.cancel()
	go func() { _ = n.Close() }()
}

// addressRetargetTimeout bounds one host-address move. It is separate from the
// Network lifetime so a stuck host transaction can never hang the conflict tick.
const addressRetargetTimeout = 10 * time.Second

// setAddressApply installs the optional host-address mover of this Network. It
// is installed by the public Agent wrapper; a Network without a host device
// leaves it nil, and then a host move is a no-op.
func (n *network) setAddressApply(apply func(ctx context.Context, vip netip.Addr) error) {
	if n == nil {
		return
	}
	n.addressApplyMu.Lock()
	n.addressApply = apply
	n.addressApplyMu.Unlock()
}

// applyHostAddress moves this node's live host /32 to vip before the new
// VirtualIP is persisted or published. It returns nil when no host mover is
// installed. A failure is returned verbatim so the caller publishes nothing and
// keeps the previous address and routes exactly as they were.
func (n *network) applyHostAddress(ctx context.Context, vip netip.Addr) error {
	if n == nil || !vip.IsValid() || !vip.Is4() {
		return nil
	}
	n.addressApplyMu.Lock()
	apply := n.addressApply
	n.addressApplyMu.Unlock()
	if apply == nil {
		return nil
	}
	moveCtx, cancel := context.WithTimeout(ctx, addressRetargetTimeout)
	defer cancel()
	return apply(moveCtx, vip)
}

func (n *network) Done() <-chan struct{} {
	if n == nil {
		return nil
	}
	return n.done
}

// localAddress is the immutable local VirtualIP allocation snapshot. A swap
// publishes a new pointer so every reader observes either the whole old or the
// whole new (ip, attempt) pair, never a torn value.
type localAddress struct {
	ip      netip.Addr
	attempt uint32
}

// localAddressSnapshot returns the current immutable snapshot. It never returns
// nil for a constructed Network.
func (n *network) localAddressSnapshot() *localAddress {
	if n == nil || n.localAddr == nil {
		return &localAddress{}
	}
	if snapshot := n.localAddr.Load(); snapshot != nil {
		return snapshot
	}
	return &localAddress{}
}

// localIP returns this node's current VirtualIP/32.
func (n *network) localVirtualIP() netip.Addr { return n.localAddressSnapshot().ip }

// setLocalAddress atomically publishes a new VirtualIP/attempt snapshot.
//
// It deliberately does not touch the compatibility mirror localIP: that field is
// written once during construction, before the Network is published, and is read
// without a lock by the excluded FACT test helpers. Keeping an ongoing unlocked
// mirror write here would be a real data race against those readers for no
// production benefit; production readers use localVirtualIP()/snapshot.
func (n *network) setLocalAddress(ip netip.Addr, attempt uint32) {
	if n == nil || n.localAddr == nil {
		return
	}
	n.localAddr.Store(&localAddress{ip: ip, attempt: attempt})
}

// LocalVirtualIP returns the selected VirtualIP/32 of this instance.
func (n *network) LocalVirtualIP() netip.Addr {
	if n == nil {
		return netip.Addr{}
	}
	return n.localVirtualIP()
}

func (n *network) rejectUnauthenticatedCarriers(listener net.Listener) {
	defer n.workers.Done()
	// One admission object per registered listener. It carries the per-listener
	// pre-auth ceiling and paces each accepted carrier against the per-source
	// new-connection budget before any identity/Noise work. The frozen 16-way
	// handshake concurrency gate is the shared limiter semaphore, deliberately a
	// separate bound from the frozen 128-connection pre-auth ceiling.
	admission := n.newListenerAdmission()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		connection, err := NewConnection(conn, ConnectionInfo{Type: "tcp"})
		if err != nil {
			_ = conn.Close()
			continue
		}
		// The source key is normalized from the raw carrier address (IPv4 host
		// only) before the wrapper hides it. It is metadata, never a membership
		// test.
		source := rateSourceKey(conn.RemoteAddr())
		// Per-listener pre-auth accounting is checked before the concurrency
		// gate, so an over-ceiling carrier is closed before identity/Noise.
		if !admission.begin() {
			_ = connection.Close()
			continue
		}
		release, admitted := n.rates.admitHandshake()
		if !admitted {
			// The returned release must NOT be called on a refusal: the slot was
			// never taken and calling it would free another carrier's slot.
			admission.release()
			_ = connection.Close()
			continue
		}
		n.workers.Add(1)
		go func(source string) {
			defer n.workers.Done()
			defer release()
			defer admission.release()
			// A carrier whose source cannot be paced inside the bounded policy
			// window is closed here, before any handshake side effect.
			if !admission.awaitSource(n.ctx, source) {
				_ = connection.Close()
				return
			}
			if err := n.admitConnection(connection, false); err != nil {
				slog.Default().Debug("inbound link admission failed", "phase", "handshake", "err", err)
				return
			}
			// Authentication succeeded, so this peer is not a flood: refund the
			// admission token it spent. Without this a legitimate client opening
			// many streams at once throttles itself, which is the opposite of what
			// the per-source budget is for.
			admission.refundSource(source)
		}(source)
	}
}

func (n *network) isClosed() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closed
}

func (n *network) removeStreamListener(listener *streamListener) {
	n.mu.Lock()
	removed := n.streamListeners[listener.address] == listener
	if removed {
		delete(n.streamListeners, listener.address)
	}
	n.mu.Unlock()
	if removed && n.streams != nil {
		n.streams.unregisterPort(listener.address.Port(), listener)
	}
}

func parseVirtualAddress(raw string) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(raw)
	if err != nil || host == "" {
		return netip.AddrPort{}, invalidConfig("address", "must contain an explicit IPv4 address and port")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return netip.AddrPort{}, invalidConfig("address", "must use an IPv4 VirtualIP")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, invalidConfig("address", "port must be in range 1..65535")
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

func provisionalVirtualIP(prefix netip.Prefix, nodeID [16]byte, attempt uint32) (netip.Addr, error) {
	bits := prefix.Bits()
	if !prefix.IsValid() || !prefix.Addr().Is4() || bits < 1 || bits > 32 || prefix != prefix.Masked() {
		return netip.Addr{}, invalidConfig("network.cidr", "must be a canonical IPv4 prefix with length 1..32")
	}

	usableHosts := uint64(1) << uint(32-bits)
	if bits <= 30 {
		usableHosts -= 2
	}
	if usableHosts == 0 {
		return netip.Addr{}, invalidConfig("network.cidr", "has no allocatable VirtualIP")
	}

	const addressDomain = "simpletier-v1/address"
	var input [len(addressDomain) + 16 + 4]byte
	copy(input[:], addressDomain)
	copy(input[len(addressDomain):], nodeID[:])
	binary.BigEndian.PutUint32(input[len(addressDomain)+16:], attempt)
	digest := sha256.Sum256(input[:])
	index := binary.BigEndian.Uint64(digest[:8]) % usableHosts

	networkBytes := prefix.Masked().Addr().As4()
	address := binary.BigEndian.Uint32(networkBytes[:])
	if bits <= 30 {
		address++
	}
	address += uint32(index)
	var addressBytes [4]byte
	binary.BigEndian.PutUint32(addressBytes[:], address)
	return netip.AddrFrom4(addressBytes), nil
}

func parseListenAddress(raw string, localIP netip.Addr) (netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return netip.AddrPort{}, invalidConfig("address", "must be :port or an explicit local IPv4 VirtualIP and port")
	}
	addr := localIP
	if host != "" {
		addr, err = netip.ParseAddr(host)
		if err != nil || !addr.Is4() {
			return netip.AddrPort{}, invalidConfig("address", "must use the local IPv4 VirtualIP")
		}
	}
	if !addr.IsValid() || !addr.Is4() {
		return netip.AddrPort{}, ErrLinkDown
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, invalidConfig("address", "port must be in range 1..65535")
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

func closeNetworkListeners(listeners []net.Listener) error {
	var closeErrors []error
	for _, listener := range listeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErrors = append(closeErrors, err)
		}
	}
	return errors.Join(closeErrors...)
}

// streamListenerQueue bounds the number of accepted-but-not-yet-Accepted
// Circuits of one virtual listener. Overflow resets the stream with RESOURCE
// instead of growing an unbounded backlog.
const streamListenerQueue = 64

type streamListener struct {
	network   *network
	address   netip.AddrPort
	done      chan struct{}
	incoming  chan *circuit.Circuit
	closeOnce sync.Once
}

// deliver queues one target-side Circuit for this listener. A full queue or a
// closed listener reports false so the caller can reset the orphaned stream.
func (l *streamListener) deliver(c *circuit.Circuit) bool {
	select {
	case l.incoming <- c:
		return true
	case <-l.done:
		return false
	default:
		return false
	}
}

// Accept returns the next Circuit accepted for this virtual listener. It reports
// ErrClosed once the listener or the Network is closed, so a blocked Accept is
// released by Network.Close.
func (l *streamListener) Accept() (Stream, error) {
	select {
	case c := <-l.incoming:
		if c == nil {
			return nil, ErrClosed
		}
		return newCircuitStream(l.network.streams, c, NodeID(hexNode([16]byte(c.TargetNode())))), nil
	case <-l.done:
		return nil, ErrClosed
	case <-l.network.ctx.Done():
		return nil, ErrClosed
	}
}

func (l *streamListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IP(l.address.Addr().AsSlice()), Port: int(l.address.Port())}
}

func (l *streamListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.network.removeStreamListener(l)
	})
	return nil
}

func (l *streamListener) closeFromNetwork() {
	l.closeOnce.Do(func() { close(l.done) })
}

// acceptIncomingCircuits is the single target-side accept loop. It pulls every
// admitted Circuit from the Circuit manager and hands it to the virtual listener
// registered for its target port; a Circuit whose listener disappeared is
// reset instead of being silently dropped.
func (n *network) acceptIncomingCircuits() {
	defer n.workers.Done()
	if n.streams == nil {
		return
	}
	for {
		if n.ctx.Err() != nil {
			return
		}
		c, err := n.streams.circuits.Accept(n.ctx)
		if err != nil {
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}
		listener := n.streams.listenerForPort(c.TargetPort())
		if listener == nil || !listener.deliver(c) {
			_ = c.Reset(circuit.ResetReasonResource)
			continue
		}
	}
}

type streamNetListener struct {
	listener StreamListener
}

func (l streamNetListener) Accept() (net.Conn, error) {
	return l.listener.Accept()
}

func (l streamNetListener) Close() error {
	return l.listener.Close()
}

func (l streamNetListener) Addr() net.Addr {
	return l.listener.Addr()
}

// PeerFact is one authenticated fact this Network currently holds about a node
// in its own network: the node's VirtualIP owners, its advertised static key
// presence and relay capability. It carries no key material and no payload
// bytes, only what a caller needs to explain why a peer is or is not reachable.
type PeerFact struct {
	// NodeID is the peer's 16-byte NodeID in lowercase hex.
	NodeID NodeID
	// VirtualIPs are the overlay addresses this peer currently owns.
	VirtualIPs []string
	// AdvertisesRelay reports that the peer published the relay capability, so
	// it may appear as a transit hop in this Network's route search.
	AdvertisesRelay bool
	// HasStaticKey reports that a NodeFact carrying the peer's static public key
	// has been accepted, which is what a data-link dial to this peer requires.
	HasStaticKey bool
}

// Peers reports the authenticated facts this Network holds about other nodes,
// ordered by NodeID. It is a diagnostic view for multi-node operation: when a
// dial fails with ErrNoRoute, this says whether the peer was ever learned at all
// (absent), learned without a static key, or learned and merely unreachable on
// the requested lane.
//
// It reads one consistent snapshot and never consults the network.
func (n *network) Peers() ([]PeerFact, error) {
	if n == nil {
		return nil, ErrClosed
	}
	if n.isClosed() {
		return nil, ErrClosed
	}
	facts := n.facts
	if facts == nil || facts.store == nil {
		return nil, nil
	}
	records, _, err := facts.store.Snapshot(time.Now())
	if err != nil {
		return nil, err
	}
	type peerState struct {
		ips       map[string]struct{}
		hasStatic bool
		relay     bool
	}
	byNode := make(map[topology.NodeID]*peerState)
	identity, identityErr := n.identityStore.Identity()
	if identityErr != nil {
		return nil, identityErr
	}
	localNode := topology.NodeID(identity.NodeID)
	for _, record := range records {
		switch payload := record.Payload.(type) {
		case topology.NodePayload:
			state := byNode[payload.NodeID]
			if state == nil {
				state = &peerState{ips: map[string]struct{}{}}
				byNode[payload.NodeID] = state
			}
			if payload.StaticPublicKey != ([32]byte{}) {
				state.hasStatic = true
			}
			for _, capability := range payload.Capabilities {
				if capability == "relay" {
					state.relay = true
				}
			}
		case topology.AddressPayload:
			state := byNode[payload.NodeID]
			if state == nil {
				state = &peerState{ips: map[string]struct{}{}}
				byNode[payload.NodeID] = state
			}
			state.ips[payload.IP.String()] = struct{}{}
		}
	}
	peers := make([]PeerFact, 0, len(byNode))
	for nodeID, state := range byNode {
		if nodeID == localNode {
			// This node's own facts are not a peer; a caller asking "who did I
			// learn" never means itself.
			continue
		}
		ips := make([]string, 0, len(state.ips))
		for ip := range state.ips {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		peers = append(peers, PeerFact{
			NodeID:          NodeID(hex.EncodeToString(nodeID[:])),
			VirtualIPs:      ips,
			AdvertisesRelay: state.relay,
			HasStaticKey:    state.hasStatic,
		})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].NodeID < peers[j].NodeID })
	return peers, nil
}
