package simpletier

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yiiilin/simpletier/internal/budget"
	"github.com/yiiilin/simpletier/internal/circuit"
	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/path"
	"github.com/yiiilin/simpletier/internal/session"
	"github.com/yiiilin/simpletier/internal/wire"
)

// The existing LINK_CTRL reserve permits at most 64 pending messages. This pump
// queues fixed-size PONG replies (16 bytes), at most one admission confirmation
// PING per in-flight attempt and the bounded outbound FACT_SUMMARY/FACT_PAGE
// frames of this Link. Routing every write through this one goroutine preserves
// LINK_CTRL counter order (CAPABILITY consumed counter 0; the confirmation PING
// is counter 1 and later controls continue from there) without adding a second
// reader or resetting the protector.
const controlReplyQueueLimit = 64

// controlAdmissionConfirmTimeout bounds the correlated PING/PONG proof that the
// peer durably admitted this exact Link. It is separate from the 5s handshake
// timeout because the peer's receiver-floor commit and registration happen
// after its side of the CAPABILITY exchange.
const controlAdmissionConfirmTimeout = 5 * time.Second

var (
	errUnsupportedControl   = errors.New("authenticated control type has no runtime consumer")
	errAdmissionUnconfirmed = errors.New("peer link admission was not confirmed")
)

// writeKind tags one queued outer write so a single writer goroutine preserves
// the per-domain nonce order of ProtectedControlIO: LINK_CTRL counters, ROUTE_CTRL
// route counters and the hop nonce floor of each admitted session all advance in
// actual wire order because only this goroutine performs the writes.
type writeKind uint8

const (
	writeControl writeKind = iota + 1
	writeRoute
	writeEndToEnd
	// writeKeyUpdate executes one Link key-update writer action through the same
	// single writer that owns every other frame of this Link.
	writeKeyUpdate
)

// keyUpdateQueueReserve keeps slots at the tail of the single outbound queue
// available to key-update control actions, so a saturated E2E/ROUTE producer can
// never starve the in-place rekey. It is a reserve inside the one existing
// queue, not a second queue or writer.
const keyUpdateQueueReserve = 8

// rekeyPauseTimeout bounds one held business write's wait for the in-place
// update to reach Stable. On expiry, or on an aborted / fail-closed update, the
// writer releases every held backing and retires the Link: a pause is bounded,
// never an indefinite hang.
const rekeyPauseTimeout = 30 * time.Second

// rekeyStablePollInterval is how often a paused writer re-reads the update
// transaction state while it has no urgent action to execute. It is a status
// read, not I/O, and it bounds the wake-up latency of a Stability reached on the
// reader path.
const rekeyStablePollInterval = 25 * time.Millisecond

// pendingWrite is one complete outer write. lease is the shared-Network
// reservation for the exact backing this queued write still owns; it is booked
// before the write is enqueued and released after the physical write returned,
// after a queue-full refusal, or when the queue is drained at Link teardown.
type pendingWrite struct {
	kind     writeKind
	control  link.ControlMessage
	envelope []byte
	payload  []byte
	hop      link.HopRoute
	kuAction link.KeyUpdateAction
	lease    *budget.Lease
}

type controlPump struct {
	network *network
	link    *link.Link
	control *link.ProtectedControlIO
	// lane is the authenticated LaneID of this Link. FACT control types are
	// consumed only on the CONTROL lane; a data Lane carries no facts.
	lane uint8
	// outbound is the sole post-CAPABILITY writer queue. It carries LINK_CTRL
	// messages produced by consume, bootstrap ROUTE_CTRL frames (PATH_*/
	// SESSION_*) and hop-protected E2E bodies. Routing every write through this
	// one goroutine preserves counter order without adding a second reader or
	// resetting the protector.
	outbound chan pendingWrite
	// urgent carries the in-place key-update writer actions. They are the only
	// frames that may run while a business write is held by the key-use policy,
	// so they are reserved out of the single writer's order instead of waiting
	// behind the held frame. It is a priority lane of the one writer, never a
	// second writer or a second reader.
	urgent chan pendingWrite
	// drainSignal is closed and replaced whenever the writer takes a frame off
	// outbound, so producers waiting for a free slot wake up and retry instead of
	// spinning or failing.
	drainSignal chan struct{}
	drainMu     sync.Mutex
	// paused records that the sole writer refused a business write because the
	// key-use policy reached its hard boundary. The refused frame stays in held
	// with its backing lease until the update is Stable or the attempt is
	// abandoned. It is observable state, not a lock: only the writer mutates it.
	paused atomic.Bool
	// heldMu guards held for status readers. The writer is the only mutator and
	// it never calls into the core while holding the lock.
	heldMu sync.Mutex
	// held is the writer-owned FIFO of business writes the policy refused after
	// the core had spent no nonce. Each element still owns its backing lease.
	held []pendingWrite
	// sender owns this Link's bounded outbound snapshot offer. It is never a
	// second reader or writer: it only enqueues through outbound.
	sender *factLinkSender
	// recvLease is the fixed per-pump receive-state reservation (maximum frame
	// length plus decode scratch). The CoreWire reader, not an SDK hook, owns
	// those buffers, so the estimate is booked once here and released when this
	// exact Link instance is retired.
	recvLease *budget.Lease
	// linkKey is the exact physical Link instance registered before this pump
	// could enqueue anything. It is dropped when the pump is retired; a lease
	// still booked under it stays visible and releasable.
	linkKey budget.LinkKey
	// budget is the exact Network-lifetime aggregate failed-tag ledger installed
	// on this pump's hop protector before any frame flowed. It is the same value
	// for every pump of the Network, which is what makes failures aggregate.
	budget *verificationBudget
	// started is set before the reader/writer are launched; releaseResources then
	// defers to the runner refcount instead of releasing under a live goroutine.
	started atomic.Bool
	// runners counts the live reader/writer goroutines. The pump's budget and
	// registry are released only when the last one has exited, so the receive
	// buffers and any pending write backing are provably unused first.
	runners atomic.Int32
	// released records that the budget release already ran.
	released atomic.Bool
	// retired is set before the pump drains its queue at teardown, so a producer
	// that races the retirement cannot leave an undrained queued lease behind.
	retired atomic.Bool
}

// admissionProbe is one outstanding admission-confirmation probe. owner is the
// exact controlPump (hence Link and direction) that registered it: only a PONG
// read by that same pump may complete or cancel the probe. done is closed once
// the owning pump observed the correlated PONG.
type admissionProbe struct {
	owner *controlPump
	done  chan struct{}
}

func (n *network) newControlPump(authenticated *link.Link, initiator bool) (*controlPump, error) {
	control, err := link.NewProtectedControlIO(authenticated, authenticated.Metadata(), n.networkContext.Descriptor(), initiator)
	if err != nil {
		return nil, err
	}
	// Install the one Network-lifetime shared failed-tag ledger on this hop
	// protector before any frame can flow. A rejected tag is then charged to the
	// aggregate 1024 ceiling instead of only this Link's own per-key counter, and
	// a rekey never resets it.
	sharedBudget := n.verificationBudget()
	control.SetVerificationBudget(sharedBudget)
	metadata := authenticated.Metadata()
	// Register the exact physical Link instance before this pump can enqueue
	// anything, so every charge under (LinkID, Epoch) is admitted only while the
	// instance is current.
	if err := n.registerPhysicalLinkKey(metadata.LinkID, metadata.LinkEpoch); err != nil {
		return nil, err
	}
	recvLease, err := n.reservePumpRecvState()
	if err != nil {
		n.dropPhysicalLinkKey(metadata.LinkID, metadata.LinkEpoch)
		return nil, err
	}
	pump := &controlPump{
		network:     n,
		link:        authenticated,
		control:     control,
		lane:        metadata.LaneID,
		outbound:    make(chan pendingWrite, controlReplyQueueLimit),
		urgent:      make(chan pendingWrite, keyUpdateQueueReserve),
		drainSignal: make(chan struct{}),
		recvLease:   recvLease,
		linkKey:     budget.LinkKey{LinkID: metadata.LinkID, Epoch: metadata.LinkEpoch},
		budget:      sharedBudget,
	}
	// Install the in-place Link key-update engine and the writer action sink
	// before any frame flows. Self-update negotiates and fences on this carrier.
	// A peer that did not negotiate capability bit6 is not an error here: the
	// Link simply never runs an update.
	if err := pump.configureKeyUpdate(authenticated, link.KeyUpdatePolicy{}); err != nil && !errors.Is(err, link.ErrKeyUpdateUnsupported) {
		pump.releaseResources()
		return nil, err
	}
	control.SetKeyUpdateActionSink(pump.enqueueKeyUpdateActions)
	// Only a CONTROL Lane carries the FACT_SUMMARY/FACT_PAGE/FACT_ACK exchange.
	// A dedicated STREAM carrier is a pure E2E data plane: giving it a fact
	// sender would offer snapshots on a lane whose frames the peer must reject
	// (consumeFactSummary is CONTROL-only) and would keep the route permanently
	// stale by advertising on a Link that closes on the first FACT frame.
	if metadata.LaneID == laneControl {
		pump.sender = &factLinkSender{}
	}
	return pump, nil
}

// releaseResources releases the pump's receive-state reservation and drops its
// physical Link instance. Before start (an admission that failed before any
// goroutine ran) it releases immediately; after start it does nothing itself,
// because the runner refcount releases only once the reader AND the writer have
// both exited, so no buffer, queue backing or cipher copy is still in use when
// the state charge returns to zero.
func (p *controlPump) releaseResources() {
	if p == nil || p.started.Load() {
		return
	}
	p.releaseAll()
}

// exitRunner is the deferred exit of the reader or the writer. The last runner
// to leave performs the release exactly once.
func (p *controlPump) exitRunner() {
	if p == nil {
		return
	}
	if p.runners.Add(-1) == 0 {
		p.releaseAll()
	}
}

// releaseAll drains every still-queued write (releasing its backing lease) and
// then releases the receive-state reservation and the physical Link instance,
// exactly once and only after the backing is provably unused.
func (p *controlPump) releaseAll() {
	if p == nil || !p.released.CompareAndSwap(false, true) {
		return
	}
	p.retired.Store(true)
	p.drainPendingWrites()
	if p.network != nil {
		p.network.releaseState(p.recvLease)
		p.recvLease = nil
		p.network.dropPhysicalLinkKey(p.linkKey.LinkID, p.linkKey.Epoch)
	}
}

// drainPendingWrites releases the backing lease of every write still queued when
// the pump is retired, so a queue that never reached the writer does not leak
// its reservation. Channel receive is the sole owner of a queued value.
func (p *controlPump) drainPendingWrites() {
	p.releaseHeld()
	for _, queue := range []chan pendingWrite{p.outbound, p.urgent} {
		if queue == nil {
			continue
		}
	drain:
		for {
			select {
			case write := <-queue:
				p.releaseWrite(write)
			default:
				break drain
			}
		}
	}
}

// start is called only after registration and both WaitGroup reservations under
// network.mu. Exactly one protected reader owns the Link after CAPABILITY. A
// responder reaches this point only after security.AcceptLinkEpoch has durably
// committed the receiver floor, so a PONG produced here proves that commit.
func (p *controlPump) start() {
	p.started.Store(true)
	p.runners.Add(3)
	go p.read()
	go p.write()
	go p.probe()
}

// routeProbeInterval is how often a Link measures its own round trip. Route cost is
// refreshed from it, so it trades freshness against control traffic; one probe a few
// seconds apart is enough for a path that changes on the scale of seconds.
const routeProbeInterval = 3 * time.Second

// probe measures this Link's round trip on a timer. PING/PONG already exists for
// admission; this reuses it so route cost reflects the path now rather than what it was
// at handshake time.
//
// Probes are only sent on the CONTROL lane: it is the lane whose queue is reserved, so a
// probe never competes with bulk data, and the answer is a plain PONG from the peer's
// control reader.
func (p *controlPump) probe() {
	defer p.exitRunner()
	if p.lane != laneControl {
		return
	}
	ticker := time.NewTicker(routeProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.network.ctx.Done():
			return
		case <-p.link.Done():
			return
		case <-ticker.C:
		}
		var probe [16]byte
		for probe == ([16]byte{}) {
			if _, err := rand.Read(probe[:]); err != nil {
				return
			}
		}
		p.control.NoteProbeSent(probe, time.Now())
		if err := p.sendControl(link.ControlMessage{Type: 1, Payload: probe[:]}); err != nil {
			return
		}
	}
}

// read is the unique post-CAPABILITY reader of this Link. It dispatches by
// FrameKind so that LINK_CTRL consumption is unchanged while ROUTE_CTRL
// bootstrap and STREAM-lane E2E bodies reach their runtime owners.
func (p *controlPump) read() {
	defer p.network.workers.Done()
	defer p.link.Close()
	defer p.exitRunner()
	for {
		message, err := p.control.ReadMessage()
		if err != nil {
			if d, ok := frameLocalDispositionOf(originReadMessage, message, err); ok {
				p.dropFrameLocally(message, d)
				continue
			}
			return
		}
		// The frozen per-Link and Network-wide control budget is charged on the
		// real authenticated control frame before it is consumed. A control
		// message is never silently dropped: an over-budget frame is paced and,
		// if the bounded budget never admits it, this Link is failed closed.
		if !p.awaitIngressControl(message) {
			return
		}
		if err := p.consumeFrame(message); err != nil {
			if d, ok := frameLocalDispositionOf(originConsumeFrame, message, err); ok {
				p.dropFrameLocally(message, d)
				continue
			}
			return
		}
	}
}

// frameOrigin names which of the pump's two error sources rejected a frame.
// The origin is part of the disposition because the frozen attribution rule
// classifies the same sentinel differently depending on where it was produced:
// only the dispatch site that tagged the origin may be classified frame-local.
type frameOrigin uint8

const (
	originReadMessage frameOrigin = iota
	originConsumeFrame
)

// frameDisposition is the frozen disposition of one rejected frame: the stable
// class name traced in place of raw error text, and the trace phrase. The zero
// value is the not-classified value; whether the rejection is fatal for the
// shared Link is the ok result of frameLocalDispositionOf, never the class name.
type frameDisposition struct {
	class  string
	reason string
}

// frameDispositionRule is one ordered entry of the frozen per-frame disposition
// policy.
type frameDispositionRule struct {
	origin frameOrigin
	reason string
	match  func(message link.ProtectedMessage, err error) (string, bool)
}

// errOnly adapts an error-only classifier to the uniform rule signature: these
// classifiers need no frame, because their origin is already carried by the
// provenance tag the dispatch site applied.
func errOnly(match func(error) (string, bool)) func(link.ProtectedMessage, error) (string, bool) {
	return func(_ link.ProtectedMessage, err error) (string, bool) { return match(err) }
}

// frameDispositionRules is the frozen disposition policy, in evaluation order.
//
// Shared reasoning, stated once for every entry below. Each entry classifies a
// frame the pump had already read completely (wire.ReadFrame consumed the whole
// frame, so the stream stays framed and this reader can continue) and whose
// rejection happens BEFORE the hop or inner AEAD tag is verified. None of these
// origins moves replay/epoch/floor state or sets a terminal flag, so the frozen
// attribution rule (docs/domains/overlay/modules/wire-protocol.md:335) drops
// the single frame and counts it on the ingress Link instead of closing the
// shared Link that every other Session, the route bootstrap and the FACT
// exchange still use. Only the stable compile-time class name is traced, never
// raw handler error text, which can carry frame-derived identifiers (or, for
// the replay origin, credentials).
//
// Order is load-bearing: read() evaluates this table in exactly this order and
// the first matching entry wins. The two origins are independent, and
// frameLocalDispositionOf only ever considers entries carrying the origin the
// dispatch site tagged, so the identical sentinel produced by the other
// dispatch site stays terminal.
//
// Two deliberate exclusions are preserved here. A joined counter-exhaustion
// cause (link.ErrCounterExhausted) forces the fatal path in every
// ReadMessage-origin entry, because that cause means the counter cannot advance
// safely. And link.ErrUnexpectedKind is deliberately absent from the global
// semantic table (frameLocalSemanticClasses) even though two lane/kind binding
// rejections are frame-local: each of those origins is carried by its own
// provenance tag (endToEndLaneMismatchError for the FrameKindEndToEnd dispatch
// and routeLaneMismatchError for the FrameKindRouteControl dispatch), so the
// identical sentinel read out of ProtectedControlIO.ReadMessage or returned by
// consumeFrame's unknown-kind default stays terminal.
var frameDispositionRules = [...]frameDispositionRule{
	// ReadMessage origin, link.ErrReplay: a ReplaySuspected record — a
	// control/route counter at or below the committed floor, or a duplicate E2E
	// message number. The replay precheck runs before end-to-end authentication,
	// and the classifier is deliberately narrow. No raw error detail is traced
	// because it can carry credentials.
	{originReadMessage, "replayed frame dropped; Link retained", errOnly(readMessageFrameLocalClass)},
	// ReadMessage origin, link.ErrSessionNotAdmitted on a fully read E2E frame
	// whose SessionID this Link has not admitted: withSession found no admission,
	// so no session hop subkey exists and the hop AEAD tag is never verified —
	// pre-end-to-end-authentication on a SessionID any peer holding the Link root
	// can forge. The kind guard makes the entry narrow: only an E2E frame qualifies.
	{originReadMessage, "unadmitted end-to-end session frame dropped; Link retained", readMessageEndToEndSessionNotAdmittedClass},
	// ReadMessage origin, link.ErrRouteMessage on a fully read ROUTE_CTRL frame:
	// readRouteLocked / validateRouteEnvelope / checkRoutePayloadLength rejected
	// the envelope, reserved values, redundant hop PathID/Generation copy,
	// reserved pad or bootstrap length before c.rx.Verify, and readRouteLocked
	// commits no RouteCtrlCounter floor and sets no terminal flag.
	{originReadMessage, "malformed route-control frame dropped; Link retained", readMessageRouteMessageClassOf},
	// ReadMessage origin, link.ErrEndToEndMessage on a fully read E2E frame:
	// decodeEndToEndEnvelope and readEndToEndLocked's hop-nonce, hop-path, pad and
	// session-class/MessageType redundancy checks rejected the frozen
	// envelope/hop-header rules before entry.rx.Verify, so the session ciphertext
	// is never interpreted here.
	{originReadMessage, "malformed end-to-end frame dropped; Link retained", readMessageEndToEndMessageClassOf},
	// ReadMessage origin, link.ErrSessionRetired on a fully read E2E frame naming a retired SessionID:
	// withSession rejects it before c.rx.Verify — the retired entry's hop keys are destroyed and its
	// tombstone is looked up by a SessionID any peer holding the Link root can forge — so the hop AEAD
	// tag is never verified. The kind guard makes the entry narrow (only an E2E frame qualifies), and
	// retirement is unchanged: the SessionID stays un-re-admittable, the hop replay domain never rebuilt.
	{originReadMessage, "retired end-to-end session frame dropped; Link retained", readMessageSessionRetiredClassOf},
	// consumeFrame origin, tagged only by the FrameKindRouteControl dispatch: a
	// hop-authenticated ROUTE_CTRL frame whose SESSION_CTRL/SESSION_READY or
	// PATH_OPEN/PATH_READY/PATH_BROKEN body failed its structural decode or
	// path-control transition has no end-to-end authentication at all, so it is
	// attributed FrameMalformed, never a Session/Path termination from forgeable identity.
	{originConsumeFrame, "pre-E2E-auth malformed frame dropped; Link retained", errOnly(preAuthFrameMalformedClassOf)},
	// consumeFrame origin, tagged only by the FrameKindEndToEnd dispatch: a fully
	// hop-authenticated E2E frame whose authenticated lane does not match the
	// Session/Path lane it names. Both producers (handleEndToEndFrame's lane guard
	// and checkIngressPeer's data guard) run before the inner tag is verified, so
	// this is the same pre-end-to-end origin.
	{originConsumeFrame, "end-to-end lane mismatch dropped; Link retained", errOnly(endToEndLaneMismatchClassOf)},
	// consumeFrame origin, tagged only by the FrameKindRouteControl dispatch: a
	// fully hop-authenticated ROUTE_CTRL bootstrap frame read from a Link that is
	// not the CONTROL lane. checkIngressPeer's control-lane guard runs before any
	// body is decoded, so no end-to-end authentication exists at all yet.
	{originConsumeFrame, "route-control frame on a data lane dropped; Link retained", errOnly(routeLaneMismatchClassOf)},
	// consumeFrame origin, the frozen frame-local semantic set: the hop AEAD and replay checks are
	// already complete here. ReadMessage commits the ROUTE_CTRL RouteCtrlCounter floor before it returns
	// the frame, while an E2E message number is committed only after the inner tag authenticates
	// (CommitEndToEnd). Such a rejection is a stale/expired ROUTE_CTRL or E2E binding for a Session/Path
	// this node no longer owns, so it drops only that frame.
	{originConsumeFrame, "frame-local semantic rejection; Link retained", errOnly(frameLocalSemanticClassOf)},
}

// frameLocalDispositionOf reports the frozen disposition of one rejected frame.
// ok is false when no rule for this origin matches, which is the fatal case: the
// rejection is not one the attribution rule isolates to this ingress Link, so
// read() must close the Link. The boolean is the disposition decision itself and
// is deliberately not derived from the class name being non-empty.
func frameLocalDispositionOf(origin frameOrigin, message link.ProtectedMessage, err error) (frameDisposition, bool) {
	for _, rule := range frameDispositionRules {
		if rule.origin != origin {
			continue
		}
		if class, ok := rule.match(message, err); ok {
			return frameDisposition{class: class, reason: rule.reason}, true
		}
	}
	return frameDisposition{}, false
}

// dropFrameLocally charges exactly one aggregate drop for a frame the frozen
// attribution rule isolates to this ingress Link, and traces the stable class
// name. It never traces raw error text, which can carry frame-derived
// identifiers. The hook is nil-safe, so a directly built pump without a Network
// limiter still works.
func (p *controlPump) dropFrameLocally(message link.ProtectedMessage, d frameDisposition) {
	traceDataPlane(d.reason, "kind", uint8(message.Kind), "class", d.class)
	p.rates().recordFrameLocalReject()
}

// frameLocalSemanticClass is one frame-local semantic rejection class: the exact
// sentinel and the stable name traced in its place. The name is a compile-time
// constant so a trace never echoes an untrusted handler error string.
type frameLocalSemanticClass struct {
	name     string
	sentinel error
}

// frameLocalSemanticClasses is the exact set of sentinels whose appearance in a
// consumeFrame error means "this one ROUTE_CTRL/E2E frame, or the one stale
// Session/Path identity it names, is rejected", never "the physical Link
// failed". It deliberately excludes every transport, authentication, framing
// and LINK_CTRL sentinel (ErrControlMessage/ErrUnexpectedKind/ErrReplay/
// ErrCounterExhausted/ErrSessionRetired/ErrResource/ErrLinkDown/ErrClosed and
// the raw AEAD failure), so an unknown kind, a LINK_CTRL semantic error and a
// hop tag failure stay fatal. ErrUnexpectedKind is deliberately absent even
// though two lane/kind binding rejections are frame-local: each of those origins
// is carried by its own provenance tag (endToEndLaneMismatchError for the
// FrameKindEndToEnd dispatch and routeLaneMismatchError for the
// FrameKindRouteControl dispatch), so the identical sentinel read out of
// ProtectedControlIO.ReadMessage or returned by consumeFrame's unknown-kind
// default stays terminal. ErrSessionRetired is absent for the same reason even
// though the ReadMessage origin now treats it as frame-local: that origin is
// carried by its own kind-guarded predicate (readMessageSessionRetiredClassOf),
// and this table must not sweep in the identical sentinel from any other
// dispatch point. A malformed outer envelope and every hop-AEAD
// rejection are produced inside ProtectedControlIO.ReadMessage and never reach
// this classifier at all, so they stay fatal too. The ROUTE/E2E handlers'
// own envelope/path/scope binding checks are expressed as these sentinels and
// are therefore frame-local, exactly like the stale Session/Path identity they
// reject; they are traced and never silently dropped.
var frameLocalSemanticClasses = [...]frameLocalSemanticClass{
	{"route-message", link.ErrRouteMessage},
	{"invalid-hop-route", link.ErrInvalidHopRoute},
	{"session-not-admitted", link.ErrSessionNotAdmitted},
	{"end-to-end-message", link.ErrEndToEndMessage},
	{"stale-session-id", session.ErrStaleSessionID},
	{"stale-attempt", session.ErrStaleAttempt},
	{"future-attempt", session.ErrFutureAttempt},
	{"stale-epoch", session.ErrStaleEpoch},
	{"future-epoch", session.ErrFutureEpoch},
	{"session-not-found", session.ErrSessionNotFound},
	{"session-timeout", session.ErrSessionTimeout},
	{"session-aborted", session.ErrSessionAborted},
	// An authenticated CIRCUIT_OPEN whose exact SessionRef is already locally
	// terminal (Manager.FailSession made it so) is a scoped RPC drop. Only the
	// narrow refusal sentinel is classified: a bare circuit.ErrSessionLost is
	// also how the injected Egress boundary reports its own I/O failures, and
	// that must stay fatal for the Link.
	{"session-ref-failed", circuit.ErrSessionRefFailed},
	// A bounded Circuit resource refusal (egress/ingress control-budget or a
	// Manager table/pre-READY ceiling) tears only the offending Circuit/Session
	// per the frozen contract, so it must not kill the shared physical Link.
	// The inbound handler reaches this through the Manager, which wraps the
	// refusal as ErrSessionLost+ErrResource; the class is the narrow
	// circuit.ErrResource sentinel, never the broad ErrSessionLost.
	{"circuit-resource", circuit.ErrResource},
}

// frameLocalSemanticClass returns the stable class name of a frame-local
// semantic rejection, or ok=false for nil and for every failure that must stay
// terminal on this physical Link. It is applied only to the error consumeFrame
// returns after ReadMessage already accepted the frame. None of these sentinels
// classifies an error from ReadMessage itself, even when it wraps one of them:
// that origin is read on a specific FrameKind and is carried by its own
// kind-guarded predicates. Those predicates are
// readMessageEndToEndSessionNotAdmittedClass and
// readMessageSessionRetiredClassOf for the two E2E SessionID lookups, and
// readMessageRouteMessageClassOf / readMessageEndToEndMessageClassOf for the
// pre-hop-AEAD envelope/hop-header structural rejections that readRouteLocked
// and readEndToEndLocked return for a fully read frame. Applying this table to a
// ReadMessage error instead would sweep a transport, LINK_CTRL or hop-AEAD
// failure into the frame-local disposition, so read() never does.
func frameLocalSemanticClassOf(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	for _, class := range frameLocalSemanticClasses {
		if errors.Is(err, class.sentinel) {
			return class.name, true
		}
	}
	return "", false
}

// isFrameLocalSemanticError reports whether err belongs to one of the
// frame-local semantic rejection classes.
func isFrameLocalSemanticError(err error) bool {
	_, ok := frameLocalSemanticClassOf(err)
	return ok
}

// preAuthFrameMalformedError tags the consumeFrame failures whose origin is
// known inside this file: the FrameKindRouteControl dispatch accepted a fully
// hop-authenticated ROUTE_CTRL frame and the SESSION_CTRL / SESSION_READY, or
// PATH_OPEN / PATH_READY / PATH_BROKEN, body it carries then failed its
// structural decode or path-control acceptance. Those bodies have no end-to-end
// tag, so the frozen failure table classifies their origin as FrameMalformed:
// drop the single frame and count it on the ingress Link, never terminate a
// Session/Path from the body's forgeable identity and never close the shared
// Link. The tag IS the provenance: the same sentinel returned from any other
// dispatch point is left untouched and stays terminal.
type preAuthFrameMalformedError struct {
	class string
	err   error
}

// Error reports only the compile-time class name. The wrapped handler error can
// carry frame-derived identifiers, which are never surfaced.
func (e *preAuthFrameMalformedError) Error() string {
	return "pre-auth frame malformed (" + e.class + ")"
}

// Unwrap keeps errors.Is/errors.As working for every other caller.
func (e *preAuthFrameMalformedError) Unwrap() error { return e.err }

// preAuthMalformedClasses are the structural decode and path-control rejection
// sentinels a hop-authenticated ROUTE_CTRL body can produce. They come from
// session.DecodeSessionCtrl, session.DecodeSessionReady and their relay
// equivalents plus the session package's own post-decode structural bindings of
// that same body, and from path.DecodeRouteControl and the path.Manager
// Accept/MarkReady/MarkBroken transitions reached by handlePathOpen,
// handlePathReady and handlePathBroken for the PATH_OPEN / PATH_READY /
// PATH_BROKEN bodies. None of them is a transport, framing or authentication
// failure, so attributing them the FrameMalformed disposition cannot
// misclassify a genuine Link failure.
//
// path.ErrClosed is deliberately absent: the path Manager marks its ledger
// closed when the Network or a Path shuts down (recordLocked and Accept both
// return it from that state), so classifying it as a body-local drop could hide
// an orderly Network shutdown. path.ErrEntropy (a local CSPRNG failure) and
// path.ErrNotFound (no live receive path produces it: the handlers only reach
// the Manager for a Path this node has installed, and a removed record leaves
// ledgerRetired/ledgerClosed behind) are left fatal for the same reason.
var preAuthMalformedClasses = [...]frameLocalSemanticClass{
	{"malformed-session-control", session.ErrMalformedMessage},
	{"session-control-too-large", session.ErrPayloadTooLarge},
	{"invalid-session-class", session.ErrInvalidClass},
	{"lane-class-mismatch", session.ErrLaneClassMismatch},
	// PATH_OPEN / PATH_READY / PATH_BROKEN bodies are hop-authenticated only,
	// exactly like SESSION_CTRL/SESSION_READY, so their decode and path-control
	// rejections are the same pre-E2E FrameMalformed origin.
	{"path-protocol", path.ErrProtocol},
	{"path-resource-limit", path.ErrResourceLimit},
	{"invalid-path", path.ErrInvalidPath},
	{"invalid-path-lane", path.ErrInvalidLane},
	{"invalid-path-node", path.ErrInvalidNode},
	{"duplicate-path-node", path.ErrDuplicateNode},
	{"path-hop-limit", path.ErrHopLimit},
	{"path-link-mismatch", path.ErrLinkMismatch},
	{"path-inactive-link", path.ErrInactiveLink},
	{"path-digest-mismatch", path.ErrPathDigestMismatch},
	{"path-conflict", path.ErrPathConflict},
	{"path-generation-expired", path.ErrPathGenerationExpired},
	{"path-identity-mismatch", path.ErrPathMismatch},
	{"path-state", path.ErrState},
}

// preAuthMalformedClassOf reports the stable class name of one structural
// SESSION_CTRL/SESSION_READY or PATH_* body failure. It only names an origin; the
// FrameKindRouteControl dispatch decides whether that origin applies to the
// frame at hand and tags it with preAuthFrameMalformedError.
func preAuthMalformedClassOf(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	for _, class := range preAuthMalformedClasses {
		if errors.Is(err, class.sentinel) {
			return class.name, true
		}
	}
	return "", false
}

// preAuthFrameMalformedClassOf reports the class of an error the
// FrameKindRouteControl dispatch tagged as a pre-end-to-end FrameMalformed
// rejection. An untagged error stays unclassified even when it wraps one of the
// same sentinels, because only consumeFrame knows where the error was produced.
func preAuthFrameMalformedClassOf(err error) (string, bool) {
	var tagged *preAuthFrameMalformedError
	if !errors.As(err, &tagged) || tagged == nil {
		return "", false
	}
	return tagged.class, true
}

// endToEndLaneMismatchError tags the consumeFrame failures whose origin is known
// inside this file: the FrameKindEndToEnd dispatch accepted a fully
// hop-authenticated E2E frame and the frame's authenticated lane does not match
// the Session/Path lane it names. Two guards produce it, both before any
// end-to-end tag is verified: handleEndToEndFrame rejects an E2E frame read from
// a Link that is neither the STREAM nor the PACKET data lane, and
// checkIngressPeer's data guard rejects an E2E frame whose ingress Link lane is
// not the installed Path's lane (reached through openLocalEndToEnd and
// forwardEndToEnd). The frozen failure table attributes that pre-end-to-end
// origin as a per-frame binding rejection: drop the single frame and count it on
// the ingress Link, never close the shared physical Link that every other
// Session, the ROUTE bootstrap and the FACT exchange still use.
//
// The tag IS the provenance. link.ErrUnexpectedKind is ALSO produced by
// ProtectedControlIO.ReadControl/ReadMessage for a wrong-kind frame read on a
// specific reader, by the FrameKindRouteControl dispatch for a route frame read
// from a data lane (which applies its own routeLaneMismatchError tag, never this
// one), and by consumeFrame's own unknown-kind default. None of those is tagged
// with this type, so the identical sentinel from any other origin stays
// terminal.
type endToEndLaneMismatchError struct {
	err error
}

// endToEndLaneMismatchClass is the stable, compile-time class name traced in
// place of this rejection. Being a constant, a trace never echoes the raw
// handler error text, which can carry frame-derived identifiers.
const endToEndLaneMismatchClass = "e2e-lane-mismatch"

// Error reports only the compile-time class name.
func (e *endToEndLaneMismatchError) Error() string {
	return "end-to-end lane mismatch (" + endToEndLaneMismatchClass + ")"
}

// Unwrap keeps errors.Is/errors.As working for every other caller.
func (e *endToEndLaneMismatchError) Unwrap() error { return e.err }

// endToEndLaneMismatchClassOf reports the class of an error the
// FrameKindEndToEnd dispatch tagged as an E2E lane/kind binding rejection. An
// untagged error stays unclassified even when it wraps link.ErrUnexpectedKind,
// because only consumeFrame knows where the error was produced.
func endToEndLaneMismatchClassOf(err error) (string, bool) {
	var tagged *endToEndLaneMismatchError
	if !errors.As(err, &tagged) || tagged == nil {
		return "", false
	}
	return endToEndLaneMismatchClass, true
}

// routeLaneMismatchError tags the consumeFrame failures whose origin is known
// inside this file: the FrameKindRouteControl dispatch accepted a fully
// hop-authenticated ROUTE_CTRL bootstrap frame (PATH_OPEN/PATH_READY/
// PATH_BROKEN/SESSION_CTRL/SESSION_READY) and checkIngressPeer rejected it
// because the ingress Link is not the CONTROL lane. Both guard sites that
// produce it (handleLocalRoute and forwardRoute, plus handlePathOpen's
// pre-Accept proof) run before any end-to-end authentication exists at all, so
// the frozen failure table attributes this origin to the ingress Link: drop the
// single frame and count it, never terminate a Session/Path from the body's
// forgeable identity and never close the shared physical data Link that every
// other Session, the route bootstrap and the FACT exchange still use.
//
// The tag IS the provenance, and the type identity is the point: only the
// FrameKindRouteControl dispatch constructs routeLaneMismatchError, so
// routeLaneMismatchClassOf can never report the E2E origin and
// endToEndLaneMismatchClassOf can never report this one. A shared
// lane-mismatch tag would have to trust a name field at the call site instead.
// link.ErrUnexpectedKind is ALSO produced by
// ProtectedControlIO.ReadControl/ReadMessage for a wrong-kind frame read on a
// specific reader, by the FrameKindEndToEnd dispatch for an E2E frame on the
// wrong lane, and by consumeFrame's own unknown-kind default. None of those is
// tagged with this type, so the identical sentinel from any other origin stays
// terminal.
type routeLaneMismatchError struct {
	err error
}

// routeLaneMismatchClass is the stable, compile-time class name traced in place
// of this rejection. Being a constant, a trace never echoes the raw handler
// error text, which can carry frame-derived identifiers.
const routeLaneMismatchClass = "route-lane-mismatch"

// Error reports only the compile-time class name.
func (e *routeLaneMismatchError) Error() string {
	return "route-control lane mismatch (" + routeLaneMismatchClass + ")"
}

// Unwrap keeps errors.Is/errors.As working for every other caller.
func (e *routeLaneMismatchError) Unwrap() error { return e.err }

// routeLaneMismatchClassOf reports the class of an error the
// FrameKindRouteControl dispatch tagged as a ROUTE_CTRL lane rejection. An
// untagged error stays unclassified even when it wraps link.ErrUnexpectedKind,
// because only consumeFrame knows where the error was produced.
func routeLaneMismatchClassOf(err error) (string, bool) {
	var tagged *routeLaneMismatchError
	if !errors.As(err, &tagged) || tagged == nil {
		return "", false
	}
	return routeLaneMismatchClass, true
}

// authenticatedInnerMalformedClasses are the inner-payload structural and
// protocol rejections of the Circuit STREAM plane. Every one of them is
// produced inside the post-AEAD handler chain: circuit.Decode* and the Manager
// Handle* methods are reached only after openLocalEndToEnd successfully opened
// the frame under the Session's end-to-end protector, and the relay forwarding
// path never touches the Circuit package. A genuine transport failure cannot
// appear in this set, so matching it at the end-to-end dispatch point is
// provenance, not a broad sentinel sweep. The broad circuit.ErrSessionLost
// (Manager.submit/sendReady wrap their own Egress I/O failures in it),
// circuit.ErrResource and circuit.ErrSessionRefFailed are deliberately absent:
// they keep their existing disposition.
var authenticatedInnerMalformedClasses = [...]frameLocalSemanticClass{
	{"inner-malformed", circuit.ErrMalformedMessage},
	{"inner-unsupported-control", circuit.ErrUnsupportedControl},
	{"inner-invalid-port", circuit.ErrInvalidPort},
	{"inner-invalid-candidate", circuit.ErrInvalidCandidate},
	{"inner-invalid-window", circuit.ErrInvalidWindow},
	{"inner-protocol", circuit.ErrProtocol},
}

// authenticatedInnerMalformedClassOf reports the class of one structural or
// protocol rejection of an inner CONTROL_RPC/STREAM_DATA payload, or ok=false
// for nil, for another MessageType, for a non-end-to-end body length and for
// every error the frozen frame-local classifier already owns. Requiring the
// authenticated envelope's MessageType keeps the attribution to the two frozen
// Circuit inner types: no other inner payload reaches the Circuit decoders.
func authenticatedInnerMalformedClassOf(message link.ProtectedMessage, err error) (string, bool) {
	if err == nil || len(message.Envelope) != wire.EnvelopeSize {
		return "", false
	}
	switch envelopeMessageType(message.Envelope) {
	case wire.MessageTypeControlRPC, wire.MessageTypeStreamData:
	default:
		return "", false
	}
	for _, class := range authenticatedInnerMalformedClasses {
		if errors.Is(err, class.sentinel) {
			return class.name, true
		}
	}
	return "", false
}

// failAuthenticatedEndToEndSession fails exactly the one E2E Session named by
// the authenticated envelope of a frame whose inner payload has already been
// authenticated under that Session's own root. The envelope is the Session
// identity here, never a value from the malformed inner bytes. The failure is
// local and scoped to this Session: it aborts the Session object, latches the
// entry terminal so every circuit-facing boundary observes it, and fails the
// Session's Circuits through the Manager-owned FailSession API, which wakes
// their blocked readers and refuses later Opens without submitting a wire frame
// or touching the physical Link. Frames of the same Session are then consumed
// without touching Circuit state (deliverCircuitFrame's terminated check), while
// every other Session and the FACT exchange on the shared Link keep running.
//
// It returns false when the identity cannot be resolved, so the caller keeps the
// error terminal instead of failing an unknown or wrong scope.
func (p *controlPump) failAuthenticatedEndToEndSession(message link.ProtectedMessage, class string) bool {
	if p == nil || p.network == nil || p.network.streams == nil || len(message.Envelope) != wire.EnvelopeSize {
		return false
	}
	rt := p.network.streams
	if rt.circuits == nil {
		return false
	}
	entry := rt.sessionEntryByID(session.SessionID(envelopeSessionID(message.Envelope)))
	if entry == nil {
		return false
	}
	if entry.sess != nil {
		_ = entry.sess.Abort()
	}
	entry.markTerminated()
	if err := rt.circuits.FailSession(circuit.SessionRef{
		ID:             circuit.SessionID(entry.id),
		PathID:         entry.scope.id,
		PathGeneration: entry.scope.gen,
	}, circuit.ErrSessionLost); err != nil {
		traceDataPlane("authenticated inner rejection: scoped Session Circuits not failed",
			"session", hexNode([16]byte(entry.id))[:8], "class", class)
	}
	traceDataPlane("authenticated inner frame rejected; scoped Session failed",
		"session", hexNode([16]byte(entry.id))[:8], "class", class)
	return true
}

// readMessageFrameLocalClass reports the replay-origin ReadMessage failure that
// is a frame-local drop rather than a Link failure: a ReplaySuspected record,
// which the frozen attribution rule requires to be dropped AND counted before
// end-to-end authentication while the ingress Link stays up. It is deliberately
// narrower than isFrameLocalSemanticError: only link.ErrReplay qualifies, and a
// counter-exhaustion cause forces the fatal path even if a future error ever
// joined the two. Truncation, malformed envelopes, wrong generation/hop path,
// hop AEAD tag failures and I/O match nothing here and stay fatal. The other
// ReadMessage-origin frame-local classes need the frame Kind and are carried
// separately by their own kind-guarded predicates
// (readMessageEndToEndSessionNotAdmittedClass, readMessageRouteMessageClassOf,
// readMessageEndToEndMessageClassOf and readMessageSessionRetiredClassOf).
func readMessageFrameLocalClass(err error) (string, bool) {
	if err == nil || !errors.Is(err, link.ErrReplay) || errors.Is(err, link.ErrCounterExhausted) {
		return "", false
	}
	return "replay-suspected", true
}

// readMessageSessionNotAdmittedClass is the stable, compile-time class name
// traced for a ReadMessage-origin E2E frame whose SessionID is not admitted on
// this Link. Being a constant, a trace never echoes the raw error text, which
// can carry a frame-derived SessionID.
const readMessageSessionNotAdmittedClass = "session-not-admitted"

// readMessageEndToEndSessionNotAdmittedClass reports the one ReadMessage failure
// that is frame-local beyond the replay class: ProtectedControlIO.ReadMessage
// fully read a hop-protected E2E frame and readEndToEndLocked found its
// SessionID absent from this Link's admission table. The Link layer deliberately
// treats that as non-terminal (withSession sets no terminal flag and
// readEndToEndLocked moves no replay/epoch floor before it returns), and the
// frozen attribution rule requires the pre-end-to-end-authentication violation
// to be dropped and counted on the ingress Link, never to close the shared Link
// that every other Session, the route bootstrap and the FACT exchange still use.
//
// The classification is a narrow kind-guarded predicate, not a sentinel sweep:
// link.ErrSessionNotAdmitted alone is not the provenance. ReadMessage reports the
// rejected frame's Kind, so only an E2E frame qualifies. A ROUTE_CTRL or
// LINK_CTRL frame, an unknown kind and every other ReadMessage failure match
// nothing here and stay terminal, as does the identical sentinel from the
// consumeFrame origin, which read() classifies through
// frameLocalSemanticClassOf's own table.
func readMessageEndToEndSessionNotAdmittedClass(message link.ProtectedMessage, err error) (string, bool) {
	if err == nil || message.Kind != wire.FrameKindEndToEnd {
		return "", false
	}
	// A counter-exhaustion cause forces the fatal path even if a future error
	// ever joined the two, exactly like the replay classifier's guard.
	if errors.Is(err, link.ErrCounterExhausted) {
		return "", false
	}
	if !errors.Is(err, link.ErrSessionNotAdmitted) {
		return "", false
	}
	return readMessageSessionNotAdmittedClass, true
}

// readMessageRouteMessageClass is the stable, compile-time class name traced for
// a ReadMessage-origin ROUTE_CTRL frame rejected by the frozen envelope,
// reserved-value, redundant hop-header or bootstrap-length rules. Being a
// constant, a trace never echoes the raw error text, which can carry
// frame-derived identifiers.
const readMessageRouteMessageClass = "route-message"

// readMessageRouteMessageClassOf reports a ReadMessage-origin frame-local
// ROUTE_CTRL structural rejection: link.ErrRouteMessage returned by
// readRouteLocked / validateRouteEnvelope / checkRoutePayloadLength for a frame
// wire.ReadFrame already consumed completely and whose hop AEAD tag has not been
// verified (those checks all run before c.rx.Verify). The Link layer documents
// that origin as non-terminal and frame-local, and readRouteLocked commits no
// RouteCtrlCounter floor and sets no terminal flag before it returns, so the
// frozen attribution rule requires the single frame to be dropped and counted
// on the ingress Link.
//
// The classification is a narrow kind-guarded predicate, not a sentinel sweep:
// link.ErrRouteMessage alone is not the provenance. ReadMessage reports the
// rejected frame's Kind, so only a ROUTE_CTRL frame qualifies; the identical
// sentinel from WriteRoute, from the consumeFrame ROUTE dispatch or from any
// other origin is read on a different path and stays terminal. A
// counter-exhaustion cause forces the fatal path even if a future error ever
// joined the two, because that cause means the counter cannot advance safely.
func readMessageRouteMessageClassOf(message link.ProtectedMessage, err error) (string, bool) {
	if err == nil || message.Kind != wire.FrameKindRouteControl {
		return "", false
	}
	if errors.Is(err, link.ErrCounterExhausted) {
		return "", false
	}
	if !errors.Is(err, link.ErrRouteMessage) {
		return "", false
	}
	return readMessageRouteMessageClass, true
}

// readMessageEndToEndMessageClass is the stable, compile-time class name traced
// for a ReadMessage-origin E2E frame rejected by the frozen envelope/hop-header
// redundancy or the session-class/MessageType binding rules.
const readMessageEndToEndMessageClass = "end-to-end-message"

// readMessageEndToEndMessageClassOf reports a ReadMessage-origin frame-local E2E
// structural rejection: link.ErrEndToEndMessage returned by
// decodeEndToEndEnvelope or by readEndToEndLocked's hop-nonce, hop-path, pad and
// session-class/MessageType checks for a frame wire.ReadFrame already consumed
// completely. Every one of those checks runs before entry.rx.Verify (the session
// ciphertext itself is never interpreted here), and none of them moves a
// replay/epoch floor or sets a terminal flag, so the frozen attribution rule
// requires the single frame to be dropped and counted on the ingress Link. The
// frame is fully read, so the stream stays framed and this reader can continue.
//
// The classification is a narrow kind-guarded predicate, not a sentinel sweep:
// link.ErrEndToEndMessage alone is not the provenance. ReadMessage reports the
// rejected frame's Kind, so only an E2E frame qualifies; the identical sentinel
// from WriteEndToEnd or from the consumeFrame E2E dispatch stays terminal. A
// counter-exhaustion cause forces the fatal path in every joined form, most
// importantly the decodeEndToEndEnvelope value that joins it with
// ErrEndToEndMessage, because that cause means the counter cannot advance
// safely.
func readMessageEndToEndMessageClassOf(message link.ProtectedMessage, err error) (string, bool) {
	if err == nil || message.Kind != wire.FrameKindEndToEnd {
		return "", false
	}
	if errors.Is(err, link.ErrCounterExhausted) {
		return "", false
	}
	if !errors.Is(err, link.ErrEndToEndMessage) {
		return "", false
	}
	return readMessageEndToEndMessageClass, true
}

// readMessageSessionRetiredClass is the stable, compile-time class name traced
// for a ReadMessage-origin E2E frame naming a SessionID this Link retired.
const readMessageSessionRetiredClass = "session-retired"

// readMessageSessionRetiredClassOf reports the last ReadMessage-origin
// frame-local class: ProtectedControlIO.ReadMessage fully read a hop-protected
// E2E frame and withSession found the envelope's SessionID in this Link's
// admission table as an explicitly retired keyless tombstone. The Link layer
// deliberately treats that as non-terminal (RetireSession and withSession set no
// terminal flag and readEndToEndLocked moves no floor before it returns), and
// the frozen attribution rule requires the pre-end-to-end-authentication
// violation to be dropped and counted on the ingress Link: the tombstone is
// looked up by a SessionID any peer holding the Link root can forge, and the
// retired entry's hop keys are already destroyed, so the hop AEAD tag is never
// verified. Closing the shared physical Link for it would let a forgeable
// SessionID deny service to every other Session, the route bootstrap and the
// FACT exchange on that Link, exactly what the rule forbids.
//
// Retirement itself is unchanged: the SessionID stays un-re-admittable and the
// hop replay domain is never rebuilt. The classification is a narrow
// kind-guarded predicate, not a sentinel sweep: link.ErrSessionRetired alone is
// not the provenance. ReadMessage reports the rejected frame's Kind, so only an
// E2E frame qualifies; the identical sentinel from AdmitSession, from the
// outbound WriteEndToEnd or from the consumeFrame origin stays terminal. A
// counter-exhaustion cause forces the fatal path.
func readMessageSessionRetiredClassOf(message link.ProtectedMessage, err error) (string, bool) {
	if err == nil || message.Kind != wire.FrameKindEndToEnd {
		return "", false
	}
	if errors.Is(err, link.ErrCounterExhausted) {
		return "", false
	}
	if !errors.Is(err, link.ErrSessionRetired) {
		return "", false
	}
	return readMessageSessionRetiredClass, true
}

// rates returns the shared Network limiter of this pump, or nil for a directly
// built pump. A nil limiter is permissive, exactly like the standalone limiter.
func (p *controlPump) rates() *networkRates {
	if p == nil || p.network == nil {
		return nil
	}
	return p.network.rates
}

// awaitIngressControl charges one inbound authenticated control frame against the
// frozen per-Link and Network-wide control budget before it is consumed. It
// covers FrameKindLinkControl (PING/PONG/LINK_ERROR/TEARDOWN, the FACT_* family,
// and the in-place key-update opcode) and FrameKindRouteControl (PATH_*/SESSION_*
// bootstrap): those are the wire classes the frozen per-Link datum names. The
// wait is bounded: the reader applies TCP backpressure for a short window and
// then fails the Link closed with an explicit counter instead of discarding a
// control message. E2E data frames are not control and are not charged here;
// their disposition belongs to the data/buffer budgets.
//
// The inbound half of an in-place key update that arrives while this writer is
// paused on a held business frame uses the same limited recovery allowance as the
// outbound action, so a rekey can always complete: the frame spends a token when
// the budget admits it and is counted as an exemption otherwise.
func (p *controlPump) awaitIngressControl(message link.ProtectedMessage) bool {
	switch message.Kind {
	case wire.FrameKindLinkControl:
		if p.paused.Load() && len(message.Payload) > 0 && message.Payload[0] == link.ControlTypeKeyUpdate {
			return p.allowRecoveryControl()
		}
	case wire.FrameKindRouteControl:
	default:
		return true
	}
	if p == nil || p.network == nil {
		return true
	}
	return p.network.awaitControl(p.network.ctx, p.link.Done(), p.linkKey.LinkID, p.linkKey.Epoch) == nil
}

// awaitEgressControl charges one outbound queued control frame (LINK_CTRL,
// bootstrap ROUTE_CTRL or an in-place key-update action) against the same frozen
// budget when the single writer is about to make it physical. A frame the bounded
// budget never admits fails the Link closed instead of being silently dropped.
// The token is spent when the frame is admitted for execution; a spent token
// followed by a teardown is the accepted fail-closed outcome, never a refund path.
func (p *controlPump) awaitEgressControl(write pendingWrite) bool {
	if write.kind == writeEndToEnd {
		return true
	}
	if p == nil || p.network == nil {
		return true
	}
	return p.network.awaitControl(p.network.ctx, p.link.Done(), p.linkKey.LinkID, p.linkKey.Epoch) == nil
}

// awaitRecoveryControl charges one in-place key-update frame. While a business
// frame is held by the key-use policy the sole writer cannot make progress
// without the recovery frame, so the frozen limited recovery allowance applies:
// the frame spends a token when the budget admits it and is counted as an
// exemption otherwise. The exemption is bounded by the existing pause timeout
// (rekeyPauseTimeout) and the reserved urgent lane, never an unlimited bypass;
// outside a pause the recovery frame waits under the same bounded policy as every
// other control frame.
func (p *controlPump) awaitRecoveryControl() bool {
	if p == nil || p.network == nil {
		return true
	}
	if p.paused.Load() {
		return p.allowRecoveryControl()
	}
	return p.network.awaitControl(p.network.ctx, p.link.Done(), p.linkKey.LinkID, p.linkKey.Epoch) == nil
}

// allowRecoveryControl is the frozen limited recovery allowance of one in-place
// key-update frame while a business frame is held by the key-use policy: the sole
// writer cannot make progress without it, so it spends a token when the budget
// admits it and is counted as an exemption otherwise. It is bounded by the
// existing pause timeout (rekeyPauseTimeout), the reserved urgent lane and the
// key-update state machine, never an unlimited bypass.
func (p *controlPump) allowRecoveryControl() bool {
	rates := p.rates()
	if rates == nil {
		return true
	}
	if ok, _ := rates.tryControl(p.linkKey.LinkID, p.linkKey.Epoch); ok {
		return true
	}
	rates.noteControlRecoveryExempt()
	return true
}

// consumeFrame routes one fully hop-authenticated frame. A semantic rejection of
// a ROUTE_CTRL/E2E frame is not terminal for the Link by itself; only a
// LINK_CTRL semantic failure (or an unsupported kind) ends this pump, exactly as
// the pre-migration strict reader did.
//
// It also attributes four origins that the handlers cannot distinguish once
// their error has left them, because this is the single dispatch point that
// still knows which kind produced the error:
//   - a structural decode or path-control rejection of a hop-authenticated
//     SESSION_CTRL/SESSION_READY or PATH_OPEN/PATH_READY/PATH_BROKEN ROUTE_CTRL
//     body is tagged preAuthFrameMalformedError, which read() treats as the
//     frozen pre-E2E FrameMalformed drop+count;
//   - a hop-authenticated ROUTE_CTRL frame read from a Link that is not the
//     CONTROL lane is tagged routeLaneMismatchError, which read() treats as the
//     frozen pre-E2E per-frame lane binding rejection (drop+count, Link
//     retained);
//   - an E2E frame whose authenticated lane does not match the Session/Path lane
//     it names is tagged endToEndLaneMismatchError, which read() treats as the
//     frozen pre-E2E per-frame binding rejection (drop+count, Link retained);
//   - a CONTROL_RPC/STREAM_DATA structural or protocol rejection that can only
//     have been produced after the end-to-end tag authenticated fails exactly
//     the E2E Session named by the authenticated envelope.
//
// Everything else is returned unchanged, so the terminal boundary is preserved.
func (p *controlPump) consumeFrame(message link.ProtectedMessage) error {
	switch message.Kind {
	case wire.FrameKindLinkControl:
		if len(message.Payload) == 0 {
			return link.ErrControlMessage
		}
		typ := message.Payload[0]
		payload := append([]byte(nil), message.Payload[1:]...)
		return p.consume(link.ControlMessage{Type: typ, Payload: payload})
	case wire.FrameKindRouteControl:
		err := p.network.handleRouteFrame(p, message)
		if err == nil {
			return nil
		}
		// Only a SESSION_CTRL/SESSION_READY or PATH_OPEN/PATH_READY/PATH_BROKEN
		// ROUTE_CTRL body carries no end-to-end authentication: it is
		// hop-authenticated only. A structural decode or path-control rejection of
		// exactly such a body is therefore the frozen pre-E2E FrameMalformed
		// origin, and read() drops plus counts the single frame without
		// terminating a Session/Path from the body's forgeable identity. The
		// envelope MessageType is part of the hop-authenticated envelope, so the
		// attribution does not trust the malformed body.
		if len(message.Envelope) == wire.EnvelopeSize {
			switch envelopeMessageType(message.Envelope) {
			case wire.MessageTypeSessionCtrl, wire.MessageTypeSessionReady,
				wire.MessageTypePathOpen, wire.MessageTypePathReady, wire.MessageTypePathBroken:
				if class, ok := preAuthMalformedClassOf(err); ok {
					return &preAuthFrameMalformedError{class: class, err: err}
				}
			}
		}
		// checkIngressPeer's control-lane guard rejects a hop-authenticated
		// ROUTE_CTRL frame read from a DATA lane before it decodes any body and
		// before any end-to-end authentication exists. That is the frozen
		// pre-E2E per-frame lane binding origin, and this dispatch is the only
		// point that still knows the error came from the route path. The tag is
		// a distinct type from the E2E one, so neither dispatch can be reported
		// under the other's class, and the identical sentinel from ReadMessage,
		// from the E2E dispatch or from the unknown-kind default stays terminal.
		if errors.Is(err, link.ErrUnexpectedKind) {
			return &routeLaneMismatchError{err: err}
		}
		return err
	case wire.FrameKindEndToEnd:
		err := p.network.handleEndToEndFrame(p, message)
		if err == nil {
			return nil
		}
		// The frozen frame-local semantic classes keep their existing
		// disposition (read() drops and counts them) before any stronger
		// attribution is considered, so a stale/expired Session/Path binding
		// and a bounded Circuit resource refusal are never turned into a
		// Session failure here.
		if isFrameLocalSemanticError(err) {
			return err
		}
		// The one E2E lane/kind binding rejection is attributed here, because
		// this is the only point that still knows the error came from the E2E
		// dispatch. handleEndToEndFrame's lane guard and checkIngressPeer's data
		// lane guard both run before the inner tag is verified, so the frame is
		// the frozen pre-end-to-end per-frame binding rejection, not a Link
		// failure. The tag keeps the identical sentinel from ReadMessage, from
		// the ROUTE_CTRL dispatch and from the unknown-kind default terminal.
		if errors.Is(err, link.ErrUnexpectedKind) {
			return &endToEndLaneMismatchError{err: err}
		}
		// A CONTROL_RPC/STREAM_DATA body that fails to decode or is refused by
		// the Manager AFTER the end-to-end tag authenticated is an authenticated
		// state error: it fails only the exact E2E Session named by the
		// authenticated envelope, leaving the shared physical Link serving every
		// other Session. A pre-AEAD error never reaches the Circuit decoders, so
		// this attribution cannot capture a transport failure.
		if class, ok := authenticatedInnerMalformedClassOf(message, err); ok &&
			p.failAuthenticatedEndToEndSession(message, class) {
			return nil
		}
		return err
	default:
		return link.ErrUnexpectedKind
	}
}

func (p *controlPump) consume(message link.ControlMessage) error {
	switch message.Type {
	case 1: // PING, already authenticated and checked to contain a 16-byte ProbeID.
		// The PONG reply is a protected control frame and must never be quietly
		// dropped: it routes through the same reserved, budgeted enqueue as every
		// other write, and a full queue is a terminal resource failure.
		return p.sendControl(link.ControlMessage{Type: 2, Payload: message.Payload})
	case 2:
		// A PONG only completes the outstanding admission-confirmation probe that
		// this exact pump owns. A PONG that arrives on another pump, or with no
		// matching probe, is ignored: it refreshes no liveness, creates no fact
		// and grants no route.
		var probe [16]byte
		copy(probe[:], message.Payload)
		// The round trip is the same measurement admission uses, so route cost gets it for
		// free: a PONG that completes no admission probe still tells this Link how long a
		// frame takes to come back.
		p.control.NoteProbeAcknowledged(probe, time.Now())
		p.network.resolveAdmissionProbe(probe, p)
		return nil
	case 3, 5: // LINK_ERROR / TEARDOWN shape was validated by ProtectedControlIO.
		return ErrLinkDown
	case 6: // FACT_SUMMARY v2, decoded and admitted by the authenticated consumer.
		if p.lane != laneControl {
			return errUnsupportedControl
		}
		return p.consumeFactSummary(message.Payload)
	case 7: // FACT_PAGE v2: staged per Link, never committed partially.
		if p.lane != laneControl {
			return errUnsupportedControl
		}
		return p.consumeFactPage(message.Payload)
	case 8: // FACT_ACK v2: correlates with this Link's own outbound snapshot.
		if p.lane != laneControl {
			return errUnsupportedControl
		}
		return p.consumeFactAck(message.Payload)
	case link.ControlTypeKeyUpdate:
		// The in-place key-update opcode rides the existing encrypted LINK_CTRL
		// frame. The single reader decodes it (no I/O) and the returned writer
		// actions execute on the same single writer.
		actions, handled, err := p.control.HandleKeyUpdateControl(message)
		if !handled {
			return errUnsupportedControl
		}
		if err != nil {
			return err
		}
		return p.enqueueKeyUpdateActions(actions)
	default:
		return errUnsupportedControl
	}
}

// sendControl enqueues one outbound control for the unique writer. It never
// blocks: a full queue is a terminal resource failure for the caller.
func (p *controlPump) sendControl(message link.ControlMessage) error {
	return p.enqueue(pendingWrite{kind: writeControl, control: message})
}

// sendRoute enqueues one bootstrap ROUTE_CTRL frame for the unique writer.
func (p *controlPump) sendRoute(envelope, payload []byte, hop link.HopRoute) error {
	return p.enqueue(pendingWrite{kind: writeRoute, envelope: envelope, payload: payload, hop: hop})
}

// sendEndToEnd enqueues one hop-protected E2E frame for the unique writer. The
// payload is opaque session ciphertext; this queue never inspects it.
func (p *controlPump) sendEndToEnd(envelope, payload []byte, hop link.HopRoute) error {
	return p.enqueue(pendingWrite{kind: writeEndToEnd, envelope: envelope, payload: payload, hop: hop})
}

func (p *controlPump) enqueue(write pendingWrite) error {
	if p.retired.Load() {
		return ErrLinkDown
	}
	// Key-update recovery actions use the reserved priority lane so they are
	// never stuck behind a business frame the policy later holds. Every other
	// write leaves the reserved tail free for them.
	queue := p.outbound
	if write.kind == writeKeyUpdate {
		queue = p.urgent
	} else {
		// Backpressure, not failure. A full queue means the physical writer is
		// behind, which is normal under concurrent load: the right response is to
		// make this producer wait for a slot, exactly as a bounded channel is meant
		// to work. Returning ErrResource here turned a busy Link into a dead
		// Circuit, which under sixteen concurrent streams killed most of them and
		// left their readers blocked forever.
		//
		// The reserved tail is still left free for key-update control, so a data
		// producer can never starve the in-place rekey.
		for len(p.outbound) >= cap(p.outbound)-keyUpdateQueueReserve {
			if p.retired.Load() {
				return ErrLinkDown
			}
			select {
			case <-p.drainSignal:
			case <-p.link.Done():
				return ErrLinkDown
			case <-p.network.ctx.Done():
				return ErrClosed
			}
		}
	}
	// Reserve the exact complete-wire backing of this queued write before it can
	// own a queue slot. Admission is all-or-none, so a full Network/Link pool is
	// a resource decision returned to the caller and never a silent unaccounted
	// enqueue.
	lease, err := p.reserveWrite(write)
	if err != nil {
		return err
	}
	write.lease = lease
	if p.retired.Load() {
		p.releaseWrite(write)
		return ErrLinkDown
	}
	select {
	case queue <- write:
		if p.retired.Load() {
			// The pump retired (and drained) while this write was being admitted,
			// so no writer will ever execute it. Releasing here is idempotent: the
			// drain will see an already-released lease and be a no-op.
			p.releaseWrite(write)
			return ErrLinkDown
		}
		return nil
	case <-p.link.Done():
		p.releaseWrite(write)
		return ErrLinkDown
	case <-p.network.ctx.Done():
		p.releaseWrite(write)
		return ErrClosed
	default:
		p.releaseWrite(write)
		return ErrResource
	}
}

// reserveWrite books one queued outer write against the shared allocator under
// this exact physical Link instance. LINK_CTRL/ROUTE_CTRL/key-update frames book
// Control; a hop-protected E2E body books Data, because sealing an inner frame
// produces a NEW owned ciphertext array that is not the same backing as the
// receiver/send buffer charged elsewhere, so it is a genuine additional charge
// under the 64 MiB Network and per-Link 4 MiB / 64 frame data bounds. The
// estimate is the complete wire size including the 4-byte length prefix, the
// outer authentication tag and the route envelope, plus one frame.
func (p *controlPump) reserveWrite(write pendingWrite) (*budget.Lease, error) {
	if p == nil || p.network == nil {
		return nil, ErrLinkDown
	}
	alloc := p.network.stateBudgetPtr()
	if alloc == nil {
		return nil, fmt.Errorf("%w: physical Link budget allocator is not available", ErrResource)
	}
	category := budget.CategoryControl
	switch write.kind {
	case writeEndToEnd:
		category = budget.CategoryData
	case writeControl, writeRoute, writeKeyUpdate:
		category = budget.CategoryControl
	default:
		return nil, fmt.Errorf("%w: unknown queued write kind %d", ErrResource, write.kind)
	}
	lease, err := alloc.Reserve(budget.Request{Charges: []budget.Charge{{
		Owner:    budget.LinkPool(budget.NetworkID(p.network.networkContext.WireID()), p.linkKey),
		Category: category,
		Bytes:    write.wireBytes(),
		Frames:   1,
	}}})
	if err != nil {
		return nil, fmt.Errorf("%w: queue write reservation: %v", ErrResource, err)
	}
	return lease, nil
}

// releaseWrite returns one queued write's backing reservation. It is idempotent
// and safe after the allocator closed.
func (p *controlPump) releaseWrite(write pendingWrite) {
	if write.lease == nil {
		return
	}
	_ = write.lease.Release()
}

// wireBytes is the complete-wire estimate of one queued write: 4-byte length
// prefix, the outer frame header/authentication tag and the payload this write
// actually owns. It is an inclusive upper bound, not a kernel allocation claim.
func (w pendingWrite) wireBytes() uint64 {
	const (
		lengthPrefix = 4
		outerTag     = 16
		linkCtrlHead = 2 // kind/hop byte plus opcode byte
		routeEnv     = 85
		keyUpdateMax = 64
	)
	switch w.kind {
	case writeControl:
		return lengthPrefix + linkCtrlHead + outerTag + uint64(len(w.control.Payload))
	case writeRoute:
		return lengthPrefix + routeEnv + uint64(len(w.payload)) + outerTag
	case writeEndToEnd:
		return lengthPrefix + uint64(len(w.payload)) + outerTag
	case writeKeyUpdate:
		return lengthPrefix + keyUpdateMax
	default:
		return lengthPrefix
	}
}

// configureKeyUpdate installs the in-place key-update engine on this Link with
// the pinned local identity, peer static, PSK, descriptor and Link tuple. The
// zero policy resolves to the built-in defaults; a test or a future runtime
// policy knob may pass an explicit one.
func (p *controlPump) configureKeyUpdate(established *link.Link, policy link.KeyUpdatePolicy) error {
	if p == nil || p.control == nil || established == nil {
		return ErrLinkDown
	}
	identity, err := p.network.identityStore.Identity()
	if err != nil {
		return err
	}
	metadata := established.Metadata()
	return p.control.ConfigureKeyUpdate(link.KeyUpdateConfig{
		Identity:                identity,
		PeerStatic:              established.PeerStatic(),
		PSK:                     p.network.networkPSK,
		Descriptor:              p.network.networkContext.Descriptor(),
		TargetLinkID:            metadata.LinkID,
		TargetLinkEpoch:         metadata.LinkEpoch,
		LaneID:                  metadata.LaneID,
		PeerAdvertisedKeyUpdate: true,
		Policy:                  policy,
	})
}

// noteDrained wakes every producer waiting for an outbound slot. The channel is
// replaced under drainMu so a waker never misses a wake-up that races the swap.
func (p *controlPump) noteDrained() {
	p.drainMu.Lock()
	close(p.drainSignal)
	p.drainSignal = make(chan struct{})
	p.drainMu.Unlock()
}

// enqueueKeyUpdateActions is the writer action sink: it enqueues every action on
// the single outbound writer without blocking, so it is safe to call from the
// reader, the writer and the policy's own poll point. A full reserved queue is a
// resource decision returned to the caller, never a deadlock.
func (p *controlPump) enqueueKeyUpdateActions(actions []link.KeyUpdateAction) error {
	for _, action := range actions {
		if err := p.enqueue(pendingWrite{kind: writeKeyUpdate, kuAction: action}); err != nil {
			return err
		}
	}
	return nil
}

// confirmAdmission sends a fresh random ProbeID PING through the unique
// protected writer and waits for the matching authenticated PONG read by the
// same pump. The probe is registered as owned by this pump, so only a PONG that
// arrives on this exact Link/attempt can complete it; a PONG observed by any
// other pump, or an unsolicited one, is not this attempt's proof. The peer
// starts its control pump only after its durable receiver-floor commit and
// registration, so a matching PONG is the honest peer's behavioral ordering
// proof that this exact Link was durably admitted. It is an ordering argument
// about when the honest peer answers, not a cryptographic fsync proof of its
// storage device. The caller must hold the sender serialization lease until this
// returns: on caller-context cancellation, Network.Close, Close, EOF, queue
// failure or the 5s deadline the attempt is retired and the connection plus
// lease are released without re-registering. ctx covers this wait only; the
// successful Link is not bound to it afterwards.
func (n *network) confirmAdmission(ctx context.Context, pump *controlPump) error {
	if ctx == nil {
		return invalidConfig("context", "must not be nil")
	}
	var probe [16]byte
	for probe == ([16]byte{}) {
		if _, err := rand.Read(probe[:]); err != nil {
			return err
		}
	}
	done, ok := n.registerAdmissionProbe(probe, pump)
	if !ok {
		return ErrResource
	}
	defer n.cancelAdmissionProbe(probe, pump)
	if err := pump.sendControl(link.ControlMessage{Type: 1, Payload: probe[:]}); err != nil {
		return err
	}
	timer := time.NewTimer(controlAdmissionConfirmTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-pump.link.Done():
		return ErrLinkDown
	case <-n.ctx.Done():
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errAdmissionUnconfirmed
	}
}

// registerAdmissionProbe reserves a fresh ProbeID for the given owning pump and
// returns the channel closed when that pump reads the matching PONG. A nil owner
// is rejected, as is reusing an ID that is still pending: the caller must not be
// able to complete a probe it does not own.
func (n *network) registerAdmissionProbe(probe [16]byte, owner *controlPump) (chan struct{}, bool) {
	if owner == nil {
		return nil, false
	}
	n.probeMu.Lock()
	defer n.probeMu.Unlock()
	if n.pendingProbes == nil {
		n.pendingProbes = make(map[[16]byte]admissionProbe)
	}
	if _, exists := n.pendingProbes[probe]; exists {
		return nil, false
	}
	done := make(chan struct{})
	n.pendingProbes[probe] = admissionProbe{owner: owner, done: done}
	return done, true
}

// resolveAdmissionProbe completes a pending probe only when the PONG was read by
// the exact pump that registered it. It returns false for a foreign-pump or
// unsolicited PONG, which must not change any Network state.
func (n *network) resolveAdmissionProbe(probe [16]byte, owner *controlPump) bool {
	n.probeMu.Lock()
	defer n.probeMu.Unlock()
	pending, ok := n.pendingProbes[probe]
	if !ok || owner == nil || pending.owner != owner {
		return false
	}
	delete(n.pendingProbes, probe)
	close(pending.done)
	return true
}

// cancelAdmissionProbe drops a probe only for its owning pump. A probe already
// resolved, or re-registered by a different pump, is left untouched so an old
// pump can never detach or complete a newer owner's probe.
func (n *network) cancelAdmissionProbe(probe [16]byte, owner *controlPump) {
	n.probeMu.Lock()
	defer n.probeMu.Unlock()
	pending, ok := n.pendingProbes[probe]
	if !ok || pending.owner != owner {
		return
	}
	delete(n.pendingProbes, probe)
}

func (p *controlPump) write() {
	defer p.network.workers.Done()
	defer p.link.Close()
	defer p.exitRunner()
	// Held business writes are owned by this goroutine, so release their backing
	// before the runner refcount can retire the pump. The defer order (LIFO)
	// makes this run before exitRunner.
	defer p.releaseHeld()
	for {
		// A key-update recovery action must never wait behind a business write
		// that the policy refused, so the reserved urgent lane is always served
		// first. This is a non-blocking priority check; the blocking select below
		// still serves urgent while it waits on outbound.
		select {
		case write := <-p.urgent:
			if !p.runKeyUpdateAction(write) {
				return
			}
			continue
		case <-p.link.Done():
			return
		case <-p.network.ctx.Done():
			return
		default:
		}
		if p.heldFrameCount() > 0 {
			// A business write is held pending rekey. Only the reserved recovery
			// actions may make progress until the update is Stable.
			if !p.awaitStableAndRetry() {
				return
			}
			continue
		}
		select {
		case write := <-p.urgent:
			if !p.runKeyUpdateAction(write) {
				return
			}
		case write := <-p.outbound:
			// A slot just freed: wake producers waiting on backpressure before
			// doing this frame's work, so a slow write does not serialize them.
			p.noteDrained()
			if !p.awaitEgressControl(write) {
				// The bounded control budget never admitted this frame. Fail the
				// Link closed instead of dropping the control silently; release
				// this write's backing exactly once first.
				p.releaseWrite(write)
				return
			}
			// The sole ProtectedControlIO TX lock spends counters in actual wire
			// order. Link.Close interrupts a blocked socket write.
			err := p.executeWrite(write)
			if errors.Is(err, link.ErrKeyUpdateRequired) {
				// All-or-none refusal before a nonce was spent: retain the frame
				// and its backing lease and pause business writes until the
				// in-place update reaches Stable. The lease is NOT released here.
				p.holdRefused(write)
				continue
			}
			// The backing of this write is no longer in use once its physical
			// write returned (success or failure); return it exactly once. A
			// partial or uncertain transport failure is terminal and is never
			// retried.
			p.releaseWrite(write)
			if err != nil {
				return
			}
		case <-p.link.Done():
			return
		case <-p.network.ctx.Done():
			return
		}
	}
}

// runKeyUpdateAction executes one in-place key-update writer action and releases
// its backing. Its failure is terminal exactly as before: an uncertain partial
// batch is never replayed.
func (p *controlPump) runKeyUpdateAction(write pendingWrite) bool {
	if !p.awaitRecoveryControl() {
		p.releaseWrite(write)
		return false
	}
	err := p.executeWrite(write)
	p.releaseWrite(write)
	return err == nil
}

// holdRefused retains one business write the core refused with
// ErrKeyUpdateRequired. The refusal is a pre-nonce, all-or-none decision, so the
// exact same frame may be re-sealed under a later root without reusing a nonce.
// The owned bytes are copied so a caller that reuses its buffer after enqueue
// cannot change what the retry seals; the copy is the same size already covered
// by this write's backing lease. The recovery engine is nudged here because the
// automatic trigger does not run on a failed write.
func (p *controlPump) holdRefused(write pendingWrite) {
	write.control.Payload = append([]byte(nil), write.control.Payload...)
	write.envelope = append([]byte(nil), write.envelope...)
	write.payload = append([]byte(nil), write.payload...)
	p.heldMu.Lock()
	p.held = append(p.held, write)
	p.heldMu.Unlock()
	p.paused.Store(true)
	if p.control != nil {
		p.control.PollKeyUpdatePolicy()
	}
}

// heldFrameCount reports how many business writes the policy currently holds.
func (p *controlPump) heldFrameCount() int {
	if p == nil {
		return 0
	}
	p.heldMu.Lock()
	defer p.heldMu.Unlock()
	return len(p.held)
}

// releaseHeld releases the backing of every held business write and clears the
// paused state. It is idempotent and safe after the allocator closed.
func (p *controlPump) releaseHeld() {
	if p == nil {
		return
	}
	p.heldMu.Lock()
	held := p.held
	p.held = nil
	p.heldMu.Unlock()
	p.paused.Store(false)
	for _, write := range held {
		p.releaseWrite(write)
	}
}

// awaitStableAndRetry blocks the writer until the in-place update reaches Stable
// and then re-executes the held writes in their original FIFO order. While it
// waits it keeps serving the urgent recovery lane, so a recovery action queued
// behind the held frame still runs. It returns false when the attempt must end:
// no recovery engine is configured, the update aborted or failed closed, the
// Link or Network retired, or the bounded pause expired. On every false path
// each held lease is released exactly once and the Link is retired normally.
func (p *controlPump) awaitStableAndRetry() bool {
	if p.control == nil || !p.control.KeyUpdateStatus().Configured {
		// No recovery channel on this Link, so a held write can never become
		// writable: fail closed now instead of retaining a lease forever.
		p.releaseHeld()
		return false
	}
	deadline := time.NewTimer(rekeyPauseTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(rekeyStablePollInterval)
	defer tick.Stop()
	for !p.keyUpdateStable() {
		select {
		case write := <-p.urgent:
			if !p.runKeyUpdateAction(write) {
				p.releaseHeld()
				return false
			}
		case <-tick.C:
			if p.keyUpdateAbandoned() {
				p.releaseHeld()
				return false
			}
		case <-p.link.Done():
			p.releaseHeld()
			return false
		case <-p.network.ctx.Done():
			p.releaseHeld()
			return false
		case <-deadline.C:
			p.releaseHeld()
			return false
		}
	}
	return p.retryHeld()
}

// keyUpdateStable reports the carrier's own mutual-DONE proof that the update
// switched this Link's roots. Status is a snapshot read with no I/O.
func (p *controlPump) keyUpdateStable() bool {
	if p == nil || p.control == nil {
		return false
	}
	return p.control.KeyUpdateStatus().State == link.KuStateStable
}

// keyUpdateAbandoned reports a recovery attempt that can no longer reach Stable:
// an aborted transaction or an automatic-start / action-sink failure the core
// already recorded.
func (p *controlPump) keyUpdateAbandoned() bool {
	if p == nil || p.control == nil {
		return true
	}
	status := p.control.KeyUpdateStatus()
	if status.Aborted || status.State == link.KuStateAborted {
		return true
	}
	return p.control.KeyUpdateTriggerError() != nil
}

// retryHeld re-executes every held write in its original order under the new
// stable root and releases each backing exactly once. A physical or partial
// failure is terminal and not retried; any remaining held backing is released.
func (p *controlPump) retryHeld() bool {
	p.heldMu.Lock()
	held := p.held
	p.held = nil
	p.heldMu.Unlock()
	p.paused.Store(false)
	for _, write := range held {
		err := p.executeWrite(write)
		p.releaseWrite(write)
		if err != nil {
			p.releaseHeld()
			return false
		}
	}
	return true
}

// executeWrite performs exactly one queued outer write through the single
// ProtectedControlIO writer and returns a physical failure (or ErrResource for an
// unknown kind). ErrKeyUpdateAbort is a deliberate pause, not a failure.
func (p *controlPump) executeWrite(write pendingWrite) error {
	switch write.kind {
	case writeControl:
		return p.control.WriteControl(write.control)
	case writeRoute:
		return p.control.WriteRoute(write.envelope, write.payload, write.hop)
	case writeEndToEnd:
		return p.control.WriteEndToEnd(write.envelope, write.payload, write.hop)
	case writeKeyUpdate:
		// Execute the action through its bound carrier, deliver the
		// writer-completion event exactly once after the physical write, then
		// enqueue the follow-ups on this same writer.
		follow, kuErr := p.control.ApplyAndCompleteKeyUpdate(write.kuAction)
		if kuErr != nil && !errors.Is(kuErr, link.ErrKeyUpdateAbort) {
			return kuErr
		}
		return p.enqueueKeyUpdateActions(follow)
	default:
		return ErrResource
	}
}
