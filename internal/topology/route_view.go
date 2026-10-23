package topology

import (
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	maxRouteCandidates = 3
	maxRouteHops       = 16
	maxRouteNodes      = 1024
	maxRouteLinks      = 4096
	pathCostUnit       = uint64(1_000_000)
)

var (
	ErrNoRoute       = errors.New("no route")
	ErrPolicyDenied  = errors.New("route policy denied")
	ErrRouteConflict = errors.New("route conflict")
	ErrRouteStale    = errors.New("route stale")
	ErrResourceLimit = errors.New("route resource limit")
	ErrInvalidFact   = errors.New("invalid route fact")

	routeRebuildSlots = make(chan struct{}, 2)
)

// LocalLinkValidator synchronously checks one local physical Link instance.
// peer is the adjacent remote NodeID; lane is CONTROL, PACKET, or STREAM.
// Implementations must only inspect a local activeLinks snapshot, perform no
// network I/O, and be safe for concurrent calls.
type LocalLinkValidator func(linkID, epoch uint64, lane uint8, peer NodeID) bool

// RoutePolicy controls whether intermediate nodes may relay traffic. Endpoints
// are never required to advertise relay capability.
type RoutePolicy struct {
	AllowRelay bool
}

// PathCost is accumulated in fixed 1,000,000-unit increments per base-cost unit.
type PathCost uint64

// LinkRef identifies one authenticated physical Link instance from the view.
type LinkRef struct {
	ID             uint64
	Epoch          uint64
	LaneID         uint8
	ConnectionType string
}

// CandidatePath is one immutable-view route; returned slices are caller-owned.
type CandidatePath struct {
	Nodes       []NodeID
	Links       []LinkRef
	LaneID      uint8
	Cost        PathCost
	ViewVersion uint64
	Freshness   RouteFreshness
}

// AddressResolution pins one live IPv4 /32 owner and its fact version.
type AddressResolution struct {
	NodeID      NodeID
	Prefix      netip.Prefix
	FactVersion FactVersion
	Freshness   RouteFreshness
}

// RouteFreshness classifies whether a result uses the last successful view.
type RouteFreshness uint8

const (
	RouteViewFresh RouteFreshness = iota
	RouteViewStale
)

// PacketRoute combines a pinned address owner with PACKET-lane candidates.
type PacketRoute struct {
	DestinationNode    NodeID
	Prefix             netip.Prefix
	AddressFactVersion FactVersion
	LaneID             uint8
	Candidates         []CandidatePath
	ViewVersion        uint64
	Freshness          RouteFreshness
}

// RouteView publishes complete topology snapshots and revalidates each query
// against current facts and local physical Link state.
type RouteView struct {
	store   *FactStore
	local   NodeID
	active  LocalLinkValidator
	refresh sync.Mutex
	mu      sync.RWMutex
	current *routeSnapshot
}

type routeSnapshot struct {
	version uint64
	stale   bool
	graph   routeGraph
}

type routeGraph struct {
	nodes     map[NodeID]routeNode
	edges     []routeEdge
	addresses map[netip.Addr]map[NodeID]routeAddress
}

type routeNode struct {
	ref   routeFactRef
	relay bool
}

type routeFactRef struct {
	key     []byte
	version FactVersion
}

type routeAddress struct {
	resolution AddressResolution
	ref        routeFactRef
}

type routeControlRef struct {
	ref    routeFactRef
	linkID uint64
	epoch  uint64
	local  bool
	peer   NodeID
}

type routeEdge struct {
	from     NodeID
	to       NodeID
	ref      routeFactRef
	link     LinkRef
	cost     uint64
	local    bool
	peer     NodeID
	controls []routeControlRef
}

type routePair struct {
	first  NodeID
	second NodeID
}

type routeArc struct {
	edge int
	from NodeID
	to   NodeID
}

type routeQueryGraph struct {
	nodes       map[NodeID]routeNode
	edges       []routeEdge
	adjacency   map[NodeID][]routeArc
	invalidated bool
}

type routeAddressOwners map[netip.Addr]map[NodeID]routeAddress

type currentRouteState struct {
	version uint64
	now     time.Time
	owners  routeAddressOwners
	// nodes holds the live NODE fact reference of every node visible in the same
	// store snapshot as owners. Address resolution checks node liveness against
	// this live map instead of the immutable view's pinned version, because a
	// renewed NODE fact of the same node is a normal re-advertisement.
	nodes  map[NodeID]routeFactRef
	checks map[string]bool
}

// NewRouteView builds the first immutable topology view from one FactStore
// snapshot. An active-link validator is required so fact-only local edges can
// never become usable routes.
func NewRouteView(store *FactStore, active LocalLinkValidator) (*RouteView, error) {
	if store == nil || active == nil {
		return nil, fmt.Errorf("%w: store and local active-link validator are required", ErrInvalidFact)
	}
	view := &RouteView{store: store, local: store.localNode, active: active}
	if err := view.Refresh(time.Now()); err != nil {
		return nil, err
	}
	return view, nil
}

// Version returns the FactStore version used to build the currently published
// complete view. A failed refresh never changes this value.
func (rv *RouteView) Version() uint64 {
	state := rv.snapshot()
	if state == nil {
		return 0
	}
	return state.version
}

// Freshness reports stale when refresh failed or the FactStore has advanced
// since this immutable view was published.
func (rv *RouteView) Freshness() RouteFreshness {
	if rv == nil || rv.store == nil {
		return RouteViewStale
	}
	state := rv.snapshot()
	if state == nil || state.stale || rv.store.Version() != state.version {
		return RouteViewStale
	}
	return RouteViewFresh
}

// Refresh atomically publishes a complete view from one deep-copied Store
// snapshot. Errors preserve the last complete view and mark it stale.
func (rv *RouteView) Refresh(now time.Time) error {
	if rv == nil || rv.store == nil || rv.active == nil {
		return fmt.Errorf("%w: uninitialized RouteView", ErrInvalidFact)
	}
	rv.refresh.Lock()
	defer rv.refresh.Unlock()

	routeRebuildSlots <- struct{}{}
	defer func() { <-routeRebuildSlots }()

	records, version, err := rv.store.Snapshot(now)
	if err != nil {
		rv.markStale()
		return classifyRouteFactError(err)
	}
	graph, err := buildRouteGraph(records, rv.store.wireID, rv.local, now)
	if err != nil {
		rv.markStale()
		return err
	}
	if rv.store.Version() != version {
		rv.markStale()
		return fmt.Errorf("%w: FactStore changed while rebuilding", ErrRouteStale)
	}

	rv.mu.Lock()
	rv.current = &routeSnapshot{version: version, graph: graph}
	rv.mu.Unlock()
	return nil
}

// ResolveVirtualIP resolves only an unambiguous IPv4 /32 AddressFact pinned in
// this view, and verifies the mapping and owner against the current FactStore.
func (rv *RouteView) ResolveVirtualIP(addr netip.Addr) (AddressResolution, error) {
	if rv == nil || rv.store == nil {
		return AddressResolution{}, fmt.Errorf("%w: uninitialized RouteView", ErrInvalidFact)
	}
	if !addr.Is4() {
		return AddressResolution{}, fmt.Errorf("%w: target must be IPv4", ErrInvalidFact)
	}
	for attempt := 0; attempt < 2; attempt++ {
		state := rv.snapshot()
		if state == nil {
			return AddressResolution{}, ErrRouteStale
		}
		current, err := rv.currentState(time.Now())
		if err != nil {
			return AddressResolution{}, err
		}
		result, queryErr := rv.resolveAddress(state, addr, current)
		if rv.store.Version() != current.version || rv.snapshot() != state {
			continue
		}
		return result, queryErr
	}
	return AddressResolution{}, ErrRouteStale
}

// Candidates returns at most three current paths for a PACKET or STREAM Lane.
// Results are copied and remain detached from the immutable internal graph.
func (rv *RouteView) Candidates(dst NodeID, lane uint8, policy RoutePolicy) ([]CandidatePath, error) {
	if rv == nil || rv.store == nil {
		return nil, fmt.Errorf("%w: uninitialized RouteView", ErrInvalidFact)
	}
	if lane != FactLanePacket && lane != FactLaneStream {
		return nil, fmt.Errorf("%w: candidates require PACKET or STREAM lane", ErrInvalidFact)
	}
	for attempt := 0; attempt < 2; attempt++ {
		state := rv.snapshot()
		if state == nil {
			return nil, ErrRouteStale
		}
		current, err := rv.currentState(time.Now())
		if err != nil {
			return nil, err
		}
		paths, _, queryErr := rv.candidatesAt(state, dst, lane, policy, current)
		if rv.store.Version() != current.version || rv.snapshot() != state {
			continue
		}
		return paths, queryErr
	}
	return nil, ErrRouteStale
}

// PacketCandidates resolves the pinned /32 destination and computes PACKET
// candidates against the same current Store snapshot used for conflict checks.
func (rv *RouteView) PacketCandidates(addr netip.Addr, policy RoutePolicy) (PacketRoute, error) {
	if rv == nil || rv.store == nil {
		return PacketRoute{}, fmt.Errorf("%w: uninitialized RouteView", ErrInvalidFact)
	}
	if !addr.Is4() {
		return PacketRoute{}, fmt.Errorf("%w: target must be IPv4", ErrInvalidFact)
	}
	for attempt := 0; attempt < 2; attempt++ {
		state := rv.snapshot()
		if state == nil {
			return PacketRoute{}, ErrRouteStale
		}
		current, err := rv.currentState(time.Now())
		if err != nil {
			return PacketRoute{}, err
		}
		resolution, queryErr := rv.resolveAddress(state, addr, current)
		if queryErr != nil {
			if rv.store.Version() != current.version || rv.snapshot() != state {
				continue
			}
			return PacketRoute{}, queryErr
		}
		paths, freshness, queryErr := rv.candidatesAt(state, resolution.NodeID, FactLanePacket, policy, current)
		if queryErr != nil {
			if rv.store.Version() != current.version || rv.snapshot() != state {
				continue
			}
			return PacketRoute{}, queryErr
		}
		if rv.store.Version() != current.version || rv.snapshot() != state {
			continue
		}
		return PacketRoute{
			DestinationNode:    resolution.NodeID,
			Prefix:             resolution.Prefix,
			AddressFactVersion: resolution.FactVersion,
			LaneID:             FactLanePacket,
			Candidates:         paths,
			ViewVersion:        state.version,
			Freshness:          freshness,
		}, nil
	}
	return PacketRoute{}, ErrRouteStale
}

func (rv *RouteView) snapshot() *routeSnapshot {
	if rv == nil {
		return nil
	}
	rv.mu.RLock()
	state := rv.current
	rv.mu.RUnlock()
	return state
}

func (rv *RouteView) markStale() {
	rv.mu.Lock()
	if rv.current != nil && !rv.current.stale {
		stale := *rv.current
		stale.stale = true
		rv.current = &stale
	}
	rv.mu.Unlock()
}

func classifyRouteFactError(err error) error {
	switch {
	case errors.Is(err, ErrFactTooLarge):
		return fmt.Errorf("%w: %v", ErrResourceLimit, err)
	case errors.Is(err, ErrFactMalformed), errors.Is(err, ErrFactNetwork):
		return fmt.Errorf("%w: %v", ErrInvalidFact, err)
	default:
		return fmt.Errorf("%w: current FactStore snapshot unavailable: %v", ErrRouteStale, err)
	}
}

func buildRouteGraph(records []FactRecord, networkID uint64, local NodeID, now time.Time) (routeGraph, error) {
	if len(records) > maxFactLiveRecords {
		return routeGraph{}, ErrResourceLimit
	}
	nodes := make(map[NodeID]routeNode)
	addressesByIP := make(map[netip.Addr]map[NodeID]routeAddress)
	links := make([]routeEdge, 0)
	var nodeCount, linkCount, addressCount int
	for _, record := range records {
		if err := ValidateFactForNetwork(record, networkID); err != nil {
			return routeGraph{}, fmt.Errorf("%w: %v", ErrInvalidFact, err)
		}
		key, err := FactKey(record)
		if err != nil {
			return routeGraph{}, fmt.Errorf("%w: %v", ErrInvalidFact, err)
		}
		ref := routeFactRef{key: append([]byte(nil), key...), version: record.Envelope.Version}
		switch payload := record.Payload.(type) {
		case NodePayload:
			if record.Envelope.Kind != FactNode || payload.NodeID != record.Envelope.Origin {
				return routeGraph{}, fmt.Errorf("%w: NODE origin mismatch", ErrInvalidFact)
			}
			nodeCount++
			if nodeCount > maxRouteNodes {
				return routeGraph{}, ErrResourceLimit
			}
			nodes[payload.NodeID] = routeNode{ref: ref, relay: hasCapability(payload.Capabilities, "relay")}
		case LinkPayload:
			if record.Envelope.Kind != FactLink || payload.From != record.Envelope.Origin {
				return routeGraph{}, fmt.Errorf("%w: LINK origin mismatch", ErrInvalidFact)
			}
			linkCount++
			if linkCount > maxRouteLinks {
				return routeGraph{}, ErrResourceLimit
			}
			peer, localEdge := localPeer(local, payload.From, payload.To)
			links = append(links, routeEdge{
				from: payload.From, to: payload.To, ref: ref,
				link: LinkRef{ID: payload.LinkID, Epoch: payload.LinkEpoch, LaneID: payload.LaneID, ConnectionType: payload.ConnectionType},
				cost: routeLinkCost(payload.Cost), local: localEdge, peer: peer,
			})
		case AddressPayload:
			if record.Envelope.Kind != FactAddress || payload.NodeID != record.Envelope.Origin || !payload.IP.Is4() || payload.PrefixLen != 32 {
				return routeGraph{}, fmt.Errorf("%w: invalid ADDRESS fact", ErrInvalidFact)
			}
			addressCount++
			if addressCount > maxAddressFacts {
				return routeGraph{}, ErrResourceLimit
			}
			if addressesByIP[payload.IP] == nil {
				addressesByIP[payload.IP] = make(map[NodeID]routeAddress)
			}
			addressesByIP[payload.IP][payload.NodeID] = routeAddress{
				resolution: AddressResolution{NodeID: payload.NodeID, Prefix: netip.PrefixFrom(payload.IP, 32), FactVersion: record.Envelope.Version},
				ref:        ref,
			}
		case RevocationPayload:
			// Tombstones are kept by FactStore and are not graph nodes or edges.
		default:
			return routeGraph{}, fmt.Errorf("%w: unknown FactRecord payload %T", ErrInvalidFact, record.Payload)
		}
	}

	controlByPair := make(map[routePair][]routeControlRef)
	for _, edge := range links {
		if edge.link.LaneID != FactLaneControl || nodes[edge.from].ref.key == nil || nodes[edge.to].ref.key == nil {
			continue
		}
		controlByPair[makeRoutePair(edge.from, edge.to)] = append(controlByPair[makeRoutePair(edge.from, edge.to)], routeControlRef{
			ref: edge.ref, linkID: edge.link.ID, epoch: edge.link.Epoch, local: edge.local, peer: edge.peer,
		})
	}

	dataEdges := make([]routeEdge, 0, len(links))
	for _, edge := range links {
		if edge.link.LaneID != FactLanePacket && edge.link.LaneID != FactLaneStream {
			continue
		}
		if nodes[edge.from].ref.key == nil || nodes[edge.to].ref.key == nil {
			continue
		}
		controls := controlByPair[makeRoutePair(edge.from, edge.to)]
		if len(controls) == 0 {
			continue
		}
		edge.controls = append([]routeControlRef(nil), controls...)
		dataEdges = append(dataEdges, edge)
	}
	sort.Slice(dataEdges, func(i, j int) bool {
		if c := bytes.Compare(dataEdges[i].from[:], dataEdges[j].from[:]); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(dataEdges[i].to[:], dataEdges[j].to[:]); c != 0 {
			return c < 0
		}
		if dataEdges[i].link.ID != dataEdges[j].link.ID {
			return dataEdges[i].link.ID < dataEdges[j].link.ID
		}
		return dataEdges[i].link.Epoch < dataEdges[j].link.Epoch
	})

	graph := routeGraph{nodes: nodes, edges: dataEdges, addresses: addressesByIP}
	return graph, nil
}

func (rv *RouteView) currentState(now time.Time) (currentRouteState, error) {
	records, version, err := rv.store.Snapshot(now)
	if err != nil {
		return currentRouteState{}, classifyRouteFactError(err)
	}
	owners := make(routeAddressOwners)
	nodes := make(map[NodeID]routeFactRef)
	for _, record := range records {
		if record.Envelope.Kind == FactNode {
			payload, ok := record.Payload.(NodePayload)
			if !ok || payload.NodeID != record.Envelope.Origin {
				// A malformed NODE fact is not evidence of a live node. The view
				// builder rejects it and marks the view stale; address resolution
				// must treat it as absent rather than as a live owner node.
				continue
			}
			key, err := FactKey(record)
			if err != nil {
				return currentRouteState{}, fmt.Errorf("%w: %v", ErrInvalidFact, err)
			}
			nodes[payload.NodeID] = routeFactRef{key: append([]byte(nil), key...), version: record.Envelope.Version}
			continue
		}
		payload, ok := record.Payload.(AddressPayload)
		if !ok || record.Envelope.Kind != FactAddress {
			continue
		}
		key, err := FactKey(record)
		if err != nil {
			return currentRouteState{}, fmt.Errorf("%w: %v", ErrInvalidFact, err)
		}
		if owners[payload.IP] == nil {
			owners[payload.IP] = make(map[NodeID]routeAddress)
		}
		owners[payload.IP][payload.NodeID] = routeAddress{
			resolution: AddressResolution{NodeID: payload.NodeID, Prefix: netip.PrefixFrom(payload.IP, 32), FactVersion: record.Envelope.Version},
			ref:        routeFactRef{key: append([]byte(nil), key...), version: record.Envelope.Version},
		}
	}
	if rv.store.Version() != version {
		return currentRouteState{}, ErrRouteStale
	}
	return currentRouteState{version: version, now: now, owners: owners, nodes: nodes, checks: make(map[string]bool)}, nil
}

func (rv *RouteView) resolveAddress(view *routeSnapshot, addr netip.Addr, current currentRouteState) (AddressResolution, error) {
	owners := current.owners[addr]
	if len(owners) > 1 {
		return AddressResolution{}, ErrRouteConflict
	}
	old, exists := view.graph.address(addr)
	if view.graph.addressConflicts(addr) {
		if len(owners) > 1 {
			return AddressResolution{}, ErrRouteConflict
		}
		return AddressResolution{}, ErrRouteStale
	}
	if !exists {
		if len(owners) != 0 {
			return AddressResolution{}, ErrRouteStale
		}
		return AddressResolution{}, ErrNoRoute
	}
	// The live FactStore owner is authoritative for this mapping, so owner
	// identity is compared and never the fact version. A renewed AddressFact of
	// the same owner carries a higher version but names the same /32 owner; that
	// renewal is exactly what the local re-advertisement tick publishes, so a
	// version mismatch alone must not report a correctly owned address as stale
	// for the whole window until the immutable view is rebuilt. The live version
	// is kept as the pin/diagnostic value. A genuinely different live owner, a
	// conflicting live owner set, or a live fact that a withdrawal/expiry/
	// revocation removed still fails closed.
	liveOwner, currentOwnerExists := owners[old.resolution.NodeID]
	if !currentOwnerExists || len(owners) != 1 || !rv.currentFact(liveOwner.ref, current) {
		return AddressResolution{}, ErrRouteStale
	}
	// The owner's NODE fact is re-advertised the same way, with a new version
	// while its identity and key stay the same, so liveness is checked against
	// the live snapshot instead of the view's pinned version. A view node that
	// no longer exists, or a node absent from the live snapshot because it
	// expired, was withdrawn or was revoked, is stale.
	if _, nodeExists := view.graph.nodes[old.resolution.NodeID]; !nodeExists {
		return AddressResolution{}, ErrRouteStale
	}
	if _, liveNodeExists := current.nodes[old.resolution.NodeID]; !liveNodeExists {
		return AddressResolution{}, ErrRouteStale
	}
	resolution := liveOwner.resolution
	resolution.Freshness = rv.queryFreshness(view, current.version, false)
	return resolution, nil
}

func (rv *RouteView) candidatesAt(view *routeSnapshot, dst NodeID, lane uint8, policy RoutePolicy, current currentRouteState) ([]CandidatePath, RouteFreshness, error) {
	graph, filtered := rv.currentGraph(view, lane, current)
	freshness := rv.queryFreshness(view, current.version, filtered)
	if _, ok := graph.nodes[rv.local]; !ok {
		if freshness == RouteViewStale {
			return nil, freshness, ErrRouteStale
		}
		return nil, freshness, ErrNoRoute
	}
	if _, ok := graph.nodes[dst]; !ok {
		if freshness == RouteViewStale {
			return nil, freshness, ErrRouteStale
		}
		return nil, freshness, ErrNoRoute
	}
	paths := kShortestPaths(&graph, rv.local, dst, lane, policy, maxRouteCandidates)
	if len(paths) == 0 {
		if dijkstraPath(&graph, rv.local, dst, lane, maxRouteHops, RoutePolicy{AllowRelay: true}, false, nil, nil) != nil {
			return nil, freshness, ErrPolicyDenied
		}
		if freshness == RouteViewStale {
			return nil, freshness, ErrRouteStale
		}
		return nil, freshness, ErrNoRoute
	}
	result := make([]CandidatePath, 0, len(paths))
	for _, path := range paths {
		candidate := CandidatePath{
			Nodes:       append([]NodeID(nil), path.nodes...),
			Links:       make([]LinkRef, len(path.arcs)),
			LaneID:      lane,
			Cost:        PathCost(path.cost),
			ViewVersion: view.version,
			Freshness:   freshness,
		}
		for index, arc := range path.arcs {
			candidate.Links[index] = graph.edges[arc.edge].link
		}
		result = append(result, candidate)
	}
	return result, freshness, nil
}

func (rv *RouteView) currentGraph(view *routeSnapshot, lane uint8, current currentRouteState) (routeQueryGraph, bool) {
	graph := routeQueryGraph{nodes: make(map[NodeID]routeNode), adjacency: make(map[NodeID][]routeArc)}
	for nodeID, node := range view.graph.nodes {
		if rv.currentFact(node.ref, current) {
			graph.nodes[nodeID] = node
		} else {
			graph.invalidated = true
		}
	}
	for _, edge := range view.graph.edges {
		if edge.link.LaneID != lane || graph.nodes[edge.from].ref.key == nil || graph.nodes[edge.to].ref.key == nil {
			continue
		}
		if !rv.currentFact(edge.ref, current) || (edge.local && !rv.active(edge.link.ID, edge.link.Epoch, edge.link.LaneID, edge.peer)) {
			graph.invalidated = true
			continue
		}
		controlAvailable := false
		for _, control := range edge.controls {
			if !rv.currentFact(control.ref, current) {
				graph.invalidated = true
				continue
			}
			if control.local && !rv.active(control.linkID, control.epoch, FactLaneControl, control.peer) {
				graph.invalidated = true
				continue
			}
			controlAvailable = true
			break
		}
		if !controlAvailable {
			graph.invalidated = true
			continue
		}
		index := len(graph.edges)
		graph.edges = append(graph.edges, edge)
		graph.adjacency[edge.from] = append(graph.adjacency[edge.from], routeArc{edge: index, from: edge.from, to: edge.to})
		graph.adjacency[edge.to] = append(graph.adjacency[edge.to], routeArc{edge: index, from: edge.to, to: edge.from})
	}
	for node := range graph.adjacency {
		sort.Slice(graph.adjacency[node], func(i, j int) bool {
			a, b := graph.adjacency[node][i], graph.adjacency[node][j]
			if c := bytes.Compare(a.to[:], b.to[:]); c != 0 {
				return c < 0
			}
			left, right := graph.edges[a.edge].link, graph.edges[b.edge].link
			if left.ID != right.ID {
				return left.ID < right.ID
			}
			return left.Epoch < right.Epoch
		})
	}
	return graph, graph.invalidated
}

func (rv *RouteView) currentFact(ref routeFactRef, current currentRouteState) bool {
	key := string(ref.key)
	if valid, exists := current.checks[key]; exists {
		return valid
	}
	valid := rv.store.IsCurrent(ref.key, ref.version, current.now)
	current.checks[key] = valid
	return valid
}

func (rv *RouteView) queryFreshness(view *routeSnapshot, storeVersion uint64, invalidated bool) RouteFreshness {
	if view.stale || invalidated || storeVersion != view.version {
		return RouteViewStale
	}
	return RouteViewFresh
}

func (g *routeGraph) address(addr netip.Addr) (routeAddress, bool) {
	owners := g.addresses[addr]
	if len(owners) != 1 {
		return routeAddress{}, false
	}
	for _, address := range owners {
		return address, true
	}
	return routeAddress{}, false
}

func (g *routeGraph) addressConflicts(addr netip.Addr) bool {
	return len(g.addresses[addr]) > 1
}

func hasCapability(capabilities []string, want string) bool {
	index := sort.SearchStrings(capabilities, want)
	return index < len(capabilities) && capabilities[index] == want
}

func localPeer(local, from, to NodeID) (NodeID, bool) {
	if from == local {
		return to, true
	}
	if to == local {
		return from, true
	}
	return NodeID{}, false
}

func makeRoutePair(a, b NodeID) routePair {
	if bytes.Compare(a[:], b[:]) <= 0 {
		return routePair{first: a, second: b}
	}
	return routePair{first: b, second: a}
}

func routeLinkCost(cost LinkCost) uint64 {
	total := pathCostUnit
	for _, term := range []struct {
		value uint64
		unit  uint64
	}{
		{uint64(cost.RTTMillis), 20_000},
		{uint64(cost.JitterMicros), 25},
		{uint64(cost.LossPPM), 60},
		{uint64(cost.QueueMicros), 50},
		{uint64(cost.ReconnectsLast5m), 500_000},
	} {
		product := saturatedMultiply(term.value, term.unit)
		total = saturatedAdd(total, product)
	}
	return total
}

func saturatedMultiply(a, b uint64) uint64 {
	if a != 0 && b > math.MaxUint64/a {
		return math.MaxUint64
	}
	return a * b
}

func saturatedAdd(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}

type routePath struct {
	nodes []NodeID
	arcs  []routeArc
	cost  uint64
}

type routePathHeap struct {
	graph *routeQueryGraph
	paths []routePath
}

func (h routePathHeap) Len() int { return len(h.paths) }
func (h routePathHeap) Less(i, j int) bool {
	return routePathLess(h.graph, h.paths[i], h.paths[j])
}
func (h routePathHeap) Swap(i, j int)   { h.paths[i], h.paths[j] = h.paths[j], h.paths[i] }
func (h *routePathHeap) Push(value any) { h.paths = append(h.paths, value.(routePath)) }
func (h *routePathHeap) Pop() any {
	last := len(h.paths) - 1
	value := h.paths[last]
	h.paths = h.paths[:last]
	return value
}

func routePathLess(graph *routeQueryGraph, a, b routePath) bool {
	if a.cost != b.cost {
		return a.cost < b.cost
	}
	limit := len(a.nodes)
	if len(b.nodes) < limit {
		limit = len(b.nodes)
	}
	for index := 0; index < limit; index++ {
		if compareNodeID(a.nodes[index], b.nodes[index]) != 0 {
			return compareNodeID(a.nodes[index], b.nodes[index]) < 0
		}
	}
	if len(a.nodes) != len(b.nodes) {
		return len(a.nodes) < len(b.nodes)
	}
	for index := 0; index < len(a.arcs); index++ {
		left := graph.edges[a.arcs[index].edge].link
		right := graph.edges[b.arcs[index].edge].link
		if left.ID != right.ID {
			return left.ID < right.ID
		}
		if left.Epoch != right.Epoch {
			return left.Epoch < right.Epoch
		}
	}
	return false
}

func compareNodeID(a, b NodeID) int { return bytes.Compare(a[:], b[:]) }

type routeSearchState struct {
	node NodeID
	hops uint8
}

func dijkstraPath(graph *routeQueryGraph, source, destination NodeID, lane uint8, maxHops int, policy RoutePolicy, enforceRelay bool, blockedEdges map[string]bool, blockedNodes map[NodeID]bool) *routePath {
	if maxHops < 0 {
		return nil
	}
	if _, exists := graph.nodes[source]; !exists {
		return nil
	}
	if _, exists := graph.nodes[destination]; !exists {
		return nil
	}
	initial := routePath{nodes: []NodeID{source}}
	frontier := &routePathHeap{graph: graph}
	heap.Init(frontier)
	heap.Push(frontier, initial)
	startState := routeSearchState{node: source}
	best := map[routeSearchState]routePath{startState: initial}
	for frontier.Len() > 0 {
		current := heap.Pop(frontier).(routePath)
		at := current.nodes[len(current.nodes)-1]
		state := routeSearchState{node: at, hops: uint8(len(current.arcs))}
		known, exists := best[state]
		if !exists || routePathLess(graph, known, current) || routePathLess(graph, current, known) {
			continue
		}
		if at == destination {
			result := current
			return &result
		}
		if len(current.arcs) >= maxHops {
			continue
		}
		for _, arc := range graph.adjacency[at] {
			edge := graph.edges[arc.edge]
			if edge.link.LaneID != lane || blockedEdges[string(edge.ref.key)] || blockedNodes[arc.to] {
				continue
			}
			if enforceRelay && arc.to != source && arc.to != destination {
				node := graph.nodes[arc.to]
				if !policy.AllowRelay || !node.relay {
					continue
				}
			}
			candidate := routePath{
				nodes: append(append([]NodeID(nil), current.nodes...), arc.to),
				arcs:  append(append([]routeArc(nil), current.arcs...), arc),
				cost:  saturatedAdd(current.cost, edge.cost),
			}
			nextState := routeSearchState{node: arc.to, hops: uint8(len(candidate.arcs))}
			previous, exists := best[nextState]
			if exists && !routePathLess(graph, candidate, previous) {
				continue
			}
			best[nextState] = candidate
			heap.Push(frontier, candidate)
		}
	}
	return nil
}

func kShortestPaths(graph *routeQueryGraph, source, destination NodeID, lane uint8, policy RoutePolicy, limit int) []routePath {
	if limit <= 0 {
		return nil
	}
	first := dijkstraPath(graph, source, destination, lane, maxRouteHops, policy, true, nil, nil)
	if first == nil {
		return nil
	}
	accepted := []routePath{*first}
	seen := map[string]bool{routePathKey(graph, *first): true}
	candidates := &routePathHeap{graph: graph}
	heap.Init(candidates)
	for len(accepted) < limit {
		previous := accepted[len(accepted)-1]
		rootCost := uint64(0)
		for spurIndex := 0; spurIndex < len(previous.arcs); spurIndex++ {
			rootNodes := previous.nodes[:spurIndex+1]
			rootArcs := previous.arcs[:spurIndex]
			blockedEdges := make(map[string]bool)
			for _, path := range accepted {
				if len(path.arcs) > spurIndex && samePathPrefix(graph, path, previous, spurIndex) {
					blockedEdges[string(graph.edges[path.arcs[spurIndex].edge].ref.key)] = true
				}
			}
			blockedNodes := make(map[NodeID]bool, spurIndex)
			for _, node := range rootNodes[:len(rootNodes)-1] {
				blockedNodes[node] = true
			}
			spur := dijkstraPath(graph, rootNodes[len(rootNodes)-1], destination, lane, maxRouteHops-len(rootArcs), policy, true, blockedEdges, blockedNodes)
			if spur != nil && len(rootArcs)+len(spur.arcs) <= maxRouteHops {
				combined := routePath{
					nodes: append(append([]NodeID(nil), rootNodes[:len(rootNodes)-1]...), spur.nodes...),
					arcs:  append(append([]routeArc(nil), rootArcs...), spur.arcs...),
					cost:  saturatedAdd(rootCost, spur.cost),
				}
				key := routePathKey(graph, combined)
				if !seen[key] {
					seen[key] = true
					heap.Push(candidates, combined)
				}
			}
			rootCost = saturatedAdd(rootCost, graph.edges[previous.arcs[spurIndex].edge].cost)
		}
		if candidates.Len() == 0 {
			break
		}
		accepted = append(accepted, heap.Pop(candidates).(routePath))
	}
	return accepted
}

func samePathPrefix(graph *routeQueryGraph, a, b routePath, arcCount int) bool {
	for index := 0; index <= arcCount; index++ {
		if a.nodes[index] != b.nodes[index] {
			return false
		}
	}
	for index := 0; index < arcCount; index++ {
		left := graph.edges[a.arcs[index].edge].ref.key
		right := graph.edges[b.arcs[index].edge].ref.key
		if !bytes.Equal(left, right) {
			return false
		}
	}
	return true
}

func routePathKey(graph *routeQueryGraph, path routePath) string {
	key := make([]byte, 0, 2+len(path.nodes)*16+len(path.arcs)*20)
	key = append(key, byte(len(path.nodes)))
	for _, node := range path.nodes {
		key = append(key, node[:]...)
	}
	key = append(key, byte(len(path.arcs)))
	for _, arc := range path.arcs {
		factKey := graph.edges[arc.edge].ref.key
		key = append(key, byte(len(factKey)))
		key = append(key, factKey...)
	}
	return string(key)
}
