// Package relay serves many isolated rooms from one fixed set of listening
// ports.
//
// The deployment it is built for: a company runs one relay inside its data
// center on a stable address. External peers reach it over WebSocket, internal
// peers over TCP, and both name the room they belong to. A room is created the
// first time someone asks for it and torn down after its last member leaves, so
// the relay's ports never change and no per-room configuration is needed.
//
// The relay is trusted infrastructure: it derives each room's key from that
// room's token, which it must do to authenticate members. Peers in different
// rooms cannot see or reach each other.
package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/room"
)

// debugRelay enables attach diagnostics; it stays off so a busy relay does not
// log per carrier.
var debugRelay = os.Getenv("SIMPLETIER_RELAY_DEBUG") != ""

// Default ingress ports, used when ServeTCP or ServeWebSocket is given an empty
// address. The two faces are independent listeners: pick either, or run both.
const (
	// DefaultTCPPort carries TCP room carriers.
	DefaultTCPPort = 22020
	// DefaultWebSocketPort carries WebSocket room carriers.
	DefaultWebSocketPort = 22021
)

// MaxTokenBytes bounds the room token a TCP carrier may announce, so a peer
// cannot make the relay buffer an unbounded prefix. It is the room manager's
// limit, re-exported so callers framing a carrier need only this package.
const MaxTokenBytes = room.MaxTokenBytes

// Options configures a Relay.
type Options struct {
	// Rooms configures how each room's network is created. Its Name and CIDR are
	// shared by every room; the token separates them.
	Rooms room.Options

	// Upgrader is the WebSocket upgrader for the HTTP ingress. Nil uses a default
	// that accepts any origin, which is what a relay serving arbitrary peers needs.
	Upgrader *websocket.Upgrader
}

// Relay serves rooms on fixed ports.
type Relay struct {
	rooms    *room.Manager
	upgrader websocket.Upgrader

	mu        sync.Mutex
	listeners []net.Listener
	servers   []*http.Server
	closed    bool
}

// New creates a relay. It listens on nothing until ServeTCP or ServeWebSocket is called.
func New(opts Options) *Relay {
	r := &Relay{rooms: room.NewManager(opts.Rooms)}
	if opts.Upgrader != nil {
		r.upgrader = *opts.Upgrader
	} else {
		r.upgrader = websocket.Upgrader{
			ReadBufferSize:  64 << 10,
			WriteBufferSize: 64 << 10,
			CheckOrigin:     func(*http.Request) bool { return true },
		}
	}
	return r
}

// Issue records a token as host-issued; only that value can join. Without RequireIssued,
// any non-empty string creates a room. See also Revoke and Count.
func (r *Relay) Issue(token string) error {
	if r == nil {
		return errors.New("relay: nil relay")
	}
	if token == "" {
		return errors.New("relay: empty token")
	}
	if len(token) > MaxTokenBytes {
		return fmt.Errorf("relay: token exceeds %d bytes", MaxTokenBytes)
	}
	return r.rooms.Issue(token)
}

// Revoke forgets a previously issued token. Active members keep running until their
// network is torn down.
func (r *Relay) Revoke(token string) {
	if r == nil {
		return
	}
	r.rooms.Revoke(token)
}

// Count returns the number of currently live rooms. It's updated immediately when a
// member joins or leaves.
func (r *Relay) Count() int {
	if r == nil {
		return 0
	}
	return r.rooms.Rooms()
}

// List returns a snapshot of every live room.
func (r *Relay) List() []room.RoomInfo {
	if r == nil {
		return nil
	}
	return r.rooms.List()
}

// Members returns the carriers attached to the room with the given id, where id comes
// from List. ok is false when no such room is live.
func (r *Relay) Members(id string) ([]room.Member, bool) {
	if r == nil {
		return nil, false
	}
	return r.rooms.Members(id)
}

// Rooms exposes the internal room manager for advanced scenarios where callers need
// the full Manager interface (e.g., custom Join logic). For most users, Issue, Revoke,
// Count, List and Members are sufficient.

func (r *Relay) Rooms() *room.Manager { return r.rooms }

// ServeTCP listens on address and serves the TCP room ingress until ctx is done.
//
// A carrier opens with a length-prefixed room token and then becomes the overlay
// handshake for that room. The token is consumed before the overlay sees the
// connection, so the handshake stream carries only handshake bytes.
func (r *Relay) ServeTCP(ctx context.Context, address string) error {
	if address == "" {
		address = fmt.Sprintf(":%d", DefaultTCPPort)
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("relay: listen tcp %s: %w", address, err)
	}
	r.trackListener(ln)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || r.isClosed() {
				return nil
			}
			continue
		}
		go r.handleTCPCarrier(ctx, conn)
	}
}

// ServeWebSocket serves the WebSocket room ingress on address until ctx is done. An
// empty address uses DefaultWebSocketPort.
//
// The room token arrives as the "room" query parameter of the upgrade request.
func (r *Relay) ServeWebSocket(ctx context.Context, address string) error {
	if address == "" {
		address = fmt.Sprintf(":%d", DefaultWebSocketPort)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", r.handleWebSocket)
	mux.HandleFunc("/healthz", r.handleHealth)

	server := &http.Server{Addr: address, Handler: mux}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("relay: listen http %s: %w", address, err)
	}
	r.trackServer(server, ln)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		if ctx.Err() != nil || r.isClosed() {
			return nil
		}
		return fmt.Errorf("relay: serve http %s: %w", address, err)
	}
	return nil
}

// Attach joins an already-established carrier to the room it names.
//
// This is the seam for hosts that own their own HTTP server: after authenticating
// a request however the host likes, upgrade it, wrap it with
// simpletier.NewWebSocketConnection and pass the result here with the room token.
// The relay never touches the host's routing, listener or upgrade policy.
//
// The returned link owns the connection; Close it to leave the room. Callers
// normally wait on Done.
func (r *Relay) Attach(ctx context.Context, conn simpletier.Connection, token string) (simpletier.AttachedLink, error) {
	if ctx == nil {
		return nil, errors.New("relay: nil context")
	}
	if token == "" {
		return nil, errors.New("relay: empty room token")
	}
	if len(token) > MaxTokenBytes {
		return nil, fmt.Errorf("relay: room token exceeds %d bytes", MaxTokenBytes)
	}

	network, err := r.rooms.Join(token)
	if err != nil {
		return nil, err
	}
	link, err := network.AttachConnection(ctx, conn, simpletier.AttachOptions{
		Role:      simpletier.LinkRoleResponder,
		Negotiate: true,
	})
	if err != nil {
		r.rooms.Leave(token)
		return nil, fmt.Errorf("relay: attach carrier: %w", err)
	}

	nodeID := string(link.Info().PeerNodeID)
	return &relayLink{
		link: link,
		leave: func() {
			r.rooms.ForgetCarrier(token, nodeID)
			r.rooms.Leave(token)
		},
	}, nil
}

// AttachFrom is Attach plus the carrier's physical address, which the caller already
// holds for its own transport.
//
// ConnectionInfo deliberately carries only safe-to-publish transport metadata, so the
// remote address is passed here instead of being smuggled through Connection. The
// built-in ingresses use this; a host mounting the relay in its own route passes
// whatever it knows about the request, typically also the remote host:port.
func (r *Relay) AttachFrom(ctx context.Context, conn simpletier.Connection, token, physicalAddr string) (simpletier.AttachedLink, error) {
	link, err := r.Attach(ctx, conn, token)
	if err != nil {
		return nil, err
	}
	if physicalAddr != "" {
		nodeID := string(link.Info().PeerNodeID)
		r.rooms.ObserveCarrier(token, nodeID, physicalAddr)
		tracked := link.(*relayLink)
		previous := tracked.leave
		tracked.leave = func() {
			r.rooms.ForgetCarrier(token, nodeID)
			previous()
		}
	}
	return link, nil
}

// relayLink releases the room membership when the carrier closes.
type relayLink struct {
	link  simpletier.AttachedLink
	once  sync.Once
	leave func()
}

func (l *relayLink) Info() simpletier.AttachedLinkInfo { return l.link.Info() }
func (l *relayLink) Done() <-chan struct{}             { return l.link.Done() }

func (l *relayLink) Close() error {
	err := l.link.Close()
	l.once.Do(l.leave)
	return err
}

func (r *Relay) handleTCPCarrier(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	token, err := readToken(conn)
	if err != nil {
		return
	}
	// The peer decides the lane: it opens one carrier for CONTROL and another for
	// STREAM to the same relay port, exactly as a built-in carrier dials one
	// connection per lane. A responder negotiates the lane from the authenticated
	// handshake, so a single accept path serves both.
	link, err := r.AttachFrom(ctx, &remainderConn{Conn: conn}, token, conn.RemoteAddr().String())
	if err != nil {
		if debugRelay {
			println("relay: tcp attach failed:", err.Error())
		}
		return
	}
	defer func() { _ = link.Close() }()
	select {
	case <-link.Done():
	case <-ctx.Done():
	}
}

func (r *Relay) handleWebSocket(w http.ResponseWriter, req *http.Request) {
	token := req.URL.Query().Get("room")
	if token == "" {
		http.Error(w, "missing room token", http.StatusBadRequest)
		return
	}
	if len(token) > MaxTokenBytes {
		http.Error(w, "room token too long", http.StatusBadRequest)
		return
	}

	ws, err := r.upgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}
	defer func() { _ = ws.Close() }()

	conn, err := simpletier.NewWebSocketConnection(ws)
	if err != nil {
		return
	}
	link, err := r.AttachFrom(req.Context(), conn, token, req.RemoteAddr)
	if err != nil {
		return
	}
	defer func() { _ = link.Close() }()
	select {
	case <-link.Done():
	case <-req.Context().Done():
	}
}

func (r *Relay) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"rooms":%d}`+"\n", r.rooms.Rooms())
}

// Close tears down every listener, server and room.
func (r *Relay) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	listeners := r.listeners
	servers := r.servers
	r.listeners = nil
	r.servers = nil
	r.mu.Unlock()

	var errs []error
	for _, server := range servers {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := server.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, err)
		}
		cancel()
	}
	for _, ln := range listeners {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if err := r.rooms.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (r *Relay) trackListener(ln net.Listener) {
	r.mu.Lock()
	r.listeners = append(r.listeners, ln)
	r.mu.Unlock()
}

func (r *Relay) trackServer(server *http.Server, ln net.Listener) {
	r.mu.Lock()
	r.servers = append(r.servers, server)
	r.listeners = append(r.listeners, ln)
	r.mu.Unlock()
}

func (r *Relay) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// readToken reads the length-prefixed room token that opens a TCP carrier.
func readToken(conn net.Conn) (string, error) {
	var size [4]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > MaxTokenBytes {
		return "", fmt.Errorf("relay: room token length %d out of range", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// WriteToken writes the length-prefixed room token that opens a TCP carrier. A
// peer calls this before handing the connection to its own Network.
func WriteToken(conn io.Writer, token string) error {
	if token == "" {
		return errors.New("relay: empty room token")
	}
	if len(token) > MaxTokenBytes {
		return fmt.Errorf("relay: room token exceeds %d bytes", MaxTokenBytes)
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(token)))
	if _, err := conn.Write(size[:]); err != nil {
		return err
	}
	_, err := io.WriteString(conn, token)
	return err
}

// JoinRoom attaches a client Network to a room over a relay TCP ingress.
//
// It opens one carrier for the CONTROL lane and a second for the STREAM lane, the
// same shape a built-in carrier uses: each lane owns its own connection, and the
// STREAM connection is pinned to the CONTROL peer it authenticated. Callers get
// back the CONTROL handle so they can close both on the way out.
func JoinRoom(ctx context.Context, network simpletier.Network, relayAddr, token string) (simpletier.AttachedLink, error) {
	if token == "" {
		return nil, errors.New("relay: empty room token")
	}

	dial := func() (simpletier.Connection, error) {
		raw, err := net.Dial("tcp", relayAddr)
		if err != nil {
			return nil, fmt.Errorf("relay: dial %s: %w", relayAddr, err)
		}
		if err := WriteToken(raw, token); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("relay: announce room: %w", err)
		}
		conn, err := simpletier.NewConnection(raw, simpletier.ConnectionInfo{Type: "tcp"})
		if err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("relay: wrap connection: %w", err)
		}
		return conn, nil
	}

	controlConn, err := dial()
	if err != nil {
		return nil, err
	}
	control, err := network.AttachConnection(ctx, controlConn, simpletier.AttachOptions{
		Role: simpletier.LinkRoleInitiator,
		Lane: laneControl,
	})
	if err != nil {
		return nil, fmt.Errorf("relay: attach control lane: %w", err)
	}

	streamConn, err := dial()
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	stream, err := network.AttachConnection(ctx, streamConn, simpletier.AttachOptions{
		Role:    simpletier.LinkRoleInitiator,
		Lane:    laneStream,
		Control: control,
	})
	if err != nil {
		_ = control.Close()
		return nil, fmt.Errorf("relay: attach stream lane: %w", err)
	}

	// The stream lane is the one business traffic rides; keep it alive for the
	// lifetime of the join and let the control handle close both.
	return &joinedLanes{control: control, stream: stream}, nil
}

// joinedLanes closes both lane handles as one.
type joinedLanes struct {
	control simpletier.AttachedLink
	stream  simpletier.AttachedLink
}

func (j *joinedLanes) Close() error {
	return errors.Join(j.stream.Close(), j.control.Close())
}

// Info reports the control lane's admission facts. The stream lane carries data
// only, so the control lane is the one whose identity callers want.
func (j *joinedLanes) Info() simpletier.AttachedLinkInfo { return j.control.Info() }

// Done closes when the control lane ends, which is what makes the room membership
// over: without a control lane the stream lane cannot be pinned to a peer.
func (j *joinedLanes) Done() <-chan struct{} { return j.control.Done() }

// laneControl and laneStream are the frozen LaneIDs for the control and stream
// lanes. They are repeated here because the enum lives in an internal package.
const (
	laneControl uint8 = 0x00
	laneStream  uint8 = 0x02
)

// remainderConn adapts a connection whose room prefix has already been consumed.
type remainderConn struct {
	net.Conn
}

// Info reports the carrier type the overlay records. The room token was consumed
// before this wrapper existed, so it is deliberately absent from the info.
func (c *remainderConn) Info() simpletier.ConnectionInfo {
	return simpletier.ConnectionInfo{Type: "tcp"}
}
