package simpletier

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
)

var ErrWebSocketMessageType = errors.New("WebSocket stream requires binary messages")

// WebSocketConnector establishes ws/wss streams using host-supplied HTTP options.
// A nil Dialer uses a private default with no environment-derived proxy. Headers
// and Dialer must not be mutated during use. HTTP authentication is NOT mesh
// authentication. Dial context controls establishment, not the returned stream.
type WebSocketConnector struct {
	Dialer *websocket.Dialer
	Header http.Header
}

func (c *WebSocketConnector) Dial(ctx context.Context, endpoint string) (Connection, error) {
	if c == nil || ctx == nil {
		return nil, invalidConfig("connector", "requires a non-nil WebSocket connector and context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base := c.Dialer
	if base == nil {
		base = &websocket.Dialer{HandshakeTimeout: upstreamDialTimeout}
	}
	dialer := *base
	var establishment websocketEstablishment
	stop := context.AfterFunc(ctx, func() {
		establishment.mu.Lock()
		defer establishment.mu.Unlock()
		if !establishment.detached && establishment.socket != nil {
			_ = establishment.socket.Close()
		}
	})
	defer stop()
	netDial := base.NetDialContext
	if netDial == nil {
		if base.NetDial != nil {
			netDial = func(_ context.Context, network, address string) (net.Conn, error) {
				return base.NetDial(network, address)
			}
		} else {
			netDial = (&net.Dialer{}).DialContext
		}
	}
	dialer.NetDialContext = establishment.track(netDial)
	if base.NetDialTLSContext != nil {
		dialer.NetDialTLSContext = establishment.track(base.NetDialTLSContext)
	}
	conn, response, err := dialer.DialContext(ctx, endpoint, c.Header.Clone())
	if response != nil && response.Body != nil {
		err = errors.Join(err, response.Body.Close())
	}
	stop()
	// Synchronize with any cancellation callback that already started. Detaching
	// under this lock is the ownership handoff; afterward Dial ctx cannot close it.
	establishment.mu.Lock()
	err = errors.Join(err, ctx.Err())
	establishment.detached = true
	socket := establishment.socket
	establishment.mu.Unlock()
	if err != nil {
		if conn != nil {
			err = errors.Join(err, conn.Close())
		} else if socket != nil {
			err = errors.Join(err, socket.Close())
		}
		return nil, err
	}
	return NewWebSocketConnection(conn)
}

type websocketEstablishment struct {
	mu       sync.Mutex
	socket   *websocketEstablishmentSocket
	detached bool
}

func (e *websocketEstablishment) track(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if nilValue(conn) {
			if err == nil {
				err = invalidConfig("connector", "socket dial returned nil without error")
			}
			return nil, err
		}
		socket := &websocketEstablishmentSocket{Conn: conn}
		e.mu.Lock()
		e.socket = socket
		canceled := ctx.Err()
		e.mu.Unlock()
		if err != nil || canceled != nil {
			return nil, errors.Join(err, canceled, socket.Close())
		}
		return socket, nil
	}
}

type websocketEstablishmentSocket struct {
	net.Conn
	once sync.Once
	err  error
}

func (s *websocketEstablishmentSocket) Close() error {
	s.once.Do(func() { s.err = s.Conn.Close() })
	return s.err
}

// NewWebSocketConnection transfers an established dedicated WebSocket into a
// Connection. The host must stop all raw reads/writes before handoff. Existing
// read limits and control handlers remain host-owned settings. Binary messages
// are streamed, not buffered whole, and may split or combine protocol frames.
// A text message or transport read/write failure closes the stream. Close shuts
// down the owned socket immediately so blocked I/O does not wait for a close
// handshake. This function neither registers a Network Link nor authenticates it.
func NewWebSocketConnection(conn *websocket.Conn) (Connection, error) {
	if conn == nil {
		return nil, invalidConfig("connection", "WebSocket must not be nil")
	}
	conn.EnableWriteCompression(false)
	return NewConnection(&webSocketStream{conn: conn}, ConnectionInfo{Type: "websocket"})
}

type webSocketStream struct {
	conn      *websocket.Conn
	readMu    sync.Mutex
	writeMu   sync.Mutex
	reader    io.Reader
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (s *webSocketStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if s.reader == nil {
			kind, reader, err := s.conn.NextReader()
			if err != nil {
				return 0, s.readFailure(err)
			}
			if kind != websocket.BinaryMessage {
				return 0, errors.Join(ErrWebSocketMessageType, s.Close())
			}
			s.reader = reader
		}
		n, err := s.reader.Read(p)
		if err == io.EOF {
			s.reader = nil
			if n == 0 {
				continue
			}
			return n, nil
		}
		if err != nil {
			return n, s.readFailure(err)
		}
		return n, nil
	}
}

func (s *webSocketStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := s.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, errors.Join(err, s.Close())
	}
	return len(p), nil
}

func (s *webSocketStream) readFailure(err error) error {
	if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		err = io.EOF
	}
	return errors.Join(err, s.Close())
}

func (s *webSocketStream) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.closeErr = s.conn.Close()
	})
	return s.closeErr
}
