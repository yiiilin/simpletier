package simpletier

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectionCarriesInfoAndIndependentIO(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	stream := &countedConnectionStream{Conn: left}
	info := ConnectionInfo{Type: "websocket"}
	conn, err := NewConnection(stream, info)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	info.Type = "changed"
	copied := conn.Info()
	copied.Type = "also-changed"
	if conn.Info().Type != "websocket" {
		t.Fatal("connection metadata is mutable through its input or output")
	}
	if err := right.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("hello")); written <- err }()
	data := make([]byte, 5)
	if _, err := io.ReadFull(right, data); err != nil || string(data) != "hello" {
		t.Fatalf("connection write: %q, %v", data, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := right.Write([]byte("reply")); written <- err }()
	if _, err := io.ReadFull(conn, data); err != nil || string(data) != "reply" {
		t.Fatalf("connection read: %q, %v", data, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil || stream.closes.Load() != 1 {
		t.Fatalf("repeated connection Close: %v; count=%d", err, stream.closes.Load())
	}
}

func TestConnectionCloseUnblocksIO(t *testing.T) {
	for _, writing := range []bool{false, true} {
		t.Run(map[bool]string{false: "read", true: "write"}[writing], func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			stream := &enteredConnectionStream{Conn: left, entered: make(chan struct{})}
			conn, err := NewConnection(stream, ConnectionInfo{Type: "custom"})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			result := make(chan error, 1)
			go func() {
				var data [1]byte
				var err error
				if writing {
					_, err = conn.Write(data[:])
				} else {
					_, err = conn.Read(data[:])
				}
				result <- err
			}()
			select {
			case <-stream.entered:
			case <-time.After(time.Second):
				t.Fatal("typed connection did not enter I/O")
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("blocked operation succeeded after close")
				}
			case <-time.After(time.Second):
				t.Fatal("typed connection Close did not unblock I/O")
			}
			if _, err := conn.Read(nil); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("read after Close = %v", err)
			}
			if _, err := conn.Write(nil); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after Close = %v", err)
			}
		})
	}
}

type enteredConnectionStream struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (s *enteredConnectionStream) Read(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	return s.Conn.Read(p)
}
func (s *enteredConnectionStream) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	return s.Conn.Write(p)
}

func TestConnectionRejectsInvalidInfoWithoutTakingOwnership(t *testing.T) {
	for _, kind := range []string{"", "a\x00b", string([]byte{0xff})} {
		left, right := net.Pipe()
		stream := &countedConnectionStream{Conn: left}
		if _, err := NewConnection(stream, ConnectionInfo{Type: kind}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("invalid metadata = %v", err)
		}
		if stream.closes.Load() != 0 {
			t.Fatal("rejected wrapper took stream ownership")
		}
		_ = left.Close()
		_ = right.Close()
	}
	for _, stream := range []io.ReadWriteCloser{nil, (*countedConnectionStream)(nil)} {
		if _, err := NewConnection(stream, ConnectionInfo{Type: "tcp"}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("nil stream = %v", err)
		}
	}
}

func TestTCPConnectorReturnsFreshConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connector := &TCPConnector{}
	dialCtx, dialCancel := context.WithCancel(ctx)
	defer dialCancel()
	first, err := connector.Dial(dialCtx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	peer1, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer1.Close()
	dialCancel()
	if err := peer1.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte("hi")); err != nil {
		t.Fatal("completed Dial context canceled a successful connection:", err)
	}
	var afterDial [2]byte
	if _, err := io.ReadFull(peer1, afterDial[:]); err != nil || string(afterDial[:]) != "hi" {
		t.Fatalf("post-Dial cancellation I/O: %q %v", afterDial, err)
	}
	second, err := connector.Dial(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	peer2, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer2.Close()
	if first == second || first.Info().Type != "tcp" || second.Info().Type != "tcp" {
		t.Fatal("TCP Connector reused a connection or lost type metadata")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peer2.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write([]byte("ok")); err != nil {
		t.Fatal("closing the first connection affected the second:", err)
	}
	var data [2]byte
	if _, err := io.ReadFull(peer2, data[:]); err != nil || string(data[:]) != "ok" {
		t.Fatalf("second connection is not independent: %q %v", data, err)
	}
	if _, err := connector.Dial(nil, listener.Addr().String()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil context = %v", err)
	}
	cancel()
	if _, err := connector.Dial(ctx, listener.Addr().String()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial = %v", err)
	}
}

func TestConfigCopiesAndValidatesConnectionTargets(t *testing.T) {
	connector := ConnectorFunc(func(context.Context, string) (Connection, error) { return nil, errors.New("unused") })
	cfg := validConfig()
	cfg.Listen, cfg.Upstreams = nil, nil
	cfg.Targets = []ConnectionTarget{{Connector: connector, Endpoint: "wss://peer.example/private?secret=not-for-logs"}}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		t.Fatal("typed targets should not require an SDK listener:", err)
	}
	cfg.Targets[0].Endpoint = "changed"
	if normalized.config.Targets[0].Endpoint == "changed" {
		t.Fatal("normalized config aliases caller target slice")
	}
	for _, bad := range []Connector{nil, ConnectorFunc(nil), (*TCPConnector)(nil)} {
		cfg.Targets = []ConnectionTarget{{Connector: bad, Endpoint: "peer"}}
		if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("nil target Connector = %v", err)
		}
	}
	cfg.Targets = []ConnectionTarget{{Connector: connector}}
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty target endpoint = %v", err)
	}
}

func TestNewNetworkUsesCustomConnector(t *testing.T) {
	entered := make(chan string, 1)
	closed := make(chan struct{})
	var infoReads atomic.Int32
	var closes atomic.Int32
	cfg := validConfig()
	cfg.Listen, cfg.Upstreams = nil, nil
	endpoint := "wss://peer.example/private?secret=not-for-logs"
	cfg.Targets = []ConnectionTarget{{Endpoint: endpoint, Connector: ConnectorFunc(func(_ context.Context, stringEndpoint string) (Connection, error) {
		entered <- stringEndpoint
		return &observedMetadataConnection{infoReads: &infoReads, closes: &closes, closed: closed, kind: "websocket"}, nil
	})}}
	n, err := NewNetwork(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	select {
	case got := <-entered:
		if got != endpoint {
			t.Fatalf("endpoint changed by core: %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("configured Connector was not called")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("pre-auth rejection failed to close the typed connection")
	}
	if infoReads.Load() == 0 || closes.Load() != 1 {
		t.Fatalf("Connection metadata/cleanup not consumed: reads=%d closes=%d", infoReads.Load(), closes.Load())
	}
	if _, err := n.DialContext(context.Background(), "tcp", "10.20.0.8:8080"); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("raw connection was treated as a route: %v", err)
	}
}

func TestNewNetworkClosesLateConnectorResult(t *testing.T) {
	for _, returnedError := range []bool{false, true} {
		t.Run(map[bool]string{false: "late success", true: "connection with error"}[returnedError], func(t *testing.T) {
			entered := make(chan struct{})
			closed := make(chan struct{})
			var closes, infoReads atomic.Int32
			cfg := validConfig()
			cfg.Listen, cfg.Upstreams = nil, nil
			cfg.Targets = []ConnectionTarget{{Endpoint: "opaque", Connector: ConnectorFunc(func(ctx context.Context, _ string) (Connection, error) {
				close(entered)
				<-ctx.Done()
				conn := &observedMetadataConnection{infoReads: &infoReads, closes: &closes, closed: closed, kind: "custom"}
				if returnedError {
					return conn, errors.New("injected dial error")
				}
				return conn, nil
			})}}
			n, err := NewNetwork(cfg)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				_ = n.Close()
				t.Fatal("Connector did not start")
			}
			if err := n.Close(); err != nil {
				t.Fatal(err)
			}
			if closes.Load() != 1 {
				t.Fatalf("late result leaked or closed twice: %d", closes.Load())
			}
		})
	}
}

func TestConnectorResultValidationAndCleanup(t *testing.T) {
	n := &network{ctx: context.Background()}
	failure := errors.New("provider failure")
	closeFailure := errors.New("close failure")
	for _, result := range []Connection{nil, (*observedMetadataConnection)(nil)} {
		err := n.tryConnectionTarget(ConnectionTarget{Endpoint: "opaque", Connector: ConnectorFunc(func(context.Context, string) (Connection, error) { return result, nil })})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("nil provider result = %v", err)
		}
	}
	for _, kind := range []string{"", "valid"} {
		var reads, closes atomic.Int32
		conn := &observedMetadataConnection{infoReads: &reads, closes: &closes, closed: make(chan struct{}), kind: kind, closeErr: closeFailure}
		returnedErr := error(nil)
		if kind == "valid" {
			returnedErr = failure
		}
		err := n.tryConnectionTarget(ConnectionTarget{Endpoint: "opaque", Connector: ConnectorFunc(func(context.Context, string) (Connection, error) { return conn, returnedErr })})
		if closes.Load() != 1 || !errors.Is(err, closeFailure) {
			t.Fatalf("result cleanup = %v, closes=%d", err, closes.Load())
		}
		if returnedErr != nil {
			if reads.Load() != 0 || !errors.Is(err, failure) {
				t.Fatal("failed result metadata was accessed or error cause was lost")
			}
		} else if reads.Load() != 1 || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("invalid Info snapshot = %v, reads=%d", err, reads.Load())
		}
	}
	if _, err := ConnectorFunc(nil).Dial(context.Background(), "opaque"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil function called directly = %v", err)
	}
}

func TestNetworkConnectorLogsDoNotExposeCredentials(t *testing.T) {
	writer := &connectionLogCapture{logged: make(chan struct{})}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	const secret = "SENSITIVE-CONNECTOR-CREDENTIAL"
	cfg := validConfig()
	cfg.Listen, cfg.Upstreams = nil, nil
	var reads, closes atomic.Int32
	cfg.Targets = []ConnectionTarget{{Endpoint: "wss://peer.example/?token=" + secret, Connector: ConnectorFunc(func(context.Context, string) (Connection, error) {
		conn := &observedMetadataConnection{infoReads: &reads, closes: &closes, closed: make(chan struct{}), kind: "custom", closeErr: errors.New(secret)}
		return conn, errors.New("dial failed with " + secret)
	})}}
	n, err := NewNetwork(cfg)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-writer.logged:
	case <-time.After(time.Second):
		_ = n.Close()
		t.Fatal("failed attempt was not logged")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	writer.mu.Lock()
	output := writer.buffer.String()
	writer.mu.Unlock()
	if strings.Contains(output, secret) || strings.Contains(output, "wss://") || !strings.Contains(output, "target_index=0") {
		t.Fatalf("unsafe or missing connection log: %s", output)
	}
}

type connectionLogCapture struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	logged chan struct{}
	once   sync.Once
}

func (w *connectionLogCapture) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buffer.Write(p)
	w.mu.Unlock()
	w.once.Do(func() { close(w.logged) })
	return n, err
}

type countedConnectionStream struct {
	net.Conn
	closes atomic.Int32
}

func (s *countedConnectionStream) Close() error {
	s.closes.Add(1)
	return s.Conn.Close()
}

type observedMetadataConnection struct {
	infoReads *atomic.Int32
	closes    *atomic.Int32
	closed    chan struct{}
	kind      string
	closeErr  error
	once      sync.Once
}

func (c *observedMetadataConnection) Info() ConnectionInfo {
	c.infoReads.Add(1)
	return ConnectionInfo{Type: c.kind}
}
func (c *observedMetadataConnection) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *observedMetadataConnection) Write(p []byte) (int, error) { return len(p), nil }
func (c *observedMetadataConnection) Close() error {
	c.closes.Add(1)
	c.once.Do(func() { close(c.closed) })
	return c.closeErr
}
