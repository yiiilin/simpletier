package simpletier

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

// ConnectionInfo is a stable public description, not proof of authentication.
// Type is safe-to-publish transport metadata, never an endpoint or credential.
type ConnectionInfo struct {
	Type string
}

// Connection is one established, dedicated, reliable, ordered full-duplex stream.
// Info returns a value snapshot. Close must safely unblock concurrent I/O.
// Successful Dial transfers ownership; establishment alone does not create a Link.
type Connection interface {
	io.ReadWriteCloser
	Info() ConnectionInfo
}

// Connector can be reused to dial multiple independent Connection instances.
// ctx controls establishment only: a returned stream must NOT be bound to that
// Dial context's lifetime. Dial must honor cancellation and clean up on failure.
// Implementations shared through SDK Config must be safe for their concurrent use.
type Connector interface {
	Dial(ctx context.Context, endpoint string) (Connection, error)
}

// ConnectorFunc adapts host-provided dialing without requiring a concrete type.
type ConnectorFunc func(context.Context, string) (Connection, error)

func (f ConnectorFunc) Dial(ctx context.Context, endpoint string) (Connection, error) {
	if ctx == nil || f == nil {
		return nil, invalidConfig("connector", "requires a non-nil context and dial function")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f(ctx, endpoint)
}

// ConnectionTarget is an outbound plan supplied directly by the SDK host.
// Endpoint is opaque to core; only its Connector interprets the address syntax.
type ConnectionTarget struct {
	Connector Connector
	Endpoint  string
}

// NewConnection wraps an existing stream with stable metadata. Rejection retains
// host ownership. Success transfers ownership and provides an idempotent Close;
// neither wrapping nor Type implies identity, encryption or Network admission.
func NewConnection(stream io.ReadWriteCloser, info ConnectionInfo) (Connection, error) {
	if nilValue(stream) {
		return nil, invalidConfig("connection", "stream must not be nil")
	}
	if err := validateConnectionInfo(info); err != nil {
		return nil, err
	}
	return &streamConnection{stream: stream, info: info}, nil
}

type streamConnection struct {
	stream    io.ReadWriteCloser
	info      ConnectionInfo
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (c *streamConnection) Info() ConnectionInfo { return c.info }

func (c *streamConnection) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.stream.Read(p)
}

func (c *streamConnection) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.stream.Write(p)
}

func (c *streamConnection) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closeErr = c.stream.Close()
	})
	return c.closeErr
}

// TCPConnector is the built-in transport provider. A zero-valued Dialer works;
// configure it before use, and do not mutate it while Network is using it.
// Endpoint is a TCP host:port, not a virtual IP route or a tcp:// URL.
type TCPConnector struct {
	Dialer net.Dialer
}

func (c *TCPConnector) Dial(ctx context.Context, endpoint string) (Connection, error) {
	if c == nil || ctx == nil {
		return nil, invalidConfig("connector", "requires a non-nil TCP connector and context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stream, err := c.Dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, stream.Close())
	}
	return NewConnection(stream, ConnectionInfo{Type: "tcp"})
}

func validateConnectionInfo(info ConnectionInfo) error {
	if info.Type == "" || !utf8.ValidString(info.Type) || strings.IndexByte(info.Type, 0) >= 0 {
		return invalidConfig("connection.type", "must be nonempty valid UTF-8 without NUL")
	}
	return nil
}

func nilValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
