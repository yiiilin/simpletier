package simpletier

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/yiiilin/simpletier/internal/wire"
)

// CarrierFrame is a structurally decoded outer frame. Its headers and Body are
// UNVERIFIED: StreamCarrier does not authenticate, encrypt, decrypt or route it.
// The caller must not mutate its slices until WriteFrame returns.
type CarrierFrame = wire.Frame

type FrameKind = wire.FrameKind
type MessageType = wire.MessageType

const (
	FrameKindLinkControl  = wire.FrameKindLinkControl
	FrameKindEndToEnd     = wire.FrameKindEndToEnd
	FrameKindRouteControl = wire.FrameKindRouteControl

	MessageTypeIPPacket     = wire.MessageTypeIPPacket
	MessageTypeUDPDatagram  = wire.MessageTypeUDPDatagram
	MessageTypeStreamData   = wire.MessageTypeStreamData
	MessageTypeControlRPC   = wire.MessageTypeControlRPC
	MessageTypeSessionCtrl  = wire.MessageTypeSessionCtrl
	MessageTypePathOpen     = wire.MessageTypePathOpen
	MessageTypePathReady    = wire.MessageTypePathReady
	MessageTypePathBroken   = wire.MessageTypePathBroken
	MessageTypeSessionReady = wire.MessageTypeSessionReady

	MaxFrameLength            = wire.MaxFrameLength
	HopHeaderSize             = wire.HopHeaderSize
	EnvelopeSize              = wire.EnvelopeSize
	EnvelopeMessageTypeOffset = wire.EnvelopeMessageTypeOffset
)

var (
	ErrFrameMalformed = wire.ErrFrameMalformed
	ErrFrameTooLarge  = wire.ErrFrameTooLarge
	ErrTruncatedFrame = wire.ErrTruncatedFrame
)

// StreamCarrier carries bounded outer frames over a dedicated, established
// full-duplex stream, including net.Conn or a multiplexer substream. It is not
// an authenticated Link and is not registered with Network.
//
// Reads and writes may run concurrently; calls in each direction are serialized.
// A separate raw Noise HANDSHAKE must finish before using normal frame mode for
// a protocol peer. Construction alone does not perform that handshake.
// StreamCarrier must not be copied after first use.
type StreamCarrier struct {
	stream    io.ReadWriteCloser
	ctx       context.Context
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
	closing   chan struct{}
	done      chan struct{}
	stopMu    sync.Mutex
	stop      func() bool
}

// NewStreamCarrier transfers stream ownership only on success. It needs no
// Config, listeners, identity files or dialing. The host must stop using the
// raw stream and preserve any bytes it has already buffered when handing it off.
//
// stream must support concurrent Read/Write, and its Close must safely unblock
// both operations. The lifetime context cancels the WHOLE carrier by closing
// that stream, not a single frame. Cancellation can therefore discard a partial
// frame. Any deadlines on a net.Conn should be set before handoff.
func NewStreamCarrier(ctx context.Context, stream io.ReadWriteCloser) (*StreamCarrier, error) {
	if ctx == nil {
		return nil, invalidConfig("context", "must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if stream == nil || nilStream(stream) {
		return nil, invalidConfig("stream", "must not be nil")
	}
	c := &StreamCarrier{
		stream:  stream,
		ctx:     ctx,
		closing: make(chan struct{}),
		done:    make(chan struct{}),
	}
	// Hold stopMu while installing the callback: an already-canceled context can
	// start Close before AfterFunc has returned its stop function.
	c.stopMu.Lock()
	c.stop = context.AfterFunc(ctx, func() { _ = c.Close() })
	c.stopMu.Unlock()
	return c, nil
}

// ReadFrame reads one complete frame, with length checked before allocation.
// Returned slices belong to the caller. EOF between frames is io.EOF; partial
// records are ErrTruncatedFrame. Any read failure closes the entire carrier;
// parsing cannot safely resume after a malformed or partially consumed frame.
func (c *StreamCarrier) ReadFrame() (CarrierFrame, error) {
	if c == nil {
		return CarrierFrame{}, net.ErrClosed
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err := c.checkOpen(); err != nil {
		return CarrierFrame{}, err
	}
	frame, err := wire.ReadFrame(c.stream)
	if err != nil {
		return CarrierFrame{}, errors.Join(err, c.ctx.Err(), c.Close())
	}
	return frame, nil
}

// WriteFrame validates and writes one complete frame without interleaving.
// Invalid local frames emit no bytes and leave the carrier usable. Transport
// errors terminate it, even if zero bytes were written; partially written frames
// are never retried. Success means local write completion, not peer acceptance.
func (c *StreamCarrier) WriteFrame(frame CarrierFrame) error {
	if c == nil {
		return net.ErrClosed
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.checkOpen(); err != nil {
		return err
	}
	writer := carrierWriter{stream: c.stream}
	err := wire.WriteFrame(&writer, frame)
	if err != nil && writer.attempted {
		return errors.Join(err, c.ctx.Err(), c.Close())
	}
	return err
}

// Close closes the owned stream exactly once and returns its original Close
// error on every call. It never acquires an I/O lock, so blocked reads/writes can
// be interrupted. The result is also available after context-triggered closure.
func (c *StreamCarrier) Close() error {
	if c == nil || c.stream == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		close(c.closing)
		c.stopMu.Lock()
		stop := c.stop
		c.stopMu.Unlock()
		if stop != nil {
			stop()
		}
		c.closeErr = c.stream.Close()
		close(c.done)
	})
	return c.closeErr
}

// Done closes after the owned stream's Close returns. It does not indicate
// authenticated Link readiness or wait for caller-owned I/O goroutines.
func (c *StreamCarrier) Done() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.done
}

func (c *StreamCarrier) checkOpen() error {
	if c.stream == nil {
		return net.ErrClosed
	}
	if err := c.ctx.Err(); err != nil {
		return errors.Join(net.ErrClosed, err)
	}
	select {
	case <-c.closing:
		return net.ErrClosed
	default:
		return nil
	}
}

// Distinguish codec rejection before emission from an underlying write failure.
type carrierWriter struct {
	stream    io.Writer
	attempted bool
}

func (w *carrierWriter) Write(p []byte) (int, error) {
	w.attempted = true
	return w.stream.Write(p)
}

func nilStream(stream io.ReadWriteCloser) bool {
	return nilValue(stream)
}
