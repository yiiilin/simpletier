package simpletier_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

func carrierFrame(kind simpletier.FrameKind, marker byte) simpletier.CarrierFrame {
	frame := simpletier.CarrierFrame{Kind: kind, Body: bytes.Repeat([]byte{marker}, 32)}
	frame.HopHeader[0] = marker
	if kind != simpletier.FrameKindLinkControl {
		frame.Envelope = make([]byte, simpletier.EnvelopeSize)
		messageType := simpletier.MessageTypeStreamData
		if kind == simpletier.FrameKindRouteControl {
			messageType = simpletier.MessageTypePathOpen
		}
		frame.Envelope[simpletier.EnvelopeMessageTypeOffset] = byte(messageType)
	}
	return frame
}

func TestStreamCarrierExistingConnections(t *testing.T) {
	for _, transport := range []string{"pipe", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			left, right := carrierConnections(t, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			a := newCarrier(t, ctx, left)
			b := newCarrier(t, ctx, right)
			for i, kind := range []simpletier.FrameKind{
				simpletier.FrameKindLinkControl,
				simpletier.FrameKindEndToEnd,
				simpletier.FrameKindRouteControl,
			} {
				transferFrame(t, a, b, carrierFrame(kind, byte(i+1)))
				transferFrame(t, b, a, carrierFrame(kind, byte(i+4)))
			}
		})
	}
}

func TestStreamCarrierFullDuplexFragmentedStream(t *testing.T) {
	left, right := carrierConnections(t, "pipe")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a := newCarrier(t, ctx, fragmentedStream{ReadWriteCloser: left})
	b := newCarrier(t, ctx, fragmentedStream{ReadWriteCloser: right})
	wantA := carrierFrame(simpletier.FrameKindEndToEnd, 10)
	wantB := carrierFrame(simpletier.FrameKindRouteControl, 20)
	writes := make(chan error, 2)
	go func() { writes <- a.WriteFrame(wantA) }()
	go func() { writes <- b.WriteFrame(wantB) }()
	type frameResult struct {
		frame simpletier.CarrierFrame
		err   error
	}
	readA, readB := make(chan frameResult, 1), make(chan frameResult, 1)
	go func() { frame, err := a.ReadFrame(); readA <- frameResult{frame, err} }()
	go func() { frame, err := b.ReadFrame(); readB <- frameResult{frame, err} }()
	gotA, gotB := <-readA, <-readB
	if gotA.err != nil || gotB.err != nil || !reflect.DeepEqual(gotA.frame, wantB) || !reflect.DeepEqual(gotB.frame, wantA) {
		t.Fatalf("fragmented duplex exchange: A=%#v B=%#v", gotA, gotB)
	}
	for i := 0; i < 2; i++ {
		if err := <-writes; err != nil {
			t.Fatal(err)
		}
	}
}

func TestStreamCarrierMaximumFrames(t *testing.T) {
	left, right := carrierConnections(t, "pipe")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, b := newCarrier(t, ctx, left), newCarrier(t, ctx, right)
	for _, kind := range []simpletier.FrameKind{simpletier.FrameKindLinkControl, simpletier.FrameKindEndToEnd, simpletier.FrameKindRouteControl} {
		frame := carrierFrame(kind, 1)
		frame.Body = bytes.Repeat([]byte{1}, int(simpletier.MaxFrameLength)-1-simpletier.HopHeaderSize-len(frame.Envelope))
		transferFrame(t, a, b, frame)
	}
}

func TestStreamCarrierCancellationReleasesWaitingOperations(t *testing.T) {
	left, _ := carrierConnections(t, "pipe")
	stream := &observedStream{Conn: left, entered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newCarrier(t, ctx, stream)
	const count = 16
	results := make(chan error, 2*count)
	for i := 0; i < count; i++ {
		go func() { _, err := c.ReadFrame(); results <- err }()
		go func() { results <- c.WriteFrame(carrierFrame(simpletier.FrameKindLinkControl, 1)) }()
	}
	waitCarrierSignal(t, stream.entered)
	cancel()
	for i := 0; i < 2*count; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("waiting operation = %v; want canceled", err)
			}
		case <-time.After(time.Second):
			t.Fatal("waiting operation was not released")
		}
	}
	waitCarrierSignal(t, c.Done())
}

func TestStreamCarrierDeadlineAndConcurrentClose(t *testing.T) {
	left, _ := carrierConnections(t, "pipe")
	stream := &observedStream{Conn: left, entered: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	c := newCarrier(t, ctx, stream)
	if _, err := c.ReadFrame(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline read = %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = c.Close() }()
	}
	wg.Wait()
	if stream.closes.Load() != 1 {
		t.Fatal("concurrent Close called underlying Close more than once")
	}
}

type fragmentedStream struct{ io.ReadWriteCloser }

func (s fragmentedStream) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return s.ReadWriteCloser.Read(p)
}

func (s fragmentedStream) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return s.ReadWriteCloser.Write(p)
}

func TestStreamCarrierSerializesConcurrentWriters(t *testing.T) {
	left, right := carrierConnections(t, "pipe")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, b := newCarrier(t, ctx, left), newCarrier(t, ctx, right)
	const count = 32
	results := make(chan error, count)
	for i := 0; i < count; i++ {
		go func(marker byte) { results <- a.WriteFrame(carrierFrame(simpletier.FrameKindLinkControl, marker)) }(byte(i))
	}
	seen := make(map[byte]bool)
	for i := 0; i < count; i++ {
		frame, err := b.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		marker := frame.HopHeader[0]
		if seen[marker] || !bytes.Equal(frame.Body, bytes.Repeat([]byte{marker}, 32)) {
			t.Fatalf("duplicate or interleaved frame: %#v", frame)
		}
		seen[marker] = true
	}
	for i := 0; i < count; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestStreamCarrierCancellationUnblocksIO(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			left, right := carrierConnections(t, "pipe")
			stream := &observedStream{Conn: left, entered: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := newCarrier(t, ctx, stream)
			result := make(chan error, 1)
			go func() {
				if operation == "read" {
					_, err := c.ReadFrame()
					result <- err
				} else {
					result <- c.WriteFrame(carrierFrame(simpletier.FrameKindLinkControl, 1))
				}
			}()
			waitCarrierSignal(t, stream.entered)
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled %s returned %v", operation, err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not unblock I/O")
			}
			waitCarrierSignal(t, c.Done())
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if stream.closes.Load() != 1 {
				t.Fatalf("underlying stream closed %d times", stream.closes.Load())
			}
			var probe [1]byte
			if _, err := right.Read(probe[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("peer read = %v; want EOF", err)
			}
		})
	}
}

func TestStreamCarrierCloseUnblocksIO(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			left, _ := carrierConnections(t, "pipe")
			stream := &observedStream{Conn: left, entered: make(chan struct{})}
			c := newCarrier(t, context.Background(), stream)
			result := make(chan error, 1)
			go func() {
				if operation == "read" {
					_, err := c.ReadFrame()
					result <- err
				} else {
					result <- c.WriteFrame(carrierFrame(simpletier.FrameKindLinkControl, 1))
				}
			}()
			waitCarrierSignal(t, stream.entered)
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("blocked I/O succeeded after close")
				}
			case <-time.After(time.Second):
				t.Fatal("Close deadlocked on an I/O lock")
			}
			if _, err := c.ReadFrame(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("read after close = %v", err)
			}
			if err := c.WriteFrame(carrierFrame(simpletier.FrameKindLinkControl, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after close = %v", err)
			}
		})
	}
}

func TestStreamCarrierConstructorCancellationRace(t *testing.T) {
	for i := 0; i < 200; i++ {
		stream := &memoryStream{input: bytes.NewReader(nil)}
		ctx, cancel := context.WithCancel(context.Background())
		start, canceled := make(chan struct{}), make(chan struct{})
		go func() {
			<-start
			cancel()
			close(canceled)
		}()
		close(start)
		c, err := simpletier.NewStreamCarrier(ctx, stream)
		<-canceled
		if err != nil {
			if !errors.Is(err, context.Canceled) || c != nil || stream.closes.Load() != 0 {
				t.Fatalf("rejected handoff changed ownership: carrier=%v err=%v closes=%d", c, err, stream.closes.Load())
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			continue
		}
		waitCarrierSignal(t, c.Done())
		if err := c.Close(); err != nil || stream.closes.Load() != 1 {
			t.Fatalf("accepted handoff did not close once: %v, closes=%d", err, stream.closes.Load())
		}
	}
}

func TestStreamCarrierConstructorRetainsStreamOnRejection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"nil context", nil, simpletier.ErrInvalidConfig},
		{"canceled context", ctx, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := &memoryStream{input: bytes.NewReader(nil)}
			if _, err := simpletier.NewStreamCarrier(tc.ctx, stream); !errors.Is(err, tc.want) {
				t.Fatalf("constructor = %v; want %v", err, tc.want)
			}
			if stream.closes.Load() != 0 {
				t.Fatal("rejected constructor took stream ownership")
			}
		})
	}
	for _, stream := range []io.ReadWriteCloser{nil, (*memoryStream)(nil)} {
		if _, err := simpletier.NewStreamCarrier(context.Background(), stream); !errors.Is(err, simpletier.ErrInvalidConfig) {
			t.Fatalf("nil stream = %v; want invalid config", err)
		}
	}
}

func TestStreamCarrierInvalidReadsCloseWithoutResynchronizing(t *testing.T) {
	tooLarge := make([]byte, 4)
	binary.BigEndian.PutUint32(tooLarge, simpletier.MaxFrameLength+1)
	unknownKind := make([]byte, 5)
	binary.BigEndian.PutUint32(unknownKind, 50)
	unknownKind[4] = 0xff
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"oversized", tooLarge, simpletier.ErrFrameTooLarge},
		{"unknown kind", unknownKind, simpletier.ErrFrameMalformed},
		{"partial prefix", []byte{0, 0}, simpletier.ErrTruncatedFrame},
		{"clean EOF", nil, io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := &memoryStream{input: bytes.NewReader(tc.data)}
			c := newCarrier(t, context.Background(), stream)
			if _, err := c.ReadFrame(); !errors.Is(err, tc.want) {
				t.Fatalf("read = %v; want %v", err, tc.want)
			}
			waitCarrierSignal(t, c.Done())
			if stream.closes.Load() != 1 {
				t.Fatal("failed read did not close stream")
			}
			if _, err := c.ReadFrame(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("read after failure = %v", err)
			}
		})
	}
}

func TestStreamCarrierSupportsGenericStreamAndShortWrites(t *testing.T) {
	stream := &memoryStream{input: bytes.NewReader(nil), maxWrite: 3}
	c := newCarrier(t, context.Background(), stream)
	want := carrierFrame(simpletier.FrameKindEndToEnd, 9)
	if err := c.WriteFrame(want); err != nil {
		t.Fatal(err)
	}
	if stream.writes < 2 {
		t.Fatal("short writer was not exercised")
	}
	reader := &memoryStream{input: bytes.NewReader(stream.output.Bytes())}
	got, err := newCarrier(t, context.Background(), reader).ReadFrame()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("short-write round trip = %#v, %v", got, err)
	}
}

func TestStreamCarrierPreservesPrebufferedBytes(t *testing.T) {
	writerStream := &memoryStream{input: bytes.NewReader(nil)}
	writer := newCarrier(t, context.Background(), writerStream)
	want := carrierFrame(simpletier.FrameKindRouteControl, 7)
	if err := writer.WriteFrame(want); err != nil {
		t.Fatal(err)
	}
	buffered := bufio.NewReader(bytes.NewReader(writerStream.output.Bytes()))
	if _, err := buffered.Peek(4); err != nil {
		t.Fatal(err)
	}
	closer := &memoryStream{input: bytes.NewReader(nil)}
	stream := struct {
		io.Reader
		io.Writer
		io.Closer
	}{buffered, &bytes.Buffer{}, closer}
	reader := newCarrier(t, context.Background(), stream)
	got, err := reader.ReadFrame()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("prebuffered frame = %#v, %v", got, err)
	}
}

func TestStreamCarrierPartialBodyPreservesIOError(t *testing.T) {
	data := make([]byte, 4+1+simpletier.HopHeaderSize+2)
	binary.BigEndian.PutUint32(data[:4], 50)
	data[4] = byte(simpletier.FrameKindLinkControl)
	failure := errors.New("partial body transport error")
	stream := &memoryStream{input: bytes.NewReader(data), readErr: failure}
	c := newCarrier(t, context.Background(), stream)
	if _, err := c.ReadFrame(); !errors.Is(err, simpletier.ErrTruncatedFrame) || !errors.Is(err, failure) {
		t.Fatalf("partial read lost its cause: %v", err)
	}
	waitCarrierSignal(t, c.Done())
	if stream.closes.Load() != 1 {
		t.Fatal("partial body did not terminate stream")
	}
}

func TestStreamCarrierLocalValidationDoesNotDamageStream(t *testing.T) {
	stream := &memoryStream{input: bytes.NewReader(nil)}
	c := newCarrier(t, context.Background(), stream)
	if err := c.WriteFrame(simpletier.CarrierFrame{}); !errors.Is(err, simpletier.ErrFrameMalformed) {
		t.Fatalf("invalid frame = %v", err)
	}
	if stream.writes != 0 || stream.closes.Load() != 0 {
		t.Fatal("local validation emitted bytes or closed stream")
	}
	if err := c.WriteFrame(carrierFrame(simpletier.FrameKindLinkControl, 1)); err != nil {
		t.Fatalf("valid frame after validation error: %v", err)
	}
}

func TestStreamCarrierPartialWriteNeverRetries(t *testing.T) {
	failure := errors.New("partial transport failure")
	stream := &memoryStream{input: bytes.NewReader(nil), writeErr: failure, failAfter: 3}
	c := newCarrier(t, context.Background(), stream)
	if err := c.WriteFrame(carrierFrame(simpletier.FrameKindLinkControl, 1)); !errors.Is(err, failure) {
		t.Fatalf("partial write = %v", err)
	}
	if stream.output.Len() != 3 || stream.writes != 1 || stream.closes.Load() != 1 {
		t.Fatal("partial write was retried or did not close the carrier")
	}
	if err := c.WriteFrame(carrierFrame(simpletier.FrameKindLinkControl, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after partial frame = %v", err)
	}
}

func TestStreamCarrierNilAndZeroHandles(t *testing.T) {
	for _, c := range []*simpletier.StreamCarrier{nil, {}} {
		if _, err := c.ReadFrame(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("uninitialized read = %v", err)
		}
		if err := c.WriteFrame(simpletier.CarrierFrame{}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("uninitialized write = %v", err)
		}
		if err := c.Close(); err != nil || c.Done() != nil {
			t.Fatalf("uninitialized lifecycle = %v", err)
		}
	}
}

func TestStreamCarrierIOFailureAndCloseErrors(t *testing.T) {
	failure := errors.New("injected write failure")
	closeFailure := errors.New("injected close failure")
	stream := &memoryStream{input: bytes.NewReader(nil), writeErr: failure, closeErr: closeFailure}
	c, err := simpletier.NewStreamCarrier(context.Background(), stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WriteFrame(carrierFrame(simpletier.FrameKindLinkControl, 1)); !errors.Is(err, failure) || !errors.Is(err, closeFailure) {
		t.Fatalf("write error lost its cause: %v", err)
	}
	if err := c.Close(); !errors.Is(err, closeFailure) {
		t.Fatalf("Close() = %v", err)
	}
	if stream.closes.Load() != 1 {
		t.Fatal("stream Close was not idempotent")
	}

	zeroWriter := &memoryStream{input: bytes.NewReader(nil), zeroWrite: true}
	zero := newCarrier(t, context.Background(), zeroWriter)
	if err := zero.WriteFrame(carrierFrame(simpletier.FrameKindLinkControl, 1)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress writer = %v", err)
	}
	waitCarrierSignal(t, zero.Done())
}

func carrierConnections(t *testing.T, transport string) (net.Conn, net.Conn) {
	t.Helper()
	if transport == "pipe" {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		return a, b
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	a, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return a, b
}

func newCarrier(t *testing.T, ctx context.Context, stream io.ReadWriteCloser) *simpletier.StreamCarrier {
	t.Helper()
	c, err := simpletier.NewStreamCarrier(ctx, stream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c
}

func transferFrame(t *testing.T, from, to *simpletier.StreamCarrier, want simpletier.CarrierFrame) {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- from.WriteFrame(want) }()
	got, err := to.ReadFrame()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("frame round trip = %#v, %v; want %#v", got, err, want)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func waitCarrierSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("carrier signal did not arrive")
	}
}

type observedStream struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
	closes  atomic.Int32
}

func (s *observedStream) Read(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	return s.Conn.Read(p)
}

func (s *observedStream) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	return s.Conn.Write(p)
}

func (s *observedStream) Close() error {
	s.closes.Add(1)
	return s.Conn.Close()
}

// memoryStream deliberately does not implement net.Conn.
type memoryStream struct {
	input     *bytes.Reader
	output    bytes.Buffer
	maxWrite  int
	zeroWrite bool
	readErr   error
	writeErr  error
	failAfter int
	closeErr  error
	writes    int
	closes    atomic.Int32
}

func (s *memoryStream) Read(p []byte) (int, error) {
	if s.input.Len() == 0 && s.readErr != nil {
		return 0, s.readErr
	}
	return s.input.Read(p)
}

func (s *memoryStream) Write(p []byte) (int, error) {
	s.writes++
	if s.writeErr != nil {
		if s.failAfter > 0 {
			n, _ := s.output.Write(p[:min(s.failAfter, len(p))])
			return n, s.writeErr
		}
		return 0, s.writeErr
	}
	if s.zeroWrite {
		return 0, nil
	}
	if s.maxWrite > 0 && len(p) > s.maxWrite {
		p = p[:s.maxWrite]
	}
	return s.output.Write(p)
}

func (s *memoryStream) Close() error {
	s.closes.Add(1)
	return s.closeErr
}
