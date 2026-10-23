package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Envelope field offsets are relative to the start of the 85-byte envelope in
// the frozen layout: network_id:u64be | src:16B | dst:16B | message_type:u8 |
// session_id:16B | key_epoch:u32be | message_number:u64be | path_id:u64be |
// path_gen:u32be | inner_len:u32be. They are published so protection code can
// read nonce/binding fields without re-deriving magic numbers.
const (
	FrameLengthPrefixSize               = 4
	FrameKindSize                       = 1
	HopHeaderSize                       = 32
	EnvelopeSize                        = 85
	EnvelopeMessageTypeOffset           = 40
	EnvelopeSessionIDOffset             = 41
	EnvelopeKeyEpochOffset              = 57
	EnvelopeMessageNumberOffset         = 61
	EnvelopePathIDOffset                = 69
	EnvelopePathGenerationOffset        = 77
	EnvelopeInnerLengthOffset           = 81
	MaxFrameLength               uint32 = 65536

	minLinkControlLength  = FrameKindSize + HopHeaderSize + 1 + 16
	minEndToEndLength     = FrameKindSize + HopHeaderSize + EnvelopeSize + 32
	minRouteControlLength = FrameKindSize + HopHeaderSize + EnvelopeSize + 1 + 16
)

// FrameKind selects which outer-frame fields and protection domains are present.
type FrameKind uint8

const (
	FrameKindLinkControl  FrameKind = 0x01
	FrameKindEndToEnd     FrameKind = 0x02
	FrameKindRouteControl FrameKind = 0x03
)

// MessageType identifies the envelope payload family.
type MessageType uint8

const (
	MessageTypeIPPacket     MessageType = 0x01
	MessageTypeUDPDatagram  MessageType = 0x02
	MessageTypeStreamData   MessageType = 0x03
	MessageTypeControlRPC   MessageType = 0x04
	MessageTypeSessionCtrl  MessageType = 0x05
	MessageTypePathOpen     MessageType = 0x06
	MessageTypePathReady    MessageType = 0x07
	MessageTypePathBroken   MessageType = 0x08
	MessageTypeSessionReady MessageType = 0x09
)

var (
	ErrFrameMalformed = errors.New("malformed frame")
	ErrFrameTooLarge  = errors.New("frame too large")
	ErrTruncatedFrame = errors.New("truncated frame")
)

// Frame is one decoded TCP-carried overlay frame. Envelope is nil for LINK_CTRL
// and exactly EnvelopeSize bytes for E2E and ROUTE_CTRL frames.
type Frame struct {
	Kind      FrameKind
	HopHeader [HopHeaderSize]byte
	Envelope  []byte
	Body      []byte
}

// ReadFrame reads one length-prefixed frame. A clean end between frames returns
// io.EOF; a partial prefix or payload returns ErrTruncatedFrame.
func ReadFrame(r io.Reader) (Frame, error) {
	var prefix [FrameLengthPrefixSize]byte
	n, err := io.ReadFull(r, prefix[:])
	if err != nil {
		if n == 0 && errors.Is(err, io.EOF) {
			return Frame{}, io.EOF
		}
		return Frame{}, fmt.Errorf("read frame length: %w: %w", ErrTruncatedFrame, err)
	}

	length := binary.BigEndian.Uint32(prefix[:])
	if length > MaxFrameLength {
		return Frame{}, fmt.Errorf("length %d exceeds %d: %w", length, MaxFrameLength, ErrFrameTooLarge)
	}
	if length < minLinkControlLength {
		return Frame{}, fmt.Errorf("length %d below minimum: %w", length, ErrFrameMalformed)
	}

	var kindByte [FrameKindSize]byte
	if _, err := io.ReadFull(r, kindByte[:]); err != nil {
		return Frame{}, fmt.Errorf("read frame kind: %w: %w", ErrTruncatedFrame, err)
	}
	kind := FrameKind(kindByte[0])
	minimum, envelopeLength, err := frameLayout(kind)
	if err != nil {
		return Frame{}, err
	}
	if length < uint32(minimum) {
		return Frame{}, fmt.Errorf("FrameKind 0x%02x length %d below minimum %d: %w", uint8(kind), length, minimum, ErrFrameMalformed)
	}
	if length > MaxFrameLength {
		return Frame{}, fmt.Errorf("length %d exceeds %d: %w", length, MaxFrameLength, ErrFrameTooLarge)
	}

	// The hop header and envelope are one contiguous run that must be read (and
	// the MessageType validated) before any body bytes are touched: a frame that
	// claims a kind it may not carry must be refused without consuming the body,
	// so a forged envelope cannot make the reader drain attacker-sized payloads.
	// Reading them together is two syscalls instead of three and does not change
	// how many bytes are consumed before the check.
	headerLength := HopHeaderSize + envelopeLength
	header := make([]byte, headerLength)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, fmt.Errorf("read frame header: %w: %w", ErrTruncatedFrame, err)
	}
	frame := Frame{Kind: kind}
	copy(frame.HopHeader[:], header[:HopHeaderSize])
	if envelopeLength != 0 {
		envelope := header[HopHeaderSize:headerLength]
		if err := validateMessageType(kind, MessageType(envelope[EnvelopeMessageTypeOffset])); err != nil {
			return Frame{}, err
		}
		frame.Envelope = envelope
	}

	bodyLength := int(length) - FrameKindSize - HopHeaderSize - envelopeLength
	if bodyLength <= 0 {
		return Frame{}, fmt.Errorf("empty protected body: %w: %w", ErrFrameMalformed, ErrTruncatedFrame)
	}
	frame.Body = make([]byte, bodyLength)
	if _, err := io.ReadFull(r, frame.Body); err != nil {
		return Frame{}, fmt.Errorf("read frame body: %w: %w", ErrTruncatedFrame, err)
	}
	return frame, nil
}

// WriteFrame encodes one frame and writes all bytes to w. length counts the
// bytes after the 4-byte prefix and is bounded by MaxFrameLength.
// frameBufPool recycles the whole-frame encoding buffer. Every frame builds one
// contiguous buffer to keep the write a single syscall, and a busy Link emits one
// frame per data chunk, so allocating that buffer per frame dominated the write
// path's allocation profile. The buffer never escapes WriteFrame.
var frameBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 64<<10)
		return &buf
	},
}

func WriteFrame(w io.Writer, frame Frame) error {
	minimum, envelopeLength, err := frameLayout(frame.Kind)
	if err != nil {
		return err
	}
	if len(frame.Envelope) != envelopeLength {
		return fmt.Errorf("FrameKind 0x%02x requires envelope length %d: %w", uint8(frame.Kind), envelopeLength, ErrFrameMalformed)
	}
	if envelopeLength != 0 {
		if err := validateMessageType(frame.Kind, MessageType(frame.Envelope[EnvelopeMessageTypeOffset])); err != nil {
			return err
		}
	}
	if len(frame.Body) == 0 {
		return fmt.Errorf("empty protected body: %w", ErrFrameMalformed)
	}

	length := uint64(FrameKindSize + HopHeaderSize + envelopeLength + len(frame.Body))
	if length > uint64(MaxFrameLength) {
		return fmt.Errorf("length %d exceeds %d: %w", length, MaxFrameLength, ErrFrameTooLarge)
	}
	if length < uint64(minimum) {
		return fmt.Errorf("length %d below minimum %d: %w", length, minimum, ErrFrameMalformed)
	}

	total := FrameLengthPrefixSize + int(length)
	bufp := frameBufPool.Get().(*[]byte)
	buf := *bufp
	if cap(buf) < total {
		buf = make([]byte, total)
	}
	buf = buf[:total]
	encoded := buf
	binary.BigEndian.PutUint32(encoded[:FrameLengthPrefixSize], uint32(length))
	encoded[FrameLengthPrefixSize] = byte(frame.Kind)
	copy(encoded[FrameLengthPrefixSize+FrameKindSize:], frame.HopHeader[:])
	offset := FrameLengthPrefixSize + FrameKindSize + HopHeaderSize
	copy(encoded[offset:], frame.Envelope)
	offset += envelopeLength
	copy(encoded[offset:], frame.Body)

	defer func() {
		*bufp = buf[:0]
		frameBufPool.Put(bufp)
	}()
	for len(encoded) > 0 {
		n, err := w.Write(encoded)
		if n < 0 || n > len(encoded) {
			return fmt.Errorf("writer returned invalid byte count %d: %w", n, io.ErrShortWrite)
		}
		encoded = encoded[n:]
		if err != nil {
			return fmt.Errorf("write frame: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("write frame: %w", io.ErrShortWrite)
		}
	}
	return nil
}

func frameLayout(kind FrameKind) (minimum, envelopeLength int, err error) {
	switch kind {
	case FrameKindLinkControl:
		return minLinkControlLength, 0, nil
	case FrameKindEndToEnd:
		return minEndToEndLength, EnvelopeSize, nil
	case FrameKindRouteControl:
		return minRouteControlLength, EnvelopeSize, nil
	default:
		return 0, 0, fmt.Errorf("unknown FrameKind 0x%02x: %w", uint8(kind), ErrFrameMalformed)
	}
}
