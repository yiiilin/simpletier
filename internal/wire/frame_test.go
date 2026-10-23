package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func makeTestFrame(kind FrameKind) Frame {
	frame := Frame{Kind: kind, Body: bytes.Repeat([]byte{0xa5}, 17)}
	for i := range frame.HopHeader {
		frame.HopHeader[i] = byte(i)
	}
	if kind != FrameKindLinkControl {
		frame.Envelope = bytes.Repeat([]byte{0x5a}, EnvelopeSize)
		switch kind {
		case FrameKindEndToEnd:
			frame.Envelope[EnvelopeMessageTypeOffset] = byte(MessageTypeIPPacket)
		case FrameKindRouteControl:
			frame.Envelope[EnvelopeMessageTypeOffset] = byte(MessageTypeSessionCtrl)
		}
	}
	if kind == FrameKindEndToEnd {
		frame.Body = bytes.Repeat([]byte{0xa5}, 32)
	}
	return frame
}

func TestWriteReadFrameRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		kind       FrameKind
		wantLength uint32
	}{
		{name: "link control minimum", kind: FrameKindLinkControl, wantLength: 50},
		{name: "end to end minimum", kind: FrameKindEndToEnd, wantLength: 150},
		{name: "route control minimum", kind: FrameKindRouteControl, wantLength: 135},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := makeTestFrame(tt.kind)
			var wire bytes.Buffer
			if err := WriteFrame(&wire, want); err != nil {
				t.Fatalf("WriteFrame() error = %v", err)
			}

			encoded := wire.Bytes()
			if got := binary.BigEndian.Uint32(encoded[:4]); got != tt.wantLength {
				t.Fatalf("length prefix = %d; want %d", got, tt.wantLength)
			}
			if got, wantSize := len(encoded), int(tt.wantLength)+4; got != wantSize {
				t.Fatalf("wire size = %d; want %d", got, wantSize)
			}

			got, err := ReadFrame(bytes.NewReader(encoded))
			if err != nil {
				t.Fatalf("ReadFrame() error = %v", err)
			}
			if got.Kind != want.Kind {
				t.Errorf("Kind = %v; want %v", got.Kind, want.Kind)
			}
			if got.HopHeader != want.HopHeader {
				t.Errorf("HopHeader = %v; want %v", got.HopHeader, want.HopHeader)
			}
			if !bytes.Equal(got.Envelope, want.Envelope) {
				t.Errorf("Envelope = %x; want %x", got.Envelope, want.Envelope)
			}
			if !bytes.Equal(got.Body, want.Body) {
				t.Errorf("Body = %x; want %x", got.Body, want.Body)
			}
		})
	}
}

func TestWriteReadFrameAcceptsAllowedMessageTypes(t *testing.T) {
	tests := []struct {
		name string
		kind FrameKind
		msg  MessageType
	}{
		{name: "IP_PACKET", kind: FrameKindEndToEnd, msg: MessageTypeIPPacket},
		{name: "UDP_DATAGRAM", kind: FrameKindEndToEnd, msg: MessageTypeUDPDatagram},
		{name: "STREAM_DATA", kind: FrameKindEndToEnd, msg: MessageTypeStreamData},
		{name: "CONTROL_RPC", kind: FrameKindEndToEnd, msg: MessageTypeControlRPC},
		{name: "SESSION_CTRL", kind: FrameKindRouteControl, msg: MessageTypeSessionCtrl},
		{name: "PATH_OPEN", kind: FrameKindRouteControl, msg: MessageTypePathOpen},
		{name: "PATH_READY", kind: FrameKindRouteControl, msg: MessageTypePathReady},
		{name: "PATH_BROKEN", kind: FrameKindRouteControl, msg: MessageTypePathBroken},
		{name: "SESSION_READY", kind: FrameKindRouteControl, msg: MessageTypeSessionReady},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := makeTestFrame(tt.kind)
			frame.Envelope[EnvelopeMessageTypeOffset] = byte(tt.msg)
			var wire bytes.Buffer
			if err := WriteFrame(&wire, frame); err != nil {
				t.Fatalf("WriteFrame() error = %v", err)
			}
			if _, err := ReadFrame(bytes.NewReader(wire.Bytes())); err != nil {
				t.Fatalf("ReadFrame() error = %v", err)
			}
		})
	}
}

func TestWriteFrameRejectsMessageTypeMismatch(t *testing.T) {
	tests := []struct {
		name string
		kind FrameKind
		msg  byte
	}{
		{name: "E2E rejects SESSION_CTRL", kind: FrameKindEndToEnd, msg: byte(MessageTypeSessionCtrl)},
		{name: "ROUTE_CTRL rejects IP_PACKET", kind: FrameKindRouteControl, msg: byte(MessageTypeIPPacket)},
		{name: "E2E rejects unknown MessageType", kind: FrameKindEndToEnd, msg: 0xff},
		{name: "ROUTE_CTRL rejects unknown MessageType", kind: FrameKindRouteControl, msg: 0xff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := makeTestFrame(tt.kind)
			frame.Envelope[EnvelopeMessageTypeOffset] = tt.msg
			var wire bytes.Buffer
			err := WriteFrame(&wire, frame)
			if !errors.Is(err, ErrFrameMalformed) {
				t.Fatalf("WriteFrame() error = %v; want ErrFrameMalformed", err)
			}
			if wire.Len() != 0 {
				t.Fatalf("WriteFrame() emitted %d bytes for invalid mapping", wire.Len())
			}
		})
	}
}

func TestReadFrameRejectsMessageTypeMismatchBeforeBody(t *testing.T) {
	tests := []struct {
		name string
		kind FrameKind
		msg  byte
	}{
		{name: "E2E rejects SESSION_CTRL", kind: FrameKindEndToEnd, msg: byte(MessageTypeSessionCtrl)},
		{name: "ROUTE_CTRL rejects IP_PACKET", kind: FrameKindRouteControl, msg: byte(MessageTypeIPPacket)},
		{name: "E2E rejects unknown MessageType", kind: FrameKindEndToEnd, msg: 0xff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := makeTestFrame(tt.kind)
			var wire bytes.Buffer
			if err := WriteFrame(&wire, frame); err != nil {
				t.Fatalf("WriteFrame() error = %v", err)
			}
			encoded := append([]byte(nil), wire.Bytes()...)
			envelopeTypeOffset := FrameLengthPrefixSize + FrameKindSize + HopHeaderSize + EnvelopeMessageTypeOffset
			encoded[envelopeTypeOffset] = tt.msg

			reader := &countingReader{data: encoded}
			_, err := ReadFrame(reader)
			if !errors.Is(err, ErrFrameMalformed) {
				t.Fatalf("ReadFrame() error = %v; want ErrFrameMalformed", err)
			}
			wantRead := FrameLengthPrefixSize + FrameKindSize + HopHeaderSize + EnvelopeSize
			if reader.readBytes != wantRead {
				t.Fatalf("ReadFrame() consumed %d bytes; want %d before rejecting MessageType", reader.readBytes, wantRead)
			}
		})
	}
}

func TestEnvelopeMessageTypeUsesWireOffset(t *testing.T) {
	const wireMessageTypeOffset = 77
	if got := FrameLengthPrefixSize + FrameKindSize + HopHeaderSize + EnvelopeMessageTypeOffset; got != wireMessageTypeOffset {
		t.Fatalf("message type wire offset = %d; want %d", got, wireMessageTypeOffset)
	}

	frame := makeTestFrame(FrameKindEndToEnd)
	var wire bytes.Buffer
	if err := WriteFrame(&wire, frame); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if got := wire.Bytes()[wireMessageTypeOffset]; got != byte(MessageTypeIPPacket) {
		t.Fatalf("raw wire MessageType at byte %d = 0x%02x; want 0x%02x", wireMessageTypeOffset, got, MessageTypeIPPacket)
	}
}

func TestEnvelopeFieldOffsetsMatchFrozenLayout(t *testing.T) {
	// The frozen envelope is 85 bytes: network_id:u64 | src:16B | dst:16B |
	// message_type:u8 | session_id:16B | key_epoch:u32 | message_number:u64 |
	// path_id:u64 | path_gen:u32 | inner_len:u32. These offsets are the
	// public contract the hop-nonce invariant reads; verify them exactly.
	offsets := []struct {
		name string
		got  int
		want int
	}{
		{"message_type", EnvelopeMessageTypeOffset, 8 + 16 + 16},
		{"session_id", EnvelopeSessionIDOffset, EnvelopeMessageTypeOffset + 1},
		{"key_epoch", EnvelopeKeyEpochOffset, EnvelopeSessionIDOffset + 16},
		{"message_number", EnvelopeMessageNumberOffset, EnvelopeKeyEpochOffset + 4},
		{"path_id", EnvelopePathIDOffset, EnvelopeMessageNumberOffset + 8},
		{"path_generation", EnvelopePathGenerationOffset, EnvelopePathIDOffset + 8},
		{"inner_length", EnvelopeInnerLengthOffset, EnvelopePathGenerationOffset + 4},
	}
	for _, tt := range offsets {
		if tt.got != tt.want {
			t.Errorf("%s offset = %d; want %d", tt.name, tt.got, tt.want)
		}
	}
	if got := EnvelopeInnerLengthOffset + 4; got != EnvelopeSize {
		t.Fatalf("inner_length end = %d; want envelope size %d", got, EnvelopeSize)
	}

	// Confirm the declared offsets are the real wire locations by writing an
	// envelope with distinctive bytes and reading them back raw.
	frame := makeTestFrame(FrameKindEndToEnd)
	const generation uint32 = 0x11223344
	const messageNumber uint64 = 0x0102030405060708
	const pathID uint64 = 0xa1a2a3a4a5a6a7a8
	const pathGeneration uint32 = 0xb1b2b3b4
	const innerLength uint32 = 0x0000002a
	binary.BigEndian.PutUint32(frame.Envelope[EnvelopeKeyEpochOffset:], generation)
	binary.BigEndian.PutUint64(frame.Envelope[EnvelopeMessageNumberOffset:], messageNumber)
	binary.BigEndian.PutUint64(frame.Envelope[EnvelopePathIDOffset:], pathID)
	binary.BigEndian.PutUint32(frame.Envelope[EnvelopePathGenerationOffset:], pathGeneration)
	binary.BigEndian.PutUint32(frame.Envelope[EnvelopeInnerLengthOffset:], innerLength)
	var out bytes.Buffer
	if err := WriteFrame(&out, frame); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	raw := out.Bytes()
	envelopeStart := FrameLengthPrefixSize + FrameKindSize + HopHeaderSize
	field := func(offset, width int) []byte {
		t.Helper()
		return raw[envelopeStart+offset : envelopeStart+offset+width]
	}
	if got := binary.BigEndian.Uint32(field(EnvelopeKeyEpochOffset, 4)); got != generation {
		t.Errorf("raw key_epoch = %#x; want %#x", got, generation)
	}
	if got := binary.BigEndian.Uint64(field(EnvelopeMessageNumberOffset, 8)); got != messageNumber {
		t.Errorf("raw message_number = %#x; want %#x", got, messageNumber)
	}
	if got := binary.BigEndian.Uint64(field(EnvelopePathIDOffset, 8)); got != pathID {
		t.Errorf("raw path_id = %#x; want %#x", got, pathID)
	}
	if got := binary.BigEndian.Uint32(field(EnvelopePathGenerationOffset, 4)); got != pathGeneration {
		t.Errorf("raw path_gen = %#x; want %#x", got, pathGeneration)
	}
	if got := binary.BigEndian.Uint32(field(EnvelopeInnerLengthOffset, 4)); got != innerLength {
		t.Errorf("raw inner_len = %#x; want %#x", got, innerLength)
	}
	if got := raw[envelopeStart+EnvelopeSessionIDOffset+15]; got != frame.Envelope[EnvelopeSessionIDOffset+15] {
		t.Errorf("raw session_id tail = %#x; want %#x", got, frame.Envelope[EnvelopeSessionIDOffset+15])
	}
}

func TestMaximumFrameLengthRoundTrips(t *testing.T) {
	tests := []struct {
		name         string
		kind         FrameKind
		envelopeSize int
	}{
		{name: "LINK_CTRL", kind: FrameKindLinkControl},
		{name: "E2E", kind: FrameKindEndToEnd, envelopeSize: EnvelopeSize},
		{name: "ROUTE_CTRL", kind: FrameKindRouteControl, envelopeSize: EnvelopeSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := makeTestFrame(tt.kind)
			frame.Body = bytes.Repeat([]byte{0x7f}, int(MaxFrameLength)-FrameKindSize-HopHeaderSize-tt.envelopeSize)

			var wire bytes.Buffer
			if err := WriteFrame(&wire, frame); err != nil {
				t.Fatalf("WriteFrame() at maximum length error = %v", err)
			}
			if got := binary.BigEndian.Uint32(wire.Bytes()[:4]); got != MaxFrameLength {
				t.Fatalf("length prefix = %d; want %d", got, MaxFrameLength)
			}
			if got, want := wire.Len(), FrameLengthPrefixSize+int(MaxFrameLength); got != want {
				t.Fatalf("wire size = %d; want %d", got, want)
			}

			got, err := ReadFrame(bytes.NewReader(wire.Bytes()))
			if err != nil {
				t.Fatalf("ReadFrame() at maximum length error = %v", err)
			}
			if got.Kind != frame.Kind || len(got.Body) != len(frame.Body) {
				t.Fatalf("decoded kind/body = %v/%d; want %v/%d", got.Kind, len(got.Body), frame.Kind, len(frame.Body))
			}
		})
	}
}

func TestReadFrameRejectsOversizedLengthBeforeReadingPayload(t *testing.T) {
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, MaxFrameLength+1)
	reader := &countingReader{data: prefix}

	_, err := ReadFrame(reader)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame() error = %v; want ErrFrameTooLarge", err)
	}
	if reader.readBytes != 4 {
		t.Fatalf("ReadFrame() read %d bytes; want only the 4-byte prefix", reader.readBytes)
	}
}

func TestReadFrameRejectsKindSpecificShortLength(t *testing.T) {
	tests := []struct {
		name   string
		kind   FrameKind
		length uint32
	}{
		{name: "link control", kind: FrameKindLinkControl, length: 49},
		{name: "end to end", kind: FrameKindEndToEnd, length: 149},
		{name: "route control", kind: FrameKindRouteControl, length: 134},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := make([]byte, int(tt.length)+4)
			binary.BigEndian.PutUint32(wire[:4], tt.length)
			wire[4] = byte(tt.kind)

			reader := &countingReader{data: wire}
			_, err := ReadFrame(reader)
			if !errors.Is(err, ErrFrameMalformed) {
				t.Fatalf("ReadFrame() error = %v; want ErrFrameMalformed", err)
			}
			wantRead := 4
			if tt.kind != FrameKindLinkControl {
				wantRead++
			}
			if reader.readBytes != wantRead {
				t.Fatalf("ReadFrame() consumed %d bytes; want %d before rejecting short length", reader.readBytes, wantRead)
			}
		})
	}
}

func TestReadFrameRejectsUnknownKind(t *testing.T) {
	wire := make([]byte, 54)
	binary.BigEndian.PutUint32(wire[:4], 50)
	wire[4] = 0xff
	reader := &countingReader{data: wire}

	_, err := ReadFrame(reader)
	if !errors.Is(err, ErrFrameMalformed) {
		t.Fatalf("ReadFrame() error = %v; want ErrFrameMalformed", err)
	}
	if reader.readBytes != 5 {
		t.Fatalf("ReadFrame() consumed %d bytes; want only the prefix and FrameKind", reader.readBytes)
	}
}

func TestReadFrameReportsTruncatedFrame(t *testing.T) {
	wire := make([]byte, 4+10)
	binary.BigEndian.PutUint32(wire[:4], 50)
	wire[4] = byte(FrameKindLinkControl)

	_, err := ReadFrame(bytes.NewReader(wire))
	if !errors.Is(err, ErrTruncatedFrame) {
		t.Fatalf("ReadFrame() error = %v; want ErrTruncatedFrame", err)
	}
}

func TestWriteFrameRejectsInvalidLayout(t *testing.T) {
	tests := []struct {
		name    string
		frame   Frame
		wantErr error
	}{
		{
			name:    "wrong envelope size",
			frame:   Frame{Kind: FrameKindEndToEnd, Body: bytes.Repeat([]byte{1}, 32), Envelope: []byte{1}},
			wantErr: ErrFrameMalformed,
		},
		{
			name:    "link control has envelope",
			frame:   Frame{Kind: FrameKindLinkControl, Body: bytes.Repeat([]byte{1}, 17), Envelope: bytes.Repeat([]byte{1}, EnvelopeSize)},
			wantErr: ErrFrameMalformed,
		},
		{
			name:    "unknown kind",
			frame:   Frame{Kind: FrameKind(0xff), Body: bytes.Repeat([]byte{1}, 17)},
			wantErr: ErrFrameMalformed,
		},
		{
			name:    "short end-to-end body",
			frame:   Frame{Kind: FrameKindEndToEnd, Body: bytes.Repeat([]byte{1}, 31), Envelope: bytes.Repeat([]byte{1}, EnvelopeSize)},
			wantErr: ErrFrameMalformed,
		},
		{
			name:    "oversized frame",
			frame:   Frame{Kind: FrameKindLinkControl, Body: bytes.Repeat([]byte{1}, int(MaxFrameLength))},
			wantErr: ErrFrameTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wire bytes.Buffer
			err := WriteFrame(&wire, tt.frame)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("WriteFrame() error = %v; want %v", err, tt.wantErr)
			}
		})
	}
}

type countingReader struct {
	data      []byte
	readBytes int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.readBytes += n
	return n, nil
}
