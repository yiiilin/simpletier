package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	HandshakeHeaderSize          = 22
	MaxHandshakeLength    uint32 = 8192
	MaxHandshakeWireBytes uint32 = 24576
)

// HandshakeKind identifies an ordered raw XX record before ordinary frame mode.
type HandshakeKind uint8

const (
	HandshakeXXMsg1 HandshakeKind = 0x01
	HandshakeXXMsg2 HandshakeKind = 0x02
	HandshakeXXMsg3 HandshakeKind = 0x03
)

var (
	ErrHandshakeMalformed = errors.New("malformed handshake")
	ErrHandshakeTooLarge  = errors.New("handshake too large")
	ErrTruncatedHandshake = errors.New("truncated handshake")
)

// HandshakeRecord is structural metadata and an opaque Noise payload, not an
// authenticated identity or Link. Returned Payload bytes belong to the caller.
type HandshakeRecord struct {
	Kind       HandshakeKind
	LinkID     uint64
	LinkEpoch  uint64
	Generation uint32
	LaneID     uint8
	Payload    []byte
}

// ReadHandshake reads a bounded raw record. The prefix counts only the bytes
// after it. Clean EOF between records is io.EOF; partial records preserve both
// ErrTruncatedHandshake and the underlying cause. Invalid header fields are
// rejected before payload allocation. No stream ownership or closure is implied.
func ReadHandshake(r io.Reader) (HandshakeRecord, error) {
	return readHandshake(r, FrameLengthPrefixSize+MaxHandshakeLength)
}

func readHandshake(r io.Reader, wireBudget uint32) (HandshakeRecord, error) {
	var prefix [FrameLengthPrefixSize]byte
	n, err := io.ReadFull(r, prefix[:])
	if err != nil {
		if n == 0 && errors.Is(err, io.EOF) {
			return HandshakeRecord{}, io.EOF
		}
		return HandshakeRecord{}, fmt.Errorf("read handshake length: %w: %w", ErrTruncatedHandshake, err)
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length > MaxHandshakeLength {
		return HandshakeRecord{}, fmt.Errorf("length %d exceeds %d: %w", length, MaxHandshakeLength, ErrHandshakeTooLarge)
	}
	if length < HandshakeHeaderSize {
		return HandshakeRecord{}, fmt.Errorf("length %d below header: %w", length, ErrHandshakeMalformed)
	}
	if FrameLengthPrefixSize+length > wireBudget {
		return HandshakeRecord{}, fmt.Errorf("record wire bytes %d exceed remaining %d: %w", FrameLengthPrefixSize+length, wireBudget, ErrHandshakeTooLarge)
	}
	var header [HandshakeHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return HandshakeRecord{}, fmt.Errorf("read handshake header: %w: %w", ErrTruncatedHandshake, err)
	}
	record := HandshakeRecord{
		Kind:       HandshakeKind(header[0]),
		LinkID:     binary.BigEndian.Uint64(header[1:9]),
		LinkEpoch:  binary.BigEndian.Uint64(header[9:17]),
		Generation: binary.BigEndian.Uint32(header[17:21]),
		LaneID:     header[21],
	}
	if _, err := handshakeRecordLength(record); err != nil {
		return HandshakeRecord{}, err
	}
	record.Payload = make([]byte, int(length)-HandshakeHeaderSize)
	if _, err := io.ReadFull(r, record.Payload); err != nil {
		return HandshakeRecord{}, fmt.Errorf("read handshake payload: %w: %w", ErrTruncatedHandshake, err)
	}
	return record, nil
}

// WriteHandshake validates before emission and handles positive short writes.
// Any transport failure can leave a partial record; callers must terminate that
// handshake instead of retrying the record on the same stream. No stream closes
// occur here. Payload must remain unchanged until this call returns.
func WriteHandshake(w io.Writer, record HandshakeRecord) error {
	length, err := handshakeRecordLength(record)
	if err != nil {
		return err
	}
	encoded := make([]byte, FrameLengthPrefixSize+int(length))
	binary.BigEndian.PutUint32(encoded[:4], length)
	encoded[4] = byte(record.Kind)
	binary.BigEndian.PutUint64(encoded[5:13], record.LinkID)
	binary.BigEndian.PutUint64(encoded[13:21], record.LinkEpoch)
	binary.BigEndian.PutUint32(encoded[21:25], record.Generation)
	encoded[25] = record.LaneID
	copy(encoded[26:], record.Payload)
	for len(encoded) > 0 {
		n, err := w.Write(encoded)
		if n < 0 || n > len(encoded) {
			return fmt.Errorf("writer returned invalid count %d: %w", n, io.ErrShortWrite)
		}
		encoded = encoded[n:]
		if err != nil {
			return fmt.Errorf("write handshake: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("write handshake: %w", io.ErrShortWrite)
		}
	}
	return nil
}

func handshakeRecordLength(record HandshakeRecord) (uint32, error) {
	if record.Kind < HandshakeXXMsg1 || record.Kind > HandshakeXXMsg3 {
		return 0, fmt.Errorf("unknown record kind 0x%02x: %w", uint8(record.Kind), ErrHandshakeMalformed)
	}
	if record.LinkID == 0 || record.LinkEpoch == 0 || record.Generation == 0 || record.LaneID > 2 {
		return 0, fmt.Errorf("invalid Link metadata: %w", ErrHandshakeMalformed)
	}
	length := uint64(HandshakeHeaderSize) + uint64(len(record.Payload))
	if length > uint64(MaxHandshakeLength) {
		return 0, fmt.Errorf("length %d exceeds %d: %w", length, MaxHandshakeLength, ErrHandshakeTooLarge)
	}
	return uint32(length), nil
}

// HandshakeSequence is a single-owner, zero-value-ready structural transcript
// tracker. Read/Write consume each received/sent record once in 1/2/3 order and
// enforce the aggregate budget before payload allocation/emission. Accept does
// the same structural validation for a prebuilt record. Payloads are not retained,
// consumed steps are not rolled back, and Done is not Noise authentication. Any
// validation/I/O failure poisons it; callers own cancellation and stream closure.
type HandshakeSequence struct {
	step       HandshakeKind
	linkID     uint64
	linkEpoch  uint64
	generation uint32
	laneID     uint8
	wireBytes  uint32
	failed     bool
}

func (s *HandshakeSequence) checkOpen() error {
	if s == nil {
		return fmt.Errorf("nil handshake sequence: %w", ErrHandshakeMalformed)
	}
	if s.failed || s.step == HandshakeXXMsg3 {
		s.failed = true
		return fmt.Errorf("handshake sequence is terminal: %w", ErrHandshakeMalformed)
	}
	return nil
}

// Read checks the remaining aggregate wire budget immediately after the prefix.
// EOF while awaiting a record aborts this sequence even though the codec preserves
// clean io.EOF. It does not close r or authenticate the opaque payload.
func (s *HandshakeSequence) Read(r io.Reader) (HandshakeRecord, error) {
	if err := s.checkOpen(); err != nil {
		return HandshakeRecord{}, err
	}
	record, err := readHandshake(r, MaxHandshakeWireBytes-s.wireBytes)
	if err != nil {
		s.failed = true
		return HandshakeRecord{}, err
	}
	if err := s.Accept(record); err != nil {
		return HandshakeRecord{}, err
	}
	return record, nil
}

// Write validates the next step before emitting bytes. On transport failure it
// poisons the sequence, never retries, and leaves stream teardown to the caller.
func (s *HandshakeSequence) Write(w io.Writer, record HandshakeRecord) error {
	if err := s.Accept(record); err != nil {
		return err
	}
	if err := WriteHandshake(w, record); err != nil {
		s.failed = true
		return err
	}
	return nil
}

func (s *HandshakeSequence) Accept(record HandshakeRecord) error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	length, err := handshakeRecordLength(record)
	if err != nil {
		s.failed = true
		return err
	}
	if record.Kind != s.step+1 {
		s.failed = true
		return fmt.Errorf("record kind %d after %d: %w", record.Kind, s.step, ErrHandshakeMalformed)
	}
	if s.step != 0 && (record.LinkID != s.linkID || record.LinkEpoch != s.linkEpoch || record.Generation != s.generation || record.LaneID != s.laneID) {
		s.failed = true
		return fmt.Errorf("handshake metadata changed: %w", ErrHandshakeMalformed)
	}
	wireBytes := s.wireBytes + FrameLengthPrefixSize + length
	if wireBytes > MaxHandshakeWireBytes {
		s.failed = true
		return fmt.Errorf("wire bytes %d exceed %d: %w", wireBytes, MaxHandshakeWireBytes, ErrHandshakeTooLarge)
	}
	s.step = record.Kind
	s.linkID, s.linkEpoch, s.generation, s.laneID = record.LinkID, record.LinkEpoch, record.Generation, record.LaneID
	s.wireBytes = wireBytes
	return nil
}

func (s *HandshakeSequence) Done() bool {
	return s != nil && !s.failed && s.step == HandshakeXXMsg3
}

func (s *HandshakeSequence) WireBytes() uint32 {
	if s == nil {
		return 0
	}
	return s.wireBytes
}
