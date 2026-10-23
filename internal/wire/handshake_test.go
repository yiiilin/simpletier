package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

func handshakeFixture(kind HandshakeKind) HandshakeRecord {
	return HandshakeRecord{Kind: kind, LinkID: 0x0102030405060708, LinkEpoch: 0x1112131415161718, Generation: 0x21222324, LaneID: 2, Payload: []byte{0xde, 0xad, 0xbe, 0xef}}
}

func TestHandshakeIndependentWireVectors(t *testing.T) {
	vectors := []struct {
		kind HandshakeKind
		hex  string
	}{
		{HandshakeXXMsg1, "0000001a01010203040506070811121314151617182122232402deadbeef"},
		{HandshakeXXMsg2, "0000001a02010203040506070811121314151617182122232402deadbeef"},
		{HandshakeXXMsg3, "0000001a03010203040506070811121314151617182122232402deadbeef"},
	}
	for _, vector := range vectors {
		want, err := hex.DecodeString(vector.hex)
		if err != nil {
			t.Fatal(err)
		}
		var encoded bytes.Buffer
		record := handshakeFixture(vector.kind)
		if err := WriteHandshake(&encoded, record); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded.Bytes(), want) {
			t.Fatalf("layout: got %x want %x", encoded.Bytes(), want)
		}
		got, err := ReadHandshake(&handshakeChunkReader{reader: bytes.NewReader(want), chunk: 1})
		if err != nil || !reflect.DeepEqual(got, record) {
			t.Fatalf("decode: %#v %v", got, err)
		}
		for i := range want {
			want[i] = 0
		}
		if !bytes.Equal(got.Payload, record.Payload) {
			t.Fatal("decoded payload aliases input")
		}
	}
}

func TestHandshakeLengthBoundsAndHeaderValidation(t *testing.T) {
	for _, length := range []uint32{0, 21, 8193, ^uint32(0)} {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], length)
		reader := &countingReader{data: prefix[:]}
		_, err := ReadHandshake(reader)
		want := ErrHandshakeMalformed
		if length > 8192 {
			want = ErrHandshakeTooLarge
		}
		if !errors.Is(err, want) || reader.readBytes != 4 {
			t.Fatalf("length=%d: %v consumed=%d", length, err, reader.readBytes)
		}
	}
	valid := handshakeFixture(HandshakeXXMsg1)
	mutations := []struct {
		name   string
		change func(*HandshakeRecord)
	}{
		{"kind0", func(r *HandshakeRecord) { r.Kind = 0 }},
		{"kind4", func(r *HandshakeRecord) { r.Kind = 4 }},
		{"link0", func(r *HandshakeRecord) { r.LinkID = 0 }},
		{"epoch0", func(r *HandshakeRecord) { r.LinkEpoch = 0 }},
		{"generation0", func(r *HandshakeRecord) { r.Generation = 0 }},
		{"lane3", func(r *HandshakeRecord) { r.LaneID = 3 }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			bad := valid
			mutation.change(&bad)
			var output bytes.Buffer
			if err := WriteHandshake(&output, bad); !errors.Is(err, ErrHandshakeMalformed) || output.Len() != 0 {
				t.Fatalf("invalid writer: %v output=%d", err, output.Len())
			}
			var encoded bytes.Buffer
			if err := WriteHandshake(&encoded, valid); err != nil {
				t.Fatal(err)
			}
			data := append([]byte(nil), encoded.Bytes()...)
			switch mutation.name {
			case "kind0":
				data[4] = 0
			case "kind4":
				data[4] = 4
			case "link0":
				clear(data[5:13])
			case "epoch0":
				clear(data[13:21])
			case "generation0":
				clear(data[21:25])
			case "lane3":
				data[25] = 3
			}
			reader := &countingReader{data: data}
			if _, err := ReadHandshake(reader); !errors.Is(err, ErrHandshakeMalformed) || reader.readBytes != 26 {
				t.Fatalf("invalid reader: %v consumed=%d", err, reader.readBytes)
			}
		})
	}
}

func TestHandshakeMaximumAndEmptyOpaquePayload(t *testing.T) {
	for _, lane := range []uint8{0, 1, 2} {
		for _, size := range []int{0, 8192 - 22} {
			record := handshakeFixture(HandshakeXXMsg1)
			record.LaneID = lane
			record.Payload = bytes.Repeat([]byte{0xa5}, size)
			var encoded bytes.Buffer
			if err := WriteHandshake(&encoded, record); err != nil {
				t.Fatal(err)
			}
			if encoded.Len() != size+26 || binary.BigEndian.Uint32(encoded.Bytes()[:4]) != uint32(size+22) {
				t.Fatal("prefix counts wrong bytes")
			}
			got, err := ReadHandshake(bytes.NewReader(encoded.Bytes()))
			if err != nil || !bytes.Equal(got.Payload, record.Payload) || got.LaneID != lane {
				t.Fatalf("maximum/empty: %#v %v", got, err)
			}
		}
	}
	bad := handshakeFixture(HandshakeXXMsg1)
	bad.Payload = make([]byte, 8192-22+1)
	var encoded bytes.Buffer
	if err := WriteHandshake(&encoded, bad); !errors.Is(err, ErrHandshakeTooLarge) || encoded.Len() != 0 {
		t.Fatalf("oversized output: %v %d", err, encoded.Len())
	}
}

func TestHandshakeEOFTruncationAndUnderlyingCause(t *testing.T) {
	var encoded bytes.Buffer
	if err := WriteHandshake(&encoded, handshakeFixture(HandshakeXXMsg1)); err != nil {
		t.Fatal(err)
	}
	data := encoded.Bytes()
	if _, err := ReadHandshake(bytes.NewReader(nil)); err != io.EOF {
		t.Fatalf("clean EOF = %v", err)
	}
	for length := 1; length < len(data); length++ {
		_, err := ReadHandshake(bytes.NewReader(data[:length]))
		if !errors.Is(err, ErrTruncatedHandshake) {
			t.Fatalf("cut %d: %v", length, err)
		}
		cause := io.ErrUnexpectedEOF
		if length == 4 || length == 26 {
			cause = io.EOF
		}
		if !errors.Is(err, cause) {
			t.Fatalf("cut %d lost cause %v: %v", length, cause, err)
		}
	}
	failure := errors.New("injected read failure")
	_, err := ReadHandshake(io.MultiReader(bytes.NewReader(data[:5]), handshakeErrorReader{err: failure}))
	if !errors.Is(err, ErrTruncatedHandshake) || !errors.Is(err, failure) {
		t.Fatalf("cause not retained: %v", err)
	}
}

func TestHandshakeShortWritesAndFailure(t *testing.T) {
	record := handshakeFixture(HandshakeXXMsg1)
	var want bytes.Buffer
	if err := WriteHandshake(&want, record); err != nil {
		t.Fatal(err)
	}
	writer := &handshakeShortWriter{limit: 3}
	if err := WriteHandshake(writer, record); err != nil || !bytes.Equal(writer.Bytes(), want.Bytes()) {
		t.Fatalf("short writes: %v %x", err, writer.Bytes())
	}
	for _, count := range []int{-1, 0, 1000} {
		bad := &handshakeBadWriter{count: count}
		if err := WriteHandshake(bad, record); !errors.Is(err, io.ErrShortWrite) || bad.calls != 1 {
			t.Fatalf("bad count %d: %v calls=%d", count, err, bad.calls)
		}
	}
	failure := errors.New("injected write failure")
	bad := &handshakeBadWriter{count: 2, err: failure}
	if err := WriteHandshake(bad, record); !errors.Is(err, failure) || bad.calls != 1 {
		t.Fatalf("partial failed write retried or lost cause: %v", err)
	}
}

func TestHandshakeSequenceOrderMetadataAndBudget(t *testing.T) {
	var sequence HandshakeSequence
	for kind := HandshakeXXMsg1; kind <= HandshakeXXMsg3; kind++ {
		record := handshakeFixture(kind)
		record.Payload = make([]byte, 8192-22)
		if kind == HandshakeXXMsg3 {
			record.Payload = record.Payload[:len(record.Payload)-12]
		}
		if err := sequence.Accept(record); err != nil {
			t.Fatal(err)
		}
	}
	if !sequence.Done() || sequence.WireBytes() != 24576 {
		t.Fatalf("sequence completed with wrong total: done=%v bytes=%d", sequence.Done(), sequence.WireBytes())
	}
	if err := sequence.Accept(handshakeFixture(HandshakeXXMsg3)); !errors.Is(err, ErrHandshakeMalformed) || sequence.Done() {
		t.Fatalf("replayed final record accepted: %v", err)
	}
	cases := []struct {
		name   string
		kind   HandshakeKind
		mutate func(*HandshakeRecord)
	}{
		{"replay", HandshakeXXMsg1, func(*HandshakeRecord) {}},
		{"skip", HandshakeXXMsg3, func(*HandshakeRecord) {}},
		{"link mismatch", HandshakeXXMsg2, func(r *HandshakeRecord) { r.LinkID++ }},
		{"epoch mismatch", HandshakeXXMsg2, func(r *HandshakeRecord) { r.LinkEpoch++ }},
		{"generation mismatch", HandshakeXXMsg2, func(r *HandshakeRecord) { r.Generation++ }},
		{"lane mismatch", HandshakeXXMsg2, func(r *HandshakeRecord) { r.LaneID = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sequence HandshakeSequence
			if err := sequence.Accept(handshakeFixture(HandshakeXXMsg1)); err != nil {
				t.Fatal(err)
			}
			record := handshakeFixture(tc.kind)
			tc.mutate(&record)
			if err := sequence.Accept(record); !errors.Is(err, ErrHandshakeMalformed) {
				t.Fatalf("invalid sequence accepted: %v", err)
			}
			if err := sequence.Accept(handshakeFixture(HandshakeXXMsg2)); !errors.Is(err, ErrHandshakeMalformed) {
				t.Fatal("failed sequence resumed")
			}
		})
	}
	var tooLarge HandshakeSequence
	for kind := HandshakeXXMsg1; kind <= HandshakeXXMsg3; kind++ {
		record := handshakeFixture(kind)
		record.Payload = make([]byte, 8192-22)
		err := tooLarge.Accept(record)
		if kind < HandshakeXXMsg3 && err != nil {
			t.Fatal(err)
		}
		if kind == HandshakeXXMsg3 && (!errors.Is(err, ErrHandshakeTooLarge) || tooLarge.WireBytes() != 16392 || tooLarge.Done()) {
			t.Fatalf("aggregate budget not enforced: %v %d", err, tooLarge.WireBytes())
		}
	}
}

func TestHandshakeSequenceTerminalInputs(t *testing.T) {
	var missing *HandshakeSequence
	if err := missing.Accept(handshakeFixture(HandshakeXXMsg1)); !errors.Is(err, ErrHandshakeMalformed) || missing.Done() || missing.WireBytes() != 0 {
		t.Fatalf("nil sequence: %v", err)
	}
	for _, kind := range []HandshakeKind{0, HandshakeXXMsg2, HandshakeXXMsg3} {
		var sequence HandshakeSequence
		if err := sequence.Accept(handshakeFixture(kind)); !errors.Is(err, ErrHandshakeMalformed) || sequence.WireBytes() != 0 || sequence.Done() {
			t.Fatalf("invalid first kind %d: %v", kind, err)
		}
		if err := sequence.Accept(handshakeFixture(HandshakeXXMsg1)); !errors.Is(err, ErrHandshakeMalformed) {
			t.Fatal("invalid first message did not poison sequence")
		}
	}
}

func TestHandshakeSequenceIOBudgetAndFailure(t *testing.T) {
	var sequence HandshakeSequence
	for _, kind := range []HandshakeKind{HandshakeXXMsg1, HandshakeXXMsg2} {
		record := handshakeFixture(kind)
		record.Payload = make([]byte, 8192-22)
		if err := sequence.Write(io.Discard, record); err != nil {
			t.Fatal(err)
		}
	}
	third := handshakeFixture(HandshakeXXMsg3)
	third.Payload = make([]byte, 8192-22)
	var encoded bytes.Buffer
	if err := WriteHandshake(&encoded, third); err != nil {
		t.Fatal(err)
	}
	reader := &countingReader{data: encoded.Bytes()}
	if _, err := sequence.Read(reader); !errors.Is(err, ErrHandshakeTooLarge) || reader.readBytes != 4 || sequence.Done() {
		t.Fatalf("aggregate read exceeded budget before rejection: %v bytes=%d", err, reader.readBytes)
	}
	if _, err := sequence.Read(reader); !errors.Is(err, ErrHandshakeMalformed) || reader.readBytes != 4 {
		t.Fatal("terminal read consumed more bytes")
	}
	failure := errors.New("stream failed")
	var failedWrite HandshakeSequence
	writer := &handshakeBadWriter{count: 2, err: failure}
	if err := failedWrite.Write(writer, handshakeFixture(HandshakeXXMsg1)); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if err := failedWrite.Write(io.Discard, handshakeFixture(HandshakeXXMsg2)); !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatal("partially written sequence resumed")
	}
	var eof HandshakeSequence
	if _, err := eof.Read(bytes.NewReader(nil)); err != io.EOF {
		t.Fatalf("sequence clean EOF = %v", err)
	}
	if err := eof.Write(io.Discard, handshakeFixture(HandshakeXXMsg1)); !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatal("aborted read sequence resumed")
	}
	var wrongFirst bytes.Buffer
	if err := WriteHandshake(&wrongFirst, handshakeFixture(HandshakeXXMsg2)); err != nil {
		t.Fatal(err)
	}
	var mismatch HandshakeSequence
	if _, err := mismatch.Read(&wrongFirst); !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatalf("decoded out-of-order = %v", err)
	}
	var terminal HandshakeSequence
	for kind := HandshakeXXMsg1; kind <= HandshakeXXMsg3; kind++ {
		if err := terminal.Write(io.Discard, handshakeFixture(kind)); err != nil {
			t.Fatal(err)
		}
	}
	untouched := &countingReader{data: []byte{0, 0, 0, 26}}
	if _, err := terminal.Read(untouched); !errors.Is(err, ErrHandshakeMalformed) || untouched.readBytes != 0 {
		t.Fatal("completed sequence consumed a fourth prefix")
	}
	var missing *HandshakeSequence
	if _, err := missing.Read(bytes.NewReader(nil)); !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatal("nil read sequence accepted")
	}
	if err := missing.Write(io.Discard, handshakeFixture(HandshakeXXMsg1)); !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatal("nil write sequence accepted")
	}
}

func TestHandshakeThreeRecordDuplexExchange(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	deadline := time.Now().Add(2 * time.Second)
	if err := left.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := right.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		var sequence HandshakeSequence
		for kind := HandshakeXXMsg1; kind <= HandshakeXXMsg3; kind++ {
			record := handshakeFixture(kind)
			record.Payload = []byte{byte(kind), 0xa5}
			if kind == HandshakeXXMsg2 {
				if err := sequence.Write(right, record); err != nil {
					result <- err
					return
				}
			} else {
				got, err := sequence.Read(right)
				if err != nil {
					result <- err
					return
				}
				if !reflect.DeepEqual(got, record) {
					result <- fmt.Errorf("peer changed record %d", kind)
					return
				}
			}
		}
		if !sequence.Done() {
			result <- errors.New("peer sequence incomplete")
			return
		}
		result <- nil
	}()
	var sequence HandshakeSequence
	for kind := HandshakeXXMsg1; kind <= HandshakeXXMsg3; kind++ {
		record := handshakeFixture(kind)
		record.Payload = []byte{byte(kind), 0xa5}
		if kind == HandshakeXXMsg2 {
			got, err := sequence.Read(left)
			if err != nil || !reflect.DeepEqual(got, record) {
				t.Fatalf("returned record changed: %#v %v", got, err)
			}
		} else {
			if err := sequence.Write(left, record); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := <-result; err != nil || !sequence.Done() {
		t.Fatalf("duplex sequence: %v done=%v", err, sequence.Done())
	}
}

type handshakeChunkReader struct {
	reader io.Reader
	chunk  int
}

func (r *handshakeChunkReader) Read(p []byte) (int, error) {
	if len(p) > r.chunk {
		p = p[:r.chunk]
	}
	return r.reader.Read(p)
}

type handshakeErrorReader struct{ err error }

func (r handshakeErrorReader) Read([]byte) (int, error) { return 0, r.err }

type handshakeShortWriter struct {
	bytes.Buffer
	limit int
}

func (w *handshakeShortWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.Buffer.Write(p)
}

type handshakeBadWriter struct {
	count int
	err   error
	calls int
}

func (w *handshakeBadWriter) Write([]byte) (int, error) { w.calls++; return w.count, w.err }
