package link

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func testLinkResult() LinkResult {
	return LinkResult{
		PeerStatic:        [32]byte{1},
		PeerNodeID:        [16]byte{2},
		LocalNodeID:       [16]byte{3},
		TxRoot:            [32]byte{4},
		RxRoot:            [32]byte{5},
		ChannelBinding:    []byte("binding"),
		CapabilityVersion: uint16(CapabilityVersion),
		CapabilityMask:    RequiredCapabilityMask,
		LinkID:            7,
		LinkEpoch:         8,
		Generation:        9,
		LaneID:            2,
	}
}

func TestNewEstablishedLinkCopiesMetadataAndOwnsOnSuccess(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	result := testLinkResult()
	link, err := NewEstablishedLink(left, result, "websocket")
	if err != nil {
		t.Fatal(err)
	}
	result.ChannelBinding[0] = 'X'
	metadata := link.Metadata()
	metadata.ChannelBinding[0] = 'Y'
	if !bytes.Equal(link.Metadata().ChannelBinding, []byte("binding")) {
		t.Fatal("Link metadata aliases caller or returned slices")
	}
	if link.ConnectionType() != "websocket" || !link.Ready() || link.PeerNodeID() != result.PeerNodeID || link.LocalNodeID() != result.LocalNodeID || link.PeerStatic() != result.PeerStatic {
		t.Fatal("Link metadata accessors changed authenticated result")
	}
	if err := link.Close(); err != nil {
		t.Fatal(err)
	}
	if link.Ready() {
		t.Fatal("Ready remained true after Close")
	}
	select {
	case <-link.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not close after Link.Close")
	}
	if _, err := link.Write([]byte("x")); err == nil {
		t.Fatal("Write after Close succeeded")
	}
}

func TestEstablishedLinkCloseUnblocksReadAndIsExactlyOnce(t *testing.T) {
	left, right := net.Pipe()
	stream := &countedCloseStream{ReadWriteCloser: left}
	link, err := NewEstablishedLink(stream, testLinkResult(), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		var data [1]byte
		_, err := link.Read(data[:])
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("read returned before Close: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	for range 4 {
		go func() { _ = link.Close() }()
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked read succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock read")
	}
	_ = right.Close()
	if stream.closes.Load() != 1 {
		t.Fatalf("underlying Close count = %d; want 1", stream.closes.Load())
	}
	select {
	case <-link.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not close")
	}
}

func TestNewEstablishedLinkRejectsWithoutTakingOwnership(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	bad := testLinkResult()
	bad.ChannelBinding = nil
	if _, err := NewEstablishedLink(left, bad, "tcp"); !errors.Is(err, ErrInvalidEstablishedLink) {
		t.Fatalf("invalid result error = %v", err)
	}
	readProbe := make(chan error, 1)
	go func() {
		var probe [11]byte
		_, err := io.ReadFull(right, probe[:])
		readProbe <- err
	}()
	if _, err := left.Write([]byte("still-owned")); err != nil {
		t.Fatalf("rejected stream was closed: %v", err)
	}
	if err := <-readProbe; err != nil {
		t.Fatalf("ownership probe read failed: %v", err)
	}
	if _, err := NewEstablishedLink((*countedCloseStream)(nil), testLinkResult(), "tcp"); !errors.Is(err, ErrInvalidEstablishedLink) {
		t.Fatalf("typed nil stream error = %v", err)
	}
	if _, err := NewEstablishedLink(left, testLinkResult(), ""); !errors.Is(err, ErrInvalidEstablishedLink) {
		t.Fatalf("empty type error = %v", err)
	}
	for _, kind := range []string{"a\x00b", string([]byte{0xff})} {
		if _, err := NewEstablishedLink(left, testLinkResult(), kind); !errors.Is(err, ErrInvalidEstablishedLink) {
			t.Fatalf("invalid type %q error = %v", kind, err)
		}
	}
	if _, err := NewEstablishedLink(left, testLinkResult(), "tcp\x00secret"); !errors.Is(err, ErrInvalidEstablishedLink) {
		t.Fatal("NUL-containing transport type accepted")
	}
}

type countedCloseStream struct {
	io.ReadWriteCloser
	closes atomic.Int32
}

func (s *countedCloseStream) Close() error {
	s.closes.Add(1)
	return s.ReadWriteCloser.Close()
}
