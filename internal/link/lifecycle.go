package link

import (
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

var ErrInvalidEstablishedLink = errors.New("invalid established link")

// Link is an authenticated Link lifecycle wrapper. It owns the stream after
// successful construction; it does not publish topology or run frame I/O.
type Link struct {
	stream         io.ReadWriteCloser
	result         LinkResult
	connectionType string
	closeOnce      sync.Once
	closeErr       error
	closed         atomic.Bool
	done           chan struct{}
}

// NewEstablishedLink transfers stream ownership only on success. The caller
// must have completed Handshake, including mutual capability verification.
// Rejection leaves the stream caller-owned. Close is idempotent and unblocks
// concurrent I/O by closing the owned stream without taking an I/O lock.
func NewEstablishedLink(stream io.ReadWriteCloser, result LinkResult, connectionType string) (*Link, error) {
	if nilValue(stream) || !validLinkResult(result) || connectionType == "" || !utf8.ValidString(connectionType) || strings.IndexByte(connectionType, 0) >= 0 {
		return nil, ErrInvalidEstablishedLink
	}
	return &Link{
		stream:         stream,
		result:         cloneLinkResult(result),
		connectionType: connectionType,
		done:           make(chan struct{}),
	}, nil
}

func (l *Link) Read(p []byte) (int, error) {
	if l == nil || l.stream == nil {
		return 0, net.ErrClosed
	}
	return l.stream.Read(p)
}

func (l *Link) Write(p []byte) (int, error) {
	if l == nil || l.stream == nil {
		return 0, net.ErrClosed
	}
	return l.stream.Write(p)
}

func (l *Link) Ready() bool { return l != nil && l.stream != nil && !l.closed.Load() }

func (l *Link) Done() <-chan struct{} {
	if l == nil {
		return nil
	}
	return l.done
}

func (l *Link) PeerNodeID() [16]byte {
	if l == nil {
		return [16]byte{}
	}
	return l.result.PeerNodeID
}

func (l *Link) LocalNodeID() [16]byte {
	if l == nil {
		return [16]byte{}
	}
	return l.result.LocalNodeID
}

func (l *Link) PeerStatic() [32]byte {
	if l == nil {
		return [32]byte{}
	}
	return l.result.PeerStatic
}

func (l *Link) ConnectionType() string {
	if l == nil {
		return ""
	}
	return l.connectionType
}

func (l *Link) Metadata() LinkResult {
	if l == nil {
		return LinkResult{}
	}
	return cloneLinkResult(l.result)
}

func (l *Link) Close() error {
	if l == nil || l.stream == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		l.closeErr = l.stream.Close()
		close(l.done)
	})
	return l.closeErr
}

func validLinkResult(result LinkResult) bool {
	if result.LinkID == 0 || result.LinkEpoch == 0 || result.Generation == 0 || result.LaneID > 2 {
		return false
	}
	if zeroKey(result.TxRoot) || zeroKey(result.RxRoot) || result.TxRoot == result.RxRoot {
		return false
	}
	if result.PeerNodeID == ([16]byte{}) || result.LocalNodeID == ([16]byte{}) || result.PeerStatic == ([32]byte{}) || len(result.ChannelBinding) == 0 {
		return false
	}
	return true
}

func cloneLinkResult(result LinkResult) LinkResult {
	result.ChannelBinding = append([]byte(nil), result.ChannelBinding...)
	return result
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
