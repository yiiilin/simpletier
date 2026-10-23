package flow

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// udpTarget is a real loopback UDP socket pair. The Delivery port writes the
// reassembled datagram with one WriteTo; the test reads it back with one
// ReadFrom. Nothing here synthesizes a completed datagram: the single read
// result is whatever the flow core reassembled and handed to Delivery.
type udpTarget struct {
	t    *testing.T
	recv net.PacketConn
	send net.PacketConn

	mu   sync.Mutex
	last Datagram
}

func newUDPTarget(t *testing.T) *udpTarget {
	t.Helper()
	recv, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target endpoint: %v", err)
	}
	send, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		recv.Close()
		t.Fatalf("listen source endpoint: %v", err)
	}
	// A 65,507-byte IPv4 UDP datagram needs receive room; loopback MTU 65,536
	// carries exactly 65,535 bytes of IP packet (20 IP + 8 UDP + 65,507).
	if udp, ok := recv.(*net.UDPConn); ok {
		_ = udp.SetReadBuffer(1 << 20)
	}
	if udp, ok := send.(*net.UDPConn); ok {
		_ = udp.SetWriteBuffer(1 << 20)
	}
	t.Cleanup(func() {
		recv.Close()
		send.Close()
	})
	return &udpTarget{t: t, recv: recv, send: send}
}

func (u *udpTarget) port() uint16 {
	return uint16(u.recv.LocalAddr().(*net.UDPAddr).Port)
}

func (u *udpTarget) DeliverDatagram(_ context.Context, datagram Datagram) error {
	written, err := u.send.WriteTo(datagram.Payload, u.recv.LocalAddr())
	if err != nil {
		return err
	}
	if written != len(datagram.Payload) {
		return fmt.Errorf("short UDP write: %d of %d bytes", written, len(datagram.Payload))
	}
	u.mu.Lock()
	u.last = datagram
	u.mu.Unlock()
	return nil
}

func (u *udpTarget) lastDatagram() Datagram {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.last
}

func (u *udpTarget) readOne(timeout time.Duration) []byte {
	u.t.Helper()
	if err := u.recv.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		u.t.Fatalf("set read deadline: %v", err)
	}
	buffer := make([]byte, 65536)
	n, _, err := u.recv.ReadFrom(buffer)
	if err != nil {
		u.t.Fatalf("read delivered datagram: %v", err)
	}
	return buffer[:n]
}

func (u *udpTarget) expectSilence(timeout time.Duration) {
	u.t.Helper()
	if err := u.recv.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		u.t.Fatalf("set read deadline: %v", err)
	}
	buffer := make([]byte, 65536)
	if n, _, err := u.recv.ReadFrom(buffer); err == nil {
		u.t.Fatalf("unexpected extra datagram of %d bytes", n)
	}
}

// TestRealUDPDeliveryPreservesOneMaxDatagram drives a real 65,507-byte IPv4
// UDP payload through two reordered fragments and one real UDP socket write,
// then reads one exact datagram back.
func TestRealUDPDeliveryPreservesOneMaxDatagram(t *testing.T) {
	target := newUDPTarget(t)
	p := newPair(t, &collectingDelivery{}, target)
	payload := patternedPayload(MaxDatagramPayload)

	association, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	datagram := OutboundDatagram{
		Source:      netipAddrPort(vipA, 40000),
		Destination: netipAddrPort(vipB, target.port()),
		Payload:     payload,
	}
	if err := association.Fragment(context.Background(), datagram); err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	requests := p.takeSentA()
	if len(requests) != 2 {
		t.Fatalf("framed %d fragments, want 2 for %d payload bytes", len(requests), len(payload))
	}
	if requests[0].FragmentIndex != 0 || requests[1].FragmentIndex != 1 {
		t.Fatalf("fragment indices %d/%d", requests[0].FragmentIndex, requests[1].FragmentIndex)
	}

	// Reordered on the wire: the second fragment arrives first.
	if err := p.feedToB(requests, 1, 0); err != nil {
		t.Fatalf("feedToB: %v", err)
	}

	got := target.readOne(5 * time.Second)
	if len(got) != MaxDatagramPayload {
		t.Fatalf("read %d bytes, want exactly %d", len(got), MaxDatagramPayload)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("reassembled real UDP datagram differs from the original payload")
	}
	if last := target.lastDatagram(); last.Destination.Port() != target.port() || last.Source != netipAddrPort(vipA, 40000) {
		t.Fatalf("delivery lost the real destination port/source peer: %+v", last)
	}
	// One datagram boundary: nothing else may follow.
	target.expectSilence(300 * time.Millisecond)
	if stats := p.b.Stats(); stats.DeliveredDatagrams != 1 || stats.DeliveredBytes != MaxDatagramPayload {
		t.Fatalf("receiver stats %+v", stats)
	}
}

// TestRealUDPEmptyDatagram confirms a legal 0-byte payload crosses the real
// socket as one empty datagram.
func TestRealUDPEmptyDatagram(t *testing.T) {
	target := newUDPTarget(t)
	p := newPair(t, &collectingDelivery{}, target)

	association, err := p.a.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	datagram := OutboundDatagram{
		Source:      netipAddrPort(vipA, 40000),
		Destination: netipAddrPort(vipB, target.port()),
		Payload:     []byte{},
	}
	if err := association.Fragment(context.Background(), datagram); err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	requests := p.takeSentA()
	if len(requests) != 1 || requests[0].FragmentCount != 1 {
		t.Fatalf("empty datagram framed as %+v", requests)
	}
	if err := p.feedToB(requests, 0); err != nil {
		t.Fatalf("feedToB: %v", err)
	}
	got := target.readOne(5 * time.Second)
	if len(got) != 0 {
		t.Fatalf("read %d bytes for an empty datagram", len(got))
	}
	target.expectSilence(300 * time.Millisecond)
}

// TestConcurrentReassemblyDeliversExactlyOnce exercises the manager lock, the
// per-association replay windows and the real UDP delivery path from several
// goroutines while Sweep and Stats run concurrently. Run with -race.
func TestConcurrentReassemblyDeliversExactlyOnce(t *testing.T) {
	target := newUDPTarget(t)
	p := newPair(t, &collectingDelivery{}, target)

	const count = 64
	type framed struct {
		requests []SendRequest
		order    []int
		payload  []byte
	}
	feeds := make([]framed, 0, count)
	for i := 0; i < count; i++ {
		var payload []byte
		if i%16 == 0 {
			payload = patternedPayload(MaxDatagramPayload)
		} else {
			payload = make([]byte, 64)
		}
		binary.BigEndian.PutUint64(payload[:8], uint64(i)+1)
		_, requests := p.sendA(payload, target.port())
		order := []int{0}
		if len(requests) == 2 {
			order = []int{1, 0}
		}
		feeds = append(feeds, framed{requests: requests, order: order, payload: payload})
	}

	received := make(chan []byte, count)
	readErr := make(chan error, 1)
	go func() {
		for i := 0; i < count; i++ {
			if err := target.recv.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
				readErr <- err
				close(received)
				return
			}
			buffer := make([]byte, 65536)
			n, _, err := target.recv.ReadFrom(buffer)
			if err != nil {
				readErr <- err
				close(received)
				return
			}
			received <- append([]byte(nil), buffer[:n]...)
		}
		close(received)
	}()

	stop := make(chan struct{})
	var sweeper sync.WaitGroup
	sweeper.Add(1)
	go func() {
		defer sweeper.Done()
		for {
			select {
			case <-stop:
				return
			default:
				p.b.Sweep()
				p.b.Stats()
				time.Sleep(time.Millisecond)
			}
		}
	}()

	feedErr := make(chan error, count)
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for i := worker; i < count; i += 8 {
				for _, index := range feeds[i].order {
					if err := p.b.Receive(context.Background(), p.envToB(), feeds[i].requests[index].Payload); err != nil {
						feedErr <- fmt.Errorf("datagram %d fragment %d: %w", i, index, err)
						return
					}
				}
			}
		}(worker)
	}
	workers.Wait()
	close(feedErr)
	for err := range feedErr {
		t.Fatalf("concurrent receive: %v", err)
	}
	close(stop)
	sweeper.Wait()

	seen := make(map[string]int, count)
	for payload := range received {
		seen[string(payload)]++
	}
	select {
	case err := <-readErr:
		t.Fatalf("real UDP reader: %v", err)
	default:
	}
	if len(seen) != count {
		t.Fatalf("delivered %d distinct datagrams, want %d", len(seen), count)
	}
	for i, feed := range feeds {
		if got := seen[string(feed.payload)]; got != 1 {
			t.Fatalf("datagram %d delivered %d times, want exactly 1", i, got)
		}
	}
	stats := p.b.Stats()
	if stats.DeliveredDatagrams != count {
		t.Fatalf("DeliveredDatagrams = %d, want %d", stats.DeliveredDatagrams, count)
	}
	if stats.Drops[DropDuplicate] != 0 || stats.Drops[DropConflict] != 0 {
		t.Fatalf("unexpected drops under concurrency: %+v", stats.Drops)
	}
	if stats.BytesHeld != 0 {
		t.Fatalf("reassembly reservations leaked: %d bytes", stats.BytesHeld)
	}
}

func netipAddrPort(ip netip.Addr, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(ip, port)
}
