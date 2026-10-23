package simpletier

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/path"
)

// TestPinnedDataPumpFollowsInstalledLinkNotSibling is the regression for the
// pinned-routing bug: a ready Path recorded one exact Link instance per hop, but
// egress looked up the adjacent pump by scanning the Network's pump map for the
// first Ready Link to the same peer on the same lane. With a second
// authenticated STREAM Link between the same two nodes the scan could select the
// sibling instance, so business frames of an already pinned Circuit left on a
// physical Link the Path never installed.
//
// The discriminator is deliberate: after a sibling STREAM Link is added while
// the pinned one is healthy, the pinned Link is closed. A correct exact-instance
// lookup then reports the Circuit's Session lost. A peer-based lookup silently
// re-routes the existing Circuit onto the sibling and keeps succeeding.
func TestPinnedDataPumpFollowsInstalledLinkNotSibling(t *testing.T) {
	target := newRelayTestNode(t, relayTargetIP, "")
	source := newRelayTestNode(t, relaySourceIP, relayCarrierURL(target))
	waitRelayLinks(t, target, 2, 30*time.Second)
	waitRelayLinks(t, source, 2, 30*time.Second)

	const address = relayTargetIP + ":19031"
	listener, err := target.Listen("tcp", address)
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 8)
	go func() {
		for {
			stream, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer stream.Close()
				accepted <- struct{}{}
				buf := make([]byte, 1)
				for {
					n, err := stream.Read(buf)
					if n > 0 {
						if _, werr := stream.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	stream := relayDialUntil(t, source, address, 5*time.Second, 30*time.Second)
	defer stream.Close()
	<-accepted
	pinnedEchoOnce(t, stream, 0x11)

	// The dial installed exactly one source-owned STREAM Path with one hop.
	source.streams.mu.Lock()
	var pinned *pathState
	for _, ps := range source.streams.pathsByScope {
		if ps.lane == path.LaneStream && ps.source && !ps.relay {
			pinned = ps
		}
	}
	source.streams.mu.Unlock()
	if pinned == nil {
		t.Fatal("no source-owned STREAM path was installed by the dial")
	}
	if len(pinned.links) != 1 {
		t.Fatalf("pinned STREAM path links = %d; want 1", len(pinned.links))
	}
	pinnedRef := pinned.links[0]

	// A second authenticated STREAM Link to the same peer on the same lane,
	// created exactly like the runtime's own dedicated data-lane loop does.
	sibling := admitSiblingStreamLink(t, source, target)
	defer sibling.Close()
	if sibling.Metadata().LaneID != laneStream || sibling.Metadata().LinkID == pinnedRef.ID {
		t.Fatalf("sibling STREAM link = %+v; want a distinct STREAM instance", sibling.Metadata())
	}

	// While the pinned Link is healthy the Circuit keeps working on it.
	pinnedEchoOnce(t, stream, 0x22)

	// Close exactly the Link the Path installed. Its sibling is still Ready, so
	// a peer-based lookup would keep the old Circuit alive on the wrong Link.
	source.mu.Lock()
	established := source.activeLinks[pinnedRef.ID]
	source.mu.Unlock()
	if established == nil {
		t.Fatalf("pinned Link %d is not active on the source", pinnedRef.ID)
	}
	if err := established.Close(); err != nil {
		t.Fatalf("close pinned Link: %v", err)
	}

	if err := stream.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := stream.Write([]byte{0x33}); err == nil {
		t.Fatal("Circuit kept writing after its pinned Link closed: egress migrated onto a sibling Link")
	}

	// A fresh Dial may legitimately establish a new Path on the sibling Link.
	fresh := relayDialUntil(t, source, address, 5*time.Second, 30*time.Second)
	defer fresh.Close()
	pinnedEchoOnce(t, fresh, 0x44)
}

// pinnedEchoOnce writes one marker byte and requires the same byte back.
func pinnedEchoOnce(t *testing.T, stream Stream, marker byte) {
	t.Helper()
	if err := stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := stream.Write([]byte{marker}); err != nil {
		t.Fatalf("write 0x%02x: %v", marker, err)
	}
	var got [1]byte
	if _, err := io.ReadFull(stream, got[:]); err != nil {
		t.Fatalf("read echo 0x%02x: %v", marker, err)
	}
	if got[0] != marker {
		t.Fatalf("echo = 0x%02x; want 0x%02x", got[0], marker)
	}
}

// admitSiblingStreamLink opens one extra authenticated STREAM (lane 2) Link
// from source to an already connected target, using the same admission path as
// the runtime's dedicated data-lane loop: dial the target carrier, then admit as
// the STREAM initiator with the exact CONTROL peer static key pinned.
//
// The public AttachConnection entry point can express this pin
// (AttachOptions.Control), but only for a CONTROL handle this Network returned
// from AttachConnection, and this test's CONTROL Link was established by the
// built-in carrier, not by that entry point. The test therefore uses the
// in-package admission seam the runtime itself uses.
func admitSiblingStreamLink(t *testing.T, source, target *network) *link.Link {
	t.Helper()
	source.mu.Lock()
	var control *link.Link
	for _, established := range source.activeLinks {
		if established.Metadata().LaneID == laneControl && established.Ready() {
			control = established
			break
		}
	}
	source.mu.Unlock()
	if control == nil {
		t.Fatal("source has no active CONTROL link to pin the sibling STREAM link against")
	}
	if len(target.carrierListeners) == 0 {
		t.Fatal("target has no carrier listener to dial")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target.carrierListeners[0].Addr().String())
	if err != nil {
		t.Fatalf("dial target carrier for sibling STREAM link: %v", err)
	}
	admitted, err := source.admitLink(ctx, newCountingConnection(conn, "tcp"), ConnectionInfo{Type: "tcp"}, linkAdmission{
		role:               LinkRoleInitiator,
		lane:               laneStream,
		expectedPeerStatic: control.PeerStatic(),
		hasExpectedPeer:    true,
	})
	if err != nil {
		t.Fatalf("admit sibling STREAM link: %v", err)
	}
	return admitted
}
