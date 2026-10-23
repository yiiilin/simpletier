package simpletier

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/security"
)

func quotaTCPAdmission(t *testing.T, initiator, receiver *network, connectionType string) (*link.Link, error, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	receiver.workers.Add(1)
	go func() {
		defer receiver.workers.Done()
		raw, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		conn, err := NewConnection(raw, ConnectionInfo{Type: "tcp"})
		if err != nil {
			_ = raw.Close()
			accepted <- err
			return
		}
		accepted <- receiver.admitConnection(conn, false)
	}()

	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := NewConnection(raw, ConnectionInfo{Type: connectionType})
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	established, initiatorErr := initiator.admitConnectionLink(conn, true)
	select {
	case receiverErr := <-accepted:
		return established, initiatorErr, receiverErr
	case <-time.After(7 * time.Second):
		t.Fatal("receiver admission did not finish")
		return nil, initiatorErr, context.DeadlineExceeded
	}
}

func manualQuotaTCPAdmission(t *testing.T, peerNetwork, receiver *network, connectionType string, linkID uint64) (net.Conn, uint64, error, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	receiver.workers.Add(1)
	go func() {
		defer receiver.workers.Done()
		raw, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		conn, err := NewConnection(raw, ConnectionInfo{Type: connectionType})
		if err != nil {
			_ = raw.Close()
			accepted <- err
			return
		}
		accepted <- receiver.admitConnection(conn, false)
	}()

	stateDir, err := peerNetwork.identityStore.StateDir()
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := security.NextLinkEpoch(stateDir, peerNetwork.networkContext.ID(), 0)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := peerNetwork.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := NewConnection(raw, ConnectionInfo{Type: connectionType})
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, handshakeErr := link.Handshake(ctx, conn, link.LinkConfig{
		Descriptor:             peerNetwork.networkContext.Descriptor(),
		NetworkID:              peerNetwork.networkContext.WireID(),
		PSK:                    peerNetwork.networkPSK,
		Identity:               identity,
		Initiator:              true,
		LinkID:                 linkID,
		LinkEpoch:              epoch,
		Generation:             uint32(linkID),
		CapabilityVersion:      uint16(link.CapabilityVersion),
		CapabilityMask:         link.RequiredCapabilityMask,
		RequiredCapabilityMask: link.RequiredCapabilityMask,
	})
	select {
	case receiverErr := <-accepted:
		return raw, epoch, handshakeErr, receiverErr
	case <-time.After(6 * time.Second):
		t.Fatal("receiver admission did not finish")
		return raw, epoch, handshakeErr, context.DeadlineExceeded
	}
}

func quotaPeerLinks(n *network, peer [16]byte) []*link.Link {
	n.mu.Lock()
	defer n.mu.Unlock()
	links := make([]*link.Link, 0, maxActiveLinksPerPeer)
	for _, established := range n.activeLinks {
		if established.PeerNodeID() == peer {
			links = append(links, established)
		}
	}
	return links
}

func waitQuotaPeerLinks(t *testing.T, n *network, peer [16]byte, count int) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		got := len(quotaPeerLinks(n, peer))
		if got == count {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("active Links for peer = %d, want %d", got, count)
		}
	}
}

func quotaReceiverEpochFloor(t *testing.T, n *network, peer [16]byte) uint64 {
	t.Helper()
	scope, err := n.identityStore.StateDir()
	if err != nil {
		t.Fatal(err)
	}
	epoch, _, ok := security.ReceiverFloorForTest(scope, n.networkContext.ID(), peer, laneControl)
	if !ok {
		t.Fatal("receiver floor was not recorded for this Link")
	}
	return epoch
}

func TestPerPeerActiveLinkQuotaRejectsSeventhAndReleasesSlot(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	a := admissionNetwork(t, token)
	b := admissionNetwork(t, token)
	identityA, err := a.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	identityB, err := b.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if a.networkContext.ID() != b.networkContext.ID() {
		t.Fatal("test peers do not share a full NetworkContext")
	}

	opened := make([]*link.Link, 0, 5)
	types := []string{"tcp", "custom", "websocket", "tcp", "custom"}
	for index, connectionType := range types {
		established, senderErr, receiverErr := quotaTCPAdmission(t, b, a, connectionType)
		if senderErr != nil || receiverErr != nil {
			t.Fatalf("B -> A Link %d: sender=%v receiver=%v", index, senderErr, receiverErr)
		}
		opened = append(opened, established)
	}

	// Add a sixth incoming Link from A without publishing it in A's local registry.
	// This leaves room for A's next real initiator attempt, so the receiver's
	// ErrResource rejection is observed as a failed correlated PING/PONG.
	remote, manualEpoch, handshakeErr, receiverErr := manualQuotaTCPAdmission(t, a, b, "websocket", 0xa006)
	if handshakeErr != nil || receiverErr != nil {
		t.Fatalf("manual A -> B Link: handshake=%v receiver=%v", handshakeErr, receiverErr)
	}
	t.Cleanup(func() { _ = remote.Close() })

	peerA, peerB := identityA.NodeID, identityB.NodeID
	waitQuotaPeerLinks(t, a, peerB, 5)
	waitQuotaPeerLinks(t, b, peerA, 6)
	if got := quotaReceiverEpochFloor(t, b, peerA); got != manualEpoch {
		t.Fatalf("receiver floor after sixth admission = %d, want %d", got, manualEpoch)
	}
	seenTypes := make(map[string]bool)
	for _, established := range quotaPeerLinks(b, peerA) {
		if !established.Ready() {
			t.Fatal("an admitted healthy Link was not Ready")
		}
		seenTypes[established.ConnectionType()] = true
	}
	for _, connectionType := range []string{"tcp", "custom", "websocket"} {
		if !seenTypes[connectionType] {
			t.Fatalf("peer Links did not preserve independent %q Type metadata", connectionType)
		}
	}

	// All physical sockets below are real loopback TCP; Type remains metadata.
	if _, senderErr, receiverErr := quotaTCPAdmission(t, a, b, "custom"); senderErr == nil || !errors.Is(receiverErr, ErrResource) || !errors.Is(senderErr, ErrLinkDown) {
		t.Fatalf("seventh admission: sender=%v receiver=%v, want failed correlated PONG and ErrResource", senderErr, receiverErr)
	}
	waitQuotaPeerLinks(t, a, peerB, 5)
	waitQuotaPeerLinks(t, b, peerA, 6)
	if got := quotaReceiverEpochFloor(t, b, peerA); got != manualEpoch+1 {
		t.Fatalf("receiver floor after quota rejection = %d, want %d", got, manualEpoch+1)
	}
	for _, established := range opened {
		if !established.Ready() {
			t.Fatal("quota rejection drained a previously healthy Link")
		}
	}

	var retired *link.Link
	for _, established := range quotaPeerLinks(b, peerA) {
		if established.Metadata().LinkID == 0xa006 {
			retired = established
			break
		}
	}
	if retired == nil {
		t.Fatal("sixth authenticated Link is missing from the receiver registry")
	}
	if err := retired.Close(); err != nil {
		t.Fatal(err)
	}
	waitQuotaPeerLinks(t, b, peerA, 5)

	replacement, senderErr, receiverErr := quotaTCPAdmission(t, a, b, "custom")
	if senderErr != nil || receiverErr != nil {
		t.Fatalf("fresh Link after slot release: sender=%v receiver=%v", senderErr, receiverErr)
	}
	if replacement.Metadata().LinkID == retired.Metadata().LinkID || replacement.Metadata().LinkEpoch <= manualEpoch {
		t.Fatal("replacement did not use a fresh LinkID and higher epoch")
	}
	waitQuotaPeerLinks(t, a, peerB, 6)
	waitQuotaPeerLinks(t, b, peerA, 6)
	if got := quotaReceiverEpochFloor(t, b, peerA); got != replacement.Metadata().LinkEpoch {
		t.Fatalf("receiver floor after replacement = %d, want %d", got, replacement.Metadata().LinkEpoch)
	}
	for _, established := range opened {
		if !established.Ready() {
			t.Fatal("higher receiver floor retired a healthy different LinkID")
		}
	}
}

type quotaCandidate struct {
	link   *link.Link
	pump   *controlPump
	remote net.Conn
	linkID uint64
	err    error
}

// authenticatedQuotaCandidates creates real loopback TCP Noise/CAPABILITY
// results, commits receiver floors in epoch order, then returns candidates for
// concurrent calls to the production registry gate.
func authenticatedQuotaCandidates(t *testing.T, n *network, count int, firstEpoch uint64) []*quotaCandidate {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	localIdentity, err := n.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	peerIdentity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	type handshakeResult struct {
		conn   net.Conn
		result link.LinkResult
		err    error
	}
	accepted := make(chan handshakeResult, count*2)
	var serverWG sync.WaitGroup
	go func() {
		for range count {
			conn, err := listener.Accept()
			if err != nil {
				accepted <- handshakeResult{err: err}
				return
			}
			serverWG.Add(1)
			go func(conn net.Conn) {
				defer serverWG.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				result, err := link.Handshake(ctx, conn, link.LinkConfig{
					Descriptor:             n.networkContext.Descriptor(),
					NetworkID:              n.networkContext.WireID(),
					PSK:                    n.networkPSK,
					Identity:               localIdentity,
					CapabilityVersion:      uint16(link.CapabilityVersion),
					CapabilityMask:         link.RequiredCapabilityMask,
					RequiredCapabilityMask: link.RequiredCapabilityMask,
				})
				accepted <- handshakeResult{conn: conn, result: result, err: err}
			}(conn)
		}
		serverWG.Wait()
	}()

	candidates := make([]*quotaCandidate, count)
	remoteConns := make([]net.Conn, count)
	for index := range count {
		index := index
		go func() {
			conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
			if err != nil {
				accepted <- handshakeResult{err: err}
				return
			}
			remoteConns[index] = conn
			linkID := uint64(0x70000000 + index + 1)
			epoch := firstEpoch + uint64(index)
			generation := uint32(0x7000 + index + 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = link.Handshake(ctx, conn, link.LinkConfig{
				Descriptor:             n.networkContext.Descriptor(),
				NetworkID:              n.networkContext.WireID(),
				PSK:                    n.networkPSK,
				Identity:               peerIdentity,
				Initiator:              true,
				LinkID:                 linkID,
				LinkEpoch:              epoch,
				Generation:             generation,
				CapabilityVersion:      uint16(link.CapabilityVersion),
				CapabilityMask:         link.RequiredCapabilityMask,
				RequiredCapabilityMask: link.RequiredCapabilityMask,
			})
			accepted <- handshakeResult{result: link.LinkResult{LinkID: linkID, LinkEpoch: epoch}, err: err}
		}()
	}

	serverResults := make([]handshakeResult, 0, count)
	clientResults := 0
	for len(serverResults) < count || clientResults < count {
		result := <-accepted
		if result.err != nil {
			t.Fatalf("Noise/CAPABILITY handshake: %v", result.err)
		}
		if result.conn == nil {
			clientResults++
			continue
		}
		serverResults = append(serverResults, result)
	}
	t.Cleanup(func() {
		for _, conn := range remoteConns {
			if conn != nil {
				_ = conn.Close()
			}
		}
	})

	sort.Slice(serverResults, func(i, j int) bool {
		return serverResults[i].result.LinkEpoch < serverResults[j].result.LinkEpoch
	})
	stateDir, err := n.identityStore.StateDir()
	if err != nil {
		t.Fatal(err)
	}
	for index, result := range serverResults {
		resultHash := sha256.Sum256(result.result.ChannelBinding)
		if err := security.AcceptLinkEpoch(
			stateDir,
			n.networkContext.ID(),
			result.result.PeerNodeID,
			result.result.LaneID,
			result.result.LinkID,
			result.result.LinkEpoch,
			resultHash,
		); err != nil {
			t.Fatalf("commit receiver floor for Link %d: %v", result.result.LinkID, err)
		}
		connectionType := []string{"tcp", "custom", "websocket"}[index%3]
		owned, err := NewConnection(result.conn, ConnectionInfo{Type: connectionType})
		if err != nil {
			t.Fatal(err)
		}
		established, err := link.NewEstablishedLink(owned, result.result, connectionType)
		if err != nil {
			t.Fatal(err)
		}
		pump, err := n.newControlPump(established, false)
		if err != nil {
			_ = established.Close()
			t.Fatal(err)
		}
		candidates[index] = &quotaCandidate{link: established, pump: pump, remote: remoteConns[index], linkID: result.result.LinkID}
	}
	return candidates
}

func TestConcurrentAuthenticatedPeerLinksRespectQuotaAndCloseRace(t *testing.T) {
	n := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	candidates := authenticatedQuotaCandidates(t, n, 16, 1)
	peer := candidates[0].link.PeerNodeID()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, candidate := range candidates {
		wg.Add(1)
		go func(candidate *quotaCandidate) {
			defer wg.Done()
			<-start
			candidate.err = n.registerAuthenticatedLink(candidate.link, candidate.pump, false)
		}(candidate)
	}
	close(start)
	wg.Wait()

	registered, rejected := 0, 0
	for _, candidate := range candidates {
		switch {
		case candidate.err == nil:
			registered++
		case errors.Is(candidate.err, ErrResource):
			rejected++
		default:
			t.Errorf("Link %d registration error = %v, want success or ErrResource", candidate.linkID, candidate.err)
		}
	}
	if registered != 6 || rejected != 10 {
		t.Fatalf("concurrent registration: admitted=%d rejected=%d, want 6/10", registered, rejected)
	}
	if got := len(quotaPeerLinks(n, peer)); got != 6 {
		t.Fatalf("concurrently registered live Links = %d, want 6", got)
	}
	for _, candidate := range candidates {
		if candidate.err == nil {
			if !candidate.link.Ready() {
				t.Fatal("a concurrently admitted Link is not Ready")
			}
			continue
		}
		if err := candidate.remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var one [1]byte
		if _, err := candidate.remote.Read(one[:]); err == nil {
			t.Fatalf("rejected Link %d stayed open", candidate.linkID)
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatalf("rejected Link %d did not close promptly", candidate.linkID)
		}
	}

	closing := authenticatedQuotaCandidates(t, n, 4, 17)
	n.mu.Lock()
	startCloseRace := make(chan struct{})
	registrationReady := make(chan struct{}, len(closing))
	for _, candidate := range closing {
		wg.Add(1)
		go func(candidate *quotaCandidate) {
			defer wg.Done()
			<-startCloseRace
			registrationReady <- struct{}{}
			candidate.err = n.registerAuthenticatedLink(candidate.link, candidate.pump, false)
		}(candidate)
	}
	close(startCloseRace)
	for range closing {
		<-registrationReady
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- n.Close() }()
	select {
	case <-n.ctx.Done():
	case <-time.After(time.Second):
		n.mu.Unlock()
		wg.Wait()
		t.Fatal("Network.Close did not cancel quota competition")
	}
	n.mu.Unlock()
	wg.Wait()
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	for _, candidate := range closing {
		if !errors.Is(candidate.err, ErrClosed) {
			t.Errorf("registration during Network.Close = %v, want ErrClosed", candidate.err)
		}
		select {
		case <-candidate.link.Done():
		default:
			t.Errorf("unregistered Link %d was not closed", candidate.linkID)
		}
	}
	n.mu.Lock()
	remaining := len(n.activeLinks)
	n.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("Network.Close retained %d active Links", remaining)
	}
	for _, candidate := range candidates {
		select {
		case <-candidate.link.Done():
		default:
			t.Errorf("Network.Close left registered Link %d open", candidate.linkID)
		}
	}
}

func TestPeerQuotaIsolationAcrossPeersAndFullContexts(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	stateDir := t.TempDir() + "/shared"
	first := admissionNetworkAt(t, stateDir, func(cfg *Config) { cfg.Network.Token = token })
	second := admissionNetworkAt(t, stateDir, func(cfg *Config) {
		cfg.Network.Token = token
		cfg.Network.CIDR = "10.21.0.0/24"
		cfg.Options.FixedIP = "10.21.0.7"
	})
	if first.networkContext.ID() == second.networkContext.ID() {
		t.Fatal("test Networks share the same full ContextID")
	}
	peer, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 6; index++ {
		_ = dialManualInitiator(t, first, peer, uint64(0x8100+index), uint64(index+1), uint32(0x8100+index))
	}
	waitQuotaPeerLinks(t, first, peer.NodeID, 6)

	otherPeer, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_ = dialManualInitiator(t, first, otherPeer, 0x8201, 1, 0x8201)
	waitQuotaPeerLinks(t, first, otherPeer.NodeID, 1)
	if got := len(quotaPeerLinks(first, peer.NodeID)); got != 6 {
		t.Fatalf("another peer changed the saturated peer count to %d", got)
	}

	for index := 0; index < 6; index++ {
		_ = dialManualInitiator(t, second, peer, uint64(0x8300+index), uint64(index+1), uint32(0x8300+index))
	}
	waitQuotaPeerLinks(t, second, peer.NodeID, 6)
	if got := len(quotaPeerLinks(first, peer.NodeID)); got != 6 {
		t.Fatalf("admissions in another full Context changed first-context count to %d", got)
	}
	if got := len(quotaPeerLinks(second, peer.NodeID)); got != 6 {
		t.Fatalf("same peer did not fill independent context quota: %d", got)
	}
}

func TestUnauthenticatedPeerDoesNotConsumeActiveQuota(t *testing.T) {
	server := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	wrong := admissionNetwork(t, "a different secret")
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", server.carrierListeners[0].Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = link.Handshake(ctx, conn, link.LinkConfig{
		Descriptor:             server.networkContext.Descriptor(),
		NetworkID:              server.networkContext.WireID(),
		PSK:                    wrong.networkPSK,
		Identity:               identity,
		Initiator:              true,
		LinkID:                 0x9001,
		LinkEpoch:              1,
		Generation:             0x9001,
		CapabilityVersion:      uint16(link.CapabilityVersion),
		CapabilityMask:         link.RequiredCapabilityMask,
		RequiredCapabilityMask: link.RequiredCapabilityMask,
	})
	_ = conn.Close()
	if err == nil {
		t.Fatal("wrong-PSK peer authenticated")
	}
	if got := len(quotaPeerLinks(server, identity.NodeID)); got != 0 {
		t.Fatalf("unauthenticated claimed identity registered %d active Links", got)
	}
	_ = dialManualInitiator(t, server, identity, 0x9002, 1, 0x9002)
	waitQuotaPeerLinks(t, server, identity.NodeID, 1)
}
