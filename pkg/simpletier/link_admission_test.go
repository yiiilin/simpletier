package simpletier

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/security"
)

func admissionNetwork(t *testing.T, token string) *network {
	t.Helper()
	cfg := validConfig()
	url, _ := freeTCPListenAddress(t)
	cfg.Listen, cfg.Upstreams = []string{url}, nil
	cfg.Network.Token = token
	// These tests exercise admission bounds, so they opt into the guard explicitly.
	enabled := true
	cfg.Options.RateLimit = &enabled
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := handle.Close(); err != nil {
			t.Error(err)
		}
	})
	return handle.(*network)
}

func waitAdmissionLinks(t *testing.T, n *network, count int) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		n.mu.Lock()
		got := len(n.activeLinks)
		n.mu.Unlock()
		if got == count {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("active Links=%d, want %d", got, count)
		}
	}
}

func TestNetworkAdmissionPreparedWireLocator(t *testing.T) {
	n := admissionNetwork(t, "locator-fixture-token")
	name := n.normalized.config.Network.Name
	cidr := n.normalized.config.Network.CIDR
	legacy := sha256.Sum256([]byte("simpletier-v1\x00" + name + "\x00" + cidr))
	want := binary.BigEndian.Uint64(legacy[:8])
	if n.networkContext.WireID() != want || n.normalized.networkContext.WireID() != want {
		t.Fatal("prepared locator does not match the declared legacy network bytes")
	}
	full := sha256.Sum256(n.networkContext.Descriptor())
	if n.networkContext.ID() != full {
		t.Fatal("wire locator replaced full ContextID state identity")
	}
	rotated, err := security.NewNetworkContext(name, cidr)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.WireID() != want || rotated.ID() != full {
		t.Fatal("network locator/context is not stable independently of token")
	}
}

func TestAuthenticatedLinkAdmissionOverExistingConnections(t *testing.T) {
	a := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	b := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	// Canonical IdentityStore path, not the original possibly-empty SDK option,
	// is the persistence source for both sender and receiver epochs.
	left, right := net.Pipe()
	client, err := NewConnection(left, ConnectionInfo{Type: "host-stream"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewConnection(right, ConnectionInfo{Type: "host-stream"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()
	results := make(chan error, 2)
	go func() { results <- a.admitConnection(client, true) }()
	go func() { results <- b.admitConnection(server, false) }()
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("admission did not finish")
		}
	}
	waitAdmissionLinks(t, a, 1)
	waitAdmissionLinks(t, b, 1)
	identityA, err := a.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	identityB, err := b.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	var active *link.Link
	for _, active = range a.activeLinks {
	}
	a.mu.Unlock()
	b.mu.Lock()
	var remote *link.Link
	for _, remote = range b.activeLinks {
	}
	b.mu.Unlock()
	if active.PeerNodeID() != identityB.NodeID || remote.PeerNodeID() != identityA.NodeID || !active.Ready() || active.ConnectionType() != "host-stream" {
		t.Fatal("authenticated peer identity or connection metadata missing")
	}
	if active.Metadata().LinkID != remote.Metadata().LinkID || active.Metadata().LinkEpoch != 1 || active.Metadata().LaneID != 0 {
		t.Fatal("CONTROL identity/epoch was not shared")
	}
	if _, err := a.DialContext(context.Background(), "tcp", "10.20.0.8:8080"); !errors.Is(err, ErrNoRoute) {
		t.Fatal("Link alone became a route", err)
	}
	if err := active.Close(); err != nil {
		t.Fatal(err)
	}
	waitAdmissionLinks(t, a, 0)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-remote.Done():
	case <-time.After(time.Second):
		t.Fatal("Network.Close did not close its owned Link")
	}
}

func TestAuthenticatedNetworkTCPAndTargetOccupancy(t *testing.T) {
	server := admissionNetwork(t, "0123456789abcdef0123456789abcdef")
	address := server.carrierListeners[0].Addr().String()
	cfg := validConfig()
	clientURL, _ := freeTCPListenAddress(t)
	cfg.Listen = []string{clientURL}
	cfg.Upstreams = []string{"tcp://" + address}
	cfg.Network.Token = "0123456789abcdef0123456789abcdef"
	// These tests exercise admission bounds, so they opt into the guard explicitly.
	enabled := true
	cfg.Options.RateLimit = &enabled
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	client := handle.(*network)
	waitAdmissionLinks(t, client, 3)
	waitAdmissionLinks(t, server, 3)
	// One healthy CONTROL adjacency keeps exactly one dedicated STREAM lane and
	// one dedicated PACKET lane (packet lanes are established for every
	// adjacency in this default-relay network); the next retry tick must not dial
	// a fourth Link for the same target.
	select {
	case <-time.After(1200 * time.Millisecond):
	case <-client.Done():
		t.Fatal("healthy client closed")
	}
	client.mu.Lock()
	count := len(client.activeLinks)
	var owned *link.Link
	for _, owned = range client.activeLinks {
	}
	client.mu.Unlock()
	server.mu.Lock()
	peerCount := len(server.activeLinks)
	server.mu.Unlock()
	if count != 3 || peerCount != 3 {
		t.Fatalf("healthy target redialled: %d/%d", count, peerCount)
	}
	// Real TCP admission returns only after the initiator's correlated PONG
	// proved the responder durably committed its receiver floor.
	if owned == nil || !owned.Ready() {
		t.Fatal("confirmed initiator admission was not Ready")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-owned.Done():
	case <-time.After(time.Second):
		t.Fatal("Network.Close removed its Link without closing it")
	}
	client.mu.Lock()
	count = len(client.activeLinks)
	client.mu.Unlock()
	if count != 0 {
		t.Fatal("closed Network retained Links")
	}
}

func TestAuthenticatedLinkAdmissionRejectsWrongPSK(t *testing.T) {
	a := admissionNetwork(t, "correct-secret-fixture")
	b := admissionNetwork(t, "wrong-secret-fixture")
	left, right := net.Pipe()
	client, _ := NewConnection(left, ConnectionInfo{Type: "host"})
	server, _ := NewConnection(right, ConnectionInfo{Type: "host"})
	defer client.Close()
	defer server.Close()
	results := make(chan error, 2)
	go func() { results <- a.admitConnection(client, true) }()
	go func() { results <- b.admitConnection(server, false) }()
	for range 2 {
		select {
		case err := <-results:
			if err == nil {
				t.Fatal("wrong token admitted")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("failed handshake did not close peer")
		}
	}
	a.mu.Lock()
	acount := len(a.activeLinks)
	a.mu.Unlock()
	b.mu.Lock()
	bcount := len(b.activeLinks)
	b.mu.Unlock()
	if acount != 0 || bcount != 0 {
		t.Fatal("failed auth registered Link")
	}
}

func TestNetworkCloseCancelsPendingGenericAdmission(t *testing.T) {
	n := admissionNetwork(t, "fixture-secret")
	left, right := net.Pipe()
	defer right.Close()
	conn, _ := NewConnection(left, ConnectionInfo{Type: "generic"})
	defer conn.Close()
	result := make(chan error, 1)
	started := make(chan struct{})
	n.workers.Add(1)
	go func() { defer n.workers.Done(); close(started); result <- n.admitConnection(conn, false) }()
	<-started
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled admission succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("generic stream admission was not canceled")
	}
}

func TestNetworkInboundAdmissionBoundAndShutdown(t *testing.T) {
	n := admissionNetwork(t, "fixture-token")
	address := n.carrierListeners[0].Addr().String()
	peers := make([]net.Conn, 0, 16)
	defer func() {
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()
	for range 16 {
		peer, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		peers = append(peers, peer)
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for len(n.inboundAdmission) != cap(n.inboundAdmission) {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("bounded admission pool did not fill")
		}
	}
	overflow, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer overflow.Close()
	if err := overflow.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := overflow.Read(data[:]); err == nil {
		t.Fatal("overflow admission stayed open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("overflow admission was not promptly rejected")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if len(n.inboundAdmission) != 0 {
		t.Fatal("Network.Close left pending admission workers")
	}
}

func TestNetworkAdmissionRejectsDataLaneWithoutControl(t *testing.T) {
	n := admissionNetwork(t, "fixture-token")
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	incoming, _ := NewConnection(right, ConnectionInfo{Type: "host"})
	cfg := link.LinkConfig{Descriptor: n.networkContext.Descriptor(), NetworkID: n.networkContext.WireID(), PSK: n.networkPSK, Identity: identity, Initiator: true, LinkID: 900, LinkEpoch: 1, Generation: 3, LaneID: 2, CapabilityVersion: uint16(link.CapabilityVersion), CapabilityMask: link.RequiredCapabilityMask, RequiredCapabilityMask: link.RequiredCapabilityMask}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() { _, err := link.Handshake(ctx, left, cfg); results <- err }()
	go func() { results <- n.admitConnection(incoming, false) }()
	var denied bool
	for range 2 {
		select {
		case err := <-results:
			// A DATA lane offered before an active same-peer CONTROL Link is a
			// typed missing-control-dependency rejection, not a permanent
			// unsupported capability.
			denied = denied || errors.Is(err, ErrMissingControlDependency)
		case <-time.After(2 * time.Second):
			t.Fatal("lane rejection blocked")
		}
	}
	if !denied {
		t.Fatal("data lane was admitted without CONTROL dependency")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.activeLinks) != 0 {
		t.Fatal("data lane entered registry")
	}
}
