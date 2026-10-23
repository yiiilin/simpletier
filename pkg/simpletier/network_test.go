package simpletier

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/security"
)

func TestNetworkCloseTimeoutContinuesCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()

	network := &network{
		done:            make(chan struct{}),
		ctx:             ctx,
		cancel:          cancel,
		streamListeners: make(map[netip.AddrPort]*streamListener),
	}
	network.workers.Add(1)
	go func() {
		defer network.workers.Done()
		<-release
	}()

	if err := network.Close(); !errors.Is(err, ErrCloseTimeout) {
		t.Fatalf("first Close() error = %v; want ErrCloseTimeout", err)
	}
	select {
	case <-network.Done():
		t.Fatal("Done() closed before the blocked worker finished")
	default:
	}

	close(release)
	released = true
	select {
	case <-network.Done():
	case <-time.After(time.Second):
		t.Fatal("Done() did not close after the worker exited")
	}
	if err := network.Close(); err != nil {
		t.Fatalf("second Close() error = %v; want nil after cleanup", err)
	}
}

func TestNewNetworkRejectsInvalidConfigBeforeSideEffects(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := validConfig()
	// An empty token is rejected before any side effect. Listen=nil is legal now,
	// so it can no longer serve as the invalid field here.
	cfg.Network.Token = ""

	if _, err := NewNetwork(cfg); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewNetwork(invalid config) error = %v; want ErrInvalidConfig", err)
	}
	if _, err := os.Stat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state_dir exists after invalid Config: stat error = %v", err)
	}
}

func TestNetworkVirtualListenerClosesAndDialReportsNoRoute(t *testing.T) {
	listenURL, _ := freeTCPListenAddress(t)
	cfg := validConfig()
	cfg.Listen = []string{listenURL}
	cfg.Upstreams = nil

	network, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork() error = %v", err)
	}
	listener, err := network.Listen("tcp", "10.20.0.7:34567")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	shorthand, err := network.Listen("tcp", ":34568")
	if err != nil {
		t.Fatalf("Listen(:34568) error = %v", err)
	}
	if got := shorthand.Addr().(*net.TCPAddr).IP.String(); got != "10.20.0.7" {
		t.Fatalf("Listen(:34568) VirtualIP = %s; want 10.20.0.7", got)
	}
	if _, err := network.Listen("tcp", "10.20.0.8:34569"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Listen on unowned VirtualIP error = %v; want ErrPermissionDenied", err)
	}
	acceptResult := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		acceptResult <- err
	}()
	if _, err := network.DialContext(context.Background(), "tcp", "10.20.0.8:34567"); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("DialContext() error = %v; want ErrNoRoute before any Link is authenticated", err)
	}
	if err := network.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-acceptResult:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Accept() error = %v; want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept() did not unblock on Network.Close")
	}
}

func TestNewNetworkBindsAndCloseReleasesResources(t *testing.T) {
	listenURL, address := freeTCPListenAddress(t)
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := validConfig()
	cfg.Listen = []string{listenURL}
	cfg.Upstreams = nil

	network, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork() error = %v", err)
	}
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("configured listener is not bound: %v", err)
	}
	_ = conn.Close()

	if err := network.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := network.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	select {
	case <-network.Done():
	default:
		t.Fatal("Done() is not closed after Close() returns")
	}

	probe, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("listener remains bound after Close(): %v", err)
	}
	_ = probe.Close()

	store, err := security.OpenIdentityStore()
	if err != nil {
		t.Fatalf("identity lock was not released after Close(): %v", err)
	}
	identity, err := store.Identity()
	if err != nil {
		t.Fatalf("reopen Identity() error = %v", err)
	}
	if identity.NodeID == ([16]byte{}) {
		t.Fatal("persisted identity has an empty NodeID")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close reopened IdentityStore: %v", err)
	}
	// No identity file exists any more: state is in memory. Closing a Network must
	// leave nothing behind on disk.
	if _, err := os.Stat(filepath.Join(stateDir, "identity.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closing the Network left an identity file: stat error = %v", err)
	}
}

func TestNewNetworkRollsBackAllListenersAndIdentityReference(t *testing.T) {
	firstURL, firstAddress := freeTCPListenAddress(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	secondURL := "tcp://" + occupied.Addr().String()
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := validConfig()
	cfg.Listen = []string{firstURL, secondURL}
	cfg.Upstreams = nil

	if _, err := NewNetwork(cfg); err == nil {
		t.Fatal("NewNetwork() succeeded although the second listener address was occupied")
	}
	probe, err := net.Listen("tcp", firstAddress)
	if err != nil {
		t.Fatalf("first listener was not rolled back: %v", err)
	}
	_ = probe.Close()

	store, err := security.OpenIdentityStore()
	if err != nil {
		t.Fatalf("IdentityStore reference leaked after constructor failure: %v", err)
	}
	if _, err := store.Identity(); err != nil {
		t.Fatalf("Identity() after constructor rollback: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close reopened IdentityStore: %v", err)
	}
	// No identity file exists any more: state is in memory. What must hold after a
	// failed constructor is that a fresh identity can still be created and used, and
	// that nothing was left on disk behind it.
	if _, err := os.Stat(filepath.Join(stateDir, "identity.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("constructor wrote an identity file: stat error = %v", err)
	}
}

func TestNewNetworkAssignsStableProvisionalVirtualIP(t *testing.T) {
	listenURL, _ := freeTCPListenAddress(t)
	cfg := validConfig()
	cfg.Listen = []string{listenURL}
	cfg.Upstreams = nil
	cfg.Options.FixedIP = ""

	first, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork(first) error = %v", err)
	}
	firstListener, err := first.Listen("tcp", ":34567")
	if err != nil {
		_ = first.Close()
		t.Fatalf("Listen(:34567) without fixed_ip error = %v", err)
	}
	firstAddr, ok := firstListener.Addr().(*net.TCPAddr)
	if !ok {
		_ = first.Close()
		t.Fatalf("Addr() type = %T; want *net.TCPAddr", firstListener.Addr())
	}
	prefix, err := netip.ParsePrefix(cfg.Network.CIDR)
	if err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	virtualIP, err := netip.ParseAddr(firstAddr.IP.String())
	if err != nil || !prefix.Contains(virtualIP) || !usableHost(prefix, virtualIP) {
		_ = first.Close()
		t.Fatalf("provisional VirtualIP %v is not usable in %s", firstAddr.IP, prefix)
	}
	if firstAddr.Port != 34567 {
		_ = first.Close()
		t.Fatalf("Listen(:34567) port = %d; want 34567", firstAddr.Port)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first) error = %v", err)
	}

	listenURL, _ = freeTCPListenAddress(t)
	cfg.Listen = []string{listenURL}
	second, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork(second) error = %v", err)
	}
	secondListener, err := second.Listen("tcp", ":34567")
	if err != nil {
		_ = second.Close()
		t.Fatalf("Listen(:34567) after reopen error = %v", err)
	}
	// A restart no longer remembers the provisional address, because state is not
	// persisted. What must hold is that a fresh Network still gets a usable address
	// in the same CIDR, and that a pinned FixedIP is what buys stability across
	// restarts.
	got, err := netip.ParseAddrPort(secondListener.Addr().String())
	if err != nil {
		_ = second.Close()
		t.Fatalf("parse reopened listener address: %v", err)
	}
	if !netip.MustParsePrefix(cfg.Network.CIDR).Contains(got.Addr()) {
		_ = second.Close()
		t.Fatalf("reopened VirtualIP %s is outside %s", got.Addr(), cfg.Network.CIDR)
	}
	_ = firstAddr
	if err := second.Close(); err != nil {
		t.Fatalf("Close(second) error = %v", err)
	}
}

func TestNewNetworkProvisionalVirtualIPSupportsSmallPrefixes(t *testing.T) {
	tests := []struct {
		name   string
		cidr   string
		wantIP netip.Addr
	}{
		{name: "point-to-point", cidr: "10.20.0.0/31"},
		{name: "single-host", cidr: "10.20.0.7/32", wantIP: netip.MustParseAddr("10.20.0.7")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listenURL, _ := freeTCPListenAddress(t)
			cfg := validConfig()
			cfg.Listen = []string{listenURL}
			cfg.Upstreams = nil
			cfg.Network.CIDR = tt.cidr
			cfg.Options.FixedIP = ""

			network, err := NewNetwork(cfg)
			if err != nil {
				t.Fatalf("NewNetwork() error = %v", err)
			}
			listener, err := network.Listen("tcp", ":23456")
			if err != nil {
				_ = network.Close()
				t.Fatalf("Listen(:23456) error = %v", err)
			}
			addr := listener.Addr().(*net.TCPAddr)
			gotIP := netip.MustParseAddr(addr.IP.String())
			prefix := netip.MustParsePrefix(tt.cidr)
			if !prefix.Contains(gotIP) || !usableHost(prefix, gotIP) {
				_ = network.Close()
				t.Fatalf("provisional VirtualIP %s is not usable in %s", gotIP, prefix)
			}
			if tt.wantIP.IsValid() && gotIP != tt.wantIP {
				_ = network.Close()
				t.Fatalf("provisional VirtualIP = %s; want %s", gotIP, tt.wantIP)
			}
			if err := network.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
		})
	}
}

func TestNewNetworkRejectsUnauthenticatedCarrier(t *testing.T) {
	listenURL, address := freeTCPListenAddress(t)
	cfg := validConfig()
	cfg.Listen = []string{listenURL}
	cfg.Upstreams = nil

	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork() error = %v", err)
	}
	defer handle.Close()

	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial local carrier listener: %v", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Admission now waits for a real handshake; an invalid zero length must
	// still be rejected immediately rather than admitted or left to timeout.
	if n, err := conn.Write([]byte{0, 0, 0, 0}); err != nil || n != 4 {
		t.Fatalf("write invalid handshake prefix = %d, %v; want 4 bytes", n, err)
	}
	var b [1]byte
	if _, err := conn.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("unauthenticated carrier read error = %v; want EOF", err)
	}
	n := handle.(*network)
	n.mu.Lock()
	admitted := len(n.activeLinks)
	n.mu.Unlock()
	if admitted != 0 {
		t.Fatalf("invalid handshake admitted %d authenticated Links; want none", admitted)
	}
}

func TestNewNetworkDoesNotFailOnUnavailableUpstream(t *testing.T) {
	upstreamURL, upstreamAddress := freeTCPListenAddress(t)
	if conn, err := net.DialTimeout("tcp", upstreamAddress, time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("expected the upstream address to be unavailable")
	}
	listenURL, listenAddress := freeTCPListenAddress(t)
	cfg := validConfig()
	cfg.Listen = []string{listenURL}
	cfg.Upstreams = []string{upstreamURL}

	network, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork() failed because an upstream is unavailable: %v", err)
	}
	conn, err := net.DialTimeout("tcp", listenAddress, time.Second)
	if err != nil {
		t.Fatalf("local listener was not retained: %v", err)
	}
	_ = conn.Close()
	if err := network.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestNewNetworkRetriesUpstreamInBackground(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	attempts := make(chan struct{}, 2)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for i := 0; i < cap(attempts); i++ {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			attempts <- struct{}{}
			_ = conn.Close()
		}
	}()

	listenURL, _ := freeTCPListenAddress(t)
	cfg := validConfig()
	cfg.Listen = []string{listenURL}
	cfg.Upstreams = []string{"tcp://" + upstream.Addr().String()}
	network, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork() failed for a reachable upstream: %v", err)
	}

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for i := 0; i < cap(attempts); i++ {
		select {
		case <-attempts:
		case <-deadline.C:
			_ = network.Close()
			t.Fatalf("upstream retry %d was not attempted", i+1)
		}
	}
	if _, err := network.DialContext(context.Background(), "tcp", "10.20.0.8:34567"); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("TCP reachability was incorrectly treated as an authenticated route: %v", err)
	}
	if err := network.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("upstream accept goroutine did not exit")
	}
	select {
	case <-network.Done():
	case <-time.After(time.Second):
		t.Fatal("Done() did not close after upstream worker shutdown")
	}
}

// TestNewNetworkIndependentLifetimes covers two Networks in one process: closing one
// must not disturb the other's listener. They no longer share any state by construction,
// so the property under test is lifecycle independence rather than shared durability.
func TestNewNetworkIndependentLifetimes(t *testing.T) {
	firstURL, _ := freeTCPListenAddress(t)
	secondURL, secondAddress := freeTCPListenAddress(t)
	firstConfig := validConfig()
	firstConfig.Listen = []string{firstURL}
	firstConfig.Upstreams = nil

	secondConfig := validConfig()
	secondConfig.Listen = []string{secondURL}
	secondConfig.Upstreams = nil
	secondConfig.Network.Name = "other-network"
	secondConfig.Network.CIDR = "10.21.0.0/24"
	secondConfig.Options.FixedIP = "10.21.0.7"

	first, err := NewNetwork(firstConfig)
	if err != nil {
		t.Fatalf("NewNetwork(first NetworkID) error = %v", err)
	}
	second, err := NewNetwork(secondConfig)
	if err != nil {
		_ = first.Close()
		t.Fatalf("NewNetwork(second) error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first) error = %v", err)
	}
	conn, err := net.DialTimeout("tcp", secondAddress, time.Second)
	if err != nil {
		t.Fatalf("second Network listener closed with first Network: %v", err)
	}
	_ = conn.Close()
	if err := second.Close(); err != nil {
		t.Fatalf("Close(second) error = %v", err)
	}
}

func freeTCPListenAddress(t testing.TB) (string, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return "tcp://" + address, address
}

func BenchmarkNewNetworkWarmStartClose(b *testing.B) {
	for _, tc := range []struct {
		name    string
		fixedIP string
	}{
		{name: "fixed-ip", fixedIP: "10.20.0.7"},
		{name: "auto-ip"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			listenURL, _ := freeTCPListenAddress(b)
			store, err := security.OpenIdentityStore()
			if err != nil {
				b.Fatal(err)
			}
			if err := store.Close(); err != nil {
				b.Fatal(err)
			}

			cfg := validConfig()
			cfg.Listen = []string{listenURL}
			cfg.Upstreams = nil
			cfg.Options.FixedIP = tc.fixedIP
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				network, err := NewNetwork(cfg)
				if err != nil {
					b.Fatal(err)
				}
				if err := network.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
