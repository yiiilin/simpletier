package simpletier

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNewAgentStartsAndClosesWithoutTUN proves the additive SDK Agent wrapper:
// AgentConfig validates and maps onto the internal adapter, Start with TUN
// disabled performs no host device I/O, LocalVirtualIP/Stats/Network are usable,
// PacketDevice/SystemNetwork are nil, and Close is idempotent and closes Done.
func TestNewAgentStartsAndClosesWithoutTUN(t *testing.T) {
	listenURL, _ := freeTCPListenAddress(t)
	tun := false
	handle, err := NewAgent(AgentConfig{
		Config: Config{
			Listen:  []string{listenURL},
			Network: NetworkConfig{Name: "agent-wrapper", CIDR: "10.101.0.0/24", Token: "agent-token-0123456789abcdef"},
			Options: RuntimeOptions{FixedIP: "10.101.0.1"},
		},
		Inbounds: AgentInbounds{TUN: &tun},
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	if handle.Network() == nil {
		t.Fatal("Agent.Network() is nil")
	}
	if got := handle.LocalVirtualIP(); got != netip.MustParseAddr("10.101.0.1") {
		t.Fatalf("Agent.LocalVirtualIP() = %s; want 10.101.0.1", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := handle.Start(ctx); err != nil {
		t.Fatalf("Agent.Start: %v", err)
	}
	if dev := handle.PacketDevice(); dev != nil {
		t.Fatalf("PacketDevice with TUN disabled = %v; want nil", dev)
	}
	if sn := handle.SystemNetwork(); sn != nil {
		t.Fatalf("SystemNetwork with TUN disabled = %v; want nil", sn)
	}
	_ = handle.Stats()

	if err := handle.Close(); err != nil {
		t.Fatalf("Agent.Close: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("second Agent.Close: %v", err)
	}
	select {
	case <-handle.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Agent.Done did not close after Close")
	}
}

// TestNewAgentRejectsInvalidConfig proves the wrapper validates before creating
// any Network or host resource.
func TestNewAgentRejectsInvalidConfig(t *testing.T) {
	tun := true
	// A proxy inbound without listen/username/password is rejected by the
	// existing AgentConfig.Validate, before NewAgent touches the host.
	handle, err := NewAgent(AgentConfig{
		Config: Config{
			Listen:  []string{"tcp://127.0.0.1:0"},
			Network: NetworkConfig{Name: "agent-invalid", CIDR: "10.101.0.0/24", Token: "agent-token-0123456789abcdef"},
			Options: RuntimeOptions{},
		},
		Inbounds: AgentInbounds{SOCKS5: &ProxyConfig{}, TUN: &tun},
	})
	if err == nil || handle != nil {
		t.Fatalf("NewAgent(invalid) = (%v, %v); want error and no handle", handle, err)
	}
}

// TestAgentStartIsIdempotentAndClosesOnNetworkEnd proves the lifecycle fixes:
// a repeated Start is a no-op instead of a second enablePacketService failure,
// Start after Close fails closed, and a direct Network.Close ends Done without an
// explicit Agent.Close.
func TestAgentStartIsIdempotentAndClosesOnNetworkEnd(t *testing.T) {
	listenURL, _ := freeTCPListenAddress(t)
	tun := false
	handle, err := NewAgent(AgentConfig{
		Config: Config{
			Listen:  []string{listenURL},
			Network: NetworkConfig{Name: "agent-lifecycle", CIDR: "10.102.0.0/24", Token: "agent-token-0123456789abcdef"},
			Options: RuntimeOptions{FixedIP: "10.102.0.1"},
		},
		Inbounds: AgentInbounds{TUN: &tun},
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for attempt := 0; attempt < 2; attempt++ {
		if err := handle.Start(ctx); err != nil {
			t.Fatalf("Start attempt %d: %v", attempt+1, err)
		}
	}
	if handle.Done() == nil {
		t.Fatal("Agent.Done() is nil")
	}

	// Ending the Network alone must end the Agent and release the adapters.
	if err := handle.Network().Close(); err != nil {
		t.Fatalf("Network.Close: %v", err)
	}
	select {
	case <-handle.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("Agent.Done did not close when the Network ended")
	}
	if err := handle.Start(ctx); !errors.Is(err, ErrClosed) && err == nil {
		t.Fatalf("Start after the Agent ended = %v; want an error", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("Agent.Close after Network.Close: %v", err)
	}
}

// TestRuntimeScopeIsNotAFilePath proves the identity store's directory accessor
// reports a scope token rather than a usable path now that runtime state is
// process-local.
//
// The accessor keeps its name because callers key per-network state by it. A value
// that could be opened is what made a journal path built from it wrong, so the check
// is that creating a file under the scope fails.
func TestRuntimeScopeIsNotAFilePath(t *testing.T) {
	n := newPacketPlaneNodeAt(t, "runtime-scope", "10.103.0.0/24", "runtime-scope-token-0123456789", "10.103.0.1", "")
	scope, err := n.identityStore.StateDir()
	if err != nil {
		t.Fatalf("StateDir() error = %v", err)
	}
	if scope == "" {
		t.Fatal("StateDir() returned an empty scope")
	}
	if !filepath.IsAbs(scope) {
		return // a bare token, never a path
	}
	if err := os.MkdirAll(scope, 0o700); err == nil {
		t.Fatalf("StateDir() %q is a usable directory", scope)
	}
}
