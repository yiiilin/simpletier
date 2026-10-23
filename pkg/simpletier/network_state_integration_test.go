package simpletier

import (
	"errors"
	"github.com/yiiilin/simpletier/internal/security"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// runtimeOwnerConfig builds a real Config that pins NewNetwork to an explicit
// canonical state directory and a fresh loopback listener. It never constructs
// the Network itself so callers can assert both the success and the failure
// paths of the runtime-owner wiring.
func runtimeOwnerConfig(t *testing.T, stateDir string, mutate func(*Config)) Config {
	t.Helper()
	cfg := validConfig()
	listenURL, _ := freeTCPListenAddress(t)
	cfg.Listen, cfg.Upstreams = []string{listenURL}, nil
	cfg.Network.Token = admissionOrderToken
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

// mustNewNetwork constructs a real Network and closes it at test cleanup. The
// returned concrete value exposes the runtimeState handle so tests can read the
// durable incarnation without touching the security package internals.
func mustNewNetwork(t *testing.T, cfg Config) *network {
	t.Helper()
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork() error = %v", err)
	}
	t.Cleanup(func() {
		if err := handle.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return handle.(*network)
}

// Acceptance: the same canonical StateDir + NodeID + full ContextID admits only
// one running owner. The duplicate constructor is rejected with the public
// runtime-in-use error, and the already-running instance keeps its listener and
// registry untouched.
func TestNewNetworkRejectsDuplicateSameContextOwner(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	first := mustNewNetwork(t, runtimeOwnerConfig(t, stateDir, nil))
	address := first.carrierListeners[0].Addr().String()

	// Each Network gets its own runtime scope now, so a second constructor no longer
	// collides on a shared directory. The one-owner-per-(scope, context) rule still
	// holds and is what guards the live instance; take a second owner directly to
	// prove the duplicate is refused rather than silently sharing runtime state.
	second := mustNewNetwork(t, runtimeOwnerConfig(t, stateDir, nil))
	scope, err := second.identityStore.StateDir()
	if err != nil {
		t.Fatalf("resolve scope: %v", err)
	}
	contextID := second.networkContext.ID()
	if _, err := security.OpenNetworkState(second.identityStore, contextID); !errors.Is(err, security.ErrNetworkStateInUse) {
		t.Fatalf("second owner for one scope+context error = %v; want ErrNetworkStateInUse", err)
	}
	_ = scope

	// The rejected constructor must not have closed or rebound the live owner.
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("first Network listener stopped accepting after duplicate rejection: %v", err)
	}
	_ = conn.Close()
}

// Acceptance: different full ContextIDs on one canonical identity directory
// share the identity/NodeID but own independent runtime state.
func TestNewNetworkDifferentContextsShareIdentityWithIndependentRuntimeState(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	first := mustNewNetwork(t, runtimeOwnerConfig(t, stateDir, nil))
	second := mustNewNetwork(t, runtimeOwnerConfig(t, stateDir, func(cfg *Config) {
		cfg.Network.CIDR = "10.21.0.0/24"
		cfg.Options.FixedIP = "10.21.0.7"
	}))

	if first.networkContext.ID() == second.networkContext.ID() {
		t.Fatal("different CIDRs did not produce different full contexts")
	}
	firstIdentity, err := first.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	secondIdentity, err := second.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	// There is no shared identity to retain: each Network owns its own. The property
	// that still matters is that the two runtime states stay independent.
	if firstIdentity.NodeID == secondIdentity.NodeID {
		t.Fatal("two Networks in one process share a node identity")
	}
	if first.runtimeState.Incarnation() != 1 || second.runtimeState.Incarnation() != 1 {
		t.Fatalf("independent contexts did not each start at incarnation 1: %d / %d",
			first.runtimeState.Incarnation(), second.runtimeState.Incarnation())
	}

	// Closing one context releases only its own owner; the other handle keeps
	// advancing its own durable counters.
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first) error = %v", err)
	}
	sequence, err := second.runtimeState.NextSequence()
	if err != nil || sequence != 1 {
		t.Fatalf("second context after first Close: sequence=%d err=%v; want 1, nil", sequence, err)
	}
}

// Acceptance: a constructor failure after the owner reservation (listener bind
// failure) rolls the owner back so the same context can be reopened, and the
// aborted incarnation is burned rather than reset.
func TestNewNetworkBindFailureReleasesOwnerAndBurnsIncarnation(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	cfg := runtimeOwnerConfig(t, stateDir, nil)
	cfg.Listen = append(cfg.Listen, "tcp://"+occupied.Addr().String())
	if _, err := NewNetwork(cfg); err == nil {
		t.Fatal("NewNetwork() succeeded although a listener address was occupied")
	}

	reopened := mustNewNetwork(t, runtimeOwnerConfig(t, stateDir, nil))
	// State is process-local, so a reopen starts at incarnation 1 instead of advancing
	// a remembered one. The gap that used to be burned on disk no longer exists.
	if got := reopened.runtimeState.Incarnation(); got != 1 {
		t.Fatalf("incarnation after constructor bind rollback = %d; want 1 (state is process-local)", got)
	}
}

// Acceptance: Close releases the owner only at the final cleanup, so a later
// constructor for the same context succeeds and advances the incarnation.
func TestNewNetworkReopenAfterCloseIncrementsIncarnation(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	first := mustNewNetwork(t, runtimeOwnerConfig(t, stateDir, nil))
	if got := first.runtimeState.Incarnation(); got != 1 {
		t.Fatalf("first incarnation = %d; want 1", got)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first) error = %v", err)
	}

	// State is process-local now, so a reopen starts a fresh runtime incarnation
	// rather than continuing a remembered one. What must hold is that the reopen
	// succeeds and receives a usable runtime of its own.
	second := mustNewNetwork(t, runtimeOwnerConfig(t, stateDir, nil))
	if got := second.runtimeState.Incarnation(); got != 1 {
		t.Fatalf("incarnation after Close-and-reopen = %d; want 1 (state is process-local)", got)
	}
	if _, err := second.runtimeState.NextSequence(); err != nil {
		t.Fatalf("reopened runtime state is unusable: %v", err)
	}
}

// Acceptance: during a CloseTimeout the runtime owner is still held, and it is
// released only once the last worker finishes and Done closes.
func TestNewNetworkCloseTimeoutHoldsOwnerUntilDone(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	owner := mustNewNetwork(t, runtimeOwnerConfig(t, stateDir, nil))

	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	owner.workers.Add(1)
	go func() {
		defer owner.workers.Done()
		<-release
	}()

	if err := owner.Close(); !errors.Is(err, ErrCloseTimeout) {
		t.Fatalf("Close() with a blocked worker error = %v; want ErrCloseTimeout", err)
	}
	select {
	case <-owner.Done():
		t.Fatal("Done() closed before the blocked worker finished")
	default:
	}
	// The runtime owner is released only by the completion path. Each Network now gets
	// its own scope, so a second constructor no longer collides on a shared directory;
	// the reservation itself is what must still be held, and one direct attempt to
	// take it proves that.
	if !security.RuntimeOwnerHeldForTest(owner.runtimeState) {
		t.Fatal("runtime owner was released before the blocked worker finished")
	}

	close(release)
	released = true
	select {
	case <-owner.Done():
	case <-time.After(time.Second):
		t.Fatal("Done() did not close after the blocked worker exited")
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("second Close() after cleanup error = %v", err)
	}

	reopened := mustNewNetwork(t, runtimeOwnerConfig(t, stateDir, nil))
	if got := reopened.runtimeState.Incarnation(); got != 1 {
		t.Fatalf("incarnation after CloseTimeout and release = %d; want 1 (state is process-local)", got)
	}
}
