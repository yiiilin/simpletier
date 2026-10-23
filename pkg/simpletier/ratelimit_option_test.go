package simpletier

import (
	"testing"
)

// TestRateLimitIsOffByDefault pins the default: a Network built from a plain config
// runs with the guard removed, so a burst of peers from one address is admitted.
func TestRateLimitIsOffByDefault(t *testing.T) {
	cfg := validConfig()
	url, _ := freeTCPListenAddress(t)
	cfg.Listen, cfg.Upstreams = []string{url}, nil

	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork: %v", err)
	}
	defer func() { _ = handle.Close() }()

	n := handle.(*network)
	if got := n.rates.limits.sourceConnectBurst; got < 1<<20 {
		t.Fatalf("default sourceConnectBurst = %v; the guard should be off", got)
	}
	if got := n.rates.limits.handshakeConcurrent; got < 1<<19 {
		t.Fatalf("default handshakeConcurrent = %d; the guard should be off", got)
	}
}

// TestRateLimitExplicitTrueRestoresTheFrozenBudget pins the opt-in: an explicit true
// gives exactly the production budget, not a raised or lowered one.
func TestRateLimitExplicitTrueRestoresTheFrozenBudget(t *testing.T) {
	cfg := validConfig()
	url, _ := freeTCPListenAddress(t)
	cfg.Listen, cfg.Upstreams = []string{url}, nil
	enabled := true
	cfg.Options.RateLimit = &enabled

	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork: %v", err)
	}
	defer func() { _ = handle.Close() }()

	n := handle.(*network)
	want := defaultRateLimits()
	if got := n.rates.limits; got.sourceConnectPerSec != want.sourceConnectPerSec ||
		got.sourceConnectBurst != want.sourceConnectBurst ||
		got.handshakeConcurrent != want.handshakeConcurrent ||
		got.preauthTotal != want.preauthTotal {
		t.Fatalf("opt-in budget = %+v; want the frozen defaults", got)
	}
}

// TestRateLimitFalseIsDistinctFromUnset proves the pointer exists for a reason: an
// explicit false and a nil both disable the guard, but false must not fall back to
// the default.
func TestRateLimitFalseIsDistinctFromUnset(t *testing.T) {
	cfg := validConfig()
	url, _ := freeTCPListenAddress(t)
	cfg.Listen, cfg.Upstreams = []string{url}, nil
	disabled := false
	cfg.Options.RateLimit = &disabled

	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork: %v", err)
	}
	defer func() { _ = handle.Close() }()

	n := handle.(*network)
	if got := n.rates.limits.sourceConnectPerSec; got < 1<<20 {
		t.Fatalf("explicit false gave sourceConnectPerSec = %v; want the guard off", got)
	}
}

// TestUnlimitedLimitsCannotRefuse pins that the unguarded budget is genuinely
// permissive rather than accidentally zero, which would refuse everything.
func TestUnlimitedLimitsCannotRefuse(t *testing.T) {
	limits := unlimitedRateLimits()
	if limits.handshakeConcurrent < 1 {
		t.Fatalf("handshakeConcurrent = %d; zero would block every handshake", limits.handshakeConcurrent)
	}
	if limits.sourceConnectPerSec <= 0 || limits.sourceConnectBurst <= 0 {
		t.Fatalf("source budget = %v/%v; zero would refuse every carrier",
			limits.sourceConnectPerSec, limits.sourceConnectBurst)
	}
	if limits.preauthTotal < 1 {
		t.Fatalf("preauthTotal = %d; zero would close every carrier", limits.preauthTotal)
	}
}
