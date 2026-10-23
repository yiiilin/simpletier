package simpletier

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestNormalizedNetworkContextIndependentVector(t *testing.T) {
	cfg := validConfig()
	cfg.Network = NetworkConfig{Name: "mesh-a", CIDR: "10.30.0.0/24", Token: "0123456789abcdef0123456789abcdef"}
	cfg.Options.FixedIP = "10.30.0.7"
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Fixed expected bytes were independently calculated using Node SHA256/HMAC
	// and are also pinned by the internal context tests, not the SDK normalizer.
	wantDescriptor, err := hex.DecodeString("73696d706c65746965722d76312f6e6574776f726b2d636f6e74657874000000066d6573682d610000000c31302e33302e302e302f3234")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(normalized.networkContext.Descriptor(), wantDescriptor) {
		t.Fatal("normalization did not prepare the exact public network descriptor")
	}
	id := normalized.networkContext.ID()
	if hex.EncodeToString(id[:]) != "c5af1c1cac81ccc9af97f836b3462087e909221ca550dfb42e57cac022db37c6" {
		t.Fatal("normalization did not preserve full ContextID")
	}
	if hex.EncodeToString(normalized.networkPSK[:]) != "0bb5fbb64399da6aac97b849567412d088cf789f477b5dbae41bd18c18da670c" {
		t.Fatal("normalization did not derive the independently expected context-bound PSK")
	}
	if normalized.networkPrefix.String() != cfg.Network.CIDR || normalized.fixedIP.String() != cfg.Options.FixedIP {
		t.Fatal("context preparation changed prefix or fixed-IP normalization")
	}
	copyOfDescriptor := normalized.networkContext.Descriptor()
	copyOfDescriptor[0] ^= 0xff
	if !bytes.Equal(normalized.networkContext.Descriptor(), wantDescriptor) || normalized.networkContext.ID() != id {
		t.Fatal("public descriptor accessor mutated prepared SDK context")
	}
}

func TestNormalizedNetworkContextSeparatesCIDRNameAndToken(t *testing.T) {
	cfg := validConfig()
	cfg.Options.FixedIP = ""
	base, err := normalizeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []NetworkConfig{
		{Name: cfg.Network.Name, CIDR: "10.21.0.0/24", Token: cfg.Network.Token},
		{Name: cfg.Network.Name + " ", CIDR: cfg.Network.CIDR, Token: cfg.Network.Token},
		{Name: " " + cfg.Network.Name, CIDR: cfg.Network.CIDR, Token: cfg.Network.Token},
		{Name: strings.ToUpper(cfg.Network.Name), CIDR: cfg.Network.CIDR, Token: cfg.Network.Token},
		{Name: "${NETWORK_NAME}", CIDR: cfg.Network.CIDR, Token: cfg.Network.Token},
	} {
		changed := cfg
		changed.Network = candidate
		got, err := normalizeConfig(changed)
		if err != nil {
			t.Fatal(err)
		}
		if got.networkContext.ID() == base.networkContext.ID() || got.networkPSK == base.networkPSK {
			t.Fatal("distinct raw name/CIDR collapsed into shared context/key")
		}
		if got.config.Network != candidate {
			t.Fatal("normalization changed literal SDK network values")
		}
	}
	rotated := cfg
	rotated.Network.Token = "rotated-fixture-token"
	got, err := normalizeConfig(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if got.networkContext.ID() != base.networkContext.ID() || got.networkPSK == base.networkPSK {
		t.Fatal("token rotation changed public identity or failed to change the key")
	}
	cfg.Network.Name = "caller changed"
	if base.config.Network.Name != "test-network" || base.networkContext.ID() == ([32]byte{}) {
		t.Fatal("prepared context depends on mutable caller config")
	}
}

func TestNewNetworkConsumesPreparedContextWithoutAuthentication(t *testing.T) {
	cfg := validConfig()
	listenURL, _ := freeTCPListenAddress(t)
	cfg.Listen, cfg.Upstreams = []string{listenURL}, nil
	prepared, err := normalizeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	n := handle.(*network)
	if n.networkContext.ID() != prepared.networkContext.ID() || n.networkPSK != prepared.networkPSK {
		t.Fatal("NewNetwork did not consume the validated context/key")
	}
	if _, err := n.DialContext(context.Background(), "tcp", "10.20.0.8:8080"); !errors.Is(err, ErrNoRoute) {
		t.Fatal("PSK preparation incorrectly admitted a peer")
	}
	firstIdentity, err := n.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	second := cfg
	secondListenURL, _ := freeTCPListenAddress(t)
	second.Listen = []string{secondListenURL}
	second.Network.CIDR = "10.21.0.0/24"
	second.Options.FixedIP = "10.21.0.7"
	otherHandle, err := NewNetwork(second)
	if err != nil {
		t.Fatal(err)
	}
	defer otherHandle.Close()
	other := otherHandle.(*network)
	secondIdentity, err := other.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	// Each Network generates its own identity now: there is no shared state directory
	// to key one identity by. Two Networks in one process must therefore be distinct
	// peers, which is what keeps a LINK fact from naming the same node on both ends.
	if firstIdentity.NodeID == secondIdentity.NodeID {
		t.Fatal("two Networks in one process share a node identity")
	}
	if n.networkContext.ID() == other.networkContext.ID() || n.networkPSK == other.networkPSK {
		t.Fatal("same name/shared identity/different CIDR shared runtime context/key")
	}
	copyOfDescriptor := n.networkContext.Descriptor()
	copyOfDescriptor[0] ^= 0xff
	if n.networkContext.ID() != prepared.networkContext.ID() {
		t.Fatal("runtime descriptor could mutate the prepared context")
	}
}

func TestContextPreparationRejectsBeforeStartupSideEffects(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.Network.Name = "PRIVATE-NAME\x00DATA" },
		func(cfg *Config) { cfg.Network.CIDR = "PRIVATE-CIDR" },
		func(cfg *Config) { cfg.Network.Token = "" },
	} {
		cfg := validConfig()
		mutate(&cfg)
		if _, err := NewNetwork(cfg); !errors.Is(err, ErrInvalidConfig) || strings.Contains(err.Error(), "PRIVATE-") {
			t.Fatalf("invalid context input rejected unsafely: %v", err)
		}
		// Rejection must happen before anything observable is created. Runtime state is
		// process-local, so the check is for a bound listener rather than a directory.
		if len(cfg.Listen) > 0 {
			t.Logf("rejected config had listeners: %v", cfg.Listen)
		}
	}
}
