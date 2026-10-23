package agent

// Platform-neutral tests of the L3 device slice: configuration validation,
// packet framing helpers and the honest cross-build resolution errors. The real
// device runtime lives in device_linux_test.go and sysnet_linux_test.go.

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDeviceConfigValidate(t *testing.T) {
	valid := DeviceConfig{
		Name:    "st-test0",
		Address: netip.MustParsePrefix("10.20.30.1/32"),
		Routes:  []netip.Prefix{netip.MustParsePrefix("10.20.31.0/24")},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid device config rejected: %v", err)
	}
	if !valid.configured() {
		t.Fatal("configured() must report true for a populated device config")
	}
	if (DeviceConfig{}).configured() {
		t.Fatal("configured() must report false for the zero device config")
	}
	cases := []struct {
		name   string
		config DeviceConfig
	}{
		{"name with space", DeviceConfig{Name: "st test"}},
		{"name with slash", DeviceConfig{Name: "st/0"}},
		{"empty name ok but -> zero config", DeviceConfig{Name: ""}},
		{"ipv6 address", DeviceConfig{Address: netip.MustParsePrefix("fd00::1/128")}},
		{"non-/32 address", DeviceConfig{Address: netip.MustParsePrefix("10.20.30.0/24")}},
		{"invalid route", DeviceConfig{Routes: []netip.Prefix{{}}}},
		{"ipv6 route", DeviceConfig{Routes: []netip.Prefix{netip.MustParsePrefix("fd00::/64")}}},
		{"route repeats address", DeviceConfig{
			Address: netip.MustParsePrefix("10.20.30.1/32"),
			Routes:  []netip.Prefix{netip.MustParsePrefix("10.20.30.1/32")},
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.config.Name == "" && !testCase.config.Address.IsValid() && len(testCase.config.Routes) == 0 {
				return
			}
			err := testCase.config.Validate()
			if err == nil {
				t.Fatalf("config %+v accepted, want ErrInvalidConfig", testCase.config)
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error %v, want ErrInvalidConfig", err)
			}
		})
	}
	longName := strings.Repeat("a", MaxDeviceNameLength+1)
	if err := (DeviceConfig{Name: longName}).Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("oversized name error %v, want ErrInvalidConfig", err)
	}
}

func TestAgentConfigDeviceValidation(t *testing.T) {
	tun := true
	config := AgentConfig{
		Inbounds: Inbounds{TUN: &tun},
		Device: DeviceConfig{
			Name:    "st-test0",
			Address: netip.MustParsePrefix("10.20.30.1/32"),
		},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("valid agent config rejected: %v", err)
	}
	config.Device.Address = netip.MustParsePrefix("10.20.30.0/24")
	if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("agent config with a prefix address error %v, want ErrInvalidConfig", err)
	}
}

func TestSystemNetworkOptionsValidate(t *testing.T) {
	valid := SystemNetworkOptions{
		Interface: "st-test0",
		MTU:       DefaultDeviceMTU,
		Address:   netip.MustParsePrefix("10.20.30.1/32"),
		Routes:    []netip.Prefix{netip.MustParsePrefix("10.20.31.0/24")},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid system network options rejected: %v", err)
	}
	if valid.mtu() != DefaultDeviceMTU {
		t.Fatalf("mtu() = %d, want %d", valid.mtu(), DefaultDeviceMTU)
	}
	if (SystemNetworkOptions{Interface: "x"}).mtu() != DefaultDeviceMTU {
		t.Fatal("zero MTU must default to DefaultDeviceMTU")
	}
	cases := []struct {
		name string
		opts SystemNetworkOptions
	}{
		{"missing interface", SystemNetworkOptions{}},
		{"mtu above the frozen default", SystemNetworkOptions{Interface: "x", MTU: DefaultDeviceMTU + 1}},
		{"mtu below the IPv4 minimum", SystemNetworkOptions{Interface: "x", MTU: MinDeviceMTU - 1}},
		{"address not /32", SystemNetworkOptions{Interface: "x", Address: netip.MustParsePrefix("10.0.0.0/24")}},
		{"ipv6 address", SystemNetworkOptions{Interface: "x", Address: netip.MustParsePrefix("fd00::1/128")}},
		{"ipv6 route", SystemNetworkOptions{Interface: "x", Routes: []netip.Prefix{netip.MustParsePrefix("fd00::/64")}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.opts.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestClampDeviceMTU(t *testing.T) {
	if mtu, err := clampDeviceMTU(0); err != nil || mtu != DefaultDeviceMTU {
		t.Fatalf("clampDeviceMTU(0) = %d, %v; want %d, nil", mtu, err, DefaultDeviceMTU)
	}
	if mtu, err := clampDeviceMTU(MinDeviceMTU); err != nil || mtu != MinDeviceMTU {
		t.Fatalf("clampDeviceMTU(%d) = %d, %v", MinDeviceMTU, mtu, err)
	}
	for _, requested := range []int{MinDeviceMTU - 1, DefaultDeviceMTU + 1} {
		if _, err := clampDeviceMTU(requested); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("clampDeviceMTU(%d) error %v, want ErrInvalidConfig", requested, err)
		}
	}
}

func TestIPv4PacketValid(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = 20
	if err := ipv4PacketValid(packet); err != nil {
		t.Fatalf("minimal IPv4 header rejected: %v", err)
	}
	cases := []struct {
		name   string
		packet []byte
	}{
		{"empty", nil},
		{"short", make([]byte, 19)},
		{"ipv6 version", append([]byte{0x60}, make([]byte, 39)...)},
		{"ihl below 5", append([]byte{0x44}, make([]byte, 39)...)},
		{"length mismatch", func() []byte {
			buffer := make([]byte, 40)
			buffer[0] = 0x45
			buffer[3] = 20
			return buffer
		}()},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := ipv4PacketValid(testCase.packet); !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("error %v, want ErrInvalidPacket", err)
			}
		})
	}
}

func TestResolveHostAdapterRejectsForeignBuilds(t *testing.T) {
	if _, err := ResolveHostAdapter("plan9"); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("ResolveHostAdapter(plan9) error %v, want ErrPlatformUnavailable", err)
	}
	if runtime.GOOS != "linux" {
		t.Skipf("foreign-build assertions are written for the current linux build, running %s", runtime.GOOS)
	}
	for _, platform := range []Platform{PlatformWindows, PlatformDarwin} {
		adapter, err := ResolveHostAdapter(platform)
		if adapter != nil {
			t.Fatalf("ResolveHostAdapter(%s) returned an adapter in a linux build", platform)
		}
		if !errors.Is(err, ErrPlatformUnavailable) {
			t.Fatalf("ResolveHostAdapter(%s) error %v, want ErrPlatformUnavailable", platform, err)
		}
		if !strings.Contains(err.Error(), "build") {
			t.Fatalf("ResolveHostAdapter(%s) error %q must name the required build", platform, err)
		}
		if _, err := NewSystemNetwork(platform, "x", SystemNetworkOptions{}); !errors.Is(err, ErrNetworkConfigUnavailable) {
			t.Fatalf("NewSystemNetwork(%s) error %v, want ErrNetworkConfigUnavailable", platform, err)
		}
	}
	adapter, err := ResolveHostAdapter(PlatformLinux)
	if err != nil {
		t.Fatalf("ResolveHostAdapter(linux): %v", err)
	}
	if adapter.Platform() != PlatformLinux {
		t.Fatalf("adapter platform %q, want linux", adapter.Platform())
	}
}

func TestInspectHostAdapter(t *testing.T) {
	info, err := InspectHostAdapter(PlatformLinux)
	if err != nil {
		if runtime.GOOS != "linux" {
			t.Skipf("linux inspection on %s: %v", runtime.GOOS, err)
		}
		t.Fatalf("InspectHostAdapter(linux): %v", err)
	}
	if info.Platform != PlatformLinux {
		t.Fatalf("info platform %q, want linux", info.Platform)
	}
	if info.MaxMTU != DefaultDeviceMTU {
		t.Fatalf("info MaxMTU %d, want %d", info.MaxMTU, DefaultDeviceMTU)
	}
	if info.DevicePath == "" || info.Driver == "" {
		t.Fatalf("inspection must name the platform resource and driver: %+v", info)
	}
	if !info.Available && info.Detail == "" {
		t.Fatalf("an unavailable adapter must explain itself: %+v", info)
	}
}

func TestContextErrorIdentity(t *testing.T) {
	if err := packetDeviceContextErr(nil); err != nil {
		t.Fatalf("nil context error %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(packetDeviceContextErr(ctx), context.Canceled) {
		t.Fatal("a cancelled context must report context.Canceled")
	}
}

// TestAfterFuncJoinedWaitsForRunningCallback is the unit-level regression for
// the wake-descriptor lifetime fix: context.AfterFunc's own stop does not wait
// for a callback that already started, so a poll that returned on stop() could
// let Close free the wake descriptor while the callback still writes it.
func TestAfterFuncJoinedWaitsForRunningCallback(t *testing.T) {
	for attempt := 0; attempt < 200; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		finished := make(chan struct{})
		stop := afterFuncJoined(ctx, func() {
			close(started)
			// Widen the window between "callback started" and "callback done" so
			// a stop that does not join is very likely to observe it.
			time.Sleep(time.Millisecond)
			close(finished)
		})
		cancel()
		<-started
		stopped := stop()
		if stopped {
			// The callback never ran, so there is nothing to join.
			continue
		}
		select {
		case <-finished:
		default:
			t.Fatal("stop returned before the cancellation callback finished")
		}
	}
}

// TestAfterFuncJoinedNilContext checks the nil-context contract: no callback and
// a stop that reports it prevented the call.
func TestAfterFuncJoinedNilContext(t *testing.T) {
	called := false
	stop := afterFuncJoined(nil, func() { called = true })
	if !stop() {
		t.Fatal("stop on a nil context must report that the callback cannot run")
	}
	if called {
		t.Fatal("a nil context must not run the callback")
	}
}

// TestAfterFuncJoinedStopsBeforeCancellation checks the common path: stopping
// before the context is done prevents the callback entirely.
func TestAfterFuncJoinedStopsBeforeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan struct{}, 1)
	stop := afterFuncJoined(ctx, func() { ran <- struct{}{} })
	if !stop() {
		t.Fatal("stop before cancellation must report that it prevented the callback")
	}
	cancel()
	select {
	case <-ran:
		t.Fatal("the callback ran although stop was called first")
	case <-time.After(20 * time.Millisecond):
	}
}
