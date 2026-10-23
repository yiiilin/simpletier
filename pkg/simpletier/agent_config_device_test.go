package simpletier

import (
	"strings"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

// TestAgentConfigDeviceNameValidation covers the device-name rule: an empty name
// keeps the platform default, a printable name is accepted, and a name the
// platform would reject is refused at configuration time.
func TestAgentConfigDeviceNameValidation(t *testing.T) {
	base := AgentConfig{
		Config: Config{
			Listen:  []string{"tcp://127.0.0.1:19099"},
			Network: NetworkConfig{Name: "n", CIDR: "10.200.0.0/24", Token: "t"},
		},
		Inbounds: AgentInbounds{TUN: boolPtr(true)},
		// A TUN device needs an explicit name so a crash leaves a handle the next run can
		// find; see TestAgentConfigRequiresDeviceNameForTUN.
		DeviceName: "st-base0",
	}

	if err := base.Validate(); err != nil {
		t.Fatalf("the base config must be valid: %v", err)
	}

	named := base
	named.DeviceName = "st-node-a"
	if err := named.Validate(); err != nil {
		t.Fatalf("a printable device name must be accepted: %v", err)
	}

	for _, bad := range []string{"with space", "with/slash", "with\\backslash", "tab\there"} {
		invalid := base
		invalid.DeviceName = bad
		err := invalid.Validate()
		if err == nil {
			t.Fatalf("device name %q must be rejected", bad)
		}
		if !strings.Contains(err.Error(), "device_name") {
			t.Fatalf("device name %q error = %v; want it to name device_name", bad, err)
		}
	}
}

// TestAgentConfigRequiresDeviceNameForTUN pins the name a host needs to clean up after
// itself.
//
// A crashed process leaves the TUN interface and the routes it installed behind. The only
// durable record that survives the crash is the interface name, so the name has to be one
// the operator chose and can therefore be found again. A platform-assigned name (tunN,
// utunN) is not stable across a restart, and there is no other place to keep the record:
// runtime state is process-local, so nothing is written to disk.
func TestAgentConfigRequiresDeviceNameForTUN(t *testing.T) {
	base := func() AgentConfig {
		return AgentConfig{
			Config: Config{
				Listen:  []string{"tcp://127.0.0.1:19100"},
				Network: NetworkConfig{Name: "n", CIDR: "10.201.0.0/24", Token: "t"},
			},
			Inbounds: AgentInbounds{TUN: boolPtr(true)},
		}
	}

	unnamed := base()
	if err := unnamed.Validate(); err == nil {
		t.Fatal("TUN with no device name was accepted; a crash would leave an interface nothing can find")
	}

	named := base()
	named.DeviceName = "simpletier-test0"
	if err := named.Validate(); err != nil {
		t.Fatalf("TUN with a device name was rejected: %v", err)
	}

	// A device name without TUN stays optional: nothing is created, so nothing needs a
	// stable handle.
	noTUN := base()
	noTUN.Inbounds.TUN = nil
	if err := noTUN.Validate(); err != nil {
		t.Fatalf("device-less configuration was rejected: %v", err)
	}
}
