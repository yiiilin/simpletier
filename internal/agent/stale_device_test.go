package agent

import (
	"errors"
	"net/netip"
	"testing"
)

// TestStaleDeviceDecision covers what to do when the requested interface name is already
// taken. This is the crash-recovery path: a killed process leaves its TUN interface and
// the /32 on it behind, and the only surviving handle is the name the operator chose.
//
// Getting this wrong is destructive in one direction and useless in the other. Reusing an
// interface that belongs to something else deletes another program's network
// configuration; refusing to reuse our own leaves the host unable to restart after a
// crash.
func TestStaleDeviceDecision(t *testing.T) {
	ours := netip.MustParsePrefix("10.249.0.1/32")
	theirs := netip.MustParsePrefix("192.168.7.9/32")

	cases := []struct {
		name     string
		existing []netip.Prefix
		want     deviceReuse
	}{
		{"absent", nil, deviceAbsent},
		{"carries our virtual ip", []netip.Prefix{ours}, deviceStale},
		{"carries someone else's address", []netip.Prefix{theirs}, deviceForeign},
		{"carries both", []netip.Prefix{theirs, ours}, deviceStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyExistingDevice(tc.existing, ours); got != tc.want {
				t.Fatalf("classifyExistingDevice(%v) = %v; want %v", tc.existing, got, tc.want)
			}
		})
	}
}

// TestStaleDeviceDecisionRejectsUnaddressableOwnAddress pins the degenerate case: if this
// node has no virtual address to look for, no existing interface can be proven ours, so
// none may be reused.
func TestStaleDeviceDecisionRejectsUnaddressableOwnAddress(t *testing.T) {
	if got := classifyExistingDevice([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}, netip.Prefix{}); got != deviceForeign {
		t.Fatalf("classify with no own address = %v; want deviceForeign", got)
	}
}

// TestReuseErrorNamesTheInterface keeps the failure actionable: the operator has to know
// which interface to remove, and why it was not removed automatically.
func TestReuseErrorNamesTheInterface(t *testing.T) {
	err := foreignDeviceError("simpletier0", []netip.Prefix{netip.MustParsePrefix("192.168.7.9/32")})
	if !errors.Is(err, ErrDeviceInUse) {
		t.Fatalf("error = %v; want ErrDeviceInUse", err)
	}
	if msg := err.Error(); !contains(msg, "simpletier0") {
		t.Fatalf("error %q does not name the interface", msg)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
