//go:build !linux && !windows && !darwin

package agent

// SystemNetwork on GOOS values that own no host network transaction.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Linux, Windows and macOS each ship their own native owner in the matching
// build-tagged file (sysnet_linux.go, sysnet_windows.go and the macOS owner).
// Every other GOOS can still build the package, but asking for a Linux, Windows
// or macOS network transaction in a process that is not that platform is a
// foreign-build error. The PacketDevice backends are unaffected: a missing
// address/route transaction is reported, never faked.

import (
	"fmt"
)

// newSystemNetwork implements the per-GOOS dispatch declared by
// NewSystemNetwork for every GOOS without a native owner.
func newSystemNetwork(platform Platform, opts SystemNetworkOptions) (SystemNetwork, error) {
	switch platform {
	case PlatformLinux, PlatformWindows, PlatformDarwin:
		return nil, fmt.Errorf("%w: the %s host network owner needs a %s build", ErrNetworkConfigUnavailable, platform, platform)
	default:
		return nil, fmt.Errorf("%w: no host network owner for platform %q", ErrNetworkConfigUnavailable, platform)
	}
}
