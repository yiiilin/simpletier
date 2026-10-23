//go:build !linux && !darwin && !windows

package agent

// Honest refusal for GOOS values outside the three confirmed P1 platforms.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Requirement anchor (prose, not an ownership pointer): R-L3-001; the L3
// feature prose path is docs/domains/overlay/features/l3-vpn.md.
//
// This file exists so the package still builds (and reports a diagnosable error)
// on every other GOOS. It never fabricates a device.

import (
	"fmt"
)

// resolveHostAdapter implements the per-GOOS dispatch declared by
// ResolveHostAdapter for every unsupported GOOS.
func resolveHostAdapter(platform Platform) (HostAdapter, error) {
	return nil, fmt.Errorf("%w: the %s host adapter is not implemented for GOOS %s; P1 covers linux TUN, windows Wintun and darwin utun",
		ErrPlatformUnavailable, platform, CurrentPlatform())
}
