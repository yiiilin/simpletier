//go:build linux

package tun_acceptance

import (
	"os"
	"testing"

	"github.com/yiiilin/simpletier/internal/testlock"
)

// TestMain serializes this package against the other test package in this
// repository that creates host-global network interfaces.
//
// This package asserts that the host interface set is byte-identical before and
// after its run. internal/agent's device tests open real TUN devices under
// short "st<hex>" names, so when `go test ./...` runs both packages at once the
// other package's interface appears or disappears inside this package's
// before/after window and the assertion reports a removal this package did not
// cause.
//
// Taking the lock here keeps the acceptance snapshot at full strength: the
// interference is removed instead of being filtered out of the snapshot.
// internal/agent acquires the same lock, so the two packages run serially with
// respect to each other while remaining free to run in parallel with packages
// that do not touch host interfaces.
func TestMain(m *testing.M) {
	release, err := testlock.Acquire()
	if err != nil {
		// The lock is an isolation aid; failing to take it must not hide real
		// acceptance results. Report and continue, as the pre-existing behaviour.
		os.Stderr.WriteString("tun_acceptance: host-network test lock unavailable: " + err.Error() + "\n")
		os.Exit(m.Run())
	}
	code := m.Run()
	release()
	os.Exit(code)
}
