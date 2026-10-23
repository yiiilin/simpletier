//go:build linux

package packet

import (
	"os"
	"testing"

	"github.com/yiiilin/simpletier/internal/testlock"
)

// TestMain serializes this package against the other test packages that create
// host-global network interfaces.
//
// This package opens real TUN devices ("k<counter>"). tests/tun_acceptance
// snapshots the host interface set before and after its run and asserts the set
// is unchanged, so concurrent execution under `go test ./...` would make that
// acceptance assertion observe an interface this package created or removed.
//
// Taking the same lock keeps the acceptance snapshot at full strength instead
// of filtering this package's interfaces out of it.
func TestMain(m *testing.M) {
	release, err := testlock.Acquire()
	if err != nil {
		os.Stderr.WriteString("packet: host-network test lock unavailable: " + err.Error() + "\n")
		os.Exit(m.Run())
	}
	code := m.Run()
	release()
	os.Exit(code)
}
