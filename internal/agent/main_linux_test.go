//go:build linux

package agent

import (
	"os"
	"testing"

	"github.com/yiiilin/simpletier/internal/testlock"
)

// TestMain serializes this package against tests/tun_acceptance.
//
// The device tests here open real TUN devices whose names are short "st<hex>"
// strings. tests/tun_acceptance snapshots the host interface set before and
// after its run and asserts the set is unchanged, so if both packages execute
// concurrently under `go test ./...` the acceptance assertion observes this
// package's interface being created or removed and reports a host mutation that
// the acceptance test did not perform.
//
// Both packages take the same host-network test lock, so they no longer overlap.
// The acceptance snapshot keeps its full strength; nothing is filtered out of
// it.
func TestMain(m *testing.M) {
	release, err := testlock.Acquire()
	if err != nil {
		os.Stderr.WriteString("agent: host-network test lock unavailable: " + err.Error() + "\n")
		os.Exit(m.Run())
	}
	code := m.Run()
	release()
	os.Exit(code)
}
