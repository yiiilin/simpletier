//go:build linux || darwin

package testlock

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockFileName is deliberately stable and host-global: every process that runs
// these tests must contend on the same file.
const lockFileName = "simpletier-host-network-tests.lock"

func acquire() (func(), error) {
	path := filepath.Join(os.TempDir(), lockFileName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("testlock: open %s: %w", path, err)
	}
	// A blocking lock: the other package finishes its interface work and the
	// kernel releases the lock when that process exits, including on a crash.
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("testlock: lock %s: %w", path, err)
	}
	return func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}, nil
}
