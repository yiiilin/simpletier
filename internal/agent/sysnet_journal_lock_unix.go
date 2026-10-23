//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package agent

// Exclusive advisory lock for the durable system network journal (Unix builds).
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// The lock is taken on the journal file itself for the lifetime of the owner. It
// is advisory (flock), so it only excludes other owners that take the same lock,
// which is exactly the contract: two SystemNetwork transactions must never
// interleave records in one journal path. The kernel releases it if the process
// dies, so a crashed owner leaves no stale lock behind.

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockJournalFile takes the non-blocking exclusive lock, or reports the current
// holder instead of waiting for it.
func lockJournalFile(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("another process already owns this journal: %w", err)
	}
	return nil
}

// unlockJournalFile releases the lock.
func unlockJournalFile(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		return fmt.Errorf("agent: unlock system network journal: %w", err)
	}
	return nil
}
