//go:build windows

package agent

// Exclusive lock for the durable system network journal (Windows build).
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Windows has no flock; the equivalent ownership token is a byte-range lock on
// the journal handle. Both the owner and any competing owner lock the same first
// byte range with LOCKFILE_FAIL_IMMEDIATELY, so the second one fails instead of
// interleaving records. The kernel releases the range if the process dies.
//
// LockFileEx requires the handle to grant GENERIC_READ or GENERIC_WRITE, so the
// journal must be opened O_RDWR (see newResourceJournal): Go strips
// GENERIC_WRITE from an O_APPEND handle, leaving only FILE_APPEND_DATA, which
// LockFileEx rejects with ERROR_ACCESS_DENIED.

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// journalLockOffset is the file offset of the single ownership byte. It sits far
// beyond any journal content on purpose. A Windows byte-range lock is mandatory,
// not advisory: while it is held, every other handle — including a second handle
// opened by the same process — is refused read and write access to the locked
// bytes. Locking byte 0 would therefore break the write-ahead contract that the
// journal exists to provide, because the pre-side-effect read-back (readJournal
// via LoadJournal) opens its own handle. Locking an offset that no record can
// reach keeps the lock a pure ownership token, which is exactly the flock
// semantics the Unix build gets for free.
//
// 1 TiB is a safe ceiling: a journal is a short JSONL record stream bounded by
// the transaction it describes, so no real file approaches it.
const (
	journalLockOffsetLow  = uint32(0)
	journalLockOffsetHigh = uint32(1 << (40 - 32))
)

func lockJournalFile(file *os.File) error {
	overlapped := windows.Overlapped{
		Offset:     journalLockOffsetLow,
		OffsetHigh: journalLockOffsetHigh,
	}
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped,
	)
	if err != nil {
		return fmt.Errorf("another process already owns this journal: %w", err)
	}
	return nil
}

func unlockJournalFile(file *os.File) error {
	overlapped := windows.Overlapped{
		Offset:     journalLockOffsetLow,
		OffsetHigh: journalLockOffsetHigh,
	}
	if err := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped); err != nil {
		return fmt.Errorf("agent: unlock system network journal: %w", err)
	}
	return nil
}
