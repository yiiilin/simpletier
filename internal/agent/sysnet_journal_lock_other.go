//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package agent

// Journal locking on GOOS values that own no host network transaction.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Such a build never creates a real owner (see sysnet_unsupported.go), so there
// is no second owner to exclude; the hooks exist only to keep the shared journal
// compiling everywhere.

import "os"

func lockJournalFile(*os.File) error { return nil }

func unlockJournalFile(*os.File) error { return nil }
