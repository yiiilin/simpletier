package agent

// Protocol-level verification for the shared write-ahead journal.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// These tests are GOOS-independent: they exercise the transaction grouping, the
// ownership verdicts, the torn-tail boundary, the durability ordering and the
// exclusive lock that every platform owner shares. The real-kernel behaviour is
// covered by sysnet_linux_test.go, and the Windows/macOS owners are covered by
// their build-tagged tests.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testJournalEntry(txn, kind, interfaceName, detail, fingerprint, outcome string) JournalEntry {
	return JournalEntry{
		Version:     journalVersion,
		Time:        time.Now().UTC(),
		Kind:        kind,
		Interface:   interfaceName,
		Detail:      detail,
		Fingerprint: fingerprint,
		Transaction: txn,
		ResourceID:  "instance=1",
		Outcome:     outcome,
	}
}

func TestJournalSelectsOnlyTheNewestTransactionAndHonoursTerminal(t *testing.T) {
	entries := []JournalEntry{
		testJournalEntry("old", "apply:address", "if0", "10.0.0.1/32", "", journalOutcomeConfirmed),
		{Version: journalVersion, Time: time.Now().UTC(), Kind: journalTerminalKind, Interface: "if0", Detail: "rolledback", Transaction: "old", ResourceID: "instance=1", Outcome: journalOutcomeConfirmed},
		testJournalEntry("new", "apply:route", "if0", "10.9.0.0/24", "", journalOutcomeIntent),
		testJournalEntry("new", "apply:route", "if0", "10.9.0.0/24", "", journalOutcomeConfirmed),
	}
	view := selectInterfaceJournal(entries, "if0")
	if view.Transaction != "new" {
		t.Fatalf("selected transaction %q, want the newest %q", view.Transaction, "new")
	}
	if view.Terminal {
		t.Fatal("the newest transaction has no terminal checkpoint")
	}
	ownership := ownershipFromJournal(view.Active)
	if len(ownership.Owned) != 1 || ownership.Owned[0].Kind != "apply:route" {
		t.Fatalf("ownership = %+v, want the confirmed route owned", ownership)
	}

	// A terminal checkpoint on the newest transaction makes the whole
	// transaction inert, even though it confirmed an effect.
	entries = append(entries, JournalEntry{
		Version: journalVersion, Time: time.Now().UTC(), Kind: journalTerminalKind,
		Interface: "if0", Detail: "rolledback", Transaction: "new", ResourceID: "instance=1", Outcome: journalOutcomeConfirmed,
	})
	view = selectInterfaceJournal(entries, "if0")
	if !view.Terminal {
		t.Fatal("the terminal checkpoint of the newest transaction was not seen")
	}
}

func TestJournalOwnershipVerdicts(t *testing.T) {
	active := []JournalEntry{
		testJournalEntry("t", "apply:mtu", "if0", "mtu=1380", "prior=1500", journalOutcomeIntent),
		testJournalEntry("t", "apply:mtu", "if0", "mtu=1380", "prior=1500", journalOutcomeConfirmed),
		// Confirmed, then rolled back: no longer owned.
		testJournalEntry("t", "apply:address", "if0", "10.0.0.1/32", "", journalOutcomeIntent),
		testJournalEntry("t", "apply:address", "if0", "10.0.0.1/32", "", journalOutcomeConfirmed),
		testJournalEntry("t", "rollback:address", "if0", "10.0.0.1/32", "", journalOutcomeIntent),
		testJournalEntry("t", "rolledback:address", "if0", "10.0.0.1/32", "", journalOutcomeConfirmed),
		// Confirmed effect, rollback started but never completed: uncertain.
		testJournalEntry("t", "apply:route", "if0", "10.0.9.0/24", "", journalOutcomeIntent),
		testJournalEntry("t", "apply:route", "if0", "10.0.9.0/24", "", journalOutcomeConfirmed),
		testJournalEntry("t", "rollback:route", "if0", "10.0.9.0/24", "", journalOutcomeIntent),
		// Intent never confirmed, even though the resource exists.
		testJournalEntry("t", "apply:link_up", "if0", "if0", "was down", journalOutcomeIntent),
		// Lost the race to an existing resource.
		testJournalEntry("t", "apply:address", "if0", "10.0.0.2/32", "", journalOutcomeIntent),
		testJournalEntry("t", "apply:address", "if0", "10.0.0.2/32", "", journalOutcomeNotOwned),
	}
	ownership := ownershipFromJournal(active)
	if len(ownership.Owned) != 1 || ownership.Owned[0].Kind != "apply:mtu" {
		t.Fatalf("Owned = %+v, want only the confirmed MTU", ownership.Owned)
	}
	if len(ownership.RolledBack) != 1 || ownership.RolledBack[0].Kind != "apply:address" {
		t.Fatalf("RolledBack = %+v, want the rolled back address", ownership.RolledBack)
	}
	if len(ownership.NotOwned) != 1 || ownership.NotOwned[0].Kind != "apply:address" {
		t.Fatalf("NotOwned = %+v, want the address that lost the race", ownership.NotOwned)
	}
	// The route (rollback in flight) and the unconfirmed link_up are uncertain.
	if len(ownership.Uncertain) != 2 {
		t.Fatalf("Uncertain = %+v, want the in-flight route and the unconfirmed link", ownership.Uncertain)
	}
	for _, entry := range ownership.Uncertain {
		if entry.Kind != "apply:route" && entry.Kind != "apply:link_up" {
			t.Fatalf("unexpected uncertain entry %+v", entry)
		}
	}
}

func TestJournalLegacyRecordsAreSelectedSeparately(t *testing.T) {
	entries := []JournalEntry{
		{Time: time.Now().UTC(), Kind: "apply:address", Interface: "if0", Detail: "10.0.0.1/32"},
		testJournalEntry("t", "apply:address", "if0", "10.0.0.2/32", "", journalOutcomeConfirmed),
	}
	view := selectInterfaceJournal(entries, "if0")
	if len(view.Legacy) != 1 {
		t.Fatalf("Legacy = %+v, want one pre-protocol record", view.Legacy)
	}
	if view.Transaction != "t" {
		t.Fatalf("transaction = %q, want t", view.Transaction)
	}
	report := RecoveryReport{Interface: "if0"}
	reportLegacyJournal(&report, view)
	if len(report.Degraded) != 1 || !strings.Contains(report.Degraded[0], "predates transaction ids") {
		t.Fatalf("report = %+v, want the legacy record degraded", report)
	}
	if len(report.Removed) != 0 {
		t.Fatalf("report.Removed = %v, want nothing removed for a legacy record", report.Removed)
	}
}

func TestJournalReadStopsAtTornTailBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "torn.jsonl")
	complete, err := json.Marshal(testJournalEntry("t", "apply:address", "if0", "10.0.0.1/32", "", journalOutcomeIntent))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	payload := string(complete) + "\n" + `{"kind":"apply:addr`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	loaded, err := readJournal(path)
	if err != nil {
		t.Fatalf("readJournal: %v", err)
	}
	if !loaded.TornTail {
		t.Fatal("a partially written final line must be reported as a torn tail")
	}
	if len(loaded.Entries) != 2 {
		t.Fatalf("entries = %d, want the complete record plus the torn marker", len(loaded.Entries))
	}
	if loaded.Entries[1].Kind != journalTornKind {
		t.Fatalf("marker kind = %q, want %q", loaded.Entries[1].Kind, journalTornKind)
	}
	view := selectInterfaceJournal(loaded.Entries, "if0")
	if !view.TornTail {
		t.Fatal("the torn tail was not attributed to the interface")
	}
	// LoadJournal keeps its published signature and surfaces the boundary too.
	entries, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal: %v", err)
	}
	if len(entries) != len(loaded.Entries) {
		t.Fatalf("LoadJournal entries = %d, want %d", len(entries), len(loaded.Entries))
	}

	// A malformed line in the middle is corruption, not a torn tail.
	corrupt := filepath.Join(t.TempDir(), "corrupt.jsonl")
	if err := os.WriteFile(corrupt, []byte("not json\n{also not json}\n"), 0o600); err != nil {
		t.Fatalf("write corrupt journal: %v", err)
	}
	if _, err := readJournal(corrupt); err == nil {
		t.Fatal("a malformed middle line must fail, not be skipped")
	}
}

func TestJournalTornTailRefusesNewRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "torn.jsonl")
	if err := os.WriteFile(path, []byte(`{"kind":"apply:addr`), 0o600); err != nil {
		t.Fatalf("write torn journal: %v", err)
	}
	journal, err := newResourceJournal(path)
	if err != nil {
		t.Fatalf("newResourceJournal: %v", err)
	}
	defer func() { _ = journal.close() }()
	if err := journal.record("apply", "address", "if0", "10.0.0.1/32", ""); err == nil {
		t.Fatal("appending after a torn tail must fail closed")
	}
	if got := len(journal.snapshot()); got != 0 {
		t.Fatalf("the in-memory journal gained %d entries from a refused write", got)
	}
}

func TestJournalFailedWriteNeverAppendsMemoryEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "poison.jsonl")
	journal, err := newResourceJournal(path)
	if err != nil {
		t.Fatalf("newResourceJournal: %v", err)
	}
	// Close the file behind the journal's back: the next write fails. A failed
	// journal write must abort the side effect and must not become a visible
	// intent, because intent-before-effect cannot be claimed.
	if err := journal.file.Close(); err != nil {
		t.Fatalf("close journal file: %v", err)
	}
	if err := journal.record("apply", "address", "if0", "10.0.0.1/32", ""); err == nil {
		t.Fatal("record over a closed file must fail")
	}
	if got := len(journal.snapshot()); got != 0 {
		t.Fatalf("the in-memory journal recorded %d entries despite a failed write", got)
	}
	// The journal is poisoned: a later record cannot slip past the torn tail.
	if err := journal.record("apply", "route", "if0", "10.0.0.0/24", ""); err == nil {
		t.Fatal("a poisoned journal must refuse every later record")
	}
	if got := len(journal.snapshot()); got != 0 {
		t.Fatalf("the in-memory journal recorded %d entries after poisoning", got)
	}
}

func TestJournalHoldsExclusiveLockForItsLifetime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked.jsonl")
	first, err := newResourceJournal(path)
	if err != nil {
		t.Fatalf("first owner: %v", err)
	}
	if _, err := newResourceJournal(path); err == nil {
		t.Fatal("a second journal owner must be rejected while the first holds the lock")
	}
	if err := first.close(); err != nil {
		t.Fatalf("close first owner: %v", err)
	}
	second, err := newResourceJournal(path)
	if err != nil {
		t.Fatalf("after the first owner closed, a new owner must succeed: %v", err)
	}
	if err := second.record("apply", "address", "if0", "10.0.0.1/32", ""); err != nil {
		t.Fatalf("record after reacquiring the lock: %v", err)
	}
	if err := second.close(); err != nil {
		t.Fatalf("close second owner: %v", err)
	}
}

func TestJournalRecordAfterCloseIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "closed.jsonl")
	journal, err := newResourceJournal(path)
	if err != nil {
		t.Fatalf("newResourceJournal: %v", err)
	}
	if err := journal.record("apply", "address", "if0", "10.0.0.1/32", ""); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := journal.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := journal.close(); err != nil {
		t.Fatalf("second close must be a no-op: %v", err)
	}
	if err := journal.record("apply", "address", "if0", "10.0.0.1/32", ""); err == nil {
		t.Fatal("record after close must fail")
	}
}

// TestJournalConcurrentCloseAndRecord runs under -race: the record and close
// paths share the journal mutex, so a close can never write through a released
// file descriptor.
func TestJournalConcurrentCloseAndRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.jsonl")
	journal, err := newResourceJournal(path)
	if err != nil {
		t.Fatalf("newResourceJournal: %v", err)
	}
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for index := 0; index < 32; index++ {
				// Errors are expected once the journal closes; the race detector
				// is the assertion here.
				_ = journal.record("apply", "route", fmt.Sprintf("if%d", worker), fmt.Sprintf("10.%d.%d.0/24", worker, index), "")
			}
		}(worker)
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		_ = journal.close()
	}()
	wait.Wait()
}

func TestJournalFieldEncodingRoundTrip(t *testing.T) {
	raw := encodeJournalFields(
		[2]string{"dst", "10.9.0.0/24"},
		[2]string{"oif", "5"},
		[2]string{"gateway", "none"},
	)
	fields := decodeJournalFields(raw)
	if fields["dst"] != "10.9.0.0/24" || fields["oif"] != "5" || fields["gateway"] != "none" {
		t.Fatalf("decode(%q) = %v", raw, fields)
	}
	// An incomplete fingerprint stays incomplete: a caller must not silently
	// treat a missing key as a wildcard.
	if _, ok := decodeJournalFields("dst=10.9.0.0/24")["oif"]; ok {
		t.Fatal("a missing field must stay absent")
	}
}

func TestJournalInstanceMatchingRequiresEveryRecord(t *testing.T) {
	entries := []JournalEntry{
		testJournalEntry("t", "apply:address", "if0", "10.0.0.1/32", "", journalOutcomeConfirmed),
	}
	if !journalInstanceMatches(entries, "instance=1") {
		t.Fatal("the matching interface instance must be accepted")
	}
	if journalInstanceMatches(entries, "instance=2") {
		t.Fatal("a different interface instance must not be accepted")
	}
	entries[0].ResourceID = ""
	if journalInstanceMatches(entries, "instance=1") {
		t.Fatal("a missing resource id cannot prove the interface instance")
	}
}
