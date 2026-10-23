package agent

// Shared write-ahead journal for the platform SystemNetwork owners.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Protocol (record version 2). Every OS side effect is preceded by an "intent"
// record that is written and fsynced before the mutation, and followed by an
// explicit outcome record that is written and fsynced after it:
//
//   - "apply:<resource>" + Outcome=intent      the mutation is about to run, its
//     result is not known yet;
//   - "apply:<resource>" + Outcome=confirmed   the mutation succeeded and the
//     resource belongs to this transaction;
//   - "apply:<resource>" + Outcome=not_owned   the mutation hit an existing
//     resource (EEXIST/ERROR_OBJECT_ALREADY_EXISTS); it is someone else's;
//   - "rollback:<resource>" + Outcome=intent   the undo is about to run;
//   - "rolledback:<resource>"                  the undo completed;
//   - "txn:closed"                             the transaction is terminal: no
//     recovery may act on anything recorded before it.
//
// Every record carries the transaction id and the interface-instance
// fingerprint (ResourceID) of the owner that wrote it. Recovery therefore:
//
//   - ignores whole transactions that have a terminal checkpoint, so a journal
//     path reused by clean transaction cycles can never delete a fresh external
//     resource using the intents of an older, already rolled back transaction;
//   - removes only "apply:<resource>" records with Outcome=confirmed that have
//     no later rolledback record, and only while the live resource still matches
//     the recorded fingerprint exactly;
//   - keeps (and reports Degraded) every pre-version-2 record, every intent
//     without a completion, every uncertain outcome and every resource whose
//     interface instance it cannot reproduce.
//
// Presence of a resource on the host is never accepted as proof of ownership.
//
// Durability discipline:
//
//   - the in-memory copy gains a record only after the file write and fsync
//     succeeded, so a failed journal write can never look like a recorded
//     intent, and Apply never proceeds past a failed intent;
//   - a failed write or fsync poisons the journal, so no later record is
//     accepted through an already-torn tail;
//   - opening a journal whose last byte is not a newline refuses to append: the
//     torn final line is a known boundary that recovery must reconcile first;
//   - the journal file is held under an exclusive OS lock for the lifetime of
//     the owner, so two owners can never interleave records in one path;
//   - record and close share one mutex, so a close can never race a write.
//
// The persisted "kind" and "interface" fields are unchanged (the Linux
// verification and the Windows/macOS owners share this exact type); the
// transaction id, resource id, outcome and version fields are additive.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// journalVersion tags records written by this protocol. Older records carry
	// no version and are always treated as unprovable by recovery.
	journalVersion = 2

	journalOutcomeIntent    = "intent"
	journalOutcomeConfirmed = "confirmed"
	journalOutcomeNotOwned  = "not_owned"
	journalOutcomeUncertain = "uncertain"

	// journalTerminalKind is the transaction-terminal checkpoint. Recovery
	// ignores every record of a transaction that has one.
	journalTerminalKind = "txn:closed"
	// journalTornKind is the synthetic marker a reader adds for an incomplete
	// final record. It is never written to disk.
	journalTornKind = "torn:journal"
)

// errJournalUnusable marks a journal that must not accept more records: it was
// closed, poisoned by a failed write, or opened over a torn tail.
var errJournalUnusable = errors.New("agent: the system network journal is not usable")

// journalEntry is one write-ahead record. Kind is "<phase>:<resource>", Detail
// names the resource, Fingerprint is the recorded resource fingerprint used by
// rollback and recovery to prove ownership, and Outcome says whether the phase
// started (intent) or completed (confirmed/not_owned).
type journalEntry struct {
	Version     int       `json:"version,omitempty"`
	Time        time.Time `json:"time"`
	Kind        string    `json:"kind"`
	Interface   string    `json:"interface"`
	Detail      string    `json:"detail,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Transaction string    `json:"transaction,omitempty"`
	ResourceID  string    `json:"resource_id,omitempty"`
	Outcome     string    `json:"outcome,omitempty"`
}

// resourceJournal is a write-ahead log of intended side effects. It is safe for
// concurrent use; the platform owners additionally serialise their own state
// machine with their own mutex.
type resourceJournal struct {
	mu      sync.Mutex
	entries []journalEntry
	file    *os.File
	locked  bool

	// transaction identifies this owner's transaction in every record it writes.
	transaction string
	// resourceID is the interface-instance fingerprint stamped on every record.
	resourceID string

	closed   bool
	unusable string
}

// ErrJournalLocked reports that another live owner already holds this journal
// path. The caller must not share the path: two SystemNetwork transactions would
// interleave their intents. The lock is an OS lock on the open file, so it is
// released by close or by process death; nothing needs to remove a stale lock
// file, and a cleanup retry can simply reopen the same path.
var ErrJournalLocked = errors.New("agent: system network journal is already owned by another process")

// newJournalTransaction builds a process-unique transaction id. A failure of
// the entropy source still yields a monotonic, collision-resistant value.
func newJournalTransaction() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("t-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("t-%d-%s", time.Now().UnixNano(), hex.EncodeToString(buf[:]))
}

// newInstanceToken builds the unpredictable ownership marker a platform owner
// writes into the interface instance (for example the Linux IFLA_IFALIAS). A
// recovery run accepts the instance only when the live marker is this exact
// value, so a reused interface name/index can never inherit another
// transaction's resources.
func newInstanceToken() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("inst-%d", time.Now().UnixNano())
	}
	return "inst-" + hex.EncodeToString(buf[:])
}

// newResourceJournal opens the optional durable journal file and takes its
// exclusive lock. An empty path keeps the journal in memory for the lifetime of
// the transaction.
func newResourceJournal(path string) (*resourceJournal, error) {
	journal := &resourceJournal{transaction: newJournalTransaction()}
	if path == "" {
		return journal, nil
	}
	torn, err := journalHasTornTail(path)
	if err != nil {
		return nil, err
	}
	// O_RDWR rather than O_WRONLY is required for the exclusive lock to be
	// obtainable on Windows. Go maps O_APPEND to FILE_APPEND_DATA and, when
	// O_TRUNC is absent, strips GENERIC_WRITE from the access mask
	// (syscall.openFile in syscall_windows.go); LockFileEx refuses a handle
	// that grants neither GENERIC_READ nor GENERIC_WRITE, so an O_WRONLY handle
	// fails the lock with ERROR_ACCESS_DENIED and the journal can never be
	// created. O_RDWR keeps GENERIC_READ, and FILE_APPEND_DATA still forces
	// every write to the end of the file. Read access is harmless: the records
	// are already readable through LoadJournal.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("agent: open system network journal %q: %w", path, err)
	}
	if err := lockJournalFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: journal %q: %v", ErrJournalLocked, path, err)
	}
	journal.file = file
	journal.locked = true
	if torn {
		// Appending after a partial line would corrupt the record boundary. The
		// journal stays readable for recovery and refuses new records instead.
		journal.unusable = fmt.Sprintf("journal %q ends with an incomplete record; reconcile it before writing", path)
	}
	return journal, nil
}

// journalHasTornTail reports whether an existing journal file ends in the
// middle of a record. A missing or empty file is not torn.
func journalHasTornTail(path string) (bool, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("agent: read system network journal %q: %w", path, err)
	}
	if len(payload) == 0 {
		return false, nil
	}
	return payload[len(payload)-1] != '\n', nil
}

// setResourceID records the interface-instance fingerprint this owner journals
// against. It is called from Prepare, before the first intent.
func (j *resourceJournal) setResourceID(id string) {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.resourceID = id
}

// beginTransaction starts a new transaction id on the same open journal file. It
// is used by an owner that keeps one device open and retargets its address: the
// previous transaction must already have written its terminal checkpoint (a
// completed, non-degraded rollback), and the fresh id keeps the new records
// from being read as part of the old transaction. The file and its exclusive OS
// lock stay open throughout, so another process can never interleave a second
// owner on this path. It refuses to start a new transaction while the current
// one has no terminal record, because that would leave unproven ownership
// behind an active new transaction.
func (j *resourceJournal) beginTransaction() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return fmt.Errorf("%w: it is closed", errJournalUnusable)
	}
	if j.unusable != "" {
		return fmt.Errorf("%w: %s", errJournalUnusable, j.unusable)
	}
	terminal := false
	for _, entry := range j.entries {
		if entry.Kind == journalTerminalKind && entry.Transaction == j.transaction {
			terminal = true
			break
		}
	}
	if !terminal {
		return fmt.Errorf("%w: the current transaction has no terminal checkpoint; roll it back before starting a new one", ErrInvalidConfig)
	}
	j.transaction = newJournalTransaction()
	// The instance fingerprint is re-stamped by the next Prepare, which reads
	// the live kernel alias again.
	j.resourceID = ""
	return nil
}

// record writes one intent. A journal write failure must abort the side effect,
// because the port contract requires intent-before-effect.
func (j *resourceJournal) record(kind, resource, interfaceName, detail, fingerprint string) error {
	return j.appendRecord(journalEntry{
		Kind:        kind + ":" + resource,
		Interface:   interfaceName,
		Detail:      detail,
		Fingerprint: fingerprint,
		Outcome:     journalOutcomeIntent,
	})
}

// confirm writes the explicit outcome of an intent that already ran. The record
// is written and fsynced before the caller continues, so a crash can always
// distinguish "the mutation never ran" from "the mutation ran and succeeded".
func (j *resourceJournal) confirm(kind, resource, interfaceName, detail, fingerprint, outcome string) error {
	return j.appendRecord(journalEntry{
		Kind:        kind + ":" + resource,
		Interface:   interfaceName,
		Detail:      detail,
		Fingerprint: fingerprint,
		Outcome:     outcome,
	})
}

// terminal appends the transaction-terminal checkpoint. Recovery ignores every
// record of a transaction that has one, so a clean rollback can never be
// replayed by a later recovery run on the same journal path.
func (j *resourceJournal) terminal(interfaceName, detail string) error {
	return j.appendRecord(journalEntry{
		Kind:      journalTerminalKind,
		Interface: interfaceName,
		Detail:    detail,
		Outcome:   journalOutcomeConfirmed,
	})
}

// appendRecord persists one record before it becomes visible in memory. A failed
// marshal, write or fsync neither appends the memory entry nor leaves the
// journal writable: the contract forbids a recorded intent that is not durable
// and a durable tail that is no longer trustworthy.
func (j *resourceJournal) appendRecord(entry journalEntry) error {
	if j == nil {
		return nil
	}
	entry.Version = journalVersion
	entry.Time = time.Now().UTC()
	if entry.Transaction == "" {
		entry.Transaction = j.transaction
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return fmt.Errorf("%w: it is closed", errJournalUnusable)
	}
	if j.unusable != "" {
		return fmt.Errorf("%w: %s", errJournalUnusable, j.unusable)
	}
	if entry.ResourceID == "" {
		entry.ResourceID = j.resourceID
	}
	if j.file == nil {
		j.entries = append(j.entries, entry)
		return nil
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		j.unusable = fmt.Sprintf("marshal journal entry: %v", err)
		return fmt.Errorf("agent: marshal journal entry: %w", err)
	}
	if _, err := j.file.Write(append(payload, '\n')); err != nil {
		j.unusable = fmt.Sprintf("write system network journal: %v", err)
		return fmt.Errorf("agent: write system network journal: %w", err)
	}
	if err := j.file.Sync(); err != nil {
		j.unusable = fmt.Sprintf("sync system network journal: %v", err)
		return fmt.Errorf("agent: sync system network journal: %w", err)
	}
	j.entries = append(j.entries, entry)
	return nil
}

// snapshot returns a copy of the in-memory journal.
func (j *resourceJournal) snapshot() []journalEntry {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]journalEntry(nil), j.entries...)
}

// close releases the durable journal file and its lock. It is idempotent. The
// journal mutex is held across the unlock and close, so a concurrent record can
// never write through a closed file.
func (j *resourceJournal) close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	var errs []error
	if j.file != nil {
		if j.locked {
			if err := unlockJournalFile(j.file); err != nil {
				errs = append(errs, err)
			}
			j.locked = false
		}
		if err := j.file.Close(); err != nil {
			errs = append(errs, err)
		}
		j.file = nil
	}
	return errors.Join(errs...)
}

// JournalEntry is the exported view of one write-ahead record. A host reads it
// through LoadJournal to reconcile after a crash, because the in-memory journal
// alone is not a durable write-ahead log.
type JournalEntry struct {
	Time        time.Time
	Kind        string
	Interface   string
	Detail      string
	Fingerprint string
	// Version is the record protocol version; zero means a pre-protocol record
	// whose ownership can never be proven.
	Version int
	// Transaction is the transaction id that wrote the record.
	Transaction string
	// ResourceID is the interface-instance fingerprint the transaction ran
	// against (Linux ifindex, Windows LUID, macOS interface index).
	ResourceID string
	// Outcome is intent, confirmed, not_owned or uncertain.
	Outcome string
}

// JournalRead is the parsed form of one persisted journal. TornTail reports an
// incomplete final record: the reader stops at that known boundary instead of
// guessing, and appends a journalTornKind marker so a caller can act
// conservatively.
type JournalRead struct {
	Entries  []JournalEntry
	TornTail bool
}

// readJournal parses a persisted journal. A malformed line in the middle is
// corruption and fails; a malformed final line is a torn append and stops the
// parse at the known boundary.
func readJournal(path string) (JournalRead, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return JournalRead{}, fmt.Errorf("agent: read system network journal %q: %w", path, err)
	}
	var result JournalRead
	lines := strings.Split(string(payload), "\n")
	lastInterface := ""
	for number, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var record journalEntry
		if err := json.Unmarshal([]byte(trimmed), &record); err != nil {
			if number == len(lines)-1 {
				result.TornTail = true
				result.Entries = append(result.Entries, JournalEntry{
					Time:      time.Now().UTC(),
					Kind:      journalTornKind,
					Interface: lastInterface,
					Detail:    "incomplete final record",
					Outcome:   journalOutcomeUncertain,
				})
				break
			}
			return JournalRead{}, fmt.Errorf("agent: journal %q line %d: %w", path, number+1, err)
		}
		if record.Interface != "" {
			lastInterface = record.Interface
		}
		result.Entries = append(result.Entries, JournalEntry{
			Time:        record.Time,
			Kind:        record.Kind,
			Interface:   record.Interface,
			Detail:      record.Detail,
			Fingerprint: record.Fingerprint,
			Version:     record.Version,
			Transaction: record.Transaction,
			ResourceID:  record.ResourceID,
			Outcome:     record.Outcome,
		})
	}
	return result, nil
}

// LoadJournal reads a persisted write-ahead journal (one JSON record per line).
// It is the read half of crash recovery: platform owners decide which journaled
// resources still match their fingerprint and remove only those. A torn final
// record is reported as a journalTornKind entry rather than silently dropped.
func LoadJournal(path string) ([]JournalEntry, error) {
	result, err := readJournal(path)
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}

// RecoveryReport is the outcome of reconciling one persisted journal.
//
// Removed lists resources this instance provably created and that still matched
// their fingerprint. Kept lists resources that were absent, pre-existing,
// already rolled back or externally modified; they are never deleted. Degraded
// explains every resource whose ownership could not be proven.
type RecoveryReport struct {
	Interface string
	Removed   []string
	Kept      []string
	Degraded  []string
}

func (r *RecoveryReport) remove(resource string) {
	r.Removed = append(r.Removed, resource)
}

func (r *RecoveryReport) keep(resource string) {
	r.Kept = append(r.Kept, resource)
}

func (r *RecoveryReport) degrade(resource, reason string) {
	r.Degraded = append(r.Degraded, reason)
	r.Kept = append(r.Kept, resource)
}

// reportLegacyJournal degrades every record that predates the transaction
// protocol and every incomplete final record. Such a record can never prove
// ownership, so the live resource is kept.
func reportLegacyJournal(report *RecoveryReport, view interfaceJournal) {
	for _, entry := range view.Legacy {
		report.degrade(entry.Kind+" "+entry.Detail,
			"the journal record predates transaction ids; ownership cannot be proven and the live resource is kept")
	}
	if view.TornTail {
		report.degrade("journal tail",
			"the journal ends with an incomplete record; any effect it describes is kept")
	}
}

// interfaceJournal is the transaction-aware view of one interface in a loaded
// journal.
type interfaceJournal struct {
	// Legacy lists pre-version-2 apply records of this interface. They carry no
	// transaction id, so their effect can never be attributed to this instance.
	Legacy []JournalEntry
	// TornTail reports an incomplete final record that may hide an effect.
	TornTail bool
	// Transaction is the newest transaction id recorded for the interface.
	Transaction string
	// Active lists that transaction's records for the interface, in order.
	Active []JournalEntry
	// Terminal reports that the newest transaction has a close checkpoint.
	Terminal bool
}

// selectInterfaceJournal groups a loaded journal by transaction for one
// interface. Only the newest transaction is actionable; older transactions are
// either terminal (ignored) or superseded by the newest one.
func selectInterfaceJournal(entries []JournalEntry, interfaceName string) interfaceJournal {
	var view interfaceJournal
	newest := ""
	for _, entry := range entries {
		if entry.Kind == journalTornKind {
			if entry.Interface == "" || entry.Interface == interfaceName {
				view.TornTail = true
			}
			continue
		}
		if entry.Interface != interfaceName {
			continue
		}
		if entry.Transaction == "" {
			if strings.HasPrefix(entry.Kind, "apply:") {
				view.Legacy = append(view.Legacy, entry)
			}
			continue
		}
		newest = entry.Transaction
	}
	if newest == "" {
		return view
	}
	view.Transaction = newest
	for _, entry := range entries {
		if entry.Interface != interfaceName || entry.Transaction != newest {
			continue
		}
		view.Active = append(view.Active, entry)
		if entry.Kind == journalTerminalKind {
			view.Terminal = true
		}
	}
	return view
}

// journalOwnership is the per-resource verdict of one transaction.
type journalOwnership struct {
	// Owned holds confirmed applies that were not rolled back, in apply order.
	Owned []JournalEntry
	// Uncertain holds resources whose effect or undo is unfinished.
	Uncertain []JournalEntry
	// NotOwned holds applies that lost the race to an existing resource.
	NotOwned []JournalEntry
	// RolledBack holds resources whose undo completed.
	RolledBack []JournalEntry
}

// ownershipFromJournal derives the ownership verdict of one transaction from
// its records. A resource is owned only when its apply record was explicitly
// confirmed and no later rollback touched it. Resources of the same type are
// keyed by their detail (route prefix, address prefix, MTU value), so several
// routes or addresses never collapse into one verdict.
func ownershipFromJournal(active []JournalEntry) journalOwnership {
	type resourceState struct {
		entry     JournalEntry
		confirmed bool
		notOwned  bool
		finished  bool
		undoing   bool
	}
	order := make([]string, 0, len(active))
	states := make(map[string]*resourceState)
	state := func(key string) *resourceState {
		entry, ok := states[key]
		if !ok {
			entry = &resourceState{}
			states[key] = entry
			order = append(order, key)
		}
		return entry
	}
	for _, entry := range active {
		phase, resource, ok := strings.Cut(entry.Kind, ":")
		if !ok {
			continue
		}
		key := resource + "\x00" + entry.Detail
		switch phase {
		case "apply", "applied":
			current := state(key)
			// Normalise the confirmation phase onto the intent resource name so
			// callers can switch on "<resource>" alone.
			entry.Kind = "apply:" + resource
			current.entry = entry
			switch entry.Outcome {
			case journalOutcomeConfirmed:
				current.confirmed = true
			case journalOutcomeNotOwned:
				current.notOwned = true
			case journalOutcomeUncertain:
				current.confirmed = false
			default:
				current.confirmed = false
			}
		case "rollback", "rolledback":
			current := state(key)
			if phase == "rolledback" {
				current.confirmed = false
				current.notOwned = false
				current.finished = true
				current.undoing = false
				continue
			}
			entry.Kind = "apply:" + resource
			current.entry = entry
			current.undoing = true
		}
	}
	var result journalOwnership
	for _, key := range order {
		current := states[key]
		switch {
		case current.finished:
			result.RolledBack = append(result.RolledBack, current.entry)
		case current.undoing:
			result.Uncertain = append(result.Uncertain, current.entry)
		case current.confirmed:
			result.Owned = append(result.Owned, current.entry)
		case current.notOwned:
			result.NotOwned = append(result.NotOwned, current.entry)
		default:
			result.Uncertain = append(result.Uncertain, current.entry)
		}
	}
	return result
}

// journalInstanceMatches reports whether every actionable record of one
// transaction carries the interface-instance fingerprint the recovery run
// observed. A missing fingerprint is not a match: it cannot prove ownership.
func journalInstanceMatches(entries []JournalEntry, want string) bool {
	if want == "" {
		return false
	}
	for _, entry := range entries {
		if entry.Kind == journalTerminalKind {
			continue
		}
		if entry.ResourceID == "" || entry.ResourceID != want {
			return false
		}
	}
	return true
}

// encodeJournalFields builds the "key=value;key=value" resource fingerprint a
// journal record carries. Values must not contain ';' or '='.
func encodeJournalFields(pairs ...[2]string) string {
	parts := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		parts = append(parts, pair[0]+"="+pair[1])
	}
	return strings.Join(parts, ";")
}

// decodeJournalFields reads a "key=value;key=value" fingerprint. It is
// deliberately permissive: a missing key simply stays absent, so a caller can
// treat an incomplete fingerprint as unprovable instead of guessing.
func decodeJournalFields(raw string) map[string]string {
	fields := make(map[string]string)
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		fields[key] = value
	}
	return fields
}

// journalDetailResource names one journaled resource for a report.
func journalDetailResource(entry JournalEntry) string {
	if entry.Detail == "" {
		return strings.TrimPrefix(entry.Kind, "apply:")
	}
	return entry.Detail
}
