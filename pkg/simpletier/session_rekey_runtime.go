package simpletier

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/yiiilin/simpletier/internal/circuit"
	"github.com/yiiilin/simpletier/internal/session"
	"github.com/yiiilin/simpletier/internal/wire"
)

// This file is the INNER SESSION rekey runtime: the source-driven key rotation
// of one already established Path+Session, on the SAME SessionID, class, lane
// and Path, without ever recreating a protector or resetting a replay window.
//
// Lifecycle (both endpoints keep serving the old epoch until the matching
// SESSION_READY commits the new one):
//
//	source poll: tx/rx NeedsRekey -> Session.Rekey (coalesced) -> SESSION_CTRL
//	target:      HandleOpen accepts committedAttempt+1 -> reply SESSION_CTRL
//	source:      HandleOpen NoiseFinish -> SESSION_READY
//	target:      HandleReady commits root/epoch -> install both protectors ->
//	             reverse SESSION_READY (old business keeps flowing meanwhile)
//	source:      HandleReady commits root/epoch -> install both protectors
//
// Contract points enforced here:
//   - exactly one coalesced next attempt per entry (rekeyPending);
//   - the next attempt is always committedAttempt+1 / targetEpoch+1 (the
//     session package itself rejects stale/future attempts; this file only
//     freezes the identity the ctrl/ready handlers validate against);
//   - the epoch stamped into an envelope is the TX protector's installed
//     CurrentEpoch at seal time, read under entry.txMu so an install can never
//     race a seal; already-queued ciphertext keeps the epoch it was built with;
//   - both protectors are preflighted (CanInstallEpoch) before either is
//     mutated, so the frozen third-install grace can never half-install or drop
//     the old key early;
//   - that grace deferral is BOUNDED: it is retried every poll, but if the
//     retained previous epoch's grace clock never starts the install can never
//     complete, so after one frozen epoch-grace budget the affected Session/Path
//     is failed scoped (staged ciphertext released, Circuits failed with
//     ErrSessionLost) instead of leaving an active Session committed ahead of
//     its protectors forever;
//   - the worker that starts a rekey is bounded and reserved under the Network
//     close gate, and any staged byte reservation is released on
//     drain/drop/cancel/Close.

// sessionRekeyRetransmitInterval bounds how often a still-pending source
// attempt is re-sent. The attempt itself is byte-identical and coalesced by
// Session.Rekey, so this is bounded retransmission, not a second attempt.
const sessionRekeyRetransmitInterval = time.Second

// pollSessionRekeys is the non-blocking Network policy hook. It snapshots the
// committed, non-relay initiator entries of this runtime and, for each one whose
// TX or RX protector crossed a 7/8 soft threshold, starts exactly one coalesced
// rekey attempt on a bounded, close-gated worker. It performs no socket I/O and
// takes no reader/writer lock.
func (rt *streamRuntime) pollSessionRekeys() {
	if rt == nil || rt.n == nil {
		return
	}
	entries := rt.rekeyCandidateEntries()
	for _, entry := range entries {
		// A third install deferred by the frozen grace is completed here once
		// the grace expires; when its bounded window elapses first, the affected
		// Session/Path is failed scoped instead of retrying forever.
		if handled, _ := rt.retryDeferredInstall(entry); handled {
			continue
		}
		if !rt.sourceRekeyDue(entry) {
			continue
		}
		if !rt.reserveRekeyWorker() {
			return
		}
		go func(e *sessionEntry) {
			defer rt.n.workers.Done()
			defer func() { <-rt.rekeySlots }()
			rt.startSourceRekey(e)
		}(entry)
	}
}

// rekeyCandidateEntries snapshots the live Session entries under the runtime
// lock. Relay entries are excluded: a relay holds no Session/root/protector and
// never starts a rekey.
func (rt *streamRuntime) rekeyCandidateEntries() []*sessionEntry {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed {
		return nil
	}
	entries := make([]*sessionEntry, 0, len(rt.sessionsByID))
	for _, entry := range rt.sessionsByID {
		if entry == nil || entry.relay || entry.sess == nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries
}

// sourceRekeyDue reports whether this entry is the Path logical source of a
// ready, protector-installed session whose current epoch crossed any soft
// threshold, or already has a coalesced attempt (pending or grace-deferred) in
// flight.
func (rt *streamRuntime) sourceRekeyDue(entry *sessionEntry) bool {
	if entry == nil || entry.sess == nil || entry.relay || entry.isTerminated() {
		return false
	}
	entry.rekeyMu.Lock()
	pending := entry.rekeyPending
	deferred := entry.deferredEpoch != 0
	entry.rekeyMu.Unlock()
	if deferred {
		return false
	}
	if entry.sess.Role() != session.RoleInitiator {
		return false
	}
	if entry.sess.State() != session.StateReady {
		return false
	}
	entry.protMu.Lock()
	tx, rx, installed := entry.tx, entry.rx, entry.installedEpoch
	entry.protMu.Unlock()
	if tx == nil || rx == nil || installed == 0 {
		return false
	}
	if pending {
		// While the epoch the attempt committed is already installed, the
		// install path owns the entry. If the attempt is no longer pending in
		// the Session (it expired at the frozen 30s deadline without a READY),
		// drop only the runtime staging: the committed identity and the old
		// protector keep serving, and a later tick may retry.
		if rootEpoch, have := entry.sess.RootEpoch(); have && rootEpoch.Epoch >= entry.rekeyEpoch {
			return false
		}
		if !entry.sess.PendingAttempt() {
			entry.clearRekeyPending()
			return false
		}
		return true
	}
	return tx.NeedsRekey() || rx.NeedsRekey()
}

// reserveRekeyWorker takes one bounded rekey slot and, under the Network close
// gate, reserves the worker on n.workers so Close waits for an in-flight rekey
// instead of releasing the runtime under it. A closed/canceled Network releases
// the slot and refuses the worker.
func (rt *streamRuntime) reserveRekeyWorker() bool {
	select {
	case rt.rekeySlots <- struct{}{}:
	default:
		return false
	}
	rt.n.mu.Lock()
	if rt.n.closed || rt.n.ctx.Err() != nil {
		rt.n.mu.Unlock()
		<-rt.rekeySlots
		return false
	}
	rt.n.workers.Add(1)
	rt.n.mu.Unlock()
	return true
}

// startSourceRekey starts (or retransmits) the single coalesced next attempt of
// this entry and sends it as a SESSION_CTRL over the CONTROL route of the SAME
// SessionID/class/lane/Path. It never blocks a reader or writer: the send is an
// enqueue on the already installed control pump.
func (rt *streamRuntime) startSourceRekey(entry *sessionEntry) {
	if entry == nil || entry.sess == nil {
		return
	}
	entry.rekeyMu.Lock()
	if entry.deferredEpoch != 0 {
		entry.rekeyMu.Unlock()
		return
	}
	if entry.rekeyPending && !entry.rekeySent.IsZero() &&
		time.Since(entry.rekeySent) < sessionRekeyRetransmitInterval {
		entry.rekeyMu.Unlock()
		return
	}
	entry.rekeyMu.Unlock()

	ctx, cancel := context.WithTimeout(rt.n.ctx, 10*time.Second)
	defer cancel()
	attempt, err := entry.sess.Rekey(ctx)
	if err != nil {
		// A terminal/refusing session clears the pending marker; the scoped
		// Path/Session failure is reported through the normal health path, not
		// as a global Link failure.
		entry.clearRekeyPending()
		traceDataPlane("session rekey refused", "session", hexNode([16]byte(entry.id))[:8], "err", err.Error())
		return
	}
	entry.noteRekeyStarted(attempt.Attempt, attempt.TargetEpoch)
	ps := rt.pathByScope(entry.scope)
	if ps == nil {
		return
	}
	ctrl := session.SessionCtrl{
		SessionID:   entry.id,
		Class:       entry.class,
		DataLaneID:  entry.lane,
		Attempt:     attempt.Attempt,
		TargetEpoch: attempt.TargetEpoch,
		Payload:     attempt.Bytes,
	}
	payload, err := ctrl.Encode()
	if err != nil {
		return
	}
	// The source sends toward the logical target on the same CONTROL route the
	// initial handshake used.
	if err := rt.sendRoutePayload(ps, wire.MessageTypeSessionCtrl, [16]byte(entry.id), payload, false, ps.pathBudget()); err != nil {
		// The CTRL never left: drop only the runtime staging so the old
		// committed identity and old epoch keep serving, and the next tick can
		// coalesce/retransmit the same Session attempt.
		entry.clearRekeyPending()
		traceDataPlane("session rekey ctrl send failed", "session", hexNode([16]byte(entry.id))[:8], "err", err.Error())
		return
	}
	traceDataPlane("SESSION_CTRL rekey sent", "session", hexNode([16]byte(entry.id))[:8], "attempt", attempt.Attempt, "epoch", attempt.TargetEpoch)
}

// --- sessionEntry rekey staging ---------------------------------------------

// noteRekeyStarted freezes the coalesced next attempt identity on this entry
// WITHOUT touching the committed entry.attempt/targetEpoch. The committed
// identity keeps serving validation and retransmission of the old attempt until
// the matching SESSION_READY legally commits the new one; a failed send or an
// expired attempt therefore never loses the old identity.
func (entry *sessionEntry) noteRekeyStarted(attempt, epoch uint32) {
	entry.rekeyMu.Lock()
	entry.rekeyPending = true
	entry.rekeyAttempt = attempt
	entry.rekeyEpoch = epoch
	entry.rekeySent = time.Now()
	entry.rekeyMu.Unlock()
}

// acceptAttempt records an attempt accepted from the peer. The very first
// attempt of a fresh session becomes the committed identity; a later attempt is
// only staged as the coalesced next attempt, so the old committed identity
// survives until the matching READY promotes it.
func (entry *sessionEntry) acceptAttempt(attempt, epoch uint32) {
	entry.rekeyMu.Lock()
	defer entry.rekeyMu.Unlock()
	if entry.attempt == 0 {
		entry.attempt = attempt
		entry.targetEpoch = epoch
		return
	}
	if attempt > entry.attempt {
		entry.rekeyPending = true
		entry.rekeyAttempt = attempt
		entry.rekeyEpoch = epoch
	}
}

// noteRelayAttempt records the attempt a rootless relay observed. A relay holds
// no Session/root/protector and commits forwarding per received READY, so its
// recorded identity is the latest observed attempt.
func (entry *sessionEntry) noteRelayAttempt(attempt, epoch uint32) {
	entry.rekeyMu.Lock()
	entry.attempt = attempt
	entry.targetEpoch = epoch
	entry.rekeyPending = false
	entry.rekeyAttempt = 0
	entry.rekeyEpoch = 0
	entry.rekeyMu.Unlock()
}

// negotiatingIdentity returns the attempt identity a SESSION_READY must name
// right now: the coalesced next attempt while one is staged, otherwise the
// committed identity.
func (entry *sessionEntry) negotiatingIdentity() (attempt, epoch uint32) {
	entry.rekeyMu.Lock()
	defer entry.rekeyMu.Unlock()
	if entry.rekeyPending && entry.rekeyAttempt != 0 && entry.rekeyEpoch != 0 {
		return entry.rekeyAttempt, entry.rekeyEpoch
	}
	return entry.attempt, entry.targetEpoch
}

// attemptIdentity returns the committed identity the relay/legacy paths use,
// plus whether a next attempt is staged and its epoch.
func (entry *sessionEntry) attemptIdentity() (attempt, epoch uint32, pending bool, pendingEpoch uint32) {
	entry.rekeyMu.Lock()
	defer entry.rekeyMu.Unlock()
	return entry.attempt, entry.targetEpoch, entry.rekeyPending, entry.rekeyEpoch
}

// identityView returns the committed identity and the staged next attempt in one
// atomic read. The committed identity is never overwritten by a staged attempt,
// so a stale/duplicate READY still validates against it.
func (entry *sessionEntry) identityView() (committedAttempt, committedEpoch uint32, pending bool, pendingAttempt, pendingEpoch uint32) {
	entry.rekeyMu.Lock()
	defer entry.rekeyMu.Unlock()
	return entry.attempt, entry.targetEpoch, entry.rekeyPending, entry.rekeyAttempt, entry.rekeyEpoch
}

// isRekeyPending reports whether a coalesced next attempt is in flight.
func (entry *sessionEntry) isRekeyPending() bool {
	entry.rekeyMu.Lock()
	defer entry.rekeyMu.Unlock()
	return entry.rekeyPending || entry.deferredEpoch != 0
}

// rekeyAcceptsEpoch reports whether a future-epoch inbound frame may be staged
// opaquely for this entry: only the exact epoch of the registered next attempt
// is accepted. Any earlier or later epoch is dropped without poisoning state.
func (entry *sessionEntry) rekeyAcceptsEpoch(epoch uint32) bool {
	if entry == nil || epoch == 0 {
		return false
	}
	entry.rekeyMu.Lock()
	defer entry.rekeyMu.Unlock()
	return entry.rekeyPending && entry.rekeyEpoch == epoch
}

// deferRekeyInstall records a committed epoch whose protector install was
// refused with the frozen third-install grace. The root is owned and kept until
// the retry succeeds or the entry closes; the old key keeps serving traffic.
//
// It also starts the deferral's one bounded window, measured on the same clock
// as the epoch grace with the same frozen budget. The deadline is stamped ONLY
// when the deferral actually starts (the first refusal of this epoch): a retry
// that is refused again must never push the bound out, or the deferral could
// still be unbounded.
func (entry *sessionEntry) deferRekeyInstall(epoch uint32, root []byte, now time.Time) {
	if entry == nil || epoch == 0 || len(root) == 0 {
		return
	}
	entry.rekeyMu.Lock()
	if entry.deferredEpoch != epoch {
		clear(entry.deferredRoot)
		entry.deferredEpoch = epoch
		entry.deferredRoot = append(entry.deferredRoot, root...)
		entry.deferredDeadline = now.Add(session.DefaultEpochGrace)
	}
	entry.rekeyMu.Unlock()
}

// rekeyInstallClock reads the same clock the E2E protectors of this runtime use
// (the injected policy seam; time.Now in production), so the bounded deferred
// install window is measured against the same frozen epoch-grace budget as the
// grace it waits on.
func (rt *streamRuntime) rekeyInstallClock() time.Time {
	if rt == nil {
		return time.Now()
	}
	if policy := rt.e2ePolicySnapshot(); policy.Clock != nil {
		return policy.Clock()
	}
	return time.Now()
}

// finishRekeyInstall clears the staging of one successfully installed epoch:
// its deferred root is wiped and, when the installed epoch is the coalesced
// attempt's target, the attempt is complete.
func (entry *sessionEntry) finishRekeyInstall(epoch uint32) {
	if entry == nil || epoch == 0 {
		return
	}
	entry.rekeyMu.Lock()
	if entry.deferredEpoch != 0 && epoch >= entry.deferredEpoch {
		clear(entry.deferredRoot)
		entry.deferredRoot = nil
		entry.deferredEpoch = 0
		entry.deferredDeadline = time.Time{}
	}
	if entry.rekeyPending && entry.rekeyEpoch != 0 && epoch >= entry.rekeyEpoch {
		// Promote the committed identity only after the epoch actually
		// installed: the old identity was never overwritten early, and a
		// duplicate READY keeps validating against the promoted (committed)
		// attempt/epoch.
		entry.attempt = entry.rekeyAttempt
		entry.targetEpoch = entry.rekeyEpoch
		entry.rekeyPending = false
		entry.rekeyAttempt = 0
		entry.rekeyEpoch = 0
		entry.rekeySent = time.Time{}
	}
	entry.rekeyMu.Unlock()
}

// clearRekeyPending drops the coalesced attempt marker and any deferred root
// when the attempt can no longer commit. Staged bytes are released separately by
// releasePending/closeProtectors.
func (entry *sessionEntry) clearRekeyPending() {
	if entry == nil {
		return
	}
	entry.rekeyMu.Lock()
	entry.rekeyPending = false
	entry.rekeyAttempt = 0
	entry.rekeyEpoch = 0
	entry.rekeySent = time.Time{}
	clear(entry.deferredRoot)
	entry.deferredRoot = nil
	entry.deferredEpoch = 0
	entry.deferredDeadline = time.Time{}
	entry.rekeyMu.Unlock()
}

// errRekeyInstallWindowExpired is the stable, typed reason a deferred protector
// install is abandoned: one frozen epoch-grace budget elapsed while the install
// was still refused, so the retained previous epoch's grace clock never started
// and the committed epoch could never legally install.
var errRekeyInstallWindowExpired = errors.New("session rekey install window expired")

// retryDeferredInstall completes a deferred third install once its frozen grace
// expired, and bounds the wait when the grace can never expire. It is a no-op
// when nothing is deferred and reports whether it handled the entry.
//
// The install is retried exactly as before. When it still does not complete
// within the deferral's one-budget window — the case where the retained previous
// epoch's grace clock never started — this fails ONLY the affected Session/Path
// scoped through the existing failure machinery, releases its staged ciphertext,
// and returns a typed reason instead of retrying forever. Normal (two-way) rekey
// installs complete before the bound and are unaffected.
func (rt *streamRuntime) retryDeferredInstall(entry *sessionEntry) (bool, error) {
	if entry == nil {
		return false, nil
	}
	entry.rekeyMu.Lock()
	epoch := entry.deferredEpoch
	root := append([]byte(nil), entry.deferredRoot...)
	entry.rekeyMu.Unlock()
	if epoch == 0 || len(root) == 0 {
		return false, nil
	}
	defer clear(root)
	entry.protMu.Lock()
	installed := entry.installedEpoch
	entry.protMu.Unlock()
	if installed == epoch {
		entry.finishRekeyInstall(epoch)
		return true, nil
	}
	if err := rt.installCommittedEpoch(entry, session.RootEpoch{Epoch: epoch, Root: root}); err != nil {
		traceDataPlane("deferred epoch install failed", "session", hexNode([16]byte(entry.id))[:8], "epoch", epoch, "err", err.Error())
	}
	// installCommittedEpoch returns nil both when the epoch installed and when
	// the frozen grace deferred it again. Only a still-deferred epoch is subject
	// to the bounded window, and a successfully installed one cleared it.
	entry.rekeyMu.Lock()
	stillDeferred := entry.deferredEpoch == epoch
	deadline := entry.deferredDeadline
	entry.rekeyMu.Unlock()
	if !stillDeferred {
		return true, nil
	}
	now := rt.rekeyInstallClock()
	if deadline.IsZero() {
		// Defensive: a deferral recorded without a deadline still gets exactly
		// one bounded window rather than an unbounded one.
		entry.rekeyMu.Lock()
		if entry.deferredEpoch == epoch && entry.deferredDeadline.IsZero() {
			entry.deferredDeadline = now.Add(session.DefaultEpochGrace)
		}
		entry.rekeyMu.Unlock()
		return true, nil
	}
	if now.Before(deadline) {
		return true, nil
	}
	cause := fmt.Errorf("%w: epoch %d still refused %s after the deferral started; the retained previous epoch's grace clock never started",
		errRekeyInstallWindowExpired, epoch, session.DefaultEpochGrace)
	return true, rt.failDeferredRekeyInstall(entry, epoch, cause)
}

// failDeferredRekeyInstall is the bounded, scoped disposition of a deferred
// install that can no longer legally complete. It fails ONLY this Session/Path
// through the same scoped machinery the other refusals use: the staged peer
// ciphertext and every lease it owns are released, the deferred root is wiped,
// the Session is aborted, the entry is latched terminal, and its Circuits are
// failed with circuit.ErrSessionLost. The physical Link and every other Session
// stay healthy. The typed cause is traced (never raw key material) and returned
// so the caller stops retrying forever.
func (rt *streamRuntime) failDeferredRekeyInstall(entry *sessionEntry, epoch uint32, cause error) error {
	if entry == nil {
		return cause
	}
	traceDataPlane("deferred session rekey install abandoned; Session failed",
		"session", hexNode([16]byte(entry.id))[:8], "epoch", epoch, "err", cause.Error())
	// Release the staged peer ciphertext (shared lease + per-Session reservation)
	// while the Session still owns its pending accounting, then drop the
	// deferred root. No ciphertext is left retained and nothing is re-staged.
	entry.releasePending()
	entry.clearRekeyPending()
	if entry.sess != nil {
		_ = entry.sess.Abort()
	}
	entry.markTerminated()
	if rt != nil && rt.circuits != nil {
		if err := rt.circuits.FailSession(circuit.SessionRef{
			ID:             circuit.SessionID(entry.id),
			PathID:         entry.scope.id,
			PathGeneration: entry.scope.gen,
		}, circuit.ErrSessionLost); err != nil {
			traceDataPlane("scoped Session Circuits not failed",
				"session", hexNode([16]byte(entry.id))[:8], "err", err.Error())
		}
	}
	return cause
}

// sessionRekeyHardPauseBudget bounds how long one egress producer pauses at a
// hard key ceiling while the coalesced IK rekey installs the next epoch. It is
// shorter than the 30s attempt deadline so a non-completing attempt fails
// closed scoped to the Session/Path instead of stalling forever.
const sessionRekeyHardPauseBudget = 5 * time.Second

// awaitSealHeadroom pauses the egress producer when its directional key is at
// the configured hard ceiling. A ready Session is about to be rotated by the
// Path owner, so the producer waits, bounded, for the committed epoch to
// install rather than failing the frame to SessionLost. Only the Path logical
// owner may start the coalesced rekey; a responder never starts one and simply
// waits for the source's rotation, failing closed only after the bounded budget
// if no install ever arrives. It MUST be called before entry.txMu is taken: the
// install path needs that same lock.
//
// This pause is measured on the real wall clock, deliberately NOT on the
// injectable E2EPolicy.Clock seam that times the epoch grace and key age. The
// two are different kinds of quantity: the injectable clock is the key state
// machine's logical time (it must be advanceable in tests), while this budget
// is a real-time liveness bound on a producer that is holding a hard key
// ceiling. The frozen rule (wire-protocol.md 62) requires that a node at a
// safety hard limit still fails closed rather than stalling, and a test clock
// only advances when a test advances it, so moving this loop onto an injected
// clock would let it block unboundedly. Note also that Go cannot catch a
// mixed-clock comparison at compile time the way Rust's distinct Instant types
// do: every source here is the same time.Time, so the separation above is a
// convention this comment exists to protect.
func (rt *streamRuntime) awaitSealHeadroom(entry *sessionEntry, tx *session.E2EProtector) error {
	if entry == nil || tx == nil {
		return traceSealLost("headroom/protectors-nil", entry, fmt.Errorf("session protectors are not installed"))
	}
	snap, ok := tx.UsageSnapshot()
	if !ok || !snap.AtHardLimit {
		return nil
	}
	initiator := entry.sess != nil && entry.sess.Role() == session.RoleInitiator
	if initiator {
		rt.requestSourceRekey(entry)
	}
	traceDataPlane("seal headroom paused", "session", hexNode([16]byte(entry.id))[:8], "epoch", snap.Epoch, "initiator", initiator)
	deadline := time.Now().Add(sessionRekeyHardPauseBudget)
	epoch := snap.Epoch
	for time.Now().Before(deadline) {
		if rt.n == nil || rt.n.ctx.Err() != nil {
			return ErrClosed
		}
		now, ok := tx.UsageSnapshot()
		if !ok || !now.AtHardLimit || now.Epoch != epoch {
			traceDataPlane("seal headroom resumed", "session", hexNode([16]byte(entry.id))[:8], "from", epoch, "to", now.Epoch)
			return nil
		}
		time.Sleep(2 * time.Millisecond)
	}
	return traceSealLost("headroom/timeout", entry, fmt.Errorf("session key epoch %d still at its hard ceiling", epoch))
}

// traceInstalledEpoch records the actual protector install state right after a
// committed READY, so a mismatch between the Session's committed epoch and the
// protectors' installed epoch is observable rather than inferred.
func (rt *streamRuntime) traceInstalledEpoch(entry *sessionEntry, wantEpoch uint32) {
	rootEpoch, have := entry.sess.RootEpoch()
	entry.protMu.Lock()
	installed, txEpoch, rxEpoch := entry.installedEpoch, uint32(0), uint32(0)
	if entry.tx != nil {
		txEpoch = entry.tx.CurrentEpoch()
	}
	if entry.rx != nil {
		rxEpoch = entry.rx.CurrentEpoch()
	}
	entry.protMu.Unlock()
	traceDataPlane("epoch install state", "session", hexNode([16]byte(entry.id))[:8],
		"want", wantEpoch, "session_epoch", rootEpoch.Epoch, "session_ok", have,
		"installed", installed, "tx", txEpoch, "rx", rxEpoch)
}

// traceSealLost records the exact egress site that failed one seal plus the
// live epoch/usage state, so a responder circuit loss is never diagnosed by
// inference. It returns err unchanged for use in a return statement.
func traceSealLost(site string, entry *sessionEntry, err error) error {
	wrapped := fmt.Errorf("%w: %v", circuit.ErrSessionLost, err)
	id := [16]byte{}
	epoch, txNum := uint32(0), uint64(0)
	if entry != nil {
		id = [16]byte(entry.id)
		entry.protMu.Lock()
		tx := entry.tx
		entry.protMu.Unlock()
		if tx != nil {
			epoch = tx.CurrentEpoch()
			if snap, ok := tx.UsageSnapshot(); ok {
				traceDataPlane("seal lost", "site", site, "session", hexNode(id)[:8], "epoch", epoch,
					"at_hard", snap.AtHardLimit, "seal_inv", snap.SealInvocations, "open_inv", snap.OpenInvocations,
					"max_inv", snap.MaxInvocations, "err", wrapped.Error())
				return wrapped
			}
		}
		txNum = entry.txNumber
	}
	traceDataPlane("seal lost", "site", site, "session", hexNode(id)[:8], "epoch", epoch, "tx_number", txNum, "err", wrapped.Error())
	return wrapped
}

// --- egress seal identity ----------------------------------------------------

// nextSealIdentity allocates the single monotonic MessageNumber of this
// (session, direction) domain and returns the installed TX KeyEpoch the frame
// must be stamped with. It must be called with entry.txMu held, so an epoch
// install can never race the seal and an already-queued ciphertext always keeps
// the epoch it was built with. A hard usage ceiling fails the frame closed and
// requests the source rekey instead of sealing under an exhausted key; the
// MessageNumber never wraps.
func (rt *streamRuntime) nextSealIdentity(entry *sessionEntry, tx *session.E2EProtector) (uint32, uint64, error) {
	if entry == nil || tx == nil {
		return 0, 0, traceSealLost("identity/protectors-nil", entry, fmt.Errorf("session protectors are not installed"))
	}
	epoch := tx.CurrentEpoch()
	if epoch == 0 {
		return 0, 0, traceSealLost("identity/epoch-zero", entry, fmt.Errorf("session key epoch is not installed"))
	}
	if entry.txNumber == math.MaxUint64 {
		return 0, 0, traceSealLost("identity/number-exhausted", entry, fmt.Errorf("session message number exhausted"))
	}
	if snap, ok := tx.UsageSnapshot(); ok && snap.AtHardLimit {
		if rt != nil {
			rt.requestSourceRekey(entry)
		}
		return 0, 0, traceSealLost("identity/hard", entry, fmt.Errorf("session key epoch %d reached its hard ceiling", epoch))
	}
	entry.txNumber++
	return epoch, entry.txNumber, nil
}

// requestSourceRekey kicks exactly one bounded rekey worker for an entry that
// hit its hard ceiling, so the producer pauses only until the new epoch is
// ready rather than failing to SessionLost. It is a no-op for a responder (only
// the Path owner may rekey) or when an attempt is already staged.
func (rt *streamRuntime) requestSourceRekey(entry *sessionEntry) {
	if rt == nil || rt.n == nil || entry == nil || entry.sess == nil {
		return
	}
	if entry.isRekeyPending() {
		return
	}
	if entry.sess.Role() != session.RoleInitiator {
		return
	}
	if !rt.reserveRekeyWorker() {
		return
	}
	go func(e *sessionEntry) {
		defer rt.n.workers.Done()
		defer func() { <-rt.rekeySlots }()
		rt.startSourceRekey(e)
	}(entry)
}
