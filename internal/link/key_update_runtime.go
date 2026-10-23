package link

import (
	"errors"

	"github.com/yiiilin/simpletier/internal/wire"
)

// ---------------------------------------------------------------------------
// Runtime driver hooks
// ---------------------------------------------------------------------------
//
// These methods are the entire seam a network runtime needs in order to run
// the in-place Link key update through the reader and writer it already owns.
// They add no goroutine, no queue and no second reader/writer: the runtime's
// one reader calls HandleKeyUpdateControl for each inbound LINK_CTRL message
// and hands the returned actions to its one writer, which calls
// ApplyAndCompleteKeyUpdate for each action in order. Usage accounting is
// always active; automatic initiation additionally needs an action sink.

// KeyUpdateUsageSnapshot returns the built-in policy's resolved limits, the
// lifetime per-domain usage counters and the current soft/hard trigger reasons.
// It is safe to call from any goroutine and takes no direction lock.
func (c *ProtectedControlIO) KeyUpdateUsageSnapshot() KeyUpdatePolicyStatus {
	if c == nil {
		return KeyUpdatePolicyStatus{Limits: DefaultKeyUpdatePolicy()}
	}
	return c.usage.status(c.keyUpdateInFlight())
}

// NeedsKeyUpdate reports whether the built-in usage policy's soft threshold has
// been reached and no update transaction is currently in flight. It is a pure
// observation: it emits nothing and changes no state.
func (c *ProtectedControlIO) NeedsKeyUpdate() bool {
	return c.KeyUpdateUsageSnapshot().NeedsUpdate
}

// StartKeyUpdateIfNeeded starts (or, on a follower, requests) exactly one
// in-place update when NeedsKeyUpdate is true and returns the writer actions.
// It returns (nil, nil) when the policy asks for nothing. The caller must
// enqueue the returned actions on the SAME single writer that already writes
// this Link's frames.
func (c *ProtectedControlIO) StartKeyUpdateIfNeeded() ([]KeyUpdateAction, error) {
	if c == nil {
		return nil, ErrControlTerminal
	}
	if !c.NeedsKeyUpdate() {
		return nil, nil
	}
	return c.RequestKeyUpdate()
}

// HandleKeyUpdateControl is the single reader's hook for one post-CAPABILITY
// LINK_CTRL message. handled is false for every control type other than the
// key-update opcode, so a runtime adds one branch to its existing control
// dispatch instead of a second reader or a new wire field. The returned actions
// must be executed by the same single writer through ApplyAndCompleteKeyUpdate.
// It performs no I/O, so the reading goroutine can never block on a write.
func (c *ProtectedControlIO) HandleKeyUpdateControl(message ControlMessage) (actions []KeyUpdateAction, handled bool, err error) {
	if c == nil {
		return nil, false, ErrControlTerminal
	}
	if message.Type != ControlTypeKeyUpdate {
		return nil, false, nil
	}
	body := make([]byte, 1+len(message.Payload))
	body[0] = ControlTypeKeyUpdate
	copy(body[1:], message.Payload)
	actions, err = c.HandleUpdate(ProtectedMessage{Kind: wire.FrameKindLinkControl, Payload: body})
	return actions, true, err
}

// ApplyAndCompleteKeyUpdate is the single-writer hook: it executes one action
// through its bound carrier and then delivers the writer-completion event to
// the owning engine exactly once, after the physical write returned. The
// returned actions are the follow-ups the same writer must enqueue (for example
// the DONE that may only follow a completed CONFIRM write). A partial or failed
// write is reported through the completion event and never retried.
func (c *ProtectedControlIO) ApplyAndCompleteKeyUpdate(action KeyUpdateAction) ([]KeyUpdateAction, error) {
	if c == nil {
		return nil, ErrControlTerminal
	}
	// The writer's safe automatic-trigger point: no direction lock is held here
	// and the completion event above may have reached Stable.
	defer c.pollKeyUpdateTrigger()
	carrier := action.Carrier
	if carrier == nil {
		carrier = c
	}
	applyErr := carrier.ApplyKeyUpdateAction(action)
	owner := action.Owner
	if owner == nil {
		if concrete, ok := carrier.(*ProtectedControlIO); ok {
			owner = concrete
		}
	}
	if owner == nil {
		return nil, applyErr
	}
	follow, completeErr := owner.CompleteKeyUpdateAction(action, applyErr)
	if applyErr != nil {
		// ErrKeyUpdateAbort is a deliberate pause, not a physical failure; the
		// caller distinguishes it with errors.Is and keeps the transaction.
		return follow, applyErr
	}
	return follow, completeErr
}

// SetKeyUpdateActionSink installs the callback the Link invokes when the
// built-in usage policy first asks to start an update. The sink receives the
// writer actions and MUST enqueue them on the existing single writer without
// blocking; a full writer queue is the runtime's own resource decision. A nil
// sink, the default, disables automatic initiation entirely: usage is still
// counted and NeedsKeyUpdate still reports, but the Link never emits an action
// on its own, so nothing is generated without an explicit action owner.
// Installing a sink (re)arms the once-per-stable-generation trigger, so a
// caller can recover from an earlier attempt that failed to start (for example
// an engine that was configured later).
func (c *ProtectedControlIO) SetKeyUpdateActionSink(sink func([]KeyUpdateAction) error) {
	if c == nil {
		return
	}
	c.triggerMu.Lock()
	c.kuSink = sink
	c.kuTriggerArmed = false
	c.kuTriggerErr = nil
	c.triggerMu.Unlock()
}

// KeyUpdateTriggerError returns the error of the most recent automatic trigger
// attempt, or nil. It lets a runtime surface "policy asked but the update could
// not start" (for example an unconfigured engine) without spinning.
func (c *ProtectedControlIO) KeyUpdateTriggerError() error {
	if c == nil {
		return nil
	}
	c.triggerMu.Lock()
	defer c.triggerMu.Unlock()
	return c.kuTriggerErr
}

// keyUpdateInFlight reports whether a transaction currently owns the engine.
func (c *ProtectedControlIO) keyUpdateInFlight() bool {
	if c == nil {
		return false
	}
	engine, err := c.keyUpdateEngine()
	if err != nil {
		return false
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.active
}

// keyUpdateStartPending reports whether an update is already being started:
// either a transaction is active, or a follower solicitation was prepared and is
// still awaiting the coordinator's XX1. It is the coalescing predicate for the
// automatic trigger, so a repeated crossing cannot be recorded as a failure.
func (c *ProtectedControlIO) keyUpdateStartPending() bool {
	if c == nil {
		return false
	}
	engine, err := c.keyUpdateEngine()
	if err != nil {
		return false
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.active || engine.requestPending
}

// pollKeyUpdateTrigger is the automatic trigger point. Callers invoke it only
// after releasing their direction lock, and it never holds engine.mu while
// calling the sink, so the sink may enqueue actions without any nested lock. It
// fires at most once per stable generation: while a transaction is in flight,
// or after an attempt failed, it does nothing until a completed update advances
// the baseline or the caller re-arms it by installing the sink/engine.
func (c *ProtectedControlIO) pollKeyUpdateTrigger() {
	if c == nil || c.terminal.Load() {
		return
	}
	c.triggerMu.Lock()
	sink := c.kuSink
	armed := c.kuTriggerArmed
	c.triggerMu.Unlock()
	if sink == nil || armed {
		return
	}
	if !c.NeedsKeyUpdate() {
		return
	}
	c.triggerMu.Lock()
	if c.kuSink == nil || c.kuTriggerArmed {
		c.triggerMu.Unlock()
		return
	}
	c.kuTriggerArmed = true
	c.triggerMu.Unlock()

	actions, startErr := c.StartKeyUpdateIfNeeded()
	switch {
	case startErr != nil && errors.Is(startErr, ErrKeyUpdateState) && c.keyUpdateStartPending():
		// A concurrent caller (or a follower solicitation already in flight) won
		// the race: this trigger coalesces onto the transaction that is already
		// active. Nothing is recorded as a failure and the arm is released, so
		// the next crossing after that transaction ends can still start one.
		c.triggerMu.Lock()
		c.kuTriggerArmed = false
		c.kuTriggerErr = nil
		c.triggerMu.Unlock()
		return
	case startErr != nil:
		// The start failed before any action batch existed (for example an
		// engine that was not configured yet). The exact error is recorded so
		// the runtime can surface it, the stream stays open, and the arm stays
		// set so this cannot spin; installing the engine or the sink re-arms.
		c.triggerMu.Lock()
		c.kuTriggerErr = startErr
		c.triggerMu.Unlock()
		return
	case len(actions) == 0:
		// The crossing cleared before anything was prepared: nothing to deliver.
		c.triggerMu.Lock()
		c.kuTriggerArmed = false
		c.kuTriggerErr = nil
		c.triggerMu.Unlock()
		return
	}
	// The sink owns delivery of the prepared batch. Its error must never be
	// dropped: the engine is already active and a partially accepted batch may
	// already have emitted an uncertain subset of actions, so retrying under a
	// fresh Noise run would replay uncertain state. The exact error stays
	// errors.Is-visible through KeyUpdateTriggerError and the owned physical
	// stream is closed, so a pump blocked on it wakes instead of hanging.
	sinkErr := sink(actions)
	c.triggerMu.Lock()
	c.kuTriggerErr = sinkErr
	c.triggerMu.Unlock()
	if sinkErr != nil {
		c.failClosedTrigger()
	}
}

// PollKeyUpdatePolicy is the runtime's callback-safe policy tick. It performs
// exactly the automatic-trigger evaluation of pollKeyUpdateTrigger: it does no
// I/O, starts no goroutine and takes no direction lock, so a runtime may call it
// from a 250ms timer and pause business writes until the transaction reaches
// Stable. It is also the pre-write poll: calling it before a business write lets
// the runtime start the recovery update instead of attempting business under an
// already exhausted key. A poll that races an active transaction coalesces onto
// it and records no failure.
func (c *ProtectedControlIO) PollKeyUpdatePolicy() {
	c.pollKeyUpdateTrigger()
}

// failClosedTrigger ends this IO after an automatic-start or action-sink
// failure. Keys, nonces, counters and the engine's transaction state are left
// untouched and the exact error stays visible through KeyUpdateTriggerError; the
// owned physical stream is closed so a pump blocked on it wakes instead of
// hanging forever. It is deliberately terminal, because a partially delivered
// prepared batch cannot be replayed safely.
func (c *ProtectedControlIO) failClosedTrigger() {
	if c == nil {
		return
	}
	c.terminal.Store(true)
	c.closeOwnedStream()
}

// closeOwnedStream closes the physical stream this IO was handed and is used
// only on an already-decided fail-closed path to wake a pump blocked in a
// synchronous read or write. Recoverable rejections never call it.
func (c *ProtectedControlIO) closeOwnedStream() {
	if c == nil || c.stream == nil {
		return
	}
	_ = c.stream.Close()
}

// noteStableGeneration advances this carrier's local policy baseline after an
// update that actually switched its own roots, and re-arms the automatic trigger
// for the next stable generation. Only the relative baseline moves: the lifetime
// per-domain counters are preserved, and an installed VerificationBudget is a
// caller-owned NETWORK lifetime ledger that no Link ever resets on Stable. The
// per-key 24h/seal/byte defaults stay cumulative-relative per stable root, so a
// fresh root does not immediately re-trigger a hard boundary.
func (c *ProtectedControlIO) noteStableGeneration(generation uint32) {
	if c == nil {
		return
	}
	if c.usage != nil {
		c.usage.noteStable(generation)
	}
	c.rearmKeyUpdateTrigger()
}

// rearmKeyUpdateTrigger clears the once-per-generation arming and the last
// trigger error. SetKeyUpdateActionSink and ConfigureKeyUpdate call it so a
// caller that installs the engine or the sink after a crossing can still get
// one automatic attempt.
func (c *ProtectedControlIO) rearmKeyUpdateTrigger() {
	if c == nil {
		return
	}
	c.triggerMu.Lock()
	c.kuTriggerArmed = false
	c.kuTriggerErr = nil
	c.triggerMu.Unlock()
}

// keyUsageHardStop reports whether the built-in policy's hard boundary is
// reached for a domain, in which case no further key use is allowed.
func (c *ProtectedControlIO) keyUsageHardStop(domain KeyUsageDomain) bool {
	if c == nil || c.usage == nil {
		return false
	}
	return c.usage.hardReached(domain)
}

// noteVerifyFailure records one rejected inbound AEAD verification and fails
// the Link closed once the aggregate rejection counter reaches the policy's
// hard boundary. The caller still returns its own authentication error.
//
// It is called only after an actual hop-AEAD open failure, never for a replay,
// schema or shape rejection, so an optional shared VerificationBudget installed
// by the caller is charged for real bad tags only. A budget that refuses (false)
// is terminal AND closes the owned physical stream, because that ledger bounds a
// wider trust domain than this one Link.
func (c *ProtectedControlIO) noteVerifyFailure(domain KeyUsageDomain) {
	if c == nil || c.usage == nil {
		return
	}
	c.usage.failedAuth(domain)
	c.kuMu.Lock()
	budget := c.verifyBudget
	c.kuMu.Unlock()
	if budget != nil && !budget.RecordFailure() {
		c.terminal.Store(true)
		c.closeOwnedStream()
	}
	if c.usage.failedAuthHardReached() {
		c.terminal.Store(true)
	}
}
