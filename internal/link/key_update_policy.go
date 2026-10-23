package link

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Built-in key-use policy (operational defaults, not a cryptographic proof)
// ---------------------------------------------------------------------------
//
// A Link's hop AEAD keys are used for as long as the Link stays stable. This
// file adds the minimal operational accounting and the trigger that lets a
// runtime ask for an in-place update before a key has been used "too much": an
// approximate successful-seal count, an approximate sealed-plaintext-byte
// count, the age of the current stable generation and the aggregate number of
// rejected authentications.
//
// The four numeric limits below are the built-in operational defaults of this
// implementation. They are NOT an RFC bound, a proof of AEAD security or a
// claim about any external suite: they are conservative engineering limits
// with a soft trigger that fires early enough to leave headroom for the
// in-band update handshake to complete. A caller that needs a different policy
// sets it explicitly through KeyUpdateConfig.Policy; every zero field means
// the built-in default below, and there is no "no policy" state because every
// Link is constructed with these defaults.
const (
	// DefaultKeyUpdateSealLimit is the built-in cap on successful AEAD seals
	// per key domain. LINK_CTRL, ROUTE_CTRL and the admitted-session E2E hop
	// domain each count their own seals; the counts are never summed.
	DefaultKeyUpdateSealLimit uint64 = 1 << 32
	// DefaultKeyUpdateByteLimit is the built-in cap on sealed plaintext bytes
	// per key domain. The plaintext is what the domain's AEAD Seal consumed
	// (the LINK_CTRL opcode byte is part of the control plaintext).
	DefaultKeyUpdateByteLimit uint64 = 1 << 48
	// DefaultKeyUpdateAgeSeconds is the built-in cap, in seconds, on the age of
	// the current stable generation.
	DefaultKeyUpdateAgeSeconds int64 = 24 * 60 * 60
	// DefaultKeyUpdateFailedAuthLimit is the built-in cap on the aggregate of
	// rejected inbound AEAD verifications across every domain.
	DefaultKeyUpdateFailedAuthLimit uint64 = 1024
)

// The soft trigger fires at 7/8 of every hard limit: the last eighth is the
// headroom in which the update handshake (and the frames racing with it) must
// complete. headroom(limit) = limit/8, computed with saturating arithmetic so
// a tiny configured limit can never underflow.
const (
	keyUpdateHeadroomNumerator   uint64 = 7
	keyUpdateHeadroomDenominator uint64 = 8
)

// keyUpdateControlHandshakeReserve is the number of LINK_CTRL frames one
// in-band update can still need after the soft trigger fired on the control
// domain: REQUEST, XX1, XX2, XX3, READY, COMMIT, ARMED, FENCE, CONFIRM and
// DONE plus the ABORT/ABORT_ACK/ABORT_REJECT variants. The control domain's
// soft threshold is pulled in by this reserve (saturating at zero) so the
// handshake that is supposed to save the control key can never itself be the
// frame that trips the hard boundary.
const keyUpdateControlHandshakeReserve uint64 = 16

// ErrKeyUpdateRequired is returned when a key domain reached the policy's hard
// boundary and no update has reached Stable since. It is a fail-closed refusal
// to spend another key under that domain; a runtime normally closes the Link
// after it. Key-update control frames for the recovery handshake are exempt,
// so a Link at the wall can still complete the update that makes it safe.
var ErrKeyUpdateRequired = errors.New("link: key update required by usage policy")

// KeyUsageDomain names one independently keyed hop domain. Each domain has its
// own AEAD key instance and nonce domain, so each counts usage on its own and
// the domains are never summed into one budget.
type KeyUsageDomain uint8

const (
	// KeyDomainControl is the LINK_CTRL key, including key-update frames.
	KeyDomainControl KeyUsageDomain = iota
	// KeyDomainRoute is the ROUTE_CTRL key.
	KeyDomainRoute
	// KeyDomainStream is the admitted-session E2E hop key domain.
	KeyDomainStream
	keyDomainCount = 3
)

func (d KeyUsageDomain) String() string {
	switch d {
	case KeyDomainControl:
		return "control"
	case KeyDomainRoute:
		return "route"
	case KeyDomainStream:
		return "stream"
	default:
		return fmt.Sprintf("domain(%d)", uint8(d))
	}
}

// KeyUpdateTrigger is a bit set of the built-in policy reasons that ask for an
// in-place key update. It is an operational accounting signal, never a
// cryptographic guarantee.
type KeyUpdateTrigger uint8

const (
	// KeyUpdateTriggerControl is the LINK_CTRL domain at/over its threshold.
	KeyUpdateTriggerControl KeyUpdateTrigger = 1 << iota
	// KeyUpdateTriggerRoute is the ROUTE_CTRL domain at/over its threshold.
	KeyUpdateTriggerRoute
	// KeyUpdateTriggerStream is the E2E hop domain at/over its threshold.
	KeyUpdateTriggerStream
	// KeyUpdateTriggerFailedAuth is the aggregate rejected-authentication
	// counter at/over its threshold.
	KeyUpdateTriggerFailedAuth
	// KeyUpdateTriggerAge is the stable generation at/over its age threshold.
	KeyUpdateTriggerAge
)

func (t KeyUpdateTrigger) String() string {
	if t == 0 {
		return "none"
	}
	names := [...]struct {
		bit  KeyUpdateTrigger
		name string
	}{
		{KeyUpdateTriggerControl, "control"},
		{KeyUpdateTriggerRoute, "route"},
		{KeyUpdateTriggerStream, "stream"},
		{KeyUpdateTriggerFailedAuth, "failed-auth"},
		{KeyUpdateTriggerAge, "age"},
	}
	out := ""
	for _, entry := range names {
		if t&entry.bit == 0 {
			continue
		}
		if out != "" {
			out += "|"
		}
		out += entry.name
	}
	return out
}

// KeyUpdatePolicy overrides the built-in operational limits for one Link. The
// zero value of every field keeps the built-in default, so KeyUpdatePolicy{}
// resolves to exactly DefaultKeyUpdatePolicy().
type KeyUpdatePolicy struct {
	SealLimit       uint64
	ByteLimit       uint64
	AgeSeconds      int64
	FailedAuthLimit uint64
}

// DefaultKeyUpdatePolicy returns the built-in operational policy. It is what
// every Link is constructed with and what a zero policy field resolves to.
func DefaultKeyUpdatePolicy() KeyUpdatePolicy {
	return KeyUpdatePolicy{
		SealLimit:       DefaultKeyUpdateSealLimit,
		ByteLimit:       DefaultKeyUpdateByteLimit,
		AgeSeconds:      DefaultKeyUpdateAgeSeconds,
		FailedAuthLimit: DefaultKeyUpdateFailedAuthLimit,
	}
}

// resolveKeyUpdatePolicy fills every zero field with its built-in default.
func resolveKeyUpdatePolicy(policy KeyUpdatePolicy) KeyUpdatePolicy {
	if policy.SealLimit == 0 {
		policy.SealLimit = DefaultKeyUpdateSealLimit
	}
	if policy.ByteLimit == 0 {
		policy.ByteLimit = DefaultKeyUpdateByteLimit
	}
	if policy.AgeSeconds == 0 {
		policy.AgeSeconds = DefaultKeyUpdateAgeSeconds
	}
	if policy.FailedAuthLimit == 0 {
		policy.FailedAuthLimit = DefaultKeyUpdateFailedAuthLimit
	}
	return policy
}

// KeyUpdateDomainUsage is one domain's monotonic usage over the whole life of
// the Link. A completed update advances the policy baseline but never clears
// these counters.
type KeyUpdateDomainUsage struct {
	Seals          uint64
	PlaintextBytes uint64
	FailedAuth     uint64
}

// KeyUpdatePolicyStatus is the caller-visible policy view: the resolved limits,
// the lifetime per-domain counters, the current soft/hard trigger reasons and
// the remaining headroom before the hard boundary.
type KeyUpdatePolicyStatus struct {
	// Limits is the resolved policy in force (defaults filled in).
	Limits  KeyUpdatePolicy
	Control KeyUpdateDomainUsage
	Route   KeyUpdateDomainUsage
	Stream  KeyUpdateDomainUsage
	// FailedAuth is the aggregate of the three per-domain counters.
	FailedAuth uint64
	// Soft and Hard are the policy reasons at or over the soft/hard boundary,
	// measured from the last stable generation.
	Soft KeyUpdateTrigger
	Hard KeyUpdateTrigger
	// NeedsUpdate is Soft != 0 while no update transaction is in flight.
	NeedsUpdate bool
	// AgeSeconds is the age of the current stable generation, clamped at zero
	// so it can never go backwards.
	AgeSeconds int64
	// RemainingSeals/RemainingBytes are the smallest per-domain headroom left
	// before the hard boundary; RemainingAgeSeconds is the age headroom.
	RemainingSeals      uint64
	RemainingBytes      uint64
	RemainingAgeSeconds int64
	// StableGeneration is the generation recorded by the last completed update.
	StableGeneration uint32
}

// keyUsageTracker owns the usage accounting. The per-domain counters are
// lifetime totals and are never reset; a completed update only advances the
// baseline the policy measures from (base/baseTime/baseGen).
type keyUsageTracker struct {
	mu       sync.Mutex
	clock    func() time.Time
	policy   KeyUpdatePolicy
	baseTime time.Time
	baseGen  uint32
	// maxAge is the high-water mark of the observed age in seconds. Age is
	// monotonic by construction: a backwards clock jump can never lower it.
	maxAge  int64
	base    [keyDomainCount]KeyUpdateDomainUsage
	current [keyDomainCount]KeyUpdateDomainUsage
}

func newKeyUsageTracker(policy KeyUpdatePolicy) *keyUsageTracker {
	now := time.Now()
	return &keyUsageTracker{clock: time.Now, policy: resolveKeyUpdatePolicy(policy), baseTime: now}
}

// setPolicy replaces the resolved policy of a Link (ConfigureKeyUpdate).
func (t *keyUsageTracker) setPolicy(policy KeyUpdatePolicy) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.policy = resolveKeyUpdatePolicy(policy)
	t.mu.Unlock()
}

// setClock installs an explicit clock and rebases the age baseline on it. It
// exists for deterministic age tests; production always uses time.Now.
func (t *keyUsageTracker) setClock(clock func() time.Time) {
	if t == nil || clock == nil {
		return
	}
	t.mu.Lock()
	t.clock = clock
	t.baseTime = clock()
	t.maxAge = 0
	t.mu.Unlock()
}

// seal records one successful AEAD seal of plaintext bytes in a domain. It is
// called after Seal returns, before the transport write result is known: the
// nonce is already spent, so a failed or partial write is still one key use.
func (t *keyUsageTracker) seal(domain KeyUsageDomain, plaintext int) {
	if t == nil || domain >= keyDomainCount || plaintext < 0 {
		return
	}
	t.mu.Lock()
	t.current[domain].Seals++
	t.current[domain].PlaintextBytes += uint64(plaintext)
	t.mu.Unlock()
}

// failedAuth records one rejected inbound AEAD verification.
func (t *keyUsageTracker) failedAuth(domain KeyUsageDomain) {
	if t == nil || domain >= keyDomainCount {
		return
	}
	t.mu.Lock()
	t.current[domain].FailedAuth++
	t.mu.Unlock()
}

// noteStable advances the policy baseline to the current counters and clock
// after a mutually completed update. The lifetime counters are preserved: only
// the point the policy measures from moves, so a completed update buys a fresh
// budget without erasing history.
func (t *keyUsageTracker) noteStable(generation uint32) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.base = t.current
	t.baseTime = t.clock()
	t.baseGen = generation
	t.maxAge = 0
	t.mu.Unlock()
}

// status returns the caller-visible policy view. active suppresses NeedsUpdate
// while a transaction is in flight, so the update handshake's own control
// frames cannot recursively trigger another transaction.
func (t *keyUsageTracker) status(active bool) KeyUpdatePolicyStatus {
	if t == nil {
		return KeyUpdatePolicyStatus{Limits: DefaultKeyUpdatePolicy()}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.statusLocked(active)
}

func (t *keyUsageTracker) statusLocked(active bool) KeyUpdatePolicyStatus {
	policy := t.policy
	age := t.ageLocked()
	status := KeyUpdatePolicyStatus{
		Limits:           policy,
		Control:          t.current[KeyDomainControl],
		Route:            t.current[KeyDomainRoute],
		Stream:           t.current[KeyDomainStream],
		AgeSeconds:       age,
		StableGeneration: t.baseGen,
		// The smallest remaining headroom over the domains starts as the whole
		// limit, which is the identity for the minimum below.
		RemainingSeals: policy.SealLimit,
		RemainingBytes: policy.ByteLimit,
	}
	status.FailedAuth = satAddUint64(status.Control.FailedAuth, satAddUint64(status.Route.FailedAuth, status.Stream.FailedAuth))
	usedFailed := satSubUint64(status.FailedAuth, t.baseFailedLocked())
	failedSoft := keyUpdateSoftThreshold(policy.FailedAuthLimit)

	for domain := KeyUsageDomain(0); domain < keyDomainCount; domain++ {
		usedSeals := satSubUint64(t.current[domain].Seals, t.base[domain].Seals)
		usedBytes := satSubUint64(t.current[domain].PlaintextBytes, t.base[domain].PlaintextBytes)
		sealSoft := keyUpdateSoftThreshold(policy.SealLimit)
		if domain == KeyDomainControl {
			// Reserve room for the update handshake itself.
			sealSoft = satSubUint64(sealSoft, keyUpdateControlHandshakeReserve)
		}
		if usedSeals >= sealSoft || usedBytes >= keyUpdateSoftThreshold(policy.ByteLimit) {
			status.Soft |= triggerForDomain(domain)
		}
		if usedSeals >= policy.SealLimit || usedBytes >= policy.ByteLimit {
			status.Hard |= triggerForDomain(domain)
		}
		status.RemainingSeals = minUint64(status.RemainingSeals, satSubUint64(policy.SealLimit, usedSeals))
		status.RemainingBytes = minUint64(status.RemainingBytes, satSubUint64(policy.ByteLimit, usedBytes))
	}
	if usedFailed >= failedSoft {
		status.Soft |= KeyUpdateTriggerFailedAuth
	}
	if usedFailed >= policy.FailedAuthLimit {
		status.Hard |= KeyUpdateTriggerFailedAuth
	}

	status.RemainingAgeSeconds = satSubInt64(policy.AgeSeconds, age)
	if age >= keyUpdateSoftThresholdInt(policy.AgeSeconds) {
		status.Soft |= KeyUpdateTriggerAge
	}
	if age >= policy.AgeSeconds {
		status.Hard |= KeyUpdateTriggerAge
	}
	status.NeedsUpdate = status.Soft != 0 && !active
	return status
}

// hardReached reports whether a domain may no longer spend a key because the
// policy's hard boundary was reached and no update has reached Stable since.
func (t *keyUsageTracker) hardReached(domain KeyUsageDomain) bool {
	if t == nil || domain >= keyDomainCount {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if satSubUint64(t.current[domain].Seals, t.base[domain].Seals) >= t.policy.SealLimit {
		return true
	}
	if satSubUint64(t.current[domain].PlaintextBytes, t.base[domain].PlaintextBytes) >= t.policy.ByteLimit {
		return true
	}
	if t.ageLocked() >= t.policy.AgeSeconds {
		return true
	}
	return satSubUint64(t.failedTotalLocked(), t.baseFailedLocked()) >= t.policy.FailedAuthLimit
}

// failedAuthHardReached reports whether the aggregated rejected-authentication
// counter alone reached the hard boundary. A verify failure fails the Link
// closed on this, independently of seal/byte/age usage.
func (t *keyUsageTracker) failedAuthHardReached() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return satSubUint64(t.failedTotalLocked(), t.baseFailedLocked()) >= t.policy.FailedAuthLimit
}

func (t *keyUsageTracker) failedTotalLocked() uint64 {
	var total uint64
	for i := 0; i < keyDomainCount; i++ {
		total = satAddUint64(total, t.current[i].FailedAuth)
	}
	return total
}

func (t *keyUsageTracker) baseFailedLocked() uint64 {
	var total uint64
	for i := 0; i < keyDomainCount; i++ {
		total = satAddUint64(total, t.base[i].FailedAuth)
	}
	return total
}

// ageLocked returns the stable generation age in whole seconds. The result is
// a monotonic high-water mark clamped at zero, so neither a non-monotonic wall
// clock nor a backwards jump can ever lower the reported age.
func (t *keyUsageTracker) ageLocked() int64 {
	elapsed := t.clock().Sub(t.baseTime)
	if elapsed < 0 {
		elapsed = 0
	}
	if seconds := int64(elapsed / time.Second); seconds > t.maxAge {
		t.maxAge = seconds
	}
	return t.maxAge
}

func triggerForDomain(domain KeyUsageDomain) KeyUpdateTrigger {
	switch domain {
	case KeyDomainControl:
		return KeyUpdateTriggerControl
	case KeyDomainRoute:
		return KeyUpdateTriggerRoute
	case KeyDomainStream:
		return KeyUpdateTriggerStream
	default:
		return 0
	}
}

func keyUpdateSoftThreshold(limit uint64) uint64 {
	if limit == 0 {
		return 0
	}
	headroom := limit / keyUpdateHeadroomDenominator * (keyUpdateHeadroomDenominator - keyUpdateHeadroomNumerator)
	return satSubUint64(limit, headroom)
}

func keyUpdateSoftThresholdInt(limit int64) int64 {
	if limit <= 0 {
		return 0
	}
	headroom := limit / int64(keyUpdateHeadroomDenominator) * int64(keyUpdateHeadroomDenominator-keyUpdateHeadroomNumerator)
	return satSubInt64(limit, headroom)
}

func satSubUint64(a, b uint64) uint64 {
	if a <= b {
		return 0
	}
	return a - b
}

func satAddUint64(a, b uint64) uint64 {
	sum := a + b
	if sum < a {
		return ^uint64(0)
	}
	return sum
}

func satSubInt64(a, b int64) int64 {
	if a <= b {
		return 0
	}
	return a - b
}

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
