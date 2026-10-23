package session

import (
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/yiiilin/simpletier/internal/security"
	"github.com/yiiilin/simpletier/internal/wire"
)

// This file is the end-to-end Session protector: the inner AEAD layer that a
// Session root protects, sitting under the hop AEAD. It consumes only the
// session root (never a link root).
//
// DESIGN-CONTRACT (concrete bytes; independent review required for the choices
// marked REVIEW):
//
//   - Envelope AAD: the exact wire.EnvelopeSize (85) raw envelope bytes, with no
//     re-encoding. This is the frozen wire AAD_e2e (wire-protocol.md 3.1).
//   - Nonce: KeyEpochBE32 | MessageNumberBE64, read from the envelope copy. No
//     other nonce domain is accepted.
//   - Traffic key (one independent HKDF per direction/epoch):
//
//     traffic_key = HKDF-Key-SHA256(
//     IKM  = session_root_key[dir],
//     salt = descriptor,
//     info = ASCII("simpletier/v2/session-traffic") || dir:u8
//     || SessionID:16B || class:u8 || KeyEpoch:u32be || LP32(descriptor),
//     L    = 32)
//
//   - Replay: a 1024-bit sliding window per (SessionID, KeyEpoch, direction,
//     processed here as one direction per protector). Open does a read-only
//     precheck, runs the AEAD, then rechecks and commits under one lock, so an
//     invalid tag never advances the window or the grace clock.
//   - Epochs: current plus previous only. The first authenticated current-epoch
//     frame starts the grace clock for the previous epoch; after the grace
//     period the previous key/window is dropped. A third InstallEpoch is
//     refused with ErrEpochRetained while the previous epoch still retains its
//     grace (including before any new-epoch authentication), so the frozen
//     30-second retention is never shortened. KeyEpoch is not allowed to wrap
//     (u32Max is rejected on install) and MessageNumber u64Max is rejected
//     before a nonce is built.
//   - Capacity: a zero policy is filled from the built-in operational defaults
//     (2^32 invocations, 2^48 plaintext bytes, 24h age, 1024 failed tags per
//     key) rather than running unbounded; a hard ceiling fails closed. Usage()
//     reports successful TX/RX invocations and plaintext bytes separately plus
//     the failed-authentication count. UsageSnapshot()/NeedsRekey() report the
//     current epoch and direction at the 7/8 soft threshold, reserving the top
//     eighth as control headroom for the source-driven IK rekey.
//   - Lifecycle: Close wipes every epoch key and drops all replay state; it is
//     idempotent and Seal/Open/InstallEpoch fail closed afterwards.
//
// REVIEW items: the traffic-info field order above, the direction-dependent
// expected Src/Dst swap, the grace default (30 s is the wire-documented value),
// and the caller-chosen usage ceilings.

var (
	// ErrE2EConfig reports an unusable protector configuration.
	ErrE2EConfig = errors.New("session: invalid end-to-end protector config")
	// ErrE2EEnvelope reports an envelope that fails the frozen layout or the
	// network/endpoint/session/class/path binding checks.
	ErrE2EEnvelope = errors.New("session: invalid end-to-end envelope")
	// ErrE2EAuthentication reports a failed end-to-end AEAD tag.
	ErrE2EAuthentication = errors.New("session: end-to-end authentication failed")
	// ErrE2EReplay reports a definite duplicate or a message below the floor.
	ErrE2EReplay = errors.New("session: replayed or out-of-order end-to-end frame")
	// ErrE2EEpochMismatch reports an unknown epoch or one outside its grace.
	ErrE2EEpochMismatch = errors.New("session: end-to-end key epoch mismatch")
	// ErrE2ENonceExhausted reports MessageNumber u64Max; a nonce is never
	// reused or wrapped.
	ErrE2ENonceExhausted = errors.New("session: end-to-end message number exhausted")
	// ErrKeyUsageExhausted reports a configured per-key use ceiling reached.
	ErrKeyUsageExhausted = errors.New("session: key usage ceiling reached")
	// ErrEpochRetained reports a refused InstallEpoch because the previous
	// epoch still retains its frozen grace window. The call is advisory: retry
	// after the grace expires. Current epoch and state are left unmutated.
	ErrEpochRetained = errors.New("session: previous key epoch still in grace")
	// ErrE2EClosed reports any Seal/Open/InstallEpoch after Close.
	ErrE2EClosed = errors.New("session: end-to-end protector closed")
)

const (
	// DefaultEpochGrace is the wire-documented grace period for the previous
	// key epoch. It is used only when E2EPolicy.GracePeriod is zero, and it is
	// the value wire-protocol.md freezes ("30 秒 grace").
	DefaultEpochGrace = 30 * time.Second
	// ReplayWindowBits is the frozen per-session-direction replay window.
	ReplayWindowBits = 1024

	// DefaultMaxE2EInvocations, DefaultMaxE2EPlainBytes, DefaultMaxE2EKeyAge and
	// DefaultMaxE2EAuthFailures are the built-in operational SDK defaults. They
	// are lifetime/abuse ceilings for one directional key, NOT cryptographic RFC
	// limits and not claims about cipher strength. A zero E2EPolicy or a zero
	// UsagePolicy field is filled from these; production never runs with an
	// unbounded key silently.
	DefaultMaxE2EInvocations  uint64        = 1 << 32 // 2^32 AEAD operations
	DefaultMaxE2EPlainBytes   uint64        = 1 << 48 // 2^48 plaintext bytes
	DefaultMaxE2EKeyAge       time.Duration = 24 * time.Hour
	DefaultMaxE2EAuthFailures uint64        = 1024

	// softRekeyNumerator/softRekeyDenominator reserve control headroom: a key is
	// reported "needs rekey" at 7/8 of every configured ceiling, leaving the top
	// eighth for in-flight control while the Path source rotates the root.
	softRekeyNumerator   uint64 = 7
	softRekeyDenominator uint64 = 8
)

// UsagePolicy is the injectable per-key capacity policy. A zero field is
// treated as "use the built-in operational default" rather than "unbounded":
// production must fail closed at a hard ceiling. Callers may lower or raise any
// field explicitly. These are operational SDK defaults, not cryptographic RFC
// limits.
type UsagePolicy struct {
	// MaxInvocations bounds AEAD invocations under one key. 0 => default.
	MaxInvocations uint64
	// MaxBytes bounds total protected plaintext bytes under one key. 0 => default.
	MaxBytes uint64
	// MaxAge bounds the monotonic age of one key. 0 => default.
	MaxAge time.Duration
	// MaxAuthFailures bounds failed AEAD tags under one key before the key fails
	// closed pending rekey. 0 => default.
	MaxAuthFailures uint64
}

// DefaultE2EPolicy returns the built-in operational policy: 2^32 invocations,
// 2^48 plaintext bytes, 24h key age and 1024 failed tags per key. It is a named
// value so callers can inspect or adapt it, not a hidden constant.
func DefaultE2EPolicy() E2EPolicy {
	return E2EPolicy{Usage: UsagePolicy{
		MaxInvocations:  DefaultMaxE2EInvocations,
		MaxBytes:        DefaultMaxE2EPlainBytes,
		MaxAge:          DefaultMaxE2EKeyAge,
		MaxAuthFailures: DefaultMaxE2EAuthFailures,
	}}
}

// normalizeE2EPolicy fills every zero usage ceiling from DefaultE2EPolicy so a
// zero policy is high-but-bounded, never unbounded. GracePeriod is left alone
// because zero already means DefaultEpochGrace.
func normalizeE2EPolicy(policy E2EPolicy) E2EPolicy {
	defaults := DefaultE2EPolicy().Usage
	if policy.Usage.MaxInvocations == 0 {
		policy.Usage.MaxInvocations = defaults.MaxInvocations
	}
	if policy.Usage.MaxBytes == 0 {
		policy.Usage.MaxBytes = defaults.MaxBytes
	}
	if policy.Usage.MaxAge == 0 {
		policy.Usage.MaxAge = defaults.MaxAge
	}
	if policy.Usage.MaxAuthFailures == 0 {
		policy.Usage.MaxAuthFailures = defaults.MaxAuthFailures
	}
	return policy
}

// softThreshold returns floor(total*7/8) without overflowing for any uint64.
func softThreshold(total uint64) uint64 {
	if total == 0 {
		return 0
	}
	d := total / softRekeyDenominator
	r := total % softRekeyDenominator
	return d*softRekeyNumerator + (r*softRekeyNumerator)/softRekeyDenominator
}

// softDuration returns floor(total*7/8) for a configured key age.
func softDuration(total time.Duration) time.Duration {
	if total <= 0 {
		return 0
	}
	return total / 8 * 7
}

// E2EPolicy carries the injectable time source, grace period and usage policy.
type E2EPolicy struct {
	// GracePeriod overrides DefaultEpochGrace when non-zero.
	GracePeriod time.Duration
	// Usage is enforced only for non-zero ceilings.
	Usage UsagePolicy
	// Clock is an optional time source for tests. Nil means time.Now.
	//
	// It times THIS protector's key state machine only: the previous epoch's
	// grace window (start, validity and expiry), the key age fed into the usage
	// snapshots, and therefore the soft/hard rekey thresholds. It deliberately
	// does NOT time the bounded egress-producer pause that waits for an install
	// (see (*streamRuntime).awaitSealHeadroom): that budget is a real-time
	// liveness bound and must elapse on the wall clock, so the two are separate
	// kinds of quantity rather than two inconsistent readings of one. Nothing
	// compares a value from this seam against a wall-clock value.
	Clock func() time.Time
}

// KeyUsage is the observable use of one epoch's key. TX and RX are reported
// separately and both byte counters are plaintext bytes; AuthFailures counts
// rejected Open tags (which never advance the replay window).
type KeyUsage struct {
	SealInvocations uint64
	SealBytes       uint64
	OpenInvocations uint64
	OpenBytes       uint64
	AuthFailures    uint64
	Started         time.Time
}

// E2EConfig is the complete immutable binding of one directional protector.
type E2EConfig struct {
	// Root is the canonical 64-byte SessionRoot (I2R || R2I).
	Root []byte
	// Descriptor is the full versioned NetworkContext descriptor.
	Descriptor []byte
	// WireID is NetworkContext.WireID(), the envelope network locator.
	WireID uint64
	// SrcNodeID/DstNodeID are the selected handshake endpoints
	// (initiator/responder), not the physical neighbour.
	SrcNodeID [16]byte
	DstNodeID [16]byte
	// PathID/PathGeneration are the bound Path scope. Both non-zero.
	PathID         uint64
	PathGeneration uint32
	// SessionID is the frozen per-session identifier.
	SessionID SessionID
	// Class is PACKET or STREAM.
	Class SessionClass
	// Direction is the direction this protector protects.
	Direction Direction
	// VerificationBudget optionally aggregates failed E2E tags across
	// protectors or a whole network. Nil means the protector enforces its own
	// per-key MaxAuthFailures ceiling (default 1024).
	VerificationBudget VerificationBudget
}

// VerificationBudget is the shared failed-tag budget seam. A caller (the Link
// worker defines an identical structural shape) injects one object so tag
// failures aggregate across protectors or a network. RecordFailure records one
// failed end-to-end tag and reports whether traffic may continue (true) or the
// caller must fail closed (false).
type VerificationBudget interface {
	RecordFailure() bool
}

// e2eReplayWindow is a 1024-bit sliding replay window over MessageNumber.
type e2eReplayWindow struct {
	seen bool
	max  uint64
	bits [ReplayWindowBits / 64]uint64
}

func newE2EReplayWindow() *e2eReplayWindow { return &e2eReplayWindow{} }

// precheck rejects a definite duplicate or a message below the window floor
// without changing any state.
func (w *e2eReplayWindow) precheck(seq uint64) error {
	if !w.seen {
		return nil
	}
	if seq > w.max {
		return nil
	}
	delta := w.max - seq
	if delta >= ReplayWindowBits {
		return fmt.Errorf("%w: message %d is below floor %d", ErrE2EReplay, seq, w.max)
	}
	if w.bits[delta/64]&(uint64(1)<<(delta%64)) != 0 {
		return fmt.Errorf("%w: message %d already accepted", ErrE2EReplay, seq)
	}
	return nil
}

// commit advances the window. It must run only after a successful AEAD and a
// successful precheck re-read, under the same lock.
func (w *e2eReplayWindow) commit(seq uint64) {
	if !w.seen {
		w.seen = true
		w.max = seq
		w.bits[0] = 1
		return
	}
	if seq > w.max {
		delta := seq - w.max
		if delta >= ReplayWindowBits {
			clear(w.bits[:])
		} else {
			w.shiftLocked(delta)
		}
		w.max = seq
		w.bits[0] |= 1
		return
	}
	delta := w.max - seq
	w.bits[delta/64] |= uint64(1) << (delta % 64)
}

func (w *e2eReplayWindow) shiftLocked(delta uint64) {
	wordShift := int(delta / 64)
	bitShift := uint(delta % 64)
	var out [ReplayWindowBits / 64]uint64
	for k := len(out) - 1; k >= 0; k-- {
		var v uint64
		if src := k - wordShift; src >= 0 && src < len(w.bits) {
			v = w.bits[src] << bitShift
		}
		if bitShift != 0 {
			if src := k - wordShift - 1; src >= 0 && src < len(w.bits) {
				v |= w.bits[src] >> (64 - bitShift)
			}
		}
		out[k] = v
	}
	w.bits = out
}

// E2EProtector protects one direction of one Session. It is safe for
// concurrent use.
type E2EProtector struct {
	root           SessionRoot
	descriptor     []byte
	wireID         uint64
	src, dst       [16]byte
	pathID         uint64
	pathGeneration uint32
	sessionID      SessionID
	class          SessionClass
	direction      Direction
	policy         E2EPolicy
	budget         VerificationBudget
	clock          func() time.Time

	mu   sync.Mutex
	keys map[uint32][32]byte
	// aeads caches the cipher of each installed epoch. chacha20poly1305.New is
	// cheap but not free, and Seal/Open run once per frame on the hottest path,
	// so rebuilding it per frame showed up as pure overhead. The cache is
	// invalidated exactly where keys are installed, dropped and cleared.
	aeads         map[uint32]cipher.AEAD
	windows       map[uint32]*e2eReplayWindow
	usage         map[uint32]*KeyUsage
	txSeen        map[uint32]bool
	txFloor       map[uint32]uint64
	currentEpoch  uint32
	previousEpoch uint32
	graceStart    time.Time
	closed        bool
}

// NewE2EProtector validates the binding and builds an empty protector.
// InstallEpoch must be called before Seal/Open.
func NewE2EProtector(cfg E2EConfig, policy E2EPolicy) (*E2EProtector, error) {
	if !cfg.Direction.Valid() {
		return nil, fmt.Errorf("%w: direction %d", ErrE2EConfig, uint8(cfg.Direction))
	}
	if !cfg.Class.Valid() {
		return nil, fmt.Errorf("%w: class 0x%02x", ErrE2EConfig, uint8(cfg.Class))
	}
	if cfg.SrcNodeID == ([16]byte{}) || cfg.DstNodeID == ([16]byte{}) || cfg.SrcNodeID == cfg.DstNodeID {
		return nil, fmt.Errorf("%w: invalid endpoints", ErrE2EConfig)
	}
	if cfg.PathID == 0 || cfg.PathGeneration == 0 {
		return nil, fmt.Errorf("%w: path %d/%d", ErrE2EConfig, cfg.PathID, cfg.PathGeneration)
	}
	if cfg.SessionID.IsZero() {
		return nil, fmt.Errorf("%w: zero session id", ErrE2EConfig)
	}
	if len(cfg.Descriptor) == 0 {
		return nil, fmt.Errorf("%w: empty descriptor", ErrE2EConfig)
	}
	root, err := ParseSessionRoot(cfg.Root)
	if err != nil || root.IsZero() {
		return nil, fmt.Errorf("%w: %v", ErrE2EConfig, err)
	}
	if policy.GracePeriod < 0 {
		return nil, fmt.Errorf("%w: negative grace period", ErrE2EConfig)
	}
	policy = normalizeE2EPolicy(policy)
	clock := policy.Clock
	if clock == nil {
		clock = time.Now
	}
	return &E2EProtector{
		root:           root,
		descriptor:     append([]byte(nil), cfg.Descriptor...),
		wireID:         cfg.WireID,
		src:            cfg.SrcNodeID,
		dst:            cfg.DstNodeID,
		pathID:         cfg.PathID,
		pathGeneration: cfg.PathGeneration,
		sessionID:      cfg.SessionID,
		class:          cfg.Class,
		direction:      cfg.Direction,
		policy:         policy,
		budget:         cfg.VerificationBudget,
		clock:          clock,
		keys:           make(map[uint32][32]byte),
		aeads:          make(map[uint32]cipher.AEAD),
		windows:        make(map[uint32]*e2eReplayWindow),
		usage:          make(map[uint32]*KeyUsage),
		txSeen:         make(map[uint32]bool),
		txFloor:        make(map[uint32]uint64),
	}, nil
}

// NewE2EProtectorForContext builds a protector bound to an initialized
// NetworkContext. It fills the descriptor and the u64 wire locator from the
// context and rejects a caller-supplied pair that disagrees with it. A zero
// WireID is legal and is filled from the context. The existing NewE2EProtector
// remains available for callers that already hold the raw descriptor.
func NewE2EProtectorForContext(nc security.NetworkContext, cfg E2EConfig, policy E2EPolicy) (*E2EProtector, error) {
	descriptor := nc.Descriptor()
	if len(descriptor) == 0 || nc.ID() == ([32]byte{}) {
		return nil, fmt.Errorf("%w: uninitialized network context", ErrE2EConfig)
	}
	if len(cfg.Descriptor) != 0 && !bytes.Equal(cfg.Descriptor, descriptor) {
		return nil, fmt.Errorf("%w: descriptor does not match the network context", ErrE2EConfig)
	}
	if cfg.WireID != 0 && cfg.WireID != nc.WireID() {
		return nil, fmt.Errorf("%w: wire id does not match the network context", ErrE2EConfig)
	}
	cfg.Descriptor = append([]byte(nil), descriptor...)
	cfg.WireID = nc.WireID()
	return NewE2EProtector(cfg, policy)
}

// Close wipes every epoch key and drops all AEAD/replay state. It is idempotent
// and terminal: Seal/Open/InstallEpoch fail closed with ErrE2EClosed afterwards.
func (p *E2EProtector) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	clear(p.root.I2R[:])
	clear(p.root.R2I[:])
	clear(p.descriptor)
	p.descriptor = nil
	for epoch := range p.keys {
		p.keys[epoch] = [32]byte{}
		delete(p.keys, epoch)
	}
	p.aeads = make(map[uint32]cipher.AEAD)
	p.windows = make(map[uint32]*e2eReplayWindow)
	p.usage = make(map[uint32]*KeyUsage)
	p.txSeen = make(map[uint32]bool)
	p.txFloor = make(map[uint32]uint64)
	p.previousEpoch = 0
	p.graceStart = time.Time{}
}

// Direction returns the direction this protector protects.
func (p *E2EProtector) Direction() Direction { return p.direction }

// CurrentEpoch returns the committed epoch, or 0 before InstallEpoch.
func (p *E2EProtector) CurrentEpoch() uint32 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentEpoch
}

// Usage returns the observable use of one epoch's key.
func (p *E2EProtector) Usage(epoch uint32) (KeyUsage, bool) {
	if p == nil {
		return KeyUsage{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.usage[epoch]
	if !ok {
		return KeyUsage{}, false
	}
	return *u, true
}

// E2EUsageSnapshot is the operational view of the current epoch's key for one
// direction. It reports the counters, the effective hard ceilings, the 7/8
// soft thresholds, and whether the Path source should start an IK rekey.
type E2EUsageSnapshot struct {
	Epoch     uint32
	Direction Direction

	SealInvocations uint64
	SealBytes       uint64
	OpenInvocations uint64
	OpenBytes       uint64
	AuthFailures    uint64
	Age             time.Duration

	MaxInvocations  uint64
	MaxBytes        uint64
	MaxAge          time.Duration
	MaxAuthFailures uint64

	SoftInvocations  uint64
	SoftBytes        uint64
	SoftAge          time.Duration
	SoftAuthFailures uint64

	NeedsRekey  bool
	AtHardLimit bool
}

// UsageSnapshot reports the current epoch/direction operational state. ok is
// false before InstallEpoch, after Close, or for a nil protector. The snapshot
// considers both Seal (TX) and Open (RX) counters, so the Path logical source
// can observe the peer's direction nearing the soft threshold without a new
// wire message.
func (p *E2EProtector) UsageSnapshot() (E2EUsageSnapshot, bool) {
	if p == nil {
		return E2EUsageSnapshot{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snapshotLocked(p.currentEpoch)
}

// NeedsRekey reports whether the current epoch has crossed any 7/8 soft
// threshold. The source checks TX and RX protectors; the responder cannot
// initiate a rekey and instead fails closed at the hard limit.
func (p *E2EProtector) NeedsRekey() bool {
	snap, ok := p.UsageSnapshot()
	return ok && snap.NeedsRekey
}

func (p *E2EProtector) snapshotLocked(epoch uint32) (E2EUsageSnapshot, bool) {
	u, ok := p.usage[epoch]
	if !ok || epoch == 0 {
		return E2EUsageSnapshot{}, false
	}
	now := p.clock()
	age := now.Sub(u.Started)
	if age < 0 {
		age = 0 // monotonic: never report a negative age
	}
	pol := p.policy.Usage
	snap := E2EUsageSnapshot{
		Epoch:            epoch,
		Direction:        p.direction,
		SealInvocations:  u.SealInvocations,
		SealBytes:        u.SealBytes,
		OpenInvocations:  u.OpenInvocations,
		OpenBytes:        u.OpenBytes,
		AuthFailures:     u.AuthFailures,
		Age:              age,
		MaxInvocations:   pol.MaxInvocations,
		MaxBytes:         pol.MaxBytes,
		MaxAge:           pol.MaxAge,
		MaxAuthFailures:  pol.MaxAuthFailures,
		SoftInvocations:  softThreshold(pol.MaxInvocations),
		SoftBytes:        softThreshold(pol.MaxBytes),
		SoftAge:          softDuration(pol.MaxAge),
		SoftAuthFailures: softThreshold(pol.MaxAuthFailures),
	}
	invocations := addU64Saturating(u.SealInvocations, u.OpenInvocations)
	totalBytes := addU64Saturating(u.SealBytes, u.OpenBytes)
	snap.NeedsRekey = (pol.MaxInvocations > 0 && invocations >= snap.SoftInvocations) ||
		(pol.MaxBytes > 0 && totalBytes >= snap.SoftBytes) ||
		(pol.MaxAge > 0 && age >= snap.SoftAge) ||
		(pol.MaxAuthFailures > 0 && u.AuthFailures >= snap.SoftAuthFailures)
	snap.AtHardLimit = p.closed ||
		(pol.MaxInvocations > 0 && invocations >= pol.MaxInvocations) ||
		(pol.MaxBytes > 0 && totalBytes >= pol.MaxBytes) ||
		(pol.MaxAge > 0 && age >= pol.MaxAge) ||
		(pol.MaxAuthFailures > 0 && u.AuthFailures >= pol.MaxAuthFailures)
	return snap, true
}

// InstallEpoch installs the traffic key for epoch derived from root, moving the
// current epoch to the single previous grace slot. The first install may use any
// non-zero epoch; later installs must be exactly current+1. u32Max is rejected
// because KeyEpoch must not wrap.
func (p *E2EProtector) InstallEpoch(epoch uint32, root []byte) error {
	if p == nil {
		return ErrE2EConfig
	}
	if epoch == 0 || epoch == ^uint32(0) {
		return fmt.Errorf("%w: epoch %d", ErrEpochExhausted, epoch)
	}
	parsed, err := ParseSessionRoot(root)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrE2EConfig, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock()
	if err := p.canInstallLocked(epoch, now); err != nil {
		return err
	}
	key, err := p.trafficKeyLocked(epoch, parsed)
	if err != nil {
		return err
	}
	if p.previousEpoch != 0 {
		p.dropEpochLocked(p.previousEpoch)
	}
	p.previousEpoch = p.currentEpoch
	p.keys[epoch] = key
	if aead, err := chacha20poly1305.New(key[:]); err == nil {
		p.aeads[epoch] = aead
	}
	p.windows[epoch] = newE2EReplayWindow()
	p.usage[epoch] = &KeyUsage{Started: now}
	p.txSeen[epoch] = false
	p.txFloor[epoch] = 0
	p.graceStart = time.Time{}
	p.currentEpoch = epoch
	return nil
}

// CanInstallEpoch is a non-mutating preflight for InstallEpoch. It lets a
// runtime check both a TX and an RX protector before installing an epoch pair,
// so a half install cannot happen. It reports ErrE2EClosed, ErrEpochExhausted,
// ErrE2EEpochMismatch, or ErrEpochRetained exactly as InstallEpoch would, and
// leaves all state untouched.
func (p *E2EProtector) CanInstallEpoch(epoch uint32) error {
	if p == nil {
		return ErrE2EConfig
	}
	if epoch == 0 || epoch == ^uint32(0) {
		return fmt.Errorf("%w: epoch %d", ErrEpochExhausted, epoch)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.canInstallLocked(epoch, p.clock())
}

func (p *E2EProtector) canInstallLocked(epoch uint32, now time.Time) error {
	if p.closed {
		return ErrE2EClosed
	}
	if p.currentEpoch != 0 && epoch != p.currentEpoch+1 {
		return fmt.Errorf("%w: epoch %d after %d", ErrE2EEpochMismatch, epoch, p.currentEpoch)
	}
	if p.previousEpoch != 0 && !p.graceExpiredLocked(now) {
		return fmt.Errorf("%w: epoch %d until %s", ErrEpochRetained, p.previousEpoch, p.previousGraceDeadlineLocked().UTC().Format(time.RFC3339Nano))
	}
	return nil
}

// MarkPeerNewEpochAuthenticated is the trusted source-side lifecycle event that
// the peer's committed epoch was authenticated by the opposite (RX) protector.
// A TX-only protector never calls Open, so it cannot start the previous epoch's
// grace on its own; the runtime forwards this event right after the matching RX
// protector successfully opens a current-epoch frame. It only starts the frozen
// 30-second retirement window for the existing previous epoch: it never
// installs a key, never accepts an arbitrary epoch, never clears state, and is
// idempotent for the current epoch. A missing previous epoch is a no-op.
func (p *E2EProtector) MarkPeerNewEpochAuthenticated(epoch uint32) error {
	if p == nil {
		return ErrE2EConfig
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrE2EClosed
	}
	if epoch == 0 || epoch != p.currentEpoch {
		return fmt.Errorf("%w: peer epoch %d, current %d", ErrE2EEpochMismatch, epoch, p.currentEpoch)
	}
	if p.previousEpoch == 0 || !p.graceStart.IsZero() {
		return nil
	}
	p.graceStart = p.clock()
	return nil
}

func (p *E2EProtector) recordVerificationFailureLocked() bool {
	if p.budget == nil {
		return true
	}
	return p.budget.RecordFailure()
}

// Seal protects plaintext for the frame's envelope epoch/message number. The
// frame's Envelope must be the exact 85-byte envelope and inner_len must equal
// len(plaintext); Kind must be E2E and Body is ignored.
func (p *E2EProtector) Seal(frame wire.Frame, plaintext []byte) (wire.Frame, error) {
	if p == nil {
		return wire.Frame{}, ErrE2EConfig
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return wire.Frame{}, ErrE2EClosed
	}
	epoch, number, inner, err := p.decodeEnvelope(frame)
	if err != nil {
		return wire.Frame{}, err
	}
	if uint64(inner) != uint64(len(plaintext)) {
		return wire.Frame{}, fmt.Errorf("%w: inner_len %d for %d plaintext bytes", ErrE2EEnvelope, inner, len(plaintext))
	}
	if number == ^uint64(0) {
		return wire.Frame{}, ErrE2ENonceExhausted
	}
	now := p.clock()
	if err := p.usableLocked(epoch, now, true); err != nil {
		return wire.Frame{}, err
	}
	if err := p.checkUsageLocked(epoch, len(plaintext), now); err != nil {
		return wire.Frame{}, err
	}
	if p.txSeen[epoch] && number <= p.txFloor[epoch] {
		return wire.Frame{}, fmt.Errorf("%w: message %d is not above %d", ErrE2ENonceExhausted, number, p.txFloor[epoch])
	}
	aead, ok := p.aeads[epoch]
	if !ok {
		return wire.Frame{}, fmt.Errorf("%w: epoch %d has no installed cipher", ErrE2EConfig, epoch)
	}
	nonce := e2eNonce(epoch, number)
	// Seal in place when the caller's slice has room for the tag: the plaintext is
	// not read after this call and Seal's dst may overlap its plaintext, so this
	// avoids allocating a whole ciphertext buffer per frame. That allocation was
	// about half of all bytes allocated during a 100 MiB transfer. A slice without
	// headroom falls back to a fresh buffer rather than reallocating under the
	// caller.
	if cap(plaintext)-len(plaintext) >= aead.Overhead() {
		frame.Body = aead.Seal(plaintext[:0], nonce[:], plaintext, frame.Envelope)
	} else {
		frame.Body = aead.Seal(nil, nonce[:], plaintext, frame.Envelope)
	}
	if frame.Body == nil {
		return wire.Frame{}, fmt.Errorf("%w: seal produced no body", ErrE2EConfig)
	}
	p.txSeen[epoch] = true
	p.txFloor[epoch] = number
	p.usage[epoch].SealInvocations = addU64Saturating(p.usage[epoch].SealInvocations, 1)
	p.usage[epoch].SealBytes = addU64Saturating(p.usage[epoch].SealBytes, uint64(len(plaintext)))
	return frame, nil
}

// Open authenticates and decrypts an E2E frame. Every binding field is checked
// before the AEAD; the replay precheck is read-only; the window and grace clock
// commit only after a successful tag.
func (p *E2EProtector) Open(frame wire.Frame) ([]byte, error) {
	if p == nil {
		return nil, ErrE2EConfig
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrE2EClosed
	}
	epoch, number, inner, err := p.decodeEnvelope(frame)
	if err != nil {
		return nil, err
	}
	if uint64(inner)+chacha20poly1305.Overhead != uint64(len(frame.Body)) {
		return nil, fmt.Errorf("%w: inner_len %d for %d body bytes", ErrE2EEnvelope, inner, len(frame.Body))
	}
	if number == ^uint64(0) {
		return nil, ErrE2ENonceExhausted
	}
	now := p.clock()
	if err := p.usableLocked(epoch, now, false); err != nil {
		return nil, err
	}
	window := p.windows[epoch]
	if window == nil {
		return nil, fmt.Errorf("%w: no replay window for epoch %d", ErrE2EEpochMismatch, epoch)
	}
	if err := window.precheck(number); err != nil {
		return nil, err
	}
	if err := p.checkUsageLocked(epoch, len(frame.Body), now); err != nil {
		return nil, err
	}
	aead, ok := p.aeads[epoch]
	if !ok {
		return nil, fmt.Errorf("%w: epoch %d has no installed cipher", ErrE2EConfig, epoch)
	}
	nonce := e2eNonce(epoch, number)
	plaintext, err := aead.Open(nil, nonce[:], frame.Body, frame.Envelope)
	if err != nil {
		p.usage[epoch].AuthFailures = addU64Saturating(p.usage[epoch].AuthFailures, 1)
		if !p.recordVerificationFailureLocked() {
			// Shared budget exhausted: fail closed without committing replay,
			// epoch or root state.
			return nil, fmt.Errorf("%w: shared verification budget exhausted", ErrKeyUsageExhausted)
		}
		return nil, fmt.Errorf("%w: %v", ErrE2EAuthentication, err)
	}
	// Atomic recheck + commit under the same lock: an invalid tag above never
	// reached here, so it never moved the window.
	if err := window.precheck(number); err != nil {
		return nil, err
	}
	window.commit(number)
	p.usage[epoch].OpenInvocations = addU64Saturating(p.usage[epoch].OpenInvocations, 1)
	p.usage[epoch].OpenBytes = addU64Saturating(p.usage[epoch].OpenBytes, uint64(len(plaintext)))
	if epoch == p.currentEpoch && p.previousEpoch != 0 && p.graceStart.IsZero() {
		p.graceStart = now
	}
	return plaintext, nil
}

// decodeEnvelope validates the frozen E2E envelope binding and returns the
// epoch, message number and inner_len.
func (p *E2EProtector) decodeEnvelope(frame wire.Frame) (uint32, uint64, uint32, error) {
	if frame.Kind != wire.FrameKindEndToEnd {
		return 0, 0, 0, fmt.Errorf("%w: FrameKind 0x%02x", ErrE2EEnvelope, uint8(frame.Kind))
	}
	env := frame.Envelope
	if len(env) != wire.EnvelopeSize {
		return 0, 0, 0, fmt.Errorf("%w: envelope is %d bytes", ErrE2EEnvelope, len(env))
	}
	if binary.BigEndian.Uint64(env[:8]) != p.wireID {
		return 0, 0, 0, fmt.Errorf("%w: network id", ErrE2EEnvelope)
	}
	src := env[8:24]
	dst := env[24:40]
	wantSrc, wantDst := p.src, p.dst
	if p.direction == DirectionResponderToInitiator {
		wantSrc, wantDst = p.dst, p.src
	}
	if !bytes.Equal(src, wantSrc[:]) || !bytes.Equal(dst, wantDst[:]) {
		return 0, 0, 0, fmt.Errorf("%w: endpoints", ErrE2EEnvelope)
	}
	if !classCarriesE2EMessageType(p.class, wire.MessageType(env[wire.EnvelopeMessageTypeOffset])) {
		return 0, 0, 0, fmt.Errorf("%w: message type 0x%02x for class %s",
			ErrE2EEnvelope, env[wire.EnvelopeMessageTypeOffset], p.class)
	}
	if !bytes.Equal(env[wire.EnvelopeSessionIDOffset:wire.EnvelopeKeyEpochOffset], p.sessionID[:]) {
		return 0, 0, 0, fmt.Errorf("%w: session id", ErrE2EEnvelope)
	}
	if binary.BigEndian.Uint64(env[wire.EnvelopePathIDOffset:]) != p.pathID ||
		binary.BigEndian.Uint32(env[wire.EnvelopePathGenerationOffset:]) != p.pathGeneration {
		return 0, 0, 0, fmt.Errorf("%w: path", ErrE2EEnvelope)
	}
	epoch := binary.BigEndian.Uint32(env[wire.EnvelopeKeyEpochOffset:])
	if epoch == 0 {
		return 0, 0, 0, fmt.Errorf("%w: epoch 0 is not a nonce domain", ErrE2EEnvelope)
	}
	number := binary.BigEndian.Uint64(env[wire.EnvelopeMessageNumberOffset:])
	inner := binary.BigEndian.Uint32(env[wire.EnvelopeInnerLengthOffset:])
	return epoch, number, inner, nil
}

// usableLocked reports whether epoch currently has a usable key. previousOnly
// is true for Seal, which additionally requires the previous epoch to still be
// inside its grace.
func (p *E2EProtector) usableLocked(epoch uint32, now time.Time, seal bool) error {
	if _, ok := p.keys[epoch]; !ok {
		return fmt.Errorf("%w: epoch %d is not installed (current %d)", ErrE2EEpochMismatch, epoch, p.currentEpoch)
	}
	if epoch == p.currentEpoch {
		return nil
	}
	if epoch != p.previousEpoch {
		return fmt.Errorf("%w: epoch %d is not installed (current %d)", ErrE2EEpochMismatch, epoch, p.currentEpoch)
	}
	if !p.graceValidLocked(now) {
		p.dropEpochLocked(epoch)
		if p.previousEpoch == epoch {
			p.previousEpoch = 0
		}
		return fmt.Errorf("%w: epoch %d grace expired", ErrE2EEpochMismatch, epoch)
	}
	return nil
}

func (p *E2EProtector) graceValidLocked(now time.Time) bool {
	if p.graceStart.IsZero() {
		return true
	}
	return now.Before(p.graceStart.Add(p.gracePeriod()))
}

// graceExpiredLocked reports whether the previous epoch's frozen grace window
// has actually elapsed. A zero graceStart means the window has not started yet,
// so it is NOT expired and the previous epoch must be retained.
func (p *E2EProtector) graceExpiredLocked(now time.Time) bool {
	if p.graceStart.IsZero() {
		return false
	}
	return !now.Before(p.graceStart.Add(p.gracePeriod()))
}

func (p *E2EProtector) previousGraceDeadlineLocked() time.Time {
	if p.graceStart.IsZero() {
		return time.Time{}
	}
	return p.graceStart.Add(p.gracePeriod())
}

func (p *E2EProtector) gracePeriod() time.Duration {
	if p.policy.GracePeriod > 0 {
		return p.policy.GracePeriod
	}
	return DefaultEpochGrace
}

func (p *E2EProtector) dropEpochLocked(epoch uint32) {
	if epoch == 0 {
		return
	}
	if _, ok := p.keys[epoch]; ok {
		p.keys[epoch] = [32]byte{}
		delete(p.keys, epoch)
		delete(p.aeads, epoch)
	}
	delete(p.windows, epoch)
	delete(p.usage, epoch)
	delete(p.txSeen, epoch)
	delete(p.txFloor, epoch)
}

func (p *E2EProtector) checkUsageLocked(epoch uint32, extraBytes int, now time.Time) error {
	u := p.usage[epoch]
	if u == nil {
		return nil
	}
	pol := p.policy.Usage
	// Checked sums: a counter overflow must fail closed, never wrap below a
	// configured ceiling.
	invocations, ok := addU64Checked(u.SealInvocations, u.OpenInvocations)
	if !ok {
		return fmt.Errorf("%w: invocation counters overflow", ErrKeyUsageExhausted)
	}
	totalBytes, ok := addU64Checked(u.SealBytes, u.OpenBytes)
	if !ok {
		return fmt.Errorf("%w: byte counters overflow", ErrKeyUsageExhausted)
	}
	if extraBytes < 0 {
		extraBytes = 0
	}
	extra := uint64(extraBytes)
	if pol.MaxInvocations > 0 && invocations >= pol.MaxInvocations {
		return fmt.Errorf("%w: invocations %d/%d", ErrKeyUsageExhausted, invocations, pol.MaxInvocations)
	}
	// Subtract the remaining budget instead of adding, so this comparison
	// cannot overflow either.
	if pol.MaxBytes > 0 && (totalBytes > pol.MaxBytes || extra > pol.MaxBytes-totalBytes) {
		return fmt.Errorf("%w: bytes %d+%d/%d", ErrKeyUsageExhausted, totalBytes, extraBytes, pol.MaxBytes)
	}
	if p.budget == nil && pol.MaxAuthFailures > 0 && u.AuthFailures >= pol.MaxAuthFailures {
		return fmt.Errorf("%w: auth failures %d/%d", ErrKeyUsageExhausted, u.AuthFailures, pol.MaxAuthFailures)
	}
	if pol.MaxAge > 0 && !u.Started.IsZero() && !now.Before(u.Started.Add(pol.MaxAge)) {
		return fmt.Errorf("%w: age %s/%s", ErrKeyUsageExhausted, now.Sub(u.Started), pol.MaxAge)
	}
	return nil
}

// addU64Checked returns a+b and whether the sum did not overflow.
func addU64Checked(a, b uint64) (uint64, bool) {
	sum := a + b
	if sum < a {
		return 0, false
	}
	return sum, true
}

// addU64Saturating returns min(a+b, MaxUint64), so an observed counter can
// never wrap below a configured ceiling.
func addU64Saturating(a, b uint64) uint64 {
	sum := a + b
	if sum < a {
		return ^uint64(0)
	}
	return sum
}

// trafficKeyLocked derives one epoch's directional traffic key.
func (p *E2EProtector) trafficKeyLocked(epoch uint32, root SessionRoot) ([32]byte, error) {
	var out [32]byte
	dirRoot := root.Direction(p.direction)
	defer clear(dirRoot[:])
	info := append([]byte("simpletier/v2/session-traffic"), byte(p.direction))
	info = append(info, p.sessionID[:]...)
	info = append(info, byte(p.class))
	info = binary.BigEndian.AppendUint32(info, epoch)
	info = appendLengthPrefixed(info, p.descriptor)
	derived, err := hkdf.Key(sha256.New, dirRoot[:], p.descriptor, string(info), 32)
	clear(info)
	if err != nil {
		return out, fmt.Errorf("session: derive epoch %d traffic key: %w", epoch, err)
	}
	copy(out[:], derived)
	clear(derived)
	return out, nil
}

func e2eNonce(epoch uint32, number uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[:4], epoch)
	binary.BigEndian.PutUint64(nonce[4:], number)
	return nonce
}

func classCarriesE2EMessageType(class SessionClass, messageType wire.MessageType) bool {
	switch class {
	case SessionClassPacket:
		return messageType == wire.MessageTypeIPPacket || messageType == wire.MessageTypeUDPDatagram
	case SessionClassStream:
		return messageType == wire.MessageTypeStreamData || messageType == wire.MessageTypeControlRPC
	default:
		return false
	}
}
