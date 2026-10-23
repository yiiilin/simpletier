package simpletier

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/flow"
	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/session"
	"github.com/yiiilin/simpletier/internal/topology"
	"github.com/yiiilin/simpletier/internal/wire"
)

// rekeyTestClock is a monotonic fake clock injected into the E2E protector
// policy. It drives real rekeys and the frozen 30s third-install grace without
// any test sleep.
type rekeyTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newRekeyTestClock() *rekeyTestClock {
	return &rekeyTestClock{now: time.Now()}
}

func (c *rekeyTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *rekeyTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// rekeyTestPolicy is a tiny, non-degenerate E2E policy: 128 AEAD invocations per
// key (7/8 soft = 112 frames) so a short stream crosses the source-driven rekey
// threshold for real. It is injected through the runtime's internal test seam,
// never through production configuration.
func rekeyTestPolicy(clk *rekeyTestClock) session.E2EPolicy {
	return rekeyTestPolicyMax(clk, 128)
}

// rekeyTestPolicyMax is the same test seam with a caller-chosen invocation
// ceiling. A multi-epoch 80 KiB burst needs a ceiling whose soft->hard headroom
// is wider than the 250ms policy tick can race through.
func rekeyTestPolicyMax(clk *rekeyTestClock, maxInvocations uint64) session.E2EPolicy {
	return session.E2EPolicy{
		Usage: session.UsagePolicy{
			MaxInvocations:  maxInvocations,
			MaxBytes:        1 << 40,
			MaxAge:          24 * time.Hour,
			MaxAuthFailures: 1 << 20,
		},
		Clock: clk.Now,
	}
}

func installRekeyPolicy(n *network, policy session.E2EPolicy) {
	n.streams.mu.Lock()
	n.streams.e2ePolicy = policy
	n.streams.mu.Unlock()
}

// rekeyTestNode starts one real SDK Network on a named network with a fixed
// VirtualIP, mirroring newRelayTestNode but parameterized so a test can use its
// own network name/CIDR/token.
func rekeyTestNode(t *testing.T, name, cidr, token, fixedIP, upstream string) *network {
	t.Helper()
	listenURL, _ := freeTCPListenAddress(t)
	cfg := Config{
		Listen:    []string{listenURL},
		Network:   NetworkConfig{Name: name, CIDR: cidr, Token: token},
		Options:   RuntimeOptions{FixedIP: fixedIP},
		Upstreams: nil,
	}
	if upstream != "" {
		cfg.Upstreams = []string{upstream}
	}
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork(fixed_ip=%s) error = %v", fixedIP, err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle.(*network)
}

// rekeyWaitRoute waits until source resolves a STREAM candidate path to the
// exact target VirtualIP of this test's network (the shared relay helper is
// pinned to another test's IP).
func rekeyWaitRoute(t *testing.T, source *network, targetIP netip.Addr, targetNode topology.NodeID, timeout time.Duration) {
	t.Helper()
	policy := topology.RoutePolicy{AllowRelay: true}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := source.facts.routes.ResolveVirtualIP(targetIP); err == nil {
			if paths, err := source.facts.routes.Candidates(targetNode, laneStream, policy); err == nil && len(paths) > 0 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("route to %s never converged", targetIP)
}

// rekeyEndpointEntry returns the committed non-relay entry of one class.
func rekeyEndpointEntry(t *testing.T, n *network, class session.SessionClass) *sessionEntry {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		n.streams.mu.Lock()
		for _, entry := range n.streams.sessionsByID {
			if entry == nil || entry.relay || entry.sess == nil || entry.class != class || !entry.isReady() {
				continue
			}
			n.streams.mu.Unlock()
			return entry
		}
		n.streams.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no committed endpoint session")
	return nil
}

// rekeyEntryInvocations reads each directional protector's current epoch
// invocation count, i.e. exactly the (Seal + Open) sum the 7/8 soft threshold
// and the hard ceiling compare against in the session policy.
func rekeyEntryInvocations(entry *sessionEntry) (txInvocations, rxInvocations uint64) {
	entry.protMu.Lock()
	tx, rx := entry.tx, entry.rx
	entry.protMu.Unlock()
	if tx != nil {
		if snap, ok := tx.UsageSnapshot(); ok {
			txInvocations = snap.SealInvocations + snap.OpenInvocations
		}
	}
	if rx != nil {
		if snap, ok := rx.UsageSnapshot(); ok {
			rxInvocations = snap.SealInvocations + snap.OpenInvocations
		}
	}
	return txInvocations, rxInvocations
}

// rekeyProtectorEpochs reads the runtime's installed epoch view.
func rekeyProtectorEpochs(entry *sessionEntry) (installed, txEpoch, rxEpoch uint32) {
	entry.protMu.Lock()
	defer entry.protMu.Unlock()
	installed = entry.installedEpoch
	if entry.tx != nil {
		txEpoch = entry.tx.CurrentEpoch()
	}
	if entry.rx != nil {
		rxEpoch = entry.rx.CurrentEpoch()
	}
	return installed, txEpoch, rxEpoch
}

// rekeyWaitSessionEpoch waits until every entry committed at least wantEpoch.
func rekeyWaitSessionEpoch(t *testing.T, want uint32, timeout time.Duration, entries ...*sessionEntry) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []uint32
	for time.Now().Before(deadline) {
		last = last[:0]
		ok := true
		for _, entry := range entries {
			rootEpoch, have := entry.sess.RootEpoch()
			last = append(last, rootEpoch.Epoch)
			if !have || rootEpoch.Epoch < want {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("session epoch never reached %d (last %v)", want, last)
}

// rekeyWaitInstalledEpoch waits until every entry installed exactly wantEpoch in
// both protectors.
func rekeyWaitInstalledEpoch(t *testing.T, want uint32, timeout time.Duration, entries ...*sessionEntry) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok := true
		for _, entry := range entries {
			installed, txEpoch, rxEpoch := rekeyProtectorEpochs(entry)
			if installed != want || txEpoch != want || rxEpoch != want {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, entry := range entries {
		installed, txEpoch, rxEpoch := rekeyProtectorEpochs(entry)
		t.Logf("entry %x installed=%d tx=%d rx=%d", entry.id[:4], installed, txEpoch, rxEpoch)
	}
	t.Fatalf("installed epoch never reached %d", want)
}

// rekeyWriteRead writes payload in chunks and reads back the identical echo,
// which forces each chunk through the real Circuit frame path.
func rekeyWriteRead(t *testing.T, stream Stream, payload []byte, chunk int) {
	t.Helper()
	echoed := make([]byte, len(payload))
	for start := 0; start < len(payload); start += chunk {
		end := start + chunk
		if end > len(payload) {
			end = len(payload)
		}
		if _, err := stream.Write(payload[start:end]); err != nil {
			t.Fatalf("write at %d: %v", start, err)
		}
		if _, err := io.ReadFull(stream, echoed[start:end]); err != nil {
			t.Fatalf("read echo at %d: %v", start, err)
		}
	}
	if !bytes.Equal(payload, echoed) {
		t.Fatalf("echo mismatch over %d bytes", len(payload))
	}
}

// rekeyEntryDue reports whether either directional protector of an entry has
// crossed its 7/8 soft threshold.
func rekeyEntryDue(entry *sessionEntry) bool {
	entry.protMu.Lock()
	tx, rx := entry.tx, entry.rx
	entry.protMu.Unlock()
	if tx != nil && tx.NeedsRekey() {
		return true
	}
	return rx != nil && rx.NeedsRekey()
}

// rekeyWriteUntilDue writes 64-byte chunks and reads each echo until the entry's
// protector reports NeedsRekey. It stops exactly at the soft boundary so a test
// never races the hard ceiling (WINDOW_UPDATE seals share the egress and inflate
// the invocation count, so a fixed frame count is not a reliable boundary).
//
// It also stops the moment the installed epoch rotates under the loop. The
// Network's 250ms policy tick can start the coalesced rekey while this loop is
// still writing; if that install lands before the next NeedsRekey check, the
// epoch changes and the fresh epoch's usage restarts at zero, so a
// NeedsRekey-only stop condition would silently keep writing into the NEW epoch
// until IT crosses soft — driving a second rekey the caller never intended.
// Stopping on the rotation keeps the "write to exactly one soft boundary"
// contract true, whichever side (this loop or the policy tick) wins the race.
func rekeyWriteUntilDue(t *testing.T, stream Stream, entry *sessionEntry, maxChunks int, seed byte) int {
	t.Helper()
	chunk := rekeyPattern(64, seed)
	echo := make([]byte, 64)
	startInstalled, _, _ := rekeyProtectorEpochs(entry)
	for i := 0; i < maxChunks; i++ {
		if rekeyEntryDue(entry) {
			return i
		}
		if installed, _, _ := rekeyProtectorEpochs(entry); startInstalled != 0 && installed != startInstalled {
			return i
		}
		if _, err := stream.Write(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if _, err := io.ReadFull(stream, echo); err != nil {
			t.Fatalf("read echo %d: %v", i, err)
		}
	}
	return maxChunks
}

// rekeyWriteOneWayUntilDue is rekeyWriteUntilDue without the echo read: the
// one-way topology has no peer bytes to read, so the test only writes and stops
// exactly at the protector's 7/8 soft boundary (never racing the tiny hard
// ceiling). It reuses the same due predicate and payload generator.
//
// The 1ms producer pace replaces the read round trip that paces the echo tests.
// An unpaced 64-byte burst of ~200 frames trips an early scoped egress failure
// (surfaced as a bare ErrSessionLost by mapStreamError) that is unrelated to the
// rekey seam under test; pacing keeps the run deterministic without changing any
// assertion.
func rekeyWriteOneWayUntilDue(t *testing.T, stream Stream, entry *sessionEntry, maxChunks int, seed byte) int {
	t.Helper()
	chunk := rekeyPattern(64, seed)
	startInstalled, _, _ := rekeyProtectorEpochs(entry)
	for i := 0; i < maxChunks; i++ {
		if rekeyEntryDue(entry) {
			return i
		}
		// Same epoch-rotation guard as rekeyWriteUntilDue: a policy-tick rekey
		// that installs mid-loop must stop this writer, not reset the budget it
		// is trying to cross once.
		if installed, _, _ := rekeyProtectorEpochs(entry); startInstalled != 0 && installed != startInstalled {
			return i
		}
		if _, err := stream.Write(chunk); err != nil {
			t.Fatalf("one-way write %d: %v", i, err)
		}
		time.Sleep(time.Millisecond)
	}
	return maxChunks
}

func rekeyPattern(size int, seed byte) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte((i*int(seed) + int(seed)*7 + 3) % 251)
	}
	return out
}

// TestSessionRekeyStreamEpochContinuity runs two real SDK Networks over a real
// carrier and drives the INNER SESSION rekey through epoch 1 -> 2 -> 3 while an
// 80 KiB stream keeps flowing. It asserts the completed rotations, that both
// sides converge on the committed epoch, that the epoch roots change while the
// SessionID/Path/physical Links stay pinned, and that the third install is
// retained by the frozen 30s grace (fake clock, no sleep) with data still
// flowing on the old protector until it completes.
func TestSessionRekeyStreamEpochContinuity(t *testing.T) {
	const (
		name  = "session-rekey-stream"
		cidr  = "10.99.0.0/24"
		token = "rekey-token-0123456789abcdef"
	)
	sourceIP := "10.99.0.1"
	targetIP := "10.99.0.3"
	clk := newRekeyTestClock()
	// A multi-epoch 80 KiB burst needs a soft->hard headroom wider than the
	// 250ms policy tick can race through; the tiny 128 ceiling is exercised by
	// TestSessionRekeyThirdInstallGrace and by the runtime hard-pause path.
	policy := rekeyTestPolicyMax(clk, 512)

	target := rekeyTestNode(t, name, cidr, token, targetIP, "")
	source := rekeyTestNode(t, name, cidr, token, sourceIP, relayCarrierURL(target))
	installRekeyPolicy(source, policy)
	installRekeyPolicy(target, policy)
	waitRelayLinks(t, target, 2, 30*time.Second)
	waitRelayLinks(t, source, 2, 30*time.Second)
	targetIdentity, err := target.identityStore.Identity()
	if err != nil {
		t.Fatalf("target identity: %v", err)
	}
	rekeyWaitRoute(t, source, netip.MustParseAddr(targetIP), topology.NodeID(targetIdentity.NodeID), 30*time.Second)
	listener, err := target.Listen("tcp", targetIP+":19031")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()
	serverRelease := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		stream, err := listener.Accept()
		if err != nil {
			return
		}
		defer stream.Close()
		buf := make([]byte, 4<<10)
		read := 0
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				read += n
				if _, werr := stream.Write(buf[:n]); werr != nil {
					t.Logf("echo server write stopped after %d bytes: %v", read, werr)
					break
				}
			}
			if err != nil {
				t.Logf("echo server read stopped after %d bytes: %v", read, err)
				break
			}
		}
		t.Logf("echo server loop ended after %d bytes", read)
		_ = stream.CloseWrite()
		<-serverRelease
	}()

	stream := relayDialUntil(t, source, targetIP+":19031", 5*time.Second, 30*time.Second)
	defer stream.Close()

	sourceEntry := rekeyEndpointEntry(t, source, session.SessionClassStream)
	targetEntry := rekeyEndpointEntry(t, target, session.SessionClassStream)
	epoch1, ok := sourceEntry.sess.RootEpoch()
	if !ok || epoch1.Epoch != 1 {
		t.Fatalf("initial source epoch = %d/%v, want 1", epoch1.Epoch, ok)
	}
	entryID := sourceEntry.id
	scope := sourceEntry.scope
	ps := source.streams.pathByScope(scope)
	if ps == nil {
		t.Fatal("source path state missing")
	}
	linksBefore := append([]topology.LinkRef(nil), ps.links...)
	nodesBefore := append([]topology.NodeID(nil), ps.nodes...)

	// Phase A: write until the epoch-1 protector actually reports NeedsRekey, so
	// the test stops exactly at the 7/8 soft boundary and never races the hard
	// ceiling (control seals share the egress and inflate the invocation count).
	if chunks := rekeyWriteUntilDue(t, stream, sourceEntry, 4096, 3); chunks == 4096 {
		t.Fatal("epoch-1 protector never reached its soft threshold")
	}

	source.streams.pollSessionRekeys()
	rekeyWaitSessionEpoch(t, 2, 20*time.Second, sourceEntry, targetEntry)
	rekeyWaitInstalledEpoch(t, 2, 20*time.Second, sourceEntry, targetEntry)

	// Explicitly assert BOTH endpoints installed epoch 2 in BOTH directions, and
	// that the next small write is real business after the completed rekey.
	for name, entry := range map[string]*sessionEntry{"source": sourceEntry, "target": targetEntry} {
		rootEpoch, have := entry.sess.RootEpoch()
		installed, txEpoch, rxEpoch := rekeyProtectorEpochs(entry)
		if !have || rootEpoch.Epoch != 2 || installed != 2 || txEpoch != 2 || rxEpoch != 2 {
			t.Fatalf("%s after rekey: committed=%d/%v installed=%d tx=%d rx=%d, want epoch 2 everywhere",
				name, rootEpoch.Epoch, have, installed, txEpoch, rxEpoch)
		}
	}
	rekeyWriteRead(t, stream, rekeyPattern(512, 23), 64)

	epoch2, _ := sourceEntry.sess.RootEpoch()
	if bytes.Equal(epoch1.Root, epoch2.Root) {
		t.Fatal("rekey committed a new epoch with an unchanged root")
	}
	if sourceEntry.id != entryID || sourceEntry.scope != scope {
		t.Fatalf("rekey changed session identity: id %x scope %+v", sourceEntry.id[:4], sourceEntry.scope)
	}
	if now := source.streams.pathByScope(scope); now == nil || len(now.links) != len(linksBefore) {
		t.Fatal("rekey changed the pinned physical Links")
	} else {
		for i := range linksBefore {
			if now.links[i] != linksBefore[i] || now.nodes[i] != nodesBefore[i] {
				t.Fatalf("rekey changed physical link/route at hop %d", i)
			}
		}
	}

	// Phase B: write until the epoch-2 protector reports NeedsRekey, so epoch 3
	// commits without the producer racing epoch 2's hard ceiling. The install is
	// then still deferred by the frozen grace; the clock is advanced only to let
	// the deliberate third install complete before the bulk write proceeds.
	if chunks := rekeyWriteUntilDue(t, stream, sourceEntry, 4096, 5); chunks == 4096 {
		t.Fatal("epoch-2 protector never reached its soft threshold")
	}

	source.streams.pollSessionRekeys()
	rekeyWaitSessionEpoch(t, 3, 20*time.Second, sourceEntry, targetEntry)
	for name, entry := range map[string]*sessionEntry{"source": sourceEntry, "target": targetEntry} {
		installed, txEpoch, rxEpoch := rekeyProtectorEpochs(entry)
		if installed != 2 || txEpoch != 2 || rxEpoch != 2 {
			t.Fatalf("%s third install was not retained by the grace: installed=%d tx=%d rx=%d", name, installed, txEpoch, rxEpoch)
		}
	}

	clk.Advance(session.DefaultEpochGrace + time.Second)
	source.streams.pollSessionRekeys()
	rekeyWaitInstalledEpoch(t, 3, 20*time.Second, sourceEntry, targetEntry)

	// Phase C: the remaining business bulk crosses the now-installed epoch 3 in
	// large writes so the last epoch stays well below its ceiling.
	rekeyWriteRead(t, stream, rekeyPattern(64<<10, 11), 4<<10)

	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	close(serverRelease)
	<-serverDone

	// Duplicate SESSION_READY for the committed epoch is idempotent: it neither
	// re-installs an epoch nor resets the egress sequence or grace state.
	attempt, epoch, _, _ := targetEntry.attemptIdentity()
	ready := session.SessionReady{
		SessionID:      targetEntry.id,
		Class:          targetEntry.class,
		DataLaneID:     targetEntry.lane,
		Attempt:        attempt,
		TargetEpoch:    epoch,
		PathID:         targetEntry.scope.id,
		PathGeneration: targetEntry.scope.gen,
	}
	readyPayload, err := ready.Encode()
	if err != nil {
		t.Fatalf("encode duplicate READY: %v", err)
	}
	envelope := buildEnvelope(target.streams.wireID, targetEntry.src, targetEntry.dst, wire.MessageTypeSessionReady, [16]byte(targetEntry.id), 0, 0, targetEntry.scope.id, targetEntry.scope.gen, len(readyPayload))
	targetEntry.txMu.Lock()
	numberBefore := targetEntry.txNumber
	targetEntry.txMu.Unlock()
	if err := target.streams.handleSessionReady(link.ProtectedMessage{Envelope: envelope, Payload: readyPayload}, targetEntry.scope.id, targetEntry.scope.gen); err != nil {
		t.Fatalf("duplicate SESSION_READY returned %v", err)
	}
	targetEntry.txMu.Lock()
	numberAfter := targetEntry.txNumber
	targetEntry.txMu.Unlock()
	if numberBefore != numberAfter {
		t.Fatalf("duplicate READY reset the egress sequence: %d -> %d", numberBefore, numberAfter)
	}
	if rootEpoch, _ := targetEntry.sess.RootEpoch(); rootEpoch.Epoch != 3 {
		t.Fatalf("duplicate READY changed the committed epoch to %d", rootEpoch.Epoch)
	}
	if installed, _, _ := rekeyProtectorEpochs(targetEntry); installed != 3 {
		t.Fatalf("duplicate READY moved installed epoch to %d", installed)
	}
}

// rekeyRelayRootlessPolicyMax is the E2E invocation ceiling for
// TestSessionRekeyRelayRootless specifically. That scenario must complete
// EXACTLY ONE rekey transition, so its 7/8 soft threshold has to stay above the
// whole epoch-2 demand of the post-rekey business write. That demand is
// dominated by WINDOW_UPDATE amplification, not by the payload: each
// circuitStream.Read calls refillWindow, which seals one CONTROL_RPC frame, so
// the 4 KiB echo (rekeyWriteRead with chunk 64) costs ~129-130 epoch-2
// invocations per direction (64 STREAM_DATA + 64 WINDOW_UPDATE + 1 close; the
// target sealed 130), not 64.
//
// Measured on this topology from the source entry's UsageSnapshot over 20
// iterations: every passing run ended epoch 2 at exactly tx=129 / rx=129
// (target tx=130), and the old 512 ceiling's intermittent failures ended at the
// hard cap tx=512 / rx=512. Those failures were NOT a workload demand near 512:
// a snapshot taken right after rekeyWaitInstalledEpoch(2) showed epoch-2 usage
// already at tx=449 / rx=448 on BOTH failing runs and 0/0 on all 18 passing
// runs. The extra budget was written by rekeyWriteUntilDue, whose
// NeedsRekey-only stop condition kept writing into the freshly installed epoch 2
// after the 250ms policy tick won the rekey race mid-loop; epoch 2 therefore
// started at its own soft threshold, the tiny post-rekey write crossed soft, and
// a SECOND rekey (attempt 2 / epoch 3) was committed and then deferred forever
// by the frozen grace on the never-advancing injected clock — after which the
// real-clock 5s hard-ceiling pause in awaitSealHeadroom failed the Circuit
// closed (required by docs/domains/overlay/modules/wire-protocol.md:62).
// rekeyWriteUntilDue now also stops when the installed epoch rotates under the
// loop, which removes that extra budget.
//
// 1024 => soft = 7/8 * 1024 = 896: ~6.9x the measured deterministic epoch-2
// demand (129 source / 130 target), so the fixed post-rekey write cannot cross
// soft and cannot request a second rekey. The initial trigger still adapts
// automatically to the higher ceiling because rekeyWriteUntilDue writes until
// NeedsRekey instead of for a fixed frame count. The ceiling is deliberately NOT
// shared with the multi-epoch tests (TestSessionRekeyStreamEpochContinuity and
// TestSessionRekeyThirdInstallGrace), which must cross soft on purpose.
const rekeyRelayRootlessPolicyMax = 1024

// TestSessionRekeyRelayRootless drives the same rekey across a real A -> R -> B
// relay topology. The relay must observe the next attempt of the same
// SessionID/scope/class/lane, keep forwarding opaque ciphertext, and stay
// rootless: no Session, no root, no E2E protector. A future attempt that no
// matching SESSION_CTRL registered is rejected without disturbing the entry.
// The scenario performs exactly ONE rekey transition and asserts that rather
// than assuming it (see rekeyRelayRootlessPolicyMax).
func TestSessionRekeyRelayRootless(t *testing.T) {
	clk := newRekeyTestClock()
	policy := rekeyTestPolicyMax(clk, rekeyRelayRootlessPolicyMax)

	source, relay, target := newRelayTopology(t)
	installRekeyPolicy(source, policy)
	installRekeyPolicy(target, policy)

	listener, err := target.Listen("tcp", relayTargetIP+":19041")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()
	serverRelease := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		stream, err := listener.Accept()
		if err != nil {
			return
		}
		defer stream.Close()
		buf := make([]byte, 4<<10)
		read := 0
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				read += n
				if _, werr := stream.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = stream.CloseWrite()
		<-serverRelease
	}()

	stream := relayDialUntil(t, source, relayTargetIP+":19041", 5*time.Second, 30*time.Second)
	defer stream.Close()

	sourceEntry := rekeyEndpointEntry(t, source, session.SessionClassStream)
	targetEntry := rekeyEndpointEntry(t, target, session.SessionClassStream)
	// The relay table can hold more than one relayed session (for example a
	// stale probe), so address the exact SessionID the endpoints established
	// instead of whichever relay entry the map yields first.
	relaySessionID := sourceEntry.id
	relayEntry := relay.streams.sessionEntryByID(relaySessionID)
	if relayEntry == nil || !relayEntry.relay {
		t.Fatalf("relay never observed session %x", relaySessionID[:4])
	}

	// Drive the rekey by usage so the tiny-ceiling race cannot strand the relay.
	if chunks := rekeyWriteUntilDue(t, stream, sourceEntry, 4096, 13); chunks == 4096 {
		t.Fatal("relay: source protector never reached its soft threshold")
	}
	source.streams.pollSessionRekeys()
	rekeyWaitInstalledEpoch(t, 2, 20*time.Second, sourceEntry, targetEntry)

	// Re-read the relay's live entry for the exact SessionID after the rekey: the
	// relay records the next attempt on its own reader goroutine, so a pointer
	// captured before the rekey is not a reliable view of its final identity.
	relayEntry = relay.streams.sessionEntryByID(relaySessionID)
	if relayEntry == nil || !relayEntry.relay {
		t.Fatalf("relay session entry %x disappeared after the rekey", relaySessionID[:4])
	}

	// The relay saw the next attempt but never built endpoint state. The initial
	// attempt is 0/epoch 1, so the first rekey identity is exactly 1/epoch 2.
	attempt, epoch, _, _ := relayEntry.attemptIdentity()
	if attempt < 1 || epoch < 2 {
		t.Fatalf("relay did not observe the next attempt: %d/%d", attempt, epoch)
	}
	if relayEntry.sess != nil {
		t.Fatal("relay acquired a Session object during rekey")
	}
	relayEntry.protMu.Lock()
	tx, rx := relayEntry.tx, relayEntry.rx
	relayEntry.protMu.Unlock()
	if tx != nil || rx != nil {
		t.Fatal("relay acquired E2E protectors during rekey")
	}
	if got := relay.streams.sessions.Len(); got != 0 {
		t.Fatalf("relay opened %d local Session(s) during rekey, want 0", got)
	}

	// A future attempt that no matching SESSION_CTRL registered is rejected and
	// leaves the relay entry untouched.
	relayPS := relay.streams.pathByScope(relayEntry.scope)
	if relayPS == nil {
		t.Fatal("relay path state missing")
	}
	bad := session.SessionCtrl{
		SessionID:   relayEntry.id,
		Class:       relayEntry.class,
		DataLaneID:  relayEntry.lane,
		Attempt:     attempt + 2,
		TargetEpoch: epoch + 2,
		Payload:     []byte{0x01, 0x02, 0x03},
	}
	badPayload, err := bad.Encode()
	if err != nil {
		t.Fatalf("encode future attempt: %v", err)
	}
	badEnvelope := buildEnvelope(relay.streams.wireID, [16]byte(relayPS.nodes[0]), [16]byte(relayPS.nodes[len(relayPS.nodes)-1]), wire.MessageTypeSessionCtrl, [16]byte(relayEntry.id), 0, 0, relayEntry.scope.id, relayEntry.scope.gen, len(badPayload))
	if err := relay.streams.observeRelaySessionCtrl(relayPS, badEnvelope, badPayload); !errors.Is(err, link.ErrRouteMessage) {
		t.Fatalf("future relay attempt error = %v, want %v", err, link.ErrRouteMessage)
	}
	attemptAfter, epochAfter, _, _ := relayEntry.attemptIdentity()
	if attemptAfter != attempt || epochAfter != epoch {
		t.Fatalf("rejected future attempt mutated relay identity: %d/%d -> %d/%d", attempt, epoch, attemptAfter, epochAfter)
	}

	// Business continues through the relay on the new epoch.
	rekeyWriteRead(t, stream, rekeyPattern(4<<10, 17), 64)

	// rekeyRelayRootlessPolicyMax exists so that the write above cannot request a
	// second transition. Assert that property instead of assuming it: the source
	// is still committed AND installed at epoch 2 with no rekey staged, and the
	// relay still records exactly one attempt advance. A regression that shrinks
	// the ceiling below the measured epoch-2 demand makes this fail with the
	// observed invocation counts instead of an opaque Circuit loss.
	txInvocations, rxInvocations := rekeyEntryInvocations(sourceEntry)
	sourceEpoch, sourceHave := sourceEntry.sess.RootEpoch()
	installed, txEpoch, rxEpoch := rekeyProtectorEpochs(sourceEntry)
	rekeyStaged := sourceEntry.isRekeyPending()
	if !sourceHave || sourceEpoch.Epoch != 2 || installed != 2 || txEpoch != 2 || rxEpoch != 2 || rekeyStaged {
		t.Fatalf("relay scenario performed more than one rekey: source committed=%d/%v installed=%d tx=%d rx=%d rekey_staged=%v (epoch-2 invocations tx=%d rx=%d, soft ceiling=%d)",
			sourceEpoch.Epoch, sourceHave, installed, txEpoch, rxEpoch, rekeyStaged,
			txInvocations, rxInvocations, rekeyRelayRootlessPolicyMax*7/8)
	}
	relayAttempt, relayEpoch, relayRekeyStaged, relayStagedEpoch := relayEntry.attemptIdentity()
	if relayAttempt != session.FirstAttempt+1 || relayEpoch != session.FirstTargetEpoch+1 || relayRekeyStaged {
		t.Fatalf("relay recorded more than one attempt advance: attempt=%d epoch=%d staged=%v staged_epoch=%d, want exactly %d/%d",
			relayAttempt, relayEpoch, relayRekeyStaged, relayStagedEpoch, session.FirstAttempt+1, session.FirstTargetEpoch+1)
	}

	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("relay CloseWrite: %v", err)
	}
	close(serverRelease)
	<-serverDone
}

// rekeyAwaitDelivery is the stop-and-wait pacing step for the PACKET-class
// producer: it blocks until the target hands over the reassembled datagram for
// the fragment just sent, bounded by timeout and the test context so a genuinely
// broken path fails with the fragment index instead of hanging.
func rekeyAwaitDelivery(t *testing.T, ctx context.Context, delivery *captureFlowDelivery, fragment int, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-delivery.datagrams:
	case <-timer.C:
		t.Fatalf("Fragment(%d): target never delivered the paced datagram within %s", fragment, timeout)
	case <-ctx.Done():
		t.Fatalf("Fragment(%d): target never delivered the paced datagram: %v", fragment, ctx.Err())
	}
}

// TestSessionRekeyUDPMaxDatagram proves the same rekey keeps the Flow UDP plane
// delivering one maximum 65,507-byte datagram over a real two-Network carrier
// after the epoch rotated: the fragment frames are sealed under the committed
// epoch and reassembled identically.
func TestSessionRekeyUDPMaxDatagram(t *testing.T) {
	const (
		name  = "session-rekey-udp"
		cidr  = "10.100.0.0/24"
		token = "rekey-udp-token-0123456789ab"
	)
	sourceIP := netip.MustParseAddr("10.100.0.1")
	targetIP := netip.MustParseAddr("10.100.0.3")

	clk := newRekeyTestClock()
	policy := rekeyTestPolicy(clk)

	target := newPacketPlaneNode(t, name, cidr, token, targetIP.String(), "")
	source := newPacketPlaneNode(t, name, cidr, token, sourceIP.String(), relayCarrierURL(target))
	installRekeyPolicy(source, policy)
	installRekeyPolicy(target, policy)

	targetDelivery := newCaptureFlowDelivery()
	if err := target.streams.enableFlowService(targetDelivery); err != nil {
		t.Fatalf("enable target flow plane: %v", err)
	}
	if err := source.streams.enableFlowService(newCaptureFlowDelivery()); err != nil {
		t.Fatalf("enable source flow plane: %v", err)
	}
	waitRelayLinks(t, target, 3, 30*time.Second)
	waitRelayLinks(t, source, 3, 30*time.Second)
	waitPacketRoute(t, source, targetIP, 30*time.Second)

	association, err := source.streams.flow.CreateAssociation()
	if err != nil {
		t.Fatalf("CreateAssociation: %v", err)
	}
	defer association.Close()

	// Cross the tiny soft threshold on the PACKET-class session with real
	// datagrams, then complete the rekey before the maximum datagram.
	//
	// This loop is PACED, not merely drained. Enqueue is ASYNCHRONOUS
	// (wire-protocol 2.2: a successful enqueue does not mean the peer received
	// it, and an overflowing UDP_DATAGRAM queue is drop+count), while the
	// source's single LINK_CTRL/E2E writer goroutine drains one frozen 64-slot
	// outbound queue (controlReplyQueueLimit) whose tail reserves
	// keyUpdateQueueReserve=8 slots for key updates. A blind 130-frame burst can
	// outrun that writer and get the correct package-level ErrResource ("resource
	// limit") back from enqueue; the queue bound is authoritative, so the
	// producer must observe real egress progress. Waiting for each accepted
	// datagram to reappear on the target's delivery port before sending the next
	// keeps outstanding egress at one frame, so the bounded queue can never be
	// what fails this threshold-crossing loop. Do not replace this with a bare
	// sleep or delete it as a redundant drain.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i := 0; i < 130; i++ {
		if err := association.Fragment(ctx, flow.OutboundDatagram{
			Source:      netip.AddrPortFrom(sourceIP, 40000),
			Destination: netip.AddrPortFrom(targetIP, 40101),
			Payload:     rekeyPattern(64, byte(i%250+1)),
		}); err != nil {
			t.Fatalf("Fragment(%d): %v", i, err)
		}
		rekeyAwaitDelivery(t, ctx, targetDelivery, i, 5*time.Second)
	}
	source.streams.pollSessionRekeys()
	sourceEntry := rekeyEndpointEntry(t, source, session.SessionClassPacket)
	targetEntry := rekeyEndpointEntry(t, target, session.SessionClassPacket)
	rekeyWaitInstalledEpoch(t, 2, 20*time.Second, sourceEntry, targetEntry)

	maxPayload := rekeyPattern(flow.MaxDatagramPayload, 19)
	if err := association.Fragment(ctx, flow.OutboundDatagram{
		Source:      netip.AddrPortFrom(sourceIP, 40000),
		Destination: netip.AddrPortFrom(targetIP, 40001),
		Payload:     maxPayload,
	}); err != nil {
		t.Fatalf("Fragment(max): %v", err)
	}
	deadline := time.After(30 * time.Second)
	for {
		select {
		case got := <-targetDelivery.datagrams:
			if got.Destination.Port() != 40001 {
				continue
			}
			if !bytes.Equal(got.Payload, maxPayload) {
				t.Fatalf("reassembled max datagram = %d bytes, want %d identical", len(got.Payload), len(maxPayload))
			}
			return
		case <-deadline:
			t.Fatal("target never delivered the maximum datagram after rekey")
		}
	}
}

// TestSessionRekeyThirdInstallGrace drives epoch 1 -> 2 normally and then, with
// the fake clock frozen, crosses the epoch-2 soft threshold with just enough
// traffic to trigger the next rekey without hitting the tiny 128 hard ceiling.
// It asserts the frozen third-install retention: the Session commits epoch 3
// while both protectors keep serving epoch 2, business still flows, and only
// after the 30s grace advances (fake clock, no sleep) does the deferred epoch 3
// install on the same protectors.
func TestSessionRekeyThirdInstallGrace(t *testing.T) {
	const (
		name  = "session-rekey-grace"
		cidr  = "10.101.0.0/24"
		token = "rekey-grace-token-0123456789"
	)
	sourceIP := "10.101.0.1"
	targetIP := "10.101.0.3"

	clk := newRekeyTestClock()
	policy := rekeyTestPolicy(clk)

	target := rekeyTestNode(t, name, cidr, token, targetIP, "")
	source := rekeyTestNode(t, name, cidr, token, sourceIP, relayCarrierURL(target))
	installRekeyPolicy(source, policy)
	installRekeyPolicy(target, policy)
	waitRelayLinks(t, target, 2, 30*time.Second)
	waitRelayLinks(t, source, 2, 30*time.Second)
	targetIdentity, err := target.identityStore.Identity()
	if err != nil {
		t.Fatalf("target identity: %v", err)
	}
	rekeyWaitRoute(t, source, netip.MustParseAddr(targetIP), topology.NodeID(targetIdentity.NodeID), 30*time.Second)

	listener, err := target.Listen("tcp", targetIP+":19051")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()
	serverRelease := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		stream, err := listener.Accept()
		if err != nil {
			return
		}
		defer stream.Close()
		buf := make([]byte, 4<<10)
		read := 0
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				read += n
				if _, werr := stream.Write(buf[:n]); werr != nil {
					t.Logf("grace echo write stopped after %d bytes: %v", read, werr)
					break
				}
			}
			if err != nil {
				t.Logf("grace echo read stopped after %d bytes: %v", read, err)
				break
			}
		}
		_ = stream.CloseWrite()
		<-serverRelease
	}()

	stream := relayDialUntil(t, source, targetIP+":19051", 5*time.Second, 30*time.Second)
	defer stream.Close()

	sourceEntry := rekeyEndpointEntry(t, source, session.SessionClassStream)
	targetEntry := rekeyEndpointEntry(t, target, session.SessionClassStream)

	// Phase A: write until the epoch-1 protector reports NeedsRekey (the tiny
	// 128 ceiling has only 16 frames of soft->hard headroom, and control seals
	// share the egress), then let epoch 2 install.
	if chunks := rekeyWriteUntilDue(t, stream, sourceEntry, 1024, 29); chunks == 1024 {
		t.Fatal("grace: epoch-1 protector never reached its soft threshold")
	}
	source.streams.pollSessionRekeys()
	rekeyWaitInstalledEpoch(t, 2, 20*time.Second, sourceEntry, targetEntry)

	// Phase B: write until the epoch-2 protector reports NeedsRekey and stop. The
	// next rekey commits epoch 3 but must NOT install while the grace is frozen.
	if chunks := rekeyWriteUntilDue(t, stream, sourceEntry, 1024, 31); chunks == 1024 {
		t.Fatal("grace: epoch-2 protector never reached its soft threshold")
	}
	source.streams.pollSessionRekeys()
	rekeyWaitSessionEpoch(t, 3, 20*time.Second, sourceEntry, targetEntry)
	for name, entry := range map[string]*sessionEntry{"source": sourceEntry, "target": targetEntry} {
		installed, txEpoch, rxEpoch := rekeyProtectorEpochs(entry)
		if installed != 2 || txEpoch != 2 || rxEpoch != 2 {
			t.Fatalf("%s third install was not retained by the grace: installed=%d tx=%d rx=%d", name, installed, txEpoch, rxEpoch)
		}
	}
	// Old-epoch business still flows while epoch 3 is deferred.
	rekeyWriteRead(t, stream, rekeyPattern(256, 37), 64)

	clk.Advance(session.DefaultEpochGrace + time.Second)
	source.streams.pollSessionRekeys()
	rekeyWaitInstalledEpoch(t, 3, 20*time.Second, sourceEntry, targetEntry)

	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("grace CloseWrite: %v", err)
	}
	close(serverRelease)
	<-serverDone
}

// TestSessionRekeyOneWayThirdInstallGraceZeroStart is the regression probe for
// the BOUNDED one-way Session rekey. With application traffic in ONE direction
// only, the source's previous-epoch grace clock never starts (no authenticated
// inbound CURRENT-epoch E2E frame ever arrives), so the frozen third-install
// grace can never expire on that side. Unbounded, the Session would stay
// committed at epoch E+2 while both tx/rx protectors stayed installed at E+1
// forever: the peer's fresh epoch ciphertext would be staged and never drained,
// and one direction would silently stall.
//
// The mechanism under test (all production code, no private-helper shortcut):
//   - E2EProtector.Open starts the previous epoch's retirement window only when
//     it authenticates a frame of its OWN current epoch, and
//     streamRuntime.recordAuthenticatedEpoch forwards that trusted event to the
//     TX protector only for the same frame;
//   - E2EProtector.graceExpiredLocked deliberately treats a zero graceStart as
//     "window has not started", i.e. NOT expired, so CanInstallEpoch keeps
//     returning ErrEpochRetained;
//   - streamRuntime.installCommittedEpoch turns that refusal into
//     deferRekeyInstall, and pollSessionRekeys -> retryDeferredInstall keeps
//     retrying it, now BOUNDED by one frozen epoch-grace budget on the same
//     clock as the grace. After that bound the deferral is abandoned and only
//     this Session/Path is failed scoped.
//
// The target does receive the source's epoch-2 data, so its grace does start and
// it retires normally; the source is the outlier.
//
// The topology is one-way on purpose: the target accepts the circuit but never
// reads and never writes, and the run stays far below the 64 KiB initial credit,
// so the only target->source E2E traffic that could start the source's grace
// clock (WINDOW_UPDATE, emitted by circuitStream.refillWindow only after a
// successful Read) never happens.
//
// The test drives usage -> pollSessionRekeys -> Session.Rekey -> SESSION_CTRL ->
// HandleOpen -> SESSION_READY -> HandleReady -> ensureProtectors ->
// installCommittedEpoch, then the production retry path after the bounded window
// elapses on the source's own clock. Each side gets its own frozen clock so the
// peer's epoch-3 ciphertext is deterministically staged before the source's
// bounded failure can run. It asserts the FIXED contract:
//
//	(a) after the window the source Session is not left active with a committed
//	    epoch that is not installed;
//	(b) it is terminal (ErrSessionLost on the affected Circuit) and the staged
//	    peer epoch-3 ciphertext is released, not retained forever;
//	(c) a fresh Session established through the real SDK path over the SAME
//	    physical Link keeps transferring;
//	(d) the Staged ciphertext ledger returns to its baseline (no leaked leases).
//
// STATUS: this probe asserts the bounded behavior. It FAILED on the pre-fix tree,
// which deferred the install forever; it passes with the bounded scoped failure.
func TestSessionRekeyOneWayThirdInstallGraceZeroStart(t *testing.T) {
	const (
		name  = "session-rekey-oneway"
		cidr  = "10.102.0.0/24"
		token = "rekey-oneway-token-0123456789"
	)
	sourceIP := "10.102.0.1"
	targetIP := "10.102.0.3"

	// Each side keeps its own frozen clock: the target retires its previous
	// epoch and installs epoch 3 on its clock, while the source's clock stays put
	// until the peer ciphertext has actually been staged, so the assertions are
	// deterministic under the runtime's background policy tick.
	sourceClock := newRekeyTestClock()
	targetClock := newRekeyTestClock()
	// The tiny 128 ceiling is the same seam TestSessionRekeyThirdInstallGrace
	// uses: 7/8 soft = 112 frames, and the whole run stays under the 64 KiB
	// initial stream credit so no WINDOW_UPDATE is ever needed.
	sourcePolicy := rekeyTestPolicy(sourceClock)
	targetPolicy := rekeyTestPolicy(targetClock)

	target := rekeyTestNode(t, name, cidr, token, targetIP, "")
	source := rekeyTestNode(t, name, cidr, token, sourceIP, relayCarrierURL(target))
	installRekeyPolicy(source, sourcePolicy)
	installRekeyPolicy(target, targetPolicy)
	waitRelayLinks(t, target, 2, 30*time.Second)
	waitRelayLinks(t, source, 2, 30*time.Second)
	targetIdentity, err := target.identityStore.Identity()
	if err != nil {
		t.Fatalf("target identity: %v", err)
	}
	rekeyWaitRoute(t, source, netip.MustParseAddr(targetIP), topology.NodeID(targetIdentity.NodeID), 30*time.Second)

	// The one-way server accepts so the dial completes, then neither reads nor
	// writes: after the epoch-2 install the target emits no E2E frame at all on
	// this Session.
	listener, err := target.Listen("tcp", targetIP+":19061")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	defer listener.Close()
	serverStream := make(chan Stream, 1)
	serverRelease := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		accepted, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer accepted.Close()
		serverStream <- accepted
		<-serverRelease
	}()

	// A second, healthy echo listener for the independent Session of (c): it
	// proves the scoped failure leaves the physical Link and its other Sessions
	// working.
	echoListener, err := target.Listen("tcp", targetIP+":19062")
	if err != nil {
		t.Fatalf("second target Listen: %v", err)
	}
	defer echoListener.Close()
	go func() {
		for {
			accepted, acceptErr := echoListener.Accept()
			if acceptErr != nil {
				return
			}
			go func(s Stream) {
				defer s.Close()
				buf := make([]byte, 4<<10)
				for {
					n, readErr := s.Read(buf)
					if n > 0 {
						if _, werr := s.Write(buf[:n]); werr != nil {
							return
						}
					}
					if readErr != nil {
						return
					}
				}
			}(accepted)
		}
	}()

	stream := relayDialUntil(t, source, targetIP+":19061", 5*time.Second, 30*time.Second)
	defer stream.Close()

	var targetSide Stream
	select {
	case targetSide = <-serverStream:
	case <-time.After(10 * time.Second):
		t.Fatal("target never accepted the one-way circuit")
	}

	sourceEntry := rekeyEndpointEntry(t, source, session.SessionClassStream)
	targetEntry := rekeyEndpointEntry(t, target, session.SessionClassStream)
	psBefore := source.streams.pathByScope(sourceEntry.scope)
	if psBefore == nil {
		t.Fatal("source path state missing")
	}
	linksBefore := append([]topology.LinkRef(nil), psBefore.links...)
	readyLinksBefore := countReadyLinks(source)
	failedSessionID := sourceEntry.id

	// Phase A: cross the epoch-1 soft threshold with source->target writes only.
	if chunks := rekeyWriteOneWayUntilDue(t, stream, sourceEntry, 1024, 43); chunks == 1024 {
		t.Fatal("one-way: epoch-1 protector never reached its soft threshold")
	}
	source.streams.pollSessionRekeys()
	rekeyWaitInstalledEpoch(t, 2, 20*time.Second, sourceEntry, targetEntry)

	// Phase B: cross the epoch-2 soft threshold. The target opened the source's
	// epoch-2 frames, so the target's grace clock started; the source opened
	// nothing, so both of its grace clocks are still zero.
	if chunks := rekeyWriteOneWayUntilDue(t, stream, sourceEntry, 1024, 47); chunks == 1024 {
		t.Fatal("one-way: epoch-2 protector never reached its soft threshold")
	}
	source.streams.pollSessionRekeys()
	rekeyWaitSessionEpoch(t, 3, 20*time.Second, sourceEntry, targetEntry)

	// Both endpoints committed epoch 3 through the real READY path while both
	// protectors still serve epoch 2: the frozen third-install deferral. While
	// the bounded window is open this is the documented behavior, and the source
	// must NOT be terminal yet.
	for label, entry := range map[string]*sessionEntry{"source": sourceEntry, "target": targetEntry} {
		installed, txEpoch, rxEpoch := rekeyProtectorEpochs(entry)
		if installed != 2 || txEpoch != 2 || rxEpoch != 2 {
			t.Fatalf("%s third install was not deferred: installed=%d tx=%d rx=%d", label, installed, txEpoch, rxEpoch)
		}
	}
	if sourceEntry.isTerminated() {
		t.Fatal("source Session was failed while the frozen deferral window was still open")
	}

	// (d) Baseline of the staged ciphertext ledger with nothing staged yet.
	baseline := snapshotStagingLedger(source.streams.budgets)

	// The target's bounded window elapses on its own clock. Its grace started on
	// the source's epoch-2 data, so it retires and installs epoch 3.
	targetClock.Advance(session.DefaultEpochGrace + time.Second)
	target.streams.pollSessionRekeys()
	rekeyWaitInstalledEpoch(t, 3, 10*time.Second, targetEntry)

	// The peer now seals epoch 3 while the source is still deferred; the source
	// stages that ciphertext opaquely and must release it, never retain it.
	probe := rekeyPattern(128, 53)
	if _, err := targetSide.Write(probe); err != nil {
		t.Fatalf("target write on its committed epoch 3 failed: %v", err)
	}
	rekeyWaitStaged(t, sourceEntry, 10*time.Second)
	staged := snapshotStagingLedger(source.streams.budgets)
	if staged.dataBytes <= baseline.dataBytes || staged.leases <= baseline.leases {
		t.Fatalf("peer epoch-3 ciphertext was never staged: staged=%+v baseline=%+v", staged, baseline)
	}

	// The source's own bounded window elapses. Its install is still refused (its
	// grace clock never started), so the production retry path must abandon the
	// deferral scoped instead of retrying forever.
	sourceClock.Advance(session.DefaultEpochGrace + time.Second)
	source.streams.pollSessionRekeys()

	// (a) An active Session must not remain committed ahead of its protectors.
	rootEpoch, have := sourceEntry.sess.RootEpoch()
	installed, txEpoch, rxEpoch := rekeyProtectorEpochs(sourceEntry)
	if !sourceEntry.isTerminated() {
		t.Fatalf("source Session stayed active after the bounded window: committed=%d/%v installed=%d tx=%d rx=%d",
			rootEpoch.Epoch, have, installed, txEpoch, rxEpoch)
	}

	// (b) The affected Circuit is terminal with ErrSessionLost, not a hang.
	if err := stream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := stream.Read(make([]byte, 16)); !errors.Is(err, ErrSessionLost) {
		t.Fatalf("source Circuit after the bounded failure = %v; want ErrSessionLost", err)
	}

	// (b) + (d) The staged peer ciphertext and every lease it owned are released.
	rekeyWaitStagingReleased(t, sourceEntry, 10*time.Second)
	after := snapshotStagingLedger(source.streams.budgets)
	if after.dataBytes != baseline.dataBytes || after.dataFrames != baseline.dataFrames ||
		after.stateBytes != baseline.stateBytes || after.leases != baseline.leases {
		t.Fatalf("staged ciphertext ledger leaked after the bounded failure: after=%+v baseline=%+v", after, baseline)
	}

	// The physical Link is not collateral damage.
	if got := countReadyLinks(source); got != readyLinksBefore {
		t.Fatalf("scoped failure changed the ready Link count: %d -> %d", readyLinksBefore, got)
	}

	// (c) A fresh Session established through the real SDK path over the same
	// physical Link keeps transferring.
	fresh := relayDialUntil(t, source, targetIP+":19062", 5*time.Second, 30*time.Second)
	defer fresh.Close()
	rekeyWriteRead(t, fresh, rekeyPattern(512, 61), 64)
	freshEntry, freshLinks := rekeyReadyPair(t, source, topology.NodeID(targetIdentity.NodeID), session.SessionClassStream)
	if freshEntry.id == failedSessionID {
		t.Fatal("the fresh dial reused the failed SessionID instead of establishing a second Session")
	}
	if freshEntry.isTerminated() {
		t.Fatal("the second Session on the same Link is terminal")
	}
	if len(freshLinks) != len(linksBefore) {
		t.Fatalf("second Session pinned %d Links; want the same %d as the failed one", len(freshLinks), len(linksBefore))
	}
	for i := range linksBefore {
		if freshLinks[i] != linksBefore[i] {
			t.Fatalf("second Session is not on the same physical Link at hop %d: %+v vs %+v", i, freshLinks[i], linksBefore[i])
		}
	}

	close(serverRelease)
	<-serverDone
}

// rekeyWaitStaged waits until the entry holds at least one staged inbound frame.
func rekeyWaitStaged(t *testing.T, entry *sessionEntry, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entry.pendMu.Lock()
		staged := len(entry.pending)
		entry.pendMu.Unlock()
		if staged > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("peer epoch ciphertext was never staged")
}

// rekeyWaitStagingReleased waits until the entry's staged queue is empty and
// latched closed by its scoped terminal failure.
func rekeyWaitStagingReleased(t *testing.T, entry *sessionEntry, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entry.pendMu.Lock()
		released := len(entry.pending) == 0 && entry.stagedClosed
		entry.pendMu.Unlock()
		if released {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("staged peer ciphertext was never released")
}

// rekeyReadyPair returns the live cached ready pair entry and its pinned
// LinkRefs for one target/class after a real SDK dial.
func rekeyReadyPair(t *testing.T, n *network, node topology.NodeID, class session.SessionClass) (*sessionEntry, []topology.LinkRef) {
	t.Helper()
	n.streams.mu.Lock()
	defer n.streams.mu.Unlock()
	pair := n.streams.pairs[pairKey{node: node, class: class}]
	if pair == nil || pair.entry == nil || pair.entry.sess == nil || pair.ps == nil {
		t.Fatalf("no ready pair for node %x class %v", node[:4], class)
	}
	return pair.entry, append([]topology.LinkRef(nil), pair.ps.links...)
}
