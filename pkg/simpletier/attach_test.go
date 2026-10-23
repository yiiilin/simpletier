package simpletier

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/internal/link"
	"github.com/yiiilin/simpletier/internal/security"
)

const attachTestToken = "0123456789abcdef0123456789abcdef"

// countingConnection is a real net.Pipe end handed to the SDK as a Connection.
// It records how many times the SDK closed it, so a test can tell "ownership was
// taken and cleanup ran exactly once" apart from "the caller still owns the
// stream and it stayed open".
type countingConnection struct {
	net.Conn
	info   ConnectionInfo
	closes atomic.Int32
}

func newCountingConnection(conn net.Conn, connectionType string) *countingConnection {
	return &countingConnection{Conn: conn, info: ConnectionInfo{Type: connectionType}}
}

func (c *countingConnection) Info() ConnectionInfo { return c.info }

func (c *countingConnection) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// gatedCleanupConnection is a net.Pipe end whose SDK-visible Close blocks until
// the test releases it. It lets one test hold an Attach attempt inside its own
// cleanup, after Network.Close already cancelled it, so the test can observe
// whether Close waits for that in-flight attempt instead of releasing the
// runtime owner underneath it.
type gatedCleanupConnection struct {
	net.Conn
	info      ConnectionInfo
	closes    atomic.Int32
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
}

func newGatedCleanupConnection(conn net.Conn, connectionType string) *gatedCleanupConnection {
	return &gatedCleanupConnection{
		Conn:    conn,
		info:    ConnectionInfo{Type: connectionType},
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (c *gatedCleanupConnection) Info() ConnectionInfo { return c.info }

func (c *gatedCleanupConnection) Close() error {
	c.closes.Add(1)
	c.enterOnce.Do(func() { close(c.entered) })
	<-c.release
	return c.Conn.Close()
}

// attachTestNetwork starts one Network owner with its own identity state
// binds no carrier listener and configures no Target, so every Connection is
// handed in by the host. Both roles otherwise share the same network context.
func attachTestNetwork(t *testing.T, token string, incomingOnly bool) *network {
	t.Helper()
	cfg := validConfig()
	cfg.Upstreams = nil
	cfg.Network.Token = token
	if incomingOnly {
		cfg.Listen = nil
	} else {
		listenURL, _ := freeTCPListenAddress(t)
		cfg.Listen = []string{listenURL}
	}
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork(incomingOnly=%t) error = %v", incomingOnly, err)
	}
	t.Cleanup(func() {
		if err := handle.Close(); err != nil {
			t.Error(err)
		}
	})
	return handle.(*network)
}

func waitAttachLinks(t *testing.T, n *network, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		n.mu.Lock()
		got := len(n.activeLinks)
		n.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active Links = %d; want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertAttachedOpen(t *testing.T, attached AttachedLink) {
	t.Helper()
	select {
	case <-attached.Done():
		t.Fatal("attached Link is already closed")
	default:
	}
}

func waitAttachedClosed(t *testing.T, attached AttachedLink) {
	t.Helper()
	select {
	case <-attached.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("attached Link did not close")
	}
}

// assertStreamOpen proves the caller still owns an untouched stream by moving
// one byte across it.
func assertStreamOpen(t *testing.T, conn *countingConnection, peer net.Conn) {
	t.Helper()
	written := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte{0x5a})
		written <- err
	}()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	n, err := conn.Read(data[:])
	if err != nil || n != 1 || data[0] != 0x5a {
		t.Fatalf("stream was taken over by a rejected Attach: read %d bytes, error %v", n, err)
	}
	if err := <-written; err != nil {
		t.Fatalf("peer write after rejected Attach: %v", err)
	}
}

// attachOverPipe runs one initiator and one responder AttachConnection against
// the two ends of a real net.Pipe and returns both handles.
func attachOverPipe(t *testing.T, initiatorNetwork, responderNetwork *network) (AttachedLink, AttachedLink) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return attachOverPipeContext(t, ctx, initiatorNetwork, responderNetwork)
}

func attachOverPipeContext(t *testing.T, ctx context.Context, initiatorNetwork, responderNetwork *network) (AttachedLink, AttachedLink) {
	t.Helper()
	initiatorStream, responderStream := net.Pipe()
	type result struct {
		attached AttachedLink
		err      error
	}
	responderResult := make(chan result, 1)
	go func() {
		attached, err := responderNetwork.AttachConnection(ctx, newCountingConnection(responderStream, "host-pipe"), AttachOptions{Role: LinkRoleResponder})
		responderResult <- result{attached: attached, err: err}
	}()
	initiatorAttached, err := initiatorNetwork.AttachConnection(ctx, newCountingConnection(initiatorStream, "host-pipe"), AttachOptions{Role: LinkRoleInitiator})
	if err != nil {
		t.Fatalf("initiator AttachConnection() error = %v", err)
	}
	got := <-responderResult
	if got.err != nil {
		t.Fatalf("responder AttachConnection() error = %v", got.err)
	}
	return initiatorAttached, got.attached
}

func TestAttachConnectionAuthenticatesBothRolesOverPipe(t *testing.T) {
	initiatorNetwork := attachTestNetwork(t, attachTestToken, true)
	responderNetwork := attachTestNetwork(t, attachTestToken, false)
	initiatorAttached, responderAttached := attachOverPipe(t, initiatorNetwork, responderNetwork)

	initiatorIdentity, err := initiatorNetwork.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	responderIdentity, err := responderNetwork.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	initiatorInfo, responderInfo := initiatorAttached.Info(), responderAttached.Info()
	if initiatorInfo.Role != LinkRoleInitiator || responderInfo.Role != LinkRoleResponder {
		t.Fatalf("roles = %s/%s; want initiator/responder", initiatorInfo.Role, responderInfo.Role)
	}
	if want := NodeID(hex.EncodeToString(responderIdentity.NodeID[:])); initiatorInfo.PeerNodeID != want {
		t.Fatalf("initiator PeerNodeID = %q; want %q", initiatorInfo.PeerNodeID, want)
	}
	if want := NodeID(hex.EncodeToString(initiatorIdentity.NodeID[:])); responderInfo.PeerNodeID != want {
		t.Fatalf("responder PeerNodeID = %q; want %q", responderInfo.PeerNodeID, want)
	}
	if initiatorInfo.LinkID == 0 || initiatorInfo.LinkID != responderInfo.LinkID {
		t.Fatalf("LinkID = %d/%d; want one shared nonzero identity", initiatorInfo.LinkID, responderInfo.LinkID)
	}
	if initiatorInfo.LinkEpoch == 0 || initiatorInfo.LinkEpoch != responderInfo.LinkEpoch {
		t.Fatalf("LinkEpoch = %d/%d; want one shared nonzero epoch", initiatorInfo.LinkEpoch, responderInfo.LinkEpoch)
	}
	if initiatorInfo.Generation == 0 || initiatorInfo.Generation != responderInfo.Generation {
		t.Fatalf("Generation = %d/%d; want one shared nonzero generation", initiatorInfo.Generation, responderInfo.Generation)
	}
	if initiatorInfo.Lane != laneControl || responderInfo.Lane != laneControl {
		t.Fatalf("Lanes = %d/%d; want CONTROL on both ends", initiatorInfo.Lane, responderInfo.Lane)
	}
	if initiatorInfo.ConnectionType != "host-pipe" || responderInfo.ConnectionType != "host-pipe" {
		t.Fatalf("ConnectionType = %q/%q; want host-pipe", initiatorInfo.ConnectionType, responderInfo.ConnectionType)
	}
	if initiatorAttached.Info() != initiatorInfo {
		t.Fatal("Info() is not a stable snapshot")
	}
	waitAttachLinks(t, initiatorNetwork, 1)
	waitAttachLinks(t, responderNetwork, 1)
	assertAttachedOpen(t, initiatorAttached)
	assertAttachedOpen(t, responderAttached)
	// An authenticated CONTROL Link is still not a mesh route.
	if _, err := initiatorNetwork.DialContext(context.Background(), "tcp", "10.20.0.8:8080"); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("attached CONTROL Link installed a route: %v", err)
	}

	// Closing one end is observed as a real peer failure on the other.
	if err := responderAttached.Close(); err != nil {
		t.Fatal(err)
	}
	waitAttachedClosed(t, initiatorAttached)
	waitAttachLinks(t, initiatorNetwork, 0)
	waitAttachLinks(t, responderNetwork, 0)
}

func TestAttachedLinkInfoCarriesOnlyNonSecretMetadata(t *testing.T) {
	want := []string{"PeerNodeID", "LinkID", "LinkEpoch", "Generation", "Lane", "Role", "ConnectionType"}
	typ := reflect.TypeOf(AttachedLinkInfo{})
	got := make([]string, 0, typ.NumField())
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.PkgPath != "" {
			t.Fatalf("AttachedLinkInfo.%s is unexported; metadata must be a public snapshot", field.Name)
		}
		got = append(got, field.Name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("AttachedLinkInfo fields = %v; want %v", got, want)
	}
}

func TestAttachConnectionRejectsWrongNetworkToken(t *testing.T) {
	initiatorNetwork := attachTestNetwork(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", true)
	responderNetwork := attachTestNetwork(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false)

	initiatorStream, responderStream := net.Pipe()
	initiatorConn := newCountingConnection(initiatorStream, "host-pipe")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	responderResult := make(chan error, 1)
	go func() {
		attached, err := responderNetwork.AttachConnection(ctx, newCountingConnection(responderStream, "host-pipe"), AttachOptions{Role: LinkRoleResponder})
		if attached != nil {
			_ = attached.Close()
		}
		responderResult <- err
	}()
	attached, err := initiatorNetwork.AttachConnection(ctx, initiatorConn, AttachOptions{Role: LinkRoleInitiator})
	if err == nil || attached != nil {
		t.Fatalf("AttachConnection() with mismatched tokens = (%v, %v); want an authentication failure", attached, err)
	}
	if responderErr := <-responderResult; responderErr == nil {
		t.Fatal("responder admitted a peer with a mismatched token")
	}
	// The request was legal, so the Network owned the stream and closed it
	// exactly once on the failure path.
	if got := initiatorConn.closes.Load(); got != 1 {
		t.Fatalf("Connection Close calls after failed authentication = %d; want exactly 1", got)
	}
	waitAttachLinks(t, initiatorNetwork, 0)
	waitAttachLinks(t, responderNetwork, 0)
}

func TestAttachConnectionCallerCancelAbortsHandshakeAndClosesOnce(t *testing.T) {
	n := attachTestNetwork(t, attachTestToken, true)
	stream, peer := net.Pipe()
	defer peer.Close()
	conn := newCountingConnection(stream, "host-pipe")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, 1)
	go func() {
		_, err := n.AttachConnection(ctx, conn, AttachOptions{Role: LinkRoleInitiator})
		results <- err
	}()

	// Wait until the attempt is really in flight: the initiator has written the
	// first handshake bytes into a pipe whose peer never answers.
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	if _, err := io.ReadFull(peer, prefix[:]); err != nil {
		t.Fatalf("initiator did not start the handshake: %v", err)
	}
	cancel()

	select {
	case err := <-results:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled AttachConnection() error = %v; want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled AttachConnection() did not return")
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("Connection Close calls after canceled attempt = %d; want exactly 1", got)
	}
	waitAttachLinks(t, n, 0)
}

func TestAttachConnectionSuccessOutlivesCallerCancel(t *testing.T) {
	initiatorNetwork := attachTestNetwork(t, attachTestToken, true)
	responderNetwork := attachTestNetwork(t, attachTestToken, false)
	ctx, cancel := context.WithCancel(context.Background())
	initiatorAttached, responderAttached := attachOverPipeContext(t, ctx, initiatorNetwork, responderNetwork)

	cancel()
	time.Sleep(50 * time.Millisecond)
	assertAttachedOpen(t, initiatorAttached)
	assertAttachedOpen(t, responderAttached)
	waitAttachLinks(t, initiatorNetwork, 1)
	waitAttachLinks(t, responderNetwork, 1)

	// The detached Link still tears down on its own Close and on peer failure.
	if err := initiatorAttached.Close(); err != nil {
		t.Fatal(err)
	}
	waitAttachedClosed(t, responderAttached)
	waitAttachLinks(t, initiatorNetwork, 0)
	waitAttachLinks(t, responderNetwork, 0)
}

func TestAttachConnectionCloseWithdrawsLinkOnce(t *testing.T) {
	initiatorNetwork := attachTestNetwork(t, attachTestToken, true)
	responderNetwork := attachTestNetwork(t, attachTestToken, false)
	initiatorAttached, responderAttached := attachOverPipe(t, initiatorNetwork, responderNetwork)

	if err := initiatorAttached.Close(); err != nil {
		t.Fatal(err)
	}
	if err := initiatorAttached.Close(); err != nil {
		t.Fatalf("second Close() error = %v; want nil", err)
	}
	waitAttachedClosed(t, initiatorAttached)
	waitAttachLinks(t, initiatorNetwork, 0)
	// The peer observes the real stream failure and withdraws its own Link.
	waitAttachedClosed(t, responderAttached)
	waitAttachLinks(t, responderNetwork, 0)

	if err := initiatorNetwork.Close(); err != nil {
		t.Fatalf("Network.Close() after closing the attachment: %v", err)
	}
	if err := responderNetwork.Close(); err != nil {
		t.Fatalf("peer Network.Close(): %v", err)
	}
}

func TestAttachConnectionIllegalParametersKeepCallerOwnership(t *testing.T) {
	n := attachTestNetwork(t, attachTestToken, true)
	canceledCtx, cancelCanceled := context.WithCancel(context.Background())
	cancelCanceled()
	for _, tt := range []struct {
		name    string
		ctx     context.Context
		options AttachOptions
	}{
		{name: "nil-context", options: AttachOptions{Role: LinkRoleInitiator}},
		{name: "canceled-context", ctx: canceledCtx, options: AttachOptions{Role: LinkRoleInitiator}},
		{name: "missing-role", ctx: context.Background()},
		{name: "unknown-role", ctx: context.Background(), options: AttachOptions{Role: LinkRole(9)}},
		{name: "lane-out-of-range", ctx: context.Background(), options: AttachOptions{Role: LinkRoleInitiator, Lane: 3}},
		{name: "negotiate-initiator", ctx: context.Background(), options: AttachOptions{Role: LinkRoleInitiator, Negotiate: true}},
		{name: "negotiate-non-control-lane", ctx: context.Background(), options: AttachOptions{Role: LinkRoleResponder, Negotiate: true, Lane: laneStream}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stream, peer := net.Pipe()
			defer peer.Close()
			conn := newCountingConnection(stream, "host-pipe")
			attached, err := n.AttachConnection(tt.ctx, conn, tt.options)
			if err == nil || attached != nil {
				t.Fatalf("illegal AttachConnection() = (%v, %v); want an error and no handle", attached, err)
			}
			if got := conn.closes.Load(); got != 0 {
				t.Fatalf("illegal parameters took ownership: Connection Close calls = %d", got)
			}
			assertStreamOpen(t, conn, peer)
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}

	if attached, err := n.AttachConnection(context.Background(), nil, AttachOptions{Role: LinkRoleInitiator}); !errors.Is(err, ErrInvalidConfig) || attached != nil {
		t.Fatalf("nil Connection = (%v, %v); want ErrInvalidConfig", attached, err)
	}
	var typedNil *countingConnection
	if attached, err := n.AttachConnection(context.Background(), typedNil, AttachOptions{Role: LinkRoleInitiator}); !errors.Is(err, ErrInvalidConfig) || attached != nil {
		t.Fatalf("typed nil Connection = (%v, %v); want ErrInvalidConfig", attached, err)
	}
	waitAttachLinks(t, n, 0)
}

// TestAttachConnectionInvalidConnectionTypeKeepsCallerOwnership pins the
// Connection-metadata class of illegal Attach requests: Info().Type is
// safe-to-publish transport metadata, so it must be non-empty, valid UTF-8 and
// free of NUL. Each rejected request leaves the Connection with the caller,
// untouched and open: not closed, not read, and no handshake byte written.
func TestAttachConnectionInvalidConnectionTypeKeepsCallerOwnership(t *testing.T) {
	n := attachTestNetwork(t, attachTestToken, true)
	for _, tt := range []struct {
		name string
		typ  string
	}{
		{name: "empty", typ: ""},
		{name: "nul", typ: "host\x00pipe"},
		{name: "leading-nul", typ: "\x00"},
		{name: "invalid-utf8", typ: string([]byte{0x68, 0x6f, 0x73, 0x74, 0xff, 0xfe})},
		{name: "lone-continuation", typ: "\x80host"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stream, peer := net.Pipe()
			defer peer.Close()
			conn := newCountingConnection(stream, tt.typ)

			attached, err := n.AttachConnection(context.Background(), conn, AttachOptions{Role: LinkRoleInitiator})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("AttachConnection() with ConnectionInfo.Type %q error = %v; want ErrInvalidConfig", tt.typ, err)
			}
			if attached != nil {
				t.Fatal("invalid Connection metadata returned an attached handle")
			}
			if got := conn.closes.Load(); got != 0 {
				t.Fatalf("invalid Connection metadata took ownership: Close calls = %d", got)
			}
			// No I/O: a rejected Attach must not have started a handshake, so the
			// peer sees nothing within its bounded read.
			if err := peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var data [1]byte
			if _, err := peer.Read(data[:]); err == nil {
				t.Fatal("rejected Attach wrote handshake bytes to the caller's stream")
			} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				t.Fatalf("peer read after rejected Attach = %v; want a silent deadline", err)
			}
			// The caller still owns a usable full-duplex stream.
			assertStreamOpen(t, conn, peer)
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if got := conn.closes.Load(); got != 1 {
				t.Fatalf("caller Close after rejected Attach = %d Close calls; want exactly 1", got)
			}
		})
	}
	waitAttachLinks(t, n, 0)
}

// or configures a Target, both are handed one end of the same host-established
// net.Pipe, and the pair still authenticates as exactly one CONTROL Link per
// side that tears down when either end goes away.
func TestAttachConnectionBetweenTwoCarrierlessNetworks(t *testing.T) {
	initiatorNetwork := attachTestNetwork(t, attachTestToken, true)
	responderNetwork := attachTestNetwork(t, attachTestToken, true)
	for name, n := range map[string]*network{"initiator": initiatorNetwork, "responder": responderNetwork} {
		if len(n.carrierListeners) != 0 {
			t.Fatalf("%s IncomingOnly Network bound %d carrier listeners; want none", name, len(n.carrierListeners))
		}
	}

	initiatorAttached, responderAttached := attachOverPipe(t, initiatorNetwork, responderNetwork)
	initiatorIdentity, err := initiatorNetwork.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	responderIdentity, err := responderNetwork.identityStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	initiatorInfo, responderInfo := initiatorAttached.Info(), responderAttached.Info()
	if initiatorInfo.Role != LinkRoleInitiator || responderInfo.Role != LinkRoleResponder {
		t.Fatalf("roles = %s/%s; want initiator/responder", initiatorInfo.Role, responderInfo.Role)
	}
	if want := NodeID(hex.EncodeToString(responderIdentity.NodeID[:])); initiatorInfo.PeerNodeID != want {
		t.Fatalf("initiator PeerNodeID = %q; want %q", initiatorInfo.PeerNodeID, want)
	}
	if want := NodeID(hex.EncodeToString(initiatorIdentity.NodeID[:])); responderInfo.PeerNodeID != want {
		t.Fatalf("responder PeerNodeID = %q; want %q", responderInfo.PeerNodeID, want)
	}
	if initiatorInfo.LinkID == 0 || initiatorInfo.LinkID != responderInfo.LinkID {
		t.Fatalf("LinkID = %d/%d; want one shared nonzero identity", initiatorInfo.LinkID, responderInfo.LinkID)
	}
	if initiatorInfo.LinkEpoch == 0 || initiatorInfo.LinkEpoch != responderInfo.LinkEpoch {
		t.Fatalf("LinkEpoch = %d/%d; want one shared nonzero epoch", initiatorInfo.LinkEpoch, responderInfo.LinkEpoch)
	}
	if initiatorInfo.Lane != laneControl || responderInfo.Lane != laneControl {
		t.Fatalf("Lanes = %d/%d; want CONTROL on both ends", initiatorInfo.Lane, responderInfo.Lane)
	}
	if initiatorInfo.ConnectionType != "host-pipe" || responderInfo.ConnectionType != "host-pipe" {
		t.Fatalf("ConnectionType = %q/%q; want host-pipe", initiatorInfo.ConnectionType, responderInfo.ConnectionType)
	}
	waitAttachLinks(t, initiatorNetwork, 1)
	waitAttachLinks(t, responderNetwork, 1)
	assertAttachedOpen(t, initiatorAttached)
	assertAttachedOpen(t, responderAttached)
	// Both Networks are incoming-only, so the authenticated CONTROL Link is
	// still the only thing they have: no carrier, no Target and no route.
	if _, err := initiatorNetwork.DialContext(context.Background(), "tcp", "10.20.0.8:8080"); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("incoming-only attach installed a route: %v", err)
	}

	if err := initiatorAttached.Close(); err != nil {
		t.Fatal(err)
	}
	waitAttachedClosed(t, initiatorAttached)
	waitAttachedClosed(t, responderAttached)
	waitAttachLinks(t, initiatorNetwork, 0)
	waitAttachLinks(t, responderNetwork, 0)
}

// TestAttachConnectionHandshakeAbortClosesStreamOnce pins the ownership
// contract of an in-flight handshake: once the request is legal the Network owns
// the Connection, so both abort paths - the caller cancelling its context and
// Network.Close - must end the attempt and close that exact stream exactly once,
// never leaving it open and never double-closing it.
func TestAttachConnectionHandshakeAbortClosesStreamOnce(t *testing.T) {
	for _, tt := range []struct {
		name          string
		abort         func(t *testing.T, n *network, cancel context.CancelFunc)
		wantErr       func(error) bool
		networkClosed bool
	}{
		{
			name:  "caller-cancel",
			abort: func(_ *testing.T, _ *network, cancel context.CancelFunc) { cancel() },
			wantErr: func(err error) bool {
				return errors.Is(err, context.Canceled)
			},
		},
		{
			name: "network-close",
			abort: func(t *testing.T, n *network, _ context.CancelFunc) {
				// Close may either wait for the aborted attempt or report the
				// bounded ErrCloseTimeout; both are allowed here, and the
				// lifetime guarantee is asserted through Done below.
				if err := n.Close(); err != nil && !errors.Is(err, ErrCloseTimeout) {
					t.Fatalf("Network.Close() error = %v", err)
				}
			},
			wantErr: func(err error) bool {
				return errors.Is(err, context.Canceled) || errors.Is(err, ErrClosed)
			},
			networkClosed: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n := attachTestNetwork(t, attachTestToken, true)
			stream, peer := net.Pipe()
			defer peer.Close()
			conn := newCountingConnection(stream, "host-pipe")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			results := make(chan error, 1)
			go func() {
				_, err := n.AttachConnection(ctx, conn, AttachOptions{Role: LinkRoleInitiator})
				results <- err
			}()

			// The attempt is really in flight: the initiator wrote its first Noise
			// message into a pipe whose peer never answers.
			if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var prefix [4]byte
			if _, err := io.ReadFull(peer, prefix[:]); err != nil {
				t.Fatalf("initiator did not start the handshake: %v", err)
			}

			tt.abort(t, n, cancel)

			select {
			case err := <-results:
				if !tt.wantErr(err) {
					t.Fatalf("aborted AttachConnection() error = %v; want a context/lifetime abort error", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("aborted AttachConnection() did not return")
			}
			if got := conn.closes.Load(); got != 1 {
				t.Fatalf("Connection Close calls after aborted handshake = %d; want exactly 1", got)
			}
			waitAttachLinks(t, n, 0)
			if tt.networkClosed {
				select {
				case <-n.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("Done() did not close after the aborted attempt ended")
				}
				return
			}
			// A caller-side abort retires only that attempt: the Network keeps
			// running and stays available for a fresh admission.
			select {
			case <-n.Done():
				t.Fatal("caller cancel closed the whole Network")
			default:
			}
			retryStream, retryPeer := net.Pipe()
			defer retryPeer.Close()
			retryConn := newCountingConnection(retryStream, "host-pipe")
			retryCtx, retryCancel := context.WithCancel(context.Background())
			defer retryCancel()
			retried := make(chan error, 1)
			go func() {
				_, err := n.AttachConnection(retryCtx, retryConn, AttachOptions{Role: LinkRoleInitiator})
				retried <- err
			}()
			if err := retryPeer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(retryPeer, prefix[:]); err != nil {
				t.Fatalf("Network did not accept a new attempt after the aborted one: %v", err)
			}
			retryCancel()
			select {
			case err := <-retried:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("second aborted AttachConnection() error = %v; want context.Canceled", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("second aborted AttachConnection() did not return")
			}
			if got := retryConn.closes.Load(); got != 1 {
				t.Fatalf("second aborted attempt closed its stream %d times; want exactly 1", got)
			}
			waitAttachLinks(t, n, 0)
		})
	}
}

// TestAttachConnectionDataLaneRequiresControlWithoutIO pins the data-lane
// ordering contract: a manually attached PACKET or STREAM lane without an active
// same-peer CONTROL dependency is a typed ordering failure, not a permanent
// unsupported capability. The attempt is legal, so it owns and closes the
// Connection exactly once and never registers a Link.
func TestAttachConnectionDataLaneRequiresControlWithoutIO(t *testing.T) {
	n := attachTestNetwork(t, attachTestToken, true)
	for _, lane := range []uint8{lanePacket, laneStream} {
		t.Run(laneName(lane), func(t *testing.T) {
			stream, peer := net.Pipe()
			defer peer.Close()
			conn := newCountingConnection(stream, "host-pipe")
			attached, err := n.AttachConnection(context.Background(), conn, AttachOptions{Role: LinkRoleInitiator, Lane: lane})
			if !errors.Is(err, ErrMissingControlDependency) {
				t.Fatalf("lane %s error = %v; want ErrMissingControlDependency", laneName(lane), err)
			}
			if errors.Is(err, ErrUnsupported) {
				t.Fatalf("lane %s was reported as a permanent unsupported capability: %v", laneName(lane), err)
			}
			if attached != nil {
				t.Fatal("data lane returned a successful handle")
			}
			if got := conn.closes.Load(); got != 1 {
				t.Fatalf("lane %s ownership: Connection Close calls = %d; want exactly 1", laneName(lane), got)
			}
		})
	}
	waitAttachLinks(t, n, 0)
}

func TestAttachConnectionRejectsPeerDeclaredDataLane(t *testing.T) {
	responderNetwork := attachTestNetwork(t, attachTestToken, true)
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	stream, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peerHandshake := make(chan error, 1)
	go func() {
		_, err := link.Handshake(ctx, peer, link.LinkConfig{
			Descriptor: responderNetwork.networkContext.Descriptor(), NetworkID: responderNetwork.networkContext.WireID(),
			PSK: responderNetwork.networkPSK, Identity: identity, Initiator: true,
			LinkID: 900, LinkEpoch: 1, Generation: 3, LaneID: laneStream,
			CapabilityVersion: uint16(link.CapabilityVersion), CapabilityMask: link.RequiredCapabilityMask,
			RequiredCapabilityMask: link.RequiredCapabilityMask,
		})
		peerHandshake <- err
	}()

	attached, err := responderNetwork.AttachConnection(ctx, newCountingConnection(stream, "host-pipe"), AttachOptions{Role: LinkRoleResponder})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("peer-declared STREAM lane error = %v; want ErrUnsupported", err)
	}
	if attached != nil {
		t.Fatal("peer-declared STREAM lane was admitted as a CONTROL Link")
	}
	if err := <-peerHandshake; err != nil {
		t.Fatalf("peer handshake failed before the lane decision: %v", err)
	}
	waitAttachLinks(t, responderNetwork, 0)
}

// TestAttachConnectionNegotiatedDataLaneWithoutControlFails proves a responder
// that negotiates the peer LaneID never guesses: a peer-declared STREAM lane with
// no active same-peer CONTROL dependency is refused as a typed ordering failure
// (ErrMissingControlDependency), never silently admitted as CONTROL and never
// reported as a permanent unsupported capability.
func TestAttachConnectionNegotiatedDataLaneWithoutControlFails(t *testing.T) {
	responderNetwork := attachTestNetwork(t, attachTestToken, true)
	identity, err := security.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	stream, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peerHandshake := make(chan error, 1)
	go func() {
		_, err := link.Handshake(ctx, peer, link.LinkConfig{
			Descriptor: responderNetwork.networkContext.Descriptor(), NetworkID: responderNetwork.networkContext.WireID(),
			PSK: responderNetwork.networkPSK, Identity: identity, Initiator: true,
			LinkID: 901, LinkEpoch: 1, Generation: 4, LaneID: laneStream,
			CapabilityVersion: uint16(link.CapabilityVersion), CapabilityMask: link.RequiredCapabilityMask,
			RequiredCapabilityMask: link.RequiredCapabilityMask,
		})
		peerHandshake <- err
	}()

	conn := newCountingConnection(stream, "host-pipe")
	attached, err := responderNetwork.AttachConnection(ctx, conn, AttachOptions{Role: LinkRoleResponder, Negotiate: true})
	if !errors.Is(err, ErrMissingControlDependency) {
		t.Fatalf("negotiated STREAM lane without CONTROL error = %v; want ErrMissingControlDependency", err)
	}
	if errors.Is(err, ErrUnsupported) {
		t.Fatalf("negotiated STREAM lane without CONTROL was reported unsupported: %v", err)
	}
	if attached != nil {
		t.Fatal("negotiated STREAM lane without CONTROL returned a handle")
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("negotiated STREAM lane ownership: Connection Close calls = %d; want exactly 1", got)
	}
	if err := <-peerHandshake; err != nil {
		t.Fatalf("peer handshake failed before the lane decision: %v", err)
	}
	waitAttachLinks(t, responderNetwork, 0)
}

// foreignAttachedLink is a caller implementation of the public AttachedLink
// interface. It has no authenticated CONTROL Link behind it, so a data-lane
// Attach must reject it as a dependency instead of trusting it.
type foreignAttachedLink struct{}

func (foreignAttachedLink) Info() AttachedLinkInfo { return AttachedLinkInfo{} }
func (foreignAttachedLink) Done() <-chan struct{}  { return make(chan struct{}) }
func (foreignAttachedLink) Close() error           { return nil }

// openAttachedControl returns a live CONTROL handle admitted by a real Network,
// with its responder peer still open, so it stays usable as a data-lane
// dependency for the lifetime of the test.
func openAttachedControl(t *testing.T) AttachedLink {
	t.Helper()
	initiatorNetwork := attachTestNetwork(t, attachTestToken, true)
	responderNetwork := attachTestNetwork(t, attachTestToken, true)
	control, _ := attachOverPipe(t, initiatorNetwork, responderNetwork)
	assertAttachedOpen(t, control)
	return control
}

// attachDataLane is one CONTROL pair plus the dedicated data-lane pair admitted
// on top of it.
type attachDataLane struct {
	control     AttachedLink
	peerControl AttachedLink
	initiator   AttachedLink
	responder   AttachedLink
}

// attachDataLaneOverPipe first establishes a CONTROL pair over a real net.Pipe
// through the public API, then admits one dedicated data Lane pinned to that
// exact CONTROL handle: the initiator requests an explicit Lane and hands over
// the CONTROL handle, while the responder negotiates the peer-declared LaneID
// exactly like the built-in accepted carrier.
func attachDataLaneOverPipe(t *testing.T, initiatorNetwork, responderNetwork *network, lane uint8) attachDataLane {
	t.Helper()
	control, peerControl := attachOverPipe(t, initiatorNetwork, responderNetwork)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	initiatorStream, responderStream := net.Pipe()
	type result struct {
		attached AttachedLink
		err      error
	}
	responderResult := make(chan result, 1)
	go func() {
		attached, err := responderNetwork.AttachConnection(ctx, newCountingConnection(responderStream, "host-pipe"), AttachOptions{Role: LinkRoleResponder, Negotiate: true})
		responderResult <- result{attached: attached, err: err}
	}()
	initiatorAttached, err := initiatorNetwork.AttachConnection(ctx, newCountingConnection(initiatorStream, "host-pipe"), AttachOptions{
		Role:    LinkRoleInitiator,
		Lane:    lane,
		Control: control,
	})
	if err != nil {
		t.Fatalf("initiator %s AttachConnection() error = %v", laneName(lane), err)
	}
	got := <-responderResult
	if got.err != nil {
		t.Fatalf("responder %s AttachConnection() error = %v", laneName(lane), got.err)
	}
	return attachDataLane{control: control, peerControl: peerControl, initiator: initiatorAttached, responder: got.attached}
}

// TestAttachConnectionDataLanePinnedToControlOverPipe is the end-to-end
// regression for the public DATA-lane Attach surface. A CONTROL pair is
// established over a real net.Pipe through AttachConnection, and a second,
// dedicated data-lane pair is then admitted by an initiator that pins that exact
// CONTROL handle while the responder negotiates the peer-declared LaneID. Both
// ends must land on the same data Lane with one shared Link identity, the data
// Link must be a distinct instance from the CONTROL dependency, and closing the
// data Link must withdraw only it and leave the CONTROL adjacency healthy.
func TestAttachConnectionDataLanePinnedToControlOverPipe(t *testing.T) {
	for _, lane := range []uint8{laneStream, lanePacket} {
		t.Run(laneName(lane), func(t *testing.T) {
			initiatorNetwork := attachTestNetwork(t, attachTestToken, true)
			responderNetwork := attachTestNetwork(t, attachTestToken, true)
			pair := attachDataLaneOverPipe(t, initiatorNetwork, responderNetwork, lane)

			initiatorInfo, responderInfo := pair.initiator.Info(), pair.responder.Info()
			if initiatorInfo.Lane != lane || responderInfo.Lane != lane {
				t.Fatalf("data Lane = %d/%d; want %d (%s)", initiatorInfo.Lane, responderInfo.Lane, lane, laneName(lane))
			}
			if initiatorInfo.Role != LinkRoleInitiator || responderInfo.Role != LinkRoleResponder {
				t.Fatalf("data roles = %s/%s; want initiator/responder", initiatorInfo.Role, responderInfo.Role)
			}
			if initiatorInfo.LinkID == 0 || initiatorInfo.LinkID != responderInfo.LinkID {
				t.Fatalf("data LinkID = %d/%d; want one shared nonzero identity", initiatorInfo.LinkID, responderInfo.LinkID)
			}
			if initiatorInfo.LinkEpoch == 0 || initiatorInfo.LinkEpoch != responderInfo.LinkEpoch {
				t.Fatalf("data LinkEpoch = %d/%d; want one shared nonzero epoch", initiatorInfo.LinkEpoch, responderInfo.LinkEpoch)
			}
			if initiatorInfo.LinkID == pair.control.Info().LinkID {
				t.Fatal("data Lane reused the CONTROL Link instance")
			}
			initiatorIdentity, err := initiatorNetwork.identityStore.Identity()
			if err != nil {
				t.Fatal(err)
			}
			responderIdentity, err := responderNetwork.identityStore.Identity()
			if err != nil {
				t.Fatal(err)
			}
			if want := NodeID(hex.EncodeToString(responderIdentity.NodeID[:])); initiatorInfo.PeerNodeID != want {
				t.Fatalf("initiator data PeerNodeID = %q; want %q", initiatorInfo.PeerNodeID, want)
			}
			if want := NodeID(hex.EncodeToString(initiatorIdentity.NodeID[:])); responderInfo.PeerNodeID != want {
				t.Fatalf("responder data PeerNodeID = %q; want %q", responderInfo.PeerNodeID, want)
			}
			if initiatorInfo.ConnectionType != "host-pipe" || responderInfo.ConnectionType != "host-pipe" {
				t.Fatalf("data ConnectionType = %q/%q; want host-pipe", initiatorInfo.ConnectionType, responderInfo.ConnectionType)
			}
			// The CONTROL dependency both data ends were pinned to is unchanged.
			if pair.control.Info().Lane != laneControl || pair.peerControl.Info().Lane != laneControl {
				t.Fatalf("control Lanes = %d/%d; want CONTROL", pair.control.Info().Lane, pair.peerControl.Info().Lane)
			}
			waitAttachLinks(t, initiatorNetwork, 2)
			waitAttachLinks(t, responderNetwork, 2)
			assertAttachedOpen(t, pair.control)
			assertAttachedOpen(t, pair.peerControl)
			assertAttachedOpen(t, pair.initiator)
			assertAttachedOpen(t, pair.responder)

			// Closing the data Link withdraws exactly that instance; the CONTROL
			// adjacency stays up on both ends.
			if err := pair.initiator.Close(); err != nil {
				t.Fatal(err)
			}
			waitAttachedClosed(t, pair.initiator)
			waitAttachedClosed(t, pair.responder)
			waitAttachLinks(t, initiatorNetwork, 1)
			waitAttachLinks(t, responderNetwork, 1)
			assertAttachedOpen(t, pair.control)
			assertAttachedOpen(t, pair.peerControl)

			if err := pair.control.Close(); err != nil {
				t.Fatal(err)
			}
			waitAttachedClosed(t, pair.control)
			waitAttachedClosed(t, pair.peerControl)
			waitAttachLinks(t, initiatorNetwork, 0)
			waitAttachLinks(t, responderNetwork, 0)
		})
	}
}

// TestAttachConnectionRejectsInvalidControlHandle pins the pre-ownership
// validation of AttachOptions.Control: a typed nil, a never-established handle,
// a foreign AttachedLink implementation and a closed handle are all illegal
// requests. Each is rejected with ErrInvalidConfig before the Connection is
// taken over, so the caller keeps an open, unused stream.
func TestAttachConnectionRejectsInvalidControlHandle(t *testing.T) {
	typedNil := (*attachedLink)(nil)
	broken := &attachedLink{}
	closed := openAttachedControl(t)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	waitAttachedClosed(t, closed)

	for _, tt := range []struct {
		name    string
		control AttachedLink
	}{
		{name: "typed-nil", control: typedNil},
		{name: "never-established", control: broken},
		{name: "foreign", control: foreignAttachedLink{}},
		{name: "closed", control: closed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n := attachTestNetwork(t, attachTestToken, true)
			stream, peer := net.Pipe()
			defer peer.Close()
			conn := newCountingConnection(stream, "host-pipe")
			attached, err := n.AttachConnection(context.Background(), conn, AttachOptions{Role: LinkRoleInitiator, Lane: laneStream, Control: tt.control})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("invalid Control error = %v; want ErrInvalidConfig", err)
			}
			if attached != nil {
				t.Fatal("invalid Control returned a handle")
			}
			if got := conn.closes.Load(); got != 0 {
				t.Fatalf("invalid Control took ownership: Connection Close calls = %d", got)
			}
			assertStreamOpen(t, conn, peer)
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			waitAttachLinks(t, n, 0)
		})
	}
}

// TestAttachConnectionRejectsControlOutsideInitiatorDataLane pins where
// AttachOptions.Control is meaningful: only an initiator PACKET/STREAM request
// may pin a CONTROL peer. A CONTROL Lane, a responder request and a negotiating
// responder are unchanged (nil Control behaves exactly as before) and a non-nil
// Control there is an illegal request rejected before the Connection is taken
// over.
func TestAttachConnectionRejectsControlOutsideInitiatorDataLane(t *testing.T) {
	control := openAttachedControl(t)
	for _, tt := range []struct {
		name    string
		options AttachOptions
	}{
		{name: "control-lane-initiator", options: AttachOptions{Role: LinkRoleInitiator, Lane: laneControl, Control: control}},
		{name: "control-lane-responder", options: AttachOptions{Role: LinkRoleResponder, Lane: laneControl, Control: control}},
		{name: "negotiating-responder", options: AttachOptions{Role: LinkRoleResponder, Negotiate: true, Control: control}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n := attachTestNetwork(t, attachTestToken, true)
			stream, peer := net.Pipe()
			defer peer.Close()
			conn := newCountingConnection(stream, "host-pipe")
			attached, err := n.AttachConnection(context.Background(), conn, tt.options)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Control on %s error = %v; want ErrInvalidConfig", tt.name, err)
			}
			if attached != nil {
				t.Fatal("Control outside an initiator data Lane returned a handle")
			}
			if got := conn.closes.Load(); got != 0 {
				t.Fatalf("Control outside an initiator data Lane took ownership: Close calls = %d", got)
			}
			assertStreamOpen(t, conn, peer)
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			waitAttachLinks(t, n, 0)
		})
	}
}

// TestAttachConnectionDataLanePinsControlPeer proves the peer named by the
// Control handle is really enforced, not merely recorded.
//
// A valid CONTROL handle used on a Network that has no CONTROL adjacency to that
// peer is refused with the existing typed ordering failure under the normal
// ownership contract, and a Network with a live CONTROL adjacency to peer A,
// asked for a data Lane against peer B while pinned to A, fails its
// authenticated handshake instead of reaching B and registers no data Link.
func TestAttachConnectionDataLanePinsControlPeer(t *testing.T) {
	t.Run("peer-not-adjacent", func(t *testing.T) {
		initiatorNetwork := attachTestNetwork(t, attachTestToken, true)
		responderNetwork := attachTestNetwork(t, attachTestToken, true)
		control, _ := attachOverPipe(t, initiatorNetwork, responderNetwork)

		other := attachTestNetwork(t, attachTestToken, true)
		stream, peer := net.Pipe()
		defer peer.Close()
		conn := newCountingConnection(stream, "host-pipe")
		attached, err := other.AttachConnection(context.Background(), conn, AttachOptions{Role: LinkRoleInitiator, Lane: laneStream, Control: control})
		if !errors.Is(err, ErrMissingControlDependency) {
			t.Fatalf("STREAM pinned to a non-adjacent CONTROL peer error = %v; want ErrMissingControlDependency", err)
		}
		if errors.Is(err, ErrUnsupported) {
			t.Fatalf("pinned data Lane was reported as a permanent unsupported capability: %v", err)
		}
		if attached != nil {
			t.Fatal("STREAM pinned to a non-adjacent CONTROL peer returned a handle")
		}
		if got := conn.closes.Load(); got != 1 {
			t.Fatalf("pinned data Lane ownership: Connection Close calls = %d; want exactly 1", got)
		}
		waitAttachLinks(t, other, 0)
	})

	t.Run("wrong-responder", func(t *testing.T) {
		initiatorNetwork := attachTestNetwork(t, attachTestToken, true)
		trustedResponder := attachTestNetwork(t, attachTestToken, true)
		control, _ := attachOverPipe(t, initiatorNetwork, trustedResponder)

		// A different peer with a different static key than the pinned CONTROL
		// dependency: the initiator must fail authentication instead of reaching
		// it, and the responder must register no Link.
		otherResponder := attachTestNetwork(t, attachTestToken, true)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		initiatorStream, responderStream := net.Pipe()
		type result struct {
			attached AttachedLink
			err      error
		}
		responderResult := make(chan result, 1)
		go func() {
			attached, err := otherResponder.AttachConnection(ctx, newCountingConnection(responderStream, "host-pipe"), AttachOptions{Role: LinkRoleResponder, Negotiate: true})
			responderResult <- result{attached: attached, err: err}
		}()
		initiatorAttached, initiatorErr := initiatorNetwork.AttachConnection(ctx, newCountingConnection(initiatorStream, "host-pipe"), AttachOptions{
			Role:    LinkRoleInitiator,
			Lane:    laneStream,
			Control: control,
		})
		got := <-responderResult

		if initiatorErr == nil || initiatorAttached != nil {
			t.Fatalf("data Lane pinned to a different responder = (%v, %v); want an authentication failure", initiatorAttached, initiatorErr)
		}
		if errors.Is(initiatorErr, ErrMissingControlDependency) {
			t.Fatalf("the pinned peer was not enforced in the handshake: %v", initiatorErr)
		}
		if got.err == nil || got.attached != nil {
			t.Fatalf("non-adjacent responder admitted a pinned STREAM peer = (%v, %v)", got.attached, got.err)
		}
		// The pinned data Lane never registered anywhere; each Network keeps only
		// its own CONTROL Link (the wrong responder keeps none).
		waitAttachLinks(t, initiatorNetwork, 1)
		waitAttachLinks(t, trustedResponder, 1)
		waitAttachLinks(t, otherResponder, 0)
	})
}

func TestCarrierlessConfigIsAccepted(t *testing.T) {
	cfg := validConfig()
	cfg.Listen = nil
	cfg.Upstreams = nil
	cfg.Targets = nil

	// A Network with no carrier of its own is legal: every Connection may enter it
	// through AttachConnection. There is no separate opt-in flag, because a config
	// that names no carrier is unambiguous on its own.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() for a carrierless config = %v; want nil", err)
	}
	handle, err := NewNetwork(cfg)
	if err != nil {
		t.Fatalf("NewNetwork for a carrierless config = %v; want nil", err)
	}
	defer func() { _ = handle.Close() }()
}

func TestAttachConnectionAfterNetworkCloseReportsClosed(t *testing.T) {
	n := attachTestNetwork(t, attachTestToken, true)
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	stream, peer := net.Pipe()
	defer peer.Close()
	conn := newCountingConnection(stream, "host-pipe")
	attached, err := n.AttachConnection(context.Background(), conn, AttachOptions{Role: LinkRoleInitiator})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("AttachConnection() after Network.Close error = %v; want ErrClosed", err)
	}
	if attached != nil {
		t.Fatal("closed Network returned an attached handle")
	}
	if got := conn.closes.Load(); got != 0 {
		t.Fatalf("closed Network took ownership: Connection Close calls = %d", got)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAttachConnectionCloseRacesNetworkClose(t *testing.T) {
	for attempt := range 3 {
		initiatorNetwork := attachTestNetwork(t, attachTestToken, true)
		responderNetwork := attachTestNetwork(t, attachTestToken, false)
		initiatorAttached, responderAttached := attachOverPipe(t, initiatorNetwork, responderNetwork)

		// Every control worker of an attached Link is reserved under the same
		// Close gate before AttachConnection returns, so closing the handle and
		// the Network together must neither deadlock nor leave Done open.
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			_ = initiatorAttached.Close()
		}()
		go func() {
			defer wait.Done()
			if err := initiatorNetwork.Close(); err != nil {
				t.Errorf("attempt %d: Network.Close() error = %v", attempt, err)
			}
		}()
		wait.Wait()
		select {
		case <-initiatorNetwork.Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("attempt %d: Done() did not close after concurrent Close", attempt)
		}
		_ = responderAttached.Close()
		if err := responderNetwork.Close(); err != nil {
			t.Fatalf("attempt %d: peer Close() error = %v", attempt, err)
		}
	}
}

// TestAttachConnectionInFlightIsWaitedForByNetworkClose pins the lifecycle gate
// of a valid, in-flight Attach: once the request is legal and the Network owns
// the Connection, the attempt is a Network worker. Close cancels it and may wait
// for it or report the bounded ErrCloseTimeout, but it must never release the
// runtime owner (Done) while that attempt is still running, and the attempt must
// end with a context error and exactly one close of the stream it owns.
func TestAttachConnectionInFlightIsWaitedForByNetworkClose(t *testing.T) {
	n := attachTestNetwork(t, attachTestToken, true)
	stream, peer := net.Pipe()
	defer peer.Close()
	conn := newGatedCleanupConnection(stream, "host-pipe")

	var releaseOnce sync.Once
	unblockCleanup := func() { releaseOnce.Do(func() { close(conn.release) }) }
	// Also runs on an early t.Fatal so the held attempt can never outlive the
	// test and block the package run.
	defer unblockCleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, 1)
	go func() {
		_, err := n.AttachConnection(ctx, conn, AttachOptions{Role: LinkRoleInitiator})
		results <- err
	}()

	// Confirm the attempt really entered the handshake: the initiator wrote its
	// first Noise message into a pipe whose peer never answers.
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	if _, err := io.ReadFull(peer, prefix[:]); err != nil {
		t.Fatalf("initiator did not start the handshake: %v", err)
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- n.Close() }()

	// Network.Close cancels the attempt; the SDK then closes the stream it owns,
	// which this test holds inside the gated Close. Until the test releases it,
	// the attempt cannot finish.
	select {
	case <-conn.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Network.Close never cancelled the in-flight handshake")
	}

	closePending := true
	select {
	case err := <-closeResult:
		closePending = false
		if !errors.Is(err, ErrCloseTimeout) {
			t.Fatalf("Network.Close() = %v while a valid Attach attempt was still in flight; want a wait or ErrCloseTimeout", err)
		}
	case <-n.Done():
		t.Fatal("Done() closed while a valid Attach attempt was still in flight")
	case <-time.After(500 * time.Millisecond):
	}
	if !closePending {
		// The bounded fallback is allowed, but it must not have released the
		// runtime owner while the attempt was still running.
		select {
		case <-n.Done():
			t.Fatal("Done() closed while a valid Attach attempt was still in flight")
		default:
		}
	}

	unblockCleanup()
	select {
	case err := <-results:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("AttachConnection() during Network.Close error = %v; want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AttachConnection() did not return after Network.Close")
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("Connection Close calls after Network.Close = %d; want exactly 1", got)
	}
	if closePending {
		select {
		case err := <-closeResult:
			if err != nil {
				t.Fatalf("Network.Close() = %v; want nil once the Attach worker ended", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Network.Close() did not return after the Attach worker ended")
		}
	} else {
		select {
		case <-n.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("Done() did not close after the Attach worker ended")
		}
	}
	waitAttachLinks(t, n, 0)
}

// TestAttachAdmissionAfterCloseWonGateClosesOwnedStreamOnce covers the branch
// AttachConnection cannot reach deterministically from outside its own entry
// point: Close already won the admission gate, so a caller that has already
// handed its stream to the Network - the only way into admitControlLink - is
// rejected with ErrClosed and the stream it now owns is closed exactly once. The
// rejection happens before the released runtime state or the closed identity
// store is touched, and it registers no Link.
func TestAttachAdmissionAfterCloseWonGateClosesOwnedStreamOnce(t *testing.T) {
	n := attachTestNetwork(t, attachTestToken, true)
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}

	stream, peer := net.Pipe()
	defer peer.Close()
	conn := newCountingConnection(stream, "host-pipe")
	attached, err := n.admitControlLink(context.Background(), conn, conn.Info(), LinkRoleInitiator, laneControl)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("admission after Network.Close error = %v; want ErrClosed", err)
	}
	if attached != nil {
		t.Fatal("admission after Network.Close returned a Link")
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("Connection Close calls after rejected admission = %d; want exactly 1", got)
	}
	waitAttachLinks(t, n, 0)
}
