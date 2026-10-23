// Command tun-chain is a test-only process helper for the three-node TUN
// relay acceptance. It is deliberately NOT a library: it exists so an
// acceptance can drive one real OS process per node, each with its own
// identity/state directory, its own fixed VirtualIP and its own real TUN
// device.
//
// Roles, and the carrier topology they expect:
//
//	source (leaf, TUN)   listen=none              upstreams=<relay carrier>
//	relay  (transit, TUN) listen=<its carrier>    upstreams=<target carrier>
//	target (leaf, TUN)    listen=<its carrier>    upstreams=none
//
// The source dials the target's VirtualIP. Each hop forwards; the relay never
// terminates the business stream. The target accepts on its VirtualIP and
// echoes every byte back unchanged.
//
// Every role prints one JSON line per observation on stdout, so the parent
// asserts on facts instead of scraping prose.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// options are the command-line flags shared by every role.
type options struct {
	role       string
	network    string
	cidr       string
	token      string
	listen     string
	upstreams  string
	fixedIP    string
	device     string
	mtu        int
	targetIP   string
	targetPort int
	bytes      int
	timeout    time.Duration
	// wsListen enables the relay's WebSocket ingress on this host:port. The
	// SDK ships an outbound WebSocket connector but no accept side, so a relay
	// that must serve a WebSocket peer hosts the upgrade itself.
	wsListen string
	wsPath   string
	// wsUpstream points this node's outbound carrier at a WebSocket endpoint
	// instead of a TCP one. The SDK's Config.Targets is the documented home for
	// a host-provided Connector, so a WebSocket leaf dials through it.
	wsUpstream string
	logLevel   string
	noTun      bool
}

// emit writes one JSON line. It is safe for concurrent use: several role
// goroutines report on the same stdout.
var emitMu sync.Mutex

func emit(event string, fields map[string]any) {
	emitMu.Lock()
	defer emitMu.Unlock()
	if fields == nil {
		fields = map[string]any{}
	}
	fields["event"] = event
	fields["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	encoded, err := json.Marshal(fields)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tun-chain: encode event %q: %v\n", event, err)
		return
	}
	fmt.Println(string(encoded))
}

// stagedError carries the stage it happened in, the offending config field and
// the SDK error class, so the parent reports the exact SDK error instead of
// hiding it behind prose.
type stagedError struct {
	Stage string
	Field string
	Class string
	Err   error
}

func (e *stagedError) Error() string { return e.Err.Error() }
func (e *stagedError) Unwrap() error { return e.Err }

// classify maps an SDK error to a stable class name the parent can assert on.
//
// It matches the exported sentinels where they exist. The device-open failures
// (no platform backend, missing driver, no privilege) keep their sentinels
// inside internal/agent, so those are recognised by their documented message
// text; the class is a diagnostic label, never an acceptance decision — the
// acceptance asserts on the concrete TUN/business result, not on this string.
func classify(err error) string {
	switch {
	case errors.Is(err, simpletier.ErrInvalidConfig):
		return "invalid_config"
	case errors.Is(err, simpletier.ErrPermissionDenied):
		return "permission_denied"
	case errors.Is(err, simpletier.ErrNoRoute):
		return "no_route"
	case errors.Is(err, simpletier.ErrAddressConflict):
		return "address_conflict"
	case errors.Is(err, simpletier.ErrClosed):
		return "closed"
	case errors.Is(err, simpletier.ErrUnsupported):
		return "unsupported"
	case errors.Is(err, simpletier.ErrLinkDown):
		return "link_down"
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "WintunOpenAdapter"), strings.Contains(message, "driver"):
		return "driver_missing_or_denied"
	case strings.Contains(message, "platform backend unavailable"):
		return "platform_unavailable"
	case strings.Contains(message, "Access is denied"), strings.Contains(message, "permission denied"):
		return "permission_denied"
	}
	return "error"
}

// fail reports one failure as a structured event and exits non-zero.
func fail(role, stage, field string, err error) {
	emit("error", map[string]any{
		"role":  role,
		"stage": stage,
		"field": field,
		"class": classify(err),
		"error": err.Error(),
	})
	os.Exit(1)
}

func main() {
	o := &options{}
	fs := flag.NewFlagSet("tun-chain", flag.ContinueOnError)
	fs.StringVar(&o.role, "role", "", "source | relay | target")
	fs.StringVar(&o.network, "network", "tun-chain", "overlay network name")
	fs.StringVar(&o.cidr, "cidr", "", "overlay CIDR")
	fs.StringVar(&o.token, "token", "", "overlay group token")
	fs.StringVar(&o.listen, "listen", "", "this node's TCP carrier listener URL; empty for the source")
	fs.StringVar(&o.upstreams, "upstreams", "", "the next hop's TCP carrier URL; empty for the target")
	fs.StringVar(&o.fixedIP, "fixed-ip", "", "this node's VirtualIP")
	fs.StringVar(&o.device, "device", "", "TUN device name; required, and the handle a crashed run leaves behind")
	fs.IntVar(&o.mtu, "mtu", 0, "requested device MTU; 0 uses the platform default")
	fs.StringVar(&o.targetIP, "target-ip", "", "the target's VirtualIP (source dials this)")
	fs.IntVar(&o.targetPort, "target-port", 19090, "the target's listening port")
	fs.IntVar(&o.bytes, "bytes", 4096, "payload size the source sends")
	fs.StringVar(&o.wsListen, "ws-listen", "", "host:port for the relay's WebSocket ingress; empty disables it")
	fs.StringVar(&o.wsPath, "ws-path", "/simpletier", "URL path the WebSocket ingress serves")
	fs.StringVar(&o.wsUpstream, "ws-upstream", "", "ws://host:port/path this node dials as its outbound carrier")
	fs.StringVar(&o.logLevel, "log-level", "", "SDK log level: debug|info|warn|error")
	fs.BoolVar(&o.noTun, "no-tun", false, "run without a host TUN device (the pure Network data plane)")
	fs.DurationVar(&o.timeout, "timeout", 120*time.Second, "bound on the whole role")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tun-chain:", err)
		os.Exit(2)
	}
	switch o.role {
	case "source", "relay", "target":
	default:
		fmt.Fprintf(os.Stderr, "tun-chain: -role must be source, relay or target; got %q\n", o.role)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	if err := run(ctx, o); err != nil {
		fail(o.role, "run", "", err)
	}
}

// run starts the Agent for this role and executes the role's behaviour.
func run(ctx context.Context, o *options) error {
	agent, err := startAgent(ctx, o)
	if err != nil {
		return err
	}
	defer func() { _ = agent.Close() }()

	switch o.role {
	case "target":
		return runTarget(ctx, agent, o)
	case "relay":
		return runRelay(ctx, agent, o)
	case "source":
		return runSource(ctx, agent, o)
	}
	return nil
}

// startAgent builds and starts the SDK Agent with a real TUN device.
func startAgent(ctx context.Context, o *options) (*simpletier.Agent, error) {
	if o.cidr == "" || o.token == "" || o.fixedIP == "" || o.device == "" {
		return nil, fmt.Errorf("-cidr, -token, -fixed-ip and -device are required")
	}
	listen := []string(nil)
	if o.listen != "" {
		listen = []string{o.listen}
	}
	upstreams := []string(nil)
	if o.upstreams != "" {
		upstreams = []string{o.upstreams}
	}
	// A WebSocket leaf reaches the relay through Config.Targets: the SDK's
	// documented place for a host-provided Connector. It is mutually exclusive
	// with a TCP upstream because a node has one outbound carrier direction.
	var targets []simpletier.ConnectionTarget
	if o.wsUpstream != "" {
		if o.upstreams != "" {
			return nil, fmt.Errorf("-ws-upstream and -upstreams are mutually exclusive")
		}
		targets = append(targets, simpletier.ConnectionTarget{
			Connector: &simpletier.WebSocketConnector{},
			Endpoint:  o.wsUpstream,
		})
	}

	tunEnabled := !o.noTun
	cfg := simpletier.AgentConfig{
		Config: simpletier.Config{
			Listen:    listen,
			Upstreams: upstreams,
			Targets:   targets,
			Network: simpletier.NetworkConfig{
				Name:  o.network,
				CIDR:  o.cidr,
				Token: o.token,
			},
			Options: simpletier.RuntimeOptions{
				FixedIP:  o.fixedIP,
				LogLevel: o.logLevel,
			},
		},
		Inbounds:   simpletier.AgentInbounds{TUN: &tunEnabled},
		DeviceName: o.device,
	}
	// A relay owns no listener of its own when it is the last hop, and the
	// legal without inventing a listener that serves no purpose.
	// exactly what makes that configuration legal: it relaxes only the
	// construction requirement (at least one listener or typed Target) and
	// leaves every explicitly configured Listen, Upstream and Target in effect.
	//
	// This matters for the hub-shaped topology: both leaves dial the hub, so a
	// Options.Relay is left unset on every role, and that is load-bearing.
	//
	// relayEnabled() reports true for a nil Relay, so an unset value makes every
	// node advertise the "relay" capability, and the route search treats a node
	// as a possible transit hop from that advertised fact. Setting Relay=false on
	// the leaves was measured to break a two-hop STREAM completely: the source's
	// own path search then returns no candidate and dial fails with
	// "no route: path: candidates for STREAM: route policy denied" (191 attempts).
	//
	// Whether a node actually carries another node's traffic is decided by the
	// route policy plus the advertised capability, not by opting out locally, so
	// leaving this unset is both sufficient and necessary.

	agent, err := simpletier.NewAgent(cfg)
	if err != nil {
		return nil, fmt.Errorf("NewAgent: %w", err)
	}
	if err := agent.Start(ctx); err != nil {
		_ = agent.Close()
		return nil, fmt.Errorf("Agent.Start: %w", err)
	}

	info := map[string]any{
		"role":      o.role,
		"fixed_ip":  o.fixedIP,
		"network":   o.network,
		"local_vip": agent.LocalVirtualIP().String(),
	}
	if device := agent.PacketDevice(); device != nil {
		info["device_mtu"] = device.MTU()
		if reporter, ok := device.(simpletier.DeviceReporter); ok {
			deviceInfo := reporter.DeviceInfo()
			info["device_name"] = deviceInfo.Name
			info["device_owned"] = deviceInfo.Owned
			info["device_ready"] = deviceInfo.Ready
			info["device_address"] = deviceInfo.Address.String()
		}
	} else if tunEnabled {
		return nil, fmt.Errorf("the Agent opened no packet device although inbounds.tun is true")
	} else {
		info["device_name"] = ""
	}
	emit("ready", info)
	return agent, nil
}

// runTarget listens on this node's VirtualIP and echoes every received byte
// unchanged until the peer half-closes.
func runTarget(ctx context.Context, agent *simpletier.Agent, o *options) error {
	network := agent.Network()
	address := netip.AddrPortFrom(netip.MustParseAddr(o.fixedIP), uint16(o.targetPort))
	listener, err := network.Listen("tcp", address.String())
	if err != nil {
		return fmt.Errorf("Listen(%s): %w", address, err)
	}
	defer listener.Close()
	emit("listening", map[string]any{"address": address.String(), "role": o.role})

	for {
		if ctx.Err() != nil {
			return nil
		}
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("Accept: %w", err)
		}
		go echoConn(conn)
	}
}

// echoConn copies everything it reads straight back, then half-closes its own
// direction so the source observes the complete echo and a clean EOF.
func echoConn(conn net.Conn) {
	defer conn.Close()
	var total int64
	buffer := make([]byte, 32<<10)
	for {
		n, readErr := conn.Read(buffer)
		if n > 0 {
			atomic.AddInt64(&total, int64(n))
			if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
				emit("echo-error", map[string]any{"error": writeErr.Error(), "echoed": atomic.LoadInt64(&total)})
				return
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) {
				emit("echo-done", map[string]any{"echoed": atomic.LoadInt64(&total), "reason": "eof"})
				return
			}
			emit("echo-done", map[string]any{"echoed": atomic.LoadInt64(&total), "reason": readErr.Error()})
			return
		}
	}
}

// runRelay holds the Network open so it keeps forwarding, and reports that it
// is alive. It never terminates the business stream.
//
// A relay that must also serve a WebSocket peer hosts that ingress itself: the
// SDK deliberately has no WebSocket accept side, so the host upgrades the
// socket and hands the result to NewWebSocketConnection + AttachConnection.
func runRelay(ctx context.Context, agent *simpletier.Agent, o *options) error {
	emit("relaying", map[string]any{"role": o.role, "note": "forwarding only; the relay owns no business endpoint"})

	ingressErr := make(chan error, 1)
	if o.wsListen != "" {
		go func() {
			ingressErr <- serveWebSocketIngress(ctx, agent.Network(), o.wsListen, o.wsPath)
		}()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-ingressErr:
		if err != nil {
			return err
		}
		return nil
	case <-agent.Done():
		return fmt.Errorf("the relay Agent stopped unexpectedly")
	}
}

// serveWebSocketIngress accepts WebSocket peer Links on the relay's own HTTP
// server and admits each one as a CONTROL Link responder.
func serveWebSocketIngress(ctx context.Context, network simpletier.Network, address, path string) error {
	upgrader := &websocket.Upgrader{
		ReadBufferSize:  32 << 10,
		WriteBufferSize: 32 << 10,
		// The peer is authenticated by the SDK's own handshake after the upgrade,
		// so the HTTP Origin check would add a second, weaker gate that no
		// SimpleTier peer populates. Authorization is the group token, not Origin.
		CheckOrigin: func(*http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			emit("ws-upgrade-error", map[string]any{"error": err.Error(), "remote": r.RemoteAddr})
			return
		}
		emit("ws-upgraded", map[string]any{"remote": r.RemoteAddr, "path": r.URL.Path})

		connection, err := simpletier.NewWebSocketConnection(conn)
		if err != nil {
			_ = conn.Close()
			emit("ws-wrap-error", map[string]any{"error": err.Error()})
			return
		}
		// The WebSocket peer dialled in and wrote the first handshake, so it is
		// the initiator. This relay answers: responder, with the LaneID taken
		// from the peer's authenticated HANDSHAKE.
		attached, err := network.AttachConnection(ctx, connection, simpletier.AttachOptions{
			Role:      simpletier.LinkRoleResponder,
			Lane:      0,
			Negotiate: true,
		})
		if err != nil {
			emit("ws-attach-error", map[string]any{"error": err.Error()})
			return
		}
		info := attached.Info()
		emit("ws-attached", map[string]any{
			"peer_node_id": string(info.PeerNodeID),
			"link_id":      info.LinkID,
			"link_epoch":   info.LinkEpoch,
			"lane":         info.Lane,
			"role":         int(info.Role),
			"conn_type":    info.ConnectionType,
		})
	})

	server := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	emit("ws-listening", map[string]any{"address": address, "path": path})

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return nil
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("WebSocket ingress ListenAndServe(%s): %w", address, err)
	}
}

// runSource dials the target's VirtualIP and compares the echo byte for byte.
func runSource(ctx context.Context, agent *simpletier.Agent, o *options) error {
	network := agent.Network()
	address := netip.AddrPortFrom(netip.MustParseAddr(o.targetIP), uint16(o.targetPort))

	// Retry until the authenticated topology converges: the peer address
	// arrives through the FACT consumer after the CONTROL link is established,
	// so the first attempts legitimately find no route.
	var conn net.Conn
	var lastErr error
	deadline := time.Now().Add(o.timeout)
	attempts := 0
	for time.Now().Before(deadline) {
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, lastErr = network.DialContext(dialCtx, "tcp", address.String())
		cancel()
		if lastErr == nil {
			break
		}
		attempts++
		// Report periodically so a stuck dial shows its reason in the log
		// instead of looking like a silent hang.
		if attempts%10 == 1 {
			emit("dial-retry", map[string]any{
				"attempt": attempts,
				"address": address.String(),
				"error":   lastErr.Error(),
			})
		}
		time.Sleep(250 * time.Millisecond)
	}
	if conn == nil {
		// Report what this node actually learned before giving up: a dial that
		// never found a route is only actionable once the peer view is visible.
		if peers, peerErr := network.Peers(); peerErr == nil {
			for _, peer := range peers {
				emit("peer", map[string]any{
					"node_id":          string(peer.NodeID),
					"virtual_ips":      peer.VirtualIPs,
					"advertises_relay": peer.AdvertisesRelay,
					"has_static_key":   peer.HasStaticKey,
				})
			}
			emit("peer-count", map[string]any{"count": len(peers)})
		} else {
			emit("peer-error", map[string]any{"error": peerErr.Error()})
		}
		return fmt.Errorf("DialContext(%s) never succeeded: %w", address, lastErr)
	}
	defer conn.Close()
	emit("connected", map[string]any{"address": address.String(), "role": o.role})

	payload := makePayload(o.bytes)
	wantSum := sha256.Sum256(payload)

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		if err == nil {
			if closer, ok := conn.(interface{ CloseWrite() error }); ok {
				err = closer.CloseWrite()
			}
		}
		writeDone <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if err := <-writeDone; err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	gotSum := sha256.Sum256(got)
	match := gotSum == wantSum
	result := map[string]any{
		"role":            o.role,
		"sent":            len(payload),
		"received":        len(got),
		"sha256_sent":     hex.EncodeToString(wantSum[:]),
		"sha256_received": hex.EncodeToString(gotSum[:]),
		"match":           match,
	}
	if !match {
		emit("mismatch", result)
		return fmt.Errorf("echo mismatch: sent %d bytes sha256 %s, received %d bytes sha256 %s",
			len(payload), result["sha256_sent"], len(got), result["sha256_received"])
	}
	emit("result", result)
	emit("PASS", map[string]any{"bytes": len(got)})
	return nil
}

// makePayload returns a deterministic payload of exactly size bytes, so the
// parent can verify what arrived without shipping the payload across hosts.
func makePayload(size int) []byte {
	if size <= 0 {
		size = 1
	}
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	return payload
}
