// Command gin-edge is a test-only process helper: one node that serves two
// different ingress faces over two different transports at the same time.
//
//	外网面 (public)   gin HTTP server
//	   GET /ws      WebSocket upgrade, then NewWebSocketConnection +
//	                AttachConnection(responder) — a peer from outside dials in
//	   GET /healthz plain HTTP, so the gin engine is visibly alive
//
//	内网面 (private)  the SDK's own carrier
//	   Listen tcp://... — an internal server dials in over plain TCP
//
// Both faces feed the same Network, so a peer that arrived over WebSocket can
// reach a peer that arrived over TCP and vice versa.
//
// It is deliberately NOT a library: an acceptance drives one real OS process
// per node and asserts on the events this prints.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

type options struct {
	network    string
	cidr       string
	token      string
	fixedIP    string
	device     string
	tcpListen  string // 内网面：SDK carrier 监听
	httpListen string // 外网面：gin HTTP 监听
	wsPath     string
	echoPort   int
	timeout    time.Duration
}

// emit writes one JSON line; several goroutines report on the same stdout.
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
		fmt.Fprintf(os.Stderr, "gin-edge: encode %q: %v\n", event, err)
		return
	}
	fmt.Println(string(encoded))
}

func main() {
	o := &options{}
	fs := flag.NewFlagSet("gin-edge", flag.ContinueOnError)
	fs.StringVar(&o.network, "network", "gin-edge", "overlay network name")
	fs.StringVar(&o.cidr, "cidr", "", "overlay CIDR")
	fs.StringVar(&o.token, "token", "", "overlay group token")
	fs.StringVar(&o.fixedIP, "fixed-ip", "", "this node's VirtualIP")
	fs.StringVar(&o.device, "device", "", "requested device name; empty = platform default")
	fs.StringVar(&o.tcpListen, "tcp-listen", "", "内网面: SDK carrier listen, e.g. tcp://0.0.0.0:19950")
	fs.StringVar(&o.httpListen, "http-listen", "", "外网面: gin HTTP listen, e.g. 0.0.0.0:19951")
	fs.StringVar(&o.wsPath, "ws-path", "/ws", "gin route that upgrades to WebSocket")
	fs.IntVar(&o.echoPort, "echo-port", 0, "if non-zero, also listen on this VirtualIP port and echo")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Minute, "role lifetime bound")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gin-edge:", err)
		os.Exit(2)
	}
	if o.cidr == "" || o.token == "" || o.fixedIP == "" {
		fmt.Fprintln(os.Stderr, "gin-edge: -cidr, -token and -fixed-ip are required")
		os.Exit(2)
	}
	if o.tcpListen == "" && o.httpListen == "" {
		fmt.Fprintln(os.Stderr, "gin-edge: at least one of -tcp-listen / -http-listen is required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	// A signal cancels cleanly so the acceptance can stop one node and watch
	// the topology react.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		cancel()
	}()

	if err := run(ctx, o); err != nil {
		emit("error", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
}

func run(ctx context.Context, o *options) error {
	// One Network owns both ingress faces. -tcp-listen is the SDK's own carrier
	// listener; the WebSocket face is admitted later through AttachConnection.
	listen := []string(nil)
	if o.tcpListen != "" {
		listen = []string{o.tcpListen}
	}
	cfg := simpletier.Config{
		Listen:  listen,
		Network: simpletier.NetworkConfig{Name: o.network, CIDR: o.cidr, Token: o.token},
		Options: simpletier.RuntimeOptions{
			FixedIP: o.fixedIP,
			// Options.Relay is left unset on purpose: a nil Relay reports
			// "willing to forward", so this node advertises the relay capability
			// and the route search may use it as a transit hop. An explicit false
			// removes that capability and breaks multi-hop STREAM routing.
		},
	}
	// NewAgent is used rather than NewNetwork so this node configures itself
	// exactly like the already-proven tun-chain nodes; the only difference under
	// test is that the public face is served by gin instead of net/http.
	tunEnabled := o.device != ""
	emit("config", map[string]any{
		"listen":    cfg.Listen,
		"upstreams": cfg.Upstreams,
		"targets":   len(cfg.Targets),
		"tun":       tunEnabled,
		"device":    o.device,
	})
	agent, err := simpletier.NewAgent(simpletier.AgentConfig{
		Config:     cfg,
		Inbounds:   simpletier.AgentInbounds{TUN: &tunEnabled},
		DeviceName: o.device,
	})
	if err != nil {
		return fmt.Errorf("NewAgent: %w", err)
	}
	if err := agent.Start(ctx); err != nil {
		_ = agent.Close()
		return fmt.Errorf("Agent.Start: %w", err)
	}
	defer func() { _ = agent.Close() }()
	network := agent.Network()

	emit("ready", map[string]any{
		"fixed_ip":    o.fixedIP,
		"local_vip":   network.LocalVirtualIP().String(),
		"tcp_listen":  o.tcpListen,
		"http_listen": o.httpListen,
		"device":      o.device,
	})

	errs := make(chan error, 3)

	// 内网面：the SDK carrier listener is already accepting inside NewNetwork.
	if o.tcpListen != "" {
		emit("tcp-face-open", map[string]any{"address": o.tcpListen})
	}

	// 外网面：gin serves plain HTTP plus one WebSocket route.
	if o.httpListen != "" {
		go func() { errs <- serveGinFace(ctx, network, o) }()
	}

	// Optional business endpoint so an acceptance can prove the two faces are
	// actually the same Network.
	if o.echoPort != 0 {
		go func() { errs <- serveEcho(ctx, network, o) }()
	}

	select {
	case <-ctx.Done():
		emit("shutdown", nil)
		return nil
	case err := <-errs:
		return err
	case <-network.Done():
		return errors.New("the Network stopped unexpectedly")
	}
}

// ginEngine builds the public HTTP face. It is written as its own function so a
// test can exercise the routes without starting the overlay.
func ginEngine(network simpletier.Network, path string) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())

	// A plain route proves the gin engine is serving: the WebSocket route alone
	// would not distinguish "gin is up" from "the overlay is up".
	engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"ok":        true,
			"local_vip": network.LocalVirtualIP().String(),
			"peers":     len(mustPeers(network)),
		})
	})

	upgrader := &websocket.Upgrader{
		ReadBufferSize:  32 << 10,
		WriteBufferSize: 32 << 10,
		// The peer is authenticated by the SDK's own Noise handshake right after
		// the upgrade, so an HTTP Origin check would add a weaker second gate
		// that no SimpleTier peer populates. Authorization is the group token.
		CheckOrigin: func(*http.Request) bool { return true },
	}

	engine.GET(path, func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			emit("ws-upgrade-error", map[string]any{"error": err.Error(), "remote": c.Request.RemoteAddr})
			return
		}
		emit("ws-upgraded", map[string]any{
			"remote": c.Request.RemoteAddr,
			"path":   c.Request.URL.Path,
		})

		connection, err := simpletier.NewWebSocketConnection(conn)
		if err != nil {
			_ = conn.Close()
			emit("ws-wrap-error", map[string]any{"error": err.Error()})
			return
		}
		// The WebSocket peer dialled in and wrote the first handshake, so it is
		// the initiator; this node answers with the LaneID taken from the peer's
		// authenticated HANDSHAKE.
		attached, err := network.AttachConnection(c.Request.Context(), connection, simpletier.AttachOptions{
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
	return engine
}

func serveGinFace(ctx context.Context, network simpletier.Network, o *options) error {
	engine := ginEngine(network, o.wsPath)
	server := &http.Server{
		Addr:              o.httpListen,
		Handler:           engine,
		ReadHeaderTimeout: 15 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	emit("http-face-open", map[string]any{"address": o.httpListen, "ws_path": o.wsPath})

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
		return fmt.Errorf("gin face ListenAndServe(%s): %w", o.httpListen, err)
	}
}

// serveEcho listens on this node's VirtualIP and echoes every byte unchanged.
func serveEcho(ctx context.Context, network simpletier.Network, o *options) error {
	address := netip.AddrPortFrom(netip.MustParseAddr(o.fixedIP), uint16(o.echoPort))
	listener, err := network.Listen("tcp", address.String())
	if err != nil {
		return fmt.Errorf("echo Listen(%s): %w", address, err)
	}
	defer listener.Close()
	emit("echo-listening", map[string]any{"address": address.String()})

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("echo Accept: %w", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			var total int64
			buf := make([]byte, 32<<10)
			for {
				n, readErr := c.Read(buf)
				if n > 0 {
					total += int64(n)
					if _, writeErr := c.Write(buf[:n]); writeErr != nil {
						emit("echo-error", map[string]any{"error": writeErr.Error(), "echoed": total})
						return
					}
				}
				if readErr != nil {
					if errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) {
						emit("echo-done", map[string]any{"echoed": total, "reason": "eof"})
						return
					}
					emit("echo-done", map[string]any{"echoed": total, "reason": readErr.Error()})
					return
				}
			}
		}(conn)
	}
}

func mustPeers(network simpletier.Network) []simpletier.PeerFact {
	peers, err := network.Peers()
	if err != nil {
		return nil
	}
	return peers
}
