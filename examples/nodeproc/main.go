// Command nodeproc is one relay or one overlay peer, meant to be run as its own OS
// process. The multi-peer benchmark drives many of these over real sockets instead of
// running a thousand Networks inside a single Go runtime, which measures the scheduler
// as much as the overlay.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
	"github.com/yiiilin/simpletier/pkg/simpletier/relay"
	"github.com/yiiilin/simpletier/pkg/simpletier/room"
)

func main() {
	mode := flag.String("mode", "", "relay | peer")
	relayAddr := flag.String("relay", "127.0.0.1:22020", "relay ingress")
	listen := flag.String("listen", "", "relay mode: ingress address")
	token := flag.String("token", "", "room token")
	name := flag.String("name", "perf", "overlay network name")
	cidr := flag.String("cidr", "10.100.0.0/24", "overlay CIDR")
	// Listener mode: echo whatever arrives.
	echoPort := flag.Int("echo-port", 0, "listen on this virtual port and echo")
	// Dialer mode: push to a peer's virtual address for the given window.
	dialAddr := flag.String("dial", "", "virtual address to push to, e.g. 10.100.0.2:9000")
	duration := flag.Duration("duration", 20*time.Second, "how long to push")
	// Latency probe target.
	probeAddr := flag.String("probe", "", "virtual address to probe for round-trip samples")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch *mode {
	case "relay":
		if err := runRelay(ctx, *listen); err != nil {
			fail(fmt.Errorf("relay: %w", err))
		}
	case "peer":
		if err := runPeer(ctx, peerConfig{
			relayAddr: *relayAddr, token: *token, name: *name, cidr: *cidr,
			echoPort: *echoPort, dialAddr: *dialAddr, duration: *duration, probeAddr: *probeAddr,
		}); err != nil {
			fail(err)
		}
	default:
		fail(fmt.Errorf("-mode must be relay or peer"))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func runRelay(ctx context.Context, listenAddr string) error {
	r := relay.New(relay.Options{Rooms: room.Options{
		Name: "perf", CIDR: "10.100.0.0/24", LogLevel: "error", RateLimit: boolPtr(false),
	}})
	defer func() { _ = r.Close() }()

	go func() { _ = r.ServeTCP(ctx, listenAddr) }()
	// Announce readiness only once the port answers, so the driver never races the bind.
	if err := waitTCP(listenAddr, 10*time.Second); err != nil {
		return err
	}
	fmt.Printf("relay-ready %s\n", listenAddr)
	<-ctx.Done()
	return nil
}

// peerConfig is one peer's role in a run.
type peerConfig struct {
	relayAddr string
	token     string
	name      string
	cidr      string
	echoPort  int
	dialAddr  string
	duration  time.Duration
	probeAddr string
}

func runPeer(ctx context.Context, cfg peerConfig) error {
	n, err := simpletier.NewNetwork(simpletier.Config{
		Network: simpletier.NetworkConfig{Name: cfg.name, CIDR: cfg.cidr, Token: cfg.token},
		Options: simpletier.RuntimeOptions{LogLevel: "error", RateLimit: boolPtr(false)},
	})
	if err != nil {
		return fmt.Errorf("network: %w", err)
	}
	defer func() { _ = n.Close() }()

	joinedAt := time.Now()
	link, err := relay.JoinRoom(ctx, n, cfg.relayAddr, cfg.token)
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	defer func() { _ = link.Close() }()

	fmt.Printf("joined in %dms vip=%s\n", time.Since(joinedAt).Milliseconds(), n.LocalVirtualIP())

	if cfg.echoPort > 0 {
		return serveEcho(ctx, n, cfg.echoPort)
	}
	if cfg.dialAddr != "" {
		return pushAndMeasure(ctx, n, cfg)
	}
	// Nothing to do but stay joined.
	<-ctx.Done()
	return nil
}

// serveEcho listens on a virtual port and echoes every accepted stream.
func serveEcho(ctx context.Context, n simpletier.Network, port int) error {
	ln, err := n.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("listen :%d: %w", port, err)
	}
	defer func() { _ = ln.Close() }()
	fmt.Printf("echo-ready :%d\n", port)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		stream, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go func(s simpletier.Stream) {
			defer func() { _ = s.Close() }()
			_, _ = io.Copy(s, s)
		}(stream)
	}
}

// pushAndMeasure writes as fast as the path allows for cfg.duration and reports bytes.
func pushAndMeasure(ctx context.Context, n simpletier.Network, cfg peerConfig) error {
	runCtx, cancel := context.WithTimeout(ctx, cfg.duration)
	defer cancel()

	var stream simpletier.Stream
	deadline := time.Now().Add(30 * time.Second)
	var dialErr error
	for time.Now().Before(deadline) {
		attemptCtx, attemptCancel := context.WithTimeout(ctx, 5*time.Second)
		stream, dialErr = n.DialContext(attemptCtx, "tcp", cfg.dialAddr)
		attemptCancel()
		if dialErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if stream == nil {
		return fmt.Errorf("dial %s: %w", cfg.dialAddr, dialErr)
	}
	defer func() { _ = stream.Close() }()
	go func() {
		<-runCtx.Done()
		_ = stream.Close()
	}()

	var sent, received int64
	var writeErr, readErr error
	var wg sync.WaitGroup
	const chunk = 64 << 10

	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, chunk)
		for runCtx.Err() == nil {
			written, err := stream.Write(buf)
			atomic.AddInt64(&sent, int64(written))
			if err != nil {
				if runCtx.Err() == nil {
					writeErr = err
				}
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, chunk)
		for runCtx.Err() == nil {
			read, err := stream.Read(buf)
			atomic.AddInt64(&received, int64(read))
			if err != nil {
				if runCtx.Err() == nil {
					readErr = err
				}
				return
			}
		}
	}()
	wg.Wait()

	elapsed := cfg.duration
	report := map[string]any{
		"uploaded":   sent,
		"downloaded": received,
		"seconds":    elapsed.Seconds(),
		"upMBps":     float64(sent) / elapsed.Seconds() / 1e6,
		"downMBps":   float64(received) / elapsed.Seconds() / 1e6,
	}
	if writeErr != nil {
		report["writeError"] = writeErr.Error()
	}
	if readErr != nil {
		report["readError"] = readErr.Error()
	}
	encoded, _ := json.Marshal(report)
	fmt.Printf("result %s\n", encoded)
	return nil
}

// waitTCP polls until addr accepts a connection.
func waitTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("%s never accepted a connection", addr)
}

func boolPtr(v bool) *bool { return &v }
