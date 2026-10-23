//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// byteAccount accumulates exactly what reached a real kernel socket: the byte
// count and the SHA-256 of the stream. It never stores payload bytes, so no
// plaintext can leak into the artifacts.
type byteAccount struct {
	mu          sync.Mutex
	bytes       int64
	segments    int64
	digest      hash.Hash
	remotes     map[string]int64
	firstRemote string
}

func newByteAccount() *byteAccount {
	return &byteAccount{digest: sha256.New(), remotes: make(map[string]int64)}
}

func (a *byteAccount) add(data []byte, remote string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bytes += int64(len(data))
	a.segments++
	_, _ = a.digest.Write(data)
	if a.firstRemote == "" {
		a.firstRemote = remote
	}
	a.remotes[remote] += int64(len(data))
}

func (a *byteAccount) snapshot() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	remotes := make(map[string]int64, len(a.remotes))
	for key, value := range a.remotes {
		remotes[key] = value
	}
	return map[string]any{
		"bytes":        a.bytes,
		"segments":     a.segments,
		"sha256":       fmt.Sprintf("%x", a.digest.Sum(nil)),
		"first_remote": a.firstRemote,
		"remotes":      remotes,
	}
}

// runTarget is the responder side: it owns the carrier listener and the real
// kernel UDP/TCP business sockets bound to its overlay VirtualIP, and it
// captures what actually arrives on its TUN (plaintext) and on its veth end
// (ciphertext).
func runTarget(ctx context.Context, o *options) error {
	ns, err := bootstrapNamespace(ctx)
	if err != nil {
		return err
	}
	emit(event{Event: "netns-ready", Role: "target", Data: ns})

	localVIP, err := netip.ParseAddr(o.vip)
	if err != nil || !localVIP.Is4() {
		return stagef("config", "vip %q must be an IPv4 overlay address", o.vip)
	}
	remoteVIP, err := netip.ParseAddr(o.peerVIP)
	if err != nil || !remoteVIP.Is4() {
		return stagef("config", "peer-vip %q must be an IPv4 overlay address", o.peerVIP)
	}
	marker, err := markerFromHex(o.markerHex)
	if err != nil {
		return stagef("config", "%w", err)
	}

	// The source owns the veth pair and moves the peer end here; this side only
	// configures the end it just received. No other namespace is ever touched.
	if err := waitForLink(ctx, o.carrierPeerIf, 25*time.Second); err != nil {
		return err
	}
	if err := runIP(ctx, "addr", "add", o.carrierPeer, "dev", o.carrierPeerIf); err != nil {
		return stagef("veth", "assign %s to %s: %w", o.carrierPeer, o.carrierPeerIf, err)
	}
	if err := runIP(ctx, "link", "set", o.carrierPeerIf, "up"); err != nil {
		return stagef("veth", "bring %s up: %w", o.carrierPeerIf, err)
	}
	vethInfo, err := ifaceByName(o.carrierPeerIf)
	if err != nil {
		return stagef("veth", "%w", err)
	}
	emit(event{Event: "veth-up", Role: "target", Data: map[string]any{
		"local_if":   o.carrierPeerIf,
		"local_addr": o.carrierPeer,
		"iface":      vethInfo,
	}})

	token, err := readToken(o.tokenFile, "token-file")
	if err != nil {
		return err
	}
	cfg := agentConfig(o, token, o.stateDir, o.carrierListen, "")
	if cfg.Listen == nil {
		return stagef("config", "carrier-listen is required for the target role")
	}
	agent, device, err := startAgent(ctx, o, cfg, "target-agent")
	if err != nil {
		return err
	}
	emit(event{Event: "agent-started", Role: "target", Data: device})

	tunName, _ := device["tun"].(string)
	if tunName == "" {
		_ = agent.Close()
		return stagef("target-agent", "the SDK did not report a TUN interface name")
	}
	facts, err := namespaceFacts(ctx, o, tunName, remoteVIP)
	if err != nil {
		_ = agent.Close()
		return err
	}
	emit(event{Event: "namespace-facts", Role: "target", Data: facts})

	if o.udpPort <= 0 || o.tcpPort <= 0 {
		_ = agent.Close()
		return stagef("config", "udp-port and tcp-port must be positive")
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localVIP.AsSlice(), Port: o.udpPort})
	if err != nil {
		_ = agent.Close()
		return stagef("business", "bind kernel UDP %s:%d: %w", localVIP, o.udpPort, err)
	}
	defer udpConn.Close()
	tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: localVIP.AsSlice(), Port: o.tcpPort})
	if err != nil {
		_ = agent.Close()
		return stagef("business", "bind kernel TCP %s:%d: %w", localVIP, o.tcpPort, err)
	}
	defer tcpListener.Close()

	// Both business directions pin the same non-default TTL, so the peer can
	// prove the original IPv4 header crossed the overlay in both directions.
	pinSocketTTL(udpConn)
	pinSocketTTL(tcpListener)

	udpAccount := newByteAccount()
	tcpAccount := newByteAccount()
	go serveUDPEcho(ctx, udpConn, udpAccount)
	go serveTCPEcho(ctx, tcpListener, tcpAccount)

	tunSniffer, err := startSniffer(tunName)
	if err != nil {
		_ = agent.Close()
		return stagef("capture", "%w", err)
	}
	defer tunSniffer.Close()
	carrierSniffer, err := startSniffer(o.carrierPeerIf)
	if err != nil {
		_ = agent.Close()
		return stagef("capture", "%w", err)
	}
	defer carrierSniffer.Close()

	counterNames := []string{tunName, o.carrierPeerIf, "lo"}
	baseline, err := readCountersAll(counterNames)
	if err != nil {
		_ = agent.Close()
		return stagef("counters", "%w", err)
	}
	emit(event{Event: "business-ready", Role: "target", Data: map[string]any{
		"udp_addr": udpConn.LocalAddr().String(),
		"tcp_addr": tcpListener.Addr().String(),
		"tun":      tunName,
		"counters": baseline,
		"captures": map[string]any{
			"tun":     tunSniffer.store.summary(),
			"carrier": carrierSniffer.store.summary(),
		},
	}})

	cmds := newCommander(ctx, "target")
	for {
		command, err := cmds.next(ctx)
		if err != nil {
			_ = agent.Close()
			return err
		}
		switch command {
		case "snapshot":
			counters, err := readCountersAll(counterNames)
			if err != nil {
				_ = agent.Close()
				return stagef("counters", "%w", err)
			}
			emit(event{Event: "snapshot", Role: "target", Data: map[string]any{
				"counters":       counters,
				"counter_deltas": diffCounters(baseline, counters),
				"udp":            udpAccount.snapshot(),
				"tcp":            tcpAccount.snapshot(),
			}})
		case "capture-reset":
			tunSniffer.store.reset()
			carrierSniffer.store.reset()
			emit(event{Event: "capture-reset", Role: "target", Data: map[string]any{
				"tun":     tunSniffer.store.summary(),
				"carrier": carrierSniffer.store.summary(),
			}})
		case "stop":
			counters, err := readCountersAll(counterNames)
			if err != nil {
				_ = agent.Close()
				return stagef("counters", "%w", err)
			}
			summary := map[string]any{
				"marker_hex": fmt.Sprintf("%x", marker),
				"tun": map[string]any{
					"name":   tunName,
					"store":  tunSniffer.store.summary(),
					"report": markerReport(tunSniffer.store, marker, 80, probeTTL, o.peerVIP),
					"error":  tunSniffer.error(),
				},
				"carrier": map[string]any{
					"name":   o.carrierPeerIf,
					"store":  carrierSniffer.store.summary(),
					"report": markerReport(carrierSniffer.store, marker, 80, probeTTL, o.peerVIP),
					"error":  carrierSniffer.error(),
				},
				"udp":            udpAccount.snapshot(),
				"tcp":            tcpAccount.snapshot(),
				"counters":       counters,
				"counter_deltas": diffCounters(baseline, counters),
			}
			emit(event{Event: "capture-summary", Role: "target", Data: summary})
			closeErr := agent.Close()
			select {
			case <-agent.Done():
			case <-time.After(10 * time.Second):
				return stagef("close", "agent.Done() did not close within 10s after Close()")
			}
			emit(event{Event: "closed", Role: "target", Data: map[string]any{
				"close_error": errorString(closeErr),
				"done_closed": true,
				"tun_present": interfacePresent(tunName),
			}})
			return nil
		default:
			_ = agent.Close()
			return stagef("ipc", "target: unexpected command %q", command)
		}
	}
}

// serveUDPEcho is the real kernel UDP socket on the target VirtualIP. Its echo
// is what makes the source's datagram bidirectional.
// pinSocketTTL pins IP_TTL on a socket (for a listener, accepted connections
// inherit it).
func pinSocketTTL(local interface {
	SyscallConn() (syscall.RawConn, error)
}) {
	raw, err := local.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, probeTTL)
	})
}

func serveUDPEcho(ctx context.Context, conn *net.UDPConn, account *byteAccount) {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		account.add(buf[:n], from.String())
		emit(event{Event: "udp-served", Role: "target", Data: map[string]any{
			"bytes":  n,
			"from":   from.String(),
			"sha256": hashHex(buf[:n]),
		}})
		_, _ = conn.WriteToUDP(buf[:n], from)
	}
}

// serveTCPEcho is the real kernel TCP echo server. It records the stream hash,
// observes the peer's FIN and then half-closes, which is the clean
// bidirectional FIN exchange the acceptance requires.
func serveTCPEcho(ctx context.Context, listener *net.TCPListener, account *byteAccount) {
	var connections int64
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = listener.SetDeadline(time.Now().Add(500 * time.Millisecond))
		conn, err := listener.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return
		}
		connections++
		index := connections
		go func(c *net.TCPConn) {
			defer c.Close()
			// An accepted connection does not reliably inherit the listener's
			// TTL, so pin it per connection: every echo segment must carry the
			// same pinned TTL the initiator used.
			pinSocketTTL(c)
			buf := make([]byte, 32*1024)
			bytes := int64(0)
			sawFIN := false
			for {
				_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
				n, readErr := c.Read(buf)
				if n > 0 {
					bytes += int64(n)
					account.add(buf[:n], c.RemoteAddr().String())
					if _, writeErr := c.Write(buf[:n]); writeErr != nil {
						break
					}
				}
				if readErr != nil {
					sawFIN = errors.Is(readErr, io.EOF)
					break
				}
			}
			_ = c.CloseWrite()
			emit(event{Event: "tcp-served", Role: "target", Data: map[string]any{
				"connection": index,
				"bytes":      bytes,
				"remote":     c.RemoteAddr().String(),
				"local":      c.LocalAddr().String(),
				"saw_fin":    sawFIN,
			}})
		}(conn)
	}
}
