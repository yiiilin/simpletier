//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// payload sizes: one 1200-byte UDP datagram plus its IPv4+UDP headers is 1228
// bytes and therefore fits the frozen 1380-byte device MTU with room to spare,
// and one 80 KiB TCP stream forces the kernel to segment at that same MTU.
const (
	udpPayloadBytes = 1200
	tcpPayloadBytes = 80 * 1024
	probeTTL        = 123
)

// runSource is the initiator side of the native acceptance: it owns the veth
// pair, moves the peer end into the target namespace, then drives ICMP, UDP and
// TCP business traffic through the kernel. No business byte in this file ever
// touches an SDK flow API: the SDK only sees the complete IP packets the kernel
// hands to the TUN device it opened.
func runSource(ctx context.Context, o *options) error {
	ns, err := bootstrapNamespace(ctx)
	if err != nil {
		return err
	}
	emit(event{Event: "netns-ready", Role: "source", Data: ns})

	remoteVIP, err := netip.ParseAddr(o.peerVIP)
	if err != nil || !remoteVIP.Is4() {
		return stagef("config", "peer-vip %q must be an IPv4 overlay address", o.peerVIP)
	}
	localVIP, err := netip.ParseAddr(o.vip)
	if err != nil || !localVIP.Is4() {
		return stagef("config", "vip %q must be an IPv4 overlay address", o.vip)
	}
	if o.tcpPort <= 0 || o.udpPort <= 0 {
		return stagef("config", "udp-port and tcp-port must be positive")
	}

	if err := createVeth(ctx, o); err != nil {
		return err
	}
	vethInfo, err := ifaceByName(o.carrierLocalIf)
	if err != nil {
		return stagef("veth", "%w", err)
	}
	emit(event{Event: "veth-up", Role: "source", Data: map[string]any{
		"local_if":   o.carrierLocalIf,
		"peer_if":    o.carrierPeerIf,
		"peer_pid":   o.peerPID,
		"local_addr": o.carrierLocal,
		"peer_addr":  o.carrierPeer,
		"iface":      vethInfo,
	}})

	cmds := newCommander(ctx, "source")
	marker, err := resolveMarker(o)
	if err != nil {
		return stagef("setup", "%w", err)
	}

	// Negative phase: the same overlay configuration with a wrong token must
	// never establish a link and must never deliver a packet.
	if err := cmds.expect(ctx, "wrong-token"); err != nil {
		return err
	}
	wrongToken, err := probeWrongToken(ctx, o, remoteVIP)
	if err != nil {
		return err
	}
	emit(event{Event: "wrong-token-done", Role: "source", Data: wrongToken})

	// Positive phase: the real token.
	if err := cmds.expect(ctx, "go"); err != nil {
		return err
	}
	token, err := readToken(o.tokenFile, "token-file")
	if err != nil {
		return err
	}
	stateDir := filepath.Join(o.stateDir, "main")
	cfg := agentConfig(o, token, stateDir, "", o.carrierUpstream)
	agent, device, err := startAgent(ctx, o, cfg, "source-agent")
	if err != nil {
		return err
	}
	emit(event{Event: "agent-started", Role: "source", Data: device})

	tunName, _ := device["tun"].(string)
	if tunName == "" {
		_ = agent.Close()
		return stagef("source-agent", "the SDK did not report a TUN interface name")
	}

	facts, err := namespaceFacts(ctx, o, tunName, remoteVIP)
	if err != nil {
		_ = agent.Close()
		return err
	}
	emit(event{Event: "namespace-facts", Role: "source", Data: facts})

	// Capture on this side's TUN as well: comparing the TTL of the same origin
	// packet before the overlay (here) and after it (the peer TUN) is the
	// frozen-opacity proof.
	tunSniffer, err := startSniffer(tunName)
	if err != nil {
		_ = agent.Close()
		return stagef("capture", "%w", err)
	}
	defer tunSniffer.Close()

	// Readiness: a kernel TCP handshake to the peer's business port completes
	// only when the packet plane, the session and the peer TUN all work.
	readiness, err := waitForOverlayTCP(ctx, remoteVIP, o.tcpPort, 25*time.Second)
	if err != nil {
		_ = agent.Close()
		return stagef("readiness", "%w", err)
	}
	emit(event{Event: "overlay-ready", Role: "source", Data: readiness})

	counterNames := []string{tunName, o.carrierLocalIf, "lo"}
	beforeAll, err := readCountersAll(counterNames)
	if err != nil {
		_ = agent.Close()
		return stagef("counters", "%w", err)
	}

	icmpPayload := buildPayload(marker, 3*len(marker))
	icmp, err := icmpEcho(ctx, localVIP, remoteVIP, icmpPayload, 0x5157, 1, probeTTL, 10*time.Second)
	if err != nil {
		_ = agent.Close()
		return stagef("icmp", "%w", err)
	}
	icmpData := map[string]any{
		"replied":       icmp.Replied,
		"reply_src":     icmp.ReplySrc,
		"reply_ttl":     icmp.TTL,
		"sent_sha256":   hashHex(icmpPayload),
		"reply_sha256":  icmp.PayloadHash,
		"round_trip_ms": icmp.RTT.Milliseconds(),
		"expected_src":  remoteVIP.String(),
	}
	emit(event{Event: "icmp-echo", Role: "source", Data: icmpData})

	udp, err := udpRoundTrip(ctx, localVIP, remoteVIP, marker, o.udpPort)
	if err != nil {
		_ = agent.Close()
		return stagef("udp", "%w", err)
	}
	emit(event{Event: "udp-echo", Role: "source", Data: udp})

	tcp, err := tcpBulk(ctx, localVIP, remoteVIP, marker, o.tcpPort, tcpPayloadBytes)
	if err != nil {
		_ = agent.Close()
		return stagef("tcp", "%w", err)
	}
	emit(event{Event: "tcp-echo", Role: "source", Data: tcp})

	afterAll, err := readCountersAll(counterNames)
	if err != nil {
		_ = agent.Close()
		return stagef("counters", "%w", err)
	}
	emit(event{Event: "probes-done", Role: "source", Data: map[string]any{
		"marker_hex":        fmt.Sprintf("%x", marker),
		"tun_capture":       markerReport(tunSniffer.store, marker, 80, probeTTL, o.vip),
		"tun_capture_store": tunSniffer.store.summary(),
		"counters":          afterAll,
		"counter_deltas":    diffCounters(beforeAll, afterAll),
		"udp_ttl":           probeTTL,
		"udp_payload_bytes": udpPayloadBytes,
		"ip_total_length":   udpPayloadBytes + 28,
		"tcp_payload_bytes": tcpPayloadBytes,
	}})

	if err := cmds.expect(ctx, "stop"); err != nil {
		_ = agent.Close()
		return err
	}
	// Closing while the device reader is still parked must cancel the read and
	// release every owned resource instead of leaking a goroutine or a device.
	closeStarted := time.Now()
	closeErr := agent.Close()
	select {
	case <-agent.Done():
	case <-time.After(10 * time.Second):
		return stagef("close", "agent.Done() did not close within 10s after Close()")
	}
	emit(event{Event: "closed", Role: "source", Data: map[string]any{
		"close_error": errorString(closeErr),
		"close_ms":    time.Since(closeStarted).Milliseconds(),
		"done_closed": true,
		"tun_present": interfacePresent(tunName),
	}})
	return nil
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func interfacePresent(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// agentConfig builds the SDK configuration for one role. The only inputs are
// explicit flags plus the token file; no environment variable is consulted.
func agentConfig(o *options, token, stateDir, listen, upstream string) simpletier.AgentConfig {
	cfg := simpletier.AgentConfig{
		Config: simpletier.Config{
			Network: simpletier.NetworkConfig{Name: o.network, CIDR: o.cidr, Token: token},
			Options: simpletier.RuntimeOptions{
				FixedIP:  o.vip,
				Relay:    boolPtr(o.relay),
				LogLevel: o.logLevel,
			},
		},
		// A TUN device needs an explicit name: it is the only handle a crashed run leaves
		// behind for the next one to find and clean up.
		DeviceName: o.role + "-tun0",
		Inbounds:   simpletier.AgentInbounds{TUN: boolPtr(true)},
	}
	if listen != "" {
		cfg.Listen = []string{listen}
	}
	if upstream != "" {
		cfg.Upstreams = []string{upstream}
	}
	return cfg
}

// startAgent constructs and starts one SDK Agent with TUN enabled and reports
// the native device facts the acceptance asserts on.
func startAgent(ctx context.Context, o *options, cfg simpletier.AgentConfig, stage string) (*simpletier.Agent, map[string]any, error) {
	agent, err := simpletier.NewAgent(cfg)
	if err != nil {
		return nil, nil, stagef(stage, "NewAgent(AgentConfig) failed: %w", err)
	}
	if err := agent.Start(ctx); err != nil {
		_ = agent.Close()
		return nil, nil, stagef(stage, "Agent.Start(ctx) failed: %w", err)
	}
	device := agent.PacketDevice()
	if device == nil {
		_ = agent.Close()
		return nil, nil, stagef(stage, "PacketDevice() is nil after a successful Start although inbounds.tun is true")
	}
	info, err := describeDevice(agent, device)
	if err != nil {
		_ = agent.Close()
		return nil, nil, stagef(stage, "%w", err)
	}
	info["local_virtual_ip"] = agent.LocalVirtualIP().String()
	info["system_network_state"] = systemNetworkState(agent)
	return agent, info, nil
}

// describeDevice reports the opened device through the public port plus the
// optional metadata methods the Linux backend adds structurally, and validates
// the OS view of it from inside this namespace.
func describeDevice(agent *simpletier.Agent, device simpletier.PacketDevice) (map[string]any, error) {
	name, source := deviceInterfaceName(device)
	info := map[string]any{
		"mtu":                   device.MTU(),
		"interface_name":        name,
		"interface_name_source": source,
		"device_type":           fmt.Sprintf("%T", device),
	}
	if name == "" {
		return nil, fmt.Errorf("the opened packet device exposes neither InterfaceName() nor an unambiguous interface")
	}
	iface, err := ifaceByName(name)
	if err != nil {
		return nil, err
	}
	info["tun"] = name
	info["iface"] = iface
	info["sysfs_mtu"] = iface.SysfsMTU
	info["sysfs_arphrd"] = iface.SysfsARP
	info["events_ready"] = deviceReady(device)
	return info, nil
}

// deviceInterfaceName prefers the interface name the device itself reports. If
// a backend does not expose it, the only honest fallback is to look for the one
// interface in this namespace that matches the device MTU and is not the
// loopback or the carrier veth. The reporting source is always published so a
// fallback can never masquerade as device-reported metadata.
func deviceInterfaceName(device simpletier.PacketDevice) (string, string) {
	if named, ok := device.(interface{ InterfaceName() string }); ok {
		if name := named.InterfaceName(); name != "" {
			return name, "packet_device"
		}
	}
	candidates := make([]string, 0, 2)
	all, err := listInterfaces()
	if err != nil {
		return "", "unavailable"
	}
	for _, iface := range all {
		if iface.Name == "lo" || strings.HasPrefix(iface.Name, "stv") {
			continue
		}
		if iface.MTU != device.MTU() {
			continue
		}
		if iface.SysfsARP != 0 && iface.SysfsARP != 65534 {
			continue
		}
		candidates = append(candidates, iface.Name)
	}
	if len(candidates) == 1 {
		return candidates[0], "namespace_scan"
	}
	return "", "unavailable"
}

// deviceReady reports whether the optional ready event was delivered. It is
// evidence only: the SDK does not promise the event to a late subscriber.
func deviceReady(device simpletier.PacketDevice) bool {
	events := device.Events()
	if events == nil {
		return false
	}
	return true
}

// journalFiles lists the durable write-ahead journal the Agent resolved for
// this node, which proves JournalPath was applied before the device was
// configured.
func journalFiles(stateDir string) []string {
	out := []string{}
	_ = filepath.WalkDir(stateDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !entry.IsDir() && strings.Contains(entry.Name(), "journal") {
			out = append(out, path)
		}
		return nil
	})
	return out
}

func systemNetworkState(agent *simpletier.Agent) string {
	sysnet := agent.SystemNetwork()
	if sysnet == nil {
		return ""
	}
	return string(sysnet.State())
}

// namespaceFacts collects the namespace-local interface and route tables plus
// the "the peer VirtualIP is not mine" probe. Everything here is asked of the
// kernel, never of the SDK.
func namespaceFacts(ctx context.Context, o *options, tunName string, remoteVIP netip.Addr) (map[string]any, error) {
	ifaces, err := listInterfaces()
	if err != nil {
		return nil, stagef("facts", "%w", err)
	}
	routes, err := readRoutes()
	if err != nil {
		return nil, stagef("facts", "%w", err)
	}
	netns, err := selfNetnsInode()
	if err != nil {
		return nil, stagef("facts", "%w", err)
	}
	hostNS, err := parentNetnsInode()
	if err != nil {
		return nil, stagef("facts", "%w", err)
	}
	probe := map[string]any{"remote_vip": remoteVIP.String(), "bind_succeeded": false}
	conn, bindErr := net.ListenUDP("udp4", &net.UDPAddr{IP: remoteVIP.AsSlice(), Port: 0})
	if bindErr == nil {
		probe["bind_succeeded"] = true
		_ = conn.Close()
	} else {
		probe["bind_error"] = bindErr.Error()
	}
	localOwned := false
	for _, iface := range ifaces {
		for _, addr := range iface.Addrs {
			if strings.HasPrefix(addr, remoteVIP.String()+"/") {
				localOwned = true
			}
		}
	}
	probe["present_in_local_addresses"] = localOwned
	_ = ctx
	return map[string]any{
		"netns_inode":      netns,
		"host_netns_inode": hostNS,
		"interfaces":       ifaces,
		"routes":           routes,
		"tun":              tunName,
		"local_vip":        o.vip,
		"peer_vip":         remoteVIP.String(),
		"remote_vip_probe": probe,
		"carrier_if":       o.carrierLocalIf,
	}, nil
}

// probeWrongToken runs the same overlay configuration with a wrong shared
// token and proves the negative: the SDK returns an explicit error and the
// packet never reaches the peer.
func probeWrongToken(ctx context.Context, o *options, remoteVIP netip.Addr) (map[string]any, error) {
	wrongToken, err := readToken(o.wrongFile, "wrong-token-file")
	if err != nil {
		return nil, err
	}
	stateDir := filepath.Join(o.stateDir, "wrong")
	cfg := agentConfig(o, wrongToken, stateDir, "", o.carrierUpstream)
	cfg.Options.LogLevel = "debug"

	before, err := readCountersAll([]string{o.carrierLocalIf, "lo"})
	if err != nil {
		return nil, stagef("wrong-token", "%w", err)
	}
	agent, device, err := startAgent(ctx, o, cfg, "wrong-token-agent")
	if err != nil {
		// A failure to even start is reported, not swallowed: the parent needs
		// the exact field to distinguish a rejected config from a rejected peer.
		return nil, err
	}
	tunName, _ := device["tun"].(string)
	result := map[string]any{
		"agent_started": true,
		"tun":           tunName,
		"device":        device,
	}

	// Give the rejected handshake time to happen, bounded and explicit.
	await := 4 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < await+5*time.Second {
			return nil, stagef("wrong-token", "not enough remaining run budget for the negative phase")
		}
	}
	select {
	case <-ctx.Done():
		_ = agent.Close()
		return nil, stagef("wrong-token", "%w", ctx.Err())
	case <-time.After(await):
	}

	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	dial, dialErr := agent.Network().DialContext(dialCtx, "tcp", net.JoinHostPort(remoteVIP.String(), strconv.Itoa(o.tcpPort)))
	cancel()
	if dialErr == nil {
		_ = dial.Close()
		result["dial_error"] = ""
		result["dial_succeeded"] = true
	} else {
		result["dial_error"] = dialErr.Error()
		result["dial_error_type"] = errorType(dialErr)
		result["dial_succeeded"] = false
	}

	// One real kernel UDP datagram into the TUN: it must never be delivered.
	marker, markerErr := newMarker()
	if markerErr != nil {
		_ = agent.Close()
		return nil, stagef("wrong-token", "%w", markerErr)
	}
	payload := buildPayload(marker, 256)
	localVIP, parseErr := netip.ParseAddr(o.vip)
	if parseErr != nil {
		_ = agent.Close()
		return nil, stagef("wrong-token", "own vip %q is not an IPv4 address: %w", o.vip, parseErr)
	}
	sendErr := sendUDPOnce(ctx, localVIP, remoteVIP, o.udpPort, payload)
	result["udp_send_error"] = errorString(sendErr)
	result["udp_sent_bytes"] = len(payload)
	result["udp_sha256"] = hashHex(payload)

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
	after, countersErr := readCountersAll([]string{o.carrierLocalIf, "lo"})
	closeErr := agent.Close()
	result["close_error"] = errorString(closeErr)
	if countersErr != nil {
		return nil, stagef("wrong-token", "%w", countersErr)
	}
	result["counters"] = after
	result["counter_deltas"] = diffCounters(before, after)
	return result, nil
}

// sendUDPOnce injects one datagram through the source VirtualIP into the TUN.
func sendUDPOnce(ctx context.Context, srcVIP, dstVIP netip.Addr, port int, payload []byte) error {
	local, err := netip.ParseAddr(srcVIP.String())
	if err != nil {
		return err
	}
	listenCfg := net.ListenConfig{Control: ttlControl(probeTTL)}
	packetConn, err := listenCfg.ListenPacket(ctx, "udp4", net.JoinHostPort(local.String(), "0"))
	if err != nil {
		return err
	}
	defer packetConn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = packetConn.SetWriteDeadline(deadline)
	}
	_, err = packetConn.WriteTo(payload, &net.UDPAddr{IP: dstVIP.AsSlice(), Port: port})
	return err
}

// waitForOverlayTCP retries a plain kernel TCP handshake until the peer's
// business port answers. The kernel route sends every attempt through the TUN.
func waitForOverlayTCP(ctx context.Context, dstVIP netip.Addr, port int, timeout time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(timeout)
	attempts := 0
	var lastErr error
	for {
		attempts++
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp4", net.JoinHostPort(dstVIP.String(), strconv.Itoa(port)))
		cancel()
		if err == nil {
			_ = conn.Close()
			return map[string]any{"attempts": attempts, "elapsed_ms": time.Since(deadline.Add(-timeout)).Milliseconds()}, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no kernel TCP handshake to %s:%d completed within %s after %d attempts: %w", dstVIP, port, timeout, attempts, lastErr)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// udpRoundTrip sends one 1200-byte datagram from the source VirtualIP and
// expects the peer's real kernel UDP socket to echo it back. The TTL is pinned
// to a non-default value so the peer can prove the IPv4 header crossed the
// overlay unchanged.
func udpRoundTrip(ctx context.Context, srcVIP, dstVIP netip.Addr, marker []byte, port int) (map[string]any, error) {
	payload := buildPayload(marker, udpPayloadBytes)
	listenCfg := net.ListenConfig{Control: ttlControl(probeTTL)}
	packetConn, err := listenCfg.ListenPacket(ctx, "udp4", net.JoinHostPort(srcVIP.String(), "0"))
	if err != nil {
		return nil, fmt.Errorf("bind source VirtualIP %s: %w", srcVIP, err)
	}
	defer packetConn.Close()
	conn, ok := packetConn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("unexpected packet connection type %T", packetConn)
	}
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return nil, err
	}
	written, err := conn.WriteToUDP(payload, &net.UDPAddr{IP: dstVIP.AsSlice(), Port: port})
	if err != nil {
		return nil, fmt.Errorf("send %d bytes to %s:%d: %w", len(payload), dstVIP, port, err)
	}
	buf := make([]byte, 2048)
	read, from, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("no UDP echo from %s:%d: %w", dstVIP, port, err)
	}
	return map[string]any{
		"local_bind":      conn.LocalAddr().String(),
		"sent_bytes":      written,
		"sent_sha256":     hashHex(payload),
		"received_bytes":  read,
		"received_sha256": hashHex(buf[:read]),
		"received_from":   from.String(),
		"expected_dst":    fmt.Sprintf("%s:%d", dstVIP, port),
		"match":           read == len(payload) && hashHex(buf[:read]) == hashHex(payload),
	}, nil
}

// tcpBulk streams 80 KiB through the kernel TCP stack to the peer's real
// kernel echo server, half-closes, and requires the clean FIN/EOF and the
// identical 80 KiB back.
func tcpBulk(ctx context.Context, srcVIP, dstVIP netip.Addr, marker []byte, port, size int) (map[string]any, error) {
	payload := buildPayload(marker, size)
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: srcVIP.AsSlice()},
		Control:   ttlControl(probeTTL),
		Timeout:   20 * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(dstVIP.String(), strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("dial %s:%d: %w", dstVIP, port, err)
	}
	defer conn.Close()
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("unexpected stream connection type %T", conn)
	}
	if err := tcpConn.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
		return nil, err
	}

	writeErr := make(chan error, 1)
	go func() {
		written := 0
		for written < len(payload) {
			n, err := tcpConn.Write(payload[written:])
			if err != nil {
				writeErr <- fmt.Errorf("write after %d bytes: %w", written, err)
				return
			}
			written += n
		}
		if err := tcpConn.CloseWrite(); err != nil {
			writeErr <- fmt.Errorf("half-close after %d bytes: %w", written, err)
			return
		}
		writeErr <- nil
	}()

	received, readErr := io.ReadAll(tcpConn)
	if err := <-writeErr; err != nil {
		return nil, err
	}
	if readErr != nil {
		return nil, fmt.Errorf("read echo after %d bytes: %w", len(received), readErr)
	}
	return map[string]any{
		"local_bind":      tcpConn.LocalAddr().String(),
		"remote_addr":     tcpConn.RemoteAddr().String(),
		"sent_bytes":      len(payload),
		"sent_sha256":     hashHex(payload),
		"received_bytes":  len(received),
		"received_sha256": hashHex(received),
		"clean_eof":       true,
		"match":           len(received) == len(payload) && hashHex(received) == hashHex(payload),
	}, nil
}
