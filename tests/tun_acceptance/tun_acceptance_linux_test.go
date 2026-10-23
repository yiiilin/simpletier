//go:build linux

package tun_acceptance

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestNativeTUNEndToEndAcceptance is the real SDK Linux Agent TUN acceptance.
//
// Two SDK Agents run in two distinct native network namespaces joined by a
// test-owned veth pair. The veth is created inside the source namespace and one
// end is moved into the target namespace by pid, so no host device, route or
// namespace is ever touched. Both Agents open their own TUN device through the
// public simpletier.NewAgent(AgentConfig)/Start(ctx) API, install their own
// overlay VirtualIP/32 and the overlay CIDR route, and carry real kernel
// ICMP/UDP/TCP traffic through the SDK's encrypted carrier.
//
// The only inter-namespace data path in this test is the SDK's own link: there
// is no test relay, no length-framed shim and no bypass. The evidence is native
// and external to the test process: TUN and carrier interface counters read
// through netlink and sysfs inside each child namespace, plus AF_PACKET
// captures proving the plaintext marker reaches the peer TUN while it never
// appears on the encrypted carrier.
func TestNativeTUNEndToEndAcceptance(t *testing.T) {
	h := newHarness(t)
	rec := &assertionRecorder{t: t}

	seed := os.Getpid()
	carrierNet := 10 + seed%200
	overlayNet := 1 + (seed/7)%250
	basePort := 30000 + seed%800

	carrierLocal := fmt.Sprintf("172.30.%d.1/30", carrierNet)
	carrierPeer := fmt.Sprintf("172.30.%d.2/30", carrierNet)
	carrierCarrier := fmt.Sprintf("172.30.%d.0/30", carrierNet)
	overlayCIDR := fmt.Sprintf("10.249.%d.0/24", overlayNet)
	sourceVIP := fmt.Sprintf("10.249.%d.1", overlayNet)
	targetVIP := fmt.Sprintf("10.249.%d.2", overlayNet)
	carrierPort := basePort
	udpPort := basePort + 1
	tcpPort := basePort + 2

	secretDir := t.TempDir()
	tokenFile := filepath.Join(secretDir, "token")
	wrongTokenFile := filepath.Join(secretDir, "wrong-token")
	token := randomToken(t)
	writeSecret(t, tokenFile, token)
	writeSecret(t, wrongTokenFile, randomToken(t))
	stateRoot := t.TempDir()

	marker := generateMarker(t)
	markerHex := hex.EncodeToString(marker)

	h.logf("run_id=%s carrier=%s overlay=%s source_vip=%s target_vip=%s ports carrier=%d udp=%d tcp=%d",
		h.runID, carrierCarrier, overlayCIDR, sourceVIP, targetVIP, carrierPort, udpPort, tcpPort)
	h.logf("marker_sha256=%s", hashString(marker))

	helperCommon := func(role string) []string {
		return []string{
			"-role", role,
			"-network", "tun-acceptance",
			"-cidr", overlayCIDR,
			"-token-file", tokenFile,
			"-marker-hex", markerHex,
			"-udp-port", fmt.Sprint(udpPort),
			"-tcp-port", fmt.Sprint(tcpPort),
			"-timeout", "160s",
			"-log-level", "warn",
		}
	}

	// Host snapshot before the run, taken by an independent helper process in
	// the host namespace: this is what "no host mutation, no leak" is judged on.
	hostBefore, err := h.runHelperOnce("-role", "helper", "-helper-op", "snapshot", "-watch-iface", "tun0")
	if err != nil {
		t.Fatalf("host snapshot before the run: %v", err)
	}
	beforeInterfaces := interfaceSignature(t, hostBefore.Data)
	beforeRoutes := routeSignature(t, hostBefore.Data)

	// ---------------------------------------------------------------------
	// Phase 1: bring up two distinct native namespaces and the test-owned veth.
	// ---------------------------------------------------------------------
	targetArgs := append(helperCommon("target"),
		"-vip", targetVIP,
		"-peer-vip", sourceVIP,
		"-state-dir", filepath.Join(stateRoot, "target"),
		"-carrier-listen", fmt.Sprintf("tcp://%s:%d", strings.Split(carrierPeer, "/")[0], carrierPort),
		"-carrier-peer", carrierPeer,
		"-carrier-peer-if", "stvB0",
	)
	target := h.spawn("target", true, targetArgs...)
	targetReady, tCursor := target.mustEvent("netns-ready", 0, 20*time.Second)
	targetNetns := uint64(jsonNumberOr(t, targetReady.Data, "netns_inode"))
	targetSeenHost := uint64(jsonNumberOr(t, targetReady.Data, "host_netns_inode"))
	rec.ok("target-in-own-netns", targetNetns != 0 && targetNetns != targetSeenHost,
		"target netns inode %d, host netns inode %d", targetNetns, targetSeenHost)

	sourceArgs := append(helperCommon("source"),
		"-vip", sourceVIP,
		"-peer-vip", targetVIP,
		"-wrong-token-file", wrongTokenFile,
		"-state-dir", filepath.Join(stateRoot, "source"),
		"-carrier-upstream", fmt.Sprintf("tcp://%s:%d", strings.Split(carrierPeer, "/")[0], carrierPort),
		"-carrier-local", carrierLocal,
		"-carrier-peer", carrierPeer,
		"-carrier-local-if", "stvA0",
		"-carrier-peer-if", "stvB0",
		"-peer-pid", fmt.Sprint(target.pid()),
	)
	source := h.spawn("source", true, sourceArgs...)
	sourceReady, sCursor := source.mustEvent("netns-ready", 0, 20*time.Second)
	sourceNetns := uint64(jsonNumberOr(t, sourceReady.Data, "netns_inode"))
	rec.ok("distinct-native-netns", sourceNetns != 0 && targetNetns != 0 && sourceNetns != targetNetns && sourceNetns != targetSeenHost,
		"source netns %d, target netns %d, host netns %d", sourceNetns, targetNetns, targetSeenHost)

	sourceVeth, sCursor := source.mustEvent("veth-up", sCursor, 20*time.Second)
	_, tCursor = target.mustEvent("veth-up", tCursor, 25*time.Second)
	rec.ok("veth-created-inside-source-ns",
		jsonStringOr(t, sourceVeth.Data, "local_if") == "stvA0" && jsonStringOr(t, sourceVeth.Data, "peer_if") == "stvB0",
		"source created %s and moved %s into the target namespace",
		jsonStringOr(t, sourceVeth.Data, "local_if"), jsonStringOr(t, sourceVeth.Data, "peer_if"))

	targetAgent, tCursor := target.mustEvent("agent-started", tCursor, 30*time.Second)
	targetFacts, tCursor := target.mustEvent("namespace-facts", tCursor, 20*time.Second)
	targetBusiness, tCursor := target.mustEvent("business-ready", tCursor, 20*time.Second)

	assertAgentDevice(t, rec, "target", targetAgent.Data, targetVIP, overlayCIDR)
	targetTun := jsonStringOr(t, targetAgent.Data, "tun")
	targetCarrier := "stvB0"

	// ---------------------------------------------------------------------
	// Phase 2: wrong token must not establish a link and must not deliver a
	// single packet; the correct token immediately after must deliver.
	// ---------------------------------------------------------------------
	target.send("snapshot")
	_, tCursor = target.mustEvent("snapshot", tCursor, 20*time.Second)

	source.send("wrong-token")
	wrongDone, sCursor := source.mustEvent("wrong-token-done", sCursor, 30*time.Second)

	target.send("snapshot")
	targetAfterWrong, tCursor := target.mustEvent("snapshot", tCursor, 20*time.Second)

	wrongDialOK, _ := jsonString(wrongDone.Data, "dial_error")
	wrongSucceeded, _ := jsonBool(wrongDone.Data, "dial_succeeded")
	rec.ok("wrong-token-dial-rejected", !wrongSucceeded && wrongDialOK != "",
		"wrong token produced dial error %q (type %q)", wrongDialOK, jsonStringOr(t, wrongDone.Data, "dial_error_type"))

	targetTunRxAfterWrong := deltaValue(targetAfterWrong.Data, targetTun, "rx_bytes_delta")
	targetUDPAfterWrong := floatValue(targetAfterWrong.Data, "udp", "bytes")
	targetTCPAfterWrong := floatValue(targetAfterWrong.Data, "tcp", "bytes")
	rec.ok("wrong-token-no-packet-delivery",
		targetTunRxAfterWrong == 0 && targetUDPAfterWrong == 0 && targetTCPAfterWrong == 0,
		"target TUN rx delta %v bytes, target business UDP %v bytes, TCP %v bytes after the wrong-token window",
		targetTunRxAfterWrong, targetUDPAfterWrong, targetTCPAfterWrong)
	rec.ok("wrong-token-handshake-attempted",
		deltaValue(wrongDone.Data, "stvA0", "tx_bytes_delta") > 0,
		"source carrier tx delta %v bytes while the handshake was rejected",
		deltaValue(wrongDone.Data, "stvA0", "tx_bytes_delta"))

	rejectionEvidence := authKeywordEvidence(source.stderrText())
	h.logf("wrong-token rejection stderr evidence: %v", rejectionEvidence)

	// ---------------------------------------------------------------------
	// Phase 3: the real token, the real TUN devices, the real business traffic.
	// ---------------------------------------------------------------------
	target.send("capture-reset")
	_, tCursor = target.mustEvent("capture-reset", tCursor, 20*time.Second)

	source.send("go")
	sourceAgent, sCursor := source.mustEvent("agent-started", sCursor, 40*time.Second)
	sourceFacts, sCursor := source.mustEvent("namespace-facts", sCursor, 20*time.Second)
	overlayReady, sCursor := source.mustEvent("overlay-ready", sCursor, 60*time.Second)
	icmpEvent, sCursor := source.mustEvent("icmp-echo", sCursor, 30*time.Second)
	udpEvent, sCursor := source.mustEvent("udp-echo", sCursor, 30*time.Second)
	tcpEvent, sCursor := source.mustEvent("tcp-echo", sCursor, 60*time.Second)
	probesDone, _ := source.mustEvent("probes-done", sCursor, 30*time.Second)

	assertAgentDevice(t, rec, "source", sourceAgent.Data, sourceVIP, overlayCIDR)
	sourceTun := jsonStringOr(t, sourceAgent.Data, "tun")
	sourceCarrier := "stvA0"

	// The carrier and overlay route tables read inside each namespace.
	assertOverlayRoute(t, rec, "source", sourceFacts.Data, sourceTun, overlayCIDR)
	assertOverlayRoute(t, rec, "target", targetFacts.Data, targetTun, overlayCIDR)
	assertPeerVIPNotLocal(t, rec, "source", sourceFacts.Data, targetVIP)
	assertPeerVIPNotLocal(t, rec, "target", targetFacts.Data, sourceVIP)

	// ICMP: the peer kernel answered an echo request that travelled over the TUN.
	icmpReplied, _ := jsonBool(icmpEvent.Data, "replied")
	icmpSrc := jsonStringOr(t, icmpEvent.Data, "reply_src")
	rec.ok("icmp-kernel-reply", icmpReplied && icmpSrc == targetVIP,
		"replied=%v reply_src=%q expected=%q rtt_ms=%v", icmpReplied, icmpSrc, targetVIP, jsonNumberOr(t, icmpEvent.Data, "round_trip_ms"))
	rec.ok("icmp-payload-round-trip",
		jsonStringOr(t, icmpEvent.Data, "reply_sha256") == jsonStringOr(t, icmpEvent.Data, "sent_sha256"),
		"sent %s reply %s", shortHash(jsonStringOr(t, icmpEvent.Data, "sent_sha256")), shortHash(jsonStringOr(t, icmpEvent.Data, "reply_sha256")))

	// UDP: 1200 payload bytes plus 20 IPv4 + 8 UDP = 1228 bytes, inside the 1380 MTU.
	udpMatch, _ := jsonBool(udpEvent.Data, "match")
	udpSent := jsonNumberOr(t, udpEvent.Data, "sent_bytes")
	udpReceived := jsonNumberOr(t, udpEvent.Data, "received_bytes")
	rec.ok("udp-bidirectional-1200", udpMatch && udpSent == 1200 && udpReceived == 1200,
		"sent %v received %v match=%v from %q local %q", udpSent, udpReceived, udpMatch,
		jsonStringOr(t, udpEvent.Data, "received_from"), jsonStringOr(t, udpEvent.Data, "local_bind"))

	// TCP: 80 KiB with a clean FIN/EOF exchange.
	tcpMatch, _ := jsonBool(tcpEvent.Data, "match")
	cleanEOF, _ := jsonBool(tcpEvent.Data, "clean_eof")
	tcpSent := jsonNumberOr(t, tcpEvent.Data, "sent_bytes")
	tcpReceived := jsonNumberOr(t, tcpEvent.Data, "received_bytes")
	rec.ok("tcp-80kib-finfull-echo", tcpMatch && cleanEOF && tcpSent == 81920 && tcpReceived == 81920,
		"sent %v received %v match=%v clean_eof=%v", tcpSent, tcpReceived, tcpMatch, cleanEOF)

	// The responder side saw the same bytes on its real kernel sockets.
	udpServed, tServed := target.mustEvent("udp-served", tCursor, 30*time.Second)
	tcpServed, _ := target.mustEvent("tcp-served", tServed, 90*time.Second)
	rec.ok("target-kernel-udp-received-exact-payload",
		jsonNumberOr(t, udpServed.Data, "bytes") == 1200 && jsonStringOr(t, udpServed.Data, "sha256") == jsonStringOr(t, udpEvent.Data, "sent_sha256"),
		"target kernel UDP socket received %v bytes hash %s (source sent hash %s) from %q",
		jsonNumberOr(t, udpServed.Data, "bytes"), shortHash(jsonStringOr(t, udpServed.Data, "sha256")),
		shortHash(jsonStringOr(t, udpEvent.Data, "sent_sha256")), jsonStringOr(t, udpServed.Data, "from"))
	tcpSawFIN, _ := jsonBool(tcpServed.Data, "saw_fin")
	rec.ok("target-kernel-tcp-stream-and-fin",
		jsonNumberOr(t, tcpServed.Data, "bytes") == 81920 && tcpSawFIN,
		"target kernel TCP echo served %v bytes and observed the peer FIN=%v on connection %v from %q",
		jsonNumberOr(t, tcpServed.Data, "bytes"), tcpSawFIN, jsonNumberOr(t, tcpServed.Data, "connection"),
		jsonStringOr(t, tcpServed.Data, "remote"))
	rec.ok("business-sockets-bound-to-target-vip",
		jsonStringOr(t, targetBusiness.Data, "udp_addr") == fmt.Sprintf("%s:%d", targetVIP, udpPort) &&
			jsonStringOr(t, targetBusiness.Data, "tcp_addr") == fmt.Sprintf("%s:%d", targetVIP, tcpPort),
		"target kernel UDP %q and TCP %q bound on the overlay VirtualIP",
		jsonStringOr(t, targetBusiness.Data, "udp_addr"), jsonStringOr(t, targetBusiness.Data, "tcp_addr"))
	rec.ok("udp-ip-size-within-mtu",
		jsonNumberOr(t, probesDone.Data, "udp_payload_bytes") == 1200 && jsonNumberOr(t, probesDone.Data, "ip_total_length") == 1228 &&
			jsonNumberOr(t, probesDone.Data, "tcp_payload_bytes") == 81920,
		"declared UDP payload %v with IPv4 total length %v, TCP stream %v",
		jsonNumberOr(t, probesDone.Data, "udp_payload_bytes"), jsonNumberOr(t, probesDone.Data, "ip_total_length"),
		jsonNumberOr(t, probesDone.Data, "tcp_payload_bytes"))

	// ---------------------------------------------------------------------
	// Phase 4: shutdown, capture summary and no-leak checks.
	// ---------------------------------------------------------------------
	source.send("stop")
	sourceClosed, sCursor := source.mustEvent("closed", sCursor, 30*time.Second)
	if err := source.waitExit(30 * time.Second); err != nil {
		t.Fatalf("source child: %v", err)
	}
	if code, err, _ := source.exitStatus(); code != 0 {
		t.Fatalf("source child exited with code %d (err %v); stderr:\n%s", code, err, tailString(source.stderrText(), 3000))
	}
	sourceDone, _ := jsonBool(sourceClosed.Data, "done_closed")
	sourceTunPresent, _ := jsonBool(sourceClosed.Data, "tun_present")
	rec.ok("source-close-cancels-reads", sourceDone && jsonStringOr(t, sourceClosed.Data, "close_error") == "",
		"source closed while the device reader was parked: Done closed=%v close_error=%q close_ms=%v",
		sourceDone, jsonStringOr(t, sourceClosed.Data, "close_error"), jsonNumberOr(t, sourceClosed.Data, "close_ms"))
	rec.ok("source-tun-removed-on-close", !sourceTunPresent,
		"the source TUN interface %s still exists after Agent.Close(): %v", sourceTun, sourceTunPresent)

	target.send("stop")
	captureSummary, tCursor := target.mustEvent("capture-summary", tCursor, 30*time.Second)
	targetClosed, tCursor := target.mustEvent("closed", tCursor, 30*time.Second)
	if err := target.waitExit(30 * time.Second); err != nil {
		t.Fatalf("target child: %v", err)
	}
	if code, err, _ := target.exitStatus(); code != 0 {
		t.Fatalf("target child exited with code %d (err %v); stderr:\n%s", code, err, tailString(target.stderrText(), 3000))
	}

	targetDone, _ := jsonBool(targetClosed.Data, "done_closed")
	targetTunPresent, _ := jsonBool(targetClosed.Data, "tun_present")
	rec.ok("target-close-releases-device", targetDone && jsonStringOr(t, targetClosed.Data, "close_error") == "" && !targetTunPresent,
		"target Done closed=%v close_error=%q, TUN %s still present=%v", targetDone,
		jsonStringOr(t, targetClosed.Data, "close_error"), targetTun, targetTunPresent)

	// Host snapshot after the run.
	hostAfter, err := h.runHelperOnce("-role", "helper", "-helper-op", "snapshot", "-watch-iface", "tun0")
	if err != nil {
		t.Fatalf("host snapshot after the run: %v", err)
	}
	afterInterfaces := interfaceSignature(t, hostAfter.Data)
	afterRoutes := routeSignature(t, hostAfter.Data)

	assertHostUntouched(t, rec, beforeInterfaces, afterInterfaces, beforeRoutes, afterRoutes, hostBefore.Data, hostAfter.Data, overlayCIDR, carrierCarrier)
	assertBusinessHashes(t, rec, captureSummary.Data, udpEvent.Data, tcpEvent.Data)
	assertCounters(t, rec, "source", probesDone.Data, sourceTun, sourceCarrier)
	assertCounters(t, rec, "target", captureSummary.Data, targetTun, targetCarrier)
	assertEncryptionEvidence(t, rec, captureSummary.Data, markerHex, sourceVIP, targetVIP)
	assertTTLOpacityAcrossTunnels(t, rec, probesDone.Data, captureSummary.Data, sourceVIP, targetVIP)

	// ---------------------------------------------------------------------
	// Artifact: full evidence table plus every raw event the helpers emitted.
	// ---------------------------------------------------------------------
	summary := map[string]any{
		"run_id":                    h.runID,
		"topology":                  map[string]any{"carrier_cidr": carrierCarrier, "overlay_cidr": overlayCIDR, "source_vip": sourceVIP, "target_vip": targetVIP, "carrier_port": carrierPort, "udp_port": udpPort, "tcp_port": tcpPort, "marker_hex": markerHex},
		"netns":                     map[string]any{"host": targetSeenHost, "source": sourceNetns, "target": targetNetns},
		"overlay_ready":             overlayReady.Data,
		"wrong_token":               wrongDone.Data,
		"rejection_evidence":        rejectionEvidence,
		"icmp":                      icmpEvent.Data,
		"udp":                       udpEvent.Data,
		"tcp":                       tcpEvent.Data,
		"probes_done":               probesDone.Data,
		"target_business":           targetBusiness.Data,
		"capture_summary":           captureSummary.Data,
		"host_before":               hostBefore.Data,
		"host_after":                hostAfter.Data,
		"host_after_wrong_snapshot": targetAfterWrong.Data,
		"source_events":             source.eventNames(),
		"target_events":             target.eventNames(),
		"assertions":                rec.snapshot(),
		"source_sha256":             sourceDigests(t, h.moduleRoot),
	}
	writeSummary(t, h, summary)
}

// assertAgentDevice checks the public device surface plus the OS view of the
// opened TUN inside the child namespace.
func assertAgentDevice(t *testing.T, rec *assertionRecorder, role string, data map[string]any, vip, overlayCIDR string) {
	t.Helper()
	mtu := jsonNumberOr(t, data, "mtu")
	sysfsMTU := jsonNumberOr(t, data, "sysfs_mtu")
	tunName := jsonStringOr(t, data, "tun")
	rec.ok(role+"-tun-device-open", tunName != "",
		"device type %T as %q (metadata source %q), MTU %v", jsonStringOr(t, data, "device_type"), tunName,
		jsonStringOr(t, data, "interface_name_source"), mtu)
	rec.ok(role+"-device-mtu-1380", mtu == 1380 && sysfsMTU == 1380,
		"PacketDevice.MTU()=%v, OS /sys/class/net/%s/mtu=%v", mtu, tunName, sysfsMTU)
	rec.ok(role+"-local-vip-installed", jsonStringOr(t, data, "local_virtual_ip") == vip,
		"Agent.LocalVirtualIP()=%q expected %q; iface addrs %v", jsonStringOr(t, data, "local_virtual_ip"), vip, ifaceAddrs(data))
	// The journal is process-local now, so there is no file to look for. What still has to
	// hold is that a real TUN interface was opened: ARPHRD_NONE is what distinguishes a
	// layer-3 tunnel from any other link type. The routes themselves are asserted
	// separately by assertOverlayRoute.
	rec.ok(role+"-real-tun-device",
		jsonNumberOr(t, data, "sysfs_arphrd") == 65534,
		"sysfs ARPHRD=%v (65534 = ARPHRD_NONE, a real TUN)", jsonNumberOr(t, data, "sysfs_arphrd"))
	state := jsonStringOr(t, data, "system_network_state")
	rec.ok(role+"-system-network-applied", state == "applied" || state == "running",
		"SystemNetwork.State()=%q after Start", state)
}

func ifaceAddrs(data map[string]any) []string {
	iface, ok := jsonObject(data, "iface")
	if !ok {
		return nil
	}
	raw, ok := iface["addrs"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

// assertOverlayRoute proves the kernel routes the overlay CIDR through the TUN
// device, never through loopback and never through a host gateway.
func assertOverlayRoute(t *testing.T, rec *assertionRecorder, role string, facts map[string]any, tunName, overlayCIDR string) {
	t.Helper()
	network := strings.Split(overlayCIDR, "/")[0]
	mask := "255.255.255.0"
	route, found := findRoute(t, facts, network, mask)
	rec.ok(role+"-overlay-cidr-routes-over-tun", found && jsonStringOr(t, route, "iface") == tunName,
		"route %s/%s -> iface %q (want %q); full table %v", network, mask, jsonStringOr(t, route, "iface"), tunName, routeTable(facts))
	if found {
		rec.ok(role+"-overlay-route-not-on-lo", jsonStringOr(t, route, "iface") != "lo",
			"overlay route iface %q", jsonStringOr(t, route, "iface"))
	}
}

func assertPeerVIPNotLocal(t *testing.T, rec *assertionRecorder, role string, facts map[string]any, peerVIP string) {
	t.Helper()
	bindSucceeded, _ := jsonBool(facts, "remote_vip_probe", "bind_succeeded")
	presentLocal, _ := jsonBool(facts, "remote_vip_probe", "present_in_local_addresses")
	rec.ok(role+"-peer-vip-not-local", !bindSucceeded && !presentLocal,
		"binding %s locally succeeded=%v, present in local addresses=%v (bind error %q)",
		peerVIP, bindSucceeded, presentLocal, jsonStringOr(t, facts, "remote_vip_probe", "bind_error"))
}

// assertCounters proves the business bytes really crossed the SDK TUN device and
// the veth carrier, and that they did not take a loopback shortcut.
func assertCounters(t *testing.T, rec *assertionRecorder, role string, data map[string]any, tunName, carrierName string) {
	t.Helper()
	tunTx := deltaValue(data, tunName, "tx_bytes_delta")
	tunRx := deltaValue(data, tunName, "rx_bytes_delta")
	carrierTx := deltaValue(data, carrierName, "tx_bytes_delta")
	carrierRx := deltaValue(data, carrierName, "rx_bytes_delta")
	loTx := deltaValue(data, "lo", "tx_bytes_delta")
	loRx := deltaValue(data, "lo", "rx_bytes_delta")
	rec.ok(role+"-tun-counters-moved", tunTx > 0 && tunRx > 0,
		"TUN %s tx %v bytes rx %v bytes", tunName, tunTx, tunRx)
	rec.ok(role+"-carrier-counters-moved", carrierTx > 0 && carrierRx > 0,
		"carrier %s tx %v bytes rx %v bytes", carrierName, carrierTx, carrierRx)
	rec.ok(role+"-no-loopback-bypass", loTx < 4096 && loRx < 4096,
		"loopback tx %v bytes rx %v bytes during the business phases", loTx, loRx)
	if role == "source" {
		rec.ok("source-tun-tx-covers-both-directions",
			tunTx > float64(81920) && tunRx > float64(81920),
			"source TUN tx %v bytes and rx %v bytes both exceed the 80 KiB echo stream", tunTx, tunRx)
	}
}

// assertEncryptionEvidence is the core link proof: the plaintext marker reaches
// the peer TUN with its original TTL and length, and never appears on the veth
// carrier, whose only traffic is the SDK's encrypted link.
func assertEncryptionEvidence(t *testing.T, rec *assertionRecorder, data map[string]any, markerHex, sourceVIP, targetVIP string) {
	t.Helper()
	tunFound, _ := jsonBool(data, "tun", "report", "marker_found")
	tunFrames := jsonNumberOr(t, data, "tun", "report", "marker_frames")
	dataTTLUniform, _ := jsonBool(data, "tun", "report", "data_ttl_uniform")
	_ = jsonNumberOr(t, data, "tun", "report", "pinned_ttl")
	icmpOriginTTLs, _ := jsonObject(data, "tun", "report", "icmp_origin_ttls")
	icmpPeerTTLs, _ := jsonObject(data, "tun", "report", "icmp_peer_ttls")
	allIPv4, _ := jsonBool(data, "tun", "report", "all_ipv4")
	bySrc, _ := jsonObject(data, "tun", "report", "by_src")
	withinMTU, _ := jsonBool(data, "tun", "report", "within_mtu_1380")
	maxTotal := jsonNumberOr(t, data, "tun", "report", "max_total_len")
	protocols, _ := jsonObject(data, "tun", "report", "protocols")
	proto := func(key string) float64 {
		value, _ := protocols[key].(float64)
		return value
	}
	carrierFound, _ := jsonBool(data, "carrier", "report", "marker_found")
	carrierPackets := jsonNumberOr(t, data, "carrier", "store", "packets")
	carrierBytes := jsonNumberOr(t, data, "carrier", "store", "bytes")

	rec.ok("plaintext-reaches-peer-tun", tunFound && tunFrames > 0,
		"%v plaintext marker frames captured on the target TUN", tunFrames)
	rec.ok("peer-tun-captured-plaintext-ipv4", allIPv4 && tunFound, "all_ipv4=%v marker_found=%v", allIPv4, tunFound)
	rec.ok("icmp-request-ttl-preserved-to-peer-tun", len(icmpOriginTTLs) == 1 && icmpOriginTTLs["123"] != nil,
		"the echo request reached the peer TUN carrying the origin's pinned TTL %v", icmpOriginTTLs)
	rec.ok("icmp-reply-generated-by-peer-kernel", len(icmpPeerTTLs) > 0,
		"the peer kernel answered with its own TTL %v, so the ICMP response is a real kernel answer", icmpPeerTTLs)
	_ = dataTTLUniform
	rec.ok("all-protocols-crossed-the-overlay",
		proto("1") > 0 && proto("6") > 0 && proto("17") > 0,
		"ICMP/TCP/UDP marker frames observed at the peer TUN: %v", protocols)
	rec.ok("ipv4-mtu-1380-respected", withinMTU && maxTotal <= 1380,
		"largest plaintext IPv4 total length %v <= 1380", maxTotal)
	rec.ok("carrier-carried-ciphertext-only", !carrierFound && carrierPackets > 0 && carrierBytes > 0,
		"carrier captured %v frames / %v bytes and the plaintext marker appeared %v times",
		carrierPackets, carrierBytes, carrierFound)
	rec.ok("marker-arrives-in-both-directions", bySrc[sourceVIP] != nil && bySrc[targetVIP] != nil,
		"plaintext marker frames observed from %s and from %s; histogram %v", sourceVIP, targetVIP, protocols)
}

// assertHostUntouched compares the independent host snapshots taken before and
// after the run.
func assertHostUntouched(t *testing.T, rec *assertionRecorder, before, after map[string]string, beforeRoutes, afterRoutes map[string]string, beforeData, afterData map[string]any, overlayCIDR, carrierCIDR string) {
	t.Helper()
	added, removed, changed := diffSignatures(before, after)
	rec.ok("host-interfaces-unchanged", len(added) == 0 && len(removed) == 0 && len(changed) == 0,
		"host interface set before/after: added %v removed %v changed %v", added, removed, changed)

	// Only meaningful when the host already runs a tun0 (typical on a developer
	// machine, absent on a bare runner). host-interfaces-unchanged above already
	// proves the stronger property, that the whole set is identical; this row
	// names the specific interface when there is one to name.
	beforeTun, beforeOK := before["tun0"]
	afterTun, afterOK := after["tun0"]
	if beforeOK {
		rec.ok("pre-existing-host-tun0-untouched", afterOK && beforeTun == afterTun,
			"host tun0 %q before -> %q after (present after=%v)", beforeTun, afterTun, afterOK)
	} else {
		rec.skip("pre-existing-host-tun0-untouched", "skipped: host has no tun0")
	}

	addedRoutes, removedRoutes, _ := diffSignatures(beforeRoutes, afterRoutes)
	rec.ok("host-routes-unchanged", len(addedRoutes) == 0 && len(removedRoutes) == 0,
		"host route set added %v removed %v", addedRoutes, removedRoutes)

	hostRoutes, _ := jsonObjectList(beforeData, "routes")
	overlayNetwork := strings.Split(overlayCIDR, "/")[0]
	carrierNetwork := strings.Split(carrierCIDR, "/")[0]
	leaked := []string{}
	for _, route := range hostRoutes {
		destination, _ := route["destination"].(string)
		iface, _ := route["iface"].(string)
		if destination == overlayNetwork || destination == carrierNetwork {
			leaked = append(leaked, fmt.Sprintf("%s via %s", destination, iface))
		}
	}
	rec.ok("test-topology-absent-from-host-routes", len(leaked) == 0,
		"host route table containing the test overlay/carrier networks: %v", leaked)

	testIfaces := map[string]any{}
	for name := range after {
		if strings.HasPrefix(name, "stv") {
			testIfaces[name] = true
		}
	}
	rec.ok("no-test-interfaces-on-host", len(testIfaces) == 0,
		"host interfaces left behind by the test: %v", testIfaces)

	watch, _ := jsonObject(afterData, "watch")
	present, _ := jsonBool(watch, "present")
	if beforeOK {
		rec.ok("host-tun0-present-after-run", present, "helper watch reported tun0 present=%v", present)
	} else {
		rec.skip("host-tun0-present-after-run", "skipped: host has no tun0")
	}
	_ = beforeData
}

// ttlHistogram extracts one TTL histogram from a marker report.
func ttlHistogram(report map[string]any, field string) map[string]any {
	value, _ := jsonObject(report, field)
	return value
}

func singleTTLKey(histogram map[string]any) (string, bool) {
	if len(histogram) != 1 {
		return "", false
	}
	for key := range histogram {
		return key, true
	}
	return "", false
}

// assertTTLOpacityAcrossTunnels is the frozen-opacity proof: the IPv4 TTL of
// packets originated by the source is read on the source TUN before the overlay
// and on the target TUN after it, and must be identical. The reverse direction
// is checked the same way, so a re-originated or TTL-rewritten packet cannot
// pass. ICMP echo replies are kernel-generated on the responder and are
// therefore recorded separately instead of being pinned.
func assertTTLOpacityAcrossTunnels(t *testing.T, rec *assertionRecorder, sourceData, targetData map[string]any, sourceVIP, targetVIP string) {
	t.Helper()
	egress, _ := jsonObject(sourceData, "tun_capture")
	ingress, _ := jsonObject(targetData, "tun", "report")
	rec.fatal("tun-capture-present-on-both-sides", egress != nil && ingress != nil,
		"source TUN capture %v, target TUN capture %v", egress != nil, ingress != nil)

	egressOrigin := ttlHistogram(egress, "origin_data_ttls")
	ingressOrigin := ttlHistogram(ingress, "origin_data_ttls")
	egressPeer := ttlHistogram(egress, "peer_data_ttls")
	ingressPeer := ttlHistogram(ingress, "peer_data_ttls")

	egressKey, egressUniform := singleTTLKey(egressOrigin)
	ingressKey, ingressUniform := singleTTLKey(ingressOrigin)
	rec.ok("source-origin-ttl-single-valued-and-identical-across-tunnels",
		egressUniform && ingressUniform && egressKey == ingressKey && egressKey == "123",
		"source-originated TTL histogram on the source TUN %v vs on the target TUN %v (source pinned 123)",
		egressOrigin, ingressOrigin)

	egressPeerKey, egressPeerUniform := singleTTLKey(egressPeer)
	ingressPeerKey, ingressPeerUniform := singleTTLKey(ingressPeer)
	rec.ok("peer-origin-ttl-single-valued-and-identical-across-tunnels",
		egressPeerUniform && ingressPeerUniform && egressPeerKey == ingressPeerKey,
		"peer-originated TTL histogram on the target TUN %v vs on the source TUN %v",
		ingressPeer, egressPeer)

	rec.ok("both-directions-observed-on-both-tunnels",
		len(egressOrigin) > 0 && len(ingressOrigin) > 0 && len(egressPeer) > 0 && len(ingressPeer) > 0,
		"origin %s and peer %s traffic observed at both TUNs", sourceVIP, targetVIP)
}

func jsonObjectOrNil(data map[string]any, path ...string) map[string]any {
	value, _ := jsonObject(data, path...)
	return value
}

// assertBusinessHashes cross-checks the initiator's sent stream hashes against
// the bytes a real kernel socket on the responder side actually received.
func assertBusinessHashes(t *testing.T, rec *assertionRecorder, capture map[string]any, udp, tcp map[string]any) {
	t.Helper()
	targetUDPBytes := floatValue(capture, "udp", "bytes")
	targetUDPHash := jsonStringOr(t, capture, "udp", "sha256")
	targetTCPBytes := floatValue(capture, "tcp", "bytes")
	targetTCPHash := jsonStringOr(t, capture, "tcp", "sha256")
	rec.ok("udp-payload-hash-identical-both-ends",
		targetUDPBytes == 1200 && targetUDPHash != "" && targetUDPHash == jsonStringOr(t, udp, "sent_sha256"),
		"responder received %v bytes hash %s, initiator sent hash %s",
		targetUDPBytes, shortHash(targetUDPHash), shortHash(jsonStringOr(t, udp, "sent_sha256")))
	rec.ok("tcp-stream-hash-identical-both-ends",
		targetTCPBytes == 81920 && targetTCPHash != "" && targetTCPHash == jsonStringOr(t, tcp, "sent_sha256"),
		"responder received %v bytes hash %s, initiator sent hash %s",
		targetTCPBytes, shortHash(targetTCPHash), shortHash(jsonStringOr(t, tcp, "sent_sha256")))
}

func deltaValue(data map[string]any, iface string, field string) float64 {
	value, ok := jsonNumber(data, "counter_deltas", iface, field)
	if !ok {
		return 0
	}
	return value
}

func floatValue(data map[string]any, path ...string) float64 {
	value, _ := jsonNumber(data, path...)
	return value
}

func jsonNumberOr(t *testing.T, data map[string]any, path ...string) float64 {
	t.Helper()
	value, ok := jsonNumber(data, path...)
	if !ok {
		t.Fatalf("event payload has no numeric %s; payload keys: %v", strings.Join(path, "."), keysOf(data))
	}
	return value
}

func jsonStringOr(t *testing.T, data map[string]any, path ...string) string {
	t.Helper()
	value, _ := jsonString(data, path...)
	return value
}

func keysOf(data map[string]any) []string {
	out := make([]string, 0, len(data))
	for key := range data {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// interfaceSignature reduces one helper snapshot to name -> "mtu|flags|addrs".
func interfaceSignature(t *testing.T, data map[string]any) map[string]string {
	t.Helper()
	list, ok := jsonObjectList(data, "interfaces")
	if !ok {
		t.Fatalf("host snapshot carries no interface list")
	}
	out := make(map[string]string, len(list))
	for _, iface := range list {
		name, _ := iface["name"].(string)
		addrs, _ := iface["addrs"].([]any)
		text := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if value, ok := addr.(string); ok {
				text = append(text, value)
			}
		}
		sort.Strings(text)
		out[name] = fmt.Sprintf("mtu=%v flags=%v addrs=%s", iface["mtu"], iface["flags"], strings.Join(text, ","))
	}
	return out
}

// routeSignature reduces one helper snapshot to "dst/mask|iface" -> gateway.
func routeSignature(t *testing.T, data map[string]any) map[string]string {
	t.Helper()
	list, ok := jsonObjectList(data, "routes")
	if !ok {
		t.Fatalf("host snapshot carries no route list")
	}
	out := make(map[string]string, len(list))
	for _, route := range list {
		key := fmt.Sprintf("%v/%v|%v", route["destination"], route["mask"], route["iface"])
		gateway, _ := route["gateway"].(string)
		out[key] = gateway
	}
	return out
}

func diffSignatures(before, after map[string]string) (added, removed, changed []string) {
	for key, value := range after {
		previous, ok := before[key]
		if !ok {
			added = append(added, key)
			continue
		}
		if previous != value {
			changed = append(changed, fmt.Sprintf("%s: %q -> %q", key, previous, value))
		}
	}
	for key := range before {
		if _, ok := after[key]; !ok {
			removed = append(removed, key)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return added, removed, changed
}

func findRoute(t *testing.T, facts map[string]any, destination, mask string) (map[string]any, bool) {
	t.Helper()
	list, ok := jsonObjectList(facts, "routes")
	if !ok {
		return nil, false
	}
	for _, route := range list {
		if route["destination"] == destination && route["mask"] == mask {
			return route, true
		}
	}
	return nil, false
}

func routeTable(facts map[string]any) []string {
	list, ok := jsonObjectList(facts, "routes")
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, route := range list {
		out = append(out, fmt.Sprintf("%v/%v|%v", route["destination"], route["mask"], route["iface"]))
	}
	sort.Strings(out)
	return out
}

// authKeywordEvidence looks for the SDK's own rejection diagnostics in the
// child's stderr. It is recorded as evidence, never asserted on: the contractual
// negative proof is the public DialContext error plus zero peer delivery.
func authKeywordEvidence(stderr string) []string {
	keywords := []string{"handshake", "auth", "psk", "PSK", "reject", "decrypt", "admission", "token", "link"}
	out := []string{}
	for _, line := range strings.Split(stderr, "\n") {
		lower := strings.ToLower(line)
		for _, keyword := range keywords {
			if strings.Contains(lower, strings.ToLower(keyword)) {
				out = append(out, strings.TrimSpace(line))
				break
			}
		}
		if len(out) >= 5 {
			break
		}
	}
	return out
}

func randomToken(t *testing.T) string {
	t.Helper()
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate token: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(secret)
}

func writeSecret(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatalf("write secret %s: %v", path, err)
	}
}

func generateMarker(t *testing.T) []byte {
	t.Helper()
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("generate marker: %v", err)
	}
	return []byte("TUN-ACCEPT-MARKER-" + hex.EncodeToString(random) + "-PAYLOAD")
}

func hashString(data []byte) string { return shortHash(fmt.Sprintf("%x", sha256.Sum256(data))) }

func shortHash(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:16]
}

// sourceDigests records the SHA-256 of every test-authored source file, so the
// evidence is bound to an exact revision of the acceptance itself.
func sourceDigests(t *testing.T, moduleRoot string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, pattern := range []string{"examples/tun-agent/*.go", "tests/tun_acceptance/*.go"} {
		matches, err := filepath.Glob(filepath.Join(moduleRoot, pattern))
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		for _, path := range matches {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			rel, _ := filepath.Rel(moduleRoot, path)
			out[rel] = fmt.Sprintf("%x", sha256.Sum256(raw))
		}
	}
	return out
}

func writeSummary(t *testing.T, h *harness, summary map[string]any) {
	t.Helper()
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatalf("encode summary: %v", err)
	}
	path := filepath.Join(h.artifactDir, "summary.json")
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatalf("write summary %s: %v", path, err)
	}
	h.logf("artifact summary: %s", path)
	h.logf("source digests:")
	for name, digest := range summary["source_sha256"].(map[string]string) {
		h.logf("  %s  %s", digest, name)
	}
}
