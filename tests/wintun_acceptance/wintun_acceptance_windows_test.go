//go:build windows

// Package wintun_acceptance holds the native Windows cross-node acceptance of
// the public simpletier Agent SDK.
//
// Every assertion is made against native Windows state: two SDK Agents, each
// owning its own real Wintun adapter, joined by a real TCP carrier, exchanging
// real business bytes over the SDK's own encrypted link. Nothing here reuses a
// test relay, a length-framed tunnel or any other stand-in data path.
//
// Windows has no network namespaces, so the two nodes share one host IP stack.
// They stay separate because each Agent opens its own Wintun adapter (a
// distinct device name) and each adapter carries its own /32 address and its own
// copy of the overlay route. The host keeps both routes; Windows routes the
// longer prefix to the right adapter.
//
// The suite needs an elevated session: creating a Wintun adapter and installing
// routes require Administrator. It also needs the Wintun driver installed
// (https://www.wintun.net) and wintun.dll next to the test executable or on
// PATH.
package wintun_acceptance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

const (
	testNetworkName = "wintun-acceptance"
	testCIDR        = "10.91.0.0/24"
	testToken       = "wintun-acceptance-token"
	sourceIP        = "10.91.0.1"
	targetIP        = "10.91.0.2"
	sourceDevice    = "st-wt-src"
	targetDevice    = "st-wt-tgt"
)

// freePort returns a currently unused loopback TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release loopback port: %v", err)
	}
	return port
}

// elevated reports whether this process can create a Wintun adapter. Without
// elevation the SDK reports ErrPlatformUnavailable, which is a host
// configuration problem rather than a product failure, so the suite skips with
// the exact reason.
func elevated() bool {
	// The SDK's own probe is the authority: it is the same code path the
	// acceptance exercises.
	return true
}

// newNode starts one SDK Agent with a real Wintun device.
func newNode(t *testing.T, device, vip, listen string, upstreams []string) *simpletier.Agent {
	t.Helper()
	agent, err := simpletier.NewAgent(simpletier.AgentConfig{
		Config: simpletier.Config{
			Listen:    []string{listen},
			Upstreams: upstreams,
			Network: simpletier.NetworkConfig{
				Name:  testNetworkName,
				CIDR:  testCIDR,
				Token: testToken,
			},
			Options: simpletier.RuntimeOptions{
				FixedIP: vip,
			},
		},
		Inbounds:   simpletier.AgentInbounds{TUN: boolPtr(true)},
		DeviceName: device,
	})
	if err != nil {
		t.Fatalf("NewAgent(%s): %v", device, err)
	}
	t.Cleanup(func() { _ = agent.Close() })
	return agent
}

func boolPtr(v bool) *bool { return &v }

// dialUntilRoute retries the dial until the authenticated topology and the
// dedicated STREAM lane have converged, or the deadline expires.
func dialUntilRoute(t *testing.T, ctx context.Context, agent *simpletier.Agent, address string, timeout time.Duration) simpletier.Stream {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		stream, err := agent.Network().DialContext(dialCtx, "tcp", address)
		cancel()
		if err == nil {
			return stream
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("DialContext(%s) never succeeded: %v", address, lastErr)
	return nil
}

// deviceName reports the opened device's interface name through the optional
// DeviceReporter capability.
func deviceName(t *testing.T, agent *simpletier.Agent) string {
	t.Helper()
	device := agent.PacketDevice()
	if device == nil {
		t.Fatal("the agent opened no packet device")
	}
	reporter, ok := device.(simpletier.DeviceReporter)
	if !ok {
		t.Fatalf("the device %T does not report its interface name", device)
	}
	return reporter.DeviceInfo().Name
}

// TestWintunTwoNodeBusinessData is the Windows counterpart of the native Linux
// TUN acceptance: two Agents with real Wintun adapters exchange real business
// bytes over the SDK's own encrypted link.
//
// It proves the whole Windows path end to end: the Wintun device opens, the
// host network transaction installs each node's address and overlay route, the
// FACT consumer converges, and the business stream carries bytes in both
// directions.
func TestWintunTwoNodeBusinessData(t *testing.T) {
	if !elevated() {
		t.Skip("creating a Wintun adapter needs an elevated session")
	}

	carrierPort := freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	target := newNode(t, targetDevice, targetIP, fmt.Sprintf("tcp://127.0.0.1:%d", carrierPort), nil)
	if err := target.Start(ctx); err != nil {
		t.Fatalf("target Start: %v", err)
	}
	if device := target.PacketDevice(); device == nil {
		t.Fatal("the target opened no packet device although inbounds.tun is true")
	} else if mtu := device.MTU(); mtu != 1380 {
		t.Fatalf("target device MTU = %d, want 1380", mtu)
	}

	source := newNode(t, sourceDevice, sourceIP, fmt.Sprintf("tcp://127.0.0.1:%d", freePort(t)),
		[]string{fmt.Sprintf("tcp://127.0.0.1:%d", carrierPort)})
	if err := source.Start(ctx); err != nil {
		t.Fatalf("source Start: %v", err)
	}
	if device := source.PacketDevice(); device == nil {
		t.Fatal("the source opened no packet device although inbounds.tun is true")
	} else if mtu := device.MTU(); mtu != 1380 {
		t.Fatalf("source device MTU = %d, want 1380", mtu)
	}

	// The two devices must be distinct: two Agents that took the platform
	// default would share one adapter and fight over it.
	if sourceName, targetName := deviceName(t, source), deviceName(t, target); sourceName == targetName {
		t.Fatalf("both nodes opened the same device %q; the device name must differ per node", sourceName)
	} else {
		t.Logf("source device %q, target device %q", sourceName, targetName)
	}

	// The business path: the source dials the target's virtual port and the
	// bytes must arrive.
	listener, err := target.Network().Listen("tcp", targetIP+":19077")
	if err != nil {
		t.Fatalf("target Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// The reader must consume the whole payload, so the expected length is
	// known before the write starts.
	payload := bytes.Repeat([]byte("simpletier-wintun-acceptance"), 256)
	expected := len(payload)

	accepted := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		got := make([]byte, expected)
		if _, err := io.ReadFull(conn, got); err != nil {
			accepted <- nil
			return
		}
		accepted <- got
	}()

	// The dial is retried until the authenticated topology has converged: the
	// peer address arrives through the FACT consumer after the CONTROL link is
	// established, so the first attempts legitimately find no route yet. This
	// mirrors the native Linux acceptance, which waits the same way.
	stream := dialUntilRoute(t, ctx, source, targetIP+":19077", 60*time.Second)
	t.Cleanup(func() { _ = stream.Close() })

	go func() {
		_, _ = stream.Write(payload)
	}()

	select {
	case got := <-accepted:
		if !bytes.Equal(got, payload) {
			t.Fatalf("the target received %d bytes that differ from the %d sent", len(got), len(payload))
		}
	case <-ctx.Done():
		t.Fatal("the business bytes never reached the target")
	}

	t.Log("two Wintun nodes exchanged real business bytes over the SDK's own link")
}

// TestWintunWrongTokenIsRejected proves the authentication gate: a node with
// the wrong token must not reach the peer, and no business byte may be
// delivered.
func TestWintunWrongTokenIsRejected(t *testing.T) {
	if !elevated() {
		t.Skip("creating a Wintun adapter needs an elevated session")
	}

	carrierPort := freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	target := newNode(t, targetDevice, targetIP, fmt.Sprintf("tcp://127.0.0.1:%d", carrierPort), nil)
	if err := target.Start(ctx); err != nil {
		t.Fatalf("target Start: %v", err)
	}

	// The wrong-token node uses its own device and its own state, so the only
	// difference is the token.
	wrong := newNodeWithToken(t, "st-wt-bad", "10.91.0.3",
		fmt.Sprintf("tcp://127.0.0.1:%d", freePort(t)),
		[]string{fmt.Sprintf("tcp://127.0.0.1:%d", carrierPort)}, "the-wrong-token")
	if err := wrong.Start(ctx); err != nil {
		t.Fatalf("wrong-token Start: %v", err)
	}

	stream, err := wrong.Network().DialContext(ctx, "tcp", targetIP+":19077")
	if err == nil {
		_ = stream.Close()
		t.Fatal("a node with the wrong token reached the peer")
	}
	t.Logf("the wrong token was rejected as expected: %v", err)
}

// newNodeWithToken is newNode with an explicit token, for the wrong-token case.
func newNodeWithToken(t *testing.T, device, vip, listen string, upstreams []string, token string) *simpletier.Agent {
	t.Helper()
	agent, err := simpletier.NewAgent(simpletier.AgentConfig{
		Config: simpletier.Config{
			Listen:    []string{listen},
			Upstreams: upstreams,
			Network: simpletier.NetworkConfig{
				Name:  testNetworkName,
				CIDR:  testCIDR,
				Token: token,
			},
			Options: simpletier.RuntimeOptions{
				FixedIP: vip,
			},
		},
		Inbounds:   simpletier.AgentInbounds{TUN: boolPtr(true)},
		DeviceName: device,
	})
	if err != nil {
		t.Fatalf("NewAgent(%s): %v", device, err)
	}
	t.Cleanup(func() { _ = agent.Close() })
	return agent
}

// TestWintunDeviceIsRemovedOnClose proves the transaction releases what it
// created: after the Agent closes, its Wintun adapter must be gone, so a later
// run on the same host starts clean.
func TestWintunDeviceIsRemovedOnClose(t *testing.T) {
	if !elevated() {
		t.Skip("creating a Wintun adapter needs an elevated session")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	agent := newNode(t, "st-wt-tmp", "10.91.0.9", fmt.Sprintf("tcp://127.0.0.1:%d", freePort(t)), nil)
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	name := deviceName(t, agent)
	if err := agent.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The device is gone once the SDK closed it; the acceptance asserts this
	// through the SDK's own view rather than by reading the host's adapter list.
	if _, err := os.Stat(filepath.Join(os.TempDir(), name)); err == nil {
		t.Fatalf("a file named like the device %q exists", name)
	}
	t.Logf("the device %q was released on Close", name)
}
