package network_runtime_test

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The three-process acceptance: a real source process, a real relay process and
// a real target process, each an independent OS process with its own 0700
// identity/state directory, its own fixed VirtualIP and a real loopback TCP
// carrier. The source drives an 80 KiB echo across A -> R -> B through the SDK
// data plane; the helper never frames application bytes itself.
const (
	chainName       = "process-chain"
	chainCIDR       = "10.249.0.0/24"
	chainToken      = "process-chain-token-0123456789"
	chainSourceIP   = "10.249.0.1"
	chainRelayIP    = "10.249.0.2"
	chainTargetIP   = "10.249.0.3"
	chainTargetPort = 19191
	chainBytes      = 80 << 10
)

func freeChainPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// buildChainHelper compiles the real helper binary once for the test.
func buildChainHelper(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	// Windows requires the .exe suffix: exec looks the name up verbatim and will
	// not find an extensionless file, even though `go build -o` would happily
	// produce one.
	name := "network-runtime-helper"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-o", binary, "./examples/network-runtime")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}
	return binary
}

type chainNode struct {
	lines <-chan string
}

// startChainNode starts one real helper process. It returns a channel of its
// stdout lines so the test can wait for a readiness or result marker without
// blocking past its deadline.
func startChainNode(t *testing.T, binary, role, listen, upstream, fixedIP string, extra ...string) *chainNode {
	t.Helper()
	args := []string{
		"-role", role,
		"-listen", listen,
		"-fixed-ip", fixedIP,
		"-name", chainName,
		"-cidr", chainCIDR,
		"-token", chainToken,
	}
	if upstream != "" {
		args = append(args, "-upstream", upstream)
	}
	if role == "target" || role == "source" {
		args = append(args, "-target-ip", chainTargetIP, "-target-port", fmt.Sprint(chainTargetPort))
	}
	args = append(args, extra...)

	cmd := exec.Command(binary, args...)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s helper: %v", role, err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_, _ = cmd.Process.Wait()
	})

	lines := make(chan string, 32)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	return &chainNode{lines: lines}
}

// waitLine waits for a stdout line with the given prefix.
func (n *chainNode) waitLine(t *testing.T, prefix string, timeout time.Duration) string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-n.lines:
			if !ok {
				t.Fatalf("helper exited before printing %q", prefix)
			}
			if strings.HasPrefix(strings.TrimSpace(line), prefix) {
				return strings.TrimSpace(line)
			}
		case <-deadline:
			t.Fatalf("helper never printed %q within %s", prefix, timeout)
		}
	}
}

func chainExpectedHash() string {
	payload := make([]byte, chainBytes)
	for i := range payload {
		payload[i] = byte((i*13 + 7) % 251)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// TestProcessChainRelayEchoOver64KiB boots three independent OS processes and
// proves an 80 KiB echo traverses A -> R -> B with no mock carrier and no
// application-level framing.
func TestProcessChainRelayEchoOver64KiB(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns three real OS processes")
	}
	binary := buildChainHelper(t)
	base := t.TempDir()

	targetCarrier := freeChainPort(t)
	relayCarrier := freeChainPort(t)

	target := startChainNode(t, binary, "target",
		fmt.Sprintf("tcp://127.0.0.1:%d", targetCarrier), "",
		chainTargetIP, filepath.Join(base, "target-state"))
	target.waitLine(t, "READY", 20*time.Second)

	relay := startChainNode(t, binary, "relay",
		fmt.Sprintf("tcp://127.0.0.1:%d", relayCarrier),
		fmt.Sprintf("tcp://127.0.0.1:%d", targetCarrier),
		chainRelayIP, filepath.Join(base, "relay-state"))
	relay.waitLine(t, "READY", 20*time.Second)

	source := startChainNode(t, binary, "source",
		fmt.Sprintf("tcp://127.0.0.1:%d", freeChainPort(t)),
		fmt.Sprintf("tcp://127.0.0.1:%d", relayCarrier),
		chainSourceIP, filepath.Join(base, "source-state"),
		"-bytes", fmt.Sprint(chainBytes), "-dial-timeout", "90s")

	line := source.waitLine(t, "PROCESS-CHAIN-OK", 120*time.Second)
	want := "PROCESS-CHAIN-OK " + chainExpectedHash()
	if line != want {
		t.Fatalf("source result = %q; want %q", line, want)
	}
}
