//go:build linux

// Command tun-agent is a test-only process helper for the native Linux TUN
// acceptance suite in tests/tun_acceptance. It is intentionally NOT a library:
// it exposes no Go API, it is never imported, and it reads no environment
// variable for configuration. Every input arrives as an explicit flag and every
// observation leaves as exactly one JSON line on stdout, so the parent test can
// assert on native kernel facts without parsing human text.
//
// Roles
//
//	source  owns the veth pair inside its own network namespace, moves the peer
//	        end into the target namespace by pid, starts an SDK Agent whose TUN
//	        is the only host I/O path, and drives the business probes
//	        (ICMP/UDP/TCP) through the kernel, never through an SDK flow API.
//	target  owns the carrier listener and the real OS UDP/TCP business
//	        listeners bound to its overlay VirtualIP, and captures the packets
//	        that reach its TUN interface (plaintext) and its veth end
//	        (ciphertext) with AF_PACKET.
//	helper  runs one bounded, read-only observation in the current namespace
//	        (namespace identity, interface/address/route snapshot) and exits.
//
// Nothing here ships product behavior. The single carrier IO path used by the
// acceptance is the SDK's own encrypted link: this helper contains no framing
// relay and never copies payload bytes between two sockets.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yiiilin/simpletier/pkg/simpletier"
)

// defaultTimeout bounds every role. The parent always passes an explicit,
// smaller value; the default only keeps a manually started helper finite.
const defaultTimeout = 150 * time.Second

// options is the complete, flag-only configuration of one helper run.
type options struct {
	role string

	network   string
	cidr      string
	vip       string
	peerVIP   string
	tokenFile string
	wrongFile string
	stateDir  string
	logLevel  string
	relay     bool

	carrierListen   string
	carrierUpstream string
	carrierLocal    string
	carrierPeer     string
	carrierLocalIf  string
	carrierPeerIf   string
	peerPID         int

	udpPort int
	tcpPort int

	markerHex string

	helperOp   string
	watchIface string

	timeout time.Duration
}

// event is one machine-readable observation. It never carries the network
// token, a PSK, or raw payload bytes: only counters, hashes and identities.
type event struct {
	Event    string         `json:"event"`
	Role     string         `json:"role"`
	Stage    string         `json:"stage,omitempty"`
	PID      int            `json:"pid,omitempty"`
	NetNS    uint64         `json:"netns_inode,omitempty"`
	HostNS   uint64         `json:"host_netns_inode,omitempty"`
	Error    string         `json:"error,omitempty"`
	ErrField string         `json:"error_field,omitempty"`
	ErrType  string         `json:"error_type,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

var (
	emitMu  sync.Mutex
	emitEnc = json.NewEncoder(os.Stdout)
)

// emit writes one JSON line. It is safe for concurrent use: several role
// goroutines report progress at the same time.
func emit(ev event) {
	if ev.PID == 0 {
		ev.PID = os.Getpid()
	}
	emitMu.Lock()
	defer emitMu.Unlock()
	if err := emitEnc.Encode(ev); err != nil {
		fmt.Fprintf(os.Stderr, "tun-agent: cannot write event: %v\n", err)
	}
}

// note writes a human diagnostic on stderr. Diagnostics never contain secrets.
func note(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "tun-agent: "+format+"\n", args...)
}

func main() {
	o := &options{}
	fs := flag.NewFlagSet("tun-agent", flag.ContinueOnError)
	fs.StringVar(&o.role, "role", "", "source | target | helper")
	fs.StringVar(&o.network, "network", "tun-acceptance", "overlay network name")
	fs.StringVar(&o.cidr, "cidr", "", "canonical overlay IPv4 CIDR")
	fs.StringVar(&o.vip, "vip", "", "own overlay VirtualIP")
	fs.StringVar(&o.peerVIP, "peer-vip", "", "the other side's overlay VirtualIP")
	fs.StringVar(&o.tokenFile, "token-file", "", "file holding the shared network token")
	fs.StringVar(&o.wrongFile, "wrong-token-file", "", "file holding a wrong token for the negative phase")
	fs.StringVar(&o.stateDir, "state-dir", "", "per-child SDK state directory")
	fs.StringVar(&o.logLevel, "log-level", "warn", "SDK log level: debug|info|warn|error")
	fs.BoolVar(&o.relay, "relay", true, "advertise the relay capability")
	fs.StringVar(&o.carrierListen, "carrier-listen", "", "target: tcp://addr:port the SDK binds")
	fs.StringVar(&o.carrierUpstream, "carrier-upstream", "", "source: tcp://addr:port the SDK dials")
	fs.StringVar(&o.carrierLocal, "carrier-local", "", "own carrier address in CIDR form, e.g. 172.30.9.1/30")
	fs.StringVar(&o.carrierPeer, "carrier-peer", "", "peer carrier address in CIDR form")
	fs.StringVar(&o.carrierLocalIf, "carrier-local-if", "stvA0", "owned veth end name in this namespace")
	fs.StringVar(&o.carrierPeerIf, "carrier-peer-if", "stvB0", "owned veth end name moved to the peer namespace")
	fs.IntVar(&o.peerPID, "peer-pid", 0, "source: pid of the target namespace owner")
	fs.IntVar(&o.udpPort, "udp-port", 0, "target: UDP business port on the overlay VirtualIP")
	fs.IntVar(&o.tcpPort, "tcp-port", 0, "target: TCP business port on the overlay VirtualIP")
	fs.StringVar(&o.markerHex, "marker-hex", "", "shared high-entropy payload marker (hex) for plaintext sniffing")
	fs.StringVar(&o.helperOp, "helper-op", "snapshot", "helper: snapshot | netns")
	fs.StringVar(&o.watchIface, "watch-iface", "", "helper: pre-existing host interface that must stay untouched")
	fs.DurationVar(&o.timeout, "timeout", defaultTimeout, "hard upper bound for this helper run")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tun-agent:", err)
		os.Exit(2)
	}
	if o.timeout <= 0 {
		o.timeout = defaultTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	// Hard watchdog: a role that blocks past its bound must not hang the parent.
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(o.timeout + 10*time.Second):
			emit(event{Event: "error", Role: o.role, Stage: "watchdog", Error: "helper exceeded its bounded lifetime"})
			os.Exit(1)
		}
	}()

	if err := runRole(ctx, o); err != nil {
		emit(event{
			Event:    "error",
			Role:     o.role,
			Stage:    stageOf(err),
			Error:    err.Error(),
			ErrField: errorField(err),
			ErrType:  errorType(err),
		})
		os.Exit(1)
	}
	emit(event{Event: "exit", Role: o.role, Data: map[string]any{"ok": true}})
}

// stageError tags an error with the phase that produced it so the parent can
// report the exact failing stage instead of a bare string.
type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return e.err.Error() }
func (e *stageError) Unwrap() error { return e.err }

func stagef(stage, format string, args ...any) error {
	return &stageError{stage: stage, err: fmt.Errorf(format, args...)}
}

func stageOf(err error) string {
	var se *stageError
	if errors.As(err, &se) {
		return se.stage
	}
	return ""
}

// errorField extracts the configuration field name that invalidConfig prefixes,
// so a mid-write SDK failure is reported with the exact contract field.
func errorField(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if !errors.Is(err, simpletier.ErrInvalidConfig) {
		return ""
	}
	if index := strings.Index(msg, ": "); index > 0 {
		return msg[:index]
	}
	return ""
}

// errorType classifies an error against the public SDK sentinels and the
// kernel errnos so the parent can distinguish a real SDK defect from an
// environment failure.
func errorType(err error) string {
	if err == nil {
		return ""
	}
	for _, entry := range []struct {
		name string
		err  error
	}{
		{"invalid_config", simpletier.ErrInvalidConfig},
		{"no_route", simpletier.ErrNoRoute},
		{"link_down", simpletier.ErrLinkDown},
		{"closed", simpletier.ErrClosed},
		{"resource", simpletier.ErrResource},
		{"address_conflict", simpletier.ErrAddressConflict},
		{"permission_denied", simpletier.ErrPermissionDenied},
		{"unsupported", simpletier.ErrUnsupported},
		{"busy", simpletier.ErrBusy},
		{"missing_control_dependency", simpletier.ErrMissingControlDependency},
	} {
		if errors.Is(err, entry.err) {
			return entry.name
		}
	}
	return "runtime"
}

func runRole(ctx context.Context, o *options) error {
	switch o.role {
	case "source":
		return runSource(ctx, o)
	case "target":
		return runTarget(ctx, o)
	case "helper":
		return runHelper(ctx, o)
	case "":
		return stagef("config", "invalid role %q: role must be source, target or helper", o.role)
	default:
		return stagef("config", "invalid role %q: role must be source, target or helper", o.role)
	}
}

// commander delivers the newline-separated commands the parent writes on the
// child's stdin. It is how readiness and phase transitions are coordinated
// without a shared library or a control socket.
type commander struct {
	role string
	ch   <-chan string
}

func newCommander(ctx context.Context, role string) *commander {
	ch := make(chan string, 8)
	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 0, 4096), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			select {
			case ch <- line:
			case <-ctx.Done():
				return
			}
		}
	}()
	return &commander{role: role, ch: ch}
}

// next returns the next command, or a bounded error when the parent closes
// stdin or the run deadline expires.
func (c *commander) next(ctx context.Context) (string, error) {
	select {
	case cmd, ok := <-c.ch:
		if !ok {
			return "", stagef("ipc", "%s: stdin closed before the parent sent the next command", c.role)
		}
		return cmd, nil
	case <-ctx.Done():
		return "", stagef("ipc", "%s: %w while waiting for the next parent command", c.role, ctx.Err())
	}
}

// expect consumes commands until want arrives, failing on an unexpected one.
func (c *commander) expect(ctx context.Context, want string) error {
	cmd, err := c.next(ctx)
	if err != nil {
		return err
	}
	if cmd != want {
		return stagef("ipc", "%s: expected command %q, received %q", c.role, want, cmd)
	}
	return nil
}

func readToken(path string, what string) (string, error) {
	if path == "" {
		return "", stagef("config", "%s file is required", what)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", stagef("config", "read %s: %w", what, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", stagef("config", "%s file is empty", what)
	}
	return token, nil
}

func boolPtr(v bool) *bool { return &v }

// resolveMarker uses the parent-provided payload marker when present, so the
// responder side can search for exactly the plaintext the initiator sent.
func resolveMarker(o *options) ([]byte, error) {
	if o.markerHex != "" {
		return markerFromHex(o.markerHex)
	}
	return newMarker()
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// counterSnapshot is the JSON shape every role reports for one interface.
type counterSnapshot struct {
	Name      string         `json:"name"`
	RxBytes   uint64         `json:"rx_bytes"`
	TxBytes   uint64         `json:"tx_bytes"`
	RxPackets uint64         `json:"rx_packets"`
	TxPackets uint64         `json:"tx_packets"`
	Source    string         `json:"source"`
	Sysfs     *sysfsCounters `json:"sysfs,omitempty"`
}

// counterDelta records how one interface moved across one phase.
type counterDelta struct {
	Name         string `json:"name"`
	RxBytes      int64  `json:"rx_bytes_delta"`
	TxBytes      int64  `json:"tx_bytes_delta"`
	RxPackets    int64  `json:"rx_packets_delta"`
	TxPackets    int64  `json:"tx_packets_delta"`
	Sha256Before string `json:"sha256_before"`
	Sha256After  string `json:"sha256_after"`
	Source       string `json:"source"`
}

func diffCounters(before, after map[string]counterSnapshot) map[string]counterDelta {
	out := make(map[string]counterDelta, len(after))
	for name, a := range after {
		b, ok := before[name]
		if !ok {
			b = counterSnapshot{Name: name}
		}
		out[name] = counterDelta{
			Name:         name,
			RxBytes:      int64(a.RxBytes) - int64(b.RxBytes),
			TxBytes:      int64(a.TxBytes) - int64(b.TxBytes),
			RxPackets:    int64(a.RxPackets) - int64(b.RxPackets),
			TxPackets:    int64(a.TxPackets) - int64(b.TxPackets),
			Sha256Before: counterHash(b),
			Sha256After:  counterHash(a),
			Source:       a.Source,
		}
	}
	return out
}

func counterHash(c counterSnapshot) string {
	return hashHex([]byte(fmt.Sprintf("%s|%d|%d|%d|%d", c.Name, c.RxBytes, c.TxBytes, c.RxPackets, c.TxPackets)))
}
