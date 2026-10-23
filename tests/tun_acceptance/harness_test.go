//go:build linux

// Package tun_acceptance holds the native Linux TUN end-to-end acceptance of
// the public simpletier Agent SDK. Every assertion in this package is made
// against native kernel state: real network namespaces, a real veth carrier, a
// real TUN device opened by the SDK, and real kernel ICMP/UDP/TCP sockets.
//
// Nothing in this package reuses a test relay, a length-framed tunnel or any
// other stand-in data path: the only carrier IO is the SDK's own encrypted
// link, and the only device IO is the SDK's own packet device.
package tun_acceptance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// eventRecord mirrors one JSON line emitted by the examples/tun-agent helper.
type eventRecord struct {
	Event    string         `json:"event"`
	Role     string         `json:"role"`
	Stage    string         `json:"stage"`
	PID      int            `json:"pid"`
	Error    string         `json:"error"`
	ErrField string         `json:"error_field"`
	ErrType  string         `json:"error_type"`
	Data     map[string]any `json:"data"`
}

// lockedBuffer is a bytes.Buffer that tolerates concurrent writer goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// child is one spawned helper process plus every observation it produced.
type child struct {
	t    *testing.T
	role string
	cmd  *exec.Cmd

	stdin io.WriteCloser
	out   lockedBuffer
	errb  lockedBuffer

	mu       sync.Mutex
	events   []eventRecord
	exited   bool
	exitErr  error
	exitCode int
	done     chan struct{}
}

// harness owns the built helper, the artifact directory and the running
// children of one acceptance run.
type harness struct {
	t           *testing.T
	moduleRoot  string
	helperPath  string
	artifactDir string
	runID       string
	ctx         context.Context
	cancel      context.CancelFunc

	mu       sync.Mutex
	children []*child
	logFile  *os.File
	logMu    sync.Mutex
}

// newHarness locates the module root, compiles the helper once, and prepares a
// per-run artifact directory inside tests/tun_acceptance/artifacts.
func newHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getuid() != 0 {
		t.Fatalf("the native TUN acceptance needs uid 0 (the capability worker confirmed root with full CAP_SYS_ADMIN/CAP_NET_ADMIN/CAP_NET_RAW); running as uid %d", os.Getuid())
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Fatalf("/dev/net/tun is required for the native TUN acceptance: %v", err)
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Fatalf("the iproute2 `ip` command is required to build the test-owned veth carrier: %v", err)
	}
	root := moduleRoot(t)
	runID := time.Now().UTC().Format("20060102T150405Z")
	artifactDir := filepath.Join(root, "tests", "tun_acceptance", "artifacts", runID)
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		t.Fatalf("create artifact directory %s: %v", artifactDir, err)
	}
	binDir := t.TempDir()
	helperPath := filepath.Join(binDir, "tun-agent")
	buildArgs := []string{"build"}
	if raceEnabled {
		// Instrument the helper too, so the SDK in the child processes is
		// covered by the race detector exactly like the parent test.
		buildArgs = append(buildArgs, "-race")
	}
	buildArgs = append(buildArgs, "-o", helperPath, "./examples/tun-agent")
	build := exec.Command("go", buildArgs...)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the tun-agent helper (%v): %v\n%s", buildArgs, err, out)
	}
	logFile, err := os.Create(filepath.Join(artifactDir, "run.log"))
	if err != nil {
		t.Fatalf("create run log: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{
		t:           t,
		moduleRoot:  root,
		helperPath:  helperPath,
		artifactDir: artifactDir,
		runID:       runID,
		ctx:         ctx,
		cancel:      cancel,
		logFile:     logFile,
	}
	t.Cleanup(func() {
		h.cancel()
		for _, c := range h.children {
			c.kill()
		}
		_ = logFile.Close()
	})
	return h
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("cannot locate the module root above %s", dir)
		}
		dir = parent
	}
}

func (h *harness) logf(format string, args ...any) {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	line := fmt.Sprintf(format, args...)
	h.t.Log(line)
	if h.logFile != nil {
		fmt.Fprintln(h.logFile, line)
	}
}

// spawn starts one helper process. newNetns puts the child into a fresh network
// and mount namespace, which is how the two peers get genuinely distinct
// network namespaces without mutating the host.
func (h *harness) spawn(role string, newNetns bool, args ...string) *child {
	h.t.Helper()
	cmd := exec.CommandContext(h.ctx, h.helperPath, args...)
	cmd.Dir = h.moduleRoot
	cmd.Env = os.Environ()
	if newNetns {
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		h.t.Fatalf("stdin pipe for %s: %v", role, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		h.t.Fatalf("stdout pipe for %s: %v", role, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		h.t.Fatalf("stderr pipe for %s: %v", role, err)
	}
	c := &child{t: h.t, role: role, cmd: cmd, stdin: stdin, done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		h.t.Fatalf("start %s helper: %v", role, err)
	}
	h.mu.Lock()
	h.children = append(h.children, c)
	h.mu.Unlock()
	h.logf("spawned %s pid=%d netns=%v args=%s", role, cmd.Process.Pid, newNetns, strings.Join(args, " "))

	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
		for scanner.Scan() {
			line := scanner.Text()
			c.out.Write([]byte(line + "\n"))
			var ev eventRecord
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				c.mu.Lock()
				c.events = append(c.events, eventRecord{Event: "unparsable", Error: line})
				c.mu.Unlock()
				continue
			}
			c.mu.Lock()
			c.events = append(c.events, ev)
			c.mu.Unlock()
		}
	}()
	stderrFile, fileErr := os.Create(filepath.Join(h.artifactDir, role+".stderr.log"))
	go func() {
		writer := io.Writer(&c.errb)
		if fileErr == nil {
			writer = io.MultiWriter(&c.errb, stderrFile)
		}
		_, _ = io.Copy(writer, stderr)
		if fileErr == nil {
			_ = stderrFile.Close()
		}
	}()
	go func() {
		err := cmd.Wait()
		c.mu.Lock()
		c.exited = true
		c.exitErr = err
		if cmd.ProcessState != nil {
			c.exitCode = cmd.ProcessState.ExitCode()
		}
		c.mu.Unlock()
		if fileErr == nil {
			_ = stderrFile.Close()
		}
		_ = os.WriteFile(filepath.Join(h.artifactDir, role+".stdout.log"), []byte(c.out.String()), 0o644)
		close(c.done)
	}()
	return c
}

func (c *child) pid() int {
	if c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}

func (c *child) send(command string) {
	c.t.Helper()
	if _, err := io.WriteString(c.stdin, command+"\n"); err != nil {
		c.t.Fatalf("send %q to %s: %v", command, c.role, err)
	}
}

func (c *child) kill() {
	c.mu.Lock()
	exited := c.exited
	c.mu.Unlock()
	if exited || c.cmd.Process == nil {
		return
	}
	_ = c.cmd.Process.Kill()
}

// waitEvent waits for the next named event at or after index from. A helper
// `error` event fails the wait immediately with the exact SDK error, its field
// and its stage, so a mid-write SDK defect is reported instead of hidden.
func (c *child) waitEvent(name string, from int, timeout time.Duration) (eventRecord, int, error) {
	deadline := time.Now().Add(timeout)
	for {
		c.mu.Lock()
		for index := from; index < len(c.events); index++ {
			ev := c.events[index]
			if ev.Event == name {
				c.mu.Unlock()
				return ev, index + 1, nil
			}
			if ev.Event == "unparsable" {
				stderr := tailString(c.errb.String(), 2000)
				c.mu.Unlock()
				return eventRecord{}, 0, fmt.Errorf("child %s wrote an unparsable stdout line %q\nstderr:\n%s", c.role, ev.Error, stderr)
			}
			if ev.Event == "error" {
				stderr := tailString(c.errb.String(), 4000)
				c.mu.Unlock()
				return eventRecord{}, 0, fmt.Errorf("child %s failed at stage %q: %s (error_field=%q error_type=%q)\nstderr:\n%s",
					c.role, ev.Stage, ev.Error, ev.ErrField, ev.ErrType, stderr)
			}
		}
		exited := c.exited
		exitErr := c.exitErr
		code := c.exitCode
		stderr := tailString(c.errb.String(), 4000)
		c.mu.Unlock()
		if exited {
			return eventRecord{}, 0, fmt.Errorf("child %s exited (code=%d err=%v) before emitting %q\nstderr:\n%s", c.role, code, exitErr, name, stderr)
		}
		if time.Now().After(deadline) {
			return eventRecord{}, 0, fmt.Errorf("child %s did not emit %q within %s\nstderr:\n%s", c.role, name, timeout, stderr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (c *child) mustEvent(name string, from int, timeout time.Duration) (eventRecord, int) {
	c.t.Helper()
	ev, next, err := c.waitEvent(name, from, timeout)
	if err != nil {
		c.t.Fatalf("%v", err)
	}
	return ev, next
}

func (c *child) waitExit(timeout time.Duration) error {
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.exitErr
	case <-time.After(timeout):
		stderr := tailString(c.errb.String(), 4000)
		return fmt.Errorf("child %s did not exit within %s\nstderr:\n%s", c.role, timeout, stderr)
	}
}

func (c *child) exitStatus() (int, error, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exitCode, c.exitErr, c.exited
}

func (c *child) stderrText() string { return c.errb.String() }

func (c *child) eventNames() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := make([]string, 0, len(c.events))
	for _, ev := range c.events {
		names = append(names, ev.Event)
	}
	return names
}

// runHelperOnce runs the helper in the host namespace and returns its snapshot.
func (h *harness) runHelperOnce(args ...string) (eventRecord, error) {
	cmd := exec.Command(h.helperPath, args...)
	cmd.Dir = h.moduleRoot
	out, err := cmd.Output()
	if err != nil {
		return eventRecord{}, fmt.Errorf("helper %s: %w", strings.Join(args, " "), err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var ev eventRecord
		if jsonErr := json.Unmarshal([]byte(line), &ev); jsonErr != nil {
			continue
		}
		if ev.Event == "helper-snapshot" {
			return ev, nil
		}
	}
	return eventRecord{}, fmt.Errorf("helper %s produced no snapshot", strings.Join(args, " "))
}

func tailString(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return "..." + text[len(text)-limit:]
}

// assertionRecorder collects named pass/fail records so the artifact carries the
// full evidence table, not just the final verdict.
type assertionRecorder struct {
	mu      sync.Mutex
	records []assertionRecord
	t       *testing.T
}

type assertionRecord struct {
	Name    string `json:"name"`
	Pass    bool   `json:"pass"`
	Skipped bool   `json:"skipped,omitempty"`
	Detail  string `json:"detail"`
}

func (a *assertionRecorder) ok(name string, condition bool, format string, args ...any) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	detail := fmt.Sprintf(format, args...)
	a.records = append(a.records, assertionRecord{Name: name, Pass: condition, Detail: detail})
	if !condition {
		a.t.Errorf("assertion %s failed: %s", name, detail)
	}
	return condition
}

// skip records an assertion that did not apply in this environment. It is a
// distinct outcome from passing: the report says so, rather than counting an
// unexercised check as evidence.
func (a *assertionRecorder) skip(name string, format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, assertionRecord{Name: name, Skipped: true, Detail: fmt.Sprintf(format, args...)})
	a.t.Logf("assertion %s skipped: %s", name, fmt.Sprintf(format, args...))
}

func (a *assertionRecorder) fatal(name string, condition bool, format string, args ...any) {
	a.mu.Lock()
	detail := fmt.Sprintf(format, args...)
	a.records = append(a.records, assertionRecord{Name: name, Pass: condition, Detail: detail})
	a.mu.Unlock()
	if !condition {
		a.t.Fatalf("assertion %s failed: %s", name, detail)
	}
}

func (a *assertionRecorder) snapshot() []assertionRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]assertionRecord, len(a.records))
	copy(out, a.records)
	return out
}

// JSON navigation helpers over the decoded event payloads.

func navigate(data map[string]any, path ...string) (any, bool) {
	var current any = data
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[key]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func jsonNumber(data map[string]any, path ...string) (float64, bool) {
	value, ok := navigate(data, path...)
	if !ok {
		return 0, false
	}
	number, ok := value.(float64)
	return number, ok
}

func jsonString(data map[string]any, path ...string) (string, bool) {
	value, ok := navigate(data, path...)
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func jsonBool(data map[string]any, path ...string) (bool, bool) {
	value, ok := navigate(data, path...)
	if !ok {
		return false, false
	}
	flag, ok := value.(bool)
	return flag, ok
}

func jsonSlice(data map[string]any, path ...string) ([]any, bool) {
	value, ok := navigate(data, path...)
	if !ok {
		return nil, false
	}
	items, ok := value.([]any)
	return items, ok
}

func jsonObject(data map[string]any, path ...string) (map[string]any, bool) {
	value, ok := navigate(data, path...)
	if !ok {
		return nil, false
	}
	object, ok := value.(map[string]any)
	return object, ok
}

func jsonObjectList(data map[string]any, path ...string) ([]map[string]any, bool) {
	value, ok := navigate(data, path...)
	if !ok {
		return nil, false
	}
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		out = append(out, object)
	}
	return out, true
}

func errIs(err error, target error) bool { return errors.Is(err, target) }
