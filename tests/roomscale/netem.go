package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// netemDelay applies a one-way delay and jitter to loopback traffic bound to or from
// one TCP port, using the kernel's netem discipline.
//
// This replaces a userspace proxy. A proxy has to decide what a "chunk" is, and any
// decision it makes is wrong somewhere: delaying per read call makes a handshake that
// arrives in ten small segments pay ten delays, so a 3-round-trip handshake measured as
// 8 round trips. The kernel delays at the packet layer, which is what a real slow path
// does, and it costs no userspace scheduling.
//
// Ports are matched both as destination and as source so a round trip crosses the delay
// twice, once each way. Filtering by port rather than delaying all of loopback keeps the
// relay's own traffic and every directly-connected peer unaffected.
type netemDelay struct {
	iface  string
	port   int
	active bool
}

// applyNetemDelay installs the qdisc and filters. It needs root; a caller that cannot
// run tc gets an error rather than a silently undelayed run.
func applyNetemDelay(iface string, port int, delay, jitter string) (*netemDelay, error) {
	n := &netemDelay{iface: iface, port: port}
	cmds := [][]string{
		{"qdisc", "add", "dev", iface, "root", "handle", "1:", "prio"},
		{"qdisc", "add", "dev", iface, "parent", "1:3", "handle", "30:", "netem",
			"delay", delay, jitter},
		{"filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1",
			"u32", "match", "ip", "dport", fmt.Sprint(port), "0xffff", "flowid", "1:3"},
		{"filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1",
			"u32", "match", "ip", "sport", fmt.Sprint(port), "0xffff", "flowid", "1:3"},
	}
	for _, args := range cmds {
		if out, err := exec.Command("tc", args...).CombinedOutput(); err != nil {
			_ = n.remove()
			return nil, fmt.Errorf("tc %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	n.active = true
	return n, nil
}

// remove deletes the qdisc, which takes its filters with it. It is idempotent.
func (n *netemDelay) remove() error {
	if n == nil || !n.active {
		return nil
	}
	n.active = false
	out, err := exec.Command("tc", "qdisc", "del", "dev", n.iface, "root").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "Cannot find") {
		return fmt.Errorf("tc qdisc del: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// netemIface is the loopback device a same-host benchmark crosses.
const netemIface = "lo"

// slowPortOffset shifts the delayed port away from the plain one so one relay process
// can accept carriers on both.
const slowPortOffset = 1

// slowPortAddr derives the delayed ingress address from the plain relay address.
func slowPortAddr(relayAddr string) (string, int, error) {
	host, portText, err := net.SplitHostPort(relayAddr)
	if err != nil {
		return "", 0, fmt.Errorf("relay address %q: %w", relayAddr, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, fmt.Errorf("relay port %q: %w", portText, err)
	}
	slow := port + slowPortOffset
	return net.JoinHostPort(host, strconv.Itoa(slow)), slow, nil
}
