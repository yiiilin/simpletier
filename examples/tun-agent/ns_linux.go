//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// sysfsPrivate is true once this process mounted its own sysfs instance inside
// its private mount namespace. Only then do /sys/class/net reads describe this
// process's network namespace; otherwise they would describe the host and every
// counter taken from them would be a false proof.
var sysfsPrivate atomic.Bool

// readNetnsInode resolves the network namespace identity of one pid from
// /proc/<pid>/ns/net, for example "net:[4026532589]" -> 4026532589.
func readNetnsInode(pid int) (uint64, error) {
	path := fmt.Sprintf("/proc/%d/ns/net", pid)
	target, err := os.Readlink(path)
	if err != nil {
		return 0, fmt.Errorf("readlink %s: %w", path, err)
	}
	return parseNetnsLink(target)
}

func parseNetnsLink(target string) (uint64, error) {
	open := strings.IndexByte(target, '[')
	closeBracket := strings.IndexByte(target, ']')
	if open < 0 || closeBracket <= open {
		return 0, fmt.Errorf("unexpected namespace link %q", target)
	}
	value, err := strconv.ParseUint(target[open+1:closeBracket], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse namespace link %q: %w", target, err)
	}
	return value, nil
}

func selfNetnsInode() (uint64, error) { return readNetnsInode(os.Getpid()) }

// parentNetnsInode reports the namespace of the test process that spawned this
// helper. The parent stays in the host namespace, so this is the host identity
// the acceptance compares against.
func parentNetnsInode() (uint64, error) { return readNetnsInode(os.Getppid()) }

// bootstrapNamespace makes this process a well-behaved namespace citizen:
//   - it makes every inherited mount private, so nothing it mounts can ever
//     propagate back into the host mount namespace;
//   - it mounts a fresh sysfs inside that private namespace so /sys/class/net
//     describes this process's network namespace, not the host's;
//   - it brings the loopback interface up, because a fresh network namespace
//     starts with lo DOWN.
//
// A failing sysfs mount is reported, not fatal: the netlink counter reader
// stays authoritative and correct either way. The loopback step is fatal only
// because the negative-path assertion "business traffic never used lo" relies
// on lo existing.
func bootstrapNamespace(ctx context.Context) (map[string]any, error) {
	report := map[string]any{"sysfs_private": false, "mount_private": false, "lo_up": false}

	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		note("cannot make mounts private: %v", err)
	} else {
		report["mount_private"] = true
	}
	if err := unix.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
		note("cannot mount a namespace-local sysfs (netlink counters remain authoritative): %v", err)
	} else {
		sysfsPrivate.Store(true)
		report["sysfs_private"] = true
	}
	if err := runIP(ctx, "link", "set", "lo", "up"); err != nil {
		return report, stagef("namespace", "bring loopback up in the fresh namespace: %w", err)
	}
	report["lo_up"] = true

	netns, err := selfNetnsInode()
	if err != nil {
		return report, stagef("namespace", "%w", err)
	}
	hostNS, err := parentNetnsInode()
	if err != nil {
		return report, stagef("namespace", "%w", err)
	}
	report["netns_inode"] = netns
	report["host_netns_inode"] = hostNS
	return report, nil
}

// runIP executes one bounded `ip` command with fixed, test-owned arguments.
// There is no shell: arguments are passed directly, so no name can be
// interpreted and no host object outside the caller's namespace is reachable.
func runIP(ctx context.Context, args ...string) error {
	cmdCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// createVeth builds the carrier link entirely inside this namespace and hands
// the peer end to the target namespace by pid. Nothing here touches a host
// device, route or namespace.
func createVeth(ctx context.Context, o *options) error {
	if o.carrierLocalIf == "" || o.carrierPeerIf == "" || o.carrierLocalIf == o.carrierPeerIf {
		return stagef("veth", "carrier interface names must be two distinct non-empty owned names")
	}
	if o.carrierLocal == "" || o.carrierPeer == "" {
		return stagef("veth", "carrier-local and carrier-peer addresses are required")
	}
	if o.peerPID <= 0 {
		return stagef("veth", "peer-pid must be a positive target namespace owner pid")
	}
	if _, err := readNetnsInode(o.peerPID); err != nil {
		return stagef("veth", "target pid %d has no readable network namespace: %w", o.peerPID, err)
	}
	if err := runIP(ctx, "link", "add", o.carrierLocalIf, "type", "veth", "peer", "name", o.carrierPeerIf); err != nil {
		return stagef("veth", "create veth pair %s/%s: %w", o.carrierLocalIf, o.carrierPeerIf, err)
	}
	if err := runIP(ctx, "link", "set", o.carrierPeerIf, "netns", strconv.Itoa(o.peerPID)); err != nil {
		return stagef("veth", "move %s into target namespace pid %d: %w", o.carrierPeerIf, o.peerPID, err)
	}
	if err := runIP(ctx, "addr", "add", o.carrierLocal, "dev", o.carrierLocalIf); err != nil {
		return stagef("veth", "assign %s to %s: %w", o.carrierLocal, o.carrierLocalIf, err)
	}
	if err := runIP(ctx, "link", "set", o.carrierLocalIf, "up"); err != nil {
		return stagef("veth", "bring %s up: %w", o.carrierLocalIf, err)
	}
	return nil
}

// waitForLink waits until one interface exists in this namespace.
func waitForLink(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := net.InterfaceByName(name); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return stagef("veth", "interface %q did not appear in this namespace within %s", name, timeout)
		}
		select {
		case <-ctx.Done():
			return stagef("veth", "%w while waiting for %q", ctx.Err(), name)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// ifaceInfo is the honest per-interface view of the current namespace.
type ifaceInfo struct {
	Name     string   `json:"name"`
	Index    int      `json:"index"`
	MTU      int      `json:"mtu"`
	Flags    string   `json:"flags"`
	Addrs    []string `json:"addrs"`
	SysfsMTU int      `json:"sysfs_mtu,omitempty"`
	SysfsARP uint64   `json:"sysfs_arphrd,omitempty"`
}

func listInterfaces() ([]ifaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	out := make([]ifaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		info := ifaceInfo{
			Name:  iface.Name,
			Index: iface.Index,
			MTU:   iface.MTU,
			Flags: iface.Flags.String(),
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("addresses of %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			info.Addrs = append(info.Addrs, addr.String())
		}
		sort.Strings(info.Addrs)
		if sysfsPrivate.Load() {
			if raw, err := os.ReadFile(filepath.Join("/sys/class/net", iface.Name, "mtu")); err == nil {
				if value, convErr := strconv.Atoi(strings.TrimSpace(string(raw))); convErr == nil {
					info.SysfsMTU = value
				}
			}
			if raw, err := os.ReadFile(filepath.Join("/sys/class/net", iface.Name, "type")); err == nil {
				if value, convErr := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); convErr == nil {
					info.SysfsARP = value
				}
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func ifaceByName(name string) (ifaceInfo, error) {
	all, err := listInterfaces()
	if err != nil {
		return ifaceInfo{}, err
	}
	for _, info := range all {
		if info.Name == name {
			return info, nil
		}
	}
	return ifaceInfo{}, fmt.Errorf("interface %q is not present in this namespace", name)
}

// routeEntry is one line of the namespace-local routing table read from
// /proc/self/net/route, which always describes the calling process's network
// namespace.
type routeEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Mask        string `json:"mask"`
	Iface       string `json:"iface"`
	Flags       string `json:"flags"`
	Metric      string `json:"metric"`
}

func readRoutes() ([]routeEntry, error) {
	raw, err := os.ReadFile("/proc/self/net/route")
	if err != nil {
		return nil, fmt.Errorf("read /proc/self/net/route: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	out := make([]routeEntry, 0, len(lines))
	for index, line := range lines {
		if index == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		out = append(out, routeEntry{
			Iface:       fields[0],
			Destination: hexRouteAddress(fields[1]),
			Gateway:     hexRouteAddress(fields[2]),
			Flags:       fields[3],
			Metric:      fields[6],
			Mask:        hexRouteAddress(fields[7]),
		})
	}
	return out, nil
}

// hexRouteAddress converts the kernel's %08X little-endian rendering of one
// __be32 route field back to a dotted quad.
func hexRouteAddress(raw string) string {
	value, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(raw), "0x"), 16, 32)
	if err != nil {
		return raw
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
}

// sysfsCounters is the /sys/class/net view of one interface, available only
// when this process mounted a namespace-local sysfs.
type sysfsCounters struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
}

func readSysfsCounters(name string) (*sysfsCounters, error) {
	if !sysfsPrivate.Load() {
		return nil, fmt.Errorf("sysfs is not namespace-local in this process")
	}
	base := filepath.Join("/sys/class/net", name, "statistics")
	read := func(stat string) (uint64, error) {
		raw, err := os.ReadFile(filepath.Join(base, stat))
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	}
	out := &sysfsCounters{}
	var err error
	if out.RxBytes, err = read("rx_bytes"); err != nil {
		return nil, err
	}
	if out.TxBytes, err = read("tx_bytes"); err != nil {
		return nil, err
	}
	if out.RxPackets, err = read("rx_packets"); err != nil {
		return nil, err
	}
	if out.TxPackets, err = read("tx_packets"); err != nil {
		return nil, err
	}
	return out, nil
}

// netlink counters: the RTM_GETLINK answer for one interface, read through a
// NETLINK_ROUTE socket. This is a pure syscall path, so it is correct in any
// namespace and independent of the sysfs mount.
const (
	iflaIfname  = 3
	iflaStats   = 7
	iflaStats64 = 23
)

func readNetlinkCounters(name string) (counterSnapshot, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return counterSnapshot{}, err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return counterSnapshot{}, fmt.Errorf("open NETLINK_ROUTE socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return counterSnapshot{}, fmt.Errorf("bind NETLINK_ROUTE socket: %w", err)
	}
	deadline := unix.Timeval{Sec: 5}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &deadline); err != nil {
		return counterSnapshot{}, fmt.Errorf("set netlink receive timeout: %w", err)
	}

	const seq = uint32(0x5157)
	request := make([]byte, 32)
	binary.LittleEndian.PutUint32(request[0:], uint32(len(request)))
	binary.LittleEndian.PutUint16(request[4:], unix.RTM_GETLINK)
	binary.LittleEndian.PutUint16(request[6:], unix.NLM_F_REQUEST)
	binary.LittleEndian.PutUint32(request[8:], seq)
	request[16] = unix.AF_UNSPEC
	binary.LittleEndian.PutUint32(request[20:], uint32(iface.Index))
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return counterSnapshot{}, fmt.Errorf("send RTM_GETLINK for %s: %w", name, err)
	}

	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return counterSnapshot{}, fmt.Errorf("receive RTM_GETLINK answer for %s: %w", name, err)
		}
		for offset := 0; offset+16 <= n; {
			length := int(binary.LittleEndian.Uint32(buf[offset:]))
			if length < 16 || offset+length > n {
				break
			}
			kind := binary.LittleEndian.Uint16(buf[offset+4:])
			if kind == unix.NLMSG_DONE {
				return counterSnapshot{}, fmt.Errorf("netlink returned no RTM_NEWLINK for %s", name)
			}
			if kind == unix.NLMSG_ERROR {
				return counterSnapshot{}, fmt.Errorf("netlink reported an error for %s", name)
			}
			if kind == unix.RTM_NEWLINK {
				counters, err := parseLinkStats(buf[offset : offset+length])
				if err != nil {
					return counterSnapshot{}, err
				}
				counters.Name = name
				counters.Source = "netlink"
				return counters, nil
			}
			offset += (length + 3) &^ 3
		}
	}
}

// parseLinkStats walks the IFLA_* attributes of one RTM_NEWLINK message and
// decodes IFLA_STATS64, falling back to the 32-bit IFLA_STATS.
func parseLinkStats(message []byte) (counterSnapshot, error) {
	out := counterSnapshot{}
	// nlmsghdr(16) + ifinfomsg(16)
	for offset := 32; offset+4 <= len(message); {
		length := int(binary.LittleEndian.Uint16(message[offset:]))
		kind := int(binary.LittleEndian.Uint16(message[offset+2:])) & 0x3fff
		if length < 4 || offset+length > len(message) {
			break
		}
		payload := message[offset+4 : offset+length]
		switch kind {
		case iflaStats64:
			if len(payload) >= 32 {
				out.RxPackets = binary.LittleEndian.Uint64(payload[0:])
				out.TxPackets = binary.LittleEndian.Uint64(payload[8:])
				out.RxBytes = binary.LittleEndian.Uint64(payload[16:])
				out.TxBytes = binary.LittleEndian.Uint64(payload[24:])
				return out, nil
			}
		case iflaStats:
			if len(payload) >= 16 {
				out.RxPackets = uint64(binary.LittleEndian.Uint32(payload[0:]))
				out.TxPackets = uint64(binary.LittleEndian.Uint32(payload[4:]))
				out.RxBytes = uint64(binary.LittleEndian.Uint32(payload[8:]))
				out.TxBytes = uint64(binary.LittleEndian.Uint32(payload[12:]))
				return out, nil
			}
		}
		offset += (length + 3) &^ 3
	}
	return counterSnapshot{}, fmt.Errorf("RTM_NEWLINK carried no usable IFLA_STATS/IFLA_STATS64")
}

// readCounters merges the syscall and sysfs views of one interface. The
// netlink reading is authoritative; the sysfs reading is a cross-check that
// must agree exactly, which is what makes the counter evidence trustworthy.
func readCounters(name string) (counterSnapshot, error) {
	out, err := readNetlinkCounters(name)
	if err != nil {
		return counterSnapshot{}, err
	}
	if sysfs, sysErr := readSysfsCounters(name); sysErr == nil {
		out.Sysfs = sysfs
	}
	return out, nil
}

func readCountersAll(names []string) (map[string]counterSnapshot, error) {
	out := make(map[string]counterSnapshot, len(names))
	for _, name := range names {
		// A link moved in with `ip link set ... netns <pid>` can be visible to
		// net.InterfaceByName before the netlink counter dump sees it, so retry
		// briefly rather than failing the whole acceptance on that window.
		var counters counterSnapshot
		var err error
		for attempt := 0; attempt < 20; attempt++ {
			counters, err = readCounters(name)
			if err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err != nil {
			// Name what this namespace actually holds: "no such interface" alone
			// cannot distinguish a missing link from a namespace that never had it.
			present := "?"
			if ifaces, listErr := listInterfaces(); listErr == nil {
				visible := make([]string, 0, len(ifaces))
				for _, iface := range ifaces {
					visible = append(visible, iface.Name)
				}
				present = strings.Join(visible, ",")
			}
			inode := uint64(0)
			if self, inodeErr := selfNetnsInode(); inodeErr == nil {
				inode = self
			}
			// Distinguish "the kernel has no such link" from "the netlink dump
			// and net.InterfaceByName disagree", which would point at the sysfs
			// remount rather than at the link itself.
			viaGo := "absent"
			if _, goErr := net.InterfaceByName(name); goErr == nil {
				viaGo = "present"
			}
			return nil, fmt.Errorf("counters of %s: %w (visible interfaces: %s; netns inode: %d; net.InterfaceByName: %s)", name, err, present, inode, viaGo)
		}
		out[name] = counters
	}
	return out, nil
}
