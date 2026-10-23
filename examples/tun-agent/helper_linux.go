//go:build linux

package main

import (
	"context"
	"os"
)

// runHelper performs one bounded, read-only observation in whatever namespace
// this process happens to be in. The acceptance uses it for the host snapshot
// before and after a run, so the "no host mutation and no leak" claim is made
// by an independent process on native kernel state rather than by the test
// process grading itself.
func runHelper(ctx context.Context, o *options) error {
	_ = ctx
	netns, err := selfNetnsInode()
	if err != nil {
		return stagef("helper", "%w", err)
	}
	hostNS, err := parentNetnsInode()
	if err != nil {
		hostNS = 0
	}
	facts := map[string]any{
		"netns_inode":      netns,
		"host_netns_inode": hostNS,
		"pid":              os.Getpid(),
	}
	switch o.helperOp {
	case "netns":
	case "snapshot":
		ifaces, err := listInterfaces()
		if err != nil {
			return stagef("helper", "%w", err)
		}
		routes, err := readRoutes()
		if err != nil {
			return stagef("helper", "%w", err)
		}
		facts["interfaces"] = ifaces
		facts["routes"] = routes
		if o.watchIface != "" {
			watched := map[string]any{"name": o.watchIface, "present": false}
			if iface, err := ifaceByName(o.watchIface); err == nil {
				watched["present"] = true
				watched["iface"] = iface
				watched["counters"], _ = readCounters(o.watchIface)
			}
			facts["watch"] = watched
		}
		carrierLike := map[string]any{}
		for _, iface := range ifaces {
			if len(iface.Name) >= 3 && iface.Name[:3] == "stv" {
				carrierLike[iface.Name] = true
			}
		}
		facts["test_owned_interfaces_present"] = carrierLike
	default:
		return stagef("config", "unknown helper-op %q", o.helperOp)
	}
	emit(event{Event: "helper-snapshot", Role: "helper", Data: facts})
	return nil
}
