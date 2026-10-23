package agent

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrDeviceInUse reports that the requested interface name is taken by an interface this
// process cannot prove it created.
var ErrDeviceInUse = errors.New("agent: device name already in use")

// deviceReuse is what to do about an interface that already carries the requested name.
type deviceReuse int

const (
	// deviceAbsent means the name is free.
	deviceAbsent deviceReuse = iota
	// deviceStale means the interface carries this node's own virtual address, so it is
	// left over from a previous run that did not shut down cleanly. It may be torn down
	// and recreated.
	deviceStale
	// deviceForeign means the interface exists but carries no address of ours. Another
	// program owns it; refusing to start is the only safe answer.
	deviceForeign
)

// classifyExistingDevice decides whether an existing interface belongs to this node.
//
// The interface name is the only durable handle a crashed process leaves behind: runtime
// state is process-local, so there is no journal on disk to consult. A name alone is not
// proof of ownership — the operator may have reused a name, or another instance may be
// running — so the deciding evidence is the node's own virtual address on the interface.
// Removing an interface because its name matched would delete another program's network
// configuration.
func classifyExistingDevice(existing []netip.Prefix, own netip.Prefix) deviceReuse {
	if len(existing) == 0 {
		return deviceAbsent
	}
	if !own.IsValid() {
		// Nothing to look for, so nothing can be proven ours.
		return deviceForeign
	}
	for _, prefix := range existing {
		if prefix == own {
			return deviceStale
		}
	}
	return deviceForeign
}

// foreignDeviceError explains a refused start: which interface, what it carries, and that
// this process did not remove it.
func foreignDeviceError(name string, existing []netip.Prefix) error {
	return fmt.Errorf("%w: interface %q carries %v, not this node's virtual address; "+
		"remove it manually if it is stale", ErrDeviceInUse, name, existing)
}
