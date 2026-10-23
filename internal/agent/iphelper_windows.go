//go:build windows

package agent

// Windows IP Helper bindings for the SystemNetwork owner and the Wintun device.
//
// doc:docs/domains/overlay/features/multiprotocol-overlay.md
//
// Requirement anchor (prose, not an ownership pointer): R-MESH-007.
//
// x/sys/windows already binds the IP Helper queries (GetIpInterfaceEntry,
// GetIpForwardTable2, GetUnicastIpAddressTable, FreeMibTable) and declares every
// MIB structure this file uses. Only the mutating calls and the name/LUID
// conversions are resolved here, dynamically from iphlpapi.dll, so no new module
// dependency is added.
//
// Every mutating call goes through the transaction owner, which journals the
// intent and the prior fingerprint before applying it.

import (
	"fmt"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsInfiniteLifetime = ^uint32(0)
)

type ipHelperAPI struct {
	initializeIPInterfaceEntry  *windows.LazyProc
	setIPInterfaceEntry         *windows.LazyProc
	createUnicastIPAddressEntry *windows.LazyProc
	deleteUnicastIPAddressEntry *windows.LazyProc
	createIPForwardEntry2       *windows.LazyProc
	deleteIPForwardEntry2       *windows.LazyProc
	convertInterfaceAliasToLuid *windows.LazyProc
	convertInterfaceLuidToIndex *windows.LazyProc
	convertInterfaceIndexToLuid *windows.LazyProc
}

var (
	ipHelperOnce  sync.Once
	ipHelperProcs *ipHelperAPI
	ipHelperErr   error
)

// loadIPHelper resolves iphlpapi.dll once per process and reports the missing
// export instead of failing later with an opaque call error.
func loadIPHelper() (*ipHelperAPI, error) {
	ipHelperOnce.Do(func() {
		dll := windows.NewLazySystemDLL("iphlpapi.dll")
		if err := dll.Load(); err != nil {
			ipHelperErr = fmt.Errorf("%w: iphlpapi.dll could not be loaded: %v; Windows host network configuration is unavailable", ErrDriverMissing, err)
			return
		}
		procs := &ipHelperAPI{
			initializeIPInterfaceEntry:  dll.NewProc("InitializeIpInterfaceEntry"),
			setIPInterfaceEntry:         dll.NewProc("SetIpInterfaceEntry"),
			createUnicastIPAddressEntry: dll.NewProc("CreateUnicastIpAddressEntry"),
			deleteUnicastIPAddressEntry: dll.NewProc("DeleteUnicastIpAddressEntry"),
			createIPForwardEntry2:       dll.NewProc("CreateIpForwardEntry2"),
			deleteIPForwardEntry2:       dll.NewProc("DeleteIpForwardEntry2"),
			convertInterfaceAliasToLuid: dll.NewProc("ConvertInterfaceAliasToLuid"),
			convertInterfaceLuidToIndex: dll.NewProc("ConvertInterfaceLuidToIndex"),
			convertInterfaceIndexToLuid: dll.NewProc("ConvertInterfaceIndexToLuid"),
		}
		exports := map[string]*windows.LazyProc{
			"InitializeIpInterfaceEntry":  procs.initializeIPInterfaceEntry,
			"SetIpInterfaceEntry":         procs.setIPInterfaceEntry,
			"CreateUnicastIpAddressEntry": procs.createUnicastIPAddressEntry,
			"DeleteUnicastIpAddressEntry": procs.deleteUnicastIPAddressEntry,
			"CreateIpForwardEntry2":       procs.createIPForwardEntry2,
			"DeleteIpForwardEntry2":       procs.deleteIPForwardEntry2,
			"ConvertInterfaceAliasToLuid": procs.convertInterfaceAliasToLuid,
			"ConvertInterfaceLuidToIndex": procs.convertInterfaceLuidToIndex,
			"ConvertInterfaceIndexToLuid": procs.convertInterfaceIndexToLuid,
		}
		for exportName, proc := range exports {
			if err := proc.Find(); err != nil {
				ipHelperErr = fmt.Errorf("%w: iphlpapi.dll does not export %s: %v", ErrDriverMissing, exportName, err)
				return
			}
		}
		ipHelperProcs = procs
	})
	return ipHelperProcs, ipHelperErr
}

// callStatus invokes a NETIO_STATUS-returning function: zero is success and the
// return value is a Win32 error code otherwise.
func callStatus(proc *windows.LazyProc, args ...uintptr) error {
	status, _, _ := proc.Call(args...)
	if status == 0 {
		return nil
	}
	return windows.Errno(status)
}

// setSockaddrInet4 writes an IPv4 address into a SOCKADDR_INET union. The union
// is declared as RawSockaddrInet6 in the MIB structures, so the IPv4 view aliases
// the same memory (family at offset 0, address at offset 4).
func setSockaddrInet4(target *windows.RawSockaddrInet6, address [4]byte) {
	ipv4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(target))
	*ipv4 = windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: address}
}

func sockaddrInet4Address(target *windows.RawSockaddrInet6) (netip.Addr, bool) {
	if target.Family != windows.AF_INET {
		return netip.Addr{}, false
	}
	ipv4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(target))
	return netip.AddrFrom4(ipv4.Addr), true
}

func setSockaddrInet4Raw(target *windows.RawSockaddrInet, address [4]byte) {
	ipv4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(target))
	*ipv4 = windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: address}
}

func sockaddrInet4RawAddress(target *windows.RawSockaddrInet) (netip.Addr, bool) {
	if target.Family != windows.AF_INET {
		return netip.Addr{}, false
	}
	ipv4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(target))
	return netip.AddrFrom4(ipv4.Addr), true
}

// interfaceLUID resolves the adapter alias (its Windows name) to an interface
// LUID, which every IP Helper v2 call uses to identify the adapter.
func interfaceLUID(alias string) (uint64, error) {
	api, err := loadIPHelper()
	if err != nil {
		return 0, err
	}
	name, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		return 0, fmt.Errorf("%w: adapter name %q: %v", ErrInvalidConfig, alias, err)
	}
	var luid uint64
	if err := callStatus(api.convertInterfaceAliasToLuid, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&luid))); err != nil {
		return 0, fmt.Errorf("ConvertInterfaceAliasToLuid(%q): %w", alias, err)
	}
	if luid == 0 {
		return 0, fmt.Errorf("%w: adapter %q has no interface LUID; the device must be created before its network configuration", ErrPlatformUnavailable, alias)
	}
	return luid, nil
}

func interfaceIndex(luid uint64) (uint32, error) {
	api, err := loadIPHelper()
	if err != nil {
		return 0, err
	}
	var index uint32
	if err := callStatus(api.convertInterfaceLuidToIndex, uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index))); err != nil {
		return 0, fmt.Errorf("ConvertInterfaceLuidToIndex: %w", err)
	}
	return index, nil
}

// interfaceMTU reads the IPv4 MTU of one interface.
func interfaceMTU(luid uint64) (int, error) {
	api, err := loadIPHelper()
	if err != nil {
		return 0, err
	}
	row := windows.MibIpInterfaceRow{}
	api.initializeIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.Family = windows.AF_INET
	row.InterfaceLuid = luid
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return 0, fmt.Errorf("GetIpInterfaceEntry: %w", err)
	}
	return int(row.NlMtu), nil
}

// setInterfaceMTU applies the IPv4 MTU through SetIpInterfaceEntry. The caller
// owns the ownership decision; this function only performs the mutation.
func setInterfaceMTU(luid uint64, mtu int) error {
	api, err := loadIPHelper()
	if err != nil {
		return err
	}
	row := windows.MibIpInterfaceRow{}
	api.initializeIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.Family = windows.AF_INET
	row.InterfaceLuid = luid
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return fmt.Errorf("GetIpInterfaceEntry: %w", err)
	}
	if row.NlMtu == uint32(mtu) {
		return nil
	}
	row.SitePrefixLength = 0
	row.NlMtu = uint32(mtu)
	if err := callStatus(api.setIPInterfaceEntry, uintptr(unsafe.Pointer(&row))); err != nil {
		return fmt.Errorf("SetIpInterfaceEntry(NlMtu=%d): %w", mtu, err)
	}
	return nil
}

// createIPv4Address assigns one manual IPv4 address to the interface.
func createIPv4Address(luid uint64, index uint32, prefix netip.Prefix) error {
	api, err := loadIPHelper()
	if err != nil {
		return err
	}
	row := windows.MibUnicastIpAddressRow{}
	setSockaddrInet4(&row.Address, prefix.Addr().As4())
	row.InterfaceLuid = luid
	row.InterfaceIndex = index
	row.PrefixOrigin = windows.IpPrefixOriginManual
	row.SuffixOrigin = windows.IpSuffixOriginManual
	row.ValidLifetime = windowsInfiniteLifetime
	row.PreferredLifetime = windowsInfiniteLifetime
	row.OnLinkPrefixLength = uint8(prefix.Bits())
	row.SkipAsSource = 0
	row.ScopeId = 0
	if err := callStatus(api.createUnicastIPAddressEntry, uintptr(unsafe.Pointer(&row))); err != nil {
		return fmt.Errorf("CreateUnicastIpAddressEntry(%s): %w", prefix, err)
	}
	return nil
}

func deleteIPv4Address(luid uint64, index uint32, address netip.Addr) error {
	api, err := loadIPHelper()
	if err != nil {
		return err
	}
	row := windows.MibUnicastIpAddressRow{}
	setSockaddrInet4(&row.Address, address.As4())
	row.InterfaceLuid = luid
	row.InterfaceIndex = index
	if err := callStatus(api.deleteUnicastIPAddressEntry, uintptr(unsafe.Pointer(&row))); err != nil {
		return fmt.Errorf("DeleteUnicastIpAddressEntry(%s): %w", address, err)
	}
	return nil
}

// addressPresent reports whether the interface still owns exactly this address,
// which is the ownership fingerprint used before removing it.
func addressPresent(luid uint64, address netip.Addr) (bool, error) {
	var table *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_INET, &table); err != nil {
		return false, fmt.Errorf("GetUnicastIpAddressTable: %w", err)
	}
	if table == nil {
		return false, nil
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	rows := unsafe.Slice(&table.Table[0], table.NumEntries)
	for index := range rows {
		if rows[index].InterfaceLuid != luid {
			continue
		}
		if present, ok := sockaddrInet4Address(&rows[index].Address); ok && present == address {
			return true, nil
		}
	}
	return false, nil
}

// interfaceIPv4Prefix returns the prefix length of an IPv4 address that is
// already present on the interface. It is the read half of the Prepare
// snapshot: the transaction records the actual prior address before it decides
// whether that address is already owned by someone else.
func interfaceIPv4Prefix(luid uint64, address netip.Addr) (netip.Prefix, bool, error) {
	var table *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_INET, &table); err != nil {
		return netip.Prefix{}, false, fmt.Errorf("GetUnicastIpAddressTable: %w", err)
	}
	if table == nil {
		return netip.Prefix{}, false, nil
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	rows := unsafe.Slice(&table.Table[0], table.NumEntries)
	for index := range rows {
		if rows[index].InterfaceLuid != luid {
			continue
		}
		present, ok := sockaddrInet4Address(&rows[index].Address)
		if !ok || present != address {
			continue
		}
		bits := int(rows[index].OnLinkPrefixLength)
		if bits > 32 {
			bits = 32
		}
		return netip.PrefixFrom(present, bits), true, nil
	}
	return netip.Prefix{}, false, nil
}

// createIPv4Route installs one on-link IPv4 route on the interface.
func createIPv4Route(luid uint64, index uint32, prefix netip.Prefix) error {
	api, err := loadIPHelper()
	if err != nil {
		return err
	}
	row := windows.MibIpForwardRow2{}
	row.InterfaceLuid = luid
	row.InterfaceIndex = index
	setSockaddrInet4Raw(&row.DestinationPrefix.Prefix, prefix.Addr().As4())
	row.DestinationPrefix.PrefixLength = uint8(prefix.Bits())
	setSockaddrInet4Raw(&row.NextHop, [4]byte{}) // on-link: next hop 0.0.0.0
	row.SitePrefixLength = 0
	row.ValidLifetime = windowsInfiniteLifetime
	row.PreferredLifetime = windowsInfiniteLifetime
	row.Metric = 0
	row.Protocol = windows.MIB_IPPROTO_NETMGMT
	row.Loopback = 0
	row.AutoconfigureAddress = 0
	row.Publish = 0
	row.Immortal = 1
	row.Age = 0
	row.Origin = windows.NlroManual
	if err := callStatus(api.createIPForwardEntry2, uintptr(unsafe.Pointer(&row))); err != nil {
		return fmt.Errorf("CreateIpForwardEntry2(%s): %w", prefix, err)
	}
	return nil
}

func deleteIPv4Route(luid uint64, index uint32, prefix netip.Prefix) error {
	api, err := loadIPHelper()
	if err != nil {
		return err
	}
	row := windows.MibIpForwardRow2{}
	row.InterfaceLuid = luid
	row.InterfaceIndex = index
	setSockaddrInet4Raw(&row.DestinationPrefix.Prefix, prefix.Addr().As4())
	row.DestinationPrefix.PrefixLength = uint8(prefix.Bits())
	// CreateIpForwardEntry2 wrote an AF_INET 0.0.0.0 NextHop for the on-link
	// route. DeleteIpForwardEntry2 matches on the row key, so the delete has to
	// describe the same NextHop family/address, metric and protocol; leaving the
	// zero-value union (family 0) makes the native lookup miss the row it just
	// created.
	setSockaddrInet4Raw(&row.NextHop, [4]byte{})
	row.Metric = 0
	row.Protocol = windows.MIB_IPPROTO_NETMGMT
	row.Origin = windows.NlroManual
	if err := callStatus(api.deleteIPForwardEntry2, uintptr(unsafe.Pointer(&row))); err != nil {
		return fmt.Errorf("DeleteIpForwardEntry2(%s): %w", prefix, err)
	}
	return nil
}

// routeState looks one canonical on-link route up on the adapter. Found reports
// the same destination prefix, prefix length and adapter LUID; Exact additionally
// proves the whole tuple this transaction creates: interface index, AF_INET
// 0.0.0.0 next hop, zero metric and NETMGMT protocol. A route that only shares
// the prefix is never reported as owned.
func routeState(luid uint64, index uint32, prefix netip.Prefix) (windowsRouteResult, error) {
	var result windowsRouteResult
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return result, fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	if table == nil {
		return result, nil
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	for _, row := range table.Rows() {
		if row.InterfaceLuid != luid {
			continue
		}
		if int(row.DestinationPrefix.PrefixLength) != prefix.Bits() {
			continue
		}
		present, ok := sockaddrInet4RawAddress(&row.DestinationPrefix.Prefix)
		if !ok || present != prefix.Addr() {
			continue
		}
		result.Found = true
		if row.InterfaceIndex != index {
			continue
		}
		nextHop, ok := sockaddrInet4RawAddress(&row.NextHop)
		if !ok || nextHop != netip.AddrFrom4([4]byte{}) {
			continue
		}
		if row.Metric != 0 || row.Protocol != windows.MIB_IPPROTO_NETMGMT {
			continue
		}
		result.Exact = true
		return result, nil
	}
	return result, nil
}
