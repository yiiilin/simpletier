// Package testlock serializes test packages that create, rename or delete
// host-global network interfaces.
//
// Two otherwise independent test packages in this repository take the host
// network namespace as their subject. internal/agent's device tests open real
// TUN devices under short "st<hex>" names, and tests/tun_acceptance asserts that
// the host interface set is byte-identical before and after its run. When
// `go test ./...` schedules those packages concurrently, the first package's
// interface appears or disappears inside the second package's before/after
// window, and the acceptance assertion reports a removal that the acceptance
// test did not cause.
//
// The lock removes that interference at its source instead of narrowing the
// acceptance snapshot, so "the host interface set did not change" keeps its
// full strength. Both packages are correct in isolation; only their concurrent
// execution was not.
//
// It is a test-only helper. Production code must not depend on it.
package testlock

// Acquire blocks until this process exclusively owns the host-network test
// lock and returns the function that releases it.
//
// The call is safe to make from a test that never mutates host interfaces; it
// then simply serializes against the packages that do.
func Acquire() (release func(), err error) {
	return acquire()
}
