//go:build !linux && !darwin

package testlock

// acquire is a no-op on platforms whose test packages do not mutate host-global
// network interfaces. The packages that contend for the lock are tagged
// linux || darwin.
func acquire() (func(), error) {
	return func() {}, nil
}
