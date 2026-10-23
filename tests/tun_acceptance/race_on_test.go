//go:build linux && race

package tun_acceptance

// raceEnabled is true when this test binary was built with -race. The harness
// then builds the examples/tun-agent helper with -race as well, so the SDK
// running inside both child processes is race-instrumented too.
const raceEnabled = true
