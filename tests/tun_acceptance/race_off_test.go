//go:build linux && !race

package tun_acceptance

// raceEnabled is false for the ordinary native run; see race_on_test.go.
const raceEnabled = false
