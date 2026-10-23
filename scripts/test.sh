#!/usr/bin/env bash
# Run the SimpleTier test suites the way CI does, so a local run and a CI run
# exercise the same commands.
#
#   scripts/test.sh              # everything below, in order
#   scripts/test.sh build        # gofmt, go build, go vet
#   scripts/test.sh unit         # package unit tests only  (runs in CI on every push)
#   scripts/test.sh race         # race detector            (runs in CI on every push)
#   scripts/test.sh acceptance   # cross-node data plane + TUN (tags and manual runs)
#   scripts/test.sh integration  # alias for acceptance, kept for existing habits
#
# The split is deliberate. `unit` and `race` are deterministic and need only a Go
# toolchain, so they gate every push. `acceptance` starts real processes, opens
# real sockets and, for the TUN half, needs root and network namespaces, so it
# runs on tags and on demand rather than on every commit.
set -euo pipefail

cd "$(dirname "$0")/.."

log() { printf '\n=== %s ===\n' "$1"; }

run_linux_build() {
  log "gofmt"
  unformatted=$(gofmt -l internal/ pkg/ tests/ examples/ 2>/dev/null)
  if [ -n "$unformatted" ]; then
    echo "gofmt needed for:" >&2
    echo "$unformatted" >&2
    return 1
  fi

  log "go build"
  go build ./...

  log "go vet"
  go vet ./...
}

run_linux_unit() {
  log "unit tests"
  # -p 1: two packages create host-global TUN interfaces, and the acceptance
  # package asserts the host interface set is unchanged. Running packages
  # concurrently makes that assertion see the other package's interface.
  go test ./internal/... ./pkg/... -count=1 -p 1
}

run_linux_acceptance() {
  log "cross-node data plane"
  go test ./tests/network_runtime/ -count=1

  log "documented SDK example"
  go run ./examples/sdk-guide-check

  log "native TUN acceptance (needs root)"
  if [ "$(id -u)" != "0" ]; then
    echo "SKIP: native TUN acceptance needs root" >&2
    return 0
  fi
  go test ./tests/tun_acceptance/ -count=1
}

run_linux_race() {
  log "race detector"
  go test -race ./internal/agent/ ./internal/security/ ./internal/packet/ -count=1
}

case "${1:-all}" in
  build)       run_linux_build ;;
  unit)        run_linux_unit ;;
  race)        run_linux_race ;;
  acceptance)  run_linux_acceptance ;;
  integration) run_linux_acceptance ;;
  all)
    run_linux_build
    run_linux_unit
    run_linux_race
    run_linux_acceptance
    ;;
  *)
    echo "usage: $0 [build|unit|race|acceptance|integration|all]" >&2
    exit 2
    ;;
esac

log "OK"
