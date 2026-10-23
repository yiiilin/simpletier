#!/usr/bin/env bash
# Cross-compile the Windows test binaries and (optionally) run them on a Windows
# host over SSH, with a hash check so the bytes that run are provably the bytes
# that were built.
#
#   scripts/test-windows.sh build              # cross-compile only
#   scripts/test-windows.sh run HOST USER PASS # cross-compile, upload, run
#
# The upload uses scp and the run uses ssh, so the Windows host needs an
# OpenSSH server. The test binaries are self-contained: they need no Go
# toolchain on the Windows side.
set -euo pipefail

cd "$(dirname "$0")/.."

OUT="${OUT:-dist/windows}"
GOOS=windows
GOARCH=amd64
CGO_ENABLED=0

log() { printf '\n=== %s ===\n' "$1"; }

build() {
  log "cross-compile for windows/$GOARCH"
  mkdir -p "$OUT"

  echo "internal/agent"
  go test -c -o "$OUT/agent.test.exe" ./internal/agent/

  echo "internal/security"
  go test -c -o "$OUT/security.test.exe" ./internal/security/

  echo "internal/packet"
  go test -c -o "$OUT/packet.test.exe" ./internal/packet/

  log "artifacts"
  ls -l "$OUT"/*.exe
  # The hashes are printed so a CI log and the Windows host can be compared.
  ( cd "$OUT" && sha256sum *.exe )
}

run_remote() {
  local host="$1" user="$2" pass="$3"
  local remote_dir="${REMOTE_DIR:-/tmp/simpletier-windows-tests}"

  log "upload to $host"
  sshpass -p "$pass" scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$OUT"/*.exe "$user@$host:$remote_dir/"

  log "hash check on $host"
  # The host must compute the same digests. A mismatch means the bytes that run
  # are not the bytes that were built, so stop before running anything.
  local local_hashes remote_hashes
  local_hashes=$( cd "$OUT" && sha256sum *.exe | awk '{print $1" "$2}' | sort )
  remote_hashes=$(sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$user@$host" "cd '$remote_dir' && sha256sum *.exe | awk '{print \$1\" \"\$2}' | sort")

  if [ "$local_hashes" != "$remote_hashes" ]; then
    echo "HASH MISMATCH" >&2
    echo "local:"  >&2; echo "$local_hashes"  >&2
    echo "remote:" >&2; echo "$remote_hashes" >&2
    return 1
  fi
  echo "hashes match:"
  echo "$remote_hashes"

  log "run on $host"
  # TermService on Windows needs an interactive session for a GUI-owning test
  # binary; running it over SSH gives session 0, which the RDP-facing tests do
  # not use. The agent and security suites are console-only.
  sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$user@$host" "cd '$remote_dir' && ./agent.test.exe -test.v 2>&1 | tail -40; echo AGENT_EXIT=\${PIPESTATUS[0]}"
}

case "${1:-build}" in
  build) build ;;
  run)
    [ $# -ge 4 ] || { echo "usage: $0 run HOST USER PASS" >&2; exit 2; }
    build
    run_remote "$2" "$3" "$4"
    ;;
  *)
    echo "usage: $0 [build|run HOST USER PASS]" >&2
    exit 2
    ;;
esac
