#!/usr/bin/env bash
# 多进程压测驱动：每个节点一个独立 OS 进程，经真实 socket 与 relay 通信。
#
# 用法: multiproc.sh <rooms> <peers-per-room> <duration> [rate-mbit]
#
# 每个房间的 10 个节点分成 5 对 (0-1, 2-3, ...)：偶数位起 echo 服务，奇数位向其推送。
set -uo pipefail

ROOMS=${1:-20}
PER_ROOM=${2:-10}
DURATION=${3:-20s}
RATE_MBIT=${4:-0}
BIN=${BIN:-/tmp/nodeproc}
BASE_PORT=${BASE_PORT:-26100}
WORK=$(mktemp -d /tmp/multiproc.XXXXXX)
RELAY_ADDR="127.0.0.1:${BASE_PORT}"
ROOM_TOKEN_PREFIX="perf-room"

cleanup() {
  # 只杀本脚本启动的进程，按记录下来的 pid
  if [ -f "$WORK/pids" ]; then
    while read -r pid; do
      kill "$pid" 2>/dev/null || true
    done < "$WORK/pids"
  fi
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "starting relay on ${RELAY_ADDR}"
"$BIN" -mode relay -listen "$RELAY_ADDR" > "$WORK/relay.log" 2>&1 &
echo $! >> "$WORK/pids"
for _ in $(seq 1 100); do
  grep -q relay-ready "$WORK/relay.log" 2>/dev/null && break
  sleep 0.1
done
if ! grep -q relay-ready "$WORK/relay.log" 2>/dev/null; then
  echo "relay failed to start:" >&2
  cat "$WORK/relay.log" >&2
  exit 1
fi
echo "relay ready"

pairs_per_room=$((PER_ROOM / 2))
pushed=0
for room in $(seq 0 $((ROOMS - 1))); do
  for pair in $(seq 0 $((pairs_per_room - 1))); do
    port=$((20000 + room * 10 + pair))
    "$BIN" -mode peer -relay "$RELAY_ADDR" -token "${ROOM_TOKEN_PREFIX}-${room}" -echo-port "$port" \
      > "$WORK/echo-${room}-${pair}.log" 2>&1 &
    echo $! >> "$WORK/pids"
    pushed=$((pushed + 1))
  done
done

echo "started ${pushed} echo nodes; waiting for them to join"
deadline=$(( $(date +%s) + 120 ))
while :; do
  ready=0
  for log in "$WORK"/echo-*.log; do
    grep -q echo-ready "$log" 2>/dev/null && ready=$((ready + 1))
  done
  [ "$ready" -ge "$pushed" ] && break
  [ "$(date +%s)" -gt "$deadline" ] && { echo "timeout: only $ready/$pushed echo nodes ready" >&2; break; }
  sleep 0.2
done
echo "echo nodes ready: ${ready}/${pushed}"

joined=0
for log in "$WORK"/echo-*.log; do
  vip=$(grep -oP 'vip=\K[\d.]+' "$log" 2>/dev/null | head -1)
  [ -n "$vip" ] || continue
  port=$(grep -oP 'echo-ready :\K\d+' "$log" 2>/dev/null | head -1)
  name=$(basename "$log" .log | sed 's/echo-//')
  echo "$name $vip $port" >> "$WORK/targets"
  joined=$((joined + 1))
done
echo "collected ${joined} targets"

start=$(date +%s.%N)
for room in $(seq 0 $((ROOMS - 1))); do
  for pair in $(seq 0 $((pairs_per_room - 1))); do
    target=$(awk -v k="${room}-${pair}" '$1==k {print $2":"$3}' "$WORK/targets")
    [ -n "$target" ] || continue
    "$BIN" -mode peer -relay "$RELAY_ADDR" -token "${ROOM_TOKEN_PREFIX}-${room}" \
      -dial "$target" -duration "$DURATION" \
      > "$WORK/push-${room}-${pair}.log" 2>&1 &
    push_pid=$!
    echo "$push_pid" >> "$WORK/pids"
    echo "$push_pid" >> "$WORK/push_pids"
  done
done

# 等所有推送进程结束。用记录下来的 pid 逐个 wait，避免 pgrep -f 匹配到本脚本自身。
for pid in $(cat "$WORK/push_pids" 2>/dev/null); do
  wait "$pid" 2>/dev/null || true
done
# wait 只保证进程退出，内核缓冲区里的落盘可能还没完成，结果解析前先同步。
sync
end=$(date +%s.%N)

echo
echo "=== results ==="
total_up=0
total_down=0
ok=0
fail=0
for log in "$WORK"/push-*.log; do
  line=$(grep -oP 'result \K\{.*\}' "$log" 2>/dev/null | head -1)
  if [ -z "$line" ]; then
    fail=$((fail + 1))
    continue
  fi
  up=$(echo "$line" | grep -oP '"upMBps":\K[\d.]+')
  down=$(echo "$line" | grep -oP '"downMBps":\K[\d.]+')
  total_up=$(echo "$total_up + $up" | bc -l)
  total_down=$(echo "$total_down + $down" | bc -l)
  echo "$up" >> "$WORK/ups.txt"
  echo "$down" >> "$WORK/downs.txt"
  ok=$((ok + 1))
done

echo "pairs ok=${ok} failed=${fail}"
if [ "$ok" -gt 0 ]; then
  report() {
    sort -n "$1" | awk '{v[NR]=$1; s+=$1} END {
      n=NR
      printf "  mean %.2f  p10 %.2f  p50 %.2f  p90 %.2f  min %.2f  max %.2f MB/s\n",
        s/n, v[int(n*0.1)+1], v[int(n*0.5)+1], v[int(n*0.9)+1], v[1], v[n]
    }'
  }
  echo "upload per pair:"
  report "$WORK/ups.txt"
  echo "download per pair:"
  report "$WORK/downs.txt"
  echo "aggregate upload:   $(echo "$total_up" | bc -l | xargs printf '%.2f') MB/s"
  echo "aggregate download: $(echo "$total_down" | bc -l | xargs printf '%.2f') MB/s"
fi
echo "wall: $(echo "$end - $start" | bc -l | xargs printf '%.1f')s"

# 保留现场以便排查
echo "workdir: $WORK"
trap - EXIT
