#!/usr/bin/env bash
# Run one scenario of the thread-server example and keep what blame and the
# servers said.
#
#   examples/thread-server/run.sh SCENARIO OUT_DIR
#
# SCENARIO: normal, or cpu (two processes spin on the CPUs the front server runs on).
# Needs root through sudo (blame) and a C compiler. Uses CPUs 0-5: the front
# server on 0-1, the backend on 2, the load on 4-5. The file /save writes to is in
# OUT_DIR: keep it on a local disk.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
scenario=$1 out=$2/$1
blame="${BLAME_BIN:-$(cargo metadata --manifest-path "$here/../../Cargo.toml" --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/blame}"
mkdir -p "$out"
cc -O2 -Wall -pthread -o "$2/server" "$here/server.c" || exit 1
pids=() names=() hogs=()
stop_all() {
    for p in "${hogs[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
    for p in "${pids[@]}"; do kill -TERM "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -f "$out/saved"
}
trap stop_all EXIT
taskset -c 2 "$2/server" -role backend -addr 9402 -log "$out/backend.truth" >/dev/null & pids+=($!); names+=(backend)
taskset -c 0-1 "$2/server" -role front -addr 9401 -backend 9402 -file "$out/saved" -log "$out/front.truth" >/dev/null & pids+=($!); names+=(front)
sleep 0.5
taskset -c 4-5 "$2/server" -role load -addr 9401 -conns 16 -secs 24 > "$out/load.txt" & load=$!
sleep 3
# Attached while the servers are busy, as it would be.
args=(); for p in "${pids[@]}"; do args+=(--pid "$p"); done
sudo -n "$blame" slow --json --above 0 --list 0 --interval 0 "${args[@]}" > "$out/blame.json" 2> "$out/blame.err" & agent=$!
for _ in $(seq 300); do (( $(grep -c '"type":"process"' "$out/blame.json" 2>/dev/null) >= 2 )) && break; sleep 0.1; done
if [[ $scenario == cpu ]]; then
    for _ in 1 2; do taskset -c 0-1 python3 -c 'while 1: pass' & hogs+=($!); done
fi
sleep 15
for p in $(pgrep -P "$agent"); do sudo -n kill -INT "$p"; done
wait "$agent"
wait "$load"
for i in "${!pids[@]}"; do echo "${names[$i]} ${pids[$i]}"; done > "$out/pids"
cat "$out/load.txt"
