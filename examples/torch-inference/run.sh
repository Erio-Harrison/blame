#!/usr/bin/env bash
# Run one scenario of the PyTorch inference example and keep what blame and
# the server said.
#
#   examples/torch-inference/run.sh SCENARIO OUT_DIR
#
# SCENARIO: normal (an idle machine), cpu (six processes spin on its CPUs),
# spin (a team's idle threads spin a while before they sleep, which is what
# OpenMP does unless told otherwise; in the other two they sleep at once,
# OMP_WAIT_POLICY=passive).
# Needs root through sudo (blame) and a python3 with torch: PYTHON names it
# (default: python3). One connection, one request at a time.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
scenario=$1 out=$2/$1
python=${PYTHON:-python3}
blame="${BLAME_BIN:-$(cargo metadata --manifest-path "$here/../../Cargo.toml" --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/blame}"
mkdir -p "$out"
hogs=()
stop_all() {
    for p in "${hogs[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
    [[ -n "${server:-}" ]] && kill -TERM "$server" 2>/dev/null
    wait 2>/dev/null
}
trap stop_all EXIT
if [[ $scenario == spin ]]; then
    env -u OMP_WAIT_POLICY "$python" "$here/server.py" 18400 "$out/server.truth" > "$out/server.out" 2>&1 & server=$!
else
    OMP_WAIT_POLICY=passive "$python" "$here/server.py" 18400 "$out/server.truth" > "$out/server.out" 2>&1 & server=$!
fi
for _ in $(seq 300); do grep -q ready "$out/server.out" 2>/dev/null && break; sleep 0.2; done
grep -q ready "$out/server.out" || { cat "$out/server.out"; exit 1; }
sudo -n "$blame" slow --json --above 0 --list 0 --interval 0 --deep --pid "$server" > "$out/blame.json" 2> "$out/blame.err" & agent=$!
for _ in $(seq 300); do grep -q '"type":"process"' "$out/blame.json" 2>/dev/null && break; sleep 0.1; done
if [[ $scenario == cpu ]]; then
    for _ in 1 2 3 4 5 6; do ( while :; do :; done ) & hogs+=($!); done
fi
"$python" "$here/load.py" 18400 1 8 > "$out/load.txt"
sleep 0.5
for p in $(pgrep -P "$agent"); do sudo -n kill -INT "$p"; done
wait "$agent"
cat "$out/load.txt"
