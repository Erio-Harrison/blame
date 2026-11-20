#!/usr/bin/env bash
#
# Run-queue accuracy against a known answer: wakers stamp the time just before
# each wake, wakees stamp it on return, and the wakees' cgroup row in
# `blame top` must report the same p99 and p99.9.
#
# [1] mixes CPU hogs into the wakees' CPUs, so the tail (about 2 ms in the dev
# VM) is real queueing rather than the VM's own stalls, which no in-guest tool
# can see. [2] runs on idle CPUs, where most of each wait is the target CPU
# waking up before it queues the thread; it guards against timing waits from
# sched_wakeup, which under-reports there by 60-80%.
#
# Needs root or passwordless sudo, systemd, a C compiler, python3.
#     ./tests/scenarios/accuracy_acceptance.sh [blame-binary]
# Env: BLAME_BIN (binary), SCN_DURATION (seconds of load, default 25)

set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -n "${1:-}" ]] && BLAME_BIN="$1"
resolve_bin || exit 1
need_root || exit 1
(( NCPU >= 4 )) || { echo "needs at least 4 CPUs" >&2; exit 1; }

DUR="${SCN_DURATION:-25}"
PAIRS=8
HOGS=4
CPUS="0-3"
SHM="/dev/shm/blame-accuracy"
# Allowed relative error of each reported percentile, low:high, percent. Idle:
# in the dev VM about 20 us per wait stays invisible between the switch and the
# return to user space (-15 to -25% at these short tails).
MIXED_RANGE="-10:10"
IDLE_RANGE="-40:10"
WORK="$(mktemp -d)"
chmod 755 "$WORK"
cleanup() {
    stop_units
    reap_tracked
    sudo -n rm -f "$SHM"
    rm -rf "$WORK"
}
trap cleanup EXIT

cc -O2 -pthread -o "$WORK/wake_truth" "$SCN_DIR/../tools/wake_truth.c" || exit 1

# "2.0ms" / "850us" / "1.2s" -> microseconds; "-" stays "-".
to_us() {
    python3 -c '
import sys
v = sys.argv[1]
for unit, mul in (("ms", 1e3), ("us", 1), ("s", 1e6)):
    if v.endswith(unit):
        print(round(float(v[:-len(unit)]) * mul)); break
else:
    print(v)' "$1"
}

# One run: case NAME HOGS LOW:HIGH. Both sides and the hogs get their own units.
run_case() {
    local name=$1 hogs=$2 range=$3 lo hi
    IFS=: read -r lo hi <<<"$range"
    local log="$WORK/$name.top" truth="$WORK/$name.truth"
    sudo -n "$BIN" top --duration $((DUR + 8)) --interval 0 --rows 500 >"$log" 2>&1 &
    local agent=$!
    _TRACKED+=("$agent")
    sleep 2
    unit_start nw-acc-wakee taskset -c "$CPUS" "$WORK/wake_truth" wakee "$SHM" "$PAIRS" "$DUR" "$truth" \
        || { bad "$name: could not start the wakees"; return; }
    if (( hogs > 0 )); then
        unit_start nw-acc-hog taskset -c "$CPUS" "$WORK/wake_truth" hog "$hogs" $((DUR + 1)) \
            || { bad "$name: could not start the hogs"; return; }
    fi
    unit_start nw-acc-waker taskset -c "$CPUS" "$WORK/wake_truth" waker "$SHM" "$PAIRS" "$DUR" \
        || { bad "$name: could not start the wakers"; return; }
    while sudo -n systemctl is-active -q nw-acc-wakee; do sleep 0.5; done
    wait "$agent"
    stop_units

    [[ -s "$truth" ]] || { bad "$name: the wakees recorded nothing"; return; }
    local t_n t_p99 t_p999 row=()
    read -r t_n t_p99 t_p999 < <(python3 -c '
import sys
v = sorted(int(x) for x in open(sys.argv[1]))
print(len(v), round(v[int(.99 * len(v))] / 1e3), round(v[int(.999 * len(v))] / 1e3))' "$truth")
    read -r -a row < <(top_rows "$log" final | awk '$1 == "nw-acc-wakee.service"')
    note "truth:    events=$t_n p99=${t_p99}us p99.9=${t_p999}us"
    note "blame: ${row[*]:-<no row>}"
    (( ${#row[@]} == 7 )) || { bad "$name: no row for nw-acc-wakee.service"; return; }
    (( row[1] >= 100000 )) \
        && ok "$name: enough samples for a p99.9 (${row[1]})" \
        || bad "$name: only ${row[1]} samples; p99.9 is not reported below 100000"
    local col i pname want got err
    for col in 3:p99:$t_p99 4:p99.9:$t_p999; do
        IFS=: read -r i pname want <<<"$col"
        got=$(to_us "${row[$i]}")
        if [[ "$got" == "-" ]]; then
            bad "$name: $pname not reported"
            continue
        fi
        err=$(python3 -c "print(round(100 * ($got - $want) / $want, 1))")
        awk -v e="$err" -v l="$lo" -v h="$hi" 'BEGIN { exit !(e >= l && e <= h) }' \
            && ok "$name: $pname ${got}us vs known ${want}us (${err}%, allowed ${lo}..${hi}%)" \
            || bad "$name: $pname ${got}us vs known ${want}us (${err}%, allowed ${lo}..${hi}%)"
    done
}

echo "blame run-queue accuracy acceptance ($BIN)"
echo "  load=${DUR}s pairs=${PAIRS} cpus=${CPUS}"
echo
echo "[1] CPU hogs share the wakees' CPUs"
run_case mixed "$HOGS" "$MIXED_RANGE"
echo
echo "[2] idle CPUs"
run_case idle 0 "$IDLE_RANGE"
echo
echo "$PASS passed, $FAIL failed"
exit $(( FAIL > 0 ))
