#!/usr/bin/env bash
#
# Run-queue latency acceptance: measured correctly, cheaply, honestly. The
# machine's waits are read from `blame top --histogram`.
#
# Needs root or passwordless sudo, bpftool, taskset, python3.
#     ./tests/scenarios/m1_acceptance.sh [blame-binary]
# Env: BLAME_BIN (binary), SCN_DURATION (seconds per window, default 8),
#      STRICT_BUDGET=1 enforces the per-switch cost budget (use on bare metal)

set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -n "${1:-}" ]] && BLAME_BIN="$1"
resolve_bin || exit 1
need_root || exit 1

DUR="${SCN_DURATION:-8}"
WORK="$(mktemp -d)"
trap 'reap_tracked; rm -rf "$WORK"' EXIT

# --- thresholds ---------------------------------------------------------------
#
# PROVISIONAL: wide margins from a first run with a `runqlat` stand-in in a
# noisy 6-vCPU VM. Tighten once there are numbers from bare metal.
# Microseconds unless noted.

# Idle machine.
IDLE_P99_MAX_US=1024
# Oversubscribed: p99 must clear this floor...
CONTENTION_P99_MIN_US=2048
# ...and be at least this many times the idle p99.
CONTENTION_RATIO_MIN=2
# Waits at least this long are what preemption looks like.
LONG_WAIT_US=1000
# Extra long waits two hogs on one core must add over idle.
PREEMPT_EXTRA_MIN=50
# Total BPF time / sched_switch calls, ns. The budget is enforced only with
# STRICT_BUDGET=1: in a VM clock reads are expensive and the figure swings with
# the workload mix, so there it is reported and guarded by a looser ceiling
# meant to catch a fall back to a hash map. In the dev VM this workload
# measured 748-1239 with the array (11 runs) and 1437-1547 with a 10240-entry
# hash map for the wait start times (3 runs); the ceiling is the midpoint. The
# gap is about 16% against roughly 10% VM noise, so an occasional false alarm
# or miss is expected.
OVERHEAD_NS_BUDGET=500
VM_NS_GUARD=1340
# Share of total CPU capacity spent in the probes, percent.
SHARE_PCT_MAX=1.0
# The load must really switch, or the budget check is vacuous.
LOAD_MIN_CS_PER_CORE=1000

echo "blame M1 acceptance ($BIN)"
echo "  window=${DUR}s cpus=${NCPU}"
echo

# --- 1. Idle baseline ----------------------------------------------------------
echo "[1] idle baseline"
run_runq "$DUR" "$WORK/idle.log" || bad "agent failed; log follows: $(cat "$WORK/idle.log")"

idle_samples=$(field "$WORK/idle.log" samples)
idle_p99=$(bucket_pct "$WORK/idle.log" 99)
idle_long=$(samples_ge "$WORK/idle.log" "$LONG_WAIT_US")
note "samples=${idle_samples:-?} p99_us=${idle_p99:-?} waits>=${LONG_WAIT_US}us=${idle_long}"

(( ${idle_samples:-0} > 0 )) \
    && ok "an idle machine still produces samples" \
    || bad "no samples on an idle machine"
(( ${idle_p99:-999999999} <= IDLE_P99_MAX_US )) \
    && ok "idle p99 is sub-millisecond-scale (<= ${IDLE_P99_MAX_US}us)" \
    || bad "idle p99 ${idle_p99:-?}us exceeds ${IDLE_P99_MAX_US}us"

# --- 2. CPU contention ---------------------------------------------------------
echo
echo "[2] CPU contention"
start_hogs $((NCPU * 2)) "0-$((NCPU - 1))"
sleep 1
run_runq "$DUR" "$WORK/contend.log" || bad "agent failed; log follows: $(cat "$WORK/contend.log")"
reap_tracked

cont_p99=$(bucket_pct "$WORK/contend.log" 99)
note "p99_us=${cont_p99:-?} (idle was ${idle_p99:-?})"

(( ${cont_p99:-0} >= CONTENTION_P99_MIN_US )) \
    && ok "p99 under contention reaches ${CONTENTION_P99_MIN_US}us" \
    || bad "p99 under contention is only ${cont_p99:-?}us"
(( ${cont_p99:-0} >= ${idle_p99:-1} * CONTENTION_RATIO_MIN )) \
    && ok "p99 is at least ${CONTENTION_RATIO_MIN}x the idle p99" \
    || bad "p99 did not rise meaningfully over idle"

# --- 3. Preempted tasks --------------------------------------------------------
# Never-sleeping tasks sharing a CPU only wait when preempted. An implementation
# that counts only wakeups records nothing here.
echo
echo "[3] preempted tasks are counted"
last_cpu=$((NCPU - 1))
start_hogs 2 "$last_cpu"
sleep 1
run_runq "$DUR" "$WORK/preempt.log" || bad "agent failed; log follows: $(cat "$WORK/preempt.log")"
reap_tracked

pre_long=$(samples_ge "$WORK/preempt.log" "$LONG_WAIT_US")
note "waits>=${LONG_WAIT_US}us: ${pre_long} (idle window had ${idle_long})"

(( pre_long >= idle_long + PREEMPT_EXTRA_MIN )) \
    && ok "two always-runnable tasks on one CPU add $((pre_long - idle_long)) long waits" \
    || bad "no extra long waits: the preemption / re-queue path is probably not being measured"

# --- 4. Losses are visible -----------------------------------------------------
# Overflow the wait table; loss must be counted and flagged.
echo
echo "[4] a full table is counted and flagged"
start_hogs $((NCPU * 2)) "0-$((NCPU - 1))"
sleep 1
run_runq "$DUR" "$WORK/full.log" --runq-start-entries 2 \
    || bad "agent failed; log follows: $(cat "$WORK/full.log")"
reap_tracked

failed=$(field "$WORK/full.log" runq_start_insert_failed)
note "runq_start_insert_failed=${failed:-?}"

(( ${failed:-0} > 0 )) \
    && ok "insert failures are counted ($failed)" \
    || bad "a 2-entry table under load recorded no failures"
grep -qE 'runq_start_insert_failed=[0-9]+ \(!\)' "$WORK/full.log" \
    && ok "loss is flagged in the report" \
    || bad "non-zero loss was not flagged"
neg=$(field "$WORK/full.log" runq_negative_delta)
(( ${neg:-1} == 0 )) \
    && ok "no negative deltas (clock is sane)" \
    || bad "negative deltas observed: ${neg:-?}"

# --- 5. Overhead ---------------------------------------------------------------
# Service-like load, cost from BPF runtime stats (agent CPU would miss it).
echo
echo "[5] kernel-side cost"
LOAD_SECS=$((DUR + 6))
spawn python3 "$SCN_DIR/workloads/service_load.py" \
    --servers 4 --server-cpus 0-3 --clients 2 --client-cpus 4-5 \
    --rate 6000 --duration "$LOAD_SECS" --warmup 2
sleep 3   # let the workload reach steady state before measuring
cs0=$(ctxt_total); t0=$(date +%s.%N)
run_runq "$DUR" "$WORK/cost.log" || bad "agent failed; log follows: $(cat "$WORK/cost.log")"
cs1=$(ctxt_total); t1=$(date +%s.%N)
reap_tracked

per_core=$(python3 -c "print(round(($cs1 - $cs0) / ($t1 - $t0) / $NCPU))")
ns_per_switch=$(field "$WORK/cost.log" ns_per_switch)
share=$(field "$WORK/cost.log" share_pct)
note "switches/cpu/s=${per_core} ns_per_switch=${ns_per_switch:-?} bpf_share=${share:-?}%"

(( per_core >= LOAD_MIN_CS_PER_CORE )) \
    && ok "workload is switching enough to be meaningful (${per_core}/cpu/s)" \
    || bad "workload only reached ${per_core} switches/cpu/s; the budget check would be vacuous"
if [[ -z "$ns_per_switch" ]]; then
    bad "cost per switch was not reported"
elif [[ "${STRICT_BUDGET:-0}" == 1 ]]; then
    (( ns_per_switch <= OVERHEAD_NS_BUDGET )) \
        && ok "${ns_per_switch} ns per switch <= budget of ${OVERHEAD_NS_BUDGET} ns" \
        || bad "cost ${ns_per_switch} ns per switch (budget ${OVERHEAD_NS_BUDGET} ns)"
else
    (( ns_per_switch <= OVERHEAD_NS_BUDGET )) \
        && note "within the ${OVERHEAD_NS_BUDGET} ns budget (not enforced without STRICT_BUDGET=1)" \
        || note "over the ${OVERHEAD_NS_BUDGET} ns budget (not enforced without STRICT_BUDGET=1)"
    (( ns_per_switch <= VM_NS_GUARD )) \
        && ok "${ns_per_switch} ns per switch <= regression ceiling of ${VM_NS_GUARD} ns" \
        || bad "cost ${ns_per_switch} ns per switch exceeds the ${VM_NS_GUARD} ns regression ceiling"
fi
[[ -n "$share" ]] && awk -v s="$share" -v m="$SHARE_PCT_MAX" 'BEGIN { exit !(s <= m) }' \
    && ok "probes use ${share}% of CPU capacity (<= ${SHARE_PCT_MAX}%)" \
    || bad "probes use ${share:-<not reported>}% of CPU capacity (limit ${SHARE_PCT_MAX}%)"

# --- 6. Nothing survives SIGKILL -----------------------------------------------
# Nothing is pinned; compare program ids (names can collide with other tools).
echo
echo "[6] no residue after SIGKILL"
before=$(bpf_prog_ids)
sudo -n "$BIN" top >"$WORK/kill.log" 2>&1 &
AGENT_JOB=$!
for _ in $(seq 100); do
    grep -q 'top attached' "$WORK/kill.log" 2>/dev/null && break
    sleep 0.1
done
grep -q 'top attached' "$WORK/kill.log" 2>/dev/null \
    || bad "agent never reported being attached; log follows: $(cat "$WORK/kill.log")"

during=$(bpf_prog_ids)
[[ "$during" != "$before" ]] \
    && ok "programs are loaded while the agent runs" \
    || bad "no new programs appeared while the agent was running"

for pid in $(live_agents); do sudo -n kill -KILL "$pid" 2>/dev/null; done
wait "$AGENT_JOB" 2>/dev/null
sleep 0.5   # let the kernel reclaim the fds the dead process held

after=$(bpf_prog_ids)
leaked=$(comm -13 <(echo "$before") <(echo "$after") | grep -c .)
note "programs leaked=${leaked}"

(( leaked == 0 )) \
    && ok "no orphaned programs" \
    || bad "$leaked program(s) survived SIGKILL"
[[ -z "$(live_agents)" ]] \
    && ok "agent process is gone" \
    || bad "agent survived SIGKILL"

run_runq 2 "$WORK/restart.log" \
    && ok "agent restarts cleanly after SIGKILL" \
    || bad "agent could not restart after SIGKILL"

echo
echo "$PASS passed, $FAIL failed"
exit $(( FAIL > 0 ))
