#!/usr/bin/env bash
#
# M0 acceptance: the kernel-to-userspace path is correct, its losses are
# visible and accurate, and nothing survives the agent's death.
#
# Requires root (or passwordless sudo) and bpftool. Run from the repo root:
#
#     ./tests/scenarios/m0_acceptance.sh [blame-binary]
# Env: BLAME_BIN (binary)

set -uo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -n "${1:-}" ]] && BLAME_BIN="$1"
resolve_bin || exit 1
WORK="$(mktemp -d)"
trap 'resume_agent 2>/dev/null; sudo -n pkill -KILL -x "$AGENT_NAME" 2>/dev/null; rm -rf "$WORK"' EXIT

# Read a `name=value` field out of the agent's final stats block.
stat_field() { grep -oP "(?<=\b$2=)\d+" "$1" | tail -1; }

# Generate exactly $1 exec events.
generate_execs() { local n=$1; for ((i = 0; i < n; i++)); do /bin/true; done; }

# Agents that have exited but not yet been reaped still appear in `pgrep` and
# still answer `kill -0`, while being immune to `kill -KILL`. Treating a zombie
# as running deadlocks every wait loop below, so filter them out.
live_agents() {
    local pid
    for pid in $(pgrep -x "$AGENT_NAME"); do
        grep -q '^State:.*Z' "/proc/$pid/status" 2>/dev/null && continue
        echo "$pid"
    done
}

ensure_no_agent() {
    sudo -n pkill -CONT -x "$AGENT_NAME" 2>/dev/null
    sudo -n pkill -KILL -x "$AGENT_NAME" 2>/dev/null
    for _ in $(seq 50); do
        [[ -z "$(live_agents)" ]] && return 0
        sleep 0.1
    done
    echo "could not clear pre-existing blame processes" >&2
    return 1
}

start_agent() {
    ensure_no_agent || return 1
    sudo -n "$BIN" --stats-interval 3600 "$@" >"$WORK/agent.log" 2>&1 &
    # `wait` on this job is what actually reaps the agent; without it every exit
    # leaves a zombie behind.
    AGENT_JOB=$!
    for _ in $(seq 50); do
        AGENT_PID="$(live_agents | head -1)"
        [[ -n "$AGENT_PID" ]] && sleep 0.5 && return 0
        sleep 0.1
    done
    echo "agent failed to start; log follows:" >&2
    cat "$WORK/agent.log" >&2
    return 1
}

# Suspend only the agent. `sudo` suspends itself alongside its child for job
# control transparency, which matters when resuming (see `resume_agent`).
freeze_agent() { sudo -n kill -STOP "$AGENT_PID"; }

# Resume both halves of the job. Resuming only the agent leaves `sudo` stopped,
# and a stopped parent cannot reap its child -- the agent would exit into a
# permanent zombie and every `wait` below would block forever.
resume_agent() {
    kill -CONT "$AGENT_JOB" 2>/dev/null
    sudo -n kill -CONT "$AGENT_PID" 2>/dev/null
}

# Signal the agent, then block until the whole `sudo` job is reaped.
reap_agent() {
    resume_agent
    sudo -n kill "-$1" "$AGENT_PID" 2>/dev/null
    wait "$AGENT_JOB" 2>/dev/null
    [[ -z "$(live_agents)" ]]
}

stop_agent() { reap_agent INT; }

echo "blame M0 acceptance ($BIN)"
echo

# --- 1. The pipeline delivers every event it claims to produce ----------------
echo "[1] pipeline correctness"
N=5000
start_agent || exit 1
generate_execs "$N"
sleep 1
stop_agent || bad "agent did not exit on SIGINT"

produced=$(stat_field "$WORK/agent.log" events_produced)
consumed=$(stat_field "$WORK/agent.log" consumed)
full=$(stat_field "$WORK/agent.log" ringbuf_full)
note "generated=$N produced=$produced consumed=$consumed ringbuf_full=$full"

[[ "$produced" == "$consumed" ]] \
    && ok "produced == consumed ($produced)" \
    || bad "produced=$produced != consumed=$consumed"
# Other processes on the box also exec, so this is a floor, not an equality.
(( produced >= N )) \
    && ok "observed at least the $N generated execs" \
    || bad "observed only $produced of $N generated execs"
(( full == 0 )) \
    && ok "no drops at the default ring buffer size" \
    || bad "unexpected drops with a full-size ring buffer: $full"
grep -q "reconcile  ok" "$WORK/agent.log" \
    && ok "self-reconciliation clean" \
    || bad "self-reconciliation reported a mismatch"

# --- 2. Losses are counted, not silent ---------------------------------------
# Freeze the consumer so the ring buffer is guaranteed to overflow. The eBPF
# program keeps running in the kernel while the process is stopped, which is the
# point: kernel-side accounting must survive a dead consumer.
echo
echo "[2] loss accounting under a stalled consumer"
N=2000
start_agent --ringbuf-bytes "$(getconf PAGESIZE)" || exit 1
freeze_agent
generate_execs "$N"
resume_agent
sleep 1
stop_agent || bad "agent did not exit on SIGINT"

produced=$(stat_field "$WORK/agent.log" events_produced)
full=$(stat_field "$WORK/agent.log" ringbuf_full)
total=$((produced + full))
note "generated=$N produced=$produced ringbuf_full=$full accounted=$total"

(( full > 0 )) \
    && ok "drops were detected and counted ($full)" \
    || bad "a page-sized ring buffer did not overflow; the test is not exercising loss"
# Every generated exec must land in exactly one bucket. Allow a small upward
# margin for unrelated processes exec'ing during the window.
(( total >= N && total <= N + 200 )) \
    && ok "every event accounted for: produced + dropped = $total ~= $N" \
    || bad "accounting gap: produced + dropped = $total, expected ~$N"
grep -q "ringbuf_full=$full (!)" "$WORK/agent.log" \
    && ok "loss is flagged in the report" \
    || bad "non-zero loss was not flagged"

# --- 3. SIGKILL leaves nothing behind ----------------------------------------
# Nothing is pinned, so the kernel should reclaim programs and maps when the
# last fd closes. A leak here means a killed agent keeps burning CPU forever.
echo
echo "[3] no residue after SIGKILL"
start_agent || exit 1
reap_agent KILL || bad "agent survived SIGKILL"
sleep 0.5   # let the kernel reclaim the fds the dead process held

residual_progs=$(sudo -n bpftool prog show 2>/dev/null | grep -c "sched_process_exec")
residual_maps=$(sudo -n bpftool map show 2>/dev/null | grep -cE "name (EVENTS|COUNTERS)")
note "residual programs=$residual_progs maps=$residual_maps"

(( residual_progs == 0 )) \
    && ok "no orphaned programs" \
    || bad "$residual_progs orphaned program(s) still attached"
(( residual_maps == 0 )) \
    && ok "no orphaned maps" \
    || bad "$residual_maps orphaned map(s) still allocated"

start_agent || bad "agent could not restart after a SIGKILL"
stop_agent
ok "agent restarts cleanly after SIGKILL"

echo
echo "$PASS passed, $FAIL failed"
exit $(( FAIL > 0 ))
