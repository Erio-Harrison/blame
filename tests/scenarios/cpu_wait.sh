#!/usr/bin/env bash
#
# What a process's threads waited for a CPU, and what the CPU did meanwhile:
# the four figures of `process_cpu` (own threads had it, a CPU limit kept
# them off it, others had it, it was idle), case by case.
#
# Each case runs a server that knows nothing of this, loads it, and compares
# blame's four figures with three counts that do not come from blame:
#   - an oracle on the scheduler's tracepoints (tests/tools/cpu_wait_oracle.py,
#     bpftrace): for each wait, what the CPU the thread was queued on ran of
#     the same process and what it was idle, from the switches alone;
#   - the kernel's count of what the threads waited (schedstat), which starts
#     when a thread is on the queue: a little after the wakeup was issued, and
#     for a thread woken onto an idle CPU only once that CPU has woken up, so
#     that it has none of the wait for an idle CPU;
#   - where there is a limit, the control group's own throttled time
#     (cpu.stat), which is the group's, not the threads': one thread waiting
#     makes the two equal, several make the threads' a multiple.
# Then what the case is about: which of the four the wait is.
#
# What the oracle cannot say: it follows the same rule within a wait that has
# a limit in it (the limit first, then what the CPU was idle beyond it), and
# does not know when in the wait the CPU was idle either. What that can have
# put on the wrong side is at most what such waits have left after own
# threads and the limit; each case with a limit says how much that was.
#
# The cases, and where each came from:
#   [1]  own       four workers on one CPU, alone: they wait for each other
#   [2]  others    one worker, two processes spinning on its CPU
#   [3]  idle      one thread alone on a CPU: every wakeup finds it idle. The
#                  "others" of a two-part split was mostly this.
#   [4]  limit     one thread, a quarter of a CPU: the CPU is idle and the
#                  thread runnable. A two-part split called this "others".
#   [5]  limit     four workers under the limit: limit and own threads
#   [6]  no limit  in a control group without one: no limit time
#   [7]  limit     under a limit while others spin on the CPU: the limit, not
#                  the others, is what keeps the threads off it
#   [8]  limit     the limit on a group above the server's
#   [9]  two CPUs  four workers on two CPUs: waits that move between queues
#   [10] two CPUs  the same under a limit: the throttled time moves with them
#   [11] siblings  two processes of one service on one CPU: each is the
#                  other's "others" (the figures are per process)
#   [12] idle      many threads woken together on idle CPUs (a pool on as
#                  many CPUs as workers): as an OpenMP team's
#   [13] Go        a Go server on one CPU, alone, then with the CPU taken,
#                  then under a limit
#   [14] tokio     the same for a tokio server
#   [15] docker    a container with --cpus: the limit as a container runtime
#                  sets it
#   [16] threads   a thread per request: threads that wait before their first
#                  turn, and run only one. Followed from their first switch
#                  off a CPU they were nobody's: their turn was "others" to
#                  the rest, and their first wait was not counted at all.
#   [18] affinity  the CPUs the server's threads may use are changed again and
#                  again while they wait: threads moved off a queue by force
#   [19] limit     the limit is taken off and put back while the server runs
#   [20] stopped   the server is stopped and continued (SIGSTOP, SIGCONT): a
#                  stopped thread is not waiting for a CPU
#   [17] random    servers, CPUs, limits, spinning neighbours and loads drawn
#                  at random (CPU_WAIT_SEED, CPU_WAIT_RANDOM cases, default 6)
#
#     ./tests/scenarios/cpu_wait.sh [blame-binary]
# Needs root through sudo, bpftrace and bpftool (the oracle), a kernel from
# 6.6 with group scheduling for the limit cases, at least 4 CPUs.
# Env: BLAME_BIN, SCN_DURATION (seconds of load per case, default 4),
#      ONLY (space separated case numbers; default all), GO, KEEP_WORK=1,
#      CPU_WAIT_IMAGE (default debian:stable-slim; [15] only if it is here).

set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -n "${1:-}" ]] && BLAME_BIN="$1"
resolve_bin || exit 1
need_root || exit 1
command -v bpftrace >/dev/null && command -v bpftool >/dev/null || { echo "needs bpftrace and bpftool" >&2; exit 1; }
(( NCPU >= 4 )) || { echo "needs at least 4 CPUs" >&2; exit 1; }

DUR="${SCN_DURATION:-4}"
PORT=19300
WORK="$(mktemp -d)"
chmod 755 "$WORK"
AGENT_JOB=""
ORACLE_JOB=""
CG="/sys/fs/cgroup/blame-cpu-wait-$$"
CONTAINER=""
cleanup() {
    stop_agent
    [[ -n "$ORACLE_JOB" ]] && { sudo -n pkill -INT -P "$ORACLE_JOB" 2>/dev/null; wait "$ORACLE_JOB" 2>/dev/null; }
    [[ -n "$CONTAINER" ]] && sudo -n docker rm -f "$CONTAINER" >/dev/null 2>&1
    reap_tracked
    sudo -n rmdir "$CG/inner" "$CG" 2>/dev/null
    if [[ -n "${KEEP_WORK:-}" ]]; then echo "work directory kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

cc -O2 -pthread -o "$WORK/http_truth" "$SCN_DIR/../tools/http_truth.c" || exit 1
cc -O2 -Wall -pthread -o "$WORK/http_load" "$SCN_DIR/../tools/http_load.c" || exit 1

le() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 <= b + 0) }'; }
ge() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 >= b + 0) }'; }
ms() { echo $(( ${1:-0} / 1000000 )); }
pct() { (( ${2:-0} > 0 )) && echo $(( $1 * 100 / $2 )) || echo 0; }
want() { [[ -z "${ONLY:-}" || " $ONLY " == *" $1 "* ]]; }

start_agent() {
    local log=$1
    shift
    sudo -n "$BIN" slow --raw --above 0 --interval 0 "$@" >"$log" 2>&1 &
    AGENT_JOB=$!
    for _ in $(seq 100); do
        grep -q 'slow attached' "$log" 2>/dev/null && return 0
        sleep 0.1
    done
    bad "agent never reported being attached: $(cat "$log")"
    stop_agent
    return 1
}
stop_agent() {
    [[ -z "$AGENT_JOB" ]] && return
    sleep 0.5
    local pid
    for pid in $(live_agents); do sudo -n kill -INT "$pid" 2>/dev/null; done
    wait "$AGENT_JOB" 2>/dev/null
    AGENT_JOB=""
}

# The CPUs: the server's one, its two, and the load's.
C1=$((NCPU - 1))
C2="$((NCPU - 2))-$((NCPU - 1))"
CLOAD="0-$((NCPU - 3))"
QUOTA="25000 100000"   # a quarter of a CPU

# Whether this kernel counts a group's throttled time (kernel.h, 6.6 on).
LIMIT_KEPT=
(( $(sudo -n bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep -c "throttled_clock_self_time") > 0 )) && LIMIT_KEPT=1

waited() { cat /proc/"$1"/task/*/schedstat 2>/dev/null | awk '{ s += $2 } END { printf "%d\n", s }'; }
throttled() { [[ -n "$1" ]] && awk '$1 == "throttled_usec" { printf "%d\n", $2 * 1000 }' "$1/cpu.stat" 2>/dev/null || echo 0; }
# A control group with a CPU limit (or "max"), optionally one inside it
# without: the path of the one to put the server in lands in CG_IN, the path
# of the one with the limit in CG_LIMITED.
make_group() {
    local limit=$1 nested=${2:-}
    sudo -n rmdir "$CG/inner" "$CG" 2>/dev/null
    sudo -n mkdir "$CG" || return 1
    echo "$limit" | sudo -n tee "$CG/cpu.max" >/dev/null || return 1
    CG_LIMITED=$CG CG_IN=$CG
    if [[ -n "$nested" ]]; then
        echo "+cpu" | sudo -n tee "$CG/cgroup.subtree_control" >/dev/null || return 1
        sudo -n mkdir "$CG/inner" || return 1
        CG_IN=$CG/inner
    fi
}
drop_group() { sudo -n rmdir "$CG/inner" "$CG" 2>/dev/null; CG_IN="" CG_LIMITED=""; }

# run NAME PID [GROUP] -- LOAD...: blame and the oracle on the process while
# the load runs. Sets, in ns: B_OWN B_LIMIT B_OTHERS B_IDLE B_TOTAL (blame),
# O_OWN O_LIMIT O_OTHERS O_IDLE O_TOTAL O_MOVED_PCT O_LIMITED_IDLE (oracle),
# K_WAITED (schedstat), K_THROTTLED (the group's cpu.stat).
run() {
    local name=$1 pid=$2 group=${3:-} waited0 throttled0 line
    shift 3; [[ "${1:-}" == "--" ]] && shift
    python3 "$SCN_DIR/../tools/cpu_wait_oracle.py" script "$pid" > "$WORK/$name.bt" || { bad "$name: no oracle"; return 1; }
    start_agent "$WORK/$name.log" --pid "$pid" || return 1
    sudo -n bpftrace "$WORK/$name.bt" > "$WORK/$name.oracle" 2>/dev/null &
    ORACLE_JOB=$!
    for _ in $(seq 200); do grep -q '^ready' "$WORK/$name.oracle" 2>/dev/null && break; sleep 0.1; done
    waited0=$(waited "$pid"); throttled0=$(throttled "$group")
    "$@" >/dev/null 2>&1
    K_WAITED=$(( $(waited "$pid") - waited0 )); K_THROTTLED=$(( $(throttled "$group") - throttled0 ))
    sudo -n pkill -INT -P "$ORACLE_JOB" 2>/dev/null; wait "$ORACLE_JOB" 2>/dev/null; ORACLE_JOB=""
    stop_agent
    line=$(grep "^process_cpu pid=$pid " "$WORK/$name.log" | tail -1)
    b() { echo "$line" | grep -oP "\b$1=\K[0-9]+" || echo 0; }
    B_OWN=$(b runq_own_threads_ns) B_LIMIT=$(b runq_cpu_limit_ns) B_OTHERS=$(b runq_others_ns) B_IDLE=$(b runq_cpu_idle_ns)
    B_TOTAL=$((B_OWN + B_LIMIT + B_OTHERS + B_IDLE))
    line=$(python3 "$SCN_DIR/../tools/cpu_wait_oracle.py" sum "$WORK/$name.oracle" | grep "^pid=$pid ")
    O_OWN=$(b own) O_LIMIT=$(b limit) O_OTHERS=$(b others) O_IDLE=$(b idle_cpu) O_TOTAL=$(b wait)
    O_MOVED_PCT=$(pct "$(b moved_waits)" "$(b waits)") O_LIMITED_IDLE=$(b limited_idle) O_LIMITED_REST=$(b limited_rest)
    note "$name: blame  own=$(ms $B_OWN) limit=$(ms $B_LIMIT) others=$(ms $B_OTHERS) idle=$(ms $B_IDLE) ms"
    note "$name: oracle own=$(ms $O_OWN) limit=$(ms $O_LIMIT) others=$(ms $O_OTHERS) idle=$(ms $O_IDLE) ms, $(b waits) waits, $O_MOVED_PCT% moved; schedstat $(ms $K_WAITED) ms; group throttled $(ms $K_THROTTLED) ms"
    (( B_TOTAL > 0 && O_TOTAL > 0 )) || { bad "$name: no figures (blame $B_TOTAL ns, oracle $O_TOTAL ns)"; return 1; }
}

# Each of the four within a tenth of the oracle's, or 3% of all the wait, or 5 ms
# (a server that hardly waits at all).
agree() {
    local name=$1 part b o wrong=""
    for part in OWN LIMIT OTHERS IDLE; do
        b=B_$part o=O_$part
        awk -v b="${!b}" -v o="${!o}" -v t="$O_TOTAL" 'BEGIN { d = b - o; if (d < 0) d = -d; m = o / 10; if (t * 0.03 > m) m = t * 0.03; if (m < 5e6) m = 5e6; exit !(d <= m) }' \
            || wrong+=" $part: $(ms ${!b}) against $(ms ${!o}) ms;"
    done
    [[ -z "$wrong" ]] && ok "$name: the four figures are the oracle's (own $(ms $B_OWN), limit $(ms $B_LIMIT), others $(ms $B_OTHERS), idle $(ms $B_IDLE) ms)" \
        || bad "$name: against the oracle:$wrong"
    # All but the wait for an idle CPU, which the kernel's count starts after.
    local queued=$((B_TOTAL - B_IDLE))
    if (( K_WAITED < 200000000 )); then
        note "$name: schedstat counted $(ms $K_WAITED) ms: too little to compare"
    else
        ge "$queued" "$(( K_WAITED * 90 / 100 ))" && le "$queued" "$(( K_WAITED * 150 / 100 ))" \
            && ok "$name: all but the idle part is the kernel's count and what precedes it ($(ms $queued) ms, schedstat $(ms $K_WAITED) ms)" \
            || bad "$name: all but the idle part is $(ms $queued) ms, schedstat $(ms $K_WAITED) ms"
    fi
}
# is NAME PART MIN_PCT: that part is at least so much of the wait.
is() {
    local v=B_$2
    ge "$(pct "${!v}" "$B_TOTAL")" "$3" \
        && ok "$1: ${2,,} is $(pct "${!v}" "$B_TOTAL")% of the wait" \
        || bad "$1: ${2,,} is $(pct "${!v}" "$B_TOTAL")% of the wait, expected $3% or more"
}
# under NAME PART MAX_PCT: that part is at most so much of the wait.
under() {
    local v=B_$2
    le "$(pct "${!v}" "$B_TOTAL")" "$3" \
        && ok "$1: ${2,,} is $(pct "${!v}" "$B_TOTAL")% of the wait" \
        || bad "$1: ${2,,} is $(pct "${!v}" "$B_TOTAL")% of the wait, expected $3% or less"
}
# The threads' limit time against the group's: equal with one thread, a multiple with several.
limit_is_groups() {
    local name=$1 most=$2
    # What the rule within a limited wait cannot place for sure (see the top).
    le "$O_LIMITED_REST" "$(( O_TOTAL / 50 ))" \
        && ok "$name: at most $(ms $O_LIMITED_REST) ms of $(ms $O_TOTAL) could be on the wrong side between idle and others" \
        || note "$name: up to $(ms $O_LIMITED_REST) ms of $(ms $O_TOTAL) could be on the wrong side between idle and others"
    (( K_THROTTLED > 100000000 )) && ge "$B_LIMIT" "$(( K_THROTTLED * 90 / 100 ))" && le "$B_LIMIT" "$(( K_THROTTLED * most / 100 ))" \
        && ok "$name: the limit time is the group's throttled time ($(ms $B_LIMIT) ms, cpu.stat $(ms $K_THROTTLED) ms)" \
        || bad "$name: limit $(ms $B_LIMIT) ms, the group's cpu.stat $(ms $K_THROTTLED) ms (expected 90% to $most% of it)"
}

# server KIND CPUS [GROUP_LIMIT [nested]] [ARGS...]: a test server on CPUS,
# in a control group if a limit ("max" for none) is given. Its pid in SERVER_PID.
server() {
    local kind=$1 cpus=$2 limit=${3:-} nested=${4:-}
    shift 2; (( $# )) && shift; (( $# )) && shift
    case $kind in
    pool|epoll|tpc) spawn taskset -c "$cpus" "$WORK/http_truth" "$kind" "$PORT" "$WORK/server.bin" "$@" ;;
    *)          spawn taskset -c "$cpus" "$kind" "$PORT" "$WORK/server.bin" "$@" ;;
    esac
    SERVER_PID="${_TRACKED[-1]}"
    sleep 0.4
    CG_IN="" CG_LIMITED=""
    if [[ -n "$limit" ]]; then
        make_group "$limit" "$nested" && echo "$SERVER_PID" | sudo -n tee "$CG_IN/cgroup.procs" >/dev/null \
            || { bad "no control group with a CPU limit could be made"; return 1; }
    fi
}
done_with() { reap_tracked; drop_group; }
load() { taskset -c "$CLOAD" "$WORK/http_load" "$PORT" "$@"; }
WORKLOAD="/n?size=200&cpu=300"

want 1 && {
echo "[1] four workers on one CPU, alone"
server pool "$C1" "" "" -w 4 && run own "$SERVER_PID" "" -- load 8 "$DUR" 0 "$WORKLOAD" && {
    agree own; is own OWN 70; under own LIMIT 0
}
done_with
}

want 2 && {
echo "[2] one worker, two processes spinning on its CPU"
server pool "$C1" "" "" -w 1 && { start_hogs 2 "$C1"; run others "$SERVER_PID" "" -- load 8 "$DUR" 0 "$WORKLOAD"; } && {
    agree others; is others OTHERS 80; under others IDLE 5
}
done_with
}

want 3 && {
echo "[3] one thread alone on a CPU: every wakeup finds it idle"
server epoll "$C1" && run idle "$SERVER_PID" "" -- load 2 "$DUR" 1000 "$WORKLOAD" && {
    agree idle; is idle IDLE 50; under idle OWN 5
    # The kernel's count does not have this wait at all.
    le "$K_WAITED" "$(( B_IDLE / 2 ))" && ok "idle: schedstat has none of it ($(ms $K_WAITED) ms against $(ms $B_IDLE))" \
        || bad "idle: schedstat counted $(ms $K_WAITED) ms, the wait for an idle CPU is $(ms $B_IDLE) ms"
}
done_with
}

if [[ -z "$LIMIT_KEPT" ]]; then
    note "this kernel does not count a group's throttled time: the limit cases [4] to [8], [10] are skipped"
else
want 4 && {
echo "[4] one thread under a limit of a quarter of a CPU"
server epoll "$C1" "$QUOTA" && run limit1 "$SERVER_PID" "$CG_LIMITED" -- load 8 "$DUR" 0 "$WORKLOAD" && {
    agree limit1; is limit1 LIMIT 80; under limit1 OTHERS 10; limit_is_groups limit1 110
}
done_with
}

want 5 && {
echo "[5] four workers under the limit"
server pool "$C1" "$QUOTA" "" -w 4 && run limit4 "$SERVER_PID" "$CG_LIMITED" -- load 8 "$DUR" 0 "$WORKLOAD" && {
    agree limit4; is limit4 LIMIT 50; under limit4 OTHERS 10; limit_is_groups limit4 600
}
done_with
}

want 6 && {
echo "[6] in a control group without a limit"
server pool "$C1" max "" -w 4 && run nolimit "$SERVER_PID" "$CG_LIMITED" -- load 8 "$DUR" 0 "$WORKLOAD" && {
    agree nolimit; under nolimit LIMIT 0; is nolimit OWN 70
    (( K_THROTTLED == 0 )) && ok "nolimit: the group was never throttled" || bad "nolimit: the group was throttled $(ms $K_THROTTLED) ms"
}
done_with
}

want 7 && {
echo "[7] under the limit while two processes spin on the CPU"
server epoll "$C1" "$QUOTA" && { start_hogs 2 "$C1"; run limitbusy "$SERVER_PID" "$CG_LIMITED" -- load 8 "$DUR" 0 "$WORKLOAD"; } && {
    agree limitbusy
    # The CPU is never idle here: only the kernel's count tells the limit from the others.
    limit_is_groups limitbusy 110
    under limitbusy IDLE 5
    (( O_LIMITED_IDLE * 10 < B_LIMIT )) && ok "limitbusy: the CPU was busy through the limit ($(ms $O_LIMITED_IDLE) ms idle of $(ms $B_LIMIT))" \
        || bad "limitbusy: the CPU was idle $(ms $O_LIMITED_IDLE) ms of the $(ms $B_LIMIT) ms under the limit: the case does not test what it says"
}
done_with
}

want 8 && {
echo "[8] the limit on the group above the server's"
server pool "$C1" "$QUOTA" nested -w 4 && run nested "$SERVER_PID" "$CG_LIMITED" -- load 8 "$DUR" 0 "$WORKLOAD" && {
    agree nested; is nested LIMIT 50; limit_is_groups nested 600
}
done_with
}
fi

want 9 && {
echo "[9] four workers on two CPUs"
server pool "$C2" "" "" -w 4 && run twocpus "$SERVER_PID" "" -- load 6 "$DUR" 400 "$WORKLOAD" && {
    agree twocpus
    (( O_MOVED_PCT >= 2 )) && ok "twocpus: waits moved between the queues ($O_MOVED_PCT%)" \
        || note "twocpus: only $O_MOVED_PCT% of the waits moved between the queues"
}
done_with
}

[[ -n "$LIMIT_KEPT" ]] && want 10 && {
echo "[10] four workers on two CPUs under the limit"
# Three quarters of a CPU and pauses in the load: the threads sleep between
# the throttled stretches, and wake on either CPU.
server pool "$C2" "75000 100000" "" -w 4 && run twolimit "$SERVER_PID" "$CG_LIMITED" -- load 6 "$DUR" 400 "$WORKLOAD" && {
    agree twolimit; is twolimit LIMIT 30; limit_is_groups twolimit 600
    (( O_MOVED_PCT >= 2 )) && ok "twolimit: waits moved between the queues ($O_MOVED_PCT%)" \
        || note "twolimit: only $O_MOVED_PCT% of the waits moved between the queues"
}
done_with
}

want 11 && {
echo "[11] two processes of one service on one CPU"
server pool "$C1" "" "" -w 2 && {
    spawn taskset -c "$C1" "$WORK/http_truth" pool $((PORT + 1)) "$WORK/sibling.bin" -w 2
    sleep 0.3
    taskset -c "$CLOAD" "$WORK/http_load" $((PORT + 1)) 8 $((DUR + 8)) 0 "$WORKLOAD" >/dev/null 2>&1 &
    sibling_load=$!
    run siblings "$SERVER_PID" "" -- load 8 "$DUR" 0 "$WORKLOAD"
} && {
    agree siblings
    # Per process: the other process of the same service is "others".
    is siblings OTHERS 30
}
kill "${sibling_load:-0}" 2>/dev/null; wait "${sibling_load:-0}" 2>/dev/null
done_with
}

want 12 && {
echo "[12] four workers woken on four CPUs that are mostly idle"
C4="$((NCPU - 4))-$((NCPU - 1))"
server pool "$C4" "" "" -w 4 && run wakeidle "$SERVER_PID" "" -- taskset -c 0 "$WORK/http_load" "$PORT" 4 "$DUR" 2000 "$WORKLOAD" && {
    agree wakeidle; is wakeidle IDLE 50
}
done_with
}

# rt NAME SERVER: a runtime's server on one CPU: alone, with the CPU taken, under a limit.
rt() {
    local name=$1 bin=$2
    server "$bin" "$C1" "" "" -p 2 && run "$name-alone" "$SERVER_PID" "" -- load 8 "$DUR" 0 "$WORKLOAD" && {
        agree "$name-alone"; under "$name-alone" LIMIT 0
    }
    done_with
    server "$bin" "$C1" "" "" -p 2 && { start_hogs 2 "$C1"; run "$name-taken" "$SERVER_PID" "" -- load 8 "$DUR" 0 "$WORKLOAD"; } && {
        # Its two threads are busy too, and wait for each other as well.
        agree "$name-taken"; is "$name-taken" OTHERS 50
    }
    done_with
    [[ -n "$LIMIT_KEPT" ]] && {
        server "$bin" "$C1" "$QUOTA" "" -p 2 && run "$name-limit" "$SERVER_PID" "$CG_LIMITED" -- load 8 "$DUR" 0 "$WORKLOAD" && {
            agree "$name-limit"; is "$name-limit" LIMIT 50; under "$name-limit" OTHERS 10; limit_is_groups "$name-limit" 800
        }
        done_with
    }
}

want 13 && {
echo "[13] a Go server"
GO_CMD="${GO:-$(command -v go || true)}"
if [[ -n "$GO_CMD" ]] && (cd "$SCN_DIR/../tools/go_truth" && GOTOOLCHAIN=local "$GO_CMD" build -o "$WORK/go_truth" .); then
    rt go "$WORK/go_truth"
else
    note "no Go toolchain (set GO or put go on PATH), or the server did not build: skipped"
fi
}

want 14 && {
echo "[14] a tokio server"
TT_TARGET="$(dirname "$(dirname "$BIN")")/tokio_truth"
tt_build() { cargo build --release --quiet "$@" --manifest-path "$SCN_DIR/../tools/tokio_truth/Cargo.toml" --target-dir "$TT_TARGET"; }
if { tt_build --offline 2>/dev/null || tt_build; }; then
    rt tokio "$TT_TARGET/release/tokio_truth"
else
    note "the tokio server did not build: skipped"
fi
}

[[ -n "$LIMIT_KEPT" ]] && want 15 && {
echo "[15] a container with --cpus"
IMAGE="${CPU_WAIT_IMAGE:-debian:stable-slim}"
if sudo -n docker image inspect "$IMAGE" >/dev/null 2>&1; then
    CONTAINER="blame-cpu-wait-$$"
    sudo -n docker run -d --rm --name "$CONTAINER" --network host --user "$(id -u):$(id -g)" --cpuset-cpus "$C1" --cpus 0.25 \
        -v "$WORK:/work" "$IMAGE" /work/http_truth pool "$PORT" /work/server.bin -w 4 >/dev/null \
        && SERVER_PID=$(sudo -n docker inspect -f '{{.State.Pid}}' "$CONTAINER") && sleep 0.5 \
        && run docker "$SERVER_PID" "/sys/fs/cgroup$(cut -d: -f3 "/proc/$SERVER_PID/cgroup")" -- load 8 "$DUR" 0 "$WORKLOAD" && {
        agree docker; is docker LIMIT 50; under docker OTHERS 10; limit_is_groups docker 600
    }
    sudo -n docker rm -f "$CONTAINER" >/dev/null 2>&1; CONTAINER=""
else
    note "no docker, or no image $IMAGE here: skipped"
fi
}

want 16 && {
echo "[16] a thread per request"
server tpc "$C1" && run threads "$SERVER_PID" "" -- taskset -c "$CLOAD" python3 "$SCN_DIR/workloads/reconnect.py" "$PORT" 8 "$DUR" && {
    # Alone on its CPU: all its threads wait for is each other. schedstat is
    # of no use here: the threads are gone, and their counts with them.
    awk -v b="$B_OWN" -v o="$O_OWN" 'BEGIN { d = b - o; if (d < 0) d = -d; exit !(d <= o / 10) }' \
        && ok "threads: own threads' part is the oracle's ($(ms $B_OWN) ms against $(ms $O_OWN))" \
        || bad "threads: own $(ms $B_OWN) ms, the oracle's $(ms $O_OWN)"
    awk -v b="$B_TOTAL" -v o="$O_TOTAL" 'BEGIN { d = b - o; if (d < 0) d = -d; exit !(d <= o / 10) }' \
        && ok "threads: the waits before a thread's first turn are counted ($(ms $B_TOTAL) ms in all, the oracle's $(ms $O_TOTAL))" \
        || bad "threads: $(ms $B_TOTAL) ms in all, the oracle's $(ms $O_TOTAL)"
    is threads OWN 90; under threads OTHERS 5
}
done_with
}

# meanwhile CMD...: run it again and again while the load runs; stop with `enough`.
meanwhile() { ( while :; do "$@"; done ) >/dev/null 2>&1 & MEANWHILE=$!; }
enough() { kill "$MEANWHILE" 2>/dev/null; wait "$MEANWHILE" 2>/dev/null; }

want 18 && {
echo "[18] the server's CPUs changed while its threads wait"
flip() {
    local tid
    for tid in $(ls /proc/"$SERVER_PID"/task 2>/dev/null); do taskset -p -c "$1" "$tid"; done
    sleep 0.02
}
flip_both() { flip "$((NCPU - 2))"; flip "$C1"; flip "$C2"; }
server pool "$C2" "" "" -w 4 && { meanwhile flip_both; run affinity "$SERVER_PID" "" -- load 8 "$DUR" 0 "$WORKLOAD"; } && {
    enough
    agree affinity
    (( O_MOVED_PCT >= 1 )) && ok "affinity: waits were moved between the queues ($O_MOVED_PCT%)" \
        || bad "affinity: no wait was moved between the queues: the case does not test what it says"
}
enough
done_with
}

[[ -n "$LIMIT_KEPT" ]] && want 19 && {
echo "[19] the limit taken off and put back while the server runs"
relimit() {
    echo "max 100000" | sudo -n tee "$CG/cpu.max"; sleep 0.3
    echo "$QUOTA" | sudo -n tee "$CG/cpu.max"; sleep 0.3
}
server pool "$C1" "$QUOTA" "" -w 4 && { meanwhile relimit; run relimit "$SERVER_PID" "$CG_LIMITED" -- load 8 "$DUR" 0 "$WORKLOAD"; } && {
    enough
    agree relimit; is relimit LIMIT 20; is relimit OWN 20; limit_is_groups relimit 600
}
enough
done_with
}

want 20 && {
echo "[20] the server stopped and continued"
pause() { kill -STOP "$SERVER_PID"; sleep 0.2; kill -CONT "$SERVER_PID"; sleep 0.2; }
server pool "$C1" "" "" -w 4 && { meanwhile pause; run stopped "$SERVER_PID" "" -- load 8 "$DUR" 0 "$WORKLOAD"; } && {
    enough
    # Half the time it is stopped: threads that are stopped do not wait for a CPU.
    agree stopped; is stopped OWN 70
    le "$B_TOTAL" "$(( DUR * 1000000000 * 4 * 70 / 100 ))" \
        && ok "stopped: the time it was stopped is not a wait ($(ms $B_TOTAL) ms of waiting by 4 workers in $DUR s)" \
        || bad "stopped: $(ms $B_TOTAL) ms of waiting by 4 workers in $DUR s, half of which it was stopped"
}
enough; kill -CONT "${SERVER_PID:-0}" 2>/dev/null
done_with
}

want 17 && {
echo "[17] random cases"
SEED="${CPU_WAIT_SEED:-$RANDOM}"
note "seed $SEED (CPU_WAIT_SEED=$SEED repeats these)"
RANDOM=$SEED
pick() { local a=("$@"); echo "${a[RANDOM % ${#a[@]}]}"; }
for ((i = 1; i <= ${CPU_WAIT_RANDOM:-6}; i++)); do
    kind=$(pick pool pool epoll)
    cpus=$(pick "$C1" "$C1" "$C2")
    workers=$(pick 1 2 4 6)
    limit=$(pick "" "" "max" "25000 100000" "50000 100000" "100000 100000" "150000 100000")
    nested=$(pick "" "" nested)
    hogs=$(pick 0 0 1 2)
    conns=$(pick 2 4 8 16)
    think=$(pick 0 0 200 1000 3000)
    spin=$(pick 100 300 1000)
    [[ -z "$LIMIT_KEPT" ]] && limit=""
    [[ -z "$limit" ]] && nested=""
    name="random$i"
    note "$name: $kind, $workers workers, CPUs $cpus, limit '${limit:-none}'${nested:+ on the group above}, $hogs spinning, $conns connections, pause ${think} us, ${spin} us of CPU a request"
    args=(); [[ $kind == pool ]] && args=(-w "$workers")
    server "$kind" "$cpus" "$limit" "$nested" "${args[@]}" && {
        (( hogs )) && start_hogs "$hogs" "$cpus"
        run "$name" "$SERVER_PID" "$CG_LIMITED" -- load "$conns" "$DUR" "$think" "/n?size=200&cpu=$spin"
    } && {
        agree "$name"
        [[ -n "$limit" && "$limit" != max ]] && (( K_THROTTLED > 0 )) && {
            ge "$B_LIMIT" "$(( K_THROTTLED * 90 / 100 ))" \
                && ok "$name: the limit time is at least the group's throttled time ($(ms $B_LIMIT) ms, cpu.stat $(ms $K_THROTTLED))" \
                || bad "$name: limit $(ms $B_LIMIT) ms is under the group's throttled time, $(ms $K_THROTTLED) ms"
        }
        [[ -z "$limit" || "$limit" == max ]] && {
            (( B_LIMIT == 0 )) && ok "$name: no limit, no limit time" || bad "$name: $(ms $B_LIMIT) ms of limit time without a limit"
        }
    }
    done_with
done
}

echo
echo "result: $PASS passed, $FAIL failed"
(( FAIL == 0 ))
