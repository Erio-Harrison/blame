#!/usr/bin/env bash
#
# Request boundary acceptance: `blame slow` against servers that log, for every
# request, when it started and ended, how much CPU its thread used and what
# each blocking call was waiting for (tests/tools/http_truth.c).
#
# [1] boundaries     every request is seen once, with the right start and end,
#                    for three server designs and the awkward ways of using a
#                    connection (keep-alive, split bodies, chunked, slow
#                    clients, 100-continue, HEAD, close, abort, pipelining)
# [2] real servers   request counts match the server's own log
# [3] attribution    CPU and sleep of the serving threads land on the right
#                    request; idle waits land on none; disk waits and memory
#                    stalls are told from other sleeps
# [4] limits         what cannot be followed is counted, and what is still
#                    reported stays correct
# [5] late attach    a server that is already busy is picked up
# [6] discovery      servers are found without being named
# [7] no residue
# [8] runtimes       Go (net/http) and tokio servers, whose goroutines and
#                    tasks move between threads: time lands on the request
#                    of the goroutine or task, not of the thread
# [9] HTTP/2         streams as requests: where each starts and ends, against a
#                    server and client that speak the frames by hand
# [10] gRPC          calls by method, status and trace id, and the time of the
#                    handler that served each, against grpc-go and tonic servers
# [11] spawned       goroutines and tasks a request spawns are followed as its
#                    helpers (--deep)
# [12] file services waits for NFS, FUSE or virtiofs are not taken for disk
#                    waits (needs a directory on one: BLAME_FSVC_DIR, or this
#                    checkout on one)
# [13] park reasons  why a request's goroutine or task was on no thread
#                    (--deep)
# [14] OpenMP        the threads of a team that take up a request's parallel
#                    work (GNU libgomp): their CPU and their wait for a CPU,
#                    against a server that opens regions (needs -fopenmp)
# [15] TLS           requests over TLS read from OpenSSL's calls (--tls), from
#                    the first ones after attaching to a busy server (needs
#                    openssl)
#
# What all of a process's threads waited for a CPU is tested apart, in
# tests/scenarios/cpu_wait.sh.
#
# Needs root or passwordless sudo, a C compiler, python3, curl. nginx is used if
# installed; the Go server needs a Go toolchain (skipped without one), the
# tokio server is built with cargo. The gRPC servers also need their
# libraries (grpc-go, tonic), fetched on the first build; skipped without.
#     ./tests/scenarios/m4_acceptance.sh [blame-binary]
# Env: BLAME_BIN, SCN_DURATION (seconds of load per case, default 4),
#      ONLY (space separated section numbers; default all),
#      GO (the go command; default: the one on PATH),
#      BLAME_FSVC_DIR (a directory on a file service, for [12]),
#      KEEP_WORK=1 (keep the logs, to look into a failure)

set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -n "${1:-}" ]] && BLAME_BIN="$1"
resolve_bin || exit 1
need_root || exit 1

DUR="${SCN_DURATION:-4}"
PORT=19200
BACKEND_PORT=19100
WORKLOADS="$SCN_DIR/workloads"
WORK="$(mktemp -d)"
chmod 755 "$WORK"
AGENT_JOB=""
MEM_CG=""
cleanup() {
    stop_agent
    reap_tracked
    [[ -n "$MEM_CG" ]] && sudo -n rmdir "$MEM_CG" 2>/dev/null
    # [12] makes its files on the file service, which may be this checkout.
    [[ -n "${FSVC_TMP:-}" ]] && rm -rf "$FSVC_TMP"
    # KEEP_WORK=1 keeps the logs, to look into a failure.
    if [[ -n "${KEEP_WORK:-}" ]]; then echo "work directory kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# With OpenMP where the compiler has it, for [14]; the rest does not use it.
HAVE_OMP=1
cc -O2 -Wall -pthread -fopenmp -o "$WORK/http_truth" "$SCN_DIR/../tools/http_truth.c" 2>/dev/null || {
    HAVE_OMP=
    cc -O2 -Wall -pthread -o "$WORK/http_truth" "$SCN_DIR/../tools/http_truth.c" || exit 1
}
# HTTPS too where OpenSSL is there to build it with (HTTP_LOAD_TLS=1).
if cc -O2 -Wall -pthread -DWITH_TLS -o "$WORK/http_load" "$SCN_DIR/../tools/http_load.c" -lssl -lcrypto 2>/dev/null \
    && openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/tls.key" -out "$WORK/tls.crt" \
        -days 1 -subj /CN=localhost >/dev/null 2>&1; then
    HAVE_TLS=1
else
    HAVE_TLS=""
    cc -O2 -Wall -pthread -o "$WORK/http_load" "$SCN_DIR/../tools/http_load.c" || exit 1
fi
# The cases over TLS: the servers and loads take these from the environment,
# the agent reads TLS (--tls).
tls_on() { export TLS_CERT="$WORK/tls.crt" TLS_KEY="$WORK/tls.key" HTTP_LOAD_TLS=1 GRPC_TLS=1 AGENT_EXTRA=--tls; }
tls_off() { unset TLS_CERT TLS_KEY HTTP_LOAD_TLS GRPC_TLS AGENT_EXTRA; }

# --- thresholds ---------------------------------------------------------------
# Pairs must have both ends within 300 us of the server's own clock. The dev VM
# freezes for up to 130 ms every ~10 s, which can push a request or two out,
# and so can a server thread losing its CPU between a call and its clock
# reading: the loads below keep the servers' busy threads below the CPU count.
PAIRED_PCT_MIN=99
# The milestone's criterion: latency within 5% of the server's own figure.
LATENCY_ERR_PCT_MAX=5
# Share of requests whose CPU / sleep is within 100 us or 10% of the server's
# figure, and the error of the totals. Seen in the dev VM: 98-100%, within 4%.
ATTR_OK_PCT_MIN=90
ATTR_ERR_PCT_MAX=10
# Sleep charged to requests that never slept, as a share of the idle time the
# server reported. Without the wake-source rules this is 25-100%.
IDLE_PCT_MAX=1

# --- helpers ------------------------------------------------------------------

# Comparisons fail on a value that is not a number: an empty one (a checker
# that did not say it), or nan (one with no samples to say it of).
isnum() { [[ $1 =~ ^[-+]?[0-9]+(\.[0-9]+)?$ ]]; }
le() { isnum "$1" && isnum "$2" && awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 <= b + 0) }'; }
ge() { isnum "$1" && isnum "$2" && awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 >= b + 0) }'; }
abs() { isnum "$1" && awk -v a="$1" 'BEGIN { print (a < 0 ? -a : a) }'; }
# a - b, or "?" if either is not a number: for messages, where $(( )) on an
# empty value would end the whole section without a word.
minus() { isnum "$1" && isnum "$2" && awk -v a="$1" -v b="$2" 'BEGIN { print a - b }' || echo "?"; }
boot_ns() { python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_BOOTTIME))'; }

# Start a ground-truth server; its pid lands in SERVER_PID.
start_server() {
    local mode=$1 port=$2 log=$3
    shift 3
    spawn "$WORK/http_truth" "$mode" "$port" "$log" "$@"
    SERVER_PID="${_TRACKED[-1]}"
    sleep 0.3
}

# Start `blame slow` on every request; the rest of the arguments are passed on.
start_agent() {
    local log=$1
    shift
    # shellcheck disable=SC2086 # AGENT_EXTRA: options for every agent of a case, split.
    sudo -n "$BIN" slow --raw --above 0 --interval 0 "$@" ${AGENT_EXTRA:-} >"$log" 2>&1 &
    AGENT_JOB=$!
    for _ in $(seq 100); do
        grep -q 'slow attached' "$log" 2>/dev/null && return 0
        sleep 0.1
    done
    bad "agent never reported being attached: $(cat "$log")"
    # The servers of this case would otherwise hold the ports for the next.
    stop_agent
    stop_servers
    return 1
}

stop_agent() {
    [[ -z "$AGENT_JOB" ]] && return
    sleep 0.5   # one drain interval, so the last requests are printed
    local pid
    for pid in $(live_agents); do sudo -n kill -INT "$pid" 2>/dev/null; done
    wait "$AGENT_JOB" 2>/dev/null
    AGENT_JOB=""
}

# Stop the servers so they write their logs.
stop_servers() { reap_tracked; }

client() { python3 "$WORKLOADS/http_client.py" "$PORT" "$@" >/dev/null 2>&1; }
load() { "$WORK/http_load" "$PORT" "$@" >/dev/null 2>&1; }

# Run the comparison; the result line lands in CHECK.
# A checker that fails or says nothing is a failure of the case, said once.
check() {
    if ! CHECK=$(python3 "$WORKLOADS/http_check.py" "$@" 2>"$WORK/check.err") || [[ -z "$CHECK" ]]; then
        bad "the checker failed on $1: $(tail -1 "$WORK/check.err")"
        CHECK=""
        return 1
    fi
    note "$CHECK"
}
# The same for the other checkers: VAR SCRIPT ARGS... sets VAR.
run_checker() {
    local var=$1 out
    shift
    if ! out=$(python3 "$@" 2>"$WORK/check.err") || [[ -z "$out" ]]; then
        bad "the checker $(basename "$1") failed on $2: $(tail -1 "$WORK/check.err")"
        out=""
    fi
    printf -v "$var" '%s' "$out"
}
val() { echo "$CHECK" | grep -oP "(?<=\b$1=)-?[0-9.]+"; }

# Idle time the server reported, in microseconds (label 1 = idle).
truth_idle_us() {
    python3 - "$1" <<'EOF'
import struct, sys
rec = "<BBHIQQIIQQQQII"
data = open(sys.argv[1], "rb").read()
idle = 0
for off in range(0, len(data) - struct.calcsize(rec) + 1, struct.calcsize(rec)):
    r = struct.unpack_from(rec, data, off)
    if r[0] == 2 and r[1] == 1:
        idle += r[5] - r[4]
print(idle // 1000)
EOF
}

# expect_boundaries WHAT [SLACK]: SLACK requests may be counted on one side
# only (those under way at a cut-off).
expect_boundaries() {
    local what=$1 slack=${2:-0} diff
    if ! isnum "$(val truth)" || ! isnum "$(val kernel)"; then
        bad "$what: no counts to compare (truth=$(val truth) kernel=$(val kernel))"
        return 1
    fi
    diff=$(( $(val truth) - $(val kernel) ))
    (( ${diff#-} <= slack && $(val truth) > 0 )) \
        && ok "$what: every request seen once ($(val kernel))" \
        || bad "$what: server served $(val truth), agent reported $(val kernel)"
    ge "$(val paired_pct)" "$PAIRED_PCT_MIN" && (( $(val spurious) * 1000 <= $(val kernel) + 1000 )) \
        && ok "$what: starts and ends match the server's ($(val paired_pct)%)" \
        || bad "$what: paired $(val paired_pct)%, spurious $(val spurious)"
}

# Everything the agent reported pairs with a request the server served, with
# the right start and end, bar the odd one whose clock reading on the server
# side was delayed. (Requests the agent left out are checked by the callers.)
still_right() {
    (( $(val kernel) > 0 && ($(val kernel) - $(val paired)) * 1000 <= $(val kernel) + 1000 ))
}

# Thread-per-connection servers log every wait for the rest of a request:
# the agent's client-wait time must match where there was one, and be next to
# nothing where there was none (an idle keep-alive wait is not a client wait).
expect_client_waits() {
    local what=$1 need_samples=$2
    if (( need_samples )); then
        ge "$(val client_ok_pct)" "$ATTR_OK_PCT_MIN" && (( $(val client_n) >= need_samples )) \
            && ok "$what: waits for the rest of a request match the server's ($(val client_ok_pct)% of $(val client_n))" \
            || bad "$what: client waits: ok $(val client_ok_pct)% of $(val client_n)"
    fi
    # At most 1 us per request on average, plus 1 ms in all.
    (( $(val client_extra_us) <= $(val kernel) + 1000 )) \
        && ok "$what: no client wait charged where the server had none ($(val client_extra_us)us)" \
        || bad "$what: $(val client_extra_us)us of client wait charged where the server had none"
}

expect_no_loss() {
    local what=$1 log=$2 name
    for name in "${@:3}"; do
        [[ "$(kernel_counter "$log" "$name")" == "0" ]] \
            && ok "$what: $name is 0" \
            || bad "$what: $name=$(kernel_counter "$log" "$name")"
    done
}

# Whether section N was asked for.
want() { [[ -z "${ONLY:-}" || " $ONLY " == *" $1 "* ]]; }

echo "blame request acceptance ($BIN)"
echo "  load=${DUR}s cpus=${NCPU}"

# --- [1] boundaries -----------------------------------------------------------
want 1 && {
echo
echo "[1] request boundaries against the server's own log"
for mode in tpc epoll pool; do
    scenarios="keepalive bigbody chunked slow head close abort down"
    # The pool server answers neither 100-continue nor pipelined requests.
    [[ "$mode" != pool ]] && scenarios="$scenarios expect100 pipeline"
    start_server tpc "$BACKEND_PORT" "$WORK/be.bin"
    start_server "$mode" "$PORT" "$WORK/b_$mode.bin" -b "$BACKEND_PORT"
    start_agent "$WORK/b_$mode.log" --pid "$SERVER_PID" || continue
    for scenario in $scenarios; do client "$scenario" 200 4; done
    stop_agent
    stop_servers
    check "$WORK/b_$mode.bin" "$WORK/b_$mode.log"
    expect_boundaries "$mode"
    # Slow clients, split bodies and 100-continue all leave the server waiting
    # for the rest of a request; only this server logs each such wait.
    [[ "$mode" == tpc ]] && expect_client_waits "$mode" 100
    expect_no_loss "$mode" "$WORK/b_$mode.log" req_parse_desync req_queue_full \
        req_response_unmatched req_insert_failed req_conn_insert_failed ringbuf_full
    # Method and path are kept; the query string, which can carry secrets, is not.
    grep -q '^req .*line="GET /k"' "$WORK/b_$mode.log" \
        && ! grep -q '^req .*line="[^"]*?' "$WORK/b_$mode.log" \
        && ok "$mode: requests carry their method and path, without the query string" \
        || bad "$mode: request lines are missing or carry a query string"
    # The abort scenario closes connections mid-request; nothing else may.
    aborted=$(kernel_counter "$WORK/b_$mode.log" req_aborted)
    in_flight=$(kernel_counter "$WORK/b_$mode.log" in_flight)
    note "aborted=$aborted in_flight=$in_flight"
    (( aborted > 0 && aborted <= 200 && in_flight == 0 )) \
        && ok "$mode: requests cut off by the client are counted as aborted, none left over" \
        || bad "$mode: aborted=$aborted in_flight=$in_flight"
done
}

# --- [2] real servers ---------------------------------------------------------
want 2 && {
echo
echo "[2] request counts against real servers"
mkdir -p "$WORK/www" && echo hello >"$WORK/www/index.html"
(cd "$WORK/www" && exec python3 -m http.server "$PORT" --bind 127.0.0.1) >"$WORK/py.log" 2>&1 &
PY_PID=$!
_TRACKED+=("$PY_PID")
sleep 0.7
start_agent "$WORK/py_slow.log" --pid "$PY_PID" && {
    for _ in $(seq 60); do
        python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$PORT/index.html').read()"
    done
    stop_agent
    stop_servers
    served=$(grep -c '"GET /index.html' "$WORK/py.log")
    seen=$(grep -c '^req .*line="GET /index.html"' "$WORK/py_slow.log")
    note "python http.server: served=$served seen=$seen"
    (( served == 60 && seen == served )) \
        && ok "python http.server: every request seen, with its method and path" \
        || bad "python http.server: served=$served seen=$seen"
}
if command -v nginx >/dev/null 2>&1; then
    cat >"$WORK/nginx.conf" <<EOF
daemon off; worker_processes 2; pid $WORK/nginx.pid; error_log $WORK/nginx.err;
events { worker_connections 256; }
http {
    access_log $WORK/nginx.access;
    client_body_temp_path $WORK/nb; proxy_temp_path $WORK/np; fastcgi_temp_path $WORK/nf;
    uwsgi_temp_path $WORK/nu; scgi_temp_path $WORK/ns;
    server { listen 127.0.0.1:$PORT; root $WORK/www; }
}
EOF
    spawn nginx -c "$WORK/nginx.conf"
    sleep 0.7
    # No --pid: the workers are found because they listen.
    start_agent "$WORK/ng_slow.log" && {
        load 8 "$DUR" 1000 /index.html,/missing
        stop_agent
        stop_servers
        served=$(wc -l <"$WORK/nginx.access")
        seen=$(grep -c '^req .*lport='"$PORT"' ' "$WORK/ng_slow.log")
        note "nginx: served=$served seen=$seen"
        (( served > 100 && seen == served )) \
            && ok "nginx: every request seen" \
            || bad "nginx: served=$served seen=$seen"
    }
else
    note "nginx not installed; skipped"
fi
}

# --- [3] attribution ----------------------------------------------------------
want 3 && {
echo
echo "[3] thread time lands on the right request"
# attribution CASE MODE CONNS THINK_US PATHS WHAT...   WHAT: cpu blk down idle client
attribution() {
    local name=$1 mode=$2 conns=$3 think=$4 paths=$5
    shift 5
    start_server tpc "$BACKEND_PORT" "$WORK/be.bin"
    start_server "$mode" "$PORT" "$WORK/a_$name.bin" -b "$BACKEND_PORT"
    start_agent "$WORK/a_$name.log" --pid "$SERVER_PID" || return
    load "$conns" "$DUR" "$think" "$paths"
    stop_agent
    stop_servers
    check "$WORK/a_$name.bin" "$WORK/a_$name.log"
    expect_boundaries "$name"
    le "$(abs "$(val latency_err_pct)")" "$LATENCY_ERR_PCT_MAX" \
        && ok "$name: latency within ${LATENCY_ERR_PCT_MAX}% of the server's ($(val latency_err_pct)%)" \
        || bad "$name: latency off by $(val latency_err_pct)%"
    local what key idle idle_pct
    for what in "$@"; do
        case "$what" in
            cpu | blk)
                [[ "$what" == cpu ]] && key="CPU time" || key="time asleep"
                ge "$(val "${what}_ok_pct")" "$ATTR_OK_PCT_MIN" \
                    && le "$(abs "$(val "${what}_err_pct")")" "$ATTR_ERR_PCT_MAX" \
                    && (( $(val "${what}_n") > 100 )) \
                    && ok "$name: $key per request matches the server's ($(val "${what}_ok_pct")% of $(val "${what}_n"), total $(val "${what}_err_pct")%)" \
                    || bad "$name: $key: ok $(val "${what}_ok_pct")% of $(val "${what}_n"), total $(val "${what}_err_pct")%"
                ;;
            down)
                ge "$(val down_ok_pct)" "$ATTR_OK_PCT_MIN" && (( $(val down_n) > 100 )) \
                    && (( $(val down_split) == 0 )) \
                    && ok "$name: downstream waits timed by socket match the server's ($(val down_ok_pct)% of $(val down_n))" \
                    || bad "$name: downstream waits: ok $(val down_ok_pct)% of $(val down_n), $(val down_split) counted as several calls"
                ;;
            client) expect_client_waits "$name" 0 ;;
            idle)
                idle=$(truth_idle_us "$WORK/a_$name.bin")
                idle_pct=$(awk -v a="$(val idle_us)" -v b="$idle" 'BEGIN { printf "%.2f", (b > 0 ? a * 100 / b : 0) }')
                note "server idle ${idle}us; charged to requests that never slept $(val idle_us)us (${idle_pct}%)"
                (( idle > 100000 )) && le "$idle_pct" "$IDLE_PCT_MAX" \
                    && ok "$name: idle waits are not charged to requests" \
                    || bad "$name: ${idle_pct}% of the idle time was charged to requests"
                ;;
        esac
    done
    expect_no_loss "$name" "$WORK/a_$name.log" req_parse_desync
    # A thread that handed a request on can still be charged a little for it
    # after the request has finished; that time is dropped and counted.
    local late
    late=$(kernel_counter "$WORK/a_$name.log" req_late_time)
    (( late * 200 <= $(val kernel) )) \
        && ok "$name: time reported after its request finished is rare ($late)" \
        || bad "$name: req_late_time=$late of $(val kernel) requests"
}
# One thread per connection: bound at the read, everything observed directly.
attribution thread-per-conn tpc 4 2000 \
    "/n?size=200&cpu=500,/d?d=2000&size=200&cpu=300,/n?size=200&cpu=1500" cpu blk idle client
# A thread pool: the worker claims its time when it writes the response, and
# its wait on the queue must not come along.
attribution pool pool 4 2000 \
    "/n?size=200&cpu=600,/w?cpu=300&sleep=1000&size=200,/d?d=2000&cpu=300&size=200" cpu blk idle
attribution pool-busy pool 32 0 \
    "/n?size=200&cpu=600,/w?cpu=300&sleep=1000&size=200,/d?d=2000&cpu=300&size=200" cpu blk
# One event loop serving interleaved requests: downstream waits are timed on
# the downstream socket, and work resumed after an answer goes to its request.
attribution event-loop epoll 4 2000 "/n?size=200&cpu=500,/d?d=2000&size=200&cpu=300" cpu down idle
attribution event-loop-busy epoll 16 0 "/n?size=200&cpu=500,/d?d=2000&size=200&cpu=300" cpu down
# The answer to a downstream call comes in three pieces, 1.5 ms apart: the call
# lasts until the last of them is read.
attribution event-loop-pieces epoll 4 2000 \
    "/n?size=200&cpu=500,/d?d=2000&size=200&cpu=300&dchunk=40&dgap=1500" cpu down

# Sleeps the kernel marks itself: waiting for the disk, and stalled on memory.
# expect_stalls CASE KEY WHAT SAMPLES MEAN_US: at least SAMPLES requests, the
# time right on 90% of them and at least MEAN_US each on average, and next to
# none of it left in "other" (100 us per request).
expect_stalls() {
    local name=$1 key=$2 what=$3 samples=$4 mean_us=$5 n us other
    n=$(val "${key}_n"); us=$(val "${key}_us"); other=$(val "${key}_other_us")
    ge "$(val "${key}_ok_pct")" "$ATTR_OK_PCT_MIN" && (( n >= samples && us >= n * mean_us )) \
        && ok "$name: $what per request matches the server's ($(val "${key}_ok_pct")% of $n, $((us / n))us each)" \
        || bad "$name: $what: ok $(val "${key}_ok_pct")% of $n, ${us}us in all"
    (( other <= n * 100 )) \
        && ok "$name: those requests have no unexplained sleep (${other}us)" \
        || bad "$name: ${other}us of sleep on those requests is not explained"
    (( $(val stall_extra_us) <= 1000 )) \
        && ok "$name: no $what on the other requests ($(val stall_extra_us)us)" \
        || bad "$name: $(val stall_extra_us)us of disk or memory time on requests that had none"
}
# Reads that bypass the page cache (the scratch directory must be on a disk).
# The file is written by the first such request, before the agent looks.
start_server tpc "$PORT" "$WORK/a_disk.bin"
curl -s -o /dev/null "http://127.0.0.1:$PORT/warm?io=4"
start_agent "$WORK/a_disk.log" --pid "$SERVER_PID" && {
    load 4 "$DUR" 2000 "/n?size=200&cpu=300,/io?io=4096&size=200,/w?sleep=2000&size=200"
    stop_agent
    stop_servers
    check "$WORK/a_disk.bin" "$WORK/a_disk.log"
    # The request that wrote the file was served before the agent attached.
    expect_boundaries disk 1
    expect_stalls disk io "disk wait" 100 300
    # A plain sleep next to them is still a plain sleep.
    ge "$(val blk_ok_pct)" "$ATTR_OK_PCT_MIN" && (( $(val blk_n) > 100 )) \
        && ok "disk: other sleeps are not taken for disk waits ($(val blk_ok_pct)% of $(val blk_n))" \
        || bad "disk: time asleep: ok $(val blk_ok_pct)% of $(val blk_n)"
}
# Appends flushed to disk. The kernel marks only part of the wait as one for
# the disk: on ext4 and xfs the wait for the journal commit is a plain sleep.
# Each way of flushing is checked on its own, next to plain sleeps.
flushes=(fsync fdatasync o_dsync syncfs)
for how in 0 1 2 3; do
    name="flush-${flushes[$how]}"
    start_server tpc "$PORT" "$WORK/a_$name.bin"
    start_agent "$WORK/a_$name.log" --pid "$SERVER_PID" || continue
    load 4 "$DUR" 2000 "/n?size=200&cpu=300,/f?fsync=4&how=$how&size=200,/w?sleep=2000&size=200"
    stop_agent
    stop_servers
    check "$WORK/a_$name.bin" "$WORK/a_$name.log"
    expect_boundaries "$name"
    expect_stalls "$name" io "disk wait" 100 50
    ge "$(val blk_ok_pct)" "$ATTR_OK_PCT_MIN" && (( $(val blk_n) > 100 )) \
        && ok "$name: other sleeps are not taken for disk waits ($(val blk_ok_pct)% of $(val blk_n))" \
        || bad "$name: time asleep: ok $(val blk_ok_pct)% of $(val blk_n)"
done
# The agent attached while the threads flush: programs that mark a thread
# while it is inside a call (a flush, a socket made readable) come in pairs,
# and one attached before its pair once left threads marked for good (their
# sleeps counted as disk ever after; 70% too much disk on a real service).
# The load runs before the agent and on after it.
start_server tpc "$PORT" "$WORK/a_flush-late.bin"
load 4 $((DUR + 3)) 2000 "/n?size=200&cpu=300,/f?fsync=4&size=200,/w?sleep=2000&size=200" &
late_load=$!
sleep 1
start_agent "$WORK/a_flush-late.log" --pid "$SERVER_PID" && {
    wait "$late_load"
    stop_agent
    stop_servers
    check "$WORK/a_flush-late.bin" "$WORK/a_flush-late.log"
    expect_stalls flush-late io "disk wait" 100 50
    ge "$(val blk_ok_pct)" "$ATTR_OK_PCT_MIN" && (( $(val blk_n) > 100 )) \
        && ok "flush-late: other sleeps are not taken for disk waits ($(val blk_ok_pct)% of $(val blk_n))" \
        || bad "flush-late: time asleep: ok $(val blk_ok_pct)% of $(val blk_n)"
} || wait "$late_load"
# A cgroup held just below what its one busy thread needs: the kernel
# throttles the thread while it allocates. The delay grows with the square of
# the excess, so the limit is set 2% under the need (some 100 ms per request).
# With swap the kernel reclaims instead, on the thread's CPU, and throttles
# next to never (a WSL2 VM: 29 ms a request, against 270 ms without); the
# pages it swaps out are then waited for by requests that touch no memory.
# So the cgroup gets no swap.
MEM_KB=65536
MEM_CG="/sys/fs/cgroup/blame-m4-$$"
if sudo -n mkdir "$MEM_CG" 2>/dev/null && [[ -e "$MEM_CG/memory.high" ]]; then
    [[ -e "$MEM_CG/memory.swap.max" ]] && echo 0 | sudo -n tee "$MEM_CG/memory.swap.max" >/dev/null
    start_server tpc "$PORT" "$WORK/a_mem.bin"
    echo "$SERVER_PID" | sudo -n tee "$MEM_CG/cgroup.procs" >/dev/null
    curl -s -o /dev/null "http://127.0.0.1:$PORT/warm?mem=1024"
    sleep 0.2
    mem_high=$(( ($(cat "$MEM_CG/memory.current") + MEM_KB * 1024) * 1000 / 1022 ))
    start_agent "$WORK/a_mem.log" --pid "$SERVER_PID" && {
        echo "$mem_high" | sudo -n tee "$MEM_CG/memory.high" >/dev/null
        load 1 "$DUR" 2000 "/n?size=200&cpu=300,/m?mem=$MEM_KB&size=200"
        stop_agent
        stop_servers
        check "$WORK/a_mem.bin" "$WORK/a_mem.log"
        expect_stalls memory mem "memory stall" 10 10000
    }
    stop_servers
    sudo -n rmdir "$MEM_CG" 2>/dev/null
else
    note "no cgroup v2 memory controller; memory stall case skipped"
fi
}

# --- [4] limits ---------------------------------------------------------------
want 4 && {
echo
echo "[4] what cannot be followed is counted; the rest stays correct"
start_server epoll "$PORT" "$WORK/l_pipe.bin"
start_agent "$WORK/l_pipe.log" --pid "$SERVER_PID" && {
    client pipe32 320 2
    client keepalive 100 2
    stop_agent
    stop_servers
    check "$WORK/l_pipe.bin" "$WORK/l_pipe.log"
    full=$(kernel_counter "$WORK/l_pipe.log" req_queue_full)
    (( full > 0 )) && grep -q 'req_queue_full=[0-9]* (!)' "$WORK/l_pipe.log" \
        && ok "more than 16 pipelined requests: the overflow is counted and flagged ($full)" \
        || bad "req_queue_full=$full"
    still_right && [[ "$(val kernel)" -ge 260 ]] \
        && ok "every request still reported is paired correctly ($(val kernel) of $(val truth))" \
        || bad "kernel=$(val kernel) paired=$(val paired) spurious=$(val spurious)"
}
start_server tpc "$PORT" "$WORK/l_tab.bin"
start_agent "$WORK/l_tab.log" --pid "$SERVER_PID" --max-requests 2 && {
    load 4 2 0 "/n?size=200&cpu=300"
    stop_agent
    stop_servers
    check "$WORK/l_tab.bin" "$WORK/l_tab.log"
    failed=$(kernel_counter "$WORK/l_tab.log" req_insert_failed)
    (( failed > 0 )) && grep -q 'req_insert_failed=[0-9]* (!)' "$WORK/l_tab.log" \
        && ok "a full request table is counted and flagged ($failed)" \
        || bad "req_insert_failed=$failed"
    still_right && [[ "$(val kernel)" -gt 0 ]] \
        && ok "every request still reported is paired correctly ($(val kernel) of $(val truth))" \
        || bad "kernel=$(val kernel) paired=$(val paired) spurious=$(val spurious)"
}
}

# A HEAD among the requests that could not be queued: where its response ends
# is not known, so the connection is given up rather than guessed at.
want 4 && {
start_server epoll "$PORT" "$WORK/l_head.bin"
start_agent "$WORK/l_head.log" --pid "$SERVER_PID" && {
    client pipehead 320 2
    client keepalive 100 2
    stop_agent
    stop_servers
    check "$WORK/l_head.bin" "$WORK/l_head.log"
    desync=$(kernel_counter "$WORK/l_head.log" req_parse_desync)
    (( desync > 0 )) \
        && ok "a HEAD left out of a full queue gives the connection up, counted ($desync)" \
        || bad "pipelined HEAD overflow: req_parse_desync=$desync"
    still_right && [[ "$(val kernel)" -ge 100 ]] \
        && ok "every request still reported is paired correctly ($(val kernel) of $(val truth))" \
        || bad "kernel=$(val kernel) paired=$(val paired) spurious=$(val spurious)"
}

# Trace ids in HTTP/1.1 requests: in one read, split across reads (also
# inside the id), in names of other case, pipelined, after a body's length;
# none where there is none or the value is not one.
spawn python3 "$WORKLOADS/http_trace.py" serve "$PORT"
SERVER_PID="${_TRACKED[-1]}"
sleep 0.5
start_agent "$WORK/tr.log" --pid "$SERVER_PID" && {
    python3 "$WORKLOADS/http_trace.py" client "$PORT" 8 > "$WORK/tr.expected"
    stop_agent
    stop_servers
    TR=$(python3 "$WORKLOADS/http_trace.py" check "$WORK/tr.expected" "$WORK/tr.log")
    note "$TR"
    tr() { echo "$TR" | grep -oP "(?<=\b$1=)[0-9]+"; }
    (( $(tr expected) > 100 && $(tr unreported) == 0 && $(tr right) == $(tr with_id) && $(tr wrong) == 0 )) \
        && ok "HTTP/1.1: every request's trace id is reported, however its headers arrived ($(tr right) of $(tr with_id))" \
        || bad "HTTP/1.1 trace ids: $TR"
    (( $(tr unexpected) == 0 && $(tr missing) == 0 )) \
        && ok "HTTP/1.1: none for requests without one or with a value that is not one" \
        || bad "HTTP/1.1 trace ids: $TR"
}

# HTTP/1.1 requests summed up by route, slow or not: none of them is slow
# enough to list, all are counted, ids in paths put together.
spawn python3 "$WORKLOADS/http_trace.py" serve "$PORT"
SERVER_PID="${_TRACKED[-1]}"
sleep 0.5
sudo -n "$BIN" slow --json --above 1000 --interval 0 --pid "$SERVER_PID" >"$WORK/rt.json" 2>"$WORK/rt.err" &
AGENT_JOB=$!
for _ in $(seq 100); do grep -qs '"type":"process"' "$WORK/rt.json" && break; sleep 0.1; done
python3 "$WORKLOADS/http_trace.py" routes "$PORT" 8 > "$WORK/rt.expected"
stop_agent
stop_servers
RT=$(python3 "$WORKLOADS/http_trace.py" check-routes "$WORK/rt.expected" "$WORK/rt.json")
note "$RT"
listed=$(grep -c '"type":"call"' "$WORK/rt.json")
rtv() { echo "$RT" | grep -oP "(?<=\b$1=)[0-9]+"; }
(( $(rtv expected) == 5 && $(rtv right) == 5 && $(rtv extra) == 0 && listed == 0 )) \
    && ok "HTTP/1.1: every request summed up under its route, ids put together, none listed ($(rtv right) routes)" \
    || bad "HTTP/1.1 routes: $RT, listed $listed"

# Peeking reads, a header block of exactly the bytes parsed per call, and a
# protocol upgrade, against a server written for them.
spawn python3 "$WORKLOADS/http_quirks.py" serve "$PORT"
SERVER_PID="${_TRACKED[-1]}"
sleep 0.5
start_agent "$WORK/q.log" --pid "$SERVER_PID" && {
    expected=$(python3 "$WORKLOADS/http_quirks.py" client "$PORT" 20)
    stop_agent
    stop_servers
    note "$expected"
    want_req=$(echo "$expected" | grep -oP '(?<=requests=)[0-9]+')
    want_up=$(echo "$expected" | grep -oP '(?<=upgrades=)[0-9]+')
    q_all=$(grep -c '^req .*line="GET /q/' "$WORK/q.log")
    q_unique=$(grep -oP '^req .*line="\KGET /q/[^"]*' "$WORK/q.log" | sort -u | wc -l)
    hdr=$(grep -c '^req .*status=200 .*line="GET /hdr4096"' "$WORK/q.log")
    up=$(grep -c '^req .*status=101 .*line="GET /up"' "$WORK/q.log")
    fake=$(grep -c 'line="GET /fake' "$WORK/q.log")
    note "q=$q_all unique=$q_unique hdr4096=$hdr up=$up fake=$fake"
    (( q_all == want_req - 2 * want_up && q_unique == q_all )) \
        && ok "a server that peeks before reading: every request seen once ($q_all)" \
        || bad "peeking server: $q_all requests reported, $q_unique distinct, $((want_req - 2 * want_up)) sent"
    (( hdr == want_up )) \
        && ok "a 4096-byte response header block in one call is followed ($hdr)" \
        || bad "4096-byte header responses reported: $hdr of $want_up"
    upgraded=$(kernel_counter "$WORK/q.log" req_upgraded)
    (( up == want_up && fake == 0 && upgraded == want_up )) \
        && ok "an upgraded connection: the upgrade request ends at 101, nothing after it is parsed" \
        || bad "upgrade: reported=$up req_upgraded=$upgraded requests inside the upgraded stream=$fake"
    expect_no_loss quirks "$WORK/q.log" req_parse_desync req_aborted req_response_unmatched
    [[ "$(kernel_counter "$WORK/q.log" in_flight)" == "0" ]] \
        && ok "quirks: no request left in flight" \
        || bad "quirks: in_flight=$(kernel_counter "$WORK/q.log" in_flight)"
}

# Downstream connections that carry more than one call at a time: one request
# pipelining three calls, and a connection shared by every thread.
spawn python3 "$WORKLOADS/http_down.py" backend "$BACKEND_PORT"
sleep 0.3
spawn python3 "$WORKLOADS/http_down.py" serve "$PORT" "$BACKEND_PORT"
SERVER_PID="${_TRACKED[-1]}"
sleep 0.5
start_agent "$WORK/dn.log" --pid "$SERVER_PID" && {
    expected=$(python3 "$WORKLOADS/http_down.py" client "$PORT" 100)
    stop_agent
    stop_servers
    note "$expected"
    # Per path: requests, and those whose downstream figures are as they should be.
    down_stats=$(awk '/^req / {
        delete f
        for (i = 2; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = kv[2] }
        lat = f["end_ns"] - f["start_ns"]; wait = f["down_wait_ns"]
        if ($0 ~ /line="GET \/pipe"/) {
            pipe++
            if (f["down_calls"] == 1 && wait >= 5500000 && wait <= lat &&
                f["down_service_ns"] >= 1500000 && f["down_service_ns"] <= 4000000 &&
                f["down_transfer_ns"] >= 3000000) pipe_ok++
        } else if ($0 ~ /line="GET \/shared"/) {
            shared++
            if (wait <= lat + 100000) shared_ok++
            if (f["down_calls"] > 0) shared_timed++
        }
    } END { printf "pipe=%d pipe_ok=%d shared=%d shared_ok=%d shared_timed=%d", pipe, pipe_ok, shared, shared_ok, shared_timed }' "$WORK/dn.log")
    note "$down_stats"
    dval() { echo "$down_stats" | grep -oP "(?<=\b$1=)[0-9]+"; }
    (( $(dval pipe) == 100 && $(dval pipe_ok) >= 95 )) \
        && ok "three pipelined downstream calls are timed as one, to the last answer ($(dval pipe_ok) of $(dval pipe))" \
        || bad "pipelined downstream calls: $(dval pipe_ok) of $(dval pipe) right"
    mixed=$(kernel_counter "$WORK/dn.log" req_down_mixed)
    (( $(dval shared) == 400 && $(dval shared_ok) == 400 && $(dval shared_timed) == 0 && mixed > 0 )) \
        && ok "calls of several requests overlapping on one connection are counted, not timed (req_down_mixed=$mixed, $(dval shared_timed) of $(dval shared) timed)" \
        || bad "shared downstream connection: req_down_mixed=$mixed, $(dval shared_ok) of $(dval shared) requests with a possible wait, $(dval shared_timed) timed"
    expect_no_loss downstream "$WORK/dn.log" req_parse_desync req_aborted req_response_unmatched
}
}

# --- [5] late attach ----------------------------------------------------------
want 5 && {
echo
echo "[5] attaching to a server that is already busy"
for mode in tpc epoll; do
    start_server "$mode" "$PORT" "$WORK/late_$mode.bin"
    "$WORK/http_load" "$PORT" 4 $((DUR + 3)) 500 "/n?size=3000&cpu=200" >/dev/null 2>&1 &
    LOAD_JOB=$!
    sleep 1.5
    start_agent "$WORK/late_$mode.log" --pid "$SERVER_PID" || continue
    attached=$(boot_ns)
    wait "$LOAD_JOB"
    stop_agent
    stop_servers
    # Each connection is picked up at its first request after attaching.
    check "$WORK/late_$mode.bin" "$WORK/late_$mode.log" --after-ns $((attached + 200000000))
    expect_boundaries "$mode, from 0.2 s after attaching" 4
    resync=$(kernel_counter "$WORK/late_$mode.log" req_parse_resync)
    (( resync >= 4 )) \
        && ok "$mode: the open connections were picked up at a message start ($resync)" \
        || bad "$mode: req_parse_resync=$resync"
done
# Requests in the middle of their 3 ms sleep when the agent attaches make their
# downstream call after it, for a request it never saw. Each connection's later
# calls must still be timed (a call no request owned once stayed open for good).
start_server tpc "$BACKEND_PORT" "$WORK/late_be.bin"
start_server tpc "$PORT" "$WORK/late_down.bin" -b "$BACKEND_PORT"
"$WORK/http_load" "$PORT" 8 $((DUR + 3)) 500 "/d?sleep=3000&d=1000&size=200" >/dev/null 2>&1 &
LOAD_JOB=$!
sleep 1.5
start_agent "$WORK/late_down.log" --pid "$SERVER_PID" && {
    attached=$(boot_ns)
    wait "$LOAD_JOB"
    stop_agent
    stop_servers
    check "$WORK/late_down.bin" "$WORK/late_down.log" --after-ns $((attached + 200000000))
    # The server logs each of its threads' sleeps, the downstream wait among them.
    ge "$(val paired_pct)" "$PAIRED_PCT_MIN" \
        && ok "after attaching mid-call, every request after the cut-off is seen ($(val paired_pct)% of $(val truth))" \
        || bad "after attaching mid-call: $(val paired_pct)% of $(val truth) requests seen"
    ge "$(val blk_ok_pct)" "$ATTR_OK_PCT_MIN" && (( $(val blk_n) > 100 )) \
        && ok "after attaching mid-call, downstream waits still count as the request's ($(val blk_ok_pct)% of $(val blk_n) right)" \
        || bad "after attaching mid-call: time asleep ok $(val blk_ok_pct)% of $(val blk_n), total $(val blk_err_pct)%"
}
}

# --- [6] discovery ------------------------------------------------------------
want 6 && {
echo
echo "[6] servers are found without being named"
start_server tpc "$PORT" "$WORK/d_before.bin"
BEFORE_PID=$SERVER_PID
start_agent "$WORK/d.log" && {
    start_server tpc $((PORT + 1)) "$WORK/d_after.bin"
    AFTER_PID=$SERVER_PID
    load 2 2 1000 "/n?size=200&cpu=200" &
    LOAD_JOB=$!
    "$WORK/http_load" $((PORT + 1)) 2 2 1000 "/n?size=200&cpu=200" >/dev/null 2>&1
    wait "$LOAD_JOB"
    stop_agent
    stop_servers
    before=$(grep -c "^req .* pid=$BEFORE_PID " "$WORK/d.log")
    after=$(grep -c "^req .* pid=$AFTER_PID " "$WORK/d.log")
    note "requests: listening before the agent started=$before, started afterwards=$after"
    (( before > 100 )) && ok "a server already listening is traced" || bad "before=$before"
    (( after > 100 )) && ok "a server started later is traced from its first accept" || bad "after=$after"
}
}

# --- [7] no residue -----------------------------------------------------------
want 7 && {
echo
echo "[7] no residue after SIGKILL"
before=$(bpf_prog_ids)
sudo -n "$BIN" slow >"$WORK/kill.log" 2>&1 &
AGENT_JOB=$!
for _ in $(seq 100); do
    grep -q 'slow attached' "$WORK/kill.log" 2>/dev/null && break
    sleep 0.1
done
[[ "$(bpf_prog_ids)" != "$before" ]] \
    && ok "programs are loaded while the agent runs" \
    || bad "no new programs appeared while the agent was running"
for pid in $(live_agents); do sudo -n kill -KILL "$pid" 2>/dev/null; done
wait "$AGENT_JOB" 2>/dev/null
AGENT_JOB=""
sleep 0.5   # let the kernel reclaim the fds the dead process held
leaked=$(comm -13 <(echo "$before") <(bpf_prog_ids) | grep -c .)
(( leaked == 0 )) && ok "no orphaned programs" || bad "$leaked program(s) survived SIGKILL"
}

# --- [8] runtimes -------------------------------------------------------------
want 8 && {
echo
echo "[8] goroutines and tokio tasks"
# Requests that compute, and ones that compute, call downstream and compute
# again: the goroutine or task parks on the downstream socket meanwhile, and
# its thread serves others. They compute milliseconds, so that the tolerance
# is a tenth of it and not 100 us: a request's CPU has its time in the kernel,
# the probes' own among it, which these servers' figures (their spins) have
# not, and on the dev VM that drifts from some 15 us a request to 100 us.
RT_PATHS="/n?size=200&cpu=2000,/c?size=200&cpu=6000,/d?size=200&cpu=1200&d=2000&cpu2=2400"
# Computing right before and after a timer: the unit parks and resumes with
# no system call nearby, so where it stopped and started is not visible.
RT_TIMER_PATHS="/n?size=200&cpu=2000,/s?size=200&cpu=1200&sleep=2000&cpu2=1600"

# rt_run CASE SERVER CONNS THINK_US PATHS [agent options]: one load against
# SERVER (two scheduler threads) with a backend; the result lands in CHECK.
rt_run() {
    local name=$1 server=$2 conns=$3 think=$4 paths=$5
    shift 5
    start_server tpc "$BACKEND_PORT" "$WORK/be.bin"
    spawn "$server" "$PORT" "$WORK/r_$name.bin" -b "$BACKEND_PORT" -p 2
    SERVER_PID="${_TRACKED[-1]}"
    sleep 0.5
    start_agent "$WORK/r_$name.log" --pid "$SERVER_PID" "$@" || return 1
    load "$conns" "$DUR" "$think" "$paths"
    stop_agent
    stop_servers
    check "$WORK/r_$name.bin" "$WORK/r_$name.log"
}

# rt_attributed CASE: boundaries, latency, CPU, downstream calls and time
# parked all match the server's own figures.
rt_attributed() {
    local name=$1 reads bad_reads
    # One freeze of the dev VM mistimes every request in flight on the server
    # side, a whole connection count of them, so only the share is held to.
    (( $(val truth) == $(val kernel) && $(val truth) > 0 )) \
        && ok "$name: every request seen once ($(val kernel))" \
        || bad "$name: server served $(val truth), agent reported $(val kernel)"
    ge "$(val paired_pct)" "$PAIRED_PCT_MIN" \
        && ok "$name: starts and ends match the server's ($(val paired_pct)%)" \
        || bad "$name: paired $(val paired_pct)%, spurious $(val spurious)"
    le "$(abs "$(val latency_err_pct)")" "$LATENCY_ERR_PCT_MAX" \
        && ok "$name: latency within ${LATENCY_ERR_PCT_MAX}% of the server's ($(val latency_err_pct)%)" \
        || bad "$name: latency off by $(val latency_err_pct)%"
    ge "$(val cpu_ok_pct)" "$ATTR_OK_PCT_MIN" && le "$(abs "$(val cpu_err_pct)")" "$ATTR_ERR_PCT_MAX" \
        && (( $(val cpu_n) > 100 )) \
        && ok "$name: CPU time per request matches the server's ($(val cpu_ok_pct)% of $(val cpu_n), total $(val cpu_err_pct)%)" \
        || bad "$name: CPU time: ok $(val cpu_ok_pct)% of $(val cpu_n), total $(val cpu_err_pct)%"
    ge "$(val down_ok_pct)" "$ATTR_OK_PCT_MIN" && (( $(val down_n) > 100 && $(val down_split) == 0 )) \
        && ok "$name: downstream calls are timed for the right request ($(val down_ok_pct)% of $(val down_n))" \
        || bad "$name: downstream calls: ok $(val down_ok_pct)% of $(val down_n), missed $(val down_missed)"
    ge "$(val park_ok_pct)" "$ATTR_OK_PCT_MIN" && (( $(val park_n) > 100 )) \
        && ok "$name: time parked in the runtime is what no thread accounts for ($(val park_ok_pct)% of $(val park_n))" \
        || bad "$name: time parked: ok $(val park_ok_pct)% of $(val park_n)"
    reads=$(kernel_counter "$WORK/r_$name.log" unit_read); reads=${reads:-0}
    bad_reads=$(kernel_counter "$WORK/r_$name.log" unit_read_inconsistent); bad_reads=${bad_reads:-0}
    if [[ $name == tokio* ]]; then
        # Probes on task polls say which task runs: tokio's state is not read.
        (( reads == 0 )) \
            && ok "$name: which task runs is told by probes, not read from the runtime" \
            || bad "$name: unit_read=$reads although probes tell which task runs"
    else
        (( reads > 1000 && bad_reads * 1000 <= reads )) \
            && ok "$name: the runtime's state reads hold together ($bad_reads of $reads do not)" \
            || bad "$name: unit_read=$reads unit_read_inconsistent=$bad_reads"
    fi
}

# rt_suite NAME SERVER LEVEL: everything, for one server.
rt_suite() {
    local rt=$1 server=$2 level=$3 unseen
    rt_run "$rt" "$server" 8 2000 "$RT_PATHS" && {
        grep -q "^blame: pid $SERVER_PID: .*: $level\$" "$WORK/r_$rt.log" \
            && ok "$rt: recognised ($(grep -oP "^blame: pid $SERVER_PID: \K.*" "$WORK/r_$rt.log"))" \
            || bad "$rt: not recognised: $(grep '^blame: pid' "$WORK/r_$rt.log")"
        rt_attributed "$rt"
    }
    # Every scheduler thread busy: units queue for threads and move between them.
    rt_run "$rt-busy" "$server" 32 0 "$RT_PATHS" && rt_attributed "$rt-busy"
    # Why units and not threads: a handler that waits for the goroutines or
    # tasks it spawned, which run on its thread meanwhile. By unit its CPU is
    # its own; by thread theirs is added to it. The handler computes 3 ms, so
    # that the tolerance is 300 us: its time in the kernel, the probes' own
    # among it, is counted as its CPU but is not in the server's figure, and
    # on the dev VM drifts from some 15 us a request to 100 us at times.
    local kids="/k?size=200&cpu=2000&kids=3&kcpu=1500&cpu2=1000"
    rt_run "$rt-kids" "$server" 32 0 "$kids" && {
        ge "$(val cpu_ok_pct)" "$ATTR_OK_PCT_MIN" && (( $(val cpu_n) > 100 )) \
            && ok "$rt: a handler waiting for what it spawned has its own CPU by unit ($(val cpu_ok_pct)% of $(val cpu_n) right)" \
            || bad "$rt: by unit, a handler waiting for what it spawned: CPU ok $(val cpu_ok_pct)%, total $(val cpu_err_pct)%"
    }
    rt_run "$rt-kids-by-thread" "$server" 32 0 "$kids" --threads-only && {
        le "$(val cpu_ok_pct)" 60 && (( $(val cpu_n) > 100 )) \
            && ok "$rt: by thread, the same load is wrong: the spawned units' CPU is the handler's ($(val cpu_ok_pct)% right, total $(val cpu_err_pct)%)" \
            || bad "$rt: by thread the handler's CPU is still right ($(val cpu_ok_pct)%): the load does not tell the two apart"
    }
    rt_run "$rt-timer" "$server" 32 0 "$RT_TIMER_PATHS" && {
        # CPU the agent could not place is counted where it reads which unit
        # a thread runs (Go); with a probe at every switch (tokio) there is
        # none to count, and the counter is not printed.
        unseen=$(kernel_counter "$WORK/r_$rt-timer.log" unit_cpu_unseen_ns)
        note "unit_cpu_unseen_ns=${unseen:-not counted}"
        unseen_ok=0
        if [[ -n "$unseen" ]]; then
            (( unseen < 10000000 )) && unseen_ok=1
        elif [[ $rt != go ]]; then
            unseen_ok=1
        fi
        # Probes say where the runtime switches goroutines or tasks: the CPU
        # around the timer wait is placed, and placed right.
        ge "$(val cpu_ok_pct)" "$ATTR_OK_PCT_MIN" && le "$(abs "$(val cpu_err_pct)")" 5 \
            && (( $(val cpu_n) > 100 && unseen_ok )) \
            && ok "$rt: CPU around a timer wait goes to the right request ($(val cpu_ok_pct)% of $(val cpu_n), total $(val cpu_err_pct)%, $([[ -n "$unseen" ]] && echo "${unseen}ns not placed" || echo "unplaced CPU not counted for $rt"))" \
            || bad "$rt: timer case: ok $(val cpu_ok_pct)%, total $(val cpu_err_pct)%, unit_cpu_unseen_ns=$unseen"
    }
}

GO_CMD="${GO:-$(command -v go || true)}"
if [[ -n "$GO_CMD" ]]; then
    (cd "$SCN_DIR/../tools/go_truth" && GOTOOLCHAIN=local "$GO_CMD" build -o "$WORK/go_truth" .) \
        && rt_suite go "$WORK/go_truth" goroutine-level \
        || bad "go: the test server did not build"
else
    note "no Go toolchain (set GO or put go on PATH); the Go server is skipped"
fi

# Over TLS, read from Go's crypto/tls (--tls): the same figures as without.
# Every Write and the handshake make a socket call that shows the connection.
if [[ -n "$GO_CMD" && -x "$WORK/go_truth" && -n "$HAVE_TLS" ]]; then
    tls_on
    rt_run go-tls "$WORK/go_truth" 8 2000 "$RT_PATHS" && {
        grep -q "^blame: pid $SERVER_PID: .*TLS read from Go's crypto/tls" "$WORK/r_go-tls.log" \
            && ok "go-tls: the server's crypto/tls is read" \
            || bad "go-tls: $(grep "^blame: pid $SERVER_PID" "$WORK/r_go-tls.log")"
        rt_attributed go-tls
        expect_no_loss go-tls "$WORK/r_go-tls.log" tls_no_socket tls_unread
    }
    rt_run go-tls-busy "$WORK/go_truth" 32 0 "$RT_PATHS" && rt_attributed go-tls-busy
    tls_off
fi

TT_TARGET="$(dirname "$(dirname "$BIN")")/tokio_truth"
tt_build() { cargo build --release --quiet "$@" --manifest-path "$SCN_DIR/../tools/tokio_truth/Cargo.toml" --target-dir "$TT_TARGET"; }
{ tt_build --offline 2>/dev/null || tt_build; } \
    && rt_suite tokio "$TT_TARGET/release/tokio_truth" task-level \
    || bad "tokio: the test server did not build"

# The same server over rustls (tokio-rustls, built with its `tls` feature).
if [[ -n "$HAVE_TLS" ]]; then
    ttt_build() { cargo build --release --quiet --features tls "$@" --manifest-path "$SCN_DIR/../tools/tokio_truth/Cargo.toml" --target-dir "$TT_TARGET-tls"; }
    if { ttt_build --offline 2>/dev/null || ttt_build; }; then
        tls_on
        rt_run tokio-tls "$TT_TARGET-tls/release/tokio_truth" 8 2000 "$RT_PATHS" && {
            grep -q "^blame: pid $SERVER_PID: .*TLS read from rustls" "$WORK/r_tokio-tls.log" \
                && ok "tokio-tls: the server's rustls is read" \
                || bad "tokio-tls: $(grep "^blame: pid $SERVER_PID" "$WORK/r_tokio-tls.log")"
            rt_attributed tokio-tls
            expect_no_loss tokio-tls "$WORK/r_tokio-tls.log" tls_no_socket tls_unread
        }
        rt_run tokio-tls-busy "$TT_TARGET-tls/release/tokio_truth" 32 0 "$RT_PATHS" && rt_attributed tokio-tls-busy
        tls_off
    else
        bad "tokio-tls: the test server did not build"
    fi
fi

# A server that starts after the agent is found when it accepts a connection,
# and looked at within a second; from then on it is attributed by unit.
RT_LATE="$TT_TARGET/release/tokio_truth"
[[ -x "$RT_LATE" ]] && {
    start_server tpc "$BACKEND_PORT" "$WORK/be.bin"
    start_agent "$WORK/r_late.log" && {
        spawn "$RT_LATE" "$PORT" "$WORK/r_late.bin" -b "$BACKEND_PORT" -p 2
        SERVER_PID="${_TRACKED[-1]}"
        sleep 0.5
        load 4 1 2000 "/n?size=200&cpu=300"
        sleep 1.2
        late_from=$(boot_ns)
        load 32 "$DUR" 0 "$RT_PATHS"
        stop_agent
        stop_servers
        check "$WORK/r_late.bin" "$WORK/r_late.log" --after-ns "$late_from"
        grep -q "^blame: pid $SERVER_PID: .*task-level\$" "$WORK/r_late.log" \
            && ge "$(val paired_pct)" "$PAIRED_PCT_MIN" \
            && ge "$(val down_ok_pct)" "$ATTR_OK_PCT_MIN" && ge "$(val cpu_ok_pct)" "$ATTR_OK_PCT_MIN" \
            && (( $(val down_n) > 100 )) \
            && ok "a server started after the agent is recognised and attributed by task (seen $(val paired_pct)%, CPU $(val cpu_ok_pct)%, downstream $(val down_ok_pct)%)" \
            || bad "late server: $(grep "^blame: pid $SERVER_PID" "$WORK/r_late.log") seen $(val paired_pct)%, CPU $(val cpu_ok_pct)% downstream $(val down_ok_pct)% of $(val down_n)"
    }
}
}

# --- [9] HTTP/2 ---------------------------------------------------------------
want 9 && {
echo
echo "[9] HTTP/2 streams against a server that speaks it frame by frame"
h2val() { echo "$H2 " | grep -oP "(?<=\\b$1=)[0-9]+"; }
# h2_case NAME CHUNK [CLIENT [TOL_US]]: every shape of request and answer (or
# what CLIENT sends); the server reads CHUNK bytes at a time. TOL_US: how far
# a start or end may be from the server's.
h2_case() {
    local name=$1 chunk=$2 said
    spawn python3 "$WORKLOADS/h2_quirks.py" serve "$PORT" "$WORK/h2_$name.srv" "$chunk"
    SERVER_PID="${_TRACKED[-1]}"
    sleep 0.5
    start_agent "$WORK/h2_$name.log" --pid "$SERVER_PID" || return
    said=$(python3 "$WORKLOADS/h2_quirks.py" "${3:-client}" "$PORT")
    stop_agent
    stop_servers
    run_checker H2 "$WORKLOADS/h2_check.py" "$WORK/h2_$name.srv" "$WORK/h2_$name.log" --tol-us "${4:-300}"
    note "$said"
    note "$H2"
    (( $(h2val streams) >= 290 && $(h2val missing) == 0 && $(h2val extra) == 0 )) \
        && ok "$name: every stream the server answered is reported once ($(h2val answered))" \
        || bad "$name: missing=$(h2val missing) extra=$(h2val extra) of $(h2val answered)"
    # One freeze of the dev VM mistimes the streams in flight; a handful at most.
    (( $(h2val mistimed) * 50 <= $(h2val answered) )) \
        && ok "$name: their starts and ends match the server's ($(h2val paired) of $(h2val answered))" \
        || bad "$name: $(h2val mistimed) of $(h2val answered) streams mistimed"
    local resets
    resets=$(kernel_counter "$WORK/h2_$name.log" req_reset)
    (( $(h2val reset) > 20 && $(h2val reset_reported) == $(h2val reset) && $(h2val misflagged) == 0 \
        && resets == $(h2val reset) )) \
        && ok "$name: streams reset by either side are reported as reset, and no others ($resets)" \
        || bad "$name: reset=$(h2val reset) reported=$(h2val reset_reported) misflagged=$(h2val misflagged) req_reset=$resets"
    [[ "$(kernel_counter "$WORK/h2_$name.log" req_aborted)" == "0" ]] \
        && ok "$name: nothing is aborted" \
        || bad "$name: req_aborted=$(kernel_counter "$WORK/h2_$name.log" req_aborted)"
    expect_no_loss "$name" "$WORK/h2_$name.log" req_h2_lost req_stream_insert_failed req_insert_failed ringbuf_full
    [[ "$(kernel_counter "$WORK/h2_$name.log" in_flight)" == "0" ]] \
        && ok "$name: no stream left in flight" \
        || bad "$name: in_flight=$(kernel_counter "$WORK/h2_$name.log" in_flight)"
}
h2_case whole-frames 4096
# Seven bytes a read: every frame header straddles two reads.
h2_case split-headers 7
# Hundreds of streams opened in one read, then reset in one write and
# answered in another, while 40 others wait for their answers: more stream
# events in a call than are acted on at a time. The server's stamps come
# after the agent dealt with those calls (about 2 us a stream), hence 2 ms.
h2_case storm 65536 storm 2000

# Connections that are already open, with streams in flight, when the agent
# attaches: each direction gets in step at a call that is frames from end to
# end, and from then on streams are followed.
spawn python3 "$WORKLOADS/h2_quirks.py" serve "$PORT" "$WORK/h2_late.srv"
SERVER_PID="${_TRACKED[-1]}"
sleep 0.5
# Long enough to outlast the agent's start (about 2 s) by a few seconds.
python3 "$WORKLOADS/h2_quirks.py" steady "$PORT" 7 >/dev/null &
steady=$!
sleep 1
start_agent "$WORK/h2_late.log" --pid "$SERVER_PID" && {
    sleep 0.5
    late_from=$(boot_ns)
    wait "$steady"
    stop_agent
    stop_servers
    run_checker H2 "$WORKLOADS/h2_check.py" "$WORK/h2_late.srv" "$WORK/h2_late.log" --after-ns "$late_from"
    note "$H2"
    (( $(h2val answered) > 500 && $(h2val missing) == 0 && $(h2val extra) == 0 \
        && $(h2val mistimed) * 50 <= $(h2val answered) )) \
        && ok "connections open before the agent: streams are followed once in step ($(h2val paired) of $(h2val answered))" \
        || bad "late attach: $H2"
    expect_no_loss late "$WORK/h2_late.log" req_h2_lost
}
wait "$steady" 2>/dev/null

# The table for people.
spawn python3 "$WORKLOADS/h2_quirks.py" serve "$PORT" "$WORK/h2_text.srv"
SERVER_PID="${_TRACKED[-1]}"
sleep 0.5
sudo -n "$BIN" slow --above 15 --interval 0 --pid "$SERVER_PID" >"$WORK/h2_text.log" 2>&1 &
AGENT_JOB=$!
for _ in $(seq 100); do grep -q 'slow attached' "$WORK/h2_text.log" 2>/dev/null && break; sleep 0.1; done
python3 "$WORKLOADS/h2_quirks.py" client "$PORT" >/dev/null
stop_agent
stop_servers
grep -qE "^  [0-9:.]+  [0-9.]+ms  HTTP/2 stream [0-9]+ on :$PORT  " "$WORK/h2_text.log" \
    && grep -q 'its handler was not followed: no time breakdown' "$WORK/h2_text.log" \
    && ok "a slow stream is shown as one, and says what it does not have" \
    || bad "no HTTP/2 stream line: $(grep -m3 'HTTP/2' "$WORK/h2_text.log")"
}

# --- [10] gRPC ----------------------------------------------------------------
want 10 && {
echo
echo "[10] gRPC calls against servers that log what they did (grpc-go, tonic)"
gval() { echo "$GRPC " | grep -oP "(?<=\b$1=)[-+]?[0-9.]+"; }
# Calls the client gives up on after 20 ms are part of every load ("T").
GRPC_PARAMS="1500,0,0,0;1000,2000,1500,0;500,500,500,0;3000,0,0,0;1000,0,0,5"
# grpc_run NAME CLIENT_ARGS... -- SERVER...: the server, the agent on it, the
# load; the comparison lands in GRPC. The server is given PORT LOGFILE 2.
grpc_run() {
    local name=$1 args=()
    shift
    while [[ "$1" != "--" ]]; do args+=("$1"); shift; done
    shift
    spawn "$@" "$PORT" "$WORK/g_$name.srv" 2
    SERVER_PID="${_TRACKED[-1]}"
    sleep 0.5
    start_agent "$WORK/g_$name.log" --pid "$SERVER_PID" || return 1
    "$WORK/grpc_client" "$PORT" 4 8 "$DUR" "${args[@]}" >"$WORK/g_$name.cli"
    stop_agent
    stop_servers
    run_checker GRPC "$WORKLOADS/grpc_check.py" "$WORK/g_$name.srv" "$WORK/g_$name.log" "$WORK/g_$name.cli"
    note "$(grep -m1 "^blame: pid $SERVER_PID" "$WORK/g_$name.log")"
    note "$GRPC"
}
# handler_parts NAME: the time before a call's handler first ran and after
# it last left: it first ran no later than the server's handler started, and
# last left no earlier than it returned. A call whose handler switch the
# agent missed has its CPU wrong as well (checked apart); the others, all.
handler_parts() {
    (( $(gval timed_cpu_ok) > 1000 && $(gval parts_ok_cpu_ok) == $(gval timed_cpu_ok) )) \
        && ok "$1: the time before its handler first ran and after it last left is within the server's ($(gval before_us)us and $(gval after_us)us on average, $(gval timed_cpu_ok) calls)" \
        || bad "$1: handler_timed=$(gval handler_timed) of $(gval followed), parts ok $(gval parts_ok_cpu_ok) of $(gval timed_cpu_ok) (all: before $(gval before_ok), after $(gval after_ok))"
}
# grpc_case NAME UNFOLLOWED_MAX_PCT CLIENT_ARGS... -- SERVER...: every call is
# reported once, as what it was, with the time of the handler that ran it.
grpc_case() {
    local name=$1 slack=$2
    shift 2
    grpc_run "$name" "$@" || return
    grep -q "^blame: pid $SERVER_PID: .*handlers followed" "$WORK/g_$name.log" \
        && ok "$name: the server is recognised and its handlers are followed" \
        || bad "$name: $(grep -m1 "^blame: pid $SERVER_PID" "$WORK/g_$name.log")"
    (( $(gval served) > 1000 && $(gval by_trace) == $(gval served) && $(gval named) == $(gval reported) \
       && $(gval dup_trace) == 0 && $(gval trace_wrong) == 0 )) \
        && ok "$name: every call the server handled is reported once, with its trace id ($(gval served))" \
        || bad "$name: served=$(gval served) by_trace=$(gval by_trace) reported=$(gval reported) named=$(gval named) reported twice=$(gval dup_trace) trace ids of no call=$(gval trace_wrong)"
    (( $(gval path_ok) == $(gval joined) && $(gval statuses) > 1000 && $(gval status_ok) == $(gval statuses) )) \
        && ok "$name: with the method the server ran and the status it answered" \
        || bad "$name: path_ok=$(gval path_ok) of $(gval joined), status_ok=$(gval status_ok) of $(gval statuses)"
    # Calls the client gave up on: reset, or answered as cancelled, 20 ms in.
    (( $(gval timeouts) > 200 && $(gval timeout_ok) * 100 >= $(gval timeouts) * 99 && $(gval resets) > 100 )) \
        && ok "$name: calls the client gave up on are reported as that ($(gval timeout_ok) of $(gval timeouts), $(gval resets) reset)" \
        || bad "$name: timeouts=$(gval timeouts) timeout_ok=$(gval timeout_ok) resets=$(gval resets)"
    (( ($(gval statuses) - $(gval followed)) * 100 <= $(gval statuses) * slack )) \
        && ok "$name: time is attributed to the calls that were answered ($(gval followed) of $(gval statuses))" \
        || bad "$name: followed=$(gval followed) of $(gval statuses)"
    (( $(gval followed) > 0 && $(gval unit_ok) == $(gval followed) && $(gval inside) == $(gval followed) )) \
        && ok "$name: to the unit that ran each, which ran between the reported start and end" \
        || bad "$name: unit_ok=$(gval unit_ok) inside=$(gval inside) of $(gval followed)"
    # Before the handler first ran and after it last left: it first ran no
    # later than the server's handler started, and last left no earlier than
    # it returned. A call whose handler switch the agent missed has its CPU
    # wrong as well (checked below); those apart, for every call.
    if (( $(gval handler_timed) == $(gval followed) )); then
        handler_parts "$name"
    else
        bad "$name: before/after handler known for $(gval handler_timed) of $(gval followed) followed calls"
    fi

    # The server's figure includes time its threads were preempted, which
    # the agent reports as run-queue time: the total may be short by that.
    ge "$(gval cpu_ok_pct)" 95 && le "$(gval cpu_err_pct)" 5 \
        && ge "$(awk -v e="$(gval cpu_err_pct)" -v r="$(gval runq_pct)" 'BEGIN { print e + r }')" -5 \
        && ok "$name: CPU time matches the server's ($(gval cpu_ok_pct)% of calls, total $(gval cpu_err_pct)%, run queue $(gval runq_pct)%)" \
        || bad "$name: CPU time: ok $(gval cpu_ok_pct)%, total $(gval cpu_err_pct)%, run queue $(gval runq_pct)%"
    # The summary by method: every call counted under its method, by how it
    # ended, and adding up to the requests listed one by one.
    (( $(gval m_paths) > 0 && $(gval m_calls_ok) == $(gval m_paths) && $(gval m_ends_ok) == $(gval m_paths) \
        && $(gval m_listed_ok) == $(gval m_paths) )) \
        && ok "$name: the summary by method has every call, under its method, by how it ended ($(gval m_paths) methods)" \
        || bad "$name: methods=$(gval m_paths) calls_ok=$(gval m_calls_ok) ends_ok=$(gval m_ends_ok) listed_ok=$(gval m_listed_ok)"
    expect_no_loss "$name" "$WORK/g_$name.log" grpc_handoff_unmatched req_h2_lost ringbuf_full req_aborted
}

# grpc_late NAME CLIENT_ARGS... -- SERVER...: the load starts first, the
# agent a second later, on connections that are already open.
grpc_late() {
    local name=$1 args=() load
    shift
    while [[ "$1" != "--" ]]; do args+=("$1"); shift; done
    shift
    spawn "$@" "$PORT" "$WORK/g_$name.srv" 2
    SERVER_PID="${_TRACKED[-1]}"
    sleep 0.5
    "$WORK/grpc_client" "$PORT" 4 8 8 "${args[@]}" >"$WORK/g_$name.cli" &
    load=$!
    sleep 1
    start_agent "$WORK/g_$name.log" --pid "$SERVER_PID" || { wait "$load"; return 1; }
    # When the agent was seen to say it is attached: no earlier than it was.
    local attached
    attached=$(python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_BOOTTIME))')
    wait "$load"
    stop_agent
    stop_servers
    export GRPC_ATTACHED_NS=$attached
    run_checker GRPC "$WORKLOADS/grpc_check.py" "$WORK/g_$name.srv" "$WORK/g_$name.log" "$WORK/g_$name.cli"
    unset GRPC_ATTACHED_NS
    note "$GRPC"
}

if [[ -n "${GO_CMD:=${GO:-$(command -v go || true)}}" ]] \
    && (cd "$SCN_DIR/../tools/grpc_go_truth" \
        && GOTOOLCHAIN=local "$GO_CMD" build -o "$WORK/grpc_go" ./server \
        && GOTOOLCHAIN=local "$GO_CMD" build -trimpath -ldflags="-s -w" -o "$WORK/grpc_go_stripped" ./server \
        && GOTOOLCHAIN=local "$GO_CMD" build -o "$WORK/grpc_client" ./client) 2>"$WORK/grpc_build.log"; then
    grpc_case go 0 "U,SS,CS,BI,T" "$GRPC_PARAMS" -- "$WORK/grpc_go"
    # Without symbols the functions are found in Go's own table.
    grpc_case go-stripped 0 "U,SS,CS,BI,T" "$GRPC_PARAMS" -- "$WORK/grpc_go_stripped"
    # Handlers run on a fixed set of goroutines instead of one each.
    grpc_case go-workers 0 "U,BI,T" "$GRPC_PARAMS" -- env WORKERS=8 "$WORK/grpc_go"
    # Over TLS, read from crypto/tls (--tls): the same.
    if [[ -n "$HAVE_TLS" ]]; then
        tls_on
        grpc_case go-tls 0 "U,SS,CS,BI,T" "$GRPC_PARAMS" -- "$WORK/grpc_go"
        expect_no_loss go-tls "$WORK/g_go-tls.log" tls_no_socket tls_unread
        tls_off
    fi

    # The summary does not depend on what is listed: with a threshold no call
    # reaches, nothing is listed and every call is still counted. As a table,
    # it has a row per method.
    for mode in --raw ""; do
        # One set of files per mode, so a failure leaves its own behind.
        q="$WORK/g_quiet${mode:+_raw}"
        spawn "$WORK/grpc_go" "$PORT" "$q.srv" 2
        SERVER_PID="${_TRACKED[-1]}"
        sleep 0.5
        # shellcheck disable=SC2086
        sudo -n "$BIN" slow $mode --above 60000 --interval 0 --pid "$SERVER_PID" >"$q.log" 2>&1 &
        AGENT_JOB=$!
        for _ in $(seq 100); do grep -q 'slow attached' "$q.log" 2>/dev/null && break; sleep 0.1; done
        "$WORK/grpc_client" "$PORT" 4 8 "$DUR" "U,SS,CS,BI,T" "$GRPC_PARAMS" >"$q.cli"
        stop_agent
        stop_servers
        if [[ -n "$mode" ]]; then
            run_checker GRPC "$WORKLOADS/grpc_check.py" "$q.srv" "$q.log" "$q.cli"
            note "$GRPC"
            (( $(gval reported) == 0 && $(gval m_paths) == 4 && $(gval m_calls_ok) == 4 && $(gval m_ends_ok) == 4 )) \
                && ok "nothing slow enough to list: the summary by method is complete all the same" \
                || bad "quiet: reported=$(gval reported) methods=$(gval m_paths) calls_ok=$(gval m_calls_ok) ends_ok=$(gval m_ends_ok)"
        else
            grep -qE '^  service +method +calls +errors +reset +p50 +p99 +max +on_cpu +runq +disk +fileservice +memory +other +off_thread +before +after +parked +not_seen$' "$q.log" \
                && (( $(grep -cE '^  \S+ +/x\.S/(U|SS|CS|BI) +[0-9]+ +[0-9]+ +[0-9]+ ' "$q.log") == 4 )) \
                && ok "the summary for people is a table with a row per method" \
                || bad "no method table: $(grep -m3 -A3 'method' "$q.log")"
        fi
    done

    # --json: the same findings as records, one JSON object a line and
    # nothing else on standard output. Every call is slow here (--above 0),
    # so only the 50 slowest are listed, at the end.
    spawn "$WORK/grpc_go" "$PORT" "$WORK/g_json.srv" 2
    SERVER_PID="${_TRACKED[-1]}"
    sleep 0.5
    sudo -n "$BIN" slow --json --above 0 --interval 1 --pid "$SERVER_PID" >"$WORK/g_json.log" 2>"$WORK/g_json.err" &
    AGENT_JOB=$!
    for _ in $(seq 100); do grep -q '"type":"process"' "$WORK/g_json.log" 2>/dev/null && break; sleep 0.1; done
    "$WORK/grpc_client" "$PORT" 4 8 "$DUR" "U,SS,CS,BI,T" "$GRPC_PARAMS" >"$WORK/g_json.cli"
    stop_agent
    stop_servers
    "$BIN" slow --json-fields >"$WORK/g_json.fields"
    run_checker GRPC "$WORKLOADS/grpc_json_check.py" "$WORK/g_json.srv" "$WORK/g_json.log" "$WORK/g_json.cli" "$WORK/g_json.fields"
    note "$GRPC"
    (( $(gval lines) > 20 && $(gval bad) == 0 && $(gval framed) == 1 )) && [[ ! -s "$WORK/g_json.err" ]] \
        && ok "json: every line of output is a record of a known type, from start to the final health ($(gval lines))" \
        || bad "json: lines=$(gval lines) bad=$(gval bad) framed=$(gval framed) stderr=$(head -c 200 "$WORK/g_json.err")"
    (( $(gval calls) == 50 && $(gval slowest) == 1 && $(gval slow) == $(gval total_calls) && $(gval slow) > 1000 )) \
        && ok "json: of $(gval slow) slow calls the 50 slowest are listed, slowest first" \
        || bad "json: calls=$(gval calls) slowest=$(gval slowest) slow=$(gval slow) total_calls=$(gval total_calls)"
    (( $(gval m_paths) == 4 && $(gval m_calls_ok) == 4 && $(gval m_ends_ok) == 4 )) \
        && ok "json: the summary by method agrees with the server and the client" \
        || bad "json: methods=$(gval m_paths) calls_ok=$(gval m_calls_ok) ends_ok=$(gval m_ends_ok)"
    (( $(gval followed) == 1 && $(gval lost) == 0 && $(gval undescribed) == 0 )) \
        && ok "json: it says what was found out about the process and that nothing was lost; --json-fields describes every field" \
        || bad "json: followed=$(gval followed) lost=$(gval lost) $(echo "$GRPC" | grep -o 'undescribed=.*')"

    # Connections opened before the agent. What their header tables held is
    # not known, so the header blocks cannot be decoded; the process has
    # decoded them, and the probes in it give the method, the trace id and
    # the status (all but the calls whose headers were read before the
    # probes were attached). Whatever is named is right, and handlers are
    # followed. Calls are matched by trace id, or by client port and
    # stream id where there is none.
    # go_late_checks NAME: what is checked of a go-late case.
    go_late_checks() {
        # Not joined: the calls in flight when the probes were attached, whose
        # headers were read before. 32 streams are in flight at a time; three
        # times that is allowed, whatever the number of calls.
        (( $(gval reported) > 1000 && $(gval reported) - $(gval joined) <= 96 )) \
            && ok "$1: calls on connections older than the agent are reported ($(gval reported), $(minus "$(gval reported)" "$(gval joined)") from before the probes)" \
            || bad "$1: reported=$(gval reported) joined=$(gval joined)"
        (( $(gval paths) * 100 >= $(gval joined) * 99 && $(gval path_ok) == $(gval paths) )) \
            && ok "$1: nearly all get their method ($(gval paths) of $(gval joined)), none a wrong one" \
            || bad "$1: paths=$(gval paths) path_ok=$(gval path_ok) of $(gval joined)"
        # Calls whose headers were read before the probes were on have no
        # trace id; how many depends on how long attaching takes. Every call
        # that started after the agent said it was attached has one.
        (( $(gval late_calls) > 1000 && $(gval late_no_trace) == 0 && $(gval trace_wrong) == 0 )) \
            && ok "$1: every call begun after attaching has its trace id ($(gval late_calls); of all $(gval with_trace) of $(gval reported)), none a wrong one" \
            || bad "$1: late_calls=$(gval late_calls) late_no_trace=$(gval late_no_trace) trace_wrong=$(gval trace_wrong)"
        (( $(gval statuses) * 100 >= $(gval answered) * 97 && $(gval statuses) == $(gval status_ok) )) \
            && ok "$1: nearly all answered calls have their status ($(gval statuses) of $(gval answered)), all the server's" \
            || bad "$1: statuses=$(gval statuses) status_ok=$(gval status_ok) answered=$(gval answered)"
        (( $(gval followed) > 1000 && $(gval unit_ok) == $(gval followed) && $(gval inside) == $(gval followed) \
            && ($(gval joined) - $(gval resets) - $(gval followed)) * 100 <= $(gval joined) )) \
            && ok "$1: their handlers are followed ($(gval followed) of $(minus "$(gval joined)" "$(gval resets)") answered)" \
            || bad "$1: followed=$(gval followed) unit_ok=$(gval unit_ok) inside=$(gval inside) joined=$(gval joined) resets=$(gval resets)"
        ge "$(gval cpu_ok_pct)" 95 && le "$(gval cpu_err_pct)" 5 \
            && ge "$(awk -v e="$(gval cpu_err_pct)" -v r="$(gval runq_pct)" 'BEGIN { print e + r }')" -5 \
            && ok "$1: CPU time matches the server's ($(gval cpu_ok_pct)% of calls, total $(gval cpu_err_pct)%)" \
            || bad "$1: CPU time: ok $(gval cpu_ok_pct)%, total $(gval cpu_err_pct)%, run queue $(gval runq_pct)%"
        # Every call begun after attaching has the two parts.
        if (( $(gval late_followed) > 1000 && $(gval late_untimed) == 0 )); then
            handler_parts "$1"
        else
            bad "$1: late_followed=$(gval late_followed) late_untimed=$(gval late_untimed)"
        fi
        expect_no_loss "$1" "$WORK/g_$1.log" grpc_handoff_unmatched req_h2_lost
    }
    grpc_late go-late "U,SS,CS,BI,T" "$GRPC_PARAMS" -- "$WORK/grpc_go" && go_late_checks go-late
    # Over TLS: the connections' sessions are placed by the socket calls the
    # first Reads and Writes after attaching make.
    if [[ -n "$HAVE_TLS" ]]; then
        tls_on
        grpc_late go-tls-late "U,SS,CS,BI,T" "$GRPC_PARAMS" -- "$WORK/grpc_go" && {
            go_late_checks go-tls-late
            expect_no_loss go-tls-late "$WORK/g_go-tls-late.log" tls_unread
            # A Read served from what the session took in before, with no
            # socket call, until one of its calls makes one: a few on each of
            # the client's 4 connections, counted.
            nosock=$(kernel_counter "$WORK/g_go-tls-late.log" tls_no_socket)
            isnum "$nosock" && (( nosock <= 16 )) \
                && ok "go-tls-late: calls of sessions older than the agent before their socket was seen: $nosock, counted" \
                || bad "go-tls-late: tls_no_socket=$nosock"
        }
        tls_off
    fi

    # The same, from a client that sends no trace header: every call has the
    # same headers, so HPACK never spells the method out again and the header
    # blocks of an older connection give no method at all. Only the process
    # can say it (and the status, which the server's table holds).
    NO_TRACEPARENT=1 grpc_late go-late-notrace "U,SS" "$GRPC_PARAMS" -- "$WORK/grpc_go" && {
        wrong=$(grep '^req ' "$WORK/g_go-late-notrace.log" | grep -v ' path=-' | grep -vc ' path=/x\.S/\(U\|SS\) ')
        (( $(gval reported) > 1000 && $(gval named) * 100 >= $(gval reported) * 99 && wrong == 0 )) \
            && ok "go-late-notrace: the method of every call is known ($(gval named) of $(gval reported)), none a wrong one" \
            || bad "go-late-notrace: reported=$(gval reported) named=$(gval named) wrong=$wrong"
        (( $(gval statuses) * 100 >= $(gval answered) * 97 && $(gval statuses) == $(gval status_ok) )) \
            && ok "go-late-notrace: nearly all answered calls have their status ($(gval statuses) of $(gval answered)), all the server's" \
            || bad "go-late-notrace: statuses=$(gval statuses) status_ok=$(gval status_ok) answered=$(gval answered)"
    }

    GT_TARGET="$(dirname "$(dirname "$BIN")")/tonic_truth"
    gt_build() { cargo build --release --quiet "$@" --manifest-path "$SCN_DIR/../tools/tonic_truth/Cargo.toml" --target-dir "$GT_TARGET"; }
    if { gt_build --offline 2>/dev/null || gt_build 2>>"$WORK/grpc_build.log"; }; then
        # The first calls are not followed: where a task keeps its stream id
        # is found from them.
        grpc_case tonic 5 "U,U,U,T" "$GRPC_PARAMS" hello -- "$GT_TARGET/release/tonic_truth"
        # Over TLS, read from rustls (--tls): the same.
        if [[ -n "$HAVE_TLS" ]]; then
            tls_on
            grpc_case tonic-tls 5 "U,U,U,T" "$GRPC_PARAMS" hello -- "$GT_TARGET/release/tonic_truth"
            expect_no_loss tonic-tls "$WORK/g_tonic-tls.log" tls_no_socket tls_unread
            tls_off
        fi
        grep -q "^blame: pid [0-9]*: stream handlers found" "$WORK/g_tonic.log" \
            && ok "tonic: where a task keeps its stream id is found while running" \
            || bad "tonic: the stream id was not found in the tasks"

        # The same for tonic. Its server does not let a handler see the
        # stream id, so calls cannot be matched one by one: the server has a
        # single method, and every name given must be that one.
        # tonic_late_checks NAME: what is checked of a tonic-late case.
        tonic_late_checks() {
            wrong=$(grep '^req ' "$WORK/g_$1.log" | grep -v ' path=-' | grep -vc ' path=/helloworld.Greeter/SayHello ')
            (( $(gval reported) > 1000 && $(gval named) * 100 >= $(gval reported) * 95 && wrong == 0 )) \
                && ok "$1: most calls get their method ($(gval named) of $(gval reported)), none a wrong one" \
                || bad "$1: reported=$(gval reported) named=$(gval named) wrong=$wrong"
            (( $(gval timed) * 100 >= ($(gval reported) - $(gval resets)) * 95 )) \
                && ok "$1: their handlers are followed ($(gval timed) with time, $(gval resets) reset)" \
                || bad "$1: timed=$(gval timed) reported=$(gval reported) resets=$(gval resets)"
            (( $(gval late_calls) > 1000 && $(gval late_no_trace) == 0 && $(gval trace_wrong) == 0 )) \
                && ok "$1: every call begun after attaching has its trace id ($(gval late_calls); of all $(gval with_trace) of $(gval reported)), none a wrong one" \
                || bad "$1: late_calls=$(gval late_calls) late_no_trace=$(gval late_no_trace) trace_wrong=$(gval trace_wrong)"
            (( $(gval statuses) * 100 >= $(gval answered) * 97 && $(gval statuses) == $(gval status_ok) )) \
                && ok "$1: nearly all answered calls have their status ($(gval statuses) of $(gval answered)), all the server's" \
                || bad "$1: statuses=$(gval statuses) status_ok=$(gval status_ok) answered=$(gval answered)"
            # The status is read in the task that serves the call, as its
            # time is: a call has both or neither.
            (( $(gval status_untimed) == 0 && $(gval timed_no_status) == 0 )) \
                && ok "$1: a call has its status exactly when its handler is followed ($(( $(gval answered) - $(gval statuses) )) have neither)" \
                || bad "$1: status_untimed=$(gval status_untimed) timed_no_status=$(gval timed_no_status)"
            # Every call begun after attaching has the two parts.
            if (( $(gval late_followed) > 1000 && $(gval late_untimed) == 0 )); then
                handler_parts "$1"
            else
                bad "$1: late_followed=$(gval late_followed) late_untimed=$(gval late_untimed)"
            fi
            expect_no_loss "$1" "$WORK/g_$1.log" grpc_handoff_unmatched req_h2_lost h2_process_unread
        }
        grpc_late tonic-late "U,U,U,T" "$GRPC_PARAMS" hello -- "$GT_TARGET/release/tonic_truth" && tonic_late_checks tonic-late
        if [[ -n "$HAVE_TLS" ]]; then
            tls_on
            grpc_late tonic-tls-late "U,U,U,T" "$GRPC_PARAMS" hello -- "$GT_TARGET/release/tonic_truth" && {
                tonic_late_checks tonic-tls-late
                expect_no_loss tonic-tls-late "$WORK/g_tonic-tls-late.log" tls_no_socket tls_unread
            }
            tls_off
        fi
        # No trace header: the method is the only thing the process has to say.
        NO_TRACEPARENT=1 grpc_late tonic-late-notrace "U,U" "$GRPC_PARAMS" hello -- "$GT_TARGET/release/tonic_truth" && {
            wrong=$(grep '^req ' "$WORK/g_tonic-late-notrace.log" | grep -v ' path=-' | grep -vc ' path=/helloworld.Greeter/SayHello ')
            (( $(gval reported) > 1000 && $(gval named) * 100 >= $(gval reported) * 99 && wrong == 0 )) \
                && ok "tonic-late-notrace: the method of every call is known ($(gval named) of $(gval reported)), none a wrong one" \
                || bad "tonic-late-notrace: reported=$(gval reported) named=$(gval named) wrong=$wrong"
        }
    else
        note "the tonic server did not build (it needs its crates: network on the first build); skipped"
        note "$(tail -2 "$WORK/grpc_build.log")"
    fi
else
    note "the gRPC servers need a Go toolchain and grpc-go (set GO; network on the first build); skipped"
    [[ -s "$WORK/grpc_build.log" ]] && note "$(tail -2 "$WORK/grpc_build.log")"
fi
}

# --- [11] spawned units ------------------------------------------------------
want 11 && {
echo
echo "[11] goroutines and tasks a request spawns (--deep)"
# Plain requests; ones that spawn three units that compute; two that each
# spawn one more; two that write to disk and flush; and one that leaves a
# unit behind that works only after the response. Handlers and spawned units
# compute milliseconds, as in [8]: the servers log only their own spins, and
# what else is on the request's CPU (the framework's work around them, time
# in the kernel, the probes' own cost) has to stay within the tolerance.
SP_PATHS="/n?size=200&cpu=2400,/k?size=200&cpu=2000&kids=3&kcpu=1600&cpu2=1200,/k2?size=200&cpu=2000&kids=2&kcpu=1200&knest=1,/kf?size=200&cpu=2000&kids=2&kcpu=1000&kfsync=4,/b?size=200&cpu=2400&bg=2000"

# sp_run CASE SERVER FRAMEWORK_SPAWNS CONNS THINK_US [agent options]: the
# result lands in CHECK.
sp_run() {
    local name=$1 server=$2 own=$3 conns=$4 think=$5
    shift 5
    spawn ${SP_ENV:+env $SP_ENV} "$server" "$PORT" "$WORK/s_$name.bin" -p 2
    SERVER_PID="${_TRACKED[-1]}"
    sleep 0.5
    start_agent "$WORK/s_$name.log" --pid "$SERVER_PID" "$@" || return 1
    load "$conns" "$DUR" "$think" "$SP_PATHS"
    stop_agent
    stop_servers
    check "$WORK/s_$name.bin" "$WORK/s_$name.log" --framework-spawns "$own"
}

# sp_attributed CASE WHAT: the request itself as before, and its spawned
# units: how many, their CPU and their disk waits, against the server's.
sp_attributed() {
    local name=$1 what=$2 late
    (( $(val truth) == $(val kernel) && $(val truth) > 0 )) && ge "$(val paired_pct)" "$PAIRED_PCT_MIN" \
        && ok "$name: every request seen once, starts and ends match ($(val kernel), $(val paired_pct)%)" \
        || bad "$name: served $(val truth), reported $(val kernel), paired $(val paired_pct)%"
    ge "$(val cpu_ok_pct)" "$ATTR_OK_PCT_MIN" && le "$(abs "$(val cpu_err_pct)")" "$ATTR_ERR_PCT_MAX" \
        && ok "$name: the handler's own CPU still matches ($(val cpu_ok_pct)% of $(val cpu_n), total $(val cpu_err_pct)%)" \
        || bad "$name: handler CPU: ok $(val cpu_ok_pct)% of $(val cpu_n), total $(val cpu_err_pct)%"
    ge "$(val spawn_count_exact_pct)" 99 && (( $(val spawn_n) > 100 )) \
        && ok "$name: the $what each request spawned are all found ($(val spawn_count_exact_pct)% of $(val spawn_n) exact, short on $(val spawn_count_under), at most $(val spawn_count_over_max) extra)" \
        || bad "$name: $what spawned: exact $(val spawn_count_exact_pct)% of $(val spawn_n), short on $(val spawn_count_under), up to $(val spawn_count_over_max) extra"
    ge "$(val spawn_cpu_ok_pct)" "$ATTR_OK_PCT_MIN" && le "$(abs "$(val spawn_cpu_err_pct)")" "$ATTR_ERR_PCT_MAX" \
        && ok "$name: their CPU matches the server's ($(val spawn_cpu_ok_pct)% of $(val spawn_cpu_n), total $(val spawn_cpu_err_pct)%)" \
        || bad "$name: their CPU: ok $(val spawn_cpu_ok_pct)% of $(val spawn_cpu_n), total $(val spawn_cpu_err_pct)%"
    ge "$(val spawn_io_ok_pct)" "$ATTR_OK_PCT_MIN" && (( $(val spawn_io_n) > 100 && $(val spawn_io_other_us) <= $(val spawn_io_n) * 100 )) \
        && ok "$name: their disk waits match the server's ($(val spawn_io_ok_pct)% of $(val spawn_io_n), $(val spawn_io_other_us)us left in other)" \
        || bad "$name: their disk waits: ok $(val spawn_io_ok_pct)% of $(val spawn_io_n), $(val spawn_io_other_us)us in other"
    # Bar the framework's own unit, which does next to nothing.
    ge "$(val spawn_plain_exact_pct)" 99 && (( $(val spawn_extra_us) <= $(val spawn_plain_n) )) \
        && ok "$name: requests that spawn nothing have no spawned units of their own ($(val spawn_plain_exact_pct)% of $(val spawn_plain_n), $(val spawn_extra_us)us)" \
        || bad "$name: on requests that spawned nothing: exact $(val spawn_plain_exact_pct)% of $(val spawn_plain_n), $(val spawn_extra_us)us"
    # A unit that works only after the response (500 us each) gives the
    # request nothing.
    (( $(val spawn_after_n) > 100 && $(val spawn_after_us) <= $(val spawn_after_n) )) \
        && ok "$name: work left running after the response is not the request's ($(val spawn_after_us)us on $(val spawn_after_n) requests)" \
        || bad "$name: $(val spawn_after_us)us of after-the-response work on $(val spawn_after_n) requests"
}

# sp_suite RT SERVER FRAMEWORK_SPAWNS WHAT NOTE
sp_suite() {
    local rt=$1 server=$2 own=$3 what=$4 says=$5
    sp_run "$rt" "$server" "$own" 8 2000 --deep && {
        grep -q "^blame: pid $SERVER_PID: .*; $says" "$WORK/s_$rt.log" \
            && ok "$rt: says it follows them ($(grep -oP "^blame: pid $SERVER_PID: \K.*" "$WORK/s_$rt.log"))" \
            || bad "$rt: $(grep '^blame: pid' "$WORK/s_$rt.log")"
        sp_attributed "$rt" "$what"
    }
    # Busy, Go's garbage collector takes the scheduler threads from the
    # spawned goroutines now and then, for up to tens of milliseconds: the
    # goroutine is on no CPU and in no run queue, the agent rightly gives it
    # nothing, but the server times its spin by the clock. Seen: their CPU
    # total -3 to -12% with the collector on, +0.5 to +0.9% with it off, the
    # gap all in a few requests 20-46 ms short. So the collector is off here.
    SP_ENV="GOGC=off" sp_run "$rt-busy" "$server" "$own" 32 0 --deep && sp_attributed "$rt-busy" "$what"
    # Without the option nothing is followed, and nothing is made up.
    sp_run "$rt-off" "$server" 0 8 2000 && {
        # The handler's own CPU is right without the option too.
        ge "$(val cpu_ok_pct)" "$ATTR_OK_PCT_MIN" && le "$(abs "$(val cpu_err_pct)")" "$ATTR_ERR_PCT_MAX" \
            && (( $(val cpu_n) > 100 )) \
            && ok "$rt: without --deep the handler's CPU is still its own ($(val cpu_ok_pct)%, total $(val cpu_err_pct)%)" \
            || bad "$rt-off: handler CPU: ok $(val cpu_ok_pct)%, total $(val cpu_err_pct)%"
        (( $(val spawn_count_under) == $(val spawn_n) && $(val spawn_n) > 100 && $(val spawn_extra_us) == 0 )) \
            && ok "$rt: without --deep no request has spawned units ($(val spawn_n) that did)" \
            || bad "$rt-off: spawn_count_under=$(val spawn_count_under) of $(val spawn_n), extra $(val spawn_extra_us)us"
    }
}

SP_GO="${GO:-$(command -v go || true)}"
if [[ -n "$SP_GO" ]]; then
    (cd "$SCN_DIR/../tools/go_truth" && GOTOOLCHAIN=local "$SP_GO" build -o "$WORK/go_truth" .) \
        && sp_suite go "$WORK/go_truth" 1 goroutines "spawned goroutines followed" \
        || bad "go: the test server did not build"
else
    note "no Go toolchain (set GO or put go on PATH); the Go server is skipped"
fi
SP_TT="$(dirname "$(dirname "$BIN")")/tokio_truth"
sp_tt_build() { cargo build --release --quiet "$@" --manifest-path "$SCN_DIR/../tools/tokio_truth/Cargo.toml" --target-dir "$SP_TT"; }
# tokio also runs closures on its blocking pool (spawn_blocking: tokio::fs
# does all its work so), which are tasks of their own spawned another way.
{ sp_tt_build --offline 2>/dev/null || sp_tt_build; } \
    && SP_PATHS="$SP_PATHS,/bk?size=200&cpu=2000&blk=2&bcpu=1200&bfsync=4" \
        sp_suite tokio "$SP_TT/release/tokio_truth" 0 tasks "spawned tasks followed" \
    || bad "tokio: the test server did not build"
}

# --- [12] file services -------------------------------------------------------
want 12 && {
echo
echo "[12] waits for a file service (NFS, FUSE, virtiofs) are not disk waits"
# A directory on a file service: BLAME_FSVC_DIR, else this checkout if it is
# on one (a shared folder in a VM).
is_fsvc() { case "$(stat -f -c %t "$1" 2>/dev/null)" in 6969|65735546|ff534d42|fe534d42|1021997|c36400) return 0;; esac; return 1; }
FSVC_DIR="${BLAME_FSVC_DIR:-}"
[[ -z "$FSVC_DIR" ]] && is_fsvc "$SCN_DIR" && FSVC_DIR="$SCN_DIR"
# fs_case NAME DIR PATHS [CONNS THINK_US]: a server whose files are in DIR;
# the result lands in CHECK.
fs_case() {
    local name=$1 dir=$2 paths=$3 conns=${4:-4} think=${5:-2000}
    start_server tpc "$PORT" "$dir/f_$name.bin"
    curl -s -o /dev/null "http://127.0.0.1:$PORT/warm?io=4"
    start_agent "$WORK/f_$name.log" --pid "$SERVER_PID" || return 1
    load "$conns" "$DUR" "$think" "/n?size=200&cpu=300,$paths,/w?sleep=2000&size=200"
    stop_agent
    stop_servers
    [[ "$dir" != "$WORK" ]] && cp "$dir/f_$name.bin" "$WORK/f_$name.bin"
    check "$WORK/f_$name.bin" "$WORK/f_$name.log"
}
# fs_expect NAME KEY WHAT: the waits the server logged are reported as KEY
# (fsvc or io), and none as the other.
fs_expect() {
    local name=$1 key=$2 what=$3 n other wrong
    n=$(val "${key}_n"); other=$(val "${key}_other_us")
    if [[ $key == fsvc ]]; then wrong=$(val fsvc_disk_us); else wrong=$(val io_fsvc_us); fi
    ge "$(val "${key}_ok_pct")" "$ATTR_OK_PCT_MIN" && (( n > 100 )) \
        && ok "$name: $what per request matches the server's ($(val "${key}_ok_pct")% of $n, $(isnum "$(val "${key}_us")" && echo $(( $(val "${key}_us") / n )) || echo "?")us each)" \
        || bad "$name: $what: ok $(val "${key}_ok_pct")% of $n"
    (( other <= n * 100 && wrong <= n * 100 )) \
        && ok "$name: none of it left in other (${other}us) or taken for the wrong store (${wrong}us)" \
        || bad "$name: ${other}us left in other, ${wrong}us taken for the wrong store"
    (( $(val stall_extra_us) <= 1000 )) \
        && ok "$name: no store waits on the other requests ($(val stall_extra_us)us)" \
        || bad "$name: $(val stall_extra_us)us of store waits on requests that had none"
}
# fs_lock NAME: of the file-service wait, none was for a lock: every thread
# has a file of its own. fs_lock NAME shared: most of it was, the file's lock
# held by another thread writing or flushing it (seen: 96.9%; in a Go server
# 95-97%, against kernel stacks in a lock's slow path within 1.1%). That is
# FUSE's (virtiofs): it holds the file's i_rwsem while it flushes. NFS
# flushes without it, and an fsync waits for the writeback of every page of
# the file, the other threads' too (WSL2's 6.6 with NFS 4.2: 87 of 99
# kernel stacks of 32 such threads in folio_wait_writeback, none in a lock's
# slow path); its share of lock is shown, not checked.
fs_lock() {
    local name=$1 n lock total
    n=$(val fsvc_n); lock=$(val fsvc_lock_us); total=$(val fsvc_us)
    if [[ ${2:-} == shared && "$(stat -f -c %t "$FSVC_DIR")" != 65735546 ]]; then
        note "$name: lock ${lock}us of ${total}us: not FUSE, whose flush holds the file's lock; not checked"
    elif [[ ${2:-} == shared ]]; then
        (( n > 100 && lock * 100 >= total * 90 )) \
            && ok "$name: most of it was for the file's lock ($(( lock / 1000 ))ms of $(( total / 1000 ))ms)" \
            || bad "$name: lock ${lock}us of ${total}us"
    else
        (( lock <= n * 100 )) \
            && ok "$name: none of it taken for a lock (${lock}us)" \
            || bad "$name: ${lock}us taken for a lock, of ${total}us"
    fi
}
FS_CASES=("flush:/f?fsync=4&size=200" "dsync:/f?fsync=4&how=2&size=200" "read:/r?rd=256&size=200"
          "mmap:/m?mm=256&size=200" "direct:/d?io=256&size=200" "stat:/s?st=20&size=200")
if [[ -n "$FSVC_DIR" ]]; then
    FSVC_TMP="$(mktemp -d "$FSVC_DIR/.blame-fsvc.XXXXXX")"
    chmod 755 "$FSVC_TMP"
    note "file service: $FSVC_DIR ($(stat -f -c %T "$FSVC_DIR"))"
    for c in "${FS_CASES[@]}"; do
        fs_case "fsvc-${c%%:*}" "$FSVC_TMP" "${c#*:}" \
            && { fs_expect "fsvc-${c%%:*}" fsvc "file-service wait"; fs_lock "fsvc-${c%%:*}"; }
    done
    # Writes and flushes of one file by every thread: most of the wait is for
    # the file's lock, held by a thread that waits for the service, and is
    # shown as such.
    fs_case fsvc-shared "$FSVC_TMP" "/f?fsync=4&shared=1&size=200" 32 0 \
        && { fs_expect fsvc-shared fsvc "file-service wait, on a file all threads write"
             fs_lock fsvc-shared shared; }
    rm -rf "$FSVC_TMP"
else
    note "no directory on a file service (set BLAME_FSVC_DIR); file-service cases skipped"
fi
# The same reads and faults on a local disk stay disk waits.
for c in "read:/r?rd=256&size=200" "mmap:/m?mm=256&size=200"; do
    fs_case "local-${c%%:*}" "$WORK" "${c#*:}" && fs_expect "local-${c%%:*}" io "disk wait"
done
}

# --- [13] why a goroutine is off its thread -------------------------------------
want 13 && {
echo
echo "[13] why a request's goroutine or task was on no thread (Go, tokio, --deep)"
# Each kind of wait the server logs: a channel a timer closes, a mutex a
# timer unlocks, a sleep, a call to the backend; plain requests beside them.
PK_PATHS="/n?size=200&cpu=600,/c?size=200&cpu=500&pch=1500,/m?size=200&cpu=500&pmu=1500,/s?size=200&cpu=500&sleep=1500,/d?size=200&cpu=500&d=1500"
# pk_run CASE SERVER PROCS CONNS THINK_US PATHS: the result lands in CHECK.
pk_run() {
    local name=$1 server=$2 procs=$3 conns=$4 think=$5 paths=$6
    start_server tpc "$BACKEND_PORT" "$WORK/be.bin"
    spawn ${SP_ENV:+env $SP_ENV} "$server" "$PORT" "$WORK/p_$name.bin" -b "$BACKEND_PORT" -p "$procs"
    SERVER_PID="${_TRACKED[-1]}"
    sleep 0.5
    start_agent "$WORK/p_$name.log" --pid "$SERVER_PID" --deep || return 1
    load "$conns" "$DUR" "$think" "$paths"
    stop_agent
    stop_servers
    check "$WORK/p_$name.bin" "$WORK/p_$name.log"
}
# pk_expect CASE [KINDS]: every kind of wait matches what the server logged,
# and next to nothing is put under a kind the server did not wait on.
pk_expect() {
    local name=$1 kinds=${2:-"channel sync sleep network"} kind
    for kind in $kinds; do
        ge "$(val "why_${kind}_ok_pct")" "$ATTR_OK_PCT_MIN" && le "$(abs "$(val "why_${kind}_err_pct")")" "$ATTR_ERR_PCT_MAX" \
            && (( $(val "why_${kind}_n") > 100 )) \
            && ok "$name: time parked on $kind matches the server's ($(val "why_${kind}_ok_pct")% of $(val "why_${kind}_n"), total $(val "why_${kind}_err_pct")%)" \
            || bad "$name: $kind: ok $(val "why_${kind}_ok_pct")% of $(val "why_${kind}_n"), total $(val "why_${kind}_err_pct")%"
    done
    (( $(val why_wrong_us) <= $(val kernel) * 10 )) \
        && ok "$name: next to none put under a kind the server did not wait on ($(val why_wrong_us)us over $(val kernel) requests)" \
        || bad "$name: $(val why_wrong_us)us put under a kind the server did not wait on ($(val kernel) requests)"
}
# tokio: what woke the task tells what it waited for; the server logs what
# it awaited: tasks it spawned, the blocking pool, a timer, the backend.
TK_PATHS="/n?size=200&cpu=600,/s?size=200&cpu=300&sleep=1500,/d?size=200&cpu=300&d=1500,/k?size=200&cpu=300&kids=2&kcpu=800,/bk?size=200&cpu=300&blk=2&bcpu=800"
TK_TT="$(dirname "$(dirname "$BIN")")/tokio_truth"
tk_build() { cargo build --release --quiet "$@" --manifest-path "$SCN_DIR/../tools/tokio_truth/Cargo.toml" --target-dir "$TK_TT"; }
if { tk_build --offline 2>/dev/null || tk_build; }; then
    pk_run tokio "$TK_TT/release/tokio_truth" 2 8 2000 "$TK_PATHS" && {
        grep -q "^blame: pid $SERVER_PID: .*; why tasks wait followed" "$WORK/p_tokio.log" \
            && ok "tokio: says it follows why tasks wait" \
            || bad "tokio: $(grep '^blame: pid' "$WORK/p_tokio.log")"
        pk_expect tokio "task blocking sleep network"
    }
    pk_run tokio-busy "$TK_TT/release/tokio_truth" 2 32 0 "$TK_PATHS" && pk_expect tokio-busy "task blocking sleep network"
    # The current-thread runtime puts woken tasks back through another
    # function; every task runs on one thread.
    pk_run tokio-ct "$TK_TT/release/tokio_truth" 0 8 2000 "$TK_PATHS" && {
        grep -q "^blame: pid $SERVER_PID: .*; why tasks wait followed (by what woke them, on multi-thread and current-thread runtimes)" "$WORK/p_tokio-ct.log" \
            && ok "tokio-ct: says it follows why tasks wait on current-thread runtimes too" \
            || bad "tokio-ct: $(grep '^blame: pid' "$WORK/p_tokio-ct.log")"
        pk_expect tokio-ct "task blocking sleep network"
    }
else
    bad "tokio: the test server did not build"
fi
# The same server built as release builds of big projects are (fat LTO, one
# codegen unit, as Qdrant): functions merged or inlined, drop glue spelling
# the scheduler's paths. Its spawns are still seen, and why its tasks wait.
TK_LTO="$(dirname "$(dirname "$BIN")")/tokio_truth_lto"
tk_lto_build() {
    CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
        cargo build --release --quiet "$@" --manifest-path "$SCN_DIR/../tools/tokio_truth/Cargo.toml" --target-dir "$TK_LTO"
}
if { tk_lto_build --offline 2>/dev/null || tk_lto_build; }; then
    pk_run tokio-lto "$TK_LTO/release/tokio_truth" 2 8 2000 "$TK_PATHS" && {
        grep -q "^blame: pid $SERVER_PID: .*; why tasks wait followed" "$WORK/p_tokio-lto.log" \
            && ok "tokio-lto: says it follows why tasks wait" \
            || bad "tokio-lto: $(grep '^blame: pid' "$WORK/p_tokio-lto.log")"
        pk_expect tokio-lto "task blocking sleep network"
        (( $(val spawn_n) > 100 )) && ge "$(val spawn_count_exact_pct)" 99 \
            && ok "tokio-lto: the tasks each request spawned are all found ($(val spawn_count_exact_pct)% of $(val spawn_n))" \
            || bad "tokio-lto: spawned: exact $(val spawn_count_exact_pct)% of $(val spawn_n)"
    }
else
    bad "tokio-lto: the test server did not build"
fi
PK_GO="${GO:-$(command -v go || true)}"
if [[ -n "$PK_GO" ]]; then
    (cd "$SCN_DIR/../tools/go_truth" && GOTOOLCHAIN=local "$PK_GO" build -o "$WORK/go_truth" .) || bad "go: the test server did not build"
    pk_run go "$WORK/go_truth" 2 8 2000 "$PK_PATHS" && {
        grep -q "^blame: pid $SERVER_PID: .*; why goroutines park followed" "$WORK/p_go.log" \
            && ok "go: says it follows why goroutines park" \
            || bad "go: $(grep '^blame: pid' "$WORK/p_go.log")"
        pk_expect go
    }
    pk_run go-busy "$WORK/go_truth" 2 32 0 "$PK_PATHS" && pk_expect go-busy
    # One scheduler thread and requests that compute 15 ms, past Go's 10 ms
    # time slice: they take turns, and the time off the thread is time
    # waiting to be run again.
    pk_run go-turns "$WORK/go_truth" 1 3 0 "/n?size=200&cpu=15000" && {
        read -r off runnable < <(python3 - "$WORK/p_go-turns.log" <<'PY'
import re, sys
off = run = 0
for line in open(sys.argv[1]):
    if not line.startswith("req "):
        continue
    d = {k: int(v) for k, v in re.findall(r" (\w+)=(-?\d+)", line)}
    on = sum(d[k] for k in ("cpu_ns", "runq_ns", "blocked_down_ns", "blocked_client_ns", "blocked_io_ns",
                            "blocked_mem_ns", "blocked_fsvc_ns", "blocked_other_ns"))
    off += max(0, d["end_ns"] - d["start_ns"] - on)
    run += d["parked_runnable_ns"]
print(off // 1000, run // 1000)
PY
)
        (( off > 100000 && runnable * 100 >= off * 90 )) \
            && ok "go-turns: time off the thread while others ran is waiting to run (${runnable}us of ${off}us)" \
            || bad "go-turns: off_thread ${off}us, of it waiting to run ${runnable}us"
    }
else
    note "no Go toolchain (set GO or put go on PATH); the Go cases are skipped"
fi
}

# --- [14] OpenMP teams ----------------------------------------------------------
want 14 && {
echo
echo "[14] the threads of an OpenMP team that take up a request's work (GNU libgomp, --deep)"
# Requests that open four regions of six threads, each computing 1.5 ms; ones
# that open two of three threads, 0.4 ms each; and plain ones. The server logs
# what the threads other than the handler's computed in the regions, how many
# pieces of work they took up, and how long they waited for a CPU.
OMP_PATHS="/n?size=200&cpu=300&omp=6&ocpu=1500&oreg=4&oq=1,/n?size=200&cpu=300&omp=3&ocpu=400&oreg=2&oq=1,/n?size=200&cpu=800"
# omp_run CASE CONNS HOW [agent options]: HOW is `first` (the agent before the
# load) or `late` (it attaches to a server that is busy). The result, of the
# requests that began once the agent had put its probes in, lands in CHECK.
omp_run() {
    local name=$1 conns=$2 how=$3 from
    shift 3
    spawn ${OMP_ENV:+env $OMP_ENV} "$WORK/http_truth" tpc "$PORT" "$WORK/o_$name.bin"
    SERVER_PID="${_TRACKED[-1]}"
    sleep 0.3
    if [[ $how == late ]]; then
        "$WORK/http_load" "$PORT" "$conns" $((DUR + 3)) 0 "$OMP_PATHS" >/dev/null 2>&1 &
        LOAD_JOB=$!
        sleep 1.5
        start_agent "$WORK/o_$name.log" --pid "$SERVER_PID" "$@" || return 1
        # A region's function gets its probes when a region is first seen to
        # run it, within the agent's next look at what came in (0.2 s).
        from=$(( $(boot_ns) + 700000000 ))
        wait "$LOAD_JOB"
    else
        start_agent "$WORK/o_$name.log" --pid "$SERVER_PID" "$@" || return 1
        load "$conns" 1 0 "$OMP_PATHS"
        from=$(boot_ns)
        load "$conns" "$DUR" 0 "$OMP_PATHS"
    fi
    stop_agent
    stop_servers
    check "$WORK/o_$name.bin" "$WORK/o_$name.log" --after-ns "$from"
}
# omp_followed CASE: the handler's own time as before; the team's pieces of
# work counted, their CPU the server's, their wait for a CPU within its bounds.
omp_followed() {
    local name=$1
    ge "$(val cpu_ok_pct)" "$ATTR_OK_PCT_MIN" && le "$(abs "$(val cpu_err_pct)")" "$ATTR_ERR_PCT_MAX" \
        && ok "$name: the handler's own CPU still matches ($(val cpu_ok_pct)% of $(val cpu_n), total $(val cpu_err_pct)%)" \
        || bad "$name: handler CPU: ok $(val cpu_ok_pct)% of $(val cpu_n), total $(val cpu_err_pct)%"
    ge "$(val spawn_count_exact_pct)" 99 && (( $(val spawn_n) > 100 )) \
        && ok "$name: the pieces of work the team took up are counted ($(val spawn_count_exact_pct)% of $(val spawn_n) requests exactly)" \
        || bad "$name: pieces: exact on $(val spawn_count_exact_pct)% of $(val spawn_n), fewer on $(val spawn_count_under), at most $(val spawn_count_over_max) too many"
    ge "$(val spawn_cpu_ok_pct)" "$ATTR_OK_PCT_MIN" && le "$(abs "$(val spawn_cpu_err_pct)")" "$ATTR_ERR_PCT_MAX" \
        && ok "$name: the team's CPU matches the server's ($(val spawn_cpu_ok_pct)% of $(val spawn_cpu_n), total $(val spawn_cpu_err_pct)%)" \
        || bad "$name: team CPU: ok $(val spawn_cpu_ok_pct)% of $(val spawn_cpu_n), total $(val spawn_cpu_err_pct)%"
    ge "$(val pool_wait_bounded_pct)" "$ATTR_OK_PCT_MIN" && (( $(val pool_wait_n) > 100 )) \
        && ok "$name: the team's wait for a CPU is within what the server says it can be ($(val pool_wait_bounded_pct)% of $(val pool_wait_n), $(val pool_wait_us)us each)" \
        || bad "$name: team wait for a CPU: within bounds on $(val pool_wait_bounded_pct)% of $(val pool_wait_n), $(val pool_wait_us)us each"
    (( $(val spawn_extra_us) == 0 )) && ge "$(val spawn_plain_exact_pct)" 100 \
        && ok "$name: requests that open no region have no team ($(val spawn_plain_n) of them)" \
        || bad "$name: $(val spawn_extra_us)us of team time on requests that opened no region, count right on $(val spawn_plain_exact_pct)%"
}
if [[ -z "$HAVE_OMP" ]]; then
    note "the compiler has no OpenMP (-fopenmp); the cases are skipped"
else
    # Idle threads of a team spin for a while (the default) ...
    omp_run spin 4 first --deep && omp_followed omp-spin
    # ... or sleep at once.
    OMP_ENV="OMP_WAIT_POLICY=passive" omp_run sleep 4 first --deep && omp_followed omp-sleep
    # The teams were there before the agent: whose a thread is cannot be had
    # from who made it.
    omp_run late 4 late --deep && omp_followed omp-late
    # Without the option nothing is followed, and nothing is made up.
    omp_run off 4 first && {
        ge "$(val cpu_ok_pct)" "$ATTR_OK_PCT_MIN" && le "$(abs "$(val cpu_err_pct)")" "$ATTR_ERR_PCT_MAX" \
            && (( $(val cpu_n) > 100 )) \
            && ok "omp: without --deep the handler's CPU is still its own ($(val cpu_ok_pct)%, total $(val cpu_err_pct)%)" \
            || bad "omp-off: handler CPU: ok $(val cpu_ok_pct)%, total $(val cpu_err_pct)%"
        (( $(val spawn_count_under) == $(val spawn_n) && $(val spawn_n) > 100 && $(val spawn_extra_us) == 0 )) \
            && ok "omp: without --deep no request has a team ($(val spawn_n) that opened regions)" \
            || bad "omp-off: $(minus "$(val spawn_n)" "$(val spawn_count_under)") of $(val spawn_n) requests have team time without --deep"
    }
fi
}

# --- [15] TLS ---------------------------------------------------------------------
want 15 && {
echo
echo "[15] requests over TLS, read from OpenSSL's calls (--tls)"
# A Python HTTPS server whose handler only sleeps 20 ms, already busy when the
# agent attaches. Each sleep must be seen as one from the first requests on:
# a TLS probe that starts requests before the scheduler hook is on takes
# their whole time for time on a CPU.
if ! command -v openssl >/dev/null; then
    note "no openssl to make a certificate; skipped"
elif ! openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/tls.key" -out "$WORK/tls.crt" \
        -days 1 -subj /CN=localhost >/dev/null 2>&1; then
    bad "tls: could not make a certificate"
else
    spawn python3 "$WORKLOADS/tls_http.py" server "$PORT" "$WORK/tls.crt" "$WORK/tls.key"
    tls_server=${_TRACKED[-1]}
    sleep 0.5
    spawn python3 "$WORKLOADS/tls_http.py" load "$PORT" "$((DUR + 4))" 8
    sleep 2
    sudo -n "$BIN" slow --json --tls --above 0 --list 0 --interval 0 --pid "$tls_server" \
        >"$WORK/tls.json" 2>"$WORK/tls.err" &
    AGENT_JOB=$!
    for _ in $(seq 100); do
        grep -q '"type":"process"' "$WORK/tls.json" 2>/dev/null && break
        sleep 0.1
    done
    sleep "$DUR"
    stop_agent
    stop_servers
    run_checker TLS "$WORKLOADS/tls_check.py" "$WORK/tls.json"
    tv() { echo "$TLS " | grep -oP "(?<=\b$1=)[0-9]+"; }
    note "$TLS"
    grep -q '"note":"TLS read from OpenSSL' "$WORK/tls.json" \
        && ok "tls: the process's libssl is followed" \
        || bad "tls: no TLS note for the server: $(grep '"type":"process"' "$WORK/tls.json" | head -1)"
    (( $(tv calls) > 100 && $(tv tls) == $(tv calls) )) \
        && ok "tls: requests read and flagged as over TLS ($(tv calls))" \
        || bad "tls: $(tv calls) requests, $(tv tls) flagged as over TLS"
    (( $(tv early) > 20 && $(tv asleep_short) == 0 )) \
        && ok "tls: every handler's sleep seen as such, from the first second on ($(tv early) in it)" \
        || bad "tls: $(tv asleep_short) requests with their sleep not seen, $(tv early) in the first second"
    (( $(tv lost) == 0 )) \
        && ok "tls: nothing lost" \
        || bad "tls: lost: $(grep -o '"lost":{[^}]*}' "$WORK/tls.json" | tail -1)"

    # Without --tls nothing over TLS is read, and that is not silent: each
    # connection that began with a handshake is counted as unread. (Python's
    # OpenSSL sets the socket up for kernel TLS here, puts no keys in: not
    # taken up by the kernel, still unread.)
    spawn python3 "$WORKLOADS/tls_http.py" server "$PORT" "$WORK/tls.crt" "$WORK/tls.key"
    tls_server=${_TRACKED[-1]}
    sleep 0.5
    sudo -n "$BIN" slow --json --above 0 --list 0 --interval 0 --pid "$tls_server" \
        >"$WORK/tls-off.json" 2>"$WORK/tls-off.err" &
    AGENT_JOB=$!
    for _ in $(seq 100); do
        grep -q '"type":"process"' "$WORK/tls-off.json" 2>/dev/null && break
        sleep 0.1
    done
    opened=$(python3 "$WORKLOADS/tls_http.py" load "$PORT" 2 4 | grep -oP '(?<=connections=)[0-9]+')
    sleep 0.5
    stop_agent
    stop_servers
    unread=$(grep '"scope":"total"' "$WORK/tls-off.json" | grep -oP '(?<="tls_unread":)[0-9]+' | tail -1)
    calls=$(grep -c '"type":"call"' "$WORK/tls-off.json")
    isnum "$opened" && (( opened > 4 && ${unread:-0} == opened && calls == 0 )) \
        && ok "tls: without --tls, every connection over TLS is counted as unread ($unread of $opened), no request made up" \
        || bad "tls: without --tls: tls_unread=${unread:-none} of ${opened:-?} connections, $calls requests"

    # Kernel TLS: from the handshake on, the socket calls carry plaintext,
    # each direction once its keys are in, and the handshake's Finished and
    # session ticket pass through them as records of their own. Every request
    # must be read from them, the first of each connection too, without --tls.
    tls_rx() { grep -oP '(?<=^TlsRxSw)\s+[0-9]+' /proc/net/tls_stat 2>/dev/null | tr -d ' \t'; }
    if [[ ! -r /proc/net/tls_stat ]] && ! sudo -n modprobe tls 2>/dev/null; then
        note "tls: no kernel TLS (tls module); kernel TLS case skipped"
    else
        KTLS=1 spawn python3 "$WORKLOADS/tls_http.py" server "$PORT" "$WORK/tls.crt" "$WORK/tls.key"
        tls_server=${_TRACKED[-1]}
        sleep 0.5
        sudo -n "$BIN" slow --json --above 0 --list 0 --interval 0 --pid "$tls_server" \
            >"$WORK/ktls.json" 2>"$WORK/ktls.err" &
        AGENT_JOB=$!
        for _ in $(seq 100); do
            grep -q '"type":"process"' "$WORK/ktls.json" 2>/dev/null && break
            sleep 0.1
        done
        rx0=$(tls_rx)
        out=$(python3 "$WORKLOADS/tls_http.py" load "$PORT" 2 4)
        rx1=$(tls_rx)
        sleep 0.5
        stop_agent
        stop_servers
        opened=$(echo "$out" | grep -oP '(?<=connections=)[0-9]+')
        answered=$(echo "$out" | grep -oP '(?<=requests=)[0-9]+')
        calls=$(grep -c '"type":"call"' "$WORK/ktls.json")
        lost=$(grep '"scope":"total"' "$WORK/ktls.json" | grep -o '"lost":{[^}]*}' | tail -1)
        if ! isnum "$rx0" || ! isnum "$rx1" || (( rx1 - rx0 < opened )); then
            note "tls: the kernel took up ${rx1:-?}-${rx0:-?} of ${opened:-?} connections; kernel TLS case skipped"
        else
            isnum "$answered" && (( opened > 4 && calls == answered )) && [[ $lost == '"lost":{}' ]] \
                && ok "tls: over kernel TLS every request is read from the socket calls ($calls of $answered, $opened connections), nothing lost" \
                || bad "tls: over kernel TLS $calls of ${answered:-?} requests seen (${opened:-?} connections), $lost"
        fi
    fi
fi
}

echo
echo "result: $PASS passed, $FAIL failed"
(( FAIL == 0 ))
