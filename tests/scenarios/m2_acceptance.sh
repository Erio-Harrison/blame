#!/usr/bin/env bash
#
# Identity attribution acceptance: run-queue waits land on the right service,
# container or pod, and the books balance.
#
# Needs root or passwordless sudo, systemd, taskset, python3.
#     ./tests/scenarios/m2_acceptance.sh [blame-binary]
# Env: BLAME_BIN, SCN_DURATION (seconds per window, default 8),
#      ENVS (space separated: systemd docker k8s; default systemd)
#      docker needs the docker engine, k8s needs k3s; each is started for the
#      run and stopped afterwards.

set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -n "${1:-}" ]] && BLAME_BIN="$1"
resolve_bin || exit 1
need_root || exit 1

DUR="${SCN_DURATION:-8}"
ENVS="${ENVS:-systemd}"
WORK="$(mktemp -d)"
CLEANUP=()
cleanup() {
    reap_tracked
    stop_units
    local c
    for c in "${CLEANUP[@]:-}"; do [[ -n "$c" ]] && eval "$c" >/dev/null 2>&1; done
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- thresholds ---------------------------------------------------------------
# Two hogs sharing a core wait out a time slice (milliseconds) every time; a
# thread that sleeps on an otherwise idle core waits microseconds.
HOG_SLOW_PCT_MIN=80
SLEEPER_SLOW_PCT_MAX=5
SLEEPER_SAMPLES_MIN=1000
# Unattributed samples allowed beside a seeded or restarted service. An idle
# machine and this scenario showed 0 in repeated runs once seeding happens before
# attaching (1-13 when it came after); without
# seeding at all it is >100.
UNATTRIBUTED_MAX=10
# A neighbour must at least multiply the victim's slow waits by this.
NEIGHBOR_FACTOR_MIN=5
# Threads in the "already running" scenario, and how many must be attributed.
PRE_THREADS=16
PRE_ATTRIBUTED_MIN=14

pct() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%d", (b > 0 ? a * 100 / b : 0) }'; }

echo "blame identity acceptance ($BIN)"
echo "  window=${DUR}s cpus=${NCPU} envs=${ENVS}"

# Samples, slow waits and slow percentage of LABEL in LOG's final table.
cells() {
    local samples slow
    samples=$(top_cell "$1" "$2" final 2)
    slow=$(top_cell "$1" "$2" final 7)
    echo "$samples $slow $(pct "$slow" "$samples")"
}

conserved() { grep -q '^  groups .* ok$' "$1"; }

# Two busy loops for SECS seconds, sharing one core so that they wait.
SPIN='end=$(( $(date +%s) + SECS )); spin() { while [ $(date +%s) -lt $end ]; do :; done; }; spin & spin; wait'
spin() { echo "${SPIN//SECS/$1}"; }

# Start `top` reporting only on exit, run "$@" while it runs, wait for it.
# The agent starts first, so whatever "$@" creates is new to it.
top_around() {
    local log=$1 secs=$2
    shift 2
    sudo -n "$BIN" top --duration "$secs" --interval 0 --rows 500 >"$log" 2>&1 &
    local agent=$!
    sleep 2
    "$@"
    wait "$agent"
}

# --- systemd -------------------------------------------------------------------
scenarios_systemd() {
    echo
    echo "[1] hogs and a sleeper are told apart"
    unit_hogs nw-hog.service 2 4 || bad "could not start hog unit"
    unit_sleeper nw-sleep.service 5 || bad "could not start sleeper unit"
    sleep 1
    run_top "$DUR" "$WORK/s1.log" || bad "agent failed: $(cat "$WORK/s1.log")"
    stop_units

    read -r hs hslow hpct <<<"$(cells "$WORK/s1.log" nw-hog.service)"
    read -r ss sslow spct <<<"$(cells "$WORK/s1.log" nw-sleep.service)"
    note "nw-hog.service    samples=$hs slow=$hslow (${hpct}%)"
    note "nw-sleep.service  samples=$ss slow=$sslow (${spct}%)"
    (( hs > 0 && hpct >= HOG_SLOW_PCT_MIN )) \
        && ok "hogs sharing a core show time-slice waits (>= ${HOG_SLOW_PCT_MIN}% slow)" \
        || bad "hog unit: ${hpct}% slow of $hs samples"
    (( ss >= SLEEPER_SAMPLES_MIN && spct <= SLEEPER_SLOW_PCT_MAX )) \
        && ok "the sleeper has many short waits (<= ${SLEEPER_SLOW_PCT_MAX}% slow) and is not mixed with the hogs" \
        || bad "sleeper unit: $ss samples, ${spct}% slow"
    conserved "$WORK/s1.log" \
        && ok "per-service samples add up to the global count" \
        || bad "samples do not add up: $(grep '^  groups' "$WORK/s1.log")"

    echo
    echo "[2] a noisy neighbour shows up on the victim and is itself visible"
    # The victim computes 1 ms per request, about half a CPU per server: a
    # service that only sleeps and answers is hardly touched by a neighbour
    # (woken, it runs at once; its waits even get shorter, the CPUs never idle).
    local web="python3 $SCN_DIR/workloads/service_load.py --servers 4 --clients 2 --server-cpus 0-3 --client-cpus 4-5 --rate 2000 --work-ms 1 --warmup 1 --duration $((DUR + 4))"
    unit_start nw-web.service $web || bad "could not start web unit"
    sleep 2
    run_top "$DUR" "$WORK/s2a.log" || bad "agent failed: $(cat "$WORK/s2a.log")"
    stop_units
    sleep 1
    unit_start nw-web.service $web || bad "could not start web unit"
    unit_hogs nw-batch.service $((NCPU * 2)) "0-3" || bad "could not start batch unit"
    sleep 2
    run_top "$DUR" "$WORK/s2b.log" || bad "agent failed: $(cat "$WORK/s2b.log")"
    stop_units

    local alone with batch_rows
    alone=$(top_cell "$WORK/s2a.log" nw-web.service final 7)
    with=$(top_cell "$WORK/s2b.log" nw-web.service final 7)
    batch_rows=$(top_cell "$WORK/s2b.log" nw-batch.service final 2)
    note "nw-web.service slow waits: alone=$alone with-neighbour=$with; nw-batch.service samples=$batch_rows"
    (( with >= NEIGHBOR_FACTOR_MIN * (alone > 10 ? alone : 10) )) \
        && ok "the victim's slow waits grow at least ${NEIGHBOR_FACTOR_MIN}x with the neighbour" \
        || bad "victim slow waits did not grow enough ($alone -> $with)"
    (( batch_rows > 0 )) \
        && ok "the neighbour has its own row" \
        || bad "no row for the neighbour"

    echo
    echo "[3] a restarted service keeps being attributed"
    local unitfile=/run/systemd/system/nw-restart.service
    sudo -n tee "$unitfile" >/dev/null <<UNIT
[Service]
ExecStart=/usr/bin/taskset -c 5 /usr/bin/python3 $SCN_DIR/workloads/sleeper.py
UNIT
    CLEANUP+=("sudo -n systemctl stop nw-restart.service; sudo -n rm -f $unitfile; sudo -n systemctl daemon-reload")
    sudo -n systemctl daemon-reload
    sudo -n systemctl start nw-restart.service || bad "could not start nw-restart.service"
    local old new
    old=$(sudo -n systemctl show -p MainPID --value nw-restart.service)
    sudo -n "$BIN" top --duration 12 --interval 4 --rows 500 >"$WORK/s3.log" 2>&1 &
    local agent=$!
    sleep 6
    sudo -n systemctl restart nw-restart.service
    new=$(sudo -n systemctl show -p MainPID --value nw-restart.service)
    wait "$agent"
    sudo -n systemctl stop nw-restart.service

    local after unatt total
    after=$(top_cell "$WORK/s3.log" nw-restart.service lastwindow 2)
    unatt=$(top_cell "$WORK/s3.log" "(unattributed)" lastwindow 2)
    total=$(top_total "$WORK/s3.log" lastwindow)
    note "main pid $old -> $new; last window: nw-restart.service=$after unattributed=$unatt of $total"
    [[ "$old" != "$new" ]] && ok "the service really restarted" || bad "pid did not change"
    (( after >= 500 )) \
        && ok "the new process is attributed to the same service" \
        || bad "only $after samples after the restart"
    (( unatt <= UNATTRIBUTED_MAX )) \
        && ok "nothing leaks into unattributed after the restart" \
        || bad "$unatt unattributed samples after the restart"

    echo
    echo "[4] a service that was already running when the agent started"
    unit_sleeper nw-pre.service 5 --threads "$PRE_THREADS" --first-sleep 4 --period-ms 60000 \
        || bad "could not start nw-pre.service"
    run_top 7 "$WORK/s4.log" || bad "agent failed: $(cat "$WORK/s4.log")"
    stop_units
    local pre unatt4
    pre=$(top_cell "$WORK/s4.log" nw-pre.service final 2)
    unatt4=$(top_cell "$WORK/s4.log" "(unattributed)" final 2)
    note "nw-pre.service samples=$pre of $PRE_THREADS threads; unattributed=$unatt4"
    (( pre >= PRE_ATTRIBUTED_MIN )) \
        && ok "threads asleep before the agent started are attributed on first wake" \
        || bad "only $pre of $PRE_THREADS first wake-ups attributed"
    (( unatt4 <= UNATTRIBUTED_MAX )) \
        && ok "unattributed stays small (<= $UNATTRIBUTED_MAX)" \
        || bad "$unatt4 unattributed samples"

    echo
    echo "[5] a fork storm does not grow the state"
    unit_start nw-storm.service sh -c 'for i in $(seq 4000); do sleep 0.001 & if (( i % 50 == 0 )); then wait; fi; done; wait' \
        || bad "could not start storm unit"
    run_top "$DUR" "$WORK/s5.log" || bad "agent failed: $(cat "$WORK/s5.log")"
    stop_units
    local rows failed
    rows=$(top_row_count "$WORK/s5.log" final)
    failed=$(kernel_counter "$WORK/s5.log" runq_group_insert_failed)
    note "rows=$rows runq_group_insert_failed=${failed:-?}"
    (( rows <= 60 )) \
        && ok "short-lived processes do not add rows ($rows)" \
        || bad "$rows rows after the storm"
    [[ "${failed:-1}" == 0 ]] \
        && ok "no samples lost to a full table" \
        || bad "table-full counter: ${failed:-?}"
    conserved "$WORK/s5.log" \
        && ok "per-service samples add up to the global count" \
        || bad "samples do not add up: $(grep '^  groups' "$WORK/s5.log")"

    echo
    echo "[6] a full table is reported, not hidden"
    unit_sleeper nw-a.service 5 || bad "could not start nw-a"
    unit_sleeper nw-b.service 5 || bad "could not start nw-b"
    unit_sleeper nw-c.service 5 || bad "could not start nw-c"
    run_top 5 "$WORK/s6.log" --group-entries 2 || bad "agent failed: $(cat "$WORK/s6.log")"
    stop_units
    failed=$(kernel_counter "$WORK/s6.log" runq_group_insert_failed)
    note "runq_group_insert_failed=${failed:-?} with a 2-entry table"
    (( ${failed:-0} > 0 )) \
        && ok "overflow of the per-service table is counted" \
        || bad "no loss counted with a 2-entry table"

    echo
    echo "[7] a cgroup removed before the report is still named"
    top_around "$WORK/s7.log" 6 \
        sudo -n systemd-run --scope -q --unit nw-brief taskset -c 5 sh -c "$(spin 1)"
    local brief gone=1
    systemctl is-active --quiet nw-brief.scope && gone=0
    brief=$(top_cell "$WORK/s7.log" nw-brief.scope final 2)
    note "nw-brief.scope samples=$brief; removed before the report: $gone; $(grep '^  names' "$WORK/s7.log")"
    (( gone )) || bad "the scope still existed when the report was printed"
    (( brief > 0 )) \
        && ok "a scope that lived one second is named, not shown as cgroup:<id>" \
        || bad "no row for nw-brief.scope: $(grep -o 'cgroup:[0-9]*' "$WORK/s7.log" | tr '\n' ' ')"
}

# --- docker --------------------------------------------------------------------
scenarios_docker() {
    echo
    echo "[8] docker containers are told apart and named"
    if ! command -v docker >/dev/null; then
        note "docker is not installed; skipped"
        return
    fi
    local was_active=0
    systemctl is-active --quiet docker && was_active=1
    sudo -n systemctl start docker || { bad "could not start docker"; return; }
    (( was_active )) || CLEANUP+=("sudo -n systemctl stop docker.socket docker containerd")
    CLEANUP+=("sudo -n docker rm -f nw-dhog nw-dsleep")
    local img=busybox
    sudo -n docker image inspect "$img" >/dev/null 2>&1 || sudo -n docker pull -q "$img" >/dev/null
    sudo -n docker run -d --name nw-dhog --cpuset-cpus 4 "$img" \
        sh -c 'while :; do :; done & while :; do :; done' >/dev/null || bad "could not start nw-dhog"
    sudo -n docker run -d --name nw-dsleep --cpuset-cpus 5 "$img" \
        sh -c 'while :; do sleep 0.001; done' >/dev/null || bad "could not start nw-dsleep"
    sleep 2
    run_top "$DUR" "$WORK/d.log" || bad "agent failed: $(cat "$WORK/d.log")"
    sudo -n docker rm -f nw-dhog nw-dsleep >/dev/null 2>&1

    read -r hs hslow hpct <<<"$(cells "$WORK/d.log" docker:nw-dhog)"
    read -r ss sslow spct <<<"$(cells "$WORK/d.log" docker:nw-dsleep)"
    note "docker:nw-dhog    samples=$hs slow=$hslow (${hpct}%)"
    note "docker:nw-dsleep  samples=$ss slow=$sslow (${spct}%)"
    (( hs > 0 && hpct >= HOG_SLOW_PCT_MIN )) \
        && ok "the hog container is shown by name with time-slice waits" \
        || bad "docker:nw-dhog missing or not slow ($hs samples, ${hpct}%)"
    (( ss > 0 && spct <= SLEEPER_SLOW_PCT_MAX )) \
        && ok "the sleeping container is shown by name with short waits" \
        || bad "docker:nw-dsleep missing or slow ($ss samples, ${spct}%)"

    echo
    echo "[9] a container removed before the report keeps its name"
    CLEANUP+=("sudo -n docker rm -f nw-dbrief")
    top_around "$WORK/d2.log" 10 \
        timeout 30 sudo -n docker run --rm --name nw-dbrief --cpuset-cpus 5 "$img" sh -c "$(spin 2)"
    local brief left
    left=$(sudo -n docker ps -aq --filter name=nw-dbrief | wc -l)
    brief=$(top_cell "$WORK/d2.log" docker:nw-dbrief final 2)
    note "docker:nw-dbrief samples=$brief; containers left: $left"
    (( left == 0 )) || bad "the container still existed when the report was printed"
    (( brief > 0 )) \
        && ok "a container that lived two seconds is shown by name" \
        || bad "no row for docker:nw-dbrief: $(grep -o 'docker:[0-9a-f]\{12\}' "$WORK/d2.log" | tr '\n' ' ')"
}

# --- kubernetes (k3s) ----------------------------------------------------------
scenarios_k8s() {
    echo
    echo "[10] kubernetes pods are identified by uid and container"
    if ! command -v k3s >/dev/null; then
        note "k3s is not installed; skipped"
        return
    fi
    local K="sudo -n k3s kubectl" was_active=0 i
    systemctl is-active --quiet k3s && was_active=1
    sudo -n systemctl start k3s || { bad "could not start k3s"; return; }
    (( was_active )) || CLEANUP+=("sudo -n k3s-killall.sh")
    CLEANUP+=("$K delete pod nw-khog nw-ksleep --now --ignore-not-found")
    for i in $(seq 60); do $K get sa default >/dev/null 2>&1 && break; sleep 2; done
    $K run nw-khog --image=busybox:1.36 --restart=Never -- sh -c 'while :; do :; done' >/dev/null
    $K run nw-ksleep --image=busybox:1.36 --restart=Never -- sh -c 'while :; do sleep 0.001; done' >/dev/null
    for i in $(seq 120); do
        [[ "$($K get pod nw-khog -o jsonpath='{.status.phase}' 2>/dev/null)" == Running &&
           "$($K get pod nw-ksleep -o jsonpath='{.status.phase}' 2>/dev/null)" == Running ]] && break
        sleep 2
    done
    local label=() p uid cid
    for p in nw-khog nw-ksleep; do
        uid=$($K get pod "$p" -o jsonpath='{.metadata.uid}')
        cid=$($K get pod "$p" -o jsonpath='{.status.containerStatuses[0].containerID}')
        cid=${cid#containerd://}
        label+=("pod:${uid:0:8}/${cid:0:12}")
    done
    note "expected labels: ${label[0]} (hog), ${label[1]} (sleeper)"
    run_top "$DUR" "$WORK/k.log" || bad "agent failed: $(cat "$WORK/k.log")"
    $K delete pod nw-khog nw-ksleep --now >/dev/null 2>&1

    local hs ss
    hs=$(top_cell "$WORK/k.log" "${label[0]}" final 2)
    ss=$(top_cell "$WORK/k.log" "${label[1]}" final 2)
    note "hog pod samples=$hs; sleeper pod samples=$ss"
    (( hs > 0 )) && ok "the hog pod appears under its uid and container id" || bad "no row for ${label[0]}"
    (( ss > 0 )) && ok "the sleeper pod appears under its uid and container id" || bad "no row for ${label[1]}"
}

for env in $ENVS; do
    case "$env" in
        systemd) scenarios_systemd ;;
        docker)  scenarios_docker ;;
        k8s)     scenarios_k8s ;;
        *) echo "unknown environment: $env" >&2; exit 2 ;;
    esac
done

echo
echo "result: $PASS passed, $FAIL failed"
(( FAIL == 0 ))
