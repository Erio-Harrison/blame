#!/usr/bin/env bash
#
# Where does the client p99 of the shop come from when there is no neighbour?
# Runs the shop at several request rates in a random order and records, per
# phase: the client's latency breakdown (see loadgen.py), CPU use of every
# container and of the load generator, busy share of the shop's CPUs, and the
# run-queue tail of each service and of the load generator from `blame top`.
# A study, not a pass/fail test.
#
#     tests/demos/shop/noise_floor.sh [blame-binary]
# Env: RATES (default "100 200 300"), PAY_PROCS (processes serving payments,
#      default "1"; e.g. "1 4" to compare), REPS (5), PHASE_SECS (20), SEED,
#      CPUS_SHOP (0-1), CPUS_LOAD (4-5), OUT (result dir), KEEP_IMAGES=1,
#      STALLS=0 turns off the stall probe (tests/tools/stalls.c), which
#      otherwise runs on STALL_CPU (default 3) during each phase; its output
#      and every request's latency are kept per phase

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../../scenarios/lib.sh"

[[ -n "${1:-}" ]] && BLAME_BIN="$1"
resolve_bin || exit 1
need_root || exit 1

RATES="${RATES:-100 200 300}"
PAY_PROCS="${PAY_PROCS:-1}"
REPS="${REPS:-5}"
PHASE_SECS="${PHASE_SECS:-20}"
CPUS_SHOP="${CPUS_SHOP:-0-1}"
CPUS_LOAD="${CPUS_LOAD:-4-5}"
SEED="${SEED:-$RANDOM}"
OUT="${OUT:-$(mktemp -d)}"
mkdir -p "$OUT"
STALL_CPU="${STALL_CPU:-3}"
STALL_PROBE=
if [[ "${STALLS:-1}" != 0 ]]; then
    STALL_PROBE=$(build_stall_probe "$OUT") || { echo "could not build the stall probe" >&2; exit 1; }
fi
D="sudo -n docker"
NET=nw-shop
NAMES=(nw-shop-db nw-shop-payments nw-shop-orders)

docker_was_active=0
systemctl is-active --quiet docker && docker_was_active=1

cleanup() {
    sudo -n systemctl stop nw-loadgen.scope >/dev/null 2>&1
    $D rm -f "${NAMES[@]}" >/dev/null 2>&1
    $D network rm $NET >/dev/null 2>&1
    [[ -n "${KEEP_IMAGES:-}" ]] || $D rmi nw-shop >/dev/null 2>&1
    (( docker_was_active )) || sudo -n systemctl stop docker.socket docker containerd >/dev/null 2>&1
}
trap cleanup EXIT

echo "seed=$SEED rates=[$RATES] reps=$REPS phase=${PHASE_SECS}s shop=$CPUS_SHOP load=$CPUS_LOAD out=$OUT"

sudo -n systemctl start docker || { echo "cannot start docker" >&2; exit 1; }
$D build -q -t nw-shop "$HERE" >/dev/null || { echo "image build failed" >&2; exit 1; }
$D network create $NET >/dev/null
$D run -d --name nw-shop-db --network $NET --cpuset-cpus "$CPUS_SHOP" -e POSTGRES_PASSWORD=x \
    postgres:16-alpine -c synchronous_commit=off >/dev/null || exit 1
start_payments() {
    $D rm -f nw-shop-payments >/dev/null 2>&1
    $D run -d --name nw-shop-payments --network $NET --cpuset-cpus "$CPUS_SHOP" \
        nw-shop payments --port 8081 --procs "$1" >/dev/null || exit 1
}
PROCS_NOW=${PAY_PROCS%% *}
start_payments "$PROCS_NOW"
$D run -d --name nw-shop-orders --network $NET --cpuset-cpus "$CPUS_SHOP" -e DB_HOST=nw-shop-db -e PAYMENTS_HOST=nw-shop-payments \
    nw-shop orders --port 8080 >/dev/null || exit 1

ORDERS_IP=$($D inspect -f '{{(index .NetworkSettings.Networks "'$NET'").IPAddress}}' nw-shop-orders)
for _ in $(seq 60); do
    curl -s -m 2 -X POST -d '{}' "http://$ORDERS_IP:8080/order" | grep -q '"ok"' && break
    sleep 1
done
curl -s -m 2 -X POST -d '{}' "http://$ORDERS_IP:8080/order" | grep -q '"ok"' \
    || { echo "the shop never answered an order" >&2; exit 1; }

# The load generator gets its own scope so `top` reports it as a row. Its id
# is noted while the scope exists, see loadgen_row.
LOADGEN_ID=0
load() {
    sudo -n systemd-run --scope -q --unit nw-loadgen \
        taskset -c "$CPUS_LOAD" python3 "$HERE/loadgen.py" --host "$ORDERS_IP" --rate "$1" --duration "$2" --workers 48 ${3:+--dump "$3"} &
    local pid=$! dir=/sys/fs/cgroup/system.slice/nw-loadgen.scope
    for _ in $(seq 50); do [[ -d $dir ]] && break; sleep 0.1; done
    LOADGEN_ID=$(stat -c %i "$dir" 2>/dev/null || echo 0)
    wait "$pid"
}

cg_usage() {   # container -> usage_usec
    local id
    id=$($D inspect -f '{{.Id}}' "$1")
    awk '$1 == "usage_usec" { print $2 }' "/sys/fs/cgroup/system.slice/docker-$id.scope/cpu.stat"
}
cpu_busy() {   # "busy total" jiffies summed over CPUS_SHOP
    local list
    list=$(python3 -c "
import sys
out = []
for part in sys.argv[1].split(','):
    a, _, b = part.partition('-')
    out += range(int(a), int(b or a) + 1)
print(' '.join(f'cpu{c}' for c in out))" "$CPUS_SHOP")
    awk -v want=" $list " 'index(want, " " $1 " ") {
        t = 0; for (i = 2; i <= NF; i++) t += $i
        busy += t - $5 - $6; total += t
    } END { print busy, total }' /proc/stat
}

load 200 8 >/dev/null   # warm-up

FIELDS=(rps errors p50_ms p99_ms p999_ms loadgen_cpu_pct late_p99_ms tail_n tail_total_ms tail_late_ms tail_wire_ms tail_pay_ms tail_db_ms tail_rest_ms)
{
    printf 'rep,pos,rate,pay_procs,%s' "$(IFS=,; echo "${FIELDS[*]}")"
    echo ",cpu_orders_pct,cpu_payments_pct,cpu_db_pct,shop_cpus_busy_pct,top_orders,top_payments,top_db,top_loadgen"
} >"$OUT/phases.csv"
# The scope is named in the final table if a window report saw it, otherwise
# it only shows as cgroup:<id>.
loadgen_row() {
    local r
    r=$(row "$1" nw-loadgen.scope)
    [[ $r == 0/0/0 ]] && r=$(row "$1" "cgroup:$LOADGEN_ID")
    echo "$r"
}
row() { echo "$(top_cell "$1" "$2" final 2)/$(top_cell "$1" "$2" final 4)/$(top_cell "$1" "$2" final 6)"; }
shuffle() { local r=$1; shift; printf '%s\n' "$@" | shuf --random-source=<(yes "$SEED-$r"); }

for rep in $(seq "$REPS"); do
    pos=0
    # shellcheck disable=SC2086
    while read -r cond; do
        pos=$((pos + 1))
        rate=${cond%:*} procs=${cond#*:}
        if [[ $procs != "$PROCS_NOW" ]]; then
            start_payments "$procs"
            PROCS_NOW=$procs
            sleep 2
            load 100 3 >/dev/null   # orders reconnects; errors here are expected
        fi
        f="$OUT/r${rep}_${pos}_${rate}_p$procs"
        run_top "$PHASE_SECS" "$f.top" &
        agent=$!
        sleep 1
        secs=$((PHASE_SECS - 2))
        declare -A before
        for c in "${NAMES[@]}"; do before[$c]=$(cg_usage "$c"); done
        read -r b0 t0 < <(cpu_busy)
        probe=
        if [[ -n ${STALL_PROBE:-} ]]; then
            taskset -c "$STALL_CPU" "$STALL_PROBE" "$((secs + 1))" "cpu$STALL_CPU" >"$f.stalls" &
            probe=$!
        fi
        load "$rate" "$secs" ${STALL_PROBE:+"$f.requests"} >"$f.client"
        [[ -n $probe ]] && wait "$probe"
        read -r b1 t1 < <(cpu_busy)
        cpu=()
        for c in nw-shop-orders nw-shop-payments nw-shop-db; do
            cpu+=("$(awk -v a="${before[$c]}" -v b="$(cg_usage "$c")" -v s="$secs" 'BEGIN { printf "%.1f", (b - a) / s / 1e4 }')")
        done
        busy=$(awk -v b="$((b1 - b0))" -v t="$((t1 - t0))" 'BEGIN { printf "%.1f", t ? b / t * 100 : 0 }')
        wait "$agent"
        vals=$(python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
print(','.join(str(d[k]) for k in sys.argv[2:]))" "$f.client" "${FIELDS[@]}")
        echo "$rep,$pos,$rate,$procs,$vals,${cpu[0]},${cpu[1]},${cpu[2]},$busy,$(row "$f.top" docker:nw-shop-orders),$(row "$f.top" docker:nw-shop-payments),$(row "$f.top" docker:nw-shop-db),$(loadgen_row "$f.top")" \
            >>"$OUT/phases.csv"
        echo "rep $rep/$REPS pos $pos rate $rate procs $procs done"
    done < <(shuffle "$rep" $(for r in $RATES; do for p in $PAY_PROCS; do echo "$r:$p"; done; done))
done

echo "done: $OUT/phases.csv"
