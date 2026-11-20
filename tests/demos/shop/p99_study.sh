#!/usr/bin/env bash
#
# Repeated version of the shop demo: does the run-queue tail of a service line
# up with the p99 a client sees? Conditions are run in a random order inside
# every round, results go to $OUT/phases.csv, and p99_study.py analyses them.
# A study, not a pass/fail test.
#
#     tests/demos/shop/p99_study.sh [blame-binary]
# Env: ROUNDS (default 10), PHASE_SECS (20), RATE (300), CPUS_SHOP (0-1),
#      CPUS_LOAD (4-5), SEED (default: random, printed), OUT (result dir),
#      KEEP_IMAGES=1, STALLS=0 turns off the stall probe (tests/tools/stalls.c),
#      which otherwise runs on STALL_CPU (default 3) during each phase so that
#      requests caught in a machine-wide stall can be told apart

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../../scenarios/lib.sh"

[[ -n "${1:-}" ]] && BLAME_BIN="$1"
resolve_bin || exit 1
need_root || exit 1

ROUNDS="${ROUNDS:-10}"
PHASE_SECS="${PHASE_SECS:-20}"
RATE="${RATE:-300}"
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
NAMES=(nw-shop-db nw-shop-payments nw-shop-orders nw-shop-batch)
# name:busy-loops:cpu-shares (0 = default)
CONDITIONS=(none:0:0 hog1:1:0 hog2:2:0 hog4:4:0 hog4low:4:2)

docker_was_active=0
systemctl is-active --quiet docker && docker_was_active=1

cleanup() {
    reap_tracked
    $D rm -f "${NAMES[@]}" >/dev/null 2>&1
    $D network rm $NET >/dev/null 2>&1
    [[ -n "${KEEP_IMAGES:-}" ]] || $D rmi nw-shop >/dev/null 2>&1
    (( docker_was_active )) || sudo -n systemctl stop docker.socket docker containerd >/dev/null 2>&1
}
trap cleanup EXIT

echo "seed=$SEED rounds=$ROUNDS phase=${PHASE_SECS}s rate=$RATE shop=$CPUS_SHOP load=$CPUS_LOAD out=$OUT"

sudo -n systemctl start docker || { echo "cannot start docker" >&2; exit 1; }
$D build -q -t nw-shop "$HERE" >/dev/null || { echo "image build failed" >&2; exit 1; }
$D network create $NET >/dev/null

$D run -d --name nw-shop-db --network $NET --cpuset-cpus "$CPUS_SHOP" -e POSTGRES_PASSWORD=x \
    postgres:16-alpine -c synchronous_commit=off >/dev/null || exit 1
$D run -d --name nw-shop-payments --network $NET --cpuset-cpus "$CPUS_SHOP" \
    nw-shop payments --port 8081 >/dev/null || exit 1
$D run -d --name nw-shop-orders --network $NET --cpuset-cpus "$CPUS_SHOP" -e DB_HOST=nw-shop-db -e PAYMENTS_HOST=nw-shop-payments \
    nw-shop orders --port 8080 >/dev/null || exit 1

ORDERS_IP=$($D inspect -f '{{(index .NetworkSettings.Networks "'$NET'").IPAddress}}' nw-shop-orders)
for _ in $(seq 60); do
    curl -s -m 2 -X POST -d '{}' "http://$ORDERS_IP:8080/order" | grep -q '"ok"' && break
    sleep 1
done
curl -s -m 2 -X POST -d '{}' "http://$ORDERS_IP:8080/order" | grep -q '"ok"' \
    || { echo "the shop never answered an order" >&2; exit 1; }

load() {
    taskset -c "$CPUS_LOAD" python3 "$HERE/loadgen.py" --host "$ORDERS_IP" --rate "$RATE" \
        --duration "$1" --workers 48 ${2:+--dump "$2"}
}
json_get() { python3 -c "import json,sys; print(json.load(open('$1'))['$2'])"; }

load 8 >/dev/null   # warm-up

echo "round,pos,cond,loops,shares_applied,rps,errors,p50_ms,p99_ms,p999_ms,orders,payments,db,batch" >"$OUT/phases.csv"
# Each service cell is samples/p99/slow, taken from the final table.
row() { echo "$(top_cell "$1" "$2" final 2)/$(top_cell "$1" "$2" final 4)/$(top_cell "$1" "$2" final 6)"; }

# Deterministic per-round shuffle, so a run can be repeated from its seed.
shuffle() { local r=$1; shift; printf '%s\n' "$@" | shuf --random-source=<(yes "$SEED-$r"); }

for round in $(seq "$ROUNDS"); do
    pos=0
    while read -r spec; do
        pos=$((pos + 1))
        IFS=: read -r cond loops shares <<<"$spec"
        applied=-
        if (( loops > 0 )); then
            $D run -d --name nw-shop-batch --cpuset-cpus "$CPUS_SHOP" busybox \
                sh -c "for i in \$(seq $loops); do (while :; do :; done) & done; wait" >/dev/null || exit 1
            if (( shares > 0 )); then
                $D update --cpu-shares "$shares" nw-shop-batch >/dev/null
                applied=$($D inspect -f '{{.HostConfig.CpuShares}}' nw-shop-batch)
            fi
            sleep 2
        fi
        f="$OUT/r${round}_${pos}_$cond"
        run_top "$PHASE_SECS" "$f.top" &
        agent=$!
        sleep 1
        probe=
        if [[ -n $STALL_PROBE ]]; then
            taskset -c "$STALL_CPU" "$STALL_PROBE" "$((PHASE_SECS - 1))" "cpu$STALL_CPU" >"$f.stalls" &
            probe=$!
        fi
        load "$((PHASE_SECS - 2))" ${STALL_PROBE:+"$f.requests"} >"$f.client"
        [[ -n $probe ]] && wait "$probe"
        wait "$agent"
        $D rm -f nw-shop-batch >/dev/null 2>&1
        echo "$round,$pos,$cond,$loops,$applied,$(json_get "$f.client" rps),$(json_get "$f.client" errors),$(json_get "$f.client" p50_ms),$(json_get "$f.client" p99_ms),$(json_get "$f.client" p999_ms),$(row "$f.top" docker:nw-shop-orders),$(row "$f.top" docker:nw-shop-payments),$(row "$f.top" docker:nw-shop-db),$(row "$f.top" docker:nw-shop-batch)" \
            >>"$OUT/phases.csv"
        echo "round $round/$ROUNDS pos $pos $cond done"
    done < <(shuffle "$round" "${CONDITIONS[@]}")
done

echo "done: $OUT/phases.csv"
