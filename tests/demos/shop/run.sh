#!/usr/bin/env bash
#
# Order-placement demo: orders -> payments -> Postgres, with a batch job as a
# noisy neighbour. Shows what `blame top` says in each phase next to what a
# client sees. A demonstration, not a pass/fail test.
#
# Needs docker, root or passwordless sudo, python3, taskset.
#     tests/demos/shop/run.sh [blame-binary]
# Env: PHASE_SECS (default 20), RATE (requests/s, default 300),
#      CPUS_SHOP (default 0-1), CPUS_LOAD (default 4-5), KEEP_IMAGES=1

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/../../scenarios/lib.sh"

[[ -n "${1:-}" ]] && BLAME_BIN="$1"
resolve_bin || exit 1
need_root || exit 1

PHASE_SECS="${PHASE_SECS:-20}"
RATE="${RATE:-300}"
CPUS_SHOP="${CPUS_SHOP:-0-1}"
CPUS_LOAD="${CPUS_LOAD:-4-5}"
WORK="$(mktemp -d)"
D="sudo -n docker"
NET=nw-shop
NAMES=(nw-shop-db nw-shop-payments nw-shop-orders nw-shop-batch)

docker_was_active=0
systemctl is-active --quiet docker && docker_was_active=1

cleanup() {
    reap_tracked
    $D rm -f "${NAMES[@]}" >/dev/null 2>&1
    $D network rm $NET >/dev/null 2>&1
    [[ -n "${KEEP_IMAGES:-}" ]] || $D rmi nw-shop >/dev/null 2>&1
    (( docker_was_active )) || sudo -n systemctl stop docker.socket docker containerd >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

sudo -n systemctl start docker || { echo "cannot start docker" >&2; exit 1; }
$D build -q -t nw-shop "$HERE" >/dev/null || { echo "image build failed" >&2; exit 1; }
$D network create $NET >/dev/null

echo "starting the shop on CPUs $CPUS_SHOP (load generator on $CPUS_LOAD)"
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
    || { echo "the shop never answered an order" >&2; $D logs nw-shop-orders 2>&1 | tail -5; exit 1; }

load() { taskset -c "$CPUS_LOAD" python3 "$HERE/loadgen.py" --host "$ORDERS_IP" --rate "$RATE" --duration "$1" --workers 48; }

echo "warming up"
load 5 >/dev/null

phase() {
    local name=$1
    echo "phase: $name (${PHASE_SECS}s)"
    run_top "$PHASE_SECS" "$WORK/$name.top" &
    local agent=$!
    sleep 1
    load "$((PHASE_SECS - 2))" >"$WORK/$name.client"
    wait "$agent"
}

phase baseline

$D run -d --name nw-shop-batch --cpuset-cpus "$CPUS_SHOP" busybox \
    sh -c 'for i in 1 2 3 4; do (while :; do :; done) & done; wait' >/dev/null || exit 1
sleep 2
phase noisy

$D update --cpu-shares 2 nw-shop-batch >/dev/null
sleep 2
phase throttled

# --- summary --------------------------------------------------------------------
json_get() { python3 -c "import json,sys; print(json.load(open('$1'))['$2'])"; }
cell() { top_cell "$WORK/$1.top" "$2" final "$3"; }

echo
printf '%-10s | %-24s | %-22s | %-22s | %-22s | %s\n' phase "client (ms)" "orders  samples/p99/slow" \
    "payments samples/p99/slow" "db       samples/p99/slow" "batch"
for p in baseline noisy throttled; do
    c="rps=$(json_get "$WORK/$p.client" rps) p50=$(json_get "$WORK/$p.client" p50_ms) p99=$(json_get "$WORK/$p.client" p99_ms) err=$(json_get "$WORK/$p.client" errors)"
    row() { echo "$(cell "$p" "$1" 2)/$(cell "$p" "$1" 4)/$(cell "$p" "$1" 6)"; }
    printf '%-10s | %-24s | %-22s | %-22s | %-22s | %s\n' "$p" "$c" \
        "$(row docker:nw-shop-orders)" "$(row docker:nw-shop-payments)" "$(row docker:nw-shop-db)" \
        "$(row docker:nw-shop-batch)"
done
echo
echo "full tables are in $WORK until this script exits; first the noisy phase:"
sed -n '/--- top (final)/,/groups/p' "$WORK/noisy.top"
