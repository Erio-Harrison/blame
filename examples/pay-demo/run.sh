#!/usr/bin/env bash
# Run one scenario of the pay demo and keep what blame and the services said.
#
#   examples/pay-demo/run.sh SCENARIO STATEMENTS_DIR OUT_DIR
#
# SCENARIO: normal, cpu (three processes spin on the CPUs risk runs on),
# downstream (ledger keeps the database locked 3 ms per entry), lock (account
# computes 1 ms under its balances' lock), nfs (5 ms added to the network path
# of NFS requests: STATEMENTS_DIR must be on an NFS mount from 127.0.0.1), disk
# (another process writes and flushes on the disk of the ledger's database and
# the gateway's audit file), cpu-payment (two processes spin on the CPU payment
# runs on), cpu-gateway (two processes spin on the two CPUs the gateway shares
# with account, ledger and the load), docker (nothing wrong; payment runs in a
# container, on Docker's bridge network), docker-cpu (the same, the container
# limited to a quarter of a CPU).
# Needs root through sudo (blame, tc), Go and cargo, and for the risk service a
# python3 with torch: PYTHON names it (default: python3). Without torch the
# demo runs without the risk service. The docker scenarios need docker through
# sudo and an image with glibc: PAY_IMAGE names it (default:
# debian:stable-slim). Uses CPUs 0-5: gateway, account, ledger
# and the load on 0-1, payment on 2, risk on 3-5.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
scenario=$1 statements=$2 out=$3/$1
python=${PYTHON:-python3}
blame="${BLAME_BIN:-$(cargo metadata --manifest-path "$here/../../Cargo.toml" --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/blame}"
mkdir -p "$out" "$3/bin"
(cd "$here/go" && go build -o "$3/bin/pay" .) || exit 1
cargo build --release --quiet --manifest-path "$here/gateway/Cargo.toml" --target-dir "$3/bin/target" || exit 1
db=$(mktemp -d)
pids=() names=() hogs=() container=
stop_all() {
    sudo -n tc qdisc del dev lo root 2>/dev/null
    for p in "${hogs[@]:-}"; do [[ -n "$p" ]] && { pkill -P "$p" 2>/dev/null; kill "$p" 2>/dev/null; }; done
    for p in "${pids[@]}"; do kill -TERM "$p" 2>/dev/null; done
    [[ -n $container ]] && sudo -n docker stop -t 5 "$container" >/dev/null 2>&1
    wait 2>/dev/null
    rm -rf "$db"
}
trap stop_all EXIT
hold=0s lock=100us
[[ $scenario == downstream ]] && hold=3ms
[[ $scenario == lock ]] && lock=1ms
if [[ $scenario == nfs ]]; then
    # Requests to the NFS server's port wait 5 ms on the way.
    sudo -n tc qdisc add dev lo root handle 1: prio
    sudo -n tc qdisc add dev lo parent 1:3 handle 30: netem delay 5ms
    sudo -n tc filter add dev lo protocol ip parent 1:0 prio 3 u32 match ip dport 2049 0xffff flowid 1:3
fi
pay=$3/bin/pay
# What payment reaches the others at: from a container, the bridge's address.
host=127.0.0.1
[[ $scenario == docker* ]] && host=$(sudo -n docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
taskset -c 0-1 "$pay" -role account -addr $host:9402 -http 127.0.0.1:9412 -statements "$statements" -lock-work $lock -log "$out/account.truth" >/dev/null & pids+=($!); names+=(account)
taskset -c 0-1 "$pay" -role ledger -addr $host:9403 -db "$db/ledger.db" -hold $hold -log "$out/ledger.truth" >/dev/null & pids+=($!); names+=(ledger)
risk=()
if "$python" -c 'import torch' 2>/dev/null; then
    OMP_NUM_THREADS=3 OMP_WAIT_POLICY=passive taskset -c 3-5 "$python" "$here/risk/server.py" $host:9404 127.0.0.1:9412 "$out/risk.truth" > "$out/risk.out" 2>&1 & pids+=($!); names+=(risk)
    for _ in $(seq 300); do grep -q ready "$out/risk.out" 2>/dev/null && break; sleep 0.2; done
    grep -q ready "$out/risk.out" || { cat "$out/risk.out"; exit 1; }
    risk=(-risk $host:9404)
else
    echo "no torch in $python: running without the risk service" >&2
fi
sleep 0.5
payment=127.0.0.1
if [[ $scenario == docker* ]]; then
    limit=(); [[ $scenario == docker-cpu ]] && limit=(--cpus 0.25)
    container=pay-demo-payment-$$
    sudo -n docker run -d --rm --name $container --user "$(id -u):$(id -g)" --cpuset-cpus 2 "${limit[@]}" \
        -v "$(realpath "$pay"):/pay:ro" -v "$(realpath "$out"):/out" "${PAY_IMAGE:-debian:stable-slim}" \
        /pay -role payment -addr 0.0.0.0:9401 -account $host:9402 -ledger $host:9403 "${risk[@]}" \
        -log /out/payment.truth >/dev/null || exit 1
    pids+=($(sudo -n docker inspect -f '{{.State.Pid}}' $container)); names+=(payment)
    payment=$(sudo -n docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' $container)
else
    taskset -c 2 "$pay" -role payment -addr 127.0.0.1:9401 -account $host:9402 -ledger $host:9403 "${risk[@]}" \
        -log "$out/payment.truth" >/dev/null & pids+=($!); names+=(payment)
fi
taskset -c 0-1 "$3/bin/target/release/pay-gateway" 127.0.0.1:8490 http://$payment:9401 http://$host:9402 \
    "$db/audit.log" "$out/gateway.truth" >/dev/null & pids+=($!); names+=(gateway)
sleep 1
taskset -c 0-1 "$pay" -role load -addr 127.0.0.1:8490 -workers 8 -secs 24 > "$out/load.txt" & load=$!
sleep 3
# Attached while the services are busy, as it would be.
args=(); for p in "${pids[@]}"; do args+=(--pid "$p"); done
sudo -n "$blame" slow --json --above 0 --list 0 --interval 0 --deep "${args[@]}" > "$out/blame.json" 2> "$out/blame.err" & agent=$!
for _ in $(seq 300); do (( $(grep -c '"type":"process"' "$out/blame.json" 2>/dev/null) >= ${#pids[@]} )) && break; sleep 0.1; done
case $scenario in
cpu)
    for _ in 1 2 3; do taskset -c 3-5 python3 -c 'while 1: pass' & hogs+=($!); done ;;
cpu-payment)
    for _ in 1 2; do taskset -c 2 python3 -c 'while 1: pass' & hogs+=($!); done ;;
cpu-gateway)
    for _ in 1 2; do taskset -c 0-1 python3 -c 'while 1: pass' & hogs+=($!); done ;;
disk)
    ( while :; do dd if=/dev/zero of="$db/noise" bs=1M count=4 conv=fsync 2>/dev/null; done ) & hogs+=($!) ;;
esac
sleep 15
for p in $(pgrep -P "$agent"); do sudo -n kill -INT "$p"; done
wait "$agent"
wait "$load"
for i in "${!pids[@]}"; do echo "${names[$i]} ${pids[$i]}"; done > "$out/pids"
cat "$out/load.txt"
