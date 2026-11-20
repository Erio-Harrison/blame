#!/usr/bin/env bash
# Shared helpers for scenario scripts; source it.
# Processes are tracked and killed by PID, never by `pkill -f` (it can match
# the calling shell). Scenarios need root or passwordless sudo.

SCN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NCPU="$(nproc)"

PASS=0
FAIL=0
ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
note() { echo "        $1"; }

# --- binary under test --------------------------------------------------------

resolve_bin() {
    BIN="${BLAME_BIN:-$(cargo metadata --no-deps --format-version 1 \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/blame}"
    if [[ ! -x "$BIN" ]]; then
        echo "blame binary not found at $BIN; run 'cargo build --release' first" >&2
        return 1
    fi
    # Process name of the agent, for pgrep/pkill -x; the kernel keeps 15 chars.
    AGENT_NAME="$(basename "$BIN" | cut -c1-15)"
}

need_root() {
    sudo -n true 2>/dev/null || { echo "needs root or passwordless sudo" >&2; return 1; }
}

# --- stall probe ----------------------------------------------------------------

# Build tests/tools/stalls.c into DIR and print the binary's path.
build_stall_probe() {
    local out="$1/stalls"
    cc -O2 -o "$out" "$SCN_DIR/../tools/stalls.c" && echo "$out"
}

# --- tracked background processes ---------------------------------------------

_TRACKED=()

# Start a command in the background and remember its PID.
spawn() {
    "$@" >/dev/null 2>&1 &
    _TRACKED+=("$!")
}

# Stop everything `spawn` started, and only that.
reap_tracked() {
    local pid
    for pid in "${_TRACKED[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
    done
    for pid in "${_TRACKED[@]:-}"; do
        [[ -n "$pid" ]] && wait "$pid" 2>/dev/null
    done
    _TRACKED=()
}

# CPU hogs that never sleep. `$2` is a taskset CPU list, e.g. "5" or "0-5".
start_hogs() {
    local count=$1 cpus=$2 i
    for ((i = 0; i < count; i++)); do
        spawn taskset -c "$cpus" sh -c 'while :; do :; done'
    done
}

# --- BPF object bookkeeping ---------------------------------------------------

# One program id per line, sorted.
bpf_prog_ids() {
    sudo -n bpftool prog show -j 2>/dev/null \
        | python3 -c 'import json,sys; print("\n".join(str(p["id"]) for p in json.load(sys.stdin)))' \
        | sort
}

# --- agent processes ----------------------------------------------------------

# Unreaped zombies still answer pgrep; filter them out or wait loops hang.
live_agents() {
    local pid
    for pid in $(pgrep -x "$AGENT_NAME"); do
        grep -q '^State:.*Z' "/proc/$pid/status" 2>/dev/null && continue
        echo "$pid"
    done
}

# --- output parsing -----------------------------------------------------------
# Parses `blame runq` output: "bucket lo_us=.. count=..", "key=value" fields.

# Last integer/decimal value of `KEY=` in FILE; empty if absent.
field() { grep -oP "(?<=\b$2=)[0-9.]+" "$1" | tail -1; }

# Upper bound of the bucket holding percentile PCT of the printed buckets,
# whatever the sample count: the report itself leaves out tail percentiles
# that too few samples back.
bucket_pct() {
    grep -E '^\s*bucket ' "$1" \
        | sed -E 's/.*hi_us=([0-9a-z]+).*count=([0-9]+).*/\1 \2/' \
        | awk -v p="$2" '{ hi[NR] = $1; c[NR] = $2; n += $2 }
              END { r = n * p / 100; for (i = 1; i <= NR; i++) { s += c[i]; if (s >= r) { print hi[i]; exit } } }'
}

# Number of samples in buckets whose lower bound is >= MIN_US.
samples_ge() {
    grep -E '^\s*bucket ' "$1" \
        | sed -E 's/.*lo_us=([0-9]+).*count=([0-9]+).*/\1 \2/' \
        | awk -v m="$2" '$1 >= m { s += $2 } END { print s + 0 }'
}

# Run `blame runq` for SECS seconds in the foreground, logging to LOG.
run_runq() {
    local secs=$1 log=$2
    shift 2
    sudo -n "$BIN" runq --duration "$secs" "$@" >"$log" 2>&1
}

# Cumulative context switches since boot, all CPUs.
ctxt_total() { awk '/^ctxt/ { print $2 }' /proc/stat; }

# --- `blame top` output ----------------------------------------------------
# Rows are "  LABEL samples p50 p99 p99.9 max slow"; labels contain no spaces.
# A percentile with too few samples behind it is printed as "-".

# Run `blame top` for SECS seconds in the foreground, logging to LOG.
run_top() {
    local secs=$1 log=$2
    shift 2
    sudo -n "$BIN" top --duration "$secs" --rows 500 "$@" >"$log" 2>&1
}

# Table rows of one section of a top log: "final" or "lastwindow".
top_rows() {
    awk -v which="$2" '
        /^--- top \(final\)/  { sec = "final"; next }
        /^--- top \(window/   { sec = "window"; window = ""; next }
        /^--- /               { sec = ""; next }
        sec == "" || NF != 7 || $1 == "service" { next }
        sec == "final"  { final = final $0 "\n" }
        sec == "window" { window = window $0 "\n" }
        END { printf "%s", (which == "final" ? final : window) }
    ' "$1"
}

# Column of LABEL's row in a section (2 samples, 3 p50, 4 p99, 5 p99.9, 6 max,
# 7 slow);
# 0 if the row is absent. Args: FILE LABEL final|lastwindow COLUMN.
top_cell() {
    local v
    v=$(top_rows "$1" "$3" | awk -v l="$2" -v c="$4" '$1 == l { print $c }')
    echo "${v:-0}"
}

# Sum of the samples column over a section.
top_total() { top_rows "$1" "$2" | awk '{ s += $2 } END { print s + 0 }'; }

# Number of table rows in a section.
top_row_count() { top_rows "$1" "$2" | wc -l; }

# Value of KEY=N in the kernel counters line of a log.
kernel_counter() { grep -oP "(?<=\b$2=)[0-9]+" "$1" | tail -1; }

# --- transient systemd units --------------------------------------------------

_UNITS=()

# Start `systemd-run` unit NAME running the rest of the arguments.
unit_start() {
    local name=$1
    shift
    sudo -n systemd-run --quiet --collect --unit="$name" "$@" || return 1
    _UNITS+=("$name")
}

unit_stop() { sudo -n systemctl stop "$1" 2>/dev/null; }

stop_units() {
    local u
    for u in "${_UNITS[@]:-}"; do
        [[ -n "$u" ]] && unit_stop "$u"
    done
    _UNITS=()
}

# Pinned hogs that never sleep, all in one unit: NAME, HOG_COUNT, CPU_LIST.
unit_hogs() {
    unit_start "$1" sh -c "for i in \$(seq $2); do taskset -c $3 sh -c 'while :; do :; done' & done; wait"
}

# A sleeper unit pinned to CPU_LIST: NAME, CPU_LIST, then sleeper.py arguments.
unit_sleeper() {
    local name=$1 cpus=$2
    shift 2
    unit_start "$name" taskset -c "$cpus" python3 "$SCN_DIR/workloads/sleeper.py" "$@"
}
