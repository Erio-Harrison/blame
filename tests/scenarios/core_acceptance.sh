#!/usr/bin/env bash
#
# CO-RE acceptance: tracepoint and kernel struct fields are relocated against
# the target BTF, and a layout the programs cannot be relocated to is refused
# at startup.
#
# Fake target layouts are compiled from C into BTF and passed with `--btf`.
# Needs root or passwordless sudo, bpftool, clang, llvm-objcopy, python3.
#     ./tests/scenarios/core_acceptance.sh [blame-binary]

set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -n "${1:-}" ]] && BLAME_BIN="$1"
resolve_bin || exit 1
need_root || exit 1
for tool in clang llvm-objcopy bpftool; do
    command -v "$tool" >/dev/null || { echo "needs $tool" >&2; exit 1; }
done

WORK="$(mktemp -d)"
trap 'reap_tracked; rm -rf "$WORK"' EXIT

# Byte offset of STRUCT.FIELD (task_struct by default) in the running
# kernel's BTF: struct_offset FIELD [STRUCT].
struct_offset() {
    sudo -n bpftool btf dump file /sys/kernel/btf/vmlinux format raw \
        | awk -v f="'$1'" -v s="'${2:-task_struct}'" '$2 == "STRUCT" && $3 == s { in_t = 1; next }
              /^\[/{ in_t = 0 } in_t && $1 == f { sub("bits_offset=", "", $3); print $3 / 8; exit }'
}
task_offset() { struct_offset "$1"; }
PID_OFF=$(task_offset pid)
TGID_OFF=$(task_offset tgid)
# Every check below compares against these: without them each would pass
# on an empty pattern.
[[ $PID_OFF =~ ^[0-9]+$ && $TGID_OFF =~ ^[0-9]+$ ]] || {
    echo "could not read task_struct's pid and tgid offsets from the kernel's BTF (pid=$PID_OFF tgid=$TGID_OFF)" >&2
    exit 1
}

# Compile a C layout into a raw BTF file: fake_btf NAME < source
fake_btf() {
    cat >"$WORK/$1.c"
    clang -g -O0 -target bpf -c "$WORK/$1.c" -o "$WORK/$1.o" \
        && llvm-objcopy --dump-section .BTF="$WORK/$1.btf" "$WORK/$1.o" \
        && echo "$WORK/$1.btf"
}

# task_struct with the fields the programs read, each at its offset in the
# running kernel unless moved. PID_AT moves `pid`; ON_CPU and PID replace a
# field's declaration (an empty value removes it). The cgroup a task is in
# (task->cgroups->dfl_cgrp->kn->id) is read too, each link at its offset.
task_layout() {
    local pid_at=${PID_AT:-$PID_OFF}
    python3 - "$pid_at" "${PID-int pid;}" "${ON_CPU-int on_cpu;}" \
        "$(task_offset __state)" "$(task_offset on_cpu)" "$(task_offset on_rq)" \
        "$(task_offset cgroups)" "$(struct_offset dfl_cgrp css_set)" \
        "$(struct_offset kn cgroup)" "$(struct_offset id kernfs_node)" <<'PY'
import sys
pid_at, pid, on_cpu = sys.argv[1], sys.argv[2], sys.argv[3]
state, cpu, rq, cgroups, dfl, kn, kid = map(int, sys.argv[4:])

def struct(name, fields):
    out, at = [], 0
    for i, (off, size, decl) in enumerate(sorted(fields)):
        if not decl:
            continue
        if off > at:
            out.append(f"char pad{i}[{off - at}];")
        out.append(decl)
        at = off + size
    return f"struct {name} {{ " + " ".join(out) + " };"

# A variable of each, or clang leaves a struct only pointed to a forward declaration.
print(struct("kernfs_node", [(kid, 8, "unsigned long long id;")]) + " struct kernfs_node k;")
print(struct("cgroup", [(kn, 8, "struct kernfs_node *kn;")]) + " struct cgroup g;")
print(struct("css_set", [(dfl, 8, "struct cgroup *dfl_cgrp;")]) + " struct css_set c;")
print(struct("task_struct", [(state, 4, "unsigned int __state;"), (cpu, 4, on_cpu),
    (rq, 4, "int on_rq;"), (int(pid_at), 4, pid), (cgroups, 8, "struct css_set *cgroups;")])
    + " struct task_struct t;")
PY
}

# Every record the programs read. The tracepoint fields stay inside the real
# records, past the 8-byte common header the verifier keeps off limits: the
# kernel refuses a program whose ctx reads fall outside. EXEC_FILENAME
# substitutes one field.
layout() {
    cat <<EOF
struct trace_event_raw_sched_process_exec { ${EXEC_FILENAME-unsigned int __data_loc_filename;} int old_pid; };
struct trace_event_raw_cgroup { unsigned long long ent; int root; int level; unsigned long long id; unsigned int __data_loc_path; };
struct trace_event_raw_sched_process_exec a; struct trace_event_raw_cgroup d;
$(task_layout)
EOF
}

# Offset of every memory load in the loaded runq_switch, while `top` runs.
switch_loads() {
    local id
    id=$(sudo -n bpftool prog show -j \
        | python3 -c 'import json,sys; print(next((p["id"] for p in json.load(sys.stdin) if p.get("name")=="runq_switch"), ""))')
    [[ -n "$id" ]] || return 1
    sudo -n bpftool prog dump xlated id "$id" | grep -oP '\(r[0-9] \+\K[0-9]+(?=\))' | sort -un | tr '\n' ' '
}

# Start `top` (which loads the run-queue programs) with the given args for a
# few seconds and capture its loads.
loads_under() {
    local log="$1"; shift
    sudo -n "$BIN" top --histogram --duration 3 --interval 0 "$@" >"$log" 2>&1 &
    local pid=$!
    sleep 1.5
    switch_loads
    wait "$pid"
}

# Expect startup to be refused: non-zero exit, nothing left loaded.
expect_refused() {
    local what="$1" log="$2"; shift 2
    local before after
    before=$(bpf_prog_ids)
    if sudo -n "$BIN" "$@" >"$log" 2>&1; then
        bad "$what: agent started"
    else
        ok "$what: agent refused to start"
    fi
    grep -q "loading the eBPF programs" "$log" \
        && ok "$what: the error names the load" \
        || bad "$what: unexpected error: $(tail -1 "$log")"
    after=$(bpf_prog_ids)
    [[ "$before" == "$after" ]] \
        && ok "$what: no programs left behind" \
        || bad "$what: programs left behind"
}

echo "blame CO-RE acceptance ($BIN)"

# --- 1. relocation follows the target BTF ------------------------------------
echo
echo "[1] field offsets come from the target BTF"
loads=$(loads_under "$WORK/real.log" --btf /sys/kernel/btf/vmlinux)
note "kernel task_struct.pid@$PID_OFF tgid@$TGID_OFF; runq_switch loads at: $loads"
[[ " $loads " == *" $PID_OFF "* ]] \
    && ok "with the kernel's BTF, task_struct.pid is read at offset $PID_OFF" \
    || bad "task_struct.pid is not read at offset $PID_OFF"
samples=$(field "$WORK/real.log" samples)
(( ${samples:-0} > 0 )) \
    && ok "explicit --btf with the kernel's own BTF works ($samples samples)" \
    || bad "no samples with --btf /sys/kernel/btf/vmlinux"

# Moved onto tgid, an int in the real kernel too, so the verifier accepts it.
shifted=$(PID_AT=$TGID_OFF layout | fake_btf shifted) || { bad "could not build fake BTF"; exit 1; }
loads=$(loads_under "$WORK/shifted.log" --btf "$shifted")
note "fake layout pid@$TGID_OFF; runq_switch loads at: $loads"
[[ " $loads " == *" $TGID_OFF "* && " $loads " != *" $PID_OFF "* ]] \
    && ok "with a moved layout, pid is read at the moved offset" \
    || bad "the load offset did not follow the target BTF"

# --- 2. layouts the programs cannot be relocated to ---------------------------
echo
echo "[2] incompatible layouts are refused"
btf=$(ON_CPU="" layout | fake_btf missing) || exit 1
expect_refused "missing task_struct.on_cpu" "$WORK/missing.log" top --duration 1 --btf "$btf"

btf=$(PID="char pid[4];" layout | fake_btf retyped) || exit 1
expect_refused "task_struct.pid is no longer an integer" "$WORK/retyped.log" top --duration 1 --btf "$btf"

# `__rel_loc` measures the payload from the field, not the record.
btf=$(EXEC_FILENAME="unsigned int __rel_loc_filename;" layout | fake_btf relloc) || exit 1
expect_refused "filename became __rel_loc" "$WORK/relloc.log" --stats-interval 0 --btf "$btf"

echo
echo "$PASS passed, $FAIL failed"
exit $(( FAIL > 0 ))
