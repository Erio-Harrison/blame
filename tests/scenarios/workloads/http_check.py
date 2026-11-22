#!/usr/bin/env python3
"""Compare `blame slow --raw` output with what the server says happened.

    http_check.py TRUTH_LOG SLOW_LOG [--after-ns N]

TRUTH_LOG is the binary log of tests/tools/http_truth.c; SLOW_LOG holds the
`req key=value ...` lines of `blame slow --raw --above 0`. Requests are paired
per client port, in order, and a pair is good when both its start and its end
are within PAIR_TOL of the server's. Prints one `check key=value ...` line:

  truth, kernel       requests on each side
  paired              good pairs; paired_pct is of truth
  spurious            kernel requests the server never served
  latency_err_pct     (sum of kernel latencies - sum of truth) / truth, over pairs
  cpu_n, cpu_ok_pct   pairs with a CPU answer; share within tolerance
  cpu_err_pct         (sum kernel - sum truth) / truth
  blk_n, blk_ok_pct   pairs with a blocked-time answer; share within tolerance
  blk_err_pct         as above, for time asleep on behalf of the request
  down_n, down_ok_pct downstream calls the server timed itself (event loop);
                      share the agent timed within tolerance, a call it
                      missed counting as wrong
  down_missed         of those, calls the agent did not see at all
  down_split          of those, calls the agent counted as more than one
  idle_us             kernel time asleep charged to requests that never slept
  client_n, client_ok_pct
                      pairs where the server waited for the rest of the
                      request (thread-per-connection logs these); share whose
                      client-wait time is right. The server times each read
                      call from before to after, which also holds the wait on
                      the run queue after the wakeup and the CPU spent copying
                      the data; the agent books those as runq and CPU. So the
                      agent's figure must lie between the server's less the
                      request's runq and CPU, and the server's (with the usual
                      tolerance at both ends)
  client_extra_us     kernel client-wait time on pairs where the server logged
                      none; only meaningful for servers that log client waits
  io_n, io_ok_pct     pairs where the server read from disk past the page
                      cache; share whose disk time is right, with the bounds
                      used for client waits (the server times the whole call)
  io_us               disk time the agent reported on those pairs
  io_other_us         what it reported as other sleep on them
  mem_n, mem_ok_pct, mem_us, mem_other_us
                      the same for pairs where the server touched fresh
                      memory, and time stalled on memory
  io_fsvc_us          file-service time the agent reported on the disk pairs
  fsvc_n, fsvc_ok_pct, fsvc_us, fsvc_other_us, fsvc_disk_us
                      the same for pairs where the server waited for a file
                      service (a file on NFS, FUSE, ...), and the disk time
                      the agent reported on them
  fsvc_lock_us        of the file-service time on those pairs, what the agent
                      reported as waiting for a lock
  stall_extra_us      disk, memory and file-service time on pairs where the
                      server did none of those
  park_n, park_ok_pct, park_err_pct
                      pairs with a blocked-time answer again, for servers whose
                      units wait inside their runtime (a parked goroutine or
                      task blocks no thread): the part of the latency no
                      thread time accounts for, against the server's figure

  spawn_n             pairs where the server spawned goroutines or tasks (it
                      logs what they did in a second record); of those:
  spawn_count_exact_pct, spawn_count_under, spawn_count_over_max
                      share where the agent counted as many spawned units
                      (plus --framework-spawns), how many it counted fewer
                      on, and the most it counted too many
  spawn_cpu_n, spawn_cpu_ok_pct, spawn_cpu_err_pct
                      their CPU against the server's, as for the handler's
  spawn_io_n, spawn_io_ok_pct, spawn_io_other_us
                      their disk waits, bounded as client waits are, and the
                      sleep left in other on those pairs
  pool_wait_n, pool_wait_bounded_pct, pool_wait_us
                      pairs where the server logged how long the threads of a
                      pool (an OpenMP team) waited for a CPU for the request;
                      the share where the agent's figure is at least what they
                      waited inside their pieces of work and at most that,
                      what they waited between pieces, and a wake-up (100 us)
                      per piece; and the agent's mean
  spawn_extra_us      spawned units' CPU and disk time on pairs where the
                      server spawned nothing
  spawn_after_n, spawn_after_us
                      pairs whose spawned units did all their work after the
                      response, and the CPU and disk time the agent gave
                      them anyway
  why_<kind>_n, why_<kind>_ok_pct, why_<kind>_err_pct
                      for channel, sync, sleep and network (Go, type 4
                      records) and task, blocking, sleep and network (tokio,
                      type 5): pairs where the server's goroutine or task
                      waited on that, and how the agent's parked_<kind>_ns
                      compares (as for CPU); for tokio, with
                      parked_runnable_ns added, on pairs that waited on one
                      kind only (its kinds end at the wake)
  why_wrong_us        what the agent put under one of those kinds where the
                      server waited on no such thing (only pairs with a park
                      or wait record)
  spawn_plain_n, spawn_plain_exact_pct
                      those pairs, and the share where the agent counted just
                      the framework's own

--framework-spawns N: units the server's framework spawns for every request
by itself, which the server cannot log.

--after-ns drops requests that started before that boot-clock time, on both
sides (used when the agent attaches to a server that is already busy).
"""
import struct
import sys

REC = "<BBHIQQIIQQQQII"
REC_SIZE = struct.calcsize(REC)
FIELDS = "type label flags tid t0 t1 port seq cpu blk tdeq tdown tid_read outst".split()
R_REQ, R_BLK, R_HELP, R_PARK, R_WAIT, R_POOL = 1, 2, 3, 4, 5, 6
L_DOWN, L_CLIENT, L_SLEEP, L_IO, L_MEM, L_FSVC = 2, 3, 5, 7, 8, 9
F_DOWN = 8

PAIR_TOL = 300_000  # ns

# What the goroutine waited on (the server's park record) -> its field there.
WHY = {"channel": "cpu", "sync": "blk", "sleep": "tdeq", "network": "tdown"}
# tokio's server says what its task waited on by what it awaited (type 5).
WHY_TOKIO = {"task": "cpu", "blocking": "blk", "sleep": "tdeq", "network": "tdown"}


def within(kernel, truth):
    """Close enough: 100 us, or 10% for longer times."""
    return abs(kernel - truth) <= max(100_000, truth // 10)


def load_truth(path):
    data = open(path, "rb").read()
    return [
        dict(zip(FIELDS, struct.unpack_from(REC, data, off)))
        for off in range(0, len(data) - REC_SIZE + 1, REC_SIZE)
    ]


def load_kernel(path):
    out = []
    for line in open(path, errors="replace"):
        if not line.startswith("req "):
            continue
        head, _, text = line.rstrip("\n").partition(' line="')
        fields = dict(part.split("=", 1) for part in head.split()[1:])
        req = {key: int(value) for key, value in fields.items()}
        req["line"] = text.partition('"')[0]
        out.append(req)
    return out


def pct(part, whole):
    # No samples is not 100% right: nan, which no comparison passes.
    return 100.0 * part / whole if whole else float("nan")


def main():
    args = sys.argv[1:]
    after = 0
    if "--after-ns" in args:
        i = args.index("--after-ns")
        after = int(args[i + 1])
        del args[i : i + 2]
    # Units the server's framework spawns for every request by itself, which
    # the server cannot log (Go's net/http: one, to watch the connection).
    framework_spawns = 0
    if "--framework-spawns" in args:
        i = args.index("--framework-spawns")
        framework_spawns = int(args[i + 1])
        del args[i : i + 2]
    truth_path, kernel_path = args

    records = load_truth(truth_path)
    truth = [r for r in records if r["type"] == R_REQ and r["t0"] >= after]
    kernel = [k for k in load_kernel(kernel_path) if k["start_ns"] >= after]

    # What the units a request spawned did, for servers that spawn some.
    helped = {(r["port"], r["seq"]): r for r in records if r["type"] == R_HELP}
    # How long the threads of a pool waited for a CPU for a request: inside
    # their pieces of work (cpu), between them (blk), and how many pieces (tdeq).
    pooled = {(r["port"], r["seq"]): r for r in records if r["type"] == R_POOL}
    # How long the handler's goroutine waited on what, for servers that log it.
    waited = {(r["port"], r["seq"]): r for r in records if r["type"] == R_PARK}
    waited_tokio = {(r["port"], r["seq"]): r for r in records if r["type"] == R_WAIT}

    # Time the server's threads spent asleep on behalf of each request.
    asleep, client_wait, io_wait, mem_wait, fsvc_wait = {}, {}, {}, {}, {}
    for r in records:
        if r["type"] != R_BLK:
            continue
        key = (r["port"], r["seq"])
        if r["label"] in (L_DOWN, L_SLEEP):
            asleep[key] = asleep.get(key, 0) + r["t1"] - r["t0"]
        elif r["label"] == L_CLIENT:
            client_wait[key] = client_wait.get(key, 0) + r["t1"] - r["t0"]
        elif r["label"] == L_IO:
            io_wait[key] = io_wait.get(key, 0) + r["t1"] - r["t0"]
        elif r["label"] == L_MEM:
            mem_wait[key] = mem_wait.get(key, 0) + r["t1"] - r["t0"]
        elif r["label"] == L_FSVC:
            fsvc_wait[key] = fsvc_wait.get(key, 0) + r["t1"] - r["t0"]

    by_port_truth, by_port_kernel = {}, {}
    for r in truth:
        by_port_truth.setdefault(r["port"], []).append(r)
    for k in kernel:
        by_port_kernel.setdefault(k["rport"], []).append(k)

    pairs, spurious = [], 0
    for port in set(by_port_truth) | set(by_port_kernel):
        ts = sorted(by_port_truth.get(port, []), key=lambda r: (r["t0"], r["t1"]))
        ks = sorted(by_port_kernel.get(port, []), key=lambda k: (k["start_ns"], k["end_ns"]))
        j = 0
        for t in ts:
            # Kernel requests that end before this one could have are extra.
            while j < len(ks) and ks[j]["end_ns"] < t["t1"] - PAIR_TOL and ks[j]["start_ns"] < t["t0"] + PAIR_TOL:
                spurious += 1
                j += 1
            if j < len(ks) and abs(ks[j]["start_ns"] - t["t0"]) <= PAIR_TOL and abs(ks[j]["end_ns"] - t["t1"]) <= PAIR_TOL:
                pairs.append((t, ks[j]))
                j += 1
        spurious += len(ks) - j

    lat_truth = sum(t["t1"] - t["t0"] for t, _ in pairs)
    lat_kernel = sum(k["end_ns"] - k["start_ns"] for _, k in pairs)

    cpu = [(k["cpu_ns"], t["cpu"]) for t, k in pairs if t["cpu"]]
    blocked, idle = [], 0
    down, down_missed, down_split = [], 0, 0
    client, client_extra = [], 0
    io, io_other, mem, mem_other, stall_extra = [], 0, [], 0, 0
    fsvc, fsvc_other, fsvc_disk, fsvc_lock, io_fsvc = [], 0, 0, 0, 0
    parked = []
    spawn, spawn_extra, spawn_plain = [], 0, []
    pool_wait = []
    why = {name: [] for name in list(WHY) + [n for n in WHY_TOKIO if n not in WHY]}
    why_wrong = 0
    for t, k in pairs:
        key = (t["port"], t["seq"])
        w = waited.get(key)
        if w:
            for name, field in WHY.items():
                truth_ns = w[field]
                kernel_ns = k.get(f"parked_{name}_ns", 0)
                if truth_ns:
                    why[name].append((kernel_ns, truth_ns))
                else:
                    why_wrong += kernel_ns
        w = waited_tokio.get(key)
        if w:
            # tokio's kinds end at the wake; the server's await, at its next
            # poll: with one kind waited on, add the wait to be polled.
            kinds = [name for name, field in WHY_TOKIO.items() if w[field]]
            for name, field in WHY_TOKIO.items():
                truth_ns = w[field]
                kernel_ns = k.get(f"parked_{name}_ns", 0)
                if truth_ns and len(kinds) == 1:
                    why[name].append((kernel_ns + k.get("parked_runnable_ns", 0), truth_ns))
                elif not truth_ns:
                    why_wrong += kernel_ns
        h = helped.get(key)
        if h:
            spawn.append((k.get("helpers", 0), h["tdeq"] + framework_spawns, k.get("helper_cpu_ns", 0), h["cpu"],
                          k.get("helper_io_ns", 0), h["blk"],
                          k.get("helper_cpu_ns", 0) + k.get("helper_runq_ns", 0),
                          k.get("helper_other_ns", 0) + k.get("helper_down_ns", 0) + k.get("helper_client_ns", 0)))
        else:
            spawn_extra += k.get("helper_cpu_ns", 0) + k.get("helper_io_ns", 0)
            spawn_plain.append(k.get("helpers", 0) - framework_spawns)
        p = pooled.get(key)
        if p:
            pool_wait.append((k.get("helper_runq_ns", 0), p["cpu"], p["blk"], p["tdeq"]))
        not_asleep = k["runq_ns"] + k["cpu_ns"]
        if key in io_wait:
            io.append((k["blocked_io_ns"], io_wait[key], not_asleep))
            io_other += k["blocked_other_ns"]
            io_fsvc += k.get("blocked_fsvc_ns", 0)
        if key in fsvc_wait:
            fsvc.append((k.get("blocked_fsvc_ns", 0), fsvc_wait[key], not_asleep))
            fsvc_other += k["blocked_other_ns"]
            fsvc_disk += k["blocked_io_ns"]
            fsvc_lock += k.get("blocked_fsvc_lock_ns", 0)
        if key in mem_wait:
            mem.append((k["blocked_mem_ns"], mem_wait[key], not_asleep))
            mem_other += k["blocked_other_ns"]
        if key not in io_wait and key not in mem_wait and key not in fsvc_wait:
            stall_extra += k["blocked_io_ns"] + k["blocked_mem_ns"] + k.get("blocked_fsvc_ns", 0)
        kernel_asleep = k["blocked_down_ns"] + k["blocked_other_ns"]
        # Pool workers time their own sleeps; the other servers log each one.
        truth_asleep = t["blk"] or asleep.get((t["port"], t["seq"]), 0)
        if truth_asleep:
            blocked.append((kernel_asleep, truth_asleep))
            on_thread = sum(k[name] for name in k if name.startswith("blocked_")) + not_asleep
            parked.append((max(0, k["end_ns"] - k["start_ns"] - on_thread), truth_asleep))
        elif not t["flags"] & F_DOWN:
            idle += kernel_asleep
        if t["tdown"]:
            # A call the agent missed is a wrong answer, not a smaller sample.
            down.append((k["down_wait_ns"] if k["down_calls"] else 0, t["tdown"] - t["tdeq"]))
            down_missed += not k["down_calls"]
            down_split += k["down_calls"] > 1
        truth_client = client_wait.get((t["port"], t["seq"]), 0)
        if truth_client:
            client.append((k["blocked_client_ns"], truth_client, k["runq_ns"] + k["cpu_ns"]))
        else:
            client_extra += k["blocked_client_ns"]

    def stalls(samples):
        return (
            f"n={len(samples)}",
            f"ok_pct={pct(sum(client_ok(*c) for c in samples), len(samples)):.2f}",
            f"us={sum(c[0] for c in samples) // 1000}",
        )

    def client_ok(kernel, truth, not_asleep):
        tol = max(100_000, truth // 10)
        return kernel <= truth + tol and kernel + not_asleep >= truth - tol

    def ok_pct(samples):
        return pct(sum(within(k, t) for k, t in samples), len(samples))

    def err_pct(samples):
        total = sum(t for _, t in samples)
        return 100.0 * (sum(k for k, _ in samples) - total) / total if total else float("nan")

    print(
        "check"
        f" truth={len(truth)} kernel={len(kernel)} paired={len(pairs)}"
        f" paired_pct={pct(len(pairs), len(truth)):.2f} spurious={spurious}"
        f" latency_err_pct={100.0 * (lat_kernel - lat_truth) / lat_truth if lat_truth else float('nan'):.2f}"
        f" cpu_n={len(cpu)} cpu_ok_pct={ok_pct(cpu):.2f} cpu_err_pct={err_pct(cpu):.2f}"
        f" blk_n={len(blocked)} blk_ok_pct={ok_pct(blocked):.2f} blk_err_pct={err_pct(blocked):.2f}"
        f" down_n={len(down)} down_ok_pct={ok_pct(down):.2f} down_missed={down_missed} down_split={down_split}"
        f" idle_us={idle // 1000}"
        f" client_n={len(client)}"
        f" client_ok_pct={pct(sum(client_ok(*c) for c in client), len(client)):.2f}"
        f" client_extra_us={client_extra // 1000}"
        + "".join(f" io_{part}" for part in stalls(io))
        + f" io_other_us={io_other // 1000} io_fsvc_us={io_fsvc // 1000}"
        + "".join(f" fsvc_{part}" for part in stalls(fsvc))
        + f" fsvc_other_us={fsvc_other // 1000} fsvc_disk_us={fsvc_disk // 1000}"
        + f" fsvc_lock_us={fsvc_lock // 1000}"
        + "".join(f" mem_{part}" for part in stalls(mem))
        + f" mem_other_us={mem_other // 1000}"
        + f" stall_extra_us={stall_extra // 1000}"
        + f" park_n={len(parked)} park_ok_pct={ok_pct(parked):.2f} park_err_pct={err_pct(parked):.2f}"
        + spawn_summary(spawn, spawn_extra, client_ok, ok_pct, err_pct)
        + "".join(f" why_{name}_n={len(v)} why_{name}_ok_pct={ok_pct(v):.2f} why_{name}_err_pct={err_pct(v):.2f}" for name, v in why.items())
        + f" why_wrong_us={why_wrong // 1000}"
        + f" spawn_plain_n={len(spawn_plain)} spawn_plain_exact_pct={pct(sum(d == 0 for d in spawn_plain), len(spawn_plain)):.2f}"
        + f" pool_wait_n={len(pool_wait)}"
        + f" pool_wait_bounded_pct={pct(sum(pool_wait_bounded(*w) for w in pool_wait), len(pool_wait)):.2f}"
        + f" pool_wait_us={sum(w[0] for w in pool_wait) // max(len(pool_wait), 1) // 1000}"
    )


def pool_wait_bounded(kernel, inside, between, pieces):
    """The agent counts a wait from the wake-up, the server's figures (the
    kernel's own) from when the thread is on a run queue; and what a thread
    waits on its way back to idle, after its piece, is no request's. So the
    agent's figure is held between two bounds, not to one value."""
    tol = max(100_000, inside // 10)
    return inside - tol <= kernel <= inside + between + pieces * 100_000 + tol


def spawn_summary(spawn, extra, client_ok, ok_pct, err_pct):
    """How the units each request spawned compare with what the server
    says they did: their number, their CPU, and their disk waits."""
    over = [k - t for k, t, *_ in spawn]
    cpu = [(kc, tc) for _, _, kc, tc, *_ in spawn if tc]
    io = [(ki, ti, kon) for *_, ki, ti, kon, _ in spawn if ti]
    io_other = sum(ko for *_, ti, _, ko in spawn if ti)
    # Spawned only units that work after the response: none of it is theirs.
    zero = [kc + ki for _, _, kc, tc, ki, ti, *_ in spawn if not tc and not ti]
    return (
        f" spawn_n={len(spawn)}"
        f" spawn_count_exact_pct={pct(sum(d == 0 for d in over), len(spawn)):.2f}"
        f" spawn_count_under={sum(d < 0 for d in over)}"
        f" spawn_count_over_max={max(over, default=0)}"
        f" spawn_cpu_n={len(cpu)} spawn_cpu_ok_pct={ok_pct(cpu):.2f} spawn_cpu_err_pct={err_pct(cpu):.2f}"
        f" spawn_io_n={len(io)} spawn_io_ok_pct={pct(sum(client_ok(*c) for c in io), len(io)):.2f}"
        f" spawn_io_other_us={io_other // 1000}"
        f" spawn_extra_us={extra // 1000}"
        f" spawn_after_n={len(zero)} spawn_after_us={sum(zero) // 1000}"
    )


if __name__ == "__main__":
    main()
