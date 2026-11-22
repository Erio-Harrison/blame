#!/usr/bin/env python3
"""Compare `blame slow --raw --above 0` with the log of a gRPC ground-truth server.

    grpc_check.py SERVER_LOG SLOW_LOG

Calls are matched by trace id: the client gives every call its own, the
server logs the one it received, the agent shows the one it decoded. A call
the agent shows without a trace id (on a connection older than the agent the
header that carries it cannot be decoded) is matched by client port and
stream id, where the server logs those. Prints one line:

  served        calls the server handled
  reported      HTTP/2 requests the agent reported
  named         of those, reported with a path
  with_trace    reported with a trace id
  joined        served calls found among the reported ones
  by_trace      of those, found by trace id
  paths         joined calls reported with a path
  path_ok       of those, with the method the server ran
  answered      joined calls the call was not over before the handler's end (not reset or given up)
  statuses      of those, reported with a gRPC status
  status_ok     of those, with the status the server answered with
  trace_wrong   reported calls whose trace id is one that no call of the run had
  followed      joined calls with time attributed to them
  unit_ok       of those, attributed to the goroutine or task that ran them
  inside        of those, whose handler ran within the reported start and end
  cpu_ok_pct    of those, share whose CPU time agrees with the server's (see below)
  cpu_err_pct   total CPU time reported for them against the server's, in percent
  runq_pct      total run-queue time reported for them, in percent of the server's CPU time
  handler_timed of the followed calls, those with the time before and after their
                handler (flag 32)
  before_ok     of those, whose handler first ran no later than the server
                started its handler (start + before_handler <= t0): the library
                runs a little of its own code in the handler's unit first
  after_ok      ... and whose handler last left its thread no earlier than the
                server's handler returned (end - after_handler >= t1)
  timed_cpu_ok  of the handler_timed calls, those whose CPU time agrees (a call
                whose handler switch the agent missed has both wrong)
  parts_ok_cpu_ok   of those, with both before_ok and after_ok
  late_followed, late_untimed   followed calls whose handler started after the
                agent was attached (GRPC_ATTACHED_NS); of those, without the
                two parts: there should be none
  before_us, after_us   mean of the two parts, us
  lead_p50_us, lead_p99_us   t0 - (start + before_handler): the handler's own
                time before the server's handler started

The server times its computing by the clock, so a thread that is preempted
while computing makes the server's figure larger by what the agent reports
as run-queue time. A call agrees when the agent's CPU time is not above the
server's, and its CPU plus run-queue time not below, by more than 100 us or
10%.
  unnamed_followed  reported requests without a path that have time attributed
  timed         reported requests that have time attributed, named or not
  resets        requests reported as reset, by either side
  timeouts      calls the client gave up on (CLIENT_LOG: `X <trace id> <path>` lines;
                counted only where the agent could know the trace id)
  late_calls    joined calls whose handler started after the agent was
                attached (GRPC_ATTACHED_NS, CLOCK_BOOTTIME ns: when the test saw
                it say so, so no earlier than it was); 0 without it
  late_no_trace of those, reported without a trace id: probes in the process
                were on when their headers were read, so there should be none
  timeout_ok    of those, reported with the right path as over within 80 ms of
                the server reading them (the client's deadline is 20 ms):
                reset by the client, or by the server, which is told the
                deadline and may get there first, or answered by it with
                CANCELLED or DEADLINE_EXCEEDED

The agent's summary by method (`method ...` lines) is checked against what
the server and the client say happened, path by path:

  m_paths       paths in the summary
  m_calls_ok    of those, with as many calls as the server answered plus the
                client gave up on
  m_ends_ok     ... and with those split right: answered with status 0, and
                the rest (another status, or reset)
  m_listed_ok   ... and agreeing with the requests the agent listed one by
                one: as many, the same CPU time in all, the same longest one
                (only when it listed every request: --above 0)
"""
import os
import sys

CPU_TOL_NS = 100_000
# The server's clock and the agent's are lined up to well under this.
CLOCK_TOL_NS = 1_000


def pctl(values, p):
    if not values:
        return 0
    values = sorted(values)
    return values[min(len(values) - 1, len(values) * p // 100)]


def main():
    server_path, slow_path = sys.argv[1:3]
    served = []
    # Calls whose headers the server read (H lines), where it logs them.
    heard = set()
    # When the server read a call's headers, where it logs that.
    read_at = {}
    for line in open(server_path):
        f = line.split()
        if len(f) == 10 and f[0] == "T":
            served.append((f[1], f[2], *(int(v) for v in f[3:])))
        elif len(f) in (3, 4) and f[0] == "H":
            heard.add(f[1])
            if len(f) == 4:
                read_at[f[1]] = int(f[3])
    given_up = {}
    if len(sys.argv) > 3:
        given_up = dict(l.split()[1:3] for l in open(sys.argv[3]) if l.startswith("X "))
    # A call the client gave up on before its headers went out was never on
    # the connection: no one could see it.
    if heard:
        given_up = {t: p for t, p in given_up.items() if t in heard}
    by_trace, by_stream = {}, {}
    listed = {}  # path -> [requests, cpu ns, longest ns]
    methods = {}
    total = named = unnamed_followed = resets = timed = with_trace = dup_trace = 0
    for line in open(slow_path, errors="replace"):
        if line.startswith("method "):
            m = dict(p.split("=", 1) for p in line.split()[1:])
            path = m.pop("path")
            methods[path] = {k: int(v) for k, v in m.items() if k != "service"}
            continue
        if not line.startswith("req "):
            continue
        head, _, tail = line.rstrip("\n").partition(' line="')
        k = {key: int(value) for key, value in (p.split("=", 1) for p in head.split()[1:])}
        if not k["flags"] & 4:
            continue
        text = dict(p.split("=", 1) for p in tail.partition('" ')[2].split())
        total += 1
        k["path"], k["trace"] = text["path"], text["trace"]
        seen = listed.setdefault(k["path"], [0, 0, 0])
        seen[0] += 1
        seen[1] += k["cpu_ns"] if k["observed_ns"] else 0
        seen[2] = max(seen[2], k["end_ns"] - k["start_ns"])
        resets += bool(k["flags"] & 24)
        timed += k["observed_ns"] > 0
        if k["path"] == "-":
            unnamed_followed += k["observed_ns"] > 0
        else:
            named += 1
        if k["trace"] != "-":
            with_trace += 1
            # A call reported twice: only one of the reports is joined.
            dup_trace += k["trace"] in by_trace
            by_trace[k["trace"]] = k
        by_stream[(k["rport"], k["stream"])] = k

    known = {t for t, *_ in served} | set(given_up)
    trace_wrong = sum(1 for k in by_trace.values() if k["trace"] not in known)
    joined = traced = paths = path_ok = statuses = status_ok = answered = 0
    followed = unit_ok = inside = cpu_ok = 0
    handler_timed = before_ok = after_ok = before_sum = after_sum = 0
    handler_timed_cpu_ok = parts_ok_cpu_ok = late_followed = late_untimed = 0
    leads = []
    cpu_truth = cpu_seen = runq_seen = 0
    timeouts = timeout_ok = 0
    attached = int(os.environ.get("GRPC_ATTACHED_NS", "0"))
    late_calls = late_no_trace = 0
    for trace, path in given_up.items():
        k = by_trace.get(trace)
        if k is None:
            continue
        timeouts += 1
        gone = k["flags"] & 24 or k["grpc_status"] in (1, 4)
        timeout_ok += bool(gone) and k["path"] == path and k["end_ns"] - k["start_ns"] <= 80e6
    for trace, path, status, unit, t0, t1, cpu, port, sid in served:
        k = by_trace.get(trace)
        traced += k is not None
        if k is None and sid:
            k = by_stream.get((port, sid))
            # The same stream, not just the same numbers on another connection.
            if k is not None and not (k["start_ns"] <= t0 and k["trace"] == "-"):
                k = None
        if k is None:
            continue
        joined += 1
        # Begun after attaching: its headers were read after, not just its
        # handler run after (a handler can wait tens of ms for a thread).
        if attached and read_at.get(trace, t0) >= attached:
            late_calls += 1
            late_no_trace += k["trace"] == "-"
        if k["path"] != "-":
            paths += 1
            path_ok += k["path"] == path
        if trace in given_up or k["flags"] & 24:
            # The handler went on after the call was over: its record is of
            # something the request no longer was.
            continue
        answered += 1
        if k["grpc_status"] >= 0:
            statuses += 1
            status_ok += k["grpc_status"] == status
        if k["observed_ns"] == 0:
            continue
        followed += 1
        unit_ok += k["unit_id"] == unit
        inside += k["start_ns"] <= t0 and t1 <= k["end_ns"]
        tol = max(CPU_TOL_NS, cpu // 10)
        cpu_right = k["cpu_ns"] <= cpu + tol and k["cpu_ns"] + k["runq_ns"] >= cpu - tol
        cpu_ok += cpu_right
        cpu_truth += cpu
        cpu_seen += k["cpu_ns"]
        runq_seen += k["runq_ns"]
        # Begun after attaching: its headers were read after, not just its
        # handler run after (a handler can wait tens of ms for a thread).
        if attached and read_at.get(trace, t0) >= attached:
            late_followed += 1
            late_untimed += not k["flags"] & 32
        if k["flags"] & 32:
            handler_timed += 1
            first_ran = k["start_ns"] + k["before_handler_ns"]
            last_left = k["end_ns"] - k["after_handler_ns"]
            before_ok += first_ran <= t0 + CLOCK_TOL_NS
            after_ok += last_left >= t1 - CLOCK_TOL_NS
            # Where the agent missed a switch of the handler, its CPU is off
            # too; those apart, the two parts must hold for every call.
            handler_timed_cpu_ok += cpu_right
            parts_ok_cpu_ok += cpu_right and first_ran <= t0 and last_left >= t1
            before_sum += k["before_handler_ns"]
            after_sum += k["after_handler_ns"]
            leads.append(t0 - first_ran)
    # What happened, by path: answered with status 0, answered otherwise or
    # given up on.
    happened = {}
    for trace, path, status, *_ in served:
        if trace not in given_up:
            ends = happened.setdefault(path, [0, 0])
            ends[status != 0] += 1
    for path in given_up.values():
        happened.setdefault(path, [0, 0])[1] += 1
    m_calls_ok = m_ends_ok = m_listed_ok = 0
    for path, m in methods.items():
        ok, rest = happened.get(path, (0, 0))
        m_calls_ok += m["calls"] == ok + rest
        m_ends_ok += m["ok"] == ok and m["errors"] + m["reset_client"] + m["reset_server"] == rest
        m_listed_ok += [m["calls"], m["cpu_ns"], m["max_ns"]] == listed.get(path)

    print(
        f"grpc served={len(served)} reported={total} named={named} with_trace={with_trace} joined={joined} by_trace={traced}"
        f" paths={paths} path_ok={path_ok} answered={answered} statuses={statuses} status_ok={status_ok}"
        f" trace_wrong={trace_wrong} dup_trace={dup_trace}"
        f" followed={followed} unit_ok={unit_ok}"
        f" inside={inside} cpu_ok_pct={100 * cpu_ok / followed if followed else 0:.2f}"
        f" cpu_err_pct={100 * (cpu_seen - cpu_truth) / cpu_truth if cpu_truth else 0:+.2f}"
        f" runq_pct={100 * runq_seen / cpu_truth if cpu_truth else 0:.2f}"
        f" handler_timed={handler_timed} before_ok={before_ok} after_ok={after_ok}"
        f" timed_cpu_ok={handler_timed_cpu_ok} parts_ok_cpu_ok={parts_ok_cpu_ok}"
        f" late_followed={late_followed} late_untimed={late_untimed}"
        f" before_us={before_sum // max(handler_timed, 1) // 1000} after_us={after_sum // max(handler_timed, 1) // 1000}"
        f" lead_p50_us={pctl(leads, 50) // 1000} lead_p99_us={pctl(leads, 99) // 1000}"
        f" unnamed_followed={unnamed_followed} timed={timed} resets={resets}"
        f" timeouts={timeouts} timeout_ok={timeout_ok} late_calls={late_calls} late_no_trace={late_no_trace}"
        f" m_paths={len(methods)} m_calls_ok={m_calls_ok} m_ends_ok={m_ends_ok} m_listed_ok={m_listed_ok}"
    )


if __name__ == "__main__":
    main()
