#!/usr/bin/env python3
"""Tables from runs of the pay demo (run.sh): what blame said, and how it compares
with what the services measured themselves.

    examples/pay-demo/report.py OUT_DIR SCENARIO...
"""
import collections
import json
import re
import sys

WHY = ["runnable", "channel", "sync", "sleep", "network", "gc", "other", "task", "blocking"]


def load(dirname):
    names = dict(l.split()[::-1] for l in open(f"{dirname}/pids"))
    calls, health, waited = [], None, []
    for line in open(f"{dirname}/blame.json"):
        d = json.loads(line)
        if d.get("type") == "call":
            d["svc"] = names.get(str(d["pid"]), "?")
            if d.get("method"):
                d["what"] = d["method"].split("/")[-1]
            elif d.get("request"):
                d["what"] = re.sub(r"/\d+", "/{id}", d["request"])
            else:
                d["what"] = None
            calls.append(d)
        elif d.get("type") == "health":
            health = d
        elif d.get("type") == "process_cpu" and d.get("scope") == "total":
            waited.append((names.get(str(d["pid"]), "?"), d))
    truth = {}
    for svc in ("gateway", "payment", "account", "ledger", "risk"):
        try:
            lines = open(f"{dirname}/{svc}.truth").readlines()
        except FileNotFoundError:
            continue
        for line in lines:
            f = line.split()
            # T <trace id> <request, possibly with spaces> <name>=<ns>...
            k = next(i for i, x in enumerate(f) if "=" in x)
            truth[(svc, f[1], " ".join(f[2:k]))] = {a: int(b) for a, b in (p.split("=") for p in f[k:])}
    return calls, truth, health, waited


def parts(d):
    t = d["time"]
    why = t.get("off_thread_by_why") or {}
    p = dict(lat=d["duration_ns"], cpu=t["on_cpu_ns"], runq=t["runq_ns"], disk=t["blocked_disk_ns"],
             down=t["blocked_downstream_ns"],
             fsvc=t["blocked_file_service_ns"], mem=t["blocked_memory_ns"], oblk=t["blocked_other_ns"],
             hand=t.get("before_handler_ns", 0) + t.get("after_handler_ns", 0), off=t["off_thread_ns"])
    for k in WHY:
        p[k] = why.get(k + "_ns", 0)
    h = d.get("spawned") or {}
    p["spawned"] = h.get("count", 0)
    p["sp_cpu"] = h.get("on_cpu_ns", 0)
    p["sp_runq"] = h.get("runq_ns", 0)
    p["sp_disk"] = h.get("blocked_disk_ns", 0)
    # tokio does not say why a task waits: its time off a thread is "waiting", reason not known.
    p["unknown"] = p["off"] - sum(why.values()) - p["hand"] if why or "before_handler_ns" in t else p["off"]
    return p


def us(ns):
    return f"{ns / 1000:,.0f}"


def pct(sorted_values, q):
    return sorted_values[min(len(sorted_values) - 1, len(sorted_values) * q // 100)]


def breakdown(calls):
    cols = [("cpu", "CPU"), ("runq", "waiting for CPU"), ("down", "downstream"), ("disk", "disk"), ("fsvc", "NFS"),
            ("mem", "memory"), ("oblk", "other blocked"), ("hand", "library before/after handler"),
            ("channel", "waiting: channel"), ("sync", "waiting: lock"), ("sleep", "waiting: sleep"),
            ("network", "waiting: network"), ("task", "waiting: another task"), ("blocking", "waiting: blocking pool"),
            ("other", "waiting: other"), ("runnable", "waiting to be run"), ("unknown", "waiting, reason not known"),
            ("spawned", "helpers"), ("sp_cpu", "helpers: CPU"), ("sp_runq", "helpers: waiting for CPU"),
            ("sp_disk", "helpers: disk")]
    groups = collections.defaultdict(list)
    for d in calls:
        if d["what"] and d.get("time"):
            groups[(d["svc"], d["what"])].append(d)
    order = {"gateway": 0, "payment": 1, "account": 2, "risk": 3, "ledger": 4}
    print("| service | request | calls | p50 | p99 | " + " | ".join(c[1] for c in cols) + " |")
    print("|" + "---|" * (5 + len(cols)))
    for (svc, what), ds in sorted(groups.items(), key=lambda x: (order.get(x[0][0], 9), x[0][1])):
        lat = sorted(d["duration_ns"] for d in ds)
        s = collections.Counter()
        for d in ds:
            for k, v in parts(d).items():
                s[k] += v
        n = len(ds)
        print(f"| {svc} | {what} | {n} | {us(pct(lat, 50))} | {us(pct(lat, 99))} | "
              + " | ".join(f"{s[c] / n:.2f}" if c == "spawned" else us(s[c] / n) for c, _ in cols) + " |")


def follow(calls, q):
    """The Charge at the q-th percentile, and the calls with its trace id elsewhere."""
    orders = sorted((d for d in calls if d["svc"] == "payment" and d["what"] == "Charge"
                     and d.get("time") and d.get("trace_id")), key=lambda d: d["duration_ns"])
    if not orders:
        return
    pick = pct(orders, q)
    same = [d for d in calls if d.get("trace_id") == pick["trace_id"]]
    print(f"trace id {pick['trace_id']} (the Charge at p{q}):\n")
    print("| service | request | took | CPU | waiting for CPU | downstream | disk | NFS | memory | other blocked | library before/after | waiting: channel | waiting: lock | waiting: sleep | waiting: network | waiting: another task | waiting: blocking pool | waiting to be run | waiting, reason not known | helpers | helpers: CPU | helpers: waiting for CPU | helpers: disk |")
    print("|" + "---|" * 23)
    for d in sorted(same, key=lambda d: -d["duration_ns"]):
        p = parts(d)
        print(f"| {d['svc']} | {d['what']} | {us(p['lat'])} | {us(p['cpu'])} | {us(p['runq'])} | {us(p['down'])} | {us(p['disk'])} | {us(p['fsvc'])} | {us(p['mem'])} | "
              f"{us(p['oblk'])} | {us(p['hand'])} | {us(p['channel'])} | {us(p['sync'])} | {us(p['sleep'])} | "
              f"{us(p['network'])} | {us(p['task'])} | {us(p['blocking'])} | {us(p['runnable'])} | {us(p['unknown'])} | "
              f"{p['spawned']} | {us(p['sp_cpu'])} | {us(p['sp_runq'])} | {us(p['sp_disk'])} |")


def compare(calls, truth):
    """blame against what the services measured, where the two say the same thing."""
    checks = [
        ("account", "Balance", "computing", lambda t: t["compute"], "CPU + waiting for CPU",
         lambda p: p["cpu"] + p["runq"]),
        ("account", "Debit", "waiting for the balances' lock", lambda t: t["lock"],
         "waiting: lock", lambda p: p["sync"]),
        ("account", "Debit", "lock, computing and the statement", lambda t: t["lock"] + t["compute"] + t["statement"],
         "everything but the library before/after", lambda p: p["lat"] - p["hand"]),
        ("payment", "Charge", "the debit and the score, then the entry", lambda t: t["checks"] + t["ledger"],
         "waiting: lock (sync.WaitGroup) + channel (the gRPC client's)", lambda p: p["sync"] + p["channel"]),
        ("ledger", "Append", "the database transaction", lambda t: t["db"],
         "everything but the library before/after", lambda p: p["lat"] - p["hand"]),
        ("gateway", "POST /pay", "the audit write (tokio::fs)", lambda t: t["audit"],
         "waiting: blocking pool + waiting to be run", lambda p: p["blocking"] + p["runnable"]),
        ("risk", "GET /score", "its thread's CPU", lambda t: t["handler_cpu"], "CPU", lambda p: p["cpu"]),
        ("risk", "GET /score", "asleep until account answered with the features", lambda t: t["features_asleep"],
         "downstream", lambda p: p["down"]),
        ("risk", "GET /score", "its team's CPU (all of it, idle spinning too)", lambda t: t["team_cpu"],
         "helpers: CPU", lambda p: p["sp_cpu"]),
    ]
    print("| service | request | the service measured | blame | calls | service mean | blame mean | total diff | calls within 100 us or 10% |")
    print("|---|---|---|---|---|---|---|---|---|")
    for svc, what, tname, tf, bname, bf in checks:
        pairs = [(tf(truth[(svc, d["trace_id"], what)]), bf(parts(d))) for d in calls
                 if d["svc"] == svc and d["what"] == what and d.get("time") and (svc, d.get("trace_id"), what) in truth]
        pairs = [(a, b) for a, b in pairs if a is not None]
        if not pairs or not sum(a for a, _ in pairs):
            continue
        T = sum(a for a, _ in pairs)
        B = sum(b for _, b in pairs)
        ok = sum(1 for a, b in pairs if abs(a - b) <= max(100_000, a // 10))
        print(f"| {svc} | {what} | {tname} | {bname} | {len(pairs)} | {us(T / len(pairs))} | {us(B / len(pairs))} | "
              f"{100 * (B - T) / T:+.1f}% | {100 * ok / len(pairs):.1f}% |")


def main():
    out = sys.argv[1]
    for scenario in sys.argv[2:]:
        calls, truth, health, waited = load(f"{out}/{scenario}")
        print(f"\n## {scenario}\n\nWhere the time of each request went, mean per call in us:\n")
        breakdown(calls)
        print()
        follow(calls, 50)
        print()
        follow(calls, 99)
        print("\nblame against the services' own measurements (joined by trace id):\n")
        compare(calls, truth)
        scores = [d for d in calls if d["svc"] == "risk" and d.get("time") and ("risk", d.get("trace_id"), "GET /score") in truth]
        if scores and health:
            idle = health.get("openmp_team_idle_cpu_ns") or 0
            left = sum(truth[("risk", d["trace_id"], "GET /score")]["team_cpu"] - parts(d)["sp_cpu"] for d in scores)
            print(f"\nrisk's teams outside their pieces of work, which is no request's: {us(idle / len(scores))} us a request "
                  f"by blame; the service's team figure less blame's is {us(left / len(scores))} us a request.")
        if waited:
            print("\nWhat each process's threads waited for a CPU, in ms per second, by what the CPU did meanwhile:\n")
            print("| service | its own threads had it | a CPU limit kept them off | others had it | it was idle |\n|---|---|---|---|---|")
            for svc, d in waited:
                per_s = lambda ns: "-" if ns is None else f"{ns * 1000 / d['over_ns']:.0f}"
                print(f"| {svc} | {per_s(d['runq_own_threads_ns'])} | {per_s(d['runq_cpu_limit_ns'])} | "
                      f"{per_s(d['runq_others_ns'])} | {per_s(d['runq_cpu_idle_ns'])} |")
        unnamed = sum(1 for d in calls if not d["what"])
        print(f"\nrequests blame reported: {len(calls)} (without a name, begun before it attached: {unnamed}); "
              f"lost: {health['lost'] if health else '?'}; agent: {health['agent'] if health else '?'}")


main()
