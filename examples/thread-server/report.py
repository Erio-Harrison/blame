#!/usr/bin/env python3
"""Tables from runs of the thread-server example (run.sh): what blame said, and
how it compares with what the servers measured themselves.

    examples/thread-server/report.py OUT_DIR SCENARIO...
"""
import collections
import json
import sys


def load(dirname):
    names = dict(l.split()[::-1] for l in open(f"{dirname}/pids"))
    calls, health = [], None
    for line in open(f"{dirname}/blame.json"):
        d = json.loads(line)
        if d.get("type") == "call" and d.get("request") and d.get("time"):
            d["svc"] = names.get(str(d["pid"]), "?")
            d["what"] = d["request"].split(" ")[1]
            calls.append(d)
        elif d.get("type") == "health":
            health = d
    truth = {}
    for svc in ("front", "backend"):
        for line in open(f"{dirname}/{svc}.truth"):
            f = line.split()
            truth[(svc, f[1])] = {k: int(v) for k, v in (p.split("=") for p in f[3:])}
    return calls, truth, health


def parts(d):
    t = d["time"]
    return dict(lat=d["duration_ns"], cpu=t["on_cpu_ns"], runq=t["runq_ns"], disk=t["blocked_disk_ns"],
                mem=t["blocked_memory_ns"], down=t["blocked_downstream_ns"], client=t["blocked_client_ns"],
                other=t["blocked_other_ns"], off=t["off_thread_ns"])


def us(ns):
    return f"{ns / 1000:,.0f}"


def breakdown(calls):
    cols = [("cpu", "CPU"), ("runq", "waiting for CPU"), ("disk", "disk"), ("mem", "memory"),
            ("down", "downstream"), ("other", "other blocked"), ("off", "off thread")]
    groups = collections.defaultdict(list)
    for d in calls:
        groups[(d["svc"], d["what"])].append(d)
    print("| service | request | calls | p50 | p99 | " + " | ".join(c[1] for c in cols) + " |")
    print("|" + "---|" * (5 + len(cols)))
    for (svc, what), ds in sorted(groups.items()):
        lat = sorted(d["duration_ns"] for d in ds)
        s = collections.Counter()
        for d in ds:
            s.update(parts(d))
        n = len(ds)
        print(f"| {svc} | {what} | {n} | {us(lat[n // 2])} | {us(lat[min(n - 1, n * 99 // 100)])} | "
              + " | ".join(us(s[c] / n) for c, _ in cols) + " |")


def compare(calls, truth):
    asleep = lambda t: t["wall"] - t["cpu"] - t["runq"]
    checks = [
        (None, "the thread's CPU time", lambda t: t["cpu"], "CPU", lambda p: p["cpu"]),
        (None, "the thread's wait for a CPU (schedstat)", lambda t: t["runq"], "waiting for CPU", lambda p: p["runq"]),
        ("/lock", "asleep (waiting for the mutex)", asleep, "other blocked", lambda p: p["other"]),
        ("/save", "asleep (write + fsync)", asleep, "disk + other blocked", lambda p: p["disk"] + p["other"]),
        ("/backend", "asleep (the call to the backend)", asleep, "downstream", lambda p: p["down"]),
        ("/sleep", "asleep (nanosleep)", asleep, "other blocked", lambda p: p["other"]),
    ]
    print("| request | the server measured | blame | calls | server mean | blame mean | total diff | calls within 100 us or 10% |")
    print("|---|---|---|---|---|---|---|---|")
    for what, tname, tf, bname, bf in checks:
        pairs = [(tf(truth[(d["svc"], d["trace_id"])]), bf(parts(d))) for d in calls
                 if (what is None or d["what"] == what) and (d["svc"], d.get("trace_id")) in truth]
        if not pairs:
            continue
        T = sum(a for a, _ in pairs)
        B = sum(b for _, b in pairs)
        ok = sum(1 for a, b in pairs if abs(a - b) <= max(100_000, a // 10))
        n = len(pairs)
        print(f"| {what or 'all'} | {tname} | {bname} | {n} | {us(T / n)} | {us(B / n)} | "
              f"{100 * (B - T) / T:+.1f}% | {100 * ok / n:.1f}% |")


def main():
    out = sys.argv[1]
    for scenario in sys.argv[2:]:
        calls, truth, health = load(f"{out}/{scenario}")
        print(f"\n## {scenario}\n\nWhere the time of each request went, mean per call in us:\n")
        breakdown(calls)
        print("\nblame against the servers' own measurements (joined by trace id):\n")
        compare(calls, truth)
        missed = sum(1 for d in calls if d["what"] == "/backend" and not d.get("downstream"))
        print(f"\n/backend calls whose call to the backend blame did not see: {missed}")
        print(f"requests blame reported: {len(calls)}; lost: {health['lost'] if health else '?'}; "
              f"agent: {health['agent'] if health else '?'}")


main()
