#!/usr/bin/env python3
"""Tables from runs of the PyTorch inference example (run.sh): what blame said
of each request, and how it compares with what the server measured itself.

    examples/torch-inference/report.py OUT_DIR SCENARIO...
"""
import json
import sys


def load(dirname):
    calls, note, health = {}, None, None
    for line in open(f"{dirname}/blame.json"):
        d = json.loads(line)
        if d.get("type") == "call" and d.get("trace_id") and d.get("time"):
            calls[d["trace_id"]] = d
        elif d.get("type") == "process":
            note = d.get("note")
        elif d.get("type") == "health":
            health = d
    truth = {}
    for line in open(f"{dirname}/server.truth"):
        f = line.split()
        if f and f[0] == "T":
            truth[f[1]] = {k: int(v) for k, v in (p.split("=") for p in f[2:])}
    return calls, truth, note, health


def ms(ns):
    return f"{ns / 1e6:.2f}"


def main():
    out = sys.argv[1]
    for scenario in sys.argv[2:]:
        calls, truth, note, health = load(f"{out}/{scenario}")
        # The first requests run before the regions' functions have probes.
        pairs = [(truth[t], c) for t, c in calls.items() if t in truth]
        pairs = pairs[len(pairs) // 5:]
        n = len(pairs)
        print(f"\n## {scenario}\n")
        print(f"blame, of the server: {note}\n")
        if not n:
            print("no request of the server's was reported")
            continue

        def mean(f):
            return sum(f(t, c) for t, c in pairs) / n

        team = lambda c: c.get("spawned") or {}
        print(f"What blame said of a request ({n} of them, mean):\n")
        print("| | ms |")
        print("|---|---|")
        print(f"| took | {ms(mean(lambda t, c: c['duration_ns']))} |")
        print(f"| its thread: on a CPU | {ms(mean(lambda t, c: c['time']['on_cpu_ns']))} |")
        print(f"| its thread: waiting for a CPU | {ms(mean(lambda t, c: c['time']['runq_ns']))} |")
        print(f"| its thread: asleep (other) | {ms(mean(lambda t, c: c['time']['blocked_other_ns']))} |")
        print(f"| its team: pieces of work taken up | {mean(lambda t, c: team(c).get('count', 0)):.1f} |")
        print(f"| its team: on a CPU | {ms(mean(lambda t, c: team(c).get('on_cpu_ns', 0)))} |")
        print(f"| its team: waiting for a CPU | {ms(mean(lambda t, c: team(c).get('runq_ns', 0)))} |")
        print("\nblame against the server's own figures (joined by trace id):\n")
        print("| | the server | blame | diff | requests within 100 us or 10% |")
        print("|---|---|---|---|---|")
        for name, tf, bf in (
            ("the handler's thread on a CPU", lambda t: t["handler_cpu"], lambda c: c["time"]["on_cpu_ns"]),
            ("its team on a CPU", lambda t: t["team_cpu"], lambda c: team(c).get("on_cpu_ns", 0)),
        ):
            T = sum(tf(t) for t, _ in pairs)
            B = sum(bf(c) for _, c in pairs)
            ok = sum(1 for t, c in pairs if abs(tf(t) - bf(c)) <= max(100_000, tf(t) // 10))
            print(f"| {name} | {ms(T / n)} | {ms(B / n)} | {100 * (B - T) / max(T, 1):+.1f}% | {100 * ok / n:.0f}% |")
        print(f"| its team waiting for a CPU | {ms(mean(lambda t, c: t['team_wait']))} | {ms(mean(lambda t, c: team(c).get('runq_ns', 0)))} | | |")
        # Over the whole run: what the teams' threads used outside their pieces of work.
        idle = (health or {}).get("openmp_team_idle_cpu_ns") or 0
        finished = (health or {}).get("requests", {}).get("finished") or 1
        left = mean(lambda t, c: t["team_cpu"] - team(c).get("on_cpu_ns", 0))
        print(f"\nThe teams' threads outside their pieces of work, which is no request's: "
              f"{ms(idle / finished)} ms a request by blame ({idle / 1e9:.2f} s over {finished} requests); "
              f"the server's team figure less blame's is {ms(left)} ms a request.")
        lost = (health or {}).get("lost")
        print(f"\nrequests: {n}; what blame says it lost: {lost if lost is not None else '?'}")


main()
