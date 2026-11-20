#!/usr/bin/env python3
"""Open-loop HTTP load: requests are sent on a fixed schedule and each latency
is measured from its scheduled send time, so a slow server cannot slow the
clock down (no coordinated omission).

Prints one JSON line: rps, errors, p50/p99/p99.9 in ms, plus where the time of
the slowest 1% went:
  late     scheduled send time -> request actually sent (the load generator)
  wire     sent -> response, minus the server's own handler time
           (network, accept and thread wake-up on both sides)
  handler  time inside the orders handler, split into pay, db and the rest
and the load generator's own CPU use.
"""

import argparse
import http.client
import itertools
import json
import resource
import threading
import time


def parse_timings(header):
    out = {}
    for part in (header or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = float(v) / 1000
    return out


def cpu_seconds():
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--rate", type=float, default=300)
    ap.add_argument("--duration", type=float, default=20)
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--dump", help="write 'scheduled_time latency' per request (CLOCK_MONOTONIC seconds)")
    args = ap.parse_args()

    counter = itertools.count()
    lock = threading.Lock()
    start = time.perf_counter() + 0.5
    total = int(args.rate * args.duration)
    records, errors = [], [0]
    body = json.dumps({"user": 7, "amount": 100})
    cpu0, wall0 = cpu_seconds(), time.perf_counter()

    def worker():
        conn = http.client.HTTPConnection(args.host, args.port, timeout=10)
        while True:
            with lock:
                i = next(counter)
            if i >= total:
                return
            due = start + i / args.rate
            wait = due - time.perf_counter()
            if wait > 0:
                time.sleep(wait)
            sent = time.perf_counter()
            try:
                conn.request("POST", "/order", body=body, headers={"Content-Type": "application/json"})
                resp = conn.getresponse()
                resp.read()
                ok = resp.status == 200
                timings = parse_timings(resp.getheader("X-Timings"))
            except Exception:
                ok = False
                conn.close()
                conn = http.client.HTTPConnection(args.host, args.port, timeout=10)
            done = time.perf_counter()
            with lock:
                if ok:
                    records.append((done - due, sent - due, done - sent, timings, due))
                else:
                    errors[0] += 1

    threads = [threading.Thread(target=worker) for _ in range(args.workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    cpu_pct = (cpu_seconds() - cpu0) / (time.perf_counter() - wall0) * 100
    records.sort(key=lambda r: r[0])
    lat = [r[0] for r in records]

    def q(p):
        return round(lat[min(len(lat) - 1, int(len(lat) * p))] * 1000, 2) if lat else None

    def mean_ms(rows, f):
        return round(sum(f(r) for r in rows) / len(rows) * 1000, 2) if rows else None

    if args.dump:
        with open(args.dump, "w") as f:
            for r in records:
                f.write(f"{r[4]:.6f} {r[0]:.6f}\n")
    tail = records[int(len(records) * 0.99):]
    h = lambda r, k: r[3].get(k, 0.0)
    print(json.dumps({
        "rps": round(len(lat) / args.duration, 1),
        "errors": errors[0],
        "p50_ms": q(0.50),
        "p99_ms": q(0.99),
        "p999_ms": q(0.999),
        "loadgen_cpu_pct": round(cpu_pct, 1),
        "late_p99_ms": round(sorted(r[1] for r in records)[int(len(records) * 0.99)] * 1000, 2) if records else None,
        "tail_n": len(tail),
        "tail_total_ms": mean_ms(tail, lambda r: r[0]),
        "tail_late_ms": mean_ms(tail, lambda r: r[1]),
        "tail_wire_ms": mean_ms(tail, lambda r: r[2] - h(r, "handler")),
        "tail_pay_ms": mean_ms(tail, lambda r: h(r, "pay")),
        "tail_db_ms": mean_ms(tail, lambda r: h(r, "db")),
        "tail_rest_ms": mean_ms(tail, lambda r: h(r, "handler") - h(r, "pay") - h(r, "db")),
    }))


if __name__ == "__main__":
    main()
