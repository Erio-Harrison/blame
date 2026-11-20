#!/usr/bin/env python3
"""Analyse the phases.csv written by p99_study.sh.

Questions and the decision rules, fixed before looking at the data:

  Q1  Does a busy neighbour raise the client p99?
      Paired by round: median of (client p99 of hog4 - client p99 of none),
      95% bootstrap CI over rounds. "Yes" if the CI is above 0.
  Q2  Does the run-queue tail of the shop's services line up with the client
      p99 across all phases?  Spearman rho between client p99 and the share of
      waits >= 1 ms, summed over orders, payments and db. "Explains" needs
      rho >= 0.5 and a 95% bootstrap CI above 0.
  Q3  Does it still line up inside one condition (so it is not just "the
      neighbour was on")?  Same rho after subtracting each condition's median
      from both series. "Explains within conditions" needs the CI above 0.

The p99 printed by `top` is a histogram bucket bound, so the slow share is the
finer signal; the bucket p99 is reported next to it.

When the stall probe ran (per-phase .stalls and .requests files), the same
questions are asked again of the "clean" client p99: the p99 of the requests
whose [scheduled, done] interval overlaps no machine-wide stall the probe saw
(Q1c, Q2c, Q3c, same rules). A stall also lengthens run-queue waits, which
cannot be taken out of the aggregated histograms, so one more check:

  Q4  Inside conditions, does total stall time track the shop's slow-wait
      share?  Spearman rho after subtracting condition medians. A CI above 0
      means the run-queue side is contaminated too, and Q2c/Q3c overstate it.
"""

import bisect
import csv
import os
import random
import statistics
import sys

UNITS = {"us": 1.0, "ms": 1e3, "s": 1e6}


def to_us(text):
    for suffix in ("us", "ms", "s"):
        if text.endswith(suffix) and (suffix != "s" or not text.endswith(("us", "ms"))):
            return float(text[: -len(suffix)]) * UNITS[suffix]
    return 0.0


def cell(text):
    samples, p99, slow = text.split("/")
    return int(samples), to_us(p99), int(slow)


def ranks(values):
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            out[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return out


def spearman(x, y):
    rx, ry = ranks(x), ranks(y)
    mx, my = statistics.fmean(rx), statistics.fmean(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** 0.5
    return num / den if den else float("nan")


def boot_ci(stat, n, reps=5000, rng=None):
    """95% percentile CI of stat(indices) over resamples of range(n)."""
    rng = rng or random.Random(1)
    vals = sorted(stat([rng.randrange(n) for _ in range(n)]) for _ in range(reps))
    vals = [v for v in vals if v == v]
    if not vals:
        return float("nan"), float("nan")
    return vals[int(0.025 * len(vals))], vals[int(0.975 * len(vals))]


def stall_view(prefix):
    """(clean p99 ms, stall ms, share of requests hit) for one phase, or None."""
    if not (os.path.exists(prefix + ".stalls") and os.path.exists(prefix + ".requests")):
        return None
    stalls = []
    for line in open(prefix + ".stalls"):
        _, start, ms = line.split()
        stalls.append((float(start), float(start) + float(ms) / 1e3))
    stalls.sort()
    starts = [a for a, _ in stalls]
    reqs = []
    for line in open(prefix + ".requests"):
        due, lat = map(float, line.split())
        reqs.append((due, due + lat))

    def hit(r):
        # Stalls are short and sorted; check those starting before r ends.
        i = bisect.bisect_left(starts, r[1])
        return any(stalls[j][1] > r[0] for j in range(max(0, i - 50), i))

    flags = [hit(r) for r in reqs]
    clean = sorted(b - a for (a, b), f in zip(reqs, flags) if not f)
    if not clean:
        return None
    p99 = clean[min(len(clean) - 1, int(len(clean) * 0.99))] * 1000
    return p99, sum(b - a for a, b in stalls) * 1000, sum(flags) / len(reqs)


def correlate(rows, conds, xkey, ykey):
    x = [r[xkey] for r in rows]
    y = [r[ykey] for r in rows]
    rho = spearman(x, y)
    lo, hi = boot_ci(lambda idx: spearman([x[i] for i in idx], [y[i] for i in idx]), len(rows))
    med_x = {c: statistics.median(r[xkey] for r in rows if r["cond"] == c) for c in conds}
    med_y = {c: statistics.median(r[ykey] for r in rows if r["cond"] == c) for c in conds}
    dx = [r[xkey] - med_x[r["cond"]] for r in rows]
    dy = [r[ykey] - med_y[r["cond"]] for r in rows]
    wr = spearman(dx, dy)
    wlo, whi = boot_ci(lambda idx: spearman([dx[i] for i in idx], [dy[i] for i in idx]), len(rows))
    return rho, lo, hi, wr, wlo, whi


def paired(rows, key, a="hog4", b="none"):
    by_round = {}
    for r in rows:
        by_round.setdefault(r["round"], {})[r["cond"]] = r
    diffs = [d[a][key] - d[b][key] for d in by_round.values() if a in d and b in d]
    lo, hi = boot_ci(lambda idx: statistics.median(diffs[i] for i in idx), len(diffs))
    return diffs, lo, hi


def main(path):
    rows = list(csv.DictReader(open(path)))
    outdir = os.path.dirname(os.path.abspath(path))
    for r in rows:
        for svc in ("orders", "payments", "db", "batch"):
            r[svc] = cell(r[svc])
        r["p99"] = float(r["p99_ms"])
        shop = [r[s] for s in ("orders", "payments", "db")]
        waits = sum(c[0] for c in shop)
        r["slow_share"] = sum(c[2] for c in shop) / waits if waits else 0.0
        r["orders_share"] = r["orders"][2] / r["orders"][0] if r["orders"][0] else 0.0
        r["orders_p99_us"] = r["orders"][1]
        view = stall_view(os.path.join(outdir, f"r{r['round']}_{r['pos']}_{r['cond']}"))
        if view:
            r["clean_p99"], r["stall_ms"], r["hit_share"] = view
    conds = []
    for r in rows:
        if r["cond"] not in conds:
            conds.append(r["cond"])
    print(f"{len(rows)} phases, {len({r['round'] for r in rows})} rounds, errors={sum(int(r['errors']) for r in rows)}")
    bad = [r for r in rows if r["cond"] == "hog4low" and r["shares_applied"] != "2"]
    print(f"cpu-shares applied in all hog4low phases: {not bad}")

    print("\nper condition (median [min..max] over rounds)")
    print(f"{'cond':8} {'client p99 ms':>22} {'shop slow share':>22} {'orders p99 bucket us':>24}")
    for c in conds:
        sel = [r for r in rows if r["cond"] == c]
        def fmt(key, scale=1.0, digits=1):
            v = [r[key] * scale for r in sel]
            return f"{statistics.median(v):.{digits}f} [{min(v):.{digits}f}..{max(v):.{digits}f}]"
        print(f"{c:8} {fmt('p99'):>22} {fmt('slow_share', 100, 2) + '%':>22} {fmt('orders_p99_us', 1, 0):>24}")

    by_round = {}
    for r in rows:
        by_round.setdefault(r["round"], {})[r["cond"]] = r
    pairs = [(d["hog4"], d["none"]) for d in by_round.values() if "hog4" in d and "none" in d]
    diffs = [a["p99"] - b["p99"] for a, b in pairs]
    lo, hi = boot_ci(lambda idx: statistics.median(diffs[i] for i in idx), len(diffs))
    print(f"\nQ1 hog4 - none, client p99 ms, paired over {len(diffs)} rounds: "
          f"median {statistics.median(diffs):+.2f}, CI [{lo:+.2f}, {hi:+.2f}], "
          f"hog4 higher in {sum(d > 0 for d in diffs)}/{len(diffs)} rounds")

    for label, key in (("shop slow share", "slow_share"), ("orders slow share", "orders_share"),
                       ("orders p99 bucket", "orders_p99_us")):
        x = [r[key] for r in rows]
        y = [r["p99"] for r in rows]
        rho = spearman(x, y)
        lo, hi = boot_ci(lambda idx: spearman([x[i] for i in idx], [y[i] for i in idx]), len(rows))
        med_x = {c: statistics.median(r[key] for r in rows if r["cond"] == c) for c in conds}
        med_y = {c: statistics.median(r["p99"] for r in rows if r["cond"] == c) for c in conds}
        dx = [r[key] - med_x[r["cond"]] for r in rows]
        dy = [r["p99"] - med_y[r["cond"]] for r in rows]
        wr = spearman(dx, dy)
        wlo, whi = boot_ci(lambda idx: spearman([dx[i] for i in idx], [dy[i] for i in idx]), len(rows))
        print(f"{label:20} Q2 pooled rho {rho:+.2f} CI [{lo:+.2f}, {hi:+.2f}]   "
              f"Q3 within-condition rho {wr:+.2f} CI [{wlo:+.2f}, {whi:+.2f}]")

    base = [r for r in rows if r["cond"] == "none"]
    print(f"\nnone condition alone: client p99 spread {min(r['p99'] for r in base):.1f}..{max(r['p99'] for r in base):.1f} ms "
          "(the noise floor any effect has to stand out from)")
    stall_report(rows, conds)


def stall_report(rows, conds):
    rows = [r for r in rows if "clean_p99" in r]
    if not rows:
        return
    print(f"\nwith machine-wide stalls taken out ({len(rows)} phases with probe data)")
    print(f"{'cond':8} {'clean p99 ms':>22} {'raw p99 ms':>14} {'stall ms':>16} {'requests hit':>14}")
    for c in conds:
        sel = [r for r in rows if r["cond"] == c]
        if not sel:
            continue
        def fmt(key, scale=1.0, digits=1):
            v = [r[key] * scale for r in sel]
            return f"{statistics.median(v):.{digits}f} [{min(v):.{digits}f}..{max(v):.{digits}f}]"
        print(f"{c:8} {fmt('clean_p99'):>22} {statistics.median(r['p99'] for r in sel):>14.1f} "
              f"{fmt('stall_ms', 1, 0):>16} {fmt('hit_share', 100, 2) + '%':>14}")
    diffs, lo, hi = paired(rows, "clean_p99")
    if diffs:
        print(f"Q1c hog4 - none, clean p99 ms, paired over {len(diffs)} rounds: "
              f"median {statistics.median(diffs):+.2f}, CI [{lo:+.2f}, {hi:+.2f}], "
              f"hog4 higher in {sum(d > 0 for d in diffs)}/{len(diffs)} rounds")
    for label, key in (("shop slow share", "slow_share"), ("orders slow share", "orders_share")):
        rho, lo, hi, wr, wlo, whi = correlate(rows, conds, key, "clean_p99")
        print(f"{label:20} Q2c pooled rho {rho:+.2f} CI [{lo:+.2f}, {hi:+.2f}]   "
              f"Q3c within-condition rho {wr:+.2f} CI [{wlo:+.2f}, {whi:+.2f}]")
    rho, lo, hi, wr, wlo, whi = correlate(rows, conds, "stall_ms", "slow_share")
    print(f"Q4 stall ms vs shop slow share: within-condition rho {wr:+.2f} CI [{wlo:+.2f}, {whi:+.2f}] "
          f"(pooled {rho:+.2f})")


if __name__ == "__main__":
    main(sys.argv[1])
