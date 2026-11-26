#!/usr/bin/env python3
"""What `blame slow --json --tls` said of tls_http.py's requests.

    tls_check.py BLAME_JSON

Prints `calls= tls= early= asleep_short= lost=`: requests reported, those
flagged as over TLS, those that started in the first second after the first
one, those whose 20 ms sleep blame did not see as a sleep (less than 15 ms of
`blocked_other`), and what the agent counted as lost in all.
"""
import datetime
import json
import sys


def at(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


calls = []
lost = 0
for line in open(sys.argv[1]):
    try:
        d = json.loads(line)
    except ValueError:
        continue
    if d.get("type") == "call" and d.get("request") == "GET /sleep" and d.get("time"):
        calls.append(d)
    elif d.get("type") == "health" and d.get("scope") == "total":
        lost = sum(d.get("lost", {}).values())
first = min((at(d["start"]) for d in calls), default=0)
short = sum(1 for d in calls if d["time"]["blocked_other_ns"] < 15_000_000)
print(f"calls={len(calls)} tls={sum(1 for d in calls if d.get('tls'))} "
      f"early={sum(1 for d in calls if at(d['start']) - first < 1)} asleep_short={short} lost={lost}")
