#!/usr/bin/env python3
"""Check the output of `blame slow --json` against a gRPC ground-truth run.

    grpc_json_check.py SERVER_LOG JSON_LOG CLIENT_LOG FIELDS_JSON

JSON_LOG is the agent's standard output, FIELDS_JSON what `--json-fields`
printed. Prints one line:

  lines         lines of output
  bad           lines that are not one JSON object with a known `type`
  framed        1 if the first record is `start` and the last a `health` of
                scope `total`
  calls         `call` records
  slowest       1 if those are the slowest requests of the run, slowest
                first, as many as `start.list_max` allows
  slow          `health.calls_slow` of the last record
  m_paths       `method` records of scope `total`
  m_calls_ok    of those, with as many calls as the server answered plus the
                client gave up on
  m_ends_ok     ... and with those split right (status 0; another status or reset)
  followed      1 if a `process` record says HTTP/2 handlers are followed
  lost          entries in the last record's `lost`
  undescribed   fields written that FIELDS_JSON does not describe
"""
import json
import sys


def main():
    server_path, json_path, client_path, fields_path = sys.argv[1:5]
    described = json.load(open(fields_path))["records"]
    records, bad = [], 0
    lines = open(json_path).read().splitlines()
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if not isinstance(record, dict) or record.get("type") not in described:
            bad += 1
            continue
        records.append(record)

    undescribed = set()
    for record in records:
        kind = record["type"]
        for key, value in record.items():
            if key == "type":
                continue
            if key not in described[kind]:
                undescribed.add(f"{kind}.{key}")
            elif key == "time" and isinstance(value, dict):
                undescribed |= {f"{kind}.time.{k}" for k in value if f"time.{k}" not in described[kind]}

    start = records[0] if records else {}
    last = records[-1] if records else {}
    framed = start.get("type") == "start" and last.get("type") == "health" and last.get("scope") == "total"
    calls = [r for r in records if r["type"] == "call"]
    durations = [r["duration_ns"] for r in calls]
    methods = [r for r in records if r["type"] == "method" and r["scope"] == "total"]
    total_calls = sum(m["calls"] for m in methods)
    # The slowest: none of the requests left out took longer than the
    # shortest listed (the summaries know the longest per method).
    slowest = (
        durations == sorted(durations, reverse=True)
        and len(calls) == min(start.get("list_max") or 0, last.get("calls_slow", -1))
        and bool(durations)
        and max(m["max_ns"] for m in methods) == durations[0]
    )

    given_up = dict(l.split()[1:3] for l in open(client_path) if l.startswith("X "))
    # A call given up on before its headers went out was never on the
    # connection: only those the server read the headers of (H lines).
    heard = {l.split()[1] for l in open(server_path) if l.startswith("H ")}
    if heard:
        given_up = {t: p for t, p in given_up.items() if t in heard}
    happened = {}
    for line in open(server_path):
        f = line.split()
        if len(f) == 10 and f[0] == "T" and f[1] not in given_up:
            happened.setdefault(f[2], [0, 0])[int(f[3]) != 0] += 1
    for path in given_up.values():
        happened.setdefault(path, [0, 0])[1] += 1
    m_calls_ok = m_ends_ok = 0
    for m in methods:
        ok, rest = happened.get(m["method"], (0, 0))
        m_calls_ok += m["calls"] == ok + rest
        m_ends_ok += m["ok"] == ok and m["errors"] + m["reset_by_client"] + m["reset_by_server"] == rest

    print(
        f"json lines={len(lines)} bad={bad} framed={int(framed)} calls={len(calls)}"
        f" slowest={int(slowest)} slow={last.get('calls_slow', -1)} total_calls={total_calls}"
        f" m_paths={len(methods)} m_calls_ok={m_calls_ok} m_ends_ok={m_ends_ok}"
        f" followed={int(any(r['type'] == 'process' and r['http2_handlers_followed'] for r in records))}"
        f" lost={len(last.get('lost', {'?': 1}))} undescribed={len(undescribed)}"
        + (f" ({' '.join(sorted(undescribed))})" if undescribed else "")
        + (f" what_was_lost={json.dumps(last['lost'], separators=(',', ':'))}" if last.get("lost") else "")
    )


if __name__ == "__main__":
    main()
