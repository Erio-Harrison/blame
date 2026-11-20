#!/usr/bin/env python3
"""Trace ids in HTTP/1.1 requests: a server, a client that sends them in the
ways they arrive, and a check of what `blame slow --raw` reported.

    http_trace.py serve PORT
    http_trace.py client PORT CONNECTIONS > EXPECTED
    http_trace.py check EXPECTED SLOW_LOG
    http_trace.py routes PORT CONNECTIONS > EXPECTED
    http_trace.py check-routes EXPECTED JSON_LOG

The server, one thread per connection, reads each request's head (and a body,
by Content-Length) as it comes and answers it at once. Every request has a path
of its own, /t/<conn>/<n>; the client prints, for each, the trace id the agent
should report, or `-` for none: its traceparent split across sends, in a name
of other case, after blanks, pipelined, after a body's length; and values that
are not a trace id (too short, all zero, not hex, under a longer name).
Prints `trace expected=N with_id=N right=N wrong=N missing=N unexpected=N`.

`routes` sends requests whose routes are known, ids in their paths (digits,
a UUID, 16 hex digits) and not; it prints how many of each route it sent.
`check-routes` compares that with the agent's summary by method (`--json`,
the `total` records): prints `routes expected=N right=N wrong=N missing=N
extra=N`.
"""
import os
import re
import socket
import sys
import threading
import time

HOST = "127.0.0.1"


def serve_conn(s):
    buf = b""
    with s:
        while True:
            while b"\r\n\r\n" not in buf:
                part = s.recv(65536)
                if not part:
                    return
                buf += part
            head, buf = buf.split(b"\r\n\r\n", 1)
            m = re.search(rb"(?i)\r\ncontent-length:\s*(\d+)", head)
            need = int(m.group(1)) if m else 0
            while len(buf) < need:
                part = s.recv(65536)
                if not part:
                    return
                buf += part
            buf = buf[need:]
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")


def serve(port):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((HOST, port))
    ls.listen(128)
    while True:
        s, _ = ls.accept()
        threading.Thread(target=serve_conn, args=(s,), daemon=True).start()


def tid():
    return os.urandom(16).hex()


def tp(trace):
    return f"00-{trace}-{os.urandom(8).hex()}-01"


def read_responses(s, n):
    got = b""
    while got.count(b"HTTP/1.1 200") < n or not got.endswith(b"\r\n\r\n"):
        part = s.recv(65536)
        if not part:
            raise SystemExit("server closed")
        got += part


def client_conn(port, c, out):
    s = socket.create_connection((HOST, port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    n = 0

    def path():
        nonlocal n
        n += 1
        return f"/t/{c}/{n}"

    def one(parts, expect):
        """One request sent in parts, a pause between them; then its answer."""
        for i, part in enumerate(parts):
            if i:
                time.sleep(0.005)
            s.sendall(part)
        read_responses(s, 1)
        out.append(expect)

    for _ in range(3):
        # Plain.
        t, p = tid(), path()
        one([f"GET {p} HTTP/1.1\r\nHost: x\r\ntraceparent: {tp(t)}\r\n\r\n".encode()], (p, t))
        # The line in one send, the headers in another.
        t, p = tid(), path()
        one([f"GET {p} HTTP/1.1\r\n".encode(), f"Host: x\r\ntraceparent: {tp(t)}\r\n\r\n".encode()], (p, t))
        # Split inside the trace id.
        t, p = tid(), path()
        whole = f"GET {p} HTTP/1.1\r\nHost: x\r\ntraceparent: {tp(t)}\r\n\r\n".encode()
        cut = whole.index(t.encode()) + 13
        one([whole[:cut], whole[cut:]], (p, t))
        # Another case of name, blanks before the value.
        t, p = tid(), path()
        one([f"GET {p} HTTP/1.1\r\nHost: x\r\nTraceParent:\t  {tp(t)}\r\n\r\n".encode()], (p, t))
        # A body, its length before the trace.
        t, p = tid(), path()
        one([f"POST {p} HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\ntraceparent: {tp(t)}\r\n\r\nhello".encode()], (p, t))
        # Two requests in one send.
        t1, p1, t2, p2 = tid(), path(), tid(), path()
        s.sendall(f"GET {p1} HTTP/1.1\r\nHost: x\r\ntraceparent: {tp(t1)}\r\n\r\n"
                  f"GET {p2} HTTP/1.1\r\nHost: x\r\ntraceparent: {tp(t2)}\r\n\r\n".encode())
        read_responses(s, 2)
        out += [(p1, t1), (p2, t2)]
        # None, and values that are not one.
        p = path()
        one([f"GET {p} HTTP/1.1\r\nHost: x\r\n\r\n".encode()], (p, "-"))
        for bad in (f"traceparent: 00-{tid()[:31]}-{os.urandom(8).hex()}-01",
                    f"traceparent: 00-{'0' * 32}-{os.urandom(8).hex()}-01",
                    f"traceparent: 00-{tid()[:20]}zz{tid()[:10]}-{os.urandom(8).hex()}-01",
                    f"traceparent-x: {tp(tid())}",
                    f"xtraceparent: {tp(tid())}"):
            p = path()
            one([f"GET {p} HTTP/1.1\r\nHost: x\r\n{bad}\r\n\r\n".encode()], (p, "-"))
    s.close()


def client(port, conns):
    outs = [[] for _ in range(conns)]
    threads = [threading.Thread(target=client_conn, args=(port, c, outs[c])) for c in range(conns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for out in outs:
        for p, t in out:
            print(p, t)


def check(expected_path, slow_path):
    expected = dict(l.split() for l in open(expected_path))
    seen = {}
    for line in open(slow_path, errors="replace"):
        if not line.startswith("req "):
            continue
        m = re.search(r' line="\S+ (\S+)" path=\S+ trace=(\S+)', line)
        if m:
            seen[m.group(1)] = m.group(2)
    with_id = sum(1 for t in expected.values() if t != "-")
    right = sum(1 for p, t in expected.items() if t != "-" and seen.get(p) == t)
    wrong = sum(1 for p, t in expected.items() if p in seen and seen[p] != t and seen[p] != "-")
    missing = sum(1 for p, t in expected.items() if t != "-" and seen.get(p) == "-")
    unexpected = sum(1 for p, t in expected.items() if t == "-" and seen.get(p, "-") != "-")
    unreported = sum(1 for p in expected if p not in seen)
    print(f"trace expected={len(expected)} with_id={with_id} right={right} wrong={wrong} "
          f"missing={missing} unexpected={unexpected} unreported={unreported}")


ROUTES = [
    ("GET /order/{id}", lambda i: f"/order/{i}"),
    ("GET /u/{id}/cart", lambda i: f"/u/{os.urandom(16).hex()[:8]}-{os.urandom(2).hex()}-{os.urandom(2).hex()}-{os.urandom(2).hex()}-{os.urandom(6).hex()}/cart"),
    ("GET /blob/{id}", lambda i: f"/blob/{os.urandom(8).hex()}"),
    ("GET /users/alice", lambda i: "/users/alice"),
    ("POST /order", lambda i: "/order"),
]


def routes_conn(port, c, counts, lock):
    s = socket.create_connection((HOST, port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    for i in range(200):
        route, path = ROUTES[(i + c) % len(ROUTES)]
        method = route.split()[0]
        body = "x" if method == "POST" else ""
        s.sendall(f"{method} {path(i)}?q={i} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n\r\n{body}".encode())
        read_responses(s, 1)
        with lock:
            counts[route] = counts.get(route, 0) + 1
    s.close()


def routes(port, conns):
    counts, lock = {}, threading.Lock()
    threads = [threading.Thread(target=routes_conn, args=(port, c, counts, lock)) for c in range(conns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for route, n in sorted(counts.items()):
        print(f"{n} {route}")


def check_routes(expected_path, json_path):
    import json
    expected = {}
    for line in open(expected_path):
        n, route = line.rstrip("\n").split(" ", 1)
        expected[route] = int(n)
    seen = {}
    for line in open(json_path):
        d = json.loads(line)
        if d.get("type") == "method" and d.get("scope") == "total":
            key = d.get("method") or d.get("method_group")
            seen[key] = seen.get(key, 0) + d["calls"]
    right = sum(1 for r, n in expected.items() if seen.get(r) == n)
    wrong = sum(1 for r, n in expected.items() if r in seen and seen[r] != n)
    missing = sum(1 for r in expected if r not in seen)
    extra = sum(1 for r in seen if r not in expected)
    print(f"routes expected={len(expected)} right={right} wrong={wrong} missing={missing} extra={extra}")


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(int(sys.argv[2]))
    elif sys.argv[1] == "client":
        client(int(sys.argv[2]), int(sys.argv[3]))
    elif sys.argv[1] == "routes":
        routes(int(sys.argv[2]), int(sys.argv[3]))
    elif sys.argv[1] == "check-routes":
        check_routes(sys.argv[2], sys.argv[3])
    else:
        check(sys.argv[2], sys.argv[3])
