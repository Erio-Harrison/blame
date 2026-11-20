#!/usr/bin/env python3
"""The pay demo's risk service: PyTorch on the CPU, one thread per connection.

    server.py PORT ACCOUNT_HOST:PORT LOG

GET /score asks the account service for the account's features
(GET /features/N, HTTP/1.1, a connection per handling thread), then runs one
forward pass of a small network. PyTorch computes it in parallel: the
handler's thread opens OpenMP regions, and a team of threads of its own
shares the work. `traceparent` is passed on. On SIGTERM the server writes, for
each request:

    T <trace id> GET /score handler_cpu=<ns> features=<ns> features_asleep=<ns> team_cpu=<ns> team_wait=<ns> pass=<ns>

handler_cpu is the handling thread's own CPU from the request read to the
answer about to be written (its thread CPU clock); features is how long the
answer of the account service took, and features_asleep that less what the
kernel counted for the thread on a CPU and waiting for one meanwhile
(/proc/thread-self/schedstat). team_cpu and team_wait are what the kernel
counted for the threads of its team while the forward pass ran
(/proc/self/task/<tid>/schedstat): on a CPU, and waiting for one. A handler's
team is the threads that appear during its first forward pass, which it runs
alone. team_cpu is everything those threads did meanwhile: their work for the
request, and what they spun waiting for the rest of the team or for the next
piece (with OMP_WAIT_POLICY=passive they sleep instead).
"""
import os
import signal
import socket
import sys
import threading
import time

import torch

# The address to listen on: a port (on 127.0.0.1), or host:port.
listen_host, _, port = sys.argv[1].rpartition(":")
port, account, log_path = int(port), sys.argv[2], sys.argv[3]
account_host, account_port = account.rsplit(":", 1)

model = torch.nn.Sequential(
    torch.nn.Linear(256, 1024), torch.nn.ReLU(),
    torch.nn.Linear(1024, 1024), torch.nn.ReLU(),
    torch.nn.Linear(1024, 1),
).eval()
x = torch.randn(32, 256)


def forward():
    with torch.no_grad():
        model(x)


def tids():
    return {int(t) for t in os.listdir("/proc/self/task")}


def schedstat(tid):
    try:
        with open(f"/proc/{tid}/schedstat" if tid == "thread-self" else f"/proc/self/task/{tid}/schedstat") as f:
            cpu, wait, _ = f.read().split()
        return int(cpu), int(wait)
    except OSError:
        return 0, 0


first = threading.Lock()
log_lock = threading.Lock()
lines = []
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"risk\":0.02}"


def header(head, wanted):
    for line in head.split(b"\r\n"):
        name, _, value = line.partition(b":")
        if name.strip().lower() == wanted:
            return value.strip()
    return b""


def trace_id(traceparent):
    parts = traceparent.split(b"-")
    return parts[1].decode() if len(parts) == 4 else "-"


def features(conn, traceparent):
    """One GET /features on the handler's connection to the account service."""
    conn.sendall(b"GET /features/1 HTTP/1.1\r\nHost: account\r\ntraceparent: " + traceparent + b"\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += conn.recv(4096)
    head, body = buf.split(b"\r\n\r\n", 1)
    length = int(header(head, b"content-length") or 0)
    while len(body) < length:
        body += conn.recv(4096)


def handle(conn):
    team = None
    buf = b""
    upstream = socket.create_connection((account_host, int(account_port)))
    upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
            head, buf = buf.split(b"\r\n\r\n", 1)
            h0 = time.thread_time_ns()
            if team is None:
                # Alone, so that the threads that appear are this handler's.
                with first:
                    before = tids()
                    forward()
                    team = sorted(tids() - before)
                h0 = time.thread_time_ns()
            traceparent = header(head, b"traceparent")
            o0 = schedstat("thread-self")
            f0 = time.monotonic_ns()
            features(upstream, traceparent)
            f1 = time.monotonic_ns()
            o1 = schedstat("thread-self")
            asleep = max(0, f1 - f0 - (o1[0] - o0[0]) - (o1[1] - o0[1]))
            s0 = [schedstat(t) for t in team]
            t0 = time.monotonic_ns()
            forward()
            t1 = time.monotonic_ns()
            s1 = [schedstat(t) for t in team]
            d = [(b[0] - a[0], b[1] - a[1]) for a, b in zip(s0, s1)]
            line = "T %s GET /score handler_cpu=%%d features=%d features_asleep=%d team_cpu=%d team_wait=%d pass=%d" % (
                trace_id(traceparent), f1 - f0, asleep, sum(c for c, _ in d), sum(w for _, w in d), t1 - t0)
            with log_lock:
                lines.append(line % (time.thread_time_ns() - h0))
            conn.sendall(RESPONSE)
    finally:
        conn.close()
        upstream.close()


def stop(*_):
    with log_lock:
        with open(log_path, "w") as f:
            f.write("\n".join(lines) + "\n")
    os._exit(0)


signal.signal(signal.SIGTERM, stop)
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((listen_host or "127.0.0.1", port))
listener.listen(64)
print("ready", os.getpid(), torch.__version__, flush=True)
while True:
    c, _ = listener.accept()
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    threading.Thread(target=handle, args=(c,), daemon=True).start()
