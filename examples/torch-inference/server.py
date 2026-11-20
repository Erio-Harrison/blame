#!/usr/bin/env python3
"""A PyTorch inference server, one thread per connection, that says what each
request cost: its own thread and the threads of the OpenMP team that computed
with it.

    server.py PORT LOG

GET /infer runs one forward pass of a small network (batch 64) on the CPU.
PyTorch computes it in parallel: the handler's thread opens OpenMP regions,
and a team of threads of its own shares the work. On SIGTERM the server
writes, for each request:

    T <trace id> handler_cpu=<ns> team_cpu=<ns> team_wait=<ns> pass=<ns>

handler_cpu is the handling thread's own CPU from the request read to the
answer about to be written (its thread CPU clock). team_cpu and team_wait are
what the kernel counted for the threads of its team while the forward pass
ran (/proc/self/task/<tid>/schedstat): on a CPU, and waiting for one. A
handler's team is the threads that appear during its first forward pass,
which it runs alone. team_cpu is everything those threads did meanwhile:
their work for the request, and what they spun waiting for the rest of the
team or for the next piece (with OMP_WAIT_POLICY=passive they sleep instead).
"""
import os
import signal
import socket
import sys
import threading
import time

import torch

port, log_path = int(sys.argv[1]), sys.argv[2]

model = torch.nn.Sequential(
    torch.nn.Linear(1024, 2048), torch.nn.ReLU(),
    torch.nn.Linear(2048, 2048), torch.nn.ReLU(),
    torch.nn.Linear(2048, 1024),
).eval()
x = torch.randn(64, 1024)


def forward():
    with torch.no_grad():
        model(x)


def tids():
    return {int(t) for t in os.listdir("/proc/self/task")}


def schedstat(tid):
    try:
        with open(f"/proc/self/task/{tid}/schedstat") as f:
            cpu, wait, _ = f.read().split()
        return int(cpu), int(wait)
    except OSError:
        return 0, 0


first = threading.Lock()
log_lock = threading.Lock()
lines = []
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


def trace_id(head):
    for line in head.split(b"\r\n"):
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"traceparent":
            parts = value.strip().split(b"-")
            if len(parts) == 4:
                return parts[1].decode()
    return "-"


def handle(conn):
    team = None
    buf = b""
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
            s0 = [schedstat(t) for t in team]
            t0 = time.monotonic_ns()
            forward()
            t1 = time.monotonic_ns()
            s1 = [schedstat(t) for t in team]
            d = [(b[0] - a[0], b[1] - a[1]) for a, b in zip(s0, s1)]
            line = "T %s handler_cpu=%%d team_cpu=%d team_wait=%d pass=%d" % (
                trace_id(head), sum(c for c, _ in d), sum(w for _, w in d), t1 - t0)
            with log_lock:
                lines.append(line % (time.thread_time_ns() - h0))
            conn.sendall(RESPONSE)
    finally:
        conn.close()


def stop(*_):
    with log_lock:
        with open(log_path, "w") as f:
            f.write("\n".join(lines) + "\n")
    os._exit(0)


signal.signal(signal.SIGTERM, stop)
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", port))
listener.listen(64)
print("ready", os.getpid(), torch.__version__, flush=True)
while True:
    c, _ = listener.accept()
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    threading.Thread(target=handle, args=(c,), daemon=True).start()
