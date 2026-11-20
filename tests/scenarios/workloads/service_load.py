#!/usr/bin/env python3
"""A small request/response service workload for the scenario scripts.

Servers wait ~1 ms on a simulated downstream; open-loop clients send at a fixed
rate and time each request from its intended send time (no coordinated
omission). Servers and clients can be pinned to disjoint CPUs.

Prints one JSON line: {"rps", "p50_ms", "p99_ms", "errors"}. Only touches
processes it created.
"""

import argparse
import asyncio
import gc
import json
import multiprocessing as mp
import os
import signal
import socket
import sys
import time

REQUEST = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


def pin(cpus):
    if cpus:
        os.sched_setaffinity(0, parse_cpus(cpus))


def parse_cpus(spec):
    out = set()
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            out.update(range(int(lo), int(hi) + 1))
        else:
            out.add(int(part))
    return out


# --- server -----------------------------------------------------------------


def server_main(port, delay_s, work_s, cpus):
    pin(cpus)
    gc.disable()
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))

    async def handle(reader, writer):
        try:
            while True:
                await reader.readuntil(b"\r\n\r\n")
                await asyncio.sleep(delay_s)
                if work_s:
                    # Computing: what a neighbour on the same CPUs takes away.
                    end = time.perf_counter() + work_s
                    while time.perf_counter() < end:
                        pass
                writer.write(RESPONSE)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    async def main():
        server = await asyncio.start_server(
            handle, "127.0.0.1", port, reuse_port=True, backlog=1024
        )
        async with server:
            await server.serve_forever()

    asyncio.run(main())


# --- client -----------------------------------------------------------------


def client_main(port, conns, rate, duration, warmup, cpus, conn):
    pin(cpus)
    gc.disable()
    period = conns / rate  # seconds between requests on one connection
    latencies = []
    errors = 0

    async def one(i):
        nonlocal errors
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        t0 = time.monotonic()
        end = t0 + duration
        next_t = t0 + (i / conns) * period
        while next_t < end:
            delay = next_t - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            intended = next_t
            next_t += period
            try:
                writer.write(REQUEST)
                await writer.drain()
                await reader.readuntil(b"ok")
            except (asyncio.IncompleteReadError, ConnectionError):
                errors += 1
                break
            if intended - t0 >= warmup:
                latencies.append(time.monotonic() - intended)
        writer.close()

    async def main():
        await asyncio.gather(*(one(i) for i in range(conns)))

    asyncio.run(main())
    conn.send((latencies, errors))
    conn.close()


# --- driver -----------------------------------------------------------------


def wait_ready(port, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def percentile(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    return sorted_vals[min(len(sorted_vals) - 1, int(len(sorted_vals) * p))]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=18090)
    ap.add_argument("--servers", type=int, default=2)
    ap.add_argument("--clients", type=int, default=2)
    ap.add_argument("--server-cpus", default="")
    ap.add_argument("--client-cpus", default="")
    ap.add_argument("--conns", type=int, default=32, help="total connections")
    ap.add_argument("--rate", type=float, default=6000, help="total requests/s")
    ap.add_argument("--duration", type=float, default=15)
    ap.add_argument("--warmup", type=float, default=2)
    ap.add_argument("--delay-ms", type=float, default=1.0)
    ap.add_argument("--work-ms", type=float, default=0.0, help="CPU each request burns")
    args = ap.parse_args()

    servers = []
    clients = []
    # Make SIGTERM run `finally`, or the server processes are orphaned.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        for _ in range(args.servers):
            p = mp.Process(
                target=server_main,
                args=(args.port, args.delay_ms / 1000, args.work_ms / 1000, args.server_cpus),
            )
            p.start()
            servers.append(p)
        if not wait_ready(args.port):
            print(json.dumps({"error": "server did not start"}))
            return 1

        per_conns = max(1, args.conns // args.clients)
        per_rate = args.rate / args.clients
        pipes = []
        for _ in range(args.clients):
            parent, child = mp.Pipe(duplex=False)
            p = mp.Process(
                target=client_main,
                args=(args.port, per_conns, per_rate, args.duration,
                      args.warmup, args.client_cpus, child),
            )
            p.start()
            clients.append(p)
            pipes.append(parent)

        all_lat, errors = [], 0
        for parent in pipes:
            lat, err = parent.recv()
            all_lat.extend(lat)
            errors += err
        for p in clients:
            p.join(timeout=5)

        all_lat.sort()
        measured = args.duration - args.warmup
        print(json.dumps({
            "rps": round(len(all_lat) / measured) if measured > 0 else 0,
            "p50_ms": round(percentile(all_lat, 0.50) * 1000, 3),
            "p99_ms": round(percentile(all_lat, 0.99) * 1000, 3),
            "errors": errors,
        }))
        return 0
    finally:
        for p in clients + servers:
            if p.is_alive():
                p.terminate()
        for p in clients + servers:
            p.join(timeout=2)
            if p.is_alive():
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
