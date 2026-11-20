#!/usr/bin/env python3
"""Two small HTTP services for the order demo.

orders:   POST /order -> calls payments, then inserts the order into Postgres.
payments: POST /pay   -> a little CPU work, then waits on a pretend bank call.
"""

import argparse
import http.client
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

local = threading.local()


def calibrate(target_s):
    """Loop count that takes about target_s of CPU on an idle core."""
    n = 10000
    while True:
        t = time.thread_time()
        x = 0
        for i in range(n):
            x += i * i
        dt = time.thread_time() - t
        if dt >= target_s / 2:
            return max(1, int(n * target_s / dt))
        n *= 2


class Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, code, body, timings=None):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if timings:
            # Milliseconds spent in each step, for the load generator's breakdown.
            self.send_header("X-Timings", ",".join(f"{k}={v * 1000:.3f}" for k, v in timings.items()))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""


class Payments(Base):
    work = 20000
    bank_ms = 2.0

    def do_POST(self):
        self.body()
        x = 0
        for i in range(self.work):
            x += i * i
        time.sleep(self.bank_ms / 1000)
        self.reply(200, {"status": "paid"})


class Orders(Base):
    payments = (os.environ.get("PAYMENTS_HOST", "payments"), 8081)
    db = {}

    def conn_payments(self):
        c = getattr(local, "pay", None)
        if c is None:
            c = local.pay = http.client.HTTPConnection(*self.payments, timeout=10)
        return c

    def conn_db(self):
        import psycopg2

        c = getattr(local, "db", None)
        if c is None:
            c = local.db = psycopg2.connect(connect_timeout=10, **self.db)
            c.autocommit = True
        return c

    def do_POST(self):
        t0 = time.perf_counter()
        raw = self.body()
        try:
            order = json.loads(raw or b"{}")
            t_pay = time.perf_counter()
            pay = self.conn_payments()
            pay.request("POST", "/pay", body=raw, headers={"Content-Length": str(len(raw))})
            resp = pay.getresponse()
            resp.read()
            if resp.status != 200:
                return self.reply(502, {"error": "payment failed"})
            t_db = time.perf_counter()
            with self.conn_db().cursor() as cur:
                cur.execute(
                    "INSERT INTO orders (user_id, amount) VALUES (%s, %s)",
                    (order.get("user", 0), order.get("amount", 0)),
                )
            t_end = time.perf_counter()
            self.reply(200, {"status": "ok"}, {
                "handler": t_end - t0, "pay": t_db - t_pay, "db": t_end - t_db,
            })
        except Exception as e:  # reset the per-thread connections and report
            local.pay = local.db = None
            self.reply(500, {"error": str(e)})


def init_db(db):
    import psycopg2

    for _ in range(60):
        try:
            c = psycopg2.connect(connect_timeout=3, **db)
            c.autocommit = True
            c.cursor().execute(
                "CREATE TABLE IF NOT EXISTS orders (id serial PRIMARY KEY, "
                "user_id int, amount int, created timestamptz DEFAULT now())"
            )
            c.close()
            return
        except Exception:
            time.sleep(1)
    raise SystemExit("database never became ready")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["orders", "payments"])
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--procs", type=int, default=1, help="processes sharing the port")
    args = ap.parse_args()
    if args.role == "payments":
        Payments.work = calibrate(0.0005)
        handler = Payments
    else:
        Orders.db = dict(
            host=os.environ["DB_HOST"], user="postgres", password="x", dbname="postgres"
        )
        init_db(Orders.db)
        handler = Orders
    ThreadingHTTPServer.request_queue_size = 256
    ThreadingHTTPServer.allow_reuse_port = True
    for _ in range(args.procs - 1):  # one Python interpreter (and GIL) each
        if os.fork() == 0:
            break
    ThreadingHTTPServer(("0.0.0.0", args.port), handler).serve_forever()


if __name__ == "__main__":
    main()
