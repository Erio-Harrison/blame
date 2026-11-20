#!/usr/bin/env python3
"""HTTP/1.1 client that exercises one way of using a connection.

    http_client.py PORT SCENARIO [REQUESTS] [CONNECTIONS]

Scenarios: keepalive bigbody chunked slow expect100 head close abort pipeline
pipe32 pipehead bighdr down mix mixlong. Prints a summary line; what the server did
with the requests is in the server's own log (tests/tools/http_truth.c).
"""
import random
import socket
import sys
import threading
import time

PORT = int(sys.argv[1])
SCEN = sys.argv[2]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 200
CONC = int(sys.argv[4]) if len(sys.argv) > 4 else 4
HOST = "127.0.0.1"


def connect():
    s = socket.create_connection((HOST, PORT))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


class Reader:
    def __init__(self, s):
        self.s = s
        self.buf = b""

    def fill(self):
        d = self.s.recv(65536)
        if not d:
            raise EOFError
        self.buf += d

    def line(self):
        while b"\r\n" not in self.buf:
            self.fill()
        l, self.buf = self.buf.split(b"\r\n", 1)
        return l

    def exact(self, n):
        while len(self.buf) < n:
            self.fill()
        d, self.buf = self.buf[:n], self.buf[n:]
        return d

    def response(self, head=False):
        """Reads one final response (skips 1xx). Returns status."""
        while True:
            st = int(self.line().split()[1])
            hdrs = {}
            while True:
                l = self.line()
                if not l:
                    break
                k, v = l.split(b":", 1)
                hdrs[k.strip().lower()] = v.strip()
            if 100 <= st < 200:
                continue
            break
        if head or st in (204, 304):
            return st
        if hdrs.get(b"transfer-encoding") == b"chunked":
            while True:
                sz = int(self.line().split(b";")[0], 16)
                if sz == 0:
                    self.line()
                    break
                self.exact(sz + 2)
        else:
            self.exact(int(hdrs.get(b"content-length", b"0")))
        return st


def req(path, method="GET", extra="", body=b""):
    h = f"{method} {path} HTTP/1.1\r\nHost: t\r\nUser-Agent: scen\r\n{extra}"
    if body:
        h += f"Content-Length: {len(body)}\r\n"
    return (h + "\r\n").encode() + body


done = [0]
lock = threading.Lock()


def count(n=1):
    with lock:
        done[0] += n


def worker(i, n):
    rnd = random.Random(i)
    s = connect()
    r = Reader(s)
    k = 0
    while k < n:
        if SCEN == "keepalive":
            s.sendall(req(f"/k?size={rnd.choice([0, 10, 100, 1000, 20000])}"))
            r.response(); k += 1
        elif SCEN == "bigbody":
            body = b"y" * rnd.choice([10000, 100000, 400000])
            data = req(f"/b?size={rnd.choice([100000, 500000])}&wchunk=8192", "POST", body=body)
            for off in range(0, len(data), 16384):
                s.sendall(data[off:off + 16384])
            r.response(); k += 1
        elif SCEN == "chunked":
            s.sendall(req(f"/c?chunked=1&size={rnd.choice([100, 5000, 60000])}&wchunk=4096"))
            r.response(); k += 1
        elif SCEN == "slow":
            data = req("/s?size=200", "POST", body=b"z" * 3000)
            cuts = sorted(rnd.sample(range(1, len(data)), 4))
            prev = 0
            for c in cuts + [len(data)]:
                s.sendall(data[prev:c]); prev = c
                time.sleep(rnd.uniform(0.002, 0.02))
            r.response(); k += 1
        elif SCEN == "expect100":
            body = b"e" * 5000
            s.sendall(req("/e?size=300", "POST", "Expect: 100-continue\r\n", b"")[:-2] +
                      f"Content-Length: {len(body)}\r\n\r\n".encode())
            # wait for the interim response before sending the body
            l = r.line()
            assert b"100" in l, l
            r.line()
            s.sendall(body)
            r.response(); k += 1
        elif SCEN == "head":
            ch = rnd.choice(["HEAD", "GET204", "GET304", "GET"])
            if ch == "HEAD":
                s.sendall(req("/h?size=5000", "HEAD")); r.response(head=True)
            elif ch == "GET204":
                s.sendall(req("/h?status=204")); r.response()
            elif ch == "GET304":
                s.sendall(req("/h?status=304")); r.response()
            else:
                s.sendall(req("/h?size=500")); r.response()
            k += 1
        elif SCEN == "close":
            # a few keep-alive requests, then Connection: close
            m = rnd.randint(1, 4)
            for j in range(m):
                last = j == m - 1
                s.sendall(req("/x?size=300", extra="Connection: close\r\n" if last else ""))
                r.response(); k += 1
            s.close(); s = connect(); r = Reader(s)
        elif SCEN == "abort":
            # full requests, then a partial one, then close mid-stream
            for j in range(rnd.randint(1, 3)):
                s.sendall(req("/x?size=300")); r.response(); k += 1
            s.sendall(req("/x?size=300")[:20])
            time.sleep(0.005)
            s.close(); s = connect(); r = Reader(s)
        elif SCEN == "pipeline":
            depth = rnd.choice([2, 3, 4, 8])
            s.sendall(b"".join(req(f"/p?size={rnd.choice([10, 300, 5000])}") for _ in range(depth)))
            for _ in range(depth):
                r.response()
            k += depth
        elif SCEN == "bighdr":
            sz = rnd.choice([1000, 3000, 6000, 12000])
            s.sendall(req("/g?size=100", extra="Cookie: " + "c" * sz + "\r\n"))
            r.response(); k += 1
        elif SCEN == "pipe32":
            s.sendall(b"".join(req("/p?size=10") for _ in range(32)))
            for _ in range(32):
                r.response()
            k += 32
        elif SCEN == "pipehead":
            # 32 pipelined, with HEADs among those the agent cannot queue.
            heads = [j >= 20 and j % 3 == 0 for j in range(32)]
            s.sendall(b"".join(req("/h?size=500", "HEAD" if h else "GET") for h in heads))
            for h in heads:
                r.response(head=h)
            k += 32
        elif SCEN == "mixlong":
            ch = rnd.random()
            if ch < 0.3:
                body = b"y" * 200000
                data = req("/b?size=300000&wchunk=8192", "POST", body=body)
                for off in range(0, len(data), 16384):
                    s.sendall(data[off:off + 16384])
                    time.sleep(0.0005)
            elif ch < 0.5:
                data = req("/s?size=200", "POST", body=b"z" * 3000)
                s.sendall(data[:30]); time.sleep(0.003); s.sendall(data[30:])
            elif ch < 0.7:
                data = req(f"/d?d=2000&size=200")
                s.sendall(data)
            else:
                s.sendall(req("/k?size=50000&chunked=1&wchunk=4096"))
            r.response(); k += 1
            time.sleep(0.002)
        elif SCEN == "down":
            if rnd.random() < 0.5:
                s.sendall(req(f"/d?d={rnd.choice([200, 1000, 5000])}&size=200"))
            else:
                s.sendall(req("/n?size=200"))
            r.response(); k += 1
        elif SCEN == "mix":
            s.sendall(req(f"/m?size={rnd.choice([10, 1000])}"))
            r.response(); k += 1
            time.sleep(rnd.uniform(0, 0.002))
        else:
            raise SystemExit("unknown scenario " + SCEN)
    count(k)
    s.close()


ths = [threading.Thread(target=worker, args=(i, N // CONC)) for i in range(CONC)]
t0 = time.time()
for t in ths:
    t.start()
for t in ths:
    t.join()
print(f"client {SCEN}: {done[0]} requests in {time.time() - t0:.2f}s")
