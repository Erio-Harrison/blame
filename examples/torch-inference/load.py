#!/usr/bin/env python3
"""load.py PORT CONNS SECS: keep-alive GET /infer on CONNS connections, each
request with a traceparent of its own."""
import socket
import sys
import threading
import time

port, conns, secs = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
end = time.time() + secs
run = int(time.time()) & 0xFFFFFFFF
done = [0] * conns


def client(i):
    s = socket.create_connection(("127.0.0.1", port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    n = 0
    while time.time() < end:
        n += 1
        trace = "%08x%08x%016x" % (run, i, n)
        s.sendall(b"GET /infer HTTP/1.1\r\nHost: x\r\ntraceparent: 00-%s-%016x-01\r\n\r\n" % (trace.encode(), n))
        buf = b""
        while not buf.endswith(b"ok"):
            data = s.recv(4096)
            if not data:
                return
            buf += data
        done[i] += 1


threads = [threading.Thread(target=client, args=(i,)) for i in range(conns)]
for t in threads:
    t.start()
for t in threads:
    t.join()
print("requests", sum(done))
