#!/usr/bin/env python3
"""A load that opens a new connection for every request, so that a server
with a thread per connection starts a thread per request.

    reconnect.py PORT WORKERS SECONDS [PATH]
"""
import socket
import sys
import threading
import time

port, workers, secs = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
path = sys.argv[4] if len(sys.argv) > 4 else "/n?size=200&cpu=300"
end = time.time() + secs


def work():
    while time.time() < end:
        try:
            # A server that stops answering ends this worker's request, not
            # the whole test.
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
            while s.recv(65536):
                pass
            s.close()
        except OSError:
            pass


threads = [threading.Thread(target=work) for _ in range(workers)]
for t in threads:
    t.start()
for t in threads:
    t.join()
