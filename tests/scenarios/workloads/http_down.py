#!/usr/bin/env python3
"""Downstream connections used in ways an HTTP backend is not.

    http_down.py backend PORT
    http_down.py serve PORT BACKEND_PORT
    http_down.py client PORT REQUESTS

The backend speaks lines: `<id> <delay_ms>\\n` is answered with `<id>\\n` after
the delay, each on its own timer, so answers on one connection can overlap.

The server, one thread per connection, answers
  /pipe    by writing three calls back to back on the thread's own backend
           connection (delays 2, 4 and 6 ms) and then reading the three
           answers: one request pipelining, which the agent times as one call
           of about 6 ms whose first byte comes after about 2 ms;
  /shared  with one call of 3 ms on a connection all threads share, the
           answers handed out by a reader thread: calls of different requests
           overlap there, and the agent must not time them.

The client sends REQUESTS `/pipe` on one connection, then REQUESTS `/shared`
on each of four connections at once. Prints `down pipe=N shared=N`.
"""
import socket
import sys
import threading
import time

HOST = "127.0.0.1"


def lines(sock):
    buf = b""
    while True:
        part = sock.recv(4096)
        if not part:
            return
        buf += part
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            yield line


def backend(port):
    def answer(conn, lock, ident, delay_ms):
        time.sleep(delay_ms / 1000)
        with lock:
            try:
                conn.sendall(ident + b"\n")
            except OSError:
                pass

    def serve(conn):
        lock = threading.Lock()
        for line in lines(conn):
            ident, delay = line.split()
            threading.Thread(target=answer, args=(conn, lock, ident, int(delay)), daemon=True).start()

    listener = socket.create_server((HOST, port))
    while True:
        conn, _ = listener.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


class Shared:
    """One backend connection for every thread; a reader hands out the answers."""

    def __init__(self, port):
        self.sock = connect(port)
        self.lock = threading.Lock()
        self.waiting = {}
        self.next = 0
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        for line in lines(self.sock):
            self.waiting.pop(int(line)).set()

    def call(self, delay_ms):
        done = threading.Event()
        with self.lock:
            self.next += 1
            self.waiting[self.next] = done
            self.sock.sendall(b"%d %d\n" % (self.next, delay_ms))
        done.wait()


def connect(port):
    sock = socket.create_connection((HOST, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def serve(port, backend_port):
    shared = Shared(backend_port)

    def serve_conn(conn):
        own = connect(backend_port)
        answers = lines(own)
        buf = b""
        with conn, own:
            while True:
                while b"\r\n\r\n" not in buf:
                    part = conn.recv(4096)
                    if not part:
                        return
                    buf += part
                head, buf = buf.split(b"\r\n\r\n", 1)
                path = head.split(b" ", 2)[1]
                if path == b"/pipe":
                    for ident, delay in ((1, 2), (2, 4), (3, 6)):
                        own.sendall(b"%d %d\n" % (ident, delay))
                    for _ in range(3):
                        next(answers)
                elif path == b"/shared":
                    shared.call(3)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    listener = socket.create_server((HOST, port))
    while True:
        conn, _ = listener.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=serve_conn, args=(conn,), daemon=True).start()


def client(port, count):
    def run(path):
        sock = connect(port)
        for _ in range(count):
            sock.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: t\r\n\r\n")
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += sock.recv(4096)
        sock.close()

    run(b"/pipe")
    threads = [threading.Thread(target=run, args=(b"/shared",)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"down pipe={count} shared={4 * count}")


if __name__ == "__main__":
    if sys.argv[1] == "backend":
        backend(int(sys.argv[2]))
    elif sys.argv[1] == "serve":
        serve(int(sys.argv[2]), int(sys.argv[3]))
    else:
        client(int(sys.argv[2]), int(sys.argv[3]))
