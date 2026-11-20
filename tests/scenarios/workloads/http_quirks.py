#!/usr/bin/env python3
"""Server and client for the uses of a connection the truth server lacks.

    http_quirks.py serve PORT
    http_quirks.py client PORT CONNECTIONS

The server, one thread per connection, peeks at every request before reading
it (MSG_PEEK through recvfrom and recvmsg, in turn), answers `/hdr4096` with a
response whose header block is exactly 4096 bytes, sent in one call, and
answers `/up` with 101 Switching Protocols and then echoes whatever comes.

Each client connection sends `GET /q/<conn>/<i>` for i in 0..5, `/hdr4096`,
then `/q/<conn>/6`; then, on a second connection, upgrades with `/up` and
sends a request line through the upgraded stream (`GET /fake`), which is not
HTTP any more and must not be counted. Prints `quirks requests=N upgrades=N`:
what the agent should report.
"""
import socket
import sys
import threading

HOST = "127.0.0.1"


def read_request(s, peek_with_recvmsg):
    """One request without a body; peeks at it first."""
    if peek_with_recvmsg:
        data, _, _, _ = s.recvmsg(65536, 0, socket.MSG_PEEK)
    else:
        data = s.recv(65536, socket.MSG_PEEK)
    if not data:
        return None
    buf = b""
    while b"\r\n\r\n" not in buf:
        part = s.recv(65536)
        if not part:
            return None
        buf += part
    return buf.split(b" ", 2)[1].decode()


def big_header_response():
    head = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Pad: "
    tail = b"\r\n\r\n"
    return head + b"p" * (4096 - len(head) - len(tail)) + tail


def serve_conn(s):
    n = 0
    with s:
        while True:
            path = read_request(s, n % 2 == 1)
            n += 1
            if path is None:
                return
            if path == "/up":
                s.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n")
                while True:
                    data = s.recv(65536)
                    if not data:
                        return
                    s.sendall(data)
            if path == "/hdr4096":
                resp = big_header_response()
                assert len(resp) == 4096
                s.sendall(resp)
            else:
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")


def serve(port):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((HOST, port))
    ls.listen(64)
    while True:
        s, _ = ls.accept()
        threading.Thread(target=serve_conn, args=(s,), daemon=True).start()


def response(s, buf):
    """Reads one response with a Content-Length; returns (status, rest)."""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(65536)
    head, buf = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    length = 0
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value)
    while len(buf) < length:
        buf += s.recv(65536)
    return status, buf[length:]


def client_conn(port, c):
    s = socket.create_connection((HOST, port))
    buf = b""
    for path in [f"/q/{c}/{i}" for i in range(6)] + ["/hdr4096", f"/q/{c}/6"]:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: t\r\n\r\n".encode())
        status, buf = response(s, buf)
        assert status == 200, status
    s.close()

    s = socket.create_connection((HOST, port))
    s.sendall(b"GET /up HTTP/1.1\r\nHost: t\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n")
    status, buf = response(s, b"")
    assert status == 101, status
    fake = b"GET /fake HTTP/1.1\r\nHost: t\r\n\r\n"
    s.sendall(fake)
    while len(buf) < len(fake):
        buf += s.recv(65536)
    s.close()


def client(port, conns):
    threads = [threading.Thread(target=client_conn, args=(port, c)) for c in range(conns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f"quirks requests={conns * 9} upgrades={conns}")


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(int(sys.argv[2]))
    else:
        client(int(sys.argv[2]), int(sys.argv[3]))
