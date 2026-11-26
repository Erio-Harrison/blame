#!/usr/bin/env python3
"""An HTTPS server and its load, over Python's ssl module (OpenSSL's libssl,
sessions placed by SSL_set_fd), for `blame slow --tls`.

    tls_http.py server PORT CERT KEY       GET /sleep: sleeps 20 ms, answers "ok"
    tls_http.py load PORT SECONDS CONNS    each connection keeps alive for 20
                                           requests, then a new one is opened

The handler's time is all asleep: a request blame reports with its time on a
CPU is one whose thread's sleeps it did not see.
"""
import http.client
import http.server
import socketserver
import ssl
import sys
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        time.sleep(0.02)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def server(port, cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = Server(("127.0.0.1", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


def load(port, seconds, conns):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    end = time.monotonic() + seconds

    def one():
        while time.monotonic() < end:
            c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx)
            try:
                for _ in range(20):
                    if time.monotonic() >= end:
                        break
                    c.request("GET", "/sleep")
                    c.getresponse().read()
            except OSError:
                time.sleep(0.05)
            finally:
                c.close()

    threads = [threading.Thread(target=one) for _ in range(conns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    if sys.argv[1] == "server":
        server(int(sys.argv[2]), sys.argv[3], sys.argv[4])
    else:
        load(int(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4]))
