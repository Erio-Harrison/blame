#!/usr/bin/env python3
"""HTTP/2 spoken by hand, frame by frame, to check where streams start and end.

    h2_quirks.py serve PORT LOGFILE [CHUNK]
    h2_quirks.py client PORT
    h2_quirks.py storm PORT
    h2_quirks.py steady PORT SECONDS

Neither side uses an HTTP/2 library or compresses headers: both only care
about frames. The server is the process `blame slow` watches. It reads CHUNK
bytes at a time (default 4096; 7 makes every frame header straddle two reads)
and logs, for every stream, when the read that completed its opening frame
header returned and when the write that carried its closing frame header
returned (CLOCK_BOOTTIME ns), as `S <client port> <stream> <start> <end>
<how>`; `end` is 0 for a stream that was reset.

The request body says how to answer: `<delay_ms>,<how>`, with `how` one of

  plain   HEADERS, DATA, trailers with END_STREAM
  data    HEADERS, then DATA with END_STREAM
  cont    trailers split over HEADERS + two CONTINUATION frames; the stream
          ends at the last of them
  padded  the same as plain with PADDED on every frame
  iov     one sendmsg of 40 pieces, frame headers cut across pieces
  split   two writes, the closing frame's header cut between them
  tiny    the body as 300 one-byte DATA frames
  rst     RST_STREAM instead of an answer
  brst    held back; reset together with every other held stream, in one write
  bdata   held back; answered together with every other held stream, in one write
  flush   releases the held streams (one write of resets, one of answers),
          then is answered plainly

The client opens streams in every shape a request can take (HEADERS alone
with END_STREAM, HEADERS + DATA, HEADERS + CONTINUATION, PADDED and PRIORITY
flags), interleaves PING, WINDOW_UPDATE, SETTINGS and a frame type nobody
knows, resets some streams itself, and at the end opens 200 at once. It
prints `h2 opened=N answered=N reset_by_server=N reset_by_client=N`.

`storm` puts hundreds of streams into single calls: with 40 streams waiting
for their answers, it opens 300 + 300 more in two writes (the server reads
them in as few reads as its CHUNK allows), which the server then resets and
answers in one write each.

`steady` keeps two connections busy for SECONDS, a stream every 2 ms on each,
several open at a time: something to attach to in the middle.
"""
import heapq
import select
import socket
import struct
import sys
import time

HOST = "127.0.0.1"
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DATA, HEADERS, PRIORITY, RST, SETTINGS, PING, GOAWAY, WINDOW, CONT = 0, 1, 2, 3, 4, 6, 7, 8, 9
END_STREAM, END_HEADERS, PADDED, PRIO = 1, 4, 8, 0x20
# Not valid HPACK for anything in particular; neither side decodes it.
BLOCK = b"\x88" + b"x" * 20


def boot_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def frame(kind, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([kind, flags]) + struct.pack(">I", sid) + payload


def padded(payload, pad=5):
    return bytes([pad]) + payload + b"\0" * pad


class Frames:
    """Cuts a byte stream into frames; yields (kind, flags, sid, payload, stamp), the
    stamp being the one given with the feed() that completed the frame's header."""

    def __init__(self):
        self.buf = b""
        self.stamp = None
        self.pending = None

    def feed(self, data, stamp=0):
        self.buf += data
        out = []
        while len(self.buf) >= 9:
            if self.stamp is None:
                self.stamp = stamp
            length = int.from_bytes(self.buf[:3], "big")
            if len(self.buf) < 9 + length:
                break
            kind, flags = self.buf[3], self.buf[4]
            sid = int.from_bytes(self.buf[5:9], "big") & 0x7FFFFFFF
            out.append((kind, flags, sid, self.buf[9 : 9 + length], self.stamp))
            self.buf = self.buf[9 + length :]
            self.stamp = None
        return out


def answer(sid, how):
    """The writes that answer a stream: a list of calls, each a list of pieces
    (one piece: send; several: sendmsg). The stream's closing frame header ends
    in the last call."""
    body = b"y" * 300
    head = frame(HEADERS, END_HEADERS, sid, BLOCK)
    if how == "data":
        return [[head + frame(DATA, END_STREAM, sid, body)]]
    if how == "cont":
        return [[
            head + frame(DATA, 0, sid, body)
            + frame(HEADERS, END_STREAM, sid, BLOCK[:5])
            + frame(CONT, 0, sid, BLOCK[5:9])
            + frame(CONT, END_HEADERS, sid, BLOCK[9:])
        ]]
    if how == "padded":
        return [[
            frame(HEADERS, END_HEADERS | PADDED, sid, padded(BLOCK))
            + frame(DATA, PADDED, sid, padded(body))
            + frame(HEADERS, END_HEADERS | END_STREAM | PADDED, sid, padded(BLOCK))
        ]]
    if how == "tiny":
        tiny = b"".join(frame(DATA, 0, sid, b"y") for _ in range(300))
        return [[head + tiny + frame(HEADERS, END_HEADERS | END_STREAM, sid, BLOCK)]]
    if how == "rst":
        return [[frame(RST, 0, sid, b"\0\0\0\2")]]
    plain = head + frame(DATA, 0, sid, body) + frame(HEADERS, END_HEADERS | END_STREAM, sid, BLOCK)
    if how == "iov":
        step = len(plain) // 40 + 1
        return [[plain[i : i + step] for i in range(0, len(plain), step)]]
    if how == "split":
        cut = len(plain) - len(BLOCK) - 5  # inside the closing frame's header
        return [[plain[:cut]], [plain[cut:]]]
    return [[plain]]


def serve(port, log_path, chunk):
    listener = socket.create_server((HOST, port))
    listener.listen(64)
    conns = {}  # socket -> state
    due = []  # (time, order, socket, stream, how)
    order = 0
    log = []
    try:
        while True:
            timeout = max(0, due[0][0] - time.monotonic()) if due else None
            readable, _, _ = select.select([listener, *conns], [], [], timeout)
            for sock in readable:
                if sock is listener:
                    conn, addr = listener.accept()
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    conns[conn] = {"port": addr[1], "frames": Frames(), "preface": b"", "open": {}}
                    conn.sendall(frame(SETTINGS, 0, 0))
                    continue
                state = conns[sock]
                try:
                    data = sock.recv(chunk)
                except OSError:
                    data = b""
                now = boot_ns()
                if not data:
                    del conns[sock]
                    sock.close()
                    continue
                if len(state["preface"]) < len(PREFACE):
                    take = len(PREFACE) - len(state["preface"])
                    state["preface"] += data[:take]
                    data = data[take:]
                    if not data:
                        continue
                for kind, flags, sid, payload, start in state["frames"].feed(data, now):
                    if kind == HEADERS and sid not in state["open"]:
                        state["open"][sid] = {"start": start, "body": b"", "reset": False}
                    stream = state["open"].get(sid)
                    if stream is None or stream["reset"]:
                        continue
                    if kind == DATA:
                        if flags & PADDED:
                            payload = payload[1 : len(payload) - payload[0]]
                        stream["body"] += payload
                    if kind == RST:
                        stream["reset"] = True
                        log.append(f"S {state['port']} {sid} {stream['start']} 0 client-rst")
                        continue
                    # The request is complete at END_STREAM, which a header block
                    # cut into pieces carries on its first piece and means at its last.
                    ended = False
                    if kind == DATA:
                        ended = bool(flags & END_STREAM)
                    elif kind == HEADERS:
                        ended = flags & END_STREAM and flags & END_HEADERS
                        stream["end_at_last_piece"] = flags & END_STREAM and not flags & END_HEADERS
                    elif kind == CONT:
                        ended = flags & END_HEADERS and stream.get("end_at_last_piece")
                    if ended and "queued" not in stream:
                        stream["queued"] = True
                        delay, _, how = (stream["body"].decode() or "0,plain").partition(",")
                        if how in ("brst", "bdata"):
                            state.setdefault(how, []).append(sid)
                            continue
                        order += 1
                        heapq.heappush(due, (time.monotonic() + int(delay) / 1000, order, sock, sid, how))
            while due and due[0][0] <= time.monotonic():
                _, _, sock, sid, how = heapq.heappop(due)
                state = conns.get(sock)
                if state is None or state["open"][sid]["reset"]:
                    continue
                end = 0
                if how == "flush":
                    # Every held stream at once: one write of resets, one of answers.
                    resets, answers = state.pop("brst", []), state.pop("bdata", [])
                    try:
                        if resets:
                            sock.sendall(b"".join(frame(RST, 0, held, b"\0\0\0\2") for held in resets))
                        if answers:
                            sock.sendall(b"".join(frame(HEADERS, END_HEADERS | END_STREAM, held, BLOCK) for held in answers))
                    except OSError:
                        continue
                    end = boot_ns()
                    log += [f"S {state['port']} {held} {state['open'][held]['start']} 0 brst" for held in resets]
                    log += [f"S {state['port']} {held} {state['open'][held]['start']} {end} bdata" for held in answers]
                    how = "plain"
                try:
                    for pieces in answer(sid, how):
                        if len(pieces) == 1:
                            sock.sendall(pieces[0])
                        else:
                            sock.sendmsg(pieces)
                        end = boot_ns()
                except OSError:
                    continue
                if how == "rst":
                    end = 0
                log.append(f"S {state['port']} {sid} {state['open'][sid]['start']} {end} {how}")
    finally:
        with open(log_path, "w") as out:
            out.write("\n".join(log) + "\n")


def client(port, storm=False):
    opened = answered = reset_by_server = reset_by_client = 0

    def run(requests, burst=False):
        """requests: (frames that open the stream and send its body, cancelled by the
        client); or a list of those, for streams opened in one write."""
        nonlocal opened, answered, reset_by_server, reset_by_client
        sock = socket.create_connection((HOST, port))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(PREFACE + frame(SETTINGS, 0, 0))
        waiting = set()
        sid = 1
        for request in requests:
            if isinstance(request, list):
                sock.sendall(b"".join(make(sid + 2 * i) for i, (make, _) in enumerate(request)))
                waiting.update(range(sid, sid + 2 * len(request), 2))
                opened += len(request)
                sid += 2 * len(request)
                time.sleep(0.02)
                continue
            make, cancel = request
            sock.sendall(make(sid))
            opened += 1
            if cancel:
                time.sleep(0.002)
                sock.sendall(frame(RST, 0, sid, b"\0\0\0\x08"))
                reset_by_client += 1
            else:
                waiting.add(sid)
            sid += 2
            if not burst:
                time.sleep(0.001)
        frames = Frames()
        sock.settimeout(10)
        while waiting:
            data = sock.recv(65536)
            if not data:
                break
            for kind, flags, stream, _, _ in frames.feed(data):
                if kind == RST and stream in waiting:
                    waiting.discard(stream)
                    reset_by_server += 1
                elif kind in (HEADERS, DATA, CONT) and stream in waiting:
                    if kind == HEADERS and flags & END_STREAM and not flags & END_HEADERS:
                        frames.pending = stream
                    elif (flags & END_STREAM and kind != CONT) or (
                        kind == CONT and flags & END_HEADERS and frames.pending == stream
                    ):
                        waiting.discard(stream)
                        answered += 1
        sock.close()

    def body(text):
        return lambda sid: frame(HEADERS, END_HEADERS, sid, BLOCK) + frame(DATA, END_STREAM, sid, text.encode())

    if storm:
        run(
            [(body("150,plain"), False) for _ in range(40)]
            + [[(body("0,brst"), False)] * 300, [(body("0,bdata"), False)] * 300]
            + [(body("30,flush"), False)]
        )
        print(f"h2 opened={opened} answered={answered} reset_by_server={reset_by_server} reset_by_client={reset_by_client}")
        return
    shapes = []
    for how in ("plain", "data", "cont", "padded", "iov", "split", "tiny", "rst"):
        shapes += [(body(f"{delay},{how}"), False) for delay in (0, 3, 6)]
    # A request with no body at all, answered plainly at once.
    shapes.append((lambda sid: frame(HEADERS, END_HEADERS | END_STREAM, sid, BLOCK), False))
    # Its header block cut in three, the end of the stream on the first piece.
    shapes.append((
        lambda sid: frame(HEADERS, END_STREAM, sid, BLOCK[:4])
        + frame(CONT, 0, sid, BLOCK[4:8])
        + frame(CONT, END_HEADERS, sid, BLOCK[8:]),
        False,
    ))
    # PADDED and PRIORITY on the opening frame, PADDED on the body.
    shapes.append((
        lambda sid: frame(HEADERS, END_HEADERS | PADDED | PRIO, sid, bytes([4]) + b"\0\0\0\0\x10" + BLOCK + b"\0" * 4)
        + frame(DATA, END_STREAM | PADDED, sid, padded(b"2,plain")),
        False,
    ))
    # Frames that are not about any stream, and one of a type nobody knows, in between.
    shapes.append((
        lambda sid: frame(PING, 0, 0, b"12345678")
        + frame(WINDOW, 0, 0, b"\0\0\x10\0")
        + frame(0x2A, 0, 0, b"unknown")
        + frame(PRIORITY, 0, sid, b"\0\0\0\0\x10")
        + frame(HEADERS, END_HEADERS, sid, BLOCK)
        + frame(WINDOW, 0, sid, b"\0\0\x10\0")
        + frame(DATA, END_STREAM, sid, b"4,cont"),
        False,
    ))
    # Given up by the client while the server is still waiting to answer.
    shapes += [(body("50,plain"), True) for _ in range(5)]
    for _ in range(3):
        run(shapes)
    # 200 streams open at once on one connection.
    run([(body(f"{20 + i % 7},plain"), False) for i in range(200)], burst=True)
    print(f"h2 opened={opened} answered={answered} reset_by_server={reset_by_server} reset_by_client={reset_by_client}")


def steady(port, seconds):
    socks = []
    for _ in range(2):
        sock = socket.create_connection((HOST, port))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(PREFACE + frame(SETTINGS, 0, 0))
        sock.setblocking(False)
        socks.append(sock)
    sid, opened = 1, 0
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        for sock in socks:
            sock.setblocking(True)
            sock.sendall(frame(HEADERS, END_HEADERS, sid, BLOCK) + frame(DATA, END_STREAM, sid, b"5,plain"))
            sock.setblocking(False)
            opened += 1
            try:
                while sock.recv(65536):
                    pass
            except BlockingIOError:
                pass
        sid += 2
        time.sleep(0.002)
    time.sleep(0.1)
    print(f"h2 opened={opened}")


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        import signal

        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        serve(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]) if len(sys.argv) > 4 else 4096)
    elif sys.argv[1] == "steady":
        steady(int(sys.argv[2]), float(sys.argv[3]))
    else:
        client(int(sys.argv[2]), storm=sys.argv[1] == "storm")
