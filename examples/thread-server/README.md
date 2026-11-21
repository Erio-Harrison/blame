# Thread server

What `blame slow` tells about a service in a language it has no adapter for:
a plain C HTTP/1.1 server that serves each connection on a thread of its own.
blame needs nothing from such a service. The thread is the unit of work, so
what the kernel sees of the thread is what the request did.

```
load ──HTTP──▶ front (C, a thread per connection) ──HTTP──▶ backend (C)
                 │
                 └─ /save: 16 KB written and flushed (fsync)
```

- `GET /compute`: 2 ms of computing.
- `GET /lock`: waits for a mutex, then computes 1 ms holding it.
- `POST /save`: 16 KB appended to a file and flushed.
- `GET /backend`: asks the backend, which sleeps 5 ms.

Each request carries its own `traceparent`, passed on to the backend. Each
server writes what it measured itself when it stops: the request's wall time,
its thread's CPU time, and its thread's wait for a CPU (from
`/proc/thread-self/schedstat`). What is left of the wall time the thread was
asleep. `report.py` joins those with blame's figures by trace id.

## Scenarios

| scenario | what is wrong | what blame should say |
|---|---|---|
| `normal` | 16 connections on two CPUs | where each kind of request waits |
| `cpu` | two processes spin on the front server's CPUs | more waiting for a CPU |

## Running

Needs root through `sudo` (blame), a C compiler and `python3`. With blame built
(`cargo build --release`):

```sh
for s in normal cpu; do examples/thread-server/run.sh $s /tmp/thread-server; done
examples/thread-server/report.py /tmp/thread-server normal cpu
```

Keep the output directory on a local disk: `/save` writes there. Each run loads
the servers for 24 s, attaches blame 3 s in and watches for 15 s. It uses CPUs
0-5: the front server on 0-1, the backend on 2, the load on 4-5.

## What it showed (2026-11-21, the arm64 VM, `normal`)

p50 of the request, then where its time went, mean per request:

| request | p50 | CPU | waiting for CPU | disk | downstream | other blocked |
|---|---|---|---|---|---|---|
| `/compute` | 2.0 ms | 1,669 us | 624 us | | | |
| `/lock` | 1.3 ms | 933 us | 537 us | | | 413 us |
| `/save` | 0.5 ms | 38 us | 710 us | 332 us | | 9 us |
| `/backend` | 5.3 ms | 24 us | 600 us | | 5,161 us | |

Against the servers' own figures, over 53,172 requests: CPU +1.6%, waiting for
a CPU +2.0%, the wait for the mutex −1.4%, write + fsync −2.0%, the call to the
backend −0.2%, nanosleep −0.0% (99.5–100% of requests within 100 us or 10%).
Every call to the backend was seen, though blame attached with calls in flight.

In `cpu` the wait for a CPU grew: `/compute` from 624 to 1,087 us, `/save` from
710 to 1,366 us (against the servers' figures: −0.6% to +1.2%).

What a thread can tell and what it cannot:

- A wait for a mutex is shown as `other`: in the kernel it is a sleep on a futex,
  the same as a condition variable's. Telling them apart takes a runtime's help
  (Go and tokio have it).
- `/save` waits twice as long for a CPU (710 us) as for the disk (332 us): with
  16 threads on two CPUs, a thread the disk wakes waits its turn.
