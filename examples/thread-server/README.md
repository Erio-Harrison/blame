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

## What it showed (2026-11-18, the arm64 VM, `normal`)

| request | p50 | CPU | waiting for CPU | disk | downstream | other blocked |
|---|---|---|---|---|---|---|
| `/compute` | 2.0 ms | 1,683 us | 661 us | | | |
| `/lock` | 1.3 ms | 946 us | 586 us | | | 501 us |
| `/save` | 0.4 ms | 40 us | 740 us | 374 us | | 14 us |
| `/backend` | 5.3 ms | 24 us | 630 us | | 4,516 us | |

Against the servers' own figures, over 51,029 requests: CPU +1.7%, waiting for
a CPU +2.8%, the wait for the mutex −1.6%, write + fsync −3.2%, nanosleep −0.0%
(99.4–100% of requests within 100 us or 10%).

What a thread can tell and what it cannot:

- A wait for a mutex is shown as `other`: in the kernel it is a sleep on a futex,
  the same as a condition variable's. Telling them apart takes a runtime's help
  (Go and tokio have it).
- `/save` takes 0.4 ms at p50, but most of it is waiting for a CPU after the
  flush, not the disk: with 16 threads on two CPUs, a thread the disk wakes
  waits its turn.

## Known issue

A connection to the backend that has a call in flight when blame attaches is
not seen as a call afterwards: none of the calls on it are, and its thread's
wait shows as `off thread` instead of `downstream`. In the run above, 2 of the
16 front threads (1,282 of 10,206 `/backend` calls) were affected, which is why
the backend call row in `report.py` is −12.7%. With blame attached before the
load starts, 1 call in 6,912 is missed.
