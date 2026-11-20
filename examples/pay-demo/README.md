# Pay demo

One payment through five processes and three runtimes, and what `blame slow
--deep` says of it at each of them: which service is slow, and what it waits
for there.

```
load ─HTTP─▶ gateway (Rust, tokio) ─gRPC─▶ payment (Go) ─gRPC─▶ account (Go)
                │                              ├─gRPC─▶ ledger (Go, SQLite)
                └─ an audit line (tokio::fs)   └─HTTP─▶ risk (PyTorch) ─HTTP─▶ account
```

- `POST /pay` at the gateway: `payment.Payments/Charge`, then a line appended to
  an audit file and flushed.
- `payment.Payments/Charge`: 300 us of computing; then, at the same time, the
  debit (`account.Accounts/Debit`) and the score (`GET /score` of risk, at most
  4 at a time); then the entry (`ledger.Ledger/Append`).
- `account.Accounts/Debit`: 100 us of computing under the balances' lock, then a
  16 KB statement written and flushed, on NFS.
- `GET /score` at risk: the account's features asked of account
  (`GET /features/N`), then a forward pass of a small network on the CPU, in
  parallel regions of three threads (OpenMP, GNU's runtime).
- `ledger.Ledger/Append`: a row in SQLite (`synchronous=FULL`, one connection).
- `GET /balance/N` at the gateway: `account.Accounts/Balance`, 100 us of
  computing.

Every request carries its own `traceparent`, passed on at each hop, HTTP/1.1
and gRPC alike. Each service writes what it measured itself when it stops.

## Scenarios

| scenario | what is wrong | what blame says |
|---|---|---|
| `normal` | nothing | the baseline |
| `cpu` | three processes spin on the CPUs risk runs on | risk waits for a CPU, its own thread and its team's |
| `downstream` | ledger keeps the database locked 3 ms per entry | ledger sleeps holding the connection, and entries wait for it; payment and the gateway wait for an answer |
| `lock` | account computes 1 ms under its balances' lock | Debit waits for a lock (Go's `sync`) |
| `nfs` | NFS requests get 5 ms more on the network | account waits for the file service, not the disk |
| `disk` | another process writes and flushes on the same disk | ledger and the gateway's blocking pool wait for the disk |
| `cpu-payment` | two processes spin on the CPU payment runs on | not in the request; in payment's own line: its threads wait for a CPU others have |
| `cpu-gateway` | two processes spin on the two CPUs the gateway shares with account, ledger and the load | Debit and the entry wait for a CPU; in the lines of the gateway, account and ledger: their threads wait for a CPU others have |
| `docker` | nothing; payment runs in a container, on Docker's bridge network | the same as `normal` |
| `docker-cpu` | the same, the container limited to a quarter of a CPU | not in the request; in payment's own line: its threads wait for a CPU that a limit keeps them off |

## Running

Needs root through `sudo` (blame, `tc`), Go, cargo, `python3`, a Python with
PyTorch for risk (without it the demo runs without risk), docker for the two
`docker` scenarios (through `sudo`; the image is `debian:stable-slim`, or
`PAY_IMAGE`), and an NFS share
mounted from 127.0.0.1 for the statements, for example:

```sh
python3 -m venv /tmp/torch-venv
/tmp/torch-venv/bin/pip install --index-url https://download.pytorch.org/whl/cpu torch
sudo apt-get install -y nfs-kernel-server
sudo mkdir -p /srv/pay-nfs /mnt/pay-statements /etc/exports.d && sudo chmod 777 /srv/pay-nfs
echo "/srv/pay-nfs 127.0.0.1(rw,sync,no_subtree_check,insecure)" | sudo tee /etc/exports.d/pay-demo.exports
sudo exportfs -ra
sudo mount -t nfs4 -o vers=4.2 127.0.0.1:/srv/pay-nfs /mnt/pay-statements
```

Then, with blame built (`cargo build --release`):

```sh
export PYTHON=/tmp/torch-venv/bin/python
for s in normal cpu cpu-payment cpu-gateway docker docker-cpu downstream lock nfs disk; do examples/pay-demo/run.sh $s /mnt/pay-statements /tmp/pay; done
examples/pay-demo/report.py /tmp/pay normal cpu cpu-payment cpu-gateway docker docker-cpu downstream lock nfs disk
```

Each run starts the services, loads them for 24 s (8 workers), attaches blame
3 s in (the services are busy when it does, as they would be) and watches for
15 s. It uses CPUs 0-5: gateway, account, ledger and the load on 0-1, payment
on 2, risk on 3-5.

`report.py` prints, for each scenario: where the time of each kind of request
went (mean per call), the Charge at p50 and at p99 followed through the
services by its trace id, blame's figures next to the services' own, and what each process's threads
waited for a CPU.

## What it showed (2026-11-19, the arm64 VM, 6 CPUs)

All requests of all five processes had their name, status and trace id
(30,000 to 73,000 a run).

### One payment followed

The Charge at p50 in `nfs`, by its trace id, in us:

| service | request | took | what blame says of it |
|---|---|---|---|
| gateway | POST /pay | 14,039 | waiting for another task 13,460 (the call to payment); blocking pool 453, whose 3 tasks waited 385 for the disk |
| payment | Charge | 13,286 | CPU 329; waiting on a lock 11,763 (`sync.WaitGroup`: the debit and the score), on a channel 802 (the gRPC client: the entry) |
| account | Debit | 11,508 | CPU 198; **file service 11,249** |
| risk | GET /score | 1,676 | CPU 819; waiting for a CPU 260; downstream 137 (account's features); asleep 460; its team: 8 pieces, CPU 911, waiting for a CPU 665 |
| ledger | Append | 756 | CPU 193; disk 454 |
| account | GET /features/1 | 69 | CPU 69 |

The gateway and payment say only that they wait for an answer. Which answer is
late is found by the trace id: account's Debit took 11.5 ms of the 13.3, and it
says why.

### What each scenario moved

Mean per call, in us; the figure the scenario is about, against `normal`:

| scenario | service, request | figure | `normal` | scenario |
|---|---|---|---|---|
| `cpu` | risk, GET /score | waiting for a CPU, its thread | 293 | 1,473 |
| | | waiting for a CPU, its team | 491 | 1,050 |
| `downstream` | ledger, Append | waiting: sleep | 0 | 3,368 |
| | | waiting: channel (for the connection) | 2,207 | 21,374 |
| | payment, Charge | waiting: channel (the gRPC client) | 4,063 | 26,005 |
| `lock` | account, Debit | waiting: lock | 7 | 304 |
| | | CPU | 201 | 1,030 |
| `nfs` | account, Debit | file service | 1,583 | 11,781 |
| | ledger, Append | disk | 1,135 | 814 |
| `disk` | ledger, Append | disk | 1,135 | 3,415 |
| | gateway, POST /pay | blocking pool's tasks: disk | 360 | 1,398 |
| | account, Debit | file service | 1,583 | 4,195 |

In `disk` the file service is slower too: the NFS server writes to the same
disk. In `cpu` the ledger's wait for the disk doubled as well (1,135 to 2,198);
why was not looked into.

### Against the services' own figures

Joined by trace id; the range over the eight scenarios:

| service | the service measured | blame | total diff | calls within 100 us or 10% |
|---|---|---|---|---|
| account | Debit: waiting for the lock (3 to 308 us) | waiting: lock | −4.7% to +29% (+29%: 9 us against 7) | 99.7% to 100% |
| account | Debit: lock, computing and the statement | all but the library before and after the handler | +0.1% to +1.5% | 98.7% to 100% |
| account | Balance: computing | CPU + waiting for a CPU | +12% to +23% | 97.9% to 99.9% |
| payment | Charge: the debit and the score, then the entry | waiting: lock + channel | −1.0% to −0.1% | 98.6% to 100% |
| ledger | Append: the transaction | all but the library before and after the handler | +0.1% to +1.0% | 99.7% to 100% |
| gateway | POST /pay: the audit write | blocking pool + waiting to be run | −2.6% to +0.3% | 92.7% to 99.3% |
| risk | GET /score: its thread's CPU | CPU | +1.0% to +2.2% | 99.6% to 100% |
| risk | GET /score: asleep until account answered | downstream | −3.5% to +2.7% | 96.1% to 99.8% |
| risk | GET /score: its team's CPU | helpers: CPU | −11.2% to −4.7% | 57% to 97% |

Balance is over because the service times only its 100 us of computing, and
blame counts what the handler's goroutine used around it in the gRPC library
(some 15 us). The team's CPU is under because the service's figure is all that
the team's threads used while the pass ran, and blame's is what they used
inside their pieces of work; the rest is reported once for the process
(`openmp_team_idle_cpu_ns`: 32 to 76 us a request, against 41 to 108 by the
service's figure less blame's).

### A CPU taken from a Go service

In `cpu-payment` Charge went from 5.8 to 12.7 ms at p50, and blame says the
request waited 2 us for a CPU. What grew is its waits: on a lock from 2,385 to
6,762 us, on a channel from 4,063 to 5,653, the library before and after the
handler from 93 to 514. The services it waits for were not that much slower
(mean: Debit 1,973 to 2,897 us, the entry 3,798 to 3,469; the score at p50:
1,474 to 2,043). An answer that has arrived wakes a thread of the Go runtime,
which waits for a CPU before it can read it and make the goroutine runnable:
that thread works for no request yet, and its wait is counted for none.

The process's own line says it. What all the threads of each process waited
for a CPU, in ms per second, by what the CPU they were queued on did meanwhile
(a later run): a thread of the same process had it; a CPU limit kept them off
it; something else ran on it; it was idle (a wait counts from the wakeup, and
an idle CPU takes a while to be woken).

| service | `normal`: own | limit | others | idle | `cpu`: own | limit | others | idle | `cpu-payment`: own | limit | others | idle | `cpu-gateway`: own | limit | others | idle |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gateway | 64 | 0 | 188 | 71 | 66 | 0 | 199 | 89 | 65 | 0 | 128 | 33 | 99 | 0 | **363** | 0 |
| payment | 292 | 0 | 23 | 47 | 219 | 0 | 74 | 62 | 163 | 0 | **981** | 0 | 220 | 0 | 24 | 43 |
| account | 225 | 0 | 201 | 96 | 206 | 0 | 255 | 119 | 157 | 0 | 130 | 69 | 345 | 0 | **720** | 1 |
| ledger | 42 | 0 | 184 | 70 | 29 | 0 | 158 | 76 | 40 | 0 | 109 | 58 | 69 | 0 | **479** | 1 |
| risk | 307 | 0 | 23 | 133 | 612 | 0 | **595** | 0 | 506 | 0 | 26 | 86 | 339 | 0 | 43 | 129 |

payment has one CPU: in `normal` its threads wait mostly for each other, and
others have the CPU 23 ms a second. With the CPU taken, a second per second.
risk's threads wait 133 ms a second in `normal` for CPUs that are idle: its
team's threads are woken for each forward pass, on CPUs nothing else uses;
with those CPUs taken (`cpu`) the idle part is gone and others have them. The
figures are the process's: they are not divided among requests (one wait of a
thread can delay several requests, or none), and how much of a request's
longer wait on a lock or a channel they explain is not said. gateway, account
and ledger share two CPUs with each other and the load, so "others" is never
small for them: for each, the other two are others.

In `cpu-gateway` POST /pay went from 6.4 to 10.2 ms at p50. Here part of it is
in the requests: account's and ledger's handlers run on the taken CPUs, and
their wait for a CPU grew (mean: Debit 160 to 673 us, the entry 227 to 843).
The gateway's own line grew least of the three: a tokio task that passes a
call on uses some 50 us of CPU a request, and has little to wait for.

What the four figures cost, by the kernel's own count of the programs' time
(`kernel.bpf_stats_enabled`), this load, against a build without them, two
runs each: some 83 ns more at each switch of threads (190 to 271-275), 73
more at each wake-up (140 to 211-214), and 130 to 136 at each move of a
thread to another CPU, which had no program before. At 136,000 switches,
85,000 wake-ups and 17,500 moves a second on the machine that is 20 ms of CPU
a second, 0.3% of the six CPUs.

### payment in a container

In `docker` payment's binary runs in a container (its own PID, mount and
network namespaces, a cgroup), and every call to and from it crosses Docker's
bridge instead of the loopback. blame is given the process's pid on the host,
as for the others, and names the service `docker:<container>`. All 75,714
requests had their name, status and trace id. Against `normal`, mean per call
in us:

| service, request | figure | `normal` | `docker` |
|---|---|---|---|
| gateway, POST /pay | p50 | 6,388 | 6,434 |
| | waiting for another task (the call to payment) | 6,628 | 6,652 |
| payment, Charge | p50 | 5,542 | 5,566 |
| | CPU | 332 | 332 |
| | waiting: lock (the debit and the score) | 2,256 | 2,371 |
| | waiting: channel (the entry) | 3,793 | 3,703 |
| | library before and after the handler | 91 | 96 |
| payment's threads waiting for a CPU, ms per second | own threads / limit / others / idle | 292 / 0 / 23 / 47 | 314 / 0 / 18 / 48 |
| payment, against its own figure | waiting: lock + channel | −0.3% | −0.2% |

In `docker-cpu` the container may use a quarter of a CPU (`--cpus 0.25`).
Charge went from 5.6 to 6.3 ms at p50 and from 17 to 48 ms at p99, and as in
`cpu-payment` the request says it waited longer on a lock (2,371 to 4,232 us)
and on a channel (3,703 to 6,075), and 94 us for a CPU. payment's own line
says why, and that it is not the same thing as in `cpu-payment`:

| payment's threads, ms per second | own threads | limit | others | idle |
|---|---|---|---|---|
| `docker` | 314 | 0 | 18 | 48 |
| `docker-cpu` | 201 | **581** | 14 | 32 |
| `cpu-payment` (no container) | 163 | 0 | **981** | 0 |

Under the limit nothing else has the CPU: it is idle, and the kernel keeps the
container's threads off it until the next period. The limit figure is the
kernel's own count of that (kernels from 6.6). It is the threads' time, so it
is more than the group's `throttled_usec` in `cpu.stat` when several threads
wait at once.

## What is not seen

- How much of one request's time a CPU taken from its Go or tokio process,
  or a CPU limit on it, cost it: see above. Comparing the hops by trace id shows it for one request
  (payment waits 12.4 ms for answers that took some 6.5).
- A wait for memory: no scenario here. (The acceptance tests have one, on a C
  server.)
- risk's own thread asleep while its team works shows as "other blocked"; the
  team's two figures say what it was waiting for.
- What the gateway and payment wait for is named by kind (another task, a
  channel, a lock), not by callee: the callee is found by the trace id.
