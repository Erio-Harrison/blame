# PyTorch inference

What `blame slow --deep` tells about a request that is computed in parallel:
a PyTorch server on the CPU, one thread per connection. The thread that
handles a request does a fifth of the computing; a team of OpenMP threads
does the rest, and they are not the request's thread.

```
load ──HTTP──▶ server.py ── forward pass ──▶ 11 parallel regions, 6 threads each
                 │                            (the handler's and 5 of its team)
                 └─ one thread per connection, each with a team of its own
```

`GET /infer` runs one forward pass of a small network (three linear layers,
batch 64). Every request carries a `traceparent`. The server writes down what
each request cost by its own measure: the handling thread's CPU, and what the
kernel counted for the threads of its team meanwhile
(`/proc/self/task/<tid>/schedstat`). `report.py` joins that with blame's
figures by trace id.

## Scenarios

| scenario | what is different | what blame should say |
|---|---|---|
| `normal` | nothing | the request used several times the CPU its own thread did |
| `cpu` | six processes spin on the machine's CPUs | its team waits for a CPU: the machine |
| `spin` | a team's idle threads spin a while before they sleep (OpenMP's default; in the other two they sleep at once) | CPU that is no request's |

## Running

Needs root through `sudo` (blame) and a Python with PyTorch, for example:

```sh
python3 -m venv /tmp/torch-venv
/tmp/torch-venv/bin/pip install --index-url https://download.pytorch.org/whl/cpu torch
```

Then, with blame built (`cargo build --release`):

```sh
export PYTHON=/tmp/torch-venv/bin/python
for s in normal cpu spin; do examples/torch-inference/run.sh $s /tmp/torch-inference; done
examples/torch-inference/report.py /tmp/torch-inference normal cpu spin
```

Each run loads the server for 8 s on one connection, one request at a time.

## What it showed (2026-11-19, the arm64 VM, 6 CPUs, torch 2.15.0+cpu)

Mean per request, in ms:

| | `normal` | `cpu` | `spin` |
|---|---|---|---|
| took | 4.66 | 22.39 | 4.61 |
| its thread: on a CPU | 3.76 | 4.29 | 3.46 |
| its thread: waiting for a CPU | 0.22 | 5.26 | 0.10 |
| its thread: asleep | 0.67 | 12.84 | 1.05 |
| **its team: on a CPU** | **13.41** | **16.38** | **14.90** |
| **its team: waiting for a CPU** | 0.99 | **16.58** | 0.21 |
| its team: pieces of work | 55 | 55 | 55 |

The team's two rows are what `--deep` adds. Without them:

- `normal` looks like a request that computes 3.8 ms on one thread. It used
  17.2 ms of CPU, 3.7 times what it took: two of them at a time fill this
  machine.
- `cpu` is five times slower, and its thread shows 12.8 ms asleep for a
  reason that is not known. It was waiting for its team, and the team waited
  16.6 ms for a CPU: the machine, not the program.

Against the server's own figures:

| | `normal` | `cpu` | `spin` |
|---|---|---|---|
| the handler's thread on a CPU | −0.1%, 100% of requests within 100 us or 10% | −0.2%, 100% | +0.4%, 100% |
| its team on a CPU | −5.5%, 100% | −7.5%, 99% | −18.7%, 0% |

The team's row is under, most in `spin`, because the two do not count the
same thing. The server's figure is all the CPU the team's threads used while
the request ran. blame's is what they used inside the pieces of work they
took up; what they spin in between (for the rest of the team to finish a
region, or for the next region) is no request's work, and blame reports it
once for the process (`openmp_team_idle_cpu_ns`):

| | `normal` | `cpu` | `spin` |
|---|---|---|---|
| the server's team figure less blame's, per request | 0.78 ms | 1.33 ms | 3.42 ms |
| the teams' CPU outside their pieces of work, by blame, per request | 0.50 ms | 0.64 ms | 3.40 ms |

In `spin` that is a fifth of what the team used. Sampled, it was threads
spinning in two places of libgomp: `gomp_team_barrier_wait_end`, done with
their piece and waiting for the others, and `gomp_barrier_wait_end`, waiting
for the next region. `OMP_WAIT_POLICY=passive` makes them sleep instead
(`normal`).

The team's wait for a CPU is counted from when a thread is woken, the
kernel's figure in `schedstat` from when it is on a run queue, and blame
counts it only for a thread that goes on to take up a piece of that region:
the two are not the same number (20.6 against 16.6 ms in `cpu`).

## What is not followed

- The first regions that run a function blame has not seen yet: it puts its
  probes on a region's function when a region is first seen to run it, and
  that takes up to 0.2 s. They are counted (`omp_region_unfollowed`: 161,
  40 and 231 regions in the runs above, of 18,600, 3,900 and 18,800).
- Other OpenMP runtimes than GNU's (LLVM's, Intel's), and thread pools of
  other kinds: ONNX Runtime's, for one. There, one thread per request
  (`intra_op_num_threads=1`) is the configuration blame is exact for.
- What runs on a GPU.
- `torch.set_num_threads(1)` does not make this model single-threaded on
  arm64 (the Arm Compute Library still opens regions of six threads);
  `OMP_NUM_THREADS=1` does.
