# blame

Where the time of a service's requests went, from eBPF, without changing or
restarting the service: each HTTP/1.1 request and gRPC call split into time on
a CPU, waiting for one, and blocked on the disk, a downstream call, a file
service or a lock, by thread, goroutine or tokio task. Worked examples with
their figures are in `examples/` (`thread-server`, `torch-inference`,
`pay-demo`).

The kernel side is C (`blame/src/bpf/`), compiled with clang and loaded by
libbpf through [libbpf-rs](https://github.com/libbpf/libbpf-rs); the agent is Rust.

## Prerequisites

Build on Linux:

1. stable rust toolchain: `rustup toolchain install stable`
1. clang with the BPF target, libelf and zlib headers, e.g. on Ubuntu:
   `apt install clang make libelf-dev zlib1g-dev pkg-config`
   (add `libbpf-dev` for editor navigation in the C code; the build does not use it)

To run: root, and a kernel with BTF (`/sys/kernel/btf/vmlinux`). On a kernel
built without BTF, pass a BTF file for it (e.g. from BTFHub) with `--btf PATH`.
`slow` also needs tracefs (`/sys/kernel/tracing`), where its tracepoints are
found. In a container, run it privileged and give it the host's tracefs
(`-v /sys/kernel/tracing:/sys/kernel/tracing`); the host's PID namespace is
not needed, but then it sees only the processes of its own.
The binary links libbpf statically and libelf, zlib and zstd dynamically.

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Loading eBPF programs needs root:

```shell
cargo build --release
sudo ./target/release/blame                    # trace exec events
sudo ./target/release/blame top --duration 10  # how long runnable threads wait for a CPU, per service /
                                               # container / pod, any process (not only HTTP or gRPC)
sudo ./target/release/blame top --histogram    # also the whole machine's waits, bucket by bucket
sudo ./target/release/blame slow --above 100   # HTTP/1.1 requests and gRPC calls slower than 100 ms,
                                               # and where the time went
sudo ./target/release/blame slow --json --duration 30   # the same as JSON, one record a line:
                                               # the slowest calls, summaries by method, what was lost
./target/release/blame slow --json-fields      # what the JSON fields mean
```

`slow` needs Linux 5.17 or newer (6.0 on arm64) and has only been run on arm64.
Processes built with Go 1.18–1.27, or with tokio 1.49–1.54 and a symbol table,
are attributed by goroutine or task instead of by thread; `--threads-only`
turns that off. gRPC calls (plaintext HTTP/2) are shown by method, status and
trace id; their time is broken down for servers on grpc-go 1.40–1.85 and on
tokio (tonic), which get probes in the process; on connections older than the
agent those probes also read the method, trace id and status the process has
already decoded. HTTP/1.1 requests carry the trace id of their `traceparent`
header too, read as the headers arrive. `--deep` also follows the goroutines and tasks a request
spawns (tokio's `spawn_blocking` too) and shows their time apart, and why the
request's goroutine or task was on no thread: for Go, why it parked (a
channel, a lock, a timer, the network, the garbage collector, or waiting to
be run); for tokio's multi-thread and current-thread runtimes, what woke it (the network, a
timer, another task, the blocking pool, or waiting to be polled). It costs
some 10-13% of throughput on light Go requests (the default mode some 6-8%).
In a process attributed by thread that computes in parallel with GNU's OpenMP
runtime (libgomp: PyTorch's Linux wheels bring their own), `--deep` follows
the threads of a team that take up a request's work, and shows their time on
a CPU and waiting for one the same way: a forward pass of 4.5 ms whose thread
was on a CPU 3.7 ms had 14.6 ms more of its team's. Not what a team's threads
spin between regions, and not other OpenMP runtimes (LLVM's, Intel's) or
thread pools of other kinds (ONNX Runtime's: there, one thread per request,
`intra_op_num_threads=1`, is what is exact).
With the summaries comes, per traced process, what all its threads waited
for a CPU, in four parts by what the CPU they were queued on did meanwhile:
another of its own threads ran on it; a CPU limit of its control group kept
them off it (a container's, say: the kernel's own count, kernels from 6.6);
something else ran on it (the CPU was taken from the process); it ran
nothing but its idle task (a wait counts from the wakeup, and an idle CPU
takes a while to be woken). "Its own threads" says no more than that: other
CPUs may have been idle meanwhile, with threads kept to too few CPUs or more
Go threads allowed than CPUs, so it is not by itself a shortage of CPUs.
Interrupts are not a part of their own: they are in whichever part the CPU
was in when it handled them, "idle" included. Next to the four: what the
hypervisor took from the CPUs the process used (steal, as `/proc/stat` says
it; 0 also where the hypervisor does not say), and the most its control
groups were throttled by a CPU limit (`cpu.stat`), which is what tells of a
limit on kernels older than 6.6. That is where a Go or tokio service robbed
of its CPU, or out of its limit, shows: a request's own wait for a CPU stays
near zero there, because the runtime's thread that could not run was not yet
working for it, and the request only waits longer on a channel or a lock
(`examples/pay-demo`). The figures are the process's, not divided among
requests; another process of the same service is "something else".
A request's `on_cpu` is all the time its thread, goroutine or task was on a
CPU, in the kernel too, and so includes what the probes themselves cost there:
some 10 us a request on a Go server whose requests each spawn three goroutines,
and several times that when the VM it was measured on was slow.
Waits for a file on network storage or a FUSE filesystem (NFS such as EFS or a
NAS, SMB, virtiofs) are shown as `fileservice`, apart from the local disk;
the part of it spent waiting for a lock another thread held, mostly another
request writing or flushing the same file, is shown with it
(`fileservice=76ms(lock=72ms)`).
With `--tls`, HTTPS requests are read where OpenSSL's libssl, loaded as a
shared library, hands their plaintext over (`SSL_read`, `SSL_write` and their
`_ex` forms), and broken down the same way: on a C++ server with a thread per
connection, against its own figures, within 3% for each part, on connections
opened before blame as after. Each of those calls then costs a trap into the
kernel, some 40-50% of throughput on light requests, so it is off unless
asked for. What it does not read: TLS libraries other than OpenSSL (Go's
`crypto/tls`, rustls, Java's own), a TLS library linked into the program
instead of loaded (the BoringSSL that gRPC's CMake build and the `grpcio`
wheels bring), and OpenSSL used over buffers in memory rather than the
socket: gRPC's C++ core, also when built on the system's libssl, and Python's
asyncio, whose calls are counted as `tls_no_socket`.
Not covered yet: TLS other than the above, io_uring, a time breakdown for
HTTP/2 servers other than grpc-go and tonic (they get latency, method, status
and trace id), runtimes other than Go and tokio (they are seen thread by
thread), and x86_64 (written, not run).

(`CARGO_TARGET_DIR` may point elsewhere.) `cargo run` runs the agent as your
user, which cannot load eBPF programs; either run the built binary with sudo as
above, or set a local cargo runner that prefixes `sudo` (`.cargo/config.toml`
is not tracked).

`blame/build.rs` compiles the eBPF programs, generates the Rust skeleton
and embeds the object in the binary.

## Tests

```shell
cargo test                                # unit tests
./tests/scenarios/m0_acceptance.sh        # needs root and a built binary
./tests/scenarios/m1_acceptance.sh
./tests/scenarios/m2_acceptance.sh        # systemd; ENVS="systemd docker k8s" adds Docker and k3s
./tests/scenarios/m4_acceptance.sh        # requests against servers that log the answer; ONLY="1 3" runs sections;
                                          # the Go server needs a Go toolchain (GO=/path/to/go, or go on PATH)
./tests/scenarios/core_acceptance.sh      # CO-RE relocation against fake target layouts
./tests/scenarios/accuracy_acceptance.sh  # run-queue p99 / p99.9 against a known answer (systemd)
./tests/scenarios/cpu_wait.sh             # a process's four waits for a CPU against an oracle (bpftrace)
./tests/check.sh                          # fmt, clippy, unit tests; --full adds all scenarios above but core_acceptance
```

## License

blame is distributed under the [MIT license].

The one exception is the eBPF code that is loaded into the kernel
(`blame/src/bpf/`), which is available under either the [MIT license] or
the [GNU General Public License, Version 2], at your option. You can use it
under MIT terms; the GPL option is there because the kernel only lets
GPL-compatible programs call some of the helpers it uses (for example
`bpf_probe_read_kernel_str`).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you shall be licensed as above, without any
additional terms or conditions.

[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
