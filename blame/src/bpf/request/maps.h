/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/* The types and tables requests are followed with. */
#ifndef BLAME_REQUEST_MAPS_H
#define BLAME_REQUEST_MAPS_H

/* Only requests at least this slow are sent to user space. */
const volatile u64 req_slow_ns = 0;
/* Trace only the processes user space listed, not every one that accepts. */
const volatile u8 req_only_listed = 0;

/* User space raises this whenever it changes REQ_PROCS. */
volatile u32 rt_gen = 1;

/*
 * A bit per pid (its low 16 bits) that may be a traced process: set with its
 * entry in REQ_PROCS, never cleared. Lets the scheduler hook pass over the
 * threads of every other process without a lookup.
 */
#define PROC_BITS 65536
volatile u64 proc_bits[PROC_BITS / 64];

/* The agent is woken once for every this many unread bytes in the ring buffer. */
#define REQ_WAKE_BYTES (64 * 1024)
/* What one request takes in the ring buffer: the event and the record header. */
#define REQ_EVENT_BYTES (sizeof(struct request_event) + 8)

enum { CONN_CLIENT = 1, CONN_DOWN = 2 };

/* What a client-facing connection speaks, once that is known. */
enum { PROTO_UNKNOWN = 0, PROTO_HTTP1, PROTO_HTTP2 };

/* What a thread's time is spent on, as far as the kernel can tell. */
enum seg {
	SEG_CPU = 0,
	SEG_RUNQ,
	SEG_BLK_DOWN,
	SEG_BLK_CLIENT,
	SEG_BLK_IO,
	SEG_BLK_MEM,
	SEG_BLK_OTHER,
	/* Waiting for a file service: NFS, SMB, FUSE, virtiofs (request/fsvc.h). */
	SEG_BLK_FSVC,
	/*
	 * Of the waits for a file service, those for a lock (a sleep in a
	 * lock's slow path, request/fsvc.h): mostly, another request's write
	 * or flush of the same file holds it.
	 */
	SEG_BLK_FSVC_LOCK,
	SEG_MAX,
};

struct seg_acc {
	u64 ns[SEG_MAX];
};

/*
 * Why a goroutine bound to a request was off every thread (Go, with probes):
 * what it parked for (runtime.gopark's reason, by kind), or, PARK_QUEUE, it
 * did not park but was taken off its thread (preempted, yielded, or back
 * from a syscall whose P was taken) and waited to be run again.
 */
enum park {
	PARK_QUEUE = 0,
	PARK_CHAN,
	PARK_SYNC,
	PARK_SLEEP,
	PARK_NET,
	PARK_GC,
	PARK_OTHER,
	/*
	 * tokio, which says nothing of why a task waits; what woke it does
	 * (runtime/tokio_tasks.h): another task (a channel, a lock, a join
	 * handle: not told apart), or the blocking pool finishing work.
	 */
	PARK_TASK,
	PARK_BLOCKING,
	PARK_MAX,
};
/* The first seven are request_event.parked_ns, the rest come after it. */
_Static_assert(PARK_MAX == 9, "request_event.parked_ns, parked_task_ns, parked_blocking_ns");

/* What woke a sleeping thread. */
enum { WAKE_OTHER = 0, WAKE_CLIENT, WAKE_LISTEN, WAKE_DOWN };

struct conn {
	u8 cls;
	/* Downstream socket: the call in progress mixes two requests. */
	u8 mixed;
	u8 proto;
	/* Followed from its first byte and never lost since: what it carried is all known. */
	u8 fresh;
	u32 tgid;
	u16 lport;
	u16 rport;
	/* Responses still to come for requests that could not be queued. */
	u32 skip;
	struct http_dir rx;
	struct http_dir tx;
	/* Requests queued and answered since the connection was first seen. */
	u32 pushed;
	u32 popped;
	/* Bit (n & 15): the n-th request is a HEAD. */
	u32 head_mask;
	u32 _pad2;
	/* Ids of the requests awaiting a response, oldest at popped. */
	u64 queue[REQ_QUEUE];
	/* Client socket: readable since, with nothing read yet; 0 = not known. */
	u64 ready_ns;
	u64 last_tx_ns;
	/* Downstream socket: the request the last call was made for. */
	u64 owner_req;
	/* The call's first write started at; 0 = no call seen. */
	u64 sent_ns;
	/* The first byte of its answer arrived at; 0 = not yet. */
	u64 answer_ns;
	/* The latest bytes of its answer arrived at. */
	u64 arrived_ns;
	/* The request has been charged up to this read; 0 = nothing read yet. */
	u64 read_ns;
	/* ... and up to this arrival. */
	u64 read_arrived_ns;
	/* HTTP/2: the two directions, the highest stream opened, streams open now. */
	struct h2_dir h2rx;
	struct h2_dir h2tx;
	u32 h2_max_sid;
	u32 h2_open;
	/*
	 * Client socket: TLS, its bytes taken from the TLS library's calls
	 * (tls/tls.h), not from the socket calls, which carry ciphertext.
	 */
	u8 tls;
	/* Its first bytes were looked at for a TLS handshake (TLS_UNREAD). */
	u8 tls_hello;
	/*
	 * Kernel TLS has the keys of these directions (KTLS_RX, KTLS_TX): on a
	 * connection left to a TLS library at its handshake (tls 2), their
	 * socket calls carry plaintext from then on.
	 */
	u8 ktls;
	u8 _pad_tls[5];
	char rx_line[REQ_LINE_LEN];
};

struct req_state {
	u64 start_ns;
	u64 ready_ns;
	u64 cgroup_id;
	struct unit_key first_unit;
	u32 tgid;
	u32 first_tid;
	u16 lport;
	u16 rport;
	u8 line_len;
	u8 flags;
	u8 _pad[2];
	/* HTTP/2: the stream. */
	u32 stream_id;
	u32 _pad2;
	struct seg_acc acc;
	/* Time its unit spent off every thread, by why (enum park). */
	u64 park[PARK_MAX];
	/* Time of the units it spawned (SRC_SPAWN), kept apart. */
	struct seg_acc helper;
	u64 helpers;
	u64 observed_ns;
	u64 retro_ns;
	u64 down_wait_ns;
	u64 down_service_ns;
	u64 down_transfer_ns;
	u64 down_calls;
	char line[REQ_LINE_LEN];
	/* HTTP/2: the connection, as header events name it. */
	u64 conn;
	/*
	 * When the handler a runtime bound it to (SRC_RUNTIME) first ran for it;
	 * 0 = not yet, or not known exactly (no switch probes).
	 */
	u64 handler_on_ns;
	/*
	 * When that handler was given another request while this one was in
	 * flight (a pooled handler moves on before the response is written): it
	 * left this one then. 0 = it did not.
	 */
	u64 handler_left_ns;
	/* HTTP/1, with REQ_F_TRACE: the trace id of its traceparent header. */
	u8 trace[16];
	/*
	 * How it ended, written by req_end() for req_end_of(): a global function
	 * is handed the request's id only (see there).
	 */
	u64 end_ns;
	struct unit_key end_unit;
	u32 end_tid;
	u16 end_status;
	u8 end_flags;
	u8 end_answered;
};

/*
 * Per-thread state, in task storage: it exists only for threads of traced
 * processes that made a socket call, costs no hash lookup to reach, and goes
 * away with the thread.
 */
struct carrier {
	/* Arguments of the call in flight; sc_nr 0 = none. */
	u64 sc_fd;
	u64 sc_a1;
	u64 sc_a2;
	u64 sc_a3;
	/* When a write was entered. */
	u64 sc_ns;
	u8 sc_nr;
	/* A wakeup has been recorded for the current sleep. */
	u8 woken;
	/* TCP state of the socket whose data woke it. */
	u8 wake_state;
	/* enum attr_source of the binding. */
	u8 source;
	/* What the kernel said the current sleep is for: a SEG_BLK_*, or 0. */
	u8 off_seg;
	/* The unit's last socket call found nothing to do: it is about to park. */
	u8 would_block;
	/*
	 * Depth of flush-to-disk calls (fsync and the like) on a filesystem
	 * backed by a block device the thread is inside: its sleeps there wait
	 * for the disk, though the kernel does not mark all of them so.
	 */
	u8 in_sync;
	/*
	 * Depth of waits for a file service the thread is inside: its sleeps
	 * there wait for a server or a process, not the disk (request/fsvc.h).
	 */
	u8 in_fsvc;
	/* The process's entry in REQ_PROCS, as of rt_gen. */
	u32 rt_gen;
	/*
	 * The functions of fsvc.h the thread is inside, as a stack: how deep,
	 * and at which depths one was a wait for a file service.
	 */
	u32 fsvc_levels;
	u8 fsvc_depth;
	/*
	 * Depth of flush calls (fsync and the like) on a file service the
	 * thread is inside: its sleeps there wait for the service, those for
	 * the file's lock while another thread writes or flushes it included.
	 */
	u8 in_sync_fsvc;
	/*
	 * Which of the two depths above the fsync or fdatasync call the thread
	 * is in raised (SYNC_*), to lower it on the way out, where the file is
	 * not known.
	 */
	u8 sync_sys;
	/* Depth of the lock slow paths of fsvc.h the thread is inside. */
	u8 in_lock;
	/*
	 * tokio, with PROC_F_PARK: the thread is in the I/O driver's turn
	 * (DRV_IO) or firing timers (DRV_TIME), or 0; it is polling a task of
	 * the blocking pool.
	 */
	u8 drv;
	u8 in_blocking;
	u8 _pad2[3];
	/* Go: where runtime.execute starts in this process, as its probe saw it (0: not yet). */
	u64 go_execute_pc;
	/* The thread's own number, as the agent numbers it (0: not said yet). */
	u32 self_tid;
	/* Its unit was taken by another thread while it waited for a CPU (units.h). */
	u8 taken;
	u8 _pad5[3];
	struct proc_cfg rt;
	/*
	 * The unit last seen running on this thread: the thread itself, or what
	 * its runtime said at the last socket call or switch-out.
	 */
	struct unit_key unit;
	/* The request that unit is bound to; 0 = none. */
	u64 req_id;
	/* The client socket that request came in on. */
	u64 req_sk;
	/* On a CPU since; 0 = not running. */
	u64 on_ns;
	/* Asleep since; 0 = not asleep. */
	u64 off_ns;
	/* Runnable since, possibly with RUNQ_RACE; 0 = not waiting. */
	u64 runq_ns;
	u64 wake_sk;
	/* The request the waking thread was bound to. */
	u64 waker_req;
	/*
	 * Go: the request the unit was bound to when it entered newproc1, to be
	 * given to the goroutine newproc1 returns; 0 = none.
	 */
	u64 spawn_req;
	/* Time of the bound request not yet added to it. */
	struct seg_acc acc;
	/* Time while unbound, waiting to be claimed. */
	struct seg_acc pend;
	/* Its last wait for a CPU: from when it was runnable to when it ran. */
	u64 rq_from;
	u64 rq_to;
	/*
	 * OpenMP (runtime/omp.h): the thread whose team it was last seen working
	 * in (0: none), and whether it is inside a piece of that team's work now.
	 */
	u32 omp_team;
	u8 omp_bound;
	u8 _pad3[3];
	/*
	 * What it has waited for a CPU, working for no request, while the region
	 * its team's thread opened at omp_wait_open was open: the region's if it
	 * goes on to take up a piece of that region's work.
	 */
	u64 omp_wait_ns;
	u64 omp_wait_open;
	/*
	 * Its wait for a CPU now (request/proc_cpu.h): the CPU it is queued on,
	 * what threads of its own process had run there when it joined that
	 * queue, and what they ran on the queues it was on before.
	 */
	u64 rq_own0;
	u64 rq_own;
	/* The same for what that CPU was idle, and for its group's queue being throttled. */
	u64 rq_idle0;
	u64 rq_idle;
	u64 rq_limit0;
	u64 rq_limit;
	u32 rq_cpu;
	/* Those above are set: it is waiting, and was seen to start. */
	u8 rq_snap;
	u8 _pad4[3];
	/*
	 * The TLS library call in flight (tls/tls.h); tls_fn 0 = none: the
	 * session, the caller's buffer, where the _ex forms write the length,
	 * the socket a socket call made inside it went to, and the stack
	 * pointer at its entry.
	 */
	u64 tls_ssl;
	u64 tls_buf;
	u64 tls_outp;
	u64 tls_sk;
	u64 tls_sp;
	u8 tls_fn;
	/*
	 * rustls (tls/rustls.h): plaintext handed to the library to send whose
	 * socket is the next socket call's, if that is a write of the same unit:
	 * rs_tx buffers (0 = none), the last of them bytes not seen if its base
	 * is 0, rs_tx_total bytes in all. Copied when handed over: rustls's list
	 * of them is gone by the write.
	 */
	u8 rs_tx;
	u8 _pad6[6];
	u64 rs_tx_base[HTTP_SEGS];
	u64 rs_tx_len[HTTP_SEGS];
	u64 rs_tx_total;
	struct unit_key rs_tx_unit;
	/* The socket the thread last read from, and the unit that read it. */
	u64 rs_rd_sk;
	struct unit_key rs_rd_unit;
};

/*
 * BIND_TAKEN: another thread took the unit while the one it was on was off
 * its CPU, and counted that wait (unit_on). The two threads settle who
 * counts it by changing BIND_WAITING or BIND_ASLEEP, whichever does first.
 */
enum { BIND_OFF = 0, BIND_RUNNING, BIND_WAITING, BIND_ASLEEP, BIND_TAKEN };

/* What a unit that is not a thread is bound to, wherever it runs next. */
struct binding {
	u64 req_id;
	u64 req_sk;
	u8 source;
	/* Parked after a socket call that found nothing to do: it resumes by repeating the call. */
	u8 io_parked;
	/* Off every thread since off_ns (0 = on one), for that reason (enum park). */
	u8 off_why;
	/* A handler (SRC_RUNTIME) that has run since it was bound. */
	u8 ran;
	/* tokio: woken since it left its thread; off_ns is since then. */
	u8 woke;
	/* The wait up to the take was counted when the take was seen (unit_on). */
	u8 taken_paid;
	u8 _pad[2];
	/*
	 * A thread took the unit while the thread it was on (taken_from) had
	 * not said it had left it: since when. What that thread did and waited
	 * from then on was not the unit's.
	 */
	u64 taken_ns;
	u32 taken_from;
	/*
	 * What the thread it is on is doing with it, and since when, as that
	 * thread last said (BIND_*; 0 while it is on none): its request can end
	 * on another thread, which then counts the stretch still open.
	 */
	u32 doing;
	u64 since;
	u64 off_ns;
	/*
	 * The thread it was last seen put on (0: none yet). A thread learns late
	 * that it no longer runs a unit (at its next switch, or when it goes to
	 * sleep); by then another thread may run the unit, and it has not left.
	 */
	u32 on_tid;
	u32 _pad2;
};

/* An HTTP/2 stream in flight: which request it is. */
struct stream_key {
	u64 sk;
	u32 sid;
	u32 _pad;
};

/* A grpc-go server transport: one per connection. */
struct transport_key {
	u64 addr;
	u32 tgid;
	u32 _pad;
};

/* A kind of tokio task in one process, by the address of its vtable. */
struct task_kind {
	u64 vtable;
	u32 tgid;
	u32 _pad;
};

/* Where tasks of one kind keep the id of the HTTP/2 stream they serve. */
struct task_stream_off {
	/* Two places that hold it; TASK_OFF_NONE in `a`: looked for and not found. */
	u16 a;
	u16 b;
};
#define TASK_OFF_NONE 0xffff

struct listen_key {
	u32 netns;
	u16 port;
	u16 _pad;
};

struct wake_ctx {
	u64 sk;
	u8 state;
};

/* Connections, keyed by the address of their struct sock. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, u64);
	__type(value, struct conn);
} REQ_CONNS SEC(".maps");

/*
 * OpenMP (runtime/omp.h). A thread that enters a parallel region hands out
 * work by a pointer to what the region shares, on its own stack: every thread
 * of the team is given that pointer. `at` is that pointer (OMP_REGIONS), the
 * thread that opened the region (OMP_OPEN), or the address of a region's
 * function (OMP_FNS).
 */
struct omp_key {
	u64 at;
	u32 tgid;
	u32 _pad;
};

struct omp_region {
	/* The request the thread that opened it was working for. */
	u64 req_id;
	u64 open_ns;
	u64 data;
	/* The thread that opened it. */
	u32 master;
	u32 _pad;
};

/* Open regions, by the pointer their work is handed out with. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct omp_key);
	__type(value, struct omp_region);
} OMP_REGIONS SEC(".maps");

/* The same, by the thread that opened them: one region per thread at a time. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct omp_key);
	__type(value, struct omp_region);
} OMP_OPEN SEC(".maps");

/*
 * Functions regions have been seen to run: OMP_FN_NEW until user space has
 * put probes on one, then OMP_FN_PROBED, or OMP_FN_FAILED.
 */
enum { OMP_FN_NEW = 0, OMP_FN_PROBED = 1, OMP_FN_FAILED = 2 };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct omp_key);
	__type(value, u8);
} OMP_FNS SEC(".maps");

/* Requests in flight, keyed by request id. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, u64);
	__type(value, struct req_state);
} REQ_TABLE SEC(".maps");

/*
 * HTTP/2 streams in flight -> request id. One connection carries many, so
 * they are not kept with the connection.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct stream_key);
	__type(value, u64);
} REQ_STREAMS SEC(".maps");

/* Traced processes, keyed by tgid. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct proc_cfg);
} REQ_PROCS SEC(".maps");

/*
 * A traced process on one CPU (request/proc_cpu.h): what its threads ran
 * there, and what they waited to run there: while a thread of the same
 * process had the CPU, while a CPU limit kept them off it, while the CPU was
 * idle, and while anything else had it. Written on that CPU.
 */
struct proc_cpu_key {
	u32 tgid;
	u32 cpu;
};

/*
 * A sum of time that another CPU may read while this one adds to it: what
 * has run so far, or, while it runs (PROC_OPEN set), that less the time it
 * started, so that the reader adds the time it is. One word: a read is of
 * one moment, with no lock.
 */
#define PROC_OPEN (1ULL << 63)

struct proc_cpu {
	/* What the process's threads ran here (as above: open while one runs). */
	u64 ran_ns;
	u64 wait_own_ns;
	u64 wait_others_ns;
	u64 wait_limit_ns;
	u64 wait_idle_ns;
};

/*
 * Sized by user space for the machine's CPUs (slow/attach.rs), which also
 * removes the entries of processes that are gone once it has read them.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct proc_cpu_key);
	__type(value, struct proc_cpu);
} PROC_CPU SEC(".maps");

/*
 * A CPU now. Only that CPU reads the first three: the traced process whose
 * thread it is running (0: none) or that it is idle, and since when. Others
 * read the last two: how long it has been idle in all (a sum as PROC_OPEN
 * says, open while it is idle), and how far the clock of its run queue is
 * behind ours, as of its last switch.
 */
struct cpu_now {
	u64 since;
	u32 tgid;
	u32 idle;
	u64 idle_ns;
	u64 clock_off;
};

/* Whether this kernel says how long a group's queue was throttled (kernel.h). */
volatile u8 proc_limit_known;

#define PROC_CPUS_MAX 4096

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, PROC_CPUS_MAX);
	__type(key, u32);
	__type(value, struct cpu_now);
} CPU_NOW SEC(".maps");

/*
 * Bindings of goroutines and tasks, which move between threads. A unit that
 * dies bound (its connection was cut, or it was spawned for a request and
 * ended) leaves its entry behind; ids are not reused, so it is only ever
 * pushed out by newer ones. Sized for spawned units: one request can leave
 * several.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct unit_key);
	__type(value, struct binding);
} UNIT_BINDING SEC(".maps");

/*
 * The client-facing HTTP/2 connection a goroutine or task last read from
 * when the connection got in step or a stream was opened: the one that
 * owns the connection, as opposed to those that handle its streams.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct unit_key);
	__type(value, u64);
} UNIT_READS SEC(".maps");

/*
 * Go, following spawned goroutines: per process, the link-time address of
 * runtime.newproc1 (where the binary is loaded follows from where the probe
 * on it fires) ...
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, u64);
} SPAWN_BASE SEC(".maps");

/* ... and the runtime's own functions a goroutine can start at, by link-time address. */
struct spawn_skip_key {
	u64 addr;
	u32 tgid;
	u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct spawn_skip_key);
	__type(value, u8);
} SPAWN_SKIP SEC(".maps");

/* Go: what each wait reason of a process's Go version is (enum park). */
struct go_wait_key {
	u32 tgid;
	u32 reason;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct go_wait_key);
	__type(value, u8);
} GO_WAIT_KIND SEC(".maps");

/* Filesystems, by the address of their super_block: FSVC_* once looked at. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u8);
} SB_KIND SEC(".maps");

/* grpc-go: server transport -> its connection. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct transport_key);
	__type(value, u64);
} GO_TRANSPORTS SEC(".maps");

/*
 * tokio, with PROC_F_TOKIO_BLOCKING: tasks seen spawned on the blocking
 * pool. Never removed; task ids are not reused, so an entry is only pushed
 * out by newer ones.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct unit_key);
	__type(value, u8);
} TOKIO_BLOCKING SEC(".maps");

/* tokio: filled in by user space once it has found the place (or given up). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct task_kind);
	__type(value, struct task_stream_off);
} TASK_STREAM_OFF SEC(".maps");

/* Per-CPU scratch for a task sample (too large for the stack). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct task_sample_event);
} REQ_SCRATCH_TASK SEC(".maps");

/*
 * Ports that were listening when the agent started. A socket first seen with
 * data on it (it was open before the agent attached) is client-facing if its
 * local port is one of them.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct listen_key);
	__type(value, u8);
} REQ_LISTEN SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct carrier);
} REQ_CARRIER SEC(".maps");

/* cgroup id -> request latency histogram, with the run-queue bucket layout. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct runq_hist);
} REQ_GROUP_HIST SEC(".maps");

/*
 * Per-CPU scratch: values too large for the stack. Only the socket-call
 * programs use them; those are tracepoint programs, which run with preemption
 * off, so a slot is never shared by two of them.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct conn);
} REQ_SCRATCH_CONN SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct req_state);
} REQ_SCRATCH_REQ SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct http_run);
} REQ_SCRATCH_HTTP SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct h2_run);
} REQ_SCRATCH_H2 SEC(".maps");

/* The socket whose data is being delivered on this CPU right now. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct wake_ctx);
} REQ_WAKE SEC(".maps");

u64 req_next_id;

/* The fd table holds this for every socket. */
extern const void socket_file_ops __ksym;

/* The bytes one socket call moved, as the protocol code is given them. */
struct call_data {
	u64 base[HTTP_SEGS];
	u64 len[HTTP_SEGS];
	u32 nseg;
	/* A vectored call had more segments than `base` holds. */
	u32 truncated;
	/* The vector itself, for a parser that walks all of it; 0 = one buffer. */
	u64 iov;
	u64 iovcnt;
	/* Bytes transferred. */
	u64 total;
};

#endif
