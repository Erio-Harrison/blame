/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Wire format shared with userspace. `blame-common` defines the same types
 * in Rust; both sides assert the sizes and offsets below, so a change on one
 * side that is not mirrored on the other fails the build. Any layout change
 * must bump EVENT_VERSION.
 */
#ifndef BLAME_H
#define BLAME_H

#define EVENT_VERSION 2
#define COMM_LEN 16
#define FILENAME_LEN 128
#define CGROUP_PATH_LEN 512
/*
 * Run-queue histogram: 0-3 us one bucket each, then 4 linear buckets per power
 * of two up to 2^25 us (~33.5 s), then one overflow bucket.
 */
#define RUNQ_BUCKETS 97
#define RUNQ_OVERFLOW_US (1ULL << 25)
/* Bytes kept of a request line ("GET /path"); the query string is not kept. */
#define REQ_LINE_LEN 64
/* Bytes of an HTTP/2 header block carried by one event. */
#define H2_HDR_CHUNK 256
/* Bytes of a new task looked at to find which stream it serves. */
#define TASK_SAMPLE_LEN 512

enum event_kind {
	EVENT_EXEC = 1,
	EVENT_CGROUP_MKDIR = 2,
	EVENT_REQUEST = 3,
	EVENT_H2_HEADERS = 4,
	EVENT_TASK_SAMPLE = 5,
	EVENT_H2_FIELDS = 6,
};

struct event_header {
	u16 version;
	u16 kind;
	u16 cpu;
	u16 _pad;
	/* bpf_ktime_get_boot_ns: includes suspend, so it maps to wall clock. */
	u64 ts_boot_ns;
	u64 cgroup_id;
	/* Reserved for Kubernetes deduplication; zero on bare metal. */
	u32 netns_id;
	u32 ifindex;
	u32 pid;
	u32 tid;
};

struct exec_event {
	struct event_header hdr;
	char comm[COMM_LEN];
	char filename[FILENAME_LEN];
	u32 old_pid;
	u32 _pad2;
};

struct cgroup_mkdir_event {
	struct event_header hdr;
	u64 id;
	/* Hierarchy id; 0 is cgroup v2. */
	s32 root;
	u32 _pad2;
	char path[CGROUP_PATH_LEN];
};

/*
 * What a runtime schedules. Threads, goroutines and tokio tasks are
 * produced; the other values are reserved so the wire format does not change
 * when their adapters arrive.
 */
enum unit_kind {
	UNIT_THREAD = 1,
	/* The carrier runs the runtime's own code, not any unit. */
	UNIT_RUNTIME = 2,
	UNIT_GOROUTINE = 3,
	UNIT_VTHREAD = 4,
	UNIT_TOKIO_TASK = 5,
	UNIT_PY_CONTEXT = 6,
	UNIT_NODE_ASYNC = 7,
	UNIT_DOTNET_TASK = 8,
	UNIT_COROUTINE = 9,
};

struct unit_key {
	u32 tgid;
	u8 kind;
	u8 _pad[3];
	/* Thread: tid. */
	u64 id;
};

/* What schedules the execution units of a process. */
enum runtime {
	/* Not looked at yet: treated as RT_NONE until user space has. */
	RT_UNKNOWN = 0,
	/* The kernel: the unit is the thread. */
	RT_NONE = 1,
	RT_GO = 2,
	RT_TOKIO = 3,
};

/*
 * A traced process, and how to read the unit running on one of its threads.
 * User space fills this in from the process's binary.
 */
struct proc_cfg {
	u8 runtime;
	/* PROC_F_* */
	u8 flags;
	/* Go: offsets of g.m, g.goid, m.g0, m.curg and m.gsignal. */
	u16 go_g_m;
	u16 go_g_goid;
	u16 go_m_g0;
	u16 go_m_curg;
	u16 go_m_gsignal;
	/* tokio: where the current task id is, relative to the thread pointer. */
	s32 tokio_task_id;
	/*
	 * grpc-go: how the HTTP/2 stream id is read behind the stream pointer
	 * the server hands to a handler. GRPC_ID_*; the offset is in bytes.
	 */
	u8 grpc_id_how;
	/*
	 * grpc-go: the argument register (0-based, as go_arg counts) that holds
	 * the decoded header frame in (*http2Server).operateHeaders. 0: the
	 * decoded headers of this version cannot be read.
	 */
	u8 grpc_frame_arg;
	u16 grpc_id_off;
	/*
	 * Rust (h2): where the Vec of a http::HeaderMap's entries keeps its
	 * pointer and its length, in the map. 0: not readable.
	 */
	u16 rs_entries_ptr;
	u16 rs_entries_len;
};

/*
 * Probes in the process report every unit switch on its threads, so the
 * runtime is not asked which unit is running.
 */
#define PROC_F_UNIT_PROBES 1
/*
 * Goroutines and tasks spawned by a unit bound to a request work for that
 * request (SRC_SPAWN). Set only when the user asked for it: Go needs probes
 * on goroutine creation for it.
 */
#define PROC_F_SPAWN 2
/*
 * Go: probes say when a goroutine parks and why, and when it is run again:
 * where a request's goroutine was while on no thread (request_event.parked_ns).
 * tokio: probes say what woke a task (runtime/tokio_tasks.h).
 */
#define PROC_F_PARK 4
/*
 * Go: a probe where the scheduler puts a goroutine on a thread
 * (runtime.execute) reports every switch to one; switches away are seen at
 * the next of those or the next kernel event.
 */
#define PROC_F_GO_EXECUTE 8
/*
 * tokio, with PROC_F_PARK: a task of the blocking pool is one seen spawned
 * there (TOKIO_BLOCKING), not one polled through a poll function of the
 * pool's kind of task: user space could not tell those apart by name (the
 * legacy mangling leaves their type arguments out).
 */
#define PROC_F_TOKIO_BLOCKING 16
/*
 * The process's TLS library is read (--tls): a connection that begins with
 * a TLS handshake is not counted as unread (TLS_UNREAD).
 */
#define PROC_F_TLS_READ 32
/* setsockopt: kernel TLS's level, and its option that takes up reading. */
#define SOL_TLS 282
#define TLS_RX 2
/*
 * Go's crypto/tls is read: its calls in flight are kept by goroutine
 * (GO_TLS_CALLS), and a socket call made inside one shows its connection.
 */
#define PROC_F_GO_TLS 64

enum {
	GRPC_ID_NONE = 0,
	/* A u32 at the offset from the stream pointer. */
	GRPC_ID_DIRECT = 1,
	/* The stream starts with a pointer; a u32 at the offset from that. */
	GRPC_ID_BEHIND_PTR = 2,
};

/* How a stretch of time came to be attributed to a request. */
enum attr_source {
	SRC_NONE = 0,
	/* The unit itself read the request. */
	SRC_OBSERVED = 1,
	/* The runtime's own record of a handoff. */
	SRC_RUNTIME = 2,
	/* A marker from an in-process component. */
	SRC_INPROC = 3,
	/* Claimed when the unit wrote the response. */
	SRC_RETRO = 4,
	/* Joined in userspace after the fact. */
	SRC_JOINED = 5,
	/* The parent unit's binding, read lazily. */
	SRC_LAZY_PARENT = 6,
	/* Inferred; never shown for a single request. */
	SRC_INFERRED = 7,
	/*
	 * Started by a unit bound to the request, while it was: a goroutine or
	 * task the request spawned. Its time is the request's helpers'.
	 */
	SRC_SPAWN = 8,
};

/* request_event.flags */
#define REQ_F_LINE_TRUNCATED 1
/* The response had no length and ended when the connection closed. */
#define REQ_F_ENDED_BY_CLOSE 2
/* An HTTP/2 stream: there is no request line, and no time by thread. */
#define REQ_F_HTTP2 4
/*
 * An HTTP/2 stream that was reset instead of answered: by the client (a
 * call cancelled, or past its deadline), or by the server (refused). Its
 * end is the reset, and its times are those up to then.
 */
#define REQ_F_RESET_CLIENT 8
#define REQ_F_RESET_SERVER 16
/*
 * A runtime handed the request to a handler and probes reported its
 * switches: before_handler_ns and after_handler_ns are known.
 */
#define REQ_F_HANDLER_TIMED 32
/* HTTP/1: the request had a traceparent header; request_event.trace holds its trace id. */
#define REQ_F_TRACE 64
/* The request came over TLS: its bytes were taken from the TLS library's calls. */
#define REQ_F_TLS 128

/*
 * One finished request: from the first byte of the request read on a
 * client-facing socket to the last byte of the response written.
 * hdr.ts_boot_ns is the start; hdr.pid/tid/cgroup_id are of the thread that
 * read it.
 */
struct request_event {
	struct event_header hdr;
	u64 req_id;
	u64 end_boot_ns;
	/* When the socket became readable before the first read; 0 = not seen. */
	u64 ready_boot_ns;
	/* The unit that read the request, and the one that wrote its last byte. */
	struct unit_key first_unit;
	struct unit_key last_unit;
	/* Time of the units working for this request, by what they were doing. */
	u64 cpu_ns;
	u64 runq_ns;
	/* Asleep until the request's own downstream socket had data. */
	u64 blocked_down_ns;
	/* Asleep until the client sent more of the request. */
	u64 blocked_client_ns;
	/* Asleep in the block layer: a disk read or write. */
	u64 blocked_io_ns;
	/* Asleep because memory was short: reclaim, throttling, refault. */
	u64 blocked_mem_ns;
	u64 blocked_other_ns;
	/* The same time split by how it was attributed. */
	u64 observed_ns;
	u64 retro_ns;
	/*
	 * Downstream calls made while a unit was bound to the request. A call
	 * runs from the start of the write on the downstream socket to the last
	 * read of its answer (wait). Of that: until the first byte of the answer
	 * arrived (service), and from then until the last byte arrived
	 * (transfer). The rest is the answer waiting to be read.
	 */
	u64 down_wait_ns;
	u64 down_service_ns;
	u64 down_transfer_ns;
	u32 down_calls;
	u32 last_tid;
	/* HTTP/2 (REQ_F_HTTP2): the stream the request was. */
	u32 stream_id;
	u32 _pad2;
	u16 lport;
	u16 rport;
	u16 status;
	u8 flags;
	u8 line_len;
	char line[REQ_LINE_LEN];
	/* The connection the request came in on: what h2_headers_event.conn names. */
	u64 conn;
	/*
	 * Time of the units the request spawned (SRC_SPAWN), and of what they
	 * spawned, by what they were doing, as for the unit serving it. They
	 * can run side by side, so this can add up to more than the latency.
	 */
	u64 helper_cpu_ns;
	u64 helper_runq_ns;
	u64 helper_down_ns;
	u64 helper_client_ns;
	u64 helper_io_ns;
	u64 helper_mem_ns;
	u64 helper_other_ns;
	/* Units spawned for the request. */
	u32 helpers;
	u32 _pad3;
	/*
	 * Asleep waiting for a file service (NFS, SMB, FUSE, virtiofs): the
	 * request's, and its spawned units'.
	 */
	u64 blocked_fsvc_ns;
	u64 helper_fsvc_ns;
	/*
	 * Go, with PROC_F_PARK: of the time the request's own goroutine was on
	 * no thread, by why: waiting to be run again (it was preempted), parked
	 * on a channel, on a sync primitive, asleep, waiting for the network,
	 * for the garbage collector, for something else (enum park).
	 */
	u64 parked_ns[7];
	/*
	 * Of blocked_fsvc_ns and helper_fsvc_ns: asleep waiting for a lock
	 * (rwsem, mutex) while in a file service's call.
	 */
	u64 blocked_fsvc_lock_ns;
	u64 helper_fsvc_lock_ns;
	/*
	 * With REQ_F_HANDLER_TIMED: of the time no thread worked for the
	 * request, from its start to when the handler a runtime gave it to
	 * first ran (the runtime's own units read it, and the handler waited to
	 * be run), and from when that handler last left its thread to the end
	 * (it was done; the runtime's own units wrote the response).
	 */
	u64 before_handler_ns;
	u64 after_handler_ns;
	/* With REQ_F_TRACE (HTTP/1): the trace id of the request's traceparent. */
	u8 trace[16];
	/*
	 * tokio, with PROC_F_PARK: of the time the request's own task was on
	 * no thread, until it was woken by another task, and by the blocking
	 * pool (enum park, past parked_ns).
	 */
	u64 parked_task_ns;
	u64 parked_blocking_ns;
};

/* h2_headers_event.bits */
/* The first bytes of the frame's payload. */
#define H2H_FRAME_START 1
/* The connection was followed from its first byte, so its header blocks can be decoded. */
#define H2H_FROM_START 2

/*
 * Part of the payload of a HEADERS or CONTINUATION frame on a client-facing
 * HTTP/2 connection, in the order the bytes went by. `seq` counts the parts
 * of one direction of one connection, also those that could not be sent: a
 * gap means the header compression state of that direction is lost. A
 * direction starts again at 0 when it gets in step with a new connection.
 */
struct h2_headers_event {
	struct event_header hdr;
	u64 conn;
	u32 seq;
	u32 sid;
	/* 0: from the client; 1: from the server. */
	u8 tx;
	u8 frame_type;
	u8 frame_flags;
	u8 bits;
	u16 len;
	/* Bytes of the frame's payload still to come after these (capped). */
	u16 left;
	u8 data[H2_HDR_CHUNK];
};

/*
 * The start of a task a connection's task has just spawned, for user space
 * to find where the task keeps its stream id (see runtime/tokio_tasks.h).
 */
struct task_sample_event {
	struct event_header hdr;
	u64 conn;
	u64 parent;
	u64 child;
	/* What kind of task: the address of its vtable. */
	u64 vtable;
	u8 mem[TASK_SAMPLE_LEN];
};

/* h2_fields_event.what */
#define H2F_REQUEST 1
#define H2F_RESPONSE 2
/* Bytes of the request's :path carried by an h2_fields_event. */
#define H2F_PATH_LEN 112

/*
 * What a server process has decoded of the headers of one stream, read in the
 * process itself (see runtime/go_grpc.h, runtime/rust_h2.h). Sent only for
 * connections that were not followed from their first byte, whose header
 * blocks cannot be decoded here. The values are as the process holds them;
 * user space checks their form.
 */
struct h2_fields_event {
	struct event_header hdr;
	u64 conn;
	u32 sid;
	/* H2F_*. */
	u8 what;
	/* The trace field holds a traceparent's trace id. */
	u8 has_trace;
	u8 has_status;
	/* Bytes of path: 0 if the request had no :path. */
	u8 path_len;
	u32 status;
	u32 _pad;
	/* The 32 hex digits of the trace id. */
	char trace[32];
	char path[H2F_PATH_LEN];
};

/* Index into COUNTERS. Every discard path lands in one of these. */
enum counter {
	EVENTS_PRODUCED = 0,
	RINGBUF_FULL = 1,
	FILENAME_TRUNCATED = 2,
	FIELD_READ_FAILED = 3,
	RUNQ_START_INSERT_FAILED = 4,
	RUNQ_NEGATIVE_DELTA = 5,
	RUNQ_GROUP_INSERT_FAILED = 6,
	CGROUP_PATH_TRUNCATED = 7,
	/* Requests: started = finished + aborted + those still in flight. */
	REQ_STARTED = 8,
	REQ_FINISHED = 9,
	/* The connection closed, or its parser lost track, before the response ended. */
	REQ_ABORTED = 10,
	/* A table was full; the connection or request is not tracked. */
	REQ_CONN_INSERT_FAILED = 11,
	REQ_INSERT_FAILED = 12,
	REQ_PROC_INSERT_FAILED = 13,
	/* More requests outstanding on one connection than the queue holds. */
	REQ_QUEUE_FULL = 14,
	/* A parser met bytes it cannot follow; it waits for the next message start. */
	REQ_PARSE_DESYNC = 15,
	REQ_PARSE_RESYNC = 16,
	/* A response ended with no request outstanding. */
	REQ_RESPONSE_UNMATCHED = 17,
	/* Time reported for a request that had already finished. */
	REQ_LATE_TIME = 18,
	/* A vectored call had more segments than are read; the rest count as body. */
	REQ_IOV_TRUNCATED = 19,
	REQ_CARRIER_FAILED = 20,
	/* The per-cgroup latency table is full; the request is not counted there. */
	REQ_GROUP_INSERT_FAILED = 21,
	/* A connection switched protocols (101); it is no longer parsed. */
	REQ_UPGRADED = 22,
	/*
	 * A request wrote on a downstream connection while another request's
	 * answer was still outstanding there (pipelined or multiplexed); the
	 * calls involved are not timed.
	 */
	REQ_DOWN_MIXED = 23,
	/* Times a runtime was asked which unit is running on a thread ... */
	UNIT_READ = 24,
	/* ... and the answer did not hold together (wrong offsets, foreign code). */
	UNIT_READ_INCONSISTENT = 25,
	/*
	 * CPU time, in ns, during which a thread went from one unit to another
	 * with no kernel event in between; it is charged to no request.
	 */
	UNIT_CPU_UNSEEN_NS = 26,
	/* An HTTP/2 connection's frames could no longer be followed; its open streams are dropped. */
	REQ_H2_LOST = 27,
	/* The stream table is full; the stream is not tracked. */
	REQ_STREAM_INSERT_FAILED = 28,
	/*
	 * A gRPC server handed a stream to a handler and the stream id read
	 * there cannot be one of the connection's: it was not read from where
	 * the stream id is. The handler's time is not attributed.
	 */
	GRPC_HANDOFF_UNMATCHED = 29,
	/*
	 * HTTP/2 streams that were reset instead of answered. They are reported
	 * like finished requests: started = finished + reset + aborted + those
	 * still in flight.
	 */
	REQ_RESET = 30,
	/* Goroutines and tasks bound to the request of the unit that spawned them. */
	SPAWN_FOLLOWED = 31,
	/*
	 * Time, in ns, of spawned units after their request had finished (work
	 * left running in the background), up to the unit's next switch:
	 * charged to no request. From then on the unit is not followed, and
	 * what it does is not counted here either.
	 */
	HELPER_LATE_NS = 32,
	/*
	 * OpenMP parallel regions opened for a request whose function had no
	 * probes yet (one seen for the first time, until user space has put
	 * them there), or that shared nothing to tell their work by: the threads
	 * that took up their work were not followed.
	 */
	OMP_REGION_UNFOLLOWED = 33,
	/*
	 * CPU time, in ns, of threads of OpenMP teams outside the pieces of
	 * work they took up: spinning for the rest of their team to finish a
	 * region, or for the next region, and the runtime's own doings. It is
	 * charged to no request.
	 */
	OMP_TEAM_IDLE_CPU_NS = 34,
	/*
	 * A traced process's figures on a CPU had no room in PROC_CPU: its
	 * threads' waits there, and what they ran there, are not counted.
	 */
	PROC_CPU_INSERT_FAILED = 35,
	/*
	 * A probe in a server process was given a request's headers or its
	 * status, on a connection whose header blocks cannot be decoded here,
	 * and what it read there did not hold together (where the arguments
	 * are could not be told, or the stream is not the request's): the
	 * request's method and trace id, or its status, are not known from the
	 * process. The process's layout is not the one these probes know.
	 */
	H2_PROCESS_UNREAD = 36,
	/* Client connections whose bytes are taken from a TLS library's calls. */
	TLS_FOLLOWED = 37,
	/*
	 * Calls of a TLS library whose socket is not known (its session was set
	 * up before the probes were there, and no socket call has shown it
	 * since): their bytes are not looked at.
	 */
	TLS_NO_SOCKET = 38,
	/*
	 * Client connections that began with a TLS handshake, in a process
	 * whose TLS library is not read (no --tls, or a library blame does not
	 * know): their requests are not seen. Those of them kernel TLS took up
	 * after the handshake are counted again in TLS_KERNEL, and user space
	 * takes them off: their plaintext goes through the socket calls.
	 */
	TLS_UNREAD = 39,
	TLS_KERNEL = 40,
	COUNTER_MAX = 41,
};

struct runq_hist {
	u64 bucket[RUNQ_BUCKETS];
};

#define ASSERT_LAYOUT(type, size) _Static_assert(sizeof(type) == size, #type " size")
#define ASSERT_OFFSET(type, field, off) \
	_Static_assert(__builtin_offsetof(type, field) == off, #type "." #field " offset")

ASSERT_LAYOUT(struct event_header, 40);
ASSERT_OFFSET(struct event_header, ts_boot_ns, 8);
ASSERT_OFFSET(struct event_header, cgroup_id, 16);
ASSERT_OFFSET(struct event_header, pid, 32);
ASSERT_LAYOUT(struct exec_event, 192);
ASSERT_OFFSET(struct exec_event, filename, 56);
ASSERT_OFFSET(struct exec_event, old_pid, 184);
ASSERT_LAYOUT(struct cgroup_mkdir_event, 568);
ASSERT_OFFSET(struct cgroup_mkdir_event, id, 40);
ASSERT_OFFSET(struct cgroup_mkdir_event, root, 48);
ASSERT_OFFSET(struct cgroup_mkdir_event, path, 56);
ASSERT_LAYOUT(struct unit_key, 16);
ASSERT_OFFSET(struct unit_key, id, 8);
ASSERT_LAYOUT(struct proc_cfg, 24);
ASSERT_OFFSET(struct proc_cfg, tokio_task_id, 12);
ASSERT_OFFSET(struct proc_cfg, grpc_id_off, 18);
ASSERT_OFFSET(struct proc_cfg, rs_entries_ptr, 20);
ASSERT_OFFSET(struct proc_cfg, rs_entries_len, 22);
ASSERT_LAYOUT(struct request_event, 488);
ASSERT_OFFSET(struct request_event, req_id, 40);
ASSERT_OFFSET(struct request_event, first_unit, 64);
ASSERT_OFFSET(struct request_event, cpu_ns, 96);
ASSERT_OFFSET(struct request_event, blocked_other_ns, 144);
ASSERT_OFFSET(struct request_event, down_calls, 192);
ASSERT_OFFSET(struct request_event, stream_id, 200);
ASSERT_OFFSET(struct request_event, lport, 208);
ASSERT_OFFSET(struct request_event, line, 216);
ASSERT_OFFSET(struct request_event, conn, 280);
ASSERT_OFFSET(struct request_event, helper_cpu_ns, 288);
ASSERT_OFFSET(struct request_event, helpers, 344);
ASSERT_OFFSET(struct request_event, blocked_fsvc_ns, 352);
ASSERT_OFFSET(struct request_event, parked_ns, 368);
ASSERT_OFFSET(struct request_event, blocked_fsvc_lock_ns, 424);
ASSERT_OFFSET(struct request_event, before_handler_ns, 440);
ASSERT_OFFSET(struct request_event, trace, 456);
ASSERT_OFFSET(struct request_event, parked_task_ns, 472);
ASSERT_LAYOUT(struct h2_headers_event, 320);
ASSERT_OFFSET(struct h2_headers_event, data, 64);
ASSERT_LAYOUT(struct h2_fields_event, 208);
ASSERT_OFFSET(struct h2_fields_event, trace, 64);
ASSERT_OFFSET(struct h2_fields_event, path, 96);
ASSERT_LAYOUT(struct task_sample_event, 584);
ASSERT_OFFSET(struct task_sample_event, mem, 72);

#endif
