#![no_std]

//! The wire format between the eBPF programs and the userspace agent.
//!
//! The kernel side defines the same types in C (`blame/src/bpf/blame.h`).
//! Both sides assert the same sizes and offsets, so a change that is not
//! mirrored on the other side fails the build. Every type is `#[repr(C)]` with
//! explicitly sized fields and explicit padding. Any layout change must bump
//! [`EVENT_VERSION`].

/// Wire format version stamped into every [`EventHeader`].
///
/// The agent rejects records carrying a version it does not know rather than
/// reinterpreting their bytes. Bump this on any layout change.
pub const EVENT_VERSION: u16 = 2;

/// Length of a `comm` string, matching the kernel's `TASK_COMM_LEN`.
pub const COMM_LEN: usize = 16;

/// Bytes reserved for an exec'd binary path. Longer paths are truncated and
/// counted in [`Counter::FilenameTruncated`].
pub const FILENAME_LEN: usize = 128;

/// Bytes reserved for a cgroup path. Longer paths are truncated and counted in
/// [`Counter::CgroupPathTruncated`].
pub const CGROUP_PATH_LEN: usize = 512;

/// Bytes kept of a request line (`GET /path`). Longer ones are cut and
/// flagged with [`REQ_F_LINE_TRUNCATED`]; the query string is never kept.
pub const REQ_LINE_LEN: usize = 64;

/// Discriminant for the event body following an [`EventHeader`].
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Exec = 1,
    CgroupMkdir = 2,
    Request = 3,
    H2Headers = 4,
    TaskSample = 5,
    H2Fields = 6,
}

impl EventKind {
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Exec),
            2 => Some(Self::CgroupMkdir),
            3 => Some(Self::Request),
            4 => Some(Self::H2Headers),
            5 => Some(Self::TaskSample),
            6 => Some(Self::H2Fields),
            _ => None,
        }
    }
}

/// Common prefix of every event.
///
/// `netns_id` and `ifindex` are always zero on bare metal, but they are carried
/// from the start deliberately: they are what lets the agent deduplicate a
/// packet observed at several points along a container network path, and adding
/// fields to a wire struct after the fact is a compatibility problem.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventHeader {
    pub version: u16,
    pub kind: u16,
    pub cpu: u16,
    pub _pad: u16,
    /// `bpf_ktime_get_boot_ns`. Monotonic and inclusive of suspend, so it can be
    /// converted to wall clock with a single offset computed at startup.
    ///
    /// Never `bpf_ktime_get_ns`: that clock stops across suspend and cannot be
    /// aligned to wall clock.
    pub ts_boot_ns: u64,
    pub cgroup_id: u64,
    /// Reserved for Kubernetes deduplication; zero on bare metal.
    pub netns_id: u32,
    /// Reserved for Kubernetes deduplication; zero on bare metal.
    pub ifindex: u32,
    pub pid: u32,
    pub tid: u32,
}

/// A process replaced its image (`sched:sched_process_exec`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub hdr: EventHeader,
    pub comm: [u8; COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
    pub old_pid: u32,
    pub _pad2: u32,
}

/// A cgroup was created (`cgroup:cgroup_mkdir`). Carries the path while the
/// cgroup still exists, so it can be named after it is gone.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CgroupMkdirEvent {
    pub hdr: EventHeader,
    /// The new cgroup's id, the same value `bpf_get_current_cgroup_id` returns
    /// for its tasks.
    pub id: u64,
    /// Hierarchy id: separates cgroup v2 from any v1 hierarchies, whose ids
    /// come from a different numbering.
    pub root: i32,
    pub _pad2: u32,
    /// Relative to the hierarchy root, e.g. `/system.slice/ssh.service`.
    pub path: [u8; CGROUP_PATH_LEN],
}

/// What a runtime schedules: the thing a request is bound to. The kinds
/// without an adapter yet are reserved in the kernel-side header.
pub const UNIT_THREAD: u8 = 1;
/// The thread was running its runtime's own code, not any unit.
pub const UNIT_RUNTIME: u8 = 2;
pub const UNIT_GOROUTINE: u8 = 3;
pub const UNIT_TOKIO_TASK: u8 = 5;

/// What schedules a process's units: the kernel (threads)...
pub const RT_NONE: u8 = 1;
/// ... or a runtime whose state the kernel side reads.
pub const RT_GO: u8 = 2;
pub const RT_TOKIO: u8 = 3;

/// A traced process (value of the `REQ_PROCS` map), and how to read the unit
/// running on one of its threads. All zero: not looked at yet.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcCfg {
    pub runtime: u8,
    /// `PROC_F_*`.
    pub flags: u8,
    /// Go: offsets of `g.m`, `g.goid`, `m.g0`, `m.curg` and `m.gsignal`.
    pub go_g_m: u16,
    pub go_g_goid: u16,
    pub go_m_g0: u16,
    pub go_m_curg: u16,
    pub go_m_gsignal: u16,
    /// tokio: where the current task id is, relative to the thread pointer.
    pub tokio_task_id: i32,
    /// grpc-go: how the HTTP/2 stream id is read behind the stream pointer
    /// the server hands to a handler (`GRPC_ID_*`), and the offset in bytes.
    pub grpc_id_how: u8,
    /// grpc-go: the argument register that holds the decoded header frame in
    /// `operateHeaders` (0-based). 0: the decoded headers cannot be read.
    pub grpc_frame_arg: u8,
    pub grpc_id_off: u16,
    /// Rust (h2): where a `http::HeaderMap`'s entries keep their pointer and
    /// length, in the map. 0: not readable.
    pub rs_entries_ptr: u16,
    pub rs_entries_len: u16,
}

/// Probes in the process report every unit switch on its threads, so the
/// runtime is not asked which unit is running.
pub const PROC_F_UNIT_PROBES: u8 = 1;
/// Go: a probe where the scheduler puts a goroutine on a thread
/// (`runtime.execute`) reports every switch to one; switches away are seen
/// at the next of those or the next kernel event.
pub const PROC_F_GO_EXECUTE: u8 = 8;
/// Goroutines and tasks spawned by a unit bound to a request work for that
/// request. Only when asked for (`blame slow --spawned`): Go needs probes on
/// goroutine creation for it.
pub const PROC_F_SPAWN: u8 = 2;
/// Go: probes say when a goroutine parks and why, and when it runs again
/// ([`RequestEvent::parked_ns`]).
pub const PROC_F_PARK: u8 = 4;
/// tokio, with [`PROC_F_PARK`]: the blocking pool's tasks are told by being
/// seen spawned there, not by the poll function they go through. Set when
/// the poll functions cannot be told apart by name (the legacy mangling
/// leaves their type arguments out).
pub const PROC_F_TOKIO_BLOCKING: u8 = 16;

/// [`RequestEvent::parked`], by index: why the request's goroutine or task
/// was on no thread. The last two are tokio's: woken by another task, and
/// by the blocking pool.
pub const PARKED: [&str; 9] = [
    "runnable", "channel", "sync", "sleep", "network", "gc", "other", "task", "blocking",
];

pub const GRPC_ID_NONE: u8 = 0;
/// A `u32` at the offset from the stream pointer.
pub const GRPC_ID_DIRECT: u8 = 1;
/// The stream starts with a pointer; a `u32` at the offset from that.
pub const GRPC_ID_BEHIND_PTR: u8 = 2;

impl ProcCfg {
    pub const fn threads() -> Self {
        Self {
            runtime: RT_NONE,
            flags: 0,
            go_g_m: 0,
            go_g_goid: 0,
            go_m_g0: 0,
            go_m_curg: 0,
            go_m_gsignal: 0,
            tokio_task_id: 0,
            grpc_id_how: GRPC_ID_NONE,
            grpc_frame_arg: 0,
            grpc_id_off: 0,
            rs_entries_ptr: 0,
            rs_entries_len: 0,
        }
    }

    /// The map value, in the kernel's layout.
    pub fn to_bytes(self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0] = self.runtime;
        out[1] = self.flags;
        out[16] = self.grpc_id_how;
        out[17] = self.grpc_frame_arg;
        out[18..20].copy_from_slice(&self.grpc_id_off.to_ne_bytes());
        out[20..22].copy_from_slice(&self.rs_entries_ptr.to_ne_bytes());
        out[22..24].copy_from_slice(&self.rs_entries_len.to_ne_bytes());
        out[2..4].copy_from_slice(&self.go_g_m.to_ne_bytes());
        out[4..6].copy_from_slice(&self.go_g_goid.to_ne_bytes());
        out[6..8].copy_from_slice(&self.go_m_g0.to_ne_bytes());
        out[8..10].copy_from_slice(&self.go_m_curg.to_ne_bytes());
        out[10..12].copy_from_slice(&self.go_m_gsignal.to_ne_bytes());
        out[12..16].copy_from_slice(&self.tokio_task_id.to_ne_bytes());
        out
    }
}

/// An execution unit: `id` is the thread id for [`UNIT_THREAD`], the
/// goroutine id or the tokio task id for those kinds.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitKey {
    pub tgid: u32,
    pub kind: u8,
    pub _pad: [u8; 3],
    pub id: u64,
}

/// An HTTP/2 stream that was reset instead of answered: by the client (a call
/// cancelled, or past its deadline) ...
pub const REQ_F_RESET_CLIENT: u8 = 8;
/// ... or by the server (refused). Its end is the reset, and its times are
/// those up to then.
pub const REQ_F_RESET_SERVER: u8 = 16;
/// A runtime handed the request to a handler and probes reported its
/// switches: [`RequestEvent::before_handler_ns`] and
/// [`RequestEvent::after_handler_ns`] are known.
pub const REQ_F_HANDLER_TIMED: u8 = 32;
/// HTTP/1: the request had a `traceparent` header; its trace id is in
/// [`RequestEvent::trace`].
pub const REQ_F_TRACE: u8 = 64;
/// The request came over TLS: its bytes were taken from the TLS library's
/// calls (OpenSSL's `SSL_read` / `SSL_write`), not from the socket's.
pub const REQ_F_TLS: u8 = 128;

/// The request line did not fit in [`REQ_LINE_LEN`].
pub const REQ_F_LINE_TRUNCATED: u8 = 1;
/// The response had no length and ended when the connection closed.
pub const REQ_F_ENDED_BY_CLOSE: u8 = 2;
/// An HTTP/2 stream: there is no request line, and no time by thread.
pub const REQ_F_HTTP2: u8 = 4;

/// One finished request: from the first byte of the request read on a
/// client-facing socket to the last byte of the response written.
/// `hdr.ts_boot_ns` is the start; `hdr.pid`, `hdr.tid` and `hdr.cgroup_id`
/// are of the thread that read it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RequestEvent {
    pub hdr: EventHeader,
    pub req_id: u64,
    pub end_boot_ns: u64,
    /// When the socket became readable before the first read; 0 = not seen.
    pub ready_boot_ns: u64,
    /// The unit that read the request, and the one that wrote its last byte.
    pub first_unit: UnitKey,
    pub last_unit: UnitKey,
    /// Time of the units working for this request, by what they were doing.
    pub cpu_ns: u64,
    pub runq_ns: u64,
    /// Asleep until the request's own downstream socket had data.
    pub blocked_down_ns: u64,
    /// Asleep until the client sent more of the request.
    pub blocked_client_ns: u64,
    /// Asleep in the block layer: a disk read or write.
    pub blocked_io_ns: u64,
    /// Asleep because memory was short: reclaim, throttling, refault.
    pub blocked_mem_ns: u64,
    pub blocked_other_ns: u64,
    /// The same time split by how it was attributed: the unit read the
    /// request itself, or claimed the time when it wrote the response.
    pub observed_ns: u64,
    pub retro_ns: u64,
    /// Downstream calls made while a unit was bound to the request. A call
    /// runs from the start of the write on the downstream socket to the last
    /// read of its answer (wait). Of that: until the first byte of the answer
    /// arrived (service), and from then until the last byte arrived
    /// (transfer). The rest is the answer waiting to be read.
    pub down_wait_ns: u64,
    pub down_service_ns: u64,
    pub down_transfer_ns: u64,
    pub down_calls: u32,
    pub last_tid: u32,
    /// HTTP/2 ([`REQ_F_HTTP2`]): the stream the request was.
    pub stream_id: u32,
    pub _pad2: u32,
    pub lport: u16,
    pub rport: u16,
    pub status: u16,
    pub flags: u8,
    pub line_len: u8,
    pub line: [u8; REQ_LINE_LEN],
    /// The connection the request came in on: what [`H2Headers::conn`] names.
    pub conn: u64,
    /// Time of the units the request spawned, and of what they spawned, by
    /// what they were doing ([`PROC_F_SPAWN`]). They can run side by side,
    /// so this can add up to more than the latency.
    pub helper_cpu_ns: u64,
    pub helper_runq_ns: u64,
    pub helper_down_ns: u64,
    pub helper_client_ns: u64,
    pub helper_io_ns: u64,
    pub helper_mem_ns: u64,
    pub helper_other_ns: u64,
    /// Units spawned for the request.
    pub helpers: u32,
    pub _pad3: u32,
    /// Asleep waiting for a file service (NFS, SMB, FUSE, virtiofs): the
    /// request's, and its spawned units'.
    pub blocked_fsvc_ns: u64,
    pub helper_fsvc_ns: u64,
    /// Go, with [`PROC_F_PARK`]: of the time the request's own goroutine
    /// was on no thread, by why ([`PARKED`]): waiting to be run again (it
    /// was preempted), parked on a channel, on a sync primitive, asleep,
    /// waiting for the network, for the garbage collector, for something
    /// else.
    pub parked_ns: [u64; 7],
    /// Of [`Self::blocked_fsvc_ns`] and [`Self::helper_fsvc_ns`]: asleep
    /// waiting for a lock (rwsem, mutex) while in a file service's call.
    pub blocked_fsvc_lock_ns: u64,
    pub helper_fsvc_lock_ns: u64,
    /// With [`REQ_F_HANDLER_TIMED`]: of the time no thread worked for the
    /// request, from its start to when the handler a runtime gave it to
    /// first ran, and from when that handler last left its thread to the
    /// end.
    pub before_handler_ns: u64,
    pub after_handler_ns: u64,
    /// With [`REQ_F_TRACE`] (HTTP/1): the trace id of the request's
    /// `traceparent` header.
    pub trace: [u8; 16],
    /// tokio, with [`PROC_F_PARK`]: of the time the request's own task was
    /// on no thread, until another task woke it, and until the blocking
    /// pool did.
    pub parked_task_ns: u64,
    pub parked_blocking_ns: u64,
}

/// Bytes of an HTTP/2 header block carried by one event.
pub const H2_HDR_CHUNK: usize = 256;
/// Bytes of a new task looked at to find which stream it serves.
pub const TASK_SAMPLE_LEN: usize = 512;

/// [`H2Headers::bits`]: the first bytes of the frame's payload.
pub const H2H_FRAME_START: u8 = 1;
/// [`H2Headers::bits`]: the connection was followed from its first byte, so
/// its header blocks can be decoded.
pub const H2H_FROM_START: u8 = 2;

/// What precedes the bytes in an HTTP/2 header event: part of the payload of
/// a HEADERS or CONTINUATION frame on a client-facing connection, in the
/// order the bytes went by. `seq` counts the parts of one direction of one
/// connection, also those that could not be sent: a gap means the header
/// compression state of that direction is lost. A direction starts again at
/// 0 when it gets in step with a new connection.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct H2Headers {
    pub hdr: EventHeader,
    pub conn: u64,
    pub seq: u32,
    pub sid: u32,
    /// 0: from the client; 1: from the server.
    pub tx: u8,
    pub frame_type: u8,
    pub frame_flags: u8,
    pub bits: u8,
    pub len: u16,
    /// Bytes of the frame's payload still to come after these (capped).
    pub left: u16,
}

/// [`H2Fields::what`]: the request's headers.
pub const H2F_REQUEST: u8 = 1;
/// [`H2Fields::what`]: the response's status.
pub const H2F_RESPONSE: u8 = 2;
/// Bytes of the request's `:path` an [`H2Fields`] carries.
pub const H2F_PATH_LEN: usize = 112;

/// What a server process has decoded of one stream's headers, read in the
/// process itself, for a connection whose header blocks the agent cannot
/// decode (it was not followed from its first byte). The values are as the
/// process holds them: the reader checks their form.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct H2Fields {
    pub hdr: EventHeader,
    pub conn: u64,
    pub sid: u32,
    /// `H2F_*`.
    pub what: u8,
    /// `trace` holds the 32 hex digits of a traceparent's trace id.
    pub has_trace: u8,
    pub has_status: u8,
    /// Bytes of `path`; 0: no `:path`.
    pub path_len: u8,
    pub status: u32,
    pub _pad: u32,
    pub trace: [u8; 32],
    pub path: [u8; H2F_PATH_LEN],
}

/// The start of a task that a connection's task has just spawned, for the
/// agent to find where such tasks keep their stream id.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TaskSampleEvent {
    pub hdr: EventHeader,
    pub conn: u64,
    pub parent: u64,
    pub child: u64,
    /// What kind of task: the address of its vtable.
    pub vtable: u64,
    pub mem: [u8; TASK_SAMPLE_LEN],
}

/// Index into the per-CPU counter array shared by all programs.
///
/// Counters are the agent's own accounting of what it produced and what it
/// dropped. A silently lossy observability system is worse than none, so every
/// discard path must land in one of these.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counter {
    /// Events successfully committed to the ring buffer.
    EventsProduced = 0,
    /// Ring buffer reservations that failed because the buffer was full. This is
    /// the authoritative kernel-side drop count.
    RingbufFull = 1,
    /// Exec paths that did not fit in [`FILENAME_LEN`].
    FilenameTruncated = 2,
    /// A field could not be read out of a tracepoint record. The event is still
    /// emitted, with the unreadable field zeroed, so this counter is the only
    /// way to tell that part of it was fabricated rather than observed.
    FieldReadFailed = 3,
    /// A runnable thread's tid is outside the table; its next wait is missing.
    RunqStartInsertFailed = 4,
    /// Switch-in earlier than the recorded start; the sample is discarded.
    RunqNegativeDelta = 5,
    /// The per-group table is full; the sample is counted globally only.
    RunqGroupInsertFailed = 6,
    /// cgroup paths that did not fit in [`CGROUP_PATH_LEN`].
    CgroupPathTruncated = 7,
    /// Requests whose first byte was read. Started = finished + aborted +
    /// those still in flight.
    ReqStarted = 8,
    ReqFinished = 9,
    /// The connection closed, or its parser lost track, before the response
    /// ended.
    ReqAborted = 10,
    /// The connection table is full; the connection is not tracked.
    ReqConnInsertFailed = 11,
    /// The request table is full; the request is not tracked.
    ReqInsertFailed = 12,
    /// The table of traced processes is full; the process is not traced.
    ReqProcInsertFailed = 13,
    /// More requests outstanding on one connection than its queue holds.
    ReqQueueFull = 14,
    /// A parser met bytes it cannot follow (not HTTP/1.x, headers longer
    /// than it scans per call, or data it cannot read) and waits for the next
    /// message start.
    ReqParseDesync = 15,
    /// A parser found a message start again.
    ReqParseResync = 16,
    /// A response ended with no request outstanding.
    ReqResponseUnmatched = 17,
    /// Time reported for a request that had already finished.
    ReqLateTime = 18,
    /// A vectored call had more segments than are read; the rest count as
    /// body bytes.
    ReqIovTruncated = 19,
    /// Per-thread state could not be allocated; the thread is not followed.
    ReqCarrierFailed = 20,
    /// The per-cgroup latency table is full; the request is not counted there.
    ReqGroupInsertFailed = 21,
    /// A connection switched protocols (101, e.g. to WebSocket); it is no
    /// longer parsed.
    ReqUpgraded = 22,
    /// A request wrote on a downstream connection while another request's
    /// answer was still outstanding there (pipelined or multiplexed); the
    /// calls involved are not timed.
    ReqDownMixed = 23,
    /// Times a runtime was asked which unit is running on a thread ...
    UnitRead = 24,
    /// ... and the answer did not hold together: the offsets are wrong for
    /// this build, or foreign code (cgo) was running.
    UnitReadInconsistent = 25,
    /// CPU time, in ns, during which a thread went from one unit to another
    /// with no kernel event in between; it is charged to no request.
    UnitCpuUnseenNs = 26,
    /// An HTTP/2 connection's frames could no longer be followed; its open
    /// streams are dropped (counted as aborted).
    ReqH2Lost = 27,
    /// The stream table is full; the stream is not tracked.
    ReqStreamInsertFailed = 28,
    /// A gRPC server handed a stream to a handler and the stream id read
    /// there cannot be one of the connection's: it was not read from where
    /// the stream id is. The handler's time is not attributed.
    GrpcHandoffUnmatched = 29,
    /// HTTP/2 streams that were reset instead of answered. They are reported
    /// like finished requests: started = finished + reset + aborted + those
    /// still in flight.
    ReqReset = 30,
    /// Goroutines and tasks bound to the request of the unit that spawned
    /// them ([`PROC_F_SPAWN`]).
    SpawnFollowed = 31,
    /// Time, in ns, of spawned units after their request had finished (work
    /// left running in the background), up to the unit's next switch:
    /// charged to no request. From then on the unit is not followed, and
    /// what it does is not counted here either.
    HelperLateNs = 32,
    /// OpenMP parallel regions opened for a request whose function had no
    /// probes yet (one seen for the first time, until the agent has put them
    /// there), or that shared nothing to tell their work by: the threads
    /// that took up their work were not followed.
    OmpRegionUnfollowed = 33,
    /// CPU time, in ns, of threads of OpenMP teams outside the pieces of
    /// work they took up: spinning for the rest of their team to finish a
    /// region, or for the next region, and the runtime's own doings. It is
    /// charged to no request.
    OmpTeamIdleCpuNs = 34,
    /// A traced process's figures on a CPU had no room in the table of
    /// what each process ran and waited on each CPU: its threads' waits
    /// there, and what they ran there, are not counted.
    ProcCpuInsertFailed = 35,
    /// A probe in a server process was given a request's headers or its
    /// status, on a connection whose header blocks cannot be decoded here,
    /// and what it read there did not hold together: the request's method
    /// and trace id, or its status, are not known from the process.
    H2ProcessUnread = 36,
    /// Client connections whose bytes are taken from a TLS library's calls.
    TlsFollowed = 37,
    /// Calls of a TLS library whose socket is not known (its session was set
    /// up before the probes were there, and no socket call has shown it
    /// since): their bytes are not looked at.
    TlsNoSocket = 38,
}

/// Number of slots in the counter array.
pub const COUNTER_MAX: u32 = 39;

impl Counter {
    pub const ALL: [Self; COUNTER_MAX as usize] = [
        Self::EventsProduced,
        Self::RingbufFull,
        Self::FilenameTruncated,
        Self::FieldReadFailed,
        Self::RunqStartInsertFailed,
        Self::RunqNegativeDelta,
        Self::RunqGroupInsertFailed,
        Self::CgroupPathTruncated,
        Self::ReqStarted,
        Self::ReqFinished,
        Self::ReqAborted,
        Self::ReqConnInsertFailed,
        Self::ReqInsertFailed,
        Self::ReqProcInsertFailed,
        Self::ReqQueueFull,
        Self::ReqParseDesync,
        Self::ReqParseResync,
        Self::ReqResponseUnmatched,
        Self::ReqLateTime,
        Self::ReqIovTruncated,
        Self::ReqCarrierFailed,
        Self::ReqGroupInsertFailed,
        Self::ReqUpgraded,
        Self::ReqDownMixed,
        Self::UnitRead,
        Self::UnitReadInconsistent,
        Self::UnitCpuUnseenNs,
        Self::ReqH2Lost,
        Self::ReqStreamInsertFailed,
        Self::GrpcHandoffUnmatched,
        Self::ReqReset,
        Self::SpawnFollowed,
        Self::HelperLateNs,
        Self::OmpRegionUnfollowed,
        Self::OmpTeamIdleCpuNs,
        Self::ProcCpuInsertFailed,
        Self::H2ProcessUnread,
        Self::TlsFollowed,
        Self::TlsNoSocket,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::EventsProduced => "events_produced",
            Self::RingbufFull => "ringbuf_full",
            Self::FilenameTruncated => "filename_truncated",
            Self::FieldReadFailed => "field_read_failed",
            Self::RunqStartInsertFailed => "runq_start_insert_failed",
            Self::RunqNegativeDelta => "runq_negative_delta",
            Self::RunqGroupInsertFailed => "runq_group_insert_failed",
            Self::CgroupPathTruncated => "cgroup_path_truncated",
            Self::ReqStarted => "req_started",
            Self::ReqFinished => "req_finished",
            Self::ReqAborted => "req_aborted",
            Self::ReqConnInsertFailed => "req_conn_insert_failed",
            Self::ReqInsertFailed => "req_insert_failed",
            Self::ReqProcInsertFailed => "req_proc_insert_failed",
            Self::ReqQueueFull => "req_queue_full",
            Self::ReqParseDesync => "req_parse_desync",
            Self::ReqParseResync => "req_parse_resync",
            Self::ReqResponseUnmatched => "req_response_unmatched",
            Self::ReqLateTime => "req_late_time",
            Self::ReqIovTruncated => "req_iov_truncated",
            Self::ReqCarrierFailed => "req_carrier_failed",
            Self::ReqGroupInsertFailed => "req_group_insert_failed",
            Self::ReqUpgraded => "req_upgraded",
            Self::ReqDownMixed => "req_down_mixed",
            Self::UnitRead => "unit_read",
            Self::UnitReadInconsistent => "unit_read_inconsistent",
            Self::UnitCpuUnseenNs => "unit_cpu_unseen_ns",
            Self::ReqH2Lost => "req_h2_lost",
            Self::ReqStreamInsertFailed => "req_stream_insert_failed",
            Self::GrpcHandoffUnmatched => "grpc_handoff_unmatched",
            Self::ReqReset => "req_reset",
            Self::SpawnFollowed => "spawn_followed",
            Self::HelperLateNs => "helper_late_ns",
            Self::OmpRegionUnfollowed => "omp_region_unfollowed",
            Self::OmpTeamIdleCpuNs => "omp_team_idle_cpu_ns",
            Self::ProcCpuInsertFailed => "proc_cpu_insert_failed",
            Self::H2ProcessUnread => "h2_process_unread",
            Self::TlsFollowed => "tls_followed",
            Self::TlsNoSocket => "tls_no_socket",
        }
    }

    /// Whether a non-zero value means observational data was lost or degraded.
    pub const fn is_loss(self) -> bool {
        match self {
            // Resyncs and unmatched responses follow attaching to connections
            // that were already open; truncated vectors are harmless in bodies.
            Self::EventsProduced
            | Self::ReqStarted
            | Self::ReqFinished
            | Self::ReqReset
            | Self::ReqParseResync
            | Self::ReqResponseUnmatched
            | Self::ReqIovTruncated
            | Self::ReqUpgraded
            | Self::ReqDownMixed
            | Self::UnitRead
            | Self::UnitCpuUnseenNs
            | Self::SpawnFollowed
            | Self::OmpTeamIdleCpuNs
            | Self::TlsFollowed
            | Self::HelperLateNs => false,
            Self::RingbufFull
            | Self::FilenameTruncated
            | Self::FieldReadFailed
            | Self::RunqStartInsertFailed
            | Self::RunqNegativeDelta
            | Self::RunqGroupInsertFailed
            | Self::CgroupPathTruncated
            | Self::ReqAborted
            | Self::ReqConnInsertFailed
            | Self::ReqInsertFailed
            | Self::ReqProcInsertFailed
            | Self::ReqQueueFull
            | Self::ReqParseDesync
            | Self::ReqLateTime
            | Self::ReqCarrierFailed
            | Self::ReqGroupInsertFailed
            | Self::OmpRegionUnfollowed
            | Self::ProcCpuInsertFailed
            | Self::UnitReadInconsistent
            | Self::ReqH2Lost
            | Self::ReqStreamInsertFailed
            | Self::GrpcHandoffUnmatched
            | Self::H2ProcessUnread
            | Self::TlsNoSocket => true,
        }
    }
}

/// Number of buckets in the run-queue latency histogram: 0-3 us one bucket
/// each, then four equal buckets per power of two up to [`RUNQ_OVERFLOW_US`],
/// then one overflow bucket.
pub const RUNQ_BUCKETS: u32 = 97;

/// Waits at least this long (~33.5 s) land in the overflow bucket.
pub const RUNQ_OVERFLOW_US: u64 = 1 << 25;

/// Bucket for a wait of `delta_ns`, as the kernel side computes it.
pub const fn runq_bucket(delta_ns: u64) -> u32 {
    let us = delta_ns / 1000;
    if us >= RUNQ_OVERFLOW_US {
        return RUNQ_BUCKETS - 1;
    }
    if us < 4 {
        return us as u32;
    }
    let top = 63 - us.leading_zeros();
    ((top - 1) << 2) | ((us >> (top - 2)) & 3) as u32
}

/// `[lo, hi)` in microseconds of bucket `k`; `hi` is `None` for the overflow
/// bucket.
pub const fn runq_bucket_range_us(k: u32) -> (u64, Option<u64>) {
    if k >= RUNQ_BUCKETS - 1 {
        return (RUNQ_OVERFLOW_US, None);
    }
    if k < 4 {
        return (k as u64, Some(k as u64 + 1));
    }
    let top = (k >> 2) + 1;
    let width = 1u64 << (top - 2);
    let lo = (1u64 << top) + (k & 3) as u64 * width;
    (lo, Some(lo + width))
}

// Mirrors the assertions in blame.h.
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<EventHeader>() == 40);
    assert!(offset_of!(EventHeader, ts_boot_ns) == 8);
    assert!(offset_of!(EventHeader, cgroup_id) == 16);
    assert!(offset_of!(EventHeader, pid) == 32);
    assert!(size_of::<ExecEvent>() == 192);
    assert!(offset_of!(ExecEvent, filename) == 56);
    assert!(offset_of!(ExecEvent, old_pid) == 184);
    assert!(size_of::<CgroupMkdirEvent>() == 568);
    assert!(offset_of!(CgroupMkdirEvent, id) == 40);
    assert!(offset_of!(CgroupMkdirEvent, root) == 48);
    assert!(offset_of!(CgroupMkdirEvent, path) == 56);
    assert!(size_of::<ProcCfg>() == 24);
    assert!(offset_of!(ProcCfg, grpc_id_off) == 18);
    assert!(offset_of!(ProcCfg, rs_entries_ptr) == 20);
    assert!(offset_of!(ProcCfg, rs_entries_len) == 22);
    assert!(offset_of!(ProcCfg, tokio_task_id) == 12);
    assert!(size_of::<UnitKey>() == 16);
    assert!(offset_of!(UnitKey, id) == 8);
    assert!(size_of::<RequestEvent>() == 488);
    assert!(offset_of!(RequestEvent, parked_task_ns) == 472);
    assert!(offset_of!(RequestEvent, trace) == 456);
    assert!(offset_of!(RequestEvent, before_handler_ns) == 440);
    assert!(offset_of!(RequestEvent, blocked_fsvc_lock_ns) == 424);
    assert!(offset_of!(RequestEvent, parked_ns) == 368);
    assert!(offset_of!(RequestEvent, blocked_fsvc_ns) == 352);
    assert!(offset_of!(RequestEvent, helper_cpu_ns) == 288);
    assert!(offset_of!(RequestEvent, helpers) == 344);
    assert!(offset_of!(RequestEvent, conn) == 280);
    assert!(size_of::<H2Headers>() == 64);
    assert!(size_of::<TaskSampleEvent>() == 584);
    assert!(size_of::<H2Fields>() == 208);
    assert!(offset_of!(H2Fields, trace) == 64);
    assert!(offset_of!(H2Fields, path) == 96);
    assert!(offset_of!(TaskSampleEvent, mem) == 72);
    assert!(offset_of!(RequestEvent, req_id) == 40);
    assert!(offset_of!(RequestEvent, first_unit) == 64);
    assert!(offset_of!(RequestEvent, cpu_ns) == 96);
    assert!(offset_of!(RequestEvent, blocked_other_ns) == 144);
    assert!(offset_of!(RequestEvent, down_calls) == 192);
    assert!(offset_of!(RequestEvent, lport) == 208);
    assert!(offset_of!(RequestEvent, line) == 216);
};

/// Trim a NUL-padded fixed-size field down to its content.
fn nul_trimmed(buf: &[u8]) -> &[u8] {
    let end = match buf.iter().position(|&b| b == 0) {
        Some(i) => i,
        None => buf.len(),
    };
    &buf[..end]
}

/// Reinterpret the head of a record as `T`.
///
/// Returns `None` when the record is too short or misaligned; callers must treat
/// that as a malformed record rather than trusting the bytes. Sound for the
/// types in this module because they are `repr(C)` aggregates of integers and
/// byte arrays, for which every bit pattern is a valid value.
fn parse_prefix<T>(buf: &[u8]) -> Option<&T> {
    if buf.len() < size_of::<T>() {
        return None;
    }
    let ptr = buf.as_ptr().cast::<T>();
    if !ptr.is_aligned() {
        return None;
    }
    // SAFETY: length and alignment checked above; see the doc comment for why
    // any bit pattern is a valid `T`.
    Some(unsafe { &*ptr })
}

impl EventHeader {
    pub fn parse(buf: &[u8]) -> Option<&Self> {
        parse_prefix(buf)
    }
}

impl CgroupMkdirEvent {
    pub fn parse(buf: &[u8]) -> Option<&Self> {
        parse_prefix(buf)
    }

    pub fn path_bytes(&self) -> &[u8] {
        nul_trimmed(&self.path)
    }

    /// A path that filled the buffer may have been cut short.
    pub fn path_truncated(&self) -> bool {
        self.path_bytes().len() >= CGROUP_PATH_LEN - 1
    }
}

impl RequestEvent {
    pub fn parse(buf: &[u8]) -> Option<&Self> {
        parse_prefix(buf)
    }

    /// Method and path, without the query string.
    pub fn line_bytes(&self) -> &[u8] {
        &self.line[..(self.line_len as usize).min(REQ_LINE_LEN)]
    }

    pub fn latency_ns(&self) -> u64 {
        self.end_boot_ns.saturating_sub(self.hdr.ts_boot_ns)
    }

    /// Why the request's own goroutine or task was on no thread, by
    /// [`PARKED`].
    pub fn parked(&self) -> [u64; 9] {
        let p = self.parked_ns;
        [
            p[0],
            p[1],
            p[2],
            p[3],
            p[4],
            p[5],
            p[6],
            self.parked_task_ns,
            self.parked_blocking_ns,
        ]
    }

    /// The trace id an HTTP/1 request's `traceparent` header carried, as
    /// it spells it: 32 lowercase hex digits.
    pub fn http1_trace(&self) -> Option<[u8; 32]> {
        if self.flags & REQ_F_TRACE == 0 {
            return None;
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 32];
        for (i, byte) in self.trace.iter().enumerate() {
            out[2 * i] = HEX[usize::from(byte >> 4)];
            out[2 * i + 1] = HEX[usize::from(byte & 15)];
        }
        Some(out)
    }
}

impl H2Headers {
    /// The event's fixed part and the header-block bytes after it.
    pub fn parse(buf: &[u8]) -> Option<(&Self, &[u8])> {
        let head: &Self = parse_prefix(buf)?;
        let data = buf.get(size_of::<Self>()..size_of::<Self>() + head.len as usize)?;
        Some((head, data))
    }
}

impl TaskSampleEvent {
    pub fn parse(buf: &[u8]) -> Option<&Self> {
        parse_prefix(buf)
    }
}

impl H2Fields {
    pub fn parse(buf: &[u8]) -> Option<&Self> {
        parse_prefix(buf)
    }

    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..(self.path_len as usize).min(H2F_PATH_LEN)]
    }
}

impl ExecEvent {
    pub fn parse(buf: &[u8]) -> Option<&Self> {
        parse_prefix(buf)
    }

    pub fn comm_bytes(&self) -> &[u8] {
        nul_trimmed(&self.comm)
    }

    pub fn filename_bytes(&self) -> &[u8] {
        nul_trimmed(&self.filename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runq_bucket_edges() {
        assert_eq!(runq_bucket(0), 0);
        assert_eq!(runq_bucket(999), 0);
        assert_eq!(runq_bucket(1_000), 1);
        assert_eq!(runq_bucket(3_999), 3);
        assert_eq!(runq_bucket(4_000), 4);
        assert_eq!(runq_bucket(7_999), 7);
        assert_eq!(runq_bucket(8_000), 8);
        assert_eq!(runq_bucket(9_999), 8);
        assert_eq!(runq_bucket(10_000), 9);
        assert_eq!(runq_bucket(1_024_000), 36); // 1024 us starts a power of two
        assert_eq!(runq_bucket((RUNQ_OVERFLOW_US - 1) * 1000), RUNQ_BUCKETS - 2);
        assert_eq!(runq_bucket(RUNQ_OVERFLOW_US * 1000), RUNQ_BUCKETS - 1);
        assert_eq!(runq_bucket(u64::MAX), RUNQ_BUCKETS - 1);
    }

    #[test]
    fn runq_bucket_ranges_tile_the_axis_and_match_the_index() {
        assert_eq!(runq_bucket_range_us(0), (0, Some(1)));
        assert_eq!(runq_bucket_range_us(36), (1024, Some(1280)));
        assert_eq!(
            runq_bucket_range_us(RUNQ_BUCKETS - 1),
            (RUNQ_OVERFLOW_US, None)
        );
        for k in 1..RUNQ_BUCKETS {
            assert_eq!(
                runq_bucket_range_us(k - 1).1,
                Some(runq_bucket_range_us(k).0)
            );
        }
        for k in 0..RUNQ_BUCKETS - 1 {
            let (lo, hi) = runq_bucket_range_us(k);
            assert_eq!(runq_bucket(lo * 1000), k);
            assert_eq!(runq_bucket(hi.unwrap() * 1000 - 1), k);
        }
    }

    #[test]
    fn runq_buckets_are_within_a_quarter_of_their_value() {
        for k in 8..RUNQ_BUCKETS - 1 {
            let (lo, hi) = runq_bucket_range_us(k);
            assert!((hi.unwrap() - lo) * 4 <= lo, "bucket {k}");
        }
    }

    #[test]
    fn counters_are_dense_and_named() {
        for (i, c) in Counter::ALL.iter().enumerate() {
            assert_eq!(*c as usize, i);
            assert!(!c.name().is_empty());
        }
        assert_eq!(Counter::ALL.len(), COUNTER_MAX as usize);
    }
}
