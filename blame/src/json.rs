//! `blame slow --json`: what the agent found, one JSON object per line, for
//! a program (or a model) to read.
//!
//! Every record has a `type`. What is not known is `null`, never a stand-in
//! value; what does not apply is left out. Durations are integers in
//! nanoseconds, in fields ending in `_ns`. What each field means is in
//! [`fields`], which `--json-fields` prints.

use blame_common::{
    Counter, PARKED, REQ_F_ENDED_BY_CLOSE, REQ_F_HANDLER_TIMED, REQ_F_HTTP2, REQ_F_RESET_CLIENT,
    REQ_F_RESET_SERVER, RequestEvent, UNIT_GOROUTINE, UNIT_THREAD, UNIT_TOKIO_TASK,
};
use serde_json::{Value, json};

use crate::{
    h2meta::Meta,
    methods::{Method, OffThread, Row},
    runq::{Hist, summary},
    slow::proc_cpu::ProcCpu,
    stats::Counters,
};

/// Bumped when a field changes meaning or goes away; adding fields does not.
pub const FORMAT: u32 = 1;

/// `2026-11-13T10:24:59.414123Z` for nanoseconds since the Unix epoch.
pub fn rfc3339(unix_ns: i128) -> Option<String> {
    if unix_ns < 0 {
        return None;
    }
    let seconds = (unix_ns / 1_000_000_000) as i64;
    let micros = (unix_ns % 1_000_000_000) / 1000;
    let days = seconds.div_euclid(86_400);
    let of_day = seconds.rem_euclid(86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        of_day / 3600,
        of_day / 60 % 60,
        of_day % 60,
    ))
}

/// The first record: what this run is.
pub fn start(threshold_ns: u64, window_s: u64, list_max: Option<u64>, traced: usize) -> Value {
    json!({
        "type": "start",
        "format": FORMAT,
        "blame": env!("CARGO_PKG_VERSION"),
        "threshold_ns": threshold_ns,
        "window_s": window_s,
        "list_max": list_max,
        "processes_traced": traced,
    })
}

/// What was found out about a traced process.
pub fn process(
    pid: u32,
    units: &str,
    http2_handlers_followed: bool,
    note: Option<&str>,
    unsupported: &[String],
) -> Value {
    json!({
        "type": "process",
        "pid": pid,
        "units": units,
        "http2_handlers_followed": http2_handlers_followed,
        "note": note,
        "unsupported": unsupported,
    })
}

/// What a traced process's threads waited for a CPU,
/// over a window or the whole run (`over_ns`).
pub fn process_cpu(window_s: Option<u64>, pid: u32, over_ns: u64, cpu: &ProcCpu) -> Value {
    let (scope, window_s) = scope(window_s);
    json!({
        "type": "process_cpu",
        "scope": scope,
        "window_s": window_s,
        "pid": pid,
        "over_ns": over_ns,
        "runq_own_threads_ns": cpu.runq_own_ns,
        "runq_cpu_limit_ns": cpu.runq_cpu_limit_ns,
        "runq_others_ns": cpu.runq_others_ns,
        "runq_cpu_idle_ns": cpu.runq_cpu_idle_ns,
        "steal_ns": cpu.steal_ns,
        "cgroup_throttled_ns": cpu.cgroup_throttled_ns,
    })
}

/// A request that took at least the threshold.
pub fn call(
    event: &RequestEvent,
    what: Option<&Meta>,
    service: Option<&str>,
    wall_offset: i128,
) -> Value {
    let http2 = event.flags & REQ_F_HTTP2 != 0;
    let latency = event.latency_ns();
    let outcome = if event.flags & REQ_F_RESET_CLIENT != 0 {
        "reset_by_client"
    } else if event.flags & REQ_F_RESET_SERVER != 0 {
        "reset_by_server"
    } else if event.flags & REQ_F_ENDED_BY_CLOSE != 0 {
        "ended_by_close"
    } else {
        "answered"
    };
    let answered = outcome == "answered" || outcome == "ended_by_close";
    let handler = match event.first_unit.kind {
        UNIT_THREAD => Some("thread"),
        UNIT_GOROUTINE => Some("goroutine"),
        UNIT_TOKIO_TASK => Some("task"),
        _ => None,
    };
    // Whose time is attributed: for HTTP/2, only a handler that was followed.
    let timed = event.observed_ns + event.retro_ns > 0;
    let on_thread = event.cpu_ns
        + event.runq_ns
        + event.blocked_down_ns
        + event.blocked_client_ns
        + event.blocked_io_ns
        + event.blocked_mem_ns
        + event.blocked_fsvc_ns
        + event.blocked_other_ns;
    let mut out = json!({
        "type": "call",
        "start": rfc3339(i128::from(event.hdr.ts_boot_ns) + wall_offset),
        "duration_ns": latency,
        "protocol": if http2 { "http2" } else { "http1" },
        "outcome": outcome,
        "service": service,
        "pid": event.hdr.pid,
        "server_port": event.lport,
        "client_port": event.rport,
        "queued_ns": (event.ready_boot_ns != 0 && event.ready_boot_ns <= event.hdr.ts_boot_ns)
            .then(|| event.hdr.ts_boot_ns - event.ready_boot_ns),
        "handler": handler
            .filter(|_| timed || !http2)
            .map(|kind| json!({"kind": kind, "id": event.first_unit.id})),
        "time": timed.then(|| json!({
            "on_cpu_ns": event.cpu_ns,
            "runq_ns": event.runq_ns,
            "blocked_downstream_ns": event.blocked_down_ns,
            "blocked_client_ns": event.blocked_client_ns,
            "blocked_disk_ns": event.blocked_io_ns,
            "blocked_memory_ns": event.blocked_mem_ns,
            "blocked_file_service_ns": event.blocked_fsvc_ns,
            "blocked_file_service_lock_ns": event.blocked_fsvc_lock_ns,
            "blocked_other_ns": event.blocked_other_ns,
            "off_thread_ns": latency.saturating_sub(on_thread),
        })),
    });
    let fields = out.as_object_mut().expect("an object");
    if let Some(time) = fields.get_mut("time").and_then(|time| time.as_object_mut()) {
        if event.flags & REQ_F_HANDLER_TIMED != 0 {
            time.insert("before_handler_ns".into(), json!(event.before_handler_ns));
            time.insert("after_handler_ns".into(), json!(event.after_handler_ns));
        }
        if let Some(why) = parked(&event.parked(), 1) {
            time.insert("off_thread_by_why".into(), why);
        }
        let parts = OffThread::of(event, latency.saturating_sub(on_thread));
        time.insert("not_seen_ns".into(), json!(parts.not_seen_ns));
    }
    if event.helpers > 0 {
        fields.insert(
            "spawned".into(),
            json!({
                "count": event.helpers,
                "on_cpu_ns": event.helper_cpu_ns,
                "runq_ns": event.helper_runq_ns,
                "blocked_downstream_ns": event.helper_down_ns,
                "blocked_client_ns": event.helper_client_ns,
                "blocked_disk_ns": event.helper_io_ns,
                "blocked_memory_ns": event.helper_mem_ns,
                "blocked_file_service_ns": event.helper_fsvc_ns,
                "blocked_file_service_lock_ns": event.helper_fsvc_lock_ns,
                "blocked_other_ns": event.helper_other_ns,
            }),
        );
    }
    if http2 {
        fields.insert("stream".into(), json!(event.stream_id));
        fields.insert(
            "method".into(),
            json!(what.and_then(|meta| meta.path.as_deref())),
        );
        fields.insert("trace_id".into(), json!(what.and_then(Meta::trace)));
        if answered {
            fields.insert(
                "grpc_status".into(),
                json!(what.and_then(|meta| meta.grpc_status)),
            );
        }
    } else {
        let trace = event.http1_trace();
        fields.insert(
            "trace_id".into(),
            json!(trace.as_ref().and_then(|id| std::str::from_utf8(id).ok())),
        );
        let line = String::from_utf8_lossy(event.line_bytes()).into_owned();
        fields.insert("request".into(), json!((!line.is_empty()).then_some(line)));
        fields.insert(
            "http_status".into(),
            json!((event.status != 0).then_some(event.status)),
        );
        if event.down_calls > 0 {
            fields.insert(
                "downstream".into(),
                json!({
                    "calls": event.down_calls,
                    "wait_ns": event.down_wait_ns,
                    "first_byte_ns": event.down_service_ns,
                    "transfer_ns": event.down_transfer_ns,
                }),
            );
        }
    }
    out
}

fn scope(window_s: Option<u64>) -> (&'static str, Option<u64>) {
    match window_s {
        Some(seconds) => ("window", Some(seconds)),
        None => ("total", None),
    }
}

/// A service's request latencies, over a window or the whole run.
pub fn service(window_s: Option<u64>, name: Option<&str>, hist: &Hist) -> Value {
    let (scope, window_s) = scope(window_s);
    let s = summary(hist);
    json!({
        "type": "service",
        "scope": scope,
        "window_s": window_s,
        "service": name,
        "requests": s.samples,
        "p50_ns": s.p50_us * 1000,
        "p99_ns": s.p99_us.map(|us| us * 1000),
        "p999_ns": s.p999_us.map(|us| us * 1000),
        "max_ns": s.max_us * 1000,
    })
}

/// One row of the summary by method.
pub fn method(window_s: Option<u64>, service: Option<&str>, row: &Row) -> Value {
    let (scope, window_s) = scope(window_s);
    let s = &row.stats;
    let latency = summary(&s.hist);
    let mean = |sum: u64| sum / s.timed.max(1);
    json!({
        "type": "method",
        "scope": scope,
        "window_s": window_s,
        "service": service,
        "method": match &row.method {
            Method::Path(path) => Some(&**path),
            Method::Other | Method::Unknown => None,
        },
        "method_group": match &row.method {
            Method::Path(_) => None,
            Method::Other => Some("other_paths"),
            Method::Unknown => Some("path_not_known"),
        },
        "calls": s.calls,
        "ok": s.ok,
        "errors": s.errors,
        "status_not_known": s.status_unknown,
        "reset_by_client": s.reset_client,
        "reset_by_server": s.reset_server,
        "without_trace_id": s.no_trace,
        "p50_ns": latency.p50_us * 1000,
        "p99_ns": latency.p99_us.map(|us| us * 1000),
        "max_ns": s.max_ns,
        "timed": s.timed,
        "time_mean": (s.timed > 0).then(|| json!({
            "on_cpu_ns": mean(s.cpu_ns),
            "runq_ns": mean(s.runq_ns),
            "blocked_disk_ns": mean(s.disk_ns),
            "blocked_memory_ns": mean(s.memory_ns),
            "blocked_file_service_ns": mean(s.file_service_ns),
            "blocked_other_ns": mean(s.blocked_other_ns),
            "off_thread_ns": mean(s.off_thread_ns),
            "before_handler_ns": mean(s.before_handler_ns),
            "after_handler_ns": mean(s.after_handler_ns),
            "not_seen_ns": mean(s.not_seen_ns),
        })),
        "off_thread_by_why_mean": parked(&s.parked_ns, s.timed),
        "spawned_mean": (s.spawned > 0).then(|| json!({
            "count": s.spawned as f64 / s.timed as f64,
            "on_cpu_ns": mean(s.spawned_cpu_ns),
            "runq_ns": mean(s.spawned_runq_ns),
            "blocked_disk_ns": mean(s.spawned_disk_ns),
            "blocked_memory_ns": mean(s.spawned_memory_ns),
            "blocked_file_service_ns": mean(s.spawned_file_service_ns),
            "blocked_other_ns": mean(s.spawned_other_ns),
        })),
    })
}

/// Go, following why goroutines park: time on no thread by why, divided by
/// `count`; `None` if none was seen.
fn parked(ns: &[u64; 9], count: u64) -> Option<Value> {
    if ns.iter().sum::<u64>() == 0 || count == 0 {
        return None;
    }
    let fields: serde_json::Map<String, Value> = PARKED
        .iter()
        .zip(ns)
        .map(|(name, ns)| (format!("{name}_ns"), json!(ns / count)))
        .collect();
    Some(Value::Object(fields))
}

/// How complete the rest is: what was counted, what was lost.
pub fn health(
    window_s: Option<u64>,
    counters: &Counters,
    slow: u64,
    listed: u64,
    agent: Option<(f64, u64)>,
) -> Value {
    let (scope, window_s) = scope(window_s);
    let started = counters.get(Counter::ReqStarted);
    let finished = counters.get(Counter::ReqFinished);
    let reset = counters.get(Counter::ReqReset);
    let aborted = counters.get(Counter::ReqAborted);
    let lost: serde_json::Map<String, Value> = Counter::ALL
        .into_iter()
        .filter(|counter| counter.is_loss() && counters.get(*counter) > 0)
        .map(|counter| (counter.name().to_string(), json!(counters.get(counter))))
        .collect();
    json!({
        "type": "health",
        "scope": scope,
        "window_s": window_s,
        "requests": {
            "started": started,
            "finished": finished,
            "reset": reset,
            "aborted": aborted,
            "in_flight": started.saturating_sub(finished + reset + aborted),
        },
        "calls_slow": slow,
        "calls_listed": listed,
        "lost": lost,
        "openmp_team_idle_cpu_ns": Some(counters.get(Counter::OmpTeamIdleCpuNs))
            .filter(|ns| *ns > 0),
        "agent": agent.map(|(cpu_percent, rss_bytes)| json!({
            "cpu_percent": (cpu_percent * 100.0).round() / 100.0,
            "rss_bytes": rss_bytes,
        })),
    })
}

/// What every field of every record means: what `--json-fields` prints.
pub fn fields() -> Value {
    json!({
        "format": FORMAT,
        "about": "One JSON object per line. `type` says which record it is. A value that is not \
                  known is null: it is never a stand-in, and nothing is inferred. A field that does \
                  not apply to a record is absent. Durations are integers in nanoseconds (`_ns`). \
                  Counts in `health` are since the agent started, also in window records.",
        "records": {
            "start": {
                "about": "First record of a run.",
                "format": "Version of this format; changes when a field changes meaning or goes away.",
                "blame": "Version of the agent.",
                "threshold_ns": "Requests at least this slow are listed as `call` records (--above).",
                "window_s": "Seconds between summaries; 0: only at the end (--interval).",
                "list_max": "Only the this many slowest requests are written as `call` records, at the end of the run, slowest first. null: every slow request is written, as it ends (--list).",
                "processes_traced": "Processes traced from the start; others are added when they accept a connection.",
            },
            "process": {
                "about": "What was found out about a traced process. Read these before drawing conclusions from missing data.",
                "pid": "The process.",
                "units": "What a request's time is attributed by: `thread`, `goroutine` (Go) or `task` (tokio).",
                "http2_handlers_followed": "Whether probes are attached that find the goroutine or task serving each HTTP/2 stream. If false, HTTP/2 calls of this process have no `handler` and no `time`.",
                "note": "The agent's own words on the above, with versions and, where something is not followed, why.",
                "unsupported": "Versions the process uses that the agent does not know (Go, grpc-go, tokio, rustc), each with what is not followed because of it; also printed to stderr as warnings. Empty: none.",
            },
            "call": {
                "about": "One request that took at least `threshold_ns`: from the first byte of the request read by the server to the last byte of the response written (or to the reset).",
                "start": "When the server read the request's first byte (UTC).",
                "duration_ns": "Start to end.",
                "protocol": "`http1` or `http2` (gRPC is http2).",
                "outcome": "`answered`; `reset_by_client` (cancelled, or past its deadline); `reset_by_server` (refused, or the server enforced the deadline); `ended_by_close` (HTTP/1 response without a length).",
                "service": "The systemd unit, container or pod the process runs in; null if not known.",
                "pid": "The server process.",
                "server_port": "Port the request came in on.",
                "client_port": "The client's port on that connection.",
                "queued_ns": "From the request's bytes arriving at the socket to the server reading them. null: the arrival was not seen.",
                "handler": "What served the request: {kind: thread|goroutine|task, id}. null for an HTTP/2 call whose handler was not followed.",
                "time": "Where the handler's time went. null if no handler was followed: then nothing is known about where the time went, not that it went nowhere.",
                "time.on_cpu_ns": "Running on a CPU.",
                "time.runq_ns": "Runnable, waiting for a CPU. High values mean CPU contention or throttling, not slow code.",
                "time.blocked_downstream_ns": "Asleep until a downstream connection of the request had data (HTTP/1, thread-per-request servers).",
                "time.blocked_client_ns": "Asleep until the client sent more of the request.",
                "time.blocked_disk_ns": "Asleep for a disk of this machine: a read or write in the block layer, or a flush (fsync and the like) of a file on a local filesystem.",
                "time.blocked_memory_ns": "Asleep because memory was short: reclaim, throttling, refault.",
                "time.blocked_file_service_ns": "Asleep waiting for a file service: a file on NFS (EFS, NAS), SMB, FUSE or virtiofs, read, written, flushed or looked up. The server, the network or the daemon behind the path is what to look at, not this machine's disk. Not counted as disk although the kernel marks part of it so.",
                "time.blocked_file_service_lock_ns": "Of `blocked_file_service_ns`: asleep for a lock (a kernel rwsem or mutex) another thread held, mostly a file's lock held by another request's write or flush of the same file. Many requests writing one file wait for each other here, not for the service.",
                "time.blocked_other_ns": "Asleep for another reason (locks, timers, other I/O).",
                "time.off_thread_ns": "The rest of the duration: the handler was on no thread (a goroutine or task that is parked: waiting for a downstream call, a lock, a channel, or the runtime's scheduler), or the request was waiting for a handler. Cannot be split further from outside the process.",
                "time.before_handler_ns": "Of `off_thread_ns`, when a runtime handed the request to a handler (gRPC in Go and tokio) and its switches were followed exactly: from the start to when the handler first ran. The runtime's own goroutines or tasks had it: the one reading the connection had not got to it yet, or the new handler was waiting to be run. Absent when not known.",
                "time.after_handler_ns": "Of `off_thread_ns`, likewise: from when the handler last left its thread to the end, if it did not run again. It was done; the runtime's own goroutines or tasks were writing the response. Absent when not known.",
                "time.off_thread_by_why": "Only with `--deep`: of `off_thread_ns`, where the request's goroutine or task was, by why, in ns: {runnable_ns, channel_ns, sync_ns, sleep_ns, network_ns, gc_ns, other_ns, task_ns, blocking_ns}. Go: from why the goroutine parked: runnable (taken off its thread and waiting to run again: more runnable goroutines than GOMAXPROCS lets run), channel, sync (Mutex, RWMutex, Cond, WaitGroup), sleep, network (waiting for a socket in Go's poller), gc, other; each includes, after the goroutine was woken, any wait for a thread to run it; task and blocking are 0. tokio (multi-thread and current-thread runtimes): from what woke the task, up to the wake: network (the I/O driver: a socket or another event source), sleep (a timer), task (another task: a channel, a lock, a join handle, not told apart), blocking (the blocking pool finished work for it), other (anything else); runnable is from the wake to its next poll, and the time of a task woken while it ran. What is left of off_thread_ns, less `before_handler_ns` and `after_handler_ns`, was not seen: `not_seen_ns`. Absent if nothing was seen.",
                "time.not_seen_ns": "Of `off_thread_ns`, what is left after `before_handler_ns`, `after_handler_ns` and `off_thread_by_why`: off any thread, and nothing seen says why (all of `off_thread_ns` when none of those is there). The four add up to `off_thread_ns`.",
                "stream": "http2: the stream id on its connection.",
                "method": "http2: the request's :path; for gRPC `/package.Service/Method`. null: not known. On a connection older than the agent the header blocks cannot be decoded; the method then comes from the process itself where it is read there (see `process.note`: grpc-go, and tonic with symbols), else once the client spells it out again.",
                "trace_id": "The trace id of the request's W3C `traceparent` header: the 32 hex digits after the two of the version, where the value is laid out so (`vv-<32 hex>-...`), not all zero; otherwise not taken. null: the request had none, or it is not known. http1: read from the request's headers as they arrive. http2: on a connection older than the agent only a process whose headers are read (see `process.note`) gives it, and not for a request whose headers were read before the agent was attached.",
                "grpc_status": "http2, answered calls: the `grpc-status` the server sent. null: none was sent (not gRPC) or it is not known (on a connection older than the agent, only where the process's headers are read: see `trace_id`). Absent for calls that were reset.",
                "request": "http1: method and path, without the query string, up to 64 bytes.",
                "http_status": "http1: the response status. null: not seen.",
                "downstream": "http1, only if the handler made downstream calls: {calls, wait_ns (first write to last read), first_byte_ns, transfer_ns}.",
                "spawned": "Only with `--deep`, and only if the request spawned goroutines or tasks (the units bound to it spawned them while they were; what those spawned counts too): {count, on_cpu_ns, runq_ns, blocked_downstream_ns, blocked_client_ns, blocked_disk_ns, blocked_memory_ns, blocked_file_service_ns, blocked_file_service_lock_ns, blocked_other_ns}, as in `time` but for them. Not part of `time`: they run side by side with the handler and with each other, so the sum can exceed `duration_ns`. Their time after the request ended is not counted. tokio's `spawn_blocking` closures (and so `tokio::fs` calls) count as spawned tasks. In a process attributed by thread that opens OpenMP parallel regions (GNU libgomp) for a request, the threads of the team that take up the regions' work count here too: `count` is the pieces of work they took up (a thread takes one per region), their time is from the start of a piece to its end, and `runq_ns` also has what a thread waited for a CPU, woken for a region, before it got to its piece. What a team's threads do between pieces (spinning for the next region) is not counted.",
            },
            "service": {
                "about": "Latency of all requests of a service, slow or not, over a window or the whole run.",
                "scope": "`window`: the last `window_s` seconds. `total`: since the agent started.",
                "window_s": "Length of the window; null for `total`.",
                "service": "As in `call.service`.",
                "requests": "Requests answered.",
                "p50_ns": "Median latency, read off a histogram (within a quarter of the value).",
                "p99_ns": "null until at least 10,000 requests are in the summary.",
                "p999_ns": "null until at least 100,000.",
                "max_ns": "Upper edge of the highest occupied histogram bucket.",
            },
            "method": {
                "about": "Requests of one service and path, all of them, slow or not: for HTTP/2 the path (for gRPC, one method), for HTTP/1 the method and route.",
                "scope": "As in `service`.",
                "window_s": "As in `service`.",
                "service": "As in `call.service`.",
                "method": "HTTP/2: as in `call.method`. HTTP/1: the request line's method and path with ids put together: a path segment of digits only, a UUID, or 16 or more hex digits becomes `{id}` (`GET /order/{id}`); nothing else is changed; `...` at the end: the line was longer than the agent keeps. null when `method_group` says why.",
                "method_group": "null for a row about one path. `path_not_known`: the requests whose path could not be decoded, together. `other_paths`: paths beyond the 256 kept apart per service, together.",
                "calls": "Requests that ended: answered or reset.",
                "ok": "Answered with gRPC status 0; HTTP/1: with a 1xx to 3xx status.",
                "errors": "Answered with another gRPC status; HTTP/1: with a 4xx or 5xx status.",
                "status_not_known": "Answered, status not known (see `call.grpc_status`; HTTP/1: no status line seen).",
                "reset_by_client": "As in `call.outcome`.",
                "reset_by_server": "As in `call.outcome`.",
                "without_trace_id": "Requests whose trace id is not known (see `call.trace_id`).",
                "p50_ns": "As in `service`.",
                "p99_ns": "As in `service`.",
                "max_ns": "The longest request, exactly.",
                "timed": "Requests whose handler was followed. `time_mean` is over these only.",
                "time_mean": "Mean per timed request of the fields of `call.time`; a request without `before_handler_ns` or `after_handler_ns` counts 0 there, so `before_handler_ns`, `after_handler_ns`, `not_seen_ns` and the sum of `off_thread_by_why_mean` add up to `off_thread_ns` (within rounding). null if `timed` is 0.",
                "off_thread_by_why_mean": "Mean per timed request of `call.time.off_thread_by_why`. null if none was seen.",
                "spawned_mean": "Only with `--deep`: mean per timed request of `call.spawned` (`count` is the mean number of units spawned; `blocked_other_ns` includes their downstream and client waits). Not part of `time_mean`, and can exceed the latency. null if no timed request spawned any.",
            },
            "process_cpu": {
                "about": "A traced process's threads, all of them, whatever they were doing: per process, not per request. A request's own `runq_ns` is only what a thread waited while working for it. A runtime's thread that waits for a CPU before it can read an answer and wake the goroutine or task the answer is for works for no request: the request then waits longer on a channel, a lock or another task, and only these figures say a CPU was what it waited for, and by what the CPU did meanwhile, why. They cannot be divided among requests: one wait can delay several, or none.",
                "scope": "As in `health`. Written with the summaries, one record per process whose threads waited.",
                "window_s": "As in `service`.",
                "pid": "The process.",
                "over_ns": "The time the figures cover: the window, or since the agent started. A process first seen later is covered from then.",
                "runq_own_threads_ns": "Its threads runnable and waiting for a CPU while another thread of the same process ran on the CPU they were queued on. That is all it says: other CPUs may have been idle meanwhile (threads kept to too few CPUs, load balancing not caught up yet, more Go threads allowed than CPUs), so it is not by itself a shortage of CPUs. Interrupts handled meanwhile are in it. This and the three below add up to all its threads waited.",
                "runq_cpu_limit_ns": "The same while a CPU limit of their control group, or of one above it, kept them off the CPU (the kernel's own count of the time the group's queue on that CPU was throttled with threads in it): the limit was used up. The CPU may have been idle meanwhile, or run something else. null on a kernel that does not keep that count (before 6.6, or without group scheduling); such a wait is then in the two below.",
                "runq_others_ns": "The same, outside a limit, while something else ran on that CPU: a thread of another process, or of the kernel (ksoftirqd among them). The CPU was taken from the process. Other processes of the same service are others here. Interrupts handled meanwhile are in it.",
                "runq_cpu_idle_ns": "The same, outside a limit, while that CPU ran nothing but its idle task: a wait counts from the wakeup, and an idle CPU takes a while to be woken and to take the thread; interrupts the CPU handled while idle (a busy network's, say) are in it too. No thread had the CPU.",
                "steal_ns": "What the hypervisor took from the CPUs its threads ran or waited on (`steal` in /proc/stat), summed over those CPUs, at the resolution of clock ticks. Not split from the four above: a stolen stretch is in whichever of them the CPU was in. 0 also where the hypervisor does not say.",
                "cgroup_throttled_ns": "The most any of its control groups (its own and those above it, cgroup v2) was throttled by a CPU limit, from their cpu.stat (`throttled_usec`): the group's time, not its threads'. Where the kernel does not say what of the threads' waits a limit caused (`runq_cpu_limit_ns` null), this is what says a limit was hit. null if no such figure could be read.",
            },
            "health": {
                "about": "How complete the other records are.",
                "scope": "`window`: written with each window's summaries. `total`: last record of the run. Counts are since the start in both.",
                "window_s": "As in `service`.",
                "requests": "{started, finished, reset, aborted, in_flight}: started = finished + reset + aborted + in_flight. `aborted`: the connection closed, or its parsing was lost, before the request ended; these are in no summary.",
                "calls_slow": "Requests that took at least `threshold_ns`, so far.",
                "calls_listed": "`call` records written so far. With `list_max` they are written only at the end of the run, the slowest first; a difference to `calls_slow` in the `total` record is requests left out by `list_max`. Those are still in the summaries.",
                "lost": "Counters that mean data was lost or degraded, by name, only those that are not zero. Empty: nothing was lost. `ringbuf_full`: records were dropped, so summaries are short by up to that many and some calls lost their names.",
                "openmp_team_idle_cpu_ns": "Only with `--deep`, where a process's OpenMP teams are followed: CPU time so far of the teams' threads outside the pieces of work they took up for requests (spinning for the rest of their team to finish a region, or for the next region, and the runtime's own doings). It is in no request's `spawned`: what the requests' CPU and this add up to is what the process used. null if none.",
                "agent": "`total` only: {cpu_percent of one core, rss_bytes} of the agent itself.",
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::methods::Methods;
    use blame_common::REQ_F_TRACE;

    fn event(flags: u8) -> RequestEvent {
        // SAFETY: plain integers and bytes; all zeroes is a valid value.
        let mut e: RequestEvent = unsafe { std::mem::zeroed() };
        e.hdr.ts_boot_ns = 5_000_000_000;
        e.hdr.pid = 812;
        e.end_boot_ns = 5_020_000_000;
        e.ready_boot_ns = 4_999_900_000;
        e.flags = flags;
        e.first_unit.kind = UNIT_GOROUTINE;
        e.first_unit.id = 36;
        e.stream_id = 7;
        e.lport = 9090;
        e.rport = 51234;
        e
    }

    /// Every key a record can carry, as `type.key` (nested: `type.key.key`).
    fn keys(record: &Value, out: &mut Vec<String>) {
        let kind = record["type"].as_str().unwrap().to_string();
        fn walk(prefix: &str, value: &Value, out: &mut Vec<String>) {
            if let Some(object) = value.as_object() {
                for (key, value) in object {
                    let path = format!("{prefix}.{key}");
                    out.push(path.clone());
                    walk(&path, value, out);
                }
            }
        }
        walk(&kind, record, out);
    }

    #[test]
    fn timestamps_are_utc_dates() {
        assert_eq!(rfc3339(0).as_deref(), Some("1970-01-01T00:00:00.000000Z"));
        assert_eq!(
            rfc3339(1_794_565_499_414_123_456).as_deref(),
            Some("2026-11-13T10:24:59.414123Z")
        );
        // A leap day, and the day after.
        assert_eq!(
            rfc3339(1_709_164_800_000_000_000).as_deref(),
            Some("2024-02-29T00:00:00.000000Z")
        );
        assert_eq!(
            rfc3339(1_709_251_200_000_000_000).as_deref(),
            Some("2024-03-01T00:00:00.000000Z")
        );
        assert_eq!(rfc3339(-1), None);
    }

    #[test]
    fn a_grpc_call_carries_what_is_known_and_null_for_what_is_not() {
        let mut e = event(REQ_F_HTTP2);
        e.cpu_ns = 3_000_000;
        e.runq_ns = 1_000_000;
        e.blocked_fsvc_ns = 6_000_000;
        e.observed_ns = 4_000_000;
        let what = Meta {
            path: Some("/order.Orders/Create".into()),
            trace: None,
            grpc_status: Some(5),
        };
        let call = call(
            &e,
            Some(&what),
            Some("shop.service"),
            1_794_565_494_414_123_456,
        );
        assert_eq!(call["start"], "2026-11-13T10:24:59.414123Z");
        assert_eq!(call["duration_ns"], 20_000_000);
        assert_eq!(call["protocol"], "http2");
        assert_eq!(call["outcome"], "answered");
        assert_eq!(call["method"], "/order.Orders/Create");
        assert_eq!(call["grpc_status"], 5);
        assert!(call["trace_id"].is_null());
        assert_eq!(call["queued_ns"], 100_000);
        assert_eq!(call["handler"], json!({"kind": "goroutine", "id": 36}));
        assert_eq!(call["time"]["on_cpu_ns"], 3_000_000);
        assert_eq!(call["time"]["blocked_file_service_ns"], 6_000_000);
        assert_eq!(call["time"]["blocked_file_service_lock_ns"], 0);
        assert_eq!(call["time"]["off_thread_ns"], 10_000_000);
        assert!(call["time"]["off_thread_by_why"].is_null());
        // Not known: absent, not 0.
        assert!(call["time"].get("before_handler_ns").is_none());
        e.flags |= REQ_F_HANDLER_TIMED;
        e.before_handler_ns = 2_000_000;
        e.after_handler_ns = 500_000;
        let timed = super::call(&e, Some(&what), None, 0);
        assert_eq!(timed["time"]["before_handler_ns"], 2_000_000);
        assert_eq!(timed["time"]["after_handler_ns"], 500_000);
        e.parked_ns[1] = 7_000_000;
        let call = super::call(&e, Some(&what), None, 0);
        assert_eq!(call["time"]["off_thread_by_why"]["channel_ns"], 7_000_000);
        assert_eq!(call["time"]["off_thread_by_why"]["runnable_ns"], 0);
        // One line, no newline inside.
        assert!(!call.to_string().contains('\n'));
    }

    #[test]
    fn a_call_without_a_followed_handler_has_no_time_and_a_reset_one_no_status() {
        let e = event(REQ_F_HTTP2 | REQ_F_RESET_CLIENT);
        let call = call(&e, None, None, 0);
        assert_eq!(call["outcome"], "reset_by_client");
        assert!(call["time"].is_null() && call["handler"].is_null());
        assert!(call["method"].is_null() && call["service"].is_null());
        // Absent, not null: a reset call has no status to know.
        assert!(call.get("grpc_status").is_none());
        assert!(call.get("request").is_none());
    }

    #[test]
    fn an_http1_request_has_its_line_and_status() {
        let mut e = event(0);
        e.status = 200;
        e.line_len = 6;
        e.line[..6].copy_from_slice(b"GET /a");
        e.first_unit.kind = UNIT_THREAD;
        e.observed_ns = 1;
        e.down_calls = 2;
        let call = call(&e, None, Some("web"), 0);
        assert_eq!(call["protocol"], "http1");
        assert_eq!(call["request"], "GET /a");
        assert_eq!(call["http_status"], 200);
        assert_eq!(call["downstream"]["calls"], 2);
        assert!(call.get("method").is_none() && call.get("stream").is_none());
        // Its traceparent's trace id, when it had one.
        assert!(call["trace_id"].is_null());
        e.flags |= REQ_F_TRACE;
        e.trace = [
            0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
            0x47, 0x36,
        ];
        let call = super::call(&e, None, Some("web"), 0);
        assert_eq!(call["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    #[test]
    fn every_field_written_is_described() {
        let described = fields();
        let mut written = Vec::new();
        let mut e = event(REQ_F_HTTP2);
        e.observed_ns = 1;
        keys(&call(&e, None, None, 0), &mut written);
        let mut http1 = event(0);
        http1.down_calls = 1;
        keys(&call(&http1, None, None, 0), &mut written);
        keys(&start(1, 10, Some(50), 1), &mut written);
        keys(
            &process(1, "goroutine", true, Some("x"), &["y".to_string()]),
            &mut written,
        );
        keys(
            &service(
                Some(10),
                Some("s"),
                &[0; blame_common::RUNQ_BUCKETS as usize],
            ),
            &mut written,
        );
        let mut methods = Methods::default();
        methods.add(&e, None);
        let rows = crate::methods::rows(methods.total(), |_| "s".to_string());
        keys(&method(None, Some("s"), &rows[0]), &mut written);
        let counters = Counters::zero();
        keys(&health(None, &counters, 1, 2, Some((1.0, 2))), &mut written);
        for key in written {
            let (kind, field) = key.split_once('.').unwrap();
            if field == "type" {
                continue;
            }
            let record = &described["records"][kind];
            // Nested objects are described by their parent, except `time`.
            let top = field.split('.').next().unwrap();
            assert!(
                record.get(field).is_some() || (record.get(top).is_some() && top != "time"),
                "`{key}` is written but not described"
            );
        }
    }
}
