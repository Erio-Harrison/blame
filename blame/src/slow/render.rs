//! One request for a person (`render_request`) or a script (`render_raw`).

use blame_common::{
    PARKED, REQ_F_ENDED_BY_CLOSE, REQ_F_HANDLER_TIMED, REQ_F_HTTP2, REQ_F_LINE_TRUNCATED,
    REQ_F_RESET_CLIENT, REQ_F_RESET_SERVER, RequestEvent, UNIT_GOROUTINE, UNIT_TOKIO_TASK,
};

use crate::{
    consume::format_wall_clock, h2meta::Meta, identity::UNATTRIBUTED, methods::OffThread,
    runq::fmt_opt, top::fmt_us,
};

pub(super) fn fmt_ns(ns: u64) -> String {
    fmt_us(ns / 1000)
}

/// Where a request's time went, derived from its event.
struct Breakdown {
    latency_ns: u64,
    blocked_ns: u64,
    /// Time of the request during which no thread was attributed to it:
    /// queued inside the server, or waiting while its thread served others.
    off_thread_ns: u64,
    /// From the socket becoming readable to the first read; `None` when the
    /// arrival was not seen (e.g. data that came before the connection was
    /// accepted).
    queued_ns: Option<u64>,
    /// Share of the attributed thread time by how it was attributed.
    observed_pct: Option<u64>,
}

fn breakdown(event: &RequestEvent) -> Breakdown {
    let latency_ns = event.latency_ns();
    let blocked_ns = event.blocked_down_ns
        + event.blocked_client_ns
        + event.blocked_io_ns
        + event.blocked_mem_ns
        + event.blocked_fsvc_ns
        + event.blocked_other_ns;
    let thread_ns = event.cpu_ns + event.runq_ns + blocked_ns;
    let attributed = event.observed_ns + event.retro_ns;
    Breakdown {
        latency_ns,
        blocked_ns,
        off_thread_ns: latency_ns.saturating_sub(thread_ns),
        queued_ns: (event.ready_boot_ns != 0 && event.ready_boot_ns <= event.hdr.ts_boot_ns)
            .then(|| event.hdr.ts_boot_ns - event.ready_boot_ns),
        observed_pct: (attributed > 0)
            .then(|| (event.observed_ns * 100 + attributed / 2) / attributed),
    }
}

fn line_text(event: &RequestEvent) -> String {
    let mut text: String = String::from_utf8_lossy(event.line_bytes())
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if event.flags & REQ_F_LINE_TRUNCATED != 0 {
        text.push_str("...");
    }
    if text.is_empty() {
        text.push('-');
    }
    text
}

/// A request for a person: what and how slow, then where the time went.
pub(super) fn render_request(
    event: &RequestEvent,
    what: Option<&Meta>,
    label: &str,
    wall_offset: i128,
) -> String {
    let b = breakdown(event);
    let label = if label == UNATTRIBUTED { "-" } else { label };
    let status = match event.status {
        0 => "-".to_string(),
        code => code.to_string(),
    };
    let closed = if event.flags & REQ_F_ENDED_BY_CLOSE != 0 {
        "  (ended by close)"
    } else {
        ""
    };
    if event.flags & REQ_F_HTTP2 != 0 {
        return render_stream(event, what, &b, label, wall_offset);
    }
    let unit = match event.first_unit.kind {
        UNIT_GOROUTINE => format!(" goroutine={}", event.first_unit.id),
        UNIT_TOKIO_TASK => format!(" task={}", event.first_unit.id),
        _ => String::new(),
    };
    let trace = event
        .http1_trace()
        .map(|id| format!("  trace={}", String::from_utf8_lossy(&id)))
        .unwrap_or_default();
    let mut out = format!(
        "  {}  {}  {status}  {}  {label}  pid={}{unit}{closed}{trace}\n",
        format_wall_clock(event.hdr.ts_boot_ns, wall_offset),
        fmt_ns(b.latency_ns),
        line_text(event),
        event.hdr.pid,
    );
    out += &format!(
        "      on_cpu={} runq={} blocked={} (downstream={} client={} disk={} fileservice={} memory={} other={}) off_thread={} queued={}\n",
        fmt_ns(event.cpu_ns),
        fmt_ns(event.runq_ns),
        fmt_ns(b.blocked_ns),
        fmt_ns(event.blocked_down_ns),
        fmt_ns(event.blocked_client_ns),
        fmt_ns(event.blocked_io_ns),
        fsvc_text(event.blocked_fsvc_ns, event.blocked_fsvc_lock_ns),
        fmt_ns(event.blocked_mem_ns),
        fmt_ns(event.blocked_other_ns),
        fmt_ns(b.off_thread_ns),
        fmt_opt(b.queued_ns, fmt_ns),
    );
    out += &parked_line(event, b.off_thread_ns);
    out += &helpers_line(event);
    let attribution = match b.observed_pct {
        Some(pct) => format!("attributed observed={pct}% at_response={}%", 100 - pct),
        None => "attributed -".to_string(),
    };
    if event.down_calls > 0 {
        out += &format!(
            "      downstream calls={} wait={} (first_byte={} transfer={} unread={})  {attribution}\n",
            event.down_calls,
            fmt_ns(event.down_wait_ns),
            fmt_ns(event.down_service_ns),
            fmt_ns(event.down_transfer_ns),
            fmt_ns(
                event
                    .down_wait_ns
                    .saturating_sub(event.down_service_ns + event.down_transfer_ns)
            ),
        );
    } else {
        out += &format!("      {attribution}\n");
    }
    out
}

/// Go, following why goroutines park: where the request's goroutine was
/// while on no thread. What is left of off_thread is time no probe saw
/// (before the goroutine was bound to the request, or on the way to
/// parking).
fn parked_line(event: &RequestEvent, off_thread_ns: u64) -> String {
    let parked = event.parked();
    let seen: u64 = parked.iter().sum();
    let timed = event.flags & REQ_F_HANDLER_TIMED != 0;
    if seen == 0 && !timed {
        return String::new();
    }
    let mut parts = Vec::new();
    let split = OffThread::of(event, off_thread_ns);
    // Before the handler first ran, after it last left its thread.
    if timed {
        parts.push(format!(
            "before_handler={}",
            fmt_ns(split.before_handler_ns)
        ));
        parts.push(format!("after_handler={}", fmt_ns(split.after_handler_ns)));
    }
    // Why the handler was off its thread in between (--deep). The last
    // two are tokio's alone: shown when there is any.
    if seen > 0 {
        parts.extend(
            PARKED
                .iter()
                .zip(parked)
                .enumerate()
                .filter(|&(i, (_, ns))| i < 7 || ns > 0)
                .map(|(_, (name, ns))| format!("{name}={}", fmt_ns(ns))),
        );
    }
    // The parts add up to off_thread.
    parts.push(format!("not_seen={}", fmt_ns(split.not_seen_ns)));
    format!("      off_thread: {}\n", parts.join(" "))
}

/// The goroutines and tasks a request spawned (`--spawned`), if any: their
/// time, which is not part of the breakdown above it. They run side by side
/// with the handler and with each other, so it can add up to more than the
/// latency; it is not a share of it.
fn helpers_line(event: &RequestEvent) -> String {
    if event.helpers == 0 {
        return String::new();
    }
    let blocked = event.helper_down_ns
        + event.helper_client_ns
        + event.helper_io_ns
        + event.helper_mem_ns
        + event.helper_fsvc_ns
        + event.helper_other_ns;
    format!(
        "      spawned={} their on_cpu={} runq={} blocked={} (downstream={} disk={} fileservice={} memory={} other={})\n",
        event.helpers,
        fmt_ns(event.helper_cpu_ns),
        fmt_ns(event.helper_runq_ns),
        fmt_ns(blocked),
        fmt_ns(event.helper_down_ns),
        fmt_ns(event.helper_io_ns),
        fsvc_text(event.helper_fsvc_ns, event.helper_fsvc_lock_ns),
        fmt_ns(event.helper_mem_ns),
        fmt_ns(event.helper_other_ns + event.helper_client_ns),
    )
}

/// A file-service wait, and of it the part spent waiting for a lock that
/// another thread held (mostly another request writing or flushing the same
/// file), when there was any: `76ms(lock=72ms)`.
fn fsvc_text(total_ns: u64, lock_ns: u64) -> String {
    if lock_ns == 0 {
        fmt_ns(total_ns)
    } else {
        format!("{}(lock={})", fmt_ns(total_ns), fmt_ns(lock_ns))
    }
}

/// Text from the wire, safe to print on one line.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || c == ' ' || c == '"' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// An HTTP/2 stream for a person.
///
/// What it is comes from its header blocks, when the connection's could be
/// decoded (`what`); otherwise it is shown by connection and stream number.
/// Where its time went is known only when the runtime's adapter found the
/// goroutine or task that served it: the unit that reads the connection
/// serves many streams at once and none in particular.
fn render_stream(
    event: &RequestEvent,
    what: Option<&Meta>,
    b: &Breakdown,
    label: &str,
    wall_offset: i128,
) -> String {
    let name = match what.and_then(|meta| meta.path.as_deref()) {
        Some(path) => printable(path),
        None => format!("HTTP/2 stream {} on :{}", event.stream_id, event.lport),
    };
    let mut first = format!(
        "  {}  {}  {name}",
        format_wall_clock(event.hdr.ts_boot_ns, wall_offset),
        fmt_ns(b.latency_ns),
    );
    // Reset instead of answered: there is no status, and the times below
    // are those up to the reset.
    if event.flags & REQ_F_RESET_CLIENT != 0 {
        first += "  reset by client";
    } else if event.flags & REQ_F_RESET_SERVER != 0 {
        first += "  reset by server";
    } else if let Some(status) = what.and_then(|meta| meta.grpc_status) {
        first += &format!("  grpc_status={status}");
    }
    first += &format!("  {label}  pid={}", event.hdr.pid);
    let followed = event.observed_ns > 0;
    if followed {
        match event.first_unit.kind {
            UNIT_GOROUTINE => first += &format!(" goroutine={}", event.first_unit.id),
            UNIT_TOKIO_TASK => first += &format!(" task={}", event.first_unit.id),
            _ => {}
        }
    }
    if let Some(trace) = what.and_then(Meta::trace) {
        first += &format!("  trace={trace}");
    }
    let second = if followed {
        format!(
            "      on_cpu={} runq={} blocked={} (disk={} fileservice={} memory={} other={}) off_thread={} queued={}",
            fmt_ns(event.cpu_ns),
            fmt_ns(event.runq_ns),
            fmt_ns(b.blocked_ns),
            fmt_ns(event.blocked_io_ns),
            fsvc_text(event.blocked_fsvc_ns, event.blocked_fsvc_lock_ns),
            fmt_ns(event.blocked_mem_ns),
            fmt_ns(event.blocked_other_ns + event.blocked_down_ns + event.blocked_client_ns),
            fmt_ns(b.off_thread_ns),
            fmt_opt(b.queued_ns, fmt_ns),
        )
    } else {
        format!(
            "      queued={}  (its handler was not followed: no time breakdown)",
            fmt_opt(b.queued_ns, fmt_ns)
        )
    };
    let parked = if followed {
        parked_line(event, b.off_thread_ns)
    } else {
        String::new()
    };
    format!("{first}\n{second}\n{parked}{}", helpers_line(event))
}

/// A request for a script: every field, times in nanoseconds since boot.
/// Numbers come before `line`, text after it. For an HTTP/2 stream:
/// `grpc_status` is -1 and `path` is `-` when not known; `trace` is `-`
/// when not known, for HTTP/1 too.
pub(super) fn render_raw(event: &RequestEvent, what: Option<&Meta>) -> String {
    let path = what.and_then(|meta| meta.path.as_deref());
    let http1_trace = event.http1_trace();
    let trace = what.and_then(Meta::trace).or_else(|| {
        http1_trace
            .as_ref()
            .and_then(|id| std::str::from_utf8(id).ok())
    });
    let grpc_status = what.and_then(|meta| meta.grpc_status);
    format!(
        "req id={} start_ns={} end_ns={} ready_ns={} pid={} tid={} last_tid={} cgroup={} \
         lport={} rport={} status={} flags={} cpu_ns={} runq_ns={} blocked_down_ns={} \
         blocked_client_ns={} blocked_io_ns={} blocked_mem_ns={} blocked_fsvc_ns={} blocked_other_ns={} observed_ns={} retro_ns={} down_calls={} \
         down_wait_ns={} down_service_ns={} down_transfer_ns={} unit_kind={} unit_id={} \
         stream={} conn={} grpc_status={} helpers={} helper_cpu_ns={} helper_runq_ns={} \
         helper_down_ns={} helper_client_ns={} helper_io_ns={} helper_mem_ns={} helper_fsvc_ns={} helper_other_ns={} \
         parked_runnable_ns={} parked_channel_ns={} parked_sync_ns={} parked_sleep_ns={} \
         parked_network_ns={} parked_gc_ns={} parked_other_ns={} blocked_fsvc_lock_ns={} helper_fsvc_lock_ns={} \
         before_handler_ns={} after_handler_ns={} parked_task_ns={} parked_blocking_ns={} line=\"{}\" path={} trace={}",
        event.req_id,
        event.hdr.ts_boot_ns,
        event.end_boot_ns,
        event.ready_boot_ns,
        event.hdr.pid,
        event.hdr.tid,
        event.last_tid,
        event.hdr.cgroup_id,
        event.lport,
        event.rport,
        event.status,
        event.flags,
        event.cpu_ns,
        event.runq_ns,
        event.blocked_down_ns,
        event.blocked_client_ns,
        event.blocked_io_ns,
        event.blocked_mem_ns,
        event.blocked_fsvc_ns,
        event.blocked_other_ns,
        event.observed_ns,
        event.retro_ns,
        event.down_calls,
        event.down_wait_ns,
        event.down_service_ns,
        event.down_transfer_ns,
        event.first_unit.kind,
        event.first_unit.id,
        event.stream_id,
        event.conn,
        grpc_status.map_or(-1, i64::from),
        event.helpers,
        event.helper_cpu_ns,
        event.helper_runq_ns,
        event.helper_down_ns,
        event.helper_client_ns,
        event.helper_io_ns,
        event.helper_mem_ns,
        event.helper_fsvc_ns,
        event.helper_other_ns,
        event.parked_ns[0],
        event.parked_ns[1],
        event.parked_ns[2],
        event.parked_ns[3],
        event.parked_ns[4],
        event.parked_ns[5],
        event.parked_ns[6],
        event.blocked_fsvc_lock_ns,
        event.helper_fsvc_lock_ns,
        event.before_handler_ns,
        event.after_handler_ns,
        event.parked_task_ns,
        event.parked_blocking_ns,
        line_text(event),
        path.map_or_else(|| "-".to_string(), printable),
        trace.unwrap_or("-"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slow::test_event::event;
    use blame_common::REQ_F_TRACE;

    #[test]
    fn time_no_thread_was_attributed_is_what_is_left_of_the_latency() {
        let b = breakdown(&event("GET /a"));
        assert_eq!(b.latency_ns, 500_000_000);
        assert_eq!(b.blocked_ns, 396_000_000);
        assert_eq!(b.off_thread_ns, 100_000_000);
        assert_eq!(b.queued_ns, Some(15_000));
        assert_eq!(b.observed_pct, Some(75));
    }

    #[test]
    fn threads_working_in_parallel_do_not_make_the_remainder_negative() {
        let mut e = event("GET /a");
        e.cpu_ns = 900_000_000;
        assert_eq!(breakdown(&e).off_thread_ns, 0);
    }

    #[test]
    fn unknown_arrival_and_no_attributed_time_are_shown_as_unknown() {
        let mut e = event("GET /a");
        e.ready_boot_ns = 0;
        e.observed_ns = 0;
        e.retro_ns = 0;
        e.down_calls = 0;
        let b = breakdown(&e);
        assert_eq!((b.queued_ns, b.observed_pct), (None, None));
        let out = render_request(&e, None, "shop.service", 0);
        assert!(out.contains("queued=-"));
        assert!(out.contains("attributed -"));
        assert!(!out.contains("downstream calls"));
    }

    #[test]
    fn a_request_is_rendered_with_its_line_service_and_breakdown() {
        let out = render_request(&event("GET /api/orders"), None, "shop.service", 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("500.0ms  200  GET /api/orders  shop.service  pid=812"));
        assert!(lines[1].contains(
            "on_cpu=3.0ms runq=1.0ms blocked=396.0ms (downstream=380.0ms client=0us disk=4.0ms fileservice=0us memory=2.0ms other=10.0ms) off_thread=100.0ms queued=15us"
        ));
        assert!(lines[2].contains(
            "downstream calls=2 wait=381.0ms (first_byte=380.5ms transfer=300us unread=200us)"
        ));
        assert!(lines[2].contains("attributed observed=75% at_response=25%"));
    }

    #[test]
    fn an_http2_stream_is_shown_without_what_is_not_known_about_it() {
        let mut e = event("");
        e.flags = REQ_F_HTTP2;
        e.stream_id = 41;
        e.status = 0;
        // No handler was found for it: no unit's time is its own.
        e.observed_ns = 0;
        let out = render_request(&e, None, "shop.service", 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("500.0ms  HTTP/2 stream 41 on :8080  shop.service  pid=812"));
        assert!(lines[1].contains("queued=15us"));
        assert!(lines[1].contains("not followed"));
        assert!(!out.contains("on_cpu") && !out.contains("off_thread"));
        let raw = render_raw(&e, None);
        assert!(raw.contains(" stream=41 "));
        assert!(raw.ends_with(
            " grpc_status=-1 helpers=0 helper_cpu_ns=0 helper_runq_ns=0 helper_down_ns=0 helper_client_ns=0 helper_io_ns=0 helper_mem_ns=0 helper_fsvc_ns=0 helper_other_ns=0 parked_runnable_ns=0 parked_channel_ns=0 parked_sync_ns=0 parked_sleep_ns=0 parked_network_ns=0 parked_gc_ns=0 parked_other_ns=0 blocked_fsvc_lock_ns=0 helper_fsvc_lock_ns=0 before_handler_ns=0 after_handler_ns=0 parked_task_ns=0 parked_blocking_ns=0 line=\"-\" path=- trace=-"
        ));
    }

    #[test]
    fn a_grpc_call_is_shown_with_its_method_status_trace_and_breakdown() {
        let mut e = event("");
        e.flags = REQ_F_HTTP2;
        e.stream_id = 41;
        e.status = 0;
        e.first_unit.kind = UNIT_GOROUTINE;
        e.first_unit.id = 8841;
        let what = Meta {
            path: Some("/order.Orders/Create new".into()),
            trace: Some(*b"4bf92f3577b34da6a3ce929d0e0e4736"),
            grpc_status: Some(5),
        };
        let out = render_request(&e, Some(&what), "shop.service", 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        // A space in what came off the wire would break the line apart.
        assert!(lines[0].contains(
            "500.0ms  /order.Orders/Create?new  grpc_status=5  shop.service  pid=812 goroutine=8841  trace=4bf92f3577b34da6a3ce929d0e0e4736"
        ));
        assert!(lines[1].contains(
            "on_cpu=3.0ms runq=1.0ms blocked=396.0ms (disk=4.0ms fileservice=0us memory=2.0ms other=390.0ms) off_thread=100.0ms queued=15us"
        ));
        let raw = render_raw(&e, Some(&what));
        assert!(raw.ends_with(
            " grpc_status=5 helpers=0 helper_cpu_ns=0 helper_runq_ns=0 helper_down_ns=0 helper_client_ns=0 helper_io_ns=0 helper_mem_ns=0 helper_fsvc_ns=0 helper_other_ns=0 parked_runnable_ns=0 parked_channel_ns=0 parked_sync_ns=0 parked_sleep_ns=0 parked_network_ns=0 parked_gc_ns=0 parked_other_ns=0 blocked_fsvc_lock_ns=0 helper_fsvc_lock_ns=0 before_handler_ns=0 after_handler_ns=0 parked_task_ns=0 parked_blocking_ns=0 line=\"-\" path=/order.Orders/Create?new trace=4bf92f3577b34da6a3ce929d0e0e4736"
        ));
    }

    #[test]
    fn a_call_that_was_reset_says_by_whom_and_gives_no_status() {
        let mut e = event("");
        e.flags = REQ_F_HTTP2 | REQ_F_RESET_CLIENT;
        e.stream_id = 41;
        e.status = 0;
        let what = Meta {
            path: Some("/order.Orders/Create".into()),
            trace: None,
            // The stream's trailers never came; whatever is here is not shown.
            grpc_status: Some(0),
        };
        let out = render_request(&e, Some(&what), "shop.service", 0);
        assert!(
            out.lines()
                .next()
                .unwrap()
                .contains("500.0ms  /order.Orders/Create  reset by client  shop.service  pid=812")
        );
        assert!(!out.contains("grpc_status"));
        e.flags = REQ_F_HTTP2 | REQ_F_RESET_SERVER;
        assert!(render_request(&e, None, "shop.service", 0).contains("  reset by server  "));
    }

    #[test]
    fn truncated_lines_and_control_bytes_are_marked() {
        let mut e = event("GET /a\x01b");
        e.flags = REQ_F_LINE_TRUNCATED | REQ_F_ENDED_BY_CLOSE;
        e.status = 0;
        assert_eq!(line_text(&e), "GET /a?b...");
        let out = render_request(&e, None, UNATTRIBUTED, 0);
        assert!(
            out.lines()
                .next()
                .unwrap()
                .contains("  -  GET /a?b...  -  pid=812  (ended by close)")
        );
    }

    #[test]
    fn spawned_units_get_a_line_of_their_own_only_when_there_are_some() {
        let mut e = event("GET /api/orders");
        assert!(!render_request(&e, None, "shop.service", 0).contains("spawned="));
        e.helpers = 3;
        e.helper_cpu_ns = 12_000_000;
        e.helper_runq_ns = 1_000_000;
        e.helper_io_ns = 900_000_000;
        e.helper_other_ns = 2_000_000;
        e.helper_client_ns = 1_000_000;
        let out = render_request(&e, None, "shop.service", 0);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4);
        // More than the latency (500 ms): the helpers ran side by side.
        assert!(lines[2].contains(
            "spawned=3 their on_cpu=12.0ms runq=1.0ms blocked=903.0ms (downstream=0us disk=900.0ms fileservice=0us memory=0us other=3.0ms)"
        ));
        let raw = render_raw(&e, None);
        assert!(raw.contains(
            " helpers=3 helper_cpu_ns=12000000 helper_runq_ns=1000000 helper_down_ns=0 helper_client_ns=1000000 helper_io_ns=900000000 helper_mem_ns=0 helper_fsvc_ns=0 helper_other_ns=2000000 parked_runnable_ns=0 parked_channel_ns=0 parked_sync_ns=0 parked_sleep_ns=0 parked_network_ns=0 parked_gc_ns=0 parked_other_ns=0 blocked_fsvc_lock_ns=0 helper_fsvc_lock_ns=0 before_handler_ns=0 after_handler_ns=0 parked_task_ns=0 parked_blocking_ns=0 line="
        ));
    }

    #[test]
    fn time_waiting_for_a_file_service_is_shown_apart_from_the_disk() {
        let mut e = event("POST /orders");
        e.blocked_fsvc_ns = 90_000_000;
        e.helpers = 1;
        e.helper_fsvc_ns = 7_000_000;
        let out = render_request(&e, None, "shop.service", 0);
        // Part of the blocked time, so not left over as off-thread.
        assert!(out.contains(
            "blocked=486.0ms (downstream=380.0ms client=0us disk=4.0ms fileservice=90.0ms memory=2.0ms other=10.0ms) off_thread=10.0ms"
        ));
        assert!(out.contains("(downstream=0us disk=0us fileservice=7.0ms memory=0us other=0us)"));
        let raw = render_raw(&e, None);
        assert!(raw.contains(" blocked_mem_ns=2000000 blocked_fsvc_ns=90000000 blocked_other_ns="));
        assert!(raw.contains(" helper_fsvc_ns=7000000 "));
        // Of it, waiting for a lock: shown only when there was any.
        assert!(!out.contains("(lock="));
        e.blocked_fsvc_lock_ns = 72_000_000;
        e.helper_fsvc_lock_ns = 1_000_000;
        let out = render_request(&e, None, "shop.service", 0);
        assert!(out.contains(" fileservice=90.0ms(lock=72.0ms) memory=2.0ms "));
        assert!(out.contains(" fileservice=7.0ms(lock=1.0ms) "));
        let raw = render_raw(&e, None);
        assert!(raw.contains(" blocked_fsvc_lock_ns=72000000 helper_fsvc_lock_ns=1000000 "));
    }

    #[test]
    fn where_a_goroutine_was_off_its_thread_is_shown_when_seen() {
        let mut e = event("GET /api/orders");
        assert!(!render_request(&e, None, "shop.service", 0).contains("off_thread:"));
        // off_thread is 100 ms; 70 of it is accounted for.
        e.parked_ns = [5_000_000, 40_000_000, 20_000_000, 0, 5_000_000, 0, 0];
        let out = render_request(&e, None, "shop.service", 0);
        assert!(out.contains(
            "off_thread: runnable=5.0ms channel=40.0ms sync=20.0ms sleep=0us network=5.0ms gc=0us other=0us not_seen=30.0ms"
        ));
        let raw = render_raw(&e, None);
        assert!(raw.contains(
            " parked_runnable_ns=5000000 parked_channel_ns=40000000 parked_sync_ns=20000000 "
        ));
        // Before the handler first ran and after it last left: not part of
        // what was not seen.
        e.flags |= REQ_F_HANDLER_TIMED;
        e.before_handler_ns = 12_000_000;
        e.after_handler_ns = 3_000_000;
        let out = render_request(&e, None, "shop.service", 0);
        assert!(out.contains(
            "off_thread: before_handler=12.0ms after_handler=3.0ms runnable=5.0ms channel=40.0ms sync=20.0ms sleep=0us network=5.0ms gc=0us other=0us not_seen=15.0ms"
        ));
        let raw = render_raw(&e, None);
        assert!(raw.contains(" before_handler_ns=12000000 after_handler_ns=3000000 parked_task_ns=0 parked_blocking_ns=0 line="));
    }

    #[test]
    fn what_woke_a_tokio_task_is_shown_only_when_there_is_any() {
        let mut e = event("GET /api/orders");
        e.parked_ns = [5_000_000, 0, 0, 0, 20_000_000, 0, 0];
        let go = render_request(&e, None, "shop.service", 0);
        assert!(!go.contains(" task=") && !go.contains(" blocking="));
        e.parked_task_ns = 30_000_000;
        e.parked_blocking_ns = 15_000_000;
        let out = render_request(&e, None, "shop.service", 0);
        assert!(out.contains(
            "off_thread: runnable=5.0ms channel=0us sync=0us sleep=0us network=20.0ms gc=0us other=0us task=30.0ms blocking=15.0ms not_seen=30.0ms"
        ));
        assert!(
            render_raw(&e, None)
                .contains(" parked_task_ns=30000000 parked_blocking_ns=15000000 line=")
        );
    }

    #[test]
    fn the_time_outside_the_handler_is_shown_without_the_reasons_too() {
        let mut e = event("GET /api/orders");
        e.flags |= REQ_F_HANDLER_TIMED;
        e.before_handler_ns = 12_000_000;
        e.after_handler_ns = 0;
        let out = render_request(&e, None, "shop.service", 0);
        // The rest of the 100 ms off the thread: not seen why.
        assert!(out.contains(
            "      off_thread: before_handler=12.0ms after_handler=0us not_seen=88.0ms\n"
        ));
        // Not known: not shown.
        e.flags &= !REQ_F_HANDLER_TIMED;
        assert!(!render_request(&e, None, "shop.service", 0).contains("off_thread:"));
    }

    #[test]
    fn an_http1_request_shows_the_trace_id_of_its_traceparent() {
        let mut e = event("GET /api/orders");
        assert!(!render_request(&e, None, "shop.service", 0).contains("trace="));
        assert!(render_raw(&e, None).ends_with(" trace=-"));
        e.flags |= REQ_F_TRACE;
        e.trace = [
            0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
            0x47, 0x36,
        ];
        let out = render_request(&e, None, "shop.service", 0);
        assert!(
            out.lines()
                .next()
                .unwrap()
                .ends_with("  trace=4bf92f3577b34da6a3ce929d0e0e4736")
        );
        assert!(render_raw(&e, None).ends_with(" trace=4bf92f3577b34da6a3ce929d0e0e4736"));
    }

    #[test]
    fn raw_lines_carry_every_field_in_nanoseconds() {
        let out = render_raw(&event("GET /a"), None);
        assert!(out.starts_with(
            "req id=42 start_ns=1000000000 end_ns=1500000000 ready_ns=999985000 pid=812 tid=815"
        ));
        assert!(out.contains(" rport=51234 status=200 "));
        assert!(out.contains(" down_calls=2 down_wait_ns=381000000 down_service_ns=380500000 down_transfer_ns=300000 "));
        assert!(out.ends_with("line=\"GET /a\" path=- trace=-"));
    }
}
