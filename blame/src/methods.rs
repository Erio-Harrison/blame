//! Requests summed up by what they were: per service and path (for gRPC,
//! the method; for HTTP/1, the method and the route, see [`route`]), how
//! many there were, how they ended, how long they took, and where the time
//! of their handlers went on average.
//!
//! Every request is counted, slow or not: the kernel side reports each one.
//! An HTTP/2 request's path comes from its header blocks (`h2meta`), an
//! HTTP/1 one's from its request line. Requests whose path is not known are
//! summed up as such, not left out and not added to another row.

use std::{collections::HashMap, rc::Rc};

use blame_common::{
    REQ_F_HANDLER_TIMED, REQ_F_HTTP2, REQ_F_LINE_TRUNCATED, REQ_F_RESET_CLIENT, REQ_F_RESET_SERVER,
    RUNQ_BUCKETS, RequestEvent, runq_bucket,
};

use crate::{
    h2meta::Meta,
    runq::{Hist, fmt_opt, summary},
    top::fmt_us,
};

/// Paths summed up separately per service; the rest share one row. A gRPC
/// service has a few dozen methods; a path with an id in it has no end.
const PATHS_PER_SERVICE: usize = 256;

/// An HTTP/1 request line (method and path, the query left out by the
/// kernel side) as a route: path segments that are ids, all digits, a UUID,
/// or 16 or more hex digits, become `{id}`, so that `/order/16844` and
/// `/order/16845` are one row. Nothing else is guessed: `/users/alice`
/// stays as it is. A line cut short by the kernel side ends in `...`.
pub fn route(event: &RequestEvent) -> String {
    let text = String::from_utf8_lossy(event.line_bytes());
    let (method, path) = text.split_once(' ').unwrap_or((&text, ""));
    let path: Vec<&str> = path
        .split('/')
        .map(|segment| if is_id(segment) { "{id}" } else { segment })
        .collect();
    let cut = if event.flags & REQ_F_LINE_TRUNCATED != 0 {
        "..."
    } else {
        ""
    };
    format!("{method} {}{cut}", path.join("/"))
}

fn is_id(segment: &str) -> bool {
    let b = segment.as_bytes();
    let hex = |c: &u8| c.is_ascii_hexdigit();
    let uuid = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                *c == b'-'
            } else {
                hex(c)
            }
        });
    !b.is_empty()
        && (b.iter().all(u8::is_ascii_digit) || uuid || (b.len() >= 16 && b.iter().all(hex)))
}

/// A request's time off any thread (`off_thread_ns`), in parts that add up
/// to it: before its handler first ran and after it last left its thread
/// (when the runtime's switches were followed exactly), parked, by why
/// (`--deep`), and the rest, which nothing split (`not_seen_ns`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OffThread {
    pub before_handler_ns: u64,
    pub after_handler_ns: u64,
    pub parked_ns: u64,
    pub not_seen_ns: u64,
}

impl OffThread {
    pub fn of(event: &RequestEvent, off_thread_ns: u64) -> Self {
        let (before_handler_ns, after_handler_ns) = if event.flags & REQ_F_HANDLER_TIMED != 0 {
            (event.before_handler_ns, event.after_handler_ns)
        } else {
            (0, 0)
        };
        let parked_ns: u64 = event.parked().iter().sum();
        Self {
            before_handler_ns,
            after_handler_ns,
            parked_ns,
            not_seen_ns: off_thread_ns
                .saturating_sub(before_handler_ns + after_handler_ns + parked_ns),
        }
    }
}

/// What a row is about.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Method {
    Path(Rc<str>),
    /// More paths than are kept apart.
    Other,
    /// The request's header blocks could not be decoded.
    Unknown,
}

impl Method {
    fn text(&self) -> &str {
        match self {
            Self::Path(path) => path,
            Self::Other => "(other paths)",
            Self::Unknown => "(path not known)",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stats {
    pub calls: u64,
    /// Answered with gRPC status 0 ...
    pub ok: u64,
    /// ... with another status ...
    pub errors: u64,
    /// ... or answered, with a status that is not known (or not gRPC).
    pub status_unknown: u64,
    pub reset_client: u64,
    pub reset_server: u64,
    /// Requests whose trace id is not known.
    pub no_trace: u64,
    /// Latencies, in the kernel side's buckets.
    pub hist: Hist,
    pub max_ns: u64,
    /// Requests whose handler was followed: the sums below are theirs.
    pub timed: u64,
    pub cpu_ns: u64,
    pub runq_ns: u64,
    pub disk_ns: u64,
    pub memory_ns: u64,
    /// Waiting for a file service (NFS, SMB, FUSE, virtiofs).
    pub file_service_ns: u64,
    pub blocked_other_ns: u64,
    pub off_thread_ns: u64,
    /// `off_thread_ns` in parts (see [`OffThread`]); the by-why part is
    /// `parked_ns` below.
    pub before_handler_ns: u64,
    pub after_handler_ns: u64,
    pub not_seen_ns: u64,
    /// Of the timed requests: the goroutines and tasks they spawned
    /// (`--deep`), and the time of those, by what they did.
    pub spawned: u64,
    pub spawned_cpu_ns: u64,
    pub spawned_runq_ns: u64,
    pub spawned_disk_ns: u64,
    pub spawned_memory_ns: u64,
    pub spawned_file_service_ns: u64,
    pub spawned_other_ns: u64,
    /// Go, following why goroutines park: the handlers' time on no thread,
    /// by why (`blame_common::PARKED`).
    pub parked_ns: [u64; 9],
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            calls: 0,
            ok: 0,
            errors: 0,
            status_unknown: 0,
            reset_client: 0,
            reset_server: 0,
            no_trace: 0,
            hist: [0; RUNQ_BUCKETS as usize],
            max_ns: 0,
            timed: 0,
            cpu_ns: 0,
            runq_ns: 0,
            disk_ns: 0,
            memory_ns: 0,
            file_service_ns: 0,
            blocked_other_ns: 0,
            off_thread_ns: 0,
            before_handler_ns: 0,
            after_handler_ns: 0,
            not_seen_ns: 0,
            spawned: 0,
            spawned_cpu_ns: 0,
            spawned_runq_ns: 0,
            spawned_disk_ns: 0,
            spawned_memory_ns: 0,
            spawned_file_service_ns: 0,
            parked_ns: [0; 9],
            spawned_other_ns: 0,
        }
    }
}

impl Stats {
    fn add(&mut self, event: &RequestEvent, what: Option<&Meta>) {
        let latency = event.latency_ns();
        self.calls += 1;
        if event.flags & REQ_F_RESET_CLIENT != 0 {
            self.reset_client += 1;
        } else if event.flags & REQ_F_RESET_SERVER != 0 {
            self.reset_server += 1;
        } else if event.flags & REQ_F_HTTP2 != 0 {
            match what.and_then(|meta| meta.grpc_status) {
                Some(0) => self.ok += 1,
                Some(_) => self.errors += 1,
                None => self.status_unknown += 1,
            }
        } else {
            // HTTP/1: 1xx to 3xx answered, 4xx and 5xx errors.
            match event.status {
                0 => self.status_unknown += 1,
                1..400 => self.ok += 1,
                _ => self.errors += 1,
            }
        }
        let trace = if event.flags & REQ_F_HTTP2 != 0 {
            what.and_then(Meta::trace).is_some()
        } else {
            event.http1_trace().is_some()
        };
        self.no_trace += u64::from(!trace);
        self.hist[runq_bucket(latency) as usize] += 1;
        self.max_ns = self.max_ns.max(latency);
        if event.observed_ns > 0 {
            let blocked_other =
                event.blocked_other_ns + event.blocked_down_ns + event.blocked_client_ns;
            let on_thread = event.cpu_ns
                + event.runq_ns
                + event.blocked_io_ns
                + event.blocked_mem_ns
                + event.blocked_fsvc_ns
                + blocked_other;
            self.timed += 1;
            self.cpu_ns += event.cpu_ns;
            self.runq_ns += event.runq_ns;
            self.disk_ns += event.blocked_io_ns;
            self.memory_ns += event.blocked_mem_ns;
            self.file_service_ns += event.blocked_fsvc_ns;
            self.blocked_other_ns += blocked_other;
            let off_thread = latency.saturating_sub(on_thread);
            let parts = OffThread::of(event, off_thread);
            self.off_thread_ns += off_thread;
            self.before_handler_ns += parts.before_handler_ns;
            self.after_handler_ns += parts.after_handler_ns;
            self.not_seen_ns += parts.not_seen_ns;
            self.spawned += u64::from(event.helpers);
            self.spawned_cpu_ns += event.helper_cpu_ns;
            self.spawned_runq_ns += event.helper_runq_ns;
            self.spawned_disk_ns += event.helper_io_ns;
            self.spawned_memory_ns += event.helper_mem_ns;
            self.spawned_file_service_ns += event.helper_fsvc_ns;
            for (sum, ns) in self.parked_ns.iter_mut().zip(event.parked()) {
                *sum += ns;
            }
            self.spawned_other_ns +=
                event.helper_other_ns + event.helper_down_ns + event.helper_client_ns;
        }
    }

    fn merge(&mut self, other: &Self) {
        self.calls += other.calls;
        self.ok += other.ok;
        self.errors += other.errors;
        self.status_unknown += other.status_unknown;
        self.reset_client += other.reset_client;
        self.reset_server += other.reset_server;
        self.no_trace += other.no_trace;
        for (mine, theirs) in self.hist.iter_mut().zip(&other.hist) {
            *mine += theirs;
        }
        self.max_ns = self.max_ns.max(other.max_ns);
        self.timed += other.timed;
        self.cpu_ns += other.cpu_ns;
        self.runq_ns += other.runq_ns;
        self.disk_ns += other.disk_ns;
        self.memory_ns += other.memory_ns;
        self.file_service_ns += other.file_service_ns;
        self.blocked_other_ns += other.blocked_other_ns;
        self.off_thread_ns += other.off_thread_ns;
        self.before_handler_ns += other.before_handler_ns;
        self.after_handler_ns += other.after_handler_ns;
        self.not_seen_ns += other.not_seen_ns;
        self.spawned += other.spawned;
        self.spawned_cpu_ns += other.spawned_cpu_ns;
        self.spawned_runq_ns += other.spawned_runq_ns;
        self.spawned_disk_ns += other.spawned_disk_ns;
        self.spawned_memory_ns += other.spawned_memory_ns;
        self.spawned_file_service_ns += other.spawned_file_service_ns;
        for (sum, ns) in self.parked_ns.iter_mut().zip(other.parked_ns) {
            *sum += ns;
        }
        self.spawned_other_ns += other.spawned_other_ns;
    }
}

/// Sums by (cgroup, method).
pub type Sums = HashMap<(u64, Method), Stats>;

#[derive(Default)]
pub struct Methods {
    /// Since the last [`Methods::take_window`].
    window: Sums,
    /// Since the start.
    total: Sums,
    /// Paths kept apart so far, per cgroup.
    paths: HashMap<u64, usize>,
}

impl Methods {
    /// Count one finished request.
    pub fn add(&mut self, event: &RequestEvent, what: Option<&Meta>) {
        let cgroup = event.hdr.cgroup_id;
        let http1: Option<Rc<str>> = (event.flags & REQ_F_HTTP2 == 0).then(|| route(event).into());
        let path = if event.flags & REQ_F_HTTP2 != 0 {
            what.and_then(|meta| meta.path.as_ref())
        } else {
            http1.as_ref()
        };
        let method = match path {
            None => Method::Unknown,
            Some(path) => {
                let wanted = (cgroup, Method::Path(Rc::clone(path)));
                if self.total.contains_key(&wanted) {
                    wanted.1
                } else {
                    let kept = self.paths.entry(cgroup).or_default();
                    if *kept < PATHS_PER_SERVICE {
                        *kept += 1;
                        wanted.1
                    } else {
                        Method::Other
                    }
                }
            }
        };
        let key = (cgroup, method);
        self.total.entry(key.clone()).or_default().add(event, what);
        self.window.entry(key).or_default().add(event, what);
    }

    /// The sums since the last call, which start over.
    pub fn take_window(&mut self) -> Sums {
        std::mem::take(&mut self.window)
    }

    pub fn total(&self) -> &Sums {
        &self.total
    }
}

/// One row of the summary: a method of a service.
pub struct Row {
    pub service: String,
    pub method: Method,
    pub stats: Stats,
}

/// Rows by service label: cgroups that share a label (a restarted service)
/// are one service. Slowest first, by p99 where there is one.
pub fn rows(sums: &Sums, mut label: impl FnMut(u64) -> String) -> Vec<Row> {
    let mut merged: HashMap<(String, Method), Stats> = HashMap::new();
    for ((cgroup, method), stats) in sums {
        merged
            .entry((label(*cgroup), method.clone()))
            .or_default()
            .merge(stats);
    }
    let mut out: Vec<Row> = merged
        .into_iter()
        .map(|((service, method), stats)| Row {
            service,
            method,
            stats,
        })
        .collect();
    out.sort_by(|a, b| {
        let key = |row: &Row| {
            let s = summary(&row.stats.hist);
            (s.p99_us.is_some(), s.p99_us, s.p50_us, row.stats.calls)
        };
        key(b)
            .cmp(&key(a))
            .then_with(|| (&a.service, &a.method).cmp(&(&b.service, &b.method)))
    });
    out
}

fn fmt_ns(ns: u64) -> String {
    fmt_us(ns / 1000)
}

/// The summary for a person. Times of the handlers are averages per request
/// that had a handler followed; `timed` says how many those were when it is
/// not all of them. The last four split `off_thread` and add up to it.
pub fn render(rows: &[Row], limit: usize) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let shown = &rows[..rows.len().min(limit)];
    let service_width = shown
        .iter()
        .map(|r| r.service.len())
        .max()
        .unwrap_or(0)
        .max(7)
        + 2;
    let method_width = shown
        .iter()
        .map(|r| r.method.text().len())
        .max()
        .unwrap_or(0)
        .max(6)
        + 2;
    let mut out = format!(
        "  {:<service_width$}{:<method_width$}{:>9}{:>8}{:>7}{:>9}{:>9}{:>9}  {:>8}{:>8}{:>8}{:>12}{:>8}{:>8}{:>11}  {:>8}{:>8}{:>8}{:>9}\n",
        "service",
        "method",
        "calls",
        "errors",
        "reset",
        "p50",
        "p99",
        "max",
        "on_cpu",
        "runq",
        "disk",
        "fileservice",
        "memory",
        "other",
        "off_thread",
        "before",
        "after",
        "parked",
        "not_seen"
    );
    for row in shown {
        let s = &row.stats;
        let latency = summary(&s.hist);
        let mean = |sum: u64| match s.timed {
            0 => "-".to_string(),
            timed => fmt_ns(sum / timed),
        };
        out += &format!(
            "  {:<service_width$}{:<method_width$}{:>9}{:>8}{:>7}{:>9}{:>9}{:>9}  {:>8}{:>8}{:>8}{:>12}{:>8}{:>8}{:>11}  {:>8}{:>8}{:>8}{:>9}",
            row.service,
            row.method.text(),
            s.calls,
            s.errors,
            s.reset_client + s.reset_server,
            fmt_us(latency.p50_us),
            fmt_opt(latency.p99_us, fmt_us),
            fmt_ns(s.max_ns),
            mean(s.cpu_ns),
            mean(s.runq_ns),
            mean(s.disk_ns),
            mean(s.file_service_ns),
            mean(s.memory_ns),
            mean(s.blocked_other_ns),
            mean(s.off_thread_ns),
            mean(s.before_handler_ns),
            mean(s.after_handler_ns),
            mean(s.parked_ns.iter().sum()),
            mean(s.not_seen_ns),
        );
        if s.timed != 0 && s.timed != s.calls {
            out += &format!("  ({} timed)", s.timed);
        }
        out.push('\n');
    }
    if rows.len() > limit {
        out += &format!("  ({} more)\n", rows.len() - limit);
    }
    out
}

/// Text from the wire or a label, safe as one field of a raw line.
fn field(text: &str) -> String {
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

/// The summary for a script: one line per row, counts and sums (ns), with
/// -1 for a percentile that has too few samples.
pub fn render_raw(rows: &[Row]) -> String {
    let mut out = String::new();
    for row in rows {
        let s = &row.stats;
        let latency = summary(&s.hist);
        out += &format!(
            "method calls={} ok={} errors={} status_unknown={} reset_client={} reset_server={} \
             p50_ns={} p99_ns={} max_ns={} timed={} cpu_ns={} runq_ns={} disk_ns={} file_service_ns={} memory_ns={} \
             blocked_other_ns={} off_thread_ns={} before_handler_ns={} after_handler_ns={} parked_ns={} \
             not_seen_ns={} service={} path={}\n",
            s.calls,
            s.ok,
            s.errors,
            s.status_unknown,
            s.reset_client,
            s.reset_server,
            latency.p50_us * 1000,
            latency.p99_us.map_or(-1, |us| (us * 1000) as i64),
            s.max_ns,
            s.timed,
            s.cpu_ns,
            s.runq_ns,
            s.disk_ns,
            s.file_service_ns,
            s.memory_ns,
            s.blocked_other_ns,
            s.off_thread_ns,
            s.before_handler_ns,
            s.after_handler_ns,
            s.parked_ns.iter().sum::<u64>(),
            s.not_seen_ns,
            field(&row.service),
            match &row.method {
                Method::Path(path) => field(path),
                Method::Other => "*".to_string(),
                Method::Unknown => "-".to_string(),
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use blame_common::REQ_F_HTTP2;

    fn call(cgroup: u64, latency_ms: u64, flags: u8, cpu_ms: u64) -> RequestEvent {
        // SAFETY: plain integers and bytes; all zeroes is a valid value.
        let mut e: RequestEvent = unsafe { std::mem::zeroed() };
        e.hdr.cgroup_id = cgroup;
        e.hdr.ts_boot_ns = 1_000_000_000;
        e.end_boot_ns = e.hdr.ts_boot_ns + latency_ms * 1_000_000;
        e.flags = REQ_F_HTTP2 | flags;
        e.cpu_ns = cpu_ms * 1_000_000;
        e.observed_ns = e.cpu_ns;
        e
    }

    fn meta(path: &str, status: Option<u32>) -> Meta {
        Meta {
            path: Some(path.into()),
            trace: None,
            grpc_status: status,
        }
    }

    fn http1(line: &str, status: u16) -> RequestEvent {
        let mut e = call(9, 10, 0, 1);
        e.flags = 0;
        e.status = status;
        e.line[..line.len()].copy_from_slice(line.as_bytes());
        e.line_len = line.len() as u8;
        e
    }

    #[test]
    fn an_http1_route_puts_ids_together_and_nothing_else() {
        let r = |line: &str| route(&http1(line, 200));
        assert_eq!(r("GET /order/16844"), "GET /order/{id}");
        assert_eq!(
            r("GET /u/123e4567-e89b-12d3-a456-426614174000/x/0a1b2c3d4e5f6a7b"),
            "GET /u/{id}/x/{id}"
        );
        // Not an id by these rules: kept.
        assert_eq!(
            r("GET /users/alice/v2/abc123"),
            "GET /users/alice/v2/abc123"
        );
        assert_eq!(r("POST /"), "POST /");
        let mut cut = http1("GET /order/1", 200);
        cut.flags |= REQ_F_LINE_TRUNCATED;
        assert_eq!(route(&cut), "GET /order/{id}...");
    }

    #[test]
    fn http1_requests_are_summed_by_route_with_their_status() {
        let mut methods = Methods::default();
        methods.add(&http1("GET /order/1", 200), None);
        methods.add(&http1("GET /order/2", 404), None);
        methods.add(&http1("GET /order/3", 503), None);
        methods.add(&http1("POST /order", 0), None);
        let total = methods.total();
        let get = &total[&(9, Method::Path("GET /order/{id}".into()))];
        assert_eq!(
            (get.calls, get.ok, get.errors, get.status_unknown),
            (3, 1, 2, 0)
        );
        assert_eq!(get.no_trace, 3);
        let post = &total[&(9, Method::Path("POST /order".into()))];
        assert_eq!((post.calls, post.status_unknown), (1, 1));
    }

    #[test]
    fn requests_are_summed_by_service_and_method_with_how_they_ended() {
        let mut methods = Methods::default();
        methods.add(&call(7, 10, 0, 2), Some(&meta("/s.S/A", Some(0))));
        methods.add(&call(7, 30, 0, 4), Some(&meta("/s.S/A", Some(5))));
        methods.add(
            &call(7, 20, REQ_F_RESET_CLIENT, 0),
            Some(&meta("/s.S/A", None)),
        );
        methods.add(&call(7, 5, 0, 1), Some(&meta("/s.S/B", None)));
        methods.add(&call(7, 5, 0, 0), None);
        // Another cgroup with the same label: the same service.
        methods.add(
            &call(8, 50, REQ_F_RESET_SERVER, 0),
            Some(&meta("/s.S/A", None)),
        );

        let rows = rows(methods.total(), |_| "shop.service".to_string());
        assert_eq!(rows.len(), 3);
        let a = rows
            .iter()
            .find(|row| row.method == Method::Path("/s.S/A".into()))
            .unwrap();
        let s = &a.stats;
        assert_eq!((s.calls, s.ok, s.errors, s.status_unknown), (4, 1, 1, 0));
        assert_eq!((s.reset_client, s.reset_server), (1, 1));
        assert_eq!(s.max_ns, 50_000_000);
        // Two of the four had a handler followed: 2 ms and 4 ms on a CPU,
        // the rest of their 10 and 30 ms off any thread.
        assert_eq!(
            (s.timed, s.cpu_ns, s.off_thread_ns),
            (2, 6_000_000, 34_000_000)
        );
        let unknown = rows
            .iter()
            .find(|row| row.method == Method::Unknown)
            .unwrap();
        assert_eq!((unknown.stats.calls, unknown.stats.status_unknown), (1, 1));

        let text = render(&rows, 20);
        let line = text.lines().find(|line| line.contains("/s.S/A")).unwrap();
        assert!(line.contains("shop.service"));
        // calls, errors, resets; then the handlers' averages.
        let cells: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(&cells[2..5], ["4", "1", "2"]);
        assert_eq!(cells[7], "50.0ms");
        assert_eq!(cells[8], "3.0ms");
        assert_eq!(cells[14], "17.0ms");
        assert!(line.ends_with("(2 timed)"));
        assert!(text.contains("(path not known)"));

        let raw = render_raw(&rows);
        assert!(raw.contains(
            "method calls=4 ok=1 errors=1 status_unknown=0 reset_client=1 reset_server=1 "
        ));
        assert!(raw.contains(" timed=2 cpu_ns=6000000 "));
        assert!(raw.contains(" service=shop.service path=/s.S/A\n"));
        assert!(raw.contains(" path=-\n"));
    }

    #[test]
    fn the_parts_of_a_method_add_up_to_the_time_of_its_requests() {
        let mut methods = Methods::default();
        let mut total_ns = 0;
        // Off the thread: before and after the handler, parked by why, and
        // the rest; with and without each, as runtimes report them.
        for i in 0..6u64 {
            let mut e = call(7, 40 + i, 0, 3);
            e.runq_ns = 1_000_000;
            e.blocked_io_ns = 2_000_000;
            e.blocked_down_ns = 500_000;
            if i % 2 == 0 {
                e.flags |= REQ_F_HANDLER_TIMED;
                e.before_handler_ns = 4_000_000 + i;
                e.after_handler_ns = 1_000_000;
            }
            if i % 3 == 0 {
                e.parked_ns[1] = 7_000_000;
                e.parked_task_ns = 2_000_000;
            }
            total_ns += e.latency_ns();
            methods.add(&e, Some(&meta("/s.S/A", Some(0))));
        }
        // Not timed: no part of it is counted.
        let mut untimed = call(7, 90, 0, 0);
        untimed.observed_ns = 0;
        methods.add(&untimed, Some(&meta("/s.S/A", Some(0))));

        let s = &methods.total()[&(7, Method::Path("/s.S/A".into()))];
        let parked: u64 = s.parked_ns.iter().sum();
        assert_eq!(
            s.before_handler_ns + s.after_handler_ns + parked + s.not_seen_ns,
            s.off_thread_ns
        );
        assert_eq!(
            s.cpu_ns
                + s.runq_ns
                + s.disk_ns
                + s.memory_ns
                + s.file_service_ns
                + s.blocked_other_ns
                + s.off_thread_ns,
            total_ns
        );
        assert_eq!(
            (s.before_handler_ns, s.after_handler_ns, parked),
            (12_000_006, 3_000_000, 18_000_000)
        );
        // In every rendering.
        let rows = rows(methods.total(), |_| "s".to_string());
        let raw = render_raw(&rows);
        assert!(raw.contains(&format!(
            " off_thread_ns={} before_handler_ns=12000006 after_handler_ns=3000000 parked_ns=18000000 not_seen_ns={} ",
            s.off_thread_ns, s.not_seen_ns
        )));
        let text = render(&rows, 20);
        assert!(
            text.lines()
                .next()
                .unwrap()
                .ends_with(" off_thread    before   after  parked not_seen")
        );
    }

    #[test]
    fn a_window_starts_over_and_the_total_does_not() {
        let mut methods = Methods::default();
        methods.add(&call(7, 10, 0, 1), Some(&meta("/s.S/A", Some(0))));
        assert_eq!(
            methods.take_window().values().map(|s| s.calls).sum::<u64>(),
            1
        );
        methods.add(&call(7, 10, 0, 1), Some(&meta("/s.S/A", Some(0))));
        assert_eq!(
            methods.take_window().values().map(|s| s.calls).sum::<u64>(),
            1
        );
        assert!(methods.take_window().is_empty());
        assert_eq!(methods.total().values().map(|s| s.calls).sum::<u64>(), 2);
    }

    #[test]
    fn paths_beyond_the_limit_share_a_row() {
        let mut methods = Methods::default();
        for i in 0..PATHS_PER_SERVICE + 40 {
            methods.add(&call(7, 1, 0, 0), Some(&meta(&format!("/users/{i}"), None)));
        }
        // One that was kept apart is still counted on its own row.
        methods.add(&call(7, 1, 0, 0), Some(&meta("/users/3", None)));
        let rows = rows(methods.total(), |_| "web".to_string());
        assert_eq!(rows.len(), PATHS_PER_SERVICE + 1);
        let other = rows.iter().find(|row| row.method == Method::Other).unwrap();
        assert_eq!(other.stats.calls, 40);
        let third = rows
            .iter()
            .find(|row| row.method == Method::Path("/users/3".into()))
            .unwrap();
        assert_eq!(third.stats.calls, 2);
        assert!(render_raw(&rows).contains(" path=*\n"));
    }
}
