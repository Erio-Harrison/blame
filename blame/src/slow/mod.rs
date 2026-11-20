//! `blame slow`: requests that took longer than a threshold, and where the
//! time of the threads serving them went.

mod attach;
mod inbox;
pub(crate) mod proc_cpu;
mod render;
mod summary;

use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use blame_common::{Counter, REQ_F_HTTP2, RUNQ_BUCKETS, RequestEvent};
use clap::Args;
use tokio::signal::unix::{SignalKind, signal};

use crate::{
    bpf::{Events, Skel},
    consume::boot_to_wall_offset_ns,
    h2meta::Meta,
    identity::{Resolver, UNATTRIBUTED},
    json,
    methods::{self},
    runq::{Hist, delta},
    stats::{Counters, UsageTracker, human_bytes},
};

use attach::{attach, follow_openmp_functions, inspect_new_processes, raise_open_files_limit};
use inbox::{Inbox, Slowest, place_stream_ids, receive};
use render::{fmt_ns, render_raw, render_request};
use summary::{aggregate, kernel_line, print_bpf_cost, read_groups, render_services, request_line};

#[derive(Debug, Args)]
pub struct SlowOpt {
    /// Show requests that took at least this many milliseconds.
    #[clap(long, default_value_t = 100.0, value_name = "MS")]
    above: f64,

    /// Trace only this process; may be given more than once. Default: every
    /// process that listens for or accepts TCP connections.
    #[clap(long = "pid", value_name = "PID")]
    pids: Vec<u32>,

    /// Stop after this many seconds. Default: run until interrupted.
    #[clap(long, value_name = "SECS")]
    duration: Option<u64>,

    /// Seconds between per-service summaries. 0 prints one only on exit.
    #[clap(long, default_value_t = 10, value_name = "SECS")]
    interval: u64,

    /// Services to show per summary; the rest are left out.
    #[clap(long, default_value_t = 20, value_name = "N")]
    rows: usize,

    /// One `key=value` line per request, with raw timestamps, for scripts.
    #[clap(long)]
    raw: bool,

    /// Everything as JSON, one object per line: slow requests, summaries by
    /// service and by method, what was found out about each process, and
    /// what was lost. `--json-fields` says what the fields mean.
    #[clap(long, conflicts_with = "raw")]
    json: bool,

    /// Print what every field of the `--json` records means, and exit.
    #[clap(long)]
    json_fields: bool,

    /// List only the N slowest of the slow requests, at the end of the run,
    /// instead of each one as it ends; the others are only counted (they
    /// are still in the summaries). 0: every one, as it ends. Default: 0,
    /// or 50 with `--json`, whose reader may not have room for more.
    #[clap(long, value_name = "N")]
    list: Option<u64>,

    /// Connections that can be followed at once. Shrink it to exercise the
    /// loss accounting.
    #[clap(long, value_name = "N")]
    max_connections: Option<u32>,

    /// Requests that can be in flight at once.
    #[clap(long, value_name = "N")]
    max_requests: Option<u32>,

    /// Attribute by thread in every process, also where a Go or tokio
    /// runtime was recognised.
    #[clap(long)]
    threads_only: bool,

    /// Follow the runtime more closely, for the time of an investigation:
    /// the goroutines and tokio tasks a request spawns (their time is shown
    /// as the request's helpers'), and, for Go, why the request's goroutine
    /// was on no thread (parked on a channel, a lock, a timer, the network,
    /// the garbage collector, or waiting to be run). Go needs probes on
    /// goroutine creation, parking and scheduling for it, which cost some
    /// 10-13% of throughput on light requests (the default mode some 6-8%).
    /// In a process attributed by thread that computes in parallel with
    /// GNU's OpenMP runtime (libgomp, as PyTorch's wheels do): the threads
    /// of a team that take up a request's work, shown the same way.
    #[clap(long, alias = "spawned", conflicts_with = "threads_only")]
    deep: bool,
}

/// How often processes the kernel side found by itself are looked at. Until
/// then such a process is attributed by thread.
const INSPECT_EVERY: Duration = Duration::from_secs(1);

/// How often the ring buffer is emptied. The kernel side wakes the agent only
/// when the buffer is filling up, so this bounds how late a slow request is
/// shown.
const DRAIN_EVERY: Duration = Duration::from_millis(200);

pub async fn run(opt: SlowOpt) -> Result<()> {
    if opt.json_fields {
        println!("{:#}", json::fields());
        return Ok(());
    }
    raise_open_files_limit();
    let attached = attach(&opt)?;
    let skel = &attached.skel;
    let inbox: Rc<RefCell<Inbox>> = Rc::default();
    let sink = Rc::clone(&inbox);
    let events = Events::new(&skel.maps.EVENTS, move |record| {
        receive(&mut sink.borrow_mut(), record);
    })?;
    let mut resolver = Resolver::new();
    resolver.refresh();
    let wall_offset = boot_to_wall_offset_ns()?;

    let started = Instant::now();
    let mut usage = UsageTracker::new()?;
    let slow_ns = (opt.above.max(0.0) * 1e6) as u64;
    if opt.json {
        println!(
            "{}",
            json::start(
                slow_ns,
                opt.interval,
                list_max(&opt),
                attached.traced_at_start
            )
        );
    } else {
        println!(
            "blame: slow attached (requests >= {}, {} traced at start, tables {})",
            fmt_ns(slow_ns),
            if opt.pids.is_empty() {
                format!("{} listening processes", attached.traced_at_start)
            } else {
                format!("{} listed processes", attached.traced_at_start)
            },
            human_bytes(attached.table_bytes),
        );
    }
    for note in &attached.notes {
        note.print(&opt);
    }

    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    // Created once: a fresh listener per loop pass misses a Ctrl-C that
    // arrives while a branch body runs.
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let timer = tokio::time::sleep(
        opt.duration
            .map_or(Duration::from_secs(10 * 365 * 86_400), Duration::from_secs),
    );
    tokio::pin!(timer);
    let mut ticker = tokio::time::interval(Duration::from_secs(opt.interval.max(1)));
    ticker.tick().await; // completes immediately
    let mut drain = tokio::time::interval(DRAIN_EVERY);
    let mut look = tokio::time::interval(INSPECT_EVERY);

    let mut previous: HashMap<u64, Hist> = HashMap::new();
    let mut previous_cpu = std::collections::BTreeMap::new();
    let mut window_started = Instant::now();
    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = &mut timer => break,
            _ = look.tick() => inspect_new_processes(&attached, &opt),
            _ = drain.tick() => {
                follow_openmp_functions(&attached);
                events.drain()?;
                print_requests(&inbox, &mut resolver, &opt, wall_offset, skel);
            }
            // The kernel side asks for this when the buffer is filling up.
            consumed = events.wait() => {
                consumed.context("ring buffer consumer failed")?;
                print_requests(&inbox, &mut resolver, &opt, wall_offset, skel);
            }
            _ = ticker.tick(), if opt.interval > 0 => {
                let current = read_groups(skel)?;
                let window = current
                    .iter()
                    .map(|(id, hist)| {
                        let zero = [0u64; RUNQ_BUCKETS as usize];
                        (*id, delta(hist, previous.get(id).unwrap_or(&zero)))
                    })
                    .collect();
                previous = current;
                let services = aggregate(&window, &mut resolver);
                let by_method = inbox.borrow_mut().methods.take_window();
                let counters = Counters::read(skel)?;
                let cpu_now = proc_cpu::read(skel)?;
                let cpu = proc_cpu::window(&cpu_now, &previous_cpu);
                previous_cpu = cpu_now;
                let over_ns = elapsed_ns(window_started);
                window_started = Instant::now();
                if opt.json {
                    let (slow, listed) = (inbox.borrow().slow, inbox.borrow().listed);
                    print_json_summaries(
                        Some(opt.interval),
                        &services,
                        &by_method,
                        &mut resolver,
                        (&cpu, over_ns),
                        json::health(Some(opt.interval), &counters, slow, listed, None),
                    );
                } else {
                    println!("--- slow (window {}s) ---", opt.interval);
                    print!("{}", render_services(&services, opt.rows));
                    print!("{}", render_methods(&by_method, &mut resolver, &opt));
                    print!("{}", render_cpu(&cpu, over_ns, &opt));
                    println!("  {}", kernel_line(&counters));
                }
            }
        }
    }

    let elapsed = started.elapsed();
    events.drain()?;
    print_requests(&inbox, &mut resolver, &opt, wall_offset, skel);
    print_slowest(&inbox, &mut resolver, &opt, wall_offset);
    let (slow, shown) = (inbox.borrow().slow, inbox.borrow().listed);
    let counters = Counters::read(skel)?;
    let cpu = proc_cpu::read(skel)?;
    let over_ns = elapsed_ns(started);
    if opt.json {
        let usage = usage.sample()?;
        let inbox = inbox.borrow();
        print_json_summaries(
            None,
            &aggregate(&read_groups(skel)?, &mut resolver),
            inbox.methods.total(),
            &mut resolver,
            (&cpu, over_ns),
            json::health(
                None,
                &counters,
                slow,
                shown,
                Some((usage.cpu_percent, usage.rss_bytes)),
            ),
        );
        return Ok(());
    }
    println!("\n--- slow (final) ---");
    print!(
        "{}",
        render_services(&aggregate(&read_groups(skel)?, &mut resolver), opt.rows)
    );
    print!(
        "{}",
        render_methods(inbox.borrow().methods.total(), &mut resolver, &opt)
    );
    print!("{}", render_cpu(&cpu, over_ns, &opt));
    println!("  {}", request_line(&counters, shown));
    if slow > shown {
        println!("  listed  the {shown} slowest of {slow} slow requests (--list)");
    }
    println!("  {}", kernel_line(&counters));
    if inbox.borrow().rejected > 0 {
        println!("  agent   rejected_records={} (!)", inbox.borrow().rejected);
    }
    print_bpf_cost(skel, elapsed, counters.get(Counter::ReqFinished))?;
    let usage = usage.sample()?;
    println!(
        "  self    cpu={:.2}%  rss={}",
        usage.cpu_percent,
        human_bytes(usage.rss_bytes)
    );
    Ok(())
}

/// What each process's threads waited for a CPU, as a table or as raw lines.
fn render_cpu(
    cpu: &std::collections::BTreeMap<u32, proc_cpu::ProcCpu>,
    over_ns: u64,
    opt: &SlowOpt,
) -> String {
    if opt.raw {
        proc_cpu::render_raw(cpu, over_ns)
    } else {
        proc_cpu::render(cpu, over_ns, opt.rows)
    }
}

fn elapsed_ns(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// How many slow requests are listed at most; `None`: all, as they end.
fn list_max(opt: &SlowOpt) -> Option<u64> {
    match opt.list {
        Some(0) => None,
        Some(max) => Some(max),
        None => opt.json.then_some(50),
    }
}

/// Write one slow request in the format asked for.
fn print_request(
    event: &RequestEvent,
    what: Option<&Meta>,
    resolver: &mut Resolver,
    opt: &SlowOpt,
    wall_offset: i128,
) {
    let label = resolver.label(event.hdr.cgroup_id);
    if opt.json {
        let service = (label != UNATTRIBUTED).then_some(label.as_str());
        println!("{}", json::call(event, what, service, wall_offset));
    } else if opt.raw {
        println!("{}", render_raw(event, what));
    } else {
        print!("{}", render_request(event, what, &label, wall_offset));
    }
}

/// With `--list N`: write the N slowest requests of the run, slowest first.
fn print_slowest(
    inbox: &RefCell<Inbox>,
    resolver: &mut Resolver,
    opt: &SlowOpt,
    wall_offset: i128,
) {
    let mut inbox = inbox.borrow_mut();
    let kept = std::mem::take(&mut inbox.slowest).into_sorted_vec();
    inbox.listed += kept.len() as u64;
    for one in &kept {
        print_request(&one.event, one.what.as_ref(), resolver, opt, wall_offset);
    }
}

/// The summaries of a window, or of the whole run, as records: services,
/// methods, then how complete they are.
fn print_json_summaries(
    window_s: Option<u64>,
    services: &[(String, Hist)],
    by_method: &methods::Sums,
    resolver: &mut Resolver,
    (cpu, over_ns): (&std::collections::BTreeMap<u32, proc_cpu::ProcCpu>, u64),
    health: serde_json::Value,
) {
    let known = |name: &str| (name != UNATTRIBUTED).then(|| name.to_string());
    for (name, hist) in services {
        if hist.iter().sum::<u64>() > 0 {
            println!("{}", json::service(window_s, known(name).as_deref(), hist));
        }
    }
    let rows = methods::rows(by_method, |cgroup| resolver.label(cgroup));
    for row in &rows {
        println!(
            "{}",
            json::method(window_s, known(&row.service).as_deref(), row)
        );
    }
    for (pid, cpu) in cpu {
        if cpu.runq_own_ns + cpu.runq_others_ns > 0 {
            println!("{}", json::process_cpu(window_s, *pid, over_ns, cpu));
        }
    }
    println!("{health}");
}

/// HTTP/2 requests by service and method, as a table or as raw lines.
fn render_methods(sums: &methods::Sums, resolver: &mut Resolver, opt: &SlowOpt) -> String {
    let rows = methods::rows(sums, |cgroup| {
        let label = resolver.label(cgroup);
        if label == UNATTRIBUTED {
            "-".to_string()
        } else {
            label
        }
    });
    if opt.raw {
        methods::render_raw(&rows)
    } else {
        methods::render(&rows, opt.rows)
    }
}

/// Take in the requests that arrived since the last call: sum them up, and
/// list the slow ones (or keep the slowest for the end).
fn print_requests(
    inbox: &RefCell<Inbox>,
    resolver: &mut Resolver,
    opt: &SlowOpt,
    wall_offset: i128,
    skel: &Skel,
) {
    let mut inbox = inbox.borrow_mut();
    place_stream_ids(&mut inbox, skel, opt.json);
    let Inbox {
        cgroups,
        requests,
        meta,
        methods,
        slow,
        listed,
        slowest,
        ..
    } = &mut *inbox;
    let list_max = list_max(opt);
    for event in cgroups.drain(..) {
        resolver.learn(&event);
    }
    let slow_ns = (opt.above.max(0.0) * 1e6) as u64;
    for event in requests.drain(..) {
        let http2 = event.flags & REQ_F_HTTP2 != 0;
        let what = http2
            .then(|| {
                meta.take_at(
                    event.conn,
                    event.stream_id,
                    event.hdr.ts_boot_ns,
                    event.end_boot_ns,
                )
            })
            .flatten();
        // The kernel side reports every request, to be summed up here;
        // only the slow ones are listed.
        methods.add(&event, what.as_ref());
        if event.latency_ns() < slow_ns {
            continue;
        }
        *slow += 1;
        if let Some(max) = list_max {
            slowest.push(Slowest {
                latency_ns: event.latency_ns(),
                order: *slow,
                event,
                what,
            });
            if slowest.len() as u64 > max {
                slowest.pop();
            }
            continue;
        }
        *listed += 1;
        print_request(&event, what.as_ref(), resolver, opt, wall_offset);
    }
}

#[cfg(test)]
mod test_event {
    use blame_common::{
        EVENT_VERSION, EventHeader, EventKind, REQ_LINE_LEN, RequestEvent, UNIT_THREAD, UnitKey,
    };

    /// A request event to render and parse in tests.
    pub(crate) fn event(line: &str) -> RequestEvent {
        let unit = UnitKey {
            tgid: 812,
            kind: UNIT_THREAD,
            _pad: [0; 3],
            id: 815,
        };
        let mut bytes = [0u8; REQ_LINE_LEN];
        bytes[..line.len()].copy_from_slice(line.as_bytes());
        RequestEvent {
            hdr: EventHeader {
                version: EVENT_VERSION,
                kind: EventKind::Request as u16,
                cpu: 0,
                _pad: 0,
                ts_boot_ns: 1_000_000_000,
                cgroup_id: 7,
                netns_id: 0,
                ifindex: 0,
                pid: 812,
                tid: 815,
            },
            req_id: 42,
            end_boot_ns: 1_500_000_000,
            ready_boot_ns: 999_985_000,
            first_unit: unit,
            last_unit: unit,
            cpu_ns: 3_000_000,
            runq_ns: 1_000_000,
            blocked_down_ns: 380_000_000,
            blocked_client_ns: 0,
            blocked_io_ns: 4_000_000,
            blocked_mem_ns: 2_000_000,
            blocked_other_ns: 10_000_000,
            observed_ns: 300_000_000,
            retro_ns: 100_000_000,
            down_wait_ns: 381_000_000,
            down_service_ns: 380_500_000,
            down_transfer_ns: 300_000,
            down_calls: 2,
            last_tid: 815,
            stream_id: 0,
            _pad2: 0,
            conn: 0,
            helper_cpu_ns: 0,
            helper_runq_ns: 0,
            helper_down_ns: 0,
            helper_client_ns: 0,
            helper_io_ns: 0,
            helper_mem_ns: 0,
            helper_other_ns: 0,
            helpers: 0,
            _pad3: 0,
            blocked_fsvc_ns: 0,
            helper_fsvc_ns: 0,
            parked_ns: [0; 7],
            blocked_fsvc_lock_ns: 0,
            helper_fsvc_lock_ns: 0,
            before_handler_ns: 0,
            after_handler_ns: 0,
            trace: [0; 16],
            parked_task_ns: 0,
            parked_blocking_ns: 0,
            lport: 8080,
            rport: 51234,
            status: 200,
            flags: 0,
            line_len: line.len() as u8,
            line: bytes,
        }
    }
}
