//! `blame top`: run-queue latency per service.

use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use blame_common::{
    CgroupMkdirEvent, EVENT_VERSION, EventHeader, EventKind, RUNQ_BUCKETS, runq_bucket,
};
use clap::Args;
use tokio::signal::unix::{SignalKind, signal};

use crate::{
    bpf::{self, Events, Skel},
    identity::{Resolver, UNATTRIBUTED},
    runq::{self, Hist, delta, fmt_opt, kernel_line, print_bpf_cost, read_hist, summary},
    stats::{Counters, UsageTracker, human_bytes},
};

#[derive(Debug, Args)]
pub struct TopOpt {
    /// Stop after this many seconds. Default: run until interrupted.
    #[clap(long, value_name = "SECS")]
    duration: Option<u64>,

    /// Seconds between per-window reports. 0 reports only on exit.
    #[clap(long, default_value_t = 10, value_name = "SECS")]
    interval: u64,

    /// Rows to show per report; the rest are summed into one line.
    #[clap(long, default_value_t = 20, value_name = "N")]
    rows: usize,

    /// Capacity of the per-cgroup table. Shrink it to exercise the loss
    /// accounting.
    #[clap(long, value_name = "N")]
    group_entries: Option<u32>,
}

/// Waits of at least 1024 us count as slow; a bucket starts there.
const SLOW_FIRST_BUCKET: usize = runq_bucket(1_024_000) as usize;

pub async fn run(opt: TopOpt) -> Result<()> {
    let attached = runq::attach(None, opt.group_entries, true)?;
    let (skel, seeded) = (&attached.skel, attached.seeded);
    // Records are queued by the ring buffer callback and taken in here, where
    // the resolver is.
    let created: Rc<RefCell<Vec<CgroupMkdirEvent>>> = Rc::default();
    let queue = Rc::clone(&created);
    let events = Events::new(&skel.maps.EVENTS, move |record| {
        if let Some(event) = cgroup_created(record) {
            queue.borrow_mut().push(*event);
        }
    })?;
    // cgroups created from here on arrive as events; this scan covers the rest.
    let mut resolver = Resolver::new();
    resolver.refresh();

    let started = Instant::now();
    let mut usage = UsageTracker::new()?;
    println!("blame: top attached ({seeded} running threads seeded)");

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

    let mut previous: HashMap<u64, Hist> = HashMap::new();
    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = &mut timer => break,
            consumed = events.wait() => {
                consumed?;
                learn_all(&created, &mut resolver);
            }
            _ = ticker.tick(), if opt.interval > 0 => {
                let current = read_groups(skel)?.groups;
                let window = delta_groups(&current, &previous);
                previous = current;
                println!("--- top (window {}s) ---", opt.interval);
                print!("{}", render(&aggregate(&window, &mut resolver), opt.rows));
                println!("  {}", kernel_line(&Counters::read(skel)?));
            }
        }
    }

    let elapsed = started.elapsed();
    events.drain()?;
    learn_all(&created, &mut resolver);
    let reading = read_groups(skel)?;
    println!("\n--- top (final) ---");
    print!(
        "{}",
        render(&aggregate(&reading.groups, &mut resolver), opt.rows)
    );
    println!("  {}", reading.conservation());
    println!("  {}", kernel_line(&Counters::read(skel)?));
    print_bpf_cost(skel, elapsed)?;
    println!("  names   learned_from_events={}", resolver.learned);
    let usage = usage.sample()?;
    println!(
        "  self    cpu={:.2}%  rss={}",
        usage.cpu_percent,
        human_bytes(usage.rss_bytes)
    );
    Ok(())
}

struct GroupReading {
    groups: HashMap<u64, Hist>,
    global_before: u64,
    global_after: u64,
}

impl GroupReading {
    fn total(&self) -> u64 {
        self.groups.values().flat_map(|h| h.iter()).sum()
    }

    /// The groups must add up to the global count, which keeps running while
    /// they are read; so the sum has to fall between two global readings.
    fn conservation(&self) -> String {
        let sum = self.total();
        let slack = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as u64;
        let ok = sum + slack >= self.global_before && sum <= self.global_after + slack;
        format!(
            "groups  sum={sum} global=[{}, {}] {}",
            self.global_before,
            self.global_after,
            if ok { "ok" } else { "MISMATCH" }
        )
    }
}

fn read_groups(skel: &Skel) -> Result<GroupReading> {
    let before: u64 = read_hist(skel)?.iter().sum();
    let groups =
        bpf::percpu_hash_u64_arrays::<{ RUNQ_BUCKETS as usize }>(&skel.maps.RUNQ_GROUP_HIST)
            .context("reading the per-cgroup table")?
            .into_iter()
            .collect();
    let after: u64 = read_hist(skel)?.iter().sum();
    Ok(GroupReading {
        groups,
        global_before: before,
        global_after: after,
    })
}

fn delta_groups(current: &HashMap<u64, Hist>, previous: &HashMap<u64, Hist>) -> HashMap<u64, Hist> {
    let zero = [0u64; RUNQ_BUCKETS as usize];
    current
        .iter()
        .map(|(id, hist)| (*id, delta(hist, previous.get(id).unwrap_or(&zero))))
        .collect()
}

/// The record as a cgroup creation event, if it is one this build knows.
fn cgroup_created(record: &[u8]) -> Option<&CgroupMkdirEvent> {
    let header = EventHeader::parse(record)?;
    if header.version != EVENT_VERSION || header.kind != EventKind::CgroupMkdir as u16 {
        return None;
    }
    CgroupMkdirEvent::parse(record)
}

fn learn_all(created: &RefCell<Vec<CgroupMkdirEvent>>, resolver: &mut Resolver) {
    for event in created.borrow_mut().drain(..) {
        resolver.learn(&event);
    }
}

/// Merge groups that share a label (a service restarted into a new cgroup is
/// one row).
fn aggregate(groups: &HashMap<u64, Hist>, resolver: &mut Resolver) -> Vec<(String, Hist)> {
    let mut merged: HashMap<String, Hist> = HashMap::new();
    for (id, hist) in groups {
        let entry = merged
            .entry(resolver.label(*id))
            .or_insert([0; RUNQ_BUCKETS as usize]);
        for (slot, value) in entry.iter_mut().zip(hist.iter()) {
            *slot += value;
        }
    }
    merged.into_iter().collect()
}

pub fn fmt_us(us: u64) -> String {
    match us {
        0..1000 => format!("{us}us"),
        1000..1_000_000 => format!("{:.1}ms", us as f64 / 1e3),
        _ => format!("{:.1}s", us as f64 / 1e6),
    }
}

/// One line per label, worst p99 first, then rows with too few samples for a
/// p99; the unattributed row is always last.
fn render(rows: &[(String, Hist)], limit: usize) -> String {
    let mut shown: Vec<_> = rows
        .iter()
        .filter(|(_, h)| h.iter().sum::<u64>() > 0)
        .map(|(name, hist)| (name.as_str(), hist, summary(hist)))
        .collect();
    shown.sort_by(|a, b| {
        let key = |r: &(&str, &Hist, runq::Summary)| {
            (
                r.0 == UNATTRIBUTED,
                r.2.p99_us.is_none(),
                u64::MAX - r.2.p99_us.unwrap_or(0),
            )
        };
        key(a)
            .cmp(&key(b))
            .then(b.2.samples.cmp(&a.2.samples))
            .then(a.0.cmp(b.0))
    });
    let unattributed = shown.iter().position(|r| r.0 == UNATTRIBUTED);
    let width = shown.iter().map(|r| r.0.len()).max().unwrap_or(0).max(7) + 2;
    let mut out = format!(
        "  {:<width$}{:>10}{:>9}{:>9}{:>9}{:>9}{:>12}\n",
        "service", "samples", "p50", "p99", "p99.9", "max", "slow(>=1ms)"
    );
    let line = |name: &str, hist: &Hist, s: &runq::Summary| {
        let slow: u64 = hist[SLOW_FIRST_BUCKET..].iter().sum();
        format!(
            "  {:<width$}{:>10}{:>9}{:>9}{:>9}{:>9}{:>12}\n",
            name,
            s.samples,
            fmt_us(s.p50_us),
            fmt_opt(s.p99_us, fmt_us),
            fmt_opt(s.p999_us, fmt_us),
            fmt_us(s.max_us),
            slow
        )
    };
    let attributed = shown.len() - usize::from(unattributed.is_some());
    for (name, hist, s) in shown.iter().take(limit.min(attributed)) {
        out += &line(name, hist, s);
    }
    if attributed > limit {
        let mut rest = [0u64; RUNQ_BUCKETS as usize];
        for (_, hist, _) in &shown[limit..attributed] {
            for (slot, value) in rest.iter_mut().zip(hist.iter()) {
                *slot += value;
            }
        }
        out += &line(
            &format!("({} more)", attributed - limit),
            &rest,
            &summary(&rest),
        );
    }
    if let Some(i) = unattributed {
        let (name, hist, s) = &shown[i];
        out += &line(name, hist, s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hist(entries: &[(usize, u64)]) -> Hist {
        let mut h = [0u64; RUNQ_BUCKETS as usize];
        for &(k, count) in entries {
            h[k] = count;
        }
        h
    }

    #[test]
    fn times_use_a_readable_unit() {
        assert_eq!(fmt_us(16), "16us");
        assert_eq!(fmt_us(2048), "2.0ms");
        assert_eq!(fmt_us(65_536), "65.5ms");
        assert_eq!(fmt_us(2_000_000), "2.0s");
    }

    #[test]
    fn rows_are_sorted_by_p99_and_unattributed_comes_last() {
        let rows = vec![
            (UNATTRIBUTED.to_string(), hist(&[(50, 20_000)])),
            ("few.service".to_string(), hist(&[(60, 50)])),
            ("quiet.service".to_string(), hist(&[(3, 20_000)])),
            (
                "noisy.service".to_string(),
                hist(&[(3, 18_000), (40, 2_000)]),
            ),
        ];
        let out = render(&rows, 10);
        let order: Vec<&str> = out
            .lines()
            .skip(1)
            .map(|l| l.split_whitespace().next().unwrap())
            .collect();
        assert_eq!(
            order,
            [
                "noisy.service",
                "quiet.service",
                "few.service",
                UNATTRIBUTED
            ]
        );
    }

    #[test]
    fn slow_counts_waits_of_a_millisecond_and_longer() {
        // Bucket 35 ends at 1024 us, where 36 starts.
        let out = render(&[("a".to_string(), hist(&[(35, 7), (36, 2), (40, 1)]))], 10);
        let row = out.lines().nth(1).unwrap();
        assert_eq!(row.split_whitespace().last(), Some("3"));
    }

    #[test]
    fn rows_beyond_the_limit_are_summed() {
        let rows: Vec<_> = (0..5)
            .map(|i| (format!("s{i}.service"), hist(&[(3 + i, 10)])))
            .collect();
        let out = render(&rows, 2);
        assert!(out.contains("(3 more)"));
        assert_eq!(out.lines().count(), 4);
    }

    #[test]
    fn empty_rows_are_not_shown() {
        let out = render(&[("a".to_string(), hist(&[]))], 10);
        assert_eq!(out.lines().count(), 1);
    }

    #[test]
    fn window_is_current_minus_previous() {
        let current = HashMap::from([(1, hist(&[(3, 5)])), (2, hist(&[(4, 2)]))]);
        let previous = HashMap::from([(1, hist(&[(3, 2)]))]);
        let window = delta_groups(&current, &previous);
        assert_eq!(window[&1][3], 3);
        assert_eq!(window[&2][4], 2);
    }

    #[test]
    fn conservation_allows_samples_in_flight() {
        let reading = |sum: u64, before: u64, after: u64| GroupReading {
            groups: HashMap::from([(1, hist(&[(3, sum)]))]),
            global_before: before,
            global_after: after,
        };
        assert!(reading(100, 100, 110).conservation().ends_with("ok"));
        assert!(reading(105, 100, 110).conservation().ends_with("ok"));
        assert!(reading(50, 100, 110).conservation().ends_with("MISMATCH"));
    }
}
