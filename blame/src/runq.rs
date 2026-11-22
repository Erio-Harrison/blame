//! How long runnable threads wait for a CPU: the run-queue programs, their
//! histograms and how they are summed up and shown, for `blame top` and
//! `blame slow`.

use std::{os::fd::OwnedFd, path::Path, time::Duration};

use anyhow::{Context as _, Result};
use blame_common::{Counter, RUNQ_BUCKETS, runq_bucket_range_us};
use libbpf_rs::{Link, MapCore, MapFlags, ProgramMut};

use crate::{
    bpf::{self, Skel},
    cgroupfs::CGROUP_ROOT,
    procfs,
    stats::Counters,
};

/// The run-queue programs.
const PROGRAMS: [&str; 3] = ["runq_wakeup", "runq_wakeup_new", "runq_switch"];

fn programs(skel: &Skel) -> [(&'static str, &ProgramMut<'static>); 3] {
    [
        (PROGRAMS[0], &skel.progs.runq_wakeup),
        (PROGRAMS[1], &skel.progs.runq_wakeup_new),
        (PROGRAMS[2], &skel.progs.runq_switch),
    ]
}

pub type Hist = [u64; RUNQ_BUCKETS as usize];

/// The loaded and attached programs. Dropping this detaches them and ends the
/// kernel-side run time accounting.
pub struct Attached {
    /// Declared first so the programs are detached before the object closes.
    _links: Vec<Link>,
    pub skel: Skel,
    /// Held open to keep the kernel's run time accounting on.
    _stats_fd: OwnedFd,
    /// Threads whose cgroup was recorded before the programs were attached.
    pub seeded: usize,
}

/// Load the run-queue programs and attach them. `thread_entries` sizes the
/// per-thread tables (default: `pid_max`); `group_entries` sizes the
/// per-cgroup table (default: the object's own). With `seed`, the cgroup of
/// every running thread is recorded first, so threads asleep now are attributed
/// on their first wake-up, and every new cgroup is reported on the `EVENTS`
/// ring with its path.
pub fn attach(
    thread_entries: Option<u32>,
    group_entries: Option<u32>,
    seed: bool,
) -> Result<Attached> {
    let mut open = bpf::open()?;
    let mut wanted = PROGRAMS.to_vec();
    if seed {
        wanted.push("cgroup_mkdir");
    }
    bpf::autoload_only(&mut open, &wanted);
    let thread_entries = match thread_entries {
        Some(entries) => entries,
        None => read_pid_max()?,
    };
    open.maps.RUNQ_START.set_max_entries(thread_entries)?;
    open.maps.RUNQ_CGROUP.set_max_entries(thread_entries)?;
    if let Some(entries) = group_entries {
        open.maps.RUNQ_GROUP_HIST.set_max_entries(entries)?;
    }
    let skel = bpf::load(open)?;
    let stats_fd = bpf::enable_run_time_stats()?;

    // Seed before attaching so that threads already running are attributed
    // from the first event, and once more after: a thread created in between
    // has no creation event and was not in the first pass.
    let seeded = if seed { seed_threads(&skel)? } else { 0 };
    let mut links = Vec::new();
    for (name, program) in programs(&skel) {
        links.push(
            program
                .attach()
                .with_context(|| format!("attaching {name}"))?,
        );
    }
    if seed {
        // Before the caller's first cgroupfs scan, so that no cgroup created
        // after it goes unseen.
        links.push(
            skel.progs
                .cgroup_mkdir
                .attach()
                .context("attaching cgroup_mkdir")?,
        );
        let late = seed_threads(&skel)?;
        log::debug!("seeded {late} threads after attaching");
    }
    Ok(Attached {
        _links: links,
        skel,
        _stats_fd: stats_fd,
        seeded,
    })
}

/// Whether the agent is in the kernel's initial PID namespace; yes if that
/// cannot be told, as before it was asked.
fn in_initial_pid_ns() -> bool {
    procfs::pid_ns(Path::new("/proc")).is_none_or(|ns| ns.is_initial())
}

/// Record the cgroup of every thread that exists now. Idempotent: it only
/// writes the thread -> cgroup table, never a count.
///
/// The table is indexed by tid as the kernel's initial PID namespace numbers
/// threads (the scheduler hooks read it off the task). Outside that
/// namespace procfs numbers them otherwise, and nothing here can tell the
/// initial numbers: nothing is seeded, and the kernel side reads the cgroup
/// of a thread it has none for off the thread itself (`runq_switch`).
fn seed_threads(skel: &Skel) -> Result<usize> {
    if !in_initial_pid_ns() {
        return Ok(0);
    }
    let table = &skel.maps.RUNQ_CGROUP;
    let mut seeded = 0;
    for (tid, id) in procfs::thread_cgroups(Path::new(CGROUP_ROOT), Path::new("/proc")) {
        // A tid beyond the table is counted by the kernel side when it runs.
        if table
            .update(&tid.to_ne_bytes(), &id.to_ne_bytes(), MapFlags::ANY)
            .is_ok()
        {
            seeded += 1;
        }
    }
    Ok(seeded)
}

/// The distribution of waits, bucket by bucket (`bucket lo_us=.. hi_us=..
/// count=..`, the last bucket's upper bound `inf`), then its summary.
pub fn render_histogram(hist: &Hist) -> String {
    let mut out = String::new();
    for (k, &count) in hist.iter().enumerate() {
        if count > 0 {
            let (lo, hi) = runq_bucket_range_us(k as u32);
            let hi = hi.map_or_else(|| "inf".to_string(), |v| v.to_string());
            out += &format!("  bucket lo_us={lo} hi_us={hi} count={count}\n");
        }
    }
    out += &format!("  {}\n", summary(hist).render());
    out
}

/// Thread ids are below `pid_max`, so the table needs that many entries.
fn read_pid_max() -> Result<u32> {
    let text = std::fs::read_to_string("/proc/sys/kernel/pid_max").context("reading pid_max")?;
    parse_pid_max(&text)
}

fn parse_pid_max(text: &str) -> Result<u32> {
    let value: u32 = text.trim().parse().context("pid_max is not a number")?;
    anyhow::ensure!(value > 0, "pid_max is 0");
    Ok(value)
}

pub fn read_hist(skel: &Skel) -> Result<Hist> {
    let mut hist = [0u64; RUNQ_BUCKETS as usize];
    for (k, slot) in hist.iter_mut().enumerate() {
        *slot = bpf::percpu_u64_sum(&skel.maps.RUNQ_HIST, k as u32)
            .with_context(|| format!("reading histogram bucket {k}"))?;
    }
    Ok(hist)
}

pub fn kernel_line(counters: &Counters) -> String {
    let render = |counter: Counter| {
        let value = counters.get(counter);
        let flag = if counter.is_loss() && value > 0 {
            " (!)"
        } else {
            ""
        };
        format!("{}={value}{flag}", counter.name())
    };
    format!(
        "kernel  {}  {}  {}  {}  {}  {}",
        render(Counter::RunqStartInsertFailed),
        render(Counter::RunqNegativeDelta),
        render(Counter::RunqGroupInsertFailed),
        render(Counter::FieldReadFailed),
        render(Counter::RingbufFull),
        render(Counter::CgroupPathTruncated),
    )
}

/// Kernel-side cost of the programs, from the kernel's own BPF run time
/// statistics. The agent's CPU cannot show this: the probes run in whichever
/// thread is being switched.
pub fn print_bpf_cost(skel: &Skel, elapsed: Duration) -> Result<()> {
    let mut total_ns = 0u128;
    let mut switch_calls = 0u64;
    let mut lines = Vec::new();
    for (name, program) in programs(skel) {
        let (calls, ns) =
            bpf::run_stats(program).with_context(|| format!("reading info of {name}"))?;
        let ns = u128::from(ns);
        total_ns += ns;
        if name == "runq_switch" {
            switch_calls = calls;
        }
        lines.push(format!(
            "  bpf     prog={name} calls={calls} avg_ns={}",
            ns / u128::from(calls.max(1))
        ));
    }
    for line in lines {
        println!("{line}");
    }
    // Per switch, with the wakeup programs' time charged to the switches: that
    // is the budgeted figure.
    let ns_per_switch = total_ns / u128::from(switch_calls.max(1));
    let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as f64;
    let share_pct = total_ns as f64 / (elapsed.as_secs_f64() * cpus * 1e9) * 100.0;
    println!(
        "  bpf     switch_calls={switch_calls} ns_per_switch={ns_per_switch} share_pct={share_pct:.3}"
    );
    Ok(())
}

pub fn delta(current: &Hist, previous: &Hist) -> Hist {
    let mut out = [0u64; RUNQ_BUCKETS as usize];
    for k in 0..out.len() {
        out[k] = current[k].saturating_sub(previous[k]);
    }
    out
}

/// A percentile is reported only when at least this many samples lie beyond
/// it; with fewer, its value moves too much from one window to the next to be
/// read as a number (checked against a known-answer workload: p99.9 from
/// 10,000 samples spread over +-30-60%, from 100,000 over +-3-10%).
const TAIL_SAMPLES_MIN: u64 = 100;

/// Percentiles read off a bucketed histogram, interpolated linearly within
/// the bucket they fall in (buckets are a quarter of a power of two wide).
/// `max_us` is the upper bound of the highest non-empty bucket. A value in the
/// overflow bucket has no upper bound and is reported as that bucket's lower
/// bound.
#[derive(Debug, PartialEq, Eq)]
pub struct Summary {
    pub samples: u64,
    pub p50_us: u64,
    /// `None` until enough samples lie beyond it; see [`TAIL_SAMPLES_MIN`].
    pub p99_us: Option<u64>,
    pub p999_us: Option<u64>,
    pub max_us: u64,
    pub in_overflow: bool,
}

/// A percentile for display: `-` when there are too few samples for it.
pub fn fmt_opt(value: Option<u64>, fmt: impl Fn(u64) -> String) -> String {
    value.map_or_else(|| "-".to_string(), fmt)
}

impl Summary {
    pub fn render(&self) -> String {
        let mut notes = String::new();
        if self.p999_us.is_none() && self.samples > 0 {
            notes += &format!(
                "  (p99.9 needs {} samples, p99 {})",
                min_samples(1000),
                min_samples(100)
            );
        }
        if self.in_overflow {
            notes += "  (overflow bucket: values are lower bounds)";
        }
        format!(
            "runq    samples={} p50_us={} p99_us={} p999_us={} max_us={}{notes}",
            self.samples,
            self.p50_us,
            fmt_opt(self.p99_us, |v| v.to_string()),
            fmt_opt(self.p999_us, |v| v.to_string()),
            self.max_us
        )
    }
}

/// Samples needed before the percentile that leaves 1/`per` of them above it
/// is reported.
const fn min_samples(per: u64) -> u64 {
    TAIL_SAMPLES_MIN * per
}

/// The value below which `fraction` of the samples lie.
fn percentile(hist: &Hist, samples: u64, fraction: f64) -> u64 {
    let rank = fraction * samples as f64;
    let mut below = 0u64;
    for (k, &count) in hist.iter().enumerate() {
        if count == 0 {
            continue;
        }
        if (below + count) as f64 >= rank {
            let (lo, hi) = runq_bucket_range_us(k as u32);
            let Some(hi) = hi else { return lo };
            let into = ((rank - below as f64) / count as f64).clamp(0.0, 1.0);
            return (lo as f64 + (hi - lo) as f64 * into).round() as u64;
        }
        below += count;
    }
    0
}

pub fn summary(hist: &Hist) -> Summary {
    let samples: u64 = hist.iter().sum();
    if samples == 0 {
        return Summary {
            samples,
            p50_us: 0,
            p99_us: None,
            p999_us: None,
            max_us: 0,
            in_overflow: false,
        };
    }
    let tail = |per: u64| {
        (samples >= min_samples(per)).then(|| percentile(hist, samples, 1.0 - 1.0 / per as f64))
    };
    let max_bucket = hist.iter().rposition(|&count| count > 0).unwrap_or(0);
    let (lo, hi) = runq_bucket_range_us(max_bucket as u32);
    Summary {
        samples,
        p50_us: percentile(hist, samples, 0.5),
        p99_us: tail(100),
        p999_us: tail(1000),
        max_us: hi.unwrap_or(lo),
        in_overflow: hi.is_none(),
    }
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
    fn empty_histogram_reports_zero_samples() {
        let s = summary(&hist(&[]));
        assert_eq!(
            (s.samples, s.p50_us, s.p99_us, s.p999_us, s.max_us),
            (0, 0, None, None, 0)
        );
    }

    #[test]
    fn percentiles_interpolate_within_the_bucket() {
        // Bucket 36 is [1024, 1280) us; the median falls halfway into it.
        let s = summary(&hist(&[(36, 200)]));
        assert_eq!(s.p50_us, 1152);
        assert_eq!(s.max_us, 1280);
        assert!(!s.in_overflow);
    }

    #[test]
    fn tail_percentiles_need_a_hundred_samples_beyond_them() {
        let few = summary(&hist(&[(8, 9_999)]));
        assert_eq!((few.p99_us, few.p999_us), (None, None));
        let s = summary(&hist(&[(8, 9_900), (36, 100)]));
        assert_eq!(s.samples, 10_000);
        assert_eq!(s.p99_us, Some(10)); // the top of bucket 8, [8, 10) us
        assert_eq!(s.p999_us, None);
        assert!(s.render().contains("p999_us=-"));
        // Rank 99,900 is the last sample of bucket 20, [64, 80) us.
        let s = summary(&hist(&[(8, 99_000), (20, 900), (36, 100)]));
        assert_eq!(s.p999_us, Some(80));
    }

    #[test]
    fn overflow_bucket_is_reported_as_a_lower_bound_and_flagged() {
        let last = RUNQ_BUCKETS as usize - 1;
        let s = summary(&hist(&[(3, 1), (last, 1)]));
        assert_eq!(s.max_us, 1 << 25);
        assert!(s.in_overflow);
        assert!(s.render().contains("lower bounds"));
    }

    #[test]
    fn pid_max_parsing() {
        assert_eq!(parse_pid_max("4194304\n").unwrap(), 4_194_304);
        assert!(parse_pid_max("0").is_err());
        assert!(parse_pid_max("abc").is_err());
    }

    #[test]
    fn window_delta_never_underflows() {
        let d = delta(&hist(&[(2, 5)]), &hist(&[(2, 7)]));
        assert_eq!(d[2], 0);
    }
}
