//! Summaries: request latency per service, the kernel side's counters,
//! and what the kernel side cost.

use std::{collections::HashMap, time::Duration};

use anyhow::{Context as _, Result};
use blame_common::{Counter, RUNQ_BUCKETS};
use libbpf_rs::skel::Skel as _;

use crate::{
    bpf::{self, Skel},
    identity::Resolver,
    runq::{Hist, fmt_opt, summary},
    stats::Counters,
    top::fmt_us,
};

use super::attach::PROGRAM_PREFIX;

pub(super) fn read_groups(skel: &Skel) -> Result<HashMap<u64, Hist>> {
    Ok(
        bpf::percpu_hash_u64_arrays::<{ RUNQ_BUCKETS as usize }>(&skel.maps.REQ_GROUP_HIST)
            .context("reading the per-cgroup request latencies")?
            .into_iter()
            .collect(),
    )
}

/// Merge cgroups that share a label (a restarted service is one row).
pub(super) fn aggregate(
    groups: &HashMap<u64, Hist>,
    resolver: &mut Resolver,
) -> Vec<(String, Hist)> {
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

/// Request latency per service, worst p99 first, then by request count.
pub(super) fn render_services(rows: &[(String, Hist)], limit: usize) -> String {
    let mut shown: Vec<_> = rows
        .iter()
        .filter(|(_, hist)| hist.iter().sum::<u64>() > 0)
        .map(|(name, hist)| (name.as_str(), summary(hist)))
        .collect();
    shown.sort_by(|a, b| {
        (b.1.p99_us.is_some(), b.1.p99_us, b.1.samples)
            .cmp(&(a.1.p99_us.is_some(), a.1.p99_us, a.1.samples))
            .then(a.0.cmp(b.0))
    });
    let width = shown.iter().map(|r| r.0.len()).max().unwrap_or(0).max(7) + 2;
    let mut out = format!(
        "  {:<width$}{:>10}{:>9}{:>9}{:>9}{:>9}\n",
        "service", "requests", "p50", "p99", "p99.9", "max"
    );
    for (name, s) in shown.iter().take(limit) {
        out += &format!(
            "  {:<width$}{:>10}{:>9}{:>9}{:>9}{:>9}\n",
            name,
            s.samples,
            fmt_us(s.p50_us),
            fmt_opt(s.p99_us, fmt_us),
            fmt_opt(s.p999_us, fmt_us),
            fmt_us(s.max_us),
        );
    }
    if shown.len() > limit {
        out += &format!("  ({} more)\n", shown.len() - limit);
    }
    out
}

fn render_counter(counters: &Counters, counter: Counter) -> String {
    let value = counters.get(counter);
    let flag = if counter.is_loss() && value > 0 {
        " (!)"
    } else {
        ""
    };
    format!("{}={value}{flag}", counter.name())
}

/// Request accounting: every request that started is finished, aborted or
/// still in flight.
pub(super) fn request_line(counters: &Counters, shown: u64) -> String {
    let started = counters.get(Counter::ReqStarted);
    let finished = counters.get(Counter::ReqFinished);
    let aborted = counters.get(Counter::ReqAborted);
    let reset = counters.get(Counter::ReqReset);
    format!(
        "requests  started={started} finished={finished} {} {} in_flight={} shown={shown}",
        render_counter(counters, Counter::ReqReset),
        render_counter(counters, Counter::ReqAborted),
        started.saturating_sub(finished + reset + aborted),
    )
}

pub(super) fn kernel_line(counters: &Counters) -> String {
    let fields: Vec<String> = [
        Counter::ReqConnInsertFailed,
        Counter::ReqInsertFailed,
        Counter::ReqProcInsertFailed,
        Counter::ReqGroupInsertFailed,
        Counter::ReqCarrierFailed,
        Counter::ReqQueueFull,
        Counter::ReqParseDesync,
        Counter::ReqParseResync,
        Counter::ReqResponseUnmatched,
        Counter::ReqLateTime,
        Counter::ReqIovTruncated,
        Counter::ReqUpgraded,
        Counter::ReqDownMixed,
        Counter::ReqH2Lost,
        Counter::ReqStreamInsertFailed,
        Counter::GrpcHandoffUnmatched,
        Counter::RingbufFull,
    ]
    .into_iter()
    .map(|counter| render_counter(counters, counter))
    .collect();
    let mut line = format!("kernel  {}", fields.join("  "));
    // Only where a runtime is being read.
    if counters.get(Counter::UnitRead) > 0 {
        line += &format!(
            "  {}  {}  {}",
            render_counter(counters, Counter::UnitRead),
            render_counter(counters, Counter::UnitReadInconsistent),
            render_counter(counters, Counter::UnitCpuUnseenNs)
        );
    }
    // Only where spawned units are followed (`--spawned`).
    if counters.get(Counter::SpawnFollowed) > 0 {
        line += &format!(
            "  {}  {}",
            render_counter(counters, Counter::SpawnFollowed),
            render_counter(counters, Counter::HelperLateNs)
        );
    }
    // Only where a process opens OpenMP regions for its requests.
    if counters.get(Counter::OmpRegionUnfollowed) > 0 || counters.get(Counter::OmpTeamIdleCpuNs) > 0
    {
        line += &format!(
            "  {}  {}",
            render_counter(counters, Counter::OmpRegionUnfollowed),
            render_counter(counters, Counter::OmpTeamIdleCpuNs)
        );
    }
    line
}

/// Kernel-side cost of the request programs, from the kernel's own run time
/// statistics: per kind of hook, per finished request, and as a share of all
/// CPU time.
pub(super) fn print_bpf_cost(skel: &Skel, elapsed: Duration, finished: u64) -> Result<()> {
    // (label, calls, ns); the socket calls are counted at their exit programs.
    let mut groups: Vec<(&str, u64, u128)> =
        ["switch", "waking", "readable", "socket_calls", "other"]
            .into_iter()
            .map(|label| (label, 0, 0))
            .collect();
    let mut total_ns = 0u128;
    for program in skel.object().progs_mut() {
        let name = program.name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix(PROGRAM_PREFIX) else {
            continue;
        };
        // Left out because the function it hooks is not in this kernel.
        if !program.autoload() {
            continue;
        }
        let (calls, ns) =
            bpf::run_stats(&program).with_context(|| format!("reading info of {name}"))?;
        let (group, counts_calls) = match rest {
            "switch" => (0, true),
            "waking" => (1, true),
            "readable" => (2, true),
            "readable_done" => (2, false),
            _ if rest.starts_with("exit_") => (3, true),
            _ if rest.starts_with("enter_") => (3, false),
            _ => (4, true),
        };
        if counts_calls {
            groups[group].1 += calls;
        }
        groups[group].2 += u128::from(ns);
        total_ns += u128::from(ns);
    }
    for (label, calls, ns) in &groups {
        println!(
            "  bpf     hook={label} calls={calls} avg_ns={}",
            ns / u128::from((*calls).max(1))
        );
    }
    let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as f64;
    let share_pct = total_ns as f64 / (elapsed.as_secs_f64() * cpus * 1e9) * 100.0;
    println!(
        "  bpf     ns_per_request={} share_pct={share_pct:.3}",
        total_ns / u128::from(finished.max(1))
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_are_listed_worst_p99_first() {
        let hist = |entries: &[(usize, u64)]| {
            let mut h = [0u64; RUNQ_BUCKETS as usize];
            for &(k, count) in entries {
                h[k] = count;
            }
            h
        };
        let rows = vec![
            ("few.service".to_string(), hist(&[(60, 50)])),
            ("quiet.service".to_string(), hist(&[(3, 20_000)])),
            (
                "slow.service".to_string(),
                hist(&[(3, 18_000), (40, 2_000)]),
            ),
            ("empty.service".to_string(), hist(&[])),
        ];
        let out = render_services(&rows, 2);
        let order: Vec<&str> = out
            .lines()
            .skip(1)
            .map(|l| l.split_whitespace().next().unwrap())
            .collect();
        assert_eq!(order, ["slow.service", "quiet.service", "(1"]);
    }
}
