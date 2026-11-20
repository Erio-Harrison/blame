//! What each traced process's threads waited for a CPU
//! (`bpf/request/proc_cpu.h`): per process, not per request.

use std::collections::{BTreeMap, HashSet};

use anyhow::{Context as _, Result};
use libbpf_rs::{MapCore as _, MapFlags};

use crate::{bpf::Skel, top::fmt_us};

/// One process's threads, summed over the CPUs, since the agent started:
/// what they waited for a CPU, by what the CPU they were queued on did
/// meanwhile. The four add up to all they waited.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcCpu {
    /// Another thread of the same process had the CPU.
    pub runq_own_ns: u64,
    /// A CPU limit on its control group kept them off it. `None`: this
    /// kernel does not say, and such a wait is in the two below.
    pub runq_cpu_limit_ns: Option<u64>,
    /// Something else ran on it.
    pub runq_others_ns: u64,
    /// It was idle, outside a limit: being woken up.
    pub runq_cpu_idle_ns: u64,
}

impl ProcCpu {
    /// What was added since `earlier`.
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            runq_own_ns: self.runq_own_ns.saturating_sub(earlier.runq_own_ns),
            runq_cpu_limit_ns: self
                .runq_cpu_limit_ns
                .map(|ns| ns.saturating_sub(earlier.runq_cpu_limit_ns.unwrap_or(0))),
            runq_others_ns: self.runq_others_ns.saturating_sub(earlier.runq_others_ns),
            runq_cpu_idle_ns: self
                .runq_cpu_idle_ns
                .saturating_sub(earlier.runq_cpu_idle_ns),
        }
    }

    /// All of it.
    pub fn total_ns(&self) -> u64 {
        self.runq_own_ns
            + self.runq_cpu_limit_ns.unwrap_or(0)
            + self.runq_others_ns
            + self.runq_cpu_idle_ns
    }
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// Every traced process's figures so far, by pid.
pub(super) fn read(skel: &Skel) -> Result<BTreeMap<u32, ProcCpu>> {
    let traced: HashSet<u32> = skel
        .maps
        .REQ_PROCS
        .keys()
        .filter_map(|key| u32_at(&key, 0))
        .collect();
    // Whether the kernel says how long a group's queue was throttled.
    let limit_known = skel
        .maps
        .bss_data
        .as_ref()
        .is_some_and(|bss| bss.proc_limit_known != 0);
    let mut out: BTreeMap<u32, ProcCpu> = BTreeMap::new();
    let table = &skel.maps.PROC_CPU;
    for key in table.keys() {
        // struct proc_cpu_key { tgid, cpu } -> struct proc_cpu { ran, wait_own, wait_others, wait_limit, wait_idle }
        let Some(pid) = u32_at(&key, 0) else { continue };
        if !traced.contains(&pid) {
            continue;
        }
        let Some(value) = table
            .lookup(&key, MapFlags::ANY)
            .context("reading a process's CPU figures")?
        else {
            continue;
        };
        let entry = out.entry(pid).or_default();
        entry.runq_own_ns += u64_at(&value, 8).unwrap_or(0);
        entry.runq_others_ns += u64_at(&value, 16).unwrap_or(0);
        if limit_known {
            *entry.runq_cpu_limit_ns.get_or_insert(0) += u64_at(&value, 24).unwrap_or(0);
        }
        entry.runq_cpu_idle_ns += u64_at(&value, 32).unwrap_or(0);
    }
    Ok(out)
}

/// What was added to each process's figures since `earlier`.
pub(super) fn window(
    current: &BTreeMap<u32, ProcCpu>,
    earlier: &BTreeMap<u32, ProcCpu>,
) -> BTreeMap<u32, ProcCpu> {
    current
        .iter()
        .map(|(pid, now)| {
            (
                *pid,
                now.since(earlier.get(pid).unwrap_or(&ProcCpu::default())),
            )
        })
        .collect()
}

/// The table for a person: per second of the `over_ns` the figures cover,
/// the processes that waited longest first.
pub(super) fn render(procs: &BTreeMap<u32, ProcCpu>, over_ns: u64, limit: usize) -> String {
    let mut rows: Vec<_> = procs.iter().filter(|(_, p)| p.total_ns() > 0).collect();
    if rows.is_empty() || over_ns == 0 {
        return String::new();
    }
    rows.sort_by_key(|(pid, p)| (std::cmp::Reverse(p.total_ns()), **pid));
    // Microseconds per second of the time covered.
    let rate = |ns: u64| {
        let per_s = u128::from(ns) * 1_000_000_000 / u128::from(over_ns);
        format!(
            "{}/s",
            fmt_us(u64::try_from(per_s / 1000).unwrap_or(u64::MAX))
        )
    };
    let mut out = format!(
        "  {:<9}{:>22}{:>12}{:>12}{:>12}\n",
        "waiting for a cpu:", "own threads had it", "cpu limit", "others", "cpu idle"
    );
    for (pid, p) in rows.iter().take(limit) {
        out += &format!(
            "  {:<9}{:>31}{:>12}{:>12}{:>12}\n",
            pid,
            rate(p.runq_own_ns),
            p.runq_cpu_limit_ns.map_or_else(|| "-".to_string(), rate),
            rate(p.runq_others_ns),
            rate(p.runq_cpu_idle_ns)
        );
    }
    if rows.len() > limit {
        out += &format!("  ({} more)\n", rows.len() - limit);
    }
    out
}

/// The same for a script: one line per process, sums in ns.
pub(super) fn render_raw(procs: &BTreeMap<u32, ProcCpu>, over_ns: u64) -> String {
    procs
        .iter()
        .filter(|(_, p)| p.total_ns() > 0)
        .map(|(pid, p)| {
            let limit = p
                .runq_cpu_limit_ns
                .map(|ns| format!(" runq_cpu_limit_ns={ns}"))
                .unwrap_or_default();
            format!(
                "process_cpu pid={pid} over_ns={over_ns} runq_own_threads_ns={}{limit} runq_others_ns={} runq_cpu_idle_ns={}\n",
                p.runq_own_ns, p.runq_others_ns, p.runq_cpu_idle_ns
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(own: u64, limit: Option<u64>, others: u64, idle: u64) -> ProcCpu {
        ProcCpu {
            runq_own_ns: own,
            runq_cpu_limit_ns: limit,
            runq_others_ns: others,
            runq_cpu_idle_ns: idle,
        }
    }

    #[test]
    fn a_window_is_what_was_added() {
        let earlier = BTreeMap::from([(7, cpu(2, Some(5), 3, 1))]);
        let current = BTreeMap::from([(7, cpu(2, Some(8), 9, 4)), (8, cpu(0, None, 1, 0))]);
        let added = window(&current, &earlier);
        assert_eq!(added[&7], cpu(0, Some(3), 6, 3));
        assert_eq!(added[&8], current[&8]);
    }

    #[test]
    fn rates_are_per_second_and_the_longest_wait_comes_first() {
        let procs = BTreeMap::from([
            (1, cpu(0, None, 20_000_000, 0)),
            (
                2,
                cpu(100_000_000, Some(2_000_000_000), 4_000_000, 6_000_000),
            ),
            (3, ProcCpu::default()),
        ]);
        let out = render(&procs, 2_000_000_000, 10);
        let lines: Vec<_> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].trim_start().starts_with('2'));
        assert!(lines[1].contains("1.0s/s"), "{out}");
        assert!(lines[1].contains("50.0ms/s"), "{out}");
        assert!(lines[1].contains("2.0ms/s"), "{out}");
        assert!(lines[1].contains("3.0ms/s"), "{out}");
        assert!(lines[2].trim_start().starts_with('1'));
        // A kernel that does not say: no figure, not a zero.
        assert!(lines[2].contains(" - "), "{out}");
        assert_eq!(
            render_raw(&procs, 2_000_000_000),
            "process_cpu pid=1 over_ns=2000000000 runq_own_threads_ns=0 runq_others_ns=20000000 runq_cpu_idle_ns=0\n\
             process_cpu pid=2 over_ns=2000000000 runq_own_threads_ns=100000000 runq_cpu_limit_ns=2000000000 runq_others_ns=4000000 runq_cpu_idle_ns=6000000\n"
        );
    }
}
