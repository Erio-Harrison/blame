//! What each traced process's threads waited for a CPU
//! (`bpf/request/proc_cpu.h`): per process, not per request. With it, what
//! the hypervisor took from the CPUs its threads used (steal), and how long
//! its control groups were throttled by a CPU limit (`cpu.stat`).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use libbpf_rs::{MapCore as _, MapFlags};

use crate::{bpf::Skel, top::fmt_us};

/// One process's threads, summed over the CPUs, since the agent started:
/// what they waited for a CPU, by what the CPU they were queued on did
/// meanwhile. The four `runq_*` add up to all they waited.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcCpu {
    /// Another thread of the same process ran on the CPU they were queued on.
    pub runq_own_ns: u64,
    /// A CPU limit on its control group kept them off it. `None`: this
    /// kernel does not say, and such a wait is in the two below.
    pub runq_cpu_limit_ns: Option<u64>,
    /// Something else ran on it.
    pub runq_others_ns: u64,
    /// It ran nothing but its idle task: being woken up, or handling
    /// interrupts while idle.
    pub runq_cpu_idle_ns: u64,
    /// What the hypervisor took from the CPUs its threads ran or waited on
    /// (`steal` in `/proc/stat`), summed over those CPUs. 0 also where the
    /// hypervisor does not say.
    pub steal_ns: u64,
    /// The most any of its control groups (its own, and those above it) was
    /// throttled by a CPU limit (`throttled_usec` in `cpu.stat`). `None`: no
    /// such figure could be read for any of them.
    pub cgroup_throttled_ns: Option<u64>,
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
            steal_ns: self.steal_ns.saturating_sub(earlier.steal_ns),
            cgroup_throttled_ns: self
                .cgroup_throttled_ns
                .map(|ns| ns.saturating_sub(earlier.cgroup_throttled_ns.unwrap_or(0))),
        }
    }

    /// All its threads waited.
    pub fn total_ns(&self) -> u64 {
        self.runq_own_ns
            + self.runq_cpu_limit_ns.unwrap_or(0)
            + self.runq_others_ns
            + self.runq_cpu_idle_ns
    }

    /// Anything to show.
    pub fn any(&self) -> bool {
        self.total_ns() > 0 || self.steal_ns > 0 || self.cgroup_throttled_ns.unwrap_or(0) > 0
    }

    /// Add one entry of the kernel side's table: `struct proc_cpu` { ran,
    /// wait_own, wait_others, wait_limit, wait_idle }.
    fn add(&mut self, words: &[u64; 5], limit_known: bool) {
        self.runq_own_ns += words[1];
        self.runq_others_ns += words[2];
        if limit_known {
            *self.runq_cpu_limit_ns.get_or_insert(0) += words[3];
        }
        self.runq_cpu_idle_ns += words[4];
    }

    fn add_figures(&mut self, other: &Self) {
        self.runq_own_ns += other.runq_own_ns;
        if let Some(ns) = other.runq_cpu_limit_ns {
            *self.runq_cpu_limit_ns.get_or_insert(0) += ns;
        }
        self.runq_others_ns += other.runq_others_ns;
        self.runq_cpu_idle_ns += other.runq_cpu_idle_ns;
    }
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// `ran` is open while a thread of the process runs there (maps.h).
const PROC_OPEN: u64 = 1 << 63;

/// Reads the kernel side's table, removes the entries of processes that are
/// gone (keeping their figures), and adds steal and cgroup throttling, which
/// are summed between reads.
#[derive(Default)]
pub(super) struct Tracker {
    /// Figures of processes that are gone, whose entries were removed.
    gone: BTreeMap<u32, ProcCpu>,
    /// Each (process, CPU) entry as it was at the last read: one that
    /// changed, or has a thread running, was used since.
    last_seen: HashMap<(u32, u32), [u64; 5]>,
    /// Each CPU's steal at the last read, in ns.
    last_steal: Vec<u64>,
    /// Steal on the CPUs each process used, summed so far.
    steal: BTreeMap<u32, u64>,
    /// Each control group's throttled time at the last read, in ns.
    last_throttled: HashMap<PathBuf, u64>,
    /// The most any of each process's control groups was throttled, summed
    /// read by read.
    throttled: BTreeMap<u32, u64>,
}

impl Tracker {
    /// Every traced process's figures so far, by pid, those gone included.
    pub(super) fn read(&mut self, skel: &Skel) -> Result<BTreeMap<u32, ProcCpu>> {
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
        let steal_now = read_steal(Path::new("/proc/stat")).unwrap_or_default();
        let table = &skel.maps.PROC_CPU;
        let mut out: BTreeMap<u32, ProcCpu> = BTreeMap::new();
        let mut used: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut gone_keys = Vec::new();
        for key in table.keys() {
            // struct proc_cpu_key { tgid, cpu }
            let (Some(pid), Some(cpu)) = (u32_at(&key, 0), u32_at(&key, 4)) else {
                continue;
            };
            let Some(value) = table
                .lookup(&key, MapFlags::ANY)
                .context("reading a process's CPU figures")?
            else {
                continue;
            };
            let mut words = [0u64; 5];
            for (i, word) in words.iter_mut().enumerate() {
                *word = u64_at(&value, i * 8).unwrap_or(0);
            }
            if !traced.contains(&pid) {
                // Gone: nothing adds to it any more. Its figures are kept
                // here and its entry made room for others.
                self.gone.entry(pid).or_default().add(&words, limit_known);
                self.last_seen.remove(&(pid, cpu));
                gone_keys.push(key);
                continue;
            }
            if words[0] & PROC_OPEN != 0 || self.last_seen.get(&(pid, cpu)) != Some(&words) {
                used.entry(pid).or_default().push(cpu);
            }
            self.last_seen.insert((pid, cpu), words);
            out.entry(pid).or_default().add(&words, limit_known);
        }
        for key in gone_keys {
            // Already gone if the kernel side removed it meanwhile.
            let _ = table.delete(&key);
        }
        if !self.last_steal.is_empty() {
            for (pid, cpus) in &used {
                let stolen: u64 = cpus
                    .iter()
                    .map(|&cpu| {
                        let cpu = cpu as usize;
                        steal_now
                            .get(cpu)
                            .zip(self.last_steal.get(cpu))
                            .map_or(0, |(now, then)| now.saturating_sub(*then))
                    })
                    .sum();
                *self.steal.entry(*pid).or_default() += stolen;
            }
        }
        if !steal_now.is_empty() {
            self.last_steal = steal_now;
        }
        // Every traced process, from the first read on: one with nothing in
        // the table yet is counted from then, not from when it first waited.
        for pid in &traced {
            if let Some(ns) =
                self.throttled_since(Path::new("/proc"), Path::new("/sys/fs/cgroup"), *pid)
            {
                *self.throttled.entry(*pid).or_default() += ns;
            }
        }
        for (pid, figures) in &self.gone {
            out.entry(*pid).or_default().add_figures(figures);
        }
        for (pid, p) in &mut out {
            p.steal_ns = self.steal.get(pid).copied().unwrap_or(0);
            p.cgroup_throttled_ns = self.throttled.get(pid).copied();
        }
        Ok(out)
    }

    /// How much longer than at the last read the most throttled of `pid`'s
    /// control groups (cgroup v2: its own and those above it) has been
    /// throttled. `None`: none of them has the figure, or the process is
    /// gone. A group first seen now counts from now.
    fn throttled_since(&mut self, proc: &Path, cgroupfs: &Path, pid: u32) -> Option<u64> {
        let membership = std::fs::read_to_string(proc.join(pid.to_string()).join("cgroup")).ok()?;
        let path = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))?;
        let mut dir = cgroupfs.join(path.trim_start_matches('/'));
        let mut most: Option<u64> = None;
        loop {
            if let Some(now) = throttled_ns(&dir.join("cpu.stat")) {
                let then = self.last_throttled.insert(dir.clone(), now).unwrap_or(now);
                most = Some(most.unwrap_or(0).max(now.saturating_sub(then)));
            }
            if dir == cgroupfs || !dir.pop() || !dir.starts_with(cgroupfs) {
                break;
            }
        }
        most
    }
}

/// `throttled_usec` of a cgroup v2 `cpu.stat`, in ns.
fn throttled_ns(file: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(file).ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("throttled_usec "))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|us| us.saturating_mul(1000))
}

/// Each CPU's steal so far, in ns, by CPU number (`/proc/stat`: the eighth
/// figure of each `cpuN` line, in clock ticks).
fn read_steal(file: &Path) -> Option<Vec<u64>> {
    // SAFETY: sysconf has no preconditions.
    let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
        .ok()
        .filter(|hz| *hz > 0)?;
    parse_steal(&std::fs::read_to_string(file).ok()?, hz)
}

fn parse_steal(text: &str, hz: u64) -> Option<Vec<u64>> {
    let mut steal = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(name) = fields.next() else { continue };
        let Some(cpu) = name
            .strip_prefix("cpu")
            .and_then(|n| n.parse::<usize>().ok())
        else {
            continue;
        };
        // user nice system idle iowait irq softirq steal
        let ticks: u64 = fields.nth(7)?.parse().ok()?;
        if steal.len() <= cpu {
            steal.resize(cpu + 1, 0);
        }
        steal[cpu] = ticks.saturating_mul(1_000_000_000) / hz;
    }
    (!steal.is_empty()).then_some(steal)
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
    let mut rows: Vec<_> = procs.iter().filter(|(_, p)| p.any()).collect();
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
    let mut group_only = false;
    let mut out = format!(
        "  {:<9}{:>22}{:>12}{:>12}{:>12}{:>16}\n",
        "waiting for a cpu:",
        "own threads had it",
        "cpu limit",
        "others",
        "cpu idle",
        "steal (its cpus)"
    );
    for (pid, p) in rows.iter().take(limit) {
        // Not known by thread on this kernel: the group's throttled time,
        // if there was any, marked as such.
        let limit = match (p.runq_cpu_limit_ns, p.cgroup_throttled_ns) {
            (Some(ns), _) => rate(ns),
            (None, Some(ns)) if ns > 0 => {
                group_only = true;
                format!("~{}", rate(ns))
            }
            (None, _) => "-".to_string(),
        };
        out += &format!(
            "  {:<9}{:>31}{:>12}{:>12}{:>12}{:>16}\n",
            pid,
            rate(p.runq_own_ns),
            limit,
            rate(p.runq_others_ns),
            rate(p.runq_cpu_idle_ns),
            rate(p.steal_ns)
        );
    }
    if rows.len() > limit {
        out += &format!("  ({} more)\n", rows.len() - limit);
    }
    if group_only {
        out += "  ~ this kernel does not say what of the threads' waits a cpu limit caused: the most its control groups were throttled (cpu.stat), not split from the other figures\n";
    }
    out
}

/// The same for a script: one line per process, sums in ns.
pub(super) fn render_raw(procs: &BTreeMap<u32, ProcCpu>, over_ns: u64) -> String {
    procs
        .iter()
        .filter(|(_, p)| p.any())
        .map(|(pid, p)| {
            let limit = p
                .runq_cpu_limit_ns
                .map(|ns| format!(" runq_cpu_limit_ns={ns}"))
                .unwrap_or_default();
            let group = p
                .cgroup_throttled_ns
                .map(|ns| format!(" cgroup_throttled_ns={ns}"))
                .unwrap_or_default();
            format!(
                "process_cpu pid={pid} over_ns={over_ns} runq_own_threads_ns={}{limit} runq_others_ns={} runq_cpu_idle_ns={} steal_ns={}{group}\n",
                p.runq_own_ns, p.runq_others_ns, p.runq_cpu_idle_ns, p.steal_ns
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
            ..ProcCpu::default()
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
            "process_cpu pid=1 over_ns=2000000000 runq_own_threads_ns=0 runq_others_ns=20000000 runq_cpu_idle_ns=0 steal_ns=0\n\
             process_cpu pid=2 over_ns=2000000000 runq_own_threads_ns=100000000 runq_cpu_limit_ns=2000000000 runq_others_ns=4000000 runq_cpu_idle_ns=6000000 steal_ns=0\n"
        );
    }

    #[test]
    fn steal_is_the_eighth_figure_of_each_cpu_line() {
        let stat = "cpu  10 0 5 100 1 0 2 7 0 0\n\
                    cpu0 5 0 2 50 0 0 1 3 0 0\n\
                    cpu2 5 0 3 50 1 0 1 4 0 0\n\
                    intr 1 2 3\n";
        // cpu1 is offline: none of it, and the numbers stay the CPUs'.
        assert_eq!(
            parse_steal(stat, 100),
            Some(vec![30_000_000, 0, 40_000_000])
        );
        assert_eq!(parse_steal("intr 1\n", 100), None);
    }

    #[test]
    fn the_most_throttled_group_counts_from_when_it_was_first_seen() {
        let dir = std::env::temp_dir().join(format!("blame-cgroup-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (proc, fs) = (dir.join("proc"), dir.join("cgroup"));
        std::fs::create_dir_all(proc.join("42")).unwrap();
        std::fs::create_dir_all(fs.join("a/b")).unwrap();
        std::fs::write(proc.join("42/cgroup"), "0::/a/b\n").unwrap();
        let stat = |file: &str, us: u64| {
            std::fs::write(
                fs.join(file),
                format!("usage_usec 1\nthrottled_usec {us}\n"),
            )
            .unwrap();
        };
        stat("a/cpu.stat", 100);
        stat("a/b/cpu.stat", 5);
        let mut tracker = Tracker::default();
        assert_eq!(tracker.throttled_since(&proc, &fs, 42), Some(0));
        // The group above was throttled 30 us more, its own 2 us more.
        stat("a/cpu.stat", 130);
        stat("a/b/cpu.stat", 7);
        assert_eq!(tracker.throttled_since(&proc, &fs, 42), Some(30_000));
        // No cpu.stat with the figure anywhere: none.
        assert_eq!(tracker.throttled_since(&proc, &fs, 43), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
