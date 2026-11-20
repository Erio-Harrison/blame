//! Kernel-side counters and the agent's accounting of its own cost.
//!
//! The overhead budget in the design is a hard constraint, not a footnote, so
//! the agent measures itself rather than asking anyone to take it on faith.

use std::{fs, time::Instant};

use anyhow::{Context as _, Result};
use blame_common::{COUNTER_MAX, Counter};

use crate::bpf::{Skel, percpu_u64_sum};

/// Kernel-side counters, summed across CPUs.
pub struct Counters {
    values: [u64; COUNTER_MAX as usize],
}

impl Counters {
    /// All zero, for tests of what is made from counters.
    #[cfg(test)]
    pub fn zero() -> Self {
        Self {
            values: [0; COUNTER_MAX as usize],
        }
    }

    pub fn read(skel: &Skel) -> Result<Self> {
        let mut values = [0u64; COUNTER_MAX as usize];
        for (index, slot) in values.iter_mut().enumerate() {
            *slot = percpu_u64_sum(&skel.maps.COUNTERS, index as u32)
                .with_context(|| format!("reading counter {index}"))?;
        }
        Ok(Self { values })
    }

    pub fn get(&self, counter: Counter) -> u64 {
        self.values[counter as usize]
    }

    /// Render as `name=value` pairs, flagging any non-zero loss counter.
    pub fn render(&self) -> String {
        Counter::ALL
            .iter()
            .map(|&counter| {
                let value = self.get(counter);
                let flag = if counter.is_loss() && value > 0 {
                    " (!)"
                } else {
                    ""
                };
                format!("{}={value}{flag}", counter.name())
            })
            .collect::<Vec<_>>()
            .join("  ")
    }
}

/// A point-in-time sample of the agent's own resource use.
pub struct Usage {
    /// CPU consumed since the previous sample, as a percentage of one core.
    pub cpu_percent: f64,
    pub rss_bytes: u64,
}

/// Tracks CPU time between samples so the reported percentage is a rate rather
/// than a cumulative total.
pub struct UsageTracker {
    last_cpu_seconds: f64,
    last_sampled_at: Instant,
}

impl UsageTracker {
    pub fn new() -> Result<Self> {
        Ok(Self {
            last_cpu_seconds: read_cpu_seconds()?,
            last_sampled_at: Instant::now(),
        })
    }

    pub fn sample(&mut self) -> Result<Usage> {
        let cpu_seconds = read_cpu_seconds()?;
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_sampled_at).as_secs_f64();
        let cpu_percent = if elapsed > 0.0 {
            (cpu_seconds - self.last_cpu_seconds) / elapsed * 100.0
        } else {
            0.0
        };

        self.last_cpu_seconds = cpu_seconds;
        self.last_sampled_at = now;

        Ok(Usage {
            cpu_percent,
            rss_bytes: read_rss_bytes()?,
        })
    }
}

/// Total user + system CPU time consumed by this process, in seconds.
fn read_cpu_seconds() -> Result<f64> {
    let stat = fs::read_to_string("/proc/self/stat").context("reading /proc/self/stat")?;

    // Field 2 is `comm`, which is parenthesised and may itself contain spaces
    // and parens, so anchor the split on the *last* ')'. What follows starts at
    // field 3 (state), putting utime (field 14) at index 11 and stime at 12.
    let after_comm = stat
        .rsplit_once(')')
        .context("malformed /proc/self/stat: no ')'")?
        .1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let parse = |index: usize, what: &str| -> Result<u64> {
        fields
            .get(index)
            .with_context(|| format!("/proc/self/stat missing {what}"))?
            .parse()
            .with_context(|| format!("/proc/self/stat has non-numeric {what}"))
    };

    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    anyhow::ensure!(
        ticks_per_second > 0,
        "sysconf(_SC_CLK_TCK) returned {ticks_per_second}"
    );

    let ticks = parse(11, "utime")? + parse(12, "stime")?;
    Ok(ticks as f64 / ticks_per_second as f64)
}

fn read_rss_bytes() -> Result<u64> {
    let statm = fs::read_to_string("/proc/self/statm").context("reading /proc/self/statm")?;
    // Fields are page counts: size, resident, shared, text, lib, data, dt.
    let resident: u64 = statm
        .split_whitespace()
        .nth(1)
        .context("/proc/self/statm missing resident field")?
        .parse()
        .context("/proc/self/statm has non-numeric resident field")?;

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    anyhow::ensure!(page_size > 0, "sysconf(_SC_PAGESIZE) returned {page_size}");
    Ok(resident * page_size as u64)
}

pub fn human_bytes(bytes: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    format!("{:.1}MiB", bytes as f64 / MIB)
}
