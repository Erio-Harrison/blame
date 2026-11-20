//! Ring buffer consumer: turns raw records into events.
//!
//! Every path that fails to produce an event increments a counter. Combined
//! with the kernel-side counters in [`crate::stats`], that makes the full
//! pipeline auditable: `events_produced` must equal `consumed` plus whatever the
//! reject counters account for.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use anyhow::{Context as _, Result};
use blame_common::{CgroupMkdirEvent, EVENT_VERSION, EventHeader, EventKind, ExecEvent};

/// Userspace-side accounting, mirroring the kernel counters.
#[derive(Default)]
pub struct ConsumerStats {
    consumed: AtomicU64,
    /// Records too short or misaligned to interpret.
    malformed: AtomicU64,
    /// Records stamped with a wire version this build does not know. Rejected
    /// rather than reinterpreted.
    version_mismatch: AtomicU64,
    /// Records whose `kind` this build does not know.
    unknown_kind: AtomicU64,
}

impl ConsumerStats {
    pub fn render(&self) -> String {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let rejected =
            load(&self.malformed) + load(&self.version_mismatch) + load(&self.unknown_kind);
        let flag = if rejected > 0 { " (!)" } else { "" };
        format!(
            "consumed={}  malformed={}  version_mismatch={}  unknown_kind={}{flag}",
            load(&self.consumed),
            load(&self.malformed),
            load(&self.version_mismatch),
            load(&self.unknown_kind),
        )
    }

    pub fn consumed(&self) -> u64 {
        self.consumed.load(Ordering::Relaxed)
    }
}

/// The per-record handler for the ring buffer consumer.
pub fn handler(debug: bool, stats: Arc<ConsumerStats>) -> Result<impl FnMut(&[u8]) + 'static> {
    let wall_offset = boot_to_wall_offset_ns()?;
    Ok(move |record: &[u8]| handle(record, debug, &stats, wall_offset))
}

fn handle(record: &[u8], debug: bool, stats: &ConsumerStats, wall_offset: i128) {
    let bump = |counter: &AtomicU64| {
        counter.fetch_add(1, Ordering::Relaxed);
    };

    let Some(header) = EventHeader::parse(record) else {
        bump(&stats.malformed);
        return;
    };
    if header.version != EVENT_VERSION {
        bump(&stats.version_mismatch);
        return;
    }

    match EventKind::from_raw(header.kind) {
        Some(EventKind::Exec) => {
            let Some(event) = ExecEvent::parse(record) else {
                bump(&stats.malformed);
                return;
            };
            bump(&stats.consumed);
            if debug {
                print_exec(event, wall_offset);
            }
        }
        // Only `blame slow` asks for these.
        Some(EventKind::H2Headers | EventKind::TaskSample | EventKind::H2Fields) => {
            bump(&stats.malformed)
        }
        Some(EventKind::CgroupMkdir) => {
            let Some(event) = CgroupMkdirEvent::parse(record) else {
                bump(&stats.malformed);
                return;
            };
            bump(&stats.consumed);
            if debug {
                println!(
                    "{}  cgroup_mkdir  id={} root={} {}",
                    format_wall_clock(event.hdr.ts_boot_ns, wall_offset),
                    event.id,
                    event.root,
                    String::from_utf8_lossy(event.path_bytes()),
                );
            }
        }
        // Request events come from programs this mode does not load.
        Some(EventKind::Request) | None => bump(&stats.unknown_kind),
    }
}

fn print_exec(event: &ExecEvent, wall_offset: i128) {
    println!(
        "{}  exec  pid={} tid={} cpu={} cgroup={} comm={} {}",
        format_wall_clock(event.hdr.ts_boot_ns, wall_offset),
        event.hdr.pid,
        event.hdr.tid,
        event.hdr.cpu,
        event.hdr.cgroup_id,
        String::from_utf8_lossy(event.comm_bytes()),
        String::from_utf8_lossy(event.filename_bytes()),
    );
}

/// Nanoseconds to add to a `CLOCK_BOOTTIME` stamp to get wall clock time.
///
/// Computed once: events carry boot time because that is what is cheap and
/// monotonic in the kernel, and the conversion happens only at display time.
pub fn boot_to_wall_offset_ns() -> Result<i128> {
    let wall = clock_gettime_ns(libc::CLOCK_REALTIME).context("clock_gettime(CLOCK_REALTIME)")?;
    let boot = clock_gettime_ns(libc::CLOCK_BOOTTIME).context("clock_gettime(CLOCK_BOOTTIME)")?;
    Ok(wall - boot)
}

pub fn clock_gettime_ns(clock: libc::clockid_t) -> Result<i128> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, properly aligned `timespec` we own.
    let ret = unsafe { libc::clock_gettime(clock, &mut ts) };
    anyhow::ensure!(
        ret == 0,
        "clock_gettime failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128)
}

/// Format a boot-time stamp as `HH:MM:SS.mmm` UTC.
pub fn format_wall_clock(ts_boot_ns: u64, wall_offset: i128) -> String {
    let wall_ns = ts_boot_ns as i128 + wall_offset;
    if wall_ns < 0 {
        return "??:??:??.???".to_string();
    }
    let seconds = (wall_ns / 1_000_000_000) as u64;
    let millis = (wall_ns % 1_000_000_000) / 1_000_000;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        (seconds / 3600) % 24,
        (seconds / 60) % 60,
        seconds % 60,
        millis,
    )
}
