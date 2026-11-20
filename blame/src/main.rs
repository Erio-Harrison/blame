//! blame agent — M0: prove the kernel-to-userspace path is reliable, cheap,
//! and honest about what it drops.

mod bpf;
mod cgroupfs;
mod consume;
mod h2meta;
mod hpack;
mod identity;
mod json;
mod methods;
mod procfs;
mod runq;
mod runtime;
mod slow;
mod stats;
mod top;

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context as _, Result};
use bpf::{Events, Skel};
use clap::{Parser, Subcommand};
use consume::ConsumerStats;
use stats::{Counters, UsageTracker, human_bytes};
use tokio::signal;

#[derive(Debug, Parser)]
#[clap(about = "eBPF tail-latency attribution agent")]
struct Opt {
    /// Print every event as it arrives.
    #[clap(long)]
    debug: bool,

    /// Seconds between statistics reports. 0 reports only on exit.
    #[clap(long, default_value_t = 10, value_name = "SECS")]
    stats_interval: u64,

    /// Ring buffer capacity in bytes; must be a power-of-two multiple of the
    /// page size. Shrink it to make overflow reproducible when exercising the
    /// loss accounting.
    #[clap(long, value_name = "BYTES")]
    ringbuf_bytes: Option<u32>,

    /// BTF file to relocate the programs against instead of the running
    /// kernel's, for kernels built without BTF (e.g. one from BTFHub).
    #[clap(long, global = true, value_name = "PATH")]
    btf: Option<PathBuf>,

    #[clap(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Measure how long runnable threads wait for a CPU.
    Runq(runq::RunqOpt),
    /// Show run-queue latency per service, container or pod.
    Top(top::TopOpt),
    /// Show slow HTTP/1.1 requests and where their time went.
    Slow(slow::SlowOpt),
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::init();
    bpf::init_logging();
    if let Some(path) = &opt.btf {
        bpf::set_target_btf(path.clone());
    }

    match opt.command {
        Some(Command::Runq(runq_opt)) => runq::run(runq_opt).await,
        Some(Command::Top(top_opt)) => top::run(top_opt).await,
        Some(Command::Slow(slow_opt)) => slow::run(slow_opt).await,
        None => run_exec_trace(opt).await,
    }
}

/// The default mode: trace `sched_process_exec` and stream the events.
async fn run_exec_trace(opt: Opt) -> Result<()> {
    let mut open = bpf::open()?;
    bpf::autoload_only(&mut open, &["sched_process_exec"]);
    if let Some(bytes) = opt.ringbuf_bytes {
        open.maps
            .EVENTS
            .set_max_entries(bytes)
            .context("resizing the EVENTS ring buffer")?;
    }
    let skel = bpf::load(open)?;
    // Dropping the link detaches the program, so it must outlive the loop.
    let _link = skel
        .progs
        .sched_process_exec
        .attach()
        .context("attaching to tracepoint sched:sched_process_exec")?;

    let consumer_stats = Arc::new(ConsumerStats::default());
    let events = Events::new(
        &skel.maps.EVENTS,
        consume::handler(opt.debug, Arc::clone(&consumer_stats))?,
    )?;

    let mut usage = UsageTracker::new()?;
    println!("blame: attached to sched:sched_process_exec. Ctrl-C to exit.");

    let mut ticker =
        tokio::time::interval(std::time::Duration::from_secs(opt.stats_interval.max(1)));
    ticker.tick().await; // the first tick completes immediately

    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .context("installing SIGINT handler")?;
    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = ticker.tick(), if opt.stats_interval > 0 => {
                report(&skel, &consumer_stats, &mut usage)?;
            }
            // A consumer error means the data path is dead; staying up would
            // mean silently observing nothing.
            consumed = events.wait() => consumed.context("ring buffer consumer failed")?,
        }
    }

    println!("\nblame: exiting.");
    events.drain()?;
    report(&skel, &consumer_stats, &mut usage)?;
    reconcile(&skel, &consumer_stats)?;
    Ok(())
}

/// Print kernel counters, agent counters, and the agent's own cost.
fn report(skel: &Skel, consumer_stats: &ConsumerStats, usage: &mut UsageTracker) -> Result<()> {
    let counters = Counters::read(skel)?;
    let usage = usage.sample()?;
    println!("--- stats ---");
    println!("  kernel  {}", counters.render());
    println!("  agent   {}", consumer_stats.render());
    println!(
        "  self    cpu={:.2}%  rss={}",
        usage.cpu_percent,
        human_bytes(usage.rss_bytes)
    );
    Ok(())
}

/// Check that every event the kernel committed reached the consumer.
///
/// A mismatch here means the agent lost records on its own side, which the
/// kernel counters cannot see.
fn reconcile(skel: &Skel, consumer_stats: &ConsumerStats) -> Result<()> {
    let counters = Counters::read(skel)?;
    let produced = counters.get(blame_common::Counter::EventsProduced);
    let consumed = consumer_stats.consumed();
    if produced == consumed {
        println!("  reconcile  ok: produced == consumed == {produced}");
    } else {
        println!(
            "  reconcile  MISMATCH: produced={produced} consumed={consumed} (delta {})",
            produced as i64 - consumed as i64
        );
    }
    Ok(())
}
