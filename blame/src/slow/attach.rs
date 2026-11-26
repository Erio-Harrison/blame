//! Loading the kernel side and attaching it: which programs load, how the
//! tables are sized, the order programs are attached in, and starting to
//! trace the processes there are (`process.rs` looks at each of them,
//! `fsvc.rs` decides the file-service hooks).

use std::{cell::RefCell, os::fd::OwnedFd, path::Path, ptr::NonNull};

use anyhow::{Context as _, Result, bail};
use libbpf_rs::{
    AsRawLibbpf as _, Link, MapCore, MapFlags,
    skel::{OpenSkel as _, Skel as _},
};

use super::{
    SlowOpt,
    fsvc::{FSVC_PREFIX, attach_fsvc, fsvc_function, fsvc_present},
    process::{ProcessNote, follow_tls, inspect_and_attach},
};
use crate::{
    bpf::{self, Skel},
    procfs,
};

/// The request programs all carry this prefix.
pub(super) const PROGRAM_PREFIX: &str = "req_";

/// Programs attached to functions of a traced process's binary carry this
/// one: loaded with the rest, attached per process (`process.rs`).
const PROBE_PREFIX: &str = "up_";

/// The ring buffer for `blame slow`. Every header block of every HTTP/2
/// request goes through it, and one that is lost takes the names of every
/// later request on its connection with it. A call takes about half a
/// kilobyte; this holds what tens of thousands of calls a second produce
/// while the agent is kept from running for a few hundred milliseconds.
const RING_BYTES: u32 = 8 << 20;

/// The parser runs in `bpf_loop`, which arrived in this kernel version.
const KERNEL_MIN: (u32, u32) = (5, 17);

pub(super) struct Attached {
    /// Declared first so the programs are detached before the object closes.
    pub(super) _links: Vec<Link>,
    /// Probes in traced processes; they stay until the agent exits.
    pub(super) probe_links: RefCell<Vec<Link>>,
    pub(super) skel: Skel,
    /// Held open to keep the kernel's run time accounting on.
    pub(super) _stats_fd: OwnedFd,
    pub(super) traced_at_start: usize,
    /// The kernel side's `rt_gen`, in the object's memory-mapped data. The
    /// skeleton is never freed (see `bpf::open`), so the pointer stays valid.
    pub(super) rt_gen: *mut u32,
    /// What was found in the processes traced from the start.
    pub(super) notes: Vec<ProcessNote>,
    pub(super) table_bytes: u64,
}

fn is_request_program(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().starts_with(PROGRAM_PREFIX)
}
/// What to say about a program that would not attach when tracefs is not
/// mounted: libbpf finds a tracepoint's id there, and a container has it
/// only when given it.
fn tracefs_hint() -> &'static str {
    let mounted = [
        "/sys/kernel/tracing/events",
        "/sys/kernel/debug/tracing/events",
    ]
    .iter()
    .any(|dir| Path::new(dir).is_dir());
    if mounted {
        ""
    } else {
        " (tracepoints are found through tracefs, which is not mounted: mount it with \
         `mount -t tracefs nodev /sys/kernel/tracing`, or give a container the host's \
         /sys/kernel/tracing)"
    }
}

/// Attach programs all at once, a thread each. One after the other, the
/// first fentry or fexit program on each function takes some 110 ms (the
/// file-service hooks: about 1.2 s); together, some 150 ms (355 ms with a
/// busy process traced). Each program's own error, or its link.
pub(super) fn attach_together(
    programs: Vec<(String, NonNull<libbpf_sys::bpf_program>)>,
) -> Vec<(String, Result<Link>)> {
    struct Prog(NonNull<libbpf_sys::bpf_program>);
    // SAFETY: each program is attached by one thread only, and libbpf keeps
    // no state shared between attaching different programs.
    unsafe impl Send for Prog {}
    std::thread::scope(|scope| {
        let handles: Vec<_> = programs
            .into_iter()
            .map(|(name, program)| {
                let program = Prog(program);
                scope.spawn(move || {
                    let program = program;
                    // SAFETY: a loaded program of the object, which outlives
                    // the scope.
                    let link = unsafe { libbpf_sys::bpf_program__attach(program.0.as_ptr()) };
                    let link = match NonNull::new(link) {
                        // SAFETY: a link libbpf just made, owned by no one else.
                        Some(link) => Ok(unsafe { Link::from_ptr(link) }),
                        None => Err(anyhow::Error::from(std::io::Error::last_os_error())),
                    };
                    (name, link)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("attaching thread panicked"))
            .collect()
    })
}

/// Where a program goes in the order of attaching. Programs come in pairs
/// that mark a thread while it is inside something (a function's entry and
/// return, a system call's entry and exit): a return attached before its
/// entry finds nothing marked and does nothing, but an entry attached before
/// its return marks threads that are never unmarked. Attached 100-200 ms
/// apart, a flush entered in between left its thread's sleeps counted as
/// disk for good, and a socket marked by `sock_def_readable` stayed the one
/// every later wakeup on that CPU came from. So returns first (0), then the
/// entries of functions (1), which only mark: by the time the programs that
/// follow requests are on (2), what they read is kept up to date.
pub(super) fn attach_rank(name: &str, program: NonNull<libbpf_sys::bpf_program>) -> u8 {
    // SAFETY: a loaded program of the object.
    let attach_type = unsafe { libbpf_sys::bpf_program__expected_attach_type(program.as_ptr()) };
    if attach_type == libbpf_sys::BPF_TRACE_FEXIT || name.starts_with("req_exit_") {
        0
    } else if attach_type == libbpf_sys::BPF_TRACE_FENTRY {
        1
    } else {
        2
    }
}

/// The loaded programs whose name passes `wanted`.
pub(super) fn loaded(
    skel: &Skel,
    wanted: impl Fn(&str) -> bool,
) -> Vec<(String, NonNull<libbpf_sys::bpf_program>)> {
    skel.object()
        .progs()
        .filter(|program| program.autoload())
        .filter_map(|program| {
            let name = program.name().to_string_lossy().into_owned();
            wanted(&name).then(|| (name, program.as_libbpf_object()))
        })
        .collect()
}

fn is_probe_program(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().starts_with(PROBE_PREFIX)
}

/// The per-process CPU table: entries per CPU, and at least this many.
const PROC_CPU_PER_CPU: u32 = 256;
const PROC_CPU_MIN: u32 = 16384;

/// Open, size and load the programs of `slow`, with the file-service hooks
/// or without them.
fn load_programs(opt: &SlowOpt, fsvc: bool) -> Result<Skel> {
    let mut open = bpf::open()?;
    for mut program in open.open_object_mut().progs_mut() {
        let name = program.name().to_string_lossy().into_owned();
        let wanted = match fsvc_function(&name) {
            Some(function) => fsvc && fsvc_present(function),
            None => {
                let name = std::ffi::OsStr::new(&name);
                is_request_program(name) || is_probe_program(name) || name == "cgroup_mkdir"
            }
        };
        program.set_autoload(wanted);
    }
    let rodata = open
        .maps
        .rodata_data
        .as_deref_mut()
        .context("the eBPF object has no read-only data")?;
    // Every request is sent up, to be summed up by method or route; which
    // are slow enough to list is decided there.
    rodata.req_slow_ns = 0;
    rodata.req_only_listed = u8::from(!opt.pids.is_empty());
    open.maps
        .EVENTS
        .set_max_entries(RING_BYTES)
        .context("sizing the ring buffer")?;
    if let Some(entries) = opt.max_connections {
        open.maps.REQ_CONNS.set_max_entries(entries)?;
    }
    if let Some(entries) = opt.max_requests {
        open.maps.REQ_TABLE.set_max_entries(entries)?;
    }
    // One entry per traced process and CPU it uses: room for 256 processes
    // on every CPU. Entries of processes that are gone are removed as they
    // are read (proc_cpu.rs).
    let cpus = u32::try_from(libbpf_rs::num_possible_cpus().context("counting the CPUs")?)
        .unwrap_or(u32::MAX);
    open.maps
        .PROC_CPU
        .set_max_entries(PROC_CPU_MIN.max(cpus.saturating_mul(PROC_CPU_PER_CPU)))
        .context("sizing the per-process CPU table")?;
    bpf::load(open)
}

pub(super) fn attach(opt: &SlowOpt) -> Result<Attached> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .context("reading the kernel release")?;
    if !kernel_at_least(&release, KERNEL_MIN) {
        bail!(
            "`blame slow` needs Linux {}.{} or newer; this is {}",
            KERNEL_MIN.0,
            KERNEL_MIN.1,
            release.trim()
        );
    }
    for &pid in &opt.pids {
        check_process(Path::new("/proc"), pid)?;
    }

    let mut skel = match load_programs(opt, true) {
        Ok(skel) => skel,
        // An fentry program on a file-service function that could not be
        // loaded (not traceable in this kernel): the rest without them.
        Err(err) => {
            let skel = load_programs(opt, false).map_err(|_| err)?;
            eprintln!(
                "blame: waits for a file service (NFS, FUSE, ...) are not told apart from disk \
                 waits: their hooks did not load"
            );
            skel
        }
    };
    let stats_fd = bpf::enable_run_time_stats()?;

    // Before attaching: a socket that is already open is classified by
    // whether its local port was listening, the first time data moves on it.
    let listening = procfs::listeners(Path::new("/proc"));
    let mut ports_left_out = 0usize;
    for (netns, port) in &listening.ports {
        let mut key = [0u8; 8];
        key[..4].copy_from_slice(&netns.to_ne_bytes());
        key[4..6].copy_from_slice(&port.to_ne_bytes());
        if skel
            .maps
            .REQ_LISTEN
            .update(&key, &[1], MapFlags::ANY)
            .is_err()
        {
            ports_left_out += 1;
        }
    }
    if ports_left_out > 0 {
        eprintln!(
            "blame: {ports_left_out} of {} listening ports did not fit the table; connections \
             already open on them are taken for outgoing ones",
            listening.ports.len()
        );
    }
    let traced = if opt.pids.is_empty() {
        &listening.pids
    } else {
        &opt.pids
    };
    let mut procs_left_out = 0usize;
    let mut found_in = Vec::new();
    let mut probe_links = Vec::new();
    for pid in traced {
        let (found, links) = inspect_and_attach(&skel, opt, *pid);
        probe_links.extend(links);
        if skel
            .maps
            .REQ_PROCS
            .update(&pid.to_ne_bytes(), &found.cfg.to_bytes(), MapFlags::ANY)
            .is_err()
        {
            procs_left_out += 1;
        } else {
            found_in.push((*pid, found));
        }
    }
    // The scheduler hook passes over threads of processes without a bit here.
    let bits = skel
        .maps
        .bss_data
        .as_deref_mut()
        .context("the eBPF object has no zero-initialised data")?;
    for (pid, _) in &found_in {
        let bit = *pid as usize % (bits.proc_bits.len() * 64);
        bits.proc_bits[bit / 64] |= 1 << (bit % 64);
    }
    if procs_left_out > 0 {
        if !opt.pids.is_empty() {
            bail!("{procs_left_out} of the listed processes did not fit the table");
        }
        eprintln!(
            "blame: {procs_left_out} of {} listening processes did not fit the table and are \
             not traced",
            traced.len()
        );
    }

    let mut links = Vec::new();
    // Before the request programs: from when those are on, requests are seen.
    links.extend(attach_fsvc(&skel));
    let mut request = loaded(&skel, |name| {
        (is_request_program(std::ffi::OsStr::new(name)) || name == "cgroup_mkdir")
            && !name.starts_with(FSVC_PREFIX)
    });
    request.sort_by_key(|(name, program)| attach_rank(name, *program));
    // One after the other: attached together, a goroutine read at a kernel
    // event right after attaching did not hold together in 2 of 10 starts
    // (0 of 20 one by one); why is not known.
    for (name, program) in request {
        // SAFETY: a loaded program of the object, which outlives the links.
        let link = unsafe { libbpf_sys::bpf_program__attach(program.as_ptr()) };
        let link = NonNull::new(link)
            .ok_or_else(std::io::Error::last_os_error)
            .with_context(|| format!("attaching {name}{}", tracefs_hint()))?;
        // SAFETY: a link libbpf just made, owned by no one else.
        links.push(unsafe { Link::from_ptr(link) });
    }
    // The TLS probes start requests too: only now that the rest is on.
    let notes = found_in
        .into_iter()
        .map(|(pid, mut found)| {
            probe_links.extend(follow_tls(&skel, opt, pid, &mut found));
            ProcessNote::of(pid, &found)
        })
        .collect();

    let bytes = |map: &dyn MapCore| {
        u64::from(map.max_entries()) * u64::from(map.key_size() + map.value_size())
    };
    let table_bytes =
        bytes(&skel.maps.REQ_CONNS) + bytes(&skel.maps.REQ_TABLE) + u64::from(RING_BYTES);
    let rt_gen = skel
        .maps
        .data_data
        .as_deref_mut()
        .map(|data| std::ptr::from_mut(&mut data.rt_gen))
        .context("the eBPF object has no writable data")?;
    // Threads that ran into a probe while the entries above were being
    // written may have taken a process for one not looked at yet.
    // SAFETY: `rt_gen` points into the object's mapped data (see `Attached`).
    unsafe { rt_gen.write_volatile(rt_gen.read_volatile().wrapping_add(1)) };
    Ok(Attached {
        rt_gen,
        notes,
        _links: links,
        probe_links: RefCell::new(probe_links),
        skel,
        _stats_fd: stats_fd,
        traced_at_start: traced.len(),
        table_bytes,
    })
}

/// A `--pid` must name a running process, not one of its threads: requests
/// are traced per process.
fn check_process(proc: &Path, pid: u32) -> Result<()> {
    let status = std::fs::read_to_string(proc.join(pid.to_string()).join("status"))
        .with_context(|| format!("--pid {pid}: no such process"))?;
    let tgid = status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .and_then(|value| value.trim().parse::<u32>().ok());
    match tgid {
        Some(tgid) if tgid != pid => {
            bail!("--pid {pid} is a thread of process {tgid}; pass the process id")
        }
        _ => Ok(()),
    }
}

/// Whether `release` (as in `/proc/sys/kernel/osrelease`) is at least `min`.
/// A release that cannot be read as `major.minor` is let through: the load
/// itself will say what is missing.
fn kernel_at_least(release: &str, min: (u32, u32)) -> bool {
    let mut parts = release
        .trim()
        .split(|c: char| !c.is_ascii_digit())
        .map(str::parse::<u32>);
    match (parts.next(), parts.next()) {
        (Some(Ok(major)), Some(Ok(minor))) => (major, minor) >= min,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_release_is_compared_by_major_and_minor() {
        assert!(kernel_at_least("6.8.0-147-generic\n", (5, 17)));
        assert!(kernel_at_least("5.17.0", (5, 17)));
        assert!(!kernel_at_least("5.15.0-91-generic", (5, 17)));
        assert!(!kernel_at_least("4.19.1", (5, 17)));
        // Unreadable: let the load decide.
        assert!(kernel_at_least("weird", (5, 17)));
    }

    #[test]
    fn a_pid_must_be_a_running_process() {
        let proc = std::env::temp_dir().join(format!("blame-pid-{}", std::process::id()));
        for (pid, tgid) in [(10, 10), (11, 10)] {
            let dir = proc.join(pid.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("status"),
                format!("Name:\tx\nTgid:\t{tgid}\nPid:\t{pid}\n"),
            )
            .unwrap();
        }
        assert!(check_process(&proc, 10).is_ok());
        let thread = check_process(&proc, 11).unwrap_err().to_string();
        assert!(thread.contains("thread of process 10"), "{thread}");
        assert!(check_process(&proc, 12).is_err());
        std::fs::remove_dir_all(&proc).unwrap();
    }
}
