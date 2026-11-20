//! Loading the kernel side, and finding out about each traced process:
//! its runtime, the probes its attribution needs, what to tell the user.

use std::{
    cell::RefCell, collections::HashSet, os::fd::OwnedFd, path::Path, ptr::NonNull, sync::OnceLock,
};

use anyhow::{Context as _, Result, bail};
use blame_common::ProcCfg;
use libbpf_rs::{
    AsRawLibbpf as _, Link, MapCore, MapFlags,
    skel::{OpenSkel as _, Skel as _},
};

use crate::{
    bpf::{self, Skel},
    json, procfs,
    runtime::{self, Inspected, Probe, ProbeAt},
};

use super::SlowOpt;

/// The request programs all carry this prefix.
pub(super) const PROGRAM_PREFIX: &str = "req_";

/// Programs attached to functions of a traced process's binary carry this
/// one: loaded with the rest, attached per process (`attach_probes`).
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

/// What was found out about one traced process, for the user.
pub(super) struct ProcessNote {
    pid: u32,
    /// What its requests' time is attributed by.
    units: &'static str,
    /// Probes that find the handler of each HTTP/2 stream are attached.
    http2_handlers_followed: bool,
    note: Option<String>,
    /// Versions blame does not know (`Inspected::unsupported`).
    unsupported: Vec<String>,
}

impl ProcessNote {
    pub(super) fn of(pid: u32, found: &Inspected) -> Self {
        Self {
            pid,
            units: match found.cfg.runtime {
                blame_common::RT_GO => "goroutine",
                blame_common::RT_TOKIO => "task",
                _ => "thread",
            },
            http2_handlers_followed: found.http2_handlers,
            note: found.note.clone(),
            unsupported: found.unsupported.clone(),
        }
    }

    /// Tell the user: a line, or a record. Plain threaded processes with
    /// nothing to say are only mentioned as records.
    pub(super) fn print(&self, opt: &SlowOpt) {
        // On stderr in both modes: easy to miss among the records otherwise.
        for warning in &self.unsupported {
            eprintln!("blame: warning: pid {}: {warning}", self.pid);
        }
        if opt.json {
            println!(
                "{}",
                json::process(
                    self.pid,
                    self.units,
                    self.http2_handlers_followed,
                    self.note.as_deref(),
                    &self.unsupported
                )
            );
        } else if let Some(note) = &self.note {
            println!("blame: pid {}: {note}", self.pid);
        }
    }
}

fn is_request_program(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().starts_with(PROGRAM_PREFIX)
}

/// The programs on the functions where a thread waits for a file service
/// (`bpf/request/fsvc.h`): `req_fsvc_<function>` at entry, `req_fsvcx_<function>`
/// at return. Attached by `attach_fsvc`, before the other request programs.
const FSVC_PREFIX: &str = "req_fsvc";

/// The kernel function a file-service program is on.
fn fsvc_function(name: &str) -> Option<&str> {
    name.strip_prefix("req_fsvcx_")
        .or_else(|| name.strip_prefix("req_fsvc_"))
}

/// The module a file-service function is in, when not in the kernel proper.
/// An fentry program on a function of a module that is not loaded does not
/// load, so it is left out; the module's waits are then counted as the
/// kernel marks them.
fn fsvc_module(function: &str) -> Option<&'static str> {
    if function.starts_with("rpc_") {
        Some("sunrpc")
    } else if function.starts_with("nfs_") {
        Some("nfs")
    } else if function.starts_with("fuse_") || function == "request_wait_answer" {
        Some("fuse")
    } else if function.starts_with("cifs_") {
        Some("cifs")
    } else if function.starts_with("v9fs_") {
        Some("9p")
    } else if function.starts_with("ceph_") {
        Some("ceph")
    } else {
        None
    }
}

/// Whether a file-service program on `function` can load: its function is
/// one ftrace can hook. A static function the compiler inlined into all its
/// callers has no entry of its own, in a loaded module too (WSL2's 6.6 for
/// x86-64: sunrpc's rpc_wait_bit_killable and nfs's nfs_direct_wait), and a
/// program on it fails the load of every file-service program.
///
/// Without ftrace's list (tracefs is not mounted in a container unless it
/// is given), the function must be in the kernel's symbols, which an
/// inlined one is not. Not its BTF: rpc_wait_bit_killable has an entry in
/// sunrpc's, and no code. Without either, its module must be loaded.
fn fsvc_present(function: &str) -> bool {
    if let Some(traceable) = traceable_functions() {
        return traceable.contains(function);
    }
    if let Some(symbols) = kernel_functions() {
        return symbols.contains(function);
    }
    fsvc_module(function).is_none_or(|module| Path::new("/sys/module").join(module).exists())
}

/// The kernel's functions, loaded modules' included (`/proc/kallsyms`, its
/// text symbols); read once. `None` if it cannot be read.
fn kernel_functions() -> Option<&'static HashSet<String>> {
    static FUNCTIONS: OnceLock<Option<HashSet<String>>> = OnceLock::new();
    FUNCTIONS
        .get_or_init(|| {
            std::fs::read_to_string("/proc/kallsyms")
                .ok()
                .map(|text| kallsyms_functions(&text))
        })
        .as_ref()
}

/// The text symbols in the text of `/proc/kallsyms`: `address type name`,
/// and a module's tab-separated `[module]` after.
fn kallsyms_functions(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (_, kind, name) = (fields.next()?, fields.next()?, fields.next()?);
            matches!(kind, "t" | "T").then(|| name.to_string())
        })
        .collect()
}

/// The functions ftrace can hook now (`available_filter_functions`), loaded
/// modules' included; read once. `None` if tracefs cannot be read.
fn traceable_functions() -> Option<&'static HashSet<String>> {
    static TRACEABLE: OnceLock<Option<HashSet<String>>> = OnceLock::new();
    TRACEABLE
        .get_or_init(|| {
            ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
                .iter()
                .find_map(|dir| {
                    std::fs::read_to_string(Path::new(dir).join("available_filter_functions")).ok()
                })
                .map(|text| filter_functions(&text))
        })
        .as_ref()
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

/// The names in the text of `available_filter_functions`: one a line, a
/// module's followed by `[module]`.
fn filter_functions(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Attach programs all at once, a thread each. One after the other, the
/// first fentry or fexit program on each function takes some 110 ms (the
/// file-service hooks: about 1.2 s); together, some 150 ms (355 ms with a
/// busy process traced). Each program's own error, or its link.
fn attach_together(
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
fn attach_rank(name: &str, program: NonNull<libbpf_sys::bpf_program>) -> u8 {
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
fn loaded(
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

/// Attach the file-service programs that were loaded. Without any, such
/// waits are counted as the kernel marks them (disk, or other): said on
/// stderr, and the rest goes on.
fn attach_fsvc(skel: &Skel) -> Vec<Link> {
    let mut links = Vec::new();
    let mut last_err = None;
    // Returns before entries (see `attach_rank`), each kind together.
    let (returns, entries): (Vec<_>, Vec<_>) = loaded(skel, |name| name.starts_with(FSVC_PREFIX))
        .into_iter()
        .partition(|(name, program)| attach_rank(name, *program) == 0);
    let attached = attach_together(returns)
        .into_iter()
        .chain(attach_together(entries));
    for (name, link) in attached {
        match link {
            Ok(link) => links.push(link),
            Err(err) => last_err = Some(format!("{name}: {err}")),
        }
    }
    if links.is_empty() || last_err.is_some() {
        eprintln!(
            "blame: waits for a file service (NFS, FUSE, ...) are not all told apart from disk \
             waits: {}",
            last_err.unwrap_or_else(|| "no function to hook".into())
        );
    }
    links
}

fn is_probe_program(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().starts_with(PROBE_PREFIX)
}

/// Attach the probes a process's attribution relies on: all of them, or
/// none. The binary is reached through `/proc/<pid>/exe`, which works in
/// whatever mount namespace it lives.
fn attach_probes(skel: &Skel, pid: u32, probes: &[Probe]) -> Result<Vec<Link>> {
    let binary = format!("/proc/{pid}/exe");
    let mut links = Vec::new();
    for probe in probes {
        let offset = usize::try_from(probe.offset).context("probe offset")?;
        let mut at = |program: &libbpf_rs::ProgramMut<'_>, ret: bool| -> Result<()> {
            links.push(
                program
                    .attach_uprobe(ret, pid as i32, &binary, offset)
                    .with_context(|| format!("probe {:?} at {offset:#x}", probe.at))?,
            );
            Ok(())
        };
        let progs = &skel.progs;
        match probe.at {
            ProbeAt::GoExecute => at(&progs.up_go_execute, false)?,
            ProbeAt::GoGrpcConn => at(&progs.up_go_grpc_conn, false)?,
            ProbeAt::GoGrpcHandle => at(&progs.up_go_grpc_handle, false)?,
            ProbeAt::GoGrpcEnd => at(&progs.up_go_grpc_end, false)?,
            ProbeAt::GoGrpcHeaders => at(&progs.up_go_grpc_headers, false)?,
            ProbeAt::TokioSpawn => at(&progs.up_tokio_spawn, false)?,
            ProbeAt::TokioSpawnBlocking => at(&progs.up_tokio_spawn_blocking, false)?,
            ProbeAt::GoPark => at(&progs.up_go_park, false)?,
            ProbeAt::GoExit => at(&progs.up_go_exit, false)?,
            ProbeAt::GoSpawn => {
                at(&progs.up_go_newproc, false)?;
                at(&progs.up_go_newproc_ret, true)?;
            }
            ProbeAt::RsRecvHeaders => at(&progs.up_rs_recv_headers, false)?,
            ProbeAt::RsSend => at(&progs.up_rs_send, false)?,
            ProbeAt::TokioPoll => {
                at(&progs.up_tokio_poll, false)?;
                at(&progs.up_tokio_poll_ret, true)?;
            }
            ProbeAt::TokioPollBlocking => {
                at(&progs.up_tokio_poll_blocking, false)?;
                at(&progs.up_tokio_poll_blocking_ret, true)?;
            }
            ProbeAt::TokioWake => at(&progs.up_tokio_wake, false)?,
            ProbeAt::TokioIoTurn => {
                at(&progs.up_tokio_io_turn, false)?;
                at(&progs.up_tokio_io_turn_ret, true)?;
            }
            ProbeAt::TokioTimers => {
                at(&progs.up_tokio_timers, false)?;
                at(&progs.up_tokio_timers_ret, true)?;
            }
        }
    }
    Ok(links)
}

/// Look at a process and attach what its attribution needs. If the probes
/// cannot be attached, the process is attributed without them.
/// The most open files the agent asks for. Every probe in a process is a
/// link that holds a file descriptor: tokio's `poll` has one instance per
/// task type, 278 of them in Qdrant, entry and return each, so the usual soft
/// limit of 1024 is not enough for a big binary.
const OPEN_FILES_WANTED: libc::rlim_t = 1 << 20;

/// Raise the soft limit on open files to what the hard limit allows (up to
/// `OPEN_FILES_WANTED`). Returns the limit in force afterwards.
pub(super) fn raise_open_files_limit() -> libc::rlim_t {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit for the calls to write and read.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return 0;
        }
        let wanted = limit.rlim_max.min(OPEN_FILES_WANTED);
        if limit.rlim_cur < wanted {
            let raised = libc::rlimit {
                rlim_cur: wanted,
                rlim_max: limit.rlim_max,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &raised) == 0 {
                limit.rlim_cur = wanted;
            }
        }
    }
    limit.rlim_cur
}

/// What to add to a failure to attach: too many open files is the one a user
/// can do something about.
fn attach_hint(err: &str) -> &'static str {
    if err.contains("Too many open files") {
        " (the limit on open files is too low for this binary: raise it with `ulimit -n`, as root also the hard limit)"
    } else {
        ""
    }
}

/// With `--deep`, in a process attributed by thread that has loaded GNU's
/// OpenMP runtime: probes where it opens parallel regions, so that the
/// threads of a team that take up a request's work are followed
/// (`bpf/runtime/omp.h`). All of them, or none.
fn follow_openmp(skel: &Skel, opt: &SlowOpt, pid: u32, found: &mut Inspected) -> Vec<Link> {
    if !opt.deep || found.cfg != ProcCfg::threads() || found.note.is_some() {
        return Vec::new();
    }
    let proc = Path::new("/proc");
    let Some(lib) = runtime::omp::libgomp(proc, pid) else {
        return Vec::new();
    };
    let file = runtime::omp::file_of(proc, pid, &lib.path);
    let mut links = Vec::new();
    for offset in &lib.entries {
        let Ok(offset) = usize::try_from(*offset) else {
            return Vec::new();
        };
        let progs = &skel.progs;
        for (program, ret) in [
            (&progs.up_omp_parallel, false),
            (&progs.up_omp_parallel_ret, true),
        ] {
            match program.attach_uprobe(ret, pid as i32, &file, offset) {
                Ok(link) => links.push(link),
                Err(err) => {
                    let text = format!("{err:#}");
                    eprintln!(
                        "blame: pid {pid}: OpenMP teams not followed: probe in {} at {offset:#x}: {text}{}",
                        lib.path,
                        attach_hint(&text)
                    );
                    return Vec::new();
                }
            }
        }
    }
    found.note = Some(
        "OpenMP (libgomp): the threads that take up a request's parallel work are followed"
            .to_owned(),
    );
    links
}

/// Functions of parallel regions the kernel side has seen run for a request
/// and that have no probes yet: put them there, and say so. A function is
/// known by its address in the process only.
pub(super) fn follow_openmp_functions(attached: &Attached) {
    let fns = &attached.skel.maps.OMP_FNS;
    let proc = Path::new("/proc");
    for key in fns.keys() {
        // OMP_FN_NEW.
        if !matches!(fns.lookup(&key, MapFlags::ANY), Ok(Some(value)) if value.first() == Some(&0))
        {
            continue;
        }
        let (Some(addr), Some(pid)) = (
            key.get(..8)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_ne_bytes),
            key.get(8..12)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_ne_bytes),
        ) else {
            continue;
        };
        let progs = &attached.skel.progs;
        let attach = || -> Result<Vec<Link>> {
            let (path, offset) = runtime::omp::locate(proc, pid, addr)
                .with_context(|| format!("{addr:#x} is in no file the process maps"))?;
            let file = runtime::omp::file_of(proc, pid, &path);
            let offset = usize::try_from(offset).context("probe offset")?;
            Ok(vec![
                progs
                    .up_omp_fn_ret
                    .attach_uprobe(true, pid as i32, &file, offset)
                    .with_context(|| format!("probe in {path} at {offset:#x}"))?,
                progs
                    .up_omp_fn
                    .attach_uprobe(false, pid as i32, &file, offset)
                    .with_context(|| format!("probe in {path} at {offset:#x}"))?,
            ])
        };
        // OMP_FN_PROBED, or OMP_FN_FAILED.
        let state = match attach() {
            Ok(links) => {
                attached.probe_links.borrow_mut().extend(links);
                1u8
            }
            Err(err) => {
                let text = format!("{err:#}");
                eprintln!(
                    "blame: pid {pid}: an OpenMP region's function is not followed: {text}{}",
                    attach_hint(&text)
                );
                2u8
            }
        };
        // The process may be gone: then there is nothing to tell.
        let _ = fns.update(&key, &[state], MapFlags::EXIST);
    }
}

fn inspect_and_attach(skel: &Skel, opt: &SlowOpt, pid: u32) -> (Inspected, Vec<Link>) {
    let mut found = inspect(opt, pid);
    if found.probes.is_empty() {
        let links = follow_openmp(skel, opt, pid, &mut found);
        return (found, links);
    }
    // The tables the probes look things up in go first: a probe that fires
    // before they are there would take the runtime's own goroutines for a
    // request's, or every park for one of another kind.
    if let Err(err) = write_spawn_skip(skel, pid, &found.spawn_skip)
        .and_then(|()| write_go_wait_kinds(skel, pid, &found.go_wait_kinds))
        && let Some(note) = &mut found.note
    {
        note.push_str(&format!(" (tables not written, so not exact: {err:#})"));
    }
    match attach_probes(skel, pid, &found.probes) {
        Ok(links) => (found, links),
        Err(err) => {
            let text = format!("{err:#}");
            eprintln!("blame: pid {pid}: {text}{}", attach_hint(&text));
            (found.without_probes(), Vec::new())
        }
    }
}

/// Tell the kernel side what each Go wait reason of `pid` is.
fn write_go_wait_kinds(skel: &Skel, pid: u32, kinds: &[u8]) -> Result<()> {
    for (reason, &kind) in kinds.iter().enumerate() {
        let mut key = [0u8; 8];
        key[..4].copy_from_slice(&pid.to_ne_bytes());
        key[4..].copy_from_slice(&(reason as u32).to_ne_bytes());
        skel.maps
            .GO_WAIT_KIND
            .update(&key, &[kind], MapFlags::ANY)
            .context("the table of Go wait reasons is full")?;
    }
    Ok(())
}

/// Tell the kernel side which goroutine starts of `pid` are the runtime's
/// own (see [`runtime::Inspected::spawn_skip`]).
fn write_spawn_skip(skel: &Skel, pid: u32, skip: &[u64]) -> Result<()> {
    let Some((&newproc, starts)) = skip.split_first() else {
        return Ok(());
    };
    for &addr in starts {
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&addr.to_ne_bytes());
        key[8..12].copy_from_slice(&pid.to_ne_bytes());
        skel.maps
            .SPAWN_SKIP
            .update(&key, &[1], MapFlags::ANY)
            .context("the table of the runtime's goroutines is full")?;
    }
    skel.maps
        .SPAWN_BASE
        .update(&pid.to_ne_bytes(), &newproc.to_ne_bytes(), MapFlags::ANY)
        .context("SPAWN_BASE")?;
    Ok(())
}

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
    let mut notes = Vec::new();
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
            notes.push(ProcessNote::of(*pid, &found));
        }
    }
    // The scheduler hook passes over threads of processes without a bit here.
    let bits = skel
        .maps
        .bss_data
        .as_deref_mut()
        .context("the eBPF object has no zero-initialised data")?;
    for note in &notes {
        let bit = note.pid as usize % (bits.proc_bits.len() * 64);
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

fn inspect(opt: &SlowOpt, pid: u32) -> Inspected {
    if opt.threads_only {
        Inspected {
            cfg: ProcCfg::threads(),
            note: None,
            probes: Vec::new(),
            fallback: None,
            spawn_skip: Vec::new(),
            go_wait_kinds: Vec::new(),
            http2_handlers: false,
            unsupported: Vec::new(),
        }
    } else {
        runtime::inspect(Path::new("/proc"), pid, opt.deep)
    }
}

/// Processes the kernel side started tracing on its own (they accepted a
/// connection) have not been looked at: do that, and tell the kernel side.
pub(super) fn inspect_new_processes(attached: &Attached, opt: &SlowOpt) {
    let procs = &attached.skel.maps.REQ_PROCS;
    let mut changed = false;
    for key in procs.keys() {
        let Ok(Some(value)) = procs.lookup(&key, MapFlags::ANY) else {
            continue;
        };
        // Byte 0 is the runtime; 0 = not looked at.
        if value.first() != Some(&0) {
            continue;
        }
        let Ok(pid) = key.as_slice().try_into().map(u32::from_ne_bytes) else {
            continue;
        };
        let (found, links) = inspect_and_attach(&attached.skel, opt, pid);
        attached.probe_links.borrow_mut().extend(links);
        // Only if the process is still there: it may have exited meanwhile.
        if procs
            .update(&key, &found.cfg.to_bytes(), MapFlags::EXIST)
            .is_ok()
        {
            changed = true;
            ProcessNote::of(pid, &found).print(opt);
        }
    }
    if changed {
        // SAFETY: points into the object's mapped data, which lives as long
        // as the process; the kernel side only reads it.
        unsafe {
            attached
                .rt_gen
                .write_volatile(attached.rt_gen.read_volatile().wrapping_add(1))
        };
    }
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
    fn traceable_functions_are_read_with_their_modules_left_off() {
        let text = "filemap_fault\nnfs_file_read [nfs]\nrpc_exit_task [sunrpc]\n";
        let names = filter_functions(text);
        assert!(names.contains("filemap_fault"));
        assert!(names.contains("nfs_file_read"));
        // Inlined into its callers: not in the list, not hooked.
        assert!(!names.contains("rpc_wait_bit_killable"));
        assert!(!names.contains("[nfs]"));
    }

    #[test]
    fn kernel_functions_are_the_text_symbols() {
        let text = "ffffffffa4357ff0 T filemap_fault\n\
                    ffffffffc0a1b2c0 t nfs_file_read\t[nfs]\n\
                    ffffffffa5000000 D jiffies\n";
        let names = kallsyms_functions(text);
        assert!(names.contains("filemap_fault"));
        assert!(names.contains("nfs_file_read"));
        assert!(!names.contains("jiffies"));
        assert!(!names.contains("rpc_wait_bit_killable"));
    }

    #[test]
    fn the_open_files_limit_is_raised_as_far_as_it_may_be() {
        let now = raise_open_files_limit();
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid rlimit to write.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        assert_eq!(limit.rlim_cur, now);
        assert_eq!(limit.rlim_cur, limit.rlim_max.min(OPEN_FILES_WANTED));
        // Asking again changes nothing.
        assert_eq!(raise_open_files_limit(), now);
    }

    #[test]
    fn a_failure_for_too_many_open_files_says_what_to_do() {
        assert!(
            attach_hint(
                "probe TokioPoll at 0x1: failed to attach uprobe: Too many open files (os error 24)"
            )
            .contains("ulimit -n")
        );
        assert_eq!(attach_hint("probe TokioPoll at 0x1: no such file"), "");
    }

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
