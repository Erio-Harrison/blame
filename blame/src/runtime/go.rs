//! Go: the version is in the build info, which stripped binaries keep; the
//! kernel side then needs the offsets of a few fields of the runtime's `g`
//! and `m` for that version.
//!
//! A binary that serves gRPC with grpc-go gets three probes as well (see
//! `bpf/runtime/go_grpc.h`). The functions are found in the table the Go
//! runtime itself uses (`.gopclntab`), which stripping leaves in place; the
//! grpc-go version is in the build info, and with it where a stream keeps
//! its id.

use blame_common::{
    GRPC_ID_BEHIND_PTR, GRPC_ID_DIRECT, PROC_F_GO_EXECUTE, PROC_F_PARK, PROC_F_SPAWN, ProcCfg,
    RT_GO,
};

use super::{
    Inspected, Probe, ProbeAt,
    elf::{EM_AARCH64, Elf},
};

const GRPC_MODULE: &str = "google.golang.org/grpc";
const FN_EXECUTE: &str = "runtime.execute";
/// Where every goroutine is created (see `bpf/runtime/go_spawn.h`).
const FN_NEWPROC1: &str = "runtime.newproc1";
/// Where a goroutine parks, and why (see `bpf/runtime/go_park.h`).
const FN_GOPARK: &str = "runtime.gopark";
/// Where a goroutine that has returned leaves its thread (see `bpf/runtime/go_park.h`).
const FN_GOEXIT0: &str = "runtime.goexit0";

/// The Go minor versions whose runtime offsets and wait reasons are in the
/// tables below. Another version is followed by thread, with a warning.
const GO_MINORS: std::ops::RangeInclusive<u32> = 18..=27;
/// The grpc-go minor versions whose stream layout is in the table below.
const GRPC_MINORS: std::ops::RangeInclusive<u32> = 40..=85;

/// What each `waitReason` of a Go minor version is, one letter per value
/// from 0: c a channel, s a sync primitive (Mutex, RWMutex, Cond,
/// WaitGroup, semacquire), z asleep, n the network poller, g the garbage
/// collector or a stop of the world, o anything else. Read from the
/// `waitReason` constants and their strings in `runtime/runtime2.go` of the
/// latest patch release of each (the values move: `chan receive` is 14 up to
/// 1.25 and 19 from 1.26; up to 1.19 a sync.Mutex waits as `semacquire`, as
/// a WaitGroup does up to 1.23).
fn go_wait_reasons(minor: u32) -> Option<&'static str> {
    Some(match minor {
        18..=19 => "ognoogggocogggccogszsoogggo",
        20..=21 => "ognoogggocogggccogszssssoggggogg",
        22 => "ognoogggocogggccogszssssoggggogggoooo",
        23 => "ognoogggocogggccogszssssoggggogggoooog",
        24 => "ognoogggocogggccogszsssssoggggogggoooogooccc",
        25 => "ognoogggocogggccogoszsssssoggggogggoooogoocccso",
        26..=27 => "ogngggogggogoszooocccsssssoggggogggoooogoocccso",
        _ => return None,
    })
}

/// The kernel side's `enum park` for each wait reason of a Go minor version.
fn go_wait_kinds(minor: u32) -> Option<Vec<u8>> {
    let letters = go_wait_reasons(minor)?;
    Some(
        letters
            .bytes()
            .map(|letter| match letter {
                b'c' => 1,
                b's' => 2,
                b'z' => 3,
                b'n' => 4,
                b'g' => 5,
                _ => 6,
            })
            .collect(),
    )
}
const FN_ADD_CONN: &str = "google.golang.org/grpc.(*Server).addConn";
const FN_HANDLE_STREAM: &str = "google.golang.org/grpc.(*Server).handleStream";
const FN_OPERATE_HEADERS: &str =
    "google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders";
/// Spelled with a capital up to grpc-go 1.68.
const FN_WRITE_STATUS: [&str; 2] = [
    "google.golang.org/grpc/internal/transport.(*http2Server).writeStatus",
    "google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus",
];

const GO_BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";

/// The Go version a binary was built with, from its build info, which
/// stripped binaries keep. `Err` carries what was found instead.
fn go_version(buildinfo: &[u8]) -> Option<Result<String, String>> {
    if !buildinfo.starts_with(GO_BUILDINFO_MAGIC) || buildinfo.len() < 33 {
        return None;
    }
    // Before 1.18 the header held pointers to the strings, not the strings.
    if buildinfo[15] & 2 == 0 {
        return Some(Err("a Go older than 1.18".to_string()));
    }
    let (len, used) = uvarint(&buildinfo[32..])?;
    let text = buildinfo.get(32 + used..32 + used + len as usize)?;
    Some(Ok(String::from_utf8_lossy(text).into_owned()))
}

/// The module list that follows the version in the build info (`go version
/// -m` prints it), as text; empty if there is none.
fn go_modules(buildinfo: &[u8]) -> String {
    let list = || {
        let (len, used) = uvarint(buildinfo.get(32..)?)?;
        let at = 32 + used + len as usize;
        let (len, used) = uvarint(buildinfo.get(at..)?)?;
        buildinfo.get(at + used..at + used + len as usize)
    };
    String::from_utf8_lossy(list().unwrap_or_default()).into_owned()
}

/// The grpc-go a binary was built with: its version, and whether the module
/// was replaced by another source (`=>` on the next line), in which case the
/// version says nothing about the code.
fn grpc_module(modules: &str) -> Option<(String, bool)> {
    let mut lines = modules.lines();
    while let Some(line) = lines.next() {
        let mut fields = line.split('\t');
        if fields.next() == Some("dep") && fields.next() == Some(GRPC_MODULE) {
            let version = fields.next()?.to_string();
            let replaced = lines.next().is_some_and(|next| next.starts_with("=>"));
            return Some((version, replaced));
        }
    }
    None
}

/// `v1.72.3` -> 72.
fn grpc_minor(version: &str) -> Option<u32> {
    let rest = version.strip_prefix("v1.")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// How the HTTP/2 stream id is read behind the stream pointer that
/// `handleStream` is given: `(GRPC_ID_*, offset)`. Read from the debug
/// information of a server built with the latest patch release of every
/// minor version listed, and run under load on 1.40, 1.60, 1.68, 1.69, 1.72,
/// 1.76, 1.77 and 1.85. In all of them the stream pointer is the fourth
/// integer argument of `handleStream`, and the transport's data word the
/// fifth of `addConn`.
fn grpc_stream_id(minor: u32) -> Option<(u8, u16)> {
    match minor {
        // *transport.Stream, the id its first field.
        40..=68 => Some((GRPC_ID_DIRECT, 0)),
        // *transport.ServerStream, which starts with a *Stream.
        69..=76 => Some((GRPC_ID_BEHIND_PTR, 0)),
        // *transport.ServerStream, with the Stream inside it.
        77..=85 => Some((GRPC_ID_DIRECT, 108)),
        _ => None,
    }
}

/// Which argument register holds the decoded header frame in
/// `(*http2Server).operateHeaders` (0-based; the receiver is 0): 1.40 to 1.59
/// take `(frame, handle, traceCtx)`, 1.60 and later `(ctx, frame, handle)`,
/// the context being an interface and so two registers. Read from the
/// signatures of every release in that range, and run on 1.40, 1.60 and 1.85.
/// Where the fields are inside the frame is the same in all of them.
fn grpc_frame_arg(minor: u32) -> u8 {
    if minor < 60 { 1 } else { 3 }
}

fn u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
fn u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// Entry addresses of the named functions, from the Go function table
/// (the layout of Go 1.18 and later, 64-bit). `None` for one that is not
/// there, or all of them if the table is not understood.
fn go_functions<const N: usize>(elf: &Elf, names: [&str; N]) -> [Option<u64>; N] {
    let mut found = [None; N];
    let walked = walk_functions(elf, |name, addr| {
        for (slot, wanted) in found.iter_mut().zip(names) {
            if slot.is_none() && name == wanted.as_bytes() {
                *slot = Some(addr);
            }
        }
    });
    if walked.is_none() {
        return [None; N];
    }
    found
}

/// Where to probe the entry of the Go function at `addr`: the file offset of
/// the branch that ends its stack check, or of its first instruction if it
/// does not start with one this knows.
///
/// A uprobe makes the kernel run the instruction it replaces: a branch it
/// runs itself (~135 ns a hit, measured on arm64, kernel 6.8), any other
/// one is copied out and single-stepped (~700 ns). Nearly every Go function
/// starts with a load and a compare, then `b.ls` to grow the stack, and
/// none of those change what a probe reads: they write only R16, R17 and
/// the flags, while the arguments (R0..R15), g (R28), SP and LR are as at
/// the entry. A stack that is grown starts the function again, so the
/// branch is passed again, as the entry is. Two forms are taken, 99.7% of
/// the functions with a check in a Go 1.27 binary; the one of big frames
/// writes R27 as well and is left at the entry. arm64 only.
pub(crate) fn go_probe_offset(elf: &Elf, addr: u64) -> Option<u64> {
    elf.file_offset(addr + past_stack_check(elf, addr))
}

/// How far past `addr` the stack check's `b.ls` is, or 0.
fn past_stack_check(elf: &Elf, addr: u64) -> u64 {
    /// `ldr x16, [x28, #16]`: the stack guard of g.
    const LOAD_GUARD: u32 = 0xf940_0b90;
    /// `cmp sp, x16`.
    const CMP_SP: u32 = 0xeb30_63ff;
    /// `cmp x17, x16`.
    const CMP_X17: u32 = 0xeb10_023f;
    /// `sub x17, sp, #imm` (either shift), under its mask.
    const SUB_X17_SP: (u32, u32) = (0xff80_03ff, 0xd100_03f1);
    /// `b.ls`, under its mask.
    const B_LS: (u32, u32) = (0xff00_001f, 0x5400_0009);
    if elf.machine != EM_AARCH64 {
        return 0;
    }
    let Some(code) = elf.bytes_at(addr, 16) else {
        return 0;
    };
    let word = |i: usize| {
        u32::from_le_bytes([
            code[4 * i],
            code[4 * i + 1],
            code[4 * i + 2],
            code[4 * i + 3],
        ])
    };
    let b_ls = |w: u32| w & B_LS.0 == B_LS.1;
    if word(0) != LOAD_GUARD {
        return 0;
    }
    if word(1) == CMP_SP && b_ls(word(2)) {
        return 8;
    }
    if word(1) & SUB_X17_SP.0 == SUB_X17_SP.1 && word(2) == CMP_X17 && b_ls(word(3)) {
        return 12;
    }
    0
}

/// Where the functions `names` start and end (the next function's start),
/// from the Go function table, which stripping leaves in place. `None` for
/// one that is not there, or all of them if the table is not understood.
pub(crate) fn go_function_ranges<const N: usize>(
    elf: &Elf,
    names: [&str; N],
) -> [Option<(u64, u64)>; N] {
    let mut found = [None; N];
    let mut lookup = || -> Option<()> {
        let table = elf.section(".gopclntab")?;
        let magic = u32_le(table, 0)?;
        if !(magic == 0xffff_fff0 || magic == 0xffff_fff1) || *table.get(7)? != 8 {
            return None;
        }
        let count = u64_le(table, 8)? as usize;
        let text = match u64_le(table, 24)? {
            0 => elf.section_addr(".text")?,
            start => start,
        };
        let names_at = u64_le(table, 32)? as usize;
        let funcs_at = u64_le(table, 64)? as usize;
        // count entries of (entry, function), then the end of the last one.
        for i in 0..count {
            let entry = u32_le(table, funcs_at + 8 * i)?;
            let next = u32_le(table, funcs_at + 8 * (i + 1))?;
            let func = funcs_at + u32_le(table, funcs_at + 8 * i + 4)? as usize;
            let name_at = names_at + u32_le(table, func + 4)? as usize;
            let rest = table.get(name_at..)?;
            let name = &rest[..rest.iter().position(|b| *b == 0)?];
            for (slot, wanted) in found.iter_mut().zip(names) {
                if slot.is_none() && name == wanted.as_bytes() && next > entry {
                    *slot = Some((text + u64::from(entry), text + u64::from(next)));
                }
            }
        }
        Some(())
    };
    if lookup().is_none() {
        return [None; N];
    }
    found
}

/// Every function in the Go function table, by name and entry address.
/// `None` if the table is not understood.
fn walk_functions(elf: &Elf, mut visit: impl FnMut(&[u8], u64)) -> Option<()> {
    let mut lookup = || -> Option<()> {
        let table = elf.section(".gopclntab")?;
        let magic = u32_le(table, 0)?;
        if !(magic == 0xffff_fff0 || magic == 0xffff_fff1) || *table.get(7)? != 8 {
            return None;
        }
        let count = u64_le(table, 8)? as usize;
        let text = match u64_le(table, 24)? {
            0 => elf.section_addr(".text")?,
            start => start,
        };
        let names_at = u64_le(table, 32)? as usize;
        let funcs_at = u64_le(table, 64)? as usize;
        for i in 0..count {
            let entry = u32_le(table, funcs_at + 8 * i)?;
            let func = funcs_at + u32_le(table, funcs_at + 8 * i + 4)? as usize;
            let name_at = names_at + u32_le(table, func + 4)? as usize;
            let rest = table.get(name_at..)?;
            let name = &rest[..rest.iter().position(|b| *b == 0)?];
            visit(name, text + u64::from(entry));
        }
        Some(())
    };
    lookup()
}

/// What a grpc-go server in this binary adds to `cfg`: the probes, the
/// place of the stream id, and what to say. `None`: no grpc-go.
fn grpc(elf: &Elf, buildinfo: &[u8], cfg: ProcCfg) -> Option<(ProcCfg, Vec<Probe>, String)> {
    let (version, replaced) = grpc_module(&go_modules(buildinfo))?;
    let no = |why: &str| {
        Some((
            cfg,
            Vec::new(),
            format!("grpc-go {version}{why}: handlers not followed"),
        ))
    };
    if replaced {
        return no(" replaced by another source");
    }
    let Some((how, off)) = grpc_minor(&version).and_then(grpc_stream_id) else {
        return no(": not supported");
    };
    let addrs = go_functions(
        elf,
        [
            FN_EXECUTE,
            FN_ADD_CONN,
            FN_HANDLE_STREAM,
            FN_WRITE_STATUS[0],
            FN_WRITE_STATUS[1],
            FN_OPERATE_HEADERS,
        ],
    );
    let offsets = addrs.map(|addr| addr.and_then(|addr| go_probe_offset(elf, addr)));
    let [
        Some(execute),
        Some(conn),
        Some(handle),
        end,
        end_old,
        Some(headers),
    ] = offsets
    else {
        // A client-only binary has the module without the server.
        return no(": server functions not found");
    };
    let Some(end) = end.or(end_old) else {
        // A client-only binary has the module without the server.
        return no(": server functions not found");
    };
    let probes = vec![
        Probe {
            at: ProbeAt::GoExecute,
            offset: execute,
        },
        Probe {
            at: ProbeAt::GoGrpcConn,
            offset: conn,
        },
        Probe {
            at: ProbeAt::GoGrpcHandle,
            offset: handle,
        },
        Probe {
            at: ProbeAt::GoGrpcEnd,
            offset: end,
        },
        Probe {
            at: ProbeAt::GoGrpcHeaders,
            offset: headers,
        },
    ];
    let cfg = ProcCfg {
        grpc_id_how: how,
        grpc_id_off: off,
        grpc_frame_arg: grpc_minor(&version).map_or(0, grpc_frame_arg),
        ..cfg
    };
    Some((cfg, probes, format!("grpc-go {version}: handlers followed")))
}

fn uvarint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, byte) in bytes.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// `go1.24.13` -> 24. Development and patched builds (`devel ...`,
/// `go1.24.13-foo`) are taken at their minor version only if they start
/// like a release.
fn go_minor(version: &str) -> Option<u32> {
    let rest = version.strip_prefix("go1.")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Offsets into the Go runtime's `g` and `m` for a minor version. They are
/// not part of any interface and do move, so every minor version listed was
/// read from the debug information of a binary built with it (the latest
/// patch release, linux/arm64; the structs are the same on amd64). A version
/// that is not listed is not supported.
fn go_offsets(minor: u32) -> Option<ProcCfg> {
    let (g_goid, m_curg, m_gsignal) = match minor {
        18..=22 => (152, 192, 80),
        23..=24 => (160, 192, 80),
        25..=27 => (152, 184, 72),
        _ => return None,
    };
    Some(ProcCfg {
        runtime: RT_GO,
        go_g_m: 48,
        go_g_goid: g_goid,
        go_m_g0: 0,
        go_m_curg: m_curg,
        go_m_gsignal: m_gsignal,
        ..ProcCfg::default()
    })
}

/// Follow goroutines started for a request (`blame slow --spawned`): a
/// probe where goroutines are created, on entry and on return.
fn follow_spawned(elf: &Elf, minor: u32, found: &mut Inspected, plain_cfg: ProcCfg, plain: &str) {
    let [newproc] = go_functions(elf, [FN_NEWPROC1]);
    let note = found.note.get_or_insert_with(String::new);
    // The runtime's own goroutines: what the package `runtime` (not
    // `runtime/pprof` and the like) starts, also as closures.
    let mut runtime_starts = Vec::new();
    walk_functions(elf, |name, addr| {
        if name.starts_with(b"runtime.") {
            runtime_starts.push(addr);
        }
    });
    let Some(offset) = newproc.and_then(|addr| go_probe_offset(elf, addr)) else {
        note.push_str("; spawned goroutines not followed: runtime.newproc1 not found");
        return;
    };
    // Which goroutine a thread runs has to be known at every switch: a
    // handler that waits for what it spawned and resumes on the same thread
    // with no kernel event in between would otherwise get their CPU.
    let [execute] = go_functions(elf, [FN_EXECUTE]);
    let has_execute = found.probes.iter().any(|p| p.at == ProbeAt::GoExecute);
    let execute = match execute.and_then(|addr| go_probe_offset(elf, addr)) {
        Some(offset) => offset,
        None if has_execute => 0,
        None => {
            note.push_str("; spawned goroutines not followed: runtime.execute not found");
            return;
        }
    };
    note.push_str("; spawned goroutines followed");
    if !has_execute {
        found.probes.push(Probe {
            at: ProbeAt::GoExecute,
            offset: execute,
        });
    }
    found.probes.push(Probe {
        at: ProbeAt::GoSpawn,
        offset,
    });
    found.cfg.flags |= PROC_F_SPAWN;
    found.spawn_skip = newproc.into_iter().chain(runtime_starts).collect();
    // Why goroutines park: the reasons of this version must be known.
    let [gopark] = go_functions(elf, [FN_GOPARK]);
    match (
        gopark.and_then(|addr| go_probe_offset(elf, addr)),
        go_wait_kinds(minor),
    ) {
        (Some(offset), Some(kinds)) => {
            note.push_str("; why goroutines park followed");
            found.probes.push(Probe {
                at: ProbeAt::GoPark,
                offset,
            });
            found.cfg.flags |= PROC_F_PARK;
            found.go_wait_kinds = kinds;
        }
        (None, _) => note.push_str("; why goroutines park not followed: runtime.gopark not found"),
        (_, None) => {
            note.push_str(
                "; why goroutines park not followed: wait reasons of this version not known",
            );
            found.unsupported.push(format!(
                "the wait reasons of Go 1.{minor} are not known (1.{} to 1.{} are): why goroutines park is not shown",
                GO_MINORS.start(),
                GO_MINORS.end()
            ));
        }
    }
    // When a goroutine that has returned leaves its thread: exact with the probe,
    // known at the thread's next goroutine or sleep without it.
    let [goexit] = go_functions(elf, [FN_GOEXIT0]);
    if let Some(offset) = goexit.and_then(|addr| go_probe_offset(elf, addr)) {
        found.probes.push(Probe {
            at: ProbeAt::GoExit,
            offset,
        });
    }
    match &mut found.fallback {
        Some((_, why)) => why.push_str(", spawned goroutines not followed"),
        None => {
            found.fallback = Some((
                plain_cfg,
                format!("{plain}; probes could not be attached, spawned goroutines not followed"),
            ));
        }
    }
}

/// `None`: not a Go binary.
pub(super) fn inspect(elf: &Elf, spawned: bool) -> Option<Inspected> {
    let buildinfo = elf.section(".go.buildinfo")?;
    let version = match go_version(buildinfo)? {
        Ok(version) => version,
        Err(what) => {
            return Some(Inspected::unsupported(
                format!("{what}: not supported, thread-level"),
                format!(
                    "the Go version could not be read ({what}): requests are attributed by thread, not by goroutine"
                ),
            ));
        }
    };
    let Some(cfg) = go_minor(&version).and_then(go_offsets) else {
        return Some(Inspected::unsupported(
            format!("{version}: not supported, thread-level"),
            format!(
                "{version} is not one of the Go versions blame knows (1.{} to 1.{}): requests are attributed by thread, not by goroutine",
                GO_MINORS.start(),
                GO_MINORS.end()
            ),
        ));
    };
    let plain = format!("{version}: goroutine-level");
    let grpc_unknown = grpc_module(&go_modules(buildinfo))
        .filter(|(grpc_version, replaced)| {
            !replaced && grpc_minor(grpc_version).and_then(grpc_stream_id).is_none()
        })
        .map(|(grpc_version, _)| {
            format!(
                "grpc-go {grpc_version} is not one of the versions blame knows (1.{} to 1.{}): gRPC calls are not followed to their handlers, and have no time breakdown",
                GRPC_MINORS.start(),
                GRPC_MINORS.end()
            )
        });
    let mut found = match grpc(elf, buildinfo, cfg) {
        Some((with_grpc, probes, what)) if !probes.is_empty() => Inspected {
            cfg: with_grpc,
            note: Some(format!("{plain}; {what}")),
            probes,
            fallback: Some((
                cfg,
                format!("{plain}; grpc-go: probes could not be attached, handlers not followed"),
            )),
            spawn_skip: Vec::new(),
            go_wait_kinds: Vec::new(),
            http2_handlers: true,
            unsupported: Vec::new(),
        },
        Some((_, _, what)) => Inspected {
            cfg,
            note: Some(format!("{plain}; {what}")),
            probes: Vec::new(),
            fallback: None,
            spawn_skip: Vec::new(),
            go_wait_kinds: Vec::new(),
            http2_handlers: false,
            unsupported: Vec::new(),
        },
        None => Inspected {
            cfg,
            note: Some(plain.clone()),
            probes: Vec::new(),
            fallback: None,
            spawn_skip: Vec::new(),
            go_wait_kinds: Vec::new(),
            http2_handlers: false,
            unsupported: Vec::new(),
        },
    };
    found.unsupported.extend(grpc_unknown);
    // Which goroutine a thread runs is told by a probe where the scheduler
    // puts one on it. Without it, it is read at kernel events only, and a
    // goroutine that waits for another one and is run again on the same
    // thread before the next event gets the other's CPU (+64-90% of a
    // handler's CPU, measured, when it waits for goroutines it spawned).
    let [execute] = go_functions(elf, [FN_EXECUTE]);
    if !found.probes.iter().any(|p| p.at == ProbeAt::GoExecute)
        && let Some(offset) = execute.and_then(|addr| go_probe_offset(elf, addr))
    {
        found.probes.push(Probe {
            at: ProbeAt::GoExecute,
            offset,
        });
        if found.fallback.is_none() {
            let said = found.note.clone().unwrap_or_else(|| plain.clone());
            found.fallback = Some((
                cfg,
                format!(
                    "{said} (probes could not be attached: goroutine switches are inferred, and \
                     CPU can go to the wrong goroutine)"
                ),
            ));
        }
    }
    if spawned {
        follow_spawned(
            elf,
            go_minor(&version).unwrap_or(0),
            &mut found,
            cfg,
            &plain,
        );
    }
    // Set last, so that no fallback (without the probes) has it.
    if found.probes.iter().any(|p| p.at == ProbeAt::GoExecute) {
        found.cfg.flags |= PROC_F_GO_EXECUTE;
    }
    Some(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buildinfo(flags: u8, version: &str) -> Vec<u8> {
        let mut out = GO_BUILDINFO_MAGIC.to_vec();
        out.extend([8, flags]);
        out.resize(32, 0);
        out.push(version.len() as u8);
        out.extend(version.as_bytes());
        out
    }

    /// The ranges the warnings name are the tables' (a version added to a
    /// table without its range, or the other way round, fails here).
    #[test]
    fn the_known_versions_are_the_tables() {
        for minor in 0..60 {
            let known = GO_MINORS.contains(&minor);
            assert_eq!(go_offsets(minor).is_some(), known, "Go offsets, 1.{minor}");
            assert_eq!(
                go_wait_reasons(minor).is_some(),
                known,
                "Go wait reasons, 1.{minor}"
            );
        }
        for minor in 0..200 {
            assert_eq!(
                grpc_stream_id(minor).is_some(),
                GRPC_MINORS.contains(&minor),
                "grpc-go 1.{minor}"
            );
        }
    }

    #[test]
    fn the_decoded_frame_is_in_the_second_or_fourth_register() {
        assert_eq!(grpc_frame_arg(40), 1);
        assert_eq!(grpc_frame_arg(59), 1);
        assert_eq!(grpc_frame_arg(60), 3);
        assert_eq!(grpc_frame_arg(85), 3);
    }

    #[test]
    fn go_version_is_read_from_inline_build_info() {
        assert_eq!(
            go_version(&buildinfo(2, "go1.24.13")),
            Some(Ok("go1.24.13".to_string()))
        );
        // Pointer format, before 1.18.
        assert!(matches!(go_version(&buildinfo(0, "")), Some(Err(_))));
        assert_eq!(
            go_version(b"not build info at all, just bytes......."),
            None
        );
    }

    #[test]
    fn grpc_go_is_found_in_the_module_list_and_a_replaced_one_is_told_apart() {
        let plain = "path\tgx/server\nmod\tgx\t(devel)\t\ndep\tgolang.org/x/net\tv0.60.0\th1:x=\n\
                     dep\tgoogle.golang.org/grpc\tv1.85.0\th1:y=\ndep\tgoogle.golang.org/protobuf\tv1.36.12\th1:z=\n";
        assert_eq!(grpc_module(plain), Some(("v1.85.0".to_string(), false)));
        let replaced = "dep\tgoogle.golang.org/grpc\tv1.85.0\n=>\t../fork\t(devel)\t\n";
        assert_eq!(grpc_module(replaced), Some(("v1.85.0".to_string(), true)));
        assert_eq!(
            grpc_module("dep\tgoogle.golang.org/grpc/examples\tv0.0.0\th1:x=\n"),
            None
        );
        assert_eq!(grpc_module(""), None);
    }

    #[test]
    fn the_stream_id_is_read_as_measured_for_each_grpc_go_version() {
        let at = |version| grpc_minor(version).and_then(grpc_stream_id);
        assert_eq!(at("v1.40.1"), Some((GRPC_ID_DIRECT, 0)));
        assert_eq!(at("v1.68.2"), Some((GRPC_ID_DIRECT, 0)));
        assert_eq!(at("v1.69.4"), Some((GRPC_ID_BEHIND_PTR, 0)));
        assert_eq!(at("v1.76.0"), Some((GRPC_ID_BEHIND_PTR, 0)));
        assert_eq!(at("v1.77.0"), Some((GRPC_ID_DIRECT, 108)));
        assert_eq!(at("v1.85.0"), Some((GRPC_ID_DIRECT, 108)));
        assert_eq!(at("v1.39.0"), None);
        assert_eq!(at("v1.86.0"), None);
        assert_eq!(at("v2.0.0"), None);
    }

    #[test]
    fn only_go_versions_that_were_looked_at_get_offsets() {
        assert_eq!(go_minor("go1.27.4"), Some(27));
        assert_eq!(go_minor("go1.22"), Some(22));
        assert_eq!(go_minor("devel +abc"), None);
        let offsets = |minor| go_offsets(minor).map(|c| (c.go_g_goid, c.go_m_curg));
        assert_eq!(offsets(22), Some((152, 192)));
        assert_eq!(offsets(24), Some((160, 192)));
        assert_eq!(offsets(25), Some((152, 184)));
        assert_eq!(offsets(27), Some((152, 184)));
        assert_eq!(go_offsets(17), None);
        assert_eq!(go_offsets(28), None);
    }

    /// The go command of this machine's toolchain, if there is one: the
    /// runtime functions probed are probed at their stack check's b.ls, and
    /// a function without the check (assembly, no frame) at its entry.
    #[test]
    fn go_entries_are_probed_past_the_stack_check() {
        let Ok(go) = std::process::Command::new("go")
            .args(["env", "GOROOT"])
            .output()
        else {
            return;
        };
        let root = String::from_utf8_lossy(&go.stdout).trim().to_owned();
        let image = std::fs::read(std::path::Path::new(&root).join("bin/go")).expect("read");
        let elf = Elf::parse(&image).expect("ELF");
        let found = go_functions(
            &elf,
            [
                FN_EXECUTE,
                FN_NEWPROC1,
                FN_GOPARK,
                FN_GOEXIT0,
                "runtime.gogo.abi0",
            ],
        );
        let word = |addr: u64| {
            let at = elf.file_offset(addr).expect("in the file") as usize;
            u32::from_le_bytes(image[at..at + 4].try_into().unwrap())
        };
        for addr in &found[..4] {
            let addr = addr.expect("runtime function");
            let at = go_probe_offset(&elf, addr).expect("offset");
            if elf.machine != EM_AARCH64 {
                assert_eq!(Some(at), elf.file_offset(addr));
                continue;
            }
            assert!(at > elf.file_offset(addr).unwrap());
            let at = at as usize;
            let w = u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
            assert_eq!(w & 0xff00_001f, 0x5400_0009, "{addr:#x}");
        }
        let gogo = found[4].expect("runtime.gogo");
        assert_ne!(word(gogo), 0xf940_0b90);
        assert_eq!(go_probe_offset(&elf, gogo), elf.file_offset(gogo));
    }
}
