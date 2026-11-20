//! tokio: the id of the task being polled is in the `CONTEXT` thread-local.
//! Its place comes from the symbol table and the TLS segment, the layout
//! from the tokio version, which panic locations spell out.
//!
//! A binary that also has the `h2` crate in it (an HTTP/2 server such as
//! tonic's) gets probes on tokio's poll and spawn functions (see
//! `bpf/runtime/tokio_tasks.h`): hyper serves every stream in a task of its
//! own, and those tasks touch no socket.

use blame_common::{
    PROC_F_PARK, PROC_F_SPAWN, PROC_F_TOKIO_BLOCKING, PROC_F_UNIT_PROBES, ProcCfg, RT_TOKIO,
};

use super::{
    Inspected, Probe, ProbeAt,
    elf::{Elf, TlsSegment, find},
};

/// The probes for following tasks, if the binary has everything they need:
/// the `h2` crate, the functions every task is polled through, and the
/// function that registers a spawned task (one per scheduler flavour).
fn task_probes(elf: &Elf) -> Vec<Probe> {
    let at = |probe, parts: &[&str]| -> Vec<Probe> {
        elf.functions(parts)
            .into_iter()
            .filter_map(|addr| elf.file_offset(addr))
            .map(|offset| Probe { at: probe, offset })
            .collect()
    };
    // Both manglings spell the path as length-prefixed names. The blocking
    // pool's tasks have poll functions of their own kind of task.
    let poll_fns = |blocking: bool| -> Vec<Probe> {
        elf.functions_where(|name| {
            find(name, b"5tokio").is_some()
                && find(name, b"4task3raw4poll").is_some()
                && find(name, b"12BlockingTask").is_some() == blocking
        })
        .into_iter()
        .filter_map(|addr| elf.file_offset(addr))
        .map(|offset| Probe {
            at: if blocking {
                ProbeAt::TokioPollBlocking
            } else {
                ProbeAt::TokioPoll
            },
            offset,
        })
        .collect()
    };
    let mut polls = poll_fns(false);
    polls.extend(poll_fns(true));
    let spawns = at(
        ProbeAt::TokioSpawn,
        &["5tokio", "OwnedTasks", "10bind_inner"],
    );
    if polls.is_empty() || spawns.is_empty() {
        return Vec::new();
    }
    polls.into_iter().chain(spawns).collect()
}

/// What tells why a task waits (`bpf/runtime/tokio_tasks.h`): where each
/// scheduler puts a woken task back on a run queue (the multi-thread one's
/// `Handle::schedule_task`, the current-thread one's `Schedule::schedule`,
/// both with the task the second argument), the I/O driver's turn and the
/// time driver's firing of timers. At least one of the first two and both
/// of the others, or none; and for which runtimes.
///
/// The multi-thread `Schedule::schedule` and `Schedule::yield_now` only jump
/// to `schedule_task`, the task left where it is. A build can inline
/// `schedule_task` into them and leave no function of that name (the shop
/// demo's gateway did once it used `tokio::fs`); then those two are probed
/// instead. Never both: a wake would count twice.
fn wake_probes(elf: &Elf) -> (Vec<Probe>, &'static str) {
    // A function of its own, not generic: in the v0 mangling a plain path
    // (`_RNv`), so neither a closure in it (`_RNC`), an instance of a
    // generic function whose type arguments spell the path (an LTO build
    // has drop glue that does), nor `with_scheduler`'s instance for it.
    // The name is any one of a list of spellings: a method of a trait impl
    // is spelled one way in each mangling (see `impl_method`).
    let one = |at: ProbeAt, spellings: &[Vec<Vec<u8>>]| -> Option<Probe> {
        let found = elf.functions_where(|name| {
            spellings
                .iter()
                .any(|parts| parts.iter().all(|part| find(name, part).is_some()))
                && (name.starts_with(b"_RNv") || !name.starts_with(b"_R"))
                && find(name, b"closure").is_none()
                && find(name, b"drop_in_place").is_none()
        });
        match found.as_slice() {
            [addr] => elf.file_offset(*addr).map(|offset| Probe { at, offset }),
            _ => None,
        }
    };
    let multi: Option<Vec<Probe>> = match one(
        ProbeAt::TokioWake,
        &[path(&[
            b"5tokio",
            b"12multi_thread",
            b"6worker",
            b"13schedule_task",
        ])],
    ) {
        Some(probe) => Some(vec![probe]),
        None => [b"8schedule".as_slice(), b"9yield_now"]
            .iter()
            .map(|name| {
                one(
                    ProbeAt::TokioWake,
                    &impl_method(
                        b"12multi_thread",
                        &[b"6Handle"],
                        b"multi_thread..handle..Handle",
                        name,
                    ),
                )
            })
            .collect(),
    };
    let current = one(
        ProbeAt::TokioWake,
        &impl_method(
            b"14current_thread",
            &[],
            b"current_thread..Handle",
            b"8schedule",
        ),
    );
    let io = one(
        ProbeAt::TokioIoTurn,
        &[path(&[b"5tokio", b"2io", b"6driver", b"6Driver", b"4turn"])],
    );
    let timers = one(
        ProbeAt::TokioTimers,
        &[path(&[b"5tokio", b"4time", b"15process_at_time"])],
    );
    let which = match (&multi, &current) {
        (Some(_), Some(_)) => "multi-thread and current-thread runtimes",
        (Some(_), None) => "multi-thread runtimes",
        (None, Some(_)) => "current-thread runtimes",
        (None, None) => return (Vec::new(), ""),
    };
    match (io, timers) {
        (Some(io), Some(timers)) => (
            multi
                .into_iter()
                .flatten()
                .chain([current, Some(io), Some(timers)].into_iter().flatten())
                .collect(),
            which,
        ),
        _ => (Vec::new(), ""),
    }
}

/// A name spelled the same in both manglings: length-prefixed parts.
fn path(parts: &[&[u8]]) -> Vec<Vec<u8>> {
    parts.iter().map(|part| part.to_vec()).collect()
}

/// How a method of tokio's `impl task::Schedule for Arc<Handle>` in the
/// scheduler module `module` is spelled, in each mangling.
///
/// v0 names the impl's self type and the trait as paths, each part
/// length-prefixed (`6Handle`, `8Schedule`; `self_v0` the parts of the self
/// type past the module). The legacy mangling spells the whole impl as one
/// part, `<impl tokio::runtime::task::Schedule for alloc::sync::Arc<...>>`
/// with its punctuation escaped, so neither has a prefix there; the
/// self type is `self_legacy` inside it, closed by the two `>`. In both the
/// method keeps its prefix (`8schedule`).
fn impl_method<'a>(
    module: &'a [u8],
    self_v0: &[&'a [u8]],
    self_legacy: &'a [u8],
    method: &'a [u8],
) -> [Vec<Vec<u8>>; 2] {
    let mut v0: Vec<Vec<u8>> = vec![b"5tokio".to_vec(), module.to_vec()];
    v0.extend(self_v0.iter().map(|part| part.to_vec()));
    v0.extend([b"8Schedule".to_vec(), method.to_vec()]);
    let mut legacy_self = self_legacy.to_vec();
    legacy_self.extend_from_slice(b"$GT$$GT$");
    let legacy = vec![
        b"5tokio".to_vec(),
        module.to_vec(),
        b"$LT$impl$u20$tokio..runtime..task..Schedule$u20$for$u20$".to_vec(),
        legacy_self,
        method.to_vec(),
    ];
    [v0, legacy]
}

/// Where closures given to `spawn_blocking` become tasks:
/// `blocking::pool::Spawner::spawn_task`, the new task's header its second
/// argument (seen in the code of 1.54 at every call: the pointer `Cell::new`
/// returned). Not the generic `ShardedImpl::spawn_task` it calls, whose
/// mangled name spells the same path in its type arguments.
fn blocking_spawns(elf: &Elf) -> Vec<Probe> {
    elf.functions_where(|name| {
        [
            &b"5tokio"[..],
            b"8blocking",
            b"4pool",
            b"7Spawner",
            b"10spawn_task",
        ]
        .iter()
        .all(|part| find(name, part).is_some())
            && find(name, b"ShardedImpl").is_none()
    })
    .into_iter()
    .filter_map(|addr| elf.file_offset(addr))
    .map(|offset| Probe {
        at: ProbeAt::TokioSpawnBlocking,
        offset,
    })
    .collect()
}

/// Whether the multi-thread scheduler's `OwnedTasks::bind_inner` is a
/// function of its own in the binary, where the spawn probe can be.
fn multi_thread_spawns(elf: &Elf) -> bool {
    !elf.functions_where(|name| {
        [
            &b"5tokio"[..],
            b"OwnedTasks",
            b"10bind_inner",
            b"12multi_thread",
        ]
        .iter()
        .all(|part| find(name, part).is_some())
    })
    .is_empty()
}

/// The `rustc` that built the binary, from the comment section a build
/// leaves unless it is stripped: `rustc version 1.97.1 (...)` -> (97, "1.97.1").
fn rustc_version(image: &[u8]) -> Option<(u32, String)> {
    const NEEDLE: &[u8] = b"rustc version 1.";
    let at = find(image, NEEDLE)? + NEEDLE.len();
    let rest = &image[at..image.len().min(at + 16)];
    let end = rest
        .iter()
        .position(|b| !(b.is_ascii_digit() || *b == b'.'))
        .unwrap_or(rest.len());
    let text = String::from_utf8_lossy(&rest[..end]).into_owned();
    let minor = text.split('.').next()?.parse().ok()?;
    Some((minor, format!("1.{text}")))
}

/// Where `http::HeaderMap` keeps the pointer and the length of its entries,
/// for a `rustc` minor version: (pointer, length). Read from the debug
/// information of the type as built by 1.78, 1.80, 1.84, 1.97 and a 1.101
/// nightly (the same in all of them), and run on the last two; 1.75 and
/// earlier differ; 1.76 and 1.77 were not looked at.
fn header_map_entries(minor: u32) -> Option<(u16, u16)> {
    (minor >= 78).then_some((32, 40))
}

/// h2's functions that are given decoded headers: `Recv::recv_headers`
/// (one function) and `Send::send_headers` / `send_trailers` (generic: one
/// instance per body type). The names are in either mangling; an instance's
/// closures and drop glue have other names that contain these.
fn is_recv_headers(name: &[u8]) -> bool {
    let legacy = b"_ZN2h25proto7streams4recv4Recv12recv_headers17h";
    (name.starts_with(b"_RNvM")
        && name.ends_with(b"4Recv12recv_headers")
        && find(name, b"2h25proto7streams4recv").is_some())
        || (name.starts_with(legacy) && name.len() == legacy.len() + 17 && name.ends_with(b"E"))
}

fn is_send(name: &[u8], method: &str) -> bool {
    let v0 = format!("4Send{}{}I", method.len(), method);
    let legacy = format!(
        "_ZN2h25proto7streams4send4Send{}{}17h",
        method.len(),
        method
    );
    (name.starts_with(b"_RINvM")
        && find(name, b"2h25proto7streams4sendNtB").is_some()
        && find(name, v0.as_bytes()).is_some())
        || (name.starts_with(legacy.as_bytes())
            && name.len() == legacy.len() + 17
            && name.ends_with(b"E"))
}

/// The probes that read decoded headers, and where the entries are in a
/// header map; the note says what was done and why not.
fn header_probes(elf: &Elf) -> (Vec<Probe>, Option<(u16, u16)>, String) {
    let Some((minor, rustc)) = rustc_version(elf.image) else {
        return (
            Vec::new(),
            None,
            "headers of older connections not read: rustc version not found".to_string(),
        );
    };
    let Some(entries) = header_map_entries(minor) else {
        return (
            Vec::new(),
            None,
            format!("headers of older connections not read: rustc {rustc} not supported"),
        );
    };
    let at = |probe, found: Vec<u64>| -> Vec<Probe> {
        found
            .into_iter()
            .filter_map(|addr| elf.file_offset(addr))
            .map(|offset| Probe { at: probe, offset })
            .collect()
    };
    let recv = at(ProbeAt::RsRecvHeaders, elf.functions_where(is_recv_headers));
    let mut send = at(
        ProbeAt::RsSend,
        elf.functions_where(|name| is_send(name, "send_headers")),
    );
    send.extend(at(
        ProbeAt::RsSend,
        elf.functions_where(|name| is_send(name, "send_trailers")),
    ));
    if recv.is_empty() || send.is_empty() {
        return (
            Vec::new(),
            None,
            format!(
                "headers of older connections not read: h2 functions not found (rustc {rustc})"
            ),
        );
    }
    (
        recv.into_iter().chain(send).collect(),
        Some(entries),
        format!("headers of older connections read (rustc {rustc})"),
    )
}

/// The oldest tokio whose current-task id is a plain integer at the offset
/// used here; older layouts differ and have not been wired up.
const TOKIO_MIN_MINOR: u32 = 49;
/// The newest tokio the offset was checked on.
const TOKIO_MAX_MINOR: u32 = 54;
/// `Context.current_task_id` within the `CONTEXT` thread-local.
const TOKIO_CURRENT_TASK_ID: u64 = 0x30;

/// `tokio-1.52.1/src/` in a panic location -> (52, "1.52.1").
fn tokio_version(image: &[u8]) -> Option<(u32, String)> {
    const NEEDLE: &[u8] = b"/tokio-1.";
    let mut from = 0;
    while let Some(at) = find(&image[from..], NEEDLE) {
        let start = from + at + NEEDLE.len();
        let rest = &image[start..image.len().min(start + 16)];
        let end = rest
            .iter()
            .position(|b| !(b.is_ascii_digit() || *b == b'.'))
            .unwrap_or(rest.len());
        if rest[end..].starts_with(b"/src/") {
            let text = String::from_utf8_lossy(&rest[..end]).into_owned();
            let minor = text.split('.').next()?.parse().ok()?;
            return Some((minor, format!("1.{text}")));
        }
        from = start;
    }
    None
}

/// Where a thread-local of the main executable is, relative to the thread
/// pointer, given its offset in the TLS segment.
fn tls_from_thread_pointer(tls: &TlsSegment, offset: u64) -> Option<i32> {
    let align = tls.align.max(1);
    let from_tp = if cfg!(target_arch = "aarch64") {
        // The block follows the 16-byte thread control block, aligned.
        (16u64.div_ceil(align) * align + offset) as i64
    } else if cfg!(target_arch = "x86_64") {
        // The block ends at the thread pointer.
        offset as i64 - (tls.size.div_ceil(align) * align) as i64
    } else {
        return None;
    };
    i32::try_from(from_tp).ok()
}

/// `None`: no sign of tokio in the binary. `spawned`: also follow the tasks
/// a request spawns (`blame slow --spawned`); the probe where tasks are
/// registered is there anyway.
pub(super) fn inspect(elf: &Elf, spawned: bool) -> Option<Inspected> {
    // Both manglings spell the path as length-prefixed names.
    let context = elf.tls_symbol("5tokio7runtime7context7CONTEXT");
    let version = tokio_version(elf.image);
    let (minor, version) = match (context, version) {
        (None, None) => return None,
        (None, Some((_, version))) => {
            return Some(Inspected::threads(Some(format!(
                "tokio {version} without symbols: not supported, thread-level"
            ))));
        }
        (Some(_), None) => {
            return Some(Inspected::threads(Some(
                "tokio of unknown version: not supported, thread-level".to_string(),
            )));
        }
        (Some(_), Some(version)) => version,
    };
    if !(TOKIO_MIN_MINOR..=TOKIO_MAX_MINOR).contains(&minor) {
        return Some(Inspected::threads(Some(format!(
            "tokio {version}: not supported, thread-level"
        ))));
    }
    let offset = elf
        .tls
        .as_ref()
        .and_then(|tls| tls_from_thread_pointer(tls, context? + TOKIO_CURRENT_TASK_ID));
    Some(match offset {
        Some(tokio_task_id) => {
            let cfg = ProcCfg {
                runtime: RT_TOKIO,
                tokio_task_id,
                ..ProcCfg::default()
            };
            let plain = format!("tokio {version}: task-level");
            // The probes on task polls say which task a thread runs at every
            // switch. Without them it is read at kernel events only, and a
            // task that waits and is polled again on the same thread before
            // the next event gets the CPU of the tasks polled in between
            // (only 40% of handlers' CPU right, measured). The spawn probe
            // finds HTTP/2 handlers, and spawned tasks when asked.
            let h2 = find(elf.image, b"/h2-0.").is_some();
            let mut probes = task_probes(elf);
            let mut headers_note = String::new();
            let mut cfg_with_headers = cfg;
            if h2 && !probes.is_empty() {
                let (header, entries, note) = header_probes(elf);
                probes.extend(header);
                if let Some((ptr, len)) = entries {
                    cfg_with_headers.rs_entries_ptr = ptr;
                    cfg_with_headers.rs_entries_len = len;
                }
                headers_note = format!("; {note}");
            }
            if probes.is_empty() {
                let not_spawned = if spawned {
                    "; task functions not found: task switches are inferred (CPU can go to the wrong task), spawned tasks not followed"
                } else {
                    "; task functions not found: task switches are inferred (CPU can go to the wrong task)"
                };
                Inspected {
                    cfg,
                    note: Some(format!("{plain}{not_spawned}")),
                    probes,
                    fallback: None,
                    spawn_skip: Vec::new(),
                    go_wait_kinds: Vec::new(),
                    http2_handlers: false,
                }
            } else {
                let blocking = if spawned {
                    blocking_spawns(elf)
                } else {
                    Vec::new()
                };
                // The legacy mangling leaves a poll function's type
                // arguments out, so the blocking pool's are not told apart
                // by name: its tasks are then told by being seen spawned.
                let blocking_by_spawn = !blocking.is_empty()
                    && !probes.iter().any(|p| p.at == ProbeAt::TokioPollBlocking);
                let blocking_note = if blocking.is_empty() {
                    " (not spawn_blocking: where it spawns was not found)"
                } else {
                    " (spawn_blocking too)"
                };
                probes.extend(blocking);
                let (wakes, which) = if spawned {
                    wake_probes(elf)
                } else {
                    (Vec::new(), "")
                };
                let (park_flag, park_note) = match (spawned, wakes.is_empty()) {
                    (false, _) => (0, String::new()),
                    (true, false) => (
                        PROC_F_PARK
                            | if blocking_by_spawn {
                                PROC_F_TOKIO_BLOCKING
                            } else {
                                0
                            },
                        format!("; why tasks wait followed (by what woke them, on {which})"),
                    ),
                    (true, true) => (
                        0,
                        "; why tasks wait not followed: the schedulers' or the drivers' functions not found"
                            .to_string(),
                    ),
                };
                probes.extend(wakes);
                let (spawn_flag, spawn_note) = match (spawned, multi_thread_spawns(elf)) {
                    (false, _) => (0, String::new()),
                    (true, true) => (
                        PROC_F_SPAWN,
                        format!("; spawned tasks followed{blocking_note}"),
                    ),
                    // No bind_inner of the multi-thread scheduler's own: an
                    // optimised build may have merged it with the
                    // current-thread one, whose probe then sees both (the
                    // LTO builds of tokio_truth and Qdrant: every task id
                    // given out was a spawn seen), or inlined it into its
                    // callers, whose spawns are then not seen. Which, the
                    // binary does not say.
                    (true, false) => (
                        PROC_F_SPAWN,
                        format!(
                            "; spawned tasks followed{blocking_note} (the multi-thread runtime's spawn has no function of its own in this build: if it was merged with the current-thread one its spawns are seen, if inlined they are not)"
                        ),
                    ),
                };
                let h2_note = if h2 {
                    format!("; HTTP/2 handlers followed{headers_note}")
                } else {
                    String::new()
                };
                let lost = match (h2, spawned) {
                    (true, true) => {
                        "HTTP/2 handlers and spawned tasks not followed, task switches inferred"
                    }
                    (true, false) => "HTTP/2 handlers not followed, task switches inferred",
                    (false, true) => "spawned tasks not followed, task switches inferred",
                    (false, false) => "task switches inferred (CPU can go to the wrong task)",
                };
                Inspected {
                    cfg: ProcCfg {
                        flags: PROC_F_UNIT_PROBES | spawn_flag | park_flag,
                        ..cfg_with_headers
                    },
                    note: Some(format!("{plain}{h2_note}{spawn_note}{park_note}")),
                    probes,
                    fallback: Some((
                        cfg,
                        format!("{plain}; probes could not be attached, {lost}"),
                    )),
                    spawn_skip: Vec::new(),
                    go_wait_kinds: Vec::new(),
                    http2_handlers: h2,
                }
            }
        }
        None => Inspected::threads(Some(format!(
            "tokio {version}: thread-locals not found, thread-level"
        ))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether `name` is one of the spellings, as `wake_probes` matches.
    fn spelled(name: &[u8], spellings: &[Vec<Vec<u8>>]) -> bool {
        spellings
            .iter()
            .any(|parts| parts.iter().all(|part| find(name, part).is_some()))
    }

    // tokio 1.54.1 built by rustc 1.93 (x86_64), with its default (legacy)
    // mangling and with `-C symbol-mangling-version=v0`.
    const MULTI_SCHEDULE: [&[u8]; 2] = [
        b"_ZN5tokio7runtime9scheduler12multi_thread6handle140_$LT$impl$u20$tokio..runtime..task..Schedule$u20$for$u20$alloc..sync..Arc$LT$tokio..runtime..scheduler..multi_thread..handle..Handle$GT$$GT$8schedule17h3200935486d1d146E",
        b"_RNvXs_NtNtNtNtCshh3s9bXguEK_5tokio7runtime9scheduler12multi_thread6handleINtNtCshQKOepsJxml_5alloc4sync3ArcNtB4_6HandleENtNtBa_4task8Schedule8schedule",
    ];
    const MULTI_YIELD: [&[u8]; 2] = [
        b"_ZN5tokio7runtime9scheduler12multi_thread6handle140_$LT$impl$u20$tokio..runtime..task..Schedule$u20$for$u20$alloc..sync..Arc$LT$tokio..runtime..scheduler..multi_thread..handle..Handle$GT$$GT$9yield_now17h5ee4e3c4aed3bafbE",
        b"_RNvXs_NtNtNtNtCshh3s9bXguEK_5tokio7runtime9scheduler12multi_thread6handleINtNtCshQKOepsJxml_5alloc4sync3ArcNtB4_6HandleENtNtBa_4task8Schedule9yield_now",
    ];
    const CURRENT_SCHEDULE: [&[u8]; 2] = [
        b"_ZN5tokio7runtime9scheduler14current_thread134_$LT$impl$u20$tokio..runtime..task..Schedule$u20$for$u20$alloc..sync..Arc$LT$tokio..runtime..scheduler..current_thread..Handle$GT$$GT$8schedule17h245274b7979a3647E",
        b"_RNvXs5_NtNtNtCshh3s9bXguEK_5tokio7runtime9scheduler14current_threadINtNtCshQKOepsJxml_5alloc4sync3ArcNtB5_6HandleENtNtB9_4task8Schedule8schedule",
    ];

    #[test]
    fn schedule_impls_are_found_in_either_mangling() {
        let multi = |method| {
            impl_method(
                b"12multi_thread",
                &[b"6Handle"],
                b"multi_thread..handle..Handle",
                method,
            )
        };
        let current = impl_method(
            b"14current_thread",
            &[],
            b"current_thread..Handle",
            b"8schedule",
        );
        for name in MULTI_SCHEDULE {
            assert!(spelled(name, &multi(b"8schedule")));
            assert!(!spelled(name, &multi(b"9yield_now")));
            assert!(!spelled(name, &current));
        }
        for name in MULTI_YIELD {
            assert!(spelled(name, &multi(b"9yield_now")));
            assert!(!spelled(name, &multi(b"8schedule")));
        }
        for name in CURRENT_SCHEDULE {
            assert!(spelled(name, &current));
            assert!(!spelled(name, &multi(b"8schedule")));
        }
    }

    #[test]
    fn rustc_version_comes_from_the_comment_section() {
        let image = b"GCC: (Ubuntu 13.3.0)\0rustc version 1.97.1 (8bab26f4f 2026-07-14)\0";
        assert_eq!(rustc_version(image), Some((97, "1.97.1".to_string())));
        let nightly = b"rustc version 1.101.0-nightly (92b5b8c87 2026-10-29)";
        assert_eq!(rustc_version(nightly), Some((101, "1.101.0".to_string())));
        assert_eq!(rustc_version(b"no compiler here"), None);
    }

    #[test]
    fn the_header_map_is_known_from_rustc_1_78() {
        assert_eq!(header_map_entries(97), Some((32, 40)));
        assert_eq!(header_map_entries(78), Some((32, 40)));
        assert_eq!(header_map_entries(77), None);
        assert_eq!(header_map_entries(75), None);
    }

    #[test]
    fn h2_functions_are_told_from_their_closures_and_glue() {
        let recv = b"_RNvMNtNtNtCscfuFiw2yFZd_2h25proto7streams4recvNtB2_4Recv12recv_headers";
        assert!(is_recv_headers(recv));
        // A closure of the transition in which recv_headers runs.
        let other = b"_RINvMs_NtNtNtCscfuFiw2yFZd_2h25proto7streams6countsNtB5_6Counts10transitionNCINvMs0_NtB7_7streamsNtB1k_5Inner12recv_headersINtNtNtCs6Mrnt9d0Mck_5hyper5proto2h27SendBuf";
        assert!(!is_recv_headers(other));
        let trailers = b"_RINvMNtNtNtCscfuFiw2yFZd_2h25proto7streams4sendNtB3_4Send13send_trailersINtNtNtCs6Mrnt9d0Mck_5hyper5proto2h27SendBufNtNtCs1vy9UVDIxJm_5bytes5bytes5BytesEECs75Zz1MCb1aC_11tonic_truth";
        assert!(is_send(trailers, "send_trailers"));
        assert!(!is_send(trailers, "send_headers"));
        // The stream-level function of the same name, and drop glue.
        let stream = b"_RINvMs_NtNtNtCscfuFiw2yFZd_2h25proto7streams7streamsINtB4_9StreamRefINtNtNtCs6Mrnt9d0Mck_5hyper5proto2h27SendBuf13send_trailers";
        assert!(!is_send(stream, "send_trailers"));
        // The older mangling: the name, a hash, and nothing after (h2 in
        // tonic_truth, built by rustc 1.93 with its default, legacy, one).
        assert!(is_recv_headers(
            b"_ZN2h25proto7streams4recv4Recv12recv_headers17h20938fa9c4ebce10E"
        ));
        assert!(is_send(
            b"_ZN2h25proto7streams4send4Send13send_trailers17h4ca579d4202438afE",
            "send_trailers"
        ));
        assert!(!is_recv_headers(
            b"_ZN2h25proto7streams4recv4Recv12recv_headers17h20938fa9c4ebce10E.llvm.1"
        ));
        // tracing's statics for the function's events: data, under its path.
        assert!(!is_recv_headers(
            b"_ZN2h25proto7streams4recv4Recv12recv_headers10__CALLSITE17h1752c9052d4650a0E"
        ));
        assert!(!is_send(
            b"_ZN2h25proto7streams4send4Send13send_trailers10__CALLSITE17hd8e0dd3021355e0eE",
            "send_trailers"
        ));
    }

    #[test]
    fn tokio_version_comes_from_a_source_path() {
        let image = b"..tokio-rustls-0.2/..cargo/registry/src/x/tokio-1.52.1/src/runtime/mod.rs..";
        assert_eq!(tokio_version(image), Some((52, "1.52.1".to_string())));
        assert_eq!(tokio_version(b"/tokio-1.x/src/"), None);
        assert_eq!(tokio_version(b"nothing here"), None);
    }
}
