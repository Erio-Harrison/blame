//! Runtime adapters, user side: what a process's binary says about the
//! runtime inside it, and where the kernel side (`bpf/runtime/`) has to look
//! to learn which goroutine or task a thread is running.
//!
//! Nothing is guessed. A runtime that is not recognised, a version that has
//! not been checked, or a build without the symbols needed leaves the process
//! at thread level, and the note says why.
//!
//! One file per runtime; each answers for a binary it recognises, in the
//! order tried in [`inspect_image`]. A runtime's file also holds what is
//! probed of the libraries that run on it (grpc-go in `go.rs`; hyper and h2
//! in `tokio.rs` and `tasks.rs`), as `bpf/runtime/` does on the kernel side.

mod elf;
mod go;
pub mod omp;
pub mod tasks;
mod tokio;

use std::path::Path;

use blame_common::ProcCfg;

use elf::Elf;

/// A point in a process's binary where the kernel side wants a probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeAt {
    /// Go: `runtime.execute`, where a goroutine is put on a thread.
    GoExecute,
    /// grpc-go: `(*Server).addConn`, once per connection.
    GoGrpcConn,
    /// grpc-go: `(*http2Server).operateHeaders`, in the goroutine that reads
    /// a connection, for every HEADERS frame.
    GoGrpcHeaders,
    /// grpc-go: `(*Server).handleStream`, in the goroutine serving a stream.
    GoGrpcHandle,
    /// grpc-go: `(*http2Server).writeStatus`, where a handler ends its stream.
    GoGrpcEnd,
    /// tokio: a `task::raw::poll` function; probed at entry and at return.
    TokioPoll,
    /// tokio: the same, for a task of the blocking pool.
    TokioPollBlocking,
    /// tokio: the multi-thread scheduler's `Handle::schedule_task`, where a
    /// woken task is put back on a run queue.
    TokioWake,
    /// tokio: the I/O driver's `Driver::turn`; probed at entry and at return.
    TokioIoTurn,
    /// tokio: the time driver's `Handle::process_at_time`, which fires
    /// timers; probed at entry and at return.
    TokioTimers,
    /// tokio: `OwnedTasks::bind_inner`, where a spawned task is registered.
    TokioSpawn,
    /// tokio: `blocking::pool::Spawner::spawn_task`, where a closure given
    /// to `spawn_blocking` (and so every `tokio::fs` call) becomes a task.
    TokioSpawnBlocking,
    /// Go: `runtime.newproc1`, where a goroutine is created; probed at entry
    /// and at return.
    GoSpawn,
    /// Go: `runtime.gopark`, where a goroutine parks, and why.
    GoPark,
    /// Go: `runtime.goexit0`, where a goroutine that has returned leaves its thread.
    GoExit,
    /// Rust h2: `Recv::recv_headers`, with a request's decoded headers.
    RsRecvHeaders,
    /// Rust h2: `Send::send_headers` or `send_trailers`, with a response's.
    RsSend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub at: ProbeAt,
    /// Offset of the function in the binary's file.
    pub offset: u64,
}

/// How one process's requests will be attributed.
#[derive(Debug, PartialEq, Eq)]
pub struct Inspected {
    pub cfg: ProcCfg,
    /// For the user: `None` for a plain threaded process.
    pub note: Option<String>,
    /// Probes `cfg` relies on. If they cannot all be attached, the process
    /// is attributed as [`Inspected::without_probes`] says.
    pub probes: Vec<Probe>,
    /// What to fall back to, and what to tell the user then.
    pub fallback: Option<(ProcCfg, String)>,
    /// Go, following spawned goroutines: link-time addresses. The first is
    /// `runtime.newproc1`'s, from which the kernel side works out where the
    /// binary is loaded; the others are functions of the runtime itself that
    /// a goroutine can start at (the garbage collector's workers, the
    /// finalizer and cleanup goroutines, ...). A request that happens to
    /// start one of those does not get it as a helper. Empty: none.
    pub spawn_skip: Vec<u64>,
    /// Go, following why goroutines park: what each wait reason of the
    /// binary's Go version is, by reason (`enum park` of the kernel side).
    /// Empty: none.
    pub go_wait_kinds: Vec<u8>,
    /// Probes find the goroutine or task that serves each HTTP/2 stream
    /// (if they can be attached).
    pub http2_handlers: bool,
    /// Versions the process uses that blame does not know, each with what is
    /// not followed because of it: told the user as warnings. Empty: none.
    pub unsupported: Vec<String>,
}

impl Inspected {
    fn threads(note: Option<String>) -> Self {
        Self {
            cfg: ProcCfg::threads(),
            note,
            probes: Vec::new(),
            fallback: None,
            spawn_skip: Vec::new(),
            go_wait_kinds: Vec::new(),
            http2_handlers: false,
            unsupported: Vec::new(),
        }
    }

    /// A process followed by thread only, because of a version blame does
    /// not know: `note` as usual, and `warning` to say so.
    fn unsupported(note: String, warning: String) -> Self {
        let mut found = Self::threads(Some(note));
        found.unsupported.push(warning);
        found
    }

    /// The same process when its probes could not be attached.
    pub fn without_probes(self) -> Self {
        match self.fallback {
            Some((cfg, note)) => Self {
                cfg,
                note: Some(note),
                probes: Vec::new(),
                fallback: None,
                spawn_skip: Vec::new(),
                go_wait_kinds: Vec::new(),
                http2_handlers: false,
                unsupported: self.unsupported,
            },
            None => Self {
                probes: Vec::new(),
                spawn_skip: Vec::new(),
                go_wait_kinds: Vec::new(),
                http2_handlers: false,
                ..self
            },
        }
    }
}

/// Look at the binary `pid` runs. `/proc/<pid>/exe` reaches it in whatever
/// mount namespace it lives.
/// `spawned`: also follow goroutines and tasks a request spawns.
pub fn inspect(proc: &Path, pid: u32, spawned: bool) -> Inspected {
    match std::fs::read(proc.join(pid.to_string()).join("exe")) {
        Ok(image) => inspect_image(&image, spawned),
        Err(_) => Inspected::threads(None),
    }
}

fn inspect_image(image: &[u8], spawned: bool) -> Inspected {
    let Some(elf) = Elf::parse(image) else {
        return Inspected::threads(None);
    };
    if let Some(found) = go::inspect(&elf, spawned) {
        return found;
    }
    if let Some(found) = tokio::inspect(&elf, spawned) {
        return found;
    }
    Inspected::threads(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_that_is_not_elf_is_a_threaded_process() {
        assert_eq!(
            inspect_image(b"#!/bin/sh\n", false),
            Inspected::threads(None)
        );
        assert_eq!(inspect_image(b"\x7fELF", true), Inspected::threads(None));
    }
}
