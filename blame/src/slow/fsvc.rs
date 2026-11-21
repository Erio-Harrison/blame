//! The kernel functions where a thread waits for a file service (NFS, FUSE,
//! ...; `bpf/request/fsvc.h`): which of them this kernel lets a program hook,
//! and attaching the programs on them.

use std::{collections::HashSet, path::Path, sync::OnceLock};

use libbpf_rs::Link;

use super::attach::{attach_rank, attach_together, loaded};
use crate::bpf::Skel;

/// The programs on the functions where a thread waits for a file service
/// (`bpf/request/fsvc.h`): `req_fsvc_<function>` at entry, `req_fsvcx_<function>`
/// at return. Attached by `attach_fsvc`, before the other request programs.
pub(super) const FSVC_PREFIX: &str = "req_fsvc";

/// The kernel function a file-service program is on.
pub(super) fn fsvc_function(name: &str) -> Option<&str> {
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
pub(super) fn fsvc_present(function: &str) -> bool {
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

/// The names in the text of `available_filter_functions`: one a line, a
/// module's followed by `[module]`.
fn filter_functions(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Attach the file-service programs that were loaded. Without any, such
/// waits are counted as the kernel marks them (disk, or other): said on
/// stderr, and the rest goes on.
pub(super) fn attach_fsvc(skel: &Skel) -> Vec<Link> {
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
}
