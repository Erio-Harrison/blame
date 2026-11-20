//! What procfs knows that the kernel side needs at startup: which cgroup each
//! thread is in, which processes listen on which TCP ports, and whether the
//! pids procfs shows are the ones the kernel side reads.

use std::{
    collections::{HashMap, HashSet},
    fs,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

/// The inode of the kernel's initial PID namespace, the same in every kernel
/// (`PROC_PID_INIT_INO`).
const INIT_PID_NS_INO: u64 = 0xEFFF_FFFC;

/// A PID namespace, as `bpf_get_ns_current_pid_tgid()` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidNs {
    /// The nsfs device, encoded as the kernel's `dev_t` (`MKDEV`), not as
    /// `stat` reports it.
    pub dev: u64,
    pub ino: u64,
}

impl PidNs {
    /// The kernel's initial namespace, whose numbers the kernel side reads
    /// anyway. Anywhere else (a WSL2 distribution, a container without the
    /// host's PID namespace) procfs numbers the same processes otherwise.
    pub fn is_initial(&self) -> bool {
        self.ino == INIT_PID_NS_INO
    }
}

/// The PID namespace this process is in. `None` if it cannot be told.
pub fn pid_ns(proc: &Path) -> Option<PidNs> {
    let meta = fs::metadata(proc.join("self/ns/pid")).ok()?;
    Some(PidNs {
        dev: kernel_dev(meta.dev()),
        ino: meta.ino(),
    })
}

/// `stat`'s encoding of a device number turned into the kernel's:
/// `major << 20 | minor`.
fn kernel_dev(dev: u64) -> u64 {
    (u64::from(libc::major(dev)) << 20) | u64::from(libc::minor(dev))
}

/// The cgroup v2 path in the text of a `/proc/<pid>/cgroup` file.
fn v2_path(text: &str) -> Option<&str> {
    text.lines().find_map(|line| line.strip_prefix("0::"))
}

/// (tid, cgroup id) for every thread that exists right now. Threads that exit
/// while this runs are skipped.
pub fn thread_cgroups(root: &Path, proc: &Path) -> Vec<(u32, u64)> {
    let mut ids: HashMap<String, Option<u64>> = HashMap::new();
    let mut out = Vec::new();
    let Ok(pids) = fs::read_dir(proc) else {
        return out;
    };
    for pid in pids.flatten() {
        let task_dir: PathBuf = pid.path().join("task");
        let Ok(tids) = fs::read_dir(&task_dir) else {
            continue;
        };
        for tid in tids.flatten() {
            let Some(tid_num) = tid
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(text) = fs::read_to_string(tid.path().join("cgroup")) else {
                continue;
            };
            let Some(path) = v2_path(&text) else {
                continue;
            };
            let id = *ids.entry(path.to_string()).or_insert_with(|| {
                fs::metadata(root.join(path.trim_start_matches('/')))
                    .ok()
                    .map(|meta| meta.ino())
            });
            if let Some(id) = id {
                out.push((tid_num, id));
            }
        }
    }
    out
}

/// TCP sockets that are listening right now.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listeners {
    /// (network namespace, port), each once.
    pub ports: Vec<(u32, u16)>,
    /// Processes holding at least one of them.
    pub pids: Vec<u32>,
}

/// Every listening TCP socket and the processes that hold one, across all
/// network namespaces. Processes that exit while this runs are skipped.
pub fn listeners(proc: &Path) -> Listeners {
    // Per namespace: inode of each listening socket -> its port.
    let mut by_ns: HashMap<u32, HashMap<u64, u16>> = HashMap::new();
    let mut pids = Vec::new();
    let Ok(entries) = fs::read_dir(proc) else {
        return Listeners::default();
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let dir = entry.path();
        let Some(ns) = fs::read_link(dir.join("ns/net"))
            .ok()
            .and_then(|link| bracketed(&link.to_string_lossy(), "net:"))
        else {
            continue;
        };
        let ns = ns as u32;
        if let std::collections::hash_map::Entry::Vacant(slot) = by_ns.entry(ns) {
            // Read through this process. If it exited in between, nothing is
            // cached, and the next process in the namespace reads it instead.
            let mut found = HashMap::new();
            let mut read = false;
            for table in ["net/tcp", "net/tcp6"] {
                if let Ok(text) = fs::read_to_string(dir.join(table)) {
                    found.extend(tcp_listeners(&text));
                    read = true;
                }
            }
            if !read {
                continue;
            }
            slot.insert(found);
        }
        let sockets = &by_ns[&ns];
        if sockets.is_empty() {
            continue;
        }
        let Ok(fds) = fs::read_dir(dir.join("fd")) else {
            continue;
        };
        let holds_one = fds.flatten().any(|fd| {
            fs::read_link(fd.path())
                .ok()
                .and_then(|link| bracketed(&link.to_string_lossy(), "socket:"))
                .is_some_and(|inode| sockets.contains_key(&inode))
        });
        if holds_one {
            pids.push(pid);
        }
    }
    let ports: HashSet<(u32, u16)> = by_ns
        .iter()
        .flat_map(|(ns, sockets)| sockets.values().map(|port| (*ns, *port)))
        .collect();
    let mut ports: Vec<_> = ports.into_iter().collect();
    ports.sort_unstable();
    pids.sort_unstable();
    Listeners { ports, pids }
}

/// The number in a link target like `net:[4026531840]` or `socket:[12345]`.
fn bracketed(target: &str, prefix: &str) -> Option<u64> {
    target
        .strip_prefix(prefix)?
        .strip_prefix('[')?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// (inode, port) of each listening socket in the text of `/proc/net/tcp` or
/// `tcp6`. Columns: slot, local address, remote address, state, ..., inode
/// (the tenth); state `0A` is LISTEN, and the port is the hex after the last
/// colon of the local address.
fn tcp_listeners(text: &str) -> Vec<(u64, u16)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if *fields.get(3)? != "0A" {
                return None;
            }
            let port = u16::from_str_radix(fields.get(1)?.rsplit_once(':')?.1, 16).ok()?;
            let inode = fields.get(9)?.parse().ok()?;
            Some((inode, port))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("blame-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn pid_namespace_is_told_from_procfs() {
        // Which namespace the test runs in depends on the machine; that it
        // can be told does not.
        assert!(pid_ns(Path::new("/proc")).is_some());
        assert_eq!(pid_ns(&tempdir("no-ns")), None);
    }

    #[test]
    fn device_numbers_take_the_kernel_encoding() {
        // stat puts the low 8 bits of the minor below the major, the rest
        // above it; the kernel keeps 20 bits of minor under the major.
        assert_eq!(kernel_dev(libc::makedev(0, 4)), 4);
        assert_eq!(kernel_dev(libc::makedev(8, 1)), (8 << 20) | 1);
        assert_eq!(kernel_dev(libc::makedev(0, 0x1234)), 0x1234);
    }

    #[test]
    fn v2_line_is_found_among_v1_lines() {
        assert_eq!(
            v2_path("0::/system.slice/ssh.service\n"),
            Some("/system.slice/ssh.service")
        );
        assert_eq!(v2_path("12:cpu:/a\n0::/b\n"), Some("/b"));
        assert_eq!(v2_path("12:cpu:/a\n"), None);
    }

    #[test]
    fn threads_resolve_through_their_cgroup_file() {
        let root = tempdir("thr-root");
        let proc = tempdir("thr-proc");
        fs::create_dir_all(root.join("x.slice")).unwrap();
        for (pid, tids) in [(10, vec![10, 11]), (20, vec![20])] {
            for tid in tids {
                let dir = proc
                    .join(pid.to_string())
                    .join("task")
                    .join(tid.to_string());
                fs::create_dir_all(&dir).unwrap();
                let path = if pid == 10 { "/x.slice" } else { "/gone.slice" };
                fs::write(dir.join("cgroup"), format!("0::{path}\n")).unwrap();
            }
        }
        let ino = fs::metadata(root.join("x.slice")).unwrap().ino();
        let mut got = thread_cgroups(&root, &proc);
        got.sort();
        // pid 20's cgroup no longer exists, so its thread is skipped.
        assert_eq!(got, vec![(10, ino), (11, ino)]);
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&proc).unwrap();
    }

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 4243 1 0000000000000000 20 4 30 10 -1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 77 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn only_listening_sockets_are_taken_from_the_tcp_table() {
        assert_eq!(tcp_listeners(TCP), vec![(4242, 8080)]);
        assert_eq!(tcp_listeners(TCP6), vec![(77, 80)]);
        assert_eq!(tcp_listeners("header only\n"), vec![]);
    }

    #[test]
    fn link_targets_carry_a_number_in_brackets() {
        assert_eq!(bracketed("net:[4026531840]", "net:"), Some(4_026_531_840));
        assert_eq!(bracketed("socket:[12345]", "socket:"), Some(12345));
        assert_eq!(bracketed("pipe:[12345]", "socket:"), None);
        assert_eq!(bracketed("/dev/null", "socket:"), None);
    }

    #[test]
    fn listeners_are_found_per_namespace_with_the_processes_holding_them() {
        use std::os::unix::fs::symlink;

        let proc = tempdir("listen");
        // 10 listens on 8080 in namespace 1; 11 shares the namespace and only
        // has a connected socket; 20 listens on 80 in namespace 2.
        for (pid, ns, tcp, tcp6, sockets) in [
            (10, 1, TCP, "", vec![4242u64]),
            (11, 1, TCP, "", vec![4243]),
            (20, 2, "", TCP6, vec![77]),
        ] {
            let dir = proc.join(pid.to_string());
            fs::create_dir_all(dir.join("ns")).unwrap();
            fs::create_dir_all(dir.join("net")).unwrap();
            fs::create_dir_all(dir.join("fd")).unwrap();
            symlink(format!("net:[{ns}]"), dir.join("ns/net")).unwrap();
            fs::write(dir.join("net/tcp"), tcp).unwrap();
            fs::write(dir.join("net/tcp6"), tcp6).unwrap();
            symlink("/dev/null", dir.join("fd/0")).unwrap();
            for (fd, inode) in sockets.iter().enumerate() {
                symlink(
                    format!("socket:[{inode}]"),
                    dir.join(format!("fd/{}", fd + 3)),
                )
                .unwrap();
            }
        }
        assert_eq!(
            listeners(&proc),
            Listeners {
                ports: vec![(1, 8080), (2, 80)],
                pids: vec![10, 20],
            }
        );
        fs::remove_dir_all(&proc).unwrap();
    }
}
