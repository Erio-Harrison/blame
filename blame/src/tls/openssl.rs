//! TLS through OpenSSL's API, user side: where a process's libssl is, and
//! where in it the functions are whose calls hand over the plaintext of its
//! connections. The kernel side is `bpf/tls/openssl.h`.
//!
//! libssl is a shared library, so it is looked for in the process's
//! mappings. The functions are exported: they are there in a stripped
//! library too. OpenSSL 1.1 and 3 keep these names (3 adds `SSL_sendfile`, for
//! kernel TLS); so do libraries made to stand in for it under the same file name.

use std::path::Path;

use crate::runtime::{elf::Elf, omp::mappings};

/// A function of libssl the kernel side probes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SslFn {
    /// `SSL_set_fd`: which socket a session is on.
    SetFd,
    /// `SSL_free`: a session is gone, and where it was may be another's.
    Free,
    /// `SSL_read` and `SSL_write`: entry and return.
    Read,
    Write,
    /// `SSL_read_ex` and `SSL_write_ex` (1.1.1 and later): entry and return.
    ReadEx,
    WriteEx,
    /// `SSL_sendfile` (3.0 and later, kernel TLS): entry and return.
    Sendfile,
}

impl SslFn {
    const ALL: [Self; 7] = [
        Self::SetFd,
        Self::Free,
        Self::Read,
        Self::Write,
        Self::ReadEx,
        Self::WriteEx,
        Self::Sendfile,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::SetFd => "SSL_set_fd",
            Self::Free => "SSL_free",
            Self::Read => "SSL_read",
            Self::Write => "SSL_write",
            Self::ReadEx => "SSL_read_ex",
            Self::WriteEx => "SSL_write_ex",
            Self::Sendfile => "SSL_sendfile",
        }
    }

    /// Without these the library is not followed: a session's socket and its
    /// plaintext both ways. The others are taken where they are.
    const fn required(self) -> bool {
        matches!(self, Self::SetFd | Self::Read | Self::Write)
    }
}

/// A process's libssl: the path it is mapped from, and where in that file
/// each function is.
#[derive(Debug, PartialEq, Eq)]
pub struct Libssl {
    pub path: String,
    pub functions: Vec<(SslFn, u64)>,
}

fn is_libssl(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|name| {
        name.starts_with("libssl.so") || name.starts_with("libssl-") && name.contains(".so")
    })
}

fn libssl_in(maps: &str, read: impl Fn(&str) -> Option<Vec<u8>>) -> Option<Libssl> {
    let path = mappings(maps)
        .map(|m| m.path)
        .find(|path| is_libssl(path))?;
    let image = read(path)?;
    let elf = Elf::parse(&image)?;
    let mut functions = Vec::new();
    for f in SslFn::ALL {
        let at = elf
            .exported_functions_where(|name| name == f.name().as_bytes())
            .first()
            .and_then(|addr| elf.file_offset(*addr));
        match at {
            Some(offset) => functions.push((f, offset)),
            None if f.required() => return None,
            None => {}
        }
    }
    Some(Libssl {
        path: path.to_owned(),
        functions,
    })
}

/// The libssl `pid` has loaded, if any, with the functions that are probed.
pub fn libssl(proc: &Path, pid: u32) -> Option<Libssl> {
    let maps = std::fs::read_to_string(proc.join(pid.to_string()).join("maps")).ok()?;
    libssl_in(&maps, |path| {
        std::fs::read(crate::runtime::omp::file_of(proc, pid, path)).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libssl_is_told_by_its_file_name() {
        assert!(is_libssl("/usr/lib/x86_64-linux-gnu/libssl.so.3"));
        assert!(is_libssl("/usr/lib64/libssl.so.1.1"));
        assert!(is_libssl("/opt/app/lib/libssl-4b1d2f.so.3"));
        assert!(!is_libssl("/usr/lib/x86_64-linux-gnu/libcrypto.so.3"));
        assert!(!is_libssl("/usr/lib/libssl3.so"));
        assert!(!is_libssl("/opt/libssl.so.3/python3"));
    }

    #[test]
    fn a_process_without_libssl_has_none() {
        let maps = "55d0c0a40000-55d0c0d1f000 r-xp 00000000 fd:01 1234 /usr/bin/python3.12\n";
        assert_eq!(libssl_in(maps, |_| panic!("nothing to read")), None);
        let maps = "7f00c0a40000-7f00c0d1f000 r-xp 00000000 fd:01 1234 /usr/lib/libssl.so.3\n";
        assert_eq!(libssl_in(maps, |_| None), None);
        assert_eq!(libssl_in(maps, |_| Some(b"not ELF".to_vec())), None);
    }

    #[test]
    fn this_machines_libssl_has_the_functions() {
        // Where the distributions put it; skipped where there is none.
        let Some(path) = [
            "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "/usr/lib/aarch64-linux-gnu/libssl.so.3",
            "/usr/lib64/libssl.so.3",
        ]
        .into_iter()
        .find(|path| Path::new(path).exists()) else {
            return;
        };
        let maps = format!("7f9a2e000000-7f9a2e330000 r-xp 00000000 fd:01 5678    {path}\n");
        let found = libssl_in(&maps, |path| std::fs::read(path).ok()).expect("libssl");
        assert_eq!(found.path, path);
        // OpenSSL 3: all seven, each at a distinct place.
        assert_eq!(found.functions.len(), 7, "{:?}", found.functions);
        let mut at: Vec<u64> = found.functions.iter().map(|(_, a)| *a).collect();
        at.sort_unstable();
        at.dedup();
        assert_eq!(at.len(), 7);
    }
}
