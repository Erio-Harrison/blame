//! TLS, user side: which TLS libraries a process reads and writes its
//! connections through, and the probes where they hand over their
//! plaintext. The kernel side is `bpf/tls/`: `tls.h` takes the plaintext to
//! the connection it belongs to whatever the library, one file per library
//! probes it.
//!
//! One file per library here too, each finding its library in a process and
//! the functions probed in it: OpenSSL's libssl (a shared library), Go's
//! crypto/tls and rustls (in the program itself).

pub mod go;
pub mod openssl;
pub mod rustls;

use std::path::Path;

use anyhow::{Context as _, Result};
use blame_common::{PROC_F_GO_TLS, PROC_F_TLS_READ};
use libbpf_rs::{Link, ProgramMut};

use crate::{
    bpf::Skel,
    runtime::{self, elf::Elf},
};

/// The TLS libraries found in a process, and what was found but cannot be read.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Found {
    pub openssl: Option<openssl::Libssl>,
    pub go: Option<go::GoTls>,
    pub rustls: Option<rustls::Rustls>,
    /// For the user: TLS in the process that is not read, and why.
    pub unread: Vec<String>,
}

impl Found {
    /// What the kernel side is told about the process (`PROC_F_*`).
    pub fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.openssl.is_some() || self.go.is_some() || self.rustls.is_some() {
            flags |= PROC_F_TLS_READ;
        }
        if self.go.is_some() {
            flags |= PROC_F_GO_TLS;
        }
        flags
    }

    fn is_empty(&self) -> bool {
        self.flags() == 0
    }

    /// For the user: what is read, and from where.
    fn note(&self) -> String {
        let mut what = Vec::new();
        if let Some(lib) = &self.openssl {
            what.push(format!("OpenSSL ({})", lib.path));
        }
        if self.go.is_some() {
            what.push("Go's crypto/tls".to_owned());
        }
        if self.rustls.is_some() {
            what.push("rustls".to_owned());
        }
        format!("TLS read from {}", what.join(" and "))
    }
}

/// The TLS libraries `pid` reads and writes its connections through.
pub fn find(proc: &Path, pid: u32) -> Found {
    let mut found = Found {
        openssl: openssl::libssl(proc, pid),
        ..Found::default()
    };
    let Ok(image) = std::fs::read(proc.join(pid.to_string()).join("exe")) else {
        return found;
    };
    let Some(elf) = Elf::parse(&image) else {
        return found;
    };
    match go::find(&elf) {
        Ok(go) => found.go = go,
        Err(why) => found.unread.push(why),
    }
    match rustls::find(&elf) {
        Ok(rustls) => found.rustls = rustls,
        Err(why) => found.unread.push(why),
    }
    found
}

/// The probes on the TLS libraries `found` in `pid`: what to tell the user,
/// and the links. All of them are attached, or an error says which one was
/// not (and none stays). Each function's returns go on before its entry: an
/// entry with no return probe yet would leave a call in flight.
pub fn attach(skel: &Skel, pid: u32, found: &Found) -> Result<Option<(String, Vec<Link>)>> {
    if found.is_empty() {
        return Ok(None);
    }
    let mut links = Vec::new();
    let progs = &skel.progs;
    let mut at = |program: &ProgramMut<'_>, ret: bool, file: &Path, offset: u64, what: &str| {
        let offset = usize::try_from(offset).context("probe offset")?;
        let link = program
            .attach_uprobe(ret, pid as i32, file, offset)
            .with_context(|| format!("probe on {what} in {} at {offset:#x}", file.display()))?;
        links.push(link);
        anyhow::Ok(())
    };
    if let Some(lib) = &found.openssl {
        use openssl::SslFn;

        let file = runtime::omp::file_of(Path::new("/proc"), pid, &lib.path);
        for (f, offset) in &lib.functions {
            let probes: &[(&ProgramMut<'_>, bool)] = match f {
                SslFn::SetFd => &[(&progs.up_ssl_set_fd, false)],
                SslFn::Free => &[(&progs.up_ssl_free, false)],
                SslFn::Read => &[(&progs.up_ssl_read_ret, true), (&progs.up_ssl_read, false)],
                SslFn::Write => &[
                    (&progs.up_ssl_write_ret, true),
                    (&progs.up_ssl_write, false),
                ],
                SslFn::ReadEx => &[
                    (&progs.up_ssl_read_ex_ret, true),
                    (&progs.up_ssl_read_ex, false),
                ],
                SslFn::WriteEx => &[
                    (&progs.up_ssl_write_ex_ret, true),
                    (&progs.up_ssl_write_ex, false),
                ],
                SslFn::Sendfile => &[
                    (&progs.up_ssl_sendfile_ret, true),
                    (&progs.up_ssl_sendfile, false),
                ],
            };
            for (program, ret) in probes {
                at(program, *ret, Path::new(&file), *offset, f.name())?;
            }
        }
    }
    let exe = Path::new("/proc").join(pid.to_string()).join("exe");
    if let Some(go) = &found.go {
        let handshakes = go.handshakes.iter().map(|f| {
            (
                f,
                &progs.up_go_tls_handshake,
                &progs.up_go_tls_handshake_ret,
            )
        });
        for (fn_, entry, ret) in [
            (&go.read, &progs.up_go_tls_read, &progs.up_go_tls_read_ret),
            (
                &go.write,
                &progs.up_go_tls_write,
                &progs.up_go_tls_write_ret,
            ),
        ]
        .into_iter()
        .chain(handshakes)
        {
            // At the return instructions themselves: uprobes, not return probes.
            for offset in &fn_.returns {
                at(ret, false, &exe, *offset, "a return of crypto/tls")?;
            }
            at(entry, false, &exe, fn_.entry, "crypto/tls")?;
        }
    }
    if let Some(rustls) = &found.rustls {
        for offset in &rustls.received {
            at(&progs.up_rs_tls_rx, false, &exe, *offset, "rustls")?;
        }
        for offset in &rustls.sent {
            at(&progs.up_rs_tls_tx, false, &exe, *offset, "rustls")?;
        }
    }
    Ok(Some((found.note(), links)))
}
