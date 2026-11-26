//! TLS, user side: which TLS library a process reads and writes its
//! connections through, and the probes where that library hands over their
//! plaintext. The kernel side is `bpf/tls/`: `tls.h` takes the plaintext to
//! the connection it belongs to whatever the library, one file per library
//! probes it.
//!
//! One file per library here too, each finding its library in a process and
//! the functions probed in it.

pub mod openssl;

use std::path::Path;

use anyhow::{Context as _, Result};
use libbpf_rs::{Link, ProgramMut};

use crate::{bpf::Skel, runtime};

/// The probes on the TLS library `pid` has loaded: what to tell the user, and
/// the links. `None`: no library it knows. All of them are attached, or an
/// error says which one was not (and none stays).
pub fn follow(skel: &Skel, pid: u32) -> Result<Option<(String, Vec<Link>)>> {
    use openssl::SslFn;

    let proc = Path::new("/proc");
    let Some(lib) = openssl::libssl(proc, pid) else {
        return Ok(None);
    };
    let file = runtime::omp::file_of(proc, pid, &lib.path);
    let progs = &skel.progs;
    let mut links = Vec::new();
    for (f, offset) in &lib.functions {
        let Ok(offset) = usize::try_from(*offset) else {
            return Ok(None);
        };
        let at: &[(&ProgramMut<'_>, bool)] = match f {
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
        // Returns first: an entry with no return probe yet would leave a call in flight.
        for (program, ret) in at {
            let link = program
                .attach_uprobe(*ret, pid as i32, &file, offset)
                .with_context(|| format!("probe on {} in {} at {offset:#x}", f.name(), lib.path))?;
            links.push(link);
        }
    }
    Ok(Some((
        format!("TLS read from OpenSSL ({})", lib.path),
        links,
    )))
}
