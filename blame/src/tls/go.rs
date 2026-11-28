//! TLS through Go's `crypto/tls`, user side: where in a Go binary
//! `(*Conn).Read` and `(*Conn).Write` start and return. The kernel side is
//! `bpf/tls/go_tls.h`.
//!
//! The functions are found in the table the Go runtime itself uses
//! (`.gopclntab`), which stripping leaves in place; it gives where each one
//! ends too. Go moves goroutine stacks, so the returns are probed where they
//! are, at each return instruction, instead of by a return probe. On arm64
//! every instruction is a 4-byte word, so those are the words that are one;
//! x86-64 instructions have no fixed length, and a byte that looks like a
//! return can be inside another instruction: not done there.

use crate::runtime::{
    elf::{EM_AARCH64, Elf},
    go::{go_function_ranges, go_probe_offset},
};

const FN_READ: &str = "crypto/tls.(*Conn).Read";
const FN_WRITE: &str = "crypto/tls.(*Conn).Write";
/// What Read, Write and Handshake call before the handshake is done; here
/// only to tell Go 1.17 and later (whose internal ABI the probes read).
const FN_HANDSHAKE_CONTEXT: &str = "crypto/tls.(*Conn).handshakeContext";
/// Where the handshake is made (`handshakeFn`), by the server or the client
/// side: its socket calls show which socket a session is on before its
/// first Read. `handshakeContext` would be too, but it is called by every
/// Read and Write, returning at once after the handshake: probed, it cost
/// ~1.1 µs each time. A binary that is only a client (or only a server)
/// has only one of them.
const FN_HANDSHAKES: [&str; 2] = [
    "crypto/tls.(*Conn).serverHandshake",
    "crypto/tls.(*Conn).clientHandshake",
];
/// `ret` on arm64.
const ARM64_RET: u32 = 0xd65f_03c0;

/// A function probed at entry and at its returns: offsets in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryAndReturns {
    pub entry: u64,
    pub returns: Vec<u64>,
}

/// Where crypto/tls hands over the plaintext of a connection in one binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoTls {
    pub read: EntryAndReturns,
    pub write: EntryAndReturns,
    /// The server's and the client's handshake, those in the binary.
    pub handshakes: Vec<EntryAndReturns>,
}

/// `Ok(None)`: not a Go binary, or one without crypto/tls. `Err`: one whose
/// crypto/tls cannot be read, and why.
pub fn find(elf: &Elf) -> Result<Option<GoTls>, String> {
    if elf.section(".gopclntab").is_none() {
        return Ok(None);
    }
    let [Some(read), Some(write), context, server, client] = go_function_ranges(
        elf,
        [
            FN_READ,
            FN_WRITE,
            FN_HANDSHAKE_CONTEXT,
            FN_HANDSHAKES[0],
            FN_HANDSHAKES[1],
        ],
    ) else {
        return Ok(None);
    };
    if context.is_none() {
        return Err("crypto/tls without (*Conn).handshakeContext (Go older than 1.17)".into());
    }
    if server.is_none() && client.is_none() {
        return Err("crypto/tls without a handshake function".into());
    }
    if elf.machine != EM_AARCH64 {
        return Err(
            "Go's crypto/tls is read on arm64 only (where its functions return is not found \
             on x86-64 yet)"
                .into(),
        );
    }
    let probe = |(start, end): (u64, u64)| -> Result<EntryAndReturns, String> {
        let not_read = || format!("crypto/tls: {start:#x}..{end:#x} not in the file");
        let code = elf
            .bytes_at(start, usize::try_from(end - start).map_err(|_| not_read())?)
            .ok_or_else(not_read)?;
        let returns: Vec<u64> = code
            .chunks_exact(4)
            .enumerate()
            .filter(|(_, word)| {
                u32::from_le_bytes([word[0], word[1], word[2], word[3]]) == ARM64_RET
            })
            .filter_map(|(i, _)| elf.file_offset(start + 4 * i as u64))
            .collect();
        if returns.is_empty() {
            return Err(format!(
                "crypto/tls: no return found in {start:#x}..{end:#x}"
            ));
        }
        Ok(EntryAndReturns {
            entry: go_probe_offset(elf, start).ok_or_else(not_read)?,
            returns,
        })
    };
    Ok(Some(GoTls {
        read: probe(read)?,
        write: probe(write)?,
        handshakes: [server, client]
            .into_iter()
            .flatten()
            .map(probe)
            .collect::<Result<_, _>>()?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `go` command of this machine's toolchain, if there is one: it
    /// fetches modules over HTTPS, so its crypto/tls is found, with returns.
    #[test]
    fn a_go_binary_has_its_crypto_tls_found() {
        let Ok(go) = std::process::Command::new("go")
            .args(["env", "GOROOT"])
            .output()
        else {
            return;
        };
        let root = String::from_utf8_lossy(&go.stdout).trim().to_owned();
        let bin = std::path::Path::new(&root).join("bin/go");
        let image = std::fs::read(bin).expect("read");
        let elf = Elf::parse(&image).expect("ELF");
        if elf.machine != EM_AARCH64 {
            assert!(find(&elf).is_err());
            return;
        }
        let found = find(&elf).expect("readable").expect("crypto/tls");
        assert!(
            found.read.returns.len() >= 2 && found.write.returns.len() >= 2,
            "{found:?}"
        );
        // The go command is a client only: the server's handshake is not linked in.
        assert_eq!(found.handshakes.len(), 1, "{found:?}");
        assert!(!found.handshakes[0].returns.is_empty(), "{found:?}");
        // Probed past the stack check, at its b.ls.
        for f in [&found.read, &found.write, &found.handshakes[0]] {
            let at = f.entry as usize;
            let word = u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
            assert_eq!(word & 0xff00_001f, 0x5400_0009, "{found:?}");
        }
        for at in found.read.returns.iter().chain(&found.write.returns) {
            let at = *at as usize;
            assert_eq!(&image[at..at + 4], &ARM64_RET.to_le_bytes());
        }
    }
}
