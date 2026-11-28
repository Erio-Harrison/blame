//! TLS through rustls, user side: where in a Rust binary rustls takes in a
//! record's plaintext and is given plaintext to send. The kernel side is
//! `bpf/tls/rustls.h`.
//!
//! The two functions are rustls 0.23's (`CommonState::take_received_plaintext`
//! and `CommonState::send_appdata_encrypt`); they keep their symbols in
//! release builds with fat or thin LTO and one codegen unit. rustls 0.22 and
//! older inline them: their binaries are said to be not read.

use crate::runtime::elf::{Elf, find as contains};

/// Where rustls's plaintext is handed over: offsets in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rustls {
    pub received: Vec<u64>,
    pub sent: Vec<u64>,
}

/// A symbol (v0 or legacy mangling) of the method `method` (with its length
/// prefix) of rustls's `common_state::CommonState`.
fn is_common_state(name: &[u8], method: &[u8]) -> bool {
    let name = match contains(name, b".llvm.") {
        Some(at) => &name[..at],
        None => name,
    };
    if name.starts_with(b"_RNvM") {
        contains(name, b"6rustls12common_state").is_some()
            && name.ends_with(&[b"11CommonState".as_slice(), method].concat())
    } else if let Some(rest) = name.strip_prefix(b"_ZN6rustls12common_state11CommonState") {
        rest.strip_prefix(method)
            .and_then(|rest| rest.strip_prefix(b"17h"))
            .is_some_and(|hash| hash.len() == 17 && hash.ends_with(b"E"))
    } else {
        false
    }
}

/// `Ok(None)`: no rustls in the binary. `Err`: rustls whose plaintext cannot
/// be read here, and why.
pub fn find(elf: &Elf) -> Result<Option<Rustls>, String> {
    let received = elf.functions_where(|name| is_common_state(name, b"23take_received_plaintext"));
    let sent = elf.functions_where(|name| is_common_state(name, b"20send_appdata_encrypt"));
    if received.is_empty() && sent.is_empty() {
        if elf
            .functions(&["6rustls", "process_new_packets"])
            .is_empty()
        {
            return Ok(None);
        }
        return Err(
            "rustls found, but not where 0.23 hands over plaintext: an older rustls, or \
             those functions inlined"
                .into(),
        );
    }
    if received.is_empty() || sent.is_empty() {
        return Err("rustls: only one direction of its plaintext found".into());
    }
    let offsets = |addrs: Vec<u64>| -> Result<Vec<u64>, String> {
        addrs
            .into_iter()
            .map(|addr| {
                elf.file_offset(addr)
                    .ok_or_else(|| format!("rustls: {addr:#x} not in the file"))
            })
            .collect()
    };
    Ok(Some(Rustls {
        received: offsets(received)?,
        sent: offsets(sent)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_methods_are_told_by_their_symbols_in_both_manglings() {
        let rx = b"23take_received_plaintext".as_slice();
        let tx = b"20send_appdata_encrypt".as_slice();
        assert!(is_common_state(
            b"_RNvMNtCs4kD4QdASFI9_6rustls12common_stateNtB2_11CommonState23take_received_plaintext",
            rx
        ));
        assert!(is_common_state(
            b"_RNvMNtCs4kD4QdASFI9_6rustls12common_stateNtB2_11CommonState20send_appdata_encrypt.llvm.123",
            tx
        ));
        assert!(is_common_state(
            b"_ZN6rustls12common_state11CommonState20send_appdata_encrypt17h0123456789abcdefE",
            tx
        ));
        // The server's early data has a method of the same name: not that one.
        assert!(!is_common_state(
            b"_RNvMs_NtNtCs4kD4QdASFI9_6rustls6server11server_connNtB4_14EarlyDataState23take_received_plaintext",
            rx
        ));
        assert!(!is_common_state(
            b"_RNvMNtCs4kD4QdASFI9_6rustls12common_stateNtB2_11CommonState19send_some_plaintext",
            tx
        ));
    }
}
