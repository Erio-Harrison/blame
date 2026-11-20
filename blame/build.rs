use std::{env, path::PathBuf};

use anyhow::Context as _;
use libbpf_cargo::SkeletonBuilder;

const SRC_DIR: &str = "src/bpf";
const SRC: &str = "src/bpf/blame.bpf.c";

/// Compile the eBPF programs with clang and generate the Rust skeleton that
/// embeds the object and gives typed access to its maps, programs and globals.
fn main() -> anyhow::Result<()> {
    let out = PathBuf::from(env::var_os("OUT_DIR").context("OUT_DIR not set")?);
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-Wall", "-Werror", "-mcpu=v3"])
        .build_and_generate(out.join("blame.skel.rs"))
        .context("building the eBPF object; is clang installed?")?;
    println!("cargo:rerun-if-changed={SRC_DIR}");
    Ok(())
}
