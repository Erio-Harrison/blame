#!/usr/bin/env bash
# Local pre-commit check: there is no CI, since the acceptance scenarios need
# root, eBPF and a kernel to try them on.
#
#   tests/check.sh          fast: fmt, clippy, unit tests (no root needed)
#   tests/check.sh --full   also builds the release binary and runs the
#                           acceptance scenarios (they use sudo themselves)
#                           but core_acceptance.sh (CO-RE against fake kernel
#                           layouts, built with clang and llvm-objcopy): that
#                           one is run by hand
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$*"; }

step "cargo fmt --check"
cargo fmt --all -- --check

step "cargo clippy"
cargo clippy --workspace --all-targets -- -D warnings

step "cargo test"
cargo test --workspace

if [[ "${1:-}" == "--full" ]]; then
    step "cargo build --release"
    cargo build --release
    # Every scenario runs, so one failure does not hide the others. They run
    # one after another: each stops the agents it started when it is done.
    failed=()
    for s in tests/scenarios/m0_acceptance.sh tests/scenarios/m1_acceptance.sh \
             tests/scenarios/m2_acceptance.sh tests/scenarios/accuracy_acceptance.sh \
             tests/scenarios/m4_acceptance.sh tests/scenarios/cpu_wait.sh; do
        step "$s"
        bash "$s" || failed+=("$s")
    done
    if (( ${#failed[@]} )); then
        printf '\nfailed: %s\n' "${failed[*]}"
        exit 1
    fi
fi

printf '\nall checks passed\n'
