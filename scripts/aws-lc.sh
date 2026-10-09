#!/bin/sh
#
# The npro-aws-lc workspace's gates: npro with tls by rustls, aws-lc-rs its
# crypto provider.  A workspace of its own, so aws-lc's C never enters
# npro's graph; this checks its door and runs its tests, which do real tls
# handshakes through npro-io's driver.
#
#   scripts/aws-lc.sh
#
# Set CARGO_TARGET_DIR to keep build output out of the tree.  Building
# aws-lc-sys compiles AWS-LC's C, so a C compiler is needed, and on some
# platforms cmake: see aws-lc-rs' requirements.

set -eu

cd "$(dirname "$0")/.."

. scripts/require.sh
require_rust
require_cargo fmt "rustup component add rustfmt"
require_cargo clippy "rustup component add clippy"
require_cargo deny "cargo install --locked cargo-deny"
require_cmd cc "a C compiler, for aws-lc-sys: your distro's gcc or clang"
require_done

m=npro-aws-lc/Cargo.toml

echo "== cargo deny, npro-aws-lc workspace"
cargo deny --manifest-path "$m" check

echo "== fmt"
cargo fmt --manifest-path "$m" --check

echo "== clippy"
cargo clippy --manifest-path "$m" --all-targets --locked -- -D warnings

echo "== test"
cargo test --manifest-path "$m" --locked

echo "== npro-aws-lc passed"
