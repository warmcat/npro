#!/bin/sh
#
# The npro-cli workspace's gates: npro's utility and its runner, which
# binds SS2 to the threads adapter and to rustls over aws-lc.  A workspace
# of its own, as npro-aws-lc is, so aws-lc and caps never enter npro's
# graph; this checks its door and runs its tests, which serve h1 over real
# sockets, plain and over tls.
#
#   scripts/cli.sh
#
# Set CARGO_TARGET_DIR to keep build output out of the tree.  It builds
# npro-aws-lc, so it needs what that does: a C compiler, and on some
# platforms cmake.

set -eu

cd "$(dirname "$0")/.."

. scripts/require.sh
require_rust
require_cargo fmt "rustup component add rustfmt"
require_cargo clippy "rustup component add clippy"
require_cargo deny "cargo install --locked cargo-deny"
require_cmd cc "a C compiler, for aws-lc-sys: your distro's gcc or clang"
require_done

m=npro-cli/Cargo.toml

echo "== cargo deny, npro-cli workspace"
cargo deny --manifest-path "$m" check

echo "== fmt"
cargo fmt --manifest-path "$m" --check

echo "== clippy"
cargo clippy --manifest-path "$m" --all-targets --locked -- -D warnings

echo "== doc"
RUSTDOCFLAGS="-D warnings" cargo doc --manifest-path "$m" --no-deps --locked

echo "== test"
cargo test --manifest-path "$m" --locked

echo "== npro-cli passed"
