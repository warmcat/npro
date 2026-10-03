#!/bin/sh
#
# The gates every commit must pass, in the order that fails fastest.
# Run from anywhere in the tree:
#
#   scripts/ci.sh
#
# Set CARGO_TARGET_DIR to keep build output out of the tree.  It checks
# first for everything it uses, and lists what is missing with the commands
# that install it; docs/toolchain.md explains each piece.

set -eu

cd "$(dirname "$0")/.."

msrv=$(sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml)

. scripts/require.sh
require_rust
require_cargo fmt "rustup component add rustfmt"
require_cargo clippy "rustup component add clippy"
require_toolchain "$msrv" "rustup toolchain install $msrv --profile minimal"
require_target thumbv7em-none-eabihf
require_cargo deny "cargo install --locked cargo-deny"
require_cargo audit "cargo install --locked cargo-audit"
require_done

echo "== fmt"
cargo fmt --all --check

echo "== clippy"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo clippy --workspace --all-targets --locked -- -D warnings

echo "== test"
cargo test --workspace --all-features --locked

echo "== doc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked

echo "== msrv $msrv"
cargo "+$msrv" check --workspace --all-targets --all-features --locked

echo "== no_std"
# the sans-IO crates must build for a target with no std at all
for c in npro-core; do
	cargo build -p "$c" --all-features --target thumbv7em-none-eabihf --locked
done

echo "== deny"
cargo deny --all-features check

echo "== audit"
cargo audit --deny warnings

echo "== all gates passed"
