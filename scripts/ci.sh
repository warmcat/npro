#!/bin/sh
#
# The gates every commit must pass, in the order that fails fastest.
# Run from anywhere in the tree:
#
#   scripts/ci.sh
#
# Set CARGO_TARGET_DIR to keep build output out of the tree.  The MSRV build
# needs the toolchain named in Cargo.toml's rust-version (rustup toolchain
# install 1.85 --profile minimal); cargo-deny and cargo-audit must be
# installed, and the no_std check needs the thumbv7em-none-eabihf target
# (rustup target add thumbv7em-none-eabihf).

set -eu

cd "$(dirname "$0")/.."

msrv=$(sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml)

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
