# Setting up a machine to build npro

This is what a developer machine needs to run `scripts/ci.sh`, the gates
every commit must pass.  A sai builder needs the same pieces, depending on
which configurations it runs: see [sai.md](sai.md).

## The pieces, in C terms

Rust's tools are managed by **rustup**, which installs and switches
between compiler versions per user, under your home directory.  It is
the nearest thing to having several gcc versions and cross sysroots side
by side, with one tool to fetch and select them.

| rustup word | C analogue | example |
|---|---|---|
| toolchain | a compiler release: rustc, cargo, the standard library | `stable`, `1.85`, `nightly` |
| component | an optional tool shipped with a toolchain | `rustfmt` (formatter), `clippy` (lint), `miri` (interpreter) |
| target | a prebuilt standard library for a cross target, like a sysroot | `thumbv7em-none-eabihf` (cortex-m4f, no OS) |

cargo is the build tool.  `cargo <name>` runs a subcommand, and extra ones
are programs called `cargo-<name>` that `cargo install` builds from
source into `~/.cargo/bin`.

## What `scripts/ci.sh` needs, and why

| piece | used by | why |
|---|---|---|
| a current stable toolchain, at least the workspace's `rust-version` (1.85) | everything | the workspace is edition 2024, which older cargo cannot even parse |
| `rustfmt`, `clippy` components | `== fmt`, `== clippy` | formatting and the lint rules AGENTS.md requires |
| the `1.85` toolchain | `== msrv` | proves the code still builds with the oldest release npro supports |
| the `thumbv7em-none-eabihf` target | `== no_std` | proves the sans-IO crates build with no operating system |
| `cargo-deny` | `== deny` | checks licences, duplicate versions and sources of dependencies |
| `cargo-audit` | `== audit` | checks dependencies against the RustSec advisory database |

`ci.sh` checks for all of these before it starts.  If any are missing, it
lists them with the command that installs each.

## Installing

### 1. rustup and the stable toolchain

On Linux and macOS:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile default
. ~/.cargo/env          # or open a new shell; it adds ~/.cargo/bin to PATH
```

`--profile default` includes `rustfmt` and `clippy`.  The `minimal`
profile leaves them out, and `cargo fmt` then fails with "no such
command".

If you would rather not run a script from the network, most distros
package rustup itself.  On Fedora: `dnf install rustup`, then
`rustup-init`.  On Debian 13 and Ubuntu 24.04: `apt install rustup`, then
`rustup default stable`.  Either way, rustup then fetches toolchains from
rust-lang.org over https, and checks them against the release manifest's
checksums.

Do not use the distro's `cargo` and `rustc` packages.  They are usually
older than npro's `rust-version`: Ubuntu 24.04 ships 1.75, which cannot
read the workspace.

### 2. The rest of what ci.sh needs

```sh
rustup toolchain install 1.85 --profile minimal
rustup target add thumbv7em-none-eabihf
cargo install --locked cargo-deny cargo-audit
```

`cargo install` compiles each tool from source, which takes a few
minutes.

### 3. Check it

```sh
rustc --version                   # 1.85 or later
cargo fmt --version; cargo clippy --version
cargo deny --version; cargo audit --version
rustup toolchain list             # stable and 1.85
rustup target list --installed    # includes thumbv7em-none-eabihf
scripts/ci.sh
```

## Where it all lives

- `~/.rustup`: toolchains, components and targets.
- `~/.cargo/bin`: the `cargo`, `rustc` and `rustup` front ends, and
  everything `cargo install` builds.
- `~/.cargo/registry`: downloaded crate sources.  npro has no dependencies
  yet, so this stays small.

The `cargo` in `~/.cargo/bin` picks the toolchain per command:
- `cargo +1.85 check` uses 1.85;
- `cargo +nightly miri test` uses nightly;
- a plain `cargo` uses the default, stable.

## Keeping it current

```sh
rustup update                                          # stable, nightly, and their components
cargo install --locked cargo-deny cargo-audit         # rebuilds a tool if a newer release exists
```

The `1.85` toolchain never changes, which is the point of it.

## When something fails

| what you see | why | fix |
|---|---|---|
| `error: no such command: 'fmt'` (or `clippy`) | the component is missing: a `minimal` rustup profile, or a distro cargo | `rustup component add rustfmt clippy` |
| `` `resolver` setting `3` is not valid `` or "failed to parse manifest" | cargo older than 1.85, usually a distro package found first on `PATH` | install rustup as above, and remove the distro `cargo` / `rustc` |
| `toolchain '1.85-…' is not installed` | the MSRV toolchain is missing | `rustup toolchain install 1.85 --profile minimal` |
| `can't find crate for 'core'` with a `--target` | that target's library is not installed | `rustup target add <target>` |
| `error: no such command: 'deny'` (or `audit`, `hack`) | that cargo subcommand is not installed | `cargo install --locked cargo-<name>` |

## Build output

cargo builds into `./target` unless `CARGO_TARGET_DIR` says otherwise.
To keep two people's builds apart in one tree, as AGENTS.md asks for C's
`./build`, give each their own:

```sh
CARGO_TARGET_DIR=$PWD/target-andy scripts/ci.sh
```
