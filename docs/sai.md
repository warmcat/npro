# npro on sai

`.sai.json` uses the C tree's platform names, so a builder that already
serves libwebsockets serves npro too once it has a Rust toolchain.  This is
what each one needs, and what each configuration checks.

## How the config is shaped

sai's step template substitutes three variables, `${prep}`, `${cmake}` and
`${cpack}`, so the name `cmake` is sai's and not a build system's.  Every
unix platform has one step, `scripts/sai.sh ${cmake}`.  Each configuration's
`cmake` names a profile in that script:

| configuration | profile | platforms | what it shows |
|---|---|---|---|
| `test` | `test` | every default platform: x86_64 and aarch64 Linux, riscv64, macOS on intel and apple silicon | the tests pass natively there |
| `test-freebsd` | `test` | freebsd/aarch64 | the same, with FreeBSD's packaged Rust |
| `test-windows` | (its own step) | w11/x86_64 | the same, under MSVC |
| `gate` | `gate` | fedora44 x86_64 | everything `scripts/ci.sh` checks: fmt, clippy, tests, docs, the MSRV build, the no_std build, cargo deny, cargo audit |
| `features` | `features` | fedora44 x86_64 | clippy over every combination of every crate's features |
| `nostd` | `nostd` | fedora44 x86_64 | the sans-IO crates build for cortex-m0 (no atomics), cortex-m4f and riscv32imc |
| `miri-big-endian` | `miri s390x-unknown-linux-gnu` | fedora44 x86_64 | the tests pass on a big-endian machine, interpreted by Miri |
| `miri-32bit` | `miri i686-unknown-linux-gnu` | fedora44 x86_64 | the tests pass where `usize` is 32 bits |
| `c-oracle` | `oracle` | fedora44 x86_64 | C lws main-dev, built afresh, records the same transcripts npro holds |

How the C build's dimensions map here:
- **The `cmake` option dimensions** become the `features` configuration.
  cargo-hack builds every combination of features, so no configuration
  per combination is written.
- **Platforms stay platforms.**
- **Machines sai has no builder for**, big-endian and 32-bit, are
  interpreted by Miri rather than run on hardware.

## Installing Rust on a builder

Install as the user the sai builder runs jobs as.  sai sets `HOME` to the
builder's home for each job, and `scripts/sai.sh` puts `$HOME/.cargo/bin`
first on `PATH`, so rustup's usual per-user install is found without
changing the builder daemon's environment.

### Every unix builder with rustup

These are the Linux builders (x86_64, aarch64 and riscv64) and the macOS
ones.  rustup provides host toolchains for all of them.  A C linker must
be present: it is already, as these builders build C lws.  On macOS that
means the Xcode command line tools.

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile default
```

That gives stable with rustfmt and clippy, which is all the `test`
profile needs.  Updating later is `rustup update`.

### The fedora44 x86_64 builder, which runs everything else

On top of the above:

```sh
rustup toolchain install 1.85 --profile minimal          # the MSRV build
rustup toolchain install nightly --profile minimal --component miri,rust-src
rustup target add thumbv6m-none-eabi thumbv7em-none-eabihf riscv32imc-unknown-none-elf
cargo install --locked cargo-deny cargo-audit cargo-hack
dnf install cmake gcc zlib-devel git                   # the C oracle build
```

The first Miri run of each target builds that target's standard library
for Miri, and takes a few minutes.  Later runs reuse it.

Network access during jobs:
- `cargo audit` fetches the RustSec advisory database from github.com on
  each run;
- the oracle clones and fetches libwebsockets from libwebsockets.org,
  keeping its checkout in `$HOME/lws-oracle` (or `$LWS_ORACLE`).

Nothing else fetches.  The workspace has no dependencies, and every build
is `--locked`.

### freebsd/aarch64

rustup has no host toolchain for aarch64 FreeBSD, so use the packaged one,
which must be at least the workspace's `rust-version` (1.85):

```sh
pkg install rust
```

It installs under `/usr/local/bin`, which the builder's `PATH` already has.

### w11/x86_64 (MSVC)

Run `rustup-init.exe` from <https://rustup.rs> with the default host,
`x86_64-pc-windows-msvc`; the builder already has the Visual Studio build
tools it links with.  Do it as the account the sai builder service runs
as, and make sure that account's `%USERPROFILE%\.cargo\bin` is on the
service's `PATH`, since the Windows step runs `cargo` directly under
`cmd`.

### Later

- **esp32**: building for the ESP32's xtensa cores needs Espressif's Rust
  fork, installed with `espup`.  That waits until there is something to
  run on the device.
- **fuzzing**: cargo-fuzz needs nightly and clang.  It joins the fuzz
  builder once the h1 parser has fuzz targets.

## A possible sai change

Nothing here needs sai changed.  A neutral name for the configuration
key, such as `build` beside `cmake`, would make npro's `.sai.json` read
better, but `cmake` does the job as it is.
