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

## Setting up a builder

[toolchain.md](toolchain.md) explains the pieces: rustup, toolchains,
components, targets, and cargo subcommands.  This section says which ones
each builder needs, and the things that are particular to sai.

### Install as the user sai runs jobs as

sai runs each job as the builder's user (`sai`), with `HOME` set to that
user's home, and `scripts/sai.sh` puts `$HOME/.cargo/bin` first on `PATH`.
So rustup must be installed **for that user**.  An install for your own
login, or for root, is invisible to the jobs.

```sh
sudo -iu sai          # a login shell as sai, with its HOME
```

On a builder whose jobs run in **sai-virt overlays** of a base VM image,
install into the base image, by booting the base itself, while no job is
using an overlay of it.  Anything installed inside a job's overlay goes
away with the overlay.  Shut the base down cleanly afterwards, and let
sai-virt make fresh overlays: an overlay made from the old base must not
be used with the new one.

Size the base for what the jobs build.  The fedora44 builder, with
everything below installed, filled a 10 GB root; 40 GB is comfortable.
After growing a base image, raise sai-virt's overlay size to match:
`"overlay_size"` in the platform's file in `/etc/sai/virt/conf.d/`, which
is 20G if not given.  The overlay must be at least the base's virtual
size; a smaller one leaves the guest's LVM unable to activate, and the job
VM hangs at boot just after `Started systemd-journald.service`.  The
overlays live in `/dev/shm`, so they take RAM as jobs write to them, not
disk.

### What each builder needs

| builder | configurations | needs |
|---|---|---|
| x86_64 and aarch64 Linux, riscv64, both macOS | `test` | rustup with stable (`--profile default`) |
| fedora44 x86_64 | `gate`, `features`, `nostd`, `miri-*`, `c-oracle` | everything below |
| freebsd/aarch64 | `test-freebsd` | `pkg install rust`, 1.85 or later; rustup has no FreeBSD aarch64 host |
| w11/x86_64 | `test-windows` | rustup with stable for the MSVC host, on the sai service's `PATH`: see below |

**Every builder with rustup**, as the `sai` user:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile default
```

Or install the distro's `rustup` package, then run `rustup default stable`
as `sai`; [toolchain.md](toolchain.md) covers both routes.  Do not rely on
distro `cargo` / `rustc` packages: Ubuntu 24.04's 1.75 is too old to read
the workspace.  On macOS, the Xcode command line tools provide the linker.

**The fedora44 builder**, on top of that, as `sai`:

```sh
rustup toolchain install 1.85 --profile minimal                               # gate: the MSRV build
rustup toolchain install nightly --profile minimal --component miri,rust-src  # miri-*
rustup target add thumbv6m-none-eabi thumbv7em-none-eabihf riscv32imc-unknown-none-elf   # nostd, gate
cargo install --locked cargo-hack cargo-deny cargo-audit                       # features, gate
cargo +nightly miri setup --target s390x-unknown-linux-gnu                     # build Miri's std once
cargo +nightly miri setup --target i686-unknown-linux-gnu
```

and, as root, for the C build `c-oracle` does:

```sh
dnf install git cmake make gcc zlib-devel
```

Miri builds a standard library for each target it interprets.
`miri setup` does it once ahead of time; otherwise every job on a fresh
overlay spends several minutes on it.

**The Windows builder.**  rustup's Windows installer is `rustup-init.exe`,
from <https://rustup.rs>:
<https://win.rustup.rs/x86_64> redirects to
<https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe>,
with its checksum beside it at the same URL plus `.sha256`
(`certutil -hashfile rustup-init.exe SHA256` to compare).
`winget install Rustlang.Rustup` fetches the same thing.

The job step runs a bare `cargo`, so cargo must be on the `PATH` the sai
builder service starts with.  rustup normally installs per user and adds
its `bin` to that user's `PATH` only, which a service running as
LocalSystem never sees.  Install it to a fixed place and put that on the
system `PATH` instead.  `setx /M` sets them for processes started later,
so the installer also needs them set in the shell it runs from.  From an
administrator PowerShell:

```powershell
setx /M RUSTUP_HOME C:\rust\rustup
setx /M CARGO_HOME C:\rust\cargo
$env:RUSTUP_HOME = 'C:\rust\rustup'
$env:CARGO_HOME = 'C:\rust\cargo'
.\rustup-init.exe -y --default-host x86_64-pc-windows-msvc --profile default --no-modify-path
```

In `cmd`, the two `$env:` lines are `set RUSTUP_HOME=C:\rust\rustup` and
`set CARGO_HOME=C:\rust\cargo`.  Do not use those `set` lines in
PowerShell: there `set` makes a PowerShell variable, not an environment
variable, and rustup then installs under `%USERPROFILE%` as usual.  The
installer ends by printing where it installed; it should say `C:\rust`.

then add `C:\rust\cargo\bin` to the system `PATH` (System Properties →
Environment Variables), and reboot: services only see a changed system
environment after one.  If the service account is not an administrator,
give it read access to `C:\rust`, and write access to
`C:\rust\cargo\registry`, where cargo would cache downloaded crates.

The linker is MSVC's `link.exe`, from the Visual Studio Build Tools the
builder already has for building C lws.  `rustup-init.exe` warns if it
cannot find them.  As the service's account (or in a new administrator
`cmd`), `cargo --version` should then print 1.85 or later.

### Checking a builder

As `sai`:

```sh
rustc --version                    # 1.85 or later
rustup toolchain list              # fedora44: stable, 1.85, nightly
rustup target list --installed     # fedora44: the three no_std targets
cargo hack --version; cargo deny --version; cargo audit --version   # fedora44
```

Each profile in `scripts/sai.sh` also checks for exactly what it uses
before running.  A job on a builder that lacks something fails at once,
listing what is missing and the command for each, rather than partway
through with a cargo error.

### Network access during jobs

- `cargo audit` (in `gate`) fetches the RustSec advisory database from
  github.com.
- `c-oracle` clones and fetches libwebsockets from libwebsockets.org,
  keeping its checkout in `$HOME/lws-oracle` (or `$LWS_ORACLE`).

Nothing else fetches.  The workspace has no dependencies, and every build
is `--locked`.

### When a job fails on setup

| what the job log shows | why | fix |
|---|---|---|
| `rustc 1.75 is older than npro's rust-version 1.85`, or cargo's `` `resolver` setting `3` is not valid `` | the job found the distro's cargo: rustup is not installed for `sai` | install rustup as `sai`, as above |
| `no such command: hack` (or `deny`, `audit`) | the cargo subcommand is not installed for `sai` | `cargo install --locked cargo-hack` (etc.) as `sai` |
| `toolchain '1.85-…' is not installed` | the MSRV toolchain is missing | `rustup toolchain install 1.85 --profile minimal` as `sai` |
| something installed earlier is missing again | it was installed inside a sai-virt overlay, not the base image | install it into the base image |
| Miri spends minutes "preparing a sysroot" every job | Miri's std is rebuilt in each fresh overlay | `cargo +nightly miri setup --target …` in the base image |

### Notes on particular builders

- **ubuntu-noble/riscv64** stays on Ubuntu 24.04.  From 25.10 on, Ubuntu
  supports only RISC-V hardware meeting a newer profile, which this
  board's silicon does not.  rustup supports it as it is.
- **esp32**, later: xtensa needs Espressif's Rust fork, installed with
  `espup`, once there is something to run on the device.
- **fuzzing**, later: cargo-fuzz needs nightly and clang, and joins the
  fuzz builder with the h1 parser's fuzz targets.

## A possible sai change

Nothing here needs sai changed.  A neutral name for the configuration
key, such as `build` beside `cmake`, would make npro's `.sai.json` read
better, but `cmake` does the job as it is.
