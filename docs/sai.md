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
| `fuzz` | `fuzz 60` | fuzz-debian13 x86_64 | no known bug still crashes, and a minute of libFuzzer on each fuzz target finds nothing new; two idle tasks carry on fuzzing in idle time, with the corpora in the `fuzz` pool ([fuzzing.md](fuzzing.md)) |

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
| fuzz-debian13 x86_64 | `fuzz`, and its idle tasks | rustup with stable and nightly, cargo-fuzz, cargo-deny, a C++ compiler and llvm-symbolizer, and an `idle` object for the platform in the builder's configuration: see below |
| w11/x86_64 | `test-windows` | rustup with stable for the MSVC host, and an `env` for the platform in the builder's configuration: see below |

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

**The fuzz builder**, the C tree's `fuzz-linux-debian13/x86_64-amd/gcc`,
which already has clang for C's fuzzing.  As `sai`, after rustup:

```sh
rustup toolchain install nightly --profile minimal   # cargo-fuzz builds with nightly
cargo install --locked cargo-fuzz cargo-deny
```

and, as root, what libFuzzer's runtime is built with, and what turns the
sanitizer's addresses into function names:

```sh
apt install g++ llvm      # llvm provides llvm-symbolizer
```

`scripts/fuzz.sh` also finds a versioned `llvm-symbolizer-NN` if that is
all there is.  Without one, reports have addresses but no function names,
and sai-server cannot tell one bug from another.

For the idle tasks, the platform in the builder's configuration needs an
`idle` object (sai's `READMEs/README-idle.md`).  It belongs to the
platform, so if C's fuzzing idle tasks already have one there, it serves
npro's too; otherwise, eg:

```json
"idle": {
	"share":	50,
	"instances":	2,
	"slice-secs":	900
}
```

With 900 second slices, every target gets a turn in each slice.

**The Windows builder.**  rustup's Windows installer is `rustup-init.exe`,
from <https://rustup.rs>:
<https://win.rustup.rs/x86_64> redirects to
<https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe>,
with its checksum beside it at the same URL plus `.sha256`
(`certutil -hashfile rustup-init.exe SHA256` to compare).
`winget install Rustlang.Rustup` fetches the same thing.

sai-builder does not pass its own environment to a job: on Windows, as
on unix, the job starts with only a fixed `PATH`, `LANG` and `TERM`, plus
`HOME` and the `SAI_*` variables.  So the system `PATH` does not reach it,
and everything cargo needs is set per platform in the builder's
configuration instead (below).  rustup goes in a fixed place outside any
profile.  From an administrator PowerShell:

```powershell
$env:RUSTUP_HOME = 'C:\rust\rustup'
$env:CARGO_HOME = 'C:\rust\cargo'
.\rustup-init.exe -y --default-host x86_64-pc-windows-msvc --profile default --no-modify-path
```

In `cmd`, the two `$env:` lines are `set RUSTUP_HOME=C:\rust\rustup` and
`set CARGO_HOME=C:\rust\cargo`.  Do not use those `set` lines in
PowerShell: there `set` makes a PowerShell variable, not an environment
variable, and rustup then installs under `%USERPROFILE%` as usual.  The
installer ends by printing where it installed; it should say `C:\rust`.

The account the jobs run as must be able to read `C:\rust\rustup` and
write `C:\rust\cargo`, where cargo keeps its package cache and the lock on
it.  For an ordinary account, here `sai`:

```powershell
icacls C:\rust\rustup /grant 'sai:(OI)(CI)RX' /T
icacls C:\rust\cargo /grant 'sai:(OI)(CI)M' /T
```

Then give the platform an `env` in the builder's configuration file.  It
is JSON, so every backslash is doubled: a single one is read as an escape,
and `\r` in `C:\rust\rustup` becomes a carriage return.

```json
{
	"name":	"w11/x86_64-amd/msvc",
	"env": [
		"PATH=c:\\rust\\cargo\\bin;c:\\Windows\\System32;c:\\Windows",
		"RUSTUP_HOME=c:\\rust\\rustup",
		"CARGO_HOME=c:\\rust\\cargo",
		"SystemRoot=c:\\Windows",
		"TEMP=c:\\Users\\sai.sai-vm\\AppData\\Local\\Temp",
		"TMP=c:\\Users\\sai.sai-vm\\AppData\\Local\\Temp"
	],
	...
}
```

- `PATH`: rustup's `cargo` first, then the system's own programs.
- `RUSTUP_HOME`, `CARGO_HOME`: without them `cargo` looks for its
  toolchains under the profile, and finds none.
- `SystemRoot`: much of Win32, sockets and crypto among it, fails
  without it.
- `TEMP`, `TMP`: where rustc and `link.exe` write temporary files.  They
  must be in the profile of the account the jobs run as, which need not
  be named after it: here the jobs run in `C:\Users\sai.sai-vm`, and
  `link.exe` failed with `LNK1104: cannot open file '...\Temp\lnk{...}.tmp'`
  while they pointed at `C:\Users\sai`.

The linker is MSVC's `link.exe`, from the Visual Studio Build Tools the
builder already has for building C lws.  rustc finds Visual Studio
itself, so none of its variables (`LIB`, `INCLUDE`, `VCINSTALLDIR`) are
needed in `env`.

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
- `fuzz` fetches the fuzz workspace's dependencies from crates.io, as
  `fuzz/Cargo.lock` pins them (`cargo fetch --locked`), once per builder.
  The pool is synced by sai-builder itself, not the job.

Nothing else fetches.  The main workspace has no dependencies, and every
build is `--locked`.

### When a job fails on setup

| what the job log shows | why | fix |
|---|---|---|
| `rustc 1.75 is older than npro's rust-version 1.85`, or cargo's `` `resolver` setting `3` is not valid `` | the job found the distro's cargo: rustup is not installed for `sai` | install rustup as `sai`, as above |
| `no such command: hack` (or `deny`, `audit`) | the cargo subcommand is not installed for `sai` | `cargo install --locked cargo-hack` (etc.) as `sai` |
| `toolchain '1.85-…' is not installed` | the MSRV toolchain is missing | `rustup toolchain install 1.85 --profile minimal` as `sai` |
| `no such command: fuzz` | cargo-fuzz is not installed for `sai` | `cargo install --locked cargo-fuzz` as `sai` |
| something installed earlier is missing again | it was installed inside a sai-virt overlay, not the base image | install it into the base image |
| Miri spends minutes "preparing a sysroot" every job | Miri's std is rebuilt in each fresh overlay | `cargo +nightly miri setup --target …` in the base image |

### Notes on particular builders

- **ubuntu-noble/riscv64** stays on Ubuntu 24.04.  From 25.10 on, Ubuntu
  supports only RISC-V hardware meeting a newer profile, which this
  board's silicon does not.  rustup supports it as it is.
- **esp32**, later: xtensa needs Espressif's Rust fork, installed with
  `espup`, once there is something to run on the device.

## A possible sai change

Nothing here needs sai changed.  A neutral name for the configuration
key, such as `build` beside `cmake`, would make npro's `.sai.json` read
better, but `cmake` does the job as it is.
