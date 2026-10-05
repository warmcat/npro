# Dependencies

npro is built so that what runs in your program is what you chose to put
there.  The protocol crates depend on nothing but `core`, and `alloc` where
a feature asks for it.  Anything else enters by a decision, made once,
written down here, and enforced on every commit.

This is a foundation of the project, not a preference.  Each crate in a
dependency tree is code you ship, and its authors are people you trust
with your users' bytes and your build machines.  A tree that grows by
default, a crate at a time, ends up trusting hundreds of people for
things a few lines would have done.  npro takes the other path: a very
small set of chosen dependencies, each worth what it costs.

That does not mean writing everything ourselves.  Where a crate does a
hard job well, such as an async runtime or a TLS stack, npro integrates
with it rather than competing with it, behind a feature or in an adapter
crate that only the people who want it build.

## The door

[`deny.toml`](../deny.toml) at the top of the tree is the door, and
`cargo deny check` is the bouncer.  `scripts/ci.sh` runs it on every
commit, and sai runs it on every push.

- **`[bans] allow`** names every crate that may appear anywhere in the
  build graph.  Any other crate fails the gate, however deep in the tree
  it sits.  A crate admitted for one job does not get to bring its own
  guests: each of its dependencies needs its own entry, and its own line
  in the register below.
- **`[bans.build] allow-build-scripts`** names the crates that may have a
  build script, code that runs on the build machine at compile time.  A
  crate with one fails the gate unless it is named there as well.
- **`executables` and `interpreted`** fail the gate if a crate ships
  prebuilt binaries or scripts.
- **`[licenses] allow`** admits only MIT.  A crate offered as
  `MIT OR Apache-2.0` passes; one only under another licence needs that
  licence admitted too, as part of the same decision.
- **`multiple-versions = "deny"`**: one version of each crate.
- **`[sources]`**: crates.io only, no git or other registries.
- **`cargo audit`** (also in `ci.sh`) fails the gate on any RustSec
  advisory against a crate in the tree.

The graph checked is the whole one: every crate, every feature, every
platform, and dev-dependencies too.  Tests and tools run on developers'
machines and builders, so they are let in on the same terms.

cargo deny treats an empty allowlist as no allowlist, so the list also
names the workspace's own crates.  That keeps it in force while nothing
else is on it.  A new workspace crate is added to it when it is created.

## Where dependencies may live

| crates | may depend on |
|---|---|
| the protocol crates: npro-core, -h1, -ws, -h2, -h3, -quic, -wt, -mqtt, -http | nothing, except crates agreed below, each behind an opt-in feature, `no_std`, and with no build script |
| npro-io, the IO adapter | std, and what its tls decision admits |
| integrations with a runtime or framework, such as tokio | that runtime, in its own opt-in crate or feature, never a default |
| npro-test, npro-fuzz, tools | what testing needs, admitted like anything else |
| the libFuzzer targets in `fuzz/` | libFuzzer and what builds it, in a workspace of their own with its own `Cargo.lock` and `deny.toml`, so none of it enters the main workspace's graph |
| npro, the facade | the npro crates only |

A protocol crate never depends on an IO crate, an async runtime, or a
crate that does IO.  Time and random are inputs, not dependencies.

## Admitting a crate

1. Ask first.  A new dependency is a design decision for the maintainer,
   not a step in implementing something.
2. In its own commit, add it to the `Cargo.toml` that needs it, behind a
   feature unless it is needed by every build.
3. Run `cargo deny --all-features check bans`.  It names every crate the
   addition brings in, and every one with a build script.  Each of those
   is part of the decision too.
4. Add each crate to `allow` in `deny.toml`, and to
   `allow-build-scripts` if it has one, with a comment naming it here.
5. Add each to the register below.
6. Say in the commit message why it is worth having, covering what the
   register asks for.

What the register records for each crate, and what decides it:

- **What it is for**, and what doing without it would cost.
- **Who maintains it**, and how actively.
- **Its unsafe code**: none, or how much, where, and why that is
  acceptable.
- **Its build script and proc-macros**, if any, and what they do.  A build
  script that touches the network is refused.
- **Its MSRV**, which must be no newer than npro's `rust-version`.
- **`no_std`**, for anything a protocol crate uses.
- **Its licence.**
- **What it brings with it.**

Removing a dependency is the same in reverse: take it out of
`Cargo.toml`, `deny.toml` and the register, in one commit.

## The register

### The main workspace

Without the opt-in features below, npro builds from its own sources and
the Rust toolchain alone.

| crate | used by | feature | why | build script | unsafe | admitted in |
|---|---|---|---|---|---|---|
| `miniz_oxide` 0.9 | npro-ws | `pmd` | permessage-deflate's inflater and deflater (RFC 1951 raw deflate), where C uses zlib.  An inflater of our own was the alternative, judged not worth it for a first pass; a deflater as well would be more again.  Maintained by oyvindln under the Frommi organisation, actively, and used by Rust's own standard library (its `rustc-dep-of-std` feature), so it is well exercised.  `no_std`, needing `alloc` (`with-alloc`); edition 2021, building at npro's `rust-version` | none | none: `#![forbid(unsafe_code)]` | the commit adding permessage-deflate's dependency |
| `adler2` 2.0 | `miniz_oxide` | (`pmd`) | the Adler-32 checksum, which `miniz_oxide` needs for zlib streams; ws uses raw deflate, so it is only carried.  The same maintainer, a maintained fork of `adler` | none | none: `#![forbid(unsafe_code)]` | the same |

Both are licensed MIT among alternatives (`miniz_oxide` MIT OR Zlib OR
Apache-2.0, `adler2` 0BSD OR MIT OR Apache-2.0), and bring nothing else:
their other dependencies are optional, and not enabled.

### The fuzz workspace

`fuzz/` builds the libFuzzer targets ([fuzzing.md](fuzzing.md)) and
nothing else; no npro crate depends on it.  Its door is `fuzz/deny.toml`,
which `scripts/fuzz.sh` checks before it builds anything.  It checks the
Linux graph only, since that is where fuzzing runs: on Windows,
`jobserver` would also bring `getrandom`, `r-efi` and `cfg-if`.

The choice was between this, the standard Rust route, and linking the
builder's own libFuzzer runtime through a shim of npro's own.  The shim
would have admitted no crates, but needed `unsafe` code in npro to turn
libFuzzer's pointer and length into a slice; npro took the crates, so
that none of its own code needs qualifying as safe.

| crate | why | build script | unsafe | licence |
|---|---|---|---|---|
| `libfuzzer-sys` 0.4.13 | the `fuzz_target!` macro, and libFuzzer's runtime, whose C++ sources it carries | compiles those sources with `cc`; nothing else, and no network | the macro's entry point, taking libFuzzer's pointer and length | (MIT or Apache-2.0) and **NCSA**, the LLVM licence of libFuzzer's sources, admitted for this workspace only |
| `arbitrary` | a dependency of `libfuzzer-sys`, for targets taking structured input; npro's take bytes | none.  It ships its maintainer's `publish.sh`, never run by a build, admitted by checksum | some | MIT or Apache-2.0 |
| `cc` | compiles libFuzzer, from `libfuzzer-sys`' build script | none | some | MIT or Apache-2.0 |
| `find-msvc-tools` | split out of `cc` | none | some | MIT or Apache-2.0 |
| `jobserver` | `cc`'s share of cargo's parallel jobs | none | some | MIT or Apache-2.0 |
| `libc` | `jobserver` and `cc` on unix | probes the rustc version, no network | the C bindings it is for | MIT or Apache-2.0 |
| `shlex` | `cc`'s parsing of compiler flags from the environment | none | a little | MIT or Apache-2.0 |

Apart from `libfuzzer-sys` and `arbitrary`, which are linked into the
targets, they are build-time only: they run on the fuzz builder while the
targets build.  All were admitted
in the commit adding the libFuzzer targets.

## Decided against

- **`rand`**: random is an input the caller provides
  (`npro_core::random::Random`).
- **`serde`**: the test transcripts are read by a small strict reader in
  npro-test.  Nothing else in npro needs a serialisation framework.
- **SHA-1 and base64 crates**: the ws handshake's needs are about 150
  lines, written in npro-core and checked against the RFC vectors.
- **`proptest` and similar**: property tests are written over npro-core's
  seeded generator, which also reproduces C's random draws.
- **An async runtime in any protocol crate**: integrations live outside
  them.

## Open

- **tls**, for npro-io.  rustls is the obvious candidate, but it needs a
  crypto backend, and its usual ones (`ring`, `aws-lc-rs`) carry C and
  assembly with build scripts.  The alternatives are adapters to the
  platform's tls or to OpenSSL.  This is decided when npro-io needs it
  (phase 1g and after, in [port-plan.md](port-plan.md)), and recorded
  here.
