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
| npro-test, fuzz targets, tools | what testing needs, admitted like anything else; fuzz targets live in their own workspace with their own lock file |
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

Admitted: **none**.  npro builds from its own sources and the Rust
toolchain alone.

| crate | used by | feature | why | build script | unsafe | admitted in |
|---|---|---|---|---|---|---|
| (none yet) | | | | | | |

## Decided, not yet admitted

- **`miniz_oxide`**, with its dependency `adler2`, for permessage-deflate,
  behind npro-ws's opt-in `pmd` feature.  Pure Rust, `no_std` with
  `alloc`.  It is admitted, with its register entry, in the commit that
  adds permessage-deflate.

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
