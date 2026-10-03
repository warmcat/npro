# lws AGENTS.md

## Overview

Please err on the side of high quality, not lazy, implementation decisions, because the code
will have to be maintained for a long time.  Everybody, LLM or person, is able to work
better if we keep the code clean and to a high standard to start with.

Even if your instructions don't include specific admonishment about quality, it is always
necessary.  Lws started in 2010 in C, now also in Rust, the main goal when working on a
feature is to improve the library with the feature.  That means shortcuts and desperate
incomplete hacks to deliver the feature are always wrong.

Our work should follow the existing usage of apis in the project as much as possible.

## Context

Read docs/agent-context.md before starting: it distils what was learned working on the C
library with agents, the decisions already taken for this project, and where the C design
documents are.

## Interacting

We will be working on the same sources, do not build into ./build since I will be using it; make
your own ./build-claude or whatever.

Often although we are working on the same sources, they are being tested on devices you don't have
access to.  So you must ask for access to data state on those remote machines; looking at the local
machine you are running on for config or data state directly is of zero use in those circumstances.

## Churn management

When you produced fixes, if possible (main branch, target is within 8 patches back,
no intervening non-sai- tag) it's preferable to --amend apply the fixes directly to
the patch that originated the problem, essentially editing the history, even if
it means just doing that and not adding any fix patch or explanation.  Similarly, unless
asked to produce a new patch or the goal is an explicit phased series, if it's on the
main branch and we are iterating on the same work, and HEAD patch is yours from the
last iteration, it's preferable to directly use --amend on it to commit.

If the changes are for mixed purposes, if you initiate new core library changes or fixes,
these should be broken out into their own patch, even if the rest relates to recent
changes and is squashed in with those.

## Completeness

If you are unable to complete something your coding partner expects from the interaction
with you, you must clearly explain to the user which parts are incomplete in this phase and need
further work.  DO NOT leave it silently incomplete and act like it is done without making the
situation crystal clear to your partner.

Often adding / modifying or removing features has a very strong expectation that you will
also take responsibility about certain side-effects.  For example, adding a switch to a

minimal example always means modifying the associated --help and the example's markdown
accordingly.  If we add significant new code, it must also bring with it api-test or other
example code to confirm it works properly.  These side-effects are expected to be taken
care of in the same phase of work, not "later", and even if not explicitly requested.

## Example code

The examples are not chaotic dumping grounds for trash.  They are supposed to show the user
the best way we know how to do things, that they can use in their own code reliably.  We
should make an extra effort to keep them clean and as quality exemplars.
 
## Rust coding

We are very concerned about:

  - security, architecturally and in the code
  - portability
  - cleanliness and hygiene of code
  - testing from several directions, static analysis and audits to
    discover problems before attackers do

 - Every crate root carries `#![forbid(unsafe_code)]`.  Not `deny`: `forbid`
   cannot be re-allowed further down the file.  No `unsafe` blocks, no `-sys`
   crates, no FFI in the protocol crates.  If bindings to C are ever wanted
   they are a separate crate that is not a dependency of anything here.

 - A panic is a bug, not error handling.  Nothing reachable from network
   data may `unwrap()`, `expect()`, index a slice with `[]`, or hit
   `unreachable!()`.  Errors are returned as `Result` with a small error
   enum per crate, never `String` or `Box<dyn Error>`.  Arithmetic on
   lengths and offsets is `checked_*` or `saturating_*`; integer narrowing is
   `try_from`, never `as`.  On a device a panic is a reboot; on a server it
   is a remotely triggered abort.

 - The core crates are `#![no_std]`, with `alloc` only where a feature
   turns it on.  No `std::io`, `std::net`, threads, `Instant`, or `async`
   in a protocol crate.  Bytes come in as caller-owned `&[u8]`, output is
   written into caller-owned `&mut [u8]`, and time is passed in as a value
   from the adapter.  Sockets, tls and the event loop live in the IO
   adapter crate and nowhere else.

 - State lives in enums, not bools.  Each machine from the C state tables
   is an `enum` whose variants carry the data that only exists in that
   state; a `match` on state has no `_ =>` arm; no `Option` that is
   "always Some when we are in state X"; no flag that duplicates something
   the state already says.  Ids and sizes are newtypes (`StreamId`, not
   `u32`).  If a field can be set to something the state forbids, it is not
   `pub`.

 - Every buffer, queue, table and header set has a declared maximum, and no
   parser recurses on external input.  Depth and size limits are part of
   the type or the config, not a comment.

 - Dependencies are close to zero and each one is justified in the commit
   adding it: MSRV-compatible, no `build.rs` that touches the network, no
   large proc-macro trees behind the core.  `cargo deny` and `cargo audit`
   configs are committed and gate CI.  Default features are the minimum
   that builds something useful; everything else is opt-in.  `deny.toml`
   admits crates only by name, transitive ones included: a new dependency
   is the maintainer's decision, asked for first, and follows
   docs/dependencies.md, which is its register.

 - No `Rc<RefCell<_>>` or `Arc<Mutex<_>>` inside the protocol crates.
   Interior mutability in the core means the ownership of the design is
   wrong; fix the design.  Whether things are `Send` is the adapter's
   decision.

 - CI gates, all with warnings as errors: `cargo fmt --check`,
   `cargo clippy --all-targets --all-features -D warnings` with
   `clippy::unwrap_used`, `expect_used`, `indexing_slicing`,
   `arithmetic_side_effects` and `as_conversions` enabled in the core,
   `cargo doc` with `missing_docs` denied on public items,
   `cargo semver-checks` on release, and a build at the pinned
   `rust-version`.  A lint is silenced only with an `#[allow]` on the one
   item, carrying a reason.

 - Tests are part of the feature.  Every parser has a `cargo-fuzz` target
   seeded from the C corpus; state machines get property tests; public
   behaviour gets doctests, which compile and run.  Where the C library
   has the same input, a differential test against it is expected.

 - Public API follows the Rust API guidelines: no `get_` prefixes, no
   out-parameters, `#[must_use]` on anything returning a `Result` or a
   value the caller must act on, and rustdoc on every public item with an
   example.

 - `unexpected_cfgs` must be a denied lint

 - Cargo features must stay additive: a feature that removes or changes
   behaviour breaks any dependent that enables a different set
