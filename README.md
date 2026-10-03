# npro

![npro network protocols logo](docs/npro.png)

npro is the Rust port of the sansIO half of
[libwebsockets](https://libwebsockets.org): h1, h2, h3, ws and wt as
entirely `safe`, `no_std` state machines that take bytes and time in,
and give bytes and events out; with an IO crate for sockets, tls
and the event loop along side it.  It's all rust.

[npro Home](https://npro.rs) - [npro Git](https://npro.rs/git/npro) - [npro CI](https://npro.rs/sai)

**Status: in Development**  The workspace and its gates are in place,
and the protocol crates arrive phase by phase as described in
[docs/port-plan.md](docs/port-plan.md).

## How it is written, and how it is checked

npro is maintained alongside C libwebsockets.  It follows the sansIO
refactor of 16 years of libwebsockets h1, h2, h3, ws and wt using `safe`
rust: the two abstract bodies of code are kept in sync.
Development and auditing of lws and npro make heavy use of Fable 5.1
but it is tightly directed by humans.

It is a port of behaviour, not a transliteration of C: the C library's
sansIO half is the specification, and the port is held to it by:

- **transcripts**: byte-for-byte records of connections driven through C
  lws with no socket and no clock of its own
  (`minimal-examples-lowlevel/api-tests/api-test-sansio` in the C tree),
  which npro replays;
- **the C state tables**: every state transition C allows, from
  `lib/sansio/wsi-state.c`, which npro's state enums must match;
- **fuzzing**, each target checked against an oracle, on every build
  and in sai's idle time, seeded from the C library's fuzz corpora
  ([docs/fuzzing.md](docs/fuzzing.md));
- **differential and conformance testing**, against C lws and the
  autobahn, h2spec and h3spec suites, as the IO crate makes them possible.

... and the enforced design rules:

- every crate is `#![forbid(unsafe_code)]`
- nothing reachable from network data may panic
- arithmetic on lengths is checked
- the dependency tree stays close to empty (cargo deny + audit)
- maximally linted via clippy to enforce code quality
- fuzzing in CI on pushes and when CI idle
- CI runs tests natively on Linux, macOS, risc-v, aarach64, Windows
- Big-endian + 32-bit via Miri
- Every feature combination tested

[docs/toolchain.md](docs/toolchain.md) explains how to set a machine up to run
the tests.

## Licence

MIT
