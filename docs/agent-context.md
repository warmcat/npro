# lws agent context

This is distilled from the working notes that coding agents kept while
working on the C libwebsockets tree with Andy, up to 2026-09-29.  It holds
what an agent starting on lws-rs would otherwise have to rediscover: who you
are working with, how Andy wants the work done, the decisions already taken
for this project, and what the C library taught us the hard way.

It is a starting point, not the authority.  Where it disagrees with the C
tree's own documents, the C tree wins; where it disagrees with AGENTS.md,
AGENTS.md wins.  Facts about the C code are as of the date above and the C
tree keeps moving.

Agent memory does not persist between cloud sessions: each one starts on a
fresh machine.  If you learn something durable that a later session needs,
propose an edit to this file in your commit rather than relying on memory.

## Who you are working with

Andy Green is the author and maintainer of libwebsockets (C, MIT, since
2010: http/1, h2, h3/quic, ws, WebTransport, mqtt, tls on several backends,
many platforms down to microcontrollers).  Andy has deep C and protocol
knowledge and wants precise root-cause analysis, not hand-holding.

Andy is relatively new to Rust.  This port exists so that Andy's
understanding of lws carries over, so:

- explain Rust-specific choices in terms of what the C does and why the
  Rust shape is better or safer, briefly, in commit messages and replies;
- never lean on "that's idiomatic" alone as a justification;
- keep the correspondence to the C design visible (names, state machines,
  the sans-IO interface) unless there is a stated reason to depart.

Since mid-2026 Andy has used AI models to find and fix bugs in C lws and
pushes the results straight to the public tree, which is also deployed to
production Internet servers.  Treat that as the bar: what you commit may
be running on a public server soon after.

## How the work is to be done

These came from real incidents, not taste.

- **One commit per logical change.**  A fix, a feature and a refactor are
  separate commits, each building and passing tests on its own, so history
  can be reviewed and bisected.  Subjects are prefixed with the area
  touched, as in the C tree (`h2: ...`, `quic: ...`).
- **A claim needs a test.**  Twice in C, an agent's confident reading of a
  flow was wrong ("the form posts here", "releasing this early is safe"),
  every existing test passed, and production broke within the hour.
  "All tests pass" is not evidence for a path no test exercises.  Before
  relying on a behavioural claim, add a test that exercises it, or read the
  code that defines the other side (the peer, the asset, the RFC text).
  Treat "by design" and "not reachable" as unverified until shown.
- **No exploit-style reproducers.**  Find and fix problems by reading, by
  tests of correct behaviour, and by fuzzing; do not write attack tools or
  crafted attack payloads as deliverables.
- **Don't brute-force sporadic failures.**  Many parallel test loops once
  exhausted a machine's memory and orphaned processes, and the bug was
  then found by reading.  Prefer one instrumented run and reading.  Keep
  test parallelism moderate (`-j4` rather than `-j8` on a shared box).
- **Ask before installing tools or system packages.**  Never install
  Node.js or anything with an npm-style uncontrolled dependency tree, even
  in a throwaway environment.  New crate dependencies are covered by
  AGENTS.md: close to zero, each justified in its commit.
- **Say what is not done.**  If a phase ends incomplete, list exactly
  what is missing.  Never leave something silently half-done.
- **When a partner makes a design call, record it and don't reopen it.**
  Suggest alternatives once, with reasons, then follow the decision.

## Decisions already taken for lws-rs

- Brand and crate name is `lws` (reserved on crates.io as a placeholder,
  0.0.1, MIT, edition 2024).  Not `libwebsockets`: in Rust a crate named
  after a C library reads as bindings or a wrapper.  The repository may be
  called `lws-rs`, but no crate name carries a `-rs` suffix.
- Home is libwebsockets.org; the repository is
  https://libwebsockets.org/git/lws-rs .  There is no `.rs` domain.
- One repository, one Cargo workspace, members under `crates/*`:
  `lws-core` (the sans-IO core), protocol crates `lws-h1`, `lws-h2`,
  `lws-h3`, `lws-ws`, `lws-wt`, an IO crate `lws-io` for sockets, tls and
  the event loop, and `lws` as the facade crate re-exporting the rest
  behind features.  quinn / quinn-proto is the model for the split.  No
  git submodules.  Member crate names are not yet reserved on crates.io:
  check before assuming one is free.
- Trust posture: `forbid(unsafe_code)`, a tiny dependency tree, the
  conformance suites (autobahn for ws, h2spec, h3spec), cargo-fuzz seeded
  from the C corpus, differential tests against C lws, clippy with
  warnings as errors, a pinned MSRV, cargo deny / cargo audit, and a README
  that says plainly that the port is AI-driven and how it is checked.
- Publishing tokens go through a cargo credential provider
  (`cargo:libsecret`), never the plaintext `credentials.toml`; tokens are
  scoped and expiring; CI publishing uses trusted publishing.

## The C tree as your reference

A checkout of C lws is your reference, never your output.  In cloud
sessions the environment's setup script puts one outside this repository;
if you cannot find it, say so rather than cloning it into this tree.  Do
not copy C sources in, and do not transliterate C: the goal is the same
behaviour and design with Rust's guarantees.

Read these first; they are the design documents written for this port:

- `READMEs/README.sans-io-split.md`: the two halves, the interface
  between them, the contract, and a section "Open before it is done"
  whose part "Before it is the port's source" lists what the C split
  still gets wrong for a port.  Read that list before designing an
  interface.
- `READMEs/README.wsi-state-machines.md`: the per-connection state
  machines, what each state means, the events that move them, and the
  close invariants.

Where the C code's history matters, the commit messages explain the
reasons for most of the rules below; `git log -S` on the C tree finds
them, if the reference checkout has history.

## sans-IO: what was learned splitting the C library

The C library was restructured in September 2026 into a sansIO half and
an IO half precisely so this port could follow it.  Terms: call them
**sansIO** and **IO**; "core" in C lws means `lib/core`, not the sansIO
half.

- The placement test: if deleting the code would change the bytes on the
  wire or the state transitions for a given input, it is sansIO; if it
  only changes when or how the same bytes move, it is IO.
- rx: IO hands sansIO bytes and learns how many were consumed.  A
  zero-length rx is the peer closing.  Datagram rx is taken whole with
  its peer address and ECN bits.
- tx is a **pull**: IO offers a buffer and a maximum; sansIO writes from
  where it got to.  No parking of composed output on the heap.  The one
  exception C kept for now is the application's own data (`lws_write()`
  framing in place, zero-copy); the README lists turning that into a pull
  as required for the port.
- The client response body is deliberately a pull at the application's
  pace (`lws_http_client_read()` in C): the application's buffer and the
  TCP window provide back-pressure.  Do not replace it with buffering.
- Hangup: POLLHUP was found more trustworthy than the read's return value
  across platforms and tls libraries.  In Rust this is the IO crate's
  concern, but the sansIO side must accept "peer closed" as an input at
  any point.
- Time must be an input.  The C sansIO half still reads the clock itself
  in about 56 places (quic congestion control, loss detection, pacing
  among them); the port must pass "now" in on every entry point instead.
- IO's requests of sansIO turned out to be about twenty calls, not four:
  want-write, want-read, deadline and close, plus transport phase
  changes, tls session queries and a few more.  "The contract" in the
  README lists them; that is what `lws-io` implements.
- A test transport that replaces the socket, driving both a client and a
  server through in-memory buffers, is how C tests the split
  (`api-test-sansio`, `api-test-sansio-split`).  Design `lws-core` so the
  same harness is trivial: that is the no-IO test surface for everything.

## State machines: lessons that apply directly

- A connection in C had one flat state enum, and it was found to be four
  machines stacked in one word: **transport** (dns, connect, tls,
  socks/proxy legs), **carrier** (the per-protocol handshake: h2 preface
  and SETTINGS, h1 upgrade...), **transaction** (headers, body, file
  serving, completion) and **close**.  203 distinct transitions were
  observed, 99 of them crossing between these notional machines.  In Rust
  each machine is its own enum, as AGENTS.md says.
- Carrier and transaction are sequential, not stacked, and the boundary
  differs per protocol: on an h1 client, "waiting for the server's reply"
  is a carrier state for the first request only and a per-transaction
  phase for later pipelined ones.  Design this per role; do not apply one
  recipe everywhere.
- Most C bugs of the last phase were **bools living beside the state**
  that some resets cleared and some did not.  Every one of them was
  folded into a state or derived from one.  The Rust rule in AGENTS.md
  (state in enums, no duplicate flags) is the cure.
- Attributes that belong to the connection rather than the protocol must
  survive a change of role (h1 -> ws, h1 -> h2c, quic -> h3).  Losing one
  at a role transition hung every http client once.
- Transitions are driven by named events through a table; an unlisted
  transition is a bug.  A table row that accepts **any** source state
  hides bugs: one such row masked a raw socket reporting "connected" in
  the middle of a SOCKS handshake.  Prefer explicit source states.  In
  Rust, exhaustive `match` without `_ =>` gives this for free.
- A client multiplexed connection (h2, h3) whose last stream has closed
  is kept warm for a few seconds (idle state with a timeout) so a new
  request to the same endpoint joins it.  This is design intent, not dead
  code.
- Parked question, do not settle without Andy: a request that joins a
  kept-warm h2/h3 connection is told "established" at the join with
  status 0, before any response arrives.  Secure Streams relies on that
  today.
- A client redirect is a transport phase ("restarting") of the same
  connection object, and its tests found three separate defects in the C
  h2 path.  Test redirects over every protocol.

## Protocol traps found in C (each deserves a Rust test)

- **A fatal verdict must stop parsing.**  An h2 connection error was
  queued as GOAWAY while the parser returned success and carried on over
  the rest of the buffer; connection-scoped hpack state then drove
  per-stream header storage out of bounds.  Every check was individually
  correct; the bridge between "detected" and "enforced" was missing.
  Ask of every verdict: what does the caller do with it?
- **h2c upgrade**: stream 1's send window was overwritten with our own
  advertised window, so the upgraded stream could not send until the peer
  happened to send WINDOW_UPDATE (most clients do, so it went unseen).
- An **h2 client stream with no body** went straight to "established"
  with no response timeout; it must wait for the reply like h1 and h3.
- **Header presence** must be explicit.  C decides whether a header
  exists from a flag each fragment creator had to remember to set; one
  path forgot, and every h3 check for forbidden headers (Connection, TE,
  Transfer-Encoding; RFC 9114 4.2) was silently dead.  h2/h3 treat
  `:authority` as Host when no Host header came.
- **Chunked bodies**: one decoder shared by client and server; chunk
  extensions and trailers skipped within a bound (4096 bytes in C); at
  least one hex digit; only a lone `chunked` Transfer-Encoding is
  accepted (anything else is 501).  An h1 POST with neither
  Content-Length nor Transfer-Encoding is counted by other means in C
  because the C client sends multipart bodies like that: decide this
  explicitly for Rust, with a test.
- **Body bytes that arrive with the headers** must be kept before the
  handler runs: in C a status page reused the receive buffer and
  clobbered them.
- **Expect: 100-continue**: send 100 only if nothing has answered yet;
  other Expect values get 417.  A client must swallow any 1xx and keep
  waiting for the final status.
- **Range requests (RFC 7233)**: multipart delimiters must be real MIME
  (`--boundary`, close delimiter, `boundary=` in Content-Type); the
  boundary is random per response; END_STREAM follows the last byte of
  the range, not end of file; at most 16 ranges; a 416 carries
  `Content-Range: bytes */len`.
- **Multiplexed fairness walk**: rotating a serviced child to the tail
  while iterating with a cached next pointer made two children alternate
  forever in one pass.  Bound every fair-share walk by the child count
  taken at the start.
- **quic output accounting**: data sent but not yet acknowledged is not
  "pending output".  Treating it as such made h3 file responses go one
  fragment per round trip and spun the loop after a client vanished.  A
  stream waiting only on an ACK, congestion window or flow control must
  not ask to write; the event that lifts the limit wakes it.
- **Receive flow control is rx only**: a role that stopped servicing when
  rx was paused also stopped its tx, and wedged.
- **TLS client handshake may complete synchronously** on its first step
  (a resumed TLS 1.3 session on loopback).  The C path then skipped peer
  certificate verification on some backends and ran ALPN selection twice.
  One step function for every step; ALPN handled once, after the peer is
  confirmed.
- **h3 to h2 fallback**: when quic loses the race, the h2 stream's
  "closed" arrives a pass after its "completed".  A client driver that
  starts the next job on "completed" must ignore the previous job's late
  "closed".
- **SOCKS5 replies**: consume only the reply's length; bytes after it
  belong to the next protocol.
- **Socket address family is platform-dependent**: macOS reports an IPv4
  peer on a dual-stack socket as a plain IPv4 address and refuses to send
  to it on that socket; Linux does neither.  Normalise a received address
  to the socket's family before recording or comparing it.
- **Silent limits**: C's default connection budget quietly stopped
  accepting on listeners when reached, with no log.  Every limit the
  port has should be visible when hit.

## Parsers

- Streaming parsers must be restartable at any byte boundary.  The oracle
  that found the most bugs in C's newer parsers compares a one-shot pass
  with a fragmented pass (input split at random, output sink deferring)
  and requires identical results.  Use the same idea in property tests
  and fuzz targets.
- A C JSON parser silently dropped elements 2..n of a scalar array when a
  broader wildcard pattern came later in its match list, truncating a
  retry-backoff table to its first entry for five years.  Whatever does
  JSON for the port, test arrays of scalars explicitly.
- A parse that returns "ok" having consumed less than its input is a held
  byte, not an error; callers loop while progress is made.

## DNS, DNSSEC and the DHT

- C's async DNS validates DNSSEC by walking the DS chain from the root.
  Not done in C: NSEC/NSEC3 (unsigned delegations fail closed) and
  Ed25519 (algorithm 15).
- Andy's production lws DHT network is **two nodes**.  Any quorum written
  as a fixed peer count (eg. "three peers agree on our external address")
  can never be met; derive thresholds from what the routing table can
  actually supply.

## Testing heritage to port

- C api-tests that are the most useful behavioural references:
  `api-test-http-transfer` (every body framing, h1/h2/h3, proxy,
  redirect, reuse and keep-warm cases), `api-test-http-ranges`,
  `api-test-keep-warm`, `api-test-ws-close`, `api-test-raw-close`,
  `api-test-sansio`, `api-test-sansio-split`, `api-test-dnssec-chain`,
  `api-test-ws-h2-txcredit`.  Each lives under
  `minimal-examples-lowlevel/api-tests/` in the C tree.
- C fuzz targets are in `fuzz/fuzz-<name>/` with committed seeds in
  `fuzz/fuzz-<name>/seeds/`; seeds named `regress-*` are past crashes.
  Targets relevant to the port: h1, h2, ws, ws-pmd, qpack, adns, jose,
  cose, lejp, lecp, tokenize.  Seed the matching cargo-fuzz targets from
  them.
- Conformance: C lws is checked with h3spec against the minimal quic
  client-server example; autobahn (ws), h2spec and h3spec are the suites
  the Rust crates are expected to pass.

## Working from a cloud session

- Andy has no shell on the cloud machine and sees only what you report and
  what you commit.  Report failures with the command and its output.
- Results come back to Andy's own git server by fetching your branch and
  cherry-picking, so every commit must stand alone: builds, passes its
  tests, one purpose.
- Do not push anywhere, and do not add credentials, tokens or remotes to
  the repository or the environment.
