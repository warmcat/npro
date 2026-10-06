# The IO model

How npro meets sockets, timers, tls and whatever scheduler the user has:
tokio, threads with blocking calls, embassy on a microcontroller, or an
event loop of their own.  Discussed and agreed with Andy on 2026-10-06;
what is still open is listed at the end.

## The rule

**The protocol crates never call IO.  Anything that could block is a
request the protocol returns, never an operation it calls.**

Every protocol entry point is sync and non-blocking: it takes bytes and
`now` as values, does its work, and returns.  That is the only kind of
function that both sync and async code can call, so the same protocol
code runs under any scheduler, and nothing in it is "coloured" sync or
async.

C's sansIO half calls out to IO: `want_write()`, `close()`, the
deadline.  npro turns those calls around: `conn.poll_request()` returns
`WantWrite`, `WantRead(bool)` or `Close(phase)`, and IO acts on the
value.  An ops struct passed into the protocol would not give the same:
its `read` must be blocking, which an async caller cannot use without
parking a thread, or `async`, which a sync caller cannot use without a
runtime.  A returned value also means no re-entry from a callback into
the library, which was a source of trouble in C.

So npro promises, and no feature changes it:

- it never spawns a task or a thread on the user's behalf;
- it never reads an ambient runtime or a global executor;
- it puts no `Send` or `'static` bound on a connection.  A connection
  is plain data, `Send` exactly when its storage and `Random` are.  The
  one place `Send` appears is the cross-context handle (below), in the
  adapters that offer one.

A protocol crate may take a trait only for a service that is sync,
cannot block, and does no IO: `Random`, and the tls record layer.  Time
is a value, not a service.

## Three layers

1. **The protocol crates** (`npro-core`, `npro-h1`, `npro-ws`, ...):
   `rx`, the `tx` pull, `deadline_passed`, `poll_request`, `poll_event`.
   These exist.

2. **The driver**, in `npro-io`, `no_std` without its `std` feature.  It
   holds a connection, its buffers and its tls, and keeps the rules
   every adapter would otherwise have to get right on its own: the order
   of rx, requests, tx and deadline; a hangup at any point; a drain that
   says whether output was delivered or dropped; tls stepped by one
   function whose first step may already finish the handshake.  It does
   no IO.  It tells the adapter what it wants, as a set, and the adapter
   tells it what happened.  A first sketch, to be designed properly:

   ```rust
   enum Want<'a> {
       Io { read: Option<&'a mut [u8]>, write: Option<&'a [u8]>, until: Option<Instant> },
       Close,
   }
   // and back: read_done(now, n), write_done(now, n), timer(now), hangup(now)
   ```

   It must be a set, not one action at a time: a connection keeps
   reading while it waits to write, or two peers each waiting to write
   wedge.

3. **Adapters**, which do the IO, each a short loop over the driver,
   each behind its own `npro-io` feature.  Features are additive: each
   adds an adapter and changes nothing else.

   | adapter | feature | scale | needs |
   |---|---|---|---|
   | threads, blocking calls | `std` | a reader and a writer thread per connection; not for tens of thousands | std only |
   | one-thread readiness loop | `mio` | many connections on one thread | `mio`, and through it `libc` (unix) and `windows-sys` |
   | tokio | `tokio` | one task per connection, spawned by the user | tokio |
   | embassy | `embassy` | connections fixed at build time (`pool_size`) | `embedded-io-async`, `embassy-time` |

   **Your own loop** is supported too, as C supports foreign loops
   (libuv, libevent, glib, sd-event): drive the driver from it directly.
   The driver is the lowest public level, and needs nothing from npro-io's
   adapters.

Notes for each adapter, from the discussion:

- **threads**: the driver behind a `Mutex` shared by the two threads,
  which is allowed in an adapter but not in a protocol crate.  The writer
  waits on a condvar for a write.  The read timeout comes from `until`.
  `shutdown()` on the socket wakes a reader blocked in `read()`.  On
  esp32 under esp-idf (std on FreeRTOS, sockets on lwIP) this runs
  unchanged, but two thread stacks per connection cost RAM there; the
  `mio` loop is the answer if that is too much.
- **mio**: std has no `poll()`.  A readiness loop needs the OS's poll,
  epoll or kqueue, and calling those is `unsafe`.  mio does that in about
  170 marked places, and is what tokio stands on.  npro's own code stays
  `#![forbid(unsafe_code)]`.
- **tokio**: wait for readiness (`readable()`, `writable()`, a sleep
  until `until`) and then do non-blocking `try_read` and `try_write`.
  That way no buffer borrowed from the driver is held across an
  `.await`, which is the same shape as a poll loop.  The future is
  `Send` when the connection is; a `&mut dyn TxSource` held across an
  `.await` must be `dyn TxSource + Send`, or it is not.  A compile-time
  test asserts `Send`, so this cannot break silently.  Plugging into
  hyper or axum is a separate question: npro is an alternative stack,
  not a hyper backend.
- **embassy**: buffers in `static` storage passed as `&'static mut`, not
  inside the future, or every task becomes large.  To check: whether
  embassy-net's `TcpSocket::read_with` and `write_with` hand a closure
  the socket's own ring buffer.  If so, `rx` and the `tx` pull work on
  it directly with no copy.

### Writing from another task or thread

`conn.send()` needs `&mut` access to the connection, so the
application's code has to run where the connection is: on the adapter's
thread, task or loop.  In C this is `lws_callback_on_writable()` plus
`lws_cancel_service()`.  An adapter may offer a `Handle`: a bounded
command queue plus a wakeup (a condvar, a waker, an eventfd).  The
handle is where `Send + 'static` appears, and nowhere else.

### What is written twice

The user-facing conveniences, such as a blocking `client.get(url)` and
an async `client.get(url).await`, are written once per adapter, thin,
over the driver.  Macro crates that generate both versions from one
source (`maybe_async` and others) are proc-macro dependencies, and are
not used; the duplication is kept small and visible instead.

## tls

rustls is itself sans-IO.  It needs nothing from an event loop: its
`TimeProvider` takes wall time, and randomness comes from its crypto
provider.  It goes inside the driver, once:

    socket -> rustls -> npro rx
    npro tx pull -> rustls -> socket

It is never wired in per adapter, so not `tokio-rustls`.  The unbuffered
API (`UnbufferedClientConnection`, and its server equivalent) works on
caller-owned buffers, as the rest of npro does.

rustls is one implementation behind a small record-layer trait in the
driver, not a fixed dependency, because the right tls differs by target.
rustls needs `alloc`, and around 16 KiB of record buffer per direction.

### The crypto provider

rustls itself carries no unsafe code; the providers are where it lives,
as in every tls stack, since constant-time and fast crypto ends up in
assembly or intrinsics.  What was found on 2026-10-06:

| provider | status | unsafe and build | platforms |
|---|---|---|---|
| `aws-lc-rs` | rustls' default; AWS | AWS-LC's C and assembly, compiled by its build script | wide |
| `ring` | its author stepped back in 2025; RUSTSEC-2025-0007 said it was unmaintained, then was withdrawn once the rustls team took on its maintenance.  Commits are slow | mostly BoringSSL's C and assembly, compiled by its build script with a C compiler | wide |
| `rustls-rustcrypto` | outside the rustls project; its README says not for production, incomplete, not audited | pure Rust over the RustCrypto crates, but not free of unsafe: their fast paths are `unsafe` intrinsics or `asm!` behind runtime cpu detection (`sha2` 0.10.9: 29 uses; `cpufeatures`: 9), which some crates can be built without, slower.  What remains even then is small and can't be avoided: `zeroize`'s volatile writes (15), so the compiler cannot drop a key wipe; `subtle`'s optimisation barrier (2); `getrandom`'s syscalls | anything Rust targets |
| `rustls-graviola` / `graviola` | by Joseph Birr-Pixton (ctz), rustls' original author; its README says it is "very new".  0.4.1, 2026-06-24 | formally verified assembly from AWS's s2n-bignum for the ECC, RSA and ML-KEM arithmetic, intrinsics for AES and SHA; no C compiler.  Brings `cfg-if` and `getrandom` | **x86_64 and aarch64 only**, and only CPUs with the listed features (AES, SHA2, PMULL, NEON on aarch64, so no Raspberry Pi 4 or older; AVX2, ADX, BMI2, PCLMULQDQ and others on x86_64) |

"Pure Rust" is not "no unsafe".  Memory safety is also not the main
risk in crypto: timing side channels and correctness are, and that is
what rustls-rustcrypto's README warns about.  The RustCrypto crates
underneath are widely used on their own, and on a microcontroller they
are likely to be in the tree anyway (`embedded-tls` uses them too).

graviola is the best fit on desktop and server: no C, and verified
assembly where the arithmetic is.  Its licence, `Apache-2.0 OR ISC OR
MIT-0`, is not MIT, and `deny.toml` admits only MIT, so it needs a
licence admitted as well as the crate.  It does not cover CPUs without
those features, or any microcontroller.

### esp32

Two different worlds, and the chip matters too:

- **esp-idf**: std on FreeRTOS.  The threads adapter works as it is.
  tls can be rustls, since there is an allocator, but with a provider
  that builds for the chip (graviola does not), or the IDF's own mbedTLS
  with the chip's crypto hardware, through a separate binding crate that
  nothing else depends on, as AGENTS.md allows for FFI.
- **esp-hal and embassy**: `no_std`, usually with no allocator.  rustls
  is out without `alloc`; `embedded-tls` is TLS 1.3 and client only,
  over RustCrypto primitives.
- **The chip**: the RISC-V parts (C3, C6) build with the normal Rust
  toolchain; Xtensa (the original esp32, S2, S3) needs Espressif's own
  fork of the compiler, which complicates pinning the MSRV in CI.

Device tests run on Andy's hardware, and their output comes back by
hand.

## Proving the adapters behave the same

The C transcripts that `npro-test` already replays against the protocol
crates are replayed through the driver, and then through each adapter's
loop over an in-memory transport, with identical results required.  An
adapter that is not in that matrix is not claimed to behave the same.
Then real sockets: npro's client against C's servers, C's clients
against npro's servers, npro against itself, and autobahn both ways, over
plain TCP first and over tls after.  These run locally until they pass,
then become sai tasks.

## Decided

- 2026-10-06: the driver lives in `npro-io`, which is `no_std` without
  its `std` feature; adapters are further additive features of it.
- 2026-10-06: a `mio` readiness loop is supported, as well as threads,
  tokio and embassy, and so is driving the driver from a loop of the
  user's own.
- 2026-10-06: tests against C lws run locally until they pass, then
  move into sai.

## Open

- The tls provider on desktop: graviola is the leading candidate, which
  needs its licence admitted.  What covers CPUs it does not, if anything.
- tls on esp32, which follows from which world and which chip.
- The driver's interface, designed by sketching all four adapter loops
  against it, embassy's included, before it is fixed.
- Admitting `mio`, `libc` and `windows-sys` (and whatever `cargo deny`
  shows they bring) when the `mio` adapter is written.  `libc` has a
  build script.
