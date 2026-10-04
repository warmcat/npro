# Fuzz seeds

One directory per fuzz target, named as the target is (`npro_fuzz::Target`).
Every file in it is one input libFuzzer starts its corpus from, and one the
smoke tests in `crates/npro-fuzz/tests/smoke.rs` run on every `cargo test`.
Files named `*.md` are left out of both.

Where a target splits its input to feed it in pieces, as `utf8` and `sha1`
do, the **first byte chooses the split** and the bytes under test follow it.
A seed for those targets starts with that byte; any value will do.

The `transcript` target also starts from every transcript in
`crates/npro-test/transcripts/`.

Seeds are small and readable on purpose: each is a case worth starting from,
named for what it is.  What the fuzzer finds goes in its corpus, which is
kept between runs, not here ([docs/fuzzing.md](../../docs/fuzzing.md)).
The protocol crates' targets start from the C library's corpora
(`fuzz/fuzz-*/seeds` in the C tree), copied with where they came from:

- `h1-request`: C's `fuzz/fuzz-h1/seeds`, each behind a control byte of
  0, named as there (`absuri.http`, `get.http`...), and some of
  `crates/npro-test/h1/requests/`, named as there;
- `h1-response` and `chunked`: some of `crates/npro-test/h1/responses/`
  and `chunked/`.

A `tight-*` seed's control byte has its top bit set, choosing the small
table with token limits.  A seed named `regress-*` is an input the fuzzer
once failed on, kept so it is tried every run, as in C.
