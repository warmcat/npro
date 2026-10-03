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
kept between runs, not here ([docs/fuzzing.md](../../docs/fuzzing.md)).  When the protocol crates arrive, their
targets' seeds come from the C library's corpora (`fuzz/fuzz-*/seeds` in
the C tree), copied with where they came from.
