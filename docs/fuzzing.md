# Fuzzing npro

Everything in npro that reads bytes from outside is fuzzed, and each fuzz
target checks the code under test against an **oracle**: another way of
getting the same answer, or a property the answer must have.  A target that
only waits for a panic finds out little about code that cannot panic; one
with an oracle finds wrong answers too.

Fuzzing runs in three places:

| where | what | when |
|---|---|---|
| `cargo test` | the smoke tests: every target over its seeds and 4000 inputs from a fixed seed | every build, every builder, Miri included |
| sai `fuzz` | the known bugs replayed, then libFuzzer for a minute on each target | every push |
| sai idle tasks | libFuzzer, the targets taking turns | builders' idle time, on the latest completed push |

## The targets

| target | the code under test | the oracle |
|---|---|---|
| `utf8` | `npro_core::utf8::Utf8Validator`, which checks ws text as it arrives | `core::str::from_utf8` over the whole text.  Fed a byte at a time, the validator must refuse at exactly the first byte no well-formed text could have next; fed in pieces of 0 to 16 bytes, it must refuse in the piece holding that byte, and go on refusing |
| `sha1` | `npro_core::sha1::Sha1`, for the ws accept | the digest of the message fed in pieces equals the digest of it in one go |
| `base64` | `npro_core::base64::encode` | a strict decoder in the harness gets the input back; exactly `encoded_len` bytes are used and no more written; a buffer one byte short, or empty, is refused with nothing written |
| `transcript` | npro-test's transcript reader | whatever it accepts keeps its limits, and step times never go backwards |

A target that splits its input to feed it in pieces takes the split from
the input's first byte, so libFuzzer explores the split like the rest of
the input.

The h1 parser's targets come next, in phase 1c of
[port-plan.md](port-plan.md), seeded from the C library's corpora.

## Where things are

- `crates/npro-fuzz`: the harnesses, one safe `fn(&[u8])` per target, and
  `Target`, which names them.  Part of the main workspace, with no
  dependencies outside it.  Its `tests/smoke.rs` is the smoke tests.
- `fuzz/`: the libFuzzer targets, one line each, which hand libFuzzer's
  input to a harness.  A **workspace of its own**, with its own
  `Cargo.lock` and `deny.toml`, so what fuzzing needs to build
  (`libfuzzer-sys` and the crates that compile libFuzzer, see
  [dependencies.md](dependencies.md)) never enters the main workspace.
- `fuzz/seeds/<target>/`: the hand-made seeds each corpus starts from
  (its [README](../fuzz/seeds/README.md)).  `transcript` also starts from
  the vendored transcripts.
- `scripts/fuzz.sh`: builds the targets and runs libFuzzer over them, by
  hand or under sai.  It follows the C tree's `fuzz/run.sh`.

## Running it by hand

It needs nightly, cargo-fuzz, cargo-deny, a C++ compiler for libFuzzer's
runtime, and ideally `llvm-symbolizer` for readable reports:

```sh
rustup toolchain install nightly --profile minimal
cargo install --locked cargo-fuzz cargo-deny
```

Then:

```sh
scripts/fuzz.sh                 # 60s on every target
scripts/fuzz.sh 600 utf8        # 10 minutes on utf8
CORPUS=~/npro-corpus scripts/fuzz.sh 3600
```

It checks the fuzz workspace with `cargo deny` before building anything,
and builds with AddressSanitizer and debug assertions.  `FUZZ_OPTS` passes
more flags to libFuzzer: `FUZZ_OPTS=-verbosity=0` leaves out its line for
every new unit and its periodic status, keeping the setup, the final
stats and any report.  Builds and corpora
go under `target/fuzz/` (or `$CARGO_TARGET_DIR/fuzz/`) unless `BUILD` and
`CORPUS` say otherwise.

### When it finds something

A finding is an input that made a target panic: the code under test
panicked, or disagreed with the oracle.  libFuzzer keeps it as
`target/fuzz/artifacts/crash-<sha1>`, and the run ends listing it.  To
replay it under the fuzz build:

```sh
target/fuzz/x86_64-unknown-linux-gnu/release/utf8 target/fuzz/artifacts/crash-...
```

The panic message says what disagreed, eg,
`utf8: fed a byte at a time it ends Complete, core says InvalidAt(1)`.
The same input reproduces it in a plain test too, which is where the fix's
regression test belongs: `npro_fuzz::Target::Utf8.run(&input)`.

## Under sai

The `fuzz` configuration in `.sai.json` runs `scripts/sai.sh fuzz 60` on
the C tree's fuzz builder, `fuzz-linux-debian13/x86_64-amd/gcc`, with
`"idle": 2` and `"pool": "fuzz"`.  As in C's fuzz job, libFuzzer runs
there with `-verbosity=0`, so the log stays a few lines per target; a
`FUZZ_OPTS` set on the builder replaces it.  [sai.md](sai.md) says what that builder
needs.  sai gives the script:

- **`SAI_POOL_DIR`**, the `fuzz` pool, which sai keeps synced between
  every builder fuzzing npro.  The corpora live there as
  `corpus-<target>/`, named by SHA-1 as sai expects, so coverage keeps
  advancing across jobs and builders.  Pools belong to a repo: npro's
  `fuzz` pool is not the C tree's.
- **`SAI_POOL_KNOWN`**, the reproducers of every bug found so far.  The CI
  run replays them before fuzzing, and fails while any still crashes.  For
  one that no longer does, it tells sai-server, which notes at which
  commit.
- **`SAI_POOL_FINDINGS`**, where findings go: the input and libFuzzer's
  report, which sai-server groups into bugs and shows **only to admins**.
  A finding can be an unfixed security bug, and job logs are public, so
  under sai the log gets only how each run went.
- **`SAI_IDLE_SECS`**, in an idle task: the slice's length, build
  included.  The time after the build is shared by as many targets as can
  each have two minutes, taking turns across slices.  An idle slice
  reports what it finds, but does not fail.

## Adding a target

1. A harness in `crates/npro-fuzz/src/targets.rs`: what it drives, and
   the oracle it checks against, reporting a disagreement with
   `finding()`.  It must not panic for any other reason.
2. A `Target` variant, its name, and its arm in `Target::run`.
3. A smoke test in `crates/npro-fuzz/tests/smoke.rs`, drawing inputs
   that reach the code, which random bytes often do not.
4. Its seeds in `fuzz/seeds/<name>/`: for a protocol parser, C's corpus
   for it, copied with where it came from.
5. A `[[bin]]` in `fuzz/Cargo.toml` and its one-line
   `fuzz/fuzz_targets/<name>.rs`.

`scripts/fuzz.sh` and sai pick it up from `cargo fuzz list`.  A target
that needs a new crate is a dependency decision like any other
([dependencies.md](dependencies.md)).

## Not done yet

- **sai-server's grouping of Rust findings.**  sai-server tells bugs
  apart by the first three frames of the report's stack that are in the
  code under test.  It skips C's runtime and libFuzzer's frames, but not
  Rust's: every panic's stack starts with `pthread_kill`,
  `std::sys::pal::unix::abort_internal` and `std::process::abort`, so
  every finding in a target is grouped as one bug.  The frames that tell
  findings apart come after `core::panicking::panic_fmt`.  sai-server
  needs to skip frames in `std::`, `core::`, `alloc::` (and `<std::`,
  `<core::`, `<alloc::` impls), `libfuzzer_sys::`, `pthread_kill`, and
  `npro_fuzz::targets::finding`, and to stop at `rust_fuzzer_test_input`.
- **Coverage reports** (`cargo fuzz coverage`) are not wired up.
- **Corpus minimizing** (`-merge=1`, and sai's pool replace) is not done;
  the corpora only grow.
