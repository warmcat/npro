//! Test support for npro, not published.
//!
//! C lws records connections driven through its sansIO half as
//! transcripts: the bytes in and out, what the application was given, and
//! when (`minimal-examples-lowlevel/api-tests/api-test-sansio` in the C
//! tree).  They are the byte-exact specification npro is checked against.
//! This crate reads them; copies of them, with where they came from, are in
//! this crate's `transcripts/` directory.
//!
//! Its tests hold npro to C's other oracles too, each in a directory with a
//! README saying where it came from: `states/`, C's connection state table
//! and what its test suite fired of it, and `h1/`, what C's h1 parser makes
//! of a corpus of heads and chunked bodies.

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    expect(
        unused_crate_dependencies,
        reason = "npro-core and npro-h1 are dev-dependencies for the tests in tests/, which the unit tests do not use"
    )
)]

mod transcript;

pub use transcript::{Error, MAX_BYTES, MAX_STEPS, Side, Step, StepKind, Transcript, vendored};
