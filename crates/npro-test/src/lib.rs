//! Test support for npro, not published.
//!
//! C lws records connections driven through its sansIO half as
//! transcripts: the bytes in and out, what the application was given, and
//! when (`minimal-examples-lowlevel/api-tests/api-test-sansio` in the C
//! tree).  They are the byte-exact specification npro is checked against.
//! This crate reads them; copies of them, with where they came from, are in
//! this crate's `transcripts/` directory.

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    expect(
        unused_crate_dependencies,
        reason = "npro-core is a dev-dependency for the state tests in tests/, which the unit tests do not use"
    )
)]

mod transcript;

pub use transcript::{Error, MAX_BYTES, MAX_STEPS, Side, Step, StepKind, Transcript, vendored};
