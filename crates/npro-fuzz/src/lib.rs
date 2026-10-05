//! Fuzz harnesses for npro, not published.
//!
//! Each target is a function taking the fuzzer's bytes.  It drives the code
//! under test with them and checks the result against an oracle: another
//! way of getting the same answer, or a property the answer must have.  A
//! disagreement is reported as a panic, which is how libFuzzer learns of a
//! finding; so is any panic in the code under test, since nothing reachable
//! from network data may panic.
//!
//! The same functions run in two places:
//!
//! - the libFuzzer targets in the separate `fuzz/` workspace, one per
//!   [`Target`], for coverage-guided campaigns (`scripts/fuzz.sh`);
//! - this crate's smoke tests, part of every `cargo test`, which run each
//!   target over its seeds and inputs from a fixed seed on every platform.
//!
//! Where a target needs to choose something beyond the bytes under test,
//! such as where to split them, the choice is taken from the input's first
//! byte, so libFuzzer explores it like any other part of the input.

#![forbid(unsafe_code)]

mod h1;
mod targets;
mod ws;

pub use h1::{chunked, h1_request, h1_response};
pub use targets::{base64, sha1, transcript, utf8};
pub use ws::{ws_client, ws_server};

/// A fuzz target: its name is the libFuzzer target's, the seed directory's
/// under `fuzz/seeds/`, and the corpus's under `corpus-<name>`.
///
/// ```
/// use npro_fuzz::Target;
///
/// for t in Target::ALL {
///     t.run(b"");
/// }
/// assert_eq!(Target::Utf8.name(), "utf8");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// [`utf8`]: incremental UTF-8 validation against `core::str`.
    Utf8,
    /// [`sha1`]: SHA-1 fed in pieces against SHA-1 in one go.
    Sha1,
    /// [`base64`]: encoding against decoding, and buffers of every size.
    Base64,
    /// [`transcript`]: npro-test's transcript reader.
    Transcript,
    /// [`h1_request`]: the h1 head parser, as a server.
    H1Request,
    /// [`h1_response`]: the h1 head parser, as a client.
    H1Response,
    /// [`chunked`]: the chunked transfer coding's decoder.
    Chunked,
    /// [`ws_server`]: the ws frame parser, as a server.
    WsServer,
    /// [`ws_client`]: the ws frame parser, as a client.
    WsClient,
}

impl Target {
    /// Every target.
    pub const ALL: [Self; 9] = [
        Self::Utf8,
        Self::Sha1,
        Self::Base64,
        Self::Transcript,
        Self::H1Request,
        Self::H1Response,
        Self::Chunked,
        Self::WsServer,
        Self::WsClient,
    ];

    /// The target's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::Sha1 => "sha1",
            Self::Base64 => "base64",
            Self::Transcript => "transcript",
            Self::H1Request => "h1-request",
            Self::H1Response => "h1-response",
            Self::Chunked => "chunked",
            Self::WsServer => "ws-server",
            Self::WsClient => "ws-client",
        }
    }

    /// Runs the target over one input.
    ///
    /// # Panics
    ///
    /// On a finding: the code under test panicked, or disagreed with the
    /// target's oracle.
    pub fn run(self, data: &[u8]) {
        match self {
            Self::Utf8 => utf8(data),
            Self::Sha1 => sha1(data),
            Self::Base64 => base64(data),
            Self::Transcript => transcript(data),
            Self::H1Request => h1_request(data),
            Self::H1Response => h1_response(data),
            Self::Chunked => chunked(data),
            Self::WsServer => ws_server(data),
            Self::WsClient => ws_client(data),
        }
    }
}
