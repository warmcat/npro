//! npro-cgi: a request answered by a script, sans-IO.
//!
//! C's CGI (`lws_cgi()` and `lws_cgi_write_split_stdout_headers()`),
//! as a service for npro-ss' server streams: a request on a route whose
//! `to` names a [`Script`] is answered by a process the runner spawns,
//! given the request as its environment ([`Vars`], RFC 3875's
//! meta-variables as C sets them) and the request's body on its stdin,
//! and what it writes on its stdout is parsed for its head ([`Head`]:
//! `Status`, `Content-Length`, `Location` and the headers to pass on),
//! then passed to the client as the answer's payload.
//!
//! What is sans-IO is here: the environment composed into caller
//! storage, and the head parsed from the bytes as they come.  Spawning
//! the process, its pipes, and the reads and writes on them are the
//! runner's, off the application's turn, as a file's reads are.
//!
//! What C does that this does too: the environment, variable for
//! variable, `GIT_PROJECT_ROOT` among the script's own making the answer
//! close-delimited for git; `Status` and `Location` (which makes a 302);
//! heads ending in CRLF or LF alone; a head that does not fit refused.
//!
//! Not yet: an answer with no length is close-delimited, where C frames
//! it chunked for a script other than git's; `cgi-chroot`; the headers a
//! login guard stamps on the request.
//!
//! ```
//! use npro_cgi::{Head, Parsed, Progress};
//!
//! // what the script wrote on its stdout, as it came
//! let mut head = Head::new();
//! let p = head.feed(b"Status: 201 Created\r\nContent-Type: text/plain\r\n\r\nhi").unwrap();
//! assert_eq!(p, Progress::Done { consumed: 49 });
//! let parsed: Parsed<'_> = head.parsed();
//! assert_eq!(parsed.status, 201);
//! assert_eq!(parsed.content_type, Some(&b"text/plain"[..]));
//! assert_eq!(parsed.content_length, None);
//! ```

#![no_std]
#![forbid(unsafe_code)]
// the integration tests' dependencies, which a lib test sees too
#![cfg_attr(
    test,
    expect(
        unused_crate_dependencies,
        reason = "the dev-dependencies are the integration tests', which a lib test sees too"
    )
)]

use core::time::Duration;

pub mod env;
pub mod head;

pub use env::{EnvError, MAX_ENV, MAX_VARS, Vars};
pub use head::{Head, HeadError, MAX_HEAD, Parsed, Progress};

/// A script, as the policy declares a CGI service: C's `cgi://` mount
/// origin with its `cgi-env`, `cgi-timeout` and `cgi-chdir`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Script<'p> {
    /// The program to run: `/usr/libexec/git-core/git-http-backend`.
    pub exec: &'p str,
    /// Variables added to its environment, after the request's: C's
    /// `cgi-env`.  `GIT_PROJECT_ROOT` among them means git's backend,
    /// whose answer is passed on as it is.
    pub env: &'p [(&'p str, &'p str)],
    /// The directory it runs in: C's `cgi-chdir`, `/tmp` if none.
    pub dir: Option<&'p str>,
    /// How long it may take to begin its answer: C's `cgi-timeout`.
    pub timeout: Duration,
}

/// Where a script may run when the policy names nowhere: C's.
pub const DEFAULT_DIR: &str = "/tmp";
