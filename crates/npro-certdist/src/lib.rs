//! npro-certdist: the certificate distribution client, sans-IO.
//!
//! lws' `lws-cert-dist-client` plugin fetches a machine's tls certificate
//! and key from a central `lws-cert-dist-server`, and keeps them
//! current: it holds a ws link to the server open under mTLS, the client
//! certificate it presents saying which name it manages, and the server
//! sends the certificate and key for that name as they are renewed.  On
//! each connect the client first says the SHA-1 of the chain it has, so
//! an unchanged one is not sent again.  This crate is that protocol,
//! wire-compatible with the C server, with no IO: the message the client
//! sends ([`hash`]), the server's message parsed as it comes
//! ([`Update`]), the rules of what may be installed ([`pem`]), and the
//! backoffs ([`Backoff`]).  The link, the files and the clock are the
//! runner's.
//!
//! The link: `wss://<server>/`, subprotocol [`PROTOCOL`], the client
//! certificate and key of the name managed, the server's CA to verify
//! it by.  Once up, the client sends `{"hash":"<sha1 hex>"}` if it has a
//! chain installed; the server answers, and from then pushes, `{"subdomain":
//! "<name>","fullchain":"<PEM>","privkey":"<PEM>"}` as one ws text
//! message, both empty for an unchanged chain.  What is installed is
//! named by the client's own configuration, never by the server's
//! `subdomain` (C logs a disagreement and goes on): a server, or whoever
//! holds its key, can replace the certificate of the name a link was made
//! for and no other.
//!
//! ```
//! use npro_certdist::{Progress, Received, Storage, Update};
//!
//! let mut update = Update::new(Storage {
//!     token: vec![0u8; 4096],
//!     names: vec![0u8; 256],
//!     fullchain: vec![0u8; 4096],
//!     privkey: vec![0u8; 4096],
//! }).unwrap();
//! let message = br#"{"subdomain":"npro.rs","fullchain":"","privkey":""}"#;
//! assert_eq!(update.feed(message).unwrap(), Progress::Done { consumed: message.len() });
//! assert_eq!(update.received(), Received::Unchanged);
//! ```

#![no_std]
#![forbid(unsafe_code)]

pub mod backoff;
pub mod hash;
pub mod pem;
pub mod update;

pub use backoff::{Backoff, CONNECT_BACKOFF, INSTALL_BACKOFF};
pub use update::{Progress, Received, Storage, Update, UpdateError};

/// The ws subprotocol the server speaks.
pub const PROTOCOL: &[u8] = b"lws-cert-dist-server";

/// The path the link is made on.
pub const PATH: &[u8] = b"/";

/// The most a certificate chain or key may be: C's `CERT_DIST_MAX_PEM`.
/// More is not something that is going to be installed, and taking it
/// would let the server make the client buffer without limit.
pub const MAX_PEM: usize = 256 * 1024;

/// The most a name a certificate is installed under may be: C's
/// `CERT_DIST_NAME_LEN`.
pub const MAX_NAME: usize = 64;

/// Whether `name` may name a certificate's installation: it becomes a
/// directory under the pki directory, so it is plain (`[A-Za-z0-9._-]`),
/// not empty, shorter than [`MAX_NAME`], starts with neither `.` nor
/// `-`, and holds no `..`.  C's `cert_dist_valid_name()`.
///
/// ```
/// use npro_certdist::valid_name;
///
/// assert!(valid_name("npro.rs"));
/// assert!(valid_name("test-org_1"));
/// assert!(!valid_name(""));
/// assert!(!valid_name(".hidden"));
/// assert!(!valid_name("a/b"));
/// assert!(!valid_name("a..b"));
/// ```
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() >= MAX_NAME {
        return false;
    }
    if matches!(b.first(), Some(b'.' | b'-')) {
        return false;
    }
    if b.windows(2).any(|w| w == b"..") {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
}
