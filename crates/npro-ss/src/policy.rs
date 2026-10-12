//! What the policy gives npro-ss, as Rust types.
//!
//! So far, a server's listeners: where each binds, whether it is tls and
//! with what, how its h1 takes requests, whether it takes ws and how, and
//! the headers every response carries.  JSON (`npro-json`) is one way to
//! make them, Rust code another; npro-ss sees only these.  It is the first
//! form of `docs/ss-policy.md`: the layers, vhosts and routes come after,
//! and nothing here stops them.

use npro_h1::server::Config as H1Config;

/// A listener, C's server streamtype: one address the adapter binds, and
/// how what it accepts is served.
///
/// ```
/// use npro_h1::server::Config;
/// use npro_ss::policy::{Listener, Tls, Ws};
///
/// let l = Listener {
///     name: "www",
///     bind: "[::]:8080",
///     tls: Tls::Plain,
///     h1: Config::default(),
///     ws: Ws::NotTaken,
///     headers: &[(b"x-frame-options", b"deny")],
/// };
/// assert_eq!(l.name, "www");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listener<'p> {
    /// Its name in the policy.
    pub name: &'p str,
    /// Where the adapter binds it, as the adapter reads addresses:
    /// `[::]:443`, or `unix:/run/npro/www.sock`.
    pub bind: &'p str,
    /// Whether what it accepts is tls.
    pub tls: Tls<'p>,
    /// How its h1 takes requests: header limits, timeouts, the most a body
    /// may be.
    pub h1: H1Config,
    /// Whether it takes a request's upgrade to ws.
    pub ws: Ws<'p>,
    /// The headers every response carries, before the application's: C's
    /// vhost `headers`.
    pub headers: &'p [(&'p [u8], &'p [u8])],
}

/// Whether a listener's connections are tls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls<'p> {
    /// They are not.
    Plain,
    /// They are, with this certificate chain and key, by path: the
    /// adapter's to load, and to load again when they change on disk.
    Server {
        /// The certificate chain, PEM.
        cert: &'p str,
        /// Its private key, PEM.
        key: &'p str,
    },
}

/// Whether a listener takes a request's upgrade to ws.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ws<'p> {
    /// It does not: such a request is the application's like any other,
    /// to answer as it chooses, which a server may do (RFC 9110 7.8).
    NotTaken,
    /// It does, as this says: npro-ss answers the handshake, or refuses
    /// it as C does, before the application sees the stream again.
    Taken(WsServer<'p>),
}

/// How a listener takes ws.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsServer<'p> {
    /// The subprotocols it has, by name; a request naming none of them is
    /// refused.  Not empty.
    pub protocols: &'p [&'p [u8]],
    /// The one of `protocols` a request naming none is given, or `None` to
    /// refuse it: C's first protocol.
    pub default: Option<usize>,
    /// What the application's messages are: C's `ws_binary`.
    pub payload: Payload,
    /// Whether permessage-deflate is taken when offered.
    pub deflate: Deflate,
}

/// What a stream's ws messages are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payload {
    /// Text, which must be UTF-8.
    Text,
    /// Binary.
    Binary,
}

/// Whether permessage-deflate (RFC 7692) is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deflate {
    /// Never.
    Off,
    /// When the client offers it.  It needs npro-ss' `pmd` feature: a
    /// policy asking for it in a build without is refused.
    Offered,
}
