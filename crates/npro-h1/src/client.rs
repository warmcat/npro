//! One h1 client connection's transaction: C's
//! `lws_generate_client_handshake()` and
//! `lws_client_interpret_server_handshake()`, sans-IO.
//!
//! [`Client::tx`] writes the request's head, composed as C composes it, in
//! C's order: the request line, `Pragma` and `Cache-Control` unless asked
//! not to, `Host`, `Origin`, then `connection: close`, or nothing for a
//! connection kept for another request, or the header lines asking for an
//! upgrade ([`Connection`]), then the application's own headers, as C's
//! `LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER` adds them, then what
//! frames the request's body ([`RequestBody`]).
//!
//! A body follows the head, pulled from the application as the server's
//! answer is ([`Client::tx`] and its [`TxSource`]): a body of a
//! Content-Length to its length, or a chunked one a chunk at a time, each
//! declared by [`Client::chunk`] with whether it is the last, as C frames
//! each `lws_write()` of a body sent with no Content-Length.  Nothing is
//! read while the request goes (C's `LRS_ISSUE_HTTP_BODY`).
//!
//! [`Client::rx`] takes the response, at most one thing each call: its head
//! ([`Event::Response`]), a piece of its body, borrowed from the input
//! ([`Event::Body`]), or the body's end ([`Event::BodyEnd`]).  What it did
//! not take is held, so a body is pulled at the application's pace, never
//! buffered.  As C:
//!
//! - an interim response, 1xx but not 101, is dropped from the table and
//!   the final one awaited, up to eight of them;
//! - a response to a HEAD, and a 204 or 304, has no body whatever its
//!   framing headers say (RFC 9112 6.3);
//! - a Transfer-Encoding must be a lone `chunked`, and wins over a
//!   Content-Length; a Content-Length must be one, and only digits;
//! - with neither, the body is what comes until the server closes
//!   ([`Client::rx_closed`]).
//!
//! A response that cannot be framed fails the connection, which asks to be
//! released.
//!
//! Time is an input: the calls that can start a timer take `now`,
//! [`Client::next_deadline`] says when the connection next needs telling the
//! time, and [`Client::deadline_passed`] tells it.  From when its request
//! begins to go, the server has C's 15s ([`RESPONSE_TIMEOUT`]) to answer,
//! and as long again after each interim response, or the connection fails.
//!
//! [`Client::redirect`] says whether the final response redirects, and
//! where to, as C's `lws_client_interpret_server_handshake()` decides it.
//! Following it is a new connection's, which is the caller's to make: C
//! closes the connection and starts over (`lws_client_reset()`).
//!
//! The final response to a request for an upgrade is not framed at all:
//! after its head, whatever its status, the connection is the upgraded
//! protocol's ([`Client::is_upgraded`]), which judges the response, as C's
//! `lws_client_ws_upgrade()` does for ws.

use core::time::Duration;

use npro_core::time::Instant;

use crate::chunked::{self, Chunk, Dechunk};
use crate::fields::{content_length, transfer_encoding_is_chunked};
use crate::head::{self, Head, Progress, Refused, Side};
use crate::own::Own;
pub use crate::own::{MAX_OWN, RespondError};
use crate::server::TxSource;
use crate::table::{CapacityTooLarge, Full, HeaderTable};
use crate::token::Token;
use crate::uri::{self, Uri, UriError};
pub use npro_core::close::Close;

/// How many interim responses a client takes before the final one: C's
/// `LWS_HTTP_INTERIM_RESPONSE_LIMIT`.
pub const INTERIM_LIMIT: u8 = 8;

/// How long the server has to answer, from when the request begins to go
/// and again after each interim response: C's
/// `PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE`, the context's
/// `timeout_secs`.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// How many redirects one request follows: C's `lws_client_reset()`
/// refuses a fifth.  Counting them is the caller's, which makes each new
/// connection.
pub const REDIRECT_LIMIT: u8 = 4;

/// The method a redirected request is made with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectMethod {
    /// The same method, with the same body.
    Same,
    /// `GET`, with no body.
    Get,
}

/// Where a redirect goes: [`Client::redirect`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redirect<'a> {
    /// The URL to make the request of, in the storage given.
    pub to: Uri<'a>,
    /// The method to make it with.
    pub method: RedirectMethod,
}

/// Why a redirect is not followed.  The first three are C's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectError {
    /// No `Location`: "HS: Redirect code but no Location".
    NoLocation,
    /// A `Location` npro does not take: "HS: URI did not parse".
    Location(UriError),
    /// From tls to plaintext, not allowed: "HS: Redirect attempted SSL
    /// downgrade".
    Downgrade,
    /// More than one `Location`, which C does not check: which to follow
    /// is not known.
    Locations,
}

impl core::fmt::Display for RedirectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoLocation => f.write_str("HS: Redirect code but no Location"),
            Self::Location(e) => write!(f, "HS: URI did not parse: {e}"),
            Self::Downgrade => f.write_str("HS: Redirect attempted SSL downgrade"),
            Self::Locations => f.write_str("HS: Redirect with more than one Location"),
        }
    }
}

impl core::error::Error for RedirectError {}

/// Where the request's `Origin` comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `http://`.
    Http,
    /// `https://`, the connection being tls.
    Https,
}

/// What to ask: C's `lws_client_connect_info`, as far as the head goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    /// The method, `GET`, `HEAD`...
    pub method: &'a [u8],
    /// The path, with any urlargs.
    pub path: &'a [u8],
    /// The `Host`, if any.
    pub host: Option<&'a [u8]>,
    /// The `Origin`'s host, sent after the scheme, if any.
    pub origin: Option<&'a [u8]>,
    /// The scheme `Origin` says.
    pub scheme: Scheme,
    /// Send `Pragma: no-cache` and `Cache-Control: no-cache`, unless C's
    /// `LCCSCF_HTTP_NO_CACHE_CONTROL`.
    pub no_cache: bool,
    /// What becomes of the connection after this request.
    pub connection: Connection<'a>,
    /// The application's own headers, names and values, sent last.  A name
    /// must be a token, and a value must have no CR, LF or NUL, so neither
    /// can end its line early; the headers the request's framing and
    /// connection depend on are the client's to write, and refused here
    /// ([`HeaderRefused`]).
    pub headers: &'a [(&'a [u8], &'a [u8])],
    /// The body that follows the head, and how it is framed.
    pub body: RequestBody,
}

/// The body that follows the request's head, and how it is framed: the
/// last of the request's headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestBody {
    /// None: nothing is said, and a server takes none (RFC 9112 6.3).
    None,
    /// This many bytes: `Content-Length`, the body pulled to its length.
    Length(u64),
    /// Of a length not known when the head goes: `Transfer-Encoding:
    /// chunked`, in C's spelling, the chunks declared by
    /// [`Client::chunk`].  C sends a body the application gave no length
    /// so (`lws_generate_client_handshake()`).
    Chunked,
}

/// Why [`Client::chunk`] refused a chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkError {
    /// The request's body is not chunked.
    NotChunked,
    /// A chunk is in hand, or the last has been declared.
    NotNow,
}

impl core::fmt::Display for ChunkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotChunked => "the request's body is not chunked",
            Self::NotNow => "a chunk is in hand, or the body is over",
        })
    }
}

impl core::error::Error for ChunkError {}

/// Why one of the application's headers is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderRefused {
    /// Its name is empty or not an RFC 9110 token.
    Name,
    /// Its value has a CR, LF or NUL.
    Value,
    /// It is one the client writes itself: `Host`, `Connection`,
    /// `Upgrade`, `Content-Length` or `Transfer-Encoding`.  Sent by the
    /// application as well, the server could read the request's framing
    /// differently from how the client sends it.
    Reserved,
}

impl core::fmt::Display for HeaderRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Name => "a header name is not a token",
            Self::Value => "a header value has a CR, LF or NUL",
            Self::Reserved => "a header the client writes itself",
        })
    }
}

impl core::error::Error for HeaderRefused {}

/// The headers the client writes itself, which the application may not.
const RESERVED: [&[u8]; 5] = [
    b"host",
    b"connection",
    b"upgrade",
    b"content-length",
    b"transfer-encoding",
];

/// Whether `c` may be in an RFC 9110 token: `tchar`.
const fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Checks one of the application's headers.
fn check_header(name: &[u8], value: &[u8]) -> Result<(), HeaderRefused> {
    if name.is_empty() || !name.iter().all(|c| is_tchar(*c)) {
        return Err(HeaderRefused::Name);
    }
    if value.iter().any(|c| matches!(c, b'\r' | b'\n' | b'\0')) {
        return Err(HeaderRefused::Value);
    }
    if RESERVED.iter().any(|r| name.eq_ignore_ascii_case(r)) {
        return Err(HeaderRefused::Reserved);
    }
    Ok(())
}

/// What becomes of the connection after the request: the last of the
/// request's headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Connection<'a> {
    /// It ends with the transaction: `connection: close`.
    Close,
    /// It is kept for another request, C's pipelining: nothing is said.
    KeepAlive,
    /// It is upgraded, these header lines, each ending in CRLF, asking for
    /// it: C's `do_ws`, whose lines `npro_ws::handshake::ClientKey`
    /// composes.
    Upgrade(&'a [u8]),
}

/// What the server's bytes were.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// The final response's head: [`Client::response`] has it, and
    /// [`Client::status`] its status.  C's
    /// `LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP`.
    Response,
    /// The next piece of its body: C's
    /// `LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ`.
    Body(&'a [u8]),
    /// Its body is over: C's `LWS_CALLBACK_COMPLETED_CLIENT_HTTP`.
    BodyEnd,
}

/// What [`Client::rx`] took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rx<'a> {
    /// How many bytes it took.  The rest are the caller's to hand in again.
    pub consumed: usize,
    /// What they were, if they came to something.
    pub event: Option<Event<'a>>,
}

/// Why the response failed the connection.  Each is one of C's
/// `CLIENT_CONNECTION_ERROR` reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The head was refused.
    Head(Refused),
    /// There is no status line: C's "HS: URI missing".
    NoStatus,
    /// More than [`INTERIM_LIMIT`] interim responses.
    TooManyInterims,
    /// A Transfer-Encoding that is not a lone `chunked`: "HS: unsupported
    /// TE".
    TransferEncoding,
    /// A second Content-Length, or one that is not one: "HS: bad
    /// Content-Length".
    ContentLength,
    /// The chunked body cannot be framed.
    Chunked(chunked::Error),
    /// The server closed before the body it said it would send.
    Closed,
    /// The server did not answer in time: C's "Timed out waiting server
    /// reply".
    TimedOut,
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Head(r) => write!(f, "{r}"),
            Self::NoStatus => f.write_str("HS: URI missing"),
            Self::TooManyInterims => f.write_str("HS: too many interim responses"),
            Self::TransferEncoding => f.write_str("HS: unsupported TE"),
            Self::ContentLength => f.write_str("HS: bad Content-Length"),
            Self::Chunked(e) => write!(f, "{e}"),
            Self::Closed => f.write_str("closed before the body ended"),
            Self::TimedOut => f.write_str("Timed out waiting server reply"),
        }
    }
}

impl core::error::Error for Failure {}

/// How the response's body is framed, and how far it has come.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Body {
    /// This much of a Content-Length body is still to come.
    Length(u64),
    /// A chunked body.
    Chunked(Dechunk),
    /// Until the server closes.
    ToClose,
    /// It is over, and its end is yet to be told.
    EndDue,
    /// It is over.
    Over,
}

/// Where the connection is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// The request is yet to go, and then its body, if `up`.
    Asking { up: Option<Upload> },
    /// The request's head is going, and then its body, if `up`; the
    /// response is due by `until`, or with a body, the head must have gone.
    Sending { until: Instant, up: Option<Upload> },
    /// The request's body is going, the next of it due by `until`: C's
    /// `PENDING_TIMEOUT_CLIENT_ISSUE_PAYLOAD`.
    Uploading { up: Upload, until: Instant },
    /// Waiting for the response's head, due by `until`; this many
    /// interims so far.
    Head { interims: u8, until: Instant },
    /// Taking the response's body.
    Body(Body),
    /// The transaction is over, and the connection is still up: as C,
    /// a client whose transaction is over leaves the connection to the
    /// server's close, or the next request's.
    Done,
    /// The transaction is over and the server has closed.
    Closed,
    /// The final response to a request for an upgrade has come: the
    /// connection is the upgraded protocol's.
    Upgraded,
    /// The connection failed.
    Failed(Failure),
}

/// The most bytes of a chunked body's framing held at once: a size line,
/// sixteen hex digits and CRLF, or a chunk's CRLF and the last-chunk.
const FRAME_MAX: usize = 18;

/// A chunked body's framing, held until it has gone: a chunk's size line,
/// or what ends a chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frame {
    buf: [u8; FRAME_MAX],
    len: usize,
    sent: usize,
}

impl Frame {
    /// `parts`, one after the other; the callers' parts fit by
    /// [`FRAME_MAX`].
    fn of(parts: &[&[u8]]) -> Self {
        let mut f = Self {
            buf: [0; FRAME_MAX],
            len: 0,
            sent: 0,
        };
        for p in parts {
            let end = f.len.saturating_add(p.len());
            if let Some(dst) = f.buf.get_mut(f.len..end) {
                dst.copy_from_slice(p);
                f.len = end;
            }
        }
        f
    }

    /// A chunk's size line: its length in hex, as C's `%X`, and CRLF.
    fn size_line(n: u64) -> Self {
        let mut d = [0u8; 16];
        let mut at = d.len();
        let mut v = n;
        loop {
            at = at.saturating_sub(1);
            let digit = usize::try_from(v & 0xf).unwrap_or(0);
            if let (Some(slot), Some(c)) = (d.get_mut(at), b"0123456789ABCDEF".get(digit)) {
                *slot = *c;
            }
            v >>= 4;
            if v == 0 {
                break;
            }
        }
        Self::of(&[d.get(at..).unwrap_or_default(), b"\r\n"])
    }

    /// What ends a chunk: the CRLF after its data, if it had any, then the
    /// last-chunk and the empty trailer, if it is the last.
    fn tail(data: bool, last: bool) -> Self {
        Self::of(&[
            if data { b"\r\n" } else { b"" },
            if last { b"0\r\n\r\n" } else { b"" },
        ])
    }

    const fn pending(&self) -> bool {
        self.sent < self.len
    }

    /// Writes what is left into `out`, returning how much.
    fn drain(&mut self, out: &mut [u8]) -> usize {
        let rest = self.buf.get(self.sent..self.len).unwrap_or_default();
        let n = rest.len().min(out.len());
        if let (Some(d), Some(s)) = (out.get_mut(..n), rest.get(..n)) {
            d.copy_from_slice(s);
        }
        self.sent = self.sent.saturating_add(n);
        n
    }
}

/// How far the request's body has gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Upload {
    /// A body of a Content-Length, this much of it still to be pulled.
    Length(u64),
    /// A chunked body between chunks: the application has yet to declare
    /// the next.
    ChunkAwaited,
    /// A chunk: its size line going, then this much of its data to pull;
    /// the last-chunk follows it if `last`.
    Chunk { line: Frame, owed: u64, last: bool },
    /// What ends a chunk going; then the body is over if `last`, or the
    /// next chunk is awaited.
    ChunkEnd { tail: Frame, last: bool },
}

/// What the request asked for: a transaction, or an upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Asked {
    /// A transaction, then the connection closes.
    Close,
    /// A transaction, the connection kept for another.
    KeepAlive,
    /// An upgrade.
    Upgrade,
}

/// One h1 client connection.
///
/// ```
/// use npro_core::time::Instant;
/// use npro_h1::client::{Client, Connection, Event, Request, RequestBody, Scheme};
/// use npro_h1::server::NoPayload;
///
/// let now = Instant::from_micros(1_000_000);
/// let mut c = Client::new([0u8; 1024], Request {
///     method: b"GET",
///     path: b"/x",
///     host: Some(b"example.com"),
///     origin: None,
///     scheme: Scheme::Http,
///     no_cache: false,
///     connection: Connection::Close,
///     headers: &[],
///     body: RequestBody::None,
/// })?;
/// let mut out = [0u8; 256];
/// let n = c.tx(now, &mut out, &mut NoPayload);
/// assert_eq!(&out[..n], b"GET /x HTTP/1.1\r\nHost: example.com\r\nconnection: close\r\n\r\n");
///
/// let mut input = &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..];
/// let rx = c.rx(now, input)?;
/// assert_eq!((rx.event, c.status()), (Some(Event::Response), Some(200)));
/// input = &input[rx.consumed..];
/// assert_eq!(c.rx(now, input)?.event, Some(Event::Body(b"ok")));
/// assert_eq!(c.rx(now, b"")?.event, Some(Event::BodyEnd));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Client<S> {
    head: Head<S>,
    asked: Asked,
    phase: Phase,
    own: Own,
    status: Option<u16>,
    /// How long the server has to answer.
    timeout: Duration,
}

/// Why a client cannot be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewError {
    /// The storage is too large for a table.
    Capacity(CapacityTooLarge),
    /// The request does not fit in the table.
    Table(Full),
    /// The request's head does not fit in [`MAX_OWN`].
    Head(RespondError),
    /// One of the application's headers is refused.
    Header(HeaderRefused),
    /// A request for an upgrade has a body, which a server refuses with
    /// 400.
    UpgradeWithBody,
}

impl core::fmt::Display for NewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Capacity(e) => write!(f, "{e}"),
            Self::Table(e) => write!(f, "{e}"),
            Self::Head(e) => write!(f, "{e}"),
            Self::Header(e) => write!(f, "{e}"),
            Self::UpgradeWithBody => f.write_str("a request for an upgrade has a body"),
        }
    }
}

impl core::error::Error for NewError {}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Client<S> {
    /// A connection to make `req`, keeping it and its response in
    /// `storage`, as C keeps a client's request in the ah it parses the
    /// response into.
    ///
    /// # Errors
    ///
    /// [`NewError`] if the storage is too large, the request does not fit,
    /// or one of its headers is refused.
    pub fn new(storage: S, req: Request<'_>) -> Result<Self, NewError> {
        for (name, value) in req.headers {
            check_header(name, value).map_err(NewError::Header)?;
        }
        let up = match req.body {
            RequestBody::None | RequestBody::Length(0) => None,
            RequestBody::Length(n) => Some(Upload::Length(n)),
            RequestBody::Chunked => Some(Upload::ChunkAwaited),
        };
        if up.is_some() && matches!(req.connection, Connection::Upgrade(_)) {
            return Err(NewError::UpgradeWithBody);
        }
        let mut t = HeaderTable::new(storage).map_err(NewError::Capacity)?;
        for (tok, v) in [
            (Token::ClientUri, Some(req.path)),
            (Token::ClientHost, req.host),
            (Token::ClientOrigin, req.origin),
            (Token::ClientMethod, Some(req.method)),
        ] {
            if let Some(v) = v {
                t.create(tok, v).map_err(NewError::Table)?;
            }
        }
        // the response is parsed after the request: an interim is dropped
        // back to here
        t.snapshot();
        Ok(Self {
            head: Head::with_table(t, Side::Client, head::Config::new()),
            asked: match req.connection {
                Connection::Close => Asked::Close,
                Connection::KeepAlive => Asked::KeepAlive,
                Connection::Upgrade(_) => Asked::Upgrade,
            },
            phase: Phase::Asking { up },
            own: request_head(&req).map_err(NewError::Head)?,
            status: None,
            timeout: RESPONSE_TIMEOUT,
        })
    }

    /// The connection with the server given `timeout` to answer, rather
    /// than [`RESPONSE_TIMEOUT`].
    #[must_use]
    pub const fn with_response_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// When the connection next needs [`Client::deadline_passed`], if it is
    /// waiting on the server.
    #[must_use]
    pub const fn next_deadline(&self) -> Option<Instant> {
        match self.phase {
            Phase::Sending { until, .. }
            | Phase::Uploading { until, .. }
            | Phase::Head { until, .. } => Some(until),
            Phase::Asking { .. }
            | Phase::Body(_)
            | Phase::Done
            | Phase::Closed
            | Phase::Upgraded
            | Phase::Failed(_) => None,
        }
    }

    /// Tells the connection it is `now`, which may be past its
    /// [`Client::next_deadline`]: then it fails, [`Failure::TimedOut`], and
    /// asks to be aborted.
    pub fn deadline_passed(&mut self, now: Instant) {
        if self.next_deadline().is_some_and(|d| now >= d) {
            self.own = Own::new();
            self.phase = Phase::Failed(Failure::TimedOut);
        }
    }

    /// Gives back the storage the connection's header table was made in,
    /// as [`crate::server::Server::into_storage`] does.
    #[must_use]
    pub fn into_storage(self) -> S {
        self.head.into_table().into_storage()
    }

    /// The response's headers, after the request's own tokens.
    #[must_use]
    pub const fn response(&self) -> &HeaderTable<S> {
        self.head.table()
    }

    /// The final response's status, once its head is in.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.status
    }

    /// Whether [`Client::rx`] has something to give without more input:
    /// the end of a response's body that came with the bytes already
    /// taken, or of one there was none of.  A caller that hands in input
    /// only as it arrives must call `rx` again, with none, while this
    /// holds.
    #[must_use]
    pub const fn rx_pending(&self) -> bool {
        matches!(self.phase, Phase::Body(Body::EndDue))
    }

    /// Whether the connection has something of its own to write: the
    /// request's head, or a chunked body's framing.  Whether the
    /// application has more of the body is the application's to say to
    /// whatever pulls it.
    #[must_use]
    pub const fn wants_write(&self) -> bool {
        self.own.pending()
            || match self.phase {
                Phase::Uploading {
                    up: Upload::Chunk { line: f, .. } | Upload::ChunkEnd { tail: f, .. },
                    ..
                } => f.pending(),
                Phase::Uploading {
                    up: Upload::Length(_) | Upload::ChunkAwaited,
                    ..
                }
                | Phase::Asking { .. }
                | Phase::Sending { .. }
                | Phase::Head { .. }
                | Phase::Body(_)
                | Phase::Done
                | Phase::Closed
                | Phase::Upgraded
                | Phase::Failed(_) => false,
            }
    }

    /// Declares the next chunk of a chunked body: `len` bytes, pulled
    /// from the application as they go, the last-chunk after them if
    /// `last`.  It may be declared before the head has gone.  A chunk of
    /// no bytes that is not the last is nothing on the wire, as in C,
    /// since it would be the last-chunk; one that is the last is the
    /// last-chunk alone.
    ///
    /// # Errors
    ///
    /// [`ChunkError::NotChunked`] if the body is not chunked, or
    /// [`ChunkError::NotNow`] while a chunk is in hand, or once the last
    /// has been declared.
    pub fn chunk(&mut self, len: u64, last: bool) -> Result<(), ChunkError> {
        let up = match &mut self.phase {
            Phase::Asking { up: Some(up) }
            | Phase::Sending { up: Some(up), .. }
            | Phase::Uploading { up, .. } => up,
            Phase::Asking { up: None } | Phase::Sending { up: None, .. } => {
                return Err(ChunkError::NotChunked);
            }
            Phase::Head { .. }
            | Phase::Body(_)
            | Phase::Done
            | Phase::Closed
            | Phase::Upgraded
            | Phase::Failed(_) => return Err(ChunkError::NotNow),
        };
        match up {
            Upload::ChunkAwaited => {}
            Upload::Length(_) => return Err(ChunkError::NotChunked),
            Upload::Chunk { .. } | Upload::ChunkEnd { .. } => return Err(ChunkError::NotNow),
        }
        *up = match (len, last) {
            (0, false) => Upload::ChunkAwaited,
            (0, true) => Upload::ChunkEnd {
                tail: Frame::tail(false, true),
                last: true,
            },
            (n, last) => Upload::Chunk {
                line: Frame::size_line(n),
                owed: n,
                last,
            },
        };
        Ok(())
    }

    /// What the connection asks of whatever carries it, once it is done
    /// with: [`Close::Abort`] once it failed, as C closes a client whose
    /// connection failed with nothing more to say; [`Close::Release`] once
    /// its transaction is over and the server has closed, a client staging
    /// no shutdown in C.  A transaction over with the connection still up
    /// asks nothing, whatever its `Connection` said: C gives the
    /// application the transaction's end
    /// (`LWS_CALLBACK_COMPLETED_CLIENT_HTTP`) and closes only if it asks,
    /// and otherwise on the server's close.  An upgraded connection is the
    /// upgraded protocol's.
    #[must_use]
    pub const fn close(&self) -> Option<Close> {
        match self.phase {
            Phase::Failed(_) => Some(Close::Abort),
            Phase::Closed => Some(Close::Release),
            Phase::Asking { .. }
            | Phase::Sending { .. }
            | Phase::Uploading { .. }
            | Phase::Head { .. }
            | Phase::Body(_)
            | Phase::Done
            | Phase::Upgraded => None,
        }
    }

    /// Why the connection failed, if it did: then it asks to be aborted.
    #[must_use]
    pub const fn failed(&self) -> Option<Failure> {
        match self.phase {
            Phase::Failed(f) => Some(f),
            Phase::Asking { .. }
            | Phase::Sending { .. }
            | Phase::Uploading { .. }
            | Phase::Head { .. }
            | Phase::Body(_)
            | Phase::Done
            | Phase::Closed
            | Phase::Upgraded => None,
        }
    }

    /// Whether the transaction is over.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Done | Phase::Closed)
    }

    /// Whether the final response redirects, and if so where, its
    /// `Location` resolved against `from`, the URL this request was made
    /// of, into `storage`; `None` before the final response, or if it is
    /// not 301, 302, 303, 307 or 308, as C follows.  A redirect from tls
    /// to plaintext is refused unless `downgrade` (C's
    /// `LCCSCF_ACCEPT_TLS_DOWNGRADE_REDIRECTS`).
    ///
    /// The method, by RFC 9110 15.4 and as browsers do, where C makes
    /// every redirect but a 307 or 308 a GET: a 307 or 308 keeps the
    /// method and its body; a 303 is a GET, but for a HEAD; a 301 or 302
    /// makes a POST a GET, and keeps any other method.
    ///
    /// ```
    /// use npro_h1::client::{Client, Connection, Event, RedirectMethod, Request, RequestBody, Scheme};
    /// use npro_h1::server::NoPayload;
    /// use npro_h1::uri;
    /// use npro_core::time::Instant;
    ///
    /// let now = Instant::from_micros(1_000_000);
    /// let mut c = Client::new([0u8; 1024], Request {
    ///     method: b"POST",
    ///     path: b"/a/form",
    ///     host: Some(b"example.com"),
    ///     origin: None,
    ///     scheme: Scheme::Https,
    ///     no_cache: false,
    ///     connection: Connection::Close,
    ///     headers: &[],
    ///     body: RequestBody::Length(0),
    /// })?;
    /// let _ = c.tx(now, &mut [0u8; 256], &mut NoPayload);
    /// let rx = c.rx(now, b"HTTP/1.1 302 Found\r\nLocation: done?ok\r\n\r\n")?;
    /// assert_eq!(rx.event, Some(Event::Response));
    ///
    /// let mut f = [0u8; 256];
    /// let from = uri::parse(b"https://example.com/a/form", &mut f)?;
    /// let mut t = [0u8; 256];
    /// let r = c.redirect(&from, false, &mut t).unwrap()?;
    /// assert_eq!((r.to.host(), r.to.target()), (&b"example.com"[..], &b"/a/done?ok"[..]));
    /// assert_eq!(r.method, RedirectMethod::Get);
    /// # Ok::<(), Box<dyn core::error::Error>>(())
    /// ```
    #[must_use]
    pub fn redirect<'b>(
        &self,
        from: &Uri<'_>,
        downgrade: bool,
        storage: &'b mut [u8],
    ) -> Option<Result<Redirect<'b>, RedirectError>> {
        let status = self.status?;
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            return None;
        }
        let t = self.head.table();
        let mut locations = t.fragments(Token::Location);
        let Some(location) = locations.next() else {
            return Some(Err(RedirectError::NoLocation));
        };
        if locations.next().is_some() {
            return Some(Err(RedirectError::Locations));
        }
        let to = match uri::resolve(from, location, storage) {
            Ok(to) => to,
            Err(e) => return Some(Err(RedirectError::Location(e))),
        };
        if from.scheme().is_tls() && !to.scheme().is_tls() && !downgrade {
            return Some(Err(RedirectError::Downgrade));
        }
        let method = t.first(Token::ClientMethod).unwrap_or_default();
        let method = match status {
            303 if method != b"HEAD" => RedirectMethod::Get,
            301 | 302 if method == b"POST" => RedirectMethod::Get,
            _ => RedirectMethod::Same,
        };
        Some(Ok(Redirect { to, method }))
    }

    /// Whether the final response to a request for an upgrade has come:
    /// from the byte after its head, the connection is the upgraded
    /// protocol's, and this takes nothing more.
    #[must_use]
    pub const fn is_upgraded(&self) -> bool {
        matches!(self.phase, Phase::Upgraded)
    }

    /// Writes the request, or what is left of it, into `out`, at `now`,
    /// returning how much: its head, then its body, pulled from `src` and
    /// framed as the head said.
    ///
    /// Without a body, the server's answer is due from when the head
    /// begins to go, as C sends it whole, in one push, and starts waiting
    /// then.  With one, as C, the body's next bytes are due from when the
    /// head has gone, and the answer from when the body has.  Unlike C,
    /// whose `PENDING_TIMEOUT_CLIENT_ISSUE_PAYLOAD` is set once for the
    /// whole body, each piece of the body that goes renews the wait for
    /// the next, as a server's answer renews its own: a body slower to go
    /// than the timeout is not cut off while it moves.
    pub fn tx(&mut self, now: Instant, out: &mut [u8], src: &mut dyn TxSource) -> usize {
        let mut written = 0usize;
        loop {
            let room = out.get_mut(written..).unwrap_or_default();
            match self.phase {
                Phase::Asking { up } => {
                    let n = self.own.drain(room);
                    if n == 0 {
                        return written;
                    }
                    written = written.saturating_add(n);
                    self.phase = Phase::Sending {
                        until: now.saturating_add(self.timeout),
                        up,
                    };
                }
                Phase::Sending { until, up } => {
                    written = written.saturating_add(self.own.drain(room));
                    if self.own.pending() {
                        return written;
                    }
                    let Some(up) = up else {
                        self.phase = Phase::Head { interims: 0, until };
                        return written;
                    };
                    self.phase = Phase::Uploading {
                        up,
                        until: now.saturating_add(self.timeout),
                    };
                }
                Phase::Uploading { up, until } => {
                    let (n, next) = upload(up, room, src);
                    written = written.saturating_add(n);
                    let until = if n > 0 {
                        now.saturating_add(self.timeout)
                    } else {
                        until
                    };
                    let Some(going) = next else {
                        // the body has gone: the answer is due
                        self.phase = Phase::Head {
                            interims: 0,
                            until: now.saturating_add(self.timeout),
                        };
                        return written;
                    };
                    self.phase = Phase::Uploading { up: going, until };
                    if n == 0 {
                        return written;
                    }
                }
                Phase::Head { .. }
                | Phase::Body(_)
                | Phase::Done
                | Phase::Closed
                | Phase::Upgraded
                | Phase::Failed(_) => return written,
            }
        }
    }

    const fn fail<'a>(&mut self, f: Failure) -> Result<Rx<'a>, Failure> {
        self.phase = Phase::Failed(f);
        Err(f)
    }

    /// Takes bytes from the server, at `now`: see [`Event`].
    ///
    /// # Errors
    ///
    /// The [`Failure`], once the response fails the connection, and on
    /// every call after.
    pub fn rx<'a>(&mut self, now: Instant, input: &'a [u8]) -> Result<Rx<'a>, Failure> {
        let held = Ok(Rx {
            consumed: 0,
            event: None,
        });
        match self.phase {
            Phase::Failed(f) => Err(f),
            Phase::Asking { .. }
            | Phase::Sending { .. }
            | Phase::Uploading { .. }
            | Phase::Done
            | Phase::Closed
            | Phase::Upgraded => held,
            Phase::Head { interims, .. } => self.rx_head(now, interims, input),
            Phase::Body(b) => self.rx_body(b, input),
        }
    }

    fn rx_head<'a>(
        &mut self,
        now: Instant,
        interims: u8,
        input: &'a [u8],
    ) -> Result<Rx<'a>, Failure> {
        let consumed = match self.head.rx(input) {
            Ok(Progress::More) => {
                return Ok(Rx {
                    consumed: input.len(),
                    event: None,
                });
            }
            Ok(Progress::Complete { consumed }) => consumed,
            // a client has no fallback role to go to
            Ok(Progress::Fallback) => return self.fail(Failure::NoStatus),
            Err(r) => return self.fail(Failure::Head(r)),
        };
        let t = self.head.table();
        let Some(line) = t.first(Token::Http).or_else(|| t.first(Token::Http10)) else {
            return self.fail(Failure::NoStatus);
        };
        let status = atoi(line);
        if (100..200).contains(&status) && status != 101 {
            let n = interims.saturating_add(1);
            if n > INTERIM_LIMIT {
                return self.fail(Failure::TooManyInterims);
            }
            // nothing for the app: back to the request, for the final one,
            // which has the timeout again
            self.head.rewind();
            self.phase = Phase::Head {
                interims: n,
                until: now.saturating_add(self.timeout),
            };
            return Ok(Rx {
                consumed,
                event: None,
            });
        }
        if self.asked == Asked::Upgrade {
            // not framed: the upgraded protocol judges it
            self.status = u16::try_from(status).ok();
            self.phase = Phase::Upgraded;
            return Ok(Rx {
                consumed,
                event: Some(Event::Response),
            });
        }
        let body = match self.framing(status) {
            Ok(b) => b,
            Err(f) => return self.fail(f),
        };
        self.status = u16::try_from(status).ok();
        self.phase = Phase::Body(body);
        Ok(Rx {
            consumed,
            event: Some(Event::Response),
        })
    }

    /// How the final response's body is framed, as C decides it.
    fn framing(&self, status: i64) -> Result<Body, Failure> {
        let t = self.head.table();
        let bodyless = status == 204
            || status == 304
            || t.first(Token::ClientMethod) == Some(b"HEAD".as_slice());
        if bodyless {
            return Ok(Body::EndDue);
        }
        if t.is_present(Token::TransferEncoding) {
            if !transfer_encoding_is_chunked(t) {
                return Err(Failure::TransferEncoding);
            }
            // it wins over any Content-Length
            return Ok(Body::Chunked(Dechunk::new()));
        }
        if t.is_present(Token::ContentLength) {
            let mut f = t.fragments(Token::ContentLength);
            return match (f.next(), f.next()) {
                (Some(v), None) if v.len() < 32 => match content_length(v) {
                    Ok(0) => Ok(Body::EndDue),
                    Ok(n) => Ok(Body::Length(n)),
                    Err(_) => Err(Failure::ContentLength),
                },
                _ => Err(Failure::ContentLength),
            };
        }
        Ok(Body::ToClose)
    }

    fn rx_body<'a>(&mut self, body: Body, input: &'a [u8]) -> Result<Rx<'a>, Failure> {
        let (consumed, next, event) = match body {
            Body::Over => {
                self.phase = Phase::Done;
                return Ok(Rx {
                    consumed: 0,
                    event: None,
                });
            }
            Body::EndDue => (0, Body::Over, Some(Event::BodyEnd)),
            Body::Length(left) => {
                let n = usize::try_from(left).unwrap_or(usize::MAX).min(input.len());
                let rest = left.saturating_sub(u64::try_from(n).unwrap_or(left));
                let next = if rest == 0 {
                    Body::EndDue
                } else {
                    Body::Length(rest)
                };
                let piece = input.get(..n).unwrap_or_default();
                (n, next, (n > 0).then_some(Event::Body(piece)))
            }
            Body::ToClose => {
                let event = (!input.is_empty()).then_some(Event::Body(input));
                (input.len(), Body::ToClose, event)
            }
            Body::Chunked(mut d) => {
                let s = match d.step(input) {
                    Ok(s) => s,
                    Err(e) => return self.fail(Failure::Chunked(e)),
                };
                match s.chunk {
                    Chunk::End => (s.consumed, Body::EndDue, None),
                    Chunk::Data(b) => (s.consumed, Body::Chunked(d), Some(Event::Body(b))),
                    Chunk::More => (s.consumed, Body::Chunked(d), None),
                }
            }
        };
        self.phase = if next == Body::Over {
            Phase::Done
        } else {
            Phase::Body(next)
        };
        Ok(Rx { consumed, event })
    }

    /// The server closed the connection: the end of a body framed by the
    /// close, or a failure if the body was framed otherwise.  The
    /// transaction over, the connection then asks to be released.
    ///
    /// # Errors
    ///
    /// [`Failure::Closed`] if a body or head was still to come.
    pub const fn rx_closed<'a>(&mut self) -> Result<Option<Event<'a>>, Failure> {
        match self.phase {
            Phase::Failed(f) => Err(f),
            Phase::Closed | Phase::Upgraded => Ok(None),
            Phase::Body(Body::ToClose | Body::EndDue) => {
                self.phase = Phase::Closed;
                Ok(Some(Event::BodyEnd))
            }
            Phase::Body(Body::Over) | Phase::Done => {
                self.phase = Phase::Closed;
                Ok(None)
            }
            Phase::Asking { .. }
            | Phase::Sending { .. }
            | Phase::Uploading { .. }
            | Phase::Head { .. }
            | Phase::Body(Body::Length(_) | Body::Chunked(_)) => {
                self.phase = Phase::Failed(Failure::Closed);
                Err(Failure::Closed)
            }
        }
    }
}

/// Writes the next of the body into `room`, pulling its data from `src`,
/// returning how much, and how far the body has gone after it: `None` once
/// it is over.
fn upload(up: Upload, room: &mut [u8], src: &mut dyn TxSource) -> (usize, Option<Upload>) {
    // the next `owed` bytes of the body's data, as much as there is room
    // for and the application has
    let mut pull = |owed: u64| {
        let cap = usize::try_from(owed).unwrap_or(usize::MAX).min(room.len());
        let n = src.fill(room.get_mut(..cap).unwrap_or_default()).min(cap);
        (n, owed.saturating_sub(u64::try_from(n).unwrap_or(owed)))
    };
    match up {
        Upload::ChunkAwaited => (0, Some(up)),
        Upload::Length(owed) => {
            let (n, rest) = pull(owed);
            (n, (rest > 0).then_some(Upload::Length(rest)))
        }
        Upload::Chunk {
            mut line,
            owed,
            last,
        } if line.pending() => {
            let n = line.drain(room);
            (n, Some(Upload::Chunk { line, owed, last }))
        }
        Upload::Chunk { line, owed, last } => {
            let (n, rest) = pull(owed);
            let next = if rest > 0 {
                Upload::Chunk {
                    line,
                    owed: rest,
                    last,
                }
            } else {
                Upload::ChunkEnd {
                    tail: Frame::tail(true, last),
                    last,
                }
            };
            (n, Some(next))
        }
        Upload::ChunkEnd { mut tail, last } => {
            let n = tail.drain(room);
            let next = if tail.pending() {
                Some(Upload::ChunkEnd { tail, last })
            } else if last {
                None
            } else {
                Some(Upload::ChunkAwaited)
            };
            (n, next)
        }
    }
}

/// C's request head.
fn request_head(r: &Request<'_>) -> Result<Own, RespondError> {
    let mut o = Own::new();
    o.push(r.method)?;
    o.push(b" ")?;
    o.push(r.path)?;
    o.push(b" HTTP/1.1\r\n")?;
    if r.no_cache {
        o.push(b"Pragma: no-cache\r\nCache-Control: no-cache\r\n")?;
    }
    if let Some(h) = r.host {
        o.push(b"Host: ")?;
        o.push(h)?;
        o.push(b"\r\n")?;
    }
    if let Some(origin) = r.origin {
        o.push(match r.scheme {
            Scheme::Http => b"Origin: http://",
            Scheme::Https => b"Origin: https://",
        })?;
        o.push(origin)?;
        o.push(b"\r\n")?;
    }
    match r.connection {
        Connection::Close => o.push(b"connection: close\r\n")?,
        Connection::KeepAlive => {}
        Connection::Upgrade(lines) => o.push(lines)?,
    }
    for (name, value) in r.headers {
        o.push(name)?;
        o.push(b": ")?;
        o.push(value)?;
        o.push(b"\r\n")?;
    }
    match r.body {
        RequestBody::None => {}
        RequestBody::Length(n) => {
            o.push(b"Content-Length: ")?;
            o.push_u64(n)?;
            o.push(b"\r\n")?;
        }
        RequestBody::Chunked => o.push(b"Transfer-Encoding: chunked\r\n")?,
    }
    o.push(b"\r\n")?;
    Ok(o)
}

/// C's `atoi()`: leading white space, a sign, then digits, as far as they
/// go; 0 if there are none.
fn atoi(s: &[u8]) -> i64 {
    let mut it = s
        .iter()
        .skip_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r'))
        .peekable();
    let negative = match it.peek() {
        Some(b'-') => {
            it.next();
            true
        }
        Some(b'+') => {
            it.next();
            false
        }
        Some(_) | None => false,
    };
    let mut v = 0i64;
    for c in it {
        if !c.is_ascii_digit() {
            break;
        }
        v = v
            .saturating_mul(10)
            .saturating_add(i64::from(c.wrapping_sub(b'0')));
    }
    if negative { v.saturating_neg() } else { v }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use crate::server::{self, NoPayload, Server};
    use alloc::vec::Vec;

    /// When the tests' connections do all they do.
    const T0: Instant = Instant::from_micros(1_000_000);

    fn get(method: &'static [u8]) -> Client<[u8; 1024]> {
        let mut c = Client::new(
            [0u8; 1024],
            Request {
                method,
                path: b"/x",
                host: Some(b"sansio"),
                origin: Some(b"sansio"),
                scheme: Scheme::Http,
                no_cache: true,
                connection: Connection::Close,
                headers: &[],
                body: RequestBody::None,
            },
        )
        .unwrap();
        let mut out = [0u8; 512];
        let _ = c.tx(T0, &mut out, &mut NoPayload);
        c
    }

    #[test]
    fn interims_are_dropped_up_to_eight() {
        let mut c = get(b"GET");
        let mut input = &b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early\r\nLink: x\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
        loop {
            let rx = c.rx(T0, input).unwrap();
            input = &input[rx.consumed..];
            if rx.event == Some(Event::Response) {
                break;
            }
        }
        assert_eq!(c.status(), Some(200));
        assert!(!c.response().is_present(Token::Link));
        assert_eq!(c.response().first(Token::ClientUri), Some(&b"/x"[..]));

        let mut many = get(b"GET");
        let nine = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(9);
        let mut rest = nine.as_slice();
        let failed = loop {
            match many.rx(T0, rest) {
                Ok(rx) => rest = &rest[rx.consumed..],
                Err(f) => break f,
            }
        };
        assert_eq!(failed, Failure::TooManyInterims);
    }

    #[test]
    fn an_upgrades_response_is_handed_over_unframed() {
        let mut c = Client::new(
            [0u8; 1024],
            Request {
                method: b"GET",
                path: b"/x",
                host: None,
                origin: None,
                scheme: Scheme::Http,
                no_cache: false,
                connection: Connection::Upgrade(b"Upgrade: x\r\nConnection: Upgrade\r\n"),
                headers: &[],
                body: RequestBody::None,
            },
        )
        .unwrap();
        let mut out = [0u8; 512];
        let n = c.tx(T0, &mut out, &mut NoPayload);
        assert_eq!(
            &out[..n],
            b"GET /x HTTP/1.1\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n"
        );
        // an interim is still dropped; the 101 is final, its frames are not
        // a body, and nor would a 200's be
        let input = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 101 Go\r\n\r\n\x81\x00";
        let first = c.rx(T0, input).unwrap();
        assert_eq!(first.event, None);
        let rx = c.rx(T0, &input[first.consumed..]).unwrap();
        assert_eq!(rx.event, Some(Event::Response));
        assert_eq!(&input[first.consumed + rx.consumed..], b"\x81\x00");
        assert!(c.is_upgraded());
        assert_eq!(c.status(), Some(101));
        assert_eq!(c.rx(T0, b"\x81\x00").unwrap().consumed, 0);
    }

    #[test]
    fn a_body_to_the_close() {
        let mut c = get(b"GET");
        let head = b"HTTP/1.0 200 OK\r\n\r\n";
        assert_eq!(c.rx(T0, head).unwrap().event, Some(Event::Response));
        assert_eq!(c.rx(T0, b"abc").unwrap().event, Some(Event::Body(b"abc")));
        assert_eq!(c.rx_closed(), Ok(Some(Event::BodyEnd)));
        assert!(c.is_done());
    }

    #[test]
    fn a_close_before_the_body_ended_fails() {
        let mut c = get(b"GET");
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(c.rx(T0, head).unwrap().event, Some(Event::Response));
        assert_eq!(c.rx_closed(), Err(Failure::Closed));
        assert_eq!(c.failed(), Some(Failure::Closed));
    }

    #[test]
    fn chunked_wins_over_a_content_length() {
        let mut c = get(b"GET");
        let mut input =
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"[..];
        let mut body = [0u8; 8];
        let mut n = 0;
        loop {
            let rx = c.rx(T0, input).unwrap();
            input = &input[rx.consumed..];
            match rx.event {
                Some(Event::Body(b)) => {
                    body[n..n + b.len()].copy_from_slice(b);
                    n += b.len();
                }
                Some(Event::BodyEnd) => break,
                Some(Event::Response) | None => {}
            }
        }
        assert_eq!(&body[..n], b"abc");
    }

    fn with_headers(headers: &[(&[u8], &[u8])]) -> Result<Client<[u8; 1024]>, NewError> {
        Client::new(
            [0u8; 1024],
            Request {
                method: b"GET",
                path: b"/x",
                host: Some(b"h"),
                origin: None,
                scheme: Scheme::Http,
                no_cache: false,
                connection: Connection::Close,
                headers,
                body: RequestBody::None,
            },
        )
    }

    #[test]
    fn the_applications_headers_go_last_as_cs_append_does() {
        let mut c = with_headers(&[(b"x-a", b"1"), (b"Cookie", b"k=v; \tj=\xff")]).unwrap();
        let mut out = [0u8; 512];
        let n = c.tx(T0, &mut out, &mut NoPayload);
        assert_eq!(
            &out[..n],
            b"GET /x HTTP/1.1\r\nHost: h\r\nconnection: close\r\nx-a: 1\r\nCookie: k=v; \tj=\xff\r\n\r\n"
        );
    }

    #[test]
    fn a_header_that_could_end_its_line_or_reframe_is_refused() {
        for (h, why) in [
            ((&b""[..], &b"v"[..]), HeaderRefused::Name),
            ((b"a b", b"v"), HeaderRefused::Name),
            ((b"a:", b"v"), HeaderRefused::Name),
            ((b"a\r\nb", b"v"), HeaderRefused::Name),
            ((b"a", b"v\r\nInjected: 1"), HeaderRefused::Value),
            ((b"a", b"v\n"), HeaderRefused::Value),
            ((b"a", b"v\0"), HeaderRefused::Value),
            ((b"Content-Length", b"1"), HeaderRefused::Reserved),
            ((b"TRANSFER-ENCODING", b"chunked"), HeaderRefused::Reserved),
            ((b"host", b"x"), HeaderRefused::Reserved),
            ((b"Connection", b"close"), HeaderRefused::Reserved),
            ((b"upgrade", b"websocket"), HeaderRefused::Reserved),
        ] {
            assert_eq!(
                with_headers(&[(b"ok", b"1"), h]).err(),
                Some(NewError::Header(why)),
                "{h:?}"
            );
        }
    }

    #[test]
    fn a_status_is_cs_atoi() {
        assert_eq!(atoi(b"200 OK"), 200);
        assert_eq!(atoi(b"\t 404"), 404);
        assert_eq!(atoi(b"-1x"), -1);
        assert_eq!(atoi(b"OK"), 0);
    }

    /// `T0` and `secs` seconds.
    fn at(secs: u64) -> Instant {
        T0.checked_add(Duration::from_secs(secs)).unwrap()
    }

    fn unsent() -> Client<[u8; 1024]> {
        Client::new(
            [0u8; 1024],
            Request {
                method: b"GET",
                path: b"/x",
                host: None,
                origin: None,
                scheme: Scheme::Http,
                no_cache: false,
                connection: Connection::Close,
                headers: &[],
                body: RequestBody::None,
            },
        )
        .unwrap()
    }

    #[test]
    fn the_answer_is_due_from_when_the_request_begins_to_go() {
        let mut c = unsent();
        assert_eq!(c.next_deadline(), None);
        let mut out = [0u8; 512];
        assert_eq!(c.tx(at(1), &mut out[..4], &mut NoPayload), 4);
        assert_eq!(c.next_deadline(), Some(at(16)));
        assert!(c.tx(at(3), &mut out, &mut NoPayload) > 0);
        assert_eq!(c.next_deadline(), Some(at(16)));
        c.deadline_passed(at(15));
        assert_eq!(c.failed(), None);
        c.deadline_passed(at(16));
        assert_eq!(c.failed(), Some(Failure::TimedOut));
        assert_eq!(c.rx(at(16), b"HTTP/1.1 200 OK\r\n"), Err(Failure::TimedOut));
        assert_eq!(c.next_deadline(), None);
        assert!(!c.wants_write());
    }

    #[test]
    fn an_interim_gives_the_server_the_timeout_again() {
        let mut c = get(b"GET");
        assert_eq!(c.next_deadline(), Some(at(15)));
        let rx = c.rx(at(10), b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        assert_eq!(rx.event, None);
        assert_eq!(c.next_deadline(), Some(at(25)));
    }

    #[test]
    fn the_final_response_ends_the_wait() {
        let mut c = get(b"GET").with_response_timeout(Duration::from_secs(2));
        let rx = c.rx(at(1), b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n");
        assert_eq!(rx.unwrap().event, Some(Event::Response));
        assert_eq!(c.next_deadline(), None);
        c.deadline_passed(at(60));
        assert_eq!(c.failed(), None);
    }

    #[test]
    fn a_timeout_says_what_c_says() {
        use alloc::string::ToString;

        assert_eq!(
            Failure::TimedOut.to_string(),
            "Timed out waiting server reply"
        );
    }

    #[test]
    fn a_client_asks_to_release_or_abort_as_c_closes_it() {
        let mut c = get(b"GET");
        assert_eq!(c.close(), None);
        let rx = c.rx(T0, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(rx.unwrap().event, Some(Event::Response));
        assert_eq!(c.rx(T0, b"").unwrap().event, Some(Event::BodyEnd));
        assert_eq!(c.rx(T0, b"").unwrap().event, None);
        assert!(c.is_done());
        // as C, done is not released: the server's close is awaited,
        // whatever the request's `connection: close` said
        assert_eq!(c.close(), None);
        assert_eq!(c.rx_closed(), Ok(None));
        assert!(c.is_done());
        assert_eq!(c.close(), Some(Close::Release));

        let mut failed = get(b"GET");
        let _ = failed.rx(T0, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n");
        assert_eq!(failed.close(), Some(Close::Abort));
    }

    /// The application's body: what is left of it, given at most `step`
    /// bytes a pull.
    struct Upload<'a> {
        rest: &'a [u8],
        step: usize,
    }

    impl TxSource for Upload<'_> {
        fn fill(&mut self, buf: &mut [u8]) -> usize {
            let n = self.rest.len().min(buf.len()).min(self.step);
            buf[..n].copy_from_slice(&self.rest[..n]);
            self.rest = &self.rest[n..];
            n
        }
    }

    fn post(body: RequestBody) -> Client<[u8; 1024]> {
        Client::new(
            [0u8; 1024],
            Request {
                method: b"POST",
                path: b"/x",
                host: Some(b"h"),
                origin: None,
                scheme: Scheme::Http,
                no_cache: false,
                connection: Connection::KeepAlive,
                headers: &[],
                body,
            },
        )
        .unwrap()
    }

    /// Everything `c` writes at `now`, `room` bytes a call, until it
    /// writes nothing.
    fn sent(
        c: &mut Client<[u8; 1024]>,
        now: Instant,
        room: usize,
        src: &mut dyn TxSource,
    ) -> Vec<u8> {
        let mut all = Vec::new();
        let mut out = [0u8; 1024];
        loop {
            let n = c.tx(now, &mut out[..room], src);
            if n == 0 {
                return all;
            }
            all.extend_from_slice(&out[..n]);
        }
    }

    const HEAD: &[u8] = b"POST /x HTTP/1.1\r\nHost: h\r\n";

    #[test]
    fn a_body_of_a_length_is_pulled_to_its_length() {
        let mut c = post(RequestBody::Length(5));
        let mut src = Upload {
            rest: b"hello world",
            step: 2,
        };
        let wire = sent(&mut c, T0, 1024, &mut src);
        assert_eq!(wire, [HEAD, b"Content-Length: 5\r\n\r\nhello"].concat());
        assert_eq!(src.rest, b" world");
        // the body has gone: the answer is awaited
        let rx = c.rx(T0, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(rx.unwrap().event, Some(Event::Response));
    }

    #[test]
    fn an_empty_body_of_a_length_says_so_and_has_nothing_to_pull() {
        let mut c = post(RequestBody::Length(0));
        let wire = sent(&mut c, T0, 1024, &mut NoPayload);
        assert_eq!(wire, [HEAD, b"Content-Length: 0\r\n\r\n"].concat());
        assert_eq!(c.next_deadline(), Some(at(15)));
        assert_eq!(c.chunk(1, true), Err(ChunkError::NotNow));
    }

    #[test]
    fn a_chunked_body_goes_a_declared_chunk_at_a_time() {
        let mut c = post(RequestBody::Chunked);
        // declared before the head has gone
        c.chunk(3, false).unwrap();
        assert_eq!(c.chunk(1, false), Err(ChunkError::NotNow));
        let mut src = Upload {
            rest: b"abcdefghijklmnopqrstuvwxyz",
            step: 2,
        };
        let wire = sent(&mut c, T0, 1024, &mut src);
        assert_eq!(
            wire,
            [HEAD, b"Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n"].concat()
        );
        // nothing more till the next is declared, and an empty one that is
        // not the last is nothing on the wire
        assert!(!c.wants_write());
        c.chunk(0, false).unwrap();
        assert_eq!(sent(&mut c, T0, 1024, &mut src), b"");
        c.chunk(23, true).unwrap();
        assert!(c.wants_write());
        let rest = sent(&mut c, T0, 1024, &mut src);
        assert_eq!(rest, b"17\r\ndefghijklmnopqrstuvwxyz\r\n0\r\n\r\n");
        assert_eq!(c.chunk(1, true), Err(ChunkError::NotNow));
        assert_eq!(c.next_deadline(), Some(at(15)));
    }

    #[test]
    fn a_last_chunk_alone_ends_the_body() {
        let mut c = post(RequestBody::Chunked);
        c.chunk(0, true).unwrap();
        let wire = sent(&mut c, T0, 1024, &mut NoPayload);
        assert_eq!(
            wire,
            [HEAD, b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"].concat()
        );
        assert_eq!(c.chunk(0, true), Err(ChunkError::NotNow));
    }

    #[test]
    fn only_a_chunked_body_takes_chunks() {
        assert_eq!(
            post(RequestBody::None).chunk(1, true),
            Err(ChunkError::NotChunked)
        );
        let mut c = post(RequestBody::Length(4));
        assert_eq!(c.chunk(1, true), Err(ChunkError::NotChunked));
        assert_ne!(sent(&mut c, T0, 1024, &mut NoPayload), b"");
        assert_eq!(c.chunk(1, true), Err(ChunkError::NotChunked));
    }

    #[test]
    fn a_size_line_is_cs_hex_and_fits_any_length() {
        let mut out = [0u8; FRAME_MAX];
        for (n, line) in [
            (1u64, &b"1\r\n"[..]),
            (0xabc, b"ABC\r\n"),
            (u64::MAX, b"FFFFFFFFFFFFFFFF\r\n"),
        ] {
            let mut f = Frame::size_line(n);
            let k = f.drain(&mut out);
            assert_eq!(&out[..k], line);
            assert!(!f.pending());
        }
    }

    #[test]
    fn an_upgrade_has_no_body() {
        let r = Client::new(
            [0u8; 1024],
            Request {
                method: b"GET",
                path: b"/x",
                host: None,
                origin: None,
                scheme: Scheme::Http,
                no_cache: false,
                connection: Connection::Upgrade(b"Upgrade: x\r\n"),
                headers: &[],
                body: RequestBody::Chunked,
            },
        );
        assert_eq!(r.err(), Some(NewError::UpgradeWithBody));
    }

    #[test]
    fn nothing_is_read_while_the_body_goes() {
        let mut c = post(RequestBody::Length(4));
        assert_ne!(sent(&mut c, T0, 1024, &mut NoPayload), b"");
        let early = b"HTTP/1.1 413 Too Large\r\n\r\n";
        assert_eq!(c.rx(T0, early).unwrap().consumed, 0);
        let mut body = Upload {
            rest: b"abcd",
            step: 4,
        };
        assert_eq!(sent(&mut c, T0, 1024, &mut body), b"abcd");
        assert_eq!(c.rx(T0, early).unwrap().event, Some(Event::Response));
    }

    #[test]
    fn the_body_has_the_timeout_for_each_piece_then_the_answer() {
        let mut c = post(RequestBody::Length(4));
        let mut src = Upload {
            rest: b"abcd",
            step: 1,
        };
        let mut out = [0u8; 1024];
        // the head: the body's first piece is due from when it has gone
        let n = c.tx(at(1), &mut out, &mut NoPayload);
        assert!(n > 0);
        assert_eq!(c.next_deadline(), Some(at(16)));
        // each piece renews it, where C's is set once for the whole body
        assert_eq!(c.tx(at(10), &mut out[..1], &mut src), 1);
        assert_eq!(c.next_deadline(), Some(at(25)));
        c.deadline_passed(at(24));
        assert_eq!(c.failed(), None);
        // the rest, at once: then the answer is due from there
        assert_eq!(c.tx(at(20), &mut out, &mut src), 3);
        assert_eq!(c.next_deadline(), Some(at(35)));

        // a body that stops coming fails the connection
        let mut stalled = post(RequestBody::Chunked);
        assert_ne!(sent(&mut stalled, at(1), 1024, &mut NoPayload), b"");
        stalled.deadline_passed(at(16));
        assert_eq!(stalled.failed(), Some(Failure::TimedOut));
        assert_eq!(stalled.chunk(1, true), Err(ChunkError::NotNow));
    }

    /// The body npro's own server takes from `wire`, which must be one
    /// request and nothing more.
    fn served(wire: &[u8]) -> Vec<u8> {
        let mut s = Server::new([0u8; 1024], server::Config::default(), T0).unwrap();
        let mut input = wire;
        let mut body = Vec::new();
        loop {
            let rx = s.rx(T0, input);
            input = &input[rx.consumed..];
            match rx.event {
                Some(server::Event::Body(b)) => body.extend_from_slice(b),
                Some(server::Event::BodyEnd) => {
                    assert!(input.is_empty(), "{}", input.escape_ascii());
                    return body;
                }
                Some(server::Event::Request) => {}
                None => assert!(rx.consumed > 0, "stuck at {}", input.escape_ascii()),
            }
        }
    }

    #[test]
    fn npros_server_takes_the_body_however_it_was_written() {
        let data: Vec<u8> = (0..=255u8).cycle().take(3000).collect();
        let source = || Upload {
            rest: &data,
            step: 333,
        };
        for room in [1, 2, 7, 1024] {
            let mut by_length = post(RequestBody::Length(3000));
            let wire = sent(&mut by_length, T0, room, &mut source());
            assert_eq!(served(&wire), data, "length, {room}");

            let mut chunked = post(RequestBody::Chunked);
            let mut src = source();
            let mut chunks = Vec::new();
            for (i, piece) in data.chunks(1000).enumerate() {
                chunked
                    .chunk(u64::try_from(piece.len()).unwrap(), i == 2)
                    .unwrap();
                chunks.extend(sent(&mut chunked, T0, room, &mut src));
            }
            assert_eq!(served(&chunks), data, "chunked, {room}");
        }
    }

    /// The client, having asked `method` of `/a/b`, given `response`.
    fn answered(method: &'static [u8], response: &[u8]) -> Client<[u8; 1024]> {
        let mut c = get(method);
        let mut input = response;
        loop {
            let rx = c.rx(T0, input).unwrap();
            input = &input[rx.consumed..];
            if rx.event == Some(Event::Response) {
                return c;
            }
            assert!(rx.consumed > 0, "stuck");
        }
    }

    /// Where `c` is redirected from `from`, as text, or why not.
    fn redirected(
        c: &Client<[u8; 1024]>,
        from: &[u8],
        downgrade: bool,
    ) -> Option<Result<(Vec<u8>, RedirectMethod), RedirectError>> {
        let mut f = [0u8; 256];
        let from = uri::parse(from, &mut f).unwrap();
        let mut t = [0u8; 256];
        c.redirect(&from, downgrade, &mut t).map(|r| {
            r.map(|r| {
                let scheme: &[u8] = if r.to.scheme().is_tls() {
                    b"https://"
                } else {
                    b"http://"
                };
                let port = alloc::string::ToString::to_string(&r.to.port());
                (
                    [
                        scheme,
                        r.to.authority_host(),
                        b":",
                        port.as_bytes(),
                        r.to.target(),
                    ]
                    .concat(),
                    r.method,
                )
            })
        })
    }

    #[test]
    fn the_redirect_codes_c_follows_say_where_and_how() {
        use RedirectMethod::{Get, Same};

        for (status, method, how) in [
            (301, &b"GET"[..], Same),
            (301, b"POST", Get),
            (301, b"PUT", Same),
            (302, b"POST", Get),
            (302, b"HEAD", Same),
            (303, b"POST", Get),
            (303, b"PUT", Get),
            (303, b"HEAD", Same),
            (307, b"POST", Same),
            (308, b"PUT", Same),
        ] {
            let head = alloc::format!(
                "HTTP/1.1 {status} X\r\nLocation: ../c?d\r\nContent-Length: 0\r\n\r\n"
            );
            let c = answered(method, head.as_bytes());
            assert_eq!(
                redirected(&c, b"https://h/a/b", false),
                Some(Ok((b"https://h:443/c?d".to_vec(), how))),
                "{status} {}",
                method.escape_ascii()
            );
        }
        for status in [200, 300, 304, 305, 306, 404] {
            let head =
                alloc::format!("HTTP/1.1 {status} X\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n");
            assert_eq!(
                redirected(&answered(b"GET", head.as_bytes()), b"http://h/", false),
                None,
                "{status}"
            );
        }
    }

    #[test]
    fn a_redirect_that_cannot_be_followed_says_why() {
        let none = answered(b"GET", b"HTTP/1.1 302 X\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            redirected(&none, b"http://h/", false),
            Some(Err(RedirectError::NoLocation))
        );
        let two = answered(
            b"GET",
            b"HTTP/1.1 302 X\r\nLocation: /a\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(
            redirected(&two, b"http://h/", false),
            Some(Err(RedirectError::Locations))
        );
        let bad = answered(
            b"GET",
            b"HTTP/1.1 302 X\r\nLocation: http://u@h/\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(
            redirected(&bad, b"http://h/", false),
            Some(Err(RedirectError::Location(UriError::UserInfo)))
        );
        let down = answered(
            b"GET",
            b"HTTP/1.1 302 X\r\nLocation: http://h/x\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(
            redirected(&down, b"https://h/", false),
            Some(Err(RedirectError::Downgrade))
        );
        assert_eq!(
            redirected(&down, b"https://h/", true),
            Some(Ok((b"http://h:80/x".to_vec(), RedirectMethod::Same)))
        );
        // up is always allowed
        let up = answered(
            b"GET",
            b"HTTP/1.1 301 X\r\nLocation: https://h:8443/x\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(
            redirected(&up, b"http://h/", false),
            Some(Ok((b"https://h:8443/x".to_vec(), RedirectMethod::Same)))
        );
    }

    #[test]
    fn nothing_redirects_before_the_final_response() {
        let mut c = get(b"GET");
        let rx = c.rx(T0, b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        assert_eq!(rx.event, None);
        assert_eq!(redirected(&c, b"http://h/", false), None);
    }
}
