//! One h1 client connection's transaction: C's
//! `lws_generate_client_handshake()` and
//! `lws_client_interpret_server_handshake()`, sans-IO.
//!
//! [`Client::tx`] writes the request's head, composed as C composes it, in
//! C's order: the request line, `Pragma` and `Cache-Control` unless asked
//! not to, `Host`, `Origin`, then `connection: close`, or nothing for a
//! connection kept for another request, or the header lines asking for an
//! upgrade ([`Connection`]).
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
//! The final response to a request for an upgrade is not framed at all:
//! after its head, whatever its status, the connection is the upgraded
//! protocol's ([`Client::is_upgraded`]), which judges the response, as C's
//! `lws_client_ws_upgrade()` does for ws.

use crate::chunked::{self, Chunk, Dechunk};
use crate::fields::{content_length, transfer_encoding_is_chunked};
use crate::head::{self, Head, Progress, Refused, Side};
use crate::own::Own;
pub use crate::own::{MAX_OWN, RespondError};
use crate::table::{CapacityTooLarge, Full, HeaderTable};
use crate::token::Token;

/// How many interim responses a client takes before the final one: C's
/// `LWS_HTTP_INTERIM_RESPONSE_LIMIT`.
pub const INTERIM_LIMIT: u8 = 8;

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
    /// Writing the request.
    Asking,
    /// Waiting for the response's head; this many interims so far.
    Head(u8),
    /// Taking the response's body.
    Body(Body),
    /// The transaction is over.
    Done,
    /// The final response to a request for an upgrade has come: the
    /// connection is the upgraded protocol's.
    Upgraded,
    /// The connection failed.
    Failed(Failure),
}

/// What the request asked for: a transaction, or an upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Asked {
    Transaction,
    Upgrade,
}

/// One h1 client connection.
///
/// ```
/// use npro_h1::client::{Client, Connection, Event, Request, Scheme};
///
/// let mut c = Client::new([0u8; 1024], Request {
///     method: b"GET",
///     path: b"/x",
///     host: Some(b"example.com"),
///     origin: None,
///     scheme: Scheme::Http,
///     no_cache: false,
///     connection: Connection::Close,
/// })?;
/// let mut out = [0u8; 256];
/// let n = c.tx(&mut out);
/// assert_eq!(&out[..n], b"GET /x HTTP/1.1\r\nHost: example.com\r\nconnection: close\r\n\r\n");
///
/// let mut input = &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..];
/// let rx = c.rx(input)?;
/// assert_eq!((rx.event, c.status()), (Some(Event::Response), Some(200)));
/// input = &input[rx.consumed..];
/// assert_eq!(c.rx(input)?.event, Some(Event::Body(b"ok")));
/// assert_eq!(c.rx(b"")?.event, Some(Event::BodyEnd));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Client<S> {
    head: Head<S>,
    asked: Asked,
    phase: Phase,
    own: Own,
    status: Option<u16>,
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
}

impl core::fmt::Display for NewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Capacity(e) => write!(f, "{e}"),
            Self::Table(e) => write!(f, "{e}"),
            Self::Head(e) => write!(f, "{e}"),
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
    /// [`NewError`] if the storage is too large, or the request does not
    /// fit.
    pub fn new(storage: S, req: Request<'_>) -> Result<Self, NewError> {
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
                Connection::Close | Connection::KeepAlive => Asked::Transaction,
                Connection::Upgrade(_) => Asked::Upgrade,
            },
            phase: Phase::Asking,
            own: request_head(&req).map_err(NewError::Head)?,
            status: None,
        })
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

    /// Whether the connection has something to write.
    #[must_use]
    pub const fn wants_write(&self) -> bool {
        self.own.pending()
    }

    /// Why the connection failed, if it did: then it asks to be released.
    #[must_use]
    pub const fn failed(&self) -> Option<Failure> {
        match self.phase {
            Phase::Failed(f) => Some(f),
            Phase::Asking | Phase::Head(_) | Phase::Body(_) | Phase::Done | Phase::Upgraded => None,
        }
    }

    /// Whether the transaction is over.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Done)
    }

    /// Whether the final response to a request for an upgrade has come:
    /// from the byte after its head, the connection is the upgraded
    /// protocol's, and this takes nothing more.
    #[must_use]
    pub const fn is_upgraded(&self) -> bool {
        matches!(self.phase, Phase::Upgraded)
    }

    /// Writes the request's head, or what is left of it, into `out`,
    /// returning how much.
    pub fn tx(&mut self, out: &mut [u8]) -> usize {
        let n = self.own.drain(out);
        if self.phase == Phase::Asking && !self.own.pending() {
            self.phase = Phase::Head(0);
        }
        n
    }

    const fn fail<'a>(&mut self, f: Failure) -> Result<Rx<'a>, Failure> {
        self.phase = Phase::Failed(f);
        Err(f)
    }

    /// Takes bytes from the server: see [`Event`].
    ///
    /// # Errors
    ///
    /// The [`Failure`], once the response fails the connection, and on
    /// every call after.
    pub fn rx<'a>(&mut self, input: &'a [u8]) -> Result<Rx<'a>, Failure> {
        let held = Ok(Rx {
            consumed: 0,
            event: None,
        });
        match self.phase {
            Phase::Failed(f) => Err(f),
            Phase::Asking | Phase::Done | Phase::Upgraded => held,
            Phase::Head(interims) => self.rx_head(interims, input),
            Phase::Body(b) => self.rx_body(b, input),
        }
    }

    fn rx_head<'a>(&mut self, interims: u8, input: &'a [u8]) -> Result<Rx<'a>, Failure> {
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
            // nothing for the app: back to the request, for the final one
            self.head.rewind();
            self.phase = Phase::Head(n);
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
    /// close, or a failure if the body was framed otherwise.
    ///
    /// # Errors
    ///
    /// [`Failure::Closed`] if a body or head was still to come.
    pub const fn rx_closed<'a>(&mut self) -> Result<Option<Event<'a>>, Failure> {
        match self.phase {
            Phase::Failed(f) => Err(f),
            Phase::Done | Phase::Upgraded => Ok(None),
            Phase::Body(Body::ToClose | Body::EndDue) => {
                self.phase = Phase::Done;
                Ok(Some(Event::BodyEnd))
            }
            Phase::Body(Body::Over) => {
                self.phase = Phase::Done;
                Ok(None)
            }
            Phase::Asking | Phase::Head(_) | Phase::Body(Body::Length(_) | Body::Chunked(_)) => {
                self.phase = Phase::Failed(Failure::Closed);
                Err(Failure::Closed)
            }
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
    use super::*;

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
            },
        )
        .unwrap();
        let mut out = [0u8; 512];
        let _ = c.tx(&mut out);
        c
    }

    #[test]
    fn interims_are_dropped_up_to_eight() {
        let mut c = get(b"GET");
        let mut input = &b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early\r\nLink: x\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
        loop {
            let rx = c.rx(input).unwrap();
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
            match many.rx(rest) {
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
            },
        )
        .unwrap();
        let mut out = [0u8; 512];
        let n = c.tx(&mut out);
        assert_eq!(
            &out[..n],
            b"GET /x HTTP/1.1\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n"
        );
        // an interim is still dropped; the 101 is final, its frames are not
        // a body, and nor would a 200's be
        let input = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 101 Go\r\n\r\n\x81\x00";
        let first = c.rx(input).unwrap();
        assert_eq!(first.event, None);
        let rx = c.rx(&input[first.consumed..]).unwrap();
        assert_eq!(rx.event, Some(Event::Response));
        assert_eq!(&input[first.consumed + rx.consumed..], b"\x81\x00");
        assert!(c.is_upgraded());
        assert_eq!(c.status(), Some(101));
        assert_eq!(c.rx(b"\x81\x00").unwrap().consumed, 0);
    }

    #[test]
    fn a_body_to_the_close() {
        let mut c = get(b"GET");
        let head = b"HTTP/1.0 200 OK\r\n\r\n";
        assert_eq!(c.rx(head).unwrap().event, Some(Event::Response));
        assert_eq!(c.rx(b"abc").unwrap().event, Some(Event::Body(b"abc")));
        assert_eq!(c.rx_closed(), Ok(Some(Event::BodyEnd)));
        assert!(c.is_done());
    }

    #[test]
    fn a_close_before_the_body_ended_fails() {
        let mut c = get(b"GET");
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(c.rx(head).unwrap().event, Some(Event::Response));
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
            let rx = c.rx(input).unwrap();
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

    #[test]
    fn a_status_is_cs_atoi() {
        assert_eq!(atoi(b"200 OK"), 200);
        assert_eq!(atoi(b"\t 404"), 404);
        assert_eq!(atoi(b"-1x"), -1);
        assert_eq!(atoi(b"OK"), 0);
    }
}
