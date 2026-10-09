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
//! Time is an input: the calls that can start a timer take `now`,
//! [`Client::next_deadline`] says when the connection next needs telling the
//! time, and [`Client::deadline_passed`] tells it.  From when its request
//! begins to go, the server has C's 15s ([`RESPONSE_TIMEOUT`]) to answer,
//! and as long again after each interim response, or the connection fails.
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
use crate::table::{CapacityTooLarge, Full, HeaderTable};
use crate::token::Token;
pub use npro_core::close::Close;

/// How many interim responses a client takes before the final one: C's
/// `LWS_HTTP_INTERIM_RESPONSE_LIMIT`.
pub const INTERIM_LIMIT: u8 = 8;

/// How long the server has to answer, from when the request begins to go
/// and again after each interim response: C's
/// `PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE`, the context's
/// `timeout_secs`.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

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
    /// The request is yet to go.
    Asking,
    /// The request is going, and the response is due by `until`.
    Sending { until: Instant },
    /// Waiting for the response's head, due by `until`; this many
    /// interims so far.
    Head { interims: u8, until: Instant },
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
/// use npro_h1::client::{Client, Connection, Event, Request, Scheme};
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
/// })?;
/// let mut out = [0u8; 256];
/// let n = c.tx(now, &mut out);
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
                Connection::Close => Asked::Close,
                Connection::KeepAlive => Asked::KeepAlive,
                Connection::Upgrade(_) => Asked::Upgrade,
            },
            phase: Phase::Asking,
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
            Phase::Sending { until } | Phase::Head { until, .. } => Some(until),
            Phase::Asking | Phase::Body(_) | Phase::Done | Phase::Upgraded | Phase::Failed(_) => {
                None
            }
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

    /// What the connection asks of whatever carries it, once it is done
    /// with: [`Close::Abort`] once it failed, as C closes a client whose
    /// connection failed with nothing more to say; [`Close::Release`] once a
    /// transaction that said `connection: close` is over, a client staging
    /// no shutdown in C.  A connection kept alive, or upgraded, asks
    /// nothing: it is the next request's, or the upgraded protocol's.
    #[must_use]
    pub const fn close(&self) -> Option<Close> {
        match (self.phase, self.asked) {
            (Phase::Failed(_), _) => Some(Close::Abort),
            (Phase::Done, Asked::Close) => Some(Close::Release),
            (Phase::Done, Asked::KeepAlive | Asked::Upgrade)
            | (
                Phase::Asking
                | Phase::Sending { .. }
                | Phase::Head { .. }
                | Phase::Body(_)
                | Phase::Upgraded,
                _,
            ) => None,
        }
    }

    /// Why the connection failed, if it did: then it asks to be aborted.
    #[must_use]
    pub const fn failed(&self) -> Option<Failure> {
        match self.phase {
            Phase::Failed(f) => Some(f),
            Phase::Asking
            | Phase::Sending { .. }
            | Phase::Head { .. }
            | Phase::Body(_)
            | Phase::Done
            | Phase::Upgraded => None,
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

    /// Writes the request's head, or what is left of it, into `out`, at
    /// `now`, returning how much.  The server's answer is due from when the
    /// head begins to go, as C sends it whole, in one push, and starts
    /// waiting then.
    pub fn tx(&mut self, now: Instant, out: &mut [u8]) -> usize {
        let n = self.own.drain(out);
        let until = match self.phase {
            Phase::Asking if n > 0 => now.saturating_add(self.timeout),
            Phase::Sending { until } => until,
            Phase::Asking
            | Phase::Head { .. }
            | Phase::Body(_)
            | Phase::Done
            | Phase::Upgraded
            | Phase::Failed(_) => return n,
        };
        self.phase = if self.own.pending() {
            Phase::Sending { until }
        } else {
            Phase::Head { interims: 0, until }
        };
        n
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
            Phase::Asking | Phase::Sending { .. } | Phase::Done | Phase::Upgraded => held,
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
            Phase::Asking
            | Phase::Sending { .. }
            | Phase::Head { .. }
            | Phase::Body(Body::Length(_) | Body::Chunked(_)) => {
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
            },
        )
        .unwrap();
        let mut out = [0u8; 512];
        let _ = c.tx(T0, &mut out);
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
            },
        )
        .unwrap();
        let mut out = [0u8; 512];
        let n = c.tx(T0, &mut out);
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
            },
        )
        .unwrap()
    }

    #[test]
    fn the_answer_is_due_from_when_the_request_begins_to_go() {
        let mut c = unsent();
        assert_eq!(c.next_deadline(), None);
        let mut out = [0u8; 512];
        assert_eq!(c.tx(at(1), &mut out[..4]), 4);
        assert_eq!(c.next_deadline(), Some(at(16)));
        assert!(c.tx(at(3), &mut out) > 0);
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
        extern crate alloc;
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
        assert_eq!(c.close(), Some(Close::Release));

        let mut failed = get(b"GET");
        let _ = failed.rx(T0, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n");
        assert_eq!(failed.close(), Some(Close::Abort));
    }
}
