//! One h1 server connection's transactions: C's `lws_handshake_server()`,
//! `lws_http_request_body_framing()` and `lws_http_transaction_completed()`,
//! sans-IO.
//!
//! Bytes from the peer go in through [`Server::rx`], which takes at most one
//! thing from them each call and says how much it took: a request's head
//! ([`Event::Request`]), a piece of its body ([`Event::Body`], borrowed from
//! the input, not copied) or the body's end ([`Event::BodyEnd`]).  Bytes it
//! did not take are held: the caller hands them in again.  So the body that
//! came with a head is never lost to an answer composed from it, and a
//! pipelined request waits until the one before it is done.
//!
//! The application answers with [`Server::respond`], and its payload is
//! pulled from it by [`Server::tx`], which writes what the connection owes
//! the peer first: C's status line and headers, or a status page.  It says
//! it is done with the transaction with [`Server::complete`].
//!
//! What C checks between a head and the application is checked here, in
//! C's order: Content-Length with Transfer-Encoding, a second Host, an
//! Expect other than `100-continue`, a Transfer-Encoding other than a lone
//! `chunked`, a second or malformed Content-Length, one past the body limit.
//! A refused request is answered with C's status page and the connection
//! shut down, as a head the parser refused is.

use crate::chunked::{Chunk, Dechunk};
use crate::fields::{content_length, transfer_encoding_is_chunked};
use crate::head::{self, Answer, Head, Progress, Refused, Side, Version};
use crate::table::{CapacityTooLarge, HeaderTable};
use crate::token::Token;

/// The most a request body may be unless configured: C's default
/// `max_http_body_size`.
pub const DEFAULT_MAX_BODY: u64 = 100 * 1024 * 1024;

/// The most bytes a response head the connection writes may have, its
/// status line and headers, or a status page with them.
pub const MAX_OWN: usize = 512;

/// How a server takes its requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    head: head::Config,
    max_body: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self::new(head::Config::new())
    }
}

impl Config {
    /// Heads parsed with `head`, bodies at most [`DEFAULT_MAX_BODY`].
    #[must_use]
    pub const fn new(head: head::Config) -> Self {
        Self {
            head,
            max_body: DEFAULT_MAX_BODY,
        }
    }

    /// Bodies longer than `max` are refused 413: C's vhost
    /// `max_http_body_size`.
    #[must_use]
    pub const fn with_max_body(mut self, max: u64) -> Self {
        self.max_body = max;
        self
    }
}

/// What the peer's bytes were.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// A request's head: [`Server::request`] has it.  C's
    /// `LWS_CALLBACK_HTTP`.
    Request,
    /// The next piece of its body: C's `LWS_CALLBACK_HTTP_BODY`.
    Body(&'a [u8]),
    /// Its body is over: C's `LWS_CALLBACK_HTTP_BODY_COMPLETION`.  Only
    /// for a request with a body or a method that has one, and not after
    /// the application completed the transaction.
    BodyEnd,
}

/// What [`Server::rx`] took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rx<'a> {
    /// How many bytes it took.  The rest are the caller's to hand in again.
    pub consumed: usize,
    /// What they were, if they came to something.
    pub event: Option<Event<'a>>,
}

/// What [`Server::tx`] wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tx {
    /// How many bytes of the buffer it used.
    pub written: usize,
    /// Whether it has more to write now.
    pub more: bool,
}

/// What the connection asks of whatever carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
    /// Stop sending, once what was written has gone, and wait for the
    /// peer to close: C's `LWS_IOCLOSE_SHUTDOWN`.
    Shutdown,
}

/// Where the application's payload comes from: [`Server::tx`] pulls it
/// into the buffer it is writing, after anything the connection writes
/// itself.
pub trait TxSource {
    /// Fills the start of `buf` with the next of the payload, returning how
    /// much: 0 if there is none yet.
    fn fill(&mut self, buf: &mut [u8]) -> usize;
}

/// The application's answer to a request: C's
/// `lws_add_http_common_headers()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response<'a> {
    /// The status code.
    pub status: u16,
    /// The `content-type`, if any.
    pub content_type: Option<&'a [u8]>,
    /// The payload's length.  Without one the connection closes after it,
    /// and says so.
    pub content_length: Option<u64>,
}

/// Why an answer cannot be given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RespondError {
    /// There is no request to answer, or it is answered already.
    NotNow,
    /// The head does not fit in [`MAX_OWN`].
    TooLong,
}

impl core::fmt::Display for RespondError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotNow => "no request to answer",
            Self::TooLong => "the response head is too long",
        })
    }
}

impl core::error::Error for RespondError {}

/// Bytes the connection writes itself, and how many of them have gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Own {
    buf: [u8; MAX_OWN],
    len: usize,
    sent: usize,
}

impl Own {
    const fn new() -> Self {
        Self {
            buf: [0; MAX_OWN],
            len: 0,
            sent: 0,
        }
    }

    fn push(&mut self, b: &[u8]) -> Result<(), RespondError> {
        let end = self.len.checked_add(b.len()).ok_or(RespondError::TooLong)?;
        let dst = self
            .buf
            .get_mut(self.len..end)
            .ok_or(RespondError::TooLong)?;
        dst.copy_from_slice(b);
        self.len = end;
        Ok(())
    }

    fn push_u64(&mut self, v: u64) -> Result<(), RespondError> {
        let mut d = [0u8; 20];
        let mut n = d.len();
        let mut v = v;
        loop {
            n = n.saturating_sub(1);
            if let Some(slot) = d.get_mut(n) {
                // v % 10 < 10
                *slot = b'0'.saturating_add(u8::try_from(v % 10).unwrap_or(0));
            }
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.push(d.get(n..).unwrap_or_default())
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

/// How the request's body is framed, and how far it has come.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Body {
    /// This much of a Content-Length body is still to come.
    Length(u64),
    /// A chunked body.
    Chunked(Dechunk),
    /// It is over, and its end is yet to be told.
    EndDue,
    /// It is over.
    Over,
}

/// The answer, and how far it has gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reply {
    /// None yet.
    Awaited,
    /// This much payload is still owed, or no length was given.
    Payload(Option<u64>),
}

/// The transaction in hand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Txn {
    body: Body,
    reply: Reply,
    /// The application said it is done.
    completed: bool,
    head_request: bool,
    keep_alive: bool,
}

/// Where the connection is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Taking a request's head.
    Head,
    /// A request is in hand.
    Request(Txn),
    /// Writing a refusal, then shutting down.
    Refusing,
    /// The connection is done with.
    Closed(Close),
}

/// One h1 server connection.
///
/// ```
/// use npro_h1::server::{Config, Event, Response, Server, TxSource};
///
/// struct Text(&'static [u8]);
/// impl TxSource for Text {
///     fn fill(&mut self, buf: &mut [u8]) -> usize {
///         let n = self.0.len().min(buf.len());
///         buf[..n].copy_from_slice(&self.0[..n]);
///         self.0 = &self.0[n..];
///         n
///     }
/// }
///
/// let mut s = Server::new([0u8; 1024], Config::default())?;
/// let rx = s.rx(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
/// assert_eq!(rx.event, Some(Event::Request));
/// s.respond(Response {
///     status: 200,
///     content_type: Some(b"text/plain"),
///     content_length: Some(2),
/// })?;
/// let mut out = [0u8; 256];
/// let tx = s.tx(&mut out, &mut Text(b"ok"));
/// s.complete();
/// assert_eq!(
///     &out[..tx.written],
///     b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nok"
/// );
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Server<S> {
    head: Head<S>,
    config: Config,
    phase: Phase,
    own: Own,
    /// The version the last request asked in, which C answers a refused
    /// request target in: `wsi->stream.request_version`.
    version: Version,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Server<S> {
    /// A connection whose request heads are kept in `storage`.
    ///
    /// # Errors
    ///
    /// [`CapacityTooLarge`] if `storage` is longer than a table may be.
    pub fn new(storage: S, config: Config) -> Result<Self, CapacityTooLarge> {
        Ok(Self {
            head: Head::new(storage, Side::Server, config.head)?,
            config,
            phase: Phase::Head,
            own: Own::new(),
            version: Version::Http10,
        })
    }

    /// The request in hand's headers.
    #[must_use]
    pub const fn request(&self) -> &HeaderTable<S> {
        self.head.table()
    }

    /// Whether the connection has something to write.
    #[must_use]
    pub const fn wants_write(&self) -> bool {
        self.own.pending()
    }

    /// What the connection asks of its carrier, once it is done with.
    #[must_use]
    pub const fn close(&self) -> Option<Close> {
        match self.phase {
            Phase::Closed(c) => Some(c),
            Phase::Head | Phase::Request(_) | Phase::Refusing => None,
        }
    }

    /// Takes bytes from the peer: see [`Event`].
    pub fn rx<'a>(&mut self, input: &'a [u8]) -> Rx<'a> {
        let held = Rx {
            consumed: 0,
            event: None,
        };
        match self.phase {
            Phase::Head => self.rx_head(input),
            Phase::Request(t) => self.rx_body(t, input),
            Phase::Refusing | Phase::Closed(_) => held,
        }
    }

    fn rx_head<'a>(&mut self, input: &'a [u8]) -> Rx<'a> {
        match self.head.rx(input) {
            Ok(Progress::More) => Rx {
                consumed: input.len(),
                event: None,
            },
            Ok(Progress::Complete { consumed }) => Rx {
                consumed,
                event: self.request_complete(),
            },
            // the server has no fallback role: a head that would go to
            // one is no request it can answer
            Ok(Progress::Fallback) => {
                self.phase = Phase::Closed(Close::Shutdown);
                Rx {
                    consumed: 0,
                    event: None,
                }
            }
            Err(r) => {
                self.refused_head(r);
                Rx {
                    consumed: 0,
                    event: None,
                }
            }
        }
    }

    /// The parser refused the head: C answers it, if it says to, in the
    /// version it can, and shuts down.
    fn refused_head(&mut self, r: Refused) {
        let Some(a) = r.answer() else {
            self.phase = Phase::Closed(Close::Shutdown);
            return;
        };
        let (code, text): (u16, &[u8]) = match a {
            Answer::UriTooLong => (414, b"Oversized request URI"),
            Answer::HeaderFieldsTooLarge => (431, b"Oversized headers"),
            Answer::BadRequest
            | Answer::Forbidden
            | Answer::NotImplemented
            | Answer::VersionNotSupported => (a.code(), b""),
        };
        let version = match r.cause() {
            // there is no version of the request's to answer in
            head::Cause::NoRequestLine
            | head::Cause::Http09
            | head::Cause::TooManyEmptyLines
            | head::Cause::BadVersion
            | head::Cause::VersionNotSupported
            | head::Cause::MethodNotImplemented => Version::Http11,
            head::Cause::UriTooLong | head::Cause::HeadTooLarge => {
                if self.head.table().is_present(Token::Http) {
                    self.head.request_version()
                } else {
                    Version::Http11
                }
            }
            // C answers in the last request's version, HTTP/1.0 on a
            // fresh connection
            head::Cause::Uri(_)
            | head::Cause::Nul
            | head::Cause::BareLf
            | head::Cause::BareCr
            | head::Cause::NameByte(_)
            | head::Cause::DuplicateMethod
            | head::Cause::NotAFieldName(_) => self.version,
        };
        self.refuse(version, code, text);
    }

    /// Queues C's status page, then the shutdown.
    fn refuse(&mut self, version: Version, code: u16, text: &[u8]) {
        self.own = Own::new();
        if status_page(&mut self.own, version, code, text).is_err() {
            self.own = Own::new();
        }
        self.phase = Phase::Refusing;
    }

    /// The head is whole: C's checks, in C's order, then the request.
    fn request_complete(&mut self) -> Option<Event<'static>> {
        let version = self.head.request_version();
        self.version = version;
        let t = self.head.table();
        let keep_alive = keep_alive(t, version);
        let present = |tok| t.is_present(tok);
        // both framings, or two Hosts to route by
        let refusal = if (present(Token::ContentLength) && present(Token::TransferEncoding))
            || t.fragments(Token::Host).nth(1).is_some()
        {
            Some(400)
        } else if present(Token::Expect) && !expect_is_continue(t) {
            Some(417)
        } else if present(Token::TransferEncoding) && !transfer_encoding_is_chunked(t) {
            Some(501)
        } else {
            None
        };
        if let Some(code) = refusal {
            self.refuse(version, code, b"");
            return None;
        }
        let body = if present(Token::TransferEncoding) {
            Body::Chunked(Dechunk::new())
        } else if present(Token::ContentLength) {
            let mut f = t.fragments(Token::ContentLength);
            let len = match (f.next(), f.next()) {
                (Some(v), None) if v.len() < 32 => content_length(v).ok(),
                _ => None,
            };
            match len {
                None => {
                    self.refuse(version, 400, b"");
                    return None;
                }
                Some(n) if n > self.config.max_body => {
                    self.refuse(version, 413, b"");
                    return None;
                }
                Some(0) => Body::EndDue,
                Some(n) => Body::Length(n),
            }
        } else if [Token::PostUri, Token::PutUri, Token::PatchUri]
            .iter()
            .any(|m| present(*m))
        {
            // no body, RFC 9112 6.3, but its method has one: told so
            Body::EndDue
        } else {
            Body::Over
        };
        self.phase = Phase::Request(Txn {
            body,
            reply: Reply::Awaited,
            completed: false,
            head_request: present(Token::HeadUri),
            keep_alive,
        });
        Some(Event::Request)
    }

    fn rx_body<'a>(&mut self, mut t: Txn, input: &'a [u8]) -> Rx<'a> {
        let (consumed, event) = match t.body {
            Body::Over => (0, None),
            Body::EndDue => {
                t.body = Body::Over;
                (0, (!t.completed).then_some(Event::BodyEnd))
            }
            Body::Length(left) => {
                let n = usize::try_from(left).unwrap_or(usize::MAX).min(input.len());
                let rest = left.saturating_sub(u64::try_from(n).unwrap_or(left));
                t.body = if rest == 0 {
                    Body::EndDue
                } else {
                    Body::Length(rest)
                };
                let piece = input.get(..n).unwrap_or_default();
                (n, (n > 0 && !t.completed).then_some(Event::Body(piece)))
            }
            Body::Chunked(mut d) => {
                let Ok(s) = d.step(input) else {
                    // the connection is out of step with its peer
                    self.phase = Phase::Closed(Close::Shutdown);
                    return Rx {
                        consumed: 0,
                        event: None,
                    };
                };
                t.body = match s.chunk {
                    Chunk::End => Body::EndDue,
                    Chunk::Data(_) | Chunk::More => Body::Chunked(d),
                };
                let event = match s.chunk {
                    Chunk::Data(b) if !t.completed => Some(Event::Body(b)),
                    Chunk::Data(_) | Chunk::More | Chunk::End => None,
                };
                (s.consumed, event)
            }
        };
        self.phase = Phase::Request(t);
        self.settle();
        Rx { consumed, event }
    }

    /// Answers the request in hand.
    ///
    /// # Errors
    ///
    /// [`RespondError`] if there is none unanswered, or the head is too
    /// long.
    pub fn respond(&mut self, r: Response<'_>) -> Result<(), RespondError> {
        let Phase::Request(mut t) = self.phase else {
            return Err(RespondError::NotNow);
        };
        if t.reply != Reply::Awaited {
            return Err(RespondError::NotNow);
        }
        let mut own = Own::new();
        status_line(&mut own, self.version, r.status)?;
        if let Some(ct) = r.content_type {
            own.push(b"content-type: ")?;
            own.push(ct)?;
            own.push(b"\r\n")?;
        }
        if let Some(n) = r.content_length {
            own.push(b"content-length: ")?;
            own.push_u64(n)?;
            own.push(b"\r\n")?;
        } else {
            // there is no length: the connection's close ends it
            own.push(b"connection: close\r\n")?;
            t.keep_alive = false;
        }
        own.push(b"\r\n")?;
        self.own = own;
        // a HEAD's answer has no payload, whatever its length says
        t.reply = Reply::Payload(if t.head_request {
            Some(0)
        } else {
            r.content_length
        });
        self.phase = Phase::Request(t);
        Ok(())
    }

    /// The application is done with the transaction: C's
    /// `lws_http_transaction_completed()`.  The rest of the request's body
    /// is taken without it, and once the answer has gone, the connection
    /// takes the next request, or, if the answer was short of its length,
    /// or the request did not keep the connection, shuts down.
    pub fn complete(&mut self) {
        if let Phase::Request(mut t) = self.phase {
            t.completed = true;
            self.phase = Phase::Request(t);
            self.settle();
        }
    }

    /// Writes what is owed the peer into `out`: the connection's own bytes,
    /// then the payload, pulled from `src`.
    pub fn tx(&mut self, out: &mut [u8], src: &mut dyn TxSource) -> Tx {
        let mut written = self.own.drain(out);
        if let Phase::Request(mut t) = self.phase {
            if !self.own.pending() {
                if let Reply::Payload(owed) = t.reply {
                    let room = out.get_mut(written..).unwrap_or_default();
                    let cap = owed.map_or(room.len(), |o| {
                        usize::try_from(o).unwrap_or(usize::MAX).min(room.len())
                    });
                    let n = src.fill(room.get_mut(..cap).unwrap_or_default()).min(cap);
                    written = written.saturating_add(n);
                    let n64 = u64::try_from(n).unwrap_or(u64::MAX);
                    t.reply = Reply::Payload(owed.map(|o| o.saturating_sub(n64)));
                    self.phase = Phase::Request(t);
                }
            }
            self.settle();
        }
        if self.phase == Phase::Refusing && !self.own.pending() {
            self.phase = Phase::Closed(Close::Shutdown);
        }
        Tx {
            written,
            more: self.own.pending(),
        }
    }

    /// Ends the transaction if it is over: the application completed it,
    /// its answer has gone, and its body has been taken.
    fn settle(&mut self) {
        let Phase::Request(t) = self.phase else {
            return;
        };
        if !t.completed || self.own.pending() {
            return;
        }
        let Reply::Payload(owed) = t.reply else {
            // completed with no answer: C closes
            self.phase = Phase::Closed(Close::Shutdown);
            return;
        };
        // with no length, the close ends it; short of its length, the peer
        // would take what comes next as the rest of it
        if owed.is_none_or(|o| o > 0) || !t.keep_alive {
            self.phase = Phase::Closed(Close::Shutdown);
            return;
        }
        match t.body {
            Body::Over | Body::EndDue => {
                self.head.reset();
                self.phase = Phase::Head;
            }
            Body::Length(_) | Body::Chunked(_) => {}
        }
    }
}

/// Whether the request keeps its connection: HTTP/1.1 does unless it says
/// `close`, HTTP/1.0 does not unless it says `keep-alive`.  C's
/// `lws_h1_request_framing()`.
fn keep_alive<S: AsRef<[u8]> + AsMut<[u8]>>(t: &HeaderTable<S>, v: Version) -> bool {
    let mut c = [0u8; 19];
    let said = t
        .copy(Token::Connection, &mut c)
        .ok()
        .and_then(|n| c.get(..n));
    match said {
        Some(s) if s.eq_ignore_ascii_case(b"keep-alive") => true,
        Some(s) if s.eq_ignore_ascii_case(b"close") => false,
        Some(_) | None => v == Version::Http11,
    }
}

/// Whether a request's Expect is exactly one `100-continue`: C's
/// `lws_http_expect_is_continue()`.
fn expect_is_continue<S: AsRef<[u8]> + AsMut<[u8]>>(t: &HeaderTable<S>) -> bool {
    let mut f = t.fragments(Token::Expect);
    let (Some(v), None) = (f.next(), f.next()) else {
        return false;
    };
    if v.len() > 30 {
        return false;
    }
    let blank = |c: &u8| *c == b' ' || *c == b'\t';
    let start = v.iter().position(|c| !blank(c)).unwrap_or(v.len());
    let end = v
        .iter()
        .rposition(|c| !blank(c))
        .map_or(0, |n| n.saturating_add(1));
    v.get(start..end)
        .is_some_and(|v| v.eq_ignore_ascii_case(b"100-continue"))
}

/// C's reason phrases.
fn reason(code: u16) -> &'static [u8] {
    const E400: [&[u8]; 18] = [
        b"Bad Request",
        b"Unauthorized",
        b"Payment Required",
        b"Forbidden",
        b"Not Found",
        b"Method Not Allowed",
        b"Not Acceptable",
        b"Proxy Auth Required",
        b"Request Timeout",
        b"Conflict",
        b"Gone",
        b"Length Required",
        b"Precondition Failed",
        b"Request Entity Too Large",
        b"Request URI too Long",
        b"Unsupported Media Type",
        b"Requested Range Not Satisfiable",
        b"Expectation Failed",
    ];
    const E500: [&[u8]; 6] = [
        b"Internal Server Error",
        b"Not Implemented",
        b"Bad Gateway",
        b"Service Unavailable",
        b"Gateway Timeout",
        b"HTTP Version Not Supported",
    ];
    match code {
        100 => b"Continue",
        200 => b"OK",
        304 => b"Not Modified",
        300..=399 => b"Redirect",
        400..=417 => E400
            .get(usize::from(code.saturating_sub(400)))
            .copied()
            .unwrap_or_default(),
        426 => b"Upgrade Required",
        431 => b"Request Header Fields Too Large",
        500..=505 => E500
            .get(usize::from(code.saturating_sub(500)))
            .copied()
            .unwrap_or_default(),
        _ => b"",
    }
}

fn status_line(own: &mut Own, v: Version, code: u16) -> Result<(), RespondError> {
    own.push(match v {
        Version::Http10 => b"HTTP/1.0 ",
        Version::Http11 => b"HTTP/1.1 ",
    })?;
    own.push_u64(u64::from(code))?;
    own.push(b" ")?;
    own.push(reason(code))?;
    own.push(b"\r\n")
}

/// C's status page: `_lws_return_http_status()` and
/// `lws_http_status_page_body()`.
fn status_page(own: &mut Own, v: Version, code: u16, text: &[u8]) -> Result<(), RespondError> {
    const PRE: &[u8] = b"<html><head><meta charset=utf-8 http-equiv=\"Content-Language\" \
content=\"en\"/><link rel=\"stylesheet\" type=\"text/css\" href=\"/error.css\"/>\
</head><body><h1>";
    const POST: &[u8] = b"</body></html>";
    let mut code_text = Own::new();
    code_text.push_u64(u64::from(code))?;
    let code_text = code_text.buf.get(..code_text.len).unwrap_or_default();
    let body_len = [PRE.len(), code_text.len(), 5, text.len(), POST.len()]
        .iter()
        .try_fold(0usize, |a, n| a.checked_add(*n))
        .ok_or(RespondError::TooLong)?;
    status_line(own, v, code)?;
    own.push(b"content-type: text/html\r\ncontent-length: ")?;
    own.push_u64(u64::try_from(body_len).map_err(|_| RespondError::TooLong)?)?;
    own.push(b"\r\n\r\n")?;
    own.push(PRE)?;
    own.push(code_text)?;
    own.push(b"</h1>")?;
    own.push(text)?;
    own.push(POST)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;

    struct Nothing;
    impl TxSource for Nothing {
        fn fill(&mut self, _: &mut [u8]) -> usize {
            0
        }
    }

    fn server() -> Server<[u8; 1024]> {
        Server::new([0u8; 1024], Config::default().with_max_body(100)).unwrap()
    }

    /// What the server writes for `head` before it shuts down.
    fn refused(head: &[u8]) -> Vec<u8> {
        let mut s = server();
        let rx = s.rx(head);
        assert_eq!(rx.event, None, "{}", head.escape_ascii());
        let mut out = [0u8; 1024];
        let tx = s.tx(&mut out, &mut Nothing);
        assert_eq!(s.close(), Some(Close::Shutdown));
        out[..tx.written].to_vec()
    }

    #[test]
    fn framing_refusals_in_cs_order() {
        for (head, line) in [
            (
                &b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
                &b"HTTP/1.1 400 Bad Request\r\n"[..],
            ),
            (
                b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
                b"HTTP/1.1 400 Bad Request\r\n",
            ),
            (
                b"GET / HTTP/1.0\r\nExpect: x\r\n\r\n",
                b"HTTP/1.0 417 Expectation Failed\r\n",
            ),
            (
                b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
                b"HTTP/1.1 501 Not Implemented\r\n",
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
                b"HTTP/1.1 400 Bad Request\r\n",
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
                b"HTTP/1.1 400 Bad Request\r\n",
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 101\r\n\r\n",
                b"HTTP/1.1 413 Request Entity Too Large\r\n",
            ),
            // a bad target before any request answers in HTTP/1.0, as C
            (b"GET /%zz HTTP/1.1\r\n\r\n", b"HTTP/1.0 403 Forbidden\r\n"),
        ] {
            let out = refused(head);
            assert!(out.starts_with(line), "{}", out.escape_ascii());
            assert!(out.ends_with(b"</body></html>"));
        }
    }

    #[test]
    fn a_chunked_body_comes_in_pieces_then_its_end() {
        let mut s = server();
        let mut input =
            &b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"[..];
        let mut seen = Vec::new();
        loop {
            let rx = s.rx(input);
            input = &input[rx.consumed..];
            match rx.event {
                Some(Event::Body(b)) => seen.extend_from_slice(b),
                Some(Event::BodyEnd) => break,
                Some(Event::Request) | None => {}
            }
            assert!(rx.consumed > 0 || rx.event.is_some());
        }
        assert_eq!(seen, b"abc");
        assert_eq!(input, b"");
    }

    #[test]
    fn a_body_after_completion_is_taken_without_the_app() {
        let mut s = server();
        let req = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET /n HTTP/1.1\r\n\r\n";
        let rx = s.rx(req);
        assert_eq!(rx.event, Some(Event::Request));
        let rest = &req[rx.consumed..];
        s.respond(Response {
            status: 200,
            content_type: None,
            content_length: Some(0),
        })
        .unwrap();
        let mut out = [0u8; 256];
        let _ = s.tx(&mut out, &mut Nothing);
        s.complete();
        let discarded = s.rx(rest);
        assert_eq!((discarded.consumed, discarded.event), (3, None));
        let next = s.rx(&rest[3..]);
        assert_eq!(next.event, Some(Event::Request));
        assert_eq!(s.request().first(Token::GetUri), Some(&b"/n"[..]));
    }

    #[test]
    fn http_1_0_closes_unless_it_keeps_alive() {
        for (head, keeps) in [
            (&b"GET / HTTP/1.0\r\n\r\n"[..], false),
            (b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", true),
            (b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n", false),
        ] {
            let mut s = server();
            assert_eq!(s.rx(head).event, Some(Event::Request));
            s.respond(Response {
                status: 200,
                content_type: None,
                content_length: Some(0),
            })
            .unwrap();
            let mut out = [0u8; 256];
            let _ = s.tx(&mut out, &mut Nothing);
            s.complete();
            assert_eq!(s.close().is_none(), keeps, "{}", head.escape_ascii());
        }
    }

    #[test]
    fn an_answer_without_a_length_closes() {
        let mut s = server();
        assert_eq!(s.rx(b"GET / HTTP/1.1\r\n\r\n").event, Some(Event::Request));
        s.respond(Response {
            status: 200,
            content_type: None,
            content_length: None,
        })
        .unwrap();
        let mut out = [0u8; 256];
        let tx = s.tx(&mut out, &mut Nothing);
        assert_eq!(
            &out[..tx.written],
            b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n"
        );
        s.complete();
        assert_eq!(s.close(), Some(Close::Shutdown));
        assert_eq!(
            s.respond(Response {
                status: 200,
                content_type: None,
                content_length: None
            }),
            Err(RespondError::NotNow)
        );
    }
}
