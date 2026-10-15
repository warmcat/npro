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
//! Time is an input: the calls that can start a timer take `now`,
//! [`Server::next_deadline`] says when the connection next needs telling
//! the time, and [`Server::deadline_passed`] tells it.  The timers are C's,
//! [`Timeouts`] says how long each is, and nothing reads a clock.
//!
//! What C checks between a head and the application is checked here, in
//! C's order: Content-Length with Transfer-Encoding, a second Host, an
//! Expect other than `100-continue`, a Transfer-Encoding other than a lone
//! `chunked`, a second or malformed Content-Length, one past the body limit.
//! A refused request is answered with C's status page and the connection
//! shut down, as a head the parser refused is.

use core::time::Duration;

use npro_core::time::Instant;

use crate::Storage;
use crate::chunked::{Chunk, Dechunk};
use crate::fields::{content_length, transfer_encoding_is_chunked};
use crate::head::{self, Answer, Head, Progress, Refused, Side, Version};
use crate::own::{Own, check_header, decimal};
use crate::table::{CapacityTooLarge, HeaderTable};
use crate::token::Token;

/// The most a request body may be unless configured: C's default
/// `max_http_body_size`.
pub const DEFAULT_MAX_BODY: u64 = 100 * 1024 * 1024;

/// How long a server waits on each part of a connection's life: C's
/// pending timeouts for an h1 server, with C's defaults.
///
/// Past `head`, `content` or `response`, the connection is dropped with
/// nothing more written, as C's timeouts mark the socket unusable; past
/// `keepalive`, it is shut down in good order, as C closes an idle
/// keep-alive connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// A request's head must be whole within this of the connection's
    /// start, or of its first byte after an idle connection's: C's
    /// `PENDING_TIMEOUT_HOLDING_AH`, the vhost's `timeout_secs_ah_idle`,
    /// 10s.  A deadline, not renewed as bytes come.
    pub head: Duration,
    /// The request's body may pause this long, and the application take
    /// this long to begin its answer to a request without one: C's
    /// `PENDING_TIMEOUT_HTTP_CONTENT`, the context's `timeout_secs`, 15s.
    pub content: Duration,
    /// The answer, once begun, may stall this long: C's
    /// `PENDING_TIMEOUT_HTTP_RESPONSE`, `timeout_secs` but at least 30s.
    pub response: Duration,
    /// A kept-alive connection may sit idle between requests this long,
    /// or for ever with `None`: C's `PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE`,
    /// the vhost's `keepalive_timeout`, 5s, where 0 is `None`.
    pub keepalive: Option<Duration>,
}

impl Timeouts {
    /// C's defaults.
    pub const DEFAULT: Self = Self {
        head: Duration::from_secs(10),
        content: Duration::from_secs(15),
        response: Duration::from_secs(30),
        keepalive: Some(Duration::from_secs(5)),
    };
}

/// How a server takes its requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    head: head::Config,
    max_body: u64,
    timeouts: Timeouts,
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
            timeouts: Timeouts::DEFAULT,
        }
    }

    /// Waits as long as `t` says, rather than [`Timeouts::DEFAULT`].
    #[must_use]
    pub const fn with_timeouts(mut self, t: Timeouts) -> Self {
        self.timeouts = t;
        self
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

/// What the connection asks of whatever carries it: a server closes in
/// good order with [`Close::Shutdown`], and past a deadline with
/// [`Close::Abort`].
pub use npro_core::close::Close;

/// Where the application's payload comes from: [`Server::tx`] pulls it
/// into the buffer it is writing, after anything the connection writes
/// itself, as [`crate::client::Client::tx`] pulls a request's body.
pub trait TxSource {
    /// Fills the start of `buf` with the next of the payload, returning how
    /// much: 0 if there is none yet.
    fn fill(&mut self, buf: &mut [u8]) -> usize;
}

/// A [`TxSource`] with nothing to give: for a connection whose
/// application has no payload, a client's request with no body among
/// them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoPayload;

impl TxSource for NoPayload {
    fn fill(&mut self, _: &mut [u8]) -> usize {
        0
    }
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
    /// The application's own headers, names and values, after the
    /// server's: C's `lws_add_http_header_by_name()` after
    /// `lws_add_http_common_headers()`.  A name must be a token, and a
    /// value must have no CR, LF or NUL, so neither can end its line
    /// early; the headers the server writes itself are refused here
    /// ([`HeaderRefused`]).
    pub headers: &'a [(&'a [u8], &'a [u8])],
}

pub use crate::own::{HeaderRefused, RespondError};

/// The least [`Storage::out`] a server may have: room for C's status
/// pages, which the server writes itself to refuse a request.
pub const MIN_OUT: usize = 512;

/// The headers the server writes itself, which the application may not:
/// `Content-Type`, given as [`Response::content_type`], and those the
/// response's framing and the connection's fate depend on,
/// `Content-Length`, `Transfer-Encoding`, `Connection` and `Upgrade`.
const RESERVED: [&[u8]; 5] = [
    b"content-type",
    b"content-length",
    b"transfer-encoding",
    b"connection",
    b"upgrade",
];

/// Why a server cannot be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewError {
    /// The table's storage is too large for a table.
    Capacity(CapacityTooLarge),
    /// [`Storage::out`] is shorter than [`MIN_OUT`].
    OutTooSmall,
}

impl core::fmt::Display for NewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Capacity(e) => write!(f, "{e}"),
            Self::OutTooSmall => write!(f, "a server's out storage is at least {MIN_OUT} bytes"),
        }
    }
}

impl core::error::Error for NewError {}

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

/// What the transaction in hand is waiting on, and until when: C's
/// pending timeout while it lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Watch {
    /// The body's next bytes, or the answer's start:
    /// `PENDING_TIMEOUT_HTTP_CONTENT`.
    Content(Instant),
    /// The body that came is over, and the application has as long as it
    /// takes to begin its answer: C clears the timeout there
    /// (`lws_h1_body_timeout()`).
    App,
    /// The answer, begun, going on: `PENDING_TIMEOUT_HTTP_RESPONSE`.
    Response(Instant),
}

/// What an idle connection waits for, and until when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wait {
    /// A request's first byte, idle between requests:
    /// `PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE`, or for ever.
    Idle(Option<Instant>),
    /// The rest of a request's head: `PENDING_TIMEOUT_HOLDING_AH`.
    Head(Instant),
}

/// The transaction in hand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Txn {
    body: Body,
    reply: Reply,
    watch: Watch,
    /// The application said it is done.
    completed: bool,
    head_request: bool,
    keep_alive: bool,
}

/// Where the connection is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Taking a request's head.
    Head(Wait),
    /// A request is in hand.
    Request(Txn),
    /// Writing a refusal, which must have gone by the deadline, then
    /// shutting down.
    Refusing(Instant),
    /// Writing a 101, which must have gone by the deadline: the request's
    /// upgrade is agreed.
    Switching(Instant),
    /// The 101 has gone: from the byte after the request's head, the
    /// connection is the upgraded protocol's, and this takes nothing more.
    Switched,
    /// The connection is done with.
    Closed(Close),
}

/// One h1 server connection.
///
/// ```
/// use npro_core::time::Instant;
/// use npro_h1::Storage;
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
/// let now = Instant::from_micros(1_000_000);
/// let mut s = Server::new(Storage { table: [0u8; 1024], out: [0u8; 1024] }, Config::default(), now)?;
/// let rx = s.rx(now, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
/// assert_eq!(rx.event, Some(Event::Request));
/// s.respond(Response {
///     status: 200,
///     content_type: Some(b"text/plain"),
///     content_length: Some(2),
///     headers: &[],
/// })?;
/// let mut out = [0u8; 256];
/// let tx = s.tx(now, &mut out, &mut Text(b"ok"));
/// s.complete(now);
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
    own: Own<S>,
    /// The version the last request asked in, which C answers a refused
    /// request target in: `wsi->stream.request_version`.
    version: Version,
    /// The status the request in hand was answered with, if it was: the
    /// last status line composed for it, as C's `access_log.response`.
    answered: Option<u16>,
    /// A transaction over since this was last taken.
    settled: Option<Settled>,
}

/// A transaction that is over: its answer, if it had one, handed to the
/// connection whole, and nothing more of it to come.  [`Server::take_settled`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settled {
    /// The status it was answered with: the last status line composed
    /// for it, or `None` if the connection closed unanswered.
    pub status: Option<u16>,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Server<S> {
    /// A connection whose request heads are kept in `storage`'s table,
    /// and its answers composed in its `out`.  The connection starts at
    /// `now`, and its first request's head must be whole within
    /// [`Timeouts::head`] of it.
    ///
    /// # Errors
    ///
    /// [`NewError`] if the table's storage is longer than a table may be,
    /// or `out` is shorter than [`MIN_OUT`].
    pub fn new(storage: Storage<S>, config: Config, now: Instant) -> Result<Self, NewError> {
        if storage.out.as_ref().len() < MIN_OUT {
            return Err(NewError::OutTooSmall);
        }
        Ok(Self {
            head: Head::new(storage.table, Side::Server, config.head)
                .map_err(NewError::Capacity)?,
            config,
            phase: Phase::Head(Wait::Head(now.saturating_add(config.timeouts.head))),
            own: Own::new(storage.out),
            version: Version::Http10,
            answered: None,
            settled: None,
        })
    }

    /// Gives back the storage the connection was made in.  It is done
    /// with the connection: as C drops the ah when the user returns from
    /// ESTABLISHED, a server upgraded to ws gives it back once the request
    /// event, the last time the headers are seen, is over.
    #[must_use]
    pub fn into_storage(self) -> Storage<S> {
        Storage {
            table: self.head.into_table().into_storage(),
            out: self.own.into_storage(),
        }
    }

    /// The request in hand's headers.
    #[must_use]
    pub const fn request(&self) -> &HeaderTable<S> {
        self.head.table()
    }

    /// The version the request in hand asked in.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// The status the request in hand was answered with, if it was: the
    /// last status line composed for it, 101 for an upgrade agreed.  For
    /// an access log line written as the connection closes, with the
    /// transaction still open: C's `access_log.response`.
    #[must_use]
    pub const fn answered(&self) -> Option<u16> {
        self.answered
    }

    /// The transaction that is over since this was last asked, if one is:
    /// its answer, or refusal, handed to the connection whole, and the
    /// connection on to the next request or closing.  Not an upgrade
    /// agreed, whose connection goes on as the upgraded protocol's.  For
    /// the access log, written as C writes it at
    /// `lws_http_transaction_completed()`.
    pub const fn take_settled(&mut self) -> Option<Settled> {
        self.settled.take()
    }

    /// The transaction in hand is over.
    const fn settled(&mut self) {
        self.settled = Some(Settled {
            status: self.answered,
        });
    }

    /// Whether a request is in hand and not yet answered: the time to
    /// answer it ([`Server::respond`]), refuse its upgrade
    /// ([`Server::refuse_upgrade`]), or accept it, as the connection
    /// carrying it changes role.
    #[must_use]
    pub const fn is_awaiting_answer(&self) -> bool {
        matches!(
            self.phase,
            Phase::Request(Txn {
                reply: Reply::Awaited,
                ..
            })
        )
    }

    /// Whether the connection answered its request's upgrade with a 101
    /// ([`Server::switch`]) and the 101 has gone: from the byte after the
    /// request's head, the connection is the upgraded protocol's.
    #[must_use]
    pub const fn is_switched(&self) -> bool {
        matches!(self.phase, Phase::Switched)
    }

    /// Whether [`Server::rx`] has something to give without more input:
    /// the end of a request's body that came with the bytes already
    /// taken, or of one there was none of.  A caller that hands in input
    /// only as it arrives must call `rx` again, with none, while this
    /// holds.
    #[must_use]
    pub const fn rx_pending(&self) -> bool {
        matches!(
            self.phase,
            Phase::Request(Txn {
                body: Body::EndDue,
                ..
            })
        )
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
            Phase::Head(_)
            | Phase::Request(_)
            | Phase::Refusing(_)
            | Phase::Switching(_)
            | Phase::Switched => None,
        }
    }

    /// When the connection next needs [`Server::deadline_passed`], if it
    /// is waiting on anything: see [`Timeouts`].
    #[must_use]
    pub const fn next_deadline(&self) -> Option<Instant> {
        match self.phase {
            Phase::Head(Wait::Idle(until)) => until,
            Phase::Head(Wait::Head(until)) | Phase::Refusing(until) | Phase::Switching(until) => {
                Some(until)
            }
            Phase::Request(t) => match t.watch {
                Watch::Content(until) | Watch::Response(until) => Some(until),
                Watch::App => None,
            },
            Phase::Closed(_) | Phase::Switched => None,
        }
    }

    /// Tells the connection it is `now`, which may be past its
    /// [`Server::next_deadline`]: then an idle connection asks to be shut
    /// down, and any other to be aborted, nothing more written, as C's
    /// timeouts close them.
    pub fn deadline_passed(&mut self, now: Instant) {
        if self.next_deadline().is_none_or(|d| now < d) {
            return;
        }
        let close = match self.phase {
            Phase::Head(Wait::Idle(_)) => Close::Shutdown,
            Phase::Head(Wait::Head(_))
            | Phase::Request(_)
            | Phase::Refusing(_)
            | Phase::Switching(_) => Close::Abort,
            // no deadline: not passed
            Phase::Switched => return,
            Phase::Closed(c) => c,
        };
        self.own.clear();
        self.phase = Phase::Closed(close);
    }

    /// The application drops the connection: nothing more is written,
    /// whatever was composed or owed, and the connection asks to be
    /// aborted, as C closes a connection whose user returned -1.  A
    /// connection already closing keeps its close.
    ///
    /// ```
    /// use npro_core::time::Instant;
    /// use npro_h1::Storage;
    /// use npro_h1::server::{Close, Config, Server};
    ///
    /// let now = Instant::from_micros(1_000_000);
    /// let mut s = Server::new(Storage { table: [0u8; 1024], out: [0u8; 1024] }, Config::default(), now)?;
    /// s.rx(now, b"GET / HTTP/1.1\r\n\r\n");
    /// s.abort();
    /// assert_eq!(s.close(), Some(Close::Abort));
    /// assert!(!s.wants_write());
    /// # Ok::<(), Box<dyn core::error::Error>>(())
    /// ```
    pub const fn abort(&mut self) {
        if let Phase::Closed(_) = self.phase {
            return;
        }
        self.own.clear();
        self.phase = Phase::Closed(Close::Abort);
    }

    /// The peer closed its side: C's zero-length rx, which its h1 server
    /// answers by closing.  What the connection already composed goes, then
    /// it shuts down; payload the application has yet to give is not
    /// asked for.
    pub const fn rx_closed(&mut self) {
        match self.phase {
            Phase::Head(_) | Phase::Request(_) | Phase::Refusing(_) | Phase::Switching(_) => {
                self.phase = Phase::Closed(Close::Shutdown);
            }
            // the upgraded protocol's to hear
            Phase::Closed(_) | Phase::Switched => {}
        }
    }

    /// Takes bytes from the peer, at `now`: see [`Event`].
    pub fn rx<'a>(&mut self, now: Instant, input: &'a [u8]) -> Rx<'a> {
        let held = Rx {
            consumed: 0,
            event: None,
        };
        match self.phase {
            Phase::Head(w) => self.rx_head(now, w, input),
            Phase::Request(t) => self.rx_body(now, t, input),
            // after a 101, the bytes are the upgraded protocol's
            Phase::Refusing(_) | Phase::Switching(_) | Phase::Switched | Phase::Closed(_) => held,
        }
    }

    fn rx_head<'a>(&mut self, now: Instant, w: Wait, input: &'a [u8]) -> Rx<'a> {
        // an idle connection's next request has begun: C attaches a table
        // to it, under PENDING_TIMEOUT_HOLDING_AH
        if matches!(w, Wait::Idle(_)) && !input.is_empty() {
            let until = now.saturating_add(self.config.timeouts.head);
            self.phase = Phase::Head(Wait::Head(until));
        }
        match self.head.rx(input) {
            Ok(Progress::More) => Rx {
                consumed: input.len(),
                event: None,
            },
            Ok(Progress::Complete { consumed }) => Rx {
                consumed,
                event: self.request_complete(now),
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
                self.refused_head(now, r);
                Rx {
                    consumed: 0,
                    event: None,
                }
            }
        }
    }

    /// The parser refused the head: C answers it, if it says to, in the
    /// version it can, and shuts down.
    fn refused_head(&mut self, now: Instant, r: Refused) {
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
        self.refuse(now, version, code, text);
    }

    /// Refuses the request in hand's upgrade with C's status page, and
    /// `extra` as a header of it, then shuts down: C's
    /// `_lws_return_http_status()` as `ws_upgrade_refuse()` uses it, a 426
    /// saying `sec-websocket-version: 13`.  It is an answer, and must have
    /// gone within [`Timeouts::response`] of `now`.
    ///
    /// # Errors
    ///
    /// [`RespondError::NotNow`] if there is no request in hand, or it is
    /// answered already; [`RespondError::TooLong`] if `extra` does not fit,
    /// and the request is still unanswered.
    pub fn refuse_upgrade(
        &mut self,
        now: Instant,
        code: u16,
        extra: Option<(&[u8], &[u8])>,
    ) -> Result<(), RespondError> {
        match self.phase {
            Phase::Request(Txn {
                reply: Reply::Awaited,
                ..
            }) => {}
            Phase::Request(_)
            | Phase::Head(_)
            | Phase::Refusing(_)
            | Phase::Switching(_)
            | Phase::Switched
            | Phase::Closed(_) => {
                return Err(RespondError::NotNow);
            }
        }
        let one;
        let headers: &[(&[u8], &[u8])] = match extra {
            Some(h) => {
                one = [h];
                &one
            }
            None => &[],
        };
        self.own
            .compose(|o| status_page(o, self.version, code, b"", headers, Page::Whole))?;
        self.answered = Some(code);
        self.refusing(now);
        Ok(())
    }

    /// Answers the request in hand with C's status page for `code`, as
    /// `lws_return_http_status()` does, `headers` after its own, and is
    /// done with the transaction at `now`, as [`Server::complete`] is: a
    /// 404 for what nothing serves, the connection kept for the next
    /// request.  A HEAD is answered with the page's head alone.
    ///
    /// # Errors
    ///
    /// [`RespondError::NotNow`] if there is no request in hand, or it is
    /// answered already; [`RespondError::Header`] if one of `headers` is
    /// refused; [`RespondError::TooLong`] if the page does not fit.  The
    /// request is then still unanswered.
    pub fn status(
        &mut self,
        now: Instant,
        code: u16,
        headers: &[(&[u8], &[u8])],
    ) -> Result<(), RespondError> {
        let Phase::Request(mut t) = self.phase else {
            return Err(RespondError::NotNow);
        };
        if t.reply != Reply::Awaited {
            return Err(RespondError::NotNow);
        }
        let version = self.version;
        let page = if t.head_request {
            Page::HeadOnly
        } else {
            Page::Whole
        };
        self.own
            .compose(|o| status_page(o, version, code, b"", headers, page))?;
        self.answered = Some(code);
        // the page is the connection's own bytes: nothing is owed
        t.reply = Reply::Payload(Some(0));
        t.completed = true;
        self.phase = Phase::Request(t);
        self.settle(now);
        Ok(())
    }

    /// Answers the request in hand with a redirect to `location`, as C's
    /// `lws_http_redirect()` composes it: `location`, then `content-type:
    /// text/html` and `content-length: 0`, so a kept connection's client
    /// knows the transaction is over, then `headers`; and is done with the
    /// transaction at `now`.
    ///
    /// # Errors
    ///
    /// [`RespondError::NotNow`] if there is no request in hand, or it is
    /// answered already; [`RespondError::Header`] if `location` or one of
    /// `headers` is refused; [`RespondError::TooLong`] if it does not fit.
    /// The request is then still unanswered.
    pub fn redirect(
        &mut self,
        now: Instant,
        code: u16,
        location: &[u8],
        headers: &[(&[u8], &[u8])],
    ) -> Result<(), RespondError> {
        let Phase::Request(mut t) = self.phase else {
            return Err(RespondError::NotNow);
        };
        if t.reply != Reply::Awaited {
            return Err(RespondError::NotNow);
        }
        check_header(b"location", location, &[]).map_err(RespondError::Header)?;
        let version = self.version;
        self.own.compose(|own| {
            status_line(own, version, code)?;
            own.push(b"location: ")?;
            own.push(location)?;
            own.push(b"\r\ncontent-type: text/html\r\ncontent-length: 0\r\n")?;
            own.push_headers(headers, &RESERVED)?;
            own.push(b"\r\n")
        })?;
        self.answered = Some(code);
        t.reply = Reply::Payload(Some(0));
        t.completed = true;
        self.phase = Phase::Request(t);
        self.settle(now);
        Ok(())
    }

    /// Queues C's status page, then the shutdown.  It fits: `out` is at
    /// least [`MIN_OUT`], which every page the server writes itself fits
    /// in (a test says so).
    fn refuse(&mut self, now: Instant, version: Version, code: u16, text: &[u8]) {
        // if it did not, nothing would be written before the shutdown
        let _ = self
            .own
            .compose(|o| status_page(o, version, code, text, &[], Page::Whole));
        self.answered = Some(code);
        self.refusing(now);
    }

    /// The status page is an answer: it goes under the response's
    /// watchdog.
    fn refusing(&mut self, now: Instant) {
        self.phase = Phase::Refusing(now.saturating_add(self.config.timeouts.response));
    }

    /// The head is whole: C's checks, in C's order, then the request.
    fn request_complete(&mut self, now: Instant) -> Option<Event<'static>> {
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
            self.refuse(now, version, code, b"");
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
                    self.refuse(now, version, 400, b"");
                    return None;
                }
                Some(n) if n > self.config.max_body => {
                    self.refuse(now, version, 413, b"");
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
        // C's lws_http_action(): content is due, or the answer
        self.answered = None;
        self.phase = Phase::Request(Txn {
            body,
            reply: Reply::Awaited,
            watch: Watch::Content(now.saturating_add(self.config.timeouts.content)),
            completed: false,
            head_request: present(Token::HeadUri),
            keep_alive,
        });
        Some(Event::Request)
    }

    fn rx_body<'a>(&mut self, now: Instant, mut t: Txn, input: &'a [u8]) -> Rx<'a> {
        let was = t.body;
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
        // C's lws_h1_body_timeout(): the body's bytes renew its timeout,
        // and its end clears it, but not under an answer begun, unless the
        // body is being discarded after the transaction
        let ended = matches!(was, Body::Length(_) | Body::Chunked(_)) && t.body == Body::EndDue;
        if t.completed || !matches!(t.watch, Watch::Response(_)) {
            if ended {
                t.watch = Watch::App;
            } else if consumed > 0 {
                t.watch = Watch::Content(now.saturating_add(self.config.timeouts.content));
            }
        }
        self.phase = Phase::Request(t);
        self.settle(now);
        Rx { consumed, event }
    }

    /// Answers the request in hand.
    ///
    /// # Errors
    ///
    /// [`RespondError`] if there is none unanswered, the head is too
    /// long, or one of the application's headers is refused.  The request
    /// is then still unanswered.
    pub fn respond(&mut self, r: Response<'_>) -> Result<(), RespondError> {
        let Phase::Request(mut t) = self.phase else {
            return Err(RespondError::NotNow);
        };
        if t.reply != Reply::Awaited {
            return Err(RespondError::NotNow);
        }
        let version = self.version;
        // a 1xx, 204 or 304 has no payload, whatever its length says
        // (RFC 9110 6.4.1), as a HEAD's answer has none
        let bodiless = matches!(r.status, 100..=199 | 204 | 304);
        self.own.compose(|own| {
            status_line(own, version, r.status)?;
            if let Some(ct) = r.content_type {
                own.push(b"content-type: ")?;
                own.push(ct)?;
                own.push(b"\r\n")?;
            }
            if let Some(n) = r.content_length {
                own.push(b"content-length: ")?;
                own.push_u64(n)?;
                own.push(b"\r\n")?;
            } else if !bodiless {
                // there is no length: the connection's close ends it
                own.push(b"connection: close\r\n")?;
            }
            own.push_headers(r.headers, &RESERVED)?;
            own.push(b"\r\n")
        })?;
        self.answered = Some(r.status);
        if r.content_length.is_none() && !bodiless {
            t.keep_alive = false;
        }
        t.reply = Reply::Payload(if t.head_request || bodiless {
            Some(0)
        } else {
            r.content_length
        });
        self.phase = Phase::Request(t);
        Ok(())
    }

    /// Agrees the request in hand's upgrade, to `upgrade`, at `now`: a 101
    /// with `upgrade` and the application's `headers`, checked as
    /// [`Response::headers`] are.  Once it has gone, within
    /// [`Timeouts::response`] of `now`, the connection is the upgraded
    /// protocol's ([`Server::is_switched`]), and this takes nothing more.
    /// For a protocol the application carries itself, or passes through,
    /// as a proxy does once the origin agreed; ws accepted here has its own
    /// 101, from `npro_ws::handshake`.
    ///
    /// # Errors
    ///
    /// [`RespondError::NotNow`] unless an HTTP/1.1 request asking for an
    /// upgrade is in hand, unanswered, with no body still to come;
    /// [`RespondError::Header`] if `upgrade` or a header is refused; or
    /// [`RespondError::TooLong`].  The request is then still unanswered.
    pub fn switch(
        &mut self,
        now: Instant,
        upgrade: &[u8],
        headers: &[(&[u8], &[u8])],
    ) -> Result<(), RespondError> {
        let Phase::Request(t) = self.phase else {
            return Err(RespondError::NotNow);
        };
        let asked = self.version == Version::Http11
            && self.head.table().is_present(Token::Upgrade)
            && t.reply == Reply::Awaited
            && matches!(t.body, Body::Over | Body::EndDue);
        if !asked {
            return Err(RespondError::NotNow);
        }
        if upgrade.is_empty() {
            return Err(RespondError::Header(HeaderRefused::Value));
        }
        check_header(b"upgrade", upgrade, &[]).map_err(RespondError::Header)?;
        self.own.compose(|own| {
            own.push(b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: ")?;
            own.push(upgrade)?;
            own.push(b"\r\n")?;
            own.push_headers(headers, &RESERVED)?;
            own.push(b"\r\n")
        })?;
        self.answered = Some(101);
        self.phase = Phase::Switching(now.saturating_add(self.config.timeouts.response));
        Ok(())
    }

    /// The application may take `d` from `now` to begin its answer to
    /// the request in hand, instead of [`Timeouts::content`]: what a
    /// script spawned for it is allowed, C's `lws_set_timeout()` with
    /// `PENDING_TIMEOUT_CGI`.  Nothing changes once the answer has begun,
    /// or with no request in hand.
    pub fn answer_within(&mut self, now: Instant, d: Duration) {
        if let Phase::Request(mut t) = self.phase {
            if t.reply == Reply::Awaited {
                t.watch = Watch::Content(now.saturating_add(d));
                self.phase = Phase::Request(t);
            }
        }
    }

    /// The application is done with the transaction, at `now`: C's
    /// `lws_http_transaction_completed()`.  The rest of the request's body
    /// is taken without it, and once the answer has gone, the connection
    /// takes the next request, or, if the answer was short of its length,
    /// or the request did not keep the connection, shuts down.
    pub fn complete(&mut self, now: Instant) {
        if let Phase::Request(mut t) = self.phase {
            t.completed = true;
            self.phase = Phase::Request(t);
            self.settle(now);
        }
    }

    /// Writes what is owed the peer into `out`, at `now`: the connection's
    /// own bytes, then the payload, pulled from `src`.  An answer begun is
    /// watched from then, and whatever more of it goes renews the watch:
    /// C's `lws_http_response_started()` and `_progress()`.
    pub fn tx(&mut self, now: Instant, out: &mut [u8], src: &mut dyn TxSource) -> Tx {
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
                }
            }
            if written > 0 && matches!(t.reply, Reply::Payload(_)) {
                t.watch = Watch::Response(now.saturating_add(self.config.timeouts.response));
            }
            self.phase = Phase::Request(t);
            self.settle(now);
        }
        if !self.own.pending() {
            match self.phase {
                Phase::Refusing(_) => {
                    self.phase = Phase::Closed(Close::Shutdown);
                    self.settled();
                }
                Phase::Switching(_) => self.phase = Phase::Switched,
                Phase::Head(_) | Phase::Request(_) | Phase::Switched | Phase::Closed(_) => {}
            }
        }
        Tx {
            written,
            more: self.own.pending(),
        }
    }

    /// Ends the transaction if it is over: the application completed it,
    /// its answer has gone, and its body has been taken.
    fn settle(&mut self, now: Instant) {
        let Phase::Request(t) = self.phase else {
            return;
        };
        if !t.completed || self.own.pending() {
            return;
        }
        let Reply::Payload(owed) = t.reply else {
            // completed with no answer: C closes
            self.phase = Phase::Closed(Close::Shutdown);
            self.settled();
            return;
        };
        // with no length, the close ends it; short of its length, the peer
        // would take what comes next as the rest of it
        if owed.is_none_or(|o| o > 0) || !t.keep_alive {
            self.phase = Phase::Closed(Close::Shutdown);
            self.settled();
            return;
        }
        match t.body {
            Body::Over | Body::EndDue => {
                self.head.reset();
                // C's PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE
                let until = self
                    .config
                    .timeouts
                    .keepalive
                    .map(|k| now.saturating_add(k));
                self.phase = Phase::Head(Wait::Idle(until));
                self.settled();
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

fn status_line<S: AsRef<[u8]> + AsMut<[u8]>>(
    own: &mut Own<S>,
    v: Version,
    code: u16,
) -> Result<(), RespondError> {
    own.push(match v {
        Version::Http10 => b"HTTP/1.0 ",
        Version::Http11 => b"HTTP/1.1 ",
    })?;
    own.push_u64(u64::from(code))?;
    own.push(b" ")?;
    own.push(reason(code))?;
    own.push(b"\r\n")
}

/// How much of a status page is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    /// Its head and its body.
    Whole,
    /// Its head alone, saying the body's length: a HEAD's answer.
    HeadOnly,
}

/// C's status page: `_lws_return_http_status()` and
/// `lws_http_status_page_body()`, with `headers` after its own.
fn status_page<S: AsRef<[u8]> + AsMut<[u8]>>(
    own: &mut Own<S>,
    v: Version,
    code: u16,
    text: &[u8],
    headers: &[(&[u8], &[u8])],
    page: Page,
) -> Result<(), RespondError> {
    const PRE: &[u8] = b"<html><head><meta charset=utf-8 http-equiv=\"Content-Language\" \
content=\"en\"/><link rel=\"stylesheet\" type=\"text/css\" href=\"/error.css\"/>\
</head><body><h1>";
    const POST: &[u8] = b"</body></html>";
    let mut d = [0u8; 20];
    let code_text = decimal(u64::from(code), &mut d);
    let body_len = [PRE.len(), code_text.len(), 5, text.len(), POST.len()]
        .iter()
        .try_fold(0usize, |a, n| a.checked_add(*n))
        .ok_or(RespondError::TooLong)?;
    status_line(own, v, code)?;
    own.push(b"content-type: text/html\r\n")?;
    // C adds the extra headers here, before the length
    own.push_headers(headers, &RESERVED)?;
    own.push(b"content-length: ")?;
    own.push_u64(u64::try_from(body_len).map_err(|_| RespondError::TooLong)?)?;
    own.push(b"\r\n\r\n")?;
    match page {
        Page::Whole => {}
        Page::HeadOnly => return Ok(()),
    }
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
    use alloc::vec;
    use alloc::vec::Vec;

    /// When the tests' connections are made, and all they do happens.
    const T0: Instant = Instant::from_micros(1_000_000);

    struct Nothing;
    impl TxSource for Nothing {
        fn fill(&mut self, _: &mut [u8]) -> usize {
            0
        }
    }

    fn server() -> Server<[u8; 1024]> {
        Server::new(
            Storage {
                table: [0u8; 1024],
                out: [0u8; 1024],
            },
            Config::default().with_max_body(100),
            T0,
        )
        .unwrap()
    }

    /// What the server writes for `head` before it shuts down.
    fn refused(head: &[u8]) -> Vec<u8> {
        let mut s = server();
        let rx = s.rx(T0, head);
        assert_eq!(rx.event, None, "{}", head.escape_ascii());
        let mut out = [0u8; 1024];
        let tx = s.tx(T0, &mut out, &mut Nothing);
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
            let rx = s.rx(T0, input);
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
        let rx = s.rx(T0, req);
        assert_eq!(rx.event, Some(Event::Request));
        let rest = &req[rx.consumed..];
        s.respond(Response {
            status: 200,
            content_type: None,
            content_length: Some(0),
            headers: &[],
        })
        .unwrap();
        let mut out = [0u8; 256];
        let _ = s.tx(T0, &mut out, &mut Nothing);
        s.complete(T0);
        let discarded = s.rx(T0, rest);
        assert_eq!((discarded.consumed, discarded.event), (3, None));
        let next = s.rx(T0, &rest[3..]);
        assert_eq!(next.event, Some(Event::Request));
        assert_eq!(s.request().first(Token::GetUri), Some(&b"/n"[..]));
    }

    #[test]
    fn a_status_page_answers_and_the_connection_is_kept() {
        let mut s = server_with(
            MIN_OUT,
            b"GET /x HTTP/1.1\r\nHost: x\r\n\r\nHEAD /y HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        s.status(T0, 404, &[(b"x-vhost", b"1")]).unwrap();
        // answered: a second answer is refused
        assert_eq!(s.status(T0, 404, &[]), Err(RespondError::NotNow));
        let mut out = [0u8; MIN_OUT];
        let tx = s.tx(T0, &mut out, &mut Nothing);
        let page = &out[..tx.written];
        assert!(
            page.starts_with(
                b"HTTP/1.1 404 Not Found\r\ncontent-type: text/html\r\nx-vhost: 1\r\n\
                content-length: 173\r\n\r\n<html>"
            ),
            "{}",
            page.escape_ascii()
        );
        assert!(page.ends_with(b"<h1>404</h1></body></html>"));
        assert!(s.close().is_none());
        // the pipelined HEAD is next, and gets the head alone
        assert_eq!(
            s.rx(T0, b"HEAD /y HTTP/1.1\r\nHost: x\r\n\r\n").event,
            Some(Event::Request)
        );
        s.status(T0, 403, &[]).unwrap();
        let head = s.tx(T0, &mut out, &mut Nothing);
        assert!(out[..head.written].ends_with(b"content-length: 173\r\n\r\n"));
        assert!(s.close().is_none());
        // a redirect is composed as C composes it, and is over at once
        assert_eq!(
            s.rx(T0, b"GET /z HTTP/1.1\r\nHost: x\r\n\r\n").event,
            Some(Event::Request)
        );
        s.redirect(T0, 302, b"/404.html", &[(b"x-vhost", b"1")])
            .unwrap();
        let r = s.tx(T0, &mut out, &mut Nothing);
        assert_eq!(
            &out[..r.written],
            b"HTTP/1.1 302 Redirect\r\nlocation: /404.html\r\ncontent-type: text/html\r\n\
              content-length: 0\r\nx-vhost: 1\r\n\r\n"
        );
        assert!(s.close().is_none());
        assert_eq!(s.redirect(T0, 302, b"/", &[]), Err(RespondError::NotNow));
        assert_eq!(
            s.rx(T0, b"GET /z HTTP/1.1\r\nHost: x\r\n\r\n").event,
            Some(Event::Request)
        );
        assert!(matches!(
            s.redirect(T0, 302, b"bad\r\nvalue", &[]),
            Err(RespondError::Header(_))
        ));
        assert!(s.is_awaiting_answer());
        // a reserved header is refused, and the request still unanswered
        let mut other = server_out(MIN_OUT);
        assert!(matches!(
            other.status(T0, 404, &[(b"content-length", b"0")]),
            Err(RespondError::Header(_))
        ));
        assert!(other.is_awaiting_answer());
    }

    #[test]
    fn a_304_has_no_payload_and_keeps_the_connection() {
        let mut s = server_out(MIN_OUT);
        s.respond(Response {
            status: 304,
            content_type: None,
            content_length: None,
            headers: &[(b"etag", b"\"x\"")],
        })
        .unwrap();
        let mut out = [0u8; 256];
        let tx = s.tx(T0, &mut out, &mut Nothing);
        assert_eq!(
            &out[..tx.written],
            b"HTTP/1.1 304 Not Modified\r\netag: \"x\"\r\n\r\n"
        );
        s.complete(T0);
        assert!(s.close().is_none());
        assert_eq!(
            s.rx(T0, b"GET /n HTTP/1.1\r\n\r\n").event,
            Some(Event::Request)
        );
    }

    #[test]
    fn http_1_0_closes_unless_it_keeps_alive() {
        for (head, keeps) in [
            (&b"GET / HTTP/1.0\r\n\r\n"[..], false),
            (b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", true),
            (b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n", false),
        ] {
            let mut s = server();
            assert_eq!(s.rx(T0, head).event, Some(Event::Request));
            s.respond(Response {
                status: 200,
                content_type: None,
                content_length: Some(0),
                headers: &[],
            })
            .unwrap();
            let mut out = [0u8; 256];
            let _ = s.tx(T0, &mut out, &mut Nothing);
            s.complete(T0);
            assert_eq!(s.close().is_none(), keeps, "{}", head.escape_ascii());
        }
    }

    #[test]
    fn an_answer_without_a_length_closes() {
        let mut s = server();
        assert_eq!(
            s.rx(T0, b"GET / HTTP/1.1\r\n\r\n").event,
            Some(Event::Request)
        );
        s.respond(Response {
            status: 200,
            content_type: None,
            content_length: None,
            headers: &[],
        })
        .unwrap();
        let mut out = [0u8; 256];
        let tx = s.tx(T0, &mut out, &mut Nothing);
        assert_eq!(
            &out[..tx.written],
            b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n"
        );
        s.complete(T0);
        assert_eq!(s.close(), Some(Close::Shutdown));
        assert_eq!(
            s.respond(Response {
                status: 200,
                content_type: None,
                content_length: None,
                headers: &[],
            }),
            Err(RespondError::NotNow)
        );
    }

    /// `T0` and `secs` seconds.
    fn at(secs: u64) -> Instant {
        T0.checked_add(Duration::from_secs(secs)).unwrap()
    }

    /// The application's payload, a piece at a time.
    struct Text<'a>(&'a [u8]);
    impl TxSource for Text<'_> {
        fn fill(&mut self, buf: &mut [u8]) -> usize {
            let n = self.0.len().min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            n
        }
    }

    const OK2: Response<'static> = Response {
        status: 200,
        content_type: None,
        content_length: Some(2),
        headers: &[],
    };

    #[test]
    fn aborted_it_writes_nothing_more_and_a_close_already_asked_stands() {
        let mut s = server();
        s.rx(T0, b"GET / HTTP/1.1\r\n\r\n");
        s.respond(OK2).unwrap();
        s.abort();
        assert_eq!(s.close(), Some(Close::Abort));
        let mut out = [0u8; 256];
        assert_eq!(s.tx(T0, &mut out, &mut Text(b"ok")).written, 0);
        assert_eq!(s.next_deadline(), None);
        // one whose peer closed asked for a shutdown already: that stands
        let mut closed = server();
        closed.rx_closed();
        closed.abort();
        assert_eq!(closed.close(), Some(Close::Shutdown));
    }

    #[test]
    fn a_head_must_be_whole_by_its_deadline_however_it_trickles() {
        let mut s = server();
        assert_eq!(s.next_deadline(), Some(at(10)));
        assert_eq!(s.rx(at(9), b"GET / HT").consumed, 8);
        assert_eq!(s.next_deadline(), Some(at(10)));
        s.deadline_passed(at(9));
        assert_eq!(s.close(), None);
        s.deadline_passed(at(10));
        assert_eq!(s.close(), Some(Close::Abort));
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn the_answer_is_due_then_watched_while_it_goes() {
        let mut s = server();
        assert_eq!(
            s.rx(at(1), b"GET / HTTP/1.1\r\n\r\n").event,
            Some(Event::Request)
        );
        // the answer must begin within the content timeout
        assert_eq!(s.next_deadline(), Some(at(16)));
        s.respond(OK2).unwrap();
        // its head going starts the response's watchdog
        let mut out = [0u8; 256];
        let mut text = Text(b"ok");
        assert_eq!(s.tx(at(2), &mut out[..8], &mut Text(b"")).written, 8);
        assert_eq!(s.next_deadline(), Some(at(32)));
        let tx = s.tx(at(20), &mut out, &mut text);
        assert!(tx.written > 0);
        assert_eq!(s.next_deadline(), Some(at(50)));
        // writing nothing renews nothing
        assert_eq!(s.tx(at(25), &mut out, &mut text).written, 0);
        assert_eq!(s.next_deadline(), Some(at(50)));
    }

    #[test]
    fn a_stalled_answer_is_dropped() {
        let mut s = server();
        s.rx(T0, b"GET / HTTP/1.1\r\n\r\n");
        s.respond(OK2).unwrap();
        let mut out = [0u8; 8];
        s.tx(T0, &mut out, &mut Text(b""));
        assert!(s.wants_write());
        s.deadline_passed(at(30));
        assert_eq!(s.close(), Some(Close::Abort));
        assert!(!s.wants_write());
        assert_eq!(s.tx(at(30), &mut out, &mut Text(b"ok")).written, 0);
    }

    #[test]
    fn a_bodys_bytes_renew_its_timeout_and_its_end_clears_it() {
        let mut s = server();
        let head = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n";
        assert_eq!(s.rx(T0, head).event, Some(Event::Request));
        assert_eq!(s.next_deadline(), Some(at(15)));
        assert_eq!(s.rx(at(10), b"ab").event, Some(Event::Body(b"ab")));
        assert_eq!(s.next_deadline(), Some(at(25)));
        assert_eq!(s.rx(at(20), b"cd").event, Some(Event::Body(b"cd")));
        // C's lws_h1_body_timeout(wsi, 0): the app has as long as it takes
        assert_eq!(s.next_deadline(), None);
        assert_eq!(s.rx(at(20), b"").event, Some(Event::BodyEnd));
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn a_body_does_not_take_the_answers_watchdog_away() {
        let mut s = server();
        let head = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n";
        s.rx(T0, head);
        s.respond(OK2).unwrap();
        let mut out = [0u8; 8];
        s.tx(T0, &mut out, &mut Text(b""));
        assert_eq!(s.next_deadline(), Some(at(30)));
        s.rx(at(10), b"ab");
        assert_eq!(s.next_deadline(), Some(at(30)));
        s.rx(at(11), b"cd");
        assert_eq!(s.next_deadline(), Some(at(30)));
    }

    #[test]
    fn a_body_discarded_after_completion_has_its_timeout_again() {
        let mut s = server();
        let head = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n";
        s.rx(T0, head);
        s.respond(OK2).unwrap();
        let mut out = [0u8; 256];
        s.tx(T0, &mut out, &mut Text(b"ok"));
        s.complete(T0);
        s.rx(at(10), b"ab");
        assert_eq!(s.next_deadline(), Some(at(25)));
    }

    /// A server that has answered one request, at `T0`, and keeps the
    /// connection.
    fn kept(t: Timeouts) -> Server<[u8; 1024]> {
        let mut s = Server::new(
            Storage {
                table: [0u8; 1024],
                out: [0u8; 1024],
            },
            Config::default().with_timeouts(t),
            T0,
        )
        .unwrap();
        s.rx(T0, b"GET / HTTP/1.1\r\n\r\n");
        s.respond(OK2).unwrap();
        let mut out = [0u8; 256];
        s.tx(T0, &mut out, &mut Text(b"ok"));
        s.complete(T0);
        assert_eq!(s.close(), None);
        s
    }

    #[test]
    fn an_idle_connection_is_shut_down_after_its_keepalive() {
        let mut s = kept(Timeouts::DEFAULT);
        assert_eq!(s.next_deadline(), Some(at(5)));
        s.deadline_passed(at(5));
        assert_eq!(s.close(), Some(Close::Shutdown));
    }

    #[test]
    fn the_next_requests_first_byte_starts_its_heads_deadline() {
        let mut s = kept(Timeouts::DEFAULT);
        s.rx(at(3), b"G");
        assert_eq!(s.next_deadline(), Some(at(13)));
        s.deadline_passed(at(13));
        assert_eq!(s.close(), Some(Close::Abort));
    }

    #[test]
    fn without_a_keepalive_an_idle_connection_waits() {
        let t = Timeouts {
            keepalive: None,
            ..Timeouts::DEFAULT
        };
        let s = kept(t);
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn a_refusal_must_go_within_the_response_timeout() {
        let mut s = server();
        s.rx(T0, b"GET /%zz HTTP/1.1\r\n\r\n");
        assert!(s.wants_write());
        assert_eq!(s.next_deadline(), Some(at(30)));
        s.deadline_passed(at(30));
        assert_eq!(s.close(), Some(Close::Abort));
        assert!(!s.wants_write());
    }

    #[test]
    fn the_peers_close_shuts_down_after_what_was_composed() {
        let mut s = server();
        s.rx(T0, b"GET / HTTP/1.1\r\n\r\n");
        s.respond(OK2).unwrap();
        s.rx_closed();
        assert_eq!(s.close(), Some(Close::Shutdown));
        assert_eq!(s.next_deadline(), None);
        // the head goes, the payload is not asked for
        let mut out = [0u8; 256];
        let tx = s.tx(T0, &mut out, &mut Text(b"ok"));
        assert!(out[..tx.written].ends_with(b"\r\n\r\n"));
        assert!(!tx.more);
    }

    /// A server whose answers are composed in `out` bytes, with `head`
    /// in hand.
    fn server_with(out: usize, head: &[u8]) -> Server<Vec<u8>> {
        let mut s = Server::new(
            Storage {
                table: vec![0u8; 1024],
                out: vec![0u8; out],
            },
            Config::default(),
            T0,
        )
        .unwrap();
        assert_eq!(s.rx(T0, head).event, Some(Event::Request));
        s
    }

    /// A server whose answers are composed in `out` bytes, a GET in hand.
    fn server_out(out: usize) -> Server<Vec<u8>> {
        server_with(out, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    }

    #[test]
    fn the_applications_headers_follow_the_servers() {
        let mut s = server_out(MIN_OUT);
        s.respond(Response {
            headers: &[(b"x-a", b"1"), (b"Cache-Control", b"max-age=60, \tpublic")],
            ..OK2
        })
        .unwrap();
        let mut out = [0u8; 256];
        let tx = s.tx(T0, &mut out, &mut Text(b"ok"));
        assert_eq!(
            &out[..tx.written],
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\
              x-a: 1\r\nCache-Control: max-age=60, \tpublic\r\n\r\nok"
        );
    }

    #[test]
    fn a_header_that_could_end_its_line_or_reframe_is_refused_and_the_request_waits() {
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
            ((b"connection", b"keep-alive"), HeaderRefused::Reserved),
            ((b"Upgrade", b"websocket"), HeaderRefused::Reserved),
            ((b"content-type", b"text/html"), HeaderRefused::Reserved),
        ] {
            let mut s = server_out(MIN_OUT);
            assert_eq!(
                s.respond(Response {
                    headers: &[(b"ok", b"1"), h],
                    ..OK2
                }),
                Err(RespondError::Header(why)),
                "{h:?}"
            );
            // nothing was composed, and the request can still be answered
            assert!(!s.wants_write());
            assert!(s.is_awaiting_answer());
            s.respond(OK2).unwrap();
        }
    }

    #[test]
    fn a_head_is_as_long_as_its_storage_allows() {
        // npro.rs' vhost headers come to over a kilobyte
        let csp = [b'a'; 1500];
        let headers: [(&[u8], &[u8]); 1] = [(b"content-security-policy", &csp)];
        let mut s = server_out(MIN_OUT);
        assert_eq!(
            s.respond(Response {
                headers: &headers,
                ..OK2
            }),
            Err(RespondError::TooLong)
        );
        assert!(!s.wants_write());
        assert!(s.is_awaiting_answer());
        let mut roomy = server_out(4096);
        roomy
            .respond(Response {
                headers: &headers,
                ..OK2
            })
            .unwrap();
        let mut out = vec![0u8; 4096];
        let tx = roomy.tx(T0, &mut out, &mut Text(b"ok"));
        assert!(out[..tx.written].ends_with(b"\r\n\r\nok"));
        assert!(
            out[..tx.written]
                .windows(csp.len())
                .any(|w| w == csp.as_slice())
        );
    }

    #[test]
    fn out_storage_is_at_least_min_out() {
        let made = |n| {
            Server::new(
                Storage {
                    table: vec![0u8; 1024],
                    out: vec![0u8; n],
                },
                Config::default(),
                T0,
            )
            .map(|_| ())
        };
        assert_eq!(made(MIN_OUT - 1), Err(NewError::OutTooSmall));
        assert_eq!(made(MIN_OUT), Ok(()));
    }

    #[test]
    fn every_page_the_server_refuses_with_fits_in_min_out() {
        for (code, text) in [
            (400, &b""[..]),
            (403, b""),
            (413, b""),
            (414, b"Oversized request URI"),
            (417, b""),
            (431, b"Oversized headers"),
            (501, b""),
            (505, b""),
        ] {
            for v in [Version::Http10, Version::Http11] {
                let mut own = Own::new([0u8; MIN_OUT]);
                assert_eq!(
                    own.compose(|o| status_page(o, v, code, text, &[], Page::Whole)),
                    Ok(()),
                    "{code}"
                );
            }
        }
    }

    #[test]
    fn an_upgrade_refusal_too_long_leaves_the_request_unanswered() {
        let mut s = server_out(MIN_OUT);
        let long = [b'v'; MIN_OUT];
        assert_eq!(
            s.refuse_upgrade(T0, 426, Some((b"x", &long))),
            Err(RespondError::TooLong)
        );
        assert!(s.is_awaiting_answer());
        assert!(!s.wants_write());
    }

    const UPGRADE: &[u8] = b"GET / HTTP/1.1\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\n";

    #[test]
    fn a_switch_is_a_101_then_nothing_more_is_taken() {
        let mut s = server();
        assert_eq!(s.rx(T0, UPGRADE).event, Some(Event::Request));
        s.switch(T0, b"x", &[(b"sec-websocket-accept", b"abc")])
            .unwrap();
        assert!(!s.is_switched());
        assert!(!s.is_awaiting_answer());
        assert_eq!(
            s.next_deadline(),
            Some(T0.saturating_add(Timeouts::DEFAULT.response))
        );
        // what follows is the upgraded protocol's, not taken here
        assert_eq!(s.rx(T0, b"\x81\x00").consumed, 0);
        let mut out = [0u8; 256];
        let tx = s.tx(T0, &mut out, &mut Text(b"never"));
        assert_eq!(
            &out[..tx.written],
            b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: x\r\n\
              sec-websocket-accept: abc\r\n\r\n"
        );
        assert!(s.is_switched());
        assert_eq!((s.next_deadline(), s.close()), (None, None));
        assert_eq!(s.rx(T0, b"\x81\x00").consumed, 0);
        assert_eq!(s.tx(T0, &mut out, &mut Text(b"never")).written, 0);
        // its peer's close is the upgraded protocol's to hear
        s.rx_closed();
        assert_eq!(s.close(), None);
    }

    #[test]
    fn a_switch_must_be_asked_for_by_an_unanswered_http11_request_without_a_body_to_come() {
        for head in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            b"GET / HTTP/1.0\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\n",
            b"POST / HTTP/1.1\r\nUpgrade: x\r\nConnection: upgrade\r\nContent-Length: 5\r\n\r\n",
        ] {
            let mut s = server();
            assert_eq!(s.rx(T0, head).event, Some(Event::Request));
            assert_eq!(
                s.switch(T0, b"x", &[]),
                Err(RespondError::NotNow),
                "{}",
                head.escape_ascii()
            );
            assert!(s.is_awaiting_answer());
        }
        let mut s = server();
        assert_eq!(s.switch(T0, b"x", &[]), Err(RespondError::NotNow));
        s.rx(T0, UPGRADE);
        s.respond(OK2).unwrap();
        assert_eq!(s.switch(T0, b"x", &[]), Err(RespondError::NotNow));
    }

    #[test]
    fn a_switch_refused_leaves_the_request_unanswered() {
        for (upgrade, headers, why) in [
            (
                &b""[..],
                &[][..],
                RespondError::Header(HeaderRefused::Value),
            ),
            (
                b"x\r\nInjected: 1",
                &[],
                RespondError::Header(HeaderRefused::Value),
            ),
            (
                b"x",
                &[(&b"Connection"[..], &b"close"[..])],
                RespondError::Header(HeaderRefused::Reserved),
            ),
            (
                b"x",
                &[(b"a b", b"1")],
                RespondError::Header(HeaderRefused::Name),
            ),
            (b"x", &[(b"a", &[b'v'; MIN_OUT][..])], RespondError::TooLong),
        ] {
            let mut s = server_with(MIN_OUT, UPGRADE);
            assert_eq!(s.switch(T0, upgrade, headers), Err(why));
            assert!(s.is_awaiting_answer());
            assert!(!s.wants_write());
        }
    }

    #[test]
    fn a_101_that_does_not_go_by_its_deadline_is_aborted() {
        let mut s = server();
        s.rx(T0, UPGRADE);
        s.switch(T0, b"x", &[]).unwrap();
        let until = s.next_deadline().unwrap();
        s.deadline_passed(until);
        assert_eq!(s.close(), Some(Close::Abort));
    }

    #[test]
    fn the_storage_comes_back() {
        let mut s = Server::new(
            Storage {
                table: [7u8; 512],
                out: [0u8; 512],
            },
            Config::default(),
            T0,
        )
        .unwrap();
        s.rx(T0, b"GET / HTTP/1.1\r\n\r\n");
        // the same storage, holding what the request's head was parsed into
        let storage: Storage<[u8; 512]> = s.into_storage();
        assert!(storage.table.windows(2).any(|w| w == b"/\0"));
    }

    #[test]
    fn a_request_awaits_its_answer_until_it_has_one() {
        let mut s = server();
        assert!(!s.is_awaiting_answer());
        s.rx(T0, b"GET / HTTP/1.1\r\n\r\n");
        assert!(s.is_awaiting_answer());
        s.respond(OK2).unwrap();
        assert!(!s.is_awaiting_answer());
    }

    #[test]
    fn the_transaction_settled_is_taken_once_with_what_it_was_answered() {
        let mut s = server_out(MIN_OUT);
        assert_eq!(s.version(), Version::Http11);
        assert_eq!((s.answered(), s.take_settled()), (None, None));
        s.status(T0, 404, &[]).unwrap();
        assert_eq!(s.answered(), Some(404));
        // not over until the page has gone to the connection
        assert_eq!(s.take_settled(), None);
        let mut out = [0u8; 512];
        assert!(!s.tx(T0, &mut out, &mut NoPayload).more);
        assert_eq!(s.take_settled(), Some(Settled { status: Some(404) }));
        assert_eq!(s.take_settled(), None);
        // the next request starts unanswered
        assert_eq!(
            s.rx(T0, b"GET /2 HTTP/1.1\r\nHost: x\r\n\r\n").event,
            Some(Event::Request)
        );
        assert_eq!(s.answered(), None);
        // an answer with payload is over once the application completes
        // it and the last of it has gone
        s.respond(OK2).unwrap();
        assert_eq!(s.answered(), Some(200));
        assert!(!s.tx(T0, &mut out, &mut Text(b"ok")).more);
        assert_eq!(s.take_settled(), None);
        s.complete(T0);
        assert_eq!(s.take_settled(), Some(Settled { status: Some(200) }));
        // completed with no answer: closed, and over, unanswered
        assert_eq!(
            s.rx(T0, b"GET /3 HTTP/1.1\r\nHost: x\r\n\r\n").event,
            Some(Event::Request)
        );
        s.complete(T0);
        assert_eq!(s.take_settled(), Some(Settled { status: None }));
        assert_eq!(s.close(), Some(Close::Shutdown));
    }

    #[test]
    fn an_upgrade_agreed_is_not_settled_and_one_refused_is() {
        const ASKING: &[u8] =
            b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";
        let mut s = server_with(MIN_OUT, ASKING);
        s.switch(T0, b"websocket", &[]).unwrap();
        assert_eq!(s.answered(), Some(101));
        let mut out = [0u8; 512];
        assert!(!s.tx(T0, &mut out, &mut NoPayload).more);
        assert!(s.is_switched());
        // the connection goes on as ws: its end is the connection's
        assert_eq!(s.take_settled(), None);
        let mut r = server_with(MIN_OUT, ASKING);
        r.refuse_upgrade(T0, 426, None).unwrap();
        assert_eq!(r.answered(), Some(426));
        assert_eq!(r.take_settled(), None);
        assert!(!r.tx(T0, &mut out, &mut NoPayload).more);
        assert_eq!(r.take_settled(), Some(Settled { status: Some(426) }));
    }
}
