//! What a stream is told, and the handles some events lend to answer them.
//!
//! [`crate::ss::Ss::poll_event`] gives one [`Event`] at a time: which
//! stream, its `&mut U`, and what happened.  An event may lend a handle
//! to act on it there and then: a request's [`Txn`] to read the request
//! and answer it, or a [`Tx`] to fill with payload.  Anything else is a
//! call made on the [`crate::ss::Ss`] after the event.

use core::net::SocketAddr;
use core::time::Duration;

use npro_core::random::Random;
use npro_core::time::Instant;
use npro_h1::client::Client;
use npro_h1::head::Version;
use npro_h1::server::{self, Response as H1Response, Server, TxSource};
use npro_h1::table::{Fragments, HeaderTable};
use npro_h1::token::{Lookup, Token, lookup};
use npro_io::conn::RoleMut;
use npro_io::driver::Driver;
use npro_io::tls::RecordLayer;
use npro_ws::conn::Kind as WsKind;

use crate::id::StreamId;
use crate::policy::{Listener, Payload, Route, Vhost};

/// Something that happened to a stream.
#[derive(Debug)]
pub struct Event<'a, U, S, R, T> {
    /// The stream.
    pub stream: StreamId,
    /// The stream's own state, given when it was made.
    pub user: &'a mut U,
    /// What happened.
    pub kind: Kind<'a, S, R, T>,
}

/// What happened to a stream.
#[derive(Debug)]
pub enum Kind<'a, S, R, T> {
    /// A request's head is in, C's `SERVER_TXN`: read it, and answer it,
    /// through the [`Txn`].
    ServerTxn(Txn<'a, S>),
    /// The request became ws, with this subprotocol, C's
    /// `SERVER_UPGRADE`: from here the stream's payload is messages.
    ServerUpgrade {
        /// The subprotocol agreed, of the route's.
        protocol: &'a [u8],
        /// The route it was on, whose `to` says what serves it.
        route: &'a Route<'a>,
    },
    /// The request asked for ws, and was refused as C refuses it: the
    /// connection closes once the refusal has gone.
    UpgradeRefused(Refusal),
    /// The request's transaction is over: what it was answered with, and
    /// what that took.  Told once for every request told, as
    /// [`Kind::ServerTxn`], [`Kind::ServerUpgrade`] or
    /// [`Kind::UpgradeRefused`]: when its answer has been handed to the
    /// connection whole, or, if the connection goes first, or carried
    /// ws from it, before [`Kind::Disconnected`].  For the access log,
    /// whose line is written at C's `lws_http_transaction_completed()`
    /// ([`crate::access`]).
    ServerTxnEnd(Ended),
    /// A stream that connected out has its answer's head, C's
    /// `ESTABLISHED_CLIENT_HTTP`, and so is connected, as the peer has
    /// agreed: read it through the [`Resp`].  Its body follows as
    /// [`Kind::Rx`].
    Response(Resp<'a, S>),
    /// A stream that connected out could not be: the address did not
    /// resolve, the connect was refused, or its tls could not be made.
    /// The stream is gone, as after [`Kind::Disconnected`].
    ConnectFailed,
    /// The peer's payload: a piece of a request's body, or of a ws
    /// message.
    Rx {
        /// The piece.
        data: &'a [u8],
        /// Whether it ends the body or the message.
        end: End,
    },
    /// The stream asked to write, and can: fill the [`Tx`].
    Tx(Tx<'a, S, R, T>),
    /// A pong came, for a ping npro sent.
    Pong,
    /// The peer closed: the stream is told [`Kind::Disconnected`] once the
    /// connection is done with.
    PeerClose {
        /// The ws close's status code, if it gave one.
        code: Option<u16>,
    },
    /// The stream's connection is gone, and so is the stream: its id is
    /// refused from here, and its `U` dropped before the next event.
    Disconnected,
}

/// A transaction over: [`Kind::ServerTxnEnd`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended {
    /// The status it was answered with, the last status line composed
    /// for it, 101 for ws agreed; or `None` if its connection went
    /// unanswered.  C's `access_log.response`, which is 0 then.
    pub status: Option<u16>,
    /// How many bytes the connection wrote from the request's head to
    /// the end: the answer's head and payload, the plaintext before any
    /// tls; for ws, the 101 and every frame.  C's `access_log.sent`.
    pub sent: u64,
}

/// Whether what a stream's peer sends is given to it: [`crate::ss::Ss::flow`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// It is, as it comes.
    Given,
    /// It waits in the connection's buffer, and the peer is held back
    /// once that is full.
    Held,
}

/// A response's head, in hand: [`Kind::Response`].
#[derive(Debug)]
pub struct Resp<'a, S> {
    pub(crate) client: &'a Client<S>,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Resp<'_, S> {
    /// The status.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.client.status().unwrap_or(0)
    }

    /// The value of the response's header `name`, any case, without its
    /// `:`, as [`Txn::header`] finds a request's: the first, of one that
    /// came more than once.
    #[must_use]
    pub fn header(&self, name: &[u8]) -> Option<&[u8]> {
        header(self.client.response(), name)
    }

    /// Every value of the response's header `name`, in order, for one
    /// that may come more than once, `set-cookie` say: each, for a
    /// header npro knows by name, without the SP the parser keeps to
    /// join it to the one before; the first alone for any other.
    #[must_use]
    pub fn values(&self, name: &[u8]) -> Values<'_> {
        let t = self.client.response();
        let mut key = [0u8; MAX_NAME];
        let known = name
            .len()
            .checked_add(1)
            .and_then(|len| key.get_mut(..len))
            .and_then(|key| {
                let (body, colon) = key.split_at_mut(name.len());
                body.copy_from_slice(name);
                body.make_ascii_lowercase();
                colon.copy_from_slice(b":");
                match lookup(key) {
                    Lookup::Matched(tok) => Some(tok),
                    Lookup::Prefix | Lookup::Nothing => None,
                }
            });
        match known {
            Some(tok) => Values::Each(t.fragments(tok)),
            None => Values::One(self.header(name)),
        }
    }
}

/// The values of a header: [`Resp::values`].
#[derive(Debug)]
pub enum Values<'a> {
    /// Each, of a header npro knows by name.
    Each(Fragments<'a>),
    /// The first alone, of any other.
    One(Option<&'a [u8]>),
}

impl<'a> Iterator for Values<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        match self {
            Self::Each(f) => f.next().map(|v| v.strip_prefix(b" ").unwrap_or(v)),
            Self::One(v) => v.take(),
        }
    }
}

/// The value of the header `name` in `t`, as [`Txn::header`] finds it.
fn header<'t, S: AsRef<[u8]> + AsMut<[u8]>>(
    t: &'t HeaderTable<S>,
    name: &[u8],
) -> Option<&'t [u8]> {
    let mut key = [0u8; MAX_NAME];
    let len = name.len().checked_add(1)?;
    let key = key.get_mut(..len)?;
    let (body, colon) = key.split_at_mut(name.len());
    body.copy_from_slice(name);
    body.make_ascii_lowercase();
    colon.copy_from_slice(b":");
    match lookup(key) {
        Lookup::Matched(tok) => t.first(tok),
        Lookup::Prefix | Lookup::Nothing => t.unknown(key),
    }
}

/// Whether a piece of payload ends what it is a piece of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// More of it follows.
    More,
    /// It is the last of the body or message.
    Last,
}

/// Why an upgrade to ws was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// It was answered with this status, as C answers it.
    Status(u16),
    /// The connection was dropped, as C drops it: an extension offer too
    /// long, or a 101 that would not fit.
    Dropped,
}

/// The most headers a response carries, the vhost's, the route's and the
/// application's together.
pub const MAX_HEADERS: usize = 64;

/// An answer to a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response<'a> {
    /// The status.
    pub status: u16,
    /// Its `content-type`, if it has payload.
    pub content_type: Option<&'a [u8]>,
    /// How long its payload is, or `None` for as long as it goes on, which
    /// the connection's close ends.
    pub content_length: Option<u64>,
    /// The application's own headers, after the vhost's and the route's.
    /// The ones the connection writes itself (its framing, `connection`,
    /// `upgrade`) are refused.
    pub headers: &'a [(&'a [u8], &'a [u8])],
}

/// Why a response was refused.  The request is still unanswered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RespondError {
    /// The stream is gone, or is not one a response is made on.
    Gone,
    /// More than [`MAX_HEADERS`], the vhost's, the route's and the
    /// application's.
    TooManyHeaders,
    /// As the connection refused it.
    Refused(server::RespondError),
}

impl core::fmt::Display for RespondError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Gone => f.write_str("no such stream, or not a server's"),
            Self::TooManyHeaders => write!(f, "more than {MAX_HEADERS} headers"),
            Self::Refused(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for RespondError {}

/// A request in hand: [`Kind::ServerTxn`].
#[derive(Debug)]
pub struct Txn<'a, S> {
    pub(crate) server: &'a mut Server<S>,
    pub(crate) listener: &'a Listener<'a>,
    /// The vhost, among the listener's.
    pub(crate) vhost: usize,
    /// The route the request's path matched, among the vhost's, and how
    /// much of the path that was.
    pub(crate) route: Option<(usize, usize)>,
    pub(crate) now: Instant,
    /// Where the connection was accepted from, if it has an address.
    pub(crate) peer: Option<SocketAddr>,
}

/// Where a request was routed: [`Txn::route`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Routed<'a> {
    /// The route, whose `to` says what serves it.
    pub route: &'a Route<'a>,
    /// Its place among the vhost's.
    pub index: usize,
    /// The rest of the path under the route's, without the `/` between:
    /// `a/b` for `/x/a/b` on `/x`.  Decoded and made safe as
    /// [`Txn::path`] is.
    pub rest: &'a [u8],
}

/// The request methods, each with the token holding its target.
const METHODS: [(Token, &[u8]); 8] = [
    (Token::GetUri, b"GET"),
    (Token::PostUri, b"POST"),
    (Token::OptionsUri, b"OPTIONS"),
    (Token::PutUri, b"PUT"),
    (Token::PatchUri, b"PATCH"),
    (Token::DeleteUri, b"DELETE"),
    (Token::Connect, b"CONNECT"),
    (Token::HeadUri, b"HEAD"),
];

/// The longest header name looked up.
const MAX_NAME: usize = 64;

impl<'a, S: AsRef<[u8]> + AsMut<[u8]>> Txn<'a, S> {
    const fn table(&self) -> &HeaderTable<S> {
        self.server.request()
    }

    fn method_token(&self) -> Option<(Token, &'static [u8])> {
        METHODS
            .iter()
            .copied()
            .find(|(t, _)| self.table().is_present(*t))
    }

    /// The request's method, uppercase.
    #[must_use]
    pub fn method(&self) -> Option<&'static [u8]> {
        self.method_token().map(|(_, m)| m)
    }

    /// The request's path, decoded and made safe as the parser does
    /// (`//`, `/./` and `/../` taken out, never above the root), without
    /// its arguments; for `CONNECT`, the authority.
    #[must_use]
    pub fn path(&self) -> Option<&[u8]> {
        request_path(self.table())
    }

    /// The listener the request came in on.
    #[must_use]
    pub const fn listener(&self) -> &'a Listener<'a> {
        self.listener
    }

    /// The address the connection was accepted from, if it has one: a
    /// unix domain socket's has none.  C's `lws_get_peer_simple()`.
    #[must_use]
    pub const fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// The version the request asked in.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.server.version()
    }

    /// The stream may take `d` from now to begin its answer, instead of
    /// the connection's content timeout: for a script spawned to answer,
    /// C's `cgi-timeout`.
    pub fn answer_within(&mut self, d: Duration) {
        self.server.answer_within(self.now, d);
    }

    /// The vhost the request is for: the one its `Host` named, or the
    /// listener's first.
    #[must_use]
    pub fn vhost(&self) -> &'a Vhost<'a> {
        // checked by Ss::new: a listener has a vhost, and the first is
        // the fallback
        self.listener
            .vhosts
            .get(self.vhost)
            .or(self.listener.vhosts.first())
            .unwrap_or(&NO_VHOST)
    }

    /// The route the request's path matched, of the vhost's, or `None`
    /// if none did: C's `lws_find_mount()`.  Then nothing serves it, and
    /// the stream answers as it chooses, [`Txn::status`] with 404 say.
    #[must_use]
    pub fn route(&self) -> Option<Routed<'_>> {
        let (index, len) = self.route?;
        let route = self.vhost().routes.get(index)?;
        let rest = self.path()?.get(len..).unwrap_or_default();
        Some(Routed {
            route,
            index,
            rest: rest.strip_prefix(b"/").unwrap_or(rest),
        })
    }

    /// The request's arguments, each decoded, in order: the query split at
    /// `&`.
    #[must_use]
    pub fn args(&self) -> Fragments<'_> {
        self.table().fragments(Token::UriArgs)
    }

    /// The value of the request's header `name`, any case, without its
    /// `:`.  A header that came more than once gives its first; one that
    /// npro knows by name is found as C's lextable finds it, any other
    /// as C's custom headers are.
    #[must_use]
    pub fn header(&self, name: &[u8]) -> Option<&[u8]> {
        header(self.table(), name)
    }

    /// Answers the request: the vhost's headers, then the route's, then
    /// the application's.  Its payload, if it has any, is the stream's to
    /// give when it is asked ([`Kind::Tx`]), the last of it saying so.
    /// A stream that answers later, once it has the body, say, does so
    /// with [`crate::ss::Ss::respond`].
    ///
    /// # Errors
    ///
    /// [`RespondError`], and the request is still unanswered.
    pub fn respond(&mut self, r: Response<'_>) -> Result<(), RespondError> {
        respond(self.server, self.own_headers(), r)
    }

    /// Answers the request with C's status page for `code`, under the
    /// vhost's and the route's headers, and is done with it: what
    /// `lws_return_http_status()` answers for a request nothing serves,
    /// the connection kept for the next.  A HEAD gets the page's head
    /// alone.  A 404 on a vhost with a [`Vhost::not_found`] document is
    /// a redirect to it instead, as C's is, unless the request was for
    /// the document itself.
    ///
    /// # Errors
    ///
    /// [`RespondError`], and the request is still unanswered.
    pub fn status(&mut self, code: u16) -> Result<(), RespondError> {
        if code == 404 {
            if let Some(doc) = self.vhost().not_found {
                let is_doc = self.path().is_some_and(|p| {
                    p.strip_prefix(b"/").unwrap_or(p)
                        == doc.as_bytes().strip_prefix(b"/").unwrap_or(doc.as_bytes())
                });
                if !is_doc {
                    return self.redirect(302, doc.as_bytes());
                }
            }
        }
        let own = self.own_headers();
        let mut all: [(&[u8], &[u8]); MAX_HEADERS] = [(&[], &[]); MAX_HEADERS];
        let n = gather(&mut all, own, &[])?;
        self.server
            .status(self.now, code, all.get(..n).unwrap_or_default())
            .map_err(RespondError::Refused)
    }

    /// Answers the request with a redirect to `location`, with `code`
    /// (301, 302, 307, 308), as C's `lws_http_redirect()` composes it,
    /// under the vhost's and the route's headers, and is done with it.
    ///
    /// # Errors
    ///
    /// [`RespondError`], and the request is still unanswered.
    pub fn redirect(&mut self, code: u16, location: &[u8]) -> Result<(), RespondError> {
        let own = self.own_headers();
        let mut all: [(&[u8], &[u8]); MAX_HEADERS] = [(&[], &[]); MAX_HEADERS];
        let n = gather(&mut all, own, &[])?;
        self.server
            .redirect(self.now, code, location, all.get(..n).unwrap_or_default())
            .map_err(RespondError::Refused)
    }

    /// The vhost's headers and the route's.
    fn own_headers(&self) -> Own<'a> {
        let vhost = self.vhost();
        Own {
            vhost: vhost.headers,
            route: self
                .route
                .and_then(|(i, _)| vhost.routes.get(i))
                .map_or(&[][..], |r| r.headers),
        }
    }
}

/// A vhost for a listener that has none, which [`crate::ss::Ss::new`]
/// refuses: never served.
static NO_VHOST: Vhost<'static> = Vhost {
    name: "",
    routes: &[],
    headers: &[],
    not_found: None,
};

/// The headers a response carries before the application's.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Own<'a> {
    pub(crate) vhost: &'a [(&'a [u8], &'a [u8])],
    pub(crate) route: &'a [(&'a [u8], &'a [u8])],
}

/// The request's path, as [`Txn::path`] gives it.
pub(crate) fn request_path<S: AsRef<[u8]> + AsMut<[u8]>>(t: &HeaderTable<S>) -> Option<&[u8]> {
    let (tok, _) = METHODS.iter().copied().find(|(t_, _)| t.is_present(*t_))?;
    t.first(tok)
}

/// Fills `all` with `own`'s headers then `app`'s: how many.
fn gather<'a>(
    all: &mut [(&'a [u8], &'a [u8]); MAX_HEADERS],
    own: Own<'a>,
    app: &'a [(&'a [u8], &'a [u8])],
) -> Result<usize, RespondError> {
    let n = own
        .vhost
        .len()
        .checked_add(own.route.len())
        .and_then(|n| n.checked_add(app.len()))
        .filter(|n| *n <= MAX_HEADERS)
        .ok_or(RespondError::TooManyHeaders)?;
    let each = own.vhost.iter().chain(own.route).chain(app);
    for (slot, h) in all.iter_mut().zip(each) {
        *slot = *h;
    }
    Ok(n)
}

/// Answers `server`'s request with `r`, after its `own` headers.
pub(crate) fn respond<S: AsRef<[u8]> + AsMut<[u8]>>(
    server: &mut Server<S>,
    own: Own<'_>,
    r: Response<'_>,
) -> Result<(), RespondError> {
    let mut all: [(&[u8], &[u8]); MAX_HEADERS] = [(&[], &[]); MAX_HEADERS];
    let n = gather(&mut all, own, r.headers)?;
    server
        .respond(H1Response {
            status: r.status,
            content_type: r.content_type,
            content_length: r.content_length,
            headers: all.get(..n).unwrap_or_default(),
        })
        .map_err(RespondError::Refused)
}

/// How much of its payload a stream gave, and whether that was the last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filled {
    /// This much, and more is to come.
    More(usize),
    /// This much, and it is the last: the response's payload is over.
    Last(usize),
}

/// What a stream wants to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxWant {
    /// Nothing.
    Idle,
    /// Payload: the response's, or the ws message's going.
    Wanted,
    /// A ws message this long, to start once the one going is done.
    Message(u64),
}

/// A stream's chance to write: [`Kind::Tx`].
#[derive(Debug)]
pub struct Tx<'a, S, R, T> {
    pub(crate) driver: &'a mut Driver<S, R, S, T>,
    pub(crate) want: &'a mut TxWant,
    pub(crate) payload: Payload,
    pub(crate) now: Instant,
}

/// The stream's payload, pulled by the connection through `f`.
struct Pull<F> {
    f: F,
    /// The connection asked.
    asked: bool,
    /// The stream said it gave the last.
    last: bool,
    total: usize,
}

impl<F: FnMut(&mut [u8]) -> Filled> TxSource for Pull<F> {
    fn fill(&mut self, buf: &mut [u8]) -> usize {
        self.asked = true;
        if self.last {
            return 0;
        }
        let n = match (self.f)(buf) {
            Filled::More(n) => n,
            Filled::Last(n) => {
                self.last = true;
                n
            }
        }
        .min(buf.len());
        self.total = self.total.saturating_add(n);
        n
    }
}

impl<S, R, T> Tx<'_, S, R, T>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
    T: RecordLayer,
{
    /// Fills what the connection has room for from `f`, which is given
    /// the room, as often as the connection takes more now, and says how
    /// much of it it filled and whether that was the last.  Returns how
    /// much it gave in all.
    ///
    /// What the connection owes of its own (a response's head) goes
    /// first, then the payload.  The last of a response's payload ends its
    /// transaction.  Giving nothing, or the connection taking no payload
    /// now (a response not yet made, a connection closing), ends the
    /// stream's asking to write: it asks again when it has more.
    pub fn fill(self, f: impl FnMut(&mut [u8]) -> Filled) -> usize {
        let Self {
            driver,
            want,
            payload,
            now,
        } = self;
        if let TxWant::Message(len) = *want {
            if let RoleMut::WsServer(ws) = driver.conn().role_mut() {
                let kind = match payload {
                    Payload::Text => WsKind::Text,
                    Payload::Binary => WsKind::Binary,
                };
                // busy with the one going: it goes on, this one waits
                if ws.send(kind, len).is_ok() {
                    *want = TxWant::Wanted;
                }
            }
        }
        let mut pull = Pull {
            f,
            asked: false,
            last: false,
            total: 0,
        };
        driver.request_write();
        // what it wants of the adapter is the adapter's to ask
        let _ = driver.want(now, &mut pull);
        if pull.last {
            if let RoleMut::H1Server(s) = driver.conn().role_mut() {
                s.complete(now);
            }
            *want = TxWant::Idle;
        } else if pull.asked && pull.total == 0 {
            // it had nothing
            *want = TxWant::Idle;
        } else if !pull.asked && !driver.conn().wants_write() {
            // the connection takes no payload now
            *want = TxWant::Idle;
        }
        // otherwise it gave some, or the connection's own bytes went first
        // and filled the room: it is asked again once there is more
        pull.total
    }
}
