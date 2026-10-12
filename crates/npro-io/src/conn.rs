//! The connection the driver carries, whichever its role.
//!
//! A [`Conn`] is one of the roles the protocol crates have: an h1 server or
//! client ([`npro_h1::server::Server`], [`npro_h1::client::Client`]), ws
//! at either end ([`npro_ws::conn::Ws`]), or raw bytes
//! ([`crate::raw::Raw`]).  It answers what the driver asks
//! of any connection, whatever its role: take these bytes ([`Conn::rx`]),
//! write into this buffer ([`Conn::tx`]), the peer closed
//! ([`Conn::rx_closed`]), what do you want ([`Conn::wants_write`],
//! [`Conn::close`]), and when do you next need the time
//! ([`Conn::next_deadline`]).  Each is one `match` over the roles.
//!
//! The role changes as C's does, h1 to ws, only through
//! [`Conn::accept_ws`] and [`Conn::upgraded_ws`], or h1 to raw through
//! [`Conn::switch_raw`], which check the h1 role is where the change may
//! happen, and give back its storage: as C drops a connection's ah when the user returns from
//! ESTABLISHED, the h1 role's request or response event is the last time
//! its headers are seen.  Bytes after the h1 head were never taken by the
//! h1 role, so they are the new role's.
//!
//! The application acts on the role through [`Conn::role`] and
//! [`Conn::role_mut`], views that borrow it: it can answer, send and close
//! as the role allows, but not put a different role in its place.

use npro_core::close::Close;
use npro_core::random::Random;
use npro_core::time::Instant;
use npro_h1::Storage;
use npro_h1::client::{self, Client};
use npro_h1::server::{self, Server, TxSource};
use npro_ws::conn::{self as ws, AsClient, AsServer, Ws};

use crate::raw::{self, Raw};

/// The role a connection has now.
#[derive(Clone, Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "a connection is one value, the size of its largest role: boxing the large ones needs alloc, which a device without one lacks"
)]
enum Inner<S, R> {
    H1Server(Server<S>),
    H1Client(Client<S>),
    WsServer(Ws<AsServer>),
    WsClient(Ws<AsClient<R>>),
    Raw(Raw),
}

/// One connection, whichever its role, `S` the storage of an h1 role's
/// header table, and `R` a ws client's random source.
///
/// A server's connection begins h1, and becomes ws when the application
/// accepts a request's upgrade:
///
/// ```
/// use npro_core::random::SeededRandom;
/// use npro_core::time::Instant;
/// use npro_h1::Storage;
/// use npro_h1::server::{Config, Server};
/// use npro_io::conn::{Conn, Event, Role};
/// use npro_ws::conn::Ws;
/// use npro_ws::handshake::{self, MAX_101};
///
/// let now = Instant::from_micros(1_000_000);
/// let server = Server::new(Storage { table: [0u8; 1024], out: [0u8; 1024] }, Config::default(), now)?;
/// // a server's connection: the random is a ws client's, unused here
/// let mut conn: Conn<_, SeededRandom> = Conn::h1_server(server);
///
/// let mut input = *b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
///                    Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
///                    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
/// let len = input.len();
/// let rx = conn.rx(now, &mut input, &mut []);
/// assert_eq!(rx.consumed, len);
/// assert!(matches!(rx.event, Some(Event::H1Server(_))));
///
/// // the application accepts the upgrade: the 101, then the connection is ws
/// let Role::H1Server(s) = conn.role() else { unreachable!() };
/// let a = handshake::server(s.request(), &[b"chat"], Some(0)).unwrap();
/// let mut first = [0u8; MAX_101];
/// let n = handshake::response_101(&a, b"chat", b"", &mut first).unwrap();
/// let storage = conn.accept_ws(Ws::server(&first[..n], now))?;
/// assert_eq!((storage.table.len(), storage.out.len()), (1024, 1024));
/// assert!(matches!(conn.role(), Role::WsServer(_)));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Conn<S, R> {
    inner: Inner<S, R>,
}

/// What the peer's bytes were: the role's event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// An h1 server's: a request's head, a piece of its body, or its end.
    H1Server(server::Event<'a>),
    /// An h1 client's: the response's head, a piece of its body, or its
    /// end.
    H1Client(client::Event<'a>),
    /// ws, either end's: a piece of a message, a pong, or the peer's
    /// close.
    Ws(ws::Event<'a>),
    /// Raw: bytes as they came, or the peer's close.
    Raw(raw::Event<'a>),
}

/// What [`Conn::rx`] took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rx<'a> {
    /// How many bytes it took.  The rest are the caller's to hand in again.
    pub consumed: usize,
    /// What they were, if they came to something.  It borrows the input
    /// and the inflate buffer, not the connection.
    pub event: Option<Event<'a>>,
}

/// The connection's role, borrowed to look at: [`Conn::role`].
#[derive(Debug)]
pub enum Role<'c, S, R> {
    /// An h1 server.
    H1Server(&'c Server<S>),
    /// An h1 client.
    H1Client(&'c Client<S>),
    /// A ws server.
    WsServer(&'c Ws<AsServer>),
    /// A ws client.
    WsClient(&'c Ws<AsClient<R>>),
    /// Raw.
    Raw(&'c Raw),
}

/// The connection's role, borrowed to act on: [`Conn::role_mut`].
#[derive(Debug)]
pub enum RoleMut<'c, S, R> {
    /// An h1 server: to answer, refuse an upgrade, complete.
    H1Server(&'c mut Server<S>),
    /// An h1 client.
    H1Client(&'c mut Client<S>),
    /// A ws server: to send, close when flushed.
    WsServer(&'c mut Ws<AsServer>),
    /// A ws client.
    WsClient(&'c mut Ws<AsClient<R>>),
    /// Raw: to close.
    Raw(&'c mut Raw),
}

/// A role change asked for where it cannot happen: the connection is not
/// the h1 role it changes from, or that role is not at the point of the
/// change.  The connection is as it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotNow;

impl core::fmt::Display for NotNow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the connection's role cannot change now")
    }
}

impl core::error::Error for NotNow {}

impl<S, R> Conn<S, R> {
    /// An h1 server's connection.
    #[must_use]
    pub const fn h1_server(s: Server<S>) -> Self {
        Self {
            inner: Inner::H1Server(s),
        }
    }

    /// An h1 client's connection.
    #[must_use]
    pub const fn h1_client(c: Client<S>) -> Self {
        Self {
            inner: Inner::H1Client(c),
        }
    }

    /// A ws server's connection from its start, its handshake done
    /// elsewhere.
    #[must_use]
    pub const fn ws_server(ws: Ws<AsServer>) -> Self {
        Self {
            inner: Inner::WsServer(ws),
        }
    }

    /// A ws client's connection from its start, its handshake done
    /// elsewhere.
    #[must_use]
    pub const fn ws_client(ws: Ws<AsClient<R>>) -> Self {
        Self {
            inner: Inner::WsClient(ws),
        }
    }

    /// The connection done with, its h1 role's storage back, as
    /// [`Server::into_storage`] gives it; `None` once the role changed,
    /// since the change gave it back then.
    ///
    /// ```
    /// use npro_core::random::SeededRandom;
    /// use npro_core::time::Instant;
    /// use npro_h1::Storage;
    /// use npro_h1::server::{Config, Server};
    /// use npro_io::conn::Conn;
    ///
    /// let now = Instant::from_micros(1_000_000);
    /// let s = Server::new(Storage { table: [0u8; 1024], out: [0u8; 1024] }, Config::default(), now)?;
    /// let conn: Conn<_, SeededRandom> = Conn::h1_server(s);
    /// assert!(conn.into_storage().is_some());
    /// # Ok::<(), Box<dyn core::error::Error>>(())
    /// ```
    #[must_use]
    pub fn into_storage(self) -> Option<Storage<S>>
    where
        S: AsRef<[u8]> + AsMut<[u8]>,
    {
        match self.inner {
            Inner::H1Server(s) => Some(s.into_storage()),
            Inner::H1Client(c) => Some(c.into_storage()),
            Inner::WsServer(_) | Inner::WsClient(_) | Inner::Raw(_) => None,
        }
    }

    /// The role, to look at.
    #[must_use]
    pub const fn role(&self) -> Role<'_, S, R> {
        match &self.inner {
            Inner::H1Server(s) => Role::H1Server(s),
            Inner::H1Client(c) => Role::H1Client(c),
            Inner::WsServer(w) => Role::WsServer(w),
            Inner::WsClient(w) => Role::WsClient(w),
            Inner::Raw(r) => Role::Raw(r),
        }
    }

    /// The role, to act on.
    #[must_use]
    pub const fn role_mut(&mut self) -> RoleMut<'_, S, R> {
        match &mut self.inner {
            Inner::H1Server(s) => RoleMut::H1Server(s),
            Inner::H1Client(c) => RoleMut::H1Client(c),
            Inner::WsServer(w) => RoleMut::WsServer(w),
            Inner::WsClient(w) => RoleMut::WsClient(w),
            Inner::Raw(r) => RoleMut::Raw(r),
        }
    }
}

impl<S: AsRef<[u8]> + AsMut<[u8]>, R: Random> Conn<S, R> {
    /// Whether [`Conn::rx`] has more to give without more input: the end
    /// of an h1 body that came with the bytes already taken, or a ws
    /// message deflated, inflating to more than one call gives.
    #[must_use]
    pub fn rx_pending(&self) -> bool {
        match &self.inner {
            Inner::H1Server(s) => s.rx_pending(),
            Inner::H1Client(c) => c.rx_pending(),
            Inner::WsServer(w) => w.rx_pending(),
            Inner::WsClient(w) => w.rx_pending(),
            Inner::Raw(_) => false,
        }
    }

    /// Whether the connection has something of its own to write.  What
    /// the application has is the driver's to know.
    #[must_use]
    pub const fn wants_write(&self) -> bool {
        match &self.inner {
            Inner::H1Server(s) => s.wants_write(),
            Inner::H1Client(c) => c.wants_write(),
            Inner::WsServer(w) => w.wants_write(),
            Inner::WsClient(w) => w.wants_write(),
            Inner::Raw(_) => false,
        }
    }

    /// What the connection asks of whatever carries it, once it is done
    /// with.
    #[must_use]
    pub const fn close(&self) -> Option<Close> {
        match &self.inner {
            Inner::H1Server(s) => s.close(),
            Inner::H1Client(c) => c.close(),
            Inner::WsServer(w) => w.close(),
            Inner::WsClient(w) => w.close(),
            Inner::Raw(r) => r.closing(),
        }
    }

    /// When the connection next needs [`Conn::deadline_passed`].
    #[must_use]
    pub const fn next_deadline(&self) -> Option<Instant> {
        match &self.inner {
            Inner::H1Server(s) => s.next_deadline(),
            Inner::H1Client(c) => c.next_deadline(),
            Inner::WsServer(w) => w.next_deadline(),
            Inner::WsClient(w) => w.next_deadline(),
            Inner::Raw(_) => None,
        }
    }

    /// Takes bytes from the peer at `now`.  A ws payload is unmasked where
    /// it lies in `input`, and a deflated message inflated into `out`,
    /// which with permessage-deflate must not be empty
    /// ([`npro_ws::conn::Ws::rx`]); the h1 roles leave both as they are.
    ///
    /// An h1 client's failure takes nothing and gives nothing: it is in
    /// [`Conn::close`], which asks for [`Close::Abort`], and the client's
    /// own `failed()`.
    pub fn rx<'a>(&mut self, now: Instant, input: &'a mut [u8], out: &'a mut [u8]) -> Rx<'a> {
        match &mut self.inner {
            Inner::H1Server(s) => {
                let r = s.rx(now, input);
                Rx {
                    consumed: r.consumed,
                    event: r.event.map(Event::H1Server),
                }
            }
            Inner::H1Client(c) => match c.rx(now, input) {
                Ok(r) => Rx {
                    consumed: r.consumed,
                    event: r.event.map(Event::H1Client),
                },
                Err(_) => Rx {
                    consumed: 0,
                    event: None,
                },
            },
            Inner::WsServer(w) => {
                let r = w.rx(now, input, out);
                Rx {
                    consumed: r.consumed,
                    event: r.event.map(Event::Ws),
                }
            }
            Inner::WsClient(w) => {
                let r = w.rx(now, input, out);
                Rx {
                    consumed: r.consumed,
                    event: r.event.map(Event::Ws),
                }
            }
            Inner::Raw(r) => {
                let (consumed, event) = r.rx(input);
                Rx {
                    consumed,
                    event: event.map(Event::Raw),
                }
            }
        }
    }

    /// The peer closed its side, at `now`, after everything it sent was
    /// taken.  An h1 client whose response body runs to the close is given
    /// its end; any other role closes as it does.
    pub fn rx_closed(&mut self, now: Instant) -> Option<Event<'static>> {
        match &mut self.inner {
            Inner::H1Server(s) => {
                s.rx_closed();
                None
            }
            Inner::H1Client(c) => c.rx_closed().ok().flatten().map(Event::H1Client),
            Inner::WsServer(w) => {
                w.rx_closed(now);
                None
            }
            Inner::WsClient(w) => {
                w.rx_closed(now);
                None
            }
            Inner::Raw(r) => r.rx_closed().map(Event::Raw),
        }
    }

    /// Writes what is owed the peer into `out`, at `now`, the
    /// application's payload pulled from `src`, returning how much.
    pub fn tx(&mut self, now: Instant, out: &mut [u8], src: &mut dyn TxSource) -> usize {
        match &mut self.inner {
            Inner::H1Server(s) => s.tx(now, out, src).written,
            Inner::H1Client(c) => c.tx(now, out, src),
            Inner::WsServer(w) => w.tx(now, out, src),
            Inner::WsClient(w) => w.tx(now, out, src),
            Inner::Raw(r) => r.tx(out, src),
        }
    }

    /// Tells the connection it is `now`, which may be past its
    /// [`Conn::next_deadline`].
    pub fn deadline_passed(&mut self, now: Instant) {
        match &mut self.inner {
            Inner::H1Server(s) => s.deadline_passed(now),
            Inner::H1Client(c) => c.deadline_passed(now),
            Inner::WsServer(w) => w.deadline_passed(now),
            Inner::WsClient(w) => w.deadline_passed(now),
            // no deadline of its own
            Inner::Raw(_) => {}
        }
    }

    /// The h1 server's request in hand asked for ws, and the application
    /// takes it: the connection becomes `ws`, made with the 101 to go
    /// first and the extensions agreed.  The h1 role's storage comes
    /// back.
    ///
    /// # Errors
    ///
    /// [`NotNow`], and the connection is as it was, if it is not an h1
    /// server with a request awaiting its answer.
    pub fn accept_ws(&mut self, ws: Ws<AsServer>) -> Result<Storage<S>, NotNow> {
        match &self.inner {
            Inner::H1Server(s) if s.is_awaiting_answer() => {}
            Inner::H1Server(_)
            | Inner::H1Client(_)
            | Inner::WsServer(_)
            | Inner::WsClient(_)
            | Inner::Raw(_) => {
                return Err(NotNow);
            }
        }
        match core::mem::replace(&mut self.inner, Inner::WsServer(ws)) {
            Inner::H1Server(s) => Ok(s.into_storage()),
            // not so, as just seen: put it back
            was
            @ (Inner::H1Client(_) | Inner::WsServer(_) | Inner::WsClient(_) | Inner::Raw(_)) => {
                self.inner = was;
                Err(NotNow)
            }
        }
    }

    /// The h1 client's request for ws was answered with a final response,
    /// which the application checked
    /// ([`npro_ws::handshake::ClientKey::check`]): the connection becomes
    /// `ws`.  The h1 role's storage comes back.
    ///
    /// # Errors
    ///
    /// [`NotNow`], and the connection is as it was, if it is not an h1
    /// client whose request for an upgrade has had its final response.
    pub fn upgraded_ws(&mut self, ws: Ws<AsClient<R>>) -> Result<Storage<S>, NotNow> {
        match &self.inner {
            Inner::H1Client(c) if c.is_upgraded() => {}
            Inner::H1Server(_)
            | Inner::H1Client(_)
            | Inner::WsServer(_)
            | Inner::WsClient(_)
            | Inner::Raw(_) => {
                return Err(NotNow);
            }
        }
        match core::mem::replace(&mut self.inner, Inner::WsClient(ws)) {
            Inner::H1Client(c) => Ok(c.into_storage()),
            // not so, as just seen: put it back
            was
            @ (Inner::H1Server(_) | Inner::WsServer(_) | Inner::WsClient(_) | Inner::Raw(_)) => {
                self.inner = was;
                Err(NotNow)
            }
        }
    }

    /// Both ends agreed an upgrade to a protocol the application carries
    /// itself: the connection becomes [`Raw`], and the h1 role's storage
    /// comes back.  An h1 server's 101 has gone ([`Server::switch`],
    /// [`Server::is_switched`]), or an h1 client's request for an upgrade
    /// was answered 101.  Bytes after the h1 head were never taken by the
    /// h1 role, so they are the raw role's.
    ///
    /// # Errors
    ///
    /// [`NotNow`], and the connection is as it was, if it is neither.
    pub fn switch_raw(&mut self) -> Result<Storage<S>, NotNow> {
        match &self.inner {
            Inner::H1Server(s) if s.is_switched() => {}
            Inner::H1Client(c) if c.is_upgraded() && c.status() == Some(101) => {}
            Inner::H1Server(_)
            | Inner::H1Client(_)
            | Inner::WsServer(_)
            | Inner::WsClient(_)
            | Inner::Raw(_) => return Err(NotNow),
        }
        match core::mem::replace(&mut self.inner, Inner::Raw(Raw::new())) {
            Inner::H1Server(s) => Ok(s.into_storage()),
            Inner::H1Client(c) => Ok(c.into_storage()),
            // not so, as just seen: put it back
            was @ (Inner::WsServer(_) | Inner::WsClient(_) | Inner::Raw(_)) => {
                self.inner = was;
                Err(NotNow)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use npro_core::random::SeededRandom;
    use npro_h1::client::{Connection, Request, RequestBody, Scheme};
    use npro_h1::server::Config;

    const T0: Instant = Instant::from_micros(1_000_000);

    type ServerConn = Conn<[u8; 1024], SeededRandom>;

    fn server() -> ServerConn {
        Conn::h1_server(
            Server::new(
                Storage {
                    table: [0u8; 1024],
                    out: [0u8; 1024],
                },
                Config::default(),
                T0,
            )
            .unwrap(),
        )
    }

    #[test]
    fn the_bytes_after_the_head_are_the_new_roles() {
        let mut c = server();
        // a request, and a masked ws "Hi" right behind it
        let mut input = *b"GET / HTTP/1.1\r\n\r\n\x81\x82\0\0\0\0Hi";
        let rx = c.rx(T0, &mut input, &mut []);
        assert!(matches!(
            rx.event,
            Some(Event::H1Server(server::Event::Request))
        ));
        let at = rx.consumed;
        assert_eq!(at, 18);
        assert!(c.accept_ws(Ws::server(b"", T0)).is_ok());
        let after = c.rx(T0, &mut input[at..], &mut []);
        assert_eq!(
            after.event,
            Some(Event::Ws(ws::Event::Message {
                kind: ws::Kind::Text,
                data: b"Hi",
                first: true,
                last: true
            }))
        );
    }

    #[test]
    fn ws_is_accepted_only_for_a_request_awaiting_its_answer() {
        let mut c = server();
        assert_eq!(c.accept_ws(Ws::server(b"", T0)), Err(NotNow));
        assert!(matches!(c.role(), Role::H1Server(_)));
        let mut input = *b"GET / HTTP/1.1\r\n\r\n";
        c.rx(T0, &mut input, &mut []);
        let RoleMut::H1Server(s) = c.role_mut() else {
            panic!("not h1");
        };
        s.respond(server::Response {
            status: 200,
            content_type: None,
            content_length: Some(0),
            headers: &[],
        })
        .unwrap();
        assert_eq!(c.accept_ws(Ws::server(b"", T0)), Err(NotNow));
        assert!(matches!(c.role(), Role::H1Server(_)));
        // nor from a client
        let mut client: ServerConn = Conn::h1_client(
            Client::new(
                Storage {
                    table: [0u8; 1024],
                    out: [0u8; 1024],
                },
                Request {
                    method: b"GET",
                    path: b"/",
                    host: None,
                    origin: None,
                    scheme: Scheme::Http,
                    no_cache: false,
                    connection: Connection::Upgrade(b""),
                    headers: &[],
                    body: RequestBody::None,
                },
            )
            .unwrap(),
        );
        assert_eq!(client.accept_ws(Ws::server(b"", T0)), Err(NotNow));
    }

    #[test]
    fn a_client_becomes_ws_only_after_its_final_response() {
        let mut c: ServerConn = Conn::h1_client(
            Client::new(
                Storage {
                    table: [0u8; 1024],
                    out: [0u8; 1024],
                },
                Request {
                    method: b"GET",
                    path: b"/",
                    host: None,
                    origin: None,
                    scheme: Scheme::Http,
                    no_cache: false,
                    connection: Connection::Upgrade(b""),
                    headers: &[],
                    body: RequestBody::None,
                },
            )
            .unwrap(),
        );
        let ws = || Ws::client(SeededRandom::new(1), T0);
        assert_eq!(c.upgraded_ws(ws()), Err(NotNow));
        let mut out = [0u8; 256];
        c.tx(T0, &mut out, &mut Nothing);
        let mut input = *b"HTTP/1.1 101 Switching Protocols\r\n\r\n";
        c.rx(T0, &mut input, &mut []);
        assert!(c.upgraded_ws(ws()).is_ok());
        assert!(matches!(c.role(), Role::WsClient(_)));
    }

    struct Nothing;
    impl TxSource for Nothing {
        fn fill(&mut self, _: &mut [u8]) -> usize {
            0
        }
    }

    #[test]
    fn a_failed_client_takes_nothing_and_asks_to_abort() {
        let mut c: ServerConn = Conn::h1_client(
            Client::new(
                Storage {
                    table: [0u8; 1024],
                    out: [0u8; 1024],
                },
                Request {
                    method: b"GET",
                    path: b"/",
                    host: None,
                    origin: None,
                    scheme: Scheme::Http,
                    no_cache: false,
                    connection: Connection::Close,
                    headers: &[],
                    body: RequestBody::None,
                },
            )
            .unwrap(),
        );
        let mut out = [0u8; 256];
        c.tx(T0, &mut out, &mut Nothing);
        let mut input = *b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n";
        let rx = c.rx(T0, &mut input, &mut []);
        assert_eq!((rx.consumed, rx.event), (0, None));
        assert_eq!(c.close(), Some(Close::Abort));
    }

    fn upgrading_client() -> ServerConn {
        Conn::h1_client(
            Client::new(
                Storage {
                    table: [0u8; 1024],
                    out: [0u8; 1024],
                },
                Request {
                    method: b"GET",
                    path: b"/",
                    host: None,
                    origin: None,
                    scheme: Scheme::Http,
                    no_cache: false,
                    connection: Connection::Upgrade(b"upgrade: x\r\nconnection: upgrade\r\n"),
                    headers: &[],
                    body: RequestBody::None,
                },
            )
            .unwrap(),
        )
    }

    #[test]
    fn a_server_becomes_raw_once_its_101_has_gone_and_the_rest_is_the_raws() {
        let mut c = server();
        // the request, and the client's first bytes of the new protocol
        let mut input = *b"GET / HTTP/1.1\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\nfirst";
        let rx = c.rx(T0, &mut input, &mut []);
        let at = rx.consumed;
        assert_eq!(&input[at..], b"first");
        let RoleMut::H1Server(s) = c.role_mut() else {
            panic!("not h1");
        };
        s.switch(T0, b"x", &[(b"x-a", b"1")]).unwrap();
        // not until the 101 has gone
        assert_eq!(c.switch_raw(), Err(NotNow));
        let mut out = [0u8; 256];
        let n = c.tx(T0, &mut out, &mut Nothing);
        assert_eq!(
            &out[..n],
            b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: x\r\nx-a: 1\r\n\r\n"
        );
        let storage = c.switch_raw().unwrap();
        assert_eq!(storage.table.len(), 1024);
        assert!(matches!(c.role(), Role::Raw(_)));
        let after = c.rx(T0, &mut input[at..], &mut []);
        assert_eq!(
            (after.consumed, after.event),
            (5, Some(Event::Raw(raw::Event::Data(b"first"))))
        );
        assert_eq!(c.next_deadline(), None);
        assert_eq!(c.rx_closed(T0), Some(Event::Raw(raw::Event::PeerClosed)));
        let RoleMut::Raw(r) = c.role_mut() else {
            panic!("not raw");
        };
        r.close(Close::Shutdown);
        assert_eq!(c.close(), Some(Close::Shutdown));
    }

    #[test]
    fn a_client_becomes_raw_only_on_a_101() {
        for (response, raw) in [
            (&b"HTTP/1.1 101 Switching Protocols\r\n\r\n"[..], true),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false),
        ] {
            let mut c = upgrading_client();
            assert_eq!(c.switch_raw(), Err(NotNow));
            let mut out = [0u8; 256];
            c.tx(T0, &mut out, &mut Nothing);
            let mut input = [0u8; 64];
            input[..response.len()].copy_from_slice(response);
            c.rx(T0, &mut input[..response.len()], &mut []);
            assert_eq!(c.switch_raw().is_ok(), raw, "{}", response.escape_ascii());
            assert_eq!(matches!(c.role(), Role::Raw(_)), raw);
        }
    }

    #[test]
    fn nothing_but_a_switched_h1_role_becomes_raw() {
        let mut c = server();
        assert_eq!(c.switch_raw(), Err(NotNow));
        let mut input = *b"GET / HTTP/1.1\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\n";
        c.rx(T0, &mut input, &mut []);
        assert!(c.accept_ws(Ws::server(b"", T0)).is_ok());
        assert_eq!(c.switch_raw(), Err(NotNow));
        assert!(matches!(c.role(), Role::WsServer(_)));
    }
}
