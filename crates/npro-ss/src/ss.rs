//! The streams, their connections, and the two sides that drive them: the
//! adapter doing the IO, and the application told what happened.
//!
//! An [`Ss`] holds a table of slots, in storage the caller gives, each able
//! to carry one stream and one connection.  A server's accepted stream and
//! its connection share a slot for their life: the adapter accepts a
//! socket on a listener ([`Ss::accepted`]), is given a [`ConnId`] for it,
//! and drives it as it would a driver, by that id; the application loops on
//! [`Ss::poll_event`], and answers by the [`StreamId`] each event names.
//! When the connection is done with, the slot's storage carries the next.
//!
//! Every limit is the caller's: how many slots, how large each buffer.
//! Each is refused when it is reached, never silently: a listener's accept
//! with no slot free is [`AcceptError::Full`], which the adapter answers
//! by closing the socket.

use core::mem;

use npro_core::close::Close;
use npro_core::random::Random;
use npro_core::time::Instant;
use npro_h1::client::{self as h1c, Client, Request};
use npro_h1::server::{self, NoPayload, Server};
use npro_h1::table::MAX_CAPACITY;
use npro_h1::token::Token;
use npro_io::conn::{Conn, Event as ConnEvent, Role, RoleMut};
use npro_io::driver::{Buffers, Driver, NetBuffers, Parts, Want};
use npro_io::host::{Connect, Host};
use npro_io::tls::{NoTls, RecordLayer};
use npro_ws::conn::{self as ws, Ws};
use npro_ws::handshake::{self, MAX_101};

use crate::event::{
    End, Event, Flow, Kind, Own, Refusal, Resp, RespondError, Response, Tx, TxWant, Txn,
    request_path, respond,
};
use crate::id::{ConnId, ListenerId, StreamId};
use crate::policy::{
    Deflate, Listener, MAX_ROUTES, MAX_VHOSTS, Payload, Route, Tls, Vhost, Ws as WsPolicy,
    WsServer, find_route, find_vhost,
};

/// The storage one connection is carried in, given back when it is done
/// with to carry the next.
#[derive(Clone, Debug)]
pub struct ConnStorage<S> {
    /// The h1 role's: its header table, and where it composes its own
    /// bytes, at least [`server::MIN_OUT`].
    pub h1: npro_h1::Storage<S>,
    /// The driver's: what is read and not yet taken, what is to be
    /// written, and with permessage-deflate, where messages are inflated.
    pub bufs: Buffers<S>,
    /// tls' records, for a tls listener's connections; empty otherwise.
    pub net: NetBuffers<S>,
}

/// A slot: room for a stream and its connection.
#[derive(Debug)]
pub struct Slot<U, S, R, T = NoTls> {
    stream_generation: u32,
    conn_generation: u32,
    stream: Stream<U>,
    conn: Link<S, R, T>,
}

impl<U, S, R, T> Slot<U, S, R, T> {
    /// A slot whose connections are carried in `storage`.
    #[must_use]
    pub const fn new(storage: ConnStorage<S>) -> Self {
        Self {
            stream_generation: 0,
            conn_generation: 0,
            stream: Stream::Free,
            conn: Link::Free(storage),
        }
    }
}

/// Where a slot's stream is.
#[derive(Debug)]
enum Stream<U> {
    /// There is none.
    Free,
    /// Accepted on a listener, or connecting out, its connection in the
    /// same slot.
    Live {
        user: U,
        tx: TxWant,
        /// Whether what the peer sends is given to it.
        rx: Flow,
    },
    /// Its connection is gone, or was never made, which it is yet to be
    /// told.
    Ending { user: U, why: Loss },
    /// It was told, and is let go at the next event.
    Ended(U),
}

/// How a stream lost its connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Loss {
    /// It was gone.
    Disconnected,
    /// It could not be made.
    ConnectFailed,
}

/// The longest address a stream connects to, as the adapter reads it,
/// and the longest server name its tls is for.
pub const MAX_ADDRESS: usize = 256;

/// Where a slot's connection is.
#[derive(Debug)]
enum Link<S, R, T> {
    /// There is none: its storage waits for the next.
    Free(ConnStorage<S>),
    /// Asked of the adapter, with its request composed, until it is made
    /// or fails.
    Connecting(Connecting<S>),
    /// Carried by a driver.
    Live(Live<S, R, T>),
    /// Never so: the storage was lost making a connection that could not
    /// be made, which [`Ss::new`] checked could be.  The slot is not used
    /// again.
    Lost,
}

/// A connection the adapter is to make, and what it will carry.
#[derive(Debug)]
struct Connecting<S> {
    client: Client<S>,
    bufs: Buffers<S>,
    net: NetBuffers<S>,
    address: Name,
    tls: Option<Name>,
    /// The adapter has taken it.
    asked: bool,
}

/// An address or a server name, copied in.
#[derive(Clone, Copy, Debug)]
struct Name {
    bytes: [u8; MAX_ADDRESS],
    len: usize,
}

impl Name {
    fn of(s: &str) -> Option<Self> {
        let mut n = Self {
            bytes: [0; MAX_ADDRESS],
            len: s.len(),
        };
        n.bytes.get_mut(..s.len())?.copy_from_slice(s.as_bytes());
        Some(n)
    }

    fn as_str(&self) -> &str {
        self.bytes
            .get(..self.len)
            .and_then(|b| core::str::from_utf8(b).ok())
            .unwrap_or_default()
    }
}

/// Which side a connection was made from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    /// Accepted on this listener.
    Accepted(ListenerId),
    /// Made out, to a stream's peer.
    Client,
}

/// A connection, and the storage it is not using.
#[derive(Debug)]
struct Live<S, R, T> {
    driver: Driver<S, R, S, T>,
    side: Side,
    /// Where its last request was routed, if one was.
    routed: Option<Routed>,
    /// The h1 role's storage, once a change of role gave it back.
    h1: Spare<npro_h1::Storage<S>>,
    /// tls' buffers, when the connection is not tls.
    net: Spare<NetBuffers<S>>,
}

/// Where a request was routed, by place in the listener's policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Routed {
    vhost: usize,
    /// The route, and how much of the path matched it; `None` if none
    /// did.
    route: Option<(usize, usize)>,
}

impl Routed {
    /// The vhost, and the route if there was one, of `l`'s.
    fn in_listener<'p>(
        self,
        l: &'p Listener<'p>,
    ) -> Option<(&'p Vhost<'p>, Option<&'p Route<'p>>)> {
        let v = l.vhosts.get(self.vhost)?;
        let r = match self.route {
            None => None,
            Some((i, _)) => Some(v.routes.get(i)?),
        };
        Some((v, r))
    }

    /// The headers a response on it carries before the application's.
    fn own<'p>(self, l: &'p Listener<'p>) -> Option<Own<'p>> {
        let (v, r) = self.in_listener(l)?;
        Some(Own {
            vhost: v.headers,
            route: r.map_or(&[][..], |r| r.headers),
        })
    }
}

/// Storage a connection may or may not be using.
#[derive(Debug)]
enum Spare<X> {
    /// It is.
    InUse,
    /// It is not, and here it is.
    Idle(X),
}

/// Why an [`Ss`] could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewError {
    /// More slots or listeners than an id can name.
    TooMany,
    /// A listener is not as it must be.
    Listener {
        /// Which.
        listener: ListenerId,
        /// Why.
        why: ListenerError,
    },
    /// A vhost is not as it must be.
    Vhost {
        /// Its listener.
        listener: ListenerId,
        /// Which, by its place among the listener's.
        vhost: usize,
        /// Why.
        why: VhostError,
    },
    /// A route is not as it must be.
    Route {
        /// Its listener.
        listener: ListenerId,
        /// Its vhost, by its place among the listener's.
        vhost: usize,
        /// Which, by its place among the vhost's.
        route: usize,
        /// Why.
        why: RouteError,
    },
    /// A slot's storage cannot carry a connection.
    Slot {
        /// Which, by its place in the table.
        slot: u32,
        /// Why.
        why: SlotError,
    },
}

/// What is wrong with a listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerError {
    /// It serves no vhost.
    NoVhosts,
    /// It serves more than [`MAX_VHOSTS`].
    TooManyVhosts,
}

/// What is wrong with a vhost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VhostError {
    /// Its name is empty.
    NoName,
    /// Another on the listener has its name.
    Duplicate,
    /// It has more than [`MAX_ROUTES`].
    TooManyRoutes,
}

/// What is wrong with a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteError {
    /// Its path does not start with `/`.
    Path,
    /// Another of the vhost's has its path.
    Duplicate,
    /// It takes ws with no subprotocols.
    NoProtocols,
    /// Its default subprotocol is not one of them.
    NoSuchDefault,
    /// It takes permessage-deflate, which this build does not have: npro-ss'
    /// `pmd` feature.
    DeflateNotBuilt,
}

/// What is wrong with a slot's storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotError {
    /// The h1 header table is larger than [`MAX_CAPACITY`].
    Table,
    /// The h1 role's own storage is under [`server::MIN_OUT`].
    Out,
    /// A listener takes permessage-deflate, and the inflate buffer is
    /// under `npro_ws::pmd::RX_CHUNK`.
    Inflate,
    /// A listener is tls, and there are no buffers for its records.
    Net,
}

impl core::fmt::Display for NewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooMany => f.write_str("more slots or listeners than ids"),
            Self::Listener { listener, why } => write!(f, "{listener}: {why:?}"),
            Self::Vhost {
                listener,
                vhost,
                why,
            } => write!(f, "{listener}, vhost {vhost}: {why:?}"),
            Self::Route {
                listener,
                vhost,
                route,
                why,
            } => write!(f, "{listener}, vhost {vhost}, route {route}: {why:?}"),
            Self::Slot { slot, why } => write!(f, "slot {slot}: {why:?}"),
        }
    }
}

impl core::error::Error for NewError {}

/// Why an accepted socket was not taken.  The adapter closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptError {
    /// There is no such listener.
    NoListener,
    /// Every slot is in use.
    Full,
    /// The record layer given does not fit the listener: one for a plain
    /// listener, or none for a tls one.
    Tls,
}

impl core::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NoListener => "no such listener",
            Self::Full => "no slot free",
            Self::Tls => "tls does not fit the listener",
        })
    }
}

impl core::error::Error for AcceptError {}

/// Why a stream could not be made to connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectError {
    /// Every slot is in use.
    Full,
    /// The address, or the server name, is longer than [`MAX_ADDRESS`].
    AddressTooLong,
    /// The request was refused, as the h1 client refuses it.
    Request(h1c::NewError),
}

impl core::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Full => f.write_str("no slot free"),
            Self::AddressTooLong => write!(f, "an address longer than {MAX_ADDRESS}"),
            Self::Request(e) => write!(f, "request refused: {e}"),
        }
    }
}

impl core::error::Error for ConnectError {}

/// An id whose stream or connection is gone: the adapter's, as a
/// [`Host`]'s.
pub use npro_io::host::Gone;

/// What the application asks of a stream: each method on [`Ss`] that acts
/// on one is [`Ss::call`] with one of these, the value a stream's calls
/// are carried as wherever the stream is fulfilled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    /// It has payload to write: [`Ss::request_tx`].
    RequestTx,
    /// It has a ws message this long to write: [`Ss::request_tx_len`].
    RequestTxLen(u64),
    /// Whether what its peer sends is given to it: [`Ss::flow`].
    Flow(Flow),
    /// It is done with: [`Ss::destroy`].
    Destroy,
}

/// Why a call was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallError {
    /// The stream is gone.
    Gone,
    /// The stream's protocol has no use for it: a length asked for on h1,
    /// whose response says its own.
    Protocol,
}

impl core::fmt::Display for CallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Gone => "no such stream",
            Self::Protocol => "not for the stream's protocol",
        })
    }
}

impl core::error::Error for CallError {}

impl From<Gone> for CallError {
    fn from(_: Gone) -> Self {
        Self::Gone
    }
}

/// Streams and their connections: see the module's description.
#[derive(Debug)]
pub struct Ss<'s, U, S, R, T = NoTls> {
    listeners: &'s [Listener<'s>],
    slots: &'s mut [Slot<U, S, R, T>],
    /// The slot whose stream was told it is gone, to let go of.
    ended: Option<usize>,
}

fn check_route(r: &Route<'_>, before: &[Route<'_>]) -> Result<(), RouteError> {
    if !r.path.starts_with('/') {
        return Err(RouteError::Path);
    }
    if before.iter().any(|b| b.path == r.path) {
        return Err(RouteError::Duplicate);
    }
    let WsPolicy::Taken(w) = r.ws else {
        return Ok(());
    };
    if w.protocols.is_empty() {
        return Err(RouteError::NoProtocols);
    }
    if w.default.is_some_and(|d| d >= w.protocols.len()) {
        return Err(RouteError::NoSuchDefault);
    }
    match w.deflate {
        Deflate::Off => Ok(()),
        Deflate::Offered if cfg!(feature = "pmd") => Ok(()),
        Deflate::Offered => Err(RouteError::DeflateNotBuilt),
    }
}

fn check_vhost(v: &Vhost<'_>, before: &[Vhost<'_>]) -> Result<(), VhostError> {
    if v.name.is_empty() {
        return Err(VhostError::NoName);
    }
    if before.iter().any(|b| b.name.eq_ignore_ascii_case(v.name)) {
        return Err(VhostError::Duplicate);
    }
    if v.routes.len() > MAX_ROUTES {
        return Err(VhostError::TooManyRoutes);
    }
    Ok(())
}

/// Checks the listener's policy, each error saying where.
fn check_listener(id: ListenerId, l: &Listener<'_>) -> Result<(), NewError> {
    let wrong = match l.vhosts.len() {
        0 => Some(ListenerError::NoVhosts),
        n if n > MAX_VHOSTS => Some(ListenerError::TooManyVhosts),
        _ => None,
    };
    if let Some(why) = wrong {
        return Err(NewError::Listener { listener: id, why });
    }
    for (vi, v) in l.vhosts.iter().enumerate() {
        check_vhost(v, l.vhosts.get(..vi).unwrap_or_default()).map_err(|why| NewError::Vhost {
            listener: id,
            vhost: vi,
            why,
        })?;
        for (ri, r) in v.routes.iter().enumerate() {
            check_route(r, v.routes.get(..ri).unwrap_or_default()).map_err(|why| {
                NewError::Route {
                    listener: id,
                    vhost: vi,
                    route: ri,
                    why,
                }
            })?;
        }
    }
    Ok(())
}

/// Whether any route of the listener's takes permessage-deflate.
fn takes_deflate(l: &Listener<'_>) -> bool {
    l.vhosts.iter().flat_map(|v| v.routes).any(|r| {
        matches!(
            r.ws,
            WsPolicy::Taken(WsServer {
                deflate: Deflate::Offered,
                ..
            })
        )
    })
}

fn check_slot<S: AsRef<[u8]>>(
    c: &ConnStorage<S>,
    deflate: bool,
    tls: bool,
) -> Result<(), SlotError> {
    if c.h1.table.as_ref().len() > MAX_CAPACITY {
        return Err(SlotError::Table);
    }
    if c.h1.out.as_ref().len() < server::MIN_OUT {
        return Err(SlotError::Out);
    }
    // without the feature, no listener takes it: Ss::new refused it
    #[cfg(feature = "pmd")]
    if deflate && c.bufs.inflate.as_ref().len() < npro_ws::pmd::RX_CHUNK {
        return Err(SlotError::Inflate);
    }
    #[cfg(not(feature = "pmd"))]
    let _: bool = deflate;
    if tls && (c.net.rx.as_ref().is_empty() || c.net.tx.as_ref().is_empty()) {
        return Err(SlotError::Net);
    }
    Ok(())
}

impl<'s, U, S, R, T> Ss<'s, U, S, R, T>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
    T: RecordLayer,
{
    /// Streams for the policy's `listeners`, carried in `slots`.
    ///
    /// # Errors
    ///
    /// [`NewError`], if a listener is not as it must be, or a slot's
    /// storage could not carry a connection of the listeners'.
    pub fn new(
        listeners: &'s [Listener<'s>],
        slots: &'s mut [Slot<U, S, R, T>],
    ) -> Result<Self, NewError> {
        if u32::try_from(listeners.len()).is_err() || u32::try_from(slots.len()).is_err() {
            return Err(NewError::TooMany);
        }
        for (i, l) in (0..).zip(listeners) {
            check_listener(ListenerId::new(i), l)?;
        }
        let deflate = listeners.iter().any(takes_deflate);
        let tls = listeners
            .iter()
            .any(|l| matches!(l.tls, Tls::Server { .. }));
        for (i, s) in (0..).zip(slots.iter()) {
            match &s.conn {
                Link::Free(c) => check_slot(c, deflate, tls),
                // a slot is made free; one in use came from another Ss
                Link::Connecting(_) | Link::Live(_) | Link::Lost => Err(SlotError::Table),
            }
            .map_err(|why| NewError::Slot { slot: i, why })?;
        }
        Ok(Self {
            listeners,
            slots,
            ended: None,
        })
    }

    /// The listeners, for the adapter to bind each where it says.
    pub fn listeners(&self) -> impl Iterator<Item = (ListenerId, &Listener<'s>)> {
        (0..)
            .zip(self.listeners)
            .map(|(i, l)| (ListenerId::new(i), l))
    }

    fn listener(&self, id: ListenerId) -> Option<&'s Listener<'s>> {
        let listeners: &'s [Listener<'s>] = self.listeners;
        listeners.get(usize::try_from(id.index()).ok()?)
    }

    /// The adapter accepted a socket on `listener`, at `now`, with `tls`
    /// its record layer if the listener is tls: the connection is made,
    /// and a stream on it with `U`'s default, and the adapter drives it by
    /// the id returned.
    ///
    /// # Errors
    ///
    /// [`AcceptError`], and the adapter closes the socket.
    pub fn accepted(
        &mut self,
        now: Instant,
        listener: ListenerId,
        tls: Option<T>,
    ) -> Result<ConnId, AcceptError>
    where
        U: Default,
    {
        let l = self.listener(listener).ok_or(AcceptError::NoListener)?;
        match (&l.tls, &tls) {
            (Tls::Plain, None) | (Tls::Server { .. }, Some(_)) => {}
            (Tls::Plain, Some(_)) | (Tls::Server { .. }, None) => return Err(AcceptError::Tls),
        }
        let (index, slot) = (0u32..)
            .zip(self.slots.iter_mut())
            .find(|(_, s)| matches!((&s.stream, &s.conn), (Stream::Free, Link::Free(_))))
            .ok_or(AcceptError::Full)?;
        let Link::Free(storage) = mem::replace(&mut slot.conn, Link::Lost) else {
            return Err(AcceptError::Full);
        };
        let ConnStorage { h1, bufs, net } = storage;
        // checked by Ss::new, so not so; if it were, the slot is lost
        let Ok(server) = Server::new(h1, l.h1, now) else {
            return Err(AcceptError::Full);
        };
        let conn = Conn::h1_server(server);
        let (driver, net) = match tls {
            None => (Driver::plain(conn, bufs), Spare::Idle(net)),
            Some(layer) => (Driver::with_tls(conn, bufs, layer, net, now), Spare::InUse),
        };
        slot.conn = Link::Live(Live {
            driver,
            side: Side::Accepted(listener),
            routed: None,
            h1: Spare::InUse,
            net,
        });
        slot.stream = Stream::Live {
            user: U::default(),
            tx: TxWant::Idle,
            rx: Flow::Given,
        };
        Ok(ConnId {
            slot: index,
            generation: slot.conn_generation,
        })
    }

    /// A stream connecting out, to `address` (`unix:/path`, or a host and
    /// port, as the adapter reads them), over tls for the server name
    /// `tls` if given, asking `request` once connected, with `user` its
    /// own state.  The adapter is asked for the connection
    /// ([`Ss::next_connect`]); the stream is told the answer's head
    /// ([`Kind::Response`]), its body ([`Kind::Rx`]), or that the
    /// connection could not be made ([`Kind::ConnectFailed`]).  The
    /// request's body, if it has one, is pulled from the stream as it
    /// asks to write.  The first form of a client stream: no retry, no
    /// redirect followed, the connection closed after.
    ///
    /// # Errors
    ///
    /// [`ConnectError`], and no stream is made.
    pub fn connect(
        &mut self,
        address: &str,
        tls: Option<&str>,
        request: Request<'_>,
        user: U,
    ) -> Result<StreamId, ConnectError> {
        let address = Name::of(address).ok_or(ConnectError::AddressTooLong)?;
        let tls = match tls {
            None => None,
            Some(t) => Some(Name::of(t).ok_or(ConnectError::AddressTooLong)?),
        };
        let (index, slot) = (0u32..)
            .zip(self.slots.iter_mut())
            .find(|(_, s)| matches!((&s.stream, &s.conn), (Stream::Free, Link::Free(_))))
            .ok_or(ConnectError::Full)?;
        let Link::Free(storage) = mem::replace(&mut slot.conn, Link::Lost) else {
            return Err(ConnectError::Full);
        };
        let ConnStorage { h1, bufs, net } = storage;
        let client = match Client::new(h1, request) {
            Ok(c) => c,
            Err(h1c::RequestRefused { why, storage: back }) => {
                slot.conn = Link::Free(ConnStorage {
                    h1: back,
                    bufs,
                    net,
                });
                return Err(ConnectError::Request(why));
            }
        };
        slot.conn = Link::Connecting(Connecting {
            client,
            bufs,
            net,
            address,
            tls,
            asked: false,
        });
        slot.stream = Stream::Live {
            user,
            tx: TxWant::Idle,
            rx: Flow::Given,
        };
        Ok(StreamId {
            slot: index,
            generation: slot.stream_generation,
        })
    }

    /// A connection a stream wants made, not yet given to the adapter,
    /// if there is one: the adapter connects, and says how it went
    /// ([`Ss::connected`], [`Ss::connect_failed`]).
    pub fn next_connect(&mut self) -> Option<(ConnId, Connect<'_>)> {
        let (index, slot) = (0u32..)
            .zip(self.slots.iter_mut())
            .find(|(_, s)| matches!(&s.conn, Link::Connecting(Connecting { asked: false, .. })))?;
        let Link::Connecting(c) = &mut slot.conn else {
            return None;
        };
        c.asked = true;
        Some((
            ConnId {
                slot: index,
                generation: slot.conn_generation,
            },
            Connect {
                address: c.address.as_str(),
                tls: c.tls.as_ref().map(Name::as_str),
            },
        ))
    }

    /// The slot of a connection being made, by its id.
    fn connecting(&mut self, id: ConnId) -> Result<&mut Slot<U, S, R, T>, Gone> {
        self.slots
            .get_mut(usize::try_from(id.slot).map_err(|_| Gone)?)
            .filter(|s| s.conn_generation == id.generation && matches!(s.conn, Link::Connecting(_)))
            .ok_or(Gone)
    }

    /// The adapter made the connection, at `now`, with `tls` its record
    /// layer if it was asked for: it is driven from here by its id, and
    /// its request goes.
    ///
    /// # Errors
    ///
    /// [`Gone`], if no such connection was asked for.
    pub fn connected(&mut self, now: Instant, id: ConnId, tls: Option<T>) -> Result<(), Gone> {
        let slot = self.connecting(id)?;
        let Link::Connecting(c) = mem::replace(&mut slot.conn, Link::Lost) else {
            return Err(Gone);
        };
        let conn = Conn::h1_client(c.client);
        let (driver, net) = match (tls, c.tls) {
            (None, None) => (Driver::plain(conn, c.bufs), Spare::Idle(c.net)),
            (Some(layer), Some(_)) => (
                Driver::with_tls(conn, c.bufs, layer, c.net, now),
                Spare::InUse,
            ),
            // not what was asked for: the slot is lost rather than carry
            // a connection with the wrong security
            (None, Some(_)) | (Some(_), None) => return Err(Gone),
        };
        let mut live = Live {
            driver,
            side: Side::Client,
            routed: None,
            h1: Spare::InUse,
            net,
        };
        // a stream destroyed while connecting: nothing to carry
        if !matches!(slot.stream, Stream::Live { .. }) {
            live.driver.hangup(now);
        }
        slot.conn = Link::Live(live);
        Ok(())
    }

    /// The adapter could not make the connection, at `now`: its storage
    /// is ready for the next, and its stream is told
    /// ([`Kind::ConnectFailed`]).
    ///
    /// # Errors
    ///
    /// [`Gone`], if no such connection was asked for.
    pub fn connect_failed(&mut self, _now: Instant, id: ConnId) -> Result<(), Gone> {
        let slot = self.connecting(id)?;
        let Link::Connecting(c) = mem::replace(&mut slot.conn, Link::Lost) else {
            return Err(Gone);
        };
        slot.conn = Link::Free(ConnStorage {
            h1: c.client.into_storage(),
            bufs: c.bufs,
            net: c.net,
        });
        slot.conn_generation = slot.conn_generation.wrapping_add(1);
        slot.stream = match mem::replace(&mut slot.stream, Stream::Free) {
            Stream::Live { user, .. } => Stream::Ending {
                user,
                why: Loss::ConnectFailed,
            },
            s @ (Stream::Free | Stream::Ending { .. } | Stream::Ended(_)) => s,
        };
        Ok(())
    }

    fn live(&mut self, id: ConnId) -> Result<&mut Live<S, R, T>, Gone> {
        let slot = self
            .slots
            .get_mut(usize::try_from(id.slot).map_err(|_| Gone)?)
            .filter(|s| s.conn_generation == id.generation)
            .ok_or(Gone)?;
        match &mut slot.conn {
            Link::Live(l) => Ok(l),
            Link::Free(_) | Link::Connecting(_) | Link::Lost => Err(Gone),
        }
    }

    /// What the connection wants of the adapter now:
    /// [`npro_io::driver::Driver::want`].  On [`Want::Release`], the
    /// adapter closes the socket and says so ([`Ss::released`]).
    ///
    /// # Errors
    ///
    /// [`Gone`], if the connection is.
    pub fn want(&mut self, now: Instant, id: ConnId) -> Result<Want<'_>, Gone> {
        Ok(self.live(id)?.driver.want(now, &mut NoPayload))
    }

    /// The adapter read `n` bytes into what [`Ss::want`] offered, at
    /// `now`; 0 is the peer's FIN.
    ///
    /// # Errors
    ///
    /// [`Gone`], if the connection is.
    pub fn read_done(&mut self, now: Instant, id: ConnId, n: usize) -> Result<(), Gone> {
        self.live(id)?.driver.read_done(now, n);
        Ok(())
    }

    /// Bytes read elsewhere, copied in at `now`, as far as there is room:
    /// [`npro_io::driver::Driver::received`].
    ///
    /// # Errors
    ///
    /// [`Gone`], if the connection is.
    pub fn received(&mut self, now: Instant, id: ConnId, bytes: &[u8]) -> Result<usize, Gone> {
        Ok(self.live(id)?.driver.received(now, bytes))
    }

    /// The adapter wrote `n` bytes of what [`Ss::want`] offered.
    ///
    /// # Errors
    ///
    /// [`Gone`], if the connection is.
    pub fn write_done(&mut self, now: Instant, id: ConnId, n: usize) -> Result<(), Gone> {
        self.live(id)?.driver.write_done(now, n);
        Ok(())
    }

    /// The adapter half-closed the socket, as [`Want::HalfClose`] asked.
    ///
    /// # Errors
    ///
    /// [`Gone`], if the connection is.
    pub fn half_closed(&mut self, now: Instant, id: ConnId) -> Result<(), Gone> {
        self.live(id)?.driver.half_closed(now);
        Ok(())
    }

    /// It is `now`, which may be past what [`Ss::want`] said.
    ///
    /// # Errors
    ///
    /// [`Gone`], if the connection is.
    pub fn timer(&mut self, now: Instant, id: ConnId) -> Result<(), Gone> {
        self.live(id)?.driver.timer(now);
        Ok(())
    }

    /// The socket hung up, or failed, at `now`.
    ///
    /// # Errors
    ///
    /// [`Gone`], if the connection is.
    pub fn hangup(&mut self, now: Instant, id: ConnId) -> Result<(), Gone> {
        self.live(id)?.driver.hangup(now);
        Ok(())
    }

    /// The adapter closed the socket, as [`Want::Release`] asked: the
    /// connection is gone, its id refused from here, its storage ready for
    /// the next, and its stream is told so.
    ///
    /// # Errors
    ///
    /// [`Gone`], if the connection is.
    pub fn released(&mut self, id: ConnId) -> Result<(), Gone> {
        self.live(id)?;
        let slot = self
            .slots
            .get_mut(usize::try_from(id.slot).map_err(|_| Gone)?)
            .ok_or(Gone)?;
        let Link::Live(live) = mem::replace(&mut slot.conn, Link::Lost) else {
            return Err(Gone);
        };
        let Parts { conn, bufs, tls } = live.driver.into_parts();
        let h1 = match (live.h1, conn.into_storage()) {
            (Spare::Idle(h1), _) | (Spare::InUse, Some(h1)) => Some(h1),
            (Spare::InUse, None) => None,
        };
        let net = match (live.net, tls) {
            (Spare::Idle(net), _) | (Spare::InUse, Some((_, net))) => Some(net),
            (Spare::InUse, None) => None,
        };
        // each is somewhere; if one were not, the slot is lost
        if let (Some(h1), Some(net)) = (h1, net) {
            slot.conn = Link::Free(ConnStorage { h1, bufs, net });
        }
        slot.conn_generation = slot.conn_generation.wrapping_add(1);
        slot.stream = match mem::replace(&mut slot.stream, Stream::Free) {
            Stream::Live { user, .. } => Stream::Ending {
                user,
                why: Loss::Disconnected,
            },
            // a stream destroyed first has no one to tell
            s @ (Stream::Free | Stream::Ending { .. } | Stream::Ended(_)) => s,
        };
        Ok(())
    }

    fn live_stream(&mut self, id: StreamId) -> Result<&mut Slot<U, S, R, T>, Gone> {
        self.slots
            .get_mut(usize::try_from(id.slot).map_err(|_| Gone)?)
            .filter(|s| {
                s.stream_generation == id.generation && matches!(s.stream, Stream::Live { .. })
            })
            .ok_or(Gone)
    }

    /// The stream's own state.
    ///
    /// # Errors
    ///
    /// [`Gone`], if the stream is.
    pub fn user(&mut self, id: StreamId) -> Result<&mut U, Gone> {
        match &mut self.live_stream(id)?.stream {
            Stream::Live { user, .. } => Ok(user),
            Stream::Free | Stream::Ending { .. } | Stream::Ended(_) => Err(Gone),
        }
    }

    /// Acts on a stream as `call` says, at `now`.
    ///
    /// # Errors
    ///
    /// [`CallError`], and nothing is done.
    pub fn call(&mut self, now: Instant, id: StreamId, call: Call) -> Result<(), CallError> {
        let slot = self.live_stream(id)?;
        let Stream::Live { tx, rx, .. } = &mut slot.stream else {
            return Err(CallError::Gone);
        };
        let live = match &mut slot.conn {
            Link::Live(live) => Some(live),
            // still being made: a call waits on the connection, but a
            // destroy ends the stream now
            Link::Connecting(_) => None,
            Link::Free(_) | Link::Lost => return Err(CallError::Gone),
        };
        match (call, live) {
            (Call::RequestTx, _) => {
                if *tx == TxWant::Idle {
                    *tx = TxWant::Wanted;
                }
            }
            (Call::Flow(f), _) => *rx = f,
            (Call::RequestTxLen(len), Some(live)) => match live.driver.conn().role_mut() {
                RoleMut::WsServer(_) | RoleMut::WsClient(_) => *tx = TxWant::Message(len),
                RoleMut::H1Server(_) | RoleMut::H1Client(_) | RoleMut::Raw(_) => {
                    return Err(CallError::Protocol);
                }
            },
            (Call::RequestTxLen(_), None) => return Err(CallError::Protocol),
            (Call::Destroy, live) => {
                if let Some(live) = live {
                    match live.driver.conn().role_mut() {
                        RoleMut::H1Server(s) => s.abort(),
                        RoleMut::WsServer(w) => w.close_when_flushed(now),
                        RoleMut::WsClient(w) => w.close_when_flushed(now),
                        RoleMut::Raw(r) => r.close(Close::Shutdown),
                        // a client's transaction is dropped by closing
                        RoleMut::H1Client(_) => live.driver.hangup(now),
                    }
                }
                slot.stream = Stream::Free;
                slot.stream_generation = slot.stream_generation.wrapping_add(1);
            }
        }
        Ok(())
    }

    /// Whether what the stream's peer sends is given to it: C's
    /// `lws_rx_flow_control()`.  Held, what comes stays in the
    /// connection's buffer, and once that is full nothing more is read
    /// from the socket, so the peer is held back; given again, it is
    /// told what waited.  For a proxy, which reads a side only when the
    /// other has room.
    ///
    /// # Errors
    ///
    /// [`CallError::Gone`], if the stream is.
    pub fn flow(&mut self, id: StreamId, flow: Flow) -> Result<(), CallError> {
        self.call(Instant::from_micros(0), id, Call::Flow(flow))
    }

    /// Answers the request in hand on the stream, as [`Txn::respond`]
    /// does: for a stream answering after its [`Kind::ServerTxn`], once
    /// it has the request's body, say.  C's `lws_ss_server_ack()`.
    ///
    /// # Errors
    ///
    /// [`RespondError`], and the request is still unanswered.
    pub fn respond(&mut self, id: StreamId, r: Response<'_>) -> Result<(), RespondError> {
        let listeners: &'s [Listener<'s>] = self.listeners;
        let slot = self.live_stream(id).map_err(|_| RespondError::Gone)?;
        let Link::Live(live) = &mut slot.conn else {
            return Err(RespondError::Gone);
        };
        let Side::Accepted(listener) = live.side else {
            return Err(RespondError::Gone);
        };
        let l = listeners
            .get(usize::try_from(listener.index()).unwrap_or(usize::MAX))
            .ok_or(RespondError::Gone)?;
        let own = live
            .routed
            .and_then(|at| at.own(l))
            .ok_or(RespondError::Gone)?;
        let RoleMut::H1Server(server) = live.driver.conn().role_mut() else {
            return Err(RespondError::Gone);
        };
        respond(server, own, r)
    }

    /// The stream has payload to write: once its connection can take it,
    /// it is given the chance ([`Kind::Tx`]), and is until it gives
    /// nothing.  C's `lws_ss_request_tx()`.  On ws, it goes on with a
    /// message begun; a message is begun with [`Ss::request_tx_len`].
    ///
    /// # Errors
    ///
    /// [`CallError`], and nothing is done.
    pub fn request_tx(&mut self, id: StreamId) -> Result<(), CallError> {
        // no call that asks to write needs the time
        self.call(Instant::from_micros(0), id, Call::RequestTx)
    }

    /// The stream has a ws message `len` long to write, begun when the
    /// message going, if any, is done, and given as
    /// [`Ss::request_tx`] gives it.  C's `lws_ss_request_tx_len()`.  If the
    /// stream gives nothing when it is asked, the message is not begun.
    ///
    /// # Errors
    ///
    /// [`CallError::Protocol`] on h1, whose response says its own length.
    pub fn request_tx_len(&mut self, id: StreamId, len: u64) -> Result<(), CallError> {
        self.call(Instant::from_micros(0), id, Call::RequestTxLen(len))
    }

    /// The stream is done with, at `now`: its id is refused from here, its
    /// `U` dropped, and its connection closed by its role's own close, an
    /// h1 transaction's by dropping it, as C's `lws_ss_destroy()`.  The
    /// adapter carries the connection to its end as ever.
    ///
    /// # Errors
    ///
    /// [`CallError::Gone`], if the stream is.
    pub fn destroy(&mut self, now: Instant, id: StreamId) -> Result<(), CallError> {
        self.call(now, id, Call::Destroy)
    }

    /// What happened next to a stream, at `now`, or `None` once nothing
    /// has.  Call it until `None` after the adapter's calls, as the
    /// driver's [`npro_io::driver::Driver::poll_rx`] is: what a stream is
    /// not told, its connection holds, and reads nothing more once that
    /// fills.
    pub fn poll_event(&mut self, now: Instant) -> Option<Event<'_, U, S, R, T>> {
        if let Some(i) = self.ended.take() {
            if let Some(slot) = self.slots.get_mut(i) {
                if let Stream::Ended(_) = slot.stream {
                    slot.stream = Stream::Free;
                    slot.stream_generation = slot.stream_generation.wrapping_add(1);
                }
            }
        }
        let listeners: &'s [Listener<'s>] = self.listeners;
        let ended = &mut self.ended;
        for (index, slot) in (0u32..).zip(self.slots.iter_mut()) {
            let Slot {
                stream_generation,
                stream,
                conn,
                ..
            } = slot;
            let id = StreamId {
                slot: index,
                generation: *stream_generation,
            };
            // a stream whose connection is gone, or was never made, is
            // told so, and let go
            if let Stream::Ending { .. } = stream {
                let Stream::Ending { user: told, why } = mem::replace(stream, Stream::Free) else {
                    continue;
                };
                *stream = Stream::Ended(told);
                let Stream::Ended(user) = stream else {
                    continue;
                };
                *ended = usize::try_from(index).ok();
                return Some(Event {
                    stream: id,
                    user,
                    kind: match why {
                        Loss::Disconnected => Kind::Disconnected,
                        Loss::ConnectFailed => Kind::ConnectFailed,
                    },
                });
            }
            let (Stream::Live { user, tx, rx }, Link::Live(live)) = (stream, conn) else {
                // no stream, or none to tell: a destroyed stream's
                // connection is the adapter's to carry to its end, and
                // one being made has nothing yet
                continue;
            };
            let Live {
                driver,
                side,
                routed,
                h1,
                ..
            } = live;
            let l = match side {
                Side::Accepted(listener) => {
                    listeners.get(usize::try_from(listener.index()).unwrap_or(usize::MAX))
                }
                Side::Client => None,
            };
            // the chance to write, if it asked and can
            if *tx != TxWant::Idle && driver.is_writable() {
                let payload = l
                    .and_then(|l| routed.and_then(|r| r.in_listener(l)))
                    .and_then(|(_, r)| r)
                    .map_or(Payload::Binary, |r| match r.ws {
                        WsPolicy::Taken(w) => w.payload,
                        WsPolicy::NotTaken => Payload::Binary,
                    });
                return Some(Event {
                    stream: id,
                    user,
                    kind: Kind::Tx(Tx {
                        driver,
                        want: tx,
                        payload,
                        now,
                    }),
                });
            }
            // what the peer sent, if anything, unless the stream holds
            // it back: the last look at this slot
            if *rx == Flow::Held {
                continue;
            }
            if let Some(step) = driver.poll_rx(now) {
                let (event, role) = step.into_parts();
                return Some(Event {
                    stream: id,
                    user,
                    kind: told(event, role, l, routed, h1, now),
                });
            }
        }
        None
    }
}

/// The adapter's side of [`Ss`], for an adapter carrying any host, as
/// npro-io's threads adapter does: each is the method of the same name.
impl<U, S, R, T> Host for Ss<'_, U, S, R, T>
where
    U: Default,
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
    T: RecordLayer,
{
    type Listener = ListenerId;
    type Conn = ConnId;
    type Tls = T;
    type Refused = AcceptError;

    fn accepted(
        &mut self,
        now: Instant,
        listener: ListenerId,
        tls: Option<T>,
    ) -> Result<ConnId, AcceptError> {
        Ss::accepted(self, now, listener, tls)
    }

    fn want(&mut self, now: Instant, conn: ConnId) -> Result<Want<'_>, Gone> {
        Ss::want(self, now, conn)
    }

    fn read_done(&mut self, now: Instant, conn: ConnId, n: usize) -> Result<(), Gone> {
        Ss::read_done(self, now, conn, n)
    }

    fn received(&mut self, now: Instant, conn: ConnId, bytes: &[u8]) -> Result<usize, Gone> {
        Ss::received(self, now, conn, bytes)
    }

    fn write_done(&mut self, now: Instant, conn: ConnId, n: usize) -> Result<(), Gone> {
        Ss::write_done(self, now, conn, n)
    }

    fn half_closed(&mut self, now: Instant, conn: ConnId) -> Result<(), Gone> {
        Ss::half_closed(self, now, conn)
    }

    fn timer(&mut self, now: Instant, conn: ConnId) -> Result<(), Gone> {
        Ss::timer(self, now, conn)
    }

    fn hangup(&mut self, now: Instant, conn: ConnId) -> Result<(), Gone> {
        Ss::hangup(self, now, conn)
    }

    fn released(&mut self, conn: ConnId) -> Result<(), Gone> {
        Ss::released(self, conn)
    }

    fn next_connect(&mut self) -> Option<(ConnId, Connect<'_>)> {
        Ss::next_connect(self)
    }

    fn connected(&mut self, now: Instant, conn: ConnId, tls: Option<T>) -> Result<(), Gone> {
        Ss::connected(self, now, conn, tls)
    }

    fn connect_failed(&mut self, now: Instant, conn: ConnId) -> Result<(), Gone> {
        Ss::connect_failed(self, now, conn)
    }
}

/// What a stream is told of its connection's event: `l` is the listener
/// an accepted one came in on.
fn told<'a, S, R, T>(
    event: ConnEvent<'a>,
    conn: &'a mut Conn<S, R>,
    l: Option<&'a Listener<'a>>,
    routed: &mut Option<Routed>,
    h1: &mut Spare<npro_h1::Storage<S>>,
    now: Instant,
) -> Kind<'a, S, R, T>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
{
    match (event, l) {
        (ConnEvent::H1Server(server::Event::Request), Some(l)) => request(conn, l, routed, h1, now),
        (
            ConnEvent::H1Server(server::Event::Body(data))
            | ConnEvent::H1Client(h1c::Event::Body(data))
            | ConnEvent::Raw(npro_io::raw::Event::Data(data)),
            _,
        ) => Kind::Rx {
            data,
            end: End::More,
        },
        (
            ConnEvent::H1Server(server::Event::BodyEnd) | ConnEvent::H1Client(h1c::Event::BodyEnd),
            _,
        ) => Kind::Rx {
            data: &[],
            end: End::Last,
        },
        (ConnEvent::H1Client(h1c::Event::Response), _) => match conn.role() {
            Role::H1Client(client) => Kind::Response(Resp { client }),
            // never so: the response came from an h1 client
            Role::H1Server(_) | Role::WsServer(_) | Role::WsClient(_) | Role::Raw(_) => {
                Kind::PeerClose { code: None }
            }
        },
        (ConnEvent::Ws(ws::Event::Message { data, last, .. }), _) => Kind::Rx {
            data,
            end: if last { End::Last } else { End::More },
        },
        (ConnEvent::Ws(ws::Event::Pong(_)), _) => Kind::Pong,
        (ConnEvent::Ws(ws::Event::PeerClose(c)), _) => Kind::PeerClose {
            code: match c.payload() {
                [a, b, ..] => Some(u16::from_be_bytes([*a, *b])),
                [] | [_] => None,
            },
        },
        // a request on no listener is never so: it comes in on one
        (ConnEvent::Raw(npro_io::raw::Event::PeerClosed), _)
        | (ConnEvent::H1Server(server::Event::Request), None) => Kind::PeerClose { code: None },
    }
}

/// A request's head is in: it is routed, to the vhost its `Host` names
/// and the route its path matches; one asking for ws on a route that
/// takes it is answered here, any other is the stream's.
fn request<'a, S, R, T>(
    conn: &'a mut Conn<S, R>,
    l: &'a Listener<'a>,
    routed: &mut Option<Routed>,
    spare: &mut Spare<npro_h1::Storage<S>>,
    now: Instant,
) -> Kind<'a, S, R, T>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
{
    // where it goes, and what it is, decided first from a look at it: the
    // role is borrowed to answer only once the answer is known
    let (at, taken) = match conn.role() {
        Role::H1Server(server) => {
            let t = server.request();
            let vhost = find_vhost(l.vhosts, t.first(Token::Host)).unwrap_or(0);
            let path = request_path(t).unwrap_or_default();
            let found = l.vhosts.get(vhost).and_then(|v| find_route(v.routes, path));
            let at = Routed {
                vhost,
                route: found.map(|(i, rest)| (i, path.len().saturating_sub(rest.len()))),
            };
            let taken = match at.in_listener(l).and_then(|(_, on)| on) {
                Some(on) if asks_for_ws(server) => match on.ws {
                    WsPolicy::Taken(w) => Some((on, w)),
                    WsPolicy::NotTaken => None,
                },
                Some(_) | None => None,
            };
            (at, taken)
        }
        Role::H1Client(_) | Role::WsServer(_) | Role::WsClient(_) | Role::Raw(_) => {
            // never so: a request comes from an h1 server
            return Kind::PeerClose { code: None };
        }
    };
    *routed = Some(at);
    let Some((route, w)) = taken else {
        let RoleMut::H1Server(server) = conn.role_mut() else {
            return Kind::PeerClose { code: None };
        };
        return Kind::ServerTxn(Txn {
            server,
            listener: l,
            vhost: at.vhost,
            route: at.route,
            now,
        });
    };
    let RoleMut::H1Server(server) = conn.role_mut() else {
        return Kind::PeerClose { code: None };
    };
    let (ws, protocol) = match handshake(server, &w, now) {
        Ok(agreed) => agreed,
        Err(refusal) => return Kind::UpgradeRefused(refusal),
    };
    match conn.accept_ws(ws) {
        Ok(storage) => {
            *spare = Spare::Idle(storage);
            Kind::ServerUpgrade { protocol, route }
        }
        // never so: the request was just found awaiting its answer
        Err(_) => Kind::UpgradeRefused(Refusal::Dropped),
    }
}

/// Whether the request asks for ws: its `Upgrade` is `websocket`, any
/// case.  One asking for something else is the stream's to answer.
fn asks_for_ws<S: AsRef<[u8]> + AsMut<[u8]>>(server: &Server<S>) -> bool {
    let mut up = [0u8; 16];
    server
        .request()
        .copy(Token::Upgrade, &mut up)
        .ok()
        .and_then(|n| up.get(..n))
        .is_some_and(|u| u.eq_ignore_ascii_case(b"websocket"))
}

/// Answers a request for ws as `w` says, at `now`: the connection to
/// carry it, made with its 101, and the subprotocol agreed; or the
/// request refused, by a status page or by dropping the connection, as C
/// refuses it.
fn handshake<'p, S: AsRef<[u8]> + AsMut<[u8]>>(
    server: &mut Server<S>,
    w: &WsServer<'p>,
    now: Instant,
) -> Result<(Ws, &'p [u8]), Refusal> {
    let t = server.request();
    #[cfg(feature = "pmd")]
    let pmd = match w.deflate {
        Deflate::Off => None,
        Deflate::Offered => {
            let Ok(p) = npro_ws::pmd::server_accept(t) else {
                server.abort();
                return Err(Refusal::Dropped);
            };
            p
        }
    };
    let accepted = match handshake::server(t, w.protocols, w.default) {
        Ok(a) => a,
        Err(r) => {
            if server.refuse_upgrade(now, r.status(), r.header()).is_err() {
                server.abort();
                return Err(Refusal::Dropped);
            }
            return Err(Refusal::Status(r.status()));
        }
    };
    let Some(name) = w.protocols.get(accepted.protocol).copied() else {
        server.abort();
        return Err(Refusal::Dropped);
    };
    #[cfg(feature = "pmd")]
    let lines = pmd
        .as_ref()
        .map_or(&[][..], npro_ws::pmd::ServerAccepted::header_lines);
    #[cfg(not(feature = "pmd"))]
    let lines = &[][..];
    let mut first = [0u8; MAX_101];
    let Some(n) = handshake::response_101(&accepted, name, lines, &mut first) else {
        server.abort();
        return Err(Refusal::Dropped);
    };
    let ws = Ws::server(first.get(..n).unwrap_or_default(), now);
    #[cfg(feature = "pmd")]
    let ws = match pmd {
        Some(p) => ws.with_pmd(p.params()),
        None => ws,
    };
    Ok((ws, name))
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use crate::event::{Filled, MAX_HEADERS};
    use crate::policy::Payload;
    use alloc::vec;
    use alloc::vec::Vec;
    use npro_core::random::SeededRandom;
    use npro_io::driver::Io;

    const T0: Instant = Instant::from_micros(1_000_000);

    type Slots = Vec<Slot<Vec<u8>, Vec<u8>, SeededRandom>>;
    type S<'s> = Ss<'s, Vec<u8>, Vec<u8>, SeededRandom>;

    fn storage(out: usize, net: usize) -> ConnStorage<Vec<u8>> {
        ConnStorage {
            h1: npro_h1::Storage {
                table: vec![0; 1024],
                out: vec![0; out],
            },
            bufs: Buffers {
                rx: vec![0; 1024],
                tx: vec![0; 1024],
                inflate: Vec::new(),
            },
            net: NetBuffers {
                rx: vec![0; net],
                tx: vec![0; net],
            },
        }
    }

    fn slots(n: usize) -> Slots {
        (0..n).map(|_| Slot::new(storage(512, 0))).collect()
    }

    const ECHO: [&[u8]; 2] = [b"chat", b"echo"];

    /// One vhost, one route serving everything, taking ws as `ws` says.
    fn listener(ws: WsPolicy<'static>) -> Listener<'static> {
        let routes: &'static [Route<'static>] = alloc::vec![Route {
            path: "/",
            matching: crate::policy::Match::Prefix,
            to: "app",
            ws,
            headers: &[],
        }]
        .leak();
        let vhosts: &'static [Vhost<'static>] = alloc::vec![Vhost {
            name: "test",
            routes,
            headers: &[(b"x-vhost", b"1")],
            not_found: None,
        }]
        .leak();
        Listener {
            name: "test",
            bind: "unix:/test",
            tls: Tls::Plain,
            h1: server::Config::default(),
            vhosts,
        }
    }

    fn ws(default: Option<usize>) -> WsPolicy<'static> {
        WsPolicy::Taken(WsServer {
            protocols: &ECHO,
            default,
            payload: Payload::Text,
            deflate: Deflate::Off,
        })
    }

    fn read(ss: &mut S<'_>, conn: ConnId, bytes: &[u8]) {
        let Ok(Want::Io(io)) = ss.want(T0, conn) else {
            panic!("not io");
        };
        let room = io.read.unwrap();
        room[..bytes.len()].copy_from_slice(bytes);
        ss.read_done(T0, conn, bytes.len()).unwrap();
    }

    fn written(ss: &mut S<'_>, conn: ConnId) -> Vec<u8> {
        let mut all = Vec::new();
        while let Ok(Want::Io(Io { write: Some(w), .. })) = ss.want(T0, conn) {
            let n = w.len();
            all.extend_from_slice(w);
            ss.write_done(T0, conn, n).unwrap();
        }
        all
    }

    /// What a stream was told, owned.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Seen {
        Txn(StreamId, Vec<u8>),
        /// The subprotocol, and the route's `to`.
        Upgrade(Vec<u8>, alloc::string::String),
        Refused(Refusal),
        Rx(Vec<u8>, End),
        Tx,
        Pong,
        PeerClose(Option<u16>),
        Disconnected(StreamId),
    }

    /// Takes every event, answering each request with 200 `ok` unless
    /// `answer` is false, and filling each chance to write with `ok`.
    fn serve(ss: &mut S<'_>, answer: bool) -> Vec<Seen> {
        let mut seen = Vec::new();
        while let Some(ev) = ss.poll_event(T0) {
            let stream = ev.stream;
            let mut tx = false;
            seen.push(match ev.kind {
                Kind::ServerTxn(mut t) => {
                    let path = t.path().unwrap_or_default().to_vec();
                    if answer {
                        t.respond(Response {
                            status: 200,
                            content_type: None,
                            content_length: Some(2),
                            headers: &[],
                        })
                        .unwrap();
                        tx = true;
                    }
                    Seen::Txn(stream, path)
                }
                Kind::ServerUpgrade { protocol, route } => {
                    Seen::Upgrade(protocol.to_vec(), route.to.into())
                }
                Kind::UpgradeRefused(r) => Seen::Refused(r),
                Kind::Rx { data, end } => Seen::Rx(data.to_vec(), end),
                Kind::Tx(t) => {
                    t.fill(|buf| {
                        buf[..2].copy_from_slice(b"ok");
                        Filled::Last(2)
                    });
                    Seen::Tx
                }
                Kind::Pong => Seen::Pong,
                Kind::PeerClose { code } => Seen::PeerClose(code),
                Kind::Response(_) | Kind::ConnectFailed | Kind::Disconnected => {
                    Seen::Disconnected(stream)
                }
            });
            if tx {
                ss.request_tx(stream).unwrap();
            }
        }
        seen
    }

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-vhost: 1\r\n\r\nok";

    #[test]
    fn requests_are_answered_one_after_another_on_one_stream() {
        let ls = [listener(WsPolicy::NotTaken)];
        let mut sl = slots(2);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let conn = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        read(&mut ss, conn, b"GET /one HTTP/1.1\r\n\r\n");
        let seen = serve(&mut ss, true);
        let Some(Seen::Txn(stream, path)) = seen.first().cloned() else {
            panic!("{seen:?}");
        };
        assert_eq!(path, b"/one");
        assert_eq!(seen.get(1), Some(&Seen::Tx));
        assert_eq!(written(&mut ss, conn), OK);
        read(&mut ss, conn, b"GET /two HTTP/1.1\r\n\r\n");
        assert_eq!(
            serve(&mut ss, true),
            [Seen::Txn(stream, b"/two".to_vec()), Seen::Tx]
        );
        assert_eq!(written(&mut ss, conn), OK);
    }

    #[test]
    fn a_connection_gone_tells_its_stream_once_and_its_ids_are_refused() {
        let ls = [listener(WsPolicy::NotTaken)];
        let mut sl = slots(1);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let conn = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        read(&mut ss, conn, b"GET / HTTP/1.1\r\n\r\n");
        let Some(Seen::Txn(stream, _)) = serve(&mut ss, false).first().cloned() else {
            panic!("no request");
        };
        ss.hangup(T0, conn).unwrap();
        // nothing was owed, so nothing was dropped
        assert!(matches!(
            ss.want(T0, conn),
            Ok(Want::Release(npro_io::driver::Outcome::Delivered))
        ));
        ss.released(conn).unwrap();
        assert_eq!(serve(&mut ss, true), [Seen::Disconnected(stream)]);
        assert_eq!(serve(&mut ss, true), []);
        assert_eq!(ss.request_tx(stream), Err(CallError::Gone));
        assert!(ss.user(stream).is_err());
        assert!(ss.want(T0, conn).is_err());
        assert_eq!(ss.released(conn), Err(Gone));
        // the slot carries the next, under new ids
        let next = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        assert_ne!(next, conn);
        read(&mut ss, next, b"GET /again HTTP/1.1\r\n\r\n");
        let Some(Seen::Txn(again, path)) = serve(&mut ss, true).first().cloned() else {
            panic!("no request");
        };
        assert_ne!(again, stream);
        assert_eq!(path, b"/again");
        assert_eq!(written(&mut ss, next), OK);
    }

    #[test]
    fn accepting_is_refused_when_full_or_when_tls_does_not_fit() {
        let ls = [
            listener(WsPolicy::NotTaken),
            Listener {
                tls: Tls::Server {
                    cert: "c.pem",
                    key: "k.pem",
                },
                ..listener(WsPolicy::NotTaken)
            },
        ];
        let mut sl: Slots = (0..2).map(|_| Slot::new(storage(512, 64))).collect();
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        assert_eq!(
            ss.accepted(T0, ListenerId::new(1), None),
            Err(AcceptError::Tls)
        );
        assert_eq!(
            ss.accepted(T0, ListenerId::new(2), None),
            Err(AcceptError::NoListener)
        );
        let a = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        ss.accepted(T0, ListenerId::new(0), None).unwrap();
        assert_eq!(
            ss.accepted(T0, ListenerId::new(0), None),
            Err(AcceptError::Full)
        );
        // a stream destroyed leaves its slot busy until its connection goes
        read(&mut ss, a, b"GET / HTTP/1.1\r\n\r\n");
        let Some(Seen::Txn(stream, _)) = serve(&mut ss, false).first().cloned() else {
            panic!("no request");
        };
        ss.destroy(T0, stream).unwrap();
        assert_eq!(
            ss.accepted(T0, ListenerId::new(0), None),
            Err(AcceptError::Full)
        );
        assert!(matches!(ss.want(T0, a), Ok(Want::Release(_))));
        ss.released(a).unwrap();
        ss.accepted(T0, ListenerId::new(0), None).unwrap();
    }

    #[test]
    fn destroyed_a_stream_is_gone_and_its_transaction_dropped_untold() {
        let ls = [listener(WsPolicy::NotTaken)];
        let mut sl = slots(1);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let conn = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        read(&mut ss, conn, b"GET / HTTP/1.1\r\n\r\n");
        let Some(Seen::Txn(stream, _)) = serve(&mut ss, false).first().cloned() else {
            panic!("no request");
        };
        ss.destroy(T0, stream).unwrap();
        assert_eq!(ss.destroy(T0, stream), Err(CallError::Gone));
        assert_eq!(ss.request_tx(stream), Err(CallError::Gone));
        assert_eq!(written(&mut ss, conn), b"");
        assert!(matches!(
            ss.want(T0, conn),
            Ok(Want::Release(npro_io::driver::Outcome::Dropped))
        ));
        ss.released(conn).unwrap();
        assert_eq!(serve(&mut ss, true), []);
    }

    const ROUTES: [Route<'static>; 3] = [
        Route {
            path: "/",
            matching: crate::policy::Match::Prefix,
            to: "files",
            ws: WsPolicy::NotTaken,
            headers: &[],
        },
        Route {
            path: "/sai",
            matching: crate::policy::Match::Prefix,
            to: "proxy",
            ws: WsPolicy::NotTaken,
            headers: &[(b"x-route", b"sai")],
        },
        Route {
            path: "/chat",
            matching: crate::policy::Match::Exact,
            to: "echo",
            ws: WsPolicy::Taken(WsServer {
                protocols: &ECHO,
                default: None,
                payload: Payload::Text,
                deflate: Deflate::Off,
            }),
            headers: &[],
        },
    ];

    /// Two vhosts: `a` with [`ROUTES`], `b` with none.
    fn two_vhosts() -> Listener<'static> {
        const VHOSTS: [Vhost<'static>; 2] = [
            Vhost {
                name: "a",
                routes: &ROUTES,
                headers: &[(b"x-vhost", b"a")],
                not_found: None,
            },
            Vhost {
                name: "b",
                routes: &[],
                headers: &[(b"x-vhost", b"b")],
                not_found: Some("/404.html"),
            },
        ];
        Listener {
            vhosts: &VHOSTS,
            ..listener(WsPolicy::NotTaken)
        }
    }

    #[test]
    fn a_request_is_routed_by_host_and_path_and_answered_under_their_headers() {
        let ls = [two_vhosts()];
        let mut sl = slots(1);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let conn = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        read(
            &mut ss,
            conn,
            b"GET /sai/x/y HTTP/1.1\r\nHost: A:8080\r\n\r\n\
              GET /nothing HTTP/1.1\r\nHost: b\r\n\r\n\
              GET /sai HTTP/1.1\r\nHost: other\r\n\r\n\
              GET /404.html HTTP/1.1\r\nHost: b\r\n\r\n",
        );
        let mut n = 0u32;
        let mut out = Vec::new();
        // each request's answer goes before the next is taken
        for _ in 0..100 {
            if n == 4 {
                break;
            }
            let Some(ev) = ss.poll_event(T0) else {
                out.extend(written(&mut ss, conn));
                continue;
            };
            let stream = ev.stream;
            let mut t = match ev.kind {
                Kind::ServerTxn(t) => t,
                Kind::Tx(tx) => {
                    // the empty answer's end, as C's EOM says it
                    tx.fill(|_| Filled::Last(0));
                    continue;
                }
                Kind::ServerUpgrade { .. }
                | Kind::UpgradeRefused(_)
                | Kind::Rx { .. }
                | Kind::Pong
                | Kind::PeerClose { .. }
                | Kind::Response(_)
                | Kind::ConnectFailed
                | Kind::Disconnected => continue,
            };
            match n {
                0 => {
                    assert_eq!(t.vhost().name, "a");
                    let r = t.route().unwrap();
                    assert_eq!((r.index, r.route.to, r.rest), (1, "proxy", &b"x/y"[..]));
                    t.respond(Response {
                        status: 200,
                        content_type: None,
                        content_length: Some(0),
                        headers: &[(b"x-app", b"1")],
                    })
                    .unwrap();
                    ss.request_tx(stream).unwrap();
                }
                1 => {
                    // b has no routes: nothing serves it, and the stream
                    // says so, which with b's 404 document is a redirect
                    // to it, the connection kept
                    assert_eq!(t.vhost().name, "b");
                    assert_eq!(t.route(), None);
                    t.status(404).unwrap();
                }
                2 => {
                    // a Host naming no vhost is the first's
                    assert_eq!(t.vhost().name, "a");
                    let r = t.route().unwrap();
                    assert_eq!((r.index, r.rest), (1, &b""[..]));
                    t.status(403).unwrap();
                }
                _ => {
                    // the document itself, not found, gets the page
                    assert_eq!(t.vhost().name, "b");
                    t.status(404).unwrap();
                }
            }
            n = n.checked_add(1).unwrap();
        }
        assert_eq!(n, 4);
        out.extend(written(&mut ss, conn));
        let text = alloc::string::String::from_utf8_lossy(&out);
        let mut answers = text.split("HTTP/1.1 ").filter(|a| !a.is_empty());
        assert_eq!(
            answers.next(),
            Some("200 OK\r\ncontent-length: 0\r\nx-vhost: a\r\nx-route: sai\r\nx-app: 1\r\n\r\n")
        );
        assert_eq!(
            answers.next(),
            Some(
                "302 Redirect\r\nlocation: /404.html\r\ncontent-type: text/html\r\n\
                 content-length: 0\r\nx-vhost: b\r\n\r\n"
            )
        );
        assert!(answers.next().unwrap().starts_with(
            "403 Forbidden\r\ncontent-type: text/html\r\nx-vhost: a\r\nx-route: sai\r\n\
             content-length: 173\r\n"
        ));
        let not_found = answers.next().unwrap();
        assert!(not_found.starts_with("404 Not Found\r\ncontent-type: text/html\r\n"));
        assert!(not_found.ends_with("<h1>404</h1></body></html>"));
        assert_eq!(answers.next(), None);
    }

    #[test]
    fn ws_is_taken_on_the_route_that_takes_it_and_on_no_other() {
        let ls = [two_vhosts()];
        let mut sl = slots(2);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let a = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        read(&mut ss, a, UPGRADE);
        assert_eq!(
            serve(&mut ss, true),
            [Seen::Upgrade(b"echo".to_vec(), "echo".into())]
        );
        // the same request under /sai is the proxy's to answer
        let b = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        let under_sai =
            alloc::string::String::from_utf8_lossy(UPGRADE).replace("/chat", "/sai/chat");
        read(&mut ss, b, under_sai.as_bytes());
        assert!(matches!(
            serve(&mut ss, true).first(),
            Some(Seen::Txn(_, p)) if p == b"/sai/chat"
        ));
    }

    #[test]
    fn the_listeners_headers_go_first_and_together_are_bounded() {
        let many = [(&b"x-a"[..], &b"1"[..]); MAX_HEADERS];
        let vhosts = [Vhost {
            name: "test",
            routes: &ROUTES,
            headers: &many,
            not_found: None,
        }];
        let ls = [Listener {
            vhosts: &vhosts,
            ..listener(WsPolicy::NotTaken)
        }];
        let mut sl = slots(1);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let conn = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        read(&mut ss, conn, b"GET / HTTP/1.1\r\n\r\n");
        let mut refused = None;
        while let Some(ev) = ss.poll_event(T0) {
            if let Kind::ServerTxn(mut t) = ev.kind {
                refused = Some(t.respond(Response {
                    status: 200,
                    content_type: None,
                    content_length: Some(0),
                    headers: &[(b"x-mine", b"2")],
                }));
            }
        }
        assert_eq!(refused, Some(Err(RespondError::TooManyHeaders)));
    }

    #[test]
    fn a_length_is_asked_for_a_ws_message_not_an_h1_answer() {
        let ls = [listener(WsPolicy::NotTaken)];
        let mut sl = slots(1);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let conn = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        read(&mut ss, conn, b"GET / HTTP/1.1\r\n\r\n");
        let Some(Seen::Txn(stream, _)) = serve(&mut ss, false).first().cloned() else {
            panic!("no request");
        };
        assert_eq!(ss.request_tx_len(stream, 2), Err(CallError::Protocol));
    }

    const UPGRADE: &[u8] = b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
        Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Protocol: echo\r\n\r\n";

    #[test]
    fn ws_is_taken_as_the_listener_says_and_carries_messages() {
        let ls = [listener(ws(None))];
        let mut sl = slots(1);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let conn = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        read(&mut ss, conn, UPGRADE);
        assert_eq!(
            serve(&mut ss, true),
            [Seen::Upgrade(b"echo".to_vec(), "app".into())]
        );
        let first = written(&mut ss, conn);
        assert!(first.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(first.ends_with(b"Sec-WebSocket-Protocol: echo\r\n\r\n"));
        // a masked "Hi", in one frame
        read(&mut ss, conn, b"\x81\x82\0\0\0\0Hi");
        let seen = serve(&mut ss, true);
        assert_eq!(seen, [Seen::Rx(b"Hi".to_vec(), End::Last)]);
        let stream = StreamId {
            slot: 0,
            generation: 0,
        };
        // a message is said whole before it is given
        ss.request_tx_len(stream, 2).unwrap();
        assert_eq!(serve(&mut ss, true), [Seen::Tx]);
        assert_eq!(written(&mut ss, conn), b"\x81\x02ok");
        // the peer's close is told with its code, and answered
        read(&mut ss, conn, b"\x88\x82\0\0\0\0\x03\xe8");
        assert_eq!(serve(&mut ss, true), [Seen::PeerClose(Some(1000))]);
        assert_eq!(written(&mut ss, conn), b"\x88\x02\x03\xe8");
    }

    #[test]
    fn ws_not_taken_is_a_request_like_any_and_one_not_had_is_refused() {
        let ls = [listener(WsPolicy::NotTaken), listener(ws(None))];
        let mut sl = slots(2);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let a = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        read(&mut ss, a, UPGRADE);
        assert!(matches!(
            serve(&mut ss, true).first(),
            Some(Seen::Txn(_, p)) if p == b"/chat"
        ));
        assert_eq!(written(&mut ss, a), OK);
        // a listener with no default refuses a request naming no protocol
        let b = ss.accepted(T0, ListenerId::new(1), None).unwrap();
        let none = b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
            Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        read(&mut ss, b, none);
        assert_eq!(serve(&mut ss, true), [Seen::Refused(Refusal::Status(400))]);
        assert!(written(&mut ss, b).starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    }

    #[test]
    fn a_request_is_read_by_name() {
        let ls = [listener(WsPolicy::NotTaken)];
        let mut sl = slots(1);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let conn = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        read(
            &mut ss,
            conn,
            b"HEAD /p?a=1&b=2 HTTP/1.1\r\nUser-Agent: me\r\nX-Foo: bar\r\n\r\n",
        );
        let mut checked = false;
        while let Some(ev) = ss.poll_event(T0) {
            if let Kind::ServerTxn(t) = ev.kind {
                assert_eq!(t.method(), Some(&b"HEAD"[..]));
                assert_eq!(t.path(), Some(&b"/p"[..]));
                assert_eq!(t.args().collect::<Vec<_>>(), [&b"a=1"[..], b"b=2"]);
                assert_eq!(t.header(b"user-agent"), Some(&b"me"[..]));
                assert_eq!(t.header(b"USER-AGENT"), Some(&b"me"[..]));
                assert_eq!(t.header(b"x-foo"), Some(&b"bar"[..]));
                assert_eq!(t.header(b"x-none"), None);
                assert_eq!(t.header(&[b'x'; 100]), None);
                checked = true;
            }
        }
        assert!(checked);
    }

    /// A client request for `/x`, closing after.
    const fn get_x() -> Request<'static> {
        Request {
            method: b"GET",
            path: b"/x",
            host: Some(b"origin"),
            origin: None,
            scheme: h1c::Scheme::Http,
            no_cache: false,
            connection: h1c::Connection::Close,
            headers: &[],
            body: h1c::RequestBody::None,
        }
    }

    #[test]
    fn a_stream_connects_out_and_is_told_the_answer() {
        let ls = [listener(WsPolicy::NotTaken)];
        let mut sl = slots(1);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let stream = ss
            .connect("unix:/origin", None, get_x(), b"mine".to_vec())
            .unwrap();
        // nothing is told before the connection is made
        assert!(ss.poll_event(T0).is_none());
        let (conn, c) = ss.next_connect().unwrap();
        assert_eq!((c.address, c.tls), ("unix:/origin", None));
        assert!(ss.next_connect().is_none());
        // a call that needs the connection waits; the user is there
        assert_eq!(ss.request_tx_len(stream, 1), Err(CallError::Protocol));
        assert_eq!(ss.user(stream).unwrap(), b"mine");
        ss.connected(T0, conn, None).unwrap();
        assert_eq!(
            written(&mut ss, conn),
            b"GET /x HTTP/1.1\r\nHost: origin\r\nconnection: close\r\n\r\n"
        );
        read(
            &mut ss,
            conn,
            b"HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\n\
              Set-Cookie: b=2\r\nContent-Length: 5\r\n\r\nhello",
        );
        let mut seen = Vec::new();
        while let Some(ev) = ss.poll_event(T0) {
            assert_eq!(ev.stream, stream);
            seen.push(match ev.kind {
                Kind::Response(r) => {
                    assert_eq!(r.status(), 201);
                    assert_eq!(r.header(b"Content-Type"), Some(&b"text/plain"[..]));
                    assert_eq!(
                        r.values(b"set-cookie").collect::<Vec<_>>(),
                        [&b"a=1"[..], b"b=2"]
                    );
                    assert_eq!(r.values(b"x-none").count(), 0);
                    Seen::Tx
                }
                Kind::Rx { data, end } => Seen::Rx(data.to_vec(), end),
                Kind::Disconnected => Seen::Disconnected(stream),
                Kind::ServerTxn(_)
                | Kind::ServerUpgrade { .. }
                | Kind::UpgradeRefused(_)
                | Kind::Tx(_)
                | Kind::Pong
                | Kind::PeerClose { .. }
                | Kind::ConnectFailed => panic!("{:?}", mem::discriminant(&ev.kind)),
            });
        }
        assert_eq!(
            seen,
            [
                Seen::Tx,
                Seen::Rx(b"hello".to_vec(), End::More),
                Seen::Rx(Vec::new(), End::Last)
            ]
        );
        // the origin closes, as asked: the connection is carried to its
        // end, the stream is told, and let go
        read(&mut ss, conn, b"");
        let mut released = false;
        for _ in 0..10 {
            // the FIN is seen as the connection is looked at
            while ss.poll_event(T0).is_some() {}
            match ss.want(T0, conn) {
                Ok(Want::HalfClose) => ss.half_closed(T0, conn).unwrap(),
                Ok(Want::Release(_)) => {
                    released = true;
                    break;
                }
                Ok(Want::Io(_)) => {}
                Err(e) => panic!("{e}"),
            }
        }
        assert!(released);
        ss.released(conn).unwrap();
        let mut told = 0;
        while let Some(ev) = ss.poll_event(T0) {
            assert!(matches!(ev.kind, Kind::Disconnected));
            told += 1;
        }
        assert_eq!(told, 1);
        assert!(ss.user(stream).is_err());
        // the slot takes the next
        assert!(ss.connect("unix:/again", None, get_x(), Vec::new()).is_ok());
    }

    #[test]
    fn a_connect_that_fails_tells_the_stream_and_frees_the_slot() {
        let ls = [listener(WsPolicy::NotTaken)];
        let mut sl = slots(1);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let stream = ss
            .connect("nowhere:1", Some("nowhere"), get_x(), Vec::new())
            .unwrap();
        assert_eq!(
            ss.connect("x:1", None, get_x(), Vec::new()).err(),
            Some(ConnectError::Full)
        );
        let (conn, c) = ss.next_connect().unwrap();
        assert_eq!(c.tls, Some("nowhere"));
        ss.connect_failed(T0, conn).unwrap();
        assert_eq!(ss.connect_failed(T0, conn), Err(Gone));
        let mut seen = Vec::new();
        while let Some(ev) = ss.poll_event(T0) {
            seen.push(matches!(ev.kind, Kind::ConnectFailed));
        }
        assert_eq!(seen, [true]);
        assert!(ss.user(stream).is_err());
        assert_eq!(ss.request_tx(stream), Err(CallError::Gone));
        // the slot is free again, for a connection or an accept
        ss.accepted(T0, ListenerId::new(0), None).unwrap();
        // an address too long, and a request the client refuses, make no
        // stream and keep the slot
        let long = alloc::string::String::from_utf8(alloc::vec![b'a'; MAX_ADDRESS + 1]).unwrap();
        let mut sl2 = slots(1);
        let mut ss2 = Ss::new(&ls, &mut sl2).unwrap();
        assert_eq!(
            ss2.connect(&long, None, get_x(), Vec::new()).err(),
            Some(ConnectError::AddressTooLong)
        );
        let bad = Request {
            headers: &[(b"content-length", b"1")],
            ..get_x()
        };
        assert!(matches!(
            ss2.connect("x:1", None, bad, Vec::new()),
            Err(ConnectError::Request(_))
        ));
        assert!(ss2.connect("x:1", None, get_x(), Vec::new()).is_ok());
    }

    #[test]
    fn a_held_stream_is_told_nothing_until_it_is_given_again() {
        let ls = [listener(WsPolicy::NotTaken)];
        let mut sl = slots(1);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let conn = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        let stream = StreamId {
            slot: 0,
            generation: 0,
        };
        ss.flow(stream, Flow::Held).unwrap();
        read(&mut ss, conn, b"GET /one HTTP/1.1\r\n\r\n");
        // what came waits in the connection
        assert_eq!(serve(&mut ss, true), []);
        assert_eq!(serve(&mut ss, true), []);
        ss.flow(stream, Flow::Given).unwrap();
        assert!(matches!(
            serve(&mut ss, true).first(),
            Some(Seen::Txn(_, p)) if p == b"/one"
        ));
    }

    #[test]
    fn a_stream_destroyed_while_connecting_is_hung_up_once_made() {
        let ls = [listener(WsPolicy::NotTaken)];
        let mut sl = slots(1);
        let mut ss = Ss::new(&ls, &mut sl).unwrap();
        let stream = ss
            .connect("unix:/origin", None, get_x(), Vec::new())
            .unwrap();
        let (conn, _) = ss.next_connect().unwrap();
        ss.destroy(T0, stream).unwrap();
        assert_eq!(ss.destroy(T0, stream), Err(CallError::Gone));
        ss.connected(T0, conn, None).unwrap();
        assert!(matches!(ss.want(T0, conn), Ok(Want::Release(_))));
        ss.released(conn).unwrap();
        assert!(ss.poll_event(T0).is_none());
        assert!(ss.connect("unix:/again", None, get_x(), Vec::new()).is_ok());
    }

    #[test]
    fn the_policy_is_checked() {
        let no_protocols = WsPolicy::Taken(WsServer {
            protocols: &[],
            default: None,
            payload: Payload::Text,
            deflate: Deflate::Off,
        });
        let at = |why| NewError::Route {
            listener: ListenerId::new(0),
            vhost: 0,
            route: 0,
            why,
        };
        for (l, want) in [
            (listener(no_protocols), at(RouteError::NoProtocols)),
            (listener(ws(Some(2))), at(RouteError::NoSuchDefault)),
            (
                Listener {
                    vhosts: &[],
                    ..listener(WsPolicy::NotTaken)
                },
                NewError::Listener {
                    listener: ListenerId::new(0),
                    why: ListenerError::NoVhosts,
                },
            ),
        ] {
            let ls = [l];
            let mut sl = slots(1);
            assert_eq!(Ss::new(&ls, &mut sl).err(), Some(want));
        }
        let no_name = [Vhost {
            name: "",
            routes: &[],
            headers: &[],
            not_found: None,
        }];
        let twice = [
            Vhost {
                name: "a",
                routes: &[],
                headers: &[],
                not_found: None,
            },
            Vhost {
                name: "A",
                routes: &[],
                headers: &[],
                not_found: None,
            },
        ];
        for (vhosts, vhost, why) in [
            (&no_name[..], 0, VhostError::NoName),
            (&twice[..], 1, VhostError::Duplicate),
        ] {
            let ls = [Listener {
                vhosts,
                ..listener(WsPolicy::NotTaken)
            }];
            let mut sl = slots(1);
            assert_eq!(
                Ss::new(&ls, &mut sl).err(),
                Some(NewError::Vhost {
                    listener: ListenerId::new(0),
                    vhost,
                    why
                })
            );
        }
        let no_slash = [Route {
            path: "x",
            ..ROUTES[0]
        }];
        let same_path = [ROUTES[0], ROUTES[1], ROUTES[1]];
        for (routes, route, why) in [
            (&no_slash[..], 0, RouteError::Path),
            (&same_path[..], 2, RouteError::Duplicate),
        ] {
            let vhosts = [Vhost {
                name: "a",
                routes,
                headers: &[],
                not_found: None,
            }];
            let ls = [Listener {
                vhosts: &vhosts,
                ..listener(WsPolicy::NotTaken)
            }];
            let mut sl = slots(1);
            assert_eq!(
                Ss::new(&ls, &mut sl).err(),
                Some(NewError::Route {
                    listener: ListenerId::new(0),
                    vhost: 0,
                    route,
                    why
                })
            );
        }
    }

    #[test]
    fn the_storage_is_checked() {
        let at = |why| NewError::Route {
            listener: ListenerId::new(0),
            vhost: 0,
            route: 0,
            why,
        };
        let ls = [listener(WsPolicy::NotTaken)];
        let mut small: Slots = vec![Slot::new(storage(64, 0))];
        assert_eq!(
            Ss::new(&ls, &mut small).err(),
            Some(NewError::Slot {
                slot: 0,
                why: SlotError::Out
            })
        );
        let tls = [Listener {
            tls: Tls::Server {
                cert: "c.pem",
                key: "k.pem",
            },
            ..listener(WsPolicy::NotTaken)
        }];
        let mut for_tls = slots(1);
        assert_eq!(
            Ss::new(&tls, &mut for_tls).err(),
            Some(NewError::Slot {
                slot: 0,
                why: SlotError::Net
            })
        );
        let deflate = [listener(WsPolicy::Taken(WsServer {
            protocols: &ECHO,
            default: None,
            payload: Payload::Text,
            deflate: Deflate::Offered,
        }))];
        let mut for_deflate = slots(1);
        let want = if cfg!(feature = "pmd") {
            NewError::Slot {
                slot: 0,
                why: SlotError::Inflate,
            }
        } else {
            at(RouteError::DeflateNotBuilt)
        };
        assert_eq!(Ss::new(&deflate, &mut for_deflate).err(), Some(want));
    }
}
