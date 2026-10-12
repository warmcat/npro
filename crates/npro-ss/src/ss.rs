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
use npro_h1::server::{self, NoPayload, Server};
use npro_h1::table::MAX_CAPACITY;
use npro_h1::token::Token;
use npro_io::conn::{Conn, Event as ConnEvent, Role, RoleMut};
use npro_io::driver::{Buffers, Driver, NetBuffers, Parts, Want};
use npro_io::host::Host;
use npro_io::tls::{NoTls, RecordLayer};
use npro_ws::conn::{self as ws, Ws};
use npro_ws::handshake::{self, MAX_101};

use crate::event::{End, Event, Kind, Refusal, RespondError, Response, Tx, TxWant, Txn, respond};
use crate::id::{ConnId, ListenerId, StreamId};
use crate::policy::{Deflate, Listener, Tls, Ws as WsPolicy, WsServer};

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
    /// Accepted on a listener, its connection in the same slot.
    Accepted { user: U, tx: TxWant },
    /// Its connection is gone, which it is yet to be told.
    Ending(U),
    /// It was told, and is let go at the next event.
    Ended(U),
}

/// Where a slot's connection is.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "a slot is room for a connection: free, it is the same size as in use, by design"
)]
enum Link<S, R, T> {
    /// There is none: its storage waits for the next.
    Free(ConnStorage<S>),
    /// Carried by a driver.
    Live(Live<S, R, T>),
    /// Never so: the storage was lost making a connection that could not
    /// be made, which [`Ss::new`] checked could be.  The slot is not used
    /// again.
    Lost,
}

/// A connection, and the storage it is not using.
#[derive(Debug)]
struct Live<S, R, T> {
    driver: Driver<S, R, S, T>,
    listener: ListenerId,
    /// The h1 role's storage, once a change of role gave it back.
    h1: Spare<npro_h1::Storage<S>>,
    /// tls' buffers, when the connection is not tls.
    net: Spare<NetBuffers<S>>,
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

fn check_listener(l: &Listener<'_>) -> Result<(), ListenerError> {
    let WsPolicy::Taken(w) = l.ws else {
        return Ok(());
    };
    if w.protocols.is_empty() {
        return Err(ListenerError::NoProtocols);
    }
    if w.default.is_some_and(|d| d >= w.protocols.len()) {
        return Err(ListenerError::NoSuchDefault);
    }
    match w.deflate {
        Deflate::Off => Ok(()),
        Deflate::Offered if cfg!(feature = "pmd") => Ok(()),
        Deflate::Offered => Err(ListenerError::DeflateNotBuilt),
    }
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
            check_listener(l).map_err(|why| NewError::Listener {
                listener: ListenerId::new(i),
                why,
            })?;
        }
        let deflate = listeners.iter().any(|l| {
            matches!(
                l.ws,
                WsPolicy::Taken(WsServer {
                    deflate: Deflate::Offered,
                    ..
                })
            )
        });
        let tls = listeners
            .iter()
            .any(|l| matches!(l.tls, Tls::Server { .. }));
        for (i, s) in (0..).zip(slots.iter()) {
            match &s.conn {
                Link::Free(c) => check_slot(c, deflate, tls),
                // a slot is made free; one in use came from another Ss
                Link::Live(_) | Link::Lost => Err(SlotError::Table),
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
            listener,
            h1: Spare::InUse,
            net,
        });
        slot.stream = Stream::Accepted {
            user: U::default(),
            tx: TxWant::Idle,
        };
        Ok(ConnId {
            slot: index,
            generation: slot.conn_generation,
        })
    }

    fn live(&mut self, id: ConnId) -> Result<&mut Live<S, R, T>, Gone> {
        let slot = self
            .slots
            .get_mut(usize::try_from(id.slot).map_err(|_| Gone)?)
            .filter(|s| s.conn_generation == id.generation)
            .ok_or(Gone)?;
        match &mut slot.conn {
            Link::Live(l) => Ok(l),
            Link::Free(_) | Link::Lost => Err(Gone),
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
            Stream::Accepted { user, .. } => Stream::Ending(user),
            // a stream destroyed first has no one to tell
            s @ (Stream::Free | Stream::Ending(_) | Stream::Ended(_)) => s,
        };
        Ok(())
    }

    fn accepted_stream(&mut self, id: StreamId) -> Result<&mut Slot<U, S, R, T>, Gone> {
        self.slots
            .get_mut(usize::try_from(id.slot).map_err(|_| Gone)?)
            .filter(|s| {
                s.stream_generation == id.generation && matches!(s.stream, Stream::Accepted { .. })
            })
            .ok_or(Gone)
    }

    /// The stream's own state.
    ///
    /// # Errors
    ///
    /// [`Gone`], if the stream is.
    pub fn user(&mut self, id: StreamId) -> Result<&mut U, Gone> {
        match &mut self.accepted_stream(id)?.stream {
            Stream::Accepted { user, .. } => Ok(user),
            Stream::Free | Stream::Ending(_) | Stream::Ended(_) => Err(Gone),
        }
    }

    /// Acts on a stream as `call` says, at `now`.
    ///
    /// # Errors
    ///
    /// [`CallError`], and nothing is done.
    pub fn call(&mut self, now: Instant, id: StreamId, call: Call) -> Result<(), CallError> {
        let slot = self.accepted_stream(id)?;
        let Stream::Accepted { tx, .. } = &mut slot.stream else {
            return Err(CallError::Gone);
        };
        let Link::Live(live) = &mut slot.conn else {
            return Err(CallError::Gone);
        };
        match call {
            Call::RequestTx => {
                if *tx == TxWant::Idle {
                    *tx = TxWant::Wanted;
                }
            }
            Call::RequestTxLen(len) => match live.driver.conn().role_mut() {
                RoleMut::WsServer(_) | RoleMut::WsClient(_) => *tx = TxWant::Message(len),
                RoleMut::H1Server(_) | RoleMut::H1Client(_) | RoleMut::Raw(_) => {
                    return Err(CallError::Protocol);
                }
            },
            Call::Destroy => {
                match live.driver.conn().role_mut() {
                    RoleMut::H1Server(s) => s.abort(),
                    RoleMut::WsServer(w) => w.close_when_flushed(now),
                    RoleMut::WsClient(w) => w.close_when_flushed(now),
                    RoleMut::Raw(r) => r.close(Close::Shutdown),
                    // the client's own close comes with client streams
                    RoleMut::H1Client(_) => live.driver.hangup(now),
                }
                slot.stream = Stream::Free;
                slot.stream_generation = slot.stream_generation.wrapping_add(1);
            }
        }
        Ok(())
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
        let slot = self.accepted_stream(id).map_err(|_| RespondError::Gone)?;
        let Link::Live(live) = &mut slot.conn else {
            return Err(RespondError::Gone);
        };
        let l = listeners
            .get(usize::try_from(live.listener.index()).unwrap_or(usize::MAX))
            .ok_or(RespondError::Gone)?;
        let RoleMut::H1Server(server) = live.driver.conn().role_mut() else {
            return Err(RespondError::Gone);
        };
        respond(server, l.headers, r)
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
            // a stream whose connection is gone is told so, and let go
            if let Stream::Ending(_) = stream {
                let Stream::Ending(told) = mem::replace(stream, Stream::Free) else {
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
                    kind: Kind::Disconnected,
                });
            }
            let (Stream::Accepted { user, tx }, Link::Live(live)) = (stream, conn) else {
                // no stream, or none to tell: a destroyed stream's
                // connection is the adapter's to carry to its end
                continue;
            };
            let Live {
                driver,
                listener,
                h1,
                ..
            } = live;
            let Some(l) = listeners.get(usize::try_from(listener.index()).unwrap_or(usize::MAX))
            else {
                continue;
            };
            // the chance to write, if it asked and can
            if *tx != TxWant::Idle && driver.is_writable() {
                return Some(Event {
                    stream: id,
                    user,
                    kind: Kind::Tx(Tx {
                        driver,
                        want: tx,
                        payload: match l.ws {
                            WsPolicy::Taken(w) => w.payload,
                            WsPolicy::NotTaken => crate::policy::Payload::Binary,
                        },
                        now,
                    }),
                });
            }
            // what the peer sent, if anything: the last look at this slot
            if let Some(step) = driver.poll_rx(now) {
                let (event, role) = step.into_parts();
                return Some(Event {
                    stream: id,
                    user,
                    kind: told(event, role, l, h1, now),
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
}

/// What a stream is told of its connection's event.
fn told<'a, S, R, T>(
    event: ConnEvent<'a>,
    conn: &'a mut Conn<S, R>,
    l: &'a Listener<'a>,
    h1: &mut Spare<npro_h1::Storage<S>>,
    now: Instant,
) -> Kind<'a, S, R, T>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
{
    match event {
        ConnEvent::H1Server(server::Event::Request) => request(conn, l, h1, now),
        ConnEvent::H1Server(server::Event::Body(data))
        | ConnEvent::H1Client(npro_h1::client::Event::Body(data))
        | ConnEvent::Raw(npro_io::raw::Event::Data(data)) => Kind::Rx {
            data,
            end: End::More,
        },
        ConnEvent::H1Server(server::Event::BodyEnd)
        | ConnEvent::H1Client(npro_h1::client::Event::BodyEnd) => Kind::Rx {
            data: &[],
            end: End::Last,
        },
        // no client streams yet: their response comes with them
        ConnEvent::H1Client(npro_h1::client::Event::Response) => Kind::Rx {
            data: &[],
            end: End::More,
        },
        ConnEvent::Ws(ws::Event::Message { data, last, .. }) => Kind::Rx {
            data,
            end: if last { End::Last } else { End::More },
        },
        ConnEvent::Ws(ws::Event::Pong(_)) => Kind::Pong,
        ConnEvent::Ws(ws::Event::PeerClose(c)) => Kind::PeerClose {
            code: match c.payload() {
                [a, b, ..] => Some(u16::from_be_bytes([*a, *b])),
                [] | [_] => None,
            },
        },
        ConnEvent::Raw(npro_io::raw::Event::PeerClosed) => Kind::PeerClose { code: None },
    }
}

/// A request's head is in: one asking for ws on a listener that takes it
/// is answered here, any other is the stream's.
fn request<'a, S, R, T>(
    conn: &'a mut Conn<S, R>,
    l: &'a Listener<'a>,
    spare: &mut Spare<npro_h1::Storage<S>>,
    now: Instant,
) -> Kind<'a, S, R, T>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
{
    // what the request is decided first, from a look at it: the role is
    // borrowed to answer only once the answer is known
    let taken = match (conn.role(), l.ws) {
        (Role::H1Server(server), WsPolicy::Taken(w)) if asks_for_ws(server) => Some(w),
        (
            Role::H1Server(_)
            | Role::H1Client(_)
            | Role::WsServer(_)
            | Role::WsClient(_)
            | Role::Raw(_),
            WsPolicy::Taken(_) | WsPolicy::NotTaken,
        ) => None,
    };
    let Some(w) = taken else {
        let RoleMut::H1Server(server) = conn.role_mut() else {
            // never so: a request comes from an h1 server
            return Kind::PeerClose { code: None };
        };
        return Kind::ServerTxn(Txn {
            server,
            headers: l.headers,
        });
    };
    let RoleMut::H1Server(server) = conn.role_mut() else {
        return Kind::PeerClose { code: None };
    };
    let (ws, protocol) = match handshake(server, &w, now) {
        Ok(agreed) => agreed,
        Err(r) => return Kind::UpgradeRefused(r),
    };
    match conn.accept_ws(ws) {
        Ok(storage) => {
            *spare = Spare::Idle(storage);
            Kind::ServerUpgrade { protocol }
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

    fn listener(ws: WsPolicy<'static>) -> Listener<'static> {
        Listener {
            name: "test",
            bind: "unix:/test",
            tls: Tls::Plain,
            h1: server::Config::default(),
            ws,
            headers: &[(b"x-vhost", b"1")],
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
        Upgrade(Vec<u8>),
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
                Kind::ServerUpgrade { protocol } => Seen::Upgrade(protocol.to_vec()),
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
                Kind::Disconnected => Seen::Disconnected(stream),
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

    #[test]
    fn the_listeners_headers_go_first_and_together_are_bounded() {
        let many = [(&b"x-a"[..], &b"1"[..]); MAX_HEADERS];
        let ls = [Listener {
            headers: &many,
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
        assert_eq!(serve(&mut ss, true), [Seen::Upgrade(b"echo".to_vec())]);
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

    #[test]
    fn the_policy_and_the_storage_are_checked() {
        let no_protocols = WsPolicy::Taken(WsServer {
            protocols: &[],
            default: None,
            payload: Payload::Text,
            deflate: Deflate::Off,
        });
        for (l, why) in [
            (listener(no_protocols), ListenerError::NoProtocols),
            (listener(ws(Some(2))), ListenerError::NoSuchDefault),
        ] {
            let ls = [l];
            let mut sl = slots(1);
            assert_eq!(
                Ss::new(&ls, &mut sl).err(),
                Some(NewError::Listener {
                    listener: ListenerId::new(0),
                    why
                })
            );
        }
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
            NewError::Listener {
                listener: ListenerId::new(0),
                why: ListenerError::DeflateNotBuilt,
            }
        };
        assert_eq!(Ss::new(&deflate, &mut for_deflate).err(), Some(want));
    }
}
