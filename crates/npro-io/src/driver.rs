//! The driver: one connection between its protocol and whatever does the
//! IO.
//!
//! It is what every adapter would otherwise have to get right on its own,
//! written once: C's IO side, less the sockets and the event loop.  It
//! holds the [`Conn`] and the buffers, in storage the caller gives, and:
//!
//! - **receives**: the adapter reads into the space [`Driver::want`]
//!   offers and says how much came ([`Driver::read_done`]), or hands bytes
//!   in ([`Driver::received`]).  [`Driver::poll_rx`] gives them to the
//!   connection a step at a time, each with its event, if any, and `&mut`
//!   the connection to answer with.  Bytes the connection does not take
//!   stay, and when they fill the buffer no more are read: the peer is
//!   held back by the TCP window, as in C.  The peer's FIN is passed on
//!   once everything before it was taken;
//! - **sends**: it pulls what the connection owes, and the application's
//!   payload when it asked to write ([`Driver::request_write`], C's
//!   `lws_callback_on_writable()`), into its tx buffer, which the adapter
//!   writes from, saying how much went ([`Driver::write_done`]);
//! - **tls**, made with [`Driver::with_tls`], between those buffers and the
//!   socket: records read are opened into the rx buffer, and what the
//!   connection writes is sealed into records, through the
//!   [`crate::tls::RecordLayer`] it is given.  Nothing of the connection
//!   is pulled until the handshake is done, which has C's 15s;
//! - **times**: [`Driver::want`] says when it next needs [`Driver::timer`];
//! - **closes** as the connection asks ([`npro_core::close::Close`]): what
//!   was written goes, then a server half-closes ([`Want::HalfClose`]) and
//!   reads until the peer's FIN, as C stages a server's shutdown; a client
//!   is released; a connection that failed or timed out is released at
//!   once with what was unwritten dropped.  Each stage has C's deadline.
//!
//! It does no IO and reads no clock: the adapter does both, and passes
//! `now` in.
//!
//! ```
//! use npro_core::random::SeededRandom;
//! use npro_core::time::Instant;
//! use npro_h1::server::{Config, Event as H1, Response, Server, TxSource};
//! use npro_io::conn::{Conn, Event, RoleMut};
//! use npro_io::driver::{Buffers, Driver, Want};
//!
//! struct Text(&'static [u8]);
//! impl TxSource for Text {
//!     fn fill(&mut self, buf: &mut [u8]) -> usize {
//!         let n = self.0.len().min(buf.len());
//!         buf[..n].copy_from_slice(&self.0[..n]);
//!         self.0 = &self.0[n..];
//!         n
//!     }
//! }
//!
//! let now = Instant::from_micros(1_000_000);
//! let conn: Conn<_, SeededRandom> =
//!     Conn::h1_server(Server::new([0u8; 1024], Config::default(), now)?);
//! let (mut rx, mut tx) = ([0u8; 256], [0u8; 256]);
//! let bufs = Buffers { rx: &mut rx[..], tx: &mut tx[..], inflate: &mut [][..] };
//! let mut d = Driver::new(conn, bufs);
//! let mut app = Text(b"ok");
//!
//! // the adapter reads into what the driver offers
//! let Want::Io(io) = d.want(now, &mut app) else { unreachable!() };
//! let req = b"GET / HTTP/1.1\r\n\r\n";
//! io.read.unwrap()[..req.len()].copy_from_slice(req);
//! d.read_done(now, req.len());
//!
//! // the application answers each event as it comes
//! while let Some(mut step) = d.poll_rx(now) {
//!     if step.event() == Some(Event::H1Server(H1::Request)) {
//!         let RoleMut::H1Server(s) = step.conn().role_mut() else { unreachable!() };
//!         s.respond(Response { status: 200, content_type: None, content_length: Some(2) })?;
//!         step.request_write();
//!     }
//! }
//!
//! // and the adapter writes what the driver has
//! let Want::Io(io) = d.want(now, &mut app) else { unreachable!() };
//! assert_eq!(io.write, Some(&b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"[..]));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

use core::time::Duration;

use npro_core::close::Close;
use npro_core::random::Random;
use npro_core::time::Instant;
use npro_h1::server::TxSource;

use crate::conn::{Conn, Event};
use crate::tls::{NoTls, RecordLayer};

/// How long a closing connection may take to flush what it wrote: C's
/// `PENDING_FLUSH_STORED_SEND_BEFORE_CLOSE`, 5s.
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a server that half-closed waits for the peer's FIN: C's
/// `PENDING_TIMEOUT_SHUTDOWN_FLUSH`, the context's `timeout_secs`, 15s.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

/// The storage the driver's buffers live in, given by the caller, all of
/// one type: slices borrowed from wherever they are (`&'static mut` on a
/// device), or with `alloc`, boxes or vectors.
#[derive(Clone, Debug)]
pub struct Buffers<B> {
    /// Bytes read, not yet taken by the connection.  Its size is the most
    /// the driver holds before it stops reading.
    pub rx: B,
    /// Bytes pulled from the connection, not yet written.
    pub tx: B,
    /// Where a ws message deflated is inflated: with permessage-deflate
    /// not empty, `npro_ws::pmd::RX_CHUNK` being C's size, and without, it
    /// may be.
    pub inflate: B,
}

/// How the connection ended, for the adapter releasing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Everything written went.
    Delivered,
    /// What was unwritten was dropped: the connection failed or timed
    /// out, or the socket hung up first.
    Dropped,
}

/// What the driver wants of the adapter now.
#[derive(Debug)]
pub enum Want<'d> {
    /// Any of what it holds, at once: a connection keeps reading while it
    /// waits to write, or two peers each waiting to write wedge.
    Io(Io<'d>),
    /// Half-close the socket's write side, then say so
    /// ([`Driver::half_closed`]).
    HalfClose,
    /// Release the socket: the connection is over.
    Release(Outcome),
}

/// The IO the driver wants, each part if it wants it.
#[derive(Debug)]
pub struct Io<'d> {
    /// Read into this, then [`Driver::read_done`].
    pub read: Option<&'d mut [u8]>,
    /// Write from this, then [`Driver::write_done`].
    pub write: Option<&'d [u8]>,
    /// Call [`Driver::timer`] at this time.
    pub until: Option<Instant>,
}

/// A step of [`Driver::poll_rx`]: what the connection made of the bytes,
/// with the connection to act on.
#[derive(Debug)]
pub struct Step<'d, S, R> {
    event: Option<Event<'d>>,
    conn: &'d mut Conn<S, R>,
    write: &'d mut Write,
}

impl<'d, S, R> Step<'d, S, R> {
    /// The event, if the bytes came to one.  It borrows the driver's
    /// buffers, not the connection.
    #[must_use]
    pub const fn event(&self) -> Option<Event<'d>> {
        self.event
    }

    /// The connection, to answer with.
    pub const fn conn(&mut self) -> &mut Conn<S, R> {
        self.conn
    }

    /// The application has payload to write: [`Driver::request_write`].
    pub const fn request_write(&mut self) {
        *self.write = Write::Wanted;
    }
}

/// Whether the application asked to write: C's
/// `lws_callback_on_writable()`.  It lasts until a pull gives nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Write {
    Idle,
    Wanted,
}

/// Where the peer's side is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fin {
    /// It may send more.
    Open,
    /// Its FIN came: the connection is told once it took what came first.
    Seen,
    /// The connection was told.
    Told,
}

/// Where the connection's end is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// In use.
    Live,
    /// The connection asked to close as `close` says; what it wrote must
    /// go by `until`.
    Flushing { close: Close, until: Instant },
    /// All went, and the server is to half-close.
    HalfCloseDue,
    /// It half-closed, and reads until the peer's FIN, or `until`.
    HalfClosed { until: Instant },
    /// Over.
    Done(Outcome),
}

/// A window `start..end` in a buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Window {
    start: usize,
    end: usize,
}

impl Window {
    const fn is_empty(self) -> bool {
        self.start >= self.end
    }

    /// Moves what is in `buf`'s window to its start, so the room is all
    /// after it.
    fn compact(&mut self, buf: &mut [u8]) {
        if self.start == 0 {
            return;
        }
        if self.end > self.start && self.end <= buf.len() {
            buf.copy_within(self.start..self.end, 0);
        }
        self.end = self.end.saturating_sub(self.start);
        self.start = 0;
    }
}

/// How long a tls handshake may take: C's `PENDING_TIMEOUT_SSL_ACCEPT` and
/// `PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE`, the context's `timeout_secs`,
/// 15s.  Past it the connection is dropped.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// The storage of a tls connection's records, as they come from and go to
/// the socket, beside its [`Buffers`] of plaintext.  A record is up to
/// 16KiB and its overhead: the rx buffer must hold one, as tls opens a
/// record only whole.
#[derive(Clone, Debug)]
pub struct NetBuffers<B> {
    /// Records read, not yet opened.
    pub rx: B,
    /// Records sealed, not yet written.
    pub tx: B,
}

/// Where a tls handshake is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handshake {
    /// Under way, to be done by the deadline.
    Due(Instant),
    /// Done: the record layer says it is established.
    Done,
}

/// The socket's side of a tls connection: the record layer, and its
/// records in and out.
#[derive(Clone, Debug)]
struct Tls<T, B> {
    layer: T,
    handshake: Handshake,
    net: NetBuffers<B>,
    /// What of `net.rx` is read and not yet opened.
    rx: Window,
    /// What of `net.tx` is sealed and not yet written.
    tx: Window,
}

/// What lies between the connection's buffers and the socket.
#[derive(Clone, Debug)]
enum Wire<T, B> {
    /// Nothing: the socket's bytes are the connection's.
    Plain,
    /// tls.
    Tls(Tls<T, B>),
}

/// One connection, its buffers in `B`, and with tls, its record layer
/// `T`: see the module's description.
#[derive(Clone, Debug)]
pub struct Driver<S, R, B, T = NoTls> {
    conn: Conn<S, R>,
    bufs: Buffers<B>,
    /// What of `bufs.rx` is read and not yet taken: plaintext.
    rx: Window,
    /// What the last step took, let go at the next call: until then its
    /// event may borrow it.
    taken: usize,
    /// What of `bufs.tx` is pulled and not yet written or sealed.
    tx: Window,
    write: Write,
    fin: Fin,
    stage: Stage,
    wire: Wire<T, B>,
}

impl<S, R, B> Driver<S, R, B, NoTls> {
    /// Carries `conn`, with `bufs`, the socket's bytes being the
    /// connection's.
    #[must_use]
    pub const fn new(conn: Conn<S, R>, bufs: Buffers<B>) -> Self {
        Self {
            conn,
            bufs,
            rx: Window { start: 0, end: 0 },
            taken: 0,
            tx: Window { start: 0, end: 0 },
            write: Write::Idle,
            fin: Fin::Open,
            stage: Stage::Live,
            wire: Wire::Plain,
        }
    }
}

impl<S, R, B, T> Driver<S, R, B, T> {
    /// Carries `conn` over tls, its record layer `layer`, from `now`: the
    /// plaintext in `bufs`, the records in `net`.  The handshake must be
    /// done within [`HANDSHAKE_TIMEOUT`].  The connection's bytes wait in
    /// `bufs` until it is.
    #[must_use]
    pub fn with_tls(
        conn: Conn<S, R>,
        bufs: Buffers<B>,
        layer: T,
        net: NetBuffers<B>,
        now: Instant,
    ) -> Self {
        Self {
            conn,
            bufs,
            rx: Window::default(),
            taken: 0,
            tx: Window::default(),
            write: Write::Idle,
            fin: Fin::Open,
            stage: Stage::Live,
            wire: Wire::Tls(Tls {
                layer,
                handshake: Handshake::Due(now.saturating_add(HANDSHAKE_TIMEOUT)),
                net,
                rx: Window::default(),
                tx: Window::default(),
            }),
        }
    }

    /// The record layer, if the connection is over tls: to ask it the
    /// peer's ALPN, or why it failed.
    #[must_use]
    pub const fn tls(&self) -> Option<&T> {
        match &self.wire {
            Wire::Plain => None,
            Wire::Tls(t) => Some(&t.layer),
        }
    }
}

impl<S, R, B, T> Driver<S, R, B, T>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
    B: AsRef<[u8]> + AsMut<[u8]>,
    T: RecordLayer,
{
    /// The connection, to act on outside a [`Step`]: to send from a timer,
    /// say.
    pub const fn conn(&mut self) -> &mut Conn<S, R> {
        &mut self.conn
    }

    /// The application has payload to write, which the next
    /// [`Driver::want`] pulls: C's `lws_callback_on_writable()`.
    pub const fn request_write(&mut self) {
        self.write = Write::Wanted;
    }

    /// Lets go of what the last step took.
    const fn let_go(&mut self) {
        self.rx.start = self.rx.start.saturating_add(self.taken);
        self.taken = 0;
        if self.rx.start > self.rx.end {
            self.rx.start = self.rx.end;
        }
    }

    /// Gives the connection what was read, one step: `None` once it takes
    /// nothing more for now.  A step may have no event: bytes were taken
    /// that came to nothing yet, a ping answered, a head not yet whole.
    /// Call it until it gives `None` after reading, before
    /// [`Driver::want`]: what it does not give, the connection holds.
    ///
    /// Once all before it was taken, the peer's FIN is passed on, which
    /// may itself be a step, an h1 client's body ending with the close.
    pub fn poll_rx(&mut self, now: Instant) -> Option<Step<'_, S, R>> {
        self.let_go();
        if !matches!(self.stage, Stage::Live) {
            return None;
        }
        let Self {
            conn,
            bufs,
            rx,
            taken,
            write,
            fin,
            ..
        } = self;
        let input = bufs
            .rx
            .as_mut()
            .get_mut(rx.start..rx.end)
            .unwrap_or_default();
        if input.is_empty() && !conn.rx_pending() {
            if *fin != Fin::Seen {
                return None;
            }
            *fin = Fin::Told;
            let event = conn.rx_closed(now);
            return Some(Step { event, conn, write });
        }
        let r = conn.rx(now, input, bufs.inflate.as_mut());
        if r.consumed == 0 && r.event.is_none() {
            return None;
        }
        *taken = r.consumed;
        Some(Step {
            event: r.event,
            conn,
            write,
        })
    }

    /// What the driver wants of the adapter now, having pulled what there
    /// is to write, the application's payload from `src`.
    pub fn want(&mut self, now: Instant, src: &mut dyn TxSource) -> Want<'_> {
        self.let_go();
        self.open(now);
        self.pull(now, src);
        self.settle(now);
        self.seal(now);
        // a handshake done by that seal lets the connection write now
        self.pull(now, src);
        self.seal(now);
        self.settle(now);
        let until = match self.stage {
            Stage::Done(o) => return Want::Release(o),
            Stage::HalfCloseDue => return Want::HalfClose,
            Stage::Live => self.conn.next_deadline(),
            Stage::Flushing { until, .. } | Stage::HalfClosed { until } => Some(until),
        };
        let until = match &self.wire {
            Wire::Tls(Tls {
                handshake: Handshake::Due(h),
                ..
            }) => Some(until.map_or(*h, |u| u.min(*h))),
            Wire::Plain | Wire::Tls(_) => until,
        };
        // a closing connection reads what comes and drops it, as C keeps
        // the kernel's rx drained; a live one reads while it has room and
        // the peer has not closed
        let reading = match self.stage {
            Stage::Live => self.fin == Fin::Open,
            Stage::Flushing { .. } | Stage::HalfClosed { .. } => true,
            Stage::HalfCloseDue | Stage::Done(_) => false,
        };
        self.rx.compact(self.bufs.rx.as_mut());
        let Self {
            bufs, rx, tx, wire, ..
        } = self;
        // the socket's bytes are the connection's, or tls records
        let (read, write) = match wire {
            Wire::Plain => (
                bufs.rx.as_mut().get_mut(rx.end..),
                bufs.tx.as_ref().get(tx.start..tx.end),
            ),
            Wire::Tls(t) => {
                t.rx.compact(t.net.rx.as_mut());
                (
                    t.net.rx.as_mut().get_mut(t.rx.end..),
                    t.net.tx.as_ref().get(t.tx.start..t.tx.end),
                )
            }
        };
        Want::Io(Io {
            read: read.filter(|r| reading && !r.is_empty()),
            write: write.filter(|w| !w.is_empty()),
            until,
        })
    }

    /// With tls, opens what records were read into the plaintext buffer,
    /// as far as it has room.  A `close_notify` is the peer's end, as its
    /// FIN is.
    fn open(&mut self, now: Instant) {
        // a connection over has nothing more to open: tls that failed may
        // not even be asked
        if let Stage::Done(_) = self.stage {
            return;
        }
        let Wire::Tls(t) = &mut self.wire else {
            return;
        };
        let mut closed = false;
        loop {
            self.rx.compact(self.bufs.rx.as_mut());
            let net = t
                .net
                .rx
                .as_mut()
                .get_mut(t.rx.start..t.rx.end)
                .unwrap_or_default();
            if net.is_empty() {
                break;
            }
            let room = self
                .bufs
                .rx
                .as_mut()
                .get_mut(self.rx.end..)
                .unwrap_or_default();
            let Ok(o) = t.layer.open(now, net, room) else {
                self.drop_all();
                return;
            };
            let room = room.len();
            let net = net.len();
            t.rx.start = t.rx.start.saturating_add(o.consumed.min(net));
            self.rx.end = self.rx.end.saturating_add(o.produced.min(room));
            closed |= o.closed;
            if (o.consumed == 0 && o.produced == 0) || o.closed {
                break;
            }
        }
        if t.layer.is_established() {
            t.handshake = Handshake::Done;
        }
        self.drop_if_closing();
        if closed {
            self.fin_came(now);
        }
    }

    /// With tls, seals what the record layer owes and the plaintext
    /// pulled, as far as there is room for the records.
    fn seal(&mut self, now: Instant) {
        if !matches!(self.stage, Stage::Live | Stage::Flushing { .. }) {
            return;
        }
        let Wire::Tls(t) = &mut self.wire else {
            return;
        };
        loop {
            if t.tx.is_empty() {
                t.tx = Window::default();
            } else if t.tx.end >= t.net.tx.as_ref().len() {
                t.tx.compact(t.net.tx.as_mut());
            }
            let plain = self
                .bufs
                .tx
                .as_ref()
                .get(self.tx.start..self.tx.end)
                .unwrap_or_default();
            if plain.is_empty() && !t.layer.wants_write() {
                break;
            }
            let room = t.net.tx.as_mut().get_mut(t.tx.end..).unwrap_or_default();
            if room.is_empty() {
                break;
            }
            let Ok(s) = t.layer.seal(now, plain, room) else {
                self.drop_all();
                return;
            };
            self.tx.start = self.tx.start.saturating_add(s.taken.min(plain.len()));
            t.tx.end = t.tx.end.saturating_add(s.written.min(room.len()));
            if self.tx.is_empty() {
                self.tx = Window::default();
            }
            if s.taken == 0 && s.written == 0 {
                break;
            }
        }
        if t.layer.is_established() {
            t.handshake = Handshake::Done;
        }
    }

    /// Pulls what the connection owes, and the application's payload if
    /// it asked to write, into the tx buffer.  Over tls, nothing until the
    /// handshake is done: the connection's transport is not up, and what it
    /// writes would start its timers early, an h1 client's wait for its
    /// answer among them, which C starts once the request has gone.
    fn pull(&mut self, now: Instant, src: &mut dyn TxSource) {
        if !matches!(self.stage, Stage::Live | Stage::Flushing { .. }) {
            return;
        }
        if let Wire::Tls(Tls {
            handshake: Handshake::Due(_),
            ..
        }) = self.wire
        {
            return;
        }
        if !self.conn.wants_write() && self.write == Write::Idle {
            return;
        }
        if self.tx.is_empty() {
            self.tx = Window::default();
        } else if self.tx.end >= self.bufs.tx.as_ref().len() {
            self.tx.compact(self.bufs.tx.as_mut());
        }
        let room = self
            .bufs
            .tx
            .as_mut()
            .get_mut(self.tx.end..)
            .unwrap_or_default();
        if room.is_empty() {
            return;
        }
        let n = self.conn.tx(now, room, src).min(room.len());
        self.tx.end = self.tx.end.saturating_add(n);
        if n == 0 {
            self.write = Write::Idle;
        }
    }

    /// Whether everything written went, or is in the socket's hands: the
    /// plaintext, and with tls, the records and what tls owes of its own.
    fn flushed(&self) -> bool {
        let wire = match &self.wire {
            Wire::Plain => true,
            Wire::Tls(t) => t.tx.is_empty() && !t.layer.wants_write(),
        };
        wire && self.tx.is_empty() && !self.conn.wants_write()
    }

    /// Moves the close along: the connection asking to close, what it
    /// wrote having gone.
    fn settle(&mut self, now: Instant) {
        if self.stage == Stage::Live {
            match self.conn.close() {
                None => {}
                Some(Close::Abort) => self.drop_all(),
                Some(close @ (Close::Shutdown | Close::Release)) => {
                    // tls says it is closing, after what was written
                    if let Wire::Tls(t) = &mut self.wire {
                        t.layer.close();
                    }
                    self.stage = Stage::Flushing {
                        close,
                        until: now.saturating_add(FLUSH_TIMEOUT),
                    };
                }
            }
        }
        if let Stage::Flushing { close, .. } = self.stage {
            if self.flushed() {
                self.stage = match close {
                    Close::Shutdown => Stage::HalfCloseDue,
                    Close::Release | Close::Abort => Stage::Done(Outcome::Delivered),
                };
            }
        }
    }

    /// Ends the connection with what is unwritten dropped.
    fn drop_all(&mut self) {
        self.tx = Window::default();
        if let Wire::Tls(t) = &mut self.wire {
            t.tx = Window::default();
        }
        self.stage = Stage::Done(Outcome::Dropped);
    }

    /// The adapter read `n` bytes into what [`Driver::want`] offered, at
    /// `now`; 0 is the peer's FIN.
    pub fn read_done(&mut self, now: Instant, n: usize) {
        self.let_go();
        if n == 0 {
            self.fin_came(now);
            return;
        }
        match &mut self.wire {
            Wire::Plain => {
                let room = self.bufs.rx.as_ref().len().saturating_sub(self.rx.end);
                self.rx.end = self.rx.end.saturating_add(n.min(room));
                self.drop_if_closing();
            }
            Wire::Tls(t) => {
                let room = t.net.rx.as_ref().len().saturating_sub(t.rx.end);
                t.rx.end = t.rx.end.saturating_add(n.min(room));
                self.open(now);
            }
        }
    }

    /// Bytes read elsewhere, copied in at `now`, as far as there is room:
    /// returns how many were taken, the rest to be handed in again once
    /// [`Driver::want`] offers to read.  For an adapter that reads into a
    /// buffer of its own, as threads blocking in `read()` must.  An empty
    /// `bytes` is nothing, not the FIN: that is [`Driver::read_done`] with
    /// 0.
    pub fn received(&mut self, now: Instant, bytes: &[u8]) -> usize {
        self.let_go();
        if self.stage != Stage::Live {
            // closing: read and dropped
            return bytes.len();
        }
        let (buf, w) = match &mut self.wire {
            Wire::Plain => (self.bufs.rx.as_mut(), &mut self.rx),
            Wire::Tls(t) => (t.net.rx.as_mut(), &mut t.rx),
        };
        w.compact(buf);
        let room = buf.get_mut(w.end..).unwrap_or_default();
        let n = bytes.len().min(room.len());
        if let (Some(d), Some(s)) = (room.get_mut(..n), bytes.get(..n)) {
            d.copy_from_slice(s);
        }
        w.end = w.end.saturating_add(n);
        self.open(now);
        n
    }

    /// A closing connection takes nothing more: what comes is dropped.
    const fn drop_if_closing(&mut self) {
        if !matches!(self.stage, Stage::Live) {
            self.rx = Window { start: 0, end: 0 };
        }
    }

    /// The peer's FIN came, or its tls' `close_notify`.
    const fn fin_came(&mut self, _now: Instant) {
        match self.stage {
            Stage::Live => {
                if matches!(self.fin, Fin::Open) {
                    self.fin = Fin::Seen;
                }
            }
            // what it waited for
            Stage::HalfClosed { .. } => self.stage = Stage::Done(Outcome::Delivered),
            // the peer may still take what goes
            Stage::Flushing { .. } | Stage::HalfCloseDue | Stage::Done(_) => {}
        }
    }

    /// The adapter wrote `n` bytes of what [`Driver::want`] offered.
    pub fn write_done(&mut self, _now: Instant, n: usize) {
        let w = match &mut self.wire {
            Wire::Plain => &mut self.tx,
            Wire::Tls(t) => &mut t.tx,
        };
        let left = w.end.saturating_sub(w.start);
        w.start = w.start.saturating_add(n.min(left));
        if w.is_empty() {
            *w = Window::default();
        }
    }

    /// The adapter half-closed the socket, as [`Want::HalfClose`] asked,
    /// at `now`: the peer's FIN is awaited, for C's
    /// [`SHUTDOWN_TIMEOUT`].
    pub fn half_closed(&mut self, now: Instant) {
        if self.stage == Stage::HalfCloseDue {
            self.stage = Stage::HalfClosed {
                until: now.saturating_add(SHUTDOWN_TIMEOUT),
            };
        }
    }

    /// It is `now`, which may be past what [`Driver::want`] said.
    pub fn timer(&mut self, now: Instant) {
        self.let_go();
        if let Wire::Tls(Tls {
            handshake: Handshake::Due(until),
            ..
        }) = self.wire
        {
            if now >= until && !matches!(self.stage, Stage::Done(_)) {
                self.drop_all();
                return;
            }
        }
        match self.stage {
            Stage::Live => self.conn.deadline_passed(now),
            Stage::Flushing { until, .. } => {
                if now >= until {
                    self.drop_all();
                }
            }
            Stage::HalfClosed { until } => {
                if now >= until {
                    // what it wrote went before it half-closed
                    self.stage = Stage::Done(Outcome::Delivered);
                }
            }
            Stage::HalfCloseDue | Stage::Done(_) => {}
        }
    }

    /// The socket hung up, or failed, at `now`: nothing more goes either
    /// way.
    pub fn hangup(&mut self, _now: Instant) {
        self.let_go();
        if let Stage::Done(_) = self.stage {
            return;
        }
        let delivered = self.flushed();
        self.drop_all();
        self.stage = Stage::Done(if delivered {
            Outcome::Delivered
        } else {
            Outcome::Dropped
        });
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use crate::conn::RoleMut;
    use alloc::vec;
    use alloc::vec::Vec;
    use npro_core::random::SeededRandom;
    use npro_h1::client::Event as H1c;
    use npro_h1::client::{Client, Connection, Request, Scheme};
    use npro_h1::server::{Config, Event as H1, Response, Server};

    const T0: Instant = Instant::from_micros(1_000_000);

    fn at(secs: u64) -> Instant {
        T0.checked_add(Duration::from_secs(secs)).unwrap()
    }

    type D = Driver<Vec<u8>, SeededRandom, Vec<u8>>;

    fn bufs(rx: usize, tx: usize) -> Buffers<Vec<u8>> {
        Buffers {
            rx: vec![0; rx],
            tx: vec![0; tx],
            inflate: Vec::new(),
        }
    }

    fn server(rx: usize, tx: usize) -> D {
        let s = Server::new(vec![0u8; 1024], Config::default(), T0).unwrap();
        Driver::new(Conn::h1_server(s), bufs(rx, tx))
    }

    /// The application's payload.
    struct Text(Vec<u8>);
    impl TxSource for Text {
        fn fill(&mut self, buf: &mut [u8]) -> usize {
            let n = self.0.len().min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
            n
        }
    }

    fn nothing() -> Text {
        Text(Vec::new())
    }

    /// Reads `bytes` in as far as the driver offers room, `app` giving
    /// what payload it has meanwhile; how many went.
    fn read(d: &mut D, now: Instant, app: &mut Text, bytes: &[u8]) -> usize {
        let Want::Io(io) = d.want(now, app) else {
            return 0;
        };
        let Some(room) = io.read else {
            return 0;
        };
        let n = room.len().min(bytes.len());
        room[..n].copy_from_slice(&bytes[..n]);
        d.read_done(now, n);
        n
    }

    /// Writes all the driver has, `max` at a time.
    fn write(d: &mut D, now: Instant, app: &mut Text, max: usize) -> Vec<u8> {
        let mut wrote = Vec::new();
        loop {
            let Want::Io(io) = d.want(now, app) else {
                return wrote;
            };
            let Some(w) = io.write else {
                return wrote;
            };
            let n = w.len().min(max);
            wrote.extend_from_slice(&w[..n]);
            d.write_done(now, n);
        }
    }

    /// Answers every request with `ok`, completing it once its answer
    /// went: what the steps gave.
    fn answer(d: &mut D, now: Instant) -> Vec<Option<Event<'static>>> {
        let mut seen = Vec::new();
        while let Some(mut step) = d.poll_rx(now) {
            let ev = step.event();
            seen.push(ev.map(|e| match e {
                Event::H1Server(H1::Request) => Event::H1Server(H1::Request),
                Event::H1Server(H1::BodyEnd) => Event::H1Server(H1::BodyEnd),
                Event::H1Server(H1::Body(_)) | Event::H1Client(_) | Event::Ws(_) => {
                    Event::H1Server(H1::Body(b""))
                }
            }));
            if ev == Some(Event::H1Server(H1::Request)) {
                let RoleMut::H1Server(s) = step.conn().role_mut() else {
                    panic!("not h1");
                };
                s.respond(Response {
                    status: 200,
                    content_type: None,
                    content_length: Some(2),
                })
                .unwrap();
                step.request_write();
            }
        }
        seen
    }

    #[test]
    fn held_bytes_stop_the_reading_until_they_are_taken() {
        let mut d = server(32, 256);
        let mut app = Text(b"ok".to_vec());
        let three = b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\nGET /c HTTP/1.1\r\n\r\n";
        assert_eq!(read(&mut d, T0, &mut app, three), 32);
        assert_eq!(answer(&mut d, T0).len(), 1);
        // the rest waits for the first: the room it left fills, and stays
        // full
        assert_eq!(read(&mut d, T0, &mut app, &three[32..]), 19);
        let Want::Io(io) = d.want(T0, &mut app) else {
            panic!("not io");
        };
        assert!(io.read.is_none());
        // the first answered and complete, the second is taken
        let wrote = write(&mut d, T0, &mut app, 1024);
        assert!(wrote.ends_with(b"\r\n\r\nok"));
        let RoleMut::H1Server(s) = d.conn().role_mut() else {
            panic!("not h1");
        };
        s.complete(T0);
        assert_eq!(answer(&mut d, T0), [Some(Event::H1Server(H1::Request))]);
        // room again for the rest
        assert_eq!(read(&mut d, T0, &mut nothing(), &three[51..]), 6);
    }

    #[test]
    fn short_writes_go_on_from_where_they_stopped() {
        let mut d = server(256, 256);
        read(&mut d, T0, &mut nothing(), b"GET / HTTP/1.1\r\n\r\n");
        answer(&mut d, T0);
        let wrote = write(&mut d, T0, &mut Text(b"ok".to_vec()), 3);
        assert_eq!(wrote, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
    }

    #[test]
    fn a_server_flushes_half_closes_and_waits_for_the_fin() {
        let mut d = server(256, 256);
        // refused: C's status page, then the shutdown
        read(&mut d, T0, &mut nothing(), b"GET /%zz HTTP/1.1\r\n\r\n");
        assert_eq!(answer(&mut d, T0), []);
        let page = write(&mut d, T0, &mut nothing(), 7);
        assert!(page.starts_with(b"HTTP/1.0 403 Forbidden\r\n"));
        assert!(matches!(d.want(T0, &mut nothing()), Want::HalfClose));
        d.half_closed(at(1));
        let Want::Io(io) = d.want(at(1), &mut nothing()) else {
            panic!("not io");
        };
        assert!(io.read.is_some() && io.write.is_none());
        assert_eq!(io.until, Some(at(16)));
        // what the peer sends now is dropped, then its FIN ends it
        assert_eq!(read(&mut d, at(2), &mut nothing(), b"junk"), 4);
        d.read_done(at(2), 0);
        assert!(matches!(
            d.want(at(2), &mut nothing()),
            Want::Release(Outcome::Delivered)
        ));
    }

    #[test]
    fn a_half_closed_server_gives_up_on_the_fin_in_time() {
        let mut d = server(256, 256);
        read(&mut d, T0, &mut nothing(), b"GET /%zz HTTP/1.1\r\n\r\n");
        answer(&mut d, T0);
        write(&mut d, T0, &mut nothing(), 1024);
        assert!(matches!(d.want(T0, &mut nothing()), Want::HalfClose));
        d.half_closed(T0);
        d.timer(at(15));
        assert!(matches!(
            d.want(at(15), &mut nothing()),
            Want::Release(Outcome::Delivered)
        ));
    }

    #[test]
    fn a_flush_that_does_not_finish_in_time_is_dropped() {
        let mut d = server(256, 256);
        read(&mut d, T0, &mut nothing(), b"GET /%zz HTTP/1.1\r\n\r\n");
        answer(&mut d, T0);
        let Want::Io(io) = d.want(T0, &mut nothing()) else {
            panic!("not io");
        };
        assert_eq!(io.until, Some(at(5)));
        d.timer(at(5));
        assert!(matches!(
            d.want(at(5), &mut nothing()),
            Want::Release(Outcome::Dropped)
        ));
    }

    #[test]
    fn a_connections_deadline_aborts_it_dropping_what_is_unwritten() {
        let mut d = server(256, 256);
        read(&mut d, T0, &mut nothing(), b"GET / HTTP/1.1\r\n\r\n");
        answer(&mut d, T0);
        // the answer's head is pulled, but never written
        let Want::Io(io) = d.want(T0, &mut nothing()) else {
            panic!("not io");
        };
        assert!(io.write.is_some());
        assert_eq!(io.until, Some(at(30)));
        d.timer(at(30));
        assert!(matches!(
            d.want(at(30), &mut nothing()),
            Want::Release(Outcome::Dropped)
        ));
    }

    #[test]
    fn the_fin_comes_after_what_came_before_it() {
        let c = Client::new(
            vec![0u8; 1024],
            Request {
                method: b"GET",
                path: b"/",
                host: None,
                origin: None,
                scheme: Scheme::Http,
                no_cache: false,
                connection: Connection::Close,
            },
        )
        .unwrap();
        let mut d: D = Driver::new(Conn::h1_client(c), bufs(256, 256));
        assert!(write(&mut d, T0, &mut nothing(), 1024).starts_with(b"GET / HTTP/1.1"));
        read(
            &mut d,
            T0,
            &mut nothing(),
            b"HTTP/1.1 200 OK\r\n\r\nall of it",
        );
        d.read_done(T0, 0);
        let mut seen = Vec::new();
        while let Some(step) = d.poll_rx(T0) {
            if let Some(Event::H1Client(e)) = step.event() {
                seen.push(match e {
                    H1c::Response => b"response".to_vec(),
                    H1c::Body(b) => b.to_vec(),
                    H1c::BodyEnd => b"end".to_vec(),
                });
            }
        }
        assert_eq!(seen, [&b"response"[..], b"all of it", b"end"]);
        // a client is released once done, with nothing to stage
        assert!(matches!(
            d.want(T0, &mut nothing()),
            Want::Release(Outcome::Delivered)
        ));
    }

    #[test]
    fn a_hangup_with_output_unwritten_drops_it() {
        let mut d = server(256, 256);
        read(&mut d, T0, &mut nothing(), b"GET / HTTP/1.1\r\n\r\n");
        answer(&mut d, T0);
        let _ = d.want(T0, &mut nothing());
        d.hangup(T0);
        assert!(matches!(
            d.want(T0, &mut nothing()),
            Want::Release(Outcome::Dropped)
        ));
    }

    #[test]
    fn received_bytes_are_taken_as_far_as_there_is_room() {
        let mut d = server(8, 256);
        assert_eq!(d.received(T0, b"GET / HTTP/1.1\r\n\r\n"), 8);
        // the head is taken into the table as it comes, making room
        assert_eq!(answer(&mut d, T0), [None]);
        assert_eq!(d.received(T0, b" HTTP/1.1\r\n\r\n"), 8);
    }

    #[test]
    fn asking_to_write_lasts_until_a_pull_gives_nothing() {
        let mut d = server(256, 256);
        read(&mut d, T0, &mut nothing(), b"GET / HTTP/1.1\r\n\r\n");
        answer(&mut d, T0);
        // the head goes, the app has nothing yet: asked again, it is pulled
        let head = write(&mut d, T0, &mut nothing(), 1024);
        assert!(head.ends_with(b"\r\n\r\n"));
        assert_eq!(write(&mut d, T0, &mut Text(b"ok".to_vec()), 1024), b"");
        d.request_write();
        assert_eq!(write(&mut d, T0, &mut Text(b"ok".to_vec()), 1024), b"ok");
    }
}

/// The driver's tls path, with a record layer of the tests' own: a toy
/// tls, its handshake a hello and its answer, its records xored, so what
/// the driver does with records is seen without a real tls stack, whose
/// provider npro does not depend on.
#[cfg(test)]
mod tls_tests {
    extern crate alloc;

    use super::*;
    use crate::conn::RoleMut;
    use crate::tls::{Failed, Opened, Sealed};
    use alloc::vec;
    use alloc::vec::Vec;
    use npro_core::random::SeededRandom;
    use npro_h1::client::{Client, Connection, Event as H1c, Request, Scheme};
    use npro_h1::server::{Config, Event as H1s, Response, Server};

    const T0: Instant = Instant::from_micros(1_000_000);

    const HANDSHAKE: u8 = 0x16;
    const DATA: u8 = 0x17;
    const ALERT: u8 = 0x15;
    /// The most plaintext in a toy record.
    const RECORD: usize = 16;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Side {
        Client,
        Server,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Hs {
        /// A client owes its hello; a server waits for one.
        Start,
        /// A client sent its hello.
        Sent,
        /// A server owes its answer, and is established once it went.
        Answer,
        Established,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Closing {
        Open,
        Asked,
        Sent,
    }

    #[derive(Debug)]
    struct Toy {
        side: Side,
        hs: Hs,
        closing: Closing,
        /// It failed: as rustls, it must not be asked again.
        failed: Option<Failed>,
        /// How often it was asked after it failed.
        asked_again: u32,
    }

    impl Toy {
        const fn new(side: Side) -> Self {
            Self {
                side,
                hs: Hs::Start,
                closing: Closing::Open,
                failed: None,
                asked_again: 0,
            }
        }

        /// Already established, as a resumed session may be on its first
        /// step.
        const fn established(side: Side) -> Self {
            Self {
                side,
                hs: Hs::Established,
                closing: Closing::Open,
                failed: None,
                asked_again: 0,
            }
        }
    }

    fn add(a: usize, b: usize) -> usize {
        a.checked_add(b).unwrap()
    }

    /// Puts a record in `net`, or `false` if there is no room.
    fn record(net: &mut [u8], at: &mut usize, kind: u8, payload: &[u8]) -> bool {
        let end = add(add(*at, 2), payload.len());
        if end > net.len() {
            return false;
        }
        net[*at] = kind;
        net[add(*at, 1)] = u8::try_from(payload.len()).unwrap();
        for (d, s) in net[add(*at, 2)..end].iter_mut().zip(payload) {
            *d = s ^ 0x5a;
        }
        *at = end;
        true
    }

    impl RecordLayer for Toy {
        fn open(&mut self, _: Instant, net: &mut [u8], plain: &mut [u8]) -> Result<Opened, Failed> {
            if let Some(f) = self.failed {
                self.asked_again = self.asked_again.checked_add(1).unwrap();
                return Err(f);
            }
            let (mut consumed, mut produced) = (0, 0);
            while net.len() >= add(consumed, 2) {
                let kind = net[consumed];
                let len = usize::from(net[add(consumed, 1)]);
                let end = add(add(consumed, 2), len);
                if net.len() < end {
                    break;
                }
                let payload: Vec<u8> = net[add(consumed, 2)..end]
                    .iter()
                    .map(|b| b ^ 0x5a)
                    .collect();
                match (kind, self.side, self.hs) {
                    (HANDSHAKE, Side::Server, Hs::Start) if payload == b"hello" => {
                        self.hs = Hs::Answer;
                    }
                    (HANDSHAKE, Side::Client, Hs::Sent) if payload == b"olleh" => {
                        self.hs = Hs::Established;
                    }
                    (DATA, _, Hs::Established) => {
                        let Some(room) = plain.get_mut(produced..add(produced, len)) else {
                            // no room for it whole: it waits
                            break;
                        };
                        room.copy_from_slice(&payload);
                        produced = add(produced, len);
                    }
                    (ALERT, _, Hs::Established) => {
                        return Ok(Opened {
                            consumed: end,
                            produced,
                            closed: true,
                        });
                    }
                    _ => {
                        self.failed = Some(Failed);
                        return Err(Failed);
                    }
                }
                consumed = end;
            }
            Ok(Opened {
                consumed,
                produced,
                closed: false,
            })
        }

        fn seal(&mut self, _: Instant, plain: &[u8], net: &mut [u8]) -> Result<Sealed, Failed> {
            if let Some(f) = self.failed {
                self.asked_again = self.asked_again.checked_add(1).unwrap();
                return Err(f);
            }
            let (mut taken, mut at) = (0, 0);
            match self.hs {
                Hs::Start if self.side == Side::Client => {
                    if record(net, &mut at, HANDSHAKE, b"hello") {
                        self.hs = Hs::Sent;
                    }
                }
                Hs::Answer => {
                    if record(net, &mut at, HANDSHAKE, b"olleh") {
                        self.hs = Hs::Established;
                    }
                }
                Hs::Start | Hs::Sent | Hs::Established => {}
            }
            if self.hs == Hs::Established {
                while taken < plain.len() {
                    let n = plain.len().checked_sub(taken).unwrap().min(RECORD);
                    if !record(net, &mut at, DATA, &plain[taken..add(taken, n)]) {
                        break;
                    }
                    taken = add(taken, n);
                }
                if self.closing == Closing::Asked
                    && taken == plain.len()
                    && record(net, &mut at, ALERT, b"")
                {
                    self.closing = Closing::Sent;
                }
            }
            Ok(Sealed { taken, written: at })
        }

        fn wants_write(&self) -> bool {
            matches!(
                (self.side, self.hs),
                (Side::Client, Hs::Start) | (_, Hs::Answer)
            ) || (self.hs == Hs::Established && self.closing == Closing::Asked)
        }

        fn is_established(&self) -> bool {
            self.hs == Hs::Established
        }

        fn alpn(&self) -> Option<&[u8]> {
            None
        }

        fn close(&mut self) {
            if self.closing == Closing::Open {
                self.closing = Closing::Asked;
            }
        }
    }

    type D = Driver<Vec<u8>, SeededRandom, Vec<u8>, Toy>;

    fn tls(conn: Conn<Vec<u8>, SeededRandom>, layer: Toy) -> D {
        Driver::with_tls(
            conn,
            Buffers {
                rx: vec![0; 256],
                tx: vec![0; 256],
                inflate: Vec::new(),
            },
            layer,
            NetBuffers {
                rx: vec![0; 256],
                tx: vec![0; 256],
            },
            T0,
        )
    }

    fn client() -> Conn<Vec<u8>, SeededRandom> {
        Conn::h1_client(
            Client::new(
                vec![0u8; 1024],
                Request {
                    method: b"GET",
                    path: b"/",
                    host: Some(b"x"),
                    origin: None,
                    scheme: Scheme::Https,
                    no_cache: false,
                    connection: Connection::Close,
                },
            )
            .unwrap(),
        )
    }

    fn server() -> Conn<Vec<u8>, SeededRandom> {
        Conn::h1_server(Server::new(vec![0u8; 1024], Config::default(), T0).unwrap())
    }

    /// The server's payload.
    struct Text(Vec<u8>);
    impl TxSource for Text {
        fn fill(&mut self, buf: &mut [u8]) -> usize {
            let n = self.0.len().min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
            n
        }
    }

    /// Moves what `from` writes into `to`, a few bytes at a time; what
    /// went.
    fn carry(from: &mut D, src: &mut Text, to: &mut D, sink: &mut Text) -> Vec<u8> {
        let mut went = Vec::new();
        loop {
            let Want::Io(io) = from.want(T0, src) else {
                return went;
            };
            let Some(w) = io.write else {
                return went;
            };
            let n = w.len().min(5);
            let bytes = w[..n].to_vec();
            from.write_done(T0, n);
            let Want::Io(into) = to.want(T0, sink) else {
                return went;
            };
            let room = into.read.unwrap();
            room[..n].copy_from_slice(&bytes);
            to.read_done(T0, n);
            went.extend_from_slice(&bytes);
        }
    }

    #[test]
    fn an_h1_exchange_goes_over_tls_and_ends_with_close_notify() {
        let (mut c, mut s) = (
            tls(client(), Toy::new(Side::Client)),
            tls(server(), Toy::new(Side::Server)),
        );
        let (mut csrc, mut ssrc) = (Text(Vec::new()), Text(b"ok".to_vec()));
        let mut wire = Vec::new();
        let mut body = Vec::new();
        for _ in 0..50 {
            wire.extend(carry(&mut c, &mut csrc, &mut s, &mut ssrc));
            while let Some(mut step) = s.poll_rx(T0) {
                if step.event() == Some(Event::H1Server(H1s::Request)) {
                    let RoleMut::H1Server(srv) = step.conn().role_mut() else {
                        panic!("not h1");
                    };
                    srv.respond(Response {
                        status: 200,
                        content_type: None,
                        content_length: None,
                    })
                    .unwrap();
                    step.request_write();
                }
            }
            wire.extend(carry(&mut s, &mut ssrc, &mut c, &mut csrc));
            if ssrc.0.is_empty() {
                if let RoleMut::H1Server(srv) = s.conn().role_mut() {
                    srv.complete(T0);
                }
            }
            while let Some(step) = c.poll_rx(T0) {
                if let Some(Event::H1Client(H1c::Body(b))) = step.event() {
                    body.extend_from_slice(b);
                }
            }
        }
        assert_eq!(body, b"ok");
        // the server closed with a close_notify, which ended the body
        assert!(matches!(s.want(T0, &mut ssrc), Want::HalfClose));
        assert!(matches!(
            c.want(T0, &mut csrc),
            Want::Release(Outcome::Delivered)
        ));
        // and none of it went as plaintext
        assert!(!wire.windows(5).any(|w| w == b"GET /"));
        assert!(!wire.windows(8).any(|w| w == b"HTTP/1.1"));
    }

    #[test]
    fn nothing_of_the_connection_goes_before_the_handshake() {
        let mut c = tls(client(), Toy::new(Side::Client));
        let Want::Io(io) = c.want(T0, &mut Text(Vec::new())) else {
            panic!("not io");
        };
        // the hello only: the request is not pulled until the handshake
        // is done
        let mut hello = [0u8; 7];
        let mut at = 0;
        assert!(record(&mut hello, &mut at, HANDSHAKE, b"hello"));
        assert_eq!(io.write, Some(&hello[..]));
    }

    #[test]
    fn a_handshake_done_on_its_first_step_takes_the_same_path() {
        let mut c = tls(client(), Toy::established(Side::Client));
        let Want::Io(io) = c.want(T0, &mut Text(Vec::new())) else {
            panic!("not io");
        };
        // the request goes at once, sealed, with no deadline but its own
        let w = io.write.unwrap();
        assert_eq!(w[0], DATA);
        assert_eq!(io.until, c.conn.next_deadline());
    }

    #[test]
    fn a_handshake_not_done_in_time_is_dropped() {
        // a server whose own deadline is later than the handshake's
        let t = npro_h1::server::Timeouts {
            head: Duration::from_secs(60),
            ..npro_h1::server::Timeouts::DEFAULT
        };
        let srv = Server::new(vec![0u8; 1024], Config::default().with_timeouts(t), T0);
        let mut s = tls(Conn::h1_server(srv.unwrap()), Toy::new(Side::Server));
        let at = T0.checked_add(HANDSHAKE_TIMEOUT).unwrap();
        let Want::Io(io) = s.want(T0, &mut Text(Vec::new())) else {
            panic!("not io");
        };
        assert_eq!(io.until, Some(at));
        s.timer(at);
        assert!(matches!(
            s.want(at, &mut Text(Vec::new())),
            Want::Release(Outcome::Dropped)
        ));
    }

    #[test]
    fn a_clients_wait_for_its_answer_starts_once_tls_is_up() {
        let mut c = tls(client(), Toy::new(Side::Client));
        let mut src = Text(Vec::new());
        let _ = c.want(T0, &mut src);
        assert_eq!(c.conn.next_deadline(), None);
        // the server's answer establishes it, at T0 + 1s
        let t1 = T0.checked_add(Duration::from_secs(1)).unwrap();
        let mut olleh = [0u8; 7];
        let mut at = 0;
        assert!(record(&mut olleh, &mut at, HANDSHAKE, b"olleh"));
        let Want::Io(io) = c.want(T0, &mut src) else {
            panic!("not io");
        };
        let hello = io.write.map_or(0, <[u8]>::len);
        c.write_done(T0, hello);
        assert_eq!(c.received(t1, &olleh), 7);
        let _ = c.want(t1, &mut src);
        assert_eq!(
            c.conn.next_deadline(),
            t1.checked_add(npro_h1::client::RESPONSE_TIMEOUT)
        );
    }

    #[test]
    fn a_record_that_does_not_open_drops_the_connection() {
        let mut s = tls(server(), Toy::new(Side::Server));
        assert_eq!(s.received(T0, &[DATA, 1, 0]), 3);
        assert!(matches!(
            s.want(T0, &mut Text(Vec::new())),
            Want::Release(Outcome::Dropped)
        ));
        // failed, the record layer is not asked again, whatever comes
        assert_eq!(s.received(T0, &[DATA, 1, 0]), 3);
        assert!(matches!(
            s.want(T0, &mut Text(Vec::new())),
            Want::Release(Outcome::Dropped)
        ));
        assert_eq!(s.tls().unwrap().asked_again, 0);
    }
}
