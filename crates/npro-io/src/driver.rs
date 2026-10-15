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
//! use npro_h1::Storage;
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
//!     Conn::h1_server(Server::new(Storage { table: [0u8; 1024], out: [0u8; 1024] }, Config::default(), now)?);
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
//!     if step.event() == Event::H1Server(H1::Request) {
//!         let RoleMut::H1Server(s) = step.conn().role_mut() else { unreachable!() };
//!         s.respond(Response { status: 200, content_type: None, content_length: Some(2), headers: &[] })?;
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

/// A step of [`Driver::poll_rx`]: an event the connection made of the
/// bytes, with the connection to act on.
#[derive(Debug)]
pub struct Step<'d, S, R> {
    event: Event<'d>,
    conn: &'d mut Conn<S, R>,
    write: &'d mut Write,
}

impl<'d, S, R> Step<'d, S, R> {
    /// The event.  It borrows the driver's buffers, not the connection.
    #[must_use]
    pub const fn event(&self) -> Event<'d> {
        self.event
    }

    /// The connection, to answer with.
    pub const fn conn(&mut self) -> &mut Conn<S, R> {
        self.conn
    }

    /// The event and the connection, for as long as the step's borrow of
    /// the driver: for a caller handing them on together, as npro-ss gives
    /// its application an event with a handle on the connection.
    #[must_use]
    pub const fn into_parts(self) -> (Event<'d>, &'d mut Conn<S, R>) {
        (self.event, self.conn)
    }

    /// The application has payload to write: [`Driver::request_write`].
    pub const fn request_write(&mut self) {
        *self.write = Write::Wanted;
    }
}

/// An event found by [`Driver::poll_rx`], its bytes taken out, and where
/// they are.
#[derive(Clone, Copy, Debug)]
struct Found {
    event: Event<'static>,
    at: At,
}

/// Where an event's bytes are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum At {
    /// It carries none.
    Nowhere,
    /// In the rx buffer, at this window of what was given the connection.
    Rx(Window),
    /// In the inflate buffer, at this window of it.
    Inflate(Window),
    /// In neither: never so, as the roles give back what they were given.
    Lost,
}

/// Where a buffer was when the connection was given it: its address and
/// length, to find the bytes of an event in it once it is no longer
/// borrowed.  Addresses are compared, never used to reach memory.
#[derive(Clone, Copy, Debug)]
struct Place {
    addr: usize,
    len: usize,
}

impl Place {
    fn of(b: &[u8]) -> Self {
        Self {
            addr: b.as_ptr().addr(),
            len: b.len(),
        }
    }

    /// Where `d` lies in the buffer, if it lies wholly in it.
    fn find(self, d: &[u8]) -> Option<Window> {
        let start = d.as_ptr().addr().checked_sub(self.addr)?;
        let end = start.checked_add(d.len())?;
        (end <= self.len).then_some(Window { start, end })
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
    /// Plaintext bytes the roles wrote, since the connection was made.
    sent: u64,
}

impl<S, R, B> Driver<S, R, B, NoTls> {
    /// Carries `conn`, with `bufs`, the socket's bytes being the
    /// connection's.
    #[must_use]
    pub const fn new(conn: Conn<S, R>, bufs: Buffers<B>) -> Self {
        Self::plain(conn, bufs)
    }
}

impl<S, R, B, T> Driver<S, R, B, T> {
    /// Carries `conn`, with `bufs`, the socket's bytes being the
    /// connection's, in a driver whose type has room for tls: where some
    /// connections are tls and some not, as a server's listeners may be,
    /// and all are one type.  [`Driver::new`] is the same with no tls.
    ///
    /// ```
    /// use npro_core::random::SeededRandom;
    /// use npro_core::time::Instant;
    /// use npro_h1::Storage;
    /// use npro_h1::server::{Config, Server};
    /// use npro_io::conn::Conn;
    /// use npro_io::driver::{Buffers, Driver};
    /// use npro_io::tls::NoTls;
    ///
    /// let now = Instant::from_micros(1_000_000);
    /// let s = Server::new(Storage { table: vec![0u8; 1024], out: vec![0u8; 512] }, Config::default(), now)?;
    /// let conn: Conn<_, SeededRandom> = Conn::h1_server(s);
    /// let bufs = Buffers { rx: vec![0u8; 256], tx: vec![0u8; 256], inflate: Vec::new() };
    /// let d: Driver<_, _, _, NoTls> = Driver::plain(conn, bufs);
    /// assert!(d.tls().is_none());
    /// # Ok::<(), Box<dyn core::error::Error>>(())
    /// ```
    #[must_use]
    pub const fn plain(conn: Conn<S, R>, bufs: Buffers<B>) -> Self {
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
            sent: 0,
        }
    }

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
            sent: 0,
        }
    }

    /// How many bytes the connection's roles have written since it was
    /// made: the plaintext, heads and payload alike, before any tls, as
    /// C's `lws_write()` counts them for the access log.  A host marks it
    /// at a request, and the difference at the transaction's end is what
    /// the answer took.
    #[must_use]
    pub const fn sent(&self) -> u64 {
        self.sent
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

    /// The driver done with, taken apart: the connection, the buffers and,
    /// over tls, the record layer and its buffers, so storage the caller
    /// gave can carry the next connection.  What the buffers held is
    /// dropped with them.
    ///
    /// ```
    /// use npro_core::random::SeededRandom;
    /// use npro_core::time::Instant;
    /// use npro_h1::Storage;
    /// use npro_h1::server::{Config, Server};
    /// use npro_io::conn::Conn;
    /// use npro_io::driver::{Buffers, Driver};
    ///
    /// let now = Instant::from_micros(1_000_000);
    /// let s = Server::new(Storage { table: vec![0u8; 1024], out: vec![0u8; 512] }, Config::default(), now)?;
    /// let conn: Conn<_, SeededRandom> = Conn::h1_server(s);
    /// let d = Driver::new(conn, Buffers { rx: vec![0u8; 256], tx: vec![0u8; 256], inflate: Vec::new() });
    /// let parts = d.into_parts();
    /// assert_eq!(parts.bufs.rx.len(), 256);
    /// assert!(parts.tls.is_none());
    /// # Ok::<(), Box<dyn core::error::Error>>(())
    /// ```
    #[must_use]
    pub fn into_parts(self) -> Parts<S, R, B, T> {
        Parts {
            conn: self.conn,
            bufs: self.bufs,
            tls: match self.wire {
                Wire::Plain => None,
                Wire::Tls(t) => Some((t.layer, t.net)),
            },
        }
    }
}

/// A driver taken apart: [`Driver::into_parts`].
#[derive(Clone, Debug)]
pub struct Parts<S, R, B, T> {
    /// The connection.
    pub conn: Conn<S, R>,
    /// Its buffers.
    pub bufs: Buffers<B>,
    /// Over tls, the record layer and the buffers of its records.
    pub tls: Option<(T, NetBuffers<B>)>,
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

    /// Whether a pull now would have room for the application's payload:
    /// the connection is live, over tls the handshake is done, and the tx
    /// buffer is not full.  For a caller deciding whether to offer its
    /// application the chance to write, as C's `POLLOUT` does, rather
    /// than leaving it to [`Driver::want`].
    #[must_use]
    pub fn is_writable(&self) -> bool {
        let up = match &self.wire {
            Wire::Plain => true,
            Wire::Tls(t) => t.handshake == Handshake::Done,
        };
        let held = self.tx.end.saturating_sub(self.tx.start);
        up && self.stage == Stage::Live && held < self.bufs.tx.as_ref().len()
    }

    /// Lets go of what the last step took.
    const fn let_go(&mut self) {
        self.rx.start = self.rx.start.saturating_add(self.taken);
        self.taken = 0;
        if self.rx.start > self.rx.end {
            self.rx.start = self.rx.end;
        }
    }

    /// Gives the connection what was read until it comes to an event,
    /// returned as a step with the connection to answer it: `None` once it
    /// takes nothing more for now.  Bytes that came to nothing yet (a head
    /// not yet whole, a ping answered) are taken on the way.  Call it until
    /// it gives `None` after reading, before [`Driver::want`]: what it does
    /// not take, the connection holds.
    ///
    /// Once all before it was taken, the peer's FIN is passed on, which
    /// may itself be an event, an h1 client's body ending with the close.
    pub fn poll_rx(&mut self, now: Instant) -> Option<Step<'_, S, R>> {
        self.let_go();
        if !matches!(self.stage, Stage::Live) {
            return None;
        }
        // An event borrows the buffers, so one cannot be returned from
        // inside the loop that takes the steps coming to none: the borrow
        // would outlast the loop's next turn.  The step is found in the
        // loop, where its bytes are, and the event made again from them
        // after it.
        let found = loop {
            let input = self
                .bufs
                .rx
                .as_mut()
                .get_mut(self.rx.start..self.rx.end)
                .unwrap_or_default();
            if input.is_empty() && !self.conn.rx_pending() {
                if self.fin != Fin::Seen {
                    return None;
                }
                self.fin = Fin::Told;
                break Found {
                    event: self.conn.rx_closed(now)?,
                    at: At::Nowhere,
                };
            }
            let rx_at = Place::of(input);
            let out = self.bufs.inflate.as_mut();
            let out_at = Place::of(out);
            let r = self.conn.rx(now, input, out);
            let consumed = r.consumed;
            let found = r.event.map(|e| Found {
                event: e.with_data(&[]),
                at: e.data().filter(|d| !d.is_empty()).map_or(At::Nowhere, |d| {
                    rx_at
                        .find(d)
                        .map(At::Rx)
                        .or_else(|| out_at.find(d).map(At::Inflate))
                        .unwrap_or(At::Lost)
                }),
            });
            match found {
                Some(f) => {
                    self.taken = consumed;
                    break f;
                }
                None if consumed == 0 => return None,
                None => {
                    self.taken = consumed;
                    self.let_go();
                }
            }
        };
        if found.at == At::Lost {
            // the role gave bytes from neither buffer: not to be trusted
            self.drop_all();
            return None;
        }
        let Self {
            conn,
            bufs,
            rx,
            write,
            ..
        } = self;
        // where they were found, so there still
        let data = match found.at {
            At::Nowhere | At::Lost => &[][..],
            At::Rx(w) => bufs
                .rx
                .as_ref()
                .get(rx.start..rx.end)
                .and_then(|b| b.get(w.start..w.end))
                .unwrap_or_default(),
            At::Inflate(w) => bufs
                .inflate
                .as_ref()
                .get(w.start..w.end)
                .unwrap_or_default(),
        };
        Some(Step {
            event: found.event.with_data(data),
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
        self.sent = self
            .sent
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
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
    /// [`SHUTDOWN_TIMEOUT`], unless it came already.
    pub fn half_closed(&mut self, now: Instant) {
        if self.stage == Stage::HalfCloseDue {
            self.stage = match self.fin {
                Fin::Open => Stage::HalfClosed {
                    until: now.saturating_add(SHUTDOWN_TIMEOUT),
                },
                // the FIN came already: in C the next read says so at once
                Fin::Seen | Fin::Told => Stage::Done(Outcome::Delivered),
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
    use crate::raw;
    use alloc::vec;
    use alloc::vec::Vec;
    use npro_core::random::SeededRandom;
    use npro_h1::Storage;
    use npro_h1::client::Event as H1c;
    use npro_h1::client::{Client, Connection, Request, RequestBody, Scheme};
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
        let s = Server::new(
            Storage {
                table: vec![0u8; 1024],
                out: vec![0u8; 512],
            },
            Config::default(),
            T0,
        )
        .unwrap();
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
    fn answer(d: &mut D, now: Instant) -> Vec<Event<'static>> {
        let mut seen = Vec::new();
        while let Some(mut step) = d.poll_rx(now) {
            let ev = step.event();
            seen.push(match ev {
                Event::H1Server(H1::Request) => Event::H1Server(H1::Request),
                Event::H1Server(H1::BodyEnd) => Event::H1Server(H1::BodyEnd),
                Event::H1Server(H1::Body(_))
                | Event::H1Client(_)
                | Event::Ws(_)
                | Event::Raw(_) => Event::H1Server(H1::Body(b"")),
            });
            if ev == Event::H1Server(H1::Request) {
                let RoleMut::H1Server(s) = step.conn().role_mut() else {
                    panic!("not h1");
                };
                s.respond(Response {
                    status: 200,
                    content_type: None,
                    content_length: Some(2),
                    headers: &[],
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
        assert_eq!(answer(&mut d, T0), [Event::H1Server(H1::Request)]);
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
    fn a_server_whose_peer_closed_first_does_not_wait_for_its_fin() {
        let mut d = server(256, 256);
        read(&mut d, T0, &mut nothing(), b"GET / HTTP/1.1\r\n\r\n");
        answer(&mut d, T0);
        // the peer's FIN, after its request: what was composed goes, and
        // the server shuts down, as C's does
        d.read_done(T0, 0);
        answer(&mut d, T0);
        let wrote = write(&mut d, T0, &mut nothing(), 1024);
        assert!(wrote.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(matches!(d.want(T0, &mut nothing()), Want::HalfClose));
        d.half_closed(T0);
        assert!(matches!(
            d.want(T0, &mut nothing()),
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
    fn a_request_body_ending_with_the_read_is_ended() {
        for (req, seen) in [
            (
                &b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nok"[..],
                &[
                    Event::H1Server(H1::Request),
                    Event::H1Server(H1::Body(b"")),
                    Event::H1Server(H1::BodyEnd),
                ][..],
            ),
            (
                b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
                &[Event::H1Server(H1::Request), Event::H1Server(H1::BodyEnd)],
            ),
        ] {
            let mut d = server(256, 256);
            assert_eq!(read(&mut d, T0, &mut nothing(), req), req.len());
            let got = answer(&mut d, T0);
            assert_eq!(got, seen, "{}", req.escape_ascii());
        }
    }

    #[test]
    fn a_response_body_ending_with_the_read_is_ended() {
        let c = Client::new(
            Storage {
                table: vec![0u8; 1024],
                out: vec![0u8; 512],
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
        .unwrap();
        let mut d: D = Driver::new(Conn::h1_client(c), bufs(256, 256));
        assert_ne!(write(&mut d, T0, &mut nothing(), 1024), b"");
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        assert_eq!(read(&mut d, T0, &mut nothing(), resp), resp.len());
        let mut ended = false;
        while let Some(step) = d.poll_rx(T0) {
            ended |= step.event() == Event::H1Client(H1c::BodyEnd);
        }
        // with no FIN: the length ended it
        assert!(ended);
        // and as C, the connection waits for the server's close
        assert!(matches!(d.want(T0, &mut nothing()), Want::Io(_)));
        d.read_done(T0, 0);
        while d.poll_rx(T0).is_some() {}
        assert!(matches!(
            d.want(T0, &mut nothing()),
            Want::Release(Outcome::Delivered)
        ));
    }

    #[test]
    fn a_warm_client_connection_takes_the_next_request() {
        let req = |path| Request {
            method: b"GET",
            path,
            host: None,
            origin: None,
            scheme: Scheme::Http,
            no_cache: false,
            connection: Connection::KeepAlive,
            headers: &[],
            body: RequestBody::None,
        };
        let c = Client::new(
            Storage {
                table: vec![0u8; 1024],
                out: vec![0u8; 512],
            },
            req(b"/one"),
        )
        .unwrap();
        let mut d: D = Driver::new(Conn::h1_client(c), bufs(256, 256));
        let ended = |drv: &mut D| {
            let mut ended = false;
            while let Some(step) = drv.poll_rx(T0) {
                ended |= step.event() == Event::H1Client(H1c::BodyEnd);
            }
            ended
        };
        assert_eq!(
            write(&mut d, T0, &mut nothing(), 1024),
            b"GET /one HTTP/1.1\r\n\r\n"
        );
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        assert_eq!(read(&mut d, T0, &mut nothing(), resp), resp.len());
        assert!(ended(&mut d));
        // kept warm for C's 5s, and not released
        let Want::Io(io) = d.want(T0, &mut nothing()) else {
            panic!("released");
        };
        assert_eq!(io.until, Some(at(5)));

        let RoleMut::H1Client(cl) = d.conn().role_mut() else {
            panic!("not h1");
        };
        cl.next(req(b"/two")).unwrap();
        assert_eq!(
            write(&mut d, T0, &mut nothing(), 1024),
            b"GET /two HTTP/1.1\r\n\r\n"
        );
        assert_eq!(read(&mut d, T0, &mut nothing(), resp), resp.len());
        assert!(ended(&mut d));

        // nothing more: released when the time is up
        d.timer(at(4));
        assert!(matches!(d.want(at(4), &mut nothing()), Want::Io(_)));
        d.timer(at(5));
        assert!(matches!(
            d.want(at(5), &mut nothing()),
            Want::Release(Outcome::Delivered)
        ));
    }

    #[test]
    fn the_fin_comes_after_what_came_before_it() {
        let c = Client::new(
            Storage {
                table: vec![0u8; 1024],
                out: vec![0u8; 512],
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
            if let Event::H1Client(e) = step.event() {
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
        // the head is taken into the table as it comes, making room, with
        // nothing to tell yet
        assert_eq!(answer(&mut d, T0), []);
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

    #[test]
    fn writable_while_live_with_room_in_the_tx_buffer() {
        let mut d = server(256, 64);
        assert!(d.is_writable());
        read(&mut d, T0, &mut nothing(), b"GET / HTTP/1.1\r\n\r\n");
        while let Some(mut step) = d.poll_rx(T0) {
            let RoleMut::H1Server(s) = step.conn().role_mut() else {
                panic!("not h1");
            };
            if s.is_awaiting_answer() {
                s.respond(Response {
                    status: 200,
                    content_type: None,
                    content_length: Some(200),
                    headers: &[],
                })
                .unwrap();
            }
        }
        // the head and payload fill the tx buffer: no room until some went
        let mut big = Text(vec![b'x'; 200]);
        d.request_write();
        let Want::Io(io) = d.want(T0, &mut big) else {
            panic!("not io");
        };
        assert_eq!(io.write.map(<[u8]>::len), Some(64));
        assert!(!d.is_writable());
        d.write_done(T0, 1);
        assert!(d.is_writable());
        // closing, it is not
        d.hangup(T0);
        assert!(!d.is_writable());
    }

    #[test]
    fn a_steps_event_and_connection_go_on_together() {
        let mut d = server(256, 256);
        read(&mut d, T0, &mut nothing(), b"GET / HTTP/1.1\r\n\r\n");
        let step = d.poll_rx(T0).unwrap();
        let (event, conn) = step.into_parts();
        assert_eq!(event, Event::H1Server(H1::Request));
        let RoleMut::H1Server(s) = conn.role_mut() else {
            panic!("not h1");
        };
        assert!(s.is_awaiting_answer());
    }

    #[test]
    fn taken_apart_the_buffers_come_back() {
        let mut d = server(32, 48);
        read(&mut d, T0, &mut nothing(), b"GET / HTTP/1.1\r\n\r\n");
        d.hangup(T0);
        assert!(matches!(d.want(T0, &mut nothing()), Want::Release(_)));
        let p = d.into_parts();
        assert_eq!((p.bufs.rx.len(), p.bufs.tx.len()), (32, 48));
        let storage = p.conn.into_storage().unwrap();
        assert_eq!((storage.table.len(), storage.out.len()), (1024, 512));
    }

    #[test]
    fn a_switched_connection_carries_raw_bytes_from_the_ones_behind_its_head() {
        let mut d = server(256, 256);
        let mut app = nothing();
        let wire = b"GET / HTTP/1.1\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\nfirst";
        assert_eq!(read(&mut d, T0, &mut app, wire), wire.len());
        let mut requests = 0;
        while let Some(mut step) = d.poll_rx(T0) {
            if step.event() == Event::H1Server(H1::Request) {
                requests += 1;
                let RoleMut::H1Server(s) = step.conn().role_mut() else {
                    panic!("not h1");
                };
                s.switch(T0, b"x", &[]).unwrap();
            }
        }
        assert_eq!(requests, 1);
        let out = write(&mut d, T0, &mut app, 1024);
        assert!(out.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
        d.conn().switch_raw().unwrap();
        // the bytes that came behind the head, held while it was h1
        let mut got = Vec::new();
        while let Some(step) = d.poll_rx(T0) {
            if let Event::Raw(raw::Event::Data(b)) = step.event() {
                got.extend_from_slice(b);
            }
        }
        assert_eq!(got, b"first");
        // the application's bytes go as they are
        let mut reply = Text(b"back".to_vec());
        d.request_write();
        assert_eq!(write(&mut d, T0, &mut reply, 1024), b"back");
        // the peer's close is told, and passed on as a shutdown
        d.read_done(T0, 0);
        let mut closed = false;
        while let Some(mut step) = d.poll_rx(T0) {
            if step.event() == Event::Raw(raw::Event::PeerClosed) {
                closed = true;
                let RoleMut::Raw(r) = step.conn().role_mut() else {
                    panic!("not raw");
                };
                r.close(Close::Shutdown);
            }
        }
        assert!(closed);
        assert!(matches!(d.want(T0, &mut app), Want::HalfClose));
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
    use npro_h1::Storage;
    use npro_h1::client::{Client, Connection, Event as H1c, Request, RequestBody, Scheme};
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
        client_with(b"GET", RequestBody::None)
    }

    fn client_with(method: &[u8], body: RequestBody) -> Conn<Vec<u8>, SeededRandom> {
        Conn::h1_client(
            Client::new(
                Storage {
                    table: vec![0u8; 1024],
                    out: vec![0u8; 512],
                },
                Request {
                    method,
                    path: b"/",
                    host: Some(b"x"),
                    origin: None,
                    scheme: Scheme::Https,
                    no_cache: false,
                    connection: Connection::Close,
                    headers: &[],
                    body,
                },
            )
            .unwrap(),
        )
    }

    fn server() -> Conn<Vec<u8>, SeededRandom> {
        Conn::h1_server(
            Server::new(
                Storage {
                    table: vec![0u8; 1024],
                    out: vec![0u8; 512],
                },
                Config::default(),
                T0,
            )
            .unwrap(),
        )
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

    /// Moves what `from` writes into `to`, a few bytes at a time, while
    /// `to` has room; what went.  Once `to` is gone, the next piece is
    /// written and lost.
    fn carry(from: &mut D, src: &mut Text, to: &mut D, sink: &mut Text) -> Vec<u8> {
        let mut went = Vec::new();
        loop {
            let Want::Io(io) = from.want(T0, src) else {
                return went;
            };
            let Some(w) = io.write else {
                return went;
            };
            let bytes = w[..w.len().min(5)].to_vec();
            let Want::Io(into) = to.want(T0, sink) else {
                // `to` is gone: what was written to it is lost, as on a
                // socket the peer has closed
                from.write_done(T0, bytes.len());
                return went;
            };
            // what `to` has not taken is back-pressure: the rest waits
            let Some(room) = into.read else {
                return went;
            };
            let n = bytes.len().min(room.len());
            room[..n].copy_from_slice(&bytes[..n]);
            to.read_done(T0, n);
            from.write_done(T0, n);
            went.extend_from_slice(&bytes[..n]);
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
                if step.event() == Event::H1Server(H1s::Request) {
                    let RoleMut::H1Server(srv) = step.conn().role_mut() else {
                        panic!("not h1");
                    };
                    srv.respond(Response {
                        status: 200,
                        content_type: None,
                        content_length: None,
                        headers: &[],
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
                if let Event::H1Client(H1c::Body(b)) = step.event() {
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
    fn an_h1_clients_body_is_pulled_through_the_driver() {
        let sent: Vec<u8> = (0..=255u8).cycle().take(700).collect();
        for body in [RequestBody::Length(700), RequestBody::Chunked] {
            let (mut c, mut s) = (
                tls(client_with(b"POST", body), Toy::new(Side::Client)),
                tls(server(), Toy::new(Side::Server)),
            );
            if body == RequestBody::Chunked {
                let RoleMut::H1Client(cl) = c.conn().role_mut() else {
                    panic!("not h1");
                };
                cl.chunk(700, true).unwrap();
            }
            let (mut csrc, mut ssrc) = (Text(sent.clone()), Text(Vec::new()));
            c.request_write();
            let mut got = Vec::new();
            let mut wire = Vec::new();
            let mut ended = false;
            for _ in 0..200 {
                wire.extend(carry(&mut c, &mut csrc, &mut s, &mut ssrc));
                while let Some(step) = s.poll_rx(T0) {
                    match step.event() {
                        Event::H1Server(H1s::Body(b)) => got.extend_from_slice(b),
                        Event::H1Server(H1s::BodyEnd) => ended = true,
                        Event::H1Server(H1s::Request)
                        | Event::H1Client(_)
                        | Event::Ws(_)
                        | Event::Raw(_) => {}
                    }
                }
                if ended {
                    break;
                }
                // the server's half of the handshake
                wire.extend(carry(&mut s, &mut ssrc, &mut c, &mut csrc));
                while c.poll_rx(T0).is_some() {}
            }
            assert!(ended, "{body:?}");
            assert_eq!(got, sent, "{body:?}");
            assert_eq!(csrc.0, b"");
            // and it went sealed
            assert!(!wire.windows(6).any(|w| w == b"POST /"));
        }
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
        let srv = Server::new(
            Storage {
                table: vec![0u8; 1024],
                out: vec![0u8; 512],
            },
            Config::default().with_timeouts(t),
            T0,
        );
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
    fn not_writable_before_the_handshake_and_the_layer_comes_back() {
        let s = tls(server(), Toy::new(Side::Server));
        assert!(!s.is_writable());
        let mut e = tls(server(), Toy::established(Side::Server));
        e.want(T0, &mut Text(Vec::new()));
        assert!(e.is_writable());
        let p = e.into_parts();
        let (layer, net) = p.tls.unwrap();
        assert!(layer.is_established());
        assert_eq!(net.rx.len(), 256);
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
