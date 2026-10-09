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

/// One connection, its buffers in `B`: see the module's description.
#[derive(Clone, Debug)]
pub struct Driver<S, R, B> {
    conn: Conn<S, R>,
    bufs: Buffers<B>,
    /// What of `bufs.rx` is read and not yet taken.
    rx: Window,
    /// What the last step took, let go at the next call: until then its
    /// event may borrow it.
    taken: usize,
    /// What of `bufs.tx` is pulled and not yet written.
    tx: Window,
    write: Write,
    fin: Fin,
    stage: Stage,
}

impl<S, R, B> Driver<S, R, B>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Carries `conn`, with `bufs`.
    #[must_use]
    pub fn new(conn: Conn<S, R>, bufs: Buffers<B>) -> Self {
        Self {
            conn,
            bufs,
            rx: Window::default(),
            taken: 0,
            tx: Window::default(),
            write: Write::Idle,
            fin: Fin::Open,
            stage: Stage::Live,
        }
    }

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
        self.pull(now, src);
        self.settle(now);
        let until = match self.stage {
            Stage::Done(o) => return Want::Release(o),
            Stage::HalfCloseDue => return Want::HalfClose,
            Stage::Live => self.conn.next_deadline(),
            Stage::Flushing { until, .. } | Stage::HalfClosed { until } => Some(until),
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
        let Self { bufs, rx, tx, .. } = self;
        let read = bufs
            .rx
            .as_mut()
            .get_mut(rx.end..)
            .filter(|r| reading && !r.is_empty());
        let write = bufs
            .tx
            .as_ref()
            .get(tx.start..tx.end)
            .filter(|w| !w.is_empty());
        Want::Io(Io { read, write, until })
    }

    /// Pulls what the connection owes, and the application's payload if
    /// it asked to write, into the tx buffer.
    fn pull(&mut self, now: Instant, src: &mut dyn TxSource) {
        if !matches!(self.stage, Stage::Live | Stage::Flushing { .. }) {
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

    /// Moves the close along: the connection asking to close, what it
    /// wrote having gone.
    fn settle(&mut self, now: Instant) {
        if self.stage == Stage::Live {
            match self.conn.close() {
                None => {}
                Some(Close::Abort) => self.drop_all(),
                Some(close @ (Close::Shutdown | Close::Release)) => {
                    self.stage = Stage::Flushing {
                        close,
                        until: now.saturating_add(FLUSH_TIMEOUT),
                    };
                }
            }
        }
        if let Stage::Flushing { close, .. } = self.stage {
            if self.tx.is_empty() && !self.conn.wants_write() {
                self.stage = match close {
                    Close::Shutdown => Stage::HalfCloseDue,
                    Close::Release | Close::Abort => Stage::Done(Outcome::Delivered),
                };
            }
        }
    }

    /// Ends the connection with what is unwritten dropped.
    const fn drop_all(&mut self) {
        self.tx = Window { start: 0, end: 0 };
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
        let room = self.bufs.rx.as_ref().len().saturating_sub(self.rx.end);
        self.rx.end = self.rx.end.saturating_add(n.min(room));
        self.drop_if_closing();
    }

    /// Bytes read elsewhere, copied in at `now`, as far as there is room:
    /// returns how many were taken, the rest to be handed in again once
    /// [`Driver::want`] offers to read.  For an adapter that reads into a
    /// buffer of its own, as threads blocking in `read()` must.  An empty
    /// `bytes` is nothing, not the FIN: that is [`Driver::read_done`] with
    /// 0.
    pub fn received(&mut self, _now: Instant, bytes: &[u8]) -> usize {
        self.let_go();
        if self.stage != Stage::Live {
            // closing: read and dropped
            return bytes.len();
        }
        self.rx.compact(self.bufs.rx.as_mut());
        let room = self
            .bufs
            .rx
            .as_mut()
            .get_mut(self.rx.end..)
            .unwrap_or_default();
        let n = bytes.len().min(room.len());
        if let (Some(d), Some(s)) = (room.get_mut(..n), bytes.get(..n)) {
            d.copy_from_slice(s);
        }
        self.rx.end = self.rx.end.saturating_add(n);
        n
    }

    /// A closing connection takes nothing more: what comes is dropped.
    const fn drop_if_closing(&mut self) {
        if !matches!(self.stage, Stage::Live) {
            self.rx = Window { start: 0, end: 0 };
        }
    }

    /// The peer's FIN came.
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
    pub const fn write_done(&mut self, _now: Instant, n: usize) {
        let left = self.tx.end.saturating_sub(self.tx.start);
        self.tx.start = self
            .tx
            .start
            .saturating_add(if n < left { n } else { left });
        if self.tx.is_empty() {
            self.tx = Window { start: 0, end: 0 };
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
        let delivered = self.tx.is_empty() && !self.conn.wants_write();
        self.tx = Window::default();
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
