//! The threads adapter: a [`Host`]'s connections over std's sockets, with
//! blocking calls, a reader and a writer thread for each.
//!
//! It is the first of the adapters in `docs/io-model.md`, std and nothing
//! else, for a program that needs little scale: npro's utility to begin
//! with.  [`serve`] accepts on the host's listeners and carries each
//! connection:
//!
//! - **the host, and the application, behind one `Mutex`**, which is the
//!   adapter's to hold, never a protocol crate's.  After every call that
//!   may have changed something, the application is given the host to
//!   act on ([`serve`]'s `app`), under the same lock, and every thread
//!   waiting on the host is woken;
//! - **the reader** blocks in `read()` into its own buffer, and hands what
//!   came to the host ([`Host::received`]).  When the host has no room,
//!   it waits for the application to take some: the socket is not read,
//!   and the peer is held back by TCP's window, as in C;
//! - **the writer** waits until the host has something to write, or a
//!   deadline is due, then writes what it has, outside the lock, from a
//!   copy, since a blocking write cannot hold it.  It half-closes and
//!   closes the socket as the host asks, which wakes the reader;
//! - **listeners** are TCP, or with unix, unix domain sockets, by the
//!   address forms [`bind`] takes;
//! - **jobs** are what the application must not do on its turn, since
//!   that holds the lock: a file read, say.  It gives one to [`Jobs`],
//!   a worker thread does it, and what it came to is applied to the host
//!   under the lock, followed by the application's turn, as C's
//!   `LWS_WITH_ASYNC_QUEUE` takes the file server's reads off the service
//!   thread.
//!
//! Time is std's monotonic clock, as [`Clock`] gives it.  tls is the
//! host's: the adapter makes each connection's record layer as `tls`
//! says, and hands it over on accepting.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, Scope};

use npro_core::time::Instant;

use crate::driver::Want;
use crate::host::Host;

/// How much the reader reads, and the writer writes, at a time.
const CHUNK: usize = 4096;

/// How long an acceptor waits after `accept()` failed (too many files
/// open, say) before it tries again, and how often an idle worker looks
/// whether it is stopped.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// What a job comes to: applied to the host, under the lock, before the
/// application's turn.
pub type Done<'j, H> = Box<dyn FnOnce(&mut H, Instant) + Send + 'j>;

/// A job: done on a worker thread, with no lock held.
type Job<'j, H> = Box<dyn FnOnce() -> Done<'j, H> + Send + 'j>;

/// Where the application gives the adapter work to do off its turn: see
/// the module's description.  It is given to the application on every
/// turn ([`serve`]'s `app`).
#[derive(Debug)]
pub struct Jobs<'j, H> {
    tx: Sender<Job<'j, H>>,
}

impl<'j, H> Jobs<'j, H> {
    /// Has `job` done on a worker thread, and what it comes to applied
    /// to the host, under the lock, with the application's turn after.
    /// `job` runs with no lock held, so it may block.  If the adapter is
    /// stopping, the job may never run.
    ///
    /// ```no_run
    /// # fn example<H>(jobs: &npro_io::threads::Jobs<'_, H>) {
    /// jobs.spawn(|| {
    ///     let bytes = std::fs::read("/etc/hostname").unwrap_or_default();
    ///     move |_host: &mut H, _now| drop(bytes)
    /// });
    /// # }
    /// ```
    pub fn spawn<F, G>(&self, job: F)
    where
        F: FnOnce() -> G + Send + 'j,
        G: FnOnce(&mut H, Instant) + Send + 'j,
    {
        // refused only once the adapter is stopping, when it is moot
        let boxed: Job<'j, H> = Box::new(move || {
            let done: Done<'j, H> = Box::new(job());
            done
        });
        if let Err(not_sent) = self.tx.send(boxed) {
            drop(not_sent);
        }
    }
}

/// std's monotonic clock, as npro's [`Instant`]: microseconds since the
/// clock was made, so that never goes backwards and never wraps.
///
/// ```
/// use npro_io::threads::Clock;
///
/// let c = Clock::new();
/// assert!(c.now() <= c.now());
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    start: std::time::Instant,
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock {
    /// A clock starting now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }

    /// It is now.
    #[must_use]
    pub fn now(&self) -> Instant {
        let us = u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX);
        Instant::from_micros(us)
    }

    /// How long from `now` until `until`, nothing if it has come.
    const fn until(now: Instant, until: Instant) -> Duration {
        Duration::from_micros(until.as_micros().saturating_sub(now.as_micros()))
    }
}

/// A listening socket.
#[derive(Debug)]
pub enum Listening {
    /// TCP.
    Tcp(TcpListener),
    /// A unix domain socket.
    #[cfg(unix)]
    Unix(UnixListener),
}

/// Binds a listener at `addr`: `unix:/path` for a unix domain socket,
/// whatever is at the path already taken away first, as C does; or an
/// address and port, `[::]:443`, `127.0.0.1:8080`, or a name and port,
/// resolved.
///
/// ```
/// use npro_io::threads::bind;
///
/// # if cfg!(miri) { return Ok(()); } // Miri has no sockets
/// let l = bind("127.0.0.1:0")?;
/// assert!(l.local_addr()?.is_some());
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Errors
///
/// The socket's, if it cannot be bound; an address it does not read is
/// `InvalidInput`.
pub fn bind(addr: &str) -> io::Result<Listening> {
    if let Some(path) = addr.strip_prefix("unix:") {
        return bind_unix(path);
    }
    let addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
    Ok(Listening::Tcp(TcpListener::bind(&addrs[..])?))
}

#[cfg(unix)]
fn bind_unix(path: &str) -> io::Result<Listening> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        Ok(()) | Err(_) => {}
    }
    Ok(Listening::Unix(UnixListener::bind(path)?))
}

#[cfg(not(unix))]
fn bind_unix(_: &str) -> io::Result<Listening> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no unix domain sockets here",
    ))
}

impl Listening {
    /// The TCP address it is bound to; `None` for a unix domain socket.
    ///
    /// # Errors
    ///
    /// The socket's.
    pub fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        match self {
            Self::Tcp(l) => l.local_addr().map(Some),
            #[cfg(unix)]
            Self::Unix(_) => Ok(None),
        }
    }

    fn accept(&self) -> io::Result<Socket> {
        match self {
            Self::Tcp(l) => l.accept().map(|(s, _)| Socket::Tcp(s)),
            #[cfg(unix)]
            Self::Unix(l) => l.accept().map(|(s, _)| Socket::Unix(s)),
        }
    }

    /// Wakes a thread blocked accepting on it, by connecting to it.
    fn wake(&self) {
        match self {
            Self::Tcp(l) => {
                if let Ok(mut a) = l.local_addr() {
                    // listening on every address: one of them is here
                    if a.ip().is_unspecified() {
                        a.set_ip(match a {
                            SocketAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
                            SocketAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
                        });
                    }
                    drop(TcpStream::connect(a));
                }
            }
            #[cfg(unix)]
            Self::Unix(l) => {
                if let Some(p) = l.local_addr().ok().as_ref().and_then(|a| a.as_pathname()) {
                    drop(UnixStream::connect(p));
                }
            }
        }
    }
}

/// A connected socket.
#[derive(Debug)]
enum Socket {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl Socket {
    fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(s) => s.try_clone().map(Self::Tcp),
            #[cfg(unix)]
            Self::Unix(s) => s.try_clone().map(Self::Unix),
        }
    }

    fn shutdown(&self, how: Shutdown) {
        // a socket the peer reset already is shut either way
        drop(match self {
            Self::Tcp(s) => s.shutdown(how),
            #[cfg(unix)]
            Self::Unix(s) => s.shutdown(how),
        });
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.read(buf),
        }
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.write(buf),
        }
    }
}

/// Stops [`serve`]: from another thread, or from the application.
///
/// ```
/// use npro_io::threads::Stop;
///
/// let s = Stop::new();
/// assert!(!s.is_stopping());
/// s.stop();
/// assert!(s.is_stopping());
/// ```
#[derive(Debug, Default)]
pub struct Stop {
    stopping: AtomicBool,
    /// The connections' sockets, to shut down, by an id of the adapter's.
    sockets: Mutex<Vec<(u64, Socket)>>,
    /// The listeners, to wake.
    listeners: Mutex<Vec<Listening>>,
    next: AtomicU64,
}

impl Stop {
    /// Not stopping yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether [`Stop::stop`] was called.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    /// Stops accepting, and shuts every connection's socket down, which
    /// the host is told as a hangup.  [`serve`] returns once each thread
    /// has seen it.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        for l in lock(&self.listeners).iter() {
            l.wake();
        }
        for (_, s) in lock(&self.sockets).iter() {
            s.shutdown(Shutdown::Both);
        }
    }

    /// Keeps a clone of a connection's socket, to shut down on stopping:
    /// its key, or `None` if stopping already.
    fn keep(&self, s: &Socket) -> Option<u64> {
        let clone = s.try_clone().ok()?;
        let mut all = lock(&self.sockets);
        if self.is_stopping() {
            return None;
        }
        let key = self.next.fetch_add(1, Ordering::Relaxed);
        all.push((key, clone));
        Some(key)
    }

    fn forget(&self, key: u64) {
        lock(&self.sockets).retain(|(k, _)| *k != key);
    }
}

/// Locks `m`, whatever a thread that panicked holding it left: nothing
/// in the adapter panics, and the host is never left half changed by one
/// of its own calls.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The host and the application, behind the lock.
struct State<H, A> {
    host: H,
    app: A,
}

/// What every thread shares.
struct Shared<'a, H, A> {
    state: Mutex<State<H, A>>,
    /// Something changed: woken after every turn of the application.
    changed: Condvar,
    clock: Clock,
    stop: &'a Stop,
    jobs: Jobs<'a, H>,
}

impl<'a, H: Host, A: FnMut(&mut H, Instant, &Jobs<'a, H>)> Shared<'a, H, A> {
    /// Gives the application its turn, then wakes whatever waits.
    fn acted(&self, s: &mut State<H, A>, now: Instant) {
        (s.app)(&mut s.host, now, &self.jobs);
        self.changed.notify_all();
    }
}

/// How many worker threads [`serve`] has for jobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Workers(pub usize);

impl Default for Workers {
    /// Two: enough that one slow read does not hold the rest.
    fn default() -> Self {
        Self(2)
    }
}

/// Carries `host`'s connections over std's sockets until `stop` is
/// stopped, then gives it back.
///
/// Each of `listeners` is accepted on, by a thread of its own; each
/// connection accepted gets its tls from `tls`, given its listener
/// (`None` for a plain one), and a reader and a writer thread.  After any
/// of them changed something, `app` is given the host, at that time, to
/// act on: to loop on the host's events, and answer them.  It runs under
/// the lock, so it must not block: what would, it gives to the [`Jobs`]
/// it is given, done by `workers` threads (at least one).
pub fn serve<'a, H, A, M>(
    host: H,
    listeners: Vec<(H::Listener, Listening)>,
    tls: M,
    app: A,
    workers: Workers,
    stop: &'a Stop,
) -> H
where
    H: Host + Send + 'a,
    H::Listener: Send,
    H::Conn: Send,
    A: FnMut(&mut H, Instant, &Jobs<'a, H>) + Send,
    M: Fn(H::Listener) -> Option<H::Tls> + Sync,
{
    let (tx, rx) = mpsc::channel::<Job<'a, H>>();
    let shared = Shared {
        state: Mutex::new(State { host, app }),
        changed: Condvar::new(),
        clock: Clock::new(),
        stop,
        jobs: Jobs { tx },
    };
    let mut accepting = Vec::new();
    for (id, l) in listeners {
        if let Ok(clone) = clone_listening(&l) {
            lock(&stop.listeners).push(clone);
        }
        accepting.push((id, l));
    }
    let rx = Mutex::new(rx);
    thread::scope(|scope| {
        for (id, l) in accepting {
            let (shared, tls) = (&shared, &tls);
            scope.spawn(move || accept(scope, shared, id, &l, tls));
        }
        for _ in 0..workers.0.max(1) {
            let (shared, rx) = (&shared, &rx);
            scope.spawn(move || work(shared, rx));
        }
    });
    lock(&stop.listeners).clear();
    shared
        .state
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
        .host
}

/// Does jobs as they come, until stopped: each with no lock held, then
/// what it came to applied under it.
fn work<'a, H, A>(shared: &Shared<'a, H, A>, rx: &Mutex<Receiver<Job<'a, H>>>)
where
    H: Host,
    A: FnMut(&mut H, Instant, &Jobs<'a, H>),
{
    loop {
        if shared.stop.is_stopping() {
            return;
        }
        let next = lock(rx).recv_timeout(ACCEPT_RETRY);
        let job = match next {
            Ok(j) => j,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let done = job();
        let mut s = lock(&shared.state);
        let now = shared.clock.now();
        done(&mut s.host, now);
        shared.acted(&mut s, now);
    }
}

fn clone_listening(l: &Listening) -> io::Result<Listening> {
    match l {
        Listening::Tcp(t) => t.try_clone().map(Listening::Tcp),
        #[cfg(unix)]
        Listening::Unix(u) => u.try_clone().map(Listening::Unix),
    }
}

/// Accepts on `l` until stopped, giving each connection to the host and
/// to a reader and a writer.
fn accept<'scope, 'a, H, A, M>(
    scope: &'scope Scope<'scope, '_>,
    shared: &'scope Shared<'a, H, A>,
    id: H::Listener,
    l: &Listening,
    tls: &M,
) where
    H: Host + Send,
    H::Listener: Send,
    H::Conn: Send,
    A: FnMut(&mut H, Instant, &Jobs<'a, H>) + Send,
    M: Fn(H::Listener) -> Option<H::Tls> + Sync,
{
    loop {
        if shared.stop.is_stopping() {
            return;
        }
        let accepted = l.accept();
        if shared.stop.is_stopping() {
            return;
        }
        let Ok(socket) = accepted else {
            thread::sleep(ACCEPT_RETRY);
            continue;
        };
        let (Ok(rd), Some(key)) = (socket.try_clone(), shared.stop.keep(&socket)) else {
            continue;
        };
        let conn = {
            let mut s = lock(&shared.state);
            let now = shared.clock.now();
            let Ok(conn) = s.host.accepted(now, id, tls(id)) else {
                // the host would not take it: it is closed
                shared.stop.forget(key);
                continue;
            };
            shared.acted(&mut s, now);
            conn
        };
        scope.spawn(move || read(shared, conn, rd));
        scope.spawn(move || {
            write(shared, conn, socket);
            shared.stop.forget(key);
        });
    }
}

/// Reads what the peer sends, and hands it to the host, until the peer's
/// FIN, a failure, or the connection is gone.
fn read<'a, H, A>(shared: &Shared<'a, H, A>, conn: H::Conn, mut socket: Socket)
where
    H: Host,
    A: FnMut(&mut H, Instant, &Jobs<'a, H>),
{
    let mut buf = [0u8; CHUNK];
    loop {
        let got = socket.read(&mut buf);
        let mut s = lock(&shared.state);
        let now = shared.clock.now();
        let n = match got {
            // stopping shuts the socket down: that is no FIN of the peer's
            Ok(_) if shared.stop.is_stopping() => {
                if s.host.hangup(now, conn).is_ok() {
                    shared.acted(&mut s, now);
                }
                return;
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                if s.host.hangup(now, conn).is_ok() {
                    shared.acted(&mut s, now);
                }
                return;
            }
        };
        if n == 0 {
            if s.host.read_done(now, conn, 0).is_ok() {
                shared.acted(&mut s, now);
            }
            return;
        }
        let mut rest = buf.get(..n).unwrap_or_default();
        loop {
            let at = shared.clock.now();
            let Ok(took) = s.host.received(at, conn, rest) else {
                return;
            };
            shared.acted(&mut s, at);
            rest = rest.get(took..).unwrap_or_default();
            if rest.is_empty() {
                break;
            }
            // no room: until the application takes some, the socket is
            // not read, and the peer is held back
            s = shared
                .changed
                .wait(s)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// What the writer does next, decided under the lock.
enum Next {
    /// Write the first `n` bytes of the copy.
    Write(usize),
    /// Half-close the socket.
    HalfClose,
    /// Close it: the connection is over.
    Release,
    /// Wait for a change, or until this long.
    Wait(Option<Duration>),
    /// A deadline came.
    Timer,
    /// The connection is gone.
    Gone,
}

/// Writes what the host has for the peer, keeps its deadlines, and
/// closes the socket as it asks, until the connection is gone.
fn write<'a, H, A>(shared: &Shared<'a, H, A>, conn: H::Conn, mut socket: Socket)
where
    H: Host,
    A: FnMut(&mut H, Instant, &Jobs<'a, H>),
{
    let mut out = [0u8; CHUNK];
    let mut s = lock(&shared.state);
    loop {
        let now = shared.clock.now();
        let next = match s.host.want(now, conn) {
            Err(_) => Next::Gone,
            Ok(Want::Release(_)) => Next::Release,
            Ok(Want::HalfClose) => Next::HalfClose,
            Ok(Want::Io(io)) => match (io.write, io.until) {
                (Some(w), _) => {
                    let n = w.len().min(out.len());
                    if let (Some(to), Some(from)) = (out.get_mut(..n), w.get(..n)) {
                        to.copy_from_slice(from);
                    }
                    Next::Write(n)
                }
                (None, Some(u)) if u <= now => Next::Timer,
                (None, until) => Next::Wait(until.map(|u| Clock::until(now, u))),
            },
        };
        match next {
            Next::Gone => return,
            Next::Release => {
                if s.host.released(conn).is_ok() {
                    shared.acted(&mut s, now);
                }
                drop(s);
                // wakes the reader, blocked in read()
                socket.shutdown(Shutdown::Both);
                return;
            }
            Next::HalfClose => {
                socket.shutdown(Shutdown::Write);
                if s.host.half_closed(now, conn).is_ok() {
                    shared.acted(&mut s, now);
                }
            }
            Next::Timer => {
                if s.host.timer(now, conn).is_ok() {
                    shared.acted(&mut s, now);
                }
            }
            Next::Wait(None) => {
                s = shared
                    .changed
                    .wait(s)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            Next::Wait(Some(d)) => {
                s = shared
                    .changed
                    .wait_timeout(s, d)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            Next::Write(n) => {
                drop(s);
                let wrote = socket.write(out.get(..n).unwrap_or_default());
                s = lock(&shared.state);
                let at = shared.clock.now();
                let ok = match wrote {
                    Ok(went) => s.host.write_done(at, conn, went),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(()),
                    Err(_) => s.host.hangup(at, conn),
                };
                if ok.is_ok() {
                    shared.acted(&mut s, at);
                }
            }
        }
    }
}
