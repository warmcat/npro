//! The front: the server's application, answering each request from
//! the service its route names.
//!
//! A policy's route says `to: "www"`; the front has the services the
//! program was built with, by name ([`Services`]), and [`check`] refuses
//! a policy naming one it does not have, listing those it has, when the
//! policy is loaded.  The services are files ([`Service::Files`]):
//! npro-files over std's file system ([`StdFs`]), its reads done by the
//! adapter's jobs, off the application's turn; and the proxy
//! ([`Service::Proxy`]): npro-proxy, the request passed to its origin by
//! a stream connecting out, which the adapter connects.  A request on a
//! route naming no service, or on no route, gets the vhost's 404.
//!
//! Each request on a vhost with an access log ([`Logs`]) is written to
//! it as its transaction ends, in C's line ([`npro_ss::access`]).
//!
//! A cgi service ([`Service::Cgi`]) is npro-cgi: the script is spawned
//! here, given the request as its environment, its stdin fed the
//! request's body and its stdout read, a chunk at a time by the
//! adapter's jobs as a file is, the head parsed and the payload passed
//! to the client ([`Running`]).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use npro_cgi::{DEFAULT_DIR, Head, Progress, Script, Vars};
use npro_core::time::Instant;
use npro_files::{Fs, Mount, Opened, Scheme, Served, Serving, serve};
use npro_io::threads::Jobs;
use npro_proxy::{Act, Asked, CAPACITY, Side, Storage, Upstream};
use npro_ss::access::{MAX_LINE, Record};
use npro_ss::event::{End, Ended, Filled, Flow, Kind, Response, Txn};
use npro_ss::id::StreamId;
use npro_ss::policy::{Listener, Tls};

use crate::runner::Streams;

/// A service the front was built with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service<'p> {
    /// npro-files, serving this mount.
    Files(Mount<'p>),
    /// npro-proxy, passing requests to this origin.
    Proxy(Upstream<'p>),
    /// A redirect, the front's own: C's `>https://` mount origin.
    Redirect(Redirect<'p>),
    /// npro-cgi, each request answered by this script.
    Cgi(Script<'p>),
}

/// A redirect: every request on the route is answered 301 to `to`, with
/// what came after the route's path appended if `append` says, as C's
/// `lws_http_redirect_hit()` does for a `>https://` origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redirect<'p> {
    /// Where to: `https://example.com`.
    pub to: &'p str,
    /// Whether the rest of the request's path follows it.
    pub append: Append,
}

/// What follows a redirect's `to`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Append {
    /// Nothing: every request goes to `to` as it is.
    Nothing,
    /// The rest of the request's path, after a `/`: C's `append-path`.
    Path,
}

/// The longest location a redirect composes.
const MAX_LOCATION: usize = 2048;

/// The services, by the name a route's `to` gives.
#[derive(Clone, Copy, Debug)]
pub struct Services<'p> {
    /// Each, by name.
    pub by_name: &'p [(&'p str, Service<'p>)],
}

impl<'p> Services<'p> {
    fn find(&self, name: &str) -> Option<&Service<'p>> {
        self.by_name
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, s)| s)
    }
}

/// A route names a service the front does not have.
#[derive(Debug)]
pub struct UnknownService {
    /// The listener, the vhost and the route's path.
    pub at: String,
    /// What it named.
    pub to: String,
    /// What there is.
    pub known: Vec<String>,
}

impl core::fmt::Display for UnknownService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}: no service {:?}; built in: {}",
            self.at,
            self.to,
            self.known.join(", ")
        )
    }
}

impl core::error::Error for UnknownService {}

/// Checks every route of `listeners` names a service of `services`.
///
/// # Errors
///
/// [`UnknownService`], the first found.
pub fn check(services: &Services<'_>, listeners: &[Listener<'_>]) -> Result<(), UnknownService> {
    for l in listeners {
        for v in l.vhosts {
            for r in v.routes {
                if services.find(r.to).is_none() {
                    return Err(UnknownService {
                        at: format!("{}, {}, {}", l.name, v.name, r.path),
                        to: r.to.to_owned(),
                        known: services
                            .by_name
                            .iter()
                            .map(|(n, _)| (*n).to_owned())
                            .collect(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// The access logs: a file for each vhost the policy gives one, C's
/// `access-log`, opened once however many vhosts share it, appended to a
/// line per request.  Opened before the listeners are bound, so a log
/// that cannot be is refused before anything is served.
#[derive(Debug)]
pub struct Logs {
    /// Each file, by its path, once.
    files: Vec<(String, File)>,
    /// Each vhost's file, by name, as an index into `files`.
    by_vhost: Vec<(String, usize)>,
}

/// An access log that could not be opened.
#[derive(Debug)]
pub struct LogError {
    /// Its path.
    pub path: String,
    /// Why.
    pub error: io::Error,
}

impl core::fmt::Display for LogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "access log {}: {}", self.path, self.error)
    }
}

impl core::error::Error for LogError {}

impl Logs {
    /// No logs: nothing is written.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            files: Vec::new(),
            by_vhost: Vec::new(),
        }
    }

    /// Opens the log of each `(vhost, path)`, to append to, made if it is
    /// not there, as C opens it.
    ///
    /// # Errors
    ///
    /// [`LogError`], the first path that could not be opened.
    pub fn open(vhosts: &[(&str, &str)]) -> Result<Self, LogError> {
        let mut logs = Self::none();
        for (vhost, path) in vhosts {
            let at = logs.files.iter().position(|(p, _)| p == path);
            let at = match at {
                Some(at) => at,
                None => logs.open_one(path)?,
            };
            logs.by_vhost.push(((*vhost).to_owned(), at));
        }
        Ok(logs)
    }

    /// Opens the file at `path`: its index.
    fn open_one(&mut self, path: &str) -> Result<usize, LogError> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(|error| LogError {
                path: path.to_owned(),
                error,
            })?;
        self.files.push((path.to_owned(), file));
        Ok(self.files.len().saturating_sub(1))
    }

    /// The record of the request `txn` holds, and which log it goes to,
    /// if its vhost has one: taken now, at the wall clock's time, since
    /// the request is gone by the time its transaction ends.
    fn record<S: AsRef<[u8]> + AsMut<[u8]>>(&self, txn: &Txn<'_, S>) -> Option<(usize, Record)> {
        let name = txn.vhost().name;
        let (_, at) = self.by_vhost.iter().find(|(v, _)| v == name)?;
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Some((*at, Record::of(txn, wall)))
    }

    /// Writes the line for `record`, the transaction having ended as
    /// `ended` says, to the log `at`.  One write per line, so lines from
    /// every process appending to the file stay whole.  A write that
    /// fails is let go, as C's is: there is nothing to tell but the log.
    fn write(&self, at: usize, record: &Record, ended: Ended) {
        let Some((_, file)) = self.files.get(at) else {
            return;
        };
        let mut line = [0u8; MAX_LINE];
        let n = record.line(ended, &mut line);
        let mut f: &File = file;
        drop(f.write_all(line.get(..n).unwrap_or_default()));
    }
}

/// std's file system, as npro-files opens files on it.  A symbolic link
/// is followed, as C follows it.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdFs;

/// A path as the service composed it, as std names it: any bytes, on
/// unix.
#[cfg(unix)]
fn os_path(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(OsStr::from_bytes(bytes))
}

/// A path as the service composed it, as std names it: UTF-8, elsewhere.
#[cfg(not(unix))]
fn os_path(bytes: &[u8]) -> Option<PathBuf> {
    core::str::from_utf8(bytes).ok().map(PathBuf::from)
}

impl Fs for StdFs {
    type File = File;

    fn open(&mut self, path: &[u8]) -> Option<Opened<File>> {
        #[cfg(unix)]
        let p = os_path(path);
        #[cfg(not(unix))]
        let p = os_path(path)?;
        let meta = std::fs::metadata(&p).ok()?;
        if meta.is_dir() {
            return Some(Opened::Dir);
        }
        if !meta.is_file() {
            return None;
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX));
        Some(Opened::File {
            file: File::open(&p).ok()?,
            len: meta.len(),
            modified,
        })
    }
}

/// A front stream's state.
#[derive(Debug, Default)]
pub struct Front {
    /// What it is sending.
    state: State,
    /// The access log's record of the request in hand, and which log it
    /// goes to, while the request is on a vhost with a log.
    log: Option<(usize, Record)>,
}

impl Front {
    /// A stream that is one side of a proxied request.
    fn proxy(side: Side<Vec<u8>>) -> Self {
        Self {
            state: State::Proxy(Box::new(side)),
            log: None,
        }
    }
}

/// What a front stream is sending.
#[derive(Debug, Default)]
pub enum State {
    /// Nothing yet.
    #[default]
    Idle,
    /// The answer is whole: nothing more goes.
    Answered,
    /// A file's bytes, from npro-files.
    File(Serving<File, Vec<u8>>),
    /// One side of a proxied request, from npro-proxy: the client's
    /// stream or the one to the origin.  Boxed: its buffers are far
    /// larger than any other state, and a std program has a heap.
    Proxy(Box<Side<Vec<u8>>>),
    /// A script's answer, from npro-cgi: boxed, it holds the head
    /// being parsed.
    Cgi(Box<Running>),
}

/// The proxy's side of a front stream, if it is one.
fn proxy_side(u: &mut Front) -> Option<&mut Side<Vec<u8>>> {
    match &mut u.state {
        State::Proxy(s) => Some(s),
        State::Idle | State::Answered | State::File(_) | State::Cgi(_) => None,
    }
}

/// How much of a script's output one read takes.
const CGI_CHUNK: usize = 16 * 1024;

/// A script answering a request: its process, and where its answer is.
#[derive(Debug)]
pub struct Running {
    child: Child,
    /// Its stdin, while the request's body is still to go to it; taken
    /// by a write job while one is out, and dropped, closing it, after
    /// the body's last piece.
    stdin: Option<ChildStdin>,
    /// Its stdout between reads: taken by the read job while one is
    /// out.
    stdout: Option<ChildStdout>,
    answer: Answer,
    /// What was read and not yet given, from `at`.
    chunk: Vec<u8>,
    at: usize,
    /// What its stdout came to.
    output: Output,
}

/// Where a script's answer is.
#[derive(Debug)]
enum Answer {
    /// Its head is being parsed: boxed, it is the one large state.
    Head(Box<Head>),
    /// Its head was passed to the client, and this much of its payload
    /// is still to come, if it gave a length.
    Started { left: Option<u64> },
}

/// What a script's stdout came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Output {
    /// More may come.
    Open,
    /// It ended: the script closed it, or exited.
    Ended,
}

impl Running {
    /// Spawns `script` to answer the request `txn` holds, with the
    /// request as its environment.  `None` if it could not be: the
    /// environment does not fit, or the program cannot be run.
    fn spawn<S: AsRef<[u8]> + AsMut<[u8]>>(script: &Script<'_>, txn: &Txn<'_, S>) -> Option<Self> {
        let vars = Vars::of(script, txn).ok()?;
        let mut command = Command::new(script.exec);
        command
            .env_clear()
            .current_dir(script.dir.unwrap_or(DEFAULT_DIR))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // what it says is this process' to say, as C logs it
            .stderr(Stdio::inherit());
        for (name, value) in vars.iter() {
            command.env(os(name), os(value));
        }
        let mut child = command.spawn().ok()?;
        let stdout = child.stdout.take();
        let mut stdin = child.stdin.take();
        // a request with no body: the script's stdin ends at once, so
        // one that reads it is not left waiting
        let has_body = txn.header(b"content-length").is_some_and(|v| v != b"0")
            || txn.header(b"transfer-encoding").is_some();
        if !has_body {
            stdin = None;
        }
        Some(Self {
            child,
            stdin,
            stdout,
            answer: Answer::Head(Box::new(Head::new())),
            chunk: Vec::new(),
            at: 0,
            output: Output::Open,
        })
    }

    /// Whether a read of its output is wanted: none is out, it has not
    /// ended, and what was read is given.
    fn wants_read(&self) -> bool {
        self.stdout.is_some() && self.output == Output::Open && self.at >= self.chunk.len()
    }

    /// Gives what was read into `buf`: how much, and whether that was
    /// the last of the payload.
    fn fill(&mut self, buf: &mut [u8]) -> Filled {
        // no room is wanted for none: a HEAD's answer takes no payload
        if buf.is_empty() {
            return Filled::Last(0);
        }
        let rest = self.chunk.get(self.at..).unwrap_or_default();
        let n = rest.len().min(buf.len());
        if let (Some(to), Some(from)) = (buf.get_mut(..n), rest.get(..n)) {
            to.copy_from_slice(from);
        }
        self.at = self.at.saturating_add(n);
        if self.at >= self.chunk.len() {
            self.chunk.clear();
            self.at = 0;
        }
        let left = match &mut self.answer {
            Answer::Started { left: Some(left) } => {
                *left = left.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
                Some(*left)
            }
            Answer::Started { left: None } | Answer::Head(_) => None,
        };
        let over = left == Some(0) || (self.output == Output::Ended && self.chunk.is_empty());
        if over {
            Filled::Last(n)
        } else {
            Filled::More(n)
        }
    }

    /// Ends the script, if it has not ended: C's `lws_cgi_kill()`.  The
    /// process is reaped by `reap`, off the turn.
    fn kill(mut self, jobs: &Jobs<'_, impl Send>) {
        // one that exited already cannot be killed, and is just reaped
        drop(self.child.kill());
        drop(self.stdin.take());
        drop(self.stdout.take());
        jobs.spawn(move || {
            drop(self.child.wait());
            move |_: &mut _, _: Instant| {}
        });
    }
}

/// `bytes` as a name or value for the environment.
#[cfg(unix)]
fn os(bytes: &[u8]) -> Cow<'_, OsStr> {
    use std::os::unix::ffi::OsStrExt;
    Cow::Borrowed(OsStr::from_bytes(bytes))
}

/// `bytes` as a name or value for the environment: as text, which an
/// environment is on other platforms.
#[cfg(not(unix))]
fn os(bytes: &[u8]) -> Cow<'_, OsStr> {
    match String::from_utf8_lossy(bytes) {
        Cow::Borrowed(s) => Cow::Borrowed(OsStr::new(s)),
        Cow::Owned(s) => Cow::Owned(s.into()),
    }
}

/// Reads the next chunk of a script's output, off the turn, and hands
/// it to the stream: its head taken as far as it goes, and once whole
/// passed to the client as the answer; then its payload, which the
/// stream asks to write.
fn read_cgi_off_the_turn<'s, 'j>(
    running: &mut Running,
    stream: StreamId,
    jobs: &Jobs<'j, Streams<'s, Front>>,
) {
    let Some(mut stdout) = running.stdout.take() else {
        return;
    };
    jobs.spawn(move || {
        let mut chunk = vec![0u8; CGI_CHUNK];
        let got = stdout.read(&mut chunk).unwrap_or_default();
        chunk.truncate(got);
        move |streams: &mut Streams<'s, Front>, now: Instant| {
            // the stream may have gone meanwhile
            let Ok(Front {
                state: State::Cgi(r),
                ..
            }) = streams.user(stream)
            else {
                return;
            };
            if got == 0 {
                r.output = Output::Ended;
            } else {
                r.stdout = Some(stdout);
            }
            let whole = match &mut r.answer {
                Answer::Head(head) => match head.feed(&chunk) {
                    Ok(Progress::Done { consumed }) => {
                        r.chunk = chunk.get(consumed..).unwrap_or_default().to_vec();
                        true
                    }
                    Ok(Progress::More) if got > 0 => false,
                    // ended in its head, or no head at all: C drops the
                    // connection; the client gets a page
                    Ok(Progress::More) | Err(_) => {
                        status(streams, now, stream, 500);
                        return;
                    }
                },
                Answer::Started { .. } => {
                    r.chunk = chunk;
                    false
                }
            };
            if whole && !answer_from_head(streams, stream) {
                return;
            }
            // the chance to write brings the next read with it
            let _ = streams.request_tx(stream);
        }
    });
}

/// Passes a script's head, whole, to the client as the answer: whether
/// the stream took it.
fn answer_from_head(streams: &mut Streams<'_, Front>, stream: StreamId) -> bool {
    // what the head says, copied out: the answer borrows the streams
    let (status, content_type, content_length, kept) = {
        let Ok(Front {
            state: State::Cgi(r),
            ..
        }) = streams.user(stream)
        else {
            return false;
        };
        let Answer::Head(head) = &r.answer else {
            return true;
        };
        let parsed = head.parsed();
        let kept: Vec<(Vec<u8>, Vec<u8>)> = parsed
            .passed()
            .map(|(n, v)| (n.to_vec(), v.to_vec()))
            .collect();
        (
            parsed.status,
            parsed.content_type.map(<[u8]>::to_vec),
            parsed.content_length,
            kept,
        )
    };
    let headers: Vec<(&[u8], &[u8])> = kept
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    let response = Response {
        status,
        content_type: content_type.as_deref(),
        content_length,
        headers: &headers,
    };
    let left = content_length;
    let taken = streams.respond(stream, response).is_ok();
    if let Ok(Front {
        state: State::Cgi(r),
        ..
    }) = streams.user(stream)
    {
        r.answer = Answer::Started { left };
    }
    taken
}

/// Writes `piece` of the request's body to the script's stdin, off the
/// turn, the stream's reading held until it is written; `end` closes
/// the stdin after it.
fn write_cgi_off_the_turn<'s, 'j>(
    running: &mut Running,
    stream: StreamId,
    piece: Vec<u8>,
    end: End,
    jobs: &Jobs<'j, Streams<'s, Front>>,
) -> Then {
    let Some(mut stdin) = running.stdin.take() else {
        return Then::Nothing;
    };
    jobs.spawn(move || {
        // a script that stopped reading: what is left is not its
        let written = stdin.write_all(&piece).is_ok();
        move |streams: &mut Streams<'s, Front>, _: Instant| {
            if let Ok(Front {
                state: State::Cgi(r),
                ..
            }) = streams.user(stream)
            {
                if written && end == End::More {
                    r.stdin = Some(stdin);
                }
            }
            let _ = streams.flow(stream, Flow::Given);
        }
    });
    Then::Flow(Flow::Held)
}

/// What the front does after an event, since the event borrows the
/// streams.
enum Then {
    Nothing,
    /// The stream has payload to write.
    Tx,
    /// A script's output is read, if a read is wanted.
    ReadCgi,
    /// The script is over with: ended and reaped.
    Reap,
    /// The stream's reading is held, or given back.
    Flow(Flow),
    /// A request to pass on, copied out: [`npro_proxy::start`].  Boxed:
    /// it carries the onward headers.
    Start(Upstream<'static>, Box<Asked>),
    /// The client is answered with this status page.
    Status(u16),
    /// The proxy's calls.
    Acts(npro_proxy::Acts),
}

/// Answers the stream with C's status page and ends its answer.
fn status(ss: &mut Streams<'_, Front>, now: Instant, stream: StreamId, code: u16) {
    if ss.status(now, stream, code).is_ok() {
        if let Ok(u) = ss.user(stream) {
            u.state = State::Answered;
        }
        let _ = ss.request_tx(stream);
    }
}

/// Applies one of the proxy's calls.
fn apply(ss: &mut Streams<'_, Front>, now: Instant, a: Act) {
    match a {
        Act::Move { from, to } => npro_proxy::moved(ss, from, to, proxy_side),
        Act::Answer { client, origin } => {
            // refused only as the role refuses it: the request is then
            // unanswered, and its timeout ends the connection
            let _ = npro_proxy::answer(ss, client, origin, proxy_side);
        }
        Act::Status(s, code) => status(ss, now, s, code),
        Act::OriginGone(client) => npro_proxy::origin_gone(ss, now, client, proxy_side),
        Act::Destroy(s) => {
            let _ = ss.destroy(now, s);
        }
        Act::RequestTx(s) => {
            let _ = ss.request_tx(s);
        }
        Act::Flow(s, f) => {
            let _ = ss.flow(s, f);
        }
    }
}

/// Reads `read` of `file`, off the turn: what it got, short at the
/// file's end or on a failure.
fn read_chunk(file: &File, read: npro_files::Read) -> Vec<u8> {
    let mut chunk = vec![0u8; read.len];
    let mut f = file;
    let mut got = 0;
    if f.seek(SeekFrom::Start(read.at)).is_ok() {
        while got < chunk.len() {
            match f.read(chunk.get_mut(got..).unwrap_or_default()) {
                Ok(0) | Err(_) => break,
                Ok(n) => got = got.saturating_add(n),
            }
        }
    }
    chunk.truncate(got);
    chunk
}

/// The next read `serving` wants, if one, given to `jobs`: done off the
/// turn, and handed back to the stream, which then asks to write.
fn read_off_the_turn<'s, 'j>(
    serving: &mut Serving<File, Vec<u8>>,
    stream: StreamId,
    jobs: &Jobs<'j, Streams<'s, Front>>,
) {
    if let Some((file, read)) = serving.wanted() {
        jobs.spawn(move || {
            let chunk = read_chunk(&file, read);
            move |streams: &mut Streams<'s, Front>, _: Instant| {
                // the stream may have gone meanwhile
                if let Ok(Front {
                    state: State::File(back),
                    ..
                }) = streams.user(stream)
                {
                    back.read_done(file, chunk);
                    let _ = streams.request_tx(stream);
                }
            }
        });
    }
}

/// Answers the request with the redirect `r` says: 301 to its `to`, the
/// rest of the path after it if it appends, or 414 if that does not
/// fit [`MAX_LOCATION`].
fn redirect<S: AsRef<[u8]> + AsMut<[u8]>>(
    r: &Redirect<'_>,
    txn: &mut Txn<'_, S>,
) -> Result<(), npro_ss::event::RespondError> {
    let mut loc = Vec::with_capacity(MAX_LOCATION);
    loc.extend_from_slice(r.to.as_bytes());
    if let (Append::Path, Some(routed)) = (r.append, txn.route()) {
        if !routed.rest.is_empty() {
            if !loc.ends_with(b"/") {
                loc.push(b'/');
            }
            loc.extend_from_slice(routed.rest);
        }
    }
    if loc.len() > MAX_LOCATION {
        txn.status(414)
    } else {
        txn.redirect(301, &loc)
    }
}

/// Answers the request `txn` holds from the service its route names,
/// setting the stream's `state` for what follows.
fn answer(services: &Services<'static>, txn: &mut Txn<'_, Vec<u8>>, user: &mut State) -> Then {
    let scheme = match txn.listener().tls {
        Tls::Plain => Scheme::Http,
        Tls::Server { .. } => Scheme::Https,
    };
    let service = txn.route().and_then(|r| services.find(r.route.to));
    match service {
        // refused only as the role refuses it: the request
        // stays unanswered, and its timeout ends the connection
        Some(Service::Files(mount)) => match serve(mount, txn, &mut StdFs, scheme) {
            Ok(Served::Answered) => {
                *user = State::Answered;
                Then::Tx
            }
            Ok(Served::Body(s)) => {
                *user = State::File(s);
                Then::Tx
            }
            Err(_) => Then::Nothing,
        },
        Some(Service::Proxy(up)) => match Asked::of(up, txn) {
            Ok(asked) => Then::Start(*up, Box::new(asked)),
            Err(e) => Then::Status(e.status()),
        },
        Some(Service::Redirect(r)) => match redirect(r, txn) {
            Ok(()) => {
                *user = State::Answered;
                Then::Tx
            }
            Err(_) => Then::Nothing,
        },
        Some(Service::Cgi(script)) => match Running::spawn(script, txn) {
            Some(running) => {
                txn.answer_within(script.timeout);
                *user = State::Cgi(Box::new(running));
                Then::ReadCgi
            }
            None => Then::Status(500),
        },
        None => match txn.status(404) {
            Ok(()) => {
                *user = State::Answered;
                Then::Tx
            }
            Err(_) => Then::Nothing,
        },
    }
}

/// The front's turn: every event answered, the file reads wanted given
/// to `jobs`, each transaction over written to its vhost's log.  This is
/// what the runner's `serve()` is given.
pub fn act<'s>(
    services: &Services<'static>,
    logs: &Logs,
    ss: &mut Streams<'s, Front>,
    now: Instant,
    jobs: &Jobs<'_, Streams<'s, Front>>,
) {
    while let Some(ev) = ss.poll_event(now) {
        let stream: StreamId = ev.stream;
        let Front { state, log } = ev.user;
        let then = match (state, ev.kind) {
            (
                State::Idle | State::Answered | State::File(_) | State::Proxy(_),
                Kind::ServerTxnEnd(ended),
            ) => {
                if let Some((at, record)) = log.take() {
                    logs.write(at, &record, ended);
                }
                Then::Nothing
            }
            // a script's transaction over, or its client gone: the script
            // is over with
            (State::Cgi(_), Kind::ServerTxnEnd(ended)) => {
                if let Some((at, record)) = log.take() {
                    logs.write(at, &record, ended);
                }
                Then::Reap
            }
            (State::Cgi(_), Kind::Disconnected) => Then::Reap,
            (State::Proxy(side), kind) => Then::Acts(npro_proxy::on_event(stream, side, kind)),
            (user, Kind::ServerTxn(mut txn)) => {
                *log = logs.record(&txn);
                answer(services, &mut txn, user)
            }
            (user, Kind::Tx(tx)) => {
                tx.fill(|buf| match user {
                    State::Idle | State::Answered | State::Proxy(_) => Filled::Last(0),
                    State::File(s) => s.fill(buf),
                    State::Cgi(r) => r.fill(buf),
                });
                match user {
                    State::File(serving) => read_off_the_turn(serving, stream, jobs),
                    State::Cgi(r) => {
                        if r.wants_read() {
                            read_cgi_off_the_turn(r, stream, jobs);
                        }
                    }
                    State::Idle | State::Answered | State::Proxy(_) => {}
                }
                Then::Nothing
            }
            // the request's body goes to the script
            (State::Cgi(r), Kind::Rx { data, end }) => {
                write_cgi_off_the_turn(r, stream, data.to_vec(), end, jobs)
            }
            (
                State::Idle | State::Answered | State::File(_) | State::Cgi(_),
                Kind::ServerUpgrade { .. }
                | Kind::UpgradeRefused(_)
                | Kind::Pong
                | Kind::PeerClose { .. }
                | Kind::Response(_)
                | Kind::ConnectFailed,
            )
            | (
                State::Idle | State::Answered | State::File(_),
                Kind::Rx { .. } | Kind::Disconnected,
            ) => Then::Nothing,
        };
        carry_out(then, stream, ss, now, jobs);
    }
}

/// Does what an event came to, once the event has let the streams go.
fn carry_out<'s>(
    then: Then,
    stream: StreamId,
    ss: &mut Streams<'s, Front>,
    now: Instant,
    jobs: &Jobs<'_, Streams<'s, Front>>,
) {
    {
        match then {
            Then::Nothing => {}
            Then::Tx => {
                let _ = ss.request_tx(stream);
            }
            Then::ReadCgi => {
                if let Ok(Front {
                    state: State::Cgi(r),
                    ..
                }) = ss.user(stream)
                {
                    if r.wants_read() {
                        read_cgi_off_the_turn(r, stream, jobs);
                    }
                }
            }
            Then::Flow(f) => {
                let _ = ss.flow(stream, f);
            }
            Then::Reap => {
                if let Ok(u) = ss.user(stream) {
                    if let State::Cgi(r) = core::mem::replace(&mut u.state, State::Answered) {
                        r.kill(jobs);
                    }
                }
            }
            Then::Status(code) => status(ss, now, stream, code),
            Then::Start(up, asked) => {
                let storage = || Storage {
                    staging: vec![0; CAPACITY],
                    out: vec![0; CAPACITY],
                };
                match npro_proxy::start(&up, &asked, stream, ss, storage(), storage(), Front::proxy)
                {
                    Ok(side) => {
                        if let Ok(u) = ss.user(stream) {
                            u.state = State::Proxy(Box::new(side));
                        }
                    }
                    Err(e) => status(ss, now, stream, e.status()),
                }
            }
            Then::Acts(acts) => {
                for a in acts.iter() {
                    apply(ss, now, a);
                }
            }
        }
    }
}
