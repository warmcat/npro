//! The front: the server's application, answering each request from
//! the service its route names.
//!
//! A policy's route says `to: "www"`; the front has the services the
//! program was built with, by name ([`Services`]), and [`check`] refuses
//! a policy naming one it does not have, listing those it has, when the
//! policy is loaded.  The first service is files ([`Service::Files`]):
//! npro-files over std's file system ([`StdFs`]), its reads done by the
//! adapter's jobs, off the application's turn.  A request on a route
//! naming no service, or on no route, gets the vhost's 404.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use npro_core::time::Instant;
use npro_files::{Fs, Mount, Opened, Scheme, Served, Serving, serve};
use npro_io::threads::Jobs;
use npro_ss::event::{Filled, Kind};
use npro_ss::id::StreamId;
use npro_ss::policy::{Listener, Tls};

use crate::runner::Streams;

/// A service the front was built with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service<'p> {
    /// npro-files, serving this mount.
    Files(Mount<'p>),
}

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

/// std's file system, as npro-files opens files on it.  A symbolic link
/// is followed, as C follows it.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdFs;

/// A path as the service composed it, as std names it: any bytes, on
/// unix.
#[cfg(unix)]
fn os_path(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
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

/// A front stream's state: what it is sending.
#[derive(Debug, Default)]
pub enum Front {
    /// Nothing yet.
    #[default]
    Idle,
    /// The answer is whole: nothing more goes.
    Answered,
    /// A file's bytes, from npro-files.
    File(Serving<File, Vec<u8>>),
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

/// The front's turn: every event answered, the file reads wanted given
/// to `jobs`.  This is what the runner's `serve()` is given.
pub fn act<'s, 'j>(
    services: &Services<'_>,
    ss: &mut Streams<'s, Front>,
    now: Instant,
    jobs: &Jobs<'j, Streams<'s, Front>>,
) {
    while let Some(ev) = ss.poll_event(now) {
        let (stream, user): (StreamId, &mut Front) = (ev.stream, ev.user);
        let mut wants_tx = false;
        match ev.kind {
            Kind::ServerTxn(mut txn) => {
                let scheme = match txn.listener().tls {
                    Tls::Plain => Scheme::Http,
                    Tls::Server { .. } => Scheme::Https,
                };
                let service = txn.route().and_then(|r| services.find(r.route.to));
                let served = match service {
                    Some(Service::Files(mount)) => serve(mount, &mut txn, &mut StdFs, scheme),
                    None => txn.status(404).map(|()| Served::Answered),
                };
                // refused only as the role refuses it: the request stays
                // unanswered, and its timeout ends the connection
                if let Ok(served) = served {
                    *user = match served {
                        Served::Answered => Front::Answered,
                        Served::Body(s) => Front::File(s),
                    };
                    wants_tx = true;
                }
            }
            Kind::Tx(tx) => {
                tx.fill(|buf| match user {
                    Front::Idle | Front::Answered => Filled::Last(0),
                    Front::File(s) => s.fill(buf),
                });
                if let Front::File(serving) = user {
                    if let Some((file, read)) = serving.wanted() {
                        jobs.spawn(move || {
                            let chunk = read_chunk(&file, read);
                            move |streams: &mut Streams<'s, Front>, _: Instant| {
                                // the stream may have gone meanwhile
                                if let Ok(Front::File(back)) = streams.user(stream) {
                                    back.read_done(file, chunk);
                                    let _ = streams.request_tx(stream);
                                }
                            }
                        });
                    }
                }
            }
            Kind::ServerUpgrade { .. }
            | Kind::UpgradeRefused(_)
            | Kind::Rx { .. }
            | Kind::Pong
            | Kind::PeerClose { .. }
            | Kind::Response(_)
            | Kind::ConnectFailed
            | Kind::Disconnected => {}
        }
        if wants_tx {
            let _ = ss.request_tx(stream);
        }
    }
}
