//! The files target: npro-files serving requests from a tree in memory.
//!
//! The input is a request, or several, fed to a stream on a vhost with
//! three routes and a 404 document: `/` and `/docs` served by npro-files
//! from mounts whose roots hold a few files and directories, `/cb` the
//! application's.  The oracles: every path the service opens is under
//! its mount's root, with no `..` component and no `\`, as the service
//! promises its file system; every request that reaches the stream is
//! answered; and nothing panics.

use npro_core::random::SeededRandom;
use npro_core::time::Instant;
use npro_files::{
    Cache, Fs, Intermediaries, MAX_PATH, Mount, Opened, Revalidate, Scheme, Served, Serving, serve,
};
use npro_h1::server::Config;
use npro_io::driver::{Buffers, NetBuffers, Want};
use npro_ss::event::{Filled, Kind};
use npro_ss::id::ListenerId;
use npro_ss::policy::{Listener, Match, Route, Tls, Vhost, Ws};
use npro_ss::ss::{ConnStorage, Slot, Ss};

use crate::targets::{control, finding};

const TARGET: &str = "files";

const T0: Instant = Instant::from_micros(1_000_000_000);

/// The most events one look at the stream may give before it is a
/// finding.
const MAX_EVENTS: usize = 4096;

const WWW: Mount<'static> = Mount {
    root: "/srv/www",
    default: "index.html",
    cache: Cache::For {
        max_age: 60,
        revalidate: Revalidate::Must,
        intermediaries: Intermediaries::Public,
    },
    mimes: &[
        (".tar.gz", "application/x-gtar"),
        ("*", "application/octet-stream"),
    ],
};

const DOCS: Mount<'static> = Mount {
    root: "/srv/docs/",
    default: "index.html",
    cache: Cache::NoCache,
    mimes: &[],
};

const ROUTES: [Route<'static>; 3] = [
    Route {
        path: "/",
        matching: Match::Prefix,
        to: "www",
        ws: Ws::NotTaken,
        headers: &[],
    },
    Route {
        path: "/docs",
        matching: Match::Prefix,
        to: "docs",
        ws: Ws::NotTaken,
        headers: &[(b"x-docs", b"1")],
    },
    Route {
        path: "/cb",
        matching: Match::Exact,
        to: "app",
        ws: Ws::NotTaken,
        headers: &[],
    },
];

const VHOSTS: [Vhost<'static>; 1] = [Vhost {
    name: "fuzz",
    routes: &ROUTES,
    headers: &[(b"x-vhost", b"1")],
    not_found: Some("/404.html"),
}];

/// The files in the tree, each `len` long, and the directories above
/// them.
const FILES: [(&str, u64); 6] = [
    ("/srv/www/index.html", 12),
    ("/srv/www/a/index.html", 0),
    ("/srv/www/a/b/x.tar.gz", 40_000),
    ("/srv/www/README", 3),
    ("/srv/www/404.html", 100),
    ("/srv/docs/index.html", 5),
];

/// The tree, checking each path it is asked for.
struct Tree;

impl Fs for Tree {
    type File = u64;

    fn open(&mut self, path: &[u8]) -> Option<Opened<u64>> {
        if path.len() > MAX_PATH {
            finding(TARGET, format_args!("a path of {} bytes", path.len()));
        }
        let under = [WWW.root, DOCS.root]
            .iter()
            .any(|root| path.starts_with(root.as_bytes()));
        if !under {
            finding(
                TARGET,
                format_args!("{} is under no mount", path.escape_ascii()),
            );
        }
        if path.contains(&b'\\') || path.split(|c| *c == b'/').any(|seg| seg == b"..") {
            finding(
                TARGET,
                format_args!("{} reaches outside", path.escape_ascii()),
            );
        }
        if let Some((_, len)) = FILES.iter().find(|(p, _)| p.as_bytes() == path) {
            return Some(Opened::File {
                file: *len,
                len: *len,
                modified: 1_700_000_000,
            });
        }
        let dir = [path.strip_suffix(b"/").unwrap_or(path), b"/"].concat();
        FILES
            .iter()
            .any(|(p, _)| p.as_bytes().starts_with(&dir))
            .then_some(Opened::Dir)
    }
}

/// A stream's state.
#[derive(Default)]
enum App {
    #[default]
    Idle,
    Answered,
    Body(Serving<u64, Vec<u8>>),
}

type S<'s> = Ss<'s, App, Vec<u8>, SeededRandom>;

fn slot() -> Slot<App, Vec<u8>, SeededRandom> {
    Slot::new(ConnStorage {
        h1: npro_h1::Storage {
            table: vec![0; 1024],
            out: vec![0; npro_h1::server::MIN_OUT],
        },
        bufs: Buffers {
            rx: vec![0; 256],
            tx: vec![0; 256],
            inflate: Vec::new(),
        },
        net: NetBuffers {
            rx: Vec::new(),
            tx: Vec::new(),
        },
    })
}

/// Answers what the stream was told, counting the requests answered.
fn events(ss: &mut S<'_>, answered: &mut usize) {
    for _ in 0..MAX_EVENTS {
        let Some(ev) = ss.poll_event(T0) else {
            return;
        };
        let (stream, user) = (ev.stream, ev.user);
        match ev.kind {
            Kind::ServerTxn(mut txn) => {
                let served = match txn.route().map(|r| r.route.to) {
                    Some("www") => serve(&WWW, &mut txn, &mut Tree, Scheme::Https),
                    Some("docs") => serve(&DOCS, &mut txn, &mut Tree, Scheme::Http),
                    Some(_) | None => txn.status(404).map(|()| Served::Answered),
                };
                // a response may be refused only as the role refuses it
                // (the head too long for the storage, say): the request
                // is then unanswered, and the connection's timeout ends it
                let Ok(served) = served else {
                    continue;
                };
                *answered = answered.saturating_add(1);
                *user = match served {
                    Served::Answered => App::Answered,
                    Served::Body(s) => App::Body(s),
                };
                let _ = ss.request_tx(stream);
            }
            Kind::Tx(tx) => {
                tx.fill(|buf| match user {
                    App::Idle | App::Answered => Filled::Last(0),
                    App::Body(s) => s.fill(buf),
                });
                if let App::Body(s) = user {
                    if let Some((file, read)) = s.wanted() {
                        // the file's bytes are its offsets
                        let n = usize::try_from(file.saturating_sub(read.at))
                            .unwrap_or(usize::MAX)
                            .min(read.len);
                        let chunk: Vec<u8> =
                            (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
                        s.read_done(file, chunk);
                        let _ = ss.request_tx(stream);
                    }
                }
            }
            Kind::ServerUpgrade { .. }
            | Kind::UpgradeRefused(_)
            | Kind::ClientUpgraded { .. }
            | Kind::NotUpgraded { .. }
            | Kind::Rx { .. }
            | Kind::Pong
            | Kind::PeerClose { .. }
            | Kind::ServerTxnEnd(_)
            | Kind::Response(_)
            | Kind::ConnectFailed
            | Kind::Disconnected => {}
        }
    }
    finding(
        TARGET,
        format_args!("more than {MAX_EVENTS} events at once"),
    );
}

/// Runs the target: see the module's description.
pub fn files(data: &[u8]) {
    let (_, mut bytes) = control(data);
    let listeners = [Listener {
        name: "fuzz",
        bind: "unix:/fuzz",
        tls: Tls::Plain,
        h1: Config::default(),
        vhosts: &VHOSTS,
    }];
    let mut slots = vec![slot()];
    let mut ss: S<'_> = Ss::new(&listeners, &mut slots)
        .unwrap_or_else(|e| finding(TARGET, format_args!("policy refused: {e}")));
    let conn = ss
        .accepted(T0, ListenerId::new(0), None, None)
        .unwrap_or_else(|e| finding(TARGET, format_args!("not accepted: {e}")));
    let mut answered = 0;
    let mut written = 0usize;
    for _ in 0..100_000 {
        let mut moved = false;
        if !bytes.is_empty() {
            if let Ok(n) = ss.received(T0, conn, bytes) {
                bytes = bytes.get(n..).unwrap_or_default();
                moved |= n > 0;
            }
        }
        events(&mut ss, &mut answered);
        match ss.want(T0, conn) {
            Ok(Want::Io(io)) => {
                if let Some(w) = io.write {
                    let n = w.len();
                    written = written.saturating_add(n);
                    let _ = ss.write_done(T0, conn, n);
                    moved = true;
                }
            }
            Ok(Want::HalfClose) => {
                let _ = ss.half_closed(T0, conn);
                moved = true;
            }
            Ok(Want::Release(_)) => {
                let _ = ss.released(conn);
                events(&mut ss, &mut answered);
                break;
            }
            Err(_) => break,
        }
        if !moved {
            break;
        }
    }
    if answered > 0 && written == 0 {
        finding(TARGET, format_args!("{answered} answered, nothing written"));
    }
}
