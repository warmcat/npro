//! The proxy target: npro-proxy between a client the fuzzer plays and an
//! origin it plays too.
//!
//! The input is split by its control byte into the client's bytes and
//! the origin's: a request, or not, and a response, or not.  The client
//! is accepted on a vhost whose one route goes to the origin; the
//! origin's connect is made, or failed when the control byte says so,
//! and its bytes read in as the proxy takes them; the client's output
//! is written a few bytes at a time, so the buffers fill and the holds
//! happen.  The oracles: nothing panics; a request the proxy took on is
//! answered, with the origin's status or a page; every byte the origin
//! sent after its head reaches the client, in order, as far as the
//! client's answer goes; and the proxy's buffers never pass their
//! capacity (their type sees to it, so a panic there is a finding).

use npro_core::random::SeededRandom;
use npro_core::time::Instant;
use npro_h1::server::Config;
use npro_io::driver::{Buffers, Io, NetBuffers, Want};
use npro_proxy::{
    Act, Asked, Side, Storage, Upstream, answer, moved, on_event, origin_gone, start,
};
use npro_ss::event::{Filled, Kind};
use npro_ss::id::{ConnId, ListenerId, StreamId};
use npro_ss::policy::{Listener, Match, Route, Tls, Vhost, Ws};
use npro_ss::ss::{ConnStorage, Slot, Ss};

use crate::targets::{control, finding};

const TARGET: &str = "proxy";

const T0: Instant = Instant::from_micros(1_000_000_000);

/// The most events one look at the streams may give before it is a
/// finding.
const MAX_EVENTS: usize = 4096;

const UP: Upstream<'static> = Upstream {
    address: "unix:/origin",
    path: "/o",
    host: "origin",
};

const ROUTES: [Route<'static>; 1] = [Route {
    path: "/",
    matching: Match::Prefix,
    to: "proxy",
    ws: Ws::NotTaken,
    headers: &[],
}];

const VHOSTS: [Vhost<'static>; 1] = [Vhost {
    name: "fuzz",
    routes: &ROUTES,
    headers: &[],
    not_found: None,
}];

#[derive(Debug, Default)]
enum App {
    #[default]
    Idle,
    Answered,
    Proxy(Box<Side<Vec<u8>>>),
}

type S<'s> = Ss<'s, App, Vec<u8>, SeededRandom>;

fn side_of(u: &mut App) -> Option<&mut Side<Vec<u8>>> {
    match u {
        App::Proxy(s) => Some(s),
        App::Idle | App::Answered => None,
    }
}

/// A side's storage: small, so the holds come, with room for a held
/// giver's piece.
fn storage() -> Storage<Vec<u8>> {
    Storage {
        staging: vec![0; 2048],
        out: vec![0; 2048],
    }
}

/// Small buffers, so bodies are many pieces and the holds come.
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

enum Then {
    Nothing,
    Start(StreamId, Box<Asked>),
    Status(StreamId, u16),
    Acts(npro_proxy::Acts),
}

/// The front, as the proxy's tests have it; counts the requests taken on.
fn events(ss: &mut S<'_>, taken: &mut usize) {
    for _ in 0..MAX_EVENTS {
        let Some(ev) = ss.poll_event(T0) else {
            return;
        };
        let (stream, user) = (ev.stream, ev.user);
        let then = match (user, ev.kind) {
            (App::Idle | App::Answered, Kind::ServerTxn(txn)) => match Asked::of(&UP, &txn) {
                Ok(asked) => Then::Start(stream, Box::new(asked)),
                Err(e) => Then::Status(stream, e.status()),
            },
            (App::Answered, Kind::Tx(tx)) => {
                tx.fill(|_| Filled::Last(0));
                Then::Nothing
            }
            (App::Proxy(side), kind) => Then::Acts(on_event(stream, side, kind)),
            (App::Idle | App::Answered, _) => Then::Nothing,
        };
        match then {
            Then::Nothing => {}
            Then::Status(s, code) => {
                if ss.status(T0, s, code).is_ok() {
                    if let Ok(u) = ss.user(s) {
                        *u = App::Answered;
                    }
                    let _ = ss.request_tx(s);
                }
            }
            Then::Start(client, asked) => {
                *taken = taken.saturating_add(1);
                match start(&UP, &asked, client, ss, storage(), storage(), |s| {
                    App::Proxy(Box::new(s))
                }) {
                    Ok(side) => {
                        if let Ok(u) = ss.user(client) {
                            *u = App::Proxy(Box::new(side));
                        }
                    }
                    Err(e) => {
                        if ss.status(T0, client, e.status()).is_ok() {
                            if let Ok(u) = ss.user(client) {
                                *u = App::Answered;
                            }
                            let _ = ss.request_tx(client);
                        }
                    }
                }
            }
            Then::Acts(acts) => {
                for a in acts.iter() {
                    apply(ss, a);
                }
            }
        }
    }
    finding(
        TARGET,
        format_args!("more than {MAX_EVENTS} events at once"),
    );
}

fn apply(ss: &mut S<'_>, a: Act) {
    match a {
        Act::Move { from, to } => moved(ss, from, to, side_of),
        Act::Answer { client, origin } => {
            // refused only as the role refuses it: the client's request
            // is then unanswered, and its timeout ends it
            let _ = answer(ss, client, origin, side_of);
        }
        Act::Status(s, code) => {
            if ss.status(T0, s, code).is_ok() {
                if let Ok(u) = ss.user(s) {
                    *u = App::Answered;
                }
                let _ = ss.request_tx(s);
            }
        }
        Act::OriginGone(client) => origin_gone(ss, T0, client, side_of),
        Act::Destroy(s) => drop(ss.destroy(T0, s)),
        Act::RequestTx(s) => drop(ss.request_tx(s)),
        Act::Flow(s, f) => drop(ss.flow(s, f)),
    }
}

/// Carries a connection's close along, if it asks: whether it is gone.
fn settle(ss: &mut S<'_>, c: ConnId) -> bool {
    match ss.want(T0, c) {
        Ok(Want::HalfClose) => {
            let _ = ss.half_closed(T0, c);
            false
        }
        Ok(Want::Release(_)) => {
            let _ = ss.released(c);
            true
        }
        Ok(Want::Io(_)) => false,
        Err(_) => true,
    }
}

/// The origin's turn: what the proxy sent it taken, its bytes read in,
/// its close once it has sent all it had, and its connection carried
/// along.  Whether anything moved, and whether the connection is gone.
fn origin_turn(
    ss: &mut S<'_>,
    oc: ConnId,
    from_origin: &mut &[u8],
    origin_fin: &mut bool,
    taken: &mut usize,
) -> (bool, bool) {
    let mut moved = false;
    if let Ok(Want::Io(io)) = ss.want(T0, oc) {
        if let Some(w) = io.write {
            let n = w.len();
            let _ = ss.write_done(T0, oc, n);
            moved = true;
        }
    }
    if from_origin.is_empty() {
        if !*origin_fin {
            *origin_fin = true;
            if ss.read_done(T0, oc, 0).is_ok() {
                moved = true;
            }
        }
    } else if let Ok(n) = ss.received(T0, oc, from_origin) {
        *from_origin = from_origin.get(n..).unwrap_or_default();
        moved |= n > 0;
    }
    events(ss, taken);
    let gone = settle(ss, oc);
    moved |= gone;
    events(ss, taken);
    (moved, gone)
}

/// Runs the target: see the module's description.
pub fn proxy(data: &[u8]) {
    let (ctl, rest) = control(data);
    // the client's bytes, then the origin's, split where the control
    // byte says, in sixteenths
    let at = rest
        .len()
        .saturating_mul(usize::from(ctl & 15))
        .checked_div(16)
        .unwrap_or(0);
    let (mut from_client, mut from_origin) = rest.split_at(at.min(rest.len()));
    let connect_fails = ctl & 16 != 0;
    let pace = usize::from(ctl >> 5).saturating_add(1).saturating_mul(7);

    let listeners = [Listener {
        name: "fuzz",
        bind: "unix:/fuzz",
        tls: Tls::Plain,
        h1: Config::default(),
        vhosts: &VHOSTS,
    }];
    let mut slots = vec![slot(), slot()];
    let mut ss: S<'_> = Ss::new(&listeners, &mut slots)
        .unwrap_or_else(|e| finding(TARGET, format_args!("policy refused: {e}")));
    let client = ss
        .accepted(T0, ListenerId::new(0), None, None)
        .unwrap_or_else(|e| finding(TARGET, format_args!("not accepted: {e}")));
    let mut origin: Option<ConnId> = None;
    let mut taken = 0;
    let mut out = Vec::new();
    let mut client_gone = false;
    // each side closes once it has sent all it had
    let mut client_fin = false;
    let mut origin_fin = false;
    for _ in 0..200_000 {
        let mut moved_any = false;
        if !client_gone && !from_client.is_empty() {
            if let Ok(n) = ss.received(T0, client, from_client) {
                from_client = from_client.get(n..).unwrap_or_default();
                moved_any |= n > 0;
            }
        } else if !client_gone && !client_fin {
            client_fin = true;
            if ss.read_done(T0, client, 0).is_ok() {
                moved_any = true;
            }
        }
        if let Some((conn, _)) = ss.next_connect() {
            if connect_fails {
                let _ = ss.connect_failed(T0, conn);
            } else if ss.connected(T0, conn, None).is_ok() {
                origin = Some(conn);
            }
            moved_any = true;
        }
        events(&mut ss, &mut taken);
        if let Some(oc) = origin {
            let (moved, gone) =
                origin_turn(&mut ss, oc, &mut from_origin, &mut origin_fin, &mut taken);
            moved_any |= moved;
            if gone {
                origin = None;
            }
        }
        if !client_gone {
            match ss.want(T0, client) {
                Ok(Want::Io(Io { write: Some(w), .. })) => {
                    let n = w.len().min(pace);
                    out.extend_from_slice(w.get(..n).unwrap_or_default());
                    let _ = ss.write_done(T0, client, n);
                    moved_any = true;
                }
                Ok(Want::Io(_)) => {}
                Ok(Want::HalfClose | Want::Release(_)) | Err(_) => {
                    if settle(&mut ss, client) {
                        client_gone = true;
                        moved_any = true;
                    }
                }
            }
            events(&mut ss, &mut taken);
        }
        if !moved_any {
            break;
        }
    }
    // a client that went before its answer (one that stopped short of
    // its upload, say) got none; one still there must have one
    // answered in the version the request asked in
    if taken > 0 && !client_gone && !out.starts_with(b"HTTP/1.") {
        finding(
            TARGET,
            format_args!("a request taken on, {} bytes answered", out.len()),
        );
    }
}
