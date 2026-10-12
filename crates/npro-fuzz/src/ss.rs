//! The ss-server target: npro-ss' server streams, driven every which way.

use core::time::Duration;

use npro_core::random::SeededRandom;
use npro_core::time::Instant;
use npro_h1::server::Config;
use npro_io::driver::{Buffers, NetBuffers, Want};
use npro_ss::event::{End, Filled, Kind, Response};
use npro_ss::id::{ConnId, ListenerId, StreamId};
use npro_ss::policy::{Deflate, Listener, Payload, Tls, Ws, WsServer};
use npro_ss::ss::{AcceptError, CallError, ConnStorage, Slot, Ss};

use crate::targets::{control, finding};

const TARGET: &str = "ss-server";

/// The slots: few, so they run out.
const SLOTS: usize = 3;

/// The most events one look at the streams may give before it is a
/// finding: the input is short, so a look that does not end is a loop.
const MAX_EVENTS: usize = 4096;

const T0: Instant = Instant::from_micros(1_000_000_000);

type S<'s> = Ss<'s, (), Vec<u8>, SeededRandom>;

const PROTOCOLS: [&[u8]; 1] = [b"echo"];

fn listeners() -> [Listener<'static>; 2] {
    [
        Listener {
            name: "h1",
            bind: "unix:/h1",
            tls: Tls::Plain,
            h1: Config::default(),
            ws: Ws::NotTaken,
            headers: &[(b"x-vhost", b"1")],
        },
        Listener {
            name: "ws",
            bind: "unix:/ws",
            tls: Tls::Plain,
            h1: Config::default(),
            ws: Ws::Taken(WsServer {
                protocols: &PROTOCOLS,
                default: Some(0),
                payload: Payload::Binary,
                deflate: Deflate::Offered,
            }),
            headers: &[],
        },
    ]
}

/// Small buffers, so they fill and hold the peer back.
fn slot() -> Slot<(), Vec<u8>, SeededRandom> {
    Slot::new(ConnStorage {
        h1: npro_h1::Storage {
            table: vec![0; 512],
            out: vec![0; npro_h1::server::MIN_OUT],
        },
        bufs: Buffers {
            rx: vec![0; 96],
            tx: vec![0; 96],
            inflate: vec![0; npro_ws::pmd::RX_CHUNK],
        },
        net: NetBuffers {
            rx: Vec::new(),
            tx: Vec::new(),
        },
    })
}

/// What the model knows of a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Known {
    Live,
    Destroyed,
    Disconnected,
}

/// The run: the streams, and what the model knows of them.
struct Run<'s> {
    ss: S<'s>,
    now: Instant,
    /// Connections accepted, and whether each was released.
    conns: Vec<(ConnId, bool)>,
    streams: Vec<(StreamId, Known)>,
    accepted: usize,
    /// How the application last chose to answer.
    how: u8,
}

/// Takes the next byte of `ops`, or 0 once there are none.
fn take(ops: &mut &[u8]) -> u8 {
    let (b, rest) = ops.split_first().map_or((0, &[][..]), |(b, r)| (*b, r));
    *ops = rest;
    b
}

impl Run<'_> {
    fn conn(&self, pick: u8) -> Option<ConnId> {
        let live: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, released)| !released)
            .map(|(c, _)| *c)
            .collect();
        let at = usize::from(pick).checked_rem(live.len())?;
        live.get(at).copied()
    }

    fn known(&self, s: StreamId) -> Option<Known> {
        self.streams
            .iter()
            .find(|(id, _)| *id == s)
            .map(|(_, k)| *k)
    }

    fn set(&mut self, s: StreamId, k: Known) {
        match self.streams.iter_mut().find(|(id, _)| *id == s) {
            Some(e) => e.1 = k,
            None => self.streams.push((s, k)),
        }
    }

    /// The most slots that may be held: by a connection not released, by
    /// a stream not yet destroyed or told it is gone, and by the one told
    /// last, whose slot is let go at the next look.  A stream on a
    /// connection not released is counted twice, so this is never less.
    fn holding(&self) -> usize {
        let unreleased = self.conns.iter().filter(|(_, r)| !r).count();
        let ended = self
            .streams
            .iter()
            .filter(|(_, k)| *k != Known::Live)
            .count();
        unreleased
            .saturating_add(self.accepted.saturating_sub(ended))
            .saturating_add(1)
    }

    fn accept(&mut self, listener: u8) {
        let must = self.holding() < SLOTS;
        match self
            .ss
            .accepted(self.now, ListenerId::new(u32::from(listener % 2)), None)
        {
            Ok(c) => {
                self.conns.push((c, false));
                self.accepted = self.accepted.saturating_add(1);
            }
            Err(AcceptError::Full) if !must => {}
            Err(e) => finding(TARGET, format_args!("accept refused: {e}")),
        }
    }

    fn feed(&mut self, pick: u8, mut bytes: &[u8]) {
        let Some(c) = self.conn(pick) else {
            return;
        };
        while !bytes.is_empty() {
            let Ok(n) = self.ss.received(self.now, c, bytes) else {
                finding(TARGET, format_args!("{c} gone before it was released"));
            };
            bytes = bytes.get(n..).unwrap_or_default();
            if bytes.is_empty() {
                return;
            }
            // full: what came is taken, as the application last chose,
            // making room, or the rest is not read
            let before = bytes.len();
            self.events(self.how);
            let Ok(again) = self.ss.received(self.now, c, bytes) else {
                finding(TARGET, format_args!("{c} gone before it was released"));
            };
            bytes = bytes.get(again..).unwrap_or_default();
            if bytes.len() == before {
                return;
            }
        }
    }

    /// Looks at what happened, answering as `how` says.
    fn events(&mut self, how: u8) {
        for _ in 0..MAX_EVENTS {
            let Some(ev) = self.ss.poll_event(self.now) else {
                return;
            };
            let stream = ev.stream;
            let then = match ev.kind {
                Kind::ServerTxn(mut txn) => {
                    let _ = (txn.method(), txn.path(), txn.header(b"host"));
                    let length = (how & 2 == 0).then_some(u64::from(how >> 4));
                    if how & 1 == 0 {
                        // an answer may be refused, as the role says: the
                        // stream goes on, unanswered
                        let ok = txn
                            .respond(Response {
                                status: 200,
                                content_type: Some(b"text/plain"),
                                content_length: length,
                                headers: &[(b"x-app", b"2")],
                            })
                            .is_ok();
                        if ok { Then::Tx } else { Then::Nothing }
                    } else if how & 4 != 0 {
                        Then::Destroy
                    } else {
                        Then::Nothing
                    }
                }
                Kind::Rx { end, .. } => {
                    if end == End::Last && how & 8 != 0 {
                        Then::TxLen(u64::from(how >> 4))
                    } else {
                        Then::Nothing
                    }
                }
                Kind::Tx(tx) => {
                    let mut left = usize::from(how >> 3);
                    let gave = tx.fill(|buf| {
                        let n = left.min(buf.len());
                        if let Some(b) = buf.get_mut(..n) {
                            b.fill(b'x');
                        }
                        left = left.saturating_sub(n);
                        if left == 0 {
                            Filled::Last(n)
                        } else {
                            Filled::More(n)
                        }
                    });
                    if gave > usize::from(how >> 3) {
                        finding(TARGET, format_args!("gave {gave}, had {}", how >> 3));
                    }
                    Then::Nothing
                }
                Kind::Disconnected => Then::Gone,
                Kind::ServerUpgrade { .. }
                | Kind::UpgradeRefused(_)
                | Kind::Pong
                | Kind::PeerClose { .. } => Then::Nothing,
            };
            match self.known(stream) {
                None | Some(Known::Live) => {}
                Some(k) => finding(TARGET, format_args!("{stream}, {k:?}, told more")),
            }
            self.set(stream, Known::Live);
            match then {
                Then::Nothing => {}
                Then::Tx => self.call(stream, |ss| ss.request_tx(stream)),
                Then::TxLen(n) => self.call(stream, |ss| ss.request_tx_len(stream, n)),
                Then::Destroy => {
                    let now = self.now;
                    self.call(stream, |ss| ss.destroy(now, stream));
                    self.set(stream, Known::Destroyed);
                    if self.ss.request_tx(stream) != Err(CallError::Gone) {
                        finding(TARGET, format_args!("{stream} destroyed, still there"));
                    }
                }
                Then::Gone => {
                    self.set(stream, Known::Disconnected);
                    if self.ss.request_tx(stream) != Err(CallError::Gone) {
                        finding(TARGET, format_args!("{stream} gone, still there"));
                    }
                }
            }
        }
        finding(
            TARGET,
            format_args!("more than {MAX_EVENTS} events at once"),
        );
    }

    /// A call on a live stream: refused only as its protocol refuses it.
    fn call(&mut self, stream: StreamId, f: impl FnOnce(&mut S<'_>) -> Result<(), CallError>) {
        match f(&mut self.ss) {
            Ok(()) | Err(CallError::Protocol) => {}
            Err(CallError::Gone) => finding(TARGET, format_args!("{stream} live, refused")),
        }
    }

    /// Writes up to `max` of what a connection has.
    fn write(&mut self, pick: u8, max: usize) {
        let Some(c) = self.conn(pick) else {
            return;
        };
        if let Ok(Want::Io(io)) = self.ss.want(self.now, c) {
            if let Some(w) = io.write {
                let n = w.len().min(max);
                let _ = self.ss.write_done(self.now, c, n);
            }
        }
    }

    /// Carries every connection's close along: a half-close done, a release
    /// done and its id then refused.
    fn settle(&mut self) {
        for i in 0..self.conns.len() {
            let Some((c, false)) = self.conns.get(i).copied() else {
                continue;
            };
            match self.ss.want(self.now, c) {
                Ok(Want::HalfClose) => {
                    let _ = self.ss.half_closed(self.now, c);
                }
                Ok(Want::Release(_)) => {
                    if self.ss.released(c).is_err() {
                        finding(TARGET, format_args!("{c} not released"));
                    }
                    if self.ss.want(self.now, c).is_ok() {
                        finding(TARGET, format_args!("{c} released, still there"));
                    }
                    if let Some(e) = self.conns.get_mut(i) {
                        e.1 = true;
                    }
                }
                Ok(Want::Io(_)) => {}
                Err(_) => finding(TARGET, format_args!("{c} gone before it was released")),
            }
        }
    }
}

impl Run<'_> {
    /// Every id whose stream or connection ended stays refused, whatever
    /// its slot carries now.
    fn audit(&mut self) {
        for (c, released) in self.conns.clone() {
            if released && self.ss.want(self.now, c).is_ok() {
                finding(TARGET, format_args!("{c} released, taken for another"));
            }
        }
        for (s, k) in self.streams.clone() {
            if k != Known::Live && self.ss.request_tx(s) != Err(CallError::Gone) {
                finding(TARGET, format_args!("{s} {k:?}, taken for another"));
            }
        }
    }
}

/// What the application does after an event.
#[derive(Clone, Copy)]
enum Then {
    Nothing,
    Tx,
    TxLen(u64),
    Destroy,
    Gone,
}

/// npro-ss's server streams on two listeners, h1 and ws with
/// permessage-deflate, in three slots with small buffers, driven by the
/// input: accepts, bytes from peers, the application's answers and calls,
/// short writes, hangups, FINs, and time passing.
///
/// Nothing panics; no look at the streams goes on without end; a stream is
/// never told anything once destroyed or told it is gone, and its id is
/// refused from then; a released connection's id is refused; an accept is
/// refused only when the slots are in use; and an id whose stream or
/// connection ended is refused even once its slot carries another.  At the
/// end, every connection hung up and released, each stream accepted was
/// destroyed or told it is gone, once, and every slot takes a connection
/// again.
pub fn ss_server(data: &[u8]) {
    let (_, mut ops) = control(data);
    let ls = listeners();
    let mut slots: Vec<_> = (0..SLOTS).map(|_| slot()).collect();
    let ss = Ss::new(&ls, &mut slots)
        .unwrap_or_else(|e| finding(TARGET, format_args!("policy refused: {e}")));
    let mut run = Run {
        ss,
        now: T0,
        conns: Vec::new(),
        streams: Vec::new(),
        accepted: 0,
        how: 0,
    };
    while !ops.is_empty() {
        let op = take(&mut ops);
        let arg = op >> 3;
        match op & 7 {
            0 => run.accept(arg),
            1 => {
                let len = usize::from(take(&mut ops) % 48).min(ops.len());
                let (bytes, rest) = ops.split_at(len);
                ops = rest;
                run.feed(arg, bytes);
            }
            2 => {
                run.how = take(&mut ops);
                run.events(run.how);
            }
            3 => run.write(arg, usize::from(take(&mut ops))),
            4 => {
                if let Some(c) = run.conn(arg) {
                    let _ = run.ss.hangup(run.now, c);
                }
            }
            5 => {
                run.now = run.now.saturating_add(Duration::from_secs(u64::from(arg)));
                for (c, released) in run.conns.clone() {
                    if !released {
                        let _ = run.ss.timer(run.now, c);
                    }
                }
            }
            6 => {
                if let Some(c) = run.conn(arg) {
                    let _ = run.ss.read_done(run.now, c, 0);
                }
            }
            _ => run.settle(),
        }
        run.settle();
        run.audit();
    }
    // the end: everything hung up, carried to its release, and told
    for (c, released) in run.conns.clone() {
        if !released {
            let _ = run.ss.hangup(run.now, c);
        }
    }
    run.settle();
    run.events(0);
    run.events(0);
    let ends = run
        .streams
        .iter()
        .filter(|(_, k)| *k != Known::Live)
        .count();
    if ends != run.accepted {
        finding(
            TARGET,
            format_args!("{} accepted, {ends} ended: {:?}", run.accepted, run.streams),
        );
    }
    for i in 0..SLOTS {
        if let Err(e) = run.ss.accepted(run.now, ListenerId::new(0), None) {
            finding(TARGET, format_args!("slot {i} of {SLOTS} lost: {e}"));
        }
    }
    run.audit();
}
