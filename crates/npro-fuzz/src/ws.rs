//! The ws targets: a server's frame parser, as C's `fuzz-ws` has it, after
//! an upgrade, and a client's, and a server's with permessage-deflate, as
//! C's `fuzz-ws-pmd`.

use npro_core::random::{Random, Unavailable};
use npro_core::time::Instant;
use npro_ws::conn::{Close, Event, Kind, Role, Side, Ws};
use npro_ws::pmd::{Params, RX_CHUNK};

use crate::targets::{Pieces, control, finding};

/// The most a piece is unmasked into: the fuzzer's input is copied here,
/// since the parser unmasks where the bytes lie.
const MAX_INPUT: usize = 64 * 1024;

/// The most a message may inflate to in `ws-pmd`: small, so a zip bomb is
/// within the fuzzer's reach, where C's is 256MiB.
const FUZZ_MAX_MESSAGE: u64 = 1 << 20;

/// When a run happens: all of it at once, so no deadline falls due and the
/// run is the frames' alone.
const T0: Instant = Instant::from_micros(1_000_000);

/// The mask a client's frames are written with: not zero, so masking is
/// done, and fixed, so a run is its input's alone.
const MASK: [u8; 4] = [0x5a, 0xa5, 0x0f, 0xf0];

/// A client's masks.
struct FixedMask;

impl Random for FixedMask {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Unavailable> {
        for (b, m) in buf.iter_mut().zip(MASK.iter().cycle()) {
            *b = *m;
        }
        Ok(())
    }
}

/// What the application was handed, a message being whole once it is.
#[derive(Debug, PartialEq, Eq)]
enum Given {
    Message(Kind, Vec<u8>),
    Pong(Vec<u8>),
    PeerClose(Vec<u8>),
}

/// Everything a run came to: what the application was handed, the part of
/// a message still open, what was written, and how it closed.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    given: Vec<Given>,
    open: Option<(Kind, Vec<u8>)>,
    wrote: Vec<u8>,
    close: Option<Close>,
}

struct Nothing;

impl npro_h1::server::TxSource for Nothing {
    fn fill(&mut self, _: &mut [u8]) -> usize {
        0
    }
}

/// Feeds `pieces` to `ws`, checking what each call says as it goes;
/// writes nothing until the end, so the run does not depend on when the
/// pong slot is drained.
fn run<'a, P: Role>(
    target: &str,
    how: &str,
    mut ws: Ws<P>,
    pieces: impl Iterator<Item = &'a [u8]>,
) -> Run {
    let mut given = Vec::new();
    let mut open: Option<(Kind, Vec<u8>)> = None;
    let mut buf = Vec::new();
    for piece in pieces {
        buf.clear();
        buf.extend_from_slice(piece);
        let mut at = 0usize;
        // calls with nothing to take that gave nothing, while it said it
        // had more to give
        let mut idle = 0u8;
        let mut inflated = [0u8; RX_CHUNK];
        while let Some(input) = buf.get_mut(at..) {
            let draining = input.is_empty();
            if draining && !ws.rx_pending() {
                break;
            }
            let len = input.len();
            let rx = ws.rx(T0, input, &mut inflated);
            if rx.consumed == 0 && rx.event.is_none() && !draining {
                finding(target, format_args!("{how}: took none of {len} bytes"));
            }
            if draining && rx.event.is_none() {
                idle = idle.saturating_add(1);
                if idle > 2 {
                    finding(target, format_args!("{how}: pending, but gives nothing"));
                }
            } else {
                idle = 0;
            }
            at = at.saturating_add(rx.consumed);
            let Some(ev) = rx.event else { continue };
            if matches!(given.last(), Some(Given::PeerClose(_))) {
                finding(target, format_args!("{how}: {ev:?} after the peer's close"));
            }
            match ev {
                Event::Message {
                    kind,
                    data,
                    first,
                    last,
                } => {
                    let mut m = match (first, open.take()) {
                        (true, None) => (kind, Vec::new()),
                        (false, Some(m)) if m.0 == kind => m,
                        (_, was) => finding(
                            target,
                            format_args!("{how}: first {first} with {was:?} open"),
                        ),
                    };
                    m.1.extend_from_slice(data);
                    if last {
                        given.push(Given::Message(m.0, m.1));
                    } else {
                        open = Some(m);
                    }
                }
                Event::Pong(p) => given.push(Given::Pong(p.payload().to_vec())),
                Event::PeerClose(p) => given.push(Given::PeerClose(p.payload().to_vec())),
            }
        }
    }
    let mut wrote = Vec::new();
    let mut out = [0u8; 64];
    loop {
        let n = ws.tx(T0, &mut out, &mut Nothing);
        if n == 0 {
            break;
        }
        wrote.extend_from_slice(out.get(..n).unwrap_or_default());
    }
    Run {
        given,
        open,
        wrote,
        close: ws.close(),
    }
}

/// The frames `side` wrote, checked as its peer would read them, and
/// returned as their opcodes and payloads: each whole and final, masked
/// with [`MASK`] by a client and not by a server, a control frame at most
/// 125 bytes, a close's payload a code and its reason, and nothing after a
/// close.
///
/// `peer_close` is the payload of the peer's close, if it sent one.  C
/// answers with it whatever it is, a lone byte included, which RFC 6455
/// 5.5.1 does not allow, and npro does as C does: so a close of one byte
/// is taken from npro only as that echo.
fn written(
    target: &str,
    side: Side,
    wrote: &[u8],
    peer_close: Option<&[u8]>,
) -> Vec<(u8, Vec<u8>)> {
    let masked = match side {
        Side::Server => 0,
        Side::Client => 0x80,
    };
    let mut frames = Vec::new();
    let mut rest = wrote;
    while let [b0, b1, tail @ ..] = rest {
        let (op, len) = (b0 & 0x0f, usize::from(b1 & 0x7f));
        if b0 & 0xf0 != 0x80 || b1 & 0x80 != masked || len > 125 {
            finding(target, format_args!("wrote a frame {b0:#04x} {b1:#04x}"));
        }
        let tail = if masked == 0 {
            tail
        } else {
            match tail.split_first_chunk::<4>() {
                Some((m, t)) if *m == MASK => t,
                _ => finding(target, format_args!("wrote a frame without the mask")),
            }
        };
        let Some((payload, after)) = tail.split_at_checked(len) else {
            finding(
                target,
                format_args!("wrote {} of a {len} byte frame", tail.len()),
            );
        };
        let payload: Vec<u8> = if masked == 0 {
            payload.to_vec()
        } else {
            payload
                .iter()
                .zip(MASK.iter().cycle())
                .map(|(b, m)| b ^ m)
                .collect()
        };
        match op {
            // a pong, of a ping's payload
            0xa => {}
            0x8 => {
                let echoed = peer_close == Some(payload.as_slice());
                if (payload.len() == 1 && !echoed) || !after.is_empty() {
                    finding(
                        target,
                        format_args!("wrote a close {payload:?} then {after:?}"),
                    );
                }
            }
            _ => finding(
                target,
                format_args!("wrote opcode {op:#x} with nothing sent"),
            ),
        }
        frames.push((op, payload));
        rest = after;
    }
    if !rest.is_empty() {
        finding(
            target,
            format_args!("wrote a frame of {} bytes", rest.len()),
        );
    }
    frames
}

/// Whether what was written is the close refusing text that is not UTF-8.
fn refused_text(sent: &[(u8, Vec<u8>)]) -> bool {
    matches!(
        sent.first(),
        Some((0x8, p)) if p.get(..2) == Some(&1007u16.to_be_bytes()[..])
    )
}

/// The text message a run leaves open, empty if none; `None` for binary.
fn open_text(r: &Run) -> Option<&[u8]> {
    match &r.open {
        None => Some(&[]),
        Some((Kind::Text, t)) => Some(t),
        Some((Kind::Binary, _)) => None,
    }
}

/// How far two runs may differ in the message they leave open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Open {
    /// As it is handed over, a piece as it comes: the same.
    Plain,
    /// Inflated: how far the inflater gets with the input it has depends
    /// on where that input stops, so one may only start the other.  The
    /// messages that end are compared whole.
    Deflated,
}

/// Whether two runs leave the same message open.  A message is handed
/// over a piece at a time as it comes, so where it turns out not to be
/// UTF-8, `bad_utf8`, or the connection is dropped partway, as a deflated
/// message that does not inflate drops it, how much of its start went first
/// depends on the split: then, and with `open` deflated, only then, one
/// run's open message need only start the other's.
fn opens_agree(a: &Run, b: &Run, bad_utf8: bool, open: Open) -> bool {
    if a.open == b.open {
        return true;
    }
    if a.close == Some(Close::Abort) || open == Open::Deflated {
        let bytes = |r: &Run| r.open.as_ref().map_or(Vec::new(), |(_, m)| m.clone());
        let (x, y) = (bytes(a), bytes(b));
        return x.starts_with(&y) || y.starts_with(&x);
    }
    match (open_text(a), open_text(b)) {
        (Some(x), Some(y)) => bad_utf8 && (x.starts_with(y) || y.starts_with(x)),
        (None, _) | (_, None) => false,
    }
}

/// Runs `frames` through `make()`'s connection whole and in pieces, and
/// checks both: see [`ws_server`].
fn frames<P: Role>(target: &str, data: &[u8], open: Open, make: impl Fn() -> Ws<P>) {
    let (ctl, frames) = control(data);
    let frames = frames.get(..MAX_INPUT).unwrap_or(frames);
    let side = make().side();
    let whole = run(target, "whole", make(), core::iter::once(frames));
    let pieces = run(target, "in pieces", make(), Pieces::new(ctl, frames));

    let peer_close = whole.given.iter().find_map(|g| match g {
        Given::PeerClose(p) => Some(p.as_slice()),
        Given::Message(..) | Given::Pong(_) => None,
    });
    let sent = written(target, side, &whole.wrote, peer_close);
    let sent_in_pieces = written(target, side, &pieces.wrote, peer_close);
    let bad_utf8 = refused_text(&sent) || refused_text(&sent_in_pieces);
    // a deflated message that does not inflate drops the connection; how
    // much it inflates first, before the inflater sees what is wrong,
    // depends on the split, so text it gives that is not UTF-8 may be seen
    // first, or not: either way, it failed
    let failed = |r: &Run, frames_sent: &[(u8, Vec<u8>)]| {
        (r.close == Some(Close::Abort) && r.wrote.is_empty()) || refused_text(frames_sent)
    };
    let ends_agree = (whole.wrote == pieces.wrote && whole.close == pieces.close)
        || (open == Open::Deflated && failed(&whole, &sent) && failed(&pieces, &sent_in_pieces));
    if whole.given != pieces.given || !ends_agree || !opens_agree(&whole, &pieces, bad_utf8, open) {
        finding(
            target,
            format_args!("whole {whole:?}, in pieces {pieces:?}"),
        );
    }
    let texts = whole.given.iter().filter_map(|g| match g {
        Given::Message(Kind::Text, t) => Some(t),
        Given::Message(Kind::Binary, _) | Given::Pong(_) | Given::PeerClose(_) => None,
    });
    for t in texts {
        if core::str::from_utf8(t).is_err() {
            finding(target, format_args!("text {t:?} is not UTF-8"));
        }
    }
}

/// A client's frames as a server reads them after the upgrade: C's
/// `fuzz-ws`.
///
/// The first byte chooses how the rest is split.  In one piece and in
/// pieces, the server must hand the application the same messages, pongs
/// and close, write the same, and close the same, of a message it refuses
/// as not UTF-8 having handed over a start of it that may differ (see
/// `opens_agree`); every call must take something or give something, and
/// while it says it has more to give without input, give it; a message's
/// pieces must
/// say where it starts; nothing may follow the peer's close; a whole text
/// message must be UTF-8 by `core::str`; and what the server writes must be
/// frames a client reads.
pub fn ws_server(data: &[u8]) {
    frames("ws-server", data, Open::Plain, || Ws::server(b"", T0));
}

/// A server's frames as a client reads them after the upgrade: as
/// [`ws_server`], from the client's side, which writes its frames masked.
pub fn ws_client(data: &[u8]) {
    frames("ws-client", data, Open::Plain, || Ws::client(FixedMask, T0));
}

/// A client's frames as a server with permessage-deflate reads them: C's
/// `fuzz-ws-pmd`, whose client offered it with no parameters the server
/// takes.  As [`ws_server`], deflated messages inflating to at most 1MiB,
/// so a zip bomb is within reach.  How far the inflater gets with the input
/// it has depends on where that stops, so a message left unfinished, whole
/// and in pieces, need only start the other; and where a message does not
/// inflate, text in it that is not UTF-8 may be refused first, or not,
/// both runs failing.
pub fn ws_pmd(data: &[u8]) {
    let params = Params::DEFAULT.with_max_message(FUZZ_MAX_MESSAGE);
    frames("ws-pmd", data, Open::Deflated, || {
        Ws::server(b"", T0).with_pmd(params)
    });
}
