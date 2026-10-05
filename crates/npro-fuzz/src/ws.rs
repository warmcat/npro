//! The ws target: a server's frame parser, as C's `fuzz-ws` has it, after
//! an upgrade.

use npro_ws::conn::{Event, Kind, Ws};

use crate::targets::{Pieces, control, finding};

const TARGET: &str = "ws-server";

/// The most a piece is unmasked into: the fuzzer's input is copied here,
/// since the parser unmasks where the bytes lie.
const MAX_INPUT: usize = 64 * 1024;

/// What the application was handed, a message being whole once it is.
#[derive(Debug, PartialEq, Eq)]
enum Given {
    Message(Kind, Vec<u8>),
    Pong(Vec<u8>),
    PeerClose(Vec<u8>),
}

/// Everything a run came to: what the application was handed, the part of
/// a message still open, what the server wrote, and how it closed.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    given: Vec<Given>,
    open: Option<(Kind, Vec<u8>)>,
    wrote: Vec<u8>,
    close: Option<npro_ws::conn::Close>,
}

struct Nothing;

impl npro_h1::server::TxSource for Nothing {
    fn fill(&mut self, _: &mut [u8]) -> usize {
        0
    }
}

/// Feeds `pieces` to a fresh server, checking what each call says as it
/// goes; writes nothing until the end, so the run does not depend on when
/// the pong slot is drained.
fn run<'a>(how: &str, pieces: impl Iterator<Item = &'a [u8]>) -> Run {
    let mut ws = Ws::server(b"");
    let mut given = Vec::new();
    let mut open: Option<(Kind, Vec<u8>)> = None;
    let mut buf = Vec::new();
    for piece in pieces {
        buf.clear();
        buf.extend_from_slice(piece);
        let mut at = 0usize;
        while let Some(input) = buf.get_mut(at..).filter(|i| !i.is_empty()) {
            let rx = ws.rx(input);
            if rx.consumed == 0 {
                finding(
                    TARGET,
                    format_args!("{how}: took none of {} bytes", input.len()),
                );
            }
            at = at.saturating_add(rx.consumed);
            let Some(ev) = rx.event else { continue };
            if matches!(given.last(), Some(Given::PeerClose(_))) {
                finding(TARGET, format_args!("{how}: {ev:?} after the peer's close"));
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
                            TARGET,
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
                Event::Pong(p) => given.push(Given::Pong(p.to_vec())),
                Event::PeerClose(p) => given.push(Given::PeerClose(p.to_vec())),
            }
        }
    }
    let mut wrote = Vec::new();
    let mut out = [0u8; 64];
    loop {
        let n = ws.tx(&mut out, &mut Nothing);
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

/// The frames a server wrote, checked as a client would read them: each
/// whole, final and unmasked, a control frame at most 125 bytes, a close's
/// payload a code and its reason, and nothing after a close.
///
/// `peer_close` is the payload of the peer's close, if it sent one.  C
/// answers with it whatever it is, a lone byte included, which RFC 6455
/// 5.5.1 does not allow, and npro does as C does: so a close of one byte
/// is taken from npro only as that echo.
fn check_written(wrote: &[u8], peer_close: Option<&[u8]>) {
    let mut rest = wrote;
    while let [b0, b1, tail @ ..] = rest {
        let (op, len) = (b0 & 0x0f, usize::from(b1 & 0x7f));
        if b0 & 0xf0 != 0x80 || b1 & 0x80 != 0 || len > 125 {
            finding(TARGET, format_args!("wrote a frame {b0:#04x} {b1:#04x}"));
        }
        let Some((payload, after)) = tail.split_at_checked(len) else {
            finding(
                TARGET,
                format_args!("wrote {} of a {len} byte frame", tail.len()),
            );
        };
        match op {
            // a pong, of a ping's payload
            0xa => {}
            0x8 => {
                let echoed = peer_close == Some(payload);
                if (payload.len() == 1 && !echoed) || !after.is_empty() {
                    finding(
                        TARGET,
                        format_args!("wrote a close {payload:?} then {after:?}"),
                    );
                }
            }
            _ => finding(
                TARGET,
                format_args!("wrote opcode {op:#x} with nothing sent"),
            ),
        }
        rest = after;
    }
    if !rest.is_empty() {
        finding(
            TARGET,
            format_args!("wrote a frame of {} bytes", rest.len()),
        );
    }
}

/// The text message a run leaves open, empty if none; `None` for binary.
fn open_text(r: &Run) -> Option<&[u8]> {
    match &r.open {
        None => Some(&[]),
        Some((Kind::Text, t)) => Some(t),
        Some((Kind::Binary, _)) => None,
    }
}

/// Whether two runs leave the same message open.  Text is handed over a
/// piece at a time once each piece checks out, so where it turns out not to
/// be UTF-8, how much of its good start went first depends on the split:
/// then, and only then, one run's open message need only start the other's.
fn opens_agree(a: &Run, b: &Run) -> bool {
    if a.open == b.open {
        return true;
    }
    let bad_utf8 = a.wrote.get(..4) == Some(b"\x88\x0a\x03\xef".as_slice())
        || a.wrote.get(..4) == Some(b"\x88\x0e\x03\xef".as_slice());
    match (open_text(a), open_text(b)) {
        (Some(x), Some(y)) => bad_utf8 && (x.starts_with(y) || y.starts_with(x)),
        (None, _) | (_, None) => false,
    }
}

/// A client's frames as a server reads them after the upgrade: C's
/// `fuzz-ws`.
///
/// The first byte chooses how the rest is split.  In one piece and in
/// pieces, the server must hand the application the same messages, pongs
/// and close, write the same, and close the same, of a message it refuses
/// as not UTF-8 having handed over a start of it that may differ (see
/// `opens_agree`); every call must take
/// something; a message's pieces must say where it starts; nothing may
/// follow the peer's close; a whole text message must be UTF-8 by
/// `core::str`; and what the server writes must be frames a client reads.
pub fn ws_server(data: &[u8]) {
    let (ctl, frames) = control(data);
    let frames = frames.get(..MAX_INPUT).unwrap_or(frames);
    let whole = run("whole", core::iter::once(frames));
    let pieces = run("in pieces", Pieces::new(ctl, frames));
    if whole.given != pieces.given
        || whole.wrote != pieces.wrote
        || whole.close != pieces.close
        || !opens_agree(&whole, &pieces)
    {
        finding(
            TARGET,
            format_args!("whole {whole:?}, in pieces {pieces:?}"),
        );
    }
    let texts = whole.given.iter().filter_map(|g| match g {
        Given::Message(Kind::Text, t) => Some(t),
        Given::Message(Kind::Binary, _) | Given::Pong(_) | Given::PeerClose(_) => None,
    });
    for t in texts {
        if core::str::from_utf8(t).is_err() {
            finding(TARGET, format_args!("text {t:?} is not UTF-8"));
        }
    }
    let peer_close = whole.given.iter().find_map(|g| match g {
        Given::PeerClose(p) => Some(p.as_slice()),
        Given::Message(..) | Given::Pong(_) => None,
    });
    check_written(&whole.wrote, peer_close);
}
