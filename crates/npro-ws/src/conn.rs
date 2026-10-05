//! A ws connection: C's `lws_ws_rx_sm()`, its writeable handling and its
//! close, sans-IO.
//!
//! [`Ws::rx`] takes the peer's bytes, at most one thing each call, and
//! unmasks a frame's payload where it lies in the input, so a message's
//! data is handed to the application without a copy: [`Event::Message`],
//! a piece of a message as it arrives, with whether it starts and ends it,
//! as C's `lws_is_first_fragment()` and `lws_is_final_fragment()` say.
//! Control frames, at most 125 bytes, are gathered here: a ping is answered
//! with a pong, a pong is given to the application, and the peer's close
//! is given to it and answered with the peer's own payload, its code made
//! 1002 if it is one no peer may send.
//!
//! What C refuses, this refuses, with C's close code and reason: a
//! fragmented control frame ("frag ctl"), a reserved opcode ("bad opc"), a
//! continuation out of place ("bad cont"), RSV bits ("rsv bits"), a server's
//! unmasked frame ("client unmasked"), a long control frame ("ctl len"), a
//! length with its top bit ("bad len"), all 1002; a frame longer than C's
//! 256MiB, 1009 "huge frame"; text that is not UTF-8, 1007 "bad utf8" or
//! "partial utf8".  After its close, the connection reads nothing more.
//!
//! [`Ws::tx`] writes in C's order: what is in flight first (the 101, a frame
//! begun), then our own close, then the pong, then the answer to the peer's
//! close, then the application's next frame, whose payload it pulls.  A
//! pong still owed when we begin a close is forgotten, as C forgets it.

use npro_core::utf8::Utf8Validator;
use npro_h1::server::TxSource;

/// The longest frame C takes: `LWS_WS_MAX_RX_FRAME_LEN`.
pub const MAX_FRAME: u64 = 0x1000_0000;

/// The longest a control frame's payload may be.
const MAX_CTL: usize = 125;

/// Which end of the connection this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// A server: the client's frames must be masked, ours are not.
    Server,
}

/// What a message is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Text, which must be UTF-8.
    Text,
    /// Binary.
    Binary,
}

/// What the peer's bytes were.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// A piece of a message: C's `LWS_CALLBACK_RECEIVE`.
    Message {
        /// What the message is.
        kind: Kind,
        /// The piece.
        data: &'a [u8],
        /// It starts the message.
        first: bool,
        /// It ends the message.
        last: bool,
    },
    /// A pong, with its payload: C's `LWS_CALLBACK_RECEIVE_PONG`.
    Pong(&'a [u8]),
    /// The peer's close, with its payload: C's
    /// `LWS_CALLBACK_WS_PEER_INITIATED_CLOSE`.  It is answered.
    PeerClose(&'a [u8]),
}

/// What [`Ws::rx`] took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rx<'a> {
    /// How many bytes it took.  The rest are the caller's to hand in again.
    pub consumed: usize,
    /// What they were, if they came to something.
    pub event: Option<Event<'a>>,
}

/// What the connection asks of its carrier, once it is done with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
    /// Stop sending once what was written has gone.
    Shutdown,
    /// Release it: the close handshake is over.
    Release,
}

/// Why a frame cannot be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// A frame is still going, or the connection is closing.
    Busy,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a frame is still going, or the connection is closing")
    }
}

impl core::error::Error for SendError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Op {
    const fn control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    const fn code(self) -> u8 {
        match self {
            Self::Continuation => 0,
            Self::Text => 1,
            Self::Binary => 2,
            Self::Close => 8,
            Self::Ping => 9,
            Self::Pong => 10,
        }
    }
}

/// A frame's header as it has come so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frame {
    op: Op,
    fin: bool,
    masked: bool,
    len: u64,
    mask: [u8; 4],
}

/// Where the frame parser is: C's `lws_rx_parse_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Parse {
    /// The first byte of a frame.
    First,
    /// The length byte.
    Len(Frame),
    /// This many more bytes of an extended length.
    LenMore(Frame, u8),
    /// This many more bytes of the mask.
    Mask(Frame, u8),
    /// This much payload is still to come; `at` of it came so far.
    Payload(Frame, u64),
    /// Nothing more is read.
    Stopped,
}

/// Where a message is, between frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Msg {
    /// Between messages.
    Idle,
    /// A message is under way, and its first piece has been given or not.
    Open { kind: Kind, given: Given },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Given {
    Nothing,
    Some,
}

/// A control frame, its payload gathered or to be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ctl {
    buf: [u8; MAX_CTL],
    len: u8,
}

impl Ctl {
    const fn new() -> Self {
        Self {
            buf: [0; MAX_CTL],
            len: 0,
        }
    }

    fn payload(&self) -> &[u8] {
        self.buf.get(..usize::from(self.len)).unwrap_or_default()
    }

    fn push(&mut self, b: &[u8]) -> bool {
        let at = usize::from(self.len);
        let Some(end) = at.checked_add(b.len()).filter(|e| *e <= MAX_CTL) else {
            return false;
        };
        if let Some(d) = self.buf.get_mut(at..end) {
            d.copy_from_slice(b);
        }
        self.len = u8::try_from(end).unwrap_or(0);
        true
    }

    fn close(code: u16, reason: &[u8]) -> Self {
        let mut c = Self::new();
        let _ = c.push(&code.to_be_bytes()) && c.push(reason);
        c
    }
}

/// Where the close is: C's close states, `lwsi_close()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Closing {
    /// Open.
    None,
    /// Our close is to go: `LCS_WAITING_TO_SEND_CLOSE`.
    WaitingToSend(Ctl),
    /// Our close has gone: `LCS_AWAITING_CLOSE_ACK`.
    AwaitingAck,
    /// The peer's close is to be answered: `LCS_RETURNED_CLOSE`.
    Returned(Ctl),
    /// The application closes once what it sent has gone:
    /// `LCS_FLUSHING_BEFORE_CLOSE`.
    Flushing,
    /// Done with.
    Closed(Close),
}

/// Bytes being written, and how many of them have gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Out {
    buf: [u8; 256],
    len: usize,
    sent: usize,
}

impl Out {
    const fn new() -> Self {
        Self {
            buf: [0; 256],
            len: 0,
            sent: 0,
        }
    }

    const fn pending(&self) -> bool {
        self.sent < self.len
    }

    fn set(&mut self, b: &[u8]) {
        *self = Self::new();
        if let Some(d) = self.buf.get_mut(..b.len()) {
            d.copy_from_slice(b);
            self.len = b.len();
        }
    }

    fn drain(&mut self, out: &mut [u8]) -> usize {
        let rest = self.buf.get(self.sent..self.len).unwrap_or_default();
        let n = rest.len().min(out.len());
        if let (Some(d), Some(s)) = (out.get_mut(..n), rest.get(..n)) {
            d.copy_from_slice(s);
        }
        self.sent = self.sent.saturating_add(n);
        n
    }
}

/// The application's frame, its header written or not, its payload owed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum App {
    Idle,
    Sending { owed: u64 },
}

/// A frame's header, unmasked, as a server writes it.
fn frame_header(op: Op, len: u64, out: &mut Out) {
    // the length is 7 bits, or 126 and 16 bits, or 127 and 64 bits: the
    // last of its big endian bytes, after the marker
    let be = len.to_be_bytes();
    let (marker, extra) = match u8::try_from(len) {
        Ok(short @ 0..126) => (short, 0),
        Ok(_) | Err(_) if u16::try_from(len).is_ok() => (126, 2),
        Ok(_) | Err(_) => (127, 8),
    };
    let mut header = [0x80 | op.code(), marker, 0, 0, 0, 0, 0, 0, 0, 0];
    let used = 2usize.saturating_add(extra);
    if let (Some(d), Some(s)) = (
        header.get_mut(2..used),
        be.get(be.len().saturating_sub(extra)..),
    ) {
        d.copy_from_slice(s);
    }
    out.set(header.get(..used).unwrap_or_default());
}

/// A control frame, header and payload.
fn control_frame(op: Op, c: &Ctl, out: &mut Out) {
    let p = c.payload();
    let mut b = [0u8; 2 + MAX_CTL];
    if let Some(h) = b.get_mut(..2) {
        h.copy_from_slice(&[0x80 | op.code(), c.len]);
    }
    if let Some(d) = b.get_mut(2..2usize.saturating_add(p.len())) {
        d.copy_from_slice(p);
    }
    out.set(b.get(..2usize.saturating_add(p.len())).unwrap_or_default());
}

/// One ws connection.
///
/// ```
/// use npro_ws::conn::{Event, Kind, Ws};
///
/// let mut ws = Ws::server(b"");
/// // a masked "Hi", with a zero mask
/// let mut frame = *b"\x81\x82\0\0\0\0Hi";
/// let rx = ws.rx(&mut frame);
/// assert_eq!(
///     rx.event,
///     Some(Event::Message { kind: Kind::Text, data: b"Hi", first: true, last: true })
/// );
/// ```
#[derive(Clone, Debug)]
pub struct Ws {
    parse: Parse,
    msg: Msg,
    utf8: Utf8Validator,
    /// A control frame's payload, gathered.
    ctl: Ctl,
    /// The pong owed, if any: C's one pending pong.
    pong: Option<Ctl>,
    closing: Closing,
    out: Out,
    app: App,
}

impl Ws {
    /// A server's connection, `first` being what goes before its frames:
    /// the 101.
    #[must_use]
    pub fn server(first: &[u8]) -> Self {
        let mut out = Out::new();
        out.set(first);
        Self {
            parse: Parse::First,
            msg: Msg::Idle,
            utf8: Utf8Validator::new(),
            ctl: Ctl::new(),
            pong: None,
            closing: Closing::None,
            out,
            app: App::Idle,
        }
    }

    /// What the connection asks of its carrier, once it is done with.
    #[must_use]
    pub const fn close(&self) -> Option<Close> {
        match self.closing {
            Closing::Closed(c) => Some(c),
            Closing::None
            | Closing::WaitingToSend(_)
            | Closing::AwaitingAck
            | Closing::Returned(_)
            | Closing::Flushing => None,
        }
    }

    /// Whether the connection has something of its own to write.
    #[must_use]
    pub const fn wants_write(&self) -> bool {
        self.out.pending()
            || self.pong.is_some()
            || matches!(
                self.closing,
                Closing::WaitingToSend(_) | Closing::Returned(_)
            )
    }

    /// Fails the connection with our close: C's `lws_close_reason()` and
    /// `LWS_HPI_RET_PLEASE_CLOSE_ME`.
    fn refuse<'a>(&mut self, code: u16, reason: &[u8]) -> Rx<'a> {
        self.parse = Parse::Stopped;
        if matches!(self.closing, Closing::None) {
            self.closing = Closing::WaitingToSend(Ctl::close(code, reason));
        }
        Rx {
            consumed: 0,
            event: None,
        }
    }

    /// Takes bytes from the peer: see [`Event`].  A frame's payload is
    /// unmasked where it lies in `input`.
    pub fn rx<'a>(&'a mut self, input: &'a mut [u8]) -> Rx<'a> {
        let mut used = 0usize;
        loop {
            match self.parse {
                Parse::Stopped => {
                    // after its close, nothing more is read
                    return Rx {
                        consumed: input.len(),
                        event: None,
                    };
                }
                Parse::Payload(f, left) => return self.payload(f, left, input, used),
                Parse::First | Parse::Len(_) | Parse::LenMore(..) | Parse::Mask(..) => {}
            }
            let Some(&c) = input.get(used) else {
                return Rx {
                    consumed: used,
                    event: None,
                };
            };
            used = used.saturating_add(1);
            if let Some((code, reason)) = self.header(c) {
                let mut r = self.refuse(code, reason);
                r.consumed = used;
                return r;
            }
        }
    }

    /// One byte of a frame's header; `Some` refuses the frame.
    fn header(&mut self, c: u8) -> Option<(u16, &'static [u8])> {
        match self.parse {
            Parse::First => {
                let fin = c & 0x80 != 0;
                let op = match c & 0x0f {
                    0 => Op::Continuation,
                    1 => Op::Text,
                    2 => Op::Binary,
                    8 => Op::Close,
                    9 => Op::Ping,
                    10 => Op::Pong,
                    _ => {
                        if c & 0x08 != 0 && !fin {
                            return Some((1002, b"frag ctl"));
                        }
                        return Some((1002, b"bad opc"));
                    }
                };
                if op.control() && !fin {
                    return Some((1002, b"frag ctl"));
                }
                match (op, self.msg) {
                    (Op::Text | Op::Binary, Msg::Open { .. }) | (Op::Continuation, Msg::Idle) => {
                        return Some((1002, b"bad cont"));
                    }
                    (Op::Text, Msg::Idle) => {
                        self.utf8 = Utf8Validator::new();
                        self.msg = Msg::Open {
                            kind: Kind::Text,
                            given: Given::Nothing,
                        };
                    }
                    (Op::Binary, Msg::Idle) => {
                        self.msg = Msg::Open {
                            kind: Kind::Binary,
                            given: Given::Nothing,
                        };
                    }
                    (Op::Continuation, Msg::Open { .. })
                    | (Op::Close | Op::Ping | Op::Pong, Msg::Idle | Msg::Open { .. }) => {}
                }
                if c & 0x70 != 0 {
                    return Some((1002, b"rsv bits"));
                }
                self.parse = Parse::Len(Frame {
                    op,
                    fin,
                    masked: false,
                    len: 0,
                    mask: [0; 4],
                });
            }
            Parse::Len(mut f) => {
                f.masked = c & 0x80 != 0;
                if !f.masked {
                    return Some((1002, b"client unmasked"));
                }
                match c & 0x7f {
                    126 | 127 if f.op.control() => return Some((1002, b"ctl len")),
                    126 => self.parse = Parse::LenMore(f, 2),
                    127 => self.parse = Parse::LenMore(f, 8),
                    n => {
                        f.len = u64::from(n);
                        self.parse = Parse::Mask(f, 4);
                    }
                }
            }
            Parse::LenMore(mut f, left) => {
                if left == 8 && c & 0x80 != 0 {
                    return Some((1002, b"bad len"));
                }
                f.len = (f.len << 8) | u64::from(c);
                let left = left.saturating_sub(1);
                if left > 0 {
                    self.parse = Parse::LenMore(f, left);
                } else if f.len > MAX_FRAME {
                    return Some((1009, b"huge frame"));
                } else {
                    self.parse = Parse::Mask(f, 4);
                }
            }
            Parse::Mask(mut f, left) => {
                let i = usize::from(4u8.saturating_sub(left));
                if let Some(m) = f.mask.get_mut(i) {
                    *m = c;
                }
                let left = left.saturating_sub(1);
                self.parse = if left > 0 {
                    Parse::Mask(f, left)
                } else {
                    self.ctl = Ctl::new();
                    Parse::Payload(f, f.len)
                };
            }
            Parse::Payload(..) | Parse::Stopped => {}
        }
        None
    }

    /// The payload of `f`, `left` of it still to come.
    fn payload<'a>(&'a mut self, f: Frame, left: u64, input: &'a mut [u8], used: usize) -> Rx<'a> {
        let rest = input.get_mut(used..).unwrap_or_default();
        let n = usize::try_from(left).unwrap_or(usize::MAX).min(rest.len());
        let at = f.len.saturating_sub(left);
        let piece = rest.get_mut(..n).unwrap_or_default();
        for (i, b) in piece.iter_mut().enumerate() {
            let k = at.wrapping_add(u64::try_from(i).unwrap_or(0)) % 4;
            *b ^= f
                .mask
                .get(usize::try_from(k).unwrap_or(0))
                .copied()
                .unwrap_or(0);
        }
        let left = left.saturating_sub(u64::try_from(n).unwrap_or(left));
        let consumed = used.saturating_add(n);
        if f.op.control() {
            let _ = self.ctl.push(piece);
            if left > 0 {
                self.parse = Parse::Payload(f, left);
                return Rx {
                    consumed,
                    event: None,
                };
            }
            self.parse = Parse::First;
            let event = self.control(f.op);
            return Rx { consumed, event };
        }
        self.parse = if left > 0 {
            Parse::Payload(f, left)
        } else {
            Parse::First
        };
        // a piece of a message: given at the frame's end, or as it comes
        if n == 0 && left > 0 {
            return Rx {
                consumed,
                event: None,
            };
        }
        let Msg::Open { kind, given } = self.msg else {
            return Rx {
                consumed,
                event: None,
            };
        };
        let last = f.fin && left == 0;
        if kind == Kind::Text {
            if self.utf8.feed(piece).is_err() {
                let mut r = self.refuse(1007, b"bad utf8");
                r.consumed = consumed;
                return r;
            }
            if last && !self.utf8.at_boundary() {
                let mut r = self.refuse(1007, b"partial utf8");
                r.consumed = consumed;
                return r;
            }
        }
        self.msg = if last {
            Msg::Idle
        } else {
            Msg::Open {
                kind,
                given: Given::Some,
            }
        };
        // nothing for the app once a close is under way
        if !matches!(self.closing, Closing::None) {
            return Rx {
                consumed,
                event: None,
            };
        }
        Rx {
            consumed,
            event: Some(Event::Message {
                kind,
                data: piece,
                first: given == Given::Nothing,
                last,
            }),
        }
    }

    /// A whole control frame has come.
    fn control(&mut self, op: Op) -> Option<Event<'_>> {
        match op {
            Op::Ping => {
                // one pong owed at a time: a second ping is dropped
                if self.pong.is_none() {
                    self.pong = Some(self.ctl);
                }
                None
            }
            Op::Pong => (self.ctl.len > 0).then(|| Event::Pong(self.ctl.payload())),
            Op::Close => self.peer_close(),
            Op::Continuation | Op::Text | Op::Binary => None,
        }
    }

    /// The peer's close: C's handling of `LWSWSOPC_CLOSE`.
    fn peer_close(&mut self) -> Option<Event<'_>> {
        match self.closing {
            // a second close changes nothing; nor is one answered while
            // the app's last goes
            Closing::Returned(_) | Closing::Flushing | Closing::Closed(_) => None,
            // the answer to ours: done
            Closing::AwaitingAck | Closing::WaitingToSend(_) => {
                self.closing = Closing::Closed(Close::Release);
                self.parse = Parse::Stopped;
                None
            }
            Closing::None => {
                if self.ctl.len >= 2 {
                    let code = u16::from_be_bytes([
                        self.ctl.buf.first().copied().unwrap_or(0),
                        self.ctl.buf.get(1).copied().unwrap_or(0),
                    ]);
                    // a code no peer may send is answered as a protocol error
                    if code < 1000
                        || matches!(code, 1004..=1006 | 1012..=1015)
                        || (1016..3000).contains(&code)
                    {
                        if let Some(b) = self.ctl.buf.get_mut(..2) {
                            b.copy_from_slice(&1002u16.to_be_bytes());
                        }
                    }
                }
                self.closing = Closing::Returned(self.ctl);
                // after the peer's close, nothing more is read
                self.parse = Parse::Stopped;
                Some(Event::PeerClose(self.ctl.payload()))
            }
        }
    }

    /// Commits a whole message, `len` bytes, whose payload [`Ws::tx`] pulls:
    /// C's `lws_write()` of a final frame.
    ///
    /// # Errors
    ///
    /// [`SendError::Busy`] while a frame is still going, or the connection
    /// is closing.
    pub fn send(&mut self, kind: Kind, len: u64) -> Result<(), SendError> {
        if self.app != App::Idle || self.out.pending() || !matches!(self.closing, Closing::None) {
            return Err(SendError::Busy);
        }
        let op = match kind {
            Kind::Text => Op::Text,
            Kind::Binary => Op::Binary,
        };
        frame_header(op, len, &mut self.out);
        self.app = App::Sending { owed: len };
        Ok(())
    }

    /// The application is done: the connection closes once what it sent
    /// has gone, without a close frame, as C's
    /// `lws_raw_transaction_completed()`.
    pub const fn close_when_flushed(&mut self) {
        if matches!(self.closing, Closing::None) {
            self.closing = Closing::Flushing;
        }
    }

    /// Writes what is owed the peer into `out`: see the module's
    /// description.
    pub fn tx(&mut self, out: &mut [u8], src: &mut dyn TxSource) -> usize {
        let mut written = 0usize;
        loop {
            let room = out.get_mut(written..).unwrap_or_default();
            if room.is_empty() {
                return written;
            }
            // what is in flight goes first
            if self.out.pending() {
                written = written.saturating_add(self.out.drain(room));
                continue;
            }
            if let App::Sending { owed } = self.app {
                let cap = usize::try_from(owed).unwrap_or(usize::MAX).min(room.len());
                let n = src.fill(room.get_mut(..cap).unwrap_or_default()).min(cap);
                written = written.saturating_add(n);
                let owed = owed.saturating_sub(u64::try_from(n).unwrap_or(owed));
                self.app = if owed == 0 {
                    App::Idle
                } else {
                    App::Sending { owed }
                };
                if owed > 0 {
                    // the rest of the payload is not here yet
                    return written;
                }
                continue;
            }
            match self.closing {
                Closing::WaitingToSend(c) => {
                    control_frame(Op::Close, &c, &mut self.out);
                    self.closing = Closing::AwaitingAck;
                    continue;
                }
                Closing::Flushing => {
                    self.closing = Closing::Closed(Close::Shutdown);
                    return written;
                }
                Closing::None
                | Closing::AwaitingAck
                | Closing::Returned(_)
                | Closing::Closed(_) => {}
            }
            // the pong goes while open, or ahead of the answer to the
            // peer's close, its ping having come first (RFC 6455 5.5.2); if
            // we began the close, it is forgotten
            if let Some(p) = self.pong.take() {
                match self.closing {
                    Closing::None | Closing::Returned(_) => {
                        control_frame(Op::Pong, &p, &mut self.out);
                    }
                    Closing::WaitingToSend(_)
                    | Closing::AwaitingAck
                    | Closing::Flushing
                    | Closing::Closed(_) => {}
                }
                continue;
            }
            if let Closing::Returned(c) = self.closing {
                control_frame(Op::Close, &c, &mut self.out);
                self.closing = Closing::Closed(Close::Shutdown);
                continue;
            }
            return written;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Nothing;
    impl TxSource for Nothing {
        fn fill(&mut self, _: &mut [u8]) -> usize {
            0
        }
    }

    /// What the server writes after taking `frames`.
    fn answers(frames: &[u8]) -> ([u8; 64], usize) {
        let mut ws = Ws::server(b"");
        let mut input = frames.to_vec();
        let mut at = 0;
        while at < input.len() {
            let rx = ws.rx(&mut input[at..]);
            if rx.consumed == 0 {
                break;
            }
            at = at.checked_add(rx.consumed).unwrap();
        }
        let mut out = [0u8; 64];
        let n = ws.tx(&mut out, &mut Nothing);
        (out, n)
    }

    #[test]
    fn refusals_close_with_cs_codes() {
        for (frames, close) in [
            (&b"\x83\x80\0\0\0\0"[..], &b"\x88\x09\x03\xeabad opc"[..]),
            (b"\x09\x80\0\0\0\0", b"\x88\x0a\x03\xeafrag ctl"),
            (b"\x80\x80\0\0\0\0", b"\x88\x0a\x03\xeabad cont"),
            (b"\xc1\x80\0\0\0\0", b"\x88\x0a\x03\xearsv bits"),
            (b"\x81\x00", b"\x88\x11\x03\xeaclient unmasked"),
            (b"\x89\xfe\0\x7e", b"\x88\x09\x03\xeactl len"),
            (b"\x82\xff\x80", b"\x88\x09\x03\xeabad len"),
            (b"\x81\x81\0\0\0\0\xff", b"\x88\x0a\x03\xefbad utf8"),
            (b"\x81\x81\0\0\0\0\xc3", b"\x88\x0e\x03\xefpartial utf8"),
        ] {
            let (out, n) = answers(frames);
            assert_eq!(&out[..n], close, "{}", frames.escape_ascii());
        }
    }

    #[test]
    fn a_reserved_close_code_is_answered_as_1002() {
        let (out, n) = answers(b"\x88\x82\0\0\0\0\x03\xed");
        assert_eq!(&out[..n], b"\x88\x02\x03\xea");
    }

    #[test]
    fn a_message_in_pieces_says_its_first_and_last() {
        let mut ws = Ws::server(b"");
        let mut a = *b"\x01\x81\0\0\0\0a";
        assert_eq!(
            ws.rx(&mut a).event,
            Some(Event::Message {
                kind: Kind::Text,
                data: b"a",
                first: true,
                last: false
            })
        );
        let mut b = *b"\x80\x81\0\0\0\0b";
        assert_eq!(
            ws.rx(&mut b).event,
            Some(Event::Message {
                kind: Kind::Text,
                data: b"b",
                first: false,
                last: true
            })
        );
    }

    #[test]
    fn a_pong_owed_is_forgotten_once_we_close() {
        // a ping, then a reserved opcode we refuse
        let (out, n) = answers(b"\x89\x81\0\0\0\0a\x83\x80\0\0\0\0");
        assert_eq!(&out[..n], b"\x88\x09\x03\xeabad opc");
    }

    #[test]
    fn a_header_takes_the_shortest_length_form() {
        for (len, want) in [
            (125, &b"\x82\x7d"[..]),
            (126, b"\x82\x7e\x00\x7e"),
            (0xffff, b"\x82\x7e\xff\xff"),
            (0x1_0000, b"\x82\x7f\0\0\0\0\0\x01\0\0"),
        ] {
            let mut out = Out::new();
            frame_header(Op::Binary, len, &mut out);
            assert_eq!(&out.buf[..out.len], want, "{len}");
        }
    }

    #[test]
    fn a_second_ping_while_a_pong_is_owed_is_dropped() {
        let (out, n) = answers(b"\x89\x81\0\0\0\0a\x89\x81\0\0\0\0b");
        assert_eq!(&out[..n], b"\x8a\x01a");
    }
}
