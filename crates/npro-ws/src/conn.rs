//! A ws connection: C's `lws_ws_rx_sm()` and `lws_ws_client_rx_sm()`, its
//! writeable handling and its close, sans-IO.  One parser serves both ends,
//! where C has two: a [`Ws`] is a server's ([`Ws::server`]) or a client's
//! ([`Ws::client`]), which masks each frame it writes with four bytes drawn
//! from its random source when the frame is begun, as C's `lws_write()`
//! draws them.
//!
//! [`Ws::rx`] takes the peer's bytes, at most one thing each call, and
//! unmasks a frame's payload where it lies in the input, so a message's
//! data is handed to the application without a copy: [`Event::Message`],
//! a piece of a message as it arrives, with whether it starts and ends it,
//! as C's `lws_is_first_fragment()` and `lws_is_final_fragment()` say.
//! Control frames, at most 125 bytes, are gathered here: a ping is answered
//! with a pong, a pong is given to the application, and the peer's close
//! is given to it and answered with the peer's own payload, its code made
//! 1002 if it is one the peer may not send (a client, as C's, takes 1012 to
//! 1015 from a server).
//!
//! What C refuses, this refuses, with C's close code and reason, each end
//! in its C parser's order: a fragmented control frame ("frag ctl"), a
//! reserved opcode ("bad opc"), a continuation out of place ("bad cont"),
//! RSV bits ("rsv bits"), a client's message begun while one is open ("bad
//! fin", which a server calls "bad cont"), a frame masked or not as the
//! side forbids ("client unmasked", "srv mask"), a long control frame ("ctl
//! len"), a length with its top bit ("bad len"), all 1002; a frame longer
//! than C's 256MiB, 1009 "huge frame"; text that is not UTF-8, 1007 "bad
//! utf8" or "partial utf8".  As C, the rest of that read is dropped; what
//! comes after it is dropped until our close has gone, and then ends the
//! connection, the peer's ack or not.  After the peer's close, nothing more
//! is read.
//!
//! [`Ws::tx`] writes in C's order: what is in flight first (the 101, a frame
//! begun), then our own close, then the pong, then the answer to the peer's
//! close, then the application's next frame, whose payload it pulls.  A
//! pong still owed when we begin a close is forgotten, as C forgets it.
//!
//! With the `pmd` feature and `Ws::with_pmd`, messages are deflated as
//! `crate::pmd` describes: a little input may then inflate to more than one
//! call of [`Ws::rx`] gives, and [`Ws::rx_pending`] says when to call it
//! again with no more.

use npro_core::random::{Random, Unavailable};
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
    /// A client: the server's frames must not be masked, ours are.
    Client,
}

/// The sealed trait pattern: public, so it can bound [`Role`], and
/// unnameable outside, so nothing else implements it.
mod sealed {
    pub trait Sealed {}
}

/// Which end a [`Ws`] is, and for a client, where its masks come from.
/// Sealed: [`AsServer`] and [`AsClient`] are the two there are.
pub trait Role: sealed::Sealed {
    /// Which end this is.
    fn side(&self) -> Side;

    /// The mask for the next frame written: `None` for a server; for a
    /// client, a draw of four bytes, as C's `lws_write()` draws one per
    /// frame.
    ///
    /// # Errors
    ///
    /// [`Unavailable`] if the random source has none to give.
    fn next_mask(&mut self) -> Result<Option<[u8; 4]>, Unavailable>;
}

/// A server's end: [`Ws::server`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsServer;

impl sealed::Sealed for AsServer {}

impl Role for AsServer {
    fn side(&self) -> Side {
        Side::Server
    }

    fn next_mask(&mut self) -> Result<Option<[u8; 4]>, Unavailable> {
        Ok(None)
    }
}

/// A client's end, masking with what `R` draws: [`Ws::client`].
#[derive(Clone, Debug)]
pub struct AsClient<R> {
    random: R,
}

impl<R> sealed::Sealed for AsClient<R> {}

impl<R: Random> Role for AsClient<R> {
    fn side(&self) -> Side {
        Side::Client
    }

    fn next_mask(&mut self) -> Result<Option<[u8; 4]>, Unavailable> {
        let mut mask = [0u8; 4];
        self.random.fill(&mut mask)?;
        Ok(Some(mask))
    }
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
    /// Release it now: the close handshake is over, or, for a client
    /// whose random source failed it, the connection cannot go on.
    Release,
}

/// Why a frame cannot be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// A frame is still going, or the connection is closing.
    Busy,
    /// A client's random source had no mask to give: the connection is
    /// failed, as C fails a short `lws_get_random()`.
    NoMask,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Busy => "a frame is still going, or the connection is closing",
            Self::NoMask => "no random for the frame's mask",
        })
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
    const fn of(kind: Kind) -> Self {
        match kind {
            Kind::Text => Self::Text,
            Kind::Binary => Self::Binary,
        }
    }

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
    /// We refused the peer's frames.  What it sends is not read: until our
    /// close has gone, it is dropped; after, anything ends the connection,
    /// as in C, where the rest of the read is dropped and whatever comes
    /// next, the ack or a frame refused again, closes it.
    Refused,
}

/// Where a message is, between frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Msg {
    /// Between messages.
    Idle,
    /// A message is under way, and its first piece has been given or not.
    Open {
        kind: Kind,
        given: Given,
        coding: Coding,
    },
}

/// How a message's payload is coded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Coding {
    /// As it is.
    Plain,
    /// Deflated: its first frame had RSV1, with permessage-deflate.
    #[cfg(feature = "pmd")]
    Deflated,
}

/// The extension in use, if any.
#[derive(Clone, Debug)]
enum Ext {
    None,
    /// permessage-deflate.
    #[cfg(feature = "pmd")]
    Pmd(alloc::boxed::Box<crate::pmd::Codec>),
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

    /// Adds `b` after what is there.
    fn push(&mut self, b: &[u8]) {
        let end = self.len.saturating_add(b.len());
        if let Some(d) = self.buf.get_mut(self.len..end) {
            d.copy_from_slice(b);
            self.len = end;
        }
    }

    /// Masks the last `n` bytes, a payload, with `mask`.
    fn mask_tail(&mut self, n: usize, mask: [u8; 4]) {
        if let Some(t) = self.buf.get_mut(self.len.saturating_sub(n)..self.len) {
            apply_mask(t, mask, 0);
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

/// The application's frame, its header written or not, its payload owed,
/// and a client's mask with how far into the payload it has come.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum App {
    Idle,
    Sending {
        owed: u64,
        mask: Option<[u8; 4]>,
        at: u64,
    },
    /// A message being deflated into frames, `owed` of it still to be
    /// pulled, and a frame going, its payload `sent` so far.
    #[cfg(feature = "pmd")]
    Deflating {
        kind: Kind,
        owed: u64,
        frame: Option<Going>,
    },
}

/// What a step of a deflated message's payload came to.
#[cfg(feature = "pmd")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Deflated {
    /// The frame is done with and gave nothing: parsing goes on, from
    /// here.
    Again(usize),
    /// Nothing to give, having taken this much.
    Nothing(usize),
    /// A piece of the message.
    Piece(Inflating),
    /// Text that is not UTF-8, with C's reason.
    Refused(&'static [u8]),
    /// It does not inflate, or is a zip bomb: the connection is dropped.
    Dropped,
}

/// A piece of a deflated message, in the codec's output.
#[cfg(feature = "pmd")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Inflating {
    consumed: usize,
    kind: Kind,
    produced: usize,
    first: bool,
    last: bool,
}

/// A deflated frame's payload going out.
#[cfg(feature = "pmd")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Going {
    sent: usize,
    mask: Option<[u8; 4]>,
    fin: bool,
}

/// Masks `b`, the bytes of a payload from `at` on, with `mask`.
pub(crate) fn apply_mask(b: &mut [u8], mask: [u8; 4], at: u64) {
    // the mask's index where `b` starts: `at` mod 4
    let start = at.to_le_bytes().first().map_or(0, |l| usize::from(l & 3));
    for (x, m) in b.iter_mut().zip(mask.iter().cycle().skip(start)) {
        *x ^= m;
    }
}

/// A frame's header, its first byte `first` (FIN, RSV and opcode), with a
/// client's mask after it.
fn frame_header(first: u8, len: u64, mask: Option<[u8; 4]>, out: &mut Out) {
    // the length is 7 bits, or 126 and 16 bits, or 127 and 64 bits: the
    // last of its big endian bytes, after the marker
    let be = len.to_be_bytes();
    let (marker, extra) = match u8::try_from(len) {
        Ok(short @ 0..126) => (short, 0),
        Ok(_) | Err(_) if u16::try_from(len).is_ok() => (126, 2),
        Ok(_) | Err(_) => (127, 8),
    };
    let masked = if mask.is_some() { 0x80 } else { 0 };
    let mut header = [0u8; 14];
    if let Some(h) = header.get_mut(..2) {
        h.copy_from_slice(&[first, masked | marker]);
    }
    let mut used = 2usize.saturating_add(extra);
    if let (Some(d), Some(s)) = (
        header.get_mut(2..used),
        be.get(be.len().saturating_sub(extra)..),
    ) {
        d.copy_from_slice(s);
    }
    if let Some(m) = mask {
        let end = used.saturating_add(4);
        if let Some(d) = header.get_mut(used..end) {
            d.copy_from_slice(&m);
        }
        used = end;
    }
    out.set(header.get(..used).unwrap_or_default());
}

/// A control frame, header and payload, masked with a client's mask.
fn control_frame(op: Op, c: &Ctl, mask: Option<[u8; 4]>, out: &mut Out) {
    frame_header(0x80 | op.code(), u64::from(c.len), mask, out);
    out.push(c.payload());
    if let Some(m) = mask {
        out.mask_tail(c.payload().len(), m);
    }
}

/// One ws connection, its end `P`: [`AsServer`], or [`AsClient`] with its
/// random source.
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
pub struct Ws<P = AsServer> {
    role: P,
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
    ext: Ext,
}

impl Ws<AsServer> {
    /// A server's connection, `first` being what goes before its frames:
    /// the 101.
    #[must_use]
    pub fn server(first: &[u8]) -> Self {
        Self::new(AsServer, first)
    }
}

impl<R: Random> Ws<AsClient<R>> {
    /// A client's connection, once the server's 101 has been checked
    /// ([`crate::handshake::ClientKey::check`]), masking its frames with
    /// what `random` draws.
    ///
    /// A real connection's source must be one the server cannot predict:
    /// see [`npro_core::random::Random`].
    #[must_use]
    pub fn client(random: R) -> Self {
        Self::new(AsClient { random }, b"")
    }
}

impl<P: Role> Ws<P> {
    fn new(role: P, first: &[u8]) -> Self {
        let mut out = Out::new();
        out.set(first);
        Self {
            role,
            parse: Parse::First,
            msg: Msg::Idle,
            utf8: Utf8Validator::new(),
            ctl: Ctl::new(),
            pong: None,
            closing: Closing::None,
            out,
            app: App::Idle,
            ext: Ext::None,
        }
    }

    /// The connection with permessage-deflate, as negotiated
    /// ([`crate::pmd`]): a message whose first frame has RSV1 is inflated,
    /// and what the application sends is deflated.
    #[cfg(feature = "pmd")]
    #[must_use]
    pub fn with_pmd(mut self, params: crate::pmd::Params) -> Self {
        let codec = crate::pmd::Codec::new(self.role.side(), params);
        self.ext = Ext::Pmd(alloc::boxed::Box::new(codec));
        self
    }

    /// Whether RSV1 may mark a data message's first frame: with
    /// permessage-deflate, as C's `lws_ws_rsv_valid()` has it.
    const fn rsv1_marks_deflate(&self) -> bool {
        match self.ext {
            Ext::None => false,
            #[cfg(feature = "pmd")]
            Ext::Pmd(_) => true,
        }
    }

    /// Which end this is.
    #[must_use]
    pub fn side(&self) -> Side {
        self.role.side()
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

    /// Whether [`Ws::rx`] has more to give without more input: with
    /// permessage-deflate, a little input may inflate to more than one
    /// call gives, as C's `rx_draining_ext`.  While it is true, call
    /// [`Ws::rx`] again, with no input if there is none.  Without
    /// permessage-deflate, never.
    #[must_use]
    #[cfg_attr(
        not(feature = "pmd"),
        expect(
            clippy::missing_const_for_fn,
            reason = "with pmd it asks the codec, which is not const at the MSRV; the API is one"
        )
    )]
    pub fn rx_pending(&self) -> bool {
        #[cfg(feature = "pmd")]
        if let (
            Ext::Pmd(codec),
            Parse::Payload(f, left),
            Msg::Open {
                coding: Coding::Deflated,
                ..
            },
        ) = (&self.ext, self.parse, self.msg)
        {
            return !f.op.control() && (left == 0 || codec.owes());
        }
        false
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
    /// `LWS_HPI_RET_PLEASE_CLOSE_ME`.  The caller takes all of its input,
    /// the rest of the read, which C drops.
    fn refuse<'a>(&mut self, code: u16, reason: &[u8]) -> Rx<'a> {
        self.parse = Parse::Refused;
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
                Parse::Refused => {
                    if !input.is_empty() && matches!(self.closing, Closing::AwaitingAck) {
                        self.closing = Closing::Closed(Close::Release);
                    }
                    return Rx {
                        consumed: input.len(),
                        event: None,
                    };
                }
                Parse::Payload(f, left) => {
                    #[cfg(feature = "pmd")]
                    if !f.op.control()
                        && matches!(
                            self.msg,
                            Msg::Open {
                                coding: Coding::Deflated,
                                ..
                            }
                        )
                    {
                        match self.deflated(f, left, input, used) {
                            // the frame is done with, and gave nothing:
                            // on to the next
                            Deflated::Again(consumed) => {
                                used = consumed;
                                continue;
                            }
                            Deflated::Nothing(consumed) => {
                                return Rx {
                                    consumed,
                                    event: None,
                                };
                            }
                            Deflated::Refused(reason) => {
                                let mut r = self.refuse(1007, reason);
                                r.consumed = input.len();
                                return r;
                            }
                            Deflated::Dropped => {
                                return Rx {
                                    consumed: input.len(),
                                    event: None,
                                };
                            }
                            Deflated::Piece(p) => return self.deflated_piece(p),
                        }
                    }
                    return self.payload(f, left, input, used);
                }
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
                // as C, the rest of what was read goes unread
                let mut r = self.refuse(code, reason);
                r.consumed = input.len();
                return r;
            }
        }
    }

    /// A frame's first byte: FIN, RSV and the opcode.  `Some` refuses
    /// the frame.
    fn first_byte(&mut self, c: u8) -> Option<(u16, &'static [u8])> {
        let fin = c & 0x80 != 0;
        let side = self.role.side();
        let op = match c & 0x0f {
            0 => Op::Continuation,
            1 => Op::Text,
            2 => Op::Binary,
            8 => Op::Close,
            9 => Op::Ping,
            10 => Op::Pong,
            // C's server calls a reserved control opcode without
            // FIN fragmented; its client, a bad opcode
            _ if side == Side::Server && c & 0x08 != 0 && !fin => {
                return Some((1002, b"frag ctl"));
            }
            _ => return Some((1002, b"bad opc")),
        };
        // RSV1 alone, on a data message's first frame, says it is
        // deflated, if that was agreed
        let deflated =
            self.rsv1_marks_deflate() && c & 0x70 == 0x40 && matches!(op, Op::Text | Op::Binary);
        let rsv = c & 0x70 != 0 && !deflated;
        if let Some(refused) = Self::first_byte_order(side, op, fin, rsv, self.msg) {
            return Some(refused);
        }
        let coding = Self::coding(deflated);
        match (op, self.msg) {
            (Op::Text, Msg::Idle) => {
                self.utf8 = Utf8Validator::new();
                self.msg = Msg::Open {
                    kind: Kind::Text,
                    given: Given::Nothing,
                    coding,
                };
            }
            (Op::Binary, Msg::Idle) => {
                self.msg = Msg::Open {
                    kind: Kind::Binary,
                    given: Given::Nothing,
                    coding,
                };
            }
            // refused above, or nothing to do
            (Op::Text | Op::Binary, Msg::Open { .. })
            | (Op::Continuation, Msg::Idle | Msg::Open { .. })
            | (Op::Close | Op::Ping | Op::Pong, Msg::Idle | Msg::Open { .. }) => {}
        }
        self.parse = Parse::Len(Frame {
            op,
            fin,
            masked: false,
            len: 0,
            mask: [0; 4],
        });
        None
    }

    /// One byte of a frame's header; `Some` refuses the frame.
    fn header(&mut self, c: u8) -> Option<(u16, &'static [u8])> {
        match self.parse {
            Parse::First => {
                if let Some(refused) = self.first_byte(c) {
                    return Some(refused);
                }
            }
            Parse::Len(mut f) => {
                f.masked = c & 0x80 != 0;
                match (self.role.side(), f.masked) {
                    (Side::Server, false) => return Some((1002, b"client unmasked")),
                    (Side::Client, true) => return Some((1002, b"srv mask")),
                    (Side::Server, true) | (Side::Client, false) => {}
                }
                match c & 0x7f {
                    126 | 127 if f.op.control() => return Some((1002, b"ctl len")),
                    126 => self.parse = Parse::LenMore(f, 2),
                    127 => self.parse = Parse::LenMore(f, 8),
                    n => {
                        f.len = u64::from(n);
                        self.parse = Self::after_len(f);
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
                    self.parse = Self::after_len(f);
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
                    Parse::Payload(f, f.len)
                };
            }
            Parse::Payload(..) | Parse::Stopped | Parse::Refused => {}
        }
        if matches!(self.parse, Parse::Payload(..)) {
            self.ctl = Ctl::new();
        }
        None
    }

    /// How a message beginning is coded.
    #[cfg(feature = "pmd")]
    const fn coding(deflated: bool) -> Coding {
        if deflated {
            Coding::Deflated
        } else {
            Coding::Plain
        }
    }

    /// How a message beginning is coded: without permessage-deflate, as
    /// it is.
    #[cfg(not(feature = "pmd"))]
    const fn coding(_deflated: bool) -> Coding {
        Coding::Plain
    }

    /// After the length: the mask, if the frame has one, else the payload.
    const fn after_len(f: Frame) -> Parse {
        if f.masked {
            Parse::Mask(f, 4)
        } else {
            Parse::Payload(f, f.len)
        }
    }

    /// The first byte's checks after its opcode, each side's in its C
    /// parser's order: the server's (`lws_ws_rx_sm()`) fragmented control,
    /// continuation, then RSV; the client's (`lws_ws_client_rx_sm()`)
    /// continuation, RSV, a message begun while one is open ("bad fin"),
    /// then fragmented control.
    const fn first_byte_order(
        side: Side,
        op: Op,
        fin: bool,
        rsv: bool,
        msg: Msg,
    ) -> Option<(u16, &'static [u8])> {
        let frag_ctl = op.control() && !fin;
        let open = matches!(msg, Msg::Open { .. });
        let stray_cont = matches!(op, Op::Continuation) && !open;
        let new_in_open = matches!(op, Op::Text | Op::Binary) && open;
        match side {
            Side::Server => {
                if frag_ctl {
                    Some((1002, b"frag ctl"))
                } else if stray_cont || new_in_open {
                    Some((1002, b"bad cont"))
                } else if rsv {
                    Some((1002, b"rsv bits"))
                } else {
                    None
                }
            }
            Side::Client => {
                if stray_cont {
                    Some((1002, b"bad cont"))
                } else if rsv {
                    Some((1002, b"rsv bits"))
                } else if new_in_open {
                    Some((1002, b"bad fin"))
                } else if frag_ctl {
                    Some((1002, b"frag ctl"))
                } else {
                    None
                }
            }
        }
    }

    /// The payload of `f`, `left` of it still to come.
    fn payload<'a>(&'a mut self, f: Frame, left: u64, input: &'a mut [u8], used: usize) -> Rx<'a> {
        let all = input.len();
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
        let Msg::Open {
            kind,
            given,
            coding,
        } = self.msg
        else {
            return Rx {
                consumed,
                event: None,
            };
        };
        let last = f.fin && left == 0;
        if kind == Kind::Text {
            if self.utf8.feed(piece).is_err() {
                let mut r = self.refuse(1007, b"bad utf8");
                r.consumed = all;
                return r;
            }
            if last && !self.utf8.at_boundary() {
                let mut r = self.refuse(1007, b"partial utf8");
                r.consumed = all;
                return r;
            }
        }
        self.msg = if last {
            Msg::Idle
        } else {
            Msg::Open {
                kind,
                given: Given::Some,
                coding,
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

    /// The payload of `f`, `left` of it still to come, in a deflated
    /// message: what fits is unmasked into the codec's hold, and inflated
    /// from there, at most [`crate::pmd::RX_CHUNK`] bytes a call, so it is
    /// taken from `input` only as it is held, and given the application
    /// as it inflates.
    #[cfg(feature = "pmd")]
    fn deflated(&mut self, f: Frame, left: u64, input: &[u8], used: usize) -> Deflated {
        let Msg::Open {
            kind,
            given,
            coding,
        } = self.msg
        else {
            return Deflated::Nothing(used);
        };
        let Ext::Pmd(codec) = &mut self.ext else {
            return Deflated::Nothing(used);
        };
        let mut left = left;
        let mut consumed = used;
        let room = codec.room();
        if room > 0 && left > 0 {
            let rest = input.get(used..).unwrap_or_default();
            let n = usize::try_from(left)
                .unwrap_or(usize::MAX)
                .min(rest.len())
                .min(room);
            let at = f.len.saturating_sub(left);
            codec.hold(
                rest.get(..n).unwrap_or_default(),
                f.masked.then_some(f.mask),
                at,
            );
            left = left.saturating_sub(u64::try_from(n).unwrap_or(left));
            consumed = consumed.saturating_add(n);
        }
        let end = f.fin && left == 0;
        let Ok(inflated) = codec.inflate(end) else {
            // C marks the socket unusable: no close goes
            self.fail();
            return Deflated::Dropped;
        };
        let more = left > 0 || codec.owes() || (end && !inflated.done);
        let piece = codec.rx_out(inflated.produced);
        let bad_text: Option<&'static [u8]> = if kind != Kind::Text {
            None
        } else if self.utf8.feed(piece).is_err() {
            Some(b"bad utf8")
        } else if inflated.done && !self.utf8.at_boundary() {
            Some(b"partial utf8")
        } else {
            None
        };
        if let Some(reason) = bad_text {
            return Deflated::Refused(reason);
        }
        self.parse = if more {
            Parse::Payload(f, left)
        } else {
            Parse::First
        };
        if inflated.produced == 0 && !inflated.done {
            return if more {
                Deflated::Nothing(consumed)
            } else {
                Deflated::Again(consumed)
            };
        }
        self.msg = if inflated.done {
            Msg::Idle
        } else {
            Msg::Open {
                kind,
                given: Given::Some,
                coding,
            }
        };
        // nothing for the app once a close is under way
        if !matches!(self.closing, Closing::None) {
            return Deflated::Nothing(consumed);
        }
        Deflated::Piece(Inflating {
            consumed,
            kind,
            produced: inflated.produced,
            first: given == Given::Nothing,
            last: inflated.done,
        })
    }

    /// A piece of a deflated message, as the application is given it.
    #[cfg(feature = "pmd")]
    fn deflated_piece(&self, p: Inflating) -> Rx<'_> {
        let data = match &self.ext {
            Ext::Pmd(codec) => codec.rx_out(p.produced),
            Ext::None => &[],
        };
        Rx {
            consumed: p.consumed,
            event: Some(Event::Message {
                kind: p.kind,
                data,
                first: p.first,
                last: p.last,
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
                    // a code no peer may send is answered as a protocol
                    // error; C's client takes 1012 to 1015 from a server
                    let reserved = match self.role.side() {
                        Side::Server => matches!(code, 1004..=1006 | 1012..=1015),
                        Side::Client => matches!(code, 1004..=1006),
                    };
                    if code < 1000 || reserved || (1016..3000).contains(&code) {
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
    /// A client's frame is masked with a mask drawn now, as C draws it in
    /// `lws_write()`.  With permessage-deflate, the message is deflated as
    /// it is pulled, into frames of at most `pmd::TX_CHUNK` bytes,
    /// each masked with a mask drawn as it is begun.
    ///
    /// # Errors
    ///
    /// [`SendError::Busy`] while a frame is still going, or the connection
    /// is closing; [`SendError::NoMask`] if a client's random source has no
    /// mask to give, which fails the connection.
    pub fn send(&mut self, kind: Kind, len: u64) -> Result<(), SendError> {
        if self.app != App::Idle || self.out.pending() || !matches!(self.closing, Closing::None) {
            return Err(SendError::Busy);
        }
        #[cfg(feature = "pmd")]
        if let Ext::Pmd(codec) = &mut self.ext {
            codec.begin_message();
            self.app = App::Deflating {
                kind,
                owed: len,
                frame: None,
            };
            return Ok(());
        }
        let Ok(mask) = self.role.next_mask() else {
            self.fail();
            return Err(SendError::NoMask);
        };
        frame_header(0x80 | Op::of(kind).code(), len, mask, &mut self.out);
        self.app = App::Sending {
            owed: len,
            mask,
            at: 0,
        };
        Ok(())
    }

    /// The connection cannot go on: a client's random source failed it,
    /// or permessage-deflate did.  Nothing more is read or written, and it
    /// asks to be released.
    const fn fail(&mut self) {
        self.parse = Parse::Stopped;
        self.pong = None;
        self.app = App::Idle;
        self.closing = Closing::Closed(Close::Release);
    }

    /// A control frame into what is in flight, masked as this end masks;
    /// `false` if the mask could not be drawn, which fails the connection.
    fn queue_control(&mut self, op: Op, c: &Ctl) -> bool {
        let Ok(mask) = self.role.next_mask() else {
            self.fail();
            return false;
        };
        control_frame(op, c, mask, &mut self.out);
        true
    }

    /// The deflated message's next step: a frame's payload, or its
    /// header, put in flight.  How much went into `room`, or `None` if
    /// the application must give more first, or the connection failed.
    #[cfg(feature = "pmd")]
    fn tx_deflated(&mut self, room: &mut [u8], src: &mut dyn TxSource) -> Option<usize> {
        let App::Deflating {
            kind,
            mut owed,
            frame,
        } = self.app
        else {
            return Some(0);
        };
        let Ext::Pmd(codec) = &mut self.ext else {
            self.app = App::Idle;
            return Some(0);
        };
        if let Some(mut g) = frame {
            let payload = codec.tx_frame();
            let rest = payload.get(g.sent..).unwrap_or_default();
            let n = rest.len().min(room.len());
            if let (Some(d), Some(s)) = (room.get_mut(..n), rest.get(..n)) {
                d.copy_from_slice(s);
                if let Some(m) = g.mask {
                    apply_mask(d, m, u64::try_from(g.sent).unwrap_or(0));
                }
            }
            g.sent = g.sent.saturating_add(n);
            self.app = match (g.sent >= payload.len(), g.fin) {
                (true, true) => App::Idle,
                (true, false) => App::Deflating {
                    kind,
                    owed,
                    frame: None,
                },
                (false, _) => App::Deflating {
                    kind,
                    owed,
                    frame: Some(g),
                },
            };
            return Some(n);
        }
        let next = codec.next_frame(&mut owed, &mut |b| src.fill(b));
        let made = match next {
            Ok(Some(made)) => made,
            Ok(None) => {
                self.app = App::Deflating {
                    kind,
                    owed,
                    frame: None,
                };
                return None;
            }
            Err(_) => {
                self.fail();
                return None;
            }
        };
        let Ok(mask) = self.role.next_mask() else {
            self.fail();
            return None;
        };
        // FIN on the last; RSV1 and the opcode on the first, the rest
        // continuations
        let fin = if made.fin { 0x80 } else { 0 };
        let first = if made.first {
            0x40 | Op::of(kind).code()
        } else {
            Op::Continuation.code()
        };
        let len = u64::try_from(made.len).unwrap_or(u64::MAX);
        frame_header(fin | first, len, mask, &mut self.out);
        self.app = App::Deflating {
            kind,
            owed,
            frame: Some(Going {
                sent: 0,
                mask,
                fin: made.fin,
            }),
        };
        Some(0)
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
            #[cfg(feature = "pmd")]
            if matches!(self.app, App::Deflating { .. }) {
                match self.tx_deflated(room, src) {
                    Some(n) => {
                        written = written.saturating_add(n);
                        continue;
                    }
                    // the application has more to give first
                    None => return written,
                }
            }
            if let App::Sending { owed, mask, at } = self.app {
                let cap = usize::try_from(owed).unwrap_or(usize::MAX).min(room.len());
                let piece = room.get_mut(..cap).unwrap_or_default();
                let n = src.fill(piece).min(cap);
                if let (Some(m), Some(p)) = (mask, piece.get_mut(..n)) {
                    apply_mask(p, m, at);
                }
                written = written.saturating_add(n);
                let n = u64::try_from(n).unwrap_or(owed);
                let owed = owed.saturating_sub(n);
                self.app = if owed == 0 {
                    App::Idle
                } else {
                    App::Sending {
                        owed,
                        mask,
                        at: at.wrapping_add(n),
                    }
                };
                if owed > 0 {
                    // the rest of the payload is not here yet
                    return written;
                }
                continue;
            }
            match self.closing {
                Closing::WaitingToSend(c) => {
                    if !self.queue_control(Op::Close, &c) {
                        return written;
                    }
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
                        if !self.queue_control(Op::Pong, &p) {
                            return written;
                        }
                    }
                    Closing::WaitingToSend(_)
                    | Closing::AwaitingAck
                    | Closing::Flushing
                    | Closing::Closed(_) => {}
                }
                continue;
            }
            if let Closing::Returned(c) = self.closing {
                if !self.queue_control(Op::Close, &c) {
                    return written;
                }
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
            frame_header(0x82, len, None, &mut out);
            assert_eq!(&out.buf[..out.len], want, "{len}");
        }
    }

    /// Masks of zero, so a client's frames read plainly.
    #[derive(Debug)]
    struct Zeros;
    impl Random for Zeros {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), Unavailable> {
            buf.fill(0);
            Ok(())
        }
    }

    /// A source with nothing to give.
    #[derive(Debug)]
    struct Dry;
    impl Random for Dry {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Unavailable> {
            Err(Unavailable)
        }
    }

    /// What a client writes after taking `frames`.
    fn client_answers(frames: &[u8]) -> ([u8; 64], usize) {
        let mut ws = Ws::client(Zeros);
        let mut input = [0u8; 16];
        let input = &mut input[..frames.len()];
        input.copy_from_slice(frames);
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
    fn a_clients_refusals_are_cs_client_parsers() {
        for (frames, close) in [
            (&b"\x83\x00"[..], &b"\x88\x89\0\0\0\0\x03\xeabad opc"[..]),
            // the server calls this one "frag ctl"
            (b"\x0b\x00", b"\x88\x89\0\0\0\0\x03\xeabad opc"),
            (b"\x80\x00", b"\x88\x8a\0\0\0\0\x03\xeabad cont"),
            (b"\xc1\x00", b"\x88\x8a\0\0\0\0\x03\xearsv bits"),
            (b"\x01\x00\x81\x00", b"\x88\x89\0\0\0\0\x03\xeabad fin"),
            (b"\x09\x00", b"\x88\x8a\0\0\0\0\x03\xeafrag ctl"),
            (b"\x81\x80", b"\x88\x8a\0\0\0\0\x03\xeasrv mask"),
            (b"\x89\x7e", b"\x88\x89\0\0\0\0\x03\xeactl len"),
            (b"\x82\x7f\x80", b"\x88\x89\0\0\0\0\x03\xeabad len"),
        ] {
            let (out, n) = client_answers(frames);
            assert_eq!(&out[..n], close, "{}", frames.escape_ascii());
        }
    }

    #[test]
    fn a_client_takes_1012_to_1015_from_a_server() {
        let (client, n) = client_answers(b"\x88\x02\x03\xf4");
        assert_eq!(&client[..n], b"\x88\x82\0\0\0\0\x03\xf4");
        // a server makes it 1002
        let (server, m) = answers(b"\x88\x82\0\0\0\0\x03\xf4");
        assert_eq!(&server[..m], b"\x88\x02\x03\xea");
    }

    #[test]
    fn after_our_close_has_gone_anything_ends_it() {
        let mut ws = Ws::client(Zeros);
        let mut bad = *b"\xc1\x05Hello";
        assert_eq!(ws.rx(&mut bad).consumed, bad.len());
        // until our close has gone, what comes is dropped
        let mut more = *b"\x81\x00";
        assert_eq!(ws.rx(&mut more).consumed, 2);
        assert_eq!(ws.close(), None);
        let mut out = [0u8; 64];
        assert!(ws.tx(&mut out, &mut Nothing) > 0);
        assert_eq!(ws.close(), None);
        let mut ack = *b"\x88\x02\x03\xe8";
        assert_eq!(ws.rx(&mut ack).consumed, 4);
        assert_eq!(ws.close(), Some(Close::Release));
    }

    #[test]
    fn a_client_with_no_random_fails() {
        let mut ws = Ws::client(Dry);
        assert_eq!(ws.send(Kind::Text, 1), Err(SendError::NoMask));
        assert_eq!(ws.close(), Some(Close::Release));
        let mut out = [0u8; 8];
        assert_eq!(ws.tx(&mut out, &mut Nothing), 0);
    }

    #[test]
    fn a_second_ping_while_a_pong_is_owed_is_dropped() {
        let (out, n) = answers(b"\x89\x81\0\0\0\0a\x89\x81\0\0\0\0b");
        assert_eq!(&out[..n], b"\x8a\x01a");
    }
}
