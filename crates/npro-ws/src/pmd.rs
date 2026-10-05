//! permessage-deflate (RFC 7692): C's `extension-permessage-deflate.c`,
//! its negotiation in `lws_extension_server_handshake()` and
//! `lws_client_ws_upgrade()`, and the inflater and deflater, which are
//! `miniz_oxide`'s where C's are zlib's.
//!
//! **Negotiation.**  A server takes the first `permessage-deflate` offer
//! in the request's `Sec-WebSocket-Extensions` ([`server_accept`]), with
//! the parameters it understands, and says what it took in its 101
//! ([`ServerAccepted::header_lines`]).  A client offers [`OFFER`] and
//! takes the server's answer if its parameters are RFC 7692's, with C's
//! ranges ([`client_accept`]).  Either way the result is the connection's
//! [`Params`], given to [`crate::conn::Ws::with_pmd`].
//!
//! **Messages.**  A message whose first frame has RSV1 is compressed: its
//! payload is inflated as it comes, the four bytes `00 00 ff ff` its
//! sender removed put back at its end, and the application given what it
//! inflates to, at most [`RX_CHUNK`] bytes a call.  A message inflating
//! to more than [`Params::max_message`], C's 256MiB by default, is a zip
//! bomb.  Data after the peer's deflate stream ended in a message is
//! refused, as C refuses it.  Each of these, and data that does not
//! inflate, drops the connection without a close, as C marks the socket
//! unusable.  What the application sends is deflated into frames of at
//! most [`TX_CHUNK`] bytes, the first with RSV1, each sync flushed
//! message's trailing `00 00 ff ff` removed.  A side that agreed to no
//! context takeover starts its deflater afresh for each message; the
//! inflater starts afresh when the peer agreed to it, or its stream ended.

use alloc::boxed::Box;
use alloc::vec::Vec;

use miniz_oxide::deflate::core::{CompressionStrategy, CompressorOxide};
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::stream::InflateState;
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};
use npro_h1::table::HeaderTable;
use npro_h1::token::Token;

use crate::conn::Side;
use crate::handshake::ClientRefusal;

/// The extension's name.
pub const NAME: &[u8] = b"permessage-deflate";

/// What a client offers: the extension with no parameters, as C's
/// `api-test-sansio` offers it.
pub const OFFER: &[u8] = NAME;

/// The most a message may inflate to by default: C's 256MiB.
pub const MAX_MESSAGE: u64 = 0x1000_0000;

/// The most inflated data given the application in one call: C's
/// default `rx_buf_size`, its drain budget.
pub const RX_CHUNK: usize = 1024;

/// The most compressed payload in one frame written: C's default
/// `tx_buf_size`.
pub const TX_CHUNK: usize = 1024;

/// The most compressed input held between calls.
const HOLD: usize = 1024;

/// The longest `Sec-WebSocket-Extensions` C takes from a client.
const MAX_OFFER: usize = 255;

/// The trailer RFC 7692 7.2.1 has a sender remove, and its receiver put
/// back.
const TRAILER: [u8; 4] = [0, 0, 0xff, 0xff];

/// The compression level C uses, for both ends.
const LEVEL: u8 = 1;

/// Whether an end keeps its compression context between messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Takeover {
    /// It may refer back into earlier messages: the default.
    Kept,
    /// It agreed not to: `*_no_context_takeover`.
    NotKept,
}

/// An LZ77 window's size, as a power of two: 8 to 15, RFC 7692's range,
/// which C checks too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WindowBits(u8);

impl WindowBits {
    /// 32KiB, the default.
    pub const MAX: Self = Self(15);

    /// `bits`, if it is in RFC 7692's range.
    #[must_use]
    pub const fn new(bits: u8) -> Option<Self> {
        if 8 <= bits && bits <= 15 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// The power of two.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// What a connection's two ends agreed, made by [`server_accept`] or
/// [`client_accept`].  RFC 7692 names each parameter for the end it
/// constrains: `server_*` the server's deflater, and so the client's
/// inflater, and `client_*` the other way round.
///
/// npro's own deflater always has the whole 32KiB window: npro never
/// agrees to less, since `miniz_oxide`'s smaller windows still refer
/// further back than they say (zlib finds distances too far back with any
/// window under 14 bits).  The peer's window may be any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    server_takeover: Takeover,
    client_takeover: Takeover,
    server_window: WindowBits,
    client_window: WindowBits,
    max_message: u64,
}

impl Params {
    /// Whether the server keeps its context between messages.
    #[must_use]
    pub const fn server_takeover(&self) -> Takeover {
        self.server_takeover
    }

    /// Whether the client keeps its context between messages.
    #[must_use]
    pub const fn client_takeover(&self) -> Takeover {
        self.client_takeover
    }

    /// The server's deflate window.
    #[must_use]
    pub const fn server_window(&self) -> WindowBits {
        self.server_window
    }

    /// The client's deflate window.
    #[must_use]
    pub const fn client_window(&self) -> WindowBits {
        self.client_window
    }

    /// The most a message may inflate to; past it, the connection is
    /// dropped.
    #[must_use]
    pub const fn max_message(&self) -> u64 {
        self.max_message
    }

    /// The same, a message inflating to at most `max` bytes, where C's
    /// limit is [`MAX_MESSAGE`].
    #[must_use]
    pub const fn with_max_message(mut self, max: u64) -> Self {
        self.max_message = max;
        self
    }

    /// RFC 7692's defaults, and C's limit on a message.
    pub const DEFAULT: Self = Self {
        server_takeover: Takeover::Kept,
        client_takeover: Takeover::Kept,
        server_window: WindowBits::MAX,
        client_window: WindowBits::MAX,
        max_message: MAX_MESSAGE,
    };

    /// Whether `side`'s own deflater keeps its context.
    const fn own_takeover(&self, side: Side) -> Takeover {
        match side {
            Side::Server => self.server_takeover,
            Side::Client => self.client_takeover,
        }
    }

    /// The peer's takeover, which governs `side`'s inflater.
    const fn peer_takeover(&self, side: Side) -> Takeover {
        match side {
            Side::Server => self.client_takeover,
            Side::Client => self.server_takeover,
        }
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The parameters RFC 7692 defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Param {
    ServerNoContextTakeover,
    ClientNoContextTakeover,
    ServerMaxWindowBits,
    ClientMaxWindowBits,
}

impl Param {
    /// Its place in a list of what was seen.
    const fn index(self) -> usize {
        match self {
            Self::ServerNoContextTakeover => 0,
            Self::ClientNoContextTakeover => 1,
            Self::ServerMaxWindowBits => 2,
            Self::ClientMaxWindowBits => 3,
        }
    }

    const fn named(name: &[u8]) -> Option<Self> {
        match name {
            b"server_no_context_takeover" => Some(Self::ServerNoContextTakeover),
            b"client_no_context_takeover" => Some(Self::ClientNoContextTakeover),
            b"server_max_window_bits" => Some(Self::ServerMaxWindowBits),
            b"client_max_window_bits" => Some(Self::ClientMaxWindowBits),
            _ => None,
        }
    }
}

/// `b` without the spaces and tabs around it.
fn trim(b: &[u8]) -> &[u8] {
    let blank = |c: &u8| *c == b' ' || *c == b'\t';
    let start = b.iter().position(|c| !blank(c)).unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !blank(c))
        .map_or(start, |n| n.saturating_add(1));
    b.get(start..end).unwrap_or_default()
}

/// A parameter, `name` or `name=value`, the value perhaps quoted.
fn param(p: &[u8]) -> (&[u8], Option<&[u8]>) {
    let mut kv = p.splitn(2, |c| *c == b'=');
    let name = trim(kv.next().unwrap_or_default());
    let value = kv.next().map(|v| {
        let v = trim(v);
        v.strip_prefix(b"\"")
            .and_then(|v| v.strip_suffix(b"\""))
            .unwrap_or(v)
    });
    (name, value)
}

/// A window size's value, as C reads it: decimal, in range.
fn window_bits(v: &[u8]) -> Option<WindowBits> {
    if v.is_empty() || v.len() > 2 || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = v.iter().fold(0u8, |n, d| {
        n.wrapping_mul(10).wrapping_add(d.wrapping_sub(b'0'))
    });
    WindowBits::new(n)
}

/// What a server took of a client's offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerAccepted {
    params: Params,
    line: [u8; 160],
    len: usize,
}

impl ServerAccepted {
    /// The connection's parameters.
    #[must_use]
    pub const fn params(&self) -> Params {
        self.params
    }

    /// The header line saying what was taken, for the 101: C's, the
    /// parameters taken in the order the client gave them.
    #[must_use]
    pub fn header_lines(&self) -> &[u8] {
        self.line.get(..self.len).unwrap_or_default()
    }
}

/// Why a server will not answer an offer: C drops the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferRefused {
    /// The extensions offered are longer than C takes.
    TooLong,
}

impl core::fmt::Display for OfferRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("extension offer too long")
    }
}

impl core::error::Error for OfferRefused {}

/// A server's answer to a request's `Sec-WebSocket-Extensions`: the first
/// `permessage-deflate` offer, with C's limit on the list, and these of
/// its parameters, the rest left alone as C leaves them:
/// `server_no_context_takeover` and `client_no_context_takeover`, as C
/// takes them.  An offer asking for a server window under 32KiB, which
/// npro's deflater cannot keep to, is declined, and the next tried: RFC
/// 7692 7.1.2.1, where C takes it and leaves the parameter out.  `None` if
/// nothing was offered, or nothing it could take.
///
/// ```
/// use npro_h1::head::{Config, Head, Side};
/// use npro_ws::pmd::{server_accept, Takeover};
///
/// let mut h = Head::new([0u8; 1024], Side::Server, Config::new())?;
/// h.rx(b"GET / HTTP/1.1\r\nSec-WebSocket-Extensions: x-foo, \
///        permessage-deflate; client_max_window_bits; \
///        client_no_context_takeover\r\n\r\n")?;
/// let a = server_accept(h.table())?.unwrap();
/// assert_eq!(a.params().client_takeover(), Takeover::NotKept);
/// assert_eq!(
///     a.header_lines(),
///     b"sec-websocket-extensions: permessage-deflate; client_no_context_takeover\r\n"
/// );
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
///
/// # Errors
///
/// [`OfferRefused`]: C drops the connection.
pub fn server_accept<S: AsRef<[u8]> + AsMut<[u8]>>(
    t: &HeaderTable<S>,
) -> Result<Option<ServerAccepted>, OfferRefused> {
    let total = t.total_len(Token::WsExtensions);
    if total == 0 {
        return Ok(None);
    }
    let mut buf = [0u8; MAX_OFFER];
    let offer = t
        .copy(Token::WsExtensions, &mut buf)
        .ok()
        .and_then(|n| buf.get(..n))
        .ok_or(OfferRefused::TooLong)?;
    Ok(offer
        .split(|c| *c == b',')
        .filter(|e| trim(e.split(|c| *c == b';').next().unwrap_or_default()) == NAME)
        .find_map(take_offer))
}

/// What a server takes of one `permessage-deflate` offer, if it can take
/// it.
fn take_offer(entry: &[u8]) -> Option<ServerAccepted> {
    let mut a = ServerAccepted {
        params: Params::DEFAULT,
        line: [0; 160],
        len: 0,
    };
    let put = |acc: &mut ServerAccepted, b: &[u8]| {
        let end = acc.len.saturating_add(b.len());
        if let Some(d) = acc.line.get_mut(acc.len..end) {
            d.copy_from_slice(b);
            acc.len = end;
        }
    };
    put(&mut a, b"sec-websocket-extensions: ");
    put(&mut a, NAME);
    for p in entry.split(|c| *c == b';').skip(1) {
        let (name, value) = param(p);
        match (Param::named(name), value) {
            (Some(Param::ServerNoContextTakeover), None)
                if a.params.server_takeover == Takeover::Kept =>
            {
                a.params.server_takeover = Takeover::NotKept;
                put(&mut a, b"; server_no_context_takeover");
            }
            (Some(Param::ClientNoContextTakeover), None)
                if a.params.client_takeover == Takeover::Kept =>
            {
                a.params.client_takeover = Takeover::NotKept;
                put(&mut a, b"; client_no_context_takeover");
            }
            // a window it can keep to, which is only the whole one; a
            // smaller one, or one not in range, declines the offer, as
            // RFC 7692 7.1.2.1 has it, where C takes the offer and
            // leaves the parameter out
            (Some(Param::ServerMaxWindowBits), Some(v)) => {
                if window_bits(v) != Some(WindowBits::MAX) {
                    return None;
                }
                put(&mut a, b"; server_max_window_bits=15");
            }
            // what the server leaves alone: the client's window is its
            // own unless the server limits it, which it need not; and
            // what it does not know, or has already
            (Some(_) | None, _) => {}
        }
    }
    put(&mut a, b"\r\n");
    Some(a)
}

/// A client's reading of the server's `Sec-WebSocket-Extensions`, having
/// offered [`OFFER`]: `permessage-deflate` alone, with RFC 7692's
/// parameters, each at most once, `*_no_context_takeover` with no value
/// and `server_max_window_bits` with one in C's range.  A
/// `client_max_window_bits` of less than 15 is refused: npro did not offer
/// it, and its deflater cannot keep to it.
///
/// C also takes its own local options from a server, which no server has
/// reason to send; npro does not.
///
/// # Errors
///
/// [`ClientRefusal::Extension`]: C's "HS: EXT: unknown ext" and "HS: EXT:
/// failed parsing options".
pub fn client_accept(said: &[u8]) -> Result<Params, ClientRefusal> {
    let mut entries = said.split(|c| *c == b',');
    let entry = entries.next().unwrap_or_default();
    if entries.next().is_some() {
        return Err(ClientRefusal::Extension);
    }
    let mut parts = entry.split(|c| *c == b';');
    if trim(parts.next().unwrap_or_default()) != NAME {
        return Err(ClientRefusal::Extension);
    }
    let mut params = Params::DEFAULT;
    let mut seen = [false; 4];
    for p in parts {
        let (name, value) = param(p);
        let which = Param::named(name).ok_or(ClientRefusal::Extension)?;
        let slot = seen
            .get_mut(which.index())
            .ok_or(ClientRefusal::Extension)?;
        if core::mem::replace(slot, true) {
            return Err(ClientRefusal::Extension);
        }
        match (which, value) {
            (Param::ServerNoContextTakeover, None) => params.server_takeover = Takeover::NotKept,
            (Param::ClientNoContextTakeover, None) => params.client_takeover = Takeover::NotKept,
            (Param::ServerMaxWindowBits, Some(v)) => {
                params.server_window = window_bits(v).ok_or(ClientRefusal::Extension)?;
            }
            // npro offers no client_max_window_bits, so a server may not
            // limit the client's window (RFC 7692 7.1.2.2); and npro's
            // deflater can keep to no smaller one.  C takes it.
            (Param::ClientMaxWindowBits, Some(v)) => {
                if window_bits(v) != Some(WindowBits::MAX) {
                    return Err(ClientRefusal::Extension);
                }
            }
            (Param::ServerNoContextTakeover | Param::ClientNoContextTakeover, Some(_))
            | (Param::ServerMaxWindowBits | Param::ClientMaxWindowBits, None) => {
                return Err(ClientRefusal::Extension);
            }
        }
    }
    Ok(params)
}

/// Why permessage-deflate drops the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fail {
    /// The payload does not inflate.
    Data,
    /// A message inflated past its limit.
    ZipBomb,
    /// Data after the end of the peer's deflate stream.
    AfterEnd,
    /// The deflater failed, or could not end a flush as RFC 7692 has it.
    Deflate,
}

/// Where the inflater is within a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RxStream {
    /// Taking the message's payload.
    Running,
    /// Taking the trailer: this much of it has gone in.
    Trailer(u8),
    /// The peer ended its deflate stream: only padding may follow.
    Ended,
}

/// What a call to [`Codec::inflate`] came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Inflated {
    /// How much it put in [`Codec::rx_out`].
    pub(crate) produced: usize,
    /// Whether the message is over.
    pub(crate) done: bool,
}

/// What the deflater is doing for the application's message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxStream {
    /// No message.
    Idle,
    /// Taking it; frames written so far.
    Running { frames: u32 },
    /// Its flush is done: what is left is its last frame.
    Flushed { frames: u32 },
}

/// A frame of compressed payload ready to go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TxFrame {
    /// Its payload's length, in [`Codec::tx_frame`].
    pub(crate) len: usize,
    /// Whether it is the message's first, which carries RSV1 and the
    /// opcode.
    pub(crate) first: bool,
    /// Whether it ends the message.
    pub(crate) fin: bool,
}

/// One connection's permessage-deflate.
#[derive(Clone)]
pub(crate) struct Codec {
    side: Side,
    params: Params,
    inflater: Option<Box<InflateState>>,
    held: Vec<u8>,
    held_at: usize,
    rx_out: Vec<u8>,
    rx_total: u64,
    rx_stream: RxStream,
    /// The inflater may owe output without more input: the last inflate
    /// filled its output, or the inflater's window did, so input it took
    /// is not yet decoded.
    rx_owed: bool,
    /// Inflating failed after giving what it gave first: the next call
    /// says so.
    rx_failed: Option<Fail>,
    deflater: Option<Box<CompressorOxide>>,
    tx_in: Vec<u8>,
    tx_in_at: usize,
    /// Compressed bytes not yet in a frame: the last four are kept back
    /// until the message ends, so its trailer can be removed.
    tx_out: Vec<u8>,
    tx_frame: Vec<u8>,
    tx_stream: TxStream,
}

impl core::fmt::Debug for Codec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Codec")
            .field("side", &self.side)
            .field("params", &self.params)
            .field("rx_stream", &self.rx_stream)
            .field("tx_stream", &self.tx_stream)
            .finish_non_exhaustive()
    }
}

impl Codec {
    pub(crate) const fn new(side: Side, params: Params) -> Self {
        Self {
            side,
            params,
            inflater: None,
            held: Vec::new(),
            held_at: 0,
            rx_out: Vec::new(),
            rx_total: 0,
            rx_stream: RxStream::Running,
            rx_owed: false,
            rx_failed: None,
            deflater: None,
            tx_in: Vec::new(),
            tx_in_at: 0,
            tx_out: Vec::new(),
            tx_frame: Vec::new(),
            tx_stream: TxStream::Idle,
        }
    }

    /// Whether compressed input is held, not yet inflated.
    pub(crate) fn holding(&self) -> bool {
        self.held_at < self.held.len()
    }

    /// Whether inflating can go on without more input: input is held, or
    /// the inflater may owe output.
    pub(crate) fn owes(&self) -> bool {
        self.holding() || self.rx_owed || self.rx_failed.is_some()
    }

    /// How much more compressed input may be held now.
    pub(crate) fn room(&self) -> usize {
        if self.held_at < self.held.len() {
            0
        } else {
            HOLD
        }
    }

    /// Holds `piece`, compressed payload, unmasked with `mask` from `at`.
    pub(crate) fn hold(&mut self, piece: &[u8], mask: Option<[u8; 4]>, at: u64) {
        self.held.clear();
        self.held_at = 0;
        self.held.extend_from_slice(piece);
        if let Some(m) = mask {
            crate::conn::apply_mask(&mut self.held, m, at);
        }
    }

    /// What the last [`Codec::inflate`] produced.
    pub(crate) fn rx_out(&self, n: usize) -> &[u8] {
        self.rx_out.get(..n).unwrap_or_default()
    }

    /// Inflates what is held, and at the message's end, `end`, the
    /// trailer, into [`Codec::rx_out`].
    ///
    /// What inflated before a failure is given first, and the failure on
    /// the next call, so the application, and the check of text, see the
    /// stream up to where it went wrong however it was split.
    pub(crate) fn inflate(&mut self, end: bool) -> Result<Inflated, Fail> {
        if let Some(f) = self.rx_failed {
            return Err(f);
        }
        let first = self.inflate_once(end)?;
        // the payload is all in, and gave nothing more: on to the trailer
        if first.produced == 0 && !first.done && matches!(self.rx_stream, RxStream::Trailer(0)) {
            return self.inflate_once(end);
        }
        Ok(first)
    }

    fn inflate_once(&mut self, end: bool) -> Result<Inflated, Fail> {
        if self.rx_out.len() < RX_CHUNK {
            self.rx_out.resize(RX_CHUNK, 0);
        }
        let held = self.held.get(self.held_at..).unwrap_or_default();
        if self.rx_stream == RxStream::Ended {
            // only the padding of the stored block it flushed with
            if held.iter().any(|b| *b != 0) {
                return Err(Fail::AfterEnd);
            }
            self.held_at = self.held.len();
            return self.produced(0, end);
        }
        let (input, flush) = match self.rx_stream {
            RxStream::Trailer(fed) => (
                TRAILER.get(usize::from(fed)..).unwrap_or_default(),
                MZFlush::Sync,
            ),
            RxStream::Running | RxStream::Ended => (held, MZFlush::None),
        };
        let inflater = self
            .inflater
            .get_or_insert_with(|| InflateState::new_boxed(DataFormat::Raw));
        let r = miniz_oxide::inflate::stream::inflate(inflater, input, &mut self.rx_out, flush);
        let progress = r.bytes_consumed > 0 || r.bytes_written > 0;
        match r.status {
            Ok(MZStatus::StreamEnd) => {
                // what it did not take is our trailer, or must be padding
                let rest = input.get(r.bytes_consumed..).unwrap_or_default();
                if matches!(self.rx_stream, RxStream::Running) && rest.iter().any(|b| *b != 0) {
                    return self.failed_after(Fail::AfterEnd, r.bytes_written);
                }
                if matches!(self.rx_stream, RxStream::Running) {
                    self.held_at = self.held.len();
                }
                self.rx_stream = RxStream::Ended;
                return self.produced(r.bytes_written, end);
            }
            // it can go no further without more input, or more room:
            // stuck only if it took and gave nothing, below
            Ok(MZStatus::Ok) | Err(MZError::Buf) => {}
            Ok(MZStatus::NeedDict) | Err(_) => {
                return self.failed_after(Fail::Data, r.bytes_written);
            }
        }
        match self.rx_stream {
            RxStream::Running => {
                self.held_at = self.held_at.saturating_add(r.bytes_consumed);
            }
            RxStream::Trailer(fed) => {
                let fed = usize::from(fed).saturating_add(r.bytes_consumed);
                self.rx_stream = RxStream::Trailer(u8::try_from(fed).unwrap_or(u8::MAX));
            }
            RxStream::Ended => {}
        }
        if !progress && !input.is_empty() {
            // C's "inflate made no progress"
            return Err(Fail::Data);
        }
        if end && !self.holding() && self.rx_stream == RxStream::Running {
            self.rx_stream = RxStream::Trailer(0);
        }
        self.produced(r.bytes_written, end)
    }

    /// Counts what was produced against the message's limit, and ends
    /// the message once its input and trailer are in and nothing more is
    /// owed.
    fn produced(&mut self, produced: usize, end: bool) -> Result<Inflated, Fail> {
        let room = self.params.max_message.saturating_sub(self.rx_total);
        let n = u64::try_from(produced).unwrap_or(u64::MAX);
        if n > room {
            // up to the limit, then the bomb
            let upto = usize::try_from(room).unwrap_or(produced);
            self.rx_total = self.params.max_message;
            return self.failed_after(Fail::ZipBomb, upto);
        }
        self.rx_total = self.rx_total.saturating_add(n);
        let trailer_in = match self.rx_stream {
            RxStream::Trailer(fed) => usize::from(fed) >= TRAILER.len(),
            RxStream::Ended => true,
            RxStream::Running => false,
        };
        // the window filling stops it with input taken but not decoded,
        // and the call emptying the window decodes none of it: so a
        // short output does not show nothing is owed
        let window_full = self
            .inflater
            .as_ref()
            .is_some_and(|i| i.last_status() == TINFLStatus::HasMoreOutput);
        self.rx_owed = produced >= self.rx_out.len() || window_full;
        let done = end && !self.holding() && trailer_in && !self.rx_owed;
        if done {
            self.message_received();
        }
        Ok(Inflated { produced, done })
    }

    /// Inflating failed with `f`, having given `produced` first: that is
    /// given now, and `f` on the next call.
    const fn failed_after(&mut self, f: Fail, produced: usize) -> Result<Inflated, Fail> {
        if produced == 0 {
            return Err(f);
        }
        self.rx_failed = Some(f);
        Ok(Inflated {
            produced,
            done: false,
        })
    }

    /// The message is over: the inflater starts afresh if the peer agreed
    /// to no context takeover, or its stream ended.
    fn message_received(&mut self) {
        let fresh = self.rx_stream == RxStream::Ended
            || self.params.peer_takeover(self.side) == Takeover::NotKept;
        if fresh {
            if let Some(i) = self.inflater.as_mut() {
                i.reset(DataFormat::Raw);
            }
        }
        self.rx_total = 0;
        self.rx_stream = RxStream::Running;
        self.rx_owed = false;
    }

    /// Begins deflating a message.
    pub(crate) fn begin_message(&mut self) {
        self.tx_stream = TxStream::Running { frames: 0 };
        self.tx_in.clear();
        self.tx_in_at = 0;
        self.tx_out.clear();
    }

    /// The payload of the frame [`Codec::next_frame`] made.
    pub(crate) fn tx_frame(&self) -> &[u8] {
        &self.tx_frame
    }

    /// Takes what the application gives, `pull` filling a buffer and
    /// saying how much, `owed` being what it still owes, and makes the
    /// next frame if one is ready.  `None` if the application must give
    /// more first.
    pub(crate) fn next_frame(
        &mut self,
        owed: &mut u64,
        pull: &mut dyn FnMut(&mut [u8]) -> usize,
    ) -> Result<Option<TxFrame>, Fail> {
        loop {
            let frames = match self.tx_stream {
                TxStream::Idle => return Ok(None),
                TxStream::Flushed { frames } => {
                    let fin = self.tx_out.len() <= TX_CHUNK;
                    return Ok(Some(self.frame(TX_CHUNK, frames, fin)));
                }
                TxStream::Running { frames } => frames,
            };
            // a frame's worth, but for the four kept back
            let keep = TRAILER.len();
            if self.tx_out.len() >= TX_CHUNK.saturating_add(keep) {
                return Ok(Some(self.frame(TX_CHUNK, frames, false)));
            }
            if self.tx_in_at >= self.tx_in.len() && *owed > 0 {
                self.tx_in.resize(TX_CHUNK, 0);
                let want = usize::try_from(*owed).unwrap_or(usize::MAX).min(TX_CHUNK);
                let got = pull(self.tx_in.get_mut(..want).unwrap_or_default()).min(want);
                self.tx_in.truncate(got);
                self.tx_in_at = 0;
                *owed = owed.saturating_sub(u64::try_from(got).unwrap_or(*owed));
                if got == 0 {
                    return Ok(None);
                }
            }
            let last_input = *owed == 0;
            let flush = if last_input {
                MZFlush::Sync
            } else {
                MZFlush::None
            };
            let deflater = self.deflater.get_or_insert_with(|| {
                Box::new(CompressorOxide::with_params(
                    DataFormat::Raw,
                    LEVEL,
                    CompressionStrategy::Default,
                    WindowBits::MAX.get(),
                ))
            });
            let at = self.tx_out.len();
            self.tx_out.resize(at.saturating_add(TX_CHUNK), 0);
            let input = self.tx_in.get(self.tx_in_at..).unwrap_or_default();
            let out = self.tx_out.get_mut(at..).unwrap_or_default();
            let r = miniz_oxide::deflate::stream::deflate(deflater, input, out, flush);
            self.tx_out.truncate(at.saturating_add(r.bytes_written));
            self.tx_in_at = self.tx_in_at.saturating_add(r.bytes_consumed);
            let flushed = match r.status {
                Ok(MZStatus::Ok | MZStatus::StreamEnd) => {
                    last_input && self.tx_in_at >= self.tx_in.len() && r.bytes_written < TX_CHUNK
                }
                // nothing new since the last flush: the stream is byte
                // aligned, and the empty stored block is all there is
                Err(MZError::Buf) if last_input && r.bytes_written == 0 => true,
                Ok(MZStatus::NeedDict) | Err(_) => return Err(Fail::Deflate),
            };
            if flushed {
                self.end_flush()?;
                self.tx_stream = TxStream::Flushed { frames };
            }
        }
    }

    /// Removes the trailer of the message's flush, as RFC 7692 7.2.1 has
    /// it; an empty message after a flush is the empty stored block's
    /// first octet, as C sends it.
    fn end_flush(&mut self) -> Result<(), Fail> {
        if self.tx_out.is_empty() {
            self.tx_out.push(0);
            return Ok(());
        }
        let n = self.tx_out.len();
        if n < TRAILER.len() || self.tx_out.get(n.saturating_sub(4)..) != Some(&TRAILER[..]) {
            return Err(Fail::Deflate);
        }
        self.tx_out.truncate(n.saturating_sub(4));
        if self.tx_out.is_empty() {
            self.tx_out.push(0);
        }
        Ok(())
    }

    /// Moves `n` compressed bytes into the frame.
    fn frame(&mut self, n: usize, frames: u32, fin: bool) -> TxFrame {
        let n = n.min(self.tx_out.len());
        self.tx_frame.clear();
        self.tx_frame.extend(self.tx_out.drain(..n));
        let frames_now = frames.saturating_add(1);
        self.tx_stream = match (fin, self.tx_stream) {
            (true, _) => {
                self.message_sent();
                TxStream::Idle
            }
            (false, TxStream::Flushed { .. }) => TxStream::Flushed { frames: frames_now },
            (false, TxStream::Idle | TxStream::Running { .. }) => {
                TxStream::Running { frames: frames_now }
            }
        };
        TxFrame {
            len: n,
            first: frames == 0,
            fin,
        }
    }

    /// The message has gone: the deflater starts afresh if this end agreed
    /// to no context takeover.
    fn message_sent(&mut self) {
        if self.params.own_takeover(self.side) == Takeover::NotKept {
            if let Some(d) = self.deflater.as_mut() {
                d.reset();
            }
        }
        self.tx_in.clear();
        self.tx_in_at = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{AsClient, Close, Event, Kind, Role, Ws};
    use alloc::vec;
    use npro_core::random::SeededRandom;
    use npro_h1::server::TxSource;

    /// A message's payload, given a piece at a time.
    struct Src<'a> {
        data: &'a [u8],
        at: usize,
    }

    impl TxSource for Src<'_> {
        fn fill(&mut self, buf: &mut [u8]) -> usize {
            let rest = self.data.get(self.at..).unwrap_or_default();
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.at = self.at.checked_add(n).unwrap();
            n
        }
    }

    /// What `ws` makes of `frames` handed in pieces of `piece`: the whole
    /// messages, and how it closed.
    fn reads<P: Role>(
        ws: &mut Ws<P>,
        frames: &[u8],
        piece: usize,
    ) -> (Vec<(Kind, Vec<u8>)>, Option<Close>) {
        let mut got = Vec::new();
        let mut open: Option<(Kind, Vec<u8>)> = None;
        let mut buf = frames.to_vec();
        for chunk in buf.chunks_mut(piece.max(1)) {
            let len = chunk.len();
            let mut at = 0;
            loop {
                let rx = ws.rx(&mut chunk[at..]);
                let consumed = rx.consumed;
                let given = match rx.event {
                    Some(Event::Message {
                        kind,
                        data,
                        first,
                        last,
                    }) => Some((kind, data.to_vec(), first, last)),
                    Some(Event::Pong(_) | Event::PeerClose(_)) | None => None,
                };
                at = at.checked_add(consumed).unwrap();
                let Some((kind, data, first, last)) = given else {
                    // what it took to its end, and drained
                    if (at == len && !ws.rx_pending()) || (consumed == 0 && at < len) {
                        break;
                    }
                    continue;
                };
                let m = open.get_or_insert_with(|| (kind, Vec::new()));
                assert_eq!(first, m.1.is_empty() && first, "first");
                m.1.extend_from_slice(&data);
                if last {
                    got.push(open.take().unwrap());
                }
            }
        }
        (got, ws.close())
    }

    /// The frames `ws` writes for `msgs`, `limit` bytes at a time.
    fn writes<P: Role>(ws: &mut Ws<P>, msgs: &[(Kind, &[u8])], limit: usize) -> Vec<u8> {
        let mut wrote = Vec::new();
        let mut buf = vec![0u8; limit];
        for (kind, data) in msgs {
            ws.send(*kind, u64::try_from(data.len()).unwrap()).unwrap();
            let mut src = Src { data, at: 0 };
            loop {
                let n = ws.tx(&mut buf, &mut src);
                if n == 0 {
                    break;
                }
                wrote.extend_from_slice(&buf[..n]);
            }
            assert_eq!(src.at, data.len(), "all of it pulled");
        }
        wrote
    }

    fn client(params: Params) -> Ws<AsClient<SeededRandom>> {
        Ws::client(SeededRandom::new(7)).with_pmd(params)
    }

    #[test]
    fn rfc_7692s_examples_inflate() {
        for (frames, want) in [
            // 7.2.3.1: a message in one frame
            (
                &b"\xc1\x07\xf2\x48\xcd\xc9\xc9\x07\x00"[..],
                &[&b"Hello"[..]][..],
            ),
            // 7.2.3.1: the same, in two frames
            (b"\x41\x03\xf2\x48\xcd\x80\x04\xc9\xc9\x07\x00", &[b"Hello"]),
            // 7.2.3.2: a second message sharing the first's context
            (
                b"\xc1\x07\xf2\x48\xcd\xc9\xc9\x07\x00\xc1\x05\xf2\x00\x11\x00\x00",
                &[b"Hello", b"Hello"],
            ),
            // 7.2.3.3: a stored block
            (
                b"\xc1\x0b\x00\x05\x00\xfa\xff\x48\x65\x6c\x6c\x6f\x00",
                &[b"Hello"],
            ),
            // 7.2.3.4: BFINAL, then the padding of the flush
            (b"\xc1\x08\xf3\x48\xcd\xc9\xc9\x07\x00\x00", &[b"Hello"]),
            // 7.2.3.5: two blocks in one message
            (
                b"\xc1\x0d\xf2\x48\x05\x00\x00\x00\xff\xff\xca\xc9\xc9\x07\x00",
                &[b"Hello"],
            ),
        ] {
            for piece in [1, 3, 64] {
                let (got, close) = reads(&mut client(Params::DEFAULT), frames, piece);
                let got: Vec<&[u8]> = got.iter().map(|(_, m)| m.as_slice()).collect();
                assert_eq!(got, want, "{} in {piece}s", frames.escape_ascii());
                assert_eq!(close, None);
            }
        }
    }

    #[test]
    fn data_after_bfinal_drops_the_connection() {
        let (got, close) = reads(
            &mut client(Params::DEFAULT),
            b"\xc1\x09\xf3\x48\xcd\xc9\xc9\x07\x00\x00\x01",
            64,
        );
        assert_eq!(got, Vec::new());
        assert_eq!(close, Some(Close::Release));
    }

    #[test]
    fn what_does_not_inflate_drops_the_connection() {
        // a block of the reserved type 3
        let (got, close) = reads(&mut client(Params::DEFAULT), b"\xc1\x02\x07\x00", 64);
        assert_eq!(got, Vec::new());
        assert_eq!(close, Some(Close::Release));
    }

    /// Bytes from a fixed stream, which do not compress.
    fn noise(n: usize) -> Vec<u8> {
        let mut r = SeededRandom::new(3);
        (0..n).map(|_| r.next_u64().to_le_bytes()[0]).collect()
    }

    /// Text that compresses well.
    fn words(n: usize) -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog "
            .iter()
            .copied()
            .cycle()
            .take(n)
            .collect()
    }

    #[test]
    fn messages_go_both_ways_and_come_back_whole() {
        // Miri interprets, thousands of times slower: the bounds, but not
        // a message of many chunks
        let sizes: &[usize] = if cfg!(miri) {
            &[0, 1, 1023, 1025]
        } else {
            &[0, 1, 5, 1023, 1024, 1025, 3000, 70_000]
        };
        let no_takeover = Params {
            server_takeover: Takeover::NotKept,
            client_takeover: Takeover::NotKept,
            ..Params::DEFAULT
        };
        // a server may say its window is small: npro's is not, nor need
        // its inflater mind
        let small = Params {
            server_window: WindowBits::new(9).unwrap(),
            ..Params::DEFAULT
        };
        for params in [Params::DEFAULT, no_takeover, small] {
            let mut payloads = Vec::new();
            for &n in sizes {
                payloads.push((Kind::Text, words(n)));
                payloads.push((Kind::Binary, noise(n)));
            }
            // an empty message straight after another
            payloads.push((Kind::Text, Vec::new()));
            let msgs: Vec<(Kind, &[u8])> =
                payloads.iter().map(|(k, d)| (*k, d.as_slice())).collect();

            let splits: &[(usize, usize)] = if cfg!(miri) {
                &[(64, 7)]
            } else {
                &[(4, 7), (1500, 4096), (64, 1)]
            };
            for &(limit, piece) in splits {
                let how = (params, limit, piece);
                // client to server
                let up = writes(&mut client(params), &msgs, limit);
                assert_eq!(
                    reads(&mut Ws::server(b"").with_pmd(params), &up, piece),
                    (payloads.clone(), None),
                    "up {how:?}"
                );
                // server to client
                let down = writes(&mut Ws::server(b"").with_pmd(params), &msgs, limit);
                assert_eq!(
                    reads(&mut client(params), &down, piece),
                    (payloads.clone(), None),
                    "down {how:?}"
                );
            }
        }
    }

    #[test]
    fn compressed_frames_carry_rsv1_on_the_first_only() {
        let data = noise(3000);
        let frames = writes(
            &mut Ws::server(b"").with_pmd(Params::DEFAULT),
            &[(Kind::Binary, &data)],
            4096,
        );
        // three frames of noise: the first binary with RSV1, then
        // continuations, the last with FIN
        assert_eq!(frames[0], 0x42);
        let mut at = 0;
        let mut firsts = Vec::new();
        while at < frames.len() {
            firsts.push(frames[at]);
            let len = match frames[at + 1] & 0x7f {
                126 => {
                    let l = usize::from(u16::from_be_bytes([frames[at + 2], frames[at + 3]]));
                    at += 4;
                    l
                }
                n => {
                    at += 2;
                    usize::from(n)
                }
            };
            assert!(len <= TX_CHUNK);
            at += len;
        }
        assert_eq!(firsts.first(), Some(&0x42));
        assert_eq!(firsts.last(), Some(&0x80));
        assert!(firsts[1..firsts.len() - 1].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_message_past_its_limit_is_a_zip_bomb() {
        let zeros = vec![0u8; 5000];
        let frames = writes(
            &mut client(Params::DEFAULT),
            &[(Kind::Binary, &zeros)],
            4096,
        );
        assert!(frames.len() < 100, "zeros compress");
        let limited = Params::DEFAULT.with_max_message(4999);
        assert_eq!(
            reads(&mut Ws::server(b"").with_pmd(limited), &frames, 4096),
            (Vec::new(), Some(Close::Release))
        );
        // and at the limit, it is not
        let exact = Params::DEFAULT.with_max_message(5000);
        assert_eq!(
            reads(&mut Ws::server(b"").with_pmd(exact), &frames, 4096),
            (vec![(Kind::Binary, zeros)], None)
        );
    }

    #[test]
    fn what_the_inflater_owes_is_given_without_more_input() {
        // fuzz/seeds/ws-pmd/regress-window-full, unmasked: blocks inflating
        // to 33026 zeros, then a block of the reserved type.  Filling the
        // inflater's 32KiB window stops it with the input taken, the bad
        // block's header in its bit buffer: the failure is owed, and must
        // be found without more input however the end comes apart
        let mut deflated = vec![
            0xec, 0xc1, 0x31, 0x01, 0x00, 0x00, 0x00, 0xc2, 0xa0, 0xf5, 0x4f, 0x6d, 0x0c, 0x1f,
            0xa0,
        ];
        deflated.resize(46, 0);
        deflated.extend_from_slice(&[0x11, 0x77]);
        // a frame longer than comes, so it never ends: only what the
        // inflater owes makes the connection pending
        let mut head = vec![0xc2, 0xfe, 0x08, 0x01];
        head.extend_from_slice(&[0; 4]);
        for split in 0..deflated.len() {
            let mut ws = Ws::server(b"").with_pmd(Params::DEFAULT);
            let mut got = 0;
            let first = [&head[..], &deflated[..split]].concat();
            for mut piece in [first, deflated[split..].to_vec()] {
                let mut at = 0;
                while at < piece.len() || ws.rx_pending() {
                    let rx = ws.rx(&mut piece[at..]);
                    at += rx.consumed;
                    if let Some(Event::Message { data, .. }) = rx.event {
                        got += data.len();
                    }
                    if ws.close().is_some() {
                        break;
                    }
                }
            }
            assert_eq!(
                (got, ws.close()),
                (33026, Some(Close::Release)),
                "split at {split}"
            );
        }
    }

    #[test]
    fn rsv1_is_refused_where_rfc_7692_forbids_it() {
        for (frames, close) in [
            // on a continuation
            (
                &b"\x01\x82\0\0\0\0He\xc0\x83\0\0\0\0llo"[..],
                &b"\x88\x0a\x03\xearsv bits"[..],
            ),
            // on a control frame
            (b"\xc9\x80\0\0\0\0", b"\x88\x0a\x03\xearsv bits"),
            // RSV2 with it
            (b"\xe1\x80\0\0\0\0", b"\x88\x0a\x03\xearsv bits"),
        ] {
            let mut ws = Ws::server(b"").with_pmd(Params::DEFAULT);
            let (got, _) = reads(&mut ws, frames, 64);
            assert_eq!(got, Vec::new());
            let mut out = [0u8; 64];
            let n = ws.tx(&mut out, &mut Src { data: b"", at: 0 });
            assert_eq!(&out[..n], close, "{}", frames.escape_ascii());
        }
    }

    #[test]
    fn a_server_takes_the_first_offer_and_echoes_what_it_took() {
        use npro_h1::head::{Config, Head, Side as HeadSide};
        for (offer, line, params) in [
            (
                &b"permessage-deflate"[..],
                Some(&b"permessage-deflate"[..]),
                Params::DEFAULT,
            ),
            (
                b"x-webkit-deflate-frame, permessage-deflate; server_no_context_takeover; \
                  client_max_window_bits, permessage-deflate",
                Some(b"permessage-deflate; server_no_context_takeover"),
                Params {
                    server_takeover: Takeover::NotKept,
                    ..Params::DEFAULT
                },
            ),
            // a smaller window than it keeps to declines the offer, and
            // the next is taken
            (
                b"permessage-deflate; server_max_window_bits=\"10\", \
                  permessage-deflate; client_no_context_takeover",
                Some(b"permessage-deflate; client_no_context_takeover"),
                Params {
                    client_takeover: Takeover::NotKept,
                    ..Params::DEFAULT
                },
            ),
            (
                b"permessage-deflate; server_max_window_bits=16",
                None,
                Params::DEFAULT,
            ),
            (
                b"permessage-deflate; server_max_window_bits=15",
                Some(b"permessage-deflate; server_max_window_bits=15"),
                Params::DEFAULT,
            ),
            (b"x-foo", None, Params::DEFAULT),
        ] {
            let mut req = b"GET / HTTP/1.1\r\nSec-WebSocket-Extensions: ".to_vec();
            req.extend_from_slice(offer);
            req.extend_from_slice(b"\r\n\r\n");
            let mut h = Head::new([0u8; 2048], HeadSide::Server, Config::new()).unwrap();
            h.rx(&req).unwrap();
            let a = server_accept(h.table()).unwrap();
            match (a, line) {
                (Some(a), Some(line)) => {
                    let mut want = b"sec-websocket-extensions: ".to_vec();
                    want.extend_from_slice(line);
                    want.extend_from_slice(b"\r\n");
                    assert_eq!(a.header_lines(), want.as_slice());
                    assert_eq!(a.params(), params);
                }
                (None, None) => {}
                (a, line) => panic!("{a:?} for {line:?}"),
            }
        }
    }

    #[test]
    fn a_client_takes_only_rfc_7692s_answers() {
        assert_eq!(client_accept(b"permessage-deflate"), Ok(Params::DEFAULT));
        assert_eq!(
            client_accept(
                b"permessage-deflate; server_no_context_takeover; client_max_window_bits=15; \
                  server_max_window_bits=\"12\""
            ),
            Ok(Params {
                server_takeover: Takeover::NotKept,
                server_window: WindowBits::new(12).unwrap(),
                ..Params::DEFAULT
            })
        );
        for bad in [
            &b"x-foo"[..],
            b"permessage-deflate, permessage-deflate",
            b"permessage-deflate; rx_buf_size=10",
            b"permessage-deflate; server_max_window_bits",
            b"permessage-deflate; server_max_window_bits=7",
            b"permessage-deflate; client_max_window_bits=14",
            b"permessage-deflate; server_no_context_takeover=1",
            b"permessage-deflate; server_no_context_takeover; server_no_context_takeover",
        ] {
            assert_eq!(
                client_accept(bad),
                Err(ClientRefusal::Extension),
                "{}",
                bad.escape_ascii()
            );
        }
    }
}
