//! npro-proxy: a request passed to an origin, and its answer passed back.
//!
//! C's `lws_http_proxy_start()` and the proxy halves of
//! `lws_callback_http_dummy()`, as a service over npro-ss' streams: a
//! request on a route whose `to` names an [`Upstream`] is made of the
//! origin by a stream connecting out ([`start`]), always as h1, and
//! whatever either side is then told ([`on_event`]) moves bytes between
//! the two through one bounded buffer per direction
//! ([`buffer::Buffer`]).  A side is read only while the other has room:
//! past the high mark the giving side's rx is held, and let go once the
//! taking side has drained it below the low one, so a slow client holds
//! the origin back, and an upload a slow origin holds the client back,
//! as C's proxy does with `lws_rx_flow_control()`.
//!
//! What goes onward (C's `lws_http_proxy_snapshot_onward()`): the
//! method, the path re-encoded under the origin's own with the
//! arguments put back ([`onward`]), the request's `Host`, and
//! `authorization`, `content-type`, `etag`, `if-modified-since`,
//! `accept-language`, `accept-encoding`, `cache-control` and `cookie`;
//! the body, framed by its `Content-Length`, an empty one said for a
//! POST, PUT or PATCH without.  What comes back: the status,
//! `content-type`, `etag`, `accept-language`, `content-encoding`,
//! `cache-control`, each `set-cookie`, and `location`; the body, by its
//! length, or to the connection's close when the origin gave none.  An
//! origin that cannot be reached is answered 503, as C answers; one
//! that goes before its answer's head, 502.
//!
//! Not yet: a chunked request body passed on (411, where C chunks it
//! onward), ws passed through, an origin over tls, and the connection
//! to the origin kept warm.  Unlike C, the request's own `Host` goes
//! onward rather than the origin's address, and the connection to the
//! client is kept alive when the origin's answer had a length, where C
//! adds `connection: close`.
//!
//! The service keeps its state in each stream's own `U`: a [`Side`] for
//! the accepted stream and one for the stream to the origin, each
//! naming the other.  An event on either comes to [`on_event`], which
//! stages what the stream received and fills what it may write, and
//! says what to do after the event ([`Act`]), since the streams cannot
//! be called while the event borrows them: the staged bytes are moved
//! to the other side's buffer ([`moved`]), the client answered from the
//! origin's head ([`answer`]), and the rest are calls on the streams.

#![no_std]
#![forbid(unsafe_code)]

pub mod buffer;
pub mod onward;

use npro_core::random::Random;
use npro_h1::client::{Connection, Request, RequestBody, Scheme};
use npro_io::tls::RecordLayer;
use npro_ss::event::{End, Filled, Flow, Kind, RespondError, Response, Txn};
use npro_ss::id::StreamId;
use npro_ss::ss::{ConnectError, Ss};

use buffer::Buffer;
use onward::Onward;

pub use buffer::CAPACITY;
pub use onward::MAX_ONWARD;

/// An origin: where a route's requests go.  C's `http://` mount origin,
/// `http://+/var/run/sai:/sai` being `unix:/var/run/sai` with the path
/// `/sai`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Upstream<'p> {
    /// Where to connect, as the adapter reads addresses: `unix:/path`, or
    /// a host and port.
    pub address: &'p str,
    /// The origin's own path, put before what came after the route's.
    pub path: &'p str,
    /// The `Host` sent onward when the request had none.
    pub host: &'p str,
}

/// The most of a head kept, either way: the headers passed on, names
/// and values together.
pub const MAX_HEAD: usize = 4096;

/// The most headers passed on, either way.
pub const MAX_HEADERS: usize = 32;

/// The request headers passed onward, in C's order.
const ONWARD: [&[u8]; 8] = [
    b"authorization",
    b"content-type",
    b"etag",
    b"if-modified-since",
    b"accept-language",
    b"accept-encoding",
    b"cache-control",
    b"cookie",
];

/// The response headers passed back, in C's order; `set-cookie` each
/// time it came.
const BACK: [&[u8]; 7] = [
    b"content-type",
    b"etag",
    b"accept-language",
    b"content-encoding",
    b"cache-control",
    b"set-cookie",
    b"location",
];

/// Headers copied out of a head, names and values, in order, within
/// [`MAX_HEAD`] bytes and [`MAX_HEADERS`] of them.
#[derive(Clone, Debug)]
pub struct Headers {
    bytes: [u8; MAX_HEAD],
    len: usize,
    /// Each header's start, the end of its name, and its end.
    spans: [(u16, u16, u16); MAX_HEADERS],
    count: usize,
}

impl Headers {
    const fn empty() -> Self {
        Self {
            bytes: [0; MAX_HEAD],
            len: 0,
            spans: [(0, 0, 0); MAX_HEADERS],
            count: 0,
        }
    }

    /// Copies a header in: `false` if it does not fit.
    fn add(&mut self, name: &[u8], value: &[u8]) -> bool {
        let Some(end) = self
            .len
            .checked_add(name.len())
            .and_then(|e| e.checked_add(value.len()))
            .filter(|e| *e <= MAX_HEAD)
        else {
            return false;
        };
        if self.count >= MAX_HEADERS {
            return false;
        }
        let (Ok(start), Ok(mid), Ok(stop)) = (
            u16::try_from(self.len),
            u16::try_from(self.len.saturating_add(name.len())),
            u16::try_from(end),
        ) else {
            return false;
        };
        let Some(to) = self.bytes.get_mut(self.len..end) else {
            return false;
        };
        let (n, v) = to.split_at_mut(name.len());
        n.copy_from_slice(name);
        v.copy_from_slice(value);
        if let Some(s) = self.spans.get_mut(self.count) {
            *s = (start, mid, stop);
        }
        self.count = self.count.saturating_add(1);
        self.len = end;
        true
    }

    /// The headers, as slices into the copy: how many.
    fn fill<'a>(&'a self, out: &mut [(&'a [u8], &'a [u8]); MAX_HEADERS]) -> usize {
        for (i, (start, mid, stop)) in self.spans.iter().take(self.count).enumerate() {
            let name = self
                .bytes
                .get(usize::from(*start)..usize::from(*mid))
                .unwrap_or_default();
            let value = self
                .bytes
                .get(usize::from(*mid)..usize::from(*stop))
                .unwrap_or_default();
            if let Some(o) = out.get_mut(i) {
                *o = (name, value);
            }
        }
        self.count
    }
}

/// Which of a proxied request's two streams a [`Side`] is.
#[derive(Clone, Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "the origin's side holds the head it copied out, the client's needs nothing: a Side is sized for the origin's either way, as each stream's U is sized for whatever it may hold"
)]
pub enum Role {
    /// The accepted stream, the client's.
    Client {
        /// Whether its answer has been made from the origin's head.
        answered: bool,
    },
    /// The stream to the origin.
    Origin {
        /// The origin's head, copied out for the client's answer.
        status: u16,
        /// Its `content-length`, if it had one it could be trusted on.
        content_length: Option<u64>,
        /// The headers passed back.
        headers: Headers,
    },
}

/// The storage one side keeps its bytes in: the caller's, as
/// everywhere in npro.  [`CAPACITY`] each, for a server.
#[derive(Clone, Copy, Debug)]
pub struct Storage<B> {
    /// For what the stream receives, waiting to be moved to the peer.
    pub staging: B,
    /// For what the stream sends, moved from the peer.
    pub out: B,
}

/// A proxied request's state on one of its two streams, its bytes in
/// storage `B`.
#[derive(Debug)]
pub struct Side<B> {
    /// The other stream.
    peer: StreamId,
    role: Role,
    /// What this stream received, waiting to be moved to the peer.
    staging: Buffer<B>,
    /// What this stream sends, moved from the peer.
    out: Buffer<B>,
    /// The peer's rx is held, for this stream's `out` to drain.
    holding_peer: bool,
}

impl<B> Side<B> {
    /// The other stream.
    #[must_use]
    pub const fn peer(&self) -> StreamId {
        self.peer
    }

    /// Which stream this is.
    #[must_use]
    pub const fn role(&self) -> &Role {
        &self.role
    }
}

/// What to do once the event is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Act {
    /// What `from` staged goes to `to`'s buffer: [`moved`].
    Move {
        /// The stream that received it.
        from: StreamId,
        /// The stream to send it.
        to: StreamId,
    },
    /// The client's stream is answered from the origin's head:
    /// [`answer`].
    Answer {
        /// The client's.
        client: StreamId,
        /// The origin's, whose [`Side`] holds the head.
        origin: StreamId,
    },
    /// The client's stream is answered with this status page, if it is
    /// not answered yet.
    Status(StreamId, u16),
    /// The origin went: the client's answer ends with what came, or, not
    /// yet answered, is 502.
    OriginGone(StreamId),
    /// The stream is done with.
    Destroy(StreamId),
    /// The stream has payload to write.
    RequestTx(StreamId),
    /// The stream's rx is held, or given again.
    Flow(StreamId, Flow),
}

/// The calls an event came to, in order: at most four.
#[derive(Clone, Copy, Debug, Default)]
pub struct Acts {
    acts: [Option<Act>; 4],
}

impl Acts {
    fn push(&mut self, a: Act) {
        if let Some(slot) = self.acts.iter_mut().find(|s| s.is_none()) {
            *slot = Some(a);
        }
    }

    /// The calls, in order.
    pub fn iter(&self) -> impl Iterator<Item = Act> + '_ {
        self.acts.iter().flatten().copied()
    }
}

/// How the request's body is framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AskedBody {
    /// There is none, and the method has none.
    None,
    /// This long.
    Length(u64),
    /// A POST, PUT or PATCH with no body: said to be empty, as C says.
    Empty,
    /// Chunked, or of no length: not passed on.
    Unframed,
}

/// What of a request [`start`] needs, copied out of it while the
/// [`Txn`] is in hand: the stream it is on cannot be borrowed by the
/// event and asked for a connection at once.
#[derive(Clone, Debug)]
pub struct Asked {
    method: &'static [u8],
    path: Onward,
    host: [u8; 256],
    host_len: usize,
    body: AskedBody,
    headers: Headers,
}

/// Why a request could not be copied out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AskError {
    /// The request is on no route.
    NoRoute,
    /// The onward path, or a header going onward, does not fit.
    TooLong,
}

impl AskError {
    /// The status the client is answered with.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::NoRoute => 404,
            Self::TooLong => 414,
        }
    }
}

impl Asked {
    /// Copies out of `txn` what the onward request needs, for
    /// `upstream`: the method, the path under the origin's with the
    /// arguments, the `Host`, the body's framing and the headers that go
    /// onward.
    ///
    /// # Errors
    ///
    /// [`AskError`].
    pub fn of<S: AsRef<[u8]> + AsMut<[u8]>>(
        upstream: &Upstream<'_>,
        txn: &Txn<'_, S>,
    ) -> Result<Self, AskError> {
        let routed = txn.route().ok_or(AskError::NoRoute)?;
        let path = Onward::new(upstream.path, routed.rest)
            .and_then(|o| o.with_args(txn.args()))
            .map_err(|onward::TooLong| AskError::TooLong)?;
        let method: &'static [u8] = match txn.method() {
            Some(b"POST") => b"POST",
            Some(b"PUT") => b"PUT",
            Some(b"PATCH") => b"PATCH",
            Some(b"DELETE") => b"DELETE",
            Some(b"HEAD") => b"HEAD",
            // C sends GET for the rest, OPTIONS and CONNECT among them
            Some(_) | None => b"GET",
        };
        let may_have_body = matches!(method, b"POST" | b"PUT" | b"PATCH");
        let body = match txn.header(b"content-length") {
            Some(v) => match length(v) {
                Some(0) => AskedBody::Empty,
                Some(n) => AskedBody::Length(n),
                None => AskedBody::Unframed,
            },
            None if txn.header(b"transfer-encoding").is_some() => AskedBody::Unframed,
            None if may_have_body => AskedBody::Empty,
            None => AskedBody::None,
        };
        let mut host = [0u8; 256];
        let from = txn.header(b"host").unwrap_or(upstream.host.as_bytes());
        let host_len = from.len().min(host.len());
        if let (Some(to), Some(f)) = (host.get_mut(..host_len), from.get(..host_len)) {
            to.copy_from_slice(f);
        }
        let mut headers = Headers::empty();
        for name in ONWARD {
            if let Some(v) = txn.header(name) {
                if !headers.add(name, v) {
                    return Err(AskError::TooLong);
                }
            }
        }
        Ok(Self {
            method,
            path,
            host,
            host_len,
            body,
            headers,
        })
    }

    /// The onward path, with its arguments.
    #[must_use]
    pub fn path(&self) -> &[u8] {
        self.path.as_bytes()
    }
}

/// A `Content-Length` value: digits alone.
fn length(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    v.iter().try_fold(0u64, |n, d| {
        n.checked_mul(10)?
            .checked_add(u64::from(d.saturating_sub(b'0')))
    })
}

/// Why a request could not be passed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// The request's body has no length: 411, where C chunks it onward.
    LengthRequired,
    /// The stream to the origin could not be made: 503.
    Connect(ConnectError),
}

impl StartError {
    /// The status the client is answered with.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::LengthRequired => 411,
            Self::Connect(_) => 503,
        }
    }
}

/// Passes the request `asked`, on the stream `client`, on to `upstream`:
/// a stream connecting out is made on `ss` with the onward request, its
/// `U` made by `into` from the origin's [`Side`], in `for_origin`; the
/// client's side, in `for_client`, is returned, for the client stream's
/// own `U`.  Make it after the event that gave the request.
///
/// # Errors
///
/// [`StartError`]: the client is to be answered with its status; the
/// storage is dropped.
pub fn start<U, S, R, T, B>(
    upstream: &Upstream<'_>,
    asked: &Asked,
    client: StreamId,
    ss: &mut Ss<'_, U, S, R, T>,
    for_client: Storage<B>,
    for_origin: Storage<B>,
    into: impl FnOnce(Side<B>) -> U,
) -> Result<Side<B>, StartError>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
    T: RecordLayer,
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    let body = match asked.body {
        AskedBody::None => RequestBody::None,
        AskedBody::Length(n) => RequestBody::Length(n),
        AskedBody::Empty => RequestBody::Length(0),
        AskedBody::Unframed => return Err(StartError::LengthRequired),
    };
    let mut headers: [(&[u8], &[u8]); MAX_HEADERS] = [(&[], &[]); MAX_HEADERS];
    let n = asked.headers.fill(&mut headers);
    let req = Request {
        method: asked.method,
        path: asked.path.as_bytes(),
        host: Some(asked.host.get(..asked.host_len).unwrap_or_default()),
        origin: None,
        scheme: Scheme::Http,
        no_cache: false,
        connection: Connection::Close,
        headers: headers.get(..n).unwrap_or_default(),
        body,
    };
    let origin_side = Side {
        peer: client,
        role: Role::Origin {
            status: 0,
            content_length: None,
            headers: Headers::empty(),
        },
        staging: Buffer::new(for_origin.staging),
        out: Buffer::new(for_origin.out),
        holding_peer: false,
    };
    let origin = ss
        .connect(upstream.address, None, req, into(origin_side))
        .map_err(StartError::Connect)?;
    Ok(Side {
        peer: origin,
        role: Role::Client { answered: false },
        staging: Buffer::new(for_client.staging),
        out: Buffer::new(for_client.out),
        holding_peer: false,
    })
}

/// What a stream of the proxy's was told, with its own [`Side`] in
/// hand: what it received is staged, its chance to write is filled from
/// its buffer, and what to do after is said.
pub fn on_event<S, R, T, B>(stream: StreamId, side: &mut Side<B>, kind: Kind<'_, S, R, T>) -> Acts
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
    T: RecordLayer,
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    let mut acts = Acts::default();
    let peer = side.peer;
    match (&mut side.role, kind) {
        // the origin answered: its head is copied out for the client
        (
            Role::Origin {
                status,
                content_length,
                headers,
            },
            Kind::Response(r),
        ) => {
            *status = r.status();
            *content_length = r.header(b"content-length").and_then(length);
            *headers = Headers::empty();
            let fits = BACK
                .iter()
                .all(|name| r.values(name).all(|v| headers.add(name, v)));
            if fits {
                acts.push(Act::Answer {
                    client: peer,
                    origin: stream,
                });
            } else {
                acts.push(Act::Status(peer, 502));
                acts.push(Act::Destroy(stream));
            }
        }
        // what either received: staged, then moved to the other
        (Role::Origin { .. } | Role::Client { .. }, Kind::Rx { data, end }) => {
            let (n, _) = side.staging.put(data);
            if n < data.len() {
                // never so while the piece fits the staging: the stream
                // is held once the peer is past the high mark
                acts.push(Act::Status(peer, 502));
                acts.push(Act::Destroy(stream));
                return acts;
            }
            if end == End::Last {
                side.staging.end();
            }
            acts.push(Act::Move {
                from: stream,
                to: peer,
            });
        }
        // either side's chance to write, from what was moved to it
        (Role::Origin { .. } | Role::Client { .. }, Kind::Tx(tx)) => {
            let out = &mut side.out;
            tx.fill(|buf| {
                let n = out.take(buf);
                if out.ended() && out.is_empty() {
                    Filled::Last(n)
                } else {
                    Filled::More(n)
                }
            });
            if side.holding_peer && side.out.below_low() {
                acts.push(Act::Move {
                    from: peer,
                    to: stream,
                });
            }
        }
        (Role::Origin { .. }, Kind::ConnectFailed) => acts.push(Act::Status(peer, 503)),
        // the origin went: what it staged goes to the client first, which
        // its state, kept until the next look, still allows
        (Role::Origin { .. }, Kind::Disconnected) => {
            acts.push(Act::Move {
                from: stream,
                to: peer,
            });
            acts.push(Act::OriginGone(peer));
        }
        (Role::Client { .. }, Kind::Disconnected) => acts.push(Act::Destroy(peer)),
        (
            Role::Origin { .. } | Role::Client { .. },
            Kind::ServerTxn(_)
            | Kind::ServerUpgrade { .. }
            | Kind::UpgradeRefused(_)
            | Kind::Pong
            | Kind::PeerClose { .. }
            | Kind::ServerTxnEnd(_),
        )
        | (Role::Client { .. }, Kind::Response(_) | Kind::ConnectFailed) => {}
    }
    acts
}

/// Moves what `from` staged to `to`'s buffer, as far as it has room:
/// [`Act::Move`].  Holds `from`'s rx while `to` is past its high mark,
/// and gives it again once `to` has drained; ends `to`'s sending when
/// `from` received its last.  `side_of` finds a stream's [`Side`] in
/// its `U`.  What comes of it is applied here: calls on `ss`, with
/// nothing left for the caller.
pub fn moved<U, S, R, T, B>(
    ss: &mut Ss<'_, U, S, R, T>,
    from: StreamId,
    to: StreamId,
    side_of: impl Fn(&mut U) -> Option<&mut Side<B>>,
) where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
    T: RecordLayer,
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    let mut piece = [0u8; 2048];
    let mut any = false;
    loop {
        let room = match ss.user(to).ok().and_then(&side_of) {
            Some(t) => t.out.room(),
            None => return,
        };
        let want = room.min(piece.len());
        let (n, ended, left) = match ss.user(from).ok().and_then(&side_of) {
            Some(f) => {
                let n = f.staging.take(piece.get_mut(..want).unwrap_or_default());
                (n, f.staging.ended(), f.staging.len())
            }
            // the giver is gone: what it staged went with it
            None => (0, true, 0),
        };
        let Some(t) = ss.user(to).ok().and_then(&side_of) else {
            return;
        };
        if n > 0 {
            t.out.put(piece.get(..n).unwrap_or_default());
            any = true;
        }
        if left == 0 {
            if ended {
                t.out.end();
                any = true;
            }
            // all moved: the giver may go on, if it was held
            if t.holding_peer {
                t.holding_peer = false;
                let _ = ss.flow(from, Flow::Given);
            }
            break;
        }
        if n == 0 || t.out.past_high() {
            // past the high mark, or no room at all: the giver waits
            // until this side has drained
            t.holding_peer = true;
            let _ = ss.flow(from, Flow::Held);
            break;
        }
    }
    if any {
        let _ = ss.request_tx(to);
    }
}

/// Answers the client's stream from the head held on the origin's:
/// [`Act::Answer`].  The client's side is then marked answered.
///
/// # Errors
///
/// [`RespondError`], and the client is not answered.
pub fn answer<U, S, R, T, B>(
    ss: &mut Ss<'_, U, S, R, T>,
    client: StreamId,
    origin: StreamId,
    side_of: impl Fn(&mut U) -> Option<&mut Side<B>>,
) -> Result<(), RespondError>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
    T: RecordLayer,
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    let (status, content_length, headers) = match ss.user(origin).ok().and_then(&side_of) {
        Some(Side {
            role:
                Role::Origin {
                    status,
                    content_length,
                    headers,
                },
            ..
        }) => (*status, *content_length, headers.clone()),
        Some(_) | None => return Err(RespondError::Gone),
    };
    let mut all: [(&[u8], &[u8]); MAX_HEADERS] = [(&[], &[]); MAX_HEADERS];
    let n = headers.fill(&mut all);
    let mut rest: [(&[u8], &[u8]); MAX_HEADERS] = [(&[], &[]); MAX_HEADERS];
    let mut content_type = None;
    let mut m = 0;
    for (name, value) in all.iter().take(n) {
        if *name == b"content-type" {
            content_type = Some(*value);
        } else if let Some(r) = rest.get_mut(m) {
            *r = (name, value);
            m = m.saturating_add(1);
        }
    }
    ss.respond(
        client,
        Response {
            status,
            content_type,
            content_length,
            headers: rest.get(..m).unwrap_or_default(),
        },
    )?;
    if let Some(Side {
        role: Role::Client { answered },
        ..
    }) = ss.user(client).ok().and_then(side_of)
    {
        *answered = true;
    }
    // the answer's head goes, and its body as it is moved
    let _ = ss.request_tx(client);
    Ok(())
}

/// The origin went: [`Act::OriginGone`].  A client not yet answered is
/// answered 502, at `now`; one answered has its answer end with what
/// came, short of its length if the origin stopped short, which the
/// connection answers by closing.
pub fn origin_gone<U, S, R, T, B>(
    ss: &mut Ss<'_, U, S, R, T>,
    now: npro_core::time::Instant,
    client: StreamId,
    side_of: impl Fn(&mut U) -> Option<&mut Side<B>>,
) where
    S: AsRef<[u8]> + AsMut<[u8]>,
    R: Random,
    T: RecordLayer,
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    let answered = match ss.user(client).ok().and_then(&side_of) {
        Some(Side {
            role: Role::Client { answered: made },
            out,
            ..
        }) => {
            out.end();
            *made
        }
        Some(_) | None => return,
    };
    if answered {
        let _ = ss.request_tx(client);
    } else {
        let _ = ss.status(now, client, 502);
        if let Some(Side {
            role: Role::Client { answered: made },
            ..
        }) = ss.user(client).ok().and_then(side_of)
        {
            *made = true;
        }
        let _ = ss.request_tx(client);
    }
}

/// Whether a side's sending is over: its buffer ended and empty.
#[must_use]
pub const fn is_done<B: AsRef<[u8]> + AsMut<[u8]>>(side: &Side<B>) -> bool {
    side.out.ended() && side.out.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_content_length_is_digits_alone() {
        assert_eq!(length(b"0"), Some(0));
        assert_eq!(length(b"1234567890"), Some(1_234_567_890));
        assert_eq!(length(b""), None);
        assert_eq!(length(b"-1"), None);
        assert_eq!(length(b"1 "), None);
        assert_eq!(length(b"99999999999999999999"), None);
    }

    #[test]
    fn headers_are_kept_within_their_bounds() {
        let mut h = Headers::empty();
        assert!(h.add(b"a", b"1"));
        let big = [b'x'; MAX_HEAD];
        assert!(!h.add(b"b", &big));
        let mut out: [(&[u8], &[u8]); MAX_HEADERS] = [(&[], &[]); MAX_HEADERS];
        assert_eq!(h.fill(&mut out), 1);
        assert_eq!(out[0], (&b"a"[..], &b"1"[..]));
        for _ in 0..MAX_HEADERS {
            h.add(b"c", b"");
        }
        assert_eq!(h.count, MAX_HEADERS);
        assert!(!h.add(b"d", b""));
    }
}
