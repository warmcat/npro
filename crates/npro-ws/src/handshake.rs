//! A server's side of the ws handshake: C's `lws_process_ws_upgrade()` and
//! `handshake_0405()`.
//!
//! C's checks, in C's order, each refusal C's status: an upgrade is a GET;
//! its `Connection` names the token `upgrade`; it has a key, of less than
//! 128 bytes, and a Host; its version is `13`, a 400 without one and a 426
//! (saying `sec-websocket-version: 13`) for another; and it asks for a
//! subprotocol the server has, the first of its list that it has, or with
//! no list, the server's default.

use npro_core::base64;
use npro_core::sha1::Sha1;
use npro_h1::table::HeaderTable;
use npro_h1::token::Token;

/// The GUID RFC 6455 4.2.2 appends to a key.
const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The longest key C takes, and one: C's `MAX_WEBSOCKET_04_KEY_LEN`.
const MAX_KEY: usize = 128;

/// The length of an accept value: base64 of a SHA-1.
pub const ACCEPT_LEN: usize = 28;

/// An upgrade the server takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The index of the subprotocol in the server's list.
    pub protocol: usize,
    /// Whether the request named it, so the 101 says it.
    pub named: bool,
    accept: [u8; ACCEPT_LEN],
}

impl Accepted {
    /// The `Sec-WebSocket-Accept` value.
    #[must_use]
    pub const fn accept(&self) -> &[u8; ACCEPT_LEN] {
        &self.accept
    }
}

/// Why an upgrade is refused, as C says why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not a GET (400).
    NotGet,
    /// No `upgrade` in `Connection` (400).
    NoConnectionUpgrade,
    /// No key, too long a key, or no Host (400).
    KeyOrHost,
    /// No version (400).
    NoVersion,
    /// A version that is not 13 (426).
    Version,
    /// A protocol list that is not one (400).
    ProtocolList,
    /// No protocol the server has (400).
    NoProtocol,
}

impl Refusal {
    /// The status C answers with.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::Version => 426,
            Self::NotGet
            | Self::NoConnectionUpgrade
            | Self::KeyOrHost
            | Self::NoVersion
            | Self::ProtocolList
            | Self::NoProtocol => 400,
        }
    }

    /// The header C's 426 adds to its status page.
    #[must_use]
    pub const fn header(self) -> Option<(&'static [u8], &'static [u8])> {
        match self {
            Self::Version => Some((b"sec-websocket-version", b"13")),
            Self::NotGet
            | Self::NoConnectionUpgrade
            | Self::KeyOrHost
            | Self::NoVersion
            | Self::ProtocolList
            | Self::NoProtocol => None,
        }
    }
}

/// Whether `c` is a token's byte, RFC 9110 5.6.2's tchar.
const fn tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// The elements of a comma separated list of tokens, each `Some` token, or
/// `None` for one that is not a token: what C's `lws_tokenize()` takes for
/// these lists.
fn tokens(v: &[u8]) -> impl Iterator<Item = Option<&[u8]>> {
    v.split(|c| *c == b',').filter_map(|e| {
        let blank = |c: &u8| *c == b' ' || *c == b'\t';
        let start = e.iter().position(|c| !blank(c))?;
        let end = e
            .iter()
            .rposition(|c| !blank(c))
            .map_or(0, |n| n.saturating_add(1));
        let t = e.get(start..end)?;
        Some(t.iter().all(|c| tchar(*c)).then_some(t))
    })
}

/// Checks an upgrade request against a server having the subprotocols
/// `protocols`, and `default` for a request naming none.
///
/// ```
/// use npro_h1::head::{Config, Head, Side};
/// use npro_ws::handshake::server;
///
/// let mut h = Head::new([0u8; 1024], Side::Server, Config::new())?;
/// h.rx(b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
///        Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
///        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")?;
/// let a = server(h.table(), &[b"chat"], Some(0)).unwrap();
/// assert_eq!(a.accept(), b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
///
/// # Errors
///
/// The [`Refusal`], whose status and header C answers with.
pub fn server<S: AsRef<[u8]> + AsMut<[u8]>>(
    t: &HeaderTable<S>,
    protocols: &[&[u8]],
    default: Option<usize>,
) -> Result<Accepted, Refusal> {
    if !t.is_present(Token::GetUri) {
        return Err(Refusal::NotGet);
    }
    let mut buf = [0u8; MAX_KEY];
    let conn = t
        .copy(
            Token::Connection,
            buf.get_mut(..MAX_KEY - 1).unwrap_or_default(),
        )
        .ok()
        .filter(|n| *n > 0)
        .and_then(|n| buf.get(..n))
        .ok_or(Refusal::NoConnectionUpgrade)?;
    let mut upgrade = false;
    for tok in tokens(conn) {
        match tok {
            Some(name) if name.eq_ignore_ascii_case(b"upgrade") => {
                upgrade = true;
                break;
            }
            Some(_) => {}
            None => return Err(Refusal::NoConnectionUpgrade),
        }
    }
    if !upgrade {
        return Err(Refusal::NoConnectionUpgrade);
    }

    let key_len = t.total_len(Token::WsKey);
    if key_len == 0 || key_len >= MAX_KEY || !t.is_present(Token::Host) {
        return Err(Refusal::KeyOrHost);
    }
    let mut key = [0u8; MAX_KEY];
    let key = t
        .copy(Token::WsKey, &mut key)
        .ok()
        .and_then(|n| key.get(..n))
        .ok_or(Refusal::KeyOrHost)?;

    match t.copy(Token::WsVersion, &mut buf) {
        Ok(0) => return Err(Refusal::NoVersion),
        Ok(2) if buf.get(..2) == Some(b"13".as_slice()) => {}
        Ok(_) | Err(_) => return Err(Refusal::Version),
    }

    let mut list = [0u8; MAX_KEY];
    let list = t
        .copy(
            Token::WsProtocol,
            list.get_mut(..MAX_KEY - 1).unwrap_or_default(),
        )
        .ok()
        .and_then(|n| list.get(..n))
        .ok_or(Refusal::ProtocolList)?;
    let (protocol, named) = if list.is_empty() {
        let d = default
            .filter(|d| *d < protocols.len())
            .ok_or(Refusal::NoProtocol)?;
        (d, false)
    } else {
        let mut found = None;
        for tok in tokens(list) {
            let name = tok.ok_or(Refusal::ProtocolList)?;
            if name.len() >= 64 {
                return Err(Refusal::ProtocolList);
            }
            if let Some(i) = protocols.iter().position(|p| *p == name) {
                found = Some(i);
                break;
            }
        }
        (found.ok_or(Refusal::NoProtocol)?, true)
    };

    let mut h = Sha1::new();
    h.update(key);
    h.update(GUID);
    let mut accept = [0u8; ACCEPT_LEN];
    base64::encode(&h.finish(), &mut accept).map_err(|_| Refusal::KeyOrHost)?;
    Ok(Accepted {
        protocol,
        named,
        accept,
    })
}

/// The most a 101 C writes may have here.
pub const MAX_101: usize = 256;

/// C's 101 for `a`, `name` being its subprotocol's: written into `out`,
/// returning how much of it.
///
/// # Errors
///
/// `None` if `out` is too small.
#[must_use]
pub fn response_101(a: &Accepted, name: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut at = 0usize;
    let mut put = |b: &[u8]| -> Option<()> {
        let end = at.checked_add(b.len())?;
        out.get_mut(at..end)?.copy_from_slice(b);
        at = end;
        Some(())
    };
    put(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")?;
    put(&a.accept)?;
    // the protocol is said only if the request named one, and it has a name
    if a.named && !name.is_empty() {
        put(b"\r\nSec-WebSocket-Protocol: ")?;
        put(name)?;
    }
    put(b"\r\n\r\n")?;
    Some(at)
}
