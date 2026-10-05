//! The ws handshake, both sides.
//!
//! **A server's**, [`server`] and [`response_101`]: C's
//! `lws_process_ws_upgrade()` and `handshake_0405()`.
//!
//! C's checks, in C's order, each refusal C's status: an upgrade is a GET;
//! its `Connection` names the token `upgrade`; it has a key, of less than
//! 128 bytes, and a Host; its version is `13`, a 400 without one and a 426
//! (saying `sec-websocket-version: 13`) for another; and it asks for a
//! subprotocol the server has, the first of its list that it has, or with
//! no list, the server's default.
//!
//! **A client's**, [`ClientKey`]: C's `lws_generate_client_ws_handshake()`
//! and `lws_client_ws_upgrade()`.  The key is 16 random bytes; the request
//! asks for the upgrade with it, the subprotocols offered and version 13;
//! and the response must be a 101 with an accept, `Upgrade: websocket`,
//! `upgrade` among its `Connection` tokens, a subprotocol, if it names one,
//! that was offered, no extension (npro-ws has none yet), and the accept
//! the key makes.

use npro_core::base64;
use npro_core::random::{Random, Unavailable};
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

    let accept = accept_of(key).ok_or(Refusal::KeyOrHost)?;
    Ok(Accepted {
        protocol,
        named,
        accept,
    })
}

/// The accept a key makes: base64 of the SHA-1 of the key and the GUID.
fn accept_of(key: &[u8]) -> Option<[u8; ACCEPT_LEN]> {
    let mut h = Sha1::new();
    h.update(key);
    h.update(GUID);
    let mut accept = [0u8; ACCEPT_LEN];
    base64::encode(&h.finish(), &mut accept).ok()?;
    Some(accept)
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

/// The length of a client's key: base64 of 16 bytes.
pub const KEY_LEN: usize = 24;

/// The most the lines [`ClientKey::request_lines`] writes may have, but
/// for the subprotocols offered.
pub const MAX_REQUEST_LINES: usize = 160;

/// Why a client fails the server's response to its upgrade: each is C's
/// `CLIENT_CONNECTION_ERROR` reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientRefusal {
    /// The status is not 101: "HS: ws upgrade response not 101".
    NotSwitching,
    /// There is no accept: "HS: ACCEPT missing".
    NoAccept,
    /// There is no `Upgrade`: "HS: UPGRADE missing".
    NoUpgrade,
    /// The `Upgrade` is not `websocket`: "HS: Upgrade to something other
    /// than websocket".
    NotWebsocket,
    /// No `upgrade` among the `Connection` tokens: "HS: UPGRADE
    /// malformed".
    Connection,
    /// A subprotocol that was not offered: "HS: PROTOCOL malformed".
    Protocol,
    /// An extension, of which there are none: "HS: EXT: unknown ext".
    Extension,
    /// The accept is not the key's: "HS: Accept hash wrong".
    Accept,
}

impl core::fmt::Display for ClientRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotSwitching => "HS: ws upgrade response not 101",
            Self::NoAccept => "HS: ACCEPT missing",
            Self::NoUpgrade => "HS: UPGRADE missing",
            Self::NotWebsocket => "HS: Upgrade to something other than websocket",
            Self::Connection => "HS: UPGRADE malformed",
            Self::Protocol => "HS: PROTOCOL malformed",
            Self::Extension => "HS: EXT: unknown ext",
            Self::Accept => "HS: Accept hash wrong",
        })
    }
}

impl core::error::Error for ClientRefusal {}

/// A client's key, and the accept it expects for it.
///
/// ```
/// use npro_core::random::SeededRandom;
/// use npro_h1::client::{Client, Connection, Event, Request, Scheme};
/// use npro_ws::handshake::{ClientKey, MAX_REQUEST_LINES};
///
/// // C's seeded random, as its ws-client transcript has it
/// let key = ClientKey::new(&mut SeededRandom::new(1))?;
/// assert_eq!(key.key(), b"OvomtQpKCWUnZW7tMR6Gqw==");
///
/// let mut lines = [0u8; MAX_REQUEST_LINES + 32];
/// let n = key.request_lines(Some(b"echo"), &mut lines).unwrap();
/// let mut c = Client::new([0u8; 1024], Request {
///     method: b"GET",
///     path: b"/echo",
///     host: Some(b"sansio"),
///     origin: None,
///     scheme: Scheme::Http,
///     no_cache: false,
///     connection: Connection::Upgrade(&lines[..n]),
/// })?;
/// let mut out = [0u8; 512];
/// let n = c.tx(&mut out);
/// assert!(out[..n].starts_with(b"GET /echo HTTP/1.1\r\nHost: sansio\r\nUpgrade: websocket\r\n"));
///
/// let rx = c.rx(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
///                 Connection: Upgrade\r\nSec-WebSocket-Protocol: echo\r\n\
///                 Sec-WebSocket-Accept: rSsJf/ZKQdiul0BGIJ6uQGawdU8=\r\n\r\n")?;
/// assert_eq!(rx.event, Some(Event::Response));
/// let chosen = key.check(c.status(), c.response(), Some(b"echo"))?;
/// assert_eq!(chosen, Some(&b"echo"[..]));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientKey {
    key: [u8; KEY_LEN],
    accept: [u8; ACCEPT_LEN],
}

impl ClientKey {
    /// A key of 16 bytes drawn from `random`, in one draw, as C draws it.
    ///
    /// # Errors
    ///
    /// [`Unavailable`] if the source has none to give: C fails the
    /// connection.
    pub fn new(random: &mut dyn Random) -> Result<Self, Unavailable> {
        let mut raw = [0u8; 16];
        random.fill(&mut raw)?;
        let mut key = [0u8; KEY_LEN];
        // 16 bytes are always 24 of base64, whose accept is always made
        base64::encode(&raw, &mut key).map_err(|_| Unavailable)?;
        let accept = accept_of(&key).ok_or(Unavailable)?;
        Ok(Self { key, accept })
    }

    /// The `Sec-WebSocket-Key` value.
    #[must_use]
    pub const fn key(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    /// The lines asking for the upgrade, in C's order, offering
    /// `protocols`, a comma separated list, if any: for the request's
    /// [`npro_h1::client::Connection::Upgrade`].  Written into `out`,
    /// returning how much of it.
    ///
    /// `None` if `out` is too small, or `protocols` would break the line:
    /// it may not hold a CR, LF or NUL.
    #[must_use]
    pub fn request_lines(&self, protocols: Option<&[u8]>, out: &mut [u8]) -> Option<usize> {
        if protocols.is_some_and(|p| p.iter().any(|c| matches!(c, b'\r' | b'\n' | 0))) {
            return None;
        }
        let mut at = 0usize;
        let mut put = |b: &[u8]| -> Option<()> {
            let end = at.checked_add(b.len())?;
            out.get_mut(at..end)?.copy_from_slice(b);
            at = end;
            Some(())
        };
        put(b"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ")?;
        put(&self.key)?;
        put(b"\r\n")?;
        if let Some(p) = protocols {
            put(b"Sec-WebSocket-Protocol: ")?;
            put(p)?;
            put(b"\r\n")?;
        }
        put(b"Sec-WebSocket-Version: 13\r\n")?;
        Some(at)
    }

    /// Checks the server's final response, its status `status` and its
    /// headers `t`, to a request that offered `offered`: C's checks, in C's
    /// order.  Returns the subprotocol the server named, if it named one.
    ///
    /// # Errors
    ///
    /// The [`ClientRefusal`]: the connection fails.
    pub fn check<'t, S: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        status: Option<u16>,
        t: &'t HeaderTable<S>,
        offered: Option<&[u8]>,
    ) -> Result<Option<&'t [u8]>, ClientRefusal> {
        if status != Some(101) {
            return Err(ClientRefusal::NotSwitching);
        }
        if t.total_len(Token::WsAccept) == 0 {
            return Err(ClientRefusal::NoAccept);
        }
        let upgrade = t.first(Token::Upgrade).ok_or(ClientRefusal::NoUpgrade)?;
        if !upgrade.eq_ignore_ascii_case(b"websocket") {
            return Err(ClientRefusal::NotWebsocket);
        }

        // C takes the list only if it fits its 64 byte buffer
        let mut buf = [0u8; 64];
        let conn = t
            .copy(Token::Connection, buf.get_mut(..63).unwrap_or_default())
            .ok()
            .filter(|n| *n > 0)
            .and_then(|n| buf.get(..n))
            .ok_or(ClientRefusal::Connection)?;
        let mut upgrade_token = false;
        for tok in tokens(conn) {
            match tok {
                Some(name) if name.eq_ignore_ascii_case(b"upgrade") => {
                    upgrade_token = true;
                    break;
                }
                Some(_) => {}
                None => return Err(ClientRefusal::Connection),
            }
        }
        if !upgrade_token {
            return Err(ClientRefusal::Connection);
        }

        let chosen = if t.total_len(Token::WsProtocol) == 0 {
            None
        } else {
            let name = t.first(Token::WsProtocol).unwrap_or_default();
            let was_offered = offered.is_some_and(|list| {
                list.split(|c| *c == b',')
                    .map(|e| {
                        let start = e.iter().position(|c| *c != b' ').unwrap_or(e.len());
                        e.get(start..).unwrap_or_default()
                    })
                    .any(|e| e == name)
            });
            if !was_offered {
                return Err(ClientRefusal::Protocol);
            }
            Some(name)
        };

        if t.total_len(Token::WsExtensions) > 0 {
            return Err(ClientRefusal::Extension);
        }
        if t.first(Token::WsAccept) != Some(self.accept.as_slice()) {
            return Err(ClientRefusal::Accept);
        }
        Ok(chosen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use npro_core::random::SeededRandom;
    use npro_h1::client::{Client, Connection, Request, Scheme};

    /// The head of a 101 with the accept of seed 1's key, as C's ws-client
    /// transcript has it.
    macro_rules! ok_101 {
        ($rest:literal) => {
            concat!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n",
                "Connection: Upgrade\r\nSec-WebSocket-Accept: rSsJf/ZKQdiul0BGIJ6uQGawdU8=\r\n",
                $rest,
                "\r\n"
            )
        };
    }

    /// What became of a response.
    #[derive(Debug, PartialEq, Eq)]
    enum Verdict {
        /// Taken, naming a protocol this long, or none.
        Took(Option<usize>),
        Refused(ClientRefusal),
    }

    /// What the key of seed 1, having offered `echo, chat`, makes of
    /// `response`.
    fn verdict(response: &str) -> Verdict {
        let key = ClientKey::new(&mut SeededRandom::new(1)).unwrap();
        let mut lines = [0u8; MAX_REQUEST_LINES];
        let n = key.request_lines(Some(b"echo, chat"), &mut lines).unwrap();
        let mut c = Client::new(
            [0u8; 1024],
            Request {
                method: b"GET",
                path: b"/",
                host: None,
                origin: None,
                scheme: Scheme::Http,
                no_cache: false,
                connection: Connection::Upgrade(&lines[..n]),
            },
        )
        .unwrap();
        let mut out = [0u8; 512];
        let _ = c.tx(&mut out);
        let _ = c.rx(response.as_bytes()).unwrap();
        assert!(c.is_upgraded(), "{response}");
        match key.check(c.status(), c.response(), Some(b"echo, chat")) {
            Ok(p) => Verdict::Took(p.map(<[u8]>::len)),
            Err(r) => Verdict::Refused(r),
        }
    }

    #[test]
    fn a_good_101_names_an_offered_protocol_or_none() {
        assert_eq!(verdict(ok_101!("")), Verdict::Took(None));
        assert_eq!(
            verdict(ok_101!("Sec-WebSocket-Protocol: chat\r\n")),
            Verdict::Took(Some(4))
        );
        assert_eq!(
            verdict(ok_101!("Sec-WebSocket-Protocol: chit\r\n")),
            Verdict::Refused(ClientRefusal::Protocol)
        );
        assert_eq!(
            verdict(ok_101!("Sec-WebSocket-Extensions: x\r\n")),
            Verdict::Refused(ClientRefusal::Extension)
        );
    }

    #[test]
    fn a_bad_response_is_refused_in_cs_order() {
        for (response, refusal) in [
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                ClientRefusal::NotSwitching,
            ),
            (
                "HTTP/1.1 101 S\r\nUpgrade: websocket\r\n\r\n",
                ClientRefusal::NoAccept,
            ),
            (
                "HTTP/1.1 101 S\r\nSec-WebSocket-Accept: x\r\n\r\n",
                ClientRefusal::NoUpgrade,
            ),
            (
                "HTTP/1.1 101 S\r\nSec-WebSocket-Accept: x\r\nUpgrade: h2c\r\n\r\n",
                ClientRefusal::NotWebsocket,
            ),
            (
                "HTTP/1.1 101 S\r\nSec-WebSocket-Accept: x\r\nUpgrade: WebSocket\r\n\r\n",
                ClientRefusal::Connection,
            ),
            (
                "HTTP/1.1 101 S\r\nSec-WebSocket-Accept: x\r\nUpgrade: websocket\r\n\
                 Connection: keep-alive\r\n\r\n",
                ClientRefusal::Connection,
            ),
            // C takes a token that starts "upgrade": npro takes only it
            (
                "HTTP/1.1 101 S\r\nSec-WebSocket-Accept: x\r\nUpgrade: websocket\r\n\
                 Connection: up\r\n\r\n",
                ClientRefusal::Connection,
            ),
            (
                "HTTP/1.1 101 S\r\nSec-WebSocket-Accept: x\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\n\r\n",
                ClientRefusal::Accept,
            ),
        ] {
            assert_eq!(verdict(response), Verdict::Refused(refusal), "{response}");
        }
    }

    #[test]
    fn the_request_lines_refuse_a_protocol_list_that_breaks_the_line() {
        let key = ClientKey::new(&mut SeededRandom::new(1)).unwrap();
        let mut out = [0u8; MAX_REQUEST_LINES];
        assert_eq!(key.request_lines(Some(b"a\r\nX: y"), &mut out), None);
        assert_eq!(key.request_lines(None, &mut out[..10]), None);
        let n = key.request_lines(None, &mut out).unwrap();
        assert_eq!(
            &out[..n],
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: OvomtQpKCWUnZW7tMR6Gqw==\r\nSec-WebSocket-Version: 13\r\n"
        );
    }
}
