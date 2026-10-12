//! A URL a client connects to, and a reference resolved against one: RFC
//! 3986 for the `http`, `https`, `ws` and `wss` schemes.  What a client is
//! told to connect to, by its user or by a server's `Location`, comes
//! through here.  C's is `lws_parse_uri()`, with the reference handling in
//! `lws_client_interpret_server_handshake()`.
//!
//! [`parse`] takes an absolute URL, and [`resolve`] a reference, absolute
//! or relative, against one ([RFC 3986 5.2]).  Either copies what it
//! keeps into caller storage, so a [`Uri`] does not borrow what it came
//! from, and its request target (path and query) is one slice, as an h1
//! request line wants it, with dot segments removed.
//!
//! Stricter than C, which takes what it is given and cuts it up:
//!
//! - userinfo (`user@host`) is refused: RFC 9110 4.2.4 forbids it in an
//!   `http` URI, and it is a way to make a host look like another;
//! - a host is a bracketed IPv6 literal, or a registered name or IPv4
//!   address of unreserved characters only, which is all dns carries;
//! - a port is decimal, 1 to 65535, where C takes `atoi()` of what is
//!   there; an empty port is the scheme's;
//! - the path, query and fragment must be RFC 3986's characters, with
//!   each `%` followed by two hex digits, so nothing that reaches a
//!   request line can end it early or change its meaning;
//! - a relative reference is resolved by RFC 3986 5.2, where C takes any
//!   reference without a `:` as an absolute path, so that `foo` is `/foo`
//!   rather than beside the base's last segment, and `//host/x` is a path;
//! - the fragment is dropped, as a request does not carry it.
//!
//! [RFC 3986 5.2]: https://www.rfc-editor.org/rfc/rfc3986#section-5.2
//!
//! ```
//! use npro_h1::uri::{self, Scheme};
//!
//! let mut b = [0u8; 256];
//! let base = uri::parse(b"https://example.com/a/b?x=1", &mut b)?;
//! assert_eq!((base.scheme(), base.host(), base.port()), (Scheme::Https, &b"example.com"[..], 443));
//! assert_eq!(base.target(), b"/a/b?x=1");
//!
//! let mut r = [0u8; 256];
//! let to = uri::resolve(&base, b"../c?y", &mut r)?;
//! assert_eq!(to.target(), b"/c?y");
//! # Ok::<(), uri::UriError>(())
//! ```

/// The schemes a client connects to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `http`.
    Http,
    /// `https`.
    Https,
    /// `ws`.
    Ws,
    /// `wss`.
    Wss,
}

impl Scheme {
    /// The scheme named `s`, whatever its case (RFC 3986 3.1).
    fn named(s: &[u8]) -> Option<Self> {
        [
            (Self::Http, &b"http"[..]),
            (Self::Https, b"https"),
            (Self::Ws, b"ws"),
            (Self::Wss, b"wss"),
        ]
        .into_iter()
        .find(|(_, n)| s.eq_ignore_ascii_case(n))
        .map(|(scheme, _)| scheme)
    }

    /// Whether the connection is over tls.
    #[must_use]
    pub const fn is_tls(self) -> bool {
        match self {
            Self::Https | Self::Wss => true,
            Self::Http | Self::Ws => false,
        }
    }

    /// The port when none is given.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        if self.is_tls() { 443 } else { 80 }
    }
}

/// Why a URL or reference is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UriError {
    /// The scheme is none of `http`, `https`, `ws` and `wss`, or is not a
    /// scheme.
    Scheme,
    /// An absolute URL has no authority (`//`).
    NoAuthority,
    /// The authority has userinfo.
    UserInfo,
    /// The host is empty, or not an IPv6 literal or a name of unreserved
    /// characters.
    Host,
    /// The port is not decimal, or not 1 to 65535.
    Port,
    /// The path, query or fragment has a character RFC 3986 does not
    /// allow there, or a `%` not followed by two hex digits.
    Char,
    /// What is kept does not fit in the storage given.
    TooLong,
}

impl core::fmt::Display for UriError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Scheme => "not an http, https, ws or wss URL",
            Self::NoAuthority => "a URL with no authority",
            Self::UserInfo => "a URL with userinfo",
            Self::Host => "a URL's host is not a name or address",
            Self::Port => "a URL's port is not 1 to 65535",
            Self::Char => "a URL has a character not allowed where it is",
            Self::TooLong => "a URL does not fit",
        })
    }
}

impl core::error::Error for UriError {}

/// An absolute URL, its host and request target in the storage it was
/// made in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uri<'a> {
    scheme: Scheme,
    /// The host as written, an IPv6 literal with its brackets.
    host: &'a [u8],
    port: u16,
    /// The path, then the query with its `?`, if any.
    target: &'a [u8],
    /// Where the query starts in `target`.
    path_len: usize,
}

impl<'a> Uri<'a> {
    /// The scheme.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host to connect to: a name, or an address, an IPv6 one without
    /// its brackets.
    #[must_use]
    pub fn host(&self) -> &'a [u8] {
        self.host
            .strip_prefix(b"[")
            .and_then(|h| h.strip_suffix(b"]"))
            .unwrap_or(self.host)
    }

    /// The host as a `Host` header has it: an IPv6 literal in brackets.
    #[must_use]
    pub const fn authority_host(&self) -> &'a [u8] {
        self.host
    }

    /// The port, the scheme's if none was given.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The request target: the path, at least `/`, with no dot segments,
    /// then the query with its `?`, if any.
    #[must_use]
    pub const fn target(&self) -> &'a [u8] {
        self.target
    }

    /// The path alone.
    #[must_use]
    pub fn path(&self) -> &'a [u8] {
        self.target.get(..self.path_len).unwrap_or(self.target)
    }

    /// The query, without its `?`, if there is one.
    #[must_use]
    pub fn query(&self) -> Option<&'a [u8]> {
        self.target
            .get(self.path_len..)
            .and_then(|q| q.strip_prefix(b"?"))
    }
}

/// Parses `url`, an absolute URL, keeping its host and request target in
/// `storage`.
///
/// # Errors
///
/// The [`UriError`] that refuses it.
pub fn parse<'s>(url: &[u8], storage: &'s mut [u8]) -> Result<Uri<'s>, UriError> {
    let (scheme, rest) = split_scheme(url).ok_or(UriError::Scheme)?;
    let scheme = Scheme::named(scheme).ok_or(UriError::Scheme)?;
    let rest = rest.strip_prefix(b"//").ok_or(UriError::NoAuthority)?;
    absolute(scheme, rest, storage)
}

/// Resolves `reference`, absolute or relative, against `base` (RFC 3986
/// 5.2), keeping the result's host and request target in `storage`.
///
/// # Errors
///
/// The [`UriError`] that refuses it.
pub fn resolve<'s>(
    base: &Uri<'_>,
    reference: &[u8],
    storage: &'s mut [u8],
) -> Result<Uri<'s>, UriError> {
    if split_scheme(reference).is_some() {
        return parse(reference, storage);
    }
    if let Some(rest) = reference.strip_prefix(b"//") {
        return absolute(base.scheme, rest, storage);
    }
    let parts = Parts::of(reference)?;
    let mut out = Out::new(storage);
    out.push(base.host)?;
    let host_len = out.len;
    match parts.path {
        // the base's path, and its query unless the reference has one
        b"" => {
            out.push(base.path())?;
            let path_len = out.len.saturating_sub(host_len);
            match parts.query {
                Some(q) => {
                    out.push(b"?")?;
                    out.push(q)?;
                }
                None => {
                    if let Some(q) = base.query() {
                        out.push(b"?")?;
                        out.push(q)?;
                    }
                }
            }
            return out.finish(base.scheme, base.port, host_len, path_len);
        }
        p if p.starts_with(b"/") => out.path(Segments::new(&[], p))?,
        // merged with the base's path up to its last `/` (5.2.3)
        p => {
            let base_path = base.path();
            let dir = base_path
                .iter()
                .rposition(|c| *c == b'/')
                .and_then(|n| base_path.get(..n))
                .unwrap_or_default();
            out.path(Segments::new(dir, p))?;
        }
    }
    let path_len = out.len.saturating_sub(host_len);
    if let Some(q) = parts.query {
        out.push(b"?")?;
        out.push(q)?;
    }
    out.finish(base.scheme, base.port, host_len, path_len)
}

/// The scheme and what follows its `:`, if `s` starts with one: a letter,
/// then letters, digits, `+`, `-` or `.`, before any `/`, `?` or `#`.
fn split_scheme(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = s.iter().position(|c| *c == b':')?;
    let (scheme, rest) = (s.get(..colon)?, s.get(colon.saturating_add(1)..)?);
    let first = *scheme.first()?;
    let ok = first.is_ascii_alphabetic()
        && scheme
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'));
    ok.then_some((scheme, rest))
}

/// What follows an absolute URL's `//`.
fn absolute<'s>(scheme: Scheme, rest: &[u8], storage: &'s mut [u8]) -> Result<Uri<'s>, UriError> {
    let end = rest
        .iter()
        .position(|c| matches!(c, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    let (authority, after) = rest.split_at(end);
    let (host, port) = authority_parts(authority)?;
    let port = port.map_or(Ok(scheme.default_port()), port_number)?;
    let parts = Parts::of(after)?;
    let mut out = Out::new(storage);
    out.push(host)?;
    let host_len = out.len;
    out.path(Segments::new(&[], parts.path))?;
    let path_len = out.len.saturating_sub(host_len);
    if let Some(q) = parts.query {
        out.push(b"?")?;
        out.push(q)?;
    }
    out.finish(scheme, port, host_len, path_len)
}

/// The host, as written, and the port's digits if there is a port.
fn authority_parts(a: &[u8]) -> Result<(&[u8], Option<&[u8]>), UriError> {
    if a.contains(&b'@') {
        return Err(UriError::UserInfo);
    }
    let (host, port) = if a.starts_with(b"[") {
        // an IPv6 literal, its brackets kept
        let close = a.iter().position(|c| *c == b']').ok_or(UriError::Host)?;
        let (host, after) = a.split_at(close.saturating_add(1));
        let inner = host.get(1..close).unwrap_or_default();
        let literal = inner
            .iter()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, b':' | b'.'));
        if inner.is_empty() || !literal {
            return Err(UriError::Host);
        }
        let port = match after {
            b"" => None,
            _ => Some(after.strip_prefix(b":").ok_or(UriError::Host)?),
        };
        (host, port)
    } else {
        let (host, port) = match a.iter().position(|c| *c == b':') {
            Some(n) => (a.get(..n).unwrap_or_default(), a.get(n.saturating_add(1)..)),
            None => (a, None),
        };
        if host.is_empty() || !host.iter().all(|c| is_unreserved(*c)) {
            return Err(UriError::Host);
        }
        (host, port)
    };
    // an empty port is the scheme's (RFC 3986 3.2.3)
    Ok((host, port.filter(|p| !p.is_empty())))
}

/// A port's digits as a port.
fn port_number(digits: &[u8]) -> Result<u16, UriError> {
    if digits.is_empty() || digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(UriError::Port);
    }
    let v = digits.iter().fold(0u32, |v, d| {
        v.saturating_mul(10)
            .saturating_add(u32::from(d.wrapping_sub(b'0')))
    });
    u16::try_from(v)
        .ok()
        .filter(|p| *p != 0)
        .ok_or(UriError::Port)
}

/// RFC 3986's unreserved characters.
const fn is_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

/// RFC 3986's `pchar`, but for `%`, which is checked with what follows it.
const fn is_pchar(c: u8) -> bool {
    is_unreserved(c)
        || matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

/// Whether `s` is only `pchar`s, percent-encodings and the `extra`
/// characters.
fn chars_ok(s: &[u8], extra: &[u8]) -> bool {
    let mut it = s.iter();
    while let Some(c) = it.next() {
        let ok = match *c {
            b'%' => {
                matches!((it.next(), it.next()), (Some(a), Some(b)) if a.is_ascii_hexdigit() && b.is_ascii_hexdigit())
            }
            c => is_pchar(c) || extra.contains(&c),
        };
        if !ok {
            return false;
        }
    }
    true
}

/// A reference's path and query, its fragment checked and dropped.
struct Parts<'r> {
    path: &'r [u8],
    query: Option<&'r [u8]>,
}

impl<'r> Parts<'r> {
    fn of(s: &'r [u8]) -> Result<Self, UriError> {
        let (s, fragment) = match s.iter().position(|c| *c == b'#') {
            Some(n) => (s.get(..n).unwrap_or_default(), s.get(n.saturating_add(1)..)),
            None => (s, None),
        };
        let (path, query) = match s.iter().position(|c| *c == b'?') {
            Some(n) => (s.get(..n).unwrap_or_default(), s.get(n.saturating_add(1)..)),
            None => (s, None),
        };
        let ok = chars_ok(path, b"/")
            && query.is_none_or(|q| chars_ok(q, b"/?"))
            && fragment.is_none_or(|f| chars_ok(f, b"/?"));
        if !ok {
            return Err(UriError::Char);
        }
        Ok(Self { path, query })
    }
}

/// A path's segments, split at each `/`.
type Split<'p> = core::slice::Split<'p, u8, fn(&u8) -> bool>;

/// The segments of a path to be made absolute and rid of dot segments:
/// those of `dir`, a base's path up to its last `/`, then those of
/// `path`, or of `path` alone if it is absolute.
struct Segments<'p> {
    dir: Split<'p>,
    path: core::iter::Peekable<Split<'p>>,
}

impl<'p> Segments<'p> {
    fn new(dir: &'p [u8], path: &'p [u8]) -> Self {
        let slash: fn(&u8) -> bool = |c| *c == b'/';
        // a leading `/` starts the path, and is not a segment
        let dir = dir.strip_prefix(b"/").unwrap_or(dir);
        let path = if dir.is_empty() {
            path.strip_prefix(b"/").unwrap_or(path)
        } else {
            path
        };
        let mut d = dir.split(slash);
        // an empty `dir` has no segments, where `split` would give one
        if dir.is_empty() {
            let _ = d.next();
        }
        Self {
            dir: d,
            path: path.split(slash).peekable(),
        }
    }

    /// The next segment, and whether it is the last.
    fn next(&mut self) -> Option<(&'p [u8], bool)> {
        if let Some(s) = self.dir.next() {
            return Some((s, false));
        }
        let s = self.path.next()?;
        Some((s, self.path.peek().is_none()))
    }
}

/// What is kept, as it is written into the caller's storage.
struct Out<'s> {
    buf: &'s mut [u8],
    len: usize,
}

impl<'s> Out<'s> {
    const fn new(buf: &'s mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    fn push(&mut self, b: &[u8]) -> Result<(), UriError> {
        let end = self.len.checked_add(b.len()).ok_or(UriError::TooLong)?;
        self.buf
            .get_mut(self.len..end)
            .ok_or(UriError::TooLong)?
            .copy_from_slice(b);
        self.len = end;
        Ok(())
    }

    /// Writes the path the segments make, absolute, with its dot
    /// segments removed (RFC 3986 5.2.4): `.` is dropped, `..` drops the
    /// segment before it, and either as the last segment leaves the path
    /// ending in `/`.
    fn path(&mut self, mut segs: Segments<'_>) -> Result<(), UriError> {
        let start = self.len;
        self.push(b"/")?;
        // the path written so far always ends in `/` before a segment
        while let Some((seg, last)) = segs.next() {
            match seg {
                b"." => {}
                b".." => {
                    // back to the `/` before the last segment written
                    let written = self.buf.get(start..self.len).unwrap_or_default();
                    let keep = written
                        .get(..written.len().saturating_sub(1))
                        .and_then(|w| w.iter().rposition(|c| *c == b'/'))
                        .map_or(1, |n| n.saturating_add(1));
                    self.len = start.saturating_add(keep);
                }
                s => {
                    self.push(s)?;
                    if !last {
                        self.push(b"/")?;
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(
        self,
        scheme: Scheme,
        port: u16,
        host_len: usize,
        path_len: usize,
    ) -> Result<Uri<'s>, UriError> {
        let kept = self.buf.get(..self.len).ok_or(UriError::TooLong)?;
        let (host, target) = kept.split_at(host_len);
        Ok(Uri {
            scheme,
            host,
            port,
            target,
            path_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &[u8]) -> Result<([u8; 64], usize), UriError> {
        let mut b = [0u8; 256];
        let u = parse(url, &mut b)?;
        let mut t = [0u8; 64];
        t[..u.target().len()].copy_from_slice(u.target());
        Ok((t, u.target().len()))
    }

    #[test]
    fn a_url_is_cut_up() {
        for (url, scheme, host, port, target) in [
            (
                &b"HTTPS://Example.com:8443/a%2Fb/c?x=1&y=/?#frag"[..],
                Scheme::Https,
                &b"Example.com"[..],
                8443,
                &b"/a%2Fb/c?x=1&y=/?"[..],
            ),
            (b"ws://[::1]/", Scheme::Ws, b"::1", 80, b"/"),
            (
                b"wss://[2001:db8::1]:9",
                Scheme::Wss,
                b"2001:db8::1",
                9,
                b"/",
            ),
            // an empty port is the scheme's, and an empty path is `/`
            (b"http://h:?q", Scheme::Http, b"h", 80, b"/?q"),
            (b"http://h", Scheme::Http, b"h", 80, b"/"),
            // dot segments go, from the path but not the query
            (
                b"http://h/a/./b/../../../c/.",
                Scheme::Http,
                b"h",
                80,
                b"/c/",
            ),
            (b"http://h/a//b/..", Scheme::Http, b"h", 80, b"/a//"),
            (b"http://h/a?b/../c", Scheme::Http, b"h", 80, b"/a?b/../c"),
        ] {
            let mut b = [0u8; 256];
            let u = parse(url, &mut b).unwrap();
            assert_eq!(
                (u.scheme(), u.host(), u.port(), u.target()),
                (scheme, host, port, target),
                "{}",
                url.escape_ascii()
            );
        }
        let mut b = [0u8; 256];
        let u = parse(b"http://[::1]:8/a/b?x=1", &mut b).unwrap();
        assert_eq!(u.authority_host(), b"[::1]");
        assert_eq!((u.path(), u.query()), (&b"/a/b"[..], Some(&b"x=1"[..])));
    }

    #[test]
    fn what_c_would_take_is_refused() {
        for (url, why) in [
            (&b"ftp://h/"[..], UriError::Scheme),
            (b"h/x", UriError::Scheme),
            (b"1http://h/", UriError::Scheme),
            (b"http:/h/", UriError::NoAuthority),
            (b"http:h", UriError::NoAuthority),
            (b"http://user@h/", UriError::UserInfo),
            (b"http://good.com@evil.com/", UriError::UserInfo),
            (b"http:///x", UriError::Host),
            (b"http://h%41/", UriError::Host),
            (b"http://h!/", UriError::Host),
            (b"http://[]/", UriError::Host),
            (b"http://[::1/", UriError::Host),
            (b"http://[::1]x/", UriError::Host),
            (b"http://[g::1]/", UriError::Host),
            (b"http://h:0/", UriError::Port),
            (b"http://h:65536/", UriError::Port),
            (b"http://h:080x/", UriError::Port),
            (b"http://h:-1/", UriError::Port),
            (b"http://h:123456/", UriError::Port),
            (b"http://h/a b", UriError::Char),
            (b"http://h/a\r\nHost: x", UriError::Char),
            (b"http://h/a%2", UriError::Char),
            (b"http://h/a%zz", UriError::Char),
            (b"http://h/\xc3\xa9", UriError::Char),
            (b"http://h/?a b", UriError::Char),
            (b"http://h/#a b", UriError::Char),
            (b"http://h/[x]", UriError::Char),
        ] {
            assert_eq!(target(url).err(), Some(why), "{}", url.escape_ascii());
        }
        assert_eq!(target(b"http://h:65535/").map(|_| ()), Ok(()));
    }

    #[test]
    fn what_does_not_fit_is_refused() {
        // `host`, then `/abc`: eight bytes
        assert_eq!(
            parse(b"http://host/abc", &mut [0u8; 7]).err(),
            Some(UriError::TooLong)
        );
        let mut b = [0u8; 8];
        assert_eq!(
            parse(b"http://host/abc", &mut b).map(|u| u.target()),
            Ok(&b"/abc"[..])
        );
    }

    /// RFC 3986 5.4's examples, with its base: the normal ones, then the
    /// abnormal, but for those with a scheme other than http (`g:h`) or a
    /// scheme with no authority (`http:g`), which are refused.
    #[test]
    fn rfc_3986_5_4_resolves() {
        let mut b = [0u8; 256];
        let base = parse(b"http://a/b/c/d;p?q", &mut b).unwrap();
        for (r, want) in [
            (&b"g"[..], &b"http://a/b/c/g"[..]),
            (b"./g", b"http://a/b/c/g"),
            (b"g/", b"http://a/b/c/g/"),
            (b"/g", b"http://a/g"),
            (b"//g", b"http://g/"),
            (b"?y", b"http://a/b/c/d;p?y"),
            (b"g?y", b"http://a/b/c/g?y"),
            (b"#s", b"http://a/b/c/d;p?q"),
            (b"g#s", b"http://a/b/c/g"),
            (b"g?y#s", b"http://a/b/c/g?y"),
            (b";x", b"http://a/b/c/;x"),
            (b"g;x", b"http://a/b/c/g;x"),
            (b"g;x?y#s", b"http://a/b/c/g;x?y"),
            (b"", b"http://a/b/c/d;p?q"),
            (b".", b"http://a/b/c/"),
            (b"./", b"http://a/b/c/"),
            (b"..", b"http://a/b/"),
            (b"../", b"http://a/b/"),
            (b"../g", b"http://a/b/g"),
            (b"../..", b"http://a/"),
            (b"../../", b"http://a/"),
            (b"../../g", b"http://a/g"),
            (b"../../../g", b"http://a/g"),
            (b"../../../../g", b"http://a/g"),
            (b"/./g", b"http://a/g"),
            (b"/../g", b"http://a/g"),
            (b"g.", b"http://a/b/c/g."),
            (b".g", b"http://a/b/c/.g"),
            (b"g..", b"http://a/b/c/g.."),
            (b"..g", b"http://a/b/c/..g"),
            (b"./../g", b"http://a/b/g"),
            (b"./g/.", b"http://a/b/c/g/"),
            (b"g/./h", b"http://a/b/c/g/h"),
            (b"g/../h", b"http://a/b/c/h"),
            (b"g;x=1/./y", b"http://a/b/c/g;x=1/y"),
            (b"g;x=1/../y", b"http://a/b/c/y"),
            (b"g?y/./x", b"http://a/b/c/g?y/./x"),
            (b"g?y/../x", b"http://a/b/c/g?y/../x"),
            (b"g#s/./x", b"http://a/b/c/g"),
            (b"g#s/../x", b"http://a/b/c/g"),
            (b"https://x:1/y", b"https://x:1/y"),
        ] {
            let mut o = [0u8; 256];
            let u =
                resolve(&base, r, &mut o).unwrap_or_else(|e| panic!("{}: {e}", r.escape_ascii()));
            let mut w = [0u8; 256];
            let want = parse(want, &mut w).unwrap();
            assert_eq!(u, want, "{}", r.escape_ascii());
        }
        let mut o = [0u8; 256];
        assert_eq!(resolve(&base, b"g:h", &mut o).err(), Some(UriError::Scheme));
        assert_eq!(
            resolve(&base, b"http:g", &mut o).err(),
            Some(UriError::NoAuthority)
        );
        assert_eq!(resolve(&base, b"g h", &mut o).err(), Some(UriError::Char));
    }

    #[test]
    fn a_network_path_keeps_the_base_scheme() {
        let mut b = [0u8; 256];
        let base = parse(b"wss://a:9/x", &mut b).unwrap();
        let mut o = [0u8; 256];
        let u = resolve(&base, b"//b/y", &mut o).unwrap();
        assert_eq!(
            (u.scheme(), u.host(), u.port(), u.target()),
            (Scheme::Wss, &b"b"[..], 443, &b"/y"[..])
        );
    }
}
