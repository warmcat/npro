//! What the policy gives npro-ss, as Rust types.
//!
//! So far, a server's: its listeners, each with where it binds, whether
//! it is tls and with what, how its h1 takes requests, and the vhosts it
//! serves; each vhost with the routes a request's path is matched
//! against, and the headers every response carries; each route with what
//! serves it, by name, and whether a request for ws on it is taken.  JSON
//! (`npro-json`) is one way to make them, Rust code another; npro-ss sees
//! only these.  It is the first form of `docs/ss-policy.md`: the layers
//! and the services' parameters come after, and nothing here stops them.
//!
//! A request is routed as C's `lws_select_vhost()` and `lws_find_mount()`
//! route it ([`find_vhost`], [`find_route`]): the vhost by its `Host`, the
//! route by the longest path that matches.

use npro_h1::server::Config as H1Config;

/// The most vhosts a listener serves.
pub const MAX_VHOSTS: usize = 256;

/// The most routes a vhost has.
pub const MAX_ROUTES: usize = 1024;

/// A listener, C's server streamtype: one address the adapter binds, and
/// the vhosts served on it.
///
/// ```
/// use npro_h1::server::Config;
/// use npro_ss::policy::{Listener, Match, Route, Tls, Vhost, Ws};
///
/// let l = Listener {
///     name: "www",
///     bind: "[::]:8080",
///     tls: Tls::Plain,
///     h1: Config::default(),
///     vhosts: &[Vhost {
///         name: "example.com",
///         routes: &[Route {
///             path: "/",
///             matching: Match::Prefix,
///             to: "files",
///             ws: Ws::NotTaken,
///             headers: &[],
///         }],
///         headers: &[(b"x-frame-options", b"deny")],
///         not_found: Some("/404.html"),
///     }],
/// };
/// assert_eq!(l.vhosts[0].routes[0].to, "files");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listener<'p> {
    /// Its name in the policy.
    pub name: &'p str,
    /// Where the adapter binds it, as the adapter reads addresses:
    /// `[::]:443`, or `unix:/run/npro/www.sock`.
    pub bind: &'p str,
    /// Whether what it accepts is tls.
    pub tls: Tls<'p>,
    /// How its h1 takes requests: header limits, timeouts, the most a body
    /// may be.
    pub h1: H1Config,
    /// The vhosts it serves, at least one and at most [`MAX_VHOSTS`]: a
    /// request goes to the one its `Host` names, or to the first.
    pub vhosts: &'p [Vhost<'p>],
}

/// Whether a listener's connections are tls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tls<'p> {
    /// They are not.
    Plain,
    /// They are, with this certificate chain and key, by path: the
    /// adapter's to load, and to load again when they change on disk.
    Server {
        /// The certificate chain, PEM.
        cert: &'p str,
        /// Its private key, PEM.
        key: &'p str,
    },
}

/// A vhost: what is served under one host name.  C's vhost, less what
/// is the listener's here (the port, the interface, tls).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vhost<'p> {
    /// Its host name, as a request's `Host` names it: `example.com`.  A
    /// `Host` of `a.example.com` reaches it too, if no vhost is named
    /// that exactly, as C's wildcard match.  Not empty, and no two vhosts
    /// on a listener share one.
    pub name: &'p str,
    /// The routes a request's path is matched against, at most
    /// [`MAX_ROUTES`], the longest match taken: C's mounts.  No two share
    /// a path.
    pub routes: &'p [Route<'p>],
    /// The headers every response carries, before the route's and the
    /// application's: C's vhost `headers`.
    pub headers: &'p [(&'p [u8], &'p [u8])],
    /// Where a request nothing serves is sent instead of a 404 page: a
    /// path on this vhost, `/404.html`, which is answered 302 with it as
    /// its `location`.  A request for the document itself that is not
    /// found gets the page.  C's `error-document-404`.
    pub not_found: Option<&'p str>,
}

/// A route: a path and what serves it.  C's mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route<'p> {
    /// The path it serves, starting with `/`: C's mountpoint.  `/` is
    /// everything.
    pub path: &'p str,
    /// How a request's path matches it.
    pub matching: Match,
    /// What serves it, by the name the application knows it by: a service
    /// (`files`, `proxy`) or an endpoint of one (`webrtc.eu1.signalling`).
    /// The application resolves it; npro-ss only carries it.
    pub to: &'p str,
    /// Whether a request for ws on it is taken by npro-ss.
    pub ws: Ws<'p>,
    /// The headers its responses carry, after the vhost's and before the
    /// application's: C's per-mount `headers`.
    pub headers: &'p [(&'p [u8], &'p [u8])],
}

/// How a request's path matches a route's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Match {
    /// The route's path, or it followed by `/` and more: C's mount.
    Prefix,
    /// The route's path alone: C's `exact-match`.
    Exact,
}

/// Whether a route takes a request's upgrade to ws.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ws<'p> {
    /// It does not: such a request is the application's like any other,
    /// to answer as it chooses, which a server may do (RFC 9110 7.8).
    NotTaken,
    /// It does, as this says: npro-ss answers the handshake, or refuses
    /// it as C does, before the application sees the stream again.
    Taken(WsServer<'p>),
}

/// How a route takes ws.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsServer<'p> {
    /// The subprotocols it has, by name; a request naming none of them is
    /// refused.  Not empty.
    pub protocols: &'p [&'p [u8]],
    /// The one of `protocols` a request naming none is given, or `None` to
    /// refuse it: C's first protocol.
    pub default: Option<usize>,
    /// What the application's messages are: C's `ws_binary`.
    pub payload: Payload,
    /// Whether permessage-deflate is taken when offered.
    pub deflate: Deflate,
}

/// What a stream's ws messages are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payload {
    /// Text, which must be UTF-8.
    Text,
    /// Binary.
    Binary,
}

/// Whether permessage-deflate (RFC 7692) is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deflate {
    /// Never.
    Off,
    /// When the client offers it.  It needs npro-ss' `pmd` feature: a
    /// policy asking for it in a build without is refused.
    Offered,
}

/// The host name in a `Host` header's value: without its port, and with
/// an IPv6 literal's brackets kept, so `[::1]:80` is `[::1]`.
fn host_name(host: &[u8]) -> &[u8] {
    let end = match host.first() {
        Some(b'[') => host
            .iter()
            .position(|c| *c == b']')
            .map(|i| i.saturating_add(1)),
        Some(_) | None => host.iter().position(|c| *c == b':'),
    };
    end.and_then(|e| host.get(..e)).unwrap_or(host)
}

/// Which of `vhosts` a request with `host` (its `Host` header, if it has
/// one) is for: the one named exactly, any case; else the one `host` is
/// under, `a.example.com` for `example.com`, the nearest if it is under
/// several; else the first.  C's `lws_select_vhost()`, except that C
/// takes the first of several a host is under, not the nearest.  `None`
/// only if there are no vhosts.
#[must_use]
pub fn find_vhost<'p>(vhosts: &'p [Vhost<'p>], host: Option<&[u8]>) -> Option<usize> {
    let Some(name) = host.map(host_name) else {
        return (!vhosts.is_empty()).then_some(0);
    };
    let exact = vhosts
        .iter()
        .position(|v| v.name.as_bytes().eq_ignore_ascii_case(name));
    let under = || {
        vhosts
            .iter()
            .enumerate()
            .filter(|(_, v)| {
                let n = v.name.as_bytes();
                name.len()
                    .checked_sub(n.len())
                    .and_then(|at| at.checked_sub(1))
                    .and_then(|dot| Some((name.get(dot)?, name.get(dot.saturating_add(1)..)?)))
                    .is_some_and(|(d, rest)| *d == b'.' && rest.eq_ignore_ascii_case(n))
            })
            .max_by_key(|(_, v)| v.name.len())
            .map(|(i, _)| i)
    };
    exact
        .or_else(under)
        .or_else(|| (!vhosts.is_empty()).then_some(0))
}

/// Whether `path` matches the route `r`: C's `lws_find_mount()` rules.
fn matches(r: &Route<'_>, path: &[u8]) -> bool {
    let mount = r.path.as_bytes();
    let Some(rest) = path.strip_prefix(mount) else {
        return false;
    };
    match r.matching {
        Match::Exact => rest.is_empty(),
        Match::Prefix => rest.is_empty() || rest.first() == Some(&b'/') || mount == b"/",
    }
}

/// Which of `routes` serves `path`: of those that match, the one with the
/// longest path, and of two as long, an exact one before a prefix, else
/// the first.  C's `lws_find_mount()`.  Gives its index and the rest of
/// the path under it, without the `/` between: `a/b` for `/x/a/b` on
/// `/x`, and for `/a/b` on `/`.
#[must_use]
pub fn find_route<'p, 'a>(routes: &'p [Route<'p>], path: &'a [u8]) -> Option<(usize, &'a [u8])> {
    let mut best: Option<(usize, &Route<'p>)> = None;
    for (i, r) in routes.iter().enumerate() {
        if !matches(r, path) {
            continue;
        }
        let better = match best {
            None => true,
            Some((_, b)) => {
                r.path.len() > b.path.len()
                    || (r.path.len() == b.path.len()
                        && r.matching == Match::Exact
                        && b.matching == Match::Prefix)
            }
        };
        if better {
            best = Some((i, r));
        }
    }
    let (i, r) = best?;
    let rest = path.get(r.path.len()..).unwrap_or_default();
    let rest = rest.strip_prefix(b"/").unwrap_or(rest);
    Some((i, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn route(path: &'static str, matching: Match) -> Route<'static> {
        Route {
            path,
            matching,
            to: "x",
            ws: Ws::NotTaken,
            headers: &[],
        }
    }

    const fn vhost(name: &'static str) -> Vhost<'static> {
        Vhost {
            name,
            routes: &[],
            headers: &[],
            not_found: None,
        }
    }

    #[test]
    fn the_longest_matching_route_wins_and_exact_beats_prefix_as_long() {
        let routes = [
            route("/", Match::Prefix),
            route("/git", Match::Prefix),
            route("/git/x", Match::Exact),
            route("/git/x", Match::Prefix),
            route("/docrepo", Match::Prefix),
            route("/docrepo/get", Match::Prefix),
            route("/only", Match::Exact),
        ];
        for (path, want) in [
            (&b"/"[..], Some((0, &b""[..]))),
            (b"/index.html", Some((0, b"index.html"))),
            (b"/a/b", Some((0, b"a/b"))),
            (b"/git", Some((1, b""))),
            (b"/git/", Some((1, b""))),
            (b"/git/repo.git", Some((1, b"repo.git"))),
            // "/gitx" is not under "/git"
            (b"/gitx", Some((0, b"gitx"))),
            (b"/git/x", Some((2, b""))),
            (b"/git/x/y", Some((3, b"y"))),
            (b"/docrepo/get/f.tar.gz", Some((5, b"f.tar.gz"))),
            (b"/docrepo/getx", Some((4, b"getx"))),
            (b"/only", Some((6, b""))),
            (b"/only/x", Some((0, b"only/x"))),
            (b"", None),
            (b"x", None),
        ] {
            assert_eq!(find_route(&routes, path), want, "{}", path.escape_ascii());
        }
        assert_eq!(find_route(&[], b"/"), None);
        // without a catch-all, nothing serves what is not under a route
        assert_eq!(find_route(&routes[1..], b"/x"), None);
    }

    #[test]
    fn the_vhost_is_the_hosts_exactly_or_above_it_or_the_first() {
        let vhosts = [
            vhost("example.com"),
            vhost("rtc.example.com"),
            vhost("[::1]"),
        ];
        for (host, want) in [
            (None, Some(0)),
            (Some(&b"example.com"[..]), Some(0)),
            (Some(b"EXAMPLE.com:443"), Some(0)),
            (Some(b"rtc.example.com"), Some(1)),
            (Some(b"a.rtc.example.com:8443"), Some(1)),
            (Some(b"www.example.com"), Some(0)),
            (Some(b"notexample.com"), Some(0)),
            (Some(b"other.org"), Some(0)),
            (Some(b"[::1]:80"), Some(2)),
            (Some(b"[::2]"), Some(0)),
            (Some(b""), Some(0)),
            (Some(b".com"), Some(0)),
        ] {
            assert_eq!(find_vhost(&vhosts, host), want, "{host:?}");
        }
        assert_eq!(find_vhost(&[], Some(b"example.com")), None);
        assert_eq!(find_vhost(&[], None), None);
    }
}
