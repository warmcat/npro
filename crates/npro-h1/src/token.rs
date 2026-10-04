//! The headers lws knows by name: C's `enum lws_token_indexes`.
//!
//! C matches a name against its generated lextable, a trie over the
//! spellings in `lextable-strings.h`, one byte at a time.  The trie is how
//! C finds them, not what they are: the spellings, their delimiters (the
//! `:` of a field name, the SP after a method, nothing after an h2
//! pseudo-header) and the token each one stands for are the behaviour, and
//! those are here.  [`lookup`] answers what the trie answers after each
//! byte of a name: matched, still a prefix of something, or nothing.
//!
//! The set is C's with every header option on, as C's default build has
//! it (`LWS_WITH_HTTP_UNCOMMON_HEADERS`, `LWS_ROLE_WS`, `LWS_ROLE_H2`), and
//! the indices are C's, so a table dumped from either side lines up.

/// A header, or a piece of a head, that lws stores by token.
///
/// Each variant names its C token.  Some hold what is not a field's value:
/// the request target of each method, the request's version or the
/// response's status, and the urlargs.  The last nine are C's
/// `_WSI_TOKEN_CLIENT_*`, where a client keeps its own request: they are
/// never matched, only created.
///
/// ```
/// use npro_h1::token::Token;
///
/// assert_eq!(Token::Host.spelling(), b"host:");
/// assert_eq!(Token::GetUri.spelling(), b"get ");
/// assert_eq!(Token::ALL.len(), Token::COUNT);
/// assert_eq!(Token::ALL[27], Token::ContentLength);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Token {
    /// `WSI_TOKEN_GET_URI`: a GET's request target.
    GetUri = 0,
    /// `WSI_TOKEN_POST_URI`: a POST's request target.
    PostUri,
    /// `WSI_TOKEN_OPTIONS_URI`: an OPTIONS's request target.
    OptionsUri,
    /// `WSI_TOKEN_HOST`.
    Host,
    /// `WSI_TOKEN_CONNECTION`.
    Connection,
    /// `WSI_TOKEN_UPGRADE`.
    Upgrade,
    /// `WSI_TOKEN_ORIGIN`, and `Sec-WebSocket-Origin`, which C stores here.
    Origin,
    /// `WSI_TOKEN_DRAFT`: `Sec-WebSocket-Draft`.
    WsDraft,
    /// `WSI_TOKEN_CHALLENGE`: the empty line that ends a head, which the
    /// lextable matches as the name `"\r\n"`.  Never stored.
    Challenge,
    /// `WSI_TOKEN_EXTENSIONS`: `Sec-WebSocket-Extensions`.
    WsExtensions,
    /// `WSI_TOKEN_KEY1`: `Sec-WebSocket-Key1`, of the hixie drafts.
    WsKey1,
    /// `WSI_TOKEN_KEY2`: `Sec-WebSocket-Key2`, of the hixie drafts.
    WsKey2,
    /// `WSI_TOKEN_PROTOCOL`: `Sec-WebSocket-Protocol`.
    WsProtocol,
    /// `WSI_TOKEN_ACCEPT`: `Sec-WebSocket-Accept`.
    WsAccept,
    /// `WSI_TOKEN_NONCE`: `Sec-WebSocket-Nonce`.
    WsNonce,
    /// `WSI_TOKEN_HTTP`: on a server, the request line's version; on a
    /// client, what follows a status line's `HTTP/1.1 `.
    Http,
    /// `WSI_TOKEN_HTTP2_SETTINGS`.
    Http2Settings,
    /// `WSI_TOKEN_HTTP_ACCEPT`.
    Accept,
    /// `WSI_TOKEN_HTTP_AC_REQUEST_HEADERS`:
    /// `Access-Control-Request-Headers`.
    AccessControlRequestHeaders,
    /// `WSI_TOKEN_HTTP_IF_MODIFIED_SINCE`.
    IfModifiedSince,
    /// `WSI_TOKEN_HTTP_IF_NONE_MATCH`.
    IfNoneMatch,
    /// `WSI_TOKEN_HTTP_ACCEPT_ENCODING`.
    AcceptEncoding,
    /// `WSI_TOKEN_HTTP_ACCEPT_LANGUAGE`.
    AcceptLanguage,
    /// `WSI_TOKEN_HTTP_PRAGMA`.
    Pragma,
    /// `WSI_TOKEN_HTTP_CACHE_CONTROL`.
    CacheControl,
    /// `WSI_TOKEN_HTTP_AUTHORIZATION`.
    Authorization,
    /// `WSI_TOKEN_HTTP_COOKIE`.
    Cookie,
    /// `WSI_TOKEN_HTTP_CONTENT_LENGTH`.
    ContentLength,
    /// `WSI_TOKEN_HTTP_CONTENT_TYPE`.
    ContentType,
    /// `WSI_TOKEN_HTTP_DATE`.
    Date,
    /// `WSI_TOKEN_HTTP_RANGE`.
    Range,
    /// `WSI_TOKEN_HTTP_REFERER`.
    Referer,
    /// `WSI_TOKEN_KEY`: `Sec-WebSocket-Key`.
    WsKey,
    /// `WSI_TOKEN_VERSION`: `Sec-WebSocket-Version`.
    WsVersion,
    /// `WSI_TOKEN_SWORIGIN`: `Sec-WebSocket-Origin`.  Matched, then stored
    /// as [`Token::Origin`], as C does.
    WsOrigin,
    /// `WSI_TOKEN_HTTP_COLON_AUTHORITY`: h2 and h3's `:authority`.
    ColonAuthority,
    /// `WSI_TOKEN_HTTP_COLON_METHOD`.
    ColonMethod,
    /// `WSI_TOKEN_HTTP_COLON_PATH`.
    ColonPath,
    /// `WSI_TOKEN_HTTP_COLON_SCHEME`.
    ColonScheme,
    /// `WSI_TOKEN_HTTP_COLON_STATUS`.
    ColonStatus,
    /// `WSI_TOKEN_HTTP_ACCEPT_CHARSET`.
    AcceptCharset,
    /// `WSI_TOKEN_HTTP_ACCEPT_RANGES`.
    AcceptRanges,
    /// `WSI_TOKEN_HTTP_ACCESS_CONTROL_ALLOW_ORIGIN`.
    AccessControlAllowOrigin,
    /// `WSI_TOKEN_HTTP_AGE`.
    Age,
    /// `WSI_TOKEN_HTTP_ALLOW`.
    Allow,
    /// `WSI_TOKEN_HTTP_CONTENT_DISPOSITION`.
    ContentDisposition,
    /// `WSI_TOKEN_HTTP_CONTENT_ENCODING`.
    ContentEncoding,
    /// `WSI_TOKEN_HTTP_CONTENT_LANGUAGE`.
    ContentLanguage,
    /// `WSI_TOKEN_HTTP_CONTENT_LOCATION`.
    ContentLocation,
    /// `WSI_TOKEN_HTTP_CONTENT_RANGE`.
    ContentRange,
    /// `WSI_TOKEN_HTTP_ETAG`.
    Etag,
    /// `WSI_TOKEN_HTTP_EXPECT`.
    Expect,
    /// `WSI_TOKEN_HTTP_EXPIRES`.
    Expires,
    /// `WSI_TOKEN_HTTP_FROM`.
    From,
    /// `WSI_TOKEN_HTTP_IF_MATCH`.
    IfMatch,
    /// `WSI_TOKEN_HTTP_IF_RANGE`.
    IfRange,
    /// `WSI_TOKEN_HTTP_IF_UNMODIFIED_SINCE`.
    IfUnmodifiedSince,
    /// `WSI_TOKEN_HTTP_LAST_MODIFIED`.
    LastModified,
    /// `WSI_TOKEN_HTTP_LINK`.
    Link,
    /// `WSI_TOKEN_HTTP_LOCATION`.
    Location,
    /// `WSI_TOKEN_HTTP_MAX_FORWARDS`.
    MaxForwards,
    /// `WSI_TOKEN_HTTP_PROXY_AUTHENTICATE`.
    ProxyAuthenticate,
    /// `WSI_TOKEN_HTTP_PROXY_AUTHORIZATION`.
    ProxyAuthorization,
    /// `WSI_TOKEN_HTTP_REFRESH`.
    Refresh,
    /// `WSI_TOKEN_HTTP_RETRY_AFTER`.
    RetryAfter,
    /// `WSI_TOKEN_HTTP_SERVER`.
    Server,
    /// `WSI_TOKEN_HTTP_SET_COOKIE`.
    SetCookie,
    /// `WSI_TOKEN_HTTP_STRICT_TRANSPORT_SECURITY`.
    StrictTransportSecurity,
    /// `WSI_TOKEN_HTTP_TRANSFER_ENCODING`.
    TransferEncoding,
    /// `WSI_TOKEN_HTTP_USER_AGENT`.
    UserAgent,
    /// `WSI_TOKEN_HTTP_VARY`.
    Vary,
    /// `WSI_TOKEN_HTTP_VIA`.
    Via,
    /// `WSI_TOKEN_HTTP_WWW_AUTHENTICATE`.
    WwwAuthenticate,
    /// `WSI_TOKEN_PATCH_URI`: a PATCH's request target.
    PatchUri,
    /// `WSI_TOKEN_PUT_URI`: a PUT's request target.
    PutUri,
    /// `WSI_TOKEN_DELETE_URI`: a DELETE's request target.
    DeleteUri,
    /// `WSI_TOKEN_HTTP_URI_ARGS`: the request target's urlargs, the part
    /// after its `?`, one fragment per `&` or `;` separated argument.
    UriArgs,
    /// `WSI_TOKEN_PROXY`.
    Proxy,
    /// `WSI_TOKEN_HTTP_X_REAL_IP`.
    XRealIp,
    /// `WSI_TOKEN_HTTP1_0`: on a client, what follows a status line's
    /// `HTTP/1.0 `.
    Http10,
    /// `WSI_TOKEN_X_FORWARDED_FOR`.
    XForwardedFor,
    /// `WSI_TOKEN_CONNECT`: a CONNECT's request target.
    Connect,
    /// `WSI_TOKEN_HEAD_URI`: a HEAD's request target.
    HeadUri,
    /// `WSI_TOKEN_TE`.
    Te,
    /// `WSI_TOKEN_REPLAY_NONCE`: ACME's `Replay-Nonce`.
    ReplayNonce,
    /// `WSI_TOKEN_COLON_PROTOCOL`: RFC 8441's `:protocol`.
    ColonProtocol,
    /// `WSI_TOKEN_X_AUTH_TOKEN`.
    XAuthToken,
    /// `WSI_TOKEN_DSS_SIGNATURE`: `X-Amzn-Dss-Signature`.
    DssSignature,
    /// `_WSI_TOKEN_CLIENT_SENT_PROTOCOLS`: the ws subprotocols a client
    /// asked for.
    ClientSentProtocols,
    /// `_WSI_TOKEN_CLIENT_PEER_ADDRESS`: the address a client connects to.
    ClientPeerAddress,
    /// `_WSI_TOKEN_CLIENT_URI`: the path a client asks for.
    ClientUri,
    /// `_WSI_TOKEN_CLIENT_HOST`: the `Host` a client sends.
    ClientHost,
    /// `_WSI_TOKEN_CLIENT_ORIGIN`: the `Origin` a client sends.
    ClientOrigin,
    /// `_WSI_TOKEN_CLIENT_METHOD`: a client's method.
    ClientMethod,
    /// `_WSI_TOKEN_CLIENT_IFACE`: the interface a client binds to.
    ClientIface,
    /// `_WSI_TOKEN_CLIENT_LOCALPORT`: the port a client binds to.
    ClientLocalport,
    /// `_WSI_TOKEN_CLIENT_ALPN`: the alpn a client offers.
    ClientAlpn,
}

impl Token {
    /// How many tokens there are: C's `WSI_TOKEN_COUNT`.
    pub const COUNT: usize = 97;

    /// Every token, in C's order, so `ALL[t as usize] == t`.
    pub const ALL: [Self; Self::COUNT] = [
        Self::GetUri,
        Self::PostUri,
        Self::OptionsUri,
        Self::Host,
        Self::Connection,
        Self::Upgrade,
        Self::Origin,
        Self::WsDraft,
        Self::Challenge,
        Self::WsExtensions,
        Self::WsKey1,
        Self::WsKey2,
        Self::WsProtocol,
        Self::WsAccept,
        Self::WsNonce,
        Self::Http,
        Self::Http2Settings,
        Self::Accept,
        Self::AccessControlRequestHeaders,
        Self::IfModifiedSince,
        Self::IfNoneMatch,
        Self::AcceptEncoding,
        Self::AcceptLanguage,
        Self::Pragma,
        Self::CacheControl,
        Self::Authorization,
        Self::Cookie,
        Self::ContentLength,
        Self::ContentType,
        Self::Date,
        Self::Range,
        Self::Referer,
        Self::WsKey,
        Self::WsVersion,
        Self::WsOrigin,
        Self::ColonAuthority,
        Self::ColonMethod,
        Self::ColonPath,
        Self::ColonScheme,
        Self::ColonStatus,
        Self::AcceptCharset,
        Self::AcceptRanges,
        Self::AccessControlAllowOrigin,
        Self::Age,
        Self::Allow,
        Self::ContentDisposition,
        Self::ContentEncoding,
        Self::ContentLanguage,
        Self::ContentLocation,
        Self::ContentRange,
        Self::Etag,
        Self::Expect,
        Self::Expires,
        Self::From,
        Self::IfMatch,
        Self::IfRange,
        Self::IfUnmodifiedSince,
        Self::LastModified,
        Self::Link,
        Self::Location,
        Self::MaxForwards,
        Self::ProxyAuthenticate,
        Self::ProxyAuthorization,
        Self::Refresh,
        Self::RetryAfter,
        Self::Server,
        Self::SetCookie,
        Self::StrictTransportSecurity,
        Self::TransferEncoding,
        Self::UserAgent,
        Self::Vary,
        Self::Via,
        Self::WwwAuthenticate,
        Self::PatchUri,
        Self::PutUri,
        Self::DeleteUri,
        Self::UriArgs,
        Self::Proxy,
        Self::XRealIp,
        Self::Http10,
        Self::XForwardedFor,
        Self::Connect,
        Self::HeadUri,
        Self::Te,
        Self::ReplayNonce,
        Self::ColonProtocol,
        Self::XAuthToken,
        Self::DssSignature,
        Self::ClientSentProtocols,
        Self::ClientPeerAddress,
        Self::ClientUri,
        Self::ClientHost,
        Self::ClientOrigin,
        Self::ClientMethod,
        Self::ClientIface,
        Self::ClientLocalport,
        Self::ClientAlpn,
    ];

    /// The request methods C knows, each the token holding its request
    /// target: C's `methods[]`, in its order.
    pub const METHODS: [Self; 8] = [
        Self::GetUri,
        Self::PostUri,
        Self::OptionsUri,
        Self::PutUri,
        Self::PatchUri,
        Self::DeleteUri,
        Self::Connect,
        Self::HeadUri,
    ];

    /// C's index of the token.
    #[must_use]
    #[expect(
        clippy::as_conversions,
        reason = "a fieldless repr(u8) enum's discriminant, which is C's index, widened"
    )]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Whether the token holds a request method's target.
    #[must_use]
    pub fn is_method(self) -> bool {
        Self::METHODS.contains(&self)
    }

    /// How the token is spelled in C's lextable, lowercase, with its
    /// delimiter: C's `lws_token_to_string()`.  Empty for the tokens that
    /// are never matched, the client's own.
    #[must_use]
    pub const fn spelling(self) -> &'static [u8] {
        match self {
            Self::GetUri => b"get ",
            Self::PostUri => b"post ",
            Self::OptionsUri => b"options ",
            Self::Host => b"host:",
            Self::Connection => b"connection:",
            Self::Upgrade => b"upgrade:",
            Self::Origin => b"origin:",
            Self::WsDraft => b"sec-websocket-draft:",
            Self::Challenge => b"\r\n",
            Self::WsExtensions => b"sec-websocket-extensions:",
            Self::WsKey1 => b"sec-websocket-key1:",
            Self::WsKey2 => b"sec-websocket-key2:",
            Self::WsProtocol => b"sec-websocket-protocol:",
            Self::WsAccept => b"sec-websocket-accept:",
            Self::WsNonce => b"sec-websocket-nonce:",
            Self::Http => b"http/1.1 ",
            Self::Http2Settings => b"http2-settings:",
            Self::Accept => b"accept:",
            Self::AccessControlRequestHeaders => b"access-control-request-headers:",
            Self::IfModifiedSince => b"if-modified-since:",
            Self::IfNoneMatch => b"if-none-match:",
            Self::AcceptEncoding => b"accept-encoding:",
            Self::AcceptLanguage => b"accept-language:",
            Self::Pragma => b"pragma:",
            Self::CacheControl => b"cache-control:",
            Self::Authorization => b"authorization:",
            Self::Cookie => b"cookie:",
            Self::ContentLength => b"content-length:",
            Self::ContentType => b"content-type:",
            Self::Date => b"date:",
            Self::Range => b"range:",
            Self::Referer => b"referer:",
            Self::WsKey => b"sec-websocket-key:",
            Self::WsVersion => b"sec-websocket-version:",
            Self::WsOrigin => b"sec-websocket-origin:",
            Self::ColonAuthority => b":authority",
            Self::ColonMethod => b":method",
            Self::ColonPath => b":path",
            Self::ColonScheme => b":scheme",
            Self::ColonStatus => b":status",
            Self::AcceptCharset => b"accept-charset:",
            Self::AcceptRanges => b"accept-ranges:",
            Self::AccessControlAllowOrigin => b"access-control-allow-origin:",
            Self::Age => b"age:",
            Self::Allow => b"allow:",
            Self::ContentDisposition => b"content-disposition:",
            Self::ContentEncoding => b"content-encoding:",
            Self::ContentLanguage => b"content-language:",
            Self::ContentLocation => b"content-location:",
            Self::ContentRange => b"content-range:",
            Self::Etag => b"etag:",
            Self::Expect => b"expect:",
            Self::Expires => b"expires:",
            Self::From => b"from:",
            Self::IfMatch => b"if-match:",
            Self::IfRange => b"if-range:",
            Self::IfUnmodifiedSince => b"if-unmodified-since:",
            Self::LastModified => b"last-modified:",
            Self::Link => b"link:",
            Self::Location => b"location:",
            Self::MaxForwards => b"max-forwards:",
            Self::ProxyAuthenticate => b"proxy-authenticate:",
            Self::ProxyAuthorization => b"proxy-authorization:",
            Self::Refresh => b"refresh:",
            Self::RetryAfter => b"retry-after:",
            Self::Server => b"server:",
            Self::SetCookie => b"set-cookie:",
            Self::StrictTransportSecurity => b"strict-transport-security:",
            Self::TransferEncoding => b"transfer-encoding:",
            Self::UserAgent => b"user-agent:",
            Self::Vary => b"vary:",
            Self::Via => b"via:",
            Self::WwwAuthenticate => b"www-authenticate:",
            Self::PatchUri => b"patch",
            Self::PutUri => b"put",
            Self::DeleteUri => b"delete",
            Self::UriArgs => b"uri-args",
            Self::Proxy => b"proxy ",
            Self::XRealIp => b"x-real-ip:",
            Self::Http10 => b"http/1.0 ",
            Self::XForwardedFor => b"x-forwarded-for:",
            Self::Connect => b"connect ",
            Self::HeadUri => b"head ",
            Self::Te => b"te:",
            Self::ReplayNonce => b"replay-nonce:",
            Self::ColonProtocol => b":protocol",
            Self::XAuthToken => b"x-auth-token:",
            Self::DssSignature => b"x-amzn-dss-signature:",
            Self::ClientSentProtocols
            | Self::ClientPeerAddress
            | Self::ClientUri
            | Self::ClientHost
            | Self::ClientOrigin
            | Self::ClientMethod
            | Self::ClientIface
            | Self::ClientLocalport
            | Self::ClientAlpn => b"",
        }
    }
}

/// What C's lextable says of a name so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// The name is the whole spelling of this token.
    Matched(Token),
    /// The name is the start of at least one spelling, and the whole of
    /// none.
    Prefix,
    /// The name is the start of no spelling.
    Nothing,
}

/// What C's lextable says of `name`, the lowercased bytes of a name so far.
///
/// No spelling is the start of another, so a name matches as soon as it is
/// the whole of one, as the trie's terminal is reached on its last byte.
///
/// ```
/// use npro_h1::token::{lookup, Lookup, Token};
///
/// assert_eq!(lookup(b"hos"), Lookup::Prefix);
/// assert_eq!(lookup(b"host:"), Lookup::Matched(Token::Host));
/// assert_eq!(lookup(b"host "), Lookup::Nothing);
/// assert_eq!(lookup(b"put"), Lookup::Matched(Token::PutUri));
/// ```
#[must_use]
pub fn lookup(name: &[u8]) -> Lookup {
    let mut prefix = false;
    for t in Token::ALL {
        let s = t.spelling();
        if s.is_empty() || !s.starts_with(name) {
            continue;
        }
        if s.len() == name.len() {
            return Lookup::Matched(t);
        }
        prefix = true;
    }
    if prefix {
        Lookup::Prefix
    } else {
        Lookup::Nothing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_is_in_cs_order() {
        for (i, t) in Token::ALL.iter().enumerate() {
            assert_eq!(t.index(), i, "{t:?}");
        }
    }

    /// The trie's terminal can only be reached on a spelling's last byte if
    /// no spelling is the start of another: then a name is matched exactly
    /// when it is a whole spelling, which is what `lookup()` relies on.
    #[test]
    fn no_spelling_is_the_start_of_another() {
        for a in Token::ALL {
            for b in Token::ALL {
                let (sa, sb) = (a.spelling(), b.spelling());
                if a != b && !sa.is_empty() {
                    assert!(!sb.starts_with(sa), "{a:?} starts {b:?}");
                }
            }
        }
    }

    #[test]
    fn every_spelling_is_lowercase() {
        for t in Token::ALL {
            assert!(!t.spelling().iter().any(u8::is_ascii_uppercase), "{t:?}");
        }
    }

    #[test]
    fn every_spelling_matches_and_every_shorter_start_is_a_prefix() {
        for t in Token::ALL {
            let s = t.spelling();
            if s.is_empty() {
                continue;
            }
            assert_eq!(lookup(s), Lookup::Matched(t));
            for n in 1..s.len() {
                assert_eq!(lookup(&s[..n]), Lookup::Prefix);
            }
        }
    }
}
