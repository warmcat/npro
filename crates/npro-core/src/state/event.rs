//! What happened to a connection, as the code driving it reports it.

/// Something that happened to a connection: C's `LWS_WSIEV_*`.
///
/// Code driving a connection does not choose the state it goes to; it says
/// what happened, and the event table ([`Machines::event`]) says where that
/// leads by role, side and state.  These are the events of the roles npro
/// has: h1 client and server, ws, and raw sockets.  Those of h2, h3, quic,
/// mqtt and webtransport arrive with their roles.
///
/// [`Machines::event`]: super::Machines::event
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Event {
    /// The transport finished: connect and any tls are done.
    TransportUp,
    /// A server parsed a request's headers.
    ReqHdrsComplete,
    /// The h1 server decided a request asking to upgrade stays http.
    ReqPlainHttp,
    /// The server began acting on a request.
    ActionBegin,
    /// A request body began.
    BodyBegin,
    /// A request body is complete.
    BodyComplete,
    /// The user finished before reading the request body: drain it.
    BodyDiscard,
    /// The user completed the transaction while its answer was queued.
    TxnCompleting,
    /// The transaction completed.
    TxnCompleted,
    /// Writable after the completion, with buffered tx drained.
    TxnDrained,
    /// Serving a file began.
    FileBegin,
    /// A read of the file was handed to a worker.
    FileReadQueued,
    /// The worker's read of the file came back.
    FileReadDone,
    /// The file was sent.
    FileComplete,
    /// An h1 client's tcp is up, before its tls.
    SocketConnected,
    /// A client request was queued behind another connection.
    Queued,
    /// A client connection issues a request.
    ReqIssue,
    /// The request headers went, and no body follows.
    ReqHdrsSent,
    /// The request headers went, and a body follows.
    ReqHdrsSentBody,
    /// The request body went.
    ReqBodySent,
    /// A 1xx interim response arrived.
    RespInterim,
    /// A new connection is a server's.
    ServerSide,
    /// A connection was adopted, without tls.
    Adopted,
    /// A connection was adopted, to accept tls on.
    AdoptedTls,
    /// A client connection was bound to its role.
    ClientBind,
    /// A client restarts on a new connection: a redirect, a retry, a
    /// fallback.
    Restart,
    /// The connection became ws: a server's upgrade decision, a client's
    /// 101.
    WsUpgraded,
    /// A client's response headers arrived.
    RespHdrs,
    /// The connection became a raw socket.
    RawUpgraded,
    /// A client's dns lookup started.
    DnsStart,
    /// A client's dns lookup is to be tried again.
    DnsRetry,
    /// A client's connect started, to the first or the next address.
    ConnectStart,
    /// An http CONNECT went to the proxy.
    ProxyConnectSent,
    /// The socks5 greeting went.
    SocksGreetingSent,
    /// The socks5 authentication went.
    SocksAuthSent,
    /// The socks5 connect request went.
    SocksConnectSent,
    /// A client's tls handshake started.
    TlsStart,
    /// A server's tls accept is in progress.
    TlsAcceptPending,
    /// A server's tls accept was handed to a worker.
    TlsAcceptQueued,
    /// A client's connect failed, and the user was told.
    ConnFailed,
    /// A client is being retargeted, and will restart.
    Retarget,
    /// We started a ws close, and have a CLOSE to send.
    WsCloseInitiated,
    /// Our ws CLOSE went.
    WsCloseSent,
    /// The peer's ws CLOSE arrived.
    WsPeerClose,
    /// The close was entered.
    CloseEntered,
    /// The close drains buffered tx first.
    CloseFlush,
    /// A live connection is to close once its buffered tx drains.
    CloseWhenFlushed,
    /// A server half-closed, and waits for the peer's FIN.
    CloseStaged,
    /// The socket is gone.
    SocketGone,
    /// The user was told the connection closed.
    UserTold,
}

impl Event {
    /// Every event.
    pub const ALL: [Self; 50] = [
        Self::TransportUp,
        Self::ReqHdrsComplete,
        Self::ReqPlainHttp,
        Self::ActionBegin,
        Self::BodyBegin,
        Self::BodyComplete,
        Self::BodyDiscard,
        Self::TxnCompleting,
        Self::TxnCompleted,
        Self::TxnDrained,
        Self::FileBegin,
        Self::FileReadQueued,
        Self::FileReadDone,
        Self::FileComplete,
        Self::SocketConnected,
        Self::Queued,
        Self::ReqIssue,
        Self::ReqHdrsSent,
        Self::ReqHdrsSentBody,
        Self::ReqBodySent,
        Self::RespInterim,
        Self::ServerSide,
        Self::Adopted,
        Self::AdoptedTls,
        Self::ClientBind,
        Self::Restart,
        Self::WsUpgraded,
        Self::RespHdrs,
        Self::RawUpgraded,
        Self::DnsStart,
        Self::DnsRetry,
        Self::ConnectStart,
        Self::ProxyConnectSent,
        Self::SocksGreetingSent,
        Self::SocksAuthSent,
        Self::SocksConnectSent,
        Self::TlsStart,
        Self::TlsAcceptPending,
        Self::TlsAcceptQueued,
        Self::ConnFailed,
        Self::Retarget,
        Self::WsCloseInitiated,
        Self::WsCloseSent,
        Self::WsPeerClose,
        Self::CloseEntered,
        Self::CloseFlush,
        Self::CloseWhenFlushed,
        Self::CloseStaged,
        Self::SocketGone,
        Self::UserTold,
    ];

    /// The event's name, as C's trace writes it after `ev=`.
    ///
    /// ```
    /// use npro_core::state::Event;
    ///
    /// assert_eq!(Event::ReqHdrsComplete.name(), "REQ_HDRS_COMPLETE");
    /// ```
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TransportUp => "TRANSPORT_UP",
            Self::ReqHdrsComplete => "REQ_HDRS_COMPLETE",
            Self::ReqPlainHttp => "REQ_PLAIN_HTTP",
            Self::ActionBegin => "ACTION_BEGIN",
            Self::BodyBegin => "BODY_BEGIN",
            Self::BodyComplete => "BODY_COMPLETE",
            Self::BodyDiscard => "BODY_DISCARD",
            Self::TxnCompleting => "TXN_COMPLETING",
            Self::TxnCompleted => "TXN_COMPLETED",
            Self::TxnDrained => "TXN_DRAINED",
            Self::FileBegin => "FILE_BEGIN",
            Self::FileReadQueued => "FILE_READ_QUEUED",
            Self::FileReadDone => "FILE_READ_DONE",
            Self::FileComplete => "FILE_COMPLETE",
            Self::SocketConnected => "SOCKET_CONNECTED",
            Self::Queued => "QUEUED",
            Self::ReqIssue => "REQ_ISSUE",
            Self::ReqHdrsSent => "REQ_HDRS_SENT",
            Self::ReqHdrsSentBody => "REQ_HDRS_SENT_BODY",
            Self::ReqBodySent => "REQ_BODY_SENT",
            Self::RespInterim => "RESP_INTERIM",
            Self::ServerSide => "SERVER_SIDE",
            Self::Adopted => "ADOPTED",
            Self::AdoptedTls => "ADOPTED_TLS",
            Self::ClientBind => "CLIENT_BIND",
            Self::Restart => "RESTART",
            Self::WsUpgraded => "WS_UPGRADED",
            Self::RespHdrs => "RESP_HDRS",
            Self::RawUpgraded => "RAW_UPGRADED",
            Self::DnsStart => "DNS_START",
            Self::DnsRetry => "DNS_RETRY",
            Self::ConnectStart => "CONNECT_START",
            Self::ProxyConnectSent => "PROXY_CONNECT_SENT",
            Self::SocksGreetingSent => "SOCKS_GREETING_SENT",
            Self::SocksAuthSent => "SOCKS_AUTH_SENT",
            Self::SocksConnectSent => "SOCKS_CONNECT_SENT",
            Self::TlsStart => "TLS_START",
            Self::TlsAcceptPending => "TLS_ACCEPT_PENDING",
            Self::TlsAcceptQueued => "TLS_ACCEPT_QUEUED",
            Self::ConnFailed => "CONN_FAILED",
            Self::Retarget => "RETARGET",
            Self::WsCloseInitiated => "WS_CLOSE_INITIATED",
            Self::WsCloseSent => "WS_CLOSE_SENT",
            Self::WsPeerClose => "WS_PEER_CLOSE",
            Self::CloseEntered => "CLOSE_ENTERED",
            Self::CloseFlush => "CLOSE_FLUSH",
            Self::CloseWhenFlushed => "CLOSE_WHEN_FLUSHED",
            Self::CloseStaged => "CLOSE_STAGED",
            Self::SocketGone => "SOCKET_GONE",
            Self::UserTold => "USER_TOLD",
        }
    }
}
