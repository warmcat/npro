//! The event table: what an event does, by role, side and state.
//!
//! This is the stage-1 part of `lws_wsi_event_edges[]` in C's
//! `lib/sansio/wsi-state.c`: the rows whose role and target are roles npro
//! has.  The rows are in C's order, grouped by event, and the first that
//! matches wins, as in C.  A row matching on `_` for a role or side is C's
//! `"*"`, and on `_` for the state is C's `ANY`.
//!
//! The site's role, when it gives one, is C's `ops` argument: a row that
//! takes it (C's `"?"`) matches only when one is given, and one that names
//! a role matches only when none is given or the site's is that role.  Every
//! other row matches only when none is given.

use super::{Close, Event, Live, Role, Side, State, Transport};

/// What a row does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum To {
    /// Sets the live state, or the carrier's while it handshakes.
    Live(Live),
    /// Sets the transport machine, over whatever the others are doing.
    Transport(Transport),
    /// Sets the close machine, over whatever the others are doing.
    Close(Close),
    /// Changes the role or side, and starts the machines from `state`.
    Role {
        role: RoleTo,
        side: SideTo,
        state: RoleState,
    },
}

/// The role a role change leads to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RoleTo {
    /// As it was.
    Keep,
    /// The one the site gave: C's `"?"`.
    Site,
    /// This one.
    Named(Role),
}

/// The side a role change leads to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SideTo {
    /// As it was.
    Keep,
    /// This one.
    Set(Side),
}

/// Where the machines start after a role change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RoleState {
    /// A transport phase, over an unconnected live state.
    Transport(Transport),
    /// A live state; unconnected is a restart on a new connection.
    Live(Live),
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "a row's result: Some is the row, as None is no row"
)]
const fn live(l: Live) -> Option<To> {
    Some(To::Live(l))
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "a row's result: Some is the row, as None is no row"
)]
const fn transport(t: Transport) -> Option<To> {
    Some(To::Transport(t))
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "a row's result: Some is the row, as None is no row"
)]
const fn close(c: Close) -> Option<To> {
    Some(To::Close(c))
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "a row's result: Some is the row, as None is no row"
)]
const fn change(role: RoleTo, side: SideTo, state: RoleState) -> Option<To> {
    Some(To::Role { role, side, state })
}

/// The row for `ev` from `role`, `side` and the reported state `from`, with
/// the site's role `site_role`, if it gave one.
#[expect(
    clippy::too_many_lines,
    reason = "one table, kept whole and in C's order so it reads against C's"
)]
#[expect(
    clippy::match_same_arms,
    reason = "a row per C row, even where two lead to the same place"
)]
pub(super) const fn row(
    role: Role,
    side: Side,
    from: State,
    ev: Event,
    site_role: Option<Role>,
) -> Option<To> {
    use Side::{Client, Server};
    use State as St;

    match ev {
        // the transport finished: a server starts on the request, an h1
        // client on sending one, the rest are up
        Event::TransportUp => match (role, side, from, site_role) {
            (
                Role::H1,
                Client,
                St::Unconnected
                | St::WaitingSsl
                | St::WaitingConnect
                | St::H1cIssueHandshake
                | St::H1cIssueHandshake2,
                None,
            ) => live(Live::H1cIssueHandshake2),
            (Role::H1, Client, St::H2WaitingToSendHeaders, None) => {
                live(Live::H2WaitingToSendHeaders)
            }
            (
                Role::RawSkt,
                Client,
                St::WaitingConnect
                | St::WaitingSsl
                | St::WaitingSocksConnectReply
                | St::WaitingProxyReply,
                None,
            ) => live(Live::Established),
            (Role::H1, Server, St::SslAckPending | St::AwaitingSslAccept | St::SslInit, None) => {
                live(Live::Headers)
            }
            (_, Server, St::SslAckPending | St::AwaitingSslAccept | St::SslInit, None) => {
                live(Live::Established)
            }
            // the non-tls fallback established the connection before the
            // accept path reports the transport up
            (_, Server, St::Established, None) => live(Live::Established),
            _ => None,
        },

        // an h1 client's tcp is up before its tls; a socks or CONNECT
        // tunnel coming up is the socket connecting, for the protocol
        Event::SocketConnected => match (role, side, from, site_role) {
            (
                Role::H1,
                Client,
                St::WaitingConnect | St::WaitingSocksConnectReply | St::WaitingProxyReply,
                None,
            ) => live(Live::H1cIssueHandshake),
            (Role::H1, Client, St::H1cIssueHandshake2, None) => live(Live::H1cIssueHandshake2),
            _ => None,
        },

        // a client request queued on, or issued by, a connection
        Event::Queued => match (side, from, site_role) {
            (Client, St::Unconnected | St::H1cIssueHandshake2, None) => {
                live(Live::H2WaitingToSendHeaders)
            }
            _ => None,
        },
        Event::ReqIssue => match (role, side, from, site_role) {
            (
                Role::H1,
                Client,
                St::H2WaitingToSendHeaders | St::Established | St::Idling | St::WaitingServerReply,
                None,
            ) => live(Live::H1cIssueHandshake2),
            _ => None,
        },

        // the request goes out, then its response is pending
        Event::ReqHdrsSent => match (role, side, from, site_role) {
            (
                Role::H1,
                Client,
                St::WaitingSsl
                | St::WaitingConnect
                | St::H1cIssueHandshake
                | St::H1cIssueHandshake2,
                None,
            ) => live(Live::WaitingServerReply),
            _ => None,
        },
        Event::ReqHdrsSentBody => match (role, side, from, site_role) {
            (
                Role::H1,
                Client,
                St::WaitingSsl
                | St::WaitingConnect
                | St::H1cIssueHandshake
                | St::H1cIssueHandshake2,
                None,
            ) => live(Live::IssueHttpBody),
            _ => None,
        },
        Event::ReqBodySent => match (side, from, site_role) {
            (Client, St::IssueHttpBody, None) => live(Live::WaitingServerReply),
            _ => None,
        },
        // a ws client takes no response headers but the 101's: it is still
        // waiting
        Event::RespInterim => match (role, side, from, site_role) {
            (Role::H1, Client, St::Established | St::WaitingServerReply, None) => {
                live(Live::WaitingServerReply)
            }
            _ => None,
        },

        // the response is done and the client idles; the h1 server's
        // transaction ends, from wherever it had got to
        Event::TxnCompleted => match (role, side, from, site_role) {
            (Role::H1, Client, St::Established, None) => live(Live::Idling),
            (_, Client, St::Idling, None) => live(Live::Idling),
            (Role::H1, Server, St::TxnCompleting, None) => live(Live::TxnCompleted),
            (
                Role::H1,
                Server,
                St::Established
                | St::Body
                | St::DiscardBody
                | St::DoingTransaction
                | St::H1Upgrade
                | St::TxnCompleted
                | St::IssuingFile
                | St::AwaitingFileRead,
                None,
            ) => live(Live::TxnCompleted),
            _ => None,
        },

        // request headers: the h1 server decides on the upgrade
        Event::ReqHdrsComplete => match (role, side, from, site_role) {
            (Role::H1, Server, St::Headers | St::Established, None) => live(Live::H1Upgrade),
            _ => None,
        },
        Event::ReqPlainHttp => match (role, side, from, site_role) {
            (Role::H1, Server, St::H1Upgrade, None) => live(Live::Established),
            _ => None,
        },

        // acting on the request
        Event::ActionBegin => match (role, side, from, site_role) {
            (Role::H1, Server, St::Established, None) => live(Live::DoingTransaction),
            _ => None,
        },

        // the request body
        Event::BodyBegin => match (role, side, from, site_role) {
            (Role::H1, Server, St::Established | St::DoingTransaction, None) => live(Live::Body),
            _ => None,
        },
        // an h1 body is complete before its answer is: the next request,
        // pipelined behind it, waits for the transaction
        Event::BodyComplete => match (role, side, from, site_role) {
            (Role::H1, Server, St::Body, None) => live(Live::DoingTransaction),
            _ => None,
        },
        // the user completed the transaction before reading the body, maybe
        // with a read of a file out on a worker, reaped by the completion
        Event::BodyDiscard => match (role, side, from, site_role) {
            (
                Role::H1,
                Server,
                St::Body
                | St::Established
                | St::DoingTransaction
                | St::H1Upgrade
                | St::IssuingFile
                | St::AwaitingFileRead
                | St::TxnCompleting,
                None,
            ) => live(Live::DiscardBody),
            _ => None,
        },

        // the user completed the transaction with its answer still queued:
        // completion waits for that to go
        Event::TxnCompleting => match (role, side, from, site_role) {
            (
                Role::H1,
                Server,
                St::Established
                | St::Body
                | St::DiscardBody
                | St::DoingTransaction
                | St::H1Upgrade
                | St::TxnCompleted
                | St::IssuingFile
                | St::TxnCompleting
                | St::AwaitingFileRead,
                None,
            ) => live(Live::TxnCompleting),
            _ => None,
        },
        // and the connection is reused for the next request
        Event::TxnDrained => match (role, side, from, site_role) {
            (Role::H1, Server, St::TxnCompleted, None) => live(Live::Headers),
            _ => None,
        },

        // serving a file: from the request, its body's completion, or the
        // upgrade's confirmation
        Event::FileBegin => match (role, side, from, site_role) {
            (_, Server, St::Established | St::DoingTransaction | St::Body, None) => {
                live(Live::IssuingFile)
            }
            (Role::H1, Server, St::H1Upgrade, None) => live(Live::IssuingFile),
            _ => None,
        },
        Event::FileReadQueued => match (side, from, site_role) {
            (Server, St::IssuingFile, None) => live(Live::AwaitingFileRead),
            _ => None,
        },
        Event::FileReadDone => match (side, from, site_role) {
            (Server, St::AwaitingFileRead, None) => live(Live::IssuingFile),
            _ => None,
        },
        Event::FileComplete => match (side, from, site_role) {
            (Server, St::IssuingFile, None) => live(Live::Established),
            _ => None,
        },

        // ---- role changes ----

        // birth on a server, adoption, the client bind, a restart
        Event::ServerSide => match (role, side, from, site_role) {
            (Role::None, Side::Unset, St::Unconnected, None) => change(
                RoleTo::Keep,
                SideTo::Set(Server),
                RoleState::Live(Live::Unconnected),
            ),
            _ => None,
        },
        Event::AdoptedTls => match (from, site_role) {
            (St::Unconnected, Some(_)) => change(
                RoleTo::Site,
                SideTo::Keep,
                RoleState::Transport(Transport::SslInit),
            ),
            _ => None,
        },
        Event::Adopted => match (from, site_role) {
            (St::Unconnected, None | Some(Role::H1)) => change(
                RoleTo::Named(Role::H1),
                SideTo::Keep,
                RoleState::Live(Live::Headers),
            ),
            (St::Unconnected, Some(_)) => change(
                RoleTo::Site,
                SideTo::Keep,
                RoleState::Live(Live::Established),
            ),
            _ => None,
        },
        Event::ClientBind => match (from, site_role) {
            (St::Unconnected, Some(_)) => change(
                RoleTo::Site,
                SideTo::Set(Client),
                RoleState::Live(Live::Unconnected),
            ),
            _ => None,
        },
        Event::Restart => match (side, site_role) {
            (Client, Some(_)) => change(
                RoleTo::Site,
                SideTo::Set(Client),
                RoleState::Live(Live::Unconnected),
            ),
            _ => None,
        },

        // ws, on a server from the upgrade decision, on a client from the
        // 101
        Event::WsUpgraded => match (role, side, from, site_role) {
            (Role::H1, Server, St::H1Upgrade, None | Some(Role::Ws))
            | (Role::H1, Client, St::WaitingServerReply, None | Some(Role::Ws)) => change(
                RoleTo::Named(Role::Ws),
                SideTo::Keep,
                RoleState::Live(Live::Established),
            ),
            _ => None,
        },

        // a client's response headers; a server may answer before the
        // request body is finished (401, 413...)
        Event::RespHdrs => match (side, from, site_role) {
            (Client, St::WaitingServerReply | St::IssueHttpBody, None) => live(Live::Established),
            _ => None,
        },

        // raw: from the request, the upgrade, the non-tls fallback on a tls
        // listener, a kept-alive connection or a listener already raw; an h1
        // client's own raw upgrade
        Event::RawUpgraded => match (role, side, from, site_role) {
            (
                _,
                Server,
                St::Headers | St::H1Upgrade | St::SslInit | St::SslAckPending | St::Established,
                Some(_),
            ) => change(
                RoleTo::Site,
                SideTo::Keep,
                RoleState::Live(Live::Established),
            ),
            (
                Role::H1,
                Client,
                St::Established | St::WaitingServerReply,
                None | Some(Role::RawSkt),
            ) => change(
                RoleTo::Named(Role::RawSkt),
                SideTo::Keep,
                RoleState::Live(Live::Established),
            ),
            _ => None,
        },

        // ---- the transport machine ----
        Event::DnsStart => match (side, from, site_role) {
            (Client, St::Unconnected, None) => transport(Transport::WaitingDns),
            _ => None,
        },
        Event::DnsRetry => match (side, from, site_role) {
            (Client, St::WaitingDns, None) => transport(Transport::None),
            _ => None,
        },
        // to the first address, the next one, or tcp after quic
        Event::ConnectStart => match (side, from, site_role) {
            (
                Client,
                St::Unconnected | St::WaitingDns | St::WaitingConnect | St::WaitingSsl,
                None,
            ) => transport(Transport::WaitingConnect),
            _ => None,
        },
        Event::ProxyConnectSent => match (side, from, site_role) {
            (Client, St::WaitingConnect, None) => transport(Transport::WaitingProxyReply),
            _ => None,
        },
        Event::SocksGreetingSent => match (side, from, site_role) {
            (Client, St::WaitingConnect, None) => transport(Transport::WaitingSocksGreetingReply),
            _ => None,
        },
        Event::SocksAuthSent => match (side, from, site_role) {
            (Client, St::WaitingSocksGreetingReply, None) => {
                transport(Transport::WaitingSocksAuthReply)
            }
            _ => None,
        },
        Event::SocksConnectSent => match (side, from, site_role) {
            (Client, St::WaitingSocksGreetingReply | St::WaitingSocksAuthReply, None) => {
                transport(Transport::WaitingSocksConnectReply)
            }
            _ => None,
        },
        Event::TlsStart => match (role, side, from, site_role) {
            (
                _,
                Client,
                St::WaitingConnect
                | St::WaitingProxyReply
                | St::WaitingSocksConnectReply
                | St::H1cIssueHandshake
                | St::WaitingSsl,
                None,
            ) => transport(Transport::WaitingSsl),
            // STARTTLS: an established raw client starts tls inside its
            // protocol
            (Role::RawSkt, Client, St::Established, None) => transport(Transport::WaitingSsl),
            _ => None,
        },
        Event::TlsAcceptPending => match (side, from, site_role) {
            (Server, St::SslInit | St::SslAckPending | St::AwaitingSslAccept, None) => {
                transport(Transport::SslAckPending)
            }
            _ => None,
        },
        Event::TlsAcceptQueued => match (side, from, site_role) {
            (Server, St::SslInit | St::SslAckPending, None) => {
                transport(Transport::AwaitingSslAccept)
            }
            _ => None,
        },
        Event::ConnFailed => match (side, site_role) {
            (Client, None) => transport(Transport::Failed),
            _ => None,
        },
        Event::Retarget => match (side, site_role) {
            (Client, None) => transport(Transport::Restarting),
            _ => None,
        },

        // ---- the close machine: the polite ws close is specific, the rest
        // can come from anywhere ----
        Event::WsCloseInitiated => match (role, from, site_role) {
            (Role::Ws, St::Established, None) => close(Close::WaitingToSendClose),
            _ => None,
        },
        Event::WsCloseSent => match (role, from, site_role) {
            (Role::Ws, St::WaitingToSendClose, None) => close(Close::AwaitingCloseAck),
            _ => None,
        },
        // the peer's CLOSE, perhaps beating the one we were about to send:
        // answer his and drop ours
        Event::WsPeerClose => match (role, from, site_role) {
            (Role::Ws, St::Established | St::WaitingToSendClose, None) => {
                close(Close::ReturnedClose)
            }
            _ => None,
        },
        // a flush the live connection had begun is now the close's own, else
        // the close has begun with nothing to wait for
        Event::CloseEntered => match (from, site_role) {
            (St::FlushingBeforeClose, None) => close(Close::FlushingBeforeClose),
            (_, None) => close(Close::Closing),
            _ => None,
        },
        Event::CloseFlush => match site_role {
            None => close(Close::FlushingBeforeClose),
            Some(_) => None,
        },
        Event::CloseWhenFlushed => match site_role {
            None => close(Close::CloseWhenFlushed),
            Some(_) => None,
        },
        Event::CloseStaged => match (side, site_role) {
            (Server, None) => close(Close::Shutdown),
            _ => None,
        },
        Event::SocketGone => match site_role {
            None => close(Close::DeadSocket),
            Some(_) => None,
        },
        Event::UserTold => match (from, site_role) {
            (St::DeadSocket, None) => close(Close::UserTold),
            _ => None,
        },
    }
}
