//! The connection state machines: transport, carrier, transaction and
//! close, and the event table that drives them.
//!
//! This is C's `lib/sansio/wsi-state.c`, and its specification is C's
//! `READMEs/README.wsi-state-machines.md`.  A connection's state is four
//! machines, each with its own enum:
//!
//! | machine | what it tracks |
//! |---|---|
//! | [`Transport`] | getting a socket to the peer: dns, connect, proxy or socks, the tls handshake or accept |
//! | [`Carrier`] | the protocol handshake on top of the socket: an h1 client's first request and reply, the h1 server's upgrade decision |
//! | [`Live`] | the transaction: the http request and response, its body and file phases, or `Established` for roles without transactions |
//! | [`Close`] | the polite ws close, draining buffered tx, the staged shutdown, dead |
//!
//! with the connection's [`Role`] and [`Side`], and whether its socket is
//! known [unusable](Socket).
//!
//! Nothing sets a machine directly.  Code driving a connection reports what
//! happened as an [`Event`], and [`Machines::event`] looks up where that
//! leads, by role, side and the state the connection reports
//! ([`Machines::state`]): one row of C's event table per edge, in C's
//! order, the first match winning.  An event with no row is refused, as is
//! anything C's `LWS_WITH_STATE_CHECK` would abort on: a close going back
//! to an earlier phase, a live state set while the connection restarts,
//! and a broken invariant.  The machines are unchanged by a refusal.
//!
//! Each change gives an [`Edge`], whose `Display` is the line C's
//! `LWS_WITH_STATE_TRACE` writes for it, less the connection's tag.  npro's
//! tests compare these with the edges C's test suite takes.
//!
//! These are the machines of the roles npro has: h1 client and server, ws,
//! and raw sockets.  The rows, states and events of h2, h3, quic, mqtt and
//! webtransport arrive with those roles.
//!
//! ```
//! use npro_core::state::{Event, Machines, Role, State};
//!
//! // an h1 server connection: born, made a server's, adopted
//! let mut m = Machines::new();
//! m.event(Event::ServerSide)?;
//! m.event_as(Event::Adopted, Role::H1)?;
//! assert_eq!(m.state(), State::Headers);
//!
//! // a request with an Upgrade: header, which becomes ws
//! let e = m.event(Event::ReqHdrsComplete)?;
//! assert_eq!(
//!     e.to_string(),
//!     "LRS h1/S:HEADERS -> h1/S:H1_UPGRADE set_state ev=REQ_HDRS_COMPLETE"
//! );
//! m.event(Event::WsUpgraded)?;
//! assert_eq!((m.role(), m.state()), (Role::Ws, State::Established));
//!
//! // a ws connection cannot be told the request body is complete
//! assert!(m.event(Event::BodyComplete).is_err());
//! # Ok::<(), npro_core::state::Refused>(())
//! ```

mod event;
mod table;

use core::fmt;

pub use event::Event;

use table::{RoleTo, SideTo, To};

/// What a connection is: which protocol drives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// No role yet: a connection just born.
    None,
    /// http/1.
    H1,
    /// websockets, after the upgrade.
    Ws,
    /// A raw socket: bytes in and out, no protocol.
    RawSkt,
}

impl Role {
    /// Every role.
    pub const ALL: [Self; 4] = [Self::None, Self::H1, Self::Ws, Self::RawSkt];

    /// The role's name, as C's trace writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "(none)",
            Self::H1 => "h1",
            Self::Ws => "ws",
            Self::RawSkt => "raw-skt",
        }
    }
}

/// Which side of the connection we are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// Not decided yet: a connection just born.
    Unset,
    /// We connected to the peer.
    Client,
    /// The peer connected to us.
    Server,
}

impl Side {
    /// Every side.
    pub const ALL: [Self; 3] = [Self::Unset, Self::Client, Self::Server];

    /// The side's letter, as C's trace writes it.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::Unset => '-',
            Self::Client => 'C',
            Self::Server => 'S',
        }
    }
}

/// Whether the connection's socket can still be used.
///
/// An attribute of the connection rather than a machine: it survives
/// changes of state and role, except a client's restart onto a new
/// connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Socket {
    /// As far as anyone knows, the socket works.
    Usable,
    /// The socket is known dead: the close takes the abortive path, and
    /// never the polite one.
    Unusable,
}

/// The transport machine: getting a socket to the peer.
///
/// It ends implicitly: setting any live or carrier state clears it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Not setting up a transport.
    None,
    /// A client is looking up the peer's address.
    WaitingDns,
    /// A client is connecting.
    WaitingConnect,
    /// A client sent an http CONNECT to a proxy, and waits for its reply.
    WaitingProxyReply,
    /// A client's tls handshake is in progress.
    WaitingSsl,
    /// A client sent the socks5 greeting.
    WaitingSocksGreetingReply,
    /// A client sent the socks5 connect request.
    WaitingSocksConnectReply,
    /// A client sent socks5 authentication.
    WaitingSocksAuthReply,
    /// A server's tls accept has not started.
    SslInit,
    /// A server's tls accept is in progress.
    SslAckPending,
    /// A server's tls accept is out on a worker.
    AwaitingSslAccept,
    /// A client's connect failed, and the user was told: the close must not
    /// tell him again.
    Failed,
    /// A client is being retargeted, and will restart on a new connection.
    Restarting,
}

/// The carrier machine: the protocol handshake between the transport and
/// the first transaction.
///
/// Once the first transaction state is set it is `Established`, and the
/// same names set again are per-transaction phases of the [`Live`] machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Carrier {
    /// The handshake has not started.
    None,
    /// An h1 client, before tls.
    H1cIssueHandshake,
    /// An h1 client, sending its first request.
    H1cIssueHandshake2,
    /// A client waiting for its first response's headers.
    WaitingServerReply,
    /// A client request queued behind another connection.
    H2WaitingToSendHeaders,
    /// An h1 server deciding on an upgrade.
    H1Upgrade,
    /// The handshake is done: the transaction machine has begun.
    Established,
}

/// The live machine: the transaction, or `Established` for roles that have
/// none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Live {
    /// Nothing yet.
    Unconnected,
    /// An h1 client, before tls.
    H1cIssueHandshake,
    /// An h1 client sending a request.
    H1cIssueHandshake2,
    /// A client request is out, its response's headers pending.
    WaitingServerReply,
    /// A client request queued behind another connection.
    H2WaitingToSendHeaders,
    /// An h1 server deciding on an upgrade a request asked for.
    H1Upgrade,
    /// A client's request headers went, and it is sending the body.
    IssueHttpBody,
    /// A server idle between requests, or reading one's headers.
    Headers,
    /// A server acting on a request; a client receiving a response; a role
    /// without transactions, in use.
    Established,
    /// A server's action is in progress, or a request body is complete and
    /// its answer is to come.
    DoingTransaction,
    /// A request body is being delivered.
    Body,
    /// A request body is being drained, unread.
    DiscardBody,
    /// A file is being served.
    IssuingFile,
    /// A read of the file being served is out on a worker.
    AwaitingFileRead,
    /// The transaction was completed while its answer was still queued.
    TxnCompleting,
    /// The transaction completed; waiting for buffered tx to drain.
    TxnCompleted,
    /// A client with nothing in flight, kept for the next request.
    Idling,
}

/// The close machine.  It only goes forwards: the variants are in order,
/// and no event takes a connection to an earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Close {
    /// Not closing.
    None,
    /// A live connection closes once its buffered tx has drained.
    CloseWhenFlushed,
    /// The close was entered, with nothing yet to wait for.
    Closing,
    /// We started a ws close and have a CLOSE to send.
    WaitingToSendClose,
    /// The peer's ws CLOSE arrived first, and we answer it.
    ReturnedClose,
    /// Our ws CLOSE went, and we wait for the peer's.
    AwaitingCloseAck,
    /// The close drains buffered tx first.
    FlushingBeforeClose,
    /// A server half-closed, and waits for the peer's FIN.
    Shutdown,
    /// The socket is gone.
    DeadSocket,
    /// The socket is gone, and the user was told.
    UserTold,
}

/// The state a connection reports: one name for what it is doing now.
///
/// The close machine if one is in progress, else the transport machine,
/// else the carrier handshake, else the live machine: C's `lwsi_state()`,
/// whose names these are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[expect(
    missing_docs,
    reason = "each variant is the like-named state of the machine it reports"
)]
pub enum State {
    Unconnected,
    WaitingDns,
    WaitingConnect,
    WaitingProxyReply,
    WaitingSsl,
    WaitingSocksGreetingReply,
    WaitingSocksConnectReply,
    WaitingSocksAuthReply,
    SslInit,
    SslAckPending,
    AwaitingSslAccept,
    H1Upgrade,
    WaitingServerReply,
    H2WaitingToSendHeaders,
    TxnCompleted,
    Idling,
    H1cIssueHandshake,
    H1cIssueHandshake2,
    IssueHttpBody,
    IssuingFile,
    Headers,
    Body,
    DiscardBody,
    Established,
    DoingTransaction,
    WaitingToSendClose,
    ReturnedClose,
    AwaitingCloseAck,
    FlushingBeforeClose,
    Shutdown,
    DeadSocket,
    AwaitingFileRead,
    TxnCompleting,
}

impl State {
    /// Every state.
    pub const ALL: [Self; 33] = [
        Self::Unconnected,
        Self::WaitingDns,
        Self::WaitingConnect,
        Self::WaitingProxyReply,
        Self::WaitingSsl,
        Self::WaitingSocksGreetingReply,
        Self::WaitingSocksConnectReply,
        Self::WaitingSocksAuthReply,
        Self::SslInit,
        Self::SslAckPending,
        Self::AwaitingSslAccept,
        Self::H1Upgrade,
        Self::WaitingServerReply,
        Self::H2WaitingToSendHeaders,
        Self::TxnCompleted,
        Self::Idling,
        Self::H1cIssueHandshake,
        Self::H1cIssueHandshake2,
        Self::IssueHttpBody,
        Self::IssuingFile,
        Self::Headers,
        Self::Body,
        Self::DiscardBody,
        Self::Established,
        Self::DoingTransaction,
        Self::WaitingToSendClose,
        Self::ReturnedClose,
        Self::AwaitingCloseAck,
        Self::FlushingBeforeClose,
        Self::Shutdown,
        Self::DeadSocket,
        Self::AwaitingFileRead,
        Self::TxnCompleting,
    ];

    /// The state's name, as C's trace writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unconnected => "UNCONNECTED",
            Self::WaitingDns => "WAITING_DNS",
            Self::WaitingConnect => "WAITING_CONNECT",
            Self::WaitingProxyReply => "WAITING_PROXY_REPLY",
            Self::WaitingSsl => "WAITING_SSL",
            Self::WaitingSocksGreetingReply => "WAITING_SOCKS_GREETING_REPLY",
            Self::WaitingSocksConnectReply => "WAITING_SOCKS_CONNECT_REPLY",
            Self::WaitingSocksAuthReply => "WAITING_SOCKS_AUTH_REPLY",
            Self::SslInit => "SSL_INIT",
            Self::SslAckPending => "SSL_ACK_PENDING",
            Self::AwaitingSslAccept => "AWAITING_SSL_ACCEPT",
            Self::H1Upgrade => "H1_UPGRADE",
            Self::WaitingServerReply => "WAITING_SERVER_REPLY",
            Self::H2WaitingToSendHeaders => "H2_WAITING_TO_SEND_HEADERS",
            Self::TxnCompleted => "TXN_COMPLETED",
            Self::Idling => "IDLING",
            Self::H1cIssueHandshake => "H1C_ISSUE_HANDSHAKE",
            Self::H1cIssueHandshake2 => "H1C_ISSUE_HANDSHAKE2",
            Self::IssueHttpBody => "ISSUE_HTTP_BODY",
            Self::IssuingFile => "ISSUING_FILE",
            Self::Headers => "HEADERS",
            Self::Body => "BODY",
            Self::DiscardBody => "DISCARD_BODY",
            Self::Established => "ESTABLISHED",
            Self::DoingTransaction => "DOING_TRANSACTION",
            Self::WaitingToSendClose => "WAITING_TO_SEND_CLOSE",
            Self::ReturnedClose => "RETURNED_CLOSE",
            Self::AwaitingCloseAck => "AWAITING_CLOSE_ACK",
            Self::FlushingBeforeClose => "FLUSHING_BEFORE_CLOSE",
            Self::Shutdown => "SHUTDOWN",
            Self::DeadSocket => "DEAD_SOCKET",
            Self::AwaitingFileRead => "AWAITING_FILE_READ",
            Self::TxnCompleting => "TXN_COMPLETING",
        }
    }
}

impl Live {
    /// The carrier phase a live state names, if it names one: set while
    /// the carrier is not established, it is the carrier's.
    const fn carrier(self) -> Option<Carrier> {
        match self {
            Self::H1cIssueHandshake => Some(Carrier::H1cIssueHandshake),
            Self::H1cIssueHandshake2 => Some(Carrier::H1cIssueHandshake2),
            Self::WaitingServerReply => Some(Carrier::WaitingServerReply),
            Self::H2WaitingToSendHeaders => Some(Carrier::H2WaitingToSendHeaders),
            Self::H1Upgrade => Some(Carrier::H1Upgrade),
            Self::Unconnected
            | Self::IssueHttpBody
            | Self::Headers
            | Self::Established
            | Self::DoingTransaction
            | Self::Body
            | Self::DiscardBody
            | Self::IssuingFile
            | Self::AwaitingFileRead
            | Self::TxnCompleting
            | Self::TxnCompleted
            | Self::Idling => None,
        }
    }

    const fn state(self) -> State {
        match self {
            Self::Unconnected => State::Unconnected,
            Self::H1cIssueHandshake => State::H1cIssueHandshake,
            Self::H1cIssueHandshake2 => State::H1cIssueHandshake2,
            Self::WaitingServerReply => State::WaitingServerReply,
            Self::H2WaitingToSendHeaders => State::H2WaitingToSendHeaders,
            Self::H1Upgrade => State::H1Upgrade,
            Self::IssueHttpBody => State::IssueHttpBody,
            Self::Headers => State::Headers,
            Self::Established => State::Established,
            Self::DoingTransaction => State::DoingTransaction,
            Self::Body => State::Body,
            Self::DiscardBody => State::DiscardBody,
            Self::IssuingFile => State::IssuingFile,
            Self::AwaitingFileRead => State::AwaitingFileRead,
            Self::TxnCompleting => State::TxnCompleting,
            Self::TxnCompleted => State::TxnCompleted,
            Self::Idling => State::Idling,
        }
    }
}

impl Transport {
    /// The state it reports, if it reports one: a failed or restarting
    /// client reports its live state, marked.
    const fn state(self) -> Option<State> {
        match self {
            Self::WaitingDns => Some(State::WaitingDns),
            Self::WaitingConnect => Some(State::WaitingConnect),
            Self::WaitingProxyReply => Some(State::WaitingProxyReply),
            Self::WaitingSsl => Some(State::WaitingSsl),
            Self::WaitingSocksGreetingReply => Some(State::WaitingSocksGreetingReply),
            Self::WaitingSocksConnectReply => Some(State::WaitingSocksConnectReply),
            Self::WaitingSocksAuthReply => Some(State::WaitingSocksAuthReply),
            Self::SslInit => Some(State::SslInit),
            Self::SslAckPending => Some(State::SslAckPending),
            Self::AwaitingSslAccept => Some(State::AwaitingSslAccept),
            Self::Failed | Self::Restarting => Some(State::Unconnected),
            Self::None => None,
        }
    }
}

impl Carrier {
    /// The state it reports while the handshake is in progress.
    const fn state(self) -> Option<State> {
        match self {
            Self::H1cIssueHandshake => Some(State::H1cIssueHandshake),
            Self::H1cIssueHandshake2 => Some(State::H1cIssueHandshake2),
            Self::WaitingServerReply => Some(State::WaitingServerReply),
            Self::H2WaitingToSendHeaders => Some(State::H2WaitingToSendHeaders),
            Self::H1Upgrade => Some(State::H1Upgrade),
            Self::None | Self::Established => None,
        }
    }
}

impl Close {
    /// The state it reports, if it reports one: a close entered with
    /// nothing to wait for reports the live state, marked.
    const fn state(self) -> Option<State> {
        match self {
            Self::CloseWhenFlushed | Self::FlushingBeforeClose => Some(State::FlushingBeforeClose),
            Self::WaitingToSendClose => Some(State::WaitingToSendClose),
            Self::ReturnedClose => Some(State::ReturnedClose),
            Self::AwaitingCloseAck => Some(State::AwaitingCloseAck),
            Self::Shutdown => Some(State::Shutdown),
            Self::DeadSocket | Self::UserTold => Some(State::DeadSocket),
            Self::None | Self::Closing => None,
        }
    }

    /// The polite close phases, which an unusable socket never enters.
    const fn polite(self) -> bool {
        match self {
            Self::WaitingToSendClose
            | Self::ReturnedClose
            | Self::AwaitingCloseAck
            | Self::Shutdown => true,
            Self::None
            | Self::CloseWhenFlushed
            | Self::Closing
            | Self::FlushingBeforeClose
            | Self::DeadSocket
            | Self::UserTold => false,
        }
    }
}

/// Why an event was refused.  The machines are left as they were.
///
/// Each is a bug at the site that raised the event, as it is in C, where
/// `LWS_WITH_STATE_CHECK` aborts on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// No row of the event table takes this event from this role, side
    /// and state.
    NoRow,
    /// The event would take the close machine back to an earlier phase.
    CloseBackwards,
    /// A live state, while the client restarts: it has none until the
    /// restart.
    Restarting,
    /// A polite close phase, with the socket known unusable.
    UnusableSocket,
    /// A staged shutdown on a raw socket, which has no half-close to wait
    /// for.
    ShutdownRaw,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoRow => "no row for the event in this state",
            Self::CloseBackwards => "the close would go backwards",
            Self::Restarting => "a live state while restarting",
            Self::UnusableSocket => "a polite close with the socket unusable",
            Self::ShutdownRaw => "a staged shutdown on a raw socket",
        })
    }
}

impl core::error::Error for Refused {}

/// A connection's four machines, its role and side, and its socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Machines {
    role: Role,
    side: Side,
    transport: Transport,
    carrier: Carrier,
    live: Live,
    close: Close,
    socket: Socket,
}

impl Default for Machines {
    fn default() -> Self {
        Self::new()
    }
}

/// Which machine an edge changed, as C's trace names its setter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum How {
    /// The live or carrier machine.
    SetState,
    /// The transport machine.
    SetTransport,
    /// The close machine.
    SetClose,
    /// The role or side, or a birth.
    RoleTransition,
    /// The socket's usability.
    SetUnusable,
}

impl How {
    /// The setter's name, as C's trace writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SetState => "set_state",
            Self::SetTransport => "set_transport",
            Self::SetClose => "set_close",
            Self::RoleTransition => "role_transition",
            Self::SetUnusable => "set_unusable",
        }
    }
}

/// A change of a connection's machines.
///
/// Its `Display` is C's trace line for it, without the connection's tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Edge {
    /// The machines before; `None` before a connection's birth.
    pub from: Option<Machines>,
    /// The machines after.
    pub to: Machines,
    /// Which setter made the change.
    pub how: How,
    /// The event that caused it; `None` for a birth or the socket's
    /// usability changing.
    pub event: Option<Event>,
}

impl Edge {
    /// Whether C's trace records the edge: it leaves out a change that
    /// shows in no state, role, side or attribute.
    #[must_use]
    pub fn traced(&self) -> bool {
        let Some(from) = self.from else {
            return true;
        };
        let to = self.to;
        let same_state = from.role == to.role && from.side == to.side && from.state() == to.state();

        !same_state
            || from.socket != to.socket
            || from.close != to.close
            || from.transport != to.transport
    }
}

impl fmt::Display for Machines {
    /// C's `role/side:STATE` with its attributes, eg,
    /// `h1/C:DEAD_SOCKET+told+unusable`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}:{}",
            self.role.name(),
            self.side.letter(),
            self.state().name()
        )?;
        if self.transport == Transport::Failed {
            f.write_str("+failed")?;
        }
        if self.transport == Transport::Restarting {
            f.write_str("+restarting")?;
        }
        if self.close == Close::UserTold {
            f.write_str("+told")?;
        }
        if self.close == Close::Closing {
            f.write_str("+closing")?;
        }
        if self.socket == Socket::Unusable {
            f.write_str("+unusable")?;
        }
        Ok(())
    }
}

impl fmt::Display for Edge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LRS ")?;
        match self.from {
            Some(m) => write!(f, "{m}")?,
            None => f.write_str("(none)/-:(zero)")?,
        }
        write!(f, " -> {} {}", self.to, self.how.name())?;
        if let Some(e) = self.event {
            write!(f, " ev={}", e.name())?;
        }
        Ok(())
    }
}

impl Machines {
    /// A connection just born: no role, no side, unconnected.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            role: Role::None,
            side: Side::Unset,
            transport: Transport::None,
            carrier: Carrier::None,
            live: Live::Unconnected,
            close: Close::None,
            socket: Socket::Usable,
        }
    }

    /// The edge of a connection's birth, as C's trace shows it.
    #[must_use]
    pub const fn birth() -> Edge {
        Edge {
            from: None,
            to: Self::new(),
            how: How::RoleTransition,
            event: None,
        }
    }

    /// The connection's role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The connection's side.
    #[must_use]
    pub const fn side(&self) -> Side {
        self.side
    }

    /// The transport machine.
    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.transport
    }

    /// The carrier machine.
    #[must_use]
    pub const fn carrier(&self) -> Carrier {
        self.carrier
    }

    /// The live machine, whether or not a close is in progress over it.
    #[must_use]
    pub const fn live(&self) -> Live {
        self.live
    }

    /// The close machine.
    #[must_use]
    pub const fn close(&self) -> Close {
        self.close
    }

    /// Whether the socket is usable.
    #[must_use]
    pub const fn socket(&self) -> Socket {
        self.socket
    }

    /// The state the connection reports: the close machine's if a close is
    /// in progress, else the transport machine's, else the carrier's while
    /// it handshakes, else the live state.
    #[must_use]
    pub const fn state(&self) -> State {
        if let Some(s) = self.close.state() {
            return s;
        }
        if let Some(s) = self.transport.state() {
            return s;
        }
        if let Some(s) = self.carrier.state() {
            return s;
        }
        self.live.state()
    }

    /// Takes an event, and gives the edge it caused.
    ///
    /// # Errors
    ///
    /// [`Refused`], if the event table has no row for it in this role, side
    /// and state, or the row it has breaks a rule of the machines.  The
    /// machines are left as they were.
    pub fn event(&mut self, ev: Event) -> Result<Edge, Refused> {
        self.apply(ev, None)
    }

    /// Takes an event that brings a role the site chooses: an adoption,
    /// a client binding or restarting, a raw upgrade.  Only rows that take
    /// the site's role match.
    ///
    /// # Errors
    ///
    /// As [`Machines::event`]; and [`Refused::NoRow`] for [`Role::None`],
    /// which is no role to bring.
    pub fn event_as(&mut self, ev: Event, role: Role) -> Result<Edge, Refused> {
        if role == Role::None {
            return Err(Refused::NoRow);
        }
        self.apply(ev, Some(role))
    }

    /// Marks the socket usable or not, and gives the edge.
    pub const fn set_socket(&mut self, socket: Socket) -> Edge {
        let from = *self;
        self.socket = socket;
        Edge {
            from: Some(from),
            to: *self,
            how: How::SetUnusable,
            event: None,
        }
    }

    fn apply(&mut self, ev: Event, site_role: Option<Role>) -> Result<Edge, Refused> {
        let to =
            table::row(self.role, self.side, self.state(), ev, site_role).ok_or(Refused::NoRow)?;
        let mut next = *self;
        let how = match to {
            To::Live(live) => {
                if self.transport == Transport::Restarting {
                    return Err(Refused::Restarting);
                }
                next.set_live(live);
                How::SetState
            }
            To::Transport(t) => {
                next.transport = t;
                How::SetTransport
            }
            To::Close(c) => {
                if c < self.close {
                    return Err(Refused::CloseBackwards);
                }
                next.close = c;
                How::SetClose
            }
            To::Role { role, side, state } => {
                let role = match role {
                    RoleTo::Keep => self.role,
                    RoleTo::Site => site_role.unwrap_or(self.role),
                    RoleTo::Named(r) => r,
                };
                let side = match side {
                    SideTo::Keep => self.side,
                    SideTo::Set(s) => s,
                };
                next.role_transition(role, side, state);
                How::RoleTransition
            }
        };
        // as C, an edge that changes no reported state, role or side is
        // not held to the invariants
        if next.role != self.role || next.side != self.side || next.state() != self.state() {
            next.check()?;
        }

        let from = *self;
        *self = next;
        Ok(Edge {
            from: Some(from),
            to: next,
            how,
            event: Some(ev),
        })
    }

    /// C's `lws_wsi_set_state_ev()`: a live state ends any transport phase;
    /// a handshake-named state while the carrier handshakes is the
    /// carrier's, and anything else establishes the carrier and is the live
    /// state.
    const fn set_live(&mut self, live: Live) {
        self.transport = Transport::None;
        match live.carrier() {
            Some(c) if !matches!(self.carrier, Carrier::Established) => self.carrier = c,
            Some(_) | None => {
                self.carrier = if matches!(live, Live::Unconnected) {
                    Carrier::None
                } else {
                    Carrier::Established
                };
                self.live = live;
            }
        }
    }

    /// C's `lws_wsi_role_transition_ev()`: the role and side change, and
    /// the machines start again from `state`.  A restart to unconnected is
    /// a new connection, which leaves the old one's close and socket
    /// behind; any other role change keeps them.
    const fn role_transition(&mut self, role: Role, side: Side, state: table::RoleState) {
        let (transport, carrier, live) = match state {
            table::RoleState::Transport(t) => (t, Carrier::None, Live::Unconnected),
            table::RoleState::Live(Live::Unconnected) => {
                (Transport::None, Carrier::None, Live::Unconnected)
            }
            table::RoleState::Live(l) => match l.carrier() {
                Some(c) => (Transport::None, c, Live::Unconnected),
                None => (Transport::None, Carrier::Established, l),
            },
        };
        let restart = matches!(state, table::RoleState::Live(Live::Unconnected));

        self.role = role;
        self.side = side;
        self.transport = transport;
        self.carrier = carrier;
        self.live = live;
        if restart {
            self.close = Close::None;
            self.socket = Socket::Usable;
        }
    }

    /// The invariants C's `LWS_WITH_STATE_CHECK` holds every edge to.
    const fn check(self) -> Result<(), Refused> {
        if matches!(self.socket, Socket::Unusable) && self.close.polite() {
            return Err(Refused::UnusableSocket);
        }
        if matches!(self.close, Close::Shutdown) && matches!(self.role, Role::RawSkt) {
            return Err(Refused::ShutdownRaw);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h1_server() -> Machines {
        let mut m = Machines::new();
        m.event(Event::ServerSide).unwrap();
        m.event_as(Event::Adopted, Role::H1).unwrap();
        m
    }

    #[test]
    fn a_refused_event_changes_nothing() {
        let mut m = h1_server();
        let before = m;
        assert_eq!(m.event(Event::WsCloseSent), Err(Refused::NoRow));
        assert_eq!(m, before);
    }

    #[test]
    fn no_role_is_no_role_to_bring() {
        let mut m = Machines::new();
        m.event(Event::ServerSide).unwrap();
        assert_eq!(m.event_as(Event::Adopted, Role::None), Err(Refused::NoRow));
    }

    #[test]
    fn a_ws_close_we_start() {
        let mut m = h1_server();
        m.event(Event::ReqHdrsComplete).unwrap();
        m.event(Event::WsUpgraded).unwrap();

        let lines = [
            Event::WsCloseInitiated,
            Event::WsCloseSent,
            Event::CloseFlush,
            Event::SocketGone,
            Event::UserTold,
        ]
        .map(|e| m.event(e).unwrap().to_string());
        assert_eq!(
            lines,
            [
                "LRS ws/S:ESTABLISHED -> ws/S:WAITING_TO_SEND_CLOSE set_close ev=WS_CLOSE_INITIATED",
                "LRS ws/S:WAITING_TO_SEND_CLOSE -> ws/S:AWAITING_CLOSE_ACK set_close ev=WS_CLOSE_SENT",
                "LRS ws/S:AWAITING_CLOSE_ACK -> ws/S:FLUSHING_BEFORE_CLOSE set_close ev=CLOSE_FLUSH",
                "LRS ws/S:FLUSHING_BEFORE_CLOSE -> ws/S:DEAD_SOCKET set_close ev=SOCKET_GONE",
                "LRS ws/S:DEAD_SOCKET -> ws/S:DEAD_SOCKET+told set_close ev=USER_TOLD",
            ]
        );
    }

    #[test]
    fn an_unusable_socket_never_closes_politely() {
        let mut m = h1_server();
        m.event(Event::ReqHdrsComplete).unwrap();
        m.event(Event::WsUpgraded).unwrap();
        m.set_socket(Socket::Unusable);
        assert_eq!(
            m.event(Event::WsCloseInitiated),
            Err(Refused::UnusableSocket)
        );
        assert_eq!(m.event(Event::CloseStaged), Err(Refused::UnusableSocket));
        // the abortive path is still open
        assert!(m.event(Event::SocketGone).is_ok());
    }

    #[test]
    fn the_close_only_goes_forwards() {
        let mut m = h1_server();
        m.event(Event::SocketGone).unwrap();
        assert_eq!(m.event(Event::CloseFlush), Err(Refused::CloseBackwards));
        // entering the close is the close, at its start
        assert_eq!(m.event(Event::CloseEntered), Err(Refused::CloseBackwards));
    }

    #[test]
    fn a_restart_is_a_new_connection() {
        let mut m = Machines::new();
        m.event_as(Event::ClientBind, Role::H1).unwrap();
        m.event(Event::ConnectStart).unwrap();
        m.set_socket(Socket::Unusable);
        m.event(Event::Retarget).unwrap();
        // no live state while restarting...
        assert_eq!(m.event(Event::TransportUp), Err(Refused::Restarting));
        // ...until the restart, which leaves the old socket behind
        m.event_as(Event::Restart, Role::H1).unwrap();
        assert_eq!(m.socket(), Socket::Usable);
        assert_eq!(m.transport(), Transport::None);
    }
}
