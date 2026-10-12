//! What an adapter drives when it carries many connections: a host.
//!
//! A [`crate::driver::Driver`] is one connection.  Something that holds
//! many, made as sockets are accepted on its listeners and named by ids
//! it hands out (npro-ss is one), is a host: the adapter accepts on the
//! host's listeners and drives each connection by its id, with the
//! driver's own calls.  It is a trait here, beside the driver, so the
//! adapters in this crate can carry a host from a crate that depends on
//! this one.
//!
//! The application is not the host's: it acts on the host between the
//! adapter's calls, as the adapter is told it may ([`crate::threads`]).

use npro_core::time::Instant;

use crate::driver::Want;

/// A connection id the host does not have: its connection is gone, or
/// never was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gone;

impl core::fmt::Display for Gone {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no such stream or connection")
    }
}

impl core::error::Error for Gone {}

/// Many connections, driven by id: see the module's description.  Each
/// call is the driver's of the same name, on the connection `conn`
/// names, and is [`Gone`] if it has gone.
pub trait Host {
    /// A listener, as the host names it.
    type Listener: Copy;
    /// A connection, as the host names it.
    type Conn: Copy;
    /// A connection's tls, as the adapter makes it on accepting.
    type Tls;
    /// Why the host would not take a socket accepted.
    type Refused: core::fmt::Display;

    /// The adapter accepted a socket on `listener` at `now`, with `tls`
    /// its tls if the listener's connections are: the connection is made,
    /// and driven from here by the id returned.
    ///
    /// # Errors
    ///
    /// Why the host would not take it: the adapter closes the socket.
    fn accepted(
        &mut self,
        now: Instant,
        listener: Self::Listener,
        tls: Option<Self::Tls>,
    ) -> Result<Self::Conn, Self::Refused>;

    /// What the connection wants of the adapter now.  On
    /// [`Want::Release`], the adapter closes the socket and says so
    /// ([`Host::released`]).
    ///
    /// # Errors
    ///
    /// [`Gone`].
    fn want(&mut self, now: Instant, conn: Self::Conn) -> Result<Want<'_>, Gone>;

    /// The adapter read `n` bytes into what [`Host::want`] offered; 0 is
    /// the peer's FIN.
    ///
    /// # Errors
    ///
    /// [`Gone`].
    fn read_done(&mut self, now: Instant, conn: Self::Conn, n: usize) -> Result<(), Gone>;

    /// Bytes read elsewhere, copied in as far as there is room: how many
    /// were taken.
    ///
    /// # Errors
    ///
    /// [`Gone`].
    fn received(&mut self, now: Instant, conn: Self::Conn, bytes: &[u8]) -> Result<usize, Gone>;

    /// The adapter wrote `n` bytes of what [`Host::want`] offered.
    ///
    /// # Errors
    ///
    /// [`Gone`].
    fn write_done(&mut self, now: Instant, conn: Self::Conn, n: usize) -> Result<(), Gone>;

    /// The adapter half-closed the socket, as [`Want::HalfClose`] asked.
    ///
    /// # Errors
    ///
    /// [`Gone`].
    fn half_closed(&mut self, now: Instant, conn: Self::Conn) -> Result<(), Gone>;

    /// It is `now`, which may be past what [`Host::want`] said.
    ///
    /// # Errors
    ///
    /// [`Gone`].
    fn timer(&mut self, now: Instant, conn: Self::Conn) -> Result<(), Gone>;

    /// The socket hung up, or failed.
    ///
    /// # Errors
    ///
    /// [`Gone`].
    fn hangup(&mut self, now: Instant, conn: Self::Conn) -> Result<(), Gone>;

    /// The adapter closed the socket, as [`Want::Release`] asked: the id
    /// is refused from here.
    ///
    /// # Errors
    ///
    /// [`Gone`].
    fn released(&mut self, conn: Self::Conn) -> Result<(), Gone>;
}
