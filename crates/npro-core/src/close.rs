//! What a connection asks of whatever carries it, once it is done with.
//!
//! The close machine ([`crate::state::Close`]) is where a connection's own
//! close has got to.  This is what it asks IO to do about the socket at
//! the end, the three ways C's `__lws_close_free_wsi()` ends one:
//!
//! - a server, closing in good order, stages a shutdown: what it wrote
//!   goes, then it half-closes and waits for the peer's FIN
//!   (`LWS_IOCLOSE_SHUTDOWN`, `LRS_SHUTDOWN`);
//! - a client closes once what it wrote has gone, staging nothing, as C
//!   stages a shutdown only for a server (`!lwsi_role_client(wsi)` in
//!   `close.c`);
//! - a connection that timed out or failed is closed at once, and
//!   nothing more goes, as C marks its socket unusable.

/// What the connection asks of whatever carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Close {
    /// Once what was written has gone, stop sending and wait for the
    /// peer to close: C's `LWS_IOCLOSE_SHUTDOWN`.
    Shutdown,
    /// Once what was written has gone, release the connection.
    Release,
    /// Release the connection now, dropping whatever is unwritten: a
    /// deadline passed or the connection failed, and C marks the socket
    /// unusable.
    Abort,
}
