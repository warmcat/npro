//! The tls record layer, as the driver sees it.
//!
//! The driver keeps tls between the socket and the connection's buffers,
//! once, so no adapter sees it: bytes read from the socket go through
//! [`RecordLayer::open`] into the connection's rx buffer, and what the
//! connection writes through [`RecordLayer::seal`] to the socket.  The
//! record layer is sans-IO too: it is handed buffers, never a socket.
//!
//! It is a trait, not a dependency, because the right tls differs by
//! target and the provider of its crypto is the application's to choose
//! (`docs/io-model.md`, "tls").  What C learned is in its contract: one
//! pair of calls drives every step of the handshake, so a handshake that
//! completes on its first step (a resumed session on loopback) takes the
//! same path as any other; and whatever the peer is, it is confirmed before
//! [`RecordLayer::is_established`] says so, and only then is its ALPN
//! known.

use npro_core::time::Instant;

#[cfg(feature = "rustls")]
pub mod rustls;

/// What [`RecordLayer::open`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    /// How much of the socket's bytes it took.
    pub consumed: usize,
    /// How much plaintext it wrote.
    pub produced: usize,
    /// The peer closed its tls, cleanly (a `close_notify`): no more
    /// plaintext comes after what was produced.
    pub closed: bool,
}

/// What [`RecordLayer::seal`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// How much of the plaintext it took.
    pub taken: usize,
    /// How much it wrote for the socket.
    pub written: usize,
}

/// The record layer failed: the handshake was refused, the peer is not
/// who it must be, a record does not decrypt.  The connection cannot go
/// on, and is dropped; the record layer knows why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failed;

impl core::fmt::Display for Failed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("tls failed")
    }
}

impl core::error::Error for Failed {}

/// A tls record layer, sans-IO: an implementation binds a tls stack
/// (rustls, or another) to the driver.
pub trait RecordLayer {
    /// Takes tls records from the front of `net`, bytes from the socket,
    /// at `now`, and writes the plaintext they carry into `plain`.  What it
    /// does not take, it is given again with more after it.  Handshake
    /// records are taken here too, and what they need sent is left for
    /// [`RecordLayer::seal`].
    ///
    /// # Errors
    ///
    /// [`Failed`] if the connection cannot go on.
    fn open(&mut self, now: Instant, net: &mut [u8], plain: &mut [u8]) -> Result<Opened, Failed>;

    /// Writes into `net`, for the socket, at `now`, what the record layer
    /// owes the peer of its own (handshake, alerts, a `close_notify` asked
    /// for), then as much of `plain` as it can, encrypted, once the
    /// handshake allows.  What it does not take of `plain`, it is given
    /// again.
    ///
    /// # Errors
    ///
    /// [`Failed`] if the connection cannot go on.
    fn seal(&mut self, now: Instant, plain: &[u8], net: &mut [u8]) -> Result<Sealed, Failed>;

    /// Whether it has records of its own to send.
    fn wants_write(&self) -> bool;

    /// Whether the handshake is done, the peer confirmed: plaintext can go.
    fn is_established(&self) -> bool;

    /// The protocol agreed with the peer (ALPN), once established.
    fn alpn(&self) -> Option<&[u8]>;

    /// Asks for a `close_notify`, to go after the plaintext still to be
    /// sealed: once [`RecordLayer::seal`] has taken all it is given.
    fn close(&mut self);
}

/// No tls: the driver's default, a type with no values, so a driver
/// without tls carries none of tls' buffers or steps, and its path through
/// tls cannot be taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoTls {}

impl RecordLayer for NoTls {
    fn open(&mut self, _: Instant, _: &mut [u8], _: &mut [u8]) -> Result<Opened, Failed> {
        match *self {}
    }

    fn seal(&mut self, _: Instant, _: &[u8], _: &mut [u8]) -> Result<Sealed, Failed> {
        match *self {}
    }

    fn wants_write(&self) -> bool {
        match *self {}
    }

    fn is_established(&self) -> bool {
        match *self {}
    }

    fn alpn(&self) -> Option<&[u8]> {
        match *self {}
    }

    fn close(&mut self) {
        match *self {}
    }
}
