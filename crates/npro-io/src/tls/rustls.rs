//! The record layer by rustls, through its unbuffered API: the
//! application makes rustls' connection, with its config and the crypto
//! provider it chooses, and the driver drives it.
//!
//! rustls' unbuffered connection is sans-IO as npro is: it is handed the
//! peer's records and buffers to write into, and says, one state at a
//! time, what it wants.  [`Rustls`] turns that into [`RecordLayer`]'s two
//! calls.  Handshake records rustls makes while taking the peer's are kept
//! until [`RecordLayer::seal`] writes them, in a buffer that grows to what
//! rustls asks: a handshake flight, its certificates included.
//!
//! rustls opens a record only whole, and gives its payload whole, so the
//! driver's buffers must hold a record (16KiB, and its overhead in the
//! records' rx buffer).  A record whose payload the plaintext buffer could
//! never hold fails the connection.
//!
//! npro depends on no crypto provider: the application gives rustls one,
//! so this is tested where one is, in `npro-aws-lc`.

extern crate alloc;

use alloc::vec::Vec;

use ::rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use ::rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use ::rustls::unbuffered::{ConnectionState, EncodeError, EncryptError, UnbufferedStatus};
use npro_core::time::Instant;

use super::{Failed, Opened, RecordLayer, Sealed};

/// The most plaintext given rustls to encrypt in one call: a record's.
const MAX_PLAINTEXT: usize = 16 * 1024;

/// The most a handshake flight kept to send may be: rustls asks no more
/// than a flight of records, certificates and all.
const MAX_PENDING: usize = 64 * 1024;

/// A guard on the steps of one call: rustls moves on each step, so this
/// is never reached unless something is wrong.
const MAX_STEPS: usize = 64;

/// The sealed trait pattern: [`Side`] is public, to bound [`Rustls`], and
/// only rustls' two unbuffered connections are one.
mod sealed {
    pub trait Sealed {}
}

/// An end of a rustls unbuffered connection: client or server.
pub trait Side: sealed::Sealed {
    /// rustls' data for the end.
    type Data;

    /// rustls' `process_tls_records()`.
    fn process<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data>;

    /// Whether the handshake is under way.
    fn handshaking(&self) -> bool;

    /// The protocol agreed, if any.
    fn alpn(&self) -> Option<&[u8]>;
}

impl sealed::Sealed for UnbufferedClientConnection {}

impl Side for UnbufferedClientConnection {
    type Data = ClientConnectionData;

    fn process<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(incoming)
    }

    fn handshaking(&self) -> bool {
        self.is_handshaking()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.alpn_protocol()
    }
}

impl sealed::Sealed for UnbufferedServerConnection {}

impl Side for UnbufferedServerConnection {
    type Data = ServerConnectionData;

    fn process<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(incoming)
    }

    fn handshaking(&self) -> bool {
        self.is_handshaking()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.alpn_protocol()
    }
}

/// Whether rustls may have something to say without being given records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    /// It may: it is new, or took records since it was last asked.
    Ask,
    /// It said it waits for the peer, or has nothing of its own to send.
    Quiet,
}

/// Where our `close_notify` is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Notify {
    Open,
    /// Asked for: it goes once the plaintext given has.
    Asked,
    Sent,
}

/// A rustls unbuffered connection, `C` its end, as a [`RecordLayer`].
#[derive(Debug)]
pub struct Rustls<C> {
    conn: C,
    /// Handshake records made, not yet written.
    pending: Vec<u8>,
    next: Next,
    notify: Notify,
    /// Why it failed, once it did.
    error: Option<::rustls::Error>,
}

/// A client's rustls record layer.
pub type RustlsClient = Rustls<UnbufferedClientConnection>;

/// A server's rustls record layer.
pub type RustlsServer = Rustls<UnbufferedServerConnection>;

impl<C: Side> Rustls<C> {
    /// The record layer of `conn`, which the application made with its
    /// config, its provider among it.
    #[must_use]
    pub const fn new(conn: C) -> Self {
        Self {
            conn,
            pending: Vec::new(),
            next: Next::Ask,
            notify: Notify::Open,
            error: None,
        }
    }

    /// rustls' connection: its peer's certificates, its protocol version.
    #[must_use]
    pub const fn conn(&self) -> &C {
        &self.conn
    }

    /// Why it failed, once it did.
    #[must_use]
    pub const fn error(&self) -> Option<&::rustls::Error> {
        self.error.as_ref()
    }

    /// It failed, as rustls says.
    fn failed(&mut self, e: ::rustls::Error) -> Failed {
        self.error = Some(e);
        Failed
    }

    /// Keeps a handshake record rustls made, growing the buffer to what it
    /// asks, within [`MAX_PENDING`].
    fn encode(
        pending: &mut Vec<u8>,
        mut encode: impl FnMut(&mut [u8]) -> Result<usize, EncodeError>,
    ) -> Result<(), Failed> {
        let at = pending.len();
        let mut room = 4096usize;
        loop {
            let want = at.checked_add(room).ok_or(Failed)?;
            if want > MAX_PENDING {
                return Err(Failed);
            }
            pending.resize(want, 0);
            match encode(pending.get_mut(at..).unwrap_or_default()) {
                Ok(n) => {
                    pending.truncate(at.saturating_add(n));
                    return Ok(());
                }
                Err(EncodeError::InsufficientSize(e)) => {
                    room = e.required_size.max(room.saturating_add(1));
                }
                Err(EncodeError::AlreadyEncoded) => {
                    pending.truncate(at);
                    return Ok(());
                }
            }
        }
    }

    /// Writes what is pending into `net`: how much.
    fn drain(&mut self, net: &mut [u8]) -> usize {
        let n = self.pending.len().min(net.len());
        if let (Some(d), Some(s)) = (net.get_mut(..n), self.pending.get(..n)) {
            d.copy_from_slice(s);
        }
        self.pending.drain(..n);
        n
    }
}

impl<C: Side> RecordLayer for Rustls<C> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "rustls' ConnectionState is non_exhaustive: a state it adds later fails the connection until it is handled here"
    )]
    fn open(&mut self, _now: Instant, net: &mut [u8], plain: &mut [u8]) -> Result<Opened, Failed> {
        // failed, rustls is not asked again: it would try to send its
        // fatal alert a second time
        if self.error.is_some() {
            return Err(Failed);
        }
        let (mut consumed, mut produced, mut closed) = (0usize, 0usize, false);
        for _ in 0..MAX_STEPS {
            let incoming = net.get_mut(consumed..).unwrap_or_default();
            if incoming.is_empty() {
                break;
            }
            let status = self.conn.process(incoming);
            let mut discard = status.discard;
            let state = match status.state {
                Ok(s) => s,
                Err(e) => {
                    self.error = Some(e);
                    return Err(Failed);
                }
            };
            let mut stop = false;
            match state {
                ConnectionState::ReadTraffic(mut r) => {
                    while let Some(len) = r.peek_len() {
                        let len = len.get();
                        let room = plain.get_mut(produced..).unwrap_or_default();
                        if len > room.len() {
                            if produced == 0 && consumed == 0 && len > plain.len() {
                                // it could never fit
                                return Err(Failed);
                            }
                            stop = true;
                            break;
                        }
                        match r.next_record() {
                            Some(Ok(rec)) => {
                                if let Some(d) = room.get_mut(..rec.payload.len()) {
                                    d.copy_from_slice(rec.payload);
                                }
                                produced = produced.saturating_add(rec.payload.len());
                                discard = discard.saturating_add(rec.discard);
                            }
                            Some(Err(e)) => return Err(self.failed(e)),
                            None => break,
                        }
                    }
                }
                ConnectionState::EncodeTlsData(mut e) => {
                    Self::encode(&mut self.pending, |out| e.encode(out))?;
                }
                // what was encoded is in hand, and goes with the next seal
                ConnectionState::TransmitTlsData(t) => t.done(),
                ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => {
                    stop = true;
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    closed = true;
                    stop = true;
                }
                // early data is not taken: refused
                _ => return Err(Failed),
            }
            consumed = consumed.saturating_add(discard).min(net.len());
            if stop {
                break;
            }
        }
        self.next = Next::Ask;
        Ok(Opened {
            consumed,
            produced,
            closed,
        })
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "rustls' ConnectionState is non_exhaustive: a state it adds later fails the connection until it is handled here"
    )]
    fn seal(&mut self, _now: Instant, plain: &[u8], net: &mut [u8]) -> Result<Sealed, Failed> {
        if self.error.is_some() {
            return Err(Failed);
        }
        let mut written = self.drain(net);
        let mut taken = 0usize;
        for _ in 0..MAX_STEPS {
            if !self.pending.is_empty() {
                // the socket must take what is pending first
                break;
            }
            let status = self.conn.process(&mut []);
            let state = match status.state {
                Ok(s) => s,
                Err(e) => {
                    self.error = Some(e);
                    return Err(Failed);
                }
            };
            match state {
                ConnectionState::EncodeTlsData(mut e) => {
                    Self::encode(&mut self.pending, |out| e.encode(out))?;
                }
                ConnectionState::TransmitTlsData(t) => t.done(),
                ConnectionState::WriteTraffic(mut w) => {
                    while taken < plain.len() {
                        let room = net.get_mut(written..).unwrap_or_default();
                        let rest = plain.get(taken..).unwrap_or_default();
                        let mut n = rest.len().min(MAX_PLAINTEXT);
                        let sent = loop {
                            if n == 0 {
                                break None;
                            }
                            match w.encrypt(rest.get(..n).unwrap_or_default(), room) {
                                Ok(k) => break Some(k),
                                Err(EncryptError::InsufficientSize(_)) => n /= 2,
                                Err(EncryptError::EncryptExhausted) => return Err(Failed),
                            }
                        };
                        let Some(k) = sent else {
                            break;
                        };
                        written = written.saturating_add(k);
                        taken = taken.saturating_add(n);
                    }
                    if self.notify == Notify::Asked && taken == plain.len() {
                        let room = net.get_mut(written..).unwrap_or_default();
                        if let Ok(k) = w.queue_close_notify(room) {
                            written = written.saturating_add(k);
                            self.notify = Notify::Sent;
                        }
                    }
                    self.next = Next::Quiet;
                    break;
                }
                ConnectionState::BlockedHandshake | ConnectionState::Closed => {
                    self.next = Next::Quiet;
                    break;
                }
                // the peer's close was told by open; ours may still go
                ConnectionState::PeerClosed => {}
                ConnectionState::ReadTraffic(_) => break,
                _ => return Err(Failed),
            }
            let more = self.drain(net.get_mut(written..).unwrap_or_default());
            written = written.saturating_add(more);
        }
        Ok(Sealed { taken, written })
    }

    fn wants_write(&self) -> bool {
        !self.pending.is_empty() || self.next == Next::Ask || self.notify == Notify::Asked
    }

    fn is_established(&self) -> bool {
        !self.conn.handshaking()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn()
    }

    fn close(&mut self) {
        if self.notify == Notify::Open {
            self.notify = Notify::Asked;
        }
    }
}
