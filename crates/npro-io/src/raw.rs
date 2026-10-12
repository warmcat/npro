//! The raw role: the connection's bytes, as they are, both ways.
//!
//! C's raw role (`roles/raw-skt`), with no framing and nothing to parse:
//! what the peer sends is the application's as it comes, and what the
//! application gives is sent as it is.  A connection becomes raw from h1
//! once both ends agreed an upgrade ([`crate::conn::Conn::switch_raw`]),
//! which is how a proxy passes a ws connection through untouched: the
//! frames, their masks and any extension are the two peers' business.
//!
//! The role has no deadline: what is carried is the peers', and so is
//! knowing when it has gone quiet too long.

use npro_core::close::Close;
use npro_h1::server::TxSource;

/// What the peer's bytes were.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// Bytes, as they came.
    Data(&'a [u8]),
    /// The peer closed its side: it sends nothing more, though it may
    /// still take what is written to it.
    PeerClosed,
}

/// Where the role is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Carrying bytes.
    Open,
    /// The application closed it, as `Close` says, once what it wrote has
    /// gone.
    Closed(Close),
}

/// A raw connection.
///
/// ```
/// use npro_core::close::Close;
/// use npro_io::raw::{Event, Raw};
///
/// let mut r = Raw::new();
/// let (consumed, event) = r.rx(b"anything");
/// assert_eq!((consumed, event), (8, Some(Event::Data(&b"anything"[..]))));
/// r.close(Close::Shutdown);
/// assert_eq!(r.closing(), Some(Close::Shutdown));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Raw {
    phase: Phase,
}

impl Default for Raw {
    fn default() -> Self {
        Self::new()
    }
}

impl Raw {
    /// A raw connection, carrying bytes.
    #[must_use]
    pub const fn new() -> Self {
        Self { phase: Phase::Open }
    }

    /// Takes the peer's bytes: all of them, as one event, if there are
    /// any.  A role closed takes them and gives nothing, as C drains a
    /// closing socket.
    pub const fn rx<'a>(&mut self, input: &'a [u8]) -> (usize, Option<Event<'a>>) {
        match self.phase {
            Phase::Open if !input.is_empty() => (input.len(), Some(Event::Data(input))),
            Phase::Open | Phase::Closed(_) => (input.len(), None),
        }
    }

    /// The peer closed its side.  It is the application's to say what
    /// follows: the role stays open for what it still writes.
    #[must_use]
    pub const fn rx_closed(&self) -> Option<Event<'static>> {
        match self.phase {
            Phase::Open => Some(Event::PeerClosed),
            Phase::Closed(_) => None,
        }
    }

    /// Writes the application's bytes, pulled from `src`, into `out`,
    /// returning how many.  Closed, it writes nothing more of them.
    pub fn tx(&mut self, out: &mut [u8], src: &mut dyn TxSource) -> usize {
        match self.phase {
            Phase::Open => src.fill(out).min(out.len()),
            Phase::Closed(_) => 0,
        }
    }

    /// The application is done with the connection: once what it wrote
    /// has gone, it is closed as `close` says.  A proxy whose other side's
    /// peer closed passes it on with [`Close::Shutdown`], so this side's
    /// peer sees a FIN after the last of the bytes.
    pub const fn close(&mut self, close: Close) {
        if let Phase::Open = self.phase {
            self.phase = Phase::Closed(close);
        }
    }

    /// What the role asks of whatever carries it, once it is closed.
    #[must_use]
    pub const fn closing(&self) -> Option<Close> {
        match self.phase {
            Phase::Open => None,
            Phase::Closed(c) => Some(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use npro_h1::server::NoPayload;

    struct Bytes(&'static [u8]);
    impl TxSource for Bytes {
        fn fill(&mut self, buf: &mut [u8]) -> usize {
            let n = self.0.len().min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            n
        }
    }

    #[test]
    fn bytes_pass_as_they_are() {
        let mut r = Raw::new();
        assert_eq!(r.rx(b""), (0, None));
        assert_eq!(r.rx(b"\x81\x00"), (2, Some(Event::Data(&b"\x81\x00"[..]))));
        let mut out = [0u8; 4];
        let mut src = Bytes(b"abcdef");
        assert_eq!(r.tx(&mut out, &mut src), 4);
        assert_eq!(&out, b"abcd");
        assert_eq!(r.tx(&mut out, &mut src), 2);
        assert_eq!(r.tx(&mut out, &mut NoPayload), 0);
    }

    #[test]
    fn the_peers_close_is_told_and_the_role_stays_open_to_write() {
        let mut r = Raw::new();
        assert_eq!(r.rx_closed(), Some(Event::PeerClosed));
        assert_eq!(r.closing(), None);
        let mut out = [0u8; 4];
        assert_eq!(r.tx(&mut out, &mut Bytes(b"ab")), 2);
    }

    #[test]
    fn closed_it_writes_and_tells_nothing_more_and_drains_what_comes() {
        let mut r = Raw::new();
        r.close(Close::Release);
        // the first close stands
        r.close(Close::Abort);
        assert_eq!(r.closing(), Some(Close::Release));
        assert_eq!(r.rx(b"late"), (4, None));
        assert_eq!(r.rx_closed(), None);
        let mut out = [0u8; 4];
        assert_eq!(r.tx(&mut out, &mut Bytes(b"ab")), 0);
    }
}
