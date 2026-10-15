//! The access log's line: C's `lws_access_log()`, one line per request
//! in the Apache form, so what reads lwsws' log reads npro's:
//!
//! ```text
//! 2.31.234.19 - - [27/Mar/2016:03:22:44 +0000] "GET /aep-screen.png HTTP/1.1" 200 152987 "https://libwebsockets.org/index.html" "Mozilla/5.0 (Macint... Chrome/49.0.2623.87 Safari/537.36"
//! ```
//!
//! A [`Record`] is taken from the request as it is told
//! ([`Kind::ServerTxn`], [`Kind::ServerUpgrade`] or
//! [`Kind::UpgradeRefused`]), as C prepares its `header_log` when the
//! request is parsed: by the time the transaction is over, the head is
//! gone.  The line is written when [`Kind::ServerTxnEnd`] says what the
//! answer was, as C writes it at `lws_http_transaction_completed()` or
//! at the close.  Writing it to a file is the application's: the record
//! is `no_std` storage, [`MAX_LINE`] bytes, kept with the stream.
//!
//! The peer's fields, the path, the referrer and the user agent, are
//! sanitized as C sanitizes them, so a peer cannot add a record, hide the
//! rest of a line, or break its quoting: `"` becomes `'`, and a C0
//! control or DEL becomes `_`.  The time is UTC, where C's is local time
//! with its offset: npro reads no time zone (decided 2026-10-15).
//!
//! [`Kind::ServerTxn`]: crate::event::Kind::ServerTxn
//! [`Kind::ServerUpgrade`]: crate::event::Kind::ServerUpgrade
//! [`Kind::UpgradeRefused`]: crate::event::Kind::UpgradeRefused
//! [`Kind::ServerTxnEnd`]: crate::event::Kind::ServerTxnEnd

use core::fmt::{self, Write};
use core::net::IpAddr;

use npro_core::time::Civil;
use npro_h1::head::Version;

use crate::event::{Ended, Txn};

/// The longest line, its newline included: C's buffer.  What does not fit
/// is cut, the user agent first, then the referrer, the line's structure
/// kept.
pub const MAX_LINE: usize = 512;

/// The longest the line's first part may be, the peer to the request
/// line: C's.
pub(crate) const MAX_HEAD: usize = 255;

/// What the line adds around the record's parts: ` ` and a status (five
/// digits at most), ` ` and the bytes (twenty digits at most), ` "`,
/// `" "`, `"` and the newline.
const TAIL: usize = 1 + 5 + 1 + 20 + 2 + 3 + 2;

/// How much of a line the record's parts may fill.
pub(crate) const MAX_PARTS: usize = MAX_LINE - TAIL;

/// What closes the line after the referrer: `" "`, the user agent, `"`
/// and the newline.
const AFTER_REFERRER: usize = 3 + 2;

/// What closes the line after the user agent: `"` and the newline.
const AFTER_UA: usize = 2;

/// What is known of a request when it is told, kept for the line written
/// when its transaction ends: the peer, the time, the request line, its
/// referrer and its user agent, sanitized.
///
/// ```
/// use npro_ss::access::{MAX_LINE, Record};
/// use npro_ss::event::Ended;
///
/// # fn with(txn: &npro_ss::event::Txn<'_, Vec<u8>>) {
/// // when the request is told, with the wall clock's seconds since 1970
/// let record = Record::of(txn, 1_767_225_600);
/// // when its transaction ends
/// let mut line = [0u8; MAX_LINE];
/// let n = record.line(Ended { status: Some(200), sent: 1234 }, &mut line);
/// assert!(line[..n].ends_with(b"\n"));
/// # }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    buf: [u8; MAX_PARTS],
    /// Where the head ends and the referrer starts.
    head: u16,
    /// Where the referrer ends and the user agent starts.
    referrer: u16,
    /// Where the user agent ends.
    len: u16,
}

impl Record {
    /// What is known of the request `txn` holds, told at `wall`, in
    /// seconds since 1970 on the wall clock, which the adapter reads.
    #[must_use]
    pub fn of<S: AsRef<[u8]> + AsMut<[u8]>>(txn: &Txn<'_, S>, wall: u64) -> Self {
        let mut buf = [0u8; MAX_PARTS];
        let mut c = Cursor {
            buf: &mut buf,
            at: 0,
            end: MAX_HEAD,
        };
        c.head(txn, wall);
        let head = c.at;
        c.end = MAX_PARTS;
        c.sanitized(txn.header(b"referer").unwrap_or_default());
        let referrer = c.at;
        c.sanitized(txn.header(b"user-agent").unwrap_or_default());
        let len = c.at;
        // each is at most MAX_PARTS, which fits
        Self {
            buf,
            head: u16::try_from(head).unwrap_or(0),
            referrer: u16::try_from(referrer).unwrap_or(0),
            len: u16::try_from(len).unwrap_or(0),
        }
    }

    /// The line, written into `out`, with what the transaction came to:
    /// how long it is.  Always whole, newline included.
    pub fn line(&self, ended: Ended, out: &mut [u8; MAX_LINE]) -> usize {
        let (head, referrer, ua) = self.parts();
        let mut c = Cursor {
            buf: out,
            at: 0,
            end: MAX_LINE,
        };
        c.bytes(head);
        // written whole: the head and the numbers fit by construction,
        // and `write!` only says what the cursor dropped
        let _ = write!(c, " {} {} \"", ended.status.unwrap_or(0), ended.sent);
        // the referrer, then the user agent, as much of each as leaves
        // room for what closes the line: C cuts the user agent first
        let room = MAX_LINE.saturating_sub(c.at).saturating_sub(AFTER_REFERRER);
        c.bytes(referrer.get(..referrer.len().min(room)).unwrap_or_default());
        c.bytes(b"\" \"");
        let left = MAX_LINE.saturating_sub(c.at).saturating_sub(AFTER_UA);
        c.bytes(ua.get(..ua.len().min(left)).unwrap_or_default());
        c.bytes(b"\"\n");
        c.at
    }

    /// The head, the referrer and the user agent.
    fn parts(&self) -> (&[u8], &[u8], &[u8]) {
        let (head, referrer, len) = (
            usize::from(self.head),
            usize::from(self.referrer),
            usize::from(self.len),
        );
        (
            self.buf.get(..head).unwrap_or_default(),
            self.buf.get(head..referrer).unwrap_or_default(),
            self.buf.get(referrer..len).unwrap_or_default(),
        )
    }
}

/// Writes into a buffer up to `end`, dropping what does not fit, as C's
/// `snprintf` and `strncpy` do: the line's structure is kept, and what is
/// cut is the end of a field.
struct Cursor<'b> {
    buf: &'b mut [u8],
    at: usize,
    end: usize,
}

impl Cursor<'_> {
    /// Appends what fits of `b`.
    fn bytes(&mut self, b: &[u8]) {
        let room = self.end.min(self.buf.len()).saturating_sub(self.at);
        let n = b.len().min(room);
        if let (Some(to), Some(from)) = (
            self.buf.get_mut(self.at..self.at.saturating_add(n)),
            b.get(..n),
        ) {
            to.copy_from_slice(from);
            self.at = self.at.saturating_add(n);
        }
    }

    /// Appends what fits of `b`, sanitized: `"` as `'`, a control or DEL
    /// as `_`.  C's `lws_access_log_sanitize()`.
    fn sanitized(&mut self, b: &[u8]) {
        for &byte in b {
            let safe = match byte {
                b'"' => b'\'',
                0..=0x1f | 0x7f => b'_',
                other => other,
            };
            self.bytes(&[safe]);
        }
    }

    /// The line's first part: the peer, the time and the request line,
    /// C's `header_log`.
    fn head<S: AsRef<[u8]> + AsMut<[u8]>>(&mut self, txn: &Txn<'_, S>, wall: u64) {
        match txn.peer() {
            // a mapped v4 address as v4, as C writes it
            Some(a) => {
                let ip: IpAddr = a.ip().to_canonical();
                let _ = write!(self, "{ip}");
            }
            None => self.bytes(b"-"),
        }
        let t = Civil::from_unix(wall);
        let _ = write!(
            self,
            " - - [{:02}/{}{}{}/{}:{:02}:{:02}:{:02} +0000] \"",
            t.day,
            char::from(t.month_name()[0]),
            char::from(t.month_name()[1]),
            char::from(t.month_name()[2]),
            t.year,
            t.hour,
            t.minute,
            t.second
        );
        match txn.method() {
            Some(m) => self.bytes(m),
            None => self.bytes(b"-"),
        }
        self.bytes(b" ");
        self.sanitized(txn.path().unwrap_or_default());
        self.bytes(match txn.version() {
            Version::Http10 => b" HTTP/1.0\"",
            Version::Http11 => b" HTTP/1.1\"",
        });
    }
}

impl Write for Cursor<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let before = self.at;
        self.bytes(s.as_bytes());
        if self.at.saturating_sub(before) == s.len() {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_cuts_at_its_end_and_keeps_what_fits() {
        let mut buf = [0u8; 8];
        let mut c = Cursor {
            buf: &mut buf,
            at: 0,
            end: 6,
        };
        c.bytes(b"abcd");
        assert!(write!(c, "{}", 12345).is_err());
        assert_eq!(c.at, 6);
        c.end = 8;
        c.sanitized(b"\"\n\x7f~");
        assert_eq!(&buf, b"abcd12'_");
    }
}
