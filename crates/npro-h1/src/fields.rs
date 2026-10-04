//! What some header values mean, read as C reads them.

use crate::table::HeaderTable;
use crate::token::Token;

/// A `Content-Length` is not one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadContentLength;

impl core::fmt::Display for BadContentLength {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("bad Content-Length")
    }
}

impl core::error::Error for BadContentLength {}

/// A `Content-Length` value: RFC 9110 8.6's `1*DIGIT`, with trailing
/// spaces tolerated as C has always tolerated them, and nothing that would
/// not fit in 64 bits.  C's `lws_http_parse_content_length()`: no sign, no
/// leading space, no wrapping round.
///
/// ```
/// use npro_h1::fields::content_length;
///
/// assert_eq!(content_length(b"10"), Ok(10));
/// assert_eq!(content_length(b"10  "), Ok(10));
/// assert!(content_length(b"10abc").is_err());
/// assert!(content_length(b"-1").is_err());
/// assert!(content_length(b"18446744073709551616").is_err());
/// ```
///
/// # Errors
///
/// [`BadContentLength`] for anything else.
pub fn content_length(value: &[u8]) -> Result<u64, BadContentLength> {
    let digits = value.iter().take_while(|c| c.is_ascii_digit()).count();
    let (num, rest) = value.split_at(digits);
    if num.is_empty() || rest.iter().any(|c| *c != b' ') {
        return Err(BadContentLength);
    }
    num.iter().try_fold(0u64, |v, c| {
        v.checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c.wrapping_sub(b'0'))))
            .ok_or(BadContentLength)
    })
}

/// Whether a head's `Transfer-Encoding` is exactly one `chunked` coding,
/// the only one lws decodes: one instance of the header, whose value is
/// `chunked` in any case, with any spaces or tabs around it.  A list of
/// codings would need each applied in turn, and a second instance of the
/// header makes a list however the sender split it.  C's
/// `lws_http_te_is_chunked()`.
///
/// ```
/// use npro_h1::fields::transfer_encoding_is_chunked;
/// use npro_h1::head::{Config, Head, Side};
///
/// let mut h = Head::new([0u8; 512], Side::Client, Config::default())?;
/// h.rx(b"HTTP/1.1 200 OK\r\nTransfer-Encoding:  Chunked \r\n\r\n")?;
/// assert!(transfer_encoding_is_chunked(h.table()));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[must_use]
pub fn transfer_encoding_is_chunked<S: AsRef<[u8]> + AsMut<[u8]>>(table: &HeaderTable<S>) -> bool {
    let mut f = table.fragments(Token::TransferEncoding);
    let (Some(v), None) = (f.next(), f.next()) else {
        return false;
    };
    // C copies it into a 32 byte buffer, with room for its NUL
    if v.is_empty() || v.len() > 30 {
        return false;
    }
    let blank = |c: &u8| *c == b' ' || *c == b'\t';
    let start = v.iter().position(|c| !blank(c)).unwrap_or(v.len());
    let end = v
        .iter()
        .rposition(|c| !blank(c))
        .map_or(0, |n| n.saturating_add(1));
    v.get(start..end)
        .is_some_and(|v| v.eq_ignore_ascii_case(b"chunked"))
}
