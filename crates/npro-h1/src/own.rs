//! Bytes a connection writes itself, a status line and headers, held until
//! they have gone.

/// The storage an h1 connection works in, the caller's: where the peer's
/// head is parsed, and where the head the connection writes is composed.
///
/// Each is as large as the caller makes it, and the longest head either
/// way is its size: a request's or response's headers, or C's status page.
/// C composes its heads in the service thread's buffer,
/// `pt_serv_buf_size`, 4096 bytes by default; a vhost with many security
/// headers needs more than a few hundred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Storage<S> {
    /// The header table's: the peer's head, and a client's own request
    /// line and host.
    pub table: S,
    /// The head the connection writes, held until it has gone.
    pub out: S,
}

/// Why one of the application's headers is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderRefused {
    /// Its name is empty or not an RFC 9110 token.
    Name,
    /// Its value has a CR, LF or NUL.
    Value,
    /// It is one the connection writes itself, those the message's
    /// framing and the connection's fate depend on.  Sent by the
    /// application as well, the peer could read the message's framing
    /// differently from how it is sent.
    Reserved,
}

impl core::fmt::Display for HeaderRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Name => "a header name is not a token",
            Self::Value => "a header value has a CR, LF or NUL",
            Self::Reserved => "a header the connection writes itself",
        })
    }
}

impl core::error::Error for HeaderRefused {}

/// Whether `c` may be in an RFC 9110 token: `tchar`.
const fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Checks one of the application's headers: a token for a name, a value
/// that cannot end its line early, and none of `reserved`, the ones the
/// connection writes itself.
pub(crate) fn check_header(
    name: &[u8],
    value: &[u8],
    reserved: &[&[u8]],
) -> Result<(), HeaderRefused> {
    if name.is_empty() || !name.iter().all(|c| is_tchar(*c)) {
        return Err(HeaderRefused::Name);
    }
    if value.iter().any(|c| matches!(c, b'\r' | b'\n' | b'\0')) {
        return Err(HeaderRefused::Value);
    }
    if reserved.iter().any(|r| name.eq_ignore_ascii_case(r)) {
        return Err(HeaderRefused::Reserved);
    }
    Ok(())
}

/// Why a head cannot be composed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RespondError {
    /// It is not the time for one: there is nothing to answer, or it is
    /// answered already.
    NotNow,
    /// The head does not fit in [`Storage::out`].
    TooLong,
    /// One of the application's headers is refused.
    Header(HeaderRefused),
}

impl core::fmt::Display for RespondError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotNow => f.write_str("not the time for a head"),
            Self::TooLong => f.write_str("the head is too long"),
            Self::Header(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for RespondError {}

/// Bytes the connection writes itself, in the caller's storage, and how
/// many of them have gone.
#[derive(Clone, Debug)]
pub(crate) struct Own<S> {
    buf: S,
    len: usize,
    sent: usize,
}

impl<S> Own<S> {
    pub(crate) const fn new(buf: S) -> Self {
        Self {
            buf,
            len: 0,
            sent: 0,
        }
    }

    pub(crate) fn into_storage(self) -> S {
        self.buf
    }

    /// Drops what is held, gone or not.
    pub(crate) const fn clear(&mut self) {
        self.len = 0;
        self.sent = 0;
    }

    pub(crate) const fn pending(&self) -> bool {
        self.sent < self.len
    }
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Own<S> {
    /// Composes a head by `f` in place of what was held: all of it, or,
    /// if it does not fit, nothing.
    pub(crate) fn compose(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<(), RespondError>,
    ) -> Result<(), RespondError> {
        self.clear();
        let r = f(self);
        if r.is_err() {
            self.clear();
        }
        r
    }

    pub(crate) fn push(&mut self, b: &[u8]) -> Result<(), RespondError> {
        let end = self.len.checked_add(b.len()).ok_or(RespondError::TooLong)?;
        let dst = self
            .buf
            .as_mut()
            .get_mut(self.len..end)
            .ok_or(RespondError::TooLong)?;
        dst.copy_from_slice(b);
        self.len = end;
        Ok(())
    }

    pub(crate) fn push_u64(&mut self, v: u64) -> Result<(), RespondError> {
        let mut d = [0u8; 20];
        self.push(decimal(v, &mut d))
    }

    /// Writes the application's headers, each checked against
    /// `reserved` first.
    pub(crate) fn push_headers(
        &mut self,
        headers: &[(&[u8], &[u8])],
        reserved: &[&[u8]],
    ) -> Result<(), RespondError> {
        for (name, value) in headers {
            check_header(name, value, reserved).map_err(RespondError::Header)?;
            self.push(name)?;
            self.push(b": ")?;
            self.push(value)?;
            self.push(b"\r\n")?;
        }
        Ok(())
    }

    /// Writes what is left into `out`, returning how much.
    pub(crate) fn drain(&mut self, out: &mut [u8]) -> usize {
        let rest = self
            .buf
            .as_ref()
            .get(self.sent..self.len)
            .unwrap_or_default();
        let n = rest.len().min(out.len());
        if let (Some(d), Some(s)) = (out.get_mut(..n), rest.get(..n)) {
            d.copy_from_slice(s);
        }
        self.sent = self.sent.saturating_add(n);
        n
    }
}

/// `v` in decimal, written into the end of `d`.
pub(crate) fn decimal(v: u64, d: &mut [u8; 20]) -> &[u8] {
    let mut n = d.len();
    let mut v = v;
    loop {
        n = n.saturating_sub(1);
        if let Some(slot) = d.get_mut(n) {
            // v % 10 < 10
            *slot = b'0'.saturating_add(u8::try_from(v % 10).unwrap_or(0));
        }
        v /= 10;
        if v == 0 {
            break;
        }
    }
    d.get(n..).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_head_that_does_not_fit_leaves_nothing() {
        let mut o = Own::new([0u8; 8]);
        assert_eq!(o.compose(|o| o.push(b"abcd")), Ok(()));
        assert!(o.pending());
        assert_eq!(
            o.compose(|o| {
                o.push(b"abcdef")?;
                o.push(b"ghi")
            }),
            Err(RespondError::TooLong)
        );
        assert!(!o.pending());
        let mut out = [0u8; 8];
        assert_eq!(o.drain(&mut out), 0);
    }

    #[test]
    fn decimals_are_cs() {
        let mut d = [0u8; 20];
        assert_eq!(decimal(0, &mut d), b"0");
        assert_eq!(decimal(u64::MAX, &mut d), b"18446744073709551615");
    }
}
