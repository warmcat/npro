//! Bytes a connection writes itself, a status line and headers, held until
//! they have gone.

/// The most bytes a head the connection writes may have: its first line
/// and headers, or a status page with them.
pub const MAX_OWN: usize = 512;

/// Why a head cannot be composed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RespondError {
    /// It is not the time for one: there is nothing to answer, or it is
    /// answered already.
    NotNow,
    /// The head does not fit in [`MAX_OWN`].
    TooLong,
}

impl core::fmt::Display for RespondError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotNow => "not the time for a head",
            Self::TooLong => "the head is too long",
        })
    }
}

impl core::error::Error for RespondError {}

/// Bytes the connection writes itself, and how many of them have gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Own {
    pub(crate) buf: [u8; MAX_OWN],
    pub(crate) len: usize,
    sent: usize,
}

impl Own {
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0; MAX_OWN],
            len: 0,
            sent: 0,
        }
    }

    pub(crate) fn push(&mut self, b: &[u8]) -> Result<(), RespondError> {
        let end = self.len.checked_add(b.len()).ok_or(RespondError::TooLong)?;
        let dst = self
            .buf
            .get_mut(self.len..end)
            .ok_or(RespondError::TooLong)?;
        dst.copy_from_slice(b);
        self.len = end;
        Ok(())
    }

    pub(crate) fn push_u64(&mut self, v: u64) -> Result<(), RespondError> {
        let mut d = [0u8; 20];
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
        self.push(d.get(n..).unwrap_or_default())
    }

    pub(crate) const fn pending(&self) -> bool {
        self.sent < self.len
    }

    /// Writes what is left into `out`, returning how much.
    pub(crate) fn drain(&mut self, out: &mut [u8]) -> usize {
        let rest = self.buf.get(self.sent..self.len).unwrap_or_default();
        let n = rest.len().min(out.len());
        if let (Some(d), Some(s)) = (out.get_mut(..n), rest.get(..n)) {
            d.copy_from_slice(s);
        }
        self.sent = self.sent.saturating_add(n);
        n
    }
}
