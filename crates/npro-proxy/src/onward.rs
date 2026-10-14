//! The onward request's path: the origin's own prefix, then what came
//! after the route's, re-encoded, then the arguments put back together.
//! C's `lws_http_proxy_start()` with `lws_proxy_pct_encode()`.
//!
//! The parser decoded the request's path and split its query at every
//! `&`, decoding each piece; what goes to the origin is encoded again,
//! each argument's name and value separately, so a decoded `=` or `&`
//! inside one cannot change the split the origin sees.

/// The longest onward path, arguments included: C's
/// `max_http_header_data`, 1024 where nothing else is set.
pub const MAX_ONWARD: usize = 1024;

/// What is left as it is when a path is re-encoded: the unreserved
/// characters, and the `/` and `.` of a path.
const fn keep_in_path(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~' | b'/')
}

/// What is left as it is in an argument's name or value: the unreserved
/// characters alone, so `=`, `&` and `/` are encoded.
const fn keep_in_query(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~')
}

/// The onward path being composed.
#[derive(Clone, Copy, Debug)]
pub struct Onward {
    bytes: [u8; MAX_ONWARD],
    len: usize,
}

/// The onward path does not fit [`MAX_ONWARD`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLong;

impl Onward {
    /// `prefix` (the origin's own path, `/git`), a `/`, then `rest` (what
    /// came after the route's path) re-encoded, with no `/` doubled, and
    /// without a `/` on the end unless `rest` had one.
    ///
    /// # Errors
    ///
    /// [`TooLong`].
    pub fn new(prefix: &str, rest: &[u8]) -> Result<Self, TooLong> {
        let mut o = Self {
            bytes: [0; MAX_ONWARD],
            len: 0,
        };
        o.push(b"/")?;
        o.push(
            prefix
                .as_bytes()
                .strip_prefix(b"/")
                .unwrap_or(prefix.as_bytes()),
        )?;
        if !rest.is_empty() {
            if !o.as_bytes().ends_with(b"/") {
                o.push(b"/")?;
            }
            o.push_encoded(rest, keep_in_path)?;
        }
        // C's lws_clean_url(): no // in what was composed
        o.clean();
        Ok(o)
    }

    /// Adds the request's arguments, each `name=value` or `name` as the
    /// parser split them, re-encoded: `?a=1&b=2`.
    ///
    /// # Errors
    ///
    /// [`TooLong`].
    pub fn with_args<'a>(mut self, args: impl Iterator<Item = &'a [u8]>) -> Result<Self, TooLong> {
        for (i, arg) in args.enumerate() {
            self.push(if i == 0 { b"?" } else { b"&" })?;
            match arg.iter().position(|c| *c == b'=') {
                Some(eq) => {
                    self.push_encoded(arg.get(..eq).unwrap_or_default(), keep_in_query)?;
                    self.push(b"=")?;
                    self.push_encoded(
                        arg.get(eq.saturating_add(1)..).unwrap_or_default(),
                        keep_in_query,
                    )?;
                }
                None => self.push_encoded(arg, keep_in_query)?,
            }
        }
        Ok(self)
    }

    fn push(&mut self, more: &[u8]) -> Result<(), TooLong> {
        let end = self
            .len
            .checked_add(more.len())
            .filter(|e| *e <= MAX_ONWARD)
            .ok_or(TooLong)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(TooLong)?
            .copy_from_slice(more);
        self.len = end;
        Ok(())
    }

    fn push_encoded(&mut self, bytes: &[u8], keep: fn(u8) -> bool) -> Result<(), TooLong> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for c in bytes {
            if keep(*c) {
                self.push(&[*c])?;
            } else {
                let hi = HEX.get(usize::from(*c >> 4)).copied().unwrap_or(b'0');
                let lo = HEX.get(usize::from(*c & 0xf)).copied().unwrap_or(b'0');
                self.push(&[b'%', hi, lo])?;
            }
        }
        Ok(())
    }

    /// Takes out any `//`, as C's `lws_clean_url()` does.
    fn clean(&mut self) {
        let mut out = 0usize;
        for i in 0..self.len {
            let c = self.bytes.get(i).copied().unwrap_or(0);
            let doubled = c == b'/'
                && out > 0
                && self.bytes.get(out.saturating_sub(1)).copied() == Some(b'/');
            if doubled {
                continue;
            }
            if let Some(b) = self.bytes.get_mut(out) {
                *b = c;
            }
            out = out.saturating_add(1);
        }
        self.len = out;
    }

    /// The path, as the onward request's.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;

    fn path(prefix: &str, rest: &[u8], args: &[&[u8]]) -> Vec<u8> {
        Onward::new(prefix, rest)
            .unwrap()
            .with_args(args.iter().copied())
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn the_prefix_and_the_rest_are_joined_once_and_re_encoded() {
        assert_eq!(path("/git", b"", &[]), b"/git");
        assert_eq!(path("/git", b"repo.git/info", &[]), b"/git/repo.git/info");
        assert_eq!(path("git/", b"x", &[]), b"/git/x");
        assert_eq!(path("/", b"a b/c", &[]), b"/a%20b/c");
        assert_eq!(path("", b"", &[]), b"/");
        assert_eq!(path("/sai", b"x/", &[]), b"/sai/x/");
        assert_eq!(path("/p", b"\xc3\xa9?#", &[]), b"/p/%C3%A9%3F%23");
    }

    #[test]
    fn arguments_are_put_back_each_name_and_value_encoded_apart() {
        assert_eq!(
            path("/", b"q", &[b"a=1", b"b=x&y=2", b"flag", b"c=d=e"]),
            b"/q?a=1&b=x%26y%3D2&flag&c=d%3De"
        );
        assert_eq!(path("/", b"", &[b"a b=c/d"]), b"/?a%20b=c%2Fd");
    }

    #[test]
    fn too_long_is_refused() {
        let long = [b'a'; MAX_ONWARD];
        assert_eq!(Onward::new("/", &long).err(), Some(TooLong));
        let fits = Onward::new("/", &long[..MAX_ONWARD - 1]).unwrap();
        assert_eq!(fits.as_bytes().len(), MAX_ONWARD);
        assert_eq!(fits.with_args([&b"a"[..]].into_iter()).err(), Some(TooLong));
    }
}
