//! Incremental UTF-8 validation, for ws text messages and close reasons
//! (RFC 6455 8.1), which arrive in pieces of any size.
//!
//! This is C's `lws_check_utf8()`: well-formed UTF-8 as RFC 3629 4 defines
//! it, so no overlong forms, no surrogates and nothing past U+10FFFF, with
//! a bad byte refused as soon as it is seen.  C keeps where it is inside a
//! character in one byte read through a table; here it is an enum, and the
//! ranges are those of RFC 3629's table.

/// The bytes are not well-formed UTF-8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid;

impl core::fmt::Display for Invalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid UTF-8")
    }
}

impl core::error::Error for Invalid {}

/// How many continuation bytes the current character still needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Left {
    One,
    Two,
    Three,
}

/// Where the validator is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Between characters.
    Boundary,
    /// Inside a character: the next byte must be in `lo..=hi`.
    Inside { left: Left, lo: u8, hi: u8 },
    /// An invalid byte was seen; nothing more is valid.
    Failed,
}

/// Validates UTF-8 fed to it in pieces.
///
/// ```
/// use npro_core::utf8::Utf8Validator;
///
/// let mut v = Utf8Validator::new();
/// let euro = "€".as_bytes(); // e2 82 ac
/// v.feed(&euro[..1])?;
/// assert!(!v.at_boundary()); // a message ending here is "partial utf8"
/// v.feed(&euro[1..])?;
/// assert!(v.at_boundary());
/// assert!(v.feed(&[0xc0, 0xaf]).is_err()); // an overlong '/'
/// # Ok::<(), npro_core::utf8::Invalid>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utf8Validator {
    state: State,
}

impl Default for Utf8Validator {
    fn default() -> Self {
        Self::new()
    }
}

impl Utf8Validator {
    /// A validator between characters, at the start of a message.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Boundary,
        }
    }

    /// Takes the next piece of the text.
    ///
    /// # Errors
    ///
    /// [`Invalid`] at the first byte that cannot be part of well-formed
    /// UTF-8, here or in an earlier piece.  After that, every piece is
    /// refused: a ws connection given invalid text closes with 1007.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), Invalid> {
        for &b in bytes {
            self.state = next(self.state, b);
            if self.state == State::Failed {
                return Err(Invalid);
            }
        }
        if self.state == State::Failed {
            return Err(Invalid);
        }
        Ok(())
    }

    /// Whether the text so far ends between characters, as a whole message
    /// must.
    #[must_use]
    pub fn at_boundary(&self) -> bool {
        self.state == State::Boundary
    }
}

/// The state after byte `b` (RFC 3629 4).
const fn next(s: State, b: u8) -> State {
    match s {
        State::Failed => State::Failed,
        State::Boundary => match b {
            0x00..=0x7f => State::Boundary,
            0xc2..=0xdf => inside(Left::One, 0x80, 0xbf),
            0xe0 => inside(Left::Two, 0xa0, 0xbf),
            0xe1..=0xec | 0xee..=0xef => inside(Left::Two, 0x80, 0xbf),
            0xed => inside(Left::Two, 0x80, 0x9f),
            0xf0 => inside(Left::Three, 0x90, 0xbf),
            0xf1..=0xf3 => inside(Left::Three, 0x80, 0xbf),
            0xf4 => inside(Left::Three, 0x80, 0x8f),
            // continuation bytes, the overlong leads c0 and c1, and leads
            // past U+10FFFF
            _ => State::Failed,
        },
        State::Inside { left, lo, hi } => {
            if b < lo || b > hi {
                return State::Failed;
            }
            match left {
                Left::One => State::Boundary,
                Left::Two => inside(Left::One, 0x80, 0xbf),
                Left::Three => inside(Left::Two, 0x80, 0xbf),
            }
        }
    }
}

const fn inside(left: Left, lo: u8, hi: u8) -> State {
    State::Inside { left, lo, hi }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What RFC 3629 says of a whole text, as the standard library says it.
    fn oracle(bytes: &[u8]) -> bool {
        core::str::from_utf8(bytes).is_ok()
    }

    fn whole(bytes: &[u8]) -> bool {
        let mut v = Utf8Validator::new();
        v.feed(bytes).is_ok() && v.at_boundary()
    }

    #[test]
    fn agrees_with_the_standard_library_on_every_short_sequence() {
        for a in 0..=255u8 {
            assert_eq!(whole(&[a]), oracle(&[a]), "{a:02x}");
            for b in 0..=255u8 {
                assert_eq!(whole(&[a, b]), oracle(&[a, b]), "{a:02x} {b:02x}");
            }
        }
        // every three bytes after a multi-byte lead
        for a in 0xc0..=0xffu8 {
            for b in 0..=255u8 {
                for c in 0..=255u8 {
                    assert_eq!(whole(&[a, b, c]), oracle(&[a, b, c]));
                }
            }
        }
    }

    #[test]
    fn the_rfc_3629_boundaries() {
        for (bytes, ok, what) in [
            (&[0xf4, 0x8f, 0xbf, 0xbf][..], true, "U+10FFFF"),
            (&[0xf4, 0x90, 0x80, 0x80][..], false, "U+110000"),
            (&[0xed, 0x9f, 0xbf][..], true, "U+D7FF"),
            (&[0xed, 0xa0, 0x80][..], false, "a surrogate"),
            (&[0xee, 0x80, 0x80][..], true, "U+E000"),
            (&[0xe0, 0x9f, 0xbf][..], false, "an overlong U+07FF"),
            (&[0xf0, 0x8f, 0xbf, 0xbf][..], false, "an overlong U+FFFF"),
            (&[0xf0, 0x90, 0x80, 0x80][..], true, "U+10000"),
        ] {
            assert_eq!(whole(bytes), ok, "{what}");
            assert_eq!(oracle(bytes), ok, "{what}");
        }
    }

    #[test]
    fn the_same_verdict_however_the_text_is_split() {
        let texts: [&[u8]; 4] = [
            "a€𝄞ç\u{10ffff}z".as_bytes(),
            &[0x61, 0xe2, 0x82, 0xac, 0xed, 0xa0, 0x80],
            &[0xf0, 0x9d, 0x84],
            &[0xe2, 0x28, 0xa1],
        ];
        for t in texts {
            let want = whole(t);
            for i in 0..=t.len() {
                for j in i..=t.len() {
                    let mut v = Utf8Validator::new();
                    let ok = v.feed(&t[..i]).is_ok()
                        && v.feed(&t[i..j]).is_ok()
                        && v.feed(&t[j..]).is_ok()
                        && v.at_boundary();
                    assert_eq!(ok, want, "{t:02x?} cut at {i} and {j}");
                }
            }
        }
    }

    #[test]
    fn a_failure_stays_failed() {
        let mut v = Utf8Validator::new();
        assert!(v.feed(&[0xff]).is_err());
        assert!(v.feed(b"fine").is_err());
        assert!(v.feed(&[]).is_err());
        assert!(!v.at_boundary());
    }
}
