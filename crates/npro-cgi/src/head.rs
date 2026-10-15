//! The script's answer's head, parsed from its stdout: C's
//! `lws_cgi_write_split_stdout_headers()` before the payload.
//!
//! A script writes headers first, `Name: value` lines, then a blank
//! line, then its payload.  C reads them a byte at a time into a 2K
//! buffer, taking a line to end at CRLF or at LF alone, and looks for
//! `Status`, `Content-Length`, `Location` (which makes the answer a 302)
//! and `Transfer-Encoding: chunked`; the other headers go to the client
//! as they are.  This takes the bytes as they come, in the pieces the
//! runner reads, into storage of its own, and says how many of the last
//! piece were the head's: the rest are the payload's first.

/// The most the head may be, blank line included: C's buffer.
pub const MAX_HEAD: usize = 2048;

/// What a script answers with no `Status` and no `Location`.
const DEFAULT_STATUS: u16 = 200;

/// Why the head was not taken: the script's answer is then no answer,
/// as C drops the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadError {
    /// It does not fit [`MAX_HEAD`].
    TooLong,
    /// A line is no header: no `:` after a token, or a NUL.
    Malformed,
}

impl core::fmt::Display for HeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "the script's head does not fit",
            Self::Malformed => "the script's head has a line that is no header",
        })
    }
}

impl core::error::Error for HeadError {}

/// What [`Head::feed`] came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// The head is not whole yet: feed it more.
    More,
    /// The head is whole, and took this much of the piece: the rest of
    /// the piece is the payload's.
    Done {
        /// How many bytes of the piece were the head's.
        consumed: usize,
    },
}

/// The head, being taken.
#[derive(Clone, Copy, Debug)]
pub struct Head {
    /// The lines, each ended by LF alone, the blank line not kept.
    buf: [u8; MAX_HEAD],
    len: usize,
    /// Whether the last byte taken was a CR, dropped, awaiting its LF.
    cr: bool,
    done: bool,
}

impl Default for Head {
    fn default() -> Self {
        Self::new()
    }
}

impl Head {
    /// Nothing taken yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_HEAD],
            len: 0,
            cr: false,
            done: false,
        }
    }

    /// Takes the next piece of the script's stdout.
    ///
    /// # Errors
    ///
    /// [`HeadError`], and nothing more is taken.
    pub fn feed(&mut self, piece: &[u8]) -> Result<Progress, HeadError> {
        if self.done {
            return Ok(Progress::Done { consumed: 0 });
        }
        for (i, &c) in piece.iter().enumerate() {
            match c {
                b'\r' => {
                    if self.cr {
                        return Err(HeadError::Malformed);
                    }
                    self.cr = true;
                }
                b'\n' => {
                    self.cr = false;
                    // a blank line ends the head
                    if self.len == 0 || self.buf.get(self.len.wrapping_sub(1)) == Some(&b'\n') {
                        self.done = true;
                        return Ok(Progress::Done {
                            consumed: i.saturating_add(1),
                        });
                    }
                    self.check_last_line()?;
                    self.push(b'\n')?;
                }
                0 => return Err(HeadError::Malformed),
                other => {
                    if self.cr {
                        // a CR not followed by LF: C drops the connection
                        return Err(HeadError::Malformed);
                    }
                    self.push(other)?;
                }
            }
        }
        Ok(Progress::More)
    }

    /// The head, once [`Progress::Done`] said it is whole.  Before that,
    /// what has come so far.
    #[must_use]
    pub fn parsed(&self) -> Parsed<'_> {
        let lines = self.buf.get(..self.len).unwrap_or_default();
        let mut p = Parsed {
            status: DEFAULT_STATUS,
            content_length: None,
            content_type: None,
            chunked: false,
            lines,
        };
        let mut status_given = false;
        for (name, value) in lines_of(lines) {
            if name.eq_ignore_ascii_case(b"status") {
                let digits: &[u8] = value.split(|b| *b == b' ').next().unwrap_or_default();
                if let Some(code) = decimal(digits).and_then(|n| u16::try_from(n).ok()) {
                    p.status = code;
                    status_given = true;
                }
            } else if name.eq_ignore_ascii_case(b"content-length") {
                p.content_length = decimal(value);
            } else if name.eq_ignore_ascii_case(b"content-type") {
                p.content_type = Some(value);
            } else if name.eq_ignore_ascii_case(b"location") && !status_given {
                // C: a Location mandates a 302
                p.status = 302;
            } else if name.eq_ignore_ascii_case(b"transfer-encoding")
                && value.eq_ignore_ascii_case(b"chunked")
            {
                p.chunked = true;
            }
        }
        p
    }

    fn push(&mut self, c: u8) -> Result<(), HeadError> {
        let at = self.buf.get_mut(self.len).ok_or(HeadError::TooLong)?;
        *at = c;
        self.len = self.len.saturating_add(1);
        Ok(())
    }

    /// The line just ended is a header: a token, a `:`, a value.
    fn check_last_line(&self) -> Result<(), HeadError> {
        let all = self.buf.get(..self.len).unwrap_or_default();
        let start = all
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |i| i.saturating_add(1));
        let line = all.get(start..).unwrap_or_default();
        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or(HeadError::Malformed)?;
        let name = line.get(..colon).unwrap_or_default();
        if name.is_empty() || !name.iter().all(|b| is_token(*b)) {
            return Err(HeadError::Malformed);
        }
        Ok(())
    }
}

/// A header name's characters: RFC 9110's token.
const fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
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

/// `digits` as a number, if that is all they are.
fn decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    digits.iter().try_fold(0u64, |n, d| {
        n.checked_mul(10)?
            .checked_add(u64::from(d.wrapping_sub(b'0')))
    })
}

/// The head, read: [`Head::parsed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parsed<'h> {
    /// The status: `Status`'s code, else 302 with a `Location`, else
    /// 200.
    pub status: u16,
    /// `Content-Length`, if the script gave one.
    pub content_length: Option<u64>,
    /// `Content-Type`, if the script gave one.
    pub content_type: Option<&'h [u8]>,
    /// Whether the script said `Transfer-Encoding: chunked`: its payload
    /// is framed already, and goes to the client as it is.
    pub chunked: bool,
    lines: &'h [u8],
}

/// Each header line of `lines`: its name and its value, the value
/// without the space after the `:`.
fn lines_of(lines: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    lines
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| {
            let colon = l.iter().position(|b| *b == b':').unwrap_or(l.len());
            let value = l.get(colon.saturating_add(1)..).unwrap_or_default();
            let trimmed = value
                .iter()
                .position(|b| *b != b' ' && *b != b'\t')
                .map_or(&[][..], |i| value.get(i..).unwrap_or_default());
            (l.get(..colon).unwrap_or_default(), trimmed)
        })
}

impl<'h> Parsed<'h> {
    /// Every header line: its name and its value, the value without the
    /// space after the `:`.
    pub fn lines(&self) -> impl Iterator<Item = (&'h [u8], &'h [u8])> + use<'h> {
        lines_of(self.lines)
    }

    /// The headers to pass to the client as the application's own: every
    /// line but those the answer is composed from (`Status`,
    /// `Content-Length`, `Content-Type`) and those the connection owns
    /// (`Transfer-Encoding`, `Connection`).
    pub fn passed(&self) -> impl Iterator<Item = (&'h [u8], &'h [u8])> + use<'h> {
        self.lines().filter(|(name, _)| {
            !name.eq_ignore_ascii_case(b"status")
                && !name.eq_ignore_ascii_case(b"content-length")
                && !name.eq_ignore_ascii_case(b"content-type")
                && !name.eq_ignore_ascii_case(b"transfer-encoding")
                && !name.eq_ignore_ascii_case(b"connection")
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use super::*;

    fn whole(bytes: &[u8]) -> (Head, Result<Progress, HeadError>) {
        let mut h = Head::new();
        let r = h.feed(bytes);
        (h, r)
    }

    #[test]
    fn gits_head_is_taken_with_its_payloads_start_left() {
        let out =
            b"Status: 200 OK\r\nExpires: Fri, 01 Jan 1980 00:00:00 GMT\r\nPragma: no-cache\r\n\
                    Cache-Control: no-cache, max-age=0, must-revalidate\r\n\
                    Content-Type: application/x-git-upload-pack-advertisement\r\n\r\n001e# service";
        let (h, r) = whole(out);
        assert_eq!(
            r,
            Ok(Progress::Done {
                consumed: out.len() - 13
            })
        );
        let p = h.parsed();
        assert_eq!(p.status, 200);
        assert_eq!(p.content_length, None);
        assert_eq!(
            p.content_type,
            Some(&b"application/x-git-upload-pack-advertisement"[..])
        );
        assert!(!p.chunked);
        let passed: Vec<(&[u8], &[u8])> = p.passed().collect();
        assert_eq!(
            passed,
            [
                (&b"Expires"[..], &b"Fri, 01 Jan 1980 00:00:00 GMT"[..]),
                (b"Pragma", b"no-cache"),
                (b"Cache-Control", b"no-cache, max-age=0, must-revalidate"),
            ]
        );
        // whole, it takes nothing more
        let mut h = h;
        assert_eq!(h.feed(b"more"), Ok(Progress::Done { consumed: 0 }));
    }

    #[test]
    fn a_head_comes_in_pieces_and_lf_alone_ends_a_line() {
        let mut h = Head::new();
        assert_eq!(h.feed(b"Content-Length: 1"), Ok(Progress::More));
        assert_eq!(h.feed(b"2\nX-A: b\n"), Ok(Progress::More));
        assert_eq!(h.feed(b"\nrest"), Ok(Progress::Done { consumed: 1 }));
        let p = h.parsed();
        assert_eq!((p.status, p.content_length), (200, Some(12)));
        assert_eq!(p.passed().collect::<Vec<_>>(), [(&b"X-A"[..], &b"b"[..])]);
        // CRLF then LF alone is a blank line too
        let (mixed, r2) = whole(b"X: 1\r\n\n");
        assert_eq!(r2, Ok(Progress::Done { consumed: 7 }));
        assert_eq!(mixed.parsed().lines().count(), 1);
        // and the blank line may come first: no headers
        let (none, r3) = whole(b"\r\nbody");
        assert_eq!(r3, Ok(Progress::Done { consumed: 2 }));
        assert_eq!(none.parsed().status, 200);
    }

    #[test]
    fn a_location_makes_a_302_unless_the_status_says() {
        let status = |bytes: &[u8]| whole(bytes).0.parsed().status;
        assert_eq!(status(b"Location: /there\r\n\r\n"), 302);
        assert_eq!(
            status(b"Location: /there\r\nStatus: 301 Moved\r\n\r\n"),
            301
        );
        assert_eq!(status(b"Status: 404\r\nLocation: /x\r\n\r\n"), 404);
        // a status that is no number is as if not given
        assert_eq!(status(b"Status: abc\r\n\r\n"), 200);
        let (chunked, _) = whole(b"Transfer-Encoding: Chunked\r\n\r\n");
        assert!(chunked.parsed().chunked);
        assert_eq!(chunked.parsed().passed().count(), 0);
    }

    #[test]
    fn what_is_no_header_or_does_not_fit_is_refused() {
        assert_eq!(
            whole(b"HTTP/1.1 200 OK\r\n\r\n").1,
            Err(HeadError::Malformed)
        );
        assert_eq!(whole(b": no name\r\n\r\n").1, Err(HeadError::Malformed));
        assert_eq!(whole(b"bad name: x\r\n\r\n").1, Err(HeadError::Malformed));
        assert_eq!(whole(b"X: 1\rY: 2\r\n\r\n").1, Err(HeadError::Malformed));
        assert_eq!(whole(b"X: 1\r\r\n\r\n").1, Err(HeadError::Malformed));
        assert_eq!(whole(b"X: a\0b\r\n\r\n").1, Err(HeadError::Malformed));
        let long = [b'x'; MAX_HEAD + 1];
        assert_eq!(whole(&long).1, Err(HeadError::TooLong));
        let mut just = Vec::from(b"X: ");
        just.resize(MAX_HEAD, b'y');
        just.extend_from_slice(b"\r\n\r\n");
        assert_eq!(whole(&just).1, Err(HeadError::TooLong));
        just.truncate(MAX_HEAD - 1);
        just.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            whole(&just).1,
            Ok(Progress::Done {
                consumed: MAX_HEAD + 3
            })
        );
    }
}
