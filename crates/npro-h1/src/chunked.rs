//! The chunked transfer coding (RFC 9112 7.1): C's
//! `lws_http_dechunk_framing()`, one decoder for a server's request bodies
//! and a client's response bodies.
//!
//! The framing is consumed and the payload handed back where it lies in
//! the input, so nothing is copied.  As in C:
//!
//! - a chunk size has at least one hex digit, and is less than 2^31;
//! - chunk extensions (`;name=value` after the size) and trailer fields
//!   (header lines after the last chunk) are skipped, but no more than
//!   [`SKIP_MAX`] bytes of them in a body, so a peer cannot keep a
//!   connection busy with an endless one;
//! - every line ends CRLF: a bare CR or LF is where something else framing
//!   the body may disagree, and is refused.

/// The most bytes of chunk extensions and trailers one body may have: C's
/// `LWS_HTTP_CHUNK_SKIP_MAX`.
pub const SKIP_MAX: u16 = 4096;

/// The largest chunk-size before another digit: C keeps the size in an
/// `int`, and refuses a digit that could take it past `INT_MAX`.
const SIZE_MAX_BEFORE_DIGIT: u32 = (0x7fff_ffff - 15) / 16;

/// Why a chunked body cannot be framed.  None can be recovered from: the
/// connection's bytes are out of step with the peer's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The chunk-size does not start with a hex digit.
    SizeNotHex,
    /// The chunk-size is 2^31 or more.
    SizeOverflow,
    /// The chunk-size is followed by something not an extension or CR.
    SizeLineGarbage,
    /// A chunk extension has a bare LF.
    ExtensionBareLf,
    /// The extensions and trailers are past [`SKIP_MAX`].
    SkipTooLong,
    /// The chunk-size line's CR is not followed by LF.
    SizeLineNoLf,
    /// A chunk's data is not followed by CR.
    DataNoCr,
    /// A chunk's data is not followed by CRLF.
    DataNoLf,
    /// A trailer line has a bare LF.
    TrailerBareLf,
    /// A trailer line has a bare CR.
    TrailerBareCr,
    /// The CR ending the trailers is not followed by LF.
    TrailersNoLf,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::SizeNotHex => "chunk size not hex",
            Self::SizeOverflow => "chunk size overflow",
            Self::SizeLineGarbage => "chunk size line garbage",
            Self::ExtensionBareLf => "chunk extension: bare LF",
            Self::SkipTooLong => "chunk extensions or trailers too long",
            Self::SizeLineNoLf => "chunk size line: no LF",
            Self::DataNoCr => "chunk payload: no CR",
            Self::DataNoLf => "chunk payload: no LF",
            Self::TrailerBareLf => "chunk trailer: bare LF",
            Self::TrailerBareCr => "chunk trailer: bare CR",
            Self::TrailersNoLf => "chunk trailer: no LF",
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}

/// Where the decoder is: C's `enum lws_chunk_parser`, with the chunk's
/// size or what is left of it where there is one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// The first hex digit of a chunk-size: `ELCP_HEX`.
    Hex,
    /// More of a chunk-size: `ELCP_HEX_MORE`.
    HexMore(u32),
    /// A chunk extension, skipped to its CR: `ELCP_EXT`.
    Ext(u32),
    /// The LF ending the chunk-size line: `ELCP_CR`.
    Cr(u32),
    /// A chunk's data, this much of it still to come: `ELCP_CONTENT`.
    Data(u32),
    /// The CR after a chunk's data: `ELCP_POST_CR`.
    PostCr,
    /// The LF after a chunk's data: `ELCP_POST_LF`.
    PostLf,
    /// After the last chunk, a trailer line or the CR ending them:
    /// `ELCP_TRAILER_CR`.
    TrailerCr,
    /// A trailer line, skipped: `ELCP_TRAILER_SKIP`.
    TrailerSkip,
    /// The LF ending a trailer line: `ELCP_TRAILER_SKIP_LF`.
    TrailerSkipLf,
    /// The LF ending the trailers, and the body: `ELCP_TRAILER_LF`.
    TrailerLf,
    /// The body is over.
    Done,
    /// The framing was refused.
    Failed(Error),
}

/// What a step of the decoder found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chunk<'a> {
    /// The bytes were all framing, and the body is not over.
    More,
    /// The next bytes of the body.
    Data(&'a [u8]),
    /// The body is over.
    End,
}

/// A step of the decoder: how much of the input it took, and what it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step<'a> {
    /// How many bytes of the input were taken, framing and data.
    pub consumed: usize,
    /// What they were.
    pub chunk: Chunk<'a>,
}

/// A chunked body's decoder.
///
/// ```
/// use npro_h1::chunked::{Chunk, Dechunk};
///
/// let mut d = Dechunk::new();
/// let mut body = &b"5;x=y\r\nhello\r\n0\r\nTrailer: t\r\n\r\nnext"[..];
/// let mut got = Vec::new();
/// loop {
///     let step = d.step(body)?;
///     body = &body[step.consumed..];
///     match step.chunk {
///         Chunk::Data(d) => got.extend_from_slice(d),
///         Chunk::More => {}
///         Chunk::End => break,
///     }
/// }
/// assert_eq!(got, b"hello");
/// assert_eq!(body, b"next");
/// # Ok::<(), npro_h1::chunked::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dechunk {
    state: State,
    /// Extension and trailer bytes skipped in this body: C's
    /// `chunk_skip`.
    skipped: u16,
}

impl Default for Dechunk {
    fn default() -> Self {
        Self::new()
    }
}

impl Dechunk {
    /// A decoder at the start of a body.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Hex,
            skipped: 0,
        }
    }

    /// Whether the body is over.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Takes framing from the start of `input` until it reaches data, the
    /// end of the body or the end of `input`; then, at data, takes as much
    /// of the chunk as `input` has.  A caller taking the body at its own
    /// pace hands in no more than it wants.
    ///
    /// # Errors
    ///
    /// The [`Error`] in the framing.  The decoder stays failed: every
    /// later step says the same.
    pub fn step<'a>(&mut self, input: &'a [u8]) -> Result<Step<'a>, Error> {
        let mut used = 0usize;
        loop {
            match self.state {
                State::Failed(e) => return Err(e),
                State::Done => {
                    return Ok(Step {
                        consumed: used,
                        chunk: Chunk::End,
                    });
                }
                State::Data(left) => {
                    let rest = input.get(used..).unwrap_or_default();
                    let n = rest.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                    if n == 0 {
                        return Ok(Step {
                            consumed: used,
                            chunk: Chunk::More,
                        });
                    }
                    let data = rest.get(..n).unwrap_or_default();
                    let n32 = u32::try_from(n).unwrap_or(left);
                    let left = left.saturating_sub(n32);
                    self.state = if left == 0 {
                        State::PostCr
                    } else {
                        State::Data(left)
                    };
                    return Ok(Step {
                        consumed: used.saturating_add(n),
                        chunk: Chunk::Data(data),
                    });
                }
                State::Hex
                | State::HexMore(_)
                | State::Ext(_)
                | State::Cr(_)
                | State::PostCr
                | State::PostLf
                | State::TrailerCr
                | State::TrailerSkip
                | State::TrailerSkipLf
                | State::TrailerLf => {}
            }
            let Some(&c) = input.get(used) else {
                return Ok(Step {
                    consumed: used,
                    chunk: Chunk::More,
                });
            };
            used = used.saturating_add(1);
            match self.framing(c) {
                Ok(state) => self.state = state,
                Err(e) => {
                    self.state = State::Failed(e);
                    return Err(e);
                }
            }
        }
    }

    /// One byte of the framing.
    fn framing(&mut self, c: u8) -> Result<State, Error> {
        Ok(match self.state {
            State::Hex | State::HexMore(_) => {
                let size = match self.state {
                    State::HexMore(s) => Some(s),
                    State::Hex
                    | State::Ext(_)
                    | State::Cr(_)
                    | State::Data(_)
                    | State::PostCr
                    | State::PostLf
                    | State::TrailerCr
                    | State::TrailerSkip
                    | State::TrailerSkipLf
                    | State::TrailerLf
                    | State::Done
                    | State::Failed(_) => None,
                };
                if let Some(d) = hex(c) {
                    let s = size.unwrap_or(0);
                    if s > SIZE_MAX_BEFORE_DIGIT {
                        return Err(Error::SizeOverflow);
                    }
                    return Ok(State::HexMore((s << 4) | u32::from(d)));
                }
                // the chunk-size must have at least one hex digit
                let Some(s) = size else {
                    return Err(Error::SizeNotHex);
                };
                if c == b'\r' {
                    return Ok(State::Cr(s));
                }
                if c != b';' && c != b' ' && c != b'\t' {
                    return Err(Error::SizeLineGarbage);
                }
                // a chunk extension, skipped up to its CR, starting here
                self.ext(c, s)?
            }
            State::Ext(s) => self.ext(c, s)?,
            State::Cr(s) => {
                if c != b'\n' {
                    return Err(Error::SizeLineNoLf);
                }
                // a zero-length chunk is the last, and trailers follow
                if s == 0 {
                    State::TrailerCr
                } else {
                    State::Data(s)
                }
            }
            State::PostCr => {
                if c != b'\r' {
                    return Err(Error::DataNoCr);
                }
                State::PostLf
            }
            State::PostLf => {
                if c != b'\n' {
                    return Err(Error::DataNoLf);
                }
                State::Hex
            }
            State::TrailerCr => {
                // the CRLF ending the trailers, or a trailer line's first
                // byte, skipped with the rest of it
                if c == b'\r' {
                    State::TrailerLf
                } else {
                    self.trailer(c)?
                }
            }
            State::TrailerSkip => self.trailer(c)?,
            State::TrailerSkipLf => {
                if c != b'\n' {
                    return Err(Error::TrailerBareCr);
                }
                State::TrailerCr
            }
            State::TrailerLf => {
                if c != b'\n' {
                    return Err(Error::TrailersNoLf);
                }
                State::Done
            }
            // step() does not ask for these
            State::Data(s) => State::Data(s),
            State::Done => State::Done,
            State::Failed(e) => return Err(e),
        })
    }

    /// A byte of a chunk extension, the chunk's size being `s`.
    fn ext(&mut self, c: u8, s: u32) -> Result<State, Error> {
        if c == b'\r' {
            return Ok(State::Cr(s));
        }
        if c == b'\n' {
            return Err(Error::ExtensionBareLf);
        }
        self.skip()?;
        Ok(State::Ext(s))
    }

    /// A byte of a trailer line.
    fn trailer(&mut self, c: u8) -> Result<State, Error> {
        self.skip()?;
        if c == b'\n' {
            return Err(Error::TrailerBareLf);
        }
        Ok(if c == b'\r' {
            State::TrailerSkipLf
        } else {
            State::TrailerSkip
        })
    }

    const fn skip(&mut self) -> Result<(), Error> {
        self.skipped = self.skipped.saturating_add(1);
        if self.skipped > SKIP_MAX {
            return Err(Error::SkipTooLong);
        }
        Ok(())
    }
}

const fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;

    type Case = (&'static [u8], Result<(&'static [u8], usize), Error>);

    /// The body's data, and how many bytes the body had, or the error.
    fn decode(mut input: &[u8], piece: usize) -> Result<(Vec<u8>, usize), Error> {
        let mut d = Dechunk::new();
        let (mut data, mut used) = (Vec::new(), 0usize);
        loop {
            let take = input.len().min(piece);
            let step = d.step(input.get(..take).unwrap_or_default())?;
            input = input.get(step.consumed..).unwrap_or_default();
            used = used.saturating_add(step.consumed);
            match step.chunk {
                Chunk::Data(b) => data.extend_from_slice(b),
                Chunk::End => return Ok((data, used)),
                Chunk::More if input.is_empty() => return Ok((data, usize::MAX)),
                Chunk::More => {}
            }
        }
    }

    #[test]
    fn bodies_and_their_ends() {
        let cases: [Case; 14] = [
            (b"0\r\n\r\n", Ok((b"", 5))),
            (b"3\r\nabc\r\n0\r\n\r\nX", Ok((b"abc", 13))),
            (b"A\r\n0123456789\r\n0\r\n\r\n", Ok((b"0123456789", 20))),
            (
                b"3;a=b c\r\nabc\r\n0\r\nT: 1\r\nU: 2\r\n\r\n",
                Ok((b"abc", 31)),
            ),
            (b"03 \r\nabc\r\n0\r\n\r\n", Ok((b"abc", 15))),
            (b"\r\n", Err(Error::SizeNotHex)),
            (b";x\r\n", Err(Error::SizeNotHex)),
            (b"3x\r\n", Err(Error::SizeLineGarbage)),
            (b"3;x\n", Err(Error::ExtensionBareLf)),
            (b"3\rx", Err(Error::SizeLineNoLf)),
            (b"1\r\nab", Err(Error::DataNoCr)),
            (b"1\r\na\rb", Err(Error::DataNoLf)),
            (b"0\r\nT: 1\n", Err(Error::TrailerBareLf)),
            (b"0\r\nT: 1\rx", Err(Error::TrailerBareCr)),
        ];
        for (input, want) in cases {
            let want = want.map(|(d, n)| (d.to_vec(), n));
            for piece in 1..=input.len() {
                assert_eq!(decode(input, piece), want, "{input:?} in {piece}s");
            }
        }
        assert_eq!(decode(b"0\r\n\rx", 9), Err(Error::TrailersNoLf));
    }

    #[test]
    fn a_size_of_2_31_or_more_is_refused() {
        assert_eq!(decode(b"7fffffff\r\n", 64), Ok((Vec::new(), usize::MAX)));
        assert_eq!(decode(b"80000000\r\n", 64), Err(Error::SizeOverflow));
        assert_eq!(
            decode(b"000000000000000001\r\na\r\n0\r\n\r\n", 64),
            Ok((b"a".to_vec(), 28))
        );
    }

    #[test]
    fn extensions_and_trailers_share_one_bound() {
        let mut b = Vec::from(&b"1;"[..]);
        b.extend(core::iter::repeat_n(b'x', 4000));
        b.extend_from_slice(b"\r\na\r\n0\r\nT: ");
        // As in C, the ';' counts and the extension's CR does not: 4001.
        // Of the trailer line, "T: ", the y's and its CR count, its LF
        // and the CRLF ending the trailers do not: 4096 is the most
        let mut ok = b.clone();
        ok.extend(core::iter::repeat_n(b'y', 4096 - 4001 - 3 - 1));
        ok.extend_from_slice(b"\r\n\r\n");
        assert!(decode(&ok, 4096).is_ok());
        b.extend(core::iter::repeat_n(b'y', 4096 - 4001 - 3));
        b.extend_from_slice(b"\r\n\r\n");
        assert_eq!(decode(&b, 4096), Err(Error::SkipTooLong));
    }

    #[test]
    fn a_failed_decoder_stays_failed() {
        let mut d = Dechunk::new();
        assert_eq!(d.step(b"x"), Err(Error::SizeNotHex));
        assert_eq!(d.step(b"0\r\n\r\n"), Err(Error::SizeNotHex));
    }
}
