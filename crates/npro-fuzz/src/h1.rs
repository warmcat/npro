//! The h1 targets: the head parser as a server and as a client, and the
//! dechunker.

use core::num::NonZeroU16;

use npro_h1::chunked::{Chunk, Dechunk, SKIP_MAX};
use npro_h1::head::{Config, Head, Progress, Refused, Side, UnknownMethod};
use npro_h1::table::{DEFAULT_CAPACITY, HeaderTable};
use npro_h1::token::Token;

use crate::targets::{Pieces, control, finding};

/// The configuration the input's control byte chooses: C's defaults, or a
/// small table with token limits and unknown methods falling back, so
/// limits are reached by inputs libFuzzer can grow to.
fn config(ctl: u8) -> (usize, Config) {
    if ctl & 0x80 == 0 {
        return (DEFAULT_CAPACITY, Config::new());
    }
    let limit = |n| NonZeroU16::new(n).unwrap_or(NonZeroU16::MIN);
    (
        256,
        Config::new()
            .with_limit(Token::GetUri, limit(33))
            .with_limit(Token::UserAgent, limit(16))
            .with_limit(Token::Host, limit(24))
            .with_limit(Token::Cookie, limit(48))
            .with_unknown_method(UnknownMethod::Fallback),
    )
}

/// Everything a parsed head is: the verdict, and the table it left.
#[derive(Debug, PartialEq, Eq)]
struct Parsed {
    verdict: Result<Progress, Refused>,
    used: usize,
    tokens: Vec<(Token, Vec<Vec<u8>>)>,
    unknown: Vec<(Vec<u8>, Vec<u8>)>,
}

fn parsed(h: &Head<Vec<u8>>, verdict: Result<Progress, Refused>) -> Parsed {
    let t = h.table();
    Parsed {
        verdict,
        used: t.used(),
        tokens: Token::ALL
            .into_iter()
            .filter(|tok| t.is_present(*tok))
            .map(|tok| (tok, t.fragments(tok).map(<[u8]>::to_vec).collect()))
            .collect(),
        unknown: t
            .unknown_headers()
            .map(|(n, v)| (n.to_vec(), v.to_vec()))
            .collect(),
    }
}

fn head(target: &str, side: Side, cap: usize, config: Config) -> Head<Vec<u8>> {
    let mut table = HeaderTable::new(vec![0u8; cap])
        .unwrap_or_else(|e| finding(target, format_args!("a table of {cap}: {e}")));
    if side == Side::Client {
        // a client's table holds its own request first
        for (t, v) in [(Token::ClientUri, &b"/x"[..]), (Token::ClientHost, b"h")] {
            if let Err(e) = table.create(t, v) {
                finding(target, format_args!("client's own {t:?}: {e}"));
            }
        }
    }
    Head::with_table(table, side, config)
}

/// The head given in one piece.
fn whole(target: &str, side: Side, ctl: u8, bytes: &[u8]) -> Parsed {
    let (cap, config) = config(ctl);
    let mut h = head(target, side, cap, config);
    let verdict = if bytes.is_empty() {
        Ok(Progress::More)
    } else {
        h.rx(bytes)
    };
    // a refused head stays refused, saying the same
    if let Err(r) = verdict {
        if h.rx(b"\r\n\r\n") != Err(r) {
            finding(target, format_args!("refused with {r}, then not"));
        }
    }
    parsed(&h, verdict)
}

/// The head given in pieces.
fn in_pieces(target: &str, side: Side, ctl: u8, bytes: &[u8]) -> Parsed {
    let (cap, config) = config(ctl);
    let mut h = head(target, side, cap, config);
    let mut verdict = Ok(Progress::More);
    let mut at = 0usize;
    for piece in Pieces::new(ctl, bytes) {
        verdict = h.rx(piece).map(|p| match p {
            Progress::Complete { consumed } => Progress::Complete {
                consumed: consumed.saturating_add(at),
            },
            Progress::More | Progress::Fallback => p,
        });
        if verdict != Ok(Progress::More) {
            break;
        }
        at = at.saturating_add(piece.len());
    }
    parsed(&h, verdict)
}

/// What every parsed head must be, whatever the bytes were.
fn check(target: &str, p: &Parsed, len: usize, cap: usize) {
    if let Ok(Progress::Complete { consumed }) = p.verdict {
        if consumed == 0 || consumed > len {
            finding(target, format_args!("consumed {consumed} of {len}"));
        }
    }
    if p.used > cap {
        finding(target, format_args!("used {} of {cap}", p.used));
    }
    // the bytes that end a line, or every value, are never in one
    let bad = |v: &[u8]| v.iter().any(|c| matches!(c, b'\r' | b'\n' | 0));
    for (t, frags) in &p.tokens {
        if frags.iter().any(|f| bad(f)) {
            finding(target, format_args!("{t:?} has a CR, LF or NUL: {frags:?}"));
        }
    }
    for (n, v) in &p.unknown {
        if bad(v) || n.contains(&0) {
            finding(target, format_args!("unknown {n:?} = {v:?}"));
        }
    }
    // a complete request's path is never above its root, nor has a step
    // that is not one (a refused head's is wherever it stopped, and goes
    // nowhere)
    if !matches!(p.verdict, Ok(Progress::Complete { .. })) {
        return;
    }
    for (t, frags) in &p.tokens {
        if !t.is_method() {
            continue;
        }
        for path in frags.iter().filter(|f| f.first() == Some(&b'/')) {
            let steps = [&b"//"[..], b"/./", b"/../"];
            if steps.iter().any(|s| path.windows(s.len()).any(|w| w == *s))
                || path.ends_with(b"/.")
                || path.ends_with(b"/..")
            {
                finding(
                    target,
                    format_args!("{t:?} path {} is not normal", path.escape_ascii()),
                );
            }
        }
    }
}

fn heads(target: &str, side: Side, data: &[u8]) {
    let (ctl, bytes) = control(data);
    let one = whole(target, side, ctl, bytes);
    check(target, &one, bytes.len(), config(ctl).0);
    let pieces = in_pieces(target, side, ctl, bytes);
    if pieces != one {
        finding(
            target,
            format_args!("in one piece:\n{one:?}\nin pieces:\n{pieces:?}"),
        );
    }
}

/// A request head as a server parses it.
///
/// The first byte chooses how the rest is split, and with its top bit, a
/// small table with token limits.  In one piece and in pieces, the head
/// must come to the same verdict and leave the same table; a refused head
/// must stay refused; no value may hold a CR, LF or NUL; and a request
/// path from the root must be normal, with no `//`, `/./` or `/../` step
/// and no `/.` or `/..` at its end.
pub fn h1_request(data: &[u8]) {
    heads("h1-request", Side::Server, data);
}

/// A response head as a client parses it: as [`h1_request`], from the
/// client's side.
pub fn h1_response(data: &[u8]) {
    heads("h1-response", Side::Client, data);
}

/// What a chunked body is: its data, and where it ended, or that it is not
/// over, or that it cannot be framed.
#[derive(Debug, PartialEq, Eq)]
enum Body {
    End { consumed: usize, data: Vec<u8> },
    More { data: Vec<u8> },
    Refused,
}

/// The oracle: RFC 9112 7.1's grammar with C's bounds, read off the whole
/// body at once, by index, written apart from the decoder.
struct Reference<'a> {
    body: &'a [u8],
    at: usize,
    skipped: u16,
    data: Vec<u8>,
}

/// Why the reference stopped: the body ended, or it is refused.
enum Stop {
    Short,
    Refused,
}

impl Reference<'_> {
    fn peek(&self) -> Result<u8, Stop> {
        self.body.get(self.at).copied().ok_or(Stop::Short)
    }

    fn take(&mut self) -> Result<u8, Stop> {
        let c = self.peek()?;
        self.at = self.at.saturating_add(1);
        Ok(c)
    }

    fn expect(&mut self, want: u8) -> Result<(), Stop> {
        if self.take()? == want {
            Ok(())
        } else {
            Err(Stop::Refused)
        }
    }

    const fn skip(&mut self) -> Result<(), Stop> {
        self.skipped = self.skipped.saturating_add(1);
        if self.skipped > SKIP_MAX {
            return Err(Stop::Refused);
        }
        Ok(())
    }

    /// The bytes of an extension or a trailer line, to the CR its line
    /// ends with, each counted.  A LF before it is refused.
    fn skip_line(&mut self) -> Result<(), Stop> {
        loop {
            match self.peek()? {
                b'\r' => return Ok(()),
                b'\n' => return Err(Stop::Refused),
                _ => {
                    self.skip()?;
                    self.at = self.at.saturating_add(1);
                }
            }
        }
    }

    fn chunk_size(&mut self) -> Result<u32, Stop> {
        let mut size = 0u32;
        let mut digits = 0usize;
        while let Some(d) = char::from(self.peek()?).to_digit(16) {
            if size > (0x7fff_ffff - 15) / 16 {
                return Err(Stop::Refused);
            }
            size = (size << 4) | d;
            digits = digits.saturating_add(1);
            self.at = self.at.saturating_add(1);
        }
        if digits == 0 {
            return Err(Stop::Refused);
        }
        Ok(size)
    }

    fn body(&mut self) -> Result<usize, Stop> {
        loop {
            let size = self.chunk_size()?;
            match self.peek()? {
                b'\r' => {}
                b';' | b' ' | b'\t' => self.skip_line()?,
                _ => return Err(Stop::Refused),
            }
            self.expect(b'\r')?;
            self.expect(b'\n')?;
            if size == 0 {
                return self.trailers();
            }
            let want = usize::try_from(size).unwrap_or(usize::MAX);
            let rest = self.body.get(self.at..).unwrap_or_default();
            let got = rest.get(..want.min(rest.len())).unwrap_or_default();
            self.data.extend_from_slice(got);
            self.at = self.at.saturating_add(got.len());
            if got.len() < want {
                return Err(Stop::Short);
            }
            self.expect(b'\r')?;
            self.expect(b'\n')?;
        }
    }

    fn trailers(&mut self) -> Result<usize, Stop> {
        loop {
            if self.peek()? == b'\r' {
                self.at = self.at.saturating_add(1);
                self.expect(b'\n')?;
                return Ok(self.at);
            }
            self.skip_line()?;
            // the CR ending a trailer line counts, its LF does not
            self.skip()?;
            self.at = self.at.saturating_add(1);
            self.expect(b'\n')?;
        }
    }
}

fn reference(body: &[u8]) -> Body {
    let mut r = Reference {
        body,
        at: 0,
        skipped: 0,
        data: Vec::new(),
    };
    match r.body() {
        Ok(consumed) => Body::End {
            consumed,
            data: r.data,
        },
        Err(Stop::Short) => Body::More { data: r.data },
        Err(Stop::Refused) => Body::Refused,
    }
}

/// The decoder, handed the body in the pieces `pieces` gives.
fn decoded<'a>(pieces: impl Iterator<Item = &'a [u8]>) -> Body {
    let mut d = Dechunk::new();
    let (mut data, mut at) = (Vec::new(), 0usize);
    for piece in pieces {
        let mut rest = piece;
        loop {
            let Ok(step) = d.step(rest) else {
                return Body::Refused;
            };
            at = at.saturating_add(step.consumed);
            rest = rest.get(step.consumed..).unwrap_or_default();
            match step.chunk {
                Chunk::Data(b) => data.extend_from_slice(b),
                Chunk::End => return Body::End { consumed: at, data },
                Chunk::More => break,
            }
            if rest.is_empty() {
                break;
            }
        }
    }
    Body::More { data }
}

/// A chunked body, as a server's request or a client's response has.
///
/// The first byte chooses how the rest is split.  Decoded in one piece and
/// in pieces, it must be what a second reading of RFC 9112 7.1 with C's
/// bounds makes of it: the same data, ending at the same byte, or refused.
pub fn chunked(data: &[u8]) {
    let (ctl, body) = control(data);
    let want = reference(body);
    let one = decoded(core::iter::once(body));
    if one != want {
        finding(
            "chunked",
            format_args!("in one piece {one:?}, the grammar says {want:?}"),
        );
    }
    let pieces = decoded(Pieces::new(ctl, body));
    if pieces != want {
        finding(
            "chunked",
            format_args!("in pieces {pieces:?}, the grammar says {want:?}"),
        );
    }
}
