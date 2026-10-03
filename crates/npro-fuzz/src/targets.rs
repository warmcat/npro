//! The targets, and what each checks.

use core::fmt;
use core::ops::Range;

use npro_core::base64::{self as b64, encoded_len};
use npro_core::sha1::Sha1;
use npro_core::utf8::Utf8Validator;
use npro_test::{MAX_BYTES, MAX_STEPS, Transcript};

/// Reports a finding to whatever is driving the target: libFuzzer, which
/// treats a panic as a crash and keeps the input, or a smoke test.
#[allow(
    clippy::panic,
    reason = "a panic is how a fuzz target reports a finding to libFuzzer"
)]
#[cold]
fn finding(target: &str, what: fmt::Arguments<'_>) -> ! {
    panic!("{target}: {what}")
}

/// The input's first byte, which chooses how a target splits the rest,
/// and the rest.
fn control(data: &[u8]) -> (u8, &[u8]) {
    data.split_first().map_or((0, data), |(c, rest)| (*c, rest))
}

/// `bytes` split into pieces of 0 to 16 bytes, the sizes drawn from a
/// small generator seeded by `ctl`.  Pieces are what arrives in one read,
/// so empty ones are included: a reader can be handed nothing.
struct Pieces<'a> {
    rest: &'a [u8],
    state: u32,
}

impl<'a> Pieces<'a> {
    fn new(ctl: u8, bytes: &'a [u8]) -> Self {
        Self {
            rest: bytes,
            state: u32::from(ctl),
        }
    }
}

impl<'a> Iterator for Pieces<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.rest.is_empty() {
            return None;
        }
        // the LCG from C's rand(): period 2^32, so sizes of 0 do not
        // repeat for long, and every split is reachable from some ctl
        self.state = self.state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let want = usize::try_from((self.state >> 16) % 17).unwrap_or(1);
        let (piece, rest) = self.rest.split_at(want.min(self.rest.len()));
        self.rest = rest;
        Some(piece)
    }
}

/// How text ends, as validation sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Utf8End {
    /// Well-formed and between characters.
    Complete,
    /// Well-formed so far, but inside a character.
    Partial,
    /// The byte at this index cannot continue any well-formed text.
    InvalidAt(usize),
}

/// The oracle: how `text` ends according to `core::str`.
fn utf8_end_by_core(text: &[u8]) -> Utf8End {
    let e = match core::str::from_utf8(text) {
        Ok(_) => return Utf8End::Complete,
        Err(e) => e,
    };
    if e.error_len().is_none() {
        return Utf8End::Partial;
    }
    // core reports where the last good character ends.  The validator
    // refuses at the first byte no well-formed text could have next,
    // which is the first index whose prefix core calls broken rather
    // than unfinished.
    let from = e.valid_up_to();
    let refused = (from..text.len()).find(|&i| {
        text.get(..=i)
            .is_some_and(|p| core::str::from_utf8(p).is_err_and(|e| e.error_len().is_some()))
    });
    Utf8End::InvalidAt(refused.unwrap_or(from))
}

/// Incremental UTF-8 validation, as ws text arrives, against `core::str`
/// over the whole text.
///
/// The first byte chooses how the rest is split.  It is validated a byte at
/// a time, which must refuse it at exactly the byte core's answer implies,
/// and in pieces, which must refuse it in the piece holding that byte, and
/// go on refusing every piece after, empty ones included.
pub fn utf8(data: &[u8]) {
    let (ctl, text) = control(data);
    let expect = utf8_end_by_core(text);

    let mut v = Utf8Validator::new();
    let mut bytewise = None;
    for (i, b) in text.iter().enumerate() {
        if v.feed(core::slice::from_ref(b)).is_err() {
            bytewise = Some(Utf8End::InvalidAt(i));
            break;
        }
    }
    let bytewise = bytewise.unwrap_or(if v.at_boundary() {
        Utf8End::Complete
    } else {
        Utf8End::Partial
    });
    if bytewise != expect {
        finding(
            "utf8",
            format_args!("fed a byte at a time it ends {bytewise:?}, core says {expect:?}"),
        );
    }

    let mut v = Utf8Validator::new();
    let mut refused: Option<Range<usize>> = None;
    let mut at = 0usize;
    for piece in Pieces::new(ctl, text) {
        let span = at..at.saturating_add(piece.len());
        match (v.feed(piece), &refused) {
            (Err(_), None) => refused = Some(span.clone()),
            (Ok(()), Some(r)) => finding(
                "utf8",
                format_args!("accepted {span:?} after refusing {r:?}"),
            ),
            (Err(_), Some(_)) | (Ok(()), None) => {}
        }
        at = span.end;
    }
    let ok = match (expect, &refused) {
        (Utf8End::InvalidAt(i), Some(r)) => r.contains(&i),
        (Utf8End::Complete, None) => v.at_boundary(),
        (Utf8End::Partial, None) => !v.at_boundary(),
        (Utf8End::InvalidAt(_), None) | (Utf8End::Complete | Utf8End::Partial, Some(_)) => false,
    };
    if !ok {
        finding(
            "utf8",
            format_args!(
                "fed in pieces it refused {refused:?} and ends at a boundary: {}, core says {expect:?}",
                v.at_boundary()
            ),
        );
    }
}

/// SHA-1 fed in pieces, as a ws key or a body arrives, against SHA-1 of
/// the whole message at once.  The first byte chooses the split.
pub fn sha1(data: &[u8]) {
    let (ctl, msg) = control(data);
    let whole = Sha1::digest(msg);

    let mut h = Sha1::new();
    for piece in Pieces::new(ctl, msg) {
        h.update(piece);
    }
    let pieces = h.finish();

    if pieces != whole {
        finding(
            "sha1",
            format_args!("in pieces {pieces:02x?}, in one go {whole:02x?}"),
        );
    }
}

/// What the encoder must leave alone: no base64 symbol is this byte.
const UNTOUCHED: u8 = 0xa5;

/// The value of a base64 symbol, RFC 4648 4's alphabet.
fn sextet(c: u8) -> Option<u8> {
    let (base, value) = match c {
        b'A'..=b'Z' => (b'A', 0),
        b'a'..=b'z' => (b'a', 26),
        b'0'..=b'9' => (b'0', 52),
        b'+' => return Some(62),
        b'/' => return Some(63),
        _ => return None,
    };
    c.checked_sub(base)?.checked_add(value)
}

/// The oracle: a strict RFC 4648 decoder, refusing anything the encoder
/// should never produce, so a wrong symbol or padding shows as `None`.
fn decode(text: &[u8]) -> Option<Vec<u8>> {
    if text.len() % 4 != 0 {
        return None;
    }
    let groups = text.len() / 4;
    let mut out = Vec::with_capacity(groups.checked_mul(3)?);
    for (n, g) in text.chunks_exact(4).enumerate() {
        let last = n.checked_add(1)? == groups;
        // padding symbols, bytes decoded, and the bits padding stands in for
        let (pad, have, shift) = match *g {
            [_, _, b'=', b'='] if last => (2, 1, 12),
            [_, _, _, b'='] if last => (1, 2, 6),
            _ => (0, 3, 0),
        };
        let mut v = 0u32;
        for &c in g.get(..4usize.checked_sub(pad)?)? {
            v = (v << 6) | u32::from(sextet(c)?);
        }
        v <<= shift;
        let bytes = v.to_be_bytes();
        let decoded = bytes.get(1..1usize.checked_add(have)?)?;
        // the bits padding stands in for must be zero, as the encoder
        // writes them
        if bytes
            .get(1usize.checked_add(have)?..)?
            .iter()
            .any(|&b| b != 0)
        {
            return None;
        }
        out.extend_from_slice(decoded);
    }
    Some(out)
}

/// base64 encoding, as the ws accept and keys use it.
///
/// The whole input is encoded into a buffer with room to spare, which must
/// use exactly `encoded_len` bytes and leave the rest alone, and decode back
/// to the input; and into buffers one byte short and empty, which must be
/// refused with nothing written.
pub fn base64(data: &[u8]) {
    let Some(len) = encoded_len(data.len()) else {
        finding(
            "base64",
            format_args!("no encoded length for {} bytes", data.len()),
        );
    };
    let mut buf = vec![UNTOUCHED; len.saturating_add(4)];

    for short in [Some(0), len.checked_sub(1)].into_iter().flatten() {
        if short >= len {
            continue;
        }
        buf.fill(UNTOUCHED);
        let Some(dst) = buf.get_mut(..short) else {
            continue;
        };
        if b64::encode(data, dst).is_ok() {
            finding(
                "base64",
                format_args!("{} bytes encoded into {short}", data.len()),
            );
        }
        if buf.iter().any(|&b| b != UNTOUCHED) {
            finding(
                "base64",
                format_args!("refused {short} bytes but wrote to them"),
            );
        }
    }

    buf.fill(UNTOUCHED);
    match b64::encode(data, &mut buf) {
        Ok(n) if n == len => {}
        Ok(n) => finding(
            "base64",
            format_args!("used {n} bytes, encoded_len says {len}"),
        ),
        Err(e) => finding(
            "base64",
            format_args!("refused a buffer of {}: {e}", buf.len()),
        ),
    }
    let (text, spare) = buf.split_at(len);
    if spare.iter().any(|&b| b != UNTOUCHED) {
        finding("base64", format_args!("wrote past the {len} bytes it used"));
    }
    if decode(text).as_deref() != Some(data) {
        finding(
            "base64",
            format_args!("{text:?} does not decode to the input"),
        );
    }
}

/// npro-test's transcript reader, which reads files that come from outside
/// the tree.  Whatever it accepts must respect its limits and its promise
/// that step times never go backwards.
pub fn transcript(data: &[u8]) {
    let Ok(t) = Transcript::parse(data) else {
        return;
    };
    if data.len() > MAX_BYTES {
        finding("transcript", format_args!("accepted {} bytes", data.len()));
    }
    if t.steps.len() > MAX_STEPS {
        finding(
            "transcript",
            format_args!("accepted {} steps", t.steps.len()),
        );
    }
    if t.steps
        .windows(2)
        .any(|w| matches!(w, [a, b] if b.t_us < a.t_us))
    {
        finding("transcript", format_args!("accepted time going backwards"));
    }
}
