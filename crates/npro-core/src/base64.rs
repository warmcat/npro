//! Base64 encoding (RFC 4648 4, the standard alphabet with padding), for
//! the ws handshake's `Sec-WebSocket-Key` and `Sec-WebSocket-Accept`.
//!
//! Only encoding: the handshake never needs to decode either value.  The
//! output goes into the caller's buffer, as everything the protocols
//! compose does.

/// The standard alphabet.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The output buffer cannot hold the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferTooSmall;

impl core::fmt::Display for BufferTooSmall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("buffer too small for the base64 encoding")
    }
}

impl core::error::Error for BufferTooSmall {}

/// The length of the encoding of `n` bytes, or `None` if it would not fit
/// a `usize`.
#[must_use]
pub const fn encoded_len(n: usize) -> Option<usize> {
    n.div_ceil(3).checked_mul(4)
}

/// Encodes `src` into the start of `dst`, returning how many bytes of `dst`
/// it used.
///
/// ```
/// use npro_core::base64;
///
/// let mut out = [0; 8];
/// let n = base64::encode(b"foob", &mut out)?;
/// assert_eq!(&out[..n], b"Zm9vYg==");
/// # Ok::<(), base64::BufferTooSmall>(())
/// ```
///
/// # Errors
///
/// [`BufferTooSmall`] if `dst` is shorter than [`encoded_len`] of `src`;
/// nothing is written then.
pub fn encode(src: &[u8], dst: &mut [u8]) -> Result<usize, BufferTooSmall> {
    let len = encoded_len(src.len()).ok_or(BufferTooSmall)?;
    let out = dst.get_mut(..len).ok_or(BufferTooSmall)?;

    for (o, i) in out.chunks_exact_mut(4).zip(src.chunks(3)) {
        let (b0, b1, b2, have) = match *i {
            [a, b, c] => (a, b, c, 4),
            [a, b] => (a, b, 0, 3),
            [a] => (a, 0, 0, 2),
            _ => (0, 0, 0, 0),
        };
        let sextets = [b0 >> 2, (b0 << 4 | b1 >> 4), (b1 << 2 | b2 >> 6), b2];
        for (n, (d, s)) in o.iter_mut().zip(sextets).enumerate() {
            *d = if n < have { symbol(s) } else { b'=' };
        }
    }

    Ok(len)
}

/// The alphabet's symbol for the low six bits of `v`.
fn symbol(v: u8) -> u8 {
    // masked to six bits, the index is always inside the 64-symbol alphabet
    ALPHABET.get(usize::from(v & 0x3f)).copied().unwrap_or(b'=')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(src: &[u8]) -> String {
        let mut out = vec![0; encoded_len(src.len()).unwrap()];
        let n = encode(src, &mut out).unwrap();
        assert_eq!(n, out.len());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn rfc_4648_vectors() {
        for (src, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(enc(src.as_bytes()), want);
        }
    }

    #[test]
    fn every_symbol_and_the_high_bits() {
        // 0x00..=0xff covers every sextet value in every position
        let all: Vec<u8> = (0..=255).collect();
        let s = enc(&all);
        for c in ALPHABET {
            assert!(s.as_bytes().contains(c));
        }
        assert!(s.starts_with("AAECAwQF"));
        assert!(s.ends_with("+/w=="));
    }

    #[test]
    fn a_short_buffer_is_refused_untouched() {
        let mut out = [b'x'; 7];
        assert_eq!(encode(b"foob", &mut out), Err(BufferTooSmall));
        assert_eq!(out, [b'x'; 7]);
    }

    #[test]
    fn the_ws_accept_of_rfc_6455() {
        // RFC 6455 1.3: base64(SHA-1(key + GUID))
        let mut h = crate::sha1::Sha1::new();
        h.update(b"dGhlIHNhbXBsZSBub25jZQ==");
        h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        assert_eq!(enc(&h.finish()), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[cfg(feature = "replay")]
    #[test]
    fn the_ws_client_transcripts_key() {
        // C's ws-client transcript: the key its client sends, drawn as the
        // first 16 bytes of lws' random seeded with 1
        use crate::random::{Random, SeededRandom};
        let mut key = [0; 16];
        SeededRandom::new(1).fill(&mut key).unwrap();
        assert_eq!(enc(&key), "OvomtQpKCWUnZW7tMR6Gqw==");
    }
}
