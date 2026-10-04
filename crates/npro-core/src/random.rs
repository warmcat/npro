//! Random, as an input.
//!
//! The protocols draw random bytes for a few things: a ws client's
//! `Sec-WebSocket-Key` and its frame masks, a multipart boundary.  In C
//! they call `lws_get_random()`; here the caller hands in a [`Random`], so
//! a test or a replay chooses where the bytes come from, and the protocol
//! crates never reach for the platform.
//!
//! A draw is the unit: one call to [`Random::fill`] is one
//! `lws_get_random()` in C.  That matters for [`SeededRandom`], which, like
//! C, spends whole 64-bit words per draw, so the same draws in the same
//! order give the same bytes as C.

/// A source of random bytes, handed in by the IO side or a test.
///
/// What the protocols use it for, a ws key and masks, must be
/// unpredictable to the peer, so a real connection's source must be a
/// cryptographically secure one, such as the operating system's.
pub trait Random {
    /// Fills `buf` with random bytes: one draw.
    ///
    /// # Errors
    ///
    /// [`Unavailable`] when the source cannot give random bytes now.  The
    /// connection drawing them fails, as C fails a short
    /// `lws_get_random()`, rather than going on with predictable ones.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Unavailable>;
}

/// The random source could not give random bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unavailable;

impl core::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("random source unavailable")
    }
}

impl core::error::Error for Unavailable {}

/// lws' seeded random: xoshiro256** seeded through C's splitmix64.
///
/// C lws puts this in place of the platform's random under fault injection
/// (`lws_fi_random_seed()`), so a run making the same draws in the same
/// order gets the same bytes, and its transcripts record them.  This is the
/// same stream, for replaying those transcripts.
///
/// **It is predictable by design.**  Never use it as the source for a real
/// connection: a peer that can predict a ws client's masks can use them
/// against intermediaries, which is what masking exists to prevent.
///
/// Each draw takes as many 64-bit words as cover it, each laid out
/// little-endian, and drops what is left of the last one, as C does.  So a
/// 4-byte draw spends a whole word:
///
/// ```
/// use npro_core::random::{Random, SeededRandom};
///
/// let mut r = SeededRandom::new(1);
/// let mut key = [0; 16];
/// let mut mask = [0; 4];
/// r.fill(&mut key)?;
/// r.fill(&mut mask)?;
///
/// // a ws client's key and its first frame's mask, as C's ws-client
/// // transcript records them
/// assert_eq!(&key[..4], &[0x3a, 0xfa, 0x26, 0xb5]);
/// assert_eq!(mask, [0x16, 0x73, 0x98, 0x76]);
/// # Ok::<(), npro_core::random::Unavailable>(())
/// ```
#[cfg(feature = "replay")]
#[derive(Clone, Debug)]
#[expect(
    missing_copy_implementations,
    reason = "a copy made by accident would draw the same random twice"
)]
pub struct SeededRandom {
    s: [u64; 4],
}

#[cfg(feature = "replay")]
impl SeededRandom {
    /// The stream C's `lws_fi_random_seed(cx, seed)` starts.
    #[must_use]
    pub fn new(mut seed: u64) -> Self {
        let mut s = [0; 4];
        for w in &mut s {
            *w = splitmix64(&mut seed);
        }
        Self { s }
    }

    /// The next 64-bit word of the stream (C's `lws_xos()`).
    pub const fn next_u64(&mut self) -> u64 {
        let [s0, s1, s2, s3] = &mut self.s;
        let result = s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s1.wrapping_shl(17);

        *s2 ^= *s0;
        *s3 ^= *s1;
        *s1 ^= *s2;
        *s0 ^= *s3;
        *s2 ^= t;
        *s3 = s3.rotate_left(45);

        result
    }
}

#[cfg(feature = "replay")]
impl Random for SeededRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Unavailable> {
        for chunk in buf.chunks_mut(8) {
            for (b, w) in chunk.iter_mut().zip(self.next_u64().to_le_bytes()) {
                *b = w;
            }
        }
        Ok(())
    }
}

/// C's splitmix64 (`lib/misc/prng.c`).
///
/// It mixes the state as it was *before* adding the increment, where the
/// reference splitmix64 mixes it after.  This is C's, so that the streams
/// match; the textbook one would seed a different stream.
#[cfg(feature = "replay")]
const fn splitmix64(s: &mut u64) -> u64 {
    let mut r = *s;
    *s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
    r = (r ^ (r >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    r = (r ^ (r >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    r ^ (r >> 31)
}

#[cfg(all(test, feature = "replay"))]
mod tests {
    use super::*;

    #[test]
    fn matches_c_api_test_random_prng() {
        // minimal-examples-lowlevel/api-tests/api-test-random-prng: the
        // first bytes lws_fi_random_seed(cx, 1234) gives
        let mut r = SeededRandom::new(1234);
        let mut b = [0; 16];
        r.fill(&mut b).unwrap();
        assert_eq!(
            b,
            [
                0x6b, 0x42, 0x89, 0x9e, 0xa3, 0x63, 0xa1, 0xa3, 0x24, 0x60, 0x07, 0xbb, 0xb7, 0x67,
                0x64, 0xdc
            ]
        );
        assert_eq!(r.next_u64(), 0xbdf5_c7a4_e6e0_a48b);
    }

    #[test]
    fn a_draw_spends_whole_words() {
        // seed 1: the ws-client transcript's key, then its first mask from
        // the low half of the third word
        let mut r = SeededRandom::new(1);
        let mut key = [0; 16];
        let mut mask = [0; 4];
        r.fill(&mut key).unwrap();
        r.fill(&mut mask).unwrap();
        assert_eq!(
            key,
            [
                0x3a, 0xfa, 0x26, 0xb5, 0x0a, 0x4a, 0x09, 0x65, 0x27, 0x65, 0x6e, 0xed, 0x31, 0x1e,
                0x86, 0xab
            ]
        );
        assert_eq!(mask, [0x16, 0x73, 0x98, 0x76]);

        // and a second mask starts on the next word, not the 4 bytes left
        let mut a = SeededRandom::new(1);
        let mut skip = [0; 24];
        a.fill(&mut skip).unwrap();
        let mut next = [0; 4];
        r.fill(&mut next).unwrap();
        let mut want = [0; 4];
        a.fill(&mut want).unwrap();
        assert_eq!(next, want);
    }

    #[test]
    fn reseeding_restarts_the_stream() {
        let mut a = SeededRandom::new(7);
        let first = a.next_u64();
        a.next_u64();
        assert_eq!(SeededRandom::new(7).next_u64(), first);
        assert_ne!(SeededRandom::new(8).next_u64(), first);
    }

    #[test]
    fn an_empty_draw_spends_nothing() {
        let mut a = SeededRandom::new(1);
        a.fill(&mut []).unwrap();
        assert_eq!(a.next_u64(), SeededRandom::new(1).next_u64());
    }
}
