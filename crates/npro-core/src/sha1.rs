//! SHA-1, for the one thing the protocols need it for: the ws handshake's
//! `Sec-WebSocket-Accept` (RFC 6455 4.2.2), which is fixed by the RFC.
//!
//! SHA-1 is broken for collision resistance and must not be used for
//! anything that needs it; the ws handshake does not.  C lws has its own in
//! `lib/misc/sha-1.c`, and so does npro rather than taking a dependency for
//! one handshake hash.

/// The size of a SHA-1 digest, in bytes.
pub const DIGEST_LEN: usize = 20;

/// The size of a SHA-1 block, in bytes.
const BLOCK: usize = 64;

/// Where the 64-bit message length goes in the last block.
const LEN_AT: usize = BLOCK - 8;

/// The initial state (RFC 3174 6.1).
const H0: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// A SHA-1 hash in progress.
///
/// ```
/// use npro_core::sha1::Sha1;
///
/// let mut h = Sha1::new();
/// h.update(b"ab");
/// h.update(b"c");
/// assert_eq!(h.finish(), Sha1::digest(b"abc"));
/// ```
#[derive(Clone, Debug)]
pub struct Sha1 {
    state: [u32; 5],
    /// Bytes of the current block taken so far.
    block: [u8; BLOCK],
    /// How much of `block` is filled.
    fill: usize,
    /// Length of the message so far, in bytes, modulo 2^64.
    len: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// A hash of nothing yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: H0,
            block: [0; BLOCK],
            fill: 0,
            len: 0,
        }
    }

    /// The digest of `data`, in one call.
    ///
    /// ```
    /// use npro_core::sha1::Sha1;
    ///
    /// assert_eq!(
    ///     Sha1::digest(b"abc")[..4],
    ///     [0xa9, 0x99, 0x3e, 0x36]
    /// );
    /// ```
    #[must_use]
    pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut h = Self::new();
        h.update(data);
        h.finish()
    }

    /// Takes more of the message.
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.byte(b);
        }
        // the length is the message's modulo 2^64 bits (RFC 3174 4); a
        // usize that does not fit 64 bits is no platform npro builds for
        let n = u64::try_from(data.len()).unwrap_or(u64::MAX);
        self.len = self.len.wrapping_add(n);
    }

    /// Pads the message and gives its digest.
    #[must_use]
    pub fn finish(mut self) -> [u8; DIGEST_LEN] {
        let bits = self.len.wrapping_mul(8);

        self.byte(0x80);
        while self.fill != LEN_AT {
            self.byte(0);
        }
        for b in bits.to_be_bytes() {
            self.byte(b);
        }

        let mut out = [0; DIGEST_LEN];
        for (o, w) in out.chunks_exact_mut(4).zip(self.state) {
            for (d, s) in o.iter_mut().zip(w.to_be_bytes()) {
                *d = s;
            }
        }
        out
    }

    /// Takes one byte into the block, compressing it when it is full.
    fn byte(&mut self, b: u8) {
        if let Some(slot) = self.block.get_mut(self.fill) {
            *slot = b;
        }
        self.fill = self.fill.saturating_add(1);
        if self.fill == BLOCK {
            self.compress();
            self.fill = 0;
        }
    }

    /// The compression function over the full block (RFC 3174 6.1).
    fn compress(&mut self) {
        // the message schedule, kept as the last 16 words: each round's
        // word is w[0], and the next is made from w[13], w[8], w[2], w[0]
        let mut w = [0u32; 16];
        for (d, c) in w.iter_mut().zip(self.block.chunks_exact(4)) {
            if let &[a, b, c, e] = c {
                *d = u32::from_be_bytes([a, b, c, e]);
            }
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;

        for t in 0..80 {
            let (f, k) = match t {
                0..20 => ((b & c) | (!b & d), 0x5a82_7999),
                20..40 => (b ^ c ^ d, 0x6ed9_eba1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[0])
                .wrapping_add(k);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;

            let next = (w[13] ^ w[8] ^ w[2] ^ w[0]).rotate_left(1);
            w.rotate_left(1);
            w[15] = next;
        }

        for (s, v) in self.state.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: [u8; DIGEST_LEN]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rfc_3174_vectors() {
        assert_eq!(
            hex(Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(Sha1::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(Sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "a million bytes: native runs keep it, Miri runs the shorter vectors"
    )]
    fn rfc_3174_a_million_a() {
        assert_eq!(
            hex(Sha1::digest(&vec![b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn padding_at_every_block_boundary() {
        // lengths around 55 / 56 / 64 bytes put the 0x80 and the length in
        // the last block or the next one: digests of 'a' repeated n times,
        // as Python's hashlib.sha1 gives them
        for (n, want) in [
            (55, "c1c8bbdc22796e28c0e15163d20899b65621d65a"),
            (56, "c2db330f6083854c99d4b5bfb6e8f29f201be699"),
            (63, "03f09f5b158a7a8cdad920bddc29b81c18a551f5"),
            (64, "0098ba824b5c16427bd7a1122a5a442a25ec644d"),
            (65, "11655326c708d70319be2610e8a57d9a5b959d3b"),
        ] {
            assert_eq!(hex(Sha1::digest(&vec![b'a'; n])), want, "{n} bytes");
        }
    }

    #[test]
    fn the_same_digest_however_the_message_is_split() {
        let msg: Vec<u8> = (0..=255u8).cycle().take(300).collect();
        let whole = Sha1::digest(&msg);
        for cut in 0..=msg.len() {
            let (x, y) = msg.split_at(cut);
            let mut h = Sha1::new();
            h.update(x);
            h.update(y);
            assert_eq!(h.finish(), whole, "split at {cut}");
        }
    }
}
