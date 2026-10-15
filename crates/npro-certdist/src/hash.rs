//! What the client tells the server first: the hash of the chain it
//! has, so an unchanged one is not sent again.

use npro_core::sha1::{DIGEST_LEN, Sha1};

/// The message, `{"hash":"<40 hex digits>"}`: its length.
pub const MESSAGE_LEN: usize = 9 + DIGEST_LEN * 2 + 2;

/// The SHA-1 of the chain `fullchain`, as installed: what the server
/// compares its own against.  C's `lws_SHA1()` of `fullchain.pem`.
#[must_use]
pub fn of(fullchain: &[u8]) -> [u8; DIGEST_LEN] {
    Sha1::digest(fullchain)
}

/// The message saying `hash`, written into `out`: the client sends it
/// as one ws text message once the link is up, if it has a chain.
///
/// ```
/// use npro_certdist::hash;
///
/// let digest = hash::of(b"-----BEGIN CERTIFICATE-----\n");
/// let mut out = [0u8; hash::MESSAGE_LEN];
/// hash::message(&digest, &mut out);
/// assert!(out.starts_with(b"{\"hash\":\""));
/// assert!(out.ends_with(b"\"}"));
/// ```
pub fn message(hash: &[u8; DIGEST_LEN], out: &mut [u8; MESSAGE_LEN]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut at = 0usize;
    let mut put = |b: u8, into: &mut [u8; MESSAGE_LEN]| {
        if let Some(slot) = into.get_mut(at) {
            *slot = b;
        }
        at = at.saturating_add(1);
    };
    for &b in b"{\"hash\":\"" {
        put(b, out);
    }
    for &b in hash {
        put(HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'), out);
        put(HEX.get(usize::from(b & 0xf)).copied().unwrap_or(b'0'), out);
    }
    for &b in b"\"}" {
        put(b, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_is_the_hex_of_the_digest_in_cs_shape() {
        let digest = of(b"abc");
        let mut out = [0u8; MESSAGE_LEN];
        message(&digest, &mut out);
        assert_eq!(
            &out,
            b"{\"hash\":\"a9993e364706816aba3e25717850c26c9cd0d89d\"}"
        );
    }
}
