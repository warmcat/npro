//! What a certificate chain or key from the server must look like
//! before it is installed: C's two checks.

/// Whether `body` could be PEM at all: armor lines and base64 are
/// printable ASCII and line ends.  A double quote or a backslash could
/// change the meaning of JSON it is carried in; a control character
/// could hide the rest of a line; a byte outside ASCII is no PEM.  C's
/// `cert_dist_pem_plausible()`: anything else is not something to
/// install, and not a server to go on listening to.
///
/// ```
/// use npro_certdist::pem::plausible;
///
/// assert!(plausible(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"));
/// assert!(!plausible(b"\"quoted\""));
/// assert!(!plausible(b"a\\b"));
/// assert!(!plausible(b"\x01"));
/// assert!(!plausible("é".as_bytes()));
/// ```
#[must_use]
pub fn plausible(body: &[u8]) -> bool {
    body.iter().all(|&c| {
        c != b'"' && c != b'\\' && (c >= 0x20 || matches!(c, b'\n' | b'\r' | b'\t')) && c <= 0x7e
    })
}

/// Whether `fullchain` and `privkey` are a pair worth installing: each
/// not empty, the chain holding a certificate's armor and the key a
/// private key's.  C's `cdc_install()` refuses anything else, so that
/// working key material is never replaced with junk.
#[must_use]
pub fn is_pair(fullchain: &[u8], privkey: &[u8]) -> bool {
    !fullchain.is_empty()
        && !privkey.is_empty()
        && holds(fullchain, b"-----BEGIN CERTIFICATE-----")
        && holds(fullchain, b"-----END CERTIFICATE-----")
        && holds(privkey, b"-----BEGIN")
        && holds(privkey, b"PRIVATE KEY-----")
}

fn holds(body: &[u8], marker: &[u8]) -> bool {
    body.windows(marker.len()).any(|w| w == marker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pair_has_both_armors_and_nothing_else_passes() {
        let c = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        let k = b"-----BEGIN EC PRIVATE KEY-----\nMIGH\n-----END EC PRIVATE KEY-----\n";
        assert!(is_pair(c, k));
        assert!(!is_pair(c, b""));
        assert!(!is_pair(b"", k));
        assert!(!is_pair(k, c));
        assert!(!is_pair(
            c,
            b"-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"
        ));
    }
}
