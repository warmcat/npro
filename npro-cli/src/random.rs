//! npro's random, from the tls provider's.
//!
//! npro draws random for ws masks and the ws key, and in time a retry's
//! jitter; it takes it as a `Random` the program gives.  The runner gives
//! the crypto provider's secure random, aws-lc's, so nothing else is
//! needed for it.

use std::sync::Arc;

use npro_core::random::{Random, Unavailable};
use rustls::crypto::CryptoProvider;

/// The provider's secure random.
#[derive(Debug, Clone)]
pub struct ProviderRandom {
    provider: Arc<CryptoProvider>,
}

impl Default for ProviderRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRandom {
    /// aws-lc's.
    ///
    /// ```
    /// use npro_cli::random::ProviderRandom;
    /// use npro_core::random::Random;
    ///
    /// let mut r = ProviderRandom::new();
    /// let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
    /// r.fill(&mut a)?;
    /// r.fill(&mut b)?;
    /// assert_ne!(a, b);
    /// # Ok::<(), npro_core::random::Unavailable>(())
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            provider: npro_aws_lc::provider(),
        }
    }
}

impl Random for ProviderRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Unavailable> {
        self.provider
            .secure_random
            .fill(buf)
            .map_err(|_| Unavailable)
    }
}
