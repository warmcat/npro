//! The backoffs, as C's retry policies have them: how long before a
//! link is made again, and before a certificate that could not be
//! installed is fetched again.

use core::time::Duration;

use npro_core::random::Random;

/// A backoff: a table of delays in milliseconds, each try taking the
/// next, the last one for ever after; with jitter, so many clients do
/// not come back together.  C's `lws_retry_bo_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    /// The delays, in milliseconds, in order.
    pub table: &'static [u32],
    /// How much is added at most, as a percentage of the delay.
    pub jitter_percent: u32,
}

/// Reconnecting a dropped link: 1s to 5s, with 20% jitter, as many
/// times as it takes.
pub const CONNECT_BACKOFF: Backoff = Backoff {
    table: &[1000, 2000, 3000, 4000, 5000],
    jitter_percent: 20,
};

/// Fetching again a certificate that could not be installed: slower,
/// since whatever failed (a full disk, bad permissions) will not have
/// gone away in a second, and growing to hourly.  Each retry has the
/// server send the whole certificate and key again.
pub const INSTALL_BACKOFF: Backoff = Backoff {
    table: &[10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000],
    jitter_percent: 20,
};

impl Backoff {
    /// The delay before try number `count` (0 the first), with jitter
    /// from `random`: the table's entry for it, or its last past the
    /// end, plus up to `jitter_percent` of that.  C's
    /// `lws_retry_get_delay_ms()`.
    ///
    /// ```
    /// use npro_certdist::CONNECT_BACKOFF;
    /// use npro_core::random::SeededRandom;
    ///
    /// let mut r = SeededRandom::new(1);
    /// let first = CONNECT_BACKOFF.delay(0, &mut r);
    /// assert!(first.as_millis() >= 1000 && first.as_millis() <= 1200);
    /// let later = CONNECT_BACKOFF.delay(100, &mut r);
    /// assert!(later.as_millis() >= 5000 && later.as_millis() <= 6000);
    /// ```
    #[must_use]
    pub fn delay(&self, count: u16, random: &mut dyn Random) -> Duration {
        let at = usize::from(count).min(self.table.len().saturating_sub(1));
        let ms = self.table.get(at).copied().unwrap_or(1000);
        let mut draw = [0u8; 2];
        // no random: no jitter, which is still a delay
        let _ = random.fill(&mut draw);
        let fraction = u32::from(u16::from_le_bytes(draw));
        // up to jitter_percent of ms: ms * jitter% * fraction / 65536
        let jitter = u64::from(ms)
            .saturating_mul(u64::from(self.jitter_percent))
            .saturating_mul(u64::from(fraction))
            / 100
            / 65_536;
        Duration::from_millis(u64::from(ms).saturating_add(jitter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use npro_core::random::SeededRandom;

    #[test]
    fn the_table_is_walked_then_held_with_bounded_jitter() {
        let mut r = SeededRandom::new(3);
        for (i, base) in INSTALL_BACKOFF.table.iter().enumerate() {
            let d = INSTALL_BACKOFF.delay(u16::try_from(i).unwrap(), &mut r);
            let ms = u64::try_from(d.as_millis()).unwrap();
            assert!(
                ms >= u64::from(*base) && ms <= u64::from(*base) * 120 / 100,
                "{i}: {ms}"
            );
        }
        let past = INSTALL_BACKOFF.delay(u16::MAX, &mut r);
        assert!(past.as_millis() >= 3_600_000);
        let none = Backoff {
            table: &[],
            jitter_percent: 0,
        };
        assert_eq!(none.delay(0, &mut r), Duration::from_millis(1000));
    }
}
