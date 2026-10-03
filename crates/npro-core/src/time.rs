//! Time, as an input.
//!
//! C's sansIO half asks the service thread's time (`lws_wsi_now()`), which
//! an embedder sets with `lws_service_set_now()`; it never reads a clock to
//! decide anything.  Here the caller passes `now` into every entry point
//! that can decide by it, and asks the connection when it next needs to be
//! called.  Nothing in the protocol crates reads a clock.
//!
//! An [`Instant`] is a point on the IO side's monotonic clock, in
//! microseconds as C's `lws_usec_t` is, from an origin the IO side chooses.
//! Intervals are [`core::time::Duration`].

use core::time::Duration;

/// A point on the monotonic clock, in microseconds from an origin the IO
/// side chooses.  Instants from different clocks must not be mixed.
///
/// ```
/// use core::time::Duration;
/// use npro_core::time::Instant;
///
/// let t0 = Instant::from_micros(1_000_000_000);
/// let t1 = t0.checked_add(Duration::from_millis(5)).unwrap();
/// assert_eq!(t1.as_micros(), 1_000_005_000);
/// assert_eq!(t1.saturating_duration_since(t0), Duration::from_millis(5));
/// assert_eq!(t0.saturating_duration_since(t1), Duration::ZERO);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    /// The instant `us` microseconds after the clock's origin.
    #[must_use]
    pub const fn from_micros(us: u64) -> Self {
        Self(us)
    }

    /// Microseconds since the clock's origin.
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// The instant `d` later, or `None` past the clock's range.  Below a
    /// microsecond, `d` is truncated.
    #[must_use]
    pub fn checked_add(self, d: Duration) -> Option<Self> {
        let us = u64::try_from(d.as_micros()).ok()?;
        self.0.checked_add(us).map(Self)
    }

    /// The instant `d` later, or the clock's last instant.  For a deadline
    /// that must never come out earlier than asked.
    #[must_use]
    pub fn saturating_add(self, d: Duration) -> Self {
        self.checked_add(d).unwrap_or(Self(u64::MAX))
    }

    /// How long after `earlier` this is, or zero if it is not later.
    #[must_use]
    pub const fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_micros(self.0.saturating_sub(earlier.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adding_stays_in_range() {
        let end = Instant::from_micros(u64::MAX - 1);
        assert_eq!(end.checked_add(Duration::from_micros(2)), None);
        assert_eq!(
            end.saturating_add(Duration::from_micros(2)),
            Instant::from_micros(u64::MAX)
        );
        assert_eq!(Instant::from_micros(0).checked_add(Duration::MAX), None);
    }

    #[test]
    fn sub_microsecond_is_truncated() {
        let t = Instant::from_micros(10);
        assert_eq!(t.checked_add(Duration::from_nanos(999)), Some(t));
        assert_eq!(
            t.checked_add(Duration::from_nanos(1_500)),
            Some(Instant::from_micros(11))
        );
    }

    #[test]
    fn instants_order_as_their_micros() {
        assert!(Instant::from_micros(1) < Instant::from_micros(2));
        assert_eq!(
            Instant::from_micros(7).saturating_duration_since(Instant::from_micros(3)),
            Duration::from_micros(4)
        );
    }
}
