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

/// A moment on the wall clock, broken into its civil parts, in UTC: what
/// a log line or an HTTP date is written from.  The protocol crates
/// never read the wall clock; the adapter passes it in as seconds since
/// 1970, and this breaks them up.
///
/// ```
/// use npro_core::time::Civil;
///
/// let c = Civil::from_unix(1_767_225_600);
/// assert_eq!((c.year, c.month, c.day), (2026, 1, 1));
/// assert_eq!((c.hour, c.minute, c.second), (0, 0, 0));
/// assert_eq!(c.month_name(), b"Jan");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    /// The year, 1970 on.
    pub year: u64,
    /// The month, 1 to 12.
    pub month: u8,
    /// The day of the month, 1 to 31.
    pub day: u8,
    /// The hour, 0 to 23.
    pub hour: u8,
    /// The minute, 0 to 59.
    pub minute: u8,
    /// The second, 0 to 59: no leap seconds, as unix time has none.
    pub second: u8,
}

/// The month names, three letters, as `strftime`'s `%b` gives them in
/// the C locale.
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

impl Civil {
    /// The moment `secs` seconds after 1970-01-01 00:00:00 UTC.  Every
    /// `u64` is some moment, far as the last are.
    #[must_use]
    pub fn from_unix(secs: u64) -> Self {
        Self::try_from_unix(secs).unwrap_or(Self {
            year: 1970,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        })
    }

    /// Howard Hinnant's `civil_from_days`, from the epoch forwards: the
    /// arithmetic cannot overflow a `u64` for any `secs`, and the parts
    /// fit their types by construction, but each step is checked so that
    /// a slip in the constants could not panic.
    fn try_from_unix(secs: u64) -> Option<Self> {
        let days = secs / 86_400;
        let rem = secs % 86_400;
        let z = days.checked_add(719_468)?;
        let era = z / 146_097;
        let doe = z.checked_sub(era.checked_mul(146_097)?)?;
        let yoe = doe
            .checked_sub(doe / 1_460)?
            .checked_add(doe / 36_524)?
            .checked_sub(doe / 146_096)?
            / 365;
        let doy = doe.checked_sub(
            yoe.checked_mul(365)?
                .checked_add(yoe / 4)?
                .checked_sub(yoe / 100)?,
        )?;
        let mp = doy.checked_mul(5)?.checked_add(2)? / 153;
        let day = doy
            .checked_sub(mp.checked_mul(153)?.checked_add(2)? / 5)?
            .checked_add(1)?;
        let month = if mp < 10 {
            mp.checked_add(3)?
        } else {
            mp.checked_sub(9)?
        };
        let mut year = yoe.checked_add(era.checked_mul(400)?)?;
        if month <= 2 {
            year = year.checked_add(1)?;
        }
        Some(Self {
            year,
            month: u8::try_from(month).ok()?,
            day: u8::try_from(day).ok()?,
            hour: u8::try_from(rem / 3_600).ok()?,
            minute: u8::try_from((rem % 3_600) / 60).ok()?,
            second: u8::try_from(rem % 60).ok()?,
        })
    }

    /// The month's name, three letters: `Jan`.
    #[must_use]
    pub fn month_name(&self) -> &'static [u8; 3] {
        MONTHS
            .get(usize::from(self.month.saturating_sub(1)))
            .copied()
            .unwrap_or(b"Jan")
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

    #[test]
    fn civil_dates_match_known_moments() {
        let c = |secs| {
            let c = Civil::from_unix(secs);
            (c.year, c.month, c.day, c.hour, c.minute, c.second)
        };
        assert_eq!(c(0), (1970, 1, 1, 0, 0, 0));
        // RFC 9110's example date, Sun, 06 Nov 1994 08:49:37 GMT
        assert_eq!(c(784_111_777), (1994, 11, 6, 8, 49, 37));
        // a leap day, and the day after
        assert_eq!(c(951_782_400), (2000, 2, 29, 0, 0, 0));
        assert_eq!(c(951_868_799), (2000, 2, 29, 23, 59, 59));
        assert_eq!(c(951_868_800), (2000, 3, 1, 0, 0, 0));
        // 2100 is not a leap year
        assert_eq!(c(4_107_456_000), (2100, 2, 28, 0, 0, 0));
        assert_eq!(c(4_107_542_400), (2100, 3, 1, 0, 0, 0));
        // the end of 2026
        assert_eq!(c(1_798_761_599), (2026, 12, 31, 23, 59, 59));
        assert_eq!(c(1_798_761_600), (2027, 1, 1, 0, 0, 0));
        assert_eq!(c(2_147_483_647), (2038, 1, 19, 3, 14, 7));
        assert_eq!(Civil::from_unix(784_111_777).month_name(), b"Nov");
    }

    #[test]
    fn every_day_of_four_centuries_comes_out_in_order() {
        // 146097 days is the calendar's whole cycle: each day's parts are
        // in range, and each day follows the one before
        let mut last = (1969, 12, 31);
        for day in 0..146_097u64 {
            let c = Civil::from_unix(day * 86_400 + 43_200);
            assert!(
                (1..=12).contains(&c.month) && (1..=31).contains(&c.day),
                "{c:?}"
            );
            assert_eq!((c.hour, c.minute, c.second), (12, 0, 0));
            let this = (c.year, c.month, c.day);
            assert!(this > last, "{this:?} after {last:?}");
            if (c.month, c.day) == (1, 1) {
                assert_eq!(c.year, last.0 + 1);
            }
            last = this;
        }
        assert_eq!(last, (2369, 12, 31));
    }

    #[test]
    fn the_last_second_is_some_moment() {
        let c = Civil::from_unix(u64::MAX);
        assert!(c.year > 1970 && (1..=12).contains(&c.month));
    }
}
