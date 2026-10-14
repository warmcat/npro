//! One direction's bytes, between the side they came from and the side
//! they go to: bounded, with the marks at which the side they come from
//! is held back and let go again, as C's proxy has
//! `LWS_HTTP_PROXY_BODY_BUFFERED_HI` and `LWS_WS_PROXY_BUFFERED_LO`.

/// How much one direction's storage should hold, for a server: room
/// enough that what a giving side staged while the taking side was
/// past the high mark (one piece of what its connection read, at most)
/// always fits when it is moved, as it must be once the giving side is
/// gone.  The storage is the caller's, so a device may give less.
pub const CAPACITY: usize = 64 * 1024;

/// Bytes one side gave that the other has not yet taken, in order, in
/// storage the caller gave.  Past a quarter of it held, the giving side
/// is held back; below an eighth, let go again.
#[derive(Clone, Debug)]
pub struct Buffer<B> {
    bytes: B,
    /// Where the unread bytes start.
    start: usize,
    /// Where they end.
    end: usize,
    /// The side giving has given its last.
    ended: bool,
}

/// What the buffer wants of the side that fills it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fill {
    /// There is room: let it give more.
    More,
    /// It is past the high mark: hold the giving side back until the
    /// taking side has drained it below the low one.
    Hold,
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Buffer<B> {
    /// Empty, in `storage`.
    #[must_use]
    pub const fn new(storage: B) -> Self {
        Self {
            bytes: storage,
            start: 0,
            end: 0,
            ended: false,
        }
    }

    /// How much it can hold: its storage's length.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.bytes.as_ref().len()
    }

    /// Past this much held, the giving side is held back.
    fn high(&self) -> usize {
        self.capacity() / 4
    }

    /// Below this much held, a giving side held back is let go.
    fn low(&self) -> usize {
        self.capacity() / 8
    }

    /// How much is held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Nothing is held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the giving side has given its last.
    #[must_use]
    pub const fn ended(&self) -> bool {
        self.ended
    }

    /// Room for this much more.
    #[must_use]
    pub fn room(&self) -> usize {
        self.capacity().saturating_sub(self.len())
    }

    /// Puts `bytes` in, as far as there is room: how many were taken, and
    /// whether the giving side is to be held back now.  A piece the
    /// giving side was told to give (its connection's rx buffer is no
    /// larger than this) fits whole while the side is not held.
    pub fn put(&mut self, bytes: &[u8]) -> (usize, Fill) {
        let capacity = self.capacity();
        if self.start > 0 && self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
        // make room at the front once the back is reached
        if self.end.saturating_add(bytes.len()) > capacity && self.start > 0 {
            self.bytes.as_mut().copy_within(self.start..self.end, 0);
            self.end = self.end.saturating_sub(self.start);
            self.start = 0;
        }
        let n = bytes.len().min(capacity.saturating_sub(self.end));
        if let (Some(to), Some(from)) = (
            self.bytes
                .as_mut()
                .get_mut(self.end..self.end.saturating_add(n)),
            bytes.get(..n),
        ) {
            to.copy_from_slice(from);
        }
        self.end = self.end.saturating_add(n);
        let fill = if self.past_high() {
            Fill::Hold
        } else {
            Fill::More
        };
        (n, fill)
    }

    /// The giving side gave its last: once what is held has gone, the
    /// taking side's answer is over.
    pub const fn end(&mut self) {
        self.ended = true;
    }

    /// Takes as much as fits `out`: how many.
    pub fn take(&mut self, out: &mut [u8]) -> usize {
        let held = self
            .bytes
            .as_ref()
            .get(self.start..self.end)
            .unwrap_or_default();
        let n = held.len().min(out.len());
        if let (Some(to), Some(from)) = (out.get_mut(..n), held.get(..n)) {
            to.copy_from_slice(from);
        }
        self.start = self.start.saturating_add(n);
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
        n
    }

    /// Whether a giving side held back may be let go: what is held is
    /// below the low mark.
    #[must_use]
    pub fn below_low(&self) -> bool {
        self.len() < self.low()
    }

    /// Whether the giving side is to be held back: what is held is past
    /// the high mark.
    #[must_use]
    pub fn past_high(&self) -> bool {
        self.len() >= self.high()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec;

    /// A small storage, for the tests.
    const SIZE: usize = 1024;

    #[test]
    fn bytes_come_out_as_they_went_in_within_the_capacity() {
        let mut b = Buffer::new([0u8; SIZE]);
        assert!(b.is_empty());
        assert_eq!(b.capacity(), SIZE);
        assert_eq!(b.put(b"hello"), (5, Fill::More));
        let mut out = [0u8; 3];
        assert_eq!(b.take(&mut out), 3);
        assert_eq!(&out, b"hel");
        assert_eq!(b.len(), 2);
        // past the high mark, a quarter: hold
        let big = [b'x'; SIZE / 4];
        assert_eq!(b.put(&big), (SIZE / 4, Fill::Hold));
        assert!(!b.below_low() && b.past_high());
        // no more room than the capacity, however it is asked
        let more = [b'y'; SIZE];
        let (n, _) = b.put(&more);
        assert_eq!(n, SIZE - SIZE / 4 - 2);
        assert_eq!(b.room(), 0);
        let mut all = vec![0u8; SIZE];
        assert_eq!(b.take(&mut all), SIZE);
        assert_eq!(&all[..2], b"lo");
        assert!(b.is_empty() && b.below_low());
        b.end();
        assert!(b.ended());
    }

    #[test]
    fn room_is_made_at_the_front_as_the_back_is_reached() {
        let mut b = Buffer::new(vec![0u8; SIZE]);
        let chunk = [b'a'; SIZE - 10];
        assert_eq!(b.put(&chunk).0, SIZE - 10);
        let mut out = vec![0u8; SIZE - 20];
        assert_eq!(b.take(&mut out), SIZE - 20);
        // 10 held at the back: the next piece needs the front
        assert_eq!(b.put(&[b'b'; 100]).0, 100);
        assert_eq!(b.len(), 110);
        let mut rest = vec![0u8; 110];
        assert_eq!(b.take(&mut rest), 110);
        assert_eq!(&rest[..10], &[b'a'; 10]);
        assert_eq!(&rest[10..], &[b'b'; 100]);
    }
}
