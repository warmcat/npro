//! The ids npro-ss hands out: a stream's, for the application, and a
//! connection's and a listener's, for the adapter.
//!
//! A stream or connection id carries the generation of the slot it was
//! given from, so once its stream or connection is gone, the id is refused
//! even after the slot carries another: it is never taken for the new one.

use core::fmt;

/// A listener: its place in the policy's list.
///
/// ```
/// use npro_ss::id::ListenerId;
///
/// assert_eq!(ListenerId::new(2).index(), 2);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenerId(u32);

impl ListenerId {
    /// The listener at `index` in the policy's list.
    #[must_use]
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Its place in the policy's list.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ListenerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "listener {}", self.0)
    }
}

/// A stream, as the application holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamId {
    pub(crate) slot: u32,
    pub(crate) generation: u32,
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream {}.{}", self.slot, self.generation)
    }
}

/// A connection, as the adapter holds it, beside its socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnId {
    pub(crate) slot: u32,
    pub(crate) generation: u32,
}

impl fmt::Display for ConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "conn {}.{}", self.slot, self.generation)
    }
}
