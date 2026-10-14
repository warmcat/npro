//! A file's bytes going to the stream, a chunk at a time, each read
//! asked of the runner: C's `lws_http_file_tx()` over its async queue.
//!
//! The stream's chance to write ([`Serving::fill`]) is filled from the
//! chunk in hand.  When that is used up and the file is not over, the
//! next read is wanted ([`Serving::wanted`]): the runner takes the file,
//! reads it off the application's turn, and gives both back
//! ([`Serving::read_done`]), on which the stream asks to write again.

use npro_ss::event::Filled;

/// The most a read is asked for at once: what a tls record carries.
pub const CHUNK: usize = 16 * 1024;

/// A read the runner is asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Read {
    /// From this far into the file.
    pub at: u64,
    /// This much, at most: the runner gives what it read, which is less
    /// only at the file's end, or when it has changed.
    pub len: usize,
}

/// Where the file is between reads.
#[derive(Debug)]
enum File<F> {
    /// Here, between reads.
    Held(F),
    /// With the runner, being read, this much asked for.
    Reading(usize),
}

/// A file being served: see the module's description.
#[derive(Debug)]
pub struct Serving<F, C> {
    file: File<F>,
    /// How long the file was when it was opened: what the response
    /// promised.
    len: u64,
    /// How far the stream has been given.
    pos: u64,
    /// The chunk in hand, and how much of it went.
    chunk: Option<(C, usize)>,
}

impl<F, C: AsRef<[u8]>> Serving<F, C> {
    /// Serves `file`, `len` long.
    #[must_use]
    pub const fn new(file: F, len: u64) -> Self {
        Self {
            file: File::Held(file),
            len,
            pos: 0,
            chunk: None,
        }
    }

    /// Fills `buf` from the chunk in hand: how much, and whether that was
    /// the file's last.  With no chunk in hand, nothing, and the next
    /// read is wanted.
    pub fn fill(&mut self, buf: &mut [u8]) -> Filled {
        let Some((chunk, used)) = &mut self.chunk else {
            return Filled::More(0);
        };
        let bytes = chunk.as_ref();
        let rest = bytes.get(*used..).unwrap_or_default();
        let n = rest.len().min(buf.len());
        if let (Some(to), Some(from)) = (buf.get_mut(..n), rest.get(..n)) {
            to.copy_from_slice(from);
        }
        *used = used.saturating_add(n);
        self.pos = self
            .pos
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if *used >= bytes.len() {
            self.chunk = None;
        }
        if self.pos >= self.len {
            Filled::Last(n)
        } else {
            Filled::More(n)
        }
    }

    /// The read wanted next, if one is: the file, for the runner to read
    /// off the turn, and what to read.  Once asked for, it is not asked
    /// for again until [`Serving::read_done`].
    pub fn wanted(&mut self) -> Option<(F, Read)> {
        if self.chunk.is_some() || self.pos >= self.len {
            return None;
        }
        let File::Held(_) = self.file else {
            return None;
        };
        let left = usize::try_from(self.len.saturating_sub(self.pos)).unwrap_or(usize::MAX);
        let len = left.min(CHUNK);
        let File::Held(file) = core::mem::replace(&mut self.file, File::Reading(len)) else {
            return None;
        };
        Some((file, Read { at: self.pos, len }))
    }

    /// The read came to `chunk`, and `file` is back.  The stream then asks
    /// to write.  A chunk short of what was asked is the file's end: it
    /// shrank since it was opened, and the stream's answer ends short of
    /// its length, which the connection answers by closing, as C's
    /// `file_had_it` does.
    pub fn read_done(&mut self, file: F, chunk: C) {
        if let File::Reading(asked) = self.file {
            let got = chunk.as_ref().len();
            if got < asked {
                self.len = self
                    .pos
                    .saturating_add(u64::try_from(got).unwrap_or(u64::MAX));
            }
        }
        self.file = File::Held(file);
        self.chunk = Some((chunk, 0));
    }

    /// How much of the file the stream has been given.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.pos
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn chunks_are_asked_for_one_at_a_time_and_the_last_ends_the_file() {
        let data: Vec<u8> = (0..40_000u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let mut s: Serving<(), Vec<u8>> = Serving::new((), 40_000);
        let mut got = Vec::new();
        let mut reads = 0;
        loop {
            let mut buf = [0u8; 1000];
            match s.fill(&mut buf) {
                Filled::More(0) => {
                    let (f, r) = s.wanted().unwrap();
                    // not asked twice
                    assert!(s.wanted().is_none());
                    assert_eq!(r.at, u64::try_from(got.len()).unwrap());
                    assert_eq!(r.len, CHUNK.min(40_000 - got.len()));
                    let at = usize::try_from(r.at).unwrap();
                    s.read_done(f, data[at..at + r.len].to_vec());
                    reads += 1;
                }
                Filled::More(n) => got.extend_from_slice(&buf[..n]),
                Filled::Last(n) => {
                    got.extend_from_slice(&buf[..n]);
                    break;
                }
            }
        }
        assert_eq!(got, data);
        assert_eq!(reads, 3);
        assert_eq!(s.position(), 40_000);
        assert!(s.wanted().is_none());
    }

    #[test]
    fn a_short_read_ends_the_file_short() {
        let mut s: Serving<(), Vec<u8>> = Serving::new((), 100);
        let (f, r) = s.wanted().unwrap();
        assert_eq!(r.len, 100);
        s.read_done(f, alloc::vec![1u8; 30]);
        let mut buf = [0u8; 50];
        assert_eq!(s.fill(&mut buf), Filled::Last(30));
        assert_eq!(s.position(), 30);
    }
}
