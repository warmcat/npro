//! Where a head's headers are kept: C's `struct allocated_headers`, the
//! "ah".
//!
//! The values are laid down in one caller-owned buffer as they arrive, each
//! piece a fragment: where it starts and how long it is.  A token's first
//! fragment is found from the token, and a header that comes again chains
//! another fragment onto it.  A header lws does not know is kept as a
//! record in the same buffer, its name and value behind eight bytes saying
//! how long each is and where the next record is, the records linked in
//! the order their names ended.
//!
//! The layout is C's, byte for byte in what it uses up: each value ends in
//! a NUL C's string users need, a record starts with C's eight bytes, and
//! the fragment slots are C's `WSI_TOKEN_COUNT`.  So a head fills the table
//! at the same byte as it fills C's, and is refused there as C refuses it.
//!
//! Where C says a token is present by a nonzero fragment index, and a link
//! ends at a zero one, here they are `Slot` and an `Option`.

use crate::token::Token;

/// The most a table holds, as C caps `max_http_header_data`.
pub const MAX_CAPACITY: usize = 32768;

/// What C's `max_http_header_data` is unless it is set.
pub const DEFAULT_CAPACITY: usize = 4096;

/// The bytes of an unknown header's record before its name: its name's
/// length, its value's, and the next record's offset, big endian, as C's
/// `UHO_NLEN`, `UHO_VLEN` and `UHO_LL`.
const RECORD: u16 = 8;

/// A table's storage is past [`MAX_CAPACITY`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityTooLarge;

impl core::fmt::Display for CapacityTooLarge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "a header table holds at most {MAX_CAPACITY} bytes")
    }
}

impl core::error::Error for CapacityTooLarge {}

/// What was asked to go into the table does not fit: its storage is full,
/// or every fragment slot is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

impl core::fmt::Display for Full {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the header table is full")
    }
}

impl core::error::Error for Full {}

/// A buffer is too small for what was to be copied into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooSmall {
    /// How many bytes it needs.
    pub needed: usize,
}

impl core::fmt::Display for TooSmall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the buffer is too small: {} bytes are needed",
            self.needed
        )
    }
}

impl core::error::Error for TooSmall {}

/// A fragment slot, `1..Token::COUNT` as C numbers `ah->frags[]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FragId(u8);

impl FragId {
    fn slot(self) -> usize {
        usize::from(self.0)
    }
}

/// One piece of a value: C's `struct lws_fragments`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Frag {
    offset: u16,
    len: u16,
    /// The fragment continuing this token's value, if any.
    next: Option<FragId>,
}

/// Whether a token is in the table, and where its value starts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Slot {
    #[default]
    Absent,
    Present(FragId),
}

/// The unknown headers' records, as C's `unk_ll_head` and `unk_ll_tail`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Unknowns {
    #[default]
    None,
    Linked {
        head: u16,
        tail: u16,
    },
}

/// Where a client's response starts in the table, as C's `rx_snap_*`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Mark {
    pos: u16,
    nfrag: u8,
    unknowns: Unknowns,
}

/// A head's headers.
///
/// `S` is the storage: `[u8; 4096]` on a device, a `Box<[u8]>` where there
/// is an allocator.  Its length is the table's capacity, C's
/// `max_http_header_data`, at most [`MAX_CAPACITY`].
///
/// [`crate::head::Head`] fills one from a peer's bytes.  Values are bytes,
/// not text: a header's value may be anything but NUL, CR and LF.
///
/// ```
/// use npro_h1::table::HeaderTable;
/// use npro_h1::token::Token;
///
/// let mut t = HeaderTable::new([0u8; 256])?;
/// t.create(Token::ClientUri, b"/x")?;
/// assert_eq!(t.first(Token::ClientUri), Some(&b"/x"[..]));
/// assert!(!t.is_present(Token::Host));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct HeaderTable<S> {
    data: S,
    capacity: u16,
    pos: u16,
    nfrag: u8,
    frags: [Frag; Token::COUNT],
    index: [Slot; Token::COUNT],
    unknowns: Unknowns,
    mark: Mark,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> HeaderTable<S> {
    /// An empty table in `data`.
    ///
    /// # Errors
    ///
    /// [`CapacityTooLarge`] if `data` is longer than [`MAX_CAPACITY`].
    pub fn new(data: S) -> Result<Self, CapacityTooLarge> {
        if data.as_ref().len() > MAX_CAPACITY {
            return Err(CapacityTooLarge);
        }
        let capacity = u16::try_from(data.as_ref().len()).map_err(|_| CapacityTooLarge)?;
        Ok(Self {
            data,
            capacity,
            pos: 0,
            nfrag: 0,
            frags: [Frag::default(); Token::COUNT],
            index: [Slot::Absent; Token::COUNT],
            unknowns: Unknowns::None,
            mark: Mark::default(),
        })
    }

    /// Gives back the storage the table was made in, as C's
    /// `lws_header_table_detach()` gives its ah back to the pool.
    #[must_use]
    pub fn into_storage(self) -> S {
        self.data
    }

    /// Empties the table, as C's `_lws_header_table_reset()`.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.nfrag = 0;
        self.frags = [Frag::default(); Token::COUNT];
        self.index = [Slot::Absent; Token::COUNT];
        self.unknowns = Unknowns::None;
        self.mark = Mark::default();
    }

    /// How many bytes the table holds.
    #[must_use]
    pub fn capacity(&self) -> usize {
        usize::from(self.capacity)
    }

    /// How many bytes are used.
    #[must_use]
    pub fn used(&self) -> usize {
        usize::from(self.pos)
    }

    /// Whether `token` is in the table: C's `lws_hdr_extant()`.
    #[must_use]
    pub fn is_present(&self, token: Token) -> bool {
        matches!(self.slot(token), Slot::Present(_))
    }

    /// The pieces of `token`'s value, one for each time the header came, or
    /// for the urlargs one per argument.  Empty if the token is absent.
    ///
    /// ```
    /// use npro_h1::head::{Config, Head, Side};
    /// use npro_h1::token::Token;
    ///
    /// let mut h = Head::new([0u8; 512], Side::Server, Config::default())?;
    /// h.rx(b"GET /?a=1&b=2 HTTP/1.1\r\n\r\n")?;
    /// let args: Vec<&[u8]> = h.table().fragments(Token::UriArgs).collect();
    /// assert_eq!(args, [&b"a=1"[..], b"b=2"]);
    /// # Ok::<(), Box<dyn core::error::Error>>(())
    /// ```
    #[must_use]
    pub fn fragments(&self, token: Token) -> Fragments<'_> {
        Fragments {
            data: self.data.as_ref(),
            frags: &self.frags,
            next: match self.slot(token) {
                Slot::Present(f) => Some(f),
                Slot::Absent => None,
            },
        }
    }

    /// The first piece of `token`'s value: C's `lws_hdr_simple_ptr()`.
    #[must_use]
    pub fn first(&self, token: Token) -> Option<&[u8]> {
        self.fragments(token).next()
    }

    /// How long `token`'s value is with its pieces joined, as
    /// [`copy`](Self::copy) joins them: C's `lws_hdr_total_length()`.
    #[must_use]
    pub fn total_len(&self, token: Token) -> usize {
        let mut n = 0usize;
        for (i, f) in self.fragments(token).enumerate() {
            if i > 0 {
                n = n.saturating_add(1);
            }
            n = n.saturating_add(f.len());
        }
        n
    }

    /// Copies `token`'s value into `out`, its pieces joined by `,`, or by
    /// `;` for cookies and `&` for urlargs: C's `lws_hdr_copy()`.  Returns
    /// how much of `out` it used, which is nothing if the token is absent.
    ///
    /// # Errors
    ///
    /// [`TooSmall`], copying nothing, if the value does not fit.
    pub fn copy(&self, token: Token, out: &mut [u8]) -> Result<usize, TooSmall> {
        let needed = self.total_len(token);
        let Some(dst) = out.get_mut(..needed) else {
            return Err(TooSmall { needed });
        };
        let sep = if token == Token::Cookie || token == Token::SetCookie {
            b';'
        } else if token == Token::UriArgs {
            b'&'
        } else {
            b','
        };
        let mut at = 0usize;
        for (i, f) in self.fragments(token).enumerate() {
            if i > 0 {
                if let Some(b) = dst.get_mut(at) {
                    *b = sep;
                }
                at = at.saturating_add(1);
            }
            let end = at.saturating_add(f.len());
            if let Some(d) = dst.get_mut(at..end) {
                d.copy_from_slice(f);
            }
            at = end;
        }
        Ok(needed)
    }

    /// The headers lws does not know, as (name, value), in the order their
    /// names ended.  A name is lowercase and ends with its `:`, as C keeps
    /// it.
    ///
    /// ```
    /// use npro_h1::head::{Config, Head, Side};
    ///
    /// let mut h = Head::new([0u8; 512], Side::Server, Config::default())?;
    /// h.rx(b"GET / HTTP/1.1\r\nX-Foo: bar\r\n\r\n")?;
    /// let u: Vec<(&[u8], &[u8])> = h.table().unknown_headers().collect();
    /// assert_eq!(u, [(&b"x-foo:"[..], &b"bar"[..])]);
    /// # Ok::<(), Box<dyn core::error::Error>>(())
    /// ```
    #[must_use]
    pub fn unknown_headers(&self) -> UnknownHeaders<'_> {
        UnknownHeaders {
            data: self.data.as_ref(),
            next: match self.unknowns {
                Unknowns::Linked { head, .. } => Some(head),
                Unknowns::None => None,
            },
        }
    }

    /// The value of the unknown header `name`, given lowercase with its
    /// `:`: C's `lws_hdr_custom_copy()`.
    #[must_use]
    pub fn unknown(&self, name: &[u8]) -> Option<&[u8]> {
        self.unknown_headers()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v)
    }

    /// Adds `value` to `token`, as another piece if it is there already:
    /// C's `lws_hdr_simple_create()`, how a client keeps its own request.
    /// An empty `value` takes the token out of the table.
    ///
    /// Unlike C, which can leave part of a value behind when it runs out
    /// of room, it adds all of it or nothing.
    ///
    /// # Errors
    ///
    /// [`Full`], changing nothing, if there is no room for it.
    pub fn create(&mut self, token: Token, value: &[u8]) -> Result<(), Full> {
        if value.is_empty() {
            if let Some(s) = self.index.get_mut(token.index()) {
                *s = Slot::Absent;
            }
            return Ok(());
        }
        // the value and its NUL
        let len = u16::try_from(value.len()).map_err(|_| Full)?;
        let end = self
            .pos
            .checked_add(len)
            .and_then(|e| e.checked_add(1))
            .ok_or(Full)?;
        if end > self.capacity {
            return Err(Full);
        }
        self.start_fragment(token)?;
        let start = self.pos;
        let dst = self
            .data
            .as_mut()
            .get_mut(usize::from(start)..usize::from(end))
            .ok_or(Full)?;
        let (v, nul) = dst.split_at_mut(value.len());
        v.copy_from_slice(value);
        nul.fill(0);
        self.pos = end;
        if let Some(f) = self.current_mut() {
            f.len = len;
        }
        Ok(())
    }

    /// Marks where a client's response starts, after its own request: C's
    /// `lws_header_table_rx_snapshot()`.  [`rewind`](Self::rewind) goes
    /// back to here.
    pub const fn snapshot(&mut self) {
        self.mark = Mark {
            pos: self.pos,
            nfrag: self.nfrag,
            unknowns: self.unknowns,
        };
    }

    /// Drops everything added since the [`snapshot`](Self::snapshot), as a
    /// client does with an interim (1xx) response: C's
    /// `lws_header_table_rx_rewind()`.
    pub fn rewind(&mut self) {
        let mark = self.mark;
        for s in &mut self.index {
            if let Slot::Present(f) = *s {
                if f.0 > mark.nfrag {
                    *s = Slot::Absent;
                }
            }
        }
        for (n, f) in self.frags.iter_mut().enumerate() {
            if n <= usize::from(mark.nfrag) {
                if f.next.is_some_and(|x| x.0 > mark.nfrag) {
                    f.next = None;
                }
            } else {
                *f = Frag::default();
            }
        }
        self.nfrag = mark.nfrag;
        self.pos = mark.pos;
        self.unknowns = mark.unknowns;
        // the restored tail's link still names a dropped record
        if let Unknowns::Linked { tail, .. } = self.unknowns {
            self.write_be(tail.saturating_add(4), &[0; 4]);
        }
    }

    // What the head parser builds the table with.

    fn slot(&self, token: Token) -> Slot {
        self.index
            .get(token.index())
            .copied()
            .unwrap_or(Slot::Absent)
    }

    pub(crate) const fn pos(&self) -> u16 {
        self.pos
    }

    pub(crate) const fn has_fragments(&self) -> bool {
        self.nfrag != 0
    }

    /// Whether another byte fits: C's `lws_pos_in_bounds()`.
    pub(crate) const fn has_room(&self) -> bool {
        self.pos < self.capacity
    }

    /// The byte at `at`, if it is in the table.
    pub(crate) fn byte(&self, at: u16) -> Option<u8> {
        self.data.as_ref().get(usize::from(at)).copied()
    }

    /// Lays down `c` past everything, outside any fragment.
    pub(crate) fn push(&mut self, c: u8) -> Result<(), Full> {
        if !self.has_room() {
            return Err(Full);
        }
        let slot = self
            .data
            .as_mut()
            .get_mut(usize::from(self.pos))
            .ok_or(Full)?;
        *slot = c;
        self.pos = self.pos.checked_add(1).ok_or(Full)?;
        Ok(())
    }

    /// Sets the end of the table back to `pos`, dropping what is past it.
    pub(crate) fn truncate(&mut self, pos: u16) {
        self.pos = self.pos.min(pos);
    }

    fn current_mut(&mut self) -> Option<&mut Frag> {
        self.frags.get_mut(usize::from(self.nfrag))
    }

    /// The fragment being filled.
    pub(crate) fn current(&self) -> &[u8] {
        let Some(f) = self.frags.get(usize::from(self.nfrag)) else {
            return &[];
        };
        let start = usize::from(f.offset);
        self.data
            .as_ref()
            .get(start..start.saturating_add(usize::from(f.len)))
            .unwrap_or_default()
    }

    /// How long the fragment being filled is.
    pub(crate) fn current_len(&self) -> u16 {
        self.frags.get(usize::from(self.nfrag)).map_or(0, |f| f.len)
    }

    /// Whether the fragment being filled is `token`'s first.
    pub(crate) fn filling_first(&self, token: Token) -> bool {
        self.slot(token) == Slot::Present(FragId(self.nfrag))
    }

    /// How long `token`'s first fragment is.
    pub(crate) fn first_len(&self, token: Token) -> u16 {
        match self.slot(token) {
            Slot::Present(f) => self.frags.get(f.slot()).map_or(0, |f| f.len),
            Slot::Absent => 0,
        }
    }

    /// Adds `c` to the fragment being filled, `max` being the most it may
    /// hold: C's `issue_char()`.  A NUL is the fragment's end, and does not
    /// count against `max`.
    pub(crate) fn issue(&mut self, c: u8, max: Option<u16>) -> Result<(), Full> {
        if !self.has_room() {
            return Err(Full);
        }
        let len = self.current_len();
        if c != 0 && max.is_some_and(|m| len >= m) {
            return Err(Full);
        }
        self.push(c)?;
        if let Some(f) = self.current_mut() {
            f.len = f.len.saturating_add(1);
        }
        Ok(())
    }

    /// Takes the last byte of the fragment being filled out of its length,
    /// leaving it in the table: how C leaves the NUL after a value.
    pub(crate) fn uncount(&mut self) {
        if let Some(f) = self.current_mut() {
            f.len = f.len.saturating_sub(1);
        }
    }

    /// Begins a fragment for `token`, chained on to its last if it is
    /// there already.  Returns whether it was.
    pub(crate) fn start_fragment(&mut self, token: Token) -> Result<bool, Full> {
        let id = self.next_frag()?;
        let pos = self.pos;
        if let Some(f) = self.frags.get_mut(id.slot()) {
            *f = Frag {
                offset: pos,
                len: 0,
                next: None,
            };
        }
        self.nfrag = id.0;
        let Some(slot) = self.index.get_mut(token.index()) else {
            return Err(Full);
        };
        let Slot::Present(mut last) = *slot else {
            *slot = Slot::Present(id);
            return Ok(false);
        };
        // to the end of the chain, which only goes forward
        while let Some(n) = self.frags.get(last.slot()).and_then(|f| f.next) {
            if n <= last {
                break;
            }
            last = n;
        }
        if let Some(f) = self.frags.get_mut(last.slot()) {
            f.next = Some(id);
        }
        Ok(true)
    }

    /// The next fragment slot, if there is one: C's check before moving
    /// `nfrag` on.
    fn next_frag(&self) -> Result<FragId, Full> {
        let n = self.nfrag.checked_add(1).ok_or(Full)?;
        if usize::from(n) >= Token::COUNT {
            return Err(Full);
        }
        Ok(FragId(n))
    }

    /// Ends the urlarg being filled and begins the next, at `&` or `;`.
    /// The caller has laid down the NUL that ends it.
    pub(crate) fn next_arg(&mut self) -> Result<(), Full> {
        let id = self.next_frag()?;
        if !self.has_room() {
            return Err(Full);
        }
        if let Some(f) = self.current_mut() {
            f.next = Some(id);
        }
        self.nfrag = id.0;
        let pos = self.pos;
        if let Some(f) = self.current_mut() {
            *f = Frag {
                offset: pos,
                len: 0,
                next: None,
            };
        }
        Ok(())
    }

    /// Begins the urlargs, at the request target's `?`.  The caller has
    /// laid down the NUL that ends the path.  The urlargs start a byte
    /// past it, as in C.
    pub(crate) fn start_args(&mut self) -> Result<(), Full> {
        let id = self.next_frag()?;
        let at = self.pos.checked_add(1).ok_or(Full)?;
        if at >= self.capacity {
            return Err(Full);
        }
        self.nfrag = id.0;
        self.pos = at;
        if let Some(f) = self.current_mut() {
            *f = Frag {
                offset: at,
                len: 0,
                next: None,
            };
        }
        if let Some(s) = self.index.get_mut(Token::UriArgs.index()) {
            *s = Slot::Present(id);
        }
        Ok(())
    }

    /// Takes the path being filled back to the `/` before its last
    /// segment, for a `/..`: the loop C has at each `/../`.
    pub(crate) fn back_up_a_segment(&mut self) {
        if self.current_len() <= 2 {
            return;
        }
        self.pos = self.pos.saturating_sub(1);
        self.uncount();
        loop {
            self.pos = self.pos.saturating_sub(1);
            self.uncount();
            if self.current_len() <= 1 || self.byte(self.pos) == Some(b'/') {
                break;
            }
        }
    }

    /// Begins an unknown header's record at the end of the table, its
    /// eight bytes zeroed while there is room for them, as C does.
    pub(crate) fn begin_record(&mut self) -> u16 {
        let at = self.pos;
        for _ in 0..RECORD {
            if self.push(0).is_err() {
                break;
            }
        }
        at
    }

    /// The name of the record at `rec` so far, everything past its eight
    /// bytes.
    pub(crate) fn record_name(&self, rec: u16) -> &[u8] {
        let start = usize::from(rec.saturating_add(RECORD));
        self.data
            .as_ref()
            .get(start..usize::from(self.pos))
            .unwrap_or_default()
    }

    /// The name of the record at `rec` has ended, here: its length goes in
    /// its record, and the record on the end of the list.
    pub(crate) fn end_record_name(&mut self, rec: u16) {
        self.unknowns = match self.unknowns {
            Unknowns::None => Unknowns::Linked {
                head: rec,
                tail: rec,
            },
            Unknowns::Linked { head, tail } => {
                self.write_be(tail.saturating_add(4), &u32::from(rec).to_be_bytes());
                Unknowns::Linked { head, tail: rec }
            }
        };
        let nlen = self.pos.saturating_sub(rec.saturating_add(RECORD));
        self.write_be(rec, &nlen.to_be_bytes());
    }

    /// The value of the record at `rec`, which started at `value`, has
    /// ended, here.
    pub(crate) fn end_record_value(&mut self, rec: u16, value: u16) {
        let vlen = self.pos.saturating_sub(value);
        self.write_be(rec.saturating_add(2), &vlen.to_be_bytes());
    }

    fn write_be(&mut self, at: u16, bytes: &[u8]) {
        let at = usize::from(at);
        if let Some(d) = self
            .data
            .as_mut()
            .get_mut(at..at.saturating_add(bytes.len()))
        {
            d.copy_from_slice(bytes);
        }
    }
}

/// The pieces of a token's value: see [`HeaderTable::fragments`].
#[derive(Clone, Debug)]
pub struct Fragments<'a> {
    data: &'a [u8],
    frags: &'a [Frag; Token::COUNT],
    next: Option<FragId>,
}

impl<'a> Iterator for Fragments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let id = self.next?;
        let f = self.frags.get(id.slot())?;
        // a chain only goes forward, as C's lws_ah_frag_next() insists
        self.next = f.next.filter(|n| *n > id);
        let start = usize::from(f.offset);
        self.data
            .get(start..start.saturating_add(usize::from(f.len)))
    }
}

/// The unknown headers: see [`HeaderTable::unknown_headers`].
#[derive(Clone, Debug)]
pub struct UnknownHeaders<'a> {
    data: &'a [u8],
    next: Option<u16>,
}

impl<'a> Iterator for UnknownHeaders<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let rec = usize::from(self.next?);
        let head = self.data.get(rec..rec.saturating_add(8))?;
        let (nlen, rest) = head.split_first_chunk::<2>()?;
        let (vlen, link) = rest.split_first_chunk::<2>()?;
        let link = u32::from_be_bytes(*link.first_chunk::<4>()?);
        // the next record is further on, or there is none: never round
        self.next = u16::try_from(link).ok().filter(|n| usize::from(*n) > rec);
        let name = rec.saturating_add(8);
        let value = name.saturating_add(usize::from(u16::from_be_bytes(*nlen)));
        let end = value.saturating_add(usize::from(u16::from_be_bytes(*vlen)));
        Some((self.data.get(name..value)?, self.data.get(value..end)?))
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn storage_past_the_cap_is_refused() {
        assert!(HeaderTable::new(vec![0u8; MAX_CAPACITY]).is_ok());
        assert_eq!(
            HeaderTable::new(vec![0u8; MAX_CAPACITY + 1]).err(),
            Some(CapacityTooLarge)
        );
    }

    #[test]
    fn create_chains_and_copy_joins() {
        let mut t = HeaderTable::new([0u8; 64]).unwrap();
        t.create(Token::Accept, b"a").unwrap();
        t.create(Token::Accept, b"bc").unwrap();
        t.create(Token::Cookie, b"x=1").unwrap();
        t.create(Token::Cookie, b"y=2").unwrap();
        assert_eq!(t.total_len(Token::Accept), 4);
        let mut out = [0u8; 8];
        assert_eq!(t.copy(Token::Accept, &mut out), Ok(4));
        assert_eq!(&out[..4], b"a,bc");
        assert_eq!(t.copy(Token::Cookie, &mut out), Ok(7));
        assert_eq!(&out[..7], b"x=1;y=2");
        assert_eq!(
            t.copy(Token::Cookie, &mut [0u8; 6]),
            Err(TooSmall { needed: 7 })
        );
        // each value and its NUL
        assert_eq!(t.used(), 2 + 3 + 4 + 4);
    }

    #[test]
    fn create_is_all_or_nothing() {
        let mut t = HeaderTable::new([0u8; 8]).unwrap();
        t.create(Token::Host, b"abc").unwrap();
        assert_eq!(t.create(Token::Host, b"defg"), Err(Full));
        assert_eq!(t.first(Token::Host), Some(&b"abc"[..]));
        assert_eq!(t.fragments(Token::Host).count(), 1);
        t.create(Token::Host, b"").unwrap();
        assert!(!t.is_present(Token::Host));
    }

    #[test]
    fn rewind_keeps_what_was_before_the_snapshot() {
        let mut t = HeaderTable::new([0u8; 64]).unwrap();
        t.create(Token::ClientUri, b"/x").unwrap();
        t.create(Token::Accept, b"a").unwrap();
        t.snapshot();
        let used = t.used();
        t.create(Token::Accept, b"b").unwrap();
        t.create(Token::Host, b"h").unwrap();
        t.rewind();
        assert_eq!(t.used(), used);
        assert!(!t.is_present(Token::Host));
        assert_eq!(t.fragments(Token::Accept).count(), 1);
        t.create(Token::Accept, b"c").unwrap();
        let v: Vec<&[u8]> = t.fragments(Token::Accept).collect();
        assert_eq!(v, [&b"a"[..], b"c"]);
    }
}
