//! npro-json: JSON for npro, sans-IO.
//!
//! What npro reads as JSON, its policy above all (`docs/ss-policy.md`),
//! is configuration that someone other than the programmer wrote, and
//! may have come over the network.  So this is a parser for I-JSON
//! (RFC 7493), the profile of JSON (RFC 8259) that leaves nothing for two
//! parsers to read differently:
//!
//! - **an object with a member named twice is refused**, as RFC 8259
//!   leaves it to each parser what that means;
//! - the text is UTF-8, with no byte order mark, and no string has a lone
//!   surrogate, raw or escaped, or a noncharacter;
//! - nothing else: no comments, no trailing commas, no single quotes.
//!
//! And one thing more, as C's lejp has it: no string may hold U+0000,
//! even escaped, since what a policy names ends up as paths and headers,
//! where a NUL would truncate it.
//!
//! The parser is a pull parser in the style of npro's protocol crates.
//! Input comes in pieces of any size ([`Parser::next`]), each call takes
//! at most one thing from them and says how much it took, and the input
//! ends with [`Parser::end`].  What it found is an [`Event`]: a container
//! opening or closing, a member's name, or a value.  Strings and numbers
//! are kept whole in caller-owned storage until they end, and the names
//! of the objects open in the same caller's storage, each to be checked
//! against the rest of its object's: so the longest string or number, and
//! all the names of the objects open at once, is what the caller gives,
//! and the depth of nesting is configured ([`Config`]).  Past any of
//! these, the document is refused, never truncated.  Nothing recurses on
//! the input.
//!
//! ```
//! use npro_json::{Config, Event, Parser, Storage};
//!
//! let mut p = Parser::new(
//!     Storage { token: [0u8; 128], names: [0u8; 128] },
//!     Config::new(),
//! )?;
//! let mut input = &br#"{"port": 443, "tls": true}"#[..];
//! let mut seen = Vec::new();
//! while !input.is_empty() {
//!     let step = p.next(input)?;
//!     input = &input[step.consumed..];
//!     if let Some(e) = step.event {
//!         seen.push(format!("{e:?}"));
//!     }
//! }
//! assert_eq!(p.end()?, None);
//! assert_eq!(
//!     seen,
//!     [
//!         "ObjectStart",
//!         "Name(\"port\")",
//!         "Number(Number(\"443\"))",
//!         "Name(\"tls\")",
//!         "Bool(true)",
//!         "ObjectEnd",
//!     ]
//! );
//!
//! let mut p = Parser::new(
//!     Storage { token: [0u8; 128], names: [0u8; 128] },
//!     Config::new(),
//! )?;
//! let twice = br#"{"a": 1, "a": 2}"#;
//! let mut at = 0;
//! let err = loop {
//!     match p.next(&twice[at..]) {
//!         Ok(step) => at += step.consumed,
//!         Err(e) => break e,
//!     }
//! };
//! assert_eq!(err.kind(), npro_json::ErrorKind::Duplicate);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![forbid(unsafe_code)]

/// The deepest nesting [`Config::with_depth`] allows.
pub const MAX_DEPTH: u8 = 64;

/// The nesting a [`Config::new`] allows: objects and arrays within each
/// other this deep.
pub const DEFAULT_DEPTH: u8 = 16;

/// The storage a parser works in, the caller's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Storage<S> {
    /// Where a string or number is kept until it ends: its size is the
    /// longest a string, unescaped, or a number may be.
    pub token: S,
    /// Where the names of the objects open are kept, to find one named
    /// twice: each object open takes 4 bytes, and each of its names 2
    /// more than its length.
    pub names: S,
}

/// How a parser parses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    depth: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    /// Nesting at most [`DEFAULT_DEPTH`] deep.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            depth: DEFAULT_DEPTH,
        }
    }

    /// Nesting at most `depth` deep, 0 being a document that is a lone
    /// string, number or literal.
    ///
    /// # Errors
    ///
    /// [`DepthTooLarge`] past [`MAX_DEPTH`].
    pub const fn with_depth(self, depth: u8) -> Result<Self, DepthTooLarge> {
        if depth > MAX_DEPTH {
            return Err(DepthTooLarge);
        }
        Ok(Self { depth })
    }
}

/// A depth past [`MAX_DEPTH`] was asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepthTooLarge;

impl core::fmt::Display for DepthTooLarge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "a JSON parser nests at most {MAX_DEPTH} deep")
    }
}

impl core::error::Error for DepthTooLarge {}

/// The names storage is longer than its offsets can say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamesTooLarge;

impl core::fmt::Display for NamesTooLarge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a JSON parser's names storage is at most 4 GiB")
    }
}

impl core::error::Error for NamesTooLarge {}

/// What the input was: one thing at a time, in the order it came.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Event<'a> {
    /// `{`.
    ObjectStart,
    /// `}`.
    ObjectEnd,
    /// `[`.
    ArrayStart,
    /// `]`.
    ArrayEnd,
    /// A member's name, unescaped: its value comes next.  No other member
    /// of the same object has had it.
    Name(&'a str),
    /// A string, unescaped.
    String(&'a str),
    /// A number.
    Number(Number<'a>),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
}

/// A number, as it was written: RFC 8259's grammar, checked.  It is the
/// reader's to say what range and precision it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Number<'a>(&'a str);

impl<'a> Number<'a> {
    /// The number as it was written.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }

    /// The number, if it is an integer, written with no fraction or
    /// exponent, from 0 to `u64::MAX`.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        self.0.parse().ok()
    }

    /// The number, if it is an integer, written with no fraction or
    /// exponent, in `i64`'s range.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.0.parse().ok()
    }

    /// The number as the nearest `f64`: infinite if it is beyond one's
    /// range.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        self.0.parse().ok()
    }
}

/// What [`Parser::next`] took.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Step<'a> {
    /// How many bytes it took.  The rest are the caller's to hand in
    /// again.
    pub consumed: usize,
    /// What they came to, if anything yet.
    pub event: Option<Event<'a>>,
}

/// Why a document is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// A byte the grammar has no place for here.
    Unexpected(u8),
    /// The input ended inside the document, or before one.
    Incomplete,
    /// Nesting deeper than [`Config`] allows.
    TooDeep,
    /// A string or number longer than [`Storage::token`].
    TokenTooLong,
    /// More names in the objects open than [`Storage::names`] holds.
    NamesFull,
    /// A member named twice in one object.
    Duplicate,
    /// A string that is not UTF-8.
    Utf8,
    /// An escape that is not one of JSON's, or a `\u` without four hex
    /// digits.
    Escape,
    /// A lone surrogate, escaped.
    Surrogate,
    /// A noncharacter, raw or escaped: U+FDD0 to U+FDEF, or one ending in
    /// FFFE or FFFF.
    Noncharacter,
    /// U+0000, escaped, or any control byte raw in a string.
    Control,
}

impl core::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unexpected(b) => write!(f, "unexpected byte 0x{b:02x}"),
            Self::Incomplete => f.write_str("the document is incomplete"),
            Self::TooDeep => f.write_str("nested too deep"),
            Self::TokenTooLong => f.write_str("a string or number is too long"),
            Self::NamesFull => f.write_str("too many member names"),
            Self::Duplicate => f.write_str("a member is named twice"),
            Self::Utf8 => f.write_str("a string is not UTF-8"),
            Self::Escape => f.write_str("a bad escape"),
            Self::Surrogate => f.write_str("a lone surrogate"),
            Self::Noncharacter => f.write_str("a noncharacter"),
            Self::Control => f.write_str("a control character in a string"),
        }
    }
}

/// Why a document is refused, and where: the byte offset into the whole
/// input of the byte refused, or of its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    at: u64,
}

impl Error {
    /// Why.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Where.
    #[must_use]
    pub const fn at(&self) -> u64 {
        self.at
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.at)
    }
}

impl core::error::Error for Error {}

/// What comes next where no token is under way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// A value: the document's, a member's after its `:`, or an array's
    /// after a `,`.
    Value,
    /// An array's first value, or its `]`.
    ValueOrEnd,
    /// An object's first name, or its `}`.
    NameOrEnd,
    /// A name, after a `,`.
    Name,
    /// The `:` after a name.
    Colon,
    /// A `,` or the container's end, after a value in one.
    CommaOrEnd,
    /// Nothing: the document is over, and only white space may follow.
    Over,
}

/// Which literal is being matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Literal {
    True,
    False,
    Null,
}

impl Literal {
    const fn text(self) -> &'static [u8] {
        match self {
            Self::True => b"true",
            Self::False => b"false",
            Self::Null => b"null",
        }
    }
}

/// Whether a string is a member's name or a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Name,
    Value,
}

/// Where a string is in an escape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Esc {
    /// In none.
    None,
    /// After a `\`.
    Backslash,
    /// After `\u`, `n` hex digits read, their value `acc`.
    Hex { n: u8, acc: u16 },
    /// After a high surrogate's `\uXXXX`: only its low one's `\u` may
    /// follow.
    High(u16),
    /// After a high surrogate and a `\`.
    HighBackslash(u16),
    /// After a high surrogate and `\u`.
    LowHex { high: u16, n: u8, acc: u16 },
}

/// Where a number is in RFC 8259's grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Num {
    /// `-`.
    Minus,
    /// A leading `0`, which nothing but a fraction or exponent follows.
    Zero,
    /// Integer digits.
    Int,
    /// `.`.
    Dot,
    /// Fraction digits.
    Frac,
    /// `e` or `E`.
    E,
    /// The exponent's sign.
    ESign,
    /// Exponent digits.
    Exp,
}

impl Num {
    /// Whether the number may end here.
    const fn may_end(self) -> bool {
        matches!(self, Self::Zero | Self::Int | Self::Frac | Self::Exp)
    }
}

/// Where the parser is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Expect(Expect),
    /// Matching a literal, `at` bytes of it so far.
    Literal {
        lit: Literal,
        at: u8,
    },
    Str {
        role: Role,
        esc: Esc,
    },
    Num(Num),
    /// The document was refused, and stays so.
    Failed(Error),
}

/// What a byte finished, for the event to be made from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Done {
    ObjectStart,
    ObjectEnd,
    ArrayStart,
    ArrayEnd,
    Name,
    String,
    /// A number, ended by the byte after it, which is not taken.
    Number,
    Bool(bool),
    Null,
}

/// Whether a byte was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Took {
    Yes,
    No,
}

/// The offset in the names storage that marks no enclosing object.
const NO_FRAME: u32 = u32::MAX;

/// A JSON parser, whose tokens and names are kept in `S`.
#[derive(Clone, Debug)]
pub struct Parser<S> {
    storage: Storage<S>,
    depth_max: u8,
    /// How many containers are open.
    depth: u8,
    /// Which of the containers open are objects: bit `n` for the one at
    /// depth `n + 1`.
    objects: u64,
    state: State,
    /// How much of `storage.token` the token under way has used.
    token: usize,
    /// How much of `storage.names` is used.
    names: usize,
    /// Where the innermost open object's names begin, after its 4 byte
    /// record of the frame enclosing it, or [`NO_FRAME`].
    frame: u32,
    /// How many bytes were taken, for an error to say where.
    at: u64,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Parser<S> {
    /// A parser keeping its tokens and names in `storage`.
    ///
    /// # Errors
    ///
    /// [`NamesTooLarge`] if [`Storage::names`] is longer than `u32` can
    /// say.
    pub fn new(storage: Storage<S>, config: Config) -> Result<Self, NamesTooLarge> {
        if u32::try_from(storage.names.as_ref().len()).is_err() {
            return Err(NamesTooLarge);
        }
        Ok(Self {
            storage,
            depth_max: config.depth,
            depth: 0,
            objects: 0,
            state: State::Expect(Expect::Value),
            token: 0,
            names: 0,
            frame: NO_FRAME,
            at: 0,
        })
    }

    /// Gives back the storage the parser was made with.
    #[must_use]
    pub fn into_storage(self) -> Storage<S> {
        self.storage
    }

    /// Whether the document is whole: its value ended, and only white
    /// space may follow.  A document that is a lone number is whole only
    /// at [`Parser::end`], as nothing before says it has ended.
    #[must_use]
    pub const fn is_over(&self) -> bool {
        matches!(self.state, State::Expect(Expect::Over))
    }

    /// Takes bytes of the document, as far as the next thing they come
    /// to.  Bytes not taken are the caller's to hand in again: the byte
    /// after a number, which ends it, is not taken with it.
    ///
    /// # Errors
    ///
    /// [`Error`] if the document is refused.  It stays refused: every
    /// call after says the same.
    pub fn next(&mut self, input: &[u8]) -> Result<Step<'_>, Error> {
        if let State::Failed(e) = self.state {
            return Err(e);
        }
        let mut consumed = 0usize;
        let mut done = None;
        for &b in input {
            match self.byte(b) {
                Ok((took, d)) => {
                    if took == Took::Yes {
                        consumed = consumed.saturating_add(1);
                        self.at = self.at.saturating_add(1);
                    }
                    if d.is_some() {
                        done = d;
                        break;
                    }
                }
                Err(kind) => return Err(self.fail(kind)),
            }
        }
        Ok(Step {
            consumed,
            event: done.map(|d| self.event(d)),
        })
    }

    /// The input is over: what was under way ends, a number that is the
    /// whole document among them.  `Ok(None)` is a whole document.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Incomplete`] if the document is not whole, or the
    /// error it was refused with.
    pub fn end(&mut self) -> Result<Option<Event<'_>>, Error> {
        match self.state {
            State::Failed(e) => Err(e),
            State::Expect(Expect::Over) => Ok(None),
            State::Num(n) if n.may_end() && self.depth == 0 => {
                self.state = State::Expect(Expect::Over);
                Ok(Some(self.event(Done::Number)))
            }
            State::Expect(_) | State::Literal { .. } | State::Str { .. } | State::Num(_) => {
                Err(self.fail(ErrorKind::Incomplete))
            }
        }
    }

    const fn fail(&mut self, kind: ErrorKind) -> Error {
        let e = Error { kind, at: self.at };
        self.state = State::Failed(e);
        e
    }

    /// The event for what was done, borrowing the token.
    fn event(&self, d: Done) -> Event<'_> {
        let token = self
            .storage
            .token
            .as_ref()
            .get(..self.token)
            .unwrap_or_default();
        // a string's token was checked as UTF-8 at its end, and a
        // number's is ASCII
        let text = core::str::from_utf8(token).unwrap_or_default();
        match d {
            Done::ObjectStart => Event::ObjectStart,
            Done::ObjectEnd => Event::ObjectEnd,
            Done::ArrayStart => Event::ArrayStart,
            Done::ArrayEnd => Event::ArrayEnd,
            Done::Name => Event::Name(text),
            Done::String => Event::String(text),
            Done::Number => Event::Number(Number(text)),
            Done::Bool(v) => Event::Bool(v),
            Done::Null => Event::Null,
        }
    }

    /// Whether the innermost container open is an object.
    fn in_object(&self) -> bool {
        self.depth
            .checked_sub(1)
            .and_then(|d| self.objects.checked_shr(u32::from(d)))
            .is_some_and(|o| o & 1 == 1)
    }

    /// What follows a value that ended.
    const fn after_value(&self) -> State {
        State::Expect(if self.depth == 0 {
            Expect::Over
        } else {
            Expect::CommaOrEnd
        })
    }

    /// One byte, in the state the parser is in.
    fn byte(&mut self, b: u8) -> Result<(Took, Option<Done>), ErrorKind> {
        match self.state {
            State::Expect(e) => self.expect(e, b),
            State::Literal { lit, at } => self.literal(lit, at, b),
            State::Str { role, esc } => self.string(role, esc, b),
            State::Num(n) => self.number(n, b),
            State::Failed(e) => Err(e.kind),
        }
    }

    fn expect(&mut self, e: Expect, b: u8) -> Result<(Took, Option<Done>), ErrorKind> {
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
            return Ok((Took::Yes, None));
        }
        let done = match (e, b) {
            (Expect::Colon, b':') => {
                self.state = State::Expect(Expect::Value);
                None
            }
            (Expect::Over | Expect::Colon, _) => return Err(ErrorKind::Unexpected(b)),
            (Expect::NameOrEnd | Expect::Name, b'"') => {
                self.token = 0;
                self.state = State::Str {
                    role: Role::Name,
                    esc: Esc::None,
                };
                None
            }
            (Expect::NameOrEnd | Expect::CommaOrEnd, b'}') if self.in_object() => {
                self.close_object()?;
                Some(Done::ObjectEnd)
            }
            (Expect::ValueOrEnd | Expect::CommaOrEnd, b']') if !self.in_object() => {
                self.depth = self.depth.saturating_sub(1);
                self.state = self.after_value();
                Some(Done::ArrayEnd)
            }
            (Expect::CommaOrEnd, b',') => {
                self.state = State::Expect(if self.in_object() {
                    Expect::Name
                } else {
                    Expect::Value
                });
                None
            }
            (Expect::Value | Expect::ValueOrEnd, _) => return self.value(b),
            (Expect::NameOrEnd | Expect::Name | Expect::CommaOrEnd, _) => {
                return Err(ErrorKind::Unexpected(b));
            }
        };
        Ok((Took::Yes, done))
    }

    /// The first byte of a value.
    fn value(&mut self, b: u8) -> Result<(Took, Option<Done>), ErrorKind> {
        let done = match b {
            b'{' => {
                self.open(true)?;
                self.open_object()?;
                self.state = State::Expect(Expect::NameOrEnd);
                Some(Done::ObjectStart)
            }
            b'[' => {
                self.open(false)?;
                self.state = State::Expect(Expect::ValueOrEnd);
                Some(Done::ArrayStart)
            }
            b'"' => {
                self.token = 0;
                self.state = State::Str {
                    role: Role::Value,
                    esc: Esc::None,
                };
                None
            }
            b't' | b'f' | b'n' => {
                let lit = match b {
                    b't' => Literal::True,
                    b'f' => Literal::False,
                    _ => Literal::Null,
                };
                self.state = State::Literal { lit, at: 1 };
                None
            }
            b'-' | b'0'..=b'9' => {
                self.token = 0;
                self.push_token(b)?;
                self.state = State::Num(match b {
                    b'-' => Num::Minus,
                    b'0' => Num::Zero,
                    _ => Num::Int,
                });
                None
            }
            _ => return Err(ErrorKind::Unexpected(b)),
        };
        Ok((Took::Yes, done))
    }

    /// A container opens, an object if `object`.
    fn open(&mut self, object: bool) -> Result<(), ErrorKind> {
        if self.depth >= self.depth_max {
            return Err(ErrorKind::TooDeep);
        }
        let bit = 1u64
            .checked_shl(u32::from(self.depth))
            .ok_or(ErrorKind::TooDeep)?;
        if object {
            self.objects |= bit;
        } else {
            self.objects &= !bit;
        }
        self.depth = self.depth.saturating_add(1);
        Ok(())
    }

    fn literal(&mut self, lit: Literal, at: u8, b: u8) -> Result<(Took, Option<Done>), ErrorKind> {
        let text = lit.text();
        if text.get(usize::from(at)) != Some(&b) {
            return Err(ErrorKind::Unexpected(b));
        }
        let at = at.saturating_add(1);
        if usize::from(at) < text.len() {
            self.state = State::Literal { lit, at };
            return Ok((Took::Yes, None));
        }
        self.state = self.after_value();
        Ok((
            Took::Yes,
            Some(match lit {
                Literal::True => Done::Bool(true),
                Literal::False => Done::Bool(false),
                Literal::Null => Done::Null,
            }),
        ))
    }

    fn number(&mut self, n: Num, b: u8) -> Result<(Took, Option<Done>), ErrorKind> {
        let next = match (n, b) {
            (Num::Minus, b'0') => Num::Zero,
            (Num::Minus | Num::Int, b'1'..=b'9') | (Num::Int, b'0') => Num::Int,
            (Num::Zero | Num::Int, b'.') => Num::Dot,
            (Num::Dot | Num::Frac, b'0'..=b'9') => Num::Frac,
            (Num::Zero | Num::Int | Num::Frac, b'e' | b'E') => Num::E,
            (Num::E, b'+' | b'-') => Num::ESign,
            (Num::E | Num::ESign | Num::Exp, b'0'..=b'9') => Num::Exp,
            // anything else ends it, if it may end, and is the next
            // thing's: what may follow a value is for that to say
            _ if n.may_end() && matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b',' | b']' | b'}') => {
                self.state = self.after_value();
                return Ok((Took::No, Some(Done::Number)));
            }
            _ => return Err(ErrorKind::Unexpected(b)),
        };
        self.push_token(b)?;
        self.state = State::Num(next);
        Ok((Took::Yes, None))
    }

    fn string(&mut self, role: Role, esc: Esc, b: u8) -> Result<(Took, Option<Done>), ErrorKind> {
        let esc = match esc {
            Esc::None => match b {
                b'"' => return self.string_end(role).map(|d| (Took::Yes, Some(d))),
                b'\\' => Esc::Backslash,
                0..=0x1f => return Err(ErrorKind::Control),
                _ => {
                    self.push_token(b)?;
                    Esc::None
                }
            },
            Esc::Backslash => {
                let c = match b {
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'/' => b'/',
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'u' => {
                        self.state = State::Str {
                            role,
                            esc: Esc::Hex { n: 0, acc: 0 },
                        };
                        return Ok((Took::Yes, None));
                    }
                    _ => return Err(ErrorKind::Escape),
                };
                self.push_token(c)?;
                Esc::None
            }
            Esc::Hex { n, acc } => {
                let acc = hex(acc, b)?;
                if n < 3 {
                    Esc::Hex {
                        n: n.saturating_add(1),
                        acc,
                    }
                } else {
                    match acc {
                        0xd800..=0xdbff => Esc::High(acc),
                        0xdc00..=0xdfff => return Err(ErrorKind::Surrogate),
                        _ => {
                            self.push_char(u32::from(acc))?;
                            Esc::None
                        }
                    }
                }
            }
            Esc::High(high) => match b {
                b'\\' => Esc::HighBackslash(high),
                _ => return Err(ErrorKind::Surrogate),
            },
            Esc::HighBackslash(high) => match b {
                b'u' => Esc::LowHex { high, n: 0, acc: 0 },
                _ => return Err(ErrorKind::Surrogate),
            },
            Esc::LowHex { high, n, acc } => {
                let acc = hex(acc, b)?;
                if n < 3 {
                    Esc::LowHex {
                        high,
                        n: n.saturating_add(1),
                        acc,
                    }
                } else {
                    if !(0xdc00..=0xdfff).contains(&acc) {
                        return Err(ErrorKind::Surrogate);
                    }
                    // RFC 8259 7: the pair's code point
                    let c = 0x1_0000u32
                        .saturating_add(u32::from(high.saturating_sub(0xd800)) << 10)
                        .saturating_add(u32::from(acc.saturating_sub(0xdc00)));
                    self.push_char(c)?;
                    Esc::None
                }
            }
        };
        self.state = State::Str { role, esc };
        Ok((Took::Yes, None))
    }

    /// A string's closing quote: its token is checked, and a name is
    /// checked against its object's others and kept.
    fn string_end(&mut self, role: Role) -> Result<Done, ErrorKind> {
        let token = self
            .storage
            .token
            .as_ref()
            .get(..self.token)
            .unwrap_or_default();
        let text = core::str::from_utf8(token).map_err(|_| ErrorKind::Utf8)?;
        for c in text.chars() {
            check_char(u32::from(c))?;
        }
        match role {
            Role::Value => {
                self.state = self.after_value();
                Ok(Done::String)
            }
            Role::Name => {
                self.keep_name()?;
                self.state = State::Expect(Expect::Colon);
                Ok(Done::Name)
            }
        }
    }

    fn push_token(&mut self, b: u8) -> Result<(), ErrorKind> {
        let slot = self
            .storage
            .token
            .as_mut()
            .get_mut(self.token)
            .ok_or(ErrorKind::TokenTooLong)?;
        *slot = b;
        self.token = self.token.saturating_add(1);
        Ok(())
    }

    /// An escaped character, as UTF-8.
    fn push_char(&mut self, c: u32) -> Result<(), ErrorKind> {
        check_char(c)?;
        let c = char::from_u32(c).ok_or(ErrorKind::Surrogate)?;
        let mut utf8 = [0u8; 4];
        for &b in c.encode_utf8(&mut utf8).as_bytes() {
            self.push_token(b)?;
        }
        Ok(())
    }

    /// An object opened: its names start a frame, after a record of the
    /// one enclosing it.
    fn open_object(&mut self) -> Result<(), ErrorKind> {
        let start = u32::try_from(self.names).map_err(|_| ErrorKind::NamesFull)?;
        self.push_names(&self.frame.to_le_bytes())?;
        self.frame = start;
        Ok(())
    }

    /// The innermost object closed: its names go, and the frame
    /// enclosing it is the innermost again.
    fn close_object(&mut self) -> Result<(), ErrorKind> {
        let start = usize::try_from(self.frame).map_err(|_| ErrorKind::NamesFull)?;
        let end = start.checked_add(4).ok_or(ErrorKind::NamesFull)?;
        let rec = self
            .storage
            .names
            .as_ref()
            .get(start..end)
            .and_then(|r| <[u8; 4]>::try_from(r).ok())
            .ok_or(ErrorKind::NamesFull)?;
        self.frame = u32::from_le_bytes(rec);
        self.names = start;
        self.depth = self.depth.saturating_sub(1);
        self.state = self.after_value();
        Ok(())
    }

    /// The name just ended, checked against the innermost object's others,
    /// then kept with them.
    fn keep_name(&mut self) -> Result<(), ErrorKind> {
        let name = self
            .storage
            .token
            .as_ref()
            .get(..self.token)
            .unwrap_or_default();
        let len = u16::try_from(name.len()).map_err(|_| ErrorKind::NamesFull)?;
        let names = self.storage.names.as_ref();
        let mut rec = usize::try_from(self.frame)
            .ok()
            .and_then(|f| f.checked_add(4))
            .ok_or(ErrorKind::NamesFull)?;
        while rec < self.names {
            let rec_len = names
                .get(rec..rec.saturating_add(2))
                .and_then(|r| <[u8; 2]>::try_from(r).ok())
                .map(u16::from_le_bytes)
                .ok_or(ErrorKind::NamesFull)?;
            let start = rec.saturating_add(2);
            let end = start.saturating_add(usize::from(rec_len));
            if names.get(start..end) == Some(name) {
                return Err(ErrorKind::Duplicate);
            }
            rec = end;
        }
        let need = name.len().saturating_add(2);
        let room = names.len().saturating_sub(self.names);
        if need > room {
            return Err(ErrorKind::NamesFull);
        }
        let at = self.names;
        let dst = self
            .storage
            .names
            .as_mut()
            .get_mut(at..at.saturating_add(need))
            .ok_or(ErrorKind::NamesFull)?;
        let (head, rest) = dst.split_at_mut(2);
        head.copy_from_slice(&len.to_le_bytes());
        rest.copy_from_slice(
            self.storage
                .token
                .as_ref()
                .get(..self.token)
                .unwrap_or_default(),
        );
        self.names = at.saturating_add(need);
        Ok(())
    }

    fn push_names(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        let end = self
            .names
            .checked_add(bytes.len())
            .ok_or(ErrorKind::NamesFull)?;
        let dst = self
            .storage
            .names
            .as_mut()
            .get_mut(self.names..end)
            .ok_or(ErrorKind::NamesFull)?;
        dst.copy_from_slice(bytes);
        self.names = end;
        Ok(())
    }
}

/// `acc` with the hex digit `b` after it.
fn hex(acc: u16, b: u8) -> Result<u16, ErrorKind> {
    let d = char::from(b).to_digit(16).ok_or(ErrorKind::Escape)?;
    let d = u16::try_from(d).map_err(|_| ErrorKind::Escape)?;
    Ok(acc.wrapping_shl(4) | d)
}

/// What I-JSON, and npro, refuse in a string: U+0000, and noncharacters.
const fn check_char(c: u32) -> Result<(), ErrorKind> {
    if c == 0 {
        return Err(ErrorKind::Control);
    }
    if (c >= 0xfdd0 && c <= 0xfdef) || c & 0xfffe == 0xfffe {
        return Err(ErrorKind::Noncharacter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    type P = Parser<Vec<u8>>;

    fn parser(token: usize, names: usize, config: Config) -> P {
        Parser::new(
            Storage {
                token: vec![0u8; token],
                names: vec![0u8; names],
            },
            config,
        )
        .unwrap()
    }

    fn show(e: Event<'_>) -> String {
        match e {
            Event::ObjectStart => "{".into(),
            Event::ObjectEnd => "}".into(),
            Event::ArrayStart => "[".into(),
            Event::ArrayEnd => "]".into(),
            Event::Name(n) => format!("{n}:"),
            Event::String(s) => format!("{s:?}"),
            Event::Number(n) => format!("#{}", n.as_str()),
            Event::Bool(b) => format!("{b}"),
            Event::Null => "null".into(),
        }
    }

    /// The events of `doc` given `piece` bytes at a time, and its end.
    #[expect(
        clippy::panic_in_result_fn,
        reason = "a test's helper: what it asserts failing is the test failing"
    )]
    fn events_with(mut p: P, doc: &[u8], piece: usize) -> Result<Vec<String>, Error> {
        let mut seen = Vec::new();
        for chunk in doc.chunks(piece.max(1)) {
            let mut input = chunk;
            loop {
                let step = p.next(input)?;
                input = &input[step.consumed..];
                match step.event {
                    Some(e) => seen.push(show(e)),
                    None if input.is_empty() => break,
                    None => panic!("took nothing, gave nothing"),
                }
            }
        }
        if let Some(e) = p.end()? {
            seen.push(show(e));
        }
        assert_eq!(p.end(), Ok(None));
        Ok(seen)
    }

    /// The events of `doc` with ample storage, the same whatever pieces
    /// it comes in.
    #[expect(
        clippy::panic_in_result_fn,
        reason = "a test's helper: what it asserts failing is the test failing"
    )]
    fn events(doc: &[u8]) -> Result<Vec<String>, ErrorKind> {
        let whole = events_with(parser(256, 256, Config::new()), doc, doc.len());
        for piece in 1..doc.len() {
            assert_eq!(
                events_with(parser(256, 256, Config::new()), doc, piece),
                whole,
                "{} in pieces of {piece}",
                doc.escape_ascii()
            );
        }
        whole.map_err(|e| e.kind())
    }

    #[test]
    fn every_kind_of_value_in_order() {
        assert_eq!(
            events(br#" {"a": [1, -2.5e+3, "s", true, false, null, {}, []], "b": {"c": 0}} "#)
                .unwrap(),
            [
                "{", "a:", "[", "#1", "#-2.5e+3", "\"s\"", "true", "false", "null", "{", "}", "[",
                "]", "]", "b:", "{", "c:", "#0", "}", "}"
            ]
        );
    }

    #[test]
    fn a_document_may_be_a_lone_value_and_a_number_ends_with_the_input() {
        assert_eq!(events(b"123").unwrap(), ["#123"]);
        assert_eq!(events(b" -0.5E-7 ").unwrap(), ["#-0.5E-7"]);
        assert_eq!(events(br#""x""#).unwrap(), ["\"x\""]);
        assert_eq!(events(b"null").unwrap(), ["null"]);
        assert_eq!(events(b"[]").unwrap(), ["[", "]"]);
    }

    #[test]
    fn numbers_are_rfc_8259s() {
        for ok in ["0", "-0", "10", "0.0", "1e5", "1E+5", "1e-05", "-12.34e56"] {
            assert_eq!(events(ok.as_bytes()).unwrap(), [format!("#{ok}")], "{ok}");
        }
        for bad in [
            &b"01"[..],
            b"-",
            b"1.",
            b".5",
            b"1e",
            b"1e+",
            b"+1",
            b"--1",
            b"1.e5",
            b"0x1",
            b"-a",
            b"1 2",
            b"[01]",
            b"[1.]",
        ] {
            assert!(events(bad).is_err(), "{}", bad.escape_ascii());
        }
    }

    #[test]
    fn number_values() {
        let n = |s| Number(s);
        assert_eq!(n("443").as_u64(), Some(443));
        assert_eq!(n("-1").as_u64(), None);
        assert_eq!(n("1e3").as_u64(), None);
        assert_eq!(n("18446744073709551616").as_u64(), None);
        assert_eq!(n("-9223372036854775808").as_i64(), Some(i64::MIN));
        assert_eq!(n("1.5e2").as_f64(), Some(150.0));
    }

    #[test]
    fn strings_are_unescaped() {
        assert_eq!(
            events(b"[\"\\\"\\\\\\/\\b\\f\\n\\r\\t\", \"\\u00e9\\u20AC\", \"\\ud83d\\ude00\", \"\xc3\xa9\"]").unwrap(),
            [
                "[",
                "\"\\\"\\\\/\\u{8}\\u{c}\\n\\r\\t\"",
                "\"\u{e9}\u{20ac}\"",
                "\"\u{1f600}\"",
                "\"\u{e9}\"",
                "]"
            ]
        );
    }

    #[test]
    fn what_i_json_and_npro_refuse_in_a_string() {
        for (doc, why) in [
            (&br#""\ud83d""#[..], ErrorKind::Surrogate),
            (br#""\ude00""#, ErrorKind::Surrogate),
            (br#""\ud83dx""#, ErrorKind::Surrogate),
            (br#""\ud83d\n""#, ErrorKind::Surrogate),
            (br#""\ud83dA""#, ErrorKind::Surrogate),
            (br#""\u0000""#, ErrorKind::Control),
            (b"\"a\x01\"", ErrorKind::Control),
            (b"\"a\tb\"", ErrorKind::Control),
            (b"\"\xff\"", ErrorKind::Utf8),
            (b"\"\xc0\x80\"", ErrorKind::Utf8),
            (b"\"\xed\xa0\x80\"", ErrorKind::Utf8),
            (br#""\ufffe""#, ErrorKind::Noncharacter),
            (br#""\ufdd0""#, ErrorKind::Noncharacter),
            (b"\"\xef\xbf\xbf\"", ErrorKind::Noncharacter),
            (br#""\ud83f\udffe""#, ErrorKind::Noncharacter),
            (br#""\x""#, ErrorKind::Escape),
            (br#""\u12g4""#, ErrorKind::Escape),
            (b"\"\\\0\"", ErrorKind::Escape),
        ] {
            assert_eq!(events(doc), Err(why), "{}", doc.escape_ascii());
        }
    }

    #[test]
    fn a_member_named_twice_is_refused_but_not_across_objects() {
        assert_eq!(events(br#"{"a":1,"b":2,"a":3}"#), Err(ErrorKind::Duplicate));
        assert_eq!(events(br#"{"a":1,"a":2}"#), Err(ErrorKind::Duplicate));
        assert_eq!(
            events(br#"{"a":{"a":{"a":1}},"b":[{"a":1},{"a":2}]}"#).map(|e| e.len()),
            Ok(21)
        );
        // an inner object's names are gone when it closes
        assert_eq!(
            events(br#"{"x":{"a":1,"b":2},"a":{"b":3}}"#).map(|e| e.len()),
            Ok(14)
        );
        assert_eq!(
            events(br#"{"x":{"a":1},"y":1,"x":2}"#),
            Err(ErrorKind::Duplicate)
        );
    }

    #[test]
    fn the_grammar_and_nothing_more() {
        for doc in [
            &b""[..],
            b"   ",
            b"{",
            b"[1,",
            b"\"abc",
            b"tru",
            b"{\"a\"",
            b"{\"a\":",
        ] {
            assert_eq!(
                events(doc),
                Err(ErrorKind::Incomplete),
                "{}",
                doc.escape_ascii()
            );
        }
        for doc in [
            &b"{,}"[..],
            b"{\"a\":1,}",
            b"[1,]",
            b"[1 2]",
            b"{\"a\" 1}",
            b"{\"a\":1 \"b\":2}",
            b"{1:2}",
            b"{]",
            b"[}",
            b"{} x",
            b"{}{}",
            b"\xef\xbb\xbf{}",
            b"{\"a\":1 # comment\n}",
            b"{'a':1}",
            b"[truex]",
            b"[nul]",
            b"]",
        ] {
            assert!(
                matches!(events(doc), Err(ErrorKind::Unexpected(_))),
                "{}",
                doc.escape_ascii()
            );
        }
    }

    #[test]
    fn nesting_is_as_deep_as_configured() {
        let deep = |d| {
            events_with(
                parser(16, 64, Config::new().with_depth(d).unwrap()),
                b"[[1]]",
                5,
            )
        };
        assert!(deep(2).is_ok());
        assert_eq!(deep(1).map_err(|e| e.kind()), Err(ErrorKind::TooDeep));
        let lone = |d, doc: &[u8]| {
            events_with(parser(16, 64, Config::new().with_depth(d).unwrap()), doc, 1)
        };
        assert!(lone(0, b"7").is_ok());
        assert_eq!(
            lone(0, b"{}").map_err(|e| e.kind()),
            Err(ErrorKind::TooDeep)
        );
        assert_eq!(Config::new().with_depth(MAX_DEPTH + 1), Err(DepthTooLarge));
        let max = Config::new().with_depth(MAX_DEPTH).unwrap();
        let mut doc = vec![b'['; usize::from(MAX_DEPTH)];
        doc.extend(vec![b']'; usize::from(MAX_DEPTH)]);
        assert!(events_with(parser(16, 64, max), &doc, 7).is_ok());
        doc.insert(0, b'[');
        doc.push(b']');
        assert_eq!(
            events_with(parser(16, 64, max), &doc, 7).map_err(|e| e.kind()),
            Err(ErrorKind::TooDeep)
        );
    }

    #[test]
    fn a_token_or_names_past_their_storage_are_refused() {
        let doc = br#"{"abcd":"efgh","ij":123456}"#;
        assert!(events_with(parser(6, 64, Config::new()), doc, 3).is_ok());
        assert_eq!(
            events_with(parser(5, 64, Config::new()), doc, 3).map_err(|e| e.kind()),
            Err(ErrorKind::TokenTooLong)
        );
        // 4 for the object, 2 + 4 and 2 + 2 for its names
        assert!(events_with(parser(16, 14, Config::new()), doc, 3).is_ok());
        assert_eq!(
            events_with(parser(16, 13, Config::new()), doc, 3).map_err(|e| e.kind()),
            Err(ErrorKind::NamesFull)
        );
        // an escaped character's UTF-8 counts
        assert_eq!(
            events_with(parser(2, 8, Config::new()), br#""\u20ac""#, 1).map_err(|e| e.kind()),
            Err(ErrorKind::TokenTooLong)
        );
    }

    #[test]
    fn a_refusal_says_where_and_stays() {
        let mut p = parser(16, 64, Config::new());
        let doc = br#"{"a": 1, }"#;
        let mut at = 0;
        let e = loop {
            match p.next(&doc[at..]) {
                Ok(s) => at += s.consumed,
                Err(e) => break e,
            }
        };
        assert_eq!((e.kind(), e.at()), (ErrorKind::Unexpected(b'}'), 9));
        assert_eq!(p.next(b"{}"), Err(e));
        assert_eq!(p.end(), Err(e));
    }

    #[test]
    fn the_byte_ending_a_number_is_not_taken_with_it() {
        let mut p = parser(16, 64, Config::new());
        assert_eq!(
            p.next(b"[12").map(|s| (s.consumed, s.event.map(show))),
            Ok((1, Some("[".into())))
        );
        assert_eq!(p.next(b"12").map(|s| (s.consumed, s.event)), Ok((2, None)));
        assert_eq!(
            p.next(b"]").map(|s| (s.consumed, s.event.map(show))),
            Ok((0, Some("#12".into())))
        );
        assert_eq!(
            p.next(b"]").map(|s| (s.consumed, s.event.map(show))),
            Ok((1, Some("]".into())))
        );
        assert!(p.is_over());
        assert_eq!(p.end(), Ok(None));
    }

    #[test]
    fn the_storage_comes_back() {
        let p = parser(3, 5, Config::new());
        let s = p.into_storage();
        assert_eq!((s.token.len(), s.names.len()), (3, 5));
    }
}
