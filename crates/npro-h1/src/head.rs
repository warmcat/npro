//! An h1 head, parsed as it arrives: C's `lws_parse()`.
//!
//! A server's head is a request line and header lines; a client's is a
//! status line and header lines.  Either ends at an empty line.  The bytes
//! are taken one at a time, in pieces of any size, and nothing is kept
//! between pieces but [`Head`] itself, so a head split anywhere parses as
//! it does whole.
//!
//! What C's parser does is what this does, branch for branch, with C's
//! state in enums: `parser_state` is `State`, the URI decoder's `ues`,
//! `ups` and `post_literal_equal` are `Esc`, `Path` and `Arg`, and the
//! name matcher's `lextable_pos` and `unk_pos` are `Name`.  Where C's
//! reasons for a refusal are labels (`bad_request_line`, `forbid`,
//! `too_large`...), here they are [`Cause`]s, and what a server answers
//! for one is [`Refused::answer`].
//!
//! Porting it found three bugs in C, fixed there first (lws 3c8459075 and
//! the two before it), so this is C as it is now: a name's start is a
//! state of its own, where C had taken a record at offset 0 for no record
//! and lost nine bytes of every request's table; a strict server refuses a
//! header line starting with a bare CR; and a value's leading OWS is not
//! kept, a repeated header's included.

use core::num::NonZeroU16;

use crate::table::{CapacityTooLarge, Full, HeaderTable};
use crate::token::{Lookup, Token, lookup};

const CR: u8 = b'\r';
const LF: u8 = b'\n';
const SP: u8 = b' ';
const HT: u8 = b'\t';

/// RFC 9112 2.2: a server ignores at least one empty line before a request
/// line.  C ignores this many, and refuses the next.
const MAX_LEADING_EMPTY_LINES: u8 = 8;

/// Whose head it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// A server, parsing a request.  It is strict about line ends and
    /// names, as what is in front of it may read them differently.
    Server,
    /// A client, parsing a response.  It is tolerant of the servers it
    /// talks to.
    Client,
}

/// What a server does with a request whose first token is no method it
/// knows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UnknownMethod {
    /// Refuse it: 501 if the token ends at a SP, 400 if it is no method.
    #[default]
    Refuse,
    /// Give the connection to another role, as C's
    /// `LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG`:
    /// [`Head::rx`] says [`Progress::Fallback`].
    Fallback,
}

/// How a head is parsed, beyond the size of its table.
///
/// ```
/// use core::num::NonZeroU16;
/// use npro_h1::head::Config;
/// use npro_h1::token::Token;
///
/// // as C's api-test-sansio context: a GET's target and a User-Agent of
/// // at most 33 and 16 bytes
/// let c = Config::new()
///     .with_limit(Token::GetUri, NonZeroU16::new(33).unwrap())
///     .with_limit(Token::UserAgent, NonZeroU16::new(16).unwrap());
/// assert_eq!(c.limit(Token::UserAgent), Some(16));
/// assert_eq!(c.limit(Token::Host), None);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    limits: [Option<NonZeroU16>; Token::COUNT],
    unknown_method: UnknownMethod,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    /// No limit on any token but the table's size, and unknown methods
    /// refused.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: [None; Token::COUNT],
            unknown_method: UnknownMethod::Refuse,
        }
    }

    /// Limits `token`'s value, or each urlarg's for a method's target, to
    /// `max` bytes: C's `token_limits`.  A longer one refuses the head.
    #[must_use]
    pub fn with_limit(mut self, token: Token, max: NonZeroU16) -> Self {
        if let Some(l) = self.limits.get_mut(token.index()) {
            *l = Some(max);
        }
        self
    }

    /// What a server does with an unknown method.
    #[must_use]
    pub const fn with_unknown_method(mut self, m: UnknownMethod) -> Self {
        self.unknown_method = m;
        self
    }

    /// The most `token`'s value may have, if it is limited.
    #[must_use]
    pub fn limit(&self, token: Token) -> Option<u16> {
        self.limits
            .get(token.index())
            .copied()
            .flatten()
            .map(NonZeroU16::get)
    }
}

/// Why a head was refused.  Each is one of C's ways out of `lws_parse()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// A NUL byte, anywhere.
    Nul,
    /// A server's head has a LF without its CR.
    BareLf,
    /// A server's head has a CR without its LF.
    BareCr,
    /// A server's header name has this byte, which no field name may.
    NameByte(u8),
    /// A request line's method came again as a header name.
    DuplicateMethod,
    /// A server's header line is named for this token, which is no h1
    /// field name.
    NotAFieldName(Token),
    /// A server's head does not start with a request line.
    NoRequestLine,
    /// The request line ended after its target: HTTP/0.9, which lws does
    /// not speak.
    Http09,
    /// More than eight empty lines came before the request line.
    TooManyEmptyLines,
    /// The request line's version is not `HTTP/` digit `.` digit.
    BadVersion,
    /// The request line's version is not 1.x.
    VersionNotSupported,
    /// The request line's method is one lws does not implement.
    MethodNotImplemented,
    /// The request target is refused.
    Uri(UriFault),
    /// The request target, or one of its urlargs, is longer than its
    /// limit, or than the table holds.
    UriTooLong,
    /// Something else in the head is longer than its limit, or than the
    /// table holds, or there were more pieces than it can track.
    HeadTooLarge,
}

/// What is wrong with a request target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UriFault {
    /// A `%` followed by something not two hex digits.
    BadEscape,
    /// A `%` escape the target ended in the middle of.
    UnfinishedEscape,
    /// A control byte, or DEL, raw or `%` escaped.
    ControlByte(u8),
    /// The target starts with its `?`: there is no path.
    EmptyPath,
}

/// The status a server answers a refused head with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// 400.
    BadRequest,
    /// 403.
    Forbidden,
    /// 414.
    UriTooLong,
    /// 431.
    HeaderFieldsTooLarge,
    /// 501.
    NotImplemented,
    /// 505.
    VersionNotSupported,
}

impl Answer {
    /// The status code.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Forbidden => 403,
            Self::UriTooLong => 414,
            Self::HeaderFieldsTooLarge => 431,
            Self::NotImplemented => 501,
            Self::VersionNotSupported => 505,
        }
    }
}

/// A refused head: why, and what a server says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused {
    cause: Cause,
    answer: Option<Answer>,
}

impl Refused {
    const fn new(side: Side, cause: Cause) -> Self {
        let answer = match side {
            Side::Client => None,
            Side::Server => match cause {
                Cause::Nul
                | Cause::BareLf
                | Cause::BareCr
                | Cause::NameByte(_)
                | Cause::DuplicateMethod
                | Cause::NotAFieldName(_) => None,
                Cause::NoRequestLine
                | Cause::Http09
                | Cause::TooManyEmptyLines
                | Cause::BadVersion => Some(Answer::BadRequest),
                Cause::VersionNotSupported => Some(Answer::VersionNotSupported),
                Cause::MethodNotImplemented => Some(Answer::NotImplemented),
                Cause::Uri(_) => Some(Answer::Forbidden),
                Cause::UriTooLong => Some(Answer::UriTooLong),
                Cause::HeadTooLarge => Some(Answer::HeaderFieldsTooLarge),
            },
        };
        Self { cause, answer }
    }

    /// Why the head was refused.
    #[must_use]
    pub const fn cause(&self) -> Cause {
        self.cause
    }

    /// What a server answers before it closes: C's `LPR_REFUSED` and the
    /// status it sends.  `None` is C's `LPR_FAIL`, closing without a word,
    /// and every refusal of a client's.
    #[must_use]
    pub const fn answer(&self) -> Option<Answer> {
        self.answer
    }
}

impl core::fmt::Display for Refused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "h1 head refused: {:?}", self.cause)?;
        if let Some(a) = self.answer {
            write!(f, ", answered {}", a.code())?;
        }
        Ok(())
    }
}

impl core::error::Error for Refused {}

/// How far a head got with the bytes it was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// All of them were taken, and the head is not over.
    More,
    /// The head is over, at the end of the first `consumed` bytes.  What
    /// follows is a body, or the next head.
    Complete {
        /// How many of the bytes were the head's.
        consumed: usize,
    },
    /// The request is not one for http, and its connection goes to another
    /// role, with every byte it sent: see [`UnknownMethod::Fallback`].
    Fallback,
}

/// The version a server answers a request in: C's
/// `lws_h1_request_version()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0.
    Http10,
    /// HTTP/1.1, which a later 1.x is answered as (RFC 9110 2.5).
    Http11,
}

/// Where in a name the parser is: C's `lextable_pos` with `unk_pos`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Name {
    /// Nothing of it yet.
    Start,
    /// Its bytes, from its record at `rec`, are the start of a spelling.
    Matching { rec: u16 },
    /// It is no spelling, and is kept, from its record at `rec`.
    Unknown { rec: u16 },
}

/// What the parser is in the middle of: C's `parser_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// A name: `WSI_TOKEN_NAME_PART`.
    Name(Name),
    /// A known token's value.
    Value(Token),
    /// An unknown header's value, its record at `rec` and the value at
    /// `value`: `WSI_TOKEN_UNKNOWN_VALUE_PART`.
    UnknownValue { rec: u16, value: u16 },
    /// The rest of a line not kept: `WSI_TOKEN_SKIPPING`.
    Skipping,
    /// A CR, which must be followed by LF: `WSI_TOKEN_SKIPPING_SAW_CR`.
    SkippingSawCr,
    /// The head is over: `WSI_PARSING_COMPLETE`.
    Complete,
    /// The head goes to the fallback role.
    Fallback,
    /// The head was refused.
    Refused(Refused),
}

/// A `%` escape in the target: C's `ues`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Esc {
    Idle,
    Percent,
    /// The first hex digit, as its value.
    PercentHigh(u8),
}

/// Where the path is, for `//`, `/./` and `/../`: C's `ups`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Path {
    Idle,
    Slash,
    SlashDot,
    SlashDotDot,
}

/// Which side of an urlarg's `=` the decoder is: C's
/// `post_literal_equal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arg {
    Name,
    Value,
}

/// What a byte of the target becomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decoded {
    /// This byte goes into the target.
    Byte(u8),
    /// Nothing goes in.
    Swallow,
}

/// What a byte did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    More,
    Complete,
    Fallback,
}

/// An h1 head being parsed into its [`HeaderTable`].
///
/// ```
/// use npro_h1::head::{Config, Head, Progress, Side};
/// use npro_h1::token::Token;
///
/// let mut h = Head::new([0u8; 1024], Side::Server, Config::default())?;
/// assert_eq!(h.rx(b"GET /a/../b?x=1 HTTP/1.1\r\nHo")?, Progress::More);
/// assert_eq!(
///     h.rx(b"st: example.com\r\n\r\nbody")?,
///     Progress::Complete { consumed: 19 }
/// );
/// let t = h.table();
/// assert_eq!(t.first(Token::GetUri), Some(&b"/b"[..]));
/// assert_eq!(t.first(Token::UriArgs), Some(&b"x=1"[..]));
/// assert_eq!(t.first(Token::Host), Some(&b"example.com"[..]));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Head<S> {
    table: HeaderTable<S>,
    side: Side,
    config: Config,
    state: State,
    esc: Esc,
    path: Path,
    arg: Arg,
    /// The limit of the value being filled: C's `current_token_limit`.
    limit: Option<u16>,
    empty_lines: u8,
}

impl<S: AsRef<[u8]> + AsMut<[u8]>> Head<S> {
    /// A head to parse into a table in `storage`.
    ///
    /// # Errors
    ///
    /// [`CapacityTooLarge`] if `storage` is past the most a table holds.
    pub fn new(storage: S, side: Side, config: Config) -> Result<Self, CapacityTooLarge> {
        Ok(Self::with_table(HeaderTable::new(storage)?, side, config))
    }

    /// A head to parse into `table`, after what it holds: how a client
    /// parses its response into the table holding its own request.
    #[must_use]
    pub const fn with_table(table: HeaderTable<S>, side: Side, config: Config) -> Self {
        Self {
            table,
            side,
            config,
            state: State::Name(Name::Start),
            esc: Esc::Idle,
            path: Path::Idle,
            arg: Arg::Name,
            limit: None,
            empty_lines: 0,
        }
    }

    /// Readies the head for the next one, with the table emptied: C's
    /// `lws_header_table_reset()`.
    pub fn reset(&mut self) {
        self.table.reset();
        self.restart();
    }

    /// Readies the head for another, dropping from the table what was put
    /// there since its [`snapshot`](HeaderTable::snapshot): how a client
    /// goes on to the final response after an interim one, as C's
    /// `lws_header_table_rx_rewind()`.
    pub fn rewind(&mut self) {
        self.table.rewind();
        self.restart();
    }

    const fn restart(&mut self) {
        self.state = State::Name(Name::Start);
        self.esc = Esc::Idle;
        self.path = Path::Idle;
        self.arg = Arg::Name;
        self.limit = None;
        self.empty_lines = 0;
    }

    /// The table, with what the head has put in it so far.
    #[must_use]
    pub const fn table(&self) -> &HeaderTable<S> {
        &self.table
    }

    /// The table, for its owner to add to, as a client does with its own
    /// request before it parses the response.
    #[must_use]
    pub const fn table_mut(&mut self) -> &mut HeaderTable<S> {
        &mut self.table
    }

    /// Whose head it is.
    #[must_use]
    pub const fn side(&self) -> Side {
        self.side
    }

    /// Whether the head is over.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }

    /// The version a server answers in, from the request line: HTTP/1.1
    /// for `HTTP/1.1` to `HTTP/1.9`, otherwise HTTP/1.0.  C's
    /// `lws_h1_request_version()`.
    #[must_use]
    pub fn request_version(&self) -> Version {
        // as C copies it, into a buffer of 11 with room for its NUL
        let mut v = [0u8; 10];
        let total = self.table.copy(Token::Http, &mut v).unwrap_or(0);
        if total > 7
            && v.get(5) == Some(&b'1')
            && v.get(7).is_some_and(|d| (b'1'..=b'9').contains(d))
        {
            Version::Http11
        } else {
            Version::Http10
        }
    }

    /// Takes the next bytes of the head.
    ///
    /// # Errors
    ///
    /// [`Refused`], as soon as a byte makes the head one lws refuses.  The
    /// head stays refused: every later call says the same.
    pub fn rx(&mut self, bytes: &[u8]) -> Result<Progress, Refused> {
        match self.state {
            State::Refused(r) => return Err(r),
            State::Complete => return Ok(Progress::Complete { consumed: 0 }),
            State::Fallback => return Ok(Progress::Fallback),
            State::Name(_)
            | State::Value(_)
            | State::UnknownValue { .. }
            | State::Skipping
            | State::SkippingSawCr => {}
        }
        for (i, &c) in bytes.iter().enumerate() {
            match self.byte(c) {
                Ok(Flow::More) => {}
                Ok(Flow::Complete) => {
                    self.state = State::Complete;
                    return Ok(Progress::Complete {
                        consumed: i.saturating_add(1),
                    });
                }
                Ok(Flow::Fallback) => {
                    self.state = State::Fallback;
                    return Ok(Progress::Fallback);
                }
                Err(cause) => {
                    let r = Refused::new(self.side, cause);
                    self.state = State::Refused(r);
                    return Err(r);
                }
            }
        }
        Ok(Progress::More)
    }

    /// Whether a server's request line has had its method.
    fn method_seen(&self) -> bool {
        Token::METHODS.iter().any(|m| self.table.is_present(*m))
    }

    /// A server, strict about line ends and names: C's
    /// `lws_h1_srv_strict()`.
    fn strict(&self) -> bool {
        self.side == Side::Server
    }

    /// A server still waiting for its request line: C's
    /// `lws_h1_srv_awaits_request_line()`.
    fn awaits_request_line(&self) -> bool {
        self.strict() && !self.method_seen()
    }

    /// A byte a server refuses in a header name, once it has had its
    /// request line: C's `lws_h1_srv_bad_name_char()`.
    fn bad_name_byte(&self, c: u8) -> bool {
        self.strict() && c != b':' && !name_byte(c) && self.method_seen()
    }

    /// Whether `t`, matched as a name, can be taken here: C's
    /// `lws_h1_token_usable()`.
    fn usable(&self, t: Token) -> bool {
        if t == Token::Challenge || t.spelling().last() == Some(&b':') {
            return true;
        }
        if self.side == Side::Client {
            return t == Token::Http || t == Token::Http10;
        }
        !self.method_seen() && t.is_method()
    }

    /// What is too large where the parser is: the target, or the rest.
    const fn too_large(t: Token) -> Cause {
        if matches!(
            t,
            Token::GetUri
                | Token::PostUri
                | Token::OptionsUri
                | Token::PutUri
                | Token::PatchUri
                | Token::DeleteUri
                | Token::Connect
                | Token::HeadUri
        ) {
            Cause::UriTooLong
        } else {
            Cause::HeadTooLarge
        }
    }

    /// One byte of the head.
    fn byte(&mut self, c: u8) -> Result<Flow, Cause> {
        if c == 0 {
            return Err(Cause::Nul);
        }
        match self.state {
            State::UnknownValue { rec, value } => self.unknown_value(c, rec, value),
            State::Value(t) => self.value(c, t),
            State::Name(n) => self.name(c, n),
            State::Skipping => {
                if c == LF {
                    if self.strict() {
                        return Err(Cause::BareLf);
                    }
                    self.state = State::Name(Name::Start);
                }
                if c == CR {
                    self.state = State::SkippingSawCr;
                }
                Ok(Flow::More)
            }
            State::SkippingSawCr => {
                if self.esc != Esc::Idle {
                    return Err(Cause::Uri(UriFault::UnfinishedEscape));
                }
                if c == LF {
                    self.state = State::Name(Name::Start);
                    return Ok(Flow::More);
                }
                if self.strict() {
                    return Err(Cause::BareCr);
                }
                self.state = State::Skipping;
                Ok(Flow::More)
            }
            State::Complete | State::Fallback | State::Refused(_) => Ok(Flow::More),
        }
    }

    fn unknown_value(&mut self, c: u8, rec: u16, value: u16) -> Result<Flow, Cause> {
        // the value ends at the CR, whose LF is then checked for like any
        // other header's
        if c == LF && self.strict() {
            return Err(Cause::BareLf);
        }
        if c == CR || c == LF {
            self.table.end_record_value(rec, value);
            self.state = if c == CR {
                State::SkippingSawCr
            } else {
                State::Name(Name::Start)
            };
            return Ok(Flow::More);
        }
        // without its leading whitespace
        if self.table.pos() != value || (c != SP && c != HT) {
            self.table.push(c).map_err(|_| Cause::HeadTooLarge)?;
        }
        Ok(Flow::More)
    }

    fn value(&mut self, mut c: u8, t: Token) -> Result<Flow, Cause> {
        if t.is_method() {
            // extra SP between the method and the target
            if self.table.first_len(t) == 0 && c == SP {
                return Ok(Flow::More);
            }
            if c == CR || c == LF {
                return Err(Cause::Http09);
            }
            if c == SP {
                return self.end_of_target();
            }
            match self.urldecode(c)? {
                Decoded::Swallow => return Ok(Flow::More),
                Decoded::Byte(d) => c = d,
            }
        } else {
            // the OWS before a header's value is not part of it (RFC 9110
            // 5.5): swallowed while the piece has nothing of the value's
            // own, a repeated header's only the SP joining it to the one
            // before.  The first line's version is no header: a HT is no
            // SP there
            let ows = c == SP || (c == HT && t != Token::Http && t != Token::Http10);
            let joining = u16::from(!self.table.filling_first(t));
            if ows && self.table.current_len() == joining {
                return Ok(Flow::More);
            }
        }
        // the end of the line
        if t != Token::Challenge && (c == CR || c == LF) {
            if self.esc != Esc::Idle {
                return Err(Cause::Uri(UriFault::UnfinishedEscape));
            }
            if t == Token::Http && self.side == Side::Server {
                if let Some(refusal) = version_refusal(self.table.current()) {
                    return Err(refusal);
                }
            }
            if c == LF {
                if self.strict() {
                    return Err(Cause::BareLf);
                }
                self.state = State::Name(Name::Start);
            } else {
                self.state = State::SkippingSawCr;
            }
            c = 0;
        }
        self.issue(c, t)?;
        if c == 0 {
            // the NUL ending the value is not part of it
            self.table.uncount();
        }
        Ok(Flow::More)
    }

    /// Adds `c` to the value of `t` being filled.
    fn issue(&mut self, c: u8, t: Token) -> Result<(), Cause> {
        self.table
            .issue(c, self.limit)
            .map_err(|_| Self::too_large(t))
    }

    /// The SP ending a request target.
    fn end_of_target(&mut self) -> Result<Flow, Cause> {
        // a target starts with a /, but only while it is the path: after
        // a ?, an empty query stays empty
        if !self.table.is_present(Token::UriArgs) && self.table.current_len() == 0 {
            self.issue(b'/', Token::GetUri)?;
        }
        if self.path == Path::SlashDotDot {
            self.table.back_up_a_segment();
        }
        self.issue(0, Token::GetUri)?;
        self.table.uncount();
        // the version, under the target's limit, as C has it
        self.state = State::Value(Token::Http);
        self.start_fragment(Token::Http)
    }

    /// A value of `t` begins.
    fn start_fragment(&mut self, t: Token) -> Result<Flow, Cause> {
        let chained = self
            .table
            .start_fragment(t)
            .map_err(|_| Self::too_large(t))?;
        if chained {
            self.issue(SP, t)?;
        }
        Ok(Flow::More)
    }

    fn name(&mut self, c: u8, n: Name) -> Result<Flow, Cause> {
        if n == Name::Start && c == LF {
            if self.strict() {
                return Err(Cause::BareLf);
            }
            // a broken peer's empty line
            return self.complete();
        }
        // an empty line where the request line should start, before
        // anything of the head: skipped, a few of them
        if c == CR && n == Name::Start && !self.table.has_fragments() && self.awaits_request_line()
        {
            self.empty_lines = self.empty_lines.saturating_add(1);
            if self.empty_lines > MAX_LEADING_EMPTY_LINES {
                return Err(Cause::TooManyEmptyLines);
            }
            self.state = State::SkippingSawCr;
            return Ok(Flow::More);
        }
        // a field name is not empty: no ':' starts one
        if c == b':' && n == Name::Start && self.strict() && self.method_seen() {
            return Err(Cause::NameByte(c));
        }
        let c = c.to_ascii_lowercase();
        // in case it is a header lws does not know, the name is kept as it
        // comes, and dropped if it turns out to be one it knows
        let rec = match n {
            Name::Start => self.table.begin_record(),
            Name::Matching { rec } | Name::Unknown { rec } => rec,
        };
        self.table.push(c).map_err(|_| Cause::HeadTooLarge)?;

        if let Name::Unknown { .. } = n {
            return self.unknown_name(c, rec);
        }
        match lookup(self.table.record_name(rec)) {
            Lookup::Prefix => {
                self.state = State::Name(Name::Matching { rec });
                Ok(Flow::More)
            }
            Lookup::Nothing => self.no_match(c, rec),
            Lookup::Matched(t) => self.matched(t, rec),
        }
    }

    /// The next byte of a name lws does not know.
    fn unknown_name(&mut self, c: u8, rec: u16) -> Result<Flow, Cause> {
        if self.awaits_request_line() {
            // a first token lws does not know: a method, if it ends at SP
            if c == SP {
                return Err(Cause::MethodNotImplemented);
            }
            if c == b':' || !name_byte(c) {
                return Err(Cause::NoRequestLine);
            }
            self.state = State::Name(Name::Unknown { rec });
            return Ok(Flow::More);
        }
        if self.bad_name_byte(c) {
            return Err(Cause::NameByte(c));
        }
        if c == b':' {
            return Ok(self.unknown_name_ended(rec));
        }
        self.state = State::Name(Name::Unknown { rec });
        Ok(Flow::More)
    }

    /// The name, ending in `c`, is the start of no spelling.
    fn no_match(&mut self, c: u8, rec: u16) -> Result<Flow, Cause> {
        if self.side == Side::Client {
            // a client keeps a header it does not know, to its ':'
            if c == b':' {
                return Ok(self.unknown_name_ended(rec));
            }
            self.state = State::Name(Name::Unknown { rec });
            return Ok(Flow::More);
        }
        if self.method_seen() {
            // the bytes before c matched the start of a token, which need
            // not be a field name's: the CR of "\r\n", which then started
            // the line, is a bare CR
            if let Some((_, before)) = self.table.record_name(rec).split_last() {
                if let Some(b) = before.iter().find(|b| !name_byte(**b)) {
                    return Err(if *b == CR {
                        Cause::BareCr
                    } else {
                        Cause::NameByte(*b)
                    });
                }
            }
            // c is where the name stopped matching any lws knows: eg the
            // SP of "host :", or the ':' of "accept-lang:"
            if self.bad_name_byte(c) {
                return Err(Cause::NameByte(c));
            }
            if c == b':' {
                return Ok(self.unknown_name_ended(rec));
            }
            self.state = State::Name(Name::Unknown { rec });
            return Ok(Flow::More);
        }
        // a method lws does not know, or no request line at all
        if self.config.unknown_method == UnknownMethod::Fallback {
            return Ok(Flow::Fallback);
        }
        if c == SP {
            return Err(Cause::MethodNotImplemented);
        }
        if c == b':' || !name_byte(c) {
            return Err(Cause::NoRequestLine);
        }
        self.state = State::Name(Name::Unknown { rec });
        Ok(Flow::More)
    }

    /// The name, from its record at `rec`, is the whole spelling of `t`.
    fn matched(&mut self, t: Token, rec: u16) -> Result<Flow, Cause> {
        if t.is_method() && self.table.is_present(t) {
            return Err(Cause::DuplicateMethod);
        }
        if !self.usable(t) {
            // a server's head starts with its request line...
            if self.awaits_request_line() {
                return Err(Cause::NoRequestLine);
            }
            // ...and a server refuses a name with a ':' or SP in it, as
            // any other; a client skips the line
            if !t.spelling().iter().all(|b| name_byte(*b)) {
                if self.strict() {
                    return Err(Cause::NotAFieldName(t));
                }
                self.table.truncate(rec);
                self.state = State::Skipping;
                return Ok(Flow::More);
            }
            // otherwise it is a name lws does not know, kept from its
            // first byte, and going on to its ':'
            self.state = State::Name(Name::Unknown { rec });
            return Ok(Flow::More);
        }
        // a header lws knows: the name kept for it is dropped
        self.table.truncate(rec);
        // Sec-WebSocket-Origin is Origin, as JWebSocket sends it
        let t = if t == Token::WsOrigin {
            Token::Origin
        } else {
            t
        };
        self.state = State::Value(t);
        self.path = Path::Idle;
        self.limit = self.config.limit(t);
        if t == Token::Challenge {
            return self.complete();
        }
        self.start_fragment(t)
    }

    /// The ':' ending the name of a header lws does not know.
    fn unknown_name_ended(&mut self, rec: u16) -> Flow {
        self.table.end_record_name(rec);
        self.state = State::UnknownValue {
            rec,
            value: self.table.pos(),
        };
        Flow::More
    }

    /// The empty line ending the head.
    fn complete(&mut self) -> Result<Flow, Cause> {
        if self.esc != Esc::Idle {
            return Err(Cause::Uri(UriFault::UnfinishedEscape));
        }
        // a server's head starts with its request line
        if self.awaits_request_line() {
            return Err(Cause::NoRequestLine);
        }
        Ok(Flow::Complete)
    }

    /// A byte of a request target: `%` escapes, then the control bytes
    /// refused, then `//`, `/./` and `/../` taken out, never above the
    /// root, then the urlargs split: C's `lws_parse_urldecode()`.
    fn urldecode(&mut self, c: u8) -> Result<Decoded, Cause> {
        let mut c = c;
        let mut escaped = false;
        match self.esc {
            Esc::Idle => {
                if c == b'%' {
                    self.esc = Esc::Percent;
                    return Ok(Decoded::Swallow);
                }
            }
            Esc::Percent => {
                let h = hex(c).ok_or(Cause::Uri(UriFault::BadEscape))?;
                self.esc = Esc::PercentHigh(h);
                return Ok(Decoded::Swallow);
            }
            Esc::PercentHigh(h) => {
                let l = hex(c).ok_or(Cause::Uri(UriFault::BadEscape))?;
                c = (h << 4) | l;
                escaped = true;
                self.esc = Esc::Idle;
            }
        }

        // no control byte or DEL in a target, raw or escaped
        if c < 0x20 || c == 0x7f {
            return Err(Cause::Uri(UriFault::ControlByte(c)));
        }
        self.unescaped(c, escaped)
    }

    /// A byte of a request target, `%` decoded if `escaped`.
    fn unescaped(&mut self, mut c: u8, escaped: bool) -> Result<Decoded, Cause> {
        let t = Token::GetUri;
        let args = self.table.is_present(Token::UriArgs);
        match self.path {
            Path::Idle => {
                // the urlargs' separators, once a ? has started them
                if (c == b'&' || c == b';') && !escaped && args {
                    self.issue(0, t)?;
                    self.table.uncount();
                    self.table.next_arg().map_err(|_| Cause::UriTooLong)?;
                    self.arg = Arg::Name;
                    return Ok(Decoded::Swallow);
                }
                // an escaped = is not the one ending an urlarg's name
                if c == b'=' && escaped && args && self.arg == Arg::Name {
                    c = b'_';
                }
                if c == b'=' && !escaped {
                    self.arg = Arg::Value;
                }
                // + is a space in the query, form encoding's; in the path
                // it is a +
                if c == b'+' && !escaped && args {
                    c = SP;
                }
                if c == b'/' && !args {
                    self.path = Path::Slash;
                }
            }
            Path::Slash => {
                if c == b'/' {
                    return Ok(Decoded::Swallow);
                }
                if c == b'.' {
                    self.path = Path::SlashDot;
                    return Ok(Decoded::Swallow);
                }
                self.path = Path::Idle;
            }
            Path::SlashDot => {
                if c == b'.' {
                    self.path = Path::SlashDotDot;
                    return Ok(Decoded::Swallow);
                }
                if c == b'/' {
                    self.path = Path::Slash;
                    return Ok(Decoded::Swallow);
                }
                if c == b'?' && !escaped {
                    // "/.?" ends the path in "/.", as "/." at its end
                    self.path = Path::Slash;
                } else {
                    // "/.dir": the . was part of it
                    self.path = Path::Idle;
                    self.issue(b'.', t)?;
                }
            }
            Path::SlashDotDot => {
                if c == b'/' || c == b'?' {
                    self.table.back_up_a_segment();
                    self.path = Path::Slash;
                    // the / backed up to stands for a / here, but a ? goes
                    // on to start the urlargs
                    if self.table.current_len() <= 1 && c != b'?' {
                        return Ok(Decoded::Swallow);
                    }
                } else {
                    // "/..x": the dots were part of it
                    self.issue(b'.', t)?;
                    self.issue(b'.', t)?;
                    self.path = Path::Idle;
                }
            }
        }

        if c == b'?' && !escaped && !args {
            if self.esc != Esc::Idle {
                return Err(Cause::Uri(UriFault::UnfinishedEscape));
            }
            // no target is all query
            if self.table.current_len() == 0 {
                return Err(Cause::Uri(UriFault::EmptyPath));
            }
            self.issue(0, t)?;
            self.table.uncount();
            self.table
                .start_args()
                .map_err(|_: Full| Cause::UriTooLong)?;
            self.arg = Arg::Name;
            self.path = Path::Idle;
            return Ok(Decoded::Swallow);
        }

        Ok(Decoded::Byte(c))
    }
}

/// Whether a server takes `c` in a header name: C's
/// `lws_http_field_name_char_valid()`, past the first byte.  No controls,
/// SP, DEL, non-ASCII, uppercase or ':'.
const fn name_byte(c: u8) -> bool {
    c > 0x20 && c < 0x7f && !c.is_ascii_uppercase() && c != b':'
}

const fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// RFC 9112 2.3: `HTTP/` digit `.` digit, which a server speaks if the
/// major version is 1: C's `lws_h1_version_refusal()`.
const fn version_refusal(v: &[u8]) -> Option<Cause> {
    let [b'H', b'T', b'T', b'P', b'/', major, b'.', minor] = *v else {
        return Some(Cause::BadVersion);
    };
    if !major.is_ascii_digit() || !minor.is_ascii_digit() {
        return Some(Cause::BadVersion);
    }
    if major != b'1' {
        return Some(Cause::VersionNotSupported);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(head: &[u8]) -> (Result<Progress, Refused>, Head<[u8; 512]>) {
        let mut h = Head::new([0u8; 512], Side::Server, Config::new()).unwrap();
        let r = h.rx(head);
        (r, h)
    }

    #[test]
    fn a_server_head_starts_the_table_at_its_first_byte() {
        // the first name's record is at 0, and begun once
        let (r, h) = server(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(r, Ok(Progress::Complete { consumed: 18 }));
        // "/" and its NUL, "HTTP/1.1" and its NUL
        assert_eq!(h.table().used(), 2 + 9);
    }

    #[test]
    fn a_lf_second_is_a_name_byte_not_a_line_end() {
        // a first token no method has, not the end of an empty head
        let (r, _) = server(b"G\nET / HTTP/1.1\r\n\r\n");
        assert_eq!(r.map_err(|e| e.cause()), Err(Cause::NoRequestLine));
        assert_eq!(r.err().and_then(|e| e.answer()), Some(Answer::BadRequest));
    }

    #[test]
    fn a_cr_starting_a_header_line_is_a_bare_cr() {
        let (r, _) = server(b"GET / HTTP/1.1\r\n\rX-A: b\r\n\r\n");
        assert_eq!(r.map_err(|e| e.cause()), Err(Cause::BareCr));
        assert_eq!(r.err().and_then(|e| e.answer()), None);
        // before the name of a header lws knows too
        let (known, _) = server(b"GET / HTTP/1.1\r\n\rHost: b\r\n\r\n");
        assert_eq!(known.map_err(|e| e.cause()), Err(Cause::BareCr));
        // a client is tolerant, as C is: the CR is the name's
        let mut h = Head::new([0u8; 512], Side::Client, Config::new()).unwrap();
        assert!(h.rx(b"HTTP/1.1 200 OK\r\n\rX-A: b\r\n\r\n").is_ok());
        assert_eq!(h.table().unknown(b"\rx-a:"), Some(&b"b"[..]));
    }

    #[test]
    fn a_header_named_like_a_token_it_cannot_be_is_kept_whole() {
        let (r, h) = server(b"GET / HTTP/1.1\r\nuri-args: x\r\nPutX: y\r\n\r\n");
        assert!(r.is_ok());
        assert_eq!(h.table().unknown(b"uri-args:"), Some(&b"x"[..]));
        assert_eq!(h.table().unknown(b"putx:"), Some(&b"y"[..]));
        assert!(!h.table().is_present(Token::UriArgs));
    }

    #[test]
    fn a_values_leading_ows_is_not_kept() {
        // RFC 9110 5.5, repeated or not: a repeated header's piece keeps
        // only the SP joining it to the one before
        let (_, h) = server(b"GET / HTTP/1.1\r\nAccept: \t a\r\nAccept:\t b \r\n\r\n");
        let v: [&[u8]; 2] = [b"a", b" b "];
        assert!(h.table().fragments(Token::Accept).eq(v));
        let mut joined = [0u8; 8];
        assert_eq!(h.table().copy(Token::Accept, &mut joined), Ok(5));
        assert_eq!(&joined[..5], b"a, b ");
        // the version is no header: a HT before it is no SP
        let (r, _) = server(b"GET /\tHTTP/1.1\r\n\r\n");
        assert!(r.is_err());
    }

    #[test]
    fn the_version_is_held_to_the_targets_limit() {
        // as C: the limit taken at the method stays for the version
        let cfg = Config::new().with_limit(Token::GetUri, NonZeroU16::new(4).unwrap());
        let mut h = Head::new([0u8; 512], Side::Server, cfg).unwrap();
        let r = h.rx(b"GET /abc HTTP/1.1\r\n\r\n");
        assert_eq!(r.map_err(|e| e.cause()), Err(Cause::HeadTooLarge));
        assert_eq!(
            r.err().and_then(|e| e.answer()),
            Some(Answer::HeaderFieldsTooLarge)
        );
        let mut longer = Head::new([0u8; 512], Side::Server, cfg).unwrap();
        let refused = longer.rx(b"GET /abcd HTTP/1.1\r\n\r\n");
        assert_eq!(
            refused.err().and_then(|e| e.answer()),
            Some(Answer::UriTooLong)
        );
    }

    #[test]
    fn a_refused_head_stays_refused_and_a_complete_one_takes_no_more() {
        let (r, mut h) = server(b"GET / HTTP/2.0\r\n");
        let e = r.unwrap_err();
        assert_eq!(e.answer(), Some(Answer::VersionNotSupported));
        assert_eq!(h.rx(b"\r\n"), Err(e));
        let (_, mut done) = server(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(done.rx(b"GET"), Ok(Progress::Complete { consumed: 0 }));
    }

    #[test]
    fn the_version_answered_in() {
        for (v, want) in [
            (&b"HTTP/1.0"[..], Version::Http10),
            (b"HTTP/1.1", Version::Http11),
            (b"HTTP/1.9", Version::Http11),
        ] {
            let mut head = b"GET / ".to_vec();
            head.extend_from_slice(v);
            head.extend_from_slice(b"\r\n\r\n");
            let (r, h) = server(&head);
            assert!(r.is_ok());
            assert_eq!(h.request_version(), want);
        }
    }

    #[test]
    fn a_fallback_role_takes_an_unknown_method() {
        let cfg = Config::new().with_unknown_method(UnknownMethod::Fallback);
        let mut h = Head::new([0u8; 512], Side::Server, cfg).unwrap();
        assert_eq!(h.rx(b"SSH-2.0\r\n"), Ok(Progress::Fallback));
        assert_eq!(h.rx(b"x"), Ok(Progress::Fallback));
    }

    #[test]
    fn an_interim_response_is_rewound_to_the_clients_own_request() {
        let mut t = HeaderTable::new([0u8; 512]).unwrap();
        t.create(Token::ClientUri, b"/x").unwrap();
        t.snapshot();
        let mut h = Head::with_table(t, Side::Client, Config::new());
        let r = h.rx(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(r, Ok(Progress::Complete { consumed: 25 }));
        h.rewind();
        assert!(!h.table().is_present(Token::Http));
        assert_eq!(
            h.rx(b"HTTP/1.1 200 OK\r\n\r\n"),
            Ok(Progress::Complete { consumed: 19 })
        );
        assert_eq!(h.table().first(Token::Http), Some(&b"200 OK"[..]));
        assert_eq!(h.table().first(Token::ClientUri), Some(&b"/x"[..]));
    }
}
