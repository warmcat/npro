//! The `lws-transcript/1` format, as C lws' `api-test-sansio` writes it.
//!
//! A transcript is one JSON object: the format, the connection's name, which
//! side lws was on, the time the run started, the seed of lws' random, and
//! the steps.  Each step is a time and one of: bytes the peer sent (`rx`),
//! bytes lws wrote (`tx`), a payload lws gave the application (`app_rx`), or
//! lws releasing the transport (`close`).  The C tree's
//! `transcripts/README.md`, copied beside the transcripts here, is the
//! specification.
//!
//! The reader takes that format and nothing else: only the keys it defines,
//! each once; lowercase hex; no string escapes; no recursion.  Anything else
//! is a new format version, and refused.

use std::{
    fmt, fs, io,
    num::NonZeroU64,
    path::{Path, PathBuf},
};

/// The one format version this reader takes.
const FORMAT: &str = "lws-transcript/1";

/// The largest transcript file read, in bytes.
pub const MAX_BYTES: usize = 1 << 20;

/// The most steps one transcript may have.
pub const MAX_STEPS: usize = 4096;

/// Which side of the connection lws was on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The peer connected to lws.
    Server,
    /// lws connected to the peer.
    Client,
}

/// What happened at one step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepKind {
    /// The peer sent these bytes, handed to lws at the step's time.
    Rx(Vec<u8>),
    /// lws wrote these bytes.  How many writes it took is not behaviour.
    Tx(Vec<u8>),
    /// lws gave the application this payload: a response body, or a ws
    /// message's payload.  How a payload is split into deliveries is not
    /// behaviour, only the concatenation of each message or body.
    AppRx(Vec<u8>),
    /// lws released the connection's transport.
    Close,
}

/// One step of a transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// When, in microseconds after the run's start, `t0_us`.
    pub t_us: u64,
    /// What happened.
    pub kind: StepKind,
}

/// One connection's life, as recorded by C lws.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    /// The connection's name, which is also its file's.
    pub case: String,
    /// Which side lws was on.
    pub side: Side,
    /// The monotonic time when the run starts, in microseconds.
    pub t0_us: u64,
    /// The wall time at `t0_us`, in seconds since 1970.
    pub t0_wall: u64,
    /// The seed of lws' random, reseeded when this connection starts; `None`
    /// when nothing in its bytes depends on lws' random.
    pub seed: Option<NonZeroU64>,
    /// What happened, in order.  Step times never go backwards.
    pub steps: Vec<Step>,
}

/// Why a transcript could not be read.
#[derive(Debug)]
pub enum Error {
    /// The file could not be read.
    Io(io::Error),
    /// The file is larger than [`MAX_BYTES`].
    TooLarge,
    /// The text is not the JSON this format allows at this byte offset.
    Syntax {
        /// Byte offset of the problem.
        offset: usize,
        /// What was expected there.
        expected: &'static str,
    },
    /// `format` names a version other than `lws-transcript/1`.
    UnknownFormat,
    /// A key the format does not define, at this byte offset.
    UnknownKey {
        /// Byte offset of the key.
        offset: usize,
    },
    /// A key given twice.
    DuplicateKey(&'static str),
    /// A key the format requires is missing.
    MissingKey(&'static str),
    /// `side` is neither `server` nor `client`.
    BadSide {
        /// Byte offset of the value.
        offset: usize,
    },
    /// A payload that is not lowercase hex of whole bytes.
    BadHex {
        /// Byte offset of the value.
        offset: usize,
    },
    /// A step that is not a time and exactly one of `rx`, `tx`, `app_rx` or
    /// an empty `close`.
    BadStep {
        /// Byte offset of the step.
        offset: usize,
    },
    /// A number too large for 64 bits.
    Overflow {
        /// Byte offset of the number.
        offset: usize,
    },
    /// More than [`MAX_STEPS`] steps.
    TooManySteps,
    /// A step earlier than the one before it.
    TimeGoesBackwards {
        /// Index of the step.
        step: usize,
    },
    /// The file's name is not its `case`.
    CaseMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read transcript: {e}"),
            Self::TooLarge => write!(f, "transcript larger than {MAX_BYTES} bytes"),
            Self::Syntax { offset, expected } => {
                write!(f, "at byte {offset}: expected {expected}")
            }
            Self::UnknownFormat => write!(f, "format is not {FORMAT}"),
            Self::UnknownKey { offset } => write!(f, "at byte {offset}: unknown key"),
            Self::DuplicateKey(k) => write!(f, "key \"{k}\" given twice"),
            Self::MissingKey(k) => write!(f, "key \"{k}\" missing"),
            Self::BadSide { offset } => {
                write!(f, "at byte {offset}: side is not server or client")
            }
            Self::BadHex { offset } => {
                write!(f, "at byte {offset}: not lowercase hex of whole bytes")
            }
            Self::BadStep { offset } => write!(
                f,
                "at byte {offset}: a step is a time and one of rx, tx, app_rx or an empty close"
            ),
            Self::Overflow { offset } => write!(f, "at byte {offset}: number too large"),
            Self::TooManySteps => write!(f, "more than {MAX_STEPS} steps"),
            Self::TimeGoesBackwards { step } => write!(f, "step {step} goes back in time"),
            Self::CaseMismatch => write!(f, "file name is not the transcript's case"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl Transcript {
    /// Reads a transcript from its text.
    ///
    /// ```
    /// use npro_test::{Side, StepKind, Transcript};
    ///
    /// let t = Transcript::parse(br#"{
    ///  "format": "lws-transcript/1", "case": "x", "side": "client",
    ///  "t0_us": 1000000000, "t0_wall": 1767225600, "seed": 0,
    ///  "steps": [ {"t": 1000, "tx": "4745"}, {"t": 2000, "close": ""} ]
    /// }"#)?;
    ///
    /// assert_eq!(t.side, Side::Client);
    /// assert_eq!(t.steps[0].kind, StepKind::Tx(b"GE".to_vec()));
    /// assert_eq!(t.steps[1].kind, StepKind::Close);
    /// # Ok::<(), npro_test::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Any departure from the format: see [`Error`].
    pub fn parse(text: &[u8]) -> Result<Self, Error> {
        if text.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }

        let mut c = Cursor { b: text, pos: 0 };
        let mut format = None;
        let mut case = None;
        let mut side = None;
        let mut t0_us = None;
        let mut t0_wall = None;
        let mut seed = None;
        let mut steps = None;

        c.members(|c, key, at| match key {
            "format" => once(&mut format, "format", c.string()?),
            "case" => once(&mut case, "case", c.string()?),
            "side" => {
                let at = c.value_offset();
                let s = match c.string()? {
                    "server" => Side::Server,
                    "client" => Side::Client,
                    _ => return Err(Error::BadSide { offset: at }),
                };
                once(&mut side, "side", s)
            }
            "t0_us" => once(&mut t0_us, "t0_us", c.uint()?),
            "t0_wall" => once(&mut t0_wall, "t0_wall", c.uint()?),
            "seed" => once(&mut seed, "seed", c.uint()?),
            "steps" => once(&mut steps, "steps", c.steps()?),
            _ => Err(Error::UnknownKey { offset: at }),
        })?;

        c.ws();
        if c.peek().is_some() {
            return Err(c.syntax("the end of the text"));
        }

        if format.ok_or(Error::MissingKey("format"))? != FORMAT {
            return Err(Error::UnknownFormat);
        }

        let steps: Vec<Step> = steps.ok_or(Error::MissingKey("steps"))?;
        let mut last = 0;
        for (i, s) in steps.iter().enumerate() {
            if s.t_us < last {
                return Err(Error::TimeGoesBackwards { step: i });
            }
            last = s.t_us;
        }

        Ok(Self {
            case: case.ok_or(Error::MissingKey("case"))?.to_owned(),
            side: side.ok_or(Error::MissingKey("side"))?,
            t0_us: t0_us.ok_or(Error::MissingKey("t0_us"))?,
            t0_wall: t0_wall.ok_or(Error::MissingKey("t0_wall"))?,
            seed: NonZeroU64::new(seed.ok_or(Error::MissingKey("seed"))?),
            steps,
        })
    }

    /// Reads a transcript file, whose name must be its case.
    ///
    /// # Errors
    ///
    /// The file cannot be read, is larger than [`MAX_BYTES`], is not the
    /// format, or is not named for its case.
    pub fn read(path: &Path) -> Result<Self, Error> {
        let max = u64::try_from(MAX_BYTES).map_err(|_| Error::TooLarge)?;
        if fs::metadata(path)?.len() > max {
            return Err(Error::TooLarge);
        }

        let t = Self::parse(&fs::read(path)?)?;
        if path.file_stem().and_then(|s| s.to_str()) != Some(t.case.as_str()) {
            return Err(Error::CaseMismatch);
        }

        Ok(t)
    }
}

/// The transcripts copied into this crate from the C tree, sorted by case.
///
/// # Errors
///
/// The directory cannot be listed, or any `.json` file in it cannot be read
/// as a transcript.
pub fn vendored() -> Result<Vec<Transcript>, Error> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("transcripts");
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    paths.retain(|p| p.extension().is_some_and(|x| x == "json"));
    paths.sort();

    paths.iter().map(|p| Transcript::read(p)).collect()
}

/// Sets a key's value, refusing a second one.
fn once<T>(slot: &mut Option<T>, key: &'static str, v: T) -> Result<(), Error> {
    if slot.replace(v).is_some() {
        return Err(Error::DuplicateKey(key));
    }
    Ok(())
}

/// The digits of lowercase hex, in order of value.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// The value of one lowercase hex digit.
fn nibble(c: u8) -> Option<u8> {
    HEX.iter()
        .position(|&d| d == c)
        .and_then(|n| u8::try_from(n).ok())
}

/// Decodes lowercase hex of whole bytes.
fn hex(s: &str) -> Option<Vec<u8>> {
    let pairs = s.as_bytes().chunks_exact(2);
    if !pairs.remainder().is_empty() {
        return None;
    }

    pairs
        .map(|p| match p {
            [hi, lo] => Some(nibble(*hi)?.checked_shl(4)? | nibble(*lo)?),
            _ => None,
        })
        .collect()
}

/// A position in the text being read.
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn syntax(&self, expected: &'static str) -> Error {
        Error::Syntax {
            offset: self.pos,
            expected,
        }
    }

    /// Skips JSON whitespace.
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    /// The offset of the next value, after any whitespace.
    fn value_offset(&mut self) -> usize {
        self.ws();
        self.pos
    }

    fn eat(&mut self, c: u8, expected: &'static str) -> Result<(), Error> {
        self.ws();
        if self.peek() != Some(c) {
            return Err(self.syntax(expected));
        }
        self.bump();
        Ok(())
    }

    /// A string with no escapes and no control characters.
    fn string(&mut self) -> Result<&'a str, Error> {
        self.eat(b'"', "a string")?;
        let start = self.pos;
        loop {
            match self.peek() {
                None => return Err(self.syntax("the end of the string")),
                Some(b'"') => break,
                Some(b'\\') => return Err(self.syntax("a string with no escapes")),
                Some(c) if c < 0x20 => return Err(self.syntax("no control characters")),
                Some(_) => self.bump(),
            }
        }
        let s = self
            .b
            .get(start..self.pos)
            .ok_or_else(|| self.syntax("a string"))?;
        self.bump();
        std::str::from_utf8(s).map_err(|_| Error::Syntax {
            offset: start,
            expected: "UTF-8",
        })
    }

    /// An unsigned integer that fits 64 bits.
    fn uint(&mut self) -> Result<u64, Error> {
        self.ws();
        let start = self.pos;
        let mut v: u64 = 0;
        while let Some(d) = self.peek().and_then(|c| char::from(c).to_digit(10)) {
            v = v
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(d)))
                .ok_or(Error::Overflow { offset: start })?;
            self.bump();
        }
        if self.pos == start {
            return Err(self.syntax("a number"));
        }
        Ok(v)
    }

    /// An object: each member's key and the key's offset are handed to
    /// `member`, which must read the value.
    fn members(
        &mut self,
        mut member: impl FnMut(&mut Self, &'a str, usize) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.eat(b'{', "{")?;
        self.ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(());
        }
        loop {
            let at = self.value_offset();
            let key = self.string()?;
            self.eat(b':', ":")?;
            member(self, key, at)?;
            self.ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b'}') => {
                    self.bump();
                    return Ok(());
                }
                _ => return Err(self.syntax(", or }")),
            }
        }
    }

    /// The array of steps.
    fn steps(&mut self) -> Result<Vec<Step>, Error> {
        let mut steps = Vec::new();
        self.eat(b'[', "[")?;
        self.ws();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(steps);
        }
        loop {
            if steps.len() >= MAX_STEPS {
                return Err(Error::TooManySteps);
            }
            steps.push(self.step()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.bump(),
                Some(b']') => {
                    self.bump();
                    return Ok(steps);
                }
                _ => return Err(self.syntax(", or ]")),
            }
        }
    }

    /// One step: a time and exactly one thing that happened.
    fn step(&mut self) -> Result<Step, Error> {
        let start = self.value_offset();
        let mut t_us = None;
        let mut kind = None;

        self.members(|c, key, at| {
            if key == "t" {
                return once(&mut t_us, "t", c.uint()?);
            }

            let v_at = c.value_offset();
            let k = match key {
                "rx" | "tx" | "app_rx" => {
                    let bytes = hex(c.string()?).ok_or(Error::BadHex { offset: v_at })?;
                    match key {
                        "rx" => StepKind::Rx(bytes),
                        "tx" => StepKind::Tx(bytes),
                        _ => StepKind::AppRx(bytes),
                    }
                }
                "close" if c.string()?.is_empty() => StepKind::Close,
                "close" => return Err(Error::BadStep { offset: start }),
                _ => return Err(Error::UnknownKey { offset: at }),
            };
            if kind.replace(k).is_some() {
                return Err(Error::BadStep { offset: start });
            }
            Ok(())
        })?;

        Ok(Step {
            t_us: t_us.ok_or(Error::MissingKey("t"))?,
            kind: kind.ok_or(Error::BadStep { offset: start })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = r#""format": "lws-transcript/1", "case": "c", "side": "server",
        "t0_us": 1000000000, "t0_wall": 1767225600, "seed": 0"#;

    fn with_steps(steps: &str) -> String {
        format!("{{ {HEAD}, \"steps\": [ {steps} ] }}")
    }

    #[test]
    fn reads_every_kind_of_step() {
        let t = Transcript::parse(
            with_steps(
                r#"{"t": 1, "rx": "00ff"}, {"t": 1, "tx": ""},
                   {"t": 2, "app_rx": "41"}, {"t": 3, "close": ""}"#,
            )
            .as_bytes(),
        )
        .unwrap();

        assert_eq!(t.case, "c");
        assert_eq!(t.side, Side::Server);
        assert_eq!(t.seed, None);
        let kinds: Vec<_> = t.steps.into_iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            [
                StepKind::Rx(vec![0, 0xff]),
                StepKind::Tx(vec![]),
                StepKind::AppRx(b"A".to_vec()),
                StepKind::Close
            ]
        );
    }

    #[test]
    fn a_nonzero_seed_is_kept() {
        let t = Transcript::parse(
            with_steps("")
                .replace("\"seed\": 0", "\"seed\": 1")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(t.seed, NonZeroU64::new(1));
    }

    fn refused(text: &str) -> Error {
        Transcript::parse(text.as_bytes()).unwrap_err()
    }

    #[test]
    fn refuses_what_the_format_does_not_define() {
        assert!(matches!(
            refused(&with_steps("").replace("/1", "/2")),
            Error::UnknownFormat
        ));
        assert!(matches!(
            refused(&with_steps("").replace("\"server\"", "\"peer\"")),
            Error::BadSide { .. }
        ));
        assert!(matches!(
            refused(&with_steps("").replace("\"seed\"", "\"sneed\"")),
            Error::UnknownKey { .. }
        ));
        assert!(matches!(
            refused(&with_steps("").replace(", \"seed\": 0", "")),
            Error::MissingKey("seed")
        ));
        assert!(matches!(
            refused(&with_steps("").replace("\"seed\": 0", "\"seed\": 0, \"seed\": 1")),
            Error::DuplicateKey("seed")
        ));
        assert!(matches!(
            refused(&format!("{} x", with_steps(""))),
            Error::Syntax { .. }
        ));
    }

    #[test]
    fn refuses_bad_steps() {
        for (steps, why) in [
            (r#"{"t": 1, "rx": "0"}"#, "odd hex"),
            (r#"{"t": 1, "rx": "0A"}"#, "uppercase hex"),
            (r#"{"t": 1, "rx": "0g"}"#, "not hex"),
            (r#"{"t": 1, "close": "00"}"#, "a close with a payload"),
            (r#"{"t": 1, "rx": "00", "tx": "00"}"#, "two kinds"),
            (r#"{"t": 1}"#, "no kind"),
            (r#"{"rx": "00"}"#, "no time"),
            (r#"{"t": 1, "rx": "a\"b"}"#, "an escape"),
            (
                r#"{"t": 2, "rx": ""}, {"t": 1, "rx": ""}"#,
                "time going back",
            ),
            (
                r#"{"t": 18446744073709551616, "rx": ""}"#,
                "a time past 64 bits",
            ),
            (r#"{"t": 1, "rx": ""},"#, "a trailing comma"),
        ] {
            assert!(
                Transcript::parse(with_steps(steps).as_bytes()).is_err(),
                "accepted {why}"
            );
        }
    }

    #[test]
    fn refuses_too_many_steps_and_too_much_text() {
        let many = vec![r#"{"t": 0, "rx": ""}"#; MAX_STEPS + 1].join(",");
        assert!(matches!(refused(&with_steps(&many)), Error::TooManySteps));

        let big = vec![b' '; MAX_BYTES + 1];
        assert!(matches!(Transcript::parse(&big), Err(Error::TooLarge)));
    }

    #[test]
    fn refuses_a_truncated_text() {
        // a text cut anywhere must be refused, never read as a shorter one
        let text = with_steps(r#"{"t": 1, "rx": "00ff"}, {"t": 2, "close": ""}"#);
        for n in 0..text.len() {
            assert!(
                Transcript::parse(text.as_bytes().get(..n).unwrap()).is_err(),
                "accepted a text cut at {n}"
            );
        }
        assert!(Transcript::parse(text.as_bytes()).is_ok());
    }
}
