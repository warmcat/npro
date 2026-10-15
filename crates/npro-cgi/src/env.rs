//! The script's environment: RFC 3875's meta-variables, as C's
//! `lws_cgi()` composes them, and no more.
//!
//! The process is given nothing of the server's own environment: what
//! it sees is what is composed here, from the request and the script's
//! declared variables, into storage the caller gives.  As in C, what
//! does not fit is a hard failure, since a peer chooses most of it.

use npro_ss::event::Txn;
use npro_ss::policy::Tls;

use crate::Script;

/// The most the whole environment may take, each variable as
/// `NAME=value` and a NUL: C's buffer.
pub const MAX_ENV: usize = 8192;

/// The most variables: C's `env_array`.
pub const MAX_VARS: usize = 64;

/// What the server says it is.
const SERVER_SOFTWARE: &[u8] = b"npro";

/// Where a script may find programs: C's.
const PATH: &[u8] = b"/bin:/usr/bin:/usr/local/bin:/var/www/cgi-bin";

/// The request headers passed as `HTTP_*`, with the name each gets, in
/// C's order.
const PASSED: [(&[u8], &[u8]); 7] = [
    (b"referer", b"HTTP_REFERER"),
    (b"host", b"HTTP_HOST"),
    (b"cookie", b"HTTP_COOKIE"),
    (b"user-agent", b"HTTP_USER_AGENT"),
    (b"content-encoding", b"HTTP_CONTENT_ENCODING"),
    (b"accept", b"HTTP_ACCEPT"),
    (b"accept-encoding", b"HTTP_ACCEPT_ENCODING"),
];

/// Why the environment could not be composed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvError {
    /// It does not fit [`MAX_ENV`], or there are more than [`MAX_VARS`].
    TooLong,
    /// A value holds a NUL, which no environment can.
    Nul,
}

impl core::fmt::Display for EnvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "the script's environment does not fit",
            Self::Nul => "a value for the script's environment holds a NUL",
        })
    }
}

impl core::error::Error for EnvError {}

/// The environment, composed: each variable `NAME=value` and a NUL,
/// one after another.
///
/// ```no_run
/// # use npro_cgi::{Script, Vars};
/// # fn with(script: &Script<'_>, txn: &npro_ss::event::Txn<'_, Vec<u8>>) -> Result<(), npro_cgi::EnvError> {
/// let vars = Vars::of(script, txn)?;
/// for (name, value) in vars.iter() {
///     // std::process::Command::env(OsStr::from_bytes(name), OsStr::from_bytes(value))
///     let _ = (name, value);
/// }
/// # Ok(()) }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Vars {
    buf: [u8; MAX_ENV],
    len: usize,
    count: usize,
}

impl Vars {
    /// The environment for `script` to answer the request `txn` holds,
    /// as C composes it: `HTTPS=ON` on tls; `REQUEST_METHOD`;
    /// `QUERY_STRING`, the arguments encoded again; `REQUEST_URI`, the
    /// path as the parser decoded and made it safe; `PATH_INFO`, the
    /// path after the route's; the headers passed as `HTTP_*`;
    /// `CONTENT_TYPE` and `CONTENT_LENGTH`; `PATH`; `SCRIPT_PATH`; the
    /// script's own; and `SERVER_SOFTWARE`.
    ///
    /// # Errors
    ///
    /// [`EnvError`]: the request is then refused, as C refuses it.
    pub fn of<S: AsRef<[u8]> + AsMut<[u8]>>(
        script: &Script<'_>,
        txn: &Txn<'_, S>,
    ) -> Result<Self, EnvError> {
        let mut v = Self {
            buf: [0; MAX_ENV],
            len: 0,
            count: 0,
        };
        if let Tls::Server { .. } = txn.listener().tls {
            v.add(b"HTTPS", b"ON")?;
        }
        v.add(b"REQUEST_METHOD", txn.method().unwrap_or(b"GET"))?;
        v.query_string(txn)?;
        let path = txn.path().unwrap_or(b"/");
        v.add(b"REQUEST_URI", path)?;
        if let Some(r) = txn.route() {
            // what came after the route's path, with its `/`: C's
            // `cgi_path + script_uri_path_len`
            let info = path.get(r.route.path.len()..).unwrap_or_default();
            v.add(b"PATH_INFO", info)?;
        }
        for (header, name) in PASSED {
            if let Some(value) = txn.header(header) {
                v.add(name, value)?;
            }
        }
        if let Some(ct) = txn.header(b"content-type") {
            v.add(b"CONTENT_TYPE", ct)?;
        }
        if let Some(cl) = txn.header(b"content-length") {
            if cl.iter().all(u8::is_ascii_digit) && !cl.is_empty() {
                v.add(b"CONTENT_LENGTH", cl)?;
            }
        }
        v.add(b"PATH", PATH)?;
        v.add(b"SCRIPT_PATH", script.exec.as_bytes())?;
        for (name, value) in script.env {
            v.add(name.as_bytes(), value.as_bytes())?;
        }
        v.add(b"SERVER_SOFTWARE", SERVER_SOFTWARE)?;
        Ok(v)
    }

    /// Whether the script is git's backend, by `GIT_PROJECT_ROOT` among
    /// its variables, whose answer C passes on as it is, close-delimited.
    #[must_use]
    pub fn is_git(script: &Script<'_>) -> bool {
        script.env.iter().any(|(n, _)| *n == "GIT_PROJECT_ROOT")
    }

    /// Each variable: its name and its value.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.buf
            .get(..self.len)
            .unwrap_or_default()
            .split(|b| *b == 0)
            .filter(|v| !v.is_empty())
            .map(|v| {
                let at = v.iter().position(|b| *b == b'=').unwrap_or(v.len());
                (
                    v.get(..at).unwrap_or_default(),
                    v.get(at.saturating_add(1)..).unwrap_or_default(),
                )
            })
    }

    /// How many variables there are.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Adds `NAME=value` and its NUL.
    fn add(&mut self, name: &[u8], value: &[u8]) -> Result<(), EnvError> {
        if self.count >= MAX_VARS {
            return Err(EnvError::TooLong);
        }
        if value.contains(&0) || name.contains(&0) || name.contains(&b'=') {
            return Err(EnvError::Nul);
        }
        self.push(name)?;
        self.push(b"=")?;
        self.push(value)?;
        self.push(&[0])?;
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    fn push(&mut self, b: &[u8]) -> Result<(), EnvError> {
        let end = self.len.checked_add(b.len()).ok_or(EnvError::TooLong)?;
        let room = self.buf.get_mut(self.len..end).ok_or(EnvError::TooLong)?;
        room.copy_from_slice(b);
        self.len = end;
        Ok(())
    }

    /// `QUERY_STRING`: the arguments as the parser split and decoded
    /// them, each encoded again, `&` between, as C's `lws_cgi()` does,
    /// so a decoded `&` or `=` inside one cannot change the split the
    /// script sees.
    fn query_string<S: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        txn: &Txn<'_, S>,
    ) -> Result<(), EnvError> {
        if self.count >= MAX_VARS {
            return Err(EnvError::TooLong);
        }
        self.push(b"QUERY_STRING=")?;
        for (i, arg) in txn.args().enumerate() {
            if i > 0 {
                self.push(b"&")?;
            }
            match arg.iter().position(|c| *c == b'=') {
                Some(at) => {
                    self.push_encoded(arg.get(..at).unwrap_or_default())?;
                    self.push(b"=")?;
                    self.push_encoded(arg.get(at.saturating_add(1)..).unwrap_or_default())?;
                }
                None => self.push_encoded(arg)?,
            }
        }
        self.push(&[0])?;
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// `b` percent-encoded but for the unreserved characters.
    fn push_encoded(&mut self, b: &[u8]) -> Result<(), EnvError> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for &c in b {
            if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~') {
                self.push(&[c])?;
            } else {
                let hi = HEX.get(usize::from(c >> 4)).copied().unwrap_or(b'0');
                let lo = HEX.get(usize::from(c & 0xf)).copied().unwrap_or(b'0');
                self.push(&[b'%', hi, lo])?;
            }
        }
        Ok(())
    }
}
