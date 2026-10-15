//! The policy, from JSON: its layers read and merged, and the Rust
//! types the services and the runner take made from the result.
//!
//! A program's policy is five layers, lowest first, each overriding
//! those under it (docs/ss-policy.md, "Defaults, by layer"): what is
//! built in ([`BUILT_IN`]), the system's `/etc/npro/defaults.json`, the
//! user's `~/.config/npro/defaults.json`, the policy file, and the
//! fragments given on the command line.  Each is a JSON object as
//! npro-json reads it, so a member named twice in one layer is refused;
//! a higher layer's member replaces a lower's, except an object, which
//! is merged member by member ([`merge`]).  Nothing is accepted and
//! ignored: a member nothing is declared for fails the load, naming its
//! path.
//!
//! The first form of the policy, as this reads it:
//!
//! ```json
//! {
//!   "listeners": {
//!     "https": { "bind": "[::]:443",
//!                "tls": { "cert": "/path/fullchain.pem", "key": "/path/key.pem" },
//!                "vhosts": ["example.com"] },
//!     "http":  { "bind": "[::]:80", "vhosts": ["example.com-http"] }
//!   },
//!   "vhosts": {
//!     "example.com": {
//!       "headers": { "strict-transport-security": "max-age=15768000" },
//!       "not-found": "/404.html",
//!       "routes": [
//!         { "path": "/",    "to": "www" },
//!         { "path": "/git", "to": "git", "headers": { "x-git": "1" } },
//!         { "path": "/chat", "to": "chat", "exact": true,
//!           "ws": { "protocols": ["chat"], "default": "chat" } }
//!       ]
//!     },
//!     "example.com-http": { "routes": [ { "path": "/", "to": "to-https" } ] }
//!   },
//!   "services": {
//!     "www":      { "type": "files", "root": "/var/www/example.com",
//!                   "default": "index.html",
//!                   "cache": { "max-age": 172800, "revalidate": false, "public": false },
//!                   "mimes": { ".tar.gz": "application/x-gtar" } },
//!     "git":      { "type": "proxy", "address": "unix:/var/run/gitohashi", "path": "/git" },
//!     "to-https": { "type": "redirect", "to": "https://example.com", "append-path": true }
//!   },
//!   "npro": { "slots": 64, "workers": 2 }
//! }
//! ```
//!
//! What comes of it borrows nothing: a [`Policy`] is made once for the
//! life of the process, and leaks its storage on purpose, since the
//! runner's listeners and the services borrow it for as long as the
//! server runs.

use core::time::Duration;
use std::fs;
use std::path::{Path, PathBuf};

use npro_cgi::Script;
use npro_files::{Cache, Intermediaries, Mount, Revalidate};
use npro_h1::server::Config as H1Config;
use npro_json::{Config, Event, Parser, Storage};
use npro_proxy::Upstream;
use npro_ss::policy::{Deflate, Listener, Match, Payload, Route, Tls, Vhost, Ws, WsServer};

use crate::front::{Append, Redirect, Service, Services};

/// The lowest layer: what npro does with no policy at all.
pub const BUILT_IN: &str = r#"{"npro": {"slots": 64, "workers": 2}}"#;

/// The system's defaults.
pub const SYSTEM_DEFAULTS: &str = "/etc/npro/defaults.json";

/// The user's defaults, under the home directory.
pub const USER_DEFAULTS: &str = ".config/npro/defaults.json";

/// The policy, when none is named.
pub const DEFAULT_POLICY: &str = "/etc/npro/policy.json";

/// The longest string or number a policy holds, and all the names of
/// the objects open at once.
const TOKEN: usize = 4096;

/// A JSON value, owned.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as written.
    Number(String),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object, its members in order; no name twice.
    Object(Vec<(String, Value)>),
}

/// Why a policy could not be loaded.
#[derive(Debug)]
pub enum PolicyError {
    /// A layer's file could not be read.
    Read {
        /// Which.
        path: PathBuf,
        /// Why.
        error: std::io::Error,
    },
    /// A layer is not JSON npro reads.
    Json {
        /// Which layer.
        layer: String,
        /// Why.
        error: npro_json::Error,
    },
    /// A layer is not an object.
    NotAnObject(String),
    /// A member is not of the type its place needs.
    Type {
        /// The member's path, `vhosts.example.com.routes[2].path`.
        at: String,
        /// What was needed.
        expected: &'static str,
    },
    /// A member nothing is declared for.
    Unknown(String),
    /// A member that must be there is not.
    Missing(String),
    /// A member refers to something not declared: a listener's vhost, a
    /// ws route's default protocol, a service's type.
    NoSuch {
        /// The member's path.
        at: String,
        /// What it named.
        name: String,
        /// What there is.
        known: Vec<String>,
    },
    /// A `-p` fragment is neither a JSON object nor `key.path=value`.
    Fragment(String),
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read { path, error } => write!(f, "{}: {error}", path.display()),
            Self::Json { layer, error } => write!(f, "{layer}: {error}"),
            Self::NotAnObject(layer) => write!(f, "{layer}: not a JSON object"),
            Self::Type { at, expected } => write!(f, "{at}: expected {expected}"),
            Self::Unknown(at) => write!(f, "{at}: nothing is declared under that name"),
            Self::Missing(at) => write!(f, "{at}: required, and not given"),
            Self::NoSuch { at, name, known } => {
                write!(f, "{at}: no {name:?}; there is {}", known.join(", "))
            }
            Self::Fragment(s) => write!(f, "{s:?}: not a JSON object, nor key.path=value"),
        }
    }
}

impl core::error::Error for PolicyError {}

/// Parses `text` as one JSON value, as npro-json reads it.
///
/// # Errors
///
/// [`PolicyError::Json`], naming `layer`.
pub fn parse(layer: &str, text: &[u8]) -> Result<Value, PolicyError> {
    let json = |error| PolicyError::Json {
        layer: layer.to_owned(),
        error,
    };
    let mut p = Parser::new(
        Storage {
            token: vec![0u8; TOKEN],
            names: vec![0u8; TOKEN],
        },
        Config::new(),
    )
    .map_err(|_| PolicyError::NotAnObject(layer.to_owned()))?;
    // the values being built, outermost first; a member's name waits
    // beside its object until its value comes
    let mut stack: Vec<(Value, Option<String>)> = Vec::new();
    let mut done: Option<Value> = None;
    let mut input = text;
    loop {
        let event = if input.is_empty() {
            match p.end().map_err(json)? {
                Some(e) => e,
                None => break,
            }
        } else {
            let step = p.next(input).map_err(json)?;
            input = input.get(step.consumed..).unwrap_or_default();
            match step.event {
                Some(e) => e,
                None => continue,
            }
        };
        let value = match event {
            Event::ObjectStart => {
                stack.push((Value::Object(Vec::new()), None));
                continue;
            }
            Event::ArrayStart => {
                stack.push((Value::Array(Vec::new()), None));
                continue;
            }
            Event::Name(n) => {
                if let Some((_, name)) = stack.last_mut() {
                    *name = Some(n.to_owned());
                }
                continue;
            }
            Event::ObjectEnd | Event::ArrayEnd => match stack.pop() {
                Some((v, _)) => v,
                None => break,
            },
            Event::String(s) => Value::String(s.to_owned()),
            Event::Number(n) => Value::Number(n.as_str().to_owned()),
            Event::Bool(b) => Value::Bool(b),
            Event::Null => Value::Null,
        };
        match stack.last_mut() {
            Some((Value::Object(members), name)) => {
                if let Some(n) = name.take() {
                    members.push((n, value));
                }
            }
            Some((Value::Array(items), _)) => items.push(value),
            Some(_) | None => done = Some(value),
        }
        if input.is_empty() && stack.is_empty() {
            // the end: nothing more may follow
            if p.end().map_err(json)?.is_some() {
                break;
            }
            break;
        }
    }
    done.ok_or_else(|| PolicyError::NotAnObject(layer.to_owned()))
}

/// `higher` over `lower`: an object's members are merged one by one,
/// anything else is replaced.
#[must_use]
pub fn merge(lower: Value, higher: Value) -> Value {
    match (lower, higher) {
        (Value::Object(mut low), Value::Object(high)) => {
            for (name, value) in high {
                match low.iter_mut().find(|(n, _)| *n == name) {
                    Some((_, slot)) => {
                        let was = core::mem::replace(slot, Value::Null);
                        *slot = merge(was, value);
                    }
                    None => low.push((name, value)),
                }
            }
            Value::Object(low)
        }
        (_, high) => high,
    }
}

/// A `-p` fragment: a JSON object, or `key.path=value`, the value JSON
/// if it reads as JSON (`443`, `true`, `"x"`), else a string.
///
/// # Errors
///
/// [`PolicyError`].
pub fn fragment(text: &str) -> Result<Value, PolicyError> {
    if text.trim_start().starts_with('{') {
        return match parse("-p", text.as_bytes())? {
            v @ Value::Object(_) => Ok(v),
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::Array(_) => Err(PolicyError::Fragment(text.to_owned())),
        };
    }
    let (path, value) = text
        .split_once('=')
        .ok_or_else(|| PolicyError::Fragment(text.to_owned()))?;
    let value = parse("-p", value.as_bytes()).unwrap_or_else(|_| Value::String(value.to_owned()));
    let mut v = value;
    for key in path.rsplit('.') {
        if key.is_empty() {
            return Err(PolicyError::Fragment(text.to_owned()));
        }
        v = Value::Object(vec![(key.to_owned(), v)]);
    }
    Ok(v)
}

/// The layers, merged: built in, the system's, the user's, `policy` if
/// given (else [`DEFAULT_POLICY`], which may be absent), and the
/// `fragments`.  A default file that is not there is no error.
///
/// # Errors
///
/// [`PolicyError`].
pub fn layers(policy: Option<&Path>, fragments: &[String]) -> Result<Value, PolicyError> {
    let mut merged = parse("built in", BUILT_IN.as_bytes())?;
    let user = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(USER_DEFAULTS));
    let defaults = [Some(PathBuf::from(SYSTEM_DEFAULTS)), user];
    for p in defaults.iter().flatten() {
        if let Some(v) = read_layer(p, Present::MayBeAbsent)? {
            merged = merge(merged, v);
        }
    }
    let (file, must) = match policy {
        Some(p) => (p.to_path_buf(), Present::Must),
        None => (PathBuf::from(DEFAULT_POLICY), Present::MayBeAbsent),
    };
    if let Some(v) = read_layer(&file, must)? {
        merged = merge(merged, v);
    }
    for f in fragments {
        merged = merge(merged, fragment(f)?);
    }
    Ok(merged)
}

/// Whether a layer's file must be there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Present {
    Must,
    MayBeAbsent,
}

fn read_layer(path: &Path, present: Present) -> Result<Option<Value>, PolicyError> {
    let text = match fs::read(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && present == Present::MayBeAbsent => {
            return Ok(None);
        }
        Err(error) => {
            return Err(PolicyError::Read {
                path: path.to_path_buf(),
                error,
            });
        }
    };
    let layer = path.display().to_string();
    match parse(&layer, &text)? {
        v @ Value::Object(_) => Ok(Some(v)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_) => {
            Err(PolicyError::NotAnObject(layer))
        }
    }
}

/// The policy as the runner and the front take it, made once, its
/// storage leaked for the life of the process.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// The listeners, for the runner.
    pub listeners: &'static [Listener<'static>],
    /// The services, for the front.
    pub services: Services<'static>,
    /// Each vhost's access log, by the vhost's name, for the front's
    /// [`crate::front::Logs`].
    pub logs: &'static [(&'static str, &'static str)],
    /// How many streams at once.
    pub slots: usize,
    /// How many worker threads for the application's jobs.
    pub workers: usize,
}

/// A member of an object, by name, with what it may hold.
struct Members<'a> {
    at: String,
    members: &'a [(String, Value)],
}

impl<'a> Members<'a> {
    /// `v` as an object at `at`.
    fn of(at: String, v: &'a Value) -> Result<Self, PolicyError> {
        match v {
            Value::Object(members) => Ok(Self { at, members }),
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::Array(_) => Err(PolicyError::Type {
                at,
                expected: "an object",
            }),
        }
    }

    fn path(&self, name: &str) -> String {
        if self.at.is_empty() {
            name.to_owned()
        } else {
            format!("{}.{name}", self.at)
        }
    }

    /// Refuses a member not in `allowed`.
    fn only(&self, allowed: &[&str]) -> Result<(), PolicyError> {
        match self
            .members
            .iter()
            .find(|(n, _)| !allowed.contains(&n.as_str()))
        {
            Some((n, _)) => Err(PolicyError::Unknown(self.path(n))),
            None => Ok(()),
        }
    }

    fn get(&self, name: &str) -> Option<&'a Value> {
        self.members.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    fn string(&self, name: &str) -> Result<Option<&'a str>, PolicyError> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(PolicyError::Type {
                at: self.path(name),
                expected: "a string",
            }),
        }
    }

    fn required(&self, name: &str) -> Result<&'a str, PolicyError> {
        self.string(name)?
            .ok_or_else(|| PolicyError::Missing(self.path(name)))
    }

    fn bool(&self, name: &str) -> Result<Option<bool>, PolicyError> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(PolicyError::Type {
                at: self.path(name),
                expected: "true or false",
            }),
        }
    }

    fn number(&self, name: &str) -> Result<Option<u64>, PolicyError> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::Number(n)) => n.parse().map(Some).map_err(|_| PolicyError::Type {
                at: self.path(name),
                expected: "a whole number, 0 or more",
            }),
            Some(_) => Err(PolicyError::Type {
                at: self.path(name),
                expected: "a number",
            }),
        }
    }

    fn object(&self, name: &str) -> Result<Option<Members<'a>>, PolicyError> {
        match self.get(name) {
            None => Ok(None),
            Some(v) => Members::of(self.path(name), v).map(Some),
        }
    }

    fn array(&self, name: &str) -> Result<Option<&'a [Value]>, PolicyError> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::Array(items)) => Ok(Some(items)),
            Some(_) => Err(PolicyError::Type {
                at: self.path(name),
                expected: "an array",
            }),
        }
    }

    /// An array of strings.
    fn strings(&self, name: &str) -> Result<Option<Vec<&'a str>>, PolicyError> {
        let Some(items) = self.array(name)? else {
            return Ok(None);
        };
        items
            .iter()
            .enumerate()
            .map(|(i, v)| match v {
                Value::String(s) => Ok(s.as_str()),
                Value::Null
                | Value::Bool(_)
                | Value::Number(_)
                | Value::Array(_)
                | Value::Object(_) => Err(PolicyError::Type {
                    at: format!("{}[{i}]", self.path(name)),
                    expected: "a string",
                }),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    /// An object of string members, as headers or mime types are given.
    fn pairs(&self, name: &str) -> Result<Vec<(&'a str, &'a str)>, PolicyError> {
        let Some(m) = self.object(name)? else {
            return Ok(Vec::new());
        };
        m.members
            .iter()
            .map(|(n, v)| match v {
                Value::String(s) => Ok((n.as_str(), s.as_str())),
                Value::Null
                | Value::Bool(_)
                | Value::Number(_)
                | Value::Array(_)
                | Value::Object(_) => Err(PolicyError::Type {
                    at: m.path(n),
                    expected: "a string",
                }),
            })
            .collect()
    }
}

/// Leaks `s` for the life of the process.
fn keep(s: &str) -> &'static str {
    Box::leak(s.to_owned().into_boxed_str())
}

fn keep_bytes(s: &str) -> &'static [u8] {
    Box::leak(s.as_bytes().to_vec().into_boxed_slice())
}

fn keep_headers(pairs: &[(&str, &str)]) -> &'static [(&'static [u8], &'static [u8])] {
    let v: Vec<(&'static [u8], &'static [u8])> = pairs
        .iter()
        .map(|(n, v)| (keep_bytes(n), keep_bytes(v)))
        .collect();
    Vec::leak(v)
}

/// How long a script may take to begin its answer when the policy does
/// not say, in seconds.
const DEFAULT_TIMEOUT: u64 = 30;

/// The policy's Rust types from the merged layers `v`.
///
/// # Errors
///
/// [`PolicyError`].
pub fn policy(v: &Value) -> Result<Policy, PolicyError> {
    let top = Members::of(String::new(), v)?;
    top.only(&["listeners", "vhosts", "services", "npro"])?;
    let services = services(&top)?;
    let (vhosts, logs) = vhosts(&top, &services)?;
    let listeners = listeners(&top, &vhosts)?;
    let npro = top.object("npro")?;
    let (slots, workers) = match npro {
        Some(n) => {
            n.only(&["slots", "workers"])?;
            (n.number("slots")?, n.number("workers")?)
        }
        None => (None, None),
    };
    Ok(Policy {
        listeners: Vec::leak(listeners),
        services: Services {
            by_name: Vec::leak(services),
        },
        logs: Vec::leak(logs),
        slots: usize::try_from(slots.unwrap_or(64)).unwrap_or(64),
        workers: usize::try_from(workers.unwrap_or(2)).unwrap_or(2),
    })
}

fn services(top: &Members<'_>) -> Result<Vec<(&'static str, Service<'static>)>, PolicyError> {
    let Some(all) = top.object("services")? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (name, v) in all.members {
        let m = Members::of(all.path(name), v)?;
        let kind = m.required("type")?;
        let service = match kind {
            "files" => {
                m.only(&["type", "root", "default", "cache", "mimes"])?;
                let cache = match m.object("cache")? {
                    None => Cache::NoStore,
                    Some(c) => {
                        c.only(&["no-cache", "max-age", "revalidate", "public"])?;
                        if c.bool("no-cache")? == Some(true) {
                            Cache::NoCache
                        } else {
                            match c.number("max-age")? {
                                None => Cache::NoStore,
                                Some(age) => Cache::For {
                                    max_age: u32::try_from(age).map_err(|_| PolicyError::Type {
                                        at: c.path("max-age"),
                                        expected: "seconds, up to 4294967295",
                                    })?,
                                    revalidate: if c.bool("revalidate")? == Some(true) {
                                        Revalidate::Must
                                    } else {
                                        Revalidate::NotNeeded
                                    },
                                    intermediaries: if c.bool("public")? == Some(true) {
                                        Intermediaries::Public
                                    } else {
                                        Intermediaries::Private
                                    },
                                },
                            }
                        }
                    }
                };
                let mimes: Vec<(&'static str, &'static str)> = m
                    .pairs("mimes")?
                    .iter()
                    .map(|(s, t)| (keep(s), keep(t)))
                    .collect();
                Service::Files(Mount {
                    root: keep(m.required("root")?),
                    default: keep(m.string("default")?.unwrap_or("index.html")),
                    cache,
                    mimes: Vec::leak(mimes),
                })
            }
            "proxy" => {
                m.only(&["type", "address", "path", "host"])?;
                Service::Proxy(Upstream {
                    address: keep(m.required("address")?),
                    path: keep(m.string("path")?.unwrap_or("/")),
                    host: keep(m.string("host")?.unwrap_or("")),
                })
            }
            "redirect" => {
                m.only(&["type", "to", "append-path"])?;
                Service::Redirect(Redirect {
                    to: keep(m.required("to")?),
                    append: if m.bool("append-path")? == Some(true) {
                        Append::Path
                    } else {
                        Append::Nothing
                    },
                })
            }
            "cgi" => {
                m.only(&["type", "exec", "env", "dir", "timeout"])?;
                let env: Vec<(&'static str, &'static str)> = m
                    .pairs("env")?
                    .iter()
                    .map(|(n, val)| (keep(n), keep(val)))
                    .collect();
                Service::Cgi(Script {
                    exec: keep(m.required("exec")?),
                    env: Vec::leak(env),
                    dir: m.string("dir")?.map(keep),
                    timeout: Duration::from_secs(m.number("timeout")?.unwrap_or(DEFAULT_TIMEOUT)),
                })
            }
            other => {
                return Err(PolicyError::NoSuch {
                    at: m.path("type"),
                    name: other.to_owned(),
                    known: vec![
                        "files".into(),
                        "proxy".into(),
                        "redirect".into(),
                        "cgi".into(),
                    ],
                });
            }
        };
        out.push((keep(name), service));
    }
    Ok(out)
}

/// The vhosts by name, and the access log of each that has one.
type Vhosts = (
    Vec<(&'static str, Vhost<'static>)>,
    Vec<(&'static str, &'static str)>,
);

fn vhosts(
    top: &Members<'_>,
    services: &[(&'static str, Service<'static>)],
) -> Result<Vhosts, PolicyError> {
    let Some(all) = top.object("vhosts")? else {
        return Ok((Vec::new(), Vec::new()));
    };
    let known: Vec<String> = services.iter().map(|(n, _)| (*n).to_owned()).collect();
    let mut out = Vec::new();
    let mut logs = Vec::new();
    for (name, v) in all.members {
        let m = Members::of(all.path(name), v)?;
        m.only(&["routes", "headers", "not-found", "access-log"])?;
        if let Some(path) = m.string("access-log")? {
            logs.push((keep(name), keep(path)));
        }
        let mut routes = Vec::new();
        for (i, r) in m.array("routes")?.unwrap_or_default().iter().enumerate() {
            let rm = Members::of(format!("{}[{i}]", m.path("routes")), r)?;
            rm.only(&["path", "to", "exact", "ws", "headers"])?;
            let to = rm.required("to")?;
            if !known.iter().any(|k| k == to) {
                return Err(PolicyError::NoSuch {
                    at: rm.path("to"),
                    name: to.to_owned(),
                    known: known.clone(),
                });
            }
            let ws = match rm.object("ws")? {
                None => Ws::NotTaken,
                Some(w) => {
                    w.only(&["protocols", "default", "binary", "deflate"])?;
                    let protocols: Vec<&'static [u8]> = w
                        .strings("protocols")?
                        .ok_or_else(|| PolicyError::Missing(w.path("protocols")))?
                        .iter()
                        .map(|p| keep_bytes(p))
                        .collect();
                    let default = match w.string("default")? {
                        None => None,
                        Some(d) => Some(
                            protocols
                                .iter()
                                .position(|p| *p == d.as_bytes())
                                .ok_or_else(|| PolicyError::NoSuch {
                                    at: w.path("default"),
                                    name: d.to_owned(),
                                    known: protocols
                                        .iter()
                                        .map(|p| String::from_utf8_lossy(p).into_owned())
                                        .collect(),
                                })?,
                        ),
                    };
                    Ws::Taken(WsServer {
                        protocols: Vec::leak(protocols),
                        default,
                        payload: if w.bool("binary")? == Some(true) {
                            Payload::Binary
                        } else {
                            Payload::Text
                        },
                        deflate: if w.bool("deflate")? == Some(true) {
                            Deflate::Offered
                        } else {
                            Deflate::Off
                        },
                    })
                }
            };
            routes.push(Route {
                path: keep(rm.required("path")?),
                matching: if rm.bool("exact")? == Some(true) {
                    Match::Exact
                } else {
                    Match::Prefix
                },
                to: keep(to),
                ws,
                headers: keep_headers(&rm.pairs("headers")?),
            });
        }
        out.push((
            keep(name),
            Vhost {
                name: keep(name),
                routes: Vec::leak(routes),
                headers: keep_headers(&m.pairs("headers")?),
                not_found: m.string("not-found")?.map(keep),
            },
        ));
    }
    Ok((out, logs))
}

fn listeners(
    top: &Members<'_>,
    vhosts: &[(&'static str, Vhost<'static>)],
) -> Result<Vec<Listener<'static>>, PolicyError> {
    let Some(all) = top.object("listeners")? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (name, v) in all.members {
        let m = Members::of(all.path(name), v)?;
        m.only(&["bind", "tls", "vhosts"])?;
        let tls = match m.object("tls")? {
            None => Tls::Plain,
            Some(t) => {
                t.only(&["cert", "key"])?;
                Tls::Server {
                    cert: keep(t.required("cert")?),
                    key: keep(t.required("key")?),
                }
            }
        };
        let mut served = Vec::new();
        for (i, want) in m.strings("vhosts")?.unwrap_or_default().iter().enumerate() {
            match vhosts.iter().find(|(n, _)| n == want) {
                Some((_, vh)) => served.push(*vh),
                None => {
                    return Err(PolicyError::NoSuch {
                        at: format!("{}[{i}]", m.path("vhosts")),
                        name: (*want).to_owned(),
                        known: vhosts.iter().map(|(n, _)| (*n).to_owned()).collect(),
                    });
                }
            }
        }
        if served.is_empty() {
            return Err(PolicyError::Missing(m.path("vhosts")));
        }
        out.push(Listener {
            name: keep(name),
            bind: keep(m.required("bind")?),
            tls,
            h1: H1Config::default(),
            vhosts: Vec::leak(served),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_is_read_into_a_value_and_a_member_twice_is_refused() {
        let v = parse("t", br#"{"a": [1, "x", true, null], "b": {"c": 2}}"#).unwrap();
        assert_eq!(
            v,
            Value::Object(vec![
                (
                    "a".into(),
                    Value::Array(vec![
                        Value::Number("1".into()),
                        Value::String("x".into()),
                        Value::Bool(true),
                        Value::Null
                    ])
                ),
                (
                    "b".into(),
                    Value::Object(vec![("c".into(), Value::Number("2".into()))])
                ),
            ])
        );
        assert!(matches!(
            parse("t", br#"{"a": 1, "a": 2}"#),
            Err(PolicyError::Json { .. })
        ));
        assert!(matches!(parse("t", b"{"), Err(PolicyError::Json { .. })));
    }

    #[test]
    fn higher_layers_merge_objects_and_replace_the_rest() {
        let low = parse("l", br#"{"npro": {"slots": 64, "workers": 2}, "a": [1]}"#).unwrap();
        let high = parse("h", br#"{"npro": {"slots": 8}, "a": [2, 3], "b": true}"#).unwrap();
        let m = merge(low, high);
        assert_eq!(
            m,
            parse(
                "m",
                br#"{"npro": {"slots": 8, "workers": 2}, "a": [2, 3], "b": true}"#
            )
            .unwrap()
        );
    }

    #[test]
    fn a_fragment_is_an_object_or_a_dotted_path() {
        assert_eq!(
            fragment("npro.slots=8").unwrap(),
            parse("f", br#"{"npro": {"slots": 8}}"#).unwrap()
        );
        assert_eq!(
            fragment("a.b=hello").unwrap(),
            parse("f", br#"{"a": {"b": "hello"}}"#).unwrap()
        );
        assert_eq!(
            fragment(r#"{"a": 1}"#).unwrap(),
            parse("f", br#"{"a": 1}"#).unwrap()
        );
        assert!(matches!(fragment("[1]"), Err(PolicyError::Fragment(_))));
        assert!(matches!(fragment("novalue"), Err(PolicyError::Fragment(_))));
        assert!(matches!(fragment("a..b=1"), Err(PolicyError::Fragment(_))));
    }

    const FULL: &str = r#"{
        "listeners": { "l": { "bind": "unix:/tmp/x", "vhosts": ["v"] } },
        "vhosts": { "v": { "not-found": "/404.html", "headers": {"x-a": "1"},
                           "access-log": "/var/log/v.log",
                           "routes": [ { "path": "/", "to": "www" },
                                       { "path": "/up", "to": "up", "exact": true },
                                       { "path": "/go", "to": "go" },
                                       { "path": "/chat", "to": "www",
                                         "ws": { "protocols": ["a", "b"], "default": "b", "binary": true } } ] } },
        "services": { "www": { "type": "files", "root": "/srv", "cache": { "max-age": 10, "public": true },
                               "mimes": { ".tar.gz": "application/x-gtar" } },
                      "up": { "type": "proxy", "address": "unix:/tmp/o", "path": "/o" },
                      "go": { "type": "redirect", "to": "https://x", "append-path": true },
                      "cgi": { "type": "cgi", "exec": "/usr/bin/env", "env": { "A": "1" }, "timeout": 5 } },
        "npro": { "slots": 4 }
    }"#;

    #[test]
    fn the_policys_types_are_made_from_the_layers() {
        let p = policy(&parse("t", FULL.as_bytes()).unwrap()).unwrap();
        assert_eq!((p.slots, p.workers), (4, 2));
        assert_eq!(p.listeners.len(), 1);
        let l = &p.listeners[0];
        assert_eq!((l.name, l.bind, l.tls), ("l", "unix:/tmp/x", Tls::Plain));
        let v = &l.vhosts[0];
        assert_eq!((v.name, v.not_found), ("v", Some("/404.html")));
        assert_eq!(p.logs, &[("v", "/var/log/v.log")]);
        assert_eq!(v.headers, &[(&b"x-a"[..], &b"1"[..])]);
        assert_eq!(v.routes.len(), 4);
        assert_eq!(v.routes[1].matching, Match::Exact);
        let Ws::Taken(w) = v.routes[3].ws else {
            panic!("ws not taken");
        };
        assert_eq!(
            (w.default, w.payload, w.deflate),
            (Some(1), Payload::Binary, Deflate::Off)
        );
        assert_eq!(p.services.by_name.len(), 4);
        assert_eq!(
            p.services.by_name[3].1,
            Service::Cgi(Script {
                exec: "/usr/bin/env",
                env: &[("A", "1")],
                dir: None,
                timeout: Duration::from_secs(5),
            })
        );
        assert!(matches!(
            p.services.by_name[0].1,
            Service::Files(Mount {
                root: "/srv",
                default: "index.html",
                cache: Cache::For {
                    max_age: 10,
                    revalidate: Revalidate::NotNeeded,
                    intermediaries: Intermediaries::Public
                },
                ..
            })
        ));
        assert!(matches!(
            p.services.by_name[2].1,
            Service::Redirect(Redirect {
                to: "https://x",
                append: Append::Path
            })
        ));
    }

    #[test]
    fn what_is_wrong_is_said_with_its_path() {
        let bad = |text: &str| {
            policy(&parse("t", text.as_bytes()).unwrap())
                .unwrap_err()
                .to_string()
        };
        assert_eq!(
            bad(r#"{"listeners": {"l": {"bind": "x", "vhosts": ["nope"]}}}"#),
            "listeners.l.vhosts[0]: no \"nope\"; there is "
        );
        assert_eq!(
            bad(r#"{"vhosts": {"v": {"routes": [{"path": "/", "to": "none"}]}}}"#),
            "vhosts.v.routes[0].to: no \"none\"; there is "
        );
        assert_eq!(
            bad(r#"{"services": {"s": {"type": "php"}}}"#),
            "services.s.type: no \"php\"; there is files, proxy, redirect, cgi"
        );
        assert_eq!(
            bad(r#"{"services": {"s": {"type": "files"}}}"#),
            "services.s.root: required, and not given"
        );
        assert_eq!(
            bad(r#"{"services": {"s": {"type": "files", "root": "/", "owner": 1}}}"#),
            "services.s.owner: nothing is declared under that name"
        );
        assert_eq!(
            bad(r#"{"npro": {"slots": "many"}}"#),
            "npro.slots: expected a number"
        );
        assert_eq!(
            bad(r#"{"listeners": {"l": {"bind": "x"}}}"#),
            "listeners.l.vhosts: required, and not given"
        );
    }
}
