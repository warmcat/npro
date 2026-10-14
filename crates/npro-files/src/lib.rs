//! npro-files: a directory served under a route, sans-IO.
//!
//! C's file serving (`lws_http_serve()`, `lws_serve_http_file()` and
//! `lws_http_file_tx()`), as a service for npro-ss' server streams: a
//! request on a route whose `to` names a [`Mount`] is answered from the
//! files under the mount's root, by [`serve`].  Opening the file is the
//! runner's, through [`Fs`], on the application's turn, as C opens it;
//! reading it is off the turn, a chunk at a time, through
//! [`serving::Serving`], as C's async queue takes the file server's reads
//! off the service thread.  So a romfs, or a test's tree in memory,
//! serves as a disk does.
//!
//! What C does that this does too: the default document for a directory;
//! the redirect to add the `/` a directory was asked for without; the
//! media type from the suffix, the mount's own first, and 415 for one
//! unknown; `cache-control` as the mount says; the `ETag` from the length
//! and the time, and 304 for a matching `if-none-match`; a HEAD answered
//! with the head alone; 403 for a path reaching outside the mount; and
//! the vhost's 404 document, by [`npro_ss::event::Txn::status`].
//!
//! Not yet: precompressed (`gzip://`) variants, byte ranges, interpreted
//! files, basic auth, and C's on-the-fly compression.
//!
//! ```
//! use npro_files::{Cache, Fs, Mount, Opened, Scheme, Served, serve};
//! use npro_ss::event::Txn;
//!
//! /// A tree with one file.
//! struct One;
//! impl Fs for One {
//!     type File = &'static [u8];
//!     fn open(&mut self, path: &[u8]) -> Option<Opened<&'static [u8]>> {
//!         (path == b"/www/index.html").then_some(Opened::File {
//!             file: b"<html>",
//!             len: 6,
//!             modified: 1_700_000_000,
//!         })
//!     }
//! }
//!
//! const WWW: Mount<'static> = Mount {
//!     root: "/www",
//!     default: "index.html",
//!     cache: Cache::NoStore,
//!     mimes: &[],
//! };
//!
//! /// Answers a request on the `www` route from the tree; the runner
//! /// reads the file's chunks into `&'static [u8]`s here.
//! fn answer<S: AsRef<[u8]> + AsMut<[u8]>>(
//!     txn: &mut Txn<'_, S>,
//! ) -> Served<&'static [u8], &'static [u8]> {
//!     serve(&WWW, txn, &mut One, Scheme::Https).unwrap_or(Served::Answered)
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]
// the integration tests' dependencies, which a lib test sees too
#![cfg_attr(
    test,
    expect(
        unused_crate_dependencies,
        reason = "npro-core, npro-h1 and npro-io are tests/serve.rs's, which the lib's own tests do not use"
    )
)]

pub mod mime;
pub mod path;
pub mod serving;

use npro_ss::event::{RespondError, Response, Txn};

pub use path::{MAX_PATH, Path, PathError};
pub use serving::{CHUNK, Read, Serving};

/// A mount: a directory served under a route.  C's `file://` mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mount<'p> {
    /// The directory: C's `origin`.
    pub root: &'p str,
    /// The document a directory is answered with: C's `default`,
    /// `index.html`.
    pub default: &'p str,
    /// What `cache-control` says.
    pub cache: Cache,
    /// The mount's own media types, `(suffix, type)`, before C's table:
    /// C's `extra-mimetypes`.  A suffix of `*` is the type for a file
    /// with no other.
    pub mimes: &'p [(&'p str, &'p str)],
}

/// What a mount's responses say in `cache-control`: C's `cache-*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cache {
    /// Nothing said: `no-store`, as C says when no caching is set.
    NoStore,
    /// `no-cache`: C's `cache-no`.
    NoCache,
    /// May be kept this long: C's `cache-max-age` with `cache-reuse`.
    For {
        /// Seconds.
        max_age: u32,
        /// C's `cache-revalidate`.
        revalidate: Revalidate,
        /// C's `cache-intermediaries`.
        intermediaries: Intermediaries,
    },
}

/// Whether a kept copy must be checked before use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revalidate {
    /// It need not: no `must-revalidate`.
    NotNeeded,
    /// It must.
    Must,
}

/// Who may keep a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intermediaries {
    /// The client alone: `private`.
    Private,
    /// Anyone on the way: `public`.
    Public,
}

/// What a file system has at a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened<F> {
    /// A file, open for reading.
    File {
        /// The runner's handle to it, read on the runner's threads.
        file: F,
        /// How long it is.
        len: u64,
        /// When it was last changed, in seconds, for the `ETag`: C's
        /// `st_mtime` as `uint32_t`.
        modified: u32,
    },
    /// A directory.
    Dir,
}

/// The runner's file system: C's `lws_plat_file_ops`, as far as opening
/// goes.  A symbolic link is followed, as C follows it.
pub trait Fs {
    /// An open file, read by the runner where it chooses.
    type File;

    /// What is at `path`, or `None` for nothing that can be served: not
    /// there, not readable, or neither a file nor a directory.
    fn open(&mut self, path: &[u8]) -> Option<Opened<Self::File>>;
}

/// The scheme the listener's connections came by, for the redirect that
/// adds a directory's `/`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `http://`.
    Http,
    /// `https://`.
    Https,
}

/// What serving a request came to.  `C` is what the runner reads a chunk
/// into.
#[derive(Debug)]
pub enum Served<F, C> {
    /// The request is answered, and nothing more goes: a redirect, a
    /// status page, a 304, a HEAD's or an empty file's head.  The stream
    /// still asks to write, and gives [`npro_ss::event::Filled::Last`]
    /// of 0 when asked, as C's EOM ends every answer.
    Answered,
    /// The file's bytes go: from [`Serving`], as the stream is asked.
    Body(Serving<F, C>),
}

/// The `ETag`'s storage: C's `"%08llX%08lX"` of the length and the time,
/// up to 16 digits of the length.
type Tag = [u8; 24];

/// `v` in uppercase hex, at least `width` digits, from `at` in `out`:
/// where it ends.
fn hex(v: u64, width: usize, out: &mut [u8], at: usize) -> usize {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut digits = [0u8; 16];
    let mut n = 0;
    let mut rest = v;
    loop {
        let nibble = usize::try_from(rest & 0xf).unwrap_or(0);
        if let Some(d) = digits.get_mut(n) {
            *d = HEX.get(nibble).copied().unwrap_or(b'0');
        }
        n = n.saturating_add(1);
        rest >>= 4;
        if rest == 0 || n >= digits.len() {
            break;
        }
    }
    let mut end = at;
    let pad = width.saturating_sub(n);
    for _ in 0..pad {
        if let Some(b) = out.get_mut(end) {
            *b = b'0';
        }
        end = end.saturating_add(1);
    }
    for i in (0..n).rev() {
        if let (Some(b), Some(d)) = (out.get_mut(end), digits.get(i)) {
            *b = *d;
        }
        end = end.saturating_add(1);
    }
    end
}

/// The `ETag` of a file `len` long, changed at `modified`: how much of
/// `out` it is.
fn etag(len: u64, modified: u32, out: &mut Tag) -> usize {
    let end = hex(len, 8, out, 0);
    hex(u64::from(modified), 8, out, end)
}

/// `cache-control`'s value for a 200, as C composes it.
fn cache_control(cache: Cache, out: &mut [u8; 48]) -> usize {
    let mut n = 0usize;
    let mut push = |s: &[u8]| {
        if let Some(to) = out.get_mut(n..n.saturating_add(s.len())) {
            to.copy_from_slice(s);
            n = n.saturating_add(s.len());
        }
    };
    match cache {
        Cache::NoStore => push(b"no-store"),
        Cache::NoCache => push(b"no-cache"),
        Cache::For {
            max_age,
            revalidate,
            intermediaries,
        } => {
            if revalidate == Revalidate::Must {
                push(b"must-revalidate, ");
            }
            push(match intermediaries {
                Intermediaries::Private => b"private",
                Intermediaries::Public => b"public",
            });
            push(b", max-age=");
            let mut d = [0u8; 10];
            push(decimal(max_age, &mut d));
        }
    }
    n
}

/// `cache-control` for a 304: C has no `no-cache` there, only the
/// max-age rule or `no-store`.
fn cache_control_304(cache: Cache, out: &mut [u8; 48]) -> usize {
    match cache {
        Cache::NoStore | Cache::NoCache => cache_control(Cache::NoStore, out),
        Cache::For { .. } => cache_control(cache, out),
    }
}

/// `n` in decimal.
fn decimal(n: u32, out: &mut [u8; 10]) -> &[u8] {
    let mut v = n;
    let mut i = out.len();
    loop {
        i = i.saturating_sub(1);
        if let Some(b) = out.get_mut(i) {
            *b = b'0'.saturating_add(u8::try_from(v % 10).unwrap_or(0));
        }
        v /= 10;
        if v == 0 || i == 0 {
            break;
        }
    }
    out.get(i..).unwrap_or_default()
}

/// The file's name: the path's last component.
fn name_of(path: &Path) -> &[u8] {
    let bytes = path.as_bytes();
    bytes
        .iter()
        .rposition(|c| *c == b'/')
        .and_then(|i| bytes.get(i.saturating_add(1)..))
        .unwrap_or(bytes)
}

/// Bytes copied out of the request, so the request can be answered while
/// they are in hand.
struct Copied {
    bytes: [u8; MAX_PATH],
    len: usize,
}

impl Copied {
    /// `bytes`, or `None` if they do not fit.
    fn of(bytes: &[u8]) -> Option<Self> {
        let mut c = Self {
            bytes: [0; MAX_PATH],
            len: bytes.len(),
        };
        c.bytes.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(c)
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

/// What of the request decides how it is served, copied out of it.
struct Asked {
    /// The route is `/`.
    at_root: bool,
    rest: Copied,
    path: Copied,
}

/// Answers the request in hand from `mount`, as C's `lws_http_serve()`
/// does: see the module's description.  `fs` opens the file, on this
/// turn; `scheme` is the listener's, for the redirect that adds a
/// directory's `/`.  The request must be on a route ([`Txn::route`]):
/// with none it is answered 404.
///
/// # Errors
///
/// [`RespondError`], as the answer was refused: the request is still
/// unanswered.
pub fn serve<S, F, C>(
    mount: &Mount<'_>,
    txn: &mut Txn<'_, S>,
    fs: &mut F,
    scheme: Scheme,
) -> Result<Served<F::File, C>, RespondError>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
    F: Fs,
    C: AsRef<[u8]>,
{
    let asked = txn.route().map(|r| {
        (
            r.route.path == "/",
            Copied::of(r.rest),
            Copied::of(txn.path().unwrap_or_default()),
        )
    });
    let asked = match asked {
        None => {
            txn.status(404)?;
            return Ok(Served::Answered);
        }
        Some((at_root, Some(rest), Some(path))) => Asked {
            at_root,
            rest,
            path,
        },
        Some((_, None, _) | (_, _, None)) => {
            txn.status(414)?;
            return Ok(Served::Answered);
        }
    };
    // a directory asked for without its /: the browser would take
    // relative urls in it as one level up, so C redirects to add it
    if !asked.at_root && asked.rest.len == 0 && !asked.path.as_bytes().ends_with(b"/") {
        return redirect_with_slash(txn, scheme, asked.path.as_bytes());
    }
    let mut file_path = match Path::compose(mount.root, asked.rest.as_bytes()) {
        Ok(p) => p,
        Err(PathError::Outside) => {
            txn.status(403)?;
            return Ok(Served::Answered);
        }
        Err(PathError::TooLong) => {
            txn.status(414)?;
            return Ok(Served::Answered);
        }
    };
    let mut opened = fs.open(file_path.as_bytes());
    if let Some(Opened::Dir) = opened {
        if file_path.join(mount.default).is_err() {
            txn.status(414)?;
            return Ok(Served::Answered);
        }
        opened = fs.open(file_path.as_bytes());
    }
    let Some(Opened::File {
        file,
        len,
        modified,
    }) = opened
    else {
        txn.status(404)?;
        return Ok(Served::Answered);
    };
    // decided before the conditional GET, so a guessed ETag cannot get a
    // 304 for a file that would be refused
    let Some(media) = mime::of(name_of(&file_path), mount.mimes) else {
        txn.status(415)?;
        return Ok(Served::Answered);
    };
    let mut tag: Tag = [0; 24];
    let tag_len = etag(len, modified, &mut tag);
    let tag = tag.get(..tag_len).unwrap_or_default();
    let mut cc = [0u8; 48];
    if txn.header(b"if-none-match") == Some(tag) {
        let n = cache_control_304(mount.cache, &mut cc);
        txn.respond(Response {
            status: 304,
            content_type: None,
            content_length: None,
            headers: &[
                (b"etag", tag),
                (b"cache-control", cc.get(..n).unwrap_or_default()),
            ],
        })?;
        return Ok(Served::Answered);
    }
    let n = cache_control(mount.cache, &mut cc);
    txn.respond(Response {
        status: 200,
        content_type: Some(media.as_bytes()),
        content_length: Some(len),
        headers: &[
            (b"cache-control", cc.get(..n).unwrap_or_default()),
            (b"etag", tag),
        ],
    })?;
    if len == 0 || txn.method() == Some(b"HEAD") {
        return Ok(Served::Answered);
    }
    Ok(Served::Body(Serving::new(file, len)))
}

/// 301 to the request's url with `/` on the end: C's
/// `lws_http_redirect_hit()`.  With no `Host` to make it from, 400.
fn redirect_with_slash<S, F, C>(
    txn: &mut Txn<'_, S>,
    scheme: Scheme,
    path: &[u8],
) -> Result<Served<F, C>, RespondError>
where
    S: AsRef<[u8]> + AsMut<[u8]>,
{
    let mut loc = [0u8; MAX_PATH];
    let mut n = 0usize;
    let fits = {
        let Some(host) = txn.header(b"host") else {
            txn.status(400)?;
            return Ok(Served::Answered);
        };
        let mut push = |s: &[u8]| -> bool {
            match loc.get_mut(n..n.saturating_add(s.len())) {
                Some(to) => {
                    to.copy_from_slice(s);
                    n = n.saturating_add(s.len());
                    true
                }
                None => false,
            }
        };
        push(match scheme {
            Scheme::Http => b"http://",
            Scheme::Https => b"https://",
        }) && push(host)
            && push(path)
            && push(b"/")
    };
    if !fits {
        txn.status(414)?;
        return Ok(Served::Answered);
    }
    txn.redirect(301, loc.get(..n).unwrap_or_default())?;
    Ok(Served::Answered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_etag_is_cs_hex_of_length_and_time() {
        let mut t: Tag = [0; 24];
        for (len, modified, want) in [
            (0x1234, 0xABCD_EF01, &b"00001234ABCDEF01"[..]),
            (0x1_0000_0000, 0, b"10000000000000000"),
            (0, 0, b"0000000000000000"),
            (u64::MAX, u32::MAX, b"FFFFFFFFFFFFFFFFFFFFFFFF"),
        ] {
            let n = etag(len, modified, &mut t);
            assert_eq!(&t[..n], want);
        }
    }

    #[test]
    fn cache_control_is_composed_as_c_composes_it() {
        let mut cc = [0u8; 48];
        for (cache, want) in [
            (Cache::NoStore, &b"no-store"[..]),
            (Cache::NoCache, b"no-cache"),
            (
                Cache::For {
                    max_age: 172_800,
                    revalidate: Revalidate::NotNeeded,
                    intermediaries: Intermediaries::Private,
                },
                b"private, max-age=172800",
            ),
            (
                Cache::For {
                    max_age: 0,
                    revalidate: Revalidate::Must,
                    intermediaries: Intermediaries::Public,
                },
                b"must-revalidate, public, max-age=0",
            ),
        ] {
            let n = cache_control(cache, &mut cc);
            assert_eq!(&cc[..n], want);
        }
        let n = cache_control_304(Cache::NoCache, &mut cc);
        assert_eq!(&cc[..n], b"no-store");
        let mut d = [0u8; 10];
        assert_eq!(decimal(u32::MAX, &mut d), b"4294967295");
        assert_eq!(decimal(0, &mut d), b"0");
    }
}
