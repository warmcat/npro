//! The file's path under the mount's root, composed into storage of a
//! declared size, and what is refused on the way: C's `lws_http_serve()`
//! before it opens anything.

/// The longest path a file may have, the mount's root included: C's
/// `char path[1024]`.
pub const MAX_PATH: usize = 1024;

/// A path composed under the root.
#[derive(Clone, Copy, Debug)]
pub struct Path {
    bytes: [u8; MAX_PATH],
    len: usize,
}

/// Why a path was not composed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// A component of the request's path is `..`, or it holds a `\`:
    /// an attempt to reach outside the mount, refused 403, as C refuses
    /// it.  The URI parser took `..` out already; this is the last stop
    /// before the path is opened under the root, and does not rely on
    /// that.  A `\` is a path separator to Windows and to nothing a
    /// mount serves.
    Outside,
    /// Root and request together are longer than [`MAX_PATH`]: 414.
    TooLong,
}

/// Whether `rest` has a whole component that is `..` (`...` and `..x`
/// are ordinary names), or a `\` anywhere: C's `lws_path_has_dotdot()`
/// and its backslash check.
fn reaches_outside(rest: &[u8]) -> bool {
    rest.contains(&b'\\') || rest.split(|c| *c == b'/').any(|seg| seg == b"..")
}

impl Path {
    /// `root/rest`, as C's `"%s/%s"`, without doubling the `/` between
    /// when `rest` is empty or `root` ends with one.
    ///
    /// # Errors
    ///
    /// [`PathError`]: `rest` reaches outside the root, or the path does
    /// not fit.
    pub fn compose(root: &str, rest: &[u8]) -> Result<Self, PathError> {
        if reaches_outside(rest) {
            return Err(PathError::Outside);
        }
        let mut p = Self {
            bytes: [0; MAX_PATH],
            len: 0,
        };
        p.push(root.as_bytes())?;
        if !rest.is_empty() {
            if !root.ends_with('/') {
                p.push(b"/")?;
            }
            p.push(rest)?;
        }
        Ok(p)
    }

    /// Appends `/name` for the directory's default document, as C
    /// appends `m->def`.
    ///
    /// # Errors
    ///
    /// [`PathError::TooLong`].
    pub fn join(&mut self, name: &str) -> Result<(), PathError> {
        if !self.as_bytes().ends_with(b"/") {
            self.push(b"/")?;
        }
        self.push(name.as_bytes())
    }

    fn push(&mut self, more: &[u8]) -> Result<(), PathError> {
        let end = self
            .len
            .checked_add(more.len())
            .filter(|e| *e <= MAX_PATH)
            .ok_or(PathError::TooLong)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(PathError::TooLong)?
            .copy_from_slice(more);
        self.len = end;
        Ok(())
    }

    /// The path, as the runner's file system opens it.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_is_root_slash_rest_with_one_slash_between() {
        let p = |root, rest| Path::compose(root, rest).map(|p| p.as_bytes().to_vec());
        assert_eq!(
            p("/var/www", b"a/b.html"),
            Ok(b"/var/www/a/b.html".to_vec())
        );
        assert_eq!(p("/var/www/", b"a"), Ok(b"/var/www/a".to_vec()));
        assert_eq!(p("/var/www", b""), Ok(b"/var/www".to_vec()));
        let mut d = Path::compose("/var/www", b"d").unwrap();
        d.join("index.html").unwrap();
        assert_eq!(d.as_bytes(), b"/var/www/d/index.html");
        let mut r = Path::compose("/var/www/", b"").unwrap();
        r.join("index.html").unwrap();
        assert_eq!(r.as_bytes(), b"/var/www/index.html");
    }

    #[test]
    fn a_dotdot_component_or_a_backslash_is_outside_and_too_long_is_refused() {
        for rest in [&b".."[..], b"../x", b"a/../x", b"a/..", b"a\\..\\x", b"x\\"] {
            assert_eq!(
                Path::compose("/r", rest).err(),
                Some(PathError::Outside),
                "{}",
                rest.escape_ascii()
            );
        }
        for rest in [&b"..."[..], b"..x", b"a/...", b"x.."] {
            assert!(Path::compose("/r", rest).is_ok(), "{}", rest.escape_ascii());
        }
        let long = [b'a'; MAX_PATH];
        assert_eq!(Path::compose("/r", &long).err(), Some(PathError::TooLong));
        let mut just = Path::compose("/r", &long[..MAX_PATH - 3]).unwrap();
        assert_eq!(just.as_bytes().len(), MAX_PATH);
        assert_eq!(just.join("x"), Err(PathError::TooLong));
    }
}
