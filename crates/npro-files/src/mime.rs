//! A file's media type, from its name's suffix: C's `lws_get_mimetype()`.

/// What C's server knows: `server_mimetypes[]`, in its order.
const BUILT_IN: [(&str, &str); 21] = [
    (".html", "text/html"),
    (".htm", "text/html"),
    (".js", "text/javascript"),
    (".css", "text/css"),
    (".png", "image/png"),
    (".jpg", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".ico", "image/x-icon"),
    (".gif", "image/gif"),
    (".svg", "image/svg+xml"),
    (".ttf", "application/x-font-ttf"),
    (".otf", "application/font-woff"),
    (".woff", "application/font-woff"),
    (".woff2", "application/font-woff2"),
    (".gz", "application/gzip"),
    (".txt", "text/plain"),
    (".xml", "application/xml"),
    (".json", "application/json"),
    (".babylon", "application/json"),
    (".mjs", "text/javascript"),
    (".wasm", "application/wasm"),
];

/// Whether `name` ends with `suffix`, any case, with something before it.
fn ends_with(name: &[u8], suffix: &str) -> bool {
    name.len() > suffix.len()
        && name
            .get(name.len().saturating_sub(suffix.len())..)
            .is_some_and(|end| end.eq_ignore_ascii_case(suffix.as_bytes()))
}

/// The media type of the file `name`, by its suffix: the first of
/// `extra` (the mount's own, each `(suffix, type)`) that matches, in
/// order; else C's own table; else `extra`'s `*` entry, if it has one,
/// which matches anything.  `None` is not served: C answers 415.  As C,
/// `.tar.gz` in `extra` is found before C's `.gz`, since `extra` goes
/// first.
///
/// ```
/// use npro_files::mime::of;
///
/// assert_eq!(of(b"a/index.html", &[]), Some("text/html"));
/// assert_eq!(of(b"a/x.tar.gz", &[(".tar.gz", "application/x-gtar")]), Some("application/x-gtar"));
/// assert_eq!(of(b"a/x.gz", &[(".tar.gz", "application/x-gtar")]), Some("application/gzip"));
/// assert_eq!(of(b"README.md", &[]), None);
/// assert_eq!(of(b"README.md", &[("*", "application/octet-stream")]), Some("application/octet-stream"));
/// ```
#[must_use]
pub fn of<'p>(name: &[u8], extra: &[(&'p str, &'p str)]) -> Option<&'p str> {
    let mut fallback = None;
    for (suffix, t) in extra {
        if *suffix == "*" {
            if fallback.is_none() {
                fallback = Some(*t);
            }
            continue;
        }
        if ends_with(name, suffix) {
            return Some(t);
        }
    }
    BUILT_IN
        .iter()
        .find(|(suffix, _)| ends_with(name, suffix))
        .map(|(_, t)| *t)
        .or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_suffix_is_matched_any_case_with_a_name_before_it() {
        assert_eq!(of(b"A.HTML", &[]), Some("text/html"));
        assert_eq!(of(b".html", &[]), None);
        assert_eq!(of(b"x.woff2", &[]), Some("application/font-woff2"));
        assert_eq!(of(b"", &[]), None);
        assert_eq!(of(b"x.md", &[("*", "a"), ("*", "b")]), Some("a"));
    }
}
