//! Every data file the tests and the fuzzers read can be checked out
//! everywhere npro is built, Windows included: no name Windows reserves for
//! a device (`nul.http` is NUL, whatever follows the dot), no character it
//! refuses, no name ending in a space or a dot.  git on Windows refuses to
//! check out a tree with one, so a builder never gets as far as a test.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses none"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod names {
    use std::fs;
    use std::path::{Path, PathBuf};

    /// The directories of files whose names come from what they hold.
    const DIRS: [&str; 5] = [
        "crates/npro-test/h1",
        "crates/npro-test/states",
        "crates/npro-test/transcripts",
        "fuzz/seeds",
        "fuzz/fuzz_targets",
    ];

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// Why Windows cannot have `name`, if it cannot.
    fn not_on_windows(name: &str) -> Option<&'static str> {
        let stem = name.split('.').next().unwrap_or(name).to_ascii_lowercase();
        let device = matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
            || ["com", "lpt"].iter().any(|d| {
                stem.strip_prefix(d)
                    .is_some_and(|n| n.len() == 1 && n.as_bytes()[0].is_ascii_digit())
            });
        if device {
            return Some("a device's name");
        }
        if name
            .chars()
            .any(|c| c < ' ' || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
        {
            return Some("a character Windows refuses");
        }
        if name.ends_with(' ') || name.ends_with('.') {
            return Some("ending in a space or a dot");
        }
        None
    }

    fn walk(dir: &Path, bad: &mut Vec<String>, seen: &mut usize) {
        for e in fs::read_dir(dir).unwrap() {
            let path = e.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            *seen = seen.checked_add(1).unwrap();
            if let Some(why) = not_on_windows(&name) {
                bad.push(format!("{}: {why}", path.display()));
            }
            if path.is_dir() {
                walk(&path, bad, seen);
            }
        }
    }

    #[test]
    fn the_rule_knows_windows_names() {
        for name in [
            "nul.http",
            "NUL",
            "con.txt",
            "Com1.json",
            "lpt9",
            "a?b",
            "a.",
        ] {
            assert!(not_on_windows(name).is_some(), "{name}");
        }
        for name in [
            "nul-in-value.http",
            "console.txt",
            "com10",
            "a.b",
            "headers-nul.http",
        ] {
            assert_eq!(not_on_windows(name), None, "{name}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "walks the tree: native runs keep it")]
    fn every_data_file_can_be_checked_out_on_windows() {
        let (mut bad, mut seen) = (Vec::new(), 0usize);
        for d in DIRS {
            walk(&repo().join(d), &mut bad, &mut seen);
        }
        assert!(seen > 100, "{seen} files");
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }
}
