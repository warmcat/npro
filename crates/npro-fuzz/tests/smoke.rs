//! Every fuzz target, run over its seeds and over inputs drawn from a fixed
//! seed, so the harnesses and what they check stay working on every
//! platform without a fuzzer.  This is a smoke test, not a campaign: that
//! is `scripts/fuzz.sh`.  A failure here reproduces exactly, since the
//! inputs are the same every run.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one drives npro-test only through npro-fuzz"
)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use npro_core::random::SeededRandom;
use npro_fuzz::Target;

/// Inputs drawn per target.  Miri interprets the tests, thousands of times
/// slower, so it gets a taste of each.
const DRAWN: usize = if cfg!(miri) { 24 } else { 4000 };

/// The longest drawn input.
const MAX_LEN: u64 = 300;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The directories `scripts/fuzz.sh` gives libFuzzer as seeds for `t`.
fn seed_dirs(t: Target) -> Vec<PathBuf> {
    let mut dirs = vec![repo().join("fuzz/seeds").join(t.name())];
    if t == Target::Transcript {
        dirs.push(repo().join("crates/npro-test/transcripts"));
    }
    dirs
}

/// The seed files in `dir`, sorted, leaving out its README.
fn seed_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<io::Result<Vec<_>>>()?;
    paths.retain(|p| p.is_file() && p.extension().is_none_or(|x| x != "md"));
    paths.sort();
    Ok(paths)
}

/// A number below `n`, or 0 if `n` is.
fn below(r: &mut SeededRandom, n: u64) -> u64 {
    r.next_u64().checked_rem(n).unwrap_or(0)
}

/// An index below `n`, or 0 if `n` is.
fn index_below(r: &mut SeededRandom, n: usize) -> usize {
    let n = u64::try_from(n).unwrap_or(u64::MAX);
    usize::try_from(below(r, n)).unwrap_or(0)
}

const fn byte(r: &mut SeededRandom) -> u8 {
    let [b, ..] = r.next_u64().to_le_bytes();
    b
}

fn bytes(r: &mut SeededRandom) -> Vec<u8> {
    let n = below(r, MAX_LEN.saturating_add(1));
    (0..n).map(|_| byte(r)).collect()
}

/// Text: random bytes are almost never UTF-8, so draw characters from
/// every length of encoding, then sometimes break it the ways a peer
/// might: a changed byte, a lost byte, or the end cut off.
fn text(r: &mut SeededRandom) -> Vec<u8> {
    let mut t = String::new();
    for _ in 0..below(r, 60) {
        // the first code point needing 1, 2, 3 and 4 bytes past the top
        let top = match below(r, 4) {
            0 => 0x80,
            1 => 0x800,
            2 => 0x1_0000,
            _ => 0x11_0000,
        };
        if let Some(c) = u32::try_from(below(r, top)).ok().and_then(char::from_u32) {
            t.push(c);
        }
    }
    let mut t = t.into_bytes();
    let at = index_below(r, t.len());
    match below(r, 4) {
        0 => {
            let b = byte(r);
            if let Some(x) = t.get_mut(at) {
                *x = b;
            }
        }
        1 if at < t.len() => {
            t.remove(at);
        }
        2 => t.truncate(at),
        _ => {}
    }
    t
}

/// A seed with a few bytes changed, inserted or removed.
fn mutated(r: &mut SeededRandom, seed: &[u8]) -> Vec<u8> {
    let mut m = seed.to_vec();
    for _ in 0..=below(r, 4) {
        let at = index_below(r, m.len().saturating_add(1));
        match below(r, 3) {
            0 => {
                let b = byte(r);
                if let Some(x) = m.get_mut(at) {
                    *x = b;
                }
            }
            1 => m.insert(at, byte(r)),
            _ if at < m.len() => {
                m.remove(at);
            }
            _ => {}
        }
    }
    m
}

/// Runs `t` over its seeds, then over `DRAWN` inputs from `draw`.
fn smoke(
    t: Target,
    mut draw: impl FnMut(&mut SeededRandom, &[Vec<u8>]) -> Vec<u8>,
) -> io::Result<()> {
    let mut seeds = Vec::new();
    for dir in seed_dirs(t) {
        let files = seed_files(&dir)?;
        if files.is_empty() {
            return Err(io::Error::other(format!("no seeds in {}", dir.display())));
        }
        for f in files {
            seeds.push(fs::read(&f)?);
        }
    }
    for s in &seeds {
        t.run(s);
    }
    let mut r = SeededRandom::new(1);
    for _ in 0..DRAWN {
        t.run(&draw(&mut r, &seeds));
    }
    Ok(())
}

/// A drawn input: the first byte is the target's choice of split, then
/// the bytes under test.
fn split_then(r: &mut SeededRandom, body: Vec<u8>) -> Vec<u8> {
    let mut v = vec![byte(r)];
    v.extend(body);
    v
}

#[test]
fn utf8() {
    smoke(Target::Utf8, |r, _| {
        let body = text(r);
        split_then(r, body)
    })
    .unwrap();
}

#[test]
fn sha1() {
    smoke(Target::Sha1, |r, _| {
        let body = bytes(r);
        split_then(r, body)
    })
    .unwrap();
}

#[test]
fn base64() {
    smoke(Target::Base64, |r, _| bytes(r)).unwrap();
}

#[test]
#[cfg_attr(
    miri,
    ignore = "hundreds of kilobytes of transcripts: native runs keep it"
)]
fn transcript() {
    smoke(Target::Transcript, |r, seeds| {
        let seed = seeds
            .get(index_below(r, seeds.len()))
            .map_or(&[][..], Vec::as_slice);
        mutated(r, seed)
    })
    .unwrap();
}

/// A seed, sometimes changed, after a split byte which may also choose the
/// target's configuration.
fn seeded(r: &mut SeededRandom, seeds: &[Vec<u8>]) -> Vec<u8> {
    let seed = seeds
        .get(index_below(r, seeds.len()))
        .map_or(&[][..], Vec::as_slice);
    // past the seed's own control byte
    let body = seed.get(1..).unwrap_or_default();
    let body = if below(r, 4) == 0 {
        body.to_vec()
    } else {
        mutated(r, body)
    };
    split_then(r, body)
}

#[test]
fn h1_request() {
    smoke(Target::H1Request, seeded).unwrap();
}

#[test]
fn h1_response() {
    smoke(Target::H1Response, seeded).unwrap();
}

#[test]
fn chunked() {
    smoke(Target::Chunked, seeded).unwrap();
}

#[test]
fn ws_server() {
    smoke(Target::WsServer, seeded).unwrap();
}

#[test]
fn every_target_has_a_smoke_test() {
    // the tests above, by name: a new target needs its own
    let tested = [
        "utf8",
        "sha1",
        "base64",
        "transcript",
        "h1-request",
        "h1-response",
        "chunked",
        "ws-server",
    ];
    assert_eq!(Target::ALL.map(Target::name), tested);
}
