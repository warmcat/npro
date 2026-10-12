//! The json target: npro-json's parser.

use core::fmt::Write as _;

use npro_json::{Config, Error, Event, Parser, Storage};

use crate::targets::{Pieces, control, finding};

const TARGET: &str = "json";

/// An event, owned, to compare runs by.
#[derive(Clone, Debug, PartialEq)]
enum Ev {
    ObjectStart,
    ObjectEnd,
    ArrayStart,
    ArrayEnd,
    Name(String),
    Str(String),
    Num(String),
    Bool(bool),
    Null,
}

impl From<Event<'_>> for Ev {
    fn from(e: Event<'_>) -> Self {
        match e {
            Event::ObjectStart => Self::ObjectStart,
            Event::ObjectEnd => Self::ObjectEnd,
            Event::ArrayStart => Self::ArrayStart,
            Event::ArrayEnd => Self::ArrayEnd,
            Event::Name(n) => Self::Name(n.to_owned()),
            Event::String(s) => Self::Str(s.to_owned()),
            Event::Number(n) => Self::Num(n.as_str().to_owned()),
            Event::Bool(b) => Self::Bool(b),
            Event::Null => Self::Null,
        }
    }
}

/// The storage and depth the control byte chooses: ample, or with its
/// top bit, small enough for the limits to be within reach.
const fn sizes(ctl: u8) -> (usize, usize, u8) {
    if ctl & 0x80 == 0 {
        (4096, 4096, npro_json::DEFAULT_DEPTH)
    } else {
        (24, 48, 4)
    }
}

fn parser(ctl: u8) -> Parser<Vec<u8>> {
    let (token, names, depth) = sizes(ctl);
    let config = Config::new()
        .with_depth(depth)
        .unwrap_or_else(|e| finding(TARGET, format_args!("depth {depth}: {e}")));
    Parser::new(
        Storage {
            token: vec![0u8; token],
            names: vec![0u8; names],
        },
        config,
    )
    .unwrap_or_else(|e| finding(TARGET, format_args!("storage: {e}")))
}

/// What a run came to: the events, and the verdict.
type Run = (Vec<Ev>, Result<(), Error>);

/// The document given in `pieces`, then its end.
fn run<'a>(ctl: u8, pieces: impl Iterator<Item = &'a [u8]>) -> Run {
    let mut p = parser(ctl);
    let mut seen = Vec::new();
    for piece in pieces {
        let mut input = piece;
        loop {
            let step = match p.next(input) {
                Ok(s) => s,
                Err(e) => return (seen, Err(e)),
            };
            if step.consumed > input.len() {
                finding(
                    TARGET,
                    format_args!("took {} of {}", step.consumed, input.len()),
                );
            }
            input = input.get(step.consumed..).unwrap_or_default();
            match step.event {
                Some(e) => seen.push(Ev::from(e)),
                None if input.is_empty() => break,
                None => finding(
                    TARGET,
                    format_args!("took nothing of {input:?}, gave nothing"),
                ),
            }
        }
    }
    match p.end() {
        Ok(Some(e)) => seen.push(Ev::from(e)),
        Ok(None) => {}
        Err(e) => return (seen, Err(e)),
    }
    if !matches!(p.end(), Ok(None)) || !p.is_over() {
        finding(TARGET, format_args!("whole, but not over after its end"));
    }
    (seen, Ok(()))
}

/// What every accepted document is, checked apart from the parser.
fn check(events: &[Ev], depth_max: u8) {
    // each open object's names, to find one named twice
    let mut open: Vec<Option<Vec<&str>>> = Vec::new();
    let mut scalars_at_top = 0usize;
    for e in events {
        match e {
            Ev::ObjectStart => open.push(Some(Vec::new())),
            Ev::ArrayStart => open.push(None),
            Ev::ObjectEnd | Ev::ArrayEnd => {
                if open.pop().is_none() {
                    finding(TARGET, format_args!("a close with nothing open"));
                }
            }
            Ev::Name(n) => {
                let Some(Some(names)) = open.last_mut() else {
                    finding(TARGET, format_args!("a name outside an object"));
                };
                if names.contains(&n.as_str()) {
                    finding(TARGET, format_args!("{n:?} named twice"));
                }
                names.push(n);
                check_str(n);
            }
            Ev::Str(s) => check_str(s),
            Ev::Num(n) => {
                let ok = n.starts_with(|c: char| c == '-' || c.is_ascii_digit())
                    && n.parse::<f64>().is_ok();
                if !ok {
                    finding(TARGET, format_args!("number {n:?}"));
                }
            }
            Ev::Bool(_) | Ev::Null => {}
        }
        if open.len() > usize::from(depth_max) {
            finding(TARGET, format_args!("nested {} deep", open.len()));
        }
        if open.is_empty() && !matches!(e, Ev::ObjectEnd | Ev::ArrayEnd) {
            scalars_at_top = scalars_at_top.saturating_add(1);
        }
    }
    if !open.is_empty() {
        finding(TARGET, format_args!("{} left open", open.len()));
    }
    let top = usize::from(matches!(
        events.first(),
        Some(Ev::ObjectStart | Ev::ArrayStart)
    ));
    if scalars_at_top.saturating_add(top) != 1 {
        finding(TARGET, format_args!("not one document: {events:?}"));
    }
}

/// What a string may not hold: U+0000, or a noncharacter.
fn check_str(s: &str) {
    for c in s.chars() {
        let c = u32::from(c);
        if c == 0 || (0xfdd0..=0xfdef).contains(&c) || c & 0xfffe == 0xfffe {
            finding(TARGET, format_args!("{s:?} holds U+{c:04X}"));
        }
    }
}

/// The events written out again, compactly.
fn write(events: &[Ev]) -> String {
    let mut out = String::new();
    let mut first = true;
    for e in events {
        let opens_or_value = !matches!(e, Ev::ObjectEnd | Ev::ArrayEnd);
        if opens_or_value && !first && !out.ends_with(':') {
            out.push(',');
        }
        first = matches!(e, Ev::ObjectStart | Ev::ArrayStart);
        match e {
            Ev::ObjectStart => out.push('{'),
            Ev::ObjectEnd => out.push('}'),
            Ev::ArrayStart => out.push('['),
            Ev::ArrayEnd => out.push(']'),
            Ev::Name(n) => {
                quote(&mut out, n);
                out.push(':');
            }
            Ev::Str(s) => quote(&mut out, s),
            Ev::Num(n) => out.push_str(n),
            Ev::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Ev::Null => out.push_str("null"),
        }
    }
    out
}

fn quote(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A JSON document, as npro-json parses it.
///
/// The first byte chooses how the rest is split, and with its top bit,
/// small storage and depth, so the limits are reached.  In one piece and
/// in pieces, the same events and the same verdict, refused at the same
/// byte; every call takes something or gives something.  An accepted
/// document is checked apart from the parser: one value, every container
/// closed, no deeper than allowed, no object with a name twice, no string
/// with U+0000 or a noncharacter, every number one `f64` reads.  Written
/// out again compactly, it parses to the same events.
pub fn json(data: &[u8]) {
    let (ctl, bytes) = control(data);
    let whole = run(ctl, core::iter::once(bytes));
    let pieces = run(ctl, Pieces::new(ctl, bytes));
    if pieces != whole {
        finding(
            TARGET,
            format_args!("in one piece:\n{whole:?}\nin pieces:\n{pieces:?}"),
        );
    }
    let (events, verdict) = whole;
    if verdict.is_err() {
        return;
    }
    check(&events, sizes(ctl).2);
    let again = write(&events);
    let (events_again, verdict_again) = run(ctl, core::iter::once(again.as_bytes()));
    if verdict_again.is_err() || events_again != events {
        finding(
            TARGET,
            format_args!("written as {again:?}, parsed to {events_again:?}, {verdict_again:?}"),
        );
    }
}
