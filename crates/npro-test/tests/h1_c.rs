//! npro's h1 head parser against C's, head by head.
//!
//! `h1/c-heads.txt` is what C lws' `lws_parse()` made of every head in
//! `h1/requests/` and `h1/responses/`, and of variations of each, as a
//! server and as a client, in two configurations: see
//! `scripts/sync-c-h1.sh`, and `h1/c-heads.c`, which wrote it.  For each,
//! npro's parser must come to the same verdict, and where the head parsed,
//! leave the same table: the same values in the same pieces, the same
//! unknown headers, and the same number of bytes used, so a head fills the
//! table at the same byte.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses only npro-h1"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod h1_c {
    use core::fmt::Write as _;
    use core::num::NonZeroU16;

    use npro_h1::chunked::{Chunk, Dechunk};
    use npro_h1::head::{Cause, Config, Head, Progress, Side, UnknownMethod};
    use npro_h1::table::HeaderTable;
    use npro_h1::token::Token;

    struct Case<'a> {
        config: &'a str,
        side: Side,
        name: &'a str,
        head: Vec<u8>,
        verdict: &'a str,
    }

    /// The lines of `c-heads.txt` for `side`, split into their fields.
    fn lines<'a>(text: &'a str, side: &str) -> Vec<[&'a str; 5]> {
        text.lines()
            .map(|l| {
                let f: Vec<&str> = l.splitn(5, ' ').collect();
                [f[0], f[1], f[2], f[3], f[4]]
            })
            .filter(|f| f[1] == side)
            .collect()
    }

    /// A hex field, "-" for no bytes.
    fn unhex(h: &str) -> Vec<u8> {
        if h == "-" {
            return Vec::new();
        }
        h.as_bytes()
            .chunks(2)
            .map(|h| u8::from_str_radix(core::str::from_utf8(h).unwrap(), 16).unwrap())
            .collect()
    }

    fn cases(text: &str) -> Vec<Case<'_>> {
        let mut all = Vec::new();
        for (name, side) in [("server", Side::Server), ("client", Side::Client)] {
            all.extend(lines(text, name).into_iter().map(|f| Case {
                config: f[0],
                side,
                name: f[2],
                head: unhex(f[3]),
                verdict: f[4],
            }));
        }
        all
    }

    fn config(name: &str) -> (usize, Config) {
        let n = |v| NonZeroU16::new(v).unwrap();
        match name {
            "default" => (4096, Config::new()),
            "tight" => (
                512,
                Config::new()
                    .with_limit(Token::GetUri, n(33))
                    .with_limit(Token::UserAgent, n(16))
                    .with_limit(Token::Host, n(24))
                    .with_limit(Token::Cookie, n(48))
                    .with_unknown_method(UnknownMethod::Fallback),
            ),
            c => panic!("config {c}"),
        }
    }

    fn hex(out: &mut String, b: &[u8]) {
        for c in b {
            write!(out, "{c:02x}").unwrap();
        }
    }

    /// Bytes that are a field of their own, as `c-heads` writes them.
    fn field(b: &[u8]) -> String {
        if b.is_empty() {
            return "-".into();
        }
        let mut s = String::new();
        hex(&mut s, b);
        s
    }

    /// The table as `c-heads` dumps C's.
    fn dump(t: &HeaderTable<Vec<u8>>, used: usize) -> String {
        let mut s = format!("used={used}");
        for tok in Token::ALL {
            if !t.is_present(tok) {
                continue;
            }
            write!(s, " t{}=", tok.index()).unwrap();
            for (i, f) in t.fragments(tok).enumerate() {
                if i > 0 {
                    s.push(',');
                }
                hex(&mut s, f);
            }
        }
        for (n, v) in t.unknown_headers() {
            s.push_str(" u");
            hex(&mut s, n);
            s.push('=');
            hex(&mut s, v);
        }
        s
    }

    /// What npro makes of a head, in `c-heads`' terms.
    fn npro(case: &Case<'_>) -> (String, Option<Cause>) {
        npro_in_pieces(case, &mut |rest| rest.len())
    }

    /// What npro makes of a head handed to it in pieces, `piece` saying how
    /// long each is from what is left.
    fn npro_in_pieces(
        case: &Case<'_>,
        piece: &mut dyn FnMut(&[u8]) -> usize,
    ) -> (String, Option<Cause>) {
        let (cap, cfg) = config(case.config);
        let mut table = HeaderTable::new(vec![0u8; cap]).unwrap();
        if case.side == Side::Client {
            // a client's table holds its own request first, as c-heads' does
            table.create(Token::ClientPeerAddress, b"sansio").unwrap();
            table.create(Token::ClientUri, b"/x").unwrap();
            table.create(Token::ClientHost, b"sansio").unwrap();
            table.create(Token::ClientMethod, b"GET").unwrap();
        }
        let mut h = Head::with_table(table, case.side, cfg);
        let mut r = Ok(Progress::More);
        let mut at = 0;
        while at < case.head.len() {
            let rest = &case.head[at..];
            let n = piece(rest).min(rest.len());
            r = h.rx(&rest[..n]).map(|p| match p {
                Progress::Complete { consumed } => Progress::Complete {
                    consumed: consumed.checked_add(at).unwrap(),
                },
                p @ (Progress::More | Progress::Fallback) => p,
            });
            if !matches!(r, Ok(Progress::More)) {
                break;
            }
            at = at.checked_add(n).unwrap();
        }
        let used = h.table().used();
        match r {
            Ok(Progress::Complete { consumed }) => (
                format!("complete {consumed} {}", dump(h.table(), used)),
                None,
            ),
            Ok(Progress::More) => (format!("more {}", dump(h.table(), used)), None),
            Ok(Progress::Fallback) => ("fallback".into(), None),
            Err(e) => {
                let v = match (case.side, e.answer(), e.cause()) {
                    (Side::Server, Some(a), _) => format!("refused {}", a.code()),
                    (Side::Client, _, Cause::Uri(_)) => "refused 0".into(),
                    (Side::Client, _, Cause::HeadTooLarge | Cause::UriTooLong) => "toolarge".into(),
                    (Side::Server, None, _) | (Side::Client, _, _) => "fail".into(),
                };
                (v, Some(e.cause()))
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "thousands of heads: native runs keep it")]
    fn every_head_parses_as_c_parses_it() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/h1/c-heads.txt"))
            .unwrap();
        let all = cases(&text);
        assert!(all.len() > 1000, "{} heads", all.len());
        let mut wrong = Vec::new();
        for case in &all {
            let (got, cause) = npro(case);
            if got == case.verdict {
                continue;
            }
            wrong.push(format!(
                "{} {:?} {}: {}\n  head: {}\n  C:    {}\n  npro: {} ({cause:?})",
                case.config,
                case.side,
                case.name,
                wrong.len(),
                case.head.escape_ascii(),
                case.verdict,
                got
            ));
        }
        assert!(
            wrong.is_empty(),
            "{} of {} heads differ:\n{}",
            wrong.len(),
            all.len(),
            wrong
                .iter()
                .take(20)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// A head in pieces parses as it does whole, wherever it is split: the
    /// oracle that found the most bugs in C's newer parsers.  Each head is
    /// split three ways, into pieces of 0 to 16 bytes from a seeded generator.
    #[test]
    #[cfg_attr(miri, ignore = "thousands of heads: native runs keep it")]
    fn every_head_parses_the_same_in_pieces() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/h1/c-heads.txt"))
            .unwrap();
        // C's rand(), as npro-fuzz's splitting uses
        let mut state = 1u32;
        let mut next = move |_: &[u8]| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            usize::try_from((state >> 16) % 17).unwrap()
        };
        for case in cases(&text) {
            let whole = npro(&case);
            for _ in 0..3 {
                assert_eq!(
                    npro_in_pieces(&case, &mut next),
                    whole,
                    "{} {:?} {}",
                    case.config,
                    case.side,
                    case.name
                );
            }
        }
    }

    /// What npro's dechunker makes of a body, in `c-heads`' terms.
    fn dechunked(body: &[u8]) -> String {
        let mut d = Dechunk::new();
        let (mut data, mut at) = (Vec::new(), 0usize);
        loop {
            let Ok(step) = d.step(&body[at..]) else {
                return "fail".into();
            };
            at = at.checked_add(step.consumed).unwrap();
            match step.chunk {
                Chunk::Data(b) => data.extend_from_slice(b),
                Chunk::End => return format!("end {at} {}", field(&data)),
                Chunk::More if at == body.len() => return format!("more {}", field(&data)),
                Chunk::More => {}
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "hundreds of bodies: native runs keep it")]
    fn every_chunked_body_is_framed_as_c_frames_it() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/h1/c-heads.txt"))
            .unwrap();
        let bodies = lines(&text, "chunked");
        assert!(bodies.len() > 100, "{} bodies", bodies.len());
        for f in bodies {
            let body = unhex(f[3]);
            assert_eq!(dechunked(&body), f[4], "{}: {}", f[2], body.escape_ascii());
        }
    }
}
