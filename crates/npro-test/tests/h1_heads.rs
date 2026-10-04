//! npro's h1 head parser against the heads of C's transcripts.
//!
//! The `h1-uri-*`, `h1-reqline-*` and `h1-header-past-limit` connections
//! are each one request to C's `sansio-uri` vhost, whose context limits a
//! GET's target to 33 bytes and a User-Agent to 16.  C either refuses the
//! request with a status, or its app answers 200 with the path lws decoded,
//! a newline and the urlargs.  So each says what C's parser made of its
//! request, and npro's must make the same of it: the same refusal, or the
//! same path and urlargs.
//!
//! The client connections' first rx is the response head.  The ones whose
//! framing C refuses (`h1-client-cl-junk` and the like) are refused after
//! the head, by what the framing headers say; the head itself parses, and
//! `npro_h1::fields` must read them as C does.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses npro-test and npro-h1"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod h1_heads {
    use core::num::NonZeroU16;

    use npro_h1::fields::{content_length, transfer_encoding_is_chunked};
    use npro_h1::head::{Config, Head, Progress, Side};
    use npro_h1::table::DEFAULT_CAPACITY;
    use npro_h1::token::Token;
    use npro_test::{StepKind, Transcript, vendored};

    /// The `sansio-uri` context's limits.
    fn uri_config() -> Config {
        Config::new()
            .with_limit(Token::GetUri, NonZeroU16::new(33).unwrap())
            .with_limit(Token::UserAgent, NonZeroU16::new(16).unwrap())
    }

    fn first_rx(t: &Transcript) -> &[u8] {
        t.steps
            .iter()
            .find_map(|s| match &s.kind {
                StepKind::Rx(b) => Some(b.as_slice()),
                StepKind::Tx(_) | StepKind::AppRx(_) | StepKind::Close => None,
            })
            .unwrap()
    }

    fn first_tx(t: &Transcript) -> &[u8] {
        t.steps
            .iter()
            .find_map(|s| match &s.kind {
                StepKind::Tx(b) => Some(b.as_slice()),
                StepKind::Rx(_) | StepKind::AppRx(_) | StepKind::Close => None,
            })
            .unwrap()
    }

    /// What the request's answer says: its status, and for a 200, its body.
    fn answered(tx: &[u8]) -> (u16, Vec<u8>) {
        let status = core::str::from_utf8(&tx[9..12]).unwrap().parse().unwrap();
        let body = tx
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|n| tx[n..].strip_prefix(b"\r\n\r\n").unwrap().to_vec())
            .unwrap();
        (status, body)
    }

    /// What C's `sansio-uri` app answers a request with: the path, a newline
    /// and the urlargs, joined as `lws_hdr_copy()` joins them.
    fn uri_app_body<S: AsRef<[u8]> + AsMut<[u8]>>(h: &Head<S>) -> Vec<u8> {
        let t = h.table();
        let path = Token::METHODS
            .iter()
            .find_map(|m| t.first(*m))
            .unwrap()
            .to_vec();
        let mut args = vec![0u8; t.total_len(Token::UriArgs)];
        t.copy(Token::UriArgs, &mut args).unwrap();
        [path, b"\n".to_vec(), args].concat()
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn requests_are_parsed_and_refused_as_c_does() {
        let mut seen = 0;
        for t in vendored().unwrap() {
            let c = t.case.as_str();
            if !(c.starts_with("h1-uri-")
                || c.starts_with("h1-reqline-")
                || c == "h1-header-past-limit")
            {
                continue;
            }
            seen += 1;
            let (status, body) = answered(first_tx(&t));
            let mut h = Head::new(vec![0u8; DEFAULT_CAPACITY], Side::Server, uri_config()).unwrap();
            match h.rx(first_rx(&t)) {
                Ok(Progress::Complete { .. }) => {
                    assert_eq!(status, 200, "{c}: C refused what npro took");
                    assert_eq!(
                        uri_app_body(&h).escape_ascii().to_string(),
                        body.escape_ascii().to_string(),
                        "{c}"
                    );
                }
                Ok(p) => panic!("{c}: {p:?}"),
                Err(r) => {
                    let a = r.answer().unwrap_or_else(|| panic!("{c}: {r} unanswered"));
                    assert_eq!(a.code(), status, "{c}: {r}");
                }
            }
        }
        assert_eq!(seen, 16, "the uri and request line cases");
    }

    /// A request split anywhere is the same request.
    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn requests_split_anywhere_parse_the_same() {
        for t in vendored().unwrap() {
            if t.side != npro_test::Side::Server {
                continue;
            }
            let rx = first_rx(&t);
            let mut whole =
                Head::new(vec![0u8; DEFAULT_CAPACITY], Side::Server, uri_config()).unwrap();
            let want = whole.rx(rx);
            for at in 0..=rx.len() {
                let mut h =
                    Head::new(vec![0u8; DEFAULT_CAPACITY], Side::Server, uri_config()).unwrap();
                let (a, b) = rx.split_at(at);
                let got = match h.rx(a) {
                    Ok(Progress::More) => h.rx(b).map(|p| match p {
                        Progress::Complete { consumed } => Progress::Complete {
                            consumed: consumed + at,
                        },
                        p @ (Progress::More | Progress::Fallback) => p,
                    }),
                    other => other,
                };
                assert_eq!(got, want, "{} split at {at}", t.case);
                if want.is_ok() {
                    assert_eq!(h.table().used(), whole.table().used(), "{}", t.case);
                }
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn response_heads_and_their_framing_as_c_reads_them() {
        let mut seen = 0;
        for t in vendored().unwrap() {
            let c = t.case.as_str();
            if !c.starts_with("h1-client-") || c.ends_with("digest-retry") {
                continue;
            }
            seen += 1;
            let mut h =
                Head::new(vec![0u8; DEFAULT_CAPACITY], Side::Client, Config::new()).unwrap();
            let rx = first_rx(&t);
            let Ok(Progress::Complete { consumed }) = h.rx(rx) else {
                panic!("{c}: the head did not parse");
            };
            let tb = h.table();
            let status = tb.first(Token::Http).unwrap();
            let cl: Vec<&[u8]> = tb.fragments(Token::ContentLength).collect();
            match c {
                "h1-client-get" => {
                    assert_eq!(status, b"200 OK");
                    assert_eq!(
                        content_length(cl[0]),
                        Ok(u64::try_from(rx.len().checked_sub(consumed).unwrap()).unwrap())
                    );
                }
                "h1-client-cl-junk" => assert!(content_length(cl[0]).is_err()),
                "h1-client-cl-twice" => assert_eq!(cl.len(), 2),
                "h1-client-te-list" => assert!(!transfer_encoding_is_chunked(tb)),
                "h1-client-head-chunked" => assert!(transfer_encoding_is_chunked(tb)),
                "h1-client-head-cl" => assert_eq!(content_length(cl[0]), Ok(10)),
                "h1-client-304-cl" => assert_eq!(status, b"304 Not Modified"),
                _ => panic!("{c}: a new client case: say what its head is"),
            }
        }
        assert_eq!(seen, 7, "the h1 client cases");
    }
}
