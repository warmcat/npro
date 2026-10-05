//! npro's h1 client replays C's h1 client transcripts.
//!
//! Each is one request C's `api-test-sansio` makes, `GET /x` (or `HEAD /x`)
//! to `sansio`, port 80, with C's defaults: no-cache headers, an `Origin`,
//! and `connection: close`.  The request npro writes must be the
//! transcript's first `tx`, byte for byte; after each `rx`, the body npro
//! gives the app must be the transcript's `app_rx` bytes, and npro must ask
//! to release the connection exactly where C released it, its `close`.
//! Where C did not, its transaction was complete at the end, and npro's
//! must be.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses npro-test and npro-h1"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod h1_client_replay {
    use npro_h1::client::{Client, Connection, Event, Request, Scheme};
    use npro_h1::table::DEFAULT_CAPACITY;
    use npro_test::{StepKind, Transcript, vendored};

    /// The h1 client transcripts that need no more of lws than this phase
    /// has: not the digest retry, which needs the digest and lws' random.
    const CASES: [&str; 7] = [
        "h1-client-get",
        "h1-client-cl-junk",
        "h1-client-cl-twice",
        "h1-client-te-list",
        "h1-client-head-chunked",
        "h1-client-head-cl",
        "h1-client-304-cl",
    ];

    /// Hands `input` to the client until it takes nothing more; returns
    /// the body it gave the app, and whether it failed.
    fn feed(c: &mut Client<Vec<u8>>, mut input: &[u8]) -> (Vec<u8>, bool) {
        let mut body = Vec::new();
        loop {
            let Ok(rx) = c.rx(input) else {
                return (body, true);
            };
            input = &input[rx.consumed..];
            match rx.event {
                Some(Event::Body(b)) => body.extend_from_slice(b),
                None if rx.consumed == 0 => return (body, false),
                Some(Event::Response | Event::BodyEnd) | None => {}
            }
        }
    }

    fn replay(t: &Transcript) {
        let mut steps = t.steps.iter().peekable();
        let Some(StepKind::Tx(want)) = steps.next().map(|s| &s.kind) else {
            panic!("{}: does not start with the request", t.case);
        };
        let method: &[u8] = if want.starts_with(b"HEAD ") {
            b"HEAD"
        } else {
            b"GET"
        };
        let mut c = Client::new(
            vec![0u8; DEFAULT_CAPACITY],
            Request {
                method,
                path: b"/x",
                host: Some(b"sansio"),
                origin: Some(b"sansio"),
                scheme: Scheme::Http,
                no_cache: true,
                connection: Connection::Close,
            },
        )
        .unwrap();
        let mut out = [0u8; 512];
        let n = c.tx(&mut out);
        assert_eq!(
            out[..n].escape_ascii().to_string(),
            want.escape_ascii().to_string(),
            "{}: the request",
            t.case
        );

        while let Some(step) = steps.next() {
            let StepKind::Rx(rx) = &step.kind else {
                panic!("{}: {:?} with no rx before it", t.case, step.kind);
            };
            let (mut want_body, mut want_close) = (Vec::new(), false);
            while let Some(next) = steps.peek() {
                match &next.kind {
                    StepKind::AppRx(b) => want_body.extend_from_slice(b),
                    StepKind::Close => want_close = true,
                    StepKind::Rx(_) => break,
                    StepKind::Tx(b) => panic!("{}: a second request {b:?}", t.case),
                }
                steps.next();
            }
            let (body, failed) = feed(&mut c, rx);
            assert_eq!(body, want_body, "{} at {}us: the body", t.case, step.t_us);
            assert_eq!(
                failed,
                want_close,
                "{} at {}us: released, {:?}",
                t.case,
                step.t_us,
                c.failed()
            );
        }
        // where C did not release it, it had completed the transaction:
        // nothing is left waiting for a body that will not come
        if c.failed().is_none() {
            assert!(c.is_done(), "{}: not done", t.case);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn cs_client_transcripts_replay() {
        let all = vendored().unwrap();
        for case in CASES {
            let t = all
                .iter()
                .find(|t| t.case == case)
                .unwrap_or_else(|| panic!("no transcript {case}"));
            replay(t);
        }
    }
}
