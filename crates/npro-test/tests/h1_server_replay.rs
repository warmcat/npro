//! npro's h1 server replays C's server transcripts byte for byte.
//!
//! Each transcript here is one connection to C's `sansio-uri` vhost, whose
//! context limits a GET's target to 33 bytes and a User-Agent to 16, and
//! whose app is ported below as C's `api-test-sansio` has it: it answers
//! 200 `text/plain` with the path, a newline and the urlargs; `/short`
//! with a length of 10 and 3 bytes (none to a HEAD); `/body-done` from the
//! body's first piece, with `ok\n`.  Each `rx` is handed to npro's server
//! at its time, the connection starting at the first, and nothing may fall
//! due between them, as nothing did in C's run; what it writes before the
//! next must be the transcript's `tx` bytes.  So must `h1-ws-server`'s
//! first exchange, a GET to the `sansio` vhost.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses npro-test, npro-core and npro-h1"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod h1_server_replay {
    use core::num::NonZeroU16;

    use npro_core::time::Instant;
    use npro_h1::head;
    use npro_h1::server::{Config, Event, Response, Server, TxSource};
    use npro_h1::table::DEFAULT_CAPACITY;
    use npro_h1::token::Token;
    use npro_test::{StepKind, Transcript, vendored};

    /// The cases this replays: every server transcript whose connection is
    /// h1 to `sansio-uri` and needs no more of lws than this phase has.
    const CASES: [&str; 19] = [
        "h1-uri-dotdot-args",
        "h1-uri-dot-args",
        "h1-uri-plus",
        "h1-uri-at-limit",
        "h1-uri-past-limit",
        "h1-header-past-limit",
        "h1-reqline-http09",
        "h1-reqline-no-method",
        "h1-reqline-version-2",
        "h1-reqline-version-junk",
        "h1-reqline-version-long",
        "h1-reqline-version-1-2",
        "h1-reqline-unknown-method",
        "h1-reqline-unknown-header-first",
        "h1-reqline-leading-empty",
        "h1-reqline-leading-empty-many",
        "h1-post-no-length",
        "h1-short-answer",
        "h1-body-done",
    ];

    /// C's `callback_uri`, for what these cases ask of it.
    #[derive(Default)]
    struct UriApp {
        /// The payload still to go.
        out: Vec<u8>,
        at: usize,
        /// Complete the transaction once the payload has gone.
        complete_when_sent: bool,
        /// `/body-done`: answer from the body.
        body_done: bool,
        /// The `sansio` vhost's `http` instead: this, to any request.
        fixed: Option<&'static [u8]>,
    }

    impl TxSource for UriApp {
        fn fill(&mut self, buf: &mut [u8]) -> usize {
            let rest = &self.out[self.at..];
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.at = self.at.checked_add(n).unwrap();
            n
        }
    }

    impl UriApp {
        fn answer(&mut self, s: &mut Server<Vec<u8>>, len: u64, payload: &[u8]) {
            s.respond(Response {
                status: 200,
                content_type: Some(b"text/plain"),
                content_length: Some(len),
            })
            .unwrap();
            self.out = payload.to_vec();
            self.at = 0;
            self.complete_when_sent = true;
        }

        fn request(&mut self, s: &mut Server<Vec<u8>>) {
            if let Some(f) = self.fixed {
                let len = u64::try_from(f.len()).unwrap();
                self.answer(s, len, f);
                return;
            }
            let t = s.request();
            let path = t
                .first(Token::GetUri)
                .or_else(|| t.first(Token::PostUri))
                .or_else(|| t.first(Token::HeadUri))
                .unwrap_or_default()
                .to_vec();
            let head = t.is_present(Token::HeadUri);
            let mut args = vec![0u8; t.total_len(Token::UriArgs)];
            t.copy(Token::UriArgs, &mut args).unwrap();
            match path.as_slice() {
                b"/short" => self.answer(s, 10, if head { b"" } else { b"abc" }),
                b"/body-done" => self.body_done = true,
                _ => {
                    let body = [path, b"\n".to_vec(), args].concat();
                    let len = u64::try_from(body.len()).unwrap();
                    self.answer(s, len, &body);
                }
            }
        }

        fn body(&mut self, s: &mut Server<Vec<u8>>) {
            if self.body_done {
                self.body_done = false;
                self.answer(s, 3, b"ok\n");
            }
        }
    }

    /// Hands `input` to the server at `now`, with the app answering, until
    /// neither takes or writes anything more; returns what was written.
    fn feed(s: &mut Server<Vec<u8>>, app: &mut UriApp, mut input: &[u8], now: Instant) -> Vec<u8> {
        let mut wrote = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let rx = s.rx(now, input);
            let mut progress = rx.consumed > 0 || rx.event.is_some();
            input = &input[rx.consumed..];
            match rx.event {
                Some(Event::Request) => app.request(s),
                Some(Event::Body(_)) => app.body(s),
                Some(Event::BodyEnd) | None => {}
            }
            loop {
                let tx = s.tx(now, &mut buf, app);
                wrote.extend_from_slice(&buf[..tx.written]);
                if app.complete_when_sent && app.at == app.out.len() && !s.wants_write() {
                    app.complete_when_sent = false;
                    s.complete(now);
                    progress = true;
                }
                if tx.written == 0 {
                    break;
                }
                progress = true;
            }
            if !progress {
                return wrote;
            }
        }
    }

    /// Replays `t`'s first `rxs` reads, with `app`, in a context limiting
    /// what `cfg` limits.
    fn replay(t: &Transcript, cfg: head::Config, mut app: UriApp, rxs: usize) {
        let start = t.steps.first().map_or(0, |s| s.t_us);
        let time = |t_us: u64| Instant::from_micros(t.t0_us.checked_add(t_us).unwrap());
        let mut s =
            Server::new(vec![0u8; DEFAULT_CAPACITY], Config::new(cfg), time(start)).unwrap();
        let mut steps = t.steps.iter().peekable();
        for _ in 0..rxs {
            let Some(step) = steps.next() else {
                break;
            };
            let StepKind::Rx(rx) = &step.kind else {
                panic!("{}: {:?} with no rx before it", t.case, step.kind);
            };
            let mut want = Vec::new();
            while let Some(next) = steps.peek() {
                match &next.kind {
                    StepKind::Tx(b) => want.extend_from_slice(b),
                    StepKind::Rx(_) => break,
                    k @ (StepKind::AppRx(_) | StepKind::Close) => {
                        panic!("{}: {k:?} is not in this replay", t.case)
                    }
                }
                steps.next();
            }
            // C's run had nothing fall due: nor may npro's
            let now = time(step.t_us);
            assert!(
                s.next_deadline().is_none_or(|d| d > now),
                "{} at {}us: a deadline passed",
                t.case,
                step.t_us
            );
            let got = feed(&mut s, &mut app, rx, now);
            assert_eq!(
                got.escape_ascii().to_string(),
                want.escape_ascii().to_string(),
                "{} at {}us",
                t.case,
                step.t_us
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn cs_server_transcripts_replay_byte_for_byte() {
        let all = vendored().unwrap();
        for case in CASES {
            let t = all
                .iter()
                .find(|t| t.case == case)
                .unwrap_or_else(|| panic!("no transcript {case}"));
            let cfg = head::Config::new()
                .with_limit(Token::GetUri, NonZeroU16::new(33).unwrap())
                .with_limit(Token::UserAgent, NonZeroU16::new(16).unwrap());
            replay(t, cfg, UriApp::default(), usize::MAX);
        }
    }

    /// `h1-ws-server`'s first exchange, a GET to the `sansio` vhost, whose
    /// `http` answers `sansio ok`; the rest of it is ws.
    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn h1_ws_servers_first_exchange_replays() {
        let all = vendored().unwrap();
        let t = all.iter().find(|t| t.case == "h1-ws-server").unwrap();
        let app = UriApp {
            fixed: Some(b"sansio ok\n"),
            ..UriApp::default()
        };
        replay(t, head::Config::new(), app, 1);
    }
}
