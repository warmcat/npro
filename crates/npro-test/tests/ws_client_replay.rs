//! npro's ws client replays C's ws client transcripts byte for byte.
//!
//! Each is one connection C's `api-test-sansio` makes: a GET of `/echo` to
//! `sansio`, port 80, with C's defaults (no-cache headers, an `Origin`),
//! offering the subprotocol `echo`, its random C's seeded stream.  npro's
//! h1 client writes the request, its upgrade lines and key from npro-ws;
//! the response is checked as C checks it, and the connection is then
//! npro-ws', masking from the same stream.  The app is C's
//! `callback_client`: once established it sends `Hello`, unless the case
//! has it quiet.  The `ws-client-pmd-*` cases also offer permessage-deflate,
//! which the server takes; they are quiet, as C's are, since what the
//! client would send is deflated, and those bytes are the deflater's
//! business.
//!
//! Each `rx` is handed in at its time, and nothing may fall due between
//! them, as nothing did in C's run.  What npro writes after each `rx` must
//! be the transcript's `tx` bytes,
//! the messages it hands the app its `app_rx` bytes, and it must ask to be
//! done with the connection exactly where C closed it, its `close`.  It
//! writes four bytes at a time, so every frame goes in pieces.

// held to clippy's rules for tests
#[cfg(test)]
mod ws_client_replay {
    use npro_core::random::SeededRandom;
    use npro_core::time::Instant;
    use npro_h1::client::{Client, Connection, Event as H1Event, Request, Scheme};
    use npro_h1::server::TxSource;
    use npro_h1::table::DEFAULT_CAPACITY;
    use npro_test::{StepKind, Transcript, vendored};
    use npro_ws::conn::{AsClient, Event, Kind, Ws};
    use npro_ws::handshake::{ClientKey, MAX_REQUEST_LINES};
    use npro_ws::pmd;

    /// A case: its transcript, whether the app is quiet, and the
    /// extensions offered.
    struct Case {
        name: &'static str,
        quiet: bool,
        extensions: Option<&'static [u8]>,
    }

    const fn case(name: &'static str, quiet: bool, extensions: Option<&'static [u8]>) -> Case {
        Case {
            name,
            quiet,
            extensions,
        }
    }

    /// The ws client transcripts: all but the digest retry, which needs
    /// digest auth.
    const CASES: [Case; 9] = [
        case("ws-client", false, None),
        case("ws-client-interim", false, None),
        case("ws-client-ping-close", true, None),
        case("ws-client-huge-frame", false, None),
        case("ws-client-rsv1-no-ext", false, None),
        case("ws-client-rsv2", false, None),
        case("ws-client-pmd-rsv2", true, Some(pmd::OFFER)),
        case("ws-client-pmd-rsv1-continuation", true, Some(pmd::OFFER)),
        case("ws-client-pmd-rsv1-ping", true, Some(pmd::OFFER)),
    ];

    /// The subprotocols offered.
    const OFFERED: &[u8] = b"echo";

    /// How much is written at a time.
    const TX_LIMIT: usize = 4;

    /// C's `callback_client`, as far as ws goes.
    #[derive(Default)]
    struct ClientApp {
        quiet: bool,
        /// What it was given, for the transcript's `app_rx`.
        app_rx: Vec<u8>,
        out: Vec<u8>,
        at: usize,
    }

    impl TxSource for ClientApp {
        fn fill(&mut self, buf: &mut [u8]) -> usize {
            let rest = &self.out[self.at..];
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.at = self.at.checked_add(n).unwrap();
            n
        }
    }

    impl ClientApp {
        /// `LWS_CALLBACK_CLIENT_ESTABLISHED`, then its writeable.
        fn established(&mut self, ws: &mut Ws<AsClient<SeededRandom>>) {
            if self.quiet {
                return;
            }
            self.out = b"Hello".to_vec();
            self.at = 0;
            ws.send(Kind::Text, 5).unwrap();
        }
    }

    /// The connection: h1 until the 101 is in, then ws, which takes the
    /// random stream on from the key's draw.
    enum Conn {
        H1 {
            client: Box<Client<Vec<u8>>>,
            key: ClientKey,
            random: Option<SeededRandom>,
            extensions: Option<&'static [u8]>,
        },
        Ws(Box<Ws<AsClient<SeededRandom>>>),
    }

    /// Hands `input` to the connection at `now`, with the app answering,
    /// until neither takes or writes anything more; returns what was
    /// written.
    fn feed(conn: &mut Conn, app: &mut ClientApp, input: &mut [u8], now: Instant) -> Vec<u8> {
        let mut wrote = Vec::new();
        let mut buf = [0u8; TX_LIMIT];
        let mut inflated = [0u8; pmd::RX_CHUNK];
        let mut at = 0usize;
        loop {
            let mut progress = false;
            match conn {
                Conn::H1 {
                    client,
                    key,
                    random,
                    extensions,
                } => {
                    let rx = client.rx(now, &input[at..]).unwrap();
                    at = at.checked_add(rx.consumed).unwrap();
                    progress |= rx.consumed > 0;
                    if rx.event == Some(H1Event::Response) {
                        assert!(client.is_upgraded());
                        let checked = key
                            .check(
                                client.status(),
                                client.response(),
                                Some(OFFERED),
                                *extensions,
                            )
                            .unwrap();
                        assert_eq!(checked.protocol, Some(OFFERED));
                        let mut ws = Ws::client(random.take().unwrap(), now);
                        if let Some(said) = checked.extensions {
                            ws = ws.with_pmd(pmd::client_accept(said).unwrap());
                        }
                        app.established(&mut ws);
                        *conn = Conn::Ws(Box::new(ws));
                        continue;
                    }
                }
                Conn::Ws(ws) => {
                    let rx = ws.rx(now, &mut input[at..], &mut inflated);
                    let consumed = rx.consumed;
                    if let Some(Event::Message { data, .. }) = rx.event {
                        app.app_rx.extend_from_slice(data);
                    }
                    at = at.checked_add(consumed).unwrap();
                    progress |= consumed > 0;
                    loop {
                        let n = ws.tx(now, &mut buf, app);
                        wrote.extend_from_slice(&buf[..n]);
                        if n == 0 {
                            break;
                        }
                        progress = true;
                    }
                }
            }
            if !progress {
                return wrote;
            }
        }
    }

    fn replay(t: &Transcript, c: &Case) {
        // C's run was seeded: its random is in the transcript
        let seed = t.seed.unwrap_or_else(|| panic!("{}: not seeded", t.case));
        let mut random = SeededRandom::new(seed.get());
        let key = ClientKey::new(&mut random).unwrap();
        let mut lines = [0u8; MAX_REQUEST_LINES + 32];
        let lines_len = key
            .request_lines(Some(OFFERED), c.extensions, &mut lines)
            .unwrap();
        let mut client = Client::new(
            vec![0u8; DEFAULT_CAPACITY],
            Request {
                method: b"GET",
                path: b"/echo",
                host: Some(b"sansio"),
                origin: Some(b"sansio"),
                scheme: Scheme::Http,
                no_cache: true,
                connection: Connection::Upgrade(&lines[..lines_len]),
            },
        )
        .unwrap();

        let time = |t_us: u64| Instant::from_micros(t.t0_us.checked_add(t_us).unwrap());
        let mut steps = t.steps.iter().peekable();
        let Some((sent, StepKind::Tx(request))) = steps.next().map(|s| (s.t_us, &s.kind)) else {
            panic!("{}: does not start with the request", t.case);
        };
        let mut out = [0u8; 512];
        let n = client.tx(time(sent), &mut out);
        assert_eq!(
            out[..n].escape_ascii().to_string(),
            request.escape_ascii().to_string(),
            "{}: the request",
            t.case
        );

        let mut conn = Conn::H1 {
            client: Box::new(client),
            key,
            random: Some(random),
            extensions: c.extensions,
        };
        let mut app = ClientApp {
            quiet: c.quiet,
            ..ClientApp::default()
        };
        while let Some(step) = steps.next() {
            let StepKind::Rx(rx) = &step.kind else {
                panic!("{}: {:?} with no rx before it", t.case, step.kind);
            };
            let (mut want, mut want_app, mut want_close) = (Vec::new(), Vec::new(), false);
            while let Some(next) = steps.peek() {
                match &next.kind {
                    StepKind::Tx(b) => want.extend_from_slice(b),
                    StepKind::AppRx(b) => want_app.extend_from_slice(b),
                    StepKind::Close => want_close = true,
                    StepKind::Rx(_) => break,
                }
                steps.next();
            }
            // C's run had nothing fall due: nor may npro's
            let now = time(step.t_us);
            let deadline = match &conn {
                Conn::H1 { client: h1, .. } => h1.next_deadline(),
                Conn::Ws(ws) => ws.next_deadline(),
            };
            assert!(
                deadline.is_none_or(|d| d > now),
                "{} at {}us: a deadline passed",
                t.case,
                step.t_us
            );
            let mut input = rx.clone();
            let got = feed(&mut conn, &mut app, &mut input, now);
            assert_eq!(
                got.escape_ascii().to_string(),
                want.escape_ascii().to_string(),
                "{} at {}us",
                t.case,
                step.t_us
            );
            assert_eq!(
                core::mem::take(&mut app.app_rx),
                want_app,
                "{} at {}us: the app's",
                t.case,
                step.t_us
            );
            let closed = match &conn {
                Conn::Ws(ws) => ws.close().is_some(),
                Conn::H1 { .. } => false,
            };
            assert_eq!(closed, want_close, "{} at {}us: closed", t.case, step.t_us);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn cs_ws_client_transcripts_replay_byte_for_byte() {
        let all = vendored().unwrap();
        for c in &CASES {
            let t = all
                .iter()
                .find(|t| t.case == c.name)
                .unwrap_or_else(|| panic!("no transcript {}", c.name));
            replay(t, c);
        }
    }
}
