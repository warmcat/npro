//! C's transcripts, replayed through npro-io's driver.
//!
//! The protocol crates replay these transcripts on their own; here the
//! same connections go through the driver, which holds them, their role
//! changes and their buffers, with the IO done by an in-memory adapter:
//! each `rx` is read into the room the driver offers, at its time, and the
//! driver's output written four bytes at a time, so every write is short.
//! What is written must be the transcript's `tx` bytes, what the
//! application is given its `app_rx` bytes, and a client must be released
//! exactly where C released it; nothing may fall due between steps, as
//! nothing did in C's run.
//!
//! The applications are the ones the role-level replays use, written
//! against the driver: on the server, C's `sansio` vhost, answering
//! `sansio ok` to h1 and echoing ws messages, closing once `Bye` has gone;
//! on the client, C's `callback_client` saying `Hello` once established,
//! and the h1 client reading a body; and C's `sansio-uri` vhost, its h1
//! server answering with the request's path and arguments.

// held to clippy's rules for tests
#[cfg(test)]
mod driver_replay {
    use core::num::NonZeroU16;

    use npro_core::random::SeededRandom;
    use npro_core::time::Instant;
    use npro_h1::client::{Client, Connection, Event as H1c, Request, Scheme};
    use npro_h1::head;
    use npro_h1::server::{Config, Event as H1s, Response, Server, TxSource};
    use npro_h1::table::DEFAULT_CAPACITY;
    use npro_h1::token::Token;
    use npro_io::conn::{Conn, Event, Role, RoleMut};
    use npro_io::driver::{Buffers, Driver, Want};
    use npro_test::{StepKind, Transcript, vendored};
    use npro_ws::conn::{Event as WsEvent, Kind, Ws};
    use npro_ws::handshake::{self, ClientKey, MAX_101, MAX_REQUEST_LINES};
    use npro_ws::pmd;

    type D = Driver<Vec<u8>, SeededRandom, Vec<u8>>;

    /// How much the adapter writes at a time.
    const TX_LIMIT: usize = 4;

    fn driver(conn: Conn<Vec<u8>, SeededRandom>) -> D {
        Driver::new(
            conn,
            Buffers {
                rx: vec![0; 4096],
                tx: vec![0; 4096],
                inflate: vec![0; pmd::RX_CHUNK],
            },
        )
    }

    /// The application, C's `sansio` vhost and `callback_client`: what it
    /// was given, and its payload going out.
    #[derive(Default)]
    struct Sansio {
        /// What it was given, for the transcript's `app_rx`.
        app_rx: Vec<u8>,
        /// A ws message being gathered, to echo whole.
        msg: Vec<u8>,
        out: Vec<u8>,
        at: usize,
        /// What its h1 transaction waits on.
        h1: H1Next,
        /// A ws client, before its 101: its key and the rest of its random.
        client: Option<(ClientKey, SeededRandom, Option<&'static [u8]>)>,
        /// Which of C's applications it is.
        is: Is,
    }

    /// Which of C's applications [`Sansio`] is.
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    enum Is {
        /// The `sansio` vhost, or a ws client saying `Hello`.
        #[default]
        Sansio,
        /// A ws client that stays quiet once established.
        Quiet,
        /// The `sansio-uri` vhost.
        Uri,
    }

    /// What an h1 transaction waits on.
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    enum H1Next {
        #[default]
        Nothing,
        /// The answer is going: complete once it went.
        Sent,
        /// `/body-done`: the answer comes from the body.
        Body,
    }

    impl TxSource for Sansio {
        fn fill(&mut self, buf: &mut [u8]) -> usize {
            let rest = &self.out[self.at..];
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.at = self.at.checked_add(n).unwrap();
            n
        }
    }

    impl Sansio {
        fn payload(&mut self, out: Vec<u8>) {
            self.out = out;
            self.at = 0;
        }

        /// Answers 200 `text/plain`, saying `len`, with `payload`.
        fn answer(&mut self, conn: &mut Conn<Vec<u8>, SeededRandom>, len: u64, payload: &[u8]) {
            let RoleMut::H1Server(server) = conn.role_mut() else {
                panic!("not an h1 server");
            };
            server
                .respond(Response {
                    status: 200,
                    content_type: Some(b"text/plain"),
                    content_length: Some(len),
                })
                .unwrap();
            self.payload(payload.to_vec());
            self.h1 = H1Next::Sent;
        }

        /// C's `callback_uri`, for what the `sansio-uri` cases ask of it:
        /// the path, a newline and the urlargs; `/short`, saying 10 and
        /// giving 3 (none to a HEAD); `/body-done` from the body's first
        /// piece.
        fn uri(&mut self, conn: &mut Conn<Vec<u8>, SeededRandom>) {
            let Role::H1Server(server) = conn.role() else {
                panic!("not an h1 server");
            };
            let t = server.request();
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
                b"/short" => self.answer(conn, 10, if head { b"" } else { b"abc" }),
                b"/body-done" => self.h1 = H1Next::Body,
                _ => {
                    let body = [path, b"\n".to_vec(), args].concat();
                    let len = u64::try_from(body.len()).unwrap();
                    self.answer(conn, len, &body);
                }
            }
        }

        /// The `sansio` vhost: ws to its `http` (default) or `echo`, with
        /// permessage-deflate on `sansio-pmd`; anything else `sansio ok`.
        fn request(&mut self, conn: &mut Conn<Vec<u8>, SeededRandom>, now: Instant) {
            const PROTOCOLS: [&[u8]; 2] = [b"http", b"echo"];
            if self.is == Is::Uri {
                self.uri(conn);
                return;
            }
            let Role::H1Server(s) = conn.role() else {
                panic!("not an h1 server");
            };
            let t = s.request();
            let mut up = [0u8; 16];
            let up_len = t.copy(Token::Upgrade, &mut up).unwrap();
            if !up[..up_len].eq_ignore_ascii_case(b"websocket") {
                self.answer(conn, 10, b"sansio ok\n");
                return;
            }
            let pmd = (t.first(Token::Host) == Some(b"sansio-pmd".as_slice()))
                .then(|| pmd::server_accept(t).unwrap())
                .flatten();
            match handshake::server(t, &PROTOCOLS, Some(0)) {
                Ok(a) => {
                    let lines = pmd
                        .as_ref()
                        .map_or(&[][..], pmd::ServerAccepted::header_lines);
                    let mut first = [0u8; MAX_101];
                    let n = handshake::response_101(&a, PROTOCOLS[a.protocol], lines, &mut first)
                        .unwrap();
                    let mut ws = Ws::server(&first[..n], now);
                    if let Some(p) = pmd {
                        ws = ws.with_pmd(p.params());
                    }
                    let storage = conn.accept_ws(ws).unwrap();
                    assert_eq!(storage.len(), DEFAULT_CAPACITY);
                }
                Err(r) => {
                    let RoleMut::H1Server(server) = conn.role_mut() else {
                        panic!("not an h1 server");
                    };
                    server.refuse_upgrade(now, r.status(), r.header()).unwrap();
                }
            }
        }

        /// A ws client's 101 is in: checked, the connection becomes ws,
        /// masking from the rest of the stream, and says hello.
        fn response(&mut self, conn: &mut Conn<Vec<u8>, SeededRandom>, now: Instant) {
            let Some((key, random, extensions)) = self.client.take() else {
                return;
            };
            let Role::H1Client(c) = conn.role() else {
                panic!("not an h1 client");
            };
            let checked = key
                .check(c.status(), c.response(), Some(b"echo"), extensions)
                .unwrap();
            let mut ws = Ws::client(random, now);
            if let Some(said) = checked.extensions {
                ws = ws.with_pmd(pmd::client_accept(said).unwrap());
            }
            conn.upgraded_ws(ws).unwrap();
            if self.is != Is::Quiet {
                let RoleMut::WsClient(client) = conn.role_mut() else {
                    panic!("not a ws client");
                };
                client.send(Kind::Text, 5).unwrap();
                self.payload(b"Hello".to_vec());
            }
        }

        /// A piece of a ws message: a server echoes it whole, and after
        /// `Bye`, closes once that has gone.
        fn message(
            &mut self,
            conn: &mut Conn<Vec<u8>, SeededRandom>,
            now: Instant,
            data: &[u8],
            last: bool,
        ) {
            self.app_rx.extend_from_slice(data);
            let RoleMut::WsServer(ws) = conn.role_mut() else {
                return;
            };
            self.msg.extend_from_slice(data);
            if !last {
                return;
            }
            let msg = core::mem::take(&mut self.msg);
            ws.send(Kind::Text, u64::try_from(msg.len()).unwrap())
                .unwrap();
            if msg == b"Bye" {
                ws.close_when_flushed(now);
            }
            self.payload(msg);
        }
    }

    /// Reads `input` in and answers what comes, writing the driver's
    /// output a few bytes at a time, until nothing moves; returns what was
    /// written.
    fn pump(d: &mut D, app: &mut Sansio, mut input: &[u8], now: Instant) -> Vec<u8> {
        let mut wrote = Vec::new();
        // a driver that goes round without end fails, not hangs
        for _ in 0..100_000 {
            let mut progress = false;
            if !input.is_empty() {
                if let Want::Io(io) = d.want(now, app) {
                    if let Some(room) = io.read {
                        let n = room.len().min(input.len());
                        room[..n].copy_from_slice(&input[..n]);
                        d.read_done(now, n);
                        input = &input[n..];
                        progress |= n > 0;
                    }
                }
            }
            for _ in 0..100_000 {
                let Some(mut step) = d.poll_rx(now) else {
                    break;
                };
                progress = true;
                match step.event() {
                    Some(Event::H1Server(H1s::Request)) => {
                        app.request(step.conn(), now);
                        step.request_write();
                    }
                    Some(Event::H1Client(H1c::Response)) => {
                        app.response(step.conn(), now);
                        step.request_write();
                    }
                    Some(Event::H1Client(H1c::Body(b))) => app.app_rx.extend_from_slice(b),
                    Some(Event::H1Server(H1s::Body(_))) if app.h1 == H1Next::Body => {
                        app.answer(step.conn(), 3, b"ok\n");
                        step.request_write();
                    }
                    Some(Event::Ws(WsEvent::Message { data, last, .. })) => {
                        app.message(step.conn(), now, data, last);
                        step.request_write();
                    }
                    Some(
                        Event::H1Server(H1s::Body(_) | H1s::BodyEnd)
                        | Event::H1Client(H1c::BodyEnd)
                        | Event::Ws(WsEvent::Pong(_) | WsEvent::PeerClose(_)),
                    )
                    | None => {}
                }
            }
            if let Want::Io(io) = d.want(now, app) {
                if let Some(w) = io.write {
                    let n = w.len().min(TX_LIMIT);
                    wrote.extend_from_slice(&w[..n]);
                    d.write_done(now, n);
                    progress = true;
                }
            }
            // the answer went: the h1 transaction is done
            if app.h1 == H1Next::Sent && app.at == app.out.len() {
                if let RoleMut::H1Server(s) = d.conn().role_mut() {
                    if !s.wants_write() {
                        app.h1 = H1Next::Nothing;
                        s.complete(now);
                        progress = true;
                    }
                }
            }
            if !progress {
                return wrote;
            }
        }
        panic!("the driver never stops moving");
    }

    /// Whether the driver lets the connection go.
    fn released(d: &mut D, app: &mut Sansio, now: Instant) -> bool {
        matches!(d.want(now, app), Want::Release(_))
    }

    /// Replays `t`'s steps after `skip` of them, through `d` with `app`.
    fn replay(t: &Transcript, d: &mut D, app: &mut Sansio, skip: usize) {
        let time = |t_us: u64| Instant::from_micros(t.t0_us.checked_add(t_us).unwrap());
        let mut steps = t.steps.iter().skip(skip).peekable();
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
            if let Want::Io(io) = d.want(now, app) {
                assert!(
                    io.until.is_none_or(|u| u > now),
                    "{} at {}us: a deadline passed",
                    t.case,
                    step.t_us
                );
            }
            let got = pump(d, app, rx, now);
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
            if t.side == npro_test::Side::Client {
                assert_eq!(
                    released(d, app, now),
                    want_close,
                    "{} at {}us: released",
                    t.case,
                    step.t_us
                );
            }
        }
    }

    fn transcript(all: &[Transcript], case: &str) -> Transcript {
        all.iter()
            .find(|t| t.case == case)
            .unwrap_or_else(|| panic!("no transcript {case}"))
            .clone()
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn cs_ws_server_transcripts_replay_through_the_driver() {
        let all = vendored().unwrap();
        for case in [
            "h1-ws-server",
            "ws-server-version-8",
            "ws-server-no-version",
            "ws-server-conn-no-upgrade",
            "ws-server-no-subprotocol",
            "ws-server-not-get",
            "ws-server-ping-close",
            "ws-server-close-partial",
            "ws-server-close-when-flushed",
            "ws-server-huge-frame",
            "ws-server-pmd-rsv1-continuation",
        ] {
            let t = transcript(&all, case);
            let start = t.steps.first().map_or(0, |s| s.t_us);
            let s = Server::new(
                vec![0u8; DEFAULT_CAPACITY],
                Config::new(head::Config::new()),
                Instant::from_micros(t.t0_us.checked_add(start).unwrap()),
            )
            .unwrap();
            replay(
                &t,
                &mut driver(Conn::h1_server(s)),
                &mut Sansio::default(),
                0,
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn cs_h1_server_transcripts_replay_through_the_driver() {
        let all = vendored().unwrap();
        for case in [
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
        ] {
            let t = transcript(&all, case);
            // the sansio-uri vhost's context limits
            let cfg = head::Config::new()
                .with_limit(Token::GetUri, NonZeroU16::new(33).unwrap())
                .with_limit(Token::UserAgent, NonZeroU16::new(16).unwrap());
            let start = t.steps.first().map_or(0, |s| s.t_us);
            let s = Server::new(
                vec![0u8; DEFAULT_CAPACITY],
                Config::new(cfg),
                Instant::from_micros(t.t0_us.checked_add(start).unwrap()),
            )
            .unwrap();
            let mut app = Sansio {
                is: Is::Uri,
                ..Sansio::default()
            };
            replay(&t, &mut driver(Conn::h1_server(s)), &mut app, 0);
        }
    }

    /// Checks the request a client writes first is the transcript's.
    fn request_goes(t: &Transcript, d: &mut D, app: &mut Sansio) {
        let Some(first) = t.steps.first() else {
            panic!("{}: empty", t.case);
        };
        let StepKind::Tx(request) = &first.kind else {
            panic!("{}: does not start with the request", t.case);
        };
        let now = Instant::from_micros(t.t0_us.checked_add(first.t_us).unwrap());
        let got = pump(d, app, b"", now);
        assert_eq!(
            got.escape_ascii().to_string(),
            request.escape_ascii().to_string(),
            "{}: the request",
            t.case
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn cs_ws_client_transcripts_replay_through_the_driver() {
        let all = vendored().unwrap();
        for (case, quiet, extensions) in [
            ("ws-client", false, None),
            ("ws-client-interim", false, None),
            ("ws-client-ping-close", true, None),
            ("ws-client-huge-frame", false, None),
            ("ws-client-rsv1-no-ext", false, None),
            ("ws-client-rsv2", false, None),
            ("ws-client-pmd-rsv2", true, Some(pmd::OFFER)),
            ("ws-client-pmd-rsv1-continuation", true, Some(pmd::OFFER)),
            ("ws-client-pmd-rsv1-ping", true, Some(pmd::OFFER)),
        ] {
            let t = transcript(&all, case);
            let seed = t.seed.unwrap_or_else(|| panic!("{case}: not seeded"));
            let mut random = SeededRandom::new(seed.get());
            let key = ClientKey::new(&mut random).unwrap();
            let mut lines = [0u8; MAX_REQUEST_LINES + 32];
            let n = key
                .request_lines(Some(b"echo"), extensions, &mut lines)
                .unwrap();
            let c = Client::new(
                vec![0u8; DEFAULT_CAPACITY],
                Request {
                    method: b"GET",
                    path: b"/echo",
                    host: Some(b"sansio"),
                    origin: Some(b"sansio"),
                    scheme: Scheme::Http,
                    no_cache: true,
                    connection: Connection::Upgrade(&lines[..n]),
                },
            )
            .unwrap();
            let mut d = driver(Conn::h1_client(c));
            let mut app = Sansio {
                client: Some((key, random, extensions)),
                is: if quiet { Is::Quiet } else { Is::Sansio },
                ..Sansio::default()
            };
            request_goes(&t, &mut d, &mut app);
            replay(&t, &mut d, &mut app, 1);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn cs_h1_client_transcripts_replay_through_the_driver() {
        let all = vendored().unwrap();
        for case in [
            "h1-client-get",
            "h1-client-cl-junk",
            "h1-client-cl-twice",
            "h1-client-te-list",
            "h1-client-head-chunked",
            "h1-client-head-cl",
            "h1-client-304-cl",
        ] {
            let t = transcript(&all, case);
            let head = matches!(
                t.steps.first().map(|s| &s.kind),
                Some(StepKind::Tx(r)) if r.starts_with(b"HEAD ")
            );
            let c = Client::new(
                vec![0u8; DEFAULT_CAPACITY],
                Request {
                    method: if head { b"HEAD" } else { b"GET" },
                    path: b"/x",
                    host: Some(b"sansio"),
                    origin: Some(b"sansio"),
                    scheme: Scheme::Http,
                    no_cache: true,
                    connection: Connection::Close,
                },
            )
            .unwrap();
            let mut d = driver(Conn::h1_client(c));
            let mut app = Sansio::default();
            request_goes(&t, &mut d, &mut app);
            replay(&t, &mut d, &mut app, 1);
        }
    }
}
