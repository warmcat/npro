//! npro's ws server replays C's ws server transcripts byte for byte.
//!
//! Each transcript is one connection to C's `sansio` vhost, whose ws
//! subprotocols are `http`, its default, and `echo`.  npro's h1 server takes
//! the request; one asking for `Upgrade: websocket` goes to npro-ws's
//! handshake, which answers a refusal with C's status page and an accepted
//! upgrade with C's 101, after which the connection is npro-ws'.  The app is
//! C's `callback_echo` in `api-test-sansio`: it echoes each whole message,
//! and after echoing `Bye`, closes once that has gone, with no close frame.
//!
//! What npro writes between one `rx` and the next must be the transcript's
//! `tx` bytes, and the messages it hands the app its `app_rx` bytes.  It
//! writes four bytes at a time, as `ws-server-close-partial` has C do, so
//! every frame here goes in pieces.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses npro-test, npro-h1 and npro-ws"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod ws_server_replay {
    use npro_h1::head;
    use npro_h1::server::{Config, Event as H1Event, Response, Server, TxSource};
    use npro_h1::table::DEFAULT_CAPACITY;
    use npro_h1::token::Token;
    use npro_test::{StepKind, Transcript, vendored};
    use npro_ws::conn::{Event, Kind, Ws};
    use npro_ws::handshake::{self, MAX_101};

    /// The ws server transcripts this half of the phase replays: not the
    /// permessage-deflate ones, which are the next phase's.
    const CASES: [&str; 10] = [
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
    ];

    /// The `sansio` vhost's ws subprotocols, the first its default.
    const PROTOCOLS: [&[u8]; 2] = [b"http", b"echo"];

    /// How much is written at a time.
    const TX_LIMIT: usize = 4;

    /// C's `callback_echo`, and the `sansio` vhost's `http` before it.
    #[derive(Default)]
    struct EchoApp {
        /// The message being gathered.
        msg: Vec<u8>,
        /// What it gave the app, for the transcript's `app_rx`.
        app_rx: Vec<u8>,
        /// The payload going out.
        out: Vec<u8>,
        at: usize,
    }

    impl TxSource for EchoApp {
        fn fill(&mut self, buf: &mut [u8]) -> usize {
            let rest = &self.out[self.at..];
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.at = self.at.checked_add(n).unwrap();
            n
        }
    }

    impl EchoApp {
        /// A piece of a message: the whole of one is echoed.
        fn message(&mut self, ws: &mut Ws, data: &[u8], last: bool) {
            self.msg.extend_from_slice(data);
            self.app_rx.extend_from_slice(data);
            if !last {
                return;
            }
            self.out = core::mem::take(&mut self.msg);
            self.at = 0;
            let len = u64::try_from(self.out.len()).unwrap();
            ws.send(Kind::Text, len).unwrap();
            if self.out == b"Bye" {
                ws.close_when_flushed();
            }
        }
    }

    /// The connection: h1 until an upgrade is accepted, then ws.
    enum Conn {
        H1(Box<Server<Vec<u8>>>),
        Ws(Box<Ws>),
    }

    /// What became of a request.
    enum Answer {
        /// The h1 server answers it.
        H1,
        /// The upgrade is accepted: the connection is ws'.
        Upgraded(Box<Ws>),
    }

    /// The h1 request in hand: an upgrade, or one to the vhost's `http`,
    /// which answers `sansio ok` to anything.
    fn request(s: &mut Server<Vec<u8>>, app: &mut EchoApp) -> Answer {
        let t = s.request();
        let mut up = [0u8; 16];
        let up_len = t.copy(Token::Upgrade, &mut up).unwrap();
        if !up[..up_len].eq_ignore_ascii_case(b"websocket") {
            s.respond(Response {
                status: 200,
                content_type: Some(b"text/plain"),
                content_length: Some(10),
            })
            .unwrap();
            app.out = b"sansio ok\n".to_vec();
            app.at = 0;
            return Answer::H1;
        }
        match handshake::server(t, &PROTOCOLS, Some(0)) {
            Ok(a) => {
                let mut first = [0u8; MAX_101];
                let n = handshake::response_101(&a, PROTOCOLS[a.protocol], &mut first).unwrap();
                Answer::Upgraded(Box::new(Ws::server(&first[..n])))
            }
            Err(r) => {
                s.refuse_upgrade(r.status(), r.header()).unwrap();
                Answer::H1
            }
        }
    }

    /// Hands `input` to the connection, with the app answering, until
    /// neither takes or writes anything more; returns what was written.
    fn feed(conn: &mut Conn, app: &mut EchoApp, input: &mut [u8]) -> Vec<u8> {
        let mut wrote = Vec::new();
        let mut buf = [0u8; TX_LIMIT];
        let mut at = 0usize;
        loop {
            let mut progress = false;
            match conn {
                Conn::H1(s) => {
                    let rx = s.rx(&input[at..]);
                    at = at.checked_add(rx.consumed).unwrap();
                    progress |= rx.consumed > 0;
                    if let Some(H1Event::Request) = rx.event {
                        progress = true;
                        if let Answer::Upgraded(ws) = request(s, app) {
                            *conn = Conn::Ws(ws);
                            continue;
                        }
                    }
                    loop {
                        let tx = s.tx(&mut buf, app);
                        wrote.extend_from_slice(&buf[..tx.written]);
                        if !app.out.is_empty() && app.at == app.out.len() && !s.wants_write() {
                            // the answer has gone: the transaction is done
                            app.out.clear();
                            s.complete();
                            progress = true;
                        }
                        if tx.written == 0 {
                            break;
                        }
                        progress = true;
                    }
                }
                Conn::Ws(ws) => {
                    let rx = ws.rx(&mut input[at..]);
                    let consumed = rx.consumed;
                    let message = match rx.event {
                        Some(Event::Message { data, last, .. }) => Some((data.to_vec(), last)),
                        Some(Event::Pong(_) | Event::PeerClose(_)) | None => None,
                    };
                    at = at.checked_add(consumed).unwrap();
                    progress |= consumed > 0;
                    if let Some((data, last)) = message {
                        app.message(ws, &data, last);
                    }
                    loop {
                        let n = ws.tx(&mut buf, app);
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

    fn replay(t: &Transcript) {
        let server = Server::new(
            vec![0u8; DEFAULT_CAPACITY],
            Config::new(head::Config::new()),
        );
        let mut conn = Conn::H1(Box::new(server.unwrap()));
        let mut app = EchoApp::default();
        let mut steps = t.steps.iter().peekable();
        while let Some(step) = steps.next() {
            let StepKind::Rx(rx) = &step.kind else {
                panic!("{}: {:?} with no rx before it", t.case, step.kind);
            };
            let (mut want, mut want_app) = (Vec::new(), Vec::new());
            while let Some(next) = steps.peek() {
                match &next.kind {
                    StepKind::Tx(b) => want.extend_from_slice(b),
                    StepKind::AppRx(b) => want_app.extend_from_slice(b),
                    StepKind::Rx(_) => break,
                    StepKind::Close => {}
                }
                steps.next();
            }
            let mut input = rx.clone();
            let got = feed(&mut conn, &mut app, &mut input);
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
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn cs_ws_server_transcripts_replay_byte_for_byte() {
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
