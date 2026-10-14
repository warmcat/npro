//! C's server transcripts, replayed through an accepted npro-ss stream.
//!
//! The driver replays these connections on its own (`driver_replay.rs`);
//! here each is a stream accepted on a listener of npro-ss, the IO done by
//! an in-memory adapter as there: each `rx` read in at its time, the
//! output written four bytes at a time.  What is written must be the
//! transcript's `tx` bytes, and what the stream is given its `app_rx`.
//!
//! The applications are C's, written against SS2's events and calls: the
//! `sansio` vhost, answering `sansio ok` to h1 and echoing ws messages,
//! destroying its stream once `Bye` has gone, its ws handshake done by
//! npro-ss as the listener says; and the `sansio-uri` vhost, answering
//! with the request's path and arguments.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one does not use npro-files"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod ss_server_replay {
    use core::num::NonZeroU16;

    use npro_core::random::SeededRandom;
    use npro_core::time::Instant;
    use npro_h1::head;
    use npro_h1::server::Config;
    use npro_h1::table::DEFAULT_CAPACITY;
    use npro_h1::token::Token;
    use npro_io::driver::{Buffers, NetBuffers, Want};
    use npro_ss::event::{End, Filled, Kind, Response, Txn};
    use npro_ss::id::{ConnId, ListenerId};
    use npro_ss::policy::{Deflate, Listener, Match, Payload, Route, Tls, Vhost, Ws, WsServer};
    use npro_ss::ss::{ConnStorage, Slot, Ss};
    use npro_test::{StepKind, Transcript, vendored};
    use npro_ws::pmd;

    type S<'s> = Ss<'s, App, Vec<u8>, SeededRandom>;

    /// How much the adapter writes at a time.
    const TX_LIMIT: usize = 4;

    /// The `sansio` vhost's ws subprotocols, the first taken by default.
    const PROTOCOLS: [&[u8]; 2] = [b"http", b"echo"];

    /// Which of C's applications a stream is.
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    enum Is {
        /// The `sansio` vhost.
        #[default]
        Sansio,
        /// The `sansio-uri` vhost.
        Uri,
    }

    /// What an h1 transaction waits on.
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    enum H1Next {
        #[default]
        Nothing,
        /// `/body-done`: the answer comes from the body.
        Body,
    }

    /// A stream's own state: C's application, and its payload going out.
    #[derive(Default)]
    struct App {
        is: Is,
        /// A ws message being gathered, to echo whole.
        msg: Vec<u8>,
        out: Vec<u8>,
        at: usize,
        h1: H1Next,
        /// It echoes `Bye`: once that has gone, it is done.
        bye: bool,
    }

    impl App {
        /// Answers 200 `text/plain`, saying `len`, with `payload`.
        fn answer(&mut self, txn: &mut Txn<'_, Vec<u8>>, len: u64, payload: &[u8]) {
            txn.respond(Response {
                status: 200,
                content_type: Some(b"text/plain"),
                content_length: Some(len),
                headers: &[],
            })
            .unwrap();
            self.out = payload.to_vec();
            self.at = 0;
        }

        /// C's `callback_uri`: the path, a newline and the urlargs;
        /// `/short`, saying 10 and giving 3 (none to a HEAD); `/body-done`
        /// from the body's first piece.  Whether it has an answer to send.
        fn uri(&mut self, txn: &mut Txn<'_, Vec<u8>>) -> bool {
            let path = txn.path().unwrap_or_default().to_vec();
            let head = txn.method() == Some(b"HEAD");
            let args = txn.args().collect::<Vec<_>>().join(&b'&');
            match path.as_slice() {
                b"/short" => self.answer(txn, 10, if head { b"" } else { b"abc" }),
                b"/body-done" => {
                    self.h1 = H1Next::Body;
                    return false;
                }
                _ => {
                    let body = [path, b"\n".to_vec(), args].concat();
                    let len = u64::try_from(body.len()).unwrap();
                    self.answer(txn, len, &body);
                }
            }
            true
        }

        /// The stream's payload, the last of it saying so.
        fn fill(&mut self, buf: &mut [u8]) -> Filled {
            let rest = &self.out[self.at..];
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            self.at = self.at.checked_add(n).unwrap();
            if self.at == self.out.len() {
                Filled::Last(n)
            } else {
                Filled::More(n)
            }
        }
    }

    fn listener(is: Is, deflate: Deflate) -> Listener<'static> {
        // the sansio-uri vhost's context limits
        let h1 = match is {
            Is::Sansio => head::Config::new(),
            Is::Uri => head::Config::new()
                .with_limit(Token::GetUri, NonZeroU16::new(33).unwrap())
                .with_limit(Token::UserAgent, NonZeroU16::new(16).unwrap()),
        };
        // C's apps serve everything on their vhost: one route, over all
        let routes: &'static [Route<'static>] = vec![Route {
            path: "/",
            matching: Match::Prefix,
            to: "app",
            ws: match is {
                Is::Sansio => Ws::Taken(WsServer {
                    protocols: &PROTOCOLS,
                    default: Some(0),
                    payload: Payload::Text,
                    deflate,
                }),
                Is::Uri => Ws::NotTaken,
            },
            headers: &[],
        }]
        .leak();
        let vhosts: &'static [Vhost<'static>] = vec![Vhost {
            name: "sansio",
            routes,
            headers: &[],
            not_found: None,
        }]
        .leak();
        Listener {
            name: "sansio",
            bind: "unix:/sansio",
            tls: Tls::Plain,
            h1: Config::new(h1),
            vhosts,
        }
    }

    fn slots() -> Vec<Slot<App, Vec<u8>, SeededRandom>> {
        (0..2)
            .map(|_| {
                Slot::new(ConnStorage {
                    h1: npro_h1::Storage {
                        table: vec![0u8; DEFAULT_CAPACITY],
                        out: vec![0u8; 512],
                    },
                    bufs: Buffers {
                        rx: vec![0; 4096],
                        tx: vec![0; 4096],
                        inflate: vec![0; pmd::RX_CHUNK],
                    },
                    net: NetBuffers {
                        rx: Vec::new(),
                        tx: Vec::new(),
                    },
                })
            })
            .collect()
    }

    /// What the application does after an event, by a call on the
    /// streams: the event borrows them, so its calls come after it.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Then {
        Nothing,
        /// Answer 200 `text/plain` this long, its payload to go.
        Respond(u64),
        RequestTx,
        RequestTxLen(u64),
        Destroy,
    }

    /// The applications' answers to every event there is, at `now`:
    /// whether there was any.
    fn events(ss: &mut S<'_>, now: Instant, is: Is, app_rx: &mut Vec<u8>) -> bool {
        let mut any = false;
        while let Some(ev) = ss.poll_event(now) {
            any = true;
            let (stream, user) = (ev.stream, ev.user);
            user.is = is;
            let then = match ev.kind {
                Kind::ServerTxn(mut txn) => {
                    let answered = match user.is {
                        Is::Uri => user.uri(&mut txn),
                        Is::Sansio => {
                            user.answer(&mut txn, 10, b"sansio ok\n");
                            true
                        }
                    };
                    if answered {
                        Then::RequestTx
                    } else {
                        Then::Nothing
                    }
                }
                Kind::Rx { data, end } => {
                    // C's transcripts record what a ws message gave its
                    // application, not a request's body
                    if user.is == Is::Sansio {
                        app_rx.extend_from_slice(data);
                    }
                    user.msg.extend_from_slice(data);
                    if user.h1 == H1Next::Body {
                        // the answer is made from the body's first piece
                        user.h1 = H1Next::Nothing;
                        user.out = b"ok\n".to_vec();
                        user.at = 0;
                        Then::Respond(3)
                    } else if end == End::Last && user.is == Is::Sansio {
                        let msg = core::mem::take(&mut user.msg);
                        user.bye = msg == b"Bye";
                        let len = u64::try_from(msg.len()).unwrap();
                        user.out = msg;
                        user.at = 0;
                        Then::RequestTxLen(len)
                    } else {
                        Then::Nothing
                    }
                }
                Kind::Tx(t) => {
                    t.fill(|buf| user.fill(buf));
                    if user.bye && user.at == user.out.len() {
                        Then::Destroy
                    } else {
                        Then::Nothing
                    }
                }
                Kind::ServerUpgrade { protocol, route } => {
                    assert!(PROTOCOLS.contains(&protocol));
                    assert_eq!(route.to, "app");
                    Then::Nothing
                }
                Kind::UpgradeRefused(_)
                | Kind::Pong
                | Kind::PeerClose { .. }
                | Kind::Disconnected => Then::Nothing,
            };
            match then {
                Then::Nothing => {}
                Then::Respond(len) => {
                    ss.respond(
                        stream,
                        Response {
                            status: 200,
                            content_type: Some(b"text/plain"),
                            content_length: Some(len),
                            headers: &[],
                        },
                    )
                    .unwrap();
                    ss.request_tx(stream).unwrap();
                }
                Then::RequestTx => ss.request_tx(stream).unwrap(),
                Then::RequestTxLen(len) => ss.request_tx_len(stream, len).unwrap(),
                Then::Destroy => ss.destroy(now, stream).unwrap(),
            }
        }
        any
    }

    /// Reads `input` in and answers what comes, writing the connection's
    /// output a few bytes at a time, until nothing moves; returns what was
    /// written.
    fn pump(
        ss: &mut S<'_>,
        conn: ConnId,
        is: Is,
        mut input: &[u8],
        now: Instant,
        app_rx: &mut Vec<u8>,
    ) -> Vec<u8> {
        let mut wrote = Vec::new();
        for _ in 0..100_000 {
            let mut progress = false;
            if !input.is_empty() {
                if let Ok(Want::Io(io)) = ss.want(now, conn) {
                    if let Some(room) = io.read {
                        let n = room.len().min(input.len());
                        room[..n].copy_from_slice(&input[..n]);
                        ss.read_done(now, conn, n).unwrap();
                        input = &input[n..];
                        progress |= n > 0;
                    }
                }
            }
            progress |= events(ss, now, is, app_rx);
            if let Ok(Want::Io(io)) = ss.want(now, conn) {
                if let Some(w) = io.write {
                    let n = w.len().min(TX_LIMIT);
                    wrote.extend_from_slice(&w[..n]);
                    ss.write_done(now, conn, n).unwrap();
                    progress = true;
                }
            }
            if !progress {
                return wrote;
            }
        }
        panic!("the streams never stop moving");
    }

    fn replay(t: &Transcript, is: Is, deflate: Deflate) {
        let listeners = [listener(is, deflate)];
        let mut slots = slots();
        let mut ss = Ss::new(&listeners, &mut slots).unwrap();
        let time = |t_us: u64| Instant::from_micros(t.t0_us.checked_add(t_us).unwrap());
        let start = t.steps.first().map_or(0, |s| s.t_us);
        let conn = ss.accepted(time(start), ListenerId::new(0), None).unwrap();
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
                    StepKind::Close => {}
                    StepKind::Rx(_) => break,
                }
                steps.next();
            }
            // C's run had nothing fall due: nor may npro's
            let now = time(step.t_us);
            if let Ok(Want::Io(io)) = ss.want(now, conn) {
                assert!(
                    io.until.is_none_or(|u| u > now),
                    "{} at {}us: a deadline passed",
                    t.case,
                    step.t_us
                );
            }
            let mut app_rx = Vec::new();
            let got = pump(&mut ss, conn, is, rx, now, &mut app_rx);
            assert_eq!(
                got.escape_ascii().to_string(),
                want.escape_ascii().to_string(),
                "{} at {}us",
                t.case,
                step.t_us
            );
            assert_eq!(
                app_rx.escape_ascii().to_string(),
                want_app.escape_ascii().to_string(),
                "{} at {}us: the app's",
                t.case,
                step.t_us
            );
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
    fn cs_ws_server_transcripts_replay_through_a_stream() {
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
        ] {
            replay(&transcript(&all, case), Is::Sansio, Deflate::Off);
        }
        // the vhost that takes permessage-deflate
        replay(
            &transcript(&all, "ws-server-pmd-rsv1-continuation"),
            Is::Sansio,
            Deflate::Offered,
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn cs_h1_server_transcripts_replay_through_a_stream() {
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
            replay(&transcript(&all, case), Is::Uri, Deflate::Off);
        }
    }
}
