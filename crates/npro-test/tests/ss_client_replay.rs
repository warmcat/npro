//! C's h1 client transcripts, replayed through a stream that connected
//! out: the request made as the transcript shows C making it, the
//! server's bytes read in at their times, and what the stream is told
//! compared with what C's client was.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one does not use npro-files or npro-ws"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod ss_client_replay {
    use npro_core::random::SeededRandom;
    use npro_core::time::Instant;
    use npro_h1::client::{Connection, Request, RequestBody, Scheme};
    use npro_h1::server::Config;
    use npro_h1::table::DEFAULT_CAPACITY;
    use npro_io::driver::{Buffers, NetBuffers, Want};
    use npro_ss::event::{End, Kind};
    use npro_ss::id::{ConnId, StreamId};
    use npro_ss::policy::{Listener, Tls, Vhost};
    use npro_ss::ss::{ConnStorage, Slot, Ss};
    use npro_test::{StepKind, Transcript, vendored};

    /// The h1 client transcripts that need no more of a client stream
    /// than its first form has: not the digest retry.
    const CASES: [&str; 7] = [
        "h1-client-get",
        "h1-client-cl-junk",
        "h1-client-cl-twice",
        "h1-client-te-list",
        "h1-client-head-chunked",
        "h1-client-head-cl",
        "h1-client-304-cl",
    ];

    /// A stream's own state: the body it was given, and what it was told
    /// of its response.
    #[derive(Default)]
    struct App {
        body: Vec<u8>,
        status: Option<u16>,
        ended: bool,
        gone: bool,
    }

    type S<'s> = Ss<'s, App, Vec<u8>, SeededRandom>;

    /// A listener the streams never use: a policy has one.
    const VHOSTS: [Vhost<'static>; 1] = [Vhost {
        name: "none",
        routes: &[],
        headers: &[],
        not_found: None,
    }];

    fn slots() -> Vec<Slot<App, Vec<u8>, SeededRandom>> {
        vec![Slot::new(ConnStorage {
            h1: npro_h1::Storage {
                table: vec![0u8; DEFAULT_CAPACITY],
                out: vec![0u8; 512],
            },
            bufs: Buffers {
                rx: vec![0; 4096],
                tx: vec![0; 4096],
                inflate: Vec::new(),
            },
            net: NetBuffers {
                rx: Vec::new(),
                tx: Vec::new(),
            },
        })]
    }

    /// Takes every event: what the stream was told.
    fn events(ss: &mut S<'_>, now: Instant, stream: StreamId) {
        while let Some(ev) = ss.poll_event(now) {
            assert_eq!(ev.stream, stream);
            let user = ev.user;
            match ev.kind {
                Kind::Response(r) => user.status = Some(r.status()),
                Kind::Rx { data, end } => {
                    user.body.extend_from_slice(data);
                    if end == End::Last {
                        user.ended = true;
                    }
                }
                Kind::Disconnected | Kind::ConnectFailed => user.gone = true,
                Kind::ServerTxn(_)
                | Kind::ServerUpgrade { .. }
                | Kind::UpgradeRefused(_)
                | Kind::Tx(_)
                | Kind::Pong
                | Kind::PeerClose { .. } => panic!("not a client's event"),
            }
        }
    }

    /// Reads `input` in and takes what comes, at `now`, until nothing
    /// moves; whether the connection asked to be released.
    fn pump(
        ss: &mut S<'_>,
        conn: ConnId,
        stream: StreamId,
        mut input: &[u8],
        now: Instant,
    ) -> bool {
        for _ in 0..100_000 {
            let mut progress = false;
            match ss.want(now, conn) {
                Ok(Want::Io(io)) => {
                    if let (Some(room), false) = (io.read, input.is_empty()) {
                        let n = room.len().min(input.len());
                        room[..n].copy_from_slice(&input[..n]);
                        ss.read_done(now, conn, n).unwrap();
                        input = &input[n..];
                        progress |= n > 0;
                    }
                }
                Ok(Want::HalfClose) => {
                    ss.half_closed(now, conn).unwrap();
                    progress = true;
                }
                Ok(Want::Release(_)) | Err(_) => return true,
            }
            let before = ss
                .user(stream)
                .map(|u| (u.body.len(), u.status, u.ended, u.gone))
                .ok();
            events(ss, now, stream);
            let after = ss
                .user(stream)
                .map(|u| (u.body.len(), u.status, u.ended, u.gone))
                .ok();
            progress |= before != after;
            if !progress {
                return false;
            }
        }
        panic!("the stream never stops moving");
    }

    fn replay(t: &Transcript) {
        let listeners = [Listener {
            name: "none",
            bind: "unix:/none",
            tls: Tls::Plain,
            h1: Config::default(),
            vhosts: &VHOSTS,
        }];
        let mut slots = slots();
        let mut ss = Ss::new(&listeners, &mut slots).unwrap();
        let time = |t_us: u64| Instant::from_micros(t.t0_us.checked_add(t_us).unwrap());
        let mut steps = t.steps.iter().peekable();
        let Some((sent, StepKind::Tx(want))) = steps.next().map(|s| (s.t_us, &s.kind)) else {
            panic!("{}: does not start with the request", t.case);
        };
        let method: &[u8] = if want.starts_with(b"HEAD ") {
            b"HEAD"
        } else {
            b"GET"
        };
        let stream = ss
            .connect(
                "unix:/sansio",
                None,
                Request {
                    method,
                    path: b"/x",
                    host: Some(b"sansio"),
                    origin: Some(b"sansio"),
                    scheme: Scheme::Http,
                    no_cache: true,
                    connection: Connection::Close,
                    headers: &[],
                    body: RequestBody::None,
                },
                App::default(),
            )
            .unwrap();
        let (conn, c) = ss.next_connect().unwrap();
        assert_eq!(c.address, "unix:/sansio");
        ss.connected(time(sent), conn, None).unwrap();
        let mut request = Vec::new();
        while let Ok(Want::Io(io)) = ss.want(time(sent), conn) {
            let Some(w) = io.write else {
                break;
            };
            let n = w.len();
            request.extend_from_slice(w);
            ss.write_done(time(sent), conn, n).unwrap();
        }
        assert_eq!(
            request.escape_ascii().to_string(),
            want.escape_ascii().to_string(),
            "{}: the request",
            t.case
        );

        let mut released = false;
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
            let now = time(step.t_us);
            if let Ok(Want::Io(io)) = ss.want(now, conn) {
                assert!(
                    io.until.is_none_or(|u| u > now),
                    "{} at {}us: a deadline passed",
                    t.case,
                    step.t_us
                );
            }
            let before = ss.user(stream).map_or(0, |u| u.body.len());
            released = pump(&mut ss, conn, stream, rx, now);
            let body = ss
                .user(stream)
                .map_or(Vec::new(), |u| u.body[before..].to_vec());
            assert_eq!(body, want_body, "{} at {}us: the body", t.case, step.t_us);
            assert_eq!(
                released, want_close,
                "{} at {}us: released",
                t.case, step.t_us
            );
        }
        if released {
            // the connection goes, and the stream is told
            ss.released(conn).unwrap();
            events(&mut ss, time(0), stream);
            assert!(ss.user(stream).is_err(), "{}: still there", t.case);
        } else {
            // C had completed the transaction: the answer was whole
            let u = ss.user(stream).unwrap();
            assert!(u.status.is_some() && u.ended, "{}: not done", t.case);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "reads the transcripts: native runs keep it")]
    fn cs_client_transcripts_replay_through_a_stream() {
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
