//! C's file-serving transcripts, replayed through npro-files on an
//! accepted npro-ss stream: the `sansio-404` vhost, whose mounts serve
//! files from a directory that is not there, falling back to its 404
//! document, `/404.html`, and whose `/cb` is the application's.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one does not use npro-ws"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod files_replay {
    use npro_core::random::SeededRandom;
    use npro_core::time::Instant;
    use npro_files::{Cache, Fs, Mount, Opened, Scheme, Served, Serving, serve};
    use npro_h1::server::Config;
    use npro_h1::table::DEFAULT_CAPACITY;
    use npro_io::driver::{Buffers, NetBuffers, Want};
    use npro_ss::event::{Filled, Kind};
    use npro_ss::id::{ConnId, ListenerId};
    use npro_ss::policy::{Listener, Match, Route, Tls, Vhost, Ws};
    use npro_ss::ss::{ConnStorage, Slot, Ss};
    use npro_test::{StepKind, Transcript, vendored};

    /// How much the adapter writes at a time.
    const TX_LIMIT: usize = 4;

    /// C's `/nonexistent-lws-sansio`: nothing is there.
    struct Nothing;

    impl Fs for Nothing {
        type File = ();

        fn open(&mut self, _: &[u8]) -> Option<Opened<()>> {
            None
        }
    }

    const NOWHERE: Mount<'static> = Mount {
        root: "/nonexistent-lws-sansio",
        default: "index.html",
        cache: Cache::NoStore,
        mimes: &[],
    };

    /// C's mounts, in its order: `/t`, `/`, `/d` and `/cb`.
    const ROUTES: [Route<'static>; 4] = [
        Route {
            path: "/t",
            matching: Match::Prefix,
            to: "files",
            ws: Ws::NotTaken,
            headers: &[],
        },
        Route {
            path: "/",
            matching: Match::Prefix,
            to: "files",
            ws: Ws::NotTaken,
            headers: &[],
        },
        Route {
            path: "/d",
            matching: Match::Prefix,
            to: "files",
            ws: Ws::NotTaken,
            headers: &[],
        },
        Route {
            path: "/cb",
            matching: Match::Prefix,
            to: "app",
            ws: Ws::NotTaken,
            headers: &[],
        },
    ];

    const VHOSTS: [Vhost<'static>; 1] = [Vhost {
        name: "sansio-404",
        routes: &ROUTES,
        headers: &[],
        not_found: Some("/404.html"),
    }];

    #[derive(Default)]
    enum App {
        #[default]
        Idle,
        Answered,
        Body(Serving<(), Vec<u8>>),
    }

    type S<'s> = Ss<'s, App, Vec<u8>, SeededRandom>;

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

    /// The application: files routes served by npro-files, `/cb` by
    /// C's `callback_http`, which answers 404.
    fn events(ss: &mut S<'_>, now: Instant) -> bool {
        let mut any = false;
        while let Some(ev) = ss.poll_event(now) {
            any = true;
            let (stream, user) = (ev.stream, ev.user);
            match ev.kind {
                Kind::ServerTxn(mut txn) => {
                    let served = match txn.route().map(|r| r.route.to) {
                        Some("files") => serve(&NOWHERE, &mut txn, &mut Nothing, Scheme::Http),
                        Some(_) | None => txn.status(404).map(|()| Served::Answered),
                    }
                    .unwrap();
                    *user = match served {
                        Served::Answered => App::Answered,
                        Served::Body(s) => App::Body(s),
                    };
                    ss.request_tx(stream).unwrap();
                }
                Kind::Tx(tx) => {
                    tx.fill(|buf| match user {
                        App::Idle | App::Answered => Filled::Last(0),
                        App::Body(s) => s.fill(buf),
                    });
                }
                Kind::ServerUpgrade { .. }
                | Kind::UpgradeRefused(_)
                | Kind::Rx { .. }
                | Kind::Pong
                | Kind::PeerClose { .. }
                | Kind::Response(_)
                | Kind::ConnectFailed
                | Kind::Disconnected => {}
            }
        }
        any
    }

    /// Reads `input` in and answers what comes, writing the connection's
    /// output a few bytes at a time, until nothing moves.
    fn pump(ss: &mut S<'_>, conn: ConnId, mut input: &[u8], now: Instant) -> Vec<u8> {
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
            progress |= events(ss, now);
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

    fn replay(t: &Transcript) {
        let listeners = [Listener {
            name: "sansio-404",
            bind: "unix:/sansio",
            tls: Tls::Plain,
            h1: Config::default(),
            vhosts: &VHOSTS,
        }];
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
            let mut want = Vec::new();
            while let Some(next) = steps.peek() {
                match &next.kind {
                    StepKind::Tx(b) => want.extend_from_slice(b),
                    StepKind::AppRx(_) | StepKind::Close => {}
                    StepKind::Rx(_) => break,
                }
                steps.next();
            }
            let got = pump(&mut ss, conn, rx, time(step.t_us));
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
    fn cs_404_document_transcript_replays_through_the_file_service() {
        let all = vendored().unwrap();
        let t = all
            .iter()
            .find(|t| t.case == "h1-404-keepalive")
            .expect("no transcript h1-404-keepalive");
        replay(t);
    }
}
