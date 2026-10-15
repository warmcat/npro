//! npro-ss over real sockets, carried by npro-io's threads adapter.
//!
//! The streams are those the in-memory tests drive; here the adapter
//! accepts on TCP and unix domain sockets bound on this machine, and std's
//! sockets are the peers: an h1 request answered, ws echoed, more clients
//! than there are slots, and the stop.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses npro-core, npro-h1, npro-io and npro-ss"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod threads {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::thread;

    use npro_core::random::SeededRandom;
    use npro_core::time::Instant;
    use npro_h1::client::{Connection, Request, RequestBody, Scheme};
    use npro_h1::server::Config;
    use npro_io::driver::{Buffers, NetBuffers};
    use npro_io::threads::{Jobs, Listening, Stop, Workers, bind, serve};
    use npro_ss::event::{End, Filled, Kind, Response};
    use npro_ss::id::{ListenerId, StreamId};
    use npro_ss::policy::{Deflate, Listener, Match, Payload, Route, Tls, Vhost, Ws, WsServer};
    use npro_ss::ss::{ConnStorage, Slot, Ss};

    /// A stream's own state: what it has to send.
    #[derive(Default)]
    struct App {
        out: Vec<u8>,
        at: usize,
        /// A ws message being gathered, to echo whole.
        msg: Vec<u8>,
        /// A client stream's: the accepted stream whose answer it fetches.
        fetching_for: Option<StreamId>,
    }

    /// What `/fetch` is answered with: `/hello`'s answer, fetched from
    /// this very server by a stream connecting out.
    const FETCH: &[u8] = b"/hello";

    type S<'s> = Ss<'s, App, Vec<u8>, SeededRandom>;

    const ECHO: [&[u8]; 1] = [b"echo"];

    /// The length of `/big`'s answer.
    const BIG: usize = 300_000;

    const ROUTES: [Route<'static>; 1] = [Route {
        path: "/",
        matching: Match::Prefix,
        to: "echo",
        ws: Ws::Taken(WsServer {
            protocols: &ECHO,
            default: Some(0),
            payload: Payload::Text,
            deflate: Deflate::Off,
        }),
        headers: &[],
    }];

    const VHOSTS: [Vhost<'static>; 1] = [Vhost {
        name: "test",
        routes: &ROUTES,
        headers: &[(b"x-test", b"1")],
        not_found: None,
    }];

    fn listener(bind: &'static str) -> Listener<'static> {
        Listener {
            name: "test",
            bind,
            tls: Tls::Plain,
            h1: Config::default(),
            vhosts: &VHOSTS,
        }
    }

    fn slots(n: usize) -> Vec<Slot<App, Vec<u8>, SeededRandom>> {
        (0..n)
            .map(|_| {
                Slot::new(ConnStorage {
                    h1: npro_h1::Storage {
                        table: vec![0; 2048],
                        out: vec![0; 1024],
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
                })
            })
            .collect()
    }

    /// What the application does after an event.
    enum Then {
        Nothing,
        Tx,
        Message(u64),
        /// The answer comes from a job, off the application's turn.
        Job,
        /// The answer is fetched from this server, by a stream
        /// connecting out.
        Fetch,
        /// A fetched answer, for the stream that asked.
        Deliver(StreamId, Vec<u8>),
    }

    /// What `/job` answers, made on a worker thread.
    const FROM_JOB: &[u8] = b"from a job";

    /// The application: an h1 request is answered with its path, or for
    /// `/big`, [`BIG`] bytes, or for `/job`, what a job comes to; a ws
    /// message is echoed.
    fn app<'s, 'j>(ss: &mut S<'s>, now: Instant, jobs: &Jobs<'j, S<'s>>, self_addr: &str) {
        while let Some(ev) = ss.poll_event(now) {
            let (stream, user): (StreamId, &mut App) = (ev.stream, ev.user);
            let then = match ev.kind {
                Kind::ServerTxn(mut txn) => {
                    let path = txn.path().unwrap_or_default();
                    let (out, then) = match path {
                        // far more than the buffers hold
                        b"/big" => (vec![b'x'; BIG], Then::Tx),
                        b"/job" => (Vec::new(), Then::Job),
                        b"/fetch" => (Vec::new(), Then::Fetch),
                        p => (p.to_vec(), Then::Tx),
                    };
                    let len = match path {
                        b"/job" => FROM_JOB.len(),
                        b"/fetch" => FETCH.len(),
                        _ => out.len(),
                    };
                    user.out = out;
                    user.at = 0;
                    txn.respond(Response {
                        status: 200,
                        content_type: Some(b"text/plain"),
                        content_length: Some(u64::try_from(len).unwrap()),
                        headers: &[],
                    })
                    .unwrap();
                    then
                }
                Kind::Rx { data, end } => {
                    user.msg.extend_from_slice(data);
                    if end != End::Last {
                        Then::Nothing
                    } else if let Some(asked) = user.fetching_for {
                        // a client stream's body is whole: for the stream
                        // that asked for it
                        Then::Deliver(asked, core::mem::take(&mut user.msg))
                    } else {
                        user.out = core::mem::take(&mut user.msg);
                        user.at = 0;
                        Then::Message(u64::try_from(user.out.len()).unwrap())
                    }
                }
                Kind::Tx(tx) => {
                    tx.fill(|buf| {
                        let rest = &user.out[user.at..];
                        let n = rest.len().min(buf.len());
                        buf[..n].copy_from_slice(&rest[..n]);
                        user.at = user.at.checked_add(n).unwrap();
                        if user.at == user.out.len() {
                            Filled::Last(n)
                        } else {
                            Filled::More(n)
                        }
                    });
                    Then::Nothing
                }
                Kind::Response(r) => {
                    assert_eq!(r.status(), 200);
                    Then::Nothing
                }
                Kind::ServerUpgrade { .. }
                | Kind::UpgradeRefused(_)
                | Kind::ClientUpgraded { .. }
                | Kind::NotUpgraded { .. }
                | Kind::Pong
                | Kind::PeerClose { .. }
                | Kind::ServerTxnEnd(_)
                | Kind::ConnectFailed
                | Kind::Disconnected => Then::Nothing,
            };
            match then {
                Then::Nothing => {}
                Then::Tx => ss.request_tx(stream).unwrap(),
                Then::Message(len) => ss.request_tx_len(stream, len).unwrap(),
                Then::Fetch => fetch(ss, stream, self_addr),
                Then::Deliver(asked, body) => {
                    if let Ok(u) = ss.user(asked) {
                        u.out = body;
                        u.at = 0;
                        ss.request_tx(asked).unwrap();
                    }
                    // the client stream is done with
                    ss.destroy(now, stream).unwrap();
                }
                Then::Job => jobs.spawn(move || {
                    // off the turn, with no lock held: it may take its time
                    thread::sleep(core::time::Duration::from_millis(20));
                    let bytes = FROM_JOB.to_vec();
                    move |streams: &mut S<'s>, _now: Instant| {
                        // the stream may have gone meanwhile
                        if let Ok(u) = streams.user(stream) {
                            u.out = bytes;
                            u.at = 0;
                            streams.request_tx(stream).unwrap();
                        }
                    }
                }),
            }
        }
    }

    /// A stream connecting out to this server, at `self_addr`, to fetch
    /// `/hello` for the stream `asked`.
    fn fetch(ss: &mut S<'_>, asked: StreamId, self_addr: &str) {
        ss.connect(
            self_addr,
            None,
            Request {
                method: b"GET",
                path: FETCH,
                host: Some(b"test"),
                origin: None,
                scheme: Scheme::Http,
                no_cache: false,
                connection: Connection::Close,
                headers: &[],
                body: RequestBody::None,
            },
            App {
                fetching_for: Some(asked),
                ..App::default()
            },
        )
        .unwrap();
    }

    /// Serves `listeners`, bound where each says, in `n` slots, while
    /// `client` runs, given the listeners bound; then stops.
    fn with_server(listeners: &[Listener<'static>], n: usize, client: impl FnOnce(&[Listening])) {
        let mut sl = slots(n);
        let ss = Ss::new(listeners, &mut sl).unwrap();
        let bound: Vec<Listening> = listeners.iter().map(|l| bind(l.bind).unwrap()).collect();
        // the first listener's address, for a stream connecting back
        let self_addr = bound
            .first()
            .and_then(|b| b.local_addr().unwrap())
            .map_or(String::new(), |a| a.to_string());
        let mut serving = Vec::new();
        for (i, b) in (0..).zip(&bound) {
            let id = ListenerId::new(i);
            serving.push((id, clone(b)));
        }
        let stop = Stop::new();
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                serve(
                    ss,
                    serving,
                    &|_| None,
                    |ss: &mut S<'_>, now, jobs| app(ss, now, jobs, &self_addr),
                    Workers::default(),
                    &stop,
                )
            });
            client(&bound);
            stop.stop();
            server.join().unwrap();
        });
    }

    fn clone(l: &Listening) -> Listening {
        match l {
            Listening::Tcp(t) => Listening::Tcp(t.try_clone().unwrap()),
            #[cfg(unix)]
            Listening::Unix(u) => Listening::Unix(u.try_clone().unwrap()),
        }
    }

    /// Everything the peer sends until it closes.
    fn all(mut s: impl Read) -> Vec<u8> {
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        got
    }

    fn tcp(l: &Listening) -> TcpStream {
        TcpStream::connect(l.local_addr().unwrap().unwrap()).unwrap()
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn an_h1_request_over_tcp_is_answered() {
        with_server(&[listener("127.0.0.1:0")], 2, |l| {
            let mut c = tcp(&l[0]);
            c.write_all(b"GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .unwrap();
            assert_eq!(
                all(c).escape_ascii().to_string(),
                "HTTP/1.1 200 OK\\r\\ncontent-type: text/plain\\r\\ncontent-length: 6\\r\\n\
                 x-test: 1\\r\\n\\r\\n/hello"
            );
        });
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn an_answer_made_by_a_job_off_the_turn_is_sent_when_it_comes() {
        with_server(&[listener("127.0.0.1:0")], 2, |l| {
            let mut c = tcp(&l[0]);
            c.write_all(b"GET /job HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .unwrap();
            assert!(all(c).ends_with(b"\r\n\r\nfrom a job"));
        });
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn an_answer_fetched_by_a_stream_connecting_out_is_delivered() {
        with_server(&[listener("127.0.0.1:0")], 4, |l| {
            let mut c = tcp(&l[0]);
            c.write_all(b"GET /fetch HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .unwrap();
            let got = all(c);
            assert!(got.ends_with(b"\r\n\r\n/hello"), "{}", got.escape_ascii());
        });
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn an_answer_far_larger_than_the_buffers_goes_whole() {
        with_server(&[listener("127.0.0.1:0")], 2, |l| {
            let mut c = tcp(&l[0]);
            c.write_all(b"GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .unwrap();
            let got = all(c);
            let at = got
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .unwrap()
                .checked_add(4)
                .unwrap();
            assert!(got.starts_with(b"HTTP/1.1 200 OK\r\n"));
            assert_eq!(got.len().checked_sub(at), Some(BIG));
            assert!(got[at..].iter().all(|b| *b == b'x'));
        });
    }

    #[test]
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn an_h1_request_over_a_unix_socket_is_answered() {
        use std::os::unix::net::UnixStream;
        use std::path::PathBuf;
        let path: PathBuf =
            std::env::temp_dir().join(format!("npro-ss-test-{}.sock", std::process::id()));
        let bind: &'static str = format!("unix:{}", path.display()).leak();
        with_server(&[listener(bind)], 2, |_| {
            let mut c = UnixStream::connect(&path).unwrap();
            c.write_all(b"GET /uds HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .unwrap();
            assert!(all(c).ends_with(b"\r\n\r\n/uds"));
        });
        drop(std::fs::remove_file(&path));
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn a_ws_message_is_echoed() {
        with_server(&[listener("127.0.0.1:0")], 2, |l| {
            let mut c = tcp(&l[0]);
            c.write_all(
                b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            )
            .unwrap();
            // the 101, to its end
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                c.read_exact(&mut b).unwrap();
                head.push(b[0]);
            }
            assert!(head.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
            // a masked "Hi", echoed unmasked
            c.write_all(b"\x81\x82\0\0\0\0Hi").unwrap();
            let mut echo = [0u8; 4];
            c.read_exact(&mut echo).unwrap();
            assert_eq!(&echo, b"\x81\x02Hi");
            // a close, answered with a close, then the server shuts down
            c.write_all(b"\x88\x82\0\0\0\0\x03\xe8").unwrap();
            assert_eq!(all(c), b"\x88\x02\x03\xe8");
        });
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn more_clients_than_slots_are_served_or_closed() {
        with_server(&[listener("127.0.0.1:0")], 2, |l| {
            let (mut served, mut closed) = (0, 0);
            thread::scope(|scope| {
                let clients: Vec<_> = (0..6)
                    .map(|i| {
                        let mut c = tcp(&l[0]);
                        scope.spawn(move || {
                            let req = format!(
                                "GET /{i} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
                            );
                            // a client closed at once may find its write refused
                            drop(c.write_all(req.as_bytes()));
                            let mut got = Vec::new();
                            drop(c.read_to_end(&mut got));
                            (i, got)
                        })
                    })
                    .collect();
                for c in clients {
                    let (i, got) = c.join().unwrap();
                    if got.is_empty() {
                        closed += 1;
                    } else {
                        assert!(got.ends_with(format!("\r\n\r\n/{i}").as_bytes()));
                        served += 1;
                    }
                }
            });
            assert!(served >= 2, "{served} served, {closed} closed");
            assert_eq!(served + closed, 6);
        });
    }
}
