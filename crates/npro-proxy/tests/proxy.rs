//! The proxy over npro-ss' streams, in memory: a request on a proxy
//! route made of an origin the test plays, its answer passed back, an
//! upload passed on, the origin unreachable or gone, and a slow client
//! holding the origin back.

// held to clippy's rules for tests
#[cfg(test)]
mod proxy {
    use npro_core::random::SeededRandom;
    use npro_core::time::Instant;
    use npro_h1::server::Config;
    use npro_io::driver::{Buffers, Io, NetBuffers, Want};
    use npro_proxy::{
        Act, Asked, Side, Storage, Upstream, answer, moved, on_event, origin_gone, start,
    };
    use npro_ss::event::{Filled, Kind};
    use npro_ss::id::{ConnId, ListenerId, StreamId};
    use npro_ss::policy::{Listener, Match, Route, Tls, Vhost, Ws};
    use npro_ss::ss::{ConnStorage, Slot, Ss};

    const T0: Instant = Instant::from_micros(1_000_000);

    const UP: Upstream<'static> = Upstream {
        address: "unix:/origin",
        path: "/git",
        host: "origin",
    };

    const ROUTES: [Route<'static>; 1] = [Route {
        path: "/up",
        matching: Match::Prefix,
        to: "proxy",
        ws: Ws::NotTaken,
        headers: &[(b"x-route", b"up")],
    }];

    const VHOSTS: [Vhost<'static>; 1] = [Vhost {
        name: "test",
        routes: &ROUTES,
        headers: &[],
        not_found: None,
    }];

    /// A stream's state: the proxy's, or nothing.
    #[derive(Debug, Default)]
    enum App {
        #[default]
        Idle,
        Answered,
        Proxy(Box<Side<Vec<u8>>>),
    }

    type S<'s> = Ss<'s, App, Vec<u8>, SeededRandom>;

    fn side_of(u: &mut App) -> Option<&mut Side<Vec<u8>>> {
        match u {
            App::Proxy(s) => Some(s),
            App::Idle | App::Answered => None,
        }
    }

    /// A side's storage: small, so the holds come, with room for a held
    /// giver's piece.
    fn storage() -> Storage<Vec<u8>> {
        Storage {
            staging: vec![0; 8192],
            out: vec![0; 8192],
        }
    }

    /// Small buffers, so a body is more than one piece.
    fn slots(n: usize) -> Vec<Slot<App, Vec<u8>, SeededRandom>> {
        (0..n)
            .map(|_| {
                Slot::new(ConnStorage {
                    h1: npro_h1::Storage {
                        table: vec![0; 2048],
                        out: vec![0; 1024],
                    },
                    bufs: Buffers {
                        rx: vec![0; 1024],
                        tx: vec![0; 1024],
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

    /// A proxied request copied out, to start after the event.
    enum Then {
        Nothing,
        Start(StreamId, Box<Asked>),
        Status(StreamId, u16),
        Acts(npro_proxy::Acts),
    }

    /// The front: proxy routes start the proxy, and its events are the
    /// proxy's.
    fn events(ss: &mut S<'_>, now: Instant) -> bool {
        let mut any = false;
        loop {
            let Some(ev) = ss.poll_event(now) else {
                return any;
            };
            any = true;
            let (stream, user) = (ev.stream, ev.user);
            let then = match (user, ev.kind) {
                (App::Idle | App::Answered, Kind::ServerTxn(txn)) => {
                    match txn.route().map(|r| r.route.to) {
                        Some("proxy") => match Asked::of(&UP, &txn) {
                            Ok(asked) => Then::Start(stream, Box::new(asked)),
                            Err(e) => Then::Status(stream, e.status()),
                        },
                        Some(_) | None => Then::Status(stream, 404),
                    }
                }
                (App::Answered, Kind::Tx(tx)) => {
                    tx.fill(|_| Filled::Last(0));
                    Then::Nothing
                }
                (App::Proxy(side), kind) => Then::Acts(on_event(stream, side, kind)),
                (App::Idle | App::Answered, _) => Then::Nothing,
            };
            match then {
                Then::Nothing => {}
                Then::Status(s, code) => {
                    ss.status(now, s, code).unwrap();
                    *ss.user(s).unwrap() = App::Answered;
                    ss.request_tx(s).unwrap();
                }
                Then::Start(client, asked) => {
                    match start(&UP, &asked, client, ss, storage(), storage(), |s| {
                        App::Proxy(Box::new(s))
                    }) {
                        Ok(side) => *ss.user(client).unwrap() = App::Proxy(Box::new(side)),
                        Err(e) => {
                            ss.status(now, client, e.status()).unwrap();
                            *ss.user(client).unwrap() = App::Answered;
                            ss.request_tx(client).unwrap();
                        }
                    }
                }
                Then::Acts(acts) => {
                    for a in acts.iter() {
                        apply(ss, now, a);
                    }
                }
            }
        }
    }

    fn apply(ss: &mut S<'_>, now: Instant, a: Act) {
        match a {
            Act::Move { from, to } => moved(ss, from, to, side_of),
            Act::Answer { client, origin } => answer(ss, client, origin, side_of).unwrap(),
            Act::Status(s, code) => {
                if ss.status(now, s, code).is_ok() {
                    if let Ok(u) = ss.user(s) {
                        *u = App::Answered;
                    }
                    ss.request_tx(s).unwrap();
                }
            }
            Act::OriginGone(client) => origin_gone(ss, now, client, side_of),
            Act::Destroy(s) => drop(ss.destroy(now, s)),
            Act::RequestTx(s) => drop(ss.request_tx(s)),
            Act::Flow(s, f) => drop(ss.flow(s, f)),
        }
    }

    /// The origin, as the test plays it: its connection, what it was
    /// sent, what it is to send back.
    struct Origin {
        conn: Option<ConnId>,
        got: Vec<u8>,
        send: Vec<u8>,
        /// Closes once `send` has gone.
        close: bool,
    }

    /// One turn of everything: the client's bytes read in, the origin's
    /// connect answered and its bytes exchanged, events taken, the
    /// client's output written `pace` bytes at a time.  Whether anything
    /// moved.
    fn turn(
        ss: &mut S<'_>,
        client: ConnId,
        input: &mut &[u8],
        out: &mut Vec<u8>,
        pace: usize,
        origin: &mut Origin,
        connect: Result<(), ()>,
    ) -> bool {
        let mut moved = false;
        if !input.is_empty() {
            if let Ok(Want::Io(Io {
                read: Some(room), ..
            })) = ss.want(T0, client)
            {
                let n = room.len().min(input.len());
                room[..n].copy_from_slice(&input[..n]);
                ss.read_done(T0, client, n).unwrap();
                *input = &input[n..];
                moved |= n > 0;
            }
        }
        if let Some((conn, c)) = ss.next_connect() {
            assert_eq!(c.address, UP.address);
            match connect {
                Ok(()) => {
                    ss.connected(T0, conn, None).unwrap();
                    origin.conn = Some(conn);
                }
                Err(()) => ss.connect_failed(T0, conn).unwrap(),
            }
            moved = true;
        }
        moved |= events(ss, T0);
        if let Some(oc) = origin.conn {
            // what the proxy sent the origin
            while let Ok(Want::Io(Io { write: Some(w), .. })) = ss.want(T0, oc) {
                let n = w.len();
                origin.got.extend_from_slice(w);
                ss.write_done(T0, oc, n).unwrap();
                moved = true;
            }
            // what the origin sends back, as far as the proxy reads it
            if !origin.send.is_empty() {
                if let Ok(n) = ss.received(T0, oc, &origin.send) {
                    origin.send.drain(..n);
                    moved |= n > 0;
                }
            } else if origin.close {
                origin.close = false;
                ss.read_done(T0, oc, 0).unwrap();
                moved = true;
            }
            moved |= events(ss, T0);
            match ss.want(T0, oc) {
                Ok(Want::HalfClose) => {
                    ss.half_closed(T0, oc).unwrap();
                    moved = true;
                }
                Ok(Want::Release(_)) => {
                    ss.released(oc).unwrap();
                    origin.conn = None;
                    moved = true;
                }
                Ok(Want::Io(_)) | Err(_) => {}
            }
            moved |= events(ss, T0);
        }
        if let Ok(Want::Io(Io { write: Some(w), .. })) = ss.want(T0, client) {
            let n = w.len().min(pace);
            out.extend_from_slice(&w[..n]);
            ss.write_done(T0, client, n).unwrap();
            moved = true;
        }
        moved
    }

    /// Serves `request` through the proxy to an origin that answers
    /// `response` (and closes after if `close`), the client's output
    /// taken `pace` bytes at a time: what the client got, and what the
    /// origin was sent.
    fn proxied(
        request: &[u8],
        response: &[u8],
        close: bool,
        pace: usize,
        connect: Result<(), ()>,
    ) -> (Vec<u8>, Vec<u8>) {
        let listeners = [Listener {
            name: "test",
            bind: "unix:/test",
            tls: Tls::Plain,
            h1: Config::default(),
            vhosts: &VHOSTS,
        }];
        let mut sl = slots(2);
        let mut ss = Ss::new(&listeners, &mut sl).unwrap();
        let client = ss.accepted(T0, ListenerId::new(0), None).unwrap();
        let mut input = request;
        let mut out = Vec::new();
        let mut origin = Origin {
            conn: None,
            got: Vec::new(),
            send: response.to_vec(),
            close,
        };
        for _ in 0..100_000 {
            if !turn(
                &mut ss,
                client,
                &mut input,
                &mut out,
                pace,
                &mut origin,
                connect,
            ) {
                break;
            }
        }
        (out, origin.got)
    }

    const GET: &[u8] = b"GET /up/repo.git/info?a=1&b=x%26y HTTP/1.1\r\nHost: test\r\nCookie: s=1\r\nX-Other: no\r\n\r\n";

    #[test]
    fn a_request_goes_on_and_its_answer_comes_back() {
        let (got, sent) = proxied(
            GET,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\
              X-Origin: hidden\r\nContent-Length: 5\r\n\r\nhello",
            true,
            4096,
            Ok(()),
        );
        assert_eq!(
            String::from_utf8_lossy(&sent),
            "GET /git/repo.git/info?a=1&b=x%26y HTTP/1.1\r\nHost: test\r\nconnection: close\r\n\
             cookie: s=1\r\n\r\n"
        );
        assert_eq!(
            String::from_utf8_lossy(&got),
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\nx-route: up\r\n\
             set-cookie: a=1\r\nset-cookie: b=2\r\n\r\nhello"
        );
    }

    #[test]
    fn an_upload_goes_on_and_an_empty_post_is_said_so() {
        let (got, sent) = proxied(
            b"POST /up HTTP/1.1\r\nHost: test\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nhello!",
            b"HTTP/1.1 204 No Content\r\n\r\n",
            true,
            4096,
            Ok(()),
        );
        assert_eq!(
            String::from_utf8_lossy(&sent),
            "POST /git HTTP/1.1\r\nHost: test\r\nconnection: close\r\ncontent-type: text/plain\r\n\
             Content-Length: 6\r\n\r\nhello!"
        );
        // C has no text for a 204
        assert!(
            got.starts_with(b"HTTP/1.1 204 \r\n"),
            "{}",
            got.escape_ascii()
        );
        let (_, sent_empty) = proxied(
            b"POST /up HTTP/1.1\r\nHost: test\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\n\r\n",
            true,
            4096,
            Ok(()),
        );
        assert!(
            sent_empty.ends_with(b"Content-Length: 0\r\n\r\n"),
            "{}",
            sent_empty.escape_ascii()
        );
    }

    #[test]
    fn an_origin_not_reached_is_503_and_one_gone_before_its_head_is_502() {
        let (got, _) = proxied(GET, b"", false, 4096, Err(()));
        assert!(
            got.starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"),
            "{}",
            got.escape_ascii()
        );
        let (gone, _) = proxied(GET, b"", true, 4096, Ok(()));
        assert!(
            gone.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"),
            "{}",
            gone.escape_ascii()
        );
    }

    #[test]
    fn a_body_with_no_length_goes_to_the_close_and_a_slow_client_holds_the_origin() {
        let body: Vec<u8> = (0..200_000u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let response = [
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec(),
            body.clone(),
        ]
        .concat();
        let (got, _) = proxied(GET, &response, true, 100, Ok(()));
        let at = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(got.starts_with(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\nconnection: close\r\n"
        ));
        assert_eq!(got[at..], body[..]);
    }
}
