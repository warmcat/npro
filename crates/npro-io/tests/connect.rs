//! The threads adapter connecting out: a host that wants one connection
//! made, to a listener this test holds, gets it driven as an accepted
//! one is; one that cannot be made is told so.

#![expect(
    unused_crate_dependencies,
    reason = "an integration test sees all of its crate's dependencies; this one uses npro-core, npro-h1 and npro-io"
)]

// held to clippy's rules for tests
#[cfg(test)]
mod connect {
    use core::net::SocketAddr;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use npro_core::random::SeededRandom;
    use npro_core::time::Instant;
    use npro_h1::Storage;
    use npro_h1::client::{self, Client, Connection, Request, RequestBody, Scheme};
    use npro_h1::server::NoPayload;
    use npro_io::conn::{Conn, Event};
    use npro_io::driver::{Buffers, Driver, Want};
    use npro_io::host::{Connect, Gone, Host};
    use npro_io::threads::{Stop, Workers, serve};
    use npro_io::tls::NoTls;

    type D = Driver<Vec<u8>, SeededRandom, Vec<u8>, NoTls>;

    /// A host of one connection, which it wants made to `address`.
    struct One {
        address: String,
        asked: bool,
        driver: Option<D>,
        failed: bool,
        /// The response's body, as it came.
        body: Vec<u8>,
        /// The response's body is whole.
        done: bool,
    }

    impl One {
        fn new(address: &str) -> Self {
            Self {
                address: address.to_owned(),
                asked: false,
                driver: None,
                failed: false,
                body: Vec::new(),
                done: false,
            }
        }

        fn driver(&mut self) -> Result<&mut D, Gone> {
            self.driver.as_mut().ok_or(Gone)
        }
    }

    impl Host for One {
        type Listener = ();
        type Conn = ();
        type Tls = NoTls;
        type Refused = Gone;

        fn accepted(
            &mut self,
            _: Instant,
            (): (),
            _: Option<NoTls>,
            _: Option<SocketAddr>,
        ) -> Result<(), Gone> {
            Err(Gone)
        }

        fn want(&mut self, now: Instant, (): ()) -> Result<Want<'_>, Gone> {
            Ok(self.driver()?.want(now, &mut NoPayload))
        }

        fn read_done(&mut self, now: Instant, (): (), n: usize) -> Result<(), Gone> {
            self.driver()?.read_done(now, n);
            Ok(())
        }

        fn received(&mut self, now: Instant, (): (), bytes: &[u8]) -> Result<usize, Gone> {
            Ok(self.driver()?.received(now, bytes))
        }

        fn write_done(&mut self, now: Instant, (): (), n: usize) -> Result<(), Gone> {
            self.driver()?.write_done(now, n);
            Ok(())
        }

        fn half_closed(&mut self, now: Instant, (): ()) -> Result<(), Gone> {
            self.driver()?.half_closed(now);
            Ok(())
        }

        fn timer(&mut self, now: Instant, (): ()) -> Result<(), Gone> {
            self.driver()?.timer(now);
            Ok(())
        }

        fn hangup(&mut self, now: Instant, (): ()) -> Result<(), Gone> {
            self.driver()?.hangup(now);
            Ok(())
        }

        fn released(&mut self, (): ()) -> Result<(), Gone> {
            self.driver.take().map(|_| ()).ok_or(Gone)
        }

        fn next_connect(&mut self) -> Option<((), Connect<'_>)> {
            if self.asked {
                return None;
            }
            self.asked = true;
            Some((
                (),
                Connect {
                    address: &self.address,
                    tls: None,
                    identity: None,
                },
            ))
        }

        fn connected(&mut self, _: Instant, (): (), tls: Option<NoTls>) -> Result<(), Gone> {
            // none was asked for
            if tls.is_some() {
                return Err(Gone);
            }
            let c = Client::new(
                Storage {
                    table: vec![0u8; 1024],
                    out: vec![0u8; 512],
                },
                Request {
                    method: b"GET",
                    path: b"/x",
                    host: Some(b"test"),
                    origin: None,
                    scheme: Scheme::Http,
                    no_cache: false,
                    connection: Connection::Close,
                    headers: &[],
                    body: RequestBody::None,
                },
            )
            .map_err(|_| Gone)?;
            self.driver = Some(Driver::plain(
                Conn::h1_client(c),
                Buffers {
                    rx: vec![0u8; 1024],
                    tx: vec![0u8; 1024],
                    inflate: Vec::new(),
                },
            ));
            Ok(())
        }

        fn connect_failed(&mut self, _: Instant, (): ()) -> Result<(), Gone> {
            self.failed = true;
            Ok(())
        }
    }

    /// The application: takes the response's body as it comes.
    fn app(h: &mut One, now: Instant) {
        let Some(d) = h.driver.as_mut() else {
            return;
        };
        while let Some(step) = d.poll_rx(now) {
            match step.event() {
                Event::H1Client(client::Event::Body(b)) => h.body.extend_from_slice(b),
                Event::H1Client(client::Event::BodyEnd) => h.done = true,
                Event::H1Client(client::Event::Response)
                | Event::H1Server(_)
                | Event::Ws(_)
                | Event::Raw(_) => {}
            }
        }
    }

    /// Runs `host` until `until` says, or a few seconds pass: the host.
    fn run(host: One, until: &AtomicBool) -> One {
        let stop = Stop::new();
        thread::scope(|scope| {
            let served = scope.spawn(|| {
                serve(
                    host,
                    Vec::new(),
                    &|(): ()| None::<NoTls>,
                    |h: &mut One, now, _| {
                        app(h, now);
                        if h.done || h.failed {
                            until.store(true, Ordering::Release);
                        }
                    },
                    Workers(1),
                    &stop,
                )
            });
            for _ in 0..500 {
                if until.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(core::time::Duration::from_millis(10));
            }
            stop.stop();
            served.join().unwrap()
        })
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn a_connection_the_host_wants_is_made_and_driven() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut head = [0u8; 256];
            let n = s.read(&mut head).unwrap();
            assert!(
                head[..n].starts_with(b"GET /x HTTP/1.1\r\n"),
                "{}",
                head[..n].escape_ascii()
            );
            s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .unwrap();
        });
        let until = AtomicBool::new(false);
        let host = run(One::new(&addr.to_string()), &until);
        peer.join().unwrap();
        assert!(!host.failed);
        assert!(host.done);
        assert_eq!(host.body, b"ok");
    }

    #[test]
    #[cfg_attr(miri, ignore = "threads: native runs keep it")]
    fn what_is_asked_for_later_is_applied_then_on_the_hosts_turn() {
        let mut host = One::new("127.0.0.1:1");
        // nothing to connect: the timer alone
        host.asked = true;
        let stop = Stop::new();
        let fired = std::sync::Mutex::new(None);
        let began = std::time::Instant::now();
        thread::scope(|scope| {
            let (fired, began, stop) = (&fired, &began, &stop);
            let served = scope.spawn(move || {
                let mut asked = false;
                serve(
                    host,
                    Vec::new(),
                    &|(): ()| None::<NoTls>,
                    move |_: &mut One, _, jobs| {
                        if !asked {
                            asked = true;
                            jobs.after(
                                core::time::Duration::from_millis(80),
                                move |h: &mut One, _| {
                                    h.done = true;
                                    *fired.lock().unwrap() = Some(began.elapsed());
                                },
                            );
                        }
                    },
                    Workers(1),
                    stop,
                )
            });
            for _ in 0..500 {
                if fired.lock().unwrap().is_some() {
                    break;
                }
                thread::sleep(core::time::Duration::from_millis(10));
            }
            stop.stop();
            let h = served.join().unwrap();
            assert!(h.done);
        });
        let at = fired.lock().unwrap().unwrap();
        assert!(at >= core::time::Duration::from_millis(80), "{at:?}");
        assert!(at < core::time::Duration::from_secs(3), "{at:?}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "sockets: native runs keep it")]
    fn a_connection_that_cannot_be_made_is_told_so() {
        // bound then dropped: nothing listens there
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let until = AtomicBool::new(false);
        let host = run(One::new(&addr.to_string()), &until);
        assert!(host.failed);
        assert!(host.driver.is_none());
    }
}
